const std = @import("std");
const Io = std.Io;
const posix = std.posix;
const filter_mod = @import("filter.zig");

/// TIOCSTI: 伪造一个字符注入到 tty 的输入队列（等价于键盘输入）。
/// 定义来自内核头文件 /usr/include/asm-generic/ioctls.h，stdlib 未收录。
const TIOCSTI: u32 = 0x5412;

/// 输入前缀键（tmux 式）：Ctrl+6 = 0x1e（ASCII RS）。
/// 终端应答序列不含 0x1e，且镜像路径已过滤应答来源，不会误触。
const PREFIX: u8 = 0x1e;
/// 前缀后按 x 退出（仿 tmux 的 detach 语义）。
const EXIT_KEY: u8 = 'x';
/// 前缀等待下一个键的超时（ms），超时则把 prefix 本身转发给受控端。
const PREFIX_TIMEOUT_MS: i32 = 1000;
/// 挂起字节（ESC 等 '['、残缺 CSI 序列）的极短超时（ms）：转义序列的
/// 字节流间隔远小于人类按键间隔，超时说明 ESC 是独立按键，转发它。
/// 否则 vim 里 ESC 后的第一个键会被当成序列字节吞掉。
const ESC_TIMEOUT_MS: i32 = 50;

/// 非交互模式（-c <command>）的运行时长（ms）：注入命令后镜像转发
/// 该时长，然后自动退出。
const CMD_TIMEOUT_MS: i64 = 5000;

/// 单调时钟当前毫秒（非交互模式计时用）。
fn nowMs() i64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts);
    return @as(i64, @intCast(ts.sec)) * 1000 +
        @divTrunc(@as(i64, @intCast(ts.nsec)), std.time.ns_per_ms);
}

// ---- libbpf 绑定（手写 extern，避免 @cImport）----

const bpf_object = opaque {};
const bpf_program = opaque {};
const bpf_map = opaque {};
const bpf_link = opaque {};
const ring_buffer = opaque {};

const RingSampleFn = *const fn (ctx: ?*anyopaque, data: ?*const anyopaque, size: usize) callconv(.c) c_int;

extern fn bpf_object__open_mem(obj_buf: [*]const u8, obj_buf_sz: usize, opts: ?*const anyopaque) ?*bpf_object;
extern fn bpf_object__load(obj: *bpf_object) c_int;
extern fn bpf_object__close(obj: *bpf_object) void;
extern fn bpf_object__find_program_by_name(obj: *const bpf_object, name: [*:0]const u8) ?*bpf_program;
extern fn bpf_object__find_map_by_name(obj: *const bpf_object, name: [*:0]const u8) ?*bpf_map;
extern fn bpf_program__attach(prog: *bpf_program) ?*bpf_link;
extern fn bpf_map__update_elem(map: *const bpf_map, key: *const anyopaque, key_sz: usize, value: *const anyopaque, value_sz: usize, flags: u64) c_int;
extern fn bpf_map__fd(map: *const bpf_map) c_int;
extern fn ring_buffer__new(map_fd: c_int, sample_cb: RingSampleFn, ctx: ?*anyopaque, opts: ?*const anyopaque) ?*ring_buffer;
extern fn ring_buffer__consume(rb: *ring_buffer) c_int;
extern fn ring_buffer__epoll_fd(rb: *const ring_buffer) c_int;
extern fn ring_buffer__free(rb: *ring_buffer) void;
extern fn libbpf_strerror(err: c_int, buf: [*]u8, size: usize) c_int;

/// ring buffer 中的事件，与 probe.bpf.c 的 struct event 对应。
const Event = extern struct {
    len: u32,
    data: [4096]u8,
};

const State = struct {
    io: Io,
    filter: *filter_mod.Filter,
};

/// 写镜像字节到 stdout（阻塞流式）。
fn writeStdout(io: Io, bytes: []const u8) bool {
    Io.File.writeStreamingAll(Io.File.stdout(), io, bytes) catch return false;
    return true;
}

/// 序列起始字节（与 filter.zig 的 isStarter 一致）：数据块含任一字节时
/// 必须逐字节过状态机，否则可整体转发。
fn isStarterByte(b: u8) bool {
    return b == 0x1b or b == 0x9b or b == 0x90 or b == 0x9d or b == 0x98 or
        b == 0x9e or b == 0x9f;
}

fn hasStarter(bytes: []const u8) bool {
    for (bytes) |b| {
        if (isStarterByte(b)) return true;
    }
    return false;
}

/// ring buffer 回调：把被控 tty 的输出经过滤后写到自己的终端。
/// filter 输出按批量累积（连续独立字节/短序列合并成块）再一次性写出，
/// 避免大输出（图片等）时每字节一次小写拖慢消费、ring 满丢数据。
/// 快速路径：filter 空闲且数据块不含序列起始字节（图片 base64 大块）
/// 时直接整体累积，跳过逐字节状态机。
fn onRingSample(ctx: ?*anyopaque, data: ?*const anyopaque, size: usize) callconv(.c) c_int {
    _ = size;
    const state: *State = @ptrCast(@alignCast(ctx.?));
    const event: *const Event = @ptrCast(@alignCast(data.?));
    const bytes = event.data[0..@intCast(event.len)];

    var out: [8192]u8 = undefined;
    var out_len: usize = 0;
    const append_out = struct {
        fn append(io: Io, buf: *[8192]u8, len: *usize, slice: []const u8) bool {
            if (len.* + slice.len > buf.len) {
                if (!writeStdout(io, buf[0..len.*])) return false;
                len.* = 0;
                // 大 slice（图片大单块等整序列）：直接写出，不经缓冲
                if (slice.len > buf.len) {
                    if (!writeStdout(io, slice)) return false;
                    return true;
                }
            }
            @memcpy(buf[len.*..][0..slice.len], slice);
            len.* += slice.len;
            return true;
        }
    }.append;

    // 分段处理：纯文本段（不含序列起始字节）在 filter 空闲时整体批量
    // 直通（一次 memcpy），序列段才逐字节过状态机——图片数据每事件仅
    // 含 2-3 个 ESC，逐字节 push 从 ~2048 次降到 ~30 次，消费提速数十倍。
    var start: usize = 0;
    while (start < bytes.len) {
        var esc = start;
        while (esc < bytes.len and !isStarterByte(bytes[esc])) esc += 1;
        if (esc > start) {
            if (state.filter.isIdle()) {
                if (!append_out(state.io, &out, &out_len, bytes[start..esc])) return -1;
            } else {
                for (bytes[start..esc]) |b| {
                    if (state.filter.push(b)) |slice| {
                        if (!append_out(state.io, &out, &out_len, slice)) return -1;
                    }
                }
            }
        }
        if (esc >= bytes.len) break;
        var j = esc;
        while (j < bytes.len) {
            const b = bytes[j];
            if (state.filter.push(b)) |slice| {
                if (!append_out(state.io, &out, &out_len, slice)) return -1;
            }
            j += 1;
            if (state.filter.isIdle()) break;
        }
        start = j;
    }
    if (out_len > 0) {
        if (!writeStdout(state.io, out[0..out_len])) return -1;
    }
    return 0;
}

/// 把一个字节注入受控端 tty 的输入队列。
fn injectByte(tty: Io.File, io: Io, b: u8) !void {
    var buf = [_]u8{b};
    const result = try io.operate(.{
        .device_io_control = .{
            .file = tty,
            .code = TIOCSTI,
            .arg = &buf,
        },
    });
    if (result.device_io_control < 0) {
        std.log.err("TIOCSTI 注入失败: {}", .{result.device_io_control});
        std.process.exit(1);
    }
}

/// 批量注入（TIOCSTI 一次一个字节）。
fn injectBytes(tty: Io.File, io: Io, bytes: []const u8) !void {
    for (bytes) |b| try injectByte(tty, io, b);
}

fn checkObj(ptr: ?*anyopaque, what: []const u8) !*anyopaque {
    if (ptr == null) {
        std.log.err("libbpf: {s} 失败", .{what});
        return error.LibbpfFailed;
    }
    return ptr.?;
}

fn checkErr(rc: c_int, what: []const u8) !void {
    if (rc < 0) {
        var buf: [256]u8 = undefined;
        _ = libbpf_strerror(rc, &buf, buf.len);
        std.log.err("libbpf: {s} 失败: {s}", .{ what, std.mem.sliceTo(&buf, 0) });
        return error.LibbpfFailed;
    }
}

pub fn main(init: std.process.Init) !void {
    const arena: std.mem.Allocator = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(arena);
    var command: ?[]const u8 = null;
    if (args.len == 4 and std.mem.eql(u8, args[2], "-c")) {
        command = args[3]; // 非交互：自动在受控端执行命令后退出
    } else if (args.len != 2) {
        std.log.err("用法: sudo {s} <tty slave 路径> [-c <命令>]", .{args[0]});
        std.process.exit(2);
    }
    const tty_path = args[1];

    // 打开目标 tty 的 slave 文件（物理 tty 或 pts）。
    const tty = try Io.Dir.openFileAbsolute(io, tty_path, .{
        .mode = .read_write,
    });
    defer Io.File.close(tty, io);

    // 控制台（自己的 stdin）：保存原始 termios，交互模式改为非规范模式、
    // 关闭回显与 ISIG（否则 Ctrl+C 变 SIGINT），defer 还原。
    const stdin_handle = posix.STDIN_FILENO;
    const orig_term = try posix.tcgetattr(stdin_handle);
    defer posix.tcsetattr(stdin_handle, .NOW, orig_term) catch {};

    var raw = orig_term;
    raw.lflag.ICANON = false;
    raw.lflag.ECHO = false;
    raw.lflag.ISIG = false; // 否则 Ctrl+C 会被终端驱动转为 SIGINT 杀掉本程序
    raw.iflag.ICRNL = false; // 否则回车 \r 会被内核转为 \n
    raw.cc[@intFromEnum(posix.V.MIN)] = 1; // 有数据就返回
    raw.cc[@intFromEnum(posix.V.TIME)] = 0;
    try posix.tcsetattr(stdin_handle, .NOW, raw);

    // ---- 加载 BPF 对象并挂载 fentry ----

    // BPF 对象：编译期嵌入（@embedFile，build.zig 的 addEmbedPath 提供搜索路径）。
    const bpf_bytes = @embedFile("probe.bpf.o");
    const obj: *bpf_object = @ptrCast(try checkObj(
        bpf_object__open_mem(bpf_bytes.ptr, bpf_bytes.len, null),
        "bpf_object__open_mem",
    ));
    defer bpf_object__close(obj);

    // 加载程序（map 在此刻于内核中创建）。
    try checkErr(bpf_object__load(obj), "bpf_object__load");

    // 用 statx 获取目标 tty 的设备号（major/index），写入过滤 map。
    const tty_path_z = try arena.dupeZ(u8, tty_path);
    var st: std.os.linux.Statx = undefined;
    if (std.os.linux.errno(std.os.linux.statx(
        std.os.linux.AT.FDCWD,
        tty_path_z.ptr,
        0,
        std.os.linux.STATX.BASIC_STATS,
        &st,
    )) != .SUCCESS) return error.StatxFailed;

    const target_dev: *bpf_map = @ptrCast(try checkObj(
        bpf_object__find_map_by_name(obj, "target_dev"),
        "find_map_by_name(target_dev)",
    ));
    var target_dev_value = [_]u32{ st.rdev_major, st.rdev_minor };
    var key: u32 = 0;
    try checkErr(bpf_map__update_elem(target_dev, &key, 4, &target_dev_value, 8, 0), "target_dev 写入");
    std.log.debug("目标 tty: major={d} minor={d}", .{ st.rdev_major, st.rdev_minor });

    // 挂 fexit（libbpf 按 SEC("fexit/n_tty_write") 自动走 bpf_program__attach_trace）。
    const prog: *bpf_program = @ptrCast(try checkObj(
        bpf_object__find_program_by_name(obj, "capture_tty_write_exit"),
        "find_program_by_name",
    ));
    const link: *bpf_link = @ptrCast(try checkObj(bpf_program__attach(prog), "bpf_program__attach"));
    _ = link;

    // ring buffer 消费。
    const events_map: *bpf_map = @ptrCast(try checkObj(
        bpf_object__find_map_by_name(obj, "events"),
        "find_map_by_name(events)",
    ));
    var out_filter = filter_mod.Filter.init(arena);
    defer out_filter.deinit();

    var state = State{ .io = io, .filter = &out_filter };

    const rb: *ring_buffer = @ptrCast(try checkObj(
        ring_buffer__new(bpf_map__fd(events_map), onRingSample, &state, null),
        "ring_buffer__new",
    ));
    defer ring_buffer__free(rb);

    // 非交互模式：注入命令 + 回车（\r）到受控端，开始计时。
    var start_ms: i64 = 0;
    if (command) |cmd| {
        try injectBytes(tty, io, cmd);
        try injectBytes(tty, io, "\r");
        start_ms = nowMs();
    }

    // ---- 主循环：poll stdin（注入，tmux 式前缀）+ poll ringbuf（回显）----

    const stdin_file = Io.File.stdin();
    var buf: [1]u8 = undefined;
    var input_dec = filter_mod.Input{};
    var prefix_wait = false;
    var prefix_bytes: [64]u8 = undefined; // kitty 事件负载最长 64 字节
    var prefix_len: usize = 0;

    var fds = [_]posix.pollfd{
        .{ .fd = posix.STDIN_FILENO, .events = posix.POLL.IN, .revents = 0 },
        .{ .fd = ring_buffer__epoll_fd(rb), .events = posix.POLL.IN, .revents = 0 },
    };

    while (true) {
        var timeout_ms: i32 = if (prefix_wait) PREFIX_TIMEOUT_MS
        else if (input_dec.pending()) ESC_TIMEOUT_MS
        else -1;
        if (command != null) {
            // 非交互：poll 分段超时（最长 1s），到 CMD_TIMEOUT_MS 自动退出。
            const elapsed = nowMs() - start_ms;
            const remain = CMD_TIMEOUT_MS - elapsed;
            if (remain <= 0) break;
            const cap: i32 = @intCast(@min(remain, 1000));
            timeout_ms = if (timeout_ms < 0 or timeout_ms > cap) cap else timeout_ms;
        }
        const nfds = posix.poll(&fds, timeout_ms) catch continue;

        // 超时：prefix 单独按下，或 ESC/残缺序列挂起 → 独立转发
        if (nfds == 0) {
            if (prefix_wait) {
                prefix_wait = false;
                try injectBytes(tty, io, prefix_bytes[0..prefix_len]);
            } else if (input_dec.pending()) {
                try injectBytes(tty, io, input_dec.flush());
            }
            continue;
        }

        if (fds[0].revents != 0) {
            const n = try Io.File.readStreaming(stdin_file, io, &.{&buf});
            if (n == 0) continue;
            const b = buf[0];

            const ev = input_dec.push(b);

            // debug 级日志：Debug 模式默认输出，Release 模式被编译期剪掉
            std.log.debug("stdin: {x:0>2} -> {s} prefix_wait={any}", .{ b, @tagName(ev), prefix_wait });

            switch (ev) {
                .prefix => |bytes| {
                    // Ctrl+6：进入前缀等待（或双击 = 字面转发）
                    if (prefix_wait) {
                        prefix_wait = false;
                        try injectBytes(tty, io, bytes);
                    } else {
                        prefix_wait = true;
                        prefix_len = @min(bytes.len, prefix_bytes.len);
                        @memcpy(prefix_bytes[0..prefix_len], bytes[0..prefix_len]);
                    }
                },
                .key => |k| {
                    // kitty 键事件（普通键原样转发）
                    if (prefix_wait) {
                        if (k.code == EXIT_KEY and (k.mods & 4) == 0) break; // 前缀后按 x 退出
                        prefix_wait = false; // 其余键：prefix 被吞，只转发该键
                    }
                    try injectBytes(tty, io, k.payload);
                },
                .forward => |bytes| {
                    // 普通字节/非 kitty 序列（原样转发；raw 模式下的 x 在等待态退出）
                    if (prefix_wait) {
                        if (bytes.len == 1 and bytes[0] == EXIT_KEY) break;
                        prefix_wait = false;
                    }
                    if (bytes.len > 0) try injectBytes(tty, io, bytes);
                },
            }
        }

        if (fds[1].revents != 0) {
            _ = ring_buffer__consume(rb);
        }
    }
}

// Zig 0.16 的测试只执行根文件的 test 块，必须显式引用模块才能跑其中的测试。
test {
    _ = @import("filter.zig");
}
