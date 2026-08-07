const std = @import("std");
const Io = std.Io;
const posix = std.posix;
const builtin = @import("builtin");
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

// ---- libbpf 绑定（手写 extern，避免 @cImport）----

const bpf_object = opaque {};
const bpf_program = opaque {};
const bpf_map = opaque {};
const bpf_link = opaque {};
const ring_buffer = opaque {};

const RingSampleFn = *const fn (ctx: ?*anyopaque, data: ?*const anyopaque, size: usize) callconv(.c) c_int;

extern fn bpf_object__open_file(path: [*:0]const u8, opts: ?*const anyopaque) ?*bpf_object;
extern fn bpf_object__load(obj: *bpf_object) c_int;
extern fn bpf_object__close(obj: *bpf_object) void;
extern fn bpf_object__find_program_by_name(obj: *const bpf_object, name: [*:0]const u8) ?*bpf_program;
extern fn bpf_object__find_map_by_name(obj: *const bpf_object, name: [*:0]const u8) ?*bpf_map;
extern fn bpf_program__attach(prog: *bpf_program) ?*bpf_link;
extern fn bpf_map__update_elem(map: *const bpf_map, key: *const anyopaque, key_sz: usize, value: *const anyopaque, value_sz: usize, flags: u64) c_int;
extern fn bpf_map__lookup_elem(map: *const bpf_map, key: *const anyopaque, key_sz: usize, value: *anyopaque, value_sz: usize, flags: u64) c_int;
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
    samples: usize = 0,
};

/// ring buffer 回调：把被控 tty 的输出经过滤后写到自己的终端。
fn onRingSample(ctx: ?*anyopaque, data: ?*const anyopaque, size: usize) callconv(.c) c_int {
    _ = size;
    const state: *State = @ptrCast(@alignCast(ctx.?));
    state.samples += 1;
    const event: *const Event = @ptrCast(@alignCast(data.?));
    const bytes = event.data[0..@intCast(event.len)];
    for (bytes) |b| {
        if (state.filter.push(b)) |slice| {
            Io.File.writeStreamingAll(Io.File.stdout(), state.io, slice) catch return -1;
        }
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
    if (args.len != 2) {
        std.log.err("用法: sudo {s} <tty slave 路径> （Ctrl+6 后按 x 退出；Ctrl+6 Ctrl+6 发送字面 Ctrl+6）", .{args[0]});
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

    // ---- 加载 BPF 对象并挂载 kprobe ----

    // BPF 对象路径：与可执行文件同目录。
    const exe_path = args[0];
    const dir_end = std.mem.lastIndexOfScalar(u8, exe_path, '/') orelse return error.BadExePath;
    const obj_path = try std.mem.concat(arena, u8, &.{ exe_path[0 .. dir_end + 1], "probe.bpf.o" });
    const obj_path_z = try arena.dupeZ(u8, obj_path);

    const obj: *bpf_object = @ptrCast(try checkObj(
        bpf_object__open_file(obj_path_z.ptr, null),
        "bpf_object__open_file",
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
    std.log.info("目标 tty: major={d} minor={d}", .{ st.rdev_major, st.rdev_minor });

    // 挂 kprobe（libbpf 按 SEC("kprobe/n_tty_write") 自动挂载）。
    const prog: *bpf_program = @ptrCast(try checkObj(
        bpf_object__find_program_by_name(obj, "capture_tty_write"),
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

    // ---- 主循环：poll stdin（注入，tmux 式前缀）+ poll ringbuf（回显）----

    const stdin_file = Io.File.stdin();
    var buf: [1]u8 = undefined;
    var input_dec = filter_mod.Input{};
    var prefix_wait = false;
    var prefix_bytes: [8]u8 = undefined;
    var prefix_len: usize = 0;

    var fds = [_]posix.pollfd{
        .{ .fd = posix.STDIN_FILENO, .events = posix.POLL.IN, .revents = 0 },
        .{ .fd = ring_buffer__epoll_fd(rb), .events = posix.POLL.IN, .revents = 0 },
    };

    while (true) {
        const timeout_ms: i32 = if (prefix_wait) PREFIX_TIMEOUT_MS else -1;
        const nfds = posix.poll(&fds, timeout_ms) catch continue;

        // 前缀超时：用户只按了 prefix，把它本身转发给受控端
        if (nfds == 0) {
            if (prefix_wait) {
                prefix_wait = false;
                try injectBytes(tty, io, prefix_bytes[0..prefix_len]);
            }
            continue;
        }

        if (fds[0].revents != 0) {
            const n = try Io.File.readStreaming(stdin_file, io, &.{&buf});
            if (n == 0) continue;
            const b = buf[0];

            const ev = input_dec.push(b);

            if (comptime builtin.mode == .Debug) {
                std.log.info("stdin: {x:0>2} -> {s} prefix_wait={any}", .{ b, @tagName(ev), prefix_wait });
            }

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
