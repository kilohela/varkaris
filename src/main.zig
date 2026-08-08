const std = @import("std");
const Io = std.Io;
const posix = std.posix;
const filter_mod = @import("filter.zig");

/// TIOCSTI: forge a character into the tty input queue (equivalent to a key press).
/// Defined in the kernel header /usr/include/asm-generic/ioctls.h, not in stdlib.
const TIOCSTI: u32 = 0x5412;

/// Input prefix key (tmux-style): Ctrl+6 = 0x1e (ASCII RS).
/// Terminal responses never contain 0x1e, and the mirror path filters out
/// response sources, so this cannot be triggered accidentally.
const PREFIX: u8 = 0x1e;
/// Pressing x after the prefix exits (tmux detach semantics).
const EXIT_KEY: u8 = 'x';
/// Timeout waiting for the key after the prefix (ms); on timeout the prefix
/// itself is forwarded to the controlled tty.
const PREFIX_TIMEOUT_MS: i32 = 1000;
/// Very short timeout for held-back bytes (ESC waiting for '[', partial CSI
/// sequences) in ms: escape sequence bytes arrive far faster than human
/// keystrokes, so a timeout means ESC was a standalone keypress — forward it.
/// Otherwise the first key after ESC in vim would be swallowed as sequence bytes.
const ESC_TIMEOUT_MS: i32 = 50;

/// Runtime of non-interactive mode (-c <command>) in ms: inject the command,
/// mirror-forward output for this duration, then exit.
const CMD_TIMEOUT_MS: i64 = 5000;

/// Current time in milliseconds on the monotonic clock (for non-interactive mode).
fn nowMs() i64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(std.os.linux.CLOCK.MONOTONIC, &ts);
    return @as(i64, @intCast(ts.sec)) * 1000 +
        @divTrunc(@as(i64, @intCast(ts.nsec)), std.time.ns_per_ms);
}

// ---- libbpf bindings (hand-written externs, avoiding @cImport) ----

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

/// Event in the ring buffer, matching struct event in probe.bpf.c.
const Event = extern struct {
    len: u32,
    data: [4096]u8,
};

const State = struct {
    io: Io,
    filter: *filter_mod.Filter,
};

/// Write mirrored bytes to stdout (blocking, streaming).
fn writeStdout(io: Io, bytes: []const u8) bool {
    Io.File.writeStreamingAll(Io.File.stdout(), io, bytes) catch return false;
    return true;
}

/// Sequence starter bytes (matches isStarter in filter.zig): if a data chunk
/// contains any of these it must go through the state machine byte by byte,
/// otherwise it can be forwarded as a whole.
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

/// Ring buffer callback: filter the controlled tty's output and write it to
/// our own terminal. Filter output is accumulated in batches (consecutive
/// plain bytes / short sequences merged into chunks) and written out once,
/// avoiding per-byte small writes on large output (images etc.) that would
/// slow consumption and overflow the ring.
/// Fast path: when the filter is idle and the chunk contains no sequence
/// starter bytes (large image base64 blocks), accumulate it as a whole,
/// skipping the byte-by-byte state machine.
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
                // Large slice (whole sequence, e.g. a big image chunk): write
                // it out directly without buffering.
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

    // Segmented processing: plain-text segments (no sequence starter bytes)
    // pass through in bulk while the filter is idle (one memcpy); sequence
    // segments go through the state machine byte by byte. Image events contain
    // only 2-3 ESC bytes each, so per-byte pushes drop from ~2048 to ~30,
    // speeding up consumption by an order of magnitude.
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

/// Inject one byte into the controlled tty's input queue.
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
        std.log.err("TIOCSTI injection failed: {}", .{result.device_io_control});
        std.process.exit(1);
    }
}

/// Inject multiple bytes (TIOCSTI takes one byte per call).
fn injectBytes(tty: Io.File, io: Io, bytes: []const u8) !void {
    for (bytes) |b| try injectByte(tty, io, b);
}

fn checkObj(ptr: ?*anyopaque, what: []const u8) !*anyopaque {
    if (ptr == null) {
        std.log.err("libbpf: {s} failed", .{what});
        return error.LibbpfFailed;
    }
    return ptr.?;
}

fn checkErr(rc: c_int, what: []const u8) !void {
    if (rc < 0) {
        var buf: [256]u8 = undefined;
        _ = libbpf_strerror(rc, &buf, buf.len);
        std.log.err("libbpf: {s} failed: {s}", .{ what, std.mem.sliceTo(&buf, 0) });
        return error.LibbpfFailed;
    }
}

pub fn main(init: std.process.Init) !void {
    const arena: std.mem.Allocator = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(arena);
    var command: ?[]const u8 = null;
    if (args.len == 4 and std.mem.eql(u8, args[2], "-c")) {
        command = args[3]; // non-interactive: run a command on the controlled tty then exit
    } else if (args.len != 2) {
        std.log.err("usage: sudo {s} <tty slave path> [-c <command>]", .{args[0]});
        std.process.exit(2);
    }
    const tty_path = args[1];

    // Open the target tty's slave file (physical tty or pts).
    const tty = try Io.Dir.openFileAbsolute(io, tty_path, .{
        .mode = .read_write,
    });
    defer Io.File.close(tty, io);

    // Our console (stdin): save the original termios, switch to non-canonical
    // mode with echo and ISIG off (otherwise Ctrl+C becomes SIGINT) in
    // interactive mode; restore on exit.
    const stdin_handle = posix.STDIN_FILENO;
    const orig_term = try posix.tcgetattr(stdin_handle);
    defer posix.tcsetattr(stdin_handle, .NOW, orig_term) catch {};

    var raw = orig_term;
    raw.lflag.ICANON = false;
    raw.lflag.ECHO = false;
    raw.lflag.ISIG = false; // otherwise Ctrl+C is turned into SIGINT by the terminal driver
    raw.iflag.ICRNL = false; // otherwise the terminal driver converts \r to \n
    raw.cc[@intFromEnum(posix.V.MIN)] = 1; // return as soon as data is available
    raw.cc[@intFromEnum(posix.V.TIME)] = 0;
    try posix.tcsetattr(stdin_handle, .NOW, raw);

    // ---- Load the BPF object and attach the fentry program ----

    // BPF object embedded at compile time (@embedFile; build.zig provides the
    // search path via addInstallFileWithDir).
    const bpf_bytes = @embedFile("probe.bpf.o");
    const obj: *bpf_object = @ptrCast(try checkObj(
        bpf_object__open_mem(bpf_bytes.ptr, bpf_bytes.len, null),
        "bpf_object__open_mem",
    ));
    defer bpf_object__close(obj);

    // Load the program (maps are created in the kernel at this point).
    try checkErr(bpf_object__load(obj), "bpf_object__load");

    // Get the target tty's device number (major/minor) via statx and write it
    // into the filter map.
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
    try checkErr(bpf_map__update_elem(target_dev, &key, 4, &target_dev_value, 8, 0), "target_dev update");
    std.log.debug("target tty: major={d} minor={d}", .{ st.rdev_major, st.rdev_minor });

    // Attach the fexit program (libbpf picks bpf_program__attach_trace
    // automatically from SEC("fexit/n_tty_write")).
    const prog: *bpf_program = @ptrCast(try checkObj(
        bpf_object__find_program_by_name(obj, "capture_tty_write_exit"),
        "find_program_by_name",
    ));
    const link: *bpf_link = @ptrCast(try checkObj(bpf_program__attach(prog), "bpf_program__attach"));
    _ = link;

    // Ring buffer consumption.
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

    // Non-interactive mode: inject command + carriage return (\r) into the
    // controlled tty and start the timer.
    var start_ms: i64 = 0;
    if (command) |cmd| {
        try injectBytes(tty, io, cmd);
        try injectBytes(tty, io, "\r");
        start_ms = nowMs();
    }

    // ---- Main loop: poll stdin (injection, tmux-style prefix) + poll ringbuf (mirror) ----

    const stdin_file = Io.File.stdin();
    var buf: [1]u8 = undefined;
    var input_dec = filter_mod.Input{};
    var prefix_wait = false;
    var prefix_bytes: [64]u8 = undefined; // kitty event payloads are at most 64 bytes
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
            // Non-interactive: cap poll timeout (max 1s); exit at CMD_TIMEOUT_MS.
            const elapsed = nowMs() - start_ms;
            const remain = CMD_TIMEOUT_MS - elapsed;
            if (remain <= 0) break;
            const cap: i32 = @intCast(@min(remain, 1000));
            timeout_ms = if (timeout_ms < 0 or timeout_ms > cap) cap else timeout_ms;
        }
        const nfds = posix.poll(&fds, timeout_ms) catch continue;

        // Timeout: the prefix was pressed alone, or ESC / a partial sequence
        // is pending -> forward independently.
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

            // Debug-level log: printed by default in Debug builds, compiled
            // away in Release builds.
            std.log.debug("stdin: {x:0>2} -> {s} prefix_wait={any}", .{ b, @tagName(ev), prefix_wait });

            switch (ev) {
                .prefix => |bytes| {
                    // Ctrl+6: enter prefix wait (or a second press = literal forward)
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
                    // kitty key event (ordinary keys forwarded verbatim)
                    if (prefix_wait) {
                        if (k.code == EXIT_KEY and (k.mods & 4) == 0) break; // prefix then x exits
                        prefix_wait = false; // other keys: prefix is swallowed, only the key is forwarded
                    }
                    try injectBytes(tty, io, k.payload);
                },
                .forward => |bytes| {
                    // Ordinary bytes / non-kitty sequences (verbatim; in raw
                    // mode x while waiting exits)
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

// Zig 0.16 only runs test blocks in the root file; the module must be
// referenced explicitly for its tests to run.
test {
    _ = @import("filter.zig");
}
