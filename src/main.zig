const std = @import("std");
const Io = std.Io;
const posix = std.posix;

/// TIOCSTI: 伪造一个字符注入到 tty 的输入队列（等价于键盘输入）。
/// 定义来自内核头文件 /usr/include/asm-generic/ioctls.h，stdlib 未收录。
const TIOCSTI: u32 = 0x5412;

pub fn main(init: std.process.Init) !void {
    const arena: std.mem.Allocator = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 3) {
        std.log.err("用法: sudo {s} <tty slave 路径> \"要透传的命令\"", .{args[0]});
        std.process.exit(2);
    }

    // 打开目标 tty 的 slave 文件（物理 tty 或 pts）。
    const tty = try Io.Dir.openFileAbsolute(io, args[1], .{
        .mode = .read_write,
    });
    defer Io.File.close(tty, io);

    // 传入单个参数，自动追加换行符，与 a.py 一致。
    var cmd: []const u8 = args[2];
    const newline_buf = [_]u8{'\n'};
    cmd = try std.mem.concat(arena, u8, &.{ cmd, &newline_buf });

    // 逐字节注入 tty 输入队列。
    for (cmd) |ch| {
        const result = try io.operate(.{
            .device_io_control = .{
                .file = tty,
                .code = TIOCSTI,
                .arg = @constCast(&ch),
            },
        });
        if (result.device_io_control < 0) {
            std.log.err("TIOCSTI 注入失败: {}", .{result.device_io_control});
            std.process.exit(1);
        }
    }
}
