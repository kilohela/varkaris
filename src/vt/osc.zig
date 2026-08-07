//! 极简 OSC 解析器 stub：仅缓存原始负载，供选择性透传过滤器分类。
//! 原实现（ghostty src/terminal/osc.zig）依赖整个 terminal 模块（simd、
//! datastruct、quirks 等），varkaris 只需要判断该 OSC 是否为查询
//! （负载以 '?' 结尾，如 "11;?"），因此用这个接口兼容的极简版替代。

const std = @import("std");

pub const Command = struct {
    /// OSC 编号（前导数字，如 11、52、1337）。
    code: u32,
    /// 负载（不含编号，可能以 ';' 开头），切片指向 Parser 内部缓冲，
    /// 只在本次 end() 返回后、下次 reset() 前有效。
    payload: []const u8,

    /// 是否为查询：负载以 '?' 结尾（如 "11;?"、"52;c;?"）。
    /// 查询会让我们的终端应答并注入回受控端，必须丢弃。
    pub fn isQuery(self: Command) bool {
        return self.payload.len > 0 and self.payload[self.payload.len - 1] == '?';
    }
};

pub const Parser = struct {
    buffer: [4096]u8,
    len: usize,
    command: Command,

    pub fn init(_: ?std.mem.Allocator) Parser {
        return .{ .buffer = undefined, .len = 0, .command = undefined };
    }

    pub fn deinit(self: *Parser) void {
        _ = self;
    }

    pub fn reset(self: *Parser) void {
        self.len = 0;
    }

    pub fn next(self: *Parser, c: u8) void {
        if (self.len >= self.buffer.len) return; // 超长 OSC 与查询无关，直接丢弃缓存
        self.buffer[self.len] = c;
        self.len += 1;
    }

    pub fn end(self: *Parser, _: ?u8) ?*Command {
        const payload = self.buffer[0..self.len];
        var code: u32 = 0;
        var i: usize = 0;
        while (i < payload.len and payload[i] >= '0' and payload[i] <= '9') : (i += 1) {
            code = code * 10 + (payload[i] - '0');
        }
        self.command = .{ .code = code, .payload = payload[i..] };
        return &self.command;
    }
};
