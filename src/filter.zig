//! 选择性透传过滤器：受控端输出（镜像路径）→ 我们的终端。
//!
//! 设计约束：
//! - 我们是第三方，不能干涉受控端与其自己终端（master/物理设备）的协商；
//!   受控端侧链路完全自洽，我们不在其中，无需也不该改动任何字节。
//! - 唯一的泄漏点：镜像把查询/协商序列转发给我们的终端后，我们的终端会
//!   应答（写入我们的 stdin），应答会被注入回受控端 → duplicate；受控端
//!   是物理 tty 时，一个本不该存在的 kitty 应答是未定义行为。
//! - 因此只过滤"会让我们终端开口说话、或改变我们终端输入编码/事件流"
//!   的序列，其余（可见输出、纯渲染指令、bracketed paste 等）原样透传。
//!
//! 过滤规则：
//! 丢弃（序列在我们的屏幕上本就不产生可见输出，丢弃零视觉损失）：
//! - 查询类：DA1/DA2（CSI c）、DSR/CPR（CSI n）、DECRQSS（DCS $ q）、
//!   XTGETTCAP（DCS + q）、XTVERSION（CSI > 0 q）、DECRQM（CSI Ps $ p）、
//!   OSC 的 '?' 查询（OSC 11;?、OSC 52;c;? 等）、kitty 键盘协议查询（CSI ? u）
//! - 协商/改输入模式类：kitty 键盘协议开启（CSI > u）、modifyOtherKeys
//!   （CSI > 4 m）、鼠标追踪（CSI ? 1000-1006/1015/1016/9 h）、
//!   focus 报告（CSI ? 1004 h）、kitty graphics（APC "G"）——这些会让
//!   我们的终端应答或改变输入编码/产生事件流，转发进受控端会造成
//!   duplicate 或受控端无法解析的输入格式。

const std = @import("std");
const vt = @import("vt/Parser.zig");

const log = std.log.scoped(.filter);

/// 丢弃的 DECSET/DECRST 模式（'?' h/l）：会让我们的终端应答或产生输入事件流。
const drop_modes = [_]u16{ 9, 1000, 1002, 1003, 1004, 1005, 1006, 1015, 1016, 2026 };

fn contains(haystack: []const u8, needle: u8) bool {
    return std.mem.indexOfScalar(u8, haystack, needle) != null;
}

fn classifyCsi(it: vt.Action.CSI) bool {
    // kitty 键盘协议：CSI > flags u（push 开启）、CSI < n u（pop）、
    // CSI = flags u（set 开启）、CSI ? u（查询）→ 全部丢弃，否则我们终端
    // 会被开启 kitty 键盘模式，输入变成 CSI code;mods u 序列（实测 Ctrl+6
    // 变成 CSI 54;5 u），前缀键 0x1e 再也收不到
    if (it.final == 'u' and (contains(it.intermediates, '>') or contains(it.intermediates, '?') or
        contains(it.intermediates, '=') or contains(it.intermediates, '<')))
        return false;
    // modifyOtherKeys：CSI > 4 m / CSI > 4;2 m → 丢弃（改变我们终端的输入编码）
    if (it.final == 'm' and contains(it.intermediates, '>')) return false;
    // DA1/DA2：CSI [?_] ... c → 丢弃
    if (it.final == 'c') return false;
    // DSR/CPR：CSI [?_] ... n → 丢弃
    if (it.final == 'n') return false;
    // XTVERSION（CSI > 0 q）与 DECRQM（CSI Ps $ q）→ 丢弃；DECSCUSR（CSI Ps q）转发
    if (it.final == 'q' and (contains(it.intermediates, '>') or contains(it.intermediates, '$')))
        return false;
    // DECRQM 查询：CSI Ps $ p → 丢弃
    if (it.final == 'p' and contains(it.intermediates, '$')) return false;
    // DECSET/DECRST（CSI ? Ps h/l）：查丢弃表；纯渲染模式（25 光标、1049 备屏、
    // 2004 bracketed paste 等）原样转发
    if ((it.final == 'h' or it.final == 'l') and contains(it.intermediates, '?')) {
        const mode: u16 = if (it.params.len > 0) it.params[0] else 0;
        for (drop_modes) |m| {
            if (mode == m) return false;
        }
    }
    return true;
}

fn classifyOsc(cmd: vt.osc.Command) bool {
    // 查询：负载以 '?' 结尾（OSC 10/11/12/4/7/52/104/110-112/1337 ...;?）→ 丢弃
    return !cmd.isQuery();
}

fn classifyDcs(it: vt.Action.DCS) bool {
    // DECRQSS（DCS $ q）与 XTGETTCAP（DCS + q）→ 丢弃；sixel 等其余转发
    if (contains(it.intermediates, '$') and it.final == 'q') return false;
    if (contains(it.intermediates, '+') and it.final == 'q') return false;
    return true;
}

/// 镜像输出过滤器。
/// 用法：逐字节 push，返回需要转发到我们终端的字节（null 表示丢弃）。
pub const Filter = struct {
    parser: vt.Parser,
    alloc: std.mem.Allocator,
    /// 当前序列的缓存字节（从序列起始到终结符）。
    pending: std.ArrayList(u8),
    /// 当前序列的转发决定；null = 无决定（CAN 中止的残缺序列按转发处理）。
    forward: ?bool = null,
    /// 丢弃模式下继续吞掉后续字节（如 kitty graphics 的大负载）。
    dropping: bool = false,
    /// 独立字节（ground→ground）返回用的稳定缓冲。
    one: [1]u8 = undefined,

    pub fn init(alloc: std.mem.Allocator) Filter {
        return .{
            .parser = vt.init(),
            .alloc = alloc,
            .pending = .empty,
        };
    }

    pub fn deinit(self: *Filter) void {
        self.pending.deinit(self.alloc);
        self.parser.deinit();
    }

    /// 返回需要写入我们终端的字节切片（指向内部缓存，下次 push 前有效），
    /// 或 null 表示丢弃。
    pub fn push(self: *Filter, c: u8) ?[]const u8 {
        if (self.dropping) {
            self.applyActions(c);
            return null;
        }

        const prev = self.parser.state;
        const actions = self.parser.next(c);

        // 独立字节（ground→ground）：立即原样转发，不经过缓存
        if (prev == .ground and self.parser.state == .ground) {
            self.one[0] = c;
            return self.one[0..1];
        }

        // 序列字节：先缓存，dispatch 时再决定
        const before_len = self.pending.items.len;
        self.pending.append(self.alloc, c) catch |err| {
            log.err("pending 追加失败: {any}", .{err});
            return null;
        };

        for (actions) |a| {
            const act = a orelse continue;
            switch (act) {
                .csi_dispatch => |it| self.forward = classifyCsi(it),
                // 注意：不能设置 forward=true —— ESC \ (ST) 也会触发 esc_dispatch，
                // 会覆盖 OSC/DCS 序列的丢弃决定；默认 null 已按转发处理。
                .osc_dispatch => |cmd| self.forward = classifyOsc(cmd),
                .dcs_hook => |d| self.forward = classifyDcs(d),
                .apc_start => self.forward = null,
                .apc_put => |b| {
                    // kitty graphics：APC 第一个负载字节是 'G'。
                    // before_len 是追加前的长度：7-bit 形式已有 ESC _（2），
                    // 8-bit 形式已有 0x9F（1）。
                    const is_gfx_start = b == 'G' and
                        ((before_len == 2 and self.pending.items[0] == 0x1b and
                        self.pending.items[1] == '_') or
                        (before_len == 1 and self.pending.items[0] == 0x9f));
                    if (is_gfx_start) {
                        self.forward = false;
                        self.dropping = true;
                        // 丢弃已开始的序列字节（ESC _ G），避免泄漏到下一个序列
                        self.pending.items.len = 0;
                        return null;
                    }
                },
                .dcs_unhook, .apc_end => {},
                else => {},
            }
        }

        // 序列结束（回到 ground，如终结符 BEL/ESC\ 或 CAN 中止）→ 按决定转发/丢弃。
        // 注意：不能在此调用 clearRetainingCapacity()，它会 memset 抹掉缓冲，
        // 返回的切片在调用方写入前必须保持有效；直接复位长度即可。
        // forward 必须一并复位，否则上一个序列的决定（如丢弃）会泄漏到
        // 下一个序列（如 UTF-8 多字节）的 ground 返回路径。
        if (prev != .ground and self.parser.state == .ground) {
            const result: ?[]const u8 = if (self.forward orelse true) self.pending.items else null;
            self.pending.items.len = 0;
            self.forward = null;
            return result;
        }

        return null;
    }

    /// 丢弃模式下仍要喂解析器保持状态同步；回到 ground 即序列结束。
    fn applyActions(self: *Filter, c: u8) void {
        _ = self.parser.next(c);
        if (self.parser.state == .ground) {
            self.dropping = false;
            self.forward = null;
            self.pending.items.len = 0;
        }
    }
};

// ---- 输入路径（我们的终端 → 受控端）----
//
// 原则：用户输入绝不过滤，只识别两种特殊输入：
//   1. 前缀键 Ctrl+6 —— 裸字节 0x1e（终端未开 kitty 键盘模式），或
//      kitty 键事件 CSI 54;... u（code=54='6' 且带 ctrl 位；我们的终端
//      若处于 kitty 键盘模式，所有按键都会编码成 CSI code;mods u）。
//   2. kitty 键事件本身 —— 需要解码才能判断"下一个键"是 x（退出）还是
//      再次按 prefix（字面转发），其余事件原样转发。

/// kitty 键盘协议修饰键位（协议标准：shift=1 alt=2 ctrl=4 super=8 hyper=16 meta=32）。
const KITTY_MOD_CTRL: u32 = 4;

/// 前缀键判定：裸 0x1e 或 kitty 事件（code='6'=54 或直接 0x1e，且带 ctrl）。
fn isPrefixKey(code: u32, mods: u32) bool {
    if ((mods & KITTY_MOD_CTRL) == 0) return false;
    return code == 0x36 or code == 0x1e;
}

/// 输入解码器：逐字节喂入，识别 kitty 键事件；其余原样透传。
pub const Input = struct {
    /// 状态机缓冲（CSI ... u 序列，kitty 事件不会太长）。
    buf: [64]u8 = undefined,
    len: usize = 0,
    /// 是否出现了中间符（0x20-0x2f）——带中间符的 'u' 是应答/协商而非键事件。
    has_intermediates: bool = false,

    pub const Key = struct {
        code: u32,
        mods: u32,
        payload: []const u8,
    };

    pub const Event = union(enum) {
        /// 原样转发（payload 指向内部缓冲，下次 push 前有效）。
        forward: []const u8,
        /// kitty 键事件：原样转发 payload（prefix 检测已在内部完成）。
        key: Key,
        /// 前缀键 Ctrl+6：不转发；payload 是原始字节（超时/双击时转发）。
        prefix: []const u8,
    };

    pub fn push(self: *Input, c: u8) Event {
        switch (self.len) {
            0 => {
                if (c == 0x1b) {
                    self.buf[0] = c;
                    self.len = 1;
                    return .{ .forward = &.{} };
                }
                if (c == 0x9b) { // 8-bit CSI
                    self.buf[0] = c;
                    self.len = 1;
                    self.has_intermediates = false;
                    return .{ .forward = &.{} };
                }
                if (c == 0x1e) { // 裸 Ctrl+6（终端未开 kitty 键盘模式）
                    self.buf[0] = c;
                    return .{ .prefix = self.buf[0..1] };
                }
                self.buf[0] = c;
                return .{ .forward = self.buf[0..1] };
            },
            1 => {
                // 刚收到 ESC，等 '['；否则 flush ESC 并重处理本字节
                if (c == '[') {
                    self.buf[1] = c;
                    self.len = 2;
                    self.has_intermediates = false;
                    return .{ .forward = &.{} };
                }
                if (c == 0x18 or c == 0x1a) { // CAN/SUB 中止
                    self.buf[0] = 0x1b;
                    self.buf[1] = c;
                    self.len = 0;
                    return .{ .forward = self.buf[0..2] };
                }
                // 非 CSI 的 ESC 序列（ESC 7、ESC O A 等）整体原样转发，
                // 该字节本身若又是 ESC 则从 ESC 状态继续
                self.len = 0;
                if (c == 0x1b) {
                    self.buf[0] = 0x1b;
                    self.len = 1;
                }
                return .{ .forward = self.buf[0..1] };
            },
            else => {
                // CSI 序列中
                if (c >= 0x30 and c <= 0x3f) {
                    // 数字与分隔符（含 ';' ':'）——注意 0x3f '?' 在参数区合法但
                    // 罕见；中间符区是 0x20-0x2f
                    self.append(c);
                    return .{ .forward = &.{} };
                }
                if (c >= 0x20 and c <= 0x2f) {
                    self.has_intermediates = true;
                    self.append(c);
                    return .{ .forward = &.{} };
                }
                if (c >= 0x40 and c <= 0x7e) {
                    // final：完整序列
                    self.append(c);
                    const seq = self.take();
                    if (c == 'u' and !self.has_intermediates) {
                        if (parseKittyEvent(seq)) |key| {
                            if (isPrefixKey(key.code, key.mods)) return .{ .prefix = key.payload };
                            return .{ .key = key };
                        }
                    }
                    return .{ .forward = seq };
                }
                if (c == 0x18 or c == 0x1a) {
                    self.append(c);
                    const seq = self.take();
                    return .{ .forward = seq };
                }
                if (c == 0x1b) {
                    // 新 ESC 开始：flush 残缺序列，本字节作为新序列起点
                    const seq = self.buf[0..self.len];
                    self.len = 0;
                    self.buf[0] = 0x1b;
                    self.len = 1;
                    return .{ .forward = seq };
                }
                // 其余控制字符：flush 当前缓冲并转发
                self.append(c);
                const seq = self.take();
                return .{ .forward = seq };
            },
        }
    }

    fn append(self: *Input, c: u8) void {
        if (self.len < self.buf.len) {
            self.buf[self.len] = c;
            self.len += 1;
        }
    }

    fn take(self: *Input) []const u8 {
        const seq = self.buf[0..self.len];
        self.len = 0;
        return seq;
    }
};

/// 解析 kitty 键事件负载（如 "ESC[54;5u" / "ESC[54:55:54;5:1;120u"）：
/// 返回 key code 与 mods，非事件格式返回 null。
fn parseKittyEvent(seq: []const u8) ?Input.Key {
    // 跳过 ESC 与 '['
    var i: usize = 0;
    if (seq.len >= 2 and seq[0] == 0x1b and seq[1] == '[') {
        i = 2;
    } else if (seq.len >= 2 and seq[0] == 0x9b) {
        i = 1;
    } else return null;

    // 第一段（到 ';' 或 final）：key code（可能含 ':' 分隔的 alternate codes）
    var code: u32 = 0;
    var have_code = false;
    while (i < seq.len and seq[i] != ';' and seq[i] != 'u') : (i += 1) {
        if (seq[i] == ':') break;
        if (seq[i] >= '0' and seq[i] <= '9') {
            code = code * 10 + (seq[i] - '0');
            have_code = true;
        } else return null;
    }
    if (!have_code) return null;

    // 第二段：mods（到 final 'u'；可能含 ':' 事件类型）
    var mods: u32 = 0;
    var in_mods = false;
    while (i < seq.len and seq[i] != 'u') : (i += 1) {
        if (seq[i] == ';') {
            in_mods = true;
            continue;
        }
        if (in_mods and seq[i] == ':') break;
        if (in_mods and seq[i] >= '0' and seq[i] <= '9') {
            mods = mods * 10 + (seq[i] - '0');
        }
    }

    return .{ .code = code, .mods = mods, .payload = seq };
}

// ---- 回归测试 ----

const testing = std.testing;

fn filterBytes(alloc: std.mem.Allocator, input: []const u8) ![]const u8 {
    var f = Filter.init(alloc);
    defer f.deinit();
    var out = std.ArrayList(u8).empty;
    defer out.deinit(alloc);
    for (input) |b| {
        if (f.push(b)) |s| try out.appendSlice(alloc, s);
    }
    return out.toOwnedSlice(alloc);
}

fn expectForward(input: []const u8) !void {
    const out = try filterBytes(testing.allocator, input);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(input, out);
}

fn expectDrop(input: []const u8) !void {
    const out = try filterBytes(testing.allocator, input);
    defer testing.allocator.free(out);
    try testing.expectEqualSlices(u8, &.{}, out);
}

fn expectOut(input: []const u8, expected: []const u8) !void {
    const out = try filterBytes(testing.allocator, input);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(expected, out);
}

test "转发：普通内容" {
    try expectForward("hello world\n");
    try expectForward("你好\xe2\x98\x83");
}

test "转发：纯渲染指令" {
    try expectForward("\x1b[38;5;196m红\x1b[0m");
    try expectForward("\x1b[?25h");
    try expectForward("\x1b[?1049h");
    try expectForward("\x1b[?2004h");
    try expectForward("\x1b[3;5H");
    try expectForward("\x1b[5 q");
    try expectForward("\x1b[?1h");
    try expectForward("\x1b7");
    try expectForward("\x1b]2;t\x1b\\");
    try expectForward("\x1b]2;t\x07");
    try expectForward("\x1b]52;c;abcd\x1b\\");
    try expectForward("\x1b]133;A\x1b\\");
    try expectForward("\x1bPq...\x1b\\");
    try expectForward("\x1b[12\x18rest");
    try expectForward("ab\x1b[25hcd\x1b]2;t\x07ef");
}

test "丢弃：终端查询" {
    try expectDrop("\x1b[6n");
    try expectDrop("\x1b[c");
    try expectDrop("\x1b[?c");
    try expectDrop("\x1b[?u");
    try expectDrop("\x1b[>0q");
    try expectDrop("\x1b[1$p");
    try expectDrop("\x1b]11;?\x1b\\");
    try expectDrop("\x1b]11;?\x07");
    try expectDrop("\x1b]52;c;?\x1b\\");
    try expectDrop("\x1bP$qDECSCL\x1b\\");
    try expectDrop("\x1bP+q\x1b\\");
}

test "丢弃：输入模式协商" {
    try expectDrop("\x1b[>1u");
    try expectDrop("\x1b[>4m");
    try expectDrop("\x1b[?1006h");
    try expectDrop("\x1b[?1004h");
    try expectDrop("\x1b[=5u"); // kitty progressive enhancement (CSI = flags u)
    try expectDrop("\x1b[<1u"); // kitty 协议 pop
    try expectDrop("\x1b[>2;3u"); // kitty push 多参数
}

test "丢弃：kitty graphics" {
    try expectDrop("\x1b_Gf=32,s=10;AAAA\x1b\\");
    try expectDrop("\x9fGf=32,s=10;AAAA\x9c");
    try expectDrop("\x1b_Ga;b\x1b\\\x1b_Gc;d\x1b\\");
}

test "丢弃：kitty graphics 不影响周围内容" {
    try expectOut("前\x1b_Gf=32;AAAA\x1b\\后", "前后");
    try expectOut("a\x1b_Gx;y\x1b\\b\x1b_Gz;w\x1b\\c", "abc");
}

// ---- Input 解码器回归测试 ----

fn inputEvents(input: []const u8, alloc: std.mem.Allocator) !struct {
    payloads: std.ArrayList(u8),
    kinds: std.ArrayList(Input.Event.Tag),
} {
    var dec = Input{};
    var payloads = std.ArrayList(u8).empty;
    var kinds = std.ArrayList(Input.Event.Tag).empty;
    for (input) |b| {
        const ev = dec.push(b);
        switch (ev) {
            .forward => |bytes| {
                try payloads.appendSlice(alloc, bytes);
                try kinds.append(alloc, .forward);
            },
            .key => |k| {
                try payloads.appendSlice(alloc, k.payload);
                try kinds.append(alloc, .key);
            },
            .prefix => |bytes| {
                try payloads.appendSlice(alloc, bytes);
                try kinds.append(alloc, .prefix);
            },
        }
    }
    return .{ .payloads = payloads, .kinds = kinds };
}

test "Input: 普通字节直通" {
    const r = try inputEvents("hello\x0d\x0a", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("hello\x0d\x0a", r.payloads.items);
    for (r.kinds.items) |k| try testing.expectEqual(.forward, k);
}

test "Input: 裸 Ctrl+6 识别为前缀" {
    const r = try inputEvents("\x1e", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), r.kinds.items.len);
    try testing.expectEqual(Input.Event.Tag.prefix, r.kinds.items[0]);
    try testing.expectEqualSlices(u8, &.{0x1e}, r.payloads.items);
}

test "Input: kitty 键事件识别" {
    // 用户实测：Ctrl+6 在 kitty 模式下为 ESC[54;5u
    const r = try inputEvents("\x1b[54;5u", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), r.kinds.items.len);
    try testing.expectEqual(Input.Event.Tag.prefix, r.kinds.items[0]);
    try testing.expectEqualStrings("\x1b[54;5u", r.payloads.items);

    // 普通键：ESC[120;1u (x) → key 事件
    const r2 = try inputEvents("\x1b[120;1u", testing.allocator);
    defer r2.payloads.deinit(testing.allocator);
    defer r2.kinds.deinit(testing.allocator);
    try testing.expectEqual(Input.Event.Tag.key, r2.kinds.items[0]);
}

test "Input: kitty 事件直通不受影响" {
    // 无 ctrl 的普通键事件 + 交错文本
    const r = try inputEvents("a\x1b[97;1ub", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("a\x1b[97;1ub", r.payloads.items);
}

test "Input: 非 kitty 的 CSI 序列整体直通" {
    const r = try inputEvents("x\x1b[25hy", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("x\x1b[25hy", r.payloads.items);
}

test "Input: kitty 事件带事件类型与文本段" {
    // ESC[54:54;5:1;54u —— alternate codes + 事件类型 + 文本段
    const r = try inputEvents("\x1b[54:54;5:1;54u", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqual(Input.Event.Tag.prefix, r.kinds.items[0]);
}

test "Input: 带中间符的 u（应答/协商）不算键事件" {
    const r = try inputEvents("\x1b[?1u", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqual(Input.Event.Tag.forward, r.kinds.items[0]);
}

test "Input: 8-bit CSI kitty 事件" {
    const r = try inputEvents("\x9b54;5u", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqual(Input.Event.Tag.prefix, r.kinds.items[0]);
}

test "Input: 交错 kitty 与普通输入" {
    const r = try inputEvents("h\x1b[54;5ui\x1b[120;1u", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("h\x1b[54;5ui\x1b[120;1u", r.payloads.items);
    try testing.expectEqual(@as(usize, 4), r.kinds.items.len);
    try testing.expectEqual(Input.Event.Tag.forward, r.kinds.items[0]);
    try testing.expectEqual(Input.Event.Tag.prefix, r.kinds.items[1]);
    try testing.expectEqual(Input.Event.Tag.forward, r.kinds.items[2]);
    try testing.expectEqual(Input.Event.Tag.key, r.kinds.items[3]);
}
