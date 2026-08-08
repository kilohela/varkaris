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
//!   focus 报告（CSI ? 1004 h）——这些会让我们的终端应答或改变输入编码/
//!   产生事件流，转发进受控端会造成 duplicate 或受控端无法解析的输入格式。
//! - kitty graphics 查询（APC "G" 负载以 "q=" 开头）：受控端程序会从
//!   受控端 tty 的真实 master 收到应答，我们的终端应答再注入会造成重复；
//!   kitty graphics 图片数据序列（其余 APC "G"）是纯渲染指令，与 sixel
//!   一样原样透传。
//!
//! 序列识别用内联的极简状态机实现（vt100.net DEC ANSI 解析器的子集，
//! 只保留区分上述规则所需的部分）：ground / escape / csi / dcs / osc / apc，
//! 整个序列缓存到 pending，回到 ground 时按缓存的决定整体转发或丢弃。

const std = @import("std");
const log = std.log.scoped(.filter);

/// 丢弃的 DECSET/DECRST 模式（'?' h/l）：会让我们的终端应答或产生输入事件流。
const drop_modes = [_]u16{ 9, 1000, 1002, 1003, 1004, 1005, 1006, 1015, 1016, 2026 };

/// 状态机状态。
const State = enum {
    ground,
    escape, // ESC 之后，等待下一个字节
    csi,
    dcs, // 头部（等待 final）或负载（dcs_done 区分）
    osc,
    apc, // APC/PM/SOS 字符串
};

/// CSI 内部子状态：决定 0x3c-0x3f（'<='>?'）与 ':' 是私有标记还是非法字节。
const CsiSub = enum { entry, param, intermediate, ignore };

/// 中间符掩码：0x20-0x3f 的位图（DECSET 的 '?'、kitty 的 '>' 等）。
fn hasInter(inter: u32, c: u8) bool {
    return (inter >> @intCast(c - 0x20)) & 1 != 0;
}

fn setInter(inter: *u32, c: u8) void {
    inter.* |= @as(u32, 1) << @intCast(c - 0x20);
}

/// 8-bit C1 起始字节（与 7-bit ESC 前缀等价）。
fn isStarter(c: u8) bool {
    return c == 0x1b or c == 0x9b or c == 0x90 or c == 0x9d or c == 0x98 or c == 0x9e or c == 0x9f;
}

/// CSI 分类：true = 转发，false = 丢弃。
fn classifyCsi(inter: u32, mode: u32, final: u8) bool {
    // kitty 键盘协议：CSI [><=?] ... u（开启/设置/查询/pop）→ 丢弃，
    // 否则我们终端会被开启 kitty 键盘模式，输入变成 CSI code;mods u
    // 序列（实测 Ctrl+6 变成 CSI 54;5 u），前缀键 0x1e 再也收不到
    if (final == 'u' and (hasInter(inter, '>') or hasInter(inter, '?') or
        hasInter(inter, '=') or hasInter(inter, '<')))
        return false;
    // modifyOtherKeys：CSI > 4 m → 丢弃（改变我们终端的输入编码）
    if (final == 'm' and hasInter(inter, '>')) return false;
    // DA1/DA2：CSI [?_] ... c → 丢弃
    if (final == 'c') return false;
    // DSR/CPR：CSI [?_] ... n → 丢弃
    if (final == 'n') return false;
    // XTVERSION（CSI > 0 q）与 DECRQM（CSI Ps $ q）→ 丢弃；DECSCUSR（CSI Ps q）转发
    if (final == 'q' and (hasInter(inter, '>') or hasInter(inter, '$')))
        return false;
    // DECRQM 查询：CSI Ps $ p → 丢弃
    if (final == 'p' and hasInter(inter, '$')) return false;
    // DECSET/DECRST（CSI ? Ps h/l）：查丢弃表；纯渲染模式（25 光标、1049 备屏、
    // 2004 bracketed paste 等）原样转发
    if ((final == 'h' or final == 'l') and hasInter(inter, '?')) {
        for (drop_modes) |m| {
            if (mode == m) return false;
        }
    }
    return true;
}

/// DCS 分类：true = 转发，false = 丢弃。
fn classifyDcs(inter: u32, final: u8) bool {
    // DECRQSS（DCS $ q）与 XTGETTCAP（DCS + q）→ 丢弃；sixel 等其余转发
    if (final == 'q' and (hasInter(inter, '$') or hasInter(inter, '+'))) return false;
    return true;
}

/// 镜像输出过滤器。
/// 用法：逐字节 push，返回需要转发到我们终端的字节（null 表示丢弃）。
pub const Filter = struct {
    alloc: std.mem.Allocator,
    /// 当前序列的缓存字节（从序列起始到当前字节）。
    pending: std.ArrayList(u8),
    /// 当前序列的转发决定；null = 无决定（CAN 中止等残缺序列按转发处理）。
    forward: ?bool = null,
    /// kitty graphics 丢弃模式：继续吞掉后续字节直到序列结束。
    dropping: bool = false,
    /// 独立字节（ground→ground）返回用的稳定缓冲。
    one: [1]u8 = undefined,

    state: State = .ground,
    /// CSI/DCS 中间符掩码（0x20-0x3f 的位）。
    inter: u32 = 0,
    csi_sub: CsiSub = .entry,
    /// CSI 第一个参数（DECSET 模式判定用）。
    csi_param0: u32 = 0,
    csi_have_param: bool = false,
    csi_param_done: bool = false,
    /// DCS 头部是否已终结（true = 负载中）。
    dcs_done: bool = false,
    /// APC 是否处于第一个负载字节（kitty graphics 探测）。
    apc_first: bool = false,
    /// kitty graphics 探测进度：0 = 无，1 = 已见 'G' 等 'q'，2 = 已见 'Gq' 等 '='。
    apc_probe: u8 = 0,

    pub fn init(alloc: std.mem.Allocator) Filter {
        return .{
            .alloc = alloc,
            .pending = .empty,
        };
    }

    pub fn deinit(self: *Filter) void {
        self.pending.deinit(self.alloc);
    }

    /// 当前是否处于 ground 且无丢弃状态（无挂起序列）。
    /// 调用方可据此走快速路径：不含序列起始字节（ESC/C1）的数据块
    /// 可直接整体转发，无需逐字节过状态机（图片 base64 大块提速用）。
    pub fn isIdle(self: *const Filter) bool {
        return self.state == .ground and !self.dropping;
    }

    /// 返回需要写入我们终端的字节切片（指向内部缓存，下次 push 前有效），
    /// 或 null 表示丢弃。
    pub fn push(self: *Filter, c: u8) ?[]const u8 {
        if (self.dropping) {
            self.step(c);
            if (self.state == .ground) {
                self.dropping = false;
                self.forward = null;
                self.pending.items.len = 0;
            }
            return null;
        }

        // 独立字节（ground→ground）：立即原样转发
        if (self.state == .ground and !isStarter(c)) {
            self.one[0] = c;
            return self.one[0..1];
        }

        // 先跑状态机（分类基于追加前的缓存），再缓存本字节
        self.step(c);
        if (!self.dropping) {
            self.pending.append(self.alloc, c) catch |err| {
                log.err("pending 追加失败: {any}", .{err});
            };
        }

        // 序列结束（回到 ground）→ 按决定整体转发/丢弃。
        // 注意：不能 clearRetainingCapacity()，返回的切片在调用方写入前
        // 必须保持有效；直接复位长度即可。forward 必须一并复位，否则上一个
        // 序列的决定（如丢弃）会泄漏到下一个序列。
        if (self.state == .ground) {
            const result: ?[]const u8 = if (self.forward orelse true) self.pending.items else null;
            self.pending.items.len = 0;
            self.forward = null;
            return result;
        }
        return null;
    }

    fn step(self: *Filter, c: u8) void {
        switch (self.state) {
            .ground => switch (c) {
                '[', 0x9b => self.enterCsi(),
                ']', 0x9d => self.enterOsc(),
                'P', 0x90 => self.enterDcs(),
                '_', '^', 'X', 0x98, 0x9e, 0x9f => self.enterApc(),
                0x1b => self.state = .escape,
                else => unreachable, // push 保证是起始字节
            },
            .escape => self.stepEscape(c),
            .csi => self.stepCsi(c),
            .dcs => self.stepDcs(c),
            .osc => self.stepOsc(c),
            .apc => self.stepApc(c),
        }
    }

    fn enterCsi(self: *Filter) void {
        self.state = .csi;
        self.inter = 0;
        self.csi_sub = .entry;
        self.csi_param0 = 0;
        self.csi_have_param = false;
        self.csi_param_done = false;
    }

    fn enterDcs(self: *Filter) void {
        self.state = .dcs;
        self.inter = 0;
        self.dcs_done = false;
    }

    fn enterOsc(self: *Filter) void {
        self.state = .osc;
    }

    fn enterApc(self: *Filter) void {
        self.state = .apc;
        self.apc_first = true;
        self.apc_probe = 0;
    }

    fn stepEscape(self: *Filter, c: u8) void {
        // 序列起始（含 8-bit C1 形式）
        if (c == '[' or c == 0x9b) return self.enterCsi();
        if (c == ']' or c == 0x9d) return self.enterOsc();
        if (c == 'P' or c == 0x90) return self.enterDcs();
        if (c == '_' or c == '^' or c == 'X' or c == 0x98 or c == 0x9e or c == 0x9f)
            return self.enterApc();
        // 停留：ESC、中间符 0x20-0x2f、C0 控制符（0x1a SUB 除外）、DEL、0xa0+
        if (c == 0x1b or c == 0x7f or (c >= 0x20 and c <= 0x2f) or c <= 0x17 or
            c == 0x19 or (c >= 0x1c and c <= 0x1f) or c >= 0xa0) return;
        // 其余（esc_dispatch、CAN/SUB 中止、8-bit ST/C1）→ 序列结束
        self.state = .ground;
    }

    fn stepCsi(self: *Filter, c: u8) void {
        // final：分类后回 ground
        if (c >= 0x40 and c <= 0x7e) {
            if (self.csi_sub != .ignore)
                self.forward = classifyCsi(self.inter, if (self.csi_have_param) self.csi_param0 else 0, c);
            self.state = .ground;
            return;
        }
        // 8-bit 起始/中止（anywhere 规则；0x90/0x98 与 0x80-0x9a 重叠，先判起始）
        switch (c) {
            0x9b => return self.enterCsi(), // 新 CSI：旧 CSI 不分类，缓冲合并
            0x90 => return self.enterDcs(),
            0x9d => return self.enterOsc(),
            0x98, 0x9e, 0x9f => return self.enterApc(),
            else => {},
        }
        // 新 ESC 开始：旧 CSI 中止（不分类）
        if (c == 0x1b) {
            self.state = .escape;
            return;
        }
        // CAN/SUB、8-bit ST、其余 C1 → 序列中止
        if (c == 0x18 or c == 0x1a or c == 0x9c or (c >= 0x80 and c <= 0x9a)) {
            self.state = .ground;
            return;
        }
        // 停留：C0、DEL、0xa0+
        if (c == 0x7f or c <= 0x17 or c == 0x19 or (c >= 0x1c and c <= 0x1f) or c >= 0xa0) return;

        // 0x20-0x3f：按子状态处理
        switch (self.csi_sub) {
            .entry => {
                if (c >= 0x20 and c <= 0x2f) {
                    setInter(&self.inter, c);
                } else if (c >= 0x3c and c <= 0x3f) {
                    // 私有标记（< = > ?）：进中间符，进入参数态
                    setInter(&self.inter, c);
                    self.csi_sub = .param;
                } else if (c == 0x3a) {
                    self.csi_sub = .ignore;
                } else {
                    // 0x30-0x39 数字、0x3b ';'
                    self.csi_sub = .param;
                    self.csiDigit(c);
                }
            },
            .param => {
                if (c >= 0x20 and c <= 0x2f) {
                    setInter(&self.inter, c);
                    self.csi_sub = .intermediate;
                } else if (c >= 0x3c and c <= 0x3f) {
                    self.csi_sub = .ignore;
                } else {
                    // 0x30-0x39 数字、0x3a ':'、0x3b ';'
                    self.csiDigit(c);
                }
            },
            .intermediate => {
                if (c >= 0x20 and c <= 0x2f) {
                    setInter(&self.inter, c);
                } else {
                    // 0x30-0x3f
                    self.csi_sub = .ignore;
                }
            },
            .ignore => {},
        }
    }

    /// 只跟踪第一个参数（DECSET 模式判定用），其余参数忽略。
    fn csiDigit(self: *Filter, c: u8) void {
        if (c == ';' or c == ':') {
            if (!self.csi_have_param) {
                self.csi_param0 = 0;
                self.csi_have_param = true;
            }
            self.csi_param_done = true;
        } else if (!self.csi_param_done) {
            self.csi_param0 = self.csi_param0 * 10 + (c - '0');
            self.csi_have_param = true;
        }
    }

    fn stepDcs(self: *Filter, c: u8) void {
        if (self.dcs_done) {
            // 负载：ST/CAN/任意字节结束
            switch (c) {
                0x9b => self.enterCsi(),
                0x90 => self.enterDcs(),
                0x9d => self.enterOsc(),
                0x98, 0x9e, 0x9f => self.enterApc(),
                0x1b => self.state = .escape,
                0x18, 0x1a, 0x9c, 0x80...0x8f, 0x91...0x97, 0x99, 0x9a => self.state = .ground,
                else => {}, // 负载字节
            }
            return;
        }
        // 头部：final 到达时分类
        if (c >= 0x40 and c <= 0x7e) {
            self.forward = classifyDcs(self.inter, c);
            self.dcs_done = true;
            return;
        }
        switch (c) {
            0x20...0x2f, 0x3c...0x3f => setInter(&self.inter, c),
            0x9b => self.enterCsi(),
            0x90 => self.enterDcs(),
            0x9d => self.enterOsc(),
            0x98, 0x9e, 0x9f => self.enterApc(),
            0x1b => self.state = .escape,
            0x18, 0x1a, 0x9c, 0x80...0x8f, 0x91...0x97, 0x99, 0x9a => self.state = .ground,
            else => {}, // 参数 0x30-0x3b、C0、DEL、0xa0+
        }
    }

    fn stepOsc(self: *Filter, c: u8) void {
        // 终结/中止：先分类（负载末尾是否 '?'），再切换状态
        switch (c) {
            0x9b => {
                self.classifyOsc();
                self.enterCsi();
            },
            0x90 => {
                self.classifyOsc();
                self.enterDcs();
            },
            0x9d => {
                self.classifyOsc();
                self.enterOsc();
            },
            0x98, 0x9e, 0x9f => {
                self.classifyOsc();
                self.enterApc();
            },
            0x1b => {
                self.classifyOsc();
                self.state = .escape;
            },
            0x07, 0x18, 0x1a, 0x9c, 0x80...0x8f, 0x91...0x97, 0x99, 0x9a => {
                self.classifyOsc();
                self.state = .ground;
            },
            else => {}, // 负载字节（含 C0、DEL、0xa0+）
        }
    }

    /// OSC 查询（负载以 '?' 结尾，如 "11;?"、"52;c;?"）→ 丢弃。
    fn classifyOsc(self: *Filter) void {
        self.forward = !(self.pending.items.len > 0 and
            self.pending.items[self.pending.items.len - 1] == '?');
    }

    fn stepApc(self: *Filter, c: u8) void {
        // 探测 kitty graphics：负载以 "q=" 开头是查询（丢弃，避免我们的终端
        // 应答与受控端真实 master 的应答重复注入）；其余（图片数据、控制命令）
        // 是纯渲染指令，原样透传。7-bit 前缀 ESC _（2 字节）或 8-bit 前缀
        // 0x9f（1 字节）已在 pending 中。
        if (self.apc_first) {
            self.apc_first = false;
            const n = self.pending.items.len; // 尚未包含 c
            if (c == 'G' and ((n == 2 and self.pending.items[0] == 0x1b and
                self.pending.items[1] == '_') or
                (n == 1 and self.pending.items[0] == 0x9f)))
            {
                self.apc_probe = 1; // 已见 'G'，等 'q'
            }
        } else if (self.apc_probe != 0) {
            if (self.apc_probe == 1) {
                if (c == 'q') {
                    self.apc_probe = 2; // 已见 'Gq'，等 '='
                } else {
                    self.apc_probe = 0; // 图片数据，转发
                }
            } else {
                // 已见 'Gq'
                if (c == '=') {
                    // kitty graphics 查询：丢弃整个序列
                    self.forward = false;
                    self.dropping = true;
                    self.pending.items.len = 0;
                }
                self.apc_probe = 0;
            }
        }
        switch (c) {
            0x9b => self.enterCsi(),
            0x90 => self.enterDcs(),
            0x9d => self.enterOsc(),
            0x98, 0x9e, 0x9f => self.enterApc(),
            0x1b => self.state = .escape,
            0x18, 0x1a, 0x9c, 0x80...0x8f, 0x91...0x97, 0x99, 0x9a => self.state = .ground,
            else => {}, // 负载字节
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

/// 输入解码器：逐字节喂入，识别 kitty 键事件与 UTF-8 多字节；其余原样透传。
pub const Input = struct {
    /// 状态机缓冲（CSI ... u 序列，kitty 事件不会太长）。
    buf: [64]u8 = undefined,
    len: usize = 0,
    /// 是否出现了中间符（0x20-0x2f）——带中间符的 'u' 是应答/协商而非键事件。
    has_intermediates: bool = false,
    /// UTF-8 多字节序列剩余连续字节数（连续字节 0x80-0x9f 与 C1 控制字符区
    /// 重叠，必须按 UTF-8 语境区分，否则中文会被误判为 8-bit CSI 等）。
    utf8_left: u8 = 0,

    pub const Key = struct {
        code: u32,
        mods: u32,
        payload: []const u8,
    };

    pub const Event = union(enum) {
        pub const Tag = std.meta.FieldEnum(Event);

        /// 原样转发（payload 指向内部缓冲，下次 push 前有效）。
        forward: []const u8,
        /// kitty 键事件：原样转发 payload（prefix 检测已在内部完成）。
        key: Key,
        /// 前缀键 Ctrl+6：不转发；payload 是原始字节（超时/双击时转发）。
        prefix: []const u8,
    };

    /// 是否有挂起字节等待转发（ESC 等 '[' 或残缺 CSI 序列）。调用方应据此
    /// 设置极短 poll 超时，超时后调用 flush() 把挂起字节独立转发。
    pub fn pending(self: *const Input) bool {
        return self.len > 0;
    }

    /// 清空并返回挂起的字节（指向内部缓冲，下次 push 前有效）。
    pub fn flush(self: *Input) []const u8 {
        const seq = self.buf[0..self.len];
        self.len = 0;
        return seq;
    }

    pub fn push(self: *Input, c: u8) Event {
        switch (self.len) {
            0 => {
                if (self.utf8_left > 0) {
                    // UTF-8 连续字节：原样转发（0x80-0x9f 按 UTF-8 处理，不是 C1）
                    self.utf8_left -= 1;
                    self.buf[0] = c;
                    return .{ .forward = self.buf[0..1] };
                }
                if (c >= 0xc0) {
                    // UTF-8 多字节起始：0xC0-0xDF → 1 个连续字节，
                    // 0xE0-0xEF → 2 个，0xF0-0xFF → 3 个
                    self.utf8_left = if (c >= 0xf0) 3 else if (c >= 0xe0) 2 else 1;
                    self.buf[0] = c;
                    return .{ .forward = self.buf[0..1] };
                }
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
                // 已收到起始字节（ESC 等 '[' 或 8-bit CSI 0x9b 等序列内容）
                const started = self.buf[0];
                if (started == 0x1b and c == '[') {
                    // 7-bit CSI 序列开始
                    self.buf[1] = c;
                    self.len = 2;
                    self.has_intermediates = false;
                    return .{ .forward = &.{} };
                }
                if (c == 0x18 or c == 0x1a) { // CAN/SUB 中止
                    self.buf[0] = started;
                    self.buf[1] = c;
                    self.len = 0;
                    return .{ .forward = self.buf[0..2] };
                }
                if (started == 0x9b) {
                    // 8-bit CSI：本字节按序列内容处理
                    if (c >= 0x20 and c <= 0x3f) { // 参数/中间符
                        self.buf[1] = c;
                        self.len = 2;
                        return .{ .forward = &.{} };
                    }
                    if (c >= 0x40 and c <= 0x7e) { // final
                        self.buf[1] = c;
                        const seq = self.buf[0..2];
                        self.len = 0;
                        if (c == 'u' and !self.has_intermediates) {
                            if (parseKittyEvent(seq)) |key| {
                                if (isPrefixKey(key.code, key.mods)) return .{ .prefix = key.payload };
                                return .{ .key = key };
                            }
                        }
                        return .{ .forward = seq };
                    }
                }
                // ESC 后非 '['（或 0x9b 后非常规字节）：ESC 与本字节整体
                // 转发（不能吞掉后到的键，否则 vim 里 ESC 后的冒号会失效）
                self.buf[1] = c;
                self.len = 0;
                if (c >= 0xc0) { // 本字节是 UTF-8 起始：后续连续字节不再被 C1 判定
                    self.utf8_left = if (c >= 0xf0) 3 else if (c >= 0xe0) 2 else 1;
                }
                return .{ .forward = self.buf[0..2] };
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

/// 解析 kitty 键事件负载（如 "ESC[54;5u" / "ESC[54:55;54;5:1;120u"）：
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

test "丢弃：kitty graphics 查询" {
    try expectDrop("\x1b_Gq=1\x1b\\");
    try expectDrop("\x1b_Gq=2\x1b\\");
    try expectDrop("\x1b_Gq=1;s=10\x1b\\");
    try expectDrop("\x9fGq=1\x9c");
}

test "转发：kitty graphics 图片数据" {
    try expectForward("\x1b_Gf=32,s=10;AAAA\x1b\\");
    try expectForward("\x9fGf=32,s=10;AAAA\x9c");
    try expectForward("\x1b_Ga=f,f=32,s=10,v=10,m=1;AAAA\x1b\\\x1b_Gm=0;BBBB\x1b\\");
    try expectForward("\x1b_Ga;b\x1b\\\x1b_Gc;d\x1b\\");
}

test "kitty graphics 查询丢弃不影响周围内容" {
    try expectOut("前\x1b_Gq=1\x1b\\后", "前后");
    try expectOut("a\x1b_Gq=1\x1b\\b\x1b_Gq=2\x1b\\c", "abc");
}

test "序列合并：中止后接新序列按整体分类" {
    try expectDrop("\x1b[12\x1b[6n"); // CSI 内 ESC 中止，合并成查询
    try expectDrop("\x1b]11;?\x1b[6n"); // OSC 查询后被新 CSI 取代
}

test "序列合并：私有标记出现在参数之后按非法处理" {
    try expectForward("\x1b[?1006>h"); // csi_ignore → 无分类 → 转发
    try expectForward("\x1b[1>u");
}

/// Input 解码器测试辅助：逐字节喂入，收集 payload 与事件类型。
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
                // 空 payload（ESC 挂起、序列中途）不构成事件，跳过
                if (bytes.len == 0) continue;
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
    var r = try inputEvents("hello\x0d\x0a", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("hello\x0d\x0a", r.payloads.items);
    for (r.kinds.items) |k| try testing.expectEqual(.forward, k);
}

test "Input: UTF-8 中文（连续字节与 C1 区重叠）" {
    // 监 = E7 9B 91（0x9B 恰为 8-bit CSI，0x91 在 C1 区）
    var r = try inputEvents("\xe7\x9b\x91", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("\xe7\x9b\x91", r.payloads.items);

    // 你好 = E4 BD A0 E5 A5 BD
    var r2 = try inputEvents("\xe4\xbd\xa0\xe5\xa5\xbd", testing.allocator);
    defer r2.payloads.deinit(testing.allocator);
    defer r2.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("\xe4\xbd\xa0\xe5\xa5\xbd", r2.payloads.items);

    // emoji 4 字节 F0 9F 98 83（0x9F/0x98 均为 8-bit 起始字节）
    var r3 = try inputEvents("\xf0\x9f\x98\x83", testing.allocator);
    defer r3.payloads.deinit(testing.allocator);
    defer r3.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("\xf0\x9f\x98\x83", r3.payloads.items);
}

test "Input: UTF-8 与 ASCII 交错" {
    var r = try inputEvents("a\xe7\x9b\x91b", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("a\xe7\x9b\x91b", r.payloads.items);
}

test "Input: ESC 后跟普通键整体转发" {
    // vim: ESC 后按 :（0x3a 不是 CSI 起始，不能吞）
    var r = try inputEvents("\x1b:", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("\x1b:", r.payloads.items);

    // ESC j（vim 移动）
    var r2 = try inputEvents("\x1bj", testing.allocator);
    defer r2.payloads.deinit(testing.allocator);
    defer r2.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("\x1bj", r2.payloads.items);

    // ESC ESC
    var r3 = try inputEvents("\x1b\x1b", testing.allocator);
    defer r3.payloads.deinit(testing.allocator);
    defer r3.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("\x1b\x1b", r3.payloads.items);
}

test "Input: 挂起的 ESC 可超时 flush" {
    var dec = Input{};
    _ = dec.push(0x1b);
    try testing.expect(dec.pending());
    try testing.expectEqualStrings("\x1b", dec.flush());
    try testing.expect(!dec.pending());

    // 残缺 CSI（ESC[5）flush 原样返回
    var dec2 = Input{};
    _ = dec2.push(0x1b);
    _ = dec2.push('[');
    _ = dec2.push('5');
    try testing.expect(dec2.pending());
    try testing.expectEqualStrings("\x1b[5", dec2.flush());

    // flush 后解码器状态复位
    _ = dec2.push('x');
    const ev = dec2.push('y');
    try testing.expectEqual(Input.Event.Tag.forward, @as(Input.Event.Tag, ev));
}

test "Input: 裸 Ctrl+6 识别为前缀" {
    var r = try inputEvents("\x1e", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), r.kinds.items.len);
    try testing.expectEqual(Input.Event.Tag.prefix, r.kinds.items[0]);
    try testing.expectEqualSlices(u8, &.{0x1e}, r.payloads.items);
}

test "Input: kitty 键事件识别" {
    // 用户实测：Ctrl+6 在 kitty 模式下为 ESC[54;5u
    var r = try inputEvents("\x1b[54;5u", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), r.kinds.items.len);
    try testing.expectEqual(Input.Event.Tag.prefix, r.kinds.items[0]);
    try testing.expectEqualStrings("\x1b[54;5u", r.payloads.items);

    // 普通键：ESC[120;1u (x) → key 事件
    var r2 = try inputEvents("\x1b[120;1u", testing.allocator);
    defer r2.payloads.deinit(testing.allocator);
    defer r2.kinds.deinit(testing.allocator);
    try testing.expectEqual(Input.Event.Tag.key, r2.kinds.items[0]);
}

test "Input: kitty 事件直通不受影响" {
    // 无 ctrl 的普通键事件 + 交错文本
    var r = try inputEvents("a\x1b[97;1ub", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("a\x1b[97;1ub", r.payloads.items);
}

test "Input: 非 kitty 的 CSI 序列整体直通" {
    var r = try inputEvents("x\x1b[25hy", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("x\x1b[25hy", r.payloads.items);
}

test "Input: kitty 事件带事件类型与文本段" {
    // ESC[54:54;5:1;54u —— alternate codes + 事件类型 + 文本段
    var r = try inputEvents("\x1b[54:54;5:1;54u", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqual(Input.Event.Tag.prefix, r.kinds.items[0]);
}

test "Input: 带中间符的 u（应答/协商）不算键事件" {
    var r = try inputEvents("\x1b[?1u", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqual(Input.Event.Tag.forward, r.kinds.items[0]);
}

test "Input: 8-bit CSI kitty 事件" {
    var r = try inputEvents("\x9b54;5u", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqual(Input.Event.Tag.prefix, r.kinds.items[0]);
}

test "Input: 交错 kitty 与普通输入" {
    var r = try inputEvents("h\x1b[54;5ui\x1b[120;1u", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("h\x1b[54;5ui\x1b[120;1u", r.payloads.items);
    try testing.expectEqual(@as(usize, 4), r.kinds.items.len);
    try testing.expectEqual(Input.Event.Tag.forward, r.kinds.items[0]);
    try testing.expectEqual(Input.Event.Tag.prefix, r.kinds.items[1]);
    try testing.expectEqual(Input.Event.Tag.forward, r.kinds.items[2]);
    try testing.expectEqual(Input.Event.Tag.key, r.kinds.items[3]);
}
