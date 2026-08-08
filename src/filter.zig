//! Selective pass-through filter: controlled tty output (mirror path) -> our terminal.
//!
//! Design constraints:
//! - We are a third party: we must not interfere with the negotiation between
//!   the controlled tty and its own terminal (master / physical device). That
//!   link is fully self-contained; we are not part of it and must not alter
//!   any byte of it.
//! - The only leak point: after the mirror forwards a query/negotiation
//!   sequence to our terminal, our terminal responds (writing to our stdin),
//!   and the response gets injected back into the controlled tty -> duplicate.
//!   When the controlled tty is a physical tty, a kitty response that should
//!   not exist there is undefined behavior.
//! - Therefore we only filter sequences that would make our terminal speak,
//!   or change our terminal's input encoding / event stream. Everything else
//!   (visible output, pure rendering instructions, bracketed paste, ...) is
//!   passed through verbatim.
//!
//! Filter rules:
//! Drop (these sequences produce no visible output on our screen anyway, so
//! dropping them is visually lossless):
//! - Queries: DA1/DA2 (CSI c), DSR/CPR (CSI n), DECRQSS (DCS $ q),
//!   XTGETTCAP (DCS + q), XTVERSION (CSI > 0 q), DECRQM (CSI Ps $ p),
//!   OSC '?' queries (OSC 11;?, OSC 52;c;? etc.), kitty keyboard protocol
//!   queries (CSI ? u)
//! - Negotiation / input-mode changes: kitty keyboard protocol enable
//!   (CSI > u), modifyOtherKeys (CSI > 4 m), mouse tracking
//!   (CSI ? 1000-1006/1015/1016/9 h), focus reporting (CSI ? 1004 h) — these
//!   make our terminal respond or change its input encoding / event stream;
//!   forwarding them into the controlled tty causes duplicates or input
//!   formats the controlled side cannot parse.
//! - kitty graphics queries (APC "G" payload starting with "q="): the program
//!   on the controlled side gets its answer from the real master of the
//!   controlled tty; our terminal's answer injected again would duplicate it.
//!   kitty graphics image data sequences (other APC "G" payloads) are pure
//!   rendering instructions and pass through verbatim, like sixel.
//!
//! Sequence recognition uses an inline minimal state machine (a subset of the
//! vt100.net DEC ANSI parser, keeping only what is needed to apply the rules
//! above): ground / escape / csi / dcs / osc / apc. The whole sequence is
//! buffered in pending, and on return to ground it is forwarded or dropped as
//! a whole according to the cached decision.

const std = @import("std");
const log = std.log.scoped(.filter);

/// DECSET/DECRST modes ('?' h/l) to drop: they make our terminal respond or
/// produce an input event stream.
const drop_modes = [_]u16{ 9, 1000, 1002, 1003, 1004, 1005, 1006, 1015, 1016, 2026 };

/// State machine states.
const State = enum {
    ground,
    escape, // after ESC, waiting for the next byte
    csi,
    dcs, // header (waiting for final) or payload (distinguished by dcs_done)
    osc,
    apc, // APC/PM/SOS string
};

/// CSI sub-state: decides whether 0x3c-0x3f ('<='>?') and ':' are private
/// markers or illegal bytes.
const CsiSub = enum { entry, param, intermediate, ignore };

/// Intermediate-byte mask: bitmap of 0x20-0x3f (DECSET's '?', kitty's '>' etc.).
fn hasInter(inter: u32, c: u8) bool {
    return (inter >> @intCast(c - 0x20)) & 1 != 0;
}

fn setInter(inter: *u32, c: u8) void {
    inter.* |= @as(u32, 1) << @intCast(c - 0x20);
}

/// 8-bit C1 starter bytes (equivalent to a 7-bit ESC prefix).
fn isStarter(c: u8) bool {
    return c == 0x1b or c == 0x9b or c == 0x90 or c == 0x9d or c == 0x98 or c == 0x9e or c == 0x9f;
}

/// CSI classification: true = forward, false = drop.
fn classifyCsi(inter: u32, mode: u32, final: u8) bool {
    // kitty keyboard protocol: CSI [><=?] ... u (enable/set/query/pop) -> drop.
    // Otherwise our terminal enters kitty keyboard mode and input becomes
    // CSI code;mods u sequences (observed: Ctrl+6 becomes CSI 54;5 u) and the
    // 0x1e prefix key is never received again.
    if (final == 'u' and (hasInter(inter, '>') or hasInter(inter, '?') or
        hasInter(inter, '=') or hasInter(inter, '<')))
        return false;
    // modifyOtherKeys: CSI > 4 m -> drop (changes our terminal's input encoding)
    if (final == 'm' and hasInter(inter, '>')) return false;
    // DA1/DA2: CSI [?_] ... c -> drop
    if (final == 'c') return false;
    // DSR/CPR: CSI [?_] ... n -> drop
    if (final == 'n') return false;
    // XTVERSION (CSI > 0 q) and DECRQM (CSI Ps $ q) -> drop; DECSCUSR (CSI Ps q) forwards
    if (final == 'q' and (hasInter(inter, '>') or hasInter(inter, '$')))
        return false;
    // DECRQM query: CSI Ps $ p -> drop
    if (final == 'p' and hasInter(inter, '$')) return false;
    // DECSET/DECRST (CSI ? Ps h/l): consult the drop table; pure rendering
    // modes (25 cursor, 1049 alt screen, 2004 bracketed paste etc.) forward
    if ((final == 'h' or final == 'l') and hasInter(inter, '?')) {
        for (drop_modes) |m| {
            if (mode == m) return false;
        }
    }
    return true;
}

/// DCS classification: true = forward, false = drop.
fn classifyDcs(inter: u32, final: u8) bool {
    // DECRQSS (DCS $ q) and XTGETTCAP (DCS + q) -> drop; everything else
    // (sixel etc.) forwards
    if (final == 'q' and (hasInter(inter, '$') or hasInter(inter, '+'))) return false;
    return true;
}

/// Mirror output filter.
/// Usage: push bytes one by one; the returned slice must be forwarded to our
/// terminal (null means drop).
pub const Filter = struct {
    alloc: std.mem.Allocator,
    /// Bytes of the current sequence (from sequence start to the current byte).
    pending: std.ArrayList(u8),
    /// Forward decision for the current sequence; null = no decision yet
    /// (truncated sequences aborted by CAN etc. are treated as forward).
    forward: ?bool = null,
    /// kitty graphics drop mode: keep swallowing bytes until the sequence ends.
    dropping: bool = false,
    /// Stable buffer for standalone bytes (ground->ground) returned to the caller.
    one: [1]u8 = undefined,

    state: State = .ground,
    /// CSI/DCS intermediate byte mask (bits 0x20-0x3f).
    inter: u32 = 0,
    csi_sub: CsiSub = .entry,
    /// First CSI parameter (used for DECSET mode detection).
    csi_param0: u32 = 0,
    csi_have_param: bool = false,
    csi_param_done: bool = false,
    /// Whether the DCS header is done (true = inside the payload).
    dcs_done: bool = false,
    /// Whether APC is at its first payload byte (kitty graphics probe).
    apc_first: bool = false,
    /// kitty graphics probe progress: 0 = none, 1 = saw 'G' waiting for 'q',
    /// 2 = saw 'Gq' waiting for '='.
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

    /// Whether we are currently in ground without a drop in progress (no
    /// pending sequence). The caller can use this to take a fast path: a data
    /// chunk with no sequence starter bytes (ESC/C1) can be forwarded as a
    /// whole without the byte-by-byte state machine (speeds up large base64
    /// image blocks).
    pub fn isIdle(self: *const Filter) bool {
        return self.state == .ground and !self.dropping;
    }

    /// Returns the byte slice to write to our terminal (pointing into an
    /// internal buffer, valid until the next push), or null to drop.
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

        // Standalone byte (ground->ground): forward verbatim immediately.
        if (self.state == .ground and !isStarter(c)) {
            self.one[0] = c;
            return self.one[0..1];
        }

        // Run the state machine first (classification is based on the buffer
        // before appending), then buffer this byte.
        self.step(c);
        if (!self.dropping) {
            self.pending.append(self.alloc, c) catch |err| {
                log.err("pending append failed: {any}", .{err});
            };
        }

        // Sequence end (back to ground) -> forward/drop as a whole per the
        // decision.
        // Note: must not clearRetainingCapacity(); the returned slice must
        // stay valid until the caller writes it. Just reset the length.
        // forward must be reset too, otherwise the previous sequence's
        // decision (e.g. drop) leaks into the next one.
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
                else => unreachable, // push guarantees a starter byte
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
        // Sequence starters (including 8-bit C1 forms)
        if (c == '[' or c == 0x9b) return self.enterCsi();
        if (c == ']' or c == 0x9d) return self.enterOsc();
        if (c == 'P' or c == 0x90) return self.enterDcs();
        if (c == '_' or c == '^' or c == 'X' or c == 0x98 or c == 0x9e or c == 0x9f)
            return self.enterApc();
        // Stay: ESC, intermediates 0x20-0x2f, C0 controls (except 0x1a SUB),
        // DEL, 0xa0+
        if (c == 0x1b or c == 0x7f or (c >= 0x20 and c <= 0x2f) or c <= 0x17 or
            c == 0x19 or (c >= 0x1c and c <= 0x1f) or c >= 0xa0) return;
        // Everything else (esc_dispatch, CAN/SUB abort, 8-bit ST/C1) -> sequence ends
        self.state = .ground;
    }

    fn stepCsi(self: *Filter, c: u8) void {
        // Final: classify then return to ground
        if (c >= 0x40 and c <= 0x7e) {
            if (self.csi_sub != .ignore)
                self.forward = classifyCsi(self.inter, if (self.csi_have_param) self.csi_param0 else 0, c);
            self.state = .ground;
            return;
        }
        // 8-bit starters/aborts (anywhere rule; 0x90/0x98 overlap 0x80-0x9a,
        // so starters are checked first)
        switch (c) {
            0x9b => return self.enterCsi(), // new CSI: old CSI not classified, buffers merge
            0x90 => return self.enterDcs(),
            0x9d => return self.enterOsc(),
            0x98, 0x9e, 0x9f => return self.enterApc(),
            else => {},
        }
        // New ESC begins: old CSI aborts (not classified)
        if (c == 0x1b) {
            self.state = .escape;
            return;
        }
        // CAN/SUB, 8-bit ST, other C1 -> sequence aborts
        if (c == 0x18 or c == 0x1a or c == 0x9c or (c >= 0x80 and c <= 0x9a)) {
            self.state = .ground;
            return;
        }
        // Stay: C0, DEL, 0xa0+
        if (c == 0x7f or c <= 0x17 or c == 0x19 or (c >= 0x1c and c <= 0x1f) or c >= 0xa0) return;

        // 0x20-0x3f: handle per sub-state
        switch (self.csi_sub) {
            .entry => {
                if (c >= 0x20 and c <= 0x2f) {
                    setInter(&self.inter, c);
                } else if (c >= 0x3c and c <= 0x3f) {
                    // Private markers (< = > ?): record as intermediate, enter param state
                    setInter(&self.inter, c);
                    self.csi_sub = .param;
                } else if (c == 0x3a) {
                    self.csi_sub = .ignore;
                } else {
                    // 0x30-0x39 digits, 0x3b ';'
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
                    // 0x30-0x39 digits, 0x3a ':', 0x3b ';'
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

    /// Tracks only the first parameter (for DECSET mode detection); the rest
    /// are ignored.
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
            // Payload: ends on ST/CAN/any byte
            switch (c) {
                0x9b => self.enterCsi(),
                0x90 => self.enterDcs(),
                0x9d => self.enterOsc(),
                0x98, 0x9e, 0x9f => self.enterApc(),
                0x1b => self.state = .escape,
                0x18, 0x1a, 0x9c, 0x80...0x8f, 0x91...0x97, 0x99, 0x9a => self.state = .ground,
                else => {}, // payload byte
            }
            return;
        }
        // Header: classify on reaching the final
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
            else => {}, // parameters 0x30-0x3b, C0, DEL, 0xa0+
        }
    }

    fn stepOsc(self: *Filter, c: u8) void {
        // Terminator/abort: classify first (is the payload ending in '?'),
        // then switch state.
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
            else => {}, // payload byte (incl. C0, DEL, 0xa0+)
        }
    }

    /// OSC queries (payload ending in '?', e.g. "11;?", "52;c;?") -> drop.
    fn classifyOsc(self: *Filter) void {
        self.forward = !(self.pending.items.len > 0 and
            self.pending.items[self.pending.items.len - 1] == '?');
    }

    fn stepApc(self: *Filter, c: u8) void {
        // Probe kitty graphics: a payload starting with "q=" is a query (drop
        // it, so our terminal's answer is not injected, duplicating the real
        // master's answer on the controlled side); anything else (image data,
        // control commands) is a pure rendering instruction and passes
        // through. The 7-bit prefix ESC _ (2 bytes) or the 8-bit prefix 0x9f
        // (1 byte) is already in pending.
        if (self.apc_first) {
            self.apc_first = false;
            const n = self.pending.items.len; // does not include c yet
            if (c == 'G' and ((n == 2 and self.pending.items[0] == 0x1b and
                self.pending.items[1] == '_') or
                (n == 1 and self.pending.items[0] == 0x9f)))
            {
                self.apc_probe = 1; // saw 'G', waiting for 'q'
            }
        } else if (self.apc_probe != 0) {
            if (self.apc_probe == 1) {
                if (c == 'q') {
                    self.apc_probe = 2; // saw 'Gq', waiting for '='
                } else {
                    self.apc_probe = 0; // image data, forward
                }
            } else {
                // saw 'Gq'
                if (c == '=') {
                    // kitty graphics query: drop the whole sequence
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
            else => {}, // payload byte
        }
    }
};

// ---- Input path (our terminal -> controlled tty) ----
//
// Principle: user input is never filtered; only two special inputs are
// recognized:
//   1. The prefix key Ctrl+6 — as a raw byte 0x1e (terminal without kitty
//      keyboard mode), or as a kitty key event CSI 54;... u (code=54='6' with
//      the ctrl bit; when our terminal is in kitty keyboard mode every key is
//      encoded as CSI code;mods u).
//   2. kitty key events themselves — they must be decoded to know whether the
//      next key is x (exit) or another prefix press (literal forward); all
//      other events forward verbatim.

/// kitty keyboard protocol modifier bits (per the protocol:
/// shift=1 alt=2 ctrl=4 super=8 hyper=16 meta=32).
const KITTY_MOD_CTRL: u32 = 4;

/// Prefix key detection: raw 0x1e or a kitty event (code='6'=54 or 0x1e itself,
/// with ctrl set).
fn isPrefixKey(code: u32, mods: u32) bool {
    if ((mods & KITTY_MOD_CTRL) == 0) return false;
    return code == 0x36 or code == 0x1e;
}

/// Input decoder: feed bytes one by one; recognizes kitty key events and
/// multi-byte UTF-8; everything else passes through verbatim.
pub const Input = struct {
    /// State machine buffer (CSI ... u sequences; kitty events are short).
    buf: [64]u8 = undefined,
    len: usize = 0,
    /// Whether an intermediate byte (0x20-0x2f) appeared — a 'u' with
    /// intermediates is a response/negotiation, not a key event.
    has_intermediates: bool = false,
    /// Remaining continuation bytes of a multi-byte UTF-8 sequence
    /// (continuation bytes 0x80-0x9f overlap the C1 control range and must be
    /// disambiguated by UTF-8 context, otherwise Chinese text would be
    /// misread as 8-bit CSI etc.).
    utf8_left: u8 = 0,

    pub const Key = struct {
        code: u32,
        mods: u32,
        payload: []const u8,
    };

    pub const Event = union(enum) {
        pub const Tag = std.meta.FieldEnum(Event);

        /// Forward verbatim (payload points into an internal buffer, valid
        /// until the next push).
        forward: []const u8,
        /// kitty key event: forward the payload verbatim (prefix detection
        /// already done internally).
        key: Key,
        /// The prefix key Ctrl+6: do not forward; the payload is the raw bytes
        /// (forwarded on timeout or double press).
        prefix: []const u8,
    };

    /// Whether bytes are held back pending forwarding (ESC waiting for '[',
    /// or a partial CSI sequence). The caller should use a very short poll
    /// timeout accordingly and call flush() to forward the held-back bytes
    /// independently on timeout.
    pub fn pending(self: *const Input) bool {
        return self.len > 0;
    }

    /// Clear and return the held-back bytes (pointing into an internal buffer,
    /// valid until the next push).
    pub fn flush(self: *Input) []const u8 {
        const seq = self.buf[0..self.len];
        self.len = 0;
        return seq;
    }

    pub fn push(self: *Input, c: u8) Event {
        switch (self.len) {
            0 => {
                if (self.utf8_left > 0) {
                    // UTF-8 continuation byte: forward verbatim (0x80-0x9f
                    // handled as UTF-8, not C1)
                    self.utf8_left -= 1;
                    self.buf[0] = c;
                    return .{ .forward = self.buf[0..1] };
                }
                if (c >= 0xc0) {
                    // Multi-byte UTF-8 start: 0xC0-0xDF -> 1 continuation byte,
                    // 0xE0-0xEF -> 2, 0xF0-0xFF -> 3
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
                if (c == 0x1e) { // raw Ctrl+6 (terminal without kitty keyboard mode)
                    self.buf[0] = c;
                    return .{ .prefix = self.buf[0..1] };
                }
                self.buf[0] = c;
                return .{ .forward = self.buf[0..1] };
            },
            1 => {
                // Received a starter byte (ESC waiting for '[' or 8-bit CSI
                // 0x9b etc. sequence content)
                const started = self.buf[0];
                if (started == 0x1b and c == '[') {
                    // 7-bit CSI sequence begins
                    self.buf[1] = c;
                    self.len = 2;
                    self.has_intermediates = false;
                    return .{ .forward = &.{} };
                }
                if (c == 0x18 or c == 0x1a) { // CAN/SUB abort
                    self.buf[0] = started;
                    self.buf[1] = c;
                    self.len = 0;
                    return .{ .forward = self.buf[0..2] };
                }
                if (started == 0x9b) {
                    // 8-bit CSI: handle this byte as sequence content
                    if (c >= 0x20 and c <= 0x3f) { // parameters/intermediates
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
                // After ESC a non-'[' (or after 0x9b an unusual byte): forward
                // ESC plus this byte as a whole (must not swallow the key that
                // follows, otherwise ':' after ESC in vim would be lost)
                self.buf[1] = c;
                self.len = 0;
                if (c >= 0xc0) { // this byte starts UTF-8: following continuation bytes no longer treated as C1
                    self.utf8_left = if (c >= 0xf0) 3 else if (c >= 0xe0) 2 else 1;
                }
                return .{ .forward = self.buf[0..2] };
            },
            else => {
                // Inside a CSI sequence
                if (c >= 0x30 and c <= 0x3f) {
                    // Digits and separators (incl. ';' ':') — note 0x3f '?' is
                    // legal but rare in the param range; intermediates are
                    // 0x20-0x2f
                    self.append(c);
                    return .{ .forward = &.{} };
                }
                if (c >= 0x20 and c <= 0x2f) {
                    self.has_intermediates = true;
                    self.append(c);
                    return .{ .forward = &.{} };
                }
                if (c >= 0x40 and c <= 0x7e) {
                    // Final: complete sequence
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
                    // New ESC begins: flush the partial sequence; this byte
                    // starts a new sequence
                    const seq = self.buf[0..self.len];
                    self.len = 0;
                    self.buf[0] = 0x1b;
                    self.len = 1;
                    return .{ .forward = seq };
                }
                // Other control characters: flush the current buffer and forward
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

/// Parse a kitty key event payload (e.g. "ESC[54;5u" / "ESC[54:55;54;5:1;120u"):
/// returns the key code and mods; null if not an event format.
fn parseKittyEvent(seq: []const u8) ?Input.Key {
    // Skip ESC and '['
    var i: usize = 0;
    if (seq.len >= 2 and seq[0] == 0x1b and seq[1] == '[') {
        i = 2;
    } else if (seq.len >= 2 and seq[0] == 0x9b) {
        i = 1;
    } else return null;

    // First segment (up to ';' or final): key code (may contain ':'
    // separated alternate codes)
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

    // Second segment: mods (up to the final 'u'; may contain ':'
    // event types)
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

// ---- Regression tests ----

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

test "forward: plain content" {
    try expectForward("hello world\n");
    try expectForward("你好\xe2\x98\x83");
}

test "forward: pure rendering instructions" {
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

test "drop: terminal queries" {
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

test "drop: input mode negotiation" {
    try expectDrop("\x1b[>1u");
    try expectDrop("\x1b[>4m");
    try expectDrop("\x1b[?1006h");
    try expectDrop("\x1b[?1004h");
    try expectDrop("\x1b[=5u"); // kitty progressive enhancement (CSI = flags u)
    try expectDrop("\x1b[<1u"); // kitty protocol pop
    try expectDrop("\x1b[>2;3u"); // kitty push with multiple parameters
}

test "drop: kitty graphics queries" {
    try expectDrop("\x1b_Gq=1\x1b\\");
    try expectDrop("\x1b_Gq=2\x1b\\");
    try expectDrop("\x1b_Gq=1;s=10\x1b\\");
    try expectDrop("\x9fGq=1\x9c");
}

test "forward: kitty graphics image data" {
    try expectForward("\x1b_Gf=32,s=10;AAAA\x1b\\");
    try expectForward("\x9fGf=32,s=10;AAAA\x9c");
    try expectForward("\x1b_Ga=f,f=32,s=10,v=10,m=1;AAAA\x1b\\\x1b_Gm=0;BBBB\x1b\\");
    try expectForward("\x1b_Ga;b\x1b\\\x1b_Gc;d\x1b\\");
}

test "kitty graphics query drop does not affect surroundings" {
    try expectOut("前\x1b_Gq=1\x1b\\后", "前后");
    try expectOut("a\x1b_Gq=1\x1b\\b\x1b_Gq=2\x1b\\c", "abc");
}

test "sequence merge: aborted sequence followed by new one classified as a whole" {
    try expectDrop("\x1b[12\x1b[6n"); // ESC abort inside CSI, merged into a query
    try expectDrop("\x1b]11;?\x1b[6n"); // OSC query then replaced by new CSI
}

test "sequence merge: private markers after params treated as invalid" {
    try expectForward("\x1b[?1006>h"); // csi_ignore -> no classification -> forward
    try expectForward("\x1b[1>u");
}

/// Input decoder test helper: feed bytes one by one, collect payloads and
/// event kinds.
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
                // Empty payload (held-back ESC, mid-sequence) is not an event; skip
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

test "Input: plain bytes pass through" {
    var r = try inputEvents("hello\x0d\x0a", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("hello\x0d\x0a", r.payloads.items);
    for (r.kinds.items) |k| try testing.expectEqual(.forward, k);
}

test "Input: UTF-8 Chinese (continuation bytes overlap C1 range)" {
    // "监" (jian) = E7 9B 91 (0x9B is exactly 8-bit CSI, 0x91 is in the C1 range)
    var r = try inputEvents("\xe7\x9b\x91", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("\xe7\x9b\x91", r.payloads.items);

    // "你好" (ni hao) = E4 BD A0 E5 A5 BD
    var r2 = try inputEvents("\xe4\xbd\xa0\xe5\xa5\xbd", testing.allocator);
    defer r2.payloads.deinit(testing.allocator);
    defer r2.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("\xe4\xbd\xa0\xe5\xa5\xbd", r2.payloads.items);

    // 4-byte emoji F0 9F 98 83 (0x9F/0x98 are both 8-bit starters)
    var r3 = try inputEvents("\xf0\x9f\x98\x83", testing.allocator);
    defer r3.payloads.deinit(testing.allocator);
    defer r3.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("\xf0\x9f\x98\x83", r3.payloads.items);
}

test "Input: UTF-8 interleaved with ASCII" {
    var r = try inputEvents("a\xe7\x9b\x91b", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("a\xe7\x9b\x91b", r.payloads.items);
}

test "Input: ESC followed by an ordinary key forwarded as a whole" {
    // vim: after ESC pressing : (0x3a is not a CSI starter, must not be swallowed)
    var r = try inputEvents("\x1b:", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("\x1b:", r.payloads.items);

    // ESC j (vim movement)
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

test "Input: held-back ESC can be flushed on timeout" {
    var dec = Input{};
    _ = dec.push(0x1b);
    try testing.expect(dec.pending());
    try testing.expectEqualStrings("\x1b", dec.flush());
    try testing.expect(!dec.pending());

    // Partial CSI (ESC[5) flushed verbatim
    var dec2 = Input{};
    _ = dec2.push(0x1b);
    _ = dec2.push('[');
    _ = dec2.push('5');
    try testing.expect(dec2.pending());
    try testing.expectEqualStrings("\x1b[5", dec2.flush());

    // Decoder state resets after flush
    _ = dec2.push('x');
    const ev = dec2.push('y');
    try testing.expectEqual(Input.Event.Tag.forward, @as(Input.Event.Tag, ev));
}

test "Input: raw Ctrl+6 recognized as prefix" {
    var r = try inputEvents("\x1e", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), r.kinds.items.len);
    try testing.expectEqual(Input.Event.Tag.prefix, r.kinds.items[0]);
    try testing.expectEqualSlices(u8, &.{0x1e}, r.payloads.items);
}

test "Input: kitty key event recognition" {
    // User-verified: Ctrl+6 in kitty mode is ESC[54;5u
    var r = try inputEvents("\x1b[54;5u", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), r.kinds.items.len);
    try testing.expectEqual(Input.Event.Tag.prefix, r.kinds.items[0]);
    try testing.expectEqualStrings("\x1b[54;5u", r.payloads.items);

    // Ordinary key: ESC[120;1u (x) -> key event
    var r2 = try inputEvents("\x1b[120;1u", testing.allocator);
    defer r2.payloads.deinit(testing.allocator);
    defer r2.kinds.deinit(testing.allocator);
    try testing.expectEqual(Input.Event.Tag.key, r2.kinds.items[0]);
}

test "Input: kitty events pass through unaffected" {
    // Ordinary key event without ctrl + interleaved text
    var r = try inputEvents("a\x1b[97;1ub", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("a\x1b[97;1ub", r.payloads.items);
}

test "Input: non-kitty CSI sequences pass through as a whole" {
    var r = try inputEvents("x\x1b[25hy", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqualStrings("x\x1b[25hy", r.payloads.items);
}

test "Input: kitty event with event types and text segments" {
    // ESC[54:54;5:1;54u —— alternate codes + event type + text segment
    var r = try inputEvents("\x1b[54:54;5:1;54u", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqual(Input.Event.Tag.prefix, r.kinds.items[0]);
}

test "Input: 'u' with intermediates (response/negotiation) is not a key event" {
    var r = try inputEvents("\x1b[?1u", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqual(Input.Event.Tag.forward, r.kinds.items[0]);
}

test "Input: 8-bit CSI kitty event" {
    var r = try inputEvents("\x9b54;5u", testing.allocator);
    defer r.payloads.deinit(testing.allocator);
    defer r.kinds.deinit(testing.allocator);
    try testing.expectEqual(Input.Event.Tag.prefix, r.kinds.items[0]);
}

test "Input: interleaved kitty and plain input" {
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
