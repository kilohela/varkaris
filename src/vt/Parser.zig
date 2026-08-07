//! VT-series parser for escape and control sequences.
//!
//! This is implemented directly as the state machine described on
//! vt100.net: https://vt100.net/emu/dec_ansi_parser
//!
//! Vendored from ghostty (src/terminal/Parser.zig), tests stripped.
pub const Parser = @This();

const std = @import("std");
const table = @import("parse_table.zig").table;
pub const osc = @import("osc.zig");

const log = std.log.scoped(.parser);

/// States for the state machine
pub const State = enum {
    ground,
    escape,
    escape_intermediate,
    csi_entry,
    csi_intermediate,
    csi_param,
    csi_ignore,
    dcs_entry,
    dcs_param,
    dcs_intermediate,
    dcs_passthrough,
    dcs_ignore,
    osc_string,
    sos_pm_apc_string,
};

/// Transition action is an action that can be taken during a state
/// transition. This is more of an internal action, not one used by
/// end users, typically.
pub const TransitionAction = enum {
    none,
    ignore,
    print,
    execute,
    collect,
    param,
    esc_dispatch,
    csi_dispatch,
    put,
    osc_put,
    apc_put,
};

/// Action is the action that a caller of the parser is expected to
/// take as a result of some input character.
pub const Action = union(enum) {
    pub const Tag = std.meta.FieldEnum(Action);

    /// Draw character to the screen. This is a unicode codepoint.
    print: u21,

    /// Execute the C0 or C1 function.
    execute: u8,

    /// Execute the CSI command. Note that pointers within this
    /// structure are only valid until the next call to "next".
    csi_dispatch: CSI,

    /// Execute the ESC command.
    esc_dispatch: ESC,

    /// Execute the OSC command.
    osc_dispatch: osc.Command,

    /// DCS-related events.
    dcs_hook: DCS,
    dcs_put: u8,
    dcs_unhook: void,

    /// APC data
    apc_start: void,
    apc_put: u8,
    apc_end: void,

    pub const CSI = struct {
        intermediates: []u8,
        params: []u16,
        params_sep: SepList,
        final: u8,

        /// The list of separators used for CSI params. The value of the
        /// bit can be mapped to Sep. The index of this bit set specifies
        /// the separator AFTER that param. For example: 0;4:3 would have
        /// index 1 set.
        pub const SepList = std.StaticBitSet(MAX_PARAMS);

        /// The separator used for CSI params.
        pub const Sep = enum(u1) { semicolon = 0, colon = 1 };

        // Implement formatter for logging
        pub fn format(
            self: CSI,
            writer: *std.Io.Writer,
        ) !void {
            try writer.print("ESC [ {s} {any} {c}", .{
                self.intermediates,
                self.params,
                self.final,
            });
        }
    };

    pub const ESC = struct {
        intermediates: []u8,
        final: u8,

        // Implement formatter for logging
        pub fn format(
            self: ESC,
            writer: *std.Io.Writer,
        ) !void {
            try writer.print("ESC {s} {c}", .{
                self.intermediates,
                self.final,
            });
        }
    };

    pub const DCS = struct {
        intermediates: []const u8 = "",
        params: []const u16 = &.{},
        final: u8,

        pub const C = extern struct {
            intermediates: [*]const u8,
            intermediates_len: usize,
            params: [*]const u16,
            params_len: usize,
            final: u8,
        };
    };

    // Implement formatter for logging. This is mostly copied from the
    // std.fmt implementation, but we modify it slightly so that we can
    // print out custom formats for some of our primitives.
    pub fn format(
        self: Action,
        writer: *std.Io.Writer,
    ) !void {
        const T = Action;
        const info = @typeInfo(T).@"union";

        try writer.writeAll(@typeName(T));
        if (info.tag_type) |TagType| {
            try writer.writeAll("{ .");
            try writer.writeAll(@tagName(@as(TagType, self)));
            try writer.writeAll(" = ");

            inline for (info.fields) |u_field| {
                // If this is the active field...
                if (self == @field(TagType, u_field.name)) {
                    const value = @field(self, u_field.name);
                    switch (@TypeOf(value)) {
                        // Unicode
                        u21 => try writer.print("'{u}' (U+{X})", .{ value, value }),

                        // Byte
                        u8 => try writer.print("0x{x}", .{value}),

                        // Note: we don't do ASCII (u8) because there are a lot
                        // of invisible characters we don't want to handle right
                        // now.

                        // All others do the default behavior
                        else => try writer.printValue(
                            "any",
                            .{},
                            @field(self, u_field.name),
                            3,
                        ),
                    }
                }
            }

            try writer.writeAll(" }");
        } else {
            try format(writer, "@{x}", .{@intFromPtr(&self)});
        }
    }
};

/// Maximum number of intermediate characters during parsing. This is
/// 4 because we also use the intermediates array for UTF8 decoding which
/// can be at most 4 bytes.
pub const MAX_INTERMEDIATE = 4;

/// Maximum number of CSI parameters. This is arbitrary. Practically, the
/// only CSI command that uses more than 3 parameters is the SGR command
/// which can be infinitely long. 24 is a reasonable limit based on empirical
/// data. This used to be 16 but Kakoune has a SGR command that uses 17
/// parameters.
///
/// We could in the future make this the static limit and then allocate after
/// but that's a lot more work and practically its so rare to exceed this
/// number. I implore TUI authors to not use more than this number of CSI
/// params, but I suspect we'll introduce a slow path with heap allocation
/// one day.
pub const MAX_PARAMS = 24;

/// Current state of the state machine
state: State,

/// Intermediate tracking.
intermediates: [MAX_INTERMEDIATE]u8,
intermediates_idx: u8,

/// Param tracking, building
params: [MAX_PARAMS]u16,
params_sep: Action.CSI.SepList,
params_idx: u8,
param_acc: u16,
param_acc_idx: u8,

/// Parser for OSC sequences
osc_parser: osc.Parser,

pub fn init() Parser {
    var result: Parser = .{
        .state = .ground,
        .intermediates_idx = 0,
        .params_sep = .initEmpty(),
        .params_idx = 0,
        .param_acc = 0,
        .param_acc_idx = 0,
        .osc_parser = .init(null),

        .intermediates = undefined,
        .params = undefined,
    };
    if (std.valgrind.runningOnValgrind() > 0) {
        // Initialize our undefined fields so Valgrind can catch it.
        // https://github.com/ziglang/zig/issues/19148
        result.intermediates = undefined;
        result.params = undefined;
    }
    return result;
}

pub fn deinit(self: *Parser) void {
    self.osc_parser.deinit();
}

/// Next consumes the next character c and returns the actions to execute.
/// Up to 3 actions may need to be executed -- in order -- representing
/// the state exit, transition, and entry actions.
pub fn next(self: *Parser, c: u8) [3]?Action {
    const effect = table[c][@intFromEnum(self.state)];

    // log.info("next: {x}", .{c});

    const next_state = effect.state;
    const action = effect.action;

    // After generating the actions, we set our next state.
    defer self.state = next_state;

    // When going from one state to another, the actions take place in this order:
    //
    // 1. exit action from old state
    // 2. transition action
    // 3. entry action to new state
    return [3]?Action{
        // Exit depends on current state
        if (self.state == next_state) null else switch (self.state) {
            .osc_string => if (self.osc_parser.end(c)) |cmd|
                Action{ .osc_dispatch = cmd.* }
            else
                null,
            .dcs_passthrough => Action{ .dcs_unhook = {} },
            .sos_pm_apc_string => Action{ .apc_end = {} },
            else => null,
        },

        self.doAction(action, c),

        // Entry depends on new state
        if (self.state == next_state) null else switch (next_state) {
            .escape, .dcs_entry, .csi_entry => clear: {
                self.clear();
                break :clear null;
            },
            .osc_string => osc_string: {
                self.osc_parser.reset();
                break :osc_string null;
            },
            .dcs_passthrough => dcs_hook: {
                // Ignore too many parameters
                if (self.params_idx >= MAX_PARAMS) break :dcs_hook null;
                // Finalize parameters
                if (self.param_acc_idx > 0) {
                    self.params[self.params_idx] = self.param_acc;
                    self.params_idx += 1;
                }
                break :dcs_hook .{
                    .dcs_hook = .{
                        .intermediates = self.intermediates[0..self.intermediates_idx],
                        .params = self.params[0..self.params_idx],
                        .final = c,
                    },
                };
            },
            .sos_pm_apc_string => Action{ .apc_start = {} },
            else => null,
        },
    };
}

pub inline fn collect(self: *Parser, c: u8) void {
    if (self.intermediates_idx >= MAX_INTERMEDIATE) {
        @branchHint(.cold);
        log.warn("invalid intermediates count", .{});
        return;
    }

    self.intermediates[self.intermediates_idx] = c;
    self.intermediates_idx += 1;
}

inline fn doAction(self: *Parser, action: TransitionAction, c: u8) ?Action {
    return switch (action) {
        .none, .ignore => null,
        .print => Action{ .print = c },
        .execute => Action{ .execute = c },
        .collect => collect: {
            self.collect(c);
            break :collect null;
        },
        .param => param: {
            // Semicolon separates parameters. If we encounter a semicolon
            // we need to store and move on to the next parameter.
            if (c == ';' or c == ':') {
                // Ignore too many parameters
                if (self.params_idx >= MAX_PARAMS) break :param null;

                // Set param final value
                self.params[self.params_idx] = self.param_acc;
                if (c == ':') self.params_sep.set(self.params_idx);
                self.params_idx += 1;

                // Reset current param value to 0
                self.param_acc = 0;
                self.param_acc_idx = 0;
                break :param null;
            }

            // A numeric value. Add it to our accumulator.
            self.param_acc *|= 10;
            self.param_acc +|= c - '0';

            // Increment our accumulator index. If we overflow then
            // we're out of bounds and we exit immediately.
            self.param_acc_idx, const overflow = @addWithOverflow(self.param_acc_idx, 1);
            if (overflow > 0) break :param null;

            // The client is expected to perform no action.
            break :param null;
        },
        .osc_put => osc_put: {
            @call(.always_inline, osc.Parser.next, .{ &self.osc_parser, c });
            break :osc_put null;
        },
        .csi_dispatch => csi_dispatch: {
            // Ignore too many parameters
            if (self.params_idx >= MAX_PARAMS) break :csi_dispatch null;

            // Finalize parameters if we have one
            if (self.param_acc_idx > 0) {
                self.params[self.params_idx] = self.param_acc;
                self.params_idx += 1;
            }

            const result: Action = .{
                .csi_dispatch = .{
                    .intermediates = self.intermediates[0..self.intermediates_idx],
                    .params = self.params[0..self.params_idx],
                    .params_sep = self.params_sep,
                    .final = c,
                },
            };

            // We only allow colon or mixed separators for the 'm' command.
            if (c != 'm' and self.params_sep.count() > 0) {
                @branchHint(.cold);
                log.warn(
                    "CSI colon or mixed separators only allowed for 'm' command, got: {f}",
                    .{result},
                );
                break :csi_dispatch null;
            }

            break :csi_dispatch result;
        },
        .esc_dispatch => Action{
            .esc_dispatch = .{
                .intermediates = self.intermediates[0..self.intermediates_idx],
                .final = c,
            },
        },
        .put => Action{ .dcs_put = c },
        .apc_put => Action{ .apc_put = c },
    };
}

pub inline fn clear(self: *Parser) void {
    self.intermediates_idx = 0;
    self.params_idx = 0;
    self.params_sep = .initEmpty();
    self.param_acc = 0;
    self.param_acc_idx = 0;
}

