//! Tawny rule files (`kind: atomic`, `kind: sequence`, `kind: threshold`),
//! described in `rules/README.md`. `compile` turns the YAML into a JSON
//! definition stored in `alert_rules.compiled_expression_json`; `load` reads
//! that JSON back for `sequence.zig` and `threshold.zig`. An atomic rule is
//! stored as a plain AST, the same shape as a compiled Sigma rule.

const std = @import("std");
const yaml = @import("yaml.zig");
const ast = @import("ast.zig");
const sigma = @import("sigma.zig");

pub const Kind = enum { atomic, sequence, threshold };

pub const max_steps = 8;
pub const min_steps = 2;
pub const max_within_seconds: u32 = 24 * 3600;

pub const Step = struct {
    name: []const u8,
    event_type: []const u8,
    /// Matches needed before the sequence moves on.
    count: u32 = 1,
    /// Fields that make the join key. Defaults to the rule's `by`.
    by: []const []const u8,
    expr: ast.Node,
};

pub const Sequence = struct {
    within_seconds: u32,
    steps: []const Step,
};

pub const Threshold = struct {
    event_type: []const u8,
    by: []const []const u8,
    window_seconds: u32,
    /// Fires when the count reaches this.
    min: u32,
    /// Count distinct values of this path instead of events.
    distinct: ?[]const u8 = null,
    expr: ast.Node,
};

pub const Atomic = struct {
    event_type: []const u8,
    expr: ast.Node,
};

pub const Rule = union(Kind) {
    atomic: Atomic,
    sequence: Sequence,
    threshold: Threshold,
};

pub const Compiled = struct {
    ok: bool,
    reason: []const u8 = "",
    kind: Kind = .sequence,
    id: []const u8 = "",
    title: []const u8 = "untitled",
    description: ?[]const u8 = null,
    severity: []const u8 = "medium",
    mitre: []const []const u8 = &.{},
    /// JSON for compiled_expression_json.
    json: []const u8 = "",
    rule: Rule = undefined,
};

/// Is this YAML a Tawny correlation rule (has a top-level `kind`)?
pub fn isTawnyRule(arena: std.mem.Allocator, text: []const u8) bool {
    const root = yaml.parse(arena, text) catch return false;
    const k = root.get("kind") orelse return false;
    const s = k.str() orelse return false;
    return std.meta.stringToEnum(Kind, s) != null;
}

const Fail = error{Fail};

const Ctx = struct {
    arena: std.mem.Allocator,
    map: *const sigma.FieldMap,
    reason: []const u8 = "",

    fn fail(c: *Ctx, comptime fmt: []const u8, args: anytype) (Fail || error{OutOfMemory}) {
        c.reason = try std.fmt.allocPrint(c.arena, fmt, args);
        return error.Fail;
    }
};

pub fn compile(arena: std.mem.Allocator, map: *const sigma.FieldMap, text: []const u8) error{OutOfMemory}!Compiled {
    var c: Ctx = .{ .arena = arena, .map = map };
    var out: Compiled = .{ .ok = false };
    compileInner(&c, text, &out) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Fail => {
            out.ok = false;
            out.reason = c.reason;
            return out;
        },
    };
    out.ok = true;
    return out;
}

fn compileInner(c: *Ctx, text: []const u8, out: *Compiled) (Fail || error{OutOfMemory})!void {
    const root = yaml.parse(c.arena, text) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return c.fail("{s}", .{yaml.describe(err)}),
    };
    const kind_text = (root.get("kind") orelse return c.fail("kind is required", .{})).str() orelse return c.fail("kind must be text", .{});
    out.kind = std.meta.stringToEnum(Kind, kind_text) orelse return c.fail("kind must be atomic, sequence or threshold", .{});
    out.id = (root.get("id") orelse return c.fail("id is required", .{})).str() orelse return c.fail("id must be text", .{});
    if (root.get("title")) |t| out.title = t.str() orelse "untitled";
    if (root.get("description")) |d| out.description = if (d.str()) |s| std.mem.trim(u8, s, " \n") else null;
    if (root.get("level")) |l| out.severity = severity(l.str() orelse "");
    if (root.get("tags")) |t| out.mitre = try mitre(c.arena, t);
    var json: std.Io.Writer.Allocating = .init(c.arena);
    const w = &json.writer;
    if (out.kind == .atomic) {
        if (root.get("where") == null) return c.fail("where is required", .{});
        out.rule = .{ .atomic = .{
            .event_type = (root.get("event_type") orelse return c.fail("event_type is required", .{})).str() orelse return c.fail("event_type must be text", .{}),
            .expr = try where(c, root.get("where")),
        } };
        try writeRule(w, out.rule);
        out.json = json.written();
        return;
    }
    const by = try byFields(c, root.get("by") orelse return c.fail("by is required", .{}));
    switch (out.kind) {
        .atomic => unreachable,
        .sequence => {
            const within = try duration(c, root.get("within") orelse return c.fail("within is required", .{}), "within");
            if (within > max_within_seconds) return c.fail("within is more than 24 hours", .{});
            const steps_node = root.get("steps") orelse return c.fail("steps is required", .{});
            if (steps_node != .list) return c.fail("steps must be a list", .{});
            if (steps_node.list.len < min_steps or steps_node.list.len > max_steps) return c.fail("a sequence has 2 to 8 steps", .{});
            const steps = try c.arena.alloc(Step, steps_node.list.len);
            for (steps_node.list, 0..) |s, i| {
                if (s != .map) return c.fail("step {d} is not a map", .{i + 1});
                steps[i] = .{
                    .name = if (s.get("name")) |n| n.str() orelse "step" else "step",
                    .event_type = (s.get("event_type") orelse return c.fail("step {d} needs event_type", .{i + 1})).str() orelse return c.fail("step {d} event_type must be text", .{i + 1}),
                    .count = if (s.get("count")) |n| try positive(c, n, "count") else 1,
                    .by = if (s.get("by")) |b| try byFields(c, b) else by,
                    .expr = try where(c, s.get("where")),
                };
                if (steps[i].by.len != by.len) return c.fail("step {d} by has a different number of fields", .{i + 1});
            }
            out.rule = .{ .sequence = .{ .within_seconds = within, .steps = steps } };
        },
        .threshold => {
            const window = try duration(c, root.get("window") orelse return c.fail("window is required", .{}), "window");
            if (window > max_within_seconds) return c.fail("window is more than 24 hours", .{});
            const min = try positive(c, root.get("min") orelse return c.fail("min is required", .{}), "min");
            if (min < 2) return c.fail("min must be at least 2", .{});
            out.rule = .{ .threshold = .{
                .event_type = (root.get("event_type") orelse return c.fail("event_type is required", .{})).str() orelse return c.fail("event_type must be text", .{}),
                .by = by,
                .window_seconds = window,
                .min = min,
                .distinct = if (root.get("distinct")) |d| d.str() orelse return c.fail("distinct must be a path", .{}) else null,
                .expr = try where(c, root.get("where")),
            } };
            if (out.rule.threshold.distinct) |d| {
                if (c.map.lookup(d)) |t| {
                    if (t == .path) out.rule.threshold.distinct = t.path;
                }
            }
        },
    }
    try writeRule(w, out.rule);
    out.json = json.written();
}

fn where(c: *Ctx, node: ?yaml.Node) (Fail || error{OutOfMemory})!ast.Node {
    const n = node orelse return .{ .constant = true };
    if (n == .null) return .{ .constant = true };
    return switch (try sigma.compileSelection(c.arena, c.map, n)) {
        .ok => |e| e,
        .rejected => |why| c.fail("where: {s}", .{why}),
    };
}

fn byFields(c: *Ctx, n: yaml.Node) (Fail || error{OutOfMemory})![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    switch (n) {
        .scalar => |s| try list.append(c.arena, s.text),
        .list => |items| for (items) |it| try list.append(c.arena, it.str() orelse return c.fail("by holds a non-string", .{})),
        else => return c.fail("by must be a field or a list of fields", .{}),
    }
    if (list.items.len == 0 or list.items.len > 4) return c.fail("by needs 1 to 4 fields", .{});
    for (list.items, 0..) |f, i| {
        if (std.mem.eql(u8, f, "agent_id")) continue;
        if (c.map.lookup(f)) |t| {
            switch (t) {
                .path => |p| list.items[i] = p,
                else => return c.fail("by field {s} must map to a single path", .{f}),
            }
        } else if (std.mem.indexOfScalar(u8, f, '.') == null and !std.mem.eql(u8, f, "event_id")) {
            return c.fail("by field {s} is not a known field or dotted path", .{f});
        }
    }
    return list.items;
}

fn positive(c: *Ctx, n: yaml.Node, what: []const u8) (Fail || error{OutOfMemory})!u32 {
    const s = n.str() orelse return c.fail("{s} must be a number", .{what});
    const v = std.fmt.parseInt(u32, s, 10) catch return c.fail("{s} must be a whole number", .{what});
    if (v == 0 or v > 100_000) return c.fail("{s} must be 1 to 100000", .{what});
    return v;
}

/// `30s`, `10m`, `24h` or plain seconds.
fn duration(c: *Ctx, n: yaml.Node, what: []const u8) (Fail || error{OutOfMemory})!u32 {
    const s = n.str() orelse return c.fail("{s} must be a duration like 10m", .{what});
    if (s.len == 0) return c.fail("{s} is empty", .{what});
    const unit = s[s.len - 1];
    const mult: u32 = switch (unit) {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        '0'...'9' => 1,
        else => return c.fail("{s} unit must be s, m or h", .{what}),
    };
    const digits = if (std.ascii.isDigit(unit)) s else s[0 .. s.len - 1];
    const v = std.fmt.parseInt(u32, digits, 10) catch return c.fail("{s} must be a duration like 10m", .{what});
    if (v == 0) return c.fail("{s} must be more than zero", .{what});
    return std.math.mul(u32, v, mult) catch c.fail("{s} is too long", .{what});
}

fn severity(level: []const u8) []const u8 {
    inline for (.{ "critical", "high", "medium", "low" }) |l| {
        if (std.ascii.eqlIgnoreCase(level, l)) return l;
    }
    if (std.ascii.eqlIgnoreCase(level, "informational")) return "low";
    return "medium";
}

fn mitre(arena: std.mem.Allocator, n: yaml.Node) ![]const []const u8 {
    if (n != .list) return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (n.list) |it| {
        const t = it.str() orelse continue;
        if (!std.ascii.startsWithIgnoreCase(t, "attack.t")) continue;
        const up = try arena.dupe(u8, t["attack.".len..]);
        for (up) |*ch| ch.* = std.ascii.toUpper(ch.*);
        try out.append(arena, up);
    }
    return out.items;
}

// --- JSON ------------------------------------------------------------------------

fn writeStrings(w: *std.Io.Writer, items: []const []const u8) !void {
    try w.writeAll("[");
    for (items, 0..) |s, i| {
        if (i > 0) try w.writeAll(",");
        try std.json.Stringify.encodeJsonString(s, .{}, w);
    }
    try w.writeAll("]");
}

pub fn writeRule(w: *std.Io.Writer, rule: Rule) error{OutOfMemory}!void {
    writeRuleInner(w, rule) catch return error.OutOfMemory;
}

fn writeRuleInner(w: *std.Io.Writer, rule: Rule) !void {
    switch (rule) {
        .atomic => |a| try ast.writeExpr(w, a.expr),
        .sequence => |s| {
            try w.print("{{\"kind\":\"sequence\",\"within_seconds\":{d},\"steps\":[", .{s.within_seconds});
            for (s.steps, 0..) |st, i| {
                if (i > 0) try w.writeAll(",");
                try w.writeAll("{\"name\":");
                try std.json.Stringify.encodeJsonString(st.name, .{}, w);
                try w.writeAll(",\"event_type\":");
                try std.json.Stringify.encodeJsonString(st.event_type, .{}, w);
                try w.print(",\"count\":{d},\"by\":", .{st.count});
                try writeStrings(w, st.by);
                try w.writeAll(",\"expr\":");
                try ast.writeExpr(w, st.expr);
                try w.writeAll("}");
            }
            try w.writeAll("]}");
        },
        .threshold => |t| {
            try w.writeAll("{\"kind\":\"threshold\",\"event_type\":");
            try std.json.Stringify.encodeJsonString(t.event_type, .{}, w);
            try w.writeAll(",\"by\":");
            try writeStrings(w, t.by);
            try w.print(",\"window_seconds\":{d},\"min\":{d}", .{ t.window_seconds, t.min });
            if (t.distinct) |d| {
                try w.writeAll(",\"distinct\":");
                try std.json.Stringify.encodeJsonString(d, .{}, w);
            }
            try w.writeAll(",\"expr\":");
            try ast.writeExpr(w, t.expr);
            try w.writeAll("}");
        },
    }
}

fn u32Of(v: ?std.json.Value) ?u32 {
    const x = v orelse return null;
    if (x != .integer or x.integer < 0 or x.integer > std.math.maxInt(u32)) return null;
    return @intCast(x.integer);
}

fn stringsOf(arena: std.mem.Allocator, v: ?std.json.Value) ![]const []const u8 {
    const x = v orelse return error.BadExpression;
    if (x != .array or x.array.items.len == 0) return error.BadExpression;
    const out = try arena.alloc([]const u8, x.array.items.len);
    for (x.array.items, 0..) |it, i| {
        if (it != .string) return error.BadExpression;
        out[i] = it.string;
    }
    return out;
}

fn strOf(v: ?std.json.Value) ![]const u8 {
    const x = v orelse return error.BadExpression;
    if (x != .string) return error.BadExpression;
    return x.string;
}

/// Load a stored definition. Everything lives in `arena`.
pub fn load(arena: std.mem.Allocator, json_text: []const u8) ast.LoadError!Rule {
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, json_text, .{}) catch return error.BadExpression;
    if (v != .object) return error.BadExpression;
    const kind = std.meta.stringToEnum(Kind, try strOf(v.object.get("kind"))) orelse return error.BadExpression;
    switch (kind) {
        .atomic => return error.BadExpression, // stored as a plain AST
        .sequence => {
            const steps_v = v.object.get("steps") orelse return error.BadExpression;
            if (steps_v != .array or steps_v.array.items.len < min_steps or steps_v.array.items.len > max_steps) return error.BadExpression;
            const steps = try arena.alloc(Step, steps_v.array.items.len);
            for (steps_v.array.items, 0..) |s, i| {
                if (s != .object) return error.BadExpression;
                steps[i] = .{
                    .name = try strOf(s.object.get("name")),
                    .event_type = try strOf(s.object.get("event_type")),
                    .count = u32Of(s.object.get("count")) orelse return error.BadExpression,
                    .by = try stringsOf(arena, s.object.get("by")),
                    .expr = try ast.parseExpr(arena, s.object.get("expr") orelse return error.BadExpression),
                };
                if (steps[i].count == 0) return error.BadExpression;
            }
            return .{ .sequence = .{
                .within_seconds = u32Of(v.object.get("within_seconds")) orelse return error.BadExpression,
                .steps = steps,
            } };
        },
        .threshold => {
            return .{ .threshold = .{
                .event_type = try strOf(v.object.get("event_type")),
                .by = try stringsOf(arena, v.object.get("by")),
                .window_seconds = u32Of(v.object.get("window_seconds")) orelse return error.BadExpression,
                .min = u32Of(v.object.get("min")) orelse return error.BadExpression,
                .distinct = if (v.object.get("distinct")) |d| (if (d == .string) d.string else return error.BadExpression) else null,
                .expr = try ast.parseExpr(arena, v.object.get("expr") orelse return error.BadExpression),
            } };
        },
    }
}

/// Join key for `by` fields from one event, or null when a field is missing.
/// `agent_id` comes from the authenticated agent, not the payload.
pub fn byKey(arena: std.mem.Allocator, by: []const []const u8, root: std.json.Value, agent_id: []const u8) !?[]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (by, 0..) |f, i| {
        if (i > 0) try out.append(arena, 0x1f);
        if (std.mem.eql(u8, f, "agent_id")) {
            try out.appendSlice(arena, agent_id);
            continue;
        }
        var buf: [64]u8 = undefined;
        const v = ast.firstScalar(root, f, &buf) orelse return null;
        if (v.len == 0) return null;
        // Keys compare without case (user names, hosts).
        for (v) |ch| try out.append(arena, std.ascii.toLower(ch));
    }
    if (out.items.len > 512) return null;
    return out.items;
}

test "sequence and threshold rules compile and load back" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const map = try arena.create(sigma.FieldMap);
    map.* = try sigma.FieldMap.load(arena);
    const seq = try compile(arena, map,
        \\id: tawny-builtin:test-seq
        \\title: Test sequence
        \\kind: sequence
        \\by: TargetUserName
        \\within: 10m
        \\level: high
        \\steps:
        \\  - name: failures
        \\    event_type: user_logon_failed
        \\    count: 5
        \\  - name: success
        \\    event_type: user_logon
        \\    where:
        \\      logon.type: [2, 10]
    );
    try std.testing.expect(seq.ok);
    const loaded = try load(arena, seq.json);
    try std.testing.expectEqual(@as(u32, 600), loaded.sequence.within_seconds);
    try std.testing.expectEqualStrings("user.name", loaded.sequence.steps[0].by[0]);
    try std.testing.expectEqual(@as(u32, 5), loaded.sequence.steps[0].count);

    const thr = try compile(arena, map,
        \\id: tawny-builtin:test-thr
        \\kind: threshold
        \\event_type: user_logon_failed
        \\by: IpAddress
        \\window: 5m
        \\min: 21
        \\distinct: TargetUserName
    );
    try std.testing.expect(thr.ok);
    const t = (try load(arena, thr.json)).threshold;
    try std.testing.expectEqualStrings("network.src_ip", t.by[0]);
    try std.testing.expectEqualStrings("user.name", t.distinct.?);

    const bad = [_][]const u8{
        "id: x\nkind: sequence\nby: agent_id\nwithin: 25h\nsteps:\n  - {event_type: a}\n  - {event_type: b}\n",
        "id: x\nkind: sequence\nby: agent_id\nwithin: 1h\nsteps:\n  - {event_type: a}\n",
        "id: x\nkind: threshold\nby: agent_id\nwindow: 1m\nmin: 1\nevent_type: a\n",
        "id: x\nkind: threshold\nby: Nope\nwindow: 1m\nmin: 5\nevent_type: a\n",
        "id: x\nkind: sequence\nby: agent_id\nwithin: 1h\nsteps:\n  - {event_type: a, where: {Mystery: 1}}\n  - {event_type: b}\n",
    };
    for (bad) |b| {
        const r = try compile(arena, map, b);
        try std.testing.expect(!r.ok);
        try std.testing.expect(r.reason.len > 0);
    }
}
