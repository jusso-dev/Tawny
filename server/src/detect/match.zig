//! Field matching for detection rules and suppressions.
//!
//! A rule names a dotted path into the event payload, an operator and a value.
//! Paths fan out over arrays: `processes.name` matches when any element of
//! `processes` has a matching `name`. Nothing here searches the whole payload text.

const std = @import("std");

pub const Operator = enum {
    exists,
    equals,
    contains,
    startswith,
    endswith,
    greater_than,
    less_than,

    pub fn fromText(text: []const u8) ?Operator {
        var lower: [16]u8 = undefined;
        if (text.len > lower.len) return null;
        return std.meta.stringToEnum(Operator, std.ascii.lowerString(&lower, text));
    }
};

/// Compare one JSON value against the wanted text. Strings compare without case.
/// Numbers compare numerically for greater_than and less_than, and fail when
/// `want` isn't a number.
pub fn matchValue(op: Operator, value: std.json.Value, want: []const u8) bool {
    switch (op) {
        .exists => return value != .null,
        .greater_than, .less_than => {
            const have = numberOf(value) orelse return false;
            const w = std.fmt.parseFloat(f64, std.mem.trim(u8, want, " \t")) catch return false;
            return if (op == .greater_than) have > w else have < w;
        },
        .equals, .contains, .startswith, .endswith => {
            var buf: [64]u8 = undefined;
            const text: []const u8 = switch (value) {
                .string => |s| s,
                .number_string => |s| s,
                .integer => |n| std.fmt.bufPrint(&buf, "{d}", .{n}) catch return false,
                .float => |f| {
                    // Numeric equality so "1" equals 1.0.
                    if (op == .equals) {
                        const w = std.fmt.parseFloat(f64, want) catch return false;
                        return f == w;
                    }
                    return textMatch(op, std.fmt.bufPrint(&buf, "{d}", .{f}) catch return false, want);
                },
                .bool => |b| if (b) "true" else "false",
                else => return false,
            };
            return textMatch(op, text, want);
        },
    }
}

fn textMatch(op: Operator, text: []const u8, want: []const u8) bool {
    return switch (op) {
        .equals => std.ascii.eqlIgnoreCase(text, want),
        .contains => std.ascii.findIgnoreCase(text, want) != null,
        .startswith => std.ascii.startsWithIgnoreCase(text, want),
        .endswith => std.ascii.endsWithIgnoreCase(text, want),
        else => false,
    };
}

fn numberOf(value: std.json.Value) ?f64 {
    return switch (value) {
        .integer => |n| @floatFromInt(n),
        .float => |f| f,
        .number_string, .string => |s| std.fmt.parseFloat(f64, std.mem.trim(u8, s, " \t")) catch null,
        else => null,
    };
}

/// Walk a dotted path and report whether any value at the end matches.
/// Arrays anywhere on the path fan out, and an array at the end matches when
/// any element matches.
pub fn matchPath(root: std.json.Value, path: []const u8, op: Operator, want: []const u8) bool {
    if (path.len == 0) return false;
    return walk(root, path, op, want, 0);
}

const max_depth = 32;

fn walk(cur: std.json.Value, rest: []const u8, op: Operator, want: []const u8, depth: usize) bool {
    if (depth > max_depth) return false;
    if (cur == .array) {
        for (cur.array.items) |item| {
            if (walk(item, rest, op, want, depth + 1)) return true;
        }
        return false;
    }
    if (rest.len == 0) return matchValue(op, cur, want);
    const dot = std.mem.indexOfScalar(u8, rest, '.');
    const key = if (dot) |d| rest[0..d] else rest;
    const next = if (dot) |d| rest[d + 1 ..] else "";
    switch (cur) {
        .object => |obj| {
            const child = obj.get(key) orelse return false;
            return walk(child, next, op, want, depth + 1);
        },
        else => return false,
    }
}

/// A rule or suppression predicate read from the database.
pub const Predicate = struct {
    operator: ?[]const u8,
    path: ?[]const u8,
    want: ?[]const u8,
};

pub const Outcome = enum { match, no_match, invalid };

/// Evaluate a stored predicate. A missing path or unknown operator is invalid,
/// so callers can log and skip it rather than fall back to a text search.
pub fn evaluate(root: std.json.Value, pred: Predicate) Outcome {
    const op_text = pred.operator orelse return .invalid;
    const op = Operator.fromText(op_text) orelse return .invalid;
    const path = pred.path orelse return .invalid;
    if (path.len == 0) return .invalid;
    const want = pred.want orelse if (op == .exists) "" else return .invalid;
    if (op != .exists and want.len == 0) return .invalid;
    return if (matchPath(root, path, op, want)) .match else .no_match;
}

fn parse(text: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, std.testing.allocator, text, .{});
}

test "operator from text covers the stored strings" {
    try std.testing.expectEqual(Operator.exists, Operator.fromText("exists").?);
    try std.testing.expectEqual(Operator.greater_than, Operator.fromText("greater_than").?);
    try std.testing.expectEqual(Operator.startswith, Operator.fromText("StartsWith").?);
    try std.testing.expect(Operator.fromText("matches") == null);
}

test "equals fans out over arrays and ignores other fields" {
    var hit = try parse("{\"processes\":[{\"name\":\"x\"},{\"name\":\"CMD.EXE\"}]}");
    defer hit.deinit();
    try std.testing.expect(matchPath(hit.value, "processes.name", .equals, "cmd.exe"));

    var miss = try parse("{\"processes\":[{\"name\":\"x\",\"command_line\":\"cmd.exe /c\"}]}");
    defer miss.deinit();
    try std.testing.expect(!matchPath(miss.value, "processes.name", .equals, "cmd.exe"));
    try std.testing.expect(matchPath(miss.value, "processes.command_line", .contains, "CMD.exe"));
}

test "equals is exact, contains is not" {
    var p = try parse("{\"process\":{\"image\":\"C:\\\\Windows\\\\cmd.exe\"}}");
    defer p.deinit();
    try std.testing.expect(!matchPath(p.value, "process.image", .equals, "cmd.exe"));
    try std.testing.expect(matchPath(p.value, "process.image", .endswith, "\\CMD.EXE"));
    try std.testing.expect(matchPath(p.value, "process.image", .startswith, "c:\\windows"));
    try std.testing.expect(matchPath(p.value, "process.image", .contains, "cmd"));
}

test "numeric comparisons" {
    var p = try parse("{\"n\":7,\"f\":2.5,\"s\":\"9\",\"list\":[1,10]}");
    defer p.deinit();
    try std.testing.expect(matchPath(p.value, "n", .greater_than, "5"));
    try std.testing.expect(!matchPath(p.value, "n", .greater_than, "7"));
    try std.testing.expect(matchPath(p.value, "f", .less_than, "3"));
    try std.testing.expect(matchPath(p.value, "s", .greater_than, "8"));
    try std.testing.expect(matchPath(p.value, "list", .greater_than, "5"));
    try std.testing.expect(!matchPath(p.value, "n", .greater_than, "five"));
    try std.testing.expect(matchPath(p.value, "n", .equals, "7"));
    try std.testing.expect(matchPath(p.value, "f", .equals, "2.5"));
}

test "exists needs a non-null value at the path" {
    var p = try parse("{\"a\":{\"b\":null,\"c\":0}}");
    defer p.deinit();
    try std.testing.expect(!matchPath(p.value, "a.b", .exists, ""));
    try std.testing.expect(matchPath(p.value, "a.c", .exists, ""));
    try std.testing.expect(!matchPath(p.value, "a.d", .exists, ""));
}

test "evaluate rejects predicates that would need a text search" {
    var p = try parse("{\"note\":\"cmd.exe\"}");
    defer p.deinit();
    try std.testing.expectEqual(Outcome.invalid, evaluate(p.value, .{ .operator = "contains", .path = null, .want = "cmd.exe" }));
    try std.testing.expectEqual(Outcome.invalid, evaluate(p.value, .{ .operator = "contains", .path = "", .want = "cmd.exe" }));
    try std.testing.expectEqual(Outcome.invalid, evaluate(p.value, .{ .operator = "regex", .path = "note", .want = "cmd" }));
    try std.testing.expectEqual(Outcome.invalid, evaluate(p.value, .{ .operator = "equals", .path = "note", .want = "" }));
    try std.testing.expectEqual(Outcome.no_match, evaluate(p.value, .{ .operator = "contains", .path = "other", .want = "cmd.exe" }));
    try std.testing.expectEqual(Outcome.match, evaluate(p.value, .{ .operator = "contains", .path = "note", .want = "CMD" }));
    try std.testing.expectEqual(Outcome.match, evaluate(p.value, .{ .operator = "exists", .path = "note", .want = null }));
}

test "ioc paths match the agent payload shapes" {
    var dns = try parse("{\"qname\":\"Evil.Example\",\"source\":\"x\"}");
    defer dns.deinit();
    try std.testing.expect(matchPath(dns.value, "qname", .equals, "evil.example"));
    try std.testing.expect(!matchPath(dns.value, "qname", .equals, "sub.evil.example"));

    var net = try parse("{\"connections\":[{\"remote_address\":\"10.0.0.1\"},{\"remote_address\":\"203.0.113.9\",\"remote_port\":443}]}");
    defer net.deinit();
    try std.testing.expect(matchPath(net.value, "connections.remote_address", .equals, "203.0.113.9"));
    try std.testing.expect(!matchPath(net.value, "connections.remote_address", .equals, "203.0.113.90"));

    var fim = try parse("{\"path\":\"/tmp/a\",\"new_sha256\":\"ABCDEF\",\"new_sha1\":\"0123\"}");
    defer fim.deinit();
    try std.testing.expect(matchPath(fim.value, "new_sha256", .equals, "abcdef"));
    try std.testing.expect(matchPath(fim.value, "new_sha1", .equals, "0123"));
    try std.testing.expect(!matchPath(fim.value, "new_sha256", .equals, "abcdef00"));

    var proc = try parse("{\"processes\":[{\"name\":\"curl\",\"command_line\":\"curl https://evil.example/x\"}]}");
    defer proc.deinit();
    try std.testing.expect(matchPath(proc.value, "processes.command_line", .contains, "evil.example"));
}
