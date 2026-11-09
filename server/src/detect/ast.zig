//! Rule AST shared by the Sigma compiler, Tawny sequence and threshold
//! rules, and the detect job.
//!
//! A compiled rule is stored as JSON in `alert_rules.compiled_expression_json`
//! and loaded back with `parseExpr`. Evaluation walks dotted paths with the
//! same fan-out rules as `match.zig`: a path that reaches an array tries every
//! element. Nothing here searches the whole payload text.

const std = @import("std");
const match = @import("match.zig");
const regex = @import("regex.zig");

pub const Op = enum {
    equals,
    contains,
    startswith,
    endswith,
    /// Sigma wildcard pattern: `*` any run, `?` one byte, `\*` `\?` `\\` escapes.
    wildcard,
    regex,
    cidr,
    exists,
    gt,
    gte,
    lt,
    lte,
};

/// Where a predicate reads its value. `join` builds `path<sep>join` from two
/// fields (for example `process.user.domain` and `process.user.name` give
/// Sysmon's `DOMAIN\name`). A missing half is left out with its separator.
pub const Field = struct {
    path: []const u8,
    join: ?[]const u8 = null,
    sep: []const u8 = "",
};

pub const Pred = struct {
    field: Field,
    op: Op,
    values: []const []const u8 = &.{},
    /// Every value must match (Sigma `|all`). Otherwise any value.
    all: bool = false,
    /// Case-insensitive. True for text operators by default; regex is
    /// case-sensitive unless Sigma `|i` was given.
    ci: bool = true,
    /// Compiled patterns for `regex`, filled by `parseExpr`.
    compiled: []const regex.Regex = &.{},
};

pub const Node = union(enum) {
    pred: Pred,
    all_of: []const Node,
    any_of: []const Node,
    not: *const Node,
    constant: bool,
};

// --- JSON form ----------------------------------------------------------------

pub fn writeExpr(w: *std.Io.Writer, node: Node) std.Io.Writer.Error!void {
    switch (node) {
        .constant => |b| try w.print("{{\"const\":{s}}}", .{if (b) "true" else "false"}),
        .not => |inner| {
            try w.writeAll("{\"not\":");
            try writeExpr(w, inner.*);
            try w.writeAll("}");
        },
        .all_of, .any_of => |items| {
            try w.writeAll(if (node == .all_of) "{\"and\":[" else "{\"or\":[");
            for (items, 0..) |it, i| {
                if (i > 0) try w.writeAll(",");
                try writeExpr(w, it);
            }
            try w.writeAll("]}");
        },
        .pred => |p| {
            try w.writeAll("{\"field\":");
            try std.json.Stringify.encodeJsonString(p.field.path, .{}, w);
            if (p.field.join) |j| {
                try w.writeAll(",\"join\":");
                try std.json.Stringify.encodeJsonString(j, .{}, w);
                try w.writeAll(",\"sep\":");
                try std.json.Stringify.encodeJsonString(p.field.sep, .{}, w);
            }
            try w.print(",\"op\":\"{s}\",\"values\":[", .{@tagName(p.op)});
            for (p.values, 0..) |v, i| {
                if (i > 0) try w.writeAll(",");
                try std.json.Stringify.encodeJsonString(v, .{}, w);
            }
            try w.print("],\"all\":{s},\"ci\":{s}}}", .{ if (p.all) "true" else "false", if (p.ci) "true" else "false" });
        },
    }
}

pub fn exprToJson(allocator: std.mem.Allocator, node: Node) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    writeExpr(&out.writer, node) catch return error.OutOfMemory;
    return out.toOwnedSlice();
}

pub const LoadError = error{ OutOfMemory, BadExpression };

/// Build a Node from its JSON form. Everything, including compiled regexes,
/// lives in `arena`.
pub fn parseExpr(arena: std.mem.Allocator, v: std.json.Value) LoadError!Node {
    return parseDepth(arena, v, 0);
}

fn parseDepth(arena: std.mem.Allocator, v: std.json.Value, depth: usize) LoadError!Node {
    if (depth > 64) return error.BadExpression;
    if (v != .object) return error.BadExpression;
    const obj = v.object;
    if (obj.get("const")) |c| {
        if (c != .bool) return error.BadExpression;
        return .{ .constant = c.bool };
    }
    if (obj.get("not")) |inner| {
        const n = try arena.create(Node);
        n.* = try parseDepth(arena, inner, depth + 1);
        return .{ .not = n };
    }
    inline for (.{ "and", "or" }) |key| {
        if (obj.get(key)) |list| {
            if (list != .array) return error.BadExpression;
            const items = try arena.alloc(Node, list.array.items.len);
            for (list.array.items, 0..) |item, i| items[i] = try parseDepth(arena, item, depth + 1);
            return if (comptime std.mem.eql(u8, key, "and")) .{ .all_of = items } else .{ .any_of = items };
        }
    }
    const field = obj.get("field") orelse return error.BadExpression;
    if (field != .string or field.string.len == 0) return error.BadExpression;
    const op_v = obj.get("op") orelse return error.BadExpression;
    if (op_v != .string) return error.BadExpression;
    const op = std.meta.stringToEnum(Op, op_v.string) orelse return error.BadExpression;
    var pred: Pred = .{ .field = .{ .path = field.string }, .op = op };
    if (obj.get("join")) |j| {
        if (j != .string) return error.BadExpression;
        pred.field.join = j.string;
        const sep = obj.get("sep") orelse return error.BadExpression;
        if (sep != .string) return error.BadExpression;
        pred.field.sep = sep.string;
    }
    if (obj.get("values")) |vals| {
        if (vals != .array) return error.BadExpression;
        const out = try arena.alloc([]const u8, vals.array.items.len);
        for (vals.array.items, 0..) |item, i| {
            if (item != .string) return error.BadExpression;
            out[i] = item.string;
        }
        pred.values = out;
    }
    if (obj.get("all")) |a| pred.all = a == .bool and a.bool;
    if (obj.get("ci")) |c| pred.ci = c == .bool and c.bool;
    if (op != .exists and pred.values.len == 0) return error.BadExpression;
    if (op == .regex) {
        const res = try arena.alloc(regex.Regex, pred.values.len);
        for (pred.values, 0..) |pat, i| {
            switch (try regex.compile(arena, pat, pred.ci)) {
                .ok => |re| res[i] = re,
                .refused => return error.BadExpression,
            }
        }
        pred.compiled = res;
    }
    if (op == .cidr) {
        for (pred.values) |c| _ = parseCidr(c) orelse return error.BadExpression;
    }
    return .{ .pred = pred };
}

// --- evaluation -----------------------------------------------------------------

pub const Env = struct {
    /// Scratch allocator for regex thread lists and joined fields.
    allocator: std.mem.Allocator,
    step_limit: usize = regex.default_step_limit,
};

pub fn eval(env: Env, node: Node, root: std.json.Value) bool {
    return evalDepth(env, node, root, 0);
}

fn evalDepth(env: Env, node: Node, root: std.json.Value, depth: usize) bool {
    if (depth > 64) return false;
    return switch (node) {
        .constant => |b| b,
        .not => |inner| !evalDepth(env, inner.*, root, depth + 1),
        .all_of => |items| {
            for (items) |it| {
                if (!evalDepth(env, it, root, depth + 1)) return false;
            }
            return true;
        },
        .any_of => |items| {
            for (items) |it| {
                if (evalDepth(env, it, root, depth + 1)) return true;
            }
            return false;
        },
        .pred => |p| evalPred(env, p, root),
    };
}

const Ctx = struct { env: Env, pred: *const Pred };

fn evalPred(env: Env, p: Pred, root: std.json.Value) bool {
    if (p.field.join) |second| return evalJoined(env, p, root, second);
    const ctx: Ctx = .{ .env = env, .pred = &p };
    return match.anyAtPath(root, p.field.path, ctx, valueMatches);
}

fn valueMatches(ctx: Ctx, value: std.json.Value) bool {
    const p = ctx.pred;
    if (p.op == .exists) return value != .null;
    if (p.all) {
        for (p.values, 0..) |want, i| {
            if (!one(ctx.env, p, i, want, value)) return false;
        }
        return p.values.len > 0;
    }
    for (p.values, 0..) |want, i| {
        if (one(ctx.env, p, i, want, value)) return true;
    }
    return false;
}

fn one(env: Env, p: *const Pred, index: usize, want: []const u8, value: std.json.Value) bool {
    switch (p.op) {
        .gt, .gte, .lt, .lte => {
            const have = match.numberValue(value) orelse return false;
            const w = std.fmt.parseFloat(f64, std.mem.trim(u8, want, " \t")) catch return false;
            return switch (p.op) {
                .gt => have > w,
                .gte => have >= w,
                .lt => have < w,
                .lte => have <= w,
                else => unreachable,
            };
        },
        else => {},
    }
    var buf: [64]u8 = undefined;
    const text = match.scalarText(value, &buf) orelse return false;
    if (p.op == .equals) {
        // Numbers compare numerically so `7` equals `7.0`.
        if (value == .integer or value == .float) {
            const have = match.numberValue(value).?;
            const w = std.fmt.parseFloat(f64, std.mem.trim(u8, want, " \t")) catch return false;
            return have == w;
        }
    }
    return textOp(env, p, index, want, text);
}

pub fn textOp(env: Env, p: *const Pred, index: usize, want: []const u8, text: []const u8) bool {
    const ci = p.ci;
    return switch (p.op) {
        .equals => if (ci) std.ascii.eqlIgnoreCase(text, want) else std.mem.eql(u8, text, want),
        .contains => if (ci) std.ascii.findIgnoreCase(text, want) != null else std.mem.indexOf(u8, text, want) != null,
        .startswith => if (ci) std.ascii.startsWithIgnoreCase(text, want) else std.mem.startsWith(u8, text, want),
        .endswith => if (ci) std.ascii.endsWithIgnoreCase(text, want) else std.mem.endsWith(u8, text, want),
        .wildcard => wildcardMatch(want, text, ci),
        .regex => blk: {
            if (index >= p.compiled.len) break :blk false;
            const r = p.compiled[index].search(env.allocator, text, env.step_limit) catch break :blk false;
            break :blk r == .match;
        },
        .cidr => cidrContains(want, text),
        else => false,
    };
}

fn evalJoined(env: Env, p: Pred, root: std.json.Value, second: []const u8) bool {
    var b1: [64]u8 = undefined;
    var b2: [64]u8 = undefined;
    const a = firstScalar(root, p.field.path, &b1);
    const b = firstScalar(root, second, &b2);
    if (p.op == .exists) return a != null or b != null;
    if (a == null and b == null) return false;
    const joined = if (a != null and b != null)
        std.mem.concat(env.allocator, u8, &.{ a.?, p.field.sep, b.? }) catch return false
    else
        env.allocator.dupe(u8, a orelse b.?) catch return false;
    defer env.allocator.free(joined);
    const v: std.json.Value = .{ .string = joined };
    return valueMatches(.{ .env = env, .pred = &p }, v);
}

const FirstCtx = struct { out: *?[]const u8, buf: *[64]u8 };

fn takeFirst(ctx: FirstCtx, value: std.json.Value) bool {
    if (match.scalarText(value, ctx.buf)) |t| {
        ctx.out.* = t;
        return true;
    }
    return false;
}

/// First scalar at a dotted path, as text. Integers are formatted into `buf`.
pub fn firstScalar(root: std.json.Value, path: []const u8, buf: *[64]u8) ?[]const u8 {
    var out: ?[]const u8 = null;
    _ = match.anyAtPath(root, path, FirstCtx{ .out = &out, .buf = buf }, takeFirst);
    return out;
}

/// Sigma wildcard match. `*` matches any run, `?` one byte. `\*`, `\?` and
/// `\\` are literals; any other backslash is a literal backslash. The greedy
/// two-pointer method keeps this at O(pattern * text) in the worst case.
pub fn wildcardMatch(pattern: []const u8, text: []const u8, ci: bool) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star_p: ?usize = null;
    var star_t: usize = 0;
    while (t < text.len) {
        if (p < pattern.len) {
            const tok = token(pattern, p);
            switch (tok.kind) {
                .star => {
                    star_p = p + tok.len;
                    star_t = t;
                    p += tok.len;
                    continue;
                },
                .one => {
                    p += tok.len;
                    t += 1;
                    continue;
                },
                .lit => {
                    const eq = if (ci) std.ascii.toLower(tok.byte) == std.ascii.toLower(text[t]) else tok.byte == text[t];
                    if (eq) {
                        p += tok.len;
                        t += 1;
                        continue;
                    }
                },
            }
        }
        if (star_p) |sp| {
            star_t += 1;
            t = star_t;
            p = sp;
            continue;
        }
        return false;
    }
    while (p < pattern.len) {
        const tok = token(pattern, p);
        if (tok.kind != .star) return false;
        p += tok.len;
    }
    return true;
}

const Tok = struct { kind: enum { lit, star, one }, byte: u8 = 0, len: usize };

fn token(pattern: []const u8, i: usize) Tok {
    const c = pattern[i];
    if (c == '\\' and i + 1 < pattern.len) {
        const n = pattern[i + 1];
        if (n == '*' or n == '?' or n == '\\') return .{ .kind = .lit, .byte = n, .len = 2 };
        return .{ .kind = .lit, .byte = '\\', .len = 1 };
    }
    if (c == '*') return .{ .kind = .star, .len = 1 };
    if (c == '?') return .{ .kind = .one, .len = 1 };
    return .{ .kind = .lit, .byte = c, .len = 1 };
}

/// True when `pattern` has an unescaped `*` or `?`.
pub fn hasWildcard(pattern: []const u8) bool {
    var i: usize = 0;
    while (i < pattern.len) {
        const tok = token(pattern, i);
        if (tok.kind != .lit) return true;
        i += tok.len;
    }
    return false;
}

/// Remove Sigma escapes from a pattern with no wildcards.
pub fn unescape(allocator: std.mem.Allocator, pattern: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < pattern.len) {
        const tok = token(pattern, i);
        try out.append(allocator, tok.byte);
        i += tok.len;
    }
    return out.toOwnedSlice(allocator);
}

pub const Cidr = struct { bytes: [16]u8, len: u8, v6: bool, prefix: u8 };

pub fn parseCidr(text: []const u8) ?Cidr {
    const slash = std.mem.indexOfScalar(u8, text, '/') orelse return null;
    const addr = parseIp(text[0..slash]) orelse return null;
    const prefix = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch return null;
    if (prefix > addr.len * 8) return null;
    return .{ .bytes = addr.bytes, .len = addr.len, .v6 = addr.len == 16, .prefix = prefix };
}

const Ip = struct { bytes: [16]u8, len: u8 };

fn parseIp(text_in: []const u8) ?Ip {
    var text = std.mem.trim(u8, text_in, " ");
    // `::ffff:1.2.3.4` is an IPv4 address for matching.
    if (std.ascii.startsWithIgnoreCase(text, "::ffff:") and std.mem.indexOfScalar(u8, text[7..], ':') == null) text = text[7..];
    var out: Ip = .{ .bytes = @splat(0), .len = 4 };
    if (std.Io.net.Ip4Address.parse(text, 0)) |a| {
        @memcpy(out.bytes[0..4], &a.bytes);
        return out;
    } else |_| {}
    // Drop a zone id.
    const pct = std.mem.indexOfScalar(u8, text, '%') orelse text.len;
    if (std.Io.net.Ip6Address.parse(text[0..pct], 0)) |a| {
        out.bytes = a.bytes;
        out.len = 16;
        return out;
    } else |_| {}
    return null;
}

pub fn cidrContains(cidr_text: []const u8, ip_text: []const u8) bool {
    const c = parseCidr(cidr_text) orelse return false;
    const ip = parseIp(ip_text) orelse return false;
    if (ip.len != c.len) return false;
    var bits: usize = c.prefix;
    var i: usize = 0;
    while (bits > 0) : (i += 1) {
        const take: u4 = @intCast(@min(bits, 8));
        const mask: u8 = if (take == 8) 0xff else @as(u8, 0xff) << @intCast(8 - @as(u8, take));
        if ((ip.bytes[i] & mask) != (c.bytes[i] & mask)) return false;
        bits -= take;
    }
    return true;
}

// --- tests ------------------------------------------------------------------------

fn parseJson(text: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, std.testing.allocator, text, .{});
}

test "wildcards and escapes" {
    try std.testing.expect(wildcardMatch("*\\cmd.exe", "C:\\Windows\\System32\\CMD.EXE", true));
    try std.testing.expect(!wildcardMatch("*\\cmd.exe", "C:\\Windows\\System32\\CMD.EXE", false));
    try std.testing.expect(wildcardMatch("a?c", "abc", true));
    try std.testing.expect(!wildcardMatch("a?c", "ac", true));
    try std.testing.expect(wildcardMatch("a\\*c", "a*c", true));
    try std.testing.expect(!wildcardMatch("a\\*c", "abc", true));
    try std.testing.expect(wildcardMatch("*a*b*c*", "xxaxxbxxcxx", true));
    try std.testing.expect(!wildcardMatch("*a*b*c*", "xxaxxcxxbxx", true));
    // Sigma: `\*` is a literal star; `\\*` is a backslash then a wildcard.
    try std.testing.expect(wildcardMatch("C:\\Windows\\\\*", "c:\\windows\\x", true));
    try std.testing.expect(!wildcardMatch("C:\\Windows\\*", "c:\\windows\\x", true));
    try std.testing.expect(hasWildcard("a*"));
    try std.testing.expect(!hasWildcard("a\\*"));
    const u = try unescape(std.testing.allocator, "a\\*b\\\\c\\d");
    defer std.testing.allocator.free(u);
    try std.testing.expectEqualStrings("a*b\\c\\d", u);
}

test "cidr" {
    try std.testing.expect(cidrContains("10.0.0.0/8", "10.20.30.40"));
    try std.testing.expect(!cidrContains("10.0.0.0/8", "11.0.0.1"));
    try std.testing.expect(cidrContains("192.168.1.0/25", "192.168.1.127"));
    try std.testing.expect(!cidrContains("192.168.1.0/25", "192.168.1.128"));
    try std.testing.expect(cidrContains("fe80::/10", "fe80::1"));
    try std.testing.expect(cidrContains("127.0.0.0/8", "::ffff:127.0.0.1"));
    try std.testing.expect(!cidrContains("127.0.0.0/8", "not-an-ip"));
    try std.testing.expect(parseCidr("10.0.0.0/33") == null);
}

test "expression round trip and evaluation" {
    const a = std.testing.allocator;
    const leaf_img: Node = .{ .pred = .{ .field = .{ .path = "process.image" }, .op = .endswith, .values = &.{ "\\powershell.exe", "\\pwsh.exe" } } };
    const leaf_cli: Node = .{ .pred = .{ .field = .{ .path = "process.command_line" }, .op = .contains, .values = &.{ " -enc", "bypass" }, .all = true } };
    const leaf_user: Node = .{ .pred = .{ .field = .{ .path = "process.user.domain", .join = "process.user.name", .sep = "\\" }, .op = .equals, .values = &.{"corp\\alice"} } };
    const filt: Node = .{ .pred = .{ .field = .{ .path = "parent.image" }, .op = .regex, .values = &.{"(?i)\\\\explorer\\.exe$"}, .ci = false } };
    const neg: Node = .{ .not = &filt };
    const root_node: Node = .{ .all_of = &.{ leaf_img, leaf_cli, leaf_user, neg } };
    const json = try exprToJson(a, root_node);
    defer a.free(json);

    var parsed_expr = try parseJson(json);
    defer parsed_expr.deinit();
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const loaded = try parseExpr(arena_state.allocator(), parsed_expr.value);
    const again = try exprToJson(a, loaded);
    defer a.free(again);
    try std.testing.expectEqualStrings(json, again);

    const env: Env = .{ .allocator = a };
    var hit = try parseJson(
        \\{"process":{"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\POWERSHELL.EXE","command_line":"powershell -enc AAA -ep Bypass","user":{"name":"alice","domain":"CORP"}},"parent":{"image":"C:\\Program Files\\Microsoft Office\\WINWORD.EXE"}}
    );
    defer hit.deinit();
    try std.testing.expect(eval(env, loaded, hit.value));

    var only_one = try parseJson(
        \\{"process":{"image":"C:\\x\\powershell.exe","command_line":"powershell -enc AAA","user":{"name":"alice","domain":"CORP"}},"parent":{"image":"C:\\Program Files\\Microsoft Office\\WINWORD.EXE"}}
    );
    defer only_one.deinit();
    try std.testing.expect(!eval(env, loaded, only_one.value));

    var filtered = try parseJson(
        \\{"process":{"image":"C:\\x\\pwsh.exe","command_line":"-enc bypass","user":{"name":"alice","domain":"CORP"}},"parent":{"image":"C:\\Windows\\Explorer.EXE"}}
    );
    defer filtered.deinit();
    try std.testing.expect(!eval(env, loaded, filtered.value));
}

test "numbers, exists and fan-out" {
    const a = std.testing.allocator;
    var ev = try parseJson("{\"event_id\":4625,\"logon\":{\"type\":3},\"list\":[{\"n\":1},{\"n\":30}]}");
    defer ev.deinit();
    const env: Env = .{ .allocator = a };
    try std.testing.expect(eval(env, .{ .pred = .{ .field = .{ .path = "event_id" }, .op = .equals, .values = &.{"4625"} } }, ev.value));
    try std.testing.expect(!eval(env, .{ .pred = .{ .field = .{ .path = "event_id" }, .op = .equals, .values = &.{"4624"} } }, ev.value));
    try std.testing.expect(eval(env, .{ .pred = .{ .field = .{ .path = "list.n" }, .op = .gte, .values = &.{"30"} } }, ev.value));
    try std.testing.expect(!eval(env, .{ .pred = .{ .field = .{ .path = "list.n" }, .op = .gt, .values = &.{"30"} } }, ev.value));
    try std.testing.expect(eval(env, .{ .pred = .{ .field = .{ .path = "logon.type" }, .op = .exists } }, ev.value));
    try std.testing.expect(!eval(env, .{ .pred = .{ .field = .{ .path = "logon.missing" }, .op = .exists } }, ev.value));
}
