//! Hunt DSL. Same grammar as `HuntQueryParser` / `HuntExecutor`.
//! Every event type is accepted. Simple top-level predicates are pushed
//! into SQL. The pull is capped at 5,000 rows.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");

pub const prefilter_cap: u32 = 5000;
pub const default_limit: u32 = 200;
pub const max_limit: u32 = 1000;

pub const Op = enum { equals, not_equals, contains, in_list, gt, lt, gte, lte };

pub const Node = union(enum) {
    @"and": [2]u32,
    @"or": [2]u32,
    not: u32,
    pred: Pred,
};

pub const Pred = struct {
    field: []u8,
    op: Op,
    values: [][]u8,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    nodes: std.ArrayList(Node) = .empty,
    root: ?u32 = null,
    from: ?[]u8 = null,
    to: ?[]u8 = null,
    event_type: ?[]u8 = null,
    agent_id: ?[]u8 = null,
    agent_like: ?[]u8 = null,
    limit: u32 = default_limit,

    pub fn deinit(self: *Plan) void {
        for (self.nodes.items) |node| switch (node) {
            .pred => |p| {
                self.allocator.free(p.field);
                for (p.values) |v| self.allocator.free(v);
                self.allocator.free(p.values);
            },
            else => {},
        };
        self.nodes.deinit(self.allocator);
        if (self.from) |s| self.allocator.free(s);
        if (self.to) |s| self.allocator.free(s);
        if (self.event_type) |s| self.allocator.free(s);
        if (self.agent_id) |s| self.allocator.free(s);
        if (self.agent_like) |s| self.allocator.free(s);
    }
};

pub const Match = struct {
    event_id: []u8,
    agent_id: []u8,
    hostname: []u8,
    event_type: []u8,
    occurred_at: []u8,
    received_at: []u8,
    payload: []u8,
};

pub const Result = struct {
    matches: []Match,
    warnings: [][]u8,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        for (self.matches) |m| {
            allocator.free(m.event_id);
            allocator.free(m.agent_id);
            allocator.free(m.hostname);
            allocator.free(m.event_type);
            allocator.free(m.occurred_at);
            allocator.free(m.received_at);
            allocator.free(m.payload);
        }
        allocator.free(self.matches);
        for (self.warnings) |w| allocator.free(w);
        allocator.free(self.warnings);
    }
};

const Kind = enum {
    ident,
    string,
    number,
    colon,
    eql,
    neq,
    gt,
    lt,
    gte,
    lte,
    lparen,
    rparen,
    lbrack,
    rbrack,
    comma,
    dot,
};

const Token = struct {
    kind: Kind,
    value: []const u8,
    owned: bool = false,
};

pub fn parse(allocator: std.mem.Allocator, source: []const u8, limit: ?u32, now_unix: i64, msg: *[]u8) !Plan {
    var plan = Plan{ .allocator = allocator };
    errdefer plan.deinit();
    var tokens = try tokenize(allocator, source, msg);
    defer {
        for (tokens.items) |t| if (t.owned) allocator.free(t.value);
        tokens.deinit(allocator);
    }

    var residual: std.ArrayList(Token) = .empty;
    defer residual.deinit(allocator);
    var ate_shortcut = false;
    var i: usize = 0;
    while (i < tokens.items.len) : (i += 1) {
        if (i + 2 >= tokens.items.len or tokens.items[i].kind != .ident or tokens.items[i + 1].kind != .colon) {
            try residual.append(allocator, tokens.items[i]);
            continue;
        }
        const field = tokens.items[i].value;
        const value_tok = tokens.items[i + 2];
        if (value_tok.kind != .ident and value_tok.kind != .string and value_tok.kind != .number) {
            try residual.append(allocator, tokens.items[i]);
            continue;
        }
        if (eqlIc(field, "from")) {
            if (!looksLikeTime(value_tok.value)) return fail(msg, "Could not parse '{s}' as an ISO-8601 datetime.", .{value_tok.value});
            if (plan.from) |old| allocator.free(old);
            plan.from = try allocator.dupe(u8, value_tok.value);
            ate_shortcut = true;
            i += 2;
            continue;
        }
        if (eqlIc(field, "to")) {
            if (!looksLikeTime(value_tok.value)) return fail(msg, "Could not parse '{s}' as an ISO-8601 datetime.", .{value_tok.value});
            if (plan.to) |old| allocator.free(old);
            plan.to = try allocator.dupe(u8, value_tok.value);
            ate_shortcut = true;
            i += 2;
            continue;
        }
        if (eqlIc(field, "last")) {
            const secs = durationSeconds(value_tok.value) orelse return fail(msg, "Could not parse duration '{s}'. Use e.g. '15m', '2h', '7d'.", .{value_tok.value});
            var tbuf: [32]u8 = undefined;
            const stamp = util.formatRfc3339(&tbuf, now_unix - secs);
            if (plan.from) |old| allocator.free(old);
            plan.from = try allocator.dupe(u8, stamp);
            ate_shortcut = true;
            i += 2;
            continue;
        }
        if (eqlIc(field, "event_type")) {
            if (plan.event_type) |old| allocator.free(old);
            plan.event_type = try normalizeEventType(allocator, value_tok.value);
            ate_shortcut = true;
            i += 2;
            continue;
        }
        if (eqlIc(field, "agent")) {
            if (plan.agent_like) |old| allocator.free(old);
            plan.agent_like = try allocator.dupe(u8, value_tok.value);
            ate_shortcut = true;
            i += 2;
            continue;
        }
        if (eqlIc(field, "agent_id")) {
            if (!isGuid(value_tok.value)) return fail(msg, "agent_id must be a GUID, got '{s}'.", .{value_tok.value});
            if (plan.agent_id) |old| allocator.free(old);
            plan.agent_id = try allocator.dupe(u8, value_tok.value);
            ate_shortcut = true;
            i += 2;
            continue;
        }
        try residual.append(allocator, tokens.items[i]);
    }

    if (residual.items.len > 0) {
        var pos: usize = 0;
        // Starter queries write `event_type:x AND field:y`. The shortcut is
        // consumed, so the residual starts with the connective. Skip those
        // leading and/or tokens. A predicate-to-predicate AND stays.
        if (ate_shortcut) {
            while (pos < residual.items.len and isConnective(residual.items[pos])) pos += 1;
        }
        if (pos < residual.items.len) {
            plan.root = try parseOr(allocator, &plan, residual.items, &pos, msg);
            if (pos < residual.items.len) return fail(msg, "Unexpected token '{s}' at position {d}.", .{ residual.items[pos].value, pos });
        }
    }
    const requested = limit orelse default_limit;
    plan.limit = std.math.clamp(requested, 1, max_limit);
    return plan;
}

pub fn matches(allocator: std.mem.Allocator, plan: *const Plan, payload_json: []const u8) !bool {
    const root = plan.root orelse return true;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer parsed.deinit();
    return evalNode(allocator, plan, root, parsed.value);
}

pub fn execute(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    tenant_id: []const u8,
    plan: *const Plan,
    min_event_id: i64,
    now_unix: i64,
) !Result {
    var warnings: std.ArrayList([]u8) = .empty;
    errdefer {
        for (warnings.items) |w| allocator.free(w);
        warnings.deinit(allocator);
    }

    var from_owned: ?[]u8 = null;
    defer if (from_owned) |s| allocator.free(s);
    var from_text: ?[]const u8 = plan.from;
    if (plan.from == null and plan.to == null and plan.event_type == null and plan.agent_id == null) {
        var tbuf: [32]u8 = undefined;
        const stamp = util.formatRfc3339(&tbuf, now_unix - 24 * 3600);
        from_owned = try allocator.dupe(u8, stamp);
        from_text = from_owned;
        try warnings.append(allocator, try allocator.dupe(u8, "No time window specified — restricted to the last 24h. Add 'last:7d' or 'from:...' to widen."));
    }

    var like_owned: ?[]u8 = null;
    defer if (like_owned) |s| allocator.free(s);
    if (plan.agent_like) |host| {
        like_owned = try std.fmt.allocPrint(allocator, "%{s}%", .{host});
    }

    var min_buf: [32]u8 = undefined;
    const min_text = std.fmt.bufPrint(&min_buf, "{d}", .{min_event_id}) catch "0";

    var params: [16]pg.Value = undefined;
    params[0] = .{ .text = tenant_id };
    params[1] = if (plan.event_type) |s| .{ .text = s } else .{ .null = {} };
    params[2] = if (plan.agent_id) |s| .{ .text = s } else .{ .null = {} };
    params[3] = if (from_text) |s| .{ .text = s } else .{ .null = {} };
    params[4] = if (plan.to) |s| .{ .text = s } else .{ .null = {} };
    params[5] = if (like_owned) |s| .{ .text = s } else .{ .null = {} };
    params[6] = .{ .text = min_text };
    var nparams: usize = 7;

    var sql: std.ArrayList(u8) = .empty;
    defer sql.deinit(allocator);
    try sql.appendSlice(allocator,
        \\SELECT te.id::text, te.agent_id::text, ag.hostname, te.event_type,
        \\       te.occurred_at::text, te.received_at::text, te.payload::text
        \\FROM telemetry_events te
        \\JOIN agents ag ON ag.id = te.agent_id
        \\WHERE te.tenant_id = $1::uuid
        \\  AND ($2::text IS NULL OR te.event_type = $2)
        \\  AND ($3::text IS NULL OR te.agent_id = $3::uuid)
        \\  AND ($4::text IS NULL OR te.occurred_at >= $4::timestamptz)
        \\  AND ($5::text IS NULL OR te.occurred_at <= $5::timestamptz)
        \\  AND ($6::text IS NULL OR ag.hostname ILIKE $6)
        \\  AND te.id > $7::bigint
    );
    if (plan.root) |root| {
        var pushed: std.ArrayList(u32) = .empty;
        defer pushed.deinit(allocator);
        if (try pushable(allocator, plan, root, &pushed)) {
            for (pushed.items) |idx| {
                if (nparams + 2 > params.len) break;
                const pred = plan.nodes.items[idx].pred;
                if (pred.values.len == 0) continue;
                if (std.mem.indexOfScalar(u8, pred.field, '.') != null) continue;
                if (!safeIdent(pred.field)) continue;
                const slot_f = nparams + 1;
                const slot_v = nparams + 2;
                const clause = switch (pred.op) {
                    .equals => try std.fmt.allocPrint(allocator, " AND lower(te.payload->>${d}) = lower(${d})", .{ slot_f, slot_v }),
                    .contains => try std.fmt.allocPrint(allocator, " AND position(lower(${d}) in lower(coalesce(te.payload->>${d}, ''))) > 0", .{ slot_v, slot_f }),
                    else => continue,
                };
                defer allocator.free(clause);
                try sql.appendSlice(allocator, clause);
                params[nparams] = .{ .text = pred.field };
                params[nparams + 1] = .{ .text = pred.values[0] };
                nparams += 2;
            }
        }
    }
    const tail = try std.fmt.allocPrint(allocator, " ORDER BY te.occurred_at DESC, te.id DESC LIMIT {d}", .{prefilter_cap});
    defer allocator.free(tail);
    try sql.appendSlice(allocator, tail);

    const rows = try conn.exec(allocator, sql.items, params[0..nparams]);
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == prefilter_cap) {
        try warnings.append(allocator, try std.fmt.allocPrint(allocator, "Hit prefilter cap of {d} events. Narrow the query with event_type, agent, or a tighter time window.", .{prefilter_cap}));
    }

    var matches_out: std.ArrayList(Match) = .empty;
    errdefer {
        for (matches_out.items) |m| {
            allocator.free(m.event_id);
            allocator.free(m.agent_id);
            allocator.free(m.hostname);
            allocator.free(m.event_type);
            allocator.free(m.occurred_at);
            allocator.free(m.received_at);
            allocator.free(m.payload);
        }
        matches_out.deinit(allocator);
    }
    for (rows) |row| {
        if (matches_out.items.len >= plan.limit) break;
        const payload = row.cols[6] orelse continue;
        const event_id = row.cols[0] orelse continue;
        const agent_id = row.cols[1] orelse continue;
        if (!(try matches(allocator, plan, payload))) continue;
        const event_copy = try allocator.dupe(u8, event_id);
        errdefer allocator.free(event_copy);
        const agent_copy = try allocator.dupe(u8, agent_id);
        errdefer allocator.free(agent_copy);
        const host_copy = try allocator.dupe(u8, row.cols[2] orelse "");
        errdefer allocator.free(host_copy);
        const type_copy = try allocator.dupe(u8, row.cols[3] orelse "");
        errdefer allocator.free(type_copy);
        const occurred_copy = try allocator.dupe(u8, row.cols[4] orelse "");
        errdefer allocator.free(occurred_copy);
        const received_copy = try allocator.dupe(u8, row.cols[5] orelse "");
        errdefer allocator.free(received_copy);
        const payload_copy = try allocator.dupe(u8, payload);
        errdefer allocator.free(payload_copy);
        try matches_out.append(allocator, .{
            .event_id = event_copy,
            .agent_id = agent_copy,
            .hostname = host_copy,
            .event_type = type_copy,
            .occurred_at = occurred_copy,
            .received_at = received_copy,
            .payload = payload_copy,
        });
    }
    return .{
        .matches = try matches_out.toOwnedSlice(allocator),
        .warnings = try warnings.toOwnedSlice(allocator),
    };
}

fn pushable(allocator: std.mem.Allocator, plan: *const Plan, idx: u32, out: *std.ArrayList(u32)) !bool {
    switch (plan.nodes.items[idx]) {
        .@"and" => |pair| {
            return (try pushable(allocator, plan, pair[0], out)) and (try pushable(allocator, plan, pair[1], out));
        },
        .pred => |p| {
            if (p.op != .equals and p.op != .contains) return false;
            if (p.values.len != 1) return false;
            if (std.mem.indexOfScalar(u8, p.field, '.') != null) return false;
            if (!safeIdent(p.field)) return false;
            try out.append(allocator, idx);
            return true;
        },
        else => return false,
    }
}

fn safeIdent(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_') return false;
    }
    return true;
}

fn evalNode(allocator: std.mem.Allocator, plan: *const Plan, idx: u32, payload: std.json.Value) !bool {
    return switch (plan.nodes.items[idx]) {
        .@"and" => |pair| (try evalNode(allocator, plan, pair[0], payload)) and (try evalNode(allocator, plan, pair[1], payload)),
        .@"or" => |pair| (try evalNode(allocator, plan, pair[0], payload)) or (try evalNode(allocator, plan, pair[1], payload)),
        .not => |inner| !(try evalNode(allocator, plan, inner, payload)),
        .pred => |p| evalPred(allocator, p, payload),
    };
}

fn evalPred(allocator: std.mem.Allocator, pred: Pred, payload: std.json.Value) !bool {
    var path = pred.field;
    if (path.len >= 8 and eqlIc(path[0..8], "payload.")) path = path[8..];
    var scalars: std.ArrayList([]u8) = .empty;
    defer {
        for (scalars.items) |s| allocator.free(s);
        scalars.deinit(allocator);
    }
    var segs_buf: [8][]const u8 = undefined;
    var nseg: usize = 0;
    var rest = path;
    while (rest.len > 0 and nseg < segs_buf.len) {
        const dot = std.mem.indexOfScalar(u8, rest, '.');
        segs_buf[nseg] = if (dot) |d| rest[0..d] else rest;
        nseg += 1;
        rest = if (dot) |d| rest[d + 1 ..] else "";
    }
    try walk(allocator, payload, segs_buf[0..nseg], 0, &scalars);
    if (scalars.items.len == 0) return pred.op == .not_equals;
    switch (pred.op) {
        .equals, .in_list => {
            for (scalars.items) |s| for (pred.values) |t| if (eqlIc(s, t)) return true;
            return false;
        },
        .not_equals => {
            for (scalars.items) |s| for (pred.values) |t| if (eqlIc(s, t)) return false;
            return true;
        },
        .contains => {
            for (scalars.items) |s| for (pred.values) |t| if (util.containsIgnoreCase(s, t)) return true;
            return false;
        },
        .gt => return cmpNum(scalars.items, pred.values, .gt),
        .lt => return cmpNum(scalars.items, pred.values, .lt),
        .gte => return cmpNum(scalars.items, pred.values, .gte),
        .lte => return cmpNum(scalars.items, pred.values, .lte),
    }
}

const Cmp = enum { gt, lt, gte, lte };

fn cmpNum(values: [][]u8, targets: [][]u8, cmp: Cmp) bool {
    for (values) |raw| {
        const a = std.fmt.parseFloat(f64, raw) catch continue;
        for (targets) |t| {
            const b = std.fmt.parseFloat(f64, t) catch continue;
            const ok = switch (cmp) {
                .gt => a > b,
                .lt => a < b,
                .gte => a >= b,
                .lte => a <= b,
            };
            if (ok) return true;
        }
    }
    return false;
}

fn walk(allocator: std.mem.Allocator, cur: std.json.Value, segs: []const []const u8, idx: usize, out: *std.ArrayList([]u8)) !void {
    if (idx >= segs.len) {
        if (try scalar(allocator, cur)) |s| try out.append(allocator, s);
        return;
    }
    switch (cur) {
        .array => |arr| {
            for (arr.items) |item| try walk(allocator, item, segs, idx, out);
        },
        .object => |obj| {
            const child = obj.get(segs[idx]) orelse return;
            try walk(allocator, child, segs, idx + 1, out);
        },
        else => {},
    }
}

fn scalar(allocator: std.mem.Allocator, value: std.json.Value) !?[]u8 {
    return switch (value) {
        .string => |s| try allocator.dupe(u8, s),
        .integer => |n| try std.fmt.allocPrint(allocator, "{d}", .{n}),
        .float => |n| try std.fmt.allocPrint(allocator, "{d}", .{n}),
        .number_string => |s| try allocator.dupe(u8, s),
        .bool => |b| try allocator.dupe(u8, if (b) "true" else "false"),
        .null => try allocator.dupe(u8, ""),
        else => null,
    };
}

const ParseError = error{BadQuery} || std.mem.Allocator.Error;

fn parseOr(allocator: std.mem.Allocator, plan: *Plan, tokens: []const Token, pos: *usize, msg: *[]u8) ParseError!u32 {
    var left = try parseAnd(allocator, plan, tokens, pos, msg);
    while (pos.* < tokens.len and tokens[pos.*].kind == .ident and eqlIc(tokens[pos.*].value, "or")) {
        pos.* += 1;
        const right = try parseAnd(allocator, plan, tokens, pos, msg);
        try plan.nodes.append(allocator, .{ .@"or" = .{ left, right } });
        left = @intCast(plan.nodes.items.len - 1);
    }
    return left;
}

fn parseAnd(allocator: std.mem.Allocator, plan: *Plan, tokens: []const Token, pos: *usize, msg: *[]u8) ParseError!u32 {
    var left = try parseUnary(allocator, plan, tokens, pos, msg);
    while (pos.* < tokens.len and tokens[pos.*].kind == .ident and eqlIc(tokens[pos.*].value, "and")) {
        pos.* += 1;
        const right = try parseUnary(allocator, plan, tokens, pos, msg);
        try plan.nodes.append(allocator, .{ .@"and" = .{ left, right } });
        left = @intCast(plan.nodes.items.len - 1);
    }
    return left;
}

fn parseUnary(allocator: std.mem.Allocator, plan: *Plan, tokens: []const Token, pos: *usize, msg: *[]u8) ParseError!u32 {
    if (pos.* >= tokens.len) return fail(msg, "Unexpected end of query.", .{});
    const tok = tokens[pos.*];
    if (tok.kind == .ident and eqlIc(tok.value, "not")) {
        pos.* += 1;
        const inner = try parseUnary(allocator, plan, tokens, pos, msg);
        try plan.nodes.append(allocator, .{ .not = inner });
        return @intCast(plan.nodes.items.len - 1);
    }
    if (tok.kind == .lparen) {
        pos.* += 1;
        const inner = try parseOr(allocator, plan, tokens, pos, msg);
        if (pos.* >= tokens.len or tokens[pos.*].kind != .rparen) return fail(msg, "Expected ')'.", .{});
        pos.* += 1;
        return inner;
    }
    return parsePred(allocator, plan, tokens, pos, msg);
}

fn parsePred(allocator: std.mem.Allocator, plan: *Plan, tokens: []const Token, pos: *usize, msg: *[]u8) ParseError!u32 {
    if (pos.* >= tokens.len or tokens[pos.*].kind != .ident) {
        if (pos.* < tokens.len) return fail(msg, "Expected a field name, got '{s}'.", .{tokens[pos.*].value});
        return fail(msg, "Expected a field name.", .{});
    }
    var field: std.ArrayList(u8) = .empty;
    errdefer field.deinit(allocator);
    try field.appendSlice(allocator, tokens[pos.*].value);
    pos.* += 1;
    while (pos.* < tokens.len and tokens[pos.*].kind == .dot) {
        pos.* += 1;
        if (pos.* >= tokens.len or tokens[pos.*].kind != .ident) return fail(msg, "Expected identifier after '.'.", .{});
        try field.append(allocator, '.');
        try field.appendSlice(allocator, tokens[pos.*].value);
        pos.* += 1;
    }
    if (pos.* >= tokens.len) return fail(msg, "Expected operator after field '{s}'.", .{field.items});
    var op: Op = switch (tokens[pos.*].kind) {
        .colon, .eql => .contains,
        .neq => .not_equals,
        .gt => .gt,
        .lt => .lt,
        .gte => .gte,
        .lte => .lte,
        else => return fail(msg, "Expected operator after '{s}', got '{s}'.", .{ field.items, tokens[pos.*].value }),
    };
    pos.* += 1;
    if (pos.* >= tokens.len) return fail(msg, "Expected value after operator on '{s}'.", .{field.items});

    var values: std.ArrayList([]u8) = .empty;
    errdefer {
        for (values.items) |v| allocator.free(v);
        values.deinit(allocator);
    }
    if (tokens[pos.*].kind == .lbrack) {
        op = .in_list;
        pos.* += 1;
        while (pos.* < tokens.len and tokens[pos.*].kind != .rbrack) {
            if (tokens[pos.*].kind == .comma) {
                pos.* += 1;
                continue;
            }
            // `cmd.exe` tokenizes as ident, dot, ident. One list entry is the join.
            var piece: std.ArrayList(u8) = .empty;
            errdefer piece.deinit(allocator);
            while (pos.* < tokens.len and tokens[pos.*].kind != .comma and tokens[pos.*].kind != .rbrack) {
                try piece.appendSlice(allocator, tokens[pos.*].value);
                pos.* += 1;
            }
            try values.append(allocator, try piece.toOwnedSlice(allocator));
        }
        if (pos.* >= tokens.len) return fail(msg, "Unterminated list, expected ']'.", .{});
        pos.* += 1;
    } else {
        if (op == .contains and tokens[pos.*].kind == .string) op = .equals;
        const trimmed = std.mem.trim(u8, tokens[pos.*].value, "*");
        try values.append(allocator, try allocator.dupe(u8, trimmed));
        pos.* += 1;
    }
    try plan.nodes.append(allocator, .{ .pred = .{
        .field = try field.toOwnedSlice(allocator),
        .op = op,
        .values = try values.toOwnedSlice(allocator),
    } });
    return @intCast(plan.nodes.items.len - 1);
}

fn tokenize(allocator: std.mem.Allocator, source: []const u8, msg: *[]u8) !std.ArrayList(Token) {
    var tokens: std.ArrayList(Token) = .empty;
    errdefer {
        for (tokens.items) |t| if (t.owned) allocator.free(t.value);
        tokens.deinit(allocator);
    }
    var i: usize = 0;
    while (i < source.len) {
        const c = source[i];
        if (std.ascii.isWhitespace(c)) {
            i += 1;
            continue;
        }
        switch (c) {
            '(' => try add(&tokens, allocator, .lparen, "(", false),
            ')' => try add(&tokens, allocator, .rparen, ")", false),
            '[' => try add(&tokens, allocator, .lbrack, "[", false),
            ']' => try add(&tokens, allocator, .rbrack, "]", false),
            ',' => try add(&tokens, allocator, .comma, ",", false),
            ':' => try add(&tokens, allocator, .colon, ":", false),
            '.' => try add(&tokens, allocator, .dot, ".", false),
            '=' => try add(&tokens, allocator, .eql, "=", false),
            '!' => {
                if (i + 1 < source.len and source[i + 1] == '=') {
                    try add(&tokens, allocator, .neq, "!=", false);
                    i += 2;
                    continue;
                }
                return fail(msg, "Expected '=' after '!'.", .{});
            },
            '>' => {
                if (i + 1 < source.len and source[i + 1] == '=') {
                    try add(&tokens, allocator, .gte, ">=", false);
                    i += 2;
                } else {
                    try add(&tokens, allocator, .gt, ">", false);
                    i += 1;
                }
                continue;
            },
            '<' => {
                if (i + 1 < source.len and source[i + 1] == '=') {
                    try add(&tokens, allocator, .lte, "<=", false);
                    i += 2;
                } else {
                    try add(&tokens, allocator, .lt, "<", false);
                    i += 1;
                }
                continue;
            },
            '"', '\'' => {
                const quote = c;
                i += 1;
                const start = i;
                while (i < source.len and source[i] != quote) {
                    if (source[i] == '\\' and i + 1 < source.len) {
                        i += 2;
                        continue;
                    }
                    i += 1;
                }
                if (i >= source.len) return fail(msg, "Unterminated string literal.", .{});
                const owned = try unescape(allocator, source[start..i]);
                try tokens.append(allocator, .{ .kind = .string, .value = owned, .owned = true });
                i += 1;
                continue;
            },
            else => {},
        }
        if (std.ascii.isDigit(c) or (c == '-' and i + 1 < source.len and std.ascii.isDigit(source[i + 1]))) {
            const start = i;
            if (c == '-') i += 1;
            while (i < source.len and (std.ascii.isDigit(source[i]) or source[i] == '.')) i += 1;
            if (i < source.len) {
                const suf = std.ascii.toLower(source[i]);
                const boundary = i + 1 >= source.len or !std.ascii.isAlphanumeric(source[i + 1]);
                if (boundary and (suf == 's' or suf == 'm' or suf == 'h' or suf == 'd')) i += 1;
            }
            try add(&tokens, allocator, .number, source[start..i], false);
            continue;
        }
        // `path:/etc/` is a starter value. `/` is not an identifier character.
        if (c == '/') {
            const start = i;
            while (i < source.len and !std.ascii.isWhitespace(source[i]) and source[i] != ')' and source[i] != ']' and source[i] != ',' and source[i] != '(' and source[i] != '[' and source[i] != ':') i += 1;
            try add(&tokens, allocator, .ident, source[start..i], false);
            continue;
        }
        if (std.ascii.isAlphabetic(c) or c == '_' or c == '*') {
            const start = i;
            while (i < source.len and (std.ascii.isAlphanumeric(source[i]) or source[i] == '_' or source[i] == '-' or source[i] == '*')) i += 1;
            try add(&tokens, allocator, .ident, source[start..i], false);
            continue;
        }
        if (c == '(' or c == ')' or c == '[' or c == ']' or c == ',' or c == ':' or c == '.' or c == '=' or c == '!' or c == '>' or c == '<' or c == '"' or c == '\'') {
            i += 1;
            continue;
        }
        return fail(msg, "Unexpected character '{c}' at position {d}.", .{ c, i });
    }
    return tokens;
}

fn add(tokens: *std.ArrayList(Token), allocator: std.mem.Allocator, kind: Kind, value: []const u8, owned: bool) !void {
    try tokens.append(allocator, .{ .kind = kind, .value = value, .owned = owned });
}

fn unescape(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        if (raw[i] == '\\' and i + 1 < raw.len and (raw[i + 1] == '"' or raw[i + 1] == '\'')) {
            try out.append(allocator, raw[i + 1]);
            i += 1;
            continue;
        }
        try out.append(allocator, raw[i]);
    }
    return out.toOwnedSlice(allocator);
}

fn fail(msg: *[]u8, comptime fmt: []const u8, args: anytype) error{BadQuery} {
    msg.* = std.fmt.bufPrint(msg.*, fmt, args) catch msg.*[0..@min(msg.*.len, 80)];
    return error.BadQuery;
}

fn eqlIc(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn isConnective(tok: Token) bool {
    return tok.kind == .ident and (eqlIc(tok.value, "and") or eqlIc(tok.value, "or"));
}

fn looksLikeTime(raw: []const u8) bool {
    if (raw.len < 10) return false;
    for (raw[0..4]) |c| if (!std.ascii.isDigit(c)) return false;
    if (raw[4] != '-' or raw[7] != '-') return false;
    return true;
}

fn durationSeconds(raw: []const u8) ?i64 {
    if (raw.len < 2) return null;
    const amount = std.fmt.parseInt(i64, raw[0 .. raw.len - 1], 10) catch return null;
    if (amount <= 0) return null;
    const unit: i64 = switch (std.ascii.toLower(raw[raw.len - 1])) {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        else => return null,
    };
    return amount * unit;
}

fn normalizeEventType(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var out = try allocator.alloc(u8, raw.len);
    for (raw, 0..) |c, i| {
        out[i] = if (c == '-') '_' else std.ascii.toLower(c);
    }
    return out;
}

fn isGuid(s: []const u8) bool {
    const parts = [_]usize{ 8, 4, 4, 4, 12 };
    var i: usize = 0;
    for (parts, 0..) |n, pi| {
        if (pi > 0) {
            if (i >= s.len or s[i] != '-') return false;
            i += 1;
        }
        var k: usize = 0;
        while (k < n) : (k += 1) {
            if (i >= s.len or !std.ascii.isHex(s[i])) return false;
            i += 1;
        }
    }
    return i == s.len;
}

fn parseOk(allocator: std.mem.Allocator, source: []const u8, limit: ?u32, now_unix: i64) !Plan {
    var storage: [240]u8 = undefined;
    var msg: []u8 = &storage;
    return parse(allocator, source, limit, now_unix, &msg) catch |err| {
        std.debug.print("hunt_parse {s}\n", .{msg});
        return err;
    };
}

test "hunt dsl keeps grammar and accepts every event type" {
    const allocator = std.testing.allocator;
    const now: i64 = 1_778_000_000;
    var plan = try parseOk(allocator, "event_type:dns-query processes.name:*evil* AND pid > 10", null, now);
    defer plan.deinit();
    try std.testing.expectEqualStrings("dns_query", plan.event_type.?);
    try std.testing.expectEqual(default_limit, plan.limit);
    try std.testing.expect(try matches(allocator, &plan, "{\"processes\":[{\"name\":\"Evil.exe\"}],\"pid\":42}"));
    try std.testing.expect(!(try matches(allocator, &plan, "{\"processes\":[{\"name\":\"Evil.exe\"}],\"pid\":3}")));
    try std.testing.expect(!(try matches(allocator, &plan, "{\"processes\":[{\"name\":\"ok.exe\"}],\"pid\":42}")));

    var exact = try parseOk(allocator, "command_line:\"hunt-needle\"", null, now);
    defer exact.deinit();
    try std.testing.expect(try matches(allocator, &exact, "{\"command_line\":\"hunt-needle\"}"));
    try std.testing.expect(!(try matches(allocator, &exact, "{\"command_line\":\"hunt-needle-extra\"}")));

    var loose = try parseOk(allocator, "command_line:hunt", null, now);
    defer loose.deinit();
    try std.testing.expect(try matches(allocator, &loose, "{\"command_line\":\"hunt-needle\"}"));

    var missing = try parseOk(allocator, "absent!=\"x\"", null, now);
    defer missing.deinit();
    try std.testing.expect(try matches(allocator, &missing, "{}"));

    var storage: [240]u8 = undefined;
    var msg: []u8 = &storage;
    try std.testing.expectError(error.BadQuery, parse(allocator, "agent_id:nope", null, now, &msg));
    try std.testing.expectEqualStrings("agent_id must be a GUID, got 'nope'.", msg);

    var wide = try parseOk(allocator, "event_type:heartbeat", 9000, now);
    defer wide.deinit();
    try std.testing.expectEqual(max_limit, wide.limit);

    var recent = try parseOk(allocator, "last:1h event_type:heartbeat", null, now);
    defer recent.deinit();
    try std.testing.expect(recent.from != null);
    try std.testing.expect(std.mem.endsWith(u8, recent.from.?, "Z"));

    var encoded = try parseOk(allocator, "event_type:process_snapshot AND processes.command_line:\"-EncodedCommand\"", null, now);
    defer encoded.deinit();
    try std.testing.expectEqualStrings("process_snapshot", encoded.event_type.?);
    try std.testing.expect(try matches(allocator, &encoded, "{\"processes\":[{\"command_line\":\"-EncodedCommand\"}]}"));
    try std.testing.expect(!(try matches(allocator, &encoded, "{\"processes\":[{\"command_line\":\"notepad\"}]}")));

    var ip = try parseOk(allocator, "last:6h AND event_type:network_snapshot AND connections.remote_address:1.1.1.1", null, now);
    defer ip.deinit();
    try std.testing.expectEqualStrings("network_snapshot", ip.event_type.?);
    try std.testing.expect(ip.from != null);
    try std.testing.expect(try matches(allocator, &ip, "{\"connections\":[{\"remote_address\":\"1.1.1.1\"}]}"));
    try std.testing.expect(!(try matches(allocator, &ip, "{\"connections\":[{\"remote_address\":\"8.8.8.8\"}]}")));

    var names = try parseOk(allocator, "processes.name:[cmd.exe, powershell.exe]", null, now);
    defer names.deinit();
    try std.testing.expect(try matches(allocator, &names, "{\"processes\":[{\"name\":\"cmd.exe\"}]}"));
    try std.testing.expect(try matches(allocator, &names, "{\"processes\":[{\"name\":\"powershell.exe\"}]}"));
    try std.testing.expect(!(try matches(allocator, &names, "{\"processes\":[{\"name\":\"explorer.exe\"}]}")));

    var fim = try parseOk(allocator, "event_type:file_integrity AND path:/etc/", null, now);
    defer fim.deinit();
    try std.testing.expectEqualStrings("file_integrity", fim.event_type.?);
    try std.testing.expect(try matches(allocator, &fim, "{\"path\":\"/etc/passwd\"}"));
    try std.testing.expect(!(try matches(allocator, &fim, "{\"path\":\"/var/log\"}")));
}

const default_tenant = "00000000-0000-0000-0000-000000000001";
const cap_agent = "00000000-0000-0000-0000-00000000d911";
const push_agent = "00000000-0000-0000-0000-00000000d912";

test "hunt prefilter stops at 5000 and a pushed predicate still finds the old row" {
    const url = std.testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return;
    if (url.len == 0) return;
    const allocator = std.testing.allocator;
    const conn = try pg.Conn.connect(allocator, std.testing.io, url);
    defer {
        conn.close();
        allocator.destroy(conn);
    }
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};

    try insertAgent(conn, cap_agent, "hunt-cap-host");
    try conn.execNoRows(
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\SELECT now(), $1::uuid, $2::uuid, 'hunt_cap_probe', now(), '{}'::jsonb
        \\FROM generate_series(1, 5001)
    , &.{ .{ .text = default_tenant }, .{ .text = cap_agent } });

    var cap = try parseOk(allocator, "event_type:hunt_cap_probe agent_id:\"00000000-0000-0000-0000-00000000d911\"", 9000, 1_778_000_000);
    defer cap.deinit();
    var cap_result = try execute(allocator, conn, default_tenant, &cap, 0, 1_778_000_000);
    defer cap_result.deinit(allocator);
    const cap_warn = joinWarnings(cap_result.warnings);
    std.debug.print("hunt_cap matches={d} limit={d} warn={s}\n", .{ cap_result.matches.len, cap.limit, cap_warn });
    try std.testing.expectEqual(max_limit, cap.limit);
    try std.testing.expectEqual(@as(usize, max_limit), cap_result.matches.len);
    try std.testing.expect(std.mem.indexOf(u8, cap_warn, "Hit prefilter cap of 5000") != null);

    try insertAgent(conn, push_agent, "hunt-push-host");
    try conn.execNoRows(
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\SELECT now(), $1::uuid, $2::uuid, 'hunt_push_probe', now(), '{"command_line":"noise"}'::jsonb
        \\FROM generate_series(1, 5001)
    , &.{ .{ .text = default_tenant }, .{ .text = push_agent } });
    try conn.execNoRows(
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES ('2020-01-01T00:00:00Z', $1::uuid, $2::uuid, 'hunt_push_probe', '2020-01-01T00:00:00Z', '{"command_line":"hunt-needle"}'::jsonb)
    , &.{ .{ .text = default_tenant }, .{ .text = push_agent } });

    var pushed = try parseOk(allocator, "event_type:hunt_push_probe agent_id:\"00000000-0000-0000-0000-00000000d912\" command_line:\"hunt-needle\"", null, 1_778_000_000);
    defer pushed.deinit();
    var pushed_result = try execute(allocator, conn, default_tenant, &pushed, 0, 1_778_000_000);
    defer pushed_result.deinit(allocator);
    std.debug.print("hunt_push matches={d}\n", .{pushed_result.matches.len});
    try std.testing.expectEqual(@as(usize, 1), pushed_result.matches.len);
    try std.testing.expect(pushed_result.warnings.len == 0);

    try conn.execSimple("ROLLBACK");
}

fn joinWarnings(warnings: [][]u8) []const u8 {
    if (warnings.len == 0) return "";
    return warnings[0];
}

fn insertAgent(conn: *pg.Conn, id: []const u8, host: []const u8) !void {
    try conn.execNoRows(
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status
        \\) VALUES ($1, $2, $3, 'linux', 'test', '0', 'arm64', now(), 'online')
    , &.{ .{ .text = id }, .{ .text = default_tenant }, .{ .text = host } });
}
