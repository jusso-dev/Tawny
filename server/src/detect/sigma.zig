//! Sigma compiler. Parses a Sigma rule (YAML subset in `yaml.zig`), maps
//! fields and logsource through `rules/sigma/field-map.yaml`, and builds the
//! rule AST in `ast.zig`.
//!
//! A rule is compiled whole or rejected whole with a reason. Nothing is ever
//! partly applied. Status is `supported`, `supported_with_notes` (compiled,
//! with notes on a mapping the operator should know about) or `rejected`.

const std = @import("std");
const yaml = @import("yaml.zig");
const ast = @import("ast.zig");
const regex = @import("regex.zig");

pub const field_map_yaml = @embedFile("sigma-field-map.yaml");

pub const Status = enum { supported, supported_with_notes, rejected };

pub const Target = union(enum) {
    path: []const u8,
    join: struct { a: []const u8, b: []const u8, sep: []const u8 },
    hashes: []const u8,
    rewrite: struct { path: []const u8, values: []const yaml.Entry },
};

pub const Logsource = struct {
    product: ?[]const u8 = null,
    category: ?[]const u8 = null,
    service: ?[]const u8 = null,
    event_type: ?[]const u8 = null,
    event_ids: []const yaml.Entry = &.{},
    keyword_fields: []const []const u8 = &.{},
};

pub const FieldMap = struct {
    fields: []const yaml.Entry,
    logsources: []const Logsource,

    /// Parse the embedded map. Everything lives in `arena`.
    pub fn load(arena: std.mem.Allocator) !FieldMap {
        return loadText(arena, field_map_yaml);
    }

    pub fn loadText(arena: std.mem.Allocator, text: []const u8) !FieldMap {
        const root = try yaml.parse(arena, text);
        const fields = root.get("fields") orelse return error.BadFieldMap;
        if (fields != .map) return error.BadFieldMap;
        const ls = root.get("logsources") orelse return error.BadFieldMap;
        if (ls != .list) return error.BadFieldMap;
        var out: std.ArrayList(Logsource) = .empty;
        for (ls.list) |item| {
            if (item != .map) return error.BadFieldMap;
            var l: Logsource = .{
                .product = if (item.get("product")) |v| v.str() else null,
                .category = if (item.get("category")) |v| v.str() else null,
                .service = if (item.get("service")) |v| v.str() else null,
                .event_type = if (item.get("event_type")) |v| v.str() else null,
            };
            if (item.get("event_ids")) |ids| {
                if (ids != .map) return error.BadFieldMap;
                l.event_ids = ids.map;
            }
            if (item.get("keyword_fields")) |kf| {
                if (kf != .list) return error.BadFieldMap;
                const names = try arena.alloc([]const u8, kf.list.len);
                for (kf.list, 0..) |n, i| names[i] = n.str() orelse return error.BadFieldMap;
                l.keyword_fields = names;
            }
            if (l.event_type == null and l.event_ids.len == 0) return error.BadFieldMap;
            try out.append(arena, l);
        }
        for (fields.map) |e| _ = targetOf(e.value) orelse return error.BadFieldMap;
        return .{ .fields = fields.map, .logsources = out.items };
    }

    pub fn lookup(self: FieldMap, name: []const u8) ?Target {
        for (self.fields) |e| {
            if (std.mem.eql(u8, e.key, name)) return targetOf(e.value);
        }
        for (self.fields) |e| {
            if (std.ascii.eqlIgnoreCase(e.key, name)) return targetOf(e.value);
        }
        return null;
    }
};

fn targetOf(v: yaml.Node) ?Target {
    switch (v) {
        .scalar => |s| return .{ .path = s.text },
        .map => {
            if (v.get("join")) |j| {
                if (j != .list or j.list.len != 2) return null;
                const sep = (v.get("sep") orelse return null).str() orelse return null;
                return .{ .join = .{ .a = j.list[0].str() orelse return null, .b = j.list[1].str() orelse return null, .sep = sep } };
            }
            if (v.get("hashes")) |h| return .{ .hashes = h.str() orelse return null };
            if (v.get("path")) |p| {
                const vals = v.get("values") orelse return null;
                if (vals != .map) return null;
                return .{ .rewrite = .{ .path = p.str() orelse return null, .values = vals.map } };
            }
            return null;
        },
        else => return null,
    }
}

pub const Compiled = struct {
    status: Status,
    /// Short reason class for counting (static text). Empty unless rejected.
    reason_kind: []const u8 = "",
    /// Full reason, for the API and the compatibility report.
    reason: []const u8 = "",
    notes: []const []const u8 = &.{},
    title: []const u8 = "untitled",
    external_id: ?[]const u8 = null,
    description: ?[]const u8 = null,
    /// Sigma `author`, kept for DRL 1.1 attribution.
    author: ?[]const u8 = null,
    severity: []const u8 = "medium",
    event_type: ?[]const u8 = null,
    mitre: []const []const u8 = &.{},
    expr: ast.Node = .{ .constant = false },
    /// JSON form of `expr` for `compiled_expression_json`.
    expr_json: []const u8 = "",
    /// Set when the whole rule is one field, one operator and one value that
    /// `match.zig` can express. Kept in the legacy columns for display.
    single: ?struct { operator: []const u8, path: []const u8, value: []const u8 } = null,
};

const Rejected = error{Rejected};
const Error = Rejected || error{OutOfMemory};

const Ctx = struct {
    arena: std.mem.Allocator,
    map: *const FieldMap,
    logsource: ?*const Logsource = null,
    notes: std.ArrayList([]const u8) = .empty,
    reason_kind: []const u8 = "",
    reason: []const u8 = "",
    /// EventID values seen, for choosing the event type of security/system rules.
    event_ids: std.ArrayList([]const u8) = .empty,
    /// Every path was a pass-through dotted Tawny path under `processes.`.
    only_legacy_paths: bool = true,
    used_fields: usize = 0,

    fn reject(c: *Ctx, kind: []const u8, comptime fmt: []const u8, args: anytype) Error {
        c.reason_kind = kind;
        c.reason = try std.fmt.allocPrint(c.arena, fmt, args);
        return error.Rejected;
    }

    fn note(c: *Ctx, comptime fmt: []const u8, args: anytype) !void {
        const text = try std.fmt.allocPrint(c.arena, fmt, args);
        for (c.notes.items) |n| {
            if (std.mem.eql(u8, n, text)) return;
        }
        try c.notes.append(c.arena, text);
    }
};

/// Compile `text`. All output lives in `arena`.
pub fn compile(arena: std.mem.Allocator, map: *const FieldMap, text: []const u8) error{OutOfMemory}!Compiled {
    var c: Ctx = .{ .arena = arena, .map = map };
    var out: Compiled = .{ .status = .rejected };
    compileInner(&c, text, &out) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Rejected => {
            out.status = .rejected;
            out.reason_kind = c.reason_kind;
            out.reason = c.reason;
            return out;
        },
    };
    out.notes = c.notes.items;
    out.status = if (c.notes.items.len > 0) .supported_with_notes else .supported;
    return out;
}

fn compileInner(c: *Ctx, text: []const u8, out: *Compiled) Error!void {
    const root = yaml.parse(c.arena, text) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return c.reject("yaml", "{s}", .{yaml.describe(err)}),
    };
    if (root != .map) return c.reject("yaml", "rule is not a YAML map", .{});
    if (root.get("correlation") != null or (root.get("type") != null and root.get("rules") != null)) {
        return c.reject("correlation", "Sigma correlation rules are not supported", .{});
    }
    if (root.get("title")) |t| out.title = t.str() orelse "untitled";
    if (root.get("id")) |v| out.external_id = v.str();
    if (root.get("description")) |v| out.description = if (v.str()) |s| std.mem.trim(u8, s, " \n") else null;
    if (root.get("author")) |v| out.author = if (v.str()) |a| std.mem.trim(u8, a, " \n") else null;
    if (root.get("level")) |v| out.severity = mapSeverity(v.str() orelse "");
    out.mitre = try mitreTags(c.arena, root.get("tags"));

    const detection = root.get("detection") orelse return c.reject("structure", "no detection section", .{});
    if (detection != .map) return c.reject("structure", "detection is not a map", .{});
    if (detection.get("timeframe") != null) return c.reject("aggregation", "timeframe and aggregations are not supported; use a Tawny threshold or sequence rule", .{});

    // Logsource first: keyword lists need its keyword fields.
    const ls_node = root.get("logsource");
    var product: ?[]const u8 = null;
    var category: ?[]const u8 = null;
    var service: ?[]const u8 = null;
    if (ls_node) |ls| {
        if (ls != .map) return c.reject("logsource", "logsource is not a map", .{});
        product = if (ls.get("product")) |v| v.str() else null;
        category = if (ls.get("category")) |v| v.str() else null;
        service = if (ls.get("service")) |v| v.str() else null;
    }
    if (ls_node != null and (category != null or service != null)) {
        c.logsource = findLogsource(c.map, product, category, service) orelse return c.reject(
            "unmapped logsource",
            "unmapped logsource product={s} category={s} service={s}",
            .{ product orelse "-", category orelse "-", service orelse "-" },
        );
    }

    // Search identifiers.
    var names: std.ArrayList([]const u8) = .empty;
    var nodes: std.ArrayList(ast.Node) = .empty;
    for (detection.map) |e| {
        if (std.mem.eql(u8, e.key, "condition")) continue;
        try names.append(c.arena, e.key);
        try nodes.append(c.arena, try searchIdent(c, e.key, e.value));
    }
    if (names.items.len == 0) return c.reject("structure", "detection has no search identifiers", .{});
    const cond_node = detection.get("condition") orelse return c.reject("structure", "detection has no condition", .{});
    var cond_texts: std.ArrayList([]const u8) = .empty;
    switch (cond_node) {
        .scalar => |s| try cond_texts.append(c.arena, s.text),
        .list => |items| for (items) |it| try cond_texts.append(c.arena, it.str() orelse return c.reject("condition", "condition list holds a non-string", .{})),
        else => return c.reject("condition", "condition is empty", .{}),
    }
    var alts: std.ArrayList(ast.Node) = .empty;
    for (cond_texts.items) |ct| {
        var cp: CondParser = .{ .c = c, .s = ct, .names = names.items, .nodes = nodes.items };
        try alts.append(c.arena, try cp.parse());
    }
    out.expr = if (alts.items.len == 1) alts.items[0] else .{ .any_of = alts.items };

    // Event type.
    if (c.logsource) |ls| {
        if (ls.event_type) |et| {
            out.event_type = et;
        } else {
            out.event_type = try eventTypeFromIds(c, ls);
        }
        // Legacy contract rules name snapshot paths (`processes.name`) under a
        // process_creation logsource. Those paths only exist in process_snapshot.
        if (std.mem.eql(u8, out.event_type.?, "process_start") and c.used_fields > 0 and c.only_legacy_paths) {
            out.event_type = "process_snapshot";
            try c.note("rule uses processes.* snapshot paths, so it runs on process_snapshot events", .{});
        }
    } else if (ls_node == null or (category == null and service == null)) {
        if (c.used_fields > 0 and c.only_legacy_paths) {
            out.event_type = "process_snapshot";
            try c.note("no logsource; processes.* paths run on process_snapshot events", .{});
        } else {
            return c.reject("unmapped logsource", "logsource needs a category or service", .{});
        }
    }

    out.expr_json = try ast.exprToJson(c.arena, out.expr);
    if (out.expr == .pred) {
        const p = out.expr.pred;
        if (p.field.join == null and p.values.len == 1 and p.ci) {
            const op: ?[]const u8 = switch (p.op) {
                .equals => "equals",
                .contains => "contains",
                .startswith => "startswith",
                .endswith => "endswith",
                else => null,
            };
            if (op) |o| out.single = .{ .operator = o, .path = p.field.path, .value = p.values[0] };
        } else if (p.op == .exists and p.field.join == null) {
            out.single = .{ .operator = "exists", .path = p.field.path, .value = "" };
        }
    }
}

fn findLogsource(map: *const FieldMap, product: ?[]const u8, category: ?[]const u8, service: ?[]const u8) ?*const Logsource {
    for (map.logsources) |*l| {
        if (!optEq(l.category, category)) continue;
        if (!optEq(l.service, service)) continue;
        if (product != null and l.product != null and !std.ascii.eqlIgnoreCase(product.?, l.product.?)) continue;
        return l;
    }
    return null;
}

fn optEq(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return std.ascii.eqlIgnoreCase(a.?, b.?);
}

fn eventTypeFromIds(c: *Ctx, ls: *const Logsource) Error![]const u8 {
    if (c.event_ids.items.len == 0) return c.reject("unmapped logsource", "service {s} needs EventID values to pick an event type", .{ls.service orelse "-"});
    var chosen: ?[]const u8 = null;
    for (c.event_ids.items) |id| {
        var found: ?[]const u8 = null;
        for (ls.event_ids) |e| {
            if (std.mem.eql(u8, e.key, id)) found = e.value.str();
        }
        const et = found orelse return c.reject("unmapped event id", "EventID {s} is not collected for service {s}", .{ id, ls.service orelse "-" });
        if (chosen) |prev| {
            if (!std.mem.eql(u8, prev, et)) return c.reject("unmapped event id", "EventID values map to more than one event type ({s}, {s})", .{ prev, et });
        }
        chosen = et;
    }
    return chosen.?;
}

fn mapSeverity(level: []const u8) []const u8 {
    if (std.ascii.eqlIgnoreCase(level, "critical")) return "critical";
    if (std.ascii.eqlIgnoreCase(level, "high")) return "high";
    if (std.ascii.eqlIgnoreCase(level, "medium")) return "medium";
    if (std.ascii.eqlIgnoreCase(level, "low")) return "low";
    if (std.ascii.eqlIgnoreCase(level, "informational")) return "low";
    return "medium";
}

fn mitreTags(arena: std.mem.Allocator, tags: ?yaml.Node) ![]const []const u8 {
    const t = tags orelse return &.{};
    if (t != .list) return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (t.list) |item| {
        const tag = item.str() orelse continue;
        if (!std.ascii.startsWithIgnoreCase(tag, "attack.t")) continue;
        const id = tag["attack.".len..];
        if (id.len < 5 or !std.ascii.isDigit(id[1])) continue;
        const upper = try arena.dupe(u8, id);
        for (upper) |*ch| ch.* = std.ascii.toUpper(ch.*);
        try out.append(arena, upper);
    }
    return out.items;
}

pub const SelectionResult = union(enum) {
    ok: ast.Node,
    rejected: []const u8,
};

/// Compile one Sigma-style selection (a field map, or a list of field maps
/// meaning any of them) for Tawny sequence and threshold rules. Field names
/// may be Sigma names from the field map or Tawny dotted paths.
pub fn compileSelection(arena: std.mem.Allocator, map: *const FieldMap, node: yaml.Node) error{OutOfMemory}!SelectionResult {
    var c: Ctx = .{ .arena = arena, .map = map };
    const out = searchIdent(&c, "where", node) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Rejected => return .{ .rejected = c.reason },
    };
    return .{ .ok = out };
}

// --- search identifiers -------------------------------------------------------

fn searchIdent(c: *Ctx, name: []const u8, v: yaml.Node) Error!ast.Node {
    switch (v) {
        .map => return fieldMap(c, v.map),
        .list => |items| {
            if (items.len == 0) return c.reject("structure", "search identifier {s} is an empty list", .{name});
            const first_is_map = items[0] == .map;
            const nodes = try c.arena.alloc(ast.Node, items.len);
            if (first_is_map) {
                for (items, 0..) |it, i| {
                    if (it != .map) return c.reject("structure", "search identifier {s} mixes maps and values", .{name});
                    nodes[i] = try fieldMap(c, it.map);
                }
                return if (nodes.len == 1) nodes[0] else .{ .any_of = nodes };
            }
            return keywords(c, name, items);
        },
        .scalar => return keywords(c, name, &.{v}),
        .null => return c.reject("structure", "search identifier {s} is empty", .{name}),
    }
}

fn fieldMap(c: *Ctx, entries: []const yaml.Entry) Error!ast.Node {
    if (entries.len == 0) return c.reject("structure", "empty selection map", .{});
    const nodes = try c.arena.alloc(ast.Node, entries.len);
    for (entries, 0..) |e, i| nodes[i] = try fieldPred(c, e.key, e.value);
    return if (nodes.len == 1) nodes[0] else .{ .all_of = nodes };
}

fn keywords(c: *Ctx, name: []const u8, items: []const yaml.Node) Error!ast.Node {
    const ls = c.logsource orelse return c.reject("keywords", "keyword search {s} needs a logsource with keyword fields", .{name});
    if (ls.keyword_fields.len == 0) return c.reject("keywords", "keyword search {s} has no keyword field for this logsource (no whole-payload search)", .{name});
    const values = try c.arena.alloc([]const u8, items.len);
    for (items, 0..) |it, i| values[i] = it.str() orelse return c.reject("keywords", "keyword list {s} holds a non-string", .{name});
    const per_field = try c.arena.alloc(ast.Node, ls.keyword_fields.len);
    for (ls.keyword_fields, 0..) |f, i| {
        per_field[i] = try textPred(c, .{ .path = f }, .contains, values, false, &.{});
    }
    c.only_legacy_paths = false;
    try c.note("keyword search {s} matches {s} only", .{ name, ls.keyword_fields[0] });
    return if (per_field.len == 1) per_field[0] else .{ .any_of = per_field };
}

const Mods = struct {
    base: enum { none, contains, startswith, endswith } = .none,
    all: bool = false,
    re: bool = false,
    re_i: bool = false,
    cidr: bool = false,
    base64: bool = false,
    base64offset: bool = false,
    wide: bool = false,
    windash: bool = false,
    exists: bool = false,
    cased: bool = false,
    cmp: ?ast.Op = null,
};

fn parseMods(c: *Ctx, field: []const u8, parts: []const []const u8) Error!Mods {
    var m: Mods = .{};
    for (parts) |p| {
        if (std.mem.eql(u8, p, "contains")) {
            m.base = .contains;
        } else if (std.mem.eql(u8, p, "startswith")) {
            m.base = .startswith;
        } else if (std.mem.eql(u8, p, "endswith")) {
            m.base = .endswith;
        } else if (std.mem.eql(u8, p, "all")) {
            m.all = true;
        } else if (std.mem.eql(u8, p, "re")) {
            m.re = true;
        } else if (std.mem.eql(u8, p, "i") and m.re) {
            m.re_i = true;
        } else if (std.mem.eql(u8, p, "cidr")) {
            m.cidr = true;
        } else if (std.mem.eql(u8, p, "base64")) {
            m.base64 = true;
        } else if (std.mem.eql(u8, p, "base64offset")) {
            m.base64offset = true;
        } else if (std.mem.eql(u8, p, "wide") or std.mem.eql(u8, p, "utf16le")) {
            m.wide = true;
        } else if (std.mem.eql(u8, p, "windash")) {
            m.windash = true;
        } else if (std.mem.eql(u8, p, "exists")) {
            m.exists = true;
        } else if (std.mem.eql(u8, p, "cased")) {
            m.cased = true;
        } else if (std.mem.eql(u8, p, "gt")) {
            m.cmp = .gt;
        } else if (std.mem.eql(u8, p, "gte")) {
            m.cmp = .gte;
        } else if (std.mem.eql(u8, p, "lt")) {
            m.cmp = .lt;
        } else if (std.mem.eql(u8, p, "lte")) {
            m.cmp = .lte;
        } else if (m.re and (std.mem.eql(u8, p, "m") or std.mem.eql(u8, p, "s"))) {
            return c.reject("unsupported modifier", "re flag '{s}' on {s} is not supported", .{ p, field });
        } else {
            return c.reject("unsupported modifier", "modifier '{s}' on {s} is not supported", .{ p, field });
        }
    }
    if (m.wide and !(m.base64 or m.base64offset)) return c.reject("unsupported modifier", "modifier 'wide' on {s} needs base64 or base64offset", .{field});
    if (m.re and (m.base != .none or m.base64 or m.base64offset or m.windash or m.cidr)) return c.reject("unsupported modifier", "re on {s} combined with another value modifier", .{field});
    if (m.base64 and m.base64offset) return c.reject("unsupported modifier", "base64 and base64offset together on {s}", .{field});
    return m;
}

fn fieldPred(c: *Ctx, key: []const u8, value: yaml.Node) Error!ast.Node {
    var parts: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, key, '|');
    const field = it.first();
    while (it.next()) |p| try parts.append(c.arena, p);
    if (field.len == 0) {
        // `|all` with no field is a keyword list where every keyword must appear.
        return c.reject("keywords", "field-less modifiers are not supported", .{});
    }
    const m = try parseMods(c, field, parts.items);

    // Collect values.
    var raw: std.ArrayList(yaml.Node) = .empty;
    switch (value) {
        .list => |items| try raw.appendSlice(c.arena, items),
        else => try raw.append(c.arena, value),
    }
    if (raw.items.len == 0) return c.reject("structure", "{s} has an empty value list", .{field});

    const target = try resolveField(c, field);
    c.used_fields += 1;

    if (std.mem.eql(u8, field, "EventID") and !m.exists and m.cmp == null) {
        for (raw.items) |rv| {
            if (rv.str()) |s| try c.event_ids.append(c.arena, s);
        }
    }

    if (m.exists) {
        if (raw.items.len != 1) return c.reject("structure", "exists on {s} takes one value", .{field});
        const b = raw.items[0].str() orelse "";
        const want = if (std.ascii.eqlIgnoreCase(b, "true")) true else if (std.ascii.eqlIgnoreCase(b, "false")) false else return c.reject("structure", "exists on {s} needs true or false", .{field});
        const node = try existsNode(c, target);
        if (want) return node;
        const inner = try c.arena.create(ast.Node);
        inner.* = node;
        return .{ .not = inner };
    }

    // Null values mean "field absent". Split them out.
    var values: std.ArrayList([]const u8) = .empty;
    var has_null = false;
    for (raw.items) |rv| {
        switch (rv) {
            .null => has_null = true,
            .scalar => |s| try values.append(c.arena, s.text),
            else => return c.reject("structure", "{s} has a nested value", .{field}),
        }
    }
    var branches: std.ArrayList(ast.Node) = .empty;
    if (has_null) {
        if (m.all) return c.reject("structure", "{s}|all with a null value", .{field});
        const ex = try c.arena.create(ast.Node);
        ex.* = try existsNode(c, target);
        try branches.append(c.arena, .{ .not = ex });
    }
    if (values.items.len > 0) try branches.append(c.arena, try valuePred(c, field, target, m, values.items));
    if (branches.items.len == 1) return branches.items[0];
    return .{ .any_of = branches.items };
}

fn resolveField(c: *Ctx, field: []const u8) Error!Target {
    if (c.map.lookup(field)) |t| {
        c.only_legacy_paths = false;
        return t;
    }
    if (std.mem.indexOfScalar(u8, field, '.') != null and isPath(field)) {
        if (!std.mem.startsWith(u8, field, "processes.")) c.only_legacy_paths = false;
        try c.note("field {s} is not a Sigma field and is used as a Tawny path", .{field});
        return .{ .path = field };
    }
    return c.reject("unmapped field", "unmapped field {s}", .{field});
}

fn isPath(s: []const u8) bool {
    for (s) |ch| {
        if (!(std.ascii.isAlphanumeric(ch) or ch == '_' or ch == '.')) return false;
    }
    return s[0] != '.' and s[s.len - 1] != '.';
}

fn existsNode(c: *Ctx, target: Target) Error!ast.Node {
    return switch (target) {
        .path => |p| .{ .pred = .{ .field = .{ .path = p }, .op = .exists } },
        .rewrite => |r| .{ .pred = .{ .field = .{ .path = r.path }, .op = .exists } },
        .join => |j| .{ .pred = .{ .field = .{ .path = j.a, .join = j.b, .sep = j.sep }, .op = .exists } },
        .hashes => |h| blk: {
            _ = c;
            break :blk .{ .pred = .{ .field = .{ .path = h }, .op = .exists } };
        },
    };
}

fn valuePred(c: *Ctx, field: []const u8, target: Target, m: Mods, values_in: []const []const u8) Error!ast.Node {
    var values = values_in;
    switch (target) {
        .hashes => |base| return hashPreds(c, field, base, m, values),
        .rewrite => |r| {
            const mapped = try c.arena.alloc([]const u8, values.len);
            for (values, 0..) |v, i| {
                mapped[i] = blk: {
                    for (r.values) |e| {
                        if (std.ascii.eqlIgnoreCase(e.key, v)) break :blk e.value.str() orelse v;
                    }
                    return c.reject("unmapped value", "value {s} of {s} has no Tawny equivalent", .{ v, field });
                };
            }
            values = mapped;
        },
        else => {},
    }
    const f: ast.Field = switch (target) {
        .path => |p| .{ .path = p },
        .rewrite => |r| .{ .path = r.path },
        .join => |j| .{ .path = j.a, .join = j.b, .sep = j.sep },
        .hashes => unreachable,
    };

    if (m.re) {
        const progs = try c.arena.alloc(regex.Regex, values.len);
        for (values, 0..) |pat, i| {
            switch (try regex.compile(c.arena, pat, m.re_i)) {
                .ok => |re| progs[i] = re,
                .refused => |why| return c.reject("regex", "Unsupported Sigma field modifier 're' on {s}: {s}", .{ field, why }),
            }
        }
        return .{ .pred = .{ .field = f, .op = .regex, .values = values, .all = m.all, .ci = m.re_i, .compiled = progs } };
    }
    if (m.cidr) {
        for (values) |v| {
            if (ast.parseCidr(v) == null) return c.reject("structure", "bad CIDR {s} on {s}", .{ v, field });
        }
        return .{ .pred = .{ .field = f, .op = .cidr, .values = values, .all = m.all } };
    }
    if (m.cmp) |op| {
        for (values) |v| {
            _ = std.fmt.parseFloat(f64, v) catch return c.reject("structure", "{s} needs a number on {s}", .{ @tagName(op), field });
        }
        return .{ .pred = .{ .field = f, .op = op, .values = values, .all = m.all } };
    }

    var vals = values;
    if (m.windash) vals = try windash(c, field, vals);
    if (m.base64 or m.base64offset) {
        for (vals) |v| {
            if (ast.hasWildcard(v)) return c.reject("structure", "wildcard in a base64 value on {s}", .{field});
        }
        var encoded: std.ArrayList([]const u8) = .empty;
        for (vals) |v| {
            const plain = try ast.unescape(c.arena, v);
            const bytes = if (m.wide) try utf16le(c.arena, plain) else plain;
            if (m.base64) {
                try encoded.append(c.arena, try b64(c.arena, bytes));
            } else {
                try base64Offsets(c.arena, bytes, &encoded);
            }
        }
        // Encoded text has no wildcard characters but may hold `\`? No: the
        // base64 alphabet is A-Z a-z 0-9 + / =, so it passes through as literal.
        vals = encoded.items;
        if (m.all and m.base64offset) return c.reject("unsupported modifier", "base64offset with all on {s}", .{field});
    }
    const base: ast.Op = switch (m.base) {
        .none => .equals,
        .contains => .contains,
        .startswith => .startswith,
        .endswith => .endswith,
    };
    return textPred(c, f, base, vals, m.all, &.{}) catch |e| e;
}

/// Build a text predicate. Values are in Sigma escape form. When any value
/// has a wildcard, every value becomes a wildcard pattern for that operator.
fn textPred(c: *Ctx, f: ast.Field, base: ast.Op, values: []const []const u8, all: bool, _: []const u8) Error!ast.Node {
    var any_wild = false;
    for (values) |v| {
        if (ast.hasWildcard(v)) any_wild = true;
    }
    const out = try c.arena.alloc([]const u8, values.len);
    if (any_wild) {
        for (values, 0..) |v, i| {
            out[i] = switch (base) {
                .contains => try std.mem.concat(c.arena, u8, &.{ "*", v, "*" }),
                .startswith => try std.mem.concat(c.arena, u8, &.{ v, "*" }),
                .endswith => try std.mem.concat(c.arena, u8, &.{ "*", v }),
                else => v,
            };
        }
        return .{ .pred = .{ .field = f, .op = .wildcard, .values = out, .all = all } };
    }
    for (values, 0..) |v, i| out[i] = try ast.unescape(c.arena, v);
    return .{ .pred = .{ .field = f, .op = base, .values = out, .all = all } };
}

fn hashPreds(c: *Ctx, field: []const u8, base_path: []const u8, m: Mods, values: []const []const u8) Error!ast.Node {
    if (m.re or m.cidr or m.cmp != null or m.base64 or m.base64offset or m.windash) {
        return c.reject("unsupported modifier", "only plain, contains, startswith and endswith work on {s}", .{field});
    }
    var nodes: std.ArrayList(ast.Node) = .empty;
    for (values) |v| {
        // `SHA256=abc`, or `IMPHASH=abc` inside a contains.
        const eq = std.mem.indexOfScalar(u8, v, '=') orelse return c.reject("unmapped value", "hash value {s} on {s} has no ALGO= prefix", .{ v, field });
        const algo = std.mem.trim(u8, v[0..eq], " *");
        const digest = std.mem.trim(u8, v[eq + 1 ..], " *,");
        if (algo.len == 0 or algo.len > 16 or digest.len == 0) return c.reject("unmapped value", "hash value {s} on {s} is not ALGO=hex", .{ v, field });
        const lower_algo = try std.ascii.allocLowerString(c.arena, algo);
        const known = std.mem.eql(u8, lower_algo, "md5") or std.mem.eql(u8, lower_algo, "sha1") or std.mem.eql(u8, lower_algo, "sha256") or std.mem.eql(u8, lower_algo, "imphash");
        if (!known) return c.reject("unmapped value", "hash algorithm {s} on {s} is not collected", .{ algo, field });
        for (digest) |ch| {
            if (!std.ascii.isHex(ch)) return c.reject("unmapped value", "hash digest on {s} is not hex", .{field});
        }
        const path = try std.mem.concat(c.arena, u8, &.{ base_path, ".", lower_algo });
        const vals = try c.arena.alloc([]const u8, 1);
        vals[0] = try std.ascii.allocLowerString(c.arena, digest);
        try nodes.append(c.arena, .{ .pred = .{ .field = .{ .path = path }, .op = .equals, .values = vals } });
    }
    try c.note("{s} values are split by algorithm and matched against {s}.<algo>", .{ field, base_path });
    if (nodes.items.len == 1) return nodes.items[0];
    return if (m.all) .{ .all_of = nodes.items } else .{ .any_of = nodes.items };
}

/// Windows dash variants (pySigma `windash`): each `-` or `/` that starts a
/// word becomes `-`, `/`, en dash, em dash or horizontal bar. Every
/// combination is listed, up to 625 values.
fn windash(c: *Ctx, field: []const u8, values: []const []const u8) Error![]const []const u8 {
    const dashes = [_][]const u8{ "-", "/", "\u{2013}", "\u{2014}", "\u{2015}" };
    var out: std.ArrayList([]const u8) = .empty;
    for (values) |v| {
        var spots: std.ArrayList(usize) = .empty;
        for (v, 0..) |ch, i| {
            if ((ch == '-' or ch == '/') and (i == 0 or !isWordChar(v[i - 1])) and i + 1 < v.len and isWordChar(v[i + 1])) {
                try spots.append(c.arena, i);
            }
        }
        if (spots.items.len == 0) {
            try out.append(c.arena, v);
            continue;
        }
        if (spots.items.len > 4) return c.reject("unsupported modifier", "windash on {s} has too many dashes to expand", .{field});
        var total: usize = 1;
        for (spots.items) |_| total *= dashes.len;
        var combo: usize = 0;
        while (combo < total) : (combo += 1) {
            var buf: std.ArrayList(u8) = .empty;
            var k = combo;
            var last: usize = 0;
            for (spots.items) |pos| {
                try buf.appendSlice(c.arena, v[last..pos]);
                try buf.appendSlice(c.arena, dashes[k % dashes.len]);
                k /= dashes.len;
                last = pos + 1;
            }
            try buf.appendSlice(c.arena, v[last..]);
            try out.append(c.arena, buf.items);
        }
    }
    return out.items;
}

fn isWordChar(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or ch == '_';
}

fn utf16le(arena: std.mem.Allocator, s: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var view = std.unicode.Utf8View.init(s) catch {
        for (s) |b| try out.appendSlice(arena, &.{ b, 0 });
        return out.items;
    };
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| {
        if (cp > 0xffff) {
            const v = cp - 0x10000;
            const hi: u16 = @intCast(0xd800 + (v >> 10));
            const lo: u16 = @intCast(0xdc00 + (v & 0x3ff));
            try out.appendSlice(arena, &std.mem.toBytes(std.mem.nativeToLittle(u16, hi)));
            try out.appendSlice(arena, &std.mem.toBytes(std.mem.nativeToLittle(u16, lo)));
        } else {
            const u: u16 = @intCast(cp);
            try out.appendSlice(arena, &std.mem.toBytes(std.mem.nativeToLittle(u16, u)));
        }
    }
    return out.items;
}

fn b64(arena: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    const enc = std.base64.standard.Encoder;
    const buf = try arena.alloc(u8, enc.calcSize(bytes.len));
    return enc.encode(buf, bytes);
}

/// pySigma base64offset: the three encodings of `value` at byte offsets 0, 1
/// and 2, with the characters that depend on unknown neighbours cut off.
fn base64Offsets(arena: std.mem.Allocator, value: []const u8, out: *std.ArrayList([]const u8)) !void {
    const start = [_]usize{ 0, 2, 3 };
    const end_cut = [_]usize{ 0, 3, 2 };
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        const padded = try arena.alloc(u8, i + value.len);
        @memset(padded[0..i], ' ');
        @memcpy(padded[i..], value);
        const enc = try b64(arena, padded);
        const cut = end_cut[(value.len + i) % 3];
        if (enc.len < start[i] + cut) continue;
        try out.append(arena, enc[start[i] .. enc.len - cut]);
    }
}

// --- condition ------------------------------------------------------------------

const CondParser = struct {
    c: *Ctx,
    s: []const u8,
    pos: usize = 0,
    names: []const []const u8,
    nodes: []const ast.Node,
    depth: usize = 0,

    fn parse(p: *CondParser) Error!ast.Node {
        if (std.mem.indexOfScalar(u8, p.s, '|') != null) return p.c.reject("aggregation", "condition aggregations (|) are not supported; use a Tawny threshold rule", .{});
        const n = try p.orExpr();
        p.ws();
        if (p.pos != p.s.len) return p.c.reject("condition", "condition has trailing text: {s}", .{p.s[p.pos..]});
        return n;
    }

    fn ws(p: *CondParser) void {
        while (p.pos < p.s.len and std.ascii.isWhitespace(p.s[p.pos])) p.pos += 1;
    }

    fn peekWord(p: *CondParser) ?[]const u8 {
        p.ws();
        if (p.pos >= p.s.len) return null;
        if (p.s[p.pos] == '(' or p.s[p.pos] == ')') return p.s[p.pos .. p.pos + 1];
        var end = p.pos;
        while (end < p.s.len and !std.ascii.isWhitespace(p.s[end]) and p.s[end] != '(' and p.s[end] != ')') end += 1;
        return p.s[p.pos..end];
    }

    fn take(p: *CondParser) ?[]const u8 {
        const w = p.peekWord() orelse return null;
        p.pos += w.len;
        return w;
    }

    fn isKw(w: ?[]const u8, kw: []const u8) bool {
        return w != null and std.ascii.eqlIgnoreCase(w.?, kw);
    }

    fn orExpr(p: *CondParser) Error!ast.Node {
        p.depth += 1;
        defer p.depth -= 1;
        if (p.depth > 32) return p.c.reject("condition", "condition nests too deep", .{});
        var items: std.ArrayList(ast.Node) = .empty;
        try items.append(p.c.arena, try p.andExpr());
        while (isKw(p.peekWord(), "or")) {
            _ = p.take();
            try items.append(p.c.arena, try p.andExpr());
        }
        return if (items.items.len == 1) items.items[0] else .{ .any_of = items.items };
    }

    fn andExpr(p: *CondParser) Error!ast.Node {
        var items: std.ArrayList(ast.Node) = .empty;
        try items.append(p.c.arena, try p.notExpr());
        while (isKw(p.peekWord(), "and")) {
            _ = p.take();
            try items.append(p.c.arena, try p.notExpr());
        }
        return if (items.items.len == 1) items.items[0] else .{ .all_of = items.items };
    }

    fn notExpr(p: *CondParser) Error!ast.Node {
        if (isKw(p.peekWord(), "not")) {
            _ = p.take();
            const inner = try p.c.arena.create(ast.Node);
            inner.* = try p.notExpr();
            return .{ .not = inner };
        }
        return p.primary();
    }

    fn primary(p: *CondParser) Error!ast.Node {
        const w = p.take() orelse return p.c.reject("condition", "condition ends early", .{});
        if (std.mem.eql(u8, w, "(")) {
            const n = try p.orExpr();
            const close = p.take();
            if (close == null or !std.mem.eql(u8, close.?, ")")) return p.c.reject("condition", "condition has an unclosed parenthesis", .{});
            return n;
        }
        if (std.mem.eql(u8, w, ")")) return p.c.reject("condition", "condition has an unexpected )", .{});
        const is_count = std.ascii.eqlIgnoreCase(w, "all") or std.ascii.eqlIgnoreCase(w, "any") or (w.len > 0 and std.ascii.isDigit(w[0]));
        if (is_count and isKw(p.peekWord(), "of")) {
            _ = p.take();
            const target = p.take() orelse return p.c.reject("condition", "'of' needs a target", .{});
            const all = std.ascii.eqlIgnoreCase(w, "all");
            if (!all and !std.ascii.eqlIgnoreCase(w, "any")) {
                const n = std.fmt.parseInt(u32, w, 10) catch return p.c.reject("condition", "bad count {s}", .{w});
                if (n != 1) return p.c.reject("condition", "'{d} of' is not supported, only '1 of' and 'all of'", .{n});
            }
            var picked: std.ArrayList(ast.Node) = .empty;
            for (p.names, 0..) |name, i| {
                const hit = if (std.ascii.eqlIgnoreCase(target, "them"))
                    !std.mem.startsWith(u8, name, "_")
                else
                    ast.wildcardMatch(target, name, false);
                if (hit) try picked.append(p.c.arena, p.nodes[i]);
            }
            if (picked.items.len == 0) return p.c.reject("condition", "'{s}' matches no search identifier", .{target});
            if (picked.items.len == 1) return picked.items[0];
            return if (all) .{ .all_of = picked.items } else .{ .any_of = picked.items };
        }
        for (p.names, 0..) |name, i| {
            if (std.mem.eql(u8, name, w)) return p.nodes[i];
        }
        return p.c.reject("condition", "condition names unknown identifier {s}", .{w});
    }
};

// --- tests ------------------------------------------------------------------------

const testing = std.testing;

fn testCompile(arena: std.mem.Allocator, text: []const u8) !Compiled {
    const map = try arena.create(FieldMap);
    map.* = try FieldMap.load(arena);
    return compile(arena, map, text);
}

fn evalJson(arena: std.mem.Allocator, node: ast.Node, payload: []const u8) !bool {
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, payload, .{});
    return ast.eval(.{ .allocator = testing.allocator }, node, v);
}

test "field map in rules/ and the embedded copy agree" {
    const repo = std.Io.Dir.cwd().readFileAlloc(testing.io, "../rules/sigma/field-map.yaml", testing.allocator, .limited(1 << 20)) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer testing.allocator.free(repo);
    try testing.expectEqualStrings(field_map_yaml, repo);
}

test "process_creation rule compiles and matches the v2 payload" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const out = try testCompile(arena,
        \\title: Office spawns PowerShell
        \\id: 4b9a0000-0000-4000-8000-000000000001
        \\status: test
        \\logsource:
        \\    product: windows
        \\    category: process_creation
        \\detection:
        \\    selection_parent:
        \\        ParentImage|endswith:
        \\            - '\WINWORD.EXE'
        \\            - '\EXCEL.EXE'
        \\    selection_child:
        \\        - Image|endswith: '\powershell.exe'
        \\        - OriginalFileName: 'PowerShell.EXE'
        \\    filter_main_cli:
        \\        CommandLine|contains|all:
        \\            - '-nop'
        \\            - 'safe-marker'
        \\    condition: all of selection_* and not 1 of filter_main_*
        \\level: high
        \\tags:
        \\    - attack.execution
        \\    - attack.t1059.001
    );
    try testing.expectEqual(Status.supported, out.status);
    try testing.expectEqualStrings("process_start", out.event_type.?);
    try testing.expectEqualStrings("high", out.severity);
    try testing.expectEqualStrings("T1059.001", out.mitre[0]);
    const golden = try std.Io.Dir.cwd().readFileAlloc(testing.io, "../schemas/events/golden/process_start.json", arena, .limited(1 << 20));
    try testing.expect(try evalJson(arena, out.expr, golden));
    try testing.expect(!try evalJson(arena, out.expr,
        \\{"process":{"image":"C:\\x\\powershell.exe","command_line":"-nop safe-marker"},"parent":{"image":"C:\\x\\WINWORD.EXE"}}
    ));
    try testing.expect(!try evalJson(arena, out.expr,
        \\{"process":{"image":"C:\\x\\powershell.exe"},"parent":{"image":"C:\\x\\explorer.exe"}}
    ));
}

test "legacy contract rule keeps its snapshot path and single predicate" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const out = try testCompile(arena,
        \\title: sus
        \\logsource:
        \\  product: windows
        \\  category: process_creation
        \\detection:
        \\  selection:
        \\    processes.name|contains: suspicious.exe
        \\  condition: selection
        \\level: high
    );
    try testing.expectEqual(Status.supported_with_notes, out.status);
    try testing.expectEqualStrings("process_snapshot", out.event_type.?);
    try testing.expectEqualStrings("processes.name", out.single.?.path);
    try testing.expectEqualStrings("contains", out.single.?.operator);
    try testing.expectEqualStrings("suspicious.exe", out.single.?.value);
    try testing.expect(try evalJson(arena, out.expr, "{\"processes\":[{\"name\":\"a\"},{\"name\":\"very-SUSPICIOUS.exe\"}]}"));
}

test "modifiers: windash, base64offset, re, cidr, exists, numbers, wildcards" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const out = try testCompile(arena,
        \\title: mods
        \\logsource:
        \\  product: windows
        \\  category: process_creation
        \\detection:
        \\  sel_dash:
        \\    CommandLine|windash|contains: ' -enc '
        \\  sel_b64:
        \\    CommandLine|base64offset|contains: 'IEX'
        \\  sel_re:
        \\    CommandLine|re: '\s-H\s'
        \\  sel_wild:
        \\    Image: 'C:\Users\\*\AppData\\*.exe'
        \\  sel_int:
        \\    IntegrityLevel: null
        \\  condition: 1 of sel_*
    );
    try testing.expectEqual(Status.supported, out.status);
    try testing.expect(try evalJson(arena, out.expr, "{\"process\":{\"command_line\":\"powershell /enc AAAA\",\"integrity_level\":\"High\"}}"));
    try testing.expect(try evalJson(arena, out.expr, "{\"process\":{\"command_line\":\"powershell \\u2013enc AAAA\",\"integrity_level\":\"High\"}}"));
    // base64 of "IEX" at offset 0 is "SUVY".
    try testing.expect(try evalJson(arena, out.expr, "{\"process\":{\"command_line\":\"-e SUVYIChOZXc=\",\"integrity_level\":\"High\"}}"));
    try testing.expect(try evalJson(arena, out.expr, "{\"process\":{\"command_line\":\"curl -H x\",\"integrity_level\":\"High\"}}"));
    try testing.expect(!try evalJson(arena, out.expr, "{\"process\":{\"command_line\":\"curl -h x\",\"integrity_level\":\"High\"}}"));
    try testing.expect(try evalJson(arena, out.expr, "{\"process\":{\"image\":\"c:\\\\users\\\\bob\\\\appdata\\\\x.exe\",\"integrity_level\":\"High\"}}"));
    try testing.expect(try evalJson(arena, out.expr, "{\"process\":{\"command_line\":\"nothing\"}}"));
    try testing.expect(!try evalJson(arena, out.expr, "{\"process\":{\"command_line\":\"nothing\",\"integrity_level\":\"High\"}}"));

    const net = try testCompile(arena,
        \\title: net
        \\logsource: {product: windows, category: network_connection}
        \\detection:
        \\  selection:
        \\    DestinationIp|cidr: '203.0.113.0/24'
        \\    DestinationPort|gte: 443
        \\    Initiated: 'true'
        \\  condition: selection
    );
    try testing.expectEqual(Status.supported, net.status);
    try testing.expectEqualStrings("network_connect", net.event_type.?);
    const golden = try std.Io.Dir.cwd().readFileAlloc(testing.io, "../schemas/events/golden/network_connect.json", arena, .limited(1 << 20));
    try testing.expect(try evalJson(arena, net.expr, golden));
}

test "security service picks the event type from EventID" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const out = try testCompile(arena,
        \\title: logon
        \\logsource:
        \\  product: windows
        \\  service: security
        \\detection:
        \\  selection:
        \\    EventID: 4624
        \\    LogonType: 2
        \\    TargetUserName|startswith: 'ali'
        \\  condition: selection
    );
    try testing.expectEqual(Status.supported, out.status);
    try testing.expectEqualStrings("user_logon", out.event_type.?);
    const golden = try std.Io.Dir.cwd().readFileAlloc(testing.io, "../schemas/events/golden/user_logon.json", arena, .limited(1 << 20));
    try testing.expect(try evalJson(arena, out.expr, golden));

    const mixed = try testCompile(arena,
        \\title: mixed
        \\logsource: {product: windows, service: security}
        \\detection:
        \\  selection:
        \\    EventID: [4624, 4688]
        \\  condition: selection
    );
    try testing.expectEqual(Status.rejected, mixed.status);
}

test "hashes and joined fields" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const out = try testCompile(arena,
        \\title: hash
        \\logsource: {product: windows, category: process_creation}
        \\detection:
        \\  selection:
        \\    Hashes|contains:
        \\      - 'SHA256=0F343B0931126A20F133D67C2B018A3B5AB57A4F0B2F3D2B41B4D6F7F8E9A0B1'
        \\      - 'IMPHASH=00000000000000000000000000000000'
        \\    User|contains: 'CORP\alice'
        \\  condition: selection
    );
    try testing.expectEqual(Status.supported_with_notes, out.status);
    const golden = try std.Io.Dir.cwd().readFileAlloc(testing.io, "../schemas/events/golden/process_start.json", arena, .limited(1 << 20));
    try testing.expect(try evalJson(arena, out.expr, golden));

    const reg = try testCompile(arena,
        \\title: run key
        \\logsource: {product: windows, category: registry_set}
        \\detection:
        \\  selection:
        \\    TargetObject|contains: '\CurrentVersion\Run\'
        \\    Details|contains: '\AppData\Local\Temp\'
        \\  condition: selection
    );
    try testing.expectEqual(Status.supported, reg.status);
    const golden_reg = try std.Io.Dir.cwd().readFileAlloc(testing.io, "../schemas/events/golden/registry_set.json", arena, .limited(1 << 20));
    try testing.expect(try evalJson(arena, reg.expr, golden_reg));
}

test "unsupported constructs reject the whole rule with a reason" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const cases = [_]struct { yaml: []const u8, kind: []const u8 }{
        .{ .kind = "unmapped field", .yaml =
        \\title: x
        \\logsource: {product: windows, category: process_creation}
        \\detection:
        \\  selection:
        \\    Image|endswith: '\cmd.exe'
        \\    Mystery: 1
        \\  condition: selection
        },
        .{ .kind = "regex", .yaml =
        \\title: x
        \\logsource: {product: windows, category: process_creation}
        \\detection:
        \\  selection:
        \\    CommandLine|re: '(a)\1'
        \\  condition: selection
        },
        .{ .kind = "aggregation", .yaml =
        \\title: x
        \\logsource: {product: windows, category: process_creation}
        \\detection:
        \\  selection:
        \\    Image|endswith: '\cmd.exe'
        \\  condition: selection | count() by Computer > 5
        },
        .{ .kind = "unmapped logsource", .yaml =
        \\title: x
        \\logsource: {product: windows, category: driver_load}
        \\detection:
        \\  selection:
        \\    ImageLoaded|endswith: '.sys'
        \\  condition: selection
        },
        .{ .kind = "unsupported modifier", .yaml =
        \\title: x
        \\logsource: {product: windows, category: process_creation}
        \\detection:
        \\  selection:
        \\    CommandLine|fieldref: Image
        \\  condition: selection
        },
        .{ .kind = "condition", .yaml =
        \\title: x
        \\logsource: {product: windows, category: process_creation}
        \\detection:
        \\  selection:
        \\    Image|endswith: '\cmd.exe'
        \\  condition: selection and missing
        },
        .{ .kind = "condition", .yaml =
        \\title: x
        \\logsource: {product: windows, category: process_creation}
        \\detection:
        \\  sel_a:
        \\    Image|endswith: '\cmd.exe'
        \\  sel_b:
        \\    Image|endswith: '\ps.exe'
        \\  condition: 2 of sel_*
        },
        .{ .kind = "keywords", .yaml =
        \\title: x
        \\logsource: {product: windows, category: network_connection}
        \\detection:
        \\  keywords:
        \\    - evil
        \\  condition: keywords
        },
    };
    for (cases) |case| {
        const out = try testCompile(arena, case.yaml);
        try testing.expectEqual(Status.rejected, out.status);
        testing.expectEqualStrings(case.kind, out.reason_kind) catch |err| {
            std.debug.print("reason: {s}\n", .{out.reason});
            return err;
        };
        try testing.expect(out.reason.len > 0);
    }
}

test "keyword list matches the logsource keyword field only" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const out = try testCompile(arena,
        \\title: kw
        \\logsource: {product: windows, category: ps_script}
        \\detection:
        \\  keywords:
        \\    - 'Invoke-Mimikatz'
        \\    - 'sekurlsa::*'
        \\  condition: keywords
    );
    try testing.expect(out.status != .rejected);
    try testing.expectEqualStrings("powershell_script_block", out.event_type.?);
    try testing.expect(try evalJson(arena, out.expr, "{\"script_block\":{\"text\":\"x; invoke-mimikatz -dump\"}}"));
    try testing.expect(try evalJson(arena, out.expr, "{\"script_block\":{\"text\":\"run sekurlsa::logonpasswords\"}}"));
    try testing.expect(!try evalJson(arena, out.expr, "{\"script_block\":{\"text\":\"benign\"},\"note\":\"Invoke-Mimikatz\"}"));
}
