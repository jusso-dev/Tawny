//! Incident grouping and risk (docs/architecture/target-edr.md sections 7
//! and 8). `attach` runs after each alert insert in jobs/detect.zig.
//!
//! An alert joins an open incident updated within the window (4 h) when:
//!   1. lineage: same agent and the same lineage root, the oldest ancestor
//!      in `process_entities` below a session root (explorer.exe,
//!      services.exe, wininit.exe, init, systemd, launchd), or
//!   2. artefact: same agent and same user, plus a shared sha256, domain or IP, or
//!   3. indicator: any agent, the same high-confidence indicator (an IOC
//!      rule match) or the same file sha256.
//! Otherwise it opens a new incident.
//!
//! Risk is the section 7 noisy-OR over the incident's evidence, deduplicated
//! by key, with each item and its points stored in `risk_items`.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const ast = @import("ast.zig");

pub const window_seconds: i64 = 4 * 3600;

/// Session roots. Lineage stops below these, so two unrelated programs the
/// user started from Explorer are not one incident.
const session_roots = [_][]const u8{
    "explorer.exe", "services.exe", "wininit.exe", "winlogon.exe", "smss.exe", "userinit.exe",
    "init",         "systemd",      "launchd",     "sshd",         "login",    "csrss.exe",
};

pub fn isSessionRoot(image_or_name: []const u8) bool {
    const base = basename(image_or_name);
    for (session_roots) |r| {
        if (std.ascii.eqlIgnoreCase(base, r)) return true;
    }
    return false;
}

fn basename(path: []const u8) []const u8 {
    const i = std.mem.lastIndexOfAny(u8, path, "\\/") orelse return path;
    return path[i + 1 ..];
}

// ---------------------------------------------------------------- risk

pub const Item = struct {
    key: []const u8,
    kind: []const u8,
    label: []const u8,
    weight: f64,
    confidence: f64 = 1.0,
    /// 0 allowlisted, 0.5 signed by a trusted vendor, 1 otherwise.
    context: f64 = 1.0,

    pub fn points(self: Item) f64 {
        return std.math.clamp(self.weight * self.confidence * self.context, 0, 100);
    }
};

/// risk = 100 * (1 - prod(1 - s/100)). Items with the same key count once
/// (the highest scoring copy). Never above 100.
pub fn noisyOr(items: []const Item) f64 {
    var prod: f64 = 1.0;
    for (items, 0..) |it, i| {
        var dup = false;
        for (items[0..i]) |prev| {
            if (std.mem.eql(u8, prev.key, it.key)) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        var best = it.points();
        for (items[i + 1 ..]) |later| {
            if (std.mem.eql(u8, later.key, it.key)) best = @max(best, later.points());
        }
        prod *= 1.0 - best / 100.0;
    }
    return 100.0 * (1.0 - prod);
}

pub fn severityFor(risk: f64, floor: []const u8) []const u8 {
    const by_risk: []const u8 = if (risk >= 85) "critical" else if (risk >= 65) "high" else if (risk >= 40) "medium" else "low";
    return if (sevRank(floor) > sevRank(by_risk)) normSev(floor) else by_risk;
}

fn normSev(s: []const u8) []const u8 {
    return switch (sevRank(s)) {
        3 => "critical",
        2 => "high",
        1 => "medium",
        else => "low",
    };
}

pub fn sevRank(s: []const u8) u8 {
    if (std.ascii.eqlIgnoreCase(s, "critical")) return 3;
    if (std.ascii.eqlIgnoreCase(s, "high")) return 2;
    if (std.ascii.eqlIgnoreCase(s, "medium")) return 1;
    return 0;
}

/// Default weight per alert when the rule YAML has none: by rule severity.
/// IOC rules are high-confidence indicator matches (section 7: 50).
pub fn alertWeight(format: []const u8, severity: []const u8) f64 {
    if (std.mem.eql(u8, format, "ioc")) return 50;
    return switch (sevRank(severity)) {
        3 => 60,
        2 => 30,
        1 => 20,
        else => 10,
    };
}

// ---------------------------------------------------------------- evidence keys

pub const Facts = struct {
    entity_id: ?[]const u8 = null,
    parent_entity_id: ?[]const u8 = null,
    user: ?[]const u8 = null,
    sha256: ?[]const u8 = null,
    domain: ?[]const u8 = null,
    ip: ?[]const u8 = null,
};

fn validEntity(s: []const u8) bool {
    if (s.len != 26) return false;
    for (s) |c| {
        if (!((c >= 'a' and c <= 'z') or (c >= '2' and c <= '7'))) return false;
    }
    return true;
}

fn validSha256(s: []const u8) bool {
    if (s.len != 64) return false;
    for (s) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}

fn first(root: std.json.Value, paths: []const []const u8, buf: *[64]u8) ?[]const u8 {
    for (paths) |p| {
        if (ast.firstScalar(root, p, buf)) |v| {
            if (v.len > 0) return v;
        }
    }
    return null;
}

/// Pull grouping facts out of an event payload. Values are copied into `arena`.
pub fn extract(arena: std.mem.Allocator, root: std.json.Value) !Facts {
    var f: Facts = .{};
    var buf: [64]u8 = undefined;
    if (first(root, &.{"process.entity_id"}, &buf)) |v| {
        if (validEntity(v)) f.entity_id = try arena.dupe(u8, v);
    }
    if (first(root, &.{"parent.entity_id"}, &buf)) |v| {
        if (validEntity(v)) f.parent_entity_id = try arena.dupe(u8, v);
    }
    if (first(root, &.{ "process.user.name", "user.name", "process.user" }, &buf)) |v| {
        f.user = try std.ascii.allocLowerString(arena, v);
    }
    if (first(root, &.{ "file.hashes.sha256", "process.hashes.sha256", "sha256" }, &buf)) |v| {
        if (validSha256(v)) f.sha256 = try std.ascii.allocLowerString(arena, v);
    }
    if (first(root, &.{ "dns.query", "qname" }, &buf)) |v| {
        f.domain = try std.ascii.allocLowerString(arena, std.mem.trimEnd(u8, v, "."));
    }
    if (first(root, &.{"network.dst_ip"}, &buf)) |v| {
        if (!privateOrLocal(v)) f.ip = try arena.dupe(u8, v);
    }
    return f;
}

/// Private, loopback and link-local destinations are shared by every host
/// on a network, so they are not artefacts worth grouping on.
fn privateOrLocal(ip: []const u8) bool {
    const prefixes = [_][]const u8{ "10.", "127.", "192.168.", "169.254.", "0.", "::1", "fe80:", "fc", "fd" };
    for (prefixes) |p| if (std.ascii.startsWithIgnoreCase(ip, p)) return true;
    if (std.mem.startsWith(u8, ip, "172.")) {
        var it = std.mem.splitScalar(u8, ip[4..], '.');
        const second = std.fmt.parseInt(u8, it.next() orelse "", 10) catch return false;
        return second >= 16 and second <= 31;
    }
    return false;
}

// ---------------------------------------------------------------- attach

pub const AlertRef = struct {
    tenant_id: []const u8,
    agent_id: []const u8,
    alert_id: []const u8,
    rule_id: []const u8,
    rule_name: []const u8,
    rule_format: []const u8,
    severity: []const u8,
    hostname: []const u8,
    occurred_at: []const u8,
    techniques_pg: []const u8 = "{}",
    root: std.json.Value,
};

fn freeRows(allocator: std.mem.Allocator, rows: []pg.Row) void {
    for (rows) |row| row.deinit(allocator);
    allocator.free(rows);
}

/// Oldest ancestor below a session root, walking `process_entities`.
/// Falls back to the entity itself when the parent chain is unknown.
pub fn lineageRoot(arena: std.mem.Allocator, conn: *pg.Conn, tenant_id: []const u8, entity_id: []const u8) ![]const u8 {
    const rows = try conn.exec(arena,
        \\WITH RECURSIVE chain(entity_id, parent_entity_id, image, depth) AS (
        \\  SELECT entity_id, parent_entity_id, image, 0 FROM process_entities
        \\  WHERE tenant_id = $1::uuid AND entity_id = $2
        \\  UNION ALL
        \\  SELECT p.entity_id, p.parent_entity_id, p.image, c.depth + 1
        \\  FROM process_entities p JOIN chain c ON p.entity_id = c.parent_entity_id
        \\  WHERE p.tenant_id = $1::uuid AND c.depth < 64
        \\)
        \\SELECT entity_id, coalesce(image, '') FROM chain ORDER BY depth
    , &.{ .{ .text = tenant_id }, .{ .text = entity_id } });
    defer freeRows(arena, rows);
    var root: []const u8 = entity_id;
    for (rows) |row| {
        const image = row.cols[1] orelse "";
        if (isSessionRoot(image)) break;
        root = row.cols[0] orelse root;
    }
    return arena.dupe(u8, root);
}

const Match = struct { id: []const u8, reason: []const u8 };

/// Group one new alert. Returns the incident id it landed in.
pub fn attach(allocator: std.mem.Allocator, conn: *pg.Conn, a: AlertRef, now_unix: i64) ![]u8 {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const f = try extract(arena, a.root);
    var keys: std.ArrayList([]const u8) = .empty;
    var root_entity: ?[]const u8 = null;
    if (f.entity_id) |eid| {
        root_entity = try lineageRoot(arena, conn, a.tenant_id, eid);
        try keys.append(arena, try std.fmt.allocPrint(arena, "root:{s}", .{root_entity.?}));
    }
    if (f.user) |u| try keys.append(arena, try std.fmt.allocPrint(arena, "user:{s}", .{u}));
    if (f.sha256) |h| try keys.append(arena, try std.fmt.allocPrint(arena, "sha256:{s}", .{h}));
    if (f.domain) |d| try keys.append(arena, try std.fmt.allocPrint(arena, "domain:{s}", .{d}));
    if (f.ip) |ip| try keys.append(arena, try std.fmt.allocPrint(arena, "ip:{s}", .{ip}));
    const is_ioc = std.mem.eql(u8, a.rule_format, "ioc");
    if (is_ioc) try keys.append(arena, try std.fmt.allocPrint(arena, "ioc:{s}", .{a.rule_id}));
    const keys_pg = try util.pgArrayText(arena, keys.items);

    var tbuf: [32]u8 = undefined;
    const since = util.formatRfc3339(&tbuf, now_unix - window_seconds);

    const found: ?Match = try findIncident(arena, conn, a, f, root_entity, is_ioc, since);
    var nbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&nbuf, now_unix);
    var id_text: []const u8 = undefined;
    var reason: []const u8 = undefined;
    if (found) |m| {
        id_text = m.id;
        reason = m.reason;
    } else {
        var idb: [36]u8 = undefined;
        id_text = try arena.dupe(u8, newId(&idb, a.alert_id, now_unix));
        reason = if (root_entity != null) "lineage" else if (is_ioc) "indicator" else if (f.sha256 != null or f.domain != null or f.ip != null) "artefact" else "alert";
        const title = try std.fmt.allocPrint(arena, "{s} on {s}", .{ a.rule_name, a.hostname });
        try conn.execNoRows(
            \\INSERT INTO incidents (id, tenant_id, title, status, severity, risk, grouping, root_entity_id,
            \\  first_seen_at, last_seen_at, created_at, updated_at)
            \\VALUES ($1::uuid, $2::uuid, $3, 'new', 'low', 0, $4, $5, $6::timestamptz, $6::timestamptz, $7::timestamptz, $7::timestamptz)
        , &.{
            .{ .text = id_text },
            .{ .text = a.tenant_id },
            .{ .text = title },
            .{ .text = reason },
            if (root_entity) |r| .{ .text = r } else .{ .null = {} },
            .{ .text = a.occurred_at },
            .{ .text = now_s },
        });
    }
    try conn.execNoRows(
        \\INSERT INTO incident_alerts (tenant_id, incident_id, alert_id, agent_id, keys, reason, occurred_at, added_at)
        \\VALUES ($1::uuid, $2::uuid, $3::bigint, $4::uuid, $5::text[], $6, $7::timestamptz, $8::timestamptz)
        \\ON CONFLICT DO NOTHING
    , &.{
        .{ .text = a.tenant_id },
        .{ .text = id_text },
        .{ .text = a.alert_id },
        .{ .text = a.agent_id },
        .{ .text = keys_pg },
        .{ .text = reason },
        .{ .text = a.occurred_at },
        .{ .text = now_s },
    });
    try recompute(allocator, conn, a.tenant_id, id_text, now_s);
    return allocator.dupe(u8, id_text);
}

/// Deterministic id from the first alert, so a retried detect job lands in
/// the same incident.
fn newId(buf: *[36]u8, alert_id: []const u8, now_unix: i64) []const u8 {
    var dig: [32]u8 = undefined;
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("tawny-incident:");
    h.update(alert_id);
    var nb: [20]u8 = undefined;
    h.update(std.fmt.bufPrint(&nb, ":{d}", .{@divFloor(now_unix, window_seconds)}) catch "");
    h.final(&dig);
    dig[6] = (dig[6] & 0x0f) | 0x40;
    dig[8] = (dig[8] & 0x3f) | 0x80;
    const hex = "0123456789abcdef";
    var j: usize = 0;
    for (dig[0..16], 0..) |b, i| {
        if (i == 4 or i == 6 or i == 8 or i == 10) {
            buf[j] = '-';
            j += 1;
        }
        buf[j] = hex[b >> 4];
        buf[j + 1] = hex[b & 0xf];
        j += 2;
    }
    return buf[0..36];
}

fn findIncident(
    arena: std.mem.Allocator,
    conn: *pg.Conn,
    a: AlertRef,
    f: Facts,
    root_entity: ?[]const u8,
    is_ioc: bool,
    since: []const u8,
) !?Match {
    // Rule 1: same agent, same lineage root.
    if (root_entity) |r| {
        const key = try std.fmt.allocPrint(arena, "root:{s}", .{r});
        if (try openWith(arena, conn, a.tenant_id, a.agent_id, &.{key}, since)) |id| return .{ .id = id, .reason = "lineage" };
    }
    // Rule 2: same agent and user, plus a shared artefact.
    if (f.user) |u| {
        var art: std.ArrayList([]const u8) = .empty;
        if (f.sha256) |h| try art.append(arena, try std.fmt.allocPrint(arena, "sha256:{s}", .{h}));
        if (f.domain) |d| try art.append(arena, try std.fmt.allocPrint(arena, "domain:{s}", .{d}));
        if (f.ip) |ip| try art.append(arena, try std.fmt.allocPrint(arena, "ip:{s}", .{ip}));
        if (art.items.len > 0) {
            const user_key = try std.fmt.allocPrint(arena, "user:{s}", .{u});
            const art_pg = try util.pgArrayText(arena, art.items);
            const rows = try conn.exec(arena,
                \\SELECT i.id::text FROM incidents i JOIN incident_alerts ia ON ia.incident_id = i.id
                \\WHERE i.tenant_id = $1::uuid AND ia.agent_id = $2::uuid
                \\  AND i.status IN ('new','investigating') AND i.last_seen_at >= $3::timestamptz
                \\  AND $4 = ANY(ia.keys) AND ia.keys && $5::text[]
                \\ORDER BY i.last_seen_at DESC LIMIT 1
            , &.{ .{ .text = a.tenant_id }, .{ .text = a.agent_id }, .{ .text = since }, .{ .text = user_key }, .{ .text = art_pg } });
            defer freeRows(arena, rows);
            if (rows.len > 0) return .{ .id = try arena.dupe(u8, rows[0].cols[0].?), .reason = "artefact" };
        }
    }
    // Rule 3: cross-agent, same high-confidence indicator or same file hash.
    var cross: std.ArrayList([]const u8) = .empty;
    if (is_ioc) try cross.append(arena, try std.fmt.allocPrint(arena, "ioc:{s}", .{a.rule_id}));
    if (f.sha256) |h| try cross.append(arena, try std.fmt.allocPrint(arena, "sha256:{s}", .{h}));
    if (cross.items.len > 0) {
        if (try openWith(arena, conn, a.tenant_id, null, cross.items, since)) |id| return .{ .id = id, .reason = "indicator" };
    }
    return null;
}

fn openWith(arena: std.mem.Allocator, conn: *pg.Conn, tenant_id: []const u8, agent_id: ?[]const u8, keys: []const []const u8, since: []const u8) !?[]const u8 {
    const keys_pg = try util.pgArrayText(arena, keys);
    const rows = try conn.exec(arena,
        \\SELECT i.id::text FROM incidents i JOIN incident_alerts ia ON ia.incident_id = i.id
        \\WHERE i.tenant_id = $1::uuid AND ($2::uuid IS NULL OR ia.agent_id = $2::uuid)
        \\  AND i.status IN ('new','investigating') AND i.last_seen_at >= $3::timestamptz
        \\  AND ia.keys && $4::text[]
        \\ORDER BY i.last_seen_at DESC LIMIT 1
    , &.{
        .{ .text = tenant_id },
        if (agent_id) |id| .{ .text = id } else .{ .null = {} },
        .{ .text = since },
        .{ .text = keys_pg },
    });
    defer freeRows(arena, rows);
    if (rows.len == 0) return null;
    return try arena.dupe(u8, rows[0].cols[0].?);
}

/// Rebuild risk, severity, title, agents, users and techniques from the
/// incident's alerts. Evidence is one item per rule (key `rule:<id>`), so a
/// rule that fires ten times counts once.
pub fn recompute(allocator: std.mem.Allocator, conn: *pg.Conn, tenant_id: []const u8, incident_id: []const u8, now_s: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const rows = try conn.exec(arena,
        \\SELECT r.id::text, r.name, r.format, a.severity, ag.hostname, ia.agent_id::text,
        \\       array_to_json(r.mitre_techniques)::text, array_to_json(ia.keys)::text, ia.occurred_at::text, a.title
        \\FROM incident_alerts ia
        \\JOIN alerts a ON a.id = ia.alert_id
        \\JOIN alert_rules r ON r.id = a.alert_rule_id
        \\JOIN agents ag ON ag.id = ia.agent_id
        \\WHERE ia.tenant_id = $1::uuid AND ia.incident_id = $2::uuid
        \\ORDER BY ia.occurred_at, a.id
    , &.{ .{ .text = tenant_id }, .{ .text = incident_id } });
    defer freeRows(arena, rows);
    if (rows.len == 0) return;

    var items: std.ArrayList(Item) = .empty;
    var agents: std.ArrayList([]const u8) = .empty;
    var users: std.ArrayList([]const u8) = .empty;
    var techs: std.ArrayList([]const u8) = .empty;
    var floor: []const u8 = "low";
    var best_title: []const u8 = rows[0].cols[1] orelse "Incident";
    var best_host: []const u8 = rows[0].cols[4] orelse "";
    var best_w: f64 = -1;
    var first_seen: []const u8 = rows[0].cols[8] orelse now_s;
    var last_seen: []const u8 = first_seen;
    for (rows) |row| {
        const c = row.cols;
        const rid = c[0] orelse continue;
        const sev = c[3] orelse "low";
        const w = alertWeight(c[2] orelse "", sev);
        try items.append(arena, .{
            .key = try std.fmt.allocPrint(arena, "rule:{s}", .{rid}),
            .kind = if (std.mem.eql(u8, c[2] orelse "", "ioc")) "indicator" else "detection",
            .label = c[1] orelse "rule",
            .weight = w,
        });
        if (w > best_w) {
            best_w = w;
            best_title = c[1] orelse best_title;
            best_host = c[4] orelse best_host;
        }
        if (sevRank(sev) == 3) floor = "critical";
        try addUnique(arena, &agents, c[5] orelse "");
        if (c[6]) |raw| {
            const list = try std.json.parseFromSliceLeaky([]const []const u8, arena, raw, .{});
            for (list) |t| try addUnique(arena, &techs, t);
        }
        if (c[7]) |raw| {
            const list = try std.json.parseFromSliceLeaky([]const []const u8, arena, raw, .{});
            for (list) |k| {
                if (std.mem.startsWith(u8, k, "user:")) try addUnique(arena, &users, k[5..]);
            }
        }
        if (c[8]) |t| {
            if (std.mem.order(u8, t, first_seen) == .lt) first_seen = t;
            if (std.mem.order(u8, t, last_seen) == .gt) last_seen = t;
        }
    }
    if (std.mem.order(u8, now_s, last_seen) == .gt) last_seen = now_s;
    const risk = noisyOr(items.items);
    const severity = severityFor(risk, floor);
    const risk_items = try itemsJson(arena, items.items);
    const title = try std.fmt.allocPrint(arena, "{s} on {s}", .{ best_title, best_host });
    var rbuf: [8]u8 = undefined;
    const risk_txt = try std.fmt.bufPrint(&rbuf, "{d}", .{@as(u32, @intFromFloat(@round(risk)))});
    try conn.execNoRows(
        \\UPDATE incidents SET risk = $3::int, severity = $4, risk_items = $5::jsonb, title = $6,
        \\  agent_ids = $7::uuid[], users = $8::text[], techniques = $9::text[],
        \\  first_seen_at = least(first_seen_at, $10::timestamptz), last_seen_at = $11::timestamptz, updated_at = $11::timestamptz
        \\WHERE tenant_id = $1::uuid AND id = $2::uuid
    , &.{
        .{ .text = tenant_id },
        .{ .text = incident_id },
        .{ .text = risk_txt },
        .{ .text = severity },
        .{ .text = risk_items },
        .{ .text = title },
        .{ .text = try util.pgArrayText(arena, agents.items) },
        .{ .text = try util.pgArrayText(arena, users.items) },
        .{ .text = try util.pgArrayText(arena, techs.items) },
        .{ .text = first_seen },
        .{ .text = last_seen },
    });
}

fn addUnique(arena: std.mem.Allocator, list: *std.ArrayList([]const u8), v: []const u8) !void {
    if (v.len == 0) return;
    for (list.items) |x| if (std.mem.eql(u8, x, v)) return;
    try list.append(arena, v);
}

/// Each evidence item once, with its points, so the analyst sees why.
pub fn itemsJson(allocator: std.mem.Allocator, items: []const Item) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, '[');
    var n: usize = 0;
    for (items, 0..) |it, i| {
        var dup = false;
        for (items[0..i]) |prev| {
            if (std.mem.eql(u8, prev.key, it.key)) dup = true;
        }
        if (dup) continue;
        if (n > 0) try out.append(allocator, ',');
        n += 1;
        try out.appendSlice(allocator, "{\"key\":");
        try util.appendEscaped(&out, allocator, it.key);
        try out.appendSlice(allocator, ",\"kind\":");
        try util.appendEscaped(&out, allocator, it.kind);
        try out.appendSlice(allocator, ",\"label\":");
        try util.appendEscaped(&out, allocator, it.label);
        const line = try std.fmt.allocPrint(allocator, ",\"weight\":{d},\"confidence\":{d},\"context\":{d},\"points\":{d}}}", .{
            it.weight, it.confidence, it.context, @round(it.points() * 10) / 10,
        });
        defer allocator.free(line);
        try out.appendSlice(allocator, line);
    }
    try out.append(allocator, ']');
    return out.toOwnedSlice(allocator);
}

test "noisy-or saturates, dedupes by key and never exceeds 100" {
    const one = [_]Item{.{ .key = "a", .kind = "d", .label = "x", .weight = 50 }};
    try std.testing.expectApproxEqAbs(@as(f64, 50), noisyOr(&one), 1e-9);
    const two = [_]Item{
        .{ .key = "a", .kind = "d", .label = "x", .weight = 50 },
        .{ .key = "b", .kind = "d", .label = "y", .weight = 50 },
    };
    try std.testing.expectApproxEqAbs(@as(f64, 75), noisyOr(&two), 1e-9);
    const dup = [_]Item{
        .{ .key = "a", .kind = "d", .label = "x", .weight = 25 },
        .{ .key = "a", .kind = "d", .label = "x", .weight = 25 },
    };
    try std.testing.expectApproxEqAbs(@as(f64, 25), noisyOr(&dup), 1e-9);
    var many: [40]Item = undefined;
    for (&many, 0..) |*m, i| m.* = .{ .key = &[_]u8{@intCast('A' + i)}, .kind = "d", .label = "x", .weight = 100 };
    try std.testing.expect(noisyOr(&many) <= 100.0);
    const allow = [_]Item{.{ .key = "a", .kind = "d", .label = "x", .weight = 80, .context = 0 }};
    try std.testing.expectEqual(@as(f64, 0), noisyOr(&allow));
    // Section 7 example chain: Office to PowerShell 25, encoded command 20,
    // unsigned exe 20, persistence 30 gives 1 - .75*.8*.8*.7 = 66.4.
    const chain = [_]Item{
        .{ .key = "o", .kind = "d", .label = "office", .weight = 25 },
        .{ .key = "e", .kind = "d", .label = "enc", .weight = 20 },
        .{ .key = "u", .kind = "d", .label = "unsigned", .weight = 20 },
        .{ .key = "p", .kind = "d", .label = "persist", .weight = 30 },
    };
    try std.testing.expectApproxEqAbs(@as(f64, 66.4), noisyOr(&chain), 1e-9);
    try std.testing.expectEqualStrings("high", severityFor(noisyOr(&chain), "low"));
    try std.testing.expectEqualStrings("critical", severityFor(10, "critical"));
    try std.testing.expectEqualStrings("medium", severityFor(40, "low"));
}

test "evidence items list each key once with points" {
    const a = std.testing.allocator;
    const items = [_]Item{
        .{ .key = "rule:1", .kind = "detection", .label = "Office spawns \"shell\"", .weight = 30 },
        .{ .key = "rule:1", .kind = "detection", .label = "Office spawns \"shell\"", .weight = 30 },
        .{ .key = "rule:2", .kind = "indicator", .label = "IOC", .weight = 50, .context = 0.5 },
    };
    const json = try itemsJson(a, &items);
    defer a.free(json);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, json, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), parsed.value.array.items.len);
    const second = parsed.value.array.items[1].object;
    try std.testing.expectEqual(@as(f64, 25), switch (second.get("points").?) {
        .float => |v| v,
        .integer => |v| @as(f64, @floatFromInt(v)),
        else => -1,
    });
}

test "session roots stop lineage and facts come from canonical fields" {
    try std.testing.expect(isSessionRoot("C:\\Windows\\explorer.exe"));
    try std.testing.expect(isSessionRoot("/sbin/launchd"));
    try std.testing.expect(!isSessionRoot("C:\\Program Files\\Microsoft Office\\WINWORD.EXE"));
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const payload =
        \\{"process":{"entity_id":"abcdefghijklmnopqrstuvwxyz","user":{"name":"CORP\\Alice"},
        \\ "hashes":{"sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
        \\ "parent":{"entity_id":"not-an-id"},"network":{"dst_ip":"192.168.1.5"},"dns":{"query":"Evil.Example."}}
    ;
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, payload, .{});
    const f = try extract(arena, v);
    try std.testing.expectEqualStrings("abcdefghijklmnopqrstuvwxyz", f.entity_id.?);
    try std.testing.expect(f.parent_entity_id == null);
    try std.testing.expectEqualStrings("corp\\alice", f.user.?);
    try std.testing.expectEqual(@as(usize, 64), f.sha256.?.len);
    try std.testing.expect(f.ip == null);
    try std.testing.expectEqualStrings("evil.example", f.domain.?);
    try std.testing.expect(!privateOrLocal("8.8.8.8"));
    try std.testing.expect(privateOrLocal("172.20.0.1"));
    try std.testing.expect(!privateOrLocal("172.32.0.1"));
}
