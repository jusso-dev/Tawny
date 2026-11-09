//! Incidents and alert triage. Lists, one incident with its alerts and risk
//! breakdown, assign, status, and alert acknowledge and resolve.
//! Case management lives in Tawny-SOC; these routes only triage.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");
const audit = @import("../http/audit.zig");

/// Route permissions, enforced by http/permissions.zig before the handler runs.
pub const routes = [_]@import("../http/permissions.zig").Route{
    .{ .method = .GET, .path = "/api/incidents", .perm = .read },
    .{ .method = .GET, .path = "/api/incidents/:id", .perm = .read },
    .{ .method = .POST, .path = "/api/incidents/:id/assign", .perm = .triage },
    .{ .method = .POST, .path = "/api/incidents/:id/status", .perm = .triage },
};

pub const statuses = [_][]const u8{ "new", "investigating", "resolved", "false_positive" };

pub fn validStatus(s: []const u8) bool {
    for (statuses) |x| if (std.mem.eql(u8, x, s)) return true;
    return false;
}

fn freeRows(allocator: std.mem.Allocator, rows: []pg.Row) void {
    for (rows) |row| row.deinit(allocator);
    allocator.free(rows);
}

fn csrfOk(request: *std.http.Server.Request, web: auth.WebUser) bool {
    return web.session_id == null or auth.checkCsrf(request, web);
}

fn isUuid(s: []const u8) bool {
    if (s.len != 36) return false;
    for (s, 0..) |c, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (c != '-') return false;
        } else if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

const incident_select =
    \\SELECT i.id::text, i.title, i.status, i.severity, i.risk::text, i.risk_items::text,
    \\       i.owner_user_id::text, u.email, i.grouping, i.root_entity_id,
    \\       array_to_json(i.agent_ids)::text, array_to_json(i.users)::text, array_to_json(i.techniques)::text,
    \\       i.first_seen_at::text, i.last_seen_at::text, i.created_at::text, i.updated_at::text,
    \\       (SELECT count(*) FROM incident_alerts ia WHERE ia.incident_id = i.id)::text,
    \\       i.soc_case_status
    \\FROM incidents i LEFT JOIN users u ON u.id = i.owner_user_id
;

fn appendIncident(out: *std.ArrayList(u8), allocator: std.mem.Allocator, c: []const ?[]const u8) !void {
    const fields = [_]struct { name: []const u8, idx: usize, raw: bool }{
        .{ .name = "id", .idx = 0, .raw = false },
        .{ .name = "title", .idx = 1, .raw = false },
        .{ .name = "status", .idx = 2, .raw = false },
        .{ .name = "severity", .idx = 3, .raw = false },
        .{ .name = "risk", .idx = 4, .raw = true },
        .{ .name = "risk_items", .idx = 5, .raw = true },
        .{ .name = "owner_user_id", .idx = 6, .raw = false },
        .{ .name = "owner_email", .idx = 7, .raw = false },
        .{ .name = "grouping", .idx = 8, .raw = false },
        .{ .name = "root_entity_id", .idx = 9, .raw = false },
        .{ .name = "agent_ids", .idx = 10, .raw = true },
        .{ .name = "users", .idx = 11, .raw = true },
        .{ .name = "techniques", .idx = 12, .raw = true },
        .{ .name = "first_seen_at", .idx = 13, .raw = false },
        .{ .name = "last_seen_at", .idx = 14, .raw = false },
        .{ .name = "created_at", .idx = 15, .raw = false },
        .{ .name = "updated_at", .idx = 16, .raw = false },
        .{ .name = "alert_count", .idx = 17, .raw = true },
        .{ .name = "soc_case_status", .idx = 18, .raw = false },
    };
    try out.append(allocator, '{');
    for (fields, 0..) |f, i| {
        if (i > 0) try out.append(allocator, ',');
        try out.append(allocator, '"');
        try out.appendSlice(allocator, f.name);
        try out.appendSlice(allocator, "\":");
        const v = c[f.idx];
        if (v == null) {
            try out.appendSlice(allocator, if (f.raw) "[]" else "null");
        } else if (f.raw) {
            try out.appendSlice(allocator, v.?);
        } else {
            try util.appendEscaped(out, allocator, v.?);
        }
    }
    try out.append(allocator, '}');
}

pub fn list(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    target: []const u8,
) !void {
    const status = util.queryParam(target, "status");
    if (status) |s| {
        if (!validStatus(s) and !std.mem.eql(u8, s, "open")) return util.problem(request, allocator, .bad_request, "Unknown status.");
    }
    const limit_raw = util.queryParam(target, "limit") orelse "100";
    var limit = std.fmt.parseInt(i32, limit_raw, 10) catch 100;
    limit = std.math.clamp(limit, 1, 500);
    var lbuf: [12]u8 = undefined;
    const lim = try std.fmt.bufPrint(&lbuf, "{d}", .{limit});
    const rows = try conn.exec(allocator, incident_select ++
        \\ WHERE i.tenant_id = $1::uuid
        \\   AND ($2::text IS NULL OR i.status = $2 OR ($2 = 'open' AND i.status IN ('new','investigating')))
        \\ ORDER BY i.last_seen_at DESC LIMIT $3::int
    , &.{
        .{ .text = web.tenant_id },
        if (status) |s| .{ .text = s } else .{ .null = {} },
        .{ .text = lim },
    });
    defer freeRows(allocator, rows);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.append(allocator, '[');
    for (rows, 0..) |row, i| {
        if (i > 0) try out.append(allocator, ',');
        try appendIncident(&out, allocator, row.cols);
    }
    try out.append(allocator, ']');
    try util.respondJson(request, .ok, out.items);
}

pub fn get(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    id: []const u8,
) !void {
    if (!isUuid(id)) return util.problem(request, allocator, .not_found, "Incident not found.");
    const rows = try conn.exec(allocator, incident_select ++ " WHERE i.tenant_id = $1::uuid AND i.id = $2::uuid", &.{
        .{ .text = web.tenant_id },
        .{ .text = id },
    });
    defer freeRows(allocator, rows);
    if (rows.len == 0) return util.problem(request, allocator, .not_found, "Incident not found.");
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try appendIncident(&out, allocator, rows[0].cols);
    _ = out.pop();

    // Alerts in time order: the incident timeline.
    const alerts = try conn.exec(allocator,
        \\SELECT a.id::text, a.title, a.severity, a.status, ia.occurred_at::text, ia.reason,
        \\       array_to_json(ia.keys)::text, a.agent_id::text, ag.hostname, r.name,
        \\       array_to_json(r.mitre_techniques)::text, te.event_type, te.payload::text
        \\FROM incident_alerts ia
        \\JOIN alerts a ON a.id = ia.alert_id
        \\JOIN alert_rules r ON r.id = a.alert_rule_id
        \\JOIN agents ag ON ag.id = a.agent_id
        \\LEFT JOIN telemetry_events te ON te.id = a.telemetry_event_id AND te.received_at = a.telemetry_received_at
        \\WHERE ia.tenant_id = $1::uuid AND ia.incident_id = $2::uuid
        \\ORDER BY ia.occurred_at, a.id
        \\LIMIT 500
    , &.{ .{ .text = web.tenant_id }, .{ .text = id } });
    defer freeRows(allocator, alerts);
    try out.appendSlice(allocator, ",\"alerts\":[");
    for (alerts, 0..) |row, i| {
        const c = row.cols;
        if (i > 0) try out.append(allocator, ',');
        try out.appendSlice(allocator, "{\"id\":");
        try out.appendSlice(allocator, c[0] orelse "0");
        const names = [_][]const u8{ "title", "severity", "status", "occurred_at", "reason" };
        for (names, 1..) |n, idx| {
            try out.appendSlice(allocator, ",\"");
            try out.appendSlice(allocator, n);
            try out.appendSlice(allocator, "\":");
            if (c[idx]) |v| try util.appendEscaped(&out, allocator, v) else try out.appendSlice(allocator, "null");
        }
        try out.appendSlice(allocator, ",\"keys\":");
        try out.appendSlice(allocator, c[6] orelse "[]");
        try out.appendSlice(allocator, ",\"agent_id\":");
        try util.appendEscaped(&out, allocator, c[7] orelse "");
        try out.appendSlice(allocator, ",\"hostname\":");
        try util.appendEscaped(&out, allocator, c[8] orelse "");
        try out.appendSlice(allocator, ",\"rule_name\":");
        try util.appendEscaped(&out, allocator, c[9] orelse "");
        try out.appendSlice(allocator, ",\"mitre_techniques\":");
        try out.appendSlice(allocator, c[10] orelse "[]");
        try out.appendSlice(allocator, ",\"event_type\":");
        if (c[11]) |v| try util.appendEscaped(&out, allocator, v) else try out.appendSlice(allocator, "null");
        try out.appendSlice(allocator, ",\"payload\":");
        try out.appendSlice(allocator, c[12] orelse "null");
        try out.append(allocator, '}');
    }
    try out.appendSlice(allocator, "]}");
    try util.respondJson(request, .ok, out.items);
}

pub fn assign(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    id: []const u8,
) !void {
    if (!csrfOk(request, web)) return util.respondJson(request, .forbidden, "{\"error\":\"csrf\"}");
    if (!isUuid(id)) return util.problem(request, allocator, .not_found, "Incident not found.");
    const body = try util.readBody(allocator, request, 4096);
    defer allocator.free(body);
    const Req = struct { owner_user_id: ?[]const u8 = null };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "owner_user_id must be a user id or null.");
    };
    defer parsed.deinit();
    const owner = parsed.value.owner_user_id;
    if (owner) |o| {
        if (!isUuid(o)) return util.problem(request, allocator, .bad_request, "owner_user_id must be a user id or null.");
        // Only someone who can triage may own an incident.
        const u = try conn.exec(allocator,
            \\SELECT 1 FROM users WHERE id = $1::uuid AND tenant_id = $2::uuid AND disabled_at IS NULL
            \\  AND role IN ('admin', 'analyst')
        , &.{ .{ .text = o }, .{ .text = web.tenant_id } });
        defer freeRows(allocator, u);
        if (u.len == 0) return util.problem(request, allocator, .bad_request, "Owner must be an active admin or analyst.");
    }
    const rows = try conn.exec(allocator,
        \\UPDATE incidents SET owner_user_id = $3::uuid, updated_at = now(),
        \\  status = CASE WHEN status = 'new' AND $3::uuid IS NOT NULL THEN 'investigating' ELSE status END
        \\WHERE tenant_id = $1::uuid AND id = $2::uuid RETURNING id::text
    , &.{ .{ .text = web.tenant_id }, .{ .text = id }, if (owner) |o| .{ .text = o } else .{ .null = {} } });
    defer freeRows(allocator, rows);
    if (rows.len == 0) return util.problem(request, allocator, .not_found, "Incident not found.");
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "incident.assign", id, null);
    try queueSoc(allocator, conn, web.tenant_id, id);
    return get(allocator, conn, request, web, id);
}

pub fn setStatus(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    id: []const u8,
) !void {
    if (!csrfOk(request, web)) return util.respondJson(request, .forbidden, "{\"error\":\"csrf\"}");
    if (!isUuid(id)) return util.problem(request, allocator, .not_found, "Incident not found.");
    const body = try util.readBody(allocator, request, 4096);
    defer allocator.free(body);
    const Req = struct { status: []const u8 };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "status must be new, investigating, resolved or false_positive.");
    };
    defer parsed.deinit();
    const st = parsed.value.status;
    if (!validStatus(st)) return util.problem(request, allocator, .bad_request, "status must be new, investigating, resolved or false_positive.");
    const rows = try conn.exec(allocator,
        \\UPDATE incidents SET status = $3, updated_at = now() WHERE tenant_id = $1::uuid AND id = $2::uuid RETURNING id::text
    , &.{ .{ .text = web.tenant_id }, .{ .text = id }, .{ .text = st } });
    defer freeRows(allocator, rows);
    if (rows.len == 0) return util.problem(request, allocator, .not_found, "Incident not found.");
    // Closing an incident resolves its open alerts too.
    if (std.mem.eql(u8, st, "resolved") or std.mem.eql(u8, st, "false_positive")) {
        try conn.execNoRows(
            \\UPDATE alerts SET status = 'resolved', resolved_at = now(), resolved_by_user_id = $3::uuid
            \\WHERE tenant_id = $1::uuid AND status IN ('open', 'acknowledged')
            \\  AND id IN (SELECT alert_id FROM incident_alerts WHERE incident_id = $2::uuid)
        , &.{ .{ .text = web.tenant_id }, .{ .text = id }, .{ .text = web.user_id } });
    }
    const meta = try std.fmt.allocPrint(allocator, "{{\"status\":\"{s}\"}}", .{st});
    defer allocator.free(meta);
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "incident.status", id, meta);
    try queueSoc(allocator, conn, web.tenant_id, id);
    return get(allocator, conn, request, web, id);
}

/// POST /api/alerts/{id}/acknowledge and /resolve.
pub fn setAlertStatus(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    id: []const u8,
    verb: []const u8,
) !void {
    if (!csrfOk(request, web)) return util.respondJson(request, .forbidden, "{\"error\":\"csrf\"}");
    _ = std.fmt.parseInt(i64, id, 10) catch return util.problem(request, allocator, .not_found, "Alert not found.");
    _ = util.readBody(allocator, request, 4096) catch {};
    const resolve = std.mem.eql(u8, verb, "resolve");
    const rows = if (resolve) try conn.exec(allocator,
        \\UPDATE alerts SET status = 'resolved', resolved_at = now(), resolved_by_user_id = $3::uuid
        \\WHERE tenant_id = $1::uuid AND id = $2::bigint RETURNING id::text, status
    , &.{ .{ .text = web.tenant_id }, .{ .text = id }, .{ .text = web.user_id } }) else try conn.exec(allocator,
        \\UPDATE alerts SET status = CASE WHEN status = 'resolved' THEN status ELSE 'acknowledged' END,
        \\  acknowledged_at = coalesce(acknowledged_at, now()), acknowledged_by_user_id = coalesce(acknowledged_by_user_id, $3::uuid)
        \\WHERE tenant_id = $1::uuid AND id = $2::bigint RETURNING id::text, status
    , &.{ .{ .text = web.tenant_id }, .{ .text = id }, .{ .text = web.user_id } });
    defer freeRows(allocator, rows);
    if (rows.len == 0) return util.problem(request, allocator, .not_found, "Alert not found.");
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, if (resolve) "alert.resolve" else "alert.acknowledge", id, null);
    const st = try util.escapeJson(allocator, rows[0].cols[1] orelse "");
    defer allocator.free(st);
    const json = try std.fmt.allocPrint(allocator, "{{\"id\":{s},\"status\":{s}}}", .{ rows[0].cols[0] orelse "0", st });
    defer allocator.free(json);
    try util.respondJson(request, .ok, json);
}

/// Status and owner changes go to Tawny-SOC like new alerts do.
fn queueSoc(allocator: std.mem.Allocator, conn: *pg.Conn, tenant_id: []const u8, incident_id: []const u8) !void {
    const payload = try std.fmt.allocPrint(allocator, "{{\"incident_id\":\"{s}\"}}", .{incident_id});
    defer allocator.free(payload);
    try conn.execNoRows(
        \\INSERT INTO work_queue (kind, tenant_id, payload)
        \\SELECT 'incident_sink', $1::uuid, $2::jsonb
        \\WHERE NOT EXISTS (
        \\  SELECT 1 FROM work_queue WHERE kind = 'incident_sink' AND payload->>'incident_id' = $3 AND locked_until IS NULL
        \\)
    , &.{ .{ .text = tenant_id }, .{ .text = payload }, .{ .text = incident_id } });
}

test "incident statuses are the four section 8 names" {
    try std.testing.expect(validStatus("new"));
    try std.testing.expect(validStatus("false_positive"));
    try std.testing.expect(!validStatus("closed"));
    try std.testing.expect(isUuid("00000000-0000-0000-0000-000000000001"));
    try std.testing.expect(!isUuid("1; DROP TABLE"));
}
