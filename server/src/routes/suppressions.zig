//! Suppression rules. List is newest first and includes the joined rule name and hostname.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");
const audit = @import("../http/audit.zig");

const rule_select =
    \\SELECT s.id::text, s.name, s.reason, s.scope, s.alert_rule_id::text, ar.name,
    \\       s.agent_id::text, ag.hostname, s.payload_path, s.operator, s.match_value,
    \\       s.is_enabled::text, s.expires_at::text, s.suppressed_count::text, s.last_suppressed_at::text,
    \\       s.created_at::text, s.updated_at::text
    \\FROM suppression_rules s
    \\LEFT JOIN alert_rules ar ON ar.id = s.alert_rule_id
    \\LEFT JOIN agents ag ON ag.id = s.agent_id
;

pub fn list(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    const rows = try conn.exec(allocator, rule_select ++ " WHERE s.tenant_id = $1::uuid ORDER BY s.created_at DESC", &.{.{ .text = web.tenant_id }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.append(allocator, '[');
    for (rows, 0..) |row, i| {
        if (i > 0) try out.append(allocator, ',');
        const item = try ruleJson(allocator, row.cols);
        defer allocator.free(item);
        try out.appendSlice(allocator, item);
    }
    try out.append(allocator, ']');
    try util.respondJson(request, .ok, out.items);
}

pub fn create(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    if (!csrfOk(request, web)) {
        try util.respondJson(request, .forbidden, "{\"error\":\"csrf\"}");
        return;
    }
    const body = try util.readBody(allocator, request, 64 * 1024);
    defer allocator.free(body);
    const fields = parseFields(allocator, body) catch {
        return util.problem(request, allocator, .bad_request, "Invalid suppression body.");
    };
    defer fields.deinit();
    if (try reject(request, allocator, fields.value)) return;
    var id_buf: [36]u8 = undefined;
    const id = util.newUuid(io, &id_buf);
    try write(io, conn, web, id, fields.value, true);
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "suppression_rule.create", id, null);
    try respondOne(allocator, conn, request, id, .created);
}

pub fn update(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    id: []const u8,
) !void {
    if (!csrfOk(request, web)) {
        try util.respondJson(request, .forbidden, "{\"error\":\"csrf\"}");
        return;
    }
    const body = try util.readBody(allocator, request, 64 * 1024);
    defer allocator.free(body);
    const fields = parseFields(allocator, body) catch {
        return util.problem(request, allocator, .bad_request, "Invalid suppression body.");
    };
    defer fields.deinit();
    if (try reject(request, allocator, fields.value)) return;
    const existing = try conn.exec(allocator, "SELECT 1 FROM suppression_rules WHERE id = $1::uuid AND tenant_id = $2::uuid", &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
    });
    defer {
        for (existing) |row| row.deinit(allocator);
        allocator.free(existing);
    }
    if (existing.len == 0) {
        try util.respondJson(request, .not_found, "{\"error\":\"not_found\"}");
        return;
    }
    try write(io, conn, web, id, fields.value, false);
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "suppression_rule.update", id, null);
    try respondOne(allocator, conn, request, id, .ok);
}

pub fn delete(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    id: []const u8,
) !void {
    if (!csrfOk(request, web)) {
        try util.respondJson(request, .forbidden, "{\"error\":\"csrf\"}");
        return;
    }
    _ = util.readBody(allocator, request, 1024) catch {};
    const rows = try conn.exec(allocator, "DELETE FROM suppression_rules WHERE id = $1::uuid AND tenant_id = $2::uuid RETURNING id::text", &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
    });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) {
        try util.respondJson(request, .not_found, "{\"error\":\"not_found\"}");
        return;
    }
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "suppression_rule.delete", id, null);
    try request.respond("", .{ .status = .no_content, .keep_alive = false });
}

const Fields = struct {
    name: []const u8,
    reason: ?[]const u8 = null,
    scope: []const u8,
    alert_rule_id: ?[]const u8 = null,
    agent_id: ?[]const u8 = null,
    payload_path: ?[]const u8 = null,
    operator: []const u8,
    match_value: ?[]const u8 = null,
    is_enabled: ?bool = null,
    expires_at: ?[]const u8 = null,
};

fn parseFields(allocator: std.mem.Allocator, body: []const u8) !std.json.Parsed(Fields) {
    return std.json.parseFromSlice(Fields, allocator, body, .{ .ignore_unknown_fields = true });
}

fn write(
    io: std.Io,
    conn: *pg.Conn,
    web: auth.WebUser,
    id: []const u8,
    fields: Fields,
    insert: bool,
) !void {
    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&tbuf, now);
    const name = std.mem.trim(u8, fields.name, " \t\r\n");
    const reason = blankToNull(fields.reason);
    const path = blankToNull(fields.payload_path);
    const match_value = blankToNull(fields.match_value);
    const rule_id = if (std.mem.eql(u8, fields.scope, "specific_rule")) fields.alert_rule_id else null;
    const enabled = if (fields.is_enabled orelse true) "true" else "false";
    const expires = blankToNull(fields.expires_at);
    if (insert) {
        try conn.execNoRows(
            \\INSERT INTO suppression_rules (
            \\  id, tenant_id, name, reason, scope, alert_rule_id, agent_id, payload_path, operator, match_value,
            \\  is_enabled, created_by_user_id, created_at, updated_at, expires_at)
            \\VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::uuid, $7::uuid, $8, $9, $10, $11::boolean, $12::uuid, $13::timestamptz, $13::timestamptz, $14::timestamptz)
        , &.{
            .{ .text = id },
            .{ .text = web.tenant_id },
            .{ .text = name },
            if (reason) |v| .{ .text = std.mem.trim(u8, v, " \t\r\n") } else .{ .null = {} },
            .{ .text = fields.scope },
            if (rule_id) |v| .{ .text = v } else .{ .null = {} },
            if (blankToNull(fields.agent_id)) |v| .{ .text = v } else .{ .null = {} },
            if (path) |v| .{ .text = std.mem.trim(u8, v, " \t\r\n") } else .{ .null = {} },
            .{ .text = fields.operator },
            if (match_value) |v| .{ .text = std.mem.trim(u8, v, " \t\r\n") } else .{ .null = {} },
            .{ .text = enabled },
            .{ .text = web.user_id },
            .{ .text = now_s },
            if (expires) |v| .{ .text = v } else .{ .null = {} },
        });
        return;
    }
    try conn.execNoRows(
        \\UPDATE suppression_rules SET name = $3, reason = $4, scope = $5, alert_rule_id = $6::uuid,
        \\  agent_id = $7::uuid, payload_path = $8, operator = $9, match_value = $10,
        \\  is_enabled = $11::boolean, expires_at = $12::timestamptz, updated_at = $13::timestamptz
        \\WHERE id = $1::uuid AND tenant_id = $2::uuid
    , &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
        .{ .text = name },
        if (reason) |v| .{ .text = std.mem.trim(u8, v, " \t\r\n") } else .{ .null = {} },
        .{ .text = fields.scope },
        if (rule_id) |v| .{ .text = v } else .{ .null = {} },
        if (blankToNull(fields.agent_id)) |v| .{ .text = v } else .{ .null = {} },
        if (path) |v| .{ .text = std.mem.trim(u8, v, " \t\r\n") } else .{ .null = {} },
        .{ .text = fields.operator },
        if (match_value) |v| .{ .text = std.mem.trim(u8, v, " \t\r\n") } else .{ .null = {} },
        .{ .text = enabled },
        if (expires) |v| .{ .text = v } else .{ .null = {} },
        .{ .text = now_s },
    });
}

fn respondOne(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    id: []const u8,
    status: std.http.Status,
) !void {
    const rows = try conn.exec(allocator, rule_select ++ " WHERE s.id = $1::uuid", &.{.{ .text = id }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) {
        try util.respondJson(request, .not_found, "{\"error\":\"not_found\"}");
        return;
    }
    const json = try ruleJson(allocator, rows[0].cols);
    defer allocator.free(json);
    try util.respondJson(request, status, json);
}

fn reject(request: *std.http.Server.Request, allocator: std.mem.Allocator, fields: Fields) !bool {
    const name = std.mem.trim(u8, fields.name, " \t\r\n");
    if (name.len == 0 or name.len > 160) {
        try util.problem(request, allocator, .bad_request, "name is required and must be 160 characters or fewer.");
        return true;
    }
    if (!std.mem.eql(u8, fields.scope, "all_rules") and !std.mem.eql(u8, fields.scope, "specific_rule")) {
        try util.problem(request, allocator, .bad_request, "scope must be all_rules or specific_rule.");
        return true;
    }
    if (std.mem.eql(u8, fields.scope, "specific_rule") and blankToNull(fields.alert_rule_id) == null) {
        try util.problem(request, allocator, .bad_request, "alert_rule_id is required when scope is specific_rule.");
        return true;
    }
    if (!knownOperator(fields.operator)) {
        try util.problem(request, allocator, .bad_request, "operator is invalid.");
        return true;
    }
    if (!std.mem.eql(u8, fields.operator, "exists") and blankToNull(fields.match_value) == null) {
        try util.problem(request, allocator, .bad_request, "match_value is required unless the operator is exists.");
        return true;
    }
    return false;
}

fn knownOperator(value: []const u8) bool {
    return std.mem.eql(u8, value, "exists") or std.mem.eql(u8, value, "equals") or std.mem.eql(u8, value, "contains") or std.mem.eql(u8, value, "greater_than") or std.mem.eql(u8, value, "less_than");
}

fn csrfOk(request: *std.http.Server.Request, web: auth.WebUser) bool {
    return web.session_id == null or auth.checkCsrf(request, web);
}

fn blankToNull(value: ?[]const u8) ?[]const u8 {
    const text = value orelse return null;
    if (std.mem.trim(u8, text, " \t\r\n").len == 0) return null;
    return text;
}

fn ruleJson(allocator: std.mem.Allocator, cols: []const ?[]u8) ![]u8 {
    const id = try util.escapeJson(allocator, cols[0] orelse "");
    defer allocator.free(id);
    const name = try util.escapeJson(allocator, cols[1] orelse "");
    defer allocator.free(name);
    const reason = try util.nullOrJsonString(allocator, cols[2]);
    defer allocator.free(reason);
    const scope = try util.escapeJson(allocator, cols[3] orelse "");
    defer allocator.free(scope);
    const rule_id = try util.nullOrJsonString(allocator, cols[4]);
    defer allocator.free(rule_id);
    const rule_name = try util.nullOrJsonString(allocator, cols[5]);
    defer allocator.free(rule_name);
    const agent_id = try util.nullOrJsonString(allocator, cols[6]);
    defer allocator.free(agent_id);
    const hostname = try util.nullOrJsonString(allocator, cols[7]);
    defer allocator.free(hostname);
    const path = try util.nullOrJsonString(allocator, cols[8]);
    defer allocator.free(path);
    const operator = try util.escapeJson(allocator, cols[9] orelse "");
    defer allocator.free(operator);
    const match_value = try util.nullOrJsonString(allocator, cols[10]);
    defer allocator.free(match_value);
    const expires = try util.nullOrJsonString(allocator, cols[12]);
    defer allocator.free(expires);
    const last = try util.nullOrJsonString(allocator, cols[14]);
    defer allocator.free(last);
    const created = try util.escapeJson(allocator, cols[15] orelse "");
    defer allocator.free(created);
    const updated = try util.escapeJson(allocator, cols[16] orelse "");
    defer allocator.free(updated);
    return std.fmt.allocPrint(allocator,
        \\{{"id":{s},"name":{s},"reason":{s},"scope":{s},"alert_rule_id":{s},"alert_rule_name":{s},"agent_id":{s},"agent_hostname":{s},"payload_path":{s},"operator":{s},"match_value":{s},"is_enabled":{s},"expires_at":{s},"suppressed_count":{s},"last_suppressed_at":{s},"created_at":{s},"updated_at":{s}}}
    , .{
        id,
        name,
        reason,
        scope,
        rule_id,
        rule_name,
        agent_id,
        hostname,
        path,
        operator,
        match_value,
        jsonBool(cols[11]),
        expires,
        cols[13] orelse "0",
        last,
        created,
        updated,
    });
}

fn jsonBool(value: ?[]const u8) []const u8 {
    const text = value orelse return "false";
    if (std.mem.eql(u8, text, "t") or std.mem.eql(u8, text, "true")) return "true";
    return "false";
}
