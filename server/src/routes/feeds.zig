//! Threat-intel feed CRUD. Secrets are stored with the v1. box and never returned.
//! Run clears last_run_at and then executes the same job as the scheduler, which
//! also walks every other feed that is due.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");
const audit = @import("../http/audit.zig");
const secrets = @import("../crypto/secret_box.zig");
const threat_intel = @import("../jobs/threat_intel.zig");

const feed_select =
    \\SELECT id::text, name, kind, url, auth_header_name, default_severity,
    \\       interval_minutes::text, is_enabled::text, status,
    \\       last_run_at::text, last_success_at::text,
    \\       last_imported_count::text, last_skipped_count::text, last_error,
    \\       created_at::text, updated_at::text
    \\FROM threat_intel_feeds
;

pub fn list(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    const rows = try conn.exec(allocator, feed_select ++ " WHERE tenant_id = $1::uuid ORDER BY name", &.{.{ .text = web.tenant_id }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.append(allocator, '[');
    for (rows, 0..) |row, i| {
        if (i > 0) try out.append(allocator, ',');
        const item = try feedJson(allocator, row.cols);
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
    const Req = struct {
        name: []const u8,
        kind: []const u8,
        url: []const u8,
        auth_header_name: ?[]const u8 = null,
        auth_header_value: ?[]const u8 = null,
        default_severity: ?[]const u8 = null,
        interval_minutes: ?i32 = null,
        is_enabled: ?bool = null,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "Invalid feed body.");
    };
    defer parsed.deinit();
    const name = std.mem.trim(u8, parsed.value.name, " \t\r\n");
    const url = std.mem.trim(u8, parsed.value.url, " \t\r\n");
    const interval = parsed.value.interval_minutes orelse 60;
    if (try rejectFeed(request, allocator, name, url, parsed.value.kind, interval)) return;
    const severity = parsed.value.default_severity orelse "high";
    if (!knownSeverity(severity)) return util.problem(request, allocator, .bad_request, "default_severity is invalid.");
    const header_value = blankToNull(parsed.value.auth_header_value);
    const encrypted = try protectHeader(allocator, io, header_value);
    defer if (encrypted) |value| allocator.free(value);
    if (header_value != null and encrypted == null) {
        return util.problem(request, allocator, .bad_request, "Integration encryption key is not configured.");
    }

    var id_buf: [36]u8 = undefined;
    const id = util.newUuid(io, &id_buf);
    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&tbuf, now);
    var interval_buf: [16]u8 = undefined;
    const interval_s = std.fmt.bufPrint(&interval_buf, "{d}", .{interval}) catch "60";
    try conn.execNoRows(
        \\INSERT INTO threat_intel_feeds (
        \\  id, tenant_id, name, kind, url, auth_header_name, auth_header_value_encrypted,
        \\  default_severity, is_enabled, interval_minutes, status, created_by_user_id, created_at, updated_at)
        \\VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9::boolean, $10::int, 'never_run', $11::uuid, $12::timestamptz, $12::timestamptz)
    , &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
        .{ .text = name },
        .{ .text = parsed.value.kind },
        .{ .text = url },
        if (blankToNull(parsed.value.auth_header_name)) |n| .{ .text = std.mem.trim(u8, n, " \t\r\n") } else .{ .null = {} },
        if (encrypted) |value| .{ .text = value } else .{ .null = {} },
        .{ .text = severity },
        .{ .text = if (parsed.value.is_enabled orelse true) "true" else "false" },
        .{ .text = interval_s },
        .{ .text = web.user_id },
        .{ .text = now_s },
    });
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "threat_intel_feed.create", id, null);
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
    const Req = struct {
        name: []const u8,
        kind: []const u8,
        url: []const u8,
        auth_header_name: ?[]const u8 = null,
        auth_header_value: ?[]const u8 = null,
        default_severity: []const u8,
        interval_minutes: i32,
        is_enabled: bool,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "Invalid feed body.");
    };
    defer parsed.deinit();
    const name = std.mem.trim(u8, parsed.value.name, " \t\r\n");
    const url = std.mem.trim(u8, parsed.value.url, " \t\r\n");
    if (try rejectFeed(request, allocator, name, url, parsed.value.kind, parsed.value.interval_minutes)) return;
    if (!knownSeverity(parsed.value.default_severity)) return util.problem(request, allocator, .bad_request, "default_severity is invalid.");
    const header_value = blankToNull(parsed.value.auth_header_value);
    const encrypted = try protectHeader(allocator, io, header_value);
    defer if (encrypted) |value| allocator.free(value);
    if (header_value != null and encrypted == null) {
        return util.problem(request, allocator, .bad_request, "Integration encryption key is not configured.");
    }
    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&tbuf, now);
    var interval_buf: [16]u8 = undefined;
    const interval_s = std.fmt.bufPrint(&interval_buf, "{d}", .{parsed.value.interval_minutes}) catch "60";
    const sql = if (encrypted != null)
        \\UPDATE threat_intel_feeds SET name = $3, kind = $4, url = $5, auth_header_name = $6,
        \\  auth_header_value_encrypted = $7, default_severity = $8, interval_minutes = $9::int,
        \\  is_enabled = $10::boolean, updated_at = $11::timestamptz
        \\WHERE id = $1::uuid AND tenant_id = $2::uuid RETURNING id::text
    else
        \\UPDATE threat_intel_feeds SET name = $3, kind = $4, url = $5, auth_header_name = $6,
        \\  default_severity = $8, interval_minutes = $9::int,
        \\  is_enabled = $10::boolean, updated_at = $11::timestamptz
        \\WHERE id = $1::uuid AND tenant_id = $2::uuid RETURNING id::text
    ;
    const rows = try conn.exec(allocator, sql, &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
        .{ .text = name },
        .{ .text = parsed.value.kind },
        .{ .text = url },
        if (blankToNull(parsed.value.auth_header_name)) |n| .{ .text = std.mem.trim(u8, n, " \t\r\n") } else .{ .null = {} },
        if (encrypted) |value| .{ .text = value } else .{ .null = {} },
        .{ .text = parsed.value.default_severity },
        .{ .text = interval_s },
        .{ .text = if (parsed.value.is_enabled) "true" else "false" },
        .{ .text = now_s },
    });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) {
        try util.respondJson(request, .not_found, "{\"error\":\"not_found\"}");
        return;
    }
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "threat_intel_feed.update", id, null);
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
    const rows = try conn.exec(allocator, "DELETE FROM threat_intel_feeds WHERE id = $1::uuid AND tenant_id = $2::uuid RETURNING id::text", &.{
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
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "threat_intel_feed.delete", id, null);
    try request.respond("", .{ .status = .no_content, .keep_alive = false });
}

pub fn run(
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
    const cleared = try conn.exec(allocator,
        \\UPDATE threat_intel_feeds SET last_run_at = NULL
        \\WHERE id = $1::uuid AND tenant_id = $2::uuid RETURNING id::text
    , &.{ .{ .text = id }, .{ .text = web.tenant_id } });
    defer {
        for (cleared) |row| row.deinit(allocator);
        allocator.free(cleared);
    }
    if (cleared.len == 0) {
        try util.respondJson(request, .not_found, "{\"error\":\"not_found\"}");
        return;
    }
    _ = try threat_intel.run(allocator, io, conn, .{
        .now_unix = util.nowUnix(io),
        .allow_private = envFlag("TAWNY_ALLOW_PRIVATE_EGRESS"),
        .secret = envSpan("TAWNY_INTEGRATION_ENCRYPTION_KEY"),
    });
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "threat_intel_feed.run", id, null);
    try respondOne(allocator, conn, request, id, .ok);
}

fn respondOne(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    id: []const u8,
    status: std.http.Status,
) !void {
    const rows = try conn.exec(allocator, feed_select ++ " WHERE id = $1::uuid", &.{.{ .text = id }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) {
        try util.respondJson(request, .not_found, "{\"error\":\"not_found\"}");
        return;
    }
    const json = try feedJson(allocator, rows[0].cols);
    defer allocator.free(json);
    try util.respondJson(request, status, json);
}

fn protectHeader(allocator: std.mem.Allocator, io: std.Io, value: ?[]const u8) !?[]u8 {
    const plaintext = value orelse return null;
    const secret = envSpan("TAWNY_INTEGRATION_ENCRYPTION_KEY");
    if (secret.len == 0) return null;
    return try secrets.protect(allocator, secret, plaintext, io);
}

fn rejectFeed(
    request: *std.http.Server.Request,
    allocator: std.mem.Allocator,
    name: []const u8,
    url: []const u8,
    kind: []const u8,
    interval: i32,
) !bool {
    if (name.len == 0 or name.len > 160) {
        try util.problem(request, allocator, .bad_request, "name is required and must be 160 characters or fewer.");
        return true;
    }
    if (!absoluteHttp(url)) {
        try util.problem(request, allocator, .bad_request, "url must be an absolute URL.");
        return true;
    }
    if (!knownKind(kind)) {
        try util.problem(request, allocator, .bad_request, "kind is not supported.");
        return true;
    }
    if (interval < 5 or interval > 10080) {
        try util.problem(request, allocator, .bad_request, "interval_minutes must be between 5 and 10080.");
        return true;
    }
    return false;
}

fn knownKind(kind: []const u8) bool {
    const names = [_][]const u8{
        "urlhaus_csv", "urlhaus_json", "otx_pulse", "misp_events", "taxii21",
        "generic_csv", "osv",              "osv_vulnerabilities",
    };
    for (names) |name| if (std.mem.eql(u8, kind, name)) return true;
    return false;
}

fn knownSeverity(value: []const u8) bool {
    return std.mem.eql(u8, value, "low") or std.mem.eql(u8, value, "medium") or std.mem.eql(u8, value, "high") or std.mem.eql(u8, value, "critical");
}

fn absoluteHttp(url: []const u8) bool {
    const rest = if (std.mem.startsWith(u8, url, "https://"))
        url["https://".len..]
    else if (std.mem.startsWith(u8, url, "http://"))
        url["http://".len..]
    else
        return false;
    if (rest.len == 0 or rest[0] == '/' or rest[0] == ':') return false;
    return std.mem.indexOfScalar(u8, rest, ' ') == null;
}

fn csrfOk(request: *std.http.Server.Request, web: auth.WebUser) bool {
    return web.session_id == null or auth.checkCsrf(request, web);
}

fn blankToNull(value: ?[]const u8) ?[]const u8 {
    const text = value orelse return null;
    if (std.mem.trim(u8, text, " \t\r\n").len == 0) return null;
    return text;
}

fn envSpan(key: [*:0]const u8) []const u8 {
    const raw = std.c.getenv(key) orelse return "";
    return std.mem.span(raw);
}

fn envFlag(key: [*:0]const u8) bool {
    const value = envSpan(key);
    return std.mem.eql(u8, value, "1") or std.ascii.eqlIgnoreCase(value, "true");
}

fn feedJson(allocator: std.mem.Allocator, cols: []const ?[]u8) ![]u8 {
    const id = try util.escapeJson(allocator, cols[0] orelse "");
    defer allocator.free(id);
    const name = try util.escapeJson(allocator, cols[1] orelse "");
    defer allocator.free(name);
    const kind = try util.escapeJson(allocator, cols[2] orelse "");
    defer allocator.free(kind);
    const url = try util.escapeJson(allocator, cols[3] orelse "");
    defer allocator.free(url);
    const header = try util.nullOrJsonString(allocator, cols[4]);
    defer allocator.free(header);
    const severity = try util.escapeJson(allocator, cols[5] orelse "high");
    defer allocator.free(severity);
    const status = try util.escapeJson(allocator, cols[8] orelse "never_run");
    defer allocator.free(status);
    const last_run = try util.nullOrJsonString(allocator, cols[9]);
    defer allocator.free(last_run);
    const last_ok = try util.nullOrJsonString(allocator, cols[10]);
    defer allocator.free(last_ok);
    const last_error = try util.nullOrJsonString(allocator, cols[13]);
    defer allocator.free(last_error);
    const created = try util.escapeJson(allocator, cols[14] orelse "");
    defer allocator.free(created);
    const updated = try util.escapeJson(allocator, cols[15] orelse "");
    defer allocator.free(updated);
    return std.fmt.allocPrint(allocator,
        \\{{"id":{s},"name":{s},"kind":{s},"url":{s},"auth_header_name":{s},"default_severity":{s},"interval_minutes":{s},"is_enabled":{s},"status":{s},"last_run_at":{s},"last_success_at":{s},"last_imported_count":{s},"last_skipped_count":{s},"last_error":{s},"created_at":{s},"updated_at":{s}}}
    , .{
        id,
        name,
        kind,
        url,
        header,
        severity,
        cols[6] orelse "60",
        jsonBool(cols[7]),
        status,
        last_run,
        last_ok,
        cols[11] orelse "0",
        cols[12] orelse "0",
        last_error,
        created,
        updated,
    });
}

fn jsonBool(value: ?[]const u8) []const u8 {
    const text = value orelse return "false";
    if (std.mem.eql(u8, text, "t") or std.mem.eql(u8, text, "true")) return "true";
    return "false";
}
