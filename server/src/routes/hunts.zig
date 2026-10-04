//! Saved hunts and ad-hoc runs. Same paths and problem titles as HuntsController.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");
const audit = @import("../http/audit.zig");
const query = @import("../hunts/query.zig");

const hunt_select =
    \\SELECT id::text, name, description, query, is_scheduled::text, schedule_cron,
    \\       alert_on_match::text, alert_severity, mitre_techniques::text, is_shared::text,
    \\       created_by_user_id::text, last_run_at::text, last_match_count::text,
    \\       created_at::text, updated_at::text
    \\FROM saved_hunts
;

pub fn list(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    const rows = try conn.exec(allocator, hunt_select ++
        \\ WHERE tenant_id = $1::uuid
        \\   AND (is_shared OR ($2::uuid IS NOT NULL AND created_by_user_id = $2::uuid))
        \\ ORDER BY name
    , &.{
        .{ .text = web.tenant_id },
        .{ .text = web.user_id },
    });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    const json = try rowsJson(allocator, rows);
    defer allocator.free(json);
    try util.respondJson(request, .ok, json);
}

pub fn get(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    id: []const u8,
) !void {
    const rows = try conn.exec(allocator, hunt_select ++ " WHERE id = $1::uuid AND tenant_id = $2::uuid", &.{
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
    const json = try huntJson(allocator, rows[0].cols);
    defer allocator.free(json);
    try util.respondJson(request, .ok, json);
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
        description: ?[]const u8 = null,
        query: []const u8,
        is_scheduled: ?bool = null,
        schedule_cron: ?[]const u8 = null,
        alert_on_match: ?bool = null,
        alert_severity: ?[]const u8 = null,
        mitre_techniques: ?[]const []const u8 = null,
        is_shared: ?bool = null,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "Invalid hunt body.");
    };
    defer parsed.deinit();
    const name = std.mem.trim(u8, parsed.value.name, " \t\r\n");
    const source = std.mem.trim(u8, parsed.value.query, " \t\r\n");
    if (try rejectHunt(request, allocator, name, source, parsed.value.schedule_cron)) return;
    const severity = parsed.value.alert_severity orelse "medium";
    if (!knownSeverity(severity)) return util.problem(request, allocator, .bad_request, "alert_severity is invalid.");
    if (!(try queryParses(allocator, io, source, null))) {
        return util.problem(request, allocator, .bad_request, "Saved hunt query did not parse.");
    }
    const dup = try conn.exec(allocator, "SELECT 1 FROM saved_hunts WHERE tenant_id = $1::uuid AND name = $2 LIMIT 1", &.{
        .{ .text = web.tenant_id },
        .{ .text = name },
    });
    defer {
        for (dup) |row| row.deinit(allocator);
        allocator.free(dup);
    }
    if (dup.len > 0) return util.problem(request, allocator, .conflict, "A saved hunt with this name already exists.");

    var id_buf: [36]u8 = undefined;
    const id = util.newUuid(io, &id_buf);
    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&tbuf, now);
    const mitre = try mitreArray(allocator, parsed.value.mitre_techniques orelse &.{});
    defer allocator.free(mitre);
    const description = blankToNull(parsed.value.description);
    const cron = blankToNull(parsed.value.schedule_cron);
    try conn.execNoRows(
        \\INSERT INTO saved_hunts (
        \\  id, tenant_id, name, description, query, created_by_user_id,
        \\  is_scheduled, schedule_cron, alert_on_match, alert_severity,
        \\  mitre_techniques, is_shared, created_at, updated_at)
        \\VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::uuid, $7::boolean, $8, $9::boolean, $10, $11::text[], $12::boolean, $13::timestamptz, $13::timestamptz)
    , &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
        .{ .text = name },
        if (description) |d| .{ .text = d } else .{ .null = {} },
        .{ .text = source },
        .{ .text = web.user_id },
        .{ .text = if (parsed.value.is_scheduled orelse false) "true" else "false" },
        if (cron) |c| .{ .text = std.mem.trim(u8, c, " \t\r\n") } else .{ .null = {} },
        .{ .text = if (parsed.value.alert_on_match orelse false) "true" else "false" },
        .{ .text = severity },
        .{ .text = mitre },
        .{ .text = if (parsed.value.is_shared orelse true) "true" else "false" },
        .{ .text = now_s },
    });
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "saved_hunt.create", id, null);
    const rows = try conn.exec(allocator, hunt_select ++ " WHERE id = $1::uuid", &.{.{ .text = id }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    const json = try huntJson(allocator, rows[0].cols);
    defer allocator.free(json);
    try util.respondJson(request, .created, json);
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
        description: ?[]const u8 = null,
        query: []const u8,
        is_scheduled: ?bool = null,
        schedule_cron: ?[]const u8 = null,
        alert_on_match: ?bool = null,
        alert_severity: ?[]const u8 = null,
        mitre_techniques: ?[]const []const u8 = null,
        is_shared: ?bool = null,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "Invalid hunt body.");
    };
    defer parsed.deinit();
    const name = std.mem.trim(u8, parsed.value.name, " \t\r\n");
    const source = std.mem.trim(u8, parsed.value.query, " \t\r\n");
    if (try rejectHunt(request, allocator, name, source, parsed.value.schedule_cron)) return;
    const severity = parsed.value.alert_severity orelse "medium";
    if (!knownSeverity(severity)) return util.problem(request, allocator, .bad_request, "alert_severity is invalid.");
    if (!(try queryParses(allocator, io, source, null))) {
        return util.problem(request, allocator, .bad_request, "Saved hunt query did not parse.");
    }
    const mitre = try mitreArray(allocator, parsed.value.mitre_techniques orelse &.{});
    defer allocator.free(mitre);
    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&tbuf, now);
    const description = blankToNull(parsed.value.description);
    const cron = blankToNull(parsed.value.schedule_cron);
    const rows = try conn.exec(allocator,
        \\UPDATE saved_hunts SET name = $3, description = $4, query = $5,
        \\  is_scheduled = $6::boolean, schedule_cron = $7, alert_on_match = $8::boolean,
        \\  alert_severity = $9, mitre_techniques = $10::text[],
        \\  is_shared = COALESCE($11::boolean, is_shared), updated_at = $12::timestamptz
        \\WHERE id = $1::uuid AND tenant_id = $2::uuid
        \\RETURNING id::text
    , &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
        .{ .text = name },
        if (description) |d| .{ .text = d } else .{ .null = {} },
        .{ .text = source },
        .{ .text = if (parsed.value.is_scheduled orelse false) "true" else "false" },
        if (cron) |c| .{ .text = std.mem.trim(u8, c, " \t\r\n") } else .{ .null = {} },
        .{ .text = if (parsed.value.alert_on_match orelse false) "true" else "false" },
        .{ .text = severity },
        .{ .text = mitre },
        if (parsed.value.is_shared) |flag| .{ .text = if (flag) "true" else "false" } else .{ .null = {} },
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
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "saved_hunt.update", id, null);
    const loaded = try conn.exec(allocator, hunt_select ++ " WHERE id = $1::uuid", &.{.{ .text = id }});
    defer {
        for (loaded) |row| row.deinit(allocator);
        allocator.free(loaded);
    }
    const json = try huntJson(allocator, loaded[0].cols);
    defer allocator.free(json);
    try util.respondJson(request, .ok, json);
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
    const rows = try conn.exec(allocator, "DELETE FROM saved_hunts WHERE id = $1::uuid AND tenant_id = $2::uuid RETURNING id::text", &.{
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
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "saved_hunt.delete", id, null);
    try request.respond("", .{ .status = .no_content, .keep_alive = false });
}

pub fn runAdHoc(
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
    const Req = struct { query: []const u8, limit: ?u32 = null };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "Could not parse hunt query.");
    };
    defer parsed.deinit();
    respondRun(allocator, io, conn, request, web, std.mem.trim(u8, parsed.value.query, " \t\r\n"), parsed.value.limit, null) catch |err| {
        if (err == error.BadQuery) return util.problem(request, allocator, .bad_request, "Could not parse hunt query.");
        return err;
    };
}

pub fn runSaved(
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
    const found = try conn.exec(allocator, "SELECT query FROM saved_hunts WHERE id = $1::uuid AND tenant_id = $2::uuid", &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
    });
    defer {
        for (found) |row| row.deinit(allocator);
        allocator.free(found);
    }
    if (found.len == 0) {
        try util.respondJson(request, .not_found, "{\"error\":\"not_found\"}");
        return;
    }
    const source = found[0].cols[0] orelse "";
    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&tbuf, now);
    try conn.execNoRows(
        \\INSERT INTO hunt_runs (tenant_id, saved_hunt_id, triggered_by_user_id, status, started_at)
        \\VALUES ($1::uuid, $2::uuid, $3::uuid, 'running', $4::timestamptz)
    , &.{
        .{ .text = web.tenant_id },
        .{ .text = id },
        .{ .text = web.user_id },
        .{ .text = now_s },
    });
    respondRun(allocator, io, conn, request, web, source, null, id) catch |err| {
        const done = util.nowUnix(io);
        var dbuf: [32]u8 = undefined;
        const done_s = util.formatRfc3339(&dbuf, done);
        conn.execNoRows(
            \\UPDATE hunt_runs SET status = 'failed', completed_at = $3::timestamptz, error_message = $4
            \\WHERE id = (
            \\  SELECT id FROM hunt_runs WHERE saved_hunt_id = $1::uuid AND tenant_id = $2::uuid
            \\  ORDER BY started_at DESC LIMIT 1)
        , &.{
            .{ .text = id },
            .{ .text = web.tenant_id },
            .{ .text = done_s },
            .{ .text = @errorName(err) },
        }) catch {};
        if (err == error.BadQuery) return util.problem(request, allocator, .bad_request, "Saved hunt query did not parse.");
        return util.problem(request, allocator, .internal_server_error, "Hunt execution failed.");
    };
}

pub fn runs(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    id: []const u8,
) !void {
    const hunt = try conn.exec(allocator, "SELECT 1 FROM saved_hunts WHERE id = $1::uuid AND tenant_id = $2::uuid", &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
    });
    defer {
        for (hunt) |row| row.deinit(allocator);
        allocator.free(hunt);
    }
    if (hunt.len == 0) {
        try util.respondJson(request, .not_found, "{\"error\":\"not_found\"}");
        return;
    }
    const rows = try conn.exec(allocator,
        \\SELECT id::text, saved_hunt_id::text, status, started_at::text, completed_at::text,
        \\       match_count::text, alerts_created::text, error_message
        \\FROM hunt_runs
        \\WHERE tenant_id = $1::uuid AND saved_hunt_id = $2::uuid
        \\ORDER BY started_at DESC LIMIT 50
    , &.{ .{ .text = web.tenant_id }, .{ .text = id } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.append(allocator, '[');
    for (rows, 0..) |row, i| {
        if (i > 0) try out.append(allocator, ',');
        const c = row.cols;
        const saved = try util.escapeJson(allocator, c[1] orelse "");
        defer allocator.free(saved);
        const status = try util.escapeJson(allocator, c[2] orelse "");
        defer allocator.free(status);
        const started = try util.escapeJson(allocator, c[3] orelse "");
        defer allocator.free(started);
        const completed = try util.nullOrJsonString(allocator, c[4]);
        defer allocator.free(completed);
        const err = try util.nullOrJsonString(allocator, c[7]);
        defer allocator.free(err);
        const item = try std.fmt.allocPrint(allocator,
            \\{{"id":{s},"saved_hunt_id":{s},"status":{s},"started_at":{s},"completed_at":{s},"match_count":{s},"alerts_created":{s},"error_message":{s}}}
        , .{
            c[0] orelse "0",
            saved,
            status,
            started,
            completed,
            c[5] orelse "0",
            c[6] orelse "0",
            err,
        });
        defer allocator.free(item);
        try out.appendSlice(allocator, item);
    }
    try out.append(allocator, ']');
    try util.respondJson(request, .ok, out.items);
}

fn respondRun(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    source: []const u8,
    limit: ?u32,
    saved_id: ?[]const u8,
) !void {
    var msg_buf: [512]u8 = undefined;
    var msg: []u8 = &msg_buf;
    var plan = query.parse(allocator, source, limit, util.nowUnix(io), &msg) catch |err| return err;
    defer plan.deinit();
    var result = try query.execute(allocator, conn, web.tenant_id, &plan, 0, util.nowUnix(io));
    defer result.deinit(allocator);
    if (saved_id) |id| {
        const now = util.nowUnix(io);
        var tbuf: [32]u8 = undefined;
        const now_s = util.formatRfc3339(&tbuf, now);
        var count_buf: [16]u8 = undefined;
        const count = std.fmt.bufPrint(&count_buf, "{d}", .{result.matches.len}) catch "0";
        try conn.execNoRows(
            \\UPDATE hunt_runs SET status = 'succeeded', completed_at = $3::timestamptz, match_count = $4::int
            \\WHERE id = (
            \\  SELECT id FROM hunt_runs WHERE saved_hunt_id = $1::uuid AND tenant_id = $2::uuid
            \\  ORDER BY started_at DESC LIMIT 1)
        , &.{ .{ .text = id }, .{ .text = web.tenant_id }, .{ .text = now_s }, .{ .text = count } });
        try conn.execNoRows(
            \\UPDATE saved_hunts SET last_run_at = $3::timestamptz, last_match_count = $4::int, updated_at = $3::timestamptz
            \\WHERE id = $1::uuid AND tenant_id = $2::uuid
        , &.{ .{ .text = id }, .{ .text = web.tenant_id }, .{ .text = now_s }, .{ .text = count } });
        try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "saved_hunt.run", id, null);
    }
    const json = try runJson(allocator, &result);
    defer allocator.free(json);
    try util.respondJson(request, .ok, json);
}

fn queryParses(allocator: std.mem.Allocator, io: std.Io, source: []const u8, limit: ?u32) !bool {
    var msg_buf: [512]u8 = undefined;
    var msg: []u8 = &msg_buf;
    var plan = query.parse(allocator, source, limit, util.nowUnix(io), &msg) catch return false;
    plan.deinit();
    return true;
}

fn rejectHunt(
    request: *std.http.Server.Request,
    allocator: std.mem.Allocator,
    name: []const u8,
    source: []const u8,
    cron: ?[]const u8,
) !bool {
    if (name.len == 0 or name.len > 160) {
        try util.problem(request, allocator, .bad_request, "name is required and must be 160 characters or fewer.");
        return true;
    }
    if (source.len == 0) {
        try util.problem(request, allocator, .bad_request, "query is required.");
        return true;
    }
    if (cron) |value| {
        if (std.mem.trim(u8, value, " \t\r\n").len > 64) {
            try util.problem(request, allocator, .bad_request, "schedule_cron must be 64 characters or fewer.");
            return true;
        }
    }
    return false;
}

fn knownSeverity(value: []const u8) bool {
    return std.mem.eql(u8, value, "low") or std.mem.eql(u8, value, "medium") or std.mem.eql(u8, value, "high") or std.mem.eql(u8, value, "critical");
}

fn csrfOk(request: *std.http.Server.Request, web: auth.WebUser) bool {
    return web.session_id == null or auth.checkCsrf(request, web);
}

fn blankToNull(value: ?[]const u8) ?[]const u8 {
    const text = value orelse return null;
    if (std.mem.trim(u8, text, " \t\r\n").len == 0) return null;
    return text;
}

fn mitreArray(allocator: std.mem.Allocator, items: []const []const u8) ![]u8 {
    var owned: std.ArrayList([]u8) = .empty;
    defer {
        for (owned.items) |item| allocator.free(item);
        owned.deinit(allocator);
    }
    for (items) |item| {
        const trimmed = std.mem.trim(u8, item, " \t\r\n");
        if (trimmed.len == 0) continue;
        var upper = try allocator.alloc(u8, trimmed.len);
        for (trimmed, 0..) |c, i| upper[i] = std.ascii.toUpper(c);
        var seen = false;
        for (owned.items) |prev| if (std.mem.eql(u8, prev, upper)) {
            seen = true;
        };
        if (seen) {
            allocator.free(upper);
            continue;
        }
        try owned.append(allocator, upper);
    }
    var views: std.ArrayList([]const u8) = .empty;
    defer views.deinit(allocator);
    for (owned.items) |item| try views.append(allocator, item);
    return util.pgArrayText(allocator, views.items);
}

fn rowsJson(allocator: std.mem.Allocator, rows: []const pg.Row) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, '[');
    for (rows, 0..) |row, i| {
        if (i > 0) try out.append(allocator, ',');
        const item = try huntJson(allocator, row.cols);
        defer allocator.free(item);
        try out.appendSlice(allocator, item);
    }
    try out.append(allocator, ']');
    return out.toOwnedSlice(allocator);
}

fn huntJson(allocator: std.mem.Allocator, cols: []const ?[]u8) ![]u8 {
    const id = try util.escapeJson(allocator, cols[0] orelse "");
    defer allocator.free(id);
    const name = try util.escapeJson(allocator, cols[1] orelse "");
    defer allocator.free(name);
    const description = try util.nullOrJsonString(allocator, cols[2]);
    defer allocator.free(description);
    const q = try util.escapeJson(allocator, cols[3] orelse "");
    defer allocator.free(q);
    const cron = try util.nullOrJsonString(allocator, cols[5]);
    defer allocator.free(cron);
    const severity = try util.escapeJson(allocator, cols[7] orelse "medium");
    defer allocator.free(severity);
    var mitre_json: []u8 = undefined;
    if (cols[8]) |raw| {
        const items = try util.parsePgTextArray(allocator, raw);
        defer {
            for (items) |it| allocator.free(it);
            allocator.free(items);
        }
        mitre_json = try util.jsonArrayStrings(allocator, items);
    } else mitre_json = try allocator.dupe(u8, "[]");
    defer allocator.free(mitre_json);
    const created_by = try util.nullOrJsonString(allocator, cols[10]);
    defer allocator.free(created_by);
    const last_run = try util.nullOrJsonString(allocator, cols[11]);
    defer allocator.free(last_run);
    const created = try util.escapeJson(allocator, cols[13] orelse "");
    defer allocator.free(created);
    const updated = try util.escapeJson(allocator, cols[14] orelse "");
    defer allocator.free(updated);
    return std.fmt.allocPrint(allocator,
        \\{{"id":{s},"name":{s},"description":{s},"query":{s},"is_scheduled":{s},"schedule_cron":{s},"alert_on_match":{s},"alert_severity":{s},"mitre_techniques":{s},"is_shared":{s},"created_by_user_id":{s},"last_run_at":{s},"last_match_count":{s},"created_at":{s},"updated_at":{s}}}
    , .{
        id,
        name,
        description,
        q,
        jsonBool(cols[4]),
        cron,
        jsonBool(cols[6]),
        severity,
        mitre_json,
        jsonBool(cols[9]),
        created_by,
        last_run,
        cols[12] orelse "null",
        created,
        updated,
    });
}

fn runJson(allocator: std.mem.Allocator, result: *const query.Result) ![]u8 {
    var matches: std.ArrayList(u8) = .empty;
    defer matches.deinit(allocator);
    try matches.append(allocator, '[');
    for (result.matches, 0..) |m, i| {
        if (i > 0) try matches.append(allocator, ',');
        const agent = try util.escapeJson(allocator, m.agent_id);
        defer allocator.free(agent);
        const host = try util.escapeJson(allocator, m.hostname);
        defer allocator.free(host);
        const et = try util.escapeJson(allocator, m.event_type);
        defer allocator.free(et);
        const occurred = try util.escapeJson(allocator, m.occurred_at);
        defer allocator.free(occurred);
        const received = try util.escapeJson(allocator, m.received_at);
        defer allocator.free(received);
        const event_id = if (digits(m.event_id)) m.event_id else try util.escapeJson(allocator, m.event_id);
        defer if (!digits(m.event_id)) allocator.free(event_id);
        const payload = if (m.payload.len > 0 and (m.payload[0] == '{' or m.payload[0] == '[')) m.payload else "null";
        const item = try std.fmt.allocPrint(allocator,
            \\{{"event_id":{s},"agent_id":{s},"hostname":{s},"event_type":{s},"occurred_at":{s},"received_at":{s},"payload":{s}}}
        , .{ event_id, agent, host, et, occurred, received, payload });
        defer allocator.free(item);
        try matches.appendSlice(allocator, item);
    }
    try matches.append(allocator, ']');
    const warnings = try util.jsonArrayStrings(allocator, result.warnings);
    defer allocator.free(warnings);
    return std.fmt.allocPrint(allocator, "{{\"match_count\":{d},\"matches\":{s},\"warnings\":{s}}}", .{
        result.matches.len,
        matches.items,
        warnings,
    });
}

fn jsonBool(value: ?[]const u8) []const u8 {
    const text = value orelse return "false";
    if (std.mem.eql(u8, text, "t") or std.mem.eql(u8, text, "true")) return "true";
    return "false";
}

fn digits(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |c| if (c < '0' or c > '9') return false;
    return true;
}
