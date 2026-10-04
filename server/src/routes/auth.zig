const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");
const passwords = @import("../crypto/passwords.zig");

pub fn login(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
) !void {
    try auth.bootstrapAdminIfEmpty(allocator, io, conn);
    const body = try util.readBody(allocator, request, 64 * 1024);
    defer allocator.free(body);
    const Req = struct { email: []const u8, password: []const u8 };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "email and password are required.");
    };
    defer parsed.deinit();

    const rows = try conn.exec(allocator,
        \\SELECT id::text, tenant_id::text, email, role, password_hash, disabled_at::text, name
        \\FROM users WHERE lower(email) = lower($1) LIMIT 1
    , &.{.{ .text = parsed.value.email }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return util.problem(request, allocator, .unauthorized, "Invalid email or password.");
    const c = rows[0].cols;
    if (c[5] != null) return util.problem(request, allocator, .unauthorized, "Invalid email or password.");
    const hash = c[4] orelse return util.problem(request, allocator, .unauthorized, "Invalid email or password.");
    const ok = try auth.verifyLoginPassword(allocator, io, hash, parsed.value.password);
    if (!ok) return util.problem(request, allocator, .unauthorized, "Invalid email or password.");

    // Rehash legacy scrypt on success
    if (!std.mem.startsWith(u8, hash, "$argon2")) {
        const new_hash = passwords.hashArgon2id(allocator, parsed.value.password, passwords.productionParams(), io) catch null;
        if (new_hash) |nh| {
            defer allocator.free(nh);
            conn.execNoRows("UPDATE users SET password_hash = $2 WHERE id = $1::uuid", &.{
                .{ .text = c[0].? },
                .{ .text = nh },
            }) catch {};
        }
    }

    const sess = try auth.createSession(allocator, io, conn, c[0].?, c[1].?);
    defer {
        allocator.free(sess.cookie);
        allocator.free(sess.csrf_hex);
    }

    const cookie_hdr = try std.fmt.allocPrint(allocator, "{s}={s}; Path=/; HttpOnly; Secure; SameSite=Lax", .{ auth.session_cookie_name, sess.cookie });
    defer allocator.free(cookie_hdr);

    const email_j = try util.escapeJson(allocator, c[2] orelse "");
    defer allocator.free(email_j);
    const name_j = try util.nullOrJsonString(allocator, c[6]);
    defer allocator.free(name_j);
    const role_j = try util.escapeJson(allocator, c[3] orelse "viewer");
    defer allocator.free(role_j);
    const id_j = try util.escapeJson(allocator, c[0].?);
    defer allocator.free(id_j);
    const tid_j = try util.escapeJson(allocator, c[1].?);
    defer allocator.free(tid_j);
    const csrf_j = try util.escapeJson(allocator, sess.csrf_hex);
    defer allocator.free(csrf_j);

    const json = try std.fmt.allocPrint(allocator,
        \\{{"id":{s},"tenant_id":{s},"email":{s},"name":{s},"role":{s},"csrf_token":{s}}}
    , .{ id_j, tid_j, email_j, name_j, role_j, csrf_j });
    defer allocator.free(json);

    try util.respondJsonHeaders(request, .ok, json, &.{
        .{ .name = "set-cookie", .value = cookie_hdr },
    });
}

pub fn logout(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    _ = io;
    if (!auth.checkCsrf(request, web)) {
        try util.respondJson(request, .forbidden, "{\"error\":\"csrf\"}");
        return;
    }
    _ = util.readBody(allocator, request, 1024) catch null;
    if (web.session_id) |sid| {
        conn.execNoRows("UPDATE sessions SET revoked_at = now() WHERE id = $1::uuid", &.{.{ .text = sid }}) catch {};
    }
    const clear = try std.fmt.allocPrint(allocator, "{s}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0", .{auth.session_cookie_name});
    defer allocator.free(clear);
    try util.respondJsonHeaders(request, .ok, "{\"ok\":true}", &.{
        .{ .name = "set-cookie", .value = clear },
    });
}

pub fn session(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    const email_j = try util.escapeJson(allocator, web.email);
    defer allocator.free(email_j);
    const id_j = try util.escapeJson(allocator, web.user_id);
    defer allocator.free(id_j);
    const tid_j = try util.escapeJson(allocator, web.tenant_id);
    defer allocator.free(tid_j);
    const role_j = try util.escapeJson(allocator, auth.roleText(web.role));
    defer allocator.free(role_j);
    const csrf_j = try util.nullOrJsonString(allocator, web.csrf_hex);
    defer allocator.free(csrf_j);
    const json = try std.fmt.allocPrint(allocator,
        \\{{"id":{s},"tenant_id":{s},"email":{s},"role":{s},"csrf_token":{s}}}
    , .{ id_j, tid_j, email_j, role_j, csrf_j });
    defer allocator.free(json);
    try util.respondJson(request, .ok, json);
}

pub fn changePassword(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    if (web.session_id != null and !auth.checkCsrf(request, web)) {
        try util.respondJson(request, .forbidden, "{\"error\":\"csrf\"}");
        return;
    }
    const body = try util.readBody(allocator, request, 16 * 1024);
    defer allocator.free(body);
    const Req = struct { current_password: []const u8, new_password: []const u8 };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "current_password and new_password are required.");
    };
    defer parsed.deinit();
    if (parsed.value.new_password.len < 8 or parsed.value.new_password.len > 200) {
        return util.problem(request, allocator, .bad_request, "password is too short.");
    }
    const rows = try conn.exec(allocator,
        \\SELECT password_hash FROM users WHERE id = $1::uuid AND tenant_id = $2::uuid AND disabled_at IS NULL LIMIT 1
    , &.{ .{ .text = web.user_id }, .{ .text = web.tenant_id } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return util.problem(request, allocator, .unauthorized, "Current password is wrong.");
    const hash = rows[0].cols[0] orelse return util.problem(request, allocator, .unauthorized, "Current password is wrong.");
    const ok = try auth.verifyLoginPassword(allocator, io, hash, parsed.value.current_password);
    if (!ok) return util.problem(request, allocator, .unauthorized, "Current password is wrong.");
    const new_hash = try passwords.hashArgon2id(allocator, parsed.value.new_password, passwords.productionParams(), io);
    defer allocator.free(new_hash);
    try conn.execNoRows("UPDATE users SET password_hash = $2 WHERE id = $1::uuid", &.{
        .{ .text = web.user_id },
        .{ .text = new_hash },
    });
    try util.respondJson(request, .ok, "{\"ok\":true}");
}

/// Pure SQL-shaped login lookup helper used by unit tests (no network).
pub fn loginLookupSql() []const u8 {
    return
        \\SELECT id::text, tenant_id::text, email, role, password_hash, disabled_at::text, name
        \\FROM users WHERE lower(email) = lower($1) LIMIT 1
    ;
}

test "login lookup sql mentions password_hash" {
    try std.testing.expect(std.mem.indexOf(u8, loginLookupSql(), "password_hash") != null);
    try std.testing.expect(std.mem.indexOf(u8, loginLookupSql(), "lower(email)") != null);
}
