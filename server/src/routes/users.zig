const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");
const audit = @import("../http/audit.zig");
const passwords = @import("../crypto/passwords.zig");

pub fn normalizeRole(role: ?[]const u8) error{BadRole}![]const u8 {
    const raw = role orelse return "viewer";
    if (raw.len == 0) return "viewer";
    if (std.ascii.eqlIgnoreCase(raw, "viewer")) return "viewer";
    if (std.ascii.eqlIgnoreCase(raw, "admin")) return "admin";
    return error.BadRole;
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

fn csrfOk(request: *std.http.Server.Request, web: auth.WebUser) bool {
    return web.session_id == null or auth.checkCsrf(request, web);
}

fn freeRows(allocator: std.mem.Allocator, rows: []pg.Row) void {
    for (rows) |row| row.deinit(allocator);
    allocator.free(rows);
}

const UserRow = struct {
    id: []const u8,
    email: []const u8,
    name: ?[]const u8,
    role: []const u8,
    github_id: ?[]const u8,
    disabled: bool,
};

fn writeUser(allocator: std.mem.Allocator, out: *std.ArrayList(u8), user: UserRow) !void {
    const id_j = try util.escapeJson(allocator, user.id);
    defer allocator.free(id_j);
    const email_j = try util.escapeJson(allocator, user.email);
    defer allocator.free(email_j);
    const name_j = try util.nullOrJsonString(allocator, user.name);
    defer allocator.free(name_j);
    const role_j = try util.escapeJson(allocator, user.role);
    defer allocator.free(role_j);
    const gh_j = try util.nullOrJsonString(allocator, user.github_id);
    defer allocator.free(gh_j);
    const disabled = if (user.disabled) "true" else "false";
    const line = try std.fmt.allocPrint(allocator,
        \\{{"id":{s},"email":{s},"name":{s},"role":{s},"github_id":{s},"disabled":{s}}}
    , .{ id_j, email_j, name_j, role_j, gh_j, disabled });
    defer allocator.free(line);
    try out.appendSlice(allocator, line);
}

fn rowUser(cols: [6]?[]const u8) ?UserRow {
    return .{
        .id = cols[0] orelse return null,
        .email = cols[1] orelse return null,
        .name = cols[2],
        .role = cols[3] orelse "viewer",
        .github_id = cols[4],
        .disabled = cols[5] != null,
    };
}

pub fn list(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    const rows = try conn.exec(allocator,
        \\SELECT id::text, email, name, role, github_id, disabled_at::text
        \\FROM users WHERE tenant_id = $1::uuid ORDER BY email
    , &.{.{ .text = web.tenant_id }});
    defer freeRows(allocator, rows);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.append(allocator, '[');
    for (rows, 0..) |row, i| {
        if (i != 0) try out.append(allocator, ',');
        var cols: [6]?[]const u8 = undefined;
        for (0..6) |c| cols[c] = if (c < row.cols.len) row.cols[c] else null;
        const user = rowUser(cols) orelse continue;
        try writeUser(allocator, &out, user);
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
    const body = try util.readBody(allocator, request, 16 * 1024);
    defer allocator.free(body);
    const Req = struct {
        email: []const u8,
        password: []const u8,
        name: ?[]const u8 = null,
        role: ?[]const u8 = null,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "email and password are required.");
    };
    defer parsed.deinit();
    if (!validEmail(parsed.value.email)) {
        return util.problem(request, allocator, .bad_request, "email and password are required.");
    }
    if (parsed.value.password.len < 8 or parsed.value.password.len > 200) {
        return util.problem(request, allocator, .bad_request, "password is too short.");
    }
    const role = normalizeRole(parsed.value.role) catch {
        return util.problem(request, allocator, .bad_request, "role must be admin or viewer.");
    };
    const email = try std.ascii.allocLowerString(allocator, parsed.value.email);
    defer allocator.free(email);

    const existing = try conn.exec(allocator,
        \\SELECT id::text FROM users WHERE tenant_id = $1::uuid AND lower(email) = $2 LIMIT 1
    , &.{ .{ .text = web.tenant_id }, .{ .text = email } });
    defer freeRows(allocator, existing);
    if (existing.len != 0) {
        return util.problem(request, allocator, .conflict, "A user with this email already exists.");
    }

    const hash = try passwords.hashArgon2id(allocator, parsed.value.password, passwords.productionParams(), io);
    defer allocator.free(hash);
    var id_buf: [36]u8 = undefined;
    const uid = util.newUuid(io, &id_buf);
    var tbuf: [32]u8 = undefined;
    const created = util.formatRfc3339(&tbuf, util.nowUnix(io));
    const name = if (parsed.value.name) |n| if (n.len == 0) null else n else null;
    try conn.execNoRows(
        \\INSERT INTO users (id, tenant_id, email, name, role, password_hash, created_at)
        \\VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7::timestamptz)
    , &.{
        .{ .text = uid },
        .{ .text = web.tenant_id },
        .{ .text = email },
        if (name) |n| .{ .text = n } else .{ .null = {} },
        .{ .text = role },
        .{ .text = hash },
        .{ .text = created },
    });
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "user.create", uid, null);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try writeUser(allocator, &out, .{
        .id = uid,
        .email = email,
        .name = name,
        .role = role,
        .github_id = null,
        .disabled = false,
    });
    try util.respondJson(request, .created, out.items);
}

pub fn update(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    user_id: []const u8,
) !void {
    if (!csrfOk(request, web)) {
        try util.respondJson(request, .forbidden, "{\"error\":\"csrf\"}");
        return;
    }
    if (!isUuid(user_id)) return util.problem(request, allocator, .not_found, "User not found.");
    const body = try util.readBody(allocator, request, 16 * 1024);
    defer allocator.free(body);
    const Req = struct {
        name: ?[]const u8 = null,
        role: ?[]const u8 = null,
        password: ?[]const u8 = null,
        disabled: ?bool = null,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "invalid user update.");
    };
    defer parsed.deinit();
    const found = try conn.exec(allocator,
        \\SELECT id::text FROM users WHERE id = $1::uuid AND tenant_id = $2::uuid LIMIT 1
    , &.{ .{ .text = user_id }, .{ .text = web.tenant_id } });
    defer freeRows(allocator, found);
    if (found.len == 0) return util.problem(request, allocator, .not_found, "User not found.");

    if (parsed.value.name) |name| {
        const stored = if (name.len == 0) null else name;
        try conn.execNoRows("UPDATE users SET name = $2 WHERE id = $1::uuid", &.{
            .{ .text = user_id },
            if (stored) |n| .{ .text = n } else .{ .null = {} },
        });
    }
    if (parsed.value.role) |role_raw| {
        const role = normalizeRole(role_raw) catch {
            return util.problem(request, allocator, .bad_request, "role must be admin or viewer.");
        };
        if (std.mem.eql(u8, user_id, web.user_id) and !std.mem.eql(u8, role, "admin")) {
            return util.problem(request, allocator, .bad_request, "cannot remove your own admin role.");
        }
        try conn.execNoRows("UPDATE users SET role = $2 WHERE id = $1::uuid", &.{
            .{ .text = user_id },
            .{ .text = role },
        });
    }
    if (parsed.value.password) |password| {
        if (password.len < 8 or password.len > 200) {
            return util.problem(request, allocator, .bad_request, "password is too short.");
        }
        const hash = try passwords.hashArgon2id(allocator, password, passwords.productionParams(), io);
        defer allocator.free(hash);
        try conn.execNoRows("UPDATE users SET password_hash = $2 WHERE id = $1::uuid", &.{
            .{ .text = user_id },
            .{ .text = hash },
        });
    }
    if (parsed.value.disabled) |disabled| {
        if (disabled and std.mem.eql(u8, user_id, web.user_id)) {
            return util.problem(request, allocator, .bad_request, "cannot disable the current user.");
        }
        if (disabled) {
            var tbuf: [32]u8 = undefined;
            const now = util.formatRfc3339(&tbuf, util.nowUnix(io));
            try conn.execNoRows("UPDATE users SET disabled_at = $2::timestamptz WHERE id = $1::uuid", &.{
                .{ .text = user_id },
                .{ .text = now },
            });
        } else {
            try conn.execNoRows("UPDATE users SET disabled_at = NULL WHERE id = $1::uuid", &.{.{ .text = user_id }});
        }
    }
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "user.update", user_id, null);
    return getOne(allocator, conn, request, web, user_id);
}

pub fn delete(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    user_id: []const u8,
) !void {
    if (!csrfOk(request, web)) {
        try util.respondJson(request, .forbidden, "{\"error\":\"csrf\"}");
        return;
    }
    _ = util.readBody(allocator, request, 1024) catch {};
    if (!isUuid(user_id)) return util.problem(request, allocator, .not_found, "User not found.");
    if (std.mem.eql(u8, user_id, web.user_id)) {
        return util.problem(request, allocator, .bad_request, "cannot delete the current user.");
    }
    const found = try conn.exec(allocator,
        \\SELECT id::text FROM users WHERE id = $1::uuid AND tenant_id = $2::uuid LIMIT 1
    , &.{ .{ .text = user_id }, .{ .text = web.tenant_id } });
    defer freeRows(allocator, found);
    if (found.len == 0) return util.problem(request, allocator, .not_found, "User not found.");
    try conn.execNoRows("DELETE FROM sessions WHERE user_id = $1::uuid", &.{.{ .text = user_id }});
    try conn.execNoRows("DELETE FROM users WHERE id = $1::uuid AND tenant_id = $2::uuid", &.{
        .{ .text = user_id },
        .{ .text = web.tenant_id },
    });
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "user.delete", user_id, null);
    try util.respondJson(request, .ok, "{\"ok\":true}");
}

fn getOne(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    user_id: []const u8,
) !void {
    const rows = try conn.exec(allocator,
        \\SELECT id::text, email, name, role, github_id, disabled_at::text
        \\FROM users WHERE id = $1::uuid AND tenant_id = $2::uuid LIMIT 1
    , &.{ .{ .text = user_id }, .{ .text = web.tenant_id } });
    defer freeRows(allocator, rows);
    if (rows.len == 0) return util.problem(request, allocator, .not_found, "User not found.");
    var cols: [6]?[]const u8 = undefined;
    for (0..6) |c| cols[c] = if (c < rows[0].cols.len) rows[0].cols[c] else null;
    const user = rowUser(cols) orelse return util.problem(request, allocator, .not_found, "User not found.");
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try writeUser(allocator, &out, user);
    try util.respondJson(request, .ok, out.items);
}

fn validEmail(email: []const u8) bool {
    if (email.len < 3 or email.len > 320) return false;
    if (std.mem.indexOfScalar(u8, email, '@') == null) return false;
    if (util.hasControlChars(email) or std.mem.indexOfScalar(u8, email, ' ') != null) return false;
    return true;
}

test "omitted role is viewer" {
    try std.testing.expectEqualStrings("viewer", try normalizeRole(null));
    try std.testing.expectEqualStrings("viewer", try normalizeRole(""));
    try std.testing.expectEqualStrings("admin", try normalizeRole("Admin"));
    try std.testing.expectError(error.BadRole, normalizeRole("owner"));
}
