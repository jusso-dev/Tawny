//! Tenant settings (password sign-in policy, analyst approval) and the
//! Entra ID (OIDC) configuration. Admin only. The OIDC client secret is
//! stored as secret_box ciphertext under TAWNY_INTEGRATION_ENCRYPTION_KEY
//! and is never returned.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");
const audit = @import("../http/audit.zig");
const secrets = @import("../crypto/secret_box.zig");

/// Route permissions, enforced by http/permissions.zig before the handler runs.
pub const routes = [_]@import("../http/permissions.zig").Route{
    .{ .method = .GET, .path = "/api/settings/tenant", .perm = .admin },
    .{ .method = .PUT, .path = "/api/settings/tenant", .perm = .admin },
    .{ .method = .GET, .path = "/api/settings/oidc", .perm = .admin },
    .{ .method = .PUT, .path = "/api/settings/oidc", .perm = .admin },
};

fn freeRows(allocator: std.mem.Allocator, rows: []pg.Row) void {
    for (rows) |row| row.deinit(allocator);
    allocator.free(rows);
}

fn csrfOk(request: *std.http.Server.Request, web: auth.WebUser) bool {
    return web.session_id == null or auth.checkCsrf(request, web);
}

pub fn envSecret() []const u8 {
    const z = std.c.getenv("TAWNY_INTEGRATION_ENCRYPTION_KEY") orelse return "";
    return std.mem.span(z);
}

pub const Tenant = struct {
    password_login_break_glass_only: bool = false,
    analyst_destructive_needs_approval: bool = false,
};

pub fn loadTenant(allocator: std.mem.Allocator, conn: *pg.Conn, tenant_id: []const u8) !Tenant {
    const rows = try conn.exec(allocator,
        \\SELECT password_login, analyst_destructive_needs_approval::text
        \\FROM tenant_settings WHERE tenant_id = $1::uuid
    , &.{.{ .text = tenant_id }});
    defer freeRows(allocator, rows);
    if (rows.len == 0) return .{};
    return .{
        .password_login_break_glass_only = std.mem.eql(u8, rows[0].cols[0] orelse "all", "break_glass"),
        .analyst_destructive_needs_approval = std.mem.eql(u8, rows[0].cols[1] orelse "false", "true"),
    };
}

pub fn analystNeedsApproval(allocator: std.mem.Allocator, conn: *pg.Conn, tenant_id: []const u8) !bool {
    return (try loadTenant(allocator, conn, tenant_id)).analyst_destructive_needs_approval;
}

/// Password sign-in rule. With the tenant limited to break-glass, only an
/// admin marked break_glass may use a password.
pub fn passwordAllowed(t: Tenant, role: []const u8, break_glass: bool) bool {
    if (!t.password_login_break_glass_only) return true;
    return break_glass and std.mem.eql(u8, role, "admin");
}

fn tenantJson(allocator: std.mem.Allocator, t: Tenant) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\{{"password_login":"{s}","analyst_destructive_needs_approval":{s}}}
    , .{
        if (t.password_login_break_glass_only) "break_glass" else "all",
        if (t.analyst_destructive_needs_approval) "true" else "false",
    });
}

pub fn getTenant(allocator: std.mem.Allocator, conn: *pg.Conn, request: *std.http.Server.Request, web: auth.WebUser) !void {
    const t = try loadTenant(allocator, conn, web.tenant_id);
    const json = try tenantJson(allocator, t);
    defer allocator.free(json);
    try util.respondJson(request, .ok, json);
}

pub fn putTenant(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    if (!csrfOk(request, web)) return util.respondJson(request, .forbidden, "{\"error\":\"csrf\"}");
    const body = try util.readBody(allocator, request, 16 * 1024);
    defer allocator.free(body);
    const Req = struct {
        password_login: ?[]const u8 = null,
        analyst_destructive_needs_approval: ?bool = null,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "Invalid settings body.");
    };
    defer parsed.deinit();
    var t = try loadTenant(allocator, conn, web.tenant_id);
    if (parsed.value.password_login) |pl| {
        if (std.mem.eql(u8, pl, "all")) {
            t.password_login_break_glass_only = false;
        } else if (std.mem.eql(u8, pl, "break_glass")) {
            // Refuse a setting that would lock every admin out.
            const glass = try conn.exec(allocator,
                \\SELECT 1 FROM users WHERE tenant_id = $1::uuid AND role = 'admin' AND break_glass
                \\  AND disabled_at IS NULL AND password_hash IS NOT NULL LIMIT 1
            , &.{.{ .text = web.tenant_id }});
            defer freeRows(allocator, glass);
            if (glass.len == 0) return util.problem(request, allocator, .conflict, "Mark at least one admin as break-glass first.");
            t.password_login_break_glass_only = true;
        } else return util.problem(request, allocator, .bad_request, "password_login must be all or break_glass.");
    }
    if (parsed.value.analyst_destructive_needs_approval) |v| t.analyst_destructive_needs_approval = v;
    try conn.execNoRows(
        \\INSERT INTO tenant_settings (tenant_id, password_login, analyst_destructive_needs_approval, updated_at)
        \\VALUES ($1::uuid, $2, $3::boolean, now())
        \\ON CONFLICT (tenant_id) DO UPDATE SET password_login = EXCLUDED.password_login,
        \\  analyst_destructive_needs_approval = EXCLUDED.analyst_destructive_needs_approval, updated_at = now()
    , &.{
        .{ .text = web.tenant_id },
        .{ .text = if (t.password_login_break_glass_only) "break_glass" else "all" },
        .{ .text = if (t.analyst_destructive_needs_approval) "true" else "false" },
    });
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "tenant_settings.update", null, null);
    const json = try tenantJson(allocator, t);
    defer allocator.free(json);
    try util.respondJson(request, .ok, json);
}

pub fn getOidc(allocator: std.mem.Allocator, conn: *pg.Conn, request: *std.http.Server.Request, web: auth.WebUser) !void {
    const rows = try conn.exec(allocator,
        \\SELECT enabled::text, entra_tenant_id, authority, client_id,
        \\       (client_secret_encrypted IS NOT NULL)::text, array_to_json(allowed_domains)::text, group_roles::text
        \\FROM tenant_oidc WHERE tenant_id = $1::uuid
    , &.{.{ .text = web.tenant_id }});
    defer freeRows(allocator, rows);
    if (rows.len == 0) return util.respondJson(request, .ok, "{\"configured\":false}");
    const c = rows[0].cols;
    const tid = try util.escapeJson(allocator, c[1] orelse "");
    defer allocator.free(tid);
    const authority = try util.nullOrJsonString(allocator, c[2]);
    defer allocator.free(authority);
    const cid = try util.escapeJson(allocator, c[3] orelse "");
    defer allocator.free(cid);
    const json = try std.fmt.allocPrint(allocator,
        \\{{"configured":true,"enabled":{s},"entra_tenant_id":{s},"authority":{s},"client_id":{s},"client_secret_set":{s},"allowed_domains":{s},"group_roles":{s}}}
    , .{ c[0] orelse "false", tid, authority, cid, c[4] orelse "false", c[5] orelse "[]", c[6] orelse "{}" });
    defer allocator.free(json);
    try util.respondJson(request, .ok, json);
}

pub fn putOidc(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    if (!csrfOk(request, web)) return util.respondJson(request, .forbidden, "{\"error\":\"csrf\"}");
    const body = try util.readBody(allocator, request, 64 * 1024);
    defer allocator.free(body);
    const Req = struct {
        enabled: bool = false,
        entra_tenant_id: []const u8,
        authority: ?[]const u8 = null,
        client_id: []const u8,
        client_secret: ?[]const u8 = null,
        allowed_domains: []const []const u8 = &.{},
        group_roles: std.json.Value = .null,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "entra_tenant_id and client_id are required.");
    };
    defer parsed.deinit();
    const v = parsed.value;
    if (v.entra_tenant_id.len == 0 or v.entra_tenant_id.len > 100 or v.client_id.len == 0 or v.client_id.len > 200 or
        util.hasControlChars(v.entra_tenant_id) or util.hasControlChars(v.client_id))
    {
        return util.problem(request, allocator, .bad_request, "entra_tenant_id and client_id are required.");
    }
    if (v.authority) |a| {
        if (!std.mem.startsWith(u8, a, "https://") and !std.mem.startsWith(u8, a, "http://127.0.0.1")) {
            return util.problem(request, allocator, .bad_request, "authority must be an https URL.");
        }
    }
    // Group map values must be role names. Keys are Entra group object ids.
    if (v.group_roles != .null) {
        if (v.group_roles != .object) return util.problem(request, allocator, .bad_request, "group_roles must map group ids to roles.");
        var it = v.group_roles.object.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* != .string or auth.roleFromText(e.value_ptr.string) == null or e.key_ptr.len == 0 or e.key_ptr.len > 100) {
                return util.problem(request, allocator, .bad_request, "group_roles values must be admin, analyst or viewer.");
            }
        }
    }
    const groups_json = try std.json.Stringify.valueAlloc(allocator, if (v.group_roles == .null) std.json.Value{ .object = .empty } else v.group_roles, .{});
    defer allocator.free(groups_json);
    var domains: std.ArrayList([]const u8) = .empty;
    defer domains.deinit(allocator);
    for (v.allowed_domains) |d| {
        if (d.len == 0 or d.len > 253 or util.hasControlChars(d)) return util.problem(request, allocator, .bad_request, "allowed_domains has an invalid entry.");
        try domains.append(allocator, d);
    }
    const domains_pg = try util.pgArrayText(allocator, domains.items);
    defer allocator.free(domains_pg);

    var secret_ct: ?[]u8 = null;
    defer if (secret_ct) |s| allocator.free(s);
    if (v.client_secret) |plain| {
        if (plain.len > 0) {
            const key = envSecret();
            if (key.len == 0) return util.problem(request, allocator, .service_unavailable, "TAWNY_INTEGRATION_ENCRYPTION_KEY is not set.");
            secret_ct = try secrets.protect(allocator, key, plain, io);
        }
    }
    try conn.execNoRows(
        \\INSERT INTO tenant_oidc (tenant_id, enabled, entra_tenant_id, authority, client_id, client_secret_encrypted,
        \\  allowed_domains, group_roles, updated_at)
        \\VALUES ($1::uuid, $2::boolean, $3, $4, $5, $6, $7::text[], $8::jsonb, now())
        \\ON CONFLICT (tenant_id) DO UPDATE SET enabled = EXCLUDED.enabled, entra_tenant_id = EXCLUDED.entra_tenant_id,
        \\  authority = EXCLUDED.authority, client_id = EXCLUDED.client_id,
        \\  client_secret_encrypted = COALESCE(EXCLUDED.client_secret_encrypted, tenant_oidc.client_secret_encrypted),
        \\  allowed_domains = EXCLUDED.allowed_domains, group_roles = EXCLUDED.group_roles,
        \\  discovery_json = NULL, jwks_json = NULL, jwks_fetched_at = NULL, updated_at = now()
    , &.{
        .{ .text = web.tenant_id },
        .{ .text = if (v.enabled) "true" else "false" },
        .{ .text = v.entra_tenant_id },
        if (v.authority) |a| .{ .text = a } else .{ .null = {} },
        .{ .text = v.client_id },
        if (secret_ct) |s| .{ .text = s } else .{ .null = {} },
        .{ .text = domains_pg },
        .{ .text = groups_json },
    });
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "tenant_oidc.update", null, null);
    return getOidc(allocator, conn, request, web);
}

test "password policy keeps break-glass admins only" {
    const open: Tenant = .{};
    const closed: Tenant = .{ .password_login_break_glass_only = true };
    try std.testing.expect(passwordAllowed(open, "viewer", false));
    try std.testing.expect(passwordAllowed(closed, "admin", true));
    try std.testing.expect(!passwordAllowed(closed, "admin", false));
    try std.testing.expect(!passwordAllowed(closed, "analyst", true));
    try std.testing.expect(!passwordAllowed(closed, "viewer", false));
}
