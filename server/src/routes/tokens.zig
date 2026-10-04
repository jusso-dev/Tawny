const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");
const audit = @import("../http/audit.zig");

pub fn createApiToken(
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
    const Req = struct {
        name: []const u8,
        role: ?[]const u8 = null,
        expires_at: ?[]const u8 = null,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "name is required and must be 160 characters or fewer.");
    };
    defer parsed.deinit();
    if (parsed.value.name.len == 0 or parsed.value.name.len > 160) {
        return util.problem(request, allocator, .bad_request, "name is required and must be 160 characters or fewer.");
    }
    const role = parsed.value.role orelse "viewer";
    if (auth.roleFromText(role) == null) {
        return util.problem(request, allocator, .bad_request, "role must be admin or viewer.");
    }

    var raw: [32]u8 = undefined;
    io.random(&raw);
    const secret_buf = try allocator.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(raw.len));
    defer allocator.free(secret_buf);
    const secret_enc = std.base64.url_safe_no_pad.Encoder.encode(secret_buf, &raw);
    const token = try std.fmt.allocPrint(allocator, "twny_{s}", .{secret_enc});
    defer allocator.free(token);
    const prefix = token[0..@min(12, token.len)];
    const hash = try util.sha256Hex(allocator, token);
    defer allocator.free(hash);

    var id_buf: [36]u8 = undefined;
    const id = util.newUuid(io, &id_buf);
    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const created = util.formatRfc3339(&tbuf, now);

    try conn.execNoRows(
        \\INSERT INTO api_tokens (id, tenant_id, name, token_hash, token_prefix, created_by_user_id, role, created_at, expires_at)
        \\VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::uuid, $7, $8::timestamptz, $9::timestamptz)
    , &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
        .{ .text = parsed.value.name },
        .{ .text = hash },
        .{ .text = prefix },
        .{ .text = web.user_id },
        .{ .text = role },
        .{ .text = created },
        if (parsed.value.expires_at) |e| .{ .text = e } else .{ .null = {} },
    });
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "api_token.create", id, null);

    const id_j = try util.escapeJson(allocator, id);
    defer allocator.free(id_j);
    const name_j = try util.escapeJson(allocator, parsed.value.name);
    defer allocator.free(name_j);
    const tok_j = try util.escapeJson(allocator, token);
    defer allocator.free(tok_j);
    const pref_j = try util.escapeJson(allocator, prefix);
    defer allocator.free(pref_j);
    const role_j = try util.escapeJson(allocator, role);
    defer allocator.free(role_j);
    const created_j = try util.escapeJson(allocator, created);
    defer allocator.free(created_j);
    const exp_j = try util.nullOrJsonString(allocator, parsed.value.expires_at);
    defer allocator.free(exp_j);
    const json = try std.fmt.allocPrint(allocator,
        \\{{"id":{s},"name":{s},"token":{s},"token_prefix":{s},"role":{s},"created_at":{s},"expires_at":{s}}}
    , .{ id_j, name_j, tok_j, pref_j, role_j, created_j, exp_j });
    defer allocator.free(json);
    try util.respondJson(request, .created, json);
}

pub fn listApiTokens(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    _ = util.readBody(allocator, request, 1024) catch {};
    const rows = try conn.exec(allocator,
        \\SELECT id::text, name, token_prefix, role, created_at::text, expires_at::text, last_used_at::text, revoked_at::text
        \\FROM api_tokens WHERE tenant_id = $1::uuid ORDER BY created_at DESC
    , &.{.{ .text = web.tenant_id }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.append(allocator, '[');
    for (rows, 0..) |row, i| {
        if (i > 0) try out.append(allocator, ',');
        const id_j = try util.escapeJson(allocator, row.cols[0] orelse "");
        defer allocator.free(id_j);
        const name_j = try util.escapeJson(allocator, row.cols[1] orelse "");
        defer allocator.free(name_j);
        const pref = try util.escapeJson(allocator, row.cols[2] orelse "");
        defer allocator.free(pref);
        const role_j = try util.escapeJson(allocator, row.cols[3] orelse "");
        defer allocator.free(role_j);
        const created = try util.escapeJson(allocator, row.cols[4] orelse "");
        defer allocator.free(created);
        const exp = try util.nullOrJsonString(allocator, row.cols[5]);
        defer allocator.free(exp);
        const used = try util.nullOrJsonString(allocator, row.cols[6]);
        defer allocator.free(used);
        const rev = try util.nullOrJsonString(allocator, row.cols[7]);
        defer allocator.free(rev);
        {
            const __tmp = try std.fmt.allocPrint(allocator, 
            "{{\"id\":{s},\"name\":{s},\"token_prefix\":{s},\"role\":{s},\"created_at\":{s},\"expires_at\":{s},\"last_used_at\":{s},\"revoked_at\":{s}}}",
            .{ id_j, name_j, pref, role_j, created, exp, used, rev },
        );
            defer allocator.free(__tmp);
            try out.appendSlice(allocator, __tmp);
        }
    }
    try out.append(allocator, ']');
    try util.respondJson(request, .ok, out.items);
}

pub fn listAuditLogs(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    target: []const u8,
) !void {
    _ = util.readBody(allocator, request, 1024) catch {};
    const limit_raw = util.queryParam(target, "limit") orelse "100";
    var limit = std.fmt.parseInt(i32, limit_raw, 10) catch 100;
    if (limit < 1) limit = 1;
    if (limit > 500) limit = 500;
    const lim = try std.fmt.allocPrint(allocator, "{d}", .{limit});
    defer allocator.free(lim);
    const action = util.queryParam(target, "action");

    const rows = if (action) |a| blk: {
        const like = try std.fmt.allocPrint(allocator, "%{s}%", .{a});
        defer allocator.free(like);
        break :blk try conn.exec(allocator,
            \\SELECT id::text, action, target, metadata_json::text, occurred_at::text
            \\FROM audit_log WHERE tenant_id = $1::uuid AND action LIKE $2
            \\ORDER BY occurred_at DESC, id DESC LIMIT $3::int
        , &.{ .{ .text = web.tenant_id }, .{ .text = like }, .{ .text = lim } });
    } else try conn.exec(allocator,
        \\SELECT id::text, action, target, metadata_json::text, occurred_at::text
        \\FROM audit_log WHERE tenant_id = $1::uuid
        \\ORDER BY occurred_at DESC, id DESC LIMIT $2::int
    , &.{ .{ .text = web.tenant_id }, .{ .text = lim } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.append(allocator, '[');
    for (rows, 0..) |row, i| {
        if (i > 0) try out.append(allocator, ',');
        const id_j = try util.escapeJson(allocator, row.cols[0] orelse "");
        defer allocator.free(id_j);
        const act = try util.escapeJson(allocator, row.cols[1] orelse "");
        defer allocator.free(act);
        const tgt = try util.nullOrJsonString(allocator, row.cols[2]);
        defer allocator.free(tgt);
        const meta = if (row.cols[3]) |m| m else "null";
        const occ = try util.escapeJson(allocator, row.cols[4] orelse "");
        defer allocator.free(occ);
        {
            const __tmp = try std.fmt.allocPrint(allocator, 
            "{{\"id\":{s},\"action\":{s},\"target\":{s},\"metadata\":{s},\"occurred_at\":{s}}}",
            .{ id_j, act, tgt, meta, occ },
        );
            defer allocator.free(__tmp);
            try out.appendSlice(allocator, __tmp);
        }
    }
    try out.append(allocator, ']');
    try util.respondJson(request, .ok, out.items);
}
