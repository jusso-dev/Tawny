const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

fn envSpan(name: [*:0]const u8) ?[]const u8 {
    const z = std.c.getenv(name) orelse return null;
    const s = std.mem.span(z);
    if (s.len == 0) return null;
    return s;
}

fn trimSlash(s: []const u8) []const u8 {
    var end = s.len;
    while (end > 0 and s[end - 1] == '/') end -= 1;
    return s[0..end];
}

fn freeRows(allocator: std.mem.Allocator, rows: []pg.Row) void {
    for (rows) |row| row.deinit(allocator);
    allocator.free(rows);
}

fn pct(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const hex = "0123456789ABCDEF";
    for (text) |c| {
        const unreserved = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~';
        if (unreserved) {
            try out.append(allocator, c);
        } else {
            try out.append(allocator, '%');
            try out.append(allocator, hex[c >> 4]);
            try out.append(allocator, hex[c & 0xf]);
        }
    }
    return out.toOwnedSlice(allocator);
}

fn b64url(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    const len = std.base64.url_safe_no_pad.Encoder.calcSize(raw.len);
    const out = try allocator.alloc(u8, len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, raw);
    return out;
}

pub fn start(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
) !void {
    const client_id = envSpan("TAWNY_GITHUB_CLIENT_ID") orelse {
        return util.problem(request, allocator, .service_unavailable, "GitHub OAuth is not configured.");
    };
    if (envSpan("TAWNY_GITHUB_CLIENT_SECRET") == null) {
        return util.problem(request, allocator, .service_unavailable, "GitHub OAuth is not configured.");
    }
    const public = trimSlash(envSpan("TAWNY_PUBLIC_URL") orelse "http://127.0.0.1:8080");
    const authorize = envSpan("TAWNY_GITHUB_AUTHORIZE_URL") orelse "https://github.com/login/oauth/authorize";

    const state = try util.randomHex(io, allocator, 32);
    defer allocator.free(state);
    const verifier = try util.randomHex(io, allocator, 32);
    defer allocator.free(verifier);
    var dig: [32]u8 = undefined;
    Sha256.hash(verifier, &dig, .{});
    const challenge = try b64url(allocator, &dig);
    defer allocator.free(challenge);

    const now = util.nowUnix(io);
    var t1: [32]u8 = undefined;
    var t2: [32]u8 = undefined;
    const created = util.formatRfc3339(&t1, now);
    const expires = util.formatRfc3339(&t2, now + 10 * 60);
    conn.execNoRows("DELETE FROM oauth_states WHERE expires_at < $1::timestamptz", &.{.{ .text = created }}) catch {};
    try conn.execNoRows(
        \\INSERT INTO oauth_states (state, pkce_verifier, created_at, expires_at)
        \\VALUES ($1, $2, $3::timestamptz, $4::timestamptz)
    , &.{
        .{ .text = state },
        .{ .text = verifier },
        .{ .text = created },
        .{ .text = expires },
    });

    const redirect_uri = try std.fmt.allocPrint(allocator, "{s}/api/auth/github/callback", .{public});
    defer allocator.free(redirect_uri);
    const redirect_enc = try pct(allocator, redirect_uri);
    defer allocator.free(redirect_enc);
    const client_enc = try pct(allocator, client_id);
    defer allocator.free(client_enc);
    const location = try std.fmt.allocPrint(allocator,
        "{s}?client_id={s}&redirect_uri={s}&scope=read%3Auser%20user%3Aemail&state={s}&code_challenge={s}&code_challenge_method=S256",
        .{ authorize, client_enc, redirect_enc, state, challenge },
    );
    defer allocator.free(location);
    try request.respond("", .{
        .status = .found,
        .extra_headers = &.{.{ .name = "location", .value = location }},
        .keep_alive = false,
    });
}

pub fn callback(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    target: []const u8,
) !void {
    const client_id = envSpan("TAWNY_GITHUB_CLIENT_ID") orelse {
        return util.problem(request, allocator, .service_unavailable, "GitHub OAuth is not configured.");
    };
    const client_secret = envSpan("TAWNY_GITHUB_CLIENT_SECRET") orelse {
        return util.problem(request, allocator, .service_unavailable, "GitHub OAuth is not configured.");
    };
    const code = util.queryParam(target, "code") orelse {
        return util.problem(request, allocator, .bad_request, "Invalid OAuth state.");
    };
    const state = util.queryParam(target, "state") orelse {
        return util.problem(request, allocator, .bad_request, "Invalid OAuth state.");
    };
    if (code.len == 0 or code.len > 512 or state.len == 0 or state.len > 128) {
        return util.problem(request, allocator, .bad_request, "Invalid OAuth state.");
    }

    var tbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&tbuf, util.nowUnix(io));
    const rows = try conn.exec(allocator,
        \\SELECT pkce_verifier FROM oauth_states WHERE state = $1 AND expires_at > $2::timestamptz LIMIT 1
    , &.{ .{ .text = state }, .{ .text = now_s } });
    defer freeRows(allocator, rows);
    if (rows.len == 0 or rows[0].cols.len == 0 or rows[0].cols[0] == null) {
        return util.problem(request, allocator, .bad_request, "Invalid OAuth state.");
    }
    const verifier = try allocator.dupe(u8, rows[0].cols[0].?);
    defer allocator.free(verifier);
    try conn.execNoRows("DELETE FROM oauth_states WHERE state = $1", &.{.{ .text = state }});

    const public = trimSlash(envSpan("TAWNY_PUBLIC_URL") orelse "http://127.0.0.1:8080");
    const token_url = envSpan("TAWNY_GITHUB_TOKEN_URL") orelse "https://github.com/login/oauth/access_token";
    const user_url = envSpan("TAWNY_GITHUB_USER_URL") orelse "https://api.github.com/user";
    const redirect_uri = try std.fmt.allocPrint(allocator, "{s}/api/auth/github/callback", .{public});
    defer allocator.free(redirect_uri);

    const token = httpToken(allocator, io, token_url, client_id, client_secret, code, redirect_uri, verifier) catch {
        return util.problem(request, allocator, .bad_gateway, "GitHub token exchange failed.");
    };
    defer allocator.free(token);
    const gh = httpUser(allocator, io, user_url, token) catch {
        return util.problem(request, allocator, .bad_gateway, "GitHub token exchange failed.");
    };
    defer allocator.free(gh.id);
    defer if (gh.email) |e| allocator.free(e);

    // Existing users only. Never INSERT a user from this callback.
    const linked = try findExisting(allocator, conn, gh.id, gh.email);
    if (linked == null) {
        return util.problem(request, allocator, .forbidden, "No account is linked to this GitHub user.");
    }
    const user = linked.?;
    defer {
        allocator.free(user.id);
        allocator.free(user.tenant_id);
        allocator.free(user.email);
        allocator.free(user.role);
        if (user.github_id) |g| allocator.free(g);
    }
    if (user.disabled) return util.problem(request, allocator, .unauthorized, "Invalid email or password.");
    if (user.github_id) |have| {
        if (!std.mem.eql(u8, have, gh.id)) {
            return util.problem(request, allocator, .forbidden, "GitHub account does not match this user.");
        }
    } else {
        conn.execNoRows("UPDATE users SET github_id = $2 WHERE id = $1::uuid AND github_id IS NULL", &.{
            .{ .text = user.id },
            .{ .text = gh.id },
        }) catch {
            return util.problem(request, allocator, .conflict, "GitHub account is already linked.");
        };
    }

    const sess = try auth.createSession(allocator, io, conn, user.id, user.tenant_id);
    defer {
        allocator.free(sess.cookie);
        allocator.free(sess.csrf_hex);
    }
    const cookie_hdr = try std.fmt.allocPrint(allocator, "{s}={s}; Path=/; HttpOnly; Secure; SameSite=Lax", .{ auth.session_cookie_name, sess.cookie });
    defer allocator.free(cookie_hdr);
    const location = try std.fmt.allocPrint(allocator, "{s}/", .{public});
    defer allocator.free(location);
    try request.respond("{\"ok\":true}", .{
        .status = .found,
        .extra_headers = &.{
            .{ .name = "location", .value = location },
            .{ .name = "set-cookie", .value = cookie_hdr },
            .{ .name = "content-type", .value = "application/json" },
        },
        .keep_alive = false,
    });
}

const Existing = struct {
    id: []u8,
    tenant_id: []u8,
    email: []u8,
    role: []u8,
    github_id: ?[]u8,
    disabled: bool,
};

fn findExisting(allocator: std.mem.Allocator, conn: *pg.Conn, github_id: []const u8, email: ?[]const u8) !?Existing {
    const by_id = try conn.exec(allocator,
        \\SELECT id::text, tenant_id::text, email, role, github_id, disabled_at::text
        \\FROM users WHERE github_id = $1 LIMIT 1
    , &.{.{ .text = github_id }});
    defer freeRows(allocator, by_id);
    if (by_id.len != 0) return try copyUser(allocator, by_id[0]);
    const mail = email orelse return null;
    const by_email = try conn.exec(allocator,
        \\SELECT id::text, tenant_id::text, email, role, github_id, disabled_at::text
        \\FROM users WHERE lower(email) = lower($1) LIMIT 1
    , &.{.{ .text = mail }});
    defer freeRows(allocator, by_email);
    if (by_email.len == 0) return null;
    return try copyUser(allocator, by_email[0]);
}

fn copyUser(allocator: std.mem.Allocator, row: pg.Row) !?Existing {
    if (row.cols.len < 4) return null;
    const id = row.cols[0] orelse return null;
    const tenant = row.cols[1] orelse return null;
    const email = row.cols[2] orelse return null;
    const role = row.cols[3] orelse "viewer";
    return .{
        .id = try allocator.dupe(u8, id),
        .tenant_id = try allocator.dupe(u8, tenant),
        .email = try allocator.dupe(u8, email),
        .role = try allocator.dupe(u8, role),
        .github_id = if (row.cols.len > 4 and row.cols[4] != null) try allocator.dupe(u8, row.cols[4].?) else null,
        .disabled = row.cols.len > 5 and row.cols[5] != null,
    };
}

fn httpToken(
    allocator: std.mem.Allocator,
    io: std.Io,
    url: []const u8,
    client_id: []const u8,
    client_secret: []const u8,
    code: []const u8,
    redirect_uri: []const u8,
    verifier: []const u8,
) ![]u8 {
    var form: std.ArrayList(u8) = .empty;
    defer form.deinit(allocator);
    try appendForm(&form, allocator, "client_id", client_id, false);
    try appendForm(&form, allocator, "client_secret", client_secret, true);
    try appendForm(&form, allocator, "code", code, true);
    try appendForm(&form, allocator, "redirect_uri", redirect_uri, true);
    try appendForm(&form, allocator, "grant_type", "authorization_code", true);
    try appendForm(&form, allocator, "code_verifier", verifier, true);
    const body = try httpFetch(allocator, io, .POST, url, form.items, "application/x-www-form-urlencoded", null);
    defer allocator.free(body);
    if (std.json.parseFromSlice(std.json.Value, allocator, body, .{ .ignore_unknown_fields = true })) |parsed| {
        defer parsed.deinit();
        if (parsed.value == .object) {
            if (parsed.value.object.get("access_token")) |tok| {
                if (tok == .string and tok.string.len > 0) return allocator.dupe(u8, tok.string);
            }
        }
    } else |_| {}
    const key = "access_token=";
    if (std.mem.indexOf(u8, body, key)) |i| {
        const rest = body[i + key.len ..];
        const end = std.mem.indexOfAny(u8, rest, "&\n\r ") orelse rest.len;
        if (end > 0) return allocator.dupe(u8, rest[0..end]);
    }
    return error.TokenExchange;
}

const GhUser = struct { id: []u8, email: ?[]u8 };

fn httpUser(allocator: std.mem.Allocator, io: std.Io, url: []const u8, token: []const u8) !GhUser {
    const authz = try std.fmt.allocPrint(allocator, "Bearer {s}", .{token});
    defer allocator.free(authz);
    const body = try httpFetch(allocator, io, .GET, url, null, null, authz);
    defer allocator.free(body);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (parsed.value != .object) return error.TokenExchange;
    const id_val = parsed.value.object.get("id") orelse return error.TokenExchange;
    const id = try jsonId(allocator, id_val);
    errdefer allocator.free(id);
    var email: ?[]u8 = null;
    if (parsed.value.object.get("email")) |em| {
        if (em == .string and em.string.len > 0) email = try allocator.dupe(u8, em.string);
    }
    return .{ .id = id, .email = email };
}

fn jsonId(allocator: std.mem.Allocator, value: std.json.Value) ![]u8 {
    switch (value) {
        .integer => |n| {
            var buf: [32]u8 = undefined;
            const s = std.fmt.bufPrint(&buf, "{d}", .{n}) catch return error.TokenExchange;
            return allocator.dupe(u8, s);
        },
        .string => |s| {
            if (s.len == 0 or s.len > 32) return error.TokenExchange;
            return allocator.dupe(u8, s);
        },
        .number_string => |s| return allocator.dupe(u8, s),
        else => return error.TokenExchange,
    }
}

fn appendForm(out: *std.ArrayList(u8), allocator: std.mem.Allocator, key: []const u8, value: []const u8, amp: bool) !void {
    if (amp) try out.append(allocator, '&');
    try out.appendSlice(allocator, key);
    try out.append(allocator, '=');
    const enc = try pct(allocator, value);
    defer allocator.free(enc);
    try out.appendSlice(allocator, enc);
}

fn httpFetch(
    allocator: std.mem.Allocator,
    io: std.Io,
    method: std.http.Method,
    url: []const u8,
    payload: ?[]const u8,
    content_type: ?[]const u8,
    authorization: ?[]const u8,
) ![]u8 {
    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();
    var buf: [16 * 1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    var extra: [2]std.http.Header = undefined;
    var n: usize = 0;
    extra[n] = .{ .name = "accept", .value = "application/json" };
    n += 1;
    if (authorization) |authz| {
        extra[n] = .{ .name = "authorization", .value = authz };
        n += 1;
    }
    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = method,
        .payload = payload,
        .keep_alive = false,
        .redirect_behavior = .unhandled,
        .response_writer = &writer,
        .headers = .{
            .user_agent = .{ .override = "tawny-server" },
            .accept_encoding = .{ .override = "identity" },
            .content_type = if (content_type) |ct| .{ .override = ct } else .omit,
        },
        .extra_headers = extra[0..n],
    }) catch return error.TokenExchange;
    if (result.status != .ok) return error.TokenExchange;
    return allocator.dupe(u8, writer.buffered());
}
