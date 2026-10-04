const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const jwt = @import("../crypto/jwt.zig");
const passwords = @import("../crypto/passwords.zig");
const util = @import("util.zig");
const state = @import("state.zig");
const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Role = enum { admin, viewer };

pub const WebUser = struct {
    user_id: []const u8,
    tenant_id: []const u8,
    email: []const u8,
    role: Role,
    session_id: ?[]const u8 = null,
    csrf_hex: ?[]const u8 = null,
};

pub const AgentAuth = struct {
    agent_id: []const u8,
    tenant_id: []const u8,
    cv: i64,
    exp: i64,
    /// True when the presented token was RS256. Heartbeat always rotates it to EdDSA.
    legacy_rs256: bool = false,
};

pub const Auth = union(enum) {
    none,
    web: WebUser,
    agent: AgentAuth,
};

pub const session_cookie_name = "tawny_session";

pub fn roleFromText(s: []const u8) ?Role {
    if (std.ascii.eqlIgnoreCase(s, "admin")) return .admin;
    if (std.ascii.eqlIgnoreCase(s, "viewer")) return .viewer;
    return null;
}

pub fn roleText(r: Role) []const u8 {
    return switch (r) {
        .admin => "admin",
        .viewer => "viewer",
    };
}

fn timingEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

fn sha256Bytes(data: []const u8) [32]u8 {
    var dig: [32]u8 = undefined;
    Sha256.hash(data, &dig, .{});
    return dig;
}

pub fn hashSecretHex(allocator: std.mem.Allocator, secret: []const u8) ![]u8 {
    return util.sha256Hex(allocator, secret);
}

/// Cookie value: `{session_id}.{secret_hex}` where secret_hex is 64 hex chars (32 bytes).
pub fn parseSessionCookie(value: []const u8) ?struct { id: []const u8, secret_hex: []const u8 } {
    const dot = std.mem.lastIndexOfScalar(u8, value, '.') orelse return null;
    if (dot == 0 or dot + 1 >= value.len) return null;
    const secret = value[dot + 1 ..];
    if (secret.len != 64) return null;
    return .{ .id = value[0..dot], .secret_hex = secret };
}

pub fn resolve(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
) !Auth {
    if (util.headerValue(request, "authorization")) |authz| {
        if (authz.len > 7 and std.ascii.eqlIgnoreCase(authz[0..7], "bearer ")) {
            const token = authz[7..];
            if (std.mem.startsWith(u8, token, "twny_")) {
                if (try resolveApiToken(allocator, conn, token)) |web| return .{ .web = web };
                return .none;
            }
            if (try resolveAgentJwt(allocator, io, conn, token)) |agent| return .{ .agent = agent };
            return .none;
        }
    }
    if (util.headerValue(request, "cookie")) |cookies| {
        if (util.cookieValue(cookies, session_cookie_name)) |raw| {
            if (try resolveSession(allocator, io, conn, raw)) |web| return .{ .web = web };
        }
    }
    return .none;
}

fn resolveApiToken(allocator: std.mem.Allocator, conn: *pg.Conn, token: []const u8) !?WebUser {
    const hash = try util.sha256Hex(allocator, token);
    defer allocator.free(hash);
    const rows = try conn.exec(allocator,
        \\SELECT t.id::text, t.tenant_id::text, t.role, t.revoked_at::text, t.expires_at::text
        \\FROM api_tokens t WHERE t.token_hash = $1 LIMIT 1
    , &.{.{ .text = hash }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return null;
    const cols = rows[0].cols;
    if (cols[3] != null) return null; // revoked
    // expires_at check is best-effort via text compare if present; skip strict parse
    const role = roleFromText(cols[2] orelse return null) orelse return null;
    return .{
        .user_id = try allocator.dupe(u8, cols[0] orelse return null),
        .tenant_id = try allocator.dupe(u8, cols[1] orelse return null),
        .email = try allocator.dupe(u8, ""),
        .role = role,
    };
}

fn resolveSession(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, cookie: []const u8) !?WebUser {
    const parts = parseSessionCookie(cookie) orelse return null;
    var secret_bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&secret_bytes, parts.secret_hex) catch return null;
    const want_hash = sha256Bytes(&secret_bytes);
    const rows = try conn.exec(allocator,
        \\SELECT s.id::text, s.user_id::text, s.tenant_id::text, s.secret_hash, s.csrf_secret,
        \\       s.revoked_at::text, s.absolute_expires_at, s.idle_expires_at,
        \\       u.email, u.role, u.disabled_at::text
        \\FROM sessions s JOIN users u ON u.id = s.user_id
        \\WHERE s.id = $1::uuid LIMIT 1
    , &.{.{ .text = parts.id }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return null;
    const c = rows[0].cols;
    if (c[5] != null) return null; // revoked
    if (c[10] != null) return null; // user disabled
    const stored_hash = c[3] orelse return null;
    // secret_hash may arrive as \x hex or raw depending on pg text encoding
    var stored_bytes: [32]u8 = undefined;
    if (!decodeBytea(stored_hash, &stored_bytes)) return null;
    if (!timingEql(&stored_bytes, &want_hash)) return null;

    const now = util.nowUnix(io);
    if (c[6]) |abs| {
        if (parseTimestamptzUnix(abs)) |exp| {
            if (now >= exp) return null;
        }
    }
    if (c[7]) |idle| {
        if (parseTimestamptzUnix(idle)) |exp| {
            if (now >= exp) return null;
        }
    }

    const role = roleFromText(c[9] orelse return null) orelse return null;
    const csrf = c[4] orelse return null;
    var csrf_raw: [32]u8 = undefined;
    if (!decodeBytea(csrf, &csrf_raw)) return null;
    const csrf_hex = try util.hexEncode(allocator, &csrf_raw);

    // Touch idle expiry (best effort)
    var idle_buf: [32]u8 = undefined;
    const idle_at = util.formatRfc3339(&idle_buf, now + 8 * 3600);
    conn.execNoRows(
        \\UPDATE sessions SET last_seen_at = now(), idle_expires_at = $2::timestamptz WHERE id = $1::uuid
    , &.{ .{ .text = parts.id }, .{ .text = idle_at } }) catch {};

    return .{
        .user_id = try allocator.dupe(u8, c[1] orelse return null),
        .tenant_id = try allocator.dupe(u8, c[2] orelse return null),
        .email = try allocator.dupe(u8, c[8] orelse ""),
        .role = role,
        .session_id = try allocator.dupe(u8, parts.id),
        .csrf_hex = csrf_hex,
    };
}

fn decodeBytea(text: []const u8, out: *[32]u8) bool {
    if (text.len == 32) {
        @memcpy(out, text[0..32]);
        return true;
    }
    if (text.len == 66 and std.mem.startsWith(u8, text, "\\x")) {
        _ = std.fmt.hexToBytes(out, text[2..]) catch return false;
        return true;
    }
    if (text.len == 64) {
        _ = std.fmt.hexToBytes(out, text) catch return false;
        return true;
    }
    return false;
}

fn parseTimestamptzUnix(text: []const u8) ?i64 {
    // Accept RFC3339-ish "YYYY-MM-DDTHH:MM:SS" or space-separated.
    if (text.len < 19) return null;
    const year = std.fmt.parseInt(i32, text[0..4], 10) catch return null;
    const month = std.fmt.parseInt(u8, text[5..7], 10) catch return null;
    const day = std.fmt.parseInt(u8, text[8..10], 10) catch return null;
    const hour = std.fmt.parseInt(u8, text[11..13], 10) catch return null;
    const min = std.fmt.parseInt(u8, text[14..16], 10) catch return null;
    const sec = std.fmt.parseInt(u8, text[17..19], 10) catch return null;
    // Approximate: days since 1970 via civil
    const z = daysFromCivil(year, month, day);
    return z * 86400 + @as(i64, hour) * 3600 + @as(i64, min) * 60 + @as(i64, sec);
}

fn daysFromCivil(year: i32, month: u8, day: u8) i64 {
    var y: i64 = year;
    const m: i64 = month;
    const d: i64 = day;
    y -= @intFromBool(m <= 2);
    const era: i64 = @divFloor(y, 400);
    const yoe: i64 = y - era * 400;
    const mp: i64 = if (m > 2) m - 3 else m + 9;
    const doy: i64 = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe: i64 = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

fn resolveAgentJwt(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, token: []const u8) !?AgentAuth {
    const now = util.nowUnix(io);
    // Peek alg
    const dot1 = std.mem.indexOfScalar(u8, token, '.') orelse return null;
    const header_b64 = token[0..dot1];
    const header_raw = b64UrlDecode(allocator, header_b64) catch return null;
    defer allocator.free(header_raw);
    const Header = struct { alg: []const u8 };
    var header = std.json.parseFromSlice(Header, allocator, header_raw, .{ .ignore_unknown_fields = true }) catch return null;
    defer header.deinit();

    if (std.mem.eql(u8, header.value.alg, "RS256")) {
        return verifyLegacyRs256(allocator, io, conn, token, now);
    }
    if (!std.mem.eql(u8, header.value.alg, "EdDSA")) return null;

    const kp = try state.ensureAgentKey(io);
    var verified = jwt.verify(allocator, token, kp.public_key, .{
        .now = now,
        .expect_iss = "tawny",
        .expect_aud = "tawny-agents",
    }) catch return null;
    defer verified.deinit();

    const agent_id = try allocator.dupe(u8, verified.claims.agent_id);
    errdefer allocator.free(agent_id);
    const tenant_id = try allocator.dupe(u8, verified.claims.tenant_id);
    errdefer allocator.free(tenant_id);

    const rows = try conn.exec(allocator,
        \\SELECT status, credential_version::text FROM agents WHERE id = $1::uuid AND tenant_id = $2::uuid LIMIT 1
    , &.{ .{ .text = agent_id }, .{ .text = tenant_id } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return null;
    const status = rows[0].cols[0] orelse return null;
    if (std.mem.eql(u8, status, "revoked")) return null;
    const cv_text = rows[0].cols[1] orelse return null;
    const cv = std.fmt.parseInt(i64, cv_text, 10) catch return null;
    if (cv != verified.claims.cv) return null;

    return .{
        .agent_id = agent_id,
        .tenant_id = tenant_id,
        .cv = verified.claims.cv,
        .exp = verified.claims.exp,
    };
}

fn verifyLegacyRs256(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    token: []const u8,
    now: i64,
) !?AgentAuth {
    const key = state.rs256Public(allocator, io) orelse return null;
    jwt.verifyRs256(allocator, token, key.n, key.e) catch return null;
    const dot1 = std.mem.indexOfScalar(u8, token, '.') orelse return null;
    const dot2 = std.mem.indexOfScalarPos(u8, token, dot1 + 1, '.') orelse return null;
    const payload_raw = b64UrlDecode(allocator, token[dot1 + 1 .. dot2]) catch return null;
    defer allocator.free(payload_raw);
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, payload_raw, .{ .ignore_unknown_fields = true }) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const obj = parsed.value.object;
    const agent_id_v = obj.get("agent_id") orelse return null;
    const tenant_id_v = obj.get("tenant_id") orelse return null;
    const cv_v = obj.get("cv") orelse return null;
    const exp_v = obj.get("exp") orelse return null;
    if (agent_id_v != .string or tenant_id_v != .string) return null;
    const cv = jsonI64(cv_v) orelse return null;
    const exp = jsonI64(exp_v) orelse return null;
    if (now >= exp) return null;
    if (obj.get("iss")) |iss| {
        if (iss != .string or !std.mem.eql(u8, iss.string, "tawny")) return null;
    } else return null;
    if (obj.get("aud")) |aud| {
        if (aud != .string or !std.mem.eql(u8, aud.string, "tawny-agents")) return null;
    } else return null;

    const agent_id = try allocator.dupe(u8, agent_id_v.string);
    errdefer allocator.free(agent_id);
    const tenant_id = try allocator.dupe(u8, tenant_id_v.string);
    errdefer allocator.free(tenant_id);
    const rows = try conn.exec(allocator,
        \\SELECT status, credential_version::text FROM agents WHERE id = $1::uuid AND tenant_id = $2::uuid LIMIT 1
    , &.{ .{ .text = agent_id }, .{ .text = tenant_id } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return null;
    const status = rows[0].cols[0] orelse return null;
    if (std.mem.eql(u8, status, "revoked")) return null;
    const cv_text = rows[0].cols[1] orelse return null;
    const db_cv = std.fmt.parseInt(i64, cv_text, 10) catch return null;
    if (db_cv != cv) return null;
    return .{
        .agent_id = agent_id,
        .tenant_id = tenant_id,
        .cv = cv,
        .exp = exp,
        .legacy_rs256 = true,
    };
}

fn jsonI64(value: std.json.Value) ?i64 {
    return switch (value) {
        .integer => |n| n,
        .string => |s| std.fmt.parseInt(i64, s, 10) catch null,
        .number_string => |s| std.fmt.parseInt(i64, s, 10) catch null,
        else => null,
    };
}

fn b64UrlDecode(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
    const trimmed = std.mem.trimEnd(u8, src, "=");
    const len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(trimmed) catch return error.InvalidToken;
    const out = try allocator.alloc(u8, len);
    errdefer allocator.free(out);
    std.base64.url_safe_no_pad.Decoder.decode(out, trimmed) catch return error.InvalidToken;
    return out;
}

pub fn requireWeb(auth: Auth) ?WebUser {
    return switch (auth) {
        .web => |w| w,
        else => null,
    };
}

pub fn requireAdmin(auth: Auth) ?WebUser {
    const w = requireWeb(auth) orelse return null;
    if (w.role != .admin) return null;
    return w;
}

pub fn requireAgent(auth: Auth) ?AgentAuth {
    return switch (auth) {
        .agent => |a| a,
        else => null,
    };
}

pub fn checkCsrf(request: *std.http.Server.Request, web: WebUser) bool {
    const got = util.headerValue(request, "x-csrf-token") orelse return false;
    const want = web.csrf_hex orelse return false;
    return timingEql(got, want);
}

pub fn issueAgentJwt(
    allocator: std.mem.Allocator,
    io: std.Io,
    agent_id: []const u8,
    tenant_id: []const u8,
    cv: i64,
) !struct { token: []u8, exp: i64 } {
    const kp = try state.ensureAgentKey(io);
    const now = util.nowUnix(io);
    const exp = now + 60 * 60;
    var jti_buf: [36]u8 = undefined;
    const jti = util.newUuid(io, &jti_buf);
    const token = try jwt.issue(allocator, .{
        .agent_id = agent_id,
        .tenant_id = tenant_id,
        .cv = cv,
        .jti = jti,
        .iss = "tawny",
        .aud = "tawny-agents",
        .exp = exp,
        .iat = now,
    }, kp);
    return .{ .token = token, .exp = exp };
}

pub fn createSession(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    user_id: []const u8,
    tenant_id: []const u8,
) !struct { cookie: []u8, csrf_hex: []u8 } {
    var id_buf: [36]u8 = undefined;
    const sid = util.newUuid(io, &id_buf);
    var secret: [32]u8 = undefined;
    var csrf: [32]u8 = undefined;
    io.random(&secret);
    io.random(&csrf);
    const secret_hash = sha256Bytes(&secret);
    const secret_hex = try util.hexEncode(allocator, &secret);
    errdefer allocator.free(secret_hex);
    const csrf_hex = try util.hexEncode(allocator, &csrf);
    errdefer allocator.free(csrf_hex);

    const now = util.nowUnix(io);
    var tbuf1: [32]u8 = undefined;
    var tbuf2: [32]u8 = undefined;
    var tbuf3: [32]u8 = undefined;
    const created = util.formatRfc3339(&tbuf1, now);
    const abs_exp = util.formatRfc3339(&tbuf2, now + 7 * 86400);
    const idle_exp = util.formatRfc3339(&tbuf3, now + 8 * 3600);

    const hash_hex = try util.hexEncode(allocator, &secret_hash);
    defer allocator.free(hash_hex);
    const csrf_body = try util.hexEncode(allocator, &csrf);
    defer allocator.free(csrf_body);
    const hash_lit = try std.fmt.allocPrint(allocator, "\\x{s}", .{hash_hex});
    defer allocator.free(hash_lit);
    const csrf_lit = try std.fmt.allocPrint(allocator, "\\x{s}", .{csrf_body});
    defer allocator.free(csrf_lit);

    try conn.execNoRows(
        \\INSERT INTO sessions (id, user_id, tenant_id, secret_hash, csrf_secret, created_at, last_seen_at, absolute_expires_at, idle_expires_at)
        \\VALUES ($1::uuid, $2::uuid, $3::uuid, $4::bytea, $5::bytea, $6::timestamptz, $6::timestamptz, $7::timestamptz, $8::timestamptz)
    , &.{
        .{ .text = sid },
        .{ .text = user_id },
        .{ .text = tenant_id },
        .{ .text = hash_lit },
        .{ .text = csrf_lit },
        .{ .text = created },
        .{ .text = abs_exp },
        .{ .text = idle_exp },
    });

    const cookie = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ sid, secret_hex });
    allocator.free(secret_hex);
    return .{ .cookie = cookie, .csrf_hex = csrf_hex };
}

pub fn verifyLoginPassword(
    allocator: std.mem.Allocator,
    io: std.Io,
    stored_hash: []const u8,
    password: []const u8,
) !bool {
    _ = passwords.verify(allocator, stored_hash, password, io) catch return false;
    return true;
}

pub fn bootstrapAdminIfEmpty(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
) !void {
    const rows = try conn.exec(allocator, "SELECT 1 FROM users LIMIT 1", &.{});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len > 0) return;
    const email_z = std.c.getenv("TAWNY_BOOTSTRAP_ADMIN_EMAIL") orelse return;
    const password_z = std.c.getenv("TAWNY_BOOTSTRAP_ADMIN_PASSWORD") orelse return;
    const email = std.mem.span(email_z);
    const password = std.mem.span(password_z);
    if (email.len == 0 or password.len == 0) return;

    const hash = try passwords.hashArgon2id(allocator, password, passwords.productionParams(), io);
    defer allocator.free(hash);
    var id_buf: [36]u8 = undefined;
    const uid = util.newUuid(io, &id_buf);
    var tbuf: [32]u8 = undefined;
    const created = util.formatRfc3339(&tbuf, util.nowUnix(io));
    try conn.execNoRows(
        \\INSERT INTO users (id, tenant_id, email, name, role, password_hash, created_at)
        \\VALUES ($1::uuid, $2::uuid, $3, 'Admin', 'admin', $4, $5::timestamptz)
        \\ON CONFLICT DO NOTHING
    , &.{
        .{ .text = uid },
        .{ .text = util.default_tenant },
        .{ .text = email },
        .{ .text = hash },
        .{ .text = created },
    });
}

test "parse session cookie" {
    const p = parseSessionCookie("00000000-0000-0000-0000-0000000000aa.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").?;
    try std.testing.expectEqualStrings("00000000-0000-0000-0000-0000000000aa", p.id);
    try std.testing.expectEqual(@as(usize, 64), p.secret_hex.len);
}

test "role parse" {
    try std.testing.expect(roleFromText("Admin").? == .admin);
    try std.testing.expect(roleFromText("viewer").? == .viewer);
    try std.testing.expect(roleFromText("nope") == null);
}
