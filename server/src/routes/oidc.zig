//! Microsoft Entra ID sign-in: OpenID Connect authorisation code flow with
//! PKCE (S256). Setup steps are in docs/entra-sso.md.
//!
//!   GET /api/auth/oidc/start?tenant=<tawny tenant uuid>
//!       Reads tenant_oidc, fetches discovery (cached), stores state, nonce
//!       and the PKCE verifier in oauth_states, redirects to Entra.
//!   GET /api/auth/oidc/callback?code=&state=
//!       Takes the state row once, exchanges the code with the client secret
//!       (decrypted from TAWNY_INTEGRATION_ENCRYPTION_KEY), verifies the ID
//!       token: RS256 signature against the JWKS (cached, refetched once for
//!       an unknown kid), iss, aud, exp, nbf, nonce, and tid. Users match on
//!       (tid, oid), never email. Groups map to a role; no matching group
//!       means no account.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");
const audit = @import("../http/audit.zig");
const jwt = @import("../crypto/jwt.zig");
const secrets = @import("../crypto/secret_box.zig");
const settings = @import("settings.zig");
const egress = @import("../sinks/egress.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Route permissions, enforced by http/permissions.zig before the handler runs.
pub const routes = [_]@import("../http/permissions.zig").Route{
    .{ .method = .GET, .path = "/api/auth/oidc/start", .perm = .public },
    .{ .method = .GET, .path = "/api/auth/oidc/callback", .perm = .public },
};

/// Clock skew allowed on exp and nbf.
pub const leeway_seconds: i64 = 120;
const jwks_max_age_seconds: i64 = 24 * 3600;

fn freeRows(allocator: std.mem.Allocator, rows: []pg.Row) void {
    for (rows) |row| row.deinit(allocator);
    allocator.free(rows);
}

fn envSpan(name: [*:0]const u8) ?[]const u8 {
    const z = std.c.getenv(name) orelse return null;
    const s = std.mem.span(z);
    return if (s.len == 0) null else s;
}

fn trimSlash(s: []const u8) []const u8 {
    var end = s.len;
    while (end > 0 and s[end - 1] == '/') end -= 1;
    return s[0..end];
}

fn pct(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const hex = "0123456789ABCDEF";
    for (text) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
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
    const out = try allocator.alloc(u8, std.base64.url_safe_no_pad.Encoder.calcSize(raw.len));
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, raw);
    return out;
}

fn b64urlDecode(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
    const trimmed = std.mem.trimEnd(u8, src, "=");
    const len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(trimmed) catch return error.InvalidToken;
    const out = try allocator.alloc(u8, len);
    errdefer allocator.free(out);
    std.base64.url_safe_no_pad.Decoder.decode(out, trimmed) catch return error.InvalidToken;
    return out;
}

pub fn pkceChallenge(allocator: std.mem.Allocator, verifier: []const u8) ![]u8 {
    var dig: [32]u8 = undefined;
    Sha256.hash(verifier, &dig, .{});
    return b64url(allocator, &dig);
}

// ------------------------------------------------------------------ config

pub const Config = struct {
    tenant_id: []const u8,
    entra_tenant_id: []const u8,
    authority: []const u8,
    client_id: []const u8,
    client_secret_ct: ?[]const u8,
    allowed_domains: []const []const u8,
    group_roles: std.json.Value,
    discovery: ?[]const u8,
    jwks: ?[]const u8,
    jwks_age: i64,
};

fn loadConfig(arena: std.mem.Allocator, conn: *pg.Conn, tenant_id: []const u8) !?Config {
    const rows = try conn.exec(arena,
        \\SELECT entra_tenant_id, authority, client_id, client_secret_encrypted,
        \\       array_to_json(allowed_domains)::text, group_roles::text, discovery_json::text, jwks_json::text,
        \\       coalesce(extract(epoch FROM now() - jwks_fetched_at)::bigint, 999999999)::text
        \\FROM tenant_oidc WHERE tenant_id = $1::uuid AND enabled
    , &.{.{ .text = tenant_id }});
    if (rows.len == 0) return null;
    const c = rows[0].cols;
    const etid = c[0] orelse return null;
    const authority = if (c[1]) |a| trimSlash(a) else try std.fmt.allocPrint(arena, "https://login.microsoftonline.com/{s}/v2.0", .{etid});
    return .{
        .tenant_id = tenant_id,
        .entra_tenant_id = etid,
        .authority = authority,
        .client_id = c[2] orelse return null,
        .client_secret_ct = c[3],
        .allowed_domains = try std.json.parseFromSliceLeaky([]const []const u8, arena, c[4] orelse "[]", .{}),
        .group_roles = try std.json.parseFromSliceLeaky(std.json.Value, arena, c[5] orelse "{}", .{}),
        .discovery = c[6],
        .jwks = c[7],
        .jwks_age = std.fmt.parseInt(i64, c[8] orelse "999999999", 10) catch 999999999,
    };
}

pub const Discovery = struct {
    issuer: []const u8,
    authorization_endpoint: []const u8,
    token_endpoint: []const u8,
    jwks_uri: []const u8,
};

/// Endpoints must be https to a public host. TAWNY_OIDC_ALLOW_LOOPBACK=1
/// also allows http://127.0.0.1, for the contract suite's mock provider only.
pub fn endpointAllowed(url: []const u8, loopback_ok: bool) bool {
    if (std.mem.startsWith(u8, url, "https://")) {
        const rest = url["https://".len..];
        const end = std.mem.indexOfAny(u8, rest, ":/?#") orelse rest.len;
        return egress.allowed(rest[0..end], false);
    }
    return loopback_ok and std.mem.startsWith(u8, url, "http://127.0.0.1:");
}

fn loopbackOk() bool {
    const v = envSpan("TAWNY_OIDC_ALLOW_LOOPBACK") orelse return false;
    return std.mem.eql(u8, v, "1") or std.ascii.eqlIgnoreCase(v, "true");
}

fn discovery(arena: std.mem.Allocator, io: std.Io, conn: *pg.Conn, cfg: Config) !Discovery {
    const text = cfg.discovery orelse blk: {
        const url = try std.fmt.allocPrint(arena, "{s}/.well-known/openid-configuration", .{cfg.authority});
        if (!endpointAllowed(url, loopbackOk())) return error.EgressRefused;
        const body = try fetch(arena, io, .GET, url, null, null);
        _ = try std.json.parseFromSliceLeaky(Discovery, arena, body, .{ .ignore_unknown_fields = true });
        try conn.execNoRows("UPDATE tenant_oidc SET discovery_json = $2::jsonb WHERE tenant_id = $1::uuid", &.{
            .{ .text = cfg.tenant_id }, .{ .text = body },
        });
        break :blk body;
    };
    const d = try std.json.parseFromSliceLeaky(Discovery, arena, text, .{ .ignore_unknown_fields = true });
    const lo = loopbackOk();
    if (!endpointAllowed(d.authorization_endpoint, lo) or !endpointAllowed(d.token_endpoint, lo) or !endpointAllowed(d.jwks_uri, lo)) return error.EgressRefused;
    return d;
}

fn fetch(arena: std.mem.Allocator, io: std.Io, method: std.http.Method, url: []const u8, form: ?[]const u8, _: ?[]const u8) ![]u8 {
    var client: std.http.Client = .{ .allocator = arena, .io = io };
    defer client.deinit();
    var aw: std.Io.Writer.Allocating = .init(arena);
    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = method,
        .payload = form,
        .keep_alive = false,
        .redirect_behavior = .unhandled,
        .response_writer = &aw.writer,
        .headers = .{
            .user_agent = .{ .override = "tawny-server" },
            .accept_encoding = .{ .override = "identity" },
            .content_type = if (form != null) .{ .override = "application/x-www-form-urlencoded" } else .omit,
        },
        .extra_headers = &.{.{ .name = "accept", .value = "application/json" }},
    }) catch return error.ProviderUnreachable;
    if (result.status != .ok) return error.ProviderRefused;
    const body = aw.written();
    if (body.len > 256 * 1024) return error.ProviderRefused;
    return body;
}

// ------------------------------------------------------------------ start

pub fn start(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, request: *std.http.Server.Request, target: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const tenant = util.queryParam(target, "tenant") orelse util.default_tenant;
    if (tenant.len != 36 or !isUuid(tenant)) return util.problem(request, allocator, .bad_request, "tenant must be a UUID.");
    const cfg = (try loadConfig(arena, conn, tenant)) orelse return util.problem(request, allocator, .not_found, "Entra ID sign-in is not configured.");
    const d = discovery(arena, io, conn, cfg) catch return util.problem(request, allocator, .bad_gateway, "Entra ID discovery failed.");

    const state = try util.randomHex(io, arena, 32);
    const nonce = try util.randomHex(io, arena, 32);
    const verifier = try util.randomHex(io, arena, 32);
    const challenge = try pkceChallenge(arena, verifier);
    const now = util.nowUnix(io);
    var t1: [32]u8 = undefined;
    var t2: [32]u8 = undefined;
    const created = util.formatRfc3339(&t1, now);
    const expires = util.formatRfc3339(&t2, now + 10 * 60);
    conn.execNoRows("DELETE FROM oauth_states WHERE expires_at < $1::timestamptz", &.{.{ .text = created }}) catch {};
    try conn.execNoRows(
        \\INSERT INTO oauth_states (state, pkce_verifier, created_at, expires_at, provider, nonce, tenant_id)
        \\VALUES ($1, $2, $3::timestamptz, $4::timestamptz, 'oidc', $5, $6::uuid)
    , &.{ .{ .text = state }, .{ .text = verifier }, .{ .text = created }, .{ .text = expires }, .{ .text = nonce }, .{ .text = tenant } });

    const redirect_uri = try redirectUri(arena);
    const location = try std.fmt.allocPrint(arena, "{s}{s}client_id={s}&response_type=code&redirect_uri={s}&response_mode=query&scope=openid%20profile%20email&state={s}&nonce={s}&code_challenge={s}&code_challenge_method=S256", .{
        d.authorization_endpoint,
        if (std.mem.indexOfScalar(u8, d.authorization_endpoint, '?') == null) "?" else "&",
        try pct(arena, cfg.client_id),
        try pct(arena, redirect_uri),
        state,
        nonce,
        challenge,
    });
    try request.respond("", .{
        .status = .found,
        .extra_headers = &.{.{ .name = "location", .value = location }},
        .keep_alive = false,
    });
}

fn redirectUri(arena: std.mem.Allocator) ![]u8 {
    const public = trimSlash(envSpan("TAWNY_PUBLIC_URL") orelse "http://127.0.0.1:8080");
    return std.fmt.allocPrint(arena, "{s}/api/auth/oidc/callback", .{public});
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

// ------------------------------------------------------------------ token checks

pub const Expect = struct {
    issuer: []const u8,
    client_id: []const u8,
    nonce: []const u8,
    entra_tenant_id: []const u8,
    now: i64,
};

pub const Identity = struct {
    oid: []const u8,
    tid: []const u8,
    email: []const u8,
    name: []const u8,
    groups: []const []const u8,
};

pub const TokenError = error{
    InvalidToken,
    WrongAlgorithm,
    UnknownKey,
    InvalidSignature,
    BadIssuer,
    BadAudience,
    Expired,
    NotYetValid,
    BadNonce,
    BadTenant,
    MissingClaim,
};

const Jwk = struct { kty: []const u8 = "", kid: ?[]const u8 = null, n: ?[]const u8 = null, e: ?[]const u8 = null, use: ?[]const u8 = null };
const Jwks = struct { keys: []const Jwk = &.{} };

/// Header kid of a compact JWT, or null.
pub fn tokenKid(arena: std.mem.Allocator, token: []const u8) ?[]const u8 {
    const dot = std.mem.indexOfScalar(u8, token, '.') orelse return null;
    const raw = b64urlDecode(arena, token[0..dot]) catch return null;
    const H = struct { kid: ?[]const u8 = null };
    const h = std.json.parseFromSliceLeaky(H, arena, raw, .{ .ignore_unknown_fields = true }) catch return null;
    return h.kid;
}

/// Verify an ID token. The signature is checked first with the existing
/// RS256 code (crypto/jwt.zig); claims are read only after it passes.
pub fn verifyIdToken(arena: std.mem.Allocator, token: []const u8, jwks_text: []const u8, want: Expect) TokenError!Identity {
    const jwks = std.json.parseFromSliceLeaky(Jwks, arena, jwks_text, .{ .ignore_unknown_fields = true }) catch return error.UnknownKey;
    const kid = tokenKid(arena, token);
    var key: ?Jwk = null;
    for (jwks.keys) |k| {
        if (!std.mem.eql(u8, k.kty, "RSA")) continue;
        if (k.use) |u| if (!std.mem.eql(u8, u, "sig")) continue;
        if (kid) |want_kid| {
            if (k.kid == null or !std.mem.eql(u8, k.kid.?, want_kid)) continue;
        }
        key = k;
        break;
    }
    const k = key orelse return error.UnknownKey;
    const n = b64urlDecode(arena, k.n orelse return error.UnknownKey) catch return error.UnknownKey;
    const e = b64urlDecode(arena, k.e orelse return error.UnknownKey) catch return error.UnknownKey;
    jwt.verifyRs256(arena, token, n, e) catch |err| return switch (err) {
        error.WrongAlgorithm => error.WrongAlgorithm,
        error.InvalidSignature, error.InvalidKey, error.UnsupportedModulus => error.InvalidSignature,
        else => error.InvalidToken,
    };

    const dot1 = std.mem.indexOfScalar(u8, token, '.') orelse return error.InvalidToken;
    const dot2 = std.mem.indexOfScalarPos(u8, token, dot1 + 1, '.') orelse return error.InvalidToken;
    const payload = b64urlDecode(arena, token[dot1 + 1 .. dot2]) catch return error.InvalidToken;
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, payload, .{}) catch return error.InvalidToken;
    if (v != .object) return error.InvalidToken;
    const o = v.object;

    const iss = str(o, "iss") orelse return error.BadIssuer;
    if (!std.mem.eql(u8, iss, want.issuer)) return error.BadIssuer;
    // aud is a string or an array; Entra sends the client id string.
    const aud_ok = switch (o.get("aud") orelse return error.BadAudience) {
        .string => |s| std.mem.eql(u8, s, want.client_id),
        .array => |arr| blk: {
            for (arr.items) |x| {
                if (x == .string and std.mem.eql(u8, x.string, want.client_id)) break :blk true;
            }
            break :blk false;
        },
        else => false,
    };
    if (!aud_ok) return error.BadAudience;
    const exp = int(o, "exp") orelse return error.Expired;
    if (want.now >= exp + leeway_seconds) return error.Expired;
    if (int(o, "nbf")) |nbf| {
        if (want.now + leeway_seconds < nbf) return error.NotYetValid;
    }
    const nonce = str(o, "nonce") orelse return error.BadNonce;
    if (!timingEql(nonce, want.nonce)) return error.BadNonce;
    const tid = str(o, "tid") orelse return error.MissingClaim;
    if (!std.ascii.eqlIgnoreCase(tid, want.entra_tenant_id)) return error.BadTenant;
    const oid = str(o, "oid") orelse return error.MissingClaim;
    if (oid.len == 0 or oid.len > 100) return error.MissingClaim;

    var groups: std.ArrayList([]const u8) = .empty;
    if (o.get("groups")) |g| {
        if (g == .array) for (g.array.items) |x| {
            if (x == .string) groups.append(arena, x.string) catch return error.InvalidToken;
        };
    }
    const email = str(o, "email") orelse str(o, "preferred_username") orelse "";
    return .{
        .oid = oid,
        .tid = tid,
        .email = email,
        .name = str(o, "name") orelse email,
        .groups = groups.items,
    };
}

fn timingEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

fn str(o: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = o.get(key) orelse return null;
    return if (v == .string) v.string else null;
}

fn int(o: std.json.ObjectMap, key: []const u8) ?i64 {
    const v = o.get(key) orelse return null;
    return switch (v) {
        .integer => |n| n,
        .float => |f| @intFromFloat(f),
        else => null,
    };
}

/// Highest role among the user's groups. Null when no group is mapped.
pub fn roleForGroups(group_roles: std.json.Value, groups: []const []const u8) ?auth.Role {
    if (group_roles != .object) return null;
    var best: ?auth.Role = null;
    for (groups) |g| {
        const v = group_roles.object.get(g) orelse continue;
        if (v != .string) continue;
        const r = auth.roleFromText(v.string) orelse continue;
        if (best == null or rank(r) > rank(best.?)) best = r;
    }
    return best;
}

fn rank(r: auth.Role) u8 {
    return switch (r) {
        .viewer => 0,
        .analyst => 1,
        .admin => 2,
    };
}

pub fn domainAllowed(allowed: []const []const u8, email: []const u8) bool {
    if (allowed.len == 0) return true;
    const at = std.mem.lastIndexOfScalar(u8, email, '@') orelse return false;
    const domain = email[at + 1 ..];
    for (allowed) |d| {
        if (std.ascii.eqlIgnoreCase(d, domain)) return true;
    }
    return false;
}

// ------------------------------------------------------------------ callback

fn refuse(request: *std.http.Server.Request, allocator: std.mem.Allocator, status: std.http.Status, title: []const u8) !void {
    return util.problem(request, allocator, status, title);
}

pub fn callback(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, request: *std.http.Server.Request, target: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    if (util.queryParam(target, "error") != null) return refuse(request, allocator, .unauthorized, "Entra ID sign-in was cancelled or refused.");
    const code_raw = util.queryParam(target, "code") orelse return refuse(request, allocator, .bad_request, "Invalid OAuth state.");
    const state = util.queryParam(target, "state") orelse return refuse(request, allocator, .bad_request, "Invalid OAuth state.");
    if (code_raw.len == 0 or code_raw.len > 4096 or state.len == 0 or state.len > 128) return refuse(request, allocator, .bad_request, "Invalid OAuth state.");
    const code = try util.percentDecode(arena, code_raw);

    // One use: the row is deleted as it is read.
    var tbuf: [32]u8 = undefined;
    const now = util.nowUnix(io);
    const st_rows = try conn.exec(arena,
        \\DELETE FROM oauth_states WHERE state = $1 AND provider = 'oidc' AND expires_at > $2::timestamptz
        \\RETURNING pkce_verifier, nonce, tenant_id::text
    , &.{ .{ .text = state }, .{ .text = util.formatRfc3339(&tbuf, now) } });
    if (st_rows.len == 0) return refuse(request, allocator, .bad_request, "Invalid OAuth state.");
    const verifier = st_rows[0].cols[0] orelse return refuse(request, allocator, .bad_request, "Invalid OAuth state.");
    const nonce = st_rows[0].cols[1] orelse return refuse(request, allocator, .bad_request, "Invalid OAuth state.");
    const tenant = st_rows[0].cols[2] orelse return refuse(request, allocator, .bad_request, "Invalid OAuth state.");

    const cfg = (try loadConfig(arena, conn, tenant)) orelse return refuse(request, allocator, .not_found, "Entra ID sign-in is not configured.");
    const d = discovery(arena, io, conn, cfg) catch return refuse(request, allocator, .bad_gateway, "Entra ID discovery failed.");
    const secret_ct = cfg.client_secret_ct orelse return refuse(request, allocator, .service_unavailable, "Entra ID client secret is not set.");
    const key = settings.envSecret();
    if (key.len == 0) return refuse(request, allocator, .service_unavailable, "TAWNY_INTEGRATION_ENCRYPTION_KEY is not set.");
    const client_secret = secrets.unprotect(arena, key, secret_ct) catch return refuse(request, allocator, .service_unavailable, "Entra ID client secret cannot be decrypted.");

    const redirect_uri = try redirectUri(arena);
    const form = try std.fmt.allocPrint(arena, "grant_type=authorization_code&client_id={s}&client_secret={s}&code={s}&redirect_uri={s}&code_verifier={s}", .{
        try pct(arena, cfg.client_id), try pct(arena, client_secret), try pct(arena, code), try pct(arena, redirect_uri), try pct(arena, verifier),
    });
    const token_body = fetch(arena, io, .POST, d.token_endpoint, form, null) catch return refuse(request, allocator, .bad_gateway, "Entra ID token exchange failed.");
    const Tok = struct { id_token: []const u8 = "" };
    const tok = std.json.parseFromSliceLeaky(Tok, arena, token_body, .{ .ignore_unknown_fields = true }) catch return refuse(request, allocator, .bad_gateway, "Entra ID token exchange failed.");
    if (tok.id_token.len == 0) return refuse(request, allocator, .bad_gateway, "Entra ID returned no ID token.");

    // Entra's v2.0 issuer names the tenant: https://login.microsoftonline.com/<tid>/v2.0.
    // Discovery for a specific tenant gives that exact string.
    const want: Expect = .{ .issuer = d.issuer, .client_id = cfg.client_id, .nonce = nonce, .entra_tenant_id = cfg.entra_tenant_id, .now = now };
    var jwks_text = try jwksFor(arena, io, conn, cfg, d, false);
    var ident = verifyIdToken(arena, tok.id_token, jwks_text, want);
    if (ident == error.UnknownKey) {
        // Keys rotate. Refetch once, then give up.
        jwks_text = try jwksFor(arena, io, conn, cfg, d, true);
        ident = verifyIdToken(arena, tok.id_token, jwks_text, want);
    }
    const id = ident catch |err| {
        std.debug.print("oidc: id token refused: {s}\n", .{@errorName(err)});
        return refuse(request, allocator, .unauthorized, "Entra ID token was not valid.");
    };

    if (!domainAllowed(cfg.allowed_domains, id.email)) return refuse(request, allocator, .forbidden, "This account's domain is not allowed.");
    const role = roleForGroups(cfg.group_roles, id.groups) orelse {
        try audit.add(allocator, io, conn, tenant, null, "oidc.refused_no_group", id.oid, null);
        return refuse(request, allocator, .forbidden, "Your Entra ID groups do not grant access to Tawny.");
    };

    const user_id = try upsertUser(arena, io, conn, tenant, id, role) orelse return refuse(request, allocator, .forbidden, "This account is disabled.");
    try audit.add(allocator, io, conn, tenant, user_id, "oidc.sign_in", null, null);
    const sess = try auth.createSession(arena, io, conn, user_id, tenant);
    const cookie_hdr = try std.fmt.allocPrint(arena, "{s}={s}; Path=/; HttpOnly; Secure; SameSite=Lax", .{ auth.session_cookie_name, sess.cookie });
    const public = trimSlash(envSpan("TAWNY_PUBLIC_URL") orelse "http://127.0.0.1:8080");
    const location = try std.fmt.allocPrint(arena, "{s}/", .{public});
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

fn jwksFor(arena: std.mem.Allocator, io: std.Io, conn: *pg.Conn, cfg: Config, d: Discovery, force: bool) ![]const u8 {
    if (!force and cfg.jwks != null and cfg.jwks_age < jwks_max_age_seconds) return cfg.jwks.?;
    const body = fetch(arena, io, .GET, d.jwks_uri, null, null) catch return cfg.jwks orelse "{\"keys\":[]}";
    _ = std.json.parseFromSliceLeaky(Jwks, arena, body, .{ .ignore_unknown_fields = true }) catch return cfg.jwks orelse "{\"keys\":[]}";
    try conn.execNoRows("UPDATE tenant_oidc SET jwks_json = $2::jsonb, jwks_fetched_at = now() WHERE tenant_id = $1::uuid", &.{
        .{ .text = cfg.tenant_id }, .{ .text = body },
    });
    return body;
}

/// Find by (tid, oid). First sign-in creates the user. The role follows the
/// groups on every sign-in, so removing someone from a group takes effect at
/// their next sign-in. Returns null for a disabled user.
fn upsertUser(arena: std.mem.Allocator, io: std.Io, conn: *pg.Conn, tenant: []const u8, id: Identity, role: auth.Role) !?[]const u8 {
    const found = try conn.exec(arena,
        \\SELECT id::text, disabled_at::text FROM users WHERE tenant_id = $1::uuid AND oidc_tid = $2 AND oidc_oid = $3 LIMIT 1
    , &.{ .{ .text = tenant }, .{ .text = std.ascii.allocLowerString(arena, id.tid) catch id.tid }, .{ .text = id.oid } });
    if (found.len > 0) {
        if (found[0].cols[1] != null) return null;
        const uid = found[0].cols[0].?;
        try conn.execNoRows("UPDATE users SET role = $2, name = $3 WHERE id = $1::uuid", &.{
            .{ .text = uid }, .{ .text = auth.roleText(role) }, .{ .text = id.name },
        });
        return uid;
    }
    var id_buf: [36]u8 = undefined;
    const uid = try arena.dupe(u8, util.newUuid(io, &id_buf));
    var tbuf: [32]u8 = undefined;
    // Email is display only. It need not be unique across identities, so an
    // address already held by a password user gets the oid appended.
    const email = if (id.email.len > 0) id.email else try std.fmt.allocPrint(arena, "{s}@entra.invalid", .{id.oid});
    const taken = try conn.exec(arena, "SELECT 1 FROM users WHERE tenant_id = $1::uuid AND lower(email) = lower($2)", &.{ .{ .text = tenant }, .{ .text = email } });
    const stored_email = if (taken.len > 0) try std.fmt.allocPrint(arena, "{s}#{s}", .{ email, id.oid }) else email;
    try conn.execNoRows(
        \\INSERT INTO users (id, tenant_id, email, name, role, password_hash, created_at, oidc_tid, oidc_oid)
        \\VALUES ($1::uuid, $2::uuid, $3, $4, $5, NULL, $6::timestamptz, $7, $8)
    , &.{
        .{ .text = uid },
        .{ .text = tenant },
        .{ .text = stored_email },
        .{ .text = id.name },
        .{ .text = auth.roleText(role) },
        .{ .text = util.formatRfc3339(&tbuf, util.nowUnix(io)) },
        .{ .text = try std.ascii.allocLowerString(arena, id.tid) },
        .{ .text = id.oid },
    });
    return uid;
}

// ------------------------------------------------------------------ tests

test "pkce challenge matches rfc 7636 appendix b" {
    const a = std.testing.allocator;
    const c = try pkceChallenge(a, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    defer a.free(c);
    try std.testing.expectEqualStrings("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", c);
}

test "groups map to the highest role and unmapped users are refused" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const map = try std.json.parseFromSliceLeaky(std.json.Value, arena,
        \\{"g-view":"viewer","g-an":"analyst","g-adm":"admin","g-bad":"owner"}
    , .{});
    try std.testing.expectEqual(auth.Role.analyst, roleForGroups(map, &.{ "g-view", "g-an" }).?);
    try std.testing.expectEqual(auth.Role.admin, roleForGroups(map, &.{ "g-adm", "g-view" }).?);
    try std.testing.expect(roleForGroups(map, &.{ "other", "g-bad" }) == null);
    try std.testing.expect(roleForGroups(map, &.{}) == null);
    try std.testing.expect(domainAllowed(&.{}, "a@b.c"));
    try std.testing.expect(domainAllowed(&.{"Example.com"}, "a@example.COM"));
    try std.testing.expect(!domainAllowed(&.{"example.com"}, "a@evil.com"));
    try std.testing.expect(!domainAllowed(&.{"example.com"}, "no-at-sign"));
}

// Test vectors: one RS256 key made with `openssl genrsa 2048` for this test
// and then deleted, so only the public modulus is here. Claims:
// iss=https://login.example/t1/v2.0, aud=client-1, nonce=n1, tid=T1, oid=o1,
// nbf=1000, exp=5000, groups=[g1]. Each tok_<x> changes one claim.
const test_n = "wvND6hS2OY8bZD3y_biQT-3LLRWVjeGdgszV7S8Qb1Dql3ooJou0lfjmO6FEX1tponoqnchywQaME5q0OqtcR9qywXWGA4hC0TxWd4x1zP2dB90SSRt5bCph0yDsYLH62DHzkRCX80MG_yLwKamDqahUbfVjCjZzO1tK25n1jm2fTUzyous8KFiMREDFHkpRtvc-0uc_g1w44iaaHvwmFnreTV8ufSG1_4ubhVqEBNJk8NxQXNq0qXjSeBGVs5GUncl5Tw571gURT6DHfvaT7ub0vpo0cQHIrdfM8Dr9X0oLIamKE4eR4FgQAgn7tZg0Q7tQeUhaPr-fJZgKoGSKqw";
const tok_valid = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2xvZ2luLmV4YW1wbGUvdDEvdjIuMCIsImF1ZCI6ImNsaWVudC0xIiwibm9uY2UiOiJuMSIsInRpZCI6IlQxIiwib2lkIjoibzEiLCJuYmYiOjEwMDAsImV4cCI6NTAwMCwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsIm5hbWUiOiJBbGljZSIsImdyb3VwcyI6WyJnMSJdfQ.YgY2Q28J4O382dpmDcucGphg45NfaOzkQF7j629dC2VHSePrBzZYw-kiwl7R6OZGdD8i6egGPegNwfGZTAejic2Dm2bw4410AR_yrV6Rb6rfVCJRFJEGUN-Xv7H79DvLF506ButW0AOaxtedB50U3G-WYGRrcd5crRp8ULVhbYSwmfvmqH0T6Jl8sKJkOYnD5EPXQlpql4GmxdmxS402MUEpiHO3htvdRpxe6IOMB0dTi9p8nHRlIjgxln-cZB6HcR-Bvh4E3QwkFUzRAx7xTiy1hT32Ovg7SG41Tqq5uViAE-1CkkGO06xAxe1mhxM35rG_JtXI-PdOxD5yblXkMg";
const tok_iss = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2V2aWwvdjIuMCIsImF1ZCI6ImNsaWVudC0xIiwibm9uY2UiOiJuMSIsInRpZCI6IlQxIiwib2lkIjoibzEiLCJuYmYiOjEwMDAsImV4cCI6NTAwMCwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsIm5hbWUiOiJBbGljZSIsImdyb3VwcyI6WyJnMSJdfQ.X8BjrAgRQWkFaZCfQi43WULJdGPUn6EfGzpN5mGynYDpAZYlc-1cduLXcafwpddAEXpLzr6BCn51-scsEq_AvHDliFzsAS4eHrTwtzGqV8N8-zd8NzW_QwYX2CIT_LsJGacB6L9xpdiMpIbvrRpTIoquG-S-eIFiBPRerE6dNOICHx-RwMXEQvqS8pOjCSdRhynXh33hQdL8UFad3pS6Jcl-JmwwNC_7wUu_d-9shSdpo6D2ez59X1X5hcRzbWZ0Uo61GtBmf1v4dSBAbMmHH-6EiD5tSpufz45rfBun3ZLRcBIQm5hs5QWRGHAS2mzOwcOx1GcxBoMFO1b9hQBaJw";
const tok_aud = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2xvZ2luLmV4YW1wbGUvdDEvdjIuMCIsImF1ZCI6Im90aGVyIiwibm9uY2UiOiJuMSIsInRpZCI6IlQxIiwib2lkIjoibzEiLCJuYmYiOjEwMDAsImV4cCI6NTAwMCwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsIm5hbWUiOiJBbGljZSIsImdyb3VwcyI6WyJnMSJdfQ.gFj6VK1ySlexYnWCJTzTfra4Pp989-2_dMYXoW43alM1d3AP-yYn1Jr7X-UP-e3TxthrNZOpKsQwW0lfHilNS4Ug_-kjL3U3UVRtdxJf-AvsF3DTJkpRoKdEYmy2Afxj8FZ5sxzjNaRE5655hEjcJoCk0aVNJjC0WdnvMQf45JhJEACztCkX2PgaNFKkmv0i16hLZBQ9uuQYuGsrXvdmwLo76kQpbXmseCS9kgdhDZLUu2AfA0A8DCUXFq2ehm03876m7vAYfeK5EBoS8Dhi0dMzvsCeMe4gbKVnjLculS_uKMglNXvdU3bGZLuTUgaPQJJh7nlvRAawS6v-YmcONg";
const tok_exp = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2xvZ2luLmV4YW1wbGUvdDEvdjIuMCIsImF1ZCI6ImNsaWVudC0xIiwibm9uY2UiOiJuMSIsInRpZCI6IlQxIiwib2lkIjoibzEiLCJuYmYiOjEwMDAsImV4cCI6MTUwMCwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsIm5hbWUiOiJBbGljZSIsImdyb3VwcyI6WyJnMSJdfQ.GCS4FjQeCMevhCo-9PM-xyiNBTAi1x7pkEhLh24cO4KYt0lnyCKyJWPmqVriip3LfOjvToSZjFiNDZcIb6uLMZcPyYN35C84mApvylMGlI4nVlhG6yiBa0_3PnQzmXBfMYGEECll-UyJmMXYSHI5PjHDIAOnN8Fc6oPbAkE1dkkabFtaZwsua1zicN6pdAVUVQq-UemPKku2bRvohPCqs5zL4fmBe9GuV9HhDniD1TnhXdVkd9aQvmIceJ-c4i2O61kMQVjj6iamGmajsTAKpmzhnTlmi1OgikEVSoDSSpwLTeXhkIW-Rg8QhVWNvsy_1BXGEw5JJzn3fQJbV1gIsA";
const tok_nbf = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2xvZ2luLmV4YW1wbGUvdDEvdjIuMCIsImF1ZCI6ImNsaWVudC0xIiwibm9uY2UiOiJuMSIsInRpZCI6IlQxIiwib2lkIjoibzEiLCJuYmYiOjQwMDAsImV4cCI6NTAwMCwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsIm5hbWUiOiJBbGljZSIsImdyb3VwcyI6WyJnMSJdfQ.HKb5k7uugs68aBLSMHAvv6Z-VSNS-KMkY3wnMLGUY5GjWM5Cve8WYfXOtrdS2RVYvEd7s5_p6CGuq2dU8XpiBF9_jfRJkMQWyRlzSFA7YkSWD-CqiRuVQ7bLmsAbj_Ly4pq0mFfVnb8qujbJZJM2BxEFtRJ5Dmh8sFTVezaTSYVl0m0jbNKhfVZYUAJRi_aUN9W02uyu5JnC6VNmpanvXtCm9S4Zbxb8Io_YjuQn7mP_WIrAHNfXG-sEQ39HvByoIz2D5P091_qd0SK4l6Asecmkn_9zK0KS-PiWAbowDRE2DW3OxoamPDHSKFBMscO-ixOh15XGN5uQfQjF2h0YuA";
const tok_nonce = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2xvZ2luLmV4YW1wbGUvdDEvdjIuMCIsImF1ZCI6ImNsaWVudC0xIiwibm9uY2UiOiJuMiIsInRpZCI6IlQxIiwib2lkIjoibzEiLCJuYmYiOjEwMDAsImV4cCI6NTAwMCwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsIm5hbWUiOiJBbGljZSIsImdyb3VwcyI6WyJnMSJdfQ.m1YOfhO9rRzF4L2ImLkCDGE3s5XwWdcSlyZvFIcE-O823RUPe7tN-GT197mlpc0GqPYVMsFhjPjHns7_F0mUNC9DnDlRD0-F7EyrCb_pzVqGu6cgtGGTPI_4mSkP_23inAcf4Qul8RmwjBx7oiVngSJYN_lbAdrna6iwvQsofx5U5oPOtPrZ6reTV3ZBYatoKdFFXk0RGD_8vbHEAF9g4n3TSHd8cJe9tQ8mpoLUnc-ExuE_Dcm3TmTVzEbxYor0ewyiJtv-yimJwF-zJmq-qc-8v8CFwv_d0HdnpMMJN721cFy-a123pMz4RsrY8wRW1Li_z4tkpqjhmePQTYDauw";
const tok_tid = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2xvZ2luLmV4YW1wbGUvdDEvdjIuMCIsImF1ZCI6ImNsaWVudC0xIiwibm9uY2UiOiJuMSIsInRpZCI6IlQyIiwib2lkIjoibzEiLCJuYmYiOjEwMDAsImV4cCI6NTAwMCwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsIm5hbWUiOiJBbGljZSIsImdyb3VwcyI6WyJnMSJdfQ.j0iEoBzHb5TMdf0Vkwbdor0wL3j6XtNDdgOu2K1f8S0drw0JaaG7gFNh3Nfj4ivFWdz0FqbHNsd734WQrq1JXqkubMLvfAeBch1s--PKxeS2ASpNi8HFffQ1_Kfjcx1z-6CP0Ll3IZNOALY59b-lqxe6h0FmFF76QUpW3nb6oKxb_n-BweSP5XP9tWNrHVBQo8fzxc4ze_dwWhw-VX8mYqZa8EwWvvPyeD2rw8dBLXUmD2dGWDQe25f2bQWEXrlAI5ZYDT6XJ4FtjpkZcgtGnYI5BHuC_o3Bw8_0oaOdoSVsVnSUFSmh6RaDLrmduU5S__6AFb157gtVzl4CmpfePQ";

test "id token checks refuse a token with no matching key" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const jwks = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"other\",\"n\":\"" ++ test_n ++ "\",\"e\":\"AQAB\"}]}";
    const token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0.e30.AAAA";
    try std.testing.expectError(error.UnknownKey, verifyIdToken(arena, token, jwks, .{
        .issuer = "x", .client_id = "x", .nonce = "x", .entra_tenant_id = "x", .now = 0,
    }));
    try std.testing.expectEqualStrings("k1", tokenKid(arena, token).?);
    // A key with the right kid but a forged signature fails the signature check.
    const jwks2 = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k1\",\"n\":\"" ++ test_n ++ "\",\"e\":\"AQAB\"}]}";
    try std.testing.expectError(error.InvalidSignature, verifyIdToken(arena, token, jwks2, .{
        .issuer = "x", .client_id = "x", .nonce = "x", .entra_tenant_id = "x", .now = 0,
    }));
}

test "id token: iss, aud, exp, nbf, nonce and tid are each enforced" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const jwks = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"k1\",\"n\":\"" ++ test_n ++ "\",\"e\":\"AQAB\"}]}";
    const want: Expect = .{ .issuer = "https://login.example/t1/v2.0", .client_id = "client-1", .nonce = "n1", .entra_tenant_id = "t1", .now = 2000 };
    const id = try verifyIdToken(arena, tok_valid, jwks, want);
    try std.testing.expectEqualStrings("o1", id.oid);
    try std.testing.expectEqualStrings("T1", id.tid);
    try std.testing.expectEqualStrings("g1", id.groups[0]);
    try std.testing.expectError(error.BadIssuer, verifyIdToken(arena, tok_iss, jwks, want));
    try std.testing.expectError(error.BadAudience, verifyIdToken(arena, tok_aud, jwks, want));
    try std.testing.expectError(error.Expired, verifyIdToken(arena, tok_exp, jwks, want));
    try std.testing.expectError(error.NotYetValid, verifyIdToken(arena, tok_nbf, jwks, want));
    try std.testing.expectError(error.BadNonce, verifyIdToken(arena, tok_nonce, jwks, want));
    try std.testing.expectError(error.BadTenant, verifyIdToken(arena, tok_tid, jwks, want));
    // The valid token expires: 5000 + leeway.
    var late = want;
    late.now = 5000 + leeway_seconds;
    try std.testing.expectError(error.Expired, verifyIdToken(arena, tok_valid, jwks, late));
    // A changed payload breaks the signature.
    var forged = try arena.dupe(u8, tok_valid);
    const dot = std.mem.indexOfScalar(u8, forged, '.').?;
    forged[dot + 5] = if (forged[dot + 5] == 'A') 'B' else 'A';
    try std.testing.expectError(error.InvalidSignature, verifyIdToken(arena, forged, jwks, want));
}

test "provider endpoints must be https to a public host" {
    try std.testing.expect(endpointAllowed("https://login.microsoftonline.com/x/v2.0", false));
    try std.testing.expect(!endpointAllowed("http://login.microsoftonline.com/x", false));
    try std.testing.expect(!endpointAllowed("https://169.254.169.254/latest", false));
    try std.testing.expect(!endpointAllowed("https://localhost/x", false));
    try std.testing.expect(!endpointAllowed("http://127.0.0.1:9999/x", false));
    try std.testing.expect(endpointAllowed("http://127.0.0.1:9999/x", true));
    try std.testing.expect(!endpointAllowed("http://127.0.0.1.evil.example/x", true));
}
