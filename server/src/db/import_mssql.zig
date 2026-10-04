//! Idempotent import of a SQL Server + Better Auth export.
//! Agent id, credential version, and device public key are kept.
//! Pre-cutover `twny_` / `wte_` values are stored as the SHA-256 hex the
//! export already contains. `v1.` feed secrets are stored unchanged and
//! checked with the configured integration key.

const std = @import("std");
const pg = @import("pg/conn.zig");
const secrets = @import("../crypto/secret_box.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const tenant = "00000000-0000-0000-0000-000000000001";

const User = struct {
    id: []const u8,
    email: []const u8,
    name: []const u8 = "",
    role: []const u8 = "viewer",
    password_hash: []const u8,
};

const Agent = struct {
    id: []const u8,
    hostname: []const u8,
    operating_system: []const u8,
    os_version: []const u8,
    agent_version: []const u8,
    architecture: []const u8,
    credential_version: i64 = 1,
    device_public_key: []const u8 = "",
    status: []const u8 = "offline",
};

const ApiToken = struct {
    id: []const u8,
    name: []const u8,
    token_hash: []const u8,
    token_prefix: []const u8,
    role: []const u8 = "viewer",
};

const EnrollmentToken = struct {
    id: []const u8,
    token_hash: []const u8,
    expires_at: []const u8,
};

const Feed = struct {
    id: []const u8,
    name: []const u8,
    kind: []const u8,
    url: []const u8,
    auth_header_value_encrypted: []const u8 = "",
    default_severity: []const u8 = "medium",
};

const Export = struct {
    users: []const User,
    agents: []const Agent,
    api_tokens: []const ApiToken,
    enrollment_tokens: []const EnrollmentToken,
    threat_intel_feeds: []const Feed,
};

const Counts = struct { inserted: u32 = 0, unchanged: u32 = 0 };

pub fn run(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, path: []const u8) !void {
    const raw = try readFile(allocator, io, path);
    defer allocator.free(raw);
    var parsed = try std.json.parseFromSlice(Export, allocator, raw, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const doc = parsed.value;
    if (doc.users.len == 0) return error.MissingUser;

    var lines: std.ArrayList([]const u8) = .empty;
    defer {
        for (lines.items) |line| allocator.free(line);
        lines.deinit(allocator);
    }

    var user_counts = Counts{};
    var first_user: ?[36]u8 = null;
    for (doc.users) |user| {
        var id_buf: [36]u8 = undefined;
        legacyUuid(user.id, &id_buf);
        if (first_user == null) first_user = id_buf;
        const role = normalizeRole(user.role);
        const outcome = try upsertUser(allocator, conn, &id_buf, user, role);
        count(&user_counts, outcome);
        const line = try std.fmt.allocPrint(allocator, "user {s} {s} {s}", .{ &id_buf, user.email, user.password_hash });
        try lines.append(allocator, line);
    }
    const owner = first_user orelse return error.MissingUser;

    var agent_counts = Counts{};
    for (doc.agents) |agent| {
        const outcome = try upsertAgent(allocator, conn, agent);
        count(&agent_counts, outcome);
        const cv = try std.fmt.allocPrint(allocator, "{d}", .{agent.credential_version});
        defer allocator.free(cv);
        const line = try std.fmt.allocPrint(allocator, "agent {s} {s} {s}", .{ agent.id, cv, agent.device_public_key });
        try lines.append(allocator, line);
        std.debug.print("preserved agent id={s} credential_version={d} device_public_key={s}\n", .{
            agent.id, agent.credential_version, agent.device_public_key,
        });
    }

    var api_counts = Counts{};
    for (doc.api_tokens) |tok| {
        const outcome = try upsertApiToken(allocator, conn, tok, &owner);
        count(&api_counts, outcome);
        const line = try std.fmt.allocPrint(allocator, "api_token {s} {s}", .{ tok.id, tok.token_hash });
        try lines.append(allocator, line);
    }

    var enroll_counts = Counts{};
    for (doc.enrollment_tokens) |tok| {
        const outcome = try upsertEnrollment(allocator, conn, tok, &owner);
        count(&enroll_counts, outcome);
        const line = try std.fmt.allocPrint(allocator, "enrollment_token {s} {s}", .{ tok.id, tok.token_hash });
        try lines.append(allocator, line);
    }

    var feed_counts = Counts{};
    const key = envSpan("TAWNY_INTEGRATION_ENCRYPTION_KEY");
    for (doc.threat_intel_feeds) |feed| {
        if (secrets.isProtected(feed.auth_header_value_encrypted)) {
            if (key.len == 0) return error.MissingEncryptionKey;
            const opened = try secrets.unprotect(allocator, key, feed.auth_header_value_encrypted);
            defer allocator.free(opened);
            var dig: [Sha256.digest_length]u8 = undefined;
            Sha256.hash(opened, &dig, .{});
            const digest = hex(&dig);
            std.debug.print("secret_decrypt=ok plaintext_sha256={s}\n", .{digest[0..]});
        }
        const outcome = try upsertFeed(allocator, conn, feed, &owner);
        count(&feed_counts, outcome);
        const line = try std.fmt.allocPrint(allocator, "feed {s} {s}", .{ feed.id, feed.auth_header_value_encrypted });
        try lines.append(allocator, line);
    }

    std.mem.sort([]const u8, lines.items, {}, lineLess);
    var hasher = Sha256.init(.{});
    for (lines.items) |line| {
        hasher.update(line);
        hasher.update("\n");
    }
    var dig: [Sha256.digest_length]u8 = undefined;
    hasher.final(&dig);

    std.debug.print("users fixture={d} inserted={d} unchanged={d}\n", .{ doc.users.len, user_counts.inserted, user_counts.unchanged });
    std.debug.print("agents fixture={d} inserted={d} unchanged={d}\n", .{ doc.agents.len, agent_counts.inserted, agent_counts.unchanged });
    std.debug.print("api_tokens fixture={d} inserted={d} unchanged={d}\n", .{ doc.api_tokens.len, api_counts.inserted, api_counts.unchanged });
    std.debug.print("enrollment_tokens fixture={d} inserted={d} unchanged={d}\n", .{ doc.enrollment_tokens.len, enroll_counts.inserted, enroll_counts.unchanged });
    std.debug.print("threat_intel_feeds fixture={d} inserted={d} unchanged={d}\n", .{ doc.threat_intel_feeds.len, feed_counts.inserted, feed_counts.unchanged });
    const report = hex(&dig);
    std.debug.print("report_sha256={s}\n", .{report[0..]});
}

fn count(counts: *Counts, inserted: bool) void {
    if (inserted) counts.inserted += 1 else counts.unchanged += 1;
}

fn lineLess(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn upsertUser(allocator: std.mem.Allocator, conn: *pg.Conn, id: *const [36]u8, user: User, role: []const u8) !bool {
    const existing = try one(allocator, conn, "SELECT password_hash FROM users WHERE id = $1::uuid", &.{.{ .text = id }});
    defer if (existing) |row| row.deinit(allocator);
    if (existing) |row| {
        const hash = row.cols[0] orelse return error.Drift;
        if (!std.mem.eql(u8, hash, user.password_hash) and !std.mem.startsWith(u8, hash, "$argon2")) return error.Drift;
        return false;
    }
    try conn.execNoRows(
        \\INSERT INTO users (id, tenant_id, email, name, role, password_hash, created_at)
        \\VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, now())
    , &.{
        .{ .text = id },
        .{ .text = tenant },
        .{ .text = user.email },
        .{ .text = user.name },
        .{ .text = role },
        .{ .text = user.password_hash },
    });
    return true;
}

fn upsertAgent(allocator: std.mem.Allocator, conn: *pg.Conn, agent: Agent) !bool {
    const existing = try one(allocator, conn,
        \\SELECT credential_version::text, COALESCE(device_public_key, '')
        \\FROM agents WHERE id = $1::uuid
    , &.{.{ .text = agent.id }});
    defer if (existing) |row| row.deinit(allocator);
    if (existing) |row| {
        const cv = row.cols[0] orelse return error.Drift;
        const key = row.cols[1] orelse "";
        var cv_buf: [32]u8 = undefined;
        const want = std.fmt.bufPrint(&cv_buf, "{d}", .{agent.credential_version}) catch return error.Drift;
        if (!std.mem.eql(u8, cv, want) or !std.mem.eql(u8, key, agent.device_public_key)) return error.Drift;
        return false;
    }
    var cv_buf: [32]u8 = undefined;
    const cv = try std.fmt.bufPrint(&cv_buf, "{d}", .{agent.credential_version});
    try conn.execNoRows(
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status, credential_version, device_public_key
        \\) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, now(), $8, $9::int, $10)
    , &.{
        .{ .text = agent.id },
        .{ .text = tenant },
        .{ .text = agent.hostname },
        .{ .text = agent.operating_system },
        .{ .text = agent.os_version },
        .{ .text = agent.agent_version },
        .{ .text = agent.architecture },
        .{ .text = agent.status },
        .{ .text = cv },
        .{ .text = agent.device_public_key },
    });
    return true;
}

fn upsertApiToken(allocator: std.mem.Allocator, conn: *pg.Conn, tok: ApiToken, owner: *const [36]u8) !bool {
    const existing = try one(allocator, conn, "SELECT token_hash FROM api_tokens WHERE id = $1::uuid", &.{.{ .text = tok.id }});
    defer if (existing) |row| row.deinit(allocator);
    if (existing) |row| {
        const hash = row.cols[0] orelse return error.Drift;
        if (!std.mem.eql(u8, hash, tok.token_hash)) return error.Drift;
        return false;
    }
    try conn.execNoRows(
        \\INSERT INTO api_tokens (id, tenant_id, name, token_hash, token_prefix, created_by_user_id, role, created_at)
        \\VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::uuid, $7, now())
    , &.{
        .{ .text = tok.id },
        .{ .text = tenant },
        .{ .text = tok.name },
        .{ .text = tok.token_hash },
        .{ .text = tok.token_prefix },
        .{ .text = owner },
        .{ .text = normalizeRole(tok.role) },
    });
    return true;
}

fn upsertEnrollment(allocator: std.mem.Allocator, conn: *pg.Conn, tok: EnrollmentToken, owner: *const [36]u8) !bool {
    const existing = try one(allocator, conn, "SELECT token_hash FROM enrollment_tokens WHERE id = $1::uuid", &.{.{ .text = tok.id }});
    defer if (existing) |row| row.deinit(allocator);
    if (existing) |row| {
        const hash = row.cols[0] orelse return error.Drift;
        if (!std.mem.eql(u8, hash, tok.token_hash)) return error.Drift;
        return false;
    }
    try conn.execNoRows(
        \\INSERT INTO enrollment_tokens (id, tenant_id, token_hash, expires_at, created_by_user_id, created_at)
        \\VALUES ($1::uuid, $2::uuid, $3, $4::timestamptz, $5::uuid, now())
    , &.{
        .{ .text = tok.id },
        .{ .text = tenant },
        .{ .text = tok.token_hash },
        .{ .text = tok.expires_at },
        .{ .text = owner },
    });
    return true;
}

fn upsertFeed(allocator: std.mem.Allocator, conn: *pg.Conn, feed: Feed, owner: *const [36]u8) !bool {
    const existing = try one(allocator, conn,
        \\SELECT COALESCE(auth_header_value_encrypted, '') FROM threat_intel_feeds WHERE id = $1::uuid
    , &.{.{ .text = feed.id }});
    defer if (existing) |row| row.deinit(allocator);
    if (existing) |row| {
        const stored = row.cols[0] orelse "";
        if (!std.mem.eql(u8, stored, feed.auth_header_value_encrypted)) return error.Drift;
        return false;
    }
    try conn.execNoRows(
        \\INSERT INTO threat_intel_feeds (
        \\  id, tenant_id, name, kind, url, auth_header_value_encrypted, default_severity,
        \\  created_by_user_id, created_at, updated_at
        \\) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8::uuid, now(), now())
    , &.{
        .{ .text = feed.id },
        .{ .text = tenant },
        .{ .text = feed.name },
        .{ .text = feed.kind },
        .{ .text = feed.url },
        .{ .text = feed.auth_header_value_encrypted },
        .{ .text = feed.default_severity },
        .{ .text = owner },
    });
    return true;
}

fn one(allocator: std.mem.Allocator, conn: *pg.Conn, sql: []const u8, params: []const pg.Value) !?pg.Row {
    const rows = try conn.exec(allocator, sql, params);
    if (rows.len == 0) {
        allocator.free(rows);
        return null;
    }
    const row = rows[0];
    if (rows.len > 1) {
        for (rows[1..]) |extra| extra.deinit(allocator);
    }
    allocator.free(rows);
    return row;
}

fn normalizeRole(role: []const u8) []const u8 {
    if (std.ascii.eqlIgnoreCase(role, "admin")) return "admin";
    return "viewer";
}

fn legacyUuid(text: []const u8, out: *[36]u8) void {
    if (text.len == 36 and text[8] == '-' and text[13] == '-' and text[18] == '-' and text[23] == '-') {
        @memcpy(out, text[0..36]);
        return;
    }
    var dig: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(text, &dig, .{});
    var bytes: [16]u8 = undefined;
    @memcpy(&bytes, dig[0..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    formatUuid(&bytes, out);
}

fn formatUuid(bytes: *const [16]u8, out: *[36]u8) void {
    const hexdigits = "0123456789abcdef";
    var i: usize = 0;
    for (bytes, 0..) |b, idx| {
        if (idx == 4 or idx == 6 or idx == 8 or idx == 10) {
            out[i] = '-';
            i += 1;
        }
        out[i] = hexdigits[b >> 4];
        out[i + 1] = hexdigits[b & 0xf];
        i += 2;
    }
}

fn hex(dig: *const [Sha256.digest_length]u8) [64]u8 {
    const hexdigits = "0123456789abcdef";
    var out: [64]u8 = undefined;
    for (dig, 0..) |b, i| {
        out[i * 2] = hexdigits[b >> 4];
        out[i * 2 + 1] = hexdigits[b & 0xf];
    }
    return out;
}

fn envSpan(name: [*:0]const u8) []const u8 {
    const z = std.c.getenv(name) orelse return "";
    return std.mem.span(z);
}

fn readFile(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    var file = if (path.len > 0 and path[0] == '/')
        try std.Io.Dir.openFileAbsolute(io, path, .{})
    else
        try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var rbuf: [4096]u8 = undefined;
    var reader = file.reader(io, &rbuf);
    return reader.interface.allocRemaining(allocator, .limited(1 << 20));
}

test "legacy better-auth id maps to a stable uuid" {
    var a: [36]u8 = undefined;
    var b: [36]u8 = undefined;
    legacyUuid("betterauth_legacy_admin", &a);
    legacyUuid("betterauth_legacy_admin", &b);
    try std.testing.expectEqualStrings(&a, &b);
    try std.testing.expect(a[14] == '5');
    var kept: [36]u8 = undefined;
    const id = "11111111-2222-4333-8444-555555555555";
    legacyUuid(id, &kept);
    try std.testing.expectEqualStrings(id, &kept);
}
