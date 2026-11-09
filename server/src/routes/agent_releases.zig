//! `GET /api/releases/latest?platform=` for Session and ApiToken callers.
//! Release bytes for an enrolled agent still arrive on heartbeat.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");

pub fn latest(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    target: []const u8,
) !void {
    _ = web;
    const platform = util.queryParam(target, "platform") orelse {
        return util.problem(request, allocator, .bad_request, "platform is required.");
    };
    if (!validPlatform(platform)) {
        return util.problem(request, allocator, .bad_request, "platform is required.");
    }
    // Optional ring (#58): only a release already open to that ring.
    const ring = util.queryParam(target, "ring");
    if (ring) |r| if (ringRank(r) == null) {
        return util.problem(request, allocator, .bad_request, "ring must be canary, internal, 10, 50 or 100.");
    };
    const body = lookupJsonRing(allocator, conn, platform, ring) catch |err| switch (err) {
        error.NotFound => return util.problem(request, allocator, .not_found, "No release is published for that platform."),
        else => return err,
    };
    defer allocator.free(body);
    try util.respondJson(request, .ok, body);
}

fn validPlatform(platform: []const u8) bool {
    if (platform.len == 0 or platform.len > 64) return false;
    if (util.hasControlChars(platform)) return false;
    return std.mem.indexOfScalar(u8, platform, ' ') == null;
}

pub fn lookupJson(allocator: std.mem.Allocator, conn: *pg.Conn, platform: []const u8) ![]u8 {
    return lookupJsonRing(allocator, conn, platform, null);
}

/// Ring order. A release open to ring R is offered to agents in R and every
/// earlier ring (agent/src/updater.zig `ringAllows`).
pub const rings = [_][]const u8{ "canary", "internal", "10", "50", "100" };

pub fn ringRank(ring: []const u8) ?u8 {
    for (rings, 0..) |r, i| if (std.mem.eql(u8, r, ring)) return @intCast(i);
    return null;
}

/// Same bucket as the agent: first four bytes of sha256(lower-case agent
/// id), big-endian, mod 100.
pub fn bucket(agent_id: []const u8) u8 {
    var lower: [64]u8 = undefined;
    const n = @min(agent_id.len, lower.len);
    for (agent_id[0..n], 0..) |c, i| lower[i] = std.ascii.toLower(c);
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(lower[0..n], &d, .{});
    return @intCast(std.mem.readInt(u32, d[0..4], .big) % 100);
}

pub fn ringForAgent(agent_id: []const u8, override: ?[]const u8) []const u8 {
    if (override) |o| if (ringRank(o) != null) return o;
    const b = bucket(agent_id);
    if (b < 10) return "10";
    if (b < 50) return "50";
    return "100";
}

/// SQL predicate: the release ring rank is at least the agent ring rank.
/// Leading and trailing spaces matter: `\\` lines joined with `++` get no
/// newline between them.
const ring_rank_sql = " array_position(ARRAY['canary','internal','10','50','100'], ring) >= array_position(ARRAY['canary','internal','10','50','100'], $2::text) ";

pub fn lookupJsonRing(allocator: std.mem.Allocator, conn: *pg.Conn, platform: []const u8, ring: ?[]const u8) ![]u8 {
    const rows = try conn.exec(allocator,
        \\SELECT version, platform, download_url, sha256, released_at::text, ring
        \\FROM agent_releases
        \\WHERE is_latest AND platform = $1
        \\  AND ($2::text IS NULL OR
    ++ ring_rank_sql ++
        \\)
        \\ORDER BY released_at DESC
        \\LIMIT 1
    , &.{ .{ .text = platform }, if (ring) |r| .{ .text = r } else .{ .null = {} } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return error.NotFound;
    const c = rows[0].cols;
    const version = try util.escapeJson(allocator, c[0] orelse "");
    defer allocator.free(version);
    const plat = try util.escapeJson(allocator, c[1] orelse "");
    defer allocator.free(plat);
    const url = try util.escapeJson(allocator, c[2] orelse "");
    defer allocator.free(url);
    const sha = try util.escapeJson(allocator, c[3] orelse "");
    defer allocator.free(sha);
    const released = try util.nullOrJsonString(allocator, c[4]);
    defer allocator.free(released);
    const ring_j = try util.escapeJson(allocator, c[5] orelse "100");
    defer allocator.free(ring_j);
    return std.fmt.allocPrint(allocator,
        \\{{"version":{s},"platform":{s},"download_url":{s},"sha256":{s},"released_at":{s},"ring":{s}}}
    , .{ version, plat, url, sha, released, ring_j });
}

/// `POST /api/agent/update-check` (agent JWT). Body `{"platform": ...}`.
/// The server picks the ring (override, else bucket) and replies with the
/// signed manifest, its signature and the download URL, or 204 when nothing
/// signed is offered to this agent. The agent verifies the signature with
/// its compiled-in key; the server only passes the bytes on.
pub fn updateCheck(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    agent: auth.AgentAuth,
) !void {
    const body = try util.readBody(allocator, request, 4096);
    defer allocator.free(body);
    const Req = struct { platform: []const u8 };
    const parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch
        return util.problem(request, allocator, .bad_request, "platform is required.");
    defer parsed.deinit();
    if (!validPlatform(parsed.value.platform)) return util.problem(request, allocator, .bad_request, "platform is required.");
    const reply = try offerJson(allocator, conn, agent.tenant_id, agent.agent_id, parsed.value.platform);
    defer if (reply) |r| allocator.free(r);
    if (reply) |r| return util.respondJson(request, .ok, r);
    try request.respond("", .{ .status = .no_content, .keep_alive = false });
}

pub fn offerJson(allocator: std.mem.Allocator, conn: *pg.Conn, tenant: []const u8, agent_id: []const u8, platform: []const u8) !?[]u8 {
    const ov = try conn.exec(allocator, "SELECT update_ring FROM agents WHERE id = $1::uuid AND tenant_id = $2::uuid", &.{ .{ .text = agent_id }, .{ .text = tenant } });
    defer {
        for (ov) |r| r.deinit(allocator);
        allocator.free(ov);
    }
    const override: ?[]const u8 = if (ov.len > 0) ov[0].cols[0] else null;
    const ring = ringForAgent(agent_id, override);
    const rows = try conn.exec(allocator,
        \\SELECT manifest, manifest_signature, download_url, ring FROM agent_releases
        \\WHERE is_latest AND platform = $1 AND manifest IS NOT NULL AND manifest_signature IS NOT NULL AND
    ++ ring_rank_sql ++
        \\
        \\ORDER BY released_at DESC LIMIT 1
    , &.{ .{ .text = platform }, .{ .text = ring } });
    defer {
        for (rows) |r| r.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return null;
    const m = try util.escapeJson(allocator, rows[0].cols[0].?);
    defer allocator.free(m);
    const sg = try util.escapeJson(allocator, rows[0].cols[1].?);
    defer allocator.free(sg);
    const u = try util.escapeJson(allocator, rows[0].cols[2] orelse "");
    defer allocator.free(u);
    const rj = try util.escapeJson(allocator, ring);
    defer allocator.free(rj);
    return try std.fmt.allocPrint(allocator,
        \\{{"manifest":{s},"signature":{s},"download_url":{s},"agent_ring":{s}}}
    , .{ m, sg, u, rj });
}

test "bucket matches the agent vector and rings map from it" {
    try std.testing.expectEqual(@as(u8, 19), bucket("00000000-0000-0000-0000-000000000001"));
    try std.testing.expectEqual(@as(u8, 16), bucket("00000000-0000-0000-0000-000000000042"));
    try std.testing.expectEqualStrings("50", ringForAgent("00000000-0000-0000-0000-000000000001", null));
    try std.testing.expectEqualStrings("canary", ringForAgent("00000000-0000-0000-0000-000000000001", "canary"));
    try std.testing.expectEqualStrings("50", ringForAgent("00000000-0000-0000-0000-000000000001", "bogus"));
    try std.testing.expectEqual(@as(?u8, null), ringRank("25"));
}

test "ring query and update-check only offer releases open to the ring" {
    const url = std.testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return;
    if (url.len == 0) return;
    const allocator = std.testing.allocator;
    const conn = try pg.Conn.connect(allocator, std.testing.io, url);
    defer {
        conn.close();
        allocator.destroy(conn);
    }
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};
    const tenant = "00000000-0000-0000-0000-000000000001";
    const agent_id = "00000000-0000-0000-0000-000000000001"; // bucket 19, ring 50
    try conn.execNoRows(
        \\INSERT INTO agents (id, tenant_id, hostname, operating_system, os_version, agent_version, architecture, enrolled_at, status)
        \\VALUES ($1::uuid, $2::uuid, 'ring-host', 'linux', 't', '0.1.0', 'x64', now(), 'online')
        \\ON CONFLICT (id) DO UPDATE SET update_ring = NULL
    , &.{ .{ .text = agent_id }, .{ .text = tenant } });
    try conn.execNoRows(
        \\INSERT INTO agent_releases (version, platform, download_url, sha256, released_at, is_latest, ring, manifest, manifest_signature)
        \\VALUES ('9.9.9', 'ringtest-x64', 'https://example.invalid/a', 'ab', now(), true, 'canary', '{"version":"9.9.9"}', 'sig')
    , &.{});
    const plat = "ringtest-x64";

    try std.testing.expectError(error.NotFound, lookupJsonRing(allocator, conn, plat, "50"));
    const canary = try lookupJsonRing(allocator, conn, plat, "canary");
    allocator.free(canary);
    try std.testing.expect((try offerJson(allocator, conn, tenant, agent_id, plat)) == null);

    // Promote to 50: the agent (ring 50) is now offered it.
    try conn.execNoRows("UPDATE agent_releases SET ring = '50' WHERE platform = $1", &.{.{ .text = plat }});
    const offer = (try offerJson(allocator, conn, tenant, agent_id, plat)).?;
    defer allocator.free(offer);
    try std.testing.expect(std.mem.indexOf(u8, offer, "\"agent_ring\":\"50\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, offer, "\"signature\":\"sig\"") != null);

    // An override to ring 100 hides it again.
    try conn.execNoRows("UPDATE agents SET update_ring = '100' WHERE id = $1::uuid", &.{.{ .text = agent_id }});
    try std.testing.expect((try offerJson(allocator, conn, tenant, agent_id, plat)) == null);
    try conn.execSimple("ROLLBACK");
}

test "latest release lookup returns the current row for a platform" {
    const url = std.testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return;
    if (url.len == 0) return;
    const allocator = std.testing.allocator;
    const conn = try pg.Conn.connect(allocator, std.testing.io, url);
    defer {
        conn.close();
        allocator.destroy(conn);
    }
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};
    try conn.execNoRows(
        \\INSERT INTO agent_releases (version, platform, download_url, sha256, released_at, is_latest)
        \\VALUES ('1.2.3', 'contract-probe-os', 'https://example.invalid/agent', 'abc', now(), true)
    , &.{});

    const body = try lookupJson(allocator, conn, "contract-probe-os");
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"version\":\"1.2.3\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"platform\":\"contract-probe-os\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "https://example.invalid/agent") != null);
    try std.testing.expectError(error.NotFound, lookupJson(allocator, conn, "no-such-platform"));
    try conn.execSimple("ROLLBACK");
}
