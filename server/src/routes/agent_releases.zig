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
    const body = lookupJson(allocator, conn, platform) catch |err| switch (err) {
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
    const rows = try conn.exec(allocator,
        \\SELECT version, platform, download_url, sha256, released_at::text
        \\FROM agent_releases
        \\WHERE is_latest AND platform = $1
        \\ORDER BY released_at DESC
        \\LIMIT 1
    , &.{.{ .text = platform }});
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
    return std.fmt.allocPrint(allocator,
        \\{{"version":{s},"platform":{s},"download_url":{s},"sha256":{s},"released_at":{s}}}
    , .{ version, plat, url, sha, released });
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
