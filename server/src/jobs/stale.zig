//! Mark agents stale at 3 minutes and offline at 15 minutes.
//! Same predicates as `MarkStaleAgentsJob`.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");

pub fn mark(conn: *pg.Conn, now_rfc3339: []const u8) !void {
    try conn.execNoRows(
        \\UPDATE agents SET status = 'stale'
        \\WHERE status = 'online'
        \\  AND last_heartbeat_at IS NOT NULL
        \\  AND last_heartbeat_at <= $1::timestamptz - interval '3 minutes'
        \\  AND last_heartbeat_at > $1::timestamptz - interval '15 minutes'
    , &.{.{ .text = now_rfc3339 }});
    try conn.execNoRows(
        \\UPDATE agents SET status = 'offline'
        \\WHERE status <> 'offline'
        \\  AND last_heartbeat_at IS NOT NULL
        \\  AND last_heartbeat_at <= $1::timestamptz - interval '15 minutes'
    , &.{.{ .text = now_rfc3339 }});
}

const default_tenant = "00000000-0000-0000-0000-000000000001";
const agent_stale = "00000000-0000-0000-0000-00000000d501";
const agent_offline = "00000000-0000-0000-0000-00000000d502";
const agent_fresh = "00000000-0000-0000-0000-00000000d503";
const agent_revoked = "00000000-0000-0000-0000-00000000d504";
const agent_quiet = "00000000-0000-0000-0000-00000000d505";

test "stale job uses the three and fifteen minute boundaries" {
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

    try insert(conn, agent_stale, "stale-4m", "online", "2026-05-14T07:56:00Z");
    try insert(conn, agent_offline, "offline-16m", "online", "2026-05-14T07:44:00Z");
    try insert(conn, agent_fresh, "online-30s", "online", "2026-05-14T07:59:30Z");
    try insert(conn, agent_revoked, "revoked-old", "revoked", "2026-05-14T07:40:00Z");
    try conn.execNoRows(
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status
        \\) VALUES ($1, $2, 'no-heartbeat', 'linux', 'test', '0', 'arm64', '2026-05-14T08:00:00Z', 'online')
    , &.{ .{ .text = agent_quiet }, .{ .text = default_tenant } });

    try mark(conn, "2026-05-14T08:00:00Z");

    const stale_n = try scalar(allocator, conn, "SELECT status FROM agents WHERE id = $1::uuid", agent_stale);
    defer allocator.free(stale_n);
    const offline_n = try scalar(allocator, conn, "SELECT status FROM agents WHERE id = $1::uuid", agent_offline);
    defer allocator.free(offline_n);
    const fresh_n = try scalar(allocator, conn, "SELECT status FROM agents WHERE id = $1::uuid", agent_fresh);
    defer allocator.free(fresh_n);
    const revoked_n = try scalar(allocator, conn, "SELECT status FROM agents WHERE id = $1::uuid", agent_revoked);
    defer allocator.free(revoked_n);
    const quiet_n = try scalar(allocator, conn, "SELECT status FROM agents WHERE id = $1::uuid", agent_quiet);
    defer allocator.free(quiet_n);
    std.debug.print("stale_job stale={s} offline={s} fresh={s} revoked={s} quiet={s}\n", .{
        stale_n, offline_n, fresh_n, revoked_n, quiet_n,
    });
    try std.testing.expectEqualStrings("stale", stale_n);
    try std.testing.expectEqualStrings("offline", offline_n);
    try std.testing.expectEqualStrings("online", fresh_n);
    try std.testing.expectEqualStrings("offline", revoked_n);
    try std.testing.expectEqualStrings("online", quiet_n);
    try conn.execSimple("ROLLBACK");
}

fn insert(conn: *pg.Conn, id: []const u8, hostname: []const u8, status: []const u8, heartbeat: []const u8) !void {
    try conn.execNoRows(
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, last_heartbeat_at, status
        \\) VALUES ($1, $2, $3, 'linux', 'test', '0', 'arm64', '2026-05-14T08:00:00Z', $4::timestamptz, $5)
    , &.{
        .{ .text = id },
        .{ .text = default_tenant },
        .{ .text = hostname },
        .{ .text = heartbeat },
        .{ .text = status },
    });
}

fn scalar(allocator: std.mem.Allocator, conn: *pg.Conn, sql: []const u8, id: []const u8) ![]u8 {
    const rows = try conn.exec(allocator, sql, &.{.{ .text = id }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    const col = rows[0].cols[0] orelse return error.NullColumn;
    return allocator.dupe(u8, col);
}