//! Daily retention. Alerts older than 365 days go first, then telemetry
//! older than 30 days that no surviving alert references.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");

pub fn run(conn: *pg.Conn, now_rfc3339: []const u8) !void {
    try conn.execNoRows("SELECT tawny_purge_expired($1::timestamptz)", &.{.{ .text = now_rfc3339 }});
}

const default_tenant = "00000000-0000-0000-0000-000000000001";
const purge_agent = "00000000-0000-0000-0000-00000000d801";

test "purge job drops telemetry older than 30 days" {
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
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status
        \\) VALUES ($1, $2, 'purge-job-host', 'linux', 'test', '0', 'arm64', now(), 'online')
    , &.{ .{ .text = purge_agent }, .{ .text = default_tenant } });
    const old_id = try scalar(allocator, conn,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES ('2026-08-01T00:00:00Z', $1, $2, 'heartbeat', '2026-08-01T00:00:00Z', '{}')
        \\RETURNING id::text
    , &.{ .{ .text = default_tenant }, .{ .text = purge_agent } });
    defer allocator.free(old_id);
    const young_id = try scalar(allocator, conn,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES ('2026-10-01T00:00:00Z', $1, $2, 'heartbeat', '2026-10-01T00:00:00Z', '{}')
        \\RETURNING id::text
    , &.{ .{ .text = default_tenant }, .{ .text = purge_agent } });
    defer allocator.free(young_id);

    try run(conn, "2026-10-04T00:00:00Z");

    const old_n = try scalar(allocator, conn, "SELECT count(*)::text FROM telemetry_events WHERE id = $1::bigint", &.{
        .{ .text = old_id },
    });
    defer allocator.free(old_n);
    const young_n = try scalar(allocator, conn, "SELECT count(*)::text FROM telemetry_events WHERE id = $1::bigint", &.{
        .{ .text = young_id },
    });
    defer allocator.free(young_n);
    std.debug.print("purge_job old={s} young={s}\n", .{ old_n, young_n });
    try std.testing.expectEqualStrings("0", old_n);
    try std.testing.expectEqualStrings("1", young_n);
    try conn.execSimple("ROLLBACK");
}

fn scalar(allocator: std.mem.Allocator, conn: *pg.Conn, sql: []const u8, params: []const pg.Value) ![]u8 {
    const rows = try conn.exec(allocator, sql, params);
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    const col = rows[0].cols[0] orelse return error.NullColumn;
    return allocator.dupe(u8, col);
}
