//! Postgres integration. Skips when TAWNY_DATABASE_URL is unset so
//! `zig build test` stays green without a database.
const std = @import("std");
const pg = @import("pg/conn.zig");
const migrate = @import("migrate.zig");

const default_tenant = "00000000-0000-0000-0000-000000000001";
const other_tenant = "00000000-0000-0000-0000-00000000e049";
const agent_own = "00000000-0000-0000-0000-00000000a001";
const agent_other = "00000000-0000-0000-0000-00000000a002";
const rule_id = "00000000-0000-0000-0000-00000000a003";

test "rls hides the other tenant and purge keeps referenced telemetry" {
    // libc getenv is empty under the Zig 0.17 test runner. The runner publishes
    // the process environment on std.testing.environ.
    const url = std.testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return;
    if (url.len == 0) return;

    const allocator = std.testing.allocator;
    const conn = try pg.Conn.connect(allocator, std.testing.io, url);
    defer {
        conn.close();
        allocator.destroy(conn);
    }

    try migrate.apply(allocator, conn);
    try std.testing.expect(try migrate.migrationsCurrent(allocator, conn));

    try rlsCase(allocator, conn);
    try purgeCase(allocator, conn);
}

fn rlsCase(allocator: std.mem.Allocator, conn: *pg.Conn) !void {
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};

    try exec(conn,
        \\INSERT INTO tenants (id, slug, name, created_at)
        \\VALUES ($1, 'rls-fixture', 'RLS fixture', now())
    , &.{.{ .text = other_tenant }});
    try exec(conn,
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status
        \\) VALUES
        \\  ($1, $2, 'rls-default-host', 'linux', 'test', '0', 'arm64', now(), 'online'),
        \\  ($3, $4, 'rls-other-host', 'linux', 'test', '0', 'arm64', now(), 'online')
    , &.{
        .{ .text = agent_own },
        .{ .text = default_tenant },
        .{ .text = agent_other },
        .{ .text = other_tenant },
    });

    // App role has no BYPASSRLS. The query names the other tenant and does
    // not rely on the caller adding tenant_id.
    try conn.execSimple("SET LOCAL ROLE tawny_app");

    const unset_other = try scalar(allocator, conn, "SELECT count(*)::text FROM agents WHERE tenant_id = $1", &.{
        .{ .text = other_tenant },
    });
    defer allocator.free(unset_other);
    try std.testing.expectEqualStrings("0", unset_other);

    const configured = try scalar(allocator, conn, "SELECT set_config('tawny.tenant_id', $1, true)", &.{
        .{ .text = default_tenant },
    });
    defer allocator.free(configured);

    const hidden = try scalar(allocator, conn, "SELECT count(*)::text FROM agents WHERE hostname = $1", &.{
        .{ .text = "rls-other-host" },
    });
    defer allocator.free(hidden);
    const own = try scalar(allocator, conn, "SELECT count(*)::text FROM agents WHERE hostname = $1", &.{
        .{ .text = "rls-default-host" },
    });
    defer allocator.free(own);
    const named = try scalar(allocator, conn, "SELECT count(*)::text FROM agents WHERE tenant_id = $1", &.{
        .{ .text = other_tenant },
    });
    defer allocator.free(named);

    std.debug.print("rls unset_other={s} hidden_host={s} own_host={s} named_other={s}\n", .{
        unset_other, hidden, own, named,
    });
    try std.testing.expectEqualStrings("0", hidden);
    try std.testing.expectEqualStrings("1", own);
    try std.testing.expectEqualStrings("0", named);

    try conn.execSimple("ROLLBACK");
}

fn purgeCase(allocator: std.mem.Allocator, conn: *pg.Conn) !void {
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};

    try exec(conn,
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status
        \\) VALUES ($1, $2, 'purge-fixture-host', 'linux', 'test', '0', 'arm64', now(), 'online')
    , &.{ .{ .text = agent_own }, .{ .text = default_tenant } });
    try exec(conn,
        \\INSERT INTO alert_rules (
        \\  id, tenant_id, name, format, severity, operator, created_at, updated_at
        \\) VALUES ($1, $2, 'purge-fixture-rule', 'tawny_predicate', 'low', 'exists', now(), now())
    , &.{ .{ .text = rule_id }, .{ .text = default_tenant } });

    const orphan = try scalar(allocator, conn,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES ('2026-08-01T00:00:00Z', $1, $2, 'heartbeat', '2026-08-01T00:00:00Z', '{}')
        \\RETURNING id::text
    , &.{ .{ .text = default_tenant }, .{ .text = agent_own } });
    defer allocator.free(orphan);
    const kept = try scalar(allocator, conn,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES ('2026-08-02T00:00:00Z', $1, $2, 'heartbeat', '2026-08-02T00:00:00Z', '{}')
        \\RETURNING id::text
    , &.{ .{ .text = default_tenant }, .{ .text = agent_own } });
    defer allocator.free(kept);
    const doomed = try scalar(allocator, conn,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES ('2026-08-03T00:00:00Z', $1, $2, 'heartbeat', '2026-08-03T00:00:00Z', '{}')
        \\RETURNING id::text
    , &.{ .{ .text = default_tenant }, .{ .text = agent_own } });
    defer allocator.free(doomed);

    try exec(conn,
        \\INSERT INTO alerts (
        \\  tenant_id, alert_rule_id, agent_id, telemetry_event_id, telemetry_received_at,
        \\  severity, title, created_at
        \\) VALUES
        \\  ($1, $2, $3, $4::bigint, '2026-08-02T00:00:00Z', 'low', 'purge-young', '2026-10-01T00:00:00Z'),
        \\  ($1, $2, $3, $5::bigint, '2026-08-03T00:00:00Z', 'low', 'purge-old', '2024-01-01T00:00:00Z')
    , &.{
        .{ .text = default_tenant },
        .{ .text = rule_id },
        .{ .text = agent_own },
        .{ .text = kept },
        .{ .text = doomed },
    });

    try conn.execSimple("SELECT tawny_purge_expired('2026-10-04T00:00:00Z')");

    const orphan_n = try countId(allocator, conn, "telemetry_events", orphan);
    defer allocator.free(orphan_n);
    const kept_n = try countId(allocator, conn, "telemetry_events", kept);
    defer allocator.free(kept_n);
    const doomed_n = try countId(allocator, conn, "telemetry_events", doomed);
    defer allocator.free(doomed_n);
    const old_alert = try scalar(allocator, conn, "SELECT count(*)::text FROM alerts WHERE title = $1", &.{
        .{ .text = "purge-old" },
    });
    defer allocator.free(old_alert);
    const young_alert = try scalar(allocator, conn, "SELECT count(*)::text FROM alerts WHERE title = $1", &.{
        .{ .text = "purge-young" },
    });
    defer allocator.free(young_alert);

    std.debug.print("purge orphan={s} kept={s} doomed={s} old_alert={s} young_alert={s}\n", .{
        orphan_n, kept_n, doomed_n, old_alert, young_alert,
    });
    try std.testing.expectEqualStrings("0", orphan_n);
    try std.testing.expectEqualStrings("1", kept_n);
    try std.testing.expectEqualStrings("0", doomed_n);
    try std.testing.expectEqualStrings("0", old_alert);
    try std.testing.expectEqualStrings("1", young_alert);

    try conn.execSimple("ROLLBACK");
}

fn countId(allocator: std.mem.Allocator, conn: *pg.Conn, table: []const u8, id: []const u8) ![]u8 {
    var sql_buf: [96]u8 = undefined;
    const sql = try std.fmt.bufPrint(&sql_buf, "SELECT count(*)::text FROM {s} WHERE id = $1::bigint", .{table});
    return scalar(allocator, conn, sql, &.{.{ .text = id }});
}

fn exec(conn: *pg.Conn, sql: []const u8, params: []const pg.Value) !void {
    conn.execNoRows(sql, params) catch |err| {
        note(conn, sql);
        return err;
    };
}

fn scalar(allocator: std.mem.Allocator, conn: *pg.Conn, sql: []const u8, params: []const pg.Value) ![]u8 {
    const rows = conn.exec(allocator, sql, params) catch |err| {
        note(conn, sql);
        return err;
    };
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len != 1 or rows[0].cols.len == 0) return error.UnexpectedRowCount;
    const col = rows[0].cols[0] orelse return error.NullColumn;
    return allocator.dupe(u8, col);
}

fn note(conn: *pg.Conn, sql: []const u8) void {
    if (conn.takeError()) |msg| {
        std.debug.print("postgres: {s}\n{s}\n", .{ msg, sql });
        conn.allocator.free(msg);
    }
}
