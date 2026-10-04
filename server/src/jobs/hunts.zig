//! Scheduled hunts. Cadence matches `ScheduledHuntsJob`.
//! A matched event is recorded in `hunt_cursors` and is not alerted again.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const hunt = @import("../hunts/query.zig");

pub fn isDue(cron: []const u8, last_run: ?i64, now_unix: i64) bool {
    const trimmed = std.mem.trim(u8, cron, " \t");
    if (trimmed.len >= 2) {
        const amount = std.fmt.parseInt(i64, trimmed[0 .. trimmed.len - 1], 10) catch 0;
        if (amount > 0) {
            const span: i64 = switch (std.ascii.toLower(trimmed[trimmed.len - 1])) {
                'm' => amount * 60,
                'h' => amount * 3600,
                'd' => amount * 86400,
                else => 0,
            };
            if (span > 0) return last_run == null or now_unix - last_run.? >= span;
        }
    }
    return last_run == null or now_unix - last_run.? >= 15 * 60;
}

pub fn run(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, now_unix: i64) !u32 {
    const rows = try conn.exec(allocator,
        \\SELECT id::text, tenant_id::text, name, query, schedule_cron,
        \\       alert_on_match::text, alert_severity,
        \\       extract(epoch from last_run_at)::bigint::text
        \\FROM saved_hunts
        \\WHERE is_scheduled AND schedule_cron IS NOT NULL
    , &.{});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    var ran: u32 = 0;
    for (rows) |row| {
        const hunt_id = row.cols[0] orelse continue;
        const tenant = row.cols[1] orelse continue;
        const name = row.cols[2] orelse "hunt";
        const query = row.cols[3] orelse continue;
        const cron = row.cols[4] orelse continue;
        const alert_on = truthy(row.cols[5] orelse "f");
        const severity = row.cols[6] orelse "medium";
        const last = if (row.cols[7]) |raw| std.fmt.parseInt(i64, raw, 10) catch null else null;
        if (!isDue(cron, last, now_unix)) continue;
        try runOne(allocator, io, conn, now_unix, hunt_id, tenant, name, query, alert_on, severity);
        ran += 1;
    }
    return ran;
}

fn truthy(value: []const u8) bool {
    return std.mem.eql(u8, value, "t") or std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "1");
}

fn runOne(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    now_unix: i64,
    hunt_id: []const u8,
    tenant: []const u8,
    name: []const u8,
    query: []const u8,
    alert_on: bool,
    severity: []const u8,
) !void {
    var storage: [240]u8 = undefined;
    var msg: []u8 = &storage;
    var plan = hunt.parse(allocator, query, null, now_unix, &msg) catch {
        try finishRun(conn, hunt_id, tenant, "failed", 0, 0, msg);
        return;
    };
    defer plan.deinit();

    const cursor = try cursorId(allocator, conn, hunt_id);
    var result = try hunt.execute(allocator, conn, tenant, &plan, cursor, now_unix);
    defer result.deinit(allocator);

    var created: i64 = 0;
    var max_id = cursor;
    if (alert_on) {
        const rule_id = try ensureRule(allocator, io, conn, tenant, hunt_id, name, severity);
        defer allocator.free(rule_id);
        for (result.matches) |m| {
            const id = std.fmt.parseInt(i64, m.event_id, 10) catch continue;
            if (id > max_id) max_id = id;
            const exists = try count(allocator, conn,
                \\SELECT count(*)::text FROM alerts
                \\WHERE tenant_id = $1::uuid AND alert_rule_id = $2::uuid AND telemetry_event_id = $3::bigint
            , &.{ .{ .text = tenant }, .{ .text = rule_id }, .{ .text = m.event_id } });
            defer allocator.free(exists);
            if (!std.mem.eql(u8, exists, "0")) continue;
            const title = try std.fmt.allocPrint(allocator, "Scheduled hunt: {s}", .{name});
            defer allocator.free(title);
            const desc = try std.fmt.allocPrint(allocator, "Matched by saved hunt '{s}'.", .{name});
            defer allocator.free(desc);
            try conn.execNoRows(
                \\INSERT INTO alerts (
                \\  tenant_id, alert_rule_id, agent_id, telemetry_event_id, telemetry_received_at,
                \\  severity, status, title, description, created_at
                \\) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::bigint, $5::timestamptz, $6, 'open', $7, $8, now())
            , &.{
                .{ .text = tenant },
                .{ .text = rule_id },
                .{ .text = m.agent_id },
                .{ .text = m.event_id },
                .{ .text = m.received_at },
                .{ .text = severity },
                .{ .text = title },
                .{ .text = desc },
            });
            created += 1;
        }
    } else {
        for (result.matches) |m| {
            const id = std.fmt.parseInt(i64, m.event_id, 10) catch continue;
            if (id > max_id) max_id = id;
        }
    }
    if (max_id > cursor) {
        var buf: [32]u8 = undefined;
        const text = std.fmt.bufPrint(&buf, "{d}", .{max_id}) catch return error.BadCursor;
        try conn.execNoRows(
            \\INSERT INTO hunt_cursors (hunt_id, tenant_id, last_event_id)
            \\VALUES ($1::uuid, $2::uuid, $3::bigint)
            \\ON CONFLICT (hunt_id) DO UPDATE
            \\SET last_event_id = GREATEST(hunt_cursors.last_event_id, EXCLUDED.last_event_id)
        , &.{ .{ .text = hunt_id }, .{ .text = tenant }, .{ .text = text } });
    }
    try finishRun(conn, hunt_id, tenant, "succeeded", result.matches.len, created, "");
}

fn finishRun(
    conn: *pg.Conn,
    hunt_id: []const u8,
    tenant: []const u8,
    status: []const u8,
    match_count: usize,
    alerts_created: i64,
    err_text: []const u8,
) !void {
    var match_buf: [32]u8 = undefined;
    const matches = std.fmt.bufPrint(&match_buf, "{d}", .{match_count}) catch "0";
    var alert_buf: [32]u8 = undefined;
    const alerts = std.fmt.bufPrint(&alert_buf, "{d}", .{alerts_created}) catch "0";
    const err_val: pg.Value = if (err_text.len == 0) .{ .null = {} } else .{ .text = err_text };
    try conn.execNoRows(
        \\INSERT INTO hunt_runs (
        \\  tenant_id, saved_hunt_id, status, started_at, completed_at, match_count, alerts_created, error_message
        \\) VALUES ($1::uuid, $2::uuid, $3, now(), now(), $4::int, $5::int, $6)
    , &.{
        .{ .text = tenant },
        .{ .text = hunt_id },
        .{ .text = status },
        .{ .text = matches },
        .{ .text = alerts },
        err_val,
    });
    try conn.execNoRows(
        \\UPDATE saved_hunts SET last_run_at = now(), last_match_count = $2::int, updated_at = now() WHERE id = $1::uuid
    , &.{ .{ .text = hunt_id }, .{ .text = matches } });
}

fn cursorId(allocator: std.mem.Allocator, conn: *pg.Conn, hunt_id: []const u8) !i64 {
    const rows = try conn.exec(allocator, "SELECT last_event_id::text FROM hunt_cursors WHERE hunt_id = $1::uuid", &.{
        .{ .text = hunt_id },
    });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return 0;
    const raw = rows[0].cols[0] orelse return 0;
    return std.fmt.parseInt(i64, raw, 10) catch 0;
}

fn ensureRule(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    tenant: []const u8,
    hunt_id: []const u8,
    name: []const u8,
    severity: []const u8,
) ![]u8 {
    const external = try std.fmt.allocPrint(allocator, "saved-hunt:{s}", .{hunt_id});
    defer allocator.free(external);
    const existing = try conn.exec(allocator,
        \\SELECT id::text FROM alert_rules WHERE tenant_id = $1::uuid AND external_id = $2 LIMIT 1
    , &.{ .{ .text = tenant }, .{ .text = external } });
    defer {
        for (existing) |row| row.deinit(allocator);
        allocator.free(existing);
    }
    if (existing.len > 0) {
        if (existing[0].cols[0]) |id| return allocator.dupe(u8, id);
    }
    var idbuf: [36]u8 = undefined;
    const rule_id = try allocator.dupe(u8, util.newUuid(io, &idbuf));
    errdefer allocator.free(rule_id);
    const rule_name = try std.fmt.allocPrint(allocator, "Hunt: {s}", .{name});
    defer allocator.free(rule_name);
    const desc = try std.fmt.allocPrint(allocator, "Auto-generated rule backing saved hunt {s}.", .{hunt_id});
    defer allocator.free(desc);
    try conn.execNoRows(
        \\INSERT INTO alert_rules (
        \\  id, tenant_id, name, format, external_id, description, severity, operator,
        \\  is_enabled, created_at, updated_at
        \\) VALUES (
        \\  $1::uuid, $2::uuid, $3, 'tawny_predicate', $4, $5, $6, 'exists', false, now(), now()
        \\)
    , &.{
        .{ .text = rule_id },
        .{ .text = tenant },
        .{ .text = rule_name },
        .{ .text = external },
        .{ .text = desc },
        .{ .text = severity },
    });
    return rule_id;
}

fn count(allocator: std.mem.Allocator, conn: *pg.Conn, sql: []const u8, params: []const pg.Value) ![]u8 {
    const rows = try conn.exec(allocator, sql, params);
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    const col = rows[0].cols[0] orelse return error.NullColumn;
    return allocator.dupe(u8, col);
}

test "schedule cadence is minutes hours days or fifteen minutes" {
    const now: i64 = 1_000_000;
    try std.testing.expect(isDue("5m", null, now));
    try std.testing.expect(!isDue("5m", now - 60, now));
    try std.testing.expect(isDue("5m", now - 300, now));
    try std.testing.expect(!isDue("* * * * *", now - 60, now));
    try std.testing.expect(isDue("* * * * *", now - 15 * 60, now));
    try std.testing.expect(isDue("1h", now - 3600, now));
}

const default_tenant = "00000000-0000-0000-0000-000000000001";
const sched_agent = "00000000-0000-0000-0000-00000000d921";
const sched_hunt = "00000000-0000-0000-0000-00000000d922";

test "scheduled hunt does not re-alert an already matched event" {
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
    try conn.execNoRows("UPDATE saved_hunts SET is_scheduled = false WHERE id <> $1::uuid", &.{.{ .text = sched_hunt }});
    try conn.execNoRows(
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status
        \\) VALUES ($1, $2, 'hunt-sched-host', 'linux', 'test', '0', 'arm64', now(), 'online')
    , &.{ .{ .text = sched_agent }, .{ .text = default_tenant } });
    try conn.execNoRows(
        \\INSERT INTO saved_hunts (
        \\  id, tenant_id, name, query, is_scheduled, schedule_cron, alert_on_match,
        \\  alert_severity, created_at, updated_at
        \\) VALUES (
        \\  $1, $2, 'sched-marker', 'event_type:process_start command_line:"hunt-sched-marker"',
        \\  true, '5m', true, 'high', now(), now()
        \\)
    , &.{ .{ .text = sched_hunt }, .{ .text = default_tenant } });
    const first = try insertEvent(allocator, conn, "{\"command_line\":\"hunt-sched-marker\"}");
    defer allocator.free(first);
    const other = try insertEvent(allocator, conn, "{\"command_line\":\"other\"}");
    defer allocator.free(other);

    const now: i64 = 2_000_000_000;
    const ran1 = try run(allocator, std.testing.io, conn, now);
    const alerts1 = try count(allocator, conn, "SELECT count(*)::text FROM alerts a JOIN alert_rules r ON r.id = a.alert_rule_id WHERE r.external_id = $1", &.{
        .{ .text = "saved-hunt:00000000-0000-0000-0000-00000000d922" },
    });
    defer allocator.free(alerts1);
    const cursor1 = try count(allocator, conn, "SELECT last_event_id::text FROM hunt_cursors WHERE hunt_id = $1::uuid", &.{
        .{ .text = sched_hunt },
    });
    defer allocator.free(cursor1);

    try conn.execNoRows("UPDATE saved_hunts SET last_run_at = now() - interval '1 hour' WHERE id = $1::uuid", &.{
        .{ .text = sched_hunt },
    });
    const ran2 = try run(allocator, std.testing.io, conn, now);
    const alerts2 = try count(allocator, conn, "SELECT count(*)::text FROM alerts a JOIN alert_rules r ON r.id = a.alert_rule_id WHERE r.external_id = $1", &.{
        .{ .text = "saved-hunt:00000000-0000-0000-0000-00000000d922" },
    });
    defer allocator.free(alerts2);

    const third = try insertEvent(allocator, conn, "{\"command_line\":\"hunt-sched-marker\"}");
    defer allocator.free(third);
    try conn.execNoRows("UPDATE saved_hunts SET last_run_at = now() - interval '1 hour' WHERE id = $1::uuid", &.{
        .{ .text = sched_hunt },
    });
    const ran3 = try run(allocator, std.testing.io, conn, now);
    const alerts3 = try count(allocator, conn, "SELECT count(*)::text FROM alerts a JOIN alert_rules r ON r.id = a.alert_rule_id WHERE r.external_id = $1", &.{
        .{ .text = "saved-hunt:00000000-0000-0000-0000-00000000d922" },
    });
    defer allocator.free(alerts3);

    std.debug.print("hunt_sched ran={d}/{d}/{d} alerts={s}/{s}/{s} cursor={s} third={s}\n", .{
        ran1, ran2, ran3, alerts1, alerts2, alerts3, cursor1, third,
    });
    try std.testing.expect(ran1 >= 1);
    try std.testing.expectEqualStrings("1", alerts1);
    try std.testing.expectEqualStrings(first, cursor1);
    try std.testing.expectEqualStrings("1", alerts2);
    try std.testing.expectEqualStrings("2", alerts3);
    try conn.execSimple("ROLLBACK");
}

fn insertEvent(allocator: std.mem.Allocator, conn: *pg.Conn, payload: []const u8) ![]u8 {
    const rows = try conn.exec(allocator,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES (now(), $1::uuid, $2::uuid, 'process_start', now(), $3::jsonb)
        \\RETURNING id::text
    , &.{ .{ .text = default_tenant }, .{ .text = sched_agent }, .{ .text = payload } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    return allocator.dupe(u8, rows[0].cols[0] orelse return error.NullColumn);
}
