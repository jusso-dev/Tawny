//! Detection worker. Ingest only inserts `work_queue` rows of kind `detect`.
//! `drain` claims them with SKIP LOCKED and creates alerts after the 202.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const package_exposure = @import("../detect/package_exposure.zig");

const DetectJob = struct {
    event_id: []const u8,
    received_at: []const u8,
    agent_id: []const u8,
    hostname: []const u8,
    event_type: []const u8,
};

pub fn enqueue(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    tenant_id: []const u8,
    agent_id: []const u8,
    hostname: []const u8,
    event_type: []const u8,
    event_id: []const u8,
    received_at: []const u8,
) !void {
    const event_id_j = try util.escapeJson(allocator, event_id);
    defer allocator.free(event_id_j);
    const received_j = try util.escapeJson(allocator, received_at);
    defer allocator.free(received_j);
    const agent_j = try util.escapeJson(allocator, agent_id);
    defer allocator.free(agent_j);
    const host_j = try util.escapeJson(allocator, hostname);
    defer allocator.free(host_j);
    const type_j = try util.escapeJson(allocator, event_type);
    defer allocator.free(type_j);
    const payload = try std.fmt.allocPrint(allocator,
        \\{{"event_id":{s},"received_at":{s},"agent_id":{s},"hostname":{s},"event_type":{s}}}
    , .{ event_id_j, received_j, agent_j, host_j, type_j });
    defer allocator.free(payload);
    try conn.execNoRows(
        \\INSERT INTO work_queue (kind, tenant_id, payload)
        \\VALUES ('detect', $1::uuid, $2::jsonb)
    , &.{ .{ .text = tenant_id }, .{ .text = payload } });
}

/// Claim ready detect jobs and evaluate them. Safe on the accept thread:
/// one connection, no second worker. Returns how many jobs were finished.
pub fn drain(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn) !u32 {
    const claimed = try conn.exec(allocator,
        \\UPDATE work_queue SET locked_until = now() + interval '5 minutes', attempts = attempts + 1
        \\WHERE id IN (
        \\  SELECT id FROM work_queue
        \\  WHERE kind = 'detect' AND run_after <= now()
        \\    AND (locked_until IS NULL OR locked_until < now())
        \\  ORDER BY id
        \\  LIMIT 64
        \\  FOR UPDATE SKIP LOCKED
        \\)
        \\RETURNING id::text, tenant_id::text, payload::text
    , &.{});
    defer {
        for (claimed) |row| row.deinit(allocator);
        allocator.free(claimed);
    }
    var done: u32 = 0;
    for (claimed) |row| {
        const qid = row.cols[0] orelse continue;
        const tenant = row.cols[1] orelse {
            try failJob(conn, qid, "missing tenant");
            continue;
        };
        const payload_txt = row.cols[2] orelse {
            try failJob(conn, qid, "missing payload");
            continue;
        };
        var parsed = std.json.parseFromSlice(DetectJob, allocator, payload_txt, .{
            .ignore_unknown_fields = true,
        }) catch {
            try failJob(conn, qid, "bad payload");
            continue;
        };
        defer parsed.deinit();
        const job = parsed.value;
        const ev = conn.exec(allocator,
            \\SELECT payload::text FROM telemetry_events
            \\WHERE id = $1::bigint AND received_at = $2::timestamptz
            \\LIMIT 1
        , &.{ .{ .text = job.event_id }, .{ .text = job.received_at } }) catch {
            try failJob(conn, qid, "telemetry lookup failed");
            continue;
        };
        defer {
            for (ev) |erow| erow.deinit(allocator);
            allocator.free(ev);
        }
        if (ev.len == 0 or ev[0].cols[0] == null) {
            try deleteJob(conn, qid);
            done += 1;
            continue;
        }
        evaluateRules(allocator, io, conn, tenant, job.agent_id, job.hostname, job.event_type, ev[0].cols[0].?, job.event_id, job.received_at) catch {
            try failJob(conn, qid, "evaluate failed");
            continue;
        };
        try deleteJob(conn, qid);
        done += 1;
    }
    return done;
}

fn failJob(conn: *pg.Conn, id: []const u8, message: []const u8) !void {
    try conn.execNoRows(
        \\UPDATE work_queue SET last_error = $2, locked_until = now() + interval '1 minute'
        \\WHERE id = $1::bigint
    , &.{ .{ .text = id }, .{ .text = message } });
}

fn deleteJob(conn: *pg.Conn, id: []const u8) !void {
    try conn.execNoRows("DELETE FROM work_queue WHERE id = $1::bigint", &.{.{ .text = id }});
}

fn evaluateRules(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    tenant_id: []const u8,
    agent_id: []const u8,
    hostname: []const u8,
    event_type: []const u8,
    payload: []const u8,
    event_id: []const u8,
    received_at: []const u8,
) !void {
    const rules = try conn.exec(allocator,
        \\SELECT id::text, name, severity, operator, payload_path, match_value, mitre_techniques::text,
        \\       format, source_definition
        \\FROM alert_rules
        \\WHERE tenant_id = $1::uuid AND is_enabled
        \\AND (event_type IS NULL OR event_type = $2)
        \\AND format IN ('tawny_predicate','sigma','ioc','package_exposure')
    , &.{ .{ .text = tenant_id }, .{ .text = event_type } });
    defer {
        for (rules) |row| row.deinit(allocator);
        allocator.free(rules);
    }
    const sups = try conn.exec(allocator,
        \\SELECT id::text, scope, alert_rule_id::text, agent_id::text, payload_path, operator, match_value
        \\FROM suppression_rules
        \\WHERE tenant_id = $1::uuid AND is_enabled
        \\AND (expires_at IS NULL OR expires_at > now())
    , &.{.{ .text = tenant_id }});
    defer {
        for (sups) |srow| srow.deinit(allocator);
        allocator.free(sups);
    }
    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const created = util.formatRfc3339(&tbuf, now);
    for (rules) |row| {
        const format = row.cols[7] orelse "";
        if (std.mem.eql(u8, format, "package_exposure")) {
            const definition = row.cols[8] orelse continue;
            if (!package_exposure.matches(allocator, definition, payload)) continue;
        } else {
            if (row.cols[3] == null) continue;
            const path = row.cols[4];
            const match_value = row.cols[5] orelse continue;
            if (!util.payloadContains(payload, path, match_value)) continue;
        }
        if (matchingSuppression(sups, row.cols[0].?, agent_id, payload)) |sid| {
            try conn.execNoRows(
                \\UPDATE suppression_rules
                \\SET suppressed_count = suppressed_count + 1, last_suppressed_at = $2::timestamptz
                \\WHERE id = $1::uuid
            , &.{ .{ .text = sid }, .{ .text = created } });
            continue;
        }
        const title = try std.fmt.allocPrint(allocator, "{s} on {s}", .{ row.cols[1] orelse "rule", hostname });
        defer allocator.free(title);
        const inserted = try conn.exec(allocator,
            \\INSERT INTO alerts (tenant_id, alert_rule_id, agent_id, telemetry_event_id, telemetry_received_at,
            \\  severity, status, title, created_at)
            \\VALUES ($1::uuid, $2::uuid, $3::uuid, $4::bigint, $5::timestamptz, $6, 'open', $7, $8::timestamptz)
            \\RETURNING id::text
        , &.{
            .{ .text = tenant_id },
            .{ .text = row.cols[0].? },
            .{ .text = agent_id },
            .{ .text = event_id },
            .{ .text = received_at },
            .{ .text = row.cols[2] orelse "medium" },
            .{ .text = title },
            .{ .text = created },
        });
        defer {
            for (inserted) |irow| irow.deinit(allocator);
            allocator.free(inserted);
        }
        if (inserted.len == 0) continue;
        enqueueSink(allocator, conn, tenant_id, inserted[0].cols[0].?) catch |err| {
            std.debug.print("sink enqueue failed: {s}\n", .{@errorName(err)});
        };
    }
}

fn matchingSuppression(rules: []const pg.Row, rule_id: []const u8, agent_id: []const u8, payload: []const u8) ?[]const u8 {
    for (rules) |s| {
        const id = s.cols[0] orelse continue;
        const scope = s.cols[1] orelse continue;
        if (std.mem.eql(u8, scope, "specific_rule")) {
            const bound = s.cols[2] orelse continue;
            if (!std.mem.eql(u8, bound, rule_id)) continue;
        }
        if (s.cols[3]) |bound_agent| {
            if (!std.mem.eql(u8, bound_agent, agent_id)) continue;
        }
        const path = s.cols[4];
        if (path == null or path.?.len == 0) return id;
        const op = s.cols[5] orelse continue;
        const want = s.cols[6] orelse continue;
        if (std.mem.eql(u8, op, "exists")) return id;
        if (util.payloadContains(payload, path, want)) return id;
    }
    return null;
}

fn enqueueSink(allocator: std.mem.Allocator, conn: *pg.Conn, tenant_id: []const u8, alert_id: []const u8) !void {
    const alert_j = try util.escapeJson(allocator, alert_id);
    defer allocator.free(alert_j);
    const tenant_j = try util.escapeJson(allocator, tenant_id);
    defer allocator.free(tenant_j);
    const payload = try std.fmt.allocPrint(allocator, "{{\"alert_id\":{s},\"tenant_id\":{s}}}", .{ alert_j, tenant_j });
    defer allocator.free(payload);
    try conn.execNoRows(
        \\INSERT INTO work_queue (kind, tenant_id, payload)
        \\VALUES ('sink', $1::uuid, $2::jsonb)
    , &.{ .{ .text = tenant_id }, .{ .text = payload } });
}

const default_tenant = "00000000-0000-0000-0000-000000000001";
const detect_agent = "00000000-0000-0000-0000-00000000d401";
const detect_rule = "00000000-0000-0000-0000-00000000d402";

test "enqueue leaves zero alerts until drain" {
    const url = std.testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return;
    if (url.len == 0) return;

    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const conn = try pg.Conn.connect(allocator, io, url);
    defer {
        conn.close();
        allocator.destroy(conn);
    }

    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};

    try exec(conn,
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status
        \\) VALUES ($1, $2, 'async-host', 'linux', 'test', '0', 'arm64', now(), 'online')
    , &.{ .{ .text = detect_agent }, .{ .text = default_tenant } });
    try exec(conn,
        \\INSERT INTO alert_rules (
        \\  id, tenant_id, name, format, severity, operator, payload_path, match_value,
        \\  event_type, created_at, updated_at
        \\) VALUES (
        \\  $1, $2, 'async-detect-rule', 'tawny_predicate', 'high', 'contains',
        \\  'command_line', 'async-detect-marker', 'process_start', now(), now()
        \\)
    , &.{ .{ .text = detect_rule }, .{ .text = default_tenant } });

    const inserted = try conn.exec(allocator,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES (now(), $1, $2, 'process_start', now(), '{"command_line":"curl async-detect-marker"}')
        \\RETURNING id::text, received_at::text
    , &.{ .{ .text = default_tenant }, .{ .text = detect_agent } });
    defer {
        for (inserted) |row| row.deinit(allocator);
        allocator.free(inserted);
    }
    try std.testing.expect(inserted.len == 1);
    const event_id = inserted[0].cols[0].?;
    const received_at = inserted[0].cols[1].?;

    try enqueue(allocator, conn, default_tenant, detect_agent, "async-host", "process_start", event_id, received_at);

    const before = try scalar(allocator, conn, "SELECT count(*)::text FROM alerts WHERE telemetry_event_id = $1::bigint", &.{
        .{ .text = event_id },
    });
    defer allocator.free(before);
    const queued = try scalar(allocator, conn,
        \\SELECT count(*)::text FROM work_queue
        \\WHERE kind = 'detect' AND payload->>'event_id' = $1
    , &.{.{ .text = event_id }});
    defer allocator.free(queued);

    // Other ready jobs would be claimed first. Park them for this transaction.
    try exec(conn,
        \\UPDATE work_queue SET locked_until = now() + interval '1 hour'
        \\WHERE kind = 'detect' AND payload->>'event_id' IS DISTINCT FROM $1
    , &.{.{ .text = event_id }});

    const finished = try drain(allocator, io, conn);
    const after = try scalar(allocator, conn, "SELECT count(*)::text FROM alerts WHERE telemetry_event_id = $1::bigint", &.{
        .{ .text = event_id },
    });
    defer allocator.free(after);
    const left = try scalar(allocator, conn,
        \\SELECT count(*)::text FROM work_queue
        \\WHERE kind = 'detect' AND payload->>'event_id' = $1
    , &.{.{ .text = event_id }});
    defer allocator.free(left);

    std.debug.print("detect_async queued={s} alerts_before={s} alerts_after={s} queued_after={s} drained={d}\n", .{
        queued, before, after, left, finished,
    });
    try std.testing.expectEqualStrings("1", queued);
    try std.testing.expectEqualStrings("0", before);
    try std.testing.expectEqualStrings("1", after);
    try std.testing.expectEqualStrings("0", left);
    try std.testing.expect(finished >= 1);

    try conn.execSimple("ROLLBACK");
}

const suppress_agent = "00000000-0000-0000-0000-00000000d601";
const suppress_rule = "00000000-0000-0000-0000-00000000d602";
const suppress_id = "00000000-0000-0000-0000-00000000d603";

test "suppression skips the alert and increments the counter" {
    const url = std.testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return;
    if (url.len == 0) return;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const conn = try pg.Conn.connect(allocator, io, url);
    defer {
        conn.close();
        allocator.destroy(conn);
    }
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};

    try exec(conn,
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status
        \\) VALUES ($1, $2, 'suppress-host', 'linux', 'test', '0', 'arm64', now(), 'online')
    , &.{ .{ .text = suppress_agent }, .{ .text = default_tenant } });
    try exec(conn,
        \\INSERT INTO alert_rules (
        \\  id, tenant_id, name, format, severity, operator, payload_path, match_value,
        \\  event_type, created_at, updated_at
        \\) VALUES (
        \\  $1, $2, 'suppress-rule', 'tawny_predicate', 'high', 'contains',
        \\  'command_line', 'suppress-marker', 'process_start', now(), now()
        \\)
    , &.{ .{ .text = suppress_rule }, .{ .text = default_tenant } });
    try exec(conn,
        \\INSERT INTO suppression_rules (
        \\  id, tenant_id, name, scope, alert_rule_id, payload_path, operator, match_value,
        \\  is_enabled, created_at, updated_at
        \\) VALUES (
        \\  $1, $2, 'suppress-marker', 'specific_rule', $3, 'command_line', 'contains',
        \\  'suppress-marker', true, now(), now()
        \\)
    , &.{ .{ .text = suppress_id }, .{ .text = default_tenant }, .{ .text = suppress_rule } });

    const inserted = try conn.exec(allocator,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES (now(), $1, $2, 'process_start', now(), '{"command_line":"curl suppress-marker"}')
        \\RETURNING id::text, received_at::text
    , &.{ .{ .text = default_tenant }, .{ .text = suppress_agent } });
    defer {
        for (inserted) |row| row.deinit(allocator);
        allocator.free(inserted);
    }
    const event_id = inserted[0].cols[0].?;
    const received_at = inserted[0].cols[1].?;
    try enqueue(allocator, conn, default_tenant, suppress_agent, "suppress-host", "process_start", event_id, received_at);
    try exec(conn,
        \\UPDATE work_queue SET locked_until = now() + interval '1 hour'
        \\WHERE kind = 'detect' AND payload->>'event_id' IS DISTINCT FROM $1
    , &.{.{ .text = event_id }});

    const finished = try drain(allocator, io, conn);
    const alerts = try scalar(allocator, conn, "SELECT count(*)::text FROM alerts WHERE telemetry_event_id = $1::bigint", &.{
        .{ .text = event_id },
    });
    defer allocator.free(alerts);
    const count = try scalar(allocator, conn, "SELECT suppressed_count::text FROM suppression_rules WHERE id = $1::uuid", &.{
        .{ .text = suppress_id },
    });
    defer allocator.free(count);
    std.debug.print("suppress_job alerts={s} count={s} drained={d}\n", .{ alerts, count, finished });
    try std.testing.expectEqualStrings("0", alerts);
    try std.testing.expectEqualStrings("1", count);
    try std.testing.expect(finished >= 1);
    try conn.execSimple("ROLLBACK");
}

const exposure_agent = "00000000-0000-0000-0000-00000000e901";
const exposure_rule = "00000000-0000-0000-0000-00000000e902";
const exposure_bad = "00000000-0000-0000-0000-00000000e903";

test "package exposure inventory alerts only after drain" {
    const url = std.testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return;
    if (url.len == 0) return;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const conn = try pg.Conn.connect(allocator, io, url);
    defer {
        conn.close();
        allocator.destroy(conn);
    }
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};

    try exec(conn,
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status
        \\) VALUES ($1, $2, 'exposure-host', 'linux', 'test', '0', 'arm64', now(), 'online')
    , &.{ .{ .text = exposure_agent }, .{ .text = default_tenant } });
    try exec(conn,
        \\INSERT INTO alert_rules (
        \\  id, tenant_id, name, format, severity, operator, event_type,
        \\  source_definition, created_at, updated_at
        \\) VALUES (
        \\  $1, $2, 'exposed-left-pad', 'package_exposure', 'high', 'exists',
        \\  'package_inventory', $3, now(), now()
        \\)
    , &.{
        .{ .text = exposure_rule },
        .{ .text = default_tenant },
        .{ .text = "{\"ecosystem\":\"npm\",\"name\":\"left-pad\",\"version_pattern\":\"^1.2.3\"}" },
    });
    try exec(conn,
        \\INSERT INTO alert_rules (
        \\  id, tenant_id, name, format, severity, operator, event_type,
        \\  source_definition, created_at, updated_at
        \\) VALUES (
        \\  $1, $2, 'bad-exposure', 'package_exposure', 'high', 'exists',
        \\  'package_inventory', 'not-json', now(), now()
        \\)
    , &.{ .{ .text = exposure_bad }, .{ .text = default_tenant } });

    const hit = try conn.exec(allocator,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES (now(), $1, $2, 'package_inventory', now(),
        \\  '{"ecosystem":"npm","name":"left-pad","version":"1.9.0"}')
        \\RETURNING id::text, received_at::text
    , &.{ .{ .text = default_tenant }, .{ .text = exposure_agent } });
    defer {
        for (hit) |row| row.deinit(allocator);
        allocator.free(hit);
    }
    const miss = try conn.exec(allocator,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES (now(), $1, $2, 'package_inventory', now(),
        \\  '{"ecosystem":"npm","name":"left-pad","version":"2.0.0"}')
        \\RETURNING id::text, received_at::text
    , &.{ .{ .text = default_tenant }, .{ .text = exposure_agent } });
    defer {
        for (miss) |row| row.deinit(allocator);
        allocator.free(miss);
    }
    try std.testing.expect(hit.len == 1 and miss.len == 1);
    const hit_id = hit[0].cols[0].?;
    const miss_id = miss[0].cols[0].?;
    try enqueue(allocator, conn, default_tenant, exposure_agent, "exposure-host", "package_inventory", hit_id, hit[0].cols[1].?);
    try enqueue(allocator, conn, default_tenant, exposure_agent, "exposure-host", "package_inventory", miss_id, miss[0].cols[1].?);

    const before = try scalar(allocator, conn, "SELECT count(*)::text FROM alerts WHERE telemetry_event_id = $1::bigint", &.{
        .{ .text = hit_id },
    });
    defer allocator.free(before);
    try exec(conn,
        \\UPDATE work_queue SET locked_until = now() + interval '1 hour'
        \\WHERE kind = 'detect'
        \\  AND payload->>'event_id' IS DISTINCT FROM $1
        \\  AND payload->>'event_id' IS DISTINCT FROM $2
    , &.{ .{ .text = hit_id }, .{ .text = miss_id } });

    const finished = try drain(allocator, io, conn);
    const hit_alerts = try scalar(allocator, conn, "SELECT count(*)::text FROM alerts WHERE telemetry_event_id = $1::bigint", &.{
        .{ .text = hit_id },
    });
    defer allocator.free(hit_alerts);
    const miss_alerts = try scalar(allocator, conn, "SELECT count(*)::text FROM alerts WHERE telemetry_event_id = $1::bigint", &.{
        .{ .text = miss_id },
    });
    defer allocator.free(miss_alerts);
    std.debug.print("package_exposure before={s} hit={s} miss={s} drained={d}\n", .{
        before, hit_alerts, miss_alerts, finished,
    });
    try std.testing.expectEqualStrings("0", before);
    try std.testing.expectEqualStrings("1", hit_alerts);
    try std.testing.expectEqualStrings("0", miss_alerts);
    try std.testing.expect(finished >= 2);
    try conn.execSimple("ROLLBACK");
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
