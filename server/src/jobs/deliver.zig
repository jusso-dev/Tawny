//! Drain `work_queue` kind `sink` after detection. Formats the alert and
//! sends it only when the destination host passes `egress.allowed`, including
//! the address DNS returns. A refused host is a permanent failure.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const egress = @import("../sinks/egress.zig");
const slack = @import("../sinks/slack.zig");
const wazuh = @import("../sinks/wazuh.zig");

const SinkJob = struct {
    alert_id: []const u8,
    tenant_id: []const u8,
};

pub const Targets = struct {
    slack_webhook: []const u8 = "",
    wazuh_host: []const u8 = "",
    wazuh_port: u16 = 514,
    wazuh_protocol: []const u8 = "udp",
    allow_private: bool = false,
};

const max_attempts: u32 = 5;

pub fn drain(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, targets: Targets) !u32 {
    const claimed = try conn.exec(allocator,
        \\UPDATE work_queue SET locked_until = now() + interval '5 minutes', attempts = attempts + 1
        \\WHERE id IN (
        \\  SELECT id FROM work_queue
        \\  WHERE kind = 'sink' AND run_after <= now()
        \\    AND (locked_until IS NULL OR locked_until < now())
        \\  ORDER BY id
        \\  LIMIT 32
        \\  FOR UPDATE SKIP LOCKED
        \\)
        \\RETURNING id::text, payload::text, attempts::text
    , &.{});
    defer {
        for (claimed) |row| row.deinit(allocator);
        allocator.free(claimed);
    }
    var done: u32 = 0;
    for (claimed) |row| {
        const qid = row.cols[0] orelse continue;
        const payload_txt = row.cols[1] orelse {
            try failJob(conn, qid, "missing payload");
            continue;
        };
        const attempts = std.fmt.parseInt(u32, row.cols[2] orelse "1", 10) catch 1;
        var parsed = std.json.parseFromSlice(SinkJob, allocator, payload_txt, .{
            .ignore_unknown_fields = true,
        }) catch {
            try failJob(conn, qid, "bad payload");
            continue;
        };
        defer parsed.deinit();
        if (attempts >= max_attempts) {
            try markSlack(conn, parsed.value.alert_id, "failed", "retries exhausted");
            try deleteJob(conn, qid);
            done += 1;
            continue;
        }
        if (deliverOne(allocator, io, conn, targets, parsed.value, qid)) |_| {
            done += 1;
        } else |err| {
            switch (err) {
                error.EgressRefused => {
                    try markSlack(conn, parsed.value.alert_id, "failed", "egress refused");
                    try deleteJob(conn, qid);
                    done += 1;
                },
                else => try failJob(conn, qid, "send failed"),
            }
        }
    }
    return done;
}

fn deliverOne(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    targets: Targets,
    job: SinkJob,
    qid: []const u8,
) !void {
    if (targets.slack_webhook.len == 0 and targets.wazuh_host.len == 0) {
        // Nothing configured. Same as the .NET noop sink.
        try deleteJob(conn, qid);
        return;
    }
    const rows = try conn.exec(allocator,
        \\SELECT a.id::text, a.alert_rule_id::text, a.severity, a.status, a.title,
        \\       a.description, a.created_at::text, ag.id::text, ag.tenant_id::text,
        \\       ag.hostname, ag.operating_system, ag.os_version, ag.architecture, ag.agent_version,
        \\       te.id::text, te.event_type, te.occurred_at::text, te.received_at::text, te.payload::text
        \\FROM alerts a
        \\JOIN agents ag ON ag.id = a.agent_id
        \\JOIN telemetry_events te ON te.id = a.telemetry_event_id AND te.received_at = a.telemetry_received_at
        \\WHERE a.id = $1::bigint AND a.tenant_id = $2::uuid
    , &.{ .{ .text = job.alert_id }, .{ .text = job.tenant_id } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) {
        try deleteJob(conn, qid);
        return;
    }
    const alert = rows[0];
    if (targets.slack_webhook.len > 0) {
        const host = hostFromUrl(targets.slack_webhook) orelse return error.EgressRefused;
        if (!egress.allowed(host, targets.allow_private)) return error.EgressRefused;
        const body = try slack.format(
            allocator,
            "",
            "",
            alert.cols[2] orelse "medium",
            alert.cols[3] orelse "open",
            alert.cols[4] orelse "alert",
            alert.cols[5] orelse "",
            alert.cols[9] orelse "",
            pascalEvent(alert.cols[15] orelse ""),
            std.fmt.parseInt(i64, alert.cols[0] orelse "0", 10) catch 0,
            alert.cols[6] orelse "",
        );
        defer allocator.free(body);
        try postSlack(allocator, io, targets.slack_webhook, body);
        try markSlack(conn, job.alert_id, "sent", "");
    }
    if (targets.wazuh_host.len > 0) {
        if (!egress.allowed(targets.wazuh_host, targets.allow_private)) return error.EgressRefused;
        const id = std.fmt.parseInt(i64, alert.cols[0] orelse "0", 10) catch 0;
        const tel_id = std.fmt.parseInt(i64, alert.cols[14] orelse "0", 10) catch 0;
        const line = try wazuh.format(allocator, .{}, .{
            .id = alert.cols[7] orelse "",
            .tenant_id = alert.cols[8] orelse "",
            .hostname = alert.cols[9] orelse "",
            .os = alert.cols[10] orelse "",
            .os_version = alert.cols[11] orelse "",
            .arch = alert.cols[12] orelse "",
            .version = alert.cols[13] orelse "",
        }, .{
            .id = id,
            .rule_id = alert.cols[1] orelse "",
            .severity = alert.cols[2] orelse "medium",
            .status = alert.cols[3] orelse "open",
            .title = alert.cols[4] orelse "alert",
            .description = alert.cols[5],
            .created_at = alert.cols[6] orelse "",
        }, .{
            .id = tel_id,
            .event_type = alert.cols[15] orelse "",
            .occurred_at = alert.cols[16] orelse "",
            .received_at = alert.cols[17] orelse "",
            .payload = alert.cols[18] orelse "{}",
        });
        defer allocator.free(line);
        try sendWazuh(io, targets.wazuh_host, targets.wazuh_port, targets.wazuh_protocol, line, targets.allow_private);
    }
    try deleteJob(conn, qid);
}

fn postSlack(allocator: std.mem.Allocator, io: std.Io, url: []const u8, body: []const u8) !void {
    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();
    var buf: [2048]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .payload = body,
        .keep_alive = false,
        .redirect_behavior = .unhandled,
        .response_writer = &writer,
        .headers = .{
            .user_agent = .{ .override = "tawny-server" },
            .accept_encoding = .{ .override = "identity" },
            .content_type = .{ .override = "application/json" },
        },
    }) catch return error.SinkSend;
    const code = @intFromEnum(result.status);
    if (code == 429 or code >= 500) return error.SinkSend;
    if (code >= 400) return error.SinkSend;
}

fn sendWazuh(
    io: std.Io,
    host: []const u8,
    port: u16,
    protocol: []const u8,
    payload: []const u8,
    allow_private: bool,
) !void {
    const dest = std.Io.net.IpAddress.resolve(io, host, port) catch return error.SinkSend;
    if (!addressAllowed(dest, allow_private)) return error.EgressRefused;
    if (std.ascii.eqlIgnoreCase(protocol, "tcp")) {
        const stream = dest.connect(io, .{ .mode = .stream }) catch return error.SinkSend;
        defer stream.close(io);
        var buf: [1024]u8 = undefined;
        var w = stream.writer(io, &buf);
        w.interface.writeAll(payload) catch return error.SinkSend;
        w.interface.writeAll("\n") catch return error.SinkSend;
        w.interface.flush() catch return error.SinkSend;
        return;
    }
    const local = std.Io.net.IpAddress{ .ip4 = std.Io.net.Ip4Address.unspecified(0) };
    const sock = local.bind(io, .{ .mode = .dgram }) catch return error.SinkSend;
    defer sock.close(io);
    sock.send(io, &dest, payload) catch return error.SinkSend;
}

fn addressAllowed(addr: std.Io.net.IpAddress, allow_private: bool) bool {
    switch (addr) {
        .ip4 => |ip4| {
            var buf: [16]u8 = undefined;
            const text = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{
                ip4.bytes[0], ip4.bytes[1], ip4.bytes[2], ip4.bytes[3],
            }) catch return false;
            return egress.allowed(text, allow_private);
        },
        .ip6 => return allow_private,
    }
}

pub fn hostFromUrl(url: []const u8) ?[]const u8 {
    const sep = std.mem.indexOf(u8, url, "://") orelse return null;
    if (sep == 0) return null;
    const rest = url[sep + 3 ..];
    if (rest.len == 0) return null;
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    var auth = rest[0..slash];
    if (std.mem.indexOfScalar(u8, auth, '@') != null) return null;
    if (auth.len >= 2 and auth[0] == '[') {
        const end = std.mem.indexOfScalar(u8, auth, ']') orelse return null;
        if (end < 2) return null;
        return auth[1..end];
    }
    if (std.mem.indexOfScalar(u8, auth, ':')) |colon| auth = auth[0..colon];
    if (auth.len == 0) return null;
    return auth;
}

fn pascalEvent(event_type: []const u8) []const u8 {
    if (std.mem.eql(u8, event_type, "process_snapshot")) return "ProcessSnapshot";
    if (std.mem.eql(u8, event_type, "network_snapshot")) return "NetworkSnapshot";
    if (std.mem.eql(u8, event_type, "user_session")) return "UserSession";
    if (std.mem.eql(u8, event_type, "system_info")) return "SystemInfo";
    if (std.mem.eql(u8, event_type, "file_integrity")) return "FileIntegrity";
    if (std.mem.eql(u8, event_type, "heartbeat")) return "Heartbeat";
    if (std.mem.eql(u8, event_type, "dns_query")) return "DnsQuery";
    if (std.mem.eql(u8, event_type, "process_launch")) return "ProcessLaunch";
    if (std.mem.eql(u8, event_type, "file_event")) return "FileEvent";
    if (std.mem.eql(u8, event_type, "package_inventory")) return "PackageInventory";
    return event_type;
}

fn markSlack(conn: *pg.Conn, alert_id: []const u8, status: []const u8, err_text: []const u8) !void {
    const err_val: pg.Value = if (err_text.len == 0) .{ .null = {} } else .{ .text = err_text };
    try conn.execNoRows(
        \\UPDATE alerts SET slack_notification_status = $2, slack_notification_error = $3
        \\WHERE id = $1::bigint
    , &.{ .{ .text = alert_id }, .{ .text = status }, err_val });
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

test "webhook host parse" {
    try std.testing.expectEqualStrings("127.0.0.1", hostFromUrl("http://127.0.0.1:9/hook").?);
    try std.testing.expectEqualStrings("hooks.slack.com", hostFromUrl("https://hooks.slack.com/services/T/B").?);
    try std.testing.expectEqualStrings("::1", hostFromUrl("http://[::1]/hook").?);
    try std.testing.expect(hostFromUrl("http://user:pass@127.0.0.1/hook") == null);
}

const default_tenant = "00000000-0000-0000-0000-000000000001";
const sink_agent = "00000000-0000-0000-0000-00000000d701";
const sink_rule = "00000000-0000-0000-0000-00000000d702";

test "sink drain refuses a loopback webhook and does not mark it sent" {
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
        \\) VALUES ($1, $2, 'sink-host', 'linux', 'test', '0.1.0', 'arm64', now(), 'online')
    , &.{ .{ .text = sink_agent }, .{ .text = default_tenant } });
    try exec(conn,
        \\INSERT INTO alert_rules (
        \\  id, tenant_id, name, format, severity, operator, created_at, updated_at
        \\) VALUES ($1, $2, 'sink-rule', 'tawny_predicate', 'high', 'exists', now(), now())
    , &.{ .{ .text = sink_rule }, .{ .text = default_tenant } });
    const ev = try scalar(allocator, conn,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES (now(), $1, $2, 'process_snapshot', now(), '{"processes":[{"name":"suspicious.exe"}]}')
        \\RETURNING id::text
    , &.{ .{ .text = default_tenant }, .{ .text = sink_agent } });
    defer allocator.free(ev);
    const received = try scalar(allocator, conn,
        \\SELECT received_at::text FROM telemetry_events WHERE id = $1::bigint
    , &.{.{ .text = ev }});
    defer allocator.free(received);
    const alert_id = try scalar(allocator, conn,
        \\INSERT INTO alerts (
        \\  tenant_id, alert_rule_id, agent_id, telemetry_event_id, telemetry_received_at,
        \\  severity, status, title, created_at
        \\) VALUES ($1, $2, $3, $4::bigint, $5::timestamptz, 'high', 'open', 'sink alert', now())
        \\RETURNING id::text
    , &.{
        .{ .text = default_tenant },
        .{ .text = sink_rule },
        .{ .text = sink_agent },
        .{ .text = ev },
        .{ .text = received },
    });
    defer allocator.free(alert_id);

    const alert_j = try std.fmt.allocPrint(allocator, "\"{s}\"", .{alert_id});
    defer allocator.free(alert_j);
    const tenant_j = try std.fmt.allocPrint(allocator, "\"{s}\"", .{default_tenant});
    defer allocator.free(tenant_j);
    const payload = try std.fmt.allocPrint(allocator, "{{\"alert_id\":{s},\"tenant_id\":{s}}}", .{ alert_j, tenant_j });
    defer allocator.free(payload);
    try exec(conn,
        \\INSERT INTO work_queue (kind, tenant_id, payload) VALUES ('sink', $1::uuid, $2::jsonb)
    , &.{ .{ .text = default_tenant }, .{ .text = payload } });
    try exec(conn,
        \\UPDATE work_queue SET locked_until = now() + interval '1 hour'
        \\WHERE kind = 'sink' AND payload->>'alert_id' IS DISTINCT FROM $1
    , &.{.{ .text = alert_id }});

    const n = try drain(allocator, io, conn, .{ .slack_webhook = "http://127.0.0.1:9/hook" });
    const status = try scalar(allocator, conn, "SELECT slack_notification_status FROM alerts WHERE id = $1::bigint", &.{
        .{ .text = alert_id },
    });
    defer allocator.free(status);
    const err_text = try scalar(allocator, conn, "SELECT coalesce(slack_notification_error, '') FROM alerts WHERE id = $1::bigint", &.{
        .{ .text = alert_id },
    });
    defer allocator.free(err_text);
    const left = try scalar(allocator, conn,
        \\SELECT count(*)::text FROM work_queue WHERE kind = 'sink' AND payload->>'alert_id' = $1
    , &.{.{ .text = alert_id }});
    defer allocator.free(left);
    const notified = try scalar(allocator, conn, "SELECT slack_notified_at IS NULL FROM alerts WHERE id = $1::bigint", &.{
        .{ .text = alert_id },
    });
    defer allocator.free(notified);

    std.debug.print("sink_egress status={s} error={s} queued_after={s} drained={d} notified_null={s}\n", .{
        status, err_text, left, n, notified,
    });
    try std.testing.expectEqualStrings("failed", status);
    try std.testing.expectEqualStrings("egress refused", err_text);
    try std.testing.expectEqualStrings("0", left);
    try std.testing.expect(n >= 1);
    try std.testing.expect(std.mem.eql(u8, notified, "t") or std.mem.eql(u8, notified, "true"));

    try conn.execSimple("ROLLBACK");
}

fn exec(conn: *pg.Conn, sql: []const u8, params: []const pg.Value) !void {
    conn.execNoRows(sql, params) catch |err| {
        if (conn.takeError()) |msg| {
            std.debug.print("postgres: {s}\n{s}\n", .{ msg, sql });
            conn.allocator.free(msg);
        }
        return err;
    };
}

fn scalar(allocator: std.mem.Allocator, conn: *pg.Conn, sql: []const u8, params: []const pg.Value) ![]u8 {
    const rows = try conn.exec(allocator, sql, params);
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len != 1 or rows[0].cols.len == 0) return error.UnexpectedRowCount;
    const col = rows[0].cols[0] orelse return error.NullColumn;
    return allocator.dupe(u8, col);
}
