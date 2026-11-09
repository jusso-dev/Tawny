//! Drain `work_queue` kind `incident_sink`: send each incident to Tawny-SOC
//! (sinks/tawny_soc.zig) through its existing ingest endpoint. Rows are
//! queued by detect (30 s debounce) and by incident assign or status.
//!
//! Configured with the existing TAWNY_SOC_* variables:
//!   TAWNY_SOC_ENABLED=true, TAWNY_SOC_ENDPOINT_URL, TAWNY_SOC_API_TOKEN
//!   TAWNY_SOC_INCIDENTS_ENABLED (default true when the sink is enabled)
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const egress = @import("../sinks/egress.zig");
const soc = @import("../sinks/tawny_soc.zig");

pub const Config = struct {
    endpoint: []const u8 = "",
    token: []const u8 = "",
    public_url: []const u8 = "",
    allow_private: bool = false,
};

const max_attempts: u32 = 5;

fn freeRows(allocator: std.mem.Allocator, rows: []pg.Row) void {
    for (rows) |row| row.deinit(allocator);
    allocator.free(rows);
}

pub fn drain(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, cfg: Config) !u32 {
    const claimed = try conn.exec(allocator,
        \\UPDATE work_queue SET locked_until = now() + interval '5 minutes', attempts = attempts + 1
        \\WHERE id IN (
        \\  SELECT id FROM work_queue
        \\  WHERE kind = 'incident_sink' AND run_after <= now()
        \\    AND (locked_until IS NULL OR locked_until < now())
        \\  ORDER BY id LIMIT 16
        \\  FOR UPDATE SKIP LOCKED
        \\)
        \\RETURNING id::text, tenant_id::text, payload->>'incident_id', attempts::text
    , &.{});
    defer freeRows(allocator, claimed);
    var done: u32 = 0;
    for (claimed) |row| {
        const qid = row.cols[0] orelse continue;
        const tenant = row.cols[1] orelse "";
        const incident = row.cols[2] orelse "";
        const attempts = std.fmt.parseInt(u32, row.cols[3] orelse "1", 10) catch 1;
        if (cfg.endpoint.len == 0) {
            try mark(conn, tenant, incident, "not_configured", null);
            try deleteJob(conn, qid);
            done += 1;
            continue;
        }
        if (sendOne(allocator, io, conn, cfg, tenant, incident)) |_| {
            try mark(conn, tenant, incident, "sent", null);
            try deleteJob(conn, qid);
            done += 1;
        } else |err| {
            const permanent = err == error.EgressRefused or err == error.NotFound or attempts >= max_attempts;
            if (permanent) {
                try mark(conn, tenant, incident, "failed", @errorName(err));
                try deleteJob(conn, qid);
                done += 1;
            } else {
                try conn.execNoRows(
                    \\UPDATE work_queue SET last_error = $2, locked_until = now() + interval '1 minute' WHERE id = $1::bigint
                , &.{ .{ .text = qid }, .{ .text = @errorName(err) } });
            }
        }
    }
    return done;
}

fn mark(conn: *pg.Conn, tenant: []const u8, incident: []const u8, status: []const u8, err: ?[]const u8) !void {
    try conn.execNoRows(
        \\UPDATE incidents SET soc_case_status = $3, soc_error = $4,
        \\  soc_synced_at = CASE WHEN $3 = 'sent' THEN now() ELSE soc_synced_at END
        \\WHERE tenant_id = $1::uuid AND id = $2::uuid
    , &.{ .{ .text = tenant }, .{ .text = incident }, .{ .text = status }, if (err) |e| .{ .text = e } else .{ .null = {} } });
}

fn deleteJob(conn: *pg.Conn, id: []const u8) !void {
    try conn.execNoRows("DELETE FROM work_queue WHERE id = $1::bigint", &.{.{ .text = id }});
}

/// Build the batch for one incident. The agent block names the first agent
/// in the incident; every agent id is in `incident.agent_ids`.
pub fn buildBatch(allocator: std.mem.Allocator, conn: *pg.Conn, public_url: []const u8, tenant: []const u8, incident: []const u8, sent_at: []const u8) ![]u8 {
    const rows = try conn.exec(allocator,
        \\SELECT i.id::text, i.title, i.status, i.severity, i.risk::text, i.risk_items::text,
        \\       array_to_json(i.techniques)::text, array_to_json(i.agent_ids)::text,
        \\       i.first_seen_at::text, i.last_seen_at::text,
        \\       (SELECT count(*) FROM incident_alerts ia WHERE ia.incident_id = i.id)::text,
        \\       ag.id::text, ag.hostname, ag.operating_system, ag.os_version, ag.architecture, ag.agent_version
        \\FROM incidents i
        \\LEFT JOIN agents ag ON ag.id = i.agent_ids[1]
        \\WHERE i.tenant_id = $1::uuid AND i.id = $2::uuid
    , &.{ .{ .text = tenant }, .{ .text = incident } });
    defer freeRows(allocator, rows);
    if (rows.len == 0) return error.NotFound;
    const c = rows[0].cols;
    const url = try std.fmt.allocPrint(allocator, "{s}/incidents/{s}", .{ std.mem.trimEnd(u8, public_url, "/"), c[0] orelse "" });
    defer allocator.free(url);
    return soc.formatIncidentBatch(allocator, .{
        .id = c[11] orelse "",
        .tenant_id = tenant,
        .hostname = c[12] orelse "",
        .os = c[13] orelse "",
        .os_version = c[14] orelse "",
        .arch = c[15] orelse "",
        .version = c[16] orelse "",
    }, .{
        .id = c[0] orelse "",
        .tenant_id = tenant,
        .title = c[1] orelse "",
        .status = c[2] orelse "new",
        .severity = c[3] orelse "low",
        .risk = std.fmt.parseInt(i64, c[4] orelse "0", 10) catch 0,
        .risk_items = c[5] orelse "[]",
        .techniques = c[6] orelse "[]",
        .agent_ids = c[7] orelse "[]",
        .first_seen_at = c[8] orelse sent_at,
        .last_seen_at = c[9] orelse sent_at,
        .alert_count = std.fmt.parseInt(i64, c[10] orelse "0", 10) catch 0,
        .url = url,
    }, sent_at);
}

fn sendOne(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, cfg: Config, tenant: []const u8, incident: []const u8) !void {
    const host = hostOf(cfg.endpoint) orelse return error.EgressRefused;
    if (!egress.allowed(host, cfg.allow_private)) return error.EgressRefused;
    var tbuf: [32]u8 = undefined;
    const body = try buildBatch(allocator, conn, cfg.public_url, tenant, incident, util.formatRfc3339(&tbuf, util.nowUnix(io)));
    defer allocator.free(body);
    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();
    var buf: [2048]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    var authz_buf: [512]u8 = undefined;
    const authz = if (cfg.token.len > 0) std.fmt.bufPrint(&authz_buf, "Bearer {s}", .{cfg.token}) catch return error.SinkSend else "";
    const extra = [_]std.http.Header{.{ .name = "authorization", .value = authz }};
    const result = client.fetch(.{
        .location = .{ .url = cfg.endpoint },
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
        .extra_headers = if (cfg.token.len > 0) &extra else &.{},
    }) catch return error.SinkSend;
    if (@intFromEnum(result.status) >= 300) return error.SinkSend;
}

fn hostOf(url: []const u8) ?[]const u8 {
    const sep = std.mem.indexOf(u8, url, "://") orelse return null;
    const rest = url[sep + 3 ..];
    const end = std.mem.indexOfAny(u8, rest, ":/?#") orelse rest.len;
    if (end == 0 or std.mem.indexOfScalar(u8, rest[0..end], '@') != null) return null;
    return rest[0..end];
}

test "incident sink drains without config and refuses private endpoints" {
    try std.testing.expectEqualStrings("soc.example.com", hostOf("https://soc.example.com/api/ingest/tawny").?);
    try std.testing.expect(hostOf("https://user@soc/x") == null);
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
    defer conn.execSimple("ROLLBACK") catch {};
    const tenant = "00000000-0000-0000-0000-000000000001";
    const inc = "00000000-0000-4000-8000-00000000e601";
    try conn.execNoRows(
        \\INSERT INTO incidents (id, tenant_id, title, severity, risk, grouping, first_seen_at, last_seen_at, created_at, updated_at)
        \\VALUES ($1::uuid, $2::uuid, 'sink test', 'low', 10, 'alert', now(), now(), now(), now())
    , &.{ .{ .text = inc }, .{ .text = tenant } });
    try conn.execNoRows("UPDATE work_queue SET locked_until = now() + interval '1 hour' WHERE kind = 'incident_sink'", &.{});
    const payload = "{\"incident_id\":\"" ++ inc ++ "\"}";
    try conn.execNoRows("INSERT INTO work_queue (kind, tenant_id, payload) VALUES ('incident_sink', $1::uuid, $2::jsonb)", &.{ .{ .text = tenant }, .{ .text = payload } });
    // Batch shape from the database row.
    const body = try buildBatch(allocator, conn, "https://tawny.example", tenant, inc, "2026-11-10T00:00:00Z");
    defer allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "https://tawny.example/incidents/" ++ inc) != null);
    // Loopback endpoint: refused, marked failed, job removed.
    try std.testing.expectEqual(@as(u32, 1), try drain(allocator, io, conn, .{ .endpoint = "http://127.0.0.1:9/api/ingest/tawny" }));
    const rows = try conn.exec(allocator, "SELECT soc_case_status, soc_error FROM incidents WHERE id = $1::uuid", &.{.{ .text = inc }});
    defer freeRows(allocator, rows);
    try std.testing.expectEqualStrings("failed", rows[0].cols[0].?);
    try std.testing.expectEqualStrings("EgressRefused", rows[0].cols[1].?);
}
