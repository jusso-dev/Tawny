//! Server-raised agent alerts (#58, target-edr §10):
//!
//! - `Agent silent`: an agent went offline without a clean shutdown notice.
//!   Closed by its next heartbeat. Never raised for revoked agents.
//! - `Sensor silent`: a sensor that was running (from `sensor_health` or
//!   `agent_health.sensors`) delivered nothing for 15 minutes while the agent
//!   kept heartbeating, or moved from running to a stopped or failed state.
//!   Closed when the sensor delivers again.
//! - `Agent tamper`: every `agent_tamper` event from the agent.
//!
//! Alerts need a rule and a telemetry event (foreign keys). Each tenant gets
//! one disabled system rule per kind (`tawny-system:<kind>`), and each alert
//! is anchored on a server-written `agent_silent` / `sensor_silent` event, or
//! the agent's own `agent_tamper` event.

const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");

pub const Kind = enum {
    agent_silent,
    sensor_silent,
    agent_tamper,

    pub fn externalId(self: Kind) []const u8 {
        return switch (self) {
            .agent_silent => "tawny-system:agent-silent",
            .sensor_silent => "tawny-system:sensor-silent",
            .agent_tamper => "tawny-system:agent-tamper",
        };
    }

    pub fn ruleName(self: Kind) []const u8 {
        return switch (self) {
            .agent_silent => "Agent silent",
            .sensor_silent => "Sensor silent",
            .agent_tamper => "Agent tamper",
        };
    }

    pub fn severity(self: Kind) []const u8 {
        return switch (self) {
            .agent_silent => "high",
            .sensor_silent => "medium",
            .agent_tamper => "high",
        };
    }
};

/// A sensor with no events for this long while its agent heartbeats is quiet.
pub const sensor_silence_seconds: i64 = 15 * 60;

const Rows = struct {
    allocator: std.mem.Allocator,
    rows: []pg.Row,
    fn deinit(self: Rows) void {
        for (self.rows) |r| r.deinit(self.allocator);
        self.allocator.free(self.rows);
    }
};

fn query(allocator: std.mem.Allocator, conn: *pg.Conn, sql: []const u8, params: []const pg.Value) !Rows {
    return .{ .allocator = allocator, .rows = try conn.exec(allocator, sql, params) };
}

/// Id of the tenant's system rule for `kind`, creating it when missing.
/// Caller frees.
pub fn ensureRule(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, tenant: []const u8, kind: Kind) ![]u8 {
    {
        const found = try query(allocator, conn,
            \\SELECT id::text FROM alert_rules WHERE tenant_id = $1::uuid AND external_id = $2 LIMIT 1
        , &.{ .{ .text = tenant }, .{ .text = kind.externalId() } });
        defer found.deinit();
        if (found.rows.len > 0) if (found.rows[0].cols[0]) |id| return allocator.dupe(u8, id);
    }
    var idbuf: [36]u8 = undefined;
    const id = util.newUuid(io, &idbuf);
    // Disabled, so the detect job never evaluates it against events.
    const ins = try query(allocator, conn,
        \\INSERT INTO alert_rules (id, tenant_id, name, format, external_id, description, severity, operator,
        \\  is_enabled, created_at, updated_at)
        \\VALUES ($1::uuid, $2::uuid, $3, 'tawny_predicate', $4, 'Raised by the Tawny server, not by event matching.',
        \\  $5, 'exists', false, now(), now())
        \\ON CONFLICT (tenant_id, external_id) WHERE external_id LIKE 'tawny-system:%' DO NOTHING
        \\RETURNING id::text
    , &.{
        .{ .text = id },
        .{ .text = tenant },
        .{ .text = kind.ruleName() },
        .{ .text = kind.externalId() },
        .{ .text = kind.severity() },
    });
    defer ins.deinit();
    if (ins.rows.len > 0) return allocator.dupe(u8, ins.rows[0].cols[0].?);
    // Lost a race with another writer: read theirs.
    const again = try query(allocator, conn,
        \\SELECT id::text FROM alert_rules WHERE tenant_id = $1::uuid AND external_id = $2 LIMIT 1
    , &.{ .{ .text = tenant }, .{ .text = kind.externalId() } });
    defer again.deinit();
    if (again.rows.len == 0) return error.SystemRuleMissing;
    return allocator.dupe(u8, again.rows[0].cols[0].?);
}

pub const Anchor = struct {
    event_id: []const u8,
    received_at: []const u8,
};

/// Insert the alert and queue it for the sinks. Returns the alert id (caller
/// frees).
pub fn raise(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    tenant: []const u8,
    agent_id: []const u8,
    kind: Kind,
    title: []const u8,
    description: []const u8,
    anchor: Anchor,
    now_rfc3339: []const u8,
) ![]u8 {
    const rule_id = try ensureRule(allocator, io, conn, tenant, kind);
    defer allocator.free(rule_id);
    const ins = try query(allocator, conn,
        \\INSERT INTO alerts (tenant_id, alert_rule_id, agent_id, telemetry_event_id, telemetry_received_at,
        \\  severity, status, title, description, created_at)
        \\VALUES ($1::uuid, $2::uuid, $3::uuid, $4::bigint, $5::timestamptz, $6, 'open', $7, $8, $9::timestamptz)
        \\RETURNING id::text
    , &.{
        .{ .text = tenant },
        .{ .text = rule_id },
        .{ .text = agent_id },
        .{ .text = anchor.event_id },
        .{ .text = anchor.received_at },
        .{ .text = kind.severity() },
        .{ .text = title },
        .{ .text = description },
        .{ .text = now_rfc3339 },
    });
    defer ins.deinit();
    const alert_id = try allocator.dupe(u8, ins.rows[0].cols[0].?);
    errdefer allocator.free(alert_id);
    const payload = try std.fmt.allocPrint(allocator, "{{\"alert_id\":\"{s}\",\"tenant_id\":\"{s}\"}}", .{ alert_id, tenant });
    defer allocator.free(payload);
    try conn.execNoRows(
        \\INSERT INTO work_queue (kind, tenant_id, payload) VALUES ('sink', $1::uuid, $2::jsonb)
    , &.{ .{ .text = tenant }, .{ .text = payload } });
    return alert_id;
}

/// Write a server-side marker event to anchor an alert. Not queued for
/// detection. Returns the anchor (caller frees both fields).
fn writeMarker(allocator: std.mem.Allocator, conn: *pg.Conn, tenant: []const u8, agent_id: []const u8, event_type: []const u8, payload: []const u8, now_rfc3339: []const u8) !Anchor {
    const rows = try query(allocator, conn,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, confidence, payload)
        \\VALUES ($1::timestamptz, $2::uuid, $3::uuid, $4, $1::timestamptz, 'server_observed', $5::jsonb)
        \\RETURNING id::text, received_at::text
    , &.{
        .{ .text = now_rfc3339 },
        .{ .text = tenant },
        .{ .text = agent_id },
        .{ .text = event_type },
        .{ .text = payload },
    });
    defer rows.deinit();
    const ev = try allocator.dupe(u8, rows.rows[0].cols[0].?);
    errdefer allocator.free(ev);
    return .{ .event_id = ev, .received_at = try allocator.dupe(u8, rows.rows[0].cols[1].?) };
}

/// Close open alerts of `kind` for an agent. Returns how many were closed.
pub fn close(allocator: std.mem.Allocator, conn: *pg.Conn, tenant: []const u8, agent_id: []const u8, kind: Kind) !usize {
    const rows = try query(allocator, conn,
        \\UPDATE alerts a SET status = 'resolved'
        \\FROM alert_rules r
        \\WHERE r.id = a.alert_rule_id AND r.tenant_id = a.tenant_id AND r.external_id = $3
        \\  AND a.tenant_id = $1::uuid AND a.agent_id = $2::uuid AND a.status = 'open'
        \\RETURNING a.id::text
    , &.{ .{ .text = tenant }, .{ .text = agent_id }, .{ .text = kind.externalId() } });
    defer rows.deinit();
    return rows.rows.len;
}

// ---------------------------------------------------------------------------
// Agent silent

/// Raise `Agent silent` for every agent that is offline, was not revoked, did
/// not send a clean shutdown notice, and has no open `Agent silent` alert.
/// Run after `stale.mark`. Returns how many alerts were raised.
pub fn raiseSilentAgents(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, now_rfc3339: []const u8) !u32 {
    const candidates = try query(allocator, conn,
        \\SELECT ag.tenant_id::text, ag.id::text, ag.hostname, ag.last_heartbeat_at::text
        \\FROM agents ag
        \\WHERE ag.status = 'offline' AND ag.revoked_at IS NULL
        \\  AND ag.clean_shutdown_at IS NULL AND ag.last_heartbeat_at IS NOT NULL
        \\  AND NOT EXISTS (
        \\    SELECT 1 FROM alerts a JOIN alert_rules r ON r.id = a.alert_rule_id
        \\    WHERE a.tenant_id = ag.tenant_id AND a.agent_id = ag.id AND a.status = 'open'
        \\      AND r.external_id = 'tawny-system:agent-silent')
        \\ORDER BY ag.last_heartbeat_at
        \\LIMIT 500
    , &.{});
    defer candidates.deinit();
    var raised: u32 = 0;
    for (candidates.rows) |row| {
        const tenant = row.cols[0] orelse continue;
        const agent_id = row.cols[1] orelse continue;
        const hostname = row.cols[2] orelse "";
        const last = row.cols[3] orelse "";
        const host_j = try util.escapeJson(allocator, hostname);
        defer allocator.free(host_j);
        const last_j = try util.escapeJson(allocator, last);
        defer allocator.free(last_j);
        const payload = try std.fmt.allocPrint(allocator, "{{\"hostname\":{s},\"last_heartbeat_at\":{s},\"reason\":\"offline without a clean shutdown notice\"}}", .{ host_j, last_j });
        defer allocator.free(payload);
        const anchor = try writeMarker(allocator, conn, tenant, agent_id, "agent_silent", payload, now_rfc3339);
        defer {
            allocator.free(anchor.event_id);
            allocator.free(anchor.received_at);
        }
        const title = try std.fmt.allocPrint(allocator, "Agent silent on {s}", .{hostname});
        defer allocator.free(title);
        const desc = try std.fmt.allocPrint(allocator, "{s} stopped sending heartbeats without a clean shutdown notice. Last heartbeat {s}.", .{ hostname, last });
        defer allocator.free(desc);
        const id = try raise(allocator, io, conn, tenant, agent_id, .agent_silent, title, desc, anchor, now_rfc3339);
        allocator.free(id);
        raised += 1;
    }
    return raised;
}

/// Heartbeat hook. `shutdown` is true for the clean shutdown notice. A normal
/// heartbeat clears an earlier notice and closes any open `Agent silent`.
pub fn onHeartbeat(allocator: std.mem.Allocator, conn: *pg.Conn, tenant: []const u8, agent_id: []const u8, shutdown: bool, reason: []const u8, now_rfc3339: []const u8) !void {
    if (shutdown) {
        try conn.execNoRows(
            \\UPDATE agents SET clean_shutdown_at = $3::timestamptz, clean_shutdown_reason = $4
            \\WHERE id = $1::uuid AND tenant_id = $2::uuid
        , &.{ .{ .text = agent_id }, .{ .text = tenant }, .{ .text = now_rfc3339 }, .{ .text = reason } });
        return;
    }
    try conn.execNoRows(
        \\UPDATE agents SET clean_shutdown_at = NULL, clean_shutdown_reason = NULL
        \\WHERE id = $1::uuid AND tenant_id = $2::uuid AND clean_shutdown_at IS NOT NULL
    , &.{ .{ .text = agent_id }, .{ .text = tenant } });
    _ = try close(allocator, conn, tenant, agent_id, .agent_silent);
}

// ---------------------------------------------------------------------------
// Sensors

/// What a sensor reported, normalised. `running` covers ok and degraded
/// states that still deliver. `stopped` covers stopped, failed, missing and
/// access_denied. `silent` is the agent's own 15 minute silence verdict.
pub const SensorState = enum { running, silent, stopped, unknown };

pub fn classify(state: []const u8) SensorState {
    const running = [_][]const u8{ "ok", "running", "degraded" };
    const stopped = [_][]const u8{ "stopped", "failed", "missing", "access_denied" };
    for (running) |s| if (std.ascii.eqlIgnoreCase(s, state)) return .running;
    for (stopped) |s| if (std.ascii.eqlIgnoreCase(s, state)) return .stopped;
    if (std.ascii.eqlIgnoreCase(state, "silent")) return .silent;
    return .unknown;
}

/// Sensors that deliver all the time on a working host. The others are
/// event-driven and can be quiet for hours.
pub fn isContinuous(sensor: []const u8) bool {
    const continuous = [_][]const u8{
        "Microsoft-Windows-Sysmon/Operational",
        "Security",
    };
    for (continuous) |c| if (std.mem.eql(u8, c, sensor)) return true;
    return false;
}

pub const SensorReport = struct {
    sensor: []const u8,
    state: []const u8,
    /// Seconds since the sensor's last event, when the agent knows it.
    last_event_age_seconds: ?i64 = null,
};

/// Ingest hook for `sensor_health` and `agent_health`. Upserts the per-sensor
/// row; a sensor that was running and is now stopped (or silent by the
/// agent's own clock) raises `Sensor silent`, and one that runs again closes
/// it.
pub fn recordSensor(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    tenant: []const u8,
    agent_id: []const u8,
    hostname: []const u8,
    report: SensorReport,
    anchor: Anchor,
    now_unix: i64,
) !void {
    var nbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&nbuf, now_unix);
    const state = classify(report.state);
    var lbuf: [32]u8 = undefined;
    // Only agent_health carries a last event age, refreshed every heartbeat.
    // sensor_health fires on state changes only, so it never feeds the
    // server-side quiet check (that would alert 15 minutes after any "ok").
    const last_event: ?[]const u8 = if (report.last_event_age_seconds) |age|
        util.formatRfc3339(&lbuf, now_unix - @max(age, 0))
    else
        null;

    const prev = try query(allocator, conn,
        \\SELECT state, was_running::text, open_alert_id::text FROM sensor_status
        \\WHERE tenant_id = $1::uuid AND agent_id = $2::uuid AND sensor = $3
    , &.{ .{ .text = tenant }, .{ .text = agent_id }, .{ .text = report.sensor } });
    defer prev.deinit();
    const had = prev.rows.len > 0;
    const was_running = had and std.mem.eql(u8, prev.rows[0].cols[1] orelse "false", "true");
    const open_alert = if (had) prev.rows[0].cols[2] else null;
    const state_text = @tagName(state);
    const changed = !had or !std.mem.eql(u8, prev.rows[0].cols[0] orelse "", state_text);

    try conn.execNoRows(
        \\INSERT INTO sensor_status (tenant_id, agent_id, sensor, state, state_since, was_running, continuous, last_event_at, updated_at)
        \\VALUES ($1::uuid, $2::uuid, $3, $4, $5::timestamptz, $6::boolean, $7::boolean, $8::timestamptz, $5::timestamptz)
        \\ON CONFLICT (tenant_id, agent_id, sensor) DO UPDATE SET
        \\  state = EXCLUDED.state,
        \\  state_since = CASE WHEN sensor_status.state = EXCLUDED.state THEN sensor_status.state_since ELSE EXCLUDED.state_since END,
        \\  was_running = sensor_status.was_running OR EXCLUDED.was_running,
        \\  last_event_at = COALESCE(EXCLUDED.last_event_at, sensor_status.last_event_at),
        \\  updated_at = EXCLUDED.updated_at
    , &.{
        .{ .text = tenant },
        .{ .text = agent_id },
        .{ .text = report.sensor },
        .{ .text = state_text },
        .{ .text = now_s },
        .{ .text = if (state == .running) "true" else "false" },
        .{ .text = if (isContinuous(report.sensor)) "true" else "false" },
        if (last_event) |l| .{ .text = l } else .{ .null = {} },
    });

    if (state == .running) {
        if (open_alert) |id| try resolveSensorAlert(conn, tenant, agent_id, report.sensor, id);
        return;
    }
    if (!changed or !was_running or open_alert != null) return;
    if (state != .stopped and state != .silent) return;
    // Sparse channels (PowerShell, System) are often quiet for hours; only a
    // stop or failure is news for them.
    if (state == .silent and !isContinuous(report.sensor)) return;
    const why = if (state == .silent) "reported no events for 15 minutes" else "stopped";
    const id = try raiseSensor(allocator, io, conn, tenant, agent_id, hostname, report.sensor, report.state, why, anchor, now_s);
    allocator.free(id);
}

fn raiseSensor(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    tenant: []const u8,
    agent_id: []const u8,
    hostname: []const u8,
    sensor: []const u8,
    state: []const u8,
    why: []const u8,
    anchor: Anchor,
    now_s: []const u8,
) ![]u8 {
    const title = try std.fmt.allocPrint(allocator, "Sensor silent on {s}: {s}", .{ hostname, sensor });
    defer allocator.free(title);
    const desc = try std.fmt.allocPrint(allocator, "Sensor {s} on {s} was running and {s} (state {s}).", .{ sensor, hostname, why, state });
    defer allocator.free(desc);
    const id = try raise(allocator, io, conn, tenant, agent_id, .sensor_silent, title, desc, anchor, now_s);
    errdefer allocator.free(id);
    try conn.execNoRows(
        \\UPDATE sensor_status SET open_alert_id = $4::bigint
        \\WHERE tenant_id = $1::uuid AND agent_id = $2::uuid AND sensor = $3
    , &.{ .{ .text = tenant }, .{ .text = agent_id }, .{ .text = sensor }, .{ .text = id } });
    return id;
}

fn resolveSensorAlert(conn: *pg.Conn, tenant: []const u8, agent_id: []const u8, sensor: []const u8, alert_id: []const u8) !void {
    try conn.execNoRows(
        \\UPDATE alerts SET status = 'resolved' WHERE id = $1::bigint AND tenant_id = $2::uuid AND status = 'open'
    , &.{ .{ .text = alert_id }, .{ .text = tenant } });
    try conn.execNoRows(
        \\UPDATE sensor_status SET open_alert_id = NULL
        \\WHERE tenant_id = $1::uuid AND agent_id = $2::uuid AND sensor = $3
    , &.{ .{ .text = tenant }, .{ .text = agent_id }, .{ .text = sensor } });
}

/// Periodic check: a continuous sensor that was running, whose agent is
/// online, and that has no event for 15 minutes raises `Sensor silent`. This
/// catches a sensor that stops without the agent noticing, for example when
/// the agent's own channel health is wedged. Returns alerts raised.
pub fn raiseQuietSensors(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, now_unix: i64) !u32 {
    var nbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&nbuf, now_unix);
    const rows = try query(allocator, conn,
        \\SELECT s.tenant_id::text, s.agent_id::text, ag.hostname, s.sensor, s.state, s.last_event_at::text
        \\FROM sensor_status s JOIN agents ag ON ag.id = s.agent_id AND ag.tenant_id = s.tenant_id
        \\WHERE s.was_running AND s.continuous AND s.open_alert_id IS NULL
        \\  AND ag.status = 'online' AND ag.revoked_at IS NULL
        \\  AND s.last_event_at IS NOT NULL
        \\  AND s.last_event_at <= $1::timestamptz - interval '15 minutes'
        \\LIMIT 500
    , &.{.{ .text = now_s }});
    defer rows.deinit();
    var raised: u32 = 0;
    for (rows.rows) |row| {
        const tenant = row.cols[0] orelse continue;
        const agent_id = row.cols[1] orelse continue;
        const hostname = row.cols[2] orelse "";
        const sensor = row.cols[3] orelse continue;
        const last = row.cols[5] orelse "";
        const sensor_j = try util.escapeJson(allocator, sensor);
        defer allocator.free(sensor_j);
        const last_j = try util.escapeJson(allocator, last);
        defer allocator.free(last_j);
        const payload = try std.fmt.allocPrint(allocator, "{{\"sensor\":{s},\"last_event_at\":{s},\"silent_seconds_threshold\":{d}}}", .{ sensor_j, last_j, sensor_silence_seconds });
        defer allocator.free(payload);
        const anchor = try writeMarker(allocator, conn, tenant, agent_id, "sensor_silent", payload, now_s);
        defer {
            allocator.free(anchor.event_id);
            allocator.free(anchor.received_at);
        }
        const why = try std.fmt.allocPrint(allocator, "has delivered no events since {s}", .{last});
        defer allocator.free(why);
        const id = try raiseSensor(allocator, io, conn, tenant, agent_id, hostname, sensor, row.cols[4] orelse "", why, anchor, now_s);
        allocator.free(id);
        raised += 1;
    }
    return raised;
}

/// Pull sensor reports out of a `sensor_health` or `agent_health` payload.
/// `sensor_health` names one channel; `agent_health.sensors` is an array of
/// `{name, status, last_event_age_seconds}`.
pub fn sensorReports(allocator: std.mem.Allocator, event_type: []const u8, payload: std.json.Value) ![]SensorReport {
    var out: std.ArrayList(SensorReport) = .empty;
    errdefer out.deinit(allocator);
    if (payload != .object) return out.toOwnedSlice(allocator);
    const obj = payload.object;
    if (std.mem.eql(u8, event_type, "sensor_health")) {
        const ch = obj.get("channel") orelse return out.toOwnedSlice(allocator);
        const st = obj.get("state") orelse return out.toOwnedSlice(allocator);
        if (ch != .string or st != .string) return out.toOwnedSlice(allocator);
        try out.append(allocator, .{ .sensor = ch.string, .state = st.string });
    } else if (std.mem.eql(u8, event_type, "agent_health")) {
        const list = obj.get("sensors") orelse return out.toOwnedSlice(allocator);
        if (list != .array) return out.toOwnedSlice(allocator);
        for (list.array.items) |item| {
            if (item != .object) continue;
            const name = item.object.get("name") orelse continue;
            const st = item.object.get("status") orelse continue;
            if (name != .string or st != .string) continue;
            if (name.string.len == 0 or name.string.len > 200) continue;
            const age: ?i64 = if (item.object.get("last_event_age_seconds")) |a| switch (a) {
                .integer => |n| n,
                else => null,
            } else null;
            try out.append(allocator, .{ .sensor = name.string, .state = st.string, .last_event_age_seconds = age });
            if (out.items.len == 32) break;
        }
    }
    return out.toOwnedSlice(allocator);
}

/// Ingest hook for `agent_tamper`: one alert per event.
pub fn onTamper(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, tenant: []const u8, agent_id: []const u8, hostname: []const u8, payload: std.json.Value, anchor: Anchor, now_unix: i64) !void {
    var nbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&nbuf, now_unix);
    var kind_buf: []const u8 = "unknown";
    var detail: []const u8 = "";
    if (payload == .object) {
        if (payload.object.get("check")) |v| if (v == .string) {
            kind_buf = v.string;
        };
        if (payload.object.get("detail")) |v| if (v == .string) {
            detail = v.string;
        };
    }
    const title = try std.fmt.allocPrint(allocator, "Agent tamper on {s}: {s}", .{ hostname, kind_buf });
    defer allocator.free(title);
    const desc = try std.fmt.allocPrint(allocator, "{s}", .{detail});
    defer allocator.free(desc);
    const id = try raise(allocator, io, conn, tenant, agent_id, .agent_tamper, title, desc, anchor, now_s);
    allocator.free(id);
}

/// Ingest hook for `agent_health`: record update state and key protection.
pub fn recordHealth(conn: *pg.Conn, tenant: []const u8, agent_id: []const u8, payload: std.json.Value, now_rfc3339: []const u8) !void {
    if (payload != .object) return;
    const obj = payload.object;
    const key = strField(obj, "key_protection");
    var state: ?[]const u8 = null;
    var version: ?[]const u8 = null;
    if (obj.get("update")) |u| if (u == .object) {
        state = strField(u.object, "state");
        version = strField(u.object, "version");
    };
    if (key == null and state == null) return;
    try conn.execNoRows(
        \\UPDATE agents SET
        \\  key_protection = COALESCE($3, key_protection),
        \\  update_state = COALESCE($4, update_state),
        \\  update_version = CASE WHEN $4 IS NULL THEN update_version ELSE $5 END,
        \\  update_state_at = CASE WHEN $4 IS NULL THEN update_state_at ELSE $6::timestamptz END
        \\WHERE id = $1::uuid AND tenant_id = $2::uuid
    , &.{
        .{ .text = agent_id },
        .{ .text = tenant },
        if (key) |k| .{ .text = k } else .{ .null = {} },
        if (state) |s| .{ .text = s } else .{ .null = {} },
        if (version) |v| .{ .text = v } else .{ .null = {} },
        .{ .text = now_rfc3339 },
    });
}

fn strField(obj: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const v = obj.get(name) orelse return null;
    if (v != .string or v.string.len == 0 or v.string.len > 64) return null;
    return v.string;
}

// ---------------------------------------------------------------------------
// Tests

test "sensor states classify and continuous sensors are named" {
    try std.testing.expectEqual(SensorState.running, classify("ok"));
    try std.testing.expectEqual(SensorState.running, classify("degraded"));
    try std.testing.expectEqual(SensorState.stopped, classify("missing"));
    try std.testing.expectEqual(SensorState.stopped, classify("failed"));
    try std.testing.expectEqual(SensorState.silent, classify("silent"));
    try std.testing.expectEqual(SensorState.unknown, classify("unknown"));
    try std.testing.expect(isContinuous("Microsoft-Windows-Sysmon/Operational"));
    try std.testing.expect(!isContinuous("Microsoft-Windows-PowerShell/Operational"));
}

test "sensor reports come from sensor_health and agent_health" {
    const a = std.testing.allocator;
    var p1 = try std.json.parseFromSlice(std.json.Value, a,
        \\{"sensor":"windows_eventlog","channel":"Security","state":"silent"}
    , .{});
    defer p1.deinit();
    const r1 = try sensorReports(a, "sensor_health", p1.value);
    defer a.free(r1);
    try std.testing.expectEqual(@as(usize, 1), r1.len);
    try std.testing.expectEqualStrings("Security", r1[0].sensor);

    var p2 = try std.json.parseFromSlice(std.json.Value, a,
        \\{"sensors":[{"name":"process_events","status":"running","last_event_age_seconds":4},{"name":7},{"name":"dns","status":"stopped"}]}
    , .{});
    defer p2.deinit();
    const r2 = try sensorReports(a, "agent_health", p2.value);
    defer a.free(r2);
    try std.testing.expectEqual(@as(usize, 2), r2.len);
    try std.testing.expectEqual(@as(?i64, 4), r2[0].last_event_age_seconds);
    try std.testing.expectEqualStrings("dns", r2[1].sensor);
}

const default_tenant = "00000000-0000-0000-0000-000000000001";
const silent_agent = "00000000-0000-0000-0000-00000000e801";
const clean_agent = "00000000-0000-0000-0000-00000000e802";
const revoked_agent = "00000000-0000-0000-0000-00000000e803";
const sensor_agent = "00000000-0000-0000-0000-00000000e804";

fn testConn(allocator: std.mem.Allocator) !?*pg.Conn {
    const url = std.testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return null;
    if (url.len == 0) return null;
    return try pg.Conn.connect(allocator, std.testing.io, url);
}

fn insertAgent(conn: *pg.Conn, id: []const u8, host: []const u8, status: []const u8, heartbeat: []const u8, revoked: bool, clean: bool) !void {
    try conn.execNoRows(
        \\INSERT INTO agents (id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, last_heartbeat_at, status, revoked_at, clean_shutdown_at)
        \\VALUES ($1, $2, $3, 'windows', 'test', '0', 'x64', '2026-05-14T07:00:00Z', $4::timestamptz, $5,
        \\  CASE WHEN $6::boolean THEN '2026-05-14T07:30:00Z'::timestamptz END,
        \\  CASE WHEN $7::boolean THEN $4::timestamptz END)
    , &.{
        .{ .text = id },
        .{ .text = default_tenant },
        .{ .text = host },
        .{ .text = heartbeat },
        .{ .text = status },
        .{ .text = if (revoked) "true" else "false" },
        .{ .text = if (clean) "true" else "false" },
    });
}

fn countOpen(allocator: std.mem.Allocator, conn: *pg.Conn, agent_id: []const u8, kind: Kind) !usize {
    const rows = try query(allocator, conn,
        \\SELECT count(*)::text FROM alerts a JOIN alert_rules r ON r.id = a.alert_rule_id
        \\WHERE a.agent_id = $1::uuid AND a.status = 'open' AND r.external_id = $2
    , &.{ .{ .text = agent_id }, .{ .text = kind.externalId() } });
    defer rows.deinit();
    return std.fmt.parseInt(usize, rows.rows[0].cols[0].?, 10);
}

test "offline agent without a shutdown notice raises Agent silent, heartbeat closes it" {
    const allocator = std.testing.allocator;
    const conn = (try testConn(allocator)) orelse return;
    defer {
        conn.close();
        allocator.destroy(conn);
    }
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};
    const stale = @import("stale.zig");

    try insertAgent(conn, silent_agent, "silent-host", "online", "2026-05-14T07:40:00Z", false, false);
    try insertAgent(conn, clean_agent, "clean-host", "online", "2026-05-14T07:40:00Z", false, true);
    try insertAgent(conn, revoked_agent, "revoked-host", "revoked", "2026-05-14T07:40:00Z", true, false);

    try stale.mark(conn, "2026-05-14T08:00:00Z");
    const io = std.testing.io;
    try std.testing.expectEqual(@as(u32, 1), try raiseSilentAgents(allocator, io, conn, "2026-05-14T08:00:00Z"));
    try std.testing.expectEqual(@as(usize, 1), try countOpen(allocator, conn, silent_agent, .agent_silent));
    try std.testing.expectEqual(@as(usize, 0), try countOpen(allocator, conn, clean_agent, .agent_silent));
    try std.testing.expectEqual(@as(usize, 0), try countOpen(allocator, conn, revoked_agent, .agent_silent));

    // The title names the host and the description the last heartbeat.
    {
        const rows = try query(allocator, conn,
            \\SELECT a.title || '|' || a.description || '|' || te.event_type FROM alerts a
            \\JOIN telemetry_events te ON te.id = a.telemetry_event_id AND te.received_at = a.telemetry_received_at
            \\WHERE a.agent_id = $1::uuid
        , &.{.{ .text = silent_agent }});
        defer rows.deinit();
        const text = rows.rows[0].cols[0].?;
        try std.testing.expect(std.mem.indexOf(u8, text, "Agent silent on silent-host") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, "2026-05-14 07:40:00") != null);
        try std.testing.expect(std.mem.endsWith(u8, text, "|agent_silent"));
    }

    // Second pass raises nothing new.
    try std.testing.expectEqual(@as(u32, 0), try raiseSilentAgents(allocator, io, conn, "2026-05-14T08:01:00Z"));

    // Next heartbeat closes it.
    try onHeartbeat(allocator, conn, default_tenant, silent_agent, false, "", "2026-05-14T08:05:00Z");
    try std.testing.expectEqual(@as(usize, 0), try countOpen(allocator, conn, silent_agent, .agent_silent));

    // Clean shutdown notice, then offline: no alert.
    try onHeartbeat(allocator, conn, default_tenant, silent_agent, true, "service_stop", "2026-05-14T08:06:00Z");
    try conn.execNoRows("UPDATE agents SET status = 'offline' WHERE id = $1::uuid", &.{.{ .text = silent_agent }});
    try std.testing.expectEqual(@as(u32, 0), try raiseSilentAgents(allocator, io, conn, "2026-05-14T08:30:00Z"));
    try conn.execSimple("ROLLBACK");
}

test "a running sensor that goes quiet raises Sensor silent, and delivery closes it" {
    const allocator = std.testing.allocator;
    const conn = (try testConn(allocator)) orelse return;
    defer {
        conn.close();
        allocator.destroy(conn);
    }
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};
    const io = std.testing.io;
    try insertAgent(conn, sensor_agent, "sensor-host", "online", "2026-05-14T08:00:00Z", false, false);
    const ev = try query(allocator, conn,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES ('2026-05-14T08:00:00Z', $1::uuid, $2::uuid, 'sensor_health', '2026-05-14T08:00:00Z', '{}')
        \\RETURNING id::text, received_at::text
    , &.{ .{ .text = default_tenant }, .{ .text = sensor_agent } });
    defer ev.deinit();
    const anchor: Anchor = .{ .event_id = ev.rows[0].cols[0].?, .received_at = ev.rows[0].cols[1].? };
    const sysmon = "Microsoft-Windows-Sysmon/Operational";
    const t0: i64 = 1778745600; // 2026-05-14T08:00:00Z

    // A sensor that was never running does not alert when it reports missing.
    try recordSensor(allocator, io, conn, default_tenant, sensor_agent, "sensor-host", .{ .sensor = "Microsoft-Windows-PowerShell/Operational", .state = "missing" }, anchor, t0);
    try std.testing.expectEqual(@as(usize, 0), try countOpen(allocator, conn, sensor_agent, .sensor_silent));

    // Sysmon running, then the agent reports it silent: one alert.
    try recordSensor(allocator, io, conn, default_tenant, sensor_agent, "sensor-host", .{ .sensor = sysmon, .state = "ok" }, anchor, t0);
    try recordSensor(allocator, io, conn, default_tenant, sensor_agent, "sensor-host", .{ .sensor = sysmon, .state = "silent" }, anchor, t0 + 900);
    try std.testing.expectEqual(@as(usize, 1), try countOpen(allocator, conn, sensor_agent, .sensor_silent));
    // Repeating the report adds nothing.
    try recordSensor(allocator, io, conn, default_tenant, sensor_agent, "sensor-host", .{ .sensor = sysmon, .state = "silent" }, anchor, t0 + 960);
    try std.testing.expectEqual(@as(usize, 1), try countOpen(allocator, conn, sensor_agent, .sensor_silent));
    // Delivery again closes it.
    try recordSensor(allocator, io, conn, default_tenant, sensor_agent, "sensor-host", .{ .sensor = sysmon, .state = "ok" }, anchor, t0 + 1000);
    try std.testing.expectEqual(@as(usize, 0), try countOpen(allocator, conn, sensor_agent, .sensor_silent));

    // A sparse channel going quiet is not news; stopping is.
    const ps = "Microsoft-Windows-PowerShell/Operational";
    try recordSensor(allocator, io, conn, default_tenant, sensor_agent, "sensor-host", .{ .sensor = ps, .state = "ok" }, anchor, t0);
    try recordSensor(allocator, io, conn, default_tenant, sensor_agent, "sensor-host", .{ .sensor = ps, .state = "silent" }, anchor, t0 + 900);
    try std.testing.expectEqual(@as(usize, 0), try countOpen(allocator, conn, sensor_agent, .sensor_silent));
    try recordSensor(allocator, io, conn, default_tenant, sensor_agent, "sensor-host", .{ .sensor = ps, .state = "failed" }, anchor, t0 + 960);
    try std.testing.expectEqual(@as(usize, 1), try countOpen(allocator, conn, sensor_agent, .sensor_silent));
    try recordSensor(allocator, io, conn, default_tenant, sensor_agent, "sensor-host", .{ .sensor = ps, .state = "ok" }, anchor, t0 + 990);
    try std.testing.expectEqual(@as(usize, 0), try countOpen(allocator, conn, sensor_agent, .sensor_silent));

    // Server-side check: Security running per agent_health, nothing for 20 minutes.
    try recordSensor(allocator, io, conn, default_tenant, sensor_agent, "sensor-host", .{ .sensor = "Security", .state = "running", .last_event_age_seconds = 0 }, anchor, t0);
    try std.testing.expectEqual(@as(u32, 0), try raiseQuietSensors(allocator, io, conn, t0 + 600));
    try std.testing.expectEqual(@as(u32, 1), try raiseQuietSensors(allocator, io, conn, t0 + 1200));
    try std.testing.expectEqual(@as(u32, 0), try raiseQuietSensors(allocator, io, conn, t0 + 1300));
    try std.testing.expectEqual(@as(usize, 1), try countOpen(allocator, conn, sensor_agent, .sensor_silent));
    try conn.execSimple("ROLLBACK");
}

test "agent_tamper raises one alert per event and health records update state" {
    const allocator = std.testing.allocator;
    const conn = (try testConn(allocator)) orelse return;
    defer {
        conn.close();
        allocator.destroy(conn);
    }
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};
    const io = std.testing.io;
    try insertAgent(conn, sensor_agent, "tamper-host", "online", "2026-05-14T08:00:00Z", false, false);
    const ev = try query(allocator, conn,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES ('2026-05-14T08:00:00Z', $1::uuid, $2::uuid, 'agent_tamper', '2026-05-14T08:00:00Z', '{}')
        \\RETURNING id::text, received_at::text
    , &.{ .{ .text = default_tenant }, .{ .text = sensor_agent } });
    defer ev.deinit();
    const anchor: Anchor = .{ .event_id = ev.rows[0].cols[0].?, .received_at = ev.rows[0].cols[1].? };
    var p = try std.json.parseFromSlice(std.json.Value, allocator,
        \\{"check":"unexpected_stop","detail":"no clean shutdown marker from the last run"}
    , .{});
    defer p.deinit();
    try onTamper(allocator, io, conn, default_tenant, sensor_agent, "tamper-host", p.value, anchor, 1778745600);
    try std.testing.expectEqual(@as(usize, 1), try countOpen(allocator, conn, sensor_agent, .agent_tamper));

    var h = try std.json.parseFromSlice(std.json.Value, allocator,
        \\{"key_protection":"dpapi","update":{"state":"staged","version":"0.2.0"}}
    , .{});
    defer h.deinit();
    try recordHealth(conn, default_tenant, sensor_agent, h.value, "2026-05-14T08:00:00Z");
    const rows = try query(allocator, conn, "SELECT key_protection || '|' || update_state || '|' || update_version FROM agents WHERE id = $1::uuid", &.{.{ .text = sensor_agent }});
    defer rows.deinit();
    try std.testing.expectEqualStrings("dpapi|staged|0.2.0", rows.rows[0].cols[0].?);
    try conn.execSimple("ROLLBACK");
}
