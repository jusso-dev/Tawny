//! Wazuh syslog line. Bytes match `WazuhSyslogFormatter` and
//! `integrations/wazuh/` (`program_name` tawny, `"integration":"tawny"`).
const std = @import("std");
const util = @import("../http/util.zig");

pub const Options = struct {
    facility: i32 = 16,
    hostname: []const u8 = "",
    app_name: []const u8 = "tawny",
    max_message_bytes: usize = 8192,
};

pub const Agent = struct {
    id: []const u8,
    tenant_id: []const u8,
    hostname: []const u8,
    os: []const u8,
    os_version: []const u8,
    arch: []const u8,
    version: []const u8,
};

pub const Alert = struct {
    id: i64,
    rule_id: []const u8,
    severity: []const u8,
    status: []const u8,
    title: []const u8,
    description: ?[]const u8,
    /// `2026-05-14T08:00:02Z`
    created_at: []const u8,
};

pub const Telemetry = struct {
    id: i64,
    event_type: []const u8,
    occurred_at: []const u8,
    received_at: []const u8,
    payload: []const u8,
};

pub fn format(
    allocator: std.mem.Allocator,
    options: Options,
    agent: Agent,
    alert: Alert,
    telemetry: ?Telemetry,
) ![]u8 {
    const max_bytes = @max(options.max_message_bytes, 1024);
    const full = try line(allocator, options, agent, alert, telemetry, true);
    if (full.len <= max_bytes) return full;
    allocator.free(full);
    return line(allocator, options, agent, alert, telemetry, false);
}

fn line(
    allocator: std.mem.Allocator,
    options: Options,
    agent: Agent,
    alert: Alert,
    telemetry: ?Telemetry,
    include_payload: bool,
) ![]u8 {
    const host = try sanitize(allocator, if (options.hostname.len == 0) "tawny" else options.hostname);
    defer allocator.free(host);
    const app = try sanitize(allocator, options.app_name);
    defer allocator.free(app);
    const facility = std.math.clamp(options.facility, 0, 23);
    const priority: i32 = facility * 8 + severityPri(alert.severity);
    var stamp_buf: [15]u8 = undefined;
    const stamp = syslogStamp(&stamp_buf, alert.created_at);
    const event_json = try buildJson(allocator, agent, alert, telemetry, include_payload);
    defer allocator.free(event_json);
    return std.fmt.allocPrint(allocator, "<{d}>{s} {s} {s}: {s}", .{
        priority, stamp, host, app, event_json,
    });
}

fn buildJson(
    allocator: std.mem.Allocator,
    agent: Agent,
    alert: Alert,
    telemetry: ?Telemetry,
    include_payload: bool,
) ![]u8 {
    const title = try util.escapeJson(allocator, alert.title);
    defer allocator.free(title);
    const description = if (alert.description) |d| try util.escapeJson(allocator, d) else try allocator.dupe(u8, "null");
    defer allocator.free(description);
    const severity = try util.escapeJson(allocator, alert.severity);
    defer allocator.free(severity);
    const status = try util.escapeJson(allocator, alert.status);
    defer allocator.free(status);
    const created_raw = try jsonTimeAlloc(allocator, alert.created_at);
    defer allocator.free(created_raw);
    const created = try util.escapeJson(allocator, created_raw);
    defer allocator.free(created);
    const rule = try util.escapeJson(allocator, alert.rule_id);
    defer allocator.free(rule);
    const agent_id = try util.escapeJson(allocator, agent.id);
    defer allocator.free(agent_id);
    const tenant = try util.escapeJson(allocator, agent.tenant_id);
    defer allocator.free(tenant);
    const hostname = try util.escapeJson(allocator, agent.hostname);
    defer allocator.free(hostname);
    const os = try util.escapeJson(allocator, agent.os);
    defer allocator.free(os);
    const os_version = try util.escapeJson(allocator, agent.os_version);
    defer allocator.free(os_version);
    const arch = try util.escapeJson(allocator, agent.arch);
    defer allocator.free(arch);
    const version = try util.escapeJson(allocator, agent.version);
    defer allocator.free(version);

    var tel_id: []const u8 = "null";
    var tel_type: []const u8 = "null";
    var tel_occ: []const u8 = "null";
    var tel_recv: []const u8 = "null";
    var tel_payload: []const u8 = "null";
    var owned_type: ?[]u8 = null;
    var owned_occ: ?[]u8 = null;
    var owned_recv: ?[]u8 = null;
    var owned_payload: ?[]u8 = null;
    defer if (owned_type) |p| allocator.free(p);
    defer if (owned_occ) |p| allocator.free(p);
    defer if (owned_recv) |p| allocator.free(p);
    defer if (owned_payload) |p| allocator.free(p);

    if (telemetry) |ev| {
        tel_id = try std.fmt.allocPrint(allocator, "{d}", .{ev.id});
        owned_type = try util.escapeJson(allocator, ev.event_type);
        tel_type = owned_type.?;
        const occ_raw = try jsonTimeAlloc(allocator, ev.occurred_at);
        defer allocator.free(occ_raw);
        const recv_raw = try jsonTimeAlloc(allocator, ev.received_at);
        defer allocator.free(recv_raw);
        owned_occ = try util.escapeJson(allocator, occ_raw);
        tel_occ = owned_occ.?;
        owned_recv = try util.escapeJson(allocator, recv_raw);
        tel_recv = owned_recv.?;
        if (include_payload) {
            owned_payload = try util.escapeJson(allocator, ev.payload);
            tel_payload = owned_payload.?;
        }
    }
    defer if (telemetry != null) allocator.free(tel_id);

    const omitted = telemetry != null and !include_payload;
    return std.fmt.allocPrint(allocator,
        \\{{"integration":"tawny","event_kind":"alert","alert_id":{d},"alert_title":{s},"alert_description":{s},"alert_severity":{s},"alert_status":{s},"alert_created_at":{s},"rule_id":{s},"agent_id":{s},"tenant_id":{s},"agent_hostname":{s},"agent_os":{s},"agent_os_version":{s},"agent_architecture":{s},"agent_version":{s},"telemetry_id":{s},"telemetry_type":{s},"telemetry_occurred_at":{s},"telemetry_received_at":{s},"telemetry_payload_json":{s},"telemetry_payload_omitted":{s}}}
    , .{
        alert.id,
        title,
        description,
        severity,
        status,
        created,
        rule,
        agent_id,
        tenant,
        hostname,
        os,
        os_version,
        arch,
        version,
        tel_id,
        tel_type,
        tel_occ,
        tel_recv,
        tel_payload,
        if (omitted) "true" else "false",
    });
}

fn severityPri(severity: []const u8) i32 {
    if (std.mem.eql(u8, severity, "critical")) return 2;
    if (std.mem.eql(u8, severity, "high")) return 3;
    if (std.mem.eql(u8, severity, "medium")) return 4;
    return 5;
}

fn sanitize(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    const raw = if (trimmed.len == 0) "tawny" else trimmed;
    const out = try allocator.alloc(u8, raw.len);
    for (raw, 0..) |c, i| {
        out[i] = if (c == ' ' or c == '\t' or c == ':') '-' else c;
    }
    return out;
}

const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

fn syslogStamp(buf: *[15]u8, created_at: []const u8) []const u8 {
    if (created_at.len < 19 or created_at[4] != '-' or created_at[7] != '-') {
        return "Jan 01 00:00:00";
    }
    const month = std.fmt.parseInt(u8, created_at[5..7], 10) catch 1;
    const name = if (month >= 1 and month <= 12) months[month - 1] else "Jan";
    return std.fmt.bufPrint(buf, "{s} {s} {s}", .{ name, created_at[8..10], created_at[11..19] }) catch "Jan 01 00:00:00";
}

fn jsonTimeAlloc(allocator: std.mem.Allocator, created_at: []const u8) ![]u8 {
    // System.Text.Json writes a zero-offset instant as +00:00.
    if (created_at.len >= 20 and created_at[19] == 'Z') {
        return std.fmt.allocPrint(allocator, "{s}+00:00", .{created_at[0..19]});
    }
    return allocator.dupe(u8, created_at);
}

const sample_agent = Agent{
    .id = "11111111-1111-4111-8111-111111111111",
    .tenant_id = "22222222-2222-4222-8222-222222222222",
    .hostname = "linux-host-01",
    .os = "linux",
    .os_version = "6.12",
    .arch = "arm64",
    .version = "0.1.0",
};

const sample_alert = Alert{
    .id = 7,
    .rule_id = "33333333-3333-4333-8333-333333333333",
    .severity = "high",
    .status = "open",
    .title = "Suspicious process on linux-host-01",
    .description = "Matched processes Contains suspicious.exe.",
    .created_at = "2026-05-14T08:00:02Z",
};

const sample_event = Telemetry{
    .id = 42,
    .event_type = "process_snapshot",
    .occurred_at = "2026-05-14T08:00:00Z",
    .received_at = "2026-05-14T08:00:01Z",
    .payload = "{\"processes\":[{\"name\":\"suspicious.exe\",\"pid\":4242}]}",
};

test "wazuh syslog matches decoder and high-severity rule" {
    const allocator = std.testing.allocator;
    const message = try format(allocator, .{ .hostname = "tawny-api", .app_name = "tawny", .facility = 16 }, sample_agent, sample_alert, sample_event);
    defer allocator.free(message);
    try std.testing.expect(std.mem.startsWith(u8, message, "<131>May 14 08:00:02 tawny-api tawny: "));
    const json_at = std.mem.indexOfScalar(u8, message, '{') orelse return error.NoJson;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, message[json_at..], .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqualStrings("tawny", root.get("integration").?.string);
    try std.testing.expectEqualStrings("alert", root.get("event_kind").?.string);
    try std.testing.expectEqual(@as(i64, 7), root.get("alert_id").?.integer);
    try std.testing.expectEqualStrings("high", root.get("alert_severity").?.string);
    try std.testing.expectEqualStrings(sample_agent.tenant_id, root.get("tenant_id").?.string);
    try std.testing.expectEqualStrings("process_snapshot", root.get("telemetry_type").?.string);
    try std.testing.expect(root.get("telemetry_payload_omitted").?.bool == false);
    const payload = root.get("telemetry_payload_json").?.string;
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"pid\":4242") != null);
    std.debug.print("wazuh_syslog {s}\n", .{message});
}

test "wazuh drops telemetry payload over the byte cap" {
    const allocator = std.testing.allocator;
    const blob = try allocator.alloc(u8, 12000);
    defer allocator.free(blob);
    @memset(blob, 'x');
    const payload = try std.fmt.allocPrint(allocator, "{{\"blob\":\"{s}\"}}", .{blob});
    defer allocator.free(payload);
    const event = Telemetry{
        .id = 99,
        .event_type = "file_integrity",
        .occurred_at = "2026-05-14T08:00:00Z",
        .received_at = "2026-05-14T08:00:01Z",
        .payload = payload,
    };
    const alert = Alert{
        .id = 1,
        .rule_id = sample_alert.rule_id,
        .severity = "low",
        .status = "open",
        .title = "Large payload",
        .description = null,
        .created_at = "2026-05-14T08:00:02Z",
    };
    const message = try format(allocator, .{ .hostname = "tawny-api", .max_message_bytes = 1024 }, sample_agent, alert, event);
    defer allocator.free(message);
    const json_at = std.mem.indexOfScalar(u8, message, '{') orelse return error.NoJson;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, message[json_at..], .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expect(root.get("telemetry_payload_omitted").?.bool == true);
    try std.testing.expect(root.get("telemetry_payload_json").? == .null);
}
