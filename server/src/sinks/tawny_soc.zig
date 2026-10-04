//! Tawny-SOC alert batch. Snake_case JSON, related telemetry keyed by id.
const std = @import("std");
const util = @import("../http/util.zig");

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
    agent_id: []const u8,
    telemetry_id: i64,
    severity: []const u8,
    status: []const u8,
    title: []const u8,
    description: ?[]const u8,
    created_at: []const u8,
};

pub const Telemetry = struct {
    id: i64,
    tenant_id: []const u8,
    agent_id: []const u8,
    event_type: []const u8,
    occurred_at: []const u8,
    received_at: []const u8,
    payload: []const u8,
};

pub fn formatAlertBatch(
    allocator: std.mem.Allocator,
    agent: Agent,
    alert: Alert,
    telemetry: Telemetry,
    sent_at: []const u8,
) ![]u8 {
    const sent = try util.escapeJson(allocator, sent_at);
    defer allocator.free(sent);
    const tenant = try util.escapeJson(allocator, agent.tenant_id);
    defer allocator.free(tenant);
    const agent_json = try formatAgent(allocator, agent);
    defer allocator.free(agent_json);
    const alert_json = try formatAlert(allocator, alert);
    defer allocator.free(alert_json);
    const tel_json = try formatTelemetry(allocator, telemetry);
    defer allocator.free(tel_json);
    return std.fmt.allocPrint(allocator,
        \\{{"source":"tawny","kind":"alert_batch","sent_at":{s},"tenant_id":{s},"agent":{s},"alerts":[{s}],"telemetry_events":{{"{d}":{s}}}}}
    , .{ sent, tenant, agent_json, alert_json, telemetry.id, tel_json });
}

fn formatAgent(allocator: std.mem.Allocator, agent: Agent) ![]u8 {
    const id = try util.escapeJson(allocator, agent.id);
    defer allocator.free(id);
    const tenant = try util.escapeJson(allocator, agent.tenant_id);
    defer allocator.free(tenant);
    const host = try util.escapeJson(allocator, agent.hostname);
    defer allocator.free(host);
    const os = try util.escapeJson(allocator, agent.os);
    defer allocator.free(os);
    const osv = try util.escapeJson(allocator, agent.os_version);
    defer allocator.free(osv);
    const arch = try util.escapeJson(allocator, agent.arch);
    defer allocator.free(arch);
    const ver = try util.escapeJson(allocator, agent.version);
    defer allocator.free(ver);
    return std.fmt.allocPrint(allocator,
        \\{{"id":{s},"tenant_id":{s},"hostname":{s},"operating_system":{s},"os_version":{s},"architecture":{s},"agent_version":{s}}}
    , .{ id, tenant, host, os, osv, arch, ver });
}

fn formatAlert(allocator: std.mem.Allocator, alert: Alert) ![]u8 {
    const rule = try util.escapeJson(allocator, alert.rule_id);
    defer allocator.free(rule);
    const agent = try util.escapeJson(allocator, alert.agent_id);
    defer allocator.free(agent);
    const sev = try util.escapeJson(allocator, alert.severity);
    defer allocator.free(sev);
    const status = try util.escapeJson(allocator, alert.status);
    defer allocator.free(status);
    const title = try util.escapeJson(allocator, alert.title);
    defer allocator.free(title);
    const description = if (alert.description) |d| try util.escapeJson(allocator, d) else try allocator.dupe(u8, "null");
    defer allocator.free(description);
    const created = try util.escapeJson(allocator, alert.created_at);
    defer allocator.free(created);
    return std.fmt.allocPrint(allocator,
        \\{{"alert_id":{d},"alert_rule_id":{s},"agent_id":{s},"telemetry_event_id":{d},"severity":{s},"status":{s},"title":{s},"description":{s},"enrichment_json":null,"created_at":{s}}}
    , .{ alert.id, rule, agent, alert.telemetry_id, sev, status, title, description, created });
}

fn formatTelemetry(allocator: std.mem.Allocator, ev: Telemetry) ![]u8 {
    const tenant = try util.escapeJson(allocator, ev.tenant_id);
    defer allocator.free(tenant);
    const agent = try util.escapeJson(allocator, ev.agent_id);
    defer allocator.free(agent);
    const kind = try util.escapeJson(allocator, ev.event_type);
    defer allocator.free(kind);
    const occurred = try util.escapeJson(allocator, ev.occurred_at);
    defer allocator.free(occurred);
    const received = try util.escapeJson(allocator, ev.received_at);
    defer allocator.free(received);
    const payload = try util.escapeJson(allocator, ev.payload);
    defer allocator.free(payload);
    return std.fmt.allocPrint(allocator,
        \\{{"telemetry_id":{d},"tenant_id":{s},"agent_id":{s},"event_type":{s},"occurred_at":{s},"received_at":{s},"payload":{s}}}
    , .{ ev.id, tenant, agent, kind, occurred, received, payload });
}

test "tawny soc batch keys telemetry by id" {
    const allocator = std.testing.allocator;
    const agent = Agent{
        .id = "11111111-1111-4111-8111-111111111111",
        .tenant_id = "22222222-2222-4222-8222-222222222222",
        .hostname = "linux-host-01",
        .os = "linux",
        .os_version = "6.12",
        .arch = "arm64",
        .version = "0.1.0",
    };
    const json = try formatAlertBatch(allocator, agent, .{
        .id = 7,
        .rule_id = "33333333-3333-4333-8333-333333333333",
        .agent_id = agent.id,
        .telemetry_id = 42,
        .severity = "high",
        .status = "open",
        .title = "Suspicious process on linux-host-01",
        .description = "Matched processes Contains suspicious.exe.",
        .created_at = "2026-05-14T08:00:02+00:00",
    }, .{
        .id = 42,
        .tenant_id = agent.tenant_id,
        .agent_id = agent.id,
        .event_type = "process_snapshot",
        .occurred_at = "2026-05-14T08:00:00+00:00",
        .received_at = "2026-05-14T08:00:01+00:00",
        .payload = "{\"processes\":[{\"name\":\"suspicious.exe\",\"pid\":4242}]}",
    }, "2026-05-27T08:00:00+00:00");
    defer allocator.free(json);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqualStrings("alert_batch", root.get("kind").?.string);
    try std.testing.expectEqualStrings("linux-host-01", root.get("agent").?.object.get("hostname").?.string);
    try std.testing.expectEqual(@as(i64, 7), root.get("alerts").?.array.items[0].object.get("alert_id").?.integer);
    const payload = root.get("telemetry_events").?.object.get("42").?.object.get("payload").?.string;
    try std.testing.expect(std.mem.indexOf(u8, payload, "suspicious.exe") != null);
}
