//! Sentinel record. Property names stay PascalCase. Enum values are the
//! .NET `ToString()` forms (`High`, `ProcessSnapshot`), matching the upload
//! serializer (`PropertyNamingPolicy = null`).
const std = @import("std");
const util = @import("../http/util.zig");

pub const Record = struct {
    time_generated: []const u8,
    tenant_id: []const u8,
    agent_id: []const u8,
    hostname: []const u8,
    os: []const u8,
    os_version: []const u8,
    arch: []const u8,
    version: []const u8,
    alert_id: i64,
    rule_id: []const u8,
    title: []const u8,
    description: ?[]const u8,
    severity: []const u8,
    status: []const u8,
    created_at: []const u8,
    telemetry_id: i64,
    telemetry_type: ?[]const u8,
    occurred_at: ?[]const u8,
    received_at: ?[]const u8,
    payload: ?[]const u8,
};

pub fn formatAlert(allocator: std.mem.Allocator, rec: Record) ![]u8 {
    const time_g = try util.escapeJson(allocator, rec.time_generated);
    defer allocator.free(time_g);
    const tenant = try util.escapeJson(allocator, rec.tenant_id);
    defer allocator.free(tenant);
    const agent = try util.escapeJson(allocator, rec.agent_id);
    defer allocator.free(agent);
    const host = try util.escapeJson(allocator, rec.hostname);
    defer allocator.free(host);
    const os = try util.escapeJson(allocator, rec.os);
    defer allocator.free(os);
    const osv = try util.escapeJson(allocator, rec.os_version);
    defer allocator.free(osv);
    const arch = try util.escapeJson(allocator, rec.arch);
    defer allocator.free(arch);
    const ver = try util.escapeJson(allocator, rec.version);
    defer allocator.free(ver);
    const rule = try util.escapeJson(allocator, rec.rule_id);
    defer allocator.free(rule);
    const title = try util.escapeJson(allocator, rec.title);
    defer allocator.free(title);
    const description = if (rec.description) |d| try util.escapeJson(allocator, d) else try allocator.dupe(u8, "null");
    defer allocator.free(description);
    const sev = try util.escapeJson(allocator, rec.severity);
    defer allocator.free(sev);
    const status = try util.escapeJson(allocator, rec.status);
    defer allocator.free(status);
    const created = try util.escapeJson(allocator, rec.created_at);
    defer allocator.free(created);
    const tel_type = if (rec.telemetry_type) |t| try util.escapeJson(allocator, t) else try allocator.dupe(u8, "null");
    defer allocator.free(tel_type);
    const occurred = if (rec.occurred_at) |t| try util.escapeJson(allocator, t) else try allocator.dupe(u8, "null");
    defer allocator.free(occurred);
    const received = if (rec.received_at) |t| try util.escapeJson(allocator, t) else try allocator.dupe(u8, "null");
    defer allocator.free(received);
    const payload = if (rec.payload) |t| try util.escapeJson(allocator, t) else try allocator.dupe(u8, "null");
    defer allocator.free(payload);
    return std.fmt.allocPrint(allocator,
        \\{{"TimeGenerated":{s},"EventKind":"alert","TawnyTenantId":{s},"AgentId":{s},"AgentHostname":{s},"AgentOs":{s},"AgentOsVersion":{s},"AgentArchitecture":{s},"AgentVersion":{s},"AlertId":{d},"AlertRuleId":{s},"AlertTitle":{s},"AlertDescription":{s},"AlertSeverity":{s},"AlertStatus":{s},"AlertCreatedAt":{s},"TelemetryEventId":{d},"TelemetryEventType":{s},"TelemetryOccurredAt":{s},"TelemetryReceivedAt":{s},"TelemetryPayload":{s}}}
    , .{
        time_g, tenant, agent, host, os, osv, arch, ver, rec.alert_id, rule, title, description, sev, status, created, rec.telemetry_id, tel_type, occurred, received, payload,
    });
}

test "sentinel record keeps pascal names and dotnet enum text" {
    const allocator = std.testing.allocator;
    const json = try formatAlert(allocator, .{
        .time_generated = "2026-05-14T08:00:02+00:00",
        .tenant_id = "22222222-2222-4222-8222-222222222222",
        .agent_id = "11111111-1111-4111-8111-111111111111",
        .hostname = "linux-host-01",
        .os = "Linux",
        .os_version = "6.12",
        .arch = "Arm64",
        .version = "0.1.0",
        .alert_id = 7,
        .rule_id = "33333333-3333-4333-8333-333333333333",
        .title = "Suspicious process on linux-host-01",
        .description = "Matched processes Contains suspicious.exe.",
        .severity = "High",
        .status = "Open",
        .created_at = "2026-05-14T08:00:02+00:00",
        .telemetry_id = 42,
        .telemetry_type = "ProcessSnapshot",
        .occurred_at = "2026-05-14T08:00:00+00:00",
        .received_at = "2026-05-14T08:00:01+00:00",
        .payload = "{\"processes\":[{\"name\":\"suspicious.exe\",\"pid\":4242}]}",
    });
    defer allocator.free(json);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqualStrings("alert", root.get("EventKind").?.string);
    try std.testing.expectEqualStrings("22222222-2222-4222-8222-222222222222", root.get("TawnyTenantId").?.string);
    try std.testing.expectEqualStrings("linux-host-01", root.get("AgentHostname").?.string);
    try std.testing.expectEqual(@as(i64, 7), root.get("AlertId").?.integer);
    try std.testing.expectEqualStrings("High", root.get("AlertSeverity").?.string);
    try std.testing.expectEqualStrings("ProcessSnapshot", root.get("TelemetryEventType").?.string);
    try std.testing.expect(std.mem.indexOf(u8, root.get("TelemetryPayload").?.string, "suspicious.exe") != null);
}
