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

// ------------------------------------------------------------------ incidents
//
// Tawny-SOC, checked at jusso-dev/Tawny-SOC fea2da8 on 10-11-2026:
// - POST /api/ingest/tawny takes {source, kind: alert_batch | telemetry_batch,
//   sent_at, tenant_id, agent, alerts[], events[], telemetry_events{}} and
//   stores each alert under id "alert-<alert_id>".
// - app/api/v1/cases has GET (list) and GET /{id} only. There is no endpoint
//   to create or update a case, so Tawny cannot create one directly.
// An incident is sent as one alert in an alert_batch, with a stable alert_id
// taken from the incident id, plus an `incident` object with the risk
// breakdown. Tawny-SOC analysts (or its agent mesh) open the case from it.
// Tawny-SOC inserts alerts with onConflictDoNothing, so a later status
// change does not update the stored alert yet: that needs a change in
// Tawny-SOC (listed in the PR). Tawny keeps no case state.

pub const Incident = struct {
    id: []const u8,
    tenant_id: []const u8,
    title: []const u8,
    status: []const u8,
    severity: []const u8,
    risk: i64,
    /// JSON array text, passed through.
    risk_items: []const u8,
    /// JSON array text of technique ids.
    techniques: []const u8,
    /// JSON array text of agent ids.
    agent_ids: []const u8,
    first_seen_at: []const u8,
    last_seen_at: []const u8,
    alert_count: i64,
    url: []const u8,
};

/// Stable numeric alert id for the SOC side: the first 13 hex digits of the
/// incident uuid (52 bits, exact in a JavaScript number).
pub fn incidentAlertId(incident_id: []const u8) i64 {
    var v: i64 = 0;
    var n: usize = 0;
    for (incident_id) |c| {
        if (c == '-') continue;
        const d = std.fmt.charToDigit(c, 16) catch continue;
        v = v * 16 + d;
        n += 1;
        if (n == 13) break;
    }
    return v;
}

pub fn formatIncidentBatch(allocator: std.mem.Allocator, agent: Agent, inc: Incident, sent_at: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const agent_json = try formatAgent(allocator, agent);
    defer allocator.free(agent_json);
    try out.appendSlice(allocator, "{\"source\":\"tawny\",\"kind\":\"alert_batch\",\"sent_at\":");
    try util.appendEscaped(&out, allocator, sent_at);
    try out.appendSlice(allocator, ",\"tenant_id\":");
    try util.appendEscaped(&out, allocator, inc.tenant_id);
    try out.appendSlice(allocator, ",\"agent\":");
    try out.appendSlice(allocator, agent_json);
    const head = try std.fmt.allocPrint(allocator, ",\"alerts\":[{{\"alert_id\":{d},\"telemetry_event_id\":0,\"kind\":\"incident\",\"severity\":", .{incidentAlertId(inc.id)});
    defer allocator.free(head);
    try out.appendSlice(allocator, head);
    try util.appendEscaped(&out, allocator, inc.severity);
    try out.appendSlice(allocator, ",\"status\":");
    try util.appendEscaped(&out, allocator, inc.status);
    try out.appendSlice(allocator, ",\"title\":");
    try util.appendEscaped(&out, allocator, inc.title);
    const desc = try std.fmt.allocPrint(allocator, "Tawny incident, risk {d}, {d} alerts. {s}", .{ inc.risk, inc.alert_count, inc.url });
    defer allocator.free(desc);
    try out.appendSlice(allocator, ",\"description\":");
    try util.appendEscaped(&out, allocator, desc);
    try out.appendSlice(allocator, ",\"created_at\":");
    try util.appendEscaped(&out, allocator, inc.first_seen_at);
    try out.appendSlice(allocator, ",\"incident\":{\"id\":");
    try util.appendEscaped(&out, allocator, inc.id);
    const nums = try std.fmt.allocPrint(allocator, ",\"risk\":{d},\"alert_count\":{d},\"risk_items\":", .{ inc.risk, inc.alert_count });
    defer allocator.free(nums);
    try out.appendSlice(allocator, nums);
    try out.appendSlice(allocator, inc.risk_items);
    try out.appendSlice(allocator, ",\"mitre_techniques\":");
    try out.appendSlice(allocator, inc.techniques);
    try out.appendSlice(allocator, ",\"agent_ids\":");
    try out.appendSlice(allocator, inc.agent_ids);
    try out.appendSlice(allocator, ",\"last_seen_at\":");
    try util.appendEscaped(&out, allocator, inc.last_seen_at);
    try out.appendSlice(allocator, ",\"url\":");
    try util.appendEscaped(&out, allocator, inc.url);
    try out.appendSlice(allocator, "}}],\"telemetry_events\":{}}");
    return out.toOwnedSlice(allocator);
}

test "incident batch fits the tawny-soc ingest schema" {
    const allocator = std.testing.allocator;
    const agent = Agent{
        .id = "11111111-1111-4111-8111-111111111111",
        .tenant_id = "22222222-2222-4222-8222-222222222222",
        .hostname = "win-01",
        .os = "windows",
        .os_version = "11",
        .arch = "x64",
        .version = "0.1.0",
    };
    const json = try formatIncidentBatch(allocator, agent, .{
        .id = "f294c8f1-a1bb-4738-8efd-79f664066674",
        .tenant_id = agent.tenant_id,
        .title = "Office spawns \"PowerShell\" on win-01",
        .status = "investigating",
        .severity = "medium",
        .risk = 44,
        .risk_items = "[{\"key\":\"rule:1\",\"points\":30}]",
        .techniques = "[\"T1059.001\"]",
        .agent_ids = "[\"11111111-1111-4111-8111-111111111111\"]",
        .first_seen_at = "2026-11-10T00:00:00Z",
        .last_seen_at = "2026-11-10T00:01:00Z",
        .alert_count = 2,
        .url = "https://tawny.example/incidents/f294c8f1-a1bb-4738-8efd-79f664066674",
    }, "2026-11-10T00:02:00Z");
    defer allocator.free(json);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    // The keys the SOC zod schema reads.
    try std.testing.expectEqualStrings("alert_batch", root.get("kind").?.string);
    try std.testing.expect(root.get("telemetry_events").? == .object);
    const alert = root.get("alerts").?.array.items[0].object;
    try std.testing.expectEqual(incidentAlertId("f294c8f1-a1bb-4738-8efd-79f664066674"), alert.get("alert_id").?.integer);
    try std.testing.expect(alert.get("alert_id").?.integer < (1 << 53));
    try std.testing.expectEqualStrings("investigating", alert.get("status").?.string);
    try std.testing.expectEqual(@as(i64, 44), alert.get("incident").?.object.get("risk").?.integer);
    try std.testing.expectEqual(incidentAlertId("f294c8f1-a1bb-4738-8efd-79f664066674"), incidentAlertId("F294C8F1A1BB4738"));
}
