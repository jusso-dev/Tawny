//! Schema 2 telemetry batches (schemas/events/envelope.v2.json).
//!
//! Envelope checks run first, then a required-field check per event type
//! that mirrors the `required` lists in schemas/events/<type>.v1.json. Types
//! with no schema (inventory types, Windows types not yet covered) only need
//! `data` to be an object. Tests below check the golden payloads against both
//! this validator and the JSON Schemas.
const std = @import("std");
const entity = @import("entity.zig");

pub const Event = struct {
    event_id: []const u8,
    event_type: []const u8,
    v: i64 = 1,
    ts: []const u8,
    seq: i64,
    data: std.json.Value,
    mono: ?i64 = null,
    priority: ?i64 = null,
    sensor: ?[]const u8 = null,
};

pub const Agent = struct {
    agent_id: []const u8,
    sensor_version: []const u8,
    boot_id: []const u8,
};

pub const Batch = struct {
    schema: i64,
    batch_id: []const u8,
    agent: Agent,
    events: []Event,
    signature: ?[]const u8 = null,
};

/// Only the schema number, to pick a parser.
pub const Probe = struct { schema: ?i64 = null };

pub const Problem = struct {
    title: []const u8,
    index: ?usize = null,
};

fn validType(t: []const u8) bool {
    if (t.len == 0 or t.len > 64) return false;
    for (t) |c| {
        if (!(std.ascii.isLower(c) or std.ascii.isDigit(c) or c == '_' or c == '.' or c == '-')) return false;
    }
    return true;
}

/// Envelope problems, or null when it is well formed. `agent_id` is the
/// authenticated agent; the body must name the same one.
pub fn checkEnvelope(b: *const Batch, agent_id: []const u8) ?Problem {
    if (b.schema != 2) return .{ .title = "Unsupported schema." };
    if (!entity.isUuid(b.batch_id)) return .{ .title = "batch_id must be a UUID." };
    if (!entity.isUuid(b.agent.agent_id) or !std.ascii.eqlIgnoreCase(b.agent.agent_id, agent_id)) {
        return .{ .title = "agent.agent_id does not match the authenticated agent." };
    }
    if (!entity.isUuid(b.agent.boot_id)) return .{ .title = "agent.boot_id must be a UUID." };
    if (b.agent.sensor_version.len == 0 or b.agent.sensor_version.len > 64 or std.mem.indexOfAny(u8, b.agent.sensor_version, "\n|") != null) {
        return .{ .title = "agent.sensor_version is invalid." };
    }
    for (b.events, 0..) |ev, i| {
        if (!entity.isUuid(ev.event_id)) return .{ .title = "event_id must be a UUID.", .index = i };
        if (!validType(ev.event_type)) return .{ .title = "event_type is invalid.", .index = i };
        if (ev.v < 1) return .{ .title = "v must be at least 1.", .index = i };
        if (ev.seq < 1) return .{ .title = "seq must be at least 1.", .index = i };
        if (entity.parseIso(ev.ts) == null) return .{ .title = "ts must be ISO 8601 UTC.", .index = i };
        if (ev.data != .object) return .{ .title = "data must be a JSON object.", .index = i };
        if (checkData(ev.event_type, ev.data)) |why| return .{ .title = why, .index = i };
    }
    return null;
}

/// Unix seconds of an event's `ts` (already checked by checkEnvelope).
pub fn tsUnix(ev: *const Event) i64 {
    const t = entity.parseIso(ev.ts) orelse return 0;
    return @intCast(t / entity.ticks_per_second);
}

fn get(v: std.json.Value, path: []const u8) ?std.json.Value {
    var cur = v;
    var it = std.mem.splitScalar(u8, path, '.');
    while (it.next()) |seg| {
        if (cur != .object) return null;
        cur = cur.object.get(seg) orelse return null;
    }
    return cur;
}

fn needObject(d: std.json.Value, path: []const u8) bool {
    const v = get(d, path) orelse return false;
    return v == .object;
}

fn needString(d: std.json.Value, path: []const u8) bool {
    const v = get(d, path) orelse return false;
    return v == .string and v.string.len > 0;
}

fn needPid(d: std.json.Value, path: []const u8) bool {
    const v = get(d, path) orelse return false;
    return v == .integer and v.integer >= 0 and v.integer <= std.math.maxInt(u32);
}

fn entityOk(d: std.json.Value, path: []const u8) bool {
    const v = get(d, path) orelse return true;
    return v == .string and entity.isEntityId(v.string);
}

/// Required fields per type; null when `data` is acceptable.
pub fn checkData(event_type: []const u8, d: std.json.Value) ?[]const u8 {
    const eq = std.mem.eql;
    if (eq(u8, event_type, "process_start") or eq(u8, event_type, "process_exit")) {
        if (!needObject(d, "process") or !needPid(d, "process.pid")) return "process.pid is required.";
        if (!entityOk(d, "process.entity_id") or !entityOk(d, "parent.entity_id")) return "entity_id must be 26 base32 characters.";
        return null;
    }
    if (eq(u8, event_type, "network_connect")) return if (needObject(d, "network")) null else "network is required.";
    if (eq(u8, event_type, "dns_query")) return if (needString(d, "dns.query") or needString(d, "qname")) null else "dns.query is required.";
    if (eq(u8, event_type, "file_create")) return if (needString(d, "file.path")) null else "file.path is required.";
    if (eq(u8, event_type, "registry_set")) return if (needString(d, "registry.key")) null else "registry.key is required.";
    if (eq(u8, event_type, "user_logon")) return if (needObject(d, "user")) null else "user is required.";
    if (eq(u8, event_type, "service_create")) return if (needString(d, "service.name")) null else "service.name is required.";
    if (eq(u8, event_type, "powershell_script_block")) {
        return if (needString(d, "script_block.id") and get(d, "script_block.text") != null) null else "script_block.id and text are required.";
    }
    if (eq(u8, event_type, "agent_health")) {
        return if (get(d, "sensor_version") != null and get(d, "buffer_depth") != null and get(d, "uptime_seconds") != null) null else "agent_health fields are required.";
    }
    if (eq(u8, event_type, "agent_tamper")) return if (needString(d, "check") and needString(d, "detail")) null else "check and detail are required.";
    return null;
}

// ---- tests ----------------------------------------------------------------

const schema_check = @import("schema_check.zig");

test "golden payloads pass the server validator and the JSON Schemas" {
    const gpa = std.testing.allocator;
    for (schema_check.schema_types) |t| {
        const path = try std.fmt.allocPrint(gpa, "{s}/golden/{s}.json", .{ schema_check.schema_dir, t });
        defer gpa.free(path);
        const text = std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(256 * 1024)) catch return error.SkipZigTest;
        defer gpa.free(text);
        var parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        if (checkData(t, parsed.value)) |why| {
            std.debug.print("{s}: {s}\n", .{ t, why });
            return error.TestUnexpectedResult;
        }
        try schema_check.expectValid(gpa, t, text);
    }
}

test "validator refuses what the schemas refuse" {
    const gpa = std.testing.allocator;
    const bad = [_]struct { t: []const u8, d: []const u8 }{
        .{ .t = "process_start", .d = "{\"parent\":{\"pid\":1}}" },
        .{ .t = "process_start", .d = "{\"process\":{\"pid\":\"12\"}}" },
        .{ .t = "process_start", .d = "{\"process\":{\"pid\":12,\"entity_id\":\"short\"}}" },
        .{ .t = "dns_query", .d = "{\"process\":{\"pid\":1}}" },
        .{ .t = "file_create", .d = "{\"file\":{\"name\":\"a\"}}" },
    };
    for (bad) |c| {
        var parsed = try std.json.parseFromSlice(std.json.Value, gpa, c.d, .{});
        defer parsed.deinit();
        try std.testing.expect(checkData(c.t, parsed.value) != null);
        try schema_check.expectInvalid(gpa, c.t, c.d);
    }
}

test "envelope checks" {
    const gpa = std.testing.allocator;
    const body =
        \\{"schema":2,"batch_id":"00000000-0000-4000-8000-0000000000b2","agent":{"agent_id":"00000000-0000-4000-8000-00000000f001","sensor_version":"0.1.0","boot_id":"3c1c4b5e-6d2a-4f0e-9b7a-2d1e5f6a7b8c"},"events":[{"event_id":"00000000-0000-4000-8000-0000000000e1","event_type":"system_info","v":1,"ts":"2026-11-09T01:00:00.000Z","seq":1,"data":{}}]}
    ;
    var parsed = try std.json.parseFromSlice(Batch, gpa, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try std.testing.expect(checkEnvelope(&parsed.value, "00000000-0000-4000-8000-00000000F001") == null);
    try std.testing.expect(checkEnvelope(&parsed.value, "00000000-0000-4000-8000-00000000f002") != null);
    try std.testing.expectEqual(@as(i64, 1794186000), tsUnix(&parsed.value.events[0]));
    try schema_check.expectValidFile(gpa, "envelope.v2.json", body);

    var b = parsed.value;
    var evs = [_]Event{b.events[0]};
    b.events = &evs;
    evs[0].ts = "yesterday";
    try std.testing.expectEqualStrings("ts must be ISO 8601 UTC.", checkEnvelope(&b, b.agent.agent_id).?.title);
    evs[0].ts = "2026-11-09T01:00:00Z";
    evs[0].event_type = "Process|Start";
    try std.testing.expect(checkEnvelope(&b, b.agent.agent_id) != null);
    evs[0].event_type = "x";
    evs[0].seq = 0;
    try std.testing.expect(checkEnvelope(&b, b.agent.agent_id) != null);
}
