//! Legacy normaliser: maps schema 1 events (and v1-shaped process payloads)
//! onto the canonical process facts the process store needs.
//!
//! Schema 1 events are stored with the type and payload the agent sent, so
//! rules, hunts and backups written for `process_launch` and the rest keep
//! working. What the normaliser adds is the process identity: a v1 event has
//! no entity id, so one is computed here with the same function the agent
//! uses (ingest/entity.zig) and the nil boot id. Payload shapes handled:
//!
//! - `process_launch` (v1 Linux and macOS agents): flat `pid`, `ppid`,
//!   `uid`, `name`, `command_line`, `image_path`, `start_time_unix` (seconds).
//! - `process_start` (v1 Windows agents and every v2 agent): nested
//!   `process{entity_id?,pid,start_time?,image,name,command_line,user,guid}`
//!   and `parent{entity_id?,pid}`.
//! - `process_exit`: `process{entity_id?,pid,guid}`.
const std = @import("std");
const entity = @import("entity.zig");

/// Canonical (v2) name for a legacy event type. Only `process_launch`
/// changed name; everything else is already canonical.
pub fn canonicalType(event_type: []const u8) []const u8 {
    if (std.mem.eql(u8, event_type, "process_launch")) return "process_start";
    return event_type;
}

pub const Kind = enum { start, exit };

pub const ProcessFacts = struct {
    kind: Kind,
    /// Null for an exit that carried no entity id; the store then closes the
    /// newest open process with that pid.
    entity_id: ?entity.Id = null,
    parent_entity_id: ?entity.Id = null,
    pid: u32,
    ppid: ?u32 = null,
    image: ?[]const u8 = null,
    name: ?[]const u8 = null,
    command_line: ?[]const u8 = null,
    user_buf: [160]u8 = undefined,
    user_len: usize = 0,
    guid: ?[]const u8 = null,
    /// 100 ns ticks since the Unix epoch.
    start_100ns: ?u64 = null,
    end_100ns: ?u64 = null,

    pub fn userName(self: *const ProcessFacts) ?[]const u8 {
        return if (self.user_len == 0) null else self.user_buf[0..self.user_len];
    }
};

fn obj(v: ?std.json.Value) ?std.json.ObjectMap {
    const x = v orelse return null;
    return if (x == .object) x.object else null;
}

fn str(o: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = o.get(key) orelse return null;
    return if (v == .string and v.string.len > 0) v.string else null;
}

fn uint(o: std.json.ObjectMap, key: []const u8) ?u32 {
    const v = o.get(key) orelse return null;
    return switch (v) {
        .integer => |n| if (n >= 0 and n <= std.math.maxInt(u32)) @intCast(n) else null,
        else => null,
    };
}

fn entityId(o: std.json.ObjectMap) ?entity.Id {
    const s = str(o, "entity_id") orelse return null;
    if (!entity.isEntityId(s)) return null;
    return s[0..entity.len].*;
}

fn setUser(f: *ProcessFacts, user: ?std.json.ObjectMap) void {
    const u = user orelse return;
    const name = str(u, "name");
    const domain = str(u, "domain");
    const text = if (name) |n|
        (if (domain) |d| std.fmt.bufPrint(&f.user_buf, "{s}\\{s}", .{ d, n }) catch null else std.fmt.bufPrint(&f.user_buf, "{s}", .{n}) catch null)
    else if (uint(u, "uid")) |uid|
        std.fmt.bufPrint(&f.user_buf, "uid:{d}", .{uid}) catch null
    else
        null;
    if (text) |t| f.user_len = t.len;
}

/// Process facts for an event, or null when the event is not about a process
/// starting or stopping (or lacks a pid). `occurred_unix` stands in for a
/// missing start or end time.
pub fn processFacts(agent_id: []const u8, event_type: []const u8, payload: std.json.Value, occurred_unix: i64) ?ProcessFacts {
    if (payload != .object) return null;
    const p = payload.object;
    const occurred: ?u64 = if (occurred_unix > 0) @as(u64, @intCast(occurred_unix)) * entity.ticks_per_second else null;

    if (std.mem.eql(u8, event_type, "process_launch")) {
        var f = ProcessFacts{ .kind = .start, .pid = uint(p, "pid") orelse return null };
        f.ppid = uint(p, "ppid");
        f.name = str(p, "name");
        f.image = str(p, "image_path");
        f.command_line = str(p, "command_line");
        if (uint(p, "uid")) |uid| {
            const t = std.fmt.bufPrint(&f.user_buf, "uid:{d}", .{uid}) catch "";
            f.user_len = t.len;
        }
        if (p.get("start_time_unix")) |v| if (v == .integer and v.integer > 0) {
            f.start_100ns = @as(u64, @intCast(v.integer)) * entity.ticks_per_second;
        };
        const start = f.start_100ns orelse return null;
        f.entity_id = entity.compute(agent_id, f.pid, start, entity.nil_uuid);
        return f;
    }

    const is_start = std.mem.eql(u8, event_type, "process_start");
    const is_exit = std.mem.eql(u8, event_type, "process_exit");
    if (!is_start and !is_exit) return null;
    const proc = obj(p.get("process")) orelse return null;
    var f = ProcessFacts{ .kind = if (is_start) .start else .exit, .pid = uint(proc, "pid") orelse return null };
    f.entity_id = entityId(proc);
    f.guid = str(proc, "guid");
    f.image = str(proc, "image");
    f.name = str(proc, "name");
    f.command_line = str(proc, "command_line");
    setUser(&f, obj(proc.get("user")));
    // Event time from a Windows payload is more precise than occurred_at.
    const event_ts: ?u64 = if (str(p, "ts")) |t| entity.parseIso(t) else null;
    if (is_start) {
        f.start_100ns = if (str(proc, "start_time")) |t| entity.parseIso(t) else null;
        if (f.start_100ns == null) f.start_100ns = event_ts orelse occurred;
        if (obj(p.get("parent"))) |parent| {
            f.parent_entity_id = entityId(parent);
            f.ppid = uint(parent, "pid");
        }
        if (f.entity_id == null) {
            f.entity_id = entity.compute(agent_id, f.pid, f.start_100ns orelse return null, entity.nil_uuid);
        }
    } else {
        f.end_100ns = if (str(p, "end_time")) |t| entity.parseIso(t) else null;
        if (f.end_100ns == null) f.end_100ns = event_ts orelse occurred;
    }
    return f;
}

// ---- tests ----------------------------------------------------------------

const test_agent = "00000000-0000-4000-8000-00000000f001";

fn parse(text: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, std.testing.allocator, text, .{});
}

test "v1 process_launch gets an entity id from pid and start seconds" {
    var p = try parse("{\"pid\":4242,\"ppid\":1,\"uid\":501,\"name\":\"curl\",\"command_line\":\"curl x\",\"image_path\":\"/usr/bin/curl\",\"image_sha256\":null,\"signature\":{\"trusted\":false,\"signer\":null},\"start_time_unix\":1762650000}");
    defer p.deinit();
    const f = processFacts(test_agent, "process_launch", p.value, 1762650001).?;
    try std.testing.expectEqual(Kind.start, f.kind);
    try std.testing.expectEqualStrings("cy4xjhmjwfr7siwjojwri4huj4", &f.entity_id.?);
    try std.testing.expectEqual(@as(?u32, 1), f.ppid);
    try std.testing.expect(f.parent_entity_id == null);
    try std.testing.expectEqualStrings("uid:501", f.userName().?);
    try std.testing.expectEqualStrings("/usr/bin/curl", f.image.?);
    try std.testing.expectEqualStrings("process_start", canonicalType("process_launch"));
    try std.testing.expectEqualStrings("dns_query", canonicalType("dns_query"));
}

test "v1 process_launch without a start time has no identity" {
    var p = try parse("{\"pid\":4242,\"ppid\":1,\"start_time_unix\":null}");
    defer p.deinit();
    try std.testing.expect(processFacts(test_agent, "process_launch", p.value, 1) == null);
}

test "v2 process_start keeps the agent's ids" {
    var p = try parse("{\"process\":{\"entity_id\":\"wxjmbxyyq7eybnyac2lfc654ka\",\"pid\":5200,\"start_time\":\"2026-11-09T01:00:05.200Z\",\"image\":\"C:\\\\x\\\\powershell.exe\",\"user\":{\"name\":\"alice\",\"domain\":\"CORP\"}},\"parent\":{\"entity_id\":\"7iyrf5zm6b5flyledskp3lodvm\",\"pid\":4100}}");
    defer p.deinit();
    const f = processFacts(test_agent, "process_start", p.value, 0).?;
    try std.testing.expectEqualStrings("wxjmbxyyq7eybnyac2lfc654ka", &f.entity_id.?);
    try std.testing.expectEqualStrings("7iyrf5zm6b5flyledskp3lodvm", &f.parent_entity_id.?);
    try std.testing.expectEqualStrings("CORP\\alice", f.userName().?);
    try std.testing.expectEqual(entity.parseIso("2026-11-09T01:00:05.200Z"), f.start_100ns);
}

test "v1 Windows process_start without an entity id gets one; a bad id is ignored" {
    var p = try parse("{\"ts\":\"2026-11-09T01:12:44.5512031Z\",\"process\":{\"entity_id\":\"NOT-AN-ID\",\"guid\":\"{g}\",\"pid\":6844,\"start_time\":\"2026-11-09T01:12:44.548Z\"},\"parent\":{\"pid\":5532}}");
    defer p.deinit();
    const f = processFacts(test_agent, "process_start", p.value, 0).?;
    try std.testing.expectEqualSlices(u8, &entity.compute(test_agent, 6844, entity.parseIso("2026-11-09T01:12:44.548Z").?, entity.nil_uuid), &f.entity_id.?);
    try std.testing.expectEqual(@as(?u32, 5532), f.ppid);
}

test "process_exit facts and non-process events" {
    var p = try parse("{\"ts\":\"2026-11-09T01:20:00.0000000Z\",\"process\":{\"guid\":\"{g}\",\"pid\":6844}}");
    defer p.deinit();
    const f = processFacts(test_agent, "process_exit", p.value, 0).?;
    try std.testing.expectEqual(Kind.exit, f.kind);
    try std.testing.expect(f.entity_id == null);
    try std.testing.expectEqual(entity.parseIso("2026-11-09T01:20:00Z"), f.end_100ns);
    var q = try parse("{\"qname\":\"x\"}");
    defer q.deinit();
    try std.testing.expect(processFacts(test_agent, "dns_query", q.value, 1) == null);
}
