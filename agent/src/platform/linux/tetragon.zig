//! Optional Tetragon source (#59). Tetragon writes one JSON object per line
//! to its export file (`--export-filename`, default
//! /var/run/cilium/tetragon/tetragon.log). The agent tails that file with
//! `audit.Tail` and maps `process_exec`, `process_exit` and
//! `process_kprobe` for `tcp_connect` to the same v2 events as the audit
//! source. Mapping is pure; the tests use testdata/tetragon.jsonl.
const std = @import("std");
const entity = @import("../../entity.zig");
const privacy = @import("../../collectors/privacy.zig");
const audit = @import("audit.zig");

pub const default_export_path = "/var/run/cilium/tetragon/tetragon.log";

pub const Kind = enum { exec, exit, connect };

/// One mapped line. `pid` and `start_100ns` let the caller keep the entity
/// table and the poller in step.
pub const Line = struct {
    mapped: audit.Mapped,
    kind: Kind,
    pid: u32,
};

pub const MapContext = struct {
    table: ?*entity.Table = null,
    /// /proc start of a live process, so ids match the poller's.
    live_start: ?*const fn (pid: u32) ?u64 = null,
};

const V = std.json.Value;

fn get(v: V, key: []const u8) ?V {
    if (v != .object) return null;
    return v.object.get(key);
}

fn str(v: V, key: []const u8) []const u8 {
    const x = get(v, key) orelse return "";
    return if (x == .string) x.string else "";
}

fn int(v: V, key: []const u8) ?i64 {
    const x = get(v, key) orelse return null;
    return switch (x) {
        .integer => |n| n,
        .number_string => |s| std.fmt.parseInt(i64, s, 10) catch null,
        else => null,
    };
}

fn pidOf(v: V) ?u32 {
    const n = int(v, "pid") orelse return null;
    if (n < 0 or n > std.math.maxInt(u32)) return null;
    return @intCast(n);
}

/// Map one export line. Null for lines we do not report.
pub fn mapLine(alloc: std.mem.Allocator, line: []const u8, ctx: MapContext) !?Line {
    const trimmed = std.mem.trim(u8, line, " \r\t");
    if (trimmed.len == 0 or trimmed[0] != '{') return null;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const root = std.json.parseFromSliceLeaky(V, arena.allocator(), trimmed, .{}) catch return null;
    const time = entity.parseIso(str(root, "time"));
    const occurred: i64 = if (time) |t| @intCast(t / entity.ticks_per_second) else 0;

    if (get(root, "process_exec")) |ev| {
        const p = get(ev, "process") orelse return null;
        const pid = pidOf(p) orelse return null;
        const payload = try processStart(alloc, ev, p, pid, ctx);
        return .{ .mapped = .{ .event_type = "process_start", .payload = payload, .occurred_at = occurred }, .kind = .exec, .pid = pid };
    }
    if (get(root, "process_exit")) |ev| {
        const p = get(ev, "process") orelse return null;
        const pid = pidOf(p) orelse return null;
        const payload = try processExit(alloc, ev, p, pid, time, ctx);
        return .{ .mapped = .{ .event_type = "process_exit", .payload = payload, .occurred_at = occurred }, .kind = .exit, .pid = pid };
    }
    if (get(root, "process_kprobe")) |ev| {
        if (!std.mem.eql(u8, str(ev, "function_name"), "tcp_connect")) return null;
        const p = get(ev, "process") orelse return null;
        const pid = pidOf(p) orelse return null;
        const args = get(ev, "args") orelse return null;
        if (args != .array or args.array.items.len == 0) return null;
        const sock = get(args.array.items[0], "sock_arg") orelse return null;
        const daddr = str(sock, "daddr");
        const dport = int(sock, "dport") orelse return null;
        if (daddr.len == 0 or dport <= 0 or dport > 65535) return null;
        const payload = try networkConnect(alloc, p, pid, sock, daddr, dport, ctx);
        return .{ .mapped = .{ .event_type = "network_connect", .payload = payload, .occurred_at = occurred }, .kind = .connect, .pid = pid };
    }
    return null;
}

fn startOf(p: V, pid: u32, ctx: MapContext) ?u64 {
    if (ctx.live_start) |f| if (f(pid)) |s| return s;
    return entity.parseIso(str(p, "start_time"));
}

fn idOf(p: V, pid: u32, ctx: MapContext) ?entity.Id {
    const t = ctx.table orelse return null;
    return t.idFor(pid, startOf(p, pid, ctx) orelse return null);
}

const Jw = std.json.Stringify;

fn header(jw: *Jw) !void {
    try jw.beginObject();
    try jw.objectField("sensor");
    try jw.write("tetragon");
}

fn processStart(alloc: std.mem.Allocator, ev: V, p: V, pid: u32, ctx: MapContext) ![]u8 {
    const start = startOf(p, pid, ctx);
    var id: ?entity.Id = null;
    if (ctx.table) |t| if (start) |s| {
        id = try t.observe(pid, s, "");
    };
    const binary = str(p, "binary");
    const args = str(p, "arguments");
    const raw_cmd = if (args.len > 0) try std.fmt.allocPrint(alloc, "{s} {s}", .{ binary, args }) else try alloc.dupe(u8, binary);
    defer alloc.free(raw_cmd);
    const cmd = try privacy.sanitizeCommandLine(alloc, raw_cmd);
    defer alloc.free(cmd);

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    var jw: Jw = .{ .writer = &out.writer };
    try header(&jw);
    try jw.objectField("process");
    try jw.beginObject();
    if (id) |v| {
        try jw.objectField("entity_id");
        try jw.write(&v);
    }
    try jw.objectField("pid");
    try jw.write(pid);
    if (start) |s| {
        var buf: [24]u8 = undefined;
        try jw.objectField("start_time");
        try jw.write(entity.formatIso(&buf, s));
    }
    try jw.objectField("name");
    try jw.write(std.fs.path.basename(binary));
    if (binary.len > 0) {
        try jw.objectField("image");
        try jw.write(binary);
    }
    try jw.objectField("command_line");
    try jw.write(cmd);
    const cwd = str(p, "cwd");
    if (cwd.len > 0) {
        try jw.objectField("cwd");
        try jw.write(cwd);
    }
    if (int(p, "uid")) |uid| if (uid >= 0) {
        try jw.objectField("user");
        try jw.beginObject();
        try jw.objectField("uid");
        try jw.write(uid);
        try jw.endObject();
    };
    try jw.endObject();
    if (get(ev, "parent")) |parent| {
        try jw.objectField("parent");
        try jw.beginObject();
        if (pidOf(parent)) |ppid| {
            if (idOf(parent, ppid, ctx)) |v| {
                try jw.objectField("entity_id");
                try jw.write(&v);
            }
            try jw.objectField("pid");
            try jw.write(ppid);
        }
        const pbin = str(parent, "binary");
        if (pbin.len > 0) {
            try jw.objectField("image");
            try jw.write(pbin);
            try jw.objectField("name");
            try jw.write(std.fs.path.basename(pbin));
        }
        try jw.endObject();
    }
    try jw.endObject();
    return out.toOwnedSlice();
}

fn processExit(alloc: std.mem.Allocator, ev: V, p: V, pid: u32, time: ?u64, ctx: MapContext) ![]u8 {
    _ = ev;
    const id = idOf(p, pid, ctx);
    if (ctx.table) |t| if (id != null) t.forget(pid);
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    var jw: Jw = .{ .writer = &out.writer };
    try header(&jw);
    try jw.objectField("process");
    try jw.beginObject();
    if (id) |v| {
        try jw.objectField("entity_id");
        try jw.write(&v);
    }
    try jw.objectField("pid");
    try jw.write(pid);
    const binary = str(p, "binary");
    if (binary.len > 0) {
        try jw.objectField("image");
        try jw.write(binary);
    }
    try jw.endObject();
    if (time) |t| {
        var buf: [24]u8 = undefined;
        try jw.objectField("end_time");
        try jw.write(entity.formatIso(&buf, t));
    }
    try jw.endObject();
    return out.toOwnedSlice();
}

fn networkConnect(alloc: std.mem.Allocator, p: V, pid: u32, sock: V, daddr: []const u8, dport: i64, ctx: MapContext) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    var jw: Jw = .{ .writer = &out.writer };
    try header(&jw);
    try jw.objectField("process");
    try jw.beginObject();
    if (idOf(p, pid, ctx)) |v| {
        try jw.objectField("entity_id");
        try jw.write(&v);
    }
    try jw.objectField("pid");
    try jw.write(pid);
    const binary = str(p, "binary");
    if (binary.len > 0) {
        try jw.objectField("image");
        try jw.write(binary);
        try jw.objectField("name");
        try jw.write(std.fs.path.basename(binary));
    }
    try jw.endObject();
    try jw.objectField("network");
    try jw.beginObject();
    try jw.objectField("protocol");
    try jw.write("tcp");
    try jw.objectField("direction");
    try jw.write("outbound");
    const saddr = str(sock, "saddr");
    if (saddr.len > 0) {
        try jw.objectField("src_ip");
        try jw.write(saddr);
    }
    if (int(sock, "sport")) |sp| if (sp > 0) {
        try jw.objectField("src_port");
        try jw.write(sp);
    };
    try jw.objectField("dst_ip");
    try jw.write(daddr);
    try jw.objectField("dst_port");
    try jw.write(dport);
    try jw.endObject();
    try jw.endObject();
    return out.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

test "tetragon export lines map to v2 events with entity ids" {
    const alloc = testing.allocator;
    var table = entity.Table.init(alloc, "0f8fad5b-d9cb-469f-a165-70867728950e", "3c1c4b5e-6d2a-4f0e-9b7a-2d1e5f6a7b8c", 64);
    defer table.deinit();
    const text = @embedFile("testdata/tetragon.jsonl");
    var got: std.ArrayList(Line) = .empty;
    defer {
        for (got.items) |l| alloc.free(l.mapped.payload);
        got.deinit(alloc);
    }
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (try mapLine(alloc, line, .{ .table = &table })) |l| try got.append(alloc, l);
    }
    const want = [_][]const u8{ "process_start", "network_connect", "process_exit" };
    try testing.expectEqual(want.len, got.items.len);
    for (want, got.items) |w, l| {
        try testing.expectEqualStrings(w, l.mapped.event_type);
        try @import("../../schema_check.zig").expectValid(alloc, l.mapped.event_type, l.mapped.payload);
    }
    const start = entity.parseIso("2026-11-10T01:00:00.123456789Z").?;
    const child = table.idFor(4242, start);
    const parent = table.idFor(4100, entity.parseIso("2026-11-10T00:59:00.000000000Z").?);
    const exec = got.items[0].mapped.payload;
    try testing.expect(std.mem.indexOf(u8, exec, &child) != null);
    try testing.expect(std.mem.indexOf(u8, exec, &parent) != null);
    try testing.expect(std.mem.indexOf(u8, exec, "\"command_line\":\"/usr/bin/curl -s https://example.com\"") != null);
    try testing.expect(std.mem.indexOf(u8, got.items[1].mapped.payload, &child) != null);
    try testing.expect(std.mem.indexOf(u8, got.items[1].mapped.payload, "\"dst_ip\":\"93.184.215.14\",\"dst_port\":443") != null);
    try testing.expect(std.mem.indexOf(u8, got.items[2].mapped.payload, &child) != null);
    try testing.expect(std.mem.indexOf(u8, got.items[2].mapped.payload, "\"end_time\":\"2026-11-10T01:00:01.000Z\"") != null);
    try testing.expectEqual(@as(u32, 4242), got.items[2].pid);
}

test "tetragon lines we do not report and bad input" {
    const alloc = testing.allocator;
    try testing.expect((try mapLine(alloc, "", .{})) == null);
    try testing.expect((try mapLine(alloc, "not json", .{})) == null);
    try testing.expect((try mapLine(alloc, "{\"process_kprobe\":{\"function_name\":\"security_file_permission\",\"process\":{\"pid\":1}}}", .{})) == null);
    try testing.expect((try mapLine(alloc, "{\"process_exec\":{\"process\":{\"binary\":\"/bin/x\"}}}", .{})) == null);
    try testing.expect((try mapLine(alloc, "{\"process_kprobe\":{\"function_name\":\"tcp_connect\",\"process\":{\"pid\":1},\"args\":[{\"sock_arg\":{\"daddr\":\"1.2.3.4\",\"dport\":0}}]}}", .{})) == null);
}
