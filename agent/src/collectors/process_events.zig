const std = @import("std");
const builtin = @import("builtin");
const iox = @import("../io_compat.zig");
const privacy = @import("privacy.zig");
const entity = @import("../entity.zig");
const schema_check = @import("../schema_check.zig");
const macos = if (builtin.target.os.tag == .macos) @import("../platform/macos.zig") else struct {};

const max_launches_per_collection: usize = 2048;
const max_hashed_image_bytes: u64 = 512 * 1024 * 1024;
const max_hash_cache_entries: usize = 1024;
/// Linux exposes /proc/<pid>/stat starttime in USER_HZ, which is 100 on every
/// mainstream architecture (it is ABI, independent of CONFIG_HZ).
const linux_user_hz: u64 = 100;

/// Diff-based process launch collector. Tracks live (pid, start time) pairs
/// across invocations and emits a `process_start` event for every pair that
/// has appeared since the previous tick. The image SHA-256 is computed from
/// the resolved executable path so the backend can pivot on hash.
///
/// With an entity table, every live process is recorded in it on each pass
/// before payloads are built, so `parent.entity_id` is filled even when the
/// parent was listed after the child. The first pass is the start-up snapshot.
///
/// Linux reads /proc; macOS uses libproc (proc_listallpids + PROC_PIDTBSDINFO
/// for the start time, KERN_PROCARGS2 for argv). This is intentionally not a
/// kernel-level exec hook (no eBPF, ETW or Endpoint Security): a process that
/// starts and exits inside one polling interval can be missed.
pub const Tracker = struct {
    allocator: std.mem.Allocator,
    /// pid -> start key observed on the previous pass.
    seen: std.AutoHashMap(u32, u64),
    /// Scratch map for the current pass; swapped with `seen` at the end.
    next: std.AutoHashMap(u32, u64),
    hashes: HashCache,
    linux_boot_time: ?u64 = null,
    entities: ?*entity.Table = null,
    /// `process_exit` payloads for processes gone since the previous pass.
    /// The end time is when the pass noticed, so it is late by up to one
    /// polling interval. Taken with `takeExits`.
    exits: std.ArrayList([]u8) = .empty,

    pub fn init(alloc: std.mem.Allocator) Tracker {
        return .{
            .allocator = alloc,
            .seen = std.AutoHashMap(u32, u64).init(alloc),
            .next = std.AutoHashMap(u32, u64).init(alloc),
            .hashes = HashCache.init(alloc),
        };
    }

    pub fn deinit(self: *Tracker) void {
        for (self.exits.items) |e| self.allocator.free(e);
        self.exits.deinit(self.allocator);
        self.seen.deinit();
        self.next.deinit();
        self.hashes.deinit();
    }

    /// Returns a list of JSON payloads, one per newly observed process.
    /// Caller owns both the outer slice and each inner payload.
    pub fn collectLaunches(self: *Tracker) ![][]u8 {
        var payloads = std.array_list.Managed([]u8).init(self.allocator);
        errdefer {
            for (payloads.items) |p| self.allocator.free(p);
            payloads.deinit();
        }

        self.next.clearRetainingCapacity();
        switch (builtin.target.os.tag) {
            .linux => try self.collectLinux(&payloads),
            .macos => try self.collectMacos(&payloads),
            else => return payloads.toOwnedSlice(), // Windows exec capture is deferred to ETW work.
        }
        // Processes that exited are in `seen` but not in `next`.
        if (self.entities != null) try self.noteExits();
        std.mem.swap(std.AutoHashMap(u32, u64), &self.seen, &self.next);

        return payloads.toOwnedSlice();
    }

    /// Caller owns the slice and each payload.
    pub fn takeExits(self: *Tracker) ![][]u8 {
        return self.exits.toOwnedSlice(self.allocator);
    }

    /// Start key (Linux clock ticks after boot, macOS microseconds) to 100 ns.
    fn keyTo100ns(self: *const Tracker, key: u64) ?u64 {
        return switch (builtin.target.os.tag) {
            .linux => linuxStart100ns(self.linux_boot_time orelse return null, key),
            .macos => if (key == 0) null else key * 10,
            else => null,
        };
    }

    fn noteExits(self: *Tracker) !void {
        const t = self.entities.?;
        const now: u64 = @as(u64, @intCast(@max(iox.timestamp(), 0))) * entity.ticks_per_second;
        var it = self.seen.iterator();
        while (it.next()) |kv| {
            const pid = kv.key_ptr.*;
            if (self.next.get(pid)) |still| if (still == kv.value_ptr.*) continue;
            const start = self.keyTo100ns(kv.value_ptr.*) orelse continue;
            const id = t.idFor(pid, start);
            if (t.map.get(pid)) |e| if (e.start_100ns == entity.truncateMs(start)) t.forget(pid);
            const payload = try buildExitEvent(self.allocator, id, pid, now);
            errdefer self.allocator.free(payload);
            try self.exits.append(self.allocator, payload);
        }
    }

    /// Record (pid, start) for this pass. Returns true when it is a launch
    /// we have not reported yet. Processes past the per-pass cap are not
    /// recorded, so they are reported on a later pass instead of being lost.
    fn observe(self: *Tracker, pid: u32, start: u64, emitted: usize) !bool {
        const is_new = if (self.seen.get(pid)) |prev| prev != start else true;
        if (is_new and emitted >= max_launches_per_collection) return false;
        try self.next.put(pid, start);
        return is_new;
    }

    fn collectLinux(self: *Tracker, payloads: *std.array_list.Managed([]u8)) !void {
        const io = iox.current();
        var proc_dir = std.Io.Dir.openDirAbsolute(io, "/proc", .{ .iterate = true }) catch return;
        defer proc_dir.close(io);

        if (self.linux_boot_time == null) self.linux_boot_time = readLinuxBootTime() catch null;

        const Fresh = struct { pid: u32, start: ?u64 };
        var fresh = std.array_list.Managed(Fresh).init(self.allocator);
        defer fresh.deinit();

        var iter = proc_dir.iterate();
        while (try iter.next(io)) |entry| {
            if (entry.kind != .directory) continue;
            const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;
            const start_time = readProcessStartTime(self.allocator, pid) catch 0;
            const start_100ns = if (self.linux_boot_time) |boot| linuxStart100ns(boot, start_time) else null;
            if (self.entities) |t| if (start_100ns) |s| {
                _ = try t.observe(pid, s, "");
            };
            if (!try self.observe(pid, start_time, payloads.items.len + fresh.items.len)) continue;
            try fresh.append(.{ .pid = pid, .start = start_100ns });
        }
        for (fresh.items) |f| {
            const payload = buildLinuxLaunchEvent(self.allocator, &self.hashes, self.entities, f.pid, f.start) catch continue;
            payloads.append(payload) catch |err| {
                self.allocator.free(payload);
                return err;
            };
        }
    }

    fn collectMacos(self: *Tracker, payloads: *std.array_list.Managed([]u8)) !void {
        if (comptime builtin.target.os.tag != .macos) return;
        const pids = try macos.libproc.listAllPids(self.allocator);
        defer self.allocator.free(pids);

        // Argv buffers are only needed when something new shows up.
        var reader: ?macos.DetailReader = null;
        defer if (reader) |*r| r.deinit();

        var fresh = std.array_list.Managed(macos.libproc.Identity).init(self.allocator);
        defer fresh.deinit();
        for (pids) |pid| {
            if (pid < 0) continue;
            const id = macos.libproc.identity(pid) orelse continue;
            if (self.entities) |t| if (macosStart100ns(id.start_sec, id.start_usec)) |s| {
                _ = try t.observe(id.pid, s, "");
            };
            if (!try self.observe(id.pid, id.startKey(), payloads.items.len + fresh.items.len)) continue;
            try fresh.append(id);
        }

        for (fresh.items) |*id| {
            if (reader == null) reader = try macos.DetailReader.init(self.allocator);
            const d = reader.?.read(@intCast(id.pid), id, true);
            const start = macosStart100ns(id.start_sec, id.start_usec);
            const payload = buildLaunchEvent(self.allocator, &self.hashes, .{
                .pid = id.pid,
                .ppid = id.ppid,
                .uid = id.uid,
                .name = d.name,
                .command_line = d.command_line,
                .image_path = d.image_path,
                .start_100ns = start,
                .entity_id = entityFor(self.entities, id.pid, start),
                .parent_entity_id = parentFor(self.entities, id.ppid, start),
            }) catch continue;
            payloads.append(payload) catch |err| {
                self.allocator.free(payload);
                return err;
            };
        }
    }
};

const LaunchFields = struct {
    pid: u32,
    ppid: u32,
    uid: u32,
    name: []const u8,
    /// Raw command line; scrubbed by privacy.sanitizeCommandLine here.
    command_line: []const u8,
    image_path: []const u8,
    /// Start time in 100 ns ticks since the Unix epoch.
    start_100ns: ?u64,
    entity_id: ?entity.Id = null,
    parent_entity_id: ?entity.Id = null,
};

/// `process_exit` data: {process{entity_id,pid},end_time}.
fn buildExitEvent(alloc: std.mem.Allocator, id: entity.Id, pid: u32, end_100ns: u64) ![]u8 {
    var buf: [24]u8 = undefined;
    return std.fmt.allocPrint(alloc, "{{\"process\":{{\"entity_id\":\"{s}\",\"pid\":{d}}},\"end_time\":\"{s}\"}}", .{ &id, pid, entity.formatIso(&buf, end_100ns) });
}

fn linuxStart100ns(boot_unix: u64, start_ticks: u64) ?u64 {
    if (start_ticks == 0) return null;
    return boot_unix * entity.ticks_per_second + start_ticks * (entity.ticks_per_second / linux_user_hz);
}

fn macosStart100ns(sec: u64, usec: u64) ?u64 {
    if (sec == 0) return null;
    return sec * entity.ticks_per_second + usec * 10;
}

fn entityFor(table: ?*entity.Table, pid: u32, start: ?u64) ?entity.Id {
    const t = table orelse return null;
    return t.idFor(pid, start orelse return null);
}

fn parentFor(table: ?*entity.Table, ppid: u32, child_start: ?u64) ?entity.Id {
    const t = table orelse return null;
    if (ppid == 0) return null;
    return t.parentOf(ppid, child_start);
}

/// `process_start` data (schemas/events/process_start.v1.json), the same on
/// Linux and macOS:
/// {process{entity_id,pid,start_time,name,image,command_line,user{uid},hashes{sha256}},
///  parent{entity_id,pid}}. Fields that are unknown are left out.
fn buildLaunchEvent(alloc: std.mem.Allocator, hashes: *HashCache, f: LaunchFields) ![]u8 {
    const safe_command_line = try privacy.sanitizeCommandLine(alloc, f.command_line);
    defer alloc.free(safe_command_line);

    const digest: ?[32]u8 = if (f.image_path.len > 0) hashes.get(f.image_path) else null;

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    var jw: std.json.Stringify = .{ .writer = &out.writer };
    try jw.beginObject();
    try jw.objectField("process");
    try jw.beginObject();
    if (f.entity_id) |id| {
        try jw.objectField("entity_id");
        try jw.write(&id);
    }
    try jw.objectField("pid");
    try jw.write(f.pid);
    if (f.start_100ns) |t| {
        var buf: [24]u8 = undefined;
        try jw.objectField("start_time");
        try jw.write(entity.formatIso(&buf, t));
    }
    try jw.objectField("name");
    try jw.write(f.name);
    if (f.image_path.len > 0) {
        try jw.objectField("image");
        try jw.write(f.image_path);
    }
    try jw.objectField("command_line");
    try jw.write(safe_command_line);
    try jw.objectField("user");
    try jw.beginObject();
    try jw.objectField("uid");
    try jw.write(f.uid);
    try jw.endObject();
    if (digest) |d| {
        const hex = std.fmt.bytesToHex(d, .lower);
        try jw.objectField("hashes");
        try jw.beginObject();
        try jw.objectField("sha256");
        try jw.write(&hex);
        try jw.endObject();
    }
    try jw.endObject();
    try jw.objectField("parent");
    try jw.beginObject();
    if (f.parent_entity_id) |id| {
        try jw.objectField("entity_id");
        try jw.write(&id);
    }
    try jw.objectField("pid");
    try jw.write(f.ppid);
    try jw.endObject();
    try jw.endObject();
    return out.toOwnedSlice();
}

fn buildLinuxLaunchEvent(alloc: std.mem.Allocator, hashes: *HashCache, table: ?*entity.Table, pid: u32, start_100ns: ?u64) ![]u8 {
    const name = readProcText(alloc, pid, "comm") catch try alloc.dupe(u8, "unknown");
    defer alloc.free(name);
    const trimmed_name = std.mem.trimEnd(u8, name, "\r\n");

    const command_line = readCommandLine(alloc, pid) catch try alloc.dupe(u8, trimmed_name);
    defer alloc.free(command_line);

    const exe_path = readExeLink(alloc, pid) catch try alloc.dupe(u8, "");
    defer alloc.free(exe_path);

    const ppid = readParentPid(alloc, pid) catch 0;
    return buildLaunchEvent(alloc, hashes, .{
        .pid = pid,
        .ppid = ppid,
        .uid = readUid(alloc, pid) catch 0,
        .name = trimmed_name,
        .command_line = command_line,
        .image_path = exe_path,
        .start_100ns = start_100ns,
        .entity_id = entityFor(table, pid, start_100ns),
        .parent_entity_id = parentFor(table, ppid, start_100ns),
    });
}

/// SHA-256 of executables keyed by path and invalidated on size/mtime change,
/// so a burst of `git`/`zsh` launches hashes the binary once. Bounded: the
/// cache is cleared when it reaches `max_hash_cache_entries`.
const HashCache = struct {
    allocator: std.mem.Allocator,
    map: std.StringHashMap(Entry),

    const Entry = struct {
        size: u64,
        mtime_ns: i96,
        digest: [32]u8,
    };

    fn init(alloc: std.mem.Allocator) HashCache {
        return .{ .allocator = alloc, .map = std.StringHashMap(Entry).init(alloc) };
    }

    fn deinit(self: *HashCache) void {
        self.clear();
        self.map.deinit();
    }

    fn clear(self: *HashCache) void {
        var it = self.map.keyIterator();
        while (it.next()) |key| self.allocator.free(key.*);
        self.map.clearRetainingCapacity();
    }

    fn get(self: *HashCache, path: []const u8) ?[32]u8 {
        const io = iox.current();
        var file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch return null;
        defer file.close(io);
        const stat = file.stat(io) catch return null;
        if (stat.kind != .file or stat.size > max_hashed_image_bytes) return null;

        if (self.map.get(path)) |entry| {
            if (entry.size == stat.size and entry.mtime_ns == stat.mtime.nanoseconds) return entry.digest;
        }
        const digest = hashFile(file) catch return null;

        if (self.map.getPtr(path)) |entry| {
            entry.* = .{ .size = stat.size, .mtime_ns = stat.mtime.nanoseconds, .digest = digest };
            return digest;
        }
        if (self.map.count() >= max_hash_cache_entries) self.clear();
        const key = self.allocator.dupe(u8, path) catch return digest;
        self.map.put(key, .{ .size = stat.size, .mtime_ns = stat.mtime.nanoseconds, .digest = digest }) catch {
            self.allocator.free(key);
        };
        return digest;
    }
};

fn hashFile(file: std.Io.File) ![32]u8 {
    const io = iox.current();
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [16 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < max_hashed_image_bytes) {
        const n = try file.readPositionalAll(io, &buf, offset);
        if (n == 0) break;
        sha.update(buf[0..n]);
        offset += n;
    }
    var digest: [32]u8 = undefined;
    sha.final(&digest);
    return digest;
}

fn readProcText(alloc: std.mem.Allocator, pid: u32, name: []const u8) ![]u8 {
    const path = try alloc.print("/proc/{d}/{s}", .{ pid, name });
    defer alloc.free(path);
    const io = iox.current();
    var file = try std.Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);
    return iox.readToEndAlloc(file, alloc, 16 * 1024);
}

fn readCommandLine(alloc: std.mem.Allocator, pid: u32) ![]u8 {
    const raw = try readProcText(alloc, pid, "cmdline");
    defer alloc.free(raw);
    const owned = try alloc.dupe(u8, raw);
    for (owned) |*ch| {
        if (ch.* == 0) ch.* = ' ';
    }
    const trimmed = std.mem.trimEnd(u8, owned, " ");
    if (trimmed.len == owned.len) return owned;
    const compact = try alloc.dupe(u8, trimmed);
    alloc.free(owned);
    return compact;
}

fn readParentPid(alloc: std.mem.Allocator, pid: u32) !u32 {
    const stat = try readProcText(alloc, pid, "stat");
    defer alloc.free(stat);
    const close = std.mem.lastIndexOfScalar(u8, stat, ')') orelse return error.BadProcStat;
    var fields = std.mem.tokenizeAny(u8, stat[close + 1 ..], " \t\r\n");
    _ = fields.next() orelse return error.BadProcStat;
    const ppid = fields.next() orelse return error.BadProcStat;
    return std.fmt.parseInt(u32, ppid, 10);
}

fn readProcessStartTime(alloc: std.mem.Allocator, pid: u32) !u64 {
    const stat = try readProcText(alloc, pid, "stat");
    defer alloc.free(stat);
    return parseProcessStartTime(stat);
}

fn parseProcessStartTime(stat: []const u8) !u64 {
    const close = std.mem.lastIndexOfScalar(u8, stat, ')') orelse return error.BadProcStat;
    var fields = std.mem.tokenizeAny(u8, stat[close + 1 ..], " \t\r\n");
    var index: usize = 0;
    while (fields.next()) |field| : (index += 1) {
        // Field 22 overall; token zero is field 3 (process state).
        if (index == 19) return std.fmt.parseInt(u64, field, 10);
    }
    return error.BadProcStat;
}

fn readLinuxBootTime() !u64 {
    const io = iox.current();
    var file = try std.Io.Dir.openFileAbsolute(io, "/proc/stat", .{});
    defer file.close(io);
    // /proc/stat reports size 0, so read a bounded prefix directly.
    var buf: [64 * 1024]u8 = undefined;
    const n = try file.readPositionalAll(io, &buf, 0);
    return parseBootTime(buf[0..n]);
}

/// `btime <seconds since epoch>` line from /proc/stat.
fn parseBootTime(stat: []const u8) !u64 {
    var lines = std.mem.splitScalar(u8, stat, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "btime ")) continue;
        return std.fmt.parseInt(u64, std.mem.trim(u8, line["btime ".len..], " \t\r"), 10);
    }
    return error.NoBootTime;
}

fn readUid(alloc: std.mem.Allocator, pid: u32) !u32 {
    const status = try readProcText(alloc, pid, "status");
    defer alloc.free(status);
    var lines = std.mem.splitScalar(u8, status, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "Uid:")) {
            var fields = std.mem.tokenizeAny(u8, line[4..], " \t");
            const raw = fields.next() orelse return 0;
            return std.fmt.parseInt(u32, raw, 10) catch 0;
        }
    }
    return 0;
}

fn readExeLink(alloc: std.mem.Allocator, pid: u32) ![]u8 {
    const link_path = try alloc.print("/proc/{d}/exe", .{pid});
    defer alloc.free(link_path);
    var buf: [4096]u8 = undefined;
    const len = std.Io.Dir.readLinkAbsolute(iox.current(), link_path, &buf) catch return alloc.dupe(u8, "");
    return alloc.dupe(u8, buf[0..len]);
}

test "tracker module loads" {
    var t = Tracker.init(std.testing.allocator);
    defer t.deinit();
}

test "process start time distinguishes PID reuse" {
    const stat = "123 (name with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242";
    try std.testing.expectEqual(@as(u64, 424242), try parseProcessStartTime(stat));
    try std.testing.expectError(error.BadProcStat, parseProcessStartTime("123 malformed"));
}

test "boot time parser" {
    try std.testing.expectEqual(@as(u64, 1730000000), try parseBootTime("cpu 1 2 3\nintr 5\nbtime 1730000000\nprocesses 9\n"));
    try std.testing.expectError(error.NoBootTime, parseBootTime("cpu 1 2 3\n"));
}

test "launch diff keys on pid and start time" {
    var t = Tracker.init(std.testing.allocator);
    defer t.deinit();

    const Pass = struct {
        fn run(tr: *Tracker, procs: []const [2]u64, new_out: *std.array_list.Managed(u32)) !void {
            new_out.clearRetainingCapacity();
            tr.next.clearRetainingCapacity();
            for (procs) |p| {
                if (try tr.observe(@intCast(p[0]), p[1], new_out.items.len)) try new_out.append(@intCast(p[0]));
            }
            std.mem.swap(std.AutoHashMap(u32, u64), &tr.seen, &tr.next);
        }
    };
    var fresh = std.array_list.Managed(u32).init(std.testing.allocator);
    defer fresh.deinit();

    try Pass.run(&t, &.{ .{ 1, 100 }, .{ 50, 200 } }, &fresh);
    try std.testing.expectEqualSlices(u32, &.{ 1, 50 }, fresh.items);

    try Pass.run(&t, &.{ .{ 1, 100 }, .{ 50, 200 } }, &fresh);
    try std.testing.expectEqual(@as(usize, 0), fresh.items.len);

    // pid 50 exits; pid 50 reused with a later start; pid 77 is new.
    try Pass.run(&t, &.{ .{ 1, 100 }, .{ 50, 999 }, .{ 77, 300 } }, &fresh);
    try std.testing.expectEqualSlices(u32, &.{ 50, 77 }, fresh.items);

    // Exited pids are forgotten, so a returning (pid, start) pair is new again.
    try Pass.run(&t, &.{.{ 1, 100 }}, &fresh);
    try std.testing.expectEqual(@as(usize, 1), t.seen.count());
}

test "launch payload shape is shared across platforms" {
    var hashes = HashCache.init(std.testing.allocator);
    defer hashes.deinit();
    var table = entity.Table.init(std.testing.allocator, "0f8fad5b-d9cb-469f-a165-70867728950e", "3c1c4b5e-6d2a-4f0e-9b7a-2d1e5f6a7b8c", 8);
    defer table.deinit();
    const parent_start = 1729990000 * entity.ticks_per_second;
    const start = 1730000000 * entity.ticks_per_second;
    const parent_id = try table.observe(1, parent_start, "");
    const payload = try buildLaunchEvent(std.testing.allocator, &hashes, .{
        .pid = 42,
        .ppid = 1,
        .uid = 501,
        .name = "curl",
        .command_line = "curl -H Authorization: Bearer abc https://example.com",
        .image_path = "",
        .start_100ns = start,
        .entity_id = entityFor(&table, 42, start),
        .parent_entity_id = parentFor(&table, 1, start),
    });
    defer std.testing.allocator.free(payload);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, payload, .{});
    defer parsed.deinit();
    const proc = parsed.value.object.get("process").?.object;
    for ([_][]const u8{ "entity_id", "pid", "start_time", "name", "command_line", "user" }) |key| {
        try std.testing.expect(proc.get(key) != null);
    }
    try std.testing.expect(std.mem.indexOf(u8, proc.get("command_line").?.string, "abc") == null);
    try std.testing.expectEqualStrings("2024-10-27T03:33:20.000Z", proc.get("start_time").?.string);
    try std.testing.expectEqualStrings(&table.idFor(42, start), proc.get("entity_id").?.string);
    const parent = parsed.value.object.get("parent").?.object;
    try std.testing.expectEqualStrings(&parent_id, parent.get("entity_id").?.string);
    try std.testing.expectEqual(@as(i64, 1), parent.get("pid").?.integer);
    try schema_check.expectValid(std.testing.allocator, "process_start", payload);
}

test "exit payload matches its schema" {
    const id = entity.compute("0f8fad5b-d9cb-469f-a165-70867728950e", 9, 1730000000 * entity.ticks_per_second, entity.nil_uuid);
    const payload = try buildExitEvent(std.testing.allocator, id, 9, 1730000100 * entity.ticks_per_second);
    defer std.testing.allocator.free(payload);
    try std.testing.expect(std.mem.indexOf(u8, payload, &id) != null);
    try schema_check.expectValid(std.testing.allocator, "process_exit", payload);
}

test "linux and macos start times convert to 100 ns ticks" {
    try std.testing.expectEqual(@as(?u64, 1730000000 * entity.ticks_per_second + 250 * 100_000), linuxStart100ns(1730000000, 250));
    try std.testing.expectEqual(@as(?u64, null), linuxStart100ns(1730000000, 0));
    try std.testing.expectEqual(@as(?u64, 1730000000 * entity.ticks_per_second + 5000 * 10), macosStart100ns(1730000000, 5000));
}

test "launch diff sees a spawned /bin/sleep with full argv and start time" {
    if (builtin.target.os.tag != .macos and builtin.target.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    iox.initialize(std.testing.io);

    var t = Tracker.init(alloc);
    defer t.deinit();
    const boot = entity.readBootId();
    var table = entity.Table.init(alloc, "0f8fad5b-d9cb-469f-a165-70867728950e", &boot, entity.Table.default_capacity);
    defer table.deinit();
    t.entities = &table;
    const baseline = try t.collectLaunches();
    for (baseline) |p| alloc.free(p);
    alloc.free(baseline);

    var child = try std.process.spawn(std.testing.io, .{
        .argv = &.{ "/bin/sleep", "5" },
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer child.kill(std.testing.io);
    const child_pid: u32 = @intCast(child.id.?);

    const launches = try t.collectLaunches();
    defer {
        for (launches) |p| alloc.free(p);
        alloc.free(launches);
    }
    var found = false;
    for (launches) |payload| {
        var parsed = try std.json.parseFromSlice(std.json.Value, alloc, payload, .{});
        defer parsed.deinit();
        const obj = parsed.value.object.get("process").?.object;
        if (obj.get("pid").?.integer != child_pid) continue;
        found = true;
        try std.testing.expectEqualStrings("sleep", obj.get("name").?.string);
        try std.testing.expectEqualStrings("/bin/sleep 5", obj.get("command_line").?.string);
        try std.testing.expectEqual(@as(usize, entity.len), obj.get("entity_id").?.string.len);
        // The test runner was recorded in the table on the baseline pass.
        const parent = parsed.value.object.get("parent").?.object;
        try std.testing.expectEqual(@as(usize, entity.len), parent.get("entity_id").?.string.len);
        try schema_check.expectValid(alloc, "process_start", payload);
        // Compare with wherever /bin/sleep really lives. usrmerge gives /usr/bin/sleep,
        // and Ubuntu 26.04 links it into Rust coreutils under /usr/lib/cargo/bin/coreutils/.
        var real_buf: [std.fs.max_path_bytes]u8 = undefined;
        const real_len = try std.Io.Dir.realPathFileAbsolute(std.testing.io, "/bin/sleep", &real_buf);
        const image_path = obj.get("image").?.string;
        if (!std.mem.eql(u8, image_path, real_buf[0..real_len]) and !std.mem.eql(u8, image_path, "/bin/sleep")) {
            std.debug.print("image_path={s} realpath(/bin/sleep)={s}\n", .{ image_path, real_buf[0..real_len] });
            return error.TestUnexpectedResult;
        }
        try std.testing.expectEqual(@as(i64, @intCast(std.c.getpid())), parent.get("pid").?.integer);
        try std.testing.expect(obj.get("hashes").?.object.get("sha256").? == .string);
        // Spawned a moment ago: start time must be close to the wall clock.
        const started: i64 = @intCast(entity.parseIso(obj.get("start_time").?.string).? / entity.ticks_per_second);
        try std.testing.expect(@abs(started - iox.timestamp()) <= 60);
    }
    try std.testing.expect(found);

    // Second pass: already reported, must not be emitted again.
    const again = try t.collectLaunches();
    defer {
        for (again) |p| alloc.free(p);
        alloc.free(again);
    }
    for (again) |payload| {
        var parsed = try std.json.parseFromSlice(std.json.Value, alloc, payload, .{});
        defer parsed.deinit();
        try std.testing.expect(parsed.value.object.get("process").?.object.get("pid").?.integer != child_pid);
    }
}
