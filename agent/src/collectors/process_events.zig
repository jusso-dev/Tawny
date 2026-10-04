const std = @import("std");
const builtin = @import("builtin");
const iox = @import("../io_compat.zig");
const privacy = @import("privacy.zig");
const macos = if (builtin.target.os.tag == .macos) @import("../platform/macos.zig") else struct {};

const max_launches_per_collection: usize = 2048;
const max_hashed_image_bytes: u64 = 512 * 1024 * 1024;
const max_hash_cache_entries: usize = 1024;
/// Linux exposes /proc/<pid>/stat starttime in USER_HZ, which is 100 on every
/// mainstream architecture (it is ABI, independent of CONFIG_HZ).
const linux_user_hz: u64 = 100;

/// Diff-based process launch collector. Tracks live (pid, start time) pairs
/// across invocations and emits a per-launch event for every pair that has
/// appeared since the previous tick. The image SHA-256 is computed from the
/// resolved executable path so the backend can pivot on hash.
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

    pub fn init(alloc: std.mem.Allocator) Tracker {
        return .{
            .allocator = alloc,
            .seen = std.AutoHashMap(u32, u64).init(alloc),
            .next = std.AutoHashMap(u32, u64).init(alloc),
            .hashes = HashCache.init(alloc),
        };
    }

    pub fn deinit(self: *Tracker) void {
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
        // Processes that exited simply are not in `next`; no separate prune pass.
        std.mem.swap(std.AutoHashMap(u32, u64), &self.seen, &self.next);

        return payloads.toOwnedSlice();
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

        var iter = proc_dir.iterate();
        while (try iter.next(io)) |entry| {
            if (entry.kind != .directory) continue;
            const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;
            const start_time = readProcessStartTime(self.allocator, pid) catch 0;
            if (!try self.observe(pid, start_time, payloads.items.len)) continue;

            const start_unix: ?i64 = if (self.linux_boot_time) |boot|
                (if (start_time > 0) @intCast(boot + start_time / linux_user_hz) else null)
            else
                null;
            const payload = buildLinuxLaunchEvent(self.allocator, &self.hashes, pid, start_unix) catch continue;
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

        for (pids) |pid| {
            if (pid < 0) continue;
            const id = macos.libproc.identity(pid) orelse continue;
            if (!try self.observe(id.pid, id.startKey(), payloads.items.len)) continue;

            if (reader == null) reader = try macos.DetailReader.init(self.allocator);
            const d = reader.?.read(pid, &id, true);
            const payload = buildLaunchEvent(self.allocator, &self.hashes, .{
                .pid = id.pid,
                .ppid = id.ppid,
                .uid = id.uid,
                .name = d.name,
                .command_line = d.command_line,
                .image_path = d.image_path,
                .start_time_unix = if (id.start_sec > 0) @intCast(id.start_sec) else null,
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
    start_time_unix: ?i64,
};

/// One payload shape for every platform:
/// {pid, ppid, uid, name, command_line, image_path, image_sha256, signature, start_time_unix}
fn buildLaunchEvent(alloc: std.mem.Allocator, hashes: *HashCache, f: LaunchFields) ![]u8 {
    const safe_command_line = try privacy.sanitizeCommandLine(alloc, f.command_line);
    defer alloc.free(safe_command_line);

    const digest: ?[32]u8 = if (f.image_path.len > 0) hashes.get(f.image_path) else null;

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;

    try w.print("{{\"pid\":{d},\"ppid\":{d},\"uid\":{d},\"name\":", .{ f.pid, f.ppid, f.uid });
    try std.json.Stringify.value(f.name, .{}, w);
    try w.writeAll(",\"command_line\":");
    try std.json.Stringify.value(safe_command_line, .{}, w);
    try w.writeAll(",\"image_path\":");
    try std.json.Stringify.value(f.image_path, .{}, w);
    if (digest) |d| {
        const hex = std.fmt.bytesToHex(d, .lower);
        try w.print(",\"image_sha256\":\"{s}\"", .{hex});
    } else {
        try w.writeAll(",\"image_sha256\":null");
    }
    try w.writeAll(",\"signature\":{\"trusted\":false,\"signer\":null}");
    if (f.start_time_unix) |t| {
        try w.print(",\"start_time_unix\":{d}", .{t});
    } else {
        try w.writeAll(",\"start_time_unix\":null");
    }
    try w.writeByte('}');
    return out.toOwnedSlice();
}

fn buildLinuxLaunchEvent(alloc: std.mem.Allocator, hashes: *HashCache, pid: u32, start_time_unix: ?i64) ![]u8 {
    const name = readProcText(alloc, pid, "comm") catch try alloc.dupe(u8, "unknown");
    defer alloc.free(name);
    const trimmed_name = std.mem.trimEnd(u8, name, "\r\n");

    const command_line = readCommandLine(alloc, pid) catch try alloc.dupe(u8, trimmed_name);
    defer alloc.free(command_line);

    const exe_path = readExeLink(alloc, pid) catch try alloc.dupe(u8, "");
    defer alloc.free(exe_path);

    return buildLaunchEvent(alloc, hashes, .{
        .pid = pid,
        .ppid = readParentPid(alloc, pid) catch 0,
        .uid = readUid(alloc, pid) catch 0,
        .name = trimmed_name,
        .command_line = command_line,
        .image_path = exe_path,
        .start_time_unix = start_time_unix,
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
    const payload = try buildLaunchEvent(std.testing.allocator, &hashes, .{
        .pid = 42,
        .ppid = 1,
        .uid = 501,
        .name = "curl",
        .command_line = "curl -H Authorization: Bearer abc https://example.com",
        .image_path = "",
        .start_time_unix = 1730000000,
    });
    defer std.testing.allocator.free(payload);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, payload, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    for ([_][]const u8{ "pid", "ppid", "uid", "name", "command_line", "image_path", "image_sha256", "signature", "start_time_unix" }) |key| {
        try std.testing.expect(obj.get(key) != null);
    }
    try std.testing.expect(std.mem.indexOf(u8, obj.get("command_line").?.string, "abc") == null);
    try std.testing.expectEqual(@as(i64, 1730000000), obj.get("start_time_unix").?.integer);
}

test "launch diff sees a spawned /bin/sleep with full argv and start time" {
    if (builtin.target.os.tag != .macos and builtin.target.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    iox.initialize(std.testing.io);

    var t = Tracker.init(alloc);
    defer t.deinit();
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
        const obj = parsed.value.object;
        if (obj.get("pid").?.integer != child_pid) continue;
        found = true;
        try std.testing.expectEqualStrings("sleep", obj.get("name").?.string);
        try std.testing.expectEqualStrings("/bin/sleep 5", obj.get("command_line").?.string);
        // macOS: /bin/sleep; Debian-style usrmerge resolves /proc/<pid>/exe to /usr/bin/sleep.
        try std.testing.expect(std.mem.endsWith(u8, obj.get("image_path").?.string, "/bin/sleep"));
        try std.testing.expectEqual(@as(i64, @intCast(std.c.getpid())), obj.get("ppid").?.integer);
        try std.testing.expect(obj.get("image_sha256").? == .string);
        // Spawned a moment ago: start time must be close to the wall clock.
        const started = obj.get("start_time_unix").?.integer;
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
        try std.testing.expect(parsed.value.object.get("pid").?.integer != child_pid);
    }
}
