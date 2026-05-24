const std = @import("std");
const builtin = @import("builtin");

/// Diff-based process launch collector. Tracks the set of live PIDs across
/// invocations and emits a per-launch event for every PID that has appeared
/// since the previous tick. The image SHA-256 is computed from the resolved
/// executable path so the backend can pivot on hash.
///
/// This is intentionally not a kernel-level exec hook (no eBPF, no ETW
/// kernel provider); we rely on /proc on Linux and shell out elsewhere.
/// A new process that starts and exits inside a single polling interval can
/// be missed — operators who need every exec should switch to kernel-grade
/// telemetry (Phase 2's eBPF / ETW path, deliberately out of scope here).
pub const Tracker = struct {
    allocator: std.mem.Allocator,
    seen: std.AutoHashMap(u32, void),

    pub fn init(alloc: std.mem.Allocator) Tracker {
        return .{
            .allocator = alloc,
            .seen = std.AutoHashMap(u32, void).init(alloc),
        };
    }

    pub fn deinit(self: *Tracker) void {
        self.seen.deinit();
    }

    /// Returns a list of JSON payloads, one per newly observed process.
    /// Caller owns both the outer slice and each inner payload.
    pub fn collectLaunches(self: *Tracker) ![][]u8 {
        var payloads = std.array_list.Managed([]u8).init(self.allocator);
        errdefer {
            for (payloads.items) |p| self.allocator.free(p);
            payloads.deinit();
        }

        switch (builtin.os.tag) {
            .linux => try self.collectLinux(&payloads),
            else => {}, // Win/macOS exec-event capture is deferred to kernel-level work.
        }

        // GC PIDs that have gone away so the map doesn't grow unboundedly.
        try self.pruneStale();

        return payloads.toOwnedSlice();
    }

    fn collectLinux(self: *Tracker, payloads: *std.array_list.Managed([]u8)) !void {
        var proc_dir = std.fs.openDirAbsolute("/proc", .{ .iterate = true }) catch return;
        defer proc_dir.close();

        var iter = proc_dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;
            const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;
            if (self.seen.contains(pid)) continue;

            // First sighting of this PID: emit a launch event and remember it.
            try self.seen.put(pid, {});
            const payload = buildLinuxLaunchEvent(self.allocator, pid) catch |err| switch (err) {
                error.FileNotFound, error.AccessDenied, error.IsDir => continue,
                else => return err,
            };
            try payloads.append(payload);
        }
    }

    fn pruneStale(self: *Tracker) !void {
        var to_remove = std.array_list.Managed(u32).init(self.allocator);
        defer to_remove.deinit();

        var it = self.seen.iterator();
        while (it.next()) |kv| {
            const pid = kv.key_ptr.*;
            if (!pidExists(pid)) try to_remove.append(pid);
        }
        for (to_remove.items) |pid| _ = self.seen.remove(pid);
    }
};

fn pidExists(pid: u32) bool {
    if (builtin.os.tag != .linux) return true;
    var buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&buf, "/proc/{d}", .{pid}) catch return false;
    var dir = std.fs.openDirAbsolute(path, .{}) catch return false;
    dir.close();
    return true;
}

fn buildLinuxLaunchEvent(alloc: std.mem.Allocator, pid: u32) ![]u8 {
    const name = readProcText(alloc, pid, "comm") catch try alloc.dupe(u8, "unknown");
    defer alloc.free(name);
    const trimmed_name = std.mem.trimRight(u8, name, "\r\n");

    const command_line = readCommandLine(alloc, pid) catch try alloc.dupe(u8, trimmed_name);
    defer alloc.free(command_line);

    const exe_path = readExeLink(alloc, pid) catch try alloc.dupe(u8, "");
    defer alloc.free(exe_path);

    const ppid = readParentPid(alloc, pid) catch 0;

    var digest = std.mem.zeroes([32]u8);
    var hashed = false;
    if (exe_path.len > 0) {
        if (hashImage(exe_path)) |d| {
            digest = d;
            hashed = true;
        } else |_| {}
    }

    const uid = readUid(alloc, pid) catch 0;

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;

    try w.print("{{\"pid\":{d},\"ppid\":{d},\"uid\":{d},\"name\":", .{ pid, ppid, uid });
    try std.json.Stringify.value(trimmed_name, .{}, w);
    try w.writeAll(",\"command_line\":");
    try std.json.Stringify.value(command_line, .{}, w);
    try w.writeAll(",\"image_path\":");
    try std.json.Stringify.value(exe_path, .{}, w);
    if (hashed) {
        try w.print(",\"image_sha256\":\"{}\"", .{std.fmt.fmtSliceHexLower(&digest)});
    } else {
        try w.writeAll(",\"image_sha256\":null");
    }
    try w.writeAll(",\"signature\":{\"trusted\":false,\"signer\":null}}");
    return out.toOwnedSlice();
}

fn readProcText(alloc: std.mem.Allocator, pid: u32, name: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(alloc, "/proc/{d}/{s}", .{ pid, name });
    defer alloc.free(path);
    var file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    return file.readToEndAlloc(alloc, 16 * 1024);
}

fn readCommandLine(alloc: std.mem.Allocator, pid: u32) ![]u8 {
    const raw = try readProcText(alloc, pid, "cmdline");
    defer alloc.free(raw);
    const owned = try alloc.dupe(u8, raw);
    for (owned) |*ch| {
        if (ch.* == 0) ch.* = ' ';
    }
    const trimmed = std.mem.trimRight(u8, owned, " ");
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
    const link_path = try std.fmt.allocPrint(alloc, "/proc/{d}/exe", .{pid});
    defer alloc.free(link_path);
    var buf: [4096]u8 = undefined;
    const resolved = std.fs.readLinkAbsolute(link_path, &buf) catch return alloc.dupe(u8, "");
    return alloc.dupe(u8, resolved);
}

fn hashImage(path: []const u8) ![32]u8 {
    var file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    var sha = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const n = try file.read(&buf);
        if (n == 0) break;
        sha.update(buf[0..n]);
    }
    var digest: [32]u8 = undefined;
    sha.final(&digest);
    return digest;
}

test "tracker module loads" {
    var t = Tracker.init(std.testing.allocator);
    defer t.deinit();
}
