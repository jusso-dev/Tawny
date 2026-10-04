const std = @import("std");

var runtime_io: ?std.Io = null;

pub fn initialize(io: std.Io) void {
    runtime_io = io;
}

pub fn current() std.Io {
    return runtime_io orelse std.Io.Threaded.global_single_threaded.io();
}

/// Read a whole file, at most `max_bytes`. Reads until EOF rather than
/// trusting stat().size: procfs/sysfs files (/proc/<pid>/cmdline,
/// /proc/net/tcp, ...) report size 0 and would otherwise read as empty.
pub fn readToEndAlloc(file: std.Io.File, allocator: std.mem.Allocator, max_bytes: usize) ![]u8 {
    const io = current();
    const stat = try file.stat(io);
    if (stat.size > max_bytes) return error.FileTooBig;

    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    var want: usize = @max(@as(usize, @intCast(stat.size)), 4096);
    while (true) {
        // One byte past the limit so an oversized file is detected.
        want = @min(want, max_bytes + 1);
        try list.ensureTotalCapacity(allocator, want);
        const dest = list.unusedCapacitySlice()[0 .. want - list.items.len];
        const n = try file.readPositionalAll(io, dest, list.items.len);
        list.items.len += n;
        if (list.items.len > max_bytes) return error.FileTooBig;
        if (n < dest.len) break; // EOF
        want *= 2;
    }
    return list.toOwnedSlice(allocator);
}

test "readToEndAlloc reads procfs-style files and enforces the limit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    {
        var f = try tmp.dir.createFile(io, "data", .{});
        defer f.close(io);
        var big: [10000]u8 = undefined;
        @memset(&big, 'x');
        try f.writePositionalAll(io, &big, 0);
    }
    var f = try tmp.dir.openFile(io, "data", .{});
    defer f.close(io);
    const all = try readToEndAlloc(f, std.testing.allocator, 10000);
    defer std.testing.allocator.free(all);
    try std.testing.expectEqual(@as(usize, 10000), all.len);
    try std.testing.expectError(error.FileTooBig, readToEndAlloc(f, std.testing.allocator, 9999));

    if (@import("builtin").target.os.tag == .linux) {
        // Reports size 0 but has content.
        var stat_file = try std.Io.Dir.openFileAbsolute(io, "/proc/self/stat", .{});
        defer stat_file.close(io);
        const stat = try readToEndAlloc(stat_file, std.testing.allocator, 16 * 1024);
        defer std.testing.allocator.free(stat);
        try std.testing.expect(stat.len > 0);
    }
}

pub fn timestamp() i64 {
    return std.Io.Clock.now(.real, current()).toSeconds();
}

pub fn sleep(nanoseconds: u64) void {
    std.Io.sleep(current(), .fromNanoseconds(@intCast(nanoseconds)), .awake) catch {};
}

pub const Timer = struct {
    started_ns: i96,

    pub fn start() !Timer {
        return .{ .started_ns = nowNs() };
    }

    pub fn read(self: Timer) u64 {
        return @intCast(nowNs() - self.started_ns);
    }

    pub fn reset(self: *Timer) void {
        self.started_ns = nowNs();
    }

    fn nowNs() i96 {
        return std.Io.Clock.now(.awake, current()).nanoseconds;
    }
};
