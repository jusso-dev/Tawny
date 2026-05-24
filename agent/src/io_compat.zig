const std = @import("std");

pub fn current() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

pub fn readToEndAlloc(file: std.Io.File, allocator: std.mem.Allocator, max_bytes: usize) ![]u8 {
    const io = current();
    const stat = try file.stat(io);
    if (stat.size > max_bytes) return error.FileTooBig;
    const buf = try allocator.alloc(u8, @intCast(stat.size));
    errdefer allocator.free(buf);
    const read = try file.readPositionalAll(io, buf, 0);
    return buf[0..read];
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
