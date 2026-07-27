const std = @import("std");
const builtin = @import("builtin");
const iox = @import("../io_compat.zig");

const max_sessions: usize = 1024;
const max_session_line_bytes: usize = 1024;
const command_timeout: std.Io.Timeout = .{ .duration = .{
    .clock = .awake,
    .raw = .fromSeconds(5),
} };

pub fn collect(alloc: std.mem.Allocator) ![]u8 {
    return switch (builtin.os.tag) {
        .macos => collectMacos(alloc),
        .windows => collectWindows(alloc),
        .linux => collectLinux(alloc),
        else => @compileError("unsupported os"),
    };
}

const c = if (builtin.os.tag == .macos) @cImport({
    @cInclude("utmpx.h");
}) else struct {};

fn collectMacos(alloc: std.mem.Allocator) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;

    try w.writeAll("{\"source\":\"utmpx\",\"sessions\":[");
    c.setutxent();
    defer c.endutxent();

    var first = true;
    var count: usize = 0;
    while (c.getutxent()) |entry| {
        if (count >= max_sessions) break;
        const session = entry.*;
        if (session.ut_type != c.USER_PROCESS) continue;
        if (!first) try w.writeByte(',');
        first = false;
        count += 1;

        try w.writeAll("{\"user\":");
        try std.json.Stringify.value(std.mem.sliceTo(&session.ut_user, 0), .{}, w);
        try w.writeAll(",\"line\":");
        try std.json.Stringify.value(std.mem.sliceTo(&session.ut_line, 0), .{}, w);
        try w.print(",\"pid\":{d}}}", .{session.ut_pid});
    }
    try w.writeAll("]}");

    return out.toOwnedSlice();
}

fn collectLinux(alloc: std.mem.Allocator) ![]u8 {
    const result = std.process.run(alloc, iox.current(), .{
        .argv = &.{"who"},
        .stdout_limit = .limited(128 * 1024),
        .stderr_limit = .limited(16 * 1024),
        .timeout = command_timeout,
    }) catch {
        return alloc.dupe(u8, "{\"source\":\"who\",\"sessions\":[]}");
    };
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);
    if (!termSucceeded(result.term)) {
        return alloc.dupe(u8, "{\"source\":\"who\",\"sessions\":[]}");
    }

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;

    try w.writeAll("{\"source\":\"who\",\"sessions\":[");
    var first = true;
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line_raw| {
        if (count >= max_sessions) break;
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0 or line.len > max_session_line_bytes) continue;
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        const user = fields.next() orelse continue;
        const tty = fields.next() orelse "";
        if (!first) try w.writeByte(',');
        first = false;
        count += 1;
        try w.writeAll("{\"user\":");
        try std.json.Stringify.value(user, .{}, w);
        try w.writeAll(",\"line\":");
        try std.json.Stringify.value(tty, .{}, w);
        try w.writeAll(",\"raw\":");
        try std.json.Stringify.value(line, .{}, w);
        try w.writeByte('}');
    }
    try w.writeAll("]}");

    return out.toOwnedSlice();
}

const WTS_CURRENT_SERVER_HANDLE: ?*anyopaque = null;
const WTSActive: u32 = 0;

const WTS_SESSION_INFOW = extern struct {
    SessionId: u32,
    pWinStationName: ?[*:0]u16,
    State: u32,
};

extern "wtsapi32" fn WTSEnumerateSessionsW(
    hServer: ?*anyopaque,
    Reserved: u32,
    Version: u32,
    ppSessionInfo: *?[*]WTS_SESSION_INFOW,
    pCount: *u32,
) callconv(.c) i32;

extern "wtsapi32" fn WTSFreeMemory(pMemory: ?*anyopaque) callconv(.c) void;

fn collectWindows(alloc: std.mem.Allocator) ![]u8 {
    var sessions_ptr: ?[*]WTS_SESSION_INFOW = null;
    var count: u32 = 0;
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions_ptr, &count) == 0) {
        return error.SessionEnumerationFailed;
    }
    defer WTSFreeMemory(@ptrCast(sessions_ptr));

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;

    try w.writeAll("{\"source\":\"wts\",\"sessions\":[");
    var first = true;
    const bounded_count = @min(count, @as(u32, @intCast(max_sessions)));
    const sessions = sessions_ptr.?[0..bounded_count];
    for (sessions) |session| {
        if (session.State != WTSActive) continue;
        if (!first) try w.writeByte(',');
        first = false;

        const name = if (session.pWinStationName) |wide|
            try std.unicode.utf16LeToUtf8Alloc(alloc, std.mem.sliceTo(wide, 0))
        else
            try alloc.dupe(u8, "");
        defer alloc.free(name);

        try w.print("{{\"session_id\":{d},\"station\":", .{session.SessionId});
        try std.json.Stringify.value(name, .{}, w);
        try w.writeByte('}');
    }
    try w.writeAll("]}");

    return out.toOwnedSlice();
}

fn termSucceeded(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

test "users collector module loads" {
    _ = collect;
}
