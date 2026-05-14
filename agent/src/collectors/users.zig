const std = @import("std");
const builtin = @import("builtin");

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
    var out = std.ArrayList(u8).init(alloc);
    errdefer out.deinit();
    var w = out.writer();

    try w.writeAll("{\"source\":\"utmpx\",\"sessions\":[");
    c.setutxent();
    defer c.endutxent();

    var first = true;
    while (c.getutxent()) |entry| {
        const session = entry.*;
        if (session.ut_type != c.USER_PROCESS) continue;
        if (!first) try w.writeByte(',');
        first = false;

        try w.writeAll("{\"user\":");
        try std.json.stringify(std.mem.sliceTo(&session.ut_user, 0), .{}, w);
        try w.writeAll(",\"line\":");
        try std.json.stringify(std.mem.sliceTo(&session.ut_line, 0), .{}, w);
        try w.print(",\"pid\":{d}}}", .{session.ut_pid});
    }
    try w.writeAll("]}");

    return out.toOwnedSlice();
}

fn collectLinux(alloc: std.mem.Allocator) ![]u8 {
    const result = std.process.Child.run(.{
        .allocator = alloc,
        .argv = &.{ "who" },
        .max_output_bytes = 128 * 1024,
    }) catch {
        return alloc.dupe(u8, "{\"source\":\"who\",\"sessions\":[]}");
    };
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    var out = std.ArrayList(u8).init(alloc);
    errdefer out.deinit();
    var w = out.writer();

    try w.writeAll("{\"source\":\"who\",\"sessions\":[");
    var first = true;
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        const user = fields.next() orelse continue;
        const tty = fields.next() orelse "";
        if (!first) try w.writeByte(',');
        first = false;
        try w.writeAll("{\"user\":");
        try std.json.stringify(user, .{}, w);
        try w.writeAll(",\"line\":");
        try std.json.stringify(tty, .{}, w);
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
) callconv(.C) i32;

extern "wtsapi32" fn WTSFreeMemory(pMemory: ?*anyopaque) callconv(.C) void;

fn collectWindows(alloc: std.mem.Allocator) ![]u8 {
    var sessions_ptr: ?[*]WTS_SESSION_INFOW = null;
    var count: u32 = 0;
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions_ptr, &count) == 0) {
        return error.SessionEnumerationFailed;
    }
    defer WTSFreeMemory(@ptrCast(sessions_ptr));

    var out = std.ArrayList(u8).init(alloc);
    errdefer out.deinit();
    var w = out.writer();

    try w.writeAll("{\"source\":\"wts\",\"sessions\":[");
    var first = true;
    const sessions = sessions_ptr.?[0..count];
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
        try std.json.stringify(name, .{}, w);
        try w.writeByte('}');
    }
    try w.writeAll("]}");

    return out.toOwnedSlice();
}

test "users collector module loads" {
    _ = collect;
}
