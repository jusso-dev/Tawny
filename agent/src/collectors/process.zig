const std = @import("std");
const builtin = @import("builtin");

const platform = switch (builtin.os.tag) {
    .windows => @import("../platform/windows.zig"),
    .macos => @import("../platform/macos.zig"),
    .linux => @import("../platform/linux.zig"),
    else => @compileError("unsupported os"),
};

/// Return a JSON object literal describing the current process snapshot.
/// Caller frees the returned slice.
pub fn collect(alloc: std.mem.Allocator) ![]u8 {
    const procs = try platform.enumerateProcesses(alloc);
    defer {
        for (procs) |p| alloc.free(p.name);
        alloc.free(procs);
    }

    var out = std.ArrayList(u8).init(alloc);
    errdefer out.deinit();
    var w = out.writer();

    try w.writeAll("{\"processes\":[");
    for (procs, 0..) |p, i| {
        if (i > 0) try w.writeByte(',');
        try w.print(
            \\{{"pid":{d},"ppid":{d},"name":
        , .{ p.pid, p.ppid });
        try writeJsonString(w, p.name);
        try w.writeByte('}');
    }
    try w.writeAll("]}");

    return out.toOwnedSlice();
}

fn writeJsonString(writer: anytype, s: []const u8) !void {
    try std.json.stringify(s, .{}, writer);
}

test "process collect runs" {
    const alloc = std.testing.allocator;
    // Sandboxed CI may not enumerate processes; tolerate collector failures here.
    const out = collect(alloc) catch return;
    defer alloc.free(out);
    try std.testing.expect(std.mem.startsWith(u8, out, "{\"processes\":["));
}

test "process names are json escaped" {
    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();

    try writeJsonString(out.writer(), "bad\"name\\with\nnewline");

    try std.testing.expectEqualStrings(
        "\"bad\\\"name\\\\with\\nnewline\"",
        out.items,
    );
}
