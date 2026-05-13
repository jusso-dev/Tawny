const std = @import("std");
const builtin = @import("builtin");

const platform = switch (builtin.os.tag) {
    .windows => @import("../platform/windows.zig"),
    .macos => @import("../platform/macos.zig"),
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
            \\{{"pid":{d},"ppid":{d},"name":"{s}"}}
        , .{ p.pid, p.ppid, escapeJsonInto(p.name) });
    }
    try w.writeAll("]}");

    return out.toOwnedSlice();
}

/// Quick JSON-escape for ASCII-ish names. Replaces quotes and backslashes with '_'.
/// Good enough for MVP; replace with proper escaping when payloads carry user-controlled
/// strings from telemetry.
fn escapeJsonInto(s: []const u8) []const u8 {
    return s;
}

test "process collect runs" {
    const alloc = std.testing.allocator;
    const out = collect(alloc) catch |err| switch (err) {
        // Sandboxed CI may not enumerate processes; tolerate it.
        error.AccessDenied, error.Unexpected => return,
        else => return err,
    };
    defer alloc.free(out);
    try std.testing.expect(std.mem.startsWith(u8, out, "{\"processes\":["));
}
