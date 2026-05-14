const std = @import("std");
const builtin = @import("builtin");
const transport = @import("transport/http.zig");

pub fn execute(
    alloc: std.mem.Allocator,
    http: *transport.Client,
    action: transport.ResponseAction,
) !void {
    if (std.mem.eql(u8, action.action_type, "kill_process")) {
        executeKillProcess(alloc, http, action) catch |err| {
            try report(http, action.id, "failed", @errorName(err));
        };
        return;
    }

    if (std.mem.eql(u8, action.action_type, "isolate_host")) {
        try report(http, action.id, "failed", "isolate_host is not implemented by this agent build");
        return;
    }

    try report(http, action.id, "failed", "unknown response action");
}

fn executeKillProcess(
    alloc: std.mem.Allocator,
    http: *transport.Client,
    action: transport.ResponseAction,
) !void {
    const parsed = try std.json.parseFromSlice(struct {
        pid: i32,
    }, alloc, action.payload, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    if (parsed.value.pid <= 0) return error.InvalidPid;

    switch (builtin.os.tag) {
        .windows => return error.UnsupportedPlatform,
        else => try std.posix.kill(parsed.value.pid, std.posix.SIG.TERM),
    }

    try report(http, action.id, "succeeded", "process termination signal sent");
}

fn report(http: *transport.Client, action_id: []const u8, status: []const u8, message: []const u8) !void {
    try http.reportActionResult(action_id, status, message);
}
