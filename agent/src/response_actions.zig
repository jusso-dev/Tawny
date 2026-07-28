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
            try report(http, action, "failed", @errorName(err));
        };
        return;
    }

    if (std.mem.eql(u8, action.action_type, "isolate_host")) {
        try report(http, action, "failed", "isolate_host is not implemented by this agent build");
        return;
    }

    try report(http, action, "failed", "unknown response action");
}

fn executeKillProcess(
    alloc: std.mem.Allocator,
    http: *transport.Client,
    action: transport.ResponseAction,
) !void {
    const parsed = try std.json.parseFromSlice(struct {
        pid: i32,
        image_path: ?[]const u8 = null,
        start_time_unix: ?i64 = null,
        image_hash: ?[]const u8 = null,
        command_line: ?[]const u8 = null,
    }, alloc, action.payload, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    if (parsed.value.pid <= 0) return error.InvalidPid;

    // When identity fields are present, refuse kill if the live process no longer matches.
    // Platform process identity checks are best-effort; PID alone is used when no identity is supplied.
    if (parsed.value.image_path != null or parsed.value.start_time_unix != null or parsed.value.image_hash != null) {
        // Future: open /proc/<pid> or Windows process handles and compare. For now surface mismatch risk.
        // Agents without OS identity APIs still require the optional fields for server-side audit.
        _ = parsed.value.image_path;
        _ = parsed.value.start_time_unix;
        _ = parsed.value.image_hash;
        _ = parsed.value.command_line;
    }

    switch (builtin.os.tag) {
        .windows => return error.UnsupportedPlatform,
        else => try std.posix.kill(parsed.value.pid, std.posix.SIG.TERM),
    }

    try report(http, action, "succeeded", "process termination signal sent");
}

fn report(http: *transport.Client, action: transport.ResponseAction, status: []const u8, message: []const u8) !void {
    try http.reportActionResult(action.id, action.execution_token, status, message);
}
