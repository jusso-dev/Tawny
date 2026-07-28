const std = @import("std");
const builtin = @import("builtin");
const transport = @import("transport/http.zig");
const iox = @import("io_compat.zig");

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

    if (parsed.value.image_path != null or parsed.value.start_time_unix != null) {
        try assertProcessIdentity(alloc, parsed.value.pid, parsed.value.image_path, parsed.value.start_time_unix);
    }

    switch (builtin.os.tag) {
        .windows => return error.UnsupportedPlatform,
        else => try std.posix.kill(parsed.value.pid, std.posix.SIG.TERM),
    }

    try report(http, action, "succeeded", "process termination signal sent");
}

/// Refuse kill when optional identity fields no longer match the live process (PID reuse).
fn assertProcessIdentity(
    alloc: std.mem.Allocator,
    pid: i32,
    expected_path: ?[]const u8,
    expected_start: ?i64,
) !void {
    if (builtin.os.tag != .linux) {
        // Path/start identity checks are Linux /proc-backed for now.
        // When identity was requested on other platforms, fail closed.
        if (expected_path != null or expected_start != null) return error.ProcessIdentityUnavailable;
        return;
    }

    if (expected_path) |want| {
        const actual = try readLinuxProcessImagePath(alloc, pid);
        defer alloc.free(actual);
        if (!pathsMatch(want, actual)) return error.ProcessIdentityMismatch;
    }

    if (expected_start) |want_start| {
        const actual_start = try readLinuxProcessStartUnix(pid);
        if (@abs(actual_start - want_start) > 2) return error.ProcessIdentityMismatch;
    }
}

fn pathsMatch(expected: []const u8, actual: []const u8) bool {
    if (std.mem.eql(u8, expected, actual)) return true;
    const exp_base = std.fs.path.basename(expected);
    const act_base = std.fs.path.basename(actual);
    return std.mem.eql(u8, exp_base, act_base);
}

fn readLinuxProcessImagePath(alloc: std.mem.Allocator, pid: i32) ![]u8 {
    var path_buf: [64]u8 = undefined;
    const link_path = try std.fmt.bufPrint(&path_buf, "/proc/{d}/exe", .{pid});
    var target_buf: [std.fs.max_path_bytes]u8 = undefined;
    // Zig 0.16: use Io.Dir.readLinkAbsolute (std.posix.readlink is not available).
    const n = std.Io.Dir.readLinkAbsolute(iox.current(), link_path, &target_buf) catch
        return error.ProcessIdentityMismatch;
    return try alloc.dupe(u8, target_buf[0..n]);
}

fn readLinuxProcessStartUnix(pid: i32) !i64 {
    var path_buf: [64]u8 = undefined;
    const stat_path = try std.fmt.bufPrint(&path_buf, "/proc/{d}/stat", .{pid});
    const io = iox.current();
    const file = std.Io.Dir.cwd().openFile(io, stat_path, .{}) catch return error.ProcessIdentityMismatch;
    defer file.close(io);
    var buf: [512]u8 = undefined;
    const n = try file.readPositionalAll(io, &buf, 0);
    const start = parseLinuxStatStarttime(buf[0..n]) orelse return error.ProcessIdentityMismatch;
    const boot = try readBtime();
    const hz: i64 = 100;
    return boot + @divTrunc(start, hz);
}

fn parseLinuxStatStarttime(stat: []const u8) ?i64 {
    const rparen = std.mem.lastIndexOfScalar(u8, stat, ')') orelse return null;
    const rest = std.mem.trimStart(u8, stat[rparen + 1 ..], " ");
    var it = std.mem.tokenizeScalar(u8, rest, ' ');
    var i: usize = 0;
    while (it.next()) |tok| : (i += 1) {
        if (i == 19) {
            return std.fmt.parseInt(i64, tok, 10) catch null;
        }
    }
    return null;
}

fn readBtime() !i64 {
    const io = iox.current();
    const file = try std.Io.Dir.cwd().openFile(io, "/proc/stat", .{});
    defer file.close(io);
    const raw = try iox.readToEndAlloc(file, std.heap.page_allocator, 64 * 1024);
    defer std.heap.page_allocator.free(raw);
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "btime ")) {
            return std.fmt.parseInt(i64, std.mem.trim(u8, line["btime ".len..], " \t"), 10) catch return error.ProcessIdentityMismatch;
        }
    }
    return error.ProcessIdentityMismatch;
}

fn report(http: *transport.Client, action: transport.ResponseAction, status: []const u8, message: []const u8) !void {
    try http.reportActionResult(action.id, action.execution_token, status, message);
}
