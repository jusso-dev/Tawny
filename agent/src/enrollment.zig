const std = @import("std");
const builtin = @import("builtin");

const Config = @import("config.zig").Config;

extern "kernel32" fn GetComputerNameA(
    name: [*]u8,
    size: *u32,
) callconv(.C) i32;

fn getHostname(buf: []u8) ![]const u8 {
    if (builtin.os.tag == .windows) {
        var size: u32 = @intCast(buf.len);
        if (GetComputerNameA(buf.ptr, &size) == 0) return error.HostnameFailed;
        return buf[0..size];
    }
    const max = std.posix.HOST_NAME_MAX;
    if (buf.len < max) return error.BufferTooSmall;
    const fixed: *[max]u8 = @ptrCast(buf.ptr);
    return try std.posix.gethostname(fixed);
}

/// POST /api/agents/enroll, populate cfg.agent_id and cfg.agent_jwt.
pub fn run(alloc: std.mem.Allocator, cfg: *Config, agent_version: []const u8) !void {
    const token = cfg.enrollment_token orelse return error.NoEnrollmentToken;

    var hostname_buf: [256]u8 = undefined;
    const hostname = getHostname(&hostname_buf) catch "unknown";

    const arch_str = switch (builtin.target.cpu.arch) {
        .x86_64 => "x64",
        .aarch64 => "arm64",
        else => "unknown",
    };
    const os_str = switch (builtin.os.tag) {
        .windows => "windows",
        .macos => "macos",
        else => "unknown",
    };

    var body_buf = std.ArrayList(u8).init(alloc);
    defer body_buf.deinit();
    var w = body_buf.writer();
    try w.print(
        \\{{"enrollment_token":"{s}","hostname":"{s}","os":"{s}","os_version":"unknown","arch":"{s}","agent_version":"{s}"}}
    ,
        .{ token, hostname, os_str, arch_str, agent_version },
    );

    const url = try std.fmt.allocPrint(alloc, "{s}/api/agents/enroll", .{cfg.backend_url});
    defer alloc.free(url);

    var client = std.http.Client{ .allocator = alloc };
    defer client.deinit();

    var response_body = std.ArrayList(u8).init(alloc);
    defer response_body.deinit();

    const res = try client.fetch(.{
        .method = .POST,
        .location = .{ .url = url },
        .headers = .{ .content_type = .{ .override = "application/json" } },
        .payload = body_buf.items,
        .response_storage = .{ .dynamic = &response_body },
    });

    if (res.status != .ok) return error.EnrollmentFailed;

    var parsed = try std.json.parseFromSlice(struct {
        agent_id: []const u8,
        jwt: []const u8,
        jwt_expires_at: []const u8,
    }, alloc, response_body.items, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    cfg.agent_id = try alloc.dupe(u8, parsed.value.agent_id);
    cfg.agent_jwt = try alloc.dupe(u8, parsed.value.jwt);

    // Burn the enrollment token so it can't be reused from the on-disk config.
    if (cfg.enrollment_token) |t| {
        alloc.free(t);
        cfg.enrollment_token = null;
    }
}
