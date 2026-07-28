const std = @import("std");
const builtin = @import("builtin");

const Config = @import("config.zig").Config;
const iox = @import("io_compat.zig");

extern "kernel32" fn GetComputerNameA(
    name: [*]u8,
    size: *u32,
) callconv(.c) i32;

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

fn base64Encode(alloc: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const Encoder = std.base64.standard.Encoder;
    const len = Encoder.calcSize(bytes.len);
    const out = try alloc.alloc(u8, len);
    _ = Encoder.encode(out, bytes);
    return out;
}

/// Generate Ed25519 keypair, persist seed next to state, return base64 public key.
fn ensureDeviceKey(alloc: std.mem.Allocator, cfg: *const Config) ![]u8 {
    const seed_path = try std.fmt.allocPrint(alloc, "{s}.devicekey", .{cfg.state_path});
    defer alloc.free(seed_path);

    var seed: [std.crypto.sign.Ed25519.KeyPair.seed_length]u8 = undefined;
    const io = iox.current();
    const existing = std.Io.Dir.cwd().openFile(io, seed_path, .{}) catch null;
    if (existing) |file| {
        defer file.close(io);
        const n = try file.readPositionalAll(io, &seed, 0);
        if (n != seed.len) return error.CorruptDeviceKey;
    } else {
        try std.Io.randomSecure(io, &seed);
        var file = try std.Io.Dir.cwd().createFile(io, seed_path, .{
            .truncate = true,
            .permissions = if (builtin.os.tag == .windows) .default_file else @enumFromInt(0o600),
        });
        defer file.close(io);
        try file.writePositionalAll(io, &seed, 0);
        try file.sync(io);
    }

    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    return try base64Encode(alloc, &kp.public_key.bytes);
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
        .linux => "linux",
        else => "unknown",
    };

    const device_pub = ensureDeviceKey(alloc, cfg) catch |err| blk: {
        // Enrollment still works without a device key on constrained platforms.
        std.log.warn("device key unavailable ({s}); enrolling without device_public_key", .{@errorName(err)});
        break :blk null;
    };
    defer if (device_pub) |p| alloc.free(p);

    var body_buf = std.array_list.Managed(u8).init(alloc);
    defer body_buf.deinit();
    if (device_pub) |pk| {
        try body_buf.print(
            \\{{"enrollment_token":"{s}","hostname":"{s}","os":"{s}","os_version":"unknown","arch":"{s}","agent_version":"{s}","device_public_key":"{s}"}}
        ,
            .{ token, hostname, os_str, arch_str, agent_version, pk },
        );
    } else {
        try body_buf.print(
            \\{{"enrollment_token":"{s}","hostname":"{s}","os":"{s}","os_version":"unknown","arch":"{s}","agent_version":"{s}"}}
        ,
            .{ token, hostname, os_str, arch_str, agent_version },
        );
    }

    const url = try std.fmt.allocPrint(alloc, "{s}/api/agents/enroll", .{cfg.backend_url});
    defer alloc.free(url);

    var client = std.http.Client{ .allocator = alloc, .io = iox.current() };
    defer client.deinit();

    var response_body: std.Io.Writer.Allocating = .init(alloc);
    defer response_body.deinit();

    const res = try client.fetch(.{
        .method = .POST,
        .location = .{ .url = url },
        .headers = .{ .content_type = .{ .override = "application/json" } },
        .payload = body_buf.items,
        .response_writer = &response_body.writer,
    });

    if (res.status != .ok) return error.EnrollmentFailed;

    var parsed = try std.json.parseFromSlice(struct {
        agent_id: []const u8,
        jwt: []const u8,
        jwt_expires_at: []const u8,
    }, alloc, response_body.written(), .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    cfg.agent_id = try alloc.dupe(u8, parsed.value.agent_id);
    cfg.agent_jwt = try alloc.dupe(u8, parsed.value.jwt);

    // Burn the enrollment token so it can't be reused from the on-disk config.
    if (cfg.enrollment_token) |t| {
        alloc.free(t);
        cfg.enrollment_token = null;
    }
}
