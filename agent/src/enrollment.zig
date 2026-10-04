const std = @import("std");
const builtin = @import("builtin");

const Config = @import("config.zig").Config;
const iox = @import("io_compat.zig");

extern "kernel32" fn GetComputerNameA(
    name: [*]u8,
    size: *u32,
) callconv(.c) i32;

fn getHostname(buf: []u8) ![]const u8 {
    if (builtin.target.os.tag == .windows) {
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
    const seed_path = try alloc.print("{s}.devicekey", .{cfg.state_path});
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
            .permissions = if (builtin.target.os.tag == .windows) .default_file else @fromBackingInt(@intCast(0o600)),
        });
        defer file.close(io);
        try file.writePositionalAll(io, &seed, 0);
        try file.sync(io);
    }

    const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    return try base64Encode(alloc, &kp.public_key.bytes);
}

pub const EnrollRequest = struct {
    enrollment_token: []const u8,
    hostname: []const u8,
    os: []const u8,
    os_version: []const u8 = "unknown",
    arch: []const u8,
    agent_version: []const u8,
    device_public_key: ?[]const u8 = null,
};

/// Serialize the enrollment request with proper JSON string escaping. Fields
/// that are not valid UTF-8 (e.g. an ANSI-codepage hostname) are made ASCII-safe
/// first so they serialize as strings rather than byte arrays.
pub fn buildEnrollBody(alloc: std.mem.Allocator, req: EnrollRequest) ![]u8 {
    var hostname_buf: [256]u8 = undefined;
    var safe = req;
    safe.hostname = asciiFallback(req.hostname, &hostname_buf);
    return std.json.Stringify.valueAlloc(alloc, safe, .{ .emit_null_optional_fields = false });
}

fn asciiFallback(value: []const u8, buf: []u8) []const u8 {
    if (std.unicode.utf8ValidateSlice(value)) return value;
    const n = @min(value.len, buf.len);
    for (value[0..n], buf[0..n]) |byte, *dst| dst.* = if (byte < 0x80) byte else '?';
    return buf[0..n];
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
    const os_str = switch (builtin.target.os.tag) {
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

    const body = try buildEnrollBody(alloc, .{
        .enrollment_token = token,
        .hostname = hostname,
        .os = os_str,
        .arch = arch_str,
        .agent_version = agent_version,
        .device_public_key = device_pub,
    });
    defer alloc.free(body);

    const url = try alloc.print("{s}/api/agents/enroll", .{cfg.backend_url});
    defer alloc.free(url);

    var client = std.http.Client{ .allocator = alloc, .io = iox.current() };
    defer client.deinit();

    var response_body: std.Io.Writer.Allocating = .init(alloc);
    defer response_body.deinit();

    const res = try client.fetch(.{
        .method = .POST,
        .location = .{ .url = url },
        .headers = .{ .content_type = .{ .override = "application/json" } },
        .payload = body,
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

    // Drop the single-use token from memory; main scrubs it from config.toml.
    if (cfg.enrollment_token) |t| {
        alloc.free(t);
        cfg.enrollment_token = null;
    }
}

test "enroll body escapes quotes, backslashes and control characters" {
    const alloc = std.testing.allocator;
    const body = try buildEnrollBody(alloc, .{
        .enrollment_token = "tok\"en\\x",
        .hostname = "host\n\x01name",
        .os = "linux",
        .arch = "x64",
        .agent_version = "0.1.0\"}",
    });
    defer alloc.free(body);
    try std.testing.expectEqualStrings(
        "{\"enrollment_token\":\"tok\\\"en\\\\x\",\"hostname\":\"host\\n\\u0001name\",\"os\":\"linux\",\"os_version\":\"unknown\",\"arch\":\"x64\",\"agent_version\":\"0.1.0\\\"}\"}",
        body,
    );
    // Round-trips through a JSON parser with the original values intact.
    const parsed = try std.json.parseFromSlice(EnrollRequest, alloc, body, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("tok\"en\\x", parsed.value.enrollment_token);
    try std.testing.expectEqualStrings("host\n\x01name", parsed.value.hostname);
    try std.testing.expect(parsed.value.device_public_key == null);
}

test "enroll body includes device key and sanitizes non-UTF-8 hostname" {
    const alloc = std.testing.allocator;
    const body = try buildEnrollBody(alloc, .{
        .enrollment_token = "t",
        .hostname = "caf\xe9",
        .os = "windows",
        .arch = "x64",
        .agent_version = "0.1.0",
        .device_public_key = "AAAA+/==",
    });
    defer alloc.free(body);
    const parsed = try std.json.parseFromSlice(EnrollRequest, alloc, body, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("caf?", parsed.value.hostname);
    try std.testing.expectEqualStrings("AAAA+/==", parsed.value.device_public_key.?);
}
