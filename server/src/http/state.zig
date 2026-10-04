const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const rsa_pem = @import("../crypto/rsa_pem.zig");

/// Set by the connection handler before `app.handle` when peer address is known.
pub var peer_ip: []const u8 = "127.0.0.1";

pub var agent_kp: ?Ed25519.KeyPair = null;

const RateBucket = struct {
    window_start: i64,
    count: u32,
};

var enroll_rates: std.StringHashMap(RateBucket) = undefined;
var enroll_rates_init = false;

pub fn ensureAgentKey(io: std.Io) !Ed25519.KeyPair {
    if (agent_kp) |kp| return kp;
    var seed: [32]u8 = undefined;
    if (std.c.getenv("TAWNY_AGENT_JWT_SEED")) |hex_z| {
        const hex = std.mem.span(hex_z);
        if (hex.len == 64) {
            _ = std.fmt.hexToBytes(&seed, hex) catch {
                io.random(&seed);
            };
        } else {
            io.random(&seed);
        }
    } else {
        // Deterministic dev default so restarts keep verifying issued tokens.
        @memset(&seed, 0x71);
        const label = "tawny-agent-jwt-dev";
        @memcpy(seed[0..label.len], label);
    }
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    agent_kp = kp;
    return kp;
}

var rs256_n: ?[]u8 = null;
var rs256_e: ?[]u8 = null;
var rs256_checked = false;

pub fn rs256Public(allocator: std.mem.Allocator, io: std.Io) ?struct { n: []const u8, e: []const u8 } {
    if (!rs256_checked) {
        rs256_checked = true;
        const loaded = rsa_pem.loadConfigured(allocator, io) catch |err| blk: {
            std.debug.print("rs256 key load failed: {s}\n", .{@errorName(err)});
            break :blk null;
        };
        if (loaded) |key| {
            rs256_n = key.n;
            rs256_e = key.e;
            std.debug.print("rs256 public key loaded n={d}\n", .{key.n.len});
        }
    }
    const n = rs256_n orelse return null;
    const e = rs256_e orelse return null;
    return .{ .n = n, .e = e };
}

var policy_rates: std.StringHashMap(RateBucket) = undefined;
var policy_rates_init = false;

/// Fixed one-minute window. Returns true when this hit exceeds `limit`.
/// `policy` and `key` match the .NET partition (agent id, tenant:agent, or tenant:user).
pub fn tooMany(io: std.Io, policy: []const u8, key: []const u8, limit: u32) bool {
    if (!policy_rates_init) {
        policy_rates = std.StringHashMap(RateBucket).init(std.heap.page_allocator);
        policy_rates_init = true;
    }
    const now = @as(i64, @intCast(std.Io.Clock.now(.real, io).toSeconds()));
    const map_key = std.fmt.allocPrint(std.heap.page_allocator, "{s}\x00{s}", .{ policy, key }) catch return false;
    const gop = policy_rates.getOrPut(map_key) catch {
        std.heap.page_allocator.free(map_key);
        return false;
    };
    if (!gop.found_existing) {
        gop.value_ptr.* = .{ .window_start = now, .count = 1 };
        return false;
    }
    std.heap.page_allocator.free(map_key);
    if (now - gop.value_ptr.window_start >= 60) {
        gop.value_ptr.* = .{ .window_start = now, .count = 1 };
        return false;
    }
    gop.value_ptr.count += 1;
    return gop.value_ptr.count > limit;
}

pub fn enrollRateLimited(io: std.Io, ip: []const u8) bool {
    if (!enroll_rates_init) {
        enroll_rates = std.StringHashMap(RateBucket).init(std.heap.page_allocator);
        enroll_rates_init = true;
    }
    const now = @as(i64, @intCast(std.Io.Clock.now(.real, io).toSeconds()));
    const gop = enroll_rates.getOrPut(ip) catch return false;
    if (!gop.found_existing) {
        gop.key_ptr.* = std.heap.page_allocator.dupe(u8, ip) catch ip;
        gop.value_ptr.* = .{ .window_start = now, .count = 1 };
        return false;
    }
    if (now - gop.value_ptr.window_start >= 60) {
        gop.value_ptr.* = .{ .window_start = now, .count = 1 };
        return false;
    }
    gop.value_ptr.count += 1;
    return gop.value_ptr.count > 10;
}

test "principal and agent-events partitions do not collapse" {
    const tenant = "00000000-0000-0000-0000-000000000001";
    const other = "11111111-1111-4111-8111-111111111111";
    const user_a = tenant ++ ":user-a";
    const user_b = tenant ++ ":user-b";
    const other_user = other ++ ":user-a";
    try std.testing.expect(!std.mem.eql(u8, user_a, user_b));
    try std.testing.expect(!std.mem.eql(u8, user_a, other_user));

    const agent = "22222222-2222-4222-8222-222222222222";
    const events = tenant ++ ":" ++ agent;
    try std.testing.expect(std.mem.startsWith(u8, events, tenant));
    try std.testing.expect(std.mem.indexOf(u8, events, agent) != null);

    const io = std.testing.io;
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        try std.testing.expect(!tooMany(io, "test-web-read", user_a, 3));
    }
    try std.testing.expect(tooMany(io, "test-web-read", user_a, 3));
    try std.testing.expect(!tooMany(io, "test-web-read", other_user, 3));
    try std.testing.expect(!tooMany(io, "test-web-read", user_b, 3));
    try std.testing.expect(!tooMany(io, "test-web-mutate", user_a, 3));
    try std.testing.expect(!tooMany(io, "test-web-admin-mutate", user_a, 1));
    try std.testing.expect(tooMany(io, "test-web-admin-mutate", user_a, 1));
    try std.testing.expect(!tooMany(io, "test-rule-imports", user_a, 1));
    try std.testing.expect(!tooMany(io, "test-hunts", user_a, 1));
    try std.testing.expect(!tooMany(io, "test-search", user_a, 1));
}
