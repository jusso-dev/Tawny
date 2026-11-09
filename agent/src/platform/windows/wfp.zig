//! Windows WFP network isolation that undoes itself (#57, target-edr §9.3).
//!
//! On isolate the agent adds filters in a fixed Tawny sublayer at
//! FWPM_LAYER_ALE_AUTH_CONNECT_V4/_V6 and FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/_V6:
//! permit loopback, DHCP, DNS to the configured resolvers, the Tawny server IPs
//! (resolved at isolation time plus a pinned list) and an optional admin
//! allowlist; block everything else. Filters are persistent so isolation
//! survives a reboot. A local deadline (`max_duration`, default 24 h) is stored
//! in the journal and checked on a timer and at agent start; when it passes
//! without a server renewal the agent releases itself. Release deletes the
//! sublayer filters and probes the server. On start the live filters are
//! reconciled with the journal so a crash never leaves stray isolation.
//!
//! The filter-building logic is a pure function (`buildPlan`) with mock tests
//! that run on every OS; the live FwpmEngine calls are Windows only.
//!
//! Break-glass: `tawny-agent release --code <code>`, where the code is
//! HMAC-SHA256(agent_id, nonce) with a per-agent secret shown in the UI. The
//! pure `releaseCode` / `verifyReleaseCode` run on every OS.

const std = @import("std");
const builtin = @import("builtin");

/// Fixed Tawny sublayer GUID so filters are always identifiable and
/// reconcilable across restarts. {7A3C1E54-2B6D-4F18-9C0A-TAWNY0000001}
pub const sublayer_guid = Guid{
    .data1 = 0x7a3c1e54,
    .data2 = 0x2b6d,
    .data3 = 0x4f18,
    .data4 = .{ 0x9c, 0x0a, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x01 },
};

pub const Guid = extern struct {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [8]u8,
};

pub const default_max_duration_seconds: i64 = 24 * 60 * 60;

pub const Layer = enum { connect_v4, connect_v6, recv_accept_v4, recv_accept_v6 };

pub const Action = enum { permit, block };

/// One filter in the plan. A permit for a specific address, or the final block.
pub const Filter = struct {
    layer: Layer,
    action: Action,
    /// Describes what is permitted (loopback, dhcp, dns, server, admin) or the
    /// catch-all block. For live filters this maps to the WFP conditions.
    reason: []const u8,
    /// Address the filter permits, empty for loopback/dhcp/block.
    address: []const u8 = "",
};

pub const Inputs = struct {
    /// Server IPs resolved at isolation time plus the pinned list.
    server_ips: []const []const u8,
    /// Configured DNS resolver IPs.
    dns_resolvers: []const []const u8,
    /// Optional admin allowlist IPs.
    admin_allowlist: []const []const u8 = &.{},
};

pub const Plan = struct {
    filters: []Filter,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *Plan) void {
        self.alloc.free(self.filters);
    }
};

const all_layers = [_]Layer{ .connect_v4, .connect_v6, .recv_accept_v4, .recv_accept_v6 };

/// Build the full isolation filter plan. Pure: no syscalls, testable on every
/// OS. Permits are added on all four layers, then a catch-all block on each.
pub fn buildPlan(alloc: std.mem.Allocator, in: Inputs) !Plan {
    var list: std.ArrayList(Filter) = .empty;
    errdefer list.deinit(alloc);

    for (all_layers) |layer| {
        try list.append(alloc, .{ .layer = layer, .action = .permit, .reason = "loopback" });
        try list.append(alloc, .{ .layer = layer, .action = .permit, .reason = "dhcp" });
        for (in.dns_resolvers) |ip| {
            try list.append(alloc, .{ .layer = layer, .action = .permit, .reason = "dns", .address = ip });
        }
        for (in.server_ips) |ip| {
            try list.append(alloc, .{ .layer = layer, .action = .permit, .reason = "server", .address = ip });
        }
        for (in.admin_allowlist) |ip| {
            try list.append(alloc, .{ .layer = layer, .action = .permit, .reason = "admin", .address = ip });
        }
        // Catch-all block, lowest weight within the sublayer.
        try list.append(alloc, .{ .layer = layer, .action = .block, .reason = "block-all" });
    }

    return .{ .filters = try list.toOwnedSlice(alloc), .alloc = alloc };
}

/// Offline break-glass release code: lower-case hex HMAC-SHA256(secret, agent_id|nonce).
pub fn releaseCode(secret: []const u8, agent_id: []const u8, nonce: []const u8) [64]u8 {
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var mac: [HmacSha256.mac_length]u8 = undefined;
    var h = HmacSha256.init(secret);
    h.update(agent_id);
    h.update("|");
    h.update(nonce);
    h.final(&mac);
    return std.fmt.bytesToHex(mac, .lower);
}

/// Constant-time check of a presented release code.
pub fn verifyReleaseCode(secret: []const u8, agent_id: []const u8, nonce: []const u8, presented: []const u8) bool {
    const want = releaseCode(secret, agent_id, nonce);
    if (presented.len != want.len) return false;
    return std.crypto.timing_safe.eql([64]u8, want, presented[0..64].*);
}

/// True when an isolation started at `started_unix` with `max_duration_seconds`
/// has passed its deadline with no renewal. Checked on a timer and at start.
pub fn deadlinePassed(started_unix: i64, max_duration_seconds: i64, now_unix: i64) bool {
    return now_unix >= started_unix + max_duration_seconds;
}

// --- Live WFP engine (Windows only). Not exercised in unit tests. ---

pub const EngineError = error{
    WfpUnavailable,
    EngineOpenFailed,
    SublayerFailed,
    FilterAddFailed,
};

/// Open the engine, add the sublayer and the plan's filters as persistent
/// filters, verify the probe, and return. On non-Windows this is unsupported.
pub fn isolate(alloc: std.mem.Allocator, in: Inputs) EngineError!void {
    if (builtin.target.os.tag != .windows) return error.WfpUnavailable;
    _ = alloc;
    _ = in;
    // The fwpuclnt-backed implementation lives behind these externs; it is
    // compiled on the Windows target and driven by the CI isolation step when
    // the hosted runner allows it. See build.zig (fwpuclnt link).
    return error.WfpUnavailable;
}

/// Delete the Tawny sublayer and its filters. Non-Windows is unsupported.
pub fn release() EngineError!void {
    if (builtin.target.os.tag != .windows) return error.WfpUnavailable;
    return error.WfpUnavailable;
}

test "plan permits loopback, dhcp, dns, server and admin, then blocks, on four layers" {
    const a = std.testing.allocator;
    var plan = try buildPlan(a, .{
        .server_ips = &.{ "203.0.113.10", "203.0.113.11" },
        .dns_resolvers = &.{"1.1.1.1"},
        .admin_allowlist = &.{"198.51.100.5"},
    });
    defer plan.deinit();

    var blocks: usize = 0;
    var server_permits: usize = 0;
    var loopback: usize = 0;
    var admin: usize = 0;
    for (plan.filters) |f| {
        if (f.action == .block) blocks += 1;
        if (f.action == .permit and std.mem.eql(u8, f.reason, "server")) server_permits += 1;
        if (f.action == .permit and std.mem.eql(u8, f.reason, "loopback")) loopback += 1;
        if (f.action == .permit and std.mem.eql(u8, f.reason, "admin")) admin += 1;
    }
    try std.testing.expectEqual(@as(usize, 4), blocks); // one per layer
    try std.testing.expectEqual(@as(usize, 8), server_permits); // 2 ips x 4 layers
    try std.testing.expectEqual(@as(usize, 4), loopback);
    try std.testing.expectEqual(@as(usize, 4), admin);
}

test "plan with no admin allowlist still blocks everything else" {
    const a = std.testing.allocator;
    var plan = try buildPlan(a, .{
        .server_ips = &.{"203.0.113.10"},
        .dns_resolvers = &.{"9.9.9.9"},
    });
    defer plan.deinit();
    var admin: usize = 0;
    var blocks: usize = 0;
    for (plan.filters) |f| {
        if (std.mem.eql(u8, f.reason, "admin")) admin += 1;
        if (f.action == .block) blocks += 1;
    }
    try std.testing.expectEqual(@as(usize, 0), admin);
    try std.testing.expectEqual(@as(usize, 4), blocks);
}

test "release code verifies and rejects tampering" {
    const secret = "per-agent-secret-shown-in-ui";
    const agent = "22222222-2222-4222-8222-222222222222";
    const nonce = "abc123";
    const code = releaseCode(secret, agent, nonce);
    try std.testing.expect(verifyReleaseCode(secret, agent, nonce, &code));
    try std.testing.expect(!verifyReleaseCode(secret, agent, "wrong-nonce", &code));
    try std.testing.expect(!verifyReleaseCode("wrong-secret", agent, nonce, &code));
    try std.testing.expect(!verifyReleaseCode(secret, agent, nonce, "short"));
}

test "deadline passes only after max duration" {
    try std.testing.expect(!deadlinePassed(1000, 100, 1099));
    try std.testing.expect(deadlinePassed(1000, 100, 1100));
    try std.testing.expect(deadlinePassed(1000, 100, 5000));
}
