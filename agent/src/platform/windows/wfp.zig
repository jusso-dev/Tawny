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

const iox = @import("../../io_compat.zig");

/// Persisted isolation state, so the agent can reconcile filters and enforce
/// the deadline across restarts. Stored at `<state_path>.wfp`.
pub const State = struct {
    isolated: bool = false,
    started_unix: i64 = 0,
    max_duration_seconds: i64 = default_max_duration_seconds,
    nonce: []const u8 = "",
    server_ips: []const []const u8 = &.{},
    dns_resolvers: []const []const u8 = &.{},
    admin_allowlist: []const []const u8 = &.{},
};

fn statePath(alloc: std.mem.Allocator, state_path: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, "{s}.wfp", .{state_path});
}

pub fn saveState(alloc: std.mem.Allocator, state_path: []const u8, s: State) !void {
    const p = try statePath(alloc, state_path);
    defer alloc.free(p);
    const body = try std.json.Stringify.valueAlloc(alloc, s, .{});
    defer alloc.free(body);
    const io = iox.current();
    if (std.fs.path.dirname(p)) |d| std.Io.Dir.cwd().createDirPath(io, d) catch {};
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = body });
}

/// Load the state. Caller calls `.deinit()` on the result. Returns null when
/// there is no state file.
pub fn loadState(alloc: std.mem.Allocator, state_path: []const u8) ?std.json.Parsed(State) {
    const p = statePath(alloc, state_path) catch return null;
    defer alloc.free(p);
    const io = iox.current();
    const raw = std.Io.Dir.cwd().readFileAlloc(io, p, alloc, .limited(64 * 1024)) catch return null;
    defer alloc.free(raw);
    // alloc_always so the parsed strings own their memory and survive freeing raw.
    return std.json.parseFromSlice(State, alloc, raw, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch null;
}

pub fn clearState(alloc: std.mem.Allocator, state_path: []const u8) void {
    const p = statePath(alloc, state_path) catch return;
    defer alloc.free(p);
    std.Io.Dir.cwd().deleteFile(iox.current(), p) catch {};
}

/// Parse a dotted IPv4 address to a host-order u32 (WFP wants host order in
/// FWP_V4_ADDR_AND_MASK). Pure, tested on every OS. Returns null on junk.
pub fn parseIpv4(text: []const u8) ?u32 {
    var out: u32 = 0;
    var octet: u32 = 0;
    var digits: u8 = 0;
    var parts: u8 = 0;
    for (text) |c| {
        if (c == '.') {
            if (digits == 0 or octet > 255) return null;
            out = (out << 8) | octet;
            octet = 0;
            digits = 0;
            parts += 1;
            if (parts > 3) return null;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
            digits += 1;
            if (digits > 3) return null;
        } else return null;
    }
    if (parts != 3 or digits == 0 or octet > 255) return null;
    return (out << 8) | octet;
}

test "parseIpv4 accepts valid addresses and refuses junk" {
    try std.testing.expectEqual(@as(?u32, 0xC0000201), parseIpv4("192.0.2.1"));
    try std.testing.expectEqual(@as(?u32, 0x7F000001), parseIpv4("127.0.0.1"));
    try std.testing.expectEqual(@as(?u32, 0), parseIpv4("0.0.0.0"));
    try std.testing.expectEqual(@as(?u32, 0xFFFFFFFF), parseIpv4("255.255.255.255"));
    try std.testing.expect(parseIpv4("256.0.0.1") == null);
    try std.testing.expect(parseIpv4("1.2.3") == null);
    try std.testing.expect(parseIpv4("1.2.3.4.5") == null);
    try std.testing.expect(parseIpv4("a.b.c.d") == null);
    try std.testing.expect(parseIpv4("") == null);
}

// --- Live WFP engine (Windows only). Compiled on the Windows target and
// driven by the CI self-test; not exercised in the cross-OS unit tests. ---

pub const EngineError = error{
    WfpUnavailable,
    EngineOpenFailed,
    TransactionFailed,
    SublayerFailed,
    FilterAddFailed,
    EnumFailed,
    BadAddress,
    OutOfMemory,
};

/// Probe results after isolating: whether the server stayed reachable and
/// whether a blocked address became unreachable.
pub const Probe = struct {
    server_reachable: bool,
    blocked_unreachable: bool,
};

/// Open the engine and add the isolation filters as persistent filters in the
/// Tawny sublayer. Everything not permitted by the plan is blocked. Non-Windows
/// is unsupported.
pub fn isolate(alloc: std.mem.Allocator, in: Inputs) EngineError!void {
    return switch (builtin.target.os.tag) {
        .windows => win.isolate(alloc, in),
        else => error.WfpUnavailable,
    };
}

/// Delete the Tawny sublayer, its filters and the provider.
pub fn release() EngineError!void {
    return switch (builtin.target.os.tag) {
        .windows => win.release(),
        else => error.WfpUnavailable,
    };
}

/// Count the filters currently in the Tawny sublayer. Used by reconcile at
/// start and by the CI self-test.
pub fn countFilters() EngineError!usize {
    return switch (builtin.target.os.tag) {
        .windows => win.countFilters(),
        else => error.WfpUnavailable,
    };
}

/// CI self-test only: add a single block filter for one remote IPv4 address
/// (no block-all), so it cannot cut the runner off. Returns the filter id.
pub fn addTestBlock(ipv4: []const u8) EngineError!u64 {
    return switch (builtin.target.os.tag) {
        .windows => win.addTestBlock(ipv4),
        else => error.WfpUnavailable,
    };
}

/// TCP connect probe with a timeout. True when the address accepts a
/// connection. Windows only.
pub fn tcpReachable(ipv4: []const u8, port: u16, timeout_ms: u32) bool {
    return switch (builtin.target.os.tag) {
        .windows => win.tcpReachable(ipv4, port, timeout_ms),
        else => false,
    };
}

const win = if (builtin.target.os.tag == .windows) struct {
    const WINAPI: std.lang.CallingConvention = .winapi;
    const HANDLE = *anyopaque;
    const DWORD = u32;

    // Action types (terminating).
    const FWP_ACTION_FLAG_TERMINATING: u32 = 0x00001000;
    const FWP_ACTION_BLOCK: u32 = 0x00000001 | FWP_ACTION_FLAG_TERMINATING;
    const FWP_ACTION_PERMIT: u32 = 0x00000002 | FWP_ACTION_FLAG_TERMINATING;
    // Data types.
    const FWP_UINT8: u32 = 1;
    const FWP_V4_ADDR_MASK: u32 = 0x100;
    const FWP_V6_ADDR_MASK: u32 = 0x101;
    // Match types.
    const FWP_MATCH_EQUAL: u32 = 0;
    // Filter flags.
    const FWPM_FILTER_FLAG_PERSISTENT: u32 = 0x00000001;
    // Enum type.
    const FWP_FILTER_ENUM_OVERLAPPING: u32 = 1;
    const RPC_C_AUTHN_WINNT: u32 = 0xFFFFFFFF;

    const G = Guid;
    fn g(d1: u32, d2: u16, d3: u16, d4: [8]u8) G {
        return .{ .data1 = d1, .data2 = d2, .data3 = d3, .data4 = d4 };
    }
    const FWPM_LAYER_ALE_AUTH_CONNECT_V4 = g(0xc38d57d1, 0x05a7, 0x4c33, .{ 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82 });
    const FWPM_LAYER_ALE_AUTH_CONNECT_V6 = g(0x4a72393b, 0x319f, 0x44bc, .{ 0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4 });
    const FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 = g(0xe1cd9fe7, 0xf4b5, 0x4273, .{ 0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50 });
    const FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 = g(0xa3b42c97, 0x9f04, 0x4672, .{ 0xb8, 0x7b, 0xca, 0xd7, 0xd3, 0xb2, 0xfa, 0x37 });
    const FWPM_CONDITION_IP_REMOTE_ADDRESS = g(0xb235ae9a, 0x1d64, 0x49b8, .{ 0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45 });
    const FWPM_CONDITION_IP_LOCAL_ADDRESS = g(0xd9ee00de, 0xc1ef, 0x4617, .{ 0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57 });
    // Our own provider key, distinct from the sublayer key.
    const provider_guid = g(0x7a3c1e54, 0x2b6d, 0x4f18, .{ 0x9c, 0x0a, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x02 });

    const FWP_BYTE_BLOB = extern struct { size: u32 = 0, data: ?[*]u8 = null };
    const FWPM_DISPLAY_DATA0 = extern struct { name: ?[*:0]const u16 = null, description: ?[*:0]const u16 = null };
    const FWP_V4_ADDR_AND_MASK = extern struct { addr: u32, mask: u32 };
    const FWP_V6_ADDR_AND_MASK = extern struct { addr: [16]u8, prefixLength: u8 };

    const FWP_VALUE0 = extern struct {
        type: u32 = 0,
        value: extern union { uint8: u8, uint16: u16, uint32: u32, ptr: ?*anyopaque } = .{ .ptr = null },
    };
    const FWP_CONDITION_VALUE0 = extern struct {
        type: u32 = 0,
        value: extern union {
            uint8: u8,
            uint16: u16,
            uint32: u32,
            v4: ?*FWP_V4_ADDR_AND_MASK,
            v6: ?*FWP_V6_ADDR_AND_MASK,
        } = .{ .v4 = null },
    };
    const FWPM_FILTER_CONDITION0 = extern struct {
        fieldKey: G,
        matchType: u32,
        conditionValue: FWP_CONDITION_VALUE0,
    };
    const FWPM_ACTION0 = extern struct { type: u32, filterType: G = std.mem.zeroes(G) };
    const FWPM_PROVIDER0 = extern struct {
        providerKey: G,
        displayData: FWPM_DISPLAY_DATA0,
        flags: u32 = 0,
        providerData: FWP_BYTE_BLOB = .{},
        serviceName: ?[*:0]u16 = null,
    };
    const FWPM_SUBLAYER0 = extern struct {
        subLayerKey: G,
        displayData: FWPM_DISPLAY_DATA0,
        flags: u32 = 0,
        providerKey: ?*G = null,
        providerData: FWP_BYTE_BLOB = .{},
        weight: u16 = 0,
    };
    const FWPM_FILTER0 = extern struct {
        filterKey: G = std.mem.zeroes(G),
        displayData: FWPM_DISPLAY_DATA0 = .{},
        flags: u32 = 0,
        providerKey: ?*G = null,
        providerData: FWP_BYTE_BLOB = .{},
        layerKey: G,
        subLayerKey: G,
        weight: FWP_VALUE0 = .{},
        numFilterConditions: u32 = 0,
        filterCondition: ?[*]const FWPM_FILTER_CONDITION0 = null,
        action: FWPM_ACTION0,
        context: extern union { rawContext: u64, providerContextKey: G } = .{ .rawContext = 0 },
        reserved: ?*G = null,
        filterId: u64 = 0,
        effectiveWeight: FWP_VALUE0 = .{},
    };
    const FWPM_FILTER_ENUM_TEMPLATE0 = extern struct {
        providerKey: ?*G = null,
        layerKey: G,
        enumType: u32,
        flags: u32 = 0,
        providerContextTemplate: ?*anyopaque = null,
        numFilterConditions: u32 = 0,
        filterCondition: ?[*]const FWPM_FILTER_CONDITION0 = null,
        actionMask: u32,
        calloutKey: ?*G = null,
    };

    extern "fwpuclnt" fn FwpmEngineOpen0(serverName: ?[*:0]const u16, authnService: u32, authIdentity: ?*anyopaque, session: ?*anyopaque, engineHandle: *HANDLE) callconv(WINAPI) DWORD;
    extern "fwpuclnt" fn FwpmEngineClose0(engineHandle: HANDLE) callconv(WINAPI) DWORD;
    extern "fwpuclnt" fn FwpmTransactionBegin0(engineHandle: HANDLE, flags: u32) callconv(WINAPI) DWORD;
    extern "fwpuclnt" fn FwpmTransactionCommit0(engineHandle: HANDLE) callconv(WINAPI) DWORD;
    extern "fwpuclnt" fn FwpmTransactionAbort0(engineHandle: HANDLE) callconv(WINAPI) DWORD;
    extern "fwpuclnt" fn FwpmProviderAdd0(engineHandle: HANDLE, provider: *const FWPM_PROVIDER0, sd: ?*anyopaque) callconv(WINAPI) DWORD;
    extern "fwpuclnt" fn FwpmProviderDeleteByKey0(engineHandle: HANDLE, key: *const G) callconv(WINAPI) DWORD;
    extern "fwpuclnt" fn FwpmSubLayerAdd0(engineHandle: HANDLE, subLayer: *const FWPM_SUBLAYER0, sd: ?*anyopaque) callconv(WINAPI) DWORD;
    extern "fwpuclnt" fn FwpmSubLayerDeleteByKey0(engineHandle: HANDLE, key: *const G) callconv(WINAPI) DWORD;
    extern "fwpuclnt" fn FwpmFilterAdd0(engineHandle: HANDLE, filter: *const FWPM_FILTER0, sd: ?*anyopaque, id: ?*u64) callconv(WINAPI) DWORD;
    extern "fwpuclnt" fn FwpmFilterDeleteById0(engineHandle: HANDLE, id: u64) callconv(WINAPI) DWORD;
    extern "fwpuclnt" fn FwpmFilterCreateEnumHandle0(engineHandle: HANDLE, enumTemplate: ?*const FWPM_FILTER_ENUM_TEMPLATE0, enumHandle: *HANDLE) callconv(WINAPI) DWORD;
    extern "fwpuclnt" fn FwpmFilterEnum0(engineHandle: HANDLE, enumHandle: HANDLE, numEntriesRequested: u32, entries: *[*]*FWPM_FILTER0, numEntriesReturned: *u32) callconv(WINAPI) DWORD;
    extern "fwpuclnt" fn FwpmFilterDestroyEnumHandle0(engineHandle: HANDLE, enumHandle: HANDLE) callconv(WINAPI) DWORD;
    extern "fwpuclnt" fn FwpmFreeMemory0(p: *?*anyopaque) callconv(WINAPI) void;

    const layers = [_]G{
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    };

    fn open(engine: *HANDLE) EngineError!void {
        if (FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, null, null, engine) != 0) return error.EngineOpenFailed;
    }

    fn ensureProviderAndSublayer(engine: HANDLE) void {
        var prov = std.mem.zeroes(FWPM_PROVIDER0);
        prov.providerKey = provider_guid;
        prov.displayData = .{ .name = tawny_name, .description = tawny_desc };
        prov.flags = 0x00000001; // FWPM_PROVIDER_FLAG_PERSISTENT
        _ = FwpmProviderAdd0(engine, &prov, null); // ignore "already exists"

        var sub = std.mem.zeroes(FWPM_SUBLAYER0);
        sub.subLayerKey = sublayer_guid;
        sub.displayData = .{ .name = tawny_name, .description = tawny_desc };
        sub.flags = 0x00000001; // FWPM_SUBLAYER_FLAG_PERSISTENT
        sub.providerKey = @constCast(&prov_key);
        sub.weight = 0xFFFF; // high, above the default sublayers
        _ = FwpmSubLayerAdd0(engine, &sub, null); // ignore "already exists"
    }

    var prov_key: G = provider_guid;
    const tawny_name: [*:0]const u16 = std.unicode.utf8ToUtf16LeStringLiteral("Tawny");
    const tawny_desc: [*:0]const u16 = std.unicode.utf8ToUtf16LeStringLiteral("Tawny EDR isolation");

    fn isV6(layer: G) bool {
        return std.meta.eql(layer, FWPM_LAYER_ALE_AUTH_CONNECT_V6) or std.meta.eql(layer, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6);
    }

    fn addPermitAddress(engine: HANDLE, layer: G, ip: u32, weight_val: u8) EngineError!void {
        var mask = FWP_V4_ADDR_AND_MASK{ .addr = ip, .mask = 0xFFFFFFFF };
        var conds = [_]FWPM_FILTER_CONDITION0{.{
            .fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS,
            .matchType = FWP_MATCH_EQUAL,
            .conditionValue = .{ .type = FWP_V4_ADDR_MASK, .value = .{ .v4 = &mask } },
        }};
        try addFilter(engine, layer, FWP_ACTION_PERMIT, weight_val, &conds);
    }

    fn addPermitLoopback(engine: HANDLE, layer: G, weight_val: u8) EngineError!void {
        if (isV6(layer)) {
            var v6addr = std.mem.zeroes([16]u8);
            v6addr[15] = 1;
            var v6 = FWP_V6_ADDR_AND_MASK{ .addr = v6addr, .prefixLength = 128 };
            var conds = [_]FWPM_FILTER_CONDITION0{.{
                .fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS,
                .matchType = FWP_MATCH_EQUAL,
                .conditionValue = .{ .type = FWP_V6_ADDR_MASK, .value = .{ .v6 = &v6 } },
            }};
            try addFilter(engine, layer, FWP_ACTION_PERMIT, weight_val, &conds);
        } else {
            var mask = FWP_V4_ADDR_AND_MASK{ .addr = 0x7F000000, .mask = 0xFF000000 }; // 127.0.0.0/8
            var conds = [_]FWPM_FILTER_CONDITION0{.{
                .fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS,
                .matchType = FWP_MATCH_EQUAL,
                .conditionValue = .{ .type = FWP_V4_ADDR_MASK, .value = .{ .v4 = &mask } },
            }};
            try addFilter(engine, layer, FWP_ACTION_PERMIT, weight_val, &conds);
        }
    }

    fn addBlockAll(engine: HANDLE, layer: G) EngineError!void {
        try addFilter(engine, layer, FWP_ACTION_BLOCK, 0, &[_]FWPM_FILTER_CONDITION0{});
    }

    fn addFilter(engine: HANDLE, layer: G, action: u32, weight_val: u8, conds: []const FWPM_FILTER_CONDITION0) EngineError!void {
        var filter = FWPM_FILTER0{
            .layerKey = layer,
            .subLayerKey = sublayer_guid,
            .action = .{ .type = action },
        };
        filter.providerKey = @constCast(&prov_key);
        filter.displayData = .{ .name = tawny_name, .description = tawny_desc };
        filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
        filter.weight = .{ .type = FWP_UINT8, .value = .{ .uint8 = weight_val } };
        if (conds.len > 0) {
            filter.numFilterConditions = @intCast(conds.len);
            filter.filterCondition = conds.ptr;
        }
        if (FwpmFilterAdd0(engine, &filter, null, null) != 0) return error.FilterAddFailed;
    }

    fn isolate(alloc: std.mem.Allocator, in: Inputs) EngineError!void {
        _ = alloc;
        var engine: HANDLE = undefined;
        try open(&engine);
        defer _ = FwpmEngineClose0(engine);
        if (FwpmTransactionBegin0(engine, 0) != 0) return error.TransactionFailed;
        errdefer _ = FwpmTransactionAbort0(engine);
        ensureProviderAndSublayer(engine);

        for (layers) |layer| {
            try addPermitLoopback(engine, layer, 15);
            if (!isV6(layer)) {
                for (in.server_ips) |s| {
                    const ip = parseIpv4(s) orelse continue;
                    try addPermitAddress(engine, layer, ip, 14);
                }
                for (in.dns_resolvers) |s| {
                    const ip = parseIpv4(s) orelse continue;
                    try addPermitAddress(engine, layer, ip, 13);
                }
                for (in.admin_allowlist) |s| {
                    const ip = parseIpv4(s) orelse continue;
                    try addPermitAddress(engine, layer, ip, 12);
                }
            }
            try addBlockAll(engine, layer);
        }
        if (FwpmTransactionCommit0(engine) != 0) return error.TransactionFailed;
    }

    fn deleteProviderFilters(engine: HANDLE) EngineError!usize {
        var removed: usize = 0;
        for (layers) |layer| {
            var tmpl = FWPM_FILTER_ENUM_TEMPLATE0{
                .layerKey = layer,
                .enumType = FWP_FILTER_ENUM_OVERLAPPING,
                .actionMask = 0xFFFFFFFF,
            };
            tmpl.providerKey = @constCast(&prov_key);
            var enum_h: HANDLE = undefined;
            if (FwpmFilterCreateEnumHandle0(engine, &tmpl, &enum_h) != 0) return error.EnumFailed;
            defer _ = FwpmFilterDestroyEnumHandle0(engine, enum_h);
            while (true) {
                var entries: [*]*FWPM_FILTER0 = undefined;
                var num: u32 = 0;
                if (FwpmFilterEnum0(engine, enum_h, 64, &entries, &num) != 0) return error.EnumFailed;
                if (num == 0) break;
                var i: u32 = 0;
                while (i < num) : (i += 1) {
                    if (std.meta.eql(entries[i].subLayerKey, sublayer_guid)) {
                        if (FwpmFilterDeleteById0(engine, entries[i].filterId) == 0) removed += 1;
                    }
                }
                var mem: ?*anyopaque = @ptrCast(entries);
                FwpmFreeMemory0(&mem);
                if (num < 64) break;
            }
        }
        return removed;
    }

    fn release() EngineError!void {
        var engine: HANDLE = undefined;
        try open(&engine);
        defer _ = FwpmEngineClose0(engine);
        if (FwpmTransactionBegin0(engine, 0) != 0) return error.TransactionFailed;
        errdefer _ = FwpmTransactionAbort0(engine);
        _ = deleteProviderFilters(engine) catch {};
        _ = FwpmSubLayerDeleteByKey0(engine, &sublayer_guid);
        _ = FwpmProviderDeleteByKey0(engine, &provider_guid);
        if (FwpmTransactionCommit0(engine) != 0) return error.TransactionFailed;
    }

    fn countFilters() EngineError!usize {
        var engine: HANDLE = undefined;
        try open(&engine);
        defer _ = FwpmEngineClose0(engine);
        var total: usize = 0;
        for (layers) |layer| {
            var tmpl = FWPM_FILTER_ENUM_TEMPLATE0{
                .layerKey = layer,
                .enumType = FWP_FILTER_ENUM_OVERLAPPING,
                .actionMask = 0xFFFFFFFF,
            };
            tmpl.providerKey = @constCast(&prov_key);
            var enum_h: HANDLE = undefined;
            if (FwpmFilterCreateEnumHandle0(engine, &tmpl, &enum_h) != 0) return error.EnumFailed;
            defer _ = FwpmFilterDestroyEnumHandle0(engine, enum_h);
            var entries: [*]*FWPM_FILTER0 = undefined;
            var num: u32 = 0;
            if (FwpmFilterEnum0(engine, enum_h, 256, &entries, &num) != 0) return error.EnumFailed;
            var i: u32 = 0;
            while (i < num) : (i += 1) {
                if (std.meta.eql(entries[i].subLayerKey, sublayer_guid)) total += 1;
            }
            if (num > 0) {
                var mem: ?*anyopaque = @ptrCast(entries);
                FwpmFreeMemory0(&mem);
            }
        }
        return total;
    }

    fn addTestBlock(ipv4: []const u8) EngineError!u64 {
        const ip = parseIpv4(ipv4) orelse return error.BadAddress;
        var engine: HANDLE = undefined;
        try open(&engine);
        defer _ = FwpmEngineClose0(engine);
        if (FwpmTransactionBegin0(engine, 0) != 0) return error.TransactionFailed;
        errdefer _ = FwpmTransactionAbort0(engine);
        ensureProviderAndSublayer(engine);
        var mask = FWP_V4_ADDR_AND_MASK{ .addr = ip, .mask = 0xFFFFFFFF };
        var conds = [_]FWPM_FILTER_CONDITION0{.{
            .fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS,
            .matchType = FWP_MATCH_EQUAL,
            .conditionValue = .{ .type = FWP_V4_ADDR_MASK, .value = .{ .v4 = &mask } },
        }};
        var filter = FWPM_FILTER0{
            .layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            .subLayerKey = sublayer_guid,
            .action = .{ .type = FWP_ACTION_BLOCK },
        };
        filter.providerKey = @constCast(&prov_key);
        filter.displayData = .{ .name = tawny_name, .description = tawny_desc };
        filter.weight = .{ .type = FWP_UINT8, .value = .{ .uint8 = 15 } };
        filter.numFilterConditions = 1;
        filter.filterCondition = &conds;
        var id: u64 = 0;
        if (FwpmFilterAdd0(engine, &filter, null, &id) != 0) return error.FilterAddFailed;
        if (FwpmTransactionCommit0(engine) != 0) return error.TransactionFailed;
        return id;
    }

    // --- TCP connect probe via ws2_32 (non-blocking + select) ---
    const SOCKET = usize;
    const INVALID_SOCKET: SOCKET = ~@as(usize, 0);
    const AF_INET: i32 = 2;
    const SOCK_STREAM: i32 = 1;
    const IPPROTO_TCP: i32 = 6;
    const FIONBIO: u32 = 0x8004667E;
    const sockaddr_in = extern struct {
        family: i16,
        port: u16,
        addr: u32,
        zero: [8]u8 = std.mem.zeroes([8]u8),
    };
    const timeval = extern struct { tv_sec: i32, tv_usec: i32 };
    const fd_set = extern struct { count: u32, array: [64]SOCKET };
    const WSADATA = extern struct { pad: [512]u8 };

    extern "ws2_32" fn WSAStartup(version: u16, data: *WSADATA) callconv(WINAPI) i32;
    extern "ws2_32" fn WSACleanup() callconv(WINAPI) i32;
    extern "ws2_32" fn socket(af: i32, t: i32, proto: i32) callconv(WINAPI) SOCKET;
    extern "ws2_32" fn closesocket(s: SOCKET) callconv(WINAPI) i32;
    extern "ws2_32" fn ioctlsocket(s: SOCKET, cmd: u32, argp: *u32) callconv(WINAPI) i32;
    extern "ws2_32" fn connect(s: SOCKET, name: *const sockaddr_in, namelen: i32) callconv(WINAPI) i32;
    extern "ws2_32" fn select(nfds: i32, readfds: ?*fd_set, writefds: ?*fd_set, exceptfds: ?*fd_set, timeout: *const timeval) callconv(WINAPI) i32;
    extern "ws2_32" fn htons(v: u16) callconv(WINAPI) u16;

    fn tcpReachable(ipv4: []const u8, port: u16, timeout_ms: u32) bool {
        const ip = parseIpv4(ipv4) orelse return false;
        var wsa: WSADATA = undefined;
        if (WSAStartup(0x0202, &wsa) != 0) return false;
        defer _ = WSACleanup();
        const s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return false;
        defer _ = closesocket(s);
        var nonblock: u32 = 1;
        _ = ioctlsocket(s, FIONBIO, &nonblock);
        // sockaddr_in wants network byte order for addr and port.
        var sa = sockaddr_in{ .family = AF_INET, .port = htons(port), .addr = std.mem.nativeToBig(u32, ip) };
        _ = connect(s, &sa, @sizeOf(sockaddr_in));
        var wset = std.mem.zeroes(fd_set);
        wset.count = 1;
        wset.array[0] = s;
        const tv = timeval{ .tv_sec = @intCast(timeout_ms / 1000), .tv_usec = @intCast((timeout_ms % 1000) * 1000) };
        const r = select(0, null, &wset, null, &tv);
        return r > 0;
    }
} else struct {};

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

test "isolation state round-trips through the state file" {
    const a = std.testing.allocator;
    const io = iox.current();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(dir);
    const state = try std.fs.path.join(a, &.{ dir, "state.toml" });
    defer a.free(state);

    try std.testing.expect(loadState(a, state) == null);
    try saveState(a, state, .{
        .isolated = true,
        .started_unix = 1_700_000_000,
        .max_duration_seconds = 3600,
        .nonce = "abc123",
        .server_ips = &.{ "203.0.113.10", "203.0.113.11" },
        .dns_resolvers = &.{"1.1.1.1"},
    });
    {
        const loaded = loadState(a, state).?;
        defer loaded.deinit();
        try std.testing.expect(loaded.value.isolated);
        try std.testing.expectEqual(@as(i64, 3600), loaded.value.max_duration_seconds);
        try std.testing.expectEqualStrings("abc123", loaded.value.nonce);
        try std.testing.expectEqual(@as(usize, 2), loaded.value.server_ips.len);
    }
    clearState(a, state);
    try std.testing.expect(loadState(a, state) == null);
}
