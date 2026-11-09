const std = @import("std");
const buffer_mod = @import("buffer.zig");
const iox = @import("../io_compat.zig");
const keystore = @import("../keystore.zig");
const entity = @import("../entity.zig");

pub const HeartbeatPayload = struct {
    agent_version: []const u8,
    uptime_seconds: i64,
    buffer_depth: usize,
};

/// Clean shutdown notice (#58): a final heartbeat. The server then skips
/// `Agent silent` when the agent goes offline.
pub const ShutdownPayload = struct {
    agent_version: []const u8,
    uptime_seconds: i64,
    buffer_depth: usize,
    shutdown: bool = true,
    shutdown_reason: []const u8,
};

pub const HeartbeatResult = struct {
    rotated_jwt: ?[]u8 = null,
    /// Latest signed YARA rule pack version for this tenant (0: none).
    yara_pack_version: u64 = 0,
    actions: []ResponseAction = &.{},

    /// Server action public key for trust-on-first-use pinning (#57). Base64
    /// Ed25519. Present on heartbeats so agents enrolled before #57 pin it.
    action_public_key: ?[]u8 = null,

    pub fn deinit(self: *HeartbeatResult, alloc: std.mem.Allocator) void {
        if (self.rotated_jwt) |jwt| alloc.free(jwt);
        if (self.action_public_key) |k| alloc.free(k);
        for (self.actions) |action| {
            alloc.free(action.id);
            alloc.free(action.action_type);
            alloc.free(action.payload);
            alloc.free(action.execution_token);
            alloc.free(action.expires_at);
            alloc.free(action.payload_hash);
            if (action.signature) |s| alloc.free(s);
        }
        if (self.actions.len > 0) alloc.free(self.actions);
    }
};

pub const ResponseAction = struct {
    id: []u8,
    action_type: []u8,
    payload: []u8,
    execution_token: []u8,
    /// RFC 3339 deadline the server signed (empty if the server omitted it).
    expires_at: []u8 = &.{},
    /// Lower-case hex SHA-256 of the payload the server signed.
    payload_hash: []u8 = &.{},
    /// Base64 Ed25519 signature over the canonical action string. Null when
    /// the server sent no signature (refused by the agent).
    signature: ?[]u8 = null,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    base_url: []const u8,
    jwt: []const u8,
    agent_id: []const u8 = "",
    /// Sent in the v2 envelope and signed.
    sensor_version: []const u8 = "0.0.0",
    /// Boot id for this boot (entity id input), lower-case UUID text.
    boot_id: [36]u8 = entity.nil_uuid.*,
    /// Plaintext seed location (legacy layout / keystore fallback).
    device_key_path: []const u8 = "",
    /// Keystore holding the device seed; plaintext-only unless set.
    secret_store: keystore.Store = .{},
    /// Device key, loaded on first signature and kept for the process life.
    device_key: ?std.crypto.sign.Ed25519.KeyPair = null,
    device_key_warned: bool = false,
    request_timeout_seconds: u32,
    max_backoff_seconds: u64,
    backoff_seconds: u64 = 0,
    consecutive_failures: u8 = 0,

    pub fn init(
        alloc: std.mem.Allocator,
        base_url: []const u8,
        jwt: []const u8,
        request_timeout_seconds: u32,
        max_backoff_seconds: u32,
    ) !Client {
        return initFull(alloc, base_url, jwt, "", "", request_timeout_seconds, max_backoff_seconds);
    }

    pub fn initFull(
        alloc: std.mem.Allocator,
        base_url: []const u8,
        jwt: []const u8,
        agent_id: []const u8,
        device_key_path: []const u8,
        request_timeout_seconds: u32,
        max_backoff_seconds: u32,
    ) !Client {
        if (request_timeout_seconds == 0 or max_backoff_seconds == 0) {
            return error.InvalidTransportConfig;
        }
        return Client{
            .allocator = alloc,
            .base_url = base_url,
            .jwt = jwt,
            .agent_id = agent_id,
            .device_key_path = device_key_path,
            .request_timeout_seconds = request_timeout_seconds,
            .max_backoff_seconds = max_backoff_seconds,
        };
    }

    pub fn deinit(self: *Client) void {
        _ = self;
    }

    pub fn heartbeat(self: *Client, p: HeartbeatPayload) !HeartbeatResult {
        const body = try std.json.Stringify.valueAlloc(self.allocator, p, .{});
        defer self.allocator.free(body);

        const response = try self.post("/api/agents/heartbeat", body);
        defer self.allocator.free(response);

        const ParsedAction = struct {
            id: []const u8,
            action_type: []const u8,
            payload: std.json.Value,
            execution_token: []const u8,
            expires_at: ?[]const u8 = null,
            payload_hash: ?[]const u8 = null,
            signature: ?[]const u8 = null,
        };
        const Parsed = struct {
            rotated_jwt: ?[]const u8 = null,
            yara_pack_version: u64 = 0,
            action_public_key: ?[]const u8 = null,
            actions: []const ParsedAction = &.{},
        };
        const parsed = std.json.parseFromSlice(Parsed, self.allocator, response, .{
            .ignore_unknown_fields = true,
        }) catch return error.InvalidHeartbeatResponse;
        defer parsed.deinit();

        var result = HeartbeatResult{ .yara_pack_version = parsed.value.yara_pack_version };
        errdefer result.deinit(self.allocator);
        if (parsed.value.rotated_jwt) |jwt| {
            result.rotated_jwt = try self.allocator.dupe(u8, jwt);
        }
        if (parsed.value.action_public_key) |k| {
            result.action_public_key = try self.allocator.dupe(u8, k);
        }
        if (parsed.value.actions.len > 0) {
            var actions = std.array_list.Managed(ResponseAction).init(self.allocator);
            errdefer {
                for (actions.items) |action| {
                    self.allocator.free(action.id);
                    self.allocator.free(action.action_type);
                    self.allocator.free(action.payload);
                    self.allocator.free(action.execution_token);
                    self.allocator.free(action.expires_at);
                    self.allocator.free(action.payload_hash);
                    if (action.signature) |s| self.allocator.free(s);
                }
                actions.deinit();
            }

            for (parsed.value.actions) |action| {
                // Action ids are interpolated into a URL path when reporting
                // results; never accept anything but a canonical UUID.
                if (!isUuid(action.id)) {
                    std.log.warn("ignoring response action with non-UUID id", .{});
                    continue;
                }
                var payload: std.Io.Writer.Allocating = .init(self.allocator);
                errdefer payload.deinit();
                try std.json.Stringify.value(action.payload, .{}, &payload.writer);
                try actions.append(.{
                    .id = try self.allocator.dupe(u8, action.id),
                    .action_type = try self.allocator.dupe(u8, action.action_type),
                    .payload = try payload.toOwnedSlice(),
                    .execution_token = try self.allocator.dupe(u8, action.execution_token),
                    .expires_at = try self.allocator.dupe(u8, action.expires_at orelse ""),
                    .payload_hash = try self.allocator.dupe(u8, action.payload_hash orelse ""),
                    .signature = if (action.signature) |s| try self.allocator.dupe(u8, s) else null,
                });
            }
            result.actions = try actions.toOwnedSlice();
        }
        return result;
    }

    /// Send the clean shutdown notice as a final heartbeat. One attempt, no
    /// retry: a stopping service has a short wait hint.
    pub fn sendShutdownNotice(self: *Client, agent_version: []const u8, uptime: i64, depth: usize, reason: []const u8) !void {
        const body = try std.json.Stringify.valueAlloc(self.allocator, ShutdownPayload{
            .agent_version = agent_version,
            .uptime_seconds = @max(uptime, 0),
            .buffer_depth = depth,
            .shutdown_reason = reason,
        }, .{});
        defer self.allocator.free(body);
        const response = try self.post("/api/agents/heartbeat", body);
        self.allocator.free(response);
    }

    /// Signed release offered to this agent (#58): POST
    /// /api/agent/update-check. Returns the reply body, or null on 204.
    pub fn updateCheck(self: *Client, platform: []const u8, ring: []const u8) !?[]u8 {
        const body = try std.json.Stringify.valueAlloc(self.allocator, .{ .platform = platform, .ring = ring }, .{});
        defer self.allocator.free(body);
        const reply = try self.post("/api/agent/update-check", body);
        if (reply.len == 0) {
            self.allocator.free(reply);
            return null;
        }
        return reply;
    }

    /// GET a release binary over HTTPS, at most `max` bytes. Redirects are
    /// followed (GitHub release assets redirect to object storage); the
    /// bytes are checked against the signed manifest by the caller.
    pub fn download(self: *Client, url: []const u8, max: u64) ![]u8 {
        if (!std.ascii.startsWithIgnoreCase(url, "https://")) return error.InsecureDownloadUrl;
        var client = std.http.Client{ .allocator = self.allocator, .io = iox.current() };
        defer client.deinit();
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer out.deinit();
        const result = try client.fetch(.{
            .method = .GET,
            .location = .{ .url = url },
            .response_writer = &out.writer,
            .redirect_behavior = .init(5),
            .keep_alive = false,
        });
        if (@backingInt(result.status) != 200) return error.DownloadFailed;
        if (out.written().len > max) return error.DownloadTooLarge;
        return out.toOwnedSlice();
    }

    /// Fetch the tenant's signed YARA rule pack. The caller verifies it
    /// (`rule_pack.verify`) before using it.
    pub fn fetchYaraPack(self: *Client) ![]u8 {
        return self.post("/api/agent/yara-rules", "{}");
    }

    pub fn reportActionResult(
        self: *Client,
        action_id: []const u8,
        execution_token: []const u8,
        status: []const u8,
        message: []const u8,
    ) !void {
        if (!isUuid(action_id)) return error.InvalidActionId;
        const path = try self.allocator.print("/api/agents/actions/{s}/result", .{action_id});
        defer self.allocator.free(path);

        const body = try buildActionResultBody(self.allocator, execution_token, status, message);
        defer self.allocator.free(body);

        const response = try self.post(path, body);
        defer self.allocator.free(response);
    }

    pub fn flushEvents(self: *Client, buf: *buffer_mod.Buffer) !void {
        if (buf.len() == 0) return;

        // One batch id per flush attempt for server-side integrity correlation.
        var batch_id: [16]u8 = undefined;
        try std.Io.randomSecure(iox.current(), &batch_id);
        batch_id[6] = (batch_id[6] & 0x0f) | 0x40;
        batch_id[8] = (batch_id[8] & 0x3f) | 0x80;
        var batch_uuid: [36]u8 = undefined;
        formatUuid(batch_id, &batch_uuid);

        var batch = try buildBatchV2(self.allocator, .{
            .agent_id = self.agent_id,
            .batch_id = &batch_uuid,
            .boot_id = &self.boot_id,
            .sensor_version = self.sensor_version,
        }, buf.items());
        defer batch.deinit(self.allocator);

        if (self.trySignBatch(batch.canonical.items)) |sig_b64| {
            defer self.allocator.free(sig_b64);
            try batch.body.appendSlice(self.allocator, ",\"signature\":\"");
            try batch.body.appendSlice(self.allocator, sig_b64);
            try batch.body.appendSlice(self.allocator, "\"");
        }
        try batch.body.appendSlice(self.allocator, "}");

        const response = try self.post("/api/agents/events", batch.body.items);
        defer self.allocator.free(response);
        buf.acknowledgeFirst(batch.sent) catch |err| {
            self.noteFailure();
            return err;
        };
    }

    fn trySignBatch(self: *Client, canonical: []const u8) ?[]u8 {
        const kp = self.deviceKey() orelse return null;
        const sig = kp.sign(canonical, null) catch return null;
        const Encoder = std.base64.standard.Encoder;
        const out_len = Encoder.calcSize(sig.toBytes().len);
        const out = self.allocator.alloc(u8, out_len) catch return null;
        _ = Encoder.encode(out, &sig.toBytes());
        return out;
    }

    /// Device key from the plaintext seed file or the keystore. Failures are
    /// retried on the next flush and logged once.
    fn deviceKey(self: *Client) ?std.crypto.sign.Ed25519.KeyPair {
        if (self.device_key) |kp| return kp;
        if (self.device_key_path.len == 0) return null;
        const loaded = keystore.loadDeviceSeed(self.allocator, self.secret_store, self.device_key_path) catch |err| {
            if (!self.device_key_warned) {
                self.device_key_warned = true;
                std.log.warn(
                    "device key unavailable from {s} ({s}, status {d}); event batches are sent unsigned",
                    .{ self.secret_store.describe(), @errorName(err), keystore.lastOsStatus() },
                );
            }
            return null;
        };
        var seed = loaded orelse return null;
        defer std.crypto.secureZero(u8, &seed);
        self.device_key = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch return null;
        return self.device_key;
    }

    fn post(self: *Client, path: []const u8, body: []const u8) ![]u8 {
        const url = try self.allocator.print("{s}{s}", .{ self.base_url, path });
        defer self.allocator.free(url);

        const auth = try self.allocator.print("Bearer {s}", .{self.jwt});
        defer self.allocator.free(auth);

        const response = self.postTimed(url, auth, body) catch |err| {
            self.noteFailure();
            return err;
        };
        self.consecutive_failures = 0;
        self.backoff_seconds = 0;
        return response;
    }

    fn postTimed(self: *Client, url: []const u8, auth: []const u8, body: []const u8) ![]u8 {
        const TimedResult = union(enum) {
            request: anyerror![]u8,
            timeout: anyerror!void,
        };
        var result_storage: [2]TimedResult = undefined;
        var select = std.Io.Select(TimedResult).init(iox.current(), &result_storage);
        defer drainTimedResults(self.allocator, &select);

        try select.concurrent(.request, fetchOnce, .{ self, url, auth, body });
        select.concurrent(.timeout, waitForTimeout, .{ iox.current(), self.request_timeout_seconds }) catch |err| {
            return err;
        };

        const first = try select.await();
        return switch (first) {
            .request => |result| result,
            .timeout => error.RequestTimeout,
        };
    }

    fn noteFailure(self: *Client) void {
        self.consecutive_failures +|= 1;
        const shift: u6 = @intCast(@min(self.consecutive_failures - 1, 8));
        const ceiling = @min(@as(u64, 1) << shift, self.max_backoff_seconds);
        const floor = @max(@as(u64, 1), ceiling / 2);
        var sample: u64 = undefined;
        std.Io.random(iox.current(), std.mem.asBytes(&sample));
        self.backoff_seconds = floor + sample % (ceiling - floor + 1);
    }
};

fn fetchOnce(self: *Client, url: []const u8, auth: []const u8, body: []const u8) anyerror![]u8 {
    var client = std.http.Client{ .allocator = self.allocator, .io = iox.current() };
    defer client.deinit();

    const response_storage = try self.allocator.alloc(u8, 1024 * 1024);
    defer self.allocator.free(response_storage);
    var response_writer: std.Io.Writer = .fixed(response_storage);

    const result = try client.fetch(.{
        .method = .POST,
        .location = .{ .url = url },
        .headers = .{
            .content_type = .{ .override = "application/json" },
            .authorization = .{ .override = auth },
        },
        .payload = body,
        .response_writer = &response_writer,
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
    });

    const status_int = @backingInt(result.status);
    if (status_int >= 200 and status_int < 300) {
        return self.allocator.dupe(u8, response_writer.buffered());
    }
    if (status_int == 401 or status_int == 403) return error.AuthenticationRejected;
    if (status_int == 408 or status_int == 429) return error.RetryableHttpError;
    if (status_int >= 400 and status_int < 500) return error.ClientHttpError;
    return error.ServerHttpError;
}

fn waitForTimeout(io: std.Io, seconds: u32) anyerror!void {
    return std.Io.sleep(io, .fromSeconds(seconds), .awake);
}

fn drainTimedResults(alloc: std.mem.Allocator, select: anytype) void {
    while (select.cancel()) |pending| {
        switch (pending) {
            .request => |result| {
                const response = result catch continue;
                alloc.free(response);
            },
            .timeout => {},
        }
    }
}

/// Canonical 8-4-4-4-12 hex UUID (either case). Used to gate any id that is
/// placed into a request path.
pub fn isUuid(value: []const u8) bool {
    if (value.len != 36) return false;
    for (value, 0..) |ch, i| {
        switch (i) {
            8, 13, 18, 23 => if (ch != '-') return false,
            else => if (!std.ascii.isHex(ch)) return false,
        }
    }
    return true;
}

fn buildActionResultBody(
    alloc: std.mem.Allocator,
    execution_token: []const u8,
    status: []const u8,
    message: []const u8,
) ![]u8 {
    return std.json.Stringify.valueAlloc(alloc, .{
        .status = status,
        .execution_token = execution_token,
        .message = message,
        .result = struct {}{},
    }, .{});
}

pub const BatchHeader = struct {
    agent_id: []const u8,
    batch_id: []const u8,
    boot_id: []const u8,
    sensor_version: []const u8,
};

pub const Batch = struct {
    /// Body without the signature and closing brace.
    body: std.ArrayList(u8) = .empty,
    /// tawny-batch-v2 string to sign (server/src/crypto/batch_sig.zig).
    canonical: std.ArrayList(u8) = .empty,
    sent: usize = 0,

    pub fn deinit(self: *Batch, alloc: std.mem.Allocator) void {
        self.body.deinit(alloc);
        self.canonical.deinit(alloc);
    }
};

/// Schema 2 body (schemas/events/envelope.v2.json) and its canonical string:
///
///   tawny-batch-v2\n<agent_id>\n<batch_id>\n<boot_id>\n<sensor_version>\n
///   <event_id>|<seq>|<event_type>|<v>|<ts>|<sha256 hex of data bytes>\n   (per event)
///
/// Up to 500 events and about 900 KiB per batch.
pub fn buildBatchV2(alloc: std.mem.Allocator, h: BatchHeader, events: []const buffer_mod.Event) !Batch {
    var b: Batch = .{};
    errdefer b.deinit(alloc);
    try b.canonical.print(alloc, "tawny-batch-v2\n{s}\n{s}\n{s}\n{s}\n", .{ h.agent_id, h.batch_id, h.boot_id, h.sensor_version });

    var jw_out: std.Io.Writer.Allocating = .init(alloc);
    defer jw_out.deinit();
    try std.json.Stringify.value(.{
        .schema = @as(u8, 2),
        .batch_id = h.batch_id,
        .agent = .{ .agent_id = h.agent_id, .sensor_version = h.sensor_version, .boot_id = h.boot_id },
    }, .{}, &jw_out.writer);
    const head = jw_out.written();
    // Reopen the object to append the events array.
    try b.body.appendSlice(alloc, head[0 .. head.len - 1]);
    try b.body.appendSlice(alloc, ",\"events\":[");

    for (events[0..@min(events.len, 500)]) |ev| {
        const estimated_len = 160 + ev.event_type.len + ev.payload.len;
        if (b.sent > 0 and b.body.items.len + estimated_len > 900 * 1024) break;
        if (b.sent > 0) try b.body.append(alloc, ',');
        var uuid: [36]u8 = undefined;
        formatUuid(ev.client_event_id, &uuid);
        var ts_buf: [24]u8 = undefined;
        const ts = entity.formatIso(&ts_buf, @as(u64, @intCast(@max(ev.occurred_at, 0))) * entity.ticks_per_second);
        // event_type is limited to [A-Za-z0-9_.-] by the buffer, so it needs no escaping.
        try b.body.print(alloc, "{{\"event_id\":\"{s}\",\"event_type\":\"{s}\",\"v\":1,\"ts\":\"{s}\",\"seq\":{d},\"data\":{s}}}", .{
            &uuid, ev.event_type, ts, ev.sequence, ev.payload,
        });

        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(ev.payload, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        try b.canonical.print(alloc, "{s}|{d}|{s}|1|{s}|{s}\n", .{ &uuid, ev.sequence, ev.event_type, ts, &hex });
        b.sent += 1;
    }
    try b.body.append(alloc, ']');
    return b;
}

fn formatUuid(id: [16]u8, out: *[36]u8) void {
    const hex = std.fmt.bytesToHex(id, .lower);
    @memcpy(out[0..8], hex[0..8]);
    out[8] = '-';
    @memcpy(out[9..13], hex[8..12]);
    out[13] = '-';
    @memcpy(out[14..18], hex[12..16]);
    out[18] = '-';
    @memcpy(out[19..23], hex[16..20]);
    out[23] = '-';
    @memcpy(out[24..36], hex[20..32]);
}

test "UUID formatting is canonical lowercase" {
    const id = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    var text: [36]u8 = undefined;
    formatUuid(id, &text);
    try std.testing.expectEqualStrings("00112233-4455-4677-8899-aabbccddeeff", &text);
}

test "backoff grows within bounded jitter window" {
    var client = try Client.init(std.testing.allocator, "https://example.invalid", "jwt", 10, 8);
    defer client.deinit();
    client.noteFailure();
    try std.testing.expectEqual(@as(u64, 1), client.backoff_seconds);
    client.noteFailure();
    try std.testing.expect(client.backoff_seconds >= 1 and client.backoff_seconds <= 2);
    for (0..10) |_| client.noteFailure();
    try std.testing.expect(client.backoff_seconds >= 4 and client.backoff_seconds <= 8);
}

test "isUuid accepts canonical UUIDs only" {
    try std.testing.expect(isUuid("00112233-4455-4677-8899-aabbccddeeff"));
    try std.testing.expect(isUuid("00112233-4455-4677-8899-AABBCCDDEEFF"));
    try std.testing.expect(!isUuid(""));
    try std.testing.expect(!isUuid("../../agents/enroll"));
    try std.testing.expect(!isUuid("00112233-4455-4677-8899-aabbccddeef"));
    try std.testing.expect(!isUuid("00112233-4455-4677-8899-aabbccddeefg"));
    try std.testing.expect(!isUuid("00112233-4455-4677-8899?aabbccddeeff"));
    try std.testing.expect(!isUuid("0011223-34455-4677-8899-aabbccddeeff"));
    try std.testing.expect(!isUuid("00112233-4455-4677-8899-aabbccddeeff/x"));
}

test "reportActionResult rejects non-UUID action id before any request" {
    var client = try Client.init(std.testing.allocator, "https://example.invalid", "jwt", 10, 8);
    defer client.deinit();
    try std.testing.expectError(
        error.InvalidActionId,
        client.reportActionResult("../heartbeat?x=1", "tok", "failed", "msg"),
    );
    try std.testing.expectError(
        error.InvalidActionId,
        client.reportActionResult("1234", "tok", "failed", "msg"),
    );
}

test "action result body escapes untrusted strings" {
    const alloc = std.testing.allocator;
    const body = try buildActionResultBody(alloc, "tok\"\\", "failed", "line1\n\"quoted\"\x07");
    defer alloc.free(body);
    try std.testing.expectEqualStrings(
        "{\"status\":\"failed\",\"execution_token\":\"tok\\\"\\\\\",\"message\":\"line1\\n\\\"quoted\\\"\\u0007\",\"result\":{}}",
        body,
    );
}

test "heartbeat body escapes agent version" {
    const alloc = std.testing.allocator;
    const body = try std.json.Stringify.valueAlloc(alloc, HeartbeatPayload{
        .agent_version = "0.1.0\",\"x\":\"\\",
        .uptime_seconds = 5,
        .buffer_depth = 2,
    }, .{});
    defer alloc.free(body);
    try std.testing.expectEqualStrings(
        "{\"agent_version\":\"0.1.0\\\",\\\"x\\\":\\\"\\\\\",\"uptime_seconds\":5,\"buffer_depth\":2}",
        body,
    );
}

test "shutdown notice body carries the flag and reason" {
    const alloc = std.testing.allocator;
    const body = try std.json.Stringify.valueAlloc(alloc, ShutdownPayload{
        .agent_version = "0.1.0",
        .uptime_seconds = 5,
        .buffer_depth = 0,
        .shutdown_reason = "service_stop",
    }, .{});
    defer alloc.free(body);
    try std.testing.expectEqualStrings(
        "{\"agent_version\":\"0.1.0\",\"uptime_seconds\":5,\"buffer_depth\":0,\"shutdown\":true,\"shutdown_reason\":\"service_stop\"}",
        body,
    );
}

test "v2 batch body and canonical string" {
    const alloc = std.testing.allocator;
    const id = [_]u8{ 0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0xe1 };
    const events = [_]buffer_mod.Event{
        .{ .client_event_id = id, .sequence = 41, .event_type = "process_start", .occurred_at = 1760000000, .payload = "{\"process\":{\"pid\":10, \"name\":\"a \\\"b\\\"\"}}" },
    };
    var b = try buildBatchV2(alloc, .{
        .agent_id = "00000000-0000-0000-0000-00000000b001",
        .batch_id = "00000000-0000-0000-0000-00000000b002",
        .boot_id = "3c1c4b5e-6d2a-4f0e-9b7a-2d1e5f6a7b8c",
        .sensor_version = "0.1.0",
    }, &events);
    defer b.deinit(alloc);
    try b.body.append(alloc, '}');
    try std.testing.expectEqualStrings(
        "{\"schema\":2,\"batch_id\":\"00000000-0000-0000-0000-00000000b002\",\"agent\":{\"agent_id\":\"00000000-0000-0000-0000-00000000b001\",\"sensor_version\":\"0.1.0\",\"boot_id\":\"3c1c4b5e-6d2a-4f0e-9b7a-2d1e5f6a7b8c\"},\"events\":[" ++
            "{\"event_id\":\"00000000-0000-4000-8000-0000000000e1\",\"event_type\":\"process_start\",\"v\":1,\"ts\":\"2025-10-09T08:53:20.000Z\",\"seq\":41,\"data\":{\"process\":{\"pid\":10, \"name\":\"a \\\"b\\\"\"}}}]}",
        b.body.items,
    );
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(events[0].payload, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const want = try std.fmt.allocPrint(alloc, "tawny-batch-v2\n00000000-0000-0000-0000-00000000b001\n00000000-0000-0000-0000-00000000b002\n3c1c4b5e-6d2a-4f0e-9b7a-2d1e5f6a7b8c\n0.1.0\n00000000-0000-4000-8000-0000000000e1|41|process_start|1|2025-10-09T08:53:20.000Z|{s}\n", .{&hex});
    defer alloc.free(want);
    try std.testing.expectEqualStrings(want, b.canonical.items);
    try std.testing.expectEqual(@as(usize, 1), b.sent);
    try @import("../schema_check.zig").expectValidFile(alloc, "envelope.v2.json", b.body.items);
}
