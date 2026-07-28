const std = @import("std");
const buffer_mod = @import("buffer.zig");
const iox = @import("../io_compat.zig");

pub const HeartbeatPayload = struct {
    agent_version: []const u8,
    uptime_seconds: i64,
    buffer_depth: usize,
};

pub const HeartbeatResult = struct {
    rotated_jwt: ?[]u8 = null,
    actions: []ResponseAction = &.{},

    pub fn deinit(self: *HeartbeatResult, alloc: std.mem.Allocator) void {
        if (self.rotated_jwt) |jwt| alloc.free(jwt);
        for (self.actions) |action| {
            alloc.free(action.id);
            alloc.free(action.action_type);
            alloc.free(action.payload);
            alloc.free(action.execution_token);
        }
        if (self.actions.len > 0) alloc.free(self.actions);
    }
};

pub const ResponseAction = struct {
    id: []u8,
    action_type: []u8,
    payload: []u8,
    execution_token: []u8,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    base_url: []const u8,
    jwt: []const u8,
    agent_id: []const u8 = "",
    device_key_path: []const u8 = "",
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
        const body = try std.fmt.allocPrint(self.allocator,
            \\{{"agent_version":"{s}","uptime_seconds":{d},"buffer_depth":{d}}}
        , .{ p.agent_version, p.uptime_seconds, p.buffer_depth });
        defer self.allocator.free(body);

        const response = try self.post("/api/agents/heartbeat", body);
        defer self.allocator.free(response);

        const ParsedAction = struct {
            id: []const u8,
            action_type: []const u8,
            payload: std.json.Value,
            execution_token: []const u8,
        };
        const Parsed = struct {
            rotated_jwt: ?[]const u8 = null,
            actions: []const ParsedAction = &.{},
        };
        const parsed = std.json.parseFromSlice(Parsed, self.allocator, response, .{
            .ignore_unknown_fields = true,
        }) catch return error.InvalidHeartbeatResponse;
        defer parsed.deinit();

        var result = HeartbeatResult{};
        if (parsed.value.rotated_jwt) |jwt| {
            result.rotated_jwt = try self.allocator.dupe(u8, jwt);
        }
        if (parsed.value.actions.len > 0) {
            var actions = std.array_list.Managed(ResponseAction).init(self.allocator);
            errdefer {
                for (actions.items) |action| {
                    self.allocator.free(action.id);
                    self.allocator.free(action.action_type);
                    self.allocator.free(action.payload);
                    self.allocator.free(action.execution_token);
                }
                actions.deinit();
            }

            for (parsed.value.actions) |action| {
                var payload: std.Io.Writer.Allocating = .init(self.allocator);
                errdefer payload.deinit();
                try std.json.Stringify.value(action.payload, .{}, &payload.writer);
                try actions.append(.{
                    .id = try self.allocator.dupe(u8, action.id),
                    .action_type = try self.allocator.dupe(u8, action.action_type),
                    .payload = try payload.toOwnedSlice(),
                    .execution_token = try self.allocator.dupe(u8, action.execution_token),
                });
            }
            result.actions = try actions.toOwnedSlice();
        }
        return result;
    }

    pub fn reportActionResult(
        self: *Client,
        action_id: []const u8,
        execution_token: []const u8,
        status: []const u8,
        message: []const u8,
    ) !void {
        const path = try std.fmt.allocPrint(self.allocator, "/api/agents/actions/{s}/result", .{action_id});
        defer self.allocator.free(path);

        var body = std.array_list.Managed(u8).init(self.allocator);
        defer body.deinit();
        try body.print("{{\"status\":\"{s}\",\"execution_token\":", .{status});
        {
            var token_writer: std.Io.Writer.Allocating = .init(self.allocator);
            defer token_writer.deinit();
            try std.json.Stringify.value(execution_token, .{}, &token_writer.writer);
            try body.appendSlice(token_writer.written());
        }
        try body.appendSlice(",\"message\":");
        var body_writer: std.Io.Writer.Allocating = .init(self.allocator);
        defer body_writer.deinit();
        try std.json.Stringify.value(message, .{}, &body_writer.writer);
        try body.appendSlice(body_writer.written());
        try body.appendSlice(",\"result\":{}}");

        const response = try self.post(path, body.items);
        defer self.allocator.free(response);
    }

    pub fn flushEvents(self: *Client, buf: *buffer_mod.Buffer) !void {
        if (buf.len() == 0) return;

        var body = std.array_list.Managed(u8).init(self.allocator);
        defer body.deinit();

        // One batch id per flush attempt for server-side integrity correlation.
        var batch_id: [16]u8 = undefined;
        try std.Io.randomSecure(iox.current(), &batch_id);
        batch_id[6] = (batch_id[6] & 0x0f) | 0x40;
        batch_id[8] = (batch_id[8] & 0x3f) | 0x80;
        var batch_uuid: [36]u8 = undefined;
        formatUuid(batch_id, &batch_uuid);

        // Build canonical string for Ed25519 device signature while emitting events.
        var canonical = std.array_list.Managed(u8).init(self.allocator);
        defer canonical.deinit();
        try canonical.appendSlice("tawny-batch-v1\n");
        try canonical.appendSlice(self.agent_id);
        try canonical.append('\n');
        try canonical.appendSlice(&batch_uuid);
        try canonical.append('\n');

        try body.appendSlice("{\"batch_id\":\"");
        try body.appendSlice(&batch_uuid);
        try body.appendSlice("\",\"events\":[");

        var sent_count: usize = 0;
        for (buf.items()[0..@min(buf.len(), 500)]) |ev| {
            const estimated_len = 128 + ev.event_type.len + ev.payload.len;
            if (sent_count > 0 and body.items.len + estimated_len > 900 * 1024) break;
            if (sent_count > 0) try body.append(',');
            var uuid: [36]u8 = undefined;
            formatUuid(ev.client_event_id, &uuid);
            try body.appendSlice("{\"client_event_id\":\"");
            try body.appendSlice(&uuid);
            try body.appendSlice("\",\"type\":");
            var type_json: std.Io.Writer.Allocating = .init(self.allocator);
            defer type_json.deinit();
            try std.json.Stringify.value(ev.event_type, .{}, &type_json.writer);
            try body.appendSlice(type_json.written());
            try body.print(
                \\,"occurred_at":{d},"sequence":{d},"payload":{s}}}
            , .{ ev.occurred_at, ev.sequence, ev.payload });

            // Canonical line: client_event_id|sequence|type|occurred_at|sha256(payload)
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(ev.payload, &digest, .{});
            try canonical.appendSlice(&uuid);
            try canonical.append('|');
            const meta = try std.fmt.allocPrint(self.allocator, "{d}|{s}|{d}|", .{ ev.sequence, ev.event_type, ev.occurred_at });
            defer self.allocator.free(meta);
            try canonical.appendSlice(meta);
            try appendHexLower(&canonical, &digest);
            try canonical.append('\n');

            sent_count += 1;
        }
        try body.appendSlice("]");

        if (trySignBatch(self.allocator, self.device_key_path, canonical.items)) |sig_b64| {
            defer self.allocator.free(sig_b64);
            try body.appendSlice(",\"signature\":\"");
            try body.appendSlice(sig_b64);
            try body.appendSlice("\"");
        }
        try body.appendSlice("}");

        const response = try self.post("/api/agents/events", body.items);
        defer self.allocator.free(response);
        buf.acknowledgeFirst(sent_count) catch |err| {
            self.noteFailure();
            return err;
        };
    }

    fn appendHexLower(list: *std.array_list.Managed(u8), bytes: []const u8) !void {
        const hex = "0123456789abcdef";
        for (bytes) |b| {
            try list.append(hex[b >> 4]);
            try list.append(hex[b & 0xf]);
        }
    }

    fn trySignBatch(alloc: std.mem.Allocator, device_key_path: []const u8, canonical: []const u8) ?[]u8 {
        if (device_key_path.len == 0) return null;
        const io = iox.current();
        const file = std.Io.Dir.cwd().openFile(io, device_key_path, .{}) catch return null;
        defer file.close(io);
        var seed: [std.crypto.sign.Ed25519.KeyPair.seed_length]u8 = undefined;
        const n = file.readPositionalAll(io, &seed, 0) catch return null;
        if (n != seed.len) return null;
        const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch return null;
        const sig = kp.sign(canonical, null) catch return null;
        const Encoder = std.base64.standard.Encoder;
        const out_len = Encoder.calcSize(sig.toBytes().len);
        const out = alloc.alloc(u8, out_len) catch return null;
        _ = Encoder.encode(out, &sig.toBytes());
        return out;
    }

    fn post(self: *Client, path: []const u8, body: []const u8) ![]u8 {
        const url = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.base_url, path });
        defer self.allocator.free(url);

        const auth = try std.fmt.allocPrint(self.allocator, "Bearer {s}", .{self.jwt});
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

    const status_int = @intFromEnum(result.status);
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
