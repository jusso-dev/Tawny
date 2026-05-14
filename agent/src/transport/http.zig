const std = @import("std");
const buffer_mod = @import("buffer.zig");

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
        }
        if (self.actions.len > 0) alloc.free(self.actions);
    }
};

pub const ResponseAction = struct {
    id: []u8,
    action_type: []u8,
    payload: []u8,
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    base_url: []const u8,
    jwt: []const u8,
    backoff_seconds: u64 = 1,

    pub fn init(alloc: std.mem.Allocator, base_url: []const u8, jwt: []const u8) !Client {
        return Client{
            .allocator = alloc,
            .base_url = base_url,
            .jwt = jwt,
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
        };
        const Parsed = struct {
            rotated_jwt: ?[]const u8 = null,
            actions: []const ParsedAction = &.{},
        };
        const parsed = std.json.parseFromSlice(Parsed, self.allocator, response, .{
            .ignore_unknown_fields = true,
        }) catch return .{};
        defer parsed.deinit();

        var result = HeartbeatResult{};
        if (parsed.value.rotated_jwt) |jwt| {
            result.rotated_jwt = try self.allocator.dupe(u8, jwt);
        }
        if (parsed.value.actions.len > 0) {
            var actions = std.ArrayList(ResponseAction).init(self.allocator);
            errdefer {
                for (actions.items) |action| {
                    self.allocator.free(action.id);
                    self.allocator.free(action.action_type);
                    self.allocator.free(action.payload);
                }
                actions.deinit();
            }

            for (parsed.value.actions) |action| {
                var payload = std.ArrayList(u8).init(self.allocator);
                errdefer payload.deinit();
                try std.json.stringify(action.payload, .{}, payload.writer());
                try actions.append(.{
                    .id = try self.allocator.dupe(u8, action.id),
                    .action_type = try self.allocator.dupe(u8, action.action_type),
                    .payload = try payload.toOwnedSlice(),
                });
            }
            result.actions = try actions.toOwnedSlice();
        }
        return result;
    }

    pub fn reportActionResult(
        self: *Client,
        action_id: []const u8,
        status: []const u8,
        message: []const u8,
    ) !void {
        const path = try std.fmt.allocPrint(self.allocator, "/api/agents/actions/{s}/result", .{action_id});
        defer self.allocator.free(path);

        var body = std.ArrayList(u8).init(self.allocator);
        defer body.deinit();
        var w = body.writer();
        try w.print("{{\"status\":\"{s}\",\"message\":", .{status});
        try std.json.stringify(message, .{}, w);
        try w.writeAll(",\"result\":{}}");

        const response = try self.post(path, body.items);
        defer self.allocator.free(response);
    }

    pub fn flushEvents(self: *Client, buf: *buffer_mod.Buffer) !void {
        if (buf.len() == 0) return;

        var body = std.ArrayList(u8).init(self.allocator);
        defer body.deinit();
        try body.appendSlice("{\"events\":[");
        for (buf.items(), 0..) |ev, i| {
            if (i > 0) try body.append(',');
            try body.writer().print(
                \\{{"type":"{s}","occurred_at":{d},"payload":{s}}}
            , .{ ev.event_type, ev.occurred_at, ev.payload });
        }
        try body.appendSlice("]}");

        const response = try self.post("/api/agents/events", body.items);
        defer self.allocator.free(response);
        buf.clear();
    }

    fn post(self: *Client, path: []const u8, body: []const u8) ![]u8 {
        const url = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.base_url, path });
        defer self.allocator.free(url);

        const auth = try std.fmt.allocPrint(self.allocator, "Bearer {s}", .{self.jwt});
        defer self.allocator.free(auth);

        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        var resp = std.ArrayList(u8).init(self.allocator);
        defer resp.deinit();

        const res = client.fetch(.{
            .method = .POST,
            .location = .{ .url = url },
            .headers = .{
                .content_type = .{ .override = "application/json" },
                .authorization = .{ .override = auth },
            },
            .payload = body,
            .response_storage = .{ .dynamic = &resp },
        }) catch |err| {
            self.backoff_seconds = @min(self.backoff_seconds * 2, 300);
            return err;
        };

        const status_int = @intFromEnum(res.status);
        if (status_int >= 200 and status_int < 300) {
            self.backoff_seconds = 1;
            return resp.toOwnedSlice();
        }
        self.backoff_seconds = @min(self.backoff_seconds * 2, 300);
        return error.HttpError;
    }
};
