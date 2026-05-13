const std = @import("std");
const buffer_mod = @import("buffer.zig");

pub const HeartbeatPayload = struct {
    agent_version: []const u8,
    uptime_seconds: i64,
    buffer_depth: usize,
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

    pub fn heartbeat(self: *Client, p: HeartbeatPayload) !void {
        const body = try std.fmt.allocPrint(self.allocator,
            \\{{"agent_version":"{s}","uptime_seconds":{d},"buffer_depth":{d}}}
        , .{ p.agent_version, p.uptime_seconds, p.buffer_depth });
        defer self.allocator.free(body);

        try self.post("/api/agents/heartbeat", body);
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

        try self.post("/api/agents/events", body.items);
        buf.clear();
    }

    fn post(self: *Client, path: []const u8, body: []const u8) !void {
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
            return;
        }
        return error.HttpError;
    }
};
