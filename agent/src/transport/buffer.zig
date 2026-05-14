const std = @import("std");

pub const Event = struct {
    event_type: []const u8,
    occurred_at: i64,
    /// Caller-owned JSON payload (object literal). Buffer takes ownership via dupe.
    payload: []const u8,
};

pub const Buffer = struct {
    allocator: std.mem.Allocator,
    capacity: usize,
    list: std.ArrayList(Event),

    pub fn init(alloc: std.mem.Allocator, capacity: usize) Buffer {
        return .{
            .allocator = alloc,
            .capacity = capacity,
            .list = std.ArrayList(Event).init(alloc),
        };
    }

    pub fn deinit(self: *Buffer) void {
        self.clear();
        self.list.deinit();
    }

    pub fn len(self: *const Buffer) usize {
        return self.list.items.len;
    }

    pub fn items(self: *const Buffer) []const Event {
        return self.list.items;
    }

    pub fn push(self: *Buffer, ev: Event) !void {
        const owned = try self.allocator.dupe(u8, ev.payload);
        try self.list.append(.{
            .event_type = ev.event_type,
            .occurred_at = ev.occurred_at,
            .payload = owned,
        });
    }

    pub fn clear(self: *Buffer) void {
        for (self.list.items) |ev| self.allocator.free(ev.payload);
        self.list.clearRetainingCapacity();
    }

    pub fn shouldSpill(self: *const Buffer) bool {
        return self.capacity > 0 and self.list.items.len > self.capacity;
    }

    pub fn spill(self: *Buffer, path: []const u8) !void {
        if (self.len() == 0) return;

        const dir = std.fs.path.dirname(path) orelse ".";
        std.fs.cwd().makePath(dir) catch {};

        var file = try std.fs.cwd().createFile(path, .{ .truncate = false });
        defer file.close();
        try file.seekFromEnd(0);

        var w = file.writer();
        for (self.list.items) |ev| {
            try w.print("{s}\t{d}\t{s}\n", .{ ev.event_type, ev.occurred_at, ev.payload });
        }
        try file.sync();
        self.clear();
    }

    pub fn replay(self: *Buffer, path: []const u8) !void {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer file.close();

        const raw = try file.readToEndAlloc(self.allocator, 32 * 1024 * 1024);
        defer self.allocator.free(raw);

        var lines = std.mem.splitScalar(u8, raw, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            var fields = std.mem.splitScalar(u8, line, '\t');
            const event_type = fields.next() orelse continue;
            const occurred_raw = fields.next() orelse continue;
            const payload = fields.rest();
            if (payload.len == 0) continue;
            const occurred_at = try std.fmt.parseInt(i64, occurred_raw, 10);
            try self.push(.{
                .event_type = event_type,
                .occurred_at = occurred_at,
                .payload = payload,
            });
        }

        std.fs.cwd().deleteFile(path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
    }
};

test "buffer pushes and clears" {
    var b = Buffer.init(std.testing.allocator, 4);
    defer b.deinit();
    try b.push(.{ .event_type = "x", .occurred_at = 0, .payload = "{}" });
    try std.testing.expectEqual(@as(usize, 1), b.len());
    b.clear();
    try std.testing.expectEqual(@as(usize, 0), b.len());
}

test "buffer spills and replays" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);
    const spill_path = try std.fs.path.join(
        std.testing.allocator,
        &.{ tmp_path, "events.spool" },
    );
    defer std.testing.allocator.free(spill_path);

    var b = Buffer.init(std.testing.allocator, 2);
    defer b.deinit();
    try b.push(.{ .event_type = "x", .occurred_at = 1, .payload = "1" });
    try b.push(.{ .event_type = "x", .occurred_at = 2, .payload = "2" });
    try b.push(.{ .event_type = "x", .occurred_at = 3, .payload = "3" });
    try std.testing.expect(b.shouldSpill());
    try b.spill(spill_path);
    try std.testing.expectEqual(@as(usize, 0), b.len());

    var replayed = Buffer.init(std.testing.allocator, 10);
    defer replayed.deinit();
    try replayed.replay(spill_path);
    try std.testing.expectEqual(@as(usize, 3), replayed.len());
    try std.testing.expectEqual(@as(i64, 1), replayed.items()[0].occurred_at);
}
