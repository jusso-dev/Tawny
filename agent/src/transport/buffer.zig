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
        // Bounded ring: drop oldest if at capacity.
        if (self.list.items.len >= self.capacity) {
            const dropped = self.list.orderedRemove(0);
            self.allocator.free(dropped.payload);
        }
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
};

test "buffer pushes and clears" {
    var b = Buffer.init(std.testing.allocator, 4);
    defer b.deinit();
    try b.push(.{ .event_type = "x", .occurred_at = 0, .payload = "{}" });
    try std.testing.expectEqual(@as(usize, 1), b.len());
    b.clear();
    try std.testing.expectEqual(@as(usize, 0), b.len());
}

test "buffer drops oldest at capacity" {
    var b = Buffer.init(std.testing.allocator, 2);
    defer b.deinit();
    try b.push(.{ .event_type = "x", .occurred_at = 1, .payload = "1" });
    try b.push(.{ .event_type = "x", .occurred_at = 2, .payload = "2" });
    try b.push(.{ .event_type = "x", .occurred_at = 3, .payload = "3" });
    try std.testing.expectEqual(@as(usize, 2), b.len());
    try std.testing.expectEqual(@as(i64, 2), b.items()[0].occurred_at);
}
