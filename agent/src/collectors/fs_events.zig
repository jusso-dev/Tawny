const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

/// Event-driven file system monitor. Wraps inotify on Linux so we don't have
/// to poll every configured path on a fixed interval; modifications surface
/// within milliseconds. Other platforms get a no-op stub today — FSEvents on
/// macOS and ReadDirectoryChangesW on Windows live on the same backplane but
/// require enough wrapper code that we ship them in follow-ups.
///
/// Cross-compilation note: every reference to a Linux-only syscall wrapper
/// (`inotify_init1`, `inotify_add_watch`, `posix.read`, `posix.close`) lives
/// behind a `comptime` guard so the function bodies are never type-checked
/// against a non-Linux `fd_t` (which on Windows is `*anyopaque`, not i32).
pub const Watcher = struct {
    allocator: std.mem.Allocator,
    paths: [][]u8,
    // Inotify fd is an i32 on Linux. Made nullable so non-Linux targets can
    // leave it unset without pretending `-1` is a valid Windows HANDLE.
    inotify_fd: ?i32 = null,
    wd_to_path: std.AutoHashMap(i32, []const u8),

    pub fn init(alloc: std.mem.Allocator, paths: []const []const u8) !Watcher {
        var watcher = Watcher{
            .allocator = alloc,
            .paths = try alloc.alloc([]u8, paths.len),
            .wd_to_path = std.AutoHashMap(i32, []const u8).init(alloc),
        };
        errdefer watcher.deinit();

        for (paths, 0..) |path, i| {
            watcher.paths[i] = try alloc.dupe(u8, path);
        }

        if (comptime builtin.os.tag == .linux) {
            const fd = std.posix.inotify_init1(linux.IN.NONBLOCK | linux.IN.CLOEXEC) catch return watcher;
            watcher.inotify_fd = fd;
            const mask = linux.IN.MODIFY
                | linux.IN.CREATE
                | linux.IN.DELETE
                | linux.IN.MOVED_FROM
                | linux.IN.MOVED_TO
                | linux.IN.ATTRIB;
            for (watcher.paths) |path| {
                const wd = std.posix.inotify_add_watch(fd, path, mask) catch continue;
                try watcher.wd_to_path.put(wd, path);
            }
        }

        return watcher;
    }

    pub fn deinit(self: *Watcher) void {
        if (comptime builtin.os.tag == .linux) {
            if (self.inotify_fd) |fd| std.posix.close(fd);
        }
        for (self.paths) |p| self.allocator.free(p);
        self.allocator.free(self.paths);
        self.wd_to_path.deinit();
    }

    /// Drain pending inotify events and translate each into a JSON payload.
    /// Caller owns both the outer slice and each inner payload.
    pub fn collectEvents(self: *Watcher) ![][]u8 {
        var payloads = std.ArrayList([]u8).init(self.allocator);
        errdefer {
            for (payloads.items) |p| self.allocator.free(p);
            payloads.deinit();
        }

        if (comptime builtin.os.tag != .linux) {
            return payloads.toOwnedSlice();
        }

        const fd = self.inotify_fd orelse return payloads.toOwnedSlice();
        try drainLinux(self, fd, &payloads);
        return payloads.toOwnedSlice();
    }
};

fn drainLinux(self: *Watcher, fd: i32, payloads: *std.ArrayList([]u8)) !void {
    if (comptime builtin.os.tag != .linux) return;

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = std.posix.read(fd, &buf) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        if (n == 0) break;

        var offset: usize = 0;
        while (offset + @sizeOf(linux.inotify_event) <= n) {
            const ev: *const linux.inotify_event = @ptrCast(@alignCast(&buf[offset]));
            const name_len = ev.len;
            const name_start = offset + @sizeOf(linux.inotify_event);
            const raw_name: []const u8 = if (name_len > 0) blk: {
                const name_buf = buf[name_start .. name_start + name_len];
                const null_idx = std.mem.indexOfScalar(u8, name_buf, 0) orelse name_buf.len;
                break :blk name_buf[0..null_idx];
            } else "";

            const base_path = self.wd_to_path.get(ev.wd) orelse "";
            const payload = try buildEvent(self.allocator, base_path, raw_name, ev.mask);
            try payloads.append(payload);

            offset += @sizeOf(linux.inotify_event) + name_len;
        }
    }
}

fn buildEvent(alloc: std.mem.Allocator, base: []const u8, name: []const u8, mask: u32) ![]u8 {
    var out = std.ArrayList(u8).init(alloc);
    errdefer out.deinit();
    var w = out.writer();

    try w.writeAll("{\"path\":");
    if (name.len == 0) {
        try std.json.stringify(base, .{}, w);
    } else {
        const composed = try std.fs.path.join(alloc, &.{ base, name });
        defer alloc.free(composed);
        try std.json.stringify(composed, .{}, w);
    }
    try w.writeAll(",\"action\":\"");
    try w.writeAll(actionName(mask));
    try w.writeAll("\",\"watch\":");
    try std.json.stringify(base, .{}, w);
    try w.writeAll(",\"is_directory\":");
    try w.print("{any}", .{(mask & linux.IN.ISDIR) != 0});
    try w.writeByte('}');
    return out.toOwnedSlice();
}

fn actionName(mask: u32) []const u8 {
    if ((mask & linux.IN.CREATE) != 0) return "create";
    if ((mask & linux.IN.DELETE) != 0) return "delete";
    if ((mask & linux.IN.MOVED_FROM) != 0) return "moved_from";
    if ((mask & linux.IN.MOVED_TO) != 0) return "moved_to";
    if ((mask & linux.IN.MODIFY) != 0) return "modify";
    if ((mask & linux.IN.ATTRIB) != 0) return "attrib";
    return "other";
}

test "watcher module loads" {
    var w = try Watcher.init(std.testing.allocator, &.{});
    defer w.deinit();
}
