const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const fsevents = if (builtin.target.os.tag == .macos) @import("../platform/macos/fsevents.zig") else struct {
    pub const Stream = void;
    pub const Event = void;
    pub const queue_capacity: usize = 0;
};

const max_events_per_collection: usize = 2048;
const max_watch_paths: usize = 4096;

/// Event-driven file system monitor over the configured `fim_paths`.
/// Linux: inotify (non-recursive). macOS: an FSEvents stream on its own
/// dispatch queue feeding a bounded queue this collector drains; FSEvents is
/// recursive, coalesces flags per path (all reported in `flags`) and cannot
/// pair renames, so the vanished side is `moved_from` and the surviving side
/// `moved_to` (see platform/macos/fsevents.zig). Events dropped because the
/// queue was full are reported as one `overflow` event carrying `dropped`.
/// Windows: no-op until ReadDirectoryChangesW lands.
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
    mac_stream: ?*fsevents.Stream = null,
    mac_drain: ?*[fsevents.queue_capacity]fsevents.Event = null,

    pub fn init(alloc: std.mem.Allocator, paths: []const []const u8) !Watcher {
        const bounded_paths = paths[0..@min(paths.len, max_watch_paths)];
        var watcher = Watcher{
            .allocator = alloc,
            .paths = try alloc.alloc([]u8, bounded_paths.len),
            .wd_to_path = std.AutoHashMap(i32, []const u8).init(alloc),
        };

        for (bounded_paths, 0..) |path, i| {
            watcher.paths[i] = alloc.dupe(u8, path) catch |err| {
                for (watcher.paths[0..i]) |initialized| alloc.free(initialized);
                alloc.free(watcher.paths);
                watcher.wd_to_path.deinit();
                return err;
            };
        }
        errdefer watcher.deinit();

        if (comptime builtin.target.os.tag == .linux) {
            const fd = std.c.inotify_init1(linux.IN.NONBLOCK | linux.IN.CLOEXEC);
            if (std.c.errno(fd) != .SUCCESS) return watcher;
            watcher.inotify_fd = fd;
            const mask = linux.IN.MODIFY | linux.IN.CREATE | linux.IN.DELETE | linux.IN.MOVED_FROM | linux.IN.MOVED_TO | linux.IN.ATTRIB;
            for (watcher.paths) |path| {
                const path_z = alloc.dupeSentinel(u8, path, 0) catch continue;
                defer alloc.free(path_z);
                const wd = std.c.inotify_add_watch(fd, path_z.ptr, mask);
                if (std.c.errno(wd) != .SUCCESS) continue;
                try watcher.wd_to_path.put(wd, path);
            }
        }

        if (comptime builtin.target.os.tag == .macos) {
            if (watcher.paths.len > 0) {
                watcher.mac_drain = try alloc.create([fsevents.queue_capacity]fsevents.Event);
                watcher.mac_stream = fsevents.Stream.start(alloc, watcher.paths) catch |err| blk: {
                    std.debug.print("fs_events: FSEvents stream not started: {s}\n", .{@errorName(err)});
                    break :blk null;
                };
            }
        }

        return watcher;
    }

    pub fn deinit(self: *Watcher) void {
        if (comptime builtin.target.os.tag == .linux) {
            if (self.inotify_fd) |fd| _ = linux.close(fd);
        }
        if (comptime builtin.target.os.tag == .macos) {
            if (self.mac_stream) |s| s.stop();
            if (self.mac_drain) |d| self.allocator.destroy(d);
        }
        for (self.paths) |p| self.allocator.free(p);
        self.allocator.free(self.paths);
        self.wd_to_path.deinit();
    }

    /// Drain pending inotify events and translate each into a JSON payload.
    /// Caller owns both the outer slice and each inner payload.
    pub fn collectEvents(self: *Watcher) ![][]u8 {
        var payloads = std.array_list.Managed([]u8).init(self.allocator);
        errdefer {
            for (payloads.items) |p| self.allocator.free(p);
            payloads.deinit();
        }

        if (comptime builtin.target.os.tag == .macos) {
            try drainMacos(self, &payloads);
            return payloads.toOwnedSlice();
        }
        if (comptime builtin.target.os.tag != .linux) {
            return payloads.toOwnedSlice();
        }

        const fd = self.inotify_fd orelse return payloads.toOwnedSlice();
        try drainLinux(self, fd, &payloads);
        return payloads.toOwnedSlice();
    }
};

fn drainLinux(self: *Watcher, fd: i32, payloads: *std.array_list.Managed([]u8)) !void {
    if (comptime builtin.target.os.tag != .linux) return;

    var buf: [4096]u8 align(@alignOf(linux.inotify_event)) = undefined;
    while (true) {
        if (payloads.items.len >= max_events_per_collection) break;
        const n = std.posix.read(fd, &buf) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        if (n == 0) break;

        var offset: usize = 0;
        while (offset + @sizeOf(linux.inotify_event) <= n) {
            if (payloads.items.len >= max_events_per_collection) return;
            const ev: *const linux.inotify_event = @ptrCast(@alignCast(&buf[offset]));
            const name_len: usize = @intCast(ev.len);
            const name_start = offset + @sizeOf(linux.inotify_event);
            const record_len = @sizeOf(linux.inotify_event) + name_len;
            if (record_len > n - offset) break;
            const raw_name: []const u8 = if (name_len > 0) blk: {
                const name_buf = buf[name_start .. name_start + name_len];
                const null_idx = std.mem.indexOfScalar(u8, name_buf, 0) orelse name_buf.len;
                break :blk name_buf[0..null_idx];
            } else "";

            const is_overflow = (ev.mask & linux.IN.Q_OVERFLOW) != 0;
            const base_path = self.wd_to_path.get(ev.wd) orelse if (is_overflow) "" else {
                offset += record_len;
                continue;
            };
            const payload = try buildEvent(self.allocator, base_path, raw_name, ev.mask);
            try payloads.append(payload);

            offset += record_len;
        }
    }
}

fn drainMacos(self: *Watcher, payloads: *std.array_list.Managed([]u8)) !void {
    if (comptime builtin.target.os.tag != .macos) return;
    const stream = self.mac_stream orelse return;
    const buf = self.mac_drain orelse return;

    const drained = stream.drain(buf);
    const events = buf[0..drained.count];
    // Paths were allocated on the FSEvents thread with the C allocator.
    defer for (events) |ev| std.heap.c_allocator.free(ev.path);

    var dropped = drained.dropped;
    for (events) |ev| {
        // The queue holds 4096 events but a pass emits at most 2048; the
        // remainder are counted as dropped rather than held across passes.
        if (payloads.items.len >= max_events_per_collection) {
            dropped += 1;
            continue;
        }
        const root = stream.roots[ev.root_index];
        const payload = try buildMacosEvent(self.allocator, root, ev);
        payloads.append(payload) catch |err| {
            self.allocator.free(payload);
            return err;
        };
    }
    if (dropped > 0) {
        const overflow = try std.fmt.allocPrint(
            self.allocator,
            "{{\"path\":\"\",\"action\":\"overflow\",\"watch\":\"\",\"is_directory\":false,\"dropped\":{d}}}",
            .{dropped},
        );
        payloads.append(overflow) catch |err| {
            self.allocator.free(overflow);
            return err;
        };
    }
}

fn buildMacosEvent(alloc: std.mem.Allocator, root: fsevents.Root, ev: fsevents.Event) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;

    // Report through the configured spelling (/etc/...) rather than the
    // firmlinked real path FSEvents delivers (/private/etc/...).
    const suffix = root.suffix(ev.path) orelse "";
    const sep: []const u8 = if (suffix.len > 0 and suffix[0] != '/' and !std.mem.endsWith(u8, root.configured, "/")) "/" else "";
    var path_buf: [4096]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}{s}{s}", .{ root.configured, sep, suffix }) catch ev.path;

    try w.writeAll("{\"path\":");
    try std.json.Stringify.value(path, .{}, w);
    try w.writeAll(",\"action\":\"");
    try w.writeAll(ev.action);
    try w.writeAll("\",\"watch\":");
    try std.json.Stringify.value(root.configured, .{}, w);
    try w.print(",\"is_directory\":{any}", .{(ev.flags & fsevents.Flag.is_dir) != 0});
    try w.writeAll(",\"flags\":[");
    try fsevents.writeFlagNames(w, ev.flags);
    try w.writeAll("]}");
    return out.toOwnedSlice();
}

fn buildEvent(alloc: std.mem.Allocator, base: []const u8, name: []const u8, mask: u32) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;

    try w.writeAll("{\"path\":");
    if (name.len == 0) {
        try std.json.Stringify.value(base, .{}, w);
    } else {
        const composed = try std.fs.path.join(alloc, &.{ base, name });
        defer alloc.free(composed);
        try std.json.Stringify.value(composed, .{}, w);
    }
    try w.writeAll(",\"action\":\"");
    try w.writeAll(actionName(mask));
    try w.writeAll("\",\"watch\":");
    try std.json.Stringify.value(base, .{}, w);
    try w.writeAll(",\"is_directory\":");
    try w.print("{any}", .{(mask & linux.IN.ISDIR) != 0});
    try w.writeByte('}');
    return out.toOwnedSlice();
}

fn actionName(mask: u32) []const u8 {
    if ((mask & linux.IN.Q_OVERFLOW) != 0) return "overflow";
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

test "macOS FSEvents reports create, modify, rename and delete" {
    if (builtin.target.os.tag != .macos) return error.SkipZigTest;
    const iox = @import("../io_compat.zig");
    const alloc = std.testing.allocator;
    iox.initialize(std.testing.io);
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const rel = try std.fs.path.join(alloc, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer alloc.free(rel);
    const rel_z = try alloc.dupeSentinel(u8, rel, 0);
    defer alloc.free(rel_z);
    var abs_buf: [1024]u8 = undefined;
    const abs = std.mem.span(std.c.realpath(rel_z.ptr, &abs_buf) orelse return error.RealpathFailed);

    var w = try Watcher.init(alloc, &.{abs});
    defer w.deinit();
    try std.testing.expect(w.mac_stream != null);
    iox.sleep(300 * std.time.ns_per_ms); // let the stream settle before acting

    {
        var f = try tmp.dir.createFile(io, "a.txt", .{});
        try f.writePositionalAll(io, "hello", 0);
        f.close(io);
    }
    iox.sleep(1500 * std.time.ns_per_ms); // separate latency windows so flags do not coalesce
    try tmp.dir.rename("a.txt", tmp.dir, "b.txt", io);
    iox.sleep(1500 * std.time.ns_per_ms);
    try tmp.dir.deleteFile(io, "b.txt");

    var seen = std.StringHashMap(void).init(alloc);
    defer seen.deinit();
    var all: std.array_list.Managed(u8) = .init(alloc);
    defer all.deinit();
    var attempt: usize = 0;
    while (attempt < 20 and !seen.contains("delete")) : (attempt += 1) {
        iox.sleep(500 * std.time.ns_per_ms);
        const events = try w.collectEvents();
        defer {
            for (events) |p| alloc.free(p);
            alloc.free(events);
        }
        for (events) |payload| {
            try all.appendSlice(payload);
            try all.append('\n');
            var parsed = try std.json.parseFromSlice(std.json.Value, alloc, payload, .{});
            defer parsed.deinit();
            const o = parsed.value.object;
            const path = o.get("path").?.string;
            try std.testing.expect(std.mem.startsWith(u8, path, abs));
            try std.testing.expectEqualStrings(abs, o.get("watch").?.string);
            const action = o.get("action").?.string;
            const key = if (std.mem.eql(u8, action, "create")) "create" else if (std.mem.eql(u8, action, "moved_from")) "moved_from" else if (std.mem.eql(u8, action, "moved_to")) "moved_to" else if (std.mem.eql(u8, action, "delete")) "delete" else "other";
            try seen.put(key, {});
        }
    }
    errdefer std.debug.print("fs events seen:\n{s}\n", .{all.items});
    try std.testing.expect(seen.contains("create"));
    try std.testing.expect(seen.contains("moved_from"));
    try std.testing.expect(seen.contains("moved_to"));
    try std.testing.expect(seen.contains("delete"));
}
