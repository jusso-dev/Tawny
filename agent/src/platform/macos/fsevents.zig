//! FSEvents file-level watcher (CoreServices), user mode only.
//!
//! The stream runs on its own serial dispatch queue; its callback filters
//! events to the configured roots, classifies them, and pushes them into a
//! fixed-capacity queue guarded by an os_unfair_lock. The agent's 5 s
//! fs_events collector drains that queue, so the main loop never blocks on
//! FSEvents and memory stays bounded. Events that arrive while the queue is
//! full are counted and surfaced as one `overflow` event with `dropped`.
//!
//! Differences from Linux inotify (documented in fs_events.zig as well):
//! - FSEvents is recursive: a watched directory reports its whole subtree.
//! - Flags are coalesced per path within the latency window, so one event can
//!   be e.g. created+modified. `action` is the best single label; `flags`
//!   carries every flag FSEvents reported.
//! - Renames arrive as unpaired per-path events. We label the side that no
//!   longer exists `moved_from` and the side that exists `moved_to`; there
//!   is no cookie to pair them.
//! - Paths are reported through the configured root (e.g. /etc/hosts), not
//!   the firmlinked real path (/private/etc/hosts) FSEvents delivers.

const std = @import("std");
const iox = @import("../../io_compat.zig");

pub const queue_capacity: usize = 4096;
const max_roots: usize = 4096;
const latency_seconds: f64 = 1.0;

// --- CoreFoundation / CoreServices / libdispatch -------------------------

const CFIndex = isize;
const CFTypeRef = *anyopaque;
const FSEventStreamRef = *anyopaque;
const dispatch_queue_t = *anyopaque;
const kCFStringEncodingUTF8: u32 = 0x08000100;
const kFSEventStreamEventIdSinceNow: u64 = 0xFFFFFFFFFFFFFFFF;
const kFSEventStreamCreateFlagNoDefer: u32 = 0x02;
const kFSEventStreamCreateFlagWatchRoot: u32 = 0x04;
const kFSEventStreamCreateFlagFileEvents: u32 = 0x10;

const FSEventStreamContext = extern struct {
    version: CFIndex = 0,
    info: ?*anyopaque,
    retain: ?*const anyopaque = null,
    release: ?*const anyopaque = null,
    copyDescription: ?*const anyopaque = null,
};

const Callback = *const fn (
    stream: ?FSEventStreamRef,
    info: ?*anyopaque,
    num_events: usize,
    event_paths: ?*anyopaque,
    event_flags: [*]const u32,
    event_ids: [*]const u64,
) callconv(.c) void;

/// CoreServices/CoreFoundation entry points, resolved at runtime with dlopen.
/// Linking the frameworks would need the macOS SDK at build time, and the
/// release pipeline cross-compiles both macOS targets on Linux without one.
/// libSystem (libdispatch, libc) is always linked, so those stay `extern`.
const Api = struct {
    CFStringCreateWithCString: *const fn (alloc: ?*anyopaque, c_str: [*:0]const u8, encoding: u32) callconv(.c) ?CFTypeRef,
    CFArrayCreate: *const fn (alloc: ?*anyopaque, values: [*]const ?*const anyopaque, num_values: CFIndex, callbacks: ?*const anyopaque) callconv(.c) ?CFTypeRef,
    CFRelease: *const fn (cf: CFTypeRef) callconv(.c) void,
    kCFTypeArrayCallBacks: *const anyopaque,
    FSEventStreamCreate: *const fn (
        alloc: ?*anyopaque,
        callback: Callback,
        context: *const FSEventStreamContext,
        paths: CFTypeRef,
        since_when: u64,
        latency: f64,
        flags: u32,
    ) callconv(.c) ?FSEventStreamRef,
    FSEventStreamSetDispatchQueue: *const fn (stream: FSEventStreamRef, queue: ?dispatch_queue_t) callconv(.c) void,
    FSEventStreamStart: *const fn (stream: FSEventStreamRef) callconv(.c) u8,
    FSEventStreamStop: *const fn (stream: FSEventStreamRef) callconv(.c) void,
    FSEventStreamInvalidate: *const fn (stream: FSEventStreamRef) callconv(.c) void,
    FSEventStreamRelease: *const fn (stream: FSEventStreamRef) callconv(.c) void,

    fn load() !Api {
        const RTLD_LAZY: c_int = 0x1;
        const RTLD_LOCAL: c_int = 0x4;
        const cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_LAZY | RTLD_LOCAL) orelse return error.CoreFoundationUnavailable;
        const cs = dlopen("/System/Library/Frameworks/CoreServices.framework/CoreServices", RTLD_LAZY | RTLD_LOCAL) orelse return error.CoreServicesUnavailable;
        // Handles stay open for the life of the process (frameworks never unload).
        var api: Api = undefined;
        inline for (@typeInfo(Api).@"struct".field_names) |name| {
            const handle = if (comptime std.mem.startsWith(u8, name, "CF") or std.mem.startsWith(u8, name, "kCF")) cf else cs;
            const sym = dlsym(handle, name) orelse return error.SymbolMissing;
            @field(api, name) = @ptrCast(@alignCast(sym));
        }
        return api;
    }
};

extern "c" fn dlopen(path: [*:0]const u8, mode: c_int) ?*anyopaque;
extern "c" fn dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) ?*anyopaque;
extern "c" fn dispatch_queue_create(label: [*:0]const u8, attr: ?*anyopaque) ?dispatch_queue_t;
extern "c" fn dispatch_sync_f(queue: dispatch_queue_t, context: ?*anyopaque, work: *const fn (?*anyopaque) callconv(.c) void) void;
extern "c" fn dispatch_release(object: dispatch_queue_t) void;
extern "c" fn faccessat(fd: c_int, path: [*:0]const u8, mode: c_int, flag: c_int) c_int;
extern "c" fn realpath(path: [*:0]const u8, resolved: [*]u8) ?[*:0]u8;

const AT_FDCWD: c_int = -2;
const AT_SYMLINK_NOFOLLOW: c_int = 0x20;
const F_OK: c_int = 0;

// --- Event flags (FSEvents.h) ---------------------------------------------

pub const Flag = struct {
    pub const must_scan_subdirs: u32 = 0x1;
    pub const user_dropped: u32 = 0x2;
    pub const kernel_dropped: u32 = 0x4;
    pub const root_changed: u32 = 0x20;
    pub const created: u32 = 0x100;
    pub const removed: u32 = 0x200;
    pub const inode_meta_mod: u32 = 0x400;
    pub const renamed: u32 = 0x800;
    pub const modified: u32 = 0x1000;
    pub const finder_info_mod: u32 = 0x2000;
    pub const change_owner: u32 = 0x4000;
    pub const xattr_mod: u32 = 0x8000;
    pub const is_dir: u32 = 0x20000;
};

const flag_names = [_]struct { bit: u32, name: []const u8 }{
    .{ .bit = Flag.must_scan_subdirs, .name = "must_scan_subdirs" },
    .{ .bit = Flag.user_dropped, .name = "user_dropped" },
    .{ .bit = Flag.kernel_dropped, .name = "kernel_dropped" },
    .{ .bit = Flag.root_changed, .name = "root_changed" },
    .{ .bit = Flag.created, .name = "created" },
    .{ .bit = Flag.removed, .name = "removed" },
    .{ .bit = Flag.inode_meta_mod, .name = "inode_meta_mod" },
    .{ .bit = Flag.renamed, .name = "renamed" },
    .{ .bit = Flag.modified, .name = "modified" },
    .{ .bit = Flag.finder_info_mod, .name = "finder_info_mod" },
    .{ .bit = Flag.change_owner, .name = "change_owner" },
    .{ .bit = Flag.xattr_mod, .name = "xattr_mod" },
};

/// Write `"flag",...` names for the set bits (no brackets).
pub fn writeFlagNames(w: *std.Io.Writer, flags: u32) !void {
    var first = true;
    for (flag_names) |f| {
        if ((flags & f.bit) == 0) continue;
        if (!first) try w.writeByte(',');
        first = false;
        try w.print("\"{s}\"", .{f.name});
    }
}

/// Map coalesced FSEvents flags plus "does the path exist now" to the
/// action vocabulary Linux inotify events use.
pub fn classify(flags: u32, present: bool) []const u8 {
    if ((flags & (Flag.must_scan_subdirs | Flag.user_dropped | Flag.kernel_dropped)) != 0) return "overflow";
    if ((flags & Flag.removed) != 0 and !present) return "delete";
    if ((flags & Flag.renamed) != 0) return if (present) "moved_to" else "moved_from";
    if ((flags & Flag.created) != 0 and present) return "create";
    if ((flags & Flag.modified) != 0) return "modify";
    if ((flags & (Flag.inode_meta_mod | Flag.change_owner | Flag.xattr_mod | Flag.finder_info_mod)) != 0) return "attrib";
    if ((flags & Flag.removed) != 0) return "delete";
    if ((flags & Flag.created) != 0) return "create";
    return "other";
}

pub const Root = struct {
    /// Path as configured (what we report).
    configured: []const u8,
    /// realpath() of it (what FSEvents reports).
    real: []const u8,
    /// A single file: watch its directory, keep only exact matches.
    is_file: bool,

    /// If `path` is under this root, return the path re-expressed under the
    /// configured spelling's suffix (`path[real.len..]`).
    pub fn suffix(self: Root, path: []const u8) ?[]const u8 {
        if (!std.mem.startsWith(u8, path, self.real)) return null;
        const rest = path[self.real.len..];
        if (rest.len == 0) return rest;
        if (self.is_file) return null;
        if (rest[0] == '/') return rest;
        if (self.real.len > 0 and self.real[self.real.len - 1] == '/') return rest; // root "/"
        return null;
    }
};

pub const Event = struct {
    /// Owned by std.heap.c_allocator (allocated on the FSEvents thread).
    path: []u8,
    root_index: u32,
    flags: u32,
    action: []const u8,
};

const Shared = struct {
    lock: std.c.os_unfair_lock = .{},
    roots: []const Root,
    ring: [queue_capacity]Event = undefined,
    head: usize = 0,
    len: usize = 0,
    dropped: u64 = 0,

    fn push(self: *Shared, ev: Event) bool {
        std.c.os_unfair_lock_lock(&self.lock);
        defer std.c.os_unfair_lock_unlock(&self.lock);
        if (self.len == queue_capacity) {
            self.dropped += 1;
            return false;
        }
        self.ring[(self.head + self.len) % queue_capacity] = ev;
        self.len += 1;
        return true;
    }

    fn countDrop(self: *Shared) void {
        std.c.os_unfair_lock_lock(&self.lock);
        defer std.c.os_unfair_lock_unlock(&self.lock);
        self.dropped += 1;
    }
};

pub const Stream = struct {
    allocator: std.mem.Allocator,
    shared: *Shared,
    roots: []Root,
    stream: FSEventStreamRef,
    queue: dispatch_queue_t,
    api: Api,

    /// Start watching. Null when there is nothing to watch; an error when
    /// CoreServices is unavailable or FSEvents refuses the stream.
    pub fn start(alloc: std.mem.Allocator, paths: []const []const u8) !?*Stream {
        if (paths.len == 0) return null;
        const api = try Api.load();
        const bounded = paths[0..@min(paths.len, max_roots)];

        const roots = try alloc.alloc(Root, bounded.len);
        var built: usize = 0;
        errdefer {
            for (roots[0..built]) |r| freeRoot(alloc, r);
            alloc.free(roots);
        }
        for (bounded) |path| {
            roots[built] = try makeRoot(alloc, path);
            built += 1;
        }

        // Watch directories; files are watched through their parent.
        var cf_paths = try alloc.alloc(?*const anyopaque, roots.len);
        defer alloc.free(cf_paths);
        var cf_count: usize = 0;
        defer for (cf_paths[0..cf_count]) |p| api.CFRelease(@constCast(p.?));
        for (roots) |r| {
            const watch = if (r.is_file) (std.fs.path.dirname(r.real) orelse "/") else r.real;
            const z = try alloc.dupeSentinel(u8, watch, 0);
            defer alloc.free(z);
            const s = api.CFStringCreateWithCString(null, z.ptr, kCFStringEncodingUTF8) orelse continue;
            cf_paths[cf_count] = s;
            cf_count += 1;
        }
        if (cf_count == 0) return error.NoWatchablePaths;
        const array = api.CFArrayCreate(null, cf_paths.ptr, @intCast(cf_count), api.kCFTypeArrayCallBacks) orelse return error.CFArrayCreateFailed;
        defer api.CFRelease(array);

        const shared = try alloc.create(Shared);
        errdefer alloc.destroy(shared);
        shared.* = .{ .roots = roots };

        const self = try alloc.create(Stream);
        errdefer alloc.destroy(self);

        const context = FSEventStreamContext{ .info = shared };
        const stream = api.FSEventStreamCreate(
            null,
            &onEvents,
            &context,
            array,
            kFSEventStreamEventIdSinceNow,
            latency_seconds,
            kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer | kFSEventStreamCreateFlagWatchRoot,
        ) orelse return error.FSEventStreamCreateFailed;
        errdefer api.FSEventStreamRelease(stream);

        const queue = dispatch_queue_create("au.tawny.agent.fsevents", null) orelse return error.DispatchQueueCreateFailed;
        errdefer dispatch_release(queue);
        api.FSEventStreamSetDispatchQueue(stream, queue);
        if (api.FSEventStreamStart(stream) == 0) {
            api.FSEventStreamInvalidate(stream);
            return error.FSEventStreamStartFailed;
        }

        self.* = .{ .allocator = alloc, .shared = shared, .roots = roots, .stream = stream, .queue = queue, .api = api };
        return self;
    }

    pub fn stop(self: *Stream) void {
        self.api.FSEventStreamStop(self.stream);
        self.api.FSEventStreamInvalidate(self.stream);
        // Serial queue: once this no-op runs, no callback is still in flight.
        dispatch_sync_f(self.queue, null, &noop);
        self.api.FSEventStreamRelease(self.stream);
        dispatch_release(self.queue);

        const sh = self.shared;
        for (0..sh.len) |i| std.heap.c_allocator.free(sh.ring[(sh.head + i) % queue_capacity].path);

        const alloc = self.allocator;
        for (self.roots) |r| freeRoot(alloc, r);
        alloc.free(self.roots);
        alloc.destroy(self.shared);
        alloc.destroy(self);
    }

    pub const Drained = struct { count: usize, dropped: u64 };

    /// Move every queued event into `out` (caller frees each `path` with
    /// std.heap.c_allocator) and return how many were dropped since the
    /// last drain.
    pub fn drain(self: *Stream, out: *[queue_capacity]Event) Drained {
        const sh = self.shared;
        std.c.os_unfair_lock_lock(&sh.lock);
        defer std.c.os_unfair_lock_unlock(&sh.lock);
        const n = sh.len;
        for (0..n) |i| out[i] = sh.ring[(sh.head + i) % queue_capacity];
        sh.head = 0;
        sh.len = 0;
        const dropped = sh.dropped;
        sh.dropped = 0;
        return .{ .count = n, .dropped = dropped };
    }
};

fn noop(_: ?*anyopaque) callconv(.c) void {}

fn makeRoot(alloc: std.mem.Allocator, path: []const u8) !Root {
    const trimmed = std.mem.trimEnd(u8, path, "/");
    const spelled = if (trimmed.len == 0) "/" else trimmed;
    const configured = try alloc.dupe(u8, spelled);
    errdefer alloc.free(configured);

    const z = try alloc.dupeSentinel(u8, spelled, 0);
    defer alloc.free(z);
    var buf: [1024]u8 = undefined; // PATH_MAX
    const real = try alloc.dupe(u8, if (realpath(z.ptr, &buf)) |r| std.mem.span(r) else spelled);
    errdefer alloc.free(real);

    return .{ .configured = configured, .real = real, .is_file = exists(z) and !isDirectory(real) };
}

fn isDirectory(path: []const u8) bool {
    const io = iox.current();
    var dir = std.Io.Dir.openDirAbsolute(io, path, .{}) catch return false;
    dir.close(io);
    return true;
}

fn freeRoot(alloc: std.mem.Allocator, r: Root) void {
    alloc.free(r.configured);
    alloc.free(r.real);
}

fn exists(path: [*:0]const u8) bool {
    return faccessat(AT_FDCWD, path, F_OK, AT_SYMLINK_NOFOLLOW) == 0;
}

fn onEvents(
    _: ?FSEventStreamRef,
    info: ?*anyopaque,
    num_events: usize,
    event_paths: ?*anyopaque,
    event_flags: [*]const u32,
    _: [*]const u64,
) callconv(.c) void {
    const shared: *Shared = @ptrCast(@alignCast(info orelse return));
    const paths: [*]const [*:0]const u8 = @ptrCast(@alignCast(event_paths orelse return));
    const c_alloc = std.heap.c_allocator;

    for (0..num_events) |i| {
        const flags = event_flags[i];
        const path = std.mem.span(paths[i]);
        const is_overflow = (flags & (Flag.must_scan_subdirs | Flag.user_dropped | Flag.kernel_dropped)) != 0;

        var root_index: ?usize = null;
        for (shared.roots, 0..) |r, idx| {
            if (r.suffix(path) != null or (is_overflow and std.mem.startsWith(u8, r.real, std.mem.trimEnd(u8, path, "/")))) {
                root_index = idx;
                break;
            }
        }
        const idx = root_index orelse continue;

        const owned = c_alloc.dupe(u8, path) catch {
            shared.countDrop();
            continue;
        };
        const ev = Event{
            .path = owned,
            .root_index = @intCast(idx),
            .flags = flags,
            .action = classify(flags, exists(paths[i])),
        };
        if (!shared.push(ev)) c_alloc.free(owned);
    }
}

test "flag classification matches inotify vocabulary" {
    try std.testing.expectEqualStrings("create", classify(Flag.created, true));
    try std.testing.expectEqualStrings("delete", classify(Flag.created | Flag.removed, false));
    try std.testing.expectEqualStrings("delete", classify(Flag.removed, false));
    try std.testing.expectEqualStrings("moved_from", classify(Flag.renamed, false));
    try std.testing.expectEqualStrings("moved_to", classify(Flag.renamed, true));
    try std.testing.expectEqualStrings("modify", classify(Flag.modified, true));
    try std.testing.expectEqualStrings("attrib", classify(Flag.change_owner, true));
    try std.testing.expectEqualStrings("attrib", classify(Flag.xattr_mod | Flag.inode_meta_mod, true));
    try std.testing.expectEqualStrings("overflow", classify(Flag.kernel_dropped, false));
    try std.testing.expectEqualStrings("overflow", classify(Flag.must_scan_subdirs | Flag.modified, true));
    try std.testing.expectEqualStrings("other", classify(0, true));

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeFlagNames(&out.writer, Flag.created | Flag.modified);
    try std.testing.expectEqualStrings("\"created\",\"modified\"", out.written());
}

test "root matching maps real paths back to the configured spelling" {
    const dir = Root{ .configured = "/etc", .real = "/private/etc", .is_file = false };
    try std.testing.expectEqualStrings("/hosts", dir.suffix("/private/etc/hosts").?);
    try std.testing.expectEqualStrings("", dir.suffix("/private/etc").?);
    try std.testing.expect(dir.suffix("/private/etcetera/x") == null);
    try std.testing.expect(dir.suffix("/private/var/x") == null);

    const file = Root{ .configured = "/etc/hosts", .real = "/private/etc/hosts", .is_file = true };
    try std.testing.expectEqualStrings("", file.suffix("/private/etc/hosts").?);
    try std.testing.expect(file.suffix("/private/etc/hosts.bak") == null);
    try std.testing.expect(file.suffix("/private/etc/hosts/x") == null);

    const slash = Root{ .configured = "/", .real = "/", .is_file = false };
    try std.testing.expectEqualStrings("tmp/x", slash.suffix("/tmp/x").?);
}
