//! Thin wevtapi wrapper: pull subscriptions with a signal event, rendered
//! event XML, and bookmarks. Windows only; the parser (evtxml.zig) and the
//! mappers (collectors/windows_events.zig) are pure and tested everywhere.
const std = @import("std");

const WINAPI: std.lang.CallingConvention = .winapi;
const HANDLE = std.os.windows.HANDLE;
const EVT_HANDLE = ?*anyopaque;
const EVT_SUBSCRIBE_CALLBACK = ?*const fn (action: u32, context: ?*anyopaque, event: EVT_HANDLE) callconv(WINAPI) u32;

const EvtSubscribeToFutureEvents: u32 = 1;
const EvtSubscribeStartAtOldestRecord: u32 = 2;
const EvtSubscribeStartAfterBookmark: u32 = 3;
const EvtRenderEventXml: u32 = 1;
const EvtRenderBookmark: u32 = 2;

const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_TIMEOUT: u32 = 1460;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_EVT_INVALID_CHANNEL_PATH: u32 = 15002;
const ERROR_EVT_CHANNEL_NOT_FOUND: u32 = 15007;

fn isMissingChannel(code: u32) bool {
    return code == ERROR_EVT_CHANNEL_NOT_FOUND or code == ERROR_EVT_INVALID_CHANNEL_PATH or code == ERROR_FILE_NOT_FOUND;
}
const ERROR_EVT_INVALID_QUERY: u32 = 15001;
const WAIT_OBJECT_0: u32 = 0;

extern "wevtapi" fn EvtSubscribe(
    session: EVT_HANDLE,
    signal_event: ?HANDLE,
    channel_path: ?[*:0]const u16,
    query: ?[*:0]const u16,
    bookmark: EVT_HANDLE,
    context: ?*anyopaque,
    callback: EVT_SUBSCRIBE_CALLBACK,
    flags: u32,
) callconv(WINAPI) EVT_HANDLE;
extern "wevtapi" fn EvtNext(
    result_set: EVT_HANDLE,
    events_size: u32,
    events: [*]EVT_HANDLE,
    timeout: u32,
    flags: u32,
    returned: *u32,
) callconv(WINAPI) i32;
extern "wevtapi" fn EvtRender(
    context: EVT_HANDLE,
    fragment: EVT_HANDLE,
    flags: u32,
    buffer_size: u32,
    buffer: ?*anyopaque,
    buffer_used: *u32,
    property_count: *u32,
) callconv(WINAPI) i32;
extern "wevtapi" fn EvtCreateBookmark(bookmark_xml: ?[*:0]const u16) callconv(WINAPI) EVT_HANDLE;
extern "wevtapi" fn EvtUpdateBookmark(bookmark: EVT_HANDLE, event: EVT_HANDLE) callconv(WINAPI) i32;
extern "wevtapi" fn EvtClose(object: EVT_HANDLE) callconv(WINAPI) i32;

extern "kernel32" fn CreateEventW(attrs: ?*anyopaque, manual_reset: i32, initial_state: i32, name: ?[*:0]const u16) callconv(WINAPI) ?HANDLE;
extern "kernel32" fn ResetEvent(event: HANDLE) callconv(WINAPI) i32;
extern "kernel32" fn WaitForSingleObject(handle: HANDLE, ms: u32) callconv(WINAPI) u32;
extern "kernel32" fn CloseHandle(handle: HANDLE) callconv(WINAPI) i32;
extern "kernel32" fn GetLastError() callconv(WINAPI) u32;

var last_error: u32 = 0;

/// Win32 error code from the last failed call in this module.
pub fn lastError() u32 {
    return last_error;
}

fn fail(comptime err: anytype) @TypeOf(err) {
    last_error = GetLastError();
    return err;
}

pub const StartMode = enum {
    /// No bookmark: only events logged after subscribing (the agent).
    future,
    /// No bookmark: every matching record still in the log (debug dump).
    oldest,
};

pub const Pulled = struct {
    count: usize,
    /// True when the per-call cap stopped the read with events left.
    capped: bool,
};

pub const Subscription = struct {
    allocator: std.mem.Allocator,
    handle: EVT_HANDLE,
    signal: HANDLE,
    bookmark: EVT_HANDLE,
    render_buf: []u8,

    /// Subscribe to `channel` with an XPath `query`. Resumes after
    /// `bookmark_xml` when given. Without EvtSubscribeStrict, a bookmarked
    /// record the log no longer holds (cleared or wrapped) resumes at the
    /// closest later record; a bookmark that cannot be used falls back to
    /// `mode`.
    pub fn open(
        alloc: std.mem.Allocator,
        channel: []const u8,
        query: []const u8,
        bookmark_xml: ?[]const u8,
        mode: StartMode,
    ) !Subscription {
        const channel_w = try std.unicode.utf8ToUtf16LeAllocZ(alloc, channel);
        defer alloc.free(channel_w);
        const query_w = try std.unicode.utf8ToUtf16LeAllocZ(alloc, query);
        defer alloc.free(query_w);

        const signal = CreateEventW(null, 1, 1, null) orelse return fail(error.SubscribeFailed);
        errdefer _ = CloseHandle(signal);

        var bookmark: EVT_HANDLE = null;
        var handle: EVT_HANDLE = null;
        if (bookmark_xml) |xml| {
            const xml_w = try std.unicode.utf8ToUtf16LeAllocZ(alloc, xml);
            defer alloc.free(xml_w);
            bookmark = EvtCreateBookmark(xml_w.ptr);
            if (bookmark != null) {
                handle = EvtSubscribe(null, signal, channel_w.ptr, query_w.ptr, bookmark, null, null, EvtSubscribeStartAfterBookmark);
                if (handle == null) {
                    last_error = GetLastError();
                    _ = EvtClose(bookmark);
                    bookmark = null;
                    if (isMissingChannel(last_error)) return error.ChannelNotFound;
                    if (last_error == ERROR_ACCESS_DENIED) return error.AccessDenied;
                }
            }
        }
        if (handle == null) {
            bookmark = EvtCreateBookmark(null);
            if (bookmark == null) return fail(error.SubscribeFailed);
            const flags = switch (mode) {
                .future => EvtSubscribeToFutureEvents,
                .oldest => EvtSubscribeStartAtOldestRecord,
            };
            handle = EvtSubscribe(null, signal, channel_w.ptr, query_w.ptr, null, null, null, flags);
            if (handle == null) {
                last_error = GetLastError();
                _ = EvtClose(bookmark);
                if (isMissingChannel(last_error)) return error.ChannelNotFound;
                return switch (last_error) {
                    ERROR_ACCESS_DENIED => error.AccessDenied,
                    ERROR_EVT_INVALID_QUERY => error.InvalidQuery,
                    else => error.SubscribeFailed,
                };
            }
        }
        errdefer _ = EvtClose(handle);
        errdefer _ = EvtClose(bookmark);
        return .{
            .allocator = alloc,
            .handle = handle,
            .signal = signal,
            .bookmark = bookmark,
            .render_buf = try alloc.alloc(u8, 16 * 1024),
        };
    }

    pub fn deinit(self: *Subscription) void {
        _ = EvtClose(self.handle);
        _ = EvtClose(self.bookmark);
        _ = CloseHandle(self.signal);
        self.allocator.free(self.render_buf);
        self.* = undefined;
    }

    /// Read up to `max` events without blocking, appending their rendered
    /// XML (UTF-8, caller frees) to `out`. The in-memory bookmark advances
    /// past each event read; persist it with `bookmarkXml` once the events
    /// are safely queued.
    pub fn pull(self: *Subscription, out: *std.array_list.Managed([]u8), max: usize) !Pulled {
        return self.pullWait(out, max, 0);
    }

    /// As `pull`, but waits once, up to `wait_ms`, for the signal when the
    /// subscription has nothing to read yet.
    pub fn pullWait(self: *Subscription, out: *std.array_list.Managed([]u8), max: usize, wait_ms: u32) !Pulled {
        var count: usize = 0;
        var waited = wait_ms == 0;
        var batch: [32]EVT_HANDLE = undefined;
        while (count < max) {
            const want: u32 = @intCast(@min(batch.len, max - count));
            var returned: u32 = 0;
            if (EvtNext(self.handle, want, &batch, 0, 0, &returned) == 0) {
                const err = GetLastError();
                if (err == ERROR_NO_MORE_ITEMS or err == ERROR_TIMEOUT) {
                    _ = ResetEvent(self.signal);
                    if (!waited and count == 0) {
                        waited = true;
                        if (WaitForSingleObject(self.signal, wait_ms) == WAIT_OBJECT_0) continue;
                    }
                    return .{ .count = count, .capped = false };
                }
                last_error = err;
                return error.PullFailed;
            }
            defer for (batch[0..returned]) |ev| {
                _ = EvtClose(ev);
            };
            for (batch[0..returned]) |ev| {
                const xml = self.render(ev, EvtRenderEventXml) catch |err| switch (err) {
                    error.OutOfMemory => return err,
                    // Skip one unrenderable record rather than stalling the channel.
                    else => {
                        _ = EvtUpdateBookmark(self.bookmark, ev);
                        continue;
                    },
                };
                errdefer self.allocator.free(xml);
                try out.append(xml);
                _ = EvtUpdateBookmark(self.bookmark, ev);
                count += 1;
            }
        }
        return .{ .count = count, .capped = true };
    }

    /// Current bookmark as XML (UTF-8, caller frees).
    pub fn bookmarkXml(self: *Subscription) ![]u8 {
        return self.render(self.bookmark, EvtRenderBookmark);
    }

    fn render(self: *Subscription, fragment: EVT_HANDLE, flags: u32) ![]u8 {
        var used: u32 = 0;
        var props: u32 = 0;
        if (EvtRender(null, fragment, flags, @intCast(self.render_buf.len), self.render_buf.ptr, &used, &props) == 0) {
            const err = GetLastError();
            if (err != ERROR_INSUFFICIENT_BUFFER) {
                last_error = err;
                return error.RenderFailed;
            }
            // Grow (bounded by the 1 MiB XML parser limit, times two for UTF-16).
            if (used > 2 * 1024 * 1024 + 2) return error.RenderFailed;
            const bigger = try self.allocator.alloc(u8, used);
            self.allocator.free(self.render_buf);
            self.render_buf = bigger;
            if (EvtRender(null, fragment, flags, @intCast(self.render_buf.len), self.render_buf.ptr, &used, &props) == 0) {
                last_error = GetLastError();
                return error.RenderFailed;
            }
        }
        const units = used / 2;
        const aligned: []align(1) const u16 = std.mem.bytesAsSlice(u16, self.render_buf[0 .. units * 2]);
        var wide = try self.allocator.alloc(u16, aligned.len);
        defer self.allocator.free(wide);
        for (aligned, 0..) |c, k| wide[k] = std.mem.littleToNative(u16, c);
        const trimmed = std.mem.sliceTo(wide, 0);
        return std.unicode.wtf16LeToWtf8Alloc(self.allocator, trimmed);
    }
};
