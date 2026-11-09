//! Process-wide shutdown flag shared by the run loop, the Windows service
//! control handler and POSIX signal handlers, plus the clean shutdown marker.
//!
//! Clean shutdown marker (#58): when the run loop stops because the service
//! manager or a signal asked it to, the agent writes `<state>.clean` and sends
//! a final heartbeat with `shutdown: true`. On the next start the agent reads
//! and removes the marker. If it is missing (crash, kill -9, `taskkill /f`,
//! power loss, or someone stopping the process outside the service manager)
//! the agent sends an `agent_tamper` event with check `unexpected_stop`.
const std = @import("std");
const builtin = @import("builtin");
const iox = @import("io_compat.zig");

var stop_flag: std.atomic.Value(bool) = .init(false);
/// Why the stop was requested, for the shutdown notice.
var stop_reason: std.atomic.Value(u8) = .init(@backingInt(StopReason.none));

pub const StopReason = enum(u8) {
    none,
    service_stop,
    system_shutdown,
    signal,
    update_restart,

    pub fn text(self: StopReason) []const u8 {
        return @tagName(self);
    }
};

pub fn requestStop() void {
    requestStopFor(.signal);
}

pub fn requestStopFor(why: StopReason) void {
    _ = stop_reason.cmpxchgStrong(@backingInt(StopReason.none), @backingInt(why), .acq_rel, .acquire);
    stop_flag.store(true, .release);
}

pub fn shouldStop() bool {
    return stop_flag.load(.acquire);
}

pub fn reason() StopReason {
    return @fromBackingInt(@intCast(stop_reason.load(.acquire)));
}

/// Install SIGTERM/SIGINT handlers that request a clean shutdown. The handler
/// only performs atomic stores, which are async-signal-safe.
pub fn installPosixSignalHandlers() void {
    if (builtin.target.os.tag == .windows) return;
    const act: std.posix.Sigaction = .{
        .handler = .{ .handler = handleSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.TERM, &act, null);
    std.posix.sigaction(.INT, &act, null);
}

fn handleSignal(_: std.posix.SIG) callconv(.c) void {
    requestStopFor(.signal);
}

// ---------------------------------------------------------------------------
// Clean shutdown marker

pub fn markerPath(alloc: std.mem.Allocator, state_path: []const u8) ![]u8 {
    return alloc.print("{s}.clean", .{state_path});
}

pub const StartKind = enum {
    /// First run on this host (no state yet): nothing to compare.
    first_run,
    /// The last run wrote the marker.
    clean,
    /// The last run did not write the marker.
    unexpected,
};

/// Read and remove the marker. `enrolled_before` is false on the very first
/// start, when no marker can exist yet.
pub fn consumeMarker(alloc: std.mem.Allocator, state_path: []const u8, enrolled_before: bool) StartKind {
    const path = markerPath(alloc, state_path) catch return if (enrolled_before) .unexpected else .first_run;
    defer alloc.free(path);
    const io = iox.current();
    const cwd = std.Io.Dir.cwd();
    const present = blk: {
        const f = cwd.openFile(io, path, .{}) catch break :blk false;
        f.close(io);
        break :blk true;
    };
    if (present) cwd.deleteFile(io, path) catch {};
    if (present) return .clean;
    return if (enrolled_before) .unexpected else .first_run;
}

/// Write the marker with the stop reason and time. Best effort.
pub fn writeMarker(alloc: std.mem.Allocator, state_path: []const u8, why: StopReason) void {
    const path = markerPath(alloc, state_path) catch return;
    defer alloc.free(path);
    var buf: [96]u8 = undefined;
    const body = std.fmt.bufPrint(&buf, "reason={s}\nat={d}\n", .{ why.text(), iox.timestamp() }) catch return;
    std.Io.Dir.cwd().writeFile(iox.current(), .{ .sub_path = path, .data = body }) catch |err| {
        std.debug.print("clean shutdown marker not written: {s}\n", .{@errorName(err)});
    };
}

test "stop flag round-trips and keeps the first reason" {
    const before = shouldStop();
    defer {
        stop_flag.store(before, .release);
        stop_reason.store(@backingInt(StopReason.none), .release);
    }
    stop_flag.store(false, .release);
    stop_reason.store(@backingInt(StopReason.none), .release);
    try std.testing.expect(!shouldStop());
    requestStopFor(.service_stop);
    requestStopFor(.signal);
    try std.testing.expect(shouldStop());
    try std.testing.expectEqual(StopReason.service_stop, reason());
}

test "clean shutdown marker: written, consumed once, missing means unexpected" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const state = try std.fs.path.join(a, &.{ ".zig-cache", "tmp", &tmp.sub_path, "state.toml" });
    defer a.free(state);

    try std.testing.expectEqual(StartKind.first_run, consumeMarker(a, state, false));
    try std.testing.expectEqual(StartKind.unexpected, consumeMarker(a, state, true));
    writeMarker(a, state, .service_stop);
    try std.testing.expectEqual(StartKind.clean, consumeMarker(a, state, true));
    // Consumed: a crash after this start shows as unexpected next time.
    try std.testing.expectEqual(StartKind.unexpected, consumeMarker(a, state, true));
}
