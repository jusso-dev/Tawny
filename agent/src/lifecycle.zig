//! Process-wide shutdown flag shared by the run loop, the Windows service
//! control handler and POSIX signal handlers.
const std = @import("std");
const builtin = @import("builtin");

var stop_flag: std.atomic.Value(bool) = .init(false);

pub fn requestStop() void {
    stop_flag.store(true, .release);
}

pub fn shouldStop() bool {
    return stop_flag.load(.acquire);
}

/// Install SIGTERM/SIGINT handlers that request a clean shutdown. The handler
/// only performs an atomic store, which is async-signal-safe.
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
    requestStop();
}

test "stop flag round-trips" {
    const before = shouldStop();
    defer stop_flag.store(before, .release);
    stop_flag.store(false, .release);
    try std.testing.expect(!shouldStop());
    requestStop();
    try std.testing.expect(shouldStop());
}
