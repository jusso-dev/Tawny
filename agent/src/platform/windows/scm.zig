//! Service Control Manager queries for tamper checks (#58). Constants and
//! signatures checked against windows-rs `Win32/winsvc/mod.rs`; values are
//! pinned by a test that runs on every OS.
const std = @import("std");
const builtin = @import("builtin");

const WINAPI: std.lang.CallingConvention = .winapi;
const SC_HANDLE = *opaque {};

pub const SC_MANAGER_CONNECT: u32 = 1;
pub const SERVICE_QUERY_STATUS: u32 = 4;
pub const SERVICE_STOPPED: u32 = 1;
pub const SERVICE_RUNNING: u32 = 4;
pub const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;

const SERVICE_STATUS = extern struct {
    dwServiceType: u32,
    dwCurrentState: u32,
    dwControlsAccepted: u32,
    dwWin32ExitCode: u32,
    dwServiceSpecificExitCode: u32,
    dwCheckPoint: u32,
    dwWaitHint: u32,
};

const impl = if (builtin.target.os.tag == .windows) struct {
    extern "advapi32" fn OpenSCManagerW(machine: ?[*:0]const u16, database: ?[*:0]const u16, access: u32) callconv(WINAPI) ?SC_HANDLE;
    extern "advapi32" fn OpenServiceW(scm: SC_HANDLE, name: [*:0]const u16, access: u32) callconv(WINAPI) ?SC_HANDLE;
    extern "advapi32" fn QueryServiceStatus(service: SC_HANDLE, status: *SERVICE_STATUS) callconv(WINAPI) i32;
    extern "advapi32" fn CloseServiceHandle(handle: SC_HANDLE) callconv(WINAPI) i32;
    extern "kernel32" fn GetLastError() callconv(WINAPI) u32;
} else struct {};

pub const ServiceState = enum { not_installed, stopped, running, other, unknown };

/// Current state of a service by name. `unknown` when the SCM can't be read.
pub fn serviceState(comptime name: []const u8) ServiceState {
    if (builtin.target.os.tag != .windows) return .unknown;
    const name_w = std.unicode.utf8ToUtf16LeStringLiteral(name);
    const scm = impl.OpenSCManagerW(null, null, SC_MANAGER_CONNECT) orelse return .unknown;
    defer _ = impl.CloseServiceHandle(scm);
    const svc = impl.OpenServiceW(scm, name_w, SERVICE_QUERY_STATUS) orelse {
        return if (impl.GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) .not_installed else .unknown;
    };
    defer _ = impl.CloseServiceHandle(svc);
    var st: SERVICE_STATUS = std.mem.zeroes(SERVICE_STATUS);
    if (impl.QueryServiceStatus(svc, &st) == 0) return .unknown;
    return fromCurrentState(st.dwCurrentState);
}

pub fn fromCurrentState(state: u32) ServiceState {
    return switch (state) {
        SERVICE_RUNNING => .running,
        SERVICE_STOPPED => .stopped,
        else => .other,
    };
}

/// Sysmon installs as `Sysmon64` on 64-bit Windows and `Sysmon` otherwise.
pub fn sysmonState() ServiceState {
    const a = serviceState("Sysmon64");
    if (a != .not_installed) return a;
    return serviceState("Sysmon");
}

test "winsvc constants match windows-rs" {
    try std.testing.expectEqual(@as(u32, 1), SC_MANAGER_CONNECT);
    try std.testing.expectEqual(@as(u32, 4), SERVICE_QUERY_STATUS);
    try std.testing.expectEqual(@as(u32, 1), SERVICE_STOPPED);
    try std.testing.expectEqual(@as(u32, 4), SERVICE_RUNNING);
    try std.testing.expectEqual(@as(u32, 1060), ERROR_SERVICE_DOES_NOT_EXIST);
    try std.testing.expectEqual(@as(usize, 28), @sizeOf(SERVICE_STATUS));
    try std.testing.expectEqual(ServiceState.running, fromCurrentState(4));
    try std.testing.expectEqual(ServiceState.other, fromCurrentState(3));
}
