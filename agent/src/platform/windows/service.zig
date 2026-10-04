//! Windows Service Control Manager integration.
//!
//! `runDispatcher` connects the process to the SCM. When the binary was not
//! launched by the SCM (console / scheduled task / developer shell) the call
//! fails with ERROR_FAILED_SERVICE_CONTROLLER_CONNECT and the caller runs the
//! agent in the foreground instead.
const std = @import("std");
const lifecycle = @import("../../lifecycle.zig");

pub const service_name = "TawnyAgent";
const service_name_w = std.unicode.utf8ToUtf16LeStringLiteral(service_name);

pub const RunFn = *const fn (alloc: std.mem.Allocator) anyerror!void;

const WINAPI: std.lang.CallingConvention = .winapi;
const SERVICE_STATUS_HANDLE = *opaque {};

const SERVICE_WIN32_OWN_PROCESS: u32 = 0x00000010;

const SERVICE_STOPPED: u32 = 1;
const SERVICE_START_PENDING: u32 = 2;
const SERVICE_STOP_PENDING: u32 = 3;
const SERVICE_RUNNING: u32 = 4;

const SERVICE_ACCEPT_STOP: u32 = 0x00000001;
const SERVICE_ACCEPT_SHUTDOWN: u32 = 0x00000004;
const SERVICE_ACCEPT_PRESHUTDOWN: u32 = 0x00000100;

const SERVICE_CONTROL_STOP: u32 = 0x00000001;
const SERVICE_CONTROL_INTERROGATE: u32 = 0x00000004;
const SERVICE_CONTROL_SHUTDOWN: u32 = 0x00000005;
const SERVICE_CONTROL_PRESHUTDOWN: u32 = 0x0000000F;

const NO_ERROR: u32 = 0;
const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
const ERROR_SERVICE_SPECIFIC_ERROR: u32 = 1066;
pub const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: u32 = 1063;

/// Covers a final in-flight HTTP flush (http_timeout_seconds default 30s).
const stop_wait_hint_ms: u32 = 45_000;
const start_wait_hint_ms: u32 = 30_000;

const SERVICE_STATUS = extern struct {
    dwServiceType: u32,
    dwCurrentState: u32,
    dwControlsAccepted: u32,
    dwWin32ExitCode: u32,
    dwServiceSpecificExitCode: u32,
    dwCheckPoint: u32,
    dwWaitHint: u32,
};

const ServiceMainFn = *const fn (argc: u32, argv: ?[*]?[*:0]u16) callconv(WINAPI) void;
const HandlerExFn = *const fn (control: u32, event_type: u32, event_data: ?*anyopaque, context: ?*anyopaque) callconv(WINAPI) u32;

const SERVICE_TABLE_ENTRYW = extern struct {
    lpServiceName: ?[*:0]const u16,
    lpServiceProc: ?ServiceMainFn,
};

extern "advapi32" fn StartServiceCtrlDispatcherW(table: [*]const SERVICE_TABLE_ENTRYW) callconv(WINAPI) i32;
extern "advapi32" fn RegisterServiceCtrlHandlerExW(
    name: [*:0]const u16,
    handler: HandlerExFn,
    context: ?*anyopaque,
) callconv(WINAPI) ?SERVICE_STATUS_HANDLE;
extern "advapi32" fn SetServiceStatus(handle: SERVICE_STATUS_HANDLE, status: *SERVICE_STATUS) callconv(WINAPI) i32;
extern "kernel32" fn GetLastError() callconv(WINAPI) u32;

var g_alloc: std.mem.Allocator = undefined;
var g_run: RunFn = undefined;
var g_status_handle: ?SERVICE_STATUS_HANDLE = null;
var g_checkpoint: std.atomic.Value(u32) = .init(0);
var g_status_lock: std.atomic.Mutex = .unlocked;

pub const DispatchResult = enum { ran_as_service, not_a_service };

/// Blocks until the service stops when launched by the SCM. Returns
/// `.not_a_service` when the process is running interactively.
pub fn runDispatcher(alloc: std.mem.Allocator, run: RunFn) !DispatchResult {
    g_alloc = alloc;
    g_run = run;
    const table = [_]SERVICE_TABLE_ENTRYW{
        .{ .lpServiceName = service_name_w, .lpServiceProc = serviceMain },
        .{ .lpServiceName = null, .lpServiceProc = null },
    };
    if (StartServiceCtrlDispatcherW(&table) != 0) return .ran_as_service;
    const err = GetLastError();
    if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) return .not_a_service;
    std.debug.print("StartServiceCtrlDispatcherW failed: win32 error {d}\n", .{err});
    return error.ServiceDispatcherFailed;
}

fn serviceMain(_: u32, _: ?[*]?[*:0]u16) callconv(WINAPI) void {
    g_status_handle = RegisterServiceCtrlHandlerExW(service_name_w, controlHandler, null);
    if (g_status_handle == null) return;

    reportStatus(SERVICE_START_PENDING, NO_ERROR, 0, start_wait_hint_ms);
    reportStatus(SERVICE_RUNNING, NO_ERROR, 0, 0);

    var service_exit: u32 = 0;
    g_run(g_alloc) catch |err| {
        std.debug.print("agent run failed: {s}\n", .{@errorName(err)});
        service_exit = 1;
    };

    // A non-zero service-specific exit code lets SCM failure actions (with
    // failureflag set) restart the agent after a fatal error.
    if (service_exit != 0) {
        reportStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, service_exit, 0);
    } else {
        reportStatus(SERVICE_STOPPED, NO_ERROR, 0, 0);
    }
}

fn controlHandler(control: u32, _: u32, _: ?*anyopaque, _: ?*anyopaque) callconv(WINAPI) u32 {
    switch (control) {
        SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_PRESHUTDOWN => {
            lifecycle.requestStop();
            reportStatus(SERVICE_STOP_PENDING, NO_ERROR, 0, stop_wait_hint_ms);
            return NO_ERROR;
        },
        SERVICE_CONTROL_INTERROGATE => return NO_ERROR,
        else => return ERROR_CALL_NOT_IMPLEMENTED,
    }
}

fn reportStatus(state: u32, win32_exit: u32, specific_exit: u32, wait_hint_ms: u32) void {
    const handle = g_status_handle orelse return;
    while (!g_status_lock.tryLock()) std.atomic.spinLoopHint();
    defer g_status_lock.unlock();

    var status = SERVICE_STATUS{
        .dwServiceType = SERVICE_WIN32_OWN_PROCESS,
        .dwCurrentState = state,
        .dwControlsAccepted = controlsAccepted(state),
        .dwWin32ExitCode = win32_exit,
        .dwServiceSpecificExitCode = specific_exit,
        .dwCheckPoint = if (isPending(state)) g_checkpoint.fetchAdd(1, .monotonic) + 1 else 0,
        .dwWaitHint = wait_hint_ms,
    };
    _ = SetServiceStatus(handle, &status);
}

fn isPending(state: u32) bool {
    return state == SERVICE_START_PENDING or state == SERVICE_STOP_PENDING;
}

fn controlsAccepted(state: u32) u32 {
    return if (state == SERVICE_RUNNING)
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN
    else
        0;
}

test "only the running state accepts stop controls" {
    try std.testing.expectEqual(@as(u32, 0), controlsAccepted(SERVICE_START_PENDING));
    try std.testing.expectEqual(@as(u32, 0), controlsAccepted(SERVICE_STOP_PENDING));
    try std.testing.expect(controlsAccepted(SERVICE_RUNNING) & SERVICE_ACCEPT_STOP != 0);
    try std.testing.expect(controlsAccepted(SERVICE_RUNNING) & SERVICE_ACCEPT_PRESHUTDOWN != 0);
}
