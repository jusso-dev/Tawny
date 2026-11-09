//! Windows process response actions (#57): kill, suspend, resume, with a PID
//! reuse identity guard and a critical-process refusal list.
//!
//! Kill uses OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION)
//! then TerminateProcess; an already-gone process is a success. Suspend and
//! resume use NtSuspendProcess / NtResumeProcess from ntdll. The identity
//! guard compares QueryFullProcessImageNameW and GetProcessTimes against the
//! action's image path and start time, so a reused PID is refused.
//!
//! The pure `isCriticalProcess` check runs on every OS and is tested
//! everywhere; the live calls are Windows only.

const std = @import("std");
const builtin = @import("builtin");

/// Windows processes that must never be killed or suspended, plus the Tawny
/// agent itself. Compared case-insensitively against the image base name.
pub const critical_processes = [_][]const u8{
    "csrss.exe",
    "wininit.exe",
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "winlogon.exe",
    "system",
    "tawny-agent.exe",
};

/// Base name after the last `/` or `\`, so Windows paths split correctly on
/// every host (POSIX basename ignores backslashes).
fn baseName(path: []const u8) []const u8 {
    var start: usize = 0;
    for (path, 0..) |c, i| {
        if (c == '/' or c == '\\') start = i + 1;
    }
    return path[start..];
}

/// True when the image base name is on the critical list. `image` may be a
/// full path or a bare name.
pub fn isCriticalProcess(image: []const u8) bool {
    const base = baseName(image);
    for (critical_processes) |crit| {
        if (std.ascii.eqlIgnoreCase(base, crit)) return true;
    }
    return false;
}

pub const Error = error{
    CriticalProcessRefused,
    ProcessIdentityMismatch,
    ProcessIdentityUnavailable,
    OpenProcessFailed,
    TerminateFailed,
    SuspendFailed,
    ResumeFailed,
    InvalidPid,
};

pub const Identity = struct {
    image_path: ?[]const u8 = null,
    start_time_unix: ?i64 = null,
};

const WINAPI: std.lang.CallingConvention = .winapi;
const HANDLE = std.os.windows.HANDLE;
const PROCESS_TERMINATE: u32 = 0x0001;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
const STILL_ACTIVE: u32 = 259;
const ERROR_INVALID_PARAMETER: u32 = 87;

const FILETIME = extern struct {
    dwLowDateTime: u32,
    dwHighDateTime: u32,
};

extern "kernel32" fn OpenProcess(access: u32, inherit: i32, pid: u32) callconv(WINAPI) ?HANDLE;
extern "kernel32" fn CloseHandle(h: HANDLE) callconv(WINAPI) i32;
extern "kernel32" fn TerminateProcess(h: HANDLE, code: u32) callconv(WINAPI) i32;
extern "kernel32" fn GetExitCodeProcess(h: HANDLE, code: *u32) callconv(WINAPI) i32;
extern "kernel32" fn GetLastError() callconv(WINAPI) u32;
extern "kernel32" fn QueryFullProcessImageNameW(h: HANDLE, flags: u32, name: [*]u16, size: *u32) callconv(WINAPI) i32;
extern "kernel32" fn GetProcessTimes(h: HANDLE, creation: *FILETIME, exit: *FILETIME, kernel: *FILETIME, user: *FILETIME) callconv(WINAPI) i32;
extern "ntdll" fn NtSuspendProcess(h: HANDLE) callconv(WINAPI) i32;
extern "ntdll" fn NtResumeProcess(h: HANDLE) callconv(WINAPI) i32;

fn filetimeToUnix(ft: FILETIME) i64 {
    const ticks: u64 = (@as(u64, ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    const epoch_delta: u64 = 116_444_736_000_000_000; // 1601 -> 1970 in 100ns
    if (ticks < epoch_delta) return 0;
    return @intCast((ticks - epoch_delta) / 10_000_000);
}

/// Open a handle and check the live process matches the action's identity.
/// Caller closes the handle. Returns null with a success "already gone" when
/// the process cannot be opened because it has exited.
fn openChecked(alloc: std.mem.Allocator, pid: u32, access: u32, id: Identity) Error!?HANDLE {
    const h = OpenProcess(access | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) orelse return null;
    errdefer _ = CloseHandle(h);

    if (id.image_path) |want| {
        var buf: [32768]u16 = undefined;
        var size: u32 = buf.len;
        if (QueryFullProcessImageNameW(h, 0, &buf, &size) == 0) return error.ProcessIdentityUnavailable;
        const actual = std.unicode.utf16LeToUtf8Alloc(alloc, buf[0..size]) catch return error.ProcessIdentityUnavailable;
        defer alloc.free(actual);
        if (!pathsMatch(want, actual)) return error.ProcessIdentityMismatch;
    }
    if (id.start_time_unix) |want_start| {
        var creation: FILETIME = undefined;
        var exit: FILETIME = undefined;
        var kernel: FILETIME = undefined;
        var user: FILETIME = undefined;
        if (GetProcessTimes(h, &creation, &exit, &kernel, &user) == 0) return error.ProcessIdentityUnavailable;
        const actual_start = filetimeToUnix(creation);
        if (@abs(actual_start - want_start) > 2) return error.ProcessIdentityMismatch;
    }
    return h;
}

fn pathsMatch(expected: []const u8, actual: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(expected, actual)) return true;
    const exp_base = std.fs.path.basename(expected);
    const act_base = std.fs.path.basename(actual);
    return std.ascii.eqlIgnoreCase(exp_base, act_base);
}

pub const Outcome = enum { done, already_gone };

const Op = enum { terminate, do_suspend, do_resume };

/// Kill a process. An already-gone process is a success. Windows only; other
/// OSes report the identity guard as unavailable (the caller uses signals).
pub fn kill(alloc: std.mem.Allocator, pid: u32, id: Identity) Error!Outcome {
    return switch (builtin.target.os.tag) {
        .windows => run(alloc, pid, id, .terminate),
        else => error.ProcessIdentityUnavailable,
    };
}

pub fn suspend_(alloc: std.mem.Allocator, pid: u32, id: Identity) Error!Outcome {
    return switch (builtin.target.os.tag) {
        .windows => run(alloc, pid, id, .do_suspend),
        else => error.ProcessIdentityUnavailable,
    };
}

pub fn resume_(alloc: std.mem.Allocator, pid: u32, id: Identity) Error!Outcome {
    return switch (builtin.target.os.tag) {
        .windows => run(alloc, pid, id, .do_resume),
        else => error.ProcessIdentityUnavailable,
    };
}

fn run(alloc: std.mem.Allocator, pid: u32, id: Identity, op: Op) Error!Outcome {
    if (pid == 0) return error.InvalidPid;
    if (id.image_path) |p| if (isCriticalProcess(p)) return error.CriticalProcessRefused;
    const access: u32 = if (op == .terminate) PROCESS_TERMINATE else PROCESS_SUSPEND_RESUME;
    const maybe = try openChecked(alloc, pid, access, id);
    const h = maybe orelse return .already_gone;
    defer _ = CloseHandle(h);
    switch (op) {
        .terminate => if (TerminateProcess(h, 1) == 0) {
            // A process that exits between open and terminate still counts gone.
            var code: u32 = 0;
            if (GetExitCodeProcess(h, &code) != 0 and code != STILL_ACTIVE) return .already_gone;
            return error.TerminateFailed;
        },
        .do_suspend => if (NtSuspendProcess(h) != 0) return error.SuspendFailed,
        .do_resume => if (NtResumeProcess(h) != 0) return error.ResumeFailed,
    }
    return .done;
}

test "critical process list matches by base name, case-insensitive, on every OS" {
    try std.testing.expect(isCriticalProcess("lsass.exe"));
    try std.testing.expect(isCriticalProcess("LSASS.EXE"));
    try std.testing.expect(isCriticalProcess("C:\\Windows\\System32\\csrss.exe"));
    try std.testing.expect(isCriticalProcess("System"));
    try std.testing.expect(isCriticalProcess("tawny-agent.exe"));
    try std.testing.expect(!isCriticalProcess("notepad.exe"));
    try std.testing.expect(!isCriticalProcess("C:\\tmp\\evil.exe"));
}

test "filetime to unix is zero before the epoch" {
    try std.testing.expectEqual(@as(i64, 0), filetimeToUnix(.{ .dwLowDateTime = 0, .dwHighDateTime = 0 }));
    // 1970-01-01 in 100ns since 1601.
    const ft = FILETIME{ .dwLowDateTime = @truncate(116_444_736_000_000_000), .dwHighDateTime = @truncate(116_444_736_000_000_000 >> 32) };
    try std.testing.expectEqual(@as(i64, 0), filetimeToUnix(ft));
}
