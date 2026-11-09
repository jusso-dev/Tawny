const std = @import("std");

pub const ProcessInfo = struct {
    pid: u32,
    ppid: u32,
    name: []u8,
    /// Empty when it cannot be read (protected process, exited, access
    /// denied). Never a copy of the name.
    command_line: []u8,
    start_time_unix: ?i64 = null,
    image_path: ?[]u8 = null,
};

const WINAPI: std.lang.CallingConvention = .winapi;
const HANDLE = std.os.windows.HANDLE;
const TH32CS_SNAPPROCESS: u32 = 0x00000002;
const INVALID_HANDLE_VALUE: HANDLE = @ptrFromInt(@as(usize, 0) -% 1);
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const ProcessCommandLineInformation: u32 = 60;
/// Command lines are capped at 32767 UTF-16 units; 64 KiB plus the
/// UNICODE_STRING header always fits.
const max_command_line_query_bytes: u32 = 64 * 1024 + 64;

const PROCESSENTRY32W = extern struct {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [260]u16,
};

const FILETIME = extern struct {
    dwLowDateTime: u32,
    dwHighDateTime: u32,
};

const UNICODE_STRING = extern struct {
    Length: u16,
    MaximumLength: u16,
    Buffer: ?[*]u16,
};

extern "kernel32" fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) callconv(.c) HANDLE;
extern "kernel32" fn Process32FirstW(hSnapshot: HANDLE, lppe: *PROCESSENTRY32W) callconv(.c) i32;
extern "kernel32" fn Process32NextW(hSnapshot: HANDLE, lppe: *PROCESSENTRY32W) callconv(.c) i32;
extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(.c) i32;
extern "kernel32" fn OpenProcess(access: u32, inherit: i32, pid: u32) callconv(WINAPI) ?HANDLE;
extern "kernel32" fn QueryFullProcessImageNameW(process: HANDLE, flags: u32, name: [*]u16, size: *u32) callconv(WINAPI) i32;
extern "kernel32" fn GetProcessTimes(process: HANDLE, creation: *FILETIME, exit: *FILETIME, kernel: *FILETIME, user: *FILETIME) callconv(WINAPI) i32;
extern "ntdll" fn NtQueryInformationProcess(process: HANDLE, class: u32, info: *anyopaque, len: u32, ret_len: ?*u32) callconv(WINAPI) i32;

pub fn enumerateProcesses(alloc: std.mem.Allocator) ![]ProcessInfo {
    const snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return error.SnapshotFailed;
    defer _ = CloseHandle(snap);

    var entry: PROCESSENTRY32W = std.mem.zeroes(PROCESSENTRY32W);
    entry.dwSize = @sizeOf(PROCESSENTRY32W);

    var list = std.array_list.Managed(ProcessInfo).init(alloc);
    errdefer {
        freeEntries(alloc, list.items);
        list.deinit();
    }

    // One scratch buffer reused for every command-line query.
    const query_buf = try alloc.alignedAlloc(u8, .of(UNICODE_STRING), max_command_line_query_bytes);
    defer alloc.free(query_buf);

    if (Process32FirstW(snap, &entry) == 0) return list.toOwnedSlice();
    while (true) {
        const wide_name = std.mem.sliceTo(&entry.szExeFile, 0);
        const name = try std.unicode.wtf16LeToWtf8Alloc(alloc, wide_name);
        errdefer alloc.free(name);
        var info = ProcessInfo{
            .pid = entry.th32ProcessID,
            .ppid = entry.th32ParentProcessID,
            .name = name,
            .command_line = &.{},
        };
        try enrich(alloc, &info, query_buf);
        errdefer {
            alloc.free(info.command_line);
            if (info.image_path) |p| alloc.free(p);
        }
        try list.append(info);
        if (Process32NextW(snap, &entry) == 0) break;
    }

    return list.toOwnedSlice();
}

pub fn freeProcesses(alloc: std.mem.Allocator, procs: []ProcessInfo) void {
    freeEntries(alloc, procs);
    alloc.free(procs);
}

fn freeEntries(alloc: std.mem.Allocator, procs: []const ProcessInfo) void {
    for (procs) |p| {
        alloc.free(p.name);
        alloc.free(p.command_line);
        if (p.image_path) |path| alloc.free(path);
    }
}

/// Fill image path, start time and command line where the process can be
/// opened. PID 0 (Idle) and protected processes fail quietly.
fn enrich(alloc: std.mem.Allocator, info: *ProcessInfo, query_buf: []align(@alignOf(UNICODE_STRING)) u8) !void {
    if (info.pid == 0) return;
    const process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, info.pid) orelse return;
    defer _ = CloseHandle(process);

    // Long enough for long-path-aware images; longer paths are left out.
    var path_buf: [4096]u16 = undefined;
    var path_len: u32 = path_buf.len;
    if (QueryFullProcessImageNameW(process, 0, &path_buf, &path_len) != 0 and path_len > 0) {
        info.image_path = try std.unicode.wtf16LeToWtf8Alloc(alloc, path_buf[0..path_len]);
    }
    errdefer if (info.image_path) |p| {
        alloc.free(p);
        info.image_path = null;
    };

    var creation: FILETIME = undefined;
    var exit_time: FILETIME = undefined;
    var kernel: FILETIME = undefined;
    var user: FILETIME = undefined;
    if (GetProcessTimes(process, &creation, &exit_time, &kernel, &user) != 0) {
        info.start_time_unix = filetimeToUnix(creation);
    }

    var ret_len: u32 = 0;
    const status = NtQueryInformationProcess(process, ProcessCommandLineInformation, query_buf.ptr, @intCast(query_buf.len), &ret_len);
    if (status >= 0) {
        if (commandLineFromQuery(query_buf)) |wide| {
            info.command_line = try std.unicode.wtf16LeToWtf8Alloc(alloc, wide);
        }
    }
}

/// The UTF-16 text a ProcessCommandLineInformation query returned: a
/// UNICODE_STRING whose buffer points inside the same allocation.
fn commandLineFromQuery(buf: []align(@alignOf(UNICODE_STRING)) const u8) ?[]const u16 {
    if (buf.len < @sizeOf(UNICODE_STRING)) return null;
    const us: *const UNICODE_STRING = @ptrCast(buf.ptr);
    const ptr = us.Buffer orelse return null;
    const units = us.Length / 2;
    if (units == 0) return null;
    const start = @intFromPtr(ptr);
    const base = @intFromPtr(buf.ptr);
    if (start < base or start + @as(usize, units) * 2 > base + buf.len) return null;
    return ptr[0..units];
}

/// FILETIME (100 ns ticks since 1601-01-01) to unix seconds.
pub fn filetimeToUnix(ft: FILETIME) ?i64 {
    const ticks = (@as(u64, ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    const epoch_delta: u64 = 116_444_736_000_000_000;
    if (ticks < epoch_delta) return null;
    return @intCast((ticks - epoch_delta) / 10_000_000);
}

test "filetime converts to unix seconds" {
    // 2026-01-01T00:00:00Z
    const ticks: u64 = 116_444_736_000_000_000 + 1_767_225_600 * 10_000_000;
    const ft = FILETIME{ .dwLowDateTime = @truncate(ticks), .dwHighDateTime = @truncate(ticks >> 32) };
    try std.testing.expectEqual(@as(?i64, 1_767_225_600), filetimeToUnix(ft));
    try std.testing.expectEqual(@as(?i64, null), filetimeToUnix(.{ .dwLowDateTime = 0, .dwHighDateTime = 0 }));
}

test "command line query buffer is read within bounds" {
    var buf: [256]u8 align(@alignOf(UNICODE_STRING)) = undefined;
    const us: *UNICODE_STRING = @ptrCast(&buf);
    const text = std.unicode.utf8ToUtf16LeStringLiteral("cmd.exe /c whoami");
    const data: [*]u16 = @ptrCast(@alignCast(&buf[@sizeOf(UNICODE_STRING)]));
    @memcpy(data[0..text.len], text);
    us.* = .{ .Length = @intCast(text.len * 2), .MaximumLength = @intCast(text.len * 2), .Buffer = data };
    try std.testing.expectEqualSlices(u16, text, commandLineFromQuery(&buf).?);

    us.Length = 0;
    try std.testing.expect(commandLineFromQuery(&buf) == null);
    us.Length = 1000; // points past the buffer
    try std.testing.expect(commandLineFromQuery(&buf) == null);
}

test "enumerated processes carry command lines and start times" {
    const alloc = std.testing.allocator;
    const procs = try enumerateProcesses(alloc);
    defer freeProcesses(alloc, procs);
    const me = std.os.windows.GetCurrentProcessId();
    var found = false;
    for (procs) |p| {
        // Never the name copied into the command line.
        if (p.command_line.len > 0) try std.testing.expect(!std.mem.eql(u8, p.command_line, p.name));
        if (p.pid != me) continue;
        found = true;
        try std.testing.expect(p.command_line.len > 0);
        try std.testing.expect(p.start_time_unix.? > 1_600_000_000);
        try std.testing.expect(std.ascii.endsWithIgnoreCase(p.image_path.?, ".exe"));
    }
    try std.testing.expect(found);
}
