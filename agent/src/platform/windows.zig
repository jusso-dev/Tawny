const std = @import("std");

pub const ProcessInfo = struct {
    pid: u32,
    ppid: u32,
    name: []u8,
    command_line: []u8,
};

const TH32CS_SNAPPROCESS: u32 = 0x00000002;
const INVALID_HANDLE_VALUE: std.os.windows.HANDLE = @ptrFromInt(@as(usize, 0) -% 1);

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

extern "kernel32" fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) callconv(.C) std.os.windows.HANDLE;
extern "kernel32" fn Process32FirstW(hSnapshot: std.os.windows.HANDLE, lppe: *PROCESSENTRY32W) callconv(.C) i32;
extern "kernel32" fn Process32NextW(hSnapshot: std.os.windows.HANDLE, lppe: *PROCESSENTRY32W) callconv(.C) i32;
extern "kernel32" fn CloseHandle(hObject: std.os.windows.HANDLE) callconv(.C) i32;

pub fn enumerateProcesses(alloc: std.mem.Allocator) ![]ProcessInfo {
    const snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return error.SnapshotFailed;
    defer _ = CloseHandle(snap);

    var entry: PROCESSENTRY32W = std.mem.zeroes(PROCESSENTRY32W);
    entry.dwSize = @sizeOf(PROCESSENTRY32W);

    var list = std.ArrayList(ProcessInfo).init(alloc);
    errdefer {
        for (list.items) |p| {
            alloc.free(p.name);
            alloc.free(p.command_line);
        }
        list.deinit();
    }

    if (Process32FirstW(snap, &entry) == 0) return list.toOwnedSlice();
    while (true) {
        const wide_name = std.mem.sliceTo(&entry.szExeFile, 0);
        const name = try std.unicode.utf16LeToUtf8Alloc(alloc, wide_name);
        errdefer alloc.free(name);
        const command_line = try alloc.dupe(u8, name);
        errdefer alloc.free(command_line);
        try list.append(.{
            .pid = entry.th32ProcessID,
            .ppid = entry.th32ParentProcessID,
            .name = name,
            .command_line = command_line,
        });
        if (Process32NextW(snap, &entry) == 0) break;
    }

    return list.toOwnedSlice();
}
