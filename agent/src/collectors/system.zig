const std = @import("std");
const builtin = @import("builtin");

pub fn collect(alloc: std.mem.Allocator) ![]u8 {
    return switch (builtin.os.tag) {
        .macos => collectMacos(alloc),
        .windows => collectWindows(alloc),
        .linux => collectLinux(alloc),
        else => @compileError("unsupported os"),
    };
}

const c = if (builtin.os.tag == .macos) @cImport({
    @cInclude("sys/sysctl.h");
    @cInclude("sys/utsname.h");
}) else struct {};

fn collectMacos(alloc: std.mem.Allocator) ![]u8 {
    var uts: c.utsname = undefined;
    if (c.uname(&uts) != 0) return error.UnameFailed;

    const mem_bytes = sysctlU64("hw.memsize") catch 0;
    const cpu_count = sysctlU32("hw.ncpu") catch 0;
    const brand = try sysctlString(alloc, "machdep.cpu.brand_string");
    defer alloc.free(brand);

    var out = std.ArrayList(u8).init(alloc);
    errdefer out.deinit();
    var w = out.writer();

    try w.writeAll("{\"platform\":\"macos\",\"hostname\":");
    try std.json.stringify(std.mem.sliceTo(&uts.nodename, 0), .{}, w);
    try w.writeAll(",\"kernel\":");
    try std.json.stringify(std.mem.sliceTo(&uts.release, 0), .{}, w);
    try w.writeAll(",\"architecture\":");
    try std.json.stringify(std.mem.sliceTo(&uts.machine, 0), .{}, w);
    try w.print(",\"memory_bytes\":{d},\"cpu_count\":{d},\"cpu_brand\":", .{ mem_bytes, cpu_count });
    try std.json.stringify(brand, .{}, w);
    try w.writeByte('}');

    return out.toOwnedSlice();
}

fn collectLinux(alloc: std.mem.Allocator) ![]u8 {
    const hostname_raw = readFileAlloc(alloc, "/proc/sys/kernel/hostname", 4 * 1024) catch
        try alloc.dupe(u8, "");
    defer alloc.free(hostname_raw);
    const kernel_raw = readFileAlloc(alloc, "/proc/sys/kernel/osrelease", 4 * 1024) catch
        try alloc.dupe(u8, "");
    defer alloc.free(kernel_raw);
    const meminfo = readFileAlloc(alloc, "/proc/meminfo", 64 * 1024) catch
        try alloc.dupe(u8, "");
    defer alloc.free(meminfo);
    const cpuinfo = readFileAlloc(alloc, "/proc/cpuinfo", 512 * 1024) catch
        try alloc.dupe(u8, "");
    defer alloc.free(cpuinfo);

    const hostname = std.mem.trim(u8, hostname_raw, " \t\r\n");
    const kernel = std.mem.trim(u8, kernel_raw, " \t\r\n");
    const mem_bytes = linuxMemTotalBytes(meminfo);
    const cpu_count = linuxCpuCount(cpuinfo);
    const cpu_brand = linuxCpuBrand(cpuinfo);

    var out = std.ArrayList(u8).init(alloc);
    errdefer out.deinit();
    var w = out.writer();

    try w.writeAll("{\"platform\":\"linux\",\"hostname\":");
    try std.json.stringify(hostname, .{}, w);
    try w.writeAll(",\"kernel\":");
    try std.json.stringify(kernel, .{}, w);
    try w.writeAll(",\"architecture\":");
    try std.json.stringify(@tagName(builtin.cpu.arch), .{}, w);
    try w.print(",\"memory_bytes\":{d},\"cpu_count\":{d},\"cpu_brand\":", .{ mem_bytes, cpu_count });
    try std.json.stringify(cpu_brand, .{}, w);
    try w.writeByte('}');

    return out.toOwnedSlice();
}

fn readFileAlloc(alloc: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    var file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    return file.readToEndAlloc(alloc, max_bytes);
}

fn linuxMemTotalBytes(meminfo: []const u8) u64 {
    var lines = std.mem.splitScalar(u8, meminfo, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "MemTotal:")) continue;
        var fields = std.mem.tokenizeAny(u8, line["MemTotal:".len..], " \t");
        const kb = std.fmt.parseInt(u64, fields.next() orelse "0", 10) catch 0;
        return kb * 1024;
    }
    return 0;
}

fn linuxCpuCount(cpuinfo: []const u8) u32 {
    var count: u32 = 0;
    var lines = std.mem.splitScalar(u8, cpuinfo, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "processor")) count += 1;
    }
    return count;
}

fn linuxCpuBrand(cpuinfo: []const u8) []const u8 {
    var lines = std.mem.splitScalar(u8, cpuinfo, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "model name")) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        return std.mem.trim(u8, line[colon + 1 ..], " \t");
    }
    return "";
}

fn sysctlU64(name: [:0]const u8) !u64 {
    var value: u64 = 0;
    var len: usize = @sizeOf(u64);
    if (c.sysctlbyname(name.ptr, &value, &len, null, 0) != 0) return error.SysctlFailed;
    return value;
}

fn sysctlU32(name: [:0]const u8) !u32 {
    var value: u32 = 0;
    var len: usize = @sizeOf(u32);
    if (c.sysctlbyname(name.ptr, &value, &len, null, 0) != 0) return error.SysctlFailed;
    return value;
}

fn sysctlString(alloc: std.mem.Allocator, name: [:0]const u8) ![]u8 {
    var len: usize = 0;
    if (c.sysctlbyname(name.ptr, null, &len, null, 0) != 0 or len == 0) {
        return alloc.dupe(u8, "");
    }
    var buf = try alloc.alloc(u8, len);
    defer alloc.free(buf);
    if (c.sysctlbyname(name.ptr, buf.ptr, &len, null, 0) != 0) return error.SysctlFailed;
    return alloc.dupe(u8, std.mem.sliceTo(buf[0..len], 0));
}

const COMPUTER_NAME_FORMAT = enum(u32) {
    ComputerNameDnsHostname = 1,
};

const RTL_OSVERSIONINFOW = extern struct {
    dwOSVersionInfoSize: u32,
    dwMajorVersion: u32,
    dwMinorVersion: u32,
    dwBuildNumber: u32,
    dwPlatformId: u32,
    szCSDVersion: [128]u16,
};

const MEMORYSTATUSEX = extern struct {
    dwLength: u32,
    dwMemoryLoad: u32,
    ullTotalPhys: u64,
    ullAvailPhys: u64,
    ullTotalPageFile: u64,
    ullAvailPageFile: u64,
    ullTotalVirtual: u64,
    ullAvailVirtual: u64,
    ullAvailExtendedVirtual: u64,
};

extern "kernel32" fn GetComputerNameExW(NameType: COMPUTER_NAME_FORMAT, lpBuffer: ?[*]u16, nSize: *u32) callconv(.C) i32;
extern "kernel32" fn GlobalMemoryStatusEx(lpBuffer: *MEMORYSTATUSEX) callconv(.C) i32;
extern "ntdll" fn RtlGetVersion(lpVersionInformation: *RTL_OSVERSIONINFOW) callconv(.C) i32;

fn collectWindows(alloc: std.mem.Allocator) ![]u8 {
    var name_len: u32 = 0;
    _ = GetComputerNameExW(.ComputerNameDnsHostname, null, &name_len);
    var name_buf = try alloc.alloc(u16, name_len + 1);
    defer alloc.free(name_buf);
    if (GetComputerNameExW(.ComputerNameDnsHostname, name_buf.ptr, &name_len) == 0) return error.ComputerNameFailed;
    const hostname = try std.unicode.utf16LeToUtf8Alloc(alloc, name_buf[0..name_len]);
    defer alloc.free(hostname);

    var version = std.mem.zeroes(RTL_OSVERSIONINFOW);
    version.dwOSVersionInfoSize = @sizeOf(RTL_OSVERSIONINFOW);
    _ = RtlGetVersion(&version);

    var mem = std.mem.zeroes(MEMORYSTATUSEX);
    mem.dwLength = @sizeOf(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&mem) == 0) return error.MemoryStatusFailed;

    var out = std.ArrayList(u8).init(alloc);
    errdefer out.deinit();
    var w = out.writer();

    try w.writeAll("{\"platform\":\"windows\",\"hostname\":");
    try std.json.stringify(hostname, .{}, w);
    try w.print(
        ",\"major\":{d},\"minor\":{d},\"build\":{d},\"memory_bytes\":{d}}}",
        .{ version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber, mem.ullTotalPhys },
    );

    return out.toOwnedSlice();
}

test "system collector module loads" {
    _ = collect;
}

test "linux proc parsers" {
    try std.testing.expectEqual(@as(u64, 1024 * 1024), linuxMemTotalBytes("MemTotal:        1024 kB\n"));
    try std.testing.expectEqual(@as(u32, 2), linuxCpuCount("processor\t: 0\nprocessor\t: 1\n"));
    try std.testing.expectEqualStrings("Sample CPU", linuxCpuBrand("model name\t: Sample CPU\n"));
}
