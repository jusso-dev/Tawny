const std = @import("std");
const builtin = @import("builtin");
const iox = @import("../io_compat.zig");

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

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;

    try w.writeAll("{\"platform\":\"macos\",\"hostname\":");
    try std.json.Stringify.value(std.mem.sliceTo(&uts.nodename, 0), .{}, w);
    try w.writeAll(",\"kernel\":");
    try std.json.Stringify.value(std.mem.sliceTo(&uts.release, 0), .{}, w);
    try w.writeAll(",\"architecture\":");
    try std.json.Stringify.value(std.mem.sliceTo(&uts.machine, 0), .{}, w);
    try w.print(",\"memory_bytes\":{d},\"cpu_count\":{d},\"cpu_brand\":", .{ mem_bytes, cpu_count });
    try std.json.Stringify.value(brand, .{}, w);
    try w.writeByte('}');

    return out.toOwnedSlice();
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

fn collectLinux(alloc: std.mem.Allocator) ![]u8 {
    const hostname_raw = readFileAbsoluteAlloc(alloc, "/proc/sys/kernel/hostname", 8 * 1024) catch
        try alloc.dupe(u8, "unknown");
    defer alloc.free(hostname_raw);
    const kernel_raw = readFileAbsoluteAlloc(alloc, "/proc/sys/kernel/osrelease", 8 * 1024) catch
        try alloc.dupe(u8, "unknown");
    defer alloc.free(kernel_raw);

    const mem_total_kb = readMemTotalKb(alloc) catch 0;
    const cpu_count = std.Thread.getCpuCount() catch 0;
    var ec2_identity = collectEc2Identity(alloc);
    defer if (ec2_identity) |*identity| identity.deinit(alloc);

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;

    try w.writeAll("{\"platform\":\"linux\",\"hostname\":");
    try std.json.Stringify.value(std.mem.trimEnd(u8, hostname_raw, "\r\n"), .{}, w);
    try w.writeAll(",\"kernel\":");
    try std.json.Stringify.value(std.mem.trimEnd(u8, kernel_raw, "\r\n"), .{}, w);
    try w.writeAll(",\"architecture\":");
    try std.json.Stringify.value(@tagName(builtin.target.cpu.arch), .{}, w);
    try w.print(",\"memory_bytes\":{d},\"cpu_count\":{d}", .{
        mem_total_kb * 1024,
        cpu_count,
    });
    if (ec2_identity) |*identity| try appendEc2Identity(w, identity);
    try w.writeByte('}');

    return out.toOwnedSlice();
}

const Ec2Identity = struct {
    instance_id: ?[]u8 = null,
    region: ?[]u8 = null,
    availability_zone: ?[]u8 = null,
    private_ipv4: ?[]u8 = null,
    public_ipv4: ?[]u8 = null,
    ipv6: ?[]u8 = null,
    private_hostname: ?[]u8 = null,
    public_hostname: ?[]u8 = null,
    network_macs: ?[]u8 = null,
    private_ipv4s: ?[]u8 = null,
    public_ipv4s: ?[]u8 = null,
    ipv6s: ?[]u8 = null,

    fn deinit(self: *Ec2Identity, alloc: std.mem.Allocator) void {
        if (self.instance_id) |value| alloc.free(value);
        if (self.region) |value| alloc.free(value);
        if (self.availability_zone) |value| alloc.free(value);
        if (self.private_ipv4) |value| alloc.free(value);
        if (self.public_ipv4) |value| alloc.free(value);
        if (self.ipv6) |value| alloc.free(value);
        if (self.private_hostname) |value| alloc.free(value);
        if (self.public_hostname) |value| alloc.free(value);
        if (self.network_macs) |value| alloc.free(value);
        if (self.private_ipv4s) |value| alloc.free(value);
        if (self.public_ipv4s) |value| alloc.free(value);
        if (self.ipv6s) |value| alloc.free(value);
    }
};

fn collectEc2Identity(alloc: std.mem.Allocator) ?Ec2Identity {
    if (!isAmazonEc2(alloc)) return null;

    const token = runCurl(alloc, &.{
        "curl",
        "--silent",
        "--show-error",
        "--fail",
        "--connect-timeout",
        "1",
        "--max-time",
        "2",
        "--noproxy",
        "*",
        "--request",
        "PUT",
        "--header",
        "X-aws-ec2-metadata-token-ttl-seconds: 21600",
        "http://169.254.169.254/latest/api/token",
    }) orelse return null;
    defer alloc.free(token);

    const token_header = std.fmt.allocPrint(
        alloc,
        "X-aws-ec2-metadata-token: {s}",
        .{token},
    ) catch return null;
    defer alloc.free(token_header);

    var identity = Ec2Identity{};
    identity.instance_id = fetchEc2Metadata(alloc, token_header, "instance-id");
    identity.region = fetchEc2Metadata(alloc, token_header, "placement/region");
    identity.availability_zone = fetchEc2Metadata(alloc, token_header, "placement/availability-zone");
    identity.private_ipv4 = fetchEc2Metadata(alloc, token_header, "local-ipv4");
    identity.public_ipv4 = fetchEc2Metadata(alloc, token_header, "public-ipv4");
    identity.ipv6 = fetchEc2Metadata(alloc, token_header, "ipv6");
    identity.private_hostname = fetchEc2Metadata(alloc, token_header, "local-hostname");
    identity.public_hostname = fetchEc2Metadata(alloc, token_header, "public-hostname");
    identity.network_macs = fetchEc2Metadata(alloc, token_header, "network/interfaces/macs/");
    if (identity.network_macs) |macs| {
        identity.private_ipv4s = fetchEc2InterfaceValues(alloc, token_header, macs, "local-ipv4s");
        identity.public_ipv4s = fetchEc2InterfaceValues(alloc, token_header, macs, "public-ipv4s");
        identity.ipv6s = fetchEc2InterfaceValues(alloc, token_header, macs, "ipv6s");
    }
    return identity;
}

fn isAmazonEc2(alloc: std.mem.Allocator) bool {
    const vendor = readFileAbsoluteAlloc(alloc, "/sys/class/dmi/id/sys_vendor", 4 * 1024) catch null;
    if (vendor) |value| {
        defer alloc.free(value);
        if (std.mem.indexOf(u8, value, "Amazon EC2") != null) return true;
    }

    const product_uuid = readFileAbsoluteAlloc(alloc, "/sys/class/dmi/id/product_uuid", 4 * 1024) catch null;
    if (product_uuid) |value| {
        defer alloc.free(value);
        if (std.ascii.startsWithIgnoreCase(std.mem.trim(u8, value, " \t\r\n"), "ec2")) return true;
    }

    const board_asset_tag = readFileAbsoluteAlloc(alloc, "/sys/class/dmi/id/board_asset_tag", 4 * 1024) catch null;
    if (board_asset_tag) |value| {
        defer alloc.free(value);
        return std.mem.startsWith(u8, std.mem.trim(u8, value, " \t\r\n"), "i-");
    }
    return false;
}

fn fetchEc2Metadata(
    alloc: std.mem.Allocator,
    token_header: []const u8,
    path: []const u8,
) ?[]u8 {
    const url = std.fmt.allocPrint(
        alloc,
        "http://169.254.169.254/latest/meta-data/{s}",
        .{path},
    ) catch return null;
    defer alloc.free(url);

    return runCurl(alloc, &.{
        "curl",
        "--silent",
        "--show-error",
        "--fail",
        "--connect-timeout",
        "1",
        "--max-time",
        "2",
        "--noproxy",
        "*",
        "--header",
        token_header,
        url,
    });
}

fn fetchEc2InterfaceValues(
    alloc: std.mem.Allocator,
    token_header: []const u8,
    macs_raw: []const u8,
    field: []const u8,
) ?[]u8 {
    var values = std.array_list.Managed(u8).init(alloc);
    defer values.deinit();

    var macs = std.mem.tokenizeAny(u8, macs_raw, " \t\r\n/");
    var count: usize = 0;
    while (macs.next()) |mac| {
        if (count >= 16) break;
        count += 1;

        const path = std.fmt.allocPrint(
            alloc,
            "network/interfaces/macs/{s}/{s}",
            .{ mac, field },
        ) catch continue;
        defer alloc.free(path);
        const result = fetchEc2Metadata(alloc, token_header, path) orelse continue;
        defer alloc.free(result);

        if (values.items.len > 0) values.append('\n') catch return null;
        values.appendSlice(result) catch return null;
    }

    if (values.items.len == 0) return null;
    return values.toOwnedSlice() catch null;
}

fn runCurl(alloc: std.mem.Allocator, argv: []const []const u8) ?[]u8 {
    const result = std.process.run(alloc, iox.current(), .{
        .argv = argv,
        .stdout_limit = .limited(16 * 1024),
        .stderr_limit = .limited(16 * 1024),
    }) catch return null;
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    const value = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (value.len == 0 or value.len > 4096) return null;
    return alloc.dupe(u8, value) catch null;
}

fn appendEc2Identity(writer: anytype, identity: *const Ec2Identity) !void {
    try writer.writeAll(",\"cloud\":{\"provider\":\"aws\",\"service\":\"ec2\"");
    try appendOptionalJsonField(writer, "instance_id", identity.instance_id);
    try appendOptionalJsonField(writer, "region", identity.region);
    try appendOptionalJsonField(writer, "availability_zone", identity.availability_zone);
    try appendOptionalJsonField(writer, "private_ipv4", identity.private_ipv4);
    try appendOptionalJsonField(writer, "public_ipv4", identity.public_ipv4);
    try appendOptionalJsonField(writer, "ipv6", identity.ipv6);
    try appendOptionalJsonField(writer, "private_hostname", identity.private_hostname);
    try appendOptionalJsonField(writer, "public_hostname", identity.public_hostname);
    try appendOptionalJsonList(writer, "network_macs", identity.network_macs);
    try appendOptionalJsonList(writer, "private_ipv4s", identity.private_ipv4s);
    try appendOptionalJsonList(writer, "public_ipv4s", identity.public_ipv4s);
    try appendOptionalJsonList(writer, "ipv6s", identity.ipv6s);
    try writer.writeByte('}');
}

fn appendOptionalJsonField(writer: anytype, name: []const u8, value: ?[]const u8) !void {
    if (value) |present| {
        try writer.writeByte(',');
        try std.json.Stringify.value(name, .{}, writer);
        try writer.writeByte(':');
        try std.json.Stringify.value(present, .{}, writer);
    }
}

fn appendOptionalJsonList(writer: anytype, name: []const u8, raw: ?[]const u8) !void {
    const present = raw orelse return;
    var values = std.mem.tokenizeAny(u8, present, " \t\r\n/");
    const first_value = values.next() orelse return;

    try writer.writeByte(',');
    try std.json.Stringify.value(name, .{}, writer);
    try writer.writeAll(":[");
    try std.json.Stringify.value(first_value, .{}, writer);
    while (values.next()) |value| {
        try writer.writeByte(',');
        try std.json.Stringify.value(value, .{}, writer);
    }
    try writer.writeByte(']');
}

fn readMemTotalKb(alloc: std.mem.Allocator) !u64 {
    const raw = try readFileAbsoluteAlloc(alloc, "/proc/meminfo", 64 * 1024);
    defer alloc.free(raw);

    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "MemTotal:")) continue;
        var parts = std.mem.tokenizeAny(u8, line, " \t");
        _ = parts.next();
        const value = parts.next() orelse return error.BadMemInfo;
        return std.fmt.parseInt(u64, value, 10);
    }
    return error.BadMemInfo;
}

fn readFileAbsoluteAlloc(alloc: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    const io = iox.current();
    var file = try std.Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);
    return iox.readToEndAlloc(file, alloc, max_bytes);
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

extern "kernel32" fn GetComputerNameExW(NameType: COMPUTER_NAME_FORMAT, lpBuffer: ?[*]u16, nSize: *u32) callconv(.c) i32;
extern "kernel32" fn GlobalMemoryStatusEx(lpBuffer: *MEMORYSTATUSEX) callconv(.c) i32;
extern "ntdll" fn RtlGetVersion(lpVersionInformation: *RTL_OSVERSIONINFOW) callconv(.c) i32;

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

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;

    try w.writeAll("{\"platform\":\"windows\",\"hostname\":");
    try std.json.Stringify.value(hostname, .{}, w);
    try w.print(
        ",\"major\":{d},\"minor\":{d},\"build\":{d},\"memory_bytes\":{d}}}",
        .{ version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber, mem.ullTotalPhys },
    );

    return out.toOwnedSlice();
}

test "system collector module loads" {
    _ = collect;
}

test "EC2 identity includes searchable public and private network identity" {
    var identity = Ec2Identity{
        .instance_id = try std.testing.allocator.dupe(u8, "i-0123456789abcdef0"),
        .region = try std.testing.allocator.dupe(u8, "ap-southeast-2"),
        .private_ipv4 = try std.testing.allocator.dupe(u8, "10.0.1.25"),
        .public_ipv4 = try std.testing.allocator.dupe(u8, "203.0.113.10"),
        .private_hostname = try std.testing.allocator.dupe(u8, "ip-10-0-1-25.ap-southeast-2.compute.internal"),
        .public_hostname = try std.testing.allocator.dupe(u8, "ec2-203-0-113-10.ap-southeast-2.compute.amazonaws.com"),
        .network_macs = try std.testing.allocator.dupe(u8, "0a:11:22:33:44:55/\n0a:66:77:88:99:aa/"),
        .private_ipv4s = try std.testing.allocator.dupe(u8, "10.0.1.25\n10.0.1.26"),
        .public_ipv4s = try std.testing.allocator.dupe(u8, "203.0.113.10\n203.0.113.11"),
    };
    defer identity.deinit(std.testing.allocator);

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try appendEc2Identity(&out.writer, &identity);

    try std.testing.expect(std.mem.indexOf(u8, out.written(), "203.0.113.10") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "10.0.1.25") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "10.0.1.26") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "203.0.113.11") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "compute.amazonaws.com") != null);
}
