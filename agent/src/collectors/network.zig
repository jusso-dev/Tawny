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

fn collectLinux(alloc: std.mem.Allocator) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;

    try w.writeAll("{\"source\":\"procfs\",\"connections\":[");
    var first = true;
    try appendProcNetRows(alloc, w, "/proc/net/tcp", "tcp", &first);
    try appendProcNetRows(alloc, w, "/proc/net/tcp6", "tcp6", &first);
    try appendProcNetRows(alloc, w, "/proc/net/udp", "udp", &first);
    try appendProcNetRows(alloc, w, "/proc/net/udp6", "udp6", &first);
    try w.writeAll("],\"neighbors\":[");
    const arp = readFileAbsoluteAlloc(alloc, "/proc/net/arp", 512 * 1024) catch null;
    if (arp) |raw| {
        defer alloc.free(raw);
        try appendArpRows(w, raw);
    }
    try w.writeAll("],\"dns_servers\":[");
    const resolv_conf = readFileAbsoluteAlloc(alloc, "/etc/resolv.conf", 64 * 1024) catch null;
    defer if (resolv_conf) |raw| alloc.free(raw);
    if (resolv_conf) |raw| try appendResolvValues(w, raw, "nameserver");
    try w.writeAll("],\"search_domains\":[");
    if (resolv_conf) |raw| try appendResolvValues(w, raw, "search");
    try w.writeAll("],\"host_mappings\":[");
    const hosts = readFileAbsoluteAlloc(alloc, "/etc/hosts", 512 * 1024) catch null;
    if (hosts) |raw| {
        defer alloc.free(raw);
        try appendHostMappings(w, raw);
    }
    try w.writeAll("]}");

    return out.toOwnedSlice();
}

fn appendProcNetRows(
    alloc: std.mem.Allocator,
    writer: anytype,
    path: []const u8,
    protocol: []const u8,
    first: *bool,
) !void {
    const raw = readFileAbsoluteAlloc(alloc, path, 512 * 1024) catch return;
    defer alloc.free(raw);

    var lines = std.mem.splitScalar(u8, raw, '\n');
    _ = lines.next(); // header
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;
        if (!first.*) try writer.writeByte(',');
        first.* = false;

        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        _ = fields.next(); // slot
        const local = fields.next() orelse "";
        const remote = fields.next() orelse "";
        const state = fields.next() orelse "";
        const local_endpoint = try parseProcNetEndpoint(alloc, protocol, local);
        defer alloc.free(local_endpoint.address);
        const remote_endpoint = try parseProcNetEndpoint(alloc, protocol, remote);
        defer alloc.free(remote_endpoint.address);

        try writer.writeAll("{\"protocol\":");
        try std.json.Stringify.value(protocol, .{}, writer);
        try writer.writeAll(",\"local_address\":");
        try std.json.Stringify.value(local_endpoint.address, .{}, writer);
        try writer.print(",\"local_port\":{d}", .{local_endpoint.port});
        try writer.writeAll(",\"remote_address\":");
        try std.json.Stringify.value(remote_endpoint.address, .{}, writer);
        try writer.print(",\"remote_port\":{d}", .{remote_endpoint.port});
        try writer.writeAll(",\"state\":");
        try std.json.Stringify.value(state, .{}, writer);
        try writer.writeAll(",\"raw\":");
        try std.json.Stringify.value(line, .{}, writer);
        try writer.writeByte('}');
    }
}

const ProcNetEndpoint = struct {
    address: []u8,
    port: u16,
};

fn parseProcNetEndpoint(alloc: std.mem.Allocator, protocol: []const u8, endpoint: []const u8) !ProcNetEndpoint {
    const separator = std.mem.indexOfScalar(u8, endpoint, ':') orelse return .{
        .address = try alloc.dupe(u8, ""),
        .port = 0,
    };

    const address_hex = endpoint[0..separator];
    const port_hex = endpoint[separator + 1 ..];
    const port = std.fmt.parseInt(u16, port_hex, 16) catch 0;

    if (!std.mem.endsWith(u8, protocol, "6") and address_hex.len == 8) {
        const raw = std.fmt.parseInt(u32, address_hex, 16) catch 0;
        return .{
            .address = try std.fmt.allocPrint(
                alloc,
                "{d}.{d}.{d}.{d}",
                .{ raw & 0xff, (raw >> 8) & 0xff, (raw >> 16) & 0xff, (raw >> 24) & 0xff },
            ),
            .port = port,
        };
    }

    if (address_hex.len != 32) {
        return .{
            .address = try alloc.dupe(u8, address_hex),
            .port = port,
        };
    }

    var bytes: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, address_hex) catch {
        return .{
            .address = try alloc.dupe(u8, address_hex),
            .port = port,
        };
    };
    for (0..4) |word| {
        const start = word * 4;
        std.mem.reverse(u8, bytes[start..][0..4]);
    }

    const unresolved = std.Io.net.Ip6Address.Unresolved{
        .bytes = bytes,
        .interface_name = null,
    };
    var address: std.Io.Writer.Allocating = .init(alloc);
    errdefer address.deinit();
    try address.writer.print("{f}", .{unresolved});
    return .{
        .address = try address.toOwnedSlice(),
        .port = port,
    };
}

fn appendArpRows(writer: anytype, raw: []const u8) !void {
    var lines = std.mem.splitScalar(u8, raw, '\n');
    _ = lines.next(); // header
    var first = true;
    while (lines.next()) |line_raw| {
        const line = stripComment(line_raw);
        if (line.len == 0) continue;

        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        const address = fields.next() orelse continue;
        _ = fields.next(); // hardware type
        _ = fields.next(); // flags
        const mac = fields.next() orelse "";
        _ = fields.next(); // mask
        const device = fields.next() orelse "";

        if (!first) try writer.writeByte(',');
        first = false;
        try writer.writeAll("{\"address\":");
        try std.json.Stringify.value(address, .{}, writer);
        try writer.writeAll(",\"mac\":");
        try std.json.Stringify.value(mac, .{}, writer);
        try writer.writeAll(",\"device\":");
        try std.json.Stringify.value(device, .{}, writer);
        try writer.writeByte('}');
    }
}

fn appendResolvValues(writer: anytype, raw: []const u8, key: []const u8) !void {
    var lines = std.mem.splitScalar(u8, raw, '\n');
    var first = true;
    while (lines.next()) |line_raw| {
        const line = stripComment(line_raw);
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        const directive = fields.next() orelse continue;
        const matches = std.mem.eql(u8, directive, key) or (std.mem.eql(u8, key, "search") and std.mem.eql(u8, directive, "domain"));
        if (!matches) continue;

        while (fields.next()) |value| {
            if (!first) try writer.writeByte(',');
            first = false;
            try std.json.Stringify.value(value, .{}, writer);
            if (std.mem.eql(u8, key, "nameserver")) break;
        }
    }
}

fn appendHostMappings(writer: anytype, raw: []const u8) !void {
    var lines = std.mem.splitScalar(u8, raw, '\n');
    var first_mapping = true;
    while (lines.next()) |line_raw| {
        const line = stripComment(line_raw);
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        const address = fields.next() orelse continue;
        const first_name = fields.next() orelse continue;

        if (!first_mapping) try writer.writeByte(',');
        first_mapping = false;
        try writer.writeAll("{\"address\":");
        try std.json.Stringify.value(address, .{}, writer);
        try writer.writeAll(",\"names\":[");
        try std.json.Stringify.value(first_name, .{}, writer);
        while (fields.next()) |name| {
            try writer.writeByte(',');
            try std.json.Stringify.value(name, .{}, writer);
        }
        try writer.writeAll("]}");
    }
}

fn stripComment(raw: []const u8) []const u8 {
    const hash = std.mem.indexOfScalar(u8, raw, '#') orelse raw.len;
    return std.mem.trim(u8, raw[0..hash], " \t\r");
}

fn collectMacos(alloc: std.mem.Allocator) ![]u8 {
    const result = try std.process.run(alloc, iox.current(), .{
        .argv = &.{ "lsof", "-i", "-P", "-n" },
        .stdout_limit = .limited(512 * 1024),
        .stderr_limit = .limited(512 * 1024),
    });
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;

    try w.writeAll("{\"source\":\"lsof\",\"connections\":[");
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    var first = true;
    var skipped_header = false;
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;
        if (!skipped_header) {
            skipped_header = true;
            continue;
        }
        if (!first) try w.writeByte(',');
        first = false;
        try w.writeAll("{\"raw\":");
        try std.json.Stringify.value(line, .{}, w);
        try w.writeByte('}');
    }
    try w.writeAll("]}");

    return out.toOwnedSlice();
}

const NO_ERROR: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const AF_INET: u32 = 2;
const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
const UDP_TABLE_OWNER_PID: u32 = 1;

extern "iphlpapi" fn GetExtendedTcpTable(
    pTcpTable: ?*anyopaque,
    pdwSize: *u32,
    bOrder: i32,
    ulAf: u32,
    TableClass: u32,
    Reserved: u32,
) callconv(.c) u32;

extern "iphlpapi" fn GetExtendedUdpTable(
    pUdpTable: ?*anyopaque,
    pdwSize: *u32,
    bOrder: i32,
    ulAf: u32,
    TableClass: u32,
    Reserved: u32,
) callconv(.c) u32;

fn collectWindows(alloc: std.mem.Allocator) ![]u8 {
    const tcp_bytes = try tableSize(alloc, true);
    const udp_bytes = try tableSize(alloc, false);
    return std.fmt.allocPrint(
        alloc,
        "{{\"source\":\"iphlpapi\",\"tcp_table_bytes\":{d},\"udp_table_bytes\":{d}}}",
        .{ tcp_bytes, udp_bytes },
    );
}

fn tableSize(alloc: std.mem.Allocator, comptime tcp: bool) !u32 {
    var size: u32 = 0;
    const first = if (tcp)
        GetExtendedTcpTable(null, &size, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    else
        GetExtendedUdpTable(null, &size, 0, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (first != ERROR_INSUFFICIENT_BUFFER and first != NO_ERROR) return error.NetworkTableFailed;
    if (size == 0) return 0;

    const bytes = try alloc.alloc(u8, size);
    defer alloc.free(bytes);
    const ptr: ?*anyopaque = @ptrCast(bytes.ptr);
    const second = if (tcp)
        GetExtendedTcpTable(ptr, &size, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    else
        GetExtendedUdpTable(ptr, &size, 0, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (second != NO_ERROR) return error.NetworkTableFailed;
    return size;
}

fn readFileAbsoluteAlloc(alloc: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    const io = iox.current();
    var file = try std.Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);
    return iox.readToEndAlloc(file, alloc, max_bytes);
}

test "network collector module loads" {
    _ = collect;
}

test "procfs IPv6 endpoint is canonicalized" {
    const endpoint = try parseProcNetEndpoint(
        std.testing.allocator,
        "tcp6",
        "0000000000000000FFFF00000100007F:01BB",
    );
    defer std.testing.allocator.free(endpoint.address);

    try std.testing.expectEqualStrings("::ffff:127.0.0.1", endpoint.address);
    try std.testing.expectEqual(@as(u16, 443), endpoint.port);
}

test "Linux network context parsers emit searchable addresses and domains" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    try appendArpRows(
        &out.writer,
        "IP address HW type Flags HW address Mask Device\n10.0.1.1 0x1 0x2 00:11:22:33:44:55 * eth0\n",
    );
    try out.writer.writeByte('\n');
    try appendResolvValues(
        &out.writer,
        "nameserver 10.0.0.2\nsearch corp.example internal.example\n",
        "nameserver",
    );
    try out.writer.writeByte('\n');
    try appendResolvValues(
        &out.writer,
        "nameserver 10.0.0.2\nsearch corp.example internal.example\n",
        "search",
    );
    try out.writer.writeByte('\n');
    try appendHostMappings(
        &out.writer,
        "127.0.0.1 localhost\n10.0.1.25 app.corp.example app\n",
    );

    try std.testing.expect(std.mem.indexOf(u8, out.written(), "10.0.1.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "10.0.0.2") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "corp.example") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "app.corp.example") != null);
}
