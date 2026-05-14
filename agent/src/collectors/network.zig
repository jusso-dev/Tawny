const std = @import("std");
const builtin = @import("builtin");

pub fn collect(alloc: std.mem.Allocator) ![]u8 {
    return switch (builtin.os.tag) {
        .macos => collectMacos(alloc),
        .windows => collectWindows(alloc),
        else => @compileError("unsupported os"),
    };
}

fn collectMacos(alloc: std.mem.Allocator) ![]u8 {
    const result = try std.process.Child.run(.{
        .allocator = alloc,
        .argv = &.{ "lsof", "-i", "-P", "-n" },
        .max_output_bytes = 512 * 1024,
    });
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    var out = std.ArrayList(u8).init(alloc);
    errdefer out.deinit();
    var w = out.writer();

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
        try std.json.stringify(line, .{}, w);
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
) callconv(.C) u32;

extern "iphlpapi" fn GetExtendedUdpTable(
    pUdpTable: ?*anyopaque,
    pdwSize: *u32,
    bOrder: i32,
    ulAf: u32,
    TableClass: u32,
    Reserved: u32,
) callconv(.C) u32;

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

test "network collector module loads" {
    _ = collect;
}
