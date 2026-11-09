const std = @import("std");
const builtin = @import("builtin");
const iox = @import("../io_compat.zig");

const max_connections: usize = 4096;
const max_neighbors: usize = 1024;
const max_dns_values: usize = 64;
const max_host_mappings: usize = 2048;
const max_names_per_mapping: usize = 32;
// Shared state-code table and pure socket parsers (no syscalls; any OS).
const macos_parse = @import("../platform/macos/parse.zig");
const macos = if (builtin.target.os.tag == .macos) @import("../platform/macos.zig") else struct {};

pub fn collect(alloc: std.mem.Allocator) ![]u8 {
    return switch (builtin.target.os.tag) {
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
    var connection_count: usize = 0;
    try appendProcNetRows(alloc, w, "/proc/net/tcp", "tcp", &first, &connection_count);
    try appendProcNetRows(alloc, w, "/proc/net/tcp6", "tcp6", &first, &connection_count);
    try appendProcNetRows(alloc, w, "/proc/net/udp", "udp", &first, &connection_count);
    try appendProcNetRows(alloc, w, "/proc/net/udp6", "udp6", &first, &connection_count);
    try w.writeAll("],\"neighbors\":[");
    const arp = readFileAbsoluteAlloc(alloc, "/proc/net/arp", 512 * 1024) catch null;
    if (arp) |raw| {
        defer alloc.free(raw);
        try appendArpRows(w, raw);
    }
    try w.writeByte(']');
    try appendResolverContext(alloc, w);
    try w.writeByte('}');

    return out.toOwnedSlice();
}

/// `,"dns_servers":[..],"search_domains":[..],"host_mappings":[..]` from
/// /etc/resolv.conf and /etc/hosts. macOS keeps /etc/resolv.conf in sync with
/// the SystemConfiguration primary resolver, so both platforms share this.
fn appendResolverContext(alloc: std.mem.Allocator, w: *std.Io.Writer) !void {
    try w.writeAll(",\"dns_servers\":[");
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
    try w.writeByte(']');
}

fn appendProcNetRows(
    alloc: std.mem.Allocator,
    writer: anytype,
    path: []const u8,
    protocol: []const u8,
    first: *bool,
    count: *usize,
) !void {
    if (count.* >= max_connections) return;
    const raw = readFileAbsoluteAlloc(alloc, path, 512 * 1024) catch return;
    defer alloc.free(raw);

    var lines = std.mem.splitScalar(u8, raw, '\n');
    _ = lines.next(); // header
    while (lines.next()) |line_raw| {
        if (count.* >= max_connections) break;
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;

        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        _ = fields.next(); // slot
        const local = fields.next() orelse continue;
        const remote = fields.next() orelse continue;
        const state = fields.next() orelse continue;
        if (state.len > 8) continue;
        const local_endpoint = parseProcNetEndpoint(alloc, protocol, local) catch continue;
        defer alloc.free(local_endpoint.address);
        const remote_endpoint = parseProcNetEndpoint(alloc, protocol, remote) catch continue;
        defer alloc.free(remote_endpoint.address);

        if (!first.*) try writer.writeByte(',');
        first.* = false;
        count.* += 1;
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
        if (macos_parse.linuxStateName(state)) |name| {
            try writer.writeAll(",\"state_name\":");
            try std.json.Stringify.value(name, .{}, writer);
        }
        try writer.writeByte('}');
    }
}

const ProcNetEndpoint = struct {
    address: []u8,
    port: u16,
};

fn parseProcNetEndpoint(alloc: std.mem.Allocator, protocol: []const u8, endpoint: []const u8) !ProcNetEndpoint {
    const separator = std.mem.indexOfScalar(u8, endpoint, ':') orelse return error.InvalidEndpoint;

    const address_hex = endpoint[0..separator];
    const port_hex = endpoint[separator + 1 ..];
    const port = std.fmt.parseInt(u16, port_hex, 16) catch return error.InvalidEndpoint;

    if (!std.mem.endsWith(u8, protocol, "6") and address_hex.len == 8) {
        const raw = std.fmt.parseInt(u32, address_hex, 16) catch return error.InvalidEndpoint;
        return .{
            .address = try alloc.print(
                "{d}.{d}.{d}.{d}",
                .{ raw & 0xff, (raw >> 8) & 0xff, (raw >> 16) & 0xff, (raw >> 24) & 0xff },
            ),
            .port = port,
        };
    }

    if (address_hex.len != 32) {
        return error.InvalidEndpoint;
    }

    var bytes: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, address_hex) catch return error.InvalidEndpoint;
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
    var count: usize = 0;
    while (lines.next()) |line_raw| {
        if (count >= max_neighbors) break;
        const line = stripComment(line_raw);
        if (line.len == 0) continue;

        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        const address = fields.next() orelse continue;
        _ = fields.next(); // hardware type
        _ = fields.next(); // flags
        const mac = fields.next() orelse "";
        _ = fields.next(); // mask
        const device = fields.next() orelse "";
        if (!isValidIp(address) or mac.len > 32 or device.len > 64) continue;

        if (!first) try writer.writeByte(',');
        first = false;
        count += 1;
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
    var count: usize = 0;
    var emitted: [max_dns_values][]const u8 = undefined;
    while (lines.next()) |line_raw| {
        if (count >= max_dns_values) break;
        const line = stripComment(line_raw);
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        const directive = fields.next() orelse continue;
        const matches = std.mem.eql(u8, directive, key) or (std.mem.eql(u8, key, "search") and std.mem.eql(u8, directive, "domain"));
        if (!matches) continue;

        while (fields.next()) |value| {
            if (count >= max_dns_values) break;
            if (std.mem.eql(u8, key, "nameserver")) {
                if (!isValidIp(value)) break;
            } else if (!isValidDomain(value)) continue;
            var duplicate = false;
            for (emitted[0..count]) |prior| {
                if (std.ascii.eqlIgnoreCase(prior, value)) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) continue;
            if (!first) try writer.writeByte(',');
            first = false;
            try std.json.Stringify.value(value, .{}, writer);
            emitted[count] = value;
            count += 1;
            if (std.mem.eql(u8, key, "nameserver")) break;
        }
    }
}

fn appendHostMappings(writer: anytype, raw: []const u8) !void {
    var lines = std.mem.splitScalar(u8, raw, '\n');
    var first_mapping = true;
    var mapping_count: usize = 0;
    while (lines.next()) |line_raw| {
        if (mapping_count >= max_host_mappings) break;
        const line = stripComment(line_raw);
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        const address = fields.next() orelse continue;
        const first_name = fields.next() orelse continue;
        if (!isValidIp(address) or !isValidDomain(first_name)) continue;

        if (!first_mapping) try writer.writeByte(',');
        first_mapping = false;
        mapping_count += 1;
        try writer.writeAll("{\"address\":");
        try std.json.Stringify.value(address, .{}, writer);
        try writer.writeAll(",\"names\":[");
        try std.json.Stringify.value(first_name, .{}, writer);
        var name_count: usize = 1;
        var emitted_names: [max_names_per_mapping][]const u8 = undefined;
        emitted_names[0] = first_name;
        while (fields.next()) |name| {
            if (name_count >= max_names_per_mapping) break;
            if (!isValidDomain(name)) continue;
            var duplicate = false;
            for (emitted_names[0..name_count]) |prior| {
                if (std.ascii.eqlIgnoreCase(prior, name)) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) continue;
            try writer.writeByte(',');
            try std.json.Stringify.value(name, .{}, writer);
            emitted_names[name_count] = name;
            name_count += 1;
        }
        try writer.writeAll("]}");
    }
}

fn stripComment(raw: []const u8) []const u8 {
    const hash = std.mem.indexOfScalar(u8, raw, '#') orelse raw.len;
    return std.mem.trim(u8, raw[0..hash], " \t\r");
}

fn isValidIp(value: []const u8) bool {
    _ = std.Io.net.IpAddress.parse(value, 0) catch return false;
    return true;
}

fn isValidDomain(value: []const u8) bool {
    if (value.len == 0 or value.len > 253) return false;
    var label_len: usize = 0;
    for (value) |ch| {
        if (ch == '.') {
            if (label_len == 0 or label_len > 63) return false;
            label_len = 0;
            continue;
        }
        if (!std.ascii.isAlphanumeric(ch) and ch != '-' and ch != '_') return false;
        label_len += 1;
    }
    return label_len > 0 and label_len <= 63;
}

/// macOS: walk every process's descriptors with libproc and decode the
/// TCP/UDP sockets (proc_pidinfo(PROC_PIDLISTFDS) -> proc_pidfdinfo(
/// PROC_PIDFDSOCKETINFO)). Rows carry the Linux fields plus the owning pid
/// and process name. Without root only the agent user's sockets are visible.
fn collectMacos(alloc: std.mem.Allocator) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;

    try w.writeAll("{\"source\":\"libproc\",\"connections\":[");
    const truncated = try appendMacosConnections(alloc, w);
    try w.writeAll("],\"neighbors\":[");
    try appendMacosNeighbors(alloc, w);
    try w.writeByte(']');
    try appendResolverContext(alloc, w);
    try w.print(",\"truncated\":{any}}}", .{truncated});

    return out.toOwnedSlice();
}

fn appendMacosConnections(alloc: std.mem.Allocator, w: *std.Io.Writer) !bool {
    if (comptime builtin.target.os.tag != .macos) return false;
    const libproc = macos.libproc;

    const pids = try libproc.listAllPids(alloc);
    defer alloc.free(pids);

    var fds = std.array_list.Managed(libproc.FdInfo).init(alloc);
    defer fds.deinit();
    // The same socket shows up once per descriptor (dup, inherited fds);
    // keep one row per (pid, socket tuple).
    var emitted = std.AutoHashMap(u64, void).init(alloc);
    defer emitted.deinit();

    var sock_buf: [libproc.socket_fdinfo_size]u8 = undefined;
    var path_buf: [libproc.path_max]u8 = undefined;
    var count: usize = 0;

    for (pids) |pid| {
        if (pid < 0) continue;
        const fd_list = (libproc.listFds(pid, &fds) catch null) orelse continue; // EPERM / exited
        var process_name: ?[]const u8 = null;
        var name_buf: [64]u8 = undefined;

        for (fd_list) |fd| {
            if (fd.proc_fdtype != libproc.PROX_FDTYPE_SOCKET) continue;
            if (!libproc.socketInfo(pid, fd.proc_fd, &sock_buf)) continue;
            const s = macos_parse.parseSocketFdInfo(&sock_buf) orelse continue;

            var h = std.hash.Wyhash.init(@intCast(pid));
            h.update(s.protocol);
            h.update(&s.local);
            h.update(std.mem.asBytes(&s.local_port));
            h.update(&s.remote);
            h.update(std.mem.asBytes(&s.remote_port));
            const gop = try emitted.getOrPut(h.final());
            if (gop.found_existing) continue;

            if (count >= max_connections) return true;
            if (process_name == null) process_name = macosProcessName(pid, &path_buf, &name_buf);

            if (count > 0) try w.writeByte(',');
            count += 1;
            try writeMacosConnection(w, s, @intCast(pid), process_name.?);
        }
    }
    return false;
}

fn macosProcessName(pid: i32, path_buf: *[macos.libproc.path_max]u8, name_buf: *[64]u8) []const u8 {
    if (macos.libproc.pidPath(pid, path_buf)) |path| {
        const base = std.fs.path.basename(path);
        if (base.len > 0) return base;
    }
    const id = macos.libproc.identity(pid) orelse return "unknown";
    const n = @min(id.name().len, name_buf.len);
    @memcpy(name_buf[0..n], id.name()[0..n]);
    return if (n > 0) name_buf[0..n] else "unknown";
}

fn writeMacosConnection(w: *std.Io.Writer, s: macos_parse.Socket, pid: u32, process_name: []const u8) !void {
    var local_buf: [64]u8 = undefined;
    var remote_buf: [64]u8 = undefined;
    try w.writeAll("{\"protocol\":");
    try std.json.Stringify.value(s.protocol, .{}, w);
    try w.writeAll(",\"local_address\":");
    try std.json.Stringify.value(macos_parse.formatAddress(s.local, s.ipv6, &local_buf), .{}, w);
    try w.print(",\"local_port\":{d}", .{s.local_port});
    try w.writeAll(",\"remote_address\":");
    try std.json.Stringify.value(macos_parse.formatAddress(s.remote, s.ipv6, &remote_buf), .{}, w);
    try w.print(",\"remote_port\":{d}", .{s.remote_port});
    try w.writeAll(",\"state\":");
    try std.json.Stringify.value(s.state.hex, .{}, w);
    try w.writeAll(",\"state_name\":");
    try std.json.Stringify.value(s.state.name, .{}, w);
    try w.print(",\"pid\":{d},\"process_name\":", .{pid});
    try std.json.Stringify.value(process_name, .{}, w);
    try w.writeByte('}');
}

fn appendMacosNeighbors(alloc: std.mem.Allocator, w: *std.Io.Writer) !void {
    if (comptime builtin.target.os.tag != .macos) return;
    const raw = macos.libproc.arpTable(alloc) catch return; // no route socket access: no neighbors
    defer alloc.free(raw);

    var it = macos_parse.NeighborIterator{ .raw = raw };
    var count: usize = 0;
    var if_buf: [16]u8 = undefined;
    while (it.next()) |n| {
        if (count >= max_neighbors) break;
        if (count > 0) try w.writeByte(',');
        count += 1;
        try w.print("{{\"address\":\"{d}.{d}.{d}.{d}\"", .{ n.address[0], n.address[1], n.address[2], n.address[3] });
        try w.print(",\"mac\":\"{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}\"", .{ n.mac[0], n.mac[1], n.mac[2], n.mac[3], n.mac[4], n.mac[5] });
        try w.writeAll(",\"device\":");
        try std.json.Stringify.value(macos.libproc.interfaceName(n.if_index, &if_buf), .{}, w);
        try w.writeByte('}');
    }
}

const NO_ERROR: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
const UDP_TABLE_OWNER_PID: u32 = 1;
/// Tables can grow between the size probe and the read; retry a few times.
const max_table_attempts: usize = 4;
const max_table_bytes: u32 = 64 * 1024 * 1024;

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

/// Layout of the iphlpapi *_OWNER_PID tables: a u32 row count, then rows.
/// Addresses and ports are in network byte order; ports use the low 16 bits
/// of a u32. The IPv6 rows also carry a scope id after each address.
pub const WindowsTable = enum {
    tcp4,
    tcp6,
    udp4,
    udp6,

    fn rowSize(self: WindowsTable) usize {
        return switch (self) {
            .tcp4 => 24, // MIB_TCPROW_OWNER_PID: state, laddr, lport, raddr, rport, pid
            .tcp6 => 56, // MIB_TCP6ROW_OWNER_PID: laddr[16], lscope, lport, raddr[16], rscope, rport, state, pid
            .udp4 => 12, // MIB_UDPROW_OWNER_PID: laddr, lport, pid
            .udp6 => 28, // MIB_UDP6ROW_OWNER_PID: laddr[16], lscope, lport, pid
        };
    }

    fn protocol(self: WindowsTable) []const u8 {
        return switch (self) {
            .tcp4 => "tcp",
            .tcp6 => "tcp6",
            .udp4 => "udp",
            .udp6 => "udp6",
        };
    }
};

/// MIB_TCP_STATE (1 CLOSED .. 12 DELETE_TCB) -> the Linux hex state code
/// and name the other platforms emit, so one rule matches every OS.
fn windowsTcpState(state: u32) macos_parse.State {
    const code: u8 = switch (state) {
        1 => 0x07, // CLOSED
        2 => 0x0A, // LISTEN
        3 => 0x02, // SYN_SENT
        4 => 0x03, // SYN_RCVD
        5 => 0x01, // ESTABLISHED
        6 => 0x04, // FIN_WAIT1
        7 => 0x05, // FIN_WAIT2
        8 => 0x08, // CLOSE_WAIT
        9 => 0x0B, // CLOSING
        10 => 0x09, // LAST_ACK
        11 => 0x06, // TIME_WAIT
        else => 0x07, // DELETE_TCB and unknown
    };
    return macos_parse.linux_states[code - 1];
}

fn readU32(bytes: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, bytes[off..][0..4], .little);
}

/// Port fields hold the port in network order in the low two bytes.
fn readPort(bytes: []const u8, off: usize) u16 {
    return std.mem.readInt(u16, bytes[off..][0..2], .big);
}

fn ipv4Bytes(bytes: []const u8, off: usize) [16]u8 {
    var out: [16]u8 = @splat(0);
    @memcpy(out[12..16], bytes[off..][0..4]);
    return out;
}

/// Append one `connections` row per table entry, in the Linux row shape
/// plus the owning pid. Pure: `table` is the raw buffer the iphlpapi call
/// filled. Returns false when the global row cap was hit.
pub fn appendWindowsTableRows(w: *std.Io.Writer, kind: WindowsTable, table: []const u8, count: *usize) !bool {
    if (table.len < 4) return true;
    const rows = readU32(table, 0);
    const size = kind.rowSize();
    // Rows start at offset 4; every row type is made of 4-byte fields.
    const available = (table.len - 4) / size;
    const n = @min(rows, available);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (count.* >= max_connections) return false;
        const r = table[4 + i * size ..][0..size];
        const ipv6 = kind == .tcp6 or kind == .udp6;
        var local: [16]u8 = undefined;
        var remote: [16]u8 = @splat(0);
        var local_port: u16 = 0;
        var remote_port: u16 = 0;
        var state: ?macos_parse.State = null;
        var pid: u32 = 0;
        switch (kind) {
            .tcp4 => {
                state = windowsTcpState(readU32(r, 0));
                local = ipv4Bytes(r, 4);
                local_port = readPort(r, 8);
                remote = ipv4Bytes(r, 12);
                remote_port = readPort(r, 16);
                pid = readU32(r, 20);
            },
            .tcp6 => {
                local = r[0..16].*;
                local_port = readPort(r, 20);
                remote = r[24..40].*;
                remote_port = readPort(r, 44);
                state = windowsTcpState(readU32(r, 48));
                pid = readU32(r, 52);
            },
            .udp4 => {
                local = ipv4Bytes(r, 0);
                local_port = readPort(r, 4);
                pid = readU32(r, 8);
            },
            .udp6 => {
                local = r[0..16].*;
                local_port = readPort(r, 20);
                pid = readU32(r, 24);
            },
        }
        if (count.* > 0) try w.writeByte(',');
        count.* += 1;
        var local_buf: [64]u8 = undefined;
        var remote_buf: [64]u8 = undefined;
        try w.writeAll("{\"protocol\":");
        try std.json.Stringify.value(kind.protocol(), .{}, w);
        try w.writeAll(",\"local_address\":");
        try std.json.Stringify.value(macos_parse.formatAddress(local, ipv6, &local_buf), .{}, w);
        try w.print(",\"local_port\":{d}", .{local_port});
        try w.writeAll(",\"remote_address\":");
        try std.json.Stringify.value(macos_parse.formatAddress(remote, ipv6, &remote_buf), .{}, w);
        try w.print(",\"remote_port\":{d}", .{remote_port});
        if (state) |s| {
            try w.writeAll(",\"state\":");
            try std.json.Stringify.value(s.hex, .{}, w);
            try w.writeAll(",\"state_name\":");
            try std.json.Stringify.value(s.name, .{}, w);
        }
        try w.print(",\"pid\":{d}}}", .{pid});
    }
    return true;
}

/// Windows: TCP and UDP owner-pid tables for IPv4 and IPv6, as
/// `connections` rows matching the Linux and macOS shape (plus pid).
fn collectWindows(alloc: std.mem.Allocator) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;

    try w.writeAll("{\"source\":\"iphlpapi\",\"connections\":[");
    var count: usize = 0;
    var complete = true;
    var failed: usize = 0;
    inline for (.{ WindowsTable.tcp4, WindowsTable.tcp6, WindowsTable.udp4, WindowsTable.udp6 }) |kind| {
        if (complete) {
            if (readWindowsTable(alloc, kind)) |table| {
                defer alloc.free(table);
                complete = try appendWindowsTableRows(w, kind, table, &count);
            } else |_| failed += 1;
        }
    }
    if (failed == 4) return error.NetworkTableFailed;
    try w.print("],\"truncated\":{any}}}", .{!complete});
    return out.toOwnedSlice();
}

fn readWindowsTable(alloc: std.mem.Allocator, comptime kind: WindowsTable) ![]u8 {
    if (comptime builtin.target.os.tag != .windows) return error.NetworkTableFailed;
    const af = if (kind == .tcp4 or kind == .udp4) AF_INET else AF_INET6;
    const is_tcp = kind == .tcp4 or kind == .tcp6;
    var size: u32 = 0;
    var attempt: usize = 0;
    while (attempt < max_table_attempts) : (attempt += 1) {
        const probe = if (is_tcp)
            GetExtendedTcpTable(null, &size, 0, af, TCP_TABLE_OWNER_PID_ALL, 0)
        else
            GetExtendedUdpTable(null, &size, 0, af, UDP_TABLE_OWNER_PID, 0);
        if (probe != ERROR_INSUFFICIENT_BUFFER and probe != NO_ERROR) return error.NetworkTableFailed;
        if (size == 0) return alloc.alloc(u8, 0);
        if (size > max_table_bytes) return error.NetworkTableFailed;
        // Headroom for sockets opened between the two calls.
        size += 4096;
        const bytes = try alloc.alignedAlloc(u8, .of(u32), size);
        errdefer alloc.free(bytes);
        const ptr: ?*anyopaque = @ptrCast(bytes.ptr);
        const result = if (is_tcp)
            GetExtendedTcpTable(ptr, &size, 0, af, TCP_TABLE_OWNER_PID_ALL, 0)
        else
            GetExtendedUdpTable(ptr, &size, 0, af, UDP_TABLE_OWNER_PID, 0);
        if (result == NO_ERROR) {
            // Return a plain-aligned copy so the caller frees with alloc.free.
            const copy = try alloc.dupe(u8, bytes[0..@min(size, bytes.len)]);
            alloc.free(bytes);
            return copy;
        }
        alloc.free(bytes);
        if (result != ERROR_INSUFFICIENT_BUFFER) return error.NetworkTableFailed;
    }
    return error.NetworkTableFailed;
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

test "windows owner-pid table buffers become connection rows" {
    const alloc = std.testing.allocator;
    var tcp4: [4 + 2 * 24]u8 = @splat(0);
    std.mem.writeInt(u32, tcp4[0..4], 2, .little);
    // Row 0: ESTABLISHED 10.1.0.4:51544 -> 93.184.215.14:443, pid 7120.
    std.mem.writeInt(u32, tcp4[4..8], 5, .little);
    @memcpy(tcp4[8..12], &[_]u8{ 10, 1, 0, 4 });
    std.mem.writeInt(u16, tcp4[12..14], 51544, .big);
    @memcpy(tcp4[16..20], &[_]u8{ 93, 184, 215, 14 });
    std.mem.writeInt(u16, tcp4[20..22], 443, .big);
    std.mem.writeInt(u32, tcp4[24..28], 7120, .little);
    // Row 1: LISTEN 0.0.0.0:135, pid 1000.
    std.mem.writeInt(u32, tcp4[28..32], 2, .little);
    std.mem.writeInt(u16, tcp4[36..38], 135, .big);
    std.mem.writeInt(u32, tcp4[48..52], 1000, .little);

    var tcp6: [4 + 56]u8 = @splat(0);
    std.mem.writeInt(u32, tcp6[0..4], 1, .little);
    tcp6[4 + 15] = 1; // ::1
    std.mem.writeInt(u16, tcp6[4 + 20 ..][0..2], 5080, .big);
    tcp6[4 + 24] = 0x20;
    tcp6[4 + 25] = 0x01;
    tcp6[4 + 26] = 0x0d;
    tcp6[4 + 27] = 0xb8;
    tcp6[4 + 39] = 0x05; // 2001:db8::5
    std.mem.writeInt(u16, tcp6[4 + 44 ..][0..2], 22, .big);
    std.mem.writeInt(u32, tcp6[4 + 48 ..][0..4], 11, .little); // TIME_WAIT
    std.mem.writeInt(u32, tcp6[4 + 52 ..][0..4], 4, .little);

    var udp4: [4 + 12]u8 = @splat(0);
    std.mem.writeInt(u32, udp4[0..4], 1, .little);
    @memcpy(udp4[4..8], &[_]u8{ 127, 0, 0, 1 });
    std.mem.writeInt(u16, udp4[8..10], 53, .big);
    std.mem.writeInt(u32, udp4[12..16], 2200, .little);

    var udp6: [4 + 28]u8 = @splat(0);
    std.mem.writeInt(u32, udp6[0..4], 1, .little);
    std.mem.writeInt(u16, udp6[4 + 20 ..][0..2], 5353, .big);
    std.mem.writeInt(u32, udp6[4 + 24 ..][0..4], 3300, .little);

    var out: std.Io.Writer.Allocating = .init(alloc);
    defer out.deinit();
    const w = &out.writer;
    var count: usize = 0;
    try w.writeByte('[');
    try std.testing.expect(try appendWindowsTableRows(w, .tcp4, &tcp4, &count));
    try std.testing.expect(try appendWindowsTableRows(w, .tcp6, &tcp6, &count));
    try std.testing.expect(try appendWindowsTableRows(w, .udp4, &udp4, &count));
    try std.testing.expect(try appendWindowsTableRows(w, .udp6, &udp6, &count));
    // A row count larger than the buffer is clamped, not over-read.
    var lying: [4 + 12]u8 = udp4;
    std.mem.writeInt(u32, lying[0..4], 1000, .little);
    try std.testing.expect(try appendWindowsTableRows(w, .udp4, &lying, &count));
    try w.writeByte(']');
    try std.testing.expectEqual(@as(usize, 6), count);

    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, out.written(), .{});
    defer parsed.deinit();
    const rows = parsed.value.array.items;
    const est = rows[0].object;
    try std.testing.expectEqualStrings("tcp", est.get("protocol").?.string);
    try std.testing.expectEqualStrings("10.1.0.4", est.get("local_address").?.string);
    try std.testing.expectEqual(@as(i64, 51544), est.get("local_port").?.integer);
    try std.testing.expectEqualStrings("93.184.215.14", est.get("remote_address").?.string);
    try std.testing.expectEqual(@as(i64, 443), est.get("remote_port").?.integer);
    try std.testing.expectEqualStrings("01", est.get("state").?.string);
    try std.testing.expectEqualStrings("ESTABLISHED", est.get("state_name").?.string);
    try std.testing.expectEqual(@as(i64, 7120), est.get("pid").?.integer);
    try std.testing.expectEqualStrings("LISTEN", rows[1].object.get("state_name").?.string);
    try std.testing.expectEqualStrings("0.0.0.0", rows[1].object.get("local_address").?.string);
    const v6 = rows[2].object;
    try std.testing.expectEqualStrings("tcp6", v6.get("protocol").?.string);
    try std.testing.expectEqualStrings("::1", v6.get("local_address").?.string);
    try std.testing.expectEqual(@as(i64, 5080), v6.get("local_port").?.integer);
    try std.testing.expectEqualStrings("2001:db8::5", v6.get("remote_address").?.string);
    try std.testing.expectEqualStrings("TIME_WAIT", v6.get("state_name").?.string);
    const udp_v4 = rows[3].object;
    try std.testing.expectEqualStrings("udp", udp_v4.get("protocol").?.string);
    try std.testing.expectEqual(@as(i64, 53), udp_v4.get("local_port").?.integer);
    try std.testing.expect(udp_v4.get("state") == null);
    try std.testing.expectEqual(@as(i64, 2200), udp_v4.get("pid").?.integer);
    const udp_v6 = rows[4].object;
    try std.testing.expectEqualStrings("udp6", udp_v6.get("protocol").?.string);
    try std.testing.expectEqualStrings("::", udp_v6.get("local_address").?.string);
    try std.testing.expectEqual(@as(i64, 5353), udp_v6.get("local_port").?.integer);
    try std.testing.expectEqual(@as(i64, 3300), udp_v6.get("pid").?.integer);
}

test "windows snapshot lists live connections with owning pids" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const out = try collect(alloc);
    defer alloc.free(out);
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, out, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqualStrings("iphlpapi", root.get("source").?.string);
    const rows = root.get("connections").?.array.items;
    // Every Windows host listens on something (RPC 135 at least).
    try std.testing.expect(rows.len > 0);
    var saw_listen = false;
    for (rows) |row| {
        try std.testing.expect(row.object.get("pid") != null);
        try std.testing.expect(row.object.get("local_address").?.string.len > 0);
        if (row.object.get("state_name")) |s| {
            if (std.mem.eql(u8, s.string, "LISTEN")) saw_listen = true;
        }
    }
    try std.testing.expect(saw_listen);
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

test "malformed procfs endpoints are rejected" {
    try std.testing.expectError(
        error.InvalidEndpoint,
        parseProcNetEndpoint(std.testing.allocator, "tcp", "not-an-endpoint"),
    );
    try std.testing.expectError(
        error.InvalidEndpoint,
        parseProcNetEndpoint(std.testing.allocator, "tcp6", "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG:01BB"),
    );
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

test "malformed network values are skipped" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    try appendResolvValues(&out.writer, "nameserver nope\nsearch ok.example bad/$domain\n", "nameserver");
    try out.writer.writeByte('\n');
    try appendHostMappings(&out.writer, "not-an-ip secret.example\n10.0.0.2 valid.example bad/name\n");

    try std.testing.expect(std.mem.indexOf(u8, out.written(), "not-an-ip") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "bad/name") == null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "valid.example") != null);
}

test "connection rows for an in-test TCP socket (macOS: with owning pid)" {
    const is_mac = builtin.target.os.tag == .macos;
    if (!is_mac and builtin.target.os.tag != .linux) return error.SkipZigTest;
    const c = std.c;
    const alloc = std.testing.allocator;

    const listener = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
    try std.testing.expect(listener >= 0);
    defer _ = c.close(listener);
    var addr = c.sockaddr.in{ .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001) };
    try std.testing.expectEqual(@as(c_int, 0), c.bind(listener, @ptrCast(&addr), @sizeOf(c.sockaddr.in)));
    try std.testing.expectEqual(@as(c_int, 0), c.listen(listener, 1));
    var addr_len: c.socklen_t = @sizeOf(c.sockaddr.in);
    try std.testing.expectEqual(@as(c_int, 0), c.getsockname(listener, @ptrCast(&addr), &addr_len));
    const port = std.mem.bigToNative(u16, addr.port);

    const client = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
    try std.testing.expect(client >= 0);
    defer _ = c.close(client);
    try std.testing.expectEqual(@as(c_int, 0), c.connect(client, @ptrCast(&addr), @sizeOf(c.sockaddr.in)));

    const out = try collect(alloc);
    defer alloc.free(out);
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, out, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqualStrings(if (is_mac) "libproc" else "procfs", root.get("source").?.string);
    try std.testing.expect(root.get("dns_servers").? == .array);

    const me: i64 = c.getpid();
    var saw_client = false;
    var saw_listener = false;
    for (root.get("connections").?.array.items) |row| {
        const o = row.object;
        if (is_mac) {
            if (o.get("pid").?.integer != me) continue;
            try std.testing.expect(o.get("process_name").?.string.len > 0);
        }
        if (o.get("remote_port").?.integer == port) {
            try std.testing.expectEqualStrings("tcp", o.get("protocol").?.string);
            try std.testing.expectEqualStrings("127.0.0.1", o.get("remote_address").?.string);
            try std.testing.expectEqualStrings("01", o.get("state").?.string);
            try std.testing.expectEqualStrings("ESTABLISHED", o.get("state_name").?.string);
            saw_client = true;
        }
        if (o.get("local_port").?.integer == port and std.mem.eql(u8, o.get("state").?.string, "0A")) {
            saw_listener = true;
        }
    }
    try std.testing.expect(saw_client);
    try std.testing.expect(saw_listener);
}
