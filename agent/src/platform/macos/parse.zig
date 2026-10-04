//! Pure parsers for the raw buffers macOS hands back from libproc / sysctl.
//! No syscalls here so the tests run on every host OS.

const std = @import("std");

/// Bytes up to the first NUL.
pub fn cString(buf: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, buf, 0) orelse buf.len;
    return buf[0..end];
}

pub const ProcArgs = struct {
    /// Executable path the kernel recorded at exec time (slice of the input).
    exec_path: []const u8,
    /// argv joined with single spaces (slice of the caller's output buffer).
    command_line: []const u8,
    argc: usize,
};

/// Parse a KERN_PROCARGS2 buffer:
///   int argc | exec_path NUL | NUL padding | argv[0] NUL ... argv[argc-1] NUL | envp...
/// The buffer may be truncated by the kernel; partial arguments are kept.
/// The environment is never read. `out` bounds the joined command line.
pub fn parseProcArgs2(raw: []const u8, out: []u8) ?ProcArgs {
    if (raw.len < @sizeOf(i32)) return null;
    const argc_raw = std.mem.readInt(i32, raw[0..4], .little);
    if (argc_raw < 0) return null;
    const argc: usize = @intCast(argc_raw);

    var pos: usize = 4;
    const exec_end = std.mem.indexOfScalarPos(u8, raw, pos, 0) orelse raw.len;
    const exec_path = raw[pos..exec_end];
    pos = exec_end;
    while (pos < raw.len and raw[pos] == 0) pos += 1;

    var written: usize = 0;
    var seen: usize = 0;
    while (seen < argc and pos < raw.len) : (seen += 1) {
        const end = std.mem.indexOfScalarPos(u8, raw, pos, 0) orelse raw.len;
        const arg = raw[pos..end];
        if (seen > 0 and written < out.len) {
            out[written] = ' ';
            written += 1;
        }
        const n = @min(arg.len, out.len - written);
        @memcpy(out[written..][0..n], arg[0..n]);
        written += n;
        pos = end + 1;
    }

    return .{
        .exec_path = exec_path,
        .command_line = std.mem.trimEnd(u8, out[0..written], " "),
        .argc = seen,
    };
}

// ---------------------------------------------------------------------------
// struct socket_fdinfo (sys/proc_info.h). Offsets verified with offsetof()
// against the macOS 26 SDK: psi @24; within socket_info: soi_protocol @156,
// soi_family @160, soi_kind @232, soi_proto @240; in_sockinfo: insi_fport @0,
// insi_lport @4, insi_vflag @24, insi_faddr @32, insi_laddr @48;
// tcp_sockinfo: tcpsi_state @80.
// ---------------------------------------------------------------------------

pub const socket_fdinfo_size: usize = 792;
const psi_offset: usize = 24;
const soi_protocol = psi_offset + 156;
const soi_family = psi_offset + 160;
const soi_kind = psi_offset + 232;
const soi_proto = psi_offset + 240;
const insi_fport = soi_proto + 0;
const insi_lport = soi_proto + 4;
const insi_vflag = soi_proto + 24;
const insi_faddr = soi_proto + 32;
const insi_laddr = soi_proto + 48;
const tcpsi_state = soi_proto + 80;

const SOCKINFO_IN: i32 = 1;
const SOCKINFO_TCP: i32 = 2;
const AF_INET: i32 = 2;
const AF_INET6: i32 = 30;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_UDP: i32 = 17;
const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;

pub const Socket = struct {
    /// "tcp" / "tcp6" / "udp" / "udp6" — same strings as Linux /proc/net.
    protocol: []const u8,
    ipv6: bool,
    local: [16]u8,
    local_port: u16,
    remote: [16]u8,
    remote_port: u16,
    state: State,
};

/// Linux /proc/net/tcp state code (uppercase hex as the kernel prints it)
/// plus the kernel's name for it, so rules written against Linux keep
/// matching macOS rows.
pub const State = struct {
    hex: []const u8,
    name: []const u8,
};

pub const linux_states = [_]State{
    .{ .hex = "01", .name = "ESTABLISHED" },
    .{ .hex = "02", .name = "SYN_SENT" },
    .{ .hex = "03", .name = "SYN_RECV" },
    .{ .hex = "04", .name = "FIN_WAIT1" },
    .{ .hex = "05", .name = "FIN_WAIT2" },
    .{ .hex = "06", .name = "TIME_WAIT" },
    .{ .hex = "07", .name = "CLOSE" },
    .{ .hex = "08", .name = "CLOSE_WAIT" },
    .{ .hex = "09", .name = "LAST_ACK" },
    .{ .hex = "0A", .name = "LISTEN" },
    .{ .hex = "0B", .name = "CLOSING" },
};

fn linuxState(code: u8) State {
    return linux_states[code - 1];
}

/// Name for a Linux /proc/net hex state ("0A" -> "LISTEN").
pub fn linuxStateName(hex: []const u8) ?[]const u8 {
    const code = std.fmt.parseInt(u8, hex, 16) catch return null;
    if (code == 0 or code > linux_states.len) return null;
    return linux_states[code - 1].name;
}

/// Map XNU TSI_S_* (netinet/tcp_fsm.h order) to the Linux equivalent.
pub fn tcpState(tsi: i32) State {
    return switch (tsi) {
        0 => linuxState(0x07), // CLOSED
        1 => linuxState(0x0A), // LISTEN
        2 => linuxState(0x02), // SYN_SENT
        3 => linuxState(0x03), // SYN_RECEIVED
        4 => linuxState(0x01), // ESTABLISHED
        5 => linuxState(0x08), // CLOSE_WAIT
        6 => linuxState(0x04), // FIN_WAIT_1
        7 => linuxState(0x0B), // CLOSING
        8 => linuxState(0x09), // LAST_ACK
        9 => linuxState(0x05), // FIN_WAIT_2
        10 => linuxState(0x06), // TIME_WAIT
        else => linuxState(0x07),
    };
}

fn readI32(buf: []const u8, offset: usize) i32 {
    return std.mem.readInt(i32, buf[offset..][0..4], .little);
}

fn port(buf: []const u8, offset: usize) u16 {
    // insi_*port is an int whose first two bytes hold the port in network
    // order (the kernel stores the in_port_t; ntohs() of the low half).
    return std.mem.readInt(u16, buf[offset..][0..2], .big);
}

/// Decode a TCP/UDP internet socket. Returns null for everything else
/// (unix sockets, raw/ICMP, kernel control, etc.).
pub fn parseSocketFdInfo(buf: *const [socket_fdinfo_size]u8) ?Socket {
    const family = readI32(buf, soi_family);
    if (family != AF_INET and family != AF_INET6) return null;
    const kind = readI32(buf, soi_kind);
    const proto = readI32(buf, soi_protocol);
    const is_tcp = kind == SOCKINFO_TCP and proto == IPPROTO_TCP;
    const is_udp = kind == SOCKINFO_IN and proto == IPPROTO_UDP;
    if (!is_tcp and !is_udp) return null;

    const vflag = buf[insi_vflag];
    const v6_family = family == AF_INET6;
    // Dual-stack sockets that are actually carrying IPv4 report INI_IPV4 only;
    // print those as dotted quads so IoC rules on remote_address still match.
    const ipv6 = (vflag & INI_IPV6) != 0 or (v6_family and (vflag & INI_IPV4) == 0);

    var s = Socket{
        .protocol = if (is_tcp)
            (if (v6_family) "tcp6" else "tcp")
        else
            (if (v6_family) "udp6" else "udp"),
        .ipv6 = ipv6,
        .local = buf[insi_laddr..][0..16].*,
        .local_port = port(buf, insi_lport),
        .remote = buf[insi_faddr..][0..16].*,
        .remote_port = port(buf, insi_fport),
        .state = undefined,
    };
    if (is_tcp) {
        s.state = tcpState(readI32(buf, tcpsi_state));
    } else {
        // Linux reports connected UDP sockets as ESTABLISHED, others CLOSE.
        s.state = if (s.remote_port != 0) linuxState(0x01) else linuxState(0x07);
    }
    return s;
}

/// Format an address from `struct in6_addr` / `struct in4in6_addr` storage.
pub fn formatAddress(bytes: [16]u8, ipv6: bool, buf: *[64]u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    if (ipv6) {
        const unresolved = std.Io.net.Ip6Address.Unresolved{ .bytes = bytes, .interface_name = null };
        w.print("{f}", .{unresolved}) catch return "";
    } else {
        // in4in6_addr: three u32 of padding, then the IPv4 address.
        w.print("{d}.{d}.{d}.{d}", .{ bytes[12], bytes[13], bytes[14], bytes[15] }) catch return "";
    }
    return w.buffered();
}

// ---------------------------------------------------------------------------
// ARP table from sysctl {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS,
// RTF_LLINFO}: a run of rt_msghdr (92 bytes) each followed by sockaddrs
// padded to 4 bytes. RTA_DST is sockaddr_inarp, RTA_GATEWAY is sockaddr_dl.
// ---------------------------------------------------------------------------

const rt_msghdr_size: usize = 92;
const RTM_VERSION: u8 = 5;
const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
const AF_LINK: u8 = 18;

pub const Neighbor = struct {
    address: [4]u8,
    mac: [6]u8,
    if_index: u16,
};

fn saRoundup(len: u8) usize {
    if (len == 0) return 4;
    return 1 + ((@as(usize, len) - 1) | 3);
}

pub const NeighborIterator = struct {
    raw: []const u8,
    pos: usize = 0,

    pub fn next(self: *NeighborIterator) ?Neighbor {
        while (self.pos + rt_msghdr_size <= self.raw.len) {
            const msg_start = self.pos;
            const msglen = std.mem.readInt(u16, self.raw[msg_start..][0..2], .little);
            if (msglen < rt_msghdr_size or msg_start + msglen > self.raw.len) {
                self.pos = self.raw.len;
                return null;
            }
            self.pos += msglen;
            const msg = self.raw[msg_start .. msg_start + msglen];
            if (msg[2] != RTM_VERSION) continue;
            const addrs = std.mem.readInt(i32, msg[12..16], .little);
            if ((addrs & RTA_DST) == 0 or (addrs & RTA_GATEWAY) == 0) continue;

            var cursor: usize = rt_msghdr_size;
            if (cursor + 8 > msg.len) continue;
            const dst = msg[cursor..];
            if (dst[1] != 2) continue; // AF_INET
            var neighbor = Neighbor{ .address = dst[4..8].*, .mac = undefined, .if_index = 0 };
            cursor += saRoundup(dst[0]);

            if (cursor + 8 > msg.len) continue;
            const gw = msg[cursor..];
            if (gw[1] != AF_LINK) continue;
            const nlen: usize = gw[5];
            const alen: usize = gw[6];
            if (alen != 6) continue; // incomplete entry, no hardware address yet
            if (cursor + 8 + nlen + alen > msg.len) continue;
            neighbor.if_index = std.mem.readInt(u16, gw[2..4], .little);
            neighbor.mac = gw[8 + nlen ..][0..6].*;
            return neighbor;
        }
        return null;
    }
};

test "procargs2 joins argv and skips exec path and environment" {
    var raw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer raw.deinit();
    try raw.writer.writeInt(i32, 3, .little);
    try raw.writer.writeAll("/bin/sleep\x00\x00\x00\x00sleep\x00--flag\x00a b\x00PATH=/usr/bin\x00SECRET=x\x00");
    var out: [256]u8 = undefined;
    const parsed = parseProcArgs2(raw.written(), &out).?;
    try std.testing.expectEqualStrings("/bin/sleep", parsed.exec_path);
    try std.testing.expectEqualStrings("sleep --flag a b", parsed.command_line);
    try std.testing.expectEqual(@as(usize, 3), parsed.argc);
}

test "procargs2 tolerates truncation and bounds output" {
    var raw: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer raw.deinit();
    try raw.writer.writeInt(i32, 4, .little);
    try raw.writer.writeAll("/x\x00a\x00bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    var out: [8]u8 = undefined;
    const parsed = parseProcArgs2(raw.written(), &out).?;
    try std.testing.expectEqualStrings("a bbbbbb", parsed.command_line);
    try std.testing.expectEqual(@as(usize, 2), parsed.argc);

    try std.testing.expect(parseProcArgs2("\x01\x00", &out) == null);
    try std.testing.expect(parseProcArgs2("\xff\xff\xff\xff/x\x00", &out) == null);
    const empty = parseProcArgs2("\x00\x00\x00\x00", &out).?;
    try std.testing.expectEqualStrings("", empty.command_line);
}

fn fakeSocket(family: i32, kind: i32, proto: i32, vflag: u8, state: i32) [socket_fdinfo_size]u8 {
    var buf = std.mem.zeroes([socket_fdinfo_size]u8);
    std.mem.writeInt(i32, buf[soi_family..][0..4], family, .little);
    std.mem.writeInt(i32, buf[soi_kind..][0..4], kind, .little);
    std.mem.writeInt(i32, buf[soi_protocol..][0..4], proto, .little);
    buf[insi_vflag] = vflag;
    // local 127.0.0.1:8080, remote 93.184.216.34:443 in network order.
    buf[insi_laddr + 12 ..][0..4].* = .{ 127, 0, 0, 1 };
    buf[insi_lport..][0..2].* = .{ 0x1F, 0x90 };
    buf[insi_faddr + 12 ..][0..4].* = .{ 93, 184, 216, 34 };
    buf[insi_fport..][0..2].* = .{ 0x01, 0xBB };
    std.mem.writeInt(i32, buf[tcpsi_state..][0..4], state, .little);
    return buf;
}

test "socket_fdinfo decodes TCP v4 with Linux state codes" {
    const buf = fakeSocket(AF_INET, SOCKINFO_TCP, IPPROTO_TCP, INI_IPV4, 4);
    const s = parseSocketFdInfo(&buf).?;
    try std.testing.expectEqualStrings("tcp", s.protocol);
    try std.testing.expectEqual(@as(u16, 8080), s.local_port);
    try std.testing.expectEqual(@as(u16, 443), s.remote_port);
    try std.testing.expectEqualStrings("01", s.state.hex);
    try std.testing.expectEqualStrings("ESTABLISHED", s.state.name);
    var abuf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("93.184.216.34", formatAddress(s.remote, s.ipv6, &abuf));
    try std.testing.expectEqualStrings("127.0.0.1", formatAddress(s.local, s.ipv6, &abuf));
}

test "socket_fdinfo decodes dual-stack, UDP and rejects others" {
    const mapped = fakeSocket(AF_INET6, SOCKINFO_TCP, IPPROTO_TCP, INI_IPV4, 1);
    const m = parseSocketFdInfo(&mapped).?;
    try std.testing.expectEqualStrings("tcp6", m.protocol);
    try std.testing.expect(!m.ipv6);
    try std.testing.expectEqualStrings("0A", m.state.hex);

    var v6 = fakeSocket(AF_INET6, SOCKINFO_IN, IPPROTO_UDP, INI_IPV6, 0);
    @memset(v6[insi_faddr..][0..16], 0);
    @memset(v6[insi_fport..][0..4], 0);
    v6[insi_laddr..][0..16].* = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const u = parseSocketFdInfo(&v6).?;
    try std.testing.expectEqualStrings("udp6", u.protocol);
    try std.testing.expectEqualStrings("07", u.state.hex);
    var abuf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("fe80::1", formatAddress(u.local, u.ipv6, &abuf));
    try std.testing.expectEqualStrings("::", formatAddress(u.remote, u.ipv6, &abuf));

    const unix_sock = fakeSocket(1, 3, 0, 0, 0);
    try std.testing.expect(parseSocketFdInfo(&unix_sock) == null);
    const icmp = fakeSocket(AF_INET, SOCKINFO_IN, 1, INI_IPV4, 0);
    try std.testing.expect(parseSocketFdInfo(&icmp) == null);
}

test "linux state names" {
    try std.testing.expectEqualStrings("LISTEN", linuxStateName("0A").?);
    try std.testing.expectEqualStrings("TIME_WAIT", linuxStateName("06").?);
    try std.testing.expect(linuxStateName("00") == null);
    try std.testing.expect(linuxStateName("zz") == null);
}

test "route dump yields complete ARP entries only" {
    var raw = std.mem.zeroes([2 * 128]u8);
    // Entry 1: 192.168.1.1 -> aa:bb:cc:dd:ee:ff on ifindex 4 (nlen 0).
    const len1: u16 = rt_msghdr_size + 16 + 20;
    std.mem.writeInt(u16, raw[0..2], len1, .little);
    raw[2] = RTM_VERSION;
    std.mem.writeInt(i32, raw[12..16], RTA_DST | RTA_GATEWAY, .little);
    raw[92] = 16;
    raw[93] = 2;
    raw[96..100].* = .{ 192, 168, 1, 1 };
    raw[108] = 20;
    raw[109] = AF_LINK;
    std.mem.writeInt(u16, raw[110..112], 4, .little);
    raw[114] = 6;
    raw[116..122].* = .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    // Entry 2: incomplete (alen 0) — must be skipped.
    const base: usize = len1;
    std.mem.writeInt(u16, raw[base..][0..2], len1, .little);
    raw[base + 2] = RTM_VERSION;
    std.mem.writeInt(i32, raw[base + 12 ..][0..4], RTA_DST | RTA_GATEWAY, .little);
    raw[base + 92] = 16;
    raw[base + 93] = 2;
    raw[base + 108] = 20;
    raw[base + 109] = AF_LINK;

    var it = NeighborIterator{ .raw = raw[0 .. 2 * len1] };
    const n = it.next().?;
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 1 }, n.address);
    try std.testing.expectEqual([6]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, n.mac);
    try std.testing.expectEqual(@as(u16, 4), n.if_index);
    try std.testing.expect(it.next() == null);

    var garbage = NeighborIterator{ .raw = &[_]u8{ 1, 0, 5 } };
    try std.testing.expect(garbage.next() == null);
}
