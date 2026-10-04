//! Refuse user-configured outbound hosts that are loopback, link-local,
//! private, or metadata, unless private egress is explicitly enabled.
const std = @import("std");

pub fn allowed(host: []const u8, allow_private: bool) bool {
    if (allow_private) return true;
    const trimmed = std.mem.trim(u8, host, " \t");
    if (trimmed.len == 0) return false;
    if (std.ascii.eqlIgnoreCase(trimmed, "localhost")) return false;
    if (std.ascii.eqlIgnoreCase(trimmed, "metadata.google.internal")) return false;
    if (std.ascii.eqlIgnoreCase(trimmed, "metadata")) return false;
    if (parseV4(trimmed)) |addr| return !privateV4(addr);
    if (std.mem.indexOfScalar(u8, trimmed, ':') != null) {
        if (std.mem.eql(u8, trimmed, "::1")) return false;
        if (startsIgnore(trimmed, "fe80:")) return false;
        if (startsIgnore(trimmed, "fc") or startsIgnore(trimmed, "fd")) return false;
    }
    return true;
}

fn parseV4(host: []const u8) ?[4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, host, '.');
    var i: usize = 0;
    while (it.next()) |part| {
        if (i == 4 or part.len == 0 or part.len > 3) return null;
        const n = std.fmt.parseInt(u8, part, 10) catch return null;
        out[i] = n;
        i += 1;
    }
    if (i != 4) return null;
    return out;
}

fn privateV4(a: [4]u8) bool {
    if (a[0] == 0 or a[0] == 10 or a[0] == 127) return true;
    if (a[0] == 169 and a[1] == 254) return true;
    if (a[0] == 172 and a[1] >= 16 and a[1] <= 31) return true;
    if (a[0] == 192 and a[1] == 168) return true;
    if (a[0] == 100 and a[1] >= 64 and a[1] <= 127) return true;
    return false;
}

fn startsIgnore(value: []const u8, prefix: []const u8) bool {
    if (value.len < prefix.len) return false;
    return std.ascii.eqlIgnoreCase(value[0..prefix.len], prefix);
}

test "egress refuses private metadata and loopback" {
    try std.testing.expect(!allowed("127.0.0.1", false));
    try std.testing.expect(!allowed("10.1.2.3", false));
    try std.testing.expect(!allowed("192.168.1.10", false));
    try std.testing.expect(!allowed("172.16.0.4", false));
    try std.testing.expect(!allowed("169.254.169.254", false));
    try std.testing.expect(!allowed("localhost", false));
    try std.testing.expect(!allowed("metadata.google.internal", false));
    try std.testing.expect(!allowed("::1", false));
    try std.testing.expect(!allowed("fe80::1", false));
    try std.testing.expect(allowed("172.15.0.1", false));
    try std.testing.expect(allowed("8.8.8.8", false));
    try std.testing.expect(allowed("hooks.slack.com", false));
    try std.testing.expect(allowed("127.0.0.1", true));
    try std.testing.expect(allowed("169.254.169.254", true));
}
