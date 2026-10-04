//! One-shot GET with the same egress rule as the other outbound jobs.
const std = @import("std");
const egress = @import("../sinks/egress.zig");

pub const Response = struct {
    status: u16,
    body: []u8,

    pub fn deinit(self: *Response, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
    }
};

pub fn get(
    allocator: std.mem.Allocator,
    io: std.Io,
    url: []const u8,
    headers: []const std.http.Header,
    user_agent: []const u8,
    allow_private: bool,
    max_body: usize,
) !Response {
    const uri = std.Uri.parse(url) catch return error.BadUrl;
    var host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
    const host = std.Io.net.HostName.fromUri(uri, &host_buf) catch return error.BadUrl;
    const port: u16 = uri.port orelse if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) 443 else 80;
    if (!egress.allowed(host.bytes, allow_private)) return error.EgressRefused;
    if (!allow_private) {
        if (std.Io.net.IpAddress.parse(host.bytes, port)) |_| {} else |_| try dnsAllowed(io, host, port);
    }

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();
    var req = client.request(.GET, uri, .{
        .keep_alive = false,
        .redirect_behavior = .unhandled,
        .headers = .{
            .user_agent = .{ .override = user_agent },
            .accept_encoding = .{ .override = "identity" },
        },
        .extra_headers = headers,
    }) catch |err| return err;
    defer req.deinit();
    req.sendBodiless() catch |err| return err;
    var redirect_buf: [1024]u8 = undefined;
    var response = req.receiveHead(&redirect_buf) catch |err| return err;
    const code: u16 = @intCast(@intFromEnum(response.head.status));

    const storage = try allocator.alloc(u8, max_body);
    defer allocator.free(storage);
    var writer = std.Io.Writer.fixed(storage);
    var transfer_buffer: [256]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    const reader = response.readerDecompressing(&transfer_buffer, &decompress, &.{});
    _ = reader.streamRemaining(&writer) catch |err| switch (err) {
        error.WriteFailed => return error.BodyTooLarge,
        else => return err,
    };
    return .{
        .status = code,
        .body = try allocator.dupe(u8, writer.buffered()),
    };
}

fn dnsAllowed(io: std.Io, host: std.Io.net.HostName, port: u16) !void {
    var storage: [16]std.Io.net.HostName.LookupResult = undefined;
    var queue = std.Io.Queue(std.Io.net.HostName.LookupResult).init(&storage);
    var canon: [std.Io.net.HostName.max_len]u8 = undefined;
    host.lookup(io, &queue, .{ .port = port, .canonical_name_buffer = &canon }) catch return error.DnsFailed;
    var slot: [1]std.Io.net.HostName.LookupResult = undefined;
    while (true) {
        const n = queue.get(io, &slot, 0) catch break;
        if (n == 0) break;
        switch (slot[0]) {
            .address => |addr| if (!resolvedAllowed(addr)) return error.EgressRefused,
            .canonical_name => {},
        }
    }
}

fn resolvedAllowed(addr: std.Io.net.IpAddress) bool {
    switch (addr) {
        .ip4 => |ip4| {
            var buf: [16]u8 = undefined;
            const text = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{
                ip4.bytes[0], ip4.bytes[1], ip4.bytes[2], ip4.bytes[3],
            }) catch return false;
            return egress.allowed(text, false);
        },
        .ip6 => |ip6| return !privateV6(ip6.bytes),
    }
}

fn privateV6(b: [16]u8) bool {
    var i: usize = 0;
    var zero = true;
    while (i < 15) : (i += 1) if (b[i] != 0) {
        zero = false;
    };
    if (zero and b[15] == 1) return true;
    if (b[0] == 0xfe and (b[1] & 0xc0) == 0x80) return true;
    if ((b[0] & 0xfe) == 0xfc) return true;
    return false;
}

test "outbound get refuses loopback unless private egress is on" {
    const refused = get(std.testing.allocator, std.testing.io, "http://127.0.0.1:9/x", &.{}, "tawny-test", false, 64);
    try std.testing.expectError(error.EgressRefused, refused);
}
