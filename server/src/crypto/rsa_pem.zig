const std = @import("std");

pub const Key = struct {
    n: []u8,
    e: []u8,

    pub fn deinit(self: Key, allocator: std.mem.Allocator) void {
        allocator.free(self.n);
        allocator.free(self.e);
    }
};

const Tlv = struct {
    tag: u8,
    body: []const u8,
    rest: []const u8,
};

fn readTlv(data: []const u8) error{InvalidKey}!Tlv {
    if (data.len < 2) return error.InvalidKey;
    const tag = data[0];
    var i: usize = 1;
    var len: usize = data[i];
    i += 1;
    if (len & 0x80 != 0) {
        const nbytes = len & 0x7f;
        if (nbytes == 0 or nbytes > 3 or i + nbytes > data.len) return error.InvalidKey;
        len = 0;
        for (data[i..][0..nbytes]) |b| len = (len << 8) | b;
        i += nbytes;
    }
    if (i + len > data.len) return error.InvalidKey;
    return .{
        .tag = tag,
        .body = data[i..][0..len],
        .rest = data[i + len ..],
    };
}

fn stripLeadingZero(bytes: []const u8) []const u8 {
    if (bytes.len > 1 and bytes[0] == 0) return bytes[1..];
    return bytes;
}

/// PKCS#1 public, PKCS#1 private, SPKI, or PKCS#8. Returns unpadded modulus and exponent slices into `der`.
fn parseKeyDer(der: []const u8) error{InvalidKey}!struct { n: []const u8, e: []const u8 } {
    const top = try readTlv(der);
    if (top.tag != 0x30) return error.InvalidKey;
    const first = try readTlv(top.body);
    if (first.tag == 0x02) {
        const second = try readTlv(first.rest);
        if (second.tag == 0x30) {
            const third = try readTlv(second.rest);
            if (third.tag != 0x04) return error.InvalidKey;
            return parseKeyDer(third.body);
        }
        if (second.tag != 0x02) return error.InvalidKey;
        if (first.body.len <= 4) {
            const third = try readTlv(second.rest);
            if (third.tag != 0x02) return error.InvalidKey;
            return .{ .n = stripLeadingZero(second.body), .e = stripLeadingZero(third.body) };
        }
        return .{ .n = stripLeadingZero(first.body), .e = stripLeadingZero(second.body) };
    }
    if (first.tag == 0x30) {
        const second = try readTlv(first.rest);
        if (second.tag == 0x03) {
            if (second.body.len < 2) return error.InvalidKey;
            return parseKeyDer(second.body[1..]);
        }
    }
    return error.InvalidKey;
}

fn decodeB64(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    var compact: std.ArrayList(u8) = .empty;
    defer compact.deinit(allocator);
    for (text) |c| {
        if (c == ' ' or c == '\n' or c == '\r' or c == '\t') continue;
        try compact.append(allocator, c);
    }
    const len = std.base64.standard.Decoder.calcSizeForSlice(compact.items) catch return error.InvalidKey;
    const out = try allocator.alloc(u8, len);
    errdefer allocator.free(out);
    std.base64.standard.Decoder.decode(out, compact.items) catch return error.InvalidKey;
    return out;
}

pub fn parsePem(allocator: std.mem.Allocator, pem: []const u8) !Key {
    var rest = pem;
    while (std.mem.indexOf(u8, rest, "-----BEGIN ")) |rel| {
        const block = rest[rel..];
        const nl = std.mem.indexOfScalar(u8, block, '\n') orelse return error.InvalidKey;
        const end_rel = std.mem.indexOf(u8, block, "-----END ") orelse return error.InvalidKey;
        const der = try decodeB64(allocator, block[nl + 1 .. end_rel]);
        defer allocator.free(der);
        if (parseKeyDer(der)) |parts| {
            if (parts.n.len == 0 or parts.e.len == 0) return error.InvalidKey;
            return .{
                .n = try allocator.dupe(u8, parts.n),
                .e = try allocator.dupe(u8, parts.e),
            };
        } else |_| {}
        const after_end = std.mem.indexOfScalar(u8, block[end_rel..], '\n') orelse block[end_rel..].len;
        rest = block[end_rel + after_end ..];
    }
    return error.InvalidKey;
}

fn envSpan(name: [*:0]const u8) ?[]const u8 {
    const z = std.c.getenv(name) orelse return null;
    const s = std.mem.span(z);
    if (s.len == 0) return null;
    return s;
}

fn readFile(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    var file = if (path.len > 0 and path[0] == '/')
        try std.Io.Dir.openFileAbsolute(io, path, .{})
    else
        try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var rbuf: [1024]u8 = undefined;
    var reader = file.reader(io, &rbuf);
    return reader.interface.allocRemaining(allocator, .limited(65_536));
}

/// `TAWNY_AGENT_JWT_SIGNING_KEY_PEM` is PEM text or a filesystem path.
/// `TAWNY_AGENT_JWT_RS256_N` (hex) plus optional `TAWNY_AGENT_JWT_RS256_E` is the fallback.
pub fn loadConfigured(allocator: std.mem.Allocator, io: std.Io) !?Key {
    if (envSpan("TAWNY_AGENT_JWT_SIGNING_KEY_PEM")) |pem| {
        if (std.mem.indexOf(u8, pem, "-----BEGIN ") != null) return try parsePem(allocator, pem);
        const file = try readFile(allocator, io, pem);
        defer allocator.free(file);
        return try parsePem(allocator, file);
    }
    const n_hex = envSpan("TAWNY_AGENT_JWT_RS256_N") orelse return null;
    const e_hex = envSpan("TAWNY_AGENT_JWT_RS256_E") orelse "010001";
    const n = try allocator.alloc(u8, n_hex.len / 2);
    errdefer allocator.free(n);
    _ = std.fmt.hexToBytes(n, n_hex) catch return error.InvalidKey;
    const e = try allocator.alloc(u8, e_hex.len / 2);
    errdefer allocator.free(e);
    _ = std.fmt.hexToBytes(e, e_hex) catch return error.InvalidKey;
    return .{ .n = n, .e = e };
}

const spki_pub =
    \\-----BEGIN PUBLIC KEY-----
    \\MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArUALTHGQNnyL/IILgTGH
    \\nFHun2VOkluMNHkhBcV01PVk8BUOa7RZcSlYZhD4LQQxjWQGkvrzHi65cRQfbhda
    \\2XiHp6Ef8TgPkmndfBrklJ7JohpuJpihYLqTtXnPYAralVW04gAm6u3zukOtSia8
    \\C2Dmr4slYoz0rv56KRQezlghStuaf0IVa03VWY0+mXkPz4cVm7ezPosfWK+B05aK
    \\dAnVlCDgnHpEFZqGHyhhaS8huqgZeY7lxR6f5tnrDuINgMqQt/AB/55mARIvA0O6
    \\972ppct1gAzIb1kC8ZHrSk7aYrxyBkFT8OhJrRYIKGBVVYU5WLuemzgQAcK3xPw1
    \\kwIDAQAB
    \\-----END PUBLIC KEY-----
;

test "spki public pem yields 2048-bit modulus" {
    const key = try parsePem(std.testing.allocator, spki_pub);
    defer key.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 256), key.n.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAD, 0x40, 0x0B, 0x4C }, key.n[0..4]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00, 0x01 }, key.e);
}

test "pkcs1 private sequence uses modulus after version" {
    // SEQUENCE { INTEGER 0, INTEGER n=0x0102, INTEGER e=0x010001, INTEGER d=0x03 }
    const der = [_]u8{
        0x30, 0x0e,
        0x02, 0x01, 0x00,
        0x02, 0x02, 0x01, 0x02,
        0x02, 0x03, 0x01, 0x00, 0x01,
        0x02, 0x01, 0x03,
    };
    const parts = try parseKeyDer(&der);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02 }, parts.n);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00, 0x01 }, parts.e);
}
