const std = @import("std");

const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Claims = struct {
    agent_id: []const u8,
    tenant_id: []const u8,
    cv: i64,
    jti: []const u8,
    iss: []const u8,
    aud: []const u8,
    exp: i64,
    iat: i64,
};

pub const Verified = struct {
    arena: std.heap.ArenaAllocator,
    claims: Claims,

    pub fn deinit(self: *Verified) void {
        self.arena.deinit();
    }
};

pub const VerifyOptions = struct {
    now: i64,
    expect_iss: ?[]const u8 = null,
    expect_aud: ?[]const u8 = null,
};

const header_json = "{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}";

pub fn issue(allocator: std.mem.Allocator, claims: Claims, key_pair: Ed25519.KeyPair) ![]u8 {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try payload.appendSlice(allocator, "{\"agent_id\":");
    try appendJsonString(&payload, allocator, claims.agent_id);
    try payload.appendSlice(allocator, ",\"tenant_id\":");
    try appendJsonString(&payload, allocator, claims.tenant_id);
    try payload.appendSlice(allocator, ",\"cv\":");
    try appendJsonInt(&payload, allocator, claims.cv);
    try payload.appendSlice(allocator, ",\"jti\":");
    try appendJsonString(&payload, allocator, claims.jti);
    try payload.appendSlice(allocator, ",\"iss\":");
    try appendJsonString(&payload, allocator, claims.iss);
    try payload.appendSlice(allocator, ",\"aud\":");
    try appendJsonString(&payload, allocator, claims.aud);
    try payload.appendSlice(allocator, ",\"exp\":");
    try appendJsonInt(&payload, allocator, claims.exp);
    try payload.appendSlice(allocator, ",\"iat\":");
    try appendJsonInt(&payload, allocator, claims.iat);
    try payload.append(allocator, '}');

    const header_b64 = try b64UrlEncode(allocator, header_json);
    defer allocator.free(header_b64);
    const payload_b64 = try b64UrlEncode(allocator, payload.items);
    defer allocator.free(payload_b64);

    var signing: std.ArrayList(u8) = .empty;
    defer signing.deinit(allocator);
    try signing.appendSlice(allocator, header_b64);
    try signing.append(allocator, '.');
    try signing.appendSlice(allocator, payload_b64);

    const sig = try key_pair.sign(signing.items, null);
    const sig_bytes = sig.toBytes();
    const sig_b64 = try b64UrlEncode(allocator, &sig_bytes);
    defer allocator.free(sig_b64);

    var token: std.ArrayList(u8) = .empty;
    errdefer token.deinit(allocator);
    try token.appendSlice(allocator, signing.items);
    try token.append(allocator, '.');
    try token.appendSlice(allocator, sig_b64);
    return token.toOwnedSlice(allocator);
}

pub fn verify(
    allocator: std.mem.Allocator,
    token: []const u8,
    public_key: Ed25519.PublicKey,
    opts: VerifyOptions,
) !Verified {
    const parts = try splitToken(token);
    const sig_raw = try b64UrlDecode(allocator, parts.sig_b64);
    defer allocator.free(sig_raw);
    if (sig_raw.len != Ed25519.Signature.encoded_length) return error.InvalidToken;
    var sig_bytes: [Ed25519.Signature.encoded_length]u8 = undefined;
    @memcpy(&sig_bytes, sig_raw);
    const signature = Ed25519.Signature.fromBytes(sig_bytes);
    signature.verify(parts.signing_input, public_key) catch return error.InvalidSignature;

    const header_raw = try b64UrlDecode(allocator, parts.header_b64);
    defer allocator.free(header_raw);
    const payload_raw = try b64UrlDecode(allocator, parts.payload_b64);
    defer allocator.free(payload_raw);

    const Header = struct { alg: []const u8, typ: ?[]const u8 = null };
    var header = std.json.parseFromSlice(Header, allocator, header_raw, .{ .ignore_unknown_fields = true }) catch return error.InvalidToken;
    defer header.deinit();
    if (!std.mem.eql(u8, header.value.alg, "EdDSA")) return error.WrongAlgorithm;

    const Payload = struct {
        agent_id: []const u8,
        tenant_id: []const u8,
        cv: i64,
        jti: []const u8,
        iss: []const u8,
        aud: []const u8,
        exp: i64,
        iat: i64,
    };
    var payload = std.json.parseFromSlice(Payload, allocator, payload_raw, .{ .ignore_unknown_fields = true }) catch return error.InvalidToken;
    defer payload.deinit();

    var verified: Verified = .{
        .arena = std.heap.ArenaAllocator.init(allocator),
        .claims = undefined,
    };
    errdefer verified.arena.deinit();
    const arena = verified.arena.allocator();
    verified.claims = .{
        .agent_id = try arena.dupe(u8, payload.value.agent_id),
        .tenant_id = try arena.dupe(u8, payload.value.tenant_id),
        .cv = payload.value.cv,
        .jti = try arena.dupe(u8, payload.value.jti),
        .iss = try arena.dupe(u8, payload.value.iss),
        .aud = try arena.dupe(u8, payload.value.aud),
        .exp = payload.value.exp,
        .iat = payload.value.iat,
    };

    if (opts.now >= verified.claims.exp) return error.Expired;
    if (opts.expect_iss) |iss| {
        if (!std.mem.eql(u8, iss, verified.claims.iss)) return error.IssuerMismatch;
    }
    if (opts.expect_aud) |aud| {
        if (!std.mem.eql(u8, aud, verified.claims.aud)) return error.AudienceMismatch;
    }
    return verified;
}

pub fn verifyRs256(
    allocator: std.mem.Allocator,
    token: []const u8,
    modulus: []const u8,
    exponent: []const u8,
) !void {
    const parts = try splitToken(token);
    const header_raw = try b64UrlDecode(allocator, parts.header_b64);
    defer allocator.free(header_raw);
    const Header = struct { alg: []const u8, typ: ?[]const u8 = null };
    var header = std.json.parseFromSlice(Header, allocator, header_raw, .{ .ignore_unknown_fields = true }) catch return error.InvalidToken;
    defer header.deinit();
    if (!std.mem.eql(u8, header.value.alg, "RS256")) return error.WrongAlgorithm;

    const sig_raw = try b64UrlDecode(allocator, parts.sig_b64);
    defer allocator.free(sig_raw);

    var mod = modulus;
    while (mod.len > sig_raw.len and mod[0] == 0) mod = mod[1..];
    if (mod.len != sig_raw.len) return error.InvalidSignature;
    var exp = exponent;
    while (exp.len > 1 and exp[0] == 0) exp = exp[1..];

    const key = std.crypto.Certificate.rsa.PublicKey.fromBytes(exp, mod) catch return error.InvalidKey;
    switch (sig_raw.len) {
        256 => try verifyPkcs1(256, sig_raw, parts.signing_input, key),
        384 => try verifyPkcs1(384, sig_raw, parts.signing_input, key),
        512 => try verifyPkcs1(512, sig_raw, parts.signing_input, key),
        else => return error.UnsupportedModulus,
    }
}

fn verifyPkcs1(
    comptime modulus_len: usize,
    sig: []const u8,
    msg: []const u8,
    public_key: std.crypto.Certificate.rsa.PublicKey,
) !void {
    var sig_buf: [modulus_len]u8 = undefined;
    @memcpy(&sig_buf, sig[0..modulus_len]);
    std.crypto.Certificate.rsa.PKCS1v1_5Signature.verify(modulus_len, &sig_buf, msg, public_key, Sha256) catch return error.InvalidSignature;
}

const Parts = struct {
    signing_input: []const u8,
    header_b64: []const u8,
    payload_b64: []const u8,
    sig_b64: []const u8,
};

fn splitToken(token: []const u8) error{InvalidToken}!Parts {
    const dot1 = std.mem.indexOfScalar(u8, token, '.') orelse return error.InvalidToken;
    const dot2 = std.mem.indexOfScalarPos(u8, token, dot1 + 1, '.') orelse return error.InvalidToken;
    if (dot2 + 1 >= token.len) return error.InvalidToken;
    if (std.mem.indexOfScalarPos(u8, token, dot2 + 1, '.') != null) return error.InvalidToken;
    return .{
        .signing_input = token[0..dot2],
        .header_b64 = token[0..dot1],
        .payload_b64 = token[dot1 + 1 .. dot2],
        .sig_b64 = token[dot2 + 1 ..],
    };
}

fn b64UrlEncode(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
    const len = std.base64.url_safe_no_pad.Encoder.calcSize(src.len);
    const out = try allocator.alloc(u8, len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, src);
    return out;
}

fn b64UrlDecode(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
    const trimmed = std.mem.trimEnd(u8, src, "=");
    const len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(trimmed) catch return error.InvalidToken;
    const out = try allocator.alloc(u8, len);
    errdefer allocator.free(out);
    std.base64.url_safe_no_pad.Decoder.decode(out, trimmed) catch return error.InvalidToken;
    return out;
}

fn appendJsonString(list: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    try list.append(allocator, '"');
    for (text) |c| {
        switch (c) {
            '"' => try list.appendSlice(allocator, "\\\""),
            '\\' => try list.appendSlice(allocator, "\\\\"),
            '\n' => try list.appendSlice(allocator, "\\n"),
            '\r' => try list.appendSlice(allocator, "\\r"),
            '\t' => try list.appendSlice(allocator, "\\t"),
            else => {
                if (c < 0x20) return error.InvalidClaim;
                try list.append(allocator, c);
            },
        }
    }
    try list.append(allocator, '"');
}

fn appendJsonInt(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: i64) !void {
    if (value == std.math.minInt(i64)) {
        try list.appendSlice(allocator, "-9223372036854775808");
        return;
    }
    var buf: [24]u8 = undefined;
    var i: usize = buf.len;
    const neg = value < 0;
    var n: u64 = if (neg) @intCast(-value) else @intCast(value);
    if (n == 0) {
        try list.append(allocator, '0');
        return;
    }
    while (n > 0) {
        i -= 1;
        buf[i] = '0' + @as(u8, @intCast(n % 10));
        n /= 10;
    }
    if (neg) {
        i -= 1;
        buf[i] = '-';
    }
    try list.appendSlice(allocator, buf[i..]);
}

test "eddsa issue and verify" {
    const allocator = std.testing.allocator;
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const claims = Claims{
        .agent_id = "agent-1",
        .tenant_id = "tenant-1",
        .cv = 3,
        .jti = "jti-1",
        .iss = "tawny",
        .aud = "agent",
        .exp = 2_000_000_000,
        .iat = 1_700_000_000,
    };
    const token = try issue(allocator, claims, kp);
    defer allocator.free(token);

    var verified = try verify(allocator, token, kp.public_key, .{
        .now = 1_800_000_000,
        .expect_iss = "tawny",
        .expect_aud = "agent",
    });
    defer verified.deinit();
    try std.testing.expectEqualSlices(u8, "agent-1", verified.claims.agent_id);
    try std.testing.expectEqualSlices(u8, "tenant-1", verified.claims.tenant_id);
    try std.testing.expectEqual(@as(i64, 3), verified.claims.cv);
    try std.testing.expectEqual(@as(i64, 2_000_000_000), verified.claims.exp);

    try std.testing.expectError(error.Expired, verify(allocator, token, kp.public_key, .{ .now = 2_000_000_000 }));
    try std.testing.expectError(error.IssuerMismatch, verify(allocator, token, kp.public_key, .{
        .now = 1_800_000_000,
        .expect_iss = "other",
    }));

    var tampered = try allocator.dupe(u8, token);
    defer allocator.free(tampered);
    const sig_at = std.mem.lastIndexOfScalar(u8, tampered, '.').?;
    tampered[sig_at + 1] = if (tampered[sig_at + 1] == 'A') 'B' else 'A';
    try std.testing.expectError(error.InvalidSignature, verify(allocator, tampered, kp.public_key, .{ .now = 1_800_000_000 }));
}

test "rfc7515 rs256" {
    const allocator = std.testing.allocator;
    const token = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
    const n_b64 = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
    const modulus = try b64UrlDecode(allocator, n_b64);
    defer allocator.free(modulus);
    const exponent = try b64UrlDecode(allocator, "AQAB");
    defer allocator.free(exponent);
    try verifyRs256(allocator, token, modulus, exponent);

    var bad = try allocator.dupe(u8, token);
    defer allocator.free(bad);
    const sig_at = std.mem.lastIndexOfScalar(u8, bad, '.').?;
    bad[sig_at + 1] = if (bad[sig_at + 1] == 'A') 'B' else 'A';
    try std.testing.expectError(error.InvalidSignature, verifyRs256(allocator, bad, modulus, exponent));
}
