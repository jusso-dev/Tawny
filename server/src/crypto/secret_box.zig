const std = @import("std");

const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const prefix = "v1.";
pub const nonce_len = Aes256Gcm.nonce_length;
pub const tag_len = Aes256Gcm.tag_length;
const key_label = "tawny-integration-secrets-v1";

pub fn isProtected(value: []const u8) bool {
    return std.mem.startsWith(u8, value, prefix);
}

pub fn protect(allocator: std.mem.Allocator, root_secret: []const u8, plaintext: []const u8, io: std.Io) ![]u8 {
    var nonce: [nonce_len]u8 = undefined;
    io.random(&nonce);
    return protectWithNonce(allocator, root_secret, plaintext, nonce);
}

pub fn protectWithNonce(
    allocator: std.mem.Allocator,
    root_secret: []const u8,
    plaintext: []const u8,
    nonce: [nonce_len]u8,
) ![]u8 {
    if (std.mem.trim(u8, plaintext, &std.ascii.whitespace).len == 0) return error.EmptyPlaintext;

    const key = deriveKey(root_secret);
    const ciphertext = try allocator.alloc(u8, plaintext.len);
    defer allocator.free(ciphertext);
    var tag: [tag_len]u8 = undefined;
    Aes256Gcm.encrypt(ciphertext, &tag, plaintext, "", nonce, key);

    const payload = try allocator.alloc(u8, nonce_len + tag_len + ciphertext.len);
    defer allocator.free(payload);
    @memcpy(payload[0..nonce_len], &nonce);
    @memcpy(payload[nonce_len..][0..tag_len], &tag);
    @memcpy(payload[nonce_len + tag_len ..], ciphertext);

    const b64_len = std.base64.standard.Encoder.calcSize(payload.len);
    const out = try allocator.alloc(u8, prefix.len + b64_len);
    @memcpy(out[0..prefix.len], prefix);
    _ = std.base64.standard.Encoder.encode(out[prefix.len..], payload);
    return out;
}

pub fn unprotect(allocator: std.mem.Allocator, root_secret: []const u8, protected_value: []const u8) ![]u8 {
    if (!isProtected(protected_value)) return error.InvalidFormat;
    const b64 = protected_value[prefix.len..];
    const payload_len = std.base64.standard.Decoder.calcSizeForSlice(b64) catch return error.InvalidFormat;
    if (payload_len <= nonce_len + tag_len) return error.InvalidFormat;

    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    std.base64.standard.Decoder.decode(payload, b64) catch return error.InvalidFormat;

    var nonce: [nonce_len]u8 = undefined;
    var tag: [tag_len]u8 = undefined;
    @memcpy(&nonce, payload[0..nonce_len]);
    @memcpy(&tag, payload[nonce_len..][0..tag_len]);
    const ciphertext = payload[nonce_len + tag_len ..];

    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);
    Aes256Gcm.decrypt(plaintext, ciphertext, tag, "", nonce, deriveKey(root_secret)) catch return error.AuthenticationFailed;
    return plaintext;
}

fn deriveKey(root_secret: []const u8) [Aes256Gcm.key_length]u8 {
    var key: [Aes256Gcm.key_length]u8 = undefined;
    HmacSha256.create(&key, key_label, root_secret);
    return key;
}

test "protectWithNonce round trip" {
    const allocator = std.testing.allocator;
    const nonce: [nonce_len]u8 = @splat(0x11);
    const boxed = try protectWithNonce(allocator, "test-root-secret", "integration-secret", nonce);
    defer allocator.free(boxed);
    const opened = try unprotect(allocator, "test-root-secret", boxed);
    defer allocator.free(opened);
    try std.testing.expectEqualSlices(u8, "integration-secret", opened);

    const again = try protectWithNonce(allocator, "test-root-secret", "integration-secret", nonce);
    defer allocator.free(again);
    try std.testing.expectEqualSlices(u8, boxed, again);
    try std.testing.expect(isProtected(boxed));
    try std.testing.expectError(error.EmptyPlaintext, protectWithNonce(allocator, "test-root-secret", "  ", nonce));
    try std.testing.expectError(error.AuthenticationFailed, unprotect(allocator, "other-secret", boxed));
}

test "dotnetVector" {
    const allocator = std.testing.allocator;
    const nonce: [nonce_len]u8 = @splat(0x11);
    const oracle = "v1.ERERERERERERERERT71hRpPeNcfo5t9CIwXXyVNdE3vM19b3fcN45DWMUozj4w==";
    const opened = try unprotect(allocator, "test-root-secret", oracle);
    defer allocator.free(opened);
    try std.testing.expectEqualSlices(u8, "integration-secret", opened);

    const boxed = try protectWithNonce(allocator, "test-root-secret", "integration-secret", nonce);
    defer allocator.free(boxed);
    try std.testing.expectEqualSlices(u8, oracle, boxed);
}
