const std = @import("std");

const argon2 = std.crypto.pwhash.argon2;
const scrypt = std.crypto.pwhash.scrypt;

// better-auth 1.6 (@better-auth/utils 0.4.2 password.node.ts): N=16384 (ln 14),
// r=16, p=1, dkLen=64, stored `saltHex:keyHex`. Scrypt salt is the hex text
// itself (UTF-8), not the decoded bytes. Caller passes an NFKC password;
// ASCII is unchanged.
pub const legacy_scrypt_params = scrypt.Params{ .ln = 14, .r = 16, .p = 1 };
pub const legacy_key_len = 64;

pub const minimum_test_params = argon2.Params{ .t = 2, .m = 16, .p = 1 };

pub fn productionParams() argon2.Params {
    return argon2.Params.interactive_2id;
}

pub const Decision = enum {
    current,
    rehash,
};

pub fn hashArgon2id(
    allocator: std.mem.Allocator,
    password: []const u8,
    params: argon2.Params,
    io: std.Io,
) ![]u8 {
    var buf: [512]u8 = undefined;
    const phc = try argon2.strHash(password, .{
        .allocator = allocator,
        .params = params,
        .mode = .argon2id,
        .encoding = .phc,
    }, &buf, io);
    return allocator.dupe(u8, phc);
}

pub fn verify(
    allocator: std.mem.Allocator,
    stored: []const u8,
    password: []const u8,
    io: std.Io,
) !Decision {
    if (std.mem.startsWith(u8, stored, "$argon2")) {
        argon2.strVerify(stored, password, .{ .allocator = allocator }, io) catch |err| switch (err) {
            error.PasswordVerificationFailed => return error.PasswordMismatch,
            else => return err,
        };
        return .current;
    }
    try verifyLegacyScrypt(allocator, stored, password);
    return .rehash;
}

pub fn verifyLegacyScrypt(allocator: std.mem.Allocator, stored: []const u8, password: []const u8) !void {
    const colon = std.mem.indexOfScalar(u8, stored, ':') orelse return error.InvalidEncoding;
    if (std.mem.indexOfScalarPos(u8, stored, colon + 1, ':') != null) return error.InvalidEncoding;
    const salt = stored[0..colon];
    const key_hex = stored[colon + 1 ..];
    if (salt.len == 0 or key_hex.len != legacy_key_len * 2) return error.InvalidEncoding;
    if (!isHex(salt) or !isHex(key_hex)) return error.InvalidEncoding;

    var expected: [legacy_key_len]u8 = undefined;
    _ = std.fmt.hexToBytes(&expected, key_hex) catch return error.InvalidEncoding;
    var actual: [legacy_key_len]u8 = undefined;
    try scrypt.kdf(allocator, &actual, password, salt, legacy_scrypt_params);
    if (!std.crypto.timing_safe.eql([legacy_key_len]u8, actual, expected)) return error.PasswordMismatch;
}

fn isHex(text: []const u8) bool {
    for (text) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
        if (!ok) return false;
    }
    return true;
}

test "argon2id minimum params round trip" {
    const allocator = std.testing.allocator;
    const stored = try hashArgon2id(allocator, "s3cret", minimum_test_params, std.testing.io);
    defer allocator.free(stored);
    try std.testing.expect(std.mem.startsWith(u8, stored, "$argon2id$"));
    try std.testing.expect(std.mem.indexOf(u8, stored, "m=16") != null);
    try std.testing.expectEqual(Decision.current, try verify(allocator, stored, "s3cret", std.testing.io));
    try std.testing.expectError(error.PasswordMismatch, verify(allocator, stored, "nope", std.testing.io));
    try std.testing.expect(productionParams().m > minimum_test_params.m);
}

test "legacy better-auth scrypt" {
    const allocator = std.testing.allocator;
    const stored = "00112233445566778899aabbccddeeff:13af89ff6a88bb0fb3277e79ba724c6c0731b15919ca892969d63abd1534b867d110179e3bc8af39995ede0f9b2ac14b2b97573df10ba3802c498dbeb61e4f64";
    try verifyLegacyScrypt(allocator, stored, "correct horse");
    try std.testing.expectEqual(Decision.rehash, try verify(allocator, stored, "correct horse", std.testing.io));
    try std.testing.expectError(error.PasswordMismatch, verifyLegacyScrypt(allocator, stored, "wrong horse"));
    try std.testing.expectError(error.InvalidEncoding, verifyLegacyScrypt(allocator, "not-a-hash", "correct horse"));
}
