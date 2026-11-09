//! Minisign signature verification (https://jedisct1.github.io/minisign/).
//!
//! Public key: two lines, an untrusted comment then base64 of
//! `"Ed" || key_id[8] || ed25519_public[32]`.
//!
//! Signature: four lines.
//!   untrusted comment: <text>
//!   base64(sig_alg[2] || key_id[8] || signature[64])
//!   trusted comment: <text>
//!   base64(global_signature[64])
//!
//! `sig_alg` is `ED` for the current default, where the signature covers the
//! BLAKE2b-512 hash of the file (prehashed), or `Ed` for the legacy form that
//! signs the file bytes directly. Both are accepted. The global signature
//! covers `signature || trusted_comment` and is always checked, so the trusted
//! comment cannot be swapped.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const Blake2b512 = std.crypto.hash.blake2.Blake2b512;

pub const key_id_len = 8;

pub const PublicKey = struct {
    key_id: [key_id_len]u8,
    key: Ed25519.PublicKey,
};

pub const Algorithm = enum { prehashed, legacy };

pub const Signature = struct {
    algorithm: Algorithm,
    key_id: [key_id_len]u8,
    signature: [Ed25519.Signature.encoded_length]u8,
    /// Slice into the signature text, without the `trusted comment: ` prefix.
    trusted_comment: []const u8,
    global_signature: [Ed25519.Signature.encoded_length]u8,
};

pub const Error = error{
    InvalidPublicKey,
    InvalidSignatureFormat,
    UnsupportedAlgorithm,
    KeyIdMismatch,
    SignatureVerificationFailed,
    TrustedCommentVerificationFailed,
};

const trusted_prefix = "trusted comment: ";
const untrusted_prefix = "untrusted comment: ";

/// Parse a public key: the two-line `.pub` file, or the bare base64 line.
pub fn parsePublicKey(text: []const u8) Error!PublicKey {
    var lines = std.mem.tokenizeAny(u8, text, "\r\n");
    var b64: ?[]const u8 = null;
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        if (line.len == 0 or std.mem.startsWith(u8, line, untrusted_prefix)) continue;
        b64 = line;
        break;
    }
    var raw: [2 + key_id_len + 32]u8 = undefined;
    decodeExact(&raw, b64 orelse return error.InvalidPublicKey) catch return error.InvalidPublicKey;
    if (!std.mem.eql(u8, raw[0..2], "Ed")) return error.UnsupportedAlgorithm;
    return .{
        .key_id = raw[2..10].*,
        .key = Ed25519.PublicKey.fromBytes(raw[10..42].*) catch return error.InvalidPublicKey,
    };
}

/// Parse a `.minisig` file. The returned trusted comment points into `text`.
pub fn parseSignature(text: []const u8) Error!Signature {
    var lines = std.mem.splitScalar(u8, text, '\n');
    const l1 = trimCr(lines.next() orelse return error.InvalidSignatureFormat);
    const l2 = trimCr(lines.next() orelse return error.InvalidSignatureFormat);
    const l3 = trimCr(lines.next() orelse return error.InvalidSignatureFormat);
    const l4 = trimCr(lines.next() orelse return error.InvalidSignatureFormat);
    if (!std.mem.startsWith(u8, l1, untrusted_prefix)) return error.InvalidSignatureFormat;
    if (!std.mem.startsWith(u8, l3, trusted_prefix)) return error.InvalidSignatureFormat;

    var sig_raw: [2 + key_id_len + 64]u8 = undefined;
    decodeExact(&sig_raw, l2) catch return error.InvalidSignatureFormat;
    const algorithm: Algorithm = if (std.mem.eql(u8, sig_raw[0..2], "ED"))
        .prehashed
    else if (std.mem.eql(u8, sig_raw[0..2], "Ed"))
        .legacy
    else
        return error.UnsupportedAlgorithm;

    var global: [64]u8 = undefined;
    decodeExact(&global, l4) catch return error.InvalidSignatureFormat;
    return .{
        .algorithm = algorithm,
        .key_id = sig_raw[2..10].*,
        .signature = sig_raw[10..74].*,
        .trusted_comment = l3[trusted_prefix.len..],
        .global_signature = global,
    };
}

/// Verify `message` against a parsed signature and key. Returns the trusted
/// comment on success.
pub fn verify(pk: PublicKey, sig: Signature, message: []const u8) Error![]const u8 {
    if (!std.mem.eql(u8, &pk.key_id, &sig.key_id)) return error.KeyIdMismatch;
    const s = Ed25519.Signature.fromBytes(sig.signature);
    switch (sig.algorithm) {
        .prehashed => {
            var digest: [Blake2b512.digest_length]u8 = undefined;
            Blake2b512.hash(message, &digest, .{});
            s.verify(&digest, pk.key) catch return error.SignatureVerificationFailed;
        },
        .legacy => s.verify(message, pk.key) catch return error.SignatureVerificationFailed,
    }
    // Global signature: signature bytes followed by the trusted comment.
    const g = Ed25519.Signature.fromBytes(sig.global_signature);
    var v = g.verifier(pk.key) catch return error.TrustedCommentVerificationFailed;
    v.update(&sig.signature);
    v.update(sig.trusted_comment);
    v.verify() catch return error.TrustedCommentVerificationFailed;
    return sig.trusted_comment;
}

/// Parse both texts and verify. Returns the trusted comment (a slice of
/// `signature_text`).
pub fn verifyText(public_key_text: []const u8, signature_text: []const u8, message: []const u8) Error![]const u8 {
    const pk = try parsePublicKey(public_key_text);
    const sig = try parseSignature(signature_text);
    return verify(pk, sig, message);
}

fn trimCr(line: []const u8) []const u8 {
    return std.mem.trimEnd(u8, line, "\r");
}

fn decodeExact(out: []u8, b64: []const u8) !void {
    const dec = std.base64.standard.Decoder;
    const n = try dec.calcSizeForSlice(b64);
    if (n != out.len) return error.InvalidLength;
    try dec.decode(out, b64);
}

// ---------------------------------------------------------------------------
// Test signer. Produces the same four-line format as `minisign -S` from a key
// pair generated inside the test. Never used outside tests.

pub const TestSigner = struct {
    kp: Ed25519.KeyPair,
    key_id: [key_id_len]u8,

    pub fn generate(io: std.Io) TestSigner {
        var id: [key_id_len]u8 = undefined;
        io.random(&id);
        return .{ .kp = Ed25519.KeyPair.generate(io), .key_id = id };
    }

    /// Two-line public key text. Caller frees.
    pub fn publicKeyText(self: TestSigner, alloc: std.mem.Allocator) ![]u8 {
        var raw: [42]u8 = undefined;
        raw[0..2].* = "Ed".*;
        raw[2..10].* = self.key_id;
        raw[10..42].* = self.kp.public_key.bytes;
        var b64: [56]u8 = undefined;
        const enc = std.base64.standard.Encoder.encode(&b64, &raw);
        return std.fmt.allocPrint(alloc, "untrusted comment: test key {x}\n{s}\n", .{ self.key_id, enc });
    }

    /// Four-line signature text. Caller frees.
    pub fn sign(self: TestSigner, alloc: std.mem.Allocator, message: []const u8, trusted_comment: []const u8, algorithm: Algorithm) ![]u8 {
        const sig = switch (algorithm) {
            .prehashed => blk: {
                var digest: [Blake2b512.digest_length]u8 = undefined;
                Blake2b512.hash(message, &digest, .{});
                break :blk try self.kp.sign(&digest, null);
            },
            .legacy => try self.kp.sign(message, null),
        };
        const sig_bytes = sig.toBytes();
        var raw: [74]u8 = undefined;
        raw[0..2].* = if (algorithm == .prehashed) "ED".* else "Ed".*;
        raw[2..10].* = self.key_id;
        raw[10..74].* = sig_bytes;

        const global_msg = try std.mem.concat(alloc, u8, &.{ &sig_bytes, trusted_comment });
        defer alloc.free(global_msg);
        const global = (try self.kp.sign(global_msg, null)).toBytes();

        var b1: [100]u8 = undefined;
        var b2: [88]u8 = undefined;
        const e1 = std.base64.standard.Encoder.encode(&b1, &raw);
        const e2 = std.base64.standard.Encoder.encode(&b2, &global);
        return std.fmt.allocPrint(alloc, "untrusted comment: signature from tawny test key\n{s}\ntrusted comment: {s}\n{s}\n", .{ e1, trusted_comment, e2 });
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

test "prehashed and legacy minisign signatures verify" {
    const a = testing.allocator;
    const signer = TestSigner.generate(testing.io);
    const pub_text = try signer.publicKeyText(a);
    defer a.free(pub_text);
    const msg = "{\"version\":\"1.2.3\"}";
    for ([_]Algorithm{ .prehashed, .legacy }) |alg| {
        const sig_text = try signer.sign(a, msg, "timestamp:1700000000\tfile:manifest.json", alg);
        defer a.free(sig_text);
        const tc = try verifyText(pub_text, sig_text, msg);
        try testing.expectEqualStrings("timestamp:1700000000\tfile:manifest.json", tc);
        const parsed = try parseSignature(sig_text);
        try testing.expectEqual(alg, parsed.algorithm);
    }
}

test "minisign refuses a changed message, a changed trusted comment and another key" {
    const a = testing.allocator;
    const signer = TestSigner.generate(testing.io);
    const other = TestSigner.generate(testing.io);
    const pub_text = try signer.publicKeyText(a);
    defer a.free(pub_text);
    const other_pub = try other.publicKeyText(a);
    defer a.free(other_pub);
    const sig_text = try signer.sign(a, "payload", "comment", .prehashed);
    defer a.free(sig_text);

    try testing.expectError(error.SignatureVerificationFailed, verifyText(pub_text, sig_text, "payloaD"));
    try testing.expectError(error.KeyIdMismatch, verifyText(other_pub, sig_text, "payload"));

    // Same key id, different key: the signature itself fails.
    var forged = other;
    forged.key_id = signer.key_id;
    const forged_pub = try forged.publicKeyText(a);
    defer a.free(forged_pub);
    try testing.expectError(error.SignatureVerificationFailed, verifyText(forged_pub, sig_text, "payload"));

    // Swap the trusted comment line: the global signature catches it.
    const swapped = try std.mem.replaceOwned(u8, a, sig_text, "trusted comment: comment", "trusted comment: rollback");
    defer a.free(swapped);
    try testing.expectError(error.TrustedCommentVerificationFailed, verifyText(pub_text, swapped, "payload"));
}

test "minisign parser refuses malformed input" {
    try testing.expectError(error.InvalidSignatureFormat, parseSignature("only one line"));
    try testing.expectError(error.InvalidPublicKey, parsePublicKey("untrusted comment: x\nnot base64!!\n"));
    // A real minisign public key line (from the minisign README) parses.
    const pk = try parsePublicKey("RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3");
    try testing.expectEqualSlices(u8, &.{ 0x1f, 0xe8, 0xb4, 0x42, 0x18, 0x0f, 0x62, 0xe7 }, &pk.key_id);
}
