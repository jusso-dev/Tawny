//! Signed YARA rule packs from the server.
//!
//! Pack JSON (from `GET /api/agent/yara-rules`):
//!   {"format":"tawny-yara-pack-v1","tenant_id":"...","version":N,
//!    "created_at":"...","key_id":"<hex sha256 of public key, first 16 bytes>",
//!    "rules_b64":"<base64 of the rule source>","sha256":"<hex>",
//!    "signature":"<base64 Ed25519>"}
//!
//! Signed bytes, one field per line, each ending with `\n`:
//!   tawny-yara-pack-v1
//!   <tenant_id>
//!   <version>
//!   <created_at>
//!   <sha256 hex of the rule source>
//!
//! The agent pins the server's rule-signing public key (from enrolment or
//! config). A pack with no signature, a bad signature, another key, or a
//! source that doesn't match its hash is refused. The server side is
//! `server/src/routes/yara_rules.zig`, which builds the same bytes.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

pub const format = "tawny-yara-pack-v1";

pub const Pack = struct {
    tenant_id: []const u8,
    version: u64,
    created_at: []const u8,
    /// Rule source, owned by the caller after `verify`.
    source: []u8,
};

pub const VerifyError = error{
    PackMalformed,
    PackUnsigned,
    PackWrongKey,
    PackBadSignature,
    PackHashMismatch,
    OutOfMemory,
};

/// Bytes the server signs.
pub fn signedBytes(alloc: std.mem.Allocator, tenant_id: []const u8, version: u64, created_at: []const u8, sha256_hex: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, "{s}\n{s}\n{d}\n{s}\n{s}\n", .{ format, tenant_id, version, created_at, sha256_hex });
}

pub fn keyId(public_key: [Ed25519.PublicKey.encoded_length]u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&public_key, &digest, .{});
    return std.fmt.bytesToHex(digest[0..16].*, .lower);
}

/// Check a pack against the pinned public key. The source in the result
/// is owned by the caller.
pub fn verify(alloc: std.mem.Allocator, pack_json: []const u8, public_key: Ed25519.PublicKey) VerifyError!Pack {
    const Raw = struct {
        format: []const u8,
        tenant_id: []const u8,
        version: u64,
        created_at: []const u8,
        key_id: ?[]const u8 = null,
        rules_b64: []const u8,
        sha256: []const u8,
        signature: ?[]const u8 = null,
    };
    var parsed = std.json.parseFromSlice(Raw, alloc, pack_json, .{ .ignore_unknown_fields = true }) catch return error.PackMalformed;
    defer parsed.deinit();
    const raw = parsed.value;
    if (!std.mem.eql(u8, raw.format, format)) return error.PackMalformed;
    if (raw.tenant_id.len == 0 or raw.tenant_id.len > 64 or raw.created_at.len == 0 or raw.created_at.len > 64) return error.PackMalformed;
    if (std.mem.indexOfScalar(u8, raw.tenant_id, '\n') != null or std.mem.indexOfScalar(u8, raw.created_at, '\n') != null) return error.PackMalformed;
    const sig_b64 = raw.signature orelse return error.PackUnsigned;
    if (sig_b64.len == 0) return error.PackUnsigned;
    if (raw.key_id) |kid| {
        const want = keyId(public_key.bytes);
        if (!std.mem.eql(u8, kid, &want)) return error.PackWrongKey;
    }

    const dec = std.base64.standard.Decoder;
    var sig_bytes: [Ed25519.Signature.encoded_length]u8 = undefined;
    const sig_len = dec.calcSizeForSlice(sig_b64) catch return error.PackBadSignature;
    if (sig_len != sig_bytes.len) return error.PackBadSignature;
    dec.decode(&sig_bytes, sig_b64) catch return error.PackBadSignature;
    const sig = Ed25519.Signature.fromBytes(sig_bytes);

    if (raw.sha256.len != 64) return error.PackMalformed;
    const msg = try signedBytes(alloc, raw.tenant_id, raw.version, raw.created_at, raw.sha256);
    defer alloc.free(msg);
    sig.verify(msg, public_key) catch return error.PackBadSignature;

    const src_len = dec.calcSizeForSlice(raw.rules_b64) catch return error.PackMalformed;
    if (src_len > 4 * 1024 * 1024) return error.PackMalformed;
    const source = try alloc.alloc(u8, src_len);
    errdefer alloc.free(source);
    dec.decode(source, raw.rules_b64) catch return error.PackMalformed;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    if (!std.ascii.eqlIgnoreCase(&hex, raw.sha256)) return error.PackHashMismatch;

    const tenant = try alloc.dupe(u8, raw.tenant_id);
    errdefer alloc.free(tenant);
    const created = try alloc.dupe(u8, raw.created_at);
    return .{ .tenant_id = tenant, .version = raw.version, .created_at = created, .source = source };
}

pub fn deinitPack(alloc: std.mem.Allocator, p: Pack) void {
    alloc.free(p.tenant_id);
    alloc.free(p.created_at);
    alloc.free(p.source);
}

/// Build a signed pack. Used by tests here; the server has its own copy.
pub fn sign(alloc: std.mem.Allocator, kp: Ed25519.KeyPair, tenant_id: []const u8, version: u64, created_at: []const u8, source: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const msg = try signedBytes(alloc, tenant_id, version, created_at, &hex);
    defer alloc.free(msg);
    const sig = try kp.sign(msg, null);
    const enc = std.base64.standard.Encoder;
    const sig_b64 = try alloc.alloc(u8, enc.calcSize(64));
    defer alloc.free(sig_b64);
    _ = enc.encode(sig_b64, &sig.toBytes());
    const src_b64 = try alloc.alloc(u8, enc.calcSize(source.len));
    defer alloc.free(src_b64);
    _ = enc.encode(src_b64, source);
    const kid = keyId(kp.public_key.bytes);
    return std.fmt.allocPrint(alloc,
        \\{{"format":"{s}","tenant_id":"{s}","version":{d},"created_at":"{s}","key_id":"{s}","rules_b64":"{s}","sha256":"{s}","signature":"{s}"}}
    , .{ format, tenant_id, version, created_at, &kid, src_b64, &hex, sig_b64 });
}

test "signed pack verifies, tampered and unsigned packs are refused" {
    const a = std.testing.allocator;
    // Keys generated inside the test.
    const kp = Ed25519.KeyPair.generate(std.testing.io);
    const other = Ed25519.KeyPair.generate(std.testing.io);
    const source = "rule a { condition: true }";
    const pack = try sign(a, kp, "00000000-0000-0000-0000-000000000001", 3, "2026-11-10T00:00:00Z", source);
    defer a.free(pack);

    const ok = try verify(a, pack, kp.public_key);
    defer deinitPack(a, ok);
    try std.testing.expectEqualStrings(source, ok.source);
    try std.testing.expectEqual(@as(u64, 3), ok.version);

    // Signed by another key.
    try std.testing.expectError(error.PackWrongKey, verify(a, pack, other.public_key));

    // Rule source changed after signing (hash and source kept consistent,
    // so the signature is what catches it).
    {
        const forged_src = "rule a { condition: false }";
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(forged_src, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        const enc = std.base64.standard.Encoder;
        var b64: [64]u8 = undefined;
        const forged_b64 = enc.encode(&b64, forged_src);
        var orig_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(source, &orig_digest, .{});
        const orig_hex = std.fmt.bytesToHex(orig_digest, .lower);
        var orig_b64: [64]u8 = undefined;
        const orig_src_b64 = enc.encode(&orig_b64, source);
        const t1 = try std.mem.replaceOwned(u8, a, pack, &orig_hex, &hex);
        defer a.free(t1);
        const t2 = try std.mem.replaceOwned(u8, a, t1, orig_src_b64, forged_b64);
        defer a.free(t2);
        try std.testing.expectError(error.PackBadSignature, verify(a, t2, kp.public_key));
    }
    // Source changed but hash left alone.
    {
        const enc = std.base64.standard.Encoder;
        var orig_b64: [64]u8 = undefined;
        const orig_src_b64 = enc.encode(&orig_b64, source);
        var new_b64: [64]u8 = undefined;
        const forged = enc.encode(&new_b64, "rule b { condition: true }");
        const t = try std.mem.replaceOwned(u8, a, pack, orig_src_b64, forged);
        defer a.free(t);
        try std.testing.expectError(error.PackHashMismatch, verify(a, t, kp.public_key));
    }
    // Version bumped.
    {
        const t = try std.mem.replaceOwned(u8, a, pack, "\"version\":3", "\"version\":4");
        defer a.free(t);
        try std.testing.expectError(error.PackBadSignature, verify(a, t, kp.public_key));
    }
    // No signature, or an empty one.
    {
        const idx = std.mem.indexOf(u8, pack, ",\"signature\"").?;
        const unsigned = try std.mem.concat(a, u8, &.{ pack[0..idx], "}" });
        defer a.free(unsigned);
        try std.testing.expectError(error.PackUnsigned, verify(a, unsigned, kp.public_key));
        const empty = try std.mem.concat(a, u8, &.{ pack[0..idx], ",\"signature\":\"\"}" });
        defer a.free(empty);
        try std.testing.expectError(error.PackUnsigned, verify(a, empty, kp.public_key));
    }
    try std.testing.expectError(error.PackMalformed, verify(a, "not json", kp.public_key));
}

test "pack signed by the server verifies (shared vector)" {
    // Produced by server/src/routes/yara_rules.zig buildPack with the
    // test-only seed bytes 0..31; the server test checks the same bytes.
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const pack =
        \\{"format":"tawny-yara-pack-v1","tenant_id":"00000000-0000-0000-0000-000000000001","version":42,"created_at":"2026-11-10T00:00:00Z","key_id":"56475aa75463474c0285df5dbf2bcab7","rules_b64":"cnVsZSBnb2xkZW5fcGFjayB7IGNvbmRpdGlvbjogdHJ1ZSB9Cg==","sha256":"5001c139c60708851dbc2ceaafbe756d48b57a832e36936bd1456c423f7c091c","signature":"kkzHrm9dM8M9MQYknKpqNGipqAEjuLq/oLjV9teWYsC2527MtLnDG8zEswRTkHKzvUF1UUZ8UrS0RywYhzuvDg=="}
    ;
    const p = try verify(std.testing.allocator, pack, kp.public_key);
    defer deinitPack(std.testing.allocator, p);
    try std.testing.expectEqualStrings("rule golden_pack { condition: true }\n", p.source);
}
