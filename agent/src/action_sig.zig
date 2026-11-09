//! Verify server-signed response actions (#57).
//!
//! The server (`server/src/crypto/action_sig.zig`) signs the canonical string
//!   tawny-action-v1\n<action_id>\n<agent_id>\n<action_type>\n<expires_at>\n<sha256 hex of payload>
//! with the action key. The agent pins the public key (enrolment or TOFU
//! heartbeat) and refuses any action that is unsigned, expired, has a payload
//! that does not match its signed hash, or whose signature does not verify.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

pub const prefix = "tawny-action-v1";

pub const VerifyError = error{
    ActionUnsigned,
    ActionExpired,
    ActionPayloadMismatch,
    ActionSignatureInvalid,
    ActionKeyMissing,
    OutOfMemory,
};

pub const Fields = struct {
    action_id: []const u8,
    agent_id: []const u8,
    action_type: []const u8,
    expires_at: []const u8,
    payload: []const u8,
    /// Hash the server signed, lower-case hex. Empty if absent.
    payload_hash: []const u8,
    /// Base64 Ed25519 signature, or null.
    signature: ?[]const u8,
};

/// Build the canonical string. Caller frees.
pub fn canonical(
    alloc: std.mem.Allocator,
    action_id: []const u8,
    agent_id: []const u8,
    action_type: []const u8,
    expires_at: []const u8,
    payload_sha256_hex: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(alloc, "{s}\n{s}\n{s}\n{s}\n{s}\n{s}", .{
        prefix, action_id, agent_id, action_type, expires_at, payload_sha256_hex,
    });
}

/// Lower-case hex SHA-256 of the payload bytes.
pub fn payloadHashHex(payload: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

/// RFC 3339 `YYYY-MM-DDTHH:MM:SS...` to a Unix second count, or null.
pub fn parseRfc3339(text: []const u8) ?i64 {
    if (text.len < 19 or text[4] != '-' or text[7] != '-' or
        (text[10] != 'T' and text[10] != ' ') or text[13] != ':' or text[16] != ':') return null;
    const year = std.fmt.parseInt(i64, text[0..4], 10) catch return null;
    const month = std.fmt.parseInt(i64, text[5..7], 10) catch return null;
    const day = std.fmt.parseInt(i64, text[8..10], 10) catch return null;
    const hour = std.fmt.parseInt(i64, text[11..13], 10) catch return null;
    const min = std.fmt.parseInt(i64, text[14..16], 10) catch return null;
    const sec = std.fmt.parseInt(i64, text[17..19], 10) catch return null;
    var y = year;
    y -= @intFromBool(month <= 2);
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const mp: i64 = if (month > 2) month - 3 else month + 9;
    const doy = @divFloor(153 * mp + 2, 5) + day - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    return days * 86400 + hour * 3600 + min * 60 + sec;
}

/// Check a signed action. `now_unix` is the current time in seconds and
/// `public_key` the pinned server key (null when none is pinned).
pub fn verify(
    alloc: std.mem.Allocator,
    f: Fields,
    public_key: ?Ed25519.PublicKey,
    now_unix: i64,
) VerifyError!void {
    const sig_b64 = f.signature orelse return error.ActionUnsigned;
    if (sig_b64.len == 0) return error.ActionUnsigned;
    const key = public_key orelse return error.ActionKeyMissing;

    // The payload the agent received must match the hash the server signed.
    const got = payloadHashHex(f.payload);
    if (f.payload_hash.len != got.len or !std.mem.eql(u8, f.payload_hash, &got)) {
        return error.ActionPayloadMismatch;
    }

    // Expiry is enforced locally so a replayed action past its deadline fails
    // even if the server missed it.
    if (parseRfc3339(f.expires_at)) |exp| {
        if (now_unix > exp) return error.ActionExpired;
    } else {
        return error.ActionSignatureInvalid;
    }

    var raw: [Ed25519.Signature.encoded_length]u8 = undefined;
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(sig_b64) catch return error.ActionSignatureInvalid;
    if (n != raw.len) return error.ActionSignatureInvalid;
    dec.decode(&raw, sig_b64) catch return error.ActionSignatureInvalid;
    const sig = Ed25519.Signature.fromBytes(raw);

    const msg = try canonical(alloc, f.action_id, f.agent_id, f.action_type, f.expires_at, f.payload_hash);
    defer alloc.free(msg);
    sig.verify(msg, key) catch return error.ActionSignatureInvalid;
}

fn testSign(alloc: std.mem.Allocator, kp: Ed25519.KeyPair, f: Fields) ![]u8 {
    const msg = try canonical(alloc, f.action_id, f.agent_id, f.action_type, f.expires_at, f.payload_hash);
    defer alloc.free(msg);
    const sig = try kp.sign(msg, null);
    const raw = sig.toBytes();
    var buf: [std.base64.standard.Encoder.calcSize(raw.len)]u8 = undefined;
    return alloc.dupe(u8, std.base64.standard.Encoder.encode(&buf, &raw));
}

test "good, tampered, expired, wrong key" {
    const a = std.testing.allocator;
    const kp = Ed25519.KeyPair.generate(std.testing.io);
    const payload = "{\"pid\":1234}";
    const hash = payloadHashHex(payload);
    var f = Fields{
        .action_id = "11111111-1111-4111-8111-111111111111",
        .agent_id = "22222222-2222-4222-8222-222222222222",
        .action_type = "kill_process",
        .expires_at = "2999-01-01T00:00:00Z",
        .payload = payload,
        .payload_hash = &hash,
        .signature = null,
    };
    const sig = try testSign(a, kp, f);
    defer a.free(sig);
    f.signature = sig;

    // Good.
    try verify(a, f, kp.public_key, 1_700_000_000);

    // Unsigned.
    var unsigned = f;
    unsigned.signature = null;
    try std.testing.expectError(error.ActionUnsigned, verify(a, unsigned, kp.public_key, 1_700_000_000));

    // No pinned key.
    try std.testing.expectError(error.ActionKeyMissing, verify(a, f, null, 1_700_000_000));

    // Tampered payload (hash no longer matches).
    var tampered = f;
    tampered.payload = "{\"pid\":9999}";
    try std.testing.expectError(error.ActionPayloadMismatch, verify(a, tampered, kp.public_key, 1_700_000_000));

    // Tampered type (signature no longer verifies).
    var retyped = f;
    retyped.action_type = "quarantine_file";
    try std.testing.expectError(error.ActionSignatureInvalid, verify(a, retyped, kp.public_key, 1_700_000_000));

    // Expired.
    var expired = f;
    expired.expires_at = "2000-01-01T00:00:00Z";
    const ehash = payloadHashHex(payload);
    expired.payload_hash = &ehash;
    const esig = try testSign(a, kp, expired);
    defer a.free(esig);
    expired.signature = esig;
    try std.testing.expectError(error.ActionExpired, verify(a, expired, kp.public_key, 1_700_000_000));

    // Wrong key.
    const other = Ed25519.KeyPair.generate(std.testing.io);
    try std.testing.expectError(error.ActionSignatureInvalid, verify(a, f, other.public_key, 1_700_000_000));
}

test "canonical matches the documented layout" {
    const a = std.testing.allocator;
    const msg = try canonical(a, "id", "agent", "kill_process", "2026-11-10T00:00:00Z", "deadbeef");
    defer a.free(msg);
    try std.testing.expectEqualStrings(
        "tawny-action-v1\nid\nagent\nkill_process\n2026-11-10T00:00:00Z\ndeadbeef",
        msg,
    );
}
