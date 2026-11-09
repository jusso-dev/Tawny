//! Server action signatures (#57).
//!
//! The server signs every response action with the action key
//! (`state.actionKey`, an Ed25519 key separate from the JWT key). The agent
//! pins the public key at enrolment (or from the heartbeat, trust on first
//! use) and refuses any action that is unsigned, expired, tampered with, or
//! signed by another key.
//!
//! Canonical string, one field per line, no trailing newline:
//!   tawny-action-v1
//!   <action_id>
//!   <agent_id>
//!   <action_type>
//!   <expires_at>
//!   <sha256 hex of the payload JSON>
//!
//! `expires_at` is the RFC 3339 string the heartbeat sends. The payload hash
//! is the lower-case hex SHA-256 of the exact payload bytes delivered to the
//! agent. The agent rebuilds this string from the action it received and
//! verifies the Ed25519 signature before it runs anything.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

pub const prefix = "tawny-action-v1";

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

/// Sign the canonical string, returning the base64 signature. Caller frees.
pub fn sign(
    alloc: std.mem.Allocator,
    kp: Ed25519.KeyPair,
    action_id: []const u8,
    agent_id: []const u8,
    action_type: []const u8,
    expires_at: []const u8,
    payload_sha256_hex: []const u8,
) ![]u8 {
    const msg = try canonical(alloc, action_id, agent_id, action_type, expires_at, payload_sha256_hex);
    defer alloc.free(msg);
    const sig = try kp.sign(msg, null);
    const raw = sig.toBytes();
    var buf: [std.base64.standard.Encoder.calcSize(raw.len)]u8 = undefined;
    const b64 = std.base64.standard.Encoder.encode(&buf, &raw);
    return alloc.dupe(u8, b64);
}

test "sign then verify round-trips, tamper fails" {
    const a = std.testing.allocator;
    const kp = Ed25519.KeyPair.generate(std.testing.io);
    const sig_b64 = try sign(a, kp, "id-1", "agent-1", "kill_process", "2026-11-10T00:00:00Z", "abc123");
    defer a.free(sig_b64);

    const msg = try canonical(a, "id-1", "agent-1", "kill_process", "2026-11-10T00:00:00Z", "abc123");
    defer a.free(msg);
    var raw: [Ed25519.Signature.encoded_length]u8 = undefined;
    try std.base64.standard.Decoder.decode(&raw, sig_b64);
    const sig = Ed25519.Signature.fromBytes(raw);
    try sig.verify(msg, kp.public_key);

    const bad = try canonical(a, "id-1", "agent-1", "suspend_process", "2026-11-10T00:00:00Z", "abc123");
    defer a.free(bad);
    try std.testing.expectError(error.SignatureVerificationFailed, sig.verify(bad, kp.public_key));

    const other = Ed25519.KeyPair.generate(std.testing.io);
    try std.testing.expectError(error.SignatureVerificationFailed, sig.verify(msg, other.public_key));
}
