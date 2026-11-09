//! Release signing public key, compiled into the agent (target-edr §10
//! "Updates"). The private half is an offline minisign key held by the
//! project owner. CI only signs through a protected GitHub environment.
//!
//! PLACEHOLDER: no release key exists yet. While `public_key` is the
//! placeholder below, `isPlaceholder()` is true and the updater refuses to
//! update (state `disabled_no_release_key`). To turn updates on, replace the
//! base64 line with the second line of the real `minisign.pub` and rebuild.
//! Never put a private key in this repository.

const std = @import("std");
const minisign = @import("minisign.zig");

/// Base64 public key line (`"Ed" || key_id || key`). The all-`A` value
/// decodes to a zero key id and a zero key, which is not a usable Ed25519
/// point, so it can never verify a signature even by accident.
pub const public_key = "RWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

pub const placeholder = "RWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

pub fn isPlaceholder() bool {
    return std.mem.eql(u8, public_key, placeholder);
}

/// The compiled-in key, or `error.NoReleaseKey` while it is the placeholder.
pub fn get() !minisign.PublicKey {
    if (isPlaceholder()) return error.NoReleaseKey;
    return minisign.parsePublicKey(public_key);
}

test "release key is still the placeholder and refuses to load" {
    // When the real key lands, this test changes with it on purpose.
    try std.testing.expect(isPlaceholder());
    try std.testing.expectError(error.NoReleaseKey, get());
    // The placeholder is the right length for a minisign key line.
    try std.testing.expectEqual(@as(usize, 56), public_key.len);
}
