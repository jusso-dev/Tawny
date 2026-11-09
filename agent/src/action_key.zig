//! Pinned server action public key (#57). The server returns it in the
//! enrolment reply (`action_public_key`) and in every heartbeat. The agent
//! writes it once to `<state_path>.actionkey` and verifies every response
//! action against it. An `action_public_key` in config.toml takes precedence.
//!
//! Trust on first use (TOFU): agents enrolled before #57 have no pinned key.
//! The first heartbeat that carries `action_public_key` pins it, over the
//! same TLS channel the JWT already trusts, and the agent logs that it did.
//! The window is that first heartbeat; after it, a different key is refused,
//! so an operator must remove the file to re-pin. This is the same model the
//! YARA rule key already uses, and the two keys are the same bytes.

const std = @import("std");
const iox = @import("io_compat.zig");
const Ed25519 = std.crypto.sign.Ed25519;

pub fn path(alloc: std.mem.Allocator, state_path: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, "{s}.actionkey", .{state_path});
}

pub fn valid(b64: []const u8) bool {
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(b64) catch return false;
    if (n != 32) return false;
    var raw: [32]u8 = undefined;
    dec.decode(&raw, b64) catch return false;
    _ = Ed25519.PublicKey.fromBytes(raw) catch return false;
    return true;
}

/// Decode a base64 key to a PublicKey, or null.
pub fn decode(b64: ?[]const u8) ?Ed25519.PublicKey {
    const text = b64 orelse return null;
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(text) catch return null;
    if (n != 32) return null;
    var raw: [32]u8 = undefined;
    dec.decode(&raw, text) catch return null;
    return Ed25519.PublicKey.fromBytes(raw) catch null;
}

/// Write the key unless one is already pinned (trust on first use).
pub fn pin(alloc: std.mem.Allocator, state_path: []const u8, b64: []const u8) !void {
    if (!valid(b64)) return error.InvalidActionKey;
    const p = try path(alloc, state_path);
    defer alloc.free(p);
    const io = iox.current();
    if (std.Io.Dir.cwd().access(io, p, .{})) |_| return else |_| {}
    if (std.fs.path.dirname(p)) |d| try std.Io.Dir.cwd().createDirPath(io, d);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = b64 });
}

/// Pinned key text, or null. Caller frees.
pub fn load(alloc: std.mem.Allocator, state_path: []const u8) ?[]u8 {
    const p = path(alloc, state_path) catch return null;
    defer alloc.free(p);
    const io = iox.current();
    const raw = std.Io.Dir.cwd().readFileAlloc(io, p, alloc, .limited(256)) catch return null;
    const trimmed = std.mem.trim(u8, raw, " \r\n");
    if (!valid(trimmed)) {
        alloc.free(raw);
        return null;
    }
    const out = alloc.dupe(u8, trimmed) catch {
        alloc.free(raw);
        return null;
    };
    alloc.free(raw);
    return out;
}

test "pin once, refuse junk, load back" {
    const a = std.testing.allocator;
    const io = iox.current();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(dir);
    const state = try std.fs.path.join(a, &.{ dir, "state.toml" });
    defer a.free(state);
    const k1 = Ed25519.KeyPair.generate(std.testing.io);
    const k2 = Ed25519.KeyPair.generate(std.testing.io);
    var b1: [44]u8 = undefined;
    var b2: [44]u8 = undefined;
    const t1 = std.base64.standard.Encoder.encode(&b1, &k1.public_key.bytes);
    const t2 = std.base64.standard.Encoder.encode(&b2, &k2.public_key.bytes);
    try std.testing.expectError(error.InvalidActionKey, pin(a, state, "not-a-key"));
    try std.testing.expect(load(a, state) == null);
    try pin(a, state, t1);
    try pin(a, state, t2); // ignored: already pinned
    const got = load(a, state).?;
    defer a.free(got);
    try std.testing.expectEqualStrings(t1, got);
    try std.testing.expect(decode(got) != null);
}
