//! Pinned YARA rule-pack public key. The server sends it in the enrolment
//! reply; the agent writes it once to `<state_path>.yarakey`. A
//! `yara_rule_key` in config.toml takes precedence. The key is public, so
//! it is a plain file, but it is only written when none exists, so a
//! later server can't swap it without an operator removing the file.

const std = @import("std");
const iox = @import("io_compat.zig");

pub fn path(alloc: std.mem.Allocator, state_path: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, "{s}.yarakey", .{state_path});
}

pub fn valid(b64: []const u8) bool {
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(b64) catch return false;
    if (n != 32) return false;
    var raw: [32]u8 = undefined;
    dec.decode(&raw, b64) catch return false;
    _ = std.crypto.sign.Ed25519.PublicKey.fromBytes(raw) catch return false;
    return true;
}

/// Write the key unless a pinned key is already there.
pub fn pin(alloc: std.mem.Allocator, state_path: []const u8, b64: []const u8) !void {
    if (!valid(b64)) return error.InvalidRuleKey;
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
    const k1 = std.crypto.sign.Ed25519.KeyPair.generate(std.testing.io);
    const k2 = std.crypto.sign.Ed25519.KeyPair.generate(std.testing.io);
    var b1: [44]u8 = undefined;
    var b2: [44]u8 = undefined;
    const t1 = std.base64.standard.Encoder.encode(&b1, &k1.public_key.bytes);
    const t2 = std.base64.standard.Encoder.encode(&b2, &k2.public_key.bytes);
    try std.testing.expectError(error.InvalidRuleKey, pin(a, state, "not-a-key"));
    try std.testing.expect(load(a, state) == null);
    try pin(a, state, t1);
    try pin(a, state, t2); // ignored: already pinned
    const got = load(a, state).?;
    defer a.free(got);
    try std.testing.expectEqualStrings(t1, got);
}
