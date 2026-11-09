//! File quarantine and restore (#57, target-edr §9.4). Windows, Linux, macOS.
//!
//! Quarantine targets a file by path plus SHA-256; it refuses if the live
//! file's hash does not match. The content is XOR-encoded with a fixed,
//! non-secret key (`xor_key`) so the stored copy cannot run and antivirus
//! leaves it alone, then written to `<dir>/<sha256>.bin`, fsynced, and its
//! hash verified from the copy before the original is deleted. A sidecar
//! `<sha256>.json` records the original path, size, timestamps, hashes and,
//! on Windows, the original ACL as an SDDL string.
//!
//! Restore de-XORs the copy back to the original path. On Windows it re-applies
//! the saved SDDL through SetNamedSecurityInfoW; on Linux and macOS it restores
//! owner-only (0600) permissions, which is the limit of what the sidecar keeps
//! on those platforms.
//!
//! The XOR key is obfuscation, not cryptography: it exists to stop execution
//! and AV, not to keep the bytes secret from an operator.

const std = @import("std");
const builtin = @import("builtin");
const iox = @import("io_compat.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Fixed, published XOR key. Obfuscation only.
pub const xor_key = [_]u8{ 0x54, 0x61, 0x77, 0x6e, 0x79, 0x51, 0x75, 0x61 }; // "TawnyQua"

pub const Error = error{
    HashMismatch,
    QuarantineVerifyFailed,
    SidecarMissing,
    FileTooBig,
};

const max_file_bytes: usize = 512 * 1024 * 1024;

fn xorInPlace(buf: []u8) void {
    for (buf, 0..) |*b, i| b.* ^= xor_key[i % xor_key.len];
}

fn sha256Hex(data: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

pub const Record = struct {
    original_path: []const u8,
    sha256: [64]u8,
    size: u64,
};

/// Quarantine a file. `expected_sha256` is lower-case hex. On success the
/// original is deleted and a sidecar is written. Caller frees `original_path`
/// is not needed; nothing is returned but the record fields.
pub fn quarantine(
    alloc: std.mem.Allocator,
    dir: []const u8,
    target_path: []const u8,
    expected_sha256: []const u8,
) !Record {
    const io = iox.current();
    const data = std.Io.Dir.cwd().readFileAlloc(io, target_path, alloc, .limited(max_file_bytes)) catch |err| switch (err) {
        error.FileTooBig, error.StreamTooLong => return error.FileTooBig,
        else => return err,
    };
    defer alloc.free(data);

    const got = sha256Hex(data);
    if (expected_sha256.len != got.len or !std.ascii.eqlIgnoreCase(expected_sha256, &got)) {
        return error.HashMismatch;
    }

    std.Io.Dir.cwd().createDirPath(io, dir) catch {};

    const bin_path = try std.fmt.allocPrint(alloc, "{s}/{s}.bin", .{ dir, got });
    defer alloc.free(bin_path);

    const encoded = try alloc.dupe(u8, data);
    defer alloc.free(encoded);
    xorInPlace(encoded);

    {
        var f = try std.Io.Dir.cwd().createFile(io, bin_path, .{ .truncate = true });
        defer f.close(io);
        try f.writePositionalAll(io, encoded, 0);
        f.sync(io) catch {};
    }

    // Verify the copy decodes back to the expected hash before deleting.
    {
        const check = try std.Io.Dir.cwd().readFileAlloc(io, bin_path, alloc, .limited(max_file_bytes));
        defer alloc.free(check);
        xorInPlace(check);
        const back = sha256Hex(check);
        if (!std.mem.eql(u8, &back, &got)) return error.QuarantineVerifyFailed;
    }

    // Sidecar with metadata and, on Windows, the original ACL.
    var sddl_buf: ?[]u8 = null;
    defer if (sddl_buf) |s| alloc.free(s);
    const sddl: []const u8 = if (builtin.target.os.tag == .windows)
        (captureSddl(alloc, target_path) catch null) orelse ""
    else
        "";
    if (sddl.len > 0) sddl_buf = @constCast(sddl);

    const sidecar_path = try std.fmt.allocPrint(alloc, "{s}/{s}.json", .{ dir, got });
    defer alloc.free(sidecar_path);
    const sidecar = try std.json.Stringify.valueAlloc(alloc, .{
        .format = "tawny-quarantine-v1",
        .original_path = target_path,
        .sha256 = &got,
        .size = data.len,
        .acl_sddl = sddl,
        .platform = @tagName(builtin.target.os.tag),
    }, .{});
    defer alloc.free(sidecar);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = sidecar_path, .data = sidecar });

    // Lock down the copy and sidecar only after the read-back verification, so
    // a SYSTEM-only ACL never blocks the agent's own verify.
    restrictPermissions(bin_path);
    restrictPermissions(sidecar_path);

    // Only now remove the original.
    try std.Io.Dir.cwd().deleteFile(io, target_path);

    return .{ .original_path = target_path, .sha256 = got, .size = data.len };
}

/// Restore a quarantined file to its original path. Returns the path, owned
/// by the caller.
pub fn restore(alloc: std.mem.Allocator, dir: []const u8, sha256_hex: []const u8) ![]u8 {
    const io = iox.current();
    const sidecar_path = try std.fmt.allocPrint(alloc, "{s}/{s}.json", .{ dir, sha256_hex });
    defer alloc.free(sidecar_path);
    const raw = std.Io.Dir.cwd().readFileAlloc(io, sidecar_path, alloc, .limited(64 * 1024)) catch return error.SidecarMissing;
    defer alloc.free(raw);
    const Meta = struct {
        original_path: []const u8,
        sha256: []const u8,
        acl_sddl: []const u8 = "",
    };
    const parsed = std.json.parseFromSlice(Meta, alloc, raw, .{ .ignore_unknown_fields = true }) catch return error.SidecarMissing;
    defer parsed.deinit();

    const bin_path = try std.fmt.allocPrint(alloc, "{s}/{s}.bin", .{ dir, sha256_hex });
    defer alloc.free(bin_path);
    const encoded = try std.Io.Dir.cwd().readFileAlloc(io, bin_path, alloc, .limited(max_file_bytes));
    defer alloc.free(encoded);
    xorInPlace(encoded);

    const back = sha256Hex(encoded);
    if (!std.ascii.eqlIgnoreCase(parsed.value.sha256, &back)) return error.QuarantineVerifyFailed;

    const original = try alloc.dupe(u8, parsed.value.original_path);
    errdefer alloc.free(original);
    if (std.fs.path.dirname(original)) |d| std.Io.Dir.cwd().createDirPath(io, d) catch {};
    {
        var f = try std.Io.Dir.cwd().createFile(io, original, .{ .truncate = true });
        defer f.close(io);
        try f.writePositionalAll(io, encoded, 0);
        f.sync(io) catch {};
    }

    if (builtin.target.os.tag == .windows) {
        if (parsed.value.acl_sddl.len > 0) applySddl(alloc, original, parsed.value.acl_sddl) catch {};
    } else {
        restrictPermissions(original);
    }

    // Clean up the quarantine copy and sidecar.
    std.Io.Dir.cwd().deleteFile(io, bin_path) catch {};
    std.Io.Dir.cwd().deleteFile(io, sidecar_path) catch {};
    return original;
}

/// Owner/SYSTEM-only permissions. POSIX uses 0600; Windows uses a SYSTEM-only
/// SDDL on the quarantine copy.
fn restrictPermissions(path: []const u8) void {
    if (builtin.target.os.tag == .windows) {
        var buf: [1024]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buf);
        // Protected DACL, no inheritance: SYSTEM and local Administrators full
        // access, everyone else none. Admins are kept so an agent that is not
        // running as SYSTEM (CI, or a service misconfiguration) can still read
        // the copy back and restore it; normal users still cannot run it.
        applySddl(fba.allocator(), path, "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)") catch {};
        return;
    }
    const io = iox.current();
    var f = std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write }) catch return;
    defer f.close(io);
    f.setPermissions(io, @enumFromInt(0o600)) catch {};
}

// --- Windows ACL helpers (SDDL via GetNamedSecurityInfoW / SetNamedSecurityInfoW) ---

const WINAPI: std.lang.CallingConvention = .winapi;
const DWORD = u32;
const SE_FILE_OBJECT: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x00000004;
const SDDL_REVISION_1: u32 = 1;

extern "advapi32" fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
    sddl: [*:0]const u16,
    revision: DWORD,
    psd: *?*anyopaque,
    size: ?*usize,
) callconv(WINAPI) i32;
extern "advapi32" fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
    sd: *anyopaque,
    revision: DWORD,
    info: DWORD,
    sddl: *?[*:0]u16,
    len: ?*usize,
) callconv(WINAPI) i32;
extern "advapi32" fn GetNamedSecurityInfoW(
    name: [*:0]const u16,
    object_type: u32,
    info: DWORD,
    owner: ?*?*anyopaque,
    group: ?*?*anyopaque,
    dacl: ?*?*anyopaque,
    sacl: ?*?*anyopaque,
    psd: *?*anyopaque,
) callconv(WINAPI) DWORD;
extern "advapi32" fn SetNamedSecurityInfoW(
    name: [*:0]u16,
    object_type: u32,
    info: DWORD,
    owner: ?*anyopaque,
    group: ?*anyopaque,
    dacl: ?*anyopaque,
    sacl: ?*anyopaque,
) callconv(WINAPI) DWORD;
extern "advapi32" fn GetSecurityDescriptorDacl(
    sd: *anyopaque,
    present: *i32,
    dacl: *?*anyopaque,
    defaulted: *i32,
) callconv(WINAPI) i32;
extern "kernel32" fn LocalFree(mem: ?*anyopaque) callconv(WINAPI) ?*anyopaque;

fn toUtf16Z(alloc: std.mem.Allocator, s: []const u8) ![:0]u16 {
    return std.unicode.utf8ToUtf16LeAllocZ(alloc, s);
}

/// Read the file's DACL as an SDDL string. Caller frees.
fn captureSddl(alloc: std.mem.Allocator, path: []const u8) !?[]u8 {
    if (builtin.target.os.tag != .windows) return null;
    const wpath = try toUtf16Z(alloc, path);
    defer alloc.free(wpath);
    var psd: ?*anyopaque = null;
    const rc = GetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, null, null, null, null, &psd);
    if (rc != 0 or psd == null) return null;
    defer _ = LocalFree(psd);
    var sddl_ptr: ?[*:0]u16 = null;
    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(psd.?, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl_ptr, null) == 0) return null;
    defer _ = LocalFree(@ptrCast(sddl_ptr));
    const ptr = sddl_ptr orelse return null;
    const len = std.mem.len(ptr);
    return try std.unicode.utf16LeToUtf8Alloc(alloc, ptr[0..len]);
}

/// Apply an SDDL DACL to a file.
fn applySddl(alloc: std.mem.Allocator, path: []const u8, sddl: []const u8) !void {
    if (builtin.target.os.tag != .windows) return;
    const wpath = try toUtf16Z(alloc, path);
    defer alloc.free(wpath);
    const wsddl = try toUtf16Z(alloc, sddl);
    defer alloc.free(wsddl);
    var psd: ?*anyopaque = null;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(wsddl, SDDL_REVISION_1, &psd, null) == 0) return error.SddlParseFailed;
    defer _ = LocalFree(psd);
    var present: i32 = 0;
    var dacl: ?*anyopaque = null;
    var defaulted: i32 = 0;
    if (GetSecurityDescriptorDacl(psd.?, &present, &dacl, &defaulted) == 0) return error.SddlParseFailed;
    const rc = SetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, null, null, dacl, null);
    if (rc != 0) return error.SetAclFailed;
}

test "xor is reversible and hashable" {
    var data = "MZ\x90\x00 fake executable".*;
    const original = data;
    xorInPlace(&data);
    try std.testing.expect(!std.mem.eql(u8, &original, &data));
    xorInPlace(&data);
    try std.testing.expectEqualSlices(u8, &original, &data);
}

test "quarantine then restore round-trips the same bytes and hash" {
    if (builtin.target.os.tag == .windows) return error.SkipZigTest; // live FS test runs in Windows CI
    const a = std.testing.allocator;
    const io = iox.current();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(root);

    const src = try std.fs.path.join(a, &.{ root, "target.bin" });
    defer a.free(src);
    const qdir = try std.fs.path.join(a, &.{ root, "quarantine" });
    defer a.free(qdir);

    const content = "MZ this pretends to be a malicious binary \x00\x01\x02";
    {
        var f = try std.Io.Dir.cwd().createFile(io, src, .{ .truncate = true });
        defer f.close(io);
        try f.writePositionalAll(io, content, 0);
    }
    const want = sha256Hex(content);

    const rec = try quarantine(a, qdir, src, &want);
    try std.testing.expectEqualSlices(u8, &want, &rec.sha256);

    // Original is gone; the stored copy is not the plaintext.
    try std.testing.expect(std.Io.Dir.cwd().access(io, src, .{}) == error.FileNotFound);
    const bin = try std.fmt.allocPrint(a, "{s}/{s}.bin", .{ qdir, want });
    defer a.free(bin);
    const stored = try std.Io.Dir.cwd().readFileAlloc(io, bin, a, .limited(max_file_bytes));
    defer a.free(stored);
    try std.testing.expect(!std.mem.eql(u8, stored, content));

    // Hash mismatch is refused.
    {
        var f = try std.Io.Dir.cwd().createFile(io, src, .{ .truncate = true });
        defer f.close(io);
        try f.writePositionalAll(io, "different", 0);
    }
    try std.testing.expectError(error.HashMismatch, quarantine(a, qdir, src, &want));
    std.Io.Dir.cwd().deleteFile(io, src) catch {};

    const restored = try restore(a, qdir, &want);
    defer a.free(restored);
    const back = try std.Io.Dir.cwd().readFileAlloc(io, restored, a, .limited(max_file_bytes));
    defer a.free(back);
    try std.testing.expectEqualStrings(content, back);
    try std.testing.expectEqualSlices(u8, &want, &sha256Hex(back));
}
