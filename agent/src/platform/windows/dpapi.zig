//! Windows secret storage for the agent JWT and device seed (#58).
//!
//! Layer 1, always: DPAPI machine scope. `CryptProtectData` with
//! `CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN` and a fixed
//! entropy value. Any process on the machine can call `CryptUnprotectData`
//! on a machine-scope blob, so the file ACL (SYSTEM and Administrators only)
//! is what keeps other users out, and the entropy stops a generic DPAPI
//! dumper from decrypting it blind.
//!
//! Layer 2, when a TPM is usable: the DPAPI blob is wrapped with RSA-OAEP
//! (SHA-256) under a non-exportable 2048-bit RSA key in the Microsoft
//! Platform Crypto Provider (`NCryptOpenStorageProvider` with
//! `MS_PLATFORM_KEY_STORAGE_PROVIDER`), machine key `TawnyAgentWrap`. The
//! secrets are at most a few hundred bytes after DPAPI, so the blob is split
//! into OAEP-sized chunks. Copying the file to another machine is useless
//! without that TPM. When the provider or key can't be used, the agent
//! falls back to DPAPI alone and says so in `key_protection`.
//!
//! File: `<dir>\<account>.dpapi`, written by temp file and rename, ACL
//! `D:PAI(A;;FA;;;SY)(A;;FA;;;BA)`. Layout:
//!   magic "TWNK" | version u8 = 1 | wrap u8 (0 = DPAPI, 1 = TPM) | body
//! For wrap = 1 the body is a sequence of `u16 LE length | RSA ciphertext`.
//!
//! Constants and signatures are checked against windows-rs
//! (`Win32/dpapi`, `Win32/ncrypt`, `Win32/bcrypt`, `Win32/winerror`) and
//! pinned by a test that runs on every OS.

const std = @import("std");
const builtin = @import("builtin");
const iox = @import("../../io_compat.zig");

pub const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
pub const CRYPTPROTECT_LOCAL_MACHINE: u32 = 0x4;
pub const NCRYPT_SILENT_FLAG: u32 = 0x40;
pub const NCRYPT_MACHINE_KEY_FLAG: u32 = 0x20;
pub const NCRYPT_OVERWRITE_KEY_FLAG: u32 = 0x80;
pub const NCRYPT_PAD_OAEP_FLAG: u32 = 0x4;
pub const NTE_BAD_KEYSET: u32 = 0x80090016;
pub const NTE_EXISTS: u32 = 0x8009000F;
pub const ms_platform_provider = "Microsoft Platform Crypto Provider";
pub const wrap_key_name = "TawnyAgentWrap";
pub const rsa_bits: u32 = 2048;
/// RSA-OAEP with SHA-256: k - 2*hLen - 2 = 256 - 64 - 2.
pub const oaep_max_plain: usize = rsa_bits / 8 - 2 * 32 - 2;

/// Fixed DPAPI entropy. Not a secret: it only ties blobs to this purpose.
pub const entropy = "tawny-agent-keystore-v1";

pub const file_acl = "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)";
const magic = "TWNK";
const format_version: u8 = 1;

pub const Wrap = enum(u8) { dpapi = 0, tpm = 1 };

pub const Error = error{
    DpapiFailed,
    TpmUnavailable,
    TpmFailed,
    CorruptBlob,
    OutOfMemory,
    KeystoreUnavailable,
};

pub var last_error: u32 = 0;

const WINAPI: std.lang.CallingConvention = .winapi;
const DATA_BLOB = extern struct {
    cbData: u32,
    pbData: ?[*]u8,
};
const BCRYPT_OAEP_PADDING_INFO = extern struct {
    pszAlgId: [*:0]const u16,
    pbLabel: ?[*]u8,
    cbLabel: u32,
};
const NCRYPT_HANDLE = usize;

const win = if (builtin.target.os.tag == .windows) struct {
    extern "crypt32" fn CryptProtectData(
        in: *const DATA_BLOB,
        descr: ?[*:0]const u16,
        entropy: ?*const DATA_BLOB,
        reserved: ?*anyopaque,
        prompt: ?*anyopaque,
        flags: u32,
        out: *DATA_BLOB,
    ) callconv(WINAPI) i32;
    extern "crypt32" fn CryptUnprotectData(
        in: *const DATA_BLOB,
        descr: ?*?[*:0]u16,
        entropy: ?*const DATA_BLOB,
        reserved: ?*anyopaque,
        prompt: ?*anyopaque,
        flags: u32,
        out: *DATA_BLOB,
    ) callconv(WINAPI) i32;
    extern "kernel32" fn LocalFree(mem: ?*anyopaque) callconv(WINAPI) ?*anyopaque;
    extern "kernel32" fn GetLastError() callconv(WINAPI) u32;

    extern "ncrypt" fn NCryptOpenStorageProvider(prov: *NCRYPT_HANDLE, name: [*:0]const u16, flags: u32) callconv(WINAPI) i32;
    extern "ncrypt" fn NCryptOpenKey(prov: NCRYPT_HANDLE, key: *NCRYPT_HANDLE, name: [*:0]const u16, legacy_spec: u32, flags: u32) callconv(WINAPI) i32;
    extern "ncrypt" fn NCryptCreatePersistedKey(prov: NCRYPT_HANDLE, key: *NCRYPT_HANDLE, alg: [*:0]const u16, name: [*:0]const u16, legacy_spec: u32, flags: u32) callconv(WINAPI) i32;
    extern "ncrypt" fn NCryptSetProperty(obj: NCRYPT_HANDLE, prop: [*:0]const u16, input: [*]const u8, len: u32, flags: u32) callconv(WINAPI) i32;
    extern "ncrypt" fn NCryptFinalizeKey(key: NCRYPT_HANDLE, flags: u32) callconv(WINAPI) i32;
    extern "ncrypt" fn NCryptEncrypt(key: NCRYPT_HANDLE, input: [*]const u8, in_len: u32, padding: ?*const anyopaque, output: ?[*]u8, out_len: u32, result: *u32, flags: u32) callconv(WINAPI) i32;
    extern "ncrypt" fn NCryptDecrypt(key: NCRYPT_HANDLE, input: [*]const u8, in_len: u32, padding: ?*const anyopaque, output: ?[*]u8, out_len: u32, result: *u32, flags: u32) callconv(WINAPI) i32;
    extern "ncrypt" fn NCryptFreeObject(obj: NCRYPT_HANDLE) callconv(WINAPI) i32;
} else struct {};

const W = std.unicode.utf8ToUtf16LeStringLiteral;

// ---------------------------------------------------------------------------
// DPAPI

/// DPAPI machine-scope protect. Caller frees.
pub fn protect(alloc: std.mem.Allocator, plain: []const u8) Error![]u8 {
    if (builtin.target.os.tag != .windows) return error.KeystoreUnavailable;
    var in = DATA_BLOB{ .cbData = @intCast(plain.len), .pbData = @constCast(plain.ptr) };
    var ent = DATA_BLOB{ .cbData = entropy.len, .pbData = @constCast(entropy.ptr) };
    var out = DATA_BLOB{ .cbData = 0, .pbData = null };
    if (win.CryptProtectData(&in, W("tawny-agent"), &ent, null, null, CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &out) == 0) {
        last_error = win.GetLastError();
        return error.DpapiFailed;
    }
    defer _ = win.LocalFree(out.pbData);
    return alloc.dupe(u8, out.pbData.?[0..out.cbData]);
}

/// DPAPI unprotect. Caller frees (and should secureZero).
pub fn unprotect(alloc: std.mem.Allocator, blob: []const u8) Error![]u8 {
    if (builtin.target.os.tag != .windows) return error.KeystoreUnavailable;
    var in = DATA_BLOB{ .cbData = @intCast(blob.len), .pbData = @constCast(blob.ptr) };
    var ent = DATA_BLOB{ .cbData = entropy.len, .pbData = @constCast(entropy.ptr) };
    var out = DATA_BLOB{ .cbData = 0, .pbData = null };
    if (win.CryptUnprotectData(&in, null, &ent, null, null, CRYPTPROTECT_UI_FORBIDDEN, &out) == 0) {
        last_error = win.GetLastError();
        return error.DpapiFailed;
    }
    defer {
        if (out.pbData) |p| std.crypto.secureZero(u8, p[0..out.cbData]);
        _ = win.LocalFree(out.pbData);
    }
    return alloc.dupe(u8, out.pbData.?[0..out.cbData]);
}

// ---------------------------------------------------------------------------
// TPM wrap through the Platform Crypto Provider

pub const Tpm = struct {
    prov: NCRYPT_HANDLE = 0,
    key: NCRYPT_HANDLE = 0,

    /// Open (or create on first use) the wrap key. `error.TpmUnavailable`
    /// when the provider or key cannot be used; callers fall back to DPAPI.
    pub fn open() Error!Tpm {
        if (builtin.target.os.tag != .windows) return error.TpmUnavailable;
        var t: Tpm = .{};
        var rc = win.NCryptOpenStorageProvider(&t.prov, W(ms_platform_provider), 0);
        if (rc != 0) return noteTpm(rc, error.TpmUnavailable);
        errdefer _ = win.NCryptFreeObject(t.prov);
        rc = win.NCryptOpenKey(t.prov, &t.key, W(wrap_key_name), 0, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG);
        if (rc == 0) return t;
        if (@as(u32, @bitCast(rc)) != NTE_BAD_KEYSET) return noteTpm(rc, error.TpmUnavailable);
        // First use: create a non-exportable machine RSA key. No export
        // policy is set, so the provider's default (not exportable) applies.
        rc = win.NCryptCreatePersistedKey(t.prov, &t.key, W("RSA"), W(wrap_key_name), 0, NCRYPT_MACHINE_KEY_FLAG);
        if (rc != 0) return noteTpm(rc, error.TpmUnavailable);
        errdefer _ = win.NCryptFreeObject(t.key);
        const bits: u32 = rsa_bits;
        rc = win.NCryptSetProperty(t.key, W("Length"), std.mem.asBytes(&bits), 4, 0);
        if (rc != 0) return noteTpm(rc, error.TpmUnavailable);
        rc = win.NCryptFinalizeKey(t.key, NCRYPT_SILENT_FLAG);
        if (rc != 0) return noteTpm(rc, error.TpmUnavailable);
        return t;
    }

    pub fn close(self: *Tpm) void {
        if (builtin.target.os.tag != .windows) return;
        if (self.key != 0) _ = win.NCryptFreeObject(self.key);
        if (self.prov != 0) _ = win.NCryptFreeObject(self.prov);
        self.* = .{};
    }

    fn padding() BCRYPT_OAEP_PADDING_INFO {
        return .{ .pszAlgId = W("SHA256"), .pbLabel = null, .cbLabel = 0 };
    }

    /// RSA-OAEP encrypt `plain` in chunks. Caller frees.
    pub fn wrap(self: *Tpm, alloc: std.mem.Allocator, plain: []const u8) Error![]u8 {
        if (builtin.target.os.tag != .windows) return error.TpmUnavailable;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(alloc);
        const pad = padding();
        var cipher: [rsa_bits / 8]u8 = undefined;
        var off: usize = 0;
        while (off < plain.len) {
            const n = @min(oaep_max_plain, plain.len - off);
            var got: u32 = 0;
            const rc = win.NCryptEncrypt(self.key, plain[off..].ptr, @intCast(n), &pad, &cipher, cipher.len, &got, NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG);
            if (rc != 0) return noteTpm(rc, error.TpmFailed);
            var len_le: [2]u8 = undefined;
            std.mem.writeInt(u16, &len_le, @intCast(got), .little);
            try out.appendSlice(alloc, &len_le);
            try out.appendSlice(alloc, cipher[0..got]);
            off += n;
        }
        return out.toOwnedSlice(alloc);
    }

    /// Reverse of `wrap`. Caller frees.
    pub fn unwrap(self: *Tpm, alloc: std.mem.Allocator, body: []const u8) Error![]u8 {
        if (builtin.target.os.tag != .windows) return error.TpmUnavailable;
        var out: std.ArrayList(u8) = .empty;
        errdefer {
            std.crypto.secureZero(u8, out.items);
            out.deinit(alloc);
        }
        const pad = padding();
        var plain: [rsa_bits / 8]u8 = undefined;
        defer std.crypto.secureZero(u8, &plain);
        var off: usize = 0;
        while (off < body.len) {
            if (body.len - off < 2) return error.CorruptBlob;
            const n = std.mem.readInt(u16, body[off..][0..2], .little);
            off += 2;
            if (n == 0 or n > plain.len or body.len - off < n) return error.CorruptBlob;
            var got: u32 = 0;
            const rc = win.NCryptDecrypt(self.key, body[off..].ptr, n, &pad, &plain, plain.len, &got, NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG);
            if (rc != 0) return noteTpm(rc, error.TpmFailed);
            try out.appendSlice(alloc, plain[0..got]);
            off += n;
        }
        return out.toOwnedSlice(alloc);
    }
};

fn noteTpm(rc: i32, err: Error) Error {
    last_error = @bitCast(rc);
    return err;
}

// ---------------------------------------------------------------------------
// Blob file format (pure, tested on every OS)

/// Frame a protected body. Caller frees.
pub fn encodeFile(alloc: std.mem.Allocator, wrap_kind: Wrap, body: []const u8) ![]u8 {
    const out = try alloc.alloc(u8, magic.len + 2 + body.len);
    @memcpy(out[0..magic.len], magic);
    out[magic.len] = format_version;
    out[magic.len + 1] = @backingInt(wrap_kind);
    @memcpy(out[magic.len + 2 ..], body);
    return out;
}

pub const Decoded = struct { wrap: Wrap, body: []const u8 };

pub fn decodeFile(bytes: []const u8) Error!Decoded {
    if (bytes.len < magic.len + 2) return error.CorruptBlob;
    if (!std.mem.eql(u8, bytes[0..magic.len], magic)) return error.CorruptBlob;
    if (bytes[magic.len] != format_version) return error.CorruptBlob;
    const w = std.enums.fromInt(Wrap, bytes[magic.len + 1]) orelse return error.CorruptBlob;
    return .{ .wrap = w, .body = bytes[magic.len + 2 ..] };
}

// ---------------------------------------------------------------------------
// Store: one file per secret under `dir`

pub const Mode = enum {
    /// Use the TPM when it opens, else DPAPI alone.
    auto,
    /// DPAPI alone (TAWNY_KEYSTORE_TPM=off, or tests).
    dpapi_only,
};

pub fn filePath(alloc: std.mem.Allocator, dir: []const u8, account: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, "{s}\\{s}.dpapi", .{ dir, account });
}

/// Protect and write. Returns how it was wrapped.
pub fn put(alloc: std.mem.Allocator, dir: []const u8, account: []const u8, value: []const u8, mode: Mode) Error!Wrap {
    const dp = try protect(alloc, value);
    defer alloc.free(dp);
    var wrap_kind: Wrap = .dpapi;
    var body: []const u8 = dp;
    var wrapped: ?[]u8 = null;
    defer if (wrapped) |w| alloc.free(w);
    if (mode == .auto) {
        if (Tpm.open()) |t| {
            var tpm = t;
            defer tpm.close();
            if (tpm.wrap(alloc, dp)) |w| {
                // Check the TPM can unwrap it before trusting the TPM copy.
                if (tpm.unwrap(alloc, w)) |back| {
                    defer alloc.free(back);
                    if (std.mem.eql(u8, back, dp)) {
                        wrapped = w;
                        body = w;
                        wrap_kind = .tpm;
                    } else alloc.free(w);
                } else |_| alloc.free(w);
            } else |_| {}
        } else |_| {}
    }
    const framed = encodeFile(alloc, wrap_kind, body) catch return error.OutOfMemory;
    defer alloc.free(framed);
    writeProtectedFile(alloc, dir, account, framed) catch return error.KeystoreUnavailable;
    return wrap_kind;
}

/// Read and unprotect. Null when the file does not exist. Caller frees.
pub fn get(alloc: std.mem.Allocator, dir: []const u8, account: []const u8, wrap_out: ?*Wrap) Error!?[]u8 {
    const path = filePath(alloc, dir, account) catch return error.OutOfMemory;
    defer alloc.free(path);
    const io = iox.current();
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .limited(64 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return null,
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.KeystoreUnavailable,
    };
    defer alloc.free(bytes);
    const d = try decodeFile(bytes);
    if (wrap_out) |w| w.* = d.wrap;
    switch (d.wrap) {
        .dpapi => return try unprotect(alloc, d.body),
        .tpm => {
            var tpm = try Tpm.open();
            defer tpm.close();
            const dp = try tpm.unwrap(alloc, d.body);
            defer {
                std.crypto.secureZero(u8, dp);
                alloc.free(dp);
            }
            return try unprotect(alloc, dp);
        },
    }
}

pub fn delete(alloc: std.mem.Allocator, dir: []const u8, account: []const u8) Error!void {
    const path = filePath(alloc, dir, account) catch return error.OutOfMemory;
    defer alloc.free(path);
    std.Io.Dir.cwd().deleteFile(iox.current(), path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return error.KeystoreUnavailable,
    };
}

fn writeProtectedFile(alloc: std.mem.Allocator, dir: []const u8, account: []const u8, bytes: []const u8) !void {
    const io = iox.current();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, dir);
    const path = try filePath(alloc, dir, account);
    defer alloc.free(path);
    const tmp = try std.fmt.allocPrint(alloc, "{s}.tmp", .{path});
    defer alloc.free(tmp);
    {
        var f = try cwd.createFile(io, tmp, .{ .truncate = true });
        defer f.close(io);
        try f.writePositionalAll(io, bytes, 0);
        try f.sync(io);
    }
    // Restrict before the rename so the final name is never readable more
    // widely. Failure here is fatal: an unrestricted blob is not acceptable.
    applyAcl(alloc, tmp) catch |err| {
        cwd.deleteFile(io, tmp) catch {};
        return err;
    };
    cwd.rename(tmp, cwd, path, io) catch |err| {
        cwd.deleteFile(io, tmp) catch {};
        return err;
    };
}

// SDDL helpers (advapi32), same calls as quarantine.zig.
const acl = if (builtin.target.os.tag == .windows) struct {
    extern "advapi32" fn ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl: [*:0]const u16, revision: u32, psd: *?*anyopaque, size: ?*usize) callconv(WINAPI) i32;
    extern "advapi32" fn GetSecurityDescriptorDacl(sd: *anyopaque, present: *i32, dacl: *?*anyopaque, defaulted: *i32) callconv(WINAPI) i32;
    extern "advapi32" fn SetNamedSecurityInfoW(name: [*:0]u16, object_type: u32, info: u32, owner: ?*anyopaque, group: ?*anyopaque, dacl: ?*anyopaque, sacl: ?*anyopaque) callconv(WINAPI) u32;
} else struct {};

const SE_FILE_OBJECT: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x4;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x80000000;

fn applyAcl(alloc: std.mem.Allocator, path: []const u8) !void {
    if (builtin.target.os.tag != .windows) return;
    const wpath = try std.unicode.utf8ToUtf16LeAllocZ(alloc, path);
    defer alloc.free(wpath);
    var psd: ?*anyopaque = null;
    if (acl.ConvertStringSecurityDescriptorToSecurityDescriptorW(W(file_acl), 1, &psd, null) == 0) return error.SddlParseFailed;
    defer _ = win.LocalFree(psd);
    var present: i32 = 0;
    var dacl: ?*anyopaque = null;
    var defaulted: i32 = 0;
    if (acl.GetSecurityDescriptorDacl(psd.?, &present, &dacl, &defaulted) == 0) return error.SddlParseFailed;
    const rc = acl.SetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, null, null, dacl, null);
    if (rc != 0) {
        last_error = rc;
        return error.SetAclFailed;
    }
}

// ---------------------------------------------------------------------------
// Tests

test "Windows crypto constants match windows-rs" {
    try std.testing.expectEqual(@as(u32, 4), CRYPTPROTECT_LOCAL_MACHINE);
    try std.testing.expectEqual(@as(u32, 1), CRYPTPROTECT_UI_FORBIDDEN);
    try std.testing.expectEqual(@as(u32, 32), NCRYPT_MACHINE_KEY_FLAG);
    try std.testing.expectEqual(@as(u32, 64), NCRYPT_SILENT_FLAG);
    try std.testing.expectEqual(@as(u32, 128), NCRYPT_OVERWRITE_KEY_FLAG);
    try std.testing.expectEqual(@as(u32, 4), NCRYPT_PAD_OAEP_FLAG);
    try std.testing.expectEqual(@as(u32, 0x80090016), NTE_BAD_KEYSET);
    try std.testing.expectEqual(@as(u32, 0x8009000F), NTE_EXISTS);
    try std.testing.expectEqualStrings("Microsoft Platform Crypto Provider", ms_platform_provider);
    try std.testing.expectEqual(@as(usize, 190), oaep_max_plain);
    try std.testing.expectEqual(@as(u32, 4), DACL_SECURITY_INFORMATION);
    try std.testing.expectEqual(@as(u32, 0x80000000), PROTECTED_DACL_SECURITY_INFORMATION);
    try std.testing.expectEqual(@as(u32, 1), SE_FILE_OBJECT);
    // DATA_BLOB is { DWORD cbData; BYTE *pbData; }.
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(DATA_BLOB, "cbData"));
    try std.testing.expectEqual(@as(usize, @sizeOf(usize)), @offsetOf(DATA_BLOB, "pbData"));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(BCRYPT_OAEP_PADDING_INFO, "pszAlgId"));
}

test "blob framing round-trips and refuses junk" {
    const a = std.testing.allocator;
    const f = try encodeFile(a, .tpm, "body");
    defer a.free(f);
    const d = try decodeFile(f);
    try std.testing.expectEqual(Wrap.tpm, d.wrap);
    try std.testing.expectEqualStrings("body", d.body);
    try std.testing.expectError(error.CorruptBlob, decodeFile("TWN"));
    try std.testing.expectError(error.CorruptBlob, decodeFile("XXXX\x01\x00body"));
    try std.testing.expectError(error.CorruptBlob, decodeFile("TWNK\x02\x00body"));
    try std.testing.expectError(error.CorruptBlob, decodeFile("TWNK\x01\x07body"));
}

test "DPAPI round trip and TPM wrap (Windows only)" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const a = std.testing.allocator;
    const secret = "tawny test secret \x00\x01\xff";
    const blob = try protect(a, secret);
    defer a.free(blob);
    try std.testing.expect(std.mem.indexOf(u8, blob, "tawny test secret") == null);
    const back = try unprotect(a, blob);
    defer a.free(back);
    try std.testing.expectEqualSlices(u8, secret, back);
    // Wrong entropy is refused: flip the blob instead (same effect, no API).
    var bad = try a.dupe(u8, blob);
    defer a.free(bad);
    bad[bad.len - 1] ^= 0xff;
    try std.testing.expectError(error.DpapiFailed, unprotect(a, bad));

    // The TPM is optional; the hosted runner usually has none.
    var tpm = Tpm.open() catch return;
    defer tpm.close();
    const big: [400]u8 = @splat(0x5a);
    const w = try tpm.wrap(a, &big);
    defer a.free(w);
    const u = try tpm.unwrap(a, w);
    defer a.free(u);
    try std.testing.expectEqualSlices(u8, &big, u);
}
