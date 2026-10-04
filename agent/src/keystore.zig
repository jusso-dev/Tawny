//! Secret storage for the agent JWT and the Ed25519 device seed.
//!
//! Backends:
//! - macOS: Security.framework generic passwords, service
//!   `dev.jusso.tawny-agent`, account = secret name. Root (LaunchDaemon) uses
//!   the System keychain; a per-user LaunchAgent uses the login keychain.
//! - Everything else (and macOS with `TAWNY_KEYSTORE=file`): `file`, meaning
//!   callers keep the legacy plaintext files (state.toml / `.devicekey`).
//!   Windows DPAPI and Linux keyring/TPM are later phases.
//!
//! File precedence: when a plaintext copy exists it is authoritative, because
//! it is only ever written as a fallback after a keystore write failed, or by
//! `--export-credentials` before an upgrade. Migration moves it into the
//! keystore, verifies the read-back, and only then removes the plaintext.

const std = @import("std");
const builtin = @import("builtin");
const env = @import("env.zig");
const iox = @import("io_compat.zig");
const keychain = if (builtin.target.os.tag == .macos) @import("platform/macos/keychain.zig") else struct {};

pub const default_service = "dev.jusso.tawny-agent";
pub const seed_len = std.crypto.sign.Ed25519.KeyPair.seed_length;
pub const Seed = [seed_len]u8;

pub const Secret = enum {
    agent_jwt,
    device_seed,

    pub fn account(self: Secret) []const u8 {
        return switch (self) {
            .agent_jwt => "agent-jwt",
            .device_seed => "device-seed",
        };
    }
};

pub const Error = error{
    /// The keystore is locked or would need user interaction.
    InteractionNotAllowed,
    /// No OS keystore (file backend), or it cannot be reached or written.
    KeystoreUnavailable,
    KeystoreFailure,
    /// Read-back after a write returned different bytes.
    KeystoreVerifyFailed,
    OutOfMemory,
};

pub const Backend = enum {
    /// Plaintext files next to state.toml (legacy behaviour).
    file,
    /// /Library/Keychains/System.keychain.
    macos_system_keychain,
    /// The calling user's default (login) keychain.
    macos_user_keychain,
    /// In-memory store for tests.
    test_vault,
};

pub const Store = struct {
    backend: Backend = .file,
    service: []const u8 = default_service,
    vault: ?*TestVault = null,

    /// True when secrets go to an OS keystore rather than plaintext files.
    pub fn isOs(self: Store) bool {
        return self.backend != .file;
    }

    pub fn describe(self: Store) []const u8 {
        return switch (self.backend) {
            .file => "plaintext state files",
            .macos_system_keychain => "macOS System keychain",
            .macos_user_keychain => "macOS login keychain",
            .test_vault => "test vault",
        };
    }

    /// Caller owns the returned bytes. Null when no such secret exists.
    pub fn get(self: Store, alloc: std.mem.Allocator, secret: Secret) Error!?[]u8 {
        return switch (self.backend) {
            .file => error.KeystoreUnavailable,
            .test_vault => self.vault.?.get(alloc, secret),
            .macos_system_keychain, .macos_user_keychain => {
                if (comptime builtin.target.os.tag != .macos) return error.KeystoreUnavailable;
                return keychain.get(alloc, self.location(), self.service, secret.account()) catch |err| mapKeychainError(err);
            },
        };
    }

    pub fn put(self: Store, secret: Secret, value: []const u8) Error!void {
        return switch (self.backend) {
            .file => error.KeystoreUnavailable,
            .test_vault => self.vault.?.put(secret, value),
            .macos_system_keychain, .macos_user_keychain => {
                if (comptime builtin.target.os.tag != .macos) return error.KeystoreUnavailable;
                return keychain.put(self.location(), self.service, secret.account(), value) catch |err| mapKeychainError(err);
            },
        };
    }

    /// Remove the secret; a missing secret is not an error.
    pub fn delete(self: Store, secret: Secret) Error!void {
        return switch (self.backend) {
            .file => error.KeystoreUnavailable,
            .test_vault => self.vault.?.delete(secret),
            .macos_system_keychain, .macos_user_keychain => {
                if (comptime builtin.target.os.tag != .macos) return error.KeystoreUnavailable;
                return keychain.delete(self.location(), self.service, secret.account()) catch |err| mapKeychainError(err);
            },
        };
    }

    /// Write, then read back and compare. Only after this succeeds may a
    /// plaintext copy be removed.
    pub fn putVerified(self: Store, alloc: std.mem.Allocator, secret: Secret, value: []const u8) Error!void {
        try self.put(secret, value);
        const back = (try self.get(alloc, secret)) orelse return error.KeystoreVerifyFailed;
        defer {
            std.crypto.secureZero(u8, back);
            alloc.free(back);
        }
        if (!std.mem.eql(u8, back, value)) return error.KeystoreVerifyFailed;
    }

    fn location(self: Store) keychain.Location {
        return if (self.backend == .macos_system_keychain) .system else .user;
    }
};

fn mapKeychainError(err: anyerror) Error {
    return switch (err) {
        error.InteractionNotAllowed => error.InteractionNotAllowed,
        error.KeychainUnavailable => error.KeystoreUnavailable,
        error.OutOfMemory => error.OutOfMemory,
        else => error.KeystoreFailure,
    };
}

/// OSStatus of the last failing keychain call (0 elsewhere), for log lines.
pub fn lastOsStatus() i32 {
    if (comptime builtin.target.os.tag != .macos) return 0;
    return keychain.last_status;
}

/// Store for this process. macOS: System keychain when running as root
/// (LaunchDaemon), login keychain otherwise (LaunchAgent). `TAWNY_KEYSTORE=file`
/// forces the plaintext-file backend (containers, debugging).
pub fn platformDefault(alloc: std.mem.Allocator) Store {
    if (env.getEnvVarOwned(alloc, "TAWNY_KEYSTORE")) |value| {
        defer alloc.free(value);
        if (std.ascii.eqlIgnoreCase(value, "file")) return .{ .backend = .file };
    } else |_| {}
    if (comptime builtin.target.os.tag == .macos) {
        return .{ .backend = if (std.c.geteuid() == 0) .macos_system_keychain else .macos_user_keychain };
    }
    return .{ .backend = .file };
}

/// In-memory keystore used by tests to exercise migration and fallback.
pub const TestVault = struct {
    alloc: std.mem.Allocator,
    jwt: ?[]u8 = null,
    seed: ?[]u8 = null,
    fail_puts: bool = false,
    /// Return different bytes on read-back (simulates an unreadable item).
    corrupt_reads: bool = false,

    pub fn deinit(self: *TestVault) void {
        if (self.jwt) |v| self.alloc.free(v);
        if (self.seed) |v| self.alloc.free(v);
    }

    fn slot(self: *TestVault, secret: Secret) *?[]u8 {
        return switch (secret) {
            .agent_jwt => &self.jwt,
            .device_seed => &self.seed,
        };
    }

    fn get(self: *TestVault, alloc: std.mem.Allocator, secret: Secret) Error!?[]u8 {
        const value = self.slot(secret).* orelse return null;
        const out = try alloc.dupe(u8, value);
        if (self.corrupt_reads and out.len > 0) out[0] ^= 0xff;
        return out;
    }

    fn put(self: *TestVault, secret: Secret, value: []const u8) Error!void {
        if (self.fail_puts) return error.InteractionNotAllowed;
        const s = self.slot(secret);
        const copy = try self.alloc.dupe(u8, value);
        if (s.*) |old| self.alloc.free(old);
        s.* = copy;
    }

    fn delete(self: *TestVault, secret: Secret) Error!void {
        const s = self.slot(secret);
        if (s.*) |old| self.alloc.free(old);
        s.* = null;
    }
};

// ---------------------------------------------------------------------------
// Device seed

/// `<state>.devicekey`, the legacy/fallback plaintext seed file.
pub fn deviceSeedPath(alloc: std.mem.Allocator, state_path: []const u8) ![]u8 {
    return alloc.print("{s}.devicekey", .{state_path});
}

/// Load the seed: plaintext file first (authoritative when present), then the
/// keystore. Null when neither has one.
pub fn loadDeviceSeed(alloc: std.mem.Allocator, store: Store, seed_path: []const u8) !?Seed {
    if (try readSeedFile(seed_path)) |seed| return seed;
    if (!store.isOs()) return null;
    const bytes = (try store.get(alloc, .device_seed)) orelse return null;
    defer {
        std.crypto.secureZero(u8, bytes);
        alloc.free(bytes);
    }
    if (bytes.len != seed_len) return error.CorruptDeviceKey;
    return bytes[0..seed_len].*;
}

/// Generate and persist a fresh seed: keystore when available (verified),
/// otherwise the 0600 plaintext file.
pub fn createDeviceSeed(alloc: std.mem.Allocator, store: Store, seed_path: []const u8) !Seed {
    var seed: Seed = undefined;
    try std.Io.randomSecure(iox.current(), &seed);
    if (store.isOs()) {
        if (store.putVerified(alloc, .device_seed, &seed)) {
            return seed;
        } else |err| {
            std.log.warn(
                "device key: {s} write failed ({s}, status {d}); storing seed in plaintext {s}",
                .{ store.describe(), @errorName(err), lastOsStatus(), seed_path },
            );
        }
    }
    try writeSecretFile(seed_path, &seed);
    return seed;
}

/// Move a plaintext seed file into the keystore. Returns true when the file
/// was migrated and removed. On any failure the file is left untouched.
pub fn migrateDeviceSeed(alloc: std.mem.Allocator, store: Store, seed_path: []const u8) !bool {
    if (!store.isOs()) return false;
    var seed = (try readSeedFile(seed_path)) orelse return false;
    defer std.crypto.secureZero(u8, &seed);
    try store.putVerified(alloc, .device_seed, &seed);
    try scrubAndDelete(seed_path);
    return true;
}

/// Copy the keystore seed back to the plaintext file (verified), then remove
/// it from the keystore. Used before an upgrade replaces the binary, because a
/// new ad-hoc signed build cannot read items the old build created.
pub fn exportDeviceSeed(alloc: std.mem.Allocator, store: Store, seed_path: []const u8) !bool {
    if (!store.isOs()) return false;
    if (try readSeedFile(seed_path)) |_| {
        // The plaintext copy is already authoritative; any keystore item is
        // stale (possibly unreadable by this build), so just drop it.
        store.delete(.device_seed) catch {};
        return true;
    }
    const bytes = (try store.get(alloc, .device_seed)) orelse return false;
    defer {
        std.crypto.secureZero(u8, bytes);
        alloc.free(bytes);
    }
    if (bytes.len != seed_len) return error.CorruptDeviceKey;
    try writeSecretFile(seed_path, bytes);
    const back = (try readSeedFile(seed_path)) orelse return error.ExportVerifyFailed;
    if (!std.mem.eql(u8, &back, bytes)) return error.ExportVerifyFailed;
    try store.delete(.device_seed);
    return true;
}

fn readSeedFile(path: []const u8) !?Seed {
    const io = iox.current();
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io);
    var seed: Seed = undefined;
    const n = try file.readPositionalAll(io, &seed, 0);
    if (n != seed.len) return error.CorruptDeviceKey;
    return seed;
}

/// Atomically write a secret file with owner-only permissions (tmp + rename).
pub fn writeSecretFile(path: []const u8, bytes: []const u8) !void {
    const io = iox.current();
    const cwd = std.Io.Dir.cwd();
    var tmp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{path}) catch return error.NameTooLong;
    {
        var file = try cwd.createFile(io, tmp_path, .{
            .truncate = true,
            .permissions = if (builtin.target.os.tag == .windows) .default_file else @fromBackingInt(@intCast(0o600)),
        });
        defer file.close(io);
        try file.writePositionalAll(io, bytes, 0);
        try file.sync(io);
    }
    cwd.rename(tmp_path, cwd, path, io) catch |err| {
        cwd.deleteFile(io, tmp_path) catch {};
        return err;
    };
}

/// Best-effort scrub: overwrite with zeros, fsync, then unlink. On APFS and
/// other copy-on-write or journaled filesystems the old blocks may survive;
/// this only avoids leaving the secret trivially recoverable.
pub fn scrubAndDelete(path: []const u8) !void {
    const io = iox.current();
    const cwd = std.Io.Dir.cwd();
    scrub: {
        const file = cwd.openFile(io, path, .{ .mode = .read_write }) catch |err| switch (err) {
            error.FileNotFound => return,
            else => break :scrub,
        };
        defer file.close(io);
        const stat = file.stat(io) catch break :scrub;
        const zeros: [512]u8 = @splat(0);
        var offset: u64 = 0;
        while (offset < stat.size) {
            const n: usize = @intCast(@min(zeros.len, stat.size - offset));
            file.writePositionalAll(io, zeros[0..n], offset) catch break :scrub;
            offset += n;
        }
        file.sync(io) catch {};
    }
    cwd.deleteFile(io, path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

// ---------------------------------------------------------------------------
// Tests

fn testPath(alloc: std.mem.Allocator, tmp: *const std.testing.TmpDir, name: []const u8) ![]u8 {
    return std.fs.path.join(alloc, &.{ ".zig-cache", "tmp", &tmp.sub_path, name });
}

test "file backend reports no OS keystore" {
    const store: Store = .{};
    try std.testing.expect(!store.isOs());
    try std.testing.expectError(error.KeystoreUnavailable, store.put(.agent_jwt, "x"));
    try std.testing.expectError(error.KeystoreUnavailable, store.get(std.testing.allocator, .agent_jwt));
}

test "device seed migrates from file into keystore and file is removed" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const seed_path = try testPath(alloc, &tmp, "state.toml.devicekey");
    defer alloc.free(seed_path);

    var vault = TestVault{ .alloc = alloc };
    defer vault.deinit();
    const store = Store{ .backend = .test_vault, .vault = &vault };

    const seed: Seed = @splat(7);
    try writeSecretFile(seed_path, &seed);
    try std.testing.expect(try migrateDeviceSeed(alloc, store, seed_path));
    try std.testing.expect((try readSeedFile(seed_path)) == null);
    try std.testing.expectEqualSlices(u8, &seed, vault.seed.?);
    try std.testing.expectEqualSlices(u8, &seed, &(try loadDeviceSeed(alloc, store, seed_path)).?);

    // Export brings it back to a file and empties the keystore.
    try std.testing.expect(try exportDeviceSeed(alloc, store, seed_path));
    try std.testing.expect(vault.seed == null);
    try std.testing.expectEqualSlices(u8, &seed, &(try readSeedFile(seed_path)).?);
}

test "device seed migration keeps the file when the keystore fails" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const seed_path = try testPath(alloc, &tmp, "state.toml.devicekey");
    defer alloc.free(seed_path);

    var vault = TestVault{ .alloc = alloc, .fail_puts = true };
    defer vault.deinit();
    const store = Store{ .backend = .test_vault, .vault = &vault };

    const seed: Seed = @splat(9);
    try writeSecretFile(seed_path, &seed);
    try std.testing.expectError(error.InteractionNotAllowed, migrateDeviceSeed(alloc, store, seed_path));
    try std.testing.expectEqualSlices(u8, &seed, &(try readSeedFile(seed_path)).?);

    // A bad read-back is caught too.
    vault.fail_puts = false;
    vault.corrupt_reads = true;
    try std.testing.expectError(error.KeystoreVerifyFailed, migrateDeviceSeed(alloc, store, seed_path));
    try std.testing.expectEqualSlices(u8, &seed, &(try readSeedFile(seed_path)).?);
}

test "createDeviceSeed falls back to a 0600 file when the keystore fails" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const seed_path = try testPath(alloc, &tmp, "state.toml.devicekey");
    defer alloc.free(seed_path);

    var vault = TestVault{ .alloc = alloc, .fail_puts = true };
    defer vault.deinit();
    const store = Store{ .backend = .test_vault, .vault = &vault };

    const seed = try createDeviceSeed(alloc, store, seed_path);
    try std.testing.expectEqualSlices(u8, &seed, &(try loadDeviceSeed(alloc, store, seed_path)).?);
    if (builtin.target.os.tag != .windows) {
        const io = iox.current();
        const file = try std.Io.Dir.cwd().openFile(io, seed_path, .{});
        defer file.close(io);
        const stat = try file.stat(io);
        try std.testing.expectEqual(@as(u32, 0o600), @as(u32, @intCast(@backingInt(stat.permissions) & 0o777)));
    }

    // With a working keystore no file is written.
    vault.fail_puts = false;
    try scrubAndDelete(seed_path);
    const seed2 = try createDeviceSeed(alloc, store, seed_path);
    try std.testing.expect((try readSeedFile(seed_path)) == null);
    try std.testing.expectEqualSlices(u8, &seed2, vault.seed.?);
}

/// Unique service name so tests never touch the agent's real items.
fn testService(buf: []u8) ![]const u8 {
    var rnd: [8]u8 = undefined;
    std.Io.random(iox.current(), &rnd);
    return std.fmt.bufPrint(buf, "dev.jusso.tawny-agent.test.{x}", .{rnd});
}

fn skipIfKeychainUnusable(err: anyerror) anyerror {
    return switch (err) {
        // Locked login keychain, no default keychain (headless CI), etc.
        error.InteractionNotAllowed, error.KeystoreUnavailable => error.SkipZigTest,
        else => err,
    };
}

test "macOS login keychain put/get/delete round trip" {
    if (builtin.target.os.tag != .macos) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    var buf: [64]u8 = undefined;
    // Login keychain only; tests never use the System keychain.
    const store = Store{ .backend = .macos_user_keychain, .service = try testService(&buf) };
    defer store.delete(.agent_jwt) catch {};

    store.putVerified(alloc, .agent_jwt, "jwt-one") catch |err| return skipIfKeychainUnusable(err);
    try store.putVerified(alloc, .agent_jwt, "jwt-two-longer");
    const got = (try store.get(alloc, .agent_jwt)).?;
    defer alloc.free(got);
    try std.testing.expectEqualStrings("jwt-two-longer", got);

    // Binary values survive unchanged.
    var seed: Seed = @splat(0);
    seed[0..4].* = .{ 0, 1, 2, 0xff };
    defer store.delete(.device_seed) catch {};
    try store.putVerified(alloc, .device_seed, &seed);

    try store.delete(.agent_jwt);
    try std.testing.expect((try store.get(alloc, .agent_jwt)) == null);
    try store.delete(.agent_jwt); // idempotent
    try store.delete(.device_seed);
}
