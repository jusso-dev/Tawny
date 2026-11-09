//! `--keystore-selftest <dir>`: CI plumbing for #58, like `--eventlog-dump`.
//! Uses the platform keystore with its files under `<dir>` (never the real
//! state directory) and proves, on the machine it runs on:
//!
//! 1. a secret round-trips (put, read back, delete);
//! 2. a plaintext `<dir>\state.toml.devicekey` is migrated into the keystore,
//!    read back, and the plaintext file is gone afterwards;
//! 3. on Windows, the `.dpapi` file holds no plaintext copy of the seed.
//!
//! Prints `KEYSTORE\t<key>=<value>` lines and returns 0 when every check
//! passes. The secrets are random bytes made for the run.

const std = @import("std");
const builtin = @import("builtin");
const keystore = @import("keystore.zig");
const iox = @import("io_compat.zig");

pub fn isDebugCommand(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--keystore-selftest");
}

pub fn run(alloc: std.mem.Allocator, args: []const []const u8) u8 {
    if (args.len != 2) {
        std.debug.print("usage: tawny-agent --keystore-selftest <empty-dir>\n", .{});
        return 2;
    }
    return selftest(alloc, args[1]) catch |err| {
        std.debug.print("KEYSTORE\tresult=failed\terror={s}\tos_status={d}\n", .{ @errorName(err), keystore.lastOsStatus() });
        return 1;
    };
}

fn selftest(alloc: std.mem.Allocator, dir: []const u8) !u8 {
    const io = iox.current();
    try std.Io.Dir.cwd().createDirPath(io, dir);
    const store = keystore.platformDefaultIn(alloc, dir);
    std.debug.print("KEYSTORE\tbackend={s}\n", .{@tagName(store.backend)});
    if (!store.isOs()) {
        std.debug.print("KEYSTORE\tresult=skipped\treason=no OS keystore on this platform\n", .{});
        return 0;
    }
    // macOS would touch a real keychain service name; this command is for
    // the Windows runner.
    if (builtin.target.os.tag != .windows) {
        std.debug.print("KEYSTORE\tresult=skipped\treason=windows only\n", .{});
        return 0;
    }

    // 1. Round trip.
    var jwt_bytes: [24]u8 = undefined;
    io.random(&jwt_bytes);
    var jwt_hex: [48]u8 = undefined;
    _ = try std.fmt.bufPrint(&jwt_hex, "{x}", .{jwt_bytes});
    try store.putVerified(alloc, .agent_jwt, &jwt_hex);
    const back = (try store.get(alloc, .agent_jwt)) orelse return error.RoundTripMissing;
    defer alloc.free(back);
    if (!std.mem.eql(u8, back, &jwt_hex)) return error.RoundTripMismatch;
    try store.delete(.agent_jwt);
    if (try store.get(alloc, .agent_jwt)) |left| {
        alloc.free(left);
        return error.DeleteLeftSecret;
    }
    std.debug.print("KEYSTORE\tround_trip=ok\n", .{});

    // 2. Plaintext seed migration.
    const state_path = try std.fs.path.join(alloc, &.{ dir, "state.toml" });
    defer alloc.free(state_path);
    const seed_path = try keystore.deviceSeedPath(alloc, state_path);
    defer alloc.free(seed_path);
    var seed: keystore.Seed = undefined;
    io.random(&seed);
    try keystore.writeSecretFile(seed_path, &seed);
    if (!try keystore.migrateDeviceSeed(alloc, store, seed_path)) return error.NotMigrated;
    const still_there = blk: {
        const f = std.Io.Dir.cwd().openFile(io, seed_path, .{}) catch break :blk false;
        f.close(io);
        break :blk true;
    };
    if (still_there) return error.PlaintextRemains;
    const loaded = (try keystore.loadDeviceSeed(alloc, store, seed_path)) orelse return error.SeedMissing;
    if (!std.mem.eql(u8, &loaded, &seed)) return error.SeedMismatch;
    std.debug.print("KEYSTORE\tmigration=ok\tplaintext_removed=true\n", .{});

    // 3. No plaintext in the protected file.
    const blob_path = try std.fmt.allocPrint(alloc, "{s}\\device-seed.dpapi", .{dir});
    defer alloc.free(blob_path);
    const blob = try std.Io.Dir.cwd().readFileAlloc(io, blob_path, alloc, .limited(64 * 1024));
    defer alloc.free(blob);
    if (std.mem.indexOf(u8, blob, &seed) != null) return error.PlaintextInBlob;
    std.debug.print("KEYSTORE\tblob_bytes={d}\tkey_protection={s}\n", .{ blob.len, store.protection() });

    try store.delete(.device_seed);
    std.debug.print("KEYSTORE\tresult=ok\n", .{});
    return 0;
}
