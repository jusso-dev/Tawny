//! Signed self-update in rings (#58, target-edr §10 "Updates").
//!
//! Flow: check the release endpoint on a timer, verify the manifest's
//! minisign signature with the compiled-in release key (update_key.zig),
//! refuse a version at or below the current one unless the manifest is a
//! signed `rollback`, download, check size and SHA-256, stage beside the
//! binary, swap (rename the running exe to `.previous`, which Windows
//! allows), then exit non-zero so the service manager starts the new binary
//! (SCM failure actions, systemd `Restart=on-failure`, launchd `KeepAlive`).
//! The new binary runs a health window: the first successful heartbeat
//! commits. Three starts without one, or the window running out, roll back
//! to `.previous` and restart again.
//!
//! While update_key.zig still holds the placeholder key, `Updater.check`
//! does nothing and reports `disabled_no_release_key`.
//!
//! Manifest (JSON, signed as a file with minisign):
//!   {"version":"0.2.0","platform":"windows-x64","sha256":"<hex>","size":123,
//!    "min_from_version":"0.1.0","ring":"canary","rollback":false}
//!
//! Rings: canary, internal, 10, 50, 100. An agent's ring is its server-side
//! `update_ring` override, else from its bucket: sha256(agent_id) first four
//! bytes big-endian mod 100; below 10 is ring 10, below 50 is ring 50, the
//! rest ring 100. A release open to ring R is offered to agents whose ring is
//! R or earlier. The server applies the same rule (routes/agent_releases.zig).

const std = @import("std");
const builtin = @import("builtin");
const minisign = @import("minisign.zig");
const update_key = @import("update_key.zig");
const iox = @import("io_compat.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

// ---------------------------------------------------------------------------
// Rings

pub const Ring = enum {
    canary,
    internal,
    @"10",
    @"50",
    @"100",

    pub fn rank(self: Ring) u8 {
        return @backingInt(self);
    }

    pub fn parse(text: []const u8) ?Ring {
        return std.meta.stringToEnum(Ring, text);
    }
};

/// Stable bucket 0..99 for an agent id (canonical lower-case UUID text).
pub fn bucket(agent_id: []const u8) u8 {
    var lower: [64]u8 = undefined;
    const n = @min(agent_id.len, lower.len);
    for (agent_id[0..n], 0..) |c, i| lower[i] = std.ascii.toLower(c);
    var d: [32]u8 = undefined;
    Sha256.hash(lower[0..n], &d, .{});
    return @intCast(std.mem.readInt(u32, d[0..4], .big) % 100);
}

pub fn ringForBucket(b: u8) Ring {
    if (b < 10) return .@"10";
    if (b < 50) return .@"50";
    return .@"100";
}

/// A release open to `release_ring` is offered to `agent_ring`.
pub fn ringAllows(release_ring: Ring, agent_ring: Ring) bool {
    return agent_ring.rank() <= release_ring.rank();
}

// ---------------------------------------------------------------------------
// Manifest

pub const Manifest = struct {
    version: []const u8,
    platform: []const u8,
    sha256: []const u8,
    size: u64,
    min_from_version: []const u8 = "0.0.0",
    ring: []const u8 = "100",
    rollback: bool = false,
};

pub const Decision = enum {
    update,
    up_to_date,
    downgrade_refused,
    wrong_platform,
    below_min_from,
    refused_version,
    not_in_ring,
    bad_manifest,
};

pub const Context = struct {
    current_version: []const u8,
    platform: []const u8,
    agent_ring: Ring,
    /// A version this agent already rolled back from; never retried.
    refused_version: ?[]const u8 = null,
};

/// Whether a verified manifest should be installed. Pure.
pub fn decide(m: Manifest, ctx: Context) Decision {
    if (!std.mem.eql(u8, m.platform, ctx.platform)) return .wrong_platform;
    if (m.sha256.len != 64 or m.size == 0 or m.size > max_binary_bytes) return .bad_manifest;
    const ring = Ring.parse(m.ring) orelse return .bad_manifest;
    if (!ringAllows(ring, ctx.agent_ring)) return .not_in_ring;
    const want = std.SemanticVersion.parse(m.version) catch return .bad_manifest;
    const have = std.SemanticVersion.parse(ctx.current_version) catch return .bad_manifest;
    const min_from = std.SemanticVersion.parse(m.min_from_version) catch return .bad_manifest;
    if (ctx.refused_version) |r| if (std.mem.eql(u8, r, m.version)) return .refused_version;
    const order = want.order(have);
    if (m.rollback) {
        // A signed rollback may go down, never sideways or up.
        return if (order == .lt) .update else .up_to_date;
    }
    if (order != .gt) return if (order == .eq) .up_to_date else .downgrade_refused;
    if (have.order(min_from) == .lt) return .below_min_from;
    return .update;
}

pub const max_binary_bytes: u64 = 256 * 1024 * 1024;

pub const VerifyError = error{
    NoReleaseKey,
    BadSignature,
    BadManifest,
    HashMismatch,
    SizeMismatch,
} || std.mem.Allocator.Error;

/// Verify the manifest signature and parse it. `key` null means the
/// placeholder is still compiled in. The parsed value borrows `manifest`.
pub fn verifyManifest(alloc: std.mem.Allocator, key: ?minisign.PublicKey, manifest: []const u8, signature: []const u8) VerifyError!std.json.Parsed(Manifest) {
    const pk = key orelse return error.NoReleaseKey;
    const sig = minisign.parseSignature(signature) catch return error.BadSignature;
    _ = minisign.verify(pk, sig, manifest) catch return error.BadSignature;
    return std.json.parseFromSlice(Manifest, alloc, manifest, .{ .ignore_unknown_fields = true }) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.BadManifest,
    };
}

/// Check downloaded bytes against the manifest.
pub fn verifyPayload(m: Manifest, bytes: []const u8) VerifyError!void {
    if (bytes.len != m.size) return error.SizeMismatch;
    var d: [32]u8 = undefined;
    Sha256.hash(bytes, &d, .{});
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{d}) catch unreachable;
    if (!std.ascii.eqlIgnoreCase(&hex, m.sha256)) return error.HashMismatch;
}

// ---------------------------------------------------------------------------
// Persisted state (`<state>.update.json`)

pub const State = enum {
    disabled_no_release_key,
    idle,
    checking,
    downloading,
    staged,
    restarting,
    health_check,
    committed,
    rolled_back,
    refused,
    failed,
};

pub const Persisted = struct {
    state: State = .idle,
    version: []const u8 = "",
    previous_version: []const u8 = "",
    sha256: []const u8 = "",
    /// Unix seconds by which the new binary must have a good heartbeat.
    deadline: i64 = 0,
    /// Starts of the new binary inside the health window.
    attempts: u32 = 0,
    refused_version: []const u8 = "",
    reason: []const u8 = "",
};

pub const health_window_seconds: i64 = 300;
pub const max_health_attempts: u32 = 3;

pub const StartAction = enum { none, health_check, rollback };

/// What a fresh start must do given the persisted state. Pure; the caller
/// bumps `attempts` before acting on `.health_check`.
pub fn onStart(p: Persisted, running_version: []const u8, now: i64) StartAction {
    if (p.state != .restarting and p.state != .health_check) return .none;
    // Still the old binary (the swap did not take): nothing to check.
    if (!std.mem.eql(u8, running_version, p.version)) return .none;
    if (p.attempts + 1 >= max_health_attempts) return .rollback;
    if (now > p.deadline) return .rollback;
    return .health_check;
}

/// Health window tick: commit on a good heartbeat, roll back after the
/// deadline. Pure.
pub fn onTick(p: Persisted, heartbeat_ok: bool, now: i64) StartAction {
    if (p.state != .health_check) return .none;
    if (heartbeat_ok) return .none; // caller commits
    if (now > p.deadline) return .rollback;
    return .health_check;
}

pub fn statePath(alloc: std.mem.Allocator, state_path: []const u8) ![]u8 {
    return alloc.print("{s}.update.json", .{state_path});
}

/// Read the persisted state. Missing or unreadable is `idle`. The strings
/// live in the returned arena.
pub fn load(alloc: std.mem.Allocator, state_path: []const u8) !std.json.Parsed(Persisted) {
    const path = try statePath(alloc, state_path);
    defer alloc.free(path);
    const text = std.Io.Dir.cwd().readFileAlloc(iox.current(), path, alloc, .limited(16 * 1024)) catch
        return std.json.parseFromSlice(Persisted, alloc, "{}", .{});
    defer alloc.free(text);
    return std.json.parseFromSlice(Persisted, alloc, text, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch
        std.json.parseFromSlice(Persisted, alloc, "{}", .{});
}

pub fn save(alloc: std.mem.Allocator, state_path: []const u8, p: Persisted) !void {
    const path = try statePath(alloc, state_path);
    defer alloc.free(path);
    const body = try std.json.Stringify.valueAlloc(alloc, p, .{});
    defer alloc.free(body);
    const tmp = try alloc.print("{s}.tmp", .{path});
    defer alloc.free(tmp);
    const io = iox.current();
    const cwd = std.Io.Dir.cwd();
    try cwd.writeFile(io, .{ .sub_path = tmp, .data = body });
    try cwd.rename(tmp, cwd, path, io);
}

// ---------------------------------------------------------------------------
// Files: stage, swap, roll back

pub const Paths = struct {
    exe: []const u8,
    staged: []u8,
    previous: []u8,
    failed: []u8,

    pub fn init(alloc: std.mem.Allocator, exe: []const u8) !Paths {
        const dir = std.fs.path.dirname(exe) orelse ".";
        const win = std.mem.endsWith(u8, exe, ".exe");
        const sep = if (builtin.target.os.tag == .windows) "\\" else "/";
        const staged = try std.fmt.allocPrint(alloc, "{s}{s}tawny-agent.staged{s}", .{ dir, sep, if (win) ".exe" else "" });
        errdefer alloc.free(staged);
        const previous = try std.fmt.allocPrint(alloc, "{s}{s}tawny-agent.previous{s}", .{ dir, sep, if (win) ".exe" else "" });
        errdefer alloc.free(previous);
        const failed = try std.fmt.allocPrint(alloc, "{s}{s}tawny-agent.failed{s}", .{ dir, sep, if (win) ".exe" else "" });
        return .{ .exe = exe, .staged = staged, .previous = previous, .failed = failed };
    }

    pub fn deinit(self: Paths, alloc: std.mem.Allocator) void {
        alloc.free(self.staged);
        alloc.free(self.previous);
        alloc.free(self.failed);
    }
};

/// Write the verified bytes next to the binary, executable, synced.
pub fn stage(paths: Paths, bytes: []const u8) !void {
    const io = iox.current();
    var f = try std.Io.Dir.cwd().createFile(io, paths.staged, .{
        .truncate = true,
        .permissions = if (builtin.target.os.tag == .windows) .default_file else @fromBackingInt(@intCast(0o755)),
    });
    defer f.close(io);
    try f.writePositionalAll(io, bytes, 0);
    try f.sync(io);
}

/// exe -> previous, staged -> exe. On Windows the running image can be
/// renamed but not overwritten, hence the two renames. If the second rename
/// fails the first is undone.
pub fn swap(paths: Paths) !void {
    const io = iox.current();
    const cwd = std.Io.Dir.cwd();
    cwd.deleteFile(io, paths.previous) catch {};
    try cwd.rename(paths.exe, cwd, paths.previous, io);
    cwd.rename(paths.staged, cwd, paths.exe, io) catch |err| {
        cwd.rename(paths.previous, cwd, paths.exe, io) catch {};
        return err;
    };
}

/// exe -> failed, previous -> exe.
pub fn rollback(paths: Paths) !void {
    const io = iox.current();
    const cwd = std.Io.Dir.cwd();
    // Without a previous binary there is nothing to go back to.
    {
        const f = cwd.openFile(io, paths.previous, .{}) catch return error.NoPreviousBinary;
        f.close(io);
    }
    cwd.deleteFile(io, paths.failed) catch {};
    try cwd.rename(paths.exe, cwd, paths.failed, io);
    cwd.rename(paths.previous, cwd, paths.exe, io) catch |err| {
        cwd.rename(paths.failed, cwd, paths.exe, io) catch {};
        return err;
    };
}

// ---------------------------------------------------------------------------
// Runtime

pub const HealthState = struct {
    state: State,
    version: ?[]const u8 = null,
    ring: ?[]const u8 = null,
    bucket: ?u8 = null,
    reason: ?[]const u8 = null,
};

pub const Fetcher = struct {
    ctx: *anyopaque,
    /// Returns `{manifest, signature, download_url}` JSON from the server,
    /// or null when no release is offered. Caller frees.
    release: *const fn (ctx: *anyopaque, alloc: std.mem.Allocator, platform: []const u8) anyerror!?[]u8,
    /// Download `url` (at most `max` bytes). Caller frees.
    download: *const fn (ctx: *anyopaque, alloc: std.mem.Allocator, url: []const u8, max: u64) anyerror![]u8,
};

pub const Outcome = enum { nothing, restart_now };

pub const Updater = struct {
    alloc: std.mem.Allocator,
    state_path: []const u8,
    exe_path: []const u8,
    current_version: []const u8,
    platform: []const u8,
    agent_id: []const u8,
    /// Server-side ring override, if the server sent one.
    ring_override: ?Ring = null,
    key: ?minisign.PublicKey,
    status: State = .idle,
    status_version: [32]u8 = @splat(0),
    status_version_len: usize = 0,
    reason: []const u8 = "",

    pub fn init(alloc: std.mem.Allocator, state_path: []const u8, exe_path: []const u8, current_version: []const u8, platform: []const u8, agent_id: []const u8) Updater {
        const key = update_key.get() catch null;
        return .{
            .alloc = alloc,
            .state_path = state_path,
            .exe_path = exe_path,
            .current_version = current_version,
            .platform = platform,
            .agent_id = agent_id,
            .key = key,
            .status = if (key == null) .disabled_no_release_key else .idle,
        };
    }

    pub fn ring(self: *const Updater) Ring {
        return self.ring_override orelse ringForBucket(bucket(self.agent_id));
    }

    pub fn health(self: *const Updater) HealthState {
        return .{
            .state = self.status,
            .version = if (self.status_version_len > 0) self.status_version[0..self.status_version_len] else null,
            .ring = @tagName(self.ring()),
            .bucket = bucket(self.agent_id),
            .reason = if (self.reason.len > 0) self.reason else null,
        };
    }

    fn setStatus(self: *Updater, s: State, version: []const u8, why: []const u8) void {
        self.status = s;
        self.reason = why;
        const n = @min(version.len, self.status_version.len);
        @memcpy(self.status_version[0..n], version[0..n]);
        self.status_version_len = n;
    }

    /// Call once at start. Returns `.restart_now` after a rollback swap.
    pub fn startCheck(self: *Updater, now: i64) !Outcome {
        var parsed = try load(self.alloc, self.state_path);
        defer parsed.deinit();
        var p = parsed.value;
        switch (onStart(p, self.current_version, now)) {
            .none => {
                if (p.state == .rolled_back) self.setStatus(.rolled_back, p.refused_version, "health check failed");
                if (self.key == null) self.status = .disabled_no_release_key;
                return .nothing;
            },
            .health_check => {
                p.state = .health_check;
                p.attempts += 1;
                try save(self.alloc, self.state_path, p);
                self.setStatus(.health_check, p.version, "");
                return .nothing;
            },
            .rollback => return self.doRollback(p, "the new version did not pass its health check"),
        }
    }

    /// Feed heartbeat results while in the health window.
    pub fn onHeartbeat(self: *Updater, ok: bool, now: i64) !Outcome {
        if (self.status != .health_check) return .nothing;
        var parsed = try load(self.alloc, self.state_path);
        defer parsed.deinit();
        var p = parsed.value;
        if (ok and p.state == .health_check) {
            p.state = .committed;
            p.attempts = 0;
            try save(self.alloc, self.state_path, p);
            self.setStatus(.committed, p.version, "");
            return .nothing;
        }
        return switch (onTick(p, ok, now)) {
            .rollback => self.doRollback(p, "no good heartbeat inside the health window"),
            else => .nothing,
        };
    }

    fn doRollback(self: *Updater, p_in: Persisted, why: []const u8) !Outcome {
        var p = p_in;
        const paths = try Paths.init(self.alloc, self.exe_path);
        defer paths.deinit(self.alloc);
        rollback(paths) catch |err| {
            p.state = .failed;
            p.reason = "rollback failed: no previous binary";
            save(self.alloc, self.state_path, p) catch {};
            self.setStatus(.failed, p.version, p.reason);
            return err;
        };
        p.state = .rolled_back;
        p.refused_version = p.version;
        p.reason = why;
        try save(self.alloc, self.state_path, p);
        self.setStatus(.rolled_back, p.version, why);
        return .restart_now;
    }

    /// One update check. Returns `.restart_now` once a new binary is in
    /// place; the caller then stops so the service manager restarts it.
    pub fn check(self: *Updater, fetcher: Fetcher) !Outcome {
        if (self.key == null) {
            self.status = .disabled_no_release_key;
            return .nothing;
        }
        if (self.status == .health_check) return .nothing;
        const offered = (try fetcher.release(fetcher.ctx, self.alloc, self.platform)) orelse {
            if (self.status != .rolled_back and self.status != .committed) self.setStatus(.idle, "", "");
            return .nothing;
        };
        defer self.alloc.free(offered);
        const Offer = struct { manifest: []const u8, signature: []const u8, download_url: []const u8 };
        const offer = std.json.parseFromSlice(Offer, self.alloc, offered, .{ .ignore_unknown_fields = true }) catch {
            self.setStatus(.refused, "", "release reply is not valid");
            return .nothing;
        };
        defer offer.deinit();
        return self.apply(fetcher, offer.value.manifest, offer.value.signature, offer.value.download_url);
    }

    /// Verify, decide, download, stage and swap. Exposed for tests.
    pub fn apply(self: *Updater, fetcher: Fetcher, manifest: []const u8, signature: []const u8, url: []const u8) !Outcome {
        var m = verifyManifest(self.alloc, self.key, manifest, signature) catch |err| {
            self.setStatus(.refused, "", @errorName(err));
            return .nothing;
        };
        defer m.deinit();
        var prev = try load(self.alloc, self.state_path);
        defer prev.deinit();
        const decision = decide(m.value, .{
            .current_version = self.current_version,
            .platform = self.platform,
            .agent_ring = self.ring(),
            .refused_version = if (prev.value.refused_version.len > 0) prev.value.refused_version else null,
        });
        switch (decision) {
            .update => {},
            .up_to_date, .not_in_ring => {
                if (self.status != .rolled_back and self.status != .committed) self.setStatus(.idle, "", "");
                return .nothing;
            },
            else => {
                self.setStatus(.refused, m.value.version, @tagName(decision));
                return .nothing;
            },
        }
        if (!isHttps(url)) {
            self.setStatus(.refused, m.value.version, "download url is not https");
            return .nothing;
        }
        self.setStatus(.downloading, m.value.version, "");
        const bytes = fetcher.download(fetcher.ctx, self.alloc, url, m.value.size) catch |err| {
            self.setStatus(.failed, m.value.version, @errorName(err));
            return .nothing;
        };
        defer self.alloc.free(bytes);
        verifyPayload(m.value, bytes) catch |err| {
            self.setStatus(.refused, m.value.version, @errorName(err));
            return .nothing;
        };
        const paths = try Paths.init(self.alloc, self.exe_path);
        defer paths.deinit(self.alloc);
        try stage(paths, bytes);
        self.setStatus(.staged, m.value.version, "");
        try swap(paths);
        try save(self.alloc, self.state_path, .{
            .state = .restarting,
            .version = m.value.version,
            .previous_version = self.current_version,
            .sha256 = m.value.sha256,
            .deadline = iox.timestamp() + health_window_seconds,
            .attempts = 0,
        });
        // Keep the signed manifest so tamper checks can compare the binary.
        saveRelease(self.alloc, self.state_path, manifest, signature) catch {};
        self.setStatus(.restarting, m.value.version, "");
        return .restart_now;
    }
};

fn isHttps(url: []const u8) bool {
    return std.ascii.startsWithIgnoreCase(url, "https://");
}

/// `<state>.release.json` + `.minisig`: the manifest the running binary was
/// installed from.
pub fn saveRelease(alloc: std.mem.Allocator, state_path: []const u8, manifest: []const u8, signature: []const u8) !void {
    const io = iox.current();
    const m = try alloc.print("{s}.release.json", .{state_path});
    defer alloc.free(m);
    const s = try alloc.print("{s}.release.json.minisig", .{state_path});
    defer alloc.free(s);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = m, .data = manifest });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = s, .data = signature });
}

/// SHA-256 the running binary should have, from the saved manifest, when
/// its signature still verifies and it names `version`.
pub fn expectedBinaryHash(alloc: std.mem.Allocator, key: ?minisign.PublicKey, state_path: []const u8, version: []const u8) ?[32]u8 {
    const io = iox.current();
    const m_path = alloc.print("{s}.release.json", .{state_path}) catch return null;
    defer alloc.free(m_path);
    const s_path = alloc.print("{s}.release.json.minisig", .{state_path}) catch return null;
    defer alloc.free(s_path);
    const manifest = std.Io.Dir.cwd().readFileAlloc(io, m_path, alloc, .limited(16 * 1024)) catch return null;
    defer alloc.free(manifest);
    const sig = std.Io.Dir.cwd().readFileAlloc(io, s_path, alloc, .limited(4096)) catch return null;
    defer alloc.free(sig);
    var parsed = verifyManifest(alloc, key, manifest, sig) catch return null;
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.version, version)) return null;
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, parsed.value.sha256) catch return null;
    return out;
}

/// Agent platform name used by releases (`windows-x64`, `linux-arm64`...).
pub fn platformName() []const u8 {
    const os = switch (builtin.target.os.tag) {
        .windows => "windows",
        .macos => "macos",
        else => "linux",
    };
    const arch = if (builtin.target.cpu.arch == .aarch64) "arm64" else "x64";
    return os ++ "-" ++ arch;
}

// ---------------------------------------------------------------------------
// Debug subcommand: `--update-selftest <dir>` (CI). Builds a fake install
// under <dir>, signs a manifest with a key made for the run, and runs the
// good, bad signature, bad hash, downgrade and rollback paths through the
// real file operations (including renaming a file the way the running exe
// is renamed). No network and no service restart.

pub fn isDebugCommand(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--update-selftest");
}

pub fn debugCommand(alloc: std.mem.Allocator, args: []const []const u8) u8 {
    if (args.len != 2) {
        std.debug.print("usage: tawny-agent --update-selftest <empty-dir>\n", .{});
        return 2;
    }
    const results = runScenarios(alloc, args[1]) catch |err| {
        std.debug.print("UPDATE\tresult=failed\terror={s}\n", .{@errorName(err)});
        return 1;
    };
    std.debug.print("UPDATE\tgood={s}\tbad_signature={s}\tbad_hash={s}\tdowngrade={s}\trollback={s}\tresult=ok\n", .{
        results.good, results.bad_sig, results.bad_hash, results.downgrade, results.rollback,
    });
    std.debug.print("UPDATE\trelease_key={s}\n", .{if (update_key.isPlaceholder()) "placeholder (updates disabled)" else "set"});
    return 0;
}

const Scenarios = struct {
    good: []const u8,
    bad_sig: []const u8,
    bad_hash: []const u8,
    downgrade: []const u8,
    rollback: []const u8,
};

const FakeServer = struct {
    payload: []const u8,
    fn download(ctx: *anyopaque, alloc: std.mem.Allocator, _: []const u8, max: u64) anyerror![]u8 {
        const self: *FakeServer = @ptrCast(@alignCast(ctx));
        if (self.payload.len > max) return error.TooBig;
        return alloc.dupe(u8, self.payload);
    }
    fn release(_: *anyopaque, _: std.mem.Allocator, _: []const u8) anyerror!?[]u8 {
        return null;
    }
    fn fetcher(self: *FakeServer) Fetcher {
        return .{ .ctx = self, .release = release, .download = download };
    }
};

fn manifestFor(alloc: std.mem.Allocator, version: []const u8, bytes: []const u8, rollback_flag: bool) ![]u8 {
    var d: [32]u8 = undefined;
    Sha256.hash(bytes, &d, .{});
    return std.fmt.allocPrint(alloc,
        \\{{"version":"{s}","platform":"{s}","sha256":"{x}","size":{d},"min_from_version":"0.0.1","ring":"100","rollback":{}}}
    , .{ version, platformName(), d, bytes.len, rollback_flag });
}

fn readAll(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(iox.current(), path, alloc, .limited(1024 * 1024));
}

fn runScenarios(alloc: std.mem.Allocator, dir: []const u8) !Scenarios {
    const io = iox.current();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, dir);
    const exe_name = if (builtin.target.os.tag == .windows) "tawny-agent.exe" else "tawny-agent";
    const exe = try std.fs.path.join(alloc, &.{ dir, exe_name });
    defer alloc.free(exe);
    const state = try std.fs.path.join(alloc, &.{ dir, "state.toml" });
    defer alloc.free(state);
    // Start clean.
    for ([_][]const u8{ ".update.json", ".release.json", ".release.json.minisig" }) |suffix| {
        const p = try alloc.print("{s}{s}", .{ state, suffix });
        defer alloc.free(p);
        cwd.deleteFile(io, p) catch {};
    }
    try cwd.writeFile(io, .{ .sub_path = exe, .data = "old agent 0.1.0" });

    const signer = minisign.TestSigner.generate(io);
    const pub_text = try signer.publicKeyText(alloc);
    defer alloc.free(pub_text);
    const key = try minisign.parsePublicKey(pub_text);

    const new_bytes = "new agent 0.2.0";
    var server = FakeServer{ .payload = new_bytes };
    var u = Updater.init(alloc, state, exe, "0.1.0", platformName(), "00000000-0000-0000-0000-000000000042");
    u.key = key;
    u.status = .idle;

    // Bad signature: signed by another key.
    const other = minisign.TestSigner.generate(io);
    const good_manifest = try manifestFor(alloc, "0.2.0", new_bytes, false);
    defer alloc.free(good_manifest);
    const forged = try other.sign(alloc, good_manifest, "tawny release", .prehashed);
    defer alloc.free(forged);
    _ = try u.apply(server.fetcher(), good_manifest, forged, "https://example.invalid/a");
    if (u.status != .refused) return error.BadSignatureAccepted;
    const bad_sig = "refused";

    // Bad hash: signed manifest, wrong bytes on the wire.
    const sig = try signer.sign(alloc, good_manifest, "tawny release", .prehashed);
    defer alloc.free(sig);
    server.payload = "new agent 0.2.X";
    _ = try u.apply(server.fetcher(), good_manifest, sig, "https://example.invalid/a");
    if (u.status != .refused) return error.BadHashAccepted;
    if (!std.mem.eql(u8, try readOnce(alloc, exe), "old agent 0.1.0")) return error.BinaryChanged;
    const bad_hash = "refused";

    // Downgrade: correctly signed, lower version, not a rollback.
    const down = try manifestFor(alloc, "0.0.9", new_bytes, false);
    defer alloc.free(down);
    const down_sig = try signer.sign(alloc, down, "tawny release", .prehashed);
    defer alloc.free(down_sig);
    server.payload = new_bytes;
    _ = try u.apply(server.fetcher(), down, down_sig, "https://example.invalid/a");
    if (u.status != .refused) return error.DowngradeAccepted;
    const downgrade = "refused";

    // Good update: staged, swapped, old binary kept as .previous.
    if (try u.apply(server.fetcher(), good_manifest, sig, "https://example.invalid/a") != .restart_now) return error.GoodUpdateNotApplied;
    if (!std.mem.eql(u8, try readOnce(alloc, exe), new_bytes)) return error.SwapFailed;
    const paths = try Paths.init(alloc, exe);
    defer paths.deinit(alloc);
    if (!std.mem.eql(u8, try readOnce(alloc, paths.previous), "old agent 0.1.0")) return error.PreviousMissing;
    const good = "swapped";

    // The new binary starts; no good heartbeat before the deadline: roll back.
    var nu = Updater.init(alloc, state, exe, "0.2.0", platformName(), "00000000-0000-0000-0000-000000000042");
    nu.key = key;
    const t0 = iox.timestamp();
    if (try nu.startCheck(t0) != .nothing or nu.status != .health_check) return error.HealthWindowNotOpened;
    if (try nu.onHeartbeat(false, t0 + health_window_seconds + 1) != .restart_now) return error.NoRollback;
    if (!std.mem.eql(u8, try readOnce(alloc, exe), "old agent 0.1.0")) return error.RollbackDidNotRestore;
    // The old binary refuses the version it rolled back from.
    var ou = Updater.init(alloc, state, exe, "0.1.0", platformName(), "00000000-0000-0000-0000-000000000042");
    ou.key = key;
    _ = try ou.startCheck(t0 + 400);
    if (ou.status != .rolled_back) return error.RollbackNotReported;
    _ = try ou.apply(server.fetcher(), good_manifest, sig, "https://example.invalid/a");
    if (ou.status != .refused) return error.RefusedVersionRetried;
    const rolled = "restored";

    return .{ .good = good, .bad_sig = bad_sig, .bad_hash = bad_hash, .downgrade = downgrade, .rollback = rolled };
}

/// Small helper for the scenarios: read a file into a static buffer.
var read_buf: [256]u8 = undefined;
fn readOnce(alloc: std.mem.Allocator, path: []const u8) ![]const u8 {
    const data = try readAll(alloc, path);
    defer alloc.free(data);
    const n = @min(data.len, read_buf.len);
    @memcpy(read_buf[0..n], data[0..n]);
    return read_buf[0..n];
}

// ---------------------------------------------------------------------------
// Tests (pure logic on every OS, plus the file scenarios in a temp dir)

const testing = std.testing;

test "bucket is stable, in range, and matches the server vector" {
    // Same vector as server/src/routes/agent_releases.zig.
    try testing.expectEqual(bucket("00000000-0000-0000-0000-000000000042"), bucket("00000000-0000-0000-0000-000000000042"));
    try testing.expectEqual(bucket("ABCDEF00-0000-0000-0000-000000000000"), bucket("abcdef00-0000-0000-0000-000000000000"));
    try testing.expectEqual(@as(u8, 19), bucket("00000000-0000-0000-0000-000000000001"));
    try testing.expectEqual(@as(u8, 16), bucket("00000000-0000-0000-0000-000000000042"));
    var seen: [100]bool = @splat(false);
    var buf: [36]u8 = undefined;
    var i: u32 = 0;
    while (i < 2000) : (i += 1) {
        const id = try std.fmt.bufPrint(&buf, "00000000-0000-0000-0000-{d:0>12}", .{i});
        const b = bucket(id);
        try testing.expect(b < 100);
        seen[b] = true;
    }
    var covered: usize = 0;
    for (seen) |s| covered += @intFromBool(s);
    try testing.expect(covered > 95);
}

test "ring order gates who is offered a release" {
    try testing.expectEqual(Ring.@"10", ringForBucket(9));
    try testing.expectEqual(Ring.@"50", ringForBucket(10));
    try testing.expectEqual(Ring.@"100", ringForBucket(99));
    try testing.expect(ringAllows(.canary, .canary));
    try testing.expect(!ringAllows(.canary, .internal));
    try testing.expect(ringAllows(.@"50", .@"10"));
    try testing.expect(!ringAllows(.@"50", .@"100"));
    try testing.expect(ringAllows(.@"100", .@"100"));
}

test "decide: upgrade, same, downgrade, rollback, platform, min_from, ring" {
    const sha: []const u8 = &(@as([64]u8, @splat('a')));
    const base: Manifest = .{ .version = "0.2.0", .platform = "linux-x64", .sha256 = sha, .size = 10, .min_from_version = "0.1.0", .ring = "100" };
    const ctx: Context = .{ .current_version = "0.1.0", .platform = "linux-x64", .agent_ring = .@"100" };
    try testing.expectEqual(Decision.update, decide(base, ctx));
    var m = base;
    m.version = "0.1.0";
    try testing.expectEqual(Decision.up_to_date, decide(m, ctx));
    m.version = "0.0.9";
    try testing.expectEqual(Decision.downgrade_refused, decide(m, ctx));
    m.rollback = true;
    try testing.expectEqual(Decision.update, decide(m, ctx));
    m.version = "0.3.0";
    try testing.expectEqual(Decision.up_to_date, decide(m, ctx));
    m = base;
    m.platform = "windows-x64";
    try testing.expectEqual(Decision.wrong_platform, decide(m, ctx));
    m = base;
    m.min_from_version = "0.1.5";
    try testing.expectEqual(Decision.below_min_from, decide(m, ctx));
    m = base;
    m.ring = "canary";
    try testing.expectEqual(Decision.not_in_ring, decide(m, ctx));
    m.ring = "bogus";
    try testing.expectEqual(Decision.bad_manifest, decide(m, ctx));
    var c2 = ctx;
    c2.refused_version = "0.2.0";
    try testing.expectEqual(Decision.refused_version, decide(base, c2));
}

test "health window: commit on heartbeat, roll back on deadline or repeated starts" {
    const p: Persisted = .{ .state = .restarting, .version = "0.2.0", .deadline = 1000, .attempts = 0 };
    try testing.expectEqual(StartAction.health_check, onStart(p, "0.2.0", 10));
    try testing.expectEqual(StartAction.none, onStart(p, "0.1.0", 10));
    try testing.expectEqual(StartAction.rollback, onStart(p, "0.2.0", 1001));
    var many = p;
    many.attempts = 2;
    try testing.expectEqual(StartAction.rollback, onStart(many, "0.2.0", 10));
    var hc = p;
    hc.state = .health_check;
    try testing.expectEqual(StartAction.none, onTick(hc, true, 10));
    try testing.expectEqual(StartAction.health_check, onTick(hc, false, 10));
    try testing.expectEqual(StartAction.rollback, onTick(hc, false, 1001));
}

test "placeholder key disables updates" {
    var u = Updater.init(testing.allocator, "x", "y", "0.1.0", "linux-x64", "00000000-0000-0000-0000-000000000001");
    try testing.expectEqual(State.disabled_no_release_key, u.status);
    var server = FakeServer{ .payload = "" };
    try testing.expectEqual(Outcome.nothing, try u.check(server.fetcher()));
    try testing.expectEqual(State.disabled_no_release_key, u.health().state);
}

test "good update, bad signature, bad hash, downgrade refused, failed health check rolls back" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fs.path.join(a, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer a.free(dir);
    const r = try runScenarios(a, dir);
    try testing.expectEqualStrings("swapped", r.good);
    try testing.expectEqualStrings("restored", r.rollback);
}

test "a committed manifest gives the expected binary hash" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state = try std.fs.path.join(a, &.{ ".zig-cache", "tmp", &tmp.sub_path, "state.toml" });
    defer a.free(state);
    const signer = minisign.TestSigner.generate(testing.io);
    const pub_text = try signer.publicKeyText(a);
    defer a.free(pub_text);
    const key = try minisign.parsePublicKey(pub_text);
    const manifest = try manifestFor(a, "0.2.0", "bytes", false);
    defer a.free(manifest);
    const sig = try signer.sign(a, manifest, "c", .prehashed);
    defer a.free(sig);
    try saveRelease(a, state, manifest, sig);
    var want: [32]u8 = undefined;
    Sha256.hash("bytes", &want, .{});
    try testing.expectEqualSlices(u8, &want, &(expectedBinaryHash(a, key, state, "0.2.0").?));
    try testing.expect(expectedBinaryHash(a, key, state, "0.3.0") == null);
    try testing.expect(expectedBinaryHash(a, null, state, "0.2.0") == null);
}
