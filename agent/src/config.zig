const std = @import("std");
const builtin = @import("builtin");
const env = @import("env.zig");
const iox = @import("io_compat.zig");
const keystore = @import("keystore.zig");

pub const Config = struct {
    allocator: std.mem.Allocator,
    backend_url: []u8,
    enrollment_token: ?[]u8 = null,
    agent_id: ?[]u8 = null,
    agent_jwt: ?[]u8 = null,
    heartbeat_interval_seconds: u32 = 60,
    process_interval_seconds: u32 = 30,
    process_events_interval_seconds: u32 = 5,
    network_interval_seconds: u32 = 30,
    users_interval_seconds: u32 = 300,
    system_interval_seconds: u32 = 3600,
    fim_interval_seconds: u32 = 300,
    fs_events_interval_seconds: u32 = 5,
    dns_interval_seconds: u32 = 30,
    supply_chain_interval_seconds: u32 = 21600,
    max_in_memory_events: usize = 1000,
    max_spool_bytes: u64 = 256 * 1024 * 1024,
    http_timeout_seconds: u32 = 30,
    max_retry_backoff_seconds: u32 = 300,
    fim_paths: [][]u8 = &.{},
    spill_path: []u8,
    config_path: []u8,
    state_path: []u8,
    /// Dangerous: permit non-loopback HTTP backends. Default false.
    allow_insecure_http: bool = false,
    /// Where the JWT and device seed live. `load` picks the platform default;
    /// literal Configs (tests) keep the plaintext-file behaviour.
    secret_store: keystore.Store = .{},

    pub fn deinit(self: *Config) void {
        self.allocator.free(self.backend_url);
        self.allocator.free(self.spill_path);
        self.allocator.free(self.config_path);
        self.allocator.free(self.state_path);
        if (self.enrollment_token) |t| self.allocator.free(t);
        if (self.agent_id) |t| self.allocator.free(t);
        if (self.agent_jwt) |t| self.allocator.free(t);
        for (self.fim_paths) |p| self.allocator.free(p);
        if (self.fim_paths.len > 0) self.allocator.free(self.fim_paths);
    }
};

/// Resolve the platform-default config directory.
fn defaultConfigPath(alloc: std.mem.Allocator) ![]u8 {
    if (builtin.target.os.tag == .windows) {
        const programdata = env.getEnvVarOwned(alloc, "PROGRAMDATA") catch
            try alloc.dupe(u8, "C:\\ProgramData");
        defer alloc.free(programdata);
        return alloc.print("{s}\\Tawny\\config.toml", .{programdata});
    }
    if (builtin.target.os.tag == .linux) {
        return alloc.dupe(u8, "/etc/tawny/config.toml");
    }
    return alloc.dupe(u8, "/Library/Application Support/Tawny/config.toml");
}

pub const LoadOptions = struct {
    /// Move plaintext JWT / device seed into the OS keystore when possible.
    migrate_secrets: bool = true,
};

/// Read TOML-ish config. Trivial line-based parser — good enough for MVP.
pub fn load(alloc: std.mem.Allocator) !Config {
    return loadWith(alloc, .{});
}

pub fn loadWith(alloc: std.mem.Allocator, options: LoadOptions) !Config {
    const env_path = env.getEnvVarOwned(alloc, "TAWNY_CONFIG") catch null;
    const path: []u8 = if (env_path) |p| p else try defaultConfigPath(alloc);
    const env_state_path = env.getEnvVarOwned(alloc, "TAWNY_STATE_PATH") catch null;

    var cfg = Config{
        .allocator = alloc,
        .backend_url = try alloc.dupe(u8, "http://localhost:5080"),
        .spill_path = try alloc.print("{s}.spool", .{path}),
        .config_path = path,
        .state_path = if (env_state_path) |p| p else try alloc.print("{s}.state", .{path}),
    };
    errdefer cfg.deinit();

    const io = iox.current();
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch {
        // First run: emit a default config alongside the binary.
        return cfg;
    };
    defer file.close(io);

    const raw = try iox.readToEndAlloc(file, alloc, 64 * 1024);
    defer alloc.free(raw);

    var line_iter = std.mem.splitScalar(u8, raw, '\n');
    while (line_iter.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0 or line[0] == '#' or line[0] == '[') continue;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const val = std.mem.trim(u8, line[eq + 1 ..], " \t\"");

        if (std.mem.eql(u8, key, "url") or std.mem.eql(u8, key, "backend_url")) {
            alloc.free(cfg.backend_url);
            cfg.backend_url = try alloc.dupe(u8, val);
        } else if (std.mem.eql(u8, key, "enrollment_token")) {
            if (cfg.enrollment_token) |old| alloc.free(old);
            cfg.enrollment_token = try alloc.dupe(u8, val);
        } else if (std.mem.eql(u8, key, "agent_id")) {
            if (cfg.agent_id) |old| alloc.free(old);
            cfg.agent_id = try alloc.dupe(u8, val);
        } else if (std.mem.eql(u8, key, "agent_jwt")) {
            if (cfg.agent_jwt) |old| alloc.free(old);
            cfg.agent_jwt = try alloc.dupe(u8, val);
        } else if (std.mem.eql(u8, key, "heartbeat_interval_seconds")) {
            cfg.heartbeat_interval_seconds = try std.fmt.parseInt(u32, val, 10);
        } else if (std.mem.eql(u8, key, "process_interval_seconds")) {
            cfg.process_interval_seconds = try std.fmt.parseInt(u32, val, 10);
        } else if (std.mem.eql(u8, key, "network_interval_seconds")) {
            cfg.network_interval_seconds = try std.fmt.parseInt(u32, val, 10);
        } else if (std.mem.eql(u8, key, "users_interval_seconds")) {
            cfg.users_interval_seconds = try std.fmt.parseInt(u32, val, 10);
        } else if (std.mem.eql(u8, key, "system_interval_seconds")) {
            cfg.system_interval_seconds = try std.fmt.parseInt(u32, val, 10);
        } else if (std.mem.eql(u8, key, "fim_interval_seconds")) {
            cfg.fim_interval_seconds = try std.fmt.parseInt(u32, val, 10);
        } else if (std.mem.eql(u8, key, "process_events_interval_seconds")) {
            cfg.process_events_interval_seconds = try std.fmt.parseInt(u32, val, 10);
        } else if (std.mem.eql(u8, key, "fs_events_interval_seconds")) {
            cfg.fs_events_interval_seconds = try std.fmt.parseInt(u32, val, 10);
        } else if (std.mem.eql(u8, key, "dns_interval_seconds")) {
            cfg.dns_interval_seconds = try std.fmt.parseInt(u32, val, 10);
        } else if (std.mem.eql(u8, key, "supply_chain_interval_seconds")) {
            cfg.supply_chain_interval_seconds = try std.fmt.parseInt(u32, val, 10);
        } else if (std.mem.eql(u8, key, "max_in_memory_events")) {
            cfg.max_in_memory_events = try std.fmt.parseInt(usize, val, 10);
        } else if (std.mem.eql(u8, key, "max_spool_bytes")) {
            cfg.max_spool_bytes = try std.fmt.parseInt(u64, val, 10);
        } else if (std.mem.eql(u8, key, "http_timeout_seconds")) {
            cfg.http_timeout_seconds = try std.fmt.parseInt(u32, val, 10);
        } else if (std.mem.eql(u8, key, "max_retry_backoff_seconds")) {
            cfg.max_retry_backoff_seconds = try std.fmt.parseInt(u32, val, 10);
        } else if (std.mem.eql(u8, key, "allow_insecure_http")) {
            cfg.allow_insecure_http = std.mem.eql(u8, val, "true") or std.mem.eql(u8, val, "1");
        } else if (std.mem.eql(u8, key, "spill_path")) {
            alloc.free(cfg.spill_path);
            cfg.spill_path = try alloc.dupe(u8, val);
        } else if (std.mem.eql(u8, key, "fim_path")) {
            try appendFimPath(&cfg, val);
        } else if (std.mem.eql(u8, key, "fim_paths")) {
            try appendFimPaths(&cfg, val);
        }
    }

    if (env_state_path == null) {
        alloc.free(cfg.state_path);
        const state_dir = std.fs.path.dirname(cfg.spill_path) orelse ".";
        cfg.state_path = try std.fs.path.join(alloc, &.{ state_dir, "state.toml" });
    }

    try validate(&cfg);
    cfg.secret_store = keystore.platformDefault(alloc);
    const state = try loadState(&cfg);
    if (state == .missing and cfg.agent_id != null and cfg.agent_jwt != null) {
        // One-time migration from legacy config files which stored mutable
        // credentials beside static settings.
        try save(&cfg);
    }
    if (options.migrate_secrets) migrateSecrets(&cfg, state == .jwt_in_file);
    return cfg;
}

/// Persist mutable enrollment state. The JWT goes to the OS keystore when one
/// is available (write + verified read-back) and state.toml keeps only
/// non-secret fields. If the keystore write fails, the JWT is written to
/// state.toml as before, with a warning. A JWT in state.toml always takes
/// precedence on load, so a fallback write can never be shadowed by an older
/// keystore copy.
pub fn save(cfg: *const Config) !void {
    if (cfg.agent_id == null or cfg.agent_jwt == null) return error.IncompleteAgentState;
    const store = cfg.secret_store;
    if (store.isOs()) {
        if (store.putVerified(cfg.allocator, .agent_jwt, cfg.agent_jwt.?)) {
            return writeStateFile(cfg, null);
        } else |err| {
            std.log.warn(
                "agent JWT: {s} write failed ({s}, status {d}); storing it in plaintext {s}",
                .{ store.describe(), @errorName(err), keystore.lastOsStatus(), cfg.state_path },
            );
        }
    }
    return writeStateFile(cfg, cfg.agent_jwt.?);
}

/// Serialize state.toml. `jwt` is null when the JWT lives in the keystore.
pub fn renderState(w: *std.Io.Writer, agent_id: []const u8, jwt: ?[]const u8) !void {
    try w.writeAll("[state]\nagent_id = ");
    try std.json.Stringify.value(agent_id, .{}, w);
    if (jwt) |value| {
        try w.writeAll("\nagent_jwt = ");
        try std.json.Stringify.value(value, .{}, w);
    }
    try w.writeByte('\n');
}

/// Atomically replace state.toml (tmp + fsync + rename, 0600).
fn writeStateFile(cfg: *const Config, jwt: ?[]const u8) !void {
    const dir = std.fs.path.dirname(cfg.state_path) orelse ".";
    const io = iox.current();
    try std.Io.Dir.cwd().createDirPath(io, dir);

    const tmp_path = try cfg.allocator.print("{s}.tmp", .{cfg.state_path});
    defer cfg.allocator.free(tmp_path);

    {
        var file = try std.Io.Dir.cwd().createFile(io, tmp_path, .{
            .truncate = true,
            .permissions = if (builtin.target.os.tag == .windows) .default_file else @fromBackingInt(@intCast(0o600)),
        });
        defer file.close(io);
        var writer_buffer: [4096]u8 = undefined;
        var file_writer = file.writer(io, &writer_buffer);
        try renderState(&file_writer.interface, cfg.agent_id.?, jwt);
        try file_writer.interface.flush();
        try file.sync(io);
    }

    try std.Io.Dir.cwd().rename(tmp_path, std.Io.Dir.cwd(), cfg.state_path, io);
    try syncParentDirectory(cfg.state_path);
}

/// Move plaintext secrets into the keystore. Never fatal: on any failure the
/// plaintext copy stays where it is and a warning is logged.
fn migrateSecrets(cfg: *Config, jwt_in_file: bool) void {
    const store = cfg.secret_store;
    if (!store.isOs()) return;

    if (jwt_in_file) {
        if (store.putVerified(cfg.allocator, .agent_jwt, cfg.agent_jwt.?)) {
            if (writeStateFile(cfg, null)) {
                std.log.info("moved agent JWT from {s} into the {s}", .{ cfg.state_path, store.describe() });
            } else |err| {
                std.log.warn("agent JWT copied to the {s} but {s} could not be rewritten ({s})", .{ store.describe(), cfg.state_path, @errorName(err) });
            }
        } else |err| {
            std.log.warn(
                "agent JWT stays in plaintext {s}: {s} unavailable ({s}, status {d})",
                .{ cfg.state_path, store.describe(), @errorName(err), keystore.lastOsStatus() },
            );
        }
    }

    const seed_path = keystore.deviceSeedPath(cfg.allocator, cfg.state_path) catch return;
    defer cfg.allocator.free(seed_path);
    if (keystore.migrateDeviceSeed(cfg.allocator, store, seed_path)) |moved| {
        if (moved) std.log.info("moved device key from {s} into the {s}", .{ seed_path, store.describe() });
    } else |err| {
        std.log.warn(
            "device key stays in plaintext {s}: {s} unavailable ({s}, status {d})",
            .{ seed_path, store.describe(), @errorName(err), keystore.lastOsStatus() },
        );
    }
}

/// `tawny-agent --export-credentials`: copy the JWT and device seed from the
/// OS keystore back into plaintext state files (verified), then remove them
/// from the keystore. Run by the installer with the *old* binary before an
/// upgrade, because the keychain only lets the exact build that created an
/// item read it. The new binary migrates the files back on first start.
pub fn exportCredentials(cfg: *Config) !void {
    const store = cfg.secret_store;
    if (!store.isOs()) return;
    const seed_path = try keystore.deviceSeedPath(cfg.allocator, cfg.state_path);
    defer cfg.allocator.free(seed_path);

    var exported_jwt = false;
    if (cfg.agent_id != null and cfg.agent_jwt != null) {
        try writeStateFile(cfg, cfg.agent_jwt.?);
        var check = Config{
            .allocator = cfg.allocator,
            .backend_url = try cfg.allocator.dupe(u8, cfg.backend_url),
            .spill_path = try cfg.allocator.dupe(u8, cfg.spill_path),
            .config_path = try cfg.allocator.dupe(u8, cfg.config_path),
            .state_path = try cfg.allocator.dupe(u8, cfg.state_path),
        };
        defer check.deinit();
        if (try loadState(&check) != .jwt_in_file or !std.mem.eql(u8, check.agent_jwt.?, cfg.agent_jwt.?)) {
            return error.ExportVerifyFailed;
        }
        exported_jwt = true;
    }
    _ = try keystore.exportDeviceSeed(cfg.allocator, store, seed_path);
    if (exported_jwt) try store.delete(.agent_jwt);
}

/// CLI entry for `--export-credentials`. Loads config without migrating,
/// exports, and reports on stderr.
pub fn exportCredentialsCommand(alloc: std.mem.Allocator) !void {
    var cfg = try loadWith(alloc, .{ .migrate_secrets = false });
    defer cfg.deinit();
    if (!cfg.secret_store.isOs()) {
        std.debug.print("credentials already stored in plaintext state files; nothing to export\n", .{});
        return;
    }
    exportCredentials(&cfg) catch |err| {
        std.debug.print("credential export from the {s} failed: {s} (status {d})\n", .{ cfg.secret_store.describe(), @errorName(err), keystore.lastOsStatus() });
        return err;
    };
    std.debug.print("exported credentials from the {s} to {s}\n", .{ cfg.secret_store.describe(), cfg.state_path });
}

pub const StateFile = struct {
    agent_id: ?[]u8 = null,
    agent_jwt: ?[]u8 = null,

    pub fn deinit(self: *StateFile, alloc: std.mem.Allocator) void {
        if (self.agent_id) |v| alloc.free(v);
        if (self.agent_jwt) |v| alloc.free(v);
    }
};

/// Parse state.toml. Empty values count as absent.
pub fn parseState(alloc: std.mem.Allocator, raw: []const u8) !StateFile {
    var out = StateFile{};
    errdefer out.deinit(alloc);
    var line_iter = std.mem.splitScalar(u8, raw, '\n');
    while (line_iter.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0 or line[0] == '#' or line[0] == '[') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const val = std.mem.trim(u8, line[eq + 1 ..], " \t\"");
        const slot: *?[]u8 = if (std.mem.eql(u8, key, "agent_id"))
            &out.agent_id
        else if (std.mem.eql(u8, key, "agent_jwt"))
            &out.agent_jwt
        else
            continue;
        if (slot.*) |old| alloc.free(old);
        slot.* = null;
        if (val.len > 0) slot.* = try alloc.dupe(u8, val);
    }
    return out;
}

/// Return `raw` without any `enrollment_token = ...` lines, or null when the
/// config contains no such line. Caller owns the returned slice.
pub fn stripEnrollmentToken(alloc: std.mem.Allocator, raw: []const u8) !?[]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    var removed = false;
    var line_iter = std.mem.splitScalar(u8, raw, '\n');
    var first = true;
    while (line_iter.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (std.mem.indexOfScalar(u8, line, '=')) |eq| {
            if (line[0] != '#' and std.mem.eql(u8, std.mem.trim(u8, line[0..eq], " \t"), "enrollment_token")) {
                removed = true;
                continue;
            }
        }
        if (!first) try out.writer.writeByte('\n');
        first = false;
        try out.writer.writeAll(line_raw);
    }
    if (!removed) {
        out.deinit();
        return null;
    }
    return try out.toOwnedSlice();
}

/// Atomically rewrite the static config file (tmp + rename) without the
/// single-use enrollment token. Returns false when no token line was present.
/// Fails (leaving the original untouched) when the config is not writable.
pub fn removeEnrollmentToken(alloc: std.mem.Allocator, config_path: []const u8) !bool {
    const io = iox.current();
    const cwd = std.Io.Dir.cwd();

    const file = cwd.openFile(io, config_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    const stat = file.stat(io) catch |err| {
        file.close(io);
        return err;
    };
    const raw = iox.readToEndAlloc(file, alloc, 64 * 1024) catch |err| {
        file.close(io);
        return err;
    };
    file.close(io);
    defer alloc.free(raw);

    const stripped = (try stripEnrollmentToken(alloc, raw)) orelse return false;
    defer alloc.free(stripped);

    const tmp_path = try alloc.print("{s}.tmp", .{config_path});
    defer alloc.free(tmp_path);

    writeSynced(io, tmp_path, stripped, stat.permissions) catch |err| {
        cwd.deleteFile(io, tmp_path) catch {};
        return err;
    };
    cwd.rename(tmp_path, cwd, config_path, io) catch |err| {
        cwd.deleteFile(io, tmp_path) catch {};
        return err;
    };
    try syncParentDirectory(config_path);
    return true;
}

fn writeSynced(io: std.Io, path: []const u8, bytes: []const u8, permissions: std.Io.File.Permissions) !void {
    var tmp = try std.Io.Dir.cwd().createFile(io, path, .{
        .truncate = true,
        // Windows: inherit the hardened ProgramData\Tawny ACL.
        .permissions = if (builtin.target.os.tag == .windows) .default_file else permissions,
    });
    defer tmp.close(io);
    try tmp.writePositionalAll(io, bytes, 0);
    try tmp.sync(io);
}

fn syncParentDirectory(path: []const u8) !void {
    if (builtin.target.os.tag != .linux) return;
    const io = iox.current();
    const parent_path = std.fs.path.dirname(path) orelse ".";
    // `openDir` otherwise uses Linux O_PATH, which cannot be passed to fsync.
    const dir = try std.Io.Dir.cwd().openDir(io, parent_path, .{ .iterate = true });
    defer dir.close(io);
    const file = std.Io.File{
        .handle = dir.handle,
        .flags = .{ .nonblocking = false },
    };
    try file.sync(io);
}

const StateSource = enum {
    /// No state.toml.
    missing,
    /// JWT read from state.toml (legacy layout or keystore fallback).
    jwt_in_file,
    /// JWT read from the OS keystore.
    jwt_in_keystore,
};

/// Load agent_id from state.toml and the JWT from state.toml when present
/// (authoritative), else from the keystore.
fn loadState(cfg: *Config) !StateSource {
    const io = iox.current();
    const file = std.Io.Dir.cwd().openFile(io, cfg.state_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return .missing,
        else => return err,
    };
    const raw = blk: {
        defer file.close(io);
        break :blk try iox.readToEndAlloc(file, cfg.allocator, 64 * 1024);
    };
    defer cfg.allocator.free(raw);

    var state = try parseState(cfg.allocator, raw);
    errdefer state.deinit(cfg.allocator);
    if (state.agent_id == null) return error.IncompleteAgentState;

    var source: StateSource = .jwt_in_file;
    if (state.agent_jwt == null) {
        const store = cfg.secret_store;
        if (!store.isOs()) return error.IncompleteAgentState;
        state.agent_jwt = store.get(cfg.allocator, .agent_jwt) catch |err| {
            std.log.warn(
                "agent JWT for {s} could not be read from the {s} ({s}, status {d}). If the agent binary was replaced without `--export-credentials`, re-enroll this host.",
                .{ cfg.state_path, store.describe(), @errorName(err), keystore.lastOsStatus() },
            );
            return error.AgentJwtUnavailable;
        };
        if (state.agent_jwt == null) {
            std.log.warn("{s} has an agent_id but the {s} holds no agent JWT; re-enroll this host", .{ cfg.state_path, store.describe() });
            return error.IncompleteAgentState;
        }
        source = .jwt_in_keystore;
    }

    if (cfg.agent_id) |old| cfg.allocator.free(old);
    if (cfg.agent_jwt) |old| cfg.allocator.free(old);
    cfg.agent_id = state.agent_id;
    cfg.agent_jwt = state.agent_jwt;
    return source;
}

fn validate(cfg: *const Config) !void {
    if (std.mem.eql(u8, cfg.config_path, cfg.spill_path) or
        std.mem.eql(u8, cfg.config_path, cfg.state_path) or
        std.mem.eql(u8, cfg.spill_path, cfg.state_path))
    {
        return error.OverlappingStatePaths;
    }
    if (cfg.max_in_memory_events == 0 or cfg.max_in_memory_events > 100_000) {
        return error.InvalidMemoryEventLimit;
    }
    if (cfg.max_spool_bytes < 1024 * 1024 or cfg.max_spool_bytes > 16 * 1024 * 1024 * 1024) {
        return error.InvalidSpoolLimit;
    }
    if (cfg.http_timeout_seconds == 0 or cfg.http_timeout_seconds > 300) {
        return error.InvalidHttpTimeout;
    }
    if (cfg.max_retry_backoff_seconds == 0 or cfg.max_retry_backoff_seconds > 3600) {
        return error.InvalidRetryBackoff;
    }

    try validateBackendUrl(cfg.backend_url, cfg.allow_insecure_http);

    const intervals = [_]u32{
        cfg.heartbeat_interval_seconds,
        cfg.process_interval_seconds,
        cfg.process_events_interval_seconds,
        cfg.network_interval_seconds,
        cfg.users_interval_seconds,
        cfg.system_interval_seconds,
        cfg.fim_interval_seconds,
        cfg.fs_events_interval_seconds,
        cfg.dns_interval_seconds,
        cfg.supply_chain_interval_seconds,
    };
    for (intervals) |interval| {
        if (interval == 0) return error.InvalidCollectionInterval;
    }
}

/// Reject remote plaintext backends unless allow_insecure_http is set.
/// Loopback HTTP remains allowed for local development without the override.
pub fn validateBackendUrl(url: []const u8, allow_insecure_http: bool) !void {
    const is_https = std.mem.startsWith(u8, url, "https://");
    const is_http = std.mem.startsWith(u8, url, "http://");
    if (!is_https and !is_http) return error.InvalidBackendUrl;

    if (is_https) return;

    // http://
    if (isLoopbackHttpUrl(url)) return;
    if (allow_insecure_http) return;
    return error.InsecureBackendUrl;
}

fn isLoopbackHttpUrl(url: []const u8) bool {
    // url starts with "http://"
    if (!std.mem.startsWith(u8, url, "http://")) return false;
    const rest = url["http://".len..];
    const host_end = std.mem.indexOfAny(u8, rest, ":/") orelse rest.len;
    const host = rest[0..host_end];
    return std.mem.eql(u8, host, "localhost")
        or std.mem.eql(u8, host, "127.0.0.1")
        or std.mem.eql(u8, host, "[::1]")
        or std.mem.eql(u8, host, "::1");
}

fn appendFimPaths(cfg: *Config, raw: []const u8) !void {
    var iter = std.mem.splitScalar(u8, raw, ',');
    while (iter.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n[]\"");
        if (trimmed.len > 0) try appendFimPath(cfg, trimmed);
    }
}

fn appendFimPath(cfg: *Config, path: []const u8) !void {
    var next = try cfg.allocator.alloc([]u8, cfg.fim_paths.len + 1);
    for (cfg.fim_paths, 0..) |existing, i| next[i] = existing;
    next[cfg.fim_paths.len] = try cfg.allocator.dupe(u8, path);
    if (cfg.fim_paths.len > 0) cfg.allocator.free(cfg.fim_paths);
    cfg.fim_paths = next;
}

test "fim paths parser accepts arrays and repeated paths" {
    var cfg = Config{
        .allocator = std.testing.allocator,
        .backend_url = try std.testing.allocator.dupe(u8, "http://localhost:5080"),
        .spill_path = try std.testing.allocator.dupe(u8, "events.spool"),
        .config_path = try std.testing.allocator.dupe(u8, "config.toml"),
        .state_path = try std.testing.allocator.dupe(u8, "state.toml"),
    };
    defer cfg.deinit();

    try appendFimPaths(&cfg, "\"/etc/hosts\", \"/tmp/a\"");
    try appendFimPath(&cfg, "/var/log/system.log");

    try std.testing.expectEqual(@as(usize, 3), cfg.fim_paths.len);
    try std.testing.expectEqualStrings("/etc/hosts", cfg.fim_paths[0]);
    try std.testing.expectEqualStrings("/tmp/a", cfg.fim_paths[1]);
    try std.testing.expectEqualStrings("/var/log/system.log", cfg.fim_paths[2]);
}

test "default config path" {
    const alloc = std.testing.allocator;
    const p = try defaultConfigPath(alloc);
    defer alloc.free(p);
    try std.testing.expect(p.len > 0);
}

test "backend url rejects remote http without override" {
    try validateBackendUrl("https://tawny.example", false);
    try validateBackendUrl("http://localhost:5080", false);
    try validateBackendUrl("http://127.0.0.1:5080", false);
    try std.testing.expectError(error.InsecureBackendUrl, validateBackendUrl("http://192.168.1.10:5080", false));
    try validateBackendUrl("http://192.168.1.10:5080", true);
}

test "production limits reject hot loops and unbounded retry settings" {
    var cfg = Config{
        .allocator = std.testing.allocator,
        .backend_url = try std.testing.allocator.dupe(u8, "https://tawny.example"),
        .spill_path = try std.testing.allocator.dupe(u8, "events.spool"),
        .config_path = try std.testing.allocator.dupe(u8, "config.toml"),
        .state_path = try std.testing.allocator.dupe(u8, "state.toml"),
    };
    defer cfg.deinit();

    try validate(&cfg);
    cfg.dns_interval_seconds = 0;
    try std.testing.expectError(error.InvalidCollectionInterval, validate(&cfg));
    cfg.dns_interval_seconds = 30;
    cfg.http_timeout_seconds = 301;
    try std.testing.expectError(error.InvalidHttpTimeout, validate(&cfg));
}

test "mutable state persists separately and overrides legacy credentials" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_path = try std.fs.path.join(
        std.testing.allocator,
        &.{ ".zig-cache", "tmp", &tmp.sub_path, "state.toml" },
    );
    defer std.testing.allocator.free(state_path);

    var saved = Config{
        .allocator = std.testing.allocator,
        .backend_url = try std.testing.allocator.dupe(u8, "https://tawny.example"),
        .spill_path = try std.testing.allocator.dupe(u8, "events.spool"),
        .config_path = try std.testing.allocator.dupe(u8, "config.toml"),
        .state_path = try std.testing.allocator.dupe(u8, state_path),
        .agent_id = try std.testing.allocator.dupe(u8, "new-id"),
        .agent_jwt = try std.testing.allocator.dupe(u8, "new-jwt"),
    };
    defer saved.deinit();
    try save(&saved);

    var loaded = Config{
        .allocator = std.testing.allocator,
        .backend_url = try std.testing.allocator.dupe(u8, "https://tawny.example"),
        .spill_path = try std.testing.allocator.dupe(u8, "events.spool"),
        .config_path = try std.testing.allocator.dupe(u8, "config.toml"),
        .state_path = try std.testing.allocator.dupe(u8, state_path),
        .agent_id = try std.testing.allocator.dupe(u8, "legacy-id"),
        .agent_jwt = try std.testing.allocator.dupe(u8, "legacy-jwt"),
    };
    defer loaded.deinit();
    try std.testing.expectEqual(StateSource.jwt_in_file, try loadState(&loaded));
    try std.testing.expectEqualStrings("new-id", loaded.agent_id.?);
    try std.testing.expectEqualStrings("new-jwt", loaded.agent_jwt.?);
}

test "stripEnrollmentToken removes only the token line" {
    const alloc = std.testing.allocator;
    const raw = "[agent]\nurl = \"https://tawny.example\"\n  enrollment_token = \"secret\"\n# enrollment_token = keep-comment\nheartbeat_interval_seconds = 60\n";
    const stripped = (try stripEnrollmentToken(alloc, raw)).?;
    defer alloc.free(stripped);
    try std.testing.expectEqualStrings(
        "[agent]\nurl = \"https://tawny.example\"\n# enrollment_token = keep-comment\nheartbeat_interval_seconds = 60\n",
        stripped,
    );
    try std.testing.expect((try stripEnrollmentToken(alloc, "url = \"x\"\n")) == null);
}

test "removeEnrollmentToken rewrites config atomically" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const config_path = try std.fs.path.join(alloc, &.{ ".zig-cache", "tmp", &tmp.sub_path, "config.toml" });
    defer alloc.free(config_path);
    const io = iox.current();
    {
        var file = try std.Io.Dir.cwd().createFile(io, config_path, .{
            .truncate = true,
            .permissions = if (builtin.target.os.tag == .windows) .default_file else @fromBackingInt(@intCast(0o640)),
        });
        defer file.close(io);
        try file.writePositionalAll(io, "url = \"https://tawny.example\"\nenrollment_token = \"tok\"\n", 0);
    }

    try std.testing.expect(try removeEnrollmentToken(alloc, config_path));
    try std.testing.expect(!try removeEnrollmentToken(alloc, config_path));

    const file = try std.Io.Dir.cwd().openFile(io, config_path, .{});
    defer file.close(io);
    const contents = try iox.readToEndAlloc(file, alloc, 4096);
    defer alloc.free(contents);
    try std.testing.expectEqualStrings("url = \"https://tawny.example\"\n", contents);
    if (builtin.target.os.tag != .windows) {
        const stat = try file.stat(io);
        try std.testing.expectEqual(@as(u32, 0o640), @as(u32, @intCast(@backingInt(stat.permissions) & 0o777)));
    }

    const tmp_path = try alloc.print("{s}.tmp", .{config_path});
    defer alloc.free(tmp_path);
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().openFile(io, tmp_path, .{}));
}

fn testConfig(alloc: std.mem.Allocator, state_path: []const u8, store: keystore.Store) !Config {
    return .{
        .allocator = alloc,
        .backend_url = try alloc.dupe(u8, "https://tawny.example"),
        .spill_path = try alloc.dupe(u8, "events.spool"),
        .config_path = try alloc.dupe(u8, "config.toml"),
        .state_path = try alloc.dupe(u8, state_path),
        .secret_store = store,
    };
}

fn readFileAlloc(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    const io = iox.current();
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    return iox.readToEndAlloc(file, alloc, 64 * 1024);
}

test "parseState and renderState round-trip with and without a JWT" {
    const alloc = std.testing.allocator;
    var out: std.Io.Writer.Allocating = .init(alloc);
    defer out.deinit();
    try renderState(&out.writer, "id-1", null);
    try std.testing.expectEqualStrings("[state]\nagent_id = \"id-1\"\n", out.written());

    var parsed = try parseState(alloc, out.written());
    defer parsed.deinit(alloc);
    try std.testing.expectEqualStrings("id-1", parsed.agent_id.?);
    try std.testing.expect(parsed.agent_jwt == null);

    out.clearRetainingCapacity();
    try renderState(&out.writer, "id-2", "a.b.c");
    var with_jwt = try parseState(alloc, out.written());
    defer with_jwt.deinit(alloc);
    try std.testing.expectEqualStrings("id-2", with_jwt.agent_id.?);
    try std.testing.expectEqualStrings("a.b.c", with_jwt.agent_jwt.?);

    var empty = try parseState(alloc, "# c\n[state]\nagent_id = \"x\"\nagent_jwt = \"\"\n");
    defer empty.deinit(alloc);
    try std.testing.expect(empty.agent_jwt == null);
}

test "save keeps the JWT out of state.toml when the keystore works" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_path = try std.fs.path.join(alloc, &.{ ".zig-cache", "tmp", &tmp.sub_path, "state.toml" });
    defer alloc.free(state_path);

    var vault = keystore.TestVault{ .alloc = alloc };
    defer vault.deinit();
    const store = keystore.Store{ .backend = .test_vault, .vault = &vault };

    var cfg = try testConfig(alloc, state_path, store);
    defer cfg.deinit();
    cfg.agent_id = try alloc.dupe(u8, "agent-1");
    cfg.agent_jwt = try alloc.dupe(u8, "jwt-1");
    try save(&cfg);

    const raw = try readFileAlloc(alloc, state_path);
    defer alloc.free(raw);
    try std.testing.expect(std.mem.indexOf(u8, raw, "jwt") == null);
    try std.testing.expectEqualStrings("jwt-1", vault.jwt.?);

    var loaded = try testConfig(alloc, state_path, store);
    defer loaded.deinit();
    try std.testing.expectEqual(StateSource.jwt_in_keystore, try loadState(&loaded));
    try std.testing.expectEqualStrings("agent-1", loaded.agent_id.?);
    try std.testing.expectEqualStrings("jwt-1", loaded.agent_jwt.?);

    // Keystore lost the JWT: load fails clearly instead of running without one.
    try store.delete(.agent_jwt);
    var orphan = try testConfig(alloc, state_path, store);
    defer orphan.deinit();
    try std.testing.expectError(error.IncompleteAgentState, loadState(&orphan));
}

test "keystore failure falls back to plaintext, which wins until migrated" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_path = try std.fs.path.join(alloc, &.{ ".zig-cache", "tmp", &tmp.sub_path, "state.toml" });
    defer alloc.free(state_path);
    const seed_path = try keystore.deviceSeedPath(alloc, state_path);
    defer alloc.free(seed_path);

    var vault = keystore.TestVault{ .alloc = alloc };
    defer vault.deinit();
    const store = keystore.Store{ .backend = .test_vault, .vault = &vault };

    var cfg = try testConfig(alloc, state_path, store);
    defer cfg.deinit();
    cfg.agent_id = try alloc.dupe(u8, "agent-1");
    cfg.agent_jwt = try alloc.dupe(u8, "jwt-old");
    try save(&cfg); // keystore now holds jwt-old

    // Rotation while the keystore is failing: plaintext fallback.
    vault.fail_puts = true;
    alloc.free(cfg.agent_jwt.?);
    cfg.agent_jwt = try alloc.dupe(u8, "jwt-new");
    try save(&cfg);
    try std.testing.expectEqualStrings("jwt-old", vault.jwt.?);

    // Legacy plaintext seed file alongside.
    const seed: keystore.Seed = @splat(3);
    try keystore.writeSecretFile(seed_path, &seed);

    // The newer plaintext JWT wins over the stale keystore copy.
    var loaded = try testConfig(alloc, state_path, store);
    defer loaded.deinit();
    try std.testing.expectEqual(StateSource.jwt_in_file, try loadState(&loaded));
    try std.testing.expectEqualStrings("jwt-new", loaded.agent_jwt.?);

    // Migration while still failing changes nothing.
    migrateSecrets(&loaded, true);
    {
        const raw = try readFileAlloc(alloc, state_path);
        defer alloc.free(raw);
        try std.testing.expect(std.mem.indexOf(u8, raw, "jwt-new") != null);
        try std.testing.expect(try keystore.loadDeviceSeed(alloc, .{}, seed_path) != null);
    }

    // Keystore back: migration moves both secrets and strips the plaintext.
    vault.fail_puts = false;
    migrateSecrets(&loaded, true);
    try std.testing.expectEqualStrings("jwt-new", vault.jwt.?);
    try std.testing.expectEqualSlices(u8, &seed, vault.seed.?);
    {
        const raw = try readFileAlloc(alloc, state_path);
        defer alloc.free(raw);
        try std.testing.expectEqualStrings("[state]\nagent_id = \"agent-1\"\n", raw);
        try std.testing.expect(try keystore.loadDeviceSeed(alloc, .{}, seed_path) == null);
    }
}

test "migration keeps plaintext when keystore read-back does not match" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_path = try std.fs.path.join(alloc, &.{ ".zig-cache", "tmp", &tmp.sub_path, "state.toml" });
    defer alloc.free(state_path);

    var vault = keystore.TestVault{ .alloc = alloc, .corrupt_reads = true };
    defer vault.deinit();
    const store = keystore.Store{ .backend = .test_vault, .vault = &vault };

    var cfg = try testConfig(alloc, state_path, .{});
    defer cfg.deinit();
    cfg.agent_id = try alloc.dupe(u8, "agent-1");
    cfg.agent_jwt = try alloc.dupe(u8, "jwt-1");
    try save(&cfg); // file backend: JWT in state.toml

    cfg.secret_store = store;
    migrateSecrets(&cfg, true);
    const raw = try readFileAlloc(alloc, state_path);
    defer alloc.free(raw);
    try std.testing.expect(std.mem.indexOf(u8, raw, "jwt-1") != null);
}

test "exportCredentials moves secrets back to plaintext and empties the keystore" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_path = try std.fs.path.join(alloc, &.{ ".zig-cache", "tmp", &tmp.sub_path, "state.toml" });
    defer alloc.free(state_path);
    const seed_path = try keystore.deviceSeedPath(alloc, state_path);
    defer alloc.free(seed_path);

    var vault = keystore.TestVault{ .alloc = alloc };
    defer vault.deinit();
    const store = keystore.Store{ .backend = .test_vault, .vault = &vault };

    var cfg = try testConfig(alloc, state_path, store);
    defer cfg.deinit();
    cfg.agent_id = try alloc.dupe(u8, "agent-1");
    cfg.agent_jwt = try alloc.dupe(u8, "jwt-1");
    try save(&cfg);
    const seed = try keystore.createDeviceSeed(alloc, store, seed_path);

    try exportCredentials(&cfg);
    try std.testing.expect(vault.jwt == null and vault.seed == null);

    var file_only = try testConfig(alloc, state_path, .{});
    defer file_only.deinit();
    try std.testing.expectEqual(StateSource.jwt_in_file, try loadState(&file_only));
    try std.testing.expectEqualStrings("jwt-1", file_only.agent_jwt.?);
    try std.testing.expectEqualSlices(u8, &seed, &(try keystore.loadDeviceSeed(alloc, .{}, seed_path)).?);
}

test "macOS login keychain migration end to end" {
    if (builtin.target.os.tag != .macos) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_path = try std.fs.path.join(alloc, &.{ ".zig-cache", "tmp", &tmp.sub_path, "state.toml" });
    defer alloc.free(state_path);
    const seed_path = try keystore.deviceSeedPath(alloc, state_path);
    defer alloc.free(seed_path);

    var rnd: [8]u8 = undefined;
    std.Io.random(iox.current(), &rnd);
    var service_buf: [64]u8 = undefined;
    const service = try std.fmt.bufPrint(&service_buf, "dev.jusso.tawny-agent.test.{x}", .{rnd});
    // Login keychain only; tests never touch the System keychain.
    const store = keystore.Store{ .backend = .macos_user_keychain, .service = service };
    defer store.delete(.agent_jwt) catch {};
    defer store.delete(.device_seed) catch {};
    store.putVerified(alloc, .agent_jwt, "probe") catch |err| switch (err) {
        error.InteractionNotAllowed, error.KeystoreUnavailable => return error.SkipZigTest,
        else => return err,
    };
    try store.delete(.agent_jwt);

    // Legacy layout: JWT in state.toml, raw seed file.
    var cfg = try testConfig(alloc, state_path, .{});
    defer cfg.deinit();
    cfg.agent_id = try alloc.dupe(u8, "agent-mac");
    cfg.agent_jwt = try alloc.dupe(u8, "header.payload.sig");
    try save(&cfg);
    const seed: keystore.Seed = @splat(0x5a);
    try keystore.writeSecretFile(seed_path, &seed);

    cfg.secret_store = store;
    migrateSecrets(&cfg, true);

    const raw = try readFileAlloc(alloc, state_path);
    defer alloc.free(raw);
    try std.testing.expectEqualStrings("[state]\nagent_id = \"agent-mac\"\n", raw);
    try std.testing.expect(try keystore.loadDeviceSeed(alloc, .{}, seed_path) == null);

    var loaded = try testConfig(alloc, state_path, store);
    defer loaded.deinit();
    try std.testing.expectEqual(StateSource.jwt_in_keystore, try loadState(&loaded));
    try std.testing.expectEqualStrings("header.payload.sig", loaded.agent_jwt.?);
    try std.testing.expectEqualSlices(u8, &seed, &(try keystore.loadDeviceSeed(alloc, store, seed_path)).?);

    try exportCredentials(&loaded);
    try std.testing.expect((try store.get(alloc, .agent_jwt)) == null);
    try std.testing.expect((try store.get(alloc, .device_seed)) == null);
}
