const std = @import("std");
const builtin = @import("builtin");
const env = @import("env.zig");
const iox = @import("io_compat.zig");

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
    if (builtin.os.tag == .windows) {
        const programdata = env.getEnvVarOwned(alloc, "PROGRAMDATA") catch
            try alloc.dupe(u8, "C:\\ProgramData");
        defer alloc.free(programdata);
        return std.fmt.allocPrint(alloc, "{s}\\Tawny\\config.toml", .{programdata});
    }
    if (builtin.os.tag == .linux) {
        return alloc.dupe(u8, "/etc/tawny/config.toml");
    }
    return alloc.dupe(u8, "/Library/Application Support/Tawny/config.toml");
}

/// Read TOML-ish config. Trivial line-based parser — good enough for MVP.
pub fn load(alloc: std.mem.Allocator) !Config {
    const env_path = env.getEnvVarOwned(alloc, "TAWNY_CONFIG") catch null;
    const path: []u8 = if (env_path) |p| p else try defaultConfigPath(alloc);
    const env_state_path = env.getEnvVarOwned(alloc, "TAWNY_STATE_PATH") catch null;

    var cfg = Config{
        .allocator = alloc,
        .backend_url = try alloc.dupe(u8, "http://localhost:5080"),
        .spill_path = try std.fmt.allocPrint(alloc, "{s}.spool", .{path}),
        .config_path = path,
        .state_path = if (env_state_path) |p| p else try std.fmt.allocPrint(alloc, "{s}.state", .{path}),
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
    const state_loaded = try loadState(&cfg);
    if (!state_loaded and cfg.agent_id != null and cfg.agent_jwt != null) {
        // One-time migration from legacy config files which stored mutable
        // credentials beside static settings.
        try save(&cfg);
    }
    return cfg;
}

/// Atomically persist mutable enrollment state outside read-only static config.
pub fn save(cfg: *const Config) !void {
    if (cfg.agent_id == null or cfg.agent_jwt == null) return error.IncompleteAgentState;
    const dir = std.fs.path.dirname(cfg.state_path) orelse ".";
    const io = iox.current();
    try std.Io.Dir.cwd().createDirPath(io, dir);

    const tmp_path = try std.fmt.allocPrint(cfg.allocator, "{s}.tmp", .{cfg.state_path});
    defer cfg.allocator.free(tmp_path);

    {
        var file = try std.Io.Dir.cwd().createFile(io, tmp_path, .{
            .truncate = true,
            .permissions = if (builtin.os.tag == .windows) .default_file else @enumFromInt(0o600),
        });
        defer file.close(io);
        var writer_buffer: [4096]u8 = undefined;
        var file_writer = file.writer(io, &writer_buffer);
        const w = &file_writer.interface;

        try w.writeAll("[state]\nagent_id = ");
        try std.json.Stringify.value(cfg.agent_id.?, .{}, w);
        try w.writeAll("\nagent_jwt = ");
        try std.json.Stringify.value(cfg.agent_jwt.?, .{}, w);
        try w.writeByte('\n');
        try w.flush();
        try file.sync(io);
    }

    try std.Io.Dir.cwd().rename(tmp_path, std.Io.Dir.cwd(), cfg.state_path, io);
    try syncParentDirectory(cfg.state_path);
}

fn syncParentDirectory(path: []const u8) !void {
    if (builtin.os.tag != .linux) return;
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

fn loadState(cfg: *Config) !bool {
    const io = iox.current();
    const file = std.Io.Dir.cwd().openFile(io, cfg.state_path, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer file.close(io);

    const raw = try iox.readToEndAlloc(file, cfg.allocator, 64 * 1024);
    defer cfg.allocator.free(raw);

    var state_id: ?[]u8 = null;
    errdefer if (state_id) |value| cfg.allocator.free(value);
    var state_jwt: ?[]u8 = null;
    errdefer if (state_jwt) |value| cfg.allocator.free(value);

    var line_iter = std.mem.splitScalar(u8, raw, '\n');
    while (line_iter.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0 or line[0] == '#' or line[0] == '[') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const val = std.mem.trim(u8, line[eq + 1 ..], " \t\"");
        if (std.mem.eql(u8, key, "agent_id")) {
            if (state_id) |old| cfg.allocator.free(old);
            state_id = try cfg.allocator.dupe(u8, val);
        } else if (std.mem.eql(u8, key, "agent_jwt")) {
            if (state_jwt) |old| cfg.allocator.free(old);
            state_jwt = try cfg.allocator.dupe(u8, val);
        }
    }
    if (state_id == null or state_jwt == null or state_id.?.len == 0 or state_jwt.?.len == 0) {
        return error.IncompleteAgentState;
    }

    if (cfg.agent_id) |old| cfg.allocator.free(old);
    if (cfg.agent_jwt) |old| cfg.allocator.free(old);
    cfg.agent_id = state_id;
    cfg.agent_jwt = state_jwt;
    return true;
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
    try std.testing.expect(try loadState(&loaded));
    try std.testing.expectEqualStrings("new-id", loaded.agent_id.?);
    try std.testing.expectEqualStrings("new-jwt", loaded.agent_jwt.?);
}
