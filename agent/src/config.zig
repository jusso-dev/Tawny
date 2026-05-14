const std = @import("std");
const builtin = @import("builtin");

pub const Config = struct {
    allocator: std.mem.Allocator,
    backend_url: []u8,
    enrollment_token: ?[]u8 = null,
    agent_id: ?[]u8 = null,
    agent_jwt: ?[]u8 = null,
    heartbeat_interval_seconds: u32 = 60,
    process_interval_seconds: u32 = 30,
    network_interval_seconds: u32 = 30,
    users_interval_seconds: u32 = 300,
    system_interval_seconds: u32 = 3600,
    fim_interval_seconds: u32 = 300,
    max_in_memory_events: usize = 1000,
    fim_paths: [][]u8 = &.{},
    spill_path: []u8,
    config_path: []u8,

    pub fn deinit(self: *Config) void {
        self.allocator.free(self.backend_url);
        self.allocator.free(self.spill_path);
        self.allocator.free(self.config_path);
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
        const programdata = std.process.getEnvVarOwned(alloc, "PROGRAMDATA") catch
            try alloc.dupe(u8, "C:\\ProgramData");
        defer alloc.free(programdata);
        return std.fmt.allocPrint(alloc, "{s}\\Tawny\\config.toml", .{programdata});
    }
    return alloc.dupe(u8, "/Library/Application Support/Tawny/config.toml");
}

/// Read TOML-ish config. Trivial line-based parser — good enough for MVP.
pub fn load(alloc: std.mem.Allocator) !Config {
    const env_path = std.process.getEnvVarOwned(alloc, "TAWNY_CONFIG") catch null;
    const path: []u8 = if (env_path) |p| p else try defaultConfigPath(alloc);

    var cfg = Config{
        .allocator = alloc,
        .backend_url = try alloc.dupe(u8, "http://localhost:5080"),
        .spill_path = try std.fmt.allocPrint(alloc, "{s}.spool", .{path}),
        .config_path = path,
    };

    const file = std.fs.cwd().openFile(path, .{}) catch {
        // First run: emit a default config alongside the binary.
        return cfg;
    };
    defer file.close();

    const raw = try file.readToEndAlloc(alloc, 64 * 1024);
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
            cfg.enrollment_token = try alloc.dupe(u8, val);
        } else if (std.mem.eql(u8, key, "agent_id")) {
            cfg.agent_id = try alloc.dupe(u8, val);
        } else if (std.mem.eql(u8, key, "agent_jwt")) {
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
        } else if (std.mem.eql(u8, key, "max_in_memory_events")) {
            cfg.max_in_memory_events = try std.fmt.parseInt(usize, val, 10);
        } else if (std.mem.eql(u8, key, "spill_path")) {
            alloc.free(cfg.spill_path);
            cfg.spill_path = try alloc.dupe(u8, val);
        } else if (std.mem.eql(u8, key, "fim_path")) {
            try appendFimPath(&cfg, val);
        } else if (std.mem.eql(u8, key, "fim_paths")) {
            try appendFimPaths(&cfg, val);
        }
    }

    return cfg;
}

pub fn save(cfg: *const Config) !void {
    // Best-effort write; create parent dirs as needed.
    const dir = std.fs.path.dirname(cfg.config_path) orelse ".";
    std.fs.cwd().makePath(dir) catch {};

    const tmp_path = try std.fmt.allocPrint(cfg.allocator, "{s}.tmp", .{cfg.config_path});
    defer cfg.allocator.free(tmp_path);

    {
        var file = try std.fs.cwd().createFile(tmp_path, .{ .truncate = true });
        defer file.close();
        var w = file.writer();

        try w.print("[backend]\nurl = \"{s}\"\n\n", .{cfg.backend_url});
        if (cfg.agent_id) |id| try w.print("agent_id = \"{s}\"\n", .{id});
        if (cfg.agent_jwt) |j| try w.print("agent_jwt = \"{s}\"\n", .{j});

        try w.print(
            \\
            \\[collection]
            \\heartbeat_interval_seconds = {d}
            \\process_interval_seconds = {d}
            \\network_interval_seconds = {d}
            \\users_interval_seconds = {d}
            \\system_interval_seconds = {d}
            \\fim_interval_seconds = {d}
            \\max_in_memory_events = {d}
            \\spill_path =
        , .{
            cfg.heartbeat_interval_seconds,
            cfg.process_interval_seconds,
            cfg.network_interval_seconds,
            cfg.users_interval_seconds,
            cfg.system_interval_seconds,
            cfg.fim_interval_seconds,
            cfg.max_in_memory_events,
        });
        try w.writeByte(' ');
        try std.json.stringify(cfg.spill_path, .{}, w);
        try w.writeAll("\nfim_paths = [");

        for (cfg.fim_paths, 0..) |path, i| {
            if (i > 0) try w.writeAll(", ");
            try std.json.stringify(path, .{}, w);
        }
        try w.writeAll("]\n");
        try file.sync();
    }

    std.fs.cwd().rename(tmp_path, cfg.config_path) catch |err| switch (err) {
        error.PathAlreadyExists => {
            std.fs.cwd().deleteFile(cfg.config_path) catch {};
            try std.fs.cwd().rename(tmp_path, cfg.config_path);
        },
        else => return err,
    };
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
