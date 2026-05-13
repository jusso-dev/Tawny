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
    max_in_memory_events: usize = 1000,
    config_path: []u8,

    pub fn deinit(self: *Config) void {
        self.allocator.free(self.backend_url);
        self.allocator.free(self.config_path);
        if (self.enrollment_token) |t| self.allocator.free(t);
        if (self.agent_id) |t| self.allocator.free(t);
        if (self.agent_jwt) |t| self.allocator.free(t);
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
        }
    }

    return cfg;
}

pub fn save(cfg: *const Config) !void {
    // Best-effort write; create parent dirs as needed.
    const dir = std.fs.path.dirname(cfg.config_path) orelse ".";
    std.fs.cwd().makePath(dir) catch {};

    var file = try std.fs.cwd().createFile(cfg.config_path, .{ .truncate = true });
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
        \\
    , .{
        cfg.heartbeat_interval_seconds,
        cfg.process_interval_seconds,
        cfg.network_interval_seconds,
    });
}

test "default config path" {
    const alloc = std.testing.allocator;
    const p = try defaultConfigPath(alloc);
    defer alloc.free(p);
    try std.testing.expect(p.len > 0);
}
