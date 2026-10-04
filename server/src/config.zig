const std = @import("std");

pub const Config = struct {
    database_url: []u8,
    http_host: []u8,
    http_port: u16,
    apply_migrations: bool,

    pub fn load(allocator: std.mem.Allocator, env: *std.process.Environ.Map) !Config {
        const database_url = try envRequired(allocator, env, "TAWNY_DATABASE_URL");
        errdefer allocator.free(database_url);
        const http_host = try envOr(allocator, env, "TAWNY_HTTP_HOST", "0.0.0.0");
        errdefer allocator.free(http_host);
        const port_text = try envOr(allocator, env, "TAWNY_HTTP_PORT", "8080");
        defer allocator.free(port_text);
        const http_port = std.fmt.parseInt(u16, port_text, 10) catch return error.BadPort;
        const apply_text = try envOr(allocator, env, "TAWNY_APPLY_MIGRATIONS_ON_STARTUP", "true");
        defer allocator.free(apply_text);
        return .{
            .database_url = database_url,
            .http_host = http_host,
            .http_port = http_port,
            .apply_migrations = std.mem.eql(u8, apply_text, "true") or std.mem.eql(u8, apply_text, "1"),
        };
    }

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        allocator.free(self.database_url);
        allocator.free(self.http_host);
    }
};

fn envRequired(allocator: std.mem.Allocator, env: *std.process.Environ.Map, name: []const u8) ![]u8 {
    const value = env.get(name) orelse return error.MissingEnv;
    if (value.len == 0) return error.MissingEnv;
    return allocator.dupe(u8, value);
}

fn envOr(allocator: std.mem.Allocator, env: *std.process.Environ.Map, name: []const u8, fallback: []const u8) ![]u8 {
    const value = env.get(name);
    if (value == null or value.?.len == 0) return allocator.dupe(u8, fallback);
    return allocator.dupe(u8, value.?);
}
