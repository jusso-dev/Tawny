const std = @import("std");

pub const Config = struct {
    database_url: []u8,
    http_host: []u8,
    http_port: u16,
    apply_migrations: bool,
    ai_enabled: bool,
    ai_model_endpoint: []u8,
    ai_model_name: []u8,
    ai_model_api_key: []u8,
    ai_confidence_threshold: f32,
    ai_allow_private_egress: bool,

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
        const ai_enabled_text = try envOr(allocator, env, "TAWNY_AI_ENABLED", "false");
        defer allocator.free(ai_enabled_text);
        const ai_model_endpoint = try envOr(allocator, env, "TAWNY_AI_MODEL_ENDPOINT", "http://localhost:11434/v1");
        errdefer allocator.free(ai_model_endpoint);
        const ai_model_name = try envOr(allocator, env, "TAWNY_AI_MODEL_NAME", "qwen2.5:7b-instruct");
        errdefer allocator.free(ai_model_name);
        const ai_model_api_key = try envOr(allocator, env, "TAWNY_AI_MODEL_API_KEY", "");
        errdefer allocator.free(ai_model_api_key);
        const ai_conf_text = try envOr(allocator, env, "TAWNY_AI_CONFIDENCE_THRESHOLD", "0.70");
        defer allocator.free(ai_conf_text);
        const ai_confidence_threshold: f32 = std.fmt.parseFloat(f32, ai_conf_text) catch 0.70;
        const ai_private_text = try envOr(allocator, env, "TAWNY_AI_ALLOW_PRIVATE_EGRESS", "true");
        defer allocator.free(ai_private_text);
        return .{
            .database_url = database_url,
            .http_host = http_host,
            .http_port = http_port,
            .apply_migrations = std.mem.eql(u8, apply_text, "true") or std.mem.eql(u8, apply_text, "1"),
            .ai_enabled = std.mem.eql(u8, ai_enabled_text, "true") or std.mem.eql(u8, ai_enabled_text, "1"),
            .ai_model_endpoint = ai_model_endpoint,
            .ai_model_name = ai_model_name,
            .ai_model_api_key = ai_model_api_key,
            .ai_confidence_threshold = ai_confidence_threshold,
            .ai_allow_private_egress = std.mem.eql(u8, ai_private_text, "true") or std.mem.eql(u8, ai_private_text, "1"),
        };
    }

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        allocator.free(self.database_url);
        allocator.free(self.http_host);
        allocator.free(self.ai_model_endpoint);
        allocator.free(self.ai_model_name);
        allocator.free(self.ai_model_api_key);
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
