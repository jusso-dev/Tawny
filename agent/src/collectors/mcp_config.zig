const std = @import("std");
const env = @import("../env.zig");
const iox = @import("../io_compat.zig");

/// MCP server-config scanner inspired by Perplexity's Bumblebee.
///
/// MCP configs live in well-known JSON files (mcp.json, claude_desktop_config.json,
/// cline_mcp_settings.json, etc.) and define which MCP servers a developer's
/// LLM client has wired up. Each server entry usually carries:
///   - a command/args (stdio transport), or
///   - a URL (sse/http transport),
///   - an `env` object with provider credentials / API keys.
///
/// Bumblebee's privacy stance, which we adopt verbatim:
///   1. We do NOT capture `env` *values*. We may emit the *names* of declared
///      env keys because they identify the server's secret-shape, but never
///      the values themselves.
///   2. URLs are sanitized to `scheme://host` before emission. Userinfo
///      (user:pass@), query, fragment, and path are all stripped so embedded
///      credentials cannot leak.
pub const Scanner = struct {
    allocator: std.mem.Allocator,
    /// Tests point this at a fixture root. Production leaves it null and scans $HOME.
    home_override: ?[]const u8 = null,

    pub fn init(alloc: std.mem.Allocator) Scanner {
        return .{ .allocator = alloc };
    }

    pub fn collectConfigs(self: *Scanner) ![][]u8 {
        var payloads: std.array_list.Managed([]u8) = .init(self.allocator);
        errdefer {
            for (payloads.items) |p| self.allocator.free(p);
            payloads.deinit();
        }

        const home = if (self.home_override) |override|
            try self.allocator.dupe(u8, override)
        else
            env.getEnvVarOwned(self.allocator, "HOME") catch try self.allocator.dupe(u8, "/");
        defer self.allocator.free(home);

        // Per Bumblebee's documented MCP file paths. Relative to $HOME only;
        // do not walk the home tree.
        const candidates = [_][]const u8{
            ".config/claude/claude_desktop_config.json",
            ".config/Claude/claude_desktop_config.json",
            "Library/Application Support/Claude/claude_desktop_config.json",
            ".cursor/mcp.json",
            ".vscode/mcp.json",
            ".vscode-server/mcp.json",
            ".windsurf/mcp.json",
            ".cline/cline_mcp_settings.json",
            ".config/cline/cline_mcp_settings.json",
            ".mcp.json",
            "mcp.json",
            "mcp_config.json",
            "mcp_settings.json",
        };
        for (candidates) |sub| {
            const path = std.fs.path.join(self.allocator, &.{ home, sub }) catch continue;
            defer self.allocator.free(path);
            self.parseConfigFile(path, &payloads) catch continue;
        }
        return payloads.toOwnedSlice();
    }

    fn parseConfigFile(self: *Scanner, path: []const u8, payloads: *std.array_list.Managed([]u8)) !void {
        if (!std.fs.path.isAbsolute(path)) return;
        const io = iox.current();
        var file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch return;
        defer file.close(io);
        const body = iox.readToEndAlloc(file, self.allocator, 1 * 1024 * 1024) catch return;
        defer self.allocator.free(body);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, body, .{}) catch return;
        defer parsed.deinit();
        if (parsed.value != .object) return;

        // Most clients put servers under "mcpServers"; cline uses
        // "cline_mcp_settings" → "servers"; some use "servers" directly.
        const containers = [_][]const u8{ "mcpServers", "servers" };
        for (containers) |key| {
            const servers = parsed.value.object.get(key) orelse continue;
            if (servers != .object) continue;
            var it = servers.object.iterator();
            while (it.next()) |kv| {
                if (kv.value_ptr.* != .object) continue;
                const payload = try self.emitServer(path, kv.key_ptr.*, kv.value_ptr.*.object);
                try payloads.append(payload);
            }
        }
    }

    fn emitServer(self: *Scanner, source_path: []const u8, server_name: []const u8, server_obj: std.json.ObjectMap) ![]u8 {
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        errdefer out.deinit();
        const w = &out.writer;
        try w.writeAll("{\"ecosystem\":\"mcp\",\"name\":");
        try std.json.Stringify.value(server_name, .{}, w);

        // Server identity. We surface enough to know what's wired up, never
        // enough to repro the trust path or steal credentials.
        const command = server_obj.get("command");
        const args = server_obj.get("args");
        const url = server_obj.get("url");

        var transport: []const u8 = "unknown";
        if (command != null and command.? == .string) transport = "stdio";
        if (url != null and url.? == .string) transport = "http";
        try w.writeAll(",\"transport\":");
        try std.json.Stringify.value(transport, .{}, w);

        if (command != null and command.? == .string) {
            try w.writeAll(",\"command\":");
            try std.json.Stringify.value(command.?.string, .{}, w);
        }
        if (args != null and args.? == .array) {
            try w.writeAll(",\"arg_count\":");
            try w.print("{d}", .{args.?.array.items.len});
        }
        if (url != null and url.? == .string) {
            const sanitized = sanitizeUrl(self.allocator, url.?.string) catch try self.allocator.dupe(u8, "");
            defer self.allocator.free(sanitized);
            try w.writeAll(",\"requested_spec\":");
            try std.json.Stringify.value(sanitized, .{}, w);
        }

        // PRIVACY: declared env *keys* only — never the values. This matches
        // Bumblebee's "Environment values and environment key names are never
        // captured" stance for values, and we additionally elide the names by
        // emitting only the *count* by default. Operators who need the names
        // for inventory reconciliation can flip a future config switch.
        if (server_obj.get("env")) |env_val| {
            if (env_val == .object) {
                try w.writeAll(",\"env_var_count\":");
                try w.print("{d}", .{env_val.object.count()});
            }
        }

        // Version is unknown for MCP servers from raw configs. We use the
        // hash of the source-path + name as a synthetic version so the
        // PackageExposure rule shape (which expects a version) still works
        // for matching. Real version tracking would require running the
        // server, which violates the read-only stance.
        try w.writeAll(",\"version\":\"configured\"");
        try w.writeAll(",\"confidence\":\"low\"");
        try w.writeAll(",\"source_path\":");
        try std.json.Stringify.value(source_path, .{}, w);
        try w.writeByte('}');
        return out.toOwnedSlice();
    }
};

/// Strip everything from a URL except scheme://host so credentials (in
/// userinfo, query, path, fragment) never leave the host.
fn sanitizeUrl(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    const scheme_end = std.mem.indexOf(u8, raw, "://") orelse return alloc.dupe(u8, "");
    const scheme = raw[0..scheme_end];
    const authority_and_path = raw[scheme_end + 3 ..];
    // Strip path/query/fragment.
    const path_idx = std.mem.indexOfAny(u8, authority_and_path, "/?#") orelse authority_and_path.len;
    var authority = authority_and_path[0..path_idx];
    // Strip userinfo (everything before the first @ before any host port).
    if (std.mem.indexOfScalar(u8, authority, '@')) |at_idx| {
        authority = authority[at_idx + 1 ..];
    }
    return alloc.print("{s}://{s}", .{ scheme, authority });
}

test "sanitize url strips creds" {
    const out = try sanitizeUrl(std.testing.allocator, "https://user:pass@mcp.example.com:8443/api?token=abc#x");
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("https://mcp.example.com:8443", out);
}

test "scanner module loads" {
    var s = Scanner.init(std.testing.allocator);
    _ = &s;
}

test "config fixture emits a sanitized server and drops env values" {
    const alloc = std.testing.allocator;
    const io = iox.current();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, ".cursor");
    try tmp.dir.writeFile(io, .{
        .sub_path = ".cursor/mcp.json",
        .data = "{\"mcpServers\":{\"demo\":{\"command\":\"npx\",\"args\":[\"-y\",\"srv\"],\"url\":\"https://user:pass@mcp.example.com:8443/api?token=abc#x\",\"env\":{\"API_KEY\":\"super-secret-value\"}}}}",
    });

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(io, &path_buf);
    var scanner = Scanner.init(alloc);
    scanner.home_override = path_buf[0..n];

    const payloads = try scanner.collectConfigs();
    defer {
        for (payloads) |payload| alloc.free(payload);
        alloc.free(payloads);
    }
    try std.testing.expectEqual(@as(usize, 1), payloads.len);
    const payload = payloads[0];
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"ecosystem\":\"mcp\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"name\":\"demo\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"command\":\"npx\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"arg_count\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"env_var_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "https://mcp.example.com:8443") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "super-secret-value") == null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "API_KEY") == null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "user:pass") == null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "token=abc") == null);
}
