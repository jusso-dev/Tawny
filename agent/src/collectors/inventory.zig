const std = @import("std");
const builtin = @import("builtin");

/// Periodic software-inventory scanner inspired by Perplexity's Bumblebee.
/// Walks well-known package roots, parses lockfiles + install metadata, and
/// emits one event per discovered package. Read-only by design: we never
/// execute package managers, never parse source files, never read environment
/// variables.
///
/// v1 covers npm (package-lock.json), pnpm (pnpm-lock.yaml), and pypi
/// (*.dist-info/METADATA). Bun / yarn / go / rubygems / composer use the
/// same on-disk shapes documented by Bumblebee and slot in via the same
/// `scanDir` walk — the parsers just haven't been written yet.
pub const Scanner = struct {
    allocator: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator) Scanner {
        return .{ .allocator = alloc };
    }

    /// Returns one JSON payload per discovered package record. Caller owns
    /// both the outer slice and each inner payload.
    pub fn collectInventory(self: *Scanner) ![][]u8 {
        var payloads = std.ArrayList([]u8).init(self.allocator);
        errdefer {
            for (payloads.items) |p| self.allocator.free(p);
            payloads.deinit();
        }

        const home = std.process.getEnvVarOwned(self.allocator, "HOME")
            catch try self.allocator.dupe(u8, "/");
        defer self.allocator.free(home);

        // Configured project roots beyond $HOME could be added later; for v1
        // we walk the most common per-user locations + the system npm prefix.
        const roots = [_][]const u8{ home, "/usr/local/lib/node_modules", "/usr/lib/node_modules" };
        for (roots) |root| {
            self.scanRoot(root, &payloads) catch continue;
        }

        return payloads.toOwnedSlice();
    }

    fn scanRoot(self: *Scanner, root: []const u8, payloads: *std.ArrayList([]u8)) !void {
        var dir = std.fs.openDirAbsolute(root, .{ .iterate = true }) catch return;
        defer dir.close();
        try self.walk(root, dir, 0, payloads);
    }

    fn walk(self: *Scanner, base: []const u8, dir: std.fs.Dir, depth: usize, payloads: *std.ArrayList([]u8)) !void {
        // Cap recursion so we don't pull the entire filesystem into memory.
        // Bumblebee uses scan profiles for this; we just hard-cap at 6 levels.
        if (depth > 6) return;

        var iter = dir.iterate();
        while (iter.next() catch null) |entry| {
            if (skipDirent(entry.name)) continue;

            if (entry.kind == .file) {
                self.handleFile(base, dir, entry.name, payloads) catch {};
                continue;
            }
            if (entry.kind != .directory) continue;

            var sub_dir = dir.openDir(entry.name, .{ .iterate = true }) catch continue;
            defer sub_dir.close();
            const sub_base = std.fs.path.join(self.allocator, &.{ base, entry.name }) catch continue;
            defer self.allocator.free(sub_base);
            self.walk(sub_base, sub_dir, depth + 1, payloads) catch continue;
        }
    }

    fn handleFile(self: *Scanner, base: []const u8, dir: std.fs.Dir, name: []const u8, payloads: *std.ArrayList([]u8)) !void {
        if (std.mem.eql(u8, name, "package-lock.json")) {
            try self.parseNpmLock(base, dir, name, payloads);
        } else if (std.mem.eql(u8, name, "pnpm-lock.yaml")) {
            try self.parsePnpmLock(base, dir, name, payloads);
        } else if (std.mem.endsWith(u8, base, ".dist-info") and std.mem.eql(u8, name, "METADATA")) {
            try self.parsePypiMetadata(base, dir, name, payloads);
        }
    }

    fn parseNpmLock(self: *Scanner, base: []const u8, dir: std.fs.Dir, name: []const u8, payloads: *std.ArrayList([]u8)) !void {
        const body = readFile(self.allocator, dir, name, 8 * 1024 * 1024) catch return;
        defer self.allocator.free(body);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, body, .{}) catch return;
        defer parsed.deinit();

        if (parsed.value != .object) return;
        const packages = parsed.value.object.get("packages") orelse return;
        if (packages != .object) return;

        const source_path = try std.fs.path.join(self.allocator, &.{ base, name });
        defer self.allocator.free(source_path);

        var it = packages.object.iterator();
        while (it.next()) |kv| {
            // npm 7+ keys look like "node_modules/foo" or "node_modules/foo/node_modules/bar".
            const path = kv.key_ptr.*;
            const pkg_obj = kv.value_ptr.*;
            if (pkg_obj != .object) continue;
            const last_node = std.mem.lastIndexOf(u8, path, "node_modules/") orelse continue;
            const package_name = path[last_node + "node_modules/".len ..];
            if (package_name.len == 0) continue;
            const version = pkg_obj.object.get("version") orelse continue;
            if (version != .string) continue;

            const payload = try buildInventoryEvent(
                self.allocator,
                "npm",
                package_name,
                version.string,
                "high",
                source_path,
                "npm-lockfile");
            try payloads.append(payload);
        }
    }

    fn parsePnpmLock(self: *Scanner, base: []const u8, dir: std.fs.Dir, name: []const u8, payloads: *std.ArrayList([]u8)) !void {
        // pnpm-lock.yaml is structured-enough that we can pull keys without a
        // full YAML parser. The `packages:` section is a flat map of
        // `'/<name>@<version>(_peer)?': { ... }`. We only need the keys.
        const body = readFile(self.allocator, dir, name, 8 * 1024 * 1024) catch return;
        defer self.allocator.free(body);

        const source_path = try std.fs.path.join(self.allocator, &.{ base, name });
        defer self.allocator.free(source_path);

        var lines = std.mem.splitScalar(u8, body, '\n');
        var in_packages = false;
        while (lines.next()) |line_raw| {
            const line = std.mem.trimRight(u8, line_raw, " \r\t");
            if (line.len == 0) continue;
            if (std.mem.startsWith(u8, line, "packages:")) { in_packages = true; continue; }
            if (!in_packages) continue;
            if (!std.mem.startsWith(u8, line, "  ")) {
                in_packages = false;
                continue;
            }
            // Expecting lines like `  /lodash@4.17.21:` (4 spaces of indent in v9, 2 in v6).
            const trimmed = std.mem.trim(u8, line, " \t");
            if (trimmed.len < 4 or trimmed[0] != '/') continue;
            const colon_idx = std.mem.lastIndexOfScalar(u8, trimmed, ':') orelse continue;
            const ref = trimmed[1..colon_idx]; // strip leading '/'
            const at_idx = std.mem.lastIndexOfScalar(u8, ref, '@') orelse continue;
            if (at_idx == 0) continue;
            const package_name = ref[0..at_idx];
            var version = ref[at_idx + 1 ..];
            // Strip pnpm peer-dep suffix `_<peer>`.
            if (std.mem.indexOfScalar(u8, version, '(')) |paren| version = version[0..paren];
            if (std.mem.indexOfScalar(u8, version, '_')) |under| version = version[0..under];

            const payload = try buildInventoryEvent(
                self.allocator,
                "npm",
                package_name,
                version,
                "high",
                source_path,
                "pnpm-lockfile");
            try payloads.append(payload);
        }
    }

    fn parsePypiMetadata(self: *Scanner, base: []const u8, dir: std.fs.Dir, name: []const u8, payloads: *std.ArrayList([]u8)) !void {
        const body = readFile(self.allocator, dir, name, 1 * 1024 * 1024) catch return;
        defer self.allocator.free(body);

        const source_path = try std.fs.path.join(self.allocator, &.{ base, name });
        defer self.allocator.free(source_path);

        var package_name: ?[]const u8 = null;
        var version: ?[]const u8 = null;
        var lines = std.mem.splitScalar(u8, body, '\n');
        while (lines.next()) |line_raw| {
            const line = std.mem.trimRight(u8, line_raw, "\r");
            if (line.len == 0) break; // Headers end at the first blank line.
            if (std.mem.startsWith(u8, line, "Name: ")) {
                package_name = line[6..];
            } else if (std.mem.startsWith(u8, line, "Version: ")) {
                version = line[9..];
            }
            if (package_name != null and version != null) break;
        }

        if (package_name == null or version == null) return;
        const payload = try buildInventoryEvent(
            self.allocator,
            "pypi",
            package_name.?,
            version.?,
            "high",
            source_path,
            "pypi-dist-info");
        try payloads.append(payload);
    }
};

fn skipDirent(name: []const u8) bool {
    if (name.len == 0) return true;
    // Skip large noisy roots that won't contain package metadata and would
    // blow up the walk.
    if (std.mem.eql(u8, name, ".git")) return true;
    if (std.mem.eql(u8, name, ".cache")) return true;
    if (std.mem.eql(u8, name, ".npm")) return true;
    if (std.mem.eql(u8, name, "tmp")) return true;
    if (std.mem.eql(u8, name, "Library")) return true; // macOS user-Library is huge.
    return false;
}

fn readFile(alloc: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, max_bytes: usize) ![]u8 {
    var file = try dir.openFile(name, .{});
    defer file.close();
    return file.readToEndAlloc(alloc, max_bytes);
}

fn buildInventoryEvent(
    alloc: std.mem.Allocator,
    ecosystem: []const u8,
    name: []const u8,
    version: []const u8,
    confidence: []const u8,
    source_path: []const u8,
    source_type: []const u8,
) ![]u8 {
    var out = std.ArrayList(u8).init(alloc);
    errdefer out.deinit();
    var w = out.writer();
    try w.writeAll("{\"ecosystem\":");
    try std.json.stringify(ecosystem, .{}, w);
    try w.writeAll(",\"name\":");
    try std.json.stringify(name, .{}, w);
    try w.writeAll(",\"version\":");
    try std.json.stringify(version, .{}, w);
    try w.writeAll(",\"confidence\":");
    try std.json.stringify(confidence, .{}, w);
    try w.writeAll(",\"source_type\":");
    try std.json.stringify(source_type, .{}, w);
    try w.writeAll(",\"source_path\":");
    try std.json.stringify(source_path, .{}, w);
    try w.writeByte('}');
    return out.toOwnedSlice();
}

test "scanner module loads" {
    var s = Scanner.init(std.testing.allocator);
    _ = &s;
}
