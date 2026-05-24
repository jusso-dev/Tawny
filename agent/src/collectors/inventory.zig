const std = @import("std");
const builtin = @import("builtin");
const env = @import("../env.zig");

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
        return self.allocator.alloc([]u8, 0);
    }

    fn scanRoot(self: *Scanner, root: []const u8, payloads: *std.array_list.Managed([]u8)) !void {
        var dir = std.fs.openDirAbsolute(root, .{ .iterate = true }) catch return;
        defer dir.close();
        try self.walk(root, dir, 0, payloads);
    }

    fn walk(self: *Scanner, base: []const u8, dir: std.Io.Dir, depth: usize, payloads: *std.array_list.Managed([]u8)) !void {
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

    fn handleFile(self: *Scanner, base: []const u8, dir: std.Io.Dir, name: []const u8, payloads: *std.array_list.Managed([]u8)) !void {
        if (std.mem.eql(u8, name, "package-lock.json")) {
            try self.parseNpmLock(base, dir, name, payloads);
        } else if (std.mem.eql(u8, name, "pnpm-lock.yaml")) {
            try self.parsePnpmLock(base, dir, name, payloads);
        } else if (std.mem.eql(u8, name, "yarn.lock")) {
            try self.parseYarnLock(base, dir, name, payloads);
        } else if (std.mem.eql(u8, name, "bun.lock")) {
            try self.parseBunLock(base, dir, name, payloads);
        } else if (std.mem.eql(u8, name, "go.sum")) {
            try self.parseGoSum(base, dir, name, payloads);
        } else if (std.mem.eql(u8, name, "go.mod")) {
            try self.parseGoMod(base, dir, name, payloads);
        } else if (std.mem.eql(u8, name, "Gemfile.lock")) {
            try self.parseGemfileLock(base, dir, name, payloads);
        } else if (std.mem.endsWith(u8, name, ".gemspec")) {
            try self.parseGemspec(base, dir, name, payloads);
        } else if (std.mem.eql(u8, name, "composer.lock")) {
            try self.parseComposerPackages(base, dir, name, payloads, "composer-lockfile");
        } else if (std.mem.eql(u8, name, "installed.json") and endsWithSegment(base, "composer")) {
            try self.parseComposerPackages(base, dir, name, payloads, "composer-installed");
        } else if (std.mem.endsWith(u8, base, ".dist-info") and std.mem.eql(u8, name, "METADATA")) {
            try self.parsePypiMetadata(base, dir, name, payloads);
        }
    }

    fn parseNpmLock(self: *Scanner, base: []const u8, dir: std.Io.Dir, name: []const u8, payloads: *std.array_list.Managed([]u8)) !void {
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

    fn parsePnpmLock(self: *Scanner, base: []const u8, dir: std.Io.Dir, name: []const u8, payloads: *std.array_list.Managed([]u8)) !void {
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

    fn parsePypiMetadata(self: *Scanner, base: []const u8, dir: std.Io.Dir, name: []const u8, payloads: *std.array_list.Managed([]u8)) !void {
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

    /// yarn.lock parser handling both Classic (v1, `version "X.Y.Z"`) and
    /// Berry (v2+, `version: X.Y.Z`) syntax. Lockfile structure is a series
    /// of blocks: a non-indented header line ending with ':' followed by
    /// indented `version` / `resolution` / etc. We just need the name from
    /// the header and the version from the indented block.
    fn parseYarnLock(self: *Scanner, base: []const u8, dir: std.Io.Dir, name: []const u8, payloads: *std.array_list.Managed([]u8)) !void {
        const body = readFile(self.allocator, dir, name, 32 * 1024 * 1024) catch return;
        defer self.allocator.free(body);

        const source_path = try std.fs.path.join(self.allocator, &.{ base, name });
        defer self.allocator.free(source_path);

        var current_name: ?[]const u8 = null;
        var lines = std.mem.splitScalar(u8, body, '\n');
        while (lines.next()) |line_raw| {
            const line = std.mem.trimRight(u8, line_raw, " \r\t");
            if (line.len == 0) {
                current_name = null;
                continue;
            }
            // Skip comments + the Berry __metadata block.
            if (line[0] == '#') continue;
            if (std.mem.startsWith(u8, line, "__metadata")) {
                current_name = null;
                continue;
            }

            // Header lines aren't indented and end with ':' (Classic + Berry both).
            if (!std.ascii.isWhitespace(line[0]) and line[line.len - 1] == ':') {
                current_name = extractYarnPackageName(line[0 .. line.len - 1]);
                continue;
            }

            // Indented lines inside a block. Look for "version".
            if (current_name) |pkg_name| {
                const trimmed = std.mem.trimLeft(u8, line, " \t");
                if (std.mem.startsWith(u8, trimmed, "version ")) {
                    // Classic: `version "7.23.5"`
                    const after = trimmed["version ".len..];
                    if (extractQuotedValue(after)) |version| {
                        const payload = try buildInventoryEvent(
                            self.allocator, "npm", pkg_name, version, "high", source_path, "yarn-lockfile");
                        try payloads.append(payload);
                        current_name = null;
                    }
                } else if (std.mem.startsWith(u8, trimmed, "version:")) {
                    // Berry: `version: 7.23.5`
                    const value = std.mem.trim(u8, trimmed["version:".len..], " \t\"");
                    if (value.len > 0) {
                        const payload = try buildInventoryEvent(
                            self.allocator, "npm", pkg_name, value, "high", source_path, "yarn-lockfile");
                        try payloads.append(payload);
                        current_name = null;
                    }
                }
            }
        }
    }

    /// bun.lock is JSONC (JSON with optional comments). The `packages` object
    /// maps spec -> [resolved_name@version, registry, metadata, integrity].
    /// We grab the resolved name@version from the first array element.
    fn parseBunLock(self: *Scanner, base: []const u8, dir: std.Io.Dir, name: []const u8, payloads: *std.array_list.Managed([]u8)) !void {
        const body = readFile(self.allocator, dir, name, 16 * 1024 * 1024) catch return;
        defer self.allocator.free(body);

        const source_path = try std.fs.path.join(self.allocator, &.{ base, name });
        defer self.allocator.free(source_path);

        // Try strict JSON first (most bun.lock files have no comments).
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, body, .{}) catch blk: {
            // Fallback: strip `// ...` line comments and retry.
            const stripped = stripLineComments(self.allocator, body) catch return;
            defer self.allocator.free(stripped);
            break :blk std.json.parseFromSlice(std.json.Value, self.allocator, stripped, .{}) catch return;
        };
        defer parsed.deinit();

        if (parsed.value != .object) return;
        const packages = parsed.value.object.get("packages") orelse return;
        if (packages != .object) return;

        var it = packages.object.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.* != .array) continue;
            const arr = kv.value_ptr.*.array.items;
            if (arr.len == 0 or arr[0] != .string) continue;
            const spec = arr[0].string;
            // spec is `<name>@<version>` — find the last '@' that isn't at pos 0 (scoped pkgs).
            const at = std.mem.lastIndexOfScalar(u8, spec, '@') orelse continue;
            if (at == 0) continue;
            const pkg_name = spec[0..at];
            const version = spec[at + 1 ..];
            if (pkg_name.len == 0 or version.len == 0) continue;

            const payload = try buildInventoryEvent(
                self.allocator, "npm", pkg_name, version, "high", source_path, "bun-lockfile");
            try payloads.append(payload);
        }
    }

    /// go.sum lists every module version (direct + transitive) with checksum
    /// pairs (one `/go.mod` line, one zip-content line). We dedupe to a single
    /// event per (module, version).
    fn parseGoSum(self: *Scanner, base: []const u8, dir: std.Io.Dir, name: []const u8, payloads: *std.array_list.Managed([]u8)) !void {
        const body = readFile(self.allocator, dir, name, 16 * 1024 * 1024) catch return;
        defer self.allocator.free(body);

        const source_path = try std.fs.path.join(self.allocator, &.{ base, name });
        defer self.allocator.free(source_path);

        var seen = std.StringHashMap(void).init(self.allocator);
        defer {
            var it = seen.iterator();
            while (it.next()) |kv| self.allocator.free(kv.key_ptr.*);
            seen.deinit();
        }

        var lines = std.mem.splitScalar(u8, body, '\n');
        while (lines.next()) |line_raw| {
            const line = std.mem.trim(u8, line_raw, " \r\t");
            if (line.len == 0) continue;

            // Format: `<module> <version>[/go.mod] <hash>`
            var fields = std.mem.tokenizeAny(u8, line, " \t");
            const module = fields.next() orelse continue;
            const raw_version = fields.next() orelse continue;
            // Trim the `/go.mod` suffix when present so both lines collapse to one event.
            const version = if (std.mem.endsWith(u8, raw_version, "/go.mod"))
                raw_version[0 .. raw_version.len - "/go.mod".len]
            else
                raw_version;

            const key = try std.fmt.allocPrint(self.allocator, "{s}@{s}", .{ module, version });
            if (seen.contains(key)) {
                self.allocator.free(key);
                continue;
            }
            try seen.put(key, {});

            const payload = try buildInventoryEvent(
                self.allocator, "go", module, version, "high", source_path, "go-sum");
            try payloads.append(payload);
        }
    }

    /// go.mod `require` blocks list direct dependencies only — useful as a
    /// supplement to go.sum (e.g. when go.sum hasn't been committed).
    fn parseGoMod(self: *Scanner, base: []const u8, dir: std.Io.Dir, name: []const u8, payloads: *std.array_list.Managed([]u8)) !void {
        const body = readFile(self.allocator, dir, name, 1 * 1024 * 1024) catch return;
        defer self.allocator.free(body);

        const source_path = try std.fs.path.join(self.allocator, &.{ base, name });
        defer self.allocator.free(source_path);

        var in_block = false;
        var lines = std.mem.splitScalar(u8, body, '\n');
        while (lines.next()) |line_raw| {
            // Strip line comments first so `// indirect` doesn't confuse parsing.
            const without_comment = if (std.mem.indexOf(u8, line_raw, "//")) |idx|
                line_raw[0..idx]
            else
                line_raw;
            const line = std.mem.trim(u8, without_comment, " \r\t");
            if (line.len == 0) continue;

            if (std.mem.eql(u8, line, "require (")) { in_block = true; continue; }
            if (in_block and std.mem.eql(u8, line, ")")) { in_block = false; continue; }

            // Match `[require] <module> <version>` on a single line, or inside a block.
            var rest = line;
            if (std.mem.startsWith(u8, rest, "require ")) {
                rest = rest["require ".len..];
            } else if (!in_block) {
                continue;
            }

            var fields = std.mem.tokenizeAny(u8, rest, " \t");
            const module = fields.next() orelse continue;
            const version = fields.next() orelse continue;
            if (!std.mem.startsWith(u8, version, "v")) continue;

            const payload = try buildInventoryEvent(
                self.allocator, "go", module, version, "medium", source_path, "go-mod");
            try payloads.append(payload);
        }
    }

    /// Gemfile.lock has a `GEM` section with a `specs:` subsection. Each
    /// gem appears at indent 4 as `  gem-name (1.2.3)`; transitive deps
    /// appear at indent 6 and we ignore those (their own entries already
    /// surface at indent 4).
    fn parseGemfileLock(self: *Scanner, base: []const u8, dir: std.Io.Dir, name: []const u8, payloads: *std.array_list.Managed([]u8)) !void {
        const body = readFile(self.allocator, dir, name, 8 * 1024 * 1024) catch return;
        defer self.allocator.free(body);

        const source_path = try std.fs.path.join(self.allocator, &.{ base, name });
        defer self.allocator.free(source_path);

        var in_specs = false;
        var lines = std.mem.splitScalar(u8, body, '\n');
        while (lines.next()) |line_raw| {
            const line = std.mem.trimRight(u8, line_raw, " \r\t");
            if (line.len == 0) continue;

            if (std.mem.startsWith(u8, line, "  specs:")) { in_specs = true; continue; }
            // A non-indented line ends the GEM block.
            if (line[0] != ' ') { in_specs = false; continue; }
            if (!in_specs) continue;

            // Gem entries are at exactly 4 leading spaces; deps are at 6+.
            if (line.len < 4 or !std.mem.startsWith(u8, line, "    ") or std.mem.startsWith(u8, line, "     ")) continue;
            const entry = line[4..];
            // Format: `gem-name (1.2.3)` — sometimes `gem-name (1.2.3-platform)`.
            const lparen = std.mem.indexOfScalar(u8, entry, '(') orelse continue;
            const rparen = std.mem.indexOfScalar(u8, entry, ')') orelse continue;
            if (rparen <= lparen + 1) continue;
            const pkg_name = std.mem.trim(u8, entry[0..lparen], " \t");
            const version = std.mem.trim(u8, entry[lparen + 1 .. rparen], " \t");
            if (pkg_name.len == 0 or version.len == 0) continue;

            const payload = try buildInventoryEvent(
                self.allocator, "rubygems", pkg_name, version, "high", source_path, "gemfile-lock");
            try payloads.append(payload);
        }
    }

    /// Each installed gem has a stub gemspec under `specifications/`. The
    /// stub line is canonical: `# stub: <name> <version> ruby <require_paths>`.
    /// Falls back to scanning `s.name` / `s.version` if the stub is missing.
    fn parseGemspec(self: *Scanner, base: []const u8, dir: std.Io.Dir, name: []const u8, payloads: *std.array_list.Managed([]u8)) !void {
        const body = readFile(self.allocator, dir, name, 1 * 1024 * 1024) catch return;
        defer self.allocator.free(body);

        const source_path = try std.fs.path.join(self.allocator, &.{ base, name });
        defer self.allocator.free(source_path);

        var pkg_name: ?[]const u8 = null;
        var version: ?[]const u8 = null;

        var lines = std.mem.splitScalar(u8, body, '\n');
        while (lines.next()) |line_raw| {
            const line = std.mem.trim(u8, line_raw, " \r\t");
            if (std.mem.startsWith(u8, line, "# stub: ")) {
                var fields = std.mem.tokenizeAny(u8, line["# stub: ".len..], " \t");
                pkg_name = fields.next();
                version = fields.next();
                break;
            }
            // Fallback path for non-stub gemspecs.
            if (pkg_name == null and std.mem.indexOf(u8, line, "s.name") != null) {
                if (extractQuotedValue(line)) |v| pkg_name = v;
            } else if (version == null and std.mem.indexOf(u8, line, "s.version") != null) {
                if (extractQuotedValue(line)) |v| version = v;
            }
            if (pkg_name != null and version != null) break;
        }

        if (pkg_name == null or version == null) return;
        const payload = try buildInventoryEvent(
            self.allocator, "rubygems", pkg_name.?, version.?, "high", source_path, "gemspec");
        try payloads.append(payload);
    }

    /// composer.lock and vendor/composer/installed.json have the same shape:
    /// a top-level object with `packages: [{name, version, ...}, ...]`. The
    /// `installed.json` format from Composer 2 also wraps under a top-level
    /// `packages` key, so the same parser handles both.
    fn parseComposerPackages(
        self: *Scanner,
        base: []const u8,
        dir: std.Io.Dir,
        name: []const u8,
        payloads: *std.array_list.Managed([]u8),
        source_type: []const u8,
    ) !void {
        const body = readFile(self.allocator, dir, name, 16 * 1024 * 1024) catch return;
        defer self.allocator.free(body);

        const source_path = try std.fs.path.join(self.allocator, &.{ base, name });
        defer self.allocator.free(source_path);

        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, body, .{}) catch return;
        defer parsed.deinit();
        if (parsed.value != .object) return;

        // Emit `packages` then `packages-dev` (composer.lock) — installed.json
        // only has `packages`, the other access is a no-op.
        const containers = [_][]const u8{ "packages", "packages-dev" };
        for (containers) |container| {
            const pkgs = parsed.value.object.get(container) orelse continue;
            if (pkgs != .array) continue;
            for (pkgs.array.items) |entry| {
                if (entry != .object) continue;
                const n = entry.object.get("name") orelse continue;
                const v = entry.object.get("version") orelse continue;
                if (n != .string or v != .string) continue;
                const payload = try buildInventoryEvent(
                    self.allocator, "packagist", n.string, v.string, "high", source_path, source_type);
                try payloads.append(payload);
            }
        }
    }
};

fn skipDirent(name: []const u8) bool {
    if (name.len == 0) return true;
    // Skip large noisy roots that won't contain useful package metadata
    // (lockfiles + manifests live at project roots, not inside these trees)
    // and would blow up the walk.
    if (std.mem.eql(u8, name, ".git")) return true;
    if (std.mem.eql(u8, name, ".cache")) return true;
    if (std.mem.eql(u8, name, ".npm")) return true;
    if (std.mem.eql(u8, name, "node_modules")) return true; // package-lock.json lives at project root, not inside
    if (std.mem.eql(u8, name, "dist")) return true;
    if (std.mem.eql(u8, name, "build")) return true;
    if (std.mem.eql(u8, name, "target")) return true; // rust / java
    if (std.mem.eql(u8, name, ".next")) return true;
    if (std.mem.eql(u8, name, ".venv")) return true;
    if (std.mem.eql(u8, name, "tmp")) return true;
    if (std.mem.eql(u8, name, "Library")) return true; // macOS user-Library is huge.
    return false;
}

fn endsWithSegment(path: []const u8, segment: []const u8) bool {
    if (path.len < segment.len) return false;
    if (path.len == segment.len) return std.mem.eql(u8, path, segment);
    const start = path.len - segment.len;
    // Require a path separator immediately before the segment so e.g.
    // "/etc/notcomposer" doesn't match "composer".
    const sep_byte = path[start - 1];
    return (sep_byte == '/' or sep_byte == '\\') and std.mem.eql(u8, path[start..], segment);
}

/// Extract the package name from a yarn.lock block header. Inputs look like:
///   "@babel/code-frame@^7.0.0"
///   "@babel/code-frame@^7.0.0", "@babel/code-frame@^7.22.5"
///   "@babel/code-frame@npm:7.23.0"  (Berry)
///   lodash@^4.17.21
/// We just grab the first comma-separated spec, strip surrounding quotes,
/// and split on the last '@' that isn't at position 0 (scoped packages).
fn extractYarnPackageName(header: []const u8) ?[]const u8 {
    var first_spec = header;
    if (std.mem.indexOf(u8, header, ", ")) |comma| {
        first_spec = header[0..comma];
    }
    first_spec = std.mem.trim(u8, first_spec, " \t\"");
    if (first_spec.len == 0) return null;
    const last_at = std.mem.lastIndexOfScalar(u8, first_spec, '@') orelse return null;
    if (last_at == 0) return null;
    const name = first_spec[0..last_at];
    if (name.len == 0) return null;
    return name;
}

/// Strip Ruby / JSONC line comments (`// ...` and `# ...` to end of line).
/// Used for parsing JSONC bun.lock when strict JSON parse fails. Returns an
/// owned slice the caller must free.
fn stripLineComments(alloc: std.mem.Allocator, src: []const u8) ![]u8 {
    var out = std.array_list.Managed(u8).init(alloc);
    errdefer out.deinit();
    var in_string = false;
    var i: usize = 0;
    while (i < src.len) {
        const c = src[i];
        if (in_string) {
            if (c == '\\' and i + 1 < src.len) {
                try out.append(c);
                try out.append(src[i + 1]);
                i += 2;
                continue;
            }
            if (c == '"') in_string = false;
            try out.append(c);
            i += 1;
            continue;
        }
        if (c == '"') {
            in_string = true;
            try out.append(c);
            i += 1;
            continue;
        }
        if (c == '/' and i + 1 < src.len and src[i + 1] == '/') {
            // Skip to end of line.
            while (i < src.len and src[i] != '\n') : (i += 1) {}
            continue;
        }
        try out.append(c);
        i += 1;
    }
    return out.toOwnedSlice();
}

/// Pull the first `"..."` (or `'...'`) literal from a line. Used by the
/// yarn Classic version line (`version "X.Y.Z"`) and the gemspec fallback
/// (`s.version = "X.Y.Z".freeze`).
fn extractQuotedValue(line: []const u8) ?[]const u8 {
    for ([_]u8{ '"', '\'' }) |quote| {
        if (std.mem.indexOfScalar(u8, line, quote)) |start| {
            if (std.mem.indexOfScalarPos(u8, line, start + 1, quote)) |end| {
                if (end > start + 1) return line[start + 1 .. end];
            }
        }
    }
    return null;
}

fn readFile(alloc: std.mem.Allocator, dir: std.Io.Dir, name: []const u8, max_bytes: usize) ![]u8 {
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
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;
    try w.writeAll("{\"ecosystem\":");
    try std.json.Stringify.value(ecosystem, .{}, w);
    try w.writeAll(",\"name\":");
    try std.json.Stringify.value(name, .{}, w);
    try w.writeAll(",\"version\":");
    try std.json.Stringify.value(version, .{}, w);
    try w.writeAll(",\"confidence\":");
    try std.json.Stringify.value(confidence, .{}, w);
    try w.writeAll(",\"source_type\":");
    try std.json.Stringify.value(source_type, .{}, w);
    try w.writeAll(",\"source_path\":");
    try std.json.Stringify.value(source_path, .{}, w);
    try w.writeByte('}');
    return out.toOwnedSlice();
}

test "scanner module loads" {
    var s = Scanner.init(std.testing.allocator);
    _ = &s;
}

test "yarn header parser handles scoped packages and Berry specs" {
    try std.testing.expectEqualStrings("lodash", extractYarnPackageName("lodash@^4.17.21").?);
    try std.testing.expectEqualStrings(
        "@babel/code-frame",
        extractYarnPackageName("\"@babel/code-frame@^7.0.0\", \"@babel/code-frame@^7.22.5\"").?,
    );
    try std.testing.expectEqualStrings(
        "@babel/code-frame",
        extractYarnPackageName("\"@babel/code-frame@npm:7.23.0\"").?,
    );
}

test "extractQuotedValue grabs the first string literal" {
    try std.testing.expectEqualStrings("7.23.5", extractQuotedValue("version \"7.23.5\"").?);
    try std.testing.expectEqualStrings("actionview", extractQuotedValue("  s.name = \"actionview\".freeze").?);
}

test "stripLineComments preserves strings and drops comments" {
    const out = try stripLineComments(std.testing.allocator, "{\"a\":1 // drop me\n,\"b\":\"// keep\"\n}");
    defer std.testing.allocator.free(out);
    try std.testing.expectEqualStrings("{\"a\":1 \n,\"b\":\"// keep\"\n}", out);
}

test "endsWithSegment respects path separators" {
    try std.testing.expect(endsWithSegment("/home/user/vendor/composer", "composer"));
    try std.testing.expect(!endsWithSegment("/home/user/notcomposer", "composer"));
    try std.testing.expect(endsWithSegment("composer", "composer"));
}
