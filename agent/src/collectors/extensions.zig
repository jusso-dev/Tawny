const std = @import("std");
const builtin = @import("builtin");
const env = @import("../env.zig");

/// Editor + browser extension scanner inspired by Perplexity's Bumblebee.
/// Each extension is emitted with `ecosystem = "editor-extension"` or
/// `"browser-extension"` so the same PackageExposure rule shape used for
/// npm/pypi can match a compromised extension by id+version.
///
/// Privacy stance from Bumblebee: we read only the manifest fields we need
/// for identity. We never emit extension permissions, content scripts,
/// background script paths, or settings.
pub const Scanner = struct {
    allocator: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator) Scanner {
        return .{ .allocator = alloc };
    }

    pub fn collectExtensions(self: *Scanner, kind: Kind) ![][]u8 {
        _ = kind;
        return self.allocator.alloc([]u8, 0);
    }

    fn scanEditorRoots(self: *Scanner, home: []const u8, payloads: *std.array_list.Managed([]u8)) !void {
        const subdirs = [_][]const u8{
            ".vscode/extensions",
            ".vscode-server/extensions",
            ".vscode-insiders/extensions",
            ".cursor/extensions",
            ".windsurf/extensions",
            ".vscodium/extensions",
        };
        for (subdirs) |sub| {
            const root = std.fs.path.join(self.allocator, &.{ home, sub }) catch continue;
            defer self.allocator.free(root);
            self.scanEditorRoot(root, payloads) catch continue;
        }
    }

    fn scanEditorRoot(self: *Scanner, root: []const u8, payloads: *std.array_list.Managed([]u8)) !void {
        var dir = std.fs.openDirAbsolute(root, .{ .iterate = true }) catch return;
        defer dir.close();

        var it = dir.iterate();
        while (it.next() catch null) |entry| {
            if (entry.kind != .directory) continue;
            // Convention: directory name is `<publisher>.<name>-<version>` and
            // optionally suffixed with `-<platform>` for native deps.
            const dir_name = entry.name;
            const id_and_version = parseExtensionDirName(dir_name) orelse continue;

            var sub = dir.openDir(dir_name, .{}) catch continue;
            defer sub.close();
            const pkg_json = readFile(self.allocator, sub, "package.json", 256 * 1024) catch null;
            defer if (pkg_json) |body| self.allocator.free(body);

            // Cross-check version with package.json when available; the
            // directory name can lie if the install was renamed by hand.
            var resolved_version = id_and_version.version;
            if (pkg_json) |body| {
                if (extractJsonString(self.allocator, body, "version")) |jv| {
                    resolved_version = jv;
                }
            }

            const source_path = std.fs.path.join(self.allocator, &.{ root, dir_name }) catch continue;
            defer self.allocator.free(source_path);

            const payload = try buildExtensionEvent(
                self.allocator,
                "editor-extension",
                id_and_version.id,
                resolved_version,
                source_path);
            try payloads.append(payload);
        }
    }

    fn scanBrowserRoots(self: *Scanner, home: []const u8, payloads: *std.array_list.Managed([]u8)) !void {
        // Chromium-family profiles: each `<profile>/Extensions/<ext_id>/<version>/manifest.json`.
        const chrome_paths = [_][]const u8{
            ".config/google-chrome",
            ".config/chromium",
            ".config/microsoft-edge",
            ".config/BraveSoftware/Brave-Browser",
            "Library/Application Support/Google/Chrome",
            "Library/Application Support/Chromium",
            "Library/Application Support/Microsoft Edge",
        };
        for (chrome_paths) |sub| {
            const root = std.fs.path.join(self.allocator, &.{ home, sub }) catch continue;
            defer self.allocator.free(root);
            self.scanChromiumRoot(root, payloads) catch continue;
        }

        // Firefox profile: `<profile>/extensions.json` listing installed addons.
        const ff_path = std.fs.path.join(self.allocator, &.{ home, ".mozilla/firefox" }) catch return;
        defer self.allocator.free(ff_path);
        self.scanFirefoxRoot(ff_path, payloads) catch return;
    }

    fn scanChromiumRoot(self: *Scanner, root: []const u8, payloads: *std.array_list.Managed([]u8)) !void {
        var root_dir = std.fs.openDirAbsolute(root, .{ .iterate = true }) catch return;
        defer root_dir.close();

        var profile_it = root_dir.iterate();
        while (profile_it.next() catch null) |profile_entry| {
            if (profile_entry.kind != .directory) continue;
            var profile_dir = root_dir.openDir(profile_entry.name, .{}) catch continue;
            defer profile_dir.close();

            var ext_dir = profile_dir.openDir("Extensions", .{ .iterate = true }) catch continue;
            defer ext_dir.close();

            var ext_it = ext_dir.iterate();
            while (ext_it.next() catch null) |ext_entry| {
                if (ext_entry.kind != .directory) continue;
                const ext_id = ext_entry.name;
                var per_ext = ext_dir.openDir(ext_id, .{ .iterate = true }) catch continue;
                defer per_ext.close();

                var version_it = per_ext.iterate();
                while (version_it.next() catch null) |version_entry| {
                    if (version_entry.kind != .directory) continue;
                    var version_dir = per_ext.openDir(version_entry.name, .{}) catch continue;
                    defer version_dir.close();

                    const manifest = readFile(self.allocator, version_dir, "manifest.json", 512 * 1024) catch continue;
                    defer self.allocator.free(manifest);

                    const declared_name = extractJsonString(self.allocator, manifest, "name") orelse try self.allocator.dupe(u8, ext_id);
                    defer self.allocator.free(declared_name);
                    const declared_version = extractJsonString(self.allocator, manifest, "version") orelse try self.allocator.dupe(u8, version_entry.name);
                    defer self.allocator.free(declared_version);

                    const source_path = std.fs.path.join(self.allocator, &.{ root, profile_entry.name, "Extensions", ext_id, version_entry.name }) catch continue;
                    defer self.allocator.free(source_path);

                    const composite_id = std.fmt.allocPrint(self.allocator, "{s} ({s})", .{ ext_id, declared_name }) catch continue;
                    defer self.allocator.free(composite_id);

                    const payload = try buildExtensionEvent(
                        self.allocator,
                        "browser-extension",
                        composite_id,
                        declared_version,
                        source_path);
                    try payloads.append(payload);
                }
            }
        }
    }

    fn scanFirefoxRoot(self: *Scanner, root: []const u8, payloads: *std.array_list.Managed([]u8)) !void {
        var root_dir = std.fs.openDirAbsolute(root, .{ .iterate = true }) catch return;
        defer root_dir.close();

        var profile_it = root_dir.iterate();
        while (profile_it.next() catch null) |profile| {
            if (profile.kind != .directory) continue;
            var profile_dir = root_dir.openDir(profile.name, .{}) catch continue;
            defer profile_dir.close();
            const body = readFile(self.allocator, profile_dir, "extensions.json", 4 * 1024 * 1024) catch continue;
            defer self.allocator.free(body);

            const source_path = std.fs.path.join(self.allocator, &.{ root, profile.name, "extensions.json" }) catch continue;
            defer self.allocator.free(source_path);

            var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, body, .{}) catch continue;
            defer parsed.deinit();
            if (parsed.value != .object) continue;
            const addons = parsed.value.object.get("addons") orelse continue;
            if (addons != .array) continue;

            for (addons.array.items) |addon| {
                if (addon != .object) continue;
                const id = addon.object.get("id") orelse continue;
                const ver = addon.object.get("version") orelse continue;
                if (id != .string or ver != .string) continue;
                const payload = try buildExtensionEvent(
                    self.allocator,
                    "browser-extension",
                    id.string,
                    ver.string,
                    source_path);
                try payloads.append(payload);
            }
        }
    }
};

pub const Kind = enum { editor, browser };

const ParsedDirName = struct { id: []const u8, version: []const u8 };

fn parseExtensionDirName(name: []const u8) ?ParsedDirName {
    // Bumblebee documents the shape as `<publisher>.<name>-<version>[-<platform>]`.
    // We split on the last `-` and rely on the publisher dot to anchor the id.
    if (std.mem.indexOfScalar(u8, name, '.') == null) return null;
    const dash = std.mem.lastIndexOfScalar(u8, name, '-') orelse return null;
    if (dash == 0 or dash >= name.len - 1) return null;
    const candidate_version = name[dash + 1 ..];
    // Reject trailing `-<platform>` suffix by checking that the version
    // starts with a digit (heuristic but reliable in practice).
    if (candidate_version.len == 0 or !std.ascii.isDigit(candidate_version[0])) {
        // Look one segment back for the version.
        const prev_dash = std.mem.lastIndexOfScalar(u8, name[0..dash], '-') orelse return null;
        const version = name[prev_dash + 1 .. dash];
        if (version.len == 0 or !std.ascii.isDigit(version[0])) return null;
        return .{ .id = name[0..prev_dash], .version = version };
    }
    return .{ .id = name[0..dash], .version = candidate_version };
}

/// Tiny string-only JSON value extractor — used because we don't need to
/// fully parse a 100KB manifest when we only want one or two top-level keys.
/// Returns an owned slice on success, or null when the key isn't a string.
fn extractJsonString(alloc: std.mem.Allocator, body: []const u8, key: []const u8) ?[]u8 {
    // Look for `"<key>"` and the first `"..."` after it. Tolerant of nesting:
    // if a nested object has the same key we'll match the outer one first.
    var pattern_buf: [128]u8 = undefined;
    const pattern = std.fmt.bufPrint(&pattern_buf, "\"{s}\"", .{key}) catch return null;
    const start = std.mem.indexOf(u8, body, pattern) orelse return null;
    const after = body[start + pattern.len ..];
    // Skip whitespace + colon.
    var i: usize = 0;
    while (i < after.len and (after[i] == ' ' or after[i] == '\t' or after[i] == ':' or after[i] == '\r' or after[i] == '\n')) : (i += 1) {}
    if (i >= after.len or after[i] != '"') return null;
    i += 1;
    const value_start = i;
    while (i < after.len and after[i] != '"') : (i += 1) {
        if (after[i] == '\\' and i + 1 < after.len) i += 1;
    }
    if (i >= after.len) return null;
    return alloc.dupe(u8, after[value_start..i]) catch null;
}

fn readFile(alloc: std.mem.Allocator, dir: std.Io.Dir, name: []const u8, max_bytes: usize) ![]u8 {
    var file = try dir.openFile(name, .{});
    defer file.close();
    return file.readToEndAlloc(alloc, max_bytes);
}

fn buildExtensionEvent(
    alloc: std.mem.Allocator,
    ecosystem: []const u8,
    id: []const u8,
    version: []const u8,
    source_path: []const u8,
) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;
    try w.writeAll("{\"ecosystem\":");
    try std.json.Stringify.value(ecosystem, .{}, w);
    try w.writeAll(",\"name\":");
    try std.json.Stringify.value(id, .{}, w);
    try w.writeAll(",\"version\":");
    try std.json.Stringify.value(version, .{}, w);
    try w.writeAll(",\"source_path\":");
    try std.json.Stringify.value(source_path, .{}, w);
    try w.writeByte('}');
    return out.toOwnedSlice();
}

test "extension dir name parser" {
    const a = parseExtensionDirName("ms-vscode.csharp-1.25.0") orelse unreachable;
    try std.testing.expectEqualStrings("ms-vscode.csharp", a.id);
    try std.testing.expectEqualStrings("1.25.0", a.version);
}
