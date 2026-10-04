//! Static SPA. Hashed files under `/assets/` are immutable. Other GET paths
//! that are not `/api` fall back to `index.html`. No `unsafe-inline` scripts.
const std = @import("std");

const csp = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

pub fn relativePath(url_path: []const u8) error{BadPath}![]const u8 {
    if (url_path.len == 0 or url_path[0] != '/') return error.BadPath;
    if (std.mem.indexOfScalar(u8, url_path, '%') != null) return error.BadPath;
    if (std.mem.indexOfScalar(u8, url_path, '\\') != null) return error.BadPath;
    if (std.mem.indexOfScalar(u8, url_path, 0) != null) return error.BadPath;
    var it = std.mem.splitScalar(u8, url_path, '/');
    while (it.next()) |seg| {
        if (seg.len == 0) continue;
        if (std.mem.eql(u8, seg, ".") or std.mem.eql(u8, seg, "..")) return error.BadPath;
    }
    return url_path[1..];
}

pub fn hasExtension(rel: []const u8) bool {
    const base = std.fs.path.basename(rel);
    return std.mem.lastIndexOfScalar(u8, base, '.') != null;
}

pub fn immutableAsset(rel: []const u8) bool {
    const base = std.fs.path.basename(rel);
    const ext = std.mem.lastIndexOfScalar(u8, base, '.') orelse return false;
    const stem = base[0..ext];
    const dot = std.mem.lastIndexOfScalar(u8, stem, '.') orelse return false;
    const hex = stem[dot + 1 ..];
    if (hex.len < 8) return false;
    for (hex) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}

pub fn contentType(rel: []const u8) []const u8 {
    if (std.mem.endsWith(u8, rel, ".html")) return "text/html; charset=utf-8";
    if (std.mem.endsWith(u8, rel, ".css")) return "text/css; charset=utf-8";
    if (std.mem.endsWith(u8, rel, ".js")) return "text/javascript; charset=utf-8";
    if (std.mem.endsWith(u8, rel, ".svg")) return "image/svg+xml";
    if (std.mem.endsWith(u8, rel, ".png")) return "image/png";
    if (std.mem.endsWith(u8, rel, ".woff2")) return "font/woff2";
    return "application/octet-stream";
}

pub fn serve(
    allocator: std.mem.Allocator,
    io: std.Io,
    request: *std.http.Server.Request,
    ui_root: []const u8,
) !void {
    const target = request.head.target;
    const path = if (std.mem.indexOfScalar(u8, target, '?')) |q| target[0..q] else target;
    if (request.head.method != .GET and request.head.method != .HEAD) {
        try respond(request, .method_not_allowed, "text/plain; charset=utf-8", "method not allowed", false);
        return;
    }
    const rel = relativePath(path) catch {
        try respond(request, .bad_request, "text/plain; charset=utf-8", "bad path", false);
        return;
    };
    var dir = std.Io.Dir.cwd().openDir(io, ui_root, .{ .follow_symlinks = false }) catch {
        try respond(request, .not_found, "text/plain; charset=utf-8", "ui not found", false);
        return;
    };
    defer dir.close(io);

    const wants_file = rel.len > 0 and hasExtension(rel);
    const name = if (wants_file) rel else "index.html";
    if (readUi(dir, io, allocator, name)) |body| {
        defer allocator.free(body);
        try respond(request, .ok, contentType(name), body, immutableAsset(name));
        return;
    } else |_| {}
    if (wants_file) {
        try respond(request, .not_found, "text/plain; charset=utf-8", "not found", false);
        return;
    }
    try respond(request, .not_found, "text/plain; charset=utf-8", "not found", false);
}

fn readUi(dir: std.Io.Dir, io: std.Io, allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    return dir.readFileAlloc(io, name, allocator, std.Io.Limit.limited(2 * 1024 * 1024));
}

fn respond(
    request: *std.http.Server.Request,
    status: std.http.Status,
    kind: []const u8,
    body: []const u8,
    immutable: bool,
) !void {
    const cache = if (immutable) "public, max-age=31536000, immutable" else "no-cache";
    try request.respond(body, .{
        .status = status,
        .extra_headers = &.{
            .{ .name = "content-type", .value = kind },
            .{ .name = "cache-control", .value = cache },
            .{ .name = "content-security-policy", .value = csp },
            .{ .name = "x-content-type-options", .value = "nosniff" },
            .{ .name = "referrer-policy", .value = "no-referrer" },
        },
        .keep_alive = false,
    });
}

test "static paths reject traversal and cache hashed assets" {
    try std.testing.expectError(error.BadPath, relativePath("/../etc/passwd"));
    try std.testing.expectError(error.BadPath, relativePath("/assets/%2e%2e/x"));
    try std.testing.expectError(error.BadPath, relativePath("/./secret"));
    try std.testing.expectEqualStrings("assets/app.js", try relativePath("/assets/app.js"));
    try std.testing.expect(immutableAsset("assets/app.0123abcd.js"));
    try std.testing.expect(!immutableAsset("assets/app.js"));
    try std.testing.expect(!immutableAsset("index.html"));
    try std.testing.expect(hasExtension("assets/app.0123abcd.css"));
    try std.testing.expect(!hasExtension("agents"));
    try std.testing.expect(std.mem.indexOf(u8, csp, "unsafe-inline") == null);
    try std.testing.expect(std.mem.indexOf(u8, csp, "frame-ancestors 'none'") != null);
}
