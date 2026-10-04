//! Hourly GitHub release sync. Matches CheckAgentReleasesJob: asset name
//! regex, .sha256 sidecar, upsert agent_releases, clear is_latest per platform.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const http_get = @import("http_get.zig");

pub const Options = struct {
    now_unix: i64,
    allow_private: bool = false,
    url: []const u8 = "https://api.github.com/repos/jusso-dev/tawny/releases/latest",
};

const platforms = [_][]const u8{
    "macos-arm64",
    "linux-arm64",
    "windows-x64",
    "macos-x64",
    "linux-x64",
};

const Asset = struct {
    name: []u8,
    url: []u8,
};

const Row = struct {
    version: []const u8,
    platform: []const u8,
    url: []const u8,
    sha256: [64]u8,
};

pub const ParsedAsset = struct {
    version: []const u8,
    platform: []const u8,
};

pub fn parseAsset(name: []const u8) ?ParsedAsset {
    const prefix = "tawny-agent-";
    if (name.len < prefix.len or !std.ascii.eqlIgnoreCase(name[0..prefix.len], prefix)) return null;
    var body = name[prefix.len..];
    if (body.len >= 4 and std.ascii.eqlIgnoreCase(body[body.len - 4 ..], ".exe")) body = body[0 .. body.len - 4];
    for (platforms) |platform| {
        if (body.len <= platform.len + 1) continue;
        if (body[body.len - platform.len - 1] != '-') continue;
        if (!std.ascii.eqlIgnoreCase(body[body.len - platform.len ..], platform)) continue;
        const version = body[0 .. body.len - platform.len - 1];
        if (version.len == 0) return null;
        return .{ .version = version, .platform = body[body.len - platform.len ..] };
    }
    return null;
}

pub fn sidecarName(buf: *[256]u8, asset_name: []const u8) ?[]const u8 {
    if (asset_name.len + 7 > buf.len) return null;
    if (asset_name.len >= 4 and std.ascii.eqlIgnoreCase(asset_name[asset_name.len - 4 ..], ".exe")) {
        const stem = asset_name[0 .. asset_name.len - 4];
        @memcpy(buf[0..stem.len], stem);
        @memcpy(buf[stem.len..][0..7], ".sha256");
        return buf[0 .. stem.len + 7];
    }
    @memcpy(buf[0..asset_name.len], asset_name);
    @memcpy(buf[asset_name.len..][0..7], ".sha256");
    return buf[0 .. asset_name.len + 7];
}

pub fn parseSha(content: []const u8) ?[64]u8 {
    var start: usize = 0;
    while (start < content.len and isWs(content[start])) start += 1;
    var end = start;
    while (end < content.len and !isWs(content[end])) end += 1;
    if (end - start != 64) return null;
    var out: [64]u8 = undefined;
    for (content[start..end], 0..) |c, i| {
        if (!std.ascii.isHex(c)) return null;
        out[i] = std.ascii.toLower(c);
    }
    return out;
}

/// Rows upserted. 404 and a release with no agent assets return 0.
pub fn run(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, options: Options) !u32 {
    const headers = [_]std.http.Header{.{ .name = "accept", .value = "application/vnd.github+json" }};
    var res = try http_get.get(allocator, io, options.url, &headers, "tawny-release-check/1.0", options.allow_private, 2 * 1024 * 1024);
    defer res.deinit(allocator);
    if (res.status == 404) {
        std.debug.print("no tawny github releases found yet; skipping agent release sync.\n", .{});
        return 0;
    }
    if (res.status < 200 or res.status >= 300) return error.ReleaseHttp;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, res.body, .{ .ignore_unknown_fields = true }) catch return error.BadJson;
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |obj| obj,
        else => return 0,
    };
    const assets_value = root.get("assets") orelse return 0;
    const assets = switch (assets_value) {
        .array => |arr| arr,
        else => return 0,
    };
    const published = switch (root.get("published_at") orelse .null) {
        .string => |s| s,
        else => "",
    };

    var copied: std.ArrayList(Asset) = .empty;
    defer {
        for (copied.items) |asset| {
            allocator.free(asset.name);
            allocator.free(asset.url);
        }
        copied.deinit(allocator);
    }
    for (assets.items) |item| {
        if (copied.items.len == 64) break;
        const obj = switch (item) {
            .object => |o| o,
            else => continue,
        };
        const name = switch (obj.get("name") orelse continue) {
            .string => |s| s,
            else => continue,
        };
        const download = switch (obj.get("browser_download_url") orelse continue) {
            .string => |s| s,
            else => continue,
        };
        try copied.append(allocator, .{
            .name = try allocator.dupe(u8, name),
            .url = try allocator.dupe(u8, download),
        });
    }

    var rows: std.ArrayList(Row) = .empty;
    defer rows.deinit(allocator);
    for (copied.items) |asset| {
        if (std.ascii.endsWithIgnoreCase(asset.name, ".sha256")) continue;
        const parsed_name = parseAsset(asset.name) orelse continue;
        var side_buf: [256]u8 = undefined;
        const side = sidecarName(&side_buf, asset.name) orelse continue;
        const side_url = findAsset(copied.items, side) orelse {
            std.debug.print("skipping release asset {s}: missing sha256 sidecar\n", .{asset.name});
            continue;
        };
        var sha_res = try http_get.get(allocator, io, side_url, &.{}, "tawny-release-check/1.0", options.allow_private, 4096);
        defer sha_res.deinit(allocator);
        if (sha_res.status < 200 or sha_res.status >= 300) return error.ReleaseHttp;
        const sha = parseSha(sha_res.body) orelse {
            std.debug.print("skipping release asset {s}: invalid sha256 sidecar\n", .{asset.name});
            continue;
        };
        try rows.append(allocator, .{
            .version = parsed_name.version,
            .platform = parsed_name.platform,
            .url = asset.url,
            .sha256 = sha,
        });
    }
    if (rows.items.len == 0) return 0;

    const nested = try inTransaction(allocator, conn);
    if (nested) try conn.execSimple("SAVEPOINT tawny_release_check") else try conn.execSimple("BEGIN");
    errdefer {
        if (nested) conn.execSimple("ROLLBACK TO SAVEPOINT tawny_release_check") catch {} else conn.execSimple("ROLLBACK") catch {};
    }

    var seen: [8][]const u8 = undefined;
    var seen_n: usize = 0;
    for (rows.items) |row| {
        var known = false;
        for (seen[0..seen_n]) |platform| if (std.mem.eql(u8, platform, row.platform)) {
            known = true;
        };
        if (known) continue;
        if (seen_n == seen.len) break;
        seen[seen_n] = row.platform;
        seen_n += 1;
        try conn.execNoRows("UPDATE agent_releases SET is_latest = false WHERE platform = $1", &.{.{ .text = row.platform }});
    }

    var released_buf: [32]u8 = undefined;
    const released = if (published.len > 0) published else util.formatRfc3339(&released_buf, options.now_unix);
    for (rows.items) |row| {
        var sha_text: [64]u8 = row.sha256;
        try conn.execNoRows(
            \\INSERT INTO agent_releases (version, platform, download_url, sha256, released_at, is_latest)
            \\VALUES ($1, $2, $3, $4, $5::timestamptz, true)
            \\ON CONFLICT (platform, version) DO UPDATE SET
            \\  download_url = EXCLUDED.download_url,
            \\  sha256 = EXCLUDED.sha256,
            \\  released_at = EXCLUDED.released_at,
            \\  is_latest = true
        , &.{
            .{ .text = row.version },
            .{ .text = row.platform },
            .{ .text = row.url },
            .{ .text = &sha_text },
            .{ .text = released },
        });
    }
    if (nested) try conn.execSimple("RELEASE SAVEPOINT tawny_release_check") else try conn.execSimple("COMMIT");
    std.debug.print("updated {d} latest tawny agent release rows.\n", .{rows.items.len});
    return @intCast(rows.items.len);
}

fn findAsset(assets: []const Asset, name: []const u8) ?[]const u8 {
    for (assets) |asset| if (std.ascii.eqlIgnoreCase(asset.name, name)) return asset.url;
    return null;
}

fn inTransaction(allocator: std.mem.Allocator, conn: *pg.Conn) !bool {
    const rows = try conn.exec(allocator, "SELECT txid_current_if_assigned()::text", &.{});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return false;
    return rows[0].cols[0] != null;
}

fn isWs(c: u8) bool {
    return c == ' ' or c == '\t' or c == '\r' or c == '\n';
}

test "agent asset names match the dotnet regex" {
    const linux = parseAsset("tawny-agent-1.2.3-linux-x64").?;
    try std.testing.expectEqualStrings("1.2.3", linux.version);
    try std.testing.expectEqualStrings("linux-x64", linux.platform);
    const win = parseAsset("tawny-agent-1.2.3-windows-x64.exe").?;
    try std.testing.expectEqualStrings("1.2.3", win.version);
    try std.testing.expectEqualStrings("windows-x64", win.platform);
    const rc = parseAsset("tawny-agent-1.2.3-rc.1-macos-arm64").?;
    try std.testing.expectEqualStrings("1.2.3-rc.1", rc.version);
    try std.testing.expectEqualStrings("macos-arm64", rc.platform);
    try std.testing.expect(parseAsset("tawny-agent-1.2.3-linux-x64.sha256") == null);
    try std.testing.expect(parseAsset("tawny-agent-linux-x64") == null);
    try std.testing.expect(parseAsset("notes.txt") == null);

    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("tawny-agent-1.2.3-windows-x64.sha256", sidecarName(&buf, "tawny-agent-1.2.3-windows-x64.exe").?);
    try std.testing.expectEqualStrings("tawny-agent-1.2.3-linux-x64.sha256", sidecarName(&buf, "tawny-agent-1.2.3-linux-x64").?);
    const sha = parseSha("ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB  tawny-agent\n").?;
    try std.testing.expectEqualStrings("abababababababababababababababababababababababababababababababab", &sha);
    try std.testing.expect(parseSha("nope") == null);
}

const rel_port = "18087";
const linux_sha = "abababababababababababababababababababababababababababababababab";
const windows_sha = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

const release_py =
    \\from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    \\import json, sys
    \\port = int(sys.argv[1])
    \\class H(BaseHTTPRequestHandler):
    \\    def do_GET(self):
    \\        if self.path.startswith("/repos/"):
    \\            if self.headers.get("User-Agent") != "tawny-release-check/1.0":
    \\                self._send(400, b"ua")
    \\                return
    \\            if "application/vnd.github+json" not in (self.headers.get("Accept") or ""):
    \\                self._send(400, b"accept")
    \\                return
    \\            base = "http://127.0.0.1:%d" % port
    \\            body = {
    \\                "tag_name": "v1.4.0-tawnytest",
    \\                "published_at": "2026-01-15T03:04:05Z",
    \\                "assets": [
    \\                    {"name": "tawny-agent-1.4.0-tawnytest-linux-x64", "browser_download_url": base + "/bin/linux"},
    \\                    {"name": "tawny-agent-1.4.0-tawnytest-linux-x64.sha256", "browser_download_url": base + "/sha/linux"},
    \\                    {"name": "tawny-agent-1.4.0-tawnytest-windows-x64.exe", "browser_download_url": base + "/bin/windows"},
    \\                    {"name": "tawny-agent-1.4.0-tawnytest-windows-x64.sha256", "browser_download_url": base + "/sha/windows"},
    \\                    {"name": "tawny-agent-1.4.0-tawnytest-linux-arm64", "browser_download_url": base + "/bin/arm"},
    \\                    {"name": "tawny-agent-1.4.0-tawnytest-macos-x64", "browser_download_url": base + "/bin/mac"},
    \\                    {"name": "tawny-agent-1.4.0-tawnytest-macos-x64.sha256", "browser_download_url": base + "/sha/mac"},
    \\                    {"name": "notes.txt", "browser_download_url": base + "/notes"},
    \\                ],
    \\            }
    \\            raw = json.dumps(body).encode()
    \\            self._send(200, raw)
    \\            return
    \\        if self.path == "/sha/linux":
    \\            self._send(200, b"ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB  tawny-agent\n")
    \\            return
    \\        if self.path == "/sha/windows":
    \\            self._send(200, b"CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD\n")
    \\            return
    \\        if self.path == "/sha/mac":
    \\            self._send(200, b"nope\n")
    \\            return
    \\        if self.path == "/missing":
    \\            self._send(404, b"")
    \\            return
    \\        self._send(404, b"")
    \\    def _send(self, status, raw):
    \\        self.send_response(status)
    \\        self.send_header("Content-Length", str(len(raw)))
    \\        self.end_headers()
    \\        self.wfile.write(raw)
    \\    def log_message(self, fmt, *args):
    \\        pass
    \\ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
;

test "release check upserts agent assets and ignores bad sidecars" {
    const url = std.testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return;
    if (url.len == 0) return;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const conn = try pg.Conn.connect(allocator, io, url);
    defer {
        conn.close();
        allocator.destroy(conn);
    }
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};
    try conn.execNoRows("DELETE FROM agent_releases WHERE version LIKE '%tawnytest%' OR version = '0.0.1-staytest'", &.{});
    try conn.execNoRows(
        \\INSERT INTO agent_releases (version, platform, download_url, sha256, released_at, is_latest)
        \\VALUES ('0.9.0-tawnytest', 'linux-x64', 'http://old', 'aa', to_timestamp(1), true)
    , &.{});
    try conn.execNoRows(
        \\INSERT INTO agent_releases (version, platform, download_url, sha256, released_at, is_latest)
        \\VALUES ('0.0.1-staytest', 'macos-arm64', 'http://stay', 'bb', to_timestamp(1), true)
    , &.{});

    var child = try std.process.spawn(io, .{
        .argv = &.{ "/usr/bin/python3", "-c", release_py, rel_port },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer child.kill(io);
    std.Io.sleep(io, .fromMilliseconds(200), .real) catch {};

    const missing = try run(allocator, io, conn, .{
        .now_unix = 2_000_000_000,
        .allow_private = true,
        .url = "http://127.0.0.1:" ++ rel_port ++ "/missing",
    });
    try std.testing.expectEqual(@as(u32, 0), missing);

    const updated = try run(allocator, io, conn, .{
        .now_unix = 2_000_000_000,
        .allow_private = true,
        .url = "http://127.0.0.1:" ++ rel_port ++ "/repos/jusso-dev/tawny/releases/latest",
    });
    const linux = try scalar(allocator, conn,
        \\SELECT version || '|' || sha256 || '|' || is_latest::text || '|' || to_char(released_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
        \\FROM agent_releases WHERE platform = 'linux-x64' AND version = '1.4.0-tawnytest'
    , &.{});
    defer allocator.free(linux);
    const old_latest = try scalar(allocator, conn, "SELECT is_latest::text FROM agent_releases WHERE version = '0.9.0-tawnytest'", &.{});
    defer allocator.free(old_latest);
    const win = try scalar(allocator, conn, "SELECT sha256 || '|' || is_latest::text FROM agent_releases WHERE platform = 'windows-x64' AND version = '1.4.0-tawnytest'", &.{});
    defer allocator.free(win);
    const stay = try scalar(allocator, conn, "SELECT is_latest::text FROM agent_releases WHERE version = '0.0.1-staytest'", &.{});
    defer allocator.free(stay);
    const skipped = try scalar(allocator, conn, "SELECT count(*)::text FROM agent_releases WHERE version = '1.4.0-tawnytest' AND platform IN ('linux-arm64', 'macos-x64')", &.{});
    defer allocator.free(skipped);

    std.debug.print("release_job updated={d} linux={s} old={s} win={s} stay={s} skipped={s}\n", .{
        updated, linux, old_latest, win, stay, skipped,
    });
    try std.testing.expectEqual(@as(u32, 2), updated);
    try std.testing.expectEqualStrings("1.4.0-tawnytest|" ++ linux_sha ++ "|true|2026-01-15T03:04:05Z", linux);
    try std.testing.expect(std.mem.eql(u8, old_latest, "f") or std.mem.eql(u8, old_latest, "false"));
    try std.testing.expectEqualStrings(windows_sha ++ "|true", win);
    try std.testing.expect(std.mem.eql(u8, stay, "t") or std.mem.eql(u8, stay, "true"));
    try std.testing.expectEqualStrings("0", skipped);
    try conn.execSimple("ROLLBACK");
    const left = try scalar(allocator, conn, "SELECT count(*)::text FROM agent_releases WHERE version LIKE '%tawnytest%' OR version = '0.0.1-staytest'", &.{});
    defer allocator.free(left);
    try std.testing.expectEqualStrings("0", left);
}

fn scalar(allocator: std.mem.Allocator, conn: *pg.Conn, sql: []const u8, params: []const pg.Value) ![]u8 {
    const rows = try conn.exec(allocator, sql, params);
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return error.NoRow;
    const col = rows[0].cols[0] orelse return error.NullColumn;
    return allocator.dupe(u8, col);
}
