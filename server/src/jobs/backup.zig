//! Daily gzip JSONL backup of telemetry received in the last 24 hours.
//! Local file and/or S3 PutObject (SigV4). Matches BackupTelemetryJob.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const sigv4 = @import("../crypto/sigv4.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;
const egress = @import("../sinks/egress.zig");

pub const Options = struct {
    now_unix: i64,
    allow_private: bool = false,
    local_path: []const u8 = "",
    s3_bucket: []const u8 = "",
    s3_prefix: []const u8 = "telemetry",
    s3_region: []const u8 = "us-east-1",
    s3_endpoint: []const u8 = "",
    access_key_id: []const u8 = "",
    secret_access_key: []const u8 = "",
};

pub fn fileName(buf: *[48]u8, now_unix: i64) []const u8 {
    var rfc_buf: [32]u8 = undefined;
    const rfc = util.formatRfc3339(&rfc_buf, now_unix);
    // 2026-10-04T12:00:00Z -> telemetry-20261004120000Z.jsonl.gz
    const stamp = buf[0..48];
    const prefix = "telemetry-";
    @memcpy(stamp[0..prefix.len], prefix);
    var n: usize = prefix.len;
    for (rfc[0..19]) |c| {
        if (c == '-' or c == ':' or c == 'T') continue;
        stamp[n] = c;
        n += 1;
    }
    const suffix = "Z.jsonl.gz";
    @memcpy(stamp[n..][0..suffix.len], suffix);
    return stamp[0 .. n + suffix.len];
}

/// Events written. Zero when neither a local path nor a bucket is set.
pub fn run(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, options: Options) !u32 {
    const local = std.mem.trim(u8, options.local_path, &std.ascii.whitespace);
    const bucket = std.mem.trim(u8, options.s3_bucket, &std.ascii.whitespace);
    if (local.len == 0 and bucket.len == 0) return 0;

    var since_buf: [32]u8 = undefined;
    var now_buf: [32]u8 = undefined;
    const since = try std.fmt.bufPrint(&since_buf, "{d}", .{options.now_unix - 24 * 3600});
    const now = try std.fmt.bufPrint(&now_buf, "{d}", .{options.now_unix});
    const rows = try conn.exec(allocator,
        \\SELECT id::text, agent_id::text, event_type,
        \\       to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        \\       to_char(received_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        \\       payload::text
        \\FROM telemetry_events
        \\WHERE received_at >= to_timestamp($1::bigint) AND received_at <= to_timestamp($2::bigint)
        \\ORDER BY received_at, id
    , &.{ .{ .text = since }, .{ .text = now } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }

    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(allocator);
    for (rows) |row| {
        const id = row.cols[0] orelse continue;
        const agent = row.cols[1] orelse continue;
        const kind = row.cols[2] orelse continue;
        const occurred = row.cols[3] orelse continue;
        const received = row.cols[4] orelse continue;
        const payload = row.cols[5] orelse "{}";
        try plain.appendSlice(allocator, "{\"id\":");
        try plain.appendSlice(allocator, id);
        try plain.appendSlice(allocator, ",\"agent_id\":");
        try appendJsonString(&plain, allocator, agent);
        try plain.appendSlice(allocator, ",\"type\":");
        if (eventTypeNumber(kind)) |n| {
            var tmp: [8]u8 = undefined;
            try plain.appendSlice(allocator, try std.fmt.bufPrint(&tmp, "{d}", .{n}));
        } else {
            try appendJsonString(&plain, allocator, kind);
        }
        try plain.appendSlice(allocator, ",\"occurred_at\":");
        try appendJsonString(&plain, allocator, occurred);
        try plain.appendSlice(allocator, ",\"received_at\":");
        try appendJsonString(&plain, allocator, received);
        try plain.appendSlice(allocator, ",\"payload\":");
        try plain.appendSlice(allocator, payload);
        try plain.appendSlice(allocator, "}\n");
    }

    const gzipped = try gzipBytes(allocator, plain.items);
    defer allocator.free(gzipped);
    var name_buf: [48]u8 = undefined;
    const name = fileName(&name_buf, options.now_unix);

    if (local.len > 0) {
        try std.Io.Dir.cwd().createDirPath(io, local);
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ local, name });
        defer allocator.free(path);
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = gzipped });
        std.debug.print("backed up {d} telemetry events to {s}.\n", .{ rows.len, path });
    }
    if (bucket.len > 0) {
        const key = try objectKey(allocator, options.s3_prefix, name);
        defer allocator.free(key);
        try putObject(allocator, io, options, bucket, key, gzipped);
        std.debug.print("backed up {d} telemetry events to s3://{s}/{s}.\n", .{ rows.len, bucket, key });
    }
    return @intCast(rows.len);
}

fn eventTypeNumber(kind: []const u8) ?u8 {
    const names = [_][]const u8{
        "process_snapshot",
        "network_snapshot",
        "user_session",
        "system_info",
        "file_integrity",
        "heartbeat",
        "dns_query",
        "process_launch",
        "file_event",
        "package_inventory",
        "editor_extension",
        "browser_extension",
        "mcp_config",
    };
    for (names, 0..) |name, i| if (std.mem.eql(u8, name, kind)) return @intCast(i);
    return null;
}

fn objectKey(allocator: std.mem.Allocator, prefix: []const u8, name: []const u8) ![]u8 {
    var trimmed = std.mem.trim(u8, prefix, &std.ascii.whitespace);
    while (trimmed.len > 0 and trimmed[0] == '/') trimmed = trimmed[1..];
    while (trimmed.len > 0 and trimmed[trimmed.len - 1] == '/') trimmed = trimmed[0 .. trimmed.len - 1];
    if (trimmed.len == 0) return allocator.dupe(u8, name);
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ trimmed, name });
}

fn putObject(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    bucket: []const u8,
    key: []const u8,
    body: []u8,
) !void {
    if (options.access_key_id.len == 0 or options.secret_access_key.len == 0) return error.MissingCredentials;
    const endpoint = std.mem.trim(u8, options.s3_endpoint, &std.ascii.whitespace);
    var url: std.ArrayList(u8) = .empty;
    defer url.deinit(allocator);
    if (endpoint.len == 0) {
        try url.appendSlice(allocator, "https://");
        try url.appendSlice(allocator, bucket);
        try url.appendSlice(allocator, ".s3.");
        try url.appendSlice(allocator, options.s3_region);
        try url.appendSlice(allocator, ".amazonaws.com/");
        try url.appendSlice(allocator, key);
    } else {
        var base = endpoint;
        while (base.len > 0 and base[base.len - 1] == '/') base = base[0 .. base.len - 1];
        try url.appendSlice(allocator, base);
        try url.append(allocator, '/');
        try url.appendSlice(allocator, bucket);
        try url.append(allocator, '/');
        try url.appendSlice(allocator, key);
    }
    const uri = std.Uri.parse(url.items) catch return error.BadUrl;
    var host_name_buf: [std.Io.net.HostName.max_len]u8 = undefined;
    const host_name = std.Io.net.HostName.fromUri(uri, &host_name_buf) catch return error.BadUrl;
    const https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
    const port: u16 = uri.port orelse if (https) 443 else 80;
    if (!egress.allowed(host_name.bytes, options.allow_private)) return error.EgressRefused;
    var host_buf: [std.Io.net.HostName.max_len + 8]u8 = undefined;
    const host = if ((https and port == 443) or (!https and port == 80))
        host_name.bytes
    else
        try std.fmt.bufPrint(&host_buf, "{s}:{d}", .{ host_name.bytes, port });

    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(body, &digest, .{});
    const payload_hex = std.fmt.bytesToHex(&digest, .lower);
    var date_buf: [16]u8 = undefined;
    const amz_date = amzDate(&date_buf, options.now_unix);
    const path = switch (uri.path) {
        .raw, .percent_encoded => |p| p,
    };
    const headers = [_]sigv4.Header{
        .{ .name = "content-type", .value = "application/gzip" },
        .{ .name = "host", .value = host },
        .{ .name = "x-amz-content-sha256", .value = &payload_hex },
        .{ .name = "x-amz-date", .value = amz_date },
    };
    var signed = try sigv4.sign(allocator, .{
        .method = "PUT",
        .uri = path,
        .query = "",
        .headers = &headers,
        .payload = body,
        .access_key_id = options.access_key_id,
        .secret_access_key = options.secret_access_key,
        .region = options.s3_region,
        .service = "s3",
        .amz_date = amz_date,
    });
    defer signed.deinit(allocator);

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();
    const extra = [_]std.http.Header{
        .{ .name = "x-amz-date", .value = amz_date },
        .{ .name = "x-amz-content-sha256", .value = &payload_hex },
    };
    var req = client.request(.PUT, uri, .{
        .keep_alive = false,
        .redirect_behavior = .unhandled,
        .headers = .{
            .host = .{ .override = host },
            .authorization = .{ .override = signed.authorization },
            .content_type = .{ .override = "application/gzip" },
            .user_agent = .{ .override = "tawny-backup/1.0" },
            .accept_encoding = .{ .override = "identity" },
        },
        .extra_headers = &extra,
    }) catch |err| return err;
    defer req.deinit();
    req.sendBodyComplete(body) catch |err| return err;
    var redirect_buf: [256]u8 = undefined;
    var response = req.receiveHead(&redirect_buf) catch |err| return err;
    const code: u16 = @intCast(@intFromEnum(response.head.status));
    var discard: [64]u8 = undefined;
    var sink = std.Io.Writer.fixed(&discard);
    var transfer_buffer: [64]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    const reader = response.readerDecompressing(&transfer_buffer, &decompress, &.{});
    _ = reader.streamRemaining(&sink) catch {};
    if (code < 200 or code >= 300) return error.S3Rejected;
}

fn amzDate(buf: *[16]u8, unix_s: i64) []const u8 {
    var rfc_buf: [32]u8 = undefined;
    const rfc = util.formatRfc3339(&rfc_buf, unix_s);
    @memcpy(buf[0..4], rfc[0..4]);
    @memcpy(buf[4..6], rfc[5..7]);
    @memcpy(buf[6..8], rfc[8..10]);
    buf[8] = 'T';
    @memcpy(buf[9..11], rfc[11..13]);
    @memcpy(buf[11..13], rfc[14..16]);
    @memcpy(buf[13..15], rfc[17..19]);
    buf[15] = 'Z';
    return buf;
}

fn gzipBytes(allocator: std.mem.Allocator, plain: []const u8) ![]u8 {
    var aw = try std.Io.Writer.Allocating.initCapacity(allocator, @max(plain.len + 64, 256));
    errdefer aw.deinit();
    const window = try allocator.alloc(u8, std.compress.flate.max_window_len);
    defer allocator.free(window);
    const comp = try allocator.create(std.compress.flate.Compress);
    defer allocator.destroy(comp);
    comp.* = try std.compress.flate.Compress.init(&aw.writer, window, .gzip, .best);
    try comp.writer.writeAll(plain);
    try comp.finish();
    return try aw.toOwnedSlice();
}

fn appendJsonString(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    try buf.append(allocator, '"');
    for (text) |c| switch (c) {
        '"' => try buf.appendSlice(allocator, "\\\""),
        '\\' => try buf.appendSlice(allocator, "\\\\"),
        else => try buf.append(allocator, c),
    };
    try buf.append(allocator, '"');
}

fn gunzip(allocator: std.mem.Allocator, compressed: []const u8) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(allocator);
    errdefer aw.deinit();
    var in: std.Io.Reader = .fixed(compressed);
    var decompress: std.compress.flate.Decompress = .init(&in, .gzip, &.{});
    _ = try decompress.reader.streamRemaining(&aw.writer);
    return try aw.toOwnedSlice();
}

test "backup file name uses utc timestamp" {
    var buf: [48]u8 = undefined;
    try std.testing.expectEqualStrings("telemetry-20330518033320Z.jsonl.gz", fileName(&buf, 2_000_000_000));
}

const default_tenant = "00000000-0000-0000-0000-000000000001";
const backup_agent = "00000000-0000-0000-0000-00000000b901";
const backup_now: i64 = 2_000_000_000;
const s3_port = "18086";

const s3_py =
    \\from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    \\import sys
    \\port = int(sys.argv[1])
    \\body_path = sys.argv[2]
    \\meta_path = sys.argv[3]
    \\class H(BaseHTTPRequestHandler):
    \\    def do_PUT(self):
    \\        n = int(self.headers.get("Content-Length") or 0)
    \\        body = self.rfile.read(n)
    \\        open(body_path, "wb").write(body)
    \\        meta = "\n".join([
    \\            self.path,
    \\            self.headers.get("Authorization") or "",
    \\            self.headers.get("Content-Type") or "",
    \\            self.headers.get("x-amz-date") or "",
    \\            self.headers.get("x-amz-content-sha256") or "",
    \\            self.headers.get("Host") or "",
    \\        ])
    \\        open(meta_path, "w").write(meta)
    \\        self.send_response(200)
    \\        self.send_header("Content-Length", "0")
    \\        self.end_headers()
    \\    def log_message(self, fmt, *args):
    \\        pass
    \\ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
;

test "telemetry backup writes gzip jsonl locally and to s3" {
    const url = std.testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return;
    if (url.len == 0) return;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const conn = try pg.Conn.connect(allocator, io, url);
    defer {
        conn.close();
        allocator.destroy(conn);
    }
    try std.testing.expectEqual(@as(u32, 0), try run(allocator, io, conn, .{ .now_unix = backup_now }));

    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};
    try conn.execNoRows(
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version, architecture, enrolled_at, status
        \\) VALUES ($1::uuid, $2::uuid, 'backup-host', 'linux', 'test', '0', 'arm64', to_timestamp(2000000000), 'online')
    , &.{ .{ .text = backup_agent }, .{ .text = default_tenant } });
    var recent_buf: [32]u8 = undefined;
    var old_buf: [32]u8 = undefined;
    const recent = try std.fmt.bufPrint(&recent_buf, "{d}", .{backup_now - 5});
    const old = try std.fmt.bufPrint(&old_buf, "{d}", .{backup_now - 24 * 3600 - 10});
    try conn.execNoRows(
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES (to_timestamp($3::bigint), $1::uuid, $2::uuid, 'process_launch', to_timestamp($3::bigint), '{"path":"backup-marker"}')
    , &.{ .{ .text = default_tenant }, .{ .text = backup_agent }, .{ .text = recent } });
    try conn.execNoRows(
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES (to_timestamp($3::bigint), $1::uuid, $2::uuid, 'file_event', to_timestamp($3::bigint), '{"path":"old-backup-marker"}')
    , &.{ .{ .text = default_tenant }, .{ .text = backup_agent }, .{ .text = old } });

    try std.Io.Dir.cwd().createDirPath(io, "zig-out");
    var child = try std.process.spawn(io, .{
        .argv = &.{ "/usr/bin/python3", "-c", s3_py, s3_port, "zig-out/backup-s3.bin", "zig-out/backup-s3.txt" },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer child.kill(io);
    std.Io.sleep(io, .fromMilliseconds(200), .real) catch {};

    const wrote = try run(allocator, io, conn, .{
        .now_unix = backup_now,
        .allow_private = true,
        .local_path = "zig-out/backup-job-test",
        .s3_bucket = "tawny-backup-test",
        .s3_prefix = "telemetry",
        .s3_region = "us-east-1",
        .s3_endpoint = "http://127.0.0.1:" ++ s3_port,
        .access_key_id = "AKIATEST",
        .secret_access_key = "secretTEST",
    });
    var name_buf: [48]u8 = undefined;
    const name = fileName(&name_buf, backup_now);
    const local_path = try std.fmt.allocPrint(allocator, "zig-out/backup-job-test/{s}", .{name});
    defer allocator.free(local_path);
    const local = try std.Io.Dir.cwd().readFileAlloc(io, local_path, allocator, std.Io.Limit.limited(1 << 20));
    defer allocator.free(local);
    const remote = try std.Io.Dir.cwd().readFileAlloc(io, "zig-out/backup-s3.bin", allocator, std.Io.Limit.limited(1 << 20));
    defer allocator.free(remote);
    const meta = try std.Io.Dir.cwd().readFileAlloc(io, "zig-out/backup-s3.txt", allocator, std.Io.Limit.limited(8192));
    defer allocator.free(meta);
    const plain = try gunzip(allocator, local);
    defer allocator.free(plain);

    std.debug.print("backup_job wrote={d} bytes={d} plain={s} meta={s}\n", .{ wrote, local.len, plain, meta });
    try std.testing.expectEqual(@as(u32, 1), wrote);
    try std.testing.expectEqualSlices(u8, local, remote);
    try std.testing.expect(local.len > 2 and local[0] == 0x1f and local[1] == 0x8b);
    try std.testing.expect(std.mem.indexOf(u8, plain, "\"type\":7") != null);
    try std.testing.expect(std.mem.indexOf(u8, plain, "backup-marker") != null);
    try std.testing.expect(std.mem.indexOf(u8, plain, "old-backup-marker") == null);
    try std.testing.expect(std.mem.indexOf(u8, plain, backup_agent) != null);
    try std.testing.expect(std.mem.startsWith(u8, meta, "/tawny-backup-test/telemetry/"));
    try std.testing.expect(std.mem.indexOf(u8, meta, "AWS4-HMAC-SHA256 Credential=AKIATEST/") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta, "application/gzip") != null);
    try conn.execSimple("ROLLBACK");
}
