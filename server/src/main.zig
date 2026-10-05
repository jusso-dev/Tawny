const std = @import("std");
const config_mod = @import("config.zig");
const pg = @import("db/pg/conn.zig");
const migrate = @import("db/migrate.zig");
const util = @import("http/util.zig");
const detect = @import("jobs/detect.zig");
const deliver = @import("jobs/deliver.zig");
const purge = @import("jobs/purge.zig");
const stale = @import("jobs/stale.zig");
const hunts = @import("jobs/hunts.zig");
const threat_intel = @import("jobs/threat_intel.zig");
const reputation = @import("jobs/reputation.zig");
const backup = @import("jobs/backup.zig");
const releases = @import("jobs/releases.zig");
const http_get = @import("jobs/http_get.zig");
const ai_reasoning = @import("jobs/ai_reasoning.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args = std.process.Args.Iterator.init(init.minimal.args);
    _ = args.next(); // argv0
    const cmd = args.next() orelse "serve";

    var cfg = try config_mod.Config.load(allocator, init.environ_map);
    defer cfg.deinit(allocator);

    if (std.mem.eql(u8, cmd, "migrate")) {
        const conn = try pg.Conn.connect(allocator, io, cfg.database_url);
        defer {
            conn.close();
            allocator.destroy(conn);
        }
        try migrate.apply(allocator, conn);
        return;
    }
    if (std.mem.eql(u8, cmd, "healthcheck")) {
        try runHealthcheck(allocator, io, cfg.http_port);
        return;
    }
    if (std.mem.eql(u8, cmd, "import-mssql")) {
        const path = args.next() orelse return error.MissingImportPath;
        const conn = try pg.Conn.connect(allocator, io, cfg.database_url);
        defer {
            conn.close();
            allocator.destroy(conn);
        }
        if (cfg.apply_migrations) try migrate.apply(allocator, conn);
        const import_mssql = @import("db/import_mssql.zig");
        try import_mssql.run(allocator, io, conn, path);
        return;
    }
    if (!std.mem.eql(u8, cmd, "serve")) return error.UnknownCommand;

    const conn = try pg.Conn.connect(allocator, io, cfg.database_url);
    defer {
        conn.close();
        allocator.destroy(conn);
    }
    if (cfg.apply_migrations) try migrate.apply(allocator, conn);

    var addr = try std.Io.net.IpAddress.resolve(io, cfg.http_host, cfg.http_port);
    var listener = try addr.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    std.debug.print("tawny-server listening on {s}:{d}\n", .{ cfg.http_host, cfg.http_port });

    const sink_targets = deliver.Targets{
        .slack_webhook = envSpan("TAWNY_SLACK_WEBHOOK_URL"),
        .wazuh_host = envSpan("TAWNY_WAZUH_HOST"),
        .wazuh_port = envPort("TAWNY_WAZUH_PORT", 514),
        .wazuh_protocol = envSpanDefault("TAWNY_WAZUH_PROTOCOL", "udp"),
        .allow_private = envFlag("TAWNY_ALLOW_PRIVATE_EGRESS"),
    };
    var last_stale: i64 = 0;
    var last_purge: i64 = 0;
    var last_hunt: i64 = 0;
    var last_ti: i64 = 0;
    var last_reputation: i64 = 0;
    var last_backup: i64 = 0;
    var last_release: i64 = 0;
    var last_ai: i64 = 0;
    // Live SSE clients outlive the accept that started them. Reaped when phase hits 2.
    var parked: [32]*Client = undefined;
    var parked_n: usize = 0;
    while (true) {
        parked_n = reapClients(allocator, &parked, parked_n);
        var stream = listener.accept(io) catch |err| {
            std.debug.print("accept failed: {s}\n", .{@errorName(err)});
            continue;
        };
        const client = allocator.create(Client) catch {
            stream.close(io);
            std.debug.print("connection failed: OutOfMemory\n", .{});
            continue;
        };
        client.* = .{
            .allocator = allocator,
            .io = io,
            .database_url = cfg.database_url,
            .stream = stream,
            .phase = .init(0),
        };
        const thread = std.Thread.spawn(.{ .stack_size = 1024 * 1024 }, serveClient, .{client}) catch |err| {
            std.debug.print("connection thread failed: {s}\n", .{@errorName(err)});
            handleConnection(allocator, io, conn, stream, &client.phase) catch |fallback_err| {
                std.debug.print("connection failed: {s}\n", .{@errorName(fallback_err)});
            };
            stream.close(io);
            allocator.destroy(client);
            runJobs(allocator, io, conn, sink_targets, &last_stale, &last_purge, &last_hunt, &last_ti, &last_reputation, &last_backup, &last_release, &last_ai);
            continue;
        };
        thread.detach();
        // Phase 0: handler has not finished a normal response and has not
        // handed the socket to the SSE loop. Phase 1: SSE owns the socket.
        // Phase 2: worker is done. Jobs run only after that handoff so a
        // live stream does not stall accept or the queue drains.
        while (client.phase.load(.acquire) == 0) {
            std.Io.sleep(io, .fromMilliseconds(1), .awake) catch {};
        }
        if (client.phase.load(.acquire) == 2) {
            allocator.destroy(client);
        } else if (parked_n < parked.len) {
            parked[parked_n] = client;
            parked_n += 1;
        } else {
            while (parked_n == parked.len) {
                parked_n = reapClients(allocator, &parked, parked_n);
                if (parked_n == parked.len) std.Io.sleep(io, .fromMilliseconds(20), .awake) catch {};
            }
            parked[parked_n] = client;
            parked_n += 1;
        }
        runJobs(allocator, io, conn, sink_targets, &last_stale, &last_purge, &last_hunt, &last_ti, &last_reputation, &last_backup, &last_release, &last_ai);
    }
}

const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    database_url: []const u8,
    stream: std.Io.net.Stream,
    /// 0 handling, 1 SSE loop owns the socket, 2 worker finished.
    phase: std.atomic.Value(u8),
};

fn reapClients(allocator: std.mem.Allocator, parked: *[32]*Client, n: usize) usize {
    var w: usize = 0;
    for (parked.*[0..n]) |client| {
        if (client.phase.load(.acquire) == 2) {
            allocator.destroy(client);
        } else {
            parked[w] = client;
            w += 1;
        }
    }
    return w;
}

fn serveClient(client: *Client) void {
    defer client.phase.store(2, .release);
    const db = pg.Conn.connect(client.allocator, client.io, client.database_url) catch |err| {
        std.debug.print("client db connect failed: {s}\n", .{@errorName(err)});
        client.stream.close(client.io);
        return;
    };
    defer client.allocator.destroy(db);
    defer db.close();
    defer client.stream.close(client.io);
    handleConnection(client.allocator, client.io, db, client.stream, &client.phase) catch |err| {
        std.debug.print("connection failed: {s}\n", .{@errorName(err)});
    };
}

fn runJobs(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    sink_targets: deliver.Targets,
    last_stale: *i64,
    last_purge: *i64,
    last_hunt: *i64,
    last_ti: *i64,
    last_reputation: *i64,
    last_backup: *i64,
    last_release: *i64,
    last_ai: *i64,
) void {
    if (detect.drain(allocator, io, conn)) |_| {} else |err| {
        std.debug.print("detect drain failed: {s}\n", .{@errorName(err)});
    }
    if (deliver.drain(allocator, io, conn, sink_targets)) |_| {} else |err| {
        std.debug.print("sink drain failed: {s}\n", .{@errorName(err)});
    }
    const now = util.nowUnix(io);
    if (now - last_purge.* >= 3600) {
        last_purge.* = now;
        var pbuf: [32]u8 = undefined;
        const stamp = util.formatRfc3339(&pbuf, now);
        purge.run(conn, stamp) catch |err| {
            std.debug.print("purge job failed: {s}\n", .{@errorName(err)});
        };
    }
    if (now - last_hunt.* >= 300) {
        last_hunt.* = now;
        if (hunts.run(allocator, io, conn, now)) |_| {} else |err| {
            std.debug.print("hunt job failed: {s}\n", .{@errorName(err)});
        }
    }
    if (now - last_ti.* >= 600) {
        last_ti.* = now;
        if (threat_intel.run(allocator, io, conn, .{
            .now_unix = now,
            .allow_private = envFlag("TAWNY_ALLOW_PRIVATE_EGRESS"),
            .secret = envSpan("TAWNY_INTEGRATION_ENCRYPTION_KEY"),
        })) |_| {} else |err| {
            std.debug.print("threat intel job failed: {s}\n", .{@errorName(err)});
        }
    }
    if (now - last_reputation.* >= 300) {
        last_reputation.* = now;
        if (reputation.run(allocator, io, conn, .{
            .now_unix = now,
            .allow_private = envFlag("TAWNY_ALLOW_PRIVATE_EGRESS"),
            .enrich = enrichOn(),
            .vt_key = envSpan("TAWNY_VIRUSTOTAL_API_KEY"),
            .abuse_key = envSpan("TAWNY_ABUSEIPDB_API_KEY"),
            .gn_key = envSpan("TAWNY_GREYNOISE_API_KEY"),
        })) |_| {} else |err| {
            std.debug.print("reputation job failed: {s}\n", .{@errorName(err)});
        }
    }
    if (now - last_backup.* >= 86400) {
        last_backup.* = now;
        if (backup.run(allocator, io, conn, .{
            .now_unix = now,
            .allow_private = envFlag("TAWNY_ALLOW_PRIVATE_EGRESS"),
            .local_path = backupLocalPath(),
            .s3_bucket = envSpan("TAWNY_BACKUP_S3_BUCKET"),
            .s3_prefix = envSpanDefault("TAWNY_BACKUP_S3_PREFIX", "telemetry"),
            .s3_region = awsRegion(),
            .s3_endpoint = envSpan("TAWNY_BACKUP_S3_ENDPOINT"),
            .access_key_id = envSpan("AWS_ACCESS_KEY_ID"),
            .secret_access_key = envSpan("AWS_SECRET_ACCESS_KEY"),
        })) |_| {} else |err| {
            std.debug.print("backup job failed: {s}\n", .{@errorName(err)});
        }
    }
    if (now - last_release.* >= 3600) {
        last_release.* = now;
        if (releases.run(allocator, io, conn, .{
            .now_unix = now,
            .allow_private = envFlag("TAWNY_ALLOW_PRIVATE_EGRESS"),
            .url = envSpanDefault("TAWNY_RELEASES_URL", "https://api.github.com/repos/jusso-dev/tawny/releases/latest"),
        })) |_| {} else |err| {
            std.debug.print("release check failed: {s}\n", .{@errorName(err)});
        }
    }
    if (now - last_stale.* >= 60) {
        last_stale.* = now;
        var tbuf: [32]u8 = undefined;
        const stamp = util.formatRfc3339(&tbuf, now);
        stale.mark(conn, stamp) catch |err| {
            std.debug.print("stale job failed: {s}\n", .{@errorName(err)});
        };
    }
    if (now - last_ai.* >= 30) {
        last_ai.* = now;
        if (ai_reasoning.drain(allocator, io, conn, .{
            .enabled = envFlag("TAWNY_AI_ENABLED"),
            .model_endpoint = envSpan("TAWNY_AI_MODEL_ENDPOINT"),
            .model_name = envSpan("TAWNY_AI_MODEL_NAME"),
            .model_api_key = envSpan("TAWNY_AI_MODEL_API_KEY"),
            .confidence_threshold = envFloat("TAWNY_AI_CONFIDENCE_THRESHOLD", 0.70),
            .allow_private_egress = envFlag("TAWNY_AI_ALLOW_PRIVATE_EGRESS"),
        })) |_| {} else |err| {
            std.debug.print("ai_reasoning job failed: {s}\n", .{@errorName(err)});
        }
    }
}

fn runHealthcheck(allocator: std.mem.Allocator, io: std.Io, port: u16) !void {
    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/api/health", .{port});
    defer allocator.free(url);
    var response = http_get.get(allocator, io, url, &.{}, "tawny-healthcheck", true, 512) catch return error.Unhealthy;
    defer response.deinit(allocator);
    if (response.status != 200) return error.Unhealthy;
    if (std.mem.indexOf(u8, response.body, "\"status\":\"ok\"") == null) return error.Unhealthy;
}

fn envSpan(key: [*:0]const u8) []const u8 {
    const raw = std.c.getenv(key) orelse return "";
    return std.mem.span(raw);
}

fn envSpanDefault(key: [*:0]const u8, fallback: []const u8) []const u8 {
    const value = envSpan(key);
    return if (value.len == 0) fallback else value;
}

fn envPort(key: [*:0]const u8, fallback: u16) u16 {
    const value = envSpan(key);
    if (value.len == 0) return fallback;
    return std.fmt.parseInt(u16, value, 10) catch fallback;
}

fn envFlag(key: [*:0]const u8) bool {
    const value = envSpan(key);
    return std.mem.eql(u8, value, "1") or std.ascii.eqlIgnoreCase(value, "true");
}

fn envFloat(key: [*:0]const u8, fallback: f32) f32 {
    const value = envSpan(key);
    if (value.len == 0) return fallback;
    return std.fmt.parseFloat(f32, value) catch fallback;
}

fn enrichOn() bool {
    const value = envSpan("TAWNY_ENRICH_ALERTS");
    if (value.len == 0) return true;
    return !(std.mem.eql(u8, value, "0") or std.ascii.eqlIgnoreCase(value, "false") or std.ascii.eqlIgnoreCase(value, "off"));
}

fn backupLocalPath() []const u8 {
    const value = envSpan("TAWNY_BACKUP_LOCAL_PATH");
    if (std.mem.eql(u8, value, "off")) return "";
    if (value.len == 0) return "backups/telemetry";
    return value;
}

fn awsRegion() []const u8 {
    const region = envSpan("AWS_REGION");
    if (region.len != 0) return region;
    return envSpanDefault("AWS_DEFAULT_REGION", "us-east-1");
}

fn handleConnection(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    stream: std.Io.net.Stream,
    phase: *std.atomic.Value(u8),
) !void {
    var rbuf: [16 * 1024]u8 = undefined;
    var wbuf: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &rbuf);
    var writer = stream.writer(io, &wbuf);
    var server = std.http.Server.init(&reader.interface, &writer.interface);
    while (true) {
        var request = server.receiveHead() catch |err| switch (err) {
            error.HttpConnectionClosing => return,
            else => return err,
        };
        const target = request.head.target;
        const path = if (std.mem.indexOfScalar(u8, target, '?')) |q| target[0..q] else target;
        if (request.head.method == .GET and std.mem.eql(u8, path, "/api/health")) {
            var tbuf: [32]u8 = undefined;
            const stamp = util.formatRfc3339(&tbuf, util.nowUnix(io));
            var body_buf: [80]u8 = undefined;
            const body = std.fmt.bufPrint(&body_buf, "{{\"status\":\"ok\",\"time\":\"{s}\"}}", .{stamp}) catch
                \\{"status":"ok"}
            ;
            try request.respond(body, .{
                .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }},
                .keep_alive = request.head.keep_alive,
            });
        } else if (request.head.method == .GET and std.mem.eql(u8, path, "/api/health/ready")) {
            const ready = readyBody(allocator, conn);
            const body = ready.body;
            try request.respond(body, .{
                .status = if (ready.ok) .ok else .service_unavailable,
                .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }},
                .keep_alive = request.head.keep_alive,
            });
        } else if (!std.mem.startsWith(u8, path, "/api")) {
            const static_files = @import("http/static.zig");
            try static_files.serve(allocator, io, &request, envSpanDefault("TAWNY_UI_DIR", "ui"));
        } else {
            const dispatch = @import("http/dispatch.zig");
            try dispatch.handle(allocator, io, conn, &request, phase);
        }
        if (!request.head.keep_alive) return;
    }
}

const Ready = struct { ok: bool, body: []const u8 };

fn readyBody(allocator: std.mem.Allocator, conn: *pg.Conn) Ready {
    const ping = conn.exec(allocator, "SELECT 1", &.{}) catch {
        return .{ .ok = false, .body = "{\"status\":\"not_ready\",\"database\":\"unreachable\",\"migrations\":\"unknown\"}" };
    };
    defer {
        for (ping) |row| row.deinit(allocator);
        allocator.free(ping);
    }
    const current = migrate.migrationsCurrent(allocator, conn) catch {
        return .{ .ok = false, .body = "{\"status\":\"not_ready\",\"database\":\"reachable\",\"migrations\":\"unknown\"}" };
    };
    if (!current) {
        return .{ .ok = false, .body = "{\"status\":\"not_ready\",\"database\":\"reachable\",\"migrations\":\"behind\"}" };
    }
    return .{ .ok = true, .body = "{\"status\":\"ready\",\"database\":\"reachable\",\"migrations\":\"current\"}" };
}

comptime {
    _ = @import("crypto/jwt.zig");
    _ = @import("crypto/secret_box.zig");
    _ = @import("crypto/sigv4.zig");
    _ = @import("crypto/passwords.zig");
    _ = @import("crypto/rsa_pem.zig");
    _ = @import("db/integration.zig");
    _ = @import("db/import_mssql.zig");
    _ = @import("http/dispatch.zig");
    _ = @import("http/state.zig");
    _ = @import("http/auth.zig");
    _ = @import("http/util.zig");
    _ = @import("http/static.zig");
    _ = @import("routes/admin_jobs.zig");
    _ = @import("routes/agent_releases.zig");
    _ = @import("routes/alerts.zig");
    _ = @import("routes/agents.zig");
    _ = @import("routes/auth.zig");
    _ = @import("routes/users.zig");
    _ = @import("routes/github.zig");
    _ = @import("jobs/detect.zig");
    _ = @import("detect/package_exposure.zig");
    _ = @import("detect/exposure_import.zig");
    _ = @import("routes/hunts.zig");
    _ = @import("routes/feeds.zig");
    _ = @import("routes/lookup.zig");
    _ = @import("routes/suppressions.zig");
    _ = @import("jobs/deliver.zig");
    _ = @import("jobs/purge.zig");
    _ = @import("jobs/stale.zig");
    _ = @import("jobs/hunts.zig");
    _ = @import("hunts/query.zig");
    _ = @import("jobs/threat_intel.zig");
    _ = @import("jobs/http_get.zig");
    _ = @import("jobs/reputation.zig");
    _ = @import("jobs/backup.zig");
    _ = @import("jobs/releases.zig");
    _ = @import("intel/feeds.zig");
    _ = @import("sinks/wazuh.zig");
    _ = @import("sinks/sentinel.zig");
    _ = @import("sinks/slack.zig");
    _ = @import("sinks/tawny_soc.zig");
    _ = @import("sinks/egress.zig");
    _ = @import("ai/reasoning.zig");
    _ = @import("jobs/ai_reasoning.zig");
    _ = @import("routes/ai.zig");
    _ = @import("fuzz.zig");
}
