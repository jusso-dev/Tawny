//! Threat-intel feeds. Every enabled feed whose interval has elapsed is
//! fetched (If-None-Match). Generic CSV is capped at 5,000 indicators and
//! materialised as IoC rules keyed `ti-feed:{id}:{kind}:{value}`. OSV feeds
//! (`osv`, `osv_vulnerabilities`) become package_exposure rules.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const feeds = @import("../intel/feeds.zig");
const package_exposure = @import("../detect/package_exposure.zig");
const egress = @import("../sinks/egress.zig");
const secrets = @import("../crypto/secret_box.zig");

pub const Options = struct {
    now_unix: i64,
    allow_private: bool = false,
    secret: []const u8 = "",
};

const Starter = struct {
    name: []const u8,
    url: []const u8,
    severity: []const u8,
    interval_minutes: i32,
    enabled: bool,
};

const starters = [_]Starter{
    .{ .name = "Feodo Tracker Botnet C2 IPs", .url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt", .severity = "high", .interval_minutes = 60, .enabled = true },
    .{ .name = "OpenPhish Community Phishing URLs", .url = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", .severity = "high", .interval_minutes = 60, .enabled = true },
    .{ .name = "PhishTank Online Valid Phishing URLs", .url = "https://data.phishtank.com/data/online-valid.csv", .severity = "high", .interval_minutes = 120, .enabled = false },
    .{ .name = "Emerging Threats Compromised IPs", .url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", .severity = "medium", .interval_minutes = 120, .enabled = false },
    .{ .name = "Blocklist.de Recent Attackers", .url = "https://lists.blocklist.de/lists/all.txt", .severity = "medium", .interval_minutes = 60, .enabled = false },
};

pub fn run(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, options: Options) !u32 {
    _ = try ensureSeeded(allocator, io, conn);
    var stamp_buf: [32]u8 = undefined;
    const stamp = util.formatRfc3339(&stamp_buf, options.now_unix);
    const rows = try conn.exec(allocator,
        \\SELECT id::text, tenant_id::text, name, kind, url,
        \\       auth_header_name, auth_header_value_encrypted,
        \\       default_severity, interval_minutes::text, etag,
        \\       extract(epoch from last_run_at)::bigint::text
        \\FROM threat_intel_feeds
        \\WHERE is_enabled
    , &.{});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    var ran: u32 = 0;
    for (rows) |row| {
        const id = row.cols[0] orelse continue;
        const interval = std.fmt.parseInt(i64, row.cols[8] orelse "60", 10) catch 60;
        const last = if (row.cols[10]) |raw| std.fmt.parseInt(i64, raw, 10) catch null else null;
        if (last != null and options.now_unix - last.? < interval * 60) continue;
        runOne(allocator, io, conn, options, stamp, row) catch |err| {
            std.debug.print("ti feed {s} failed: {s}\n", .{ id, @errorName(err) });
            markFailed(conn, id, stamp, @errorName(err)) catch {};
        };
        ran += 1;
    }
    return ran;
}

pub fn ensureSeeded(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn) !u32 {
    const tenants = try conn.exec(allocator, "SELECT id::text FROM tenants", &.{});
    defer {
        for (tenants) |row| row.deinit(allocator);
        allocator.free(tenants);
    }
    var added: u32 = 0;
    for (tenants) |tenant_row| {
        const tenant = tenant_row.cols[0] orelse continue;
        const existing = try conn.exec(allocator, "SELECT url FROM threat_intel_feeds WHERE tenant_id = $1::uuid", &.{.{ .text = tenant }});
        defer {
            for (existing) |row| row.deinit(allocator);
            allocator.free(existing);
        }
        for (starters) |starter| {
            var known = false;
            for (existing) |row| {
                const url = row.cols[0] orelse continue;
                if (std.ascii.eqlIgnoreCase(url, starter.url)) known = true;
            }
            if (known) continue;
            var idbuf: [36]u8 = undefined;
            const id = util.newUuid(io, &idbuf);
            const minutes = try std.fmt.allocPrint(allocator, "{d}", .{starter.interval_minutes});
            defer allocator.free(minutes);
            const enabled: []const u8 = if (starter.enabled) "true" else "false";
            try conn.execNoRows(
                \\INSERT INTO threat_intel_feeds (
                \\  id, tenant_id, name, kind, url, default_severity, is_enabled,
                \\  interval_minutes, status, created_at, updated_at
                \\) VALUES (
                \\  $1::uuid, $2::uuid, $3, 'generic_csv', $4, $5, $6::boolean,
                \\  $7::int, 'never_run', now(), now()
                \\)
            , &.{
                .{ .text = id },
                .{ .text = tenant },
                .{ .text = starter.name },
                .{ .text = starter.url },
                .{ .text = starter.severity },
                .{ .text = enabled },
                .{ .text = minutes },
            });
            added += 1;
        }
    }
    if (added > 0) std.debug.print("ti seeded {d}\n", .{added});
    return added;
}

const FeedRow = pg.Row;

fn runOne(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    options: Options,
    stamp: []const u8,
    row: FeedRow,
) !void {
    const id = row.cols[0] orelse return;
    const tenant = row.cols[1] orelse return;
    const name = row.cols[2] orelse "feed";
    const kind = row.cols[3] orelse "generic_csv";
    const url = row.cols[4] orelse return;
    const auth_name = row.cols[5] orelse "";
    const auth_stored = row.cols[6];
    const severity = row.cols[7] orelse "high";
    const etag = row.cols[9];

    try conn.execNoRows(
        "UPDATE threat_intel_feeds SET last_run_at = $2::timestamptz, updated_at = $2::timestamptz WHERE id = $1::uuid",
        &.{ .{ .text = id }, .{ .text = stamp } },
    );

    var header_value: []u8 = "";
    var header_owned = false;
    defer if (header_owned) allocator.free(header_value);
    if (auth_stored) |stored| {
        if (stored.len > 0 and secrets.isProtected(stored)) {
            if (options.secret.len == 0) return error.MissingSecret;
            header_value = try secrets.unprotect(allocator, options.secret, stored);
            header_owned = true;
        } else if (stored.len > 0) {
            header_value = try allocator.dupe(u8, stored);
            header_owned = true;
            if (options.secret.len > 0) {
                const boxed = try secrets.protect(allocator, options.secret, stored, io);
                defer allocator.free(boxed);
                try conn.execNoRows(
                    "UPDATE threat_intel_feeds SET auth_header_value_encrypted = $2, updated_at = $3::timestamptz WHERE id = $1::uuid",
                    &.{ .{ .text = id }, .{ .text = boxed }, .{ .text = stamp } },
                );
            }
        }
    }

    var fetched = try fetchFeed(allocator, io, url, etag, auth_name, header_value, options.allow_private);
    defer fetched.deinit(allocator);
    if (fetched.fail) |msg| {
        try markFailed(conn, id, stamp, msg);
        return;
    }
    if (!fetched.modified) {
        try conn.execNoRows(
            \\UPDATE threat_intel_feeds
            \\SET status = 'healthy', last_success_at = $2::timestamptz, last_error = NULL, updated_at = $2::timestamptz
            \\WHERE id = $1::uuid
        , &.{ .{ .text = id }, .{ .text = stamp } });
        return;
    }
    if (isOsvKind(kind)) {
        var parsed = feeds.parseOsv(allocator, fetched.body) catch {
            try markFailed(conn, id, stamp, "OSV parse failed");
            return;
        };
        defer parsed.deinit(allocator);
        const imported = try materialiseExposures(allocator, io, conn, tenant, id, name, severity, stamp, parsed.exposures);
        const imported_txt = try std.fmt.allocPrint(allocator, "{d}", .{parsed.exposures.len});
        defer allocator.free(imported_txt);
        const etag_value: []const u8 = fetched.etag orelse "";
        try markHealthy(conn, id, stamp, imported_txt, "0", etag_value);
        std.debug.print("ti feed {s} imported {d} new {d}\n", .{ name, parsed.exposures.len, imported });
        return;
    }
    if (!std.mem.eql(u8, kind, "generic_csv")) {
        try markFailed(conn, id, stamp, "Unsupported feed kind");
        return;
    }
    var parsed = try feeds.parseGenericCsv(allocator, fetched.body);
    defer parsed.deinit(allocator);
    const imported = try materialise(allocator, io, conn, tenant, id, name, severity, stamp, parsed.indicators);
    const etag_value: []const u8 = fetched.etag orelse "";
    const imported_txt = try std.fmt.allocPrint(allocator, "{d}", .{parsed.indicators.len});
    defer allocator.free(imported_txt);
    const skipped_txt = try std.fmt.allocPrint(allocator, "{d}", .{parsed.skipped});
    defer allocator.free(skipped_txt);
    try markHealthy(conn, id, stamp, imported_txt, skipped_txt, etag_value);
    std.debug.print("ti feed {s} imported {d} new {d}\n", .{ name, parsed.indicators.len, imported });
}

fn isOsvKind(kind: []const u8) bool {
    return std.ascii.eqlIgnoreCase(kind, "osv") or std.ascii.eqlIgnoreCase(kind, "osv_vulnerabilities");
}

fn markHealthy(
    conn: *pg.Conn,
    id: []const u8,
    stamp: []const u8,
    imported: []const u8,
    skipped: []const u8,
    etag: []const u8,
) !void {
    try conn.execNoRows(
        \\UPDATE threat_intel_feeds
        \\SET status = 'healthy', last_success_at = $2::timestamptz, last_error = NULL,
        \\    last_imported_count = $3::int, last_skipped_count = $4::int,
        \\    etag = NULLIF($5, ''), updated_at = $2::timestamptz
        \\WHERE id = $1::uuid
    , &.{
        .{ .text = id },
        .{ .text = stamp },
        .{ .text = imported },
        .{ .text = skipped },
        .{ .text = etag },
    });
}

fn materialise(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    tenant: []const u8,
    feed_id: []const u8,
    feed_name: []const u8,
    severity: []const u8,
    stamp: []const u8,
    indicators: []const feeds.Indicator,
) !u32 {
    const like = try std.fmt.allocPrint(allocator, "ti-feed:{s}:%", .{feed_id});
    defer allocator.free(like);
    const existing = try conn.exec(allocator,
        \\SELECT external_id FROM alert_rules
        \\WHERE tenant_id = $1::uuid AND external_id ILIKE $2
    , &.{ .{ .text = tenant }, .{ .text = like } });
    defer {
        for (existing) |row| row.deinit(allocator);
        allocator.free(existing);
    }
    var created: u32 = 0;
    for (indicators) |ind| {
        const compiled = compileKind(ind.kind) orelse continue;
        const lower = try toLower(allocator, ind.value);
        defer allocator.free(lower);
        const external = try std.fmt.allocPrint(allocator, "ti-feed:{s}:{s}:{s}", .{ feed_id, ind.kind, lower });
        defer allocator.free(external);
        var seen = false;
        for (existing) |row| {
            const have = row.cols[0] orelse continue;
            if (std.ascii.eqlIgnoreCase(have, external)) seen = true;
        }
        if (seen) continue;
        var idbuf: [36]u8 = undefined;
        const rule_id = util.newUuid(io, &idbuf);
        const rule_name = try std.fmt.allocPrint(allocator, "TI feed {s}: {s} {s}", .{ feed_name, ind.kind, ind.value });
        defer allocator.free(rule_name);
        try conn.execNoRows(
            \\INSERT INTO alert_rules (
            \\  id, tenant_id, name, format, external_id, description, event_type,
            \\  severity, operator, payload_path, match_value, is_enabled, created_at, updated_at
            \\) VALUES (
            \\  $1::uuid, $2::uuid, $3, 'ioc', $4, $5, $6,
            \\  $7, 'equals', $8, $9, true, $10::timestamptz, $10::timestamptz
            \\)
        , &.{
            .{ .text = rule_id },
            .{ .text = tenant },
            .{ .text = rule_name },
            .{ .text = external },
            .{ .text = ind.description },
            .{ .text = compiled.event_type },
            .{ .text = severity },
            .{ .text = compiled.path },
            .{ .text = ind.value },
            .{ .text = stamp },
        });
        created += 1;
    }
    return created;
}

const Compiled = struct { event_type: []const u8, path: []const u8 };

fn materialiseExposures(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    tenant: []const u8,
    feed_id: []const u8,
    feed_name: []const u8,
    severity: []const u8,
    stamp: []const u8,
    exposures: []const feeds.Exposure,
) !u32 {
    const like = try std.fmt.allocPrint(allocator, "ti-feed:{s}:%", .{feed_id});
    defer allocator.free(like);
    const existing = try conn.exec(allocator,
        \\SELECT external_id FROM alert_rules
        \\WHERE tenant_id = $1::uuid AND external_id ILIKE $2
    , &.{ .{ .text = tenant }, .{ .text = like } });
    defer {
        for (existing) |row| row.deinit(allocator);
        allocator.free(existing);
    }
    var created: u32 = 0;
    for (exposures) |exposure| {
        const display = exposure.version_pattern orelse "any";
        var external = try std.fmt.allocPrint(allocator, "ti-feed:{s}:exposure:{s}:{s}:{s}", .{
            feed_id, exposure.ecosystem, exposure.name, display,
        });
        defer allocator.free(external);
        if (exposure.advisory_id) |advisory| {
            if (advisory.len > 0) {
                const with_advisory = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ external, advisory });
                allocator.free(external);
                external = with_advisory;
            }
        }
        if (external.len > 128) {
            const cut = try allocator.dupe(u8, external[0..128]);
            allocator.free(external);
            external = cut;
        }
        var seen = false;
        for (existing) |row| {
            const have = row.cols[0] orelse continue;
            if (std.ascii.eqlIgnoreCase(have, external)) seen = true;
        }
        if (seen) continue;
        var idbuf: [36]u8 = undefined;
        const rule_id = util.newUuid(io, &idbuf);
        const rule_name = try std.fmt.allocPrint(allocator, "OSV: {s}/{s} {s}", .{ exposure.ecosystem, exposure.name, display });
        defer allocator.free(rule_name);
        var fallback: ?[]u8 = null;
        defer if (fallback) |value| allocator.free(value);
        const description: []const u8 = if (exposure.summary) |summary|
            summary
        else blk: {
            fallback = try std.fmt.allocPrint(allocator, "OSV exposure from {s}: {s}/{s} {s}.", .{
                feed_name, exposure.ecosystem, exposure.name, display,
            });
            break :blk fallback.?;
        };
        const definition = try package_exposure.serializeDefinition(
            allocator,
            exposure.ecosystem,
            exposure.name,
            exposure.version_pattern,
            exposure.advisory_id,
            exposure.advisory_url,
        );
        defer allocator.free(definition);
        try conn.execNoRows(
            \\INSERT INTO alert_rules (
            \\  id, tenant_id, name, format, external_id, description, event_type,
            \\  severity, operator, source_definition, is_enabled, created_at, updated_at
            \\) VALUES (
            \\  $1::uuid, $2::uuid, $3, 'package_exposure', $4, $5, $6,
            \\  $7, 'exists', $8, true, $9::timestamptz, $9::timestamptz
            \\)
        , &.{
            .{ .text = rule_id },
            .{ .text = tenant },
            .{ .text = rule_name },
            .{ .text = external },
            .{ .text = description },
            .{ .text = exposureEventType(exposure.ecosystem) },
            .{ .text = severity },
            .{ .text = definition },
            .{ .text = stamp },
        });
        created += 1;
    }
    return created;
}

fn exposureEventType(ecosystem: []const u8) []const u8 {
    if (std.mem.eql(u8, ecosystem, "editor-extension") or std.mem.eql(u8, ecosystem, "editor_extension")) return "editor_extension";
    if (std.mem.eql(u8, ecosystem, "browser-extension") or std.mem.eql(u8, ecosystem, "browser_extension")) return "browser_extension";
    if (std.mem.eql(u8, ecosystem, "mcp") or std.mem.eql(u8, ecosystem, "mcp_server") or std.mem.eql(u8, ecosystem, "mcp-server")) return "mcp_config";
    return "package_inventory";
}

fn compileKind(kind: []const u8) ?Compiled {
    if (std.mem.eql(u8, kind, "sha256")) return .{ .event_type = "file_integrity", .path = "new_sha256" };
    if (std.mem.eql(u8, kind, "sha1")) return .{ .event_type = "file_integrity", .path = "new_sha1" };
    if (std.mem.eql(u8, kind, "ipv4") or std.mem.eql(u8, kind, "ipv6")) return .{ .event_type = "network_snapshot", .path = "connections.remote_address" };
    if (std.mem.eql(u8, kind, "domain")) return .{ .event_type = "dns_query", .path = "qname" };
    return null;
}

fn markFailed(conn: *pg.Conn, id: []const u8, stamp: []const u8, message: []const u8) !void {
    const msg = if (message.len > 2000) message[0..2000] else message;
    try conn.execNoRows(
        \\UPDATE threat_intel_feeds
        \\SET status = 'failed', last_error = $3, updated_at = $2::timestamptz
        \\WHERE id = $1::uuid
    , &.{ .{ .text = id }, .{ .text = stamp }, .{ .text = msg } });
}

const FetchOutcome = struct {
    modified: bool = false,
    etag: ?[]u8 = null,
    body: []u8 = &.{},
    fail: ?[]u8 = null,
    body_owned: bool = false,

    fn deinit(self: *FetchOutcome, allocator: std.mem.Allocator) void {
        if (self.etag) |etag| allocator.free(etag);
        if (self.fail) |msg| allocator.free(msg);
        if (self.body_owned) allocator.free(self.body);
    }
};

fn fetchFeed(
    allocator: std.mem.Allocator,
    io: std.Io,
    url: []const u8,
    etag: ?[]const u8,
    auth_name: []const u8,
    auth_value: []const u8,
    allow_private: bool,
) !FetchOutcome {
    const uri = std.Uri.parse(url) catch return error.BadUrl;
    var host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
    const host = std.Io.net.HostName.fromUri(uri, &host_buf) catch return error.BadUrl;
    const port: u16 = uri.port orelse if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) 443 else 80;
    if (!egress.allowed(host.bytes, allow_private)) return error.EgressRefused;
    if (!allow_private) try dnsAllowed(io, host, port);

    var client: std.http.Client = .{ .allocator = allocator, .io = io };
    defer client.deinit();
    var extra: [2]std.http.Header = undefined;
    var n: usize = 0;
    var inm_buf: [300]u8 = undefined;
    if (etag) |tag| {
        if (tag.len > 0 and tag.len < 280) {
            const quoted = std.fmt.bufPrint(&inm_buf, "\"{s}\"", .{tag}) catch return error.BadUrl;
            extra[n] = .{ .name = "if-none-match", .value = quoted };
            n += 1;
        }
    }
    if (auth_name.len > 0 and auth_value.len > 0) {
        extra[n] = .{ .name = auth_name, .value = auth_value };
        n += 1;
    }
    var req = client.request(.GET, uri, .{
        .keep_alive = false,
        .redirect_behavior = .unhandled,
        .headers = .{
            .user_agent = .{ .override = "Tawny-EDR/1.0 (+https://github.com/jusso-dev/Tawny)" },
            .accept_encoding = .{ .override = "identity" },
        },
        .extra_headers = extra[0..n],
    }) catch |err| return fetchFailed(allocator, err);
    defer req.deinit();
    req.sendBodiless() catch |err| return fetchFailed(allocator, err);
    var redirect_buf: [1024]u8 = undefined;
    var response = req.receiveHead(&redirect_buf) catch |err| return fetchFailed(allocator, err);
    const code = @intFromEnum(response.head.status);
    if (response.head.status == .not_modified) {
        return .{
            .modified = false,
            .etag = copyEtag(allocator, response.head.bytes),
        };
    }
    if (code < 200 or code >= 300) {
        const msg = try std.fmt.allocPrint(allocator, "Feed responded with {d} {s}", .{ code, response.head.reason });
        return .{ .fail = msg };
    }
    const etag_copy = copyEtag(allocator, response.head.bytes);
    const storage = try allocator.alloc(u8, 8 * 1024 * 1024);
    defer allocator.free(storage);
    var writer = std.Io.Writer.fixed(storage);
    var transfer_buffer: [128]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    const reader = response.readerDecompressing(&transfer_buffer, &decompress, &.{});
    _ = reader.streamRemaining(&writer) catch |err| return fetchFailed(allocator, err);
    return .{
        .modified = true,
        .etag = etag_copy,
        .body = try allocator.dupe(u8, writer.buffered()),
        .body_owned = true,
    };
}

fn dnsAllowed(io: std.Io, host: std.Io.net.HostName, port: u16) !void {
    if (std.Io.net.IpAddress.parse(host.bytes, port)) |_| return else |_| {}
    var storage: [16]std.Io.net.HostName.LookupResult = undefined;
    var queue = std.Io.Queue(std.Io.net.HostName.LookupResult).init(&storage);
    var canon: [std.Io.net.HostName.max_len]u8 = undefined;
    host.lookup(io, &queue, .{ .port = port, .canonical_name_buffer = &canon }) catch |err| {
        std.debug.print("ti dns {s}: {s}\n", .{ host.bytes, @errorName(err) });
        return error.DnsFailed;
    };
    var slot: [1]std.Io.net.HostName.LookupResult = undefined;
    while (true) {
        const n = queue.get(io, &slot, 0) catch break;
        if (n == 0) break;
        switch (slot[0]) {
            .address => |addr| if (!resolvedAllowed(addr, false)) return error.EgressRefused,
            .canonical_name => {},
        }
    }
}

fn fetchFailed(allocator: std.mem.Allocator, err: anyerror) !FetchOutcome {
    return .{ .fail = try std.fmt.allocPrint(allocator, "{s}", .{@errorName(err)}) };
}

fn privateV6(b: [16]u8) bool {
    var i: usize = 0;
    var zero = true;
    while (i < 15) : (i += 1) if (b[i] != 0) {
        zero = false;
    };
    if (zero and b[15] == 1) return true;
    if (b[0] == 0xfe and (b[1] & 0xc0) == 0x80) return true;
    if ((b[0] & 0xfe) == 0xfc) return true;
    return false;
}

fn resolvedAllowed(addr: std.Io.net.IpAddress, allow_private: bool) bool {
    if (allow_private) return true;
    switch (addr) {
        .ip4 => |ip4| {
            var buf: [16]u8 = undefined;
            const text = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{
                ip4.bytes[0], ip4.bytes[1], ip4.bytes[2], ip4.bytes[3],
            }) catch return false;
            return egress.allowed(text, false);
        },
        .ip6 => |ip6| return !privateV6(ip6.bytes),
    }
}

fn copyEtag(allocator: std.mem.Allocator, head: []const u8) ?[]u8 {
    var it = std.mem.splitScalar(u8, head, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, "\r ");
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "etag")) continue;
        var value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (value.len >= 2 and std.ascii.eqlIgnoreCase(value[0..2], "W/")) {
            value = std.mem.trim(u8, value[2..], " \t");
        }
        value = std.mem.trim(u8, value, "\"");
        if (value.len == 0) return null;
        return allocator.dupe(u8, value) catch null;
    }
    return null;
}

fn toLower(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, value.len);
    for (value, 0..) |c, i| out[i] = std.ascii.toLower(c);
    return out;
}

test "feed fetch refuses loopback unless private egress is on" {
    const allocator = std.testing.allocator;
    const refused = fetchFeed(allocator, std.testing.io, "http://127.0.0.1:9/feed", null, "", "", false);
    try std.testing.expectError(error.EgressRefused, refused);
}

const default_tenant = "00000000-0000-0000-0000-000000000001";
const ti_feed = "00000000-0000-0000-0000-00000000d931";
const ti_port = "18084";

test "starter feeds seed once and a feed materialises ioc rules" {
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

    try conn.execNoRows("DELETE FROM threat_intel_feeds WHERE tenant_id = $1::uuid", &.{.{ .text = default_tenant }});
    const added = try ensureSeeded(allocator, io, conn);
    const again = try ensureSeeded(allocator, io, conn);
    const feodo = try scalar(allocator, conn, "SELECT is_enabled::text FROM threat_intel_feeds WHERE tenant_id = $1::uuid AND url ILIKE '%feodotracker%'", &.{.{ .text = default_tenant }});
    defer allocator.free(feodo);
    const phish = try scalar(allocator, conn, "SELECT is_enabled::text FROM threat_intel_feeds WHERE tenant_id = $1::uuid AND url ILIKE '%phishtank%'", &.{.{ .text = default_tenant }});
    defer allocator.free(phish);
    const openphish = try scalar(allocator, conn, "SELECT is_enabled::text FROM threat_intel_feeds WHERE tenant_id = $1::uuid AND url ILIKE '%openphish%'", &.{.{ .text = default_tenant }});
    defer allocator.free(openphish);
    try std.testing.expectEqual(@as(u32, 5), added);
    try std.testing.expectEqual(@as(u32, 0), again);
    try std.testing.expect(enabledFlag(feodo));
    try std.testing.expect(enabledFlag(openphish));
    try std.testing.expect(!enabledFlag(phish));

    var child = try std.process.spawn(io, .{
        .argv = &.{ "/usr/bin/python3", "-c", fixture_py, ti_port },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer child.kill(io);
    std.Io.sleep(io, .fromMilliseconds(200), .real) catch {};

    try conn.execNoRows("UPDATE threat_intel_feeds SET is_enabled = false WHERE tenant_id = $1::uuid", &.{.{ .text = default_tenant }});
    try conn.execNoRows(
        \\INSERT INTO threat_intel_feeds (
        \\  id, tenant_id, name, kind, url, auth_header_name, auth_header_value_encrypted,
        \\  default_severity, is_enabled, interval_minutes, status, created_at, updated_at
        \\) VALUES (
        \\  $1::uuid, $2::uuid, 'Test phishing domains', 'generic_csv', $3,
        \\  'X-Api-Key', 'legacy-plaintext', 'high', true, 0, 'never_run', now(), now()
        \\)
    , &.{ .{ .text = ti_feed }, .{ .text = default_tenant }, .{ .text = "http://127.0.0.1:" ++ ti_port ++ "/feed" } });

    const now: i64 = 2_000_000_000;
    const options = Options{ .now_unix = now, .allow_private = true, .secret = "test-integration-encryption-key" };
    const ran = try run(allocator, io, conn, options);
    const rules = try scalar(allocator, conn, "SELECT count(*)::text FROM alert_rules WHERE external_id ILIKE $1", &.{.{ .text = "ti-feed:00000000-0000-0000-0000-00000000d931:%" }});
    defer allocator.free(rules);
    const domain = try scalar(allocator, conn,
        \\SELECT event_type || ' ' || payload_path || ' ' || operator || ' ' || match_value || ' ' || is_enabled::text
        \\FROM alert_rules WHERE external_id = $1
    , &.{.{ .text = "ti-feed:00000000-0000-0000-0000-00000000d931:domain:evil.example" }});
    defer allocator.free(domain);
    const ip = try scalar(allocator, conn, "SELECT event_type || ' ' || payload_path || ' ' || match_value FROM alert_rules WHERE external_id = $1", &.{
        .{ .text = "ti-feed:00000000-0000-0000-0000-00000000d931:ipv4:203.0.113.9" },
    });
    defer allocator.free(ip);
    const stored = try scalar(allocator, conn, "SELECT auth_header_value_encrypted FROM threat_intel_feeds WHERE id = $1::uuid", &.{.{ .text = ti_feed }});
    defer allocator.free(stored);
    const etag = try scalar(allocator, conn, "SELECT coalesce(etag, '') FROM threat_intel_feeds WHERE id = $1::uuid", &.{.{ .text = ti_feed }});
    defer allocator.free(etag);
    const status = try scalar(allocator, conn, "SELECT status FROM threat_intel_feeds WHERE id = $1::uuid", &.{.{ .text = ti_feed }});
    defer allocator.free(status);
    const plain = try secrets.unprotect(allocator, options.secret, stored);
    defer allocator.free(plain);

    try conn.execNoRows("UPDATE threat_intel_feeds SET last_run_at = NULL WHERE id = $1::uuid", &.{.{ .text = ti_feed }});
    const ran2 = try run(allocator, io, conn, options);
    const rules2 = try scalar(allocator, conn, "SELECT count(*)::text FROM alert_rules WHERE external_id ILIKE $1", &.{.{ .text = "ti-feed:00000000-0000-0000-0000-00000000d931:%" }});
    defer allocator.free(rules2);

    std.debug.print("ti_job ran={d}/{d} rules={s}/{s} domain={s} ip={s} etag={s} status={s}\n", .{
        ran, ran2, rules, rules2, domain, ip, etag, status,
    });
    try std.testing.expect(ran >= 1);
    try std.testing.expectEqualStrings("2", rules);
    try std.testing.expect(std.mem.startsWith(u8, domain, "dns_query qname equals evil.example "));
    try std.testing.expect(std.mem.endsWith(u8, domain, " t") or std.mem.endsWith(u8, domain, " true"));
    try std.testing.expectEqualStrings("network_snapshot connections.remote_address 203.0.113.9", ip);
    try std.testing.expect(secrets.isProtected(stored));
    try std.testing.expectEqualStrings("legacy-plaintext", plain);
    try std.testing.expectEqualStrings("abc", etag);
    try std.testing.expectEqualStrings("healthy", status);
    try std.testing.expect(ran2 >= 1);
    try std.testing.expectEqualStrings("2", rules2);
    try conn.execSimple("ROLLBACK");
}

fn enabledFlag(value: []const u8) bool {
    return std.mem.eql(u8, value, "t") or std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "1");
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

const fixture_py =
    \\from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    \\import sys
    \\port = int(sys.argv[1])
    \\class H(BaseHTTPRequestHandler):
    \\    def do_GET(self):
    \\        key = self.headers.get("X-Api-Key")
    \\        if key != "legacy-plaintext":
    \\            self.send_response(401)
    \\            self.send_header("Content-Length", "0")
    \\            self.end_headers()
    \\            return
    \\        inm = self.headers.get("If-None-Match")
    \\        if inm == '"abc"':
    \\            self.send_response(304)
    \\            self.send_header("ETag", '"abc"')
    \\            self.end_headers()
    \\            return
    \\        body = b"https://evil.example/phish\n203.0.113.9\n"
    \\        self.send_response(200)
    \\        self.send_header("ETag", '"abc"')
    \\        self.send_header("Content-Length", str(len(body)))
    \\        self.end_headers()
    \\        self.wfile.write(body)
    \\    def log_message(self, fmt, *args):
    \\        pass
    \\ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
;

const osv_feed = "00000000-0000-0000-0000-00000000e931";
const osv_port = "18088";

test "osv package exposure feed materialises rules" {
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

    try conn.execNoRows("DELETE FROM threat_intel_feeds WHERE tenant_id = $1::uuid", &.{.{ .text = default_tenant }});
    _ = try ensureSeeded(allocator, io, conn);
    try conn.execNoRows("UPDATE threat_intel_feeds SET is_enabled = false WHERE tenant_id = $1::uuid", &.{.{ .text = default_tenant }});

    var child = try std.process.spawn(io, .{
        .argv = &.{ "/usr/bin/python3", "-c", osv_fixture_py, osv_port },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer child.kill(io);
    std.Io.sleep(io, .fromMilliseconds(300), .real) catch {};

    try conn.execNoRows(
        \\INSERT INTO threat_intel_feeds (
        \\  id, tenant_id, name, kind, url, default_severity, is_enabled,
        \\  interval_minutes, status, created_at, updated_at
        \\) VALUES (
        \\  $1::uuid, $2::uuid, 'OSV test', 'osv', $3,
        \\  'high', true, 0, 'never_run', now(), now()
        \\)
    , &.{ .{ .text = osv_feed }, .{ .text = default_tenant }, .{ .text = "http://127.0.0.1:" ++ osv_port ++ "/osv" } });

    const options = Options{ .now_unix = 2_000_000_000, .allow_private = true };
    const ran = try run(allocator, io, conn, options);
    const prefix = "ti-feed:00000000-0000-0000-0000-00000000e931:";
    const rules = try scalar(allocator, conn, "SELECT count(*)::text FROM alert_rules WHERE external_id ILIKE $1 AND format = 'package_exposure' AND operator = 'exists'", &.{
        .{ .text = prefix ++ "%" },
    });
    defer allocator.free(rules);
    const npm_id = prefix ++ "exposure:npm:Left-Pad:1.0.0,1.0.1:GHSA-test";
    const npm = try scalar(allocator, conn, "SELECT format || ' ' || operator || ' ' || event_type || ' ' || description FROM alert_rules WHERE external_id = $1", &.{
        .{ .text = npm_id },
    });
    defer allocator.free(npm);
    const npm_def = try scalar(allocator, conn, "SELECT source_definition FROM alert_rules WHERE external_id = $1", &.{.{ .text = npm_id }});
    defer allocator.free(npm_def);
    const pypi_pattern = try scalar(allocator, conn, "SELECT (source_definition::jsonb)->>'version_pattern' FROM alert_rules WHERE external_id = $1", &.{
        .{ .text = prefix ++ "exposure:pypi:leftpad:<2.0.0:GHSA-test" },
    });
    defer allocator.free(pypi_pattern);
    const editor = try scalar(allocator, conn, "SELECT event_type FROM alert_rules WHERE external_id = $1", &.{
        .{ .text = prefix ++ "exposure:editor-extension:evil.ext:9.9.9:GHSA-test" },
    });
    defer allocator.free(editor);
    const node_eco = try scalar(allocator, conn, "SELECT (source_definition::jsonb)->>'ecosystem' FROM alert_rules WHERE external_id = $1", &.{
        .{ .text = prefix ++ "exposure:node:left-pad:0.0.1:GHSA-test" },
    });
    defer allocator.free(node_eco);
    const long_len = try scalar(allocator, conn, "SELECT length(external_id)::text FROM alert_rules WHERE external_id LIKE $1", &.{
        .{ .text = prefix ++ "exposure:npm:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%" },
    });
    defer allocator.free(long_len);
    const imported = try scalar(allocator, conn, "SELECT last_imported_count::text FROM threat_intel_feeds WHERE id = $1::uuid", &.{.{ .text = osv_feed }});
    defer allocator.free(imported);

    try conn.execNoRows("UPDATE threat_intel_feeds SET last_run_at = NULL, etag = NULL WHERE id = $1::uuid", &.{.{ .text = osv_feed }});
    const ran2 = try run(allocator, io, conn, options);
    const rules2 = try scalar(allocator, conn, "SELECT count(*)::text FROM alert_rules WHERE external_id ILIKE $1 AND format = 'package_exposure'", &.{
        .{ .text = prefix ++ "%" },
    });
    defer allocator.free(rules2);

    std.debug.print("osv_job ran={d}/{d} rules={s}/{s} npm={s} pypi={s} editor={s} node={s} long={s} imported={s}\n", .{
        ran, ran2, rules, rules2, npm, pypi_pattern, editor, node_eco, long_len, imported,
    });
    try std.testing.expect(ran >= 1);
    try std.testing.expectEqualStrings("5", rules);
    try std.testing.expectEqualStrings("package_exposure exists package_inventory bad left-pad", npm);
    try std.testing.expect(package_exposure.matches(allocator, npm_def,
        \\{"ecosystem":"npm","name":"Left-Pad","version":"1.0.0"}
    ));
    try std.testing.expect(!package_exposure.matches(allocator, npm_def,
        \\{"ecosystem":"npm","name":"Left-Pad","version":"9.9.9"}
    ));
    try std.testing.expectEqualStrings("<2.0.0", pypi_pattern);
    try std.testing.expectEqualStrings("editor_extension", editor);
    try std.testing.expectEqualStrings("node", node_eco);
    try std.testing.expectEqualStrings("128", long_len);
    try std.testing.expectEqualStrings("5", imported);
    try std.testing.expect(ran2 >= 1);
    try std.testing.expectEqualStrings("5", rules2);
    try conn.execSimple("ROLLBACK");
}

const osv_fixture_py =
    \\from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    \\import sys
    \\port = int(sys.argv[1])
    \\long = "A" * 80
    \\body = ('{"id":"GHSA-test","summary":"bad left-pad","references":[{"url":"https://example.test/adv"}],"affected":['
    \\ '{"package":{"ecosystem":"NPM","name":"Left-Pad"},"versions":["1.0.0","1.0.1"]},'
    \\ '{"package":{"ecosystem":"PyPI","name":"leftpad"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]},'
    \\ '{"package":{"ecosystem":"editor-extension","name":"evil.ext"},"versions":["9.9.9"]},'
    \\ '{"package":{"ecosystem":"Node","name":"left-pad"},"versions":["0.0.1"]},'
    \\ '{"package":{"ecosystem":"npm","name":"%s"},"versions":["1.0.0"]}]}' % long).encode()
    \\class H(BaseHTTPRequestHandler):
    \\    def do_GET(self):
    \\        self.send_response(200)
    \\        self.send_header("ETag", '"osv1"')
    \\        self.send_header("Content-Length", str(len(body)))
    \\        self.end_headers()
    \\        self.wfile.write(body)
    \\    def log_message(self, fmt, *args):
    \\        pass
    \\ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
;
