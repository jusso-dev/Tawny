//! `POST /api/threat-intel/lookup`. Matches enabled IOC rules whose
//! `external_id` is `ti-feed:{feedId}:{kind}:{value}` for a tenant feed.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");

pub fn lookup(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    if (web.session_id != null and !auth.checkCsrf(request, web)) {
        try util.respondJson(request, .forbidden, "{\"error\":\"csrf\"}");
        return;
    }
    const body = util.readBody(allocator, request, 256 * 1024) catch |err| switch (err) {
        error.BodyTooLarge => return util.problem(request, allocator, .bad_request, "values may contain at most 500 indicators."),
        else => return err,
    };
    defer allocator.free(body);
    const Req = struct { values: []const []const u8 = &.{} };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "values must contain at least one indicator.");
    };
    defer parsed.deinit();
    const values = parsed.value.values;
    if (values.len == 0) {
        return util.problem(request, allocator, .bad_request, "values must contain at least one indicator.");
    }
    if (values.len > 500) {
        return util.problem(request, allocator, .bad_request, "values may contain at most 500 indicators.");
    }
    for (values) |value| {
        const trimmed = std.mem.trim(u8, value, " \t\r\n");
        if (trimmed.len == 0 or trimmed.len > 512) {
            return util.problem(request, allocator, .bad_request, "each indicator must contain 1 to 512 characters.");
        }
    }
    const json = try matchesJson(allocator, conn, web.tenant_id, values);
    defer allocator.free(json);
    try util.respondJson(request, .ok, json);
}

/// `ti-feed:{feedUuid}:{kind}:{value}`. Kind is the segment between the
/// second and third colons. Feed id is returned as a slice of `external_id`.
pub fn parseFeedExternalId(external_id: []const u8) ?struct { feed_id: []const u8, kind: []const u8 } {
    const prefix = "ti-feed:";
    if (external_id.len < prefix.len) return null;
    if (!std.ascii.eqlIgnoreCase(external_id[0..prefix.len], prefix)) return null;
    const rest = external_id[prefix.len..];
    const feed_end = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
    if (feed_end != 36) return null;
    const after_feed = rest[feed_end + 1 ..];
    const kind_end = std.mem.indexOfScalar(u8, after_feed, ':') orelse return null;
    if (kind_end == 0) return null;
    return .{ .feed_id = rest[0..feed_end], .kind = after_feed[0..kind_end] };
}

pub fn matchesJson(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    tenant_id: []const u8,
    values: []const []const u8,
) ![]u8 {
    const feeds = try conn.exec(allocator, "SELECT id::text, name FROM threat_intel_feeds WHERE tenant_id = $1::uuid", &.{
        .{ .text = tenant_id },
    });
    defer {
        for (feeds) |row| row.deinit(allocator);
        allocator.free(feeds);
    }
    if (feeds.len == 0) return allocator.dupe(u8, "{\"matches\":[]}");

    var lowered: std.ArrayList([]u8) = .empty;
    defer {
        for (lowered.items) |item| allocator.free(item);
        lowered.deinit(allocator);
    }
    for (values) |value| {
        const trimmed = std.mem.trim(u8, value, " \t\r\n");
        if (trimmed.len == 0 or trimmed.len > 512) continue;
        const copy = try allocator.alloc(u8, trimmed.len);
        _ = std.ascii.lowerString(copy, trimmed);
        var seen = false;
        for (lowered.items) |have| {
            if (std.mem.eql(u8, have, copy)) {
                seen = true;
                break;
            }
        }
        if (seen) {
            allocator.free(copy);
            continue;
        }
        try lowered.append(allocator, copy);
    }
    if (lowered.items.len == 0) return allocator.dupe(u8, "{\"matches\":[]}");

    var sql: std.ArrayList(u8) = .empty;
    defer sql.deinit(allocator);
    try sql.appendSlice(allocator,
        \\SELECT match_value, id::text, name, description, severity, external_id
        \\FROM alert_rules
        \\WHERE tenant_id = $1::uuid AND is_enabled AND format = 'ioc' AND match_value IS NOT NULL AND lower(match_value) IN (
    );
    var args: std.ArrayList(pg.Value) = .empty;
    defer args.deinit(allocator);
    try args.append(allocator, .{ .text = tenant_id });
    for (lowered.items, 0..) |item, i| {
        if (i != 0) try sql.append(allocator, ',');
        var nbuf: [16]u8 = undefined;
        const n = std.fmt.bufPrint(&nbuf, "${d}", .{i + 2}) catch return error.OutOfMemory;
        try sql.appendSlice(allocator, n);
        try args.append(allocator, .{ .text = item });
    }
    try sql.append(allocator, ')');

    const rules = try conn.exec(allocator, sql.items, args.items);
    defer {
        for (rules) |row| row.deinit(allocator);
        allocator.free(rules);
    }

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"matches\":[");
    var wrote: usize = 0;
    for (rules) |row| {
        const external_id = row.cols[5] orelse continue;
        const parsed_id = parseFeedExternalId(external_id) orelse continue;
        const feed_name = feedName(feeds, parsed_id.feed_id) orelse continue;
        if (wrote != 0) try out.append(allocator, ',');
        wrote += 1;
        const value_j = try util.escapeJson(allocator, row.cols[0] orelse "");
        defer allocator.free(value_j);
        const kind_j = try util.escapeJson(allocator, parsed_id.kind);
        defer allocator.free(kind_j);
        const rule_id_j = try util.escapeJson(allocator, row.cols[1] orelse "");
        defer allocator.free(rule_id_j);
        const rule_name_j = try util.escapeJson(allocator, row.cols[2] orelse "");
        defer allocator.free(rule_name_j);
        const description_j = try util.nullOrJsonString(allocator, row.cols[3]);
        defer allocator.free(description_j);
        const severity_j = try util.escapeJson(allocator, row.cols[4] orelse "");
        defer allocator.free(severity_j);
        const feed_id_j = try util.escapeJson(allocator, parsed_id.feed_id);
        defer allocator.free(feed_id_j);
        const feed_name_j = try util.escapeJson(allocator, feed_name);
        defer allocator.free(feed_name_j);
        const line = try std.fmt.allocPrint(allocator,
            \\{{"value":{s},"kind":{s},"rule_id":{s},"rule_name":{s},"description":{s},"severity":{s},"feed_id":{s},"feed_name":{s}}}
        , .{ value_j, kind_j, rule_id_j, rule_name_j, description_j, severity_j, feed_id_j, feed_name_j });
        defer allocator.free(line);
        try out.appendSlice(allocator, line);
    }
    try out.appendSlice(allocator, "]}");
    return out.toOwnedSlice(allocator);
}

fn feedName(feeds: []const pg.Row, feed_id: []const u8) ?[]const u8 {
    for (feeds) |row| {
        const id = row.cols[0] orelse continue;
        if (std.ascii.eqlIgnoreCase(id, feed_id)) return row.cols[1] orelse "";
    }
    return null;
}

test "feed external id splits feed and kind" {
    const ok = parseFeedExternalId("ti-feed:44444422-2222-4333-8444-555555555555:domain:evil.example");
    try std.testing.expect(ok != null);
    try std.testing.expectEqualStrings("44444422-2222-4333-8444-555555555555", ok.?.feed_id);
    try std.testing.expectEqualStrings("domain", ok.?.kind);
    try std.testing.expect(parseFeedExternalId("ioc:evil.example") == null);
    try std.testing.expect(parseFeedExternalId("ti-feed:not-a-uuid:domain:x") == null);
    try std.testing.expect(parseFeedExternalId("TI-FEED:44444422-2222-4333-8444-555555555555:sha256:abc") != null);
}

test "lookup returns only feed-backed ioc rules for the tenant" {
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

    var feed_buf: [36]u8 = undefined;
    const feed_id = util.newUuid(io, &feed_buf);
    var rule_buf: [36]u8 = undefined;
    const rule_id = util.newUuid(io, &rule_buf);
    var external_buf: [96]u8 = undefined;
    const external_id = std.fmt.bufPrint(&external_buf, "ti-feed:{s}:domain:evil.example", .{feed_id}) catch return error.OutOfMemory;

    try conn.execNoRows(
        \\INSERT INTO threat_intel_feeds (
        \\  id, tenant_id, name, kind, url, default_severity, is_enabled, interval_minutes, status, created_at, updated_at)
        \\VALUES ($1::uuid, $2::uuid, 'fixture-feed', 'domain', 'https://example.invalid/iocs', 'high', true, 60, 'never_run', '2026-10-04T00:00:00Z', '2026-10-04T00:00:00Z')
    , &.{ .{ .text = feed_id }, .{ .text = util.default_tenant } });
    try conn.execNoRows(
        \\INSERT INTO alert_rules (
        \\  id, tenant_id, name, format, external_id, description, severity, operator, match_value, is_enabled, created_at, updated_at)
        \\VALUES ($1::uuid, $2::uuid, 'evil domain', 'ioc', $3, 'known bad', 'high', 'equals', 'Evil.Example', true, '2026-10-04T00:00:00Z', '2026-10-04T00:00:00Z')
    , &.{ .{ .text = rule_id }, .{ .text = util.default_tenant }, .{ .text = external_id } });

    const json = try matchesJson(allocator, conn, util.default_tenant, &.{ "  EVIL.EXAMPLE  ", "nope.example" });
    defer allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"kind\":\"domain\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "Evil.Example") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "fixture-feed") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "nope.example") == null);
    try conn.execSimple("ROLLBACK");
}
