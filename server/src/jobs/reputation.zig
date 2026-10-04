//! Reputation enrichment. Matches ReputationEnrichmentJob + ReputationEnricher:
//! newest 100 alerts from the last 24h with null enrichment, VirusTotal /
//! AbuseIPDB / GreyNoise, 24h reputation_cache. Provider and verdict strings
//! are the .NET enum names (VirusTotal, AbuseIpDb, Malicious, ...).
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const http_get = @import("http_get.zig");

pub const Provider = enum { virus_total, abuse_ipdb, grey_noise };

pub const Options = struct {
    now_unix: i64,
    allow_private: bool = false,
    enrich: bool = true,
    cache_ttl_hours: i64 = 24,
    vt_key: []const u8 = "",
    abuse_key: []const u8 = "",
    gn_key: []const u8 = "",
    vt_base: []const u8 = "https://www.virustotal.com",
    abuse_base: []const u8 = "https://api.abuseipdb.com",
    gn_base: []const u8 = "https://api.greynoise.io",
};

pub const Indicator = struct {
    kind: []u8,
    value: []u8,

    pub fn deinit(self: Indicator, allocator: std.mem.Allocator) void {
        allocator.free(self.kind);
        allocator.free(self.value);
    }
};

const Lookup = struct {
    verdict: []u8,
    score: ?i32,
    detail: []u8,

    fn deinit(self: *Lookup, allocator: std.mem.Allocator) void {
        allocator.free(self.verdict);
        allocator.free(self.detail);
    }
};

const batch_sql =
    \\SELECT a.id::text, a.tenant_id::text, r.format, r.payload_path, r.match_value, t.payload::text
    \\FROM alerts a
    \\JOIN alert_rules r ON r.id = a.alert_rule_id
    \\JOIN telemetry_events t ON t.id = a.telemetry_event_id AND t.received_at = a.telemetry_received_at
    \\WHERE a.enrichment_json IS NULL AND a.created_at >= to_timestamp($1::bigint)
    \\ORDER BY a.created_at DESC, a.id DESC
    \\LIMIT 100
;

/// Alerts that received a lookup. No-indicator rows are written and not counted.
pub fn run(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, options: Options) !u32 {
    if (!options.enrich) return 0;
    var cutoff_buf: [32]u8 = undefined;
    const cutoff = try std.fmt.bufPrint(&cutoff_buf, "{d}", .{options.now_unix - 24 * 3600});
    const rows = try conn.exec(allocator, batch_sql, &.{.{ .text = cutoff }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }

    var enriched: u32 = 0;
    for (rows) |row| {
        const id = row.cols[0] orelse continue;
        const tenant = row.cols[1] orelse continue;
        const format = row.cols[2] orelse "";
        const payload = row.cols[5] orelse "{}";
        const indicator = try extractIndicator(allocator, format, row.cols[3], row.cols[4], payload);
        if (indicator == null) {
            try conn.execNoRows(
                "UPDATE alerts SET enrichment_json = $2::jsonb WHERE id = $1::bigint",
                &.{ .{ .text = id }, .{ .text = "{\"enriched\":false,\"reason\":\"no_extractable_indicator\"}" } },
            );
            continue;
        }
        var ind = indicator.?;
        defer ind.deinit(allocator);
        const body = try buildEnrichment(allocator, io, conn, options, tenant, ind.kind, ind.value);
        defer allocator.free(body);
        try conn.execNoRows(
            "UPDATE alerts SET enrichment_json = $2::jsonb WHERE id = $1::bigint",
            &.{ .{ .text = id }, .{ .text = body } },
        );
        enriched += 1;
    }
    if (enriched > 0) std.debug.print("reputation enrichment completed: {d} alerts enriched.\n", .{enriched});
    return enriched;
}

pub fn providerName(provider: Provider) []const u8 {
    return switch (provider) {
        .virus_total => "VirusTotal",
        .abuse_ipdb => "AbuseIpDb",
        .grey_noise => "GreyNoise",
    };
}

pub fn providersFor(kind: []const u8, vt_key: []const u8, abuse_key: []const u8, out: *[3]Provider) []const Provider {
    var n: usize = 0;
    if (vt_key.len > 0 and (std.mem.eql(u8, kind, "sha256") or std.mem.eql(u8, kind, "sha1") or std.mem.eql(u8, kind, "ipv4") or std.mem.eql(u8, kind, "domain"))) {
        out[n] = .virus_total;
        n += 1;
    }
    if (abuse_key.len > 0 and std.mem.eql(u8, kind, "ipv4")) {
        out[n] = .abuse_ipdb;
        n += 1;
    }
    if (std.mem.eql(u8, kind, "ipv4")) {
        out[n] = .grey_noise;
        n += 1;
    }
    return out[0..n];
}

pub fn vtVerdict(malicious: i32, suspicious: i32) []const u8 {
    if (malicious >= 5) return "Malicious";
    if (malicious >= 1) return "Suspicious";
    if (suspicious > 0) return "Suspicious";
    return "Clean";
}

pub fn abuseVerdict(score: i32) []const u8 {
    if (score >= 75) return "Malicious";
    if (score >= 25) return "Suspicious";
    return "Clean";
}

pub fn gnVerdict(classification: ?[]const u8) []const u8 {
    const name = classification orelse return "Unknown";
    if (std.mem.eql(u8, name, "malicious")) return "Malicious";
    if (std.mem.eql(u8, name, "suspicious")) return "Suspicious";
    if (std.mem.eql(u8, name, "benign")) return "Clean";
    return "Unknown";
}

pub fn extractIndicator(
    allocator: std.mem.Allocator,
    format: []const u8,
    path: ?[]const u8,
    match_value: ?[]const u8,
    payload: []const u8,
) !?Indicator {
    if (std.mem.eql(u8, format, "ioc")) {
        if (match_value) |value| if (value.len > 0) {
            if (iocKind(path)) |kind| {
                const kind_copy = try allocator.dupe(u8, kind);
                errdefer allocator.free(kind_copy);
                return .{ .kind = kind_copy, .value = try allocator.dupe(u8, value) };
            }
        };
    }
    const raw_path = path orelse return null;
    const trimmed = std.mem.trim(u8, raw_path, &std.ascii.whitespace);
    if (trimmed.len == 0) return null;
    const scalar_text = (firstScalar(allocator, payload, trimmed) catch return null) orelse return null;
    if (std.mem.trim(u8, scalar_text, &std.ascii.whitespace).len == 0) {
        allocator.free(scalar_text);
        return null;
    }
    const kind = fallbackKind(trimmed) orelse {
        allocator.free(scalar_text);
        return null;
    };
    const kind_copy = try allocator.dupe(u8, kind);
    errdefer allocator.free(kind_copy);
    return .{ .kind = kind_copy, .value = scalar_text };
}

fn iocKind(path: ?[]const u8) ?[]const u8 {
    const p = path orelse return null;
    if (std.mem.eql(u8, p, "new_sha256")) return "sha256";
    if (std.mem.eql(u8, p, "new_sha1")) return "sha1";
    if (std.mem.eql(u8, p, "connections.remote_address")) return "ipv4";
    if (std.mem.eql(u8, p, "processes.command_line")) return "domain";
    return null;
}

fn fallbackKind(path: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, path, "new_sha256")) return "sha256";
    if (std.mem.eql(u8, path, "new_sha1")) return "sha1";
    if (containsIgnore(path, "address")) return "ipv4";
    if (containsIgnore(path, "domain")) return "domain";
    return null;
}

fn buildEnrichment(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    options: Options,
    tenant: []const u8,
    kind: []const u8,
    value: []const u8,
) ![]u8 {
    var providers: [3]Provider = undefined;
    const list = providersFor(kind, options.vt_key, options.abuse_key, &providers);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"enriched\":true,\"indicator\":{\"kind\":");
    try appendJsonString(&out, allocator, kind);
    try out.appendSlice(allocator, ",\"value\":");
    try appendJsonString(&out, allocator, value);
    try out.appendSlice(allocator, "},\"lookups\":[");
    var wrote: usize = 0;
    for (list) |provider| {
        const lookup = lookupOne(allocator, io, conn, options, tenant, provider, kind, value) catch |err| {
            std.debug.print("reputation {s} {s} skipped: {s}\n", .{ providerName(provider), kind, @errorName(err) });
            continue;
        };
        if (lookup == null) continue;
        var got = lookup.?;
        defer got.deinit(allocator);
        if (wrote != 0) try out.append(allocator, ',');
        try appendLookup(&out, allocator, providerName(provider), got.verdict, got.score, got.detail);
        wrote += 1;
    }
    try out.appendSlice(allocator, "]}");
    return out.toOwnedSlice(allocator);
}

fn lookupOne(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    options: Options,
    tenant: []const u8,
    provider: Provider,
    kind: []const u8,
    value: []const u8,
) !?Lookup {
    if (try readCache(allocator, conn, options.now_unix, tenant, provider, kind, value)) |hit| return hit;
    const fresh = try probe(allocator, io, options, provider, kind, value) orelse return null;
    errdefer {
        var tmp = fresh;
        tmp.deinit(allocator);
    }
    try writeCache(conn, options, tenant, provider, kind, value, fresh);
    return fresh;
}

fn readCache(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    now_unix: i64,
    tenant: []const u8,
    provider: Provider,
    kind: []const u8,
    value: []const u8,
) !?Lookup {
    var now_buf: [32]u8 = undefined;
    const now_txt = try std.fmt.bufPrint(&now_buf, "{d}", .{now_unix});
    const rows = try conn.exec(allocator,
        \\SELECT verdict, coalesce(score::text, ''), detail_json::text
        \\FROM reputation_cache
        \\WHERE tenant_id = $1::uuid AND provider = $2 AND indicator_kind = $3
        \\  AND indicator_value = $4 AND expires_at > to_timestamp($5::bigint)
        \\LIMIT 1
    , &.{
        .{ .text = tenant },
        .{ .text = providerName(provider) },
        .{ .text = kind },
        .{ .text = value },
        .{ .text = now_txt },
    });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return null;
    const verdict = rows[0].cols[0] orelse return null;
    const score_txt = rows[0].cols[1] orelse "";
    const detail = rows[0].cols[2] orelse "{}";
    const owned_verdict = try allocator.dupe(u8, verdict);
    errdefer allocator.free(owned_verdict);
    return .{
        .verdict = owned_verdict,
        .score = if (score_txt.len == 0) null else std.fmt.parseInt(i32, score_txt, 10) catch null,
        .detail = try allocator.dupe(u8, detail),
    };
}

fn writeCache(
    conn: *pg.Conn,
    options: Options,
    tenant: []const u8,
    provider: Provider,
    kind: []const u8,
    value: []const u8,
    lookup: Lookup,
) !void {
    var now_buf: [32]u8 = undefined;
    var exp_buf: [32]u8 = undefined;
    var score_buf: [16]u8 = undefined;
    const now_txt = try std.fmt.bufPrint(&now_buf, "{d}", .{options.now_unix});
    const exp_txt = try std.fmt.bufPrint(&exp_buf, "{d}", .{options.now_unix + options.cache_ttl_hours * 3600});
    const score_val: pg.Value = if (lookup.score) |score| .{
        .text = try std.fmt.bufPrint(&score_buf, "{d}", .{score}),
    } else .{ .null = {} };
    try conn.execNoRows(
        \\INSERT INTO reputation_cache (
        \\  tenant_id, provider, indicator_kind, indicator_value, verdict, score, detail_json, fetched_at, expires_at
        \\) VALUES (
        \\  $1::uuid, $2, $3, $4, $5, $6::integer, $7::jsonb, to_timestamp($8::bigint), to_timestamp($9::bigint)
        \\)
        \\ON CONFLICT (tenant_id, provider, indicator_kind, indicator_value) DO UPDATE SET
        \\  verdict = EXCLUDED.verdict, score = EXCLUDED.score, detail_json = EXCLUDED.detail_json,
        \\  fetched_at = EXCLUDED.fetched_at, expires_at = EXCLUDED.expires_at
    , &.{
        .{ .text = tenant },
        .{ .text = providerName(provider) },
        .{ .text = kind },
        .{ .text = value },
        .{ .text = lookup.verdict },
        score_val,
        .{ .text = lookup.detail },
        .{ .text = now_txt },
        .{ .text = exp_txt },
    });
}

fn probe(
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    provider: Provider,
    kind: []const u8,
    value: []const u8,
) !?Lookup {
    return switch (provider) {
        .virus_total => probeVirusTotal(allocator, io, options, kind, value),
        .abuse_ipdb => probeAbuse(allocator, io, options, kind, value),
        .grey_noise => probeGreyNoise(allocator, io, options, kind, value),
    };
}

fn probeVirusTotal(allocator: std.mem.Allocator, io: std.Io, options: Options, kind: []const u8, value: []const u8) !?Lookup {
    if (options.vt_key.len == 0) return null;
    const segment = if (std.mem.eql(u8, kind, "ipv4"))
        "ip_addresses"
    else if (std.mem.eql(u8, kind, "domain"))
        "domains"
    else if (std.mem.eql(u8, kind, "sha256") or std.mem.eql(u8, kind, "sha1"))
        "files"
    else
        return null;
    var url: std.ArrayList(u8) = .empty;
    defer url.deinit(allocator);
    try url.appendSlice(allocator, trimSlash(options.vt_base));
    try url.appendSlice(allocator, "/api/v3/");
    try url.appendSlice(allocator, segment);
    try url.append(allocator, '/');
    try appendEncoded(&url, allocator, value);
    const headers = [_]std.http.Header{.{ .name = "x-apikey", .value = options.vt_key }};
    var res = try http_get.get(allocator, io, url.items, &headers, "Tawny-EDR/1.0 (+https://github.com/jusso-dev/Tawny)", options.allow_private, 256 * 1024);
    defer res.deinit(allocator);
    if (res.status == 404) return try lookupOwned(allocator, "Unknown", null, "{\"not_found\":true}");
    if (res.status < 200 or res.status >= 300) {
        const detail = try std.fmt.allocPrint(allocator, "{{\"http_status\":{d}}}", .{res.status});
        errdefer allocator.free(detail);
        return .{ .verdict = try allocator.dupe(u8, "Error"), .score = null, .detail = detail };
    }
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, res.body, .{}) catch return error.BadJson;
    defer parsed.deinit();
    const stats = objGet(objGet(objGet(parsed.value, "data") orelse return error.BadJson, "attributes") orelse return error.BadJson, "last_analysis_stats") orelse return error.BadJson;
    const malicious = jsonInt(objGet(stats, "malicious") orelse return error.BadJson) orelse return error.BadJson;
    const suspicious = if (objGet(stats, "suspicious")) |v| jsonInt(v) orelse 0 else 0;
    var detail: std.ArrayList(u8) = .empty;
    errdefer detail.deinit(allocator);
    try detail.appendSlice(allocator, "{\"malicious\":");
    try appendInt(&detail, allocator, malicious);
    try detail.appendSlice(allocator, ",\"suspicious\":");
    try appendInt(&detail, allocator, suspicious);
    try detail.appendSlice(allocator, ",\"stats\":");
    try appendJsonString(&detail, allocator, statsSlice(res.body) orelse "{}");
    try detail.append(allocator, '}');
    const verdict = try allocator.dupe(u8, vtVerdict(malicious, suspicious));
    errdefer allocator.free(verdict);
    return .{ .verdict = verdict, .score = malicious, .detail = try detail.toOwnedSlice(allocator) };
}

fn probeAbuse(allocator: std.mem.Allocator, io: std.Io, options: Options, kind: []const u8, value: []const u8) !?Lookup {
    if (options.abuse_key.len == 0 or !std.mem.eql(u8, kind, "ipv4")) return null;
    var url: std.ArrayList(u8) = .empty;
    defer url.deinit(allocator);
    try url.appendSlice(allocator, trimSlash(options.abuse_base));
    try url.appendSlice(allocator, "/api/v2/check?ipAddress=");
    try appendEncoded(&url, allocator, value);
    try url.appendSlice(allocator, "&maxAgeInDays=90");
    const headers = [_]std.http.Header{
        .{ .name = "accept", .value = "application/json" },
        .{ .name = "Key", .value = options.abuse_key },
    };
    var res = try http_get.get(allocator, io, url.items, &headers, "Tawny-EDR/1.0 (+https://github.com/jusso-dev/Tawny)", options.allow_private, 256 * 1024);
    defer res.deinit(allocator);
    if (res.status < 200 or res.status >= 300) {
        const detail = try std.fmt.allocPrint(allocator, "{{\"http_status\":{d}}}", .{res.status});
        errdefer allocator.free(detail);
        return .{ .verdict = try allocator.dupe(u8, "Error"), .score = null, .detail = detail };
    }
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, res.body, .{}) catch return error.BadJson;
    defer parsed.deinit();
    const data = objGet(parsed.value, "data") orelse return error.BadJson;
    const score = jsonInt(objGet(data, "abuseConfidenceScore") orelse return error.BadJson) orelse return error.BadJson;
    const reports = if (objGet(data, "totalReports")) |v| jsonInt(v) orelse 0 else 0;
    var detail: std.ArrayList(u8) = .empty;
    errdefer detail.deinit(allocator);
    try detail.appendSlice(allocator, "{\"confidence\":");
    try appendInt(&detail, allocator, score);
    try detail.appendSlice(allocator, ",\"usage_type\":");
    try appendMaybe(&detail, allocator, jsonStr(objGet(data, "usageType")));
    try detail.appendSlice(allocator, ",\"country\":");
    try appendMaybe(&detail, allocator, jsonStr(objGet(data, "countryCode")));
    try detail.appendSlice(allocator, ",\"total_reports\":");
    try appendInt(&detail, allocator, reports);
    try detail.append(allocator, '}');
    const verdict = try allocator.dupe(u8, abuseVerdict(score));
    errdefer allocator.free(verdict);
    return .{ .verdict = verdict, .score = score, .detail = try detail.toOwnedSlice(allocator) };
}

fn probeGreyNoise(allocator: std.mem.Allocator, io: std.Io, options: Options, kind: []const u8, value: []const u8) !?Lookup {
    if (!std.mem.eql(u8, kind, "ipv4")) return null;
    var url: std.ArrayList(u8) = .empty;
    defer url.deinit(allocator);
    try url.appendSlice(allocator, trimSlash(options.gn_base));
    try url.appendSlice(allocator, "/v3/community/");
    try appendEncoded(&url, allocator, value);
    var headers_buf: [2]std.http.Header = undefined;
    var n: usize = 1;
    headers_buf[0] = .{ .name = "accept", .value = "application/json" };
    if (options.gn_key.len > 0) {
        headers_buf[1] = .{ .name = "key", .value = options.gn_key };
        n = 2;
    }
    var res = try http_get.get(allocator, io, url.items, headers_buf[0..n], "Tawny-EDR/1.0 (+https://github.com/jusso-dev/Tawny)", options.allow_private, 256 * 1024);
    defer res.deinit(allocator);
    if (res.status == 404) return try lookupOwned(allocator, "Unknown", null, "{\"not_found\":true}");
    if (res.status < 200 or res.status >= 300) {
        const detail = try std.fmt.allocPrint(allocator, "{{\"http_status\":{d}}}", .{res.status});
        errdefer allocator.free(detail);
        return .{ .verdict = try allocator.dupe(u8, "Error"), .score = null, .detail = detail };
    }
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, res.body, .{}) catch return error.BadJson;
    defer parsed.deinit();
    const classification = jsonStr(objGet(parsed.value, "classification"));
    var detail: std.ArrayList(u8) = .empty;
    errdefer detail.deinit(allocator);
    try detail.appendSlice(allocator, "{\"classification\":");
    try appendMaybe(&detail, allocator, classification);
    try detail.appendSlice(allocator, ",\"noise\":");
    try detail.appendSlice(allocator, if (jsonBoolTrue(objGet(parsed.value, "noise"))) "true" else "false");
    try detail.appendSlice(allocator, ",\"riot\":");
    try detail.appendSlice(allocator, if (jsonBoolTrue(objGet(parsed.value, "riot"))) "true" else "false");
    try detail.appendSlice(allocator, ",\"name\":");
    try appendMaybe(&detail, allocator, jsonStr(objGet(parsed.value, "name")));
    try detail.append(allocator, '}');
    const verdict = try allocator.dupe(u8, gnVerdict(classification));
    errdefer allocator.free(verdict);
    return .{ .verdict = verdict, .score = null, .detail = try detail.toOwnedSlice(allocator) };
}

fn lookupOwned(allocator: std.mem.Allocator, verdict: []const u8, score: ?i32, detail: []const u8) !Lookup {
    const owned_verdict = try allocator.dupe(u8, verdict);
    errdefer allocator.free(owned_verdict);
    return .{ .verdict = owned_verdict, .score = score, .detail = try allocator.dupe(u8, detail) };
}

fn appendLookup(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, provider: []const u8, verdict: []const u8, score: ?i32, detail: []const u8) !void {
    try buf.appendSlice(allocator, "{\"provider\":");
    try appendJsonString(buf, allocator, provider);
    try buf.appendSlice(allocator, ",\"verdict\":");
    try appendJsonString(buf, allocator, verdict);
    try buf.appendSlice(allocator, ",\"score\":");
    if (score) |n| try appendInt(buf, allocator, n) else try buf.appendSlice(allocator, "null");
    try buf.appendSlice(allocator, ",\"detail\":");
    try buf.appendSlice(allocator, detail);
    try buf.append(allocator, '}');
}

fn appendMaybe(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, text: ?[]const u8) !void {
    if (text) |value| try appendJsonString(buf, allocator, value) else try buf.appendSlice(allocator, "null");
}

fn appendInt(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, n: i32) !void {
    var tmp: [16]u8 = undefined;
    try buf.appendSlice(allocator, try std.fmt.bufPrint(&tmp, "{d}", .{n}));
}

fn appendJsonString(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    const hex = "0123456789abcdef";
    try buf.append(allocator, '"');
    for (text) |c| switch (c) {
        '"' => try buf.appendSlice(allocator, "\\\""),
        '\\' => try buf.appendSlice(allocator, "\\\\"),
        '\n' => try buf.appendSlice(allocator, "\\n"),
        '\r' => try buf.appendSlice(allocator, "\\r"),
        '\t' => try buf.appendSlice(allocator, "\\t"),
        else => if (c < 0x20) {
            try buf.appendSlice(allocator, "\\u00");
            try buf.append(allocator, hex[c >> 4]);
            try buf.append(allocator, hex[c & 0xf]);
        } else try buf.append(allocator, c),
    };
    try buf.append(allocator, '"');
}

fn appendEncoded(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    const hex = "0123456789ABCDEF";
    for (text) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            try buf.append(allocator, c);
        } else {
            try buf.append(allocator, '%');
            try buf.append(allocator, hex[c >> 4]);
            try buf.append(allocator, hex[c & 0xf]);
        }
    }
}

fn trimSlash(s: []const u8) []const u8 {
    var end = s.len;
    while (end > 0 and s[end - 1] == '/') end -= 1;
    return s[0..end];
}

fn objGet(value: std.json.Value, key: []const u8) ?std.json.Value {
    return switch (value) {
        .object => |obj| obj.get(key),
        else => null,
    };
}

fn jsonInt(value: std.json.Value) ?i32 {
    return switch (value) {
        .integer => |n| std.math.cast(i32, n),
        .number_string => |s| std.fmt.parseInt(i32, s, 10) catch null,
        else => null,
    };
}

fn jsonStr(value: ?std.json.Value) ?[]const u8 {
    const v = value orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn jsonBoolTrue(value: ?std.json.Value) bool {
    const v = value orelse return false;
    return switch (v) {
        .bool => |b| b,
        else => false,
    };
}

fn statsSlice(body: []const u8) ?[]const u8 {
    const key = "\"last_analysis_stats\"";
    const at = std.mem.indexOf(u8, body, key) orelse return null;
    const colon = std.mem.indexOfScalarPos(u8, body, at + key.len, ':') orelse return null;
    var i = colon + 1;
    while (i < body.len and std.ascii.isWhitespace(body[i])) i += 1;
    if (i >= body.len or body[i] != '{') return null;
    var depth: i32 = 0;
    const start = i;
    while (i < body.len) : (i += 1) {
        if (body[i] == '{') depth += 1;
        if (body[i] == '}') {
            depth -= 1;
            if (depth == 0) return body[start .. i + 1];
        }
    }
    return null;
}

fn firstScalar(allocator: std.mem.Allocator, payload: []const u8, path: []const u8) !?[]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    defer parsed.deinit();
    var segs: [16][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, path, '.');
    while (it.next()) |seg| {
        if (seg.len == 0) continue;
        if (n == segs.len) return null;
        segs[n] = seg;
        n += 1;
    }
    return try firstAt(allocator, parsed.value, segs[0..n], 0);
}

fn firstAt(allocator: std.mem.Allocator, cur: std.json.Value, segs: []const []const u8, idx: usize) !?[]u8 {
    if (idx >= segs.len) return scalarText(allocator, cur);
    switch (cur) {
        .array => |arr| {
            for (arr.items) |item| {
                if (try firstAt(allocator, item, segs, idx)) |found| return found;
            }
            return null;
        },
        .object => |obj| {
            const child = obj.get(segs[idx]) orelse return null;
            return try firstAt(allocator, child, segs, idx + 1);
        },
        else => return null,
    }
}

fn scalarText(allocator: std.mem.Allocator, value: std.json.Value) !?[]u8 {
    return switch (value) {
        .string => |s| try allocator.dupe(u8, s),
        .integer => |n| try std.fmt.allocPrint(allocator, "{d}", .{n}),
        .float => |n| try std.fmt.allocPrint(allocator, "{d}", .{n}),
        .number_string => |s| try allocator.dupe(u8, s),
        else => null,
    };
}

fn containsIgnore(hay: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or hay.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(hay[i..][0..needle.len], needle)) return true;
    }
    return false;
}

test "reputation providers follow kind and api keys" {
    var buf: [3]Provider = undefined;
    const all = providersFor("ipv4", "vt", "ab", &buf);
    try std.testing.expectEqual(@as(usize, 3), all.len);
    try std.testing.expectEqual(Provider.virus_total, all[0]);
    try std.testing.expectEqual(Provider.abuse_ipdb, all[1]);
    try std.testing.expectEqual(Provider.grey_noise, all[2]);
    const gn = providersFor("ipv4", "", "", &buf);
    try std.testing.expectEqual(@as(usize, 1), gn.len);
    try std.testing.expectEqual(Provider.grey_noise, gn[0]);
    const hash = providersFor("sha256", "vt", "ab", &buf);
    try std.testing.expectEqual(@as(usize, 1), hash.len);
    try std.testing.expectEqual(@as(usize, 0), providersFor("sha256", "", "", &buf).len);
    try std.testing.expectEqual(@as(usize, 0), providersFor("domain", "", "ab", &buf).len);
    try std.testing.expectEqualStrings("Malicious", vtVerdict(5, 0));
    try std.testing.expectEqualStrings("Suspicious", vtVerdict(1, 0));
    try std.testing.expectEqualStrings("Suspicious", vtVerdict(0, 2));
    try std.testing.expectEqualStrings("Clean", vtVerdict(0, 0));
    try std.testing.expectEqualStrings("Malicious", abuseVerdict(75));
    try std.testing.expectEqualStrings("Suspicious", abuseVerdict(25));
    try std.testing.expectEqualStrings("Clean", abuseVerdict(24));
    try std.testing.expectEqualStrings("Clean", gnVerdict("benign"));
    try std.testing.expectEqualStrings("Unknown", gnVerdict("unknown"));
    try std.testing.expectEqualStrings("Unknown", gnVerdict(null));
}

test "reputation extract indicator matches ioc and payload paths" {
    const allocator = std.testing.allocator;
    const ioc = (try extractIndicator(allocator, "ioc", "new_sha256", "ABC", "{}")).?;
    defer ioc.deinit(allocator);
    try std.testing.expectEqualStrings("sha256", ioc.kind);
    try std.testing.expectEqualStrings("ABC", ioc.value);

    const ip = (try extractIndicator(allocator, "tawny_predicate", "connections.remote_address", null, "{\"connections\":[{\"remote_address\":\"203.0.113.8\"}]}")).?;
    defer ip.deinit(allocator);
    try std.testing.expectEqualStrings("ipv4", ip.kind);
    try std.testing.expectEqualStrings("203.0.113.8", ip.value);

    const domain = (try extractIndicator(allocator, "ioc", "processes.command_line", "evil.example", "{}")).?;
    defer domain.deinit(allocator);
    try std.testing.expectEqualStrings("domain", domain.kind);

    const none = try extractIndicator(allocator, "tawny_predicate", "command_line", "curl", "{\"command_line\":\"curl\"}");
    try std.testing.expect(none == null);
    const missing = try extractIndicator(allocator, "ioc", "new_sha256", "", "{}");
    try std.testing.expect(missing == null);
}

const default_tenant = "00000000-0000-0000-0000-000000000001";
const rep_agent = "00000000-0000-0000-0000-00000000a901";
const rep_rule = "00000000-0000-0000-0000-00000000a902";
const rep_none = "00000000-0000-0000-0000-00000000a903";
const rep_port = "18085";
const rep_now: i64 = 2_000_000_000;

const fixture_py =
    \\from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    \\import sys
    \\port = int(sys.argv[1])
    \\logp = sys.argv[2]
    \\class H(BaseHTTPRequestHandler):
    \\    def do_GET(self):
    \\        with open(logp, "a") as f:
    \\            f.write(self.path + "\n")
    \\            f.write("x-apikey=" + str(self.headers.get("x-apikey")) + "\n")
    \\            f.write("Key=" + str(self.headers.get("Key")) + "\n")
    \\            f.write("key=" + str(self.headers.get("key")) + "\n")
    \\        if self.path.startswith("/api/v3/"):
    \\            body = b'{"data":{"attributes":{"last_analysis_stats":{"malicious":7,"suspicious":1,"harmless":40}}}}'
    \\        elif self.path.startswith("/api/v2/check"):
    \\            body = b'{"data":{"abuseConfidenceScore":80,"usageType":"Data Center","countryCode":"US","totalReports":4}}'
    \\        elif self.path.startswith("/v3/community/"):
    \\            body = b'{"classification":"malicious","noise":true,"riot":false,"name":"Test Scanner"}'
    \\        else:
    \\            self.send_response(404)
    \\            self.send_header("Content-Length", "0")
    \\            self.end_headers()
    \\            return
    \\        self.send_response(200)
    \\        self.send_header("Content-Type", "application/json")
    \\        self.send_header("Content-Length", str(len(body)))
    \\        self.end_headers()
    \\        self.wfile.write(body)
    \\    def log_message(self, fmt, *args):
    \\        pass
    \\ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
;

test "reputation job enriches one hundred alerts and uses the 24h cache" {
    const url = std.testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return;
    if (url.len == 0) return;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    try std.Io.Dir.cwd().createDirPath(io, "zig-out");
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = "zig-out/rep-hits.txt", .data = "" });

    const conn = try pg.Conn.connect(allocator, io, url);
    defer {
        conn.close();
        allocator.destroy(conn);
    }
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};

    try conn.execNoRows("DELETE FROM reputation_cache WHERE indicator_value = $1", &.{.{ .text = "203.0.113.50" }});
    try conn.execNoRows(
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version, architecture, enrolled_at, status
        \\) VALUES ($1::uuid, $2::uuid, 'rep-host', 'linux', 'test', '0', 'arm64', to_timestamp(2000000000), 'online')
    , &.{ .{ .text = rep_agent }, .{ .text = default_tenant } });
    try conn.execNoRows(
        \\INSERT INTO alert_rules (
        \\  id, tenant_id, name, format, severity, operator, payload_path, match_value, event_type, created_at, updated_at
        \\) VALUES (
        \\  $1::uuid, $2::uuid, 'rep-ioc', 'ioc', 'high', 'equals', 'connections.remote_address', '203.0.113.50',
        \\  'network_snapshot', to_timestamp(2000000000), to_timestamp(2000000000)
        \\)
    , &.{ .{ .text = rep_rule }, .{ .text = default_tenant } });
    try conn.execNoRows(
        \\INSERT INTO alert_rules (
        \\  id, tenant_id, name, format, severity, operator, payload_path, event_type, created_at, updated_at
        \\) VALUES (
        \\  $1::uuid, $2::uuid, 'rep-none', 'tawny_predicate', 'low', 'contains', 'command_line',
        \\  'process_start', to_timestamp(2000000000), to_timestamp(2000000000)
        \\)
    , &.{ .{ .text = rep_none }, .{ .text = default_tenant } });
    const event = try conn.exec(allocator,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES (to_timestamp(2000000000), $1::uuid, $2::uuid, 'network_snapshot', to_timestamp(2000000000), '{}')
        \\RETURNING id::text
    , &.{ .{ .text = default_tenant }, .{ .text = rep_agent } });
    defer {
        for (event) |row| row.deinit(allocator);
        allocator.free(event);
    }
    const event_id = event[0].cols[0].?;

    var newest: ?[]u8 = null;
    defer if (newest) |p| allocator.free(p);
    var i: i64 = 0;
    while (i <= 100) : (i += 1) {
        if (i == 99) continue;
        var created_buf: [32]u8 = undefined;
        const created = try std.fmt.bufPrint(&created_buf, "{d}", .{rep_now - i});
        const inserted = try conn.exec(allocator,
            \\INSERT INTO alerts (
            \\  tenant_id, alert_rule_id, agent_id, telemetry_event_id, telemetry_received_at,
            \\  severity, status, title, created_at
            \\) VALUES (
            \\  $1::uuid, $2::uuid, $3::uuid, $4::bigint, to_timestamp(2000000000),
            \\  'high', 'open', 'rep', to_timestamp($5::bigint)
            \\) RETURNING id::text
        , &.{
            .{ .text = default_tenant },
            .{ .text = rep_rule },
            .{ .text = rep_agent },
            .{ .text = event_id },
            .{ .text = created },
        });
        defer {
            for (inserted) |row| row.deinit(allocator);
            allocator.free(inserted);
        }
        if (i == 0) newest = try allocator.dupe(u8, inserted[0].cols[0].?);
    }
    var none_created: [32]u8 = undefined;
    const none_ts = try std.fmt.bufPrint(&none_created, "{d}", .{rep_now - 99});
    try conn.execNoRows(
        \\INSERT INTO alerts (
        \\  tenant_id, alert_rule_id, agent_id, telemetry_event_id, telemetry_received_at,
        \\  severity, status, title, created_at
        \\) VALUES (
        \\  $1::uuid, $2::uuid, $3::uuid, $4::bigint, to_timestamp(2000000000),
        \\  'low', 'open', 'rep-none', to_timestamp($5::bigint)
        \\)
    , &.{
        .{ .text = default_tenant },
        .{ .text = rep_none },
        .{ .text = rep_agent },
        .{ .text = event_id },
        .{ .text = none_ts },
    });
    var old_buf: [32]u8 = undefined;
    const old_ts = try std.fmt.bufPrint(&old_buf, "{d}", .{rep_now - 48 * 3600});
    try conn.execNoRows(
        \\INSERT INTO alerts (
        \\  tenant_id, alert_rule_id, agent_id, telemetry_event_id, telemetry_received_at,
        \\  severity, status, title, created_at
        \\) VALUES (
        \\  $1::uuid, $2::uuid, $3::uuid, $4::bigint, to_timestamp(2000000000),
        \\  'high', 'open', 'rep-old', to_timestamp($5::bigint)
        \\)
    , &.{
        .{ .text = default_tenant },
        .{ .text = rep_rule },
        .{ .text = rep_agent },
        .{ .text = event_id },
        .{ .text = old_ts },
    });

    const base = "http://127.0.0.1:" ++ rep_port;
    const off = Options{
        .now_unix = rep_now,
        .allow_private = true,
        .enrich = false,
        .vt_key = "vt-test-key",
        .abuse_key = "abuse-test-key",
        .gn_key = "gn-test-key",
        .vt_base = base,
        .abuse_base = base,
        .gn_base = base,
    };
    try std.testing.expectEqual(@as(u32, 0), try run(allocator, io, conn, off));

    var child = try std.process.spawn(io, .{
        .argv = &.{ "/usr/bin/python3", "-c", fixture_py, rep_port, "zig-out/rep-hits.txt" },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer child.kill(io);
    std.Io.sleep(io, .fromMilliseconds(200), .real) catch {};

    const on = Options{
        .now_unix = rep_now,
        .allow_private = true,
        .vt_key = "vt-test-key",
        .abuse_key = "abuse-test-key",
        .gn_key = "gn-test-key",
        .vt_base = base,
        .abuse_base = base,
        .gn_base = base,
    };
    const enriched = try run(allocator, io, conn, on);
    const hits = try countHits(allocator, io);
    const summary = try scalar(allocator, conn,
        \\SELECT count(*) FILTER (WHERE enrichment_json IS NULL)::text || '/' || count(*)::text
        \\FROM alerts WHERE agent_id = $1::uuid
    , &.{.{ .text = rep_agent }});
    defer allocator.free(summary);
    const looked = try scalar(allocator, conn,
        \\SELECT (enrichment_json->'lookups'->0->>'provider') || '|' ||
        \\       (enrichment_json->'lookups'->0->>'verdict') || '|' ||
        \\       (enrichment_json->'lookups'->0->>'score') || '|' ||
        \\       (enrichment_json->'lookups'->1->>'provider') || '|' ||
        \\       (enrichment_json->'lookups'->1->>'verdict') || '|' ||
        \\       (enrichment_json->'lookups'->1->>'score') || '|' ||
        \\       (enrichment_json->'lookups'->2->>'provider') || '|' ||
        \\       (enrichment_json->'lookups'->2->>'verdict') || '|' ||
        \\       coalesce(enrichment_json->'lookups'->2->>'score', 'null') || '|' ||
        \\       (enrichment_json->'indicator'->>'value') || '|' ||
        \\       (enrichment_json->'lookups'->1->'detail'->>'confidence') || '|' ||
        \\       (enrichment_json->'lookups'->2->'detail'->>'name')
        \\FROM alerts WHERE id = $1::bigint
    , &.{.{ .text = newest.? }});
    defer allocator.free(looked);
    const reason = try scalar(allocator, conn,
        \\SELECT enrichment_json->>'reason' FROM alerts WHERE alert_rule_id = $1::uuid
    , &.{.{ .text = rep_none }});
    defer allocator.free(reason);
    const log = try std.Io.Dir.cwd().readFileAlloc(io, "zig-out/rep-hits.txt", allocator, std.Io.Limit.limited(1 << 20));
    defer allocator.free(log);

    try conn.execNoRows("UPDATE reputation_cache SET expires_at = to_timestamp(1) WHERE indicator_value = $1", &.{.{ .text = "203.0.113.50" }});
    try conn.execNoRows("UPDATE alerts SET enrichment_json = NULL WHERE id = $1::bigint", &.{.{ .text = newest.? }});
    const again = try run(allocator, io, conn, on);
    const hits2 = try countHits(allocator, io);
    const left = try scalar(allocator, conn,
        \\SELECT coalesce(string_agg(title, ',' ORDER BY title), '')
        \\FROM alerts WHERE agent_id = $1::uuid AND enrichment_json IS NULL
    , &.{.{ .text = rep_agent }});
    defer allocator.free(left);

    std.debug.print("rep_job enriched={d}/{d} hits={d}/{d} rows={s} looked={s} reason={s} left={s}\n", .{
        enriched, again, hits, hits2, summary, looked, reason, left,
    });
    try std.testing.expectEqual(@as(u32, 99), enriched);
    try std.testing.expectEqual(@as(usize, 3), hits);
    try std.testing.expectEqualStrings("2/102", summary);
    try std.testing.expectEqualStrings("VirusTotal|Malicious|7|AbuseIpDb|Malicious|80|GreyNoise|Malicious|null|203.0.113.50|80|Test Scanner", looked);
    try std.testing.expectEqualStrings("no_extractable_indicator", reason);
    try std.testing.expect(std.mem.indexOf(u8, log, "x-apikey=vt-test-key") != null);
    try std.testing.expect(std.mem.indexOf(u8, log, "Key=abuse-test-key") != null);
    try std.testing.expect(std.mem.indexOf(u8, log, "key=gn-test-key") != null);
    try std.testing.expectEqual(@as(u32, 2), again);
    try std.testing.expectEqual(@as(usize, 6), hits2);
    try std.testing.expectEqualStrings("rep-old", left);
    try conn.execSimple("ROLLBACK");
}

fn countHits(allocator: std.mem.Allocator, io: std.Io) !usize {
    const text = std.Io.Dir.cwd().readFileAlloc(io, "zig-out/rep-hits.txt", allocator, std.Io.Limit.limited(1 << 20)) catch return 0;
    defer allocator.free(text);
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| if (line.len > 0 and line[0] == '/') {
        n += 1;
    };
    return n;
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
