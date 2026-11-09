//! YARA rule packs and `yara_match` alerts.
//!
//! - `POST /api/alert-rules/yara` (admin): store a tenant YARA rule. The
//!   source goes in `source_definition`. The server does not compile YARA,
//!   so it only checks size and that the text names at least one rule; the
//!   agent compiles the bundled pack and refuses it whole if any rule fails.
//! - `GET /api/yara/rule-key` (web): the base64 rule-pack public key to
//!   pin in agent config as `yara_rule_key`.
//! - `POST /api/agent/yara-rules` (agent JWT): the tenant's enabled YARA
//!   rules concatenated into one source and signed. Format and signed bytes
//!   match `agent/src/rule_pack.zig`.
//!
//! A `yara_match` event raises an alert through the `yara` rule that names
//! the matched rule (see `jobs/detect.zig`), so YARA alerts use the normal
//! suppression and sink path.

const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");
const audit = @import("../http/audit.zig");
const state = @import("../http/state.zig");
const Ed25519 = std.crypto.sign.Ed25519;

pub const pack_format = "tawny-yara-pack-v1";
const max_rule_bytes = 256 * 1024;
const max_pack_bytes = 4 * 1024 * 1024;

pub fn signedBytes(allocator: std.mem.Allocator, tenant_id: []const u8, version: u64, created_at: []const u8, sha256_hex: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}\n{s}\n{d}\n{s}\n{s}\n", .{ pack_format, tenant_id, version, created_at, sha256_hex });
}

pub fn keyId(public_key: [32]u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&public_key, &digest, .{});
    return std.fmt.bytesToHex(digest[0..16].*, .lower);
}

/// Signed pack JSON for `source`.
pub fn buildPack(allocator: std.mem.Allocator, kp: Ed25519.KeyPair, tenant_id: []const u8, version: u64, created_at: []const u8, source: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const msg = try signedBytes(allocator, tenant_id, version, created_at, &hex);
    defer allocator.free(msg);
    const sig = try kp.sign(msg, null);
    const enc = std.base64.standard.Encoder;
    var sig_b64: [88]u8 = undefined;
    const sig_text = enc.encode(&sig_b64, &sig.toBytes());
    const src_b64 = try allocator.alloc(u8, enc.calcSize(source.len));
    defer allocator.free(src_b64);
    _ = enc.encode(src_b64, source);
    const kid = keyId(kp.public_key.bytes);
    const tenant_j = try util.escapeJson(allocator, tenant_id);
    defer allocator.free(tenant_j);
    const created_j = try util.escapeJson(allocator, created_at);
    defer allocator.free(created_j);
    return std.fmt.allocPrint(allocator,
        \\{{"format":"{s}","tenant_id":{s},"version":{d},"created_at":{s},"key_id":"{s}","rules_b64":"{s}","sha256":"{s}","signature":"{s}"}}
    , .{ pack_format, tenant_j, version, created_j, &kid, src_b64, &hex, sig_text });
}

pub fn publicKeyB64(buf: *[44]u8, kp: Ed25519.KeyPair) []const u8 {
    return std.base64.standard.Encoder.encode(buf, &kp.public_key.bytes);
}

/// Rule names declared in YARA source (`rule name`, `private rule name`,
/// `global rule name`). Comments and strings are skipped well enough for
/// naming; the agent's compiler is the real check.
pub fn ruleNames(allocator: std.mem.Allocator, source: []const u8) ![][]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < source.len) {
        const c = source[i];
        if (c == '/' and i + 1 < source.len and source[i + 1] == '/') {
            while (i < source.len and source[i] != '\n') i += 1;
            continue;
        }
        if (c == '/' and i + 1 < source.len and source[i + 1] == '*') {
            i += 2;
            while (i + 1 < source.len and !(source[i] == '*' and source[i + 1] == '/')) i += 1;
            i += 2;
            continue;
        }
        if (c == '"') {
            i += 1;
            while (i < source.len and source[i] != '"') : (i += 1) {
                if (source[i] == '\\') i += 1;
            }
            i += 1;
            continue;
        }
        if (std.mem.startsWith(u8, source[i..], "rule") and (i == 0 or !isIdent(source[i - 1])) and i + 4 < source.len and std.ascii.isWhitespace(source[i + 4])) {
            var j = i + 4;
            while (j < source.len and std.ascii.isWhitespace(source[j])) j += 1;
            const start = j;
            while (j < source.len and isIdent(source[j])) j += 1;
            if (j > start) try out.append(allocator, source[start..j]);
            i = j;
            continue;
        }
        i += 1;
    }
    return out.toOwnedSlice(allocator);
}

fn isIdent(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

pub fn createRule(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    if (web.session_id != null and !auth.checkCsrf(request, web)) {
        try util.respondJson(request, .forbidden, "{\"error\":\"csrf\"}");
        return;
    }
    const body = try util.readBody(allocator, request, max_rule_bytes + 4096);
    defer allocator.free(body);
    const Req = struct {
        name: ?[]const u8 = null,
        rule_source: []const u8,
        severity: []const u8 = "high",
        is_enabled: bool = true,
        mitre_techniques: ?[]const []const u8 = null,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "rule_source is required.");
    };
    defer parsed.deinit();
    const src = parsed.value.rule_source;
    if (src.len == 0 or src.len > max_rule_bytes) return util.problem(request, allocator, .bad_request, "rule_source must be 1 to 262144 bytes.");
    const names = try ruleNames(allocator, src);
    defer allocator.free(names);
    if (names.len == 0) return util.problem(request, allocator, .bad_request, "rule_source declares no YARA rule.");
    const sev = parsed.value.severity;
    if (!(std.mem.eql(u8, sev, "low") or std.mem.eql(u8, sev, "medium") or std.mem.eql(u8, sev, "high") or std.mem.eql(u8, sev, "critical"))) {
        return util.problem(request, allocator, .bad_request, "severity must be low, medium, high or critical.");
    }
    const name = parsed.value.name orelse names[0];
    if (name.len == 0 or name.len > 160) return util.problem(request, allocator, .bad_request, "name must be 1 to 160 characters.");
    // Alerts find the rule by the YARA rule names it declares.
    const names_arr = try util.pgArrayText(allocator, names);
    defer allocator.free(names_arr);
    const mitre = try util.pgArrayText(allocator, parsed.value.mitre_techniques orelse &.{});
    defer allocator.free(mitre);
    var id_buf: [36]u8 = undefined;
    const id = util.newUuid(io, &id_buf);
    var tbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&tbuf, util.nowUnix(io));
    try conn.execNoRows(
        \\INSERT INTO alert_rules (id, tenant_id, name, format, event_type, severity, operator, source_definition,
        \\  compile_notes, is_enabled, mitre_techniques, created_at, updated_at)
        \\VALUES ($1::uuid, $2::uuid, $3, 'yara', 'yara_match', $4, 'exists', $5, $6::text[], $7::boolean, $8::text[],
        \\  $9::timestamptz, $9::timestamptz)
    , &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
        .{ .text = name },
        .{ .text = sev },
        .{ .text = src },
        .{ .text = names_arr },
        .{ .text = if (parsed.value.is_enabled) "true" else "false" },
        .{ .text = mitre },
        .{ .text = now_s },
    });
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "alert_rule.create_yara", id, null);
    const id_j = try util.escapeJson(allocator, id);
    defer allocator.free(id_j);
    const name_j = try util.escapeJson(allocator, name);
    defer allocator.free(name_j);
    const names_json = try util.jsonArrayStrings(allocator, names);
    defer allocator.free(names_json);
    const out = try std.fmt.allocPrint(allocator, "{{\"id\":{s},\"name\":{s},\"format\":\"yara\",\"event_type\":\"yara_match\",\"yara_rules\":{s}}}", .{ id_j, name_j, names_json });
    defer allocator.free(out);
    try util.respondJson(request, .created, out);
}

pub fn ruleKey(allocator: std.mem.Allocator, io: std.Io, request: *std.http.Server.Request) !void {
    const kp = try state.rulePackKey(io);
    var buf: [44]u8 = undefined;
    const kid = keyId(kp.public_key.bytes);
    const out = try std.fmt.allocPrint(allocator, "{{\"format\":\"{s}\",\"public_key\":\"{s}\",\"key_id\":\"{s}\"}}", .{ pack_format, publicKeyB64(&buf, kp), &kid });
    defer allocator.free(out);
    try util.respondJson(request, .ok, out);
}

/// Bundle enabled YARA rules for a tenant. Version is the newest
/// `updated_at` in microseconds, so any edit, enable or disable changes it.
pub const Bundle = struct {
    source: []u8,
    version: u64,
    count: usize,
};

pub fn bundle(allocator: std.mem.Allocator, conn: *pg.Conn, tenant_id: []const u8) !Bundle {
    const rows = try conn.exec(allocator,
        \\SELECT source_definition, (extract(epoch from updated_at) * 1000000)::bigint::text, name
        \\FROM alert_rules
        \\WHERE tenant_id = $1::uuid AND format = 'yara' AND is_enabled AND source_definition IS NOT NULL
        \\ORDER BY created_at, id
    , &.{.{ .text = tenant_id }});
    defer {
        for (rows) |r| r.deinit(allocator);
        allocator.free(rows);
    }
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var version: u64 = 0;
    for (rows) |r| {
        const src = r.cols[0] orelse continue;
        if (out.items.len + src.len > max_pack_bytes) break;
        try out.appendSlice(allocator, "// tawny rule: ");
        for (r.cols[2] orelse "") |c| try out.append(allocator, if (c == '\n' or c == '\r') ' ' else c);
        try out.append(allocator, '\n');
        try out.appendSlice(allocator, src);
        try out.append(allocator, '\n');
        const v = std.fmt.parseInt(u64, r.cols[1] orelse "0", 10) catch 0;
        version = @max(version, v);
    }
    // Disabling the last rule must still change the version.
    version = @max(version, try lastChange(allocator, conn, tenant_id));
    return .{ .source = try out.toOwnedSlice(allocator), .version = version, .count = rows.len };
}

fn lastChange(allocator: std.mem.Allocator, conn: *pg.Conn, tenant_id: []const u8) !u64 {
    const rows = try conn.exec(allocator,
        \\SELECT coalesce(max((extract(epoch from updated_at) * 1000000)::bigint), 0)::text
        \\FROM alert_rules WHERE tenant_id = $1::uuid AND format = 'yara'
    , &.{.{ .text = tenant_id }});
    defer {
        for (rows) |r| r.deinit(allocator);
        allocator.free(rows);
    }
    return std.fmt.parseInt(u64, (if (rows.len > 0) rows[0].cols[0] else null) orelse "0", 10) catch 0;
}

/// Version only, for the heartbeat reply.
pub fn packVersion(allocator: std.mem.Allocator, conn: *pg.Conn, tenant_id: []const u8) !u64 {
    return lastChange(allocator, conn, tenant_id);
}

pub fn agentPack(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    agent: auth.AgentAuth,
) !void {
    _ = util.readBody(allocator, request, 1024) catch {};
    const b = try bundle(allocator, conn, agent.tenant_id);
    defer allocator.free(b.source);
    const kp = try state.rulePackKey(io);
    var tbuf: [32]u8 = undefined;
    const created = util.formatRfc3339(&tbuf, util.nowUnix(io));
    const pack = try buildPack(allocator, kp, agent.tenant_id, b.version, created, b.source);
    defer allocator.free(pack);
    try util.respondJson(request, .ok, pack);
}

test "rule names are found outside comments and strings" {
    const a = std.testing.allocator;
    const names = try ruleNames(a,
        \\// rule commented_out
        \\/* rule also_not */
        \\private rule helper { condition: true }
        \\rule eicar : test { strings: $a = "rule fake" condition: $a and helper }
        \\global rule g{condition:true}
    );
    defer a.free(names);
    try std.testing.expectEqual(@as(usize, 3), names.len);
    try std.testing.expectEqualStrings("helper", names[0]);
    try std.testing.expectEqualStrings("eicar", names[1]);
    try std.testing.expectEqualStrings("g", names[2]);
}

test "pack signature covers tenant, version, time and source hash" {
    const a = std.testing.allocator;
    const kp = Ed25519.KeyPair.generate(std.testing.io);
    const pack = try buildPack(a, kp, "00000000-0000-0000-0000-000000000001", 5, "2026-11-10T00:00:00Z", "rule a { condition: true }");
    defer a.free(pack);
    const P = struct { tenant_id: []const u8, version: u64, created_at: []const u8, sha256: []const u8, signature: []const u8, rules_b64: []const u8 };
    var parsed = try std.json.parseFromSlice(P, a, pack, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const msg = try signedBytes(a, parsed.value.tenant_id, parsed.value.version, parsed.value.created_at, parsed.value.sha256);
    defer a.free(msg);
    var sig_bytes: [64]u8 = undefined;
    try std.base64.standard.Decoder.decode(&sig_bytes, parsed.value.signature);
    try Ed25519.Signature.fromBytes(sig_bytes).verify(msg, kp.public_key);
    const other = try signedBytes(a, parsed.value.tenant_id, 6, parsed.value.created_at, parsed.value.sha256);
    defer a.free(other);
    try std.testing.expectError(error.SignatureVerificationFailed, Ed25519.Signature.fromBytes(sig_bytes).verify(other, kp.public_key));
}

const default_tenant = "00000000-0000-0000-0000-000000000001";
const yara_agent = "00000000-0000-0000-0000-00000000ea01";
const yara_rule = "00000000-0000-0000-0000-00000000ea02";

test "yara rules bundle into a signed pack and yara_match raises one alert" {
    const url = std.testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return;
    if (url.len == 0) return;
    const detect = @import("../jobs/detect.zig");
    const a = std.testing.allocator;
    const io = std.testing.io;
    const conn = try pg.Conn.connect(a, io, url);
    defer {
        conn.close();
        a.destroy(conn);
    }
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};
    try conn.execNoRows(
        \\INSERT INTO agents (id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status)
        \\VALUES ($1, $2, 'yara-host', 'linux', 'test', '0', 'x64', now(), 'online')
    , &.{ .{ .text = yara_agent }, .{ .text = default_tenant } });
    const src = "rule tawny_test_marker : test { strings: $a = \"tawny-yara-marker\" condition: $a }";
    try conn.execNoRows(
        \\INSERT INTO alert_rules (id, tenant_id, name, format, event_type, severity, operator,
        \\  source_definition, compile_notes, created_at, updated_at)
        \\VALUES ($1, $2, 'yara marker', 'yara', 'yara_match', 'high', 'exists', $3, '{tawny_test_marker}', now(), now())
    , &.{ .{ .text = yara_rule }, .{ .text = default_tenant }, .{ .text = src } });

    const b = try bundle(a, conn, default_tenant);
    defer a.free(b.source);
    try std.testing.expect(std.mem.indexOf(u8, b.source, "tawny_test_marker") != null);
    try std.testing.expect(b.version > 0);
    try std.testing.expectEqual(b.version, try packVersion(a, conn, default_tenant));

    // Pack signs with the rule key and verifies against its public key.
    const kp = try state.rulePackKey(io);
    const pack = try buildPack(a, kp, default_tenant, b.version, "2026-11-10T00:00:00Z", b.source);
    defer a.free(pack);
    try std.testing.expect(std.mem.indexOf(u8, pack, "\"signature\":\"") != null);

    var cache = detect.RuleCache.init(a);
    defer cache.deinit();
    const payloads = [_][]const u8{
        "{\"rule\":\"tawny_test_marker\",\"tags\":[\"test\"],\"file\":{\"path\":\"/tmp/x.exe\",\"hashes\":{\"sha256\":\"ab\"}},\"trigger\":\"file_event\"}",
        "{\"rule\":\"some_other_rule\",\"tags\":[],\"file\":{\"path\":\"/tmp/y.exe\"},\"trigger\":\"scheduled\"}",
    };
    const want = [_][]const u8{ "1", "0" };
    for (payloads, 0..) |pl, i| {
        const rows = try conn.exec(a,
            \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
            \\VALUES (now(), $1, $2, 'yara_match', now(), $3::jsonb) RETURNING id::text, received_at::text, occurred_at::text
        , &.{ .{ .text = default_tenant }, .{ .text = yara_agent }, .{ .text = pl } });
        defer {
            for (rows) |r| r.deinit(a);
            a.free(rows);
        }
        try detect.evaluateRules(a, io, conn, &cache, .{
            .tenant_id = default_tenant,
            .agent_id = yara_agent,
            .hostname = "yara-host",
            .event_type = "yara_match",
            .payload = pl,
            .event_id = rows[0].cols[0].?,
            .received_at = rows[0].cols[1].?,
            .occurred_at = rows[0].cols[2].?,
        });
        const n = try conn.exec(a, "SELECT count(*)::text, max(description) FROM alerts WHERE telemetry_event_id = $1::bigint AND alert_rule_id = $2::uuid", &.{ .{ .text = rows[0].cols[0].? }, .{ .text = yara_rule } });
        defer {
            for (n) |r| r.deinit(a);
            a.free(n);
        }
        std.debug.print("yara_alert event={d} alerts={s} description={s}\n", .{ i, n[0].cols[0].?, n[0].cols[1] orelse "-" });
        try std.testing.expectEqualStrings(want[i], n[0].cols[0].?);
    }
    try conn.execSimple("ROLLBACK");
}

test "server pack is byte-identical to the agent's rule_pack.sign output" {
    // Same test-only seed (bytes 0..31) as the vector produced by
    // agent/src/rule_pack.zig `sign`; Ed25519 signatures are deterministic.
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    const pack = try buildPack(std.testing.allocator, kp, "00000000-0000-0000-0000-000000000001", 42, "2026-11-10T00:00:00Z", "rule golden_pack { condition: true }\n");
    defer std.testing.allocator.free(pack);
    try std.testing.expectEqualStrings(
        \\{"format":"tawny-yara-pack-v1","tenant_id":"00000000-0000-0000-0000-000000000001","version":42,"created_at":"2026-11-10T00:00:00Z","key_id":"56475aa75463474c0285df5dbf2bcab7","rules_b64":"cnVsZSBnb2xkZW5fcGFjayB7IGNvbmRpdGlvbjogdHJ1ZSB9Cg==","sha256":"5001c139c60708851dbc2ceaafbe756d48b57a832e36936bd1456c423f7c091c","signature":"kkzHrm9dM8M9MQYknKpqNGipqAEjuLq/oLjV9teWYsC2527MtLnDG8zEswRTkHKzvUF1UUZ8UrS0RywYhzuvDg=="}
    , pack);
}
