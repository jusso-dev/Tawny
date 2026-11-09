//! Fixture tests for the built-in rules in `rules/builtin/`. Each test makes
//! its own tenant, seeds the built-ins into it, stores events with explicit
//! event times and runs them through the detect job's rule evaluation.
//! Every starter rule fires once on its fixture and not on a near miss.
//! Needs TAWNY_DATABASE_URL.

const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const detect = @import("../jobs/detect.zig");
const builtin = @import("builtin.zig");
const purge = @import("../jobs/purge.zig");

const testing = std.testing;

const Fixture = struct {
    conn: *pg.Conn,
    tenant: []const u8,
    agent: []const u8,
    cache: detect.RuleCache,

    fn evt(f: *Fixture, event_type: []const u8, when: []const u8, payload: []const u8) ![]u8 {
        const a = testing.allocator;
        const rows = f.conn.exec(a,
            \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
            \\VALUES (now(), $1::uuid, $2::uuid, $3, $4::timestamptz, $5::jsonb)
            \\RETURNING id::text, received_at::text
        , &.{ .{ .text = f.tenant }, .{ .text = f.agent }, .{ .text = event_type }, .{ .text = when }, .{ .text = payload } }) catch |err| {
            if (f.conn.takeError()) |msg| {
                std.debug.print("postgres: {s}\npayload: {s}\n", .{ msg, payload });
                f.conn.allocator.free(msg);
            }
            return err;
        };
        defer {
            for (rows) |r| r.deinit(a);
            a.free(rows);
        }
        errdefer if (f.conn.takeError()) |msg| {
            std.debug.print("postgres: {s}\n", .{msg});
            f.conn.allocator.free(msg);
        };
        try detect.evaluateRules(a, testing.io, f.conn, &f.cache, .{
            .tenant_id = f.tenant,
            .agent_id = f.agent,
            .hostname = "corr-host",
            .event_type = event_type,
            .payload = payload,
            .event_id = rows[0].cols[0].?,
            .received_at = rows[0].cols[1].?,
            .occurred_at = when,
        });
        return a.dupe(u8, rows[0].cols[0].?);
    }

    fn alerts(f: *Fixture, external_id: []const u8) !usize {
        const a = testing.allocator;
        const rows = try f.conn.exec(a,
            \\SELECT count(*)::text FROM alerts al JOIN alert_rules r ON r.id = al.alert_rule_id
            \\WHERE al.tenant_id = $1::uuid AND r.external_id = $2
        , &.{ .{ .text = f.tenant }, .{ .text = external_id } });
        defer {
            for (rows) |r| r.deinit(a);
            a.free(rows);
        }
        return std.fmt.parseInt(usize, rows[0].cols[0].?, 10);
    }
};

fn setup(conn: *pg.Conn, tenant: []const u8, agent: []const u8) !Fixture {
    const a = testing.allocator;
    try conn.execNoRows(
        \\INSERT INTO tenants (id, slug, name, created_at) VALUES ($1::uuid, $1, 'corr', now())
    , &.{.{ .text = tenant }});
    try conn.execNoRows(
        \\INSERT INTO agents (id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status)
        \\VALUES ($1::uuid, $2::uuid, 'corr-host', 'windows', 'test', '0', 'x64', now(), 'online')
    , &.{ .{ .text = agent }, .{ .text = tenant } });
    const added = try builtin.ensureSeeded(a, testing.io, conn);
    try testing.expect(added >= builtin.files.len);
    // Seeding again adds nothing.
    try testing.expectEqual(@as(u32, 0), try builtin.ensureSeeded(a, testing.io, conn));
    return .{ .conn = conn, .tenant = tenant, .agent = agent, .cache = detect.RuleCache.init(a) };
}

fn connect() !?*pg.Conn {
    const url = testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return null;
    if (url.len == 0) return null;
    return try pg.Conn.connect(testing.allocator, testing.io, url);
}

fn close(conn: *pg.Conn) void {
    conn.close();
    testing.allocator.destroy(conn);
}

/// Event time `minute` minutes and `second` seconds after 02:00 (seconds
/// may run past 59).
fn at(buf: []u8, minute: u32, second: u32) []const u8 {
    const total = minute * 60 + second;
    return std.fmt.bufPrint(buf, "2026-11-09T{d:0>2}:{d:0>2}:{d:0>2}Z", .{ 2 + total / 3600, (total / 60) % 60, total % 60 }) catch unreachable;
}

const failed_rule = "tawny-builtin:failed-logons-then-success";
const ip_rule = "tawny-builtin:failed-logons-from-one-ip";
const office_rule = "tawny-builtin:office-spawns-shell";
const service_rule = "tawny-builtin:service-in-user-writable-folder";
const enc_rule = "tawny-builtin:encoded-powershell-then-connect";

fn failedLogon(buf: []u8, user: []const u8, ip: []const u8) []const u8 {
    return std.fmt.bufPrint(buf,
        \\{{"event_id":4625,"user":{{"name":"{s}","domain":"CORP"}},"logon":{{"type":3}},"network":{{"src_ip":"{s}"}}}}
    , .{ user, ip }) catch unreachable;
}

fn logon(buf: []u8, user: []const u8) []const u8 {
    return std.fmt.bufPrint(buf,
        \\{{"event_id":4624,"user":{{"name":"{s}","domain":"CORP"}},"logon":{{"type":3}},"network":{{"src_ip":"198.51.100.7"}}}}
    , .{user}) catch unreachable;
}

test "builtin: five failed logons then a success fires once, near misses do not" {
    const conn = (try connect()) orelse return;
    defer close(conn);
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};
    var f = try setup(conn, "00000000-0000-0000-0000-0000000c0001", "00000000-0000-0000-0000-0000000c00a1");
    defer f.cache.deinit();
    var tb: [32]u8 = undefined;
    var pb: [256]u8 = undefined;

    // Hit: alice fails 5 times in 2 minutes, then logs on at minute 4.
    for (0..5) |i| testing.allocator.free(try f.evt("user_logon_failed", at(&tb, 0, @intCast(i * 20)), failedLogon(&pb, "alice", "198.51.100.7")));
    try testing.expectEqual(@as(usize, 0), try f.alerts(failed_rule));
    testing.allocator.free(try f.evt("user_logon", at(&tb, 4, 0), logon(&pb, "Alice")));
    try testing.expectEqual(@as(usize, 1), try f.alerts(failed_rule));
    // A second success does not fire again: the sequence was consumed.
    testing.allocator.free(try f.evt("user_logon", at(&tb, 4, 30), logon(&pb, "alice")));
    try testing.expectEqual(@as(usize, 1), try f.alerts(failed_rule));

    // Near miss 1: bob fails only 4 times.
    for (0..4) |i| testing.allocator.free(try f.evt("user_logon_failed", at(&tb, 10, @intCast(i * 10)), failedLogon(&pb, "bob", "198.51.100.8")));
    testing.allocator.free(try f.evt("user_logon", at(&tb, 11, 0), logon(&pb, "bob")));
    // Near miss 2: carol fails 5 times but succeeds 11 minutes after the first failure.
    for (0..5) |i| testing.allocator.free(try f.evt("user_logon_failed", at(&tb, 20, @intCast(i * 10)), failedLogon(&pb, "carol", "198.51.100.9")));
    testing.allocator.free(try f.evt("user_logon", at(&tb, 31, 1), logon(&pb, "carol")));
    // Near miss 3: dave fails 5 times, but erin is the one who logs on.
    for (0..5) |i| testing.allocator.free(try f.evt("user_logon_failed", at(&tb, 40, @intCast(i * 10)), failedLogon(&pb, "dave", "198.51.100.10")));
    testing.allocator.free(try f.evt("user_logon", at(&tb, 41, 0), logon(&pb, "erin")));
    try testing.expectEqual(@as(usize, 1), try f.alerts(failed_rule));
    try testing.expectEqual(@as(usize, 0), try f.alerts(ip_rule));
    std.debug.print("builtin_failed_then_success alerts=1 near_misses=0\n", .{});
    try conn.execSimple("ROLLBACK");
}

test "builtin: more than 20 failed logons from one IP in 5 minutes" {
    const conn = (try connect()) orelse return;
    defer close(conn);
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};
    var f = try setup(conn, "00000000-0000-0000-0000-0000000c0002", "00000000-0000-0000-0000-0000000c00a2");
    defer f.cache.deinit();
    var tb: [32]u8 = undefined;
    var pb: [256]u8 = undefined;
    var ub: [16]u8 = undefined;

    // Near miss: exactly 20 from 203.0.113.50 in 4 minutes.
    for (0..20) |i| {
        const user = std.fmt.bufPrint(&ub, "user{d}", .{i}) catch unreachable;
        testing.allocator.free(try f.evt("user_logon_failed", at(&tb, 0, @intCast(i * 12)), failedLogon(&pb, user, "203.0.113.50")));
    }
    try testing.expectEqual(@as(usize, 0), try f.alerts(ip_rule));
    // Near miss: a 21st from another IP.
    testing.allocator.free(try f.evt("user_logon_failed", at(&tb, 4, 10), failedLogon(&pb, "x", "203.0.113.51")));
    try testing.expectEqual(@as(usize, 0), try f.alerts(ip_rule));
    // Near miss: the 21st from the same IP but 6 minutes later, so the window
    // holds fewer than 21.
    testing.allocator.free(try f.evt("user_logon_failed", at(&tb, 9, 0), failedLogon(&pb, "x", "203.0.113.50")));
    try testing.expectEqual(@as(usize, 0), try f.alerts(ip_rule));

    // Hit: 21 from 203.0.113.60 in 2 minutes. Fires once at the 21st.
    for (0..25) |i| {
        testing.allocator.free(try f.evt("user_logon_failed", at(&tb, 20, @intCast(i * 2)), failedLogon(&pb, "admin", "203.0.113.60")));
    }
    try testing.expectEqual(@as(usize, 1), try f.alerts(ip_rule));
    std.debug.print("builtin_ip_threshold alerts=1 near_misses=0\n", .{});
    try conn.execSimple("ROLLBACK");
}

test "builtin: office starts a shell, and a new service in a user folder" {
    const conn = (try connect()) orelse return;
    defer close(conn);
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};
    var f = try setup(conn, "00000000-0000-0000-0000-0000000c0003", "00000000-0000-0000-0000-0000000c00a3");
    defer f.cache.deinit();
    var tb: [32]u8 = undefined;

    const golden = try std.Io.Dir.cwd().readFileAlloc(testing.io, "../schemas/events/golden/process_start.json", testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(golden);
    // Hit: the golden payload is WINWORD.EXE starting powershell.exe.
    testing.allocator.free(try f.evt("process_start", at(&tb, 0, 0), golden));
    // Near misses: explorer starting powershell, and Word starting notepad.
    testing.allocator.free(try f.evt("process_start", at(&tb, 0, 1),
        \\{"process":{"pid":1,"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},"parent":{"image":"C:\\Windows\\explorer.exe"}}
    ));
    testing.allocator.free(try f.evt("process_start", at(&tb, 0, 2),
        \\{"process":{"pid":2,"image":"C:\\Windows\\System32\\notepad.exe"},"parent":{"image":"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"}}
    ));
    try testing.expectEqual(@as(usize, 1), try f.alerts(office_rule));

    const svc_golden = try std.Io.Dir.cwd().readFileAlloc(testing.io, "../schemas/events/golden/service_create.json", testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(svc_golden);
    // Hit: golden 7045 installs a service from AppData\Local\Temp.
    testing.allocator.free(try f.evt("service_create", at(&tb, 1, 0), svc_golden));
    // Near miss: a service under Program Files.
    testing.allocator.free(try f.evt("service_create", at(&tb, 1, 1),
        \\{"event_id":7045,"service":{"name":"Vendor","image_path":"\"C:\\Program Files\\Vendor\\svc.exe\" -k","start_type":"auto start"}}
    ));
    try testing.expectEqual(@as(usize, 1), try f.alerts(service_rule));
    std.debug.print("builtin_office_and_service office=1 service=1\n", .{});
    try conn.execSimple("ROLLBACK");
}

const enc_start =
    \\{"process":{"entity_id":"aaaaaaaaaaaaaaaaaaaaaaaaaa","pid":10,"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","command_line":"powershell.exe -NoP -enc SQBFAFgA"},"parent":{"image":"C:\\Windows\\explorer.exe"}}
;
const plain_start =
    \\{"process":{"entity_id":"bbbbbbbbbbbbbbbbbbbbbbbbbb","pid":11,"image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","command_line":"powershell.exe -NoP -File x.ps1"}}
;

fn connectFor(buf: []u8, entity: []const u8, direction: []const u8) []const u8 {
    return std.fmt.bufPrint(buf,
        \\{{"process":{{"entity_id":"{s}","pid":10}},"network":{{"protocol":"tcp","direction":"{s}","dst_ip":"203.0.113.10","dst_port":443}}}}
    , .{ entity, direction }) catch unreachable;
}

test "builtin: encoded powershell then an outbound connection from the same entity" {
    const conn = (try connect()) orelse return;
    defer close(conn);
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};
    var f = try setup(conn, "00000000-0000-0000-0000-0000000c0004", "00000000-0000-0000-0000-0000000c00a4");
    defer f.cache.deinit();
    var tb: [32]u8 = undefined;
    var pb: [512]u8 = undefined;

    // Near misses: a connection before the encoded start, an inbound one,
    // one from another entity, and a plain PowerShell that then connects.
    testing.allocator.free(try f.evt("network_connect", at(&tb, 0, 0), connectFor(&pb, "aaaaaaaaaaaaaaaaaaaaaaaaaa", "outbound")));
    testing.allocator.free(try f.evt("process_start", at(&tb, 0, 5), enc_start));
    testing.allocator.free(try f.evt("network_connect", at(&tb, 0, 6), connectFor(&pb, "aaaaaaaaaaaaaaaaaaaaaaaaaa", "inbound")));
    testing.allocator.free(try f.evt("network_connect", at(&tb, 0, 7), connectFor(&pb, "cccccccccccccccccccccccccc", "outbound")));
    testing.allocator.free(try f.evt("process_start", at(&tb, 0, 8), plain_start));
    testing.allocator.free(try f.evt("network_connect", at(&tb, 0, 9), connectFor(&pb, "bbbbbbbbbbbbbbbbbbbbbbbbbb", "outbound")));
    try testing.expectEqual(@as(usize, 0), try f.alerts(enc_rule));
    // Hit: the encoded process connects out.
    testing.allocator.free(try f.evt("network_connect", at(&tb, 1, 0), connectFor(&pb, "aaaaaaaaaaaaaaaaaaaaaaaaaa", "outbound")));
    try testing.expectEqual(@as(usize, 1), try f.alerts(enc_rule));
    // Only once.
    testing.allocator.free(try f.evt("network_connect", at(&tb, 1, 1), connectFor(&pb, "aaaaaaaaaaaaaaaaaaaaaaaaaa", "outbound")));
    try testing.expectEqual(@as(usize, 1), try f.alerts(enc_rule));
    std.debug.print("builtin_encoded_then_connect alerts=1 near_misses=0\n", .{});
    try conn.execSimple("ROLLBACK");
}

const restart_tenant = "00000000-0000-0000-0000-0000000c0005";
const restart_agent = "00000000-0000-0000-0000-0000000c00a5";

fn cleanupRestart(conn: *pg.Conn) void {
    const stmts = [_][]const u8{
        "DELETE FROM work_queue WHERE tenant_id = $1::uuid",
        "DELETE FROM incident_alerts WHERE tenant_id = $1::uuid",
        "DELETE FROM incidents WHERE tenant_id = $1::uuid",
        "DELETE FROM alerts WHERE tenant_id = $1::uuid",
        "DELETE FROM sequence_state WHERE tenant_id = $1::uuid",
        "DELETE FROM threshold_counters WHERE tenant_id = $1::uuid",
        "DELETE FROM telemetry_events WHERE tenant_id = $1::uuid",
        "DELETE FROM alert_rules WHERE tenant_id = $1::uuid",
        "DELETE FROM agents WHERE tenant_id = $1::uuid",
        "DELETE FROM tenants WHERE id = $1::uuid",
    };
    for (stmts) |s| conn.execNoRows(s, &.{.{ .text = restart_tenant }}) catch {};
}

test "sequence and threshold state survive a reconnect" {
    const first = (try connect()) orelse return;
    cleanupRestart(first);
    var tb: [32]u8 = undefined;
    var pb: [256]u8 = undefined;
    {
        defer close(first);
        // Committed, like a running server: no transaction around this part.
        var f = try setup(first, restart_tenant, restart_agent);
        defer f.cache.deinit();
        for (0..5) |i| testing.allocator.free(try f.evt("user_logon_failed", at(&tb, 0, @intCast(i * 5)), failedLogon(&pb, "frank", "192.0.2.77")));
        for (0..15) |i| testing.allocator.free(try f.evt("user_logon_failed", at(&tb, 1, @intCast(i * 2)), failedLogon(&pb, "x", "192.0.2.77")));
        try testing.expectEqual(@as(usize, 0), try f.alerts(failed_rule));
        try testing.expectEqual(@as(usize, 0), try f.alerts(ip_rule));
    }
    // New connection and a fresh rule cache stand in for a restarted server.
    const second = (try connect()).?;
    defer close(second);
    defer cleanupRestart(second);
    var f: Fixture = .{ .conn = second, .tenant = restart_tenant, .agent = restart_agent, .cache = detect.RuleCache.init(testing.allocator) };
    defer f.cache.deinit();
    testing.allocator.free(try f.evt("user_logon", at(&tb, 2, 0), logon(&pb, "frank")));
    try testing.expectEqual(@as(usize, 1), try f.alerts(failed_rule));
    // 20 failures so far from 192.0.2.77; the 21st after the restart fires.
    testing.allocator.free(try f.evt("user_logon_failed", at(&tb, 2, 10), failedLogon(&pb, "y", "192.0.2.77")));
    try testing.expectEqual(@as(usize, 1), try f.alerts(ip_rule));

    // Purge drops expired state and keeps live state.
    try second.execNoRows(
        \\INSERT INTO threshold_counters (tenant_id, rule_id, by_key, event_id, occurred_at, expires_at)
        \\SELECT $1::uuid, id, 'old', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:05:00Z' FROM alert_rules
        \\WHERE tenant_id = $1::uuid AND external_id = $2
    , &.{ .{ .text = restart_tenant }, .{ .text = ip_rule } });
    try purge.purgeDetectionState(second, "2026-11-09T03:00:00Z");
    const rows = try second.exec(testing.allocator, "SELECT count(*)::text FROM threshold_counters WHERE tenant_id = $1::uuid AND by_key = 'old'", &.{.{ .text = restart_tenant }});
    defer {
        for (rows) |r| r.deinit(testing.allocator);
        testing.allocator.free(rows);
    }
    try testing.expectEqualStrings("0", rows[0].cols[0].?);
    std.debug.print("restart_state sequence_alerts=1 threshold_alerts=1 purged_old=1\n", .{});
}
