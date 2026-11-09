//! Incident grouping against Postgres. Each test runs in a transaction and
//! rolls back. Needs TAWNY_DATABASE_URL; skips without it.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const detect = @import("../jobs/detect.zig");
const incidents = @import("incidents.zig");

const testing = std.testing;
const tenant = "00000000-0000-0000-0000-000000000001";
const other_tenant = "00000000-0000-0000-0000-0000000ee060";
const agent_a = "00000000-0000-0000-0000-0000000e6001";
const agent_b = "00000000-0000-0000-0000-0000000e6002";
const rule_office = "00000000-0000-0000-0000-0000000e6011";
const rule_enc = "00000000-0000-0000-0000-0000000e6012";
const rule_ioc = "00000000-0000-0000-0000-0000000e6013";
const rule_other = "00000000-0000-0000-0000-0000000e6014";

// Entity ids: 26 base32 characters. explorer > winword > powershell > child.
const e_explorer = "aaaaaaaaaaaaaaaaaaaaaaaaaa";
const e_word = "bbbbbbbbbbbbbbbbbbbbbbbbbb";
const e_ps = "cccccccccccccccccccccccccc";
const e_child = "dddddddddddddddddddddddddd";
const e_unrelated = "eeeeeeeeeeeeeeeeeeeeeeeeee";

fn connect() !?*pg.Conn {
    const url = testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return null;
    if (url.len == 0) return null;
    return try pg.Conn.connect(testing.allocator, testing.io, url);
}

fn close(conn: *pg.Conn) void {
    conn.close();
    testing.allocator.destroy(conn);
}

fn exec(conn: *pg.Conn, sql: []const u8, params: []const pg.Value) !void {
    conn.execNoRows(sql, params) catch |err| {
        if (conn.takeError()) |msg| {
            std.debug.print("postgres: {s}\n{s}\n", .{ msg, sql });
            conn.allocator.free(msg);
        }
        return err;
    };
}

fn scalar(conn: *pg.Conn, sql: []const u8, params: []const pg.Value) ![]u8 {
    const a = testing.allocator;
    const rows = conn.exec(a, sql, params) catch |err| {
        if (conn.takeError()) |msg| {
            std.debug.print("postgres: {s}\n{s}\n", .{ msg, sql });
            conn.allocator.free(msg);
        }
        return err;
    };
    defer {
        for (rows) |r| r.deinit(a);
        a.free(rows);
    }
    if (rows.len != 1) return error.UnexpectedRowCount;
    return a.dupe(u8, rows[0].cols[0] orelse "");
}

fn seed(conn: *pg.Conn) !void {
    try exec(conn,
        \\INSERT INTO agents (id, tenant_id, hostname, operating_system, os_version, agent_version, architecture, enrolled_at, status)
        \\VALUES ($1::uuid, $3::uuid, 'inc-host-a', 'windows', '11', '0', 'x64', now(), 'online'),
        \\       ($2::uuid, $3::uuid, 'inc-host-b', 'windows', '11', '0', 'x64', now(), 'online')
    , &.{ .{ .text = agent_a }, .{ .text = agent_b }, .{ .text = tenant } });
    try exec(conn,
        \\INSERT INTO alert_rules (id, tenant_id, name, format, severity, operator, payload_path, match_value, event_type, mitre_techniques, created_at, updated_at)
        \\VALUES ($1::uuid, $5::uuid, 'inc Office spawns PowerShell', 'tawny_predicate', 'high', 'contains', 'process.image', 'inc-office-marker', 'process_start', '{T1204.002,T1059.001}', now(), now()),
        \\       ($2::uuid, $5::uuid, 'inc Encoded command', 'tawny_predicate', 'medium', 'contains', 'process.command_line', 'inc-enc-marker', 'process_start', '{T1027}', now(), now()),
        \\       ($3::uuid, $5::uuid, 'inc Known bad hash', 'ioc', 'high', 'equals', 'process.hashes.sha256', 'inc-never', 'process_start', '{}', now(), now()),
        \\       ($4::uuid, $5::uuid, 'inc Unrelated', 'tawny_predicate', 'low', 'contains', 'process.image', 'inc-never', 'process_start', '{}', now(), now())
    , &.{ .{ .text = rule_office }, .{ .text = rule_enc }, .{ .text = rule_ioc }, .{ .text = rule_other }, .{ .text = tenant } });
    // Lineage: explorer (session root) > winword > powershell > child.
    try exec(conn,
        \\INSERT INTO process_entities (tenant_id, agent_id, entity_id, parent_entity_id, pid, image, start_time)
        \\VALUES ($1::uuid, $2::uuid, $3, NULL, 100, 'C:\Windows\explorer.exe', now()),
        \\       ($1::uuid, $2::uuid, $4, $3, 200, 'C:\Program Files\Microsoft Office\WINWORD.EXE', now()),
        \\       ($1::uuid, $2::uuid, $5, $4, 300, 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', now()),
        \\       ($1::uuid, $2::uuid, $6, $5, 400, 'C:\Users\a\AppData\Local\Temp\payload.exe', now()),
        \\       ($1::uuid, $2::uuid, $7, $3, 500, 'C:\Program Files\Notepad++\notepad++.exe', now())
    , &.{
        .{ .text = tenant }, .{ .text = agent_a }, .{ .text = e_explorer }, .{ .text = e_word },
        .{ .text = e_ps },   .{ .text = e_child }, .{ .text = e_unrelated },
    });
}

/// Insert an event and an alert for `rule`, then group it. Returns the incident id.
fn alertOn(conn: *pg.Conn, agent: []const u8, rule: []const u8, rule_name: []const u8, format: []const u8, payload: []const u8, now_unix: i64) ![]u8 {
    const a = testing.allocator;
    const ev = try conn.exec(a,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES (now(), $1::uuid, $2::uuid, 'process_start', now(), $3::jsonb) RETURNING id::text, received_at::text
    , &.{ .{ .text = tenant }, .{ .text = agent }, .{ .text = payload } });
    defer {
        for (ev) |r| r.deinit(a);
        a.free(ev);
    }
    const al = try conn.exec(a,
        \\INSERT INTO alerts (tenant_id, alert_rule_id, agent_id, telemetry_event_id, telemetry_received_at, severity, title, created_at)
        \\SELECT $1::uuid, $2::uuid, $3::uuid, $4::bigint, $5::timestamptz, severity, name, now() FROM alert_rules WHERE id = $2::uuid
        \\RETURNING id::text, severity
    , &.{ .{ .text = tenant }, .{ .text = rule }, .{ .text = agent }, .{ .text = ev[0].cols[0].? }, .{ .text = ev[0].cols[1].? } });
    defer {
        for (al) |r| r.deinit(a);
        a.free(al);
    }
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const root = try std.json.parseFromSliceLeaky(std.json.Value, arena_state.allocator(), payload, .{});
    var tb: [32]u8 = undefined;
    return incidents.attach(a, conn, .{
        .tenant_id = tenant,
        .agent_id = agent,
        .alert_id = al[0].cols[0].?,
        .rule_id = rule,
        .rule_name = rule_name,
        .rule_format = format,
        .severity = al[0].cols[1].?,
        .hostname = if (std.mem.eql(u8, agent, agent_a)) "inc-host-a" else "inc-host-b",
        .occurred_at = @import("../http/util.zig").formatRfc3339(&tb, now_unix),
        .root = root,
    }, now_unix);
}

fn nowUnix() i64 {
    return @intCast(std.Io.Clock.now(.real, testing.io).toSeconds());
}

test "same host and lineage group into one incident with an explained score" {
    const conn = (try connect()) orelse return;
    defer close(conn);
    try conn.execSimple("BEGIN");
    defer conn.execSimple("ROLLBACK") catch {};
    try seed(conn);
    const now = nowUnix();
    const a = testing.allocator;

    // Office starts PowerShell (entity e_ps), then PowerShell's child runs
    // an encoded command. Both share the lineage root winword (below explorer).
    const first = try alertOn(conn, agent_a, rule_office, "inc Office spawns PowerShell", "tawny_predicate",
        \\{"process":{"entity_id":"cccccccccccccccccccccccccc","image":"powershell.exe","user":{"name":"CORP\\alice"}},"parent":{"entity_id":"bbbbbbbbbbbbbbbbbbbbbbbbbb"}}
    , now);
    defer a.free(first);
    const second = try alertOn(conn, agent_a, rule_enc, "inc Encoded command", "tawny_predicate",
        \\{"process":{"entity_id":"dddddddddddddddddddddddddd","command_line":"payload.exe -enc AAAA","user":{"name":"CORP\\alice"}}}
    , now + 60);
    defer a.free(second);
    try testing.expectEqualStrings(first, second);

    // A program started from the same Explorer is a different lineage root.
    const unrelated = try alertOn(conn, agent_a, rule_other, "inc Unrelated", "tawny_predicate",
        \\{"process":{"entity_id":"eeeeeeeeeeeeeeeeeeeeeeeeee","image":"notepad++.exe"}}
    , now + 120);
    defer a.free(unrelated);
    try testing.expect(!std.mem.eql(u8, first, unrelated));

    const root = try scalar(conn, "SELECT root_entity_id FROM incidents WHERE id = $1::uuid", &.{.{ .text = first }});
    defer a.free(root);
    try testing.expectEqualStrings(e_word, root);
    const count = try scalar(conn, "SELECT count(*)::text FROM incident_alerts WHERE incident_id = $1::uuid", &.{.{ .text = first }});
    defer a.free(count);
    try testing.expectEqualStrings("2", count);

    // Risk: high rule 30 and medium rule 20 -> 100 * (1 - .7 * .8) = 44.
    const risk = try scalar(conn, "SELECT risk::text || ' ' || severity || ' ' || jsonb_array_length(risk_items)::text FROM incidents WHERE id = $1::uuid", &.{.{ .text = first }});
    defer a.free(risk);
    try testing.expectEqualStrings("44 medium 2", risk);
    const points = try scalar(conn,
        \\SELECT string_agg((e->>'label') || '=' || (e->>'points'), ',' ORDER BY e->>'label')
        \\FROM incidents, jsonb_array_elements(risk_items) e WHERE id = $1::uuid
    , &.{.{ .text = first }});
    defer a.free(points);
    try testing.expectEqualStrings("inc Encoded command=20,inc Office spawns PowerShell=30", points);
    const techs = try scalar(conn, "SELECT array_to_string(techniques, ',') || ' ' || array_to_string(users, ',') FROM incidents WHERE id = $1::uuid", &.{.{ .text = first }});
    defer a.free(techs);
    try testing.expectEqualStrings("T1204.002,T1059.001,T1027 corp\\alice", techs);

    // A repeat of the same rule adds the alert but not the evidence.
    const again = try alertOn(conn, agent_a, rule_office, "inc Office spawns PowerShell", "tawny_predicate",
        \\{"process":{"entity_id":"cccccccccccccccccccccccccc"}}
    , now + 180);
    defer a.free(again);
    try testing.expectEqualStrings(first, again);
    const risk2 = try scalar(conn, "SELECT risk::text FROM incidents WHERE id = $1::uuid", &.{.{ .text = first }});
    defer a.free(risk2);
    try testing.expectEqualStrings("44", risk2);
    std.debug.print("incident_lineage id={s} risk={s} items={s}\n", .{ first, risk, points });
}

test "the window, a closed incident and artefact and indicator rules" {
    const conn = (try connect()) orelse return;
    defer close(conn);
    try conn.execSimple("BEGIN");
    defer conn.execSimple("ROLLBACK") catch {};
    try seed(conn);
    const a = testing.allocator;
    const now = nowUnix();
    const lineage_payload =
        \\{"process":{"entity_id":"cccccccccccccccccccccccccc"}}
    ;
    const first = try alertOn(conn, agent_a, rule_office, "inc Office spawns PowerShell", "tawny_predicate", lineage_payload, now - 5 * 3600);
    defer a.free(first);
    // Five hours later: outside the four hour window, so a new incident.
    const later = try alertOn(conn, agent_a, rule_office, "inc Office spawns PowerShell", "tawny_predicate", lineage_payload, now);
    defer a.free(later);
    try testing.expect(!std.mem.eql(u8, first, later));
    // Resolved incidents take no new alerts.
    try exec(conn, "UPDATE incidents SET status = 'resolved' WHERE id = $1::uuid", &.{.{ .text = later }});
    const after_close = try alertOn(conn, agent_a, rule_office, "inc Office spawns PowerShell", "tawny_predicate", lineage_payload, now + 10);
    defer a.free(after_close);
    try testing.expect(!std.mem.eql(u8, later, after_close));

    // Artefact rule: same agent and user plus a shared domain, no entity ids.
    const dom1 = try alertOn(conn, agent_b, rule_enc, "inc Encoded command", "tawny_predicate",
        \\{"user":{"name":"bob"},"dns":{"query":"bad.example.net"}}
    , now);
    defer a.free(dom1);
    const dom2 = try alertOn(conn, agent_b, rule_other, "inc Unrelated", "tawny_predicate",
        \\{"process":{"user":{"name":"BOB"}},"dns":{"query":"bad.example.net."}}
    , now + 30);
    defer a.free(dom2);
    try testing.expectEqualStrings(dom1, dom2);
    // Same domain, different user: not grouped.
    const dom3 = try alertOn(conn, agent_b, rule_other, "inc Unrelated", "tawny_predicate",
        \\{"user":{"name":"carol"},"dns":{"query":"bad.example.net"}}
    , now + 40);
    defer a.free(dom3);
    try testing.expect(!std.mem.eql(u8, dom1, dom3));

    // Indicator rule: the same IOC rule on two agents is one incident.
    const hash =
        \\{"process":{"hashes":{"sha256":"1111111111111111111111111111111111111111111111111111111111111111"}}}
    ;
    const ioc_a = try alertOn(conn, agent_a, rule_ioc, "inc Known bad hash", "ioc", hash, now);
    defer a.free(ioc_a);
    const ioc_b = try alertOn(conn, agent_b, rule_ioc, "inc Known bad hash", "ioc", hash, now + 5);
    defer a.free(ioc_b);
    try testing.expectEqualStrings(ioc_a, ioc_b);
    const grouping = try scalar(conn, "SELECT grouping || ' ' || cardinality(agent_ids)::text || ' ' || risk::text FROM incidents WHERE id = $1::uuid", &.{.{ .text = ioc_a }});
    defer a.free(grouping);
    // One IOC rule counts once (50) even on two agents.
    try testing.expectEqualStrings("indicator 2 50", grouping);
}

test "detect job groups its alerts and incidents stay inside their tenant" {
    const conn = (try connect()) orelse return;
    defer close(conn);
    try conn.execSimple("BEGIN");
    defer conn.execSimple("ROLLBACK") catch {};
    try seed(conn);
    const a = testing.allocator;
    var cache = detect.RuleCache.init(a);
    defer cache.deinit();
    const payload =
        \\{"process":{"entity_id":"cccccccccccccccccccccccccc","image":"inc-office-marker","command_line":"x -enc inc-enc-marker"}}
    ;
    const ev = try conn.exec(a,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES (now(), $1::uuid, $2::uuid, 'process_start', now(), $3::jsonb) RETURNING id::text, received_at::text, occurred_at::text
    , &.{ .{ .text = tenant }, .{ .text = agent_a }, .{ .text = payload } });
    defer {
        for (ev) |r| r.deinit(a);
        a.free(ev);
    }
    try detect.evaluateRules(a, testing.io, conn, &cache, .{
        .tenant_id = tenant,
        .agent_id = agent_a,
        .hostname = "inc-host-a",
        .event_type = "process_start",
        .payload = payload,
        .event_id = ev[0].cols[0].?,
        .received_at = ev[0].cols[1].?,
        .occurred_at = ev[0].cols[2].?,
    });
    // Both rules matched one event: two alerts, one incident, one SOC update queued.
    const n = try scalar(conn,
        \\SELECT count(DISTINCT ia.incident_id)::text || '/' || count(*)::text FROM incident_alerts ia
        \\JOIN alerts al ON al.id = ia.alert_id WHERE al.telemetry_event_id = $1::bigint
    , &.{.{ .text = ev[0].cols[0].? }});
    defer a.free(n);
    try testing.expectEqualStrings("1/2", n);
    const queued = try scalar(conn,
        \\SELECT count(*)::text FROM work_queue WHERE kind = 'incident_sink'
        \\  AND payload->>'incident_id' = (SELECT incident_id::text FROM incident_alerts ia JOIN alerts al ON al.id = ia.alert_id
        \\    WHERE al.telemetry_event_id = $1::bigint LIMIT 1)
    , &.{.{ .text = ev[0].cols[0].? }});
    defer a.free(queued);
    try testing.expectEqualStrings("1", queued);

    // Row-level security: the app role in another tenant sees none of it.
    try exec(conn, "INSERT INTO tenants (id, slug, name, created_at) VALUES ($1::uuid, 'inc-rls', 'inc rls', now())", &.{.{ .text = other_tenant }});
    try conn.execSimple("SET LOCAL ROLE tawny_app");
    const unset = try scalar(conn, "SELECT count(*)::text FROM incidents", &.{});
    defer a.free(unset);
    try testing.expectEqualStrings("0", unset);
    try conn.execSimple("SELECT set_config('tawny.tenant_id', '" ++ other_tenant ++ "', true)");
    const hidden = try scalar(conn, "SELECT (SELECT count(*) FROM incidents)::text || '/' || (SELECT count(*) FROM incident_alerts)::text", &.{});
    defer a.free(hidden);
    try testing.expectEqualStrings("0/0", hidden);
    try conn.execSimple("SELECT set_config('tawny.tenant_id', '" ++ tenant ++ "', true)");
    const own = try scalar(conn, "SELECT (count(*) > 0)::text FROM incidents", &.{});
    defer a.free(own);
    try testing.expectEqualStrings("true", own);
    std.debug.print("incident_rls unset={s} other={s} own={s}\n", .{ unset, hidden, own });
}
