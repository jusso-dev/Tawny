//! Process entity integration tests against Postgres. Skips when
//! TAWNY_DATABASE_URL is unset. Each test runs in a transaction that is
//! rolled back.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const migrate = @import("../db/migrate.zig");
const entity = @import("entity.zig");
const legacy = @import("legacy.zig");
const v2 = @import("v2.zig");
const process_store = @import("process_store.zig");

const tenant = "00000000-0000-0000-0000-000000000001";
const other_tenant = "00000000-0000-0000-0000-00000000e055";
const fixture_agent = "00000000-0000-4000-8000-00000000f001";
const v1_agent = "00000000-0000-4000-8000-00000000f002";

fn connect(allocator: std.mem.Allocator) !?*pg.Conn {
    const url = std.testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return null;
    if (url.len == 0) return null;
    const conn = try pg.Conn.connect(allocator, std.testing.io, url);
    errdefer {
        conn.close();
        allocator.destroy(conn);
    }
    try migrate.apply(allocator, conn);
    return conn;
}

fn close(allocator: std.mem.Allocator, conn: *pg.Conn) void {
    conn.close();
    allocator.destroy(conn);
}

fn addAgent(conn: *pg.Conn, id: []const u8, tenant_id: []const u8, host: []const u8) !void {
    try conn.execNoRows(
        \\INSERT INTO agents (id, tenant_id, hostname, operating_system, os_version, agent_version, architecture, enrolled_at, status)
        \\VALUES ($1::uuid, $2::uuid, $3, 'windows', 'test', '0', 'x64', now(), 'online')
    , &.{ .{ .text = id }, .{ .text = tenant_id }, .{ .text = host } });
}

/// Insert one event row and record its process facts, the way storeBatch
/// does after the telemetry insert.
fn ingestOne(allocator: std.mem.Allocator, conn: *pg.Conn, tenant_id: []const u8, agent_id: []const u8, event_type: []const u8, payload: std.json.Value, occurred_unix: i64) !void {
    const text = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(text);
    var ts_buf: [24]u8 = undefined;
    const ts = std.fmt.bufPrint(&ts_buf, "{d}", .{occurred_unix}) catch unreachable;
    const rows = try conn.exec(allocator,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES (now(), $1::uuid, $2::uuid, $3, to_timestamp($4::bigint), $5::jsonb) RETURNING id::text
    , &.{ .{ .text = tenant_id }, .{ .text = agent_id }, .{ .text = event_type }, .{ .text = ts }, .{ .text = text } });
    defer {
        for (rows) |r| r.deinit(allocator);
        allocator.free(rows);
    }
    if (legacy.processFacts(agent_id, event_type, payload, occurred_unix)) |f| {
        try process_store.record(conn, tenant_id, agent_id, rows[0].cols[0].?, &f);
    }
}

fn treeOf(allocator: std.mem.Allocator, conn: *pg.Conn, tenant_id: []const u8, agent_id: []const u8, eid: []const u8) !std.json.Parsed(std.json.Value) {
    const json = (try process_store.treeJson(allocator, conn, tenant_id, agent_id, eid)) orelse return error.ProcessNotFound;
    defer allocator.free(json);
    return std.json.parseFromSlice(std.json.Value, allocator, json, .{});
}

fn str(v: std.json.Value, key: []const u8) []const u8 {
    const x = v.object.get(key) orelse return "";
    return if (x == .string) x.string else "";
}

test "office to powershell to payload fixture rebuilds as a three-level tree; v1 and v2 side by side; pid reuse" {
    const allocator = std.testing.allocator;
    const conn = (try connect(allocator)) orelse return;
    defer close(allocator, conn);
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};
    try addAgent(conn, fixture_agent, tenant, "fixture-office-host");
    try addAgent(conn, v1_agent, tenant, "fixture-v1-host");

    // v2: the fixture batch, checked like the route checks it.
    const body = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, "fixtures/process-chain-office.v2.json", allocator, .limited(1 << 20));
    defer allocator.free(body);
    var batch = try std.json.parseFromSlice(v2.Batch, allocator, body, .{ .ignore_unknown_fields = true });
    defer batch.deinit();
    try std.testing.expect(v2.checkEnvelope(&batch.value, fixture_agent) == null);
    // The ids in the fixture are the ones the agent function gives.
    const boot = batch.value.agent.boot_id;
    try std.testing.expectEqualStrings(&entity.compute(fixture_agent, 4100, entity.parseIso("2026-11-09T01:00:00.100Z").?, boot), "7iyrf5zm6b5flyledskp3lodvm");
    for (batch.value.events) |*ev| {
        try ingestOne(allocator, conn, tenant, fixture_agent, ev.event_type, ev.data, v2.tsUnix(ev));
    }

    // v1 in the same run: a process_launch pair (parent then child) from an
    // older Linux agent, no entity ids in the payload.
    const v1_parent = "{\"pid\":700,\"ppid\":1,\"uid\":0,\"name\":\"bash\",\"command_line\":\"bash\",\"image_path\":\"/bin/bash\",\"image_sha256\":null,\"signature\":{\"trusted\":false,\"signer\":null},\"start_time_unix\":1762650000}";
    const v1_child = "{\"pid\":701,\"ppid\":700,\"uid\":0,\"name\":\"curl\",\"command_line\":\"curl x\",\"image_path\":\"/usr/bin/curl\",\"image_sha256\":null,\"signature\":{\"trusted\":false,\"signer\":null},\"start_time_unix\":1762650005}";
    for ([_][]const u8{ v1_parent, v1_child }) |p| {
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, p, .{});
        defer parsed.deinit();
        try ingestOne(allocator, conn, tenant, v1_agent, "process_launch", parsed.value, 1762650010);
    }

    // Tree from the middle of the fixture chain.
    {
        var t = try treeOf(allocator, conn, tenant, fixture_agent, "wxjmbxyyq7eybnyac2lfc654ka");
        defer t.deinit();
        const root = t.value.object;
        try std.testing.expectEqualStrings("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", str(root.get("process").?, "image"));
        const ancestors = root.get("ancestors").?.array.items;
        try std.testing.expectEqual(@as(usize, 1), ancestors.len);
        try std.testing.expectEqualStrings("7iyrf5zm6b5flyledskp3lodvm", str(ancestors[0], "entity_id"));
        const children = root.get("children").?.array.items;
        try std.testing.expectEqual(@as(usize, 1), children.len);
        try std.testing.expectEqualStrings("z64l2w3c4w3q2jhyq5jbnley3q", str(children[0], "entity_id"));
        try std.testing.expectEqualStrings("2026-11-09T01:00:30.000Z", str(children[0], "end_time"));
    }
    // Tree from the root: three levels, payload.exe at depth 2.
    {
        var t = try treeOf(allocator, conn, tenant, fixture_agent, "7iyrf5zm6b5flyledskp3lodvm");
        defer t.deinit();
        const root = t.value.object;
        try std.testing.expectEqual(@as(usize, 0), root.get("ancestors").?.array.items.len);
        const children = root.get("children").?.array.items;
        try std.testing.expectEqual(@as(usize, 2), children.len);
        try std.testing.expectEqualStrings("powershell.exe", std.fs.path.basenameWindows(str(children[0], "image")));
        try std.testing.expectEqual(@as(i64, 1), children[0].object.get("depth").?.integer);
        try std.testing.expectEqualStrings("payload.exe", std.fs.path.basenameWindows(str(children[1], "image")));
        try std.testing.expectEqual(@as(i64, 2), children[1].object.get("depth").?.integer);
    }
    // Tree from the leaf: two ancestors in order.
    {
        var t = try treeOf(allocator, conn, tenant, fixture_agent, "z64l2w3c4w3q2jhyq5jbnley3q");
        defer t.deinit();
        const ancestors = t.value.object.get("ancestors").?.array.items;
        try std.testing.expectEqual(@as(usize, 2), ancestors.len);
        try std.testing.expectEqualStrings("wxjmbxyyq7eybnyac2lfc654ka", str(ancestors[0], "entity_id"));
        try std.testing.expectEqualStrings("7iyrf5zm6b5flyledskp3lodvm", str(ancestors[1], "entity_id"));
    }
    // v1 rows joined through the legacy normaliser.
    {
        const child_id = entity.compute(v1_agent, 701, 1762650005 * entity.ticks_per_second, entity.nil_uuid);
        const parent_id = entity.compute(v1_agent, 700, 1762650000 * entity.ticks_per_second, entity.nil_uuid);
        var t = try treeOf(allocator, conn, tenant, v1_agent, &child_id);
        defer t.deinit();
        const ancestors = t.value.object.get("ancestors").?.array.items;
        try std.testing.expectEqual(@as(usize, 1), ancestors.len);
        try std.testing.expectEqualStrings(&parent_id, str(ancestors[0], "entity_id"));
    }

    // PID reuse: pid 4100 exits and comes back as a different process with
    // a child of its own. The old tree is unchanged and the new child joins
    // the new holder of the pid.
    {
        const reuse_start = entity.parseIso("2026-11-09T02:00:00.000Z").?;
        const reused = entity.compute(fixture_agent, 4100, reuse_start, boot);
        try std.testing.expect(!std.mem.eql(u8, &reused, "7iyrf5zm6b5flyledskp3lodvm"));
        const child = entity.compute(fixture_agent, 7400, reuse_start + 10 * entity.ticks_per_second, boot);
        var buf: [24]u8 = undefined;
        const p1 = try std.fmt.allocPrint(allocator, "{{\"process\":{{\"entity_id\":\"{s}\",\"pid\":4100,\"start_time\":\"{s}\",\"image\":\"C:\\\\Windows\\\\notepad.exe\"}}}}", .{ &reused, entity.formatIso(&buf, reuse_start) });
        defer allocator.free(p1);
        const p2 = try std.fmt.allocPrint(allocator, "{{\"process\":{{\"entity_id\":\"{s}\",\"pid\":7400,\"start_time\":\"{s}\"}},\"parent\":{{\"entity_id\":\"{s}\",\"pid\":4100}}}}", .{ &child, entity.formatIso(&buf, reuse_start + 10 * entity.ticks_per_second), &reused });
        defer allocator.free(p2);
        for ([_][]const u8{ p1, p2 }) |p| {
            var parsed = try std.json.parseFromSlice(std.json.Value, allocator, p, .{});
            defer parsed.deinit();
            try ingestOne(allocator, conn, tenant, fixture_agent, "process_start", parsed.value, 1762653600);
        }
        var t = try treeOf(allocator, conn, tenant, fixture_agent, &child);
        defer t.deinit();
        const ancestors = t.value.object.get("ancestors").?.array.items;
        try std.testing.expectEqual(@as(usize, 1), ancestors.len);
        try std.testing.expectEqualStrings(&reused, str(ancestors[0], "entity_id"));
        var old = try treeOf(allocator, conn, tenant, fixture_agent, "7iyrf5zm6b5flyledskp3lodvm");
        defer old.deinit();
        try std.testing.expectEqual(@as(usize, 2), old.value.object.get("children").?.array.items.len);
    }

    // Row-level security: the app role sees only the tenant it is set to.
    {
        try conn.execNoRows("INSERT INTO tenants (id, slug, name, created_at) VALUES ($1, 'proc-rls', 'Process RLS', now())", &.{.{ .text = other_tenant }});
        try conn.execSimple("SET LOCAL ROLE tawny_app");
        const none = try conn.exec(allocator, "SELECT count(*)::text FROM process_entities", &.{});
        defer {
            for (none) |r| r.deinit(allocator);
            allocator.free(none);
        }
        try std.testing.expectEqualStrings("0", none[0].cols[0].?);
        try conn.execSimple("SELECT set_config('tawny.tenant_id', '" ++ other_tenant ++ "', true)");
        try std.testing.expect((try process_store.treeJson(allocator, conn, other_tenant, fixture_agent, "7iyrf5zm6b5flyledskp3lodvm")) == null);
        try conn.execSimple("SELECT set_config('tawny.tenant_id', '" ++ tenant ++ "', true)");
        const json = (try process_store.treeJson(allocator, conn, tenant, fixture_agent, "7iyrf5zm6b5flyledskp3lodvm")).?;
        allocator.free(json);
        try conn.execSimple("RESET ROLE");
    }

    try conn.execSimple("ROLLBACK");
}
