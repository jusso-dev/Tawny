//! process_entities: one row per process, keyed by (tenant_id, entity_id).
//! Ingest upserts on process_start and sets end_time on process_exit; the
//! tree API walks parent_entity_id. The server never derives identity from a
//! pid alone: v2 rows carry the agent's entity id, v1 rows the id the legacy
//! normaliser computed. The one pid lookup is a v1-style exit with no entity
//! id, which closes the newest still-open process with that pid.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const entity = @import("entity.zig");
const legacy = @import("legacy.zig");

fn isoOrNull(buf: *[24]u8, ticks: ?u64) pg.Value {
    const t = ticks orelse return .{ .null = {} };
    return .{ .text = entity.formatIso(buf, t) };
}

fn opt(v: ?[]const u8) pg.Value {
    return if (v) |s| .{ .text = s } else .{ .null = {} };
}

/// Upsert or close one process. `event_id` is the telemetry_events id of the
/// event the facts came from.
pub fn record(
    conn: *pg.Conn,
    tenant_id: []const u8,
    agent_id: []const u8,
    event_id: []const u8,
    f: *const legacy.ProcessFacts,
) !void {
    var pid_buf: [12]u8 = undefined;
    const pid_s = std.fmt.bufPrint(&pid_buf, "{d}", .{f.pid}) catch unreachable;
    switch (f.kind) {
        .start => {
            const id = f.entity_id orelse return;
            var start_buf: [24]u8 = undefined;
            // A child that arrives before its parent keeps the parent link;
            // a later start for the same id only fills fields that were empty.
            try conn.execNoRows(
                \\INSERT INTO process_entities (
                \\  tenant_id, agent_id, entity_id, parent_entity_id, pid, image, command_line,
                \\  user_name, start_time, first_event_id
                \\) VALUES ($1::uuid, $2::uuid, $3, $4, $5::bigint, $6, $7, $8, $9::timestamptz, $10::bigint)
                \\ON CONFLICT (tenant_id, entity_id) DO UPDATE SET
                \\  parent_entity_id = COALESCE(process_entities.parent_entity_id, EXCLUDED.parent_entity_id),
                \\  image = COALESCE(process_entities.image, EXCLUDED.image),
                \\  command_line = COALESCE(process_entities.command_line, EXCLUDED.command_line),
                \\  user_name = COALESCE(process_entities.user_name, EXCLUDED.user_name),
                \\  start_time = COALESCE(process_entities.start_time, EXCLUDED.start_time)
                \\WHERE process_entities.agent_id = EXCLUDED.agent_id
            , &.{
                .{ .text = tenant_id },
                .{ .text = agent_id },
                .{ .text = &id },
                if (f.parent_entity_id) |*p| .{ .text = p } else .{ .null = {} },
                .{ .text = pid_s },
                opt(f.image orelse f.name),
                opt(f.command_line),
                opt(f.userName()),
                isoOrNull(&start_buf, f.start_100ns),
                .{ .text = event_id },
            });
            // v1 events have no parent entity id. Link to the newest process
            // of the same agent that held the ppid and started no later.
            if (f.parent_entity_id == null) if (f.ppid) |ppid| if (ppid != 0) {
                var ppid_buf: [12]u8 = undefined;
                try conn.execNoRows(
                    \\UPDATE process_entities c SET parent_entity_id = (
                    \\  SELECT p.entity_id FROM process_entities p
                    \\  WHERE p.tenant_id = c.tenant_id AND p.agent_id = c.agent_id AND p.pid = $4::bigint
                    \\    AND p.entity_id <> c.entity_id
                    \\    AND (p.start_time IS NULL OR c.start_time IS NULL OR p.start_time <= c.start_time)
                    \\    AND (p.end_time IS NULL OR c.start_time IS NULL OR p.end_time >= c.start_time)
                    \\  ORDER BY p.start_time DESC NULLS LAST LIMIT 1)
                    \\WHERE c.tenant_id = $1::uuid AND c.agent_id = $2::uuid AND c.entity_id = $3
                    \\  AND c.parent_entity_id IS NULL
                , &.{
                    .{ .text = tenant_id },
                    .{ .text = agent_id },
                    .{ .text = &id },
                    .{ .text = std.fmt.bufPrint(&ppid_buf, "{d}", .{ppid}) catch unreachable },
                });
            };
        },
        .exit => {
            var end_buf: [24]u8 = undefined;
            const end = isoOrNull(&end_buf, f.end_100ns);
            if (f.entity_id) |id| {
                try conn.execNoRows(
                    \\UPDATE process_entities SET end_time = COALESCE($4::timestamptz, now())
                    \\WHERE tenant_id = $1::uuid AND agent_id = $2::uuid AND entity_id = $3 AND end_time IS NULL
                , &.{ .{ .text = tenant_id }, .{ .text = agent_id }, .{ .text = &id }, end });
            } else {
                try conn.execNoRows(
                    \\UPDATE process_entities SET end_time = COALESCE($4::timestamptz, now())
                    \\WHERE tenant_id = $1::uuid AND entity_id = (
                    \\  SELECT entity_id FROM process_entities
                    \\  WHERE tenant_id = $1::uuid AND agent_id = $2::uuid AND pid = $3::bigint AND end_time IS NULL
                    \\  ORDER BY start_time DESC NULLS LAST LIMIT 1)
                , &.{ .{ .text = tenant_id }, .{ .text = agent_id }, .{ .text = pid_s }, end });
            }
        },
    }
}

pub const max_ancestors = 64;
pub const max_children = 500;

const node_columns =
    \\entity_id, parent_entity_id, pid::text, image, command_line, user_name,
    \\to_char(start_time AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    \\to_char(end_time AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    \\first_event_id::text
;

fn writeNode(out: *std.ArrayList(u8), allocator: std.mem.Allocator, cols: []const ?[]u8, depth: ?i64) !void {
    const names = [_][]const u8{ "entity_id", "parent_entity_id", "pid", "image", "command_line", "user_name", "start_time", "end_time", "first_event_id" };
    try out.append(allocator, '{');
    for (names, 0..) |name, i| {
        if (i > 0) try out.append(allocator, ',');
        try out.print(allocator, "\"{s}\":", .{name});
        const v = cols[i] orelse {
            try out.appendSlice(allocator, "null");
            continue;
        };
        if (i == 2 or i == 8) {
            try out.appendSlice(allocator, v);
        } else {
            var w: std.Io.Writer.Allocating = .init(allocator);
            defer w.deinit();
            try std.json.Stringify.value(v, .{}, &w.writer);
            try out.appendSlice(allocator, w.written());
        }
    }
    if (depth) |d| try out.print(allocator, ",\"depth\":{d}", .{d});
    try out.append(allocator, '}');
}

fn freeRows(allocator: std.mem.Allocator, rows: []pg.Row) void {
    for (rows) |row| row.deinit(allocator);
    allocator.free(rows);
}

/// `{"process":{...},"ancestors":[parent, grandparent, ...],"children":[...]}`
/// for one entity, or null when the entity is not on this agent in this
/// tenant. `children` is every descendant, each with `depth` (1 is a direct
/// child), ordered by depth then start time.
pub fn treeJson(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    tenant_id: []const u8,
    agent_id: []const u8,
    entity_id: []const u8,
) !?[]u8 {
    const self_rows = try conn.exec(allocator, "SELECT " ++ node_columns ++
        \\ FROM process_entities WHERE tenant_id = $1::uuid AND agent_id = $2::uuid AND entity_id = $3
    , &.{ .{ .text = tenant_id }, .{ .text = agent_id }, .{ .text = entity_id } });
    defer freeRows(allocator, self_rows);
    if (self_rows.len == 0) return null;

    const ancestors = try conn.exec(allocator,
        \\WITH RECURSIVE up(eid, depth) AS (
        \\  SELECT parent_entity_id, 1 FROM process_entities
        \\  WHERE tenant_id = $1::uuid AND agent_id = $2::uuid AND entity_id = $3
        \\  UNION ALL
        \\  SELECT p.parent_entity_id, up.depth + 1 FROM up
        \\  JOIN process_entities p ON p.tenant_id = $1::uuid AND p.agent_id = $2::uuid AND p.entity_id = up.eid
        \\  WHERE up.depth <
    ++ std.fmt.comptimePrint("{d}", .{max_ancestors}) ++
        \\
        \\)
        \\SELECT
    ++ " " ++ node_columns ++
        \\, up.depth::text FROM up
        \\JOIN process_entities p ON p.tenant_id = $1::uuid AND p.agent_id = $2::uuid AND p.entity_id = up.eid
        \\ORDER BY up.depth
    , &.{ .{ .text = tenant_id }, .{ .text = agent_id }, .{ .text = entity_id } });
    defer freeRows(allocator, ancestors);

    const children = try conn.exec(allocator,
        \\WITH RECURSIVE down(eid, depth) AS (
        \\  SELECT entity_id, 1 FROM process_entities
        \\  WHERE tenant_id = $1::uuid AND agent_id = $2::uuid AND parent_entity_id = $3
        \\  UNION ALL
        \\  SELECT c.entity_id, down.depth + 1 FROM down
        \\  JOIN process_entities c ON c.tenant_id = $1::uuid AND c.agent_id = $2::uuid AND c.parent_entity_id = down.eid
        \\  WHERE down.depth <
    ++ std.fmt.comptimePrint("{d}", .{max_ancestors}) ++
        \\
        \\)
        \\SELECT
    ++ " " ++ node_columns ++
        \\, down.depth::text FROM down
        \\JOIN process_entities p ON p.tenant_id = $1::uuid AND p.agent_id = $2::uuid AND p.entity_id = down.eid
        \\ORDER BY down.depth, p.start_time NULLS LAST
        \\LIMIT
    ++ std.fmt.comptimePrint(" {d}", .{max_children})
    , &.{ .{ .text = tenant_id }, .{ .text = agent_id }, .{ .text = entity_id } });
    defer freeRows(allocator, children);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"process\":");
    try writeNode(&out, allocator, self_rows[0].cols, null);
    try out.appendSlice(allocator, ",\"ancestors\":[");
    for (ancestors, 0..) |row, i| {
        if (i > 0) try out.append(allocator, ',');
        try writeNode(&out, allocator, row.cols[0..9], std.fmt.parseInt(i64, row.cols[9] orelse "0", 10) catch 0);
    }
    try out.appendSlice(allocator, "],\"children\":[");
    for (children, 0..) |row, i| {
        if (i > 0) try out.append(allocator, ',');
        try writeNode(&out, allocator, row.cols[0..9], std.fmt.parseInt(i64, row.cols[9] orelse "0", 10) catch 0);
    }
    try out.appendSlice(allocator, "]}");
    return try out.toOwnedSlice(allocator);
}

/// Newest processes on an agent, for the agent page's process picker.
pub fn recentJson(allocator: std.mem.Allocator, conn: *pg.Conn, tenant_id: []const u8, agent_id: []const u8, limit: u32) ![]u8 {
    var lim_buf: [12]u8 = undefined;
    const rows = try conn.exec(allocator, "SELECT " ++ node_columns ++
        \\ FROM process_entities WHERE tenant_id = $1::uuid AND agent_id = $2::uuid
        \\ORDER BY start_time DESC NULLS LAST LIMIT $3::int
    , &.{ .{ .text = tenant_id }, .{ .text = agent_id }, .{ .text = std.fmt.bufPrint(&lim_buf, "{d}", .{limit}) catch unreachable } });
    defer freeRows(allocator, rows);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"processes\":[");
    for (rows, 0..) |row, i| {
        if (i > 0) try out.append(allocator, ',');
        try writeNode(&out, allocator, row.cols, null);
    }
    try out.appendSlice(allocator, "]}");
    return out.toOwnedSlice(allocator);
}
