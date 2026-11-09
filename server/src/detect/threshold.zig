//! Threshold rules: count (or count distinct values of a field) of matching
//! events per `by` key inside a sliding window. Every matching event is a
//! `threshold_counters` row, so the count survives a server restart and the
//! window slides exactly. When the rule fires, the rows for that key are
//! cleared, so one burst raises one alert.

const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const ast = @import("ast.zig");
const tawny_rule = @import("tawny_rule.zig");
const sequence = @import("sequence.zig");

pub const Fired = struct { count: u32 };

pub fn apply(
    scratch: std.mem.Allocator,
    conn: *pg.Conn,
    rule_id: []const u8,
    t: tawny_rule.Threshold,
    ev: sequence.Event,
) !?Fired {
    if (!std.mem.eql(u8, t.event_type, ev.event_type)) return null;
    if (!ast.eval(.{ .allocator = scratch }, t.expr, ev.root)) return null;
    const key = (try tawny_rule.byKey(scratch, t.by, ev.root, ev.agent_id)) orelse return null;
    var value: ?[]const u8 = null;
    var vbuf: [64]u8 = undefined;
    if (t.distinct) |path| {
        const v = ast.firstScalar(ev.root, path, &vbuf) orelse return null;
        value = try std.ascii.allocLowerString(scratch, v);
    }
    var wbuf: [12]u8 = undefined;
    const window = std.fmt.bufPrint(&wbuf, "{d}", .{t.window_seconds}) catch unreachable;
    try conn.execNoRows(
        \\INSERT INTO threshold_counters (tenant_id, rule_id, by_key, value, event_id, occurred_at, expires_at)
        \\VALUES ($1::uuid, $2::uuid, $3, $4, $5::bigint, $6::timestamptz, $6::timestamptz + make_interval(secs => $7::int))
    , &.{
        .{ .text = ev.tenant_id },
        .{ .text = rule_id },
        .{ .text = key },
        if (value) |v| .{ .text = v } else .{ .null = {} },
        .{ .text = ev.event_id },
        .{ .text = ev.occurred_at },
        .{ .text = window },
    });
    const sql = if (t.distinct != null)
        \\SELECT count(DISTINCT value)::text FROM threshold_counters
        \\WHERE tenant_id = $1::uuid AND rule_id = $2::uuid AND by_key = $3
        \\  AND occurred_at > $4::timestamptz - make_interval(secs => $5::int) AND occurred_at <= $4::timestamptz
    else
        \\SELECT count(*)::text FROM threshold_counters
        \\WHERE tenant_id = $1::uuid AND rule_id = $2::uuid AND by_key = $3
        \\  AND occurred_at > $4::timestamptz - make_interval(secs => $5::int) AND occurred_at <= $4::timestamptz
    ;
    const rows = try conn.exec(scratch, sql, &.{
        .{ .text = ev.tenant_id },
        .{ .text = rule_id },
        .{ .text = key },
        .{ .text = ev.occurred_at },
        .{ .text = window },
    });
    defer {
        for (rows) |r| r.deinit(scratch);
        scratch.free(rows);
    }
    const n = std.fmt.parseInt(u32, (if (rows.len > 0) rows[0].cols[0] else null) orelse "0", 10) catch 0;
    if (n < t.min) return null;
    try conn.execNoRows(
        \\DELETE FROM threshold_counters WHERE tenant_id = $1::uuid AND rule_id = $2::uuid AND by_key = $3
    , &.{ .{ .text = ev.tenant_id }, .{ .text = rule_id }, .{ .text = key } });
    return .{ .count = n };
}
