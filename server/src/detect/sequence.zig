//! Sequence rules: ordered steps joined by a `by` key inside a window.
//! State is one `sequence_state` row per rule and key, so it survives a
//! server restart.
//!
//! Each event moves a sequence at most one step. Steps are tried from the
//! last to the first, and a step applies only when the stored state is
//! waiting for it (or, for the first step, when there is no live state).
//! `within` counts from the first event of the sequence. A step with
//! `count: n` needs n matching events before the next step can start.

const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const ast = @import("ast.zig");
const tawny_rule = @import("tawny_rule.zig");

pub const State = struct {
    /// Index of the step being waited for.
    step: u32,
    /// Matches so far toward that step's count.
    count: u32,
};

pub const Transition = union(enum) {
    /// Store this state.
    store: State,
    /// Every step is done: raise an alert and clear the state.
    fire,
    /// The event does not move this sequence.
    none,
};

/// Pure state change for event matching step `index` of `steps` total,
/// where that step needs `need` matches. `current` is null when there is
/// no live state.
pub fn advance(current: ?State, index: u32, need: u32, steps: u32) Transition {
    const cur = current orelse State{ .step = 0, .count = 0 };
    if (cur.step != index) return .none;
    const count = cur.count + 1;
    if (count < need) return .{ .store = .{ .step = index, .count = count } };
    if (index + 1 >= steps) return .fire;
    return .{ .store = .{ .step = index + 1, .count = 0 } };
}

pub const Event = struct {
    tenant_id: []const u8,
    agent_id: []const u8,
    event_id: []const u8,
    event_type: []const u8,
    /// Event time from the sensor, RFC 3339.
    occurred_at: []const u8,
    root: std.json.Value,
};

pub const Fired = struct {
    /// Event ids of the sequence, oldest first, as Postgres array text.
    event_ids: []const u8,
};

/// Apply one event to one sequence rule. Returns the event ids when the
/// sequence completes. `scratch` holds the result.
pub fn apply(
    scratch: std.mem.Allocator,
    conn: *pg.Conn,
    rule_id: []const u8,
    seq: tawny_rule.Sequence,
    ev: Event,
) !?Fired {
    const steps: u32 = @intCast(seq.steps.len);
    var i: u32 = steps;
    while (i > 0) {
        i -= 1;
        const step = seq.steps[i];
        if (!std.mem.eql(u8, step.event_type, ev.event_type)) continue;
        if (!ast.eval(.{ .allocator = scratch }, step.expr, ev.root)) continue;
        const key = (try tawny_rule.byKey(scratch, step.by, ev.root, ev.agent_id)) orelse continue;
        const current = try load(scratch, conn, ev.tenant_id, rule_id, key, ev.occurred_at);
        switch (advance(current, i, step.count, steps)) {
            .none => continue,
            .store => |st| {
                try store(conn, ev, rule_id, key, st, current == null, seq.within_seconds);
                return null;
            },
            .fire => {
                const rows = try conn.exec(scratch,
                    \\DELETE FROM sequence_state
                    \\WHERE tenant_id = $1::uuid AND rule_id = $2::uuid AND by_key = $3
                    \\RETURNING array_append(event_ids, $4::bigint)::text
                , &.{ .{ .text = ev.tenant_id }, .{ .text = rule_id }, .{ .text = key }, .{ .text = ev.event_id } });
                const ids = if (rows.len > 0 and rows[0].cols[0] != null)
                    try scratch.dupe(u8, rows[0].cols[0].?)
                else
                    try std.fmt.allocPrint(scratch, "{{{s}}}", .{ev.event_id});
                for (rows) |r| r.deinit(scratch);
                scratch.free(rows);
                return .{ .event_ids = ids };
            },
        }
    }
    return null;
}

/// Live state for a key at event time `at`. Expired state is deleted.
fn load(scratch: std.mem.Allocator, conn: *pg.Conn, tenant: []const u8, rule_id: []const u8, key: []const u8, at: []const u8) !?State {
    const rows = try conn.exec(scratch,
        \\SELECT step::text, step_count::text, (expires_at < $4::timestamptz)::text
        \\FROM sequence_state
        \\WHERE tenant_id = $1::uuid AND rule_id = $2::uuid AND by_key = $3
        \\FOR UPDATE
    , &.{ .{ .text = tenant }, .{ .text = rule_id }, .{ .text = key }, .{ .text = at } });
    defer {
        for (rows) |r| r.deinit(scratch);
        scratch.free(rows);
    }
    if (rows.len == 0) return null;
    const expired = std.mem.eql(u8, rows[0].cols[2] orelse "t", "true") or std.mem.eql(u8, rows[0].cols[2] orelse "t", "t");
    if (expired) {
        try conn.execNoRows(
            \\DELETE FROM sequence_state WHERE tenant_id = $1::uuid AND rule_id = $2::uuid AND by_key = $3
        , &.{ .{ .text = tenant }, .{ .text = rule_id }, .{ .text = key } });
        return null;
    }
    return .{
        .step = std.fmt.parseInt(u32, rows[0].cols[0] orelse "0", 10) catch 0,
        .count = std.fmt.parseInt(u32, rows[0].cols[1] orelse "0", 10) catch 0,
    };
}

fn store(conn: *pg.Conn, ev: Event, rule_id: []const u8, key: []const u8, st: State, fresh: bool, within: u32) !void {
    var sbuf: [12]u8 = undefined;
    var cbuf: [12]u8 = undefined;
    var wbuf: [12]u8 = undefined;
    const step_s = std.fmt.bufPrint(&sbuf, "{d}", .{st.step}) catch unreachable;
    const count_s = std.fmt.bufPrint(&cbuf, "{d}", .{st.count}) catch unreachable;
    const within_s = std.fmt.bufPrint(&wbuf, "{d}", .{within}) catch unreachable;
    if (fresh) {
        try conn.execNoRows(
            \\INSERT INTO sequence_state (tenant_id, rule_id, agent_id, by_key, step, step_count, last_event_id,
            \\  event_ids, started_at, expires_at, updated_at)
            \\VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::int, $6::int, $7::bigint, ARRAY[$7::bigint],
            \\  $8::timestamptz, $8::timestamptz + make_interval(secs => $9::int), now())
            \\ON CONFLICT (tenant_id, rule_id, by_key) DO UPDATE SET
            \\  agent_id = EXCLUDED.agent_id, step = EXCLUDED.step, step_count = EXCLUDED.step_count,
            \\  last_event_id = EXCLUDED.last_event_id, event_ids = EXCLUDED.event_ids,
            \\  started_at = EXCLUDED.started_at, expires_at = EXCLUDED.expires_at, updated_at = now()
        , &.{
            .{ .text = ev.tenant_id },  .{ .text = rule_id },        .{ .text = ev.agent_id },
            .{ .text = key },           .{ .text = step_s },         .{ .text = count_s },
            .{ .text = ev.event_id },   .{ .text = ev.occurred_at }, .{ .text = within_s },
        });
        return;
    }
    // Keep at most 64 event ids per sequence.
    try conn.execNoRows(
        \\UPDATE sequence_state SET step = $4::int, step_count = $5::int, agent_id = $6::uuid,
        \\  last_event_id = $7::bigint,
        \\  event_ids = CASE WHEN cardinality(event_ids) < 64 THEN array_append(event_ids, $7::bigint) ELSE event_ids END,
        \\  updated_at = now()
        \\WHERE tenant_id = $1::uuid AND rule_id = $2::uuid AND by_key = $3
    , &.{
        .{ .text = ev.tenant_id }, .{ .text = rule_id },     .{ .text = key },
        .{ .text = step_s },       .{ .text = count_s },     .{ .text = ev.agent_id },
        .{ .text = ev.event_id },
    });
}

test "advance walks steps and counts" {
    // Three-step rule, first step needs two matches.
    try std.testing.expectEqual(Transition{ .store = .{ .step = 0, .count = 1 } }, advance(null, 0, 2, 3));
    try std.testing.expectEqual(Transition{ .store = .{ .step = 1, .count = 0 } }, advance(.{ .step = 0, .count = 1 }, 0, 2, 3));
    try std.testing.expectEqual(Transition.none, advance(null, 1, 1, 3));
    try std.testing.expectEqual(Transition.none, advance(.{ .step = 0, .count = 1 }, 1, 1, 3));
    try std.testing.expectEqual(Transition{ .store = .{ .step = 2, .count = 0 } }, advance(.{ .step = 1, .count = 0 }, 1, 1, 3));
    try std.testing.expectEqual(Transition.fire, advance(.{ .step = 2, .count = 0 }, 2, 1, 3));
    // A later first-step match doesn't reset progress.
    try std.testing.expectEqual(Transition.none, advance(.{ .step = 2, .count = 0 }, 0, 1, 3));
}
