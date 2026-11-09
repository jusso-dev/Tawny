//! Detection worker. Ingest only inserts `work_queue` rows of kind `detect`.
//! `drain` claims them with SKIP LOCKED and creates alerts after the 202.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const match = @import("../detect/match.zig");
const package_exposure = @import("../detect/package_exposure.zig");
const ast = @import("../detect/ast.zig");
const tawny_rule = @import("../detect/tawny_rule.zig");
const sequence = @import("../detect/sequence.zig");
const threshold = @import("../detect/threshold.zig");
const incidents = @import("../detect/incidents.zig");

/// Compiled rule expressions, parsed once per drain. Keyed by rule id and
/// updated_at so an edited rule is parsed again.
pub const RuleCache = struct {
    arena: std.heap.ArenaAllocator,
    map: std.StringHashMapUnmanaged(?ast.Node) = .empty,
    rules: std.StringHashMapUnmanaged(?tawny_rule.Rule) = .empty,

    pub fn init(gpa: std.mem.Allocator) RuleCache {
        return .{ .arena = .init(gpa) };
    }

    pub fn deinit(self: *RuleCache) void {
        self.arena.deinit();
    }

    /// Parsed expression, or null when the stored JSON is unusable.
    fn get(self: *RuleCache, rule_id: []const u8, updated_at: []const u8, json_text: []const u8) !?ast.Node {
        const a = self.arena.allocator();
        const key = try std.mem.concat(a, u8, &.{ rule_id, "@", updated_at });
        const gop = try self.map.getOrPut(a, key);
        if (gop.found_existing) return gop.value_ptr.*;
        gop.value_ptr.* = blk: {
            const v = std.json.parseFromSliceLeaky(std.json.Value, a, json_text, .{}) catch break :blk null;
            break :blk ast.parseExpr(a, v) catch null;
        };
        return gop.value_ptr.*;
    }

    fn getRule(self: *RuleCache, rule_id: []const u8, updated_at: []const u8, json_text: []const u8) !?tawny_rule.Rule {
        const a = self.arena.allocator();
        const key = try std.mem.concat(a, u8, &.{ rule_id, "@", updated_at });
        const gop = try self.rules.getOrPut(a, key);
        if (gop.found_existing) return gop.value_ptr.*;
        gop.value_ptr.* = tawny_rule.load(a, json_text) catch null;
        return gop.value_ptr.*;
    }
};

const DetectJob = struct {
    event_id: []const u8,
    received_at: []const u8,
    agent_id: []const u8,
    hostname: []const u8,
    event_type: []const u8,
};

pub fn enqueue(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    tenant_id: []const u8,
    agent_id: []const u8,
    hostname: []const u8,
    event_type: []const u8,
    event_id: []const u8,
    received_at: []const u8,
) !void {
    const event_id_j = try util.escapeJson(allocator, event_id);
    defer allocator.free(event_id_j);
    const received_j = try util.escapeJson(allocator, received_at);
    defer allocator.free(received_j);
    const agent_j = try util.escapeJson(allocator, agent_id);
    defer allocator.free(agent_j);
    const host_j = try util.escapeJson(allocator, hostname);
    defer allocator.free(host_j);
    const type_j = try util.escapeJson(allocator, event_type);
    defer allocator.free(type_j);
    const payload = try std.fmt.allocPrint(allocator,
        \\{{"event_id":{s},"received_at":{s},"agent_id":{s},"hostname":{s},"event_type":{s}}}
    , .{ event_id_j, received_j, agent_j, host_j, type_j });
    defer allocator.free(payload);
    try conn.execNoRows(
        \\INSERT INTO work_queue (kind, tenant_id, payload)
        \\VALUES ('detect', $1::uuid, $2::jsonb)
    , &.{ .{ .text = tenant_id }, .{ .text = payload } });
}

/// Claim ready detect jobs and evaluate them. Safe on the accept thread:
/// one connection, no second worker. Returns how many jobs were finished.
pub fn drain(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn) !u32 {
    const claimed = try conn.exec(allocator,
        \\UPDATE work_queue SET locked_until = now() + interval '5 minutes', attempts = attempts + 1
        \\WHERE id IN (
        \\  SELECT id FROM work_queue
        \\  WHERE kind = 'detect' AND run_after <= now()
        \\    AND (locked_until IS NULL OR locked_until < now())
        \\  ORDER BY id
        \\  LIMIT 64
        \\  FOR UPDATE SKIP LOCKED
        \\)
        \\RETURNING id::text, tenant_id::text, payload::text
    , &.{});
    defer {
        for (claimed) |row| row.deinit(allocator);
        allocator.free(claimed);
    }
    var cache = RuleCache.init(allocator);
    defer cache.deinit();
    var done: u32 = 0;
    for (claimed) |row| {
        const qid = row.cols[0] orelse continue;
        const tenant = row.cols[1] orelse {
            try failJob(conn, qid, "missing tenant");
            continue;
        };
        const payload_txt = row.cols[2] orelse {
            try failJob(conn, qid, "missing payload");
            continue;
        };
        var parsed = std.json.parseFromSlice(DetectJob, allocator, payload_txt, .{
            .ignore_unknown_fields = true,
        }) catch {
            try failJob(conn, qid, "bad payload");
            continue;
        };
        defer parsed.deinit();
        const job = parsed.value;
        const ev = conn.exec(allocator,
            \\SELECT payload::text, occurred_at::text FROM telemetry_events
            \\WHERE id = $1::bigint AND received_at = $2::timestamptz
            \\LIMIT 1
        , &.{ .{ .text = job.event_id }, .{ .text = job.received_at } }) catch {
            try failJob(conn, qid, "telemetry lookup failed");
            continue;
        };
        defer {
            for (ev) |erow| erow.deinit(allocator);
            allocator.free(ev);
        }
        if (ev.len == 0 or ev[0].cols[0] == null) {
            try deleteJob(conn, qid);
            done += 1;
            continue;
        }
        evaluateRules(allocator, io, conn, &cache, .{
            .tenant_id = tenant,
            .agent_id = job.agent_id,
            .hostname = job.hostname,
            .event_type = job.event_type,
            .payload = ev[0].cols[0].?,
            .event_id = job.event_id,
            .received_at = job.received_at,
            .occurred_at = ev[0].cols[1] orelse job.received_at,
        }) catch {
            try failJob(conn, qid, "evaluate failed");
            continue;
        };
        try deleteJob(conn, qid);
        done += 1;
    }
    return done;
}

fn failJob(conn: *pg.Conn, id: []const u8, message: []const u8) !void {
    try conn.execNoRows(
        \\UPDATE work_queue SET last_error = $2, locked_until = now() + interval '1 minute'
        \\WHERE id = $1::bigint
    , &.{ .{ .text = id }, .{ .text = message } });
}

fn deleteJob(conn: *pg.Conn, id: []const u8) !void {
    try conn.execNoRows("DELETE FROM work_queue WHERE id = $1::bigint", &.{.{ .text = id }});
}

pub const EventCtx = struct {
    tenant_id: []const u8,
    agent_id: []const u8,
    hostname: []const u8,
    event_type: []const u8,
    payload: []const u8,
    event_id: []const u8,
    received_at: []const u8,
    occurred_at: []const u8,
};

/// Evaluate every enabled rule for one stored event. Public for the
/// correlation fixture tests, which call it without the work queue.
pub fn evaluateRules(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    cache: *RuleCache,
    e: EventCtx,
) !void {
    // Atomic formats first, then sequence and threshold rules. Sequence rows
    // have no event_type (their steps name it), so they are always loaded.
    const rules = try conn.exec(allocator,
        \\SELECT id::text, name, severity, operator, payload_path, match_value, mitre_techniques::text,
        \\       format, source_definition, compiled_expression_json::text, updated_at::text,
        \\       compile_notes::text
        \\FROM alert_rules
        \\WHERE tenant_id = $1::uuid AND is_enabled
        \\AND (event_type IS NULL OR event_type = $2)
        \\AND format IN ('tawny_predicate','sigma','ioc','package_exposure','atomic','sequence','threshold','yara')
        \\ORDER BY CASE WHEN format IN ('sequence','threshold') THEN 1 ELSE 0 END, id
    , &.{ .{ .text = e.tenant_id }, .{ .text = e.event_type } });
    defer {
        for (rules) |row| row.deinit(allocator);
        allocator.free(rules);
    }
    const sups = try conn.exec(allocator,
        \\SELECT id::text, scope, alert_rule_id::text, agent_id::text, payload_path, operator, match_value
        \\FROM suppression_rules
        \\WHERE tenant_id = $1::uuid AND is_enabled
        \\AND (expires_at IS NULL OR expires_at > now())
    , &.{.{ .text = e.tenant_id }});
    defer {
        for (sups) |srow| srow.deinit(allocator);
        allocator.free(sups);
    }
    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const created = util.formatRfc3339(&tbuf, now);
    // Parse once per event. Every rule and suppression reads this tree.
    var parsed_payload = std.json.parseFromSlice(std.json.Value, allocator, e.payload, .{}) catch {
        std.debug.print("detect: event {s} payload is not JSON, skipped\n", .{e.event_id});
        return;
    };
    defer parsed_payload.deinit();
    const root = parsed_payload.value;
    for (rules) |row| {
        const rule_id = row.cols[0] orelse continue;
        const format = row.cols[7] orelse "";
        var description: ?[]u8 = null;
        defer if (description) |d| allocator.free(d);
        if (std.mem.eql(u8, format, "package_exposure")) {
            const definition = row.cols[8] orelse continue;
            if (!package_exposure.matches(allocator, definition, e.payload)) continue;
        } else if (std.mem.eql(u8, format, "yara")) {
            // A yara_match from the agent names the YARA rule that matched;
            // the stored rule lists the names it declares.
            if (!std.mem.eql(u8, e.event_type, "yara_match")) continue;
            if (!yaraRuleMatches(allocator, row.cols[11], root)) continue;
            description = yaraDescription(allocator, root) catch null;
        } else if (std.mem.eql(u8, format, "sequence") or std.mem.eql(u8, format, "threshold")) {
            const json_text = row.cols[9] orelse continue;
            const rule = (try cache.getRule(rule_id, row.cols[10] orelse "", json_text)) orelse {
                std.debug.print("detect: rule {s} has an unusable definition, skipped\n", .{rule_id});
                continue;
            };
            var scratch_state = std.heap.ArenaAllocator.init(allocator);
            defer scratch_state.deinit();
            const scratch = scratch_state.allocator();
            const sev: sequence.Event = .{
                .tenant_id = e.tenant_id,
                .agent_id = e.agent_id,
                .event_id = e.event_id,
                .event_type = e.event_type,
                .occurred_at = e.occurred_at,
                .root = root,
            };
            switch (rule) {
                .sequence => |sq| {
                    const fired = (try sequence.apply(scratch, conn, rule_id, sq, sev)) orelse continue;
                    description = try std.fmt.allocPrint(allocator, "Sequence complete. Events: {s}", .{fired.event_ids});
                },
                .threshold => |th| {
                    const fired = (try threshold.apply(scratch, conn, rule_id, th, sev)) orelse continue;
                    description = try std.fmt.allocPrint(allocator, "Threshold reached: {d} in {d} seconds.", .{ fired.count, th.window_seconds });
                },
                .atomic => continue,
            }
        } else if ((std.mem.eql(u8, format, "sigma") or std.mem.eql(u8, format, "atomic")) and row.cols[9] != null) {
            // Compiled AST. Sigma rows from before #56 have none and use the
            // single predicate below.
            const expr = (try cache.get(rule_id, row.cols[10] orelse "", row.cols[9].?)) orelse {
                std.debug.print("detect: rule {s} has an unusable compiled expression, skipped\n", .{rule_id});
                continue;
            };
            if (!ast.eval(.{ .allocator = allocator }, expr, root)) continue;
        } else if (std.mem.eql(u8, format, "atomic")) {
            continue;
        } else {
            switch (match.evaluate(root, .{ .operator = row.cols[3], .path = row.cols[4], .want = row.cols[5] })) {
                .match => {},
                .no_match => continue,
                .invalid => {
                    std.debug.print("detect: rule {s} has no usable path or operator, skipped\n", .{rule_id});
                    continue;
                },
            }
        }
        if (matchingSuppression(sups, rule_id, e.agent_id, root)) |sid| {
            try conn.execNoRows(
                \\UPDATE suppression_rules
                \\SET suppressed_count = suppressed_count + 1, last_suppressed_at = $2::timestamptz
                \\WHERE id = $1::uuid
            , &.{ .{ .text = sid }, .{ .text = created } });
            continue;
        }
        try raiseAlert(allocator, conn, e, row.cols[0].?, row.cols[1] orelse "rule", row.cols[2] orelse "medium", description, created, .{
            .format = format,
            .root = root,
            .now_unix = now,
        });
    }
}

fn yaraRuleMatches(allocator: std.mem.Allocator, names_text: ?[]const u8, root: std.json.Value) bool {
    const text = names_text orelse return false;
    if (root != .object) return false;
    const rule = root.object.get("rule") orelse return false;
    if (rule != .string) return false;
    const names = util.parsePgTextArray(allocator, text) catch return false;
    defer {
        for (names) |n| allocator.free(n);
        allocator.free(names);
    }
    for (names) |n| {
        if (std.mem.eql(u8, n, rule.string)) return true;
    }
    return false;
}

fn yaraDescription(allocator: std.mem.Allocator, root: std.json.Value) ![]u8 {
    var b1: [64]u8 = undefined;
    var b2: [64]u8 = undefined;
    var b3: [64]u8 = undefined;
    const rule = ast.firstScalar(root, "rule", &b1) orelse "?";
    const path = ast.firstScalar(root, "file.path", &b2) orelse "?";
    const sha = ast.firstScalar(root, "file.hashes.sha256", &b3) orelse "?";
    return std.fmt.allocPrint(allocator, "YARA rule {s} matched {s} (sha256 {s}).", .{ rule, path, sha });
}

fn raiseAlert(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    e: EventCtx,
    rule_id: []const u8,
    rule_name: []const u8,
    severity: []const u8,
    description: ?[]const u8,
    created: []const u8,
    group: Group,
) !void {
    const title = try std.fmt.allocPrint(allocator, "{s} on {s}", .{ rule_name, e.hostname });
    defer allocator.free(title);
    const inserted = try conn.exec(allocator,
        \\INSERT INTO alerts (tenant_id, alert_rule_id, agent_id, telemetry_event_id, telemetry_received_at,
        \\  severity, status, title, description, created_at)
        \\VALUES ($1::uuid, $2::uuid, $3::uuid, $4::bigint, $5::timestamptz, $6, 'open', $7, $8, $9::timestamptz)
        \\RETURNING id::text
    , &.{
        .{ .text = e.tenant_id },
        .{ .text = rule_id },
        .{ .text = e.agent_id },
        .{ .text = e.event_id },
        .{ .text = e.received_at },
        .{ .text = severity },
        .{ .text = title },
        if (description) |d| .{ .text = d } else .{ .null = {} },
        .{ .text = created },
    });
    defer {
        for (inserted) |irow| irow.deinit(allocator);
        allocator.free(inserted);
    }
    if (inserted.len == 0) return;
    enqueueSink(allocator, conn, e.tenant_id, inserted[0].cols[0].?) catch |err| {
        std.debug.print("sink enqueue failed: {s}\n", .{@errorName(err)});
    };
    // Group into an incident (target-edr section 8). A grouping failure must
    // not lose the alert, which is already stored.
    const incident_id = incidents.attach(allocator, conn, .{
        .tenant_id = e.tenant_id,
        .agent_id = e.agent_id,
        .alert_id = inserted[0].cols[0].?,
        .rule_id = rule_id,
        .rule_name = rule_name,
        .rule_format = group.format,
        .severity = severity,
        .hostname = e.hostname,
        .occurred_at = e.occurred_at,
        .root = group.root,
    }, group.now_unix) catch |err| {
        if (conn.takeError()) |msg| {
            defer conn.allocator.free(msg);
            std.debug.print("incident grouping failed: {s}: {s}\n", .{ @errorName(err), msg });
        } else std.debug.print("incident grouping failed: {s}\n", .{@errorName(err)});
        return;
    };
    defer allocator.free(incident_id);
    enqueueIncidentSink(allocator, conn, e.tenant_id, incident_id) catch |err| {
        std.debug.print("incident sink enqueue failed: {s}\n", .{@errorName(err)});
    };
}

const Group = struct {
    format: []const u8,
    root: std.json.Value,
    now_unix: i64,
};

/// One pending Tawny-SOC update per incident: later alerts within the
/// debounce reuse the queued row (target-edr section 8, "debounced").
fn enqueueIncidentSink(allocator: std.mem.Allocator, conn: *pg.Conn, tenant_id: []const u8, incident_id: []const u8) !void {
    const id_j = try util.escapeJson(allocator, incident_id);
    defer allocator.free(id_j);
    const payload = try std.fmt.allocPrint(allocator, "{{\"incident_id\":{s}}}", .{id_j});
    defer allocator.free(payload);
    try conn.execNoRows(
        \\INSERT INTO work_queue (kind, tenant_id, payload, run_after)
        \\SELECT 'incident_sink', $1::uuid, $2::jsonb, now() + interval '30 seconds'
        \\WHERE NOT EXISTS (
        \\  SELECT 1 FROM work_queue WHERE kind = 'incident_sink' AND payload->>'incident_id' = $3
        \\    AND locked_until IS NULL
        \\)
    , &.{ .{ .text = tenant_id }, .{ .text = payload }, .{ .text = incident_id } });
}

fn matchingSuppression(rules: []const pg.Row, rule_id: []const u8, agent_id: []const u8, root: std.json.Value) ?[]const u8 {
    for (rules) |s| {
        const id = s.cols[0] orelse continue;
        const scope = s.cols[1] orelse continue;
        if (std.mem.eql(u8, scope, "specific_rule")) {
            const bound = s.cols[2] orelse continue;
            if (!std.mem.eql(u8, bound, rule_id)) continue;
        }
        if (s.cols[3]) |bound_agent| {
            if (!std.mem.eql(u8, bound_agent, agent_id)) continue;
        }
        // No path: the suppression covers the whole scope (rule and agent).
        const path = s.cols[4];
        if (path == null or path.?.len == 0) return id;
        if (match.evaluate(root, .{ .operator = s.cols[5], .path = path, .want = s.cols[6] }) == .match) return id;
    }
    return null;
}

fn enqueueSink(allocator: std.mem.Allocator, conn: *pg.Conn, tenant_id: []const u8, alert_id: []const u8) !void {
    const alert_j = try util.escapeJson(allocator, alert_id);
    defer allocator.free(alert_j);
    const tenant_j = try util.escapeJson(allocator, tenant_id);
    defer allocator.free(tenant_j);
    const payload = try std.fmt.allocPrint(allocator, "{{\"alert_id\":{s},\"tenant_id\":{s}}}", .{ alert_j, tenant_j });
    defer allocator.free(payload);
    try conn.execNoRows(
        \\INSERT INTO work_queue (kind, tenant_id, payload)
        \\VALUES ('sink', $1::uuid, $2::jsonb)
    , &.{ .{ .text = tenant_id }, .{ .text = payload } });
}

const default_tenant = "00000000-0000-0000-0000-000000000001";
const detect_agent = "00000000-0000-0000-0000-00000000d401";
const detect_rule = "00000000-0000-0000-0000-00000000d402";

test "enqueue leaves zero alerts until drain" {
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

    try exec(conn,
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status
        \\) VALUES ($1, $2, 'async-host', 'linux', 'test', '0', 'arm64', now(), 'online')
    , &.{ .{ .text = detect_agent }, .{ .text = default_tenant } });
    try exec(conn,
        \\INSERT INTO alert_rules (
        \\  id, tenant_id, name, format, severity, operator, payload_path, match_value,
        \\  event_type, created_at, updated_at
        \\) VALUES (
        \\  $1, $2, 'async-detect-rule', 'tawny_predicate', 'high', 'contains',
        \\  'command_line', 'async-detect-marker', 'process_start', now(), now()
        \\)
    , &.{ .{ .text = detect_rule }, .{ .text = default_tenant } });

    const inserted = try conn.exec(allocator,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES (now(), $1, $2, 'process_start', now(), '{"command_line":"curl async-detect-marker"}')
        \\RETURNING id::text, received_at::text
    , &.{ .{ .text = default_tenant }, .{ .text = detect_agent } });
    defer {
        for (inserted) |row| row.deinit(allocator);
        allocator.free(inserted);
    }
    try std.testing.expect(inserted.len == 1);
    const event_id = inserted[0].cols[0].?;
    const received_at = inserted[0].cols[1].?;

    try enqueue(allocator, conn, default_tenant, detect_agent, "async-host", "process_start", event_id, received_at);

    const before = try scalar(allocator, conn, "SELECT count(*)::text FROM alerts WHERE telemetry_event_id = $1::bigint", &.{
        .{ .text = event_id },
    });
    defer allocator.free(before);
    const queued = try scalar(allocator, conn,
        \\SELECT count(*)::text FROM work_queue
        \\WHERE kind = 'detect' AND payload->>'event_id' = $1
    , &.{.{ .text = event_id }});
    defer allocator.free(queued);

    // Other ready jobs would be claimed first. Park them for this transaction.
    try exec(conn,
        \\UPDATE work_queue SET locked_until = now() + interval '1 hour'
        \\WHERE kind = 'detect' AND payload->>'event_id' IS DISTINCT FROM $1
    , &.{.{ .text = event_id }});

    const finished = try drain(allocator, io, conn);
    const after = try scalar(allocator, conn, "SELECT count(*)::text FROM alerts WHERE telemetry_event_id = $1::bigint", &.{
        .{ .text = event_id },
    });
    defer allocator.free(after);
    const left = try scalar(allocator, conn,
        \\SELECT count(*)::text FROM work_queue
        \\WHERE kind = 'detect' AND payload->>'event_id' = $1
    , &.{.{ .text = event_id }});
    defer allocator.free(left);

    std.debug.print("detect_async queued={s} alerts_before={s} alerts_after={s} queued_after={s} drained={d}\n", .{
        queued, before, after, left, finished,
    });
    try std.testing.expectEqualStrings("1", queued);
    try std.testing.expectEqualStrings("0", before);
    try std.testing.expectEqualStrings("1", after);
    try std.testing.expectEqualStrings("0", left);
    try std.testing.expect(finished >= 1);

    try conn.execSimple("ROLLBACK");
}

const suppress_agent = "00000000-0000-0000-0000-00000000d601";
const suppress_rule = "00000000-0000-0000-0000-00000000d602";
const suppress_id = "00000000-0000-0000-0000-00000000d603";

test "suppression skips the alert and increments the counter" {
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

    try exec(conn,
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status
        \\) VALUES ($1, $2, 'suppress-host', 'linux', 'test', '0', 'arm64', now(), 'online')
    , &.{ .{ .text = suppress_agent }, .{ .text = default_tenant } });
    try exec(conn,
        \\INSERT INTO alert_rules (
        \\  id, tenant_id, name, format, severity, operator, payload_path, match_value,
        \\  event_type, created_at, updated_at
        \\) VALUES (
        \\  $1, $2, 'suppress-rule', 'tawny_predicate', 'high', 'contains',
        \\  'command_line', 'suppress-marker', 'process_start', now(), now()
        \\)
    , &.{ .{ .text = suppress_rule }, .{ .text = default_tenant } });
    try exec(conn,
        \\INSERT INTO suppression_rules (
        \\  id, tenant_id, name, scope, alert_rule_id, payload_path, operator, match_value,
        \\  is_enabled, created_at, updated_at
        \\) VALUES (
        \\  $1, $2, 'suppress-marker', 'specific_rule', $3, 'command_line', 'contains',
        \\  'suppress-marker', true, now(), now()
        \\)
    , &.{ .{ .text = suppress_id }, .{ .text = default_tenant }, .{ .text = suppress_rule } });

    const inserted = try conn.exec(allocator,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES (now(), $1, $2, 'process_start', now(), '{"command_line":"curl suppress-marker"}')
        \\RETURNING id::text, received_at::text
    , &.{ .{ .text = default_tenant }, .{ .text = suppress_agent } });
    defer {
        for (inserted) |row| row.deinit(allocator);
        allocator.free(inserted);
    }
    const event_id = inserted[0].cols[0].?;
    const received_at = inserted[0].cols[1].?;
    try enqueue(allocator, conn, default_tenant, suppress_agent, "suppress-host", "process_start", event_id, received_at);
    try exec(conn,
        \\UPDATE work_queue SET locked_until = now() + interval '1 hour'
        \\WHERE kind = 'detect' AND payload->>'event_id' IS DISTINCT FROM $1
    , &.{.{ .text = event_id }});

    const finished = try drain(allocator, io, conn);
    const alerts = try scalar(allocator, conn, "SELECT count(*)::text FROM alerts WHERE telemetry_event_id = $1::bigint", &.{
        .{ .text = event_id },
    });
    defer allocator.free(alerts);
    const count = try scalar(allocator, conn, "SELECT suppressed_count::text FROM suppression_rules WHERE id = $1::uuid", &.{
        .{ .text = suppress_id },
    });
    defer allocator.free(count);
    std.debug.print("suppress_job alerts={s} count={s} drained={d}\n", .{ alerts, count, finished });
    try std.testing.expectEqualStrings("0", alerts);
    try std.testing.expectEqualStrings("1", count);
    try std.testing.expect(finished >= 1);
    try conn.execSimple("ROLLBACK");
}

const scoped_agent = "00000000-0000-0000-0000-00000000d701";
const scoped_rule = "00000000-0000-0000-0000-00000000d702";
const scoped_sup = "00000000-0000-0000-0000-00000000d703";

test "field rules honour operator and a scoped suppression only hides its own value" {
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

    try exec(conn,
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status
        \\) VALUES ($1, $2, 'scoped-host', 'windows', 'test', '0', 'x64', now(), 'online')
    , &.{ .{ .text = scoped_agent }, .{ .text = default_tenant } });
    try exec(conn,
        \\INSERT INTO alert_rules (
        \\  id, tenant_id, name, format, severity, operator, payload_path, match_value,
        \\  event_type, created_at, updated_at
        \\) VALUES (
        \\  $1, $2, 'scoped-rule', 'tawny_predicate', 'high', 'equals',
        \\  'processes.name', 'scoped-cmd.exe', 'process_snapshot', now(), now()
        \\)
    , &.{ .{ .text = scoped_rule }, .{ .text = default_tenant } });
    // Suppress only when the user is svc-backup.
    try exec(conn,
        \\INSERT INTO suppression_rules (
        \\  id, tenant_id, name, scope, alert_rule_id, payload_path, operator, match_value,
        \\  is_enabled, created_at, updated_at
        \\) VALUES (
        \\  $1, $2, 'scoped-sup', 'specific_rule', $3, 'processes.user', 'equals',
        \\  'svc-backup', true, now(), now()
        \\)
    , &.{ .{ .text = scoped_sup }, .{ .text = default_tenant }, .{ .text = scoped_rule } });

    const payloads = [_][]const u8{
        // 0: name matches, user is suppressed.
        "{\"processes\":[{\"name\":\"SCOPED-CMD.EXE\",\"user\":\"svc-backup\"}]}",
        // 1: name matches, other user mentions svc-backup elsewhere. Must alert.
        "{\"processes\":[{\"name\":\"scoped-cmd.exe\",\"user\":\"alice\",\"command_line\":\"run as svc-backup\"}]}",
        // 2: value only in command_line. equals on name must not fire.
        "{\"processes\":[{\"name\":\"x.exe\",\"command_line\":\"scoped-cmd.exe /c\"}]}",
    };
    var ids: [payloads.len][]u8 = undefined;
    var stamps: [payloads.len][]u8 = undefined;
    for (payloads, 0..) |pl, i| {
        const rows = try conn.exec(allocator,
            \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
            \\VALUES (now(), $1, $2, 'process_snapshot', now(), $3::jsonb)
            \\RETURNING id::text, received_at::text
        , &.{ .{ .text = default_tenant }, .{ .text = scoped_agent }, .{ .text = pl } });
        defer {
            for (rows) |row| row.deinit(allocator);
            allocator.free(rows);
        }
        ids[i] = try allocator.dupe(u8, rows[0].cols[0].?);
        stamps[i] = try allocator.dupe(u8, rows[0].cols[1].?);
    }
    defer for (0..payloads.len) |i| {
        allocator.free(ids[i]);
        allocator.free(stamps[i]);
    };
    try exec(conn, "UPDATE work_queue SET locked_until = now() + interval '1 hour' WHERE kind = 'detect'", &.{});
    for (0..payloads.len) |i| {
        try enqueue(allocator, conn, default_tenant, scoped_agent, "scoped-host", "process_snapshot", ids[i], stamps[i]);
    }
    _ = try drain(allocator, io, conn);

    const want = [_][]const u8{ "0", "1", "0" };
    for (0..payloads.len) |i| {
        const n = try scalar(allocator, conn, "SELECT count(*)::text FROM alerts WHERE telemetry_event_id = $1::bigint", &.{.{ .text = ids[i] }});
        defer allocator.free(n);
        try std.testing.expectEqualStrings(want[i], n);
    }
    const count = try scalar(allocator, conn, "SELECT suppressed_count::text FROM suppression_rules WHERE id = $1::uuid", &.{.{ .text = scoped_sup }});
    defer allocator.free(count);
    try std.testing.expectEqualStrings("1", count);
    try conn.execSimple("ROLLBACK");
}

const exposure_agent = "00000000-0000-0000-0000-00000000e901";
const exposure_rule = "00000000-0000-0000-0000-00000000e902";
const exposure_bad = "00000000-0000-0000-0000-00000000e903";

test "package exposure inventory alerts only after drain" {
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

    try exec(conn,
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status
        \\) VALUES ($1, $2, 'exposure-host', 'linux', 'test', '0', 'arm64', now(), 'online')
    , &.{ .{ .text = exposure_agent }, .{ .text = default_tenant } });
    try exec(conn,
        \\INSERT INTO alert_rules (
        \\  id, tenant_id, name, format, severity, operator, event_type,
        \\  source_definition, created_at, updated_at
        \\) VALUES (
        \\  $1, $2, 'exposed-left-pad', 'package_exposure', 'high', 'exists',
        \\  'package_inventory', $3, now(), now()
        \\)
    , &.{
        .{ .text = exposure_rule },
        .{ .text = default_tenant },
        .{ .text = "{\"ecosystem\":\"npm\",\"name\":\"left-pad\",\"version_pattern\":\"^1.2.3\"}" },
    });
    try exec(conn,
        \\INSERT INTO alert_rules (
        \\  id, tenant_id, name, format, severity, operator, event_type,
        \\  source_definition, created_at, updated_at
        \\) VALUES (
        \\  $1, $2, 'bad-exposure', 'package_exposure', 'high', 'exists',
        \\  'package_inventory', 'not-json', now(), now()
        \\)
    , &.{ .{ .text = exposure_bad }, .{ .text = default_tenant } });

    const hit = try conn.exec(allocator,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES (now(), $1, $2, 'package_inventory', now(),
        \\  '{"ecosystem":"npm","name":"left-pad","version":"1.9.0"}')
        \\RETURNING id::text, received_at::text
    , &.{ .{ .text = default_tenant }, .{ .text = exposure_agent } });
    defer {
        for (hit) |row| row.deinit(allocator);
        allocator.free(hit);
    }
    const miss = try conn.exec(allocator,
        \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
        \\VALUES (now(), $1, $2, 'package_inventory', now(),
        \\  '{"ecosystem":"npm","name":"left-pad","version":"2.0.0"}')
        \\RETURNING id::text, received_at::text
    , &.{ .{ .text = default_tenant }, .{ .text = exposure_agent } });
    defer {
        for (miss) |row| row.deinit(allocator);
        allocator.free(miss);
    }
    try std.testing.expect(hit.len == 1 and miss.len == 1);
    const hit_id = hit[0].cols[0].?;
    const miss_id = miss[0].cols[0].?;
    try enqueue(allocator, conn, default_tenant, exposure_agent, "exposure-host", "package_inventory", hit_id, hit[0].cols[1].?);
    try enqueue(allocator, conn, default_tenant, exposure_agent, "exposure-host", "package_inventory", miss_id, miss[0].cols[1].?);

    const before = try scalar(allocator, conn, "SELECT count(*)::text FROM alerts WHERE telemetry_event_id = $1::bigint", &.{
        .{ .text = hit_id },
    });
    defer allocator.free(before);
    try exec(conn,
        \\UPDATE work_queue SET locked_until = now() + interval '1 hour'
        \\WHERE kind = 'detect'
        \\  AND payload->>'event_id' IS DISTINCT FROM $1
        \\  AND payload->>'event_id' IS DISTINCT FROM $2
    , &.{ .{ .text = hit_id }, .{ .text = miss_id } });

    const finished = try drain(allocator, io, conn);
    const hit_alerts = try scalar(allocator, conn, "SELECT count(*)::text FROM alerts WHERE telemetry_event_id = $1::bigint", &.{
        .{ .text = hit_id },
    });
    defer allocator.free(hit_alerts);
    const miss_alerts = try scalar(allocator, conn, "SELECT count(*)::text FROM alerts WHERE telemetry_event_id = $1::bigint", &.{
        .{ .text = miss_id },
    });
    defer allocator.free(miss_alerts);
    std.debug.print("package_exposure before={s} hit={s} miss={s} drained={d}\n", .{
        before, hit_alerts, miss_alerts, finished,
    });
    try std.testing.expectEqualStrings("0", before);
    try std.testing.expectEqualStrings("1", hit_alerts);
    try std.testing.expectEqualStrings("0", miss_alerts);
    try std.testing.expect(finished >= 2);
    try conn.execSimple("ROLLBACK");
}

const sigma_agent = "00000000-0000-0000-0000-00000000da01";
const sigma_rule = "00000000-0000-0000-0000-00000000da02";

test "compiled sigma rule with several selections alerts only on the full match" {
    const url = std.testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return;
    if (url.len == 0) return;
    const sigma = @import("../detect/sigma.zig");
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const conn = try pg.Conn.connect(allocator, io, url);
    defer {
        conn.close();
        allocator.destroy(conn);
    }
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const map = try arena.create(sigma.FieldMap);
    map.* = try sigma.FieldMap.load(arena);
    const compiled = try sigma.compile(arena, map,
        \\title: office spawns encoded powershell
        \\logsource: {product: windows, category: process_creation}
        \\detection:
        \\  parent:
        \\    ParentImage|endswith: '\WINWORD.EXE'
        \\  child:
        \\    Image|endswith: '\powershell.exe'
        \\    CommandLine|windash|contains: ' -enc '
        \\  filter:
        \\    CommandLine|contains: 'sigma-db-allowed'
        \\  condition: parent and child and not filter
    );
    try std.testing.expect(compiled.status == .supported);

    try exec(conn,
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status
        \\) VALUES ($1, $2, 'sigma-host', 'windows', 'test', '0', 'x64', now(), 'online')
    , &.{ .{ .text = sigma_agent }, .{ .text = default_tenant } });
    try exec(conn,
        \\INSERT INTO alert_rules (
        \\  id, tenant_id, name, format, severity, operator, event_type,
        \\  compiled_expression_json, compile_status, created_at, updated_at
        \\) VALUES ($1, $2, 'sigma-db-rule', 'sigma', 'high', 'exists', 'process_start', $3::jsonb, 'supported', now(), now())
    , &.{ .{ .text = sigma_rule }, .{ .text = default_tenant }, .{ .text = compiled.expr_json } });

    const payloads = [_][]const u8{
        "{\"process\":{\"image\":\"C:\\\\x\\\\powershell.exe\",\"command_line\":\"powershell /enc AAAA\"},\"parent\":{\"image\":\"C:\\\\Office\\\\WINWORD.EXE\"}}",
        "{\"process\":{\"image\":\"C:\\\\x\\\\powershell.exe\",\"command_line\":\"powershell -enc AAAA\"},\"parent\":{\"image\":\"C:\\\\x\\\\explorer.exe\"}}",
        "{\"process\":{\"image\":\"C:\\\\x\\\\powershell.exe\",\"command_line\":\"powershell -enc sigma-db-allowed\"},\"parent\":{\"image\":\"C:\\\\Office\\\\WINWORD.EXE\"}}",
    };
    const want = [_][]const u8{ "1", "0", "0" };
    try exec(conn, "UPDATE work_queue SET locked_until = now() + interval '1 hour' WHERE kind = 'detect'", &.{});
    var ids: [payloads.len][]u8 = undefined;
    for (payloads, 0..) |pl, i| {
        const rows = try conn.exec(allocator,
            \\INSERT INTO telemetry_events (received_at, tenant_id, agent_id, event_type, occurred_at, payload)
            \\VALUES (now(), $1, $2, 'process_start', now(), $3::jsonb)
            \\RETURNING id::text, received_at::text
        , &.{ .{ .text = default_tenant }, .{ .text = sigma_agent }, .{ .text = pl } });
        defer {
            for (rows) |row| row.deinit(allocator);
            allocator.free(rows);
        }
        ids[i] = try allocator.dupe(u8, rows[0].cols[0].?);
        try enqueue(allocator, conn, default_tenant, sigma_agent, "sigma-host", "process_start", rows[0].cols[0].?, rows[0].cols[1].?);
    }
    defer for (ids) |id| allocator.free(id);
    _ = try drain(allocator, io, conn);
    for (ids, 0..) |id, i| {
        const n = try scalar(allocator, conn, "SELECT count(*)::text FROM alerts WHERE telemetry_event_id = $1::bigint AND alert_rule_id = $2::uuid", &.{ .{ .text = id }, .{ .text = sigma_rule } });
        defer allocator.free(n);
        std.debug.print("sigma_db event={d} alerts={s}\n", .{ i, n });
        try std.testing.expectEqualStrings(want[i], n);
    }
    try conn.execSimple("ROLLBACK");
}

fn exec(conn: *pg.Conn, sql: []const u8, params: []const pg.Value) !void {
    conn.execNoRows(sql, params) catch |err| {
        note(conn, sql);
        return err;
    };
}

fn scalar(allocator: std.mem.Allocator, conn: *pg.Conn, sql: []const u8, params: []const pg.Value) ![]u8 {
    const rows = conn.exec(allocator, sql, params) catch |err| {
        note(conn, sql);
        return err;
    };
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len != 1 or rows[0].cols.len == 0) return error.UnexpectedRowCount;
    const col = rows[0].cols[0] orelse return error.NullColumn;
    return allocator.dupe(u8, col);
}

fn note(conn: *pg.Conn, sql: []const u8) void {
    if (conn.takeError()) |msg| {
        std.debug.print("postgres: {s}\n{s}\n", .{ msg, sql });
        conn.allocator.free(msg);
    }
}
