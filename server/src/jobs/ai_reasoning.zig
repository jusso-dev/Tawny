//! AI Security Reasoning Job.
//!
//! Processes security observations from the work_queue through the
//! AI reasoning pipeline. For each observation:
//! 1. Generate behaviour fingerprint
//! 2. Look up existing findings by fingerprint
//! 3. If no finding found, invoke the LLM for reasoning
//! 4. Persist investigation and create/update findings
//!
//! This job runs periodically from the main server loop and is
//! controlled by the TAWNY_AI_ENABLED config flag.

const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const reasoning = @import("../ai/reasoning.zig");

pub const AiJobConfig = struct {
    enabled: bool = false,
    model_endpoint: []const u8 = "http://localhost:11434/v1",
    model_name: []const u8 = "qwen2.5:7b-instruct",
    model_api_key: []const u8 = "",
    confidence_threshold: f32 = 0.70,
    allow_private_egress: bool = true,
};

const ObservationJob = struct {
    id: []const u8,
    tenant_id: []const u8,
    agent_id: []const u8,
    hostname: []const u8,
    observation_type: []const u8,
    features_json: []const u8,
    observables_json: []const u8,
};

/// Claim ready AI reasoning jobs and process them. Returns how many were finished.
pub fn drain(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn, config: AiJobConfig) !u32 {
    if (!config.enabled) return 0;

    const claimed = try conn.exec(allocator,
        \\UPDATE work_queue SET locked_until = now() + interval '5 minutes', attempts = attempts + 1
        \\WHERE id IN (
        \\  SELECT id FROM work_queue
        \\  WHERE kind = 'ai_reasoning' AND run_after <= now()
        \\    AND (locked_until IS NULL OR locked_until < now())
        \\  ORDER BY id
        \\  LIMIT 16
        \\  FOR UPDATE SKIP LOCKED
        \\)
        \\RETURNING id::text, tenant_id::text, payload::text
    , &.{});
    defer {
        for (claimed) |row| row.deinit(allocator);
        allocator.free(claimed);
    }

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

        var parsed = std.json.parseFromSlice(ObservationJob, allocator, payload_txt, .{
            .ignore_unknown_fields = true,
        }) catch {
            try failJob(conn, qid, "bad payload");
            continue;
        };
        defer parsed.deinit();
        const job = parsed.value;

        processObservation(allocator, io, conn, config, tenant, job) catch |err| {
            std.debug.print("ai_reasoning job failed: {s}\n", .{@errorName(err)});
            try failJob(conn, qid, "processing failed");
            continue;
        };

        try deleteJob(conn, qid);
        done += 1;
    }
    return done;
}

fn processObservation(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    config: AiJobConfig,
    tenant_id: []const u8,
    job: ObservationJob,
) !void {
    // Generate behaviour fingerprint
    const fingerprint = try reasoning.generateFingerprint(allocator, job.features_json);
    defer allocator.free(fingerprint);

    // Update the observation with the fingerprint
    try conn.execNoRows(
        \\UPDATE security_observations
        \\SET behaviour_fingerprint = $2, processing_status = 'processing'
        \\WHERE id = $1::uuid
    , &.{ .{ .text = job.id }, .{ .text = fingerprint } });

    // Look up existing finding by fingerprint
    const existing_finding = reasoning.lookupFinding(allocator, conn, tenant_id, fingerprint) catch null;

    if (existing_finding) |finding_id| {
        // Known behaviour — reuse the finding, no LLM call needed
        try conn.execNoRows(
            \\UPDATE security_findings
            \\SET occurrences = occurrences + 1, last_seen_at = now()
            \\WHERE id = $1::uuid
        , &.{ .{ .text = finding_id } });

        try conn.execNoRows(
            \\UPDATE security_observations
            \\SET processing_status = 'completed', processed_at = now()
            \\WHERE id = $1::uuid
        , &.{ .{ .text = job.id } });

        std.debug.print("ai_reasoning: reused finding {s} for observation {s}\n", .{ finding_id, job.id });
        return;
    }

    // Novel behaviour — invoke the LLM
    const ai_config = reasoning.AiConfig{
        .enabled = config.enabled,
        .model_endpoint = config.model_endpoint,
        .model_name = config.model_name,
        .model_api_key = config.model_api_key,
        .confidence_threshold = config.confidence_threshold,
        .allow_private_egress = config.allow_private_egress,
    };

    var result = reasoning.reason(allocator, io, conn, ai_config, tenant_id, job.id, job.features_json, job.observables_json) catch |err| {
        try conn.execNoRows(
            \\UPDATE security_observations
            \\SET processing_status = 'failed', processing_error = $2, processed_at = now()
            \\WHERE id = $1::uuid
        , &.{ .{ .text = job.id }, .{ .text = @errorName(err) } });
        return err;
    };
    defer result.deinit(allocator);

    // Create a new finding from the investigation
    try createFindingFromResult(allocator, io, conn, tenant_id, fingerprint, job, result);

    // Mark observation as completed
    try conn.execNoRows(
        \\UPDATE security_observations
        \\SET processing_status = 'completed', processed_at = now()
        \\WHERE id = $1::uuid
    , &.{ .{ .text = job.id } });

    std.debug.print("ai_reasoning: created new finding for observation {s}, verdict={s} confidence={d:.2}\n", .{
        job.id, result.verdict, result.confidence,
    });
}

fn createFindingFromResult(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    tenant_id: []const u8,
    fingerprint: []const u8,
    job: ObservationJob,
    result: reasoning.ReasoningResult,
) !void {
    var id_buf: [36]u8 = undefined;
    const finding_id = util.newUuid(io, &id_buf);
    var now_buf: [32]u8 = undefined;
    const now = util.formatRfc3339(&now_buf, std.Io.Clock.now(.real, io).toSeconds());

    // Serialize arrays to JSON
    var attack_json: std.ArrayList(u8) = .empty;
    defer attack_json.deinit(allocator);
    try attack_json.append(allocator, '[');
    for (result.attack_techniques, 0..) |t, i| {
        if (i > 0) try attack_json.append(allocator, ',');
        try appendJsonString(&attack_json, allocator, t);
    }
    try attack_json.append(allocator, ']');

    var actions_json: std.ArrayList(u8) = .empty;
    defer actions_json.deinit(allocator);
    try actions_json.append(allocator, '[');
    for (result.recommended_actions, 0..) |a, i| {
        if (i > 0) try actions_json.append(allocator, ',');
        try appendJsonString(&actions_json, allocator, a);
    }
    try actions_json.append(allocator, ']');

    const confidence_val: f32 = @floatCast(result.confidence);

    try conn.execNoRows(
        \\INSERT INTO security_findings (
        \\  id, tenant_id, behaviour_fingerprint, classification, confidence, severity,
        \\  attack_techniques, required_features, supporting_features, recommended_actions,
        \\  source, model, trust_level, status, first_seen_at, last_seen_at, occurrences
        \\) VALUES (
        \\  $1::uuid, $2::uuid, $3, $4, $5::real, $6, $7::jsonb, $8::jsonb, '{}'::jsonb,
        \\  $9::jsonb, 'llm_investigation', $10, 'candidate', 'active',
        \\  $11::timestamptz, $11::timestamptz, 1
        \\)
    , &.{
        .{ .text = finding_id },
        .{ .text = tenant_id },
        .{ .text = fingerprint },
        .{ .text = result.verdict },
        .{ .text = try std.fmt.allocPrint(allocator, "{d}", .{confidence_val}) },
        .{ .text = result.severity },
        .{ .text = try attack_json.toOwnedSlice(allocator) },
        .{ .text = job.features_json },
        .{ .text = try actions_json.toOwnedSlice(allocator) },
        .{ .text = result.status },
        .{ .text = now },
    });
}

/// Enqueue an observation for AI reasoning.
pub fn enqueue(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    tenant_id: []const u8,
    agent_id: []const u8,
    hostname: []const u8,
    observation_type: []const u8,
    features_json: []const u8,
    observables_json: []const u8,
) !void {
    var id_buf: [36]u8 = undefined;
    const id = util.newUuid(io, &id_buf);
    var now_buf: [32]u8 = undefined;
    const now = util.formatRfc3339(&now_buf, std.Io.Clock.now(.real, io).toSeconds());

    // Insert the observation
    try conn.execNoRows(
        \\INSERT INTO security_observations (
        \\  id, tenant_id, agent_id, hostname, observation_type,
        \\  features, observables, created_at
        \\) VALUES (
        \\  $1::uuid, $2::uuid, $3::uuid, $4, $5, $6::jsonb, $7::jsonb, $8::timestamptz
        \\)
    , &.{
        .{ .text = id },
        .{ .text = tenant_id },
        .{ .text = agent_id },
        .{ .text = hostname },
        .{ .text = observation_type },
        .{ .text = features_json },
        .{ .text = observables_json },
        .{ .text = now },
    });

    // Enqueue for processing
    const payload = try std.fmt.allocPrint(allocator,
        \\{{"id":{s},"tenant_id":{s},"agent_id":{s},"hostname":{s},"observation_type":{s},"features_json":{s},"observables_json":{s}}}
    , .{
        try util.escapeJson(allocator, id),
        try util.escapeJson(allocator, tenant_id),
        try util.escapeJson(allocator, agent_id),
        try util.escapeJson(allocator, hostname),
        try util.escapeJson(allocator, observation_type),
        try util.escapeJson(allocator, features_json),
        try util.escapeJson(allocator, observables_json),
    });
    defer allocator.free(payload);

    try conn.execNoRows(
        \\INSERT INTO work_queue (kind, tenant_id, payload)
        \\VALUES ('ai_reasoning', $1::uuid, $2::jsonb)
    , &.{ .{ .text = tenant_id }, .{ .text = payload } });
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

// JSON helper
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
