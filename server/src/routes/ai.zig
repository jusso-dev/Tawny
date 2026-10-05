//! API routes for AI Security Reasoning.
//!
//! Endpoints:
//! - GET    /api/ai/config           — Get AI configuration
//! - PUT    /api/ai/config           — Update AI configuration (admin only)
//! - GET    /api/ai/findings         — List security findings
//! - GET    /api/ai/findings/{id}    — Get finding detail
//! - GET    /api/ai/investigations   — List investigations
//! - GET    /api/ai/investigations/{id} — Get investigation detail
//! - GET    /api/ai/metrics          — Get AI/cost metrics
//! - POST   /api/ai/observations     — Submit a behaviour observation

const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");
const reasoning = @import("../ai/reasoning.zig");
const ai_job = @import("../jobs/ai_reasoning.zig");

/// GET /api/ai/config — Get current AI configuration.
pub fn getConfig(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    _ = conn;
    _ = web;
    const config = ai_job.AiJobConfig{
        .enabled = aiConfigEnabled(),
        .model_endpoint = envSpan("TAWNY_AI_MODEL_ENDPOINT"),
        .model_name = envSpan("TAWNY_AI_MODEL_NAME"),
        .model_api_key = envSpan("TAWNY_AI_MODEL_API_KEY"),
        .confidence_threshold = envFloat("TAWNY_AI_CONFIDENCE_THRESHOLD", 0.70),
        .allow_private_egress = envFlag("TAWNY_AI_ALLOW_PRIVATE_EGRESS"),
    };

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"ai_enabled\":");
    try out.append(allocator, if (config.enabled) 't' else 'f');
    try out.appendSlice(allocator, ",\"model_endpoint\":");
    try appendJsonString(&out, allocator, config.model_endpoint);
    try out.appendSlice(allocator, ",\"model_name\":");
    try appendJsonString(&out, allocator, config.model_name);
    try out.appendSlice(allocator, ",\"model_api_key_configured\":");
    try out.append(allocator, if (config.model_api_key.len > 0) 't' else 'f');
    try out.appendSlice(allocator, ",\"confidence_threshold\":");
    try out.appendSlice(allocator, try std.fmt.allocPrint(allocator, "{d}", .{config.confidence_threshold}));
    try out.appendSlice(allocator, ",\"allow_private_egress\":");
    try out.append(allocator, if (config.allow_private_egress) 't' else 'f');
    try out.appendSlice(allocator, "}");

    try util.respondJson(request, .ok, out.items);
}

/// PUT /api/ai/config — Update AI configuration (admin only).
/// Note: In this first implementation, config is read from environment
/// variables. This endpoint returns a message indicating that config
/// changes require a server restart with new env vars.
pub fn updateConfig(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    _ = conn;
    _ = web;
    const body = try util.readBody(allocator, request, 16 * 1024);
    defer allocator.free(body);

    const Req = struct {
        ai_enabled: ?bool = null,
        model_endpoint: ?[]const u8 = null,
        model_name: ?[]const u8 = null,
        confidence_threshold: ?f32 = null,
    };
    const parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "Invalid configuration body.");
    };

    // In this first implementation, we validate the config but don't
    // persist it. Config is read from environment variables at startup.
    // A future implementation will support dynamic config updates.
    if (parsed.value.ai_enabled) |enabled| {
        if (enabled and envSpan("TAWNY_AI_MODEL_ENDPOINT").len == 0) {
            return util.problem(request, allocator, .bad_request, "AI model endpoint must be configured via TAWNY_AI_MODEL_ENDPOINT.");
        }
    }

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"message\":\"Configuration validated. Apply via environment variables and restart the server.\",\"current_config\":{");
    try out.appendSlice(allocator, "\"ai_enabled\":");
    try out.append(allocator, if (aiConfigEnabled()) 't' else 'f');
    try out.appendSlice(allocator, ",\"model_endpoint\":");
    try appendJsonString(&out, allocator, envSpan("TAWNY_AI_MODEL_ENDPOINT"));
    try out.appendSlice(allocator, ",\"model_name\":");
    try appendJsonString(&out, allocator, envSpan("TAWNY_AI_MODEL_NAME"));
    try out.appendSlice(allocator, "}}");

    try util.respondJson(request, .ok, out.items);
}

/// GET /api/ai/findings — List security findings.
pub fn listFindings(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    const rows = try conn.exec(allocator,
        \\SELECT id::text, behaviour_fingerprint, classification, confidence::text, severity,
        \\       attack_techniques::text, trust_level, status, model, occurrences::text,
        \\       validation_count::text, false_positive_count::text,
        \\       first_seen_at::text, last_seen_at::text
        \\FROM security_findings
        \\WHERE tenant_id = $1::uuid
        \\ORDER BY last_seen_at DESC
        \\LIMIT 200
    , &.{ .{ .text = web.tenant_id } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.append(allocator, '[');
    for (rows, 0..) |row, i| {
        if (i != 0) try out.append(allocator, ',');
        try appendFinding(&out, allocator, row);
    }
    try out.append(allocator, ']');
    try util.respondJson(request, .ok, out.items);
}

/// GET /api/ai/findings/{id} — Get finding detail.
pub fn getFinding(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    id: []const u8,
) !void {
    const rows = try conn.exec(allocator,
        \\SELECT id::text, behaviour_fingerprint, classification, confidence::text, severity,
        \\       attack_techniques::text, required_features::text, supporting_features::text,
        \\       recommended_actions::text, source, model, model_version, trust_level, status,
        \\       first_seen_at::text, last_seen_at::text, expires_at::text,
        \\       occurrences::text, validation_count::text, false_positive_count::text
        \\FROM security_findings
        \\WHERE tenant_id = $1::uuid AND id = $2::uuid
        \\LIMIT 1
    , &.{ .{ .text = web.tenant_id }, .{ .text = id } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return util.problem(request, allocator, .not_found, "Finding not found.");

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try appendFindingDetail(&out, allocator, rows[0]);
    try util.respondJson(request, .ok, out.items);
}

/// GET /api/ai/investigations — List investigations.
pub fn listInvestigations(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    const rows = try conn.exec(allocator,
        \\SELECT id::text, observation_id::text, finding_id::text, status,
        \\       final_confidence::text, verdict, severity, model, provider,
        \\       started_at::text, completed_at::text
        \\FROM security_investigations
        \\WHERE tenant_id = $1::uuid
        \\ORDER BY started_at DESC
        \\LIMIT 200
    , &.{ .{ .text = web.tenant_id } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.append(allocator, '[');
    for (rows, 0..) |row, i| {
        if (i != 0) try out.append(allocator, ',');
        try appendInvestigation(&out, allocator, row);
    }
    try out.append(allocator, ']');
    try util.respondJson(request, .ok, out.items);
}

/// GET /api/ai/investigations/{id} — Get investigation detail.
pub fn getInvestigation(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    id: []const u8,
) !void {
    const rows = try conn.exec(allocator,
        \\SELECT id::text, observation_id::text, finding_id::text, status,
        \\       hypotheses::text, evidence::text, tool_calls::text, related_findings::text,
        \\       intermediate_confidence::text, final_confidence::text, verdict, severity,
        \\       attack_techniques::text, recommended_actions::text, rationale,
        \\       model, model_version, provider, started_at::text, completed_at::text, error_message
        \\FROM security_investigations
        \\WHERE tenant_id = $1::uuid AND id = $2::uuid
        \\LIMIT 1
    , &.{ .{ .text = web.tenant_id }, .{ .text = id } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return util.problem(request, allocator, .not_found, "Investigation not found.");

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try appendInvestigationDetail(&out, allocator, rows[0]);
    try util.respondJson(request, .ok, out.items);
}

/// GET /api/ai/metrics — Get AI/cost metrics.
pub fn getMetrics(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    // Observation counts by status
    const obs_rows = try conn.exec(allocator,
        \\SELECT processing_status, count(*)::text
        \\FROM security_observations
        \\WHERE tenant_id = $1::uuid
        \\GROUP BY processing_status
    , &.{ .{ .text = web.tenant_id } });
    defer {
        for (obs_rows) |row| row.deinit(allocator);
        allocator.free(obs_rows);
    }

    // Finding counts by trust level
    const finding_rows = try conn.exec(allocator,
        \\SELECT trust_level, count(*)::text
        \\FROM security_findings
        \\WHERE tenant_id = $1::uuid AND status = 'active'
        \\GROUP BY trust_level
    , &.{ .{ .text = web.tenant_id } });
    defer {
        for (finding_rows) |row| row.deinit(allocator);
        allocator.free(finding_rows);
    }

    // Model run stats
    const model_rows = try conn.exec(allocator,
        \\SELECT count(*)::text,
        \\       coalesce(sum(tokens_input), 0)::text,
        \\       coalesce(sum(tokens_output), 0)::text,
        \\       coalesce(avg(latency_ms), 0)::text
        \\FROM security_model_runs
        \\WHERE tenant_id = $1::uuid
    , &.{ .{ .text = web.tenant_id } });
    defer {
        for (model_rows) |row| row.deinit(allocator);
        allocator.free(model_rows);
    }

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"observations\":{");
    for (obs_rows, 0..) |row, i| {
        if (i != 0) try out.append(allocator, ',');
        try appendJsonString(&out, allocator, row.cols[0] orelse "");
        try out.append(allocator, ':');
        try out.appendSlice(allocator, row.cols[1] orelse "0");
    }
    try out.appendSlice(allocator, "},\"findings\":{");
    for (finding_rows, 0..) |row, i| {
        if (i != 0) try out.append(allocator, ',');
        try appendJsonString(&out, allocator, row.cols[0] orelse "");
        try out.append(allocator, ':');
        try out.appendSlice(allocator, row.cols[1] orelse "0");
    }
    try out.appendSlice( allocator, "},\"model_runs\":{");
    try out.appendSlice(allocator, "\"total\":");
    try out.appendSlice(allocator, if (model_rows.len > 0) model_rows[0].cols[0] orelse "0" else "0");
    try out.appendSlice(allocator, ",\"total_tokens_input\":");
    try out.appendSlice(allocator, if (model_rows.len > 0) model_rows[0].cols[1] orelse "0" else "0");
    try out.appendSlice(allocator, ",\"total_tokens_output\":");
    try out.appendSlice(allocator, if (model_rows.len > 0) model_rows[0].cols[2] orelse "0" else "0");
    try out.appendSlice(allocator, ",\"avg_latency_ms\":");
    try out.appendSlice(allocator, if (model_rows.len > 0) model_rows[0].cols[3] orelse "0" else "0");
    try out.appendSlice(allocator, "}}");

    try util.respondJson(request, .ok, out.items);
}

/// POST /api/ai/observations — Submit a behaviour observation for AI reasoning.
pub fn submitObservation(
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
    const body = try util.readBody(allocator, request, 256 * 1024);
    defer allocator.free(body);

    const Req = struct {
        agent_id: ?[]const u8 = null,
        hostname: ?[]const u8 = null,
        observation_type: []const u8,
        features: std.json.Value,
        observables: ?std.json.Value = null,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "Invalid observation body.");
    };
    defer parsed.deinit();

    if (parsed.value.observation_type.len == 0) {
        return util.problem(request, allocator, .bad_request, "observation_type is required.");
    }

    // Serialize features and observables to JSON strings
    var features_buf: std.ArrayList(u8) = .empty;
    defer features_buf.deinit(allocator);
    try writeJsonValue(&features_buf, allocator, parsed.value.features);

    var observables_buf: std.ArrayList(u8) = .empty;
    defer observables_buf.deinit(allocator);
    if (parsed.value.observables) |obs| {
        try writeJsonValue(&observables_buf, allocator, obs);
    } else {
        try observables_buf.appendSlice(allocator, "{}");
    }

    const agent_id = parsed.value.agent_id orelse "";
    const hostname = parsed.value.hostname orelse "";

    // Enqueue the observation
    ai_job.enqueue(
        allocator,
        io,
        conn,
        web.tenant_id,
        agent_id,
        hostname,
        parsed.value.observation_type,
        features_buf.items,
        observables_buf.items,
    ) catch {
        return util.problem(request, allocator, .internal_server_error, "Failed to enqueue observation.");
    };

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"status\":\"enqueued\",\"message\":\"Observation queued for AI reasoning.\"}");
    try util.respondJson(request, .ok, out.items);
}

// Helper functions

fn appendFinding(out: *std.ArrayList(u8), allocator: std.mem.Allocator, row: pg.Row) !void {
    const c = row.cols;
    try out.appendSlice(allocator, "{\"id\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[0] orelse ""));
    try out.appendSlice(allocator, ",\"behaviour_fingerprint\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[1] orelse ""));
    try out.appendSlice(allocator, ",\"classification\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[2] orelse ""));
    try out.appendSlice(allocator, ",\"confidence\":");
    try out.appendSlice(allocator, c[3] orelse "0");
    try out.appendSlice(allocator, ",\"severity\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[4] orelse ""));
    try out.appendSlice(allocator, ",\"attack_techniques\":");
    try out.appendSlice(allocator, c[5] orelse "[]");
    try out.appendSlice(allocator, ",\"trust_level\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[6] orelse ""));
    try out.appendSlice(allocator, ",\"status\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[7] orelse ""));
    try out.appendSlice(allocator, ",\"model\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[8]));
    try out.appendSlice(allocator, ",\"occurrences\":");
    try out.appendSlice(allocator, c[9] orelse "0");
    try out.appendSlice(allocator, ",\"validation_count\":");
    try out.appendSlice(allocator, c[10] orelse "0");
    try out.appendSlice(allocator, ",\"false_positive_count\":");
    try out.appendSlice(allocator, c[11] orelse "0");
    try out.appendSlice(allocator, ",\"first_seen_at\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[12]));
    try out.appendSlice(allocator, ",\"last_seen_at\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[13]));
    try out.append(allocator, '}');
}

fn appendFindingDetail(out: *std.ArrayList(u8), allocator: std.mem.Allocator, row: pg.Row) !void {
    const c = row.cols;
    try out.appendSlice(allocator, "{\"id\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[0] orelse ""));
    try out.appendSlice(allocator, ",\"behaviour_fingerprint\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[1] orelse ""));
    try out.appendSlice(allocator, ",\"classification\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[2] orelse ""));
    try out.appendSlice(allocator, ",\"confidence\":");
    try out.appendSlice(allocator, c[3] orelse "0");
    try out.appendSlice(allocator, ",\"severity\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[4] orelse ""));
    try out.appendSlice(allocator, ",\"attack_techniques\":");
    try out.appendSlice(allocator, c[5] orelse "[]");
    try out.appendSlice(allocator, ",\"required_features\":");
    try out.appendSlice(allocator, c[6] orelse "{}");
    try out.appendSlice(allocator, ",\"supporting_features\":");
    try out.appendSlice(allocator, c[7] orelse "{}");
    try out.appendSlice(allocator, ",\"recommended_actions\":");
    try out.appendSlice(allocator, c[8] orelse "[]");
    try out.appendSlice(allocator, ",\"source\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[9] orelse ""));
    try out.appendSlice(allocator, ",\"model\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[10]));
    try out.appendSlice(allocator, ",\"model_version\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[11]));
    try out.appendSlice(allocator, ",\"trust_level\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[12] orelse ""));
    try out.appendSlice(allocator, ",\"status\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[13] orelse ""));
    try out.appendSlice(allocator, ",\"first_seen_at\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[14]));
    try out.appendSlice(allocator, ",\"last_seen_at\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[15]));
    try out.appendSlice(allocator, ",\"expires_at\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[16]));
    try out.appendSlice(allocator, ",\"occurrences\":");
    try out.appendSlice(allocator, c[17] orelse "0");
    try out.appendSlice(allocator, ",\"validation_count\":");
    try out.appendSlice(allocator, c[18] orelse "0");
    try out.appendSlice(allocator, ",\"false_positive_count\":");
    try out.appendSlice(allocator, c[19] orelse "0");
    try out.append(allocator, '}');
}

fn appendInvestigation(out: *std.ArrayList(u8), allocator: std.mem.Allocator, row: pg.Row) !void {
    const c = row.cols;
    try out.appendSlice(allocator, "{\"id\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[0] orelse ""));
    try out.appendSlice(allocator, ",\"observation_id\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[1] orelse ""));
    try out.appendSlice(allocator, ",\"finding_id\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[2]));
    try out.appendSlice(allocator, ",\"status\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[3] orelse ""));
    try out.appendSlice(allocator, ",\"final_confidence\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[4]));
    try out.appendSlice(allocator, ",\"verdict\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[5]));
    try out.appendSlice(allocator, ",\"severity\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[6]));
    try out.appendSlice(allocator, ",\"model\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[7]));
    try out.appendSlice(allocator, ",\"provider\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[8]));
    try out.appendSlice(allocator, ",\"started_at\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[9]));
    try out.appendSlice(allocator, ",\"completed_at\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[10]));
    try out.append(allocator, '}');
}

fn appendInvestigationDetail(out: *std.ArrayList(u8), allocator: std.mem.Allocator, row: pg.Row) !void {
    const c = row.cols;
    try out.appendSlice(allocator, "{\"id\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[0] orelse ""));
    try out.appendSlice(allocator, ",\"observation_id\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[1] orelse ""));
    try out.appendSlice(allocator, ",\"finding_id\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[2]));
    try out.appendSlice(allocator, ",\"status\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[3] orelse ""));
    try out.appendSlice(allocator, ",\"hypotheses\":");
    try out.appendSlice(allocator, c[4] orelse "[]");
    try out.appendSlice(allocator, ",\"evidence\":");
    try out.appendSlice(allocator, c[5] orelse "[]");
    try out.appendSlice(allocator, ",\"tool_calls\":");
    try out.appendSlice(allocator, c[6] orelse "[]");
    try out.appendSlice(allocator, ",\"related_findings\":");
    try out.appendSlice(allocator, c[7] orelse "[]");
    try out.appendSlice(allocator, ",\"intermediate_confidence\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[8]));
    try out.appendSlice(allocator, ",\"final_confidence\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[9]));
    try out.appendSlice(allocator, ",\"verdict\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[10]));
    try out.appendSlice(allocator, ",\"severity\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[11]));
    try out.appendSlice(allocator, ",\"attack_techniques\":");
    try out.appendSlice(allocator, c[12] orelse "[]");
    try out.appendSlice(allocator, ",\"recommended_actions\":");
    try out.appendSlice(allocator, c[13] orelse "[]");
    try out.appendSlice(allocator, ",\"rationale\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[14]));
    try out.appendSlice(allocator, ",\"model\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[15]));
    try out.appendSlice(allocator, ",\"model_version\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[16]));
    try out.appendSlice(allocator, ",\"provider\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[17]));
    try out.appendSlice(allocator, ",\"started_at\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[18]));
    try out.appendSlice(allocator, ",\"completed_at\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[19]));
    try out.appendSlice(allocator, ",\"error_message\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[20]));
    try out.append(allocator, '}');
}

fn writeJsonValue(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, value: std.json.Value) !void {
    switch (value) {
        .string => |s| try appendJsonString(buf, allocator, s),
        .integer => |n| try buf.appendSlice(allocator, try std.fmt.allocPrint(allocator, "{d}", .{n})),
        .float => |n| try buf.appendSlice(allocator, try std.fmt.allocPrint(allocator, "{d}", .{n})),
        .number_string => |s| try buf.appendSlice(allocator, s),
        .bool => |b| try buf.appendSlice(allocator, if (b) "true" else "false"),
        .null => try buf.appendSlice(allocator, "null"),
        .array => |arr| {
            try buf.append(allocator, '[');
            for (arr.items, 0..) |item, i| {
                if (i > 0) try buf.append(allocator, ',');
                try writeJsonValue(buf, allocator, item);
            }
            try buf.append(allocator, ']');
        },
        .object => |obj| {
            try buf.append(allocator, '{');
            var i: usize = 0;
            var it = obj.iterator();
            while (it.next()) |entry| {
                if (i > 0) try buf.append(allocator, ',');
                try appendJsonString(buf, allocator, entry.key_ptr.*);
                try buf.append(allocator, ':');
                try writeJsonValue(buf, allocator, entry.value_ptr.*);
                i += 1;
            }
            try buf.append(allocator, '}');
        },
    }
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

fn aiConfigEnabled() bool {
    const value = envSpan("TAWNY_AI_ENABLED");
    return std.mem.eql(u8, value, "1") or std.ascii.eqlIgnoreCase(value, "true");
}

fn envSpan(key: [*:0]const u8) []const u8 {
    const raw = std.c.getenv(key) orelse return "";
    return std.mem.span(raw);
}

fn envFlag(key: [*:0]const u8) bool {
    const value = envSpan(key);
    return std.mem.eql(u8, value, "1") or std.ascii.eqlIgnoreCase(value, "true");
}

fn envFloat(key: [*:0]const u8, fallback: f32) f32 {
    const value = envSpan(key);
    if (value.len == 0) return fallback;
    return std.fmt.parseFloat(f32, value) catch fallback;
}
