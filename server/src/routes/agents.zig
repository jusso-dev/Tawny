const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");
const audit = @import("../http/audit.zig");
const state = @import("../http/state.zig");
const detect = @import("../jobs/detect.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn createEnrollmentToken(
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
    const body = try util.readBody(allocator, request, 16 * 1024);
    defer allocator.free(body);
    const Req = struct { lifetime_hours: ?i64 = null };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "lifetime_hours required.");
    };
    defer parsed.deinit();
    const hours = parsed.value.lifetime_hours orelse 24;

    const raw_hex = try util.randomHex(io, allocator, 24);
    defer allocator.free(raw_hex);
    const raw = try std.fmt.allocPrint(allocator, "wte_{s}", .{raw_hex});
    defer allocator.free(raw);
    const hash = try util.sha256Hex(allocator, raw);
    defer allocator.free(hash);

    var id_buf: [36]u8 = undefined;
    const id = util.newUuid(io, &id_buf);
    const now = util.nowUnix(io);
    var t1: [32]u8 = undefined;
    var t2: [32]u8 = undefined;
    const created = util.formatRfc3339(&t1, now);
    const expires = util.formatRfc3339(&t2, now + hours * 3600);

    try conn.execNoRows(
        \\INSERT INTO enrollment_tokens (id, tenant_id, token_hash, expires_at, created_by_user_id, created_at)
        \\VALUES ($1::uuid, $2::uuid, $3, $4::timestamptz, $5::uuid, $6::timestamptz)
    , &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
        .{ .text = hash },
        .{ .text = expires },
        .{ .text = web.user_id },
        .{ .text = created },
    });
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "enrollment_token.create", id, null);

    const id_j = try util.escapeJson(allocator, id);
    defer allocator.free(id_j);
    const tok_j = try util.escapeJson(allocator, raw);
    defer allocator.free(tok_j);
    const exp_j = try util.escapeJson(allocator, expires);
    defer allocator.free(exp_j);
    const json = try std.fmt.allocPrint(allocator, "{{\"id\":{s},\"token\":{s},\"expires_at\":{s}}}", .{ id_j, tok_j, exp_j });
    defer allocator.free(json);
    try util.respondJson(request, .ok, json);
}

pub fn enroll(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
) !void {
    if (state.enrollRateLimited(io, state.peer_ip)) {
        try util.respondJson(request, .too_many_requests,
            \\{"error":"rate_limited","detail":"Too many requests.","policy":"agent-enrollment"}
        );
        return;
    }
    const body = try util.readBody(allocator, request, 16 * 1024);
    defer allocator.free(body);
    const Req = struct {
        enrollment_token: []const u8,
        hostname: []const u8,
        os: []const u8,
        os_version: []const u8,
        arch: []const u8,
        agent_version: []const u8,
        device_public_key: ?[]const u8 = null,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "Invalid enroll body.");
    };
    defer parsed.deinit();
    const req = parsed.value;

    if (util.hasControlChars(req.hostname)) {
        return util.problem(request, allocator, .bad_request, "hostname must not contain control characters.");
    }
    const os = util.parseOs(req.os) orelse {
        return util.problem(request, allocator, .bad_request, "os must be windows, macos, or linux.");
    };
    const arch = util.parseArch(req.arch) orelse {
        return util.problem(request, allocator, .bad_request, "arch must be x64/amd64/x86_64 or arm64/aarch64.");
    };

    const hash = try util.sha256Hex(allocator, req.enrollment_token);
    defer allocator.free(hash);
    const rows = try conn.exec(allocator,
        \\SELECT id::text, tenant_id::text, expires_at, used_at::text FROM enrollment_tokens WHERE token_hash = $1 LIMIT 1
    , &.{.{ .text = hash }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return util.problem(request, allocator, .unauthorized, "Unknown enrollment token.");
    const t = rows[0].cols;
    if (t[3] != null) return util.problem(request, allocator, .conflict, "Enrollment token already used.");
    const now = util.nowUnix(io);
    if (t[2]) |exp_text| {
        if (auth_parse_ts(exp_text)) |exp| {
            if (exp <= now) return util.problem(request, allocator, .gone, "Enrollment token expired.");
        }
    }

    var id_buf: [36]u8 = undefined;
    const agent_id = util.newUuid(io, &id_buf);
    var tbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&tbuf, now);
    const tenant_id = t[1].?;
    const token_id = t[0].?;

    try conn.execNoRows(
        \\INSERT INTO agents (id, tenant_id, hostname, operating_system, os_version, agent_version, architecture,
        \\  enrolled_at, last_heartbeat_at, status, credential_version, device_public_key, public_ip)
        \\VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8::timestamptz, $8::timestamptz, 'online', 1, $9, $10)
    , &.{
        .{ .text = agent_id },
        .{ .text = tenant_id },
        .{ .text = req.hostname },
        .{ .text = os },
        .{ .text = req.os_version },
        .{ .text = req.agent_version },
        .{ .text = arch },
        .{ .text = now_s },
        if (req.device_public_key) |k| .{ .text = k } else .{ .null = {} },
        .{ .text = state.peer_ip },
    });
    try conn.execNoRows(
        \\UPDATE enrollment_tokens SET used_at = $2::timestamptz, used_by_agent_id = $3::uuid WHERE id = $1::uuid AND used_at IS NULL
    , &.{ .{ .text = token_id }, .{ .text = now_s }, .{ .text = agent_id } });

    try audit.add(allocator, io, conn, tenant_id, null, "agent.enroll", agent_id, null);

    const issued = try auth.issueAgentJwt(allocator, io, agent_id, tenant_id, 1);
    defer allocator.free(issued.token);
    var expbuf: [32]u8 = undefined;
    const exp_s = util.formatRfc3339(&expbuf, issued.exp);
    try audit.add(allocator, io, conn, tenant_id, null, "agent.credential_issue", agent_id, null);

    const aid_j = try util.escapeJson(allocator, agent_id);
    defer allocator.free(aid_j);
    const jwt_j = try util.escapeJson(allocator, issued.token);
    defer allocator.free(jwt_j);
    const exp_j = try util.escapeJson(allocator, exp_s);
    defer allocator.free(exp_j);
    const json = try std.fmt.allocPrint(allocator,
        \\{{"agent_id":{s},"jwt":{s},"jwt_expires_at":{s},"config":{{"heartbeat_interval_seconds":60}}}}
    , .{ aid_j, jwt_j, exp_j });
    defer allocator.free(json);
    try util.respondJson(request, .ok, json);
}

fn auth_parse_ts(text: []const u8) ?i64 {
    if (text.len < 19) return null;
    const year = std.fmt.parseInt(i32, text[0..4], 10) catch return null;
    const month = std.fmt.parseInt(u8, text[5..7], 10) catch return null;
    const day = std.fmt.parseInt(u8, text[8..10], 10) catch return null;
    const hour = std.fmt.parseInt(u8, text[11..13], 10) catch return null;
    const min = std.fmt.parseInt(u8, text[14..16], 10) catch return null;
    const sec = std.fmt.parseInt(u8, text[17..19], 10) catch return null;
    // reuse rough conversion via format inverse — daysFromCivil inline
    var y: i64 = year;
    const m: i64 = month;
    const d: i64 = day;
    y -= @intFromBool(m <= 2);
    const era: i64 = @divFloor(y, 400);
    const yoe: i64 = y - era * 400;
    const mp: i64 = if (m > 2) m - 3 else m + 9;
    const doy: i64 = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe: i64 = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const z = era * 146097 + doe - 719468;
    return z * 86400 + @as(i64, hour) * 3600 + @as(i64, min) * 60 + @as(i64, sec);
}

fn agentSummaryJson(allocator: std.mem.Allocator, cols: []const ?[]u8) ![]u8 {
    // id, hostname, os, os_version, agent_version, arch, status, last_hb, enrolled, public_ip
    const id = try util.escapeJson(allocator, cols[0] orelse "");
    defer allocator.free(id);
    const host = try util.escapeJson(allocator, cols[1] orelse "");
    defer allocator.free(host);
    const os = try util.escapeJson(allocator, cols[2] orelse "");
    defer allocator.free(os);
    const osv = try util.escapeJson(allocator, cols[3] orelse "");
    defer allocator.free(osv);
    const ver = try util.escapeJson(allocator, cols[4] orelse "");
    defer allocator.free(ver);
    const arch = try util.escapeJson(allocator, cols[5] orelse "");
    defer allocator.free(arch);
    const status = try util.escapeJson(allocator, cols[6] orelse "");
    defer allocator.free(status);
    const lhb = try util.nullOrJsonString(allocator, cols[7]);
    defer allocator.free(lhb);
    const enr = try util.escapeJson(allocator, cols[8] orelse "");
    defer allocator.free(enr);
    const pip = try util.nullOrJsonString(allocator, cols[9]);
    defer allocator.free(pip);
    var tags_json: []u8 = undefined;
    if (cols[10]) |raw| {
        const items = try util.parsePgTextArray(allocator, raw);
        defer {
            for (items) |it| allocator.free(it);
            allocator.free(items);
        }
        tags_json = try util.jsonArrayStrings(allocator, items);
    } else {
        tags_json = try allocator.dupe(u8, "[]");
    }
    defer allocator.free(tags_json);
    return std.fmt.allocPrint(allocator,
        \\{{"id":{s},"hostname":{s},"operating_system":{s},"os_version":{s},"agent_version":{s},"architecture":{s},"status":{s},"last_heartbeat_at":{s},"enrolled_at":{s},"public_ip":{s},"tags":{s}}}
    , .{ id, host, os, osv, ver, arch, status, lhb, enr, pip, tags_json });
}

const agent_select =
    \\SELECT id::text, hostname, operating_system, os_version, agent_version, architecture, status,
    \\       last_heartbeat_at::text, enrolled_at::text, public_ip, tags::text
    \\FROM agents
;

pub fn listAgents(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    _ = util.readBody(allocator, request, 1024) catch {};
    const rows = try conn.exec(allocator, agent_select ++
        \\ WHERE tenant_id = $1::uuid ORDER BY last_heartbeat_at DESC NULLS LAST
    , &.{.{ .text = web.tenant_id }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.append(allocator, '[');
    for (rows, 0..) |row, i| {
        if (i > 0) try out.append(allocator, ',');
        const one = try agentSummaryJson(allocator, row.cols);
        defer allocator.free(one);
        try out.appendSlice(allocator, one);
    }
    try out.append(allocator, ']');
    try util.respondJson(request, .ok, out.items);
}

pub fn getAgent(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    id: []const u8,
) !void {
    _ = util.readBody(allocator, request, 1024) catch {};
    const rows = try conn.exec(allocator, agent_select ++
        \\ WHERE id = $1::uuid AND tenant_id = $2::uuid LIMIT 1
    , &.{ .{ .text = id }, .{ .text = web.tenant_id } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return util.problem(request, allocator, .not_found, "Agent not found.");
    const json = try agentSummaryJson(allocator, rows[0].cols);
    defer allocator.free(json);
    try util.respondJson(request, .ok, json);
}

pub fn revokeAgent(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    id: []const u8,
) !void {
    if (web.session_id != null and !auth.checkCsrf(request, web)) {
        try util.respondJson(request, .forbidden, "{\"error\":\"csrf\"}");
        return;
    }
    _ = util.readBody(allocator, request, 16 * 1024) catch {};
    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&tbuf, now);
    try conn.execNoRows(
        \\UPDATE agents SET status = 'revoked', revoked_at = $3::timestamptz, credential_version = credential_version + 1
        \\WHERE id = $1::uuid AND tenant_id = $2::uuid
    , &.{ .{ .text = id }, .{ .text = web.tenant_id }, .{ .text = now_s } });
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "agent.revoke", id, null);
    const rows = try conn.exec(allocator, agent_select ++
        \\ WHERE id = $1::uuid AND tenant_id = $2::uuid LIMIT 1
    , &.{ .{ .text = id }, .{ .text = web.tenant_id } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return util.problem(request, allocator, .not_found, "Agent not found.");
    const json = try agentSummaryJson(allocator, rows[0].cols);
    defer allocator.free(json);
    try util.respondJson(request, .ok, json);
}

pub fn heartbeat(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    agent: auth.AgentAuth,
) !void {
    if (state.tooMany(io, "agent-heartbeat", agent.agent_id, 12)) {
        try util.respondJson(request, .too_many_requests,
            \\{"error":"rate_limited","detail":"Too many requests.","policy":"agent-heartbeat"}
        );
        return;
    }
    const body = try util.readBody(allocator, request, 16 * 1024);
    defer allocator.free(body);
    const Req = struct {
        agent_version: []const u8,
        uptime_seconds: i64,
        buffer_depth: i64,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "Invalid heartbeat body.");
    };
    defer parsed.deinit();
    if (parsed.value.uptime_seconds < 0) {
        return util.problem(request, allocator, .bad_request, "UptimeSeconds must be greater than or equal to '0'.");
    }
    if (parsed.value.buffer_depth < 0) {
        return util.problem(request, allocator, .bad_request, "BufferDepth must be greater than or equal to '0'.");
    }

    const rows = try conn.exec(allocator,
        \\SELECT status, agent_version, credential_version::text FROM agents
        \\WHERE id = $1::uuid AND tenant_id = $2::uuid LIMIT 1
    , &.{ .{ .text = agent.agent_id }, .{ .text = agent.tenant_id } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return util.problem(request, allocator, .not_found, "Agent not found.");
    const prev_status = rows[0].cols[0] orelse "unknown";
    const prev_ver = rows[0].cols[1] orelse "";
    const cv = std.fmt.parseInt(i64, rows[0].cols[2] orelse "1", 10) catch 1;

    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&tbuf, now);
    try conn.execNoRows(
        \\UPDATE agents SET last_heartbeat_at = $3::timestamptz, status = 'online', agent_version = $4
        \\WHERE id = $1::uuid AND tenant_id = $2::uuid
    , &.{
        .{ .text = agent.agent_id },
        .{ .text = agent.tenant_id },
        .{ .text = now_s },
        .{ .text = parsed.value.agent_version },
    });

    if (!std.mem.eql(u8, prev_status, "online") or !std.mem.eql(u8, prev_ver, parsed.value.agent_version)) {
        try audit.add(allocator, io, conn, agent.tenant_id, null, "agent.heartbeat_change", agent.agent_id, null);
    }

    // Expire stale actions
    try conn.execNoRows(
        \\UPDATE response_actions SET status = 'expired', completed_at = $2::timestamptz, execution_token_hash = NULL
        \\WHERE agent_id = $1::uuid AND expires_at IS NOT NULL AND expires_at <= $2::timestamptz
        \\AND status IN ('pending','dispatched','running')
    , &.{ .{ .text = agent.agent_id }, .{ .text = now_s } });

    const pending = try conn.exec(allocator,
        \\SELECT id::text, action_type, payload_json, expires_at::text, payload_hash
        \\FROM response_actions
        \\WHERE agent_id = $1::uuid AND status = 'pending'
        \\ORDER BY requested_at ASC LIMIT 10
    , &.{.{ .text = agent.agent_id }});
    defer {
        for (pending) |row| row.deinit(allocator);
        allocator.free(pending);
    }

    var actions_json: std.ArrayList(u8) = .empty;
    defer actions_json.deinit(allocator);
    try actions_json.append(allocator, '[');
    for (pending, 0..) |row, i| {
        if (i > 0) try actions_json.append(allocator, ',');
        const exec_raw = try util.randomHex(io, allocator, 32);
        defer allocator.free(exec_raw);
        const exec_hash = try util.sha256Hex(allocator, exec_raw);
        defer allocator.free(exec_hash);
        var exp_at = row.cols[3];
        var exp_owned: ?[]u8 = null;
        defer if (exp_owned) |e| allocator.free(e);
        if (exp_at == null) {
            exp_owned = try allocator.dupe(u8, util.formatRfc3339(&tbuf, now + 15 * 60));
            exp_at = exp_owned;
        }
        var ph = row.cols[4];
        var ph_owned: ?[]u8 = null;
        defer if (ph_owned) |p| allocator.free(p);
        if (ph == null) {
            ph_owned = try util.sha256Hex(allocator, row.cols[2] orelse "{}");
            ph = ph_owned;
        }
        try conn.execNoRows(
            \\UPDATE response_actions SET status = 'dispatched', dispatched_at = $2::timestamptz,
            \\  execution_token_hash = $3, expires_at = COALESCE(expires_at, $4::timestamptz),
            \\  payload_hash = COALESCE(payload_hash, $5)
            \\WHERE id = $1::uuid
        , &.{
            .{ .text = row.cols[0].? },
            .{ .text = now_s },
            .{ .text = exec_hash },
            .{ .text = exp_at.? },
            .{ .text = ph.? },
        });
        const id_j = try util.escapeJson(allocator, row.cols[0].?);
        defer allocator.free(id_j);
        const at_j = try util.escapeJson(allocator, row.cols[1] orelse "");
        defer allocator.free(at_j);
        const tok_j = try util.escapeJson(allocator, exec_raw);
        defer allocator.free(tok_j);
        const exp_j = try util.escapeJson(allocator, exp_at.?);
        defer allocator.free(exp_j);
        const ph_j = try util.escapeJson(allocator, ph.?);
        defer allocator.free(ph_j);
        const payload = row.cols[2] orelse "{}";
        {
            const __tmp = try std.fmt.allocPrint(allocator, 
            "{{\"id\":{s},\"action_type\":{s},\"payload\":{s},\"execution_token\":{s},\"expires_at\":{s},\"payload_hash\":{s}}}",
            .{ id_j, at_j, payload, tok_j, exp_j, ph_j },
        );
            defer allocator.free(__tmp);
            try actions_json.appendSlice(allocator, __tmp);
        }
    }
    try actions_json.append(allocator, ']');
    if (pending.len > 0) {
        try audit.add(allocator, io, conn, agent.tenant_id, null, "response_action.dispatch", agent.agent_id, null);
    }

    // Release lookup
    const rel = try conn.exec(allocator,
        \\SELECT version, download_url, sha256 FROM agent_releases r
        \\JOIN agents a ON a.id = $1::uuid
        \\WHERE r.is_latest AND r.platform = (a.operating_system || '-' || a.architecture)
        \\LIMIT 1
    , &.{.{ .text = agent.agent_id }});
    defer {
        for (rel) |row| row.deinit(allocator);
        allocator.free(rel);
    }

    var rotated: ?[]u8 = null;
    var rot_exp: ?i64 = null;
    defer if (rotated) |r| allocator.free(r);
    // RS256 tokens rotate on the next heartbeat even when lifetime remains.
    // EdDSA rotates only inside the 15-minute window, matching .NET ShouldRotate.
    if (agent.legacy_rs256 or agent.exp <= now + 15 * 60) {
        const issued = try auth.issueAgentJwt(allocator, io, agent.agent_id, agent.tenant_id, cv);
        rotated = issued.token;
        rot_exp = issued.exp;
        try audit.add(allocator, io, conn, agent.tenant_id, null, "agent.credential_rotate", agent.agent_id, null);
    }

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.appendSlice(allocator, "{");
    if (rel.len > 0) {
        const v = try util.escapeJson(allocator, rel[0].cols[0] orelse "");
        defer allocator.free(v);
        const u = try util.escapeJson(allocator, rel[0].cols[1] orelse "");
        defer allocator.free(u);
        const s = try util.escapeJson(allocator, rel[0].cols[2] orelse "");
        defer allocator.free(s);
        {
            const __tmp = try std.fmt.allocPrint(allocator, "\"latest_agent_version\":{s},\"download_url\":{s},\"sha256\":{s},", .{ v, u, s });
            defer allocator.free(__tmp);
            try out.appendSlice(allocator, __tmp);
        }
    } else {
        try out.appendSlice(allocator, "\"latest_agent_version\":null,\"download_url\":null,\"sha256\":null,");
    }
    if (rotated) |r| {
        const rj = try util.escapeJson(allocator, r);
        defer allocator.free(rj);
        var eb: [32]u8 = undefined;
        const es = util.formatRfc3339(&eb, rot_exp.?);
        const ej = try util.escapeJson(allocator, es);
        defer allocator.free(ej);
        {
            const __tmp = try std.fmt.allocPrint(allocator, "\"rotated_jwt\":{s},\"jwt_expires_at\":{s},", .{ rj, ej });
            defer allocator.free(__tmp);
            try out.appendSlice(allocator, __tmp);
        }
    } else {
        try out.appendSlice(allocator, "\"rotated_jwt\":null,\"jwt_expires_at\":null,");
    }
    try out.appendSlice(allocator, "\"actions\":");
    try out.appendSlice(allocator, actions_json.items);
    try out.append(allocator, '}');
    try util.respondJson(request, .ok, out.items);
}

pub fn ingestEvents(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    agent: auth.AgentAuth,
) !void {
    var event_key_buf: [80]u8 = undefined;
    const event_key = std.fmt.bufPrint(&event_key_buf, "{s}:{s}", .{ agent.tenant_id, agent.agent_id }) catch agent.agent_id;
    if (state.tooMany(io, "agent-events", event_key, 120)) {
        try util.respondJson(request, .too_many_requests,
            \\{"error":"rate_limited","detail":"Too many requests.","policy":"agent-events"}
        );
        return;
    }
    const body = try util.readBody(allocator, request, 1024 * 1024);
    defer allocator.free(body);

    const Event = struct {
        type: []const u8,
        occurred_at: std.json.Value,
        payload: std.json.Value,
        client_event_id: ?[]const u8 = null,
        sequence: ?i64 = null,
    };
    const Req = struct {
        events: []Event,
        batch_id: ?[]const u8 = null,
        signature: ?[]const u8 = null,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "Invalid events body.");
    };
    defer parsed.deinit();
    if (parsed.value.events.len == 0) {
        try util.respondJson(request, .accepted, "");
        return;
    }
    if (parsed.value.events.len > 500) {
        return util.problem(request, allocator, .bad_request, "At most 500 events per batch.");
    }

    const arows = try conn.exec(allocator,
        \\SELECT device_public_key, last_telemetry_sequence::text, hostname
        \\FROM agents WHERE id = $1::uuid AND tenant_id = $2::uuid LIMIT 1
    , &.{ .{ .text = agent.agent_id }, .{ .text = agent.tenant_id } });
    defer {
        for (arows) |row| row.deinit(allocator);
        allocator.free(arows);
    }
    if (arows.len == 0) return util.problem(request, allocator, .not_found, "Agent not found.");
    const device_key = arows[0].cols[0];
    const last_seq: i64 = if (arows[0].cols[1]) |s| std.fmt.parseInt(i64, s, 10) catch 0 else 0;
    const hostname = arows[0].cols[2] orelse "";

    if (device_key != null and device_key.?.len > 0) {
        if (parsed.value.signature == null or parsed.value.signature.?.len == 0) {
            try audit.add(allocator, io, conn, agent.tenant_id, null, "telemetry.signature_rejected", agent.agent_id, null);
            return util.problem(request, allocator, .unauthorized, "Invalid or missing device batch signature.");
        }
        // Full verify deferred; missing signature path is required.
    }

    var batch_buf: [36]u8 = undefined;
    const batch_id = parsed.value.batch_id orelse util.newUuid(io, &batch_buf);
    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const received = util.formatRfc3339(&tbuf, now);

    var min_seq: ?i64 = null;
    var max_seq: ?i64 = null;
    for (parsed.value.events) |ev| {
        if (ev.sequence) |s| {
            min_seq = if (min_seq) |m| @min(m, s) else s;
            max_seq = if (max_seq) |m| @max(m, s) else s;
        }
    }
    const rollback = if (min_seq) |m| (last_seq > 0 and m < last_seq) else false;
    const gap = if (min_seq) |m| (last_seq > 0 and m > last_seq + 1) else false;
    if (rollback) try audit.add(allocator, io, conn, agent.tenant_id, null, "telemetry.sequence_rollback", agent.agent_id, null);
    if (gap) try audit.add(allocator, io, conn, agent.tenant_id, null, "telemetry.sequence_gap", agent.agent_id, null);

    var inserted: usize = 0;
    for (parsed.value.events) |ev| {
        // occurred_at may be unix number or string
        const occurred_unix: i64 = switch (ev.occurred_at) {
            .integer => |n| n,
            .float => |f| @intFromFloat(f),
            .string => |s| std.fmt.parseInt(i64, s, 10) catch auth_parse_ts(s) orelse now,
            else => now,
        };
        if (occurred_unix > now + 300) {
            return util.problem(request, allocator, .bad_request, "occurred_at too far in the future");
        }
        if (ev.payload != .object) {
            return util.problem(request, allocator, .bad_request, "payload must be a JSON object.");
        }
        var payload_buf: std.ArrayList(u8) = .empty;
        defer payload_buf.deinit(allocator);
        const payload_tmp = try std.json.Stringify.valueAlloc(allocator, ev.payload, .{});
        defer allocator.free(payload_tmp);
        try payload_buf.appendSlice(allocator, payload_tmp);

        if (ev.client_event_id) |cid| {
            const existing = try conn.exec(allocator,
                \\SELECT 1 FROM telemetry_dedupe WHERE tenant_id = $1::uuid AND agent_id = $2::uuid AND client_event_id = $3::uuid
            , &.{ .{ .text = agent.tenant_id }, .{ .text = agent.agent_id }, .{ .text = cid } });
            defer {
                for (existing) |row| row.deinit(allocator);
                allocator.free(existing);
            }
            if (existing.len > 0) continue;
        }

        var obuf: [32]u8 = undefined;
        const occurred_s = util.formatRfc3339(&obuf, occurred_unix);
        const digest = try util.sha256Hex(allocator, payload_buf.items);
        defer allocator.free(digest);

        const seq_val: pg.Value = if (ev.sequence) |s| blk: {
            const t = try std.fmt.allocPrint(allocator, "{d}", .{s});
            break :blk .{ .text = t };
        } else .{ .null = {} };
        defer if (seq_val == .text) allocator.free(seq_val.text);

        const ins = try conn.exec(allocator,
            \\INSERT INTO telemetry_events (received_at, client_event_id, batch_id, sequence_number, tenant_id, agent_id, event_type, occurred_at, confidence, payload_digest, payload)
            \\VALUES ($1::timestamptz, $2::uuid, $3::uuid, $4::bigint, $5::uuid, $6::uuid, $7, $8::timestamptz, 'agent_reported', $9, $10::jsonb)
            \\RETURNING id::text, received_at::text
        , &.{
            .{ .text = received },
            if (ev.client_event_id) |c| .{ .text = c } else .{ .null = {} },
            .{ .text = batch_id },
            seq_val,
            .{ .text = agent.tenant_id },
            .{ .text = agent.agent_id },
            .{ .text = ev.type },
            .{ .text = occurred_s },
            .{ .text = digest },
            .{ .text = payload_buf.items },
        });
        defer {
            for (ins) |row| row.deinit(allocator);
            allocator.free(ins);
        }
        if (ins.len == 0) continue;
        const event_id = ins[0].cols[0].?;
        const recv_at = ins[0].cols[1].?;
        if (ev.client_event_id) |cid| {
            conn.execNoRows(
                \\INSERT INTO telemetry_dedupe (tenant_id, agent_id, client_event_id, received_at, event_id)
                \\VALUES ($1::uuid, $2::uuid, $3::uuid, $4::timestamptz, $5::bigint)
                \\ON CONFLICT DO NOTHING
            , &.{
                .{ .text = agent.tenant_id },
                .{ .text = agent.agent_id },
                .{ .text = cid },
                .{ .text = recv_at },
                .{ .text = event_id },
            }) catch {};
        }
        inserted += 1;
        try detect.enqueue(allocator, conn, agent.tenant_id, agent.agent_id, hostname, ev.type, event_id, recv_at);
    }

    if (!rollback) {
        if (max_seq) |mx| {
            if (mx > last_seq) {
                const mx_s = try std.fmt.allocPrint(allocator, "{d}", .{mx});
                defer allocator.free(mx_s);
                const cnt_s = try std.fmt.allocPrint(allocator, "{d}", .{inserted});
                defer allocator.free(cnt_s);
                try conn.execNoRows(
                    \\UPDATE agents SET last_telemetry_sequence = $3::bigint, last_telemetry_batch_id = $4::uuid, last_ingest_event_count = $5
                    \\WHERE id = $1::uuid AND tenant_id = $2::uuid
                , &.{
                    .{ .text = agent.agent_id },
                    .{ .text = agent.tenant_id },
                    .{ .text = mx_s },
                    .{ .text = batch_id },
                    .{ .text = cnt_s },
                });
            }
        }
    }

    try util.respondJson(request, .accepted, "");
}

pub fn createAction(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    agent_id: []const u8,
) !void {
    if (web.session_id != null and !auth.checkCsrf(request, web)) {
        try util.respondJson(request, .forbidden, "{\"error\":\"csrf\"}");
        return;
    }
    var action_key_buf: [96]u8 = undefined;
    const action_key = std.fmt.bufPrint(&action_key_buf, "{s}:{s}", .{ web.tenant_id, web.user_id }) catch web.user_id;
    if (state.tooMany(io, "response-actions", action_key, 20)) {
        try util.respondJson(request, .too_many_requests,
            \\{"error":"rate_limited","detail":"Too many requests.","policy":"response-actions"}
        );
        return;
    }
    const body = try util.readBody(allocator, request, 64 * 1024);
    defer allocator.free(body);
    const Req = struct {
        action_type: []const u8,
        payload: std.json.Value,
        idempotency_key: ?[]const u8 = null,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "Invalid action body.");
    };
    defer parsed.deinit();

    const exists = try conn.exec(allocator, "SELECT 1 FROM agents WHERE id = $1::uuid AND tenant_id = $2::uuid", &.{
        .{ .text = agent_id },
        .{ .text = web.tenant_id },
    });
    defer {
        for (exists) |row| row.deinit(allocator);
        allocator.free(exists);
    }
    if (exists.len == 0) return util.problem(request, allocator, .not_found, "Agent not found.");

    const idem_key: ?[]const u8 = if (parsed.value.idempotency_key) |k| (if (k.len > 0) k else null) else null;
    if (idem_key) |k| {
        if (try respondIdempotent(allocator, conn, request, web.tenant_id, agent_id, k)) return;
    }

    var payload_buf: std.ArrayList(u8) = .empty;
    defer payload_buf.deinit(allocator);
    const payload_tmp = try std.json.Stringify.valueAlloc(allocator, parsed.value.payload, .{});
    defer allocator.free(payload_tmp);
    try payload_buf.appendSlice(allocator, payload_tmp);
    const ph = try util.sha256Hex(allocator, payload_buf.items);
    defer allocator.free(ph);

    var id_buf: [36]u8 = undefined;
    const id = util.newUuid(io, &id_buf);
    const now = util.nowUnix(io);
    var t1: [32]u8 = undefined;
    var t2: [32]u8 = undefined;
    const requested = util.formatRfc3339(&t1, now);
    const expires = util.formatRfc3339(&t2, now + 15 * 60);

    conn.execNoRows(
        \\INSERT INTO response_actions (id, agent_id, tenant_id, action_type, status, requested_by_user_id,
        \\  requested_at, expires_at, payload_json, payload_hash, idempotency_key)
        \\VALUES ($1::uuid, $2::uuid, $3::uuid, $4, 'pending', $5::uuid, $6::timestamptz, $7::timestamptz, $8::jsonb, $9, $10)
    , &.{
        .{ .text = id },
        .{ .text = agent_id },
        .{ .text = web.tenant_id },
        .{ .text = parsed.value.action_type },
        .{ .text = web.user_id },
        .{ .text = requested },
        .{ .text = expires },
        .{ .text = payload_buf.items },
        .{ .text = ph },
        if (idem_key) |k| .{ .text = k } else .{ .null = {} },
    }) catch |err| {
        if (idem_key) |k| {
            if (err == error.QueryFailed) {
                const msg = conn.takeError();
                defer if (msg) |m| conn.allocator.free(m);
                if (msg != null and idempotencyConflict(msg.?)) {
                    if (try respondIdempotent(allocator, conn, request, web.tenant_id, agent_id, k)) return;
                }
            }
        }
        return err;
    };
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "response_action.create", id, null);

    const id_j = try util.escapeJson(allocator, id);
    defer allocator.free(id_j);
    const at_j = try util.escapeJson(allocator, parsed.value.action_type);
    defer allocator.free(at_j);
    const aid_j = try util.escapeJson(allocator, agent_id);
    defer allocator.free(aid_j);
    const req_j = try util.escapeJson(allocator, requested);
    defer allocator.free(req_j);
    const exp_j = try util.escapeJson(allocator, expires);
    defer allocator.free(exp_j);
    const ph_j = try util.escapeJson(allocator, ph);
    defer allocator.free(ph_j);
    const json = try std.fmt.allocPrint(allocator,
        \\{{"id":{s},"agent_id":{s},"action_type":{s},"status":"pending","requested_at":{s},"expires_at":{s},"payload":{s},"payload_hash":{s}}}
    , .{ id_j, aid_j, at_j, req_j, exp_j, payload_buf.items, ph_j });
    defer allocator.free(json);
    try util.respondJson(request, .created, json);
}

fn idempotencyConflict(msg: []const u8) bool {
    return std.mem.indexOf(u8, msg, "duplicate key") != null and std.mem.indexOf(u8, msg, "idempotency_key") != null;
}

/// A repeat POST with the same non-empty key returns the stored action, including a finished result.
fn respondIdempotent(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    tenant_id: []const u8,
    agent_id: []const u8,
    key: []const u8,
) !bool {
    const rows = try conn.exec(allocator,
        \\SELECT id::text, agent_id::text, action_type, status, payload_json::text, result_json::text
        \\FROM response_actions
        \\WHERE tenant_id = $1::uuid AND agent_id = $2::uuid AND idempotency_key = $3
        \\LIMIT 1
    , &.{ .{ .text = tenant_id }, .{ .text = agent_id }, .{ .text = key } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return false;
    const c = rows[0].cols;
    const id_j = try util.escapeJson(allocator, c[0] orelse "");
    defer allocator.free(id_j);
    const aid_j = try util.escapeJson(allocator, c[1] orelse "");
    defer allocator.free(aid_j);
    const at_j = try util.escapeJson(allocator, c[2] orelse "");
    defer allocator.free(at_j);
    const st_j = try util.escapeJson(allocator, c[3] orelse "");
    defer allocator.free(st_j);
    const json = try std.fmt.allocPrint(allocator,
        \\{{"id":{s},"agent_id":{s},"action_type":{s},"status":{s},"payload":{s},"result":{s}}}
    , .{ id_j, aid_j, at_j, st_j, c[4] orelse "null", c[5] orelse "null" });
    defer allocator.free(json);
    try util.respondJson(request, .ok, json);
    return true;
}

pub fn actionResult(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    agent: auth.AgentAuth,
    id: []const u8,
) !void {
    const body = try util.readBody(allocator, request, 64 * 1024);
    defer allocator.free(body);
    const Req = struct {
        status: []const u8,
        execution_token: []const u8,
        message: ?[]const u8 = null,
        result: ?std.json.Value = null,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "Invalid result body.");
    };
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.status, "succeeded") and !std.mem.eql(u8, parsed.value.status, "failed")) {
        return util.problem(request, allocator, .bad_request, "Response action results must be succeeded or failed.");
    }

    const rows = try conn.exec(allocator,
        \\SELECT agent_id::text, status, execution_token_hash FROM response_actions
        \\WHERE id = $1::uuid AND tenant_id = $2::uuid LIMIT 1
    , &.{ .{ .text = id }, .{ .text = agent.tenant_id } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return util.problem(request, allocator, .not_found, "Action not found.");
    if (!std.mem.eql(u8, rows[0].cols[0] orelse "", agent.agent_id)) {
        return util.problem(request, allocator, .not_found, "Action not found.");
    }
    const st = rows[0].cols[1] orelse "";
    if (std.mem.eql(u8, st, "succeeded") or std.mem.eql(u8, st, "failed") or std.mem.eql(u8, st, "expired") or std.mem.eql(u8, st, "cancelled")) {
        return util.problem(request, allocator, .conflict, "Action already terminal.");
    }
    const want = rows[0].cols[2] orelse return util.problem(request, allocator, .unauthorized, "Invalid execution token.");
    const got = try util.sha256Hex(allocator, parsed.value.execution_token);
    defer allocator.free(got);
    if (!std.mem.eql(u8, want, got)) {
        return util.problem(request, allocator, .unauthorized, "Invalid execution token.");
    }

    var result_buf: std.ArrayList(u8) = .empty;
    defer result_buf.deinit(allocator);
    try result_buf.appendSlice(allocator, "{\"message\":");
    if (parsed.value.message) |m| {
        const esc = try util.escapeJson(allocator, m);
        defer allocator.free(esc);
        try result_buf.appendSlice(allocator, esc);
    } else {
        try result_buf.appendSlice(allocator, "null");
    }
    try result_buf.appendSlice(allocator, ",\"result\":");
    if (parsed.value.result) |r| {
        const result_tmp = try std.json.Stringify.valueAlloc(allocator, r, .{});
        defer allocator.free(result_tmp);
        try result_buf.appendSlice(allocator, result_tmp);
    } else {
        try result_buf.appendSlice(allocator, "{}");
    }
    try result_buf.append(allocator, '}');
    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&tbuf, now);
    try conn.execNoRows(
        \\UPDATE response_actions SET status = $2, completed_at = $3::timestamptz, result_json = $4::jsonb, execution_token_hash = NULL
        \\WHERE id = $1::uuid
    , &.{
        .{ .text = id },
        .{ .text = parsed.value.status },
        .{ .text = now_s },
        .{ .text = result_buf.items },
    });
    try audit.add(allocator, io, conn, agent.tenant_id, null, "response_action.complete", id, null);
    try request.respond("", .{ .status = .no_content, .keep_alive = false });
}

pub fn listAgentEvents(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    agent_id: []const u8,
    target: []const u8,
) !void {
    _ = util.readBody(allocator, request, 1024) catch {};
    const exists = try conn.exec(allocator, "SELECT 1 FROM agents WHERE id = $1::uuid AND tenant_id = $2::uuid", &.{
        .{ .text = agent_id },
        .{ .text = web.tenant_id },
    });
    defer {
        for (exists) |row| row.deinit(allocator);
        allocator.free(exists);
    }
    if (exists.len == 0) return util.problem(request, allocator, .not_found, "Agent not found.");

    const typ = util.queryParam(target, "type");
    const limit_raw = util.queryParam(target, "limit") orelse "50";
    var limit = std.fmt.parseInt(i32, limit_raw, 10) catch 50;
    if (limit < 1) limit = 1;
    if (limit > 200) limit = 200;
    const lim = try std.fmt.allocPrint(allocator, "{d}", .{limit});
    defer allocator.free(lim);

    const rows = if (typ) |t| try conn.exec(allocator,
        \\SELECT id::text, client_event_id::text, batch_id::text, sequence_number::text, agent_id::text,
        \\       event_type, occurred_at::text, received_at::text, confidence, payload::text
        \\FROM telemetry_events
        \\WHERE agent_id = $1::uuid AND tenant_id = $2::uuid AND event_type = $3
        \\ORDER BY received_at DESC LIMIT $4::int
    , &.{ .{ .text = agent_id }, .{ .text = web.tenant_id }, .{ .text = t }, .{ .text = lim } }) else try conn.exec(allocator,
        \\SELECT id::text, client_event_id::text, batch_id::text, sequence_number::text, agent_id::text,
        \\       event_type, occurred_at::text, received_at::text, confidence, payload::text
        \\FROM telemetry_events
        \\WHERE agent_id = $1::uuid AND tenant_id = $2::uuid
        \\ORDER BY received_at DESC LIMIT $3::int
    , &.{ .{ .text = agent_id }, .{ .text = web.tenant_id }, .{ .text = lim } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.append(allocator, '[');
    for (rows, 0..) |row, i| {
        if (i > 0) try out.append(allocator, ',');
        const id_j = try util.escapeJson(allocator, row.cols[0] orelse "");
        defer allocator.free(id_j);
        const cid = try util.nullOrJsonString(allocator, row.cols[1]);
        defer allocator.free(cid);
        const bid = try util.nullOrJsonString(allocator, row.cols[2]);
        defer allocator.free(bid);
        const seq = if (row.cols[3]) |s| s else "null";
        const aid = try util.escapeJson(allocator, row.cols[4] orelse "");
        defer allocator.free(aid);
        const typ_j = try util.escapeJson(allocator, row.cols[5] orelse "");
        defer allocator.free(typ_j);
        const oc = try util.escapeJson(allocator, row.cols[6] orelse "");
        defer allocator.free(oc);
        const rc = try util.escapeJson(allocator, row.cols[7] orelse "");
        defer allocator.free(rc);
        const conf = try util.escapeJson(allocator, row.cols[8] orelse "agent_reported");
        defer allocator.free(conf);
        const payload = row.cols[9] orelse "{}";
        {
            const __tmp = try std.fmt.allocPrint(allocator, 
            "{{\"id\":{s},\"client_event_id\":{s},\"batch_id\":{s},\"sequence_number\":{s},\"agent_id\":{s},\"type\":{s},\"occurred_at\":{s},\"received_at\":{s},\"confidence\":{s},\"payload\":{s}}}",
            .{ id_j, cid, bid, seq, aid, typ_j, oc, rc, conf, payload },
        );
            defer allocator.free(__tmp);
            try out.appendSlice(allocator, __tmp);
        }
    }
    try out.append(allocator, ']');
    try util.respondJson(request, .ok, out.items);
}

const sse_keepalive = ": keep-alive\n\n";
const sse_slot_cap: u32 = 32;
var sse_slots = std.atomic.Value(u32).init(0);

const event_window_sql =
    \\SELECT id::text, event_type, occurred_at::text
    \\FROM telemetry_events
    \\WHERE agent_id = $1::uuid AND tenant_id = $2::uuid
    \\ORDER BY id DESC
    \\LIMIT 20
;

fn acquireSseSlot() bool {
    const held = sse_slots.fetchAdd(1, .monotonic);
    if (held >= sse_slot_cap) {
        _ = sse_slots.fetchSub(1, .monotonic);
        return false;
    }
    return true;
}

fn releaseSseSlot() void {
    _ = sse_slots.fetchSub(1, .monotonic);
}

fn freeRows(allocator: std.mem.Allocator, rows: []pg.Row) void {
    for (rows) |row| row.deinit(allocator);
    allocator.free(rows);
}

fn newestEventId(rows: []const pg.Row) i64 {
    if (rows.len == 0) return 0;
    const text = rows[0].cols[0] orelse return 0;
    return std.fmt.parseInt(i64, text, 10) catch 0;
}

fn eventsJson(allocator: std.mem.Allocator, rows: []const pg.Row) ![]u8 {
    var json: std.ArrayList(u8) = .empty;
    errdefer json.deinit(allocator);
    try json.append(allocator, '[');
    for (rows, 0..) |row, i| {
        if (i != 0) try json.append(allocator, ',');
        const id_j = try util.escapeJson(allocator, row.cols[0] orelse "");
        defer allocator.free(id_j);
        const typ_j = try util.escapeJson(allocator, row.cols[1] orelse "");
        defer allocator.free(typ_j);
        const at_j = try util.escapeJson(allocator, row.cols[2] orelse "");
        defer allocator.free(at_j);
        const line = try std.fmt.allocPrint(allocator, "{{\"id\":{s},\"type\":{s},\"occurred_at\":{s}}}", .{ id_j, typ_j, at_j });
        defer allocator.free(line);
        try json.appendSlice(allocator, line);
    }
    try json.append(allocator, ']');
    return json.toOwnedSlice(allocator);
}

fn formatSse(allocator: std.mem.Allocator, json: []const u8, event_id: ?[]const u8) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    try body.appendSlice(allocator, "retry: 5000\n");
    if (event_id) |id| if (id.len > 0) {
        try body.appendSlice(allocator, "id: ");
        try body.appendSlice(allocator, id);
        try body.append(allocator, '\n');
    };
    try body.appendSlice(allocator, "data: ");
    try body.appendSlice(allocator, json);
    try body.appendSlice(allocator, "\n\n");
    return body.toOwnedSlice(allocator);
}

fn queryEventWindow(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    agent_id: []const u8,
    tenant_id: []const u8,
) ![]pg.Row {
    return conn.exec(allocator, event_window_sql, &.{ .{ .text = agent_id }, .{ .text = tenant_id } });
}

fn writeSse(body: *std.http.BodyWriter, bytes: []const u8) !void {
    try body.writer.writeAll(bytes);
    try body.writer.flush();
    // The chunked writer stores the CRLF trailer until the next chunk starts.
    // Finish this chunk so the event is readable before the next write.
    switch (body.state) {
        .chunk_len => |n| if (n == 2) {
            try body.http_protocol_output.writeAll("\r\n");
            body.state = .{ .chunk_len = 0 };
        },
        else => {},
    }
    try body.flush();
}

fn respondOneShot(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    rows: []const pg.Row,
) !void {
    const json = try eventsJson(allocator, rows);
    defer allocator.free(json);
    const event_id: ?[]const u8 = if (rows.len > 0) rows[0].cols[0] else null;
    const frame = try formatSse(allocator, json, event_id);
    defer allocator.free(frame);
    try request.respond(frame, .{
        .status = .ok,
        .extra_headers = &.{
            .{ .name = "content-type", .value = "text/event-stream" },
            .{ .name = "cache-control", .value = "no-cache" },
        },
        .keep_alive = false,
    });
}

/// Hold the agent event stream open. The worker thread flushes one frame,
/// stores phase 1, then writes a fresh latest-20 array when the newest id
/// changes and a comment every 15s. `end` is not called; closing the socket
/// ends the chunked body. The 33rd concurrent stream is one frame then close.
pub fn streamAgentEvents(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    agent_id: []const u8,
    phase: *std.atomic.Value(u8),
) !void {
    _ = util.readBody(allocator, request, 1024) catch {};
    if (agent_id.len > 64 or web.tenant_id.len > 64) {
        return util.problem(request, allocator, .not_found, "Agent not found.");
    }
    var agent_buf: [64]u8 = undefined;
    var tenant_buf: [64]u8 = undefined;
    @memcpy(agent_buf[0..agent_id.len], agent_id);
    @memcpy(tenant_buf[0..web.tenant_id.len], web.tenant_id);
    const agent_copy = agent_buf[0..agent_id.len];
    const tenant_copy = tenant_buf[0..web.tenant_id.len];

    const exists = try conn.exec(allocator, "SELECT 1 FROM agents WHERE id = $1::uuid AND tenant_id = $2::uuid", &.{
        .{ .text = agent_copy },
        .{ .text = tenant_copy },
    });
    defer freeRows(allocator, exists);
    if (exists.len == 0) return util.problem(request, allocator, .not_found, "Agent not found.");

    if (!acquireSseSlot()) {
        const rows = try queryEventWindow(allocator, conn, agent_copy, tenant_copy);
        defer freeRows(allocator, rows);
        return respondOneShot(allocator, request, rows);
    }
    defer releaseSseSlot();

    var last_id: i64 = 0;
    const first_frame = blk: {
        const rows = try queryEventWindow(allocator, conn, agent_copy, tenant_copy);
        defer freeRows(allocator, rows);
        last_id = newestEventId(rows);
        const json = try eventsJson(allocator, rows);
        defer allocator.free(json);
        const event_id: ?[]const u8 = if (rows.len > 0) rows[0].cols[0] else null;
        break :blk try formatSse(allocator, json, event_id);
    };
    defer allocator.free(first_frame);

    request.head.keep_alive = false;
    var scratch: [8192]u8 = undefined;
    var body = try request.respondStreaming(&scratch, .{
        .respond_options = .{
            .status = .ok,
            .extra_headers = &.{
                .{ .name = "content-type", .value = "text/event-stream" },
                .{ .name = "cache-control", .value = "no-cache" },
            },
            .keep_alive = false,
        },
    });
    try writeSse(&body, first_frame);
    phase.store(1, .release);

    var ticks: u32 = 0;
    while (true) {
        std.Io.sleep(io, .fromMilliseconds(1000), .awake) catch return;
        ticks += 1;
        const rows = queryEventWindow(allocator, conn, agent_copy, tenant_copy) catch |err| {
            std.debug.print("sse query failed: {s}\n", .{@errorName(err)});
            if (ticks >= 15) {
                writeSse(&body, sse_keepalive) catch return;
                ticks = 0;
            }
            continue;
        };
        const now_id = newestEventId(rows);
        if (now_id != last_id) {
            const json = eventsJson(allocator, rows) catch {
                freeRows(allocator, rows);
                return;
            };
            defer allocator.free(json);
            const event_id: ?[]const u8 = if (rows.len > 0) rows[0].cols[0] else null;
            const frame = formatSse(allocator, json, event_id) catch {
                freeRows(allocator, rows);
                return;
            };
            defer allocator.free(frame);
            freeRows(allocator, rows);
            writeSse(&body, frame) catch return;
            last_id = now_id;
            ticks = 0;
        } else {
            freeRows(allocator, rows);
            if (ticks >= 15) {
                writeSse(&body, sse_keepalive) catch return;
                ticks = 0;
            }
        }
    }
}

test "enroll token prefix" {
    try std.testing.expect(std.mem.startsWith(u8, "wte_abc", "wte_"));
}

test "sse frame is retry, id, and one data array" {
    const allocator = std.testing.allocator;
    const empty = try formatSse(allocator, "[]", null);
    defer allocator.free(empty);
    try std.testing.expectEqualStrings("retry: 5000\ndata: []\n\n", empty);
    const framed = try formatSse(allocator, "[{\"id\":\"10\"}]", "10");
    defer allocator.free(framed);
    try std.testing.expectEqualStrings("retry: 5000\nid: 10\ndata: [{\"id\":\"10\"}]\n\n", framed);
    try std.testing.expectEqualStrings(": keep-alive\n\n", sse_keepalive);
}

test "idempotency conflict message names the key" {
    try std.testing.expect(idempotencyConflict("duplicate key value violates unique constraint \"response_actions_tenant_id_agent_id_idempotency_key_key\""));
    try std.testing.expect(!idempotencyConflict("duplicate key value violates unique constraint \"agents_pkey\""));
    try std.testing.expect(!idempotencyConflict("syntax error at idempotency_key"));
}

test "idempotency key replay returns the stored action" {
    const url = std.testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return;
    if (url.len == 0) return;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const migrate = @import("../db/migrate.zig");
    const conn = try pg.Conn.connect(allocator, io, url);
    defer {
        conn.close();
        allocator.destroy(conn);
    }
    try migrate.apply(allocator, conn);
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};

    var agent_buf: [36]u8 = undefined;
    const agent_id = util.newUuid(io, &agent_buf);
    try conn.execNoRows(
        \\INSERT INTO agents (
        \\  id, tenant_id, hostname, operating_system, os_version, agent_version,
        \\  architecture, enrolled_at, status, tags
        \\) VALUES ($1::uuid, $2::uuid, 'idem-host', 'linux', 'test', '0', 'arm64', now(), 'online', '{clinic}')
    , &.{ .{ .text = agent_id }, .{ .text = "00000000-0000-0000-0000-000000000001" } });

    var id_buf: [36]u8 = undefined;
    const action_id = util.newUuid(io, &id_buf);
    const key = "replay-key";
    try conn.execNoRows(
        \\INSERT INTO response_actions (
        \\  id, agent_id, tenant_id, action_type, status, requested_at, expires_at,
        \\  payload_json, idempotency_key
        \\) VALUES (
        \\  $1::uuid, $2::uuid, $3::uuid, 'isolate_host', 'pending', now(), now(), '{}'::jsonb, $4
        \\)
    , &.{
        .{ .text = action_id },
        .{ .text = agent_id },
        .{ .text = "00000000-0000-0000-0000-000000000001" },
        .{ .text = key },
    });

    const pending = try conn.exec(allocator,
        \\SELECT id::text, status, result_json::text FROM response_actions
        \\WHERE tenant_id = $1::uuid AND agent_id = $2::uuid AND idempotency_key = $3
    , &.{
        .{ .text = "00000000-0000-0000-0000-000000000001" },
        .{ .text = agent_id },
        .{ .text = key },
    });
    defer {
        for (pending) |row| row.deinit(allocator);
        allocator.free(pending);
    }
    try std.testing.expectEqual(@as(usize, 1), pending.len);
    try std.testing.expectEqualStrings(action_id, pending[0].cols[0].?);
    try std.testing.expectEqualStrings("pending", pending[0].cols[1].?);
    try std.testing.expect(pending[0].cols[2] == null);

    try conn.execNoRows(
        \\UPDATE response_actions SET status = 'failed', result_json = '{"message":"isolation not supported by this agent"}'::jsonb
        \\WHERE id = $1::uuid
    , &.{.{ .text = action_id }});
    const failed = try conn.exec(allocator,
        \\SELECT id::text, status, result_json::text FROM response_actions
        \\WHERE tenant_id = $1::uuid AND agent_id = $2::uuid AND idempotency_key = $3
    , &.{
        .{ .text = "00000000-0000-0000-0000-000000000001" },
        .{ .text = agent_id },
        .{ .text = key },
    });
    defer {
        for (failed) |row| row.deinit(allocator);
        allocator.free(failed);
    }
    try std.testing.expectEqualStrings(action_id, failed[0].cols[0].?);
    try std.testing.expectEqualStrings("failed", failed[0].cols[1].?);
    try std.testing.expect(std.mem.indexOf(u8, failed[0].cols[2].?, "isolation not supported by this agent") != null);

    var other_buf: [36]u8 = undefined;
    const other = util.newUuid(io, &other_buf);
    try conn.execSimple("SAVEPOINT dup_key");
    const dup = conn.execNoRows(
        \\INSERT INTO response_actions (
        \\  id, agent_id, tenant_id, action_type, status, requested_at, expires_at,
        \\  payload_json, idempotency_key
        \\) VALUES (
        \\  $1::uuid, $2::uuid, $3::uuid, 'isolate_host', 'pending', now(), now(), '{}'::jsonb, $4
        \\)
    , &.{
        .{ .text = other },
        .{ .text = agent_id },
        .{ .text = "00000000-0000-0000-0000-000000000001" },
        .{ .text = key },
    });
    try std.testing.expectError(error.QueryFailed, dup);
    const msg = conn.takeError();
    try std.testing.expect(msg != null);
    defer conn.allocator.free(msg.?);
    try std.testing.expect(idempotencyConflict(msg.?));
    try conn.execSimple("ROLLBACK TO SAVEPOINT dup_key");

    const listed = try conn.exec(allocator, agent_select ++ " WHERE id = $1::uuid", &.{.{ .text = agent_id }});
    defer {
        for (listed) |row| row.deinit(allocator);
        allocator.free(listed);
    }
    const summary = try agentSummaryJson(allocator, listed[0].cols);
    defer allocator.free(summary);
    try std.testing.expect(std.mem.indexOf(u8, summary, "\"tags\":[\"clinic\"]") != null);

    try conn.execSimple("ROLLBACK");
}
