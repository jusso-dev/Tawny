//! Routes the contract surface onto the handlers in `routes/`.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("util.zig");
const auth = @import("auth.zig");
const agents = @import("../routes/agents.zig");
const alerts = @import("../routes/alerts.zig");
const tokens = @import("../routes/tokens.zig");
const session = @import("../routes/auth.zig");
const users = @import("../routes/users.zig");
const github = @import("../routes/github.zig");
const admin_jobs = @import("../routes/admin_jobs.zig");
const agent_releases = @import("../routes/agent_releases.zig");
const hunts_http = @import("../routes/hunts.zig");
const feeds_http = @import("../routes/feeds.zig");
const suppressions = @import("../routes/suppressions.zig");
const lookup_http = @import("../routes/lookup.zig");
const state = @import("state.zig");

pub fn handle(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    phase: *std.atomic.Value(u8),
) !void {
    var target_buf: [4096]u8 = undefined;
    const target_raw = request.head.target;
    if (target_raw.len > target_buf.len) {
        try util.respondJson(request, .uri_too_long, "{\"error\":\"not_found\"}");
        return;
    }
    @memcpy(target_buf[0..target_raw.len], target_raw);
    const target = target_buf[0..target_raw.len];
    const path = util.pathOnly(target);
    const method = request.head.method;

    var parts: [8][]const u8 = undefined;
    const n = splitPath(path, &parts);

    const resolved = auth.resolve(allocator, io, conn, request) catch {
        try util.respondJson(request, .internal_server_error, "{\"error\":\"internal\"}");
        return;
    };

    route(allocator, io, conn, request, method, target, parts[0..n], resolved, phase) catch |err| {
        if (conn.takeError()) |msg| {
            std.debug.print("route {s} {s} failed: {s}: {s}\n", .{ @tagName(method), path, @errorName(err), msg });
            conn.allocator.free(msg);
        } else {
            std.debug.print("route {s} {s} failed: {s}\n", .{ @tagName(method), path, @errorName(err) });
        }
        util.respondJson(request, .internal_server_error, "{\"error\":\"internal\"}") catch {};
    };
}

fn route(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    method: std.http.Method,
    target: []const u8,
    parts: []const []const u8,
    resolved: auth.Auth,
    phase: *std.atomic.Value(u8),
) !void {
    if (parts.len >= 2 and std.mem.eql(u8, parts[0], "api") and std.mem.eql(u8, parts[1], "auth")) {
        if (parts.len == 3 and std.mem.eql(u8, parts[2], "login") and method == .POST) {
            return session.login(allocator, io, conn, request);
        }
        if (parts.len == 4 and std.mem.eql(u8, parts[2], "github") and std.mem.eql(u8, parts[3], "start") and method == .GET) {
            return github.start(allocator, io, conn, request);
        }
        if (parts.len == 4 and std.mem.eql(u8, parts[2], "github") and std.mem.eql(u8, parts[3], "callback") and method == .GET) {
            return github.callback(allocator, io, conn, request, target);
        }
        const session_route = (parts.len == 3 and std.mem.eql(u8, parts[2], "logout") and method == .POST) or
            (parts.len == 3 and std.mem.eql(u8, parts[2], "session") and method == .GET) or
            (parts.len == 3 and std.mem.eql(u8, parts[2], "password") and method == .POST);
        if (!session_route) return notFound(request);
        const web = try needWeb(request, resolved) orelse return;
        if (parts.len == 3 and std.mem.eql(u8, parts[2], "logout") and method == .POST) {
            return session.logout(allocator, io, conn, request, web);
        }
        if (parts.len == 3 and std.mem.eql(u8, parts[2], "session") and method == .GET) {
            return session.session(allocator, request, web);
        }
        if (try stopLimited(request, io, web, policy_web_mutate)) return;
        return session.changePassword(allocator, io, conn, request, web);
    }

    if (parts.len >= 2 and std.mem.eql(u8, parts[0], "api") and std.mem.eql(u8, parts[1], "users")) {
        const web = try needAdmin(request, resolved) orelse return;
        if (parts.len == 2 and method == .GET) return users.list(allocator, conn, request, web);
        if (try stopLimited(request, io, web, policy_web_admin_mutate)) return;
        if (parts.len == 2 and method == .POST) return users.create(allocator, io, conn, request, web);
        if (parts.len == 3 and method == .PUT) return users.update(allocator, io, conn, request, web, parts[2]);
        if (parts.len == 3 and method == .DELETE) return users.delete(allocator, io, conn, request, web, parts[2]);
        return notFound(request);
    }

    if (parts.len == 2 and std.mem.eql(u8, parts[0], "api") and std.mem.eql(u8, parts[1], "enrollment-tokens") and method == .POST) {
        const web = try needAdmin(request, resolved) orelse return;
        if (try stopLimited(request, io, web, policy_web_admin_mutate)) return;
        return agents.createEnrollmentToken(allocator, io, conn, request, web);
    }

    if (parts.len >= 2 and std.mem.eql(u8, parts[0], "api") and std.mem.eql(u8, parts[1], "agents")) {
        if (parts.len == 3 and std.mem.eql(u8, parts[2], "enroll") and method == .POST) {
            return agents.enroll(allocator, io, conn, request);
        }
        if (parts.len == 3 and std.mem.eql(u8, parts[2], "heartbeat") and method == .POST) {
            const agent = try needAgent(request, resolved) orelse return;
            return agents.heartbeat(allocator, io, conn, request, agent);
        }
        if (parts.len == 3 and std.mem.eql(u8, parts[2], "events") and method == .POST) {
            const agent = try needAgent(request, resolved) orelse return;
            return agents.ingestEvents(allocator, io, conn, request, agent);
        }
        if (parts.len == 5 and std.mem.eql(u8, parts[2], "actions") and std.mem.eql(u8, parts[4], "result") and method == .POST) {
            const agent = try needAgent(request, resolved) orelse return;
            return agents.actionResult(allocator, io, conn, request, agent, parts[3]);
        }
        if (parts.len == 2 and method == .GET) {
            const web = try needWeb(request, resolved) orelse return;
            return agents.listAgents(allocator, conn, request, web);
        }
        if (parts.len == 3 and method == .GET) {
            const web = try needWeb(request, resolved) orelse return;
            return agents.getAgent(allocator, conn, request, web, parts[2]);
        }
        if (parts.len == 4 and std.mem.eql(u8, parts[3], "revoke") and method == .POST) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_web_admin_mutate)) return;
            return agents.revokeAgent(allocator, io, conn, request, web, parts[2]);
        }
        if (parts.len == 4 and std.mem.eql(u8, parts[3], "events") and method == .GET) {
            const web = try needWeb(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_web_read)) return;
            return agents.listAgentEvents(allocator, conn, request, web, parts[2], target);
        }
        if (parts.len == 5 and std.mem.eql(u8, parts[3], "events") and std.mem.eql(u8, parts[4], "stream") and method == .GET) {
            const web = try needWeb(request, resolved) orelse return;
            return agents.streamAgentEvents(allocator, io, conn, request, web, parts[2], phase);
        }
        if (parts.len == 4 and std.mem.eql(u8, parts[3], "actions") and method == .POST) {
            const web = try needAdmin(request, resolved) orelse return;
            return agents.createAction(allocator, io, conn, request, web, parts[2]);
        }
        if (parts.len == 4 and std.mem.eql(u8, parts[3], "actions") and method == .GET) {
            const web = try needWeb(request, resolved) orelse return;
            return listActions(allocator, conn, request, web, parts[2]);
        }
        if (parts.len == 5 and std.mem.eql(u8, parts[3], "actions") and method == .GET) {
            const web = try needWeb(request, resolved) orelse return;
            return getAction(allocator, conn, request, web, parts[2], parts[4]);
        }
        return notFound(request);
    }

    if (parts.len >= 2 and std.mem.eql(u8, parts[0], "api") and std.mem.eql(u8, parts[1], "alert-rules")) {
        if (parts.len == 2 and method == .GET) {
            const web = try needWeb(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_web_read)) return;
            return alerts.listRules(allocator, conn, request, web);
        }
        if (parts.len == 2 and method == .POST) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_web_read)) return;
            return alerts.createPredicate(allocator, io, conn, request, web);
        }
        if (parts.len == 3 and std.mem.eql(u8, parts[2], "exposures") and method == .POST) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_rule_imports)) return;
            return alerts.importExposures(allocator, io, conn, request, web);
        }
        if (parts.len == 3 and std.mem.eql(u8, parts[2], "sigma") and method == .POST) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_rule_imports)) return;
            return alerts.importSigma(allocator, io, conn, request, web);
        }
        if (parts.len == 3 and std.mem.eql(u8, parts[2], "iocs") and method == .POST) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_rule_imports)) return;
            return alerts.importIocs(allocator, io, conn, request, web);
        }
        if (parts.len == 3 and method == .PUT) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_web_read)) return;
            return alerts.updateRule(allocator, io, conn, request, web, parts[2]);
        }
        if (parts.len == 3 and method == .DELETE) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_web_read)) return;
            return alerts.deleteRule(allocator, io, conn, request, web, parts[2]);
        }
        return notFound(request);
    }

    if (parts.len >= 2 and std.mem.eql(u8, parts[0], "api") and std.mem.eql(u8, parts[1], "hunts")) {
        if (parts.len == 3 and std.mem.eql(u8, parts[2], "run") and method == .POST) {
            const web = try needWeb(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_hunts)) return;
            return hunts_http.runAdHoc(allocator, io, conn, request, web);
        }
        if (parts.len == 2 and method == .GET) {
            const web = try needWeb(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_hunts)) return;
            return hunts_http.list(allocator, conn, request, web);
        }
        if (parts.len == 2 and method == .POST) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_hunts)) return;
            return hunts_http.create(allocator, io, conn, request, web);
        }
        if (parts.len == 3 and method == .GET) {
            const web = try needWeb(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_hunts)) return;
            return hunts_http.get(allocator, conn, request, web, parts[2]);
        }
        if (parts.len == 3 and method == .PUT) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_hunts)) return;
            return hunts_http.update(allocator, io, conn, request, web, parts[2]);
        }
        if (parts.len == 3 and method == .DELETE) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_hunts)) return;
            return hunts_http.delete(allocator, io, conn, request, web, parts[2]);
        }
        if (parts.len == 4 and std.mem.eql(u8, parts[3], "run") and method == .POST) {
            const web = try needWeb(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_hunts)) return;
            return hunts_http.runSaved(allocator, io, conn, request, web, parts[2]);
        }
        if (parts.len == 4 and std.mem.eql(u8, parts[3], "runs") and method == .GET) {
            const web = try needWeb(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_hunts)) return;
            return hunts_http.runs(allocator, conn, request, web, parts[2]);
        }
        return notFound(request);
    }

    if (parts.len >= 2 and std.mem.eql(u8, parts[0], "api") and std.mem.eql(u8, parts[1], "threat-intel-feeds")) {
        if (parts.len == 2 and method == .GET) {
            const web = try needWeb(request, resolved) orelse return;
            return feeds_http.list(allocator, conn, request, web);
        }
        if (parts.len == 2 and method == .POST) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_web_admin_mutate)) return;
            return feeds_http.create(allocator, io, conn, request, web);
        }
        if (parts.len == 3 and method == .PUT) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_web_admin_mutate)) return;
            return feeds_http.update(allocator, io, conn, request, web, parts[2]);
        }
        if (parts.len == 3 and method == .DELETE) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_web_admin_mutate)) return;
            return feeds_http.delete(allocator, io, conn, request, web, parts[2]);
        }
        if (parts.len == 4 and std.mem.eql(u8, parts[3], "run") and method == .POST) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_web_admin_mutate)) return;
            return feeds_http.run(allocator, io, conn, request, web, parts[2]);
        }
        return notFound(request);
    }

    if (parts.len >= 2 and std.mem.eql(u8, parts[0], "api") and std.mem.eql(u8, parts[1], "suppression-rules")) {
        if (parts.len == 2 and method == .GET) {
            const web = try needWeb(request, resolved) orelse return;
            return suppressions.list(allocator, conn, request, web);
        }
        if (parts.len == 2 and method == .POST) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_web_admin_mutate)) return;
            return suppressions.create(allocator, io, conn, request, web);
        }
        if (parts.len == 3 and method == .PUT) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_web_admin_mutate)) return;
            return suppressions.update(allocator, io, conn, request, web, parts[2]);
        }
        if (parts.len == 3 and method == .DELETE) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_web_admin_mutate)) return;
            return suppressions.delete(allocator, io, conn, request, web, parts[2]);
        }
        return notFound(request);
    }

    if (parts.len >= 2 and std.mem.eql(u8, parts[0], "api") and std.mem.eql(u8, parts[1], "alerts")) {
        const web = try needWeb(request, resolved) orelse return;
        if (parts.len == 2 and method == .GET) {
            if (try stopLimited(request, io, web, policy_web_read)) return;
            return alerts.listAlerts(allocator, conn, request, web, target);
        }
        if (parts.len == 3 and method == .GET) {
            if (try stopLimited(request, io, web, policy_web_read)) return;
            return alerts.getAlert(allocator, conn, request, web, parts[2]);
        }
        return notFound(request);
    }

    if (parts.len == 2 and std.mem.eql(u8, parts[0], "api") and std.mem.eql(u8, parts[1], "api-tokens")) {
        if (method == .POST) {
            const web = try needAdmin(request, resolved) orelse return;
            if (try stopLimited(request, io, web, policy_web_admin_mutate)) return;
            return tokens.createApiToken(allocator, io, conn, request, web);
        }
        if (method == .GET) {
            const web = try needWeb(request, resolved) orelse return;
            return tokens.listApiTokens(allocator, conn, request, web);
        }
        return notFound(request);
    }

    if (parts.len == 3 and std.mem.eql(u8, parts[0], "api") and std.mem.eql(u8, parts[1], "releases") and std.mem.eql(u8, parts[2], "latest") and method == .GET) {
        const web = try needWeb(request, resolved) orelse return;
        return agent_releases.latest(allocator, conn, request, web, target);
    }

    if (parts.len == 3 and std.mem.eql(u8, parts[0], "api") and std.mem.eql(u8, parts[1], "admin") and std.mem.eql(u8, parts[2], "jobs") and method == .GET) {
        const web = try needAdmin(request, resolved) orelse return;
        return admin_jobs.list(allocator, conn, request, web);
    }

    if (parts.len == 3 and std.mem.eql(u8, parts[0], "api") and std.mem.eql(u8, parts[1], "threat-intel") and std.mem.eql(u8, parts[2], "lookup") and method == .POST) {
        const web = try needWeb(request, resolved) orelse return;
        if (try stopLimited(request, io, web, policy_search)) return;
        return lookup_http.lookup(allocator, conn, request, web);
    }

    if (parts.len == 2 and std.mem.eql(u8, parts[0], "api") and std.mem.eql(u8, parts[1], "audit-logs") and method == .GET) {
        const web = try needWeb(request, resolved) orelse return;
        return tokens.listAuditLogs(allocator, conn, request, web, target);
    }

    return notFound(request);
}

fn listActions(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    agent_id: []const u8,
) !void {
    const rows = try conn.exec(allocator,
        \\SELECT id::text, action_type, status, payload_json::text, payload_hash,
        \\       requested_at::text, dispatched_at::text, completed_at::text, result_json::text
        \\FROM response_actions
        \\WHERE tenant_id = $1::uuid AND agent_id = $2::uuid
        \\ORDER BY requested_at DESC
    , &.{ .{ .text = web.tenant_id }, .{ .text = agent_id } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.append(allocator, '[');
    for (rows, 0..) |row, i| {
        if (i != 0) try out.append(allocator, ',');
        try appendAction(&out, allocator, row);
    }
    try out.append(allocator, ']');
    try util.respondJson(request, .ok, out.items);
}

fn getAction(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    agent_id: []const u8,
    id: []const u8,
) !void {
    const rows = try conn.exec(allocator,
        \\SELECT id::text, action_type, status, payload_json::text, payload_hash,
        \\       requested_at::text, dispatched_at::text, completed_at::text, result_json::text
        \\FROM response_actions
        \\WHERE tenant_id = $1::uuid AND agent_id = $2::uuid AND id = $3::uuid
        \\LIMIT 1
    , &.{ .{ .text = web.tenant_id }, .{ .text = agent_id }, .{ .text = id } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return util.problem(request, allocator, .not_found, "Action not found.");
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try appendAction(&out, allocator, rows[0]);
    try util.respondJson(request, .ok, out.items);
}

fn appendAction(out: *std.ArrayList(u8), allocator: std.mem.Allocator, row: pg.Row) !void {
    const c = row.cols;
    try out.appendSlice(allocator, "{\"id\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[0] orelse ""));
    try out.appendSlice(allocator, ",\"action_type\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[1] orelse ""));
    try out.appendSlice(allocator, ",\"status\":");
    try out.appendSlice(allocator, try util.escapeJson(allocator, c[2] orelse ""));
    try out.appendSlice(allocator, ",\"payload\":");
    try out.appendSlice(allocator, c[3] orelse "null");
    try out.appendSlice(allocator, ",\"payload_hash\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[4]));
    try out.appendSlice(allocator, ",\"requested_at\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[5]));
    try out.appendSlice(allocator, ",\"dispatched_at\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[6]));
    try out.appendSlice(allocator, ",\"completed_at\":");
    try out.appendSlice(allocator, try util.nullOrJsonString(allocator, c[7]));
    try out.appendSlice(allocator, ",\"result\":");
    try out.appendSlice(allocator, c[8] orelse "null");
    try out.append(allocator, '}');
}

fn splitPath(path: []const u8, out: *[8][]const u8) usize {
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |part| {
        if (part.len == 0) continue;
        if (n == out.len) break;
        out[n] = part;
        n += 1;
    }
    return n;
}

const Policy = struct {
    name: []const u8,
    limit: u32,
    body: []const u8,
};

const policy_web_read = Policy{
    .name = "web-read",
    .limit = 300,
    .body = "{\"error\":\"rate_limited\",\"detail\":\"Too many requests.\",\"policy\":\"web-read\"}",
};
const policy_web_mutate = Policy{
    .name = "web-mutate",
    .limit = 60,
    .body = "{\"error\":\"rate_limited\",\"detail\":\"Too many requests.\",\"policy\":\"web-mutate\"}",
};
const policy_web_admin_mutate = Policy{
    .name = "web-admin-mutate",
    .limit = 30,
    .body = "{\"error\":\"rate_limited\",\"detail\":\"Too many requests.\",\"policy\":\"web-admin-mutate\"}",
};
const policy_rule_imports = Policy{
    .name = "rule-imports",
    .limit = 10,
    .body = "{\"error\":\"rate_limited\",\"detail\":\"Too many requests.\",\"policy\":\"rule-imports\"}",
};
const policy_hunts = Policy{
    .name = "hunts",
    .limit = 20,
    .body = "{\"error\":\"rate_limited\",\"detail\":\"Too many requests.\",\"policy\":\"hunts\"}",
};
const policy_search = Policy{
    .name = "search",
    .limit = 60,
    .body = "{\"error\":\"rate_limited\",\"detail\":\"Too many requests.\",\"policy\":\"search\"}",
};

fn stopLimited(
    request: *std.http.Server.Request,
    io: std.Io,
    web: auth.WebUser,
    policy: Policy,
) !bool {
    var buf: [256]u8 = undefined;
    const key = std.fmt.bufPrint(&buf, "{s}:{s}", .{ web.tenant_id, web.user_id }) catch web.user_id;
    if (!state.tooMany(io, policy.name, key, policy.limit)) return false;
    try util.respondJson(request, .too_many_requests, policy.body);
    return true;
}

fn needWeb(request: *std.http.Server.Request, resolved: auth.Auth) !?auth.WebUser {
    if (auth.requireWeb(resolved)) |web| return web;
    try util.respondJson(request, .unauthorized, "{\"title\":\"Unauthorized.\",\"status\":401}");
    return null;
}

fn needAdmin(request: *std.http.Server.Request, resolved: auth.Auth) !?auth.WebUser {
    if (auth.requireAdmin(resolved)) |web| return web;
    if (auth.requireWeb(resolved) != null) {
        try util.respondJson(request, .forbidden, "{\"title\":\"Forbidden.\",\"status\":403}");
    } else {
        try util.respondJson(request, .unauthorized, "{\"title\":\"Unauthorized.\",\"status\":401}");
    }
    return null;
}

fn needAgent(request: *std.http.Server.Request, resolved: auth.Auth) !?auth.AgentAuth {
    if (auth.requireAgent(resolved)) |agent| return agent;
    try util.respondJson(request, .unauthorized, "{\"title\":\"Unauthorized.\",\"status\":401}");
    return null;
}

fn notFound(request: *std.http.Server.Request) !void {
    try util.respondJson(request, .not_found, "{\"error\":\"not_found\"}");
}
