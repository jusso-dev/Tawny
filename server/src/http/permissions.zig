//! Route permission gate. Each file in `routes/` declares `pub const routes`,
//! a table of method, path pattern and the `auth.Permission` it needs.
//! Dispatch looks the request up here before it calls a handler, so a route
//! missing from every table answers 404 and a role without the permission
//! answers 403. The matrix is written out in docs/api.md.
const std = @import("std");
const auth = @import("auth.zig");

pub const Route = struct {
    method: std.http.Method,
    /// `/api/agents/:id/actions`. `:name` matches one non-empty segment.
    path: []const u8,
    perm: auth.Permission,
};

const tables = .{
    @import("../routes/auth.zig").routes,
    @import("../routes/github.zig").routes,
    @import("../routes/oidc.zig").routes,
    @import("../routes/users.zig").routes,
    @import("../routes/tokens.zig").routes,
    @import("../routes/agents.zig").routes,
    @import("../routes/yara_rules.zig").routes,
    @import("../routes/agent_releases.zig").routes,
    @import("../routes/alerts.zig").routes,
    @import("../routes/incidents.zig").routes,
    @import("../routes/attack.zig").routes,
    @import("../routes/hunts.zig").routes,
    @import("../routes/feeds.zig").routes,
    @import("../routes/suppressions.zig").routes,
    @import("../routes/lookup.zig").routes,
    @import("../routes/admin_jobs.zig").routes,
    @import("../routes/ai.zig").routes,
    @import("../routes/settings.zig").routes,
};

pub const all: []const Route = blk: {
    var list: []const Route = &.{};
    for (tables) |t| list = list ++ t;
    break :blk &list[0..list.len].*;
};

fn segmentsMatch(pattern: []const u8, parts: []const []const u8) bool {
    var it = std.mem.splitScalar(u8, pattern, '/');
    var i: usize = 0;
    while (it.next()) |seg| {
        if (seg.len == 0) continue;
        if (i >= parts.len) return false;
        if (seg[0] == ':') {
            if (parts[i].len == 0) return false;
        } else if (!std.mem.eql(u8, seg, parts[i])) return false;
        i += 1;
    }
    return i == parts.len;
}

/// Literal segments win over `:param` ones, so `/api/agents/enroll` is not
/// read as `/api/agents/:id`.
pub fn lookup(method: std.http.Method, parts: []const []const u8) ?Route {
    var best: ?Route = null;
    var best_literals: usize = 0;
    for (all) |r| {
        if (r.method != method) continue;
        if (!segmentsMatch(r.path, parts)) continue;
        const lits = literalCount(r.path);
        if (best == null or lits > best_literals) {
            best = r;
            best_literals = lits;
        }
    }
    return best;
}

fn literalCount(pattern: []const u8) usize {
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, pattern, '/');
    while (it.next()) |seg| {
        if (seg.len != 0 and seg[0] != ':') n += 1;
    }
    return n;
}

pub const Decision = enum { allow, unauthorized, forbidden };

pub fn decide(perm: auth.Permission, resolved: auth.Auth) Decision {
    return switch (perm) {
        .public => .allow,
        .agent => if (auth.requireAgent(resolved) != null) .allow else .unauthorized,
        else => blk: {
            const web = auth.requireWeb(resolved) orelse break :blk .unauthorized;
            break :blk if (auth.can(web.role, perm)) .allow else .forbidden;
        },
    };
}

fn split(path: []const u8, out: *[8][]const u8) []const []const u8 {
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |p| {
        if (p.len == 0) continue;
        out[n] = p;
        n += 1;
    }
    return out[0..n];
}

fn webAs(role: auth.Role) auth.Auth {
    return .{ .web = .{ .user_id = "u", .tenant_id = "t", .email = "", .role = role } };
}

/// One row per route: what admin, analyst and viewer get. `a` allow, `f`
/// forbidden. Public and agent routes are listed with their own markers.
const Expect = struct { method: std.http.Method, path: []const u8, admin: u8, analyst: u8, viewer: u8 };

const expected = [_]Expect{
    // Sign-in and session
    .{ .method = .POST, .path = "/api/auth/login", .admin = 'p', .analyst = 'p', .viewer = 'p' },
    .{ .method = .GET, .path = "/api/auth/methods", .admin = 'p', .analyst = 'p', .viewer = 'p' },
    .{ .method = .GET, .path = "/api/auth/github/start", .admin = 'p', .analyst = 'p', .viewer = 'p' },
    .{ .method = .GET, .path = "/api/auth/github/callback", .admin = 'p', .analyst = 'p', .viewer = 'p' },
    .{ .method = .GET, .path = "/api/auth/oidc/start", .admin = 'p', .analyst = 'p', .viewer = 'p' },
    .{ .method = .GET, .path = "/api/auth/oidc/callback", .admin = 'p', .analyst = 'p', .viewer = 'p' },
    .{ .method = .POST, .path = "/api/auth/logout", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .GET, .path = "/api/auth/session", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .POST, .path = "/api/auth/password", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    // Users and tokens
    .{ .method = .GET, .path = "/api/users", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .POST, .path = "/api/users", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .PUT, .path = "/api/users/x", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .DELETE, .path = "/api/users/x", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .POST, .path = "/api/api-tokens", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .GET, .path = "/api/api-tokens", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .GET, .path = "/api/audit-logs", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    // Agents and response
    .{ .method = .POST, .path = "/api/enrollment-tokens", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .POST, .path = "/api/agents/enroll", .admin = 'p', .analyst = 'p', .viewer = 'p' },
    .{ .method = .POST, .path = "/api/agents/heartbeat", .admin = 'g', .analyst = 'g', .viewer = 'g' },
    .{ .method = .POST, .path = "/api/agents/events", .admin = 'g', .analyst = 'g', .viewer = 'g' },
    .{ .method = .POST, .path = "/api/agents/actions/y/result", .admin = 'g', .analyst = 'g', .viewer = 'g' },
    .{ .method = .POST, .path = "/api/agent/yara-rules", .admin = 'g', .analyst = 'g', .viewer = 'g' },
    .{ .method = .POST, .path = "/api/agent/update-check", .admin = 'g', .analyst = 'g', .viewer = 'g' },
    .{ .method = .GET, .path = "/api/agents", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .GET, .path = "/api/agents/x", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .POST, .path = "/api/agents/x/revoke", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .GET, .path = "/api/agents/x/events", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .GET, .path = "/api/agents/x/events/stream", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .GET, .path = "/api/agents/x/process-tree", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .POST, .path = "/api/agents/x/actions", .admin = 'a', .analyst = 'a', .viewer = 'f' },
    .{ .method = .GET, .path = "/api/agents/x/actions", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .GET, .path = "/api/agents/x/actions/y", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .POST, .path = "/api/agents/x/actions/y/approve", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .GET, .path = "/api/releases/latest", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .GET, .path = "/api/yara/rule-key", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    // Rules
    .{ .method = .GET, .path = "/api/alert-rules", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .POST, .path = "/api/alert-rules", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .POST, .path = "/api/alert-rules/exposures", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .POST, .path = "/api/alert-rules/yara", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .POST, .path = "/api/alert-rules/sigma", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .POST, .path = "/api/alert-rules/iocs", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .PUT, .path = "/api/alert-rules/x", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .DELETE, .path = "/api/alert-rules/x", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    // Alerts and incidents
    .{ .method = .GET, .path = "/api/alerts", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .GET, .path = "/api/alerts/x", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .POST, .path = "/api/alerts/x/acknowledge", .admin = 'a', .analyst = 'a', .viewer = 'f' },
    .{ .method = .POST, .path = "/api/alerts/x/resolve", .admin = 'a', .analyst = 'a', .viewer = 'f' },
    .{ .method = .GET, .path = "/api/incidents", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .GET, .path = "/api/incidents/x", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .POST, .path = "/api/incidents/x/assign", .admin = 'a', .analyst = 'a', .viewer = 'f' },
    .{ .method = .POST, .path = "/api/incidents/x/status", .admin = 'a', .analyst = 'a', .viewer = 'f' },
    .{ .method = .GET, .path = "/api/attack/coverage", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    // Hunts
    .{ .method = .POST, .path = "/api/hunts/run", .admin = 'a', .analyst = 'a', .viewer = 'f' },
    .{ .method = .GET, .path = "/api/hunts", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .POST, .path = "/api/hunts", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .GET, .path = "/api/hunts/x", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .PUT, .path = "/api/hunts/x", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .DELETE, .path = "/api/hunts/x", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .POST, .path = "/api/hunts/x/run", .admin = 'a', .analyst = 'a', .viewer = 'f' },
    .{ .method = .GET, .path = "/api/hunts/x/runs", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    // Feeds, exceptions, lookup
    .{ .method = .GET, .path = "/api/threat-intel-feeds", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .POST, .path = "/api/threat-intel-feeds", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .PUT, .path = "/api/threat-intel-feeds/x", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .DELETE, .path = "/api/threat-intel-feeds/x", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .POST, .path = "/api/threat-intel-feeds/x/run", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .GET, .path = "/api/suppression-rules", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .POST, .path = "/api/suppression-rules", .admin = 'a', .analyst = 'a', .viewer = 'f' },
    .{ .method = .PUT, .path = "/api/suppression-rules/x", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .DELETE, .path = "/api/suppression-rules/x", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .POST, .path = "/api/threat-intel/lookup", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    // Jobs, AI, settings
    .{ .method = .GET, .path = "/api/admin/jobs", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .GET, .path = "/api/ai/config", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .PUT, .path = "/api/ai/config", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .GET, .path = "/api/ai/findings", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .GET, .path = "/api/ai/findings/x", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .GET, .path = "/api/ai/investigations", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .GET, .path = "/api/ai/investigations/x", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .GET, .path = "/api/ai/metrics", .admin = 'a', .analyst = 'a', .viewer = 'a' },
    .{ .method = .POST, .path = "/api/ai/observations", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .GET, .path = "/api/settings/tenant", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .PUT, .path = "/api/settings/tenant", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .GET, .path = "/api/settings/oidc", .admin = 'a', .analyst = 'f', .viewer = 'f' },
    .{ .method = .PUT, .path = "/api/settings/oidc", .admin = 'a', .analyst = 'f', .viewer = 'f' },
};

test "every route answers each role as the matrix says" {
    const agent_auth: auth.Auth = .{ .agent = .{ .agent_id = "a", .tenant_id = "t", .cv = 1, .exp = 0 } };
    for (expected) |e| {
        var buf: [8][]const u8 = undefined;
        const parts = split(e.path, &buf);
        const r = lookup(e.method, parts) orelse {
            std.debug.print("no route for {s} {s}\n", .{ @tagName(e.method), e.path });
            return error.MissingRoute;
        };
        const roles = [_]struct { role: auth.Role, want: u8 }{
            .{ .role = .admin, .want = e.admin },
            .{ .role = .analyst, .want = e.analyst },
            .{ .role = .viewer, .want = e.viewer },
        };
        for (roles) |rr| {
            const got = decide(r.perm, webAs(rr.role));
            const want: Decision = switch (rr.want) {
                'a', 'p' => .allow,
                'f' => .forbidden,
                // Agent routes refuse every web role.
                'g' => .unauthorized,
                else => unreachable,
            };
            if (got != want) {
                std.debug.print("{s} {s} as {s}: got {s}, want {s}\n", .{ @tagName(e.method), e.path, @tagName(rr.role), @tagName(got), @tagName(want) });
                return error.MatrixMismatch;
            }
        }
        // Anonymous callers: public routes allow, everything else is 401.
        const anon = decide(r.perm, .none);
        try std.testing.expectEqual(if (e.admin == 'p') Decision.allow else Decision.unauthorized, anon);
        if (e.admin == 'g') try std.testing.expectEqual(Decision.allow, decide(r.perm, agent_auth));
    }
    // The matrix lists every declared route, and nothing twice.
    try std.testing.expectEqual(all.len, expected.len);
    for (all, 0..) |a, i| {
        for (all[i + 1 ..]) |b| {
            try std.testing.expect(!(a.method == b.method and std.mem.eql(u8, a.path, b.path)));
        }
    }
}

test "literal segments beat parameters" {
    var buf: [8][]const u8 = undefined;
    const r = lookup(.POST, split("/api/agents/enroll", &buf)).?;
    try std.testing.expectEqual(auth.Permission.public, r.perm);
    try std.testing.expect(lookup(.GET, split("/api/nope", &buf)) == null);
    try std.testing.expect(lookup(.PATCH, split("/api/users/x", &buf)) == null);
}
