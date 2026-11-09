//! GET /api/attack/coverage (docs/architecture/target-edr.md section 6).
//!
//! Three states per technique, each from its own source:
//!   telemetry  a healthy agent (seen in 15 minutes, no failed sensor) sent
//!              one of the technique's event types in the last 24 hours
//!   detection  an enabled rule in this tenant lists the technique
//!   response   an action in coverage.yaml applies on the platform
//! No state is read from another. A technique with a rule but no telemetry
//! shows detection true and telemetry false.
//!
//! Names and tactics: rules/attack/techniques.json (ATT&CK Enterprise 20.1
//! subset), embedded from server/src/detect/attack/ (a test checks the copy).
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");
const yaml = @import("../detect/yaml.zig");

/// Route permissions, enforced by http/permissions.zig before the handler runs.
pub const routes = [_]@import("../http/permissions.zig").Route{
    .{ .method = .GET, .path = "/api/attack/coverage", .perm = .read },
};

pub const coverage_yaml = @embedFile("../detect/attack/coverage.yaml");
pub const techniques_json = @embedFile("../detect/attack/techniques.json");

pub const Technique = struct {
    id: []const u8,
    name: []const u8,
    tactics: []const []const u8,
    platforms: []const []const u8,
};
pub const Tactic = struct { shortname: []const u8, name: []const u8, id: []const u8 };
pub const Catalog = struct {
    attack_version: []const u8,
    tactics: []const Tactic,
    techniques: []const Technique,
};

pub const Entry = struct {
    id: []const u8,
    telemetry: []const []const u8,
    response: []const []const u8,
};

pub const Map = struct {
    attack_version: []const u8,
    /// action name -> platforms
    actions: []const struct { name: []const u8, platforms: []const []const u8 },
    entries: []const Entry,
};

pub fn loadCatalog(arena: std.mem.Allocator) !Catalog {
    return std.json.parseFromSliceLeaky(Catalog, arena, techniques_json, .{ .ignore_unknown_fields = true });
}

fn strList(arena: std.mem.Allocator, node: ?yaml.Node) ![]const []const u8 {
    const n = node orelse return &.{};
    if (n != .list) return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (n.list) |item| {
        if (item.str()) |s| try out.append(arena, s);
    }
    return out.toOwnedSlice(arena);
}

pub fn loadMap(arena: std.mem.Allocator) !Map {
    const root = try yaml.parse(arena, coverage_yaml);
    const version = (root.get("attack_version") orelse return error.BadCoverage).str() orelse return error.BadCoverage;
    const ActionT = @typeInfo(@FieldType(Map, "actions")).pointer.child;
    var actions: std.ArrayList(ActionT) = .empty;
    if (root.get("actions")) |a| {
        if (a != .map) return error.BadCoverage;
        for (a.map) |e| try actions.append(arena, .{ .name = e.key, .platforms = try strList(arena, e.value) });
    }
    var entries: std.ArrayList(Entry) = .empty;
    const techs = root.get("techniques") orelse return error.BadCoverage;
    if (techs != .list) return error.BadCoverage;
    for (techs.list) |t| {
        const id = (t.get("id") orelse return error.BadCoverage).str() orelse return error.BadCoverage;
        try entries.append(arena, .{
            .id = id,
            .telemetry = try strList(arena, t.get("telemetry")),
            .response = try strList(arena, t.get("response")),
        });
    }
    return .{ .attack_version = version, .actions = try actions.toOwnedSlice(arena), .entries = try entries.toOwnedSlice(arena) };
}

fn contains(list: []const []const u8, s: []const u8) bool {
    for (list) |x| if (std.ascii.eqlIgnoreCase(x, s)) return true;
    return false;
}

/// Platform names in ATT&CK are "Windows", "Linux", "macOS"; agents report
/// "windows", "linux", "macos".
fn attackPlatform(p: []const u8) []const u8 {
    if (std.mem.eql(u8, p, "windows")) return "Windows";
    if (std.mem.eql(u8, p, "linux")) return "Linux";
    if (std.mem.eql(u8, p, "macos")) return "macOS";
    return p;
}

pub const State = struct {
    telemetry: bool,
    telemetry_sources: []const []const u8,
    detection: bool,
    rules: []const []const u8,
    response: bool,
    actions: []const []const u8,
};

/// Pure state computation, so the separation of the three states is testable
/// without a database. `seen_types` are event types from healthy agents on
/// the platform; `rule_techniques` are (rule name, technique) pairs.
pub fn computeState(
    arena: std.mem.Allocator,
    m: Map,
    entry: ?Entry,
    technique_id: []const u8,
    platform: ?[]const u8,
    seen_types: []const []const u8,
    rule_techniques: []const [2][]const u8,
) !State {
    var sources: std.ArrayList([]const u8) = .empty;
    var acts: std.ArrayList([]const u8) = .empty;
    var rules: std.ArrayList([]const u8) = .empty;
    if (entry) |e| {
        for (e.telemetry) |t| {
            if (contains(seen_types, t)) try sources.append(arena, t);
        }
        for (e.response) |a| {
            for (m.actions) |def| {
                if (!std.mem.eql(u8, def.name, a)) continue;
                if (platform == null or contains(def.platforms, platform.?)) try acts.append(arena, a);
            }
        }
    }
    for (rule_techniques) |rt| {
        // A rule tagged with a parent technique does not cover sub-techniques
        // and the other way round: exact id only.
        if (std.ascii.eqlIgnoreCase(rt[1], technique_id) and !contains(rules.items, rt[0])) try rules.append(arena, rt[0]);
    }
    return .{
        .telemetry = sources.items.len > 0,
        .telemetry_sources = sources.items,
        .detection = rules.items.len > 0,
        .rules = rules.items,
        .response = acts.items.len > 0,
        .actions = acts.items,
    };
}

fn freeRows(allocator: std.mem.Allocator, rows: []pg.Row) void {
    for (rows) |row| row.deinit(allocator);
    allocator.free(rows);
}

pub fn coverage(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    target: []const u8,
) !void {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const platform = util.queryParam(target, "platform");
    if (platform) |p| {
        if (util.parseOs(p) == null) return util.problem(request, allocator, .bad_request, "platform must be windows, linux or macos.");
    }
    const catalog = try loadCatalog(arena);
    const m = try loadMap(arena);

    // Telemetry: event types from healthy agents in the last 24 hours. An
    // agent is healthy when it heartbeated in 15 minutes and has no sensor
    // in a failed state.
    const seen_rows = try conn.exec(arena,
        \\SELECT DISTINCT te.event_type FROM telemetry_events te
        \\JOIN agents ag ON ag.id = te.agent_id
        \\WHERE te.tenant_id = $1::uuid AND te.received_at >= now() - interval '24 hours'
        \\  AND ag.revoked_at IS NULL AND ag.last_heartbeat_at >= now() - interval '15 minutes'
        \\  AND ($2::text IS NULL OR ag.operating_system = $2)
        \\  AND NOT EXISTS (
        \\    SELECT 1 FROM sensor_status ss WHERE ss.tenant_id = ag.tenant_id AND ss.agent_id = ag.id
        \\      AND ss.state IN ('failed', 'missing', 'access_denied')
        \\  )
    , &.{ .{ .text = web.tenant_id }, if (platform) |p| .{ .text = p } else .{ .null = {} } });
    var seen: std.ArrayList([]const u8) = .empty;
    for (seen_rows) |r| if (r.cols[0]) |t| try seen.append(arena, t);

    // Detection: enabled rules and their techniques. Platform does not
    // filter rules: most rules do not say which platform they run on.
    const rule_rows = try conn.exec(arena,
        \\SELECT r.name, upper(t) FROM alert_rules r, unnest(r.mitre_techniques) AS t
        \\WHERE r.tenant_id = $1::uuid AND r.is_enabled
    , &.{.{ .text = web.tenant_id }});
    var pairs: std.ArrayList([2][]const u8) = .empty;
    for (rule_rows) |r| {
        if (r.cols[0] != null and r.cols[1] != null) try pairs.append(arena, .{ r.cols[0].?, r.cols[1].? });
    }

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.appendSlice(allocator, "{\"attack_version\":");
    try util.appendEscaped(&out, allocator, catalog.attack_version);
    try out.appendSlice(allocator, ",\"platform\":");
    if (platform) |p| try util.appendEscaped(&out, allocator, p) else try out.appendSlice(allocator, "null");
    try out.appendSlice(allocator, ",\"tactics\":");
    try out.appendSlice(allocator, try std.json.Stringify.valueAlloc(arena, catalog.tactics, .{}));
    try out.appendSlice(allocator, ",\"techniques\":[");
    var n: usize = 0;
    for (catalog.techniques) |t| {
        if (platform) |p| {
            if (!contains(t.platforms, attackPlatform(p))) continue;
        }
        var entry: ?Entry = null;
        for (m.entries) |e| {
            if (std.mem.eql(u8, e.id, t.id)) entry = e;
        }
        const st = try computeState(arena, m, entry, t.id, platform, seen.items, pairs.items);
        if (n > 0) try out.append(allocator, ',');
        n += 1;
        const obj = .{
            .id = t.id,
            .name = t.name,
            .tactics = t.tactics,
            .mapped = entry != null,
            .telemetry = .{ .available = st.telemetry, .sources = st.telemetry_sources, .expected = if (entry) |e| e.telemetry else &[_][]const u8{} },
            .detection = .{ .available = st.detection, .rules = st.rules },
            .response = .{ .available = st.response, .actions = st.actions },
        };
        try out.appendSlice(allocator, try std.json.Stringify.valueAlloc(arena, obj, .{}));
    }
    try out.appendSlice(allocator, "]}");
    try util.respondJson(request, .ok, out.items);
}

test "coverage map and catalog agree with the pinned release" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const catalog = try loadCatalog(arena);
    const m = try loadMap(arena);
    try std.testing.expectEqualStrings("20.1", catalog.attack_version);
    try std.testing.expectEqualStrings(catalog.attack_version, m.attack_version);
    // Every mapped technique has a name, every action is defined, and every
    // telemetry source is a known event type.
    const event_types = [_][]const u8{
        "process_start",   "process_exit", "file_create",            "registry_set",  "network_connect", "dns_query",
        "user_logon",      "service_create", "powershell_script_block", "sensor_health", "agent_tamper",
    };
    for (m.entries) |e| {
        var found = false;
        for (catalog.techniques) |t| {
            if (std.mem.eql(u8, t.id, e.id)) found = true;
        }
        if (!found) {
            std.debug.print("coverage.yaml names {s}, not in techniques.json\n", .{e.id});
            return error.UnknownTechnique;
        }
        for (e.response) |a| {
            var def = false;
            for (m.actions) |d| {
                if (std.mem.eql(u8, d.name, a)) def = true;
            }
            try std.testing.expect(def);
        }
        for (e.telemetry) |t| try std.testing.expect(contains(&event_types, t));
    }
    var t1059: ?Technique = null;
    for (catalog.techniques) |t| {
        if (std.mem.eql(u8, t.id, "T1059.001")) t1059 = t;
    }
    try std.testing.expectEqualStrings("Command and Scripting Interpreter: PowerShell", t1059.?.name);
    try std.testing.expectEqualStrings("execution", t1059.?.tactics[0]);
}

test "the three states never follow from one another" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const m = try loadMap(arena);
    var entry: ?Entry = null;
    for (m.entries) |e| {
        if (std.mem.eql(u8, e.id, "T1059.001")) entry = e;
    }
    // A rule, no telemetry: detection only.
    const pairs = [_][2][]const u8{.{ "Encoded PowerShell", "T1059.001" }};
    const a = try computeState(arena, m, entry, "T1059.001", "windows", &.{}, &pairs);
    try std.testing.expect(a.detection and !a.telemetry);
    try std.testing.expect(a.response);
    // Telemetry, no rule.
    const b = try computeState(arena, m, entry, "T1059.001", "windows", &.{"process_start"}, &.{});
    try std.testing.expect(b.telemetry and !b.detection);
    // Response depends on platform alone: isolate_host is Windows only.
    var t1110: ?Entry = null;
    for (m.entries) |e| {
        if (std.mem.eql(u8, e.id, "T1110")) t1110 = e;
    }
    const c = try computeState(arena, m, t1110, "T1110", "linux", &.{"user_logon"}, &pairs);
    try std.testing.expect(c.telemetry and !c.detection and !c.response);
    // A rule on the parent technique is not detection for the sub-technique.
    const parent = [_][2][]const u8{.{ "Any interpreter", "T1059" }};
    const d = try computeState(arena, m, entry, "T1059.001", null, &.{}, &parent);
    try std.testing.expect(!d.detection);
    // Unmapped technique: telemetry and response unknown, so false.
    const e = try computeState(arena, m, null, "T1595", null, &.{"process_start"}, &.{});
    try std.testing.expect(!e.telemetry and !e.response and !e.detection);
}

test "embedded attack files match rules/attack" {
    const io = std.testing.io;
    const files = [_]struct { name: []const u8, embedded: []const u8 }{
        .{ .name = "../rules/attack/coverage.yaml", .embedded = coverage_yaml },
        .{ .name = "../rules/attack/techniques.json", .embedded = techniques_json },
    };
    for (files) |f| {
        const text = std.Io.Dir.cwd().readFileAlloc(io, f.name, std.testing.allocator, .limited(1 << 20)) catch |err| {
            if (err == error.FileNotFound) return; // not run from server/
            return err;
        };
        defer std.testing.allocator.free(text);
        try std.testing.expectEqualStrings(text, f.embedded);
    }
}
