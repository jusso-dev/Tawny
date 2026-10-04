const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");
const audit = @import("../http/audit.zig");
const exposure_import = @import("../detect/exposure_import.zig");

fn ruleResponseJson(allocator: std.mem.Allocator, cols: []const ?[]u8) ![]u8 {
    // id name format external_id description event_type severity operator payload_path match_value source_definition is_enabled mitre created updated
    const id = try util.escapeJson(allocator, cols[0] orelse "");
    defer allocator.free(id);
    const name = try util.escapeJson(allocator, cols[1] orelse "");
    defer allocator.free(name);
    const format = try util.escapeJson(allocator, cols[2] orelse "");
    defer allocator.free(format);
    const ext = try util.nullOrJsonString(allocator, cols[3]);
    defer allocator.free(ext);
    const desc = try util.nullOrJsonString(allocator, cols[4]);
    defer allocator.free(desc);
    const et = try util.nullOrJsonString(allocator, cols[5]);
    defer allocator.free(et);
    const sev = try util.escapeJson(allocator, cols[6] orelse "medium");
    defer allocator.free(sev);
    const op = try util.nullOrJsonString(allocator, cols[7]);
    defer allocator.free(op);
    const path = try util.nullOrJsonString(allocator, cols[8]);
    defer allocator.free(path);
    const mv = try util.nullOrJsonString(allocator, cols[9]);
    defer allocator.free(mv);
    const src = try util.nullOrJsonString(allocator, cols[10]);
    defer allocator.free(src);
    const en = if (cols[11]) |v| (if (std.mem.eql(u8, v, "t") or std.mem.eql(u8, v, "true")) "true" else "false") else "true";
    var mitre_json: []u8 = undefined;
    if (cols[12]) |raw| {
        const items = try util.parsePgTextArray(allocator, raw);
        defer {
            for (items) |it| allocator.free(it);
            allocator.free(items);
        }
        mitre_json = try util.jsonArrayStrings(allocator, items);
    } else {
        mitre_json = try allocator.dupe(u8, "[]");
    }
    defer allocator.free(mitre_json);
    const created = try util.escapeJson(allocator, cols[13] orelse "");
    defer allocator.free(created);
    const updated = try util.escapeJson(allocator, cols[14] orelse "");
    defer allocator.free(updated);
    return std.fmt.allocPrint(allocator,
        \\{{"id":{s},"name":{s},"format":{s},"external_id":{s},"description":{s},"event_type":{s},"severity":{s},"operator":{s},"payload_path":{s},"match_value":{s},"source_definition":{s},"is_enabled":{s},"mitre_techniques":{s},"created_at":{s},"updated_at":{s}}}
    , .{ id, name, format, ext, desc, et, sev, op, path, mv, src, en, mitre_json, created, updated });
}

const rule_select =
    \\SELECT id::text, name, format, external_id, description, event_type, severity, operator,
    \\       payload_path, match_value, source_definition, is_enabled::text, mitre_techniques::text,
    \\       created_at::text, updated_at::text
    \\FROM alert_rules
;

pub fn createPredicate(
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
    const body = try util.readBody(allocator, request, 64 * 1024);
    defer allocator.free(body);
    const Req = struct {
        name: []const u8,
        event_type: ?[]const u8 = null,
        severity: []const u8,
        operator: []const u8,
        payload_path: ?[]const u8 = null,
        match_value: ?[]const u8 = null,
        is_enabled: ?bool = true,
        mitre_techniques: ?[]const []const u8 = null,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "Invalid rule body.");
    };
    defer parsed.deinit();
    if (parsed.value.name.len == 0 or parsed.value.name.len > 160) {
        return util.problem(request, allocator, .bad_request, "Rule name is required and must be 160 characters or fewer.");
    }

    var id_buf: [36]u8 = undefined;
    const id = util.newUuid(io, &id_buf);
    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&tbuf, now);
    const mitre = try util.pgArrayText(allocator, parsed.value.mitre_techniques orelse &.{});
    defer allocator.free(mitre);
    const enabled = if (parsed.value.is_enabled orelse true) "true" else "false";

    try conn.execNoRows(
        \\INSERT INTO alert_rules (id, tenant_id, name, format, event_type, severity, operator, payload_path, match_value,
        \\  is_enabled, mitre_techniques, created_at, updated_at)
        \\VALUES ($1::uuid, $2::uuid, $3, 'tawny_predicate', $4, $5, $6, $7, $8, $9::boolean, $10::text[], $11::timestamptz, $11::timestamptz)
    , &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
        .{ .text = parsed.value.name },
        if (parsed.value.event_type) |e| .{ .text = e } else .{ .null = {} },
        .{ .text = parsed.value.severity },
        .{ .text = parsed.value.operator },
        if (parsed.value.payload_path) |p| .{ .text = p } else .{ .null = {} },
        if (parsed.value.match_value) |m| .{ .text = m } else .{ .null = {} },
        .{ .text = enabled },
        .{ .text = mitre },
        .{ .text = now_s },
    });
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "alert_rule.create", id, null);
    const rows = try conn.exec(allocator, rule_select ++ " WHERE id = $1::uuid", &.{.{ .text = id }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    const json = try ruleResponseJson(allocator, rows[0].cols);
    defer allocator.free(json);
    try util.respondJson(request, .created, json);
}

pub fn importSigma(
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
    const Req = struct { rule_yaml: []const u8, is_enabled: ?bool = true };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "rule_yaml required.");
    };
    defer parsed.deinit();

    var imported = importSigmaYaml(allocator, parsed.value.rule_yaml) catch |err| {
        const msg = switch (err) {
            error.UnsupportedModifierRe => "Unsupported Sigma field modifier 're'.",
            else => "Sigma rule could not be imported.",
        };
        return util.problem(request, allocator, .bad_request, msg);
    };
    defer imported.deinit(allocator);

    var id_buf: [36]u8 = undefined;
    const id = util.newUuid(io, &id_buf);
    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&tbuf, now);
    const enabled = if (parsed.value.is_enabled orelse true) "true" else "false";
    const mitre = try util.pgArrayText(allocator, imported.mitre.items);
    defer allocator.free(mitre);

    try conn.execNoRows(
        \\INSERT INTO alert_rules (id, tenant_id, name, format, external_id, description, event_type, severity, operator,
        \\  payload_path, match_value, source_definition, is_enabled, mitre_techniques, created_at, updated_at)
        \\VALUES ($1::uuid, $2::uuid, $3, 'sigma', $4, $5, $6, $7, $8, $9, $10, $11, $12::boolean, $13::text[], $14::timestamptz, $14::timestamptz)
    , &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
        .{ .text = imported.title },
        if (imported.external_id) |e| .{ .text = e } else .{ .null = {} },
        if (imported.description) |d| .{ .text = d } else .{ .null = {} },
        if (imported.event_type) |e| .{ .text = e } else .{ .null = {} },
        .{ .text = imported.severity },
        if (imported.operator) |o| .{ .text = o } else .{ .text = "exists" },
        if (imported.payload_path) |p| .{ .text = p } else .{ .null = {} },
        if (imported.match_value) |m| .{ .text = m } else .{ .null = {} },
        .{ .text = parsed.value.rule_yaml },
        .{ .text = enabled },
        .{ .text = mitre },
        .{ .text = now_s },
    });
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "alert_rule.import_sigma", id, null);
    const rows = try conn.exec(allocator, rule_select ++ " WHERE id = $1::uuid", &.{.{ .text = id }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    const json = try ruleResponseJson(allocator, rows[0].cols);
    defer allocator.free(json);
    try util.respondJson(request, .created, json);
}

const SigmaImported = struct {
    title: []u8,
    external_id: ?[]u8 = null,
    description: ?[]u8 = null,
    event_type: ?[]u8 = null,
    severity: []u8,
    operator: ?[]u8 = null,
    payload_path: ?[]u8 = null,
    match_value: ?[]u8 = null,
    mitre: std.ArrayList([]u8),

    fn deinit(self: *SigmaImported, allocator: std.mem.Allocator) void {
        allocator.free(self.title);
        if (self.external_id) |e| allocator.free(e);
        if (self.description) |d| allocator.free(d);
        if (self.event_type) |e| allocator.free(e);
        allocator.free(self.severity);
        if (self.operator) |o| allocator.free(o);
        if (self.payload_path) |p| allocator.free(p);
        if (self.match_value) |m| allocator.free(m);
        for (self.mitre.items) |m| allocator.free(m);
        self.mitre.deinit(allocator);
    }
};

pub fn importSigmaYaml(allocator: std.mem.Allocator, yaml: []const u8) !SigmaImported {
    if (std.mem.indexOf(u8, yaml, "|re:") != null or std.mem.indexOf(u8, yaml, "|re :") != null) {
        return error.UnsupportedModifierRe;
    }
    // Also catch `processes.name|re:`
    var line_it = std.mem.splitScalar(u8, yaml, '\n');
    while (line_it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t");
        if (std.mem.indexOf(u8, trimmed, "|re")) |idx| {
            const after = trimmed[idx + 3 ..];
            if (after.len == 0 or after[0] == ':' or after[0] == ' ') return error.UnsupportedModifierRe;
        }
    }

    var result: SigmaImported = .{
        .title = try allocator.dupe(u8, "untitled"),
        .severity = try allocator.dupe(u8, "medium"),
        .mitre = .empty,
    };
    errdefer result.deinit(allocator);

    var in_detection = false;
    var in_logsource = false;
    var in_tags = false;
    var selection_count: usize = 0;
    var condition_is_selection = false;

    line_it = std.mem.splitScalar(u8, yaml, '\n');
    while (line_it.next()) |raw_line| {
        const line = std.mem.trimEnd(u8, raw_line, "\r");
        if (line.len == 0) continue;
        const indent = blk: {
            var i: usize = 0;
            while (i < line.len and (line[i] == ' ' or line[i] == '\t')) : (i += 1) {}
            break :blk i;
        };
        const content = std.mem.trim(u8, line[indent..], " \t");

        if (indent == 0) {
            in_detection = false;
            in_logsource = false;
            in_tags = false;
            if (std.mem.startsWith(u8, content, "title:")) {
                allocator.free(result.title);
                result.title = try allocator.dupe(u8, trimScalar(content["title:".len..]));
            } else if (std.mem.startsWith(u8, content, "id:")) {
                result.external_id = try allocator.dupe(u8, trimScalar(content["id:".len..]));
            } else if (std.mem.startsWith(u8, content, "description:")) {
                result.description = try allocator.dupe(u8, trimScalar(content["description:".len..]));
            } else if (std.mem.startsWith(u8, content, "level:")) {
                allocator.free(result.severity);
                result.severity = try allocator.dupe(u8, mapSeverity(trimScalar(content["level:".len..])));
            } else if (std.mem.eql(u8, content, "detection:")) {
                in_detection = true;
            } else if (std.mem.eql(u8, content, "logsource:")) {
                in_logsource = true;
            } else if (std.mem.eql(u8, content, "tags:")) {
                in_tags = true;
            }
            continue;
        }

        if (in_tags and std.mem.startsWith(u8, content, "- ")) {
            const tag = trimScalar(content[2..]);
            if (std.ascii.startsWithIgnoreCase(tag, "attack.t")) {
                const id = tag[std.mem.indexOfScalar(u8, tag, '.').? + 1 ..];
                const upper = try allocator.dupe(u8, id);
                for (upper) |*c| c.* = std.ascii.toUpper(c.*);
                try result.mitre.append(allocator, upper);
            }
        }

        if (in_logsource) {
            if (std.mem.startsWith(u8, content, "category:") or std.mem.startsWith(u8, content, "product:") or std.mem.startsWith(u8, content, "service:")) {
                const val = trimScalar(content[std.mem.indexOfScalar(u8, content, ':').? + 1 ..]);
                if (std.ascii.findIgnoreCase(val, "process") != null) {
                    result.event_type = try allocator.dupe(u8, "process_snapshot");
                } else if (std.ascii.findIgnoreCase(val, "network") != null) {
                    result.event_type = try allocator.dupe(u8, "network_snapshot");
                } else if (std.ascii.findIgnoreCase(val, "file") != null or std.ascii.findIgnoreCase(val, "fim") != null) {
                    result.event_type = try allocator.dupe(u8, "file_integrity");
                }
            }
        }

        if (in_detection) {
            if (std.mem.startsWith(u8, content, "condition:")) {
                const cond = trimScalar(content["condition:".len..]);
                condition_is_selection = std.mem.eql(u8, cond, "selection");
            } else if (std.mem.indexOfScalar(u8, content, ':')) |colon| {
                const key = std.mem.trim(u8, content[0..colon], " \t");
                const val = trimScalar(content[colon + 1 ..]);
                if (std.mem.eql(u8, key, "condition")) continue;
                // Named selection header (`selection:`) — count selections, not fields.
                if (val.len == 0 and std.mem.indexOfScalar(u8, key, '|') == null) {
                    selection_count += 1;
                    continue;
                }
                if (std.mem.indexOfScalar(u8, key, '|')) |pipe| {
                    const field = key[0..pipe];
                    const mod = key[pipe + 1 ..];
                    if (std.mem.eql(u8, mod, "re")) return error.UnsupportedModifierRe;
                    const op = if (std.mem.eql(u8, mod, "contains")) "contains" else if (std.mem.eql(u8, mod, "exists")) "exists" else if (std.mem.eql(u8, mod, "gt")) "greater_than" else if (std.mem.eql(u8, mod, "lt")) "less_than" else "equals";
                    if (result.operator == null) result.operator = try allocator.dupe(u8, op);
                    if (result.payload_path == null) result.payload_path = try allocator.dupe(u8, normalizeField(field));
                    if (result.match_value == null and val.len > 0) result.match_value = try allocator.dupe(u8, val);
                } else if (indent > 2) {
                    if (result.operator == null) result.operator = try allocator.dupe(u8, "equals");
                    if (result.payload_path == null) result.payload_path = try allocator.dupe(u8, normalizeField(key));
                    if (result.match_value == null and val.len > 0) result.match_value = try allocator.dupe(u8, val);
                }
            }
        }
    }

    if (!condition_is_selection or selection_count != 1) {
        // Multi-selection: clear predicate fields
        if (result.operator) |o| {
            allocator.free(o);
            result.operator = null;
        }
        if (result.payload_path) |p| {
            allocator.free(p);
            result.payload_path = null;
        }
        if (result.match_value) |m| {
            allocator.free(m);
            result.match_value = null;
        }
    }
    if (result.event_type == null) {
        result.event_type = try allocator.dupe(u8, "process_snapshot");
    }
    return result;
}

fn trimScalar(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\"'");
}

fn mapSeverity(level: []const u8) []const u8 {
    if (std.ascii.eqlIgnoreCase(level, "critical")) return "critical";
    if (std.ascii.eqlIgnoreCase(level, "high")) return "high";
    if (std.ascii.eqlIgnoreCase(level, "medium")) return "medium";
    if (std.ascii.eqlIgnoreCase(level, "low")) return "low";
    if (std.ascii.eqlIgnoreCase(level, "informational")) return "low";
    return "medium";
}

fn normalizeField(field: []const u8) []const u8 {
    if (std.mem.eql(u8, field, "Image") or std.mem.eql(u8, field, "process.name") or std.mem.eql(u8, field, "process.executable"))
        return "processes.name";
    if (std.mem.eql(u8, field, "CommandLine") or std.mem.eql(u8, field, "process.command_line"))
        return "processes.command_line";
    return field;
}

pub fn updateRule(
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
    const body = try util.readBody(allocator, request, 64 * 1024);
    defer allocator.free(body);
    const Req = struct {
        name: []const u8,
        event_type: ?[]const u8 = null,
        severity: []const u8,
        operator: ?[]const u8 = null,
        payload_path: ?[]const u8 = null,
        match_value: ?[]const u8 = null,
        is_enabled: bool,
        mitre_techniques: ?[]const []const u8 = null,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "Invalid update body.");
    };
    defer parsed.deinit();

    const rows = try conn.exec(allocator, rule_select ++ " WHERE id = $1::uuid AND tenant_id = $2::uuid", &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
    });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return util.problem(request, allocator, .not_found, "Rule not found.");
    const format = rows[0].cols[2] orelse "tawny_predicate";
    if (!std.mem.eql(u8, format, "tawny_predicate")) {
        const cur_op = rows[0].cols[7];
        const cur_path = rows[0].cols[8];
        const cur_mv = rows[0].cols[9];
        const op_changed = !optionalEql(cur_op, parsed.value.operator);
        const path_changed = !optionalEql(cur_path, parsed.value.payload_path);
        const mv_changed = !optionalEql(cur_mv, parsed.value.match_value);
        if (op_changed or path_changed or mv_changed) {
            const title = try std.fmt.allocPrint(allocator, "{s} rules cannot have their match logic edited. Re-import the rule to change it.", .{format});
            defer allocator.free(title);
            return util.problem(request, allocator, .conflict, title);
        }
    }

    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&tbuf, now);
    const mitre = try util.pgArrayText(allocator, parsed.value.mitre_techniques orelse &.{});
    defer allocator.free(mitre);
    const enabled = if (parsed.value.is_enabled) "true" else "false";

    if (std.mem.eql(u8, format, "tawny_predicate")) {
        try conn.execNoRows(
            \\UPDATE alert_rules SET name=$3, event_type=$4, severity=$5, operator=$6, payload_path=$7, match_value=$8,
            \\  is_enabled=$9::boolean, mitre_techniques=$10::text[], updated_at=$11::timestamptz
            \\WHERE id=$1::uuid AND tenant_id=$2::uuid
        , &.{
            .{ .text = id },
            .{ .text = web.tenant_id },
            .{ .text = parsed.value.name },
            if (parsed.value.event_type) |e| .{ .text = e } else .{ .null = {} },
            .{ .text = parsed.value.severity },
            if (parsed.value.operator) |o| .{ .text = o } else .{ .null = {} },
            if (parsed.value.payload_path) |p| .{ .text = p } else .{ .null = {} },
            if (parsed.value.match_value) |m| .{ .text = m } else .{ .null = {} },
            .{ .text = enabled },
            .{ .text = mitre },
            .{ .text = now_s },
        });
    } else {
        try conn.execNoRows(
            \\UPDATE alert_rules SET name=$3, severity=$4, is_enabled=$5::boolean, mitre_techniques=$6::text[], updated_at=$7::timestamptz
            \\WHERE id=$1::uuid AND tenant_id=$2::uuid
        , &.{
            .{ .text = id },
            .{ .text = web.tenant_id },
            .{ .text = parsed.value.name },
            .{ .text = parsed.value.severity },
            .{ .text = enabled },
            .{ .text = mitre },
            .{ .text = now_s },
        });
    }
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "alert_rule.update", id, null);
    const updated = try conn.exec(allocator, rule_select ++ " WHERE id = $1::uuid", &.{.{ .text = id }});
    defer {
        for (updated) |row| row.deinit(allocator);
        allocator.free(updated);
    }
    const json = try ruleResponseJson(allocator, updated[0].cols);
    defer allocator.free(json);
    try util.respondJson(request, .ok, json);
}

fn optionalEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) {
        // JSON null vs missing DB null
        if (a == null and b != null and b.?.len == 0) return true;
        if (b == null and a != null and a.?.len == 0) return true;
        return false;
    }
    return std.mem.eql(u8, a.?, b.?);
}

pub fn deleteRule(
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
    _ = util.readBody(allocator, request, 1024) catch {};
    const refs = try conn.exec(allocator, "SELECT 1 FROM alerts WHERE alert_rule_id = $1::uuid AND tenant_id = $2::uuid LIMIT 1", &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
    });
    defer {
        for (refs) |row| row.deinit(allocator);
        allocator.free(refs);
    }
    if (refs.len > 0) {
        return util.problem(request, allocator, .conflict, "Alert rule has alerts and cannot be deleted. Disable it instead.");
    }
    try conn.execNoRows("DELETE FROM alert_rules WHERE id = $1::uuid AND tenant_id = $2::uuid", &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
    });
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "alert_rule.delete", id, null);
    try request.respond("", .{ .status = .no_content, .keep_alive = false });
}

pub fn importIocs(
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
    const body = try util.readBody(allocator, request, 1024 * 1024);
    defer allocator.free(body);
    const Req = struct {
        definition: []const u8,
        source_format: []const u8,
        severity: ?[]const u8 = null,
        is_enabled: ?bool = true,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "Invalid IoC body.");
    };
    defer parsed.deinit();
    const severity = parsed.value.severity orelse "high";
    const enabled = if (parsed.value.is_enabled orelse true) "true" else "false";

    var rules_json: std.ArrayList(u8) = .empty;
    defer rules_json.deinit(allocator);
    try rules_json.append(allocator, '[');
    var skipped_json: std.ArrayList(u8) = .empty;
    defer skipped_json.deinit(allocator);
    try skipped_json.append(allocator, '[');
    var rule_count: usize = 0;
    var skip_count: usize = 0;

    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&tbuf, now);

    const format = parsed.value.source_format;
    const trimmed_def = std.mem.trim(u8, parsed.value.definition, " \t\r\n");
    const as_stix = std.mem.eql(u8, format, "stix") or (std.mem.eql(u8, format, "auto") and trimmed_def.len > 0 and trimmed_def[0] == '{');
    const as_raw = std.mem.eql(u8, format, "raw") or (std.mem.eql(u8, format, "auto") and !as_stix);
    if (as_raw) {
        try parseRawIocs(allocator, io, conn, web, parsed.value.definition, severity, enabled, now_s, &rules_json, &skipped_json, &rule_count, &skip_count);
    } else if (as_stix) {
        try parseStixIocs(allocator, io, conn, web, parsed.value.definition, severity, enabled, now_s, &rules_json, &rule_count);
    } else {
        return util.problem(request, allocator, .bad_request, "Use source_format auto, stix, openioc, or raw.");
    }

    try rules_json.append(allocator, ']');
    try skipped_json.append(allocator, ']');
    if (rule_count == 0) {
        return util.problem(request, allocator, .bad_request, "No supported SHA-1, SHA-256, domain, IPv4, or IPv6 indicators were found.");
    }
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "alert_rule.import_iocs", null, null);
    const json = try std.fmt.allocPrint(allocator, "{{\"rules\":{s},\"skipped_indicators\":{s}}}", .{ rules_json.items, skipped_json.items });
    defer allocator.free(json);
    try util.respondJson(request, .created, json);
}

fn insertIocRule(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    web: auth.WebUser,
    name: []const u8,
    event_type: []const u8,
    severity: []const u8,
    operator: []const u8,
    path: []const u8,
    match_value: []const u8,
    enabled: []const u8,
    now_s: []const u8,
    rules_json: *std.ArrayList(u8),
    rule_count: *usize,
) !void {
    var id_buf: [36]u8 = undefined;
    const id = util.newUuid(io, &id_buf);
    try conn.execNoRows(
        \\INSERT INTO alert_rules (id, tenant_id, name, format, event_type, severity, operator, payload_path, match_value,
        \\  is_enabled, created_at, updated_at)
        \\VALUES ($1::uuid, $2::uuid, $3, 'ioc', $4, $5, $6, $7, $8, $9::boolean, $10::timestamptz, $10::timestamptz)
    , &.{
        .{ .text = id },
        .{ .text = web.tenant_id },
        .{ .text = name },
        .{ .text = event_type },
        .{ .text = severity },
        .{ .text = operator },
        .{ .text = path },
        .{ .text = match_value },
        .{ .text = enabled },
        .{ .text = now_s },
    });
    const rows = try conn.exec(allocator, rule_select ++ " WHERE id = $1::uuid", &.{.{ .text = id }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rule_count.* > 0) try rules_json.append(allocator, ',');
    const one = try ruleResponseJson(allocator, rows[0].cols);
    defer allocator.free(one);
    try rules_json.appendSlice(allocator, one);
    rule_count.* += 1;
}

fn parseRawIocs(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    web: auth.WebUser,
    definition: []const u8,
    severity: []const u8,
    enabled: []const u8,
    now_s: []const u8,
    rules_json: *std.ArrayList(u8),
    skipped_json: *std.ArrayList(u8),
    rule_count: *usize,
    skip_count: *usize,
) !void {
    var it = std.mem.tokenizeAny(u8, definition, " \t\r\n,;");
    while (it.next()) |tok| {
        const t = std.mem.trim(u8, tok, " \t\"'");
        if (t.len == 32 and isHex(t)) {
            // Could be MD5 — skip
            if (skip_count.* > 0) try skipped_json.append(allocator, ',');
            const msg = try std.fmt.allocPrint(allocator, "Skipped MD5 {s}; Tawny agents currently emit SHA-1 and SHA-256 file hashes.", .{t});
            defer allocator.free(msg);
            const esc = try util.escapeJson(allocator, msg);
            defer allocator.free(esc);
            try skipped_json.appendSlice(allocator, esc);
            skip_count.* += 1;
        } else if (t.len == 40 and isHex(t)) {
            const lower = try allocator.dupe(u8, t);
            defer allocator.free(lower);
            for (lower) |*c| c.* = std.ascii.toLower(c.*);
            const name = try std.fmt.allocPrint(allocator, "IoC SHA-1: {s}", .{lower});
            defer allocator.free(name);
            try insertIocRule(allocator, io, conn, web, name, "file_integrity", severity, "equals", "new_sha1", lower, enabled, now_s, rules_json, rule_count);
        } else if (t.len == 64 and isHex(t)) {
            const lower = try allocator.dupe(u8, t);
            defer allocator.free(lower);
            for (lower) |*c| c.* = std.ascii.toLower(c.*);
            const name = try std.fmt.allocPrint(allocator, "IoC SHA-256: {s}", .{lower});
            defer allocator.free(name);
            try insertIocRule(allocator, io, conn, web, name, "file_integrity", severity, "equals", "new_sha256", lower, enabled, now_s, rules_json, rule_count);
        }
    }
}

fn parseStixIocs(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    web: auth.WebUser,
    definition: []const u8,
    severity: []const u8,
    enabled: []const u8,
    now_s: []const u8,
    rules_json: *std.ArrayList(u8),
    rule_count: *usize,
) !void {
    // Extract patterns from STIX JSON text with simple scans
    var search_from: usize = 0;
    while (std.mem.indexOfPos(u8, definition, search_from, "ipv4-addr:value")) |idx| {
        if (extractQuotedAfter(definition, idx)) |ip| {
            const name = try std.fmt.allocPrint(allocator, "IoC IP: {s}", .{ip});
            defer allocator.free(name);
            try insertIocRule(allocator, io, conn, web, name, "network_snapshot", severity, "equals", "connections.remote_address", ip, enabled, now_s, rules_json, rule_count);
        }
        search_from = idx + 1;
    }
    search_from = 0;
    while (std.mem.indexOfPos(u8, definition, search_from, "domain-name:value")) |idx| {
        if (extractQuotedAfter(definition, idx)) |host| {
            const lower = try allocator.dupe(u8, host);
            defer allocator.free(lower);
            for (lower) |*c| c.* = std.ascii.toLower(c.*);
            const name = try std.fmt.allocPrint(allocator, "IoC domain: {s}", .{lower});
            defer allocator.free(name);
            try insertIocRule(allocator, io, conn, web, name, "process_snapshot", severity, "contains", "processes.command_line", lower, enabled, now_s, rules_json, rule_count);
            const dns_name = try std.fmt.allocPrint(allocator, "IoC domain: {s} (DNS)", .{lower});
            defer allocator.free(dns_name);
            try insertIocRule(allocator, io, conn, web, dns_name, "dns_query", severity, "equals", "qname", lower, enabled, now_s, rules_json, rule_count);
        }
        search_from = idx + 1;
    }
    search_from = 0;
    while (std.mem.indexOfPos(u8, definition, search_from, "SHA-256")) |idx| {
        if (extractQuotedAfter(definition, idx)) |hash| {
            if (hash.len == 64 and isHex(hash)) {
                const lower = try allocator.dupe(u8, hash);
                defer allocator.free(lower);
                for (lower) |*c| c.* = std.ascii.toLower(c.*);
                const name = try std.fmt.allocPrint(allocator, "IoC SHA-256: {s}", .{lower});
                defer allocator.free(name);
                try insertIocRule(allocator, io, conn, web, name, "file_integrity", severity, "equals", "new_sha256", lower, enabled, now_s, rules_json, rule_count);
            }
        }
        search_from = idx + 1;
    }
}

fn extractQuotedAfter(text: []const u8, from: usize) ?[]const u8 {
    const eq = std.mem.indexOfPos(u8, text, from, " = '") orelse std.mem.indexOfPos(u8, text, from, "='") orelse return null;
    var i = eq;
    while (i < text.len and text[i] != '\'') : (i += 1) {}
    if (i >= text.len) return null;
    const start = i + 1;
    const end = std.mem.indexOfScalarPos(u8, text, start, '\'') orelse return null;
    return text[start..end];
}

fn isHex(s: []const u8) bool {
    for (s) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
        if (!ok) return false;
    }
    return true;
}

pub fn listAlerts(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    target: []const u8,
) !void {
    _ = util.readBody(allocator, request, 1024) catch {};
    const limit_raw = util.queryParam(target, "limit") orelse "50";
    var limit = std.fmt.parseInt(i32, limit_raw, 10) catch 50;
    if (limit < 1) limit = 1;
    if (limit > 500) limit = 500;
    const lim = try std.fmt.allocPrint(allocator, "{d}", .{limit});
    defer allocator.free(lim);
    const after_id = util.queryParam(target, "after_id");
    const since = util.queryParam(target, "since");

    const rows = if (after_id != null or since != null) blk: {
        if (after_id) |aid| {
            break :blk try conn.exec(allocator,
                \\SELECT a.id::text, a.alert_rule_id::text, r.name, a.agent_id::text, ag.hostname,
                \\       a.severity, a.status, a.title, a.created_at::text, r.mitre_techniques::text,
                \\       ag.operating_system, ag.os_version
                \\FROM alerts a
                \\JOIN alert_rules r ON r.id = a.alert_rule_id
                \\JOIN agents ag ON ag.id = a.agent_id
                \\WHERE a.tenant_id = $1::uuid AND a.id > $2::bigint
                \\ORDER BY a.id ASC LIMIT $3::int
            , &.{ .{ .text = web.tenant_id }, .{ .text = aid }, .{ .text = lim } });
        } else {
            break :blk try conn.exec(allocator,
                \\SELECT a.id::text, a.alert_rule_id::text, r.name, a.agent_id::text, ag.hostname,
                \\       a.severity, a.status, a.title, a.created_at::text, r.mitre_techniques::text,
                \\       ag.operating_system, ag.os_version
                \\FROM alerts a
                \\JOIN alert_rules r ON r.id = a.alert_rule_id
                \\JOIN agents ag ON ag.id = a.agent_id
                \\WHERE a.tenant_id = $1::uuid AND a.created_at >= $2::timestamptz
                \\ORDER BY a.id ASC LIMIT $3::int
            , &.{ .{ .text = web.tenant_id }, .{ .text = since.? }, .{ .text = lim } });
        }
    } else try conn.exec(allocator,
        \\SELECT a.id::text, a.alert_rule_id::text, r.name, a.agent_id::text, ag.hostname,
        \\       a.severity, a.status, a.title, a.created_at::text, r.mitre_techniques::text,
        \\       ag.operating_system, ag.os_version
        \\FROM alerts a
        \\JOIN alert_rules r ON r.id = a.alert_rule_id
        \\JOIN agents ag ON ag.id = a.agent_id
        \\WHERE a.tenant_id = $1::uuid
        \\ORDER BY a.created_at DESC, a.id DESC LIMIT $2::int
    , &.{ .{ .text = web.tenant_id }, .{ .text = lim } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.append(allocator, '[');
    for (rows, 0..) |row, i| {
        if (i > 0) try out.append(allocator, ',');
        var mitre_json: []u8 = undefined;
        if (row.cols[9]) |raw| {
            const items = try util.parsePgTextArray(allocator, raw);
            defer {
                for (items) |it| allocator.free(it);
                allocator.free(items);
            }
            mitre_json = try util.jsonArrayStrings(allocator, items);
        } else mitre_json = try allocator.dupe(u8, "[]");
        defer allocator.free(mitre_json);
        const id_j = row.cols[0] orelse "0";
        const rid = try util.escapeJson(allocator, row.cols[1] orelse "");
        defer allocator.free(rid);
        const rname = try util.escapeJson(allocator, row.cols[2] orelse "");
        defer allocator.free(rname);
        const aid = try util.escapeJson(allocator, row.cols[3] orelse "");
        defer allocator.free(aid);
        const host = try util.escapeJson(allocator, row.cols[4] orelse "");
        defer allocator.free(host);
        const sev = try util.escapeJson(allocator, row.cols[5] orelse "");
        defer allocator.free(sev);
        const st = try util.escapeJson(allocator, row.cols[6] orelse "");
        defer allocator.free(st);
        const title = try util.escapeJson(allocator, row.cols[7] orelse "");
        defer allocator.free(title);
        const created = try util.escapeJson(allocator, row.cols[8] orelse "");
        defer allocator.free(created);
        const aos = try util.escapeJson(allocator, row.cols[10] orelse "");
        defer allocator.free(aos);
        const aosv = try util.escapeJson(allocator, row.cols[11] orelse "");
        defer allocator.free(aosv);
        {
            const __tmp = try std.fmt.allocPrint(allocator, 
            "{{\"id\":{s},\"alert_rule_id\":{s},\"rule_name\":{s},\"agent_id\":{s},\"hostname\":{s},\"severity\":{s},\"status\":{s},\"title\":{s},\"created_at\":{s},\"mitre_techniques\":{s},\"agent_os\":{s},\"agent_os_version\":{s}}}",
            .{ id_j, rid, rname, aid, host, sev, st, title, created, mitre_json, aos, aosv },
        );
            defer allocator.free(__tmp);
            try out.appendSlice(allocator, __tmp);
        }
    }
    try out.append(allocator, ']');
    try util.respondJson(request, .ok, out.items);
}

pub fn getAlert(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
    id: []const u8,
) !void {
    const rows = try conn.exec(allocator,
        \\SELECT a.id::text, a.alert_rule_id::text, r.name, a.agent_id::text, ag.hostname,
        \\       a.severity, a.status, a.title, a.created_at::text, r.mitre_techniques::text,
        \\       ag.operating_system, ag.os_version
        \\FROM alerts a
        \\JOIN alert_rules r ON r.id = a.alert_rule_id
        \\JOIN agents ag ON ag.id = a.agent_id
        \\WHERE a.tenant_id = $1::uuid AND a.id = $2::bigint LIMIT 1
    , &.{ .{ .text = web.tenant_id }, .{ .text = id } });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len == 0) return util.problem(request, allocator, .not_found, "Alert not found.");
    // Build one object by temporarily using listAlerts shape
    var mitre_json: []u8 = undefined;
    if (rows[0].cols[9]) |raw| {
        const items = try util.parsePgTextArray(allocator, raw);
        defer {
            for (items) |it| allocator.free(it);
            allocator.free(items);
        }
        mitre_json = try util.jsonArrayStrings(allocator, items);
    } else mitre_json = try allocator.dupe(u8, "[]");
    defer allocator.free(mitre_json);
    const row = rows[0].cols;
    const id_j = row[0] orelse "0";
    const rid = try util.escapeJson(allocator, row[1] orelse "");
    defer allocator.free(rid);
    const rname = try util.escapeJson(allocator, row[2] orelse "");
    defer allocator.free(rname);
    const aid = try util.escapeJson(allocator, row[3] orelse "");
    defer allocator.free(aid);
    const host = try util.escapeJson(allocator, row[4] orelse "");
    defer allocator.free(host);
    const sev = try util.escapeJson(allocator, row[5] orelse "");
    defer allocator.free(sev);
    const st = try util.escapeJson(allocator, row[6] orelse "");
    defer allocator.free(st);
    const title = try util.escapeJson(allocator, row[7] orelse "");
    defer allocator.free(title);
    const created = try util.escapeJson(allocator, row[8] orelse "");
    defer allocator.free(created);
    const aos = try util.escapeJson(allocator, row[10] orelse "");
    defer allocator.free(aos);
    const aosv = try util.escapeJson(allocator, row[11] orelse "");
    defer allocator.free(aosv);
    const json = try std.fmt.allocPrint(allocator,
        "{{\"id\":{s},\"alert_rule_id\":{s},\"rule_name\":{s},\"agent_id\":{s},\"hostname\":{s},\"severity\":{s},\"status\":{s},\"title\":{s},\"created_at\":{s},\"mitre_techniques\":{s},\"agent_os\":{s},\"agent_os_version\":{s}}}",
        .{ id_j, rid, rname, aid, host, sev, st, title, created, mitre_json, aos, aosv },
    );
    defer allocator.free(json);
    try util.respondJson(request, .ok, json);
}

pub fn listRules(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    const rows = try conn.exec(allocator, rule_select ++ " WHERE tenant_id = $1::uuid ORDER BY name", &.{.{ .text = web.tenant_id }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.append(allocator, '[');
    for (rows, 0..) |row, i| {
        if (i > 0) try out.append(allocator, ',');
        const item = try ruleResponseJson(allocator, row.cols);
        defer allocator.free(item);
        try out.appendSlice(allocator, item);
    }
    try out.append(allocator, ']');
    try util.respondJson(request, .ok, out.items);
}

pub fn importExposures(
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
    const body = try util.readBody(allocator, request, 1024 * 1024);
    defer allocator.free(body);
    const Req = struct {
        definition: []const u8,
        severity: ?[]const u8 = null,
        is_enabled: ?bool = null,
    };
    var parsed = std.json.parseFromSlice(Req, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return util.problem(request, allocator, .bad_request, "Definition is empty.");
    };
    defer parsed.deinit();
    const severity = parsed.value.severity orelse "high";
    if (!knownSeverity(severity)) return util.problem(request, allocator, .bad_request, "severity is invalid.");
    var outcome = exposure_import.compile(allocator, parsed.value.definition) catch |err| switch (err) {
        error.Empty => return util.problem(request, allocator, .bad_request, "Definition is empty."),
        error.BadJson => return util.problem(request, allocator, .bad_request, "Could not parse JSON: invalid JSON."),
        error.BadShape => return util.problem(request, allocator, .bad_request, "Definition must be a JSON object (OSV) or an array of {ecosystem, name, version_pattern}."),
        error.NoneCompiled => return util.problem(request, allocator, .bad_request, "No exposure rules could be compiled. Check ecosystem/name fields."),
        else => return err,
    };
    defer outcome.deinit(allocator);

    const enabled = if (parsed.value.is_enabled orelse true) "true" else "false";
    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const now_s = util.formatRfc3339(&tbuf, now);
    var ids: std.ArrayList([36]u8) = .empty;
    defer ids.deinit(allocator);
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};
    for (outcome.rules) |rule| {
        var id_buf: [36]u8 = undefined;
        const id = util.newUuid(io, &id_buf);
        try insertExposure(conn, web.tenant_id, id, rule, severity, enabled, now_s);
        try ids.append(allocator, id_buf);
    }
    var meta_buf: [96]u8 = undefined;
    const meta = std.fmt.bufPrint(&meta_buf, "{{\"count\":{d},\"skipped\":{d}}}", .{ outcome.rules.len, outcome.skipped.len }) catch "{}";
    try audit.add(allocator, io, conn, web.tenant_id, web.user_id, "alert_rule.import_exposures", null, meta);
    var rules_json: std.ArrayList(u8) = .empty;
    defer rules_json.deinit(allocator);
    try rules_json.append(allocator, '[');
    for (ids.items, 0..) |id, i| {
        if (i > 0) try rules_json.append(allocator, ',');
        const rows = try conn.exec(allocator, rule_select ++ " WHERE id = $1::uuid", &.{.{ .text = id[0..] }});
        defer {
            for (rows) |row| row.deinit(allocator);
            allocator.free(rows);
        }
        const item = try ruleResponseJson(allocator, rows[0].cols);
        defer allocator.free(item);
        try rules_json.appendSlice(allocator, item);
    }
    try rules_json.append(allocator, ']');
    const skipped_json = try util.jsonArrayStrings(allocator, outcome.skipped);
    defer allocator.free(skipped_json);
    const json = try std.fmt.allocPrint(allocator, "{{\"rules\":{s},\"skipped_entries\":{s}}}", .{ rules_json.items, skipped_json });
    defer allocator.free(json);
    try conn.execSimple("COMMIT");
    try util.respondJson(request, .created, json);
}

fn insertExposure(
    conn: *pg.Conn,
    tenant_id: []const u8,
    id: []const u8,
    rule: exposure_import.Rule,
    severity: []const u8,
    enabled: []const u8,
    now_s: []const u8,
) !void {
    try conn.execNoRows(
        \\INSERT INTO alert_rules (
        \\  id, tenant_id, name, format, external_id, description, event_type, severity, operator,
        \\  source_definition, is_enabled, mitre_techniques, created_at, updated_at)
        \\VALUES (
        \\  $1::uuid, $2::uuid, $3, 'package_exposure', $4, $5, $6, $7, 'exists',
        \\  $8, $9::boolean, '{}', $10::timestamptz, $10::timestamptz)
    , &.{
        .{ .text = id },
        .{ .text = tenant_id },
        .{ .text = rule.name },
        .{ .text = rule.external_id },
        .{ .text = rule.description },
        .{ .text = rule.event_type },
        .{ .text = severity },
        .{ .text = rule.source_definition },
        .{ .text = enabled },
        .{ .text = now_s },
    });
}

fn knownSeverity(value: []const u8) bool {
    return std.mem.eql(u8, value, "low") or std.mem.eql(u8, value, "medium") or std.mem.eql(u8, value, "high") or std.mem.eql(u8, value, "critical");
}

test "sigma rejects re modifier" {
    const allocator = std.testing.allocator;
    const yaml =
        \\title: bad
        \\detection:
        \\  selection:
        \\    processes.name|re: x
        \\  condition: selection
        \\level: high
    ;
    try std.testing.expectError(error.UnsupportedModifierRe, importSigmaYaml(allocator, yaml));
}

test "sigma contains process_creation" {
    const allocator = std.testing.allocator;
    const yaml =
        \\title: sus
        \\id: 11111111-1111-1111-1111-111111111111
        \\logsource:
        \\  product: windows
        \\  category: process_creation
        \\detection:
        \\  selection:
        \\    processes.name|contains: suspicious.exe
        \\  condition: selection
        \\level: high
    ;
    var imported = try importSigmaYaml(allocator, yaml);
    defer imported.deinit(allocator);
    try std.testing.expectEqualStrings("sus", imported.title);
    try std.testing.expectEqualStrings("process_snapshot", imported.event_type.?);
    try std.testing.expectEqualStrings("processes.name", imported.payload_path.?);
    try std.testing.expectEqualStrings("contains", imported.operator.?);
    try std.testing.expectEqualStrings("suspicious.exe", imported.match_value.?);
    try std.testing.expectEqualStrings("high", imported.severity);
}

test "exposure import persists a normalized npm rule" {
    const url = std.testing.environ.getPosix("TAWNY_DATABASE_URL") orelse return;
    if (url.len == 0) return;
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const conn = try pg.Conn.connect(allocator, io, url);
    defer {
        conn.close();
        allocator.destroy(conn);
    }
    var outcome = try exposure_import.compile(allocator, "[{\"ecosystem\":\"Node\",\"name\":\"left-pad\",\"version_pattern\":\"^1.2.3\"}]");
    defer outcome.deinit(allocator);
    try conn.execSimple("BEGIN");
    errdefer conn.execSimple("ROLLBACK") catch {};
    var id_buf: [36]u8 = undefined;
    const id = util.newUuid(io, &id_buf);
    try insertExposure(conn, util.default_tenant, id, outcome.rules[0], "high", "true", "2026-10-04T00:00:00Z");
    const rows = try conn.exec(allocator, "SELECT format, event_type, external_id, source_definition FROM alert_rules WHERE id = $1::uuid", &.{.{ .text = id }});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    try std.testing.expectEqualStrings("package_exposure", rows[0].cols[0].?);
    try std.testing.expectEqualStrings("package_inventory", rows[0].cols[1].?);
    try std.testing.expect(std.mem.startsWith(u8, rows[0].cols[2].?, "exposure:npm:left-pad:"));
    const matcher = @import("../detect/package_exposure.zig");
    try std.testing.expect(matcher.matches(allocator, rows[0].cols[3].?, "{\"ecosystem\":\"npm\",\"name\":\"left-pad\",\"version\":\"1.4.0\"}"));
    try std.testing.expect(!matcher.matches(allocator, rows[0].cols[3].?, "{\"ecosystem\":\"npm\",\"name\":\"left-pad\",\"version\":\"2.0.0\"}"));
    try conn.execSimple("ROLLBACK");
}
