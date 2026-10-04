//! HTTP package-exposure import. Same rules as ExposureRuleImporter:
//! OSV objects and `[{ecosystem, name, version_pattern}]` lists, ecosystem
//! aliases (node → npm), max 1,000 rules. Threat-intel feeds stay on
//! `feeds.parseOsv`, which only lowercases and does not apply these aliases.
const std = @import("std");
const package_exposure = @import("package_exposure.zig");

pub const max_rules: usize = 1000;

pub const Rule = struct {
    name: []u8,
    external_id: []u8,
    description: []u8,
    event_type: []u8,
    source_definition: []u8,

    pub fn deinit(self: Rule, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.external_id);
        allocator.free(self.description);
        allocator.free(self.event_type);
        allocator.free(self.source_definition);
    }
};

pub const Outcome = struct {
    rules: []Rule,
    skipped: [][]u8,

    pub fn deinit(self: *Outcome, allocator: std.mem.Allocator) void {
        for (self.rules) |rule| rule.deinit(allocator);
        allocator.free(self.rules);
        for (self.skipped) |entry| allocator.free(entry);
        allocator.free(self.skipped);
    }
};

pub fn compile(allocator: std.mem.Allocator, definition: []const u8) !Outcome {
    if (isBlank(definition)) return error.Empty;
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, definition, .{}) catch return error.BadJson;
    defer parsed.deinit();

    var rules: std.ArrayList(Rule) = .empty;
    errdefer {
        for (rules.items) |rule| rule.deinit(allocator);
        rules.deinit(allocator);
    }
    var skipped: std.ArrayList([]u8) = .empty;
    errdefer {
        for (skipped.items) |entry| allocator.free(entry);
        skipped.deinit(allocator);
    }

    switch (parsed.value) {
        .array => |entries| {
            for (entries.items) |entry| {
                if (rules.items.len >= max_rules) {
                    try skipped.append(allocator, try allocator.dupe(u8, "Stopped at the import limit of 1000 rules."));
                    break;
                }
                if (try compileSimple(allocator, entry)) |rule| {
                    try rules.append(allocator, rule);
                } else {
                    try skipped.append(allocator, try fingerprint(allocator, entry));
                }
            }
        },
        .object => |obj| {
            if (obj.get("advisories")) |bundle| {
                if (bundle == .array) {
                    for (bundle.array.items) |advisory| try appendOsv(allocator, advisory, &rules, &skipped);
                } else {
                    try appendOsv(allocator, parsed.value, &rules, &skipped);
                }
            } else {
                try appendOsv(allocator, parsed.value, &rules, &skipped);
            }
        },
        else => return error.BadShape,
    }

    if (rules.items.len == 0) return error.NoneCompiled;
    const owned_rules = try rules.toOwnedSlice(allocator);
    const owned_skipped = skipped.toOwnedSlice(allocator) catch |err| {
        for (owned_rules) |rule| rule.deinit(allocator);
        allocator.free(owned_rules);
        return err;
    };
    return .{ .rules = owned_rules, .skipped = owned_skipped };
}

fn appendOsv(
    allocator: std.mem.Allocator,
    advisory: std.json.Value,
    rules: *std.ArrayList(Rule),
    skipped: *std.ArrayList([]u8),
) !void {
    if (rules.items.len >= max_rules) return;
    const obj = switch (advisory) {
        .object => |value| value,
        else => {
            try skipped.append(allocator, try allocator.dupe(u8, "<no id>"));
            return;
        },
    };
    const advisory_id = jsonString(obj, "id");
    const summary = jsonString(obj, "summary");
    const advisory_url = firstUrl(obj);
    const affected = obj.get("affected") orelse {
        try skipped.append(allocator, try allocator.dupe(u8, labelOr(advisory_id, "<no id>")));
        return;
    };
    if (affected != .array) {
        try skipped.append(allocator, try allocator.dupe(u8, labelOr(advisory_id, "<no id>")));
        return;
    }
    for (affected.array.items) |item| {
        if (rules.items.len >= max_rules) return;
        const affected_obj = switch (item) {
            .object => |value| value,
            else => continue,
        };
        const package = affected_obj.get("package") orelse continue;
        const package_obj = switch (package) {
            .object => |value| value,
            else => continue,
        };
        const ecosystem = jsonString(package_obj, "ecosystem") orelse continue;
        const package_name = jsonString(package_obj, "name") orelse continue;
        if (isBlank(ecosystem) or isBlank(package_name)) continue;
        const ecosystem_norm = try normalizeEcosystem(allocator, ecosystem);
        defer allocator.free(ecosystem_norm);
        const pattern = try buildOsvPattern(allocator, affected_obj);
        defer if (pattern) |value| allocator.free(value);
        try rules.append(allocator, try buildRule(
            allocator,
            ecosystem_norm,
            package_name,
            pattern,
            advisory_id,
            advisory_url,
            summary,
        ));
    }
}

fn compileSimple(allocator: std.mem.Allocator, entry: std.json.Value) !?Rule {
    const obj = switch (entry) {
        .object => |value| value,
        else => return null,
    };
    const ecosystem = jsonString(obj, "ecosystem") orelse return null;
    const package_name = jsonString(obj, "name") orelse return null;
    if (isBlank(ecosystem) or isBlank(package_name)) return null;
    const ecosystem_norm = try normalizeEcosystem(allocator, ecosystem);
    defer allocator.free(ecosystem_norm);
    const pattern = jsonString(obj, "version_pattern");
    const advisory_id = jsonString(obj, "advisory_id");
    const advisory_url = jsonString(obj, "advisory_url");
    return try buildRule(allocator, ecosystem_norm, package_name, pattern, advisory_id, advisory_url, null);
}

fn buildRule(
    allocator: std.mem.Allocator,
    ecosystem: []const u8,
    name: []const u8,
    version_pattern: ?[]const u8,
    advisory_id: ?[]const u8,
    advisory_url: ?[]const u8,
    summary: ?[]const u8,
) !Rule {
    const display = version_pattern orelse "any";
    const stored_pattern: ?[]const u8 = if (version_pattern) |value| (if (isBlank(value)) null else value) else null;
    const rule_name = try std.fmt.allocPrint(allocator, "Exposed {s}/{s} {s}", .{ ecosystem, name, display });
    errdefer allocator.free(rule_name);
    var external = try std.fmt.allocPrint(allocator, "exposure:{s}:{s}:{s}", .{ ecosystem, name, display });
    errdefer allocator.free(external);
    if (advisory_id) |id| {
        if (id.len > 0) {
            const with_id = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ external, id });
            allocator.free(external);
            external = with_id;
        }
    }
    if (external.len > 128) {
        const cut = try allocator.dupe(u8, external[0..128]);
        allocator.free(external);
        external = cut;
    }
    const description = if (summary) |text|
        try allocator.dupe(u8, text)
    else
        try std.fmt.allocPrint(allocator, "Installed package {s}/{s} matches version pattern {s}.", .{ ecosystem, name, display });
    errdefer allocator.free(description);
    const event_type = try allocator.dupe(u8, exposureEventType(ecosystem));
    errdefer allocator.free(event_type);
    const source = try package_exposure.serializeDefinition(allocator, ecosystem, name, stored_pattern, advisory_id, advisory_url);
    return .{
        .name = rule_name,
        .external_id = external,
        .description = description,
        .event_type = event_type,
        .source_definition = source,
    };
}

fn exposureEventType(ecosystem: []const u8) []const u8 {
    if (std.mem.eql(u8, ecosystem, "editor-extension") or std.mem.eql(u8, ecosystem, "editor_extension")) return "editor_extension";
    if (std.mem.eql(u8, ecosystem, "browser-extension") or std.mem.eql(u8, ecosystem, "browser_extension")) return "browser_extension";
    if (std.mem.eql(u8, ecosystem, "mcp") or std.mem.eql(u8, ecosystem, "mcp_server") or std.mem.eql(u8, ecosystem, "mcp-server")) return "mcp_config";
    return "package_inventory";
}

fn normalizeEcosystem(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    const lower = try toLower(allocator, trimmed);
    const canon = canonicalEcosystem(lower);
    if (!std.mem.eql(u8, canon, lower)) {
        allocator.free(lower);
        return allocator.dupe(u8, canon);
    }
    return lower;
}

fn canonicalEcosystem(lower: []const u8) []const u8 {
    if (std.mem.eql(u8, lower, "go") or std.mem.eql(u8, lower, "go modules")) return "go";
    if (std.mem.eql(u8, lower, "npm") or std.mem.eql(u8, lower, "node")) return "npm";
    if (std.mem.eql(u8, lower, "pypi") or std.mem.eql(u8, lower, "python")) return "pypi";
    if (std.mem.eql(u8, lower, "rubygems") or std.mem.eql(u8, lower, "gem")) return "rubygems";
    if (std.mem.eql(u8, lower, "packagist") or std.mem.eql(u8, lower, "composer")) return "packagist";
    if (std.mem.eql(u8, lower, "crates.io") or std.mem.eql(u8, lower, "rust")) return "crates.io";
    if (std.mem.eql(u8, lower, "maven") or std.mem.eql(u8, lower, "java")) return "maven";
    if (std.mem.eql(u8, lower, "nuget") or std.mem.eql(u8, lower, ".net")) return "nuget";
    return lower;
}

fn buildOsvPattern(allocator: std.mem.Allocator, affected: std.json.ObjectMap) !?[]u8 {
    if (affected.get("versions")) |versions| {
        if (versions == .array) {
            var joined: std.ArrayList(u8) = .empty;
            errdefer joined.deinit(allocator);
            var any = false;
            for (versions.array.items) |version| {
                if (version != .string or isBlank(version.string)) continue;
                if (any) try joined.append(allocator, ',');
                try joined.appendSlice(allocator, version.string);
                any = true;
            }
            if (any) return try joined.toOwnedSlice(allocator);
            joined.deinit(allocator);
        }
    }
    const ranges = affected.get("ranges") orelse return null;
    if (ranges != .array) return null;
    var parts: std.ArrayList([]const u8) = .empty;
    defer {
        for (parts.items) |part| allocator.free(part);
        parts.deinit(allocator);
    }
    for (ranges.array.items) |range| {
        const range_obj = switch (range) {
            .object => |value| value,
            else => continue,
        };
        const events = range_obj.get("events") orelse continue;
        if (events != .array) continue;
        var introduced: ?[]const u8 = null;
        var fixed_at: ?[]const u8 = null;
        for (events.array.items) |event| {
            const event_obj = switch (event) {
                .object => |value| value,
                else => continue,
            };
            if (jsonString(event_obj, "introduced")) |value| introduced = value;
            if (jsonString(event_obj, "fixed")) |value| fixed_at = value;
        }
        if (introduced) |value| {
            if (!std.mem.eql(u8, value, "0")) {
                const fragment = try std.fmt.allocPrint(allocator, ">={s}", .{value});
                errdefer allocator.free(fragment);
                try parts.append(allocator, fragment);
            }
        }
        if (fixed_at) |value| {
            const fragment = try std.fmt.allocPrint(allocator, "<{s}", .{value});
            errdefer allocator.free(fragment);
            try parts.append(allocator, fragment);
        }
    }
    if (parts.items.len == 0) return null;
    return try std.mem.join(allocator, ",", parts.items);
}

fn firstUrl(advisory: std.json.ObjectMap) ?[]const u8 {
    const refs = advisory.get("references") orelse return null;
    if (refs != .array) return null;
    for (refs.array.items) |item| {
        const obj = switch (item) {
            .object => |value| value,
            else => continue,
        };
        if (jsonString(obj, "url")) |url| return url;
    }
    return null;
}

fn fingerprint(allocator: std.mem.Allocator, entry: std.json.Value) ![]u8 {
    const obj = switch (entry) {
        .object => |value| value,
        else => return allocator.dupe(u8, "?/?"),
    };
    const ecosystem = jsonString(obj, "ecosystem") orelse "?";
    const name = jsonString(obj, "name") orelse "?";
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ ecosystem, name });
}

fn jsonString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = obj.get(key) orelse return null;
    return switch (value) {
        .string => |text| text,
        else => null,
    };
}

fn labelOr(value: ?[]const u8, fallback: []const u8) []const u8 {
    const text = value orelse return fallback;
    if (isBlank(text)) return fallback;
    return text;
}

fn toLower(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, value.len);
    for (value, 0..) |c, i| out[i] = std.ascii.toLower(c);
    return out;
}

fn isBlank(value: []const u8) bool {
    return std.mem.trim(u8, value, " \t\r\n").len == 0;
}

test "exposure import normalizes node and prefers versions" {
    const allocator = std.testing.allocator;
    const body =
        \\{"id":"GHSA-example","summary":"bad left-pad","affected":[
        \\  {"package":{"ecosystem":"Node","name":"Left-Pad"},"versions":["1.0.0","",1],"ranges":[{"events":[{"introduced":"9.0.0"}]}]},
        \\  {"package":{"ecosystem":" Python ","name":"req"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]},
        \\  {"package":{"ecosystem":"editor-extension","name":"evil.ext"},"versions":["0.5.7"]}
        \\],"references":[{"url":"https://example.com/advisory"}]}
    ;
    var outcome = try compile(allocator, body);
    defer outcome.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), outcome.rules.len);
    try std.testing.expectEqualStrings("Exposed npm/Left-Pad 1.0.0", outcome.rules[0].name);
    try std.testing.expectEqualStrings("package_inventory", outcome.rules[0].event_type);
    try std.testing.expect(std.mem.indexOf(u8, outcome.rules[0].source_definition, "\"ecosystem\":\"npm\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.rules[0].source_definition, "\"version_pattern\":\"1.0.0\"") != null);
    try std.testing.expect(std.mem.endsWith(u8, outcome.rules[0].external_id, ":GHSA-example"));
    try std.testing.expectEqualStrings("bad left-pad", outcome.rules[0].description);
    try std.testing.expect(std.mem.startsWith(u8, outcome.rules[1].external_id, "exposure:pypi:req:"));
    try std.testing.expect(std.mem.indexOf(u8, outcome.rules[1].source_definition, "\"ecosystem\":\"pypi\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, outcome.rules[1].source_definition, "\"version_pattern\":\"<2.0.0\"") != null);
    try std.testing.expectEqualStrings("editor_extension", outcome.rules[2].event_type);
    try std.testing.expect(package_exposure.matches(allocator, outcome.rules[0].source_definition, "{\"ecosystem\":\"NPM\",\"name\":\"left-pad\",\"version\":\"1.0.0\"}"));
}

test "exposure import simple list skips blank rows and aliases go modules" {
    const allocator = std.testing.allocator;
    const body =
        \\[{"ecosystem":"Go Modules","name":"mod","version_pattern":">=1.2.0"},{"ecosystem":"","name":"x"},{"no":"fields"}]
    ;
    var outcome = try compile(allocator, body);
    defer outcome.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), outcome.rules.len);
    try std.testing.expect(std.mem.indexOf(u8, outcome.rules[0].source_definition, "\"ecosystem\":\"go\"") != null);
    try std.testing.expectEqualStrings("Installed package go/mod matches version pattern >=1.2.0.", outcome.rules[0].description);
    try std.testing.expectEqual(@as(usize, 2), outcome.skipped.len);
    try std.testing.expectEqualStrings("/x", outcome.skipped[0]);
    try std.testing.expectEqualStrings("?/?", outcome.skipped[1]);
}

test "exposure import rejects empty, bad json, and empty compiles" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.Empty, compile(allocator, "  "));
    try std.testing.expectError(error.BadJson, compile(allocator, "{"));
    try std.testing.expectError(error.BadShape, compile(allocator, "42"));
    try std.testing.expectError(error.NoneCompiled, compile(allocator, "{\"id\":\"GHSA-none\"}"));
}
