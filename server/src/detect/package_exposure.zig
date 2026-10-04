//! Package exposure matcher. Same rules as PackageExposureEvaluator:
//! ecosystem and name are ordinal-ignore-case, a blank version pattern
//! matches any version, and comma-separated fragments are OR. `^` pins the
//! major only (`^0.2.3` matches `0.9.0`). `~` pins major.minor.
const std = @import("std");
const util = @import("../http/util.zig");

const Semver = struct { major: i32, minor: i32, patch: i32 };

const Definition = struct {
    ecosystem: []u8,
    name: []u8,
    version_pattern: ?[]u8,

    fn deinit(self: Definition, allocator: std.mem.Allocator) void {
        allocator.free(self.ecosystem);
        allocator.free(self.name);
        if (self.version_pattern) |pattern| allocator.free(pattern);
    }
};

/// False on a bad definition or a non-matching payload. Parse errors do not alert.
pub fn matches(allocator: std.mem.Allocator, definition_json: []const u8, payload_json: []const u8) bool {
    const def = parseDefinition(allocator, definition_json) catch return false;
    defer def.deinit(allocator);
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{}) catch return false;
    defer parsed.deinit();
    return evaluate(def, parsed.value);
}

pub fn versionMatches(pattern: []const u8, actual: []const u8) bool {
    if (isBlank(actual)) return false;
    var it = std.mem.splitScalar(u8, pattern, ',');
    while (it.next()) |raw| {
        const range = std.mem.trim(u8, raw, " \t\r\n");
        if (range.len == 0) continue;
        if (matchesSingle(range, actual)) return true;
    }
    return false;
}

/// Snake-case JSON, null optional fields included, matching System.Text.Json.
pub fn serializeDefinition(
    allocator: std.mem.Allocator,
    ecosystem: []const u8,
    name: []const u8,
    version_pattern: ?[]const u8,
    advisory_id: ?[]const u8,
    advisory_url: ?[]const u8,
) ![]u8 {
    const eco = try util.escapeJson(allocator, ecosystem);
    defer allocator.free(eco);
    const package_name = try util.escapeJson(allocator, name);
    defer allocator.free(package_name);
    const pattern = if (version_pattern) |value| try util.escapeJson(allocator, value) else null;
    defer if (pattern) |value| allocator.free(value);
    const advisory = if (advisory_id) |value| try util.escapeJson(allocator, value) else null;
    defer if (advisory) |value| allocator.free(value);
    const url = if (advisory_url) |value| try util.escapeJson(allocator, value) else null;
    defer if (url) |value| allocator.free(value);
    return std.fmt.allocPrint(allocator,
        \\{{"ecosystem":{s},"name":{s},"version_pattern":{s},"advisory_id":{s},"advisory_url":{s}}}
    , .{
        eco,
        package_name,
        pattern orelse "null",
        advisory orelse "null",
        url orelse "null",
    });
}

fn parseDefinition(allocator: std.mem.Allocator, json: []const u8) !Definition {
    if (isBlank(json)) return error.Empty;
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch return error.BadJson;
    defer parsed.deinit();
    const obj = switch (parsed.value) {
        .object => |value| value,
        else => return error.BadJson,
    };
    const ecosystem = switch (objectField(obj, "ecosystem") orelse return error.BadJson) {
        .string => |value| value,
        else => return error.BadJson,
    };
    const name = switch (objectField(obj, "name") orelse return error.BadJson) {
        .string => |value| value,
        else => return error.BadJson,
    };
    if (isBlank(ecosystem) or isBlank(name)) return error.BadJson;
    const ecosystem_copy = try allocator.dupe(u8, ecosystem);
    errdefer allocator.free(ecosystem_copy);
    const name_copy = try allocator.dupe(u8, name);
    errdefer allocator.free(name_copy);
    var pattern: ?[]u8 = null;
    if (objectField(obj, "version_pattern")) |value| {
        switch (value) {
            .null => {},
            .string => |text| {
                if (!isBlank(text)) pattern = try allocator.dupe(u8, text);
            },
            else => return error.BadJson,
        }
    }
    return .{
        .ecosystem = ecosystem_copy,
        .name = name_copy,
        .version_pattern = pattern,
    };
}

fn evaluate(def: Definition, payload: std.json.Value) bool {
    const obj = switch (payload) {
        .object => |value| value,
        else => return false,
    };
    const ecosystem = switch (obj.get("ecosystem") orelse return false) {
        .string => |value| value,
        else => return false,
    };
    if (!std.ascii.eqlIgnoreCase(ecosystem, def.ecosystem)) return false;
    const name = switch (obj.get("name") orelse return false) {
        .string => |value| value,
        else => return false,
    };
    if (!std.ascii.eqlIgnoreCase(name, def.name)) return false;
    const pattern = def.version_pattern orelse return true;
    const version = switch (obj.get("version") orelse return false) {
        .string => |value| value,
        else => return false,
    };
    return versionMatches(pattern, version);
}

fn matchesSingle(range: []const u8, actual: []const u8) bool {
    if (std.mem.eql(u8, range, "*")) return true;
    if (std.mem.startsWith(u8, range, ">=")) return compareVersion(actual, trim(range[2..])) >= 0;
    if (std.mem.startsWith(u8, range, "<=")) return compareVersion(actual, trim(range[2..])) <= 0;
    if (std.mem.startsWith(u8, range, ">")) return compareVersion(actual, trim(range[1..])) > 0;
    if (std.mem.startsWith(u8, range, "<")) return compareVersion(actual, trim(range[1..])) < 0;
    if (std.mem.startsWith(u8, range, "=")) return std.ascii.eqlIgnoreCase(trim(range[1..]), actual);
    if (std.mem.startsWith(u8, range, "^")) {
        const anchor = parseSemver(trim(range[1..])) orelse return false;
        const current = parseSemver(actual) orelse return false;
        if (current.major != anchor.major) return false;
        return compareSemver(current, anchor) >= 0;
    }
    if (std.mem.startsWith(u8, range, "~")) {
        const anchor = parseSemver(trim(range[1..])) orelse return false;
        const current = parseSemver(actual) orelse return false;
        if (current.major != anchor.major or current.minor != anchor.minor) return false;
        return compareSemver(current, anchor) >= 0;
    }
    return std.ascii.eqlIgnoreCase(range, actual);
}

fn compareVersion(a: []const u8, b: []const u8) i32 {
    if (parseSemver(a)) |left| {
        if (parseSemver(b)) |right| return compareSemver(left, right);
    }
    return orderToInt(std.ascii.orderIgnoreCase(a, b));
}

fn parseSemver(raw: []const u8) ?Semver {
    var stripped = raw;
    while (stripped.len > 0 and (stripped[0] == 'v' or stripped[0] == 'V')) stripped = stripped[1..];
    if (std.mem.indexOfAny(u8, stripped, "-+")) |cut| stripped = stripped[0..cut];
    if (stripped.len == 0) return null;
    var parts = std.mem.splitScalar(u8, stripped, '.');
    const major = parseI32(parts.next() orelse return null) orelse return null;
    var minor: i32 = 0;
    var patch: i32 = 0;
    if (parts.next()) |part| minor = parseI32(part) orelse 0;
    if (parts.next()) |part| patch = parseI32(part) orelse 0;
    return .{ .major = major, .minor = minor, .patch = patch };
}

fn parseI32(raw: []const u8) ?i32 {
    const text = std.mem.trim(u8, raw, " \t\r\n");
    if (text.len == 0) return null;
    return std.fmt.parseInt(i32, text, 10) catch null;
}

fn compareSemver(a: Semver, b: Semver) i32 {
    if (a.major != b.major) return orderToInt(std.math.order(a.major, b.major));
    if (a.minor != b.minor) return orderToInt(std.math.order(a.minor, b.minor));
    return orderToInt(std.math.order(a.patch, b.patch));
}

fn orderToInt(order: std.math.Order) i32 {
    return switch (order) {
        .lt => -1,
        .eq => 0,
        .gt => 1,
    };
}

fn objectField(obj: std.json.ObjectMap, name: []const u8) ?std.json.Value {
    var it = obj.iterator();
    while (it.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, name)) return entry.value_ptr.*;
    }
    return null;
}

fn trim(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t\r\n");
}

fn isBlank(value: []const u8) bool {
    if (value.len == 0) return true;
    for (value) |c| {
        if (c != ' ' and c != '\t' and c != '\r' and c != '\n' and c != 0x0b and c != 0x0c) return false;
    }
    return true;
}

test "package exposure version patterns match the dotnet caret rules" {
    const cases = [_]struct { pattern: []const u8, actual: []const u8, want: bool }{
        .{ .pattern = "^1.2.3", .actual = "1.9.0", .want = true },
        .{ .pattern = "^1.2.3", .actual = "1.2.3", .want = true },
        .{ .pattern = "^1.2.3", .actual = "1.2.2", .want = false },
        .{ .pattern = "^1.2.3", .actual = "2.0.0", .want = false },
        .{ .pattern = "^1.2.3", .actual = "v1.9.0", .want = true },
        .{ .pattern = "^0.2.3", .actual = "0.9.0", .want = true },
        .{ .pattern = "^1.x.3", .actual = "1.5.0", .want = true },
        .{ .pattern = "^1.2.3", .actual = "not-a-version", .want = false },
        .{ .pattern = "~1.2.3", .actual = "1.2.9", .want = true },
        .{ .pattern = "~1.2.3", .actual = "1.3.0", .want = false },
        .{ .pattern = "~1.2.3", .actual = "1.2.2", .want = false },
        .{ .pattern = ">=1.2.0,<2.0.0", .actual = "0.1.0", .want = true },
        .{ .pattern = ">=1.2.0,<2.0.0", .actual = "9.0.0", .want = true },
        .{ .pattern = "*", .actual = "anything", .want = true },
        .{ .pattern = "=1.2.3", .actual = "1.2.3", .want = true },
        .{ .pattern = "=1.2.3", .actual = "v1.2.3", .want = false },
        .{ .pattern = "1.2.3", .actual = "1.2.3", .want = true },
        .{ .pattern = "1.2.3", .actual = "V1.2.3", .want = false },
        .{ .pattern = ">=v1.2.0", .actual = "1.2.0", .want = true },
        .{ .pattern = ">=1.2.3-alpha", .actual = "1.2.3", .want = true },
        .{ .pattern = ">1.0.0", .actual = "1.0.1", .want = true },
        .{ .pattern = "<=1.0.0", .actual = "1.0.0", .want = true },
        .{ .pattern = "<1.0.0", .actual = "0.9.0", .want = true },
        .{ .pattern = "<2.0.0", .actual = "2.0.0", .want = false },
        .{ .pattern = "1.0.0,2.0.0", .actual = "2.0.0", .want = true },
        .{ .pattern = "abc", .actual = "ABC", .want = true },
        .{ .pattern = ">=abc", .actual = "ABC", .want = true },
        .{ .pattern = "1.0.0", .actual = "   ", .want = false },
        .{ .pattern = ",", .actual = "1.0.0", .want = false },
    };
    for (cases) |case| {
        try std.testing.expectEqual(case.want, versionMatches(case.pattern, case.actual));
    }

    const allocator = std.testing.allocator;
    try std.testing.expect(matches(allocator,
        \\{"ecosystem":"NPM","name":"Left-Pad","version_pattern":"^1.2.3"}
    ,
        \\{"ecosystem":"npm","name":"left-pad","version":"1.9.0"}
    ));
    try std.testing.expect(!matches(allocator,
        \\{"ecosystem":"npm","name":"left-pad","version_pattern":"^1.2.3"}
    ,
        \\{"ecosystem":"npm","name":"left-pad"}
    ));
    try std.testing.expect(matches(allocator,
        \\{"ecosystem":"npm","name":"left-pad","version_pattern":"  "}
    ,
        \\{"ecosystem":"npm","name":"left-pad"}
    ));
    try std.testing.expect(!matches(allocator,
        \\{"ecosystem":"npm","name":"left-pad","version_pattern":"1.0.0"}
    ,
        \\{"ecosystem":"npm","name":"left-pad","version":1}
    ));
    try std.testing.expect(!matches(allocator, " ",
        \\{"ecosystem":"npm","name":"left-pad","version":"1.0.0"}
    ));
    try std.testing.expect(!matches(allocator, "{",
        \\{"ecosystem":"npm","name":"left-pad","version":"1.0.0"}
    ));
    const stored = try serializeDefinition(allocator, "npm", "left-pad", "^1.2.3", "GHSA-test", null);
    defer allocator.free(stored);
    try std.testing.expect(matches(allocator, stored,
        \\{"ecosystem":"npm","name":"left-pad","version":"1.4.0"}
    ));
}
