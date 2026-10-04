//! Threat-intel feed parsers. Generic CSV matches ThreatIntelFetcher:
//! sha256, sha1, ipv4, domain. URLs become the host. MD5 and junk are skipped.
//! At most 5,000 unique indicators are kept. OSV records become package
//! exposures. Ecosystem is lowercased only; `Node` stays `node`. Versions
//! win over ranges. There is no 5,000 cap on exposures.
const std = @import("std");

pub const max_indicators: usize = 5_000;

pub const Indicator = struct {
    kind: []u8,
    value: []u8,
    description: []u8,

    pub fn deinit(self: Indicator, allocator: std.mem.Allocator) void {
        allocator.free(self.kind);
        allocator.free(self.value);
        allocator.free(self.description);
    }
};

pub const ParseResult = struct {
    indicators: []Indicator,
    skipped: usize,

    pub fn deinit(self: *ParseResult, allocator: std.mem.Allocator) void {
        for (self.indicators) |ind| ind.deinit(allocator);
        allocator.free(self.indicators);
    }
};

pub fn parseGenericCsv(allocator: std.mem.Allocator, body: []const u8) !ParseResult {
    var found: std.ArrayList(Indicator) = .empty;
    errdefer {
        for (found.items) |ind| ind.deinit(allocator);
        found.deinit(allocator);
    }
    var lines = std.mem.splitScalar(u8, body, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var cols = std.mem.splitScalar(u8, line, ',');
        while (cols.next()) |col| {
            const cell = std.mem.trim(u8, col, " \t");
            if (try normalize(allocator, cell)) |ind| {
                try found.append(allocator, ind);
                break;
            }
        }
    }
    return takeBudget(allocator, &found);
}

fn takeBudget(allocator: std.mem.Allocator, found: *std.ArrayList(Indicator)) !ParseResult {
    var seen: std.StringHashMap(void) = .init(allocator);
    defer {
        var it = seen.keyIterator();
        while (it.next()) |key| allocator.free(key.*);
        seen.deinit();
    }
    var taken: std.ArrayList(Indicator) = .empty;
    errdefer {
        for (taken.items) |ind| ind.deinit(allocator);
        taken.deinit(allocator);
    }
    var skipped: usize = 0;
    var i: usize = 0;
    while (i < found.items.len) : (i += 1) {
        const ind = found.items[i];
        const key = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ ind.kind, ind.value });
        const lower = try toLower(allocator, key);
        allocator.free(key);
        if (seen.contains(lower)) {
            allocator.free(lower);
            ind.deinit(allocator);
            continue;
        }
        try seen.put(lower, {});
        if (taken.items.len >= max_indicators) {
            skipped += 1;
            ind.deinit(allocator);
            continue;
        }
        try taken.append(allocator, ind);
    }
    const indicators = try taken.toOwnedSlice(allocator);
    found.deinit(allocator);
    return .{ .indicators = indicators, .skipped = skipped };
}

fn normalize(allocator: std.mem.Allocator, raw: []const u8) !?Indicator {
    const value = std.mem.trim(u8, std.mem.trim(u8, raw, " \t"), "\"");
    if (value.len == 0) return null;
    if (isHex(value, 64)) {
        const lower = try toLower(allocator, value);
        return try indicator(allocator, "sha256", lower, "Generic CSV");
    }
    if (isHex(value, 40)) {
        const lower = try toLower(allocator, value);
        return try indicator(allocator, "sha1", lower, "Generic CSV");
    }
    if (try formatV4(allocator, value)) |ip| {
        return try indicator(allocator, "ipv4", ip, "Generic CSV");
    }
    if (try fromUrl(allocator, value)) |ind| return ind;
    if (isDomain(value)) {
        const lower = try toLower(allocator, value);
        return try indicator(allocator, "domain", lower, "Generic CSV");
    }
    return null;
}

fn fromUrl(allocator: std.mem.Allocator, raw: []const u8) !?Indicator {
    const uri = std.Uri.parse(raw) catch return null;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "http") and !std.ascii.eqlIgnoreCase(uri.scheme, "https")) return null;
    var host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
    const host = std.Io.net.HostName.fromUri(uri, &host_buf) catch return null;
    const desc = try std.fmt.allocPrint(allocator, "Generic CSV URL: {s}", .{raw});
    errdefer allocator.free(desc);
    if (try formatV4(allocator, host.bytes)) |ip| {
        return try owned(allocator, "ipv4", ip, desc);
    }
    if (!isDomain(host.bytes)) {
        allocator.free(desc);
        return null;
    }
    const lower = try toLower(allocator, host.bytes);
    return try owned(allocator, "domain", lower, desc);
}

fn indicator(allocator: std.mem.Allocator, kind: []const u8, value: []u8, desc: []const u8) !Indicator {
    errdefer allocator.free(value);
    const description = try allocator.dupe(u8, desc);
    return owned(allocator, kind, value, description);
}

fn owned(allocator: std.mem.Allocator, kind: []const u8, value: []u8, description: []u8) !Indicator {
    const kind_copy = try allocator.dupe(u8, kind);
    return .{ .kind = kind_copy, .value = value, .description = description };
}

fn formatV4(allocator: std.mem.Allocator, value: []const u8) !?[]u8 {
    const ip = std.Io.net.Ip4Address.parse(value, 0) catch return null;
    return try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
        ip.bytes[0], ip.bytes[1], ip.bytes[2], ip.bytes[3],
    });
}

fn isHex(value: []const u8, n: usize) bool {
    if (value.len != n) return false;
    for (value) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}

fn isDomain(value: []const u8) bool {
    if (value.len < 4 or value.len > 253) return false;
    var labels: usize = 0;
    var start: usize = 0;
    var i: usize = 0;
    while (i <= value.len) : (i += 1) {
        if (i == value.len or value[i] == '.') {
            const label = value[start..i];
            if (label.len == 0 or label.len > 63) return false;
            if (!std.ascii.isAlphanumeric(label[0]) or !std.ascii.isAlphanumeric(label[label.len - 1])) return false;
            for (label) |c| {
                if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
            }
            labels += 1;
            if (i == value.len) {
                if (label.len < 2 or label.len > 63) return false;
                for (label) |c| if (!std.ascii.isAlphabetic(c)) return false;
            }
            start = i + 1;
        }
    }
    return labels >= 2;
}

fn toLower(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, value.len);
    for (value, 0..) |c, i| out[i] = std.ascii.toLower(c);
    return out;
}

test "generic csv normalizes public feed shapes" {
    const allocator = std.testing.allocator;
    const body =
        \\# public threat feed
        \\https://Login.Example.test/phish?id=42
        \\observed,203.0.113.7,scanner
        \\0123456789ABCDEF0123456789ABCDEF01234567
        \\not-an-indicator
        \\
    ;
    var parsed = try parseGenericCsv(allocator, body);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), parsed.indicators.len);
    try std.testing.expectEqualStrings("domain", parsed.indicators[0].kind);
    try std.testing.expectEqualStrings("login.example.test", parsed.indicators[0].value);
    try std.testing.expectEqualStrings("Generic CSV URL: https://Login.Example.test/phish?id=42", parsed.indicators[0].description);
    try std.testing.expectEqualStrings("ipv4", parsed.indicators[1].kind);
    try std.testing.expectEqualStrings("203.0.113.7", parsed.indicators[1].value);
    try std.testing.expectEqualStrings("sha1", parsed.indicators[2].kind);
    try std.testing.expectEqualStrings("0123456789abcdef0123456789abcdef01234567", parsed.indicators[2].value);
    try std.testing.expectEqual(@as(usize, 0), parsed.skipped);
}

pub const Exposure = struct {
    ecosystem: []u8,
    name: []u8,
    version_pattern: ?[]u8 = null,
    advisory_id: ?[]u8 = null,
    advisory_url: ?[]u8 = null,
    summary: ?[]u8 = null,

    pub fn deinit(self: Exposure, allocator: std.mem.Allocator) void {
        allocator.free(self.ecosystem);
        allocator.free(self.name);
        if (self.version_pattern) |value| allocator.free(value);
        if (self.advisory_id) |value| allocator.free(value);
        if (self.advisory_url) |value| allocator.free(value);
        if (self.summary) |value| allocator.free(value);
    }
};

pub const OsvResult = struct {
    exposures: []Exposure,

    pub fn deinit(self: *OsvResult, allocator: std.mem.Allocator) void {
        for (self.exposures) |exposure| exposure.deinit(allocator);
        allocator.free(self.exposures);
    }
};

pub fn parseOsv(allocator: std.mem.Allocator, body: []const u8) !OsvResult {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.OsvParseFailed;
    defer parsed.deinit();
    var out: std.ArrayList(Exposure) = .empty;
    errdefer {
        for (out.items) |exposure| exposure.deinit(allocator);
        out.deinit(allocator);
    }
    switch (parsed.value) {
        .array => |entries| {
            for (entries.items) |entry| try appendOsvRecord(allocator, entry, &out);
        },
        .object => |obj| {
            if (obj.get("advisories")) |bundle| {
                if (bundle == .array) {
                    for (bundle.array.items) |entry| try appendOsvRecord(allocator, entry, &out);
                } else {
                    try appendOsvRecord(allocator, parsed.value, &out);
                }
            } else {
                try appendOsvRecord(allocator, parsed.value, &out);
            }
        },
        else => {},
    }
    return .{ .exposures = try out.toOwnedSlice(allocator) };
}

fn appendOsvRecord(allocator: std.mem.Allocator, advisory: std.json.Value, out: *std.ArrayList(Exposure)) !void {
    const obj = switch (advisory) {
        .object => |value| value,
        else => return,
    };
    const advisory_id = jsonString(obj, "id");
    const summary = jsonString(obj, "summary");
    const advisory_url = firstOsvUrl(obj);
    const affected = obj.get("affected") orelse return;
    if (affected != .array) return;
    for (affected.array.items) |item| {
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
        const pattern = try buildOsvPattern(allocator, affected_obj);
        errdefer if (pattern) |value| allocator.free(value);
        const ecosystem_lower = try toLower(allocator, ecosystem);
        errdefer allocator.free(ecosystem_lower);
        const name_copy = try allocator.dupe(u8, package_name);
        errdefer allocator.free(name_copy);
        const id_copy = try dupeOpt(allocator, advisory_id);
        errdefer if (id_copy) |value| allocator.free(value);
        const url_copy = try dupeOpt(allocator, advisory_url);
        errdefer if (url_copy) |value| allocator.free(value);
        const summary_copy = try dupeOpt(allocator, summary);
        errdefer if (summary_copy) |value| allocator.free(value);
        try out.append(allocator, .{
            .ecosystem = ecosystem_lower,
            .name = name_copy,
            .version_pattern = pattern,
            .advisory_id = id_copy,
            .advisory_url = url_copy,
            .summary = summary_copy,
        });
    }
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
            joined = .empty;
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

fn firstOsvUrl(advisory: std.json.ObjectMap) ?[]const u8 {
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

fn jsonString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = obj.get(key) orelse return null;
    return switch (value) {
        .string => |text| text,
        else => null,
    };
}

fn dupeOpt(allocator: std.mem.Allocator, value: ?[]const u8) !?[]u8 {
    const text = value orelse return null;
    return try allocator.dupe(u8, text);
}

fn isBlank(value: []const u8) bool {
    if (value.len == 0) return true;
    for (value) |c| {
        if (c != ' ' and c != '\t' and c != '\r' and c != '\n') return false;
    }
    return true;
}

test "osv package records lower the ecosystem and prefer versions" {
    const allocator = std.testing.allocator;
    const body =
        \\{"advisories":[{
        \\  "id":"GHSA-test","summary":"bad left-pad",
        \\  "references":[{"url":"https://example.test/adv"}],
        \\  "affected":[
        \\    {"package":{"ecosystem":"NPM","name":"Left-Pad"},"versions":["1.0.0","  ",1],"ranges":[{"events":[{"introduced":"9.0.0"}]}]},
        \\    {"package":{"ecosystem":"PyPI","name":"leftpad"},"ranges":[{"events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]},
        \\    {"package":{"ecosystem":"Node","name":"left-pad"},"versions":["0.0.1"]}
        \\  ]
        \\}]}
    ;
    var parsed = try parseOsv(allocator, body);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), parsed.exposures.len);
    try std.testing.expectEqualStrings("npm", parsed.exposures[0].ecosystem);
    try std.testing.expectEqualStrings("Left-Pad", parsed.exposures[0].name);
    try std.testing.expectEqualStrings("1.0.0", parsed.exposures[0].version_pattern.?);
    try std.testing.expectEqualStrings("GHSA-test", parsed.exposures[0].advisory_id.?);
    try std.testing.expectEqualStrings("https://example.test/adv", parsed.exposures[0].advisory_url.?);
    try std.testing.expectEqualStrings("pypi", parsed.exposures[1].ecosystem);
    try std.testing.expectEqualStrings("<2.0.0", parsed.exposures[1].version_pattern.?);
    try std.testing.expectEqualStrings("node", parsed.exposures[2].ecosystem);
    try std.testing.expectError(error.OsvParseFailed, parseOsv(allocator, "{"));
    var empty = try parseOsv(allocator, "{\"advisories\":[]}");
    defer empty.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), empty.exposures.len);
}

test "generic csv keeps 5000 unique indicators" {
    const allocator = std.testing.allocator;
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    var i: usize = 1;
    while (i <= 5001) : (i += 1) {
        const line = try std.fmt.allocPrint(allocator, "203.0.{d}.{d}\n", .{ (i >> 8) & 255, i & 255 });
        defer allocator.free(line);
        try body.appendSlice(allocator, line);
    }
    try body.appendSlice(allocator, "203.0.0.1\n");
    try body.appendSlice(allocator, "d41d8cd98f00b204e9800998ecf8427e\n");
    var parsed = try parseGenericCsv(allocator, body.items);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(max_indicators, parsed.indicators.len);
    try std.testing.expectEqual(@as(usize, 1), parsed.skipped);
    try std.testing.expectEqualStrings("203.0.0.1", parsed.indicators[0].value);
    try std.testing.expectEqualStrings("203.0.19.136", parsed.indicators[max_indicators - 1].value);
}
