const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const json_ct: std.http.Header = .{ .name = "content-type", .value = "application/json" };

pub fn nowUnix(io: std.Io) i64 {
    return @intCast(std.Io.Clock.now(.real, io).toSeconds());
}

pub fn twoDigits(n: u8) [2]u8 {
    return .{ '0' + n / 10, '0' + n % 10 };
}

/// RFC3339 UTC without fractional seconds. Avoids `{d:0>2}` (prints '+').
pub fn formatRfc3339(buf: *[32]u8, unix_s: i64) []const u8 {
    const day = @divFloor(unix_s, 86400);
    const sod: u32 = @intCast(@mod(unix_s, 86400));
    var y: i32 = 0;
    var m: i32 = 0;
    var d: i32 = 0;
    civilFromDays(day, &y, &m, &d);
    const hh: u8 = @intCast(sod / 3600);
    const mm: u8 = @intCast((sod % 3600) / 60);
    const ss: u8 = @intCast(sod % 60);
    const mo = twoDigits(@intCast(m));
    const da = twoDigits(@intCast(d));
    const hb = twoDigits(hh);
    const mb = twoDigits(mm);
    const sb = twoDigits(ss);
    const year: u32 = @intCast(y);
    buf[0] = '0' + @as(u8, @intCast((year / 1000) % 10));
    buf[1] = '0' + @as(u8, @intCast((year / 100) % 10));
    buf[2] = '0' + @as(u8, @intCast((year / 10) % 10));
    buf[3] = '0' + @as(u8, @intCast(year % 10));
    buf[4] = '-';
    buf[5] = mo[0];
    buf[6] = mo[1];
    buf[7] = '-';
    buf[8] = da[0];
    buf[9] = da[1];
    buf[10] = 'T';
    buf[11] = hb[0];
    buf[12] = hb[1];
    buf[13] = ':';
    buf[14] = mb[0];
    buf[15] = mb[1];
    buf[16] = ':';
    buf[17] = sb[0];
    buf[18] = sb[1];
    buf[19] = 'Z';
    return buf[0..20];
}

fn civilFromDays(unix_day: i64, year_out: *i32, month_out: *i32, day_out: *i32) void {
    const z = unix_day + 719468;
    const era = if (z >= 0) @divFloor(z, 146097) else @divFloor(z - 146096, 146097);
    const doe: u32 = @intCast(z - era * 146097);
    const yoe: u32 = @intCast(@divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365));
    const y: i32 = @intCast(yoe);
    var year = y + @as(i32, @intCast(era)) * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp: u32 = @intCast(@divFloor(5 * doy + 2, 153));
    const day: i32 = @intCast(doy - @divFloor(153 * mp + 2, 5) + 1);
    const month: i32 = if (mp < 10) @as(i32, @intCast(mp)) + 3 else @as(i32, @intCast(mp)) - 9;
    if (month <= 2) year += 1;
    year_out.* = year;
    month_out.* = month;
    day_out.* = day;
}

const hex_digits = "0123456789abcdef";

pub fn hexEncode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, data.len * 2);
    for (data, 0..) |b, i| {
        out[i * 2] = hex_digits[b >> 4];
        out[i * 2 + 1] = hex_digits[b & 0xf];
    }
    return out;
}

pub fn sha256Hex(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var dig: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &dig, .{});
    return hexEncode(allocator, &dig);
}

pub fn sha256HexBuf(data: []const u8, out: *[64]u8) void {
    var dig: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &dig, .{});
    for (dig, 0..) |b, i| {
        out[i * 2] = hex_digits[b >> 4];
        out[i * 2 + 1] = hex_digits[b & 0xf];
    }
}

pub fn randomHex(io: std.Io, allocator: std.mem.Allocator, nbytes: usize) ![]u8 {
    const raw = try allocator.alloc(u8, nbytes);
    defer allocator.free(raw);
    io.random(raw);
    return hexEncode(allocator, raw);
}

pub fn newUuid(io: std.Io, buf: *[36]u8) []const u8 {
    var b: [16]u8 = undefined;
    io.random(&b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const hex = "0123456789abcdef";
    var i: usize = 0;
    var o: usize = 0;
    while (i < 16) : (i += 1) {
        if (o == 8 or o == 13 or o == 18 or o == 23) {
            buf[o] = '-';
            o += 1;
        }
        buf[o] = hex[b[i] >> 4];
        buf[o + 1] = hex[b[i] & 0xf];
        o += 2;
    }
    return buf[0..36];
}

pub fn escapeJson(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, '"');
    for (text) |c| {
        switch (c) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => {
                if (c < 0x20) {
                    var tmp: [6]u8 = undefined;
                    const s = try std.fmt.bufPrint(&tmp, "\\u{x:0>4}", .{c});
                    // Avoid format that prints '+': write manually
                    _ = s;
                    try out.appendSlice(allocator, "\\u00");
                    const hex = "0123456789abcdef";
                    try out.append(allocator, hex[c >> 4]);
                    try out.append(allocator, hex[c & 0xf]);
                } else {
                    try out.append(allocator, c);
                }
            },
        }
    }
    try out.append(allocator, '"');
    return out.toOwnedSlice(allocator);
}

pub fn appendEscaped(list: *std.ArrayList(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    const esc = try escapeJson(allocator, text);
    defer allocator.free(esc);
    try list.appendSlice(allocator, esc);
}

pub fn respondJson(request: *std.http.Server.Request, status: std.http.Status, body: []const u8) !void {
    try request.respond(body, .{
        .status = status,
        .extra_headers = &.{json_ct},
        .keep_alive = false,
    });
}

pub fn respondJsonHeaders(
    request: *std.http.Server.Request,
    status: std.http.Status,
    body: []const u8,
    extra: []const std.http.Header,
) !void {
    var headers: [8]std.http.Header = undefined;
    headers[0] = json_ct;
    const n = @min(extra.len, headers.len - 1);
    @memcpy(headers[1..][0..n], extra[0..n]);
    try request.respond(body, .{
        .status = status,
        .extra_headers = headers[0 .. 1 + n],
        .keep_alive = false,
    });
}

pub fn problem(request: *std.http.Server.Request, allocator: std.mem.Allocator, status: std.http.Status, title: []const u8) !void {
    const code: u16 = @intFromEnum(status);
    const esc = try escapeJson(allocator, title);
    defer allocator.free(esc);
    const body = try std.fmt.allocPrint(allocator, "{{\"title\":{s},\"status\":{d}}}", .{ esc, code });
    defer allocator.free(body);
    try respondJson(request, status, body);
}

pub fn readBody(allocator: std.mem.Allocator, request: *std.http.Server.Request, max: usize) ![]u8 {
    request.head.expect = null;
    var transfer: [4096]u8 = undefined;
    const r = request.readerExpectNone(&transfer);
    return r.allocRemaining(allocator, .limited(max)) catch |err| switch (err) {
        error.StreamTooLong => return error.BodyTooLarge,
        else => return err,
    };
}

pub fn headerValue(request: *std.http.Server.Request, name: []const u8) ?[]const u8 {
    var it = request.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

pub fn pathOnly(target: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, target, '?')) |q| return target[0..q];
    return target;
}

pub fn queryParam(target: []const u8, key: []const u8) ?[]const u8 {
    const q = std.mem.indexOfScalar(u8, target, '?') orelse return null;
    var rest = target[q + 1 ..];
    while (rest.len > 0) {
        const amp = std.mem.indexOfScalar(u8, rest, '&');
        const pair = if (amp) |a| rest[0..a] else rest;
        rest = if (amp) |a| rest[a + 1 ..] else "";
        if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
            if (std.mem.eql(u8, pair[0..eq], key)) return pair[eq + 1 ..];
        } else if (std.mem.eql(u8, pair, key)) {
            return "";
        }
    }
    return null;
}

pub fn parseOs(os: []const u8) ?[]const u8 {
    if (std.ascii.eqlIgnoreCase(os, "windows")) return "windows";
    if (std.ascii.eqlIgnoreCase(os, "macos")) return "macos";
    if (std.ascii.eqlIgnoreCase(os, "linux")) return "linux";
    return null;
}

pub fn parseArch(arch: []const u8) ?[]const u8 {
    if (std.ascii.eqlIgnoreCase(arch, "x64") or std.ascii.eqlIgnoreCase(arch, "amd64") or std.ascii.eqlIgnoreCase(arch, "x86_64"))
        return "x64";
    if (std.ascii.eqlIgnoreCase(arch, "arm64") or std.ascii.eqlIgnoreCase(arch, "aarch64"))
        return "arm64";
    return null;
}

pub fn hasControlChars(s: []const u8) bool {
    for (s) |c| if (c < 0x20 or c == 0x7f) return true;
    return false;
}

pub fn eqIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

pub fn containsIgnoreCase(hay: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (hay.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(hay[i .. i + needle.len], needle)) return true;
    }
    return false;
}

/// Simple contains match: search whole payload text, or value at dotted path if present as string.
pub fn payloadContains(payload_json: []const u8, path: ?[]const u8, match_value: []const u8) bool {
    if (match_value.len == 0) return false;
    if (path) |p| {
        if (p.len > 0 and pathContains(payload_json, p, match_value)) return true;
    }
    return containsIgnoreCase(payload_json, match_value);
}

/// Compare before the parse tree is freed. A returned slice would dangle.
fn pathContains(json: []const u8, path: []const u8, needle: []const u8) bool {
    var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, json, .{}) catch return false;
    defer parsed.deinit();
    var cur = parsed.value;
    var rest = path;
    while (rest.len > 0) {
        const dot = std.mem.indexOfScalar(u8, rest, '.');
        const key = if (dot) |d| rest[0..d] else rest;
        rest = if (dot) |d| rest[d + 1 ..] else "";
        switch (cur) {
            .object => |obj| {
                cur = obj.get(key) orelse return false;
            },
            else => return false,
        }
    }
    return switch (cur) {
        .string => |s| containsIgnoreCase(s, needle),
        else => false,
    };
}

pub fn pgArrayText(allocator: std.mem.Allocator, items: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, '{');
    for (items, 0..) |it, i| {
        if (i > 0) try out.append(allocator, ',');
        try out.append(allocator, '"');
        for (it) |c| {
            if (c == '"' or c == '\\') try out.append(allocator, '\\');
            try out.append(allocator, c);
        }
        try out.append(allocator, '"');
    }
    try out.append(allocator, '}');
    return out.toOwnedSlice(allocator);
}

pub fn parsePgTextArray(allocator: std.mem.Allocator, raw: []const u8) ![][]const u8 {
    if (raw.len < 2 or raw[0] != '{' or raw[raw.len - 1] != '}') {
        return try allocator.alloc([]const u8, 0);
    }
    const inner = raw[1 .. raw.len - 1];
    if (inner.len == 0) return try allocator.alloc([]const u8, 0);
    var list: std.ArrayList([]const u8) = .empty;
    errdefer list.deinit(allocator);
    var i: usize = 0;
    while (i < inner.len) {
        if (inner[i] == '"') {
            i += 1;
            const start = i;
            while (i < inner.len and inner[i] != '"') : (i += 1) {
                if (inner[i] == '\\') i += 1;
            }
            try list.append(allocator, try allocator.dupe(u8, inner[start..i]));
            if (i < inner.len) i += 1; // closing quote
            if (i < inner.len and inner[i] == ',') i += 1;
        } else {
            const start = i;
            while (i < inner.len and inner[i] != ',') : (i += 1) {}
            try list.append(allocator, try allocator.dupe(u8, inner[start..i]));
            if (i < inner.len) i += 1;
        }
    }
    return list.toOwnedSlice(allocator);
}

pub fn jsonArrayStrings(allocator: std.mem.Allocator, items: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, '[');
    for (items, 0..) |it, i| {
        if (i > 0) try out.append(allocator, ',');
        try appendEscaped(&out, allocator, it);
    }
    try out.append(allocator, ']');
    return out.toOwnedSlice(allocator);
}

pub fn nullOrJsonString(allocator: std.mem.Allocator, opt: ?[]const u8) ![]u8 {
    if (opt) |s| return escapeJson(allocator, s);
    return try allocator.dupe(u8, "null");
}

pub fn cookieValue(cookie_header: []const u8, name: []const u8) ?[]const u8 {
    var rest = cookie_header;
    while (rest.len > 0) {
        const semi = std.mem.indexOfScalar(u8, rest, ';');
        var part = if (semi) |s| rest[0..s] else rest;
        rest = if (semi) |s| rest[s + 1 ..] else "";
        while (part.len > 0 and part[0] == ' ') part = part[1..];
        if (part.len >= name.len + 1 and std.mem.eql(u8, part[0..name.len], name) and part[name.len] == '=') {
            return part[name.len + 1 ..];
        }
    }
    return null;
}

pub const default_tenant = "00000000-0000-0000-0000-000000000001";

test "parse os arch" {
    try std.testing.expectEqualStrings("linux", parseOs("Linux").?);
    try std.testing.expect(parseOs("freebsd") == null);
    try std.testing.expectEqualStrings("x64", parseArch("amd64").?);
    try std.testing.expectEqualStrings("arm64", parseArch("aarch64").?);
    try std.testing.expect(parseArch("sparc") == null);
}

test "control chars" {
    try std.testing.expect(hasControlChars("a\nb"));
    try std.testing.expect(!hasControlChars("host.example"));
}

test "rfc3339 format" {
    var buf: [32]u8 = undefined;
    // 2020-01-01T00:00:00Z = 1577836800
    const s = formatRfc3339(&buf, 1577836800);
    try std.testing.expectEqualStrings("2020-01-01T00:00:00Z", s);
}

test "contains ignore case" {
    try std.testing.expect(containsIgnoreCase("Hello World", "world"));
    try std.testing.expect(!containsIgnoreCase("Hello", "xyz"));
}

test "sha256 hex length" {
    const allocator = std.testing.allocator;
    const h = try sha256Hex(allocator, "abc");
    defer allocator.free(h);
    try std.testing.expectEqual(@as(usize, 64), h.len);
}
