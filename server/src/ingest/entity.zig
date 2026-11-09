//! Process entity IDs, the same function as agent/src/entity.zig.
//!
//!   entity_id = base32( SHA-256( agent_id || pid_le32 || start_time_100ns_le64 || boot_id )[0..16] )
//!
//! `agent_id` and `boot_id` are the 36 lower-case ASCII bytes of the canonical
//! UUID text (nil UUID when unknown), `pid` is u32 LE, `start_time_100ns` is
//! u64 LE ticks of 100 ns since the Unix epoch truncated to whole
//! milliseconds, and base32 is RFC 4648 lower case without padding (26
//! characters). The server only computes an id for v1 (legacy) process events,
//! which carry no boot id, so those use the nil UUID. v2 events bring the id
//! the agent computed. Both files carry the same golden tests.
const std = @import("std");

pub const len: usize = 26;
pub const Id = [len]u8;
pub const nil_uuid = "00000000-0000-0000-0000-000000000000";
pub const ticks_per_ms: u64 = 10_000;
pub const ticks_per_second: u64 = 10_000_000;

const alphabet = "abcdefghijklmnopqrstuvwxyz234567";

pub fn base32(bytes: [16]u8) Id {
    var out: Id = undefined;
    var acc: u32 = 0;
    var bits: u5 = 0;
    var o: usize = 0;
    for (bytes) |b| {
        acc = (acc << 8) | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[o] = alphabet[@intCast((acc >> bits) & 31)];
            o += 1;
        }
        acc &= (@as(u32, 1) << bits) - 1;
    }
    if (bits > 0) {
        out[o] = alphabet[@intCast((acc << (5 - bits)) & 31)];
        o += 1;
    }
    std.debug.assert(o == len);
    return out;
}

pub fn canonicalUuid(text: []const u8) [36]u8 {
    var out: [36]u8 = nil_uuid.*;
    if (text.len != 36) return out;
    for (text, 0..) |c, i| {
        switch (i) {
            8, 13, 18, 23 => if (c != '-') return nil_uuid.*,
            else => if (!std.ascii.isHex(c)) return nil_uuid.*,
        }
        out[i] = std.ascii.toLower(c);
    }
    return out;
}

pub fn isUuid(text: []const u8) bool {
    if (text.len != 36) return false;
    const c = canonicalUuid(text);
    return !std.mem.eql(u8, &c, nil_uuid) or std.mem.eql(u8, text, nil_uuid);
}

/// True for a 26-character lower-case base32 entity id.
pub fn isEntityId(text: []const u8) bool {
    if (text.len != len) return false;
    for (text) |c| {
        if (!((c >= 'a' and c <= 'z') or (c >= '2' and c <= '7'))) return false;
    }
    return true;
}

pub fn truncateMs(start_100ns: u64) u64 {
    return start_100ns - start_100ns % ticks_per_ms;
}

pub fn compute(agent_id: []const u8, pid: u32, start_100ns: u64, boot_id: []const u8) Id {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    const a = canonicalUuid(agent_id);
    h.update(&a);
    var pid_le: [4]u8 = undefined;
    std.mem.writeInt(u32, &pid_le, pid, .little);
    h.update(&pid_le);
    var start_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &start_le, truncateMs(start_100ns), .little);
    h.update(&start_le);
    const b = canonicalUuid(boot_id);
    h.update(&b);
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return base32(digest[0..16].*);
}

/// ISO 8601 UTC (`T` or space separator, optional fraction, optional `Z`) to
/// 100 ns ticks since the Unix epoch. Anything after the fraction other than
/// `Z` is refused, so the text is safe to hand to Postgres after formatIso.
pub fn parseIso(s: []const u8) ?u64 {
    if (s.len < 19 or s.len > 40 or s[4] != '-' or s[7] != '-' or (s[10] != 'T' and s[10] != ' ') or s[13] != ':' or s[16] != ':') return null;
    const y = std.fmt.parseInt(i64, s[0..4], 10) catch return null;
    const m = std.fmt.parseInt(u8, s[5..7], 10) catch return null;
    const d = std.fmt.parseInt(u8, s[8..10], 10) catch return null;
    const hh = std.fmt.parseInt(i64, s[11..13], 10) catch return null;
    const mm = std.fmt.parseInt(i64, s[14..16], 10) catch return null;
    const ss = std.fmt.parseInt(i64, s[17..19], 10) catch return null;
    if (m < 1 or m > 12 or d < 1 or d > 31 or hh > 23 or mm > 59 or ss > 60) return null;
    var frac: u64 = 0;
    var i: usize = 19;
    if (i < s.len and s[i] == '.') {
        i += 1;
        var digits: u32 = 0;
        while (i < s.len and std.ascii.isDigit(s[i])) : (i += 1) {
            if (digits < 7) {
                frac = frac * 10 + (s[i] - '0');
                digits += 1;
            }
        }
        if (digits == 0) return null;
        while (digits < 7) : (digits += 1) frac *= 10;
    }
    if (i < s.len and s[i] == 'Z') i += 1;
    if (i != s.len) return null;
    const yy = if (m <= 2) y - 1 else y;
    const era = @divFloor(yy, 400);
    const yoe = yy - era * 400;
    const mp: i64 = if (m > 2) m - 3 else m + 9;
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    const secs = days * 86400 + hh * 3600 + mm * 60 + ss;
    if (secs < 0) return null;
    return @as(u64, @intCast(secs)) * ticks_per_second + frac;
}

/// 100 ns ticks to `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn formatIso(buf: *[24]u8, ticks: u64) []const u8 {
    const secs: i64 = @intCast(ticks / ticks_per_second);
    const ms: u64 = (ticks % ticks_per_second) / ticks_per_ms;
    const z = @divFloor(secs, 86400) + 719468;
    const sod: u64 = @intCast(@mod(secs, 86400));
    const era = @divFloor(z, 146097);
    const doe: u64 = @intCast(z - era * 146097);
    const yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const mp = (5 * doy + 2) / 153;
    const day = doy - (153 * mp + 2) / 5 + 1;
    const month = if (mp < 10) mp + 3 else mp - 9;
    const year: i64 = @as(i64, @intCast(yoe)) + era * 400 + @as(i64, if (month <= 2) 1 else 0);
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
        @as(u64, @intCast(@min(year, 9999))), month, day, sod / 3600, (sod / 60) % 60, sod % 60, ms,
    }) catch unreachable;
}

// Same inputs and outputs as the tests in agent/src/entity.zig.
const golden_agent = "0f8fad5b-d9cb-469f-a165-70867728950e";
const golden_boot = "3c1c4b5e-6d2a-4f0e-9b7a-2d1e5f6a7b8c";

test "entity id golden values match the agent" {
    try std.testing.expectEqualStrings("t2brmmuntrcdcqfziccyckt3lm", &compute(golden_agent, 4242, 17941867645480000, golden_boot));
    try std.testing.expectEqualStrings("2nht3dql7uoginwzsplvmrzejm", &compute(golden_agent, 4242, 17941872000000000, golden_boot));
    try std.testing.expectEqualStrings("jxaz76mjj6mgg7gdglttce3yxy", &compute(nil_uuid, 0, 0, nil_uuid));
    try std.testing.expectEqualStrings("aujn3ffo4cvqnno2et2cap5phi", &compute(golden_agent, 4242, 17941867645480000, nil_uuid));
    const fixture_agent = "00000000-0000-4000-8000-00000000f001";
    try std.testing.expectEqualStrings("7iyrf5zm6b5flyledskp3lodvm", &compute(fixture_agent, 4100, parseIso("2026-11-09T01:00:00.100Z").?, golden_boot));
    try std.testing.expectEqualStrings("wxjmbxyyq7eybnyac2lfc654ka", &compute(fixture_agent, 5200, parseIso("2026-11-09T01:00:05.200Z").?, golden_boot));
    try std.testing.expectEqualStrings("z64l2w3c4w3q2jhyq5jbnley3q", &compute(fixture_agent, 6300, parseIso("2026-11-09T01:00:09.300Z").?, golden_boot));
    // Legacy (v1) id for a seconds-only start time and no boot id.
    try std.testing.expectEqualStrings("cy4xjhmjwfr7siwjojwri4huj4", &compute(fixture_agent, 4242, 1762650000 * ticks_per_second, nil_uuid));
}

test "entity id format and iso parsing" {
    try std.testing.expect(isEntityId("t2brmmuntrcdcqfziccyckt3lm"));
    try std.testing.expect(!isEntityId("T2BRMMUNTRCDCQFZICCYCKT3LM"));
    try std.testing.expect(!isEntityId("t2brmmuntrcdcqfziccyckt3l1"));
    try std.testing.expect(!isEntityId("short"));
    var buf: [24]u8 = undefined;
    try std.testing.expectEqualStrings("2026-11-09T01:12:44.548Z", formatIso(&buf, parseIso("2026-11-09 01:12:44.5481234").?));
    try std.testing.expectEqual(@as(?u64, null), parseIso("2026-11-09T01:12:44.548Z'; drop"));
    try std.testing.expectEqual(@as(?u64, null), parseIso("2026-11-09T01:12:44."));
    try std.testing.expect(isUuid("0F8FAD5B-D9CB-469F-A165-70867728950E"));
    try std.testing.expect(isUuid(nil_uuid));
    try std.testing.expect(!isUuid("0f8fad5b-d9cb-469f-a165-70867728950"));
}
