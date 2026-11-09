//! Process entity IDs (docs/architecture/target-edr.md section 2.4).
//!
//!   entity_id = base32( SHA-256( agent_id || pid_le32 || start_time_100ns_le64 || boot_id )[0..16] )
//!
//! Byte encoding, fixed so every OS and the server agree:
//! - `agent_id` and `boot_id` are the 36 ASCII bytes of the canonical UUID
//!   text, lower case (`0f8fad5b-d9cb-469f-a165-70867728950e`). Upper case
//!   input is lowered first. An unknown boot id is the nil UUID text.
//! - `pid` is a little-endian u32.
//! - `start_time_100ns` is a little-endian u64 count of 100 ns ticks since
//!   1970-01-01T00:00:00Z, truncated to whole milliseconds (a multiple of
//!   10_000). Sysmon `UtcTime` only has milliseconds, so truncating makes it
//!   agree with `GetProcessTimes` for the same process.
//! - base32 is RFC 4648 (`a-z2-7`) in lower case without padding: 16 bytes
//!   become 26 characters.
//!
//! The same function lives in server/src/ingest/entity.zig and both carry the
//! same golden tests.
const std = @import("std");
const builtin = @import("builtin");
const iox = @import("io_compat.zig");

pub const len: usize = 26;
pub const Id = [len]u8;
pub const nil_uuid = "00000000-0000-0000-0000-000000000000";
pub const ticks_per_ms: u64 = 10_000;
pub const ticks_per_second: u64 = 10_000_000;

const alphabet = "abcdefghijklmnopqrstuvwxyz234567";

/// Lower-case base32 (RFC 4648 alphabet) of 16 bytes, no padding.
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

/// Lower-cased canonical UUID text, or the nil UUID when `text` is not one.
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

/// Truncate to whole milliseconds, as the hash input requires.
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

// ---------------------------------------------------------------------------
// Time helpers

/// Windows FILETIME ticks (since 1601) to ticks since the Unix epoch.
pub fn fromFiletime(ticks_1601: u64) ?u64 {
    const delta: u64 = 116_444_736_000_000_000;
    if (ticks_1601 < delta) return null;
    return ticks_1601 - delta;
}

/// `2026-11-09T01:12:44.548Z` or `2026-11-09 01:12:44.548` (Sysmon UtcTime)
/// or `2026-11-09T01:12:44.5512031Z` (event TimeCreated) to 100 ns ticks.
pub fn parseIso(s: []const u8) ?u64 {
    if (s.len < 19 or s[4] != '-' or s[7] != '-' or (s[10] != 'T' and s[10] != ' ') or s[13] != ':' or s[16] != ':') return null;
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
        while (digits < 7) : (digits += 1) frac *= 10;
    }
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
        @as(u64, @intCast(year)), month, day, sod / 3600, (sod / 60) % 60, sod % 60, ms,
    }) catch unreachable;
}

// ---------------------------------------------------------------------------
// Boot id

extern "c" fn sysctlbyname(name: [*:0]const u8, oldp: ?*anyopaque, oldlenp: ?*usize, newp: ?*anyopaque, newlen: usize) c_int;

/// Boot id for this boot as canonical lower-case UUID text; the nil UUID when
/// it can't be read. Linux: /proc/sys/kernel/random/boot_id. macOS:
/// `kern.bootsessionuuid`. Windows: a UUID derived from the registry BootId
/// counter (see `windowsBootId`).
pub fn readBootId() [36]u8 {
    switch (builtin.target.os.tag) {
        .linux => {
            const io = iox.current();
            var file = std.Io.Dir.openFileAbsolute(io, "/proc/sys/kernel/random/boot_id", .{}) catch return nil_uuid.*;
            defer file.close(io);
            var buf: [64]u8 = undefined;
            const n = file.readPositionalAll(io, &buf, 0) catch return nil_uuid.*;
            return canonicalUuid(std.mem.trim(u8, buf[0..n], " \t\r\n"));
        },
        .macos => {
            var buf: [64]u8 = undefined;
            var n: usize = buf.len;
            if (sysctlbyname("kern.bootsessionuuid", &buf, &n, null, 0) != 0) return nil_uuid.*;
            return canonicalUuid(std.mem.trim(u8, buf[0..@min(n, buf.len)], " \t\r\n\x00"));
        },
        .windows => return windowsBootId(),
        else => return nil_uuid.*,
    }
}

/// UUID text for a Windows boot: SHA-256("tawny-windows-boot\x00" || BootId_le32)
/// truncated to 16 bytes with RFC 9562 version 8 bits. BootId is the counter
/// at HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters.
pub fn bootIdFromCounter(counter: u32) [36]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("tawny-windows-boot\x00");
    var le: [4]u8 = undefined;
    std.mem.writeInt(u32, &le, counter, .little);
    h.update(&le);
    var digest: [32]u8 = undefined;
    h.final(&digest);
    var id: [16]u8 = digest[0..16].*;
    id[6] = (id[6] & 0x0f) | 0x80;
    id[8] = (id[8] & 0x3f) | 0x80;
    const hex = std.fmt.bytesToHex(id, .lower);
    var out: [36]u8 = undefined;
    @memcpy(out[0..8], hex[0..8]);
    out[8] = '-';
    @memcpy(out[9..13], hex[8..12]);
    out[13] = '-';
    @memcpy(out[14..18], hex[12..16]);
    out[18] = '-';
    @memcpy(out[19..23], hex[16..20]);
    out[23] = '-';
    @memcpy(out[24..36], hex[20..32]);
    return out;
}

const win = struct {
    const HKEY = *opaque {};
    const HKEY_LOCAL_MACHINE: HKEY = @ptrFromInt(0x80000002);
    const RRF_RT_REG_DWORD: u32 = 0x00000010;
    extern "advapi32" fn RegGetValueW(key: HKEY, sub_key: [*:0]const u16, value: [*:0]const u16, flags: u32, kind: ?*u32, data: ?*anyopaque, data_len: ?*u32) callconv(.winapi) i32;
};

fn windowsBootId() [36]u8 {
    if (builtin.target.os.tag != .windows) return nil_uuid.*;
    const sub = std.unicode.utf8ToUtf16LeStringLiteral("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters");
    const name = std.unicode.utf8ToUtf16LeStringLiteral("BootId");
    var value: u32 = 0;
    var size: u32 = @sizeOf(u32);
    if (win.RegGetValueW(win.HKEY_LOCAL_MACHINE, sub, name, win.RRF_RT_REG_DWORD, null, &value, &size) != 0) return nil_uuid.*;
    return bootIdFromCounter(value);
}

// ---------------------------------------------------------------------------
// pid -> entity table

/// Bounded LRU from pid to the process currently holding it. Filled from a
/// snapshot at start and from every process start, so a child's
/// `parent.entity_id` is known when the child is first seen.
pub const Table = struct {
    allocator: std.mem.Allocator,
    agent_id: [36]u8,
    boot_id: [36]u8,
    capacity: usize,
    map: std.AutoHashMap(u32, Entry),
    clock: u64 = 0,

    pub const Entry = struct {
        start_100ns: u64,
        id: Id,
        last_used: u64,
        /// Sysmon ProcessGuid when known, so an exit can be matched exactly.
        guid: [38]u8 = @splat(0),
        guid_len: u8 = 0,

        pub fn guidSlice(self: *const Entry) []const u8 {
            return self.guid[0..self.guid_len];
        }
    };

    pub const default_capacity: usize = 8192;

    pub fn init(alloc: std.mem.Allocator, agent_id: []const u8, boot_id: []const u8, capacity: usize) Table {
        return .{
            .allocator = alloc,
            .agent_id = canonicalUuid(agent_id),
            .boot_id = canonicalUuid(boot_id),
            .capacity = @max(capacity, 1),
            .map = std.AutoHashMap(u32, Entry).init(alloc),
        };
    }

    pub fn deinit(self: *Table) void {
        self.map.deinit();
    }

    pub fn idFor(self: *const Table, pid: u32, start_100ns: u64) Id {
        return compute(&self.agent_id, pid, start_100ns, &self.boot_id);
    }

    /// Record that `pid` started at `start_100ns`. Replaces an older holder
    /// of the same pid (pid reuse). Returns the entity id.
    pub fn observe(self: *Table, pid: u32, start_100ns: u64, guid: []const u8) !Id {
        self.clock += 1;
        const start = truncateMs(start_100ns);
        if (self.map.getPtr(pid)) |e| {
            if (e.start_100ns == start) {
                e.last_used = self.clock;
                if (guid.len > 0 and guid.len <= e.guid.len) {
                    @memcpy(e.guid[0..guid.len], guid);
                    e.guid_len = @intCast(guid.len);
                }
                return e.id;
            }
        } else if (self.map.count() >= self.capacity) {
            self.evictOldest();
        }
        var entry = Entry{ .start_100ns = start, .id = self.idFor(pid, start), .last_used = self.clock };
        if (guid.len > 0 and guid.len <= entry.guid.len) {
            @memcpy(entry.guid[0..guid.len], guid);
            entry.guid_len = @intCast(guid.len);
        }
        try self.map.put(pid, entry);
        return entry.id;
    }

    /// Entity currently holding `pid`, if it started no later than
    /// `not_after_100ns` (a parent can't start after its child). A later
    /// start means the pid was reused and the real parent is unknown.
    pub fn parentOf(self: *Table, ppid: u32, child_start_100ns: ?u64) ?Id {
        const e = self.map.getPtr(ppid) orelse return null;
        if (child_start_100ns) |c| if (e.start_100ns > truncateMs(c)) return null;
        self.clock += 1;
        e.last_used = self.clock;
        return e.id;
    }

    /// Entity for `pid` right now. When `guid` is given and the entry has a
    /// different one, the pid belongs to someone else and null is returned.
    pub fn lookup(self: *Table, pid: u32, guid: []const u8) ?Id {
        const e = self.map.getPtr(pid) orelse return null;
        if (guid.len > 0 and e.guid_len > 0 and !std.ascii.eqlIgnoreCase(e.guidSlice(), guid)) return null;
        self.clock += 1;
        e.last_used = self.clock;
        return e.id;
    }

    pub fn forget(self: *Table, pid: u32) void {
        _ = self.map.remove(pid);
    }

    fn evictOldest(self: *Table) void {
        var oldest_pid: ?u32 = null;
        var oldest: u64 = std.math.maxInt(u64);
        var it = self.map.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.last_used < oldest) {
                oldest = kv.value_ptr.last_used;
                oldest_pid = kv.key_ptr.*;
            }
        }
        if (oldest_pid) |p| _ = self.map.remove(p);
    }
};

/// Seed the table from a process snapshot. Linux and macOS seed through the
/// launch tracker's first pass; Windows reads GetProcessTimes here.
pub fn seedFromSystem(table: *Table) void {
    if (builtin.target.os.tag != .windows) return;
    const platform = @import("platform/windows.zig");
    const procs = platform.enumerateProcesses(table.allocator) catch return;
    defer platform.freeProcesses(table.allocator, procs);
    for (procs) |p| {
        const start = p.start_time_100ns orelse continue;
        _ = table.observe(p.pid, start, "") catch return;
    }
}

// ---------------------------------------------------------------------------
// Tests. The same golden values are checked in server/src/ingest/entity.zig.

const golden_agent = "0f8fad5b-d9cb-469f-a165-70867728950e";
const golden_boot = "3c1c4b5e-6d2a-4f0e-9b7a-2d1e5f6a7b8c";

test "entity id golden values" {
    try std.testing.expectEqualStrings("t2brmmuntrcdcqfziccyckt3lm", &compute(golden_agent, 4242, 17941867645480000, golden_boot));
    try std.testing.expectEqualStrings("2nht3dql7uoginwzsplvmrzejm", &compute(golden_agent, 4242, 17941872000000000, golden_boot));
    try std.testing.expectEqualStrings("jxaz76mjj6mgg7gdglttce3yxy", &compute(nil_uuid, 0, 0, nil_uuid));
    try std.testing.expectEqualStrings("aujn3ffo4cvqnno2et2cap5phi", &compute(golden_agent, 4242, 17941867645480000, nil_uuid));
    // Fixture chain in server/fixtures/process-chain-office.v2.json.
    const fixture_agent = "00000000-0000-4000-8000-00000000f001";
    try std.testing.expectEqualStrings("7iyrf5zm6b5flyledskp3lodvm", &compute(fixture_agent, 4100, parseIso("2026-11-09T01:00:00.100Z").?, golden_boot));
    try std.testing.expectEqualStrings("wxjmbxyyq7eybnyac2lfc654ka", &compute(fixture_agent, 5200, parseIso("2026-11-09T01:00:05.200Z").?, golden_boot));
    try std.testing.expectEqualStrings("z64l2w3c4w3q2jhyq5jbnley3q", &compute(fixture_agent, 6300, parseIso("2026-11-09T01:00:09.300Z").?, golden_boot));
}

test "entity id ignores uuid case and sub-millisecond ticks" {
    const upper = "0F8FAD5B-D9CB-469F-A165-70867728950E";
    const a = compute(golden_agent, 4242, 17941867645480000, golden_boot);
    try std.testing.expectEqualSlices(u8, &a, &compute(upper, 4242, 17941867645480000, "3C1C4B5E-6D2A-4F0E-9B7A-2D1E5F6A7B8C"));
    try std.testing.expectEqualSlices(u8, &a, &compute(golden_agent, 4242, 17941867645489999, golden_boot));
    // Sysmon UtcTime (ms) and the 4688 TimeCreated (100 ns) land on the same id.
    try std.testing.expectEqualSlices(u8, &a, &compute(golden_agent, 4242, parseIso("2026-11-09 01:12:44.548").?, golden_boot));
    try std.testing.expectEqualSlices(u8, &a, &compute(golden_agent, 4242, parseIso("2026-11-09T01:12:44.5487031Z").?, golden_boot));
}

test "base32 matches RFC 4648 vectors in lower case" {
    // RFC 4648 "foobar" is MZXW6YTBOI======; check a 16-byte input instead.
    try std.testing.expectEqualStrings("aaaaaaaaaaaaaaaaaaaaaaaaaa", &base32(@splat(0)));
    try std.testing.expectEqualStrings("77777777777777777777777774", &base32(@splat(0xff)));
}

test "iso round trip and filetime" {
    var buf: [24]u8 = undefined;
    const t = parseIso("2026-11-09T01:12:44.548Z").?;
    try std.testing.expectEqual(@as(u64, 17941867645480000), t);
    try std.testing.expectEqualStrings("2026-11-09T01:12:44.548Z", formatIso(&buf, t));
    try std.testing.expectEqualStrings("2000-02-29T23:59:59.000Z", formatIso(&buf, parseIso("2000-02-29T23:59:59Z").?));
    try std.testing.expectEqual(@as(?u64, 0), fromFiletime(116_444_736_000_000_000));
    try std.testing.expectEqual(@as(?u64, null), parseIso("not a time"));
}

test "windows boot id is a stable v8 uuid" {
    const a = bootIdFromCounter(42);
    try std.testing.expectEqualSlices(u8, &a, &bootIdFromCounter(42));
    try std.testing.expect(!std.mem.eql(u8, &a, &bootIdFromCounter(43)));
    try std.testing.expectEqual(@as(u8, '8'), a[14]);
    try std.testing.expectEqualSlices(u8, &a, &canonicalUuid(&a));
}

test "boot id reads on this host" {
    const id = readBootId();
    try std.testing.expectEqual(@as(usize, 36), id.len);
    if (builtin.target.os.tag == .linux or builtin.target.os.tag == .macos) {
        try std.testing.expect(!std.mem.eql(u8, &id, nil_uuid));
    }
}

test "pid reuse gives a new id and the child joins the right parent" {
    var t = Table.init(std.testing.allocator, golden_agent, golden_boot, 16);
    defer t.deinit();
    const s = ticks_per_second;
    const first = try t.observe(100, 1000 * s, "");
    try std.testing.expectEqualSlices(u8, &first, &(try t.observe(100, 1000 * s, "")));
    // A child of the first holder of pid 100.
    try std.testing.expectEqualSlices(u8, &first, &t.parentOf(100, 1001 * s).?);

    // pid 100 exits and is reused by a later process.
    const second = try t.observe(100, 2000 * s, "");
    try std.testing.expect(!std.mem.eql(u8, &first, &second));
    try std.testing.expectEqualSlices(u8, &second, &t.parentOf(100, 2001 * s).?);
    // A child that started before the second holder can't be its child.
    try std.testing.expect(t.parentOf(100, 1500 * s) == null);
    try std.testing.expect(t.parentOf(999, 1500 * s) == null);
}

test "table is bounded and evicts the least recently used pid" {
    var t = Table.init(std.testing.allocator, golden_agent, golden_boot, 3);
    defer t.deinit();
    _ = try t.observe(1, 10, "");
    _ = try t.observe(2, 20, "");
    _ = try t.observe(3, 30, "");
    _ = t.lookup(1, ""); // 2 is now the oldest
    _ = try t.observe(4, 40, "");
    try std.testing.expectEqual(@as(u32, 3), t.map.count());
    try std.testing.expect(t.lookup(2, "") == null);
    try std.testing.expect(t.lookup(1, "") != null);
}

test "lookup refuses a different sysmon guid" {
    var t = Table.init(std.testing.allocator, golden_agent, golden_boot, 4);
    defer t.deinit();
    _ = try t.observe(7, 10 * ticks_per_second, "{aaaa}");
    try std.testing.expect(t.lookup(7, "{AAAA}") != null);
    try std.testing.expect(t.lookup(7, "{bbbb}") == null);
    try std.testing.expect(t.lookup(7, "") != null);
}
