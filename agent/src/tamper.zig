//! Tamper checks (#58, target-edr §10 "Tamper detection"). Each finding is an
//! `agent_tamper` event (schemas/events/agent_tamper.v1.json):
//!
//! - `unexpected_stop`: the last run ended without the clean shutdown marker
//!   (lifecycle.zig).
//! - `binary_changed`: the agent executable's SHA-256 differs from the
//!   manifest the updater committed (`<state>.release.json`), or, without
//!   one, from the hash taken when this process started.
//! - `config_changed`, `identity_changed`: config.toml, state.toml, the device
//!   key or the pinned action key changed (hash and mtime) without the agent
//!   writing it. The agent calls `Monitor.acceptOwnWrite` after its own writes.
//! - `sysmon_stopped` (Windows): the Sysmon service was running and is not.
//! - `defender_exclusion` (Windows): Defender Operational 5007 shows a new
//!   path or process exclusion covering a Tawny path. Mapped from the event
//!   log by collectors/windows_events.zig through `defenderExclusionPayload`.
//!
//! No anti-debug or rootkit behaviour: these are detections, not defences.

const std = @import("std");
const builtin = @import("builtin");
const iox = @import("io_compat.zig");
const scm = @import("platform/windows/scm.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Check = enum {
    unexpected_stop,
    binary_changed,
    config_changed,
    identity_changed,
    sysmon_stopped,
    defender_exclusion,
};

/// `agent_tamper` payload. Caller frees.
pub fn payload(alloc: std.mem.Allocator, check: Check, detail: []const u8, extra: Extra) ![]u8 {
    return std.json.Stringify.valueAlloc(alloc, .{
        .check = @tagName(check),
        .detail = detail,
        .path = extra.path,
        .expected_sha256 = extra.expected_sha256,
        .actual_sha256 = extra.actual_sha256,
        .service = extra.service,
        .exclusion = extra.exclusion,
    }, .{ .emit_null_optional_fields = false });
}

pub const Extra = struct {
    path: ?[]const u8 = null,
    expected_sha256: ?[]const u8 = null,
    actual_sha256: ?[]const u8 = null,
    service: ?[]const u8 = null,
    exclusion: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------
// Defender 5007

/// Paths and names that, when excluded from Defender, blind it to Tawny or
/// let something hide beside it. Compared case-insensitively.
const tawny_paths = [_][]const u8{
    "C:\\ProgramData\\Tawny",
    "C:\\Program Files\\Tawny",
};
const tawny_process = "tawny-agent.exe";

/// Defender 5007 `New Value` looks like
/// `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\ProgramData\Tawny = 0x0`.
/// Returns the excluded value and its kind when the change adds a path or
/// process exclusion, else null.
pub const Exclusion = struct { kind: enum { path, process }, value: []const u8 };

pub fn parseExclusion(new_value: []const u8) ?Exclusion {
    const markers = [_]struct { m: []const u8, k: @FieldType(Exclusion, "kind") }{
        .{ .m = "\\Exclusions\\Paths\\", .k = .path },
        .{ .m = "\\Exclusions\\Processes\\", .k = .process },
    };
    for (markers) |mk| {
        const at = std.ascii.findIgnoreCase(new_value, mk.m) orelse continue;
        var rest = new_value[at + mk.m.len ..];
        if (std.mem.lastIndexOf(u8, rest, " = ")) |eq| rest = rest[0..eq];
        rest = std.mem.trim(u8, rest, " \t\"");
        if (rest.len == 0) return null;
        return .{ .kind = mk.k, .value = rest };
    }
    return null;
}

/// True when excluding `value` from scanning covers a Tawny path: the value
/// is a Tawny path, sits under one, or is a parent of one (for example `C:\`).
pub fn coversTawny(ex: Exclusion) bool {
    switch (ex.kind) {
        .process => {
            const base = std.fs.path.basenameWindows(ex.value);
            return std.ascii.eqlIgnoreCase(base, tawny_process);
        },
        .path => {
            const v = std.mem.trimEnd(u8, ex.value, "\\/");
            if (v.len == 0) return false;
            for (tawny_paths) |p| {
                if (isPrefixPath(v, p) or isPrefixPath(p, v)) return true;
            }
            // Environment-variable forms Defender keeps unexpanded.
            const env_forms = [_][]const u8{ "%ProgramData%\\Tawny", "%ProgramFiles%\\Tawny", "%ProgramData%", "%ProgramFiles%" };
            for (env_forms) |p| if (isPrefixPath(p, v) or isPrefixPath(v, p)) return true;
            return false;
        },
    }
}

/// `parent` equals `child` or is a directory above it (case-insensitive,
/// either slash).
fn isPrefixPath(parent: []const u8, child: []const u8) bool {
    const p = std.mem.trimEnd(u8, parent, "\\/");
    if (child.len < p.len) return false;
    for (p, child[0..p.len]) |a, b| {
        const na = if (a == '/') '\\' else std.ascii.toLower(a);
        const nb = if (b == '/') '\\' else std.ascii.toLower(b);
        if (na != nb) return false;
    }
    return child.len == p.len or child[p.len] == '\\' or child[p.len] == '/' or (p.len > 0 and p[p.len - 1] == ':');
}

/// Payload for a 5007 event, or null when it is not a new exclusion covering
/// Tawny. An exclusion that was already there (same old and new value) is
/// ignored.
pub fn defenderExclusionPayload(alloc: std.mem.Allocator, old_value: ?[]const u8, new_value: ?[]const u8) !?[]u8 {
    const nv = new_value orelse return null;
    const ex = parseExclusion(nv) orelse return null;
    if (old_value) |ov| if (parseExclusion(ov)) |old_ex| {
        if (old_ex.kind == ex.kind and std.ascii.eqlIgnoreCase(old_ex.value, ex.value)) return null;
    };
    if (!coversTawny(ex)) return null;
    const detail = try std.fmt.allocPrint(alloc, "Defender {s} exclusion added that covers Tawny: {s}", .{ @tagName(ex.kind), ex.value });
    defer alloc.free(detail);
    return try payload(alloc, .defender_exclusion, detail, .{ .exclusion = ex.value });
}

// ---------------------------------------------------------------------------
// File baselines

pub const FileKind = enum { binary, config, identity };

pub const Fingerprint = struct {
    present: bool,
    sha256: [32]u8 = @splat(0),
    mtime_ns: i96 = 0,
    size: u64 = 0,

    pub fn eql(a: Fingerprint, b: Fingerprint) bool {
        if (a.present != b.present) return false;
        if (!a.present) return true;
        return std.mem.eql(u8, &a.sha256, &b.sha256);
    }
};

/// Hash a file (at most `max_bytes`). Missing files are `present = false`.
pub fn fingerprint(path: []const u8, max_bytes: u64) !Fingerprint {
    const io = iox.current();
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return .{ .present = false },
        else => return err,
    };
    defer file.close(io);
    const st = try file.stat(io);
    if (st.size > max_bytes) return error.FileTooBig;
    var h = Sha256.init(.{});
    var buf: [64 * 1024]u8 = undefined;
    var off: u64 = 0;
    while (true) {
        const n = try file.readPositionalAll(io, &buf, off);
        if (n == 0) break;
        h.update(buf[0..n]);
        off += n;
        if (n < buf.len) break;
    }
    return .{ .present = true, .sha256 = h.finalResult(), .mtime_ns = st.mtime.toNanoseconds(), .size = st.size };
}

pub const Watched = struct {
    kind: FileKind,
    path: []u8,
    base: Fingerprint,
    /// The binary is compared with the committed release hash, not the start.
    expected_sha256: ?[32]u8 = null,
    /// Already reported for the current contents: report once per change.
    reported: bool = false,
};

pub const SysmonTracker = struct {
    was_running: bool = false,
    reported: bool = false,

    /// Feed the current state. Returns true once when Sysmon goes from
    /// running to anything else. Coming back clears the report.
    pub fn observe(self: *SysmonTracker, state: scm.ServiceState) bool {
        switch (state) {
            .running => {
                self.was_running = true;
                self.reported = false;
                return false;
            },
            .unknown => return false,
            .stopped, .other, .not_installed => {
                if (!self.was_running or self.reported) return false;
                self.reported = true;
                return true;
            },
        }
    }
};

const max_binary_bytes: u64 = 256 * 1024 * 1024;
const max_small_bytes: u64 = 1024 * 1024;

pub const Monitor = struct {
    alloc: std.mem.Allocator,
    files: std.ArrayList(Watched) = .empty,
    sysmon: SysmonTracker = .{},
    checks: u32 = 0,

    pub fn deinit(self: *Monitor) void {
        for (self.files.items) |f| self.alloc.free(f.path);
        self.files.deinit(self.alloc);
    }

    /// Start watching `path`, baseline taken now. Unreadable files are
    /// skipped with a log line.
    pub fn watch(self: *Monitor, kind: FileKind, path: []const u8) !void {
        const fp = fingerprint(path, if (kind == .binary) max_binary_bytes else max_small_bytes) catch |err| {
            std.debug.print("tamper: cannot baseline {s}: {s}\n", .{ path, @errorName(err) });
            return;
        };
        const owned = try self.alloc.dupe(u8, path);
        errdefer self.alloc.free(owned);
        try self.files.append(self.alloc, .{ .kind = kind, .path = owned, .base = fp });
    }

    /// Pin the binary to the hash from a committed, signature-checked
    /// release manifest.
    pub fn expectBinary(self: *Monitor, sha256: [32]u8) void {
        for (self.files.items) |*f| if (f.kind == .binary) {
            f.expected_sha256 = sha256;
        };
    }

    /// The agent changed `path` itself (JWT rotation, key pinning): take a
    /// new baseline so it isn't reported.
    pub fn acceptOwnWrite(self: *Monitor, path: []const u8) void {
        for (self.files.items) |*f| if (std.mem.eql(u8, f.path, path)) {
            f.base = fingerprint(f.path, max_small_bytes) catch f.base;
            f.reported = false;
        };
    }

    /// Run every check. Returns `agent_tamper` payloads; caller frees each
    /// and the slice. The binary is hashed every 5th call.
    pub fn check(self: *Monitor) ![][]u8 {
        var out: std.ArrayList([]u8) = .empty;
        errdefer {
            for (out.items) |p| self.alloc.free(p);
            out.deinit(self.alloc);
        }
        self.checks +%= 1;
        for (self.files.items) |*f| {
            if (f.kind == .binary and self.checks % 5 != 1) continue;
            const now = fingerprint(f.path, if (f.kind == .binary) max_binary_bytes else max_small_bytes) catch continue;
            if (try self.compare(f, now)) |p| try out.append(self.alloc, p);
        }
        if (builtin.target.os.tag == .windows) {
            if (self.sysmon.observe(scm.sysmonState())) {
                try out.append(self.alloc, try payload(self.alloc, .sysmon_stopped, "The Sysmon service was running and has stopped.", .{ .service = "Sysmon" }));
            }
        }
        return out.toOwnedSlice(self.alloc);
    }

    fn compare(self: *Monitor, f: *Watched, now: Fingerprint) !?[]u8 {
        var exp_hex: [64]u8 = undefined;
        var act_hex: [64]u8 = undefined;
        if (f.kind == .binary) {
            const want = f.expected_sha256 orelse f.base.sha256;
            if (now.present and std.mem.eql(u8, &want, &now.sha256)) {
                f.reported = false;
                return null;
            }
            if (f.reported) return null;
            f.reported = true;
            _ = std.fmt.bufPrint(&exp_hex, "{x}", .{want}) catch unreachable;
            _ = std.fmt.bufPrint(&act_hex, "{x}", .{now.sha256}) catch unreachable;
            const why = if (!now.present) "The agent binary is missing." else if (f.expected_sha256 != null) "The agent binary does not match the signed release manifest." else "The agent binary changed while the agent was running.";
            return try payload(self.alloc, .binary_changed, why, .{ .path = f.path, .expected_sha256 = &exp_hex, .actual_sha256 = if (now.present) &act_hex else null });
        }
        if (Fingerprint.eql(f.base, now)) return null;
        // Report once, then take the new contents as the baseline so a
        // second edit is reported again.
        f.base = now;
        const check_kind: Check = if (f.kind == .config) .config_changed else .identity_changed;
        const why = if (!now.present)
            (if (f.kind == .config) "The agent config file was removed outside the agent." else "An agent identity file was removed outside the agent.")
        else
            (if (f.kind == .config) "The agent config file changed outside the agent." else "An agent identity file changed outside the agent.");
        _ = std.fmt.bufPrint(&act_hex, "{x}", .{now.sha256}) catch unreachable;
        return try payload(self.alloc, check_kind, why, .{ .path = f.path, .actual_sha256 = if (now.present) &act_hex else null });
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const schema_check = @import("schema_check.zig");

test "Defender 5007 exclusions that cover Tawny are reported, others are not" {
    const a = testing.allocator;
    const cases = [_]struct { new: []const u8, hit: bool }{
        .{ .new = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\ProgramData\\Tawny = 0x0", .hit = true },
        .{ .new = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\c:\\programdata\\tawny\\state = 0x0", .hit = true },
        .{ .new = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\ = 0x0", .hit = true },
        .{ .new = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\ProgramData = 0x0", .hit = true },
        .{ .new = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes\\C:\\Program Files\\Tawny\\tawny-agent.exe = 0x0", .hit = true },
        .{ .new = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\%ProgramData%\\Tawny = 0x0", .hit = true },
        .{ .new = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\ProgramDataX = 0x0", .hit = false },
        .{ .new = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\D:\\builds = 0x0", .hit = false },
        .{ .new = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions\\.log = 0x0", .hit = false },
        .{ .new = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring = 0x1", .hit = false },
    };
    for (cases) |c| {
        const got = try defenderExclusionPayload(a, null, c.new);
        defer if (got) |g| a.free(g);
        if ((got != null) != c.hit) {
            std.debug.print("case {s}: want hit={}\n", .{ c.new, c.hit });
            return error.TestUnexpectedResult;
        }
        if (got) |g| try schema_check.expectValid(a, "agent_tamper", g);
    }
    // Unchanged value (Defender rewrites on policy refresh): not news.
    const same = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\ProgramData\\Tawny = 0x0";
    try testing.expect((try defenderExclusionPayload(a, same, same)) == null);
}

test "config and identity changes are reported once per change, own writes are not" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fs.path.join(a, &.{ ".zig-cache", "tmp", &tmp.sub_path });
    defer a.free(dir);
    const cfg = try std.fs.path.join(a, &.{ dir, "config.toml" });
    defer a.free(cfg);
    const key = try std.fs.path.join(a, &.{ dir, "state.toml.devicekey" });
    defer a.free(key);
    const io = iox.current();
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = cfg, .data = "url = \"https://a\"\n" });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = key, .data = "0123456789abcdef0123456789abcdef" });

    var m = Monitor{ .alloc = a };
    defer m.deinit();
    try m.watch(.config, cfg);
    try m.watch(.identity, key);

    const quiet = try m.check();
    defer a.free(quiet);
    try testing.expectEqual(@as(usize, 0), quiet.len);

    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = cfg, .data = "url = \"https://evil\"\n" });
    try std.Io.Dir.cwd().deleteFile(io, key);
    const found = try m.check();
    defer {
        for (found) |p| a.free(p);
        a.free(found);
    }
    try testing.expectEqual(@as(usize, 2), found.len);
    try testing.expect(std.mem.indexOf(u8, found[0], "\"config_changed\"") != null);
    try testing.expect(std.mem.indexOf(u8, found[1], "\"identity_changed\"") != null);
    for (found) |p| try schema_check.expectValid(a, "agent_tamper", p);

    const again = try m.check();
    defer a.free(again);
    try testing.expectEqual(@as(usize, 0), again.len);

    // The agent rewrites its own file and says so: nothing reported.
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = cfg, .data = "url = \"https://b\"\n" });
    m.acceptOwnWrite(cfg);
    const own = try m.check();
    defer a.free(own);
    try testing.expectEqual(@as(usize, 0), own.len);
}

test "binary hash is checked against the committed manifest hash" {
    const a = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const bin = try std.fs.path.join(a, &.{ ".zig-cache", "tmp", &tmp.sub_path, "tawny-agent" });
    defer a.free(bin);
    const io = iox.current();
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = bin, .data = "release bytes" });
    var m = Monitor{ .alloc = a };
    defer m.deinit();
    try m.watch(.binary, bin);
    const ok = try m.check();
    defer a.free(ok);
    try testing.expectEqual(@as(usize, 0), ok.len);

    // The manifest says something else: reported once.
    var want: [32]u8 = undefined;
    Sha256.hash("signed release bytes", &want, .{});
    m.expectBinary(want);
    m.checks = 0;
    const bad = try m.check();
    defer {
        for (bad) |p| a.free(p);
        a.free(bad);
    }
    try testing.expectEqual(@as(usize, 1), bad.len);
    try testing.expect(std.mem.indexOf(u8, bad[0], "signed release manifest") != null);
    try schema_check.expectValid(a, "agent_tamper", bad[0]);
    m.checks = 0;
    const once = try m.check();
    defer a.free(once);
    try testing.expectEqual(@as(usize, 0), once.len);
}

test "Sysmon stop is reported once after it was seen running" {
    var t: SysmonTracker = .{};
    try testing.expect(!t.observe(.not_installed));
    try testing.expect(!t.observe(.running));
    try testing.expect(!t.observe(.unknown));
    try testing.expect(t.observe(.stopped));
    try testing.expect(!t.observe(.stopped));
    try testing.expect(!t.observe(.running));
    try testing.expect(t.observe(.not_installed));
}

test "unexpected stop payload matches its schema" {
    const a = testing.allocator;
    const p = try payload(a, .unexpected_stop, "The agent started without the clean shutdown marker from its last run.", .{});
    defer a.free(p);
    try schema_check.expectValid(a, "agent_tamper", p);
}
