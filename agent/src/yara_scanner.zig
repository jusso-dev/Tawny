//! YARA triggers on the agent. Files are scanned on the host and never
//! uploaded. Three triggers:
//!
//! - file events: a created, modified or moved-in file with an executable
//!   or script extension, in a watched folder (`fim_paths`), is scanned;
//! - the `yara_scan` response action: scan one path or one folder now;
//! - a scheduled scan of startup and temp folders (`yara_scan_interval_seconds`).
//!
//! Each match becomes a `yara_match` event: rule, tags, file path, SHA-256,
//! size and trigger. Rules come from a signed pack (`rule_pack.zig`); with no
//! verified pack, nothing is scanned.

const std = @import("std");
const builtin = @import("builtin");
const yara = @import("yara.zig");
const rule_pack = @import("rule_pack.zig");
const iox = @import("io_compat.zig");

pub const Trigger = enum { file_event, response_action, scheduled };

/// Extensions treated as executables or scripts.
const scan_extensions = [_][]const u8{
    "exe", "dll",  "sys", "scr", "com", "cpl", "msi", "ocx",
    "ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js",  "jse",
    "wsf", "hta",  "lnk", "jar", "py",  "sh",  "elf", "so",
    "dylib", "app", "bin", "",
};

/// Should a file event trigger a scan? Only creates, modifies and moves
/// into a folder, and only executables and scripts. Files with no
/// extension count (ELF and Mach-O binaries often have none).
pub fn wantsScan(path: []const u8, action: []const u8, is_directory: bool) bool {
    if (is_directory) return false;
    const act_ok = std.mem.eql(u8, action, "create") or std.mem.eql(u8, action, "modify") or std.mem.eql(u8, action, "moved_to") or std.mem.eql(u8, action, "renamed") or std.mem.eql(u8, action, "created") or std.mem.eql(u8, action, "modified");
    if (!act_ok) return false;
    const base = std.fs.path.basename(path);
    if (base.len == 0 or base[0] == '.') return false;
    const dot = std.mem.lastIndexOfScalar(u8, base, '.');
    const ext = if (dot) |d| base[d + 1 ..] else "";
    for (scan_extensions) |e| {
        if (std.ascii.eqlIgnoreCase(e, ext)) return true;
    }
    return false;
}

/// Environment lookups for `scheduledFolders`, from the process environment.
pub const ProcessEnv = struct {
    alloc: std.mem.Allocator,
    held: std.ArrayList([]u8) = .empty,

    pub fn get(self: *ProcessEnv, name: [:0]const u8) ?[]const u8 {
        const v = @import("env.zig").getEnvVarOwned(self.alloc, name) catch return null;
        self.held.append(self.alloc, v) catch {
            self.alloc.free(v);
            return null;
        };
        return v;
    }

    pub fn deinit(self: *ProcessEnv) void {
        for (self.held.items) |v| self.alloc.free(v);
        self.held.deinit(self.alloc);
    }
};

/// Startup and temp folders for the scheduled scan. `env` has
/// `get(name) ?[]const u8`.
pub fn scheduledFolders(alloc: std.mem.Allocator, env: anytype) ![][]u8 {
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |p| alloc.free(p);
        out.deinit(alloc);
    }
    switch (builtin.target.os.tag) {
        .windows => {
            if (env.get("ProgramData")) |pd| try out.append(alloc, try std.fs.path.join(alloc, &.{ pd, "Microsoft", "Windows", "Start Menu", "Programs", "StartUp" }));
            if (env.get("APPDATA")) |ad| try out.append(alloc, try std.fs.path.join(alloc, &.{ ad, "Microsoft", "Windows", "Start Menu", "Programs", "Startup" }));
            if (env.get("TEMP")) |t| try out.append(alloc, try alloc.dupe(u8, t));
            if (env.get("SystemRoot")) |sr| try out.append(alloc, try std.fs.path.join(alloc, &.{ sr, "Temp" }));
        },
        .macos => {
            try out.append(alloc, try alloc.dupe(u8, "/Library/LaunchAgents"));
            try out.append(alloc, try alloc.dupe(u8, "/Library/LaunchDaemons"));
            try out.append(alloc, try alloc.dupe(u8, "/tmp"));
            if (env.get("HOME")) |h| try out.append(alloc, try std.fs.path.join(alloc, &.{ h, "Library", "LaunchAgents" }));
        },
        else => {
            try out.append(alloc, try alloc.dupe(u8, "/tmp"));
            try out.append(alloc, try alloc.dupe(u8, "/var/tmp"));
            try out.append(alloc, try alloc.dupe(u8, "/dev/shm"));
            try out.append(alloc, try alloc.dupe(u8, "/etc/init.d"));
            try out.append(alloc, try alloc.dupe(u8, "/etc/systemd/system"));
            try out.append(alloc, try alloc.dupe(u8, "/etc/cron.d"));
        },
    }
    return out.toOwnedSlice(alloc);
}

pub const max_files_per_folder: usize = 2000;

pub const Scanner = struct {
    alloc: std.mem.Allocator,
    public_key: ?std.crypto.sign.Ed25519.PublicKey,
    rules: ?yara.Rules = null,
    pack_version: u64 = 0,
    options: yara.Options = .{},

    pub fn deinit(self: *Scanner) void {
        if (self.rules) |*r| r.deinit();
        self.rules = null;
    }

    pub const LoadError = rule_pack.VerifyError || yara.Error || error{ NoPublicKey, PackCompileFailed, PackOlder };

    /// Verify a pack and compile its rules. The old rules stay in place
    /// when the new pack is refused.
    pub fn loadPack(self: *Scanner, pack_json: []const u8) LoadError!void {
        const key = self.public_key orelse return error.NoPublicKey;
        const pack = try rule_pack.verify(self.alloc, pack_json, key);
        defer rule_pack.deinitPack(self.alloc, pack);
        if (self.rules != null and pack.version < self.pack_version) return error.PackOlder;
        switch (try yara.compile(self.alloc, pack.source)) {
            .ok => |r| {
                if (self.rules) |*old| old.deinit();
                self.rules = r;
                self.pack_version = pack.version;
            },
            .failed => |msg| {
                std.debug.print("yara pack {d} did not compile: {s}\n", .{ pack.version, msg });
                self.alloc.free(msg);
                return error.PackCompileFailed;
            },
        }
    }

    /// Scan one file. Returns `yara_match` payloads (one per matching rule).
    pub fn scanPath(self: *Scanner, path: []const u8, trigger: Trigger) ![][]u8 {
        var out: std.ArrayList([]u8) = .empty;
        errdefer {
            for (out.items) |p| self.alloc.free(p);
            out.deinit(self.alloc);
        }
        const rules = if (self.rules) |*r| r else return out.toOwnedSlice(self.alloc);
        const data = yara.readCapped(self.alloc, path, self.options.max_file_bytes) catch |err| switch (err) {
            error.FileTooLarge, error.FileNotFound, error.AccessDenied, error.IsDir => return out.toOwnedSlice(self.alloc),
            else => return err,
        };
        defer self.alloc.free(data);
        const matches = rules.scanBuffer(self.alloc, data, self.options) catch |err| switch (err) {
            error.YaraTimeout => {
                std.debug.print("yara scan of {s} timed out\n", .{path});
                return out.toOwnedSlice(self.alloc);
            },
            else => return err,
        };
        defer yara.freeMatches(self.alloc, matches);
        if (matches.len == 0) return out.toOwnedSlice(self.alloc);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        for (matches) |m| {
            try out.append(self.alloc, try matchPayload(self.alloc, m, path, &hex, data.len, trigger, self.pack_version));
        }
        return out.toOwnedSlice(self.alloc);
    }

    /// Scan regular files directly in `folder` (not recursive), up to
    /// `max_files_per_folder`.
    pub fn scanFolder(self: *Scanner, folder: []const u8, trigger: Trigger) ![][]u8 {
        var out: std.ArrayList([]u8) = .empty;
        errdefer {
            for (out.items) |p| self.alloc.free(p);
            out.deinit(self.alloc);
        }
        if (self.rules == null) return out.toOwnedSlice(self.alloc);
        const io = iox.current();
        var dir = std.Io.Dir.cwd().openDir(io, folder, .{ .iterate = true }) catch return out.toOwnedSlice(self.alloc);
        defer dir.close(io);
        var it = dir.iterate();
        var n: usize = 0;
        while (it.next(io) catch null) |entry| {
            if (entry.kind != .file) continue;
            n += 1;
            if (n > max_files_per_folder) break;
            const full = try std.fs.path.join(self.alloc, &.{ folder, entry.name });
            defer self.alloc.free(full);
            const got = try self.scanPath(full, trigger);
            defer self.alloc.free(got);
            try out.appendSlice(self.alloc, got);
        }
        return out.toOwnedSlice(self.alloc);
    }

    /// File events (fs_events payloads) to scan results.
    pub fn onFileEvents(self: *Scanner, events: []const []const u8) ![][]u8 {
        var out: std.ArrayList([]u8) = .empty;
        errdefer {
            for (out.items) |p| self.alloc.free(p);
            out.deinit(self.alloc);
        }
        if (self.rules == null) return out.toOwnedSlice(self.alloc);
        for (events) |ev| {
            const parsed = std.json.parseFromSlice(struct {
                path: []const u8 = "",
                action: []const u8 = "",
                is_directory: bool = false,
            }, self.alloc, ev, .{ .ignore_unknown_fields = true }) catch continue;
            defer parsed.deinit();
            if (!wantsScan(parsed.value.path, parsed.value.action, parsed.value.is_directory)) continue;
            const got = try self.scanPath(parsed.value.path, .file_event);
            defer self.alloc.free(got);
            try out.appendSlice(self.alloc, got);
        }
        return out.toOwnedSlice(self.alloc);
    }
};

pub fn matchPayload(alloc: std.mem.Allocator, m: yara.Match, path: []const u8, sha256_hex: []const u8, size: usize, trigger: Trigger, pack_version: u64) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;
    try w.writeAll("{\"rule\":");
    try std.json.Stringify.value(m.rule, .{}, w);
    try w.writeAll(",\"tags\":[");
    for (m.tags, 0..) |t, i| {
        if (i > 0) try w.writeAll(",");
        try std.json.Stringify.value(t, .{}, w);
    }
    try w.writeAll("],\"file\":{\"path\":");
    try std.json.Stringify.value(path, .{}, w);
    try w.writeAll(",\"name\":");
    try std.json.Stringify.value(std.fs.path.basename(path), .{}, w);
    try w.print(",\"size\":{d},\"hashes\":{{\"sha256\":\"{s}\"}}}},\"trigger\":\"{s}\",\"pack_version\":{d}}}", .{ size, sha256_hex, @tagName(trigger), pack_version });
    return out.toOwnedSlice();
}

test "scheduled folders per platform" {
    const a = std.testing.allocator;
    const Fake = struct {
        pub fn get(_: *@This(), name: [:0]const u8) ?[]const u8 {
            if (std.mem.eql(u8, name, "HOME")) return "/home/u";
            if (std.mem.eql(u8, name, "TEMP")) return "C:\\Temp";
            if (std.mem.eql(u8, name, "APPDATA")) return "C:\\Users\\u\\AppData\\Roaming";
            return null;
        }
    };
    var fake: Fake = .{};
    const folders = try scheduledFolders(a, &fake);
    defer {
        for (folders) |f| a.free(f);
        a.free(folders);
    }
    try std.testing.expect(folders.len >= 2);
}

test "scan triggers pick executables and scripts" {
    try std.testing.expect(wantsScan("C:\\Users\\a\\Downloads\\x.EXE", "create", false));
    try std.testing.expect(wantsScan("/tmp/run.sh", "moved_to", false));
    try std.testing.expect(wantsScan("/tmp/payload", "modify", false));
    try std.testing.expect(!wantsScan("/tmp/notes.txt", "create", false));
    try std.testing.expect(!wantsScan("/tmp/x.exe", "delete", false));
    try std.testing.expect(!wantsScan("/tmp/dir.exe", "create", true));
    try std.testing.expect(!wantsScan("/tmp/.hidden", "create", false));
}

test "yara_match payload shape" {
    const a = std.testing.allocator;
    var tags = [_][]u8{@constCast("t1")};
    const p = try matchPayload(a, .{ .rule = @constCast("r"), .tags = &tags }, "/tmp/a b.exe", "ab", 3, .scheduled, 7);
    defer a.free(p);
    try std.testing.expectEqualStrings(
        \\{"rule":"r","tags":["t1"],"file":{"path":"/tmp/a b.exe","name":"a b.exe","size":3,"hashes":{"sha256":"ab"}},"trigger":"scheduled","pack_version":7}
    , p);
}

test "scanner refuses unsigned and tampered packs and keeps the old rules" {
    const a = std.testing.allocator;
    const kp = std.crypto.sign.Ed25519.KeyPair.generate(std.testing.io);
    var s: Scanner = .{ .alloc = a, .public_key = kp.public_key };
    defer s.deinit();
    const pack = try rule_pack.sign(a, kp, "t", 1, "2026-11-10T00:00:00Z", yara.eicar_rule);
    defer a.free(pack);
    const idx = std.mem.indexOf(u8, pack, ",\"signature\"").?;
    const unsigned = try std.mem.concat(a, u8, &.{ pack[0..idx], "}" });
    defer a.free(unsigned);
    try std.testing.expectError(error.PackUnsigned, s.loadPack(unsigned));
    const tampered = try std.mem.replaceOwned(u8, a, pack, "\"version\":1", "\"version\":2");
    defer a.free(tampered);
    try std.testing.expectError(error.PackBadSignature, s.loadPack(tampered));
    try std.testing.expect(s.rules == null);
    var none: Scanner = .{ .alloc = a, .public_key = null };
    try std.testing.expectError(error.NoPublicKey, none.loadPack(pack));
    if (!yara.enabled) {
        try std.testing.expectError(error.YaraUnavailable, s.loadPack(pack));
        return;
    }
    try s.loadPack(pack);
    try std.testing.expect(s.rules != null);
    // A tampered pack after a good one leaves the good rules in place.
    try std.testing.expectError(error.PackBadSignature, s.loadPack(tampered));
    try std.testing.expectEqual(@as(u64, 1), s.pack_version);
}

test "EICAR written to a watched folder is detected through file events" {
    if (!yara.enabled) return error.SkipZigTest;
    if (builtin.target.os.tag != .linux and builtin.target.os.tag != .macos) return error.SkipZigTest;
    const fs_events = @import("collectors/fs_events.zig");
    const a = std.testing.allocator;
    const io = iox.current();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const folder = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(folder);

    const kp = std.crypto.sign.Ed25519.KeyPair.generate(std.testing.io);
    var s: Scanner = .{ .alloc = a, .public_key = kp.public_key };
    defer s.deinit();
    const pack = try rule_pack.sign(a, kp, "t", 1, "2026-11-10T00:00:00Z", yara.eicar_rule);
    defer a.free(pack);
    try s.loadPack(pack);

    var watcher = try fs_events.Watcher.init(a, &.{folder});
    defer watcher.deinit();
    if (builtin.target.os.tag == .macos) std.Io.sleep(io, .fromMilliseconds(500), .awake) catch {};

    // EICAR built at run time and written into the watched folder.
    var buf: [68]u8 = undefined;
    try tmp.dir.writeFile(io, .{ .sub_path = "dropper.exe", .data = yara.eicar(&buf) });
    try tmp.dir.writeFile(io, .{ .sub_path = "readme.txt", .data = yara.eicar(&buf) });

    var found: ?[]u8 = null;
    defer if (found) |f| a.free(f);
    var tries: usize = 0;
    while (tries < 40 and found == null) : (tries += 1) {
        std.Io.sleep(io, .fromMilliseconds(100), .awake) catch {};
        const events = try watcher.collectEvents();
        defer {
            for (events) |e| a.free(e);
            a.free(events);
        }
        const hits = try s.onFileEvents(events);
        defer a.free(hits);
        for (hits) |h| {
            // Only the .exe is a scan target; the .txt is not.
            try std.testing.expect(std.mem.indexOf(u8, h, "readme.txt") == null);
            if (found == null) found = h else a.free(h);
        }
    }
    const hit = found orelse return error.EicarNotDetected;
    try std.testing.expect(std.mem.indexOf(u8, hit, "\"rule\":\"eicar_test_file\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, hit, "dropper.exe") != null);
    try std.testing.expect(std.mem.indexOf(u8, hit, "\"trigger\":\"file_event\"") != null);
    // SHA-256 of the 68-byte EICAR string.
    try std.testing.expect(std.mem.indexOf(u8, hit, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") != null);
    std.debug.print("yara_eicar_file_event {s}\n", .{hit});
}

test "scheduled folder scan and the response-action path" {
    if (!yara.enabled) return error.SkipZigTest;
    const a = std.testing.allocator;
    const io = iox.current();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const folder = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(folder);
    const kp = std.crypto.sign.Ed25519.KeyPair.generate(std.testing.io);
    var s: Scanner = .{ .alloc = a, .public_key = kp.public_key };
    defer s.deinit();
    const pack = try rule_pack.sign(a, kp, "t", 2, "2026-11-10T00:00:00Z", yara.eicar_rule);
    defer a.free(pack);
    try s.loadPack(pack);
    var buf: [68]u8 = undefined;
    try tmp.dir.writeFile(io, .{ .sub_path = "a.txt", .data = yara.eicar(&buf) });
    try tmp.dir.writeFile(io, .{ .sub_path = "b.bin", .data = "clean" });
    const hits = try s.scanFolder(folder, .scheduled);
    defer {
        for (hits) |h| a.free(h);
        a.free(hits);
    }
    try std.testing.expectEqual(@as(usize, 1), hits.len);
    try std.testing.expect(std.mem.indexOf(u8, hits[0], "\"trigger\":\"scheduled\"") != null);
}
