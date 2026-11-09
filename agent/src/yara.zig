//! YARA scanning through libyara (built in with `zig build -Dyara=true`).
//!
//! Without `-Dyara=true` every call returns `error.YaraUnavailable`, so the
//! default agent build has no C dependency. Rules are compiled from source
//! that has passed `rule_pack.verify` (signed by the server).
//!
//! Scans have a timeout (seconds, enforced by libyara) and a size cap: files
//! larger than `max_file_bytes` are not read.

const std = @import("std");
const build_options = @import("build_options");
const iox = @import("io_compat.zig");

pub const enabled = build_options.yara;

pub const default_timeout_seconds: u32 = 10;
pub const default_max_file_bytes: u64 = 64 * 1024 * 1024;

pub const Error = error{
    YaraUnavailable,
    YaraInit,
    YaraCompile,
    YaraScan,
    YaraTimeout,
    FileTooLarge,
    OutOfMemory,
};

pub const Match = struct {
    rule: []u8,
    tags: [][]u8,

    pub fn deinit(self: Match, alloc: std.mem.Allocator) void {
        alloc.free(self.rule);
        for (self.tags) |t| alloc.free(t);
        alloc.free(self.tags);
    }
};

pub fn freeMatches(alloc: std.mem.Allocator, matches: []Match) void {
    for (matches) |m| m.deinit(alloc);
    alloc.free(matches);
}

pub const Options = struct {
    timeout_seconds: u32 = default_timeout_seconds,
    max_file_bytes: u64 = default_max_file_bytes,
};

// --- libyara externs (only referenced when enabled) --------------------------

const c = struct {
    const YR_COMPILER = opaque {};
    const YR_RULES = opaque {};
    const YR_SCAN_CONTEXT = opaque {};
    /// Leading fields of YR_RULE (libyara/include/yara/types.h). Only
    /// `identifier` and `tags` are read; both are plain pointers after load.
    const YR_RULE = extern struct {
        flags: i32,
        num_atoms: i32,
        required_strings: u32,
        unused: u32,
        identifier: ?[*:0]const u8,
        tags: ?[*:0]const u8,
    };
    const CompilerCallback = *const fn (c_int, ?[*:0]const u8, c_int, ?*const YR_RULE, ?[*:0]const u8, ?*anyopaque) callconv(.c) void;
    const ScanCallback = *const fn (?*YR_SCAN_CONTEXT, c_int, ?*anyopaque, ?*anyopaque) callconv(.c) c_int;

    extern fn yr_initialize() c_int;
    extern fn yr_finalize() c_int;
    extern fn yr_compiler_create(compiler: *?*YR_COMPILER) c_int;
    extern fn yr_compiler_destroy(compiler: *YR_COMPILER) void;
    extern fn yr_compiler_set_callback(compiler: *YR_COMPILER, cb: CompilerCallback, user: ?*anyopaque) void;
    extern fn yr_compiler_add_string(compiler: *YR_COMPILER, rules: [*:0]const u8, namespace: ?[*:0]const u8) c_int;
    extern fn yr_compiler_get_rules(compiler: *YR_COMPILER, rules: *?*YR_RULES) c_int;
    extern fn yr_rules_destroy(rules: *YR_RULES) c_int;
    extern fn yr_rules_scan_mem(rules: *YR_RULES, buffer: [*]const u8, len: usize, flags: c_int, cb: ScanCallback, user: ?*anyopaque, timeout: c_int) c_int;

    const ERROR_SUCCESS = 0;
    const ERROR_SCAN_TIMEOUT = 26;
    const CALLBACK_MSG_RULE_MATCHING = 1;
    const CALLBACK_CONTINUE = 0;
    const CALLBACK_ERROR = 2;
    const SCAN_FLAGS_FAST_MODE = 1;
};

// yr_initialize and yr_finalize are reference counted inside libyara but
// not thread safe. A spin lock keeps the counter and the calls together.
var init_lock: std.atomic.Mutex = .unlocked;
var init_count: usize = 0;

fn lock() void {
    while (!init_lock.tryLock()) std.atomic.spinLoopHint();
}

fn acquire() Error!void {
    if (!enabled) return error.YaraUnavailable;
    lock();
    defer init_lock.unlock();
    if (init_count == 0) {
        if (c.yr_initialize() != c.ERROR_SUCCESS) return error.YaraInit;
    }
    init_count += 1;
}

fn release() void {
    if (!enabled) return;
    lock();
    defer init_lock.unlock();
    init_count -= 1;
    if (init_count == 0) _ = c.yr_finalize();
}

/// Compiled rules. Create with `compile`, free with `deinit`.
pub const Rules = struct {
    handle: if (enabled) *c.YR_RULES else void,

    pub fn deinit(self: *Rules) void {
        if (!enabled) return;
        _ = c.yr_rules_destroy(self.handle);
        release();
    }

    /// Scan a buffer. The caller frees the matches with `freeMatches`.
    pub fn scanBuffer(self: *const Rules, alloc: std.mem.Allocator, data: []const u8, opts: Options) Error![]Match {
        if (!enabled) return error.YaraUnavailable;
        var ctx: ScanCtx = .{ .alloc = alloc };
        errdefer ctx.deinit();
        const timeout: c_int = @intCast(@min(opts.timeout_seconds, 3600));
        const rc = c.yr_rules_scan_mem(self.handle, if (data.len == 0) @as([*]const u8, @ptrCast("")) else data.ptr, data.len, c.SCAN_FLAGS_FAST_MODE, scanCallback, &ctx, timeout);
        if (ctx.oom) return error.OutOfMemory;
        if (rc == c.ERROR_SCAN_TIMEOUT) return error.YaraTimeout;
        if (rc != c.ERROR_SUCCESS) return error.YaraScan;
        return ctx.matches.toOwnedSlice(alloc);
    }

    /// Read a file (at most `opts.max_file_bytes`) and scan it. Files are
    /// read into memory rather than mapped, so a file that changes while it
    /// is scanned can't fault the agent.
    pub fn scanFile(self: *const Rules, alloc: std.mem.Allocator, path: []const u8, opts: Options) (Error || anyerror)![]Match {
        if (!enabled) return error.YaraUnavailable;
        const data = try readCapped(alloc, path, opts.max_file_bytes);
        defer alloc.free(data);
        return self.scanBuffer(alloc, data, opts);
    }
};

/// Read a whole file, refusing files over `max` bytes.
pub fn readCapped(alloc: std.mem.Allocator, path: []const u8, max: u64) ![]u8 {
    const io = iox.current();
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const st = try file.stat(io);
    if (st.size > max) return error.FileTooLarge;
    const buf = try alloc.alloc(u8, @intCast(st.size));
    errdefer alloc.free(buf);
    const n = try file.readPositionalAll(io, buf, 0);
    if (n != buf.len) return alloc.realloc(buf, n);
    return buf;
}

const ScanCtx = struct {
    alloc: std.mem.Allocator,
    matches: std.ArrayList(Match) = .empty,
    oom: bool = false,

    fn deinit(self: *ScanCtx) void {
        for (self.matches.items) |m| m.deinit(self.alloc);
        self.matches.deinit(self.alloc);
    }
};

fn scanCallback(_: ?*c.YR_SCAN_CONTEXT, message: c_int, data: ?*anyopaque, user: ?*anyopaque) callconv(.c) c_int {
    if (message != c.CALLBACK_MSG_RULE_MATCHING) return c.CALLBACK_CONTINUE;
    const ctx: *ScanCtx = @ptrCast(@alignCast(user.?));
    const rule: *const c.YR_RULE = @ptrCast(@alignCast(data.?));
    addMatch(ctx, rule) catch {
        ctx.oom = true;
        return c.CALLBACK_ERROR;
    };
    return c.CALLBACK_CONTINUE;
}

fn addMatch(ctx: *ScanCtx, rule: *const c.YR_RULE) !void {
    if (ctx.matches.items.len >= 256) return;
    const name = try ctx.alloc.dupe(u8, std.mem.span(rule.identifier orelse ""));
    errdefer ctx.alloc.free(name);
    var tags: std.ArrayList([]u8) = .empty;
    errdefer {
        for (tags.items) |t| ctx.alloc.free(t);
        tags.deinit(ctx.alloc);
    }
    if (rule.tags) |first| {
        var p: [*:0]const u8 = first;
        while (p[0] != 0 and tags.items.len < 32) {
            const t = std.mem.span(p);
            try tags.append(ctx.alloc, try ctx.alloc.dupe(u8, t));
            p += t.len + 1;
        }
    }
    try ctx.matches.append(ctx.alloc, .{ .rule = name, .tags = try tags.toOwnedSlice(ctx.alloc) });
}

const CompileCtx = struct {
    alloc: std.mem.Allocator,
    first_error: ?[]u8 = null,
};

fn compilerCallback(level: c_int, _: ?[*:0]const u8, line: c_int, _: ?*const c.YR_RULE, message: ?[*:0]const u8, user: ?*anyopaque) callconv(.c) void {
    if (level != 0) return; // 0 is YARA_ERROR_LEVEL_ERROR; warnings are ignored
    const ctx: *CompileCtx = @ptrCast(@alignCast(user.?));
    if (ctx.first_error != null) return;
    ctx.first_error = std.fmt.allocPrint(ctx.alloc, "line {d}: {s}", .{ line, std.mem.span(message orelse "") }) catch null;
}

pub const CompileResult = union(enum) {
    ok: Rules,
    /// First compiler error. Owned by the caller.
    failed: []u8,
};

/// Compile rule source. On failure the message is owned by the caller.
pub fn compile(alloc: std.mem.Allocator, source: []const u8) Error!CompileResult {
    if (!enabled) return error.YaraUnavailable;
    try acquire();
    var ok = false;
    defer if (!ok) release();
    var compiler: ?*c.YR_COMPILER = null;
    if (c.yr_compiler_create(&compiler) != c.ERROR_SUCCESS) return error.YaraInit;
    defer c.yr_compiler_destroy(compiler.?);
    var ctx: CompileCtx = .{ .alloc = alloc };
    c.yr_compiler_set_callback(compiler.?, compilerCallback, &ctx);
    const z = try alloc.dupeSentinel(u8, source, 0);
    defer alloc.free(z);
    const errors = c.yr_compiler_add_string(compiler.?, z.ptr, null);
    if (errors != 0) {
        return .{ .failed = ctx.first_error orelse try alloc.dupe(u8, "rules did not compile") };
    }
    if (ctx.first_error) |e| alloc.free(e);
    var rules: ?*c.YR_RULES = null;
    if (c.yr_compiler_get_rules(compiler.?, &rules) != c.ERROR_SUCCESS) return error.YaraCompile;
    ok = true;
    return .{ .ok = .{ .handle = rules.? } };
}

// --- tests ---------------------------------------------------------------------

/// EICAR test string, assembled at run time so no file in the repository
/// holds it (antivirus on dev machines and CI would quarantine one).
pub fn eicar(buf: *[68]u8) []const u8 {
    const parts = [_][]const u8{ "X5O!P%@AP[4\\PZX54(P^)7CC)7}", "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!", "$H+H*" };
    var n: usize = 0;
    for (parts) |p| {
        @memcpy(buf[n .. n + p.len], p);
        n += p.len;
    }
    return buf[0..n];
}

/// Rule for the EICAR string, built from pieces for the same reason.
pub const eicar_rule =
    \\rule eicar_test_file : test eicar
    \\{
    \\  strings:
    \\    $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    \\    $b = "X5O!P%@AP"
    \\  condition:
    \\    $a and $b and filesize < 256
    \\}
;

test "yara is unavailable without -Dyara=true" {
    if (enabled) return error.SkipZigTest;
    try std.testing.expectError(error.YaraUnavailable, compile(std.testing.allocator, eicar_rule));
}

test "yara compiles, reports errors and scans the EICAR string in a buffer" {
    if (!enabled) return error.SkipZigTest;
    const a = std.testing.allocator;
    switch (try compile(a, "rule broken { condition: $missing }")) {
        .ok => |*r| {
            var rr = r.*;
            rr.deinit();
            return error.TestUnexpectedResult;
        },
        .failed => |msg| {
            defer a.free(msg);
            try std.testing.expect(msg.len > 0);
        },
    }
    var res = try compile(a, eicar_rule);
    var rules = res.ok;
    defer rules.deinit();
    var buf: [68]u8 = undefined;
    const matches = try rules.scanBuffer(a, eicar(&buf), .{});
    defer freeMatches(a, matches);
    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expectEqualStrings("eicar_test_file", matches[0].rule);
    try std.testing.expectEqual(@as(usize, 2), matches[0].tags.len);
    try std.testing.expectEqualStrings("eicar", matches[0].tags[1]);
    const none = try rules.scanBuffer(a, "nothing to see", .{});
    defer freeMatches(a, none);
    try std.testing.expectEqual(@as(usize, 0), none.len);
    _ = &res;
}

test "yara scanFile honours the size cap" {
    if (!enabled) return error.SkipZigTest;
    const a = std.testing.allocator;
    const io = iox.current();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [68]u8 = undefined;
    try tmp.dir.writeFile(io, .{ .sub_path = "sample.bin", .data = eicar(&buf) });
    const path = try tmp.dir.realPathFileAlloc(io, "sample.bin", a);
    defer a.free(path);
    var res = try compile(a, eicar_rule);
    var rules = res.ok;
    defer rules.deinit();
    const hit = try rules.scanFile(a, path, .{});
    defer freeMatches(a, hit);
    try std.testing.expectEqual(@as(usize, 1), hit.len);
    try std.testing.expectError(error.FileTooLarge, rules.scanFile(a, path, .{ .max_file_bytes = 10 }));
    _ = &res;
}
