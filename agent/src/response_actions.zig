//! Response actions (#57). Every action the server sends is signed; the agent
//! verifies the signature against the pinned action key before it runs
//! anything, journals the action for dedupe and restart replay, then dispatches
//! to the platform handler. Results are reported to the server and retried
//! until acked (the server redelivers pending actions on each heartbeat).

const std = @import("std");
const builtin = @import("builtin");
const transport = @import("transport/http.zig");
const iox = @import("io_compat.zig");
const action_sig = @import("action_sig.zig");
const action_key = @import("action_key.zig");
const journal_mod = @import("action_journal.zig");
const quarantine = @import("quarantine.zig");
const Ed25519 = std.crypto.sign.Ed25519;
const process_control = if (builtin.target.os.tag == .windows)
    @import("platform/windows/process_control.zig")
else
    struct {};

pub const Context = struct {
    alloc: std.mem.Allocator,
    http: *transport.Client,
    agent_id: []const u8,
    public_key: ?Ed25519.PublicKey,
    journal: *journal_mod.Journal,
    quarantine_dir: []const u8,
};

const Result = struct {
    status: []const u8,
    message: []const u8,
    /// message is heap-owned and must be freed.
    owned: bool = false,
};

fn ok(msg: []const u8) Result {
    return .{ .status = "succeeded", .message = msg };
}
fn fail(msg: []const u8) Result {
    return .{ .status = "failed", .message = msg };
}

/// Run one action: dedupe, verify, journal, dispatch, report.
pub fn execute(ctx: Context, action: transport.ResponseAction) void {
    // Dedupe and restart replay. A finished action is reported again with the
    // fresh token from this dispatch, not re-run.
    if (ctx.journal.read(action.id)) |entry| {
        defer ctx.journal.freeEntry(entry);
        if (entry.state == .done) {
            if (report(ctx.http, action, entry.status, entry.message)) {
                ctx.journal.clear(action.id);
            }
            return;
        }
        // state == running: the agent crashed mid-action. The handlers are
        // idempotent (kill of a gone process, quarantine by hash), so re-run.
    }

    // Verify the server signature before doing anything.
    const fields = action_sig.Fields{
        .action_id = action.id,
        .agent_id = ctx.agent_id,
        .action_type = action.action_type,
        .expires_at = action.expires_at,
        .payload = action.payload,
        .payload_hash = action.payload_hash,
        .signature = action.signature,
    };
    action_sig.verify(ctx.alloc, fields, ctx.public_key, iox.timestamp()) catch |err| {
        const reason = switch (err) {
            error.ActionUnsigned => "action has no server signature",
            error.ActionExpired => "action expired before execution",
            error.ActionPayloadMismatch => "action payload does not match its signed hash",
            error.ActionSignatureInvalid => "action signature did not verify",
            error.ActionKeyMissing => "no pinned server action key",
            error.OutOfMemory => "out of memory verifying action",
        };
        _ = report(ctx.http, action, "failed", reason);
        return;
    };

    ctx.journal.begin(action.id, action.action_type) catch {};

    const result = dispatch(ctx, action);
    defer if (result.owned) ctx.alloc.free(result.message);

    ctx.journal.finish(action.id, action.action_type, result.status, result.message) catch {};
    if (report(ctx.http, action, result.status, result.message)) {
        ctx.journal.clear(action.id);
    }
}

fn dispatch(ctx: Context, action: transport.ResponseAction) Result {
    const t = action.action_type;
    if (std.mem.eql(u8, t, "kill_process")) return processAction(ctx, action, .kill);
    if (std.mem.eql(u8, t, "suspend_process")) return processAction(ctx, action, .do_suspend);
    if (std.mem.eql(u8, t, "resume_process")) return processAction(ctx, action, .do_resume);
    if (std.mem.eql(u8, t, "quarantine_file")) return quarantineAction(ctx, action);
    if (std.mem.eql(u8, t, "restore_file")) return restoreAction(ctx, action);
    if (std.mem.eql(u8, t, "isolate_host") or std.mem.eql(u8, t, "isolate"))
        return fail(isolate_unsupported_message);
    if (std.mem.eql(u8, t, "release"))
        return fail("release is not supported on this agent build");
    return fail("unknown response action");
}

/// The message the Linux e2e agent returns for isolate_host until #59 adds
/// nftables isolation. Contract tests assert on this exact string.
pub const isolate_unsupported_message = "isolate_host is not supported on linux yet (nftables isolation lands in #59)";

const ProcessOp = enum { kill, do_suspend, do_resume };

const ProcessPayload = struct {
    pid: i32,
    image_path: ?[]const u8 = null,
    start_time_unix: ?i64 = null,
    image_hash: ?[]const u8 = null,
    command_line: ?[]const u8 = null,
};

fn processAction(ctx: Context, action: transport.ResponseAction, op: ProcessOp) Result {
    const parsed = std.json.parseFromSlice(ProcessPayload, ctx.alloc, action.payload, .{ .ignore_unknown_fields = true }) catch
        return fail("invalid process action payload");
    defer parsed.deinit();
    const p = parsed.value;
    if (p.pid <= 0) return fail("process action needs a positive pid");

    if (builtin.target.os.tag == .windows) {
        const id = process_control.Identity{ .image_path = p.image_path, .start_time_unix = p.start_time_unix };
        const outcome = switch (op) {
            .kill => process_control.kill(ctx.alloc, @intCast(p.pid), id),
            .do_suspend => process_control.suspend_(ctx.alloc, @intCast(p.pid), id),
            .do_resume => process_control.resume_(ctx.alloc, @intCast(p.pid), id),
        } catch |err| return fail(processErrorReason(err));
        return switch (outcome) {
            .already_gone => ok("process already gone"),
            .done => switch (op) {
                .kill => ok("process terminated"),
                .do_suspend => ok("process suspended"),
                .do_resume => ok("process resumed"),
            },
        };
    }

    // POSIX: identity guard is Linux /proc backed; macOS fails closed when
    // identity is requested.
    if (p.image_path != null or p.start_time_unix != null) {
        assertProcessIdentity(ctx.alloc, p.pid, p.image_path, p.start_time_unix) catch |err|
            return fail(@errorName(err));
    }
    const sig = switch (op) {
        .kill => std.posix.SIG.TERM,
        .do_suspend => std.posix.SIG.STOP,
        .do_resume => std.posix.SIG.CONT,
    };
    std.posix.kill(p.pid, sig) catch |err| switch (err) {
        error.ProcessNotFound => return ok("process already gone"),
        else => return fail(@errorName(err)),
    };
    return switch (op) {
        .kill => ok("process termination signal sent"),
        .do_suspend => ok("process suspended"),
        .do_resume => ok("process resumed"),
    };
}

fn processErrorReason(err: anyerror) []const u8 {
    return switch (err) {
        error.CriticalProcessRefused => "refused: target is a critical system process",
        error.ProcessIdentityMismatch => "refused: process identity no longer matches (possible PID reuse)",
        error.ProcessIdentityUnavailable => "could not confirm process identity",
        error.InvalidPid => "process action needs a positive pid",
        else => @errorName(err),
    };
}

const FilePayload = struct {
    path: ?[]const u8 = null,
    sha256: ?[]const u8 = null,
};

fn quarantineAction(ctx: Context, action: transport.ResponseAction) Result {
    const parsed = std.json.parseFromSlice(FilePayload, ctx.alloc, action.payload, .{ .ignore_unknown_fields = true }) catch
        return fail("invalid quarantine payload");
    defer parsed.deinit();
    const path = parsed.value.path orelse return fail("quarantine_file needs a path");
    const sha = parsed.value.sha256 orelse return fail("quarantine_file needs a sha256");
    const rec = quarantine.quarantine(ctx.alloc, ctx.quarantine_dir, path, sha) catch |err| return switch (err) {
        error.HashMismatch => fail("refused: file hash does not match the action"),
        error.FileTooBig => fail("file too large to quarantine"),
        error.QuarantineVerifyFailed => fail("quarantine copy failed verification"),
        else => fail(@errorName(err)),
    };
    const msg = std.fmt.allocPrint(ctx.alloc, "quarantined {s} ({d} bytes)", .{ rec.sha256[0..16], rec.size }) catch
        return ok("quarantined");
    return .{ .status = "succeeded", .message = msg, .owned = true };
}

fn restoreAction(ctx: Context, action: transport.ResponseAction) Result {
    const parsed = std.json.parseFromSlice(FilePayload, ctx.alloc, action.payload, .{ .ignore_unknown_fields = true }) catch
        return fail("invalid restore payload");
    defer parsed.deinit();
    const sha = parsed.value.sha256 orelse return fail("restore_file needs a sha256");
    const original = quarantine.restore(ctx.alloc, ctx.quarantine_dir, sha) catch |err| return switch (err) {
        error.SidecarMissing => fail("no quarantined file for that sha256"),
        error.QuarantineVerifyFailed => fail("quarantine copy failed verification"),
        else => fail(@errorName(err)),
    };
    defer ctx.alloc.free(original);
    const msg = std.fmt.allocPrint(ctx.alloc, "restored to {s}", .{original}) catch return ok("restored");
    return .{ .status = "succeeded", .message = msg, .owned = true };
}

/// Refuse kill/suspend/resume when optional identity fields no longer match
/// the live process (PID reuse). Windows delegates to the process_control
/// identity check so it no longer fails closed; POSIX uses /proc on Linux.
fn assertProcessIdentity(
    alloc: std.mem.Allocator,
    pid: i32,
    expected_path: ?[]const u8,
    expected_start: ?i64,
) !void {
    if (builtin.target.os.tag == .windows) {
        // process_control re-checks inside its open; nothing to do here.
        return;
    }
    if (builtin.target.os.tag != .linux) {
        if (expected_path != null or expected_start != null) return error.ProcessIdentityUnavailable;
        return;
    }

    if (expected_path) |want| {
        const actual = try readLinuxProcessImagePath(alloc, pid);
        defer alloc.free(actual);
        if (!pathsMatch(want, actual)) return error.ProcessIdentityMismatch;
    }

    if (expected_start) |want_start| {
        const actual_start = try readLinuxProcessStartUnix(pid);
        if (@abs(actual_start - want_start) > 2) return error.ProcessIdentityMismatch;
    }
}

fn pathsMatch(expected: []const u8, actual: []const u8) bool {
    if (std.mem.eql(u8, expected, actual)) return true;
    const exp_base = std.fs.path.basename(expected);
    const act_base = std.fs.path.basename(actual);
    return std.mem.eql(u8, exp_base, act_base);
}

fn readLinuxProcessImagePath(alloc: std.mem.Allocator, pid: i32) ![]u8 {
    var path_buf: [64]u8 = undefined;
    const link_path = try std.fmt.bufPrint(&path_buf, "/proc/{d}/exe", .{pid});
    var target_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = std.Io.Dir.readLinkAbsolute(iox.current(), link_path, &target_buf) catch
        return error.ProcessIdentityMismatch;
    return try alloc.dupe(u8, target_buf[0..n]);
}

fn readLinuxProcessStartUnix(pid: i32) !i64 {
    var path_buf: [64]u8 = undefined;
    const stat_path = try std.fmt.bufPrint(&path_buf, "/proc/{d}/stat", .{pid});
    const io = iox.current();
    const file = std.Io.Dir.cwd().openFile(io, stat_path, .{}) catch return error.ProcessIdentityMismatch;
    defer file.close(io);
    var buf: [512]u8 = undefined;
    const n = try file.readPositionalAll(io, &buf, 0);
    const start = parseLinuxStatStarttime(buf[0..n]) orelse return error.ProcessIdentityMismatch;
    const boot = try readBtime();
    const hz: i64 = 100;
    return boot + @divTrunc(start, hz);
}

fn parseLinuxStatStarttime(stat: []const u8) ?i64 {
    const rparen = std.mem.lastIndexOfScalar(u8, stat, ')') orelse return null;
    const rest = std.mem.trimStart(u8, stat[rparen + 1 ..], " ");
    var it = std.mem.tokenizeScalar(u8, rest, ' ');
    var i: usize = 0;
    while (it.next()) |tok| : (i += 1) {
        if (i == 19) {
            return std.fmt.parseInt(i64, tok, 10) catch null;
        }
    }
    return null;
}

fn readBtime() !i64 {
    const io = iox.current();
    const file = try std.Io.Dir.cwd().openFile(io, "/proc/stat", .{});
    defer file.close(io);
    const raw = try iox.readToEndAlloc(file, std.heap.page_allocator, 64 * 1024);
    defer std.heap.page_allocator.free(raw);
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "btime ")) {
            return std.fmt.parseInt(i64, std.mem.trim(u8, line["btime ".len..], " \t"), 10) catch return error.ProcessIdentityMismatch;
        }
    }
    return error.ProcessIdentityMismatch;
}

/// Report a result. Returns true when the server acked it (so the journal
/// entry can be cleared). A failed report leaves the entry for the next
/// heartbeat to retry.
fn report(http: *transport.Client, action: transport.ResponseAction, status: []const u8, message: []const u8) bool {
    http.reportActionResult(action.id, action.execution_token, status, message) catch |err| {
        std.debug.print("response action {s} result report failed: {s}\n", .{ action.id, @errorName(err) });
        return false;
    };
    return true;
}

test "pure helpers compile on every OS" {
    _ = action_sig;
    _ = action_key;
    _ = journal_mod;
    _ = quarantine;
    try std.testing.expect(pathsMatch("/usr/bin/evil", "evil"));
    try std.testing.expect(!pathsMatch("/usr/bin/a", "/usr/bin/b"));
}
