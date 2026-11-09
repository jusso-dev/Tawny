//! Debug subcommands that drive the response actions from CI without a server
//! (#57). Windows CI starts a process, then calls these to kill it by PID and
//! start time, suspend and resume a child, and quarantine and restore a file.
//! Like `--eventlog-dump`, these are plumbing for tests, not a product surface.
//!
//! Usage (argv after the program name):
//!   --kill-pid <pid> [<image_path> <start_unix>]
//!   --suspend-pid <pid>
//!   --resume-pid <pid>
//!   --quarantine <path> <sha256_hex> <dir>
//!   --restore <sha256_hex> <dir>
//!
//! Each prints one status line and returns 0 on success.

const std = @import("std");
const builtin = @import("builtin");
const quarantine = @import("quarantine.zig");
const wfp = @import("platform/windows/wfp.zig");
const process_control = if (builtin.target.os.tag == .windows)
    @import("platform/windows/process_control.zig")
else
    struct {};

pub fn isDebugCommand(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "--kill-pid") or
        std.mem.eql(u8, arg, "--suspend-pid") or
        std.mem.eql(u8, arg, "--resume-pid") or
        std.mem.eql(u8, arg, "--quarantine") or
        std.mem.eql(u8, arg, "--restore") or
        std.mem.eql(u8, arg, "--wfp-selftest");
}

/// `args` is argv[1..]. Returns a process exit code.
pub fn run(alloc: std.mem.Allocator, args: []const []const u8) u8 {
    if (args.len == 0) return usage();
    const cmd = args[0];

    if (std.mem.eql(u8, cmd, "--wfp-selftest")) {
        return wfpSelftest();
    }

    if (std.mem.eql(u8, cmd, "--quarantine")) {
        if (args.len != 4) return usage();
        const rec = quarantine.quarantine(alloc, args[3], args[1], args[2]) catch |err| {
            std.debug.print("quarantine failed: {s}\n", .{@errorName(err)});
            return 1;
        };
        std.debug.print("quarantined sha256={s} size={d}\n", .{ &rec.sha256, rec.size });
        return 0;
    }
    if (std.mem.eql(u8, cmd, "--restore")) {
        if (args.len != 3) return usage();
        const original = quarantine.restore(alloc, args[2], args[1]) catch |err| {
            std.debug.print("restore failed: {s}\n", .{@errorName(err)});
            return 1;
        };
        defer alloc.free(original);
        std.debug.print("restored path={s}\n", .{original});
        return 0;
    }

    // Process actions.
    if (builtin.target.os.tag != .windows) {
        std.debug.print("process debug commands are Windows only\n", .{});
        return 2;
    }
    if (args.len < 2) return usage();
    const pid = std.fmt.parseInt(u32, args[1], 10) catch {
        std.debug.print("bad pid\n", .{});
        return 2;
    };
    var id = process_control.Identity{};
    if (std.mem.eql(u8, cmd, "--kill-pid") and args.len >= 4) {
        id.image_path = args[2];
        id.start_time_unix = std.fmt.parseInt(i64, args[3], 10) catch null;
    }
    const outcome = if (std.mem.eql(u8, cmd, "--kill-pid"))
        process_control.kill(alloc, pid, id)
    else if (std.mem.eql(u8, cmd, "--suspend-pid"))
        process_control.suspend_(alloc, pid, id)
    else if (std.mem.eql(u8, cmd, "--resume-pid"))
        process_control.resume_(alloc, pid, id)
    else
        return usage();

    const o = outcome catch |err| {
        std.debug.print("{s} failed: {s}\n", .{ cmd, @errorName(err) });
        return 1;
    };
    std.debug.print("{s} ok: {s}\n", .{ cmd, @tagName(o) });
    return 0;
}

/// Safe live WFP test for CI: add one block filter for a TEST-NET address
/// (never a block-all, so it can't cut the runner off), confirm it is present,
/// confirm a routable address stays reachable, then release and confirm the
/// sublayer is empty. Windows only.
fn wfpSelftest() u8 {
    if (builtin.target.os.tag != .windows) {
        std.debug.print("wfp-selftest is Windows only\n", .{});
        return 2;
    }
    wfp.release() catch {}; // clean slate
    const id = wfp.addTestBlock("192.0.2.1") catch |err| {
        std.debug.print("wfp addTestBlock failed: {s}\n", .{@errorName(err)});
        return 1;
    };
    const count_after_add = wfp.countFilters() catch 0;
    if (count_after_add < 1) {
        std.debug.print("wfp filter not present after add\n", .{});
        _ = wfp.release() catch {};
        return 1;
    }
    // TEST-NET should not connect; a routable address must still work, proving
    // the single block did not over-block.
    const blocked_unreachable = !wfp.tcpReachable("192.0.2.1", 9, 1500);
    const internet_up = wfp.tcpReachable("1.1.1.1", 443, 4000);
    wfp.release() catch |err| {
        std.debug.print("wfp release failed: {s}\n", .{@errorName(err)});
        return 1;
    };
    const count_after_release = wfp.countFilters() catch 0;
    std.debug.print(
        "wfp-selftest id={d} count_after_add={d} blocked_unreachable={} internet_up={} count_after_release={d}\n",
        .{ id, count_after_add, blocked_unreachable, internet_up, count_after_release },
    );
    if (count_after_release != 0) {
        std.debug.print("wfp filters remain after release\n", .{});
        return 1;
    }
    // Over-blocking (internet down) is a failure; the TEST-NET block itself is
    // unverifiable against a baseline, so it is reported, not asserted.
    if (!internet_up) {
        std.debug.print("wfp over-blocked: routable address unreachable\n", .{});
        return 1;
    }
    return 0;
}

fn usage() u8 {
    std.debug.print("usage: --kill-pid <pid> [<image> <start>] | --suspend-pid <pid> | --resume-pid <pid> | --quarantine <path> <sha256> <dir> | --restore <sha256> <dir> | --wfp-selftest\n", .{});
    return 2;
}
