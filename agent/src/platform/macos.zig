//! macOS process enumeration via libproc (no `ps` subprocess).
//!
//! proc_listallpids -> proc_pidinfo(PROC_PIDTBSDINFO) for pid/ppid/uid/start
//! time/name, proc_pidpath for the image, sysctl KERN_PROCARGS2 for argv.
//! When not running as root, other users' processes refuse TBSDINFO and
//! PROCARGS2 with EPERM; they still appear with name/ppid/uid from the short
//! BSD info, and their image path (proc_pidpath is not restricted).

const std = @import("std");
pub const libproc = @import("macos/libproc.zig");
pub const parse = @import("macos/parse.zig");

pub const ProcessInfo = struct {
    pid: u32,
    ppid: u32,
    name: []u8,
    command_line: []u8,
    uid: ?u32 = null,
    start_time_unix: ?i64 = null,
    image_path: ?[]u8 = null,
};

/// Maximum argv bytes we join; privacy.sanitizeCommandLine reads at most 32 KiB.
const max_command_line_bytes: usize = 32 * 1024;

/// Reusable scratch buffers for reading per-process details. One instance
/// per collection pass keeps allocations bounded (≈100 KiB) no matter how
/// many processes exist.
pub const DetailReader = struct {
    allocator: std.mem.Allocator,
    args_buf: []u8,
    cmd_buf: []u8,
    path_buf: [libproc.path_max]u8 = undefined,

    pub const Details = struct {
        name: []const u8,
        command_line: []const u8,
        image_path: []const u8,
    };

    pub fn init(alloc: std.mem.Allocator) !DetailReader {
        const args_buf = try alloc.alloc(u8, libproc.procargs_buffer_bytes);
        errdefer alloc.free(args_buf);
        return .{
            .allocator = alloc,
            .args_buf = args_buf,
            .cmd_buf = try alloc.alloc(u8, max_command_line_bytes),
        };
    }

    pub fn deinit(self: *DetailReader) void {
        self.allocator.free(self.args_buf);
        self.allocator.free(self.cmd_buf);
    }

    /// Slices point into the reader's buffers and stay valid until the next call.
    pub fn read(self: *DetailReader, pid: i32, id: *const libproc.Identity, want_args: bool) Details {
        var image_path: []const u8 = libproc.pidPath(pid, &self.path_buf) orelse "";
        var command_line: []const u8 = "";
        if (want_args) {
            if (libproc.procArgs(pid, self.args_buf)) |raw| {
                if (parse.parseProcArgs2(raw, self.cmd_buf)) |args| {
                    command_line = args.command_line;
                    if (image_path.len == 0) image_path = args.exec_path;
                }
            }
        }
        const base = std.fs.path.basename(image_path);
        const name = if (base.len > 0) base else id.name();
        return .{
            .name = if (name.len > 0) name else "unknown",
            .command_line = if (command_line.len > 0) command_line else name,
            .image_path = image_path,
        };
    }
};

pub fn enumerateProcesses(alloc: std.mem.Allocator) ![]ProcessInfo {
    const pids = try libproc.listAllPids(alloc);
    defer alloc.free(pids);

    var reader = try DetailReader.init(alloc);
    defer reader.deinit();

    var list = try std.array_list.Managed(ProcessInfo).initCapacity(alloc, pids.len);
    errdefer {
        freeEntries(alloc, list.items);
        list.deinit();
    }

    for (pids) |pid| {
        if (pid < 0) continue;
        const id = libproc.identity(pid) orelse continue; // exited mid-scan
        const d = reader.read(pid, &id, true);

        const name = try alloc.dupe(u8, d.name);
        errdefer alloc.free(name);
        const command_line = try alloc.dupe(u8, d.command_line);
        errdefer alloc.free(command_line);
        const image_path: ?[]u8 = if (d.image_path.len > 0) try alloc.dupe(u8, d.image_path) else null;

        try list.append(.{
            .pid = id.pid,
            .ppid = id.ppid,
            .name = name,
            .command_line = command_line,
            .uid = id.uid,
            .start_time_unix = if (id.start_sec > 0) @intCast(id.start_sec) else null,
            .image_path = image_path,
        });
    }

    return list.toOwnedSlice();
}

pub fn freeProcesses(alloc: std.mem.Allocator, procs: []ProcessInfo) void {
    freeEntries(alloc, procs);
    alloc.free(procs);
}

fn freeEntries(alloc: std.mem.Allocator, procs: []const ProcessInfo) void {
    for (procs) |p| {
        alloc.free(p.name);
        alloc.free(p.command_line);
        if (p.image_path) |path| alloc.free(path);
    }
}

test "enumerate finds this process with argv, path and start time" {
    const alloc = std.testing.allocator;
    const procs = try enumerateProcesses(alloc);
    defer freeProcesses(alloc, procs);

    const me: u32 = @intCast(std.c.getpid());
    for (procs) |p| {
        if (p.pid != me) continue;
        try std.testing.expect(p.start_time_unix.? > 1_600_000_000);
        try std.testing.expect(p.image_path != null);
        try std.testing.expect(p.command_line.len > 0);
        try std.testing.expectEqual(@as(u32, @intCast(std.c.getuid())), p.uid.?);
        return;
    }
    return error.SelfNotFound;
}
