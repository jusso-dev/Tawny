const std = @import("std");

pub const ProcessInfo = struct {
    pid: u32,
    ppid: u32,
    name: []u8,
    command_line: []u8,
};

const c = @cImport({
    @cInclude("libproc.h");
    @cInclude("sys/proc_info.h");
    @cInclude("sys/sysctl.h");
});

const PROC_PIDPATHINFO_MAXSIZE = 4 * 1024;

pub fn enumerateProcesses(alloc: std.mem.Allocator) ![]ProcessInfo {
    // Size the pid buffer.
    const n = c.proc_listpids(c.PROC_ALL_PIDS, 0, null, 0);
    if (n <= 0) return error.ProcListFailed;

    const pid_buf_bytes = @as(usize, @intCast(n));
    const pid_count = pid_buf_bytes / @sizeOf(c.pid_t);
    const pids = try alloc.alloc(c.pid_t, pid_count);
    defer alloc.free(pids);

    const n2 = c.proc_listpids(c.PROC_ALL_PIDS, 0, pids.ptr, @intCast(pid_buf_bytes));
    if (n2 <= 0) return error.ProcListFailed;
    const actual = @as(usize, @intCast(n2)) / @sizeOf(c.pid_t);

    var list = std.ArrayList(ProcessInfo).init(alloc);
    errdefer {
        for (list.items) |p| {
            alloc.free(p.name);
            alloc.free(p.command_line);
        }
        list.deinit();
    }

    var name_buf: [PROC_PIDPATHINFO_MAXSIZE]u8 = undefined;

    for (pids[0..actual]) |pid| {
        if (pid == 0) continue;
        var info: c.proc_bsdinfo = undefined;
        const got = c.proc_pidinfo(
            pid,
            c.PROC_PIDTBSDINFO,
            0,
            &info,
            @sizeOf(c.proc_bsdinfo),
        );
        if (got != @sizeOf(c.proc_bsdinfo)) continue;

        const name_len = c.proc_name(pid, &name_buf, name_buf.len);
        const name_slice = if (name_len > 0)
            name_buf[0..@as(usize, @intCast(name_len))]
        else
            "unknown";

        const owned = try alloc.dupe(u8, name_slice);
        errdefer alloc.free(owned);
        const command_line = try alloc.dupe(u8, owned);
        errdefer alloc.free(command_line);
        try list.append(.{
            .pid = @intCast(pid),
            .ppid = @intCast(info.pbi_ppid),
            .name = owned,
            .command_line = command_line,
        });
    }

    return list.toOwnedSlice();
}
