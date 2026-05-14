const std = @import("std");

pub const ProcessInfo = struct {
    pid: u32,
    ppid: u32,
    name: []u8,
    command_line: []u8,
};

pub fn enumerateProcesses(alloc: std.mem.Allocator) ![]ProcessInfo {
    var proc_dir = try std.fs.openDirAbsolute("/proc", .{ .iterate = true });
    defer proc_dir.close();

    var list = std.ArrayList(ProcessInfo).init(alloc);
    errdefer {
        for (list.items) |p| {
            alloc.free(p.name);
            alloc.free(p.command_line);
        }
        list.deinit();
    }

    var iter = proc_dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .directory) continue;
        const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;

        const raw_name = readProcText(alloc, pid, "comm") catch try alloc.dupe(u8, "unknown");
        defer alloc.free(raw_name);
        const name = try alloc.dupe(u8, std.mem.trimRight(u8, raw_name, "\r\n"));
        errdefer alloc.free(name);
        const command_line = readCommandLine(alloc, pid) catch try alloc.dupe(u8, name);
        errdefer alloc.free(command_line);
        const ppid = readParentPid(alloc, pid) catch 0;

        try list.append(.{
            .pid = pid,
            .ppid = ppid,
            .name = name,
            .command_line = command_line,
        });
    }

    return list.toOwnedSlice();
}

fn readParentPid(alloc: std.mem.Allocator, pid: u32) !u32 {
    const stat = try readProcText(alloc, pid, "stat");
    defer alloc.free(stat);

    const close = std.mem.lastIndexOfScalar(u8, stat, ')') orelse return error.BadProcStat;
    var fields = std.mem.tokenizeAny(u8, stat[close + 1 ..], " \t\r\n");
    _ = fields.next() orelse return error.BadProcStat; // state
    const ppid = fields.next() orelse return error.BadProcStat;
    return std.fmt.parseInt(u32, ppid, 10);
}

fn readProcText(alloc: std.mem.Allocator, pid: u32, name: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(alloc, "/proc/{d}/{s}", .{ pid, name });
    defer alloc.free(path);
    var file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    return file.readToEndAlloc(alloc, 16 * 1024);
}

fn readCommandLine(alloc: std.mem.Allocator, pid: u32) ![]u8 {
    const raw = try readProcText(alloc, pid, "cmdline");
    defer alloc.free(raw);

    const owned = try alloc.dupe(u8, raw);
    for (owned) |*ch| {
        if (ch.* == 0) ch.* = ' ';
    }

    const trimmed = std.mem.trimRight(u8, owned, " ");
    if (trimmed.len == owned.len) {
        return owned;
    }

    const compact = try alloc.dupe(u8, trimmed);
    alloc.free(owned);
    return compact;
}
