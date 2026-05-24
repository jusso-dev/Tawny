const std = @import("std");
const iox = @import("../io_compat.zig");

pub const ProcessInfo = struct {
    pid: u32,
    ppid: u32,
    name: []u8,
    command_line: []u8,
};

pub fn enumerateProcesses(alloc: std.mem.Allocator) ![]ProcessInfo {
    const result = try std.process.run(alloc, iox.current(), .{
        .argv = &.{ "ps", "-axo", "pid=,ppid=,comm=" },
        .stdout_limit = .limited(2 * 1024 * 1024),
        .stderr_limit = .limited(64 * 1024),
    });
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    var list = std.array_list.Managed(ProcessInfo).init(alloc);
    errdefer {
        for (list.items) |p| {
            alloc.free(p.name);
            alloc.free(p.command_line);
        }
        list.deinit();
    }

    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;

        var fields = std.mem.tokenizeAny(u8, line, " \t");
        const pid_raw = fields.next() orelse continue;
        const ppid_raw = fields.next() orelse continue;
        const command = fields.rest();
        const name = std.fs.path.basename(command);

        try list.append(.{
            .pid = std.fmt.parseInt(u32, pid_raw, 10) catch continue,
            .ppid = std.fmt.parseInt(u32, ppid_raw, 10) catch 0,
            .name = try alloc.dupe(u8, if (name.len == 0) "unknown" else name),
            .command_line = try alloc.dupe(u8, command),
        });
    }

    return list.toOwnedSlice();
}
