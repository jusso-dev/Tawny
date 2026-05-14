const std = @import("std");

pub const ProcessInfo = struct {
    pid: u32,
    ppid: u32,
    name: []u8,
};

pub fn enumerateProcesses(alloc: std.mem.Allocator) ![]ProcessInfo {
    const result = try std.process.Child.run(.{
        .allocator = alloc,
        .argv = &.{ "ps", "-eo", "pid=,ppid=,comm=" },
        .max_output_bytes = 512 * 1024,
    });
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    var list = std.ArrayList(ProcessInfo).init(alloc);
    errdefer {
        for (list.items) |p| alloc.free(p.name);
        list.deinit();
    }

    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r");
        if (line.len == 0) continue;

        var fields = std.mem.tokenizeAny(u8, line, " \t");
        const pid_raw = fields.next() orelse continue;
        const ppid_raw = fields.next() orelse continue;
        const name_raw = fields.rest();

        const pid = std.fmt.parseInt(u32, pid_raw, 10) catch continue;
        const ppid = std.fmt.parseInt(u32, ppid_raw, 10) catch 0;
        const name = std.mem.trim(u8, name_raw, " \t\r");

        try list.append(.{
            .pid = pid,
            .ppid = ppid,
            .name = try alloc.dupe(u8, if (name.len > 0) name else "unknown"),
        });
    }

    return list.toOwnedSlice();
}
