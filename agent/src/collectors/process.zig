const std = @import("std");
const builtin = @import("builtin");
const privacy = @import("privacy.zig");

const max_processes: usize = 2048;
const max_process_name_bytes: usize = 256;

const platform = switch (builtin.target.os.tag) {
    .windows => @import("../platform/windows.zig"),
    .macos => @import("../platform/macos.zig"),
    .linux => @import("../platform/linux.zig"),
    else => @compileError("unsupported os"),
};

/// Return a JSON object literal describing the current process snapshot.
/// Caller frees the returned slice.
pub fn collect(alloc: std.mem.Allocator) ![]u8 {
    const procs = try platform.enumerateProcesses(alloc);
    defer freeProcesses(alloc, procs);

    // pid -> index so each row can carry its parent's name (Sigma
    // ParentImage maps to processes.parent_name).
    var by_pid = std.AutoHashMap(u32, usize).init(alloc);
    defer by_pid.deinit();
    try by_pid.ensureTotalCapacity(@intCast(procs.len));
    for (procs, 0..) |p, i| by_pid.putAssumeCapacity(p.pid, i);

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;

    try w.writeAll("{\"processes\":[");
    const process_count = @min(procs.len, max_processes);
    for (procs[0..process_count], 0..) |p, i| {
        const safe_command_line = try privacy.sanitizeCommandLine(alloc, p.command_line);
        defer alloc.free(safe_command_line);
        if (i > 0) try w.writeByte(',');
        try w.print(
            \\{{"pid":{d},"ppid":{d},"name":
        , .{ p.pid, p.ppid });
        try writeJsonString(w, p.name[0..@min(p.name.len, max_process_name_bytes)]);
        try w.writeAll(",\"command_line\":");
        try writeJsonString(w, safe_command_line);
        if (p.ppid != p.pid) {
            if (by_pid.get(p.ppid)) |parent_index| {
                const parent = procs[parent_index].name;
                try w.writeAll(",\"parent_name\":");
                try writeJsonString(w, parent[0..@min(parent.len, max_process_name_bytes)]);
            }
        }
        try writeOptionalFields(w, p);
        try w.writeByte('}');
    }
    try w.print("],\"truncated\":{any}}}", .{procs.len > process_count});

    return out.toOwnedSlice();
}

/// Fields only some platforms fill (macOS today): uid, start time, image path.
fn writeOptionalFields(w: *std.Io.Writer, p: anytype) !void {
    const P = @TypeOf(p);
    if (@hasField(P, "uid")) {
        if (p.uid) |uid| try w.print(",\"uid\":{d}", .{uid});
    }
    if (@hasField(P, "start_time_unix")) {
        if (p.start_time_unix) |t| try w.print(",\"start_time_unix\":{d}", .{t});
    }
    if (@hasField(P, "image_path")) {
        if (p.image_path) |path| {
            try w.writeAll(",\"image_path\":");
            try writeJsonString(w, path);
        }
    }
}

fn freeProcesses(alloc: std.mem.Allocator, procs: []platform.ProcessInfo) void {
    if (@hasDecl(platform, "freeProcesses")) return platform.freeProcesses(alloc, procs);
    for (procs) |p| {
        alloc.free(p.name);
        alloc.free(p.command_line);
    }
    alloc.free(procs);
}

fn writeJsonString(writer: anytype, s: []const u8) !void {
    try std.json.Stringify.value(s, .{}, writer);
}

test {
    _ = platform;
}

test "process collect runs" {
    const alloc = std.testing.allocator;
    // Sandboxed CI may not enumerate processes; tolerate collector failures here.
    const out = collect(alloc) catch |err| {
        // libproc needs no special sandbox permissions; only tolerate others.
        if (builtin.target.os.tag == .macos) return err;
        return;
    };
    defer alloc.free(out);
    try std.testing.expect(std.mem.startsWith(u8, out, "{\"processes\":["));
    // Every row needs a name; procfs files report size 0, so a reader that
    // trusts stat().size returns empty names.
    try std.testing.expect(std.mem.indexOf(u8, out, "\"name\":\"\"") == null);
    if (builtin.target.os.tag == .macos) {
        try std.testing.expect(std.mem.indexOf(u8, out, "\"start_time_unix\":") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "\"parent_name\":") != null);
        try std.testing.expect(std.mem.indexOf(u8, out, "\"image_path\":") != null);
    }
}

test "process names are json escaped" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();

    try writeJsonString(&out.writer, "bad\"name\\with\nnewline");

    try std.testing.expectEqualStrings(
        "\"bad\\\"name\\\\with\\nnewline\"",
        out.written(),
    );
}
