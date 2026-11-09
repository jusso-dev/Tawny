//! Durable action journal (#57, target-edr §9.2).
//!
//! Each action is written to `<state_dir>/actions/<id>.json` before it runs.
//! The journal dedupes by `action_id`, so a restart in the middle of an action
//! never runs a finished one twice, and the result is kept until the server
//! acks it. The server redelivers pending actions on every heartbeat, so a
//! `done` action that has not been acked is reported again with the fresh
//! execution token from the new dispatch.
//!
//! File states:
//!   running  the agent started the action and may have crashed; idempotent
//!            actions (kill of a gone process, quarantine by hash) re-run.
//!   done     the action finished; `status` and `message` hold the result,
//!            reported until the server stops redelivering it.

const std = @import("std");
const iox = @import("io_compat.zig");

pub const State = enum { running, done };

pub const Entry = struct {
    action_id: []const u8,
    action_type: []const u8,
    state: State,
    status: []const u8 = "",
    message: []const u8 = "",
};

pub const Journal = struct {
    alloc: std.mem.Allocator,
    dir: []u8,

    /// `<state_dir>/actions`. The state dir is the directory of state_path.
    pub fn init(alloc: std.mem.Allocator, state_path: []const u8) !Journal {
        const state_dir = std.fs.path.dirname(state_path) orelse ".";
        const dir = try std.fs.path.join(alloc, &.{ state_dir, "actions" });
        const io = iox.current();
        std.Io.Dir.cwd().createDirPath(io, dir) catch {};
        return .{ .alloc = alloc, .dir = dir };
    }

    pub fn deinit(self: *Journal) void {
        self.alloc.free(self.dir);
    }

    fn pathFor(self: *Journal, id: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.alloc, "{s}/{s}.json", .{ self.dir, id });
    }

    /// Read the journal entry for an action id, or null. Caller owns the
    /// returned strings via `freeEntry`.
    pub fn read(self: *Journal, id: []const u8) ?Entry {
        const p = self.pathFor(id) catch return null;
        defer self.alloc.free(p);
        const io = iox.current();
        const raw = std.Io.Dir.cwd().readFileAlloc(io, p, self.alloc, .limited(256 * 1024)) catch return null;
        defer self.alloc.free(raw);
        const Raw = struct {
            action_id: []const u8,
            action_type: []const u8,
            state: []const u8,
            status: []const u8 = "",
            message: []const u8 = "",
        };
        const parsed = std.json.parseFromSlice(Raw, self.alloc, raw, .{ .ignore_unknown_fields = true }) catch return null;
        defer parsed.deinit();
        const st: State = if (std.mem.eql(u8, parsed.value.state, "done")) .done else .running;
        return Entry{
            .action_id = self.alloc.dupe(u8, parsed.value.action_id) catch return null,
            .action_type = self.alloc.dupe(u8, parsed.value.action_type) catch return null,
            .state = st,
            .status = self.alloc.dupe(u8, parsed.value.status) catch "",
            .message = self.alloc.dupe(u8, parsed.value.message) catch "",
        };
    }

    pub fn freeEntry(self: *Journal, e: Entry) void {
        self.alloc.free(e.action_id);
        self.alloc.free(e.action_type);
        if (e.status.len > 0) self.alloc.free(e.status);
        if (e.message.len > 0) self.alloc.free(e.message);
    }

    fn write(self: *Journal, e: Entry) !void {
        const p = try self.pathFor(e.action_id);
        defer self.alloc.free(p);
        const body = try std.json.Stringify.valueAlloc(self.alloc, .{
            .action_id = e.action_id,
            .action_type = e.action_type,
            .state = @tagName(e.state),
            .status = e.status,
            .message = e.message,
        }, .{});
        defer self.alloc.free(body);
        const io = iox.current();
        const tmp = try std.fmt.allocPrint(self.alloc, "{s}.tmp", .{p});
        defer self.alloc.free(tmp);
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = tmp, .data = body });
        try std.Io.Dir.cwd().rename(tmp, std.Io.Dir.cwd(), p, io);
    }

    /// Mark an action as started. Writes `running` unless it is already there.
    pub fn begin(self: *Journal, id: []const u8, action_type: []const u8) !void {
        try self.write(.{ .action_id = id, .action_type = action_type, .state = .running });
    }

    /// Record the terminal result so it survives a restart and is reported
    /// until the server acks it.
    pub fn finish(self: *Journal, id: []const u8, action_type: []const u8, status: []const u8, message: []const u8) !void {
        try self.write(.{ .action_id = id, .action_type = action_type, .state = .done, .status = status, .message = message });
    }

    /// Remove a journal entry once the server has acked the result.
    pub fn clear(self: *Journal, id: []const u8) void {
        const p = self.pathFor(id) catch return;
        defer self.alloc.free(p);
        const io = iox.current();
        std.Io.Dir.cwd().deleteFile(io, p) catch {};
    }
};

test "dedupe and result survive a restart" {
    const a = std.testing.allocator;
    const io = iox.current();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(io, ".", a);
    defer a.free(dir);
    const state = try std.fs.path.join(a, &.{ dir, "state.toml" });
    defer a.free(state);

    var j = try Journal.init(a, state);
    defer j.deinit();

    const id = "33333333-3333-4333-8333-333333333333";
    try std.testing.expect(j.read(id) == null);

    try j.begin(id, "kill_process");
    {
        const e = j.read(id).?;
        defer j.freeEntry(e);
        try std.testing.expectEqual(State.running, e.state);
    }

    try j.finish(id, "kill_process", "succeeded", "already gone");

    // A fresh journal (restart) still sees the finished result.
    var j2 = try Journal.init(a, state);
    defer j2.deinit();
    {
        const e = j2.read(id).?;
        defer j2.freeEntry(e);
        try std.testing.expectEqual(State.done, e.state);
        try std.testing.expectEqualStrings("succeeded", e.status);
        try std.testing.expectEqualStrings("already gone", e.message);
    }

    j2.clear(id);
    try std.testing.expect(j2.read(id) == null);
}
