//! `GET /api/admin/jobs` replaces the removed `/hangfire` dashboard.
const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const auth = @import("../http/auth.zig");

pub fn list(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    request: *std.http.Server.Request,
    web: auth.WebUser,
) !void {
    _ = web;
    const rows = try conn.exec(allocator,
        \\SELECT name, schedule, last_started_at::text, last_finished_at::text, last_status, last_error
        \\FROM jobs ORDER BY name
    , &.{});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.append(allocator, '[');
    for (rows, 0..) |row, i| {
        if (i != 0) try out.append(allocator, ',');
        const name = try util.escapeJson(allocator, row.cols[0] orelse "");
        defer allocator.free(name);
        const schedule = try util.escapeJson(allocator, row.cols[1] orelse "");
        defer allocator.free(schedule);
        const started = try util.nullOrJsonString(allocator, row.cols[2]);
        defer allocator.free(started);
        const finished = try util.nullOrJsonString(allocator, row.cols[3]);
        defer allocator.free(finished);
        const status = try util.nullOrJsonString(allocator, row.cols[4]);
        defer allocator.free(status);
        const err = try util.nullOrJsonString(allocator, row.cols[5]);
        defer allocator.free(err);
        const line = try std.fmt.allocPrint(allocator,
            \\{{"name":{s},"schedule":{s},"last_started_at":{s},"last_finished_at":{s},"last_status":{s},"last_error":{s}}}
        , .{ name, schedule, started, finished, status, err });
        defer allocator.free(line);
        try out.appendSlice(allocator, line);
    }
    try out.append(allocator, ']');
    try util.respondJson(request, .ok, out.items);
}
