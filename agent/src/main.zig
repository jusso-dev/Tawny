const std = @import("std");
const builtin = @import("builtin");

const config_mod = @import("config.zig");
const enrollment = @import("enrollment.zig");
const transport = @import("transport/http.zig");
const buffer = @import("transport/buffer.zig");
const process_collector = @import("collectors/process.zig");

const AGENT_VERSION = "0.1.0";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var stderr = std.io.getStdErr().writer();
    try stderr.print("tawny-agent {s} starting on {s}\n", .{ AGENT_VERSION, @tagName(builtin.os.tag) });

    var cfg = config_mod.load(alloc) catch |err| {
        try stderr.print("config load failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer cfg.deinit();

    if (cfg.agent_id == null) {
        try stderr.print("not enrolled; running enrollment...\n", .{});
        try enrollment.run(alloc, &cfg, AGENT_VERSION);
        try config_mod.save(&cfg);
    }

    var http = try transport.Client.init(alloc, cfg.backend_url, cfg.agent_jwt.?);
    defer http.deinit();

    var buf = buffer.Buffer.init(alloc, cfg.max_in_memory_events);
    defer buf.deinit();

    var heartbeat_timer = try std.time.Timer.start();
    var collect_timer = try std.time.Timer.start();
    const start_time = std.time.timestamp();

    while (true) {
        if (heartbeat_timer.read() / std.time.ns_per_s >= cfg.heartbeat_interval_seconds) {
            heartbeat_timer.reset();
            http.heartbeat(.{
                .agent_version = AGENT_VERSION,
                .uptime_seconds = @intCast(std.time.timestamp() - start_time),
                .buffer_depth = buf.len(),
            }) catch |err| {
                try stderr.print("heartbeat failed: {s}\n", .{@errorName(err)});
            };
        }

        if (collect_timer.read() / std.time.ns_per_s >= cfg.process_interval_seconds) {
            collect_timer.reset();
            const snap = process_collector.collect(alloc) catch |err| {
                try stderr.print("process collector failed: {s}\n", .{@errorName(err)});
                continue;
            };
            defer alloc.free(snap);
            try buf.push(.{
                .event_type = "process_snapshot",
                .occurred_at = std.time.timestamp(),
                .payload = snap,
            });
        }

        if (buf.len() > 0) {
            http.flushEvents(&buf) catch |err| {
                try stderr.print("flush failed (will retry): {s}\n", .{@errorName(err)});
            };
        }

        std.time.sleep(1 * std.time.ns_per_s);
    }
}

test "main module loads" {
    _ = config_mod;
    _ = enrollment;
    _ = transport;
    _ = buffer;
    _ = process_collector;
}
