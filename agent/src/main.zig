const std = @import("std");
const builtin = @import("builtin");

const config_mod = @import("config.zig");
const enrollment = @import("enrollment.zig");
const transport = @import("transport/http.zig");
const buffer = @import("transport/buffer.zig");
const process_collector = @import("collectors/process.zig");
const network_collector = @import("collectors/network.zig");
const users_collector = @import("collectors/users.zig");
const system_collector = @import("collectors/system.zig");
const fim_collector = @import("collectors/fim.zig");
const response_actions = @import("response_actions.zig");

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
    try buf.replay(cfg.spill_path);

    var fim = try fim_collector.Watcher.init(alloc, cfg.fim_paths);
    defer fim.deinit();

    var heartbeat_timer = try std.time.Timer.start();
    var process_timer = try std.time.Timer.start();
    var network_timer = try std.time.Timer.start();
    var users_timer = try std.time.Timer.start();
    var system_timer = try std.time.Timer.start();
    var fim_timer = try std.time.Timer.start();
    const start_time = std.time.timestamp();

    if (system_collector.collect(alloc)) |payload| {
        defer alloc.free(payload);
        try buf.push(.{
            .event_type = "system_info",
            .occurred_at = std.time.timestamp(),
            .payload = payload,
        });
        try spillIfNeeded(&buf, cfg.spill_path);
    } else |err| {
        try stderr.print("system collector failed: {s}\n", .{@errorName(err)});
    }

    while (true) {
        if (heartbeat_timer.read() / std.time.ns_per_s >= cfg.heartbeat_interval_seconds) {
            heartbeat_timer.reset();
            var heartbeat = http.heartbeat(.{
                .agent_version = AGENT_VERSION,
                .uptime_seconds = @intCast(std.time.timestamp() - start_time),
                .buffer_depth = buf.len(),
            }) catch |err| {
                try stderr.print("heartbeat failed: {s}\n", .{@errorName(err)});
                continue;
            };
            defer heartbeat.deinit(alloc);
            if (heartbeat.rotated_jwt) |rotated| {
                persistRotatedJwt(alloc, &cfg, &http, rotated) catch |err| {
                    try stderr.print("jwt rotation persist failed: {s}\n", .{@errorName(err)});
                };
            }
            for (heartbeat.actions) |action| {
                response_actions.execute(alloc, &http, action) catch |err| {
                    try stderr.print("response action {s} failed: {s}\n", .{ action.id, @errorName(err) });
                };
            }
        }

        if (process_timer.read() / std.time.ns_per_s >= cfg.process_interval_seconds) {
            process_timer.reset();
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
            try spillIfNeeded(&buf, cfg.spill_path);
        }

        if (network_timer.read() / std.time.ns_per_s >= cfg.network_interval_seconds) {
            network_timer.reset();
            const snap = network_collector.collect(alloc) catch |err| {
                try stderr.print("network collector failed: {s}\n", .{@errorName(err)});
                continue;
            };
            defer alloc.free(snap);
            try buf.push(.{
                .event_type = "network_snapshot",
                .occurred_at = std.time.timestamp(),
                .payload = snap,
            });
            try spillIfNeeded(&buf, cfg.spill_path);
        }

        if (users_timer.read() / std.time.ns_per_s >= cfg.users_interval_seconds) {
            users_timer.reset();
            const snap = users_collector.collect(alloc) catch |err| {
                try stderr.print("users collector failed: {s}\n", .{@errorName(err)});
                continue;
            };
            defer alloc.free(snap);
            try buf.push(.{
                .event_type = "user_session",
                .occurred_at = std.time.timestamp(),
                .payload = snap,
            });
            try spillIfNeeded(&buf, cfg.spill_path);
        }

        if (system_timer.read() / std.time.ns_per_s >= cfg.system_interval_seconds) {
            system_timer.reset();
            const snap = system_collector.collect(alloc) catch |err| {
                try stderr.print("system collector failed: {s}\n", .{@errorName(err)});
                continue;
            };
            defer alloc.free(snap);
            try buf.push(.{
                .event_type = "system_info",
                .occurred_at = std.time.timestamp(),
                .payload = snap,
            });
            try spillIfNeeded(&buf, cfg.spill_path);
        }

        if (fim_timer.read() / std.time.ns_per_s >= cfg.fim_interval_seconds) {
            fim_timer.reset();
            const changes = fim.collectChanges() catch |err| {
                try stderr.print("fim collector failed: {s}\n", .{@errorName(err)});
                continue;
            };
            defer alloc.free(changes);
            for (changes) |payload| {
                defer alloc.free(payload);
                try buf.push(.{
                    .event_type = "file_integrity",
                    .occurred_at = std.time.timestamp(),
                    .payload = payload,
                });
                try spillIfNeeded(&buf, cfg.spill_path);
            }
        }

        if (buf.len() == 0) {
            buf.replay(cfg.spill_path) catch |err| {
                try stderr.print("buffer replay failed: {s}\n", .{@errorName(err)});
            };
        }

        if (buf.len() > 0) {
            http.flushEvents(&buf) catch |err| {
                try stderr.print("flush failed (will retry): {s}\n", .{@errorName(err)});
                if (buf.shouldSpill()) {
                    buf.spill(cfg.spill_path) catch |spill_err| {
                        try stderr.print("buffer spill failed: {s}\n", .{@errorName(spill_err)});
                    };
                }
                std.time.sleep(http.backoff_seconds * std.time.ns_per_s);
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
    _ = network_collector;
    _ = users_collector;
    _ = system_collector;
    _ = fim_collector;
    _ = response_actions;
}

fn spillIfNeeded(buf: *buffer.Buffer, path: []const u8) !void {
    if (buf.shouldSpill()) try buf.spill(path);
}

fn persistRotatedJwt(
    alloc: std.mem.Allocator,
    cfg: *config_mod.Config,
    http: *transport.Client,
    rotated: []const u8,
) !void {
    const owned = try alloc.dupe(u8, rotated);
    if (cfg.agent_jwt) |old| alloc.free(old);
    cfg.agent_jwt = owned;
    http.jwt = owned;
    try config_mod.save(cfg);
}
