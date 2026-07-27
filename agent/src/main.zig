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
const process_events = @import("collectors/process_events.zig");
const fs_events = @import("collectors/fs_events.zig");
const dns_collector = @import("collectors/dns.zig");
const inventory_collector = @import("collectors/inventory.zig");
const extensions_collector = @import("collectors/extensions.zig");
const mcp_collector = @import("collectors/mcp_config.zig");
const response_actions = @import("response_actions.zig");
const iox = @import("io_compat.zig");

const AGENT_VERSION = "0.1.0";

pub fn main(init: std.process.Init) !void {
    iox.initialize(init.io);
    const alloc = init.gpa;

    std.debug.print("tawny-agent {s} starting on {s}\n", .{ AGENT_VERSION, @tagName(builtin.os.tag) });

    var cfg = config_mod.load(alloc) catch |err| {
        std.debug.print("config load failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer cfg.deinit();

    if (cfg.agent_id == null) {
        std.debug.print("not enrolled; running enrollment...\n", .{});
        try enrollment.run(alloc, &cfg, AGENT_VERSION);
        try config_mod.save(&cfg);
    }

    var http = try transport.Client.init(
        alloc,
        cfg.backend_url,
        cfg.agent_jwt.?,
        cfg.http_timeout_seconds,
        cfg.max_retry_backoff_seconds,
    );
    defer http.deinit();

    var buf = try buffer.Buffer.init(
        alloc,
        cfg.max_in_memory_events,
        cfg.spill_path,
        cfg.max_spool_bytes,
    );
    defer buf.deinit();
    try buf.replay();

    var fim = try fim_collector.Watcher.init(alloc, cfg.fim_paths);
    defer fim.deinit();

    var process_tracker = process_events.Tracker.init(alloc);
    defer process_tracker.deinit();

    var fs_watcher = try fs_events.Watcher.init(alloc, cfg.fim_paths);
    defer fs_watcher.deinit();

    var dns = dns_collector.Collector.init(alloc);

    var inventory = inventory_collector.Scanner.init(alloc);
    var extensions = extensions_collector.Scanner.init(alloc);
    var mcp = mcp_collector.Scanner.init(alloc);

    var heartbeat_timer = try iox.Timer.start();
    var process_timer = try iox.Timer.start();
    var process_events_timer = try iox.Timer.start();
    var network_timer = try iox.Timer.start();
    var users_timer = try iox.Timer.start();
    var system_timer = try iox.Timer.start();
    var fim_timer = try iox.Timer.start();
    var fs_events_timer = try iox.Timer.start();
    var dns_timer = try iox.Timer.start();
    var supply_chain_timer = try iox.Timer.start();
    var flush_retry_timer = try iox.Timer.start();
    const start_time = iox.timestamp();

    if (system_collector.collect(alloc)) |payload| {
        defer alloc.free(payload);
        queueEvent(&buf, "system_info", payload);
    } else |err| {
        std.debug.print("system collector failed: {s}\n", .{@errorName(err)});
    }

    while (true) {
        if (heartbeat_timer.read() / std.time.ns_per_s >= cfg.heartbeat_interval_seconds) {
            heartbeat_timer.reset();
            if (http.heartbeat(.{
                .agent_version = AGENT_VERSION,
                .uptime_seconds = @intCast(iox.timestamp() - start_time),
                .buffer_depth = buf.totalLen(),
            })) |heartbeat_result| {
                var heartbeat = heartbeat_result;
                defer heartbeat.deinit(alloc);
                if (heartbeat.rotated_jwt) |rotated| {
                    persistRotatedJwt(alloc, &cfg, &http, rotated) catch |err| {
                        std.debug.print("jwt rotation persist failed: {s}\n", .{@errorName(err)});
                    };
                }
                for (heartbeat.actions) |action| {
                    response_actions.execute(alloc, &http, action) catch |err| {
                        std.debug.print("response action {s} failed: {s}\n", .{ action.id, @errorName(err) });
                    };
                }
            } else |err| {
                std.debug.print("heartbeat failed: {s}\n", .{@errorName(err)});
            }
        }

        if (process_timer.read() / std.time.ns_per_s >= cfg.process_interval_seconds) {
            process_timer.reset();
            if (process_collector.collect(alloc)) |snap| {
                defer alloc.free(snap);
                queueEvent(&buf, "process_snapshot", snap);
            } else |err| {
                std.debug.print("process collector failed: {s}\n", .{@errorName(err)});
            }
        }

        if (network_timer.read() / std.time.ns_per_s >= cfg.network_interval_seconds) {
            network_timer.reset();
            if (network_collector.collect(alloc)) |snap| {
                defer alloc.free(snap);
                queueEvent(&buf, "network_snapshot", snap);
            } else |err| {
                std.debug.print("network collector failed: {s}\n", .{@errorName(err)});
            }
        }

        if (users_timer.read() / std.time.ns_per_s >= cfg.users_interval_seconds) {
            users_timer.reset();
            if (users_collector.collect(alloc)) |snap| {
                defer alloc.free(snap);
                queueEvent(&buf, "user_session", snap);
            } else |err| {
                std.debug.print("users collector failed: {s}\n", .{@errorName(err)});
            }
        }

        if (system_timer.read() / std.time.ns_per_s >= cfg.system_interval_seconds) {
            system_timer.reset();
            if (system_collector.collect(alloc)) |snap| {
                defer alloc.free(snap);
                queueEvent(&buf, "system_info", snap);
            } else |err| {
                std.debug.print("system collector failed: {s}\n", .{@errorName(err)});
            }
        }

        if (fim_timer.read() / std.time.ns_per_s >= cfg.fim_interval_seconds) {
            fim_timer.reset();
            if (fim.collectChanges()) |changes| {
                defer alloc.free(changes);
                for (changes) |payload| {
                    defer alloc.free(payload);
                    queueEvent(&buf, "file_integrity", payload);
                }
            } else |err| {
                std.debug.print("fim collector failed: {s}\n", .{@errorName(err)});
            }
        }

        if (process_events_timer.read() / std.time.ns_per_s >= cfg.process_events_interval_seconds) {
            process_events_timer.reset();
            if (process_tracker.collectLaunches()) |launches| {
                emitBatch(&buf, "process_launch", launches, alloc);
            } else |err| {
                std.debug.print("process_events collector failed: {s}\n", .{@errorName(err)});
            }
        }

        if (fs_events_timer.read() / std.time.ns_per_s >= cfg.fs_events_interval_seconds) {
            fs_events_timer.reset();
            if (fs_watcher.collectEvents()) |events| {
                emitBatch(&buf, "file_event", events, alloc);
            } else |err| {
                std.debug.print("fs_events collector failed: {s}\n", .{@errorName(err)});
            }
        }

        if (dns_timer.read() / std.time.ns_per_s >= cfg.dns_interval_seconds) {
            dns_timer.reset();
            if (dns.collectQueries()) |queries| {
                emitBatch(&buf, "dns_query", queries, alloc);
            } else |err| {
                std.debug.print("dns collector failed: {s}\n", .{@errorName(err)});
            }
        }

        // Supply-chain inventory + extensions + MCP configs run on a much
        // longer cadence — these are slow filesystem walks, not real-time.
        if (supply_chain_timer.read() / std.time.ns_per_s >= cfg.supply_chain_interval_seconds) {
            supply_chain_timer.reset();

            if (inventory.collectInventory()) |payloads| {
                emitBatch(&buf, "package_inventory", payloads, alloc);
            } else |err| {
                std.debug.print("inventory collector failed: {s}\n", .{@errorName(err)});
            }

            if (extensions.collectExtensions(.editor)) |payloads| {
                emitBatch(&buf, "editor_extension", payloads, alloc);
            } else |err| {
                std.debug.print("editor extensions failed: {s}\n", .{@errorName(err)});
            }

            if (extensions.collectExtensions(.browser)) |payloads| {
                emitBatch(&buf, "browser_extension", payloads, alloc);
            } else |err| {
                std.debug.print("browser extensions failed: {s}\n", .{@errorName(err)});
            }

            if (mcp.collectConfigs()) |payloads| {
                emitBatch(&buf, "mcp_config", payloads, alloc);
            } else |err| {
                std.debug.print("mcp config failed: {s}\n", .{@errorName(err)});
            }
        }

        const retry_ready = http.backoff_seconds == 0 or
            flush_retry_timer.read() / std.time.ns_per_s >= http.backoff_seconds;
        if (buf.len() > 0 and retry_ready) {
            http.flushEvents(&buf) catch |err| {
                std.debug.print(
                    "flush failed (retry in {d}s): {s}\n",
                    .{ http.backoff_seconds, @errorName(err) },
                );
            };
            flush_retry_timer.reset();
        }

        iox.sleep(1 * std.time.ns_per_s);
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
    _ = process_events;
    _ = fs_events;
    _ = dns_collector;
    _ = inventory_collector;
    _ = extensions_collector;
    _ = mcp_collector;
    _ = response_actions;
}

fn emitBatch(
    buf: *buffer.Buffer,
    event_type: []const u8,
    payloads: [][]u8,
    alloc: std.mem.Allocator,
) void {
    defer alloc.free(payloads);
    for (payloads) |payload| {
        defer alloc.free(payload);
        buf.push(.{
            .event_type = event_type,
            .occurred_at = iox.timestamp(),
            .payload = payload,
        }) catch |err| {
            std.debug.print("queue event batch {s} stopped: {s}\n", .{ event_type, @errorName(err) });
            break;
        };
    }
}

fn queueEvent(buf: *buffer.Buffer, event_type: []const u8, payload: []const u8) void {
    buf.push(.{
        .event_type = event_type,
        .occurred_at = iox.timestamp(),
        .payload = payload,
    }) catch |err| {
        std.debug.print("queue event {s} failed: {s}\n", .{ event_type, @errorName(err) });
    };
}

fn persistRotatedJwt(
    alloc: std.mem.Allocator,
    cfg: *config_mod.Config,
    http: *transport.Client,
    rotated: []const u8,
) !void {
    const owned = try alloc.dupe(u8, rotated);
    const previous = cfg.agent_jwt;
    cfg.agent_jwt = owned;
    config_mod.save(cfg) catch |err| {
        cfg.agent_jwt = previous;
        alloc.free(owned);
        return err;
    };
    http.jwt = owned;
    if (previous) |old| alloc.free(old);
}

test "JWT rotation keeps current token when state persistence fails" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const blocked_parent = try std.fs.path.join(
        std.testing.allocator,
        &.{ ".zig-cache", "tmp", &tmp.sub_path, "not-a-directory" },
    );
    defer std.testing.allocator.free(blocked_parent);
    const io = iox.current();
    {
        var file = try std.Io.Dir.cwd().createFile(io, blocked_parent, .{ .truncate = true });
        file.close(io);
    }
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ blocked_parent, "state.toml" });
    defer std.testing.allocator.free(state_path);

    var cfg = config_mod.Config{
        .allocator = std.testing.allocator,
        .backend_url = try std.testing.allocator.dupe(u8, "https://tawny.example"),
        .spill_path = try std.testing.allocator.dupe(u8, "events.spool"),
        .config_path = try std.testing.allocator.dupe(u8, "config.toml"),
        .state_path = try std.testing.allocator.dupe(u8, state_path),
        .agent_id = try std.testing.allocator.dupe(u8, "agent-id"),
        .agent_jwt = try std.testing.allocator.dupe(u8, "old-jwt"),
    };
    defer cfg.deinit();
    var http = try transport.Client.init(
        std.testing.allocator,
        cfg.backend_url,
        cfg.agent_jwt.?,
        30,
        300,
    );
    defer http.deinit();

    try std.testing.expectError(
        error.NotDir,
        persistRotatedJwt(std.testing.allocator, &cfg, &http, "new-jwt"),
    );
    try std.testing.expectEqualStrings("old-jwt", cfg.agent_jwt.?);
    try std.testing.expectEqualStrings("old-jwt", http.jwt);
}
