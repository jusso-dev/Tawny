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
const windows_events = @import("collectors/windows_events.zig");
const response_actions = @import("response_actions.zig");
const action_key = @import("action_key.zig");
const action_journal = @import("action_journal.zig");
const yara_scanner = @import("yara_scanner.zig");
const entity = @import("entity.zig");
const iox = @import("io_compat.zig");
const lifecycle = @import("lifecycle.zig");
const windows_service = if (builtin.target.os.tag == .windows) @import("platform/windows/service.zig") else struct {};

const AGENT_VERSION = "0.1.0";

pub fn main(init: std.process.Init) !void {
    iox.initialize(init.io);
    const alloc = init.gpa;

    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len == 2 and std.mem.eql(u8, args[1], "--export-credentials")) {
        return config_mod.exportCredentialsCommand(alloc);
    }
    if (args.len >= 2 and std.mem.eql(u8, args[1], "--eventlog-dump")) {
        return windows_events.dumpCommand(alloc, args[2..]);
    }
    if (args.len >= 2 and @import("response_debug.zig").isDebugCommand(args[1])) {
        const code = @import("response_debug.zig").run(alloc, args[1..]);
        if (code != 0) std.process.exit(code);
        return;
    }
    // Break-glass: tawny-agent release --code <code>
    if (args.len == 4 and std.mem.eql(u8, args[1], "release") and std.mem.eql(u8, args[2], "--code")) {
        return releaseCodeCommand(alloc, args[3]);
    }

    if (builtin.target.os.tag == .windows) {
        // Under the SCM this blocks until the service stops; ServiceMain runs
        // the agent loop. Interactive launches fall through to console mode.
        switch (try windows_service.runDispatcher(alloc, runAgent)) {
            .ran_as_service => return,
            .not_a_service => {},
        }
    } else {
        lifecycle.installPosixSignalHandlers();
    }
    try runAgent(alloc);
}

/// Agent run loop shared by console mode and the Windows service. Returns
/// cleanly once `lifecycle.requestStop()` has been called.
fn runAgent(alloc: std.mem.Allocator) anyerror!void {
    std.debug.print("tawny-agent {s} starting on {s}\n", .{ AGENT_VERSION, @tagName(builtin.target.os.tag) });

    var cfg = config_mod.load(alloc) catch |err| {
        std.debug.print("config load failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer cfg.deinit();

    if (cfg.agent_id == null) {
        std.debug.print("not enrolled; running enrollment...\n", .{});
        try enrollment.run(alloc, &cfg, AGENT_VERSION);
        try config_mod.save(&cfg);
        scrubEnrollmentToken(alloc, cfg.config_path);
    } else if (cfg.enrollment_token) |token| {
        // Already enrolled: the single-use token is never sent again.
        alloc.free(token);
        cfg.enrollment_token = null;
        scrubEnrollmentToken(alloc, cfg.config_path);
    }

    const device_key_path = try alloc.print("{s}.devicekey", .{cfg.state_path});
    defer alloc.free(device_key_path);
    var http = try transport.Client.initFull(
        alloc,
        cfg.backend_url,
        cfg.agent_jwt.?,
        cfg.agent_id orelse "",
        device_key_path,
        cfg.http_timeout_seconds,
        cfg.max_retry_backoff_seconds,
    );
    defer http.deinit();
    http.secret_store = cfg.secret_store;
    http.sensor_version = AGENT_VERSION;
    const boot_id = entity.readBootId();
    http.boot_id = boot_id;

    // pid -> entity table. The launch tracker's first pass (and on Windows a
    // process snapshot) seeds it before any child is reported.
    var entities = entity.Table.init(alloc, cfg.agent_id orelse "", &boot_id, entity.Table.default_capacity);
    defer entities.deinit();
    entity.seedFromSystem(&entities);

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
    process_tracker.entities = &entities;
    // Baseline pass: record what is already running without reporting it as
    // new launches, so parents are known when their children appear.
    if (process_tracker.collectLaunches()) |baseline| {
        for (baseline) |p| alloc.free(p);
        alloc.free(baseline);
        if (process_tracker.takeExits()) |gone| {
            for (gone) |p| alloc.free(p);
            alloc.free(gone);
        } else |_| {}
    } else |err| {
        std.debug.print("process baseline failed: {s}\n", .{@errorName(err)});
    }

    var fs_watcher = try fs_events.Watcher.init(alloc, cfg.fim_paths);
    defer fs_watcher.deinit();

    var dns = dns_collector.Collector.init(alloc);
    defer dns.deinit();
    dns.start();

    // Bookmarks live beside state.toml so a restart resumes each channel.
    var eventlog = try windows_events.Collector.init(alloc, std.fs.path.dirname(cfg.state_path) orelse ".");
    defer eventlog.deinit();
    eventlog.setEntities(&entities);

    // YARA: rules only from a pack signed by the pinned server key.
    const pinned_key = if (cfg.yara_rule_key == null) @import("yara_key.zig").load(alloc, cfg.state_path) else null;
    defer if (pinned_key) |k| alloc.free(k);
    var yara = yara_scanner.Scanner{
        .alloc = alloc,
        .public_key = yaraRuleKey(cfg.yara_rule_key orelse pinned_key),
        .options = .{ .timeout_seconds = cfg.yara_timeout_seconds, .max_file_bytes = cfg.yara_max_file_bytes },
    };
    defer yara.deinit();
    var yara_timer = try iox.Timer.start();

    // Response actions (#57): pinned server action key, local journal and the
    // quarantine directory. The action key is the one pinned at enrolment (or
    // from config.yara_rule_key, same bytes); TOFU from a heartbeat pins it
    // for agents enrolled before #57.
    var action_pub_text = action_key.load(alloc, cfg.state_path);
    defer if (action_pub_text) |k| alloc.free(k);
    var action_pub: ?std.crypto.sign.Ed25519.PublicKey =
        action_key.decode(action_pub_text orelse cfg.yara_rule_key);

    var journal = action_journal.Journal.init(alloc, cfg.state_path) catch |err| blk: {
        std.debug.print("action journal unavailable: {s}\n", .{@errorName(err)});
        break :blk null;
    };
    defer if (journal) |*j| j.deinit();

    const quarantine_dir = quarantineDir(alloc, cfg.state_path) catch try alloc.dupe(u8, "quarantine");
    defer alloc.free(quarantine_dir);

    // Reconcile WFP isolation with the journal at start, so a crash never
    // leaves stray filters and an expired deadline releases itself (#57 §9.3).
    reconcileIsolation(alloc, &cfg);

    var inventory = inventory_collector.Scanner.init(alloc);
    var extensions = extensions_collector.Scanner.init(alloc);
    var mcp = mcp_collector.Scanner.init(alloc);

    var heartbeat_timer = try iox.Timer.start();
    var process_timer = try iox.Timer.start();
    var process_events_timer = try iox.Timer.start();
    var eventlog_timer = try iox.Timer.start();
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

    while (!lifecycle.shouldStop()) {
        if (heartbeat_timer.read() / std.time.ns_per_s >= cfg.heartbeat_interval_seconds) {
            heartbeat_timer.reset();
            const uptime: i64 = @intCast(iox.timestamp() - start_time);
            if (healthPayload(alloc, uptime, buf.totalLen(), buf.next_sequence, &boot_id)) |payload| {
                defer alloc.free(payload);
                queueEvent(&buf, "agent_health", payload);
            } else |_| {}
            if (http.heartbeat(.{
                .agent_version = AGENT_VERSION,
                .uptime_seconds = uptime,
                .buffer_depth = buf.totalLen(),
            })) |heartbeat_result| {
                var heartbeat = heartbeat_result;
                defer heartbeat.deinit(alloc);
                if (heartbeat.rotated_jwt) |rotated| {
                    persistRotatedJwt(alloc, &cfg, &http, rotated) catch |err| {
                        std.debug.print("jwt rotation persist failed: {s}\n", .{@errorName(err)});
                    };
                }
                if (heartbeat.yara_pack_version > yara.pack_version and yara.public_key != null) {
                    refreshYaraPack(alloc, &http, &yara);
                }
                // Trust on first use: an agent enrolled before #57 pins the
                // action key from its first heartbeat that carries it.
                if (action_pub == null) {
                    if (heartbeat.action_public_key) |k| {
                        action_key.pin(alloc, cfg.state_path, k) catch {};
                        if (action_key.load(alloc, cfg.state_path)) |pinned| {
                            if (action_pub_text) |old| alloc.free(old);
                            action_pub_text = pinned;
                            action_pub = action_key.decode(pinned);
                            std.log.info("pinned the server action key (trust on first use)", .{});
                        }
                    }
                }
                for (heartbeat.actions) |action| {
                    if (std.mem.eql(u8, action.action_type, "yara_scan")) {
                        runYaraAction(alloc, &http, &yara, &buf, action);
                        continue;
                    }
                    if (journal) |*j| {
                        response_actions.execute(.{
                            .alloc = alloc,
                            .http = &http,
                            .agent_id = cfg.agent_id orelse "",
                            .public_key = action_pub,
                            .journal = j,
                            .quarantine_dir = quarantine_dir,
                            .state_path = cfg.state_path,
                            .backend_url = cfg.backend_url,
                        }, action);
                    } else {
                        std.debug.print("response action {s} skipped: no journal\n", .{action.id});
                    }
                }
                // Enforce the isolation deadline: if it passed with no renewal,
                // release ourselves.
                enforceIsolationDeadline(alloc, &cfg);
            } else |err| {
                std.debug.print("heartbeat failed: {s}\n", .{@errorName(err)});
            }
        }

        if (lifecycle.shouldStop()) break;
        if (process_timer.read() / std.time.ns_per_s >= cfg.process_interval_seconds) {
            process_timer.reset();
            if (process_collector.collect(alloc)) |snap| {
                defer alloc.free(snap);
                queueEvent(&buf, "process_snapshot", snap);
            } else |err| {
                std.debug.print("process collector failed: {s}\n", .{@errorName(err)});
            }
        }

        if (lifecycle.shouldStop()) break;
        if (network_timer.read() / std.time.ns_per_s >= cfg.network_interval_seconds) {
            network_timer.reset();
            if (network_collector.collect(alloc)) |snap| {
                defer alloc.free(snap);
                queueEvent(&buf, "network_snapshot", snap);
            } else |err| {
                std.debug.print("network collector failed: {s}\n", .{@errorName(err)});
            }
        }

        if (lifecycle.shouldStop()) break;
        if (users_timer.read() / std.time.ns_per_s >= cfg.users_interval_seconds) {
            users_timer.reset();
            if (users_collector.collect(alloc)) |snap| {
                defer alloc.free(snap);
                queueEvent(&buf, "user_session", snap);
            } else |err| {
                std.debug.print("users collector failed: {s}\n", .{@errorName(err)});
            }
        }

        if (lifecycle.shouldStop()) break;
        if (system_timer.read() / std.time.ns_per_s >= cfg.system_interval_seconds) {
            system_timer.reset();
            if (system_collector.collect(alloc)) |snap| {
                defer alloc.free(snap);
                queueEvent(&buf, "system_info", snap);
            } else |err| {
                std.debug.print("system collector failed: {s}\n", .{@errorName(err)});
            }
        }

        if (lifecycle.shouldStop()) break;
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

        if (lifecycle.shouldStop()) break;
        if (process_events_timer.read() / std.time.ns_per_s >= cfg.process_events_interval_seconds) {
            process_events_timer.reset();
            if (process_tracker.collectLaunches()) |launches| {
                emitBatch(&buf, "process_start", launches, alloc);
            } else |err| {
                std.debug.print("process_events collector failed: {s}\n", .{@errorName(err)});
            }
            if (process_tracker.takeExits()) |exits| {
                emitBatch(&buf, "process_exit", exits, alloc);
            } else |_| {}
        }

        if (lifecycle.shouldStop()) break;
        if (builtin.target.os.tag == .windows and
            eventlog_timer.read() / std.time.ns_per_s >= cfg.eventlog_interval_seconds)
        {
            eventlog_timer.reset();
            if (eventlog.collect()) |items| {
                defer windows_events.freeItems(alloc, items);
                for (items) |item| {
                    buf.push(.{
                        .client_event_id = item.client_event_id,
                        .event_type = item.event_type,
                        .occurred_at = item.occurred_at,
                        .payload = item.payload,
                    }) catch |err| {
                        eventlog.noteQueueDrop();
                        std.debug.print("queue {s} failed: {s}\n", .{ item.event_type, @errorName(err) });
                    };
                }
                // Bookmarks move only after the events are in the spool, so
                // a crash replays (deduplicated by client_event_id) rather
                // than skips.
                eventlog.commit();
            } else |err| {
                std.debug.print("eventlog collector failed: {s}\n", .{@errorName(err)});
            }
        }

        if (lifecycle.shouldStop()) break;
        if (fs_events_timer.read() / std.time.ns_per_s >= cfg.fs_events_interval_seconds) {
            fs_events_timer.reset();
            if (fs_watcher.collectEvents()) |events| {
                if (yara.rules != null) {
                    if (yara.onFileEvents(events)) |hits| emitBatch(&buf, "yara_match", hits, alloc) else |err| {
                        std.debug.print("yara file scan failed: {s}\n", .{@errorName(err)});
                    }
                }
                emitBatch(&buf, "file_event", events, alloc);
            } else |err| {
                std.debug.print("fs_events collector failed: {s}\n", .{@errorName(err)});
            }
        }

        if (lifecycle.shouldStop()) break;
        if (cfg.yara_scan_interval_seconds > 0 and yara.rules != null and yara_timer.read() / std.time.ns_per_s >= cfg.yara_scan_interval_seconds) {
            yara_timer.reset();
            scheduledYaraScan(alloc, &yara, &buf);
        }

        if (lifecycle.shouldStop()) break;
        if (dns_timer.read() / std.time.ns_per_s >= cfg.dns_interval_seconds) {
            dns_timer.reset();
            if (dns.collectQueries()) |queries| {
                emitBatch(&buf, "dns_query", queries, alloc);
            } else |err| {
                std.debug.print("dns collector failed: {s}\n", .{@errorName(err)});
            }
        }

        if (lifecycle.shouldStop()) break;
        // Supply-chain inventory + extensions + MCP configs run on a much
        // longer cadence — these are slow filesystem walks, not real-time.
        if (supply_chain_timer.read() / std.time.ns_per_s >= cfg.supply_chain_interval_seconds) {
            supply_chain_timer.reset();

            if (inventory.collectInventory()) |payloads| {
                emitBatch(&buf, "package_inventory", payloads, alloc);
            } else |err| {
                std.debug.print("inventory collector failed: {s}\n", .{@errorName(err)});
            }

            if (lifecycle.shouldStop()) break;
            if (extensions.collectExtensions(.editor)) |payloads| {
                emitBatch(&buf, "editor_extension", payloads, alloc);
            } else |err| {
                std.debug.print("editor extensions failed: {s}\n", .{@errorName(err)});
            }

            if (lifecycle.shouldStop()) break;
            if (extensions.collectExtensions(.browser)) |payloads| {
                emitBatch(&buf, "browser_extension", payloads, alloc);
            } else |err| {
                std.debug.print("browser extensions failed: {s}\n", .{@errorName(err)});
            }

            if (lifecycle.shouldStop()) break;
            if (mcp.collectConfigs()) |payloads| {
                emitBatch(&buf, "mcp_config", payloads, alloc);
            } else |err| {
                std.debug.print("mcp config failed: {s}\n", .{@errorName(err)});
            }
        }

        if (lifecycle.shouldStop()) break;
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
    std.debug.print("tawny-agent stopping\n", .{});
}

/// Quarantine directory. `%ProgramData%\Tawny\Quarantine` on Windows,
/// `/var/lib/tawny/quarantine` on Linux/macOS when writable, otherwise next to
/// the state file so an unprivileged dev or CI agent still works.
fn quarantineDir(alloc: std.mem.Allocator, state_path: []const u8) ![]u8 {
    if (builtin.target.os.tag == .windows) {
        const programdata = @import("env.zig").getEnvVarOwned(alloc, "PROGRAMDATA") catch
            try alloc.dupe(u8, "C:\\ProgramData");
        defer alloc.free(programdata);
        return alloc.print("{s}\\Tawny\\Quarantine", .{programdata});
    }
    const state_dir = std.fs.path.dirname(state_path) orelse ".";
    return std.fs.path.join(alloc, &.{ state_dir, "quarantine" });
}

const wfp = @import("platform/windows/wfp.zig");

/// At start, reconcile WFP filters with the stored isolation state. If the
/// deadline has passed, or there is no isolation on record, remove any stray
/// Tawny filters. If still isolated and the filters are gone (a crash), re-add
/// them from the stored inputs.
fn reconcileIsolation(alloc: std.mem.Allocator, cfg: *config_mod.Config) void {
    if (builtin.target.os.tag != .windows) return;
    const loaded = wfp.loadState(alloc, cfg.state_path);
    if (loaded == null) {
        // No record: clear anything stray so a crash never leaves isolation on.
        if (wfp.countFilters()) |n| {
            if (n > 0) wfp.release() catch {};
        } else |_| {}
        return;
    }
    const s = loaded.?;
    defer s.deinit();
    if (!s.value.isolated) {
        wfp.release() catch {};
        wfp.clearState(alloc, cfg.state_path);
        return;
    }
    if (wfp.deadlinePassed(s.value.started_unix, s.value.max_duration_seconds, iox.timestamp())) {
        std.log.info("isolation deadline passed; releasing", .{});
        wfp.release() catch {};
        wfp.clearState(alloc, cfg.state_path);
        return;
    }
    // Still isolated within the deadline: ensure the filters are present.
    const n = wfp.countFilters() catch 0;
    if (n == 0) {
        std.log.info("re-applying isolation filters after restart", .{});
        wfp.isolate(alloc, .{
            .server_ips = s.value.server_ips,
            .dns_resolvers = s.value.dns_resolvers,
            .admin_allowlist = s.value.admin_allowlist,
        }) catch |err| std.debug.print("re-isolate failed: {s}\n", .{@errorName(err)});
    }
}

/// On each heartbeat, release isolation if its deadline has passed with no
/// server renewal.
fn enforceIsolationDeadline(alloc: std.mem.Allocator, cfg: *config_mod.Config) void {
    if (builtin.target.os.tag != .windows) return;
    const loaded = wfp.loadState(alloc, cfg.state_path) orelse return;
    defer loaded.deinit();
    if (!loaded.value.isolated) return;
    if (wfp.deadlinePassed(loaded.value.started_unix, loaded.value.max_duration_seconds, iox.timestamp())) {
        std.log.info("isolation deadline passed; releasing", .{});
        wfp.release() catch {};
        wfp.clearState(alloc, cfg.state_path);
    }
}

/// Break-glass: `tawny-agent release --code <code>`. The code is
/// HMAC-SHA256(secret, agent_id|nonce). The per-agent secret comes from
/// TAWNY_ISOLATION_SECRET (shown in the UI); the nonce is the one recorded when
/// isolation started. On a valid code the agent releases WFP isolation offline.
fn releaseCodeCommand(alloc: std.mem.Allocator, code: []const u8) !void {
    var cfg = try config_mod.load(alloc);
    defer cfg.deinit();
    const agent_id = cfg.agent_id orelse {
        std.debug.print("release: this host is not enrolled\n", .{});
        return;
    };
    const secret = @import("env.zig").getEnvVarOwned(alloc, "TAWNY_ISOLATION_SECRET") catch null;
    defer if (secret) |s| alloc.free(s);
    if (secret == null or secret.?.len == 0) {
        std.debug.print("release: TAWNY_ISOLATION_SECRET is not set; cannot verify the break-glass code\n", .{});
        return;
    }
    const loaded = wfp.loadState(alloc, cfg.state_path) orelse {
        std.debug.print("release: no isolation on record\n", .{});
        return;
    };
    defer loaded.deinit();
    if (!wfp.verifyReleaseCode(secret.?, agent_id, loaded.value.nonce, code)) {
        std.debug.print("release: break-glass code did not verify\n", .{});
        return;
    }
    wfp.release() catch |err| {
        std.debug.print("release: {s}\n", .{@errorName(err)});
        return;
    };
    wfp.clearState(alloc, cfg.state_path);
    std.debug.print("release: isolation released by break-glass code\n", .{});
}

fn scrubEnrollmentToken(alloc: std.mem.Allocator, config_path: []const u8) void {
    const removed = config_mod.removeEnrollmentToken(alloc, config_path) catch |err| {
        std.log.warn(
            "enrollment token is still present in {s} and could not be removed ({s}); delete the enrollment_token line manually",
            .{ config_path, @errorName(err) },
        );
        return;
    };
    if (removed) std.log.info("removed spent enrollment_token from {s}", .{config_path});
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
    _ = lifecycle;
    _ = iox;
    _ = entity;
    _ = @import("schema_check.zig");
    _ = @import("yara.zig");
    _ = @import("rule_pack.zig");
    _ = @import("yara_scanner.zig");
    _ = @import("yara_key.zig");
    _ = @import("action_sig.zig");
    _ = @import("action_key.zig");
    _ = @import("action_journal.zig");
    _ = @import("quarantine.zig");
    _ = @import("platform/windows/wfp.zig");
    _ = @import("platform/windows/process_control.zig");
    _ = @import("response_debug.zig");
    // Pure macOS parsers have no syscalls, so their tests run on every host.
    _ = @import("platform/macos/parse.zig");
    // Windows event log parsing and mapping are pure too.
    _ = @import("platform/windows/evtxml.zig");
    _ = windows_events;
    if (builtin.target.os.tag == .macos) {
        _ = @import("platform/macos/fsevents.zig");
        _ = @import("platform/macos/dnslog.zig");
    }
    if (builtin.target.os.tag == .windows) _ = windows_service;
}

fn yaraRuleKey(text: ?[]const u8) ?std.crypto.sign.Ed25519.PublicKey {
    const b64 = text orelse return null;
    var raw: [32]u8 = undefined;
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(b64) catch return null;
    if (n != raw.len) return null;
    dec.decode(&raw, b64) catch return null;
    return std.crypto.sign.Ed25519.PublicKey.fromBytes(raw) catch null;
}

fn refreshYaraPack(alloc: std.mem.Allocator, http: *transport.Client, yara: *yara_scanner.Scanner) void {
    const pack = http.fetchYaraPack() catch |err| {
        std.debug.print("yara pack fetch failed: {s}\n", .{@errorName(err)});
        return;
    };
    defer alloc.free(pack);
    yara.loadPack(pack) catch |err| {
        // Unsigned, tampered or wrong-key packs land here; old rules stay.
        std.debug.print("yara pack refused: {s}\n", .{@errorName(err)});
    };
}

/// `yara_scan` response action: payload `{"path": "..."}`, a file or a folder.
fn runYaraAction(alloc: std.mem.Allocator, http: *transport.Client, yara: *yara_scanner.Scanner, buf: *buffer.Buffer, action: transport.ResponseAction) void {
    const report = struct {
        fn send(h: *transport.Client, a: transport.ResponseAction, status: []const u8, msg: []const u8) void {
            h.reportActionResult(a.id, a.execution_token, status, msg) catch |err| {
                std.debug.print("yara_scan result report failed: {s}\n", .{@errorName(err)});
            };
        }
    }.send;
    if (yara.rules == null) return report(http, action, "failed", "no verified YARA rule pack on this agent");
    const parsed = std.json.parseFromSlice(struct { path: []const u8 }, alloc, action.payload, .{ .ignore_unknown_fields = true }) catch
        return report(http, action, "failed", "payload needs a path");
    defer parsed.deinit();
    const path = parsed.value.path;
    if (path.len == 0 or path.len > 4096) return report(http, action, "failed", "payload needs a path");
    const io = iox.current();
    const is_dir = blk: {
        var d = std.Io.Dir.cwd().openDir(io, path, .{}) catch break :blk false;
        d.close(io);
        break :blk true;
    };
    const hits = (if (is_dir) yara.scanFolder(path, .response_action) else yara.scanPath(path, .response_action)) catch |err|
        return report(http, action, "failed", @errorName(err));
    const n = hits.len;
    emitBatch(buf, "yara_match", hits, alloc);
    var msg_buf: [64]u8 = undefined;
    const msg = std.fmt.bufPrint(&msg_buf, "scan finished, {d} match(es)", .{n}) catch "scan finished";
    report(http, action, "succeeded", msg);
}

fn scheduledYaraScan(alloc: std.mem.Allocator, yara: *yara_scanner.Scanner, buf: *buffer.Buffer) void {
    var env = yara_scanner.ProcessEnv{ .alloc = alloc };
    defer env.deinit();
    const folders = yara_scanner.scheduledFolders(alloc, &env) catch return;
    defer {
        for (folders) |f| alloc.free(f);
        alloc.free(folders);
    }
    for (folders) |folder| {
        if (lifecycle.shouldStop()) return;
        const hits = yara.scanFolder(folder, .scheduled) catch |err| {
            std.debug.print("yara scheduled scan of {s} failed: {s}\n", .{ folder, @errorName(err) });
            continue;
        };
        emitBatch(buf, "yara_match", hits, alloc);
    }
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

/// `agent_health` data (schemas/events/agent_health.v1.json).
fn healthPayload(alloc: std.mem.Allocator, uptime: i64, depth: usize, next_sequence: u64, boot_id: []const u8) ![]u8 {
    return std.json.Stringify.valueAlloc(alloc, .{
        .sensor_version = AGENT_VERSION,
        .buffer_depth = depth,
        .uptime_seconds = @max(uptime, 0),
        .next_sequence = next_sequence,
        .boot_id = boot_id,
    }, .{});
}

test "agent_health payload matches its schema" {
    const p = try healthPayload(std.testing.allocator, 5, 2, 9, entity.nil_uuid);
    defer std.testing.allocator.free(p);
    try @import("schema_check.zig").expectValid(std.testing.allocator, "agent_health", p);
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
