//! Linux kernel event source (#59, docs/architecture/linux-sensor.md).
//!
//! Picks audit netlink, the auditd log, Tetragon's export or nothing (the
//! /proc poller only), drains it once per agent loop and reports the choice
//! through `sensor_health` and `agent_health.sensors`.
const std = @import("std");
const builtin = @import("builtin");
const iox = @import("../io_compat.zig");
const entity = @import("../entity.zig");
const config = @import("../config.zig");
const process_events = @import("process_events.zig");
const audit = @import("../platform/linux/audit.zig");
const tetragon = @import("../platform/linux/tetragon.zig");

pub const Source = enum {
    audit_netlink,
    audit_multicast,
    audit_log,
    tetragon,
    proc_poller,

    pub fn kernel(self: Source) bool {
        return self != .proc_poller;
    }

    /// Sources that see every exec on their own. The others depend on
    /// rules or a log someone else controls, so the poller keeps its normal
    /// interval beside them.
    pub fn complete(self: Source) bool {
        return self == .audit_netlink or self == .tetragon;
    }
};

/// The /proc poller interval while a kernel source is running.
pub const reconcile_seconds: u32 = 600;
pub const default_audit_log = "/var/log/audit/audit.log";
/// An event whose EOE never came is completed after this long.
const stale_seconds: u64 = 5;
/// Mapped events per drain at most; the rest wait for the next loop.
const max_items_per_collect: usize = 8192;

pub const Item = struct {
    event_type: []const u8,
    payload: []u8,
    occurred_at: i64,
};

pub const Options = struct {
    mode: config.LinuxSensor = .auto,
    audit_log_path: ?[]const u8 = null,
    tetragon_export_path: ?[]const u8 = null,
    watch_dirs: []const []const u8 = &.{},
    /// Register as the audit daemon when no other owns the socket.
    allow_daemon: bool = true,
};

/// Bounded set of entity ids the kernel source reported, so the
/// reconciliation pass does not report them again.
const IdSet = struct {
    map: std.AutoHashMapUnmanaged(entity.Id, void) = .empty,
    const cap: usize = 16384;

    fn add(self: *IdSet, alloc: std.mem.Allocator, id: entity.Id) void {
        if (self.map.count() >= cap) self.map.clearRetainingCapacity();
        self.map.put(alloc, id, {}) catch {};
    }
    fn has(self: *const IdSet, id: entity.Id) bool {
        return self.map.contains(id);
    }
};

pub const Sensor = struct {
    alloc: std.mem.Allocator,
    table: ?*entity.Table = null,
    hashes: process_events.HashCache,
    source: Source = .proc_poller,
    /// Why the source is not audit netlink as the audit daemon.
    reason: []const u8 = "",
    live: ?*audit.Live = null,
    tail: ?audit.Tail = null,
    tail_path: ?[]u8 = null,
    asmb: audit.Assembler,
    boot_time: ?u64 = null,
    own_pid: u32 = 0,
    events: u64 = 0,
    last_event: i64 = 0,
    rate_events: u64 = 0,
    rate_since: i64 = 0,
    started: IdSet = .{},
    exited: IdSet = .{},
    /// A sensor_health event is due (start, source change).
    health_due: bool = true,

    pub fn init(alloc: std.mem.Allocator) Sensor {
        return .{
            .alloc = alloc,
            .hashes = process_events.HashCache.init(alloc),
            .asmb = audit.Assembler.init(alloc, false),
        };
    }

    pub fn deinit(self: *Sensor) void {
        if (comptime builtin.target.os.tag == .linux) {
            if (self.live) |l| l.close();
        }
        self.live = null;
        if (self.tail) |*t| t.deinit();
        if (self.tail_path) |p| self.alloc.free(p);
        self.asmb.deinit();
        self.hashes.deinit();
        self.started.map.deinit(self.alloc);
        self.exited.map.deinit(self.alloc);
    }

    pub fn kernelActive(self: *const Sensor) bool {
        return self.source.kernel();
    }

    /// /proc poller interval: a reconciliation pass beside a complete
    /// source, the configured interval otherwise.
    pub fn pollSeconds(self: *const Sensor, configured: u32) u32 {
        return if (self.source.complete()) @max(configured, reconcile_seconds) else configured;
    }

    /// Choose a source. Never fails: the fallback is the /proc poller.
    pub fn start(self: *Sensor, opts: Options) void {
        self.rate_since = iox.timestamp();
        if (comptime builtin.target.os.tag != .linux) {
            self.reason = "not linux";
            return;
        }
        self.own_pid = @intCast(std.os.linux.getpid());
        self.boot_time = process_events.readLinuxBootTime() catch null;
        const mode = opts.mode;
        if (mode == .proc) {
            self.reason = "linux_sensor = proc";
            return;
        }
        if (mode == .auto or mode == .audit) {
            if (audit.Live.open(self.alloc, opts.watch_dirs, opts.allow_daemon)) |live| {
                self.live = live;
                self.source = if (live.mode == .daemon) .audit_netlink else .audit_multicast;
                self.reason = if (live.mode == .daemon) "" else switch (live.daemon_error orelse error.AccessDenied) {
                    error.DaemonPresent => "another audit daemon owns the socket; reading its records read-only",
                    else => |e| multicastReason(e),
                };
                return;
            } else |err| {
                self.reason = openReason(err);
            }
        }
        if (mode == .auto or mode == .audit or mode == .audit_log) {
            const log_path = opts.audit_log_path orelse default_audit_log;
            if (self.openTail(log_path)) {
                self.source = .audit_log;
                self.asmb.complete_on_new_serial = true;
                if (mode == .audit_log) self.reason = "linux_sensor = audit_log";
                return;
            }
            if (mode == .audit_log) self.reason = "audit log not readable";
            if (mode == .audit or mode == .audit_log) return;
        }
        if (mode == .auto or mode == .tetragon) {
            const path = opts.tetragon_export_path orelse tetragon.default_export_path;
            if (self.openTail(path)) {
                self.source = .tetragon;
                if (mode == .tetragon) self.reason = "";
                return;
            }
            if (mode == .tetragon) self.reason = "tetragon export file not readable";
        }
    }

    fn openTail(self: *Sensor, path: []const u8) bool {
        const owned = self.alloc.dupe(u8, path) catch return false;
        self.tail = audit.Tail.open(self.alloc, owned, true) catch {
            self.alloc.free(owned);
            return false;
        };
        self.tail_path = owned;
        return true;
    }

    fn liveStart(self: *const Sensor, pid: u32) ?u64 {
        if (comptime builtin.target.os.tag != .linux) return null;
        const boot = self.boot_time orelse return null;
        const ticks = process_events.readProcessStartTime(self.alloc, pid) catch return null;
        return process_events.linuxStart100ns(boot, ticks);
    }

    /// Mapped events since the last call. Caller frees with `freeItems`.
    pub fn collect(self: *Sensor) ![]Item {
        var out: std.ArrayList(Item) = .empty;
        errdefer freeList(self.alloc, &out);
        switch (self.source) {
            .proc_poller => {},
            .audit_netlink, .audit_multicast => {
                try self.live.?.drain(&self.asmb);
                try self.asmb.flushOlderThan(@as(u64, @intCast(@max(iox.timestamp(), 0))) -| stale_seconds);
                try self.mapAudit(&out);
            },
            .audit_log => {
                if (self.tail.?.poll() catch null) |text| {
                    defer self.alloc.free(text);
                    try audit.feedLog(&self.asmb, text);
                }
                try self.asmb.flushOlderThan(@as(u64, @intCast(@max(iox.timestamp(), 0))) -| stale_seconds);
                try self.mapAudit(&out);
            },
            .tetragon => {
                if (self.tail.?.poll() catch null) |text| {
                    defer self.alloc.free(text);
                    var lines = std.mem.splitScalar(u8, text, '\n');
                    while (lines.next()) |line| {
                        if (out.items.len >= max_items_per_collect) break;
                        const l = (tetragon.mapLine(self.alloc, line, .{ .table = self.table }) catch null) orelse continue;
                        if (l.pid == self.own_pid) {
                            self.alloc.free(l.mapped.payload);
                            continue;
                        }
                        self.note(l.mapped.event_type, l.mapped.payload);
                        try appendItem(self.alloc, &out, l.mapped);
                    }
                }
            },
        }
        if (out.items.len > 0) {
            self.events += out.items.len;
            self.rate_events += out.items.len;
            self.last_event = iox.timestamp();
        }
        return out.toOwnedSlice(self.alloc);
    }

    fn mapAudit(self: *Sensor, out: *std.ArrayList(Item)) !void {
        const events = try self.asmb.take();
        defer {
            for (events) |e| self.asmb.destroy(e);
            self.alloc.free(events);
        }
        for (events) |e| {
            if (out.items.len >= max_items_per_collect) break;
            if (e.pid == self.own_pid and self.own_pid != 0) continue;
            const live = if (e.kind() == .exec) self.liveStart(e.pid) else null;
            const m = (audit.map(self.alloc, e, .{
                .table = self.table,
                .hashes = &self.hashes,
                .live_start_100ns = live,
            }) catch continue) orelse continue;
            self.note(m.event_type, m.payload);
            try appendItem(self.alloc, out, m);
        }
    }

    /// Remember process ids this source reported.
    fn note(self: *Sensor, event_type: []const u8, payload: []const u8) void {
        const id = processEntity(payload) orelse return;
        if (std.mem.eql(u8, event_type, "process_start")) self.started.add(self.alloc, id);
        if (std.mem.eql(u8, event_type, "process_exit")) self.exited.add(self.alloc, id);
    }

    /// True when the reconciliation pass should drop this payload because
    /// the kernel source already reported it.
    pub fn alreadyReported(self: *const Sensor, event_type: []const u8, payload: []const u8) bool {
        if (!self.kernelActive()) return false;
        const id = processEntity(payload) orelse return false;
        if (std.mem.eql(u8, event_type, "process_start")) return self.started.has(id);
        if (std.mem.eql(u8, event_type, "process_exit")) return self.exited.has(id);
        return false;
    }

    /// Events per minute since the previous call (one health interval).
    pub fn takeRate(self: *Sensor) u64 {
        const now = iox.timestamp();
        const elapsed: u64 = @intCast(@max(now - self.rate_since, 1));
        const rate = self.rate_events * 60 / elapsed;
        self.rate_events = 0;
        self.rate_since = now;
        return rate;
    }

    pub fn status(self: *const Sensor) []const u8 {
        return if (self.source == .audit_netlink or (self.source == .tetragon and self.reason.len == 0)) "running" else "degraded";
    }

    /// `sensor_health` payload (schemas/events/sensor_health.v1.json).
    pub fn healthPayload(self: *const Sensor, alloc: std.mem.Allocator) ![]u8 {
        var out: std.Io.Writer.Allocating = .init(alloc);
        errdefer out.deinit();
        var jw: std.json.Stringify = .{ .writer = &out.writer };
        try jw.beginObject();
        try jw.objectField("sensor");
        try jw.write("linux_kernel");
        try jw.objectField("channel");
        try jw.write(@tagName(self.source));
        try jw.objectField("state");
        try jw.write(if (self.source.kernel()) "ok" else "missing");
        try jw.objectField("status");
        try jw.write(if (std.mem.eql(u8, self.status(), "running")) "ok" else "degraded");
        try jw.objectField("source");
        try jw.write(@tagName(self.source));
        if (self.reason.len > 0) {
            try jw.objectField("reason");
            try jw.write(self.reason);
        }
        try jw.objectField("process_start_source");
        try jw.write(if (self.source.kernel()) @tagName(self.source) else "proc_poller");
        if (self.tail_path) |p| {
            try jw.objectField("path");
            try jw.write(p);
        }
        try jw.objectField("counters");
        try jw.beginObject();
        try jw.objectField("events");
        try jw.write(self.events);
        if (self.live) |l| {
            try jw.objectField("dropped");
            try jw.write(l.dropped.load(.monotonic));
            try jw.objectField("records");
            try jw.write(l.received.load(.monotonic));
        }
        try jw.objectField("assembler_evicted");
        try jw.write(self.asmb.evicted);
        try jw.endObject();
        try jw.endObject();
        return out.toOwnedSlice();
    }
};

fn openReason(err: audit.OpenError) []const u8 {
    return switch (err) {
        error.AccessDenied => "audit netlink refused (needs CAP_AUDIT_CONTROL or CAP_AUDIT_READ)",
        error.DaemonPresent => "another audit daemon owns the socket and the multicast group was refused",
        error.AuditUnavailable => "audit netlink unavailable (no kernel audit, or not in the initial namespaces)",
        error.UnsupportedArch => "audit rules not supported on this architecture",
        error.ThreadStartFailed => switch (audit.last_spawn_errno) {
            1 => "audit reader thread refused (pthread_create EPERM)",
            11 => "audit reader thread refused (pthread_create EAGAIN, thread limit)",
            22 => "audit reader thread refused (pthread_create EINVAL)",
            else => "audit reader thread refused (pthread_create failed)",
        },
        else => "audit netlink failed to start",
    };
}

fn multicastReason(err: audit.OpenError) []const u8 {
    return switch (err) {
        error.AccessDenied => "cannot register as the audit daemon (needs CAP_AUDIT_CONTROL); reading the multicast group, which carries only rules others load",
        error.AuditUnavailable => "cannot register as the audit daemon (not in the initial namespaces); reading the multicast group, which carries only rules others load",
        else => "cannot register as the audit daemon; reading the multicast group, which carries only rules others load",
    };
}

fn appendItem(alloc: std.mem.Allocator, out: *std.ArrayList(Item), m: audit.Mapped) !void {
    out.append(alloc, .{ .event_type = m.event_type, .payload = m.payload, .occurred_at = m.occurred_at }) catch |err| {
        alloc.free(m.payload);
        return err;
    };
}

fn freeList(alloc: std.mem.Allocator, list: *std.ArrayList(Item)) void {
    for (list.items) |i| alloc.free(i.payload);
    list.deinit(alloc);
}

pub fn freeItems(alloc: std.mem.Allocator, items: []Item) void {
    for (items) |i| alloc.free(i.payload);
    alloc.free(items);
}

/// `process.entity_id` from a payload built by this agent.
pub fn processEntity(payload: []const u8) ?entity.Id {
    const key = "\"process\":{\"entity_id\":\"";
    const at = std.mem.indexOf(u8, payload, key) orelse return null;
    const start = at + key.len;
    if (start + entity.len > payload.len) return null;
    return payload[start..][0..entity.len].*;
}

/// `tawny-agent --linux-sensor-dump [--seconds N] [--source auto|audit|tetragon|proc]
/// [--audit-log PATH] [--tetragon-export PATH] [--watch DIR]`: start the
/// kernel source, print `SENSOR_HEALTH<TAB>json` and `READY`, then for N
/// seconds print each event as `EVENT<TAB>type<TAB>json`, then a SUMMARY line.
/// No server or enrolment. CI uses it to prove the capability set.
pub fn dumpCommand(alloc: std.mem.Allocator, args: []const []const u8) !void {
    var opts = Options{};
    var seconds: u32 = 10;
    var watch: std.ArrayList([]const u8) = .empty;
    defer watch.deinit(alloc);
    var i: usize = 0;
    while (i < args.len) : (i += 2) {
        if (i + 1 >= args.len) return error.InvalidArguments;
        const a = args[i];
        const v = args[i + 1];
        if (std.mem.eql(u8, a, "--seconds")) {
            seconds = try std.fmt.parseInt(u32, v, 10);
        } else if (std.mem.eql(u8, a, "--source")) {
            opts.mode = std.meta.stringToEnum(config.LinuxSensor, v) orelse return error.InvalidArguments;
        } else if (std.mem.eql(u8, a, "--audit-log")) {
            opts.audit_log_path = v;
        } else if (std.mem.eql(u8, a, "--tetragon-export")) {
            opts.tetragon_export_path = v;
        } else if (std.mem.eql(u8, a, "--watch")) {
            try watch.append(alloc, v);
        } else return error.InvalidArguments;
    }
    opts.watch_dirs = watch.items;

    var boot = entity.readBootId();
    var table = entity.Table.init(alloc, entity.nil_uuid, &boot, entity.Table.default_capacity);
    defer table.deinit();
    var sensor = Sensor.init(alloc);
    defer sensor.deinit();
    sensor.table = &table;
    sensor.start(opts);

    var out_buf: [64 * 1024]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(iox.current(), &out_buf);
    const w = &stdout.interface;
    const health = try sensor.healthPayload(alloc);
    defer alloc.free(health);
    try w.print("SENSOR_HEALTH\t{s}\n", .{health});
    try w.print("READY\t{s}\t{s}\n", .{ @tagName(sensor.source), sensor.status() });
    try w.flush();

    var counts: [4]u64 = @splat(0);
    const names = [_][]const u8{ "process_start", "process_exit", "network_connect", "file_create" };
    var timer = try iox.Timer.start();
    // One more drain after the deadline picks up the last records.
    var last = false;
    while (true) {
        if (timer.read() / std.time.ns_per_s >= seconds) last = true;
        if (last) iox.sleep(500 * std.time.ns_per_ms);
        const items = try sensor.collect();
        defer freeItems(alloc, items);
        for (items) |it| {
            for (names, 0..) |n, k| if (std.mem.eql(u8, n, it.event_type)) {
                counts[k] += 1;
            };
            try w.print("EVENT\t{s}\t{s}\n", .{ it.event_type, it.payload });
        }
        try w.flush();
        if (last) break;
        iox.sleep(250 * std.time.ns_per_ms);
    }
    try w.print("SUMMARY\tsource={s}\tstatus={s}\tprocess_start={d}\tprocess_exit={d}\tnetwork_connect={d}\tfile_create={d}\n", .{ @tagName(sensor.source), sensor.status(), counts[0], counts[1], counts[2], counts[3] });
    try w.flush();
}

test "sensor health payload matches its schema in each state" {
    const alloc = std.testing.allocator;
    var s = Sensor.init(alloc);
    defer s.deinit();
    s.reason = "audit netlink refused (needs CAP_AUDIT_CONTROL or CAP_AUDIT_READ)";
    const degraded = try s.healthPayload(alloc);
    defer alloc.free(degraded);
    try @import("../schema_check.zig").expectValid(alloc, "sensor_health", degraded);
    try std.testing.expect(std.mem.indexOf(u8, degraded, "\"status\":\"degraded\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, degraded, "\"process_start_source\":\"proc_poller\"") != null);
    try std.testing.expectEqualStrings("degraded", s.status());
    try std.testing.expect(!s.kernelActive());

    s.source = .audit_netlink;
    s.reason = "";
    const ok = try s.healthPayload(alloc);
    defer alloc.free(ok);
    try @import("../schema_check.zig").expectValid(alloc, "sensor_health", ok);
    try std.testing.expect(std.mem.indexOf(u8, ok, "\"status\":\"ok\"") != null);
    try std.testing.expectEqualStrings("running", s.status());
}

test "reconciliation drops processes the kernel source reported" {
    const alloc = std.testing.allocator;
    var s = Sensor.init(alloc);
    defer s.deinit();
    const id: entity.Id = "abcdefghijklmnopqrstuvwxyz".*;
    const p = "{\"process\":{\"entity_id\":\"abcdefghijklmnopqrstuvwxyz\",\"pid\":5}}";
    s.note("process_start", p);
    try std.testing.expect(!s.alreadyReported("process_start", p)); // proc only
    s.source = .audit_netlink;
    try std.testing.expect(s.alreadyReported("process_start", p));
    try std.testing.expect(!s.alreadyReported("process_exit", p));
    try std.testing.expectEqual(id, processEntity(p).?);
    try std.testing.expect(processEntity("{\"process\":{\"pid\":5}}") == null);
}

test "fallback without a kernel source keeps the poller" {
    const alloc = std.testing.allocator;
    var s = Sensor.init(alloc);
    defer s.deinit();
    s.start(.{ .mode = .proc });
    try std.testing.expectEqual(Source.proc_poller, s.source);
    const items = try s.collect();
    defer freeItems(alloc, items);
    try std.testing.expectEqual(@as(usize, 0), items.len);
}
