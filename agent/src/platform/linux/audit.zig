//! Linux kernel audit sensor (#59, docs/architecture/linux-sensor.md).
//!
//! Records come from a `NETLINK_AUDIT` socket (the agent registered as the
//! audit daemon, or the read-only multicast group when auditd owns the
//! socket) or from auditd's log file. Each record carries
//! `audit(<sec>.<ms>:<serial>)`; records with the same serial are one kernel
//! event. `Assembler` joins them, `map` turns a joined event into a v2
//! `process_start`, `process_exit`, `network_connect` or `file_create`
//! payload. Parsing, joining and mapping are pure so the tests run on every
//! OS against captured records in testdata/.
const std = @import("std");
const builtin = @import("builtin");
const entity = @import("../../entity.zig");
const privacy = @import("../../collectors/privacy.zig");
const process_events = @import("../../collectors/process_events.zig");
const iox = @import("../../io_compat.zig");

// ---------------------------------------------------------------------------
// Kernel constants, from include/uapi/linux/audit.h and linux/netlink.h. The
// pin test below checks them against the values in that header.

pub const netlink_audit: u32 = 9;
/// AUDIT_NLGRP_READLOG, the read-only multicast group (needs CAP_AUDIT_READ).
pub const nlgrp_readlog: u32 = 1;

pub const msg = struct {
    pub const get: u16 = 1000;
    pub const set: u16 = 1001;
    pub const add_rule: u16 = 1011;
    pub const del_rule: u16 = 1012;
    pub const syscall: u16 = 1300;
    pub const path: u16 = 1302;
    pub const sockaddr: u16 = 1306;
    pub const cwd: u16 = 1307;
    pub const execve: u16 = 1309;
    pub const eoe: u16 = 1320;
    pub const proctitle: u16 = 1327;
};

const status_enabled: u32 = 0x0001;
const status_pid: u32 = 0x0004;
const status_backlog_limit: u32 = 0x0010;
const filter_exit: u32 = 0x04;
const action_always: u32 = 2;
const field_arch: u32 = 11;
const field_perm: u32 = 106;
const field_dir: u32 = 107;
const field_filterkey: u32 = 210;
const op_equal: u32 = 0x40000000;
const perm_write: u32 = 2;
const perm_attr: u32 = 8;
const max_fields: usize = 64;
const bitmask_words: usize = 64;

pub const arch_x86_64: u32 = 62 | 0x80000000 | 0x40000000;
pub const arch_aarch64: u32 = 183 | 0x80000000 | 0x40000000;

/// Filter key on every rule the agent loads, so a restart can remove them.
pub const rule_key = "tawny";
const einprogress: i64 = -115;

pub const Kind = enum { exec, connect, exit_group };

/// Syscalls the mapper cares about. PATH records with nametype=CREATE from
/// any other syscall become `file_create`.
pub fn syscallKind(arch: u32, nr: u32) ?Kind {
    return switch (arch) {
        arch_x86_64 => switch (nr) {
            59, 322 => .exec,
            42 => .connect,
            231 => .exit_group,
            else => null,
        },
        arch_aarch64 => switch (nr) {
            221, 281 => .exec,
            203 => .connect,
            94 => .exit_group,
            else => null,
        },
        else => null,
    };
}

// ---------------------------------------------------------------------------
// Records

pub const Record = struct {
    type: u16,
    sec: u64,
    ms: u32,
    serial: u64,
    body: []const u8,
};

/// A netlink record: the message type from nlmsghdr and the payload
/// `audit(1731200000.123:4567): key=value ...`.
pub fn parseNetlink(msg_type: u16, payload: []const u8) ?Record {
    const text = std.mem.trimEnd(u8, payload, "\x00\n");
    return parseStamped(msg_type, text);
}

/// An auditd log line: `type=SYSCALL msg=audit(...): key=value ...`, with an
/// optional `node=` prefix and the enriched `\x1d` suffix.
pub fn parseLogLine(line: []const u8) ?Record {
    const at = std.mem.indexOf(u8, line, "type=") orelse return null;
    var rest = line[at + "type=".len ..];
    const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse return null;
    const t = typeFromName(rest[0..sp]) orelse return null;
    rest = rest[sp + 1 ..];
    if (!std.mem.startsWith(u8, rest, "msg=")) return null;
    return parseStamped(t, rest["msg=".len..]);
}

fn parseStamped(msg_type: u16, text: []const u8) ?Record {
    if (!std.mem.startsWith(u8, text, "audit(")) return null;
    const close = std.mem.indexOfScalar(u8, text, ')') orelse return null;
    const stamp = text["audit(".len..close];
    const dot = std.mem.indexOfScalar(u8, stamp, '.') orelse return null;
    const colon = std.mem.indexOfScalar(u8, stamp, ':') orelse return null;
    if (colon < dot) return null;
    const sec = std.fmt.parseInt(u64, stamp[0..dot], 10) catch return null;
    const ms = std.fmt.parseInt(u32, stamp[dot + 1 .. colon], 10) catch return null;
    const serial = std.fmt.parseInt(u64, stamp[colon + 1 ..], 10) catch return null;
    var body = text[close + 1 ..];
    if (std.mem.startsWith(u8, body, ":")) body = body[1..];
    if (std.mem.indexOfScalar(u8, body, 0x1d)) |gs| body = body[0..gs];
    return .{ .type = msg_type, .sec = sec, .ms = ms, .serial = serial, .body = std.mem.trim(u8, body, " ") };
}

fn typeFromName(name: []const u8) ?u16 {
    const names = [_]struct { []const u8, u16 }{
        .{ "SYSCALL", msg.syscall },     .{ "PATH", msg.path },
        .{ "SOCKADDR", msg.sockaddr },   .{ "CWD", msg.cwd },
        .{ "EXECVE", msg.execve },       .{ "EOE", msg.eoe },
        .{ "PROCTITLE", msg.proctitle },
    };
    for (names) |n| if (std.mem.eql(u8, n[0], name)) return n[1];
    return null;
}

pub const Field = struct {
    key: []const u8,
    value: []const u8,
    quoted: bool,
};

/// `key=value` pairs. Values are `"quoted"`, bare, or bare hex for untrusted
/// strings that hold spaces, quotes or control bytes.
pub const FieldIter = struct {
    s: []const u8,
    i: usize = 0,

    pub fn next(self: *FieldIter) ?Field {
        while (self.i < self.s.len and self.s[self.i] == ' ') self.i += 1;
        if (self.i >= self.s.len) return null;
        const key_start = self.i;
        while (self.i < self.s.len and self.s[self.i] != '=' and self.s[self.i] != ' ') self.i += 1;
        const key = self.s[key_start..self.i];
        if (self.i >= self.s.len or self.s[self.i] != '=') return .{ .key = key, .value = "", .quoted = false };
        self.i += 1;
        if (self.i < self.s.len and (self.s[self.i] == '"' or self.s[self.i] == '\'')) {
            const q = self.s[self.i];
            self.i += 1;
            const v_start = self.i;
            while (self.i < self.s.len and self.s[self.i] != q) self.i += 1;
            const v = self.s[v_start..self.i];
            if (self.i < self.s.len) self.i += 1;
            return .{ .key = key, .value = v, .quoted = true };
        }
        const v_start = self.i;
        while (self.i < self.s.len and self.s[self.i] != ' ') self.i += 1;
        return .{ .key = key, .value = self.s[v_start..self.i], .quoted = false };
    }
};

/// Decode an untrusted string field: quoted text as is, `(null)` as empty,
/// bare hex decoded. Appends to `out`, bounded by `limit`.
fn appendString(alloc: std.mem.Allocator, out: *std.ArrayList(u8), f: Field, limit: usize) !void {
    const room = limit -| out.items.len;
    if (room == 0) return;
    if (f.quoted) return out.appendSlice(alloc, f.value[0..@min(f.value.len, room)]);
    if (std.mem.eql(u8, f.value, "(null)")) return;
    if (f.value.len % 2 == 0 and isHex(f.value)) {
        const n = @min(f.value.len / 2, room);
        try out.ensureUnusedCapacity(alloc, n);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const b = std.fmt.parseInt(u8, f.value[i * 2 .. i * 2 + 2], 16) catch unreachable;
            out.appendAssumeCapacity(b);
        }
        return;
    }
    return out.appendSlice(alloc, f.value[0..@min(f.value.len, room)]);
}

fn isHex(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Joining records by serial

const max_string_bytes: usize = 4096;
const max_args: usize = 256;
const max_arg_bytes: usize = 32 * 1024;
const max_paths: usize = 8;

pub const PathItem = struct {
    name: std.ArrayList(u8) = .empty,
    create: bool = false,
    parent: bool = false,
};

/// One kernel event: the records that share a serial.
pub const Event = struct {
    serial: u64,
    sec: u64,
    ms: u32,
    have_syscall: bool = false,
    arch: u32 = 0,
    syscall: u32 = 0,
    success: ?bool = null,
    exit: i64 = 0,
    pid: u32 = 0,
    ppid: u32 = 0,
    uid: u32 = 0,
    comm: std.ArrayList(u8) = .empty,
    exe: std.ArrayList(u8) = .empty,
    cwd: std.ArrayList(u8) = .empty,
    proctitle: std.ArrayList(u8) = .empty,
    args: std.ArrayList(std.ArrayList(u8)) = .empty,
    arg_bytes: usize = 0,
    paths: std.ArrayList(PathItem) = .empty,
    saddr: std.ArrayList(u8) = .empty,

    pub fn deinit(self: *Event, alloc: std.mem.Allocator) void {
        self.comm.deinit(alloc);
        self.exe.deinit(alloc);
        self.cwd.deinit(alloc);
        self.proctitle.deinit(alloc);
        for (self.args.items) |*a| a.deinit(alloc);
        self.args.deinit(alloc);
        for (self.paths.items) |*p| p.name.deinit(alloc);
        self.paths.deinit(alloc);
        self.saddr.deinit(alloc);
    }

    pub fn time100ns(self: *const Event) u64 {
        return self.sec * entity.ticks_per_second + @as(u64, self.ms) * entity.ticks_per_ms;
    }

    pub fn kind(self: *const Event) ?Kind {
        if (!self.have_syscall) return null;
        return syscallKind(self.arch, self.syscall);
    }

    fn add(self: *Event, alloc: std.mem.Allocator, rec: Record) !void {
        var it = FieldIter{ .s = rec.body };
        switch (rec.type) {
            msg.syscall => {
                self.have_syscall = true;
                while (it.next()) |f| {
                    if (eq(f.key, "arch")) {
                        self.arch = std.fmt.parseInt(u32, f.value, 16) catch 0;
                    } else if (eq(f.key, "syscall")) {
                        self.syscall = std.fmt.parseInt(u32, f.value, 10) catch 0;
                    } else if (eq(f.key, "success")) {
                        self.success = eq(f.value, "yes");
                    } else if (eq(f.key, "exit")) {
                        self.exit = std.fmt.parseInt(i64, f.value, 10) catch 0;
                    } else if (eq(f.key, "pid")) {
                        self.pid = std.fmt.parseInt(u32, f.value, 10) catch 0;
                    } else if (eq(f.key, "ppid")) {
                        self.ppid = std.fmt.parseInt(u32, f.value, 10) catch 0;
                    } else if (eq(f.key, "uid")) {
                        self.uid = std.fmt.parseInt(u32, f.value, 10) catch 0;
                    } else if (eq(f.key, "comm")) {
                        self.comm.clearRetainingCapacity();
                        try appendString(alloc, &self.comm, f, max_string_bytes);
                    } else if (eq(f.key, "exe")) {
                        self.exe.clearRetainingCapacity();
                        try appendString(alloc, &self.exe, f, max_string_bytes);
                    }
                }
            },
            msg.execve => while (it.next()) |f| {
                try self.addArg(alloc, f);
            },
            msg.cwd => while (it.next()) |f| {
                if (eq(f.key, "cwd")) {
                    self.cwd.clearRetainingCapacity();
                    try appendString(alloc, &self.cwd, f, max_string_bytes);
                }
            },
            msg.proctitle => while (it.next()) |f| {
                if (eq(f.key, "proctitle")) {
                    self.proctitle.clearRetainingCapacity();
                    try appendString(alloc, &self.proctitle, f, max_arg_bytes);
                }
            },
            msg.sockaddr => while (it.next()) |f| {
                if (eq(f.key, "saddr") and f.value.len <= 256 and f.value.len % 2 == 0 and isHex(f.value)) {
                    self.saddr.clearRetainingCapacity();
                    try appendString(alloc, &self.saddr, f, 128);
                }
            },
            msg.path => {
                if (self.paths.items.len >= max_paths) return;
                var item = PathItem{};
                errdefer item.name.deinit(alloc);
                while (it.next()) |f| {
                    if (eq(f.key, "name")) {
                        try appendString(alloc, &item.name, f, max_string_bytes);
                    } else if (eq(f.key, "nametype")) {
                        item.create = eq(f.value, "CREATE");
                        item.parent = eq(f.value, "PARENT");
                    }
                }
                try self.paths.append(alloc, item);
            },
            else => {},
        }
    }

    /// EXECVE fields: `argc`, `aN`, and for long arguments `aN_len` plus
    /// chunks `aN[i]`.
    fn addArg(self: *Event, alloc: std.mem.Allocator, f: Field) !void {
        if (f.key.len < 2 or f.key[0] != 'a' or !std.ascii.isDigit(f.key[1])) return;
        var end: usize = 1;
        while (end < f.key.len and std.ascii.isDigit(f.key[end])) end += 1;
        const rest = f.key[end..];
        if (std.mem.eql(u8, rest, "_len")) return;
        if (rest.len > 0 and rest[0] != '[') return;
        const index = std.fmt.parseInt(usize, f.key[1..end], 10) catch return;
        if (index >= max_args) return;
        while (self.args.items.len <= index) try self.args.append(alloc, .empty);
        const before = self.args.items[index].items.len;
        try appendString(alloc, &self.args.items[index], f, before + (max_arg_bytes -| self.arg_bytes));
        self.arg_bytes += self.args.items[index].items.len - before;
    }
};

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

/// Joins records into events by serial. Netlink delivers an EOE record after
/// each multi-record event; auditd's log does not, so with
/// `complete_on_new_serial` a record with a new serial completes the others.
/// `flushOlderThan` bounds how long a lost EOE can hold an event.
pub const Assembler = struct {
    alloc: std.mem.Allocator,
    complete_on_new_serial: bool = false,
    pending: std.AutoArrayHashMapUnmanaged(u64, *Event) = .empty,
    done: std.ArrayList(*Event) = .empty,
    /// Records for serials past the pending cap, completed early.
    evicted: u64 = 0,

    pub const max_pending: usize = 1024;

    pub fn init(alloc: std.mem.Allocator, complete_on_new_serial: bool) Assembler {
        return .{ .alloc = alloc, .complete_on_new_serial = complete_on_new_serial };
    }

    pub fn deinit(self: *Assembler) void {
        for (self.pending.values()) |e| self.destroy(e);
        self.pending.deinit(self.alloc);
        for (self.done.items) |e| self.destroy(e);
        self.done.deinit(self.alloc);
    }

    pub fn destroy(self: *Assembler, e: *Event) void {
        e.deinit(self.alloc);
        self.alloc.destroy(e);
    }

    pub fn feed(self: *Assembler, rec: Record) !void {
        switch (rec.type) {
            msg.syscall, msg.execve, msg.cwd, msg.path, msg.sockaddr, msg.proctitle, msg.eoe => {},
            else => return,
        }
        if (self.complete_on_new_serial and !self.pending.contains(rec.serial)) try self.completeAll();
        if (rec.type == msg.eoe) {
            if (self.pending.fetchOrderedRemove(rec.serial)) |kv| try self.finish(kv.value);
            return;
        }
        const gop = try self.pending.getOrPut(self.alloc, rec.serial);
        if (!gop.found_existing) {
            const e = self.alloc.create(Event) catch |err| {
                _ = self.pending.orderedRemove(rec.serial);
                return err;
            };
            e.* = .{ .serial = rec.serial, .sec = rec.sec, .ms = rec.ms };
            gop.value_ptr.* = e;
        }
        try gop.value_ptr.*.add(self.alloc, rec);
        if (self.pending.count() > max_pending) {
            const oldest = self.pending.values()[0];
            self.pending.orderedRemoveAt(0);
            self.evicted += 1;
            try self.finish(oldest);
        }
    }

    fn finish(self: *Assembler, e: *Event) !void {
        self.done.append(self.alloc, e) catch |err| {
            self.destroy(e);
            return err;
        };
    }

    pub fn completeAll(self: *Assembler) !void {
        while (self.pending.count() > 0) {
            const e = self.pending.values()[0];
            self.pending.orderedRemoveAt(0);
            try self.finish(e);
        }
    }

    /// Complete events whose first record is older than `sec`.
    pub fn flushOlderThan(self: *Assembler, sec: u64) !void {
        while (self.pending.count() > 0) {
            const e = self.pending.values()[0];
            if (e.sec >= sec) break;
            self.pending.orderedRemoveAt(0);
            try self.finish(e);
        }
    }

    /// Completed events in arrival order. Free each with `destroy`.
    pub fn take(self: *Assembler) ![]*Event {
        return self.done.toOwnedSlice(self.alloc);
    }
};

/// Feed every line of an auditd log chunk.
pub fn feedLog(asmb: *Assembler, text: []const u8) !void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (parseLogLine(line)) |rec| try asmb.feed(rec);
    }
}

// ---------------------------------------------------------------------------
// Mapping to v2 events

pub const Mapped = struct {
    event_type: []const u8,
    payload: []u8,
    occurred_at: i64,
};

pub const MapContext = struct {
    table: ?*entity.Table = null,
    hashes: ?*process_events.HashCache = null,
    /// Start of the process read from /proc while it is still alive, so the
    /// entity id matches the poller's. Otherwise the event time is used.
    live_start_100ns: ?u64 = null,
    /// `sensor` field value.
    sensor: []const u8 = "linux_audit",
};

/// Map one joined event. Null when it is not one we report.
pub fn map(alloc: std.mem.Allocator, ev: *const Event, ctx: MapContext) !?Mapped {
    const occurred: i64 = @intCast(ev.sec);
    if (ev.kind()) |k| switch (k) {
        .exec => {
            if (ev.success != true) return null;
            return .{ .event_type = "process_start", .payload = try processStart(alloc, ev, ctx), .occurred_at = occurred };
        },
        .connect => {
            if (!(ev.success == true or ev.exit == einprogress)) return null;
            const peer = parseSockaddr(ev.saddr.items) orelse return null;
            return .{ .event_type = "network_connect", .payload = try networkConnect(alloc, ev, ctx, peer), .occurred_at = occurred };
        },
        .exit_group => return .{ .event_type = "process_exit", .payload = try processExit(alloc, ev, ctx), .occurred_at = occurred },
    };
    if (!ev.have_syscall or ev.success == false) return null;
    for (ev.paths.items) |p| {
        if (!p.create or p.name.items.len == 0) continue;
        const full = try createdPath(alloc, ev, p.name.items);
        defer alloc.free(full);
        return .{ .event_type = "file_create", .payload = try fileCreate(alloc, ev, ctx, full), .occurred_at = occurred };
    }
    return null;
}

/// Audit records always carry Linux paths, so join and split with '/' even
/// when these tests run on Windows.
fn joinPosix(alloc: std.mem.Allocator, dir: []const u8, name: []const u8) ![]u8 {
    const d = std.mem.trimEnd(u8, dir, "/");
    const n = std.mem.trimStart(u8, name, "/");
    if (d.len == 0) return std.fmt.allocPrint(alloc, "/{s}", .{n});
    return std.fmt.allocPrint(alloc, "{s}/{s}", .{ d, n });
}

fn extensionPosix(name: []const u8) []const u8 {
    const base = std.fs.path.basenamePosix(name);
    const dot = std.mem.lastIndexOfScalar(u8, base, '.') orelse return "";
    if (dot == 0) return "";
    return base[dot..];
}

test "posix path helpers ignore the host separator" {
    const a = testing.allocator;
    const p1 = try joinPosix(a, "/etc/cron.d/", "backdoor");
    defer a.free(p1);
    try testing.expectEqualStrings("/etc/cron.d/backdoor", p1);
    const p2 = try joinPosix(a, "/", "x");
    defer a.free(p2);
    try testing.expectEqualStrings("/x", p2);
    try testing.expectEqualStrings(".sh", extensionPosix("/var/tmp/payload.sh"));
    try testing.expectEqualStrings("", extensionPosix(".bashrc"));
}

/// Absolute path of a created file: as given, else under the PARENT item, else
/// under the CWD record.
fn createdPath(alloc: std.mem.Allocator, ev: *const Event, name: []const u8) ![]u8 {
    if (name.len > 0 and name[0] == '/') return alloc.dupe(u8, name);
    for (ev.paths.items) |p| {
        if (p.parent and p.name.items.len > 0 and p.name.items[0] == '/') {
            return joinPosix(alloc, p.name.items, std.fs.path.basenamePosix(name));
        }
    }
    if (ev.cwd.items.len > 0) return joinPosix(alloc, ev.cwd.items, name);
    return alloc.dupe(u8, name);
}

pub const Peer = struct {
    ip_buf: [64]u8 = undefined,
    ip_len: usize = 0,
    port: u16,

    pub fn ip(self: *const Peer) []const u8 {
        return self.ip_buf[0..self.ip_len];
    }
};

/// `struct sockaddr` bytes in host order (little-endian on every supported
/// arch). AF_INET and AF_INET6 only; port 0 is skipped.
pub fn parseSockaddr(b: []const u8) ?Peer {
    if (b.len < 2) return null;
    const family = std.mem.readInt(u16, b[0..2], .little);
    var p = Peer{ .port = 0 };
    var w: std.Io.Writer = .fixed(&p.ip_buf);
    switch (family) {
        2 => {
            if (b.len < 8) return null;
            p.port = std.mem.readInt(u16, b[2..4], .big);
            w.print("{d}.{d}.{d}.{d}", .{ b[4], b[5], b[6], b[7] }) catch return null;
        },
        10 => {
            if (b.len < 24) return null;
            p.port = std.mem.readInt(u16, b[2..4], .big);
            const addr: [16]u8 = b[8..24].*;
            const v4_mapped = std.mem.allEqual(u8, addr[0..10], 0) and addr[10] == 0xff and addr[11] == 0xff;
            if (v4_mapped) {
                w.print("{d}.{d}.{d}.{d}", .{ addr[12], addr[13], addr[14], addr[15] }) catch return null;
            } else {
                const unresolved = std.Io.net.Ip6Address.Unresolved{ .bytes = addr, .interface_name = null };
                w.print("{f}", .{unresolved}) catch return null;
            }
        },
        else => return null,
    }
    if (p.port == 0) return null;
    p.ip_len = w.buffered().len;
    return p;
}

const Jw = std.json.Stringify;

fn beginPayload(jw: *Jw, ev: *const Event, ctx: MapContext) !void {
    try jw.beginObject();
    try jw.objectField("sensor");
    try jw.write(ctx.sensor);
    try jw.objectField("record_id");
    try jw.write(ev.serial);
    var buf: [24]u8 = undefined;
    try jw.objectField("ts");
    try jw.write(entity.formatIso(&buf, ev.time100ns()));
}

/// The acting process for connect and file events: entity from the table
/// when the pid is known, otherwise pid only.
fn actor(jw: *Jw, ev: *const Event, ctx: MapContext) !void {
    try jw.objectField("process");
    try jw.beginObject();
    if (ctx.table) |t| if (t.lookup(ev.pid, "")) |id| {
        try jw.objectField("entity_id");
        try jw.write(&id);
    };
    try jw.objectField("pid");
    try jw.write(ev.pid);
    if (ev.comm.items.len > 0) {
        try jw.objectField("name");
        try jw.write(ev.comm.items);
    }
    if (ev.exe.items.len > 0) {
        try jw.objectField("image");
        try jw.write(ev.exe.items);
    }
    try jw.objectField("user");
    try jw.beginObject();
    try jw.objectField("uid");
    try jw.write(ev.uid);
    try jw.endObject();
    try jw.endObject();
}

/// Arguments joined with spaces, else the proctitle (NUL separated), else
/// comm.
fn commandLine(alloc: std.mem.Allocator, ev: *const Event) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    if (ev.args.items.len > 0) {
        for (ev.args.items, 0..) |a, i| {
            if (i > 0) try out.append(alloc, ' ');
            try out.appendSlice(alloc, a.items);
        }
    } else if (ev.proctitle.items.len > 0) {
        try out.appendSlice(alloc, std.mem.trimEnd(u8, ev.proctitle.items, "\x00"));
        for (out.items) |*c| if (c.* == 0) {
            c.* = ' ';
        };
    } else {
        try out.appendSlice(alloc, ev.comm.items);
    }
    return out.toOwnedSlice(alloc);
}

fn processStart(alloc: std.mem.Allocator, ev: *const Event, ctx: MapContext) ![]u8 {
    const start = ctx.live_start_100ns orelse ev.time100ns();
    const id: ?entity.Id = if (ctx.table) |t| try t.observe(ev.pid, start, "") else null;
    const parent_id: ?entity.Id = if (ctx.table) |t| (if (ev.ppid != 0) t.parentOf(ev.ppid, start) else null) else null;
    const raw_cmd = try commandLine(alloc, ev);
    defer alloc.free(raw_cmd);
    const cmd = try privacy.sanitizeCommandLine(alloc, raw_cmd);
    defer alloc.free(cmd);
    const digest: ?[32]u8 = if (ctx.hashes) |h| (if (ev.exe.items.len > 0) h.get(ev.exe.items) else null) else null;

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    var jw: Jw = .{ .writer = &out.writer };
    try beginPayload(&jw, ev, ctx);
    try jw.objectField("process");
    try jw.beginObject();
    if (id) |v| {
        try jw.objectField("entity_id");
        try jw.write(&v);
    }
    try jw.objectField("pid");
    try jw.write(ev.pid);
    var tbuf: [24]u8 = undefined;
    try jw.objectField("start_time");
    try jw.write(entity.formatIso(&tbuf, start));
    try jw.objectField("name");
    try jw.write(ev.comm.items);
    if (ev.exe.items.len > 0) {
        try jw.objectField("image");
        try jw.write(ev.exe.items);
    }
    try jw.objectField("command_line");
    try jw.write(cmd);
    if (ev.cwd.items.len > 0) {
        try jw.objectField("cwd");
        try jw.write(ev.cwd.items);
    }
    try jw.objectField("user");
    try jw.beginObject();
    try jw.objectField("uid");
    try jw.write(ev.uid);
    try jw.endObject();
    if (digest) |d| {
        const hex = std.fmt.bytesToHex(d, .lower);
        try jw.objectField("hashes");
        try jw.beginObject();
        try jw.objectField("sha256");
        try jw.write(&hex);
        try jw.endObject();
    }
    try jw.endObject();
    try jw.objectField("parent");
    try jw.beginObject();
    if (parent_id) |v| {
        try jw.objectField("entity_id");
        try jw.write(&v);
    }
    try jw.objectField("pid");
    try jw.write(ev.ppid);
    try jw.endObject();
    try jw.endObject();
    return out.toOwnedSlice();
}

fn processExit(alloc: std.mem.Allocator, ev: *const Event, ctx: MapContext) ![]u8 {
    var id: ?entity.Id = null;
    if (ctx.table) |t| {
        id = t.lookup(ev.pid, "");
        if (id != null) t.forget(ev.pid);
    }
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    var jw: Jw = .{ .writer = &out.writer };
    try beginPayload(&jw, ev, ctx);
    try jw.objectField("process");
    try jw.beginObject();
    if (id) |v| {
        try jw.objectField("entity_id");
        try jw.write(&v);
    }
    try jw.objectField("pid");
    try jw.write(ev.pid);
    if (ev.comm.items.len > 0) {
        try jw.objectField("name");
        try jw.write(ev.comm.items);
    }
    if (ev.exe.items.len > 0) {
        try jw.objectField("image");
        try jw.write(ev.exe.items);
    }
    try jw.endObject();
    var tbuf: [24]u8 = undefined;
    try jw.objectField("end_time");
    try jw.write(entity.formatIso(&tbuf, ev.time100ns()));
    try jw.endObject();
    return out.toOwnedSlice();
}

fn networkConnect(alloc: std.mem.Allocator, ev: *const Event, ctx: MapContext, peer: Peer) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    var jw: Jw = .{ .writer = &out.writer };
    try beginPayload(&jw, ev, ctx);
    try actor(&jw, ev, ctx);
    try jw.objectField("network");
    try jw.beginObject();
    try jw.objectField("direction");
    try jw.write("outbound");
    try jw.objectField("dst_ip");
    try jw.write(peer.ip());
    try jw.objectField("dst_port");
    try jw.write(peer.port);
    try jw.endObject();
    try jw.endObject();
    return out.toOwnedSlice();
}

fn fileCreate(alloc: std.mem.Allocator, ev: *const Event, ctx: MapContext, path: []const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    var jw: Jw = .{ .writer = &out.writer };
    try beginPayload(&jw, ev, ctx);
    try actor(&jw, ev, ctx);
    try jw.objectField("file");
    try jw.beginObject();
    try jw.objectField("path");
    try jw.write(path);
    const name = std.fs.path.basenamePosix(path);
    try jw.objectField("name");
    try jw.write(name);
    const ext = extensionPosix(name);
    if (ext.len > 1) {
        try jw.objectField("extension");
        try jw.write(ext[1..]);
    }
    try jw.endObject();
    try jw.endObject();
    return out.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Rule encoding (struct audit_rule_data), pure so it is tested everywhere

pub const RuleSpec = union(enum) {
    /// `-a always,exit -F arch=<arch> -S <syscalls> -k tawny`
    syscalls: struct { arch: u32, numbers: []const u32 },
    /// `-w <dir> -p wa -k tawny`
    watch_dir: []const u8,
};

/// `struct audit_rule_data` with its string buffer, little-endian.
pub fn encodeRule(alloc: std.mem.Allocator, spec: RuleSpec) ![]u8 {
    const fixed = 4 * (3 + bitmask_words + 3 * max_fields + 1);
    var strings: std.ArrayList(u8) = .empty;
    defer strings.deinit(alloc);
    var mask: [bitmask_words]u32 = @splat(0);
    var fields: [max_fields]u32 = @splat(0);
    var values: [max_fields]u32 = @splat(0);
    var flags: [max_fields]u32 = @splat(0);
    var n: usize = 0;
    switch (spec) {
        .syscalls => |s| {
            for (s.numbers) |nr| mask[nr / 32] |= @as(u32, 1) << @intCast(nr % 32);
            fields[n] = field_arch;
            values[n] = s.arch;
            flags[n] = op_equal;
            n += 1;
        },
        .watch_dir => |dir| {
            mask = @splat(0xffffffff);
            fields[n] = field_dir;
            values[n] = @intCast(dir.len);
            flags[n] = op_equal;
            try strings.appendSlice(alloc, dir);
            n += 1;
            fields[n] = field_perm;
            values[n] = perm_write | perm_attr;
            flags[n] = op_equal;
            n += 1;
        },
    }
    fields[n] = field_filterkey;
    values[n] = rule_key.len;
    flags[n] = op_equal;
    try strings.appendSlice(alloc, rule_key);
    n += 1;

    const out = try alloc.alloc(u8, fixed + strings.items.len);
    var o: usize = 0;
    const put = struct {
        fn f(buf: []u8, at: *usize, v: u32) void {
            std.mem.writeInt(u32, buf[at.*..][0..4], v, .little);
            at.* += 4;
        }
    }.f;
    put(out, &o, filter_exit);
    put(out, &o, action_always);
    put(out, &o, @intCast(n));
    for (mask) |m| put(out, &o, m);
    for (fields) |v| put(out, &o, v);
    for (values) |v| put(out, &o, v);
    for (flags) |v| put(out, &o, v);
    put(out, &o, @intCast(strings.items.len));
    @memcpy(out[o..], strings.items);
    return out;
}

/// Rules for the native architecture: exec, connect and exit_group, plus a
/// write watch per folder.
pub fn nativeRules(alloc: std.mem.Allocator, watch_dirs: []const []const u8) ![][]u8 {
    var list: std.ArrayList([]u8) = .empty;
    errdefer {
        for (list.items) |r| alloc.free(r);
        list.deinit(alloc);
    }
    const native: ?struct { u32, [4]u32 } = switch (builtin.target.cpu.arch) {
        .x86_64 => .{ arch_x86_64, .{ 59, 322, 42, 231 } },
        .aarch64 => .{ arch_aarch64, .{ 221, 281, 203, 94 } },
        else => null,
    };
    const nat = native orelse return error.UnsupportedArch;
    try list.append(alloc, try encodeRule(alloc, .{ .syscalls = .{ .arch = nat[0], .numbers = &nat[1] } }));
    for (watch_dirs) |d| {
        if (d.len == 0 or d[0] != '/' or d.len > 1024) continue;
        try list.append(alloc, try encodeRule(alloc, .{ .watch_dir = d }));
    }
    return list.toOwnedSlice(alloc);
}

// ---------------------------------------------------------------------------
// Live netlink reader (Linux only)

pub const Mode = enum { daemon, multicast };

pub const OpenError = error{
    /// No audit in this kernel, or not the initial namespaces (containers).
    AuditUnavailable,
    /// Neither CAP_AUDIT_CONTROL nor CAP_AUDIT_READ.
    AccessDenied,
    /// Another audit daemon (auditd) is registered.
    DaemonPresent,
    UnsupportedArch,
    OutOfMemory,
    SystemResources,
};

const Raw = struct { type: u16, bytes: []u8 };

/// Spin lock: the reader thread holds it for a list append only.
const SpinLock = struct {
    held: std.atomic.Value(bool) = .init(false),
    fn lock(self: *SpinLock) void {
        while (self.held.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    fn unlock(self: *SpinLock) void {
        self.held.store(false, .release);
    }
};

pub const Live = struct {
    alloc: std.mem.Allocator,
    fd: i32,
    mode: Mode,
    thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = .init(false),
    lock: SpinLock = .{},
    queue: std.ArrayList(Raw) = .empty,
    queued_bytes: usize = 0,
    dropped: std.atomic.Value(u64) = .init(0),
    received: std.atomic.Value(u64) = .init(0),
    kernel_lost: u32 = 0,
    rules: [][]u8 = &.{},
    restore_enabled: ?u32 = null,
    /// Why registering as the audit daemon failed, in multicast mode.
    daemon_error: ?OpenError = null,
    seq: u32 = 1,

    const max_queue_records: usize = 65536;
    const max_queue_bytes: usize = 32 * 1024 * 1024;

    /// Register as the audit daemon and load rules; if another daemon owns
    /// audit, or CAP_AUDIT_CONTROL is missing, join the multicast group.
    pub fn open(alloc: std.mem.Allocator, watch_dirs: []const []const u8, allow_daemon: bool) OpenError!*Live {
        if (comptime builtin.target.os.tag != .linux) return error.AuditUnavailable;
        const self = try alloc.create(Live);
        errdefer alloc.destroy(self);
        self.* = .{ .alloc = alloc, .fd = -1, .mode = .daemon };

        var daemon_err: OpenError = error.AccessDenied;
        if (allow_daemon) {
            if (self.openDaemon(watch_dirs)) {
                try self.spawn();
                return self;
            } else |err| daemon_err = err;
            self.closeFd();
        }
        self.openMulticast() catch |err| {
            self.closeFd();
            return if (allow_daemon) daemon_err else err;
        };
        self.mode = .multicast;
        self.daemon_error = if (allow_daemon) daemon_err else null;
        try self.spawn();
        return self;
    }

    fn spawn(self: *Live) OpenError!void {
        self.thread = std.Thread.spawn(.{ .stack_size = 256 * 1024 }, readerMain, .{self}) catch return error.SystemResources;
    }

    fn closeFd(self: *Live) void {
        if (self.fd >= 0) _ = std.os.linux.close(self.fd);
        self.fd = -1;
    }

    fn socketOpen(self: *Live, groups: u32) OpenError!void {
        const linux = std.os.linux;
        const rc = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, netlink_audit);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.AccessDenied,
            .PROTONOSUPPORT, .AFNOSUPPORT => return error.AuditUnavailable,
            .NOMEM, .NOBUFS, .MFILE, .NFILE => return error.SystemResources,
            else => return error.AuditUnavailable,
        }
        self.fd = @intCast(rc);
        // 1 s receive timeout so the reader notices stop.
        const tv = linux.timeval{ .sec = 1, .usec = 0 };
        _ = linux.setsockopt(self.fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
        const rcvbuf: i32 = 4 * 1024 * 1024;
        _ = linux.setsockopt(self.fd, linux.SOL.SOCKET, linux.SO.RCVBUF, std.mem.asBytes(&rcvbuf), @sizeOf(i32));
        var addr = linux.sockaddr.nl{ .pid = 0, .groups = groups };
        switch (linux.errno(linux.bind(self.fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.nl)))) {
            .SUCCESS => {},
            .PERM, .ACCES => return error.AccessDenied,
            else => return error.AuditUnavailable,
        }
    }

    fn openMulticast(self: *Live) OpenError!void {
        try self.socketOpen(@as(u32, 1) << @intCast(nlgrp_readlog - 1));
    }

    const Status = extern struct {
        mask: u32 = 0,
        enabled: u32 = 0,
        failure: u32 = 0,
        pid: u32 = 0,
        rate_limit: u32 = 0,
        backlog_limit: u32 = 0,
        lost: u32 = 0,
        backlog: u32 = 0,
        feature_bitmap: u32 = 0,
        backlog_wait_time: u32 = 0,
        backlog_wait_time_actual: u32 = 0,
    };

    fn openDaemon(self: *Live, watch_dirs: []const []const u8) OpenError!void {
        try self.socketOpen(0);
        // AUDIT_GET tells us whether another daemon is registered.
        const status = try self.getStatus();
        if (status.pid != 0 and status.pid != @as(u32, @intCast(std.os.linux.getpid())) and pidAlive(status.pid)) {
            return error.DaemonPresent;
        }
        if (status.enabled == 2) return error.AccessDenied; // rules locked
        self.rules = nativeRules(self.alloc, watch_dirs) catch |err|
            return if (err == error.OutOfMemory) error.OutOfMemory else error.UnsupportedArch;
        // Remove rules a crashed run left behind, then load ours.
        for (self.rules) |r| self.request(msg.del_rule, r) catch {};
        // The syscall rule (first) must load. A watch rule for a folder that
        // is missing or refused is dropped and logged, not fatal.
        for (self.rules, 0..) |*r, i| {
            self.request(msg.add_rule, r.*) catch |err| switch (err) {
                error.DaemonPresent => {}, // EEXIST: the rule is already loaded
                else => {
                    if (i == 0) {
                        self.unloadRules();
                        return err;
                    }
                    std.log.warn("audit: watch rule {d} not loaded: {s}", .{ i, @errorName(err) });
                    self.alloc.free(r.*);
                    r.* = &.{};
                },
            };
        }
        var set = Status{ .mask = status_pid | status_backlog_limit, .pid = @intCast(std.os.linux.getpid()), .backlog_limit = @max(status.backlog_limit, 8192) };
        if (status.enabled == 0) {
            set.mask |= status_enabled;
            set.enabled = 1;
            self.restore_enabled = 0;
        }
        self.request(msg.set, std.mem.asBytes(&set)) catch |err| {
            self.unloadRules();
            return err;
        };
        self.kernel_lost = status.lost;
    }

    fn unloadRules(self: *Live) void {
        for (self.rules) |r| if (r.len > 0) self.sendOnly(msg.del_rule, r);
        for (self.rules) |r| self.alloc.free(r);
        if (self.rules.len > 0) self.alloc.free(self.rules);
        self.rules = &.{};
    }

    fn sendOnly(self: *Live, t: u16, payload: []const u8) void {
        _ = self.send(t, payload, false) catch {};
    }

    fn send(self: *Live, t: u16, payload: []const u8, ack: bool) OpenError!u32 {
        const linux = std.os.linux;
        const hdr_len = @sizeOf(linux.nlmsghdr);
        var buf: [16 * 1024]u8 align(4) = undefined;
        const total = hdr_len + payload.len;
        if (total > buf.len) return error.SystemResources;
        self.seq += 1;
        const hdr = linux.nlmsghdr{
            .len = @intCast(total),
            .type = @enumFromInt(t),
            .flags = linux.NLM_F_REQUEST | (if (ack) @as(u16, linux.NLM_F_ACK) else 0),
            .seq = self.seq,
            .pid = 0,
        };
        @memcpy(buf[0..hdr_len], std.mem.asBytes(&hdr));
        @memcpy(buf[hdr_len..total], payload);
        var addr = linux.sockaddr.nl{ .pid = 0, .groups = 0 };
        const rc = linux.sendto(self.fd, &buf, total, 0, @ptrCast(&addr), @sizeOf(linux.sockaddr.nl));
        switch (linux.errno(rc)) {
            .SUCCESS => return self.seq,
            .PERM, .ACCES => return error.AccessDenied,
            else => return error.AuditUnavailable,
        }
    }

    /// Send and wait for the kernel's ack. Records that arrive meanwhile go
    /// to the queue.
    fn request(self: *Live, t: u16, payload: []const u8) OpenError!void {
        const seq = try self.send(t, payload, true);
        var st: ?Status = null;
        return self.awaitReply(seq, false, &st);
    }

    fn getStatus(self: *Live) OpenError!Status {
        const seq = try self.send(msg.get, "", true);
        var st: ?Status = null;
        try self.awaitReply(seq, true, &st);
        return st orelse error.AuditUnavailable;
    }

    fn awaitReply(self: *Live, seq: u32, want_status: bool, status: *?Status) OpenError!void {
        const linux = std.os.linux;
        var buf: [9000]u8 align(4) = undefined;
        var acked = false;
        var tries: usize = 0;
        while (tries < 64) : (tries += 1) {
            if (acked and (!want_status or status.* != null)) return;
            const rc = linux.recvfrom(self.fd, &buf, buf.len, 0, null, null);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                .AGAIN => return error.AuditUnavailable, // timed out
                else => return error.AuditUnavailable,
            }
            var off: usize = 0;
            const n: usize = rc;
            while (off + @sizeOf(linux.nlmsghdr) <= n) {
                const hdr: *align(1) const linux.nlmsghdr = @ptrCast(buf[off..].ptr);
                const len: usize = @max(hdr.len, @sizeOf(linux.nlmsghdr));
                const end = @min(off + len, n);
                const body = buf[off + @sizeOf(linux.nlmsghdr) .. end];
                const t: u16 = @intFromEnum(hdr.type);
                if (t == 2 and hdr.seq == seq) { // NLMSG_ERROR
                    const code: i32 = if (body.len >= 4) std.mem.readInt(i32, body[0..4], .little) else 0;
                    if (code == 0) {
                        acked = true;
                    } else if (code == -1 or code == -13) {
                        return error.AccessDenied;
                    } else if (code == -17) {
                        return error.DaemonPresent; // EEXIST: another daemon
                    } else {
                        return error.AuditUnavailable;
                    }
                } else if (t == msg.get and want_status) {
                    var s = Status{};
                    const take = @min(body.len, @sizeOf(Status));
                    @memcpy(std.mem.asBytes(&s)[0..take], body[0..take]);
                    status.* = s;
                } else if (t >= 1100) {
                    self.push(t, body);
                }
                off += std.mem.alignForward(usize, len, 4);
            }
        }
        return error.AuditUnavailable;
    }

    fn push(self: *Live, t: u16, body: []const u8) void {
        _ = self.received.fetchAdd(1, .monotonic);
        self.lock.lock();
        defer self.lock.unlock();
        if (self.queue.items.len >= max_queue_records or self.queued_bytes + body.len > max_queue_bytes) {
            _ = self.dropped.fetchAdd(1, .monotonic);
            return;
        }
        const copy = self.alloc.dupe(u8, body) catch {
            _ = self.dropped.fetchAdd(1, .monotonic);
            return;
        };
        self.queue.append(self.alloc, .{ .type = t, .bytes = copy }) catch {
            self.alloc.free(copy);
            _ = self.dropped.fetchAdd(1, .monotonic);
            return;
        };
        self.queued_bytes += copy.len;
    }

    fn readerMain(self: *Live) void {
        const linux = std.os.linux;
        var buf: [9000]u8 align(4) = undefined;
        while (!self.stop_flag.load(.acquire)) {
            const rc = linux.recvfrom(self.fd, &buf, buf.len, 0, null, null);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .NOBUFS => {
                    _ = self.dropped.fetchAdd(1, .monotonic);
                    continue;
                },
                .AGAIN, .INTR => continue,
                else => return,
            }
            const n: usize = rc;
            var off: usize = 0;
            while (off + @sizeOf(linux.nlmsghdr) <= n) {
                const hdr: *align(1) const linux.nlmsghdr = @ptrCast(buf[off..].ptr);
                const len: usize = @max(hdr.len, @sizeOf(linux.nlmsghdr));
                const end = @min(off + len, n);
                const t: u16 = @intFromEnum(hdr.type);
                if (t >= 1100) self.push(t, buf[off + @sizeOf(linux.nlmsghdr) .. end]);
                off += std.mem.alignForward(usize, len, 4);
            }
        }
    }

    /// Move queued records into the assembler.
    pub fn drain(self: *Live, asmb: *Assembler) !void {
        self.lock.lock();
        var taken = self.queue;
        self.queue = .empty;
        self.queued_bytes = 0;
        self.lock.unlock();
        defer {
            for (taken.items) |r| self.alloc.free(r.bytes);
            taken.deinit(self.alloc);
        }
        for (taken.items) |r| {
            if (parseNetlink(r.type, r.bytes)) |rec| try asmb.feed(rec);
        }
    }

    pub fn close(self: *Live) void {
        self.stop_flag.store(true, .release);
        if (self.thread) |t| t.join();
        self.thread = null;
        if (self.mode == .daemon and self.fd >= 0) {
            self.unloadRules();
            var set = Status{ .mask = status_pid, .pid = 0 };
            if (self.restore_enabled) |v| {
                set.mask |= status_enabled;
                set.enabled = v;
            }
            self.sendOnly(msg.set, std.mem.asBytes(&set));
        } else {
            self.unloadRules();
        }
        self.closeFd();
        for (self.queue.items) |r| self.alloc.free(r.bytes);
        self.queue.deinit(self.alloc);
        self.alloc.destroy(self);
    }
};

fn pidAlive(pid: u32) bool {
    if (comptime builtin.target.os.tag != .linux) return false;
    var buf: [32]u8 = undefined;
    const path = std.fmt.bufPrint(&buf, "/proc/{d}", .{pid}) catch return false;
    var d = std.Io.Dir.openDirAbsolute(iox.current(), path, .{}) catch |err| return err != error.FileNotFound;
    d.close(iox.current());
    return true;
}

// ---------------------------------------------------------------------------
// Tail of a growing text file (auditd log, Tetragon export)

pub const Tail = struct {
    alloc: std.mem.Allocator,
    path: []const u8,
    offset: u64 = 0,
    inode: u64 = 0,
    partial: std.ArrayList(u8) = .empty,
    /// Bytes read per poll at most.
    max_chunk: usize = 4 * 1024 * 1024,

    /// Start at the end of the file so old history is not replayed.
    pub fn open(alloc: std.mem.Allocator, path: []const u8, from_end: bool) !Tail {
        const io = iox.current();
        var f = try std.Io.Dir.cwd().openFile(io, path, .{});
        defer f.close(io);
        const st = try f.stat(io);
        return .{ .alloc = alloc, .path = path, .offset = if (from_end) st.size else 0, .inode = @intCast(st.inode) };
    }

    pub fn deinit(self: *Tail) void {
        self.partial.deinit(self.alloc);
    }

    /// Complete lines appended since the last poll, or null. A rotated or
    /// truncated file is read again from the start.
    pub fn poll(self: *Tail) !?[]u8 {
        const io = iox.current();
        var f = try std.Io.Dir.cwd().openFile(io, self.path, .{});
        defer f.close(io);
        const st = try f.stat(io);
        if (@as(u64, @intCast(st.inode)) != self.inode or st.size < self.offset) {
            self.inode = @intCast(st.inode);
            self.offset = 0;
            self.partial.clearRetainingCapacity();
        }
        if (st.size == self.offset) return null;
        const want: usize = @intCast(@min(st.size - self.offset, self.max_chunk));
        const start = self.partial.items.len;
        try self.partial.ensureUnusedCapacity(self.alloc, want);
        const dest = self.partial.unusedCapacitySlice()[0..want];
        const n = try f.readPositionalAll(io, dest, self.offset);
        self.partial.items.len += n;
        self.offset += n;
        _ = start;
        const last_nl = std.mem.lastIndexOfScalar(u8, self.partial.items, '\n') orelse {
            if (self.partial.items.len > self.max_chunk) self.partial.clearRetainingCapacity();
            return null;
        };
        const lines = try self.alloc.dupe(u8, self.partial.items[0 .. last_nl + 1]);
        const rest = self.partial.items.len - (last_nl + 1);
        std.mem.copyForwards(u8, self.partial.items[0..rest], self.partial.items[last_nl + 1 ..]);
        self.partial.items.len = rest;
        return lines;
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const samples = struct {
    const netlink = @embedFile("testdata/netlink_exec_connect.txt");
    const log = @embedFile("testdata/audit.log");
};

/// Captured netlink records, one per line: `<type> <payload>`.
fn feedNetlinkCapture(asmb: *Assembler, text: []const u8) !void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const sp = std.mem.indexOfScalar(u8, line, ' ') orelse continue;
        const t = std.fmt.parseInt(u16, line[0..sp], 10) catch continue;
        if (parseNetlink(t, line[sp + 1 ..])) |rec| try asmb.feed(rec);
    }
}

fn mapAll(alloc: std.mem.Allocator, asmb: *Assembler, ctx: MapContext) !std.ArrayList(Mapped) {
    var out: std.ArrayList(Mapped) = .empty;
    errdefer {
        for (out.items) |m| alloc.free(m.payload);
        out.deinit(alloc);
    }
    const events = try asmb.take();
    defer {
        for (events) |e| asmb.destroy(e);
        alloc.free(events);
    }
    for (events) |e| if (try map(alloc, e, ctx)) |m| try out.append(alloc, m);
    return out;
}

fn freeMapped(alloc: std.mem.Allocator, list: *std.ArrayList(Mapped)) void {
    for (list.items) |m| alloc.free(m.payload);
    list.deinit(alloc);
}

test "kernel constants match linux/audit.h and the syscall tables" {
    // include/uapi/linux/audit.h
    try testing.expectEqual(@as(u16, 1000), msg.get);
    try testing.expectEqual(@as(u16, 1001), msg.set);
    try testing.expectEqual(@as(u16, 1011), msg.add_rule);
    try testing.expectEqual(@as(u16, 1012), msg.del_rule);
    try testing.expectEqual(@as(u16, 1300), msg.syscall);
    try testing.expectEqual(@as(u16, 1302), msg.path);
    try testing.expectEqual(@as(u16, 1306), msg.sockaddr);
    try testing.expectEqual(@as(u16, 1307), msg.cwd);
    try testing.expectEqual(@as(u16, 1309), msg.execve);
    try testing.expectEqual(@as(u16, 1320), msg.eoe);
    try testing.expectEqual(@as(u16, 1327), msg.proctitle);
    try testing.expectEqual(@as(u32, 0x04), filter_exit);
    try testing.expectEqual(@as(u32, 2), action_always);
    try testing.expectEqual(@as(u32, 11), field_arch);
    try testing.expectEqual(@as(u32, 106), field_perm);
    try testing.expectEqual(@as(u32, 107), field_dir);
    try testing.expectEqual(@as(u32, 210), field_filterkey);
    try testing.expectEqual(@as(u32, 0x40000000), op_equal);
    try testing.expectEqual(@as(u32, 0xC000003E), arch_x86_64);
    try testing.expectEqual(@as(u32, 0xC00000B7), arch_aarch64);
    // Netlink family and the std library agree. (std.os.linux.AUDIT.ARCH does
    // not compile in Zig 0.17, so the arch values are pinned above.)
    try testing.expectEqual(@as(u32, std.os.linux.NETLINK.AUDIT), netlink_audit);
    // Syscall numbers in syscallKind and nativeRules.
    const X64 = std.os.linux.syscalls.X64;
    const A64 = std.os.linux.syscalls.Arm64;
    try testing.expectEqual(@as(usize, 59), @intFromEnum(X64.execve));
    try testing.expectEqual(@as(usize, 322), @intFromEnum(X64.execveat));
    try testing.expectEqual(@as(usize, 42), @intFromEnum(X64.connect));
    try testing.expectEqual(@as(usize, 231), @intFromEnum(X64.exit_group));
    try testing.expectEqual(@as(usize, 221), @intFromEnum(A64.execve));
    try testing.expectEqual(@as(usize, 281), @intFromEnum(A64.execveat));
    try testing.expectEqual(@as(usize, 203), @intFromEnum(A64.connect));
    try testing.expectEqual(@as(usize, 94), @intFromEnum(A64.exit_group));
}

test "record headers parse from netlink and the auditd log" {
    const r = parseNetlink(1300, "audit(1731200000.123:4567): arch=c000003e syscall=59\x00").?;
    try testing.expectEqual(@as(u64, 1731200000), r.sec);
    try testing.expectEqual(@as(u32, 123), r.ms);
    try testing.expectEqual(@as(u64, 4567), r.serial);
    try testing.expectEqualStrings("arch=c000003e syscall=59", r.body);
    const l = parseLogLine("node=web1 type=CWD msg=audit(1731200000.123:4567): cwd=\"/tmp\"\x1dEXTRA=1").?;
    try testing.expectEqual(msg.cwd, l.type);
    try testing.expectEqualStrings("cwd=\"/tmp\"", l.body);
    try testing.expect(parseLogLine("type=USER_LOGIN msg=audit(1.2:3): pid=1") == null);
    try testing.expect(parseNetlink(1300, "garbage") == null);
    try testing.expect(parseNetlink(1300, "audit(1:2.3): x") == null);
}

test "field values: quoted, bare hex and null" {
    const alloc = testing.allocator;
    var it = FieldIter{ .s = "comm=\"ls\" exe=2F746D702F6120622F78 name=(null) key=\"tawny\" bare" };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);
    const comm = it.next().?;
    try appendString(alloc, &out, comm, 100);
    try testing.expectEqualStrings("ls", out.items);
    out.clearRetainingCapacity();
    try appendString(alloc, &out, it.next().?, 100);
    try testing.expectEqualStrings("/tmp/a b/x", out.items);
    out.clearRetainingCapacity();
    try appendString(alloc, &out, it.next().?, 100);
    try testing.expectEqualStrings("", out.items);
    try testing.expectEqualStrings("key", it.next().?.key);
    try testing.expectEqualStrings("bare", it.next().?.key);
    try testing.expect(it.next() == null);
}

test "sockaddr: ipv4, ipv6, v4-mapped, unix and port 0" {
    var buf: [64]u8 = undefined;
    const v4 = try std.fmt.hexToBytes(&buf, "020001BBCB00710A0000000000000000");
    const p4 = parseSockaddr(v4).?;
    try testing.expectEqualStrings("203.0.113.10", p4.ip());
    try testing.expectEqual(@as(u16, 443), p4.port);
    const v6 = try std.fmt.hexToBytes(&buf, "0A0000500000000020010DB8000000000000000000000001" ++ "00000000");
    const p6 = parseSockaddr(v6).?;
    try testing.expectEqualStrings("2001:db8::1", p6.ip());
    try testing.expectEqual(@as(u16, 80), p6.port);
    const mapped = try std.fmt.hexToBytes(&buf, "0A00003500000000" ++ "00000000000000000000FFFF08080808" ++ "00000000");
    try testing.expectEqualStrings("8.8.8.8", parseSockaddr(mapped).?.ip());
    try testing.expect(parseSockaddr(try std.fmt.hexToBytes(&buf, "01002F746D70")) == null);
    try testing.expect(parseSockaddr(try std.fmt.hexToBytes(&buf, "02000000C0A80101")) == null);
}

test "netlink capture joins by serial and maps to v2 events with entity ids" {
    const alloc = testing.allocator;
    var table = entity.Table.init(alloc, "0f8fad5b-d9cb-469f-a165-70867728950e", "3c1c4b5e-6d2a-4f0e-9b7a-2d1e5f6a7b8c", 64);
    defer table.deinit();
    // The parent shell is already in the table, as the poller's first pass
    // would leave it.
    _ = try table.observe(4100, 1731199000 * entity.ticks_per_second, "");

    var asmb = Assembler.init(alloc, false);
    defer asmb.deinit();
    try feedNetlinkCapture(&asmb, samples.netlink);
    var got = try mapAll(alloc, &asmb, .{ .table = &table });
    defer freeMapped(alloc, &got);

    try testing.expectEqual(@as(usize, 4), got.items.len);
    try testing.expectEqualStrings("process_start", got.items[0].event_type);
    try testing.expectEqualStrings("network_connect", got.items[1].event_type);
    try testing.expectEqualStrings("network_connect", got.items[2].event_type);
    try testing.expectEqualStrings("process_exit", got.items[3].event_type);
    for (got.items) |m| try @import("../../schema_check.zig").expectValid(alloc, m.event_type, m.payload);

    const start = got.items[0].payload;
    const child_id = table.idFor(4242, 1731200000 * entity.ticks_per_second + 123 * entity.ticks_per_ms);
    const parent_id = table.idFor(4100, 1731199000 * entity.ticks_per_second);
    try testing.expect(std.mem.indexOf(u8, start, &child_id) != null);
    try testing.expect(std.mem.indexOf(u8, start, &parent_id) != null);
    try testing.expect(std.mem.indexOf(u8, start, "\"command_line\":\"curl -s https://example.com/a b\"") != null);
    try testing.expect(std.mem.indexOf(u8, start, "\"cwd\":\"/home/alice\"") != null);
    try testing.expect(std.mem.indexOf(u8, start, "\"image\":\"/usr/bin/curl\"") != null);
    try testing.expect(std.mem.indexOf(u8, start, "\"record_id\":4567") != null);

    // Owning process on connect, including a non-blocking EINPROGRESS one.
    try testing.expect(std.mem.indexOf(u8, got.items[1].payload, &child_id) != null);
    try testing.expect(std.mem.indexOf(u8, got.items[1].payload, "\"dst_ip\":\"93.184.215.14\",\"dst_port\":443") != null);
    try testing.expect(std.mem.indexOf(u8, got.items[2].payload, "\"dst_ip\":\"2001:db8::10\",\"dst_port\":443") != null);
    try testing.expect(std.mem.indexOf(u8, got.items[3].payload, &child_id) != null);
    // Exit forgets the pid.
    try testing.expect(table.lookup(4242, "") == null);
}

test "auditd log lines join without EOE and map exec, connect, create, exit" {
    const alloc = testing.allocator;
    var table = entity.Table.init(alloc, entity.nil_uuid, entity.nil_uuid, 64);
    defer table.deinit();
    var asmb = Assembler.init(alloc, true);
    defer asmb.deinit();
    try feedLog(&asmb, samples.log);
    try asmb.completeAll();
    var got = try mapAll(alloc, &asmb, .{ .table = &table });
    defer freeMapped(alloc, &got);

    const want = [_][]const u8{ "process_start", "process_start", "network_connect", "file_create", "file_create", "process_exit" };
    try testing.expectEqual(want.len, got.items.len);
    for (want, got.items) |w, m| {
        try testing.expectEqualStrings(w, m.event_type);
        try @import("../../schema_check.zig").expectValid(alloc, m.event_type, m.payload);
    }
    // Long argument split in chunks, hex-encoded argument with a space.
    try testing.expect(std.mem.indexOf(u8, got.items[0].payload, "\"command_line\":\"python3 -c print('hello world')\"") != null);
    // execveat with only a PROCTITLE.
    try testing.expect(std.mem.indexOf(u8, got.items[1].payload, "\"command_line\":\"sh -c id\"") != null);
    // Relative name under the PARENT item, and under the CWD.
    try testing.expect(std.mem.indexOf(u8, got.items[3].payload, "\"path\":\"/etc/cron.d/backdoor\",\"name\":\"backdoor\"") != null);
    try testing.expect(std.mem.indexOf(u8, got.items[4].payload, "\"path\":\"/var/tmp/x/payload.sh\",\"name\":\"payload.sh\",\"extension\":\"sh\"") != null);
}

test "failed exec, refused connect and unix sockets are not reported" {
    const alloc = testing.allocator;
    var asmb = Assembler.init(alloc, false);
    defer asmb.deinit();
    const text =
        \\1300 audit(1731200100.000:9001): arch=c000003e syscall=59 success=no exit=-2 ppid=1 pid=50 uid=0 comm="sh" exe="/usr/bin/sh"
        \\1320 audit(1731200100.000:9001):
        \\1300 audit(1731200100.000:9002): arch=c000003e syscall=42 success=no exit=-111 ppid=1 pid=51 uid=0 comm="nc" exe="/usr/bin/nc"
        \\1306 audit(1731200100.000:9002): saddr=020001BBCB00710A0000000000000000
        \\1320 audit(1731200100.000:9002):
        \\1300 audit(1731200100.000:9003): arch=c000003e syscall=42 success=yes exit=0 ppid=1 pid=52 uid=0 comm="ls" exe="/usr/bin/ls"
        \\1306 audit(1731200100.000:9003): saddr=01002F72756E2F6E7363642F736F636B6574
        \\1320 audit(1731200100.000:9003):
    ;
    try feedNetlinkCapture(&asmb, text);
    var got = try mapAll(alloc, &asmb, .{});
    defer freeMapped(alloc, &got);
    try testing.expectEqual(@as(usize, 0), got.items.len);
}

test "assembler bounds pending events and flushes stale ones" {
    const alloc = testing.allocator;
    var asmb = Assembler.init(alloc, false);
    defer asmb.deinit();
    var i: u64 = 0;
    while (i < Assembler.max_pending + 5) : (i += 1) {
        try asmb.feed(.{ .type = msg.syscall, .sec = 100 + i, .ms = 0, .serial = i, .body = "arch=c000003e syscall=231 pid=7" });
    }
    try testing.expectEqual(@as(u64, 5), asmb.evicted);
    try asmb.flushOlderThan(100 + 10);
    try testing.expectEqual(@as(usize, Assembler.max_pending - 5), asmb.pending.count());
    const done = try asmb.take();
    defer {
        for (done) |e| asmb.destroy(e);
        alloc.free(done);
    }
    try testing.expectEqual(@as(usize, 10), done.len);
    try testing.expectEqual(Kind.exit_group, done[0].kind().?);
}

test "audit rule encoding matches struct audit_rule_data" {
    const alloc = testing.allocator;
    const r = try encodeRule(alloc, .{ .syscalls = .{ .arch = arch_x86_64, .numbers = &.{ 59, 42 } } });
    defer alloc.free(r);
    const fixed = 4 * (3 + 64 + 3 * 64 + 1);
    try testing.expectEqual(@as(usize, fixed + rule_key.len), r.len);
    const word = struct {
        fn at(b: []const u8, i: usize) u32 {
            return std.mem.readInt(u32, b[i * 4 ..][0..4], .little);
        }
    }.at;
    try testing.expectEqual(filter_exit, word(r, 0));
    try testing.expectEqual(action_always, word(r, 1));
    try testing.expectEqual(@as(u32, 2), word(r, 2));
    // mask[1] bit 27 (59) and mask[1] bit 10 (42).
    try testing.expectEqual((@as(u32, 1) << 27) | (@as(u32, 1) << 10), word(r, 3 + 1));
    try testing.expectEqual(field_arch, word(r, 3 + 64));
    try testing.expectEqual(field_filterkey, word(r, 3 + 64 + 1));
    try testing.expectEqual(arch_x86_64, word(r, 3 + 128));
    try testing.expectEqual(@as(u32, rule_key.len), word(r, 3 + 128 + 1));
    try testing.expectEqual(op_equal, word(r, 3 + 192));
    try testing.expectEqual(@as(u32, rule_key.len), word(r, 3 + 256));
    try testing.expectEqualStrings(rule_key, r[fixed..]);

    const w = try encodeRule(alloc, .{ .watch_dir = "/etc/cron.d" });
    defer alloc.free(w);
    try testing.expectEqual(@as(u32, 3), word(w, 2));
    try testing.expectEqual(@as(u32, 0xffffffff), word(w, 3));
    try testing.expectEqualStrings("/etc/cron.dtawny", w[fixed..]);
}

test "tail returns complete lines and follows truncation" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const rel = try std.fs.path.join(alloc, &.{ ".zig-cache", "tmp", &tmp.sub_path, "audit.log" });
    defer alloc.free(rel);
    {
        var f = try tmp.dir.createFile(io, "audit.log", .{});
        defer f.close(io);
        try f.writePositionalAll(io, "old line\n", 0);
    }
    var t = try Tail.open(alloc, rel, true);
    defer t.deinit();
    try testing.expect((try t.poll()) == null);
    {
        var f = try tmp.dir.openFile(io, "audit.log", .{ .mode = .read_write });
        defer f.close(io);
        try f.writePositionalAll(io, "one\ntw", 9);
    }
    const a = (try t.poll()).?;
    defer alloc.free(a);
    try testing.expectEqualStrings("one\n", a);
    {
        var f = try tmp.dir.openFile(io, "audit.log", .{ .mode = .read_write });
        defer f.close(io);
        try f.writePositionalAll(io, "o\n", 15);
    }
    const b = (try t.poll()).?;
    defer alloc.free(b);
    try testing.expectEqualStrings("two\n", b);
    {
        var f = try tmp.dir.createFile(io, "audit.log", .{ .truncate = true });
        defer f.close(io);
        try f.writePositionalAll(io, "new\n", 0);
    }
    const c = (try t.poll()).?;
    defer alloc.free(c);
    try testing.expectEqualStrings("new\n", c);
}
