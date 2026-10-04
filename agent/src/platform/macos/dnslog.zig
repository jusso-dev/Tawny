//! DNS queries from mDNSResponder's unified-log messages (user mode).
//!
//! mDNSResponder logs every query it sends upstream as
//!   "[Q<id>] Handling concluded querier: <qname>. <TYPE> IN"
//! with format string "[Q%u] Handling concluded querier: %@". `%@` is private
//! by default, so on a stock Mac the name renders as `<private>`. It is only
//! readable when the host carries a logging override for that one subsystem,
//! e.g. /Library/Preferences/Logging/Subsystems/com.apple.mDNSResponder.plist
//! with DEFAULT-OPTIONS / Enable-Private-Data = true (or the equivalent MDM
//! com.apple.system.logging profile). That is scoped to mDNSResponder; it is
//! not the system-wide `log config --mode private_data:on`.
//!
//! We never emit `<private>`: redacted lines are counted, and when the stream
//! shows only redacted names the collector stops itself and retries later.
//!
//! Attribution: "[R<rid>] DNSService... START -- ... client pid: <pid> (<name>)"
//! names the requesting process, and "[R<rid>->Q<qid>] ..." lines link the
//! request to the question; both are best-effort and bounded.
//!
//! Limits: only queries that go to the wire are logged (cache hits are not);
//! answers are logged with `sensitive, mask.hash` and stay hashed even with
//! the override, so `response_ips` is always empty.

const std = @import("std");
const iox = @import("../../io_compat.zig");

pub const queue_capacity: usize = 2048;
const max_line_bytes: usize = 16 * 1024;
const max_map_entries: usize = 8192;

pub const predicate =
    \\process == "mDNSResponder" AND (eventMessage CONTAINS "Handling concluded querier" OR eventMessage CONTAINS "client pid:" OR eventMessage CONTAINS "->Q")
;

// --- Pure parsers -----------------------------------------------------------

pub const Querier = struct {
    qid: u32,
    /// Without the trailing root dot.
    qname: []const u8,
    qtype: []const u8,
    redacted: bool,
};

fn parseBracketId(msg: []const u8, prefix: u8) ?struct { id: u32, rest: []const u8 } {
    if (msg.len < 4 or msg[0] != '[' or msg[1] != prefix) return null;
    var i: usize = 2;
    while (i < msg.len and std.ascii.isDigit(msg[i])) i += 1;
    if (i == 2) return null;
    const id = std.fmt.parseInt(u32, msg[2..i], 10) catch return null;
    return .{ .id = id, .rest = msg[i..] };
}

/// "[Q22103] Handling concluded querier: example.org. AAAA IN"
pub fn parseQuerier(msg: []const u8) ?Querier {
    const head = parseBracketId(msg, 'Q') orelse return null;
    const marker = "] Handling concluded querier: ";
    if (!std.mem.startsWith(u8, head.rest, marker)) return null;
    var fields = std.mem.tokenizeScalar(u8, head.rest[marker.len..], ' ');
    const name_raw = fields.next() orelse return null;
    const qtype = fields.next() orelse return null;
    if (name_raw[0] == '<') return .{ .qid = head.id, .qname = "", .qtype = qtype, .redacted = true };
    const qname = std.mem.trimEnd(u8, name_raw, ".");
    if (!isValidDomain(qname) or !isValidQtype(qtype)) return null;
    return .{ .qid = head.id, .qname = qname, .qtype = qtype, .redacted = false };
}

pub const ClientStart = struct {
    rid: u32,
    pid: u32,
    process_name: []const u8,
};

/// "[R1707032] DNSServiceGetAddrInfo START -- ..., client pid: 43637 (NewsToday2), name hash: ..."
pub fn parseClientStart(msg: []const u8) ?ClientStart {
    const head = parseBracketId(msg, 'R') orelse return null;
    if (head.rest.len == 0 or head.rest[0] != ']') return null;
    const marker = "client pid: ";
    const at = std.mem.indexOf(u8, head.rest, marker) orelse return null;
    const tail = head.rest[at + marker.len ..];
    var end: usize = 0;
    while (end < tail.len and std.ascii.isDigit(tail[end])) end += 1;
    const pid = std.fmt.parseInt(u32, tail[0..end], 10) catch return null;
    var name: []const u8 = "";
    if (std.mem.startsWith(u8, tail[end..], " (")) {
        const open = end + 2;
        if (std.mem.indexOfScalarPos(u8, tail, open, ')')) |close| name = tail[open..close];
    }
    return .{ .rid = head.id, .pid = pid, .process_name = name };
}

/// "[R1707042->Q22103] Question assigned DNS service 83" -> {rid, qid}
pub fn parseLink(msg: []const u8) ?[2]u32 {
    const head = parseBracketId(msg, 'R') orelse return null;
    if (!std.mem.startsWith(u8, head.rest, "->Q")) return null;
    var i: usize = 3;
    while (i < head.rest.len and std.ascii.isDigit(head.rest[i])) i += 1;
    if (i == 3 or i >= head.rest.len or head.rest[i] != ']') return null;
    const qid = std.fmt.parseInt(u32, head.rest[3..i], 10) catch return null;
    return .{ head.id, qid };
}

/// `eventMessage` from one `log stream --style ndjson` line.
pub fn eventMessage(alloc: std.mem.Allocator, line: []const u8) ?std.json.Parsed(Line) {
    if (line.len == 0 or line[0] != '{') return null;
    return std.json.parseFromSlice(Line, alloc, line, .{ .ignore_unknown_fields = true }) catch null;
}

pub const Line = struct { eventMessage: []const u8 = "" };

pub fn isValidDomain(value: []const u8) bool {
    if (value.len == 0 or value.len > 253) return false;
    var label_len: usize = 0;
    for (value) |ch| {
        if (ch == '.') {
            if (label_len == 0 or label_len > 63) return false;
            label_len = 0;
            continue;
        }
        if (!std.ascii.isAlphanumeric(ch) and ch != '-' and ch != '_') return false;
        label_len += 1;
    }
    return label_len > 0 and label_len <= 63;
}

fn isValidQtype(value: []const u8) bool {
    if (value.len == 0 or value.len > 15) return false;
    for (value) |ch| if (!std.ascii.isAlphanumeric(ch)) return false;
    return true;
}

// --- Shared state between the reader thread and the collector ---------------

pub const Query = struct {
    qid: u32,
    qname: [253]u8,
    qname_len: u8,
    qtype: [16]u8,
    qtype_len: u8,

    pub fn name(self: *const Query) []const u8 {
        return self.qname[0..self.qname_len];
    }
    pub fn typeName(self: *const Query) []const u8 {
        return self.qtype[0..self.qtype_len];
    }
};

pub const Client = struct {
    pid: u32,
    name: [64]u8,
    name_len: u8,

    pub fn processName(self: *const Client) []const u8 {
        return self.name[0..self.name_len];
    }
};

const Shared = struct {
    lock: std.c.os_unfair_lock = .{},
    ring: [queue_capacity]Query = undefined,
    len: usize = 0,
    dropped: u64 = 0,
    redacted: u64 = 0,
    plaintext: u64 = 0,
    clients: std.AutoHashMap(u32, Client),
    links: std.AutoHashMap(u32, u32),
    /// Set by the reader thread when the pipe hits EOF (child exited).
    finished: std.atomic.Value(bool) = .init(false),

    fn acquire(self: *Shared) void {
        std.c.os_unfair_lock_lock(&self.lock);
    }
    fn release(self: *Shared) void {
        std.c.os_unfair_lock_unlock(&self.lock);
    }

    /// Apply one log message. Runs on the reader thread.
    fn ingest(self: *Shared, msg: []const u8) void {
        if (parseQuerier(msg)) |q| {
            self.acquire();
            defer self.release();
            if (q.redacted) {
                self.redacted += 1;
                return;
            }
            self.plaintext += 1;
            if (self.len == queue_capacity) {
                self.dropped += 1;
                return;
            }
            var entry = Query{ .qid = q.qid, .qname = undefined, .qname_len = @intCast(q.qname.len), .qtype = undefined, .qtype_len = @intCast(q.qtype.len) };
            @memcpy(entry.qname[0..q.qname.len], q.qname);
            @memcpy(entry.qtype[0..q.qtype.len], q.qtype);
            self.ring[self.len] = entry;
            self.len += 1;
            return;
        }
        if (parseLink(msg)) |link| {
            self.acquire();
            defer self.release();
            if (self.links.count() >= max_map_entries) self.links.clearRetainingCapacity();
            self.links.put(link[1], link[0]) catch {};
            return;
        }
        if (parseClientStart(msg)) |start| {
            self.acquire();
            defer self.release();
            if (self.clients.count() >= max_map_entries) self.clients.clearRetainingCapacity();
            var c = Client{ .pid = start.pid, .name = undefined, .name_len = 0 };
            const n = @min(start.process_name.len, c.name.len);
            @memcpy(c.name[0..n], start.process_name[0..n]);
            c.name_len = @intCast(n);
            self.clients.put(start.rid, c) catch {};
        }
    }
};

pub const Drained = struct {
    count: usize,
    dropped: u64,
    redacted: u64,
    plaintext: u64,
};

pub const Resolved = struct {
    query: Query,
    client: ?Client,
};

/// `log stream` child + reader thread feeding a bounded queue.
pub const Stream = struct {
    allocator: std.mem.Allocator,
    shared: *Shared,
    child: std.process.Child,
    thread: std.Thread,

    pub fn start(alloc: std.mem.Allocator) !*Stream {
        const shared = try alloc.create(Shared);
        errdefer alloc.destroy(shared);
        shared.* = .{
            .clients = std.AutoHashMap(u32, Client).init(std.heap.c_allocator),
            .links = std.AutoHashMap(u32, u32).init(std.heap.c_allocator),
        };
        errdefer {
            shared.clients.deinit();
            shared.links.deinit();
        }

        const io = iox.current();
        var child = try std.process.spawn(io, .{
            .argv = &.{ "/usr/bin/log", "stream", "--style", "ndjson", "--level", "default", "--predicate", predicate },
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .ignore,
        });
        errdefer child.kill(io);

        const self = try alloc.create(Stream);
        errdefer alloc.destroy(self);
        self.* = .{ .allocator = alloc, .shared = shared, .child = child, .thread = undefined };
        self.thread = try std.Thread.spawn(.{ .stack_size = 256 * 1024 }, readerMain, .{ shared, child.stdout.?.handle });
        return self;
    }

    /// True once `log stream` has exited (e.g. not admin, or killed).
    pub fn finished(self: *Stream) bool {
        return self.shared.finished.load(.acquire);
    }

    pub fn stop(self: *Stream) void {
        const io = iox.current();
        if (self.child.id) |pid| _ = std.c.kill(pid, std.c.SIG.TERM);
        self.thread.join(); // reader sees EOF once the child is gone
        _ = self.child.wait(io) catch {};
        self.shared.clients.deinit();
        self.shared.links.deinit();
        self.allocator.destroy(self.shared);
        self.allocator.destroy(self);
    }

    /// Move queued queries into `out`, resolving the requesting process
    /// where the R/Q link and client START line have been seen.
    pub fn drain(self: *Stream, out: *[queue_capacity]Resolved) Drained {
        const sh = self.shared;
        sh.acquire();
        defer sh.release();
        for (sh.ring[0..sh.len], 0..) |q, i| {
            const client: ?Client = if (sh.links.get(q.qid)) |rid| sh.clients.get(rid) else null;
            out[i] = .{ .query = q, .client = client };
        }
        const result = Drained{ .count = sh.len, .dropped = sh.dropped, .redacted = sh.redacted, .plaintext = sh.plaintext };
        sh.len = 0;
        sh.dropped = 0;
        sh.redacted = 0;
        sh.plaintext = 0;
        return result;
    }
};

fn readerMain(shared: *Shared, fd: std.posix.fd_t) void {
    defer shared.finished.store(true, .release);
    var line_buf: [max_line_bytes]u8 = undefined;
    var line_len: usize = 0;
    var discarding = false;
    var chunk: [16 * 1024]u8 = undefined;
    var arena_buf: [64 * 1024]u8 = undefined;

    while (true) {
        const n = std.c.read(fd, &chunk, chunk.len);
        if (n < 0) {
            if (std.c.errno(n) == .INTR) continue;
            return;
        }
        if (n == 0) return;
        for (chunk[0..@intCast(n)]) |byte| {
            if (byte == '\n') {
                if (!discarding and line_len > 0) {
                    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
                    if (eventMessage(fba.allocator(), line_buf[0..line_len])) |parsed| {
                        shared.ingest(parsed.value.eventMessage);
                    }
                }
                line_len = 0;
                discarding = false;
                continue;
            }
            if (discarding) continue;
            if (line_len == line_buf.len) {
                discarding = true; // oversized line: skip to the next newline
                continue;
            }
            line_buf[line_len] = byte;
            line_len += 1;
        }
    }
}

test "querier lines yield names and never <private>" {
    const q = parseQuerier("[Q22103] Handling concluded querier: tawny-probe-7731.example.org. AAAA IN").?;
    try std.testing.expectEqual(@as(u32, 22103), q.qid);
    try std.testing.expectEqualStrings("tawny-probe-7731.example.org", q.qname);
    try std.testing.expectEqualStrings("AAAA", q.qtype);
    try std.testing.expect(!q.redacted);

    const r = parseQuerier("[Q14134] Handling concluded querier: <private> A IN").?;
    try std.testing.expect(r.redacted);
    try std.testing.expectEqualStrings("", r.qname);

    try std.testing.expect(parseQuerier("[Q1] Handling concluded querier: bad/name. A IN") == null);
    try std.testing.expect(parseQuerier("[Q1] Querier concluded -- reason: response") == null);
    try std.testing.expect(parseQuerier("Handling concluded querier: x.com. A IN") == null);
}

test "client start and link lines" {
    const s = parseClientStart("[R1707032] DNSServiceGetAddrInfo START -- hostname: <mask.hash: 'gR+m'>, protocols: 0, flags: 0xC000D000, interface index: 0, client pid: 43637 (NewsToday2), name hash: cf6c9b39").?;
    try std.testing.expectEqual(@as(u32, 1707032), s.rid);
    try std.testing.expectEqual(@as(u32, 43637), s.pid);
    try std.testing.expectEqualStrings("NewsToday2", s.process_name);

    const g = parseClientStart("[R1707030] getaddrinfo start -- flags: 0xC000D000, hostname: <mask.hash: 'x'>, client pid: 679 (syspolicyd)").?;
    try std.testing.expectEqual(@as(u32, 679), g.pid);
    try std.testing.expectEqualStrings("syspolicyd", g.process_name);

    try std.testing.expect(parseClientStart("[R1707042->Q22103] Question assigned DNS service 83") == null);

    const link = parseLink("[R1707042->Q22103] Question assigned DNS service 83").?;
    try std.testing.expectEqual(@as(u32, 1707042), link[0]);
    try std.testing.expectEqual(@as(u32, 22103), link[1]);
    try std.testing.expect(parseLink("[R1707042] DNSServiceQueryRecord START") == null);
}

test "ndjson eventMessage extraction and shared ingest attribution" {
    var buf: [8192]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    const parsed = eventMessage(fba.allocator(), "{\"processID\":649,\"eventMessage\":\"[Q5] Handling concluded querier: a.example. A IN\",\"subsystem\":\"com.apple.mDNSResponder\"}").?;
    try std.testing.expectEqualStrings("[Q5] Handling concluded querier: a.example. A IN", parsed.value.eventMessage);
    try std.testing.expect(eventMessage(fba.allocator(), "Filtering the log data using \"process == x\"") == null);

    var shared = Shared{
        .clients = std.AutoHashMap(u32, Client).init(std.testing.allocator),
        .links = std.AutoHashMap(u32, u32).init(std.testing.allocator),
    };
    defer shared.clients.deinit();
    defer shared.links.deinit();
    shared.ingest("[R9] DNSServiceQueryRecord START -- qname: <mask.hash: 'x'>, qtype: A, client pid: 321 (curl), name hash: 1");
    shared.ingest("[R9->Q5] Question assigned DNS service 83");
    shared.ingest("[Q5] Handling concluded querier: a.example. A IN");
    shared.ingest("[Q6] Handling concluded querier: <private> AAAA IN");
    shared.ingest("[Q7] Handling concluded querier: b.example. AAAA IN");

    try std.testing.expectEqual(@as(usize, 2), shared.len);
    try std.testing.expectEqual(@as(u64, 1), shared.redacted);
    try std.testing.expectEqualStrings("a.example", shared.ring[0].name());
    const rid = shared.links.get(5).?;
    try std.testing.expectEqual(@as(u32, 321), shared.clients.get(rid).?.pid);
    try std.testing.expect(shared.links.get(7) == null);
}
