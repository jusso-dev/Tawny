const std = @import("std");
const builtin = @import("builtin");
const iox = @import("../io_compat.zig");

const dnslog = if (builtin.target.os.tag == .macos) @import("../platform/macos/dnslog.zig") else struct {};
const libproc = if (builtin.target.os.tag == .macos) @import("../platform/macos/libproc.zig") else struct {};
const mac_retry_seconds: i64 = 3600;
/// Redacted querier lines (with no readable ones) before we conclude the
/// host has no private-data override and stop the stream.
const mac_redacted_threshold: u64 = 20;

const MacState = struct {
    stream: ?*dnslog.Stream = null,
    buf: ?*[dnslog.queue_capacity]dnslog.Resolved = null,
    retry_at: i64 = 0,
    redacted_total: u64 = 0,
    plaintext_total: u64 = 0,
};

fn buildMacosPayload(alloc: std.mem.Allocator, r: *const dnslog.Resolved) ![]u8 {
    var payload: std.Io.Writer.Allocating = .init(alloc);
    errdefer payload.deinit();
    const w = &payload.writer;
    try w.writeAll("{\"qname\":");
    try std.json.Stringify.value(r.query.name(), .{}, w);
    try w.writeAll(",\"qtype\":");
    try std.json.Stringify.value(r.query.typeName(), .{}, w);
    // Answers are logged mask.hash'ed even with the override.
    try w.writeAll(",\"response_ips\":[],\"resolver\":\"mDNSResponder\"");
    if (r.client) |c| {
        // The log carries a 15-char comm; prefer the live image name.
        var path_buf: [libproc.path_max]u8 = undefined;
        const live = if (libproc.pidPath(@intCast(c.pid), &path_buf)) |p| std.fs.path.basename(p) else "";
        try w.print(",\"pid\":{d},\"process_name\":", .{c.pid});
        try std.json.Stringify.value(if (live.len > 0) live else c.processName(), .{}, w);
    }
    try w.writeByte('}');
    return payload.toOwnedSlice();
}

const max_dns_events: usize = 4096;
const max_journal_line_bytes: usize = 64 * 1024;
const journal_timeout: std.Io.Timeout = .{ .duration = .{
    .clock = .awake,
    .raw = .fromSeconds(10),
} };

/// DNS query collector. Linux: shells out to `journalctl -u systemd-resolved`
/// since the last collection and pulls structured JSON lines, then matches
/// log entries that look like DNS queries.
///
/// This is intentionally user-mode and dependency-free: it does not attach to
/// the resolved varlink socket, does not parse pcap, and does not require
/// privileges beyond journal read access. The trade-off is that systems not
/// running systemd-resolved emit nothing, and operators must enable resolved
/// query logging (`resolvectl log-level debug`) to see every lookup. That's
/// flagged in the README + the Detections page.
///
/// macOS: a `log stream` child filtered to mDNSResponder, read by a
/// background thread into a bounded queue (platform/macos/dnslog.zig). Query
/// names are private in the unified log unless the host has an
/// Enable-Private-Data override for com.apple.mDNSResponder; redacted names
/// are never emitted, and a stream that only ever yields `<private>` is shut
/// down and retried hourly. /etc/hosts entries are emitted as on Linux.
pub const Collector = struct {
    allocator: std.mem.Allocator,
    last_run_unix: i64 = 0,
    last_hosts_hash: ?u64 = null,
    mac: if (builtin.target.os.tag == .macos) MacState else void = if (builtin.target.os.tag == .macos) .{} else {},

    pub fn init(alloc: std.mem.Allocator) Collector {
        return .{ .allocator = alloc };
    }

    /// Start background capture now (macOS `log stream` takes a few seconds
    /// to attach) instead of on the first collection tick.
    pub fn start(self: *Collector) void {
        if (comptime builtin.target.os.tag != .macos) return;
        var scratch = std.array_list.Managed([]u8).init(self.allocator);
        defer scratch.deinit();
        self.collectMacos(&scratch, iox.timestamp()) catch |err| {
            std.debug.print("dns: start failed: {s}\n", .{@errorName(err)});
        };
    }

    pub fn deinit(self: *Collector) void {
        if (comptime builtin.target.os.tag == .macos) {
            if (self.mac.stream) |s| s.stop();
            if (self.mac.buf) |b| self.allocator.destroy(b);
            self.mac = .{};
        }
    }

    /// Returns one JSON payload per detected DNS query since the last call.
    /// Caller owns the outer slice and each inner payload.
    pub fn collectQueries(self: *Collector) ![][]u8 {
        const collection_started = iox.timestamp();
        var payloads = std.array_list.Managed([]u8).init(self.allocator);
        errdefer {
            for (payloads.items) |p| self.allocator.free(p);
            payloads.deinit();
        }

        switch (builtin.target.os.tag) {
            .linux => {
                try self.collectStaticHosts(&payloads);
                if (try self.collectLinux(&payloads)) {
                    self.last_run_unix = collection_started;
                }
            },
            .macos => {
                try self.collectStaticHosts(&payloads);
                try self.collectMacos(&payloads, collection_started);
            },
            else => {}, // Windows DNS capture needs ETW; not in this collector.
        }

        try dedupePayloads(self.allocator, &payloads);
        return payloads.toOwnedSlice();
    }

    fn collectMacos(self: *Collector, payloads: *std.array_list.Managed([]u8), now: i64) !void {
        if (comptime builtin.target.os.tag != .macos) return;
        const m = &self.mac;

        if (m.stream == null) {
            if (now < m.retry_at) return;
            if (m.buf == null) m.buf = try self.allocator.create([dnslog.queue_capacity]dnslog.Resolved);
            m.stream = dnslog.Stream.start(self.allocator) catch |err| {
                std.debug.print("dns: cannot start mDNSResponder log stream: {s}\n", .{@errorName(err)});
                m.retry_at = now + mac_retry_seconds;
                return;
            };
            m.redacted_total = 0;
            m.plaintext_total = 0;
            return; // first drain on the next tick
        }

        const stream = m.stream.?;
        const drained = stream.drain(m.buf.?);
        m.redacted_total += drained.redacted;
        m.plaintext_total += drained.plaintext;
        if (drained.dropped > 0) {
            std.debug.print("dns: dropped {d} mDNSResponder queries (queue full)\n", .{drained.dropped});
        }

        for (m.buf.?[0..drained.count]) |*r| {
            if (payloads.items.len >= max_dns_events) break;
            const payload = try buildMacosPayload(self.allocator, r);
            payloads.append(payload) catch |err| {
                self.allocator.free(payload);
                return err;
            };
        }

        if (m.plaintext_total == 0 and m.redacted_total >= mac_redacted_threshold) {
            std.debug.print(
                "dns: mDNSResponder query names are redacted (<private>); macOS dns_query needs an Enable-Private-Data logging override for com.apple.mDNSResponder. Retrying in {d}s.\n",
                .{mac_retry_seconds},
            );
            self.stopMacStream(now);
        } else if (stream.finished()) {
            std.debug.print("dns: `log stream` exited (agent must run as root/admin); retrying in {d}s\n", .{mac_retry_seconds});
            self.stopMacStream(now);
        }
    }

    fn stopMacStream(self: *Collector, now: i64) void {
        if (comptime builtin.target.os.tag != .macos) return;
        if (self.mac.stream) |s| s.stop();
        self.mac.stream = null;
        self.mac.retry_at = now + mac_retry_seconds;
    }

    fn collectLinux(self: *Collector, payloads: *std.array_list.Managed([]u8)) !bool {
        const since_arg = if (self.last_run_unix == 0)
            try self.allocator.dupe(u8, "60 seconds ago")
        else
            try self.allocator.print("@{d}", .{self.last_run_unix});
        defer self.allocator.free(since_arg);

        const result = std.process.run(self.allocator, iox.current(), .{
            .argv = &.{
                "journalctl",
                "-u",
                "systemd-resolved",
                "-u",
                "dnsmasq",
                "-u",
                "unbound",
                "-u",
                "named",
                "--since",
                since_arg,
                "--output=json",
                "--lines=4096",
                "--no-pager",
                "--quiet",
            },
            .stdout_limit = .limited(2 * 1024 * 1024),
            .stderr_limit = .limited(64 * 1024),
            .timeout = journal_timeout,
        }) catch return false; // journalctl missing, blocked, or timed out.
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);
        if (!termSucceeded(result.term)) return false;

        var lines = std.mem.splitScalar(u8, result.stdout, '\n');
        while (lines.next()) |line| {
            if (payloads.items.len >= max_dns_events) break;
            if (line.len == 0) continue;
            if (line.len > max_journal_line_bytes) continue;
            try parseLine(self.allocator, line, payloads);
        }
        return true;
    }

    fn collectStaticHosts(self: *Collector, payloads: *std.array_list.Managed([]u8)) !void {
        const io = iox.current();
        var file = std.Io.Dir.openFileAbsolute(io, "/etc/hosts", .{}) catch return;
        defer file.close(io);
        const raw = iox.readToEndAlloc(file, self.allocator, 512 * 1024) catch return;
        defer self.allocator.free(raw);

        const hash = std.hash.Wyhash.hash(0, raw);
        if (self.last_hosts_hash != null and self.last_hosts_hash.? == hash) return;
        try appendHostsEntries(self.allocator, raw, payloads);
        self.last_hosts_hash = hash;
    }
};

/// Parse one journal JSON line. We tolerate journal entries that aren't DNS
/// queries: we look for an `MESSAGE` field containing a hostname being looked
/// up. systemd-resolved at debug level emits messages like:
///   "Looking up RR for example.com IN A"
///   "Got DNS reply ... example.com IN A -> 93.184.216.34"
fn parseLine(alloc: std.mem.Allocator, line: []const u8, out: *std.array_list.Managed([]u8)) !void {
    if (out.items.len >= max_dns_events or line.len > max_journal_line_bytes) return;
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, line, .{}) catch return;
    defer parsed.deinit();

    if (parsed.value != .object) return;
    const obj = parsed.value.object;
    const message_entry = obj.get("MESSAGE") orelse return;
    if (message_entry != .string) return;
    const message = message_entry.string;

    const qname = extractQname(message) orelse return;
    if (!isValidDomain(qname)) return;
    const qtype = extractQtype(message) orelse "A";
    if (!isValidQtype(qtype)) return;
    const reply_ip = extractReplyIp(message);
    const resolver = resolverName(obj);
    const ts_secs: i64 = blk: {
        const ts_entry = obj.get("__REALTIME_TIMESTAMP") orelse break :blk iox.timestamp();
        if (ts_entry != .string) break :blk iox.timestamp();
        const micros = std.fmt.parseInt(i64, ts_entry.string, 10) catch break :blk iox.timestamp();
        break :blk @divTrunc(micros, 1_000_000);
    };
    _ = ts_secs; // ts surfaces on the event envelope, not the payload, so we drop it here.

    var payload: std.Io.Writer.Allocating = .init(alloc);
    errdefer payload.deinit();
    const w = &payload.writer;

    try w.writeAll("{\"qname\":");
    try std.json.Stringify.value(qname, .{}, w);
    try w.writeAll(",\"qtype\":");
    try std.json.Stringify.value(qtype, .{}, w);
    try w.writeAll(",\"response_ips\":");
    if (reply_ip) |ip| {
        try w.writeAll("[");
        try std.json.Stringify.value(ip, .{}, w);
        try w.writeAll("]");
    } else {
        try w.writeAll("[]");
    }
    try w.writeAll(",\"resolver\":");
    try std.json.Stringify.value(resolver, .{}, w);
    try w.writeByte('}');

    try out.append(try payload.toOwnedSlice());
}

fn extractQname(message: []const u8) ?[]const u8 {
    // Common shapes:
    //   "Looking up RR for example.com IN A"
    //   "Got DNS reply for example.com IN A: 93.184.216.34"
    //   "Resolved example.com -> 93.184.216.34"
    const triggers = [_][]const u8{
        "Looking up RR for ",
        "Got DNS reply for ",
        "Resolved ",
        "query: ",
        "reply ",
        "cached ",
    };
    inline for (triggers) |trigger| {
        if (std.mem.indexOf(u8, message, trigger)) |idx| {
            const start = idx + trigger.len;
            const rest = message[start..];
            const end = std.mem.indexOfAny(u8, rest, " \t:->") orelse rest.len;
            const candidate = std.mem.trim(u8, rest[0..end], " \t.,");
            if (candidate.len > 0 and candidate.len <= 253) return candidate;
        }
    }
    if (std.mem.indexOf(u8, message, "query[")) |query_idx| {
        const close_offset = std.mem.indexOf(u8, message[query_idx..], "] ") orelse return null;
        const close = query_idx + close_offset;
        const rest = message[close + 2 ..];
        const end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
        const candidate = std.mem.trim(u8, rest[0..end], " \t.,");
        if (candidate.len > 0 and candidate.len <= 253) return candidate;
    }
    return null;
}

fn extractQtype(message: []const u8) ?[]const u8 {
    if (std.mem.indexOf(u8, message, "query[")) |query_idx| {
        const start = query_idx + "query[".len;
        const close_offset = std.mem.indexOfScalar(u8, message[start..], ']') orelse return null;
        const close = start + close_offset;
        const candidate = message[start..close];
        if (candidate.len > 0 and candidate.len <= 16) return candidate;
    }
    const types = [_][]const u8{ " A ", " AAAA ", " CNAME ", " MX ", " TXT ", " NS ", " PTR ", " SOA " };
    for (types) |type_token| {
        if (std.mem.indexOf(u8, message, type_token) != null) {
            return std.mem.trim(u8, type_token, " ");
        }
    }
    return null;
}

fn extractReplyIp(message: []const u8) ?[]const u8 {
    // Heuristic: find the last "->" or ": " followed by an IPv4 / IPv6 literal.
    const markers = [_][]const u8{ "-> ", ": ", " is " };
    for (markers) |marker| {
        if (std.mem.lastIndexOf(u8, message, marker)) |idx| {
            const start = idx + marker.len;
            const tail = std.mem.trim(u8, message[start..], " \t.,;");
            if (looksLikeIp(tail)) return tail;
        }
    }
    return null;
}

fn resolverName(obj: std.json.ObjectMap) []const u8 {
    const unit_entry = obj.get("_SYSTEMD_UNIT") orelse return "systemd-resolved";
    if (unit_entry != .string) return "systemd-resolved";
    if (unit_entry.string.len == 0 or unit_entry.string.len > 128) return "systemd-resolved";
    const suffix = ".service";
    if (std.mem.endsWith(u8, unit_entry.string, suffix)) {
        return unit_entry.string[0 .. unit_entry.string.len - suffix.len];
    }
    return unit_entry.string;
}

fn looksLikeIp(text: []const u8) bool {
    _ = std.Io.net.IpAddress.parse(text, 0) catch return false;
    return true;
}

fn isValidDomain(value: []const u8) bool {
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
    const known = [_][]const u8{ "A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SOA", "SRV", "CAA", "ANY" };
    for (known) |candidate| {
        if (std.ascii.eqlIgnoreCase(value, candidate)) return true;
    }
    return false;
}

fn termSucceeded(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn appendHostsEntries(
    alloc: std.mem.Allocator,
    raw: []const u8,
    out: *std.array_list.Managed([]u8),
) !void {
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line_raw| {
        if (out.items.len >= max_dns_events) break;
        const hash = std.mem.indexOfScalar(u8, line_raw, '#') orelse line_raw.len;
        const line = std.mem.trim(u8, line_raw[0..hash], " \t\r");
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        const address = fields.next() orelse continue;
        if (!looksLikeIp(address)) continue;
        const qtype = if (std.mem.indexOfScalar(u8, address, ':') != null) "AAAA" else "A";

        while (fields.next()) |qname| {
            if (out.items.len >= max_dns_events) break;
            if (!isValidDomain(qname)) continue;

            var payload: std.Io.Writer.Allocating = .init(alloc);
            errdefer payload.deinit();
            const w = &payload.writer;
            try w.writeAll("{\"qname\":");
            try std.json.Stringify.value(qname, .{}, w);
            try w.writeAll(",\"qtype\":");
            try std.json.Stringify.value(qtype, .{}, w);
            try w.writeAll(",\"response_ips\":[");
            try std.json.Stringify.value(address, .{}, w);
            try w.writeAll("],\"resolver\":\"hosts-file\"}");
            try out.append(try payload.toOwnedSlice());
        }
    }
}

fn dedupePayloads(alloc: std.mem.Allocator, payloads: *std.array_list.Managed([]u8)) !void {
    var seen = std.StringHashMap(void).init(alloc);
    defer seen.deinit();
    try seen.ensureTotalCapacity(@intCast(payloads.items.len));

    var write_index: usize = 0;
    for (payloads.items) |payload| {
        if (seen.contains(payload)) {
            alloc.free(payload);
            continue;
        }
        seen.putAssumeCapacityNoClobber(payload, {});
        payloads.items[write_index] = payload;
        write_index += 1;
    }
    payloads.items.len = write_index;
}

test "qname extraction" {
    const a = extractQname("Looking up RR for example.com IN A");
    try std.testing.expect(a != null);
    try std.testing.expectEqualStrings("example.com", a.?);
}

test "hosts file entries become DNS telemetry" {
    var payloads = std.array_list.Managed([]u8).init(std.testing.allocator);
    defer {
        for (payloads.items) |payload| std.testing.allocator.free(payload);
        payloads.deinit();
    }

    try appendHostsEntries(
        std.testing.allocator,
        "127.0.0.1 localhost\n10.0.1.25 app.corp.example app # service\n",
        &payloads,
    );

    try std.testing.expectEqual(@as(usize, 3), payloads.items.len);
    try std.testing.expect(std.mem.indexOf(u8, payloads.items[1], "app.corp.example") != null);
    try std.testing.expect(std.mem.indexOf(u8, payloads.items[1], "10.0.1.25") != null);
    try std.testing.expect(std.mem.indexOf(u8, payloads.items[1], "hosts-file") != null);
}

test "dnsmasq journal query is parsed" {
    var payloads = std.array_list.Managed([]u8).init(std.testing.allocator);
    defer {
        for (payloads.items) |payload| std.testing.allocator.free(payload);
        payloads.deinit();
    }

    try parseLine(
        std.testing.allocator,
        \\{"MESSAGE":"query[AAAA] api.corp.example from 10.0.1.25","_SYSTEMD_UNIT":"dnsmasq.service"}
    ,
        &payloads,
    );

    try std.testing.expectEqual(@as(usize, 1), payloads.items.len);
    try std.testing.expect(std.mem.indexOf(u8, payloads.items[0], "api.corp.example") != null);
    try std.testing.expect(std.mem.indexOf(u8, payloads.items[0], "AAAA") != null);
    try std.testing.expect(std.mem.indexOf(u8, payloads.items[0], "dnsmasq") != null);
}

test "malformed DNS values are rejected and duplicates are stable" {
    var payloads = std.array_list.Managed([]u8).init(std.testing.allocator);
    defer {
        for (payloads.items) |payload| std.testing.allocator.free(payload);
        payloads.deinit();
    }

    try parseLine(
        std.testing.allocator,
        \\{"MESSAGE":"query[A] bad/$name from 10.0.1.25","_SYSTEMD_UNIT":"dnsmasq.service"}
    ,
        &payloads,
    );
    try appendHostsEntries(
        std.testing.allocator,
        "10.0.0.2 valid.example valid.example\nnot-an-ip ignored.example\n",
        &payloads,
    );
    try dedupePayloads(std.testing.allocator, &payloads);

    try std.testing.expectEqual(@as(usize, 1), payloads.items.len);
    try std.testing.expect(std.mem.indexOf(u8, payloads.items[0], "valid.example") != null);
}

test "macOS dns_query from mDNSResponder log when the host allows it" {
    if (builtin.target.os.tag != .macos) return error.SkipZigTest;
    // Needs the per-subsystem private-data override and an admin/root user.
    const io = std.testing.io;
    std.Io.Dir.accessAbsolute(io, "/Library/Preferences/Logging/Subsystems/com.apple.mDNSResponder.plist", .{}) catch return error.SkipZigTest;
    iox.initialize(io);
    const alloc = std.testing.allocator;

    var c = Collector.init(alloc);
    defer c.deinit();
    const first = try c.collectQueries(); // starts the stream
    for (first) |p| alloc.free(p);
    alloc.free(first);
    if (c.mac.stream == null) return error.SkipZigTest;
    iox.sleep(2 * std.time.ns_per_s); // let `log stream` attach

    var name_buf: [64]u8 = undefined;
    const qname = try std.fmt.bufPrint(&name_buf, "tawny-dns-probe-{d}.example.net", .{std.c.getpid()});
    const lookup = try std.process.run(alloc, io, .{ .argv = &.{ "/usr/bin/dscacheutil", "-q", "host", "-a", "name", qname } });
    alloc.free(lookup.stdout);
    alloc.free(lookup.stderr);

    var found = false;
    var attempt: usize = 0;
    while (!found and attempt < 10) : (attempt += 1) {
        iox.sleep(1 * std.time.ns_per_s);
        if (c.mac.stream) |s| if (s.finished()) return error.SkipZigTest; // not admin
        const got = try c.collectQueries();
        defer {
            for (got) |p| alloc.free(p);
            alloc.free(got);
        }
        for (got) |payload| {
            try std.testing.expect(std.mem.indexOf(u8, payload, "<private>") == null);
            if (std.mem.indexOf(u8, payload, qname) == null) continue;
            var parsed = try std.json.parseFromSlice(std.json.Value, alloc, payload, .{});
            defer parsed.deinit();
            const o = parsed.value.object;
            try std.testing.expectEqualStrings("mDNSResponder", o.get("resolver").?.string);
            if (o.get("process_name")) |pn| try std.testing.expectEqualStrings("dscacheutil", pn.string);
            found = true;
        }
    }
    try std.testing.expect(found);
}
