const std = @import("std");
const builtin = @import("builtin");
const iox = @import("../io_compat.zig");

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
pub const Collector = struct {
    allocator: std.mem.Allocator,
    last_run_unix: i64 = 0,
    last_hosts_hash: ?u64 = null,

    pub fn init(alloc: std.mem.Allocator) Collector {
        return .{ .allocator = alloc };
    }

    /// Returns one JSON payload per detected DNS query since the last call.
    /// Caller owns the outer slice and each inner payload.
    pub fn collectQueries(self: *Collector) ![][]u8 {
        var payloads = std.array_list.Managed([]u8).init(self.allocator);
        errdefer {
            for (payloads.items) |p| self.allocator.free(p);
            payloads.deinit();
        }

        switch (builtin.os.tag) {
            .linux => {
                try self.collectStaticHosts(&payloads);
                try self.collectLinux(&payloads);
            },
            else => {}, // Win/macOS DNS capture needs ETW / NetworkExtension; not in this collector.
        }

        self.last_run_unix = iox.timestamp();
        return payloads.toOwnedSlice();
    }

    fn collectLinux(self: *Collector, payloads: *std.array_list.Managed([]u8)) !void {
        const since_arg = if (self.last_run_unix == 0)
            try self.allocator.dupe(u8, "60 seconds ago")
        else
            try std.fmt.allocPrint(self.allocator, "@{d}", .{self.last_run_unix});
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
                "--no-pager",
                "--quiet",
            },
            .stdout_limit = .limited(4 * 1024 * 1024),
            .stderr_limit = .limited(4 * 1024 * 1024),
        }) catch return; // journalctl missing or not permitted; silently skip.
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);

        var lines = std.mem.splitScalar(u8, result.stdout, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            try parseLine(self.allocator, line, payloads);
        }
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
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, line, .{}) catch return;
    defer parsed.deinit();

    if (parsed.value != .object) return;
    const obj = parsed.value.object;
    const message_entry = obj.get("MESSAGE") orelse return;
    if (message_entry != .string) return;
    const message = message_entry.string;

    const qname = extractQname(message) orelse return;
    const qtype = extractQtype(message) orelse "A";
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
    const suffix = ".service";
    if (std.mem.endsWith(u8, unit_entry.string, suffix)) {
        return unit_entry.string[0 .. unit_entry.string.len - suffix.len];
    }
    return unit_entry.string;
}

fn looksLikeIp(text: []const u8) bool {
    if (text.len == 0) return false;
    var has_digit = false;
    var has_dot_or_colon = false;
    for (text) |c| {
        if (std.ascii.isDigit(c)) has_digit = true;
        if (c == '.' or c == ':') has_dot_or_colon = true;
        if (!std.ascii.isAlphanumeric(c) and c != '.' and c != ':') return false;
    }
    return has_digit and has_dot_or_colon;
}

fn appendHostsEntries(
    alloc: std.mem.Allocator,
    raw: []const u8,
    out: *std.array_list.Managed([]u8),
) !void {
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line_raw| {
        const hash = std.mem.indexOfScalar(u8, line_raw, '#') orelse line_raw.len;
        const line = std.mem.trim(u8, line_raw[0..hash], " \t\r");
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        const address = fields.next() orelse continue;
        if (!looksLikeIp(address)) continue;
        const qtype = if (std.mem.indexOfScalar(u8, address, ':') != null) "AAAA" else "A";

        while (fields.next()) |qname| {
            if (qname.len == 0 or qname.len > 253) continue;

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
