const std = @import("std");
const builtin = @import("builtin");

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

    pub fn init(alloc: std.mem.Allocator) Collector {
        return .{ .allocator = alloc };
    }

    /// Returns one JSON payload per detected DNS query since the last call.
    /// Caller owns the outer slice and each inner payload.
    pub fn collectQueries(self: *Collector) ![][]u8 {
        var payloads = std.ArrayList([]u8).init(self.allocator);
        errdefer {
            for (payloads.items) |p| self.allocator.free(p);
            payloads.deinit();
        }

        switch (builtin.os.tag) {
            .linux => try self.collectLinux(&payloads),
            else => {}, // Win/macOS DNS capture needs ETW / NetworkExtension; not in this collector.
        }

        self.last_run_unix = std.time.timestamp();
        return payloads.toOwnedSlice();
    }

    fn collectLinux(self: *Collector, payloads: *std.ArrayList([]u8)) !void {
        const since_arg = if (self.last_run_unix == 0)
            try self.allocator.dupe(u8, "60 seconds ago")
        else
            try std.fmt.allocPrint(self.allocator, "@{d}", .{self.last_run_unix});
        defer self.allocator.free(since_arg);

        var child = std.process.Child.init(
            &.{
                "journalctl",
                "-u",
                "systemd-resolved",
                "--since",
                since_arg,
                "--output=json",
                "--no-pager",
                "--quiet",
            },
            self.allocator,
        );
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;

        child.spawn() catch return; // journalctl missing or not permitted; silently skip.
        defer _ = child.kill() catch {};

        const stdout = child.stdout orelse return;
        const output = stdout.reader().readAllAlloc(self.allocator, 4 * 1024 * 1024) catch return;
        defer self.allocator.free(output);
        _ = child.wait() catch {};

        var lines = std.mem.splitScalar(u8, output, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            try parseLine(self.allocator, line, payloads);
        }
    }
};

/// Parse one journal JSON line. We tolerate journal entries that aren't DNS
/// queries: we look for an `MESSAGE` field containing a hostname being looked
/// up. systemd-resolved at debug level emits messages like:
///   "Looking up RR for example.com IN A"
///   "Got DNS reply ... example.com IN A -> 93.184.216.34"
fn parseLine(alloc: std.mem.Allocator, line: []const u8, out: *std.ArrayList([]u8)) !void {
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
    const ts_secs: i64 = blk: {
        const ts_entry = obj.get("__REALTIME_TIMESTAMP") orelse break :blk std.time.timestamp();
        if (ts_entry != .string) break :blk std.time.timestamp();
        const micros = std.fmt.parseInt(i64, ts_entry.string, 10) catch break :blk std.time.timestamp();
        break :blk @divTrunc(micros, 1_000_000);
    };
    _ = ts_secs; // ts surfaces on the event envelope, not the payload, so we drop it here.

    var payload = std.ArrayList(u8).init(alloc);
    errdefer payload.deinit();
    var w = payload.writer();

    try w.writeAll("{\"qname\":");
    try std.json.stringify(qname, .{}, w);
    try w.writeAll(",\"qtype\":");
    try std.json.stringify(qtype, .{}, w);
    try w.writeAll(",\"response_ips\":");
    if (reply_ip) |ip| {
        try w.writeAll("[");
        try std.json.stringify(ip, .{}, w);
        try w.writeAll("]");
    } else {
        try w.writeAll("[]");
    }
    try w.writeAll(",\"resolver\":\"systemd-resolved\"}");

    try out.append(try payload.toOwnedSlice());
}

fn extractQname(message: []const u8) ?[]const u8 {
    // Common shapes:
    //   "Looking up RR for example.com IN A"
    //   "Got DNS reply for example.com IN A: 93.184.216.34"
    //   "Resolved example.com -> 93.184.216.34"
    const triggers = [_][]const u8{ "Looking up RR for ", "Got DNS reply for ", "Resolved " };
    inline for (triggers) |trigger| {
        if (std.mem.indexOf(u8, message, trigger)) |idx| {
            const start = idx + trigger.len;
            const rest = message[start..];
            const end = std.mem.indexOfAny(u8, rest, " \t:->") orelse rest.len;
            const candidate = std.mem.trim(u8, rest[0..end], " \t.,");
            if (candidate.len > 0 and candidate.len <= 253) return candidate;
        }
    }
    return null;
}

fn extractQtype(message: []const u8) ?[]const u8 {
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
    const markers = [_][]const u8{ "-> ", ": " };
    for (markers) |marker| {
        if (std.mem.lastIndexOf(u8, message, marker)) |idx| {
            const start = idx + marker.len;
            const tail = std.mem.trim(u8, message[start..], " \t.,;");
            if (looksLikeIp(tail)) return tail;
        }
    }
    return null;
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

test "qname extraction" {
    const a = extractQname("Looking up RR for example.com IN A");
    try std.testing.expect(a != null);
    try std.testing.expectEqualStrings("example.com", a.?);
}
