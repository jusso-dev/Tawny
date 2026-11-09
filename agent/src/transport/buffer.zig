const std = @import("std");
const builtin = @import("builtin");
const iox = @import("../io_compat.zig");

const spool_magic = "TWNYSP01";
/// EVT1 records (older agents) carry no sequence; EVT2 records do.
const record_magic_v1 = "EVT1";
const record_magic = "EVT2";
const spool_header_len: usize = 24;
const record_header_len: usize = 12;
/// id(16) + occurred_at(8) + type_len(2)
const v1_fixed_body: usize = 26;
/// id(16) + occurred_at(8) + sequence(8) + type_len(2)
const v2_fixed_body: usize = 34;
const max_record_bytes: usize = 768 * 1024;

pub const Event = struct {
    client_event_id: [16]u8 = @splat(0),
    /// Durable per-agent sequence. Assigned at push, stored in the record and
    /// kept across restarts (see `Buffer.next_sequence`).
    sequence: u64 = 0,
    event_type: []const u8,
    occurred_at: i64,
    /// Caller-owned event type and JSON payload. Buffer takes ownership via dupe.
    payload: []const u8,
    spool_end: u64 = 0,
};

pub const Buffer = struct {
    allocator: std.mem.Allocator,
    capacity: usize,
    max_spool_bytes: u64,
    spool_path: []u8,
    list: std.array_list.Managed(Event),
    pending_count: usize = 0,
    acknowledged_offset: u64 = spool_header_len,
    next_load_offset: u64 = spool_header_len,
    /// Next sequence to hand out. Restored at replay from the `.seq` sidecar
    /// (written before every acknowledgement) and from the sequences of the
    /// records still in the spool, so it never goes back after a restart.
    next_sequence: u64 = 1,
    /// Logical end of spool file. Tracked in memory because Windows denies
    /// `File.stat` on handles opened for write (AccessDenied in Io.Threaded).
    spool_size: u64 = spool_header_len,

    pub fn init(
        alloc: std.mem.Allocator,
        capacity: usize,
        spool_path: []const u8,
        max_spool_bytes: u64,
    ) !Buffer {
        if (max_spool_bytes < spool_header_len + record_header_len) {
            return error.InvalidSpoolLimit;
        }
        return .{
            .allocator = alloc,
            .capacity = @max(capacity, 1),
            .max_spool_bytes = max_spool_bytes,
            .spool_path = try alloc.dupe(u8, spool_path),
            .list = std.array_list.Managed(Event).init(alloc),
        };
    }

    pub fn deinit(self: *Buffer) void {
        self.clear();
        self.list.deinit();
        self.allocator.free(self.spool_path);
    }

    /// Number currently ready for transport. Disk may contain more records.
    pub fn len(self: *const Buffer) usize {
        return self.list.items.len;
    }

    pub fn totalLen(self: *const Buffer) usize {
        return self.pending_count;
    }

    pub fn items(self: *const Buffer) []const Event {
        return self.list.items;
    }

    /// Write-ahead append. Successful return means event is synced to disk.
    pub fn push(self: *Buffer, ev: Event) !void {
        try validateEventShape(ev.event_type, ev.payload);
        if (!try std.json.validate(self.allocator, ev.payload)) return error.InvalidEventPayload;
        var id = ev.client_event_id;
        if (isZeroId(id)) {
            try std.Io.randomSecure(iox.current(), &id);
            id[6] = (id[6] & 0x0f) | 0x40;
            id[8] = (id[8] & 0x3f) | 0x80;
        }

        const seq = self.next_sequence;
        const record = try encodeRecord(self.allocator, id, ev.occurred_at, seq, ev.event_type, ev.payload);
        defer self.allocator.free(record);

        try self.ensureSpool();
        try self.compactIfUseful(record.len);

        const offset = self.spool_size;
        if (offset + record.len > self.max_spool_bytes) return error.SpoolFull;

        const io = iox.current();
        var file = try std.Io.Dir.cwd().createFile(io, self.spool_path, .{ .truncate = false });
        defer file.close(io);
        try file.writePositionalAll(io, record, offset);
        try file.sync(io);
        self.spool_size = offset + record.len;
        self.next_sequence = seq + 1;

        self.pending_count += 1;
        if (self.list.items.len < self.capacity) {
            try self.appendOwned(id, seq, ev.occurred_at, ev.event_type, ev.payload, self.spool_size);
            self.next_load_offset = self.spool_size;
        }
    }

    pub fn clear(self: *Buffer) void {
        for (self.list.items) |ev| {
            self.allocator.free(ev.event_type);
            self.allocator.free(ev.payload);
        }
        self.list.clearRetainingCapacity();
    }

    /// Memory-only helper retained for tests. Transport must use acknowledgeFirst.
    pub fn discardFirst(self: *Buffer, count: usize) void {
        const discard_count = @min(count, self.list.items.len);
        for (self.list.items[0..discard_count]) |ev| {
            self.allocator.free(ev.event_type);
            self.allocator.free(ev.payload);
        }

        const remaining = self.list.items.len - discard_count;
        std.mem.copyForwards(
            Event,
            self.list.items[0..remaining],
            self.list.items[discard_count..],
        );
        self.list.items.len = remaining;
    }

    /// Persist acknowledgement before releasing memory. A crash can resend, but
    /// cannot forget, records; client_event_id lets backend deduplicate resend.
    pub fn acknowledgeFirst(self: *Buffer, count: usize) !void {
        const acknowledged = @min(count, self.list.items.len);
        if (acknowledged == 0) return;

        const next_ack = self.list.items[acknowledged - 1].spool_end;
        // Sequence high-water mark first: once the ack moves, replay no longer
        // sees the acknowledged records and their sequences.
        try self.writeSequenceMark();
        try self.writeAcknowledgedOffset(next_ack);
        self.acknowledged_offset = next_ack;
        self.pending_count -= @min(acknowledged, self.pending_count);
        self.discardFirst(acknowledged);
        try self.loadMore();
    }

    /// Load pending records without deleting spool. Corrupt/truncated records
    /// are skipped; valid records after corruption remain recoverable.
    pub fn replay(self: *Buffer) !void {
        self.clear();
        self.pending_count = 0;
        self.acknowledged_offset = spool_header_len;
        self.next_load_offset = spool_header_len;
        self.spool_size = spool_header_len;
        self.next_sequence = @max(self.next_sequence, self.readSequenceMark());

        const io = iox.current();
        const file = std.Io.Dir.cwd().openFile(io, self.spool_path, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                try self.ensureSpool();
                return;
            },
            else => return err,
        };
        defer file.close(io);

        // Read-only open: File.stat is reliable on Windows here (write handles are not).
        const stat = try file.stat(io);
        if (stat.size > self.max_spool_bytes) return error.SpoolTooLarge;
        const raw = try iox.readToEndAlloc(file, self.allocator, @intCast(self.max_spool_bytes));
        defer self.allocator.free(raw);
        self.spool_size = raw.len;

        if (raw.len < spool_header_len or !std.mem.eql(u8, raw[0..spool_magic.len], spool_magic)) {
            try self.convertLegacy(raw);
            return self.replay();
        }

        const stored_ack = std.mem.readInt(u64, raw[8..16], .little);
        const stored_inverse = std.mem.readInt(u64, raw[16..24], .little);
        const ack_valid = stored_ack ^ stored_inverse == std.math.maxInt(u64) and
            stored_ack >= spool_header_len and stored_ack <= raw.len;
        self.acknowledged_offset = if (ack_valid) stored_ack else spool_header_len;
        self.next_load_offset = self.acknowledged_offset;

        // Sequences stored in the records win; older EVT1 records get fresh ones.
        var cursor: usize = @intCast(self.acknowledged_offset);
        while (nextRecord(raw, &cursor)) |record| {
            if (record.sequence) |s| self.next_sequence = @max(self.next_sequence, s + 1);
        }
        cursor = @intCast(self.acknowledged_offset);
        while (nextRecord(raw, &cursor)) |record| {
            if (!try std.json.validate(self.allocator, record.payload)) continue;
            self.pending_count += 1;
            if (self.list.items.len < self.capacity) {
                const seq = record.sequence orelse self.takeSequence();
                try self.appendOwned(
                    record.id,
                    seq,
                    record.occurred_at,
                    record.event_type,
                    record.payload,
                    record.end,
                );
                self.next_load_offset = record.end;
            }
        }
    }

    fn takeSequence(self: *Buffer) u64 {
        const seq = self.next_sequence;
        self.next_sequence += 1;
        return seq;
    }

    fn sequencePath(self: *Buffer) ![]u8 {
        return self.allocator.print("{s}.seq", .{self.spool_path});
    }

    /// `<spool>.seq`: next_sequence as u64 LE followed by its complement.
    fn writeSequenceMark(self: *Buffer) !void {
        const path = try self.sequencePath();
        defer self.allocator.free(path);
        const io = iox.current();
        var file = try std.Io.Dir.cwd().createFile(io, path, .{
            .truncate = false,
            .permissions = if (builtin.target.os.tag == .windows) .default_file else @fromBackingInt(@intCast(0o600)),
        });
        defer file.close(io);
        var encoded: [16]u8 = undefined;
        std.mem.writeInt(u64, encoded[0..8], self.next_sequence, .little);
        std.mem.writeInt(u64, encoded[8..16], ~self.next_sequence, .little);
        try file.writePositionalAll(io, &encoded, 0);
        try file.sync(io);
    }

    fn readSequenceMark(self: *Buffer) u64 {
        const path = self.sequencePath() catch return 1;
        defer self.allocator.free(path);
        const io = iox.current();
        var file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return 1;
        defer file.close(io);
        var encoded: [16]u8 = undefined;
        const n = file.readPositionalAll(io, &encoded, 0) catch return 1;
        if (n != encoded.len) return 1;
        const value = std.mem.readInt(u64, encoded[0..8], .little);
        if (value ^ std.mem.readInt(u64, encoded[8..16], .little) != std.math.maxInt(u64)) return 1;
        return @max(value, 1);
    }

    fn loadMore(self: *Buffer) !void {
        if (self.list.items.len >= self.capacity or self.pending_count == self.list.items.len) return;

        const io = iox.current();
        const file = try std.Io.Dir.cwd().openFile(io, self.spool_path, .{});
        defer file.close(io);
        const raw = try iox.readToEndAlloc(file, self.allocator, @intCast(self.max_spool_bytes));
        defer self.allocator.free(raw);

        var cursor: usize = @intCast(@min(self.next_load_offset, raw.len));
        while (self.list.items.len < self.capacity) {
            const record = nextRecord(raw, &cursor) orelse break;
            if (!try std.json.validate(self.allocator, record.payload)) continue;
            const seq = record.sequence orelse self.takeSequence();
            try self.appendOwned(
                record.id,
                seq,
                record.occurred_at,
                record.event_type,
                record.payload,
                record.end,
            );
            self.next_load_offset = record.end;
        }
    }

    fn appendOwned(
        self: *Buffer,
        id: [16]u8,
        sequence: u64,
        occurred_at: i64,
        event_type: []const u8,
        payload: []const u8,
        spool_end: u64,
    ) !void {
        const owned_event_type = try self.allocator.dupe(u8, event_type);
        errdefer self.allocator.free(owned_event_type);
        const owned_payload = try self.allocator.dupe(u8, payload);
        errdefer self.allocator.free(owned_payload);
        try self.list.append(.{
            .client_event_id = id,
            .sequence = sequence,
            .event_type = owned_event_type,
            .occurred_at = occurred_at,
            .payload = owned_payload,
            .spool_end = spool_end,
        });
    }

    fn ensureSpool(self: *Buffer) !void {
        const io = iox.current();
        const dir = std.fs.path.dirname(self.spool_path) orelse ".";
        try std.Io.Dir.cwd().createDirPath(io, dir);

        const existing = std.Io.Dir.cwd().openFile(io, self.spool_path, .{}) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        if (existing) |file| {
            file.close(io);
            return;
        }

        var file = try std.Io.Dir.cwd().createFile(io, self.spool_path, .{
            .truncate = true,
            .permissions = if (builtin.target.os.tag == .windows) .default_file else @fromBackingInt(@intCast(0o600)),
        });
        defer file.close(io);
        const header = makeHeader(spool_header_len);
        try file.writePositionalAll(io, &header, 0);
        try file.sync(io);
        self.spool_size = spool_header_len;
        try syncParentDirectory(self.spool_path);
    }

    fn writeAcknowledgedOffset(self: *Buffer, offset: u64) !void {
        const io = iox.current();
        var file = try std.Io.Dir.cwd().createFile(io, self.spool_path, .{ .truncate = false });
        defer file.close(io);
        var encoded: [16]u8 = undefined;
        std.mem.writeInt(u64, encoded[0..8], offset, .little);
        std.mem.writeInt(u64, encoded[8..16], ~offset, .little);
        try file.writePositionalAll(io, &encoded, 8);
        try file.sync(io);
    }

    fn compactIfUseful(self: *Buffer, incoming_len: usize) !void {
        const io = iox.current();
        const size = self.spool_size;
        const reclaimable = self.acknowledged_offset - spool_header_len;
        if (reclaimable == 0) return;
        if (size + incoming_len <= self.max_spool_bytes and reclaimable < self.max_spool_bytes / 4) return;

        const raw = raw: {
            const file = try std.Io.Dir.cwd().openFile(io, self.spool_path, .{});
            defer file.close(io);
            break :raw try iox.readToEndAlloc(file, self.allocator, @intCast(self.max_spool_bytes));
        };
        defer self.allocator.free(raw);
        if (self.acknowledged_offset > raw.len) return error.CorruptSpoolHeader;

        const kept = raw[@intCast(self.acknowledged_offset)..];
        const new_size = spool_header_len + kept.len;
        const tmp_path = try self.allocator.print("{s}.tmp", .{self.spool_path});
        defer self.allocator.free(tmp_path);
        {
            var tmp = try std.Io.Dir.cwd().createFile(io, tmp_path, .{
                .truncate = true,
                .permissions = if (builtin.target.os.tag == .windows) .default_file else @fromBackingInt(@intCast(0o600)),
            });
            defer tmp.close(io);
            const header = makeHeader(spool_header_len);
            try tmp.writePositionalAll(io, &header, 0);
            try tmp.writePositionalAll(io, kept, spool_header_len);
            try tmp.sync(io);
        }
        try std.Io.Dir.cwd().rename(tmp_path, std.Io.Dir.cwd(), self.spool_path, io);
        try syncParentDirectory(self.spool_path);

        for (self.list.items) |*event| event.spool_end -= reclaimable;
        self.next_load_offset -= reclaimable;
        self.acknowledged_offset = spool_header_len;
        self.spool_size = new_size;
    }

    fn convertLegacy(self: *Buffer, raw: []const u8) !void {
        self.clear();
        var lines = std.mem.splitScalar(u8, raw, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            var fields = std.mem.splitScalar(u8, line, '\t');
            const event_type = fields.next() orelse continue;
            const occurred_raw = fields.next() orelse continue;
            const payload = fields.rest();
            if (event_type.len == 0 or payload.len == 0) continue;
            const occurred_at = std.fmt.parseInt(i64, occurred_raw, 10) catch continue;
            validateEventShape(event_type, payload) catch continue;
            if (!try std.json.validate(self.allocator, payload)) continue;
            var id: [16]u8 = undefined;
            try std.Io.randomSecure(iox.current(), &id);
            id[6] = (id[6] & 0x0f) | 0x40;
            id[8] = (id[8] & 0x3f) | 0x80;
            try self.appendOwned(id, self.takeSequence(), occurred_at, event_type, payload, 0);
        }

        const tmp_path = try self.allocator.print("{s}.tmp", .{self.spool_path});
        defer self.allocator.free(tmp_path);
        const io = iox.current();
        {
            var tmp = try std.Io.Dir.cwd().createFile(io, tmp_path, .{
                .truncate = true,
                .permissions = if (builtin.target.os.tag == .windows) .default_file else @fromBackingInt(@intCast(0o600)),
            });
            defer tmp.close(io);
            const header = makeHeader(spool_header_len);
            try tmp.writePositionalAll(io, &header, 0);
            var offset: u64 = spool_header_len;
            for (self.list.items) |event| {
                const record = try encodeRecord(
                    self.allocator,
                    event.client_event_id,
                    event.occurred_at,
                    event.sequence,
                    event.event_type,
                    event.payload,
                );
                defer self.allocator.free(record);
                if (offset + record.len > self.max_spool_bytes) return error.SpoolFull;
                try tmp.writePositionalAll(io, record, offset);
                offset += record.len;
            }
            try tmp.sync(io);
            self.spool_size = offset;
        }
        try std.Io.Dir.cwd().rename(tmp_path, std.Io.Dir.cwd(), self.spool_path, io);
        try syncParentDirectory(self.spool_path);
        self.clear();
    }
};

const ParsedRecord = struct {
    id: [16]u8,
    occurred_at: i64,
    /// Null for EVT1 records written by older agents.
    sequence: ?u64,
    event_type: []const u8,
    payload: []const u8,
    end: u64,
};

fn nextRecord(raw: []const u8, cursor: *usize) ?ParsedRecord {
    while (cursor.* + record_header_len <= raw.len) {
        const magic = raw[cursor.*..][0..record_magic.len];
        const is_v2 = std.mem.eql(u8, magic, record_magic);
        if (!is_v2 and !std.mem.eql(u8, magic, record_magic_v1)) {
            cursor.* += 1;
            continue;
        }
        const fixed: usize = if (is_v2) v2_fixed_body else v1_fixed_body;

        const body_len = std.mem.readInt(u32, raw[cursor.* + 4 ..][0..4], .little);
        if (body_len < fixed or body_len > max_record_bytes) {
            cursor.* += 1;
            continue;
        }
        const end = cursor.* + record_header_len + body_len;
        if (end > raw.len) {
            cursor.* += 1;
            continue;
        }
        const expected_crc = std.mem.readInt(u32, raw[cursor.* + 8 ..][0..4], .little);
        const body = raw[cursor.* + record_header_len .. end];
        if (std.hash.Crc32.hash(body) != expected_crc) {
            cursor.* += 1;
            continue;
        }

        const type_len = std.mem.readInt(u16, body[fixed - 2 ..][0..2], .little);
        if (fixed + type_len > body.len) {
            cursor.* += 1;
            continue;
        }
        const parsed = ParsedRecord{
            .id = body[0..16].*,
            .occurred_at = std.mem.readInt(i64, body[16..24], .little),
            .sequence = if (is_v2) std.mem.readInt(u64, body[24..32], .little) else null,
            .event_type = body[fixed .. fixed + type_len],
            .payload = body[fixed + type_len ..],
            .end = @intCast(end),
        };
        cursor.* = end;
        return parsed;
    }
    cursor.* = raw.len;
    return null;
}

fn encodeRecord(
    alloc: std.mem.Allocator,
    id: [16]u8,
    occurred_at: i64,
    sequence: u64,
    event_type: []const u8,
    payload: []const u8,
) ![]u8 {
    try validateEventShape(event_type, payload);
    const body_len = v2_fixed_body + event_type.len + payload.len;
    const record = try alloc.alloc(u8, record_header_len + body_len);
    errdefer alloc.free(record);
    @memcpy(record[0..4], record_magic);
    std.mem.writeInt(u32, record[4..8], @intCast(body_len), .little);
    @memcpy(record[12..28], &id);
    std.mem.writeInt(i64, record[28..36], occurred_at, .little);
    std.mem.writeInt(u64, record[36..44], sequence, .little);
    std.mem.writeInt(u16, record[44..46], @intCast(event_type.len), .little);
    @memcpy(record[46 .. 46 + event_type.len], event_type);
    @memcpy(record[46 + event_type.len ..], payload);
    std.mem.writeInt(u32, record[8..12], std.hash.Crc32.hash(record[12..]), .little);
    return record;
}

fn validateEventShape(event_type: []const u8, payload: []const u8) !void {
    if (event_type.len == 0 or event_type.len > 64) return error.InvalidEventType;
    for (event_type) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '-' or byte == '.')) {
            return error.InvalidEventType;
        }
    }
    if (v2_fixed_body + event_type.len + payload.len > max_record_bytes) return error.EventTooLarge;
}

fn makeHeader(acknowledged_offset: u64) [spool_header_len]u8 {
    var header: [spool_header_len]u8 = undefined;
    @memcpy(header[0..8], spool_magic);
    std.mem.writeInt(u64, header[8..16], acknowledged_offset, .little);
    std.mem.writeInt(u64, header[16..24], ~acknowledged_offset, .little);
    return header;
}

fn isZeroId(id: [16]u8) bool {
    for (id) |byte| if (byte != 0) return false;
    return true;
}

fn syncParentDirectory(path: []const u8) !void {
    if (builtin.target.os.tag != .linux) return;
    const io = iox.current();
    const parent_path = std.fs.path.dirname(path) orelse ".";
    // `openDir` otherwise uses Linux O_PATH, which cannot be passed to fsync.
    const dir = try std.Io.Dir.cwd().openDir(io, parent_path, .{ .iterate = true });
    defer dir.close(io);
    const file = std.Io.File{
        .handle = dir.handle,
        .flags = .{ .nonblocking = false },
    };
    try file.sync(io);
}

test "buffer durably replays and acknowledges" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const spill_path = try std.fs.path.join(
        std.testing.allocator,
        &.{ ".zig-cache", "tmp", &tmp.sub_path, "events.spool" },
    );
    defer std.testing.allocator.free(spill_path);

    var retained_id: [16]u8 = undefined;
    {
        var b = try Buffer.init(std.testing.allocator, 2, spill_path, 1024 * 1024);
        defer b.deinit();
        try b.replay();
        try b.push(.{ .event_type = "x", .occurred_at = 1, .payload = "1" });
        try b.push(.{ .event_type = "x", .occurred_at = 2, .payload = "2" });
        try b.push(.{ .event_type = "x", .occurred_at = 3, .payload = "3" });
        try std.testing.expectEqual(@as(usize, 2), b.len());
        try std.testing.expectEqual(@as(usize, 3), b.totalLen());
        try b.acknowledgeFirst(2);
        try std.testing.expectEqual(@as(usize, 1), b.len());
        try std.testing.expectEqual(@as(i64, 3), b.items()[0].occurred_at);
        retained_id = b.items()[0].client_event_id;
    }

    var replayed = try Buffer.init(std.testing.allocator, 2, spill_path, 1024 * 1024);
    defer replayed.deinit();
    try replayed.replay();
    try std.testing.expectEqual(@as(usize, 1), replayed.totalLen());
    try std.testing.expectEqual(@as(i64, 3), replayed.items()[0].occurred_at);
    try std.testing.expectEqualSlices(u8, &retained_id, &replayed.items()[0].client_event_id);
}

test "buffer recovers valid records around corruption" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const spill_path = try std.fs.path.join(
        std.testing.allocator,
        &.{ ".zig-cache", "tmp", &tmp.sub_path, "corrupt.spool" },
    );
    defer std.testing.allocator.free(spill_path);

    var b = try Buffer.init(std.testing.allocator, 8, spill_path, 1024 * 1024);
    defer b.deinit();
    try b.replay();
    try b.push(.{ .event_type = "first", .occurred_at = 1, .payload = "{}" });

    const io = iox.current();
    {
        // Append garbage at end without File.stat on a write handle (Windows
        // returns AccessDenied). Size is known from the buffer after push.
        const offset = b.spool_size;
        var file = try std.Io.Dir.cwd().createFile(io, spill_path, .{ .truncate = false });
        defer file.close(io);
        try file.writePositionalAll(io, "bad-record", offset);
        try file.sync(io);
        b.spool_size = offset + "bad-record".len;
    }
    try b.push(.{ .event_type = "second", .occurred_at = 2, .payload = "{}" });

    var replayed = try Buffer.init(std.testing.allocator, 8, spill_path, 1024 * 1024);
    defer replayed.deinit();
    try replayed.replay();
    try std.testing.expectEqual(@as(usize, 2), replayed.totalLen());
    try std.testing.expectEqualStrings("first", replayed.items()[0].event_type);
    try std.testing.expectEqualStrings("second", replayed.items()[1].event_type);
}

test "buffer enforces spool bound without dropping queued events" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const spill_path = try std.fs.path.join(
        std.testing.allocator,
        &.{ ".zig-cache", "tmp", &tmp.sub_path, "bounded.spool" },
    );
    defer std.testing.allocator.free(spill_path);

    var b = try Buffer.init(std.testing.allocator, 8, spill_path, 96);
    defer b.deinit();
    try b.replay();
    try b.push(.{ .event_type = "x", .occurred_at = 1, .payload = "{}" });
    try std.testing.expectError(
        error.SpoolFull,
        b.push(.{ .event_type = "x", .occurred_at = 2, .payload = "{}" }),
    );
    try std.testing.expectEqual(@as(usize, 1), b.totalLen());
    try b.acknowledgeFirst(1);
    try b.push(.{ .event_type = "x", .occurred_at = 3, .payload = "{}" });
    try std.testing.expectEqual(@as(usize, 1), b.totalLen());
}

test "buffer rejects event too large for backend ingest limit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const spill_path = try std.fs.path.join(
        std.testing.allocator,
        &.{ ".zig-cache", "tmp", &tmp.sub_path, "oversized.spool" },
    );
    defer std.testing.allocator.free(spill_path);
    const payload = try std.testing.allocator.alloc(u8, max_record_bytes);
    defer std.testing.allocator.free(payload);
    @memset(payload, 'a');

    var b = try Buffer.init(std.testing.allocator, 8, spill_path, 2 * 1024 * 1024);
    defer b.deinit();
    try b.replay();
    try std.testing.expectError(
        error.EventTooLarge,
        b.push(.{ .event_type = "x", .occurred_at = 1, .payload = payload }),
    );
    try std.testing.expectEqual(@as(usize, 0), b.totalLen());
}

test "legacy spool converts and ignores malformed lines" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const spill_path = try std.fs.path.join(
        std.testing.allocator,
        &.{ ".zig-cache", "tmp", &tmp.sub_path, "legacy.spool" },
    );
    defer std.testing.allocator.free(spill_path);

    const io = iox.current();
    {
        var file = try std.Io.Dir.cwd().createFile(io, spill_path, .{ .truncate = true });
        defer file.close(io);
        try file.writePositionalAll(io, "x\t1\t{}\nbad\tnope\t{}\ny\t2\t{\"a\":1}\n", 0);
        try file.sync(io);
    }

    var b = try Buffer.init(std.testing.allocator, 8, spill_path, 1024 * 1024);
    defer b.deinit();
    try b.replay();
    try std.testing.expectEqual(@as(usize, 2), b.totalLen());
    try std.testing.expect(!isZeroId(b.items()[0].client_event_id));
}

test "sequence survives a restart, including after everything is acknowledged" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const spill_path = try std.fs.path.join(
        std.testing.allocator,
        &.{ ".zig-cache", "tmp", &tmp.sub_path, "seq.spool" },
    );
    defer std.testing.allocator.free(spill_path);

    {
        var b = try Buffer.init(std.testing.allocator, 8, spill_path, 1024 * 1024);
        defer b.deinit();
        try b.replay();
        try b.push(.{ .event_type = "x", .occurred_at = 1, .payload = "{}" });
        try b.push(.{ .event_type = "x", .occurred_at = 2, .payload = "{}" });
        try b.push(.{ .event_type = "x", .occurred_at = 3, .payload = "{}" });
        try std.testing.expectEqual(@as(u64, 1), b.items()[0].sequence);
        try std.testing.expectEqual(@as(u64, 3), b.items()[2].sequence);
        try b.acknowledgeFirst(1);
    }
    // Restart 1: unacknowledged records keep the sequence they were pushed with.
    {
        var b = try Buffer.init(std.testing.allocator, 8, spill_path, 1024 * 1024);
        defer b.deinit();
        try b.replay();
        try std.testing.expectEqual(@as(usize, 2), b.len());
        try std.testing.expectEqual(@as(u64, 2), b.items()[0].sequence);
        try std.testing.expectEqual(@as(u64, 3), b.items()[1].sequence);
        try b.push(.{ .event_type = "x", .occurred_at = 4, .payload = "{}" });
        try std.testing.expectEqual(@as(u64, 4), b.items()[2].sequence);
        try b.acknowledgeFirst(3);
        try std.testing.expectEqual(@as(usize, 0), b.totalLen());
    }
    // Restart 2: the spool is empty, the sidecar still moves the sequence on.
    {
        var b = try Buffer.init(std.testing.allocator, 8, spill_path, 1024 * 1024);
        defer b.deinit();
        try b.replay();
        try std.testing.expectEqual(@as(usize, 0), b.totalLen());
        try b.push(.{ .event_type = "x", .occurred_at = 5, .payload = "{}" });
        try std.testing.expectEqual(@as(u64, 5), b.items()[0].sequence);
    }
}

test "EVT1 records from an older agent still replay" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const spill_path = try std.fs.path.join(
        std.testing.allocator,
        &.{ ".zig-cache", "tmp", &tmp.sub_path, "v1.spool" },
    );
    defer std.testing.allocator.free(spill_path);
    const io = iox.current();
    {
        // Header plus one EVT1 record: id, occurred_at, type_len, type, payload.
        const event_type = "system_info";
        const payload = "{}";
        var rec: [record_header_len + v1_fixed_body + event_type.len + payload.len]u8 = undefined;
        @memcpy(rec[0..4], record_magic_v1);
        std.mem.writeInt(u32, rec[4..8], v1_fixed_body + event_type.len + payload.len, .little);
        @memset(rec[12..28], 0x11);
        std.mem.writeInt(i64, rec[28..36], 7, .little);
        std.mem.writeInt(u16, rec[36..38], event_type.len, .little);
        @memcpy(rec[38 .. 38 + event_type.len], event_type);
        @memcpy(rec[38 + event_type.len ..], payload);
        std.mem.writeInt(u32, rec[8..12], std.hash.Crc32.hash(rec[12..]), .little);
        var file = try std.Io.Dir.cwd().createFile(io, spill_path, .{ .truncate = true });
        defer file.close(io);
        const header = makeHeader(spool_header_len);
        try file.writePositionalAll(io, &header, 0);
        try file.writePositionalAll(io, &rec, spool_header_len);
        try file.sync(io);
    }
    var b = try Buffer.init(std.testing.allocator, 8, spill_path, 1024 * 1024);
    defer b.deinit();
    try b.replay();
    try std.testing.expectEqual(@as(usize, 1), b.len());
    try std.testing.expectEqualStrings("system_info", b.items()[0].event_type);
    try std.testing.expectEqual(@as(i64, 7), b.items()[0].occurred_at);
    try std.testing.expectEqual(@as(u64, 1), b.items()[0].sequence);
    try b.push(.{ .event_type = "x", .occurred_at = 8, .payload = "{}" });
    try std.testing.expectEqual(@as(u64, 2), b.items()[1].sequence);
}
