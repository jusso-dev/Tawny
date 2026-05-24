const std = @import("std");
const iox = @import("../io_compat.zig");

const Sha1Digest = [20]u8;
const Sha256Digest = [32]u8;

const WatchedFile = struct {
    path: []u8,
    sha1: Sha1Digest,
    sha256: Sha256Digest,
    size_bytes: u64,
    exists: bool,
};

pub const Watcher = struct {
    allocator: std.mem.Allocator,
    files: std.array_list.Managed(WatchedFile),

    pub fn init(alloc: std.mem.Allocator, paths: []const []const u8) !Watcher {
        var watcher = Watcher{
            .allocator = alloc,
            .files = std.array_list.Managed(WatchedFile).init(alloc),
        };
        errdefer watcher.deinit();

        for (paths) |path| {
            const snapshot = snapshotFile(path) catch Snapshot{
                .sha1 = std.mem.zeroes(Sha1Digest),
                .sha256 = std.mem.zeroes(Sha256Digest),
                .size_bytes = 0,
                .exists = false,
            };
            try watcher.files.append(.{
                .path = try alloc.dupe(u8, path),
                .sha1 = snapshot.sha1,
                .sha256 = snapshot.sha256,
                .size_bytes = snapshot.size_bytes,
                .exists = snapshot.exists,
            });
        }

        return watcher;
    }

    pub fn deinit(self: *Watcher) void {
        for (self.files.items) |file| self.allocator.free(file.path);
        self.files.deinit();
    }

    pub fn collectChanges(self: *Watcher) ![][]u8 {
        var payloads = std.array_list.Managed([]u8).init(self.allocator);
        errdefer {
            for (payloads.items) |payload| self.allocator.free(payload);
            payloads.deinit();
        }

        for (self.files.items) |*file| {
            const next = snapshotFile(file.path) catch Snapshot{
                .sha1 = std.mem.zeroes(Sha1Digest),
                .sha256 = std.mem.zeroes(Sha256Digest),
                .size_bytes = 0,
                .exists = false,
            };

            const changed = file.exists != next.exists or
                !std.mem.eql(u8, &file.sha1, &next.sha1) or
                !std.mem.eql(u8, &file.sha256, &next.sha256) or
                file.size_bytes != next.size_bytes;
            if (!changed) continue;

            const payload = try formatChange(
                self.allocator,
                file.path,
                file.sha1,
                next.sha1,
                file.sha256,
                next.sha256,
                next.size_bytes,
                next.exists,
            );
            try payloads.append(payload);

            file.sha1 = next.sha1;
            file.sha256 = next.sha256;
            file.size_bytes = next.size_bytes;
            file.exists = next.exists;
        }

        return payloads.toOwnedSlice();
    }
};

const Snapshot = struct {
    sha1: Sha1Digest,
    sha256: Sha256Digest,
    size_bytes: u64,
    exists: bool,
};

fn snapshotFile(path: []const u8) !Snapshot {
    const io = iox.current();
    var file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    const stat = try file.stat(io);
    var sha1 = std.crypto.hash.Sha1.init(.{});
    var sha256 = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [8192]u8 = undefined;
    var offset: u64 = 0;
    while (true) {
        const n = try file.readPositionalAll(io, &buf, offset);
        if (n == 0) break;
        sha1.update(buf[0..n]);
        sha256.update(buf[0..n]);
        offset += n;
    }

    var sha1_digest: Sha1Digest = undefined;
    var sha256_digest: Sha256Digest = undefined;
    sha1.final(&sha1_digest);
    sha256.final(&sha256_digest);
    return .{
        .sha1 = sha1_digest,
        .sha256 = sha256_digest,
        .size_bytes = stat.size,
        .exists = true,
    };
}

fn formatChange(
    alloc: std.mem.Allocator,
    path: []const u8,
    old_sha1: Sha1Digest,
    new_sha1: Sha1Digest,
    old_sha256: Sha256Digest,
    new_sha256: Sha256Digest,
    size_bytes: u64,
    exists: bool,
) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const w = &out.writer;
    const old_sha1_hex = std.fmt.bytesToHex(old_sha1, .lower);
    const new_sha1_hex = std.fmt.bytesToHex(new_sha1, .lower);
    const old_sha256_hex = std.fmt.bytesToHex(old_sha256, .lower);
    const new_sha256_hex = std.fmt.bytesToHex(new_sha256, .lower);

    try w.writeAll("{\"path\":");
    try std.json.Stringify.value(path, .{}, w);
    try w.print(
        ",\"old_sha1\":\"{s}\",\"new_sha1\":\"{s}\",\"old_sha256\":\"{s}\",\"new_sha256\":\"{s}\",\"size_bytes\":{d},\"exists\":{any}}}",
        .{
            old_sha1_hex,
            new_sha1_hex,
            old_sha256_hex,
            new_sha256_hex,
            size_bytes,
            exists,
        },
    );

    return out.toOwnedSlice();
}

test "fim emits only on hash change" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "watched.txt", .data = "one" });
    const path = try tmp.dir.realpathAlloc(std.testing.allocator, "watched.txt");
    defer std.testing.allocator.free(path);

    var watcher = try Watcher.init(std.testing.allocator, &.{path});
    defer watcher.deinit();

    const unchanged = try watcher.collectChanges();
    defer std.testing.allocator.free(unchanged);
    try std.testing.expectEqual(@as(usize, 0), unchanged.len);

    try tmp.dir.writeFile(.{ .sub_path = "watched.txt", .data = "two" });
    const changed = try watcher.collectChanges();
    defer {
        for (changed) |payload| std.testing.allocator.free(payload);
        std.testing.allocator.free(changed);
    }
    try std.testing.expectEqual(@as(usize, 1), changed.len);
    try std.testing.expect(std.mem.indexOf(u8, changed[0], "\"path\"") != null);
}
