const std = @import("std");

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
    files: std.ArrayList(WatchedFile),

    pub fn init(alloc: std.mem.Allocator, paths: []const []const u8) !Watcher {
        var watcher = Watcher{
            .allocator = alloc,
            .files = std.ArrayList(WatchedFile).init(alloc),
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
        var payloads = std.ArrayList([]u8).init(self.allocator);
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
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const stat = try file.stat();
    var sha1 = std.crypto.hash.Sha1.init(.{});
    var sha256 = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try file.read(&buf);
        if (n == 0) break;
        sha1.update(buf[0..n]);
        sha256.update(buf[0..n]);
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
    var out = std.ArrayList(u8).init(alloc);
    errdefer out.deinit();
    var w = out.writer();

    try w.writeAll("{\"path\":");
    try std.json.stringify(path, .{}, w);
    try w.print(
        ",\"old_sha1\":\"{}\",\"new_sha1\":\"{}\",\"old_sha256\":\"{}\",\"new_sha256\":\"{}\",\"size_bytes\":{d},\"exists\":{any}}}",
        .{
            std.fmt.fmtSliceHexLower(&old_sha1),
            std.fmt.fmtSliceHexLower(&new_sha1),
            std.fmt.fmtSliceHexLower(&old_sha256),
            std.fmt.fmtSliceHexLower(&new_sha256),
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
