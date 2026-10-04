//! Corpus exercised by `zig test` and, when a libFuzzer build is used, by
//! `std.testing.fuzz`. Invalid hunt text is a handled parse error.
const std = @import("std");
const util = @import("http/util.zig");
const query = @import("hunts/query.zig");

const corpus = [_][]const u8{
    "",
    "%",
    "%2",
    "%3A",
    "a%2Fb",
    "a+b",
    "type:process",
    "from:2020-01-01T00:00:00Z AND name:cmd.exe",
};

fn takeSample(smith: *std.testing.Smith, buf: []u8, hash: u32) []const u8 {
    if (smith.in) |in| return in;
    const n: usize = smith.sliceWithHash(buf, hash);
    return buf[0..n];
}

fn fuzzPercentDecode(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [256]u8 = undefined;
    const sample = takeSample(smith, &buf, 0x71a75eed);
    const out = try util.percentDecode(std.testing.allocator, sample);
    defer std.testing.allocator.free(out);
    try std.testing.expect(out.len <= sample.len);
    if (std.mem.eql(u8, sample, "%3A")) try std.testing.expectEqualStrings(":", out);
    if (std.mem.eql(u8, sample, "a%2Fb")) try std.testing.expectEqualStrings("a/b", out);
    if (std.mem.eql(u8, sample, "a+b")) try std.testing.expectEqualStrings("a b", out);
    if (sample.len == 0) try std.testing.expectEqual(@as(usize, 0), out.len);
}

fn fuzzHuntParse(_: void, smith: *std.testing.Smith) anyerror!void {
    var buf: [256]u8 = undefined;
    const sample = takeSample(smith, &buf, 0x0c0a11e1);
    var storage: [240]u8 = undefined;
    var msg: []u8 = &storage;
    if (query.parse(std.testing.allocator, sample, null, 0, &msg)) |plan| {
        var parsed = plan;
        parsed.deinit();
    } else |_| {}
}

test "fuzz percent-decode never grows" {
    try std.testing.fuzz({}, fuzzPercentDecode, .{ .corpus = &corpus });
}

test "fuzz hunt parse handles junk" {
    try std.testing.fuzz({}, fuzzHuntParse, .{ .corpus = &corpus });
}
