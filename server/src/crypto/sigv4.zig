const std = @import("std");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Request = struct {
    method: []const u8,
    uri: []const u8,
    query: []const u8,
    headers: []const Header,
    payload: []const u8,
    access_key_id: []const u8,
    secret_access_key: []const u8,
    region: []const u8,
    service: []const u8,
    amz_date: []const u8,
};

pub const Signed = struct {
    signature_hex: [64]u8,
    canonical_hash_hex: [64]u8,
    authorization: []u8,

    pub fn deinit(self: *Signed, allocator: std.mem.Allocator) void {
        allocator.free(self.authorization);
    }
};

pub fn sign(allocator: std.mem.Allocator, request: Request) !Signed {
    if (request.amz_date.len < 16) return error.InvalidDate;
    if (request.headers.len > 64) return error.TooManyHeaders;

    var order: [64]usize = undefined;
    for (0..request.headers.len) |i| order[i] = i;
    var i: usize = 1;
    while (i < request.headers.len) : (i += 1) {
        const key = order[i];
        var j = i;
        while (j > 0 and headerLess(request.headers[key].name, request.headers[order[j - 1]].name)) : (j -= 1) {
            order[j] = order[j - 1];
        }
        order[j] = key;
    }

    var signed_headers: std.ArrayList(u8) = .empty;
    defer signed_headers.deinit(allocator);
    var values: [64][]u8 = undefined;
    var nvals: usize = 0;
    defer {
        for (values[0..nvals]) |value| allocator.free(value);
    }

    var canonical: std.ArrayList(u8) = .empty;
    defer canonical.deinit(allocator);

    for (request.method) |c| try canonical.append(allocator, std.ascii.toUpper(c));
    try canonical.append(allocator, '\n');
    try canonical.appendSlice(allocator, request.uri);
    try canonical.append(allocator, '\n');
    try canonical.appendSlice(allocator, request.query);
    try canonical.append(allocator, '\n');

    for (order[0..request.headers.len]) |idx| {
        const header = request.headers[idx];
        if (nvals != 0) try signed_headers.append(allocator, ';');
        for (header.name) |c| try signed_headers.append(allocator, std.ascii.toLower(c));

        const value = try canonicalHeaderValue(allocator, header.value);
        values[nvals] = value;
        nvals += 1;

        try canonical.appendSlice(allocator, signed_headers.items[signed_headers.items.len - header.name.len ..]);
        try canonical.append(allocator, ':');
        try canonical.appendSlice(allocator, value);
        try canonical.append(allocator, '\n');
    }
    try canonical.append(allocator, '\n');
    try canonical.appendSlice(allocator, signed_headers.items);
    try canonical.append(allocator, '\n');

    var payload_hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(request.payload, &payload_hash, .{});
    const payload_hex = std.fmt.bytesToHex(&payload_hash, .lower);
    try canonical.appendSlice(allocator, &payload_hex);

    var canonical_hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(canonical.items, &canonical_hash, .{});
    const canonical_hex = std.fmt.bytesToHex(&canonical_hash, .lower);

    var to_sign: std.ArrayList(u8) = .empty;
    defer to_sign.deinit(allocator);
    try to_sign.appendSlice(allocator, "AWS4-HMAC-SHA256\n");
    try to_sign.appendSlice(allocator, request.amz_date);
    try to_sign.append(allocator, '\n');
    try to_sign.appendSlice(allocator, request.amz_date[0..8]);
    try to_sign.append(allocator, '/');
    try to_sign.appendSlice(allocator, request.region);
    try to_sign.append(allocator, '/');
    try to_sign.appendSlice(allocator, request.service);
    try to_sign.appendSlice(allocator, "/aws4_request\n");
    try to_sign.appendSlice(allocator, &canonical_hex);

    const signing_key = try deriveSigningKey(allocator, request.secret_access_key, request.amz_date[0..8], request.region, request.service);
    var raw_sig: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&raw_sig, to_sign.items, &signing_key);
    const signature_hex = std.fmt.bytesToHex(&raw_sig, .lower);

    var authorization: std.ArrayList(u8) = .empty;
    errdefer authorization.deinit(allocator);
    try authorization.appendSlice(allocator, "AWS4-HMAC-SHA256 Credential=");
    try authorization.appendSlice(allocator, request.access_key_id);
    try authorization.append(allocator, '/');
    try authorization.appendSlice(allocator, request.amz_date[0..8]);
    try authorization.append(allocator, '/');
    try authorization.appendSlice(allocator, request.region);
    try authorization.append(allocator, '/');
    try authorization.appendSlice(allocator, request.service);
    try authorization.appendSlice(allocator, "/aws4_request, SignedHeaders=");
    try authorization.appendSlice(allocator, signed_headers.items);
    try authorization.appendSlice(allocator, ", Signature=");
    try authorization.appendSlice(allocator, &signature_hex);

    return .{
        .signature_hex = signature_hex,
        .canonical_hash_hex = canonical_hex,
        .authorization = try authorization.toOwnedSlice(allocator),
    };
}

fn deriveSigningKey(
    allocator: std.mem.Allocator,
    secret: []const u8,
    date_stamp: []const u8,
    region: []const u8,
    service: []const u8,
) ![32]u8 {
    const prefixed = try allocator.alloc(u8, 4 + secret.len);
    defer allocator.free(prefixed);
    @memcpy(prefixed[0..4], "AWS4");
    @memcpy(prefixed[4..], secret);
    var k_date: [32]u8 = undefined;
    HmacSha256.create(&k_date, date_stamp, prefixed);
    var k_region: [32]u8 = undefined;
    HmacSha256.create(&k_region, region, &k_date);
    var k_service: [32]u8 = undefined;
    HmacSha256.create(&k_service, service, &k_region);
    var k_signing: [32]u8 = undefined;
    HmacSha256.create(&k_signing, "aws4_request", &k_service);
    return k_signing;
}

fn headerLess(a: []const u8, b: []const u8) bool {
    const n = @min(a.len, b.len);
    for (a[0..n], b[0..n]) |ca, cb| {
        const la = std.ascii.toLower(ca);
        const lb = std.ascii.toLower(cb);
        if (la < lb) return true;
        if (la > lb) return false;
    }
    return a.len < b.len;
}

fn canonicalHeaderValue(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    const trimmed = std.mem.trim(u8, raw, &std.ascii.whitespace);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var prev_ws = false;
    for (trimmed) |c| {
        if (c == ' ' or c == '\t') {
            if (!prev_ws) try out.append(allocator, ' ');
            prev_ws = true;
        } else {
            try out.append(allocator, c);
            prev_ws = false;
        }
    }
    if (out.items.len == 0) {
        out.deinit(allocator);
        return allocator.alloc(u8, 0);
    }
    return out.toOwnedSlice(allocator);
}

test "aws sigv4 get iam example" {
    const allocator = std.testing.allocator;
    const headers = [_]Header{
        .{ .name = "X-Amz-Date", .value = "20150830T123600Z" },
        .{ .name = "Host", .value = "iam.amazonaws.com" },
        .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded; charset=utf-8" },
    };
    var signed = try sign(allocator, .{
        .method = "GET",
        .uri = "/",
        .query = "Action=ListUsers&Version=2010-05-08",
        .headers = &headers,
        .payload = "",
        .access_key_id = "AKIDEXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "iam",
        .amz_date = "20150830T123600Z",
    });
    defer signed.deinit(allocator);

    try std.testing.expectEqualSlices(u8, "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59", &signed.canonical_hash_hex);
    try std.testing.expectEqualSlices(u8, "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7", &signed.signature_hex);
    try std.testing.expectEqualSlices(
        u8,
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
        signed.authorization,
    );
}

test "sigv4 put body changes signature" {
    const allocator = std.testing.allocator;
    const headers = [_]Header{
        .{ .name = "host", .value = "example.amazonaws.com" },
        .{ .name = "x-amz-date", .value = "20150830T123600Z" },
    };
    var empty = try sign(allocator, .{
        .method = "PUT",
        .uri = "/object",
        .query = "",
        .headers = &headers,
        .payload = "",
        .access_key_id = "AKIDEXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "s3",
        .amz_date = "20150830T123600Z",
    });
    defer empty.deinit(allocator);
    var body = try sign(allocator, .{
        .method = "PUT",
        .uri = "/object",
        .query = "",
        .headers = &headers,
        .payload = "hello",
        .access_key_id = "AKIDEXAMPLE",
        .secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        .region = "us-east-1",
        .service = "s3",
        .amz_date = "20150830T123600Z",
    });
    defer body.deinit(allocator);
    try std.testing.expect(!std.mem.eql(u8, &empty.signature_hex, &body.signature_hex));
    try std.testing.expect(std.mem.startsWith(u8, body.authorization, "AWS4-HMAC-SHA256 "));
}
