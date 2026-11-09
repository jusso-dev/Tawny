//! Ed25519 device signatures on telemetry batches.
//!
//! Schema 1 batches (older agents) sign:
//!
//!   tawny-batch-v1\n
//!   <agent_id>\n
//!   <batch_id>\n
//!   <client_event_id>|<sequence>|<type>|<occurred_at>|<sha256 hex of payload bytes>\n   (one per event)
//!
//! Schema 2 batches (agent/src/transport/http.zig) sign:
//!
//!   tawny-batch-v2\n
//!   <agent_id>\n
//!   <batch_id>\n
//!   <agent.boot_id>\n
//!   <agent.sensor_version>\n
//!   <event_id>|<seq>|<event_type>|<v>|<ts>|<sha256 hex of data bytes>\n   (one per event)
//!
//! `ts` is the decoded ISO 8601 string (`2025-10-09T08:53:20.000Z`).
//!
//! What v2 signs and why: `boot_id` is an input to every process entity id,
//! so a changed boot id would move processes into another tree; it is signed.
//! `sensor_version` is signed so a downgrade claim can't be forged. Per event,
//! `v` picks the payload schema, so it is signed with the rest of the event
//! identity. `mono`, `priority` and `sensor` are not signed: the server does
//! not store or act on them. The `schema` number is fixed by the prefix.
//! `agent_id` is the authenticated agent from the JWT, not the body field.
//!
//! The payload hash covers the exact bytes the agent wrote, so the server takes
//! each payload (and the time) as a raw slice of the request body rather than
//! re-serialising the parsed value.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

pub const prefix_v1 = "tawny-batch-v1\n";
pub const prefix_v2 = "tawny-batch-v2\n";

/// Raw byte ranges for one event, taken from the request body.
pub const RawEvent = struct {
    payload: []const u8 = "",
    occurred_at: []const u8 = "",
};

/// Signed fields of one schema 2 event.
pub const EventV2 = struct {
    event_id: []const u8,
    seq: i64,
    event_type: []const u8,
    v: i64,
    /// Decoded `ts` string.
    ts: []const u8,
    data_raw: []const u8,
};

/// Signed fields of one event, as the agent formatted them.
pub const Event = struct {
    client_event_id: []const u8,
    sequence: i64,
    type: []const u8,
    occurred_at_raw: []const u8,
    payload_raw: []const u8,
};

pub const Error = error{
    BadBody,
    BadPublicKey,
    BadSignature,
    SignatureMismatch,
} || std.mem.Allocator.Error;

/// Walk the body and return the raw `payload` and `occurred_at` slices of each
/// element of the top-level `events` array, in order. The caller frees the slice.
/// Duplicate keys are rejected by the typed parse that runs first, so the raw
/// slices here and the parsed values refer to the same members.
pub fn rawEvents(allocator: std.mem.Allocator, body: []const u8) Error![]RawEvent {
    return rawEventsKeyed(allocator, body, "payload", "occurred_at");
}

/// Schema 2: raw `data` slices (in `payload`; `occurred_at` holds the raw `ts`).
pub fn rawEventsV2(allocator: std.mem.Allocator, body: []const u8) Error![]RawEvent {
    return rawEventsKeyed(allocator, body, "data", "ts");
}

fn rawEventsKeyed(allocator: std.mem.Allocator, body: []const u8, payload_key: []const u8, time_key: []const u8) Error![]RawEvent {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var out: std.ArrayList(RawEvent) = .empty;
    errdefer out.deinit(allocator);

    var sc = std.json.Scanner.initCompleteInput(arena, body);
    defer sc.deinit();

    if ((sc.next() catch return error.BadBody) != .object_begin) return error.BadBody;
    var seen_events = false;
    while (true) {
        const key = (try nextKey(&sc, arena)) orelse break;
        if (!std.mem.eql(u8, key, "events")) {
            sc.skipValue() catch return error.BadBody;
            continue;
        }
        if (seen_events) return error.BadBody;
        seen_events = true;
        if ((sc.next() catch return error.BadBody) != .array_begin) return error.BadBody;
        while (true) {
            const t = sc.peekNextTokenType() catch return error.BadBody;
            if (t == .array_end) {
                _ = sc.next() catch return error.BadBody;
                break;
            }
            if (t != .object_begin) return error.BadBody;
            _ = sc.next() catch return error.BadBody;
            var ev: RawEvent = .{};
            while (true) {
                const field = (try nextKey(&sc, arena)) orelse break;
                const want_payload = std.mem.eql(u8, field, payload_key);
                const want_time = std.mem.eql(u8, field, time_key);
                // peek skips the colon and whitespace, leaving cursor on the value.
                _ = sc.peekNextTokenType() catch return error.BadBody;
                const start = sc.cursor;
                sc.skipValue() catch return error.BadBody;
                const raw = body[start..sc.cursor];
                if (want_payload) ev.payload = raw;
                if (want_time) ev.occurred_at = raw;
            }
            try out.append(allocator, ev);
        }
    }
    return out.toOwnedSlice(allocator);
}

/// Next object key, or null at the end of the object.
fn nextKey(sc: *std.json.Scanner, arena: std.mem.Allocator) Error!?[]const u8 {
    const tok = sc.nextAlloc(arena, .alloc_if_needed) catch return error.BadBody;
    return switch (tok) {
        .object_end => null,
        .string => |s| s,
        .allocated_string => |s| s,
        else => error.BadBody,
    };
}

/// Rebuild the exact string the agent signed.
pub fn canonical(allocator: std.mem.Allocator, agent_id: []const u8, batch_id: []const u8, events: []const Event) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, prefix_v1);
    try out.appendSlice(allocator, agent_id);
    try out.append(allocator, '\n');
    try out.appendSlice(allocator, batch_id);
    try out.append(allocator, '\n');
    for (events) |ev| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(ev.payload_raw, &digest, .{});
        try out.print(allocator, "{s}|{d}|{s}|{s}|", .{ ev.client_event_id, ev.sequence, ev.type, ev.occurred_at_raw });
        const hex = std.fmt.bytesToHex(digest, .lower);
        try out.appendSlice(allocator, &hex);
        try out.append(allocator, '\n');
    }
    return out.toOwnedSlice(allocator);
}

/// Rebuild the exact schema 2 string the agent signed.
pub fn canonicalV2(
    allocator: std.mem.Allocator,
    agent_id: []const u8,
    batch_id: []const u8,
    boot_id: []const u8,
    sensor_version: []const u8,
    events: []const EventV2,
) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, prefix_v2);
    for ([_][]const u8{ agent_id, batch_id, boot_id, sensor_version }) |line| {
        // A newline inside a header field would let one field pose as two.
        if (std.mem.indexOfScalar(u8, line, '\n') != null) return error.BadBody;
        try out.appendSlice(allocator, line);
        try out.append(allocator, '\n');
    }
    for (events) |ev| {
        if (std.mem.indexOfAny(u8, ev.event_type, "|\n") != null) return error.BadBody;
        if (std.mem.indexOfAny(u8, ev.ts, "|\n") != null) return error.BadBody;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(ev.data_raw, &digest, .{});
        try out.print(allocator, "{s}|{d}|{s}|{d}|{s}|", .{ ev.event_id, ev.seq, ev.event_type, ev.v, ev.ts });
        const hex = std.fmt.bytesToHex(digest, .lower);
        try out.appendSlice(allocator, &hex);
        try out.append(allocator, '\n');
    }
    return out.toOwnedSlice(allocator);
}

/// Verify a base64 Ed25519 signature over `message` with a base64 public key.
pub fn verify(public_key_b64: []const u8, message: []const u8, signature_b64: []const u8) Error!void {
    const D = std.base64.standard.Decoder;
    var pk_bytes: [Ed25519.PublicKey.encoded_length]u8 = undefined;
    const pk_len = D.calcSizeForSlice(public_key_b64) catch return error.BadPublicKey;
    if (pk_len != pk_bytes.len) return error.BadPublicKey;
    D.decode(&pk_bytes, public_key_b64) catch return error.BadPublicKey;
    const pk = Ed25519.PublicKey.fromBytes(pk_bytes) catch return error.BadPublicKey;

    var sig_bytes: [Ed25519.Signature.encoded_length]u8 = undefined;
    const sig_len = D.calcSizeForSlice(signature_b64) catch return error.BadSignature;
    if (sig_len != sig_bytes.len) return error.BadSignature;
    D.decode(&sig_bytes, signature_b64) catch return error.BadSignature;
    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    sig.verify(message, pk) catch return error.SignatureMismatch;
}

// ---- tests ----------------------------------------------------------------

const test_agent = "00000000-0000-0000-0000-00000000b001";
const test_batch = "00000000-0000-0000-0000-00000000b002";

const Fixture = struct {
    kp: Ed25519.KeyPair,
    pk_b64: [44]u8,
};

fn fixture() !Fixture {
    // Test-only seed. Never used outside this file.
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    var f: Fixture = .{ .kp = kp, .pk_b64 = undefined };
    _ = std.base64.standard.Encoder.encode(&f.pk_b64, &kp.public_key.bytes);
    return f;
}

/// Build the canonical string the way agent/src/transport/http.zig does, from
/// the same inputs the agent holds, without using `canonical` above.
fn agentCanonical(allocator: std.mem.Allocator, evs: []const struct { cid: []const u8, seq: u64, ty: []const u8, at: i64, payload: []const u8 }) ![]u8 {
    var c: std.ArrayList(u8) = .empty;
    errdefer c.deinit(allocator);
    try c.appendSlice(allocator, "tawny-batch-v1\n" ++ test_agent ++ "\n" ++ test_batch ++ "\n");
    for (evs) |ev| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(ev.payload, &digest, .{});
        try c.appendSlice(allocator, ev.cid);
        try c.append(allocator, '|');
        try c.print(allocator, "{d}|{s}|{d}|", .{ ev.seq, ev.ty, ev.at });
        for (digest) |b| try c.print(allocator, "{x:0>2}", .{b});
        try c.append(allocator, '\n');
    }
    return c.toOwnedSlice(allocator);
}

const golden_body =
    \\{"batch_id":"00000000-0000-0000-0000-00000000b002","events":[{"client_event_id":"00000000-0000-0000-0000-0000000000e1","type":"process_launch","occurred_at":1760000000,"sequence":41,"payload":{"pid":10, "name":"a \"b\""}},{"client_event_id":"00000000-0000-0000-0000-0000000000e2","type":"dns_query","occurred_at":1760000001,"sequence":42,"payload":{"qname":"x.example","n":1.50}}]}
;

const BodyEvent = struct {
    type: []const u8,
    occurred_at: std.json.Value,
    payload: std.json.Value,
    client_event_id: ?[]const u8 = null,
    sequence: ?i64 = null,
};
const BodyReq = struct { events: []BodyEvent, batch_id: ?[]const u8 = null };

/// Verify `body` the way routes/agents.zig does.
fn serverVerify(allocator: std.mem.Allocator, body: []const u8, pk_b64: []const u8, sig_b64: []const u8) !void {
    var parsed = try std.json.parseFromSlice(BodyReq, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const raws = try rawEvents(allocator, body);
    defer allocator.free(raws);
    if (raws.len != parsed.value.events.len) return error.BadBody;
    const evs = try allocator.alloc(Event, raws.len);
    defer allocator.free(evs);
    for (parsed.value.events, raws, 0..) |ev, raw, i| {
        evs[i] = .{
            .client_event_id = ev.client_event_id orelse return error.BadBody,
            .sequence = ev.sequence orelse return error.BadBody,
            .type = ev.type,
            .occurred_at_raw = raw.occurred_at,
            .payload_raw = raw.payload,
        };
    }
    const msg = try canonical(allocator, test_agent, parsed.value.batch_id orelse return error.BadBody, evs);
    defer allocator.free(msg);
    try verify(pk_b64, msg, sig_b64);
}

fn signGolden(allocator: std.mem.Allocator, f: Fixture) ![88]u8 {
    const msg = try agentCanonical(allocator, &.{
        .{ .cid = "00000000-0000-0000-0000-0000000000e1", .seq = 41, .ty = "process_launch", .at = 1760000000, .payload = "{\"pid\":10, \"name\":\"a \\\"b\\\"\"}" },
        .{ .cid = "00000000-0000-0000-0000-0000000000e2", .seq = 42, .ty = "dns_query", .at = 1760000001, .payload = "{\"qname\":\"x.example\",\"n\":1.50}" },
    });
    defer allocator.free(msg);
    const sig = try f.kp.sign(msg, null);
    var out: [88]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &sig.toBytes());
    return out;
}

test "raw events keep exact payload bytes" {
    const raws = try rawEvents(std.testing.allocator, golden_body);
    defer std.testing.allocator.free(raws);
    try std.testing.expectEqual(@as(usize, 2), raws.len);
    try std.testing.expectEqualStrings("{\"pid\":10, \"name\":\"a \\\"b\\\"\"}", raws[0].payload);
    try std.testing.expectEqualStrings("1760000000", raws[0].occurred_at);
    try std.testing.expectEqualStrings("{\"qname\":\"x.example\",\"n\":1.50}", raws[1].payload);
}

test "raw events rejects bodies that aren't an object with an events array" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.BadBody, rawEvents(a, "[]"));
    try std.testing.expectError(error.BadBody, rawEvents(a, "{\"events\":{}}"));
    try std.testing.expectError(error.BadBody, rawEvents(a, "{\"events\":[1]}"));
    try std.testing.expectError(error.BadBody, rawEvents(a, "{\"events\":[],\"events\":[]}"));
}

test "golden batch signed like the agent verifies" {
    const a = std.testing.allocator;
    const f = try fixture();
    const sig = try signGolden(a, f);
    try serverVerify(a, golden_body, &f.pk_b64, &sig);
}

test "any change to a signed field fails verification" {
    const a = std.testing.allocator;
    const f = try fixture();
    const sig = try signGolden(a, f);
    const swaps = [_]struct { from: []const u8, to: []const u8 }{
        .{ .from = "\"pid\":10", .to = "\"pid\":11" }, // payload byte
        .{ .from = "\"pid\":10, ", .to = "\"pid\":10," }, // payload whitespace
        .{ .from = "\"sequence\":41", .to = "\"sequence\":40" },
        .{ .from = "\"type\":\"dns_query\"", .to = "\"type\":\"dns_queries\"" },
        .{ .from = "\"occurred_at\":1760000001", .to = "\"occurred_at\":1760000002" },
        .{ .from = "0000000000e2", .to = "0000000000e3" }, // client_event_id
        .{ .from = "00000000b002", .to = "00000000b003" }, // batch_id
    };
    for (swaps) |sw| {
        const body = try std.mem.replaceOwned(u8, a, golden_body, sw.from, sw.to);
        defer a.free(body);
        try std.testing.expect(!std.mem.eql(u8, body, golden_body));
        try std.testing.expectError(error.SignatureMismatch, serverVerify(a, body, &f.pk_b64, &sig));
    }
}

test "forged, truncated and wrong-key signatures are refused" {
    const a = std.testing.allocator;
    const f = try fixture();
    var sig = try signGolden(a, f);

    var flipped = sig;
    flipped[10] = if (flipped[10] == 'A') 'B' else 'A';
    try std.testing.expectError(error.SignatureMismatch, serverVerify(a, golden_body, &f.pk_b64, &flipped));
    try std.testing.expectError(error.BadSignature, serverVerify(a, golden_body, &f.pk_b64, sig[0..40]));
    try std.testing.expectError(error.BadSignature, serverVerify(a, golden_body, &f.pk_b64, "not base64!!"));

    var other_seed: [32]u8 = @splat(0xa5);
    const other = try Ed25519.KeyPair.generateDeterministic(other_seed);
    std.crypto.secureZero(u8, &other_seed);
    var other_pk: [44]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&other_pk, &other.public_key.bytes);
    try std.testing.expectError(error.SignatureMismatch, serverVerify(a, golden_body, &other_pk, &sig));
    try std.testing.expectError(error.BadPublicKey, serverVerify(a, golden_body, "AAAA", &sig));
    std.crypto.secureZero(u8, &sig);
}

// ---- schema 2 ---------------------------------------------------------------

const test_boot = "3c1c4b5e-6d2a-4f0e-9b7a-2d1e5f6a7b8c";

const golden_body_v2 =
    \\{"schema":2,"batch_id":"00000000-0000-0000-0000-00000000b002","agent":{"agent_id":"00000000-0000-0000-0000-00000000b001","sensor_version":"0.1.0","boot_id":"3c1c4b5e-6d2a-4f0e-9b7a-2d1e5f6a7b8c"},"events":[{"event_id":"00000000-0000-0000-0000-0000000000e1","event_type":"process_start","v":1,"ts":"2025-10-09T08:53:20.000Z","seq":41,"data":{"process":{"entity_id":"t2brmmuntrcdcqfziccyckt3lm","pid":10, "name":"a \"b\""}}},{"event_id":"00000000-0000-0000-0000-0000000000e2","event_type":"dns_query","v":1,"ts":"2025-10-09T08:53:21.000Z","seq":42,"data":{"qname":"x.example","n":1.50}}]}
;

/// The schema 2 string built the way agent/src/transport/http.zig builds it.
fn agentCanonicalV2(allocator: std.mem.Allocator) ![]u8 {
    var c: std.ArrayList(u8) = .empty;
    errdefer c.deinit(allocator);
    try c.appendSlice(allocator, "tawny-batch-v2\n" ++ test_agent ++ "\n" ++ test_batch ++ "\n" ++ test_boot ++ "\n0.1.0\n");
    const evs = [_]struct { id: []const u8, seq: u64, ty: []const u8, ts: []const u8, data: []const u8 }{
        .{ .id = "00000000-0000-0000-0000-0000000000e1", .seq = 41, .ty = "process_start", .ts = "2025-10-09T08:53:20.000Z", .data = "{\"process\":{\"entity_id\":\"t2brmmuntrcdcqfziccyckt3lm\",\"pid\":10, \"name\":\"a \\\"b\\\"\"}}" },
        .{ .id = "00000000-0000-0000-0000-0000000000e2", .seq = 42, .ty = "dns_query", .ts = "2025-10-09T08:53:21.000Z", .data = "{\"qname\":\"x.example\",\"n\":1.50}" },
    };
    for (evs) |ev| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(ev.data, &digest, .{});
        try c.print(allocator, "{s}|{d}|{s}|1|{s}|", .{ ev.id, ev.seq, ev.ty, ev.ts });
        for (digest) |b| try c.print(allocator, "{x:0>2}", .{b});
        try c.append(allocator, '\n');
    }
    return c.toOwnedSlice(allocator);
}

const BodyEventV2 = struct { event_id: []const u8, event_type: []const u8, v: i64 = 1, ts: []const u8, seq: i64, data: std.json.Value };
const BodyReqV2 = struct {
    schema: i64,
    batch_id: []const u8,
    agent: struct { agent_id: []const u8, sensor_version: []const u8, boot_id: []const u8 },
    events: []BodyEventV2,
};

/// Verify a schema 2 body the way routes/agents.zig does.
fn serverVerifyV2(allocator: std.mem.Allocator, body: []const u8, pk_b64: []const u8, sig_b64: []const u8) !void {
    var parsed = try std.json.parseFromSlice(BodyReqV2, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const raws = try rawEventsV2(allocator, body);
    defer allocator.free(raws);
    if (raws.len != parsed.value.events.len) return error.BadBody;
    const evs = try allocator.alloc(EventV2, raws.len);
    defer allocator.free(evs);
    for (parsed.value.events, raws, 0..) |ev, raw, i| {
        evs[i] = .{ .event_id = ev.event_id, .seq = ev.seq, .event_type = ev.event_type, .v = ev.v, .ts = ev.ts, .data_raw = raw.payload };
    }
    const a = parsed.value.agent;
    const msg = try canonicalV2(allocator, test_agent, parsed.value.batch_id, a.boot_id, a.sensor_version, evs);
    defer allocator.free(msg);
    try verify(pk_b64, msg, sig_b64);
}

fn signGoldenV2(allocator: std.mem.Allocator, f: Fixture) ![88]u8 {
    const msg = try agentCanonicalV2(allocator);
    defer allocator.free(msg);
    const sig = try f.kp.sign(msg, null);
    var out: [88]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &sig.toBytes());
    return out;
}

test "v2 canonical string golden value" {
    const a = std.testing.allocator;
    const msg = try canonicalV2(a, test_agent, test_batch, test_boot, "0.1.0", &.{
        .{ .event_id = "e1", .seq = 7, .event_type = "process_start", .v = 1, .ts = "2025-10-09T08:53:20.000Z", .data_raw = "{}" },
    });
    defer a.free(msg);
    try std.testing.expectEqualStrings(
        "tawny-batch-v2\n" ++ test_agent ++ "\n" ++ test_batch ++ "\n" ++ test_boot ++ "\n0.1.0\n" ++
            "e1|7|process_start|1|2025-10-09T08:53:20.000Z|44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a\n",
        msg,
    );
    try std.testing.expectError(error.BadBody, canonicalV2(a, test_agent, test_batch, "x\ny", "0.1.0", &.{}));
}

test "v2 golden batch signed like the agent verifies, and v1 still does" {
    const a = std.testing.allocator;
    const f = try fixture();
    const sig2 = try signGoldenV2(a, f);
    try serverVerifyV2(a, golden_body_v2, &f.pk_b64, &sig2);
    const sig1 = try signGolden(a, f);
    try serverVerify(a, golden_body, &f.pk_b64, &sig1);
    // A v1 signature never verifies a v2 body and the reverse.
    try std.testing.expectError(error.SignatureMismatch, serverVerifyV2(a, golden_body_v2, &f.pk_b64, &sig1));
    try std.testing.expectError(error.SignatureMismatch, serverVerify(a, golden_body, &f.pk_b64, &sig2));
}

test "v2: any change to a signed field fails verification" {
    const a = std.testing.allocator;
    const f = try fixture();
    const sig = try signGoldenV2(a, f);
    const swaps = [_]struct { from: []const u8, to: []const u8 }{
        .{ .from = "\"pid\":10", .to = "\"pid\":11" }, // data byte
        .{ .from = "\"pid\":10, ", .to = "\"pid\":10," }, // data whitespace
        .{ .from = "t2brmmuntrcdcqfziccyckt3lm", .to = "t2brmmuntrcdcqfziccyckt3ln" }, // entity id
        .{ .from = "\"seq\":41", .to = "\"seq\":40" },
        .{ .from = "\"event_type\":\"dns_query\"", .to = "\"event_type\":\"dns_queries\"" },
        .{ .from = "08:53:21.000Z", .to = "08:53:22.000Z" }, // ts
        .{ .from = "\"v\":1,\"ts\":\"2025-10-09T08:53:21", .to = "\"v\":2,\"ts\":\"2025-10-09T08:53:21" },
        .{ .from = "0000000000e2", .to = "0000000000e3" }, // event_id
        .{ .from = "00000000b002", .to = "00000000b003" }, // batch_id
        .{ .from = "3c1c4b5e-6d2a", .to = "3c1c4b5e-6d2b" }, // boot_id
        .{ .from = "\"sensor_version\":\"0.1.0\"", .to = "\"sensor_version\":\"0.0.9\"" },
    };
    for (swaps) |sw| {
        const body = try std.mem.replaceOwned(u8, a, golden_body_v2, sw.from, sw.to);
        defer a.free(body);
        try std.testing.expect(!std.mem.eql(u8, body, golden_body_v2));
        serverVerifyV2(a, body, &f.pk_b64, &sig) catch |err| {
            try std.testing.expectEqual(error.SignatureMismatch, err);
            continue;
        };
        std.debug.print("tamper not caught: {s} -> {s}\n", .{ sw.from, sw.to });
        return error.TestUnexpectedResult;
    }
}

test "v2 raw events keep exact data bytes" {
    const raws = try rawEventsV2(std.testing.allocator, golden_body_v2);
    defer std.testing.allocator.free(raws);
    try std.testing.expectEqual(@as(usize, 2), raws.len);
    try std.testing.expectEqualStrings("\"2025-10-09T08:53:20.000Z\"", raws[0].occurred_at);
    try std.testing.expectEqualStrings("{\"qname\":\"x.example\",\"n\":1.50}", raws[1].payload);
}
