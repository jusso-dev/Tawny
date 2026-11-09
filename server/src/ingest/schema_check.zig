//! Test-only check of a JSON payload against schemas/events/<type>.v1.json.
//!
//! Supports the subset the schemas use: `type` (name or list), `required`,
//! `properties`, `items`, `enum`, `const`, `anyOf`, `minLength`, `maxLength`,
//! `minimum`, `allOf`, and `$ref` to `#/$defs/<name>` or `common.v1.json#/$defs/<name>`.
//! `pattern` and `format` are not checked. Schemas are read from
//! ../schemas/events relative to the working directory (`agent/` under
//! `zig build test`, `server/` under `zig test`). The same file is in
//! server/src/ingest/schema_check.zig; keep the two identical.
const std = @import("std");

pub const schema_dir = "../schemas/events";

pub const Failure = error{ SchemaMismatch, SchemaMissing };

pub const Checker = struct {
    arena: std.heap.ArenaAllocator,
    io: std.Io,
    common: ?std.json.Value = null,
    /// First failure, for the test log.
    reason: []const u8 = "",
    path: std.ArrayList(u8) = .empty,

    pub fn init(gpa: std.mem.Allocator, io: std.Io) Checker {
        return .{ .arena = std.heap.ArenaAllocator.init(gpa), .io = io };
    }

    pub fn deinit(self: *Checker) void {
        self.arena.deinit();
    }

    pub fn load(self: *Checker, name: []const u8) !std.json.Value {
        const a = self.arena.allocator();
        const path = try std.fmt.allocPrint(a, "{s}/{s}", .{ schema_dir, name });
        const text = std.Io.Dir.cwd().readFileAlloc(self.io, path, a, .limited(256 * 1024)) catch return error.SchemaMissing;
        return std.json.parseFromSliceLeaky(std.json.Value, a, text, .{});
    }

    /// Check `payload` (JSON text) against `<event_type>.v1.json`.
    pub fn check(self: *Checker, event_type: []const u8, payload: []const u8) !void {
        const file = try std.fmt.allocPrint(self.arena.allocator(), "{s}.v1.json", .{event_type});
        return self.checkFile(file, payload);
    }

    /// Check `payload` against a schema file in schemas/events.
    pub fn checkFile(self: *Checker, file: []const u8, payload: []const u8) !void {
        const a = self.arena.allocator();
        const schema = try self.load(file);
        if (self.common == null) self.common = try self.load("common.v1.json");
        const value = try std.json.parseFromSliceLeaky(std.json.Value, a, payload, .{});
        if (!try self.node(schema, schema, value)) return error.SchemaMismatch;
    }

    fn fail(self: *Checker, why: []const u8) bool {
        if (self.reason.len == 0) self.reason = why;
        return false;
    }

    fn resolve(self: *Checker, root: std.json.Value, ref: []const u8) ?struct { root: std.json.Value, schema: std.json.Value } {
        var doc = root;
        var frag = ref;
        if (std.mem.startsWith(u8, ref, "common.v1.json#")) {
            doc = self.common orelse return null;
            frag = ref["common.v1.json".len..];
        }
        const prefix = "#/$defs/";
        if (!std.mem.startsWith(u8, frag, prefix)) return null;
        const defs = doc.object.get("$defs") orelse return null;
        const s = defs.object.get(frag[prefix.len..]) orelse return null;
        return .{ .root = doc, .schema = s };
    }

    fn typeMatches(name: []const u8, v: std.json.Value) bool {
        return switch (v) {
            .null => std.mem.eql(u8, name, "null"),
            .bool => std.mem.eql(u8, name, "boolean"),
            .integer => std.mem.eql(u8, name, "integer") or std.mem.eql(u8, name, "number"),
            .float, .number_string => std.mem.eql(u8, name, "number"),
            .string => std.mem.eql(u8, name, "string"),
            .array => std.mem.eql(u8, name, "array"),
            .object => std.mem.eql(u8, name, "object"),
        };
    }

    fn node(self: *Checker, root: std.json.Value, schema: std.json.Value, v: std.json.Value) error{OutOfMemory}!bool {
        if (schema == .bool) return schema.bool;
        if (schema != .object) return true;
        const s = schema.object;
        if (s.get("$ref")) |ref| {
            const r = self.resolve(root, ref.string) orelse return self.fail("unresolved $ref");
            if (!try self.node(r.root, r.schema, v)) return false;
        }
        if (s.get("type")) |t| {
            const ok = switch (t) {
                .string => |name| typeMatches(name, v),
                .array => |list| blk: {
                    for (list.items) |name| if (typeMatches(name.string, v)) break :blk true;
                    break :blk false;
                },
                else => true,
            };
            if (!ok) return self.fail("type");
        }
        if (s.get("const")) |c| if (!jsonEqual(c, v)) return self.fail("const");
        if (s.get("enum")) |e| {
            var found = false;
            for (e.array.items) |item| if (jsonEqual(item, v)) {
                found = true;
                break;
            };
            if (!found) return self.fail("enum");
        }
        if (v == .string) {
            const n = std.unicode.utf8CountCodepoints(v.string) catch v.string.len;
            if (s.get("minLength")) |m| if (n < m.integer) return self.fail("minLength");
            if (s.get("maxLength")) |m| if (n > m.integer) return self.fail("maxLength");
        }
        if (s.get("minimum")) |m| switch (v) {
            .integer => |n| if (n < m.integer) return self.fail("minimum"),
            else => {},
        };
        if (s.get("allOf")) |all| for (all.array.items) |sub| {
            if (!try self.node(root, sub, v)) return false;
        };
        if (s.get("anyOf")) |any| {
            var ok = false;
            const saved = self.reason;
            for (any.array.items) |alt| if (try self.node(root, alt, v)) {
                ok = true;
                break;
            };
            self.reason = saved;
            if (!ok) return self.fail("anyOf");
        }
        if (v == .object) {
            if (s.get("required")) |req| for (req.array.items) |name| {
                if (v.object.get(name.string) == null) return self.fail(name.string);
            };
            if (s.get("properties")) |props| {
                var it = props.object.iterator();
                while (it.next()) |kv| {
                    const child = v.object.get(kv.key_ptr.*) orelse continue;
                    if (!try self.node(root, kv.value_ptr.*, child)) return false;
                }
            }
        }
        if (v == .array) if (s.get("items")) |items| for (v.array.items) |item| {
            if (!try self.node(root, items, item)) return false;
        };
        return true;
    }
};

fn jsonEqual(a: std.json.Value, b: std.json.Value) bool {
    return switch (a) {
        .string => |x| b == .string and std.mem.eql(u8, x, b.string),
        .integer => |x| b == .integer and x == b.integer,
        .bool => |x| b == .bool and x == b.bool,
        .null => b == .null,
        else => false,
    };
}

/// Fail the calling test when `payload` does not match the schema. Skips
/// when the schemas directory is not there (a copy of agent/ on its own).
pub fn expectValid(gpa: std.mem.Allocator, event_type: []const u8, payload: []const u8) !void {
    var c = Checker.init(gpa, std.testing.io);
    defer c.deinit();
    c.check(event_type, payload) catch |err| switch (err) {
        error.SchemaMissing => return error.SkipZigTest,
        error.SchemaMismatch => {
            std.debug.print("{s} payload fails its schema at '{s}': {s}\n", .{ event_type, c.reason, payload });
            return err;
        },
        else => return err,
    };
}

/// As `expectValid` for a named schema file (`envelope.v2.json`).
pub fn expectValidFile(gpa: std.mem.Allocator, file: []const u8, payload: []const u8) !void {
    var c = Checker.init(gpa, std.testing.io);
    defer c.deinit();
    c.checkFile(file, payload) catch |err| switch (err) {
        error.SchemaMissing => return error.SkipZigTest,
        error.SchemaMismatch => {
            std.debug.print("{s} fails at '{s}': {s}\n", .{ file, c.reason, payload });
            return err;
        },
        else => return err,
    };
}

pub fn expectInvalid(gpa: std.mem.Allocator, event_type: []const u8, payload: []const u8) !void {
    var c = Checker.init(gpa, std.testing.io);
    defer c.deinit();
    c.check(event_type, payload) catch |err| switch (err) {
        error.SchemaMissing => return error.SkipZigTest,
        error.SchemaMismatch => return,
        else => return err,
    };
    std.debug.print("{s} payload should fail its schema: {s}\n", .{ event_type, payload });
    return error.TestUnexpectedResult;
}

/// Every type with a schema, and its golden payload in schemas/events/golden/.
pub const schema_types = [_][]const u8{
    "process_start",          "process_exit",  "network_connect", "dns_query",
    "file_create",            "registry_set",  "user_logon",      "service_create",
    "powershell_script_block", "agent_health", "sensor_health",
    "agent_tamper",
};

test "golden payloads match their schemas" {
    const gpa = std.testing.allocator;
    var c = Checker.init(gpa, std.testing.io);
    defer c.deinit();
    for (schema_types) |t| {
        const path = try std.fmt.allocPrint(c.arena.allocator(), "{s}/golden/{s}.json", .{ schema_dir, t });
        const text = std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, c.arena.allocator(), .limited(256 * 1024)) catch return error.SkipZigTest;
        try expectValid(gpa, t, text);
    }
}

test "schemas refuse payloads missing required fields" {
    const gpa = std.testing.allocator;
    try expectInvalid(gpa, "process_start", "{\"parent\":{\"pid\":1}}");
    try expectInvalid(gpa, "process_start", "{\"process\":{\"pid\":\"12\"}}");
    try expectInvalid(gpa, "process_start", "{\"process\":{\"pid\":12,\"entity_id\":\"short\"}}");
    try expectInvalid(gpa, "dns_query", "{\"process\":{\"pid\":1}}");
    try expectInvalid(gpa, "file_create", "{\"file\":{\"name\":\"a\"}}");
    try expectValid(gpa, "dns_query", "{\"qname\":\"example.com\"}");
}
