//! Built-in rules from `rules/builtin/`, seeded into every tenant. Like the
//! threat-intel starter feeds, seeding is idempotent per tenant: a rule is
//! added when the tenant has no row with its `tawny-builtin:` external id.
//! A tenant that disables or edits a built-in keeps its change. Deleting a
//! built-in brings it back on the next seed, so disable it instead.
//!
//! The YAML is embedded from `server/src/detect/builtin/`, a copy of
//! `rules/builtin/` (a test fails when the two differ).

const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("../http/util.zig");
const sigma = @import("sigma.zig");
const tawny_rule = @import("tawny_rule.zig");

pub const files = [_]struct { name: []const u8, text: []const u8 }{
    .{ .name = "failed-logons-then-success.yml", .text = @embedFile("builtin/failed-logons-then-success.yml") },
    .{ .name = "failed-logons-from-one-ip.yml", .text = @embedFile("builtin/failed-logons-from-one-ip.yml") },
    .{ .name = "office-spawns-shell.yml", .text = @embedFile("builtin/office-spawns-shell.yml") },
    .{ .name = "service-in-user-writable-folder.yml", .text = @embedFile("builtin/service-in-user-writable-folder.yml") },
    .{ .name = "encoded-powershell-then-connect.yml", .text = @embedFile("builtin/encoded-powershell-then-connect.yml") },
};

/// Seeding runs once per process and again when the tenant count changes.
var seeded_tenants: ?usize = null;

pub fn ensureSeededOnce(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn) !void {
    const rows = try conn.exec(allocator, "SELECT count(*)::text FROM tenants", &.{});
    defer {
        for (rows) |r| r.deinit(allocator);
        allocator.free(rows);
    }
    const n = std.fmt.parseInt(usize, rows[0].cols[0] orelse "0", 10) catch 0;
    if (seeded_tenants != null and seeded_tenants.? == n) return;
    _ = try ensureSeeded(allocator, io, conn);
    seeded_tenants = n;
}

/// Add missing built-ins to every tenant. Returns how many rows were added.
pub fn ensureSeeded(allocator: std.mem.Allocator, io: std.Io, conn: *pg.Conn) !u32 {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const map = try arena.create(sigma.FieldMap);
    map.* = try sigma.FieldMap.load(arena);
    var compiled: [files.len]tawny_rule.Compiled = undefined;
    for (files, 0..) |f, i| {
        compiled[i] = try tawny_rule.compile(arena, map, f.text);
        if (!compiled[i].ok) {
            std.debug.print("builtin rule {s} does not compile: {s}\n", .{ f.name, compiled[i].reason });
            return error.BuiltinRuleInvalid;
        }
    }
    const tenants = try conn.exec(allocator, "SELECT id::text FROM tenants", &.{});
    defer {
        for (tenants) |r| r.deinit(allocator);
        allocator.free(tenants);
    }
    var added: u32 = 0;
    for (tenants) |trow| {
        const tenant = trow.cols[0] orelse continue;
        for (files, 0..) |f, i| {
            const c = compiled[i];
            var idbuf: [36]u8 = undefined;
            const id = util.newUuid(io, &idbuf);
            const mitre = try util.pgArrayText(arena, c.mitre);
            const format: []const u8 = @tagName(c.kind);
            const event_type: ?[]const u8 = switch (c.rule) {
                .atomic => |a| a.event_type,
                .threshold => |t| t.event_type,
                .sequence => null,
            };
            const rows = try conn.exec(allocator,
                \\INSERT INTO alert_rules (id, tenant_id, name, format, external_id, description, event_type, severity,
                \\  operator, source_definition, compiled_expression_json, compile_status, mitre_techniques,
                \\  is_enabled, created_at, updated_at)
                \\VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, 'exists', $9, $10::jsonb, 'supported', $11::text[],
                \\  true, now(), now())
                \\ON CONFLICT (tenant_id, external_id) WHERE external_id LIKE 'tawny-builtin:%' DO NOTHING
                \\RETURNING id::text
            , &.{
                .{ .text = id },
                .{ .text = tenant },
                .{ .text = c.title },
                .{ .text = format },
                .{ .text = c.id },
                if (c.description) |d| .{ .text = d } else .{ .null = {} },
                if (event_type) |e| .{ .text = e } else .{ .null = {} },
                .{ .text = c.severity },
                .{ .text = f.text },
                .{ .text = c.json },
                .{ .text = mitre },
            });
            defer {
                for (rows) |r| r.deinit(allocator);
                allocator.free(rows);
            }
            added += @intCast(rows.len);
        }
    }
    if (added > 0) std.debug.print("builtin rules seeded {d}\n", .{added});
    return added;
}

test "builtin rules compile and match rules/builtin" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const map = try arena.create(sigma.FieldMap);
    map.* = try sigma.FieldMap.load(arena);
    for (files) |f| {
        const c = try tawny_rule.compile(arena, map, f.text);
        if (!c.ok) std.debug.print("{s}: {s}\n", .{ f.name, c.reason });
        try std.testing.expect(c.ok);
        try std.testing.expect(std.mem.startsWith(u8, c.id, "tawny-builtin:"));
        const path = try std.fmt.allocPrint(arena, "../rules/builtin/{s}", .{f.name});
        const repo = std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, arena, .limited(1 << 20)) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        try std.testing.expectEqualStrings(f.text, repo);
    }
    // Every file in rules/builtin is embedded.
    var dir = std.Io.Dir.cwd().openDir(std.testing.io, "../rules/builtin", .{ .iterate = true }) catch return;
    defer dir.close(std.testing.io);
    var it = dir.iterate();
    var n: usize = 0;
    while (try it.next(std.testing.io)) |e| {
        if (std.mem.endsWith(u8, e.name, ".yml")) n += 1;
    }
    try std.testing.expectEqual(files.len, n);
}
