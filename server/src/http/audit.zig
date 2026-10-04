const std = @import("std");
const pg = @import("../db/pg/conn.zig");
const util = @import("util.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn add(
    allocator: std.mem.Allocator,
    io: std.Io,
    conn: *pg.Conn,
    tenant_id: []const u8,
    user_id: ?[]const u8,
    action: []const u8,
    target: ?[]const u8,
    metadata_json: ?[]const u8,
) !void {
    const now = util.nowUnix(io);
    var tbuf: [32]u8 = undefined;
    const occurred = util.formatRfc3339(&tbuf, now);

    var material: std.ArrayList(u8) = .empty;
    defer material.deinit(allocator);
    try material.appendSlice(allocator, tenant_id);
    try material.append(allocator, '|');
    try material.appendSlice(allocator, action);
    try material.append(allocator, '|');
    if (target) |t| try material.appendSlice(allocator, t);
    try material.append(allocator, '|');
    try material.appendSlice(allocator, occurred);

    var dig: [32]u8 = undefined;
    Sha256.hash(material.items, &dig, .{});
    const hash_hex = try util.hexEncode(allocator, &dig);
    defer allocator.free(hash_hex);
    const hash_lit = try std.fmt.allocPrint(allocator, "\\x{s}", .{hash_hex});
    defer allocator.free(hash_lit);

    if (user_id) |uid| {
        try conn.execNoRows(
            \\INSERT INTO audit_log (tenant_id, user_id, action, target, metadata_json, occurred_at, prev_hash, hash)
            \\VALUES ($1::uuid, $2::uuid, $3, $4, $5::jsonb, $6::timestamptz, NULL, $7::bytea)
        , &.{
            .{ .text = tenant_id },
            .{ .text = uid },
            .{ .text = action },
            if (target) |t| .{ .text = t } else .{ .null = {} },
            if (metadata_json) |m| .{ .text = m } else .{ .null = {} },
            .{ .text = occurred },
            .{ .text = hash_lit },
        });
    } else {
        try conn.execNoRows(
            \\INSERT INTO audit_log (tenant_id, user_id, action, target, metadata_json, occurred_at, prev_hash, hash)
            \\VALUES ($1::uuid, NULL, $2, $3, $4::jsonb, $5::timestamptz, NULL, $6::bytea)
        , &.{
            .{ .text = tenant_id },
            .{ .text = action },
            if (target) |t| .{ .text = t } else .{ .null = {} },
            if (metadata_json) |m| .{ .text = m } else .{ .null = {} },
            .{ .text = occurred },
            .{ .text = hash_lit },
        });
    }
}
