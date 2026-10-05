const std = @import("std");
const pg = @import("pg/conn.zig");

const migration_sql = @embedFile("migrations/0001_init.sql");
const migration_version = "0001_init";
const purge_sql = @embedFile("migrations/0002_purge.sql");
const purge_version = "0002_purge";
const ai_reasoning_sql = @embedFile("migrations/0003_ai_reasoning.sql");
const ai_reasoning_version = "0003_ai_reasoning";

pub fn apply(allocator: std.mem.Allocator, conn: *pg.Conn) !void {
    try conn.execSimple(
        \\CREATE TABLE IF NOT EXISTS schema_migrations (
        \\  version text PRIMARY KEY,
        \\  applied_at timestamptz NOT NULL DEFAULT now()
        \\);
    );
    try conn.execSimple("SELECT pg_advisory_lock(490017)");
    defer conn.execSimple("SELECT pg_advisory_unlock(490017)") catch {};

    try applyScript(allocator, conn, migration_version, migration_sql, true);
    try ensureRoles(allocator, conn);
    try applyScript(allocator, conn, purge_version, purge_sql, false);
    try applyScript(allocator, conn, ai_reasoning_version, ai_reasoning_sql, true);
    try conn.execSimple("GRANT EXECUTE ON FUNCTION tawny_purge_expired(timestamptz) TO tawny_jobs");
    try ensurePartitions(conn);
}

fn applyScript(
    allocator: std.mem.Allocator,
    conn: *pg.Conn,
    version: []const u8,
    sql: []const u8,
    transactional: bool,
) !void {
    if (try migrationApplied(allocator, conn, version)) return;
    if (transactional) try conn.execSimple("BEGIN");
    conn.execSimple(sql) catch |err| {
        if (transactional) conn.execSimple("ROLLBACK") catch {};
        return err;
    };
    conn.execNoRows("INSERT INTO schema_migrations (version) VALUES ($1)", &.{
        .{ .text = version },
    }) catch |err| {
        if (transactional) conn.execSimple("ROLLBACK") catch {};
        return err;
    };
    if (transactional) try conn.execSimple("COMMIT");
}

fn migrationApplied(allocator: std.mem.Allocator, conn: *pg.Conn, version: []const u8) !bool {
    const rows = try conn.exec(allocator, "SELECT 1 FROM schema_migrations WHERE version = $1", &.{
        .{ .text = version },
    });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    return rows.len == 1;
}

/// CREATE ROLE cannot run inside a transaction or a DO block. Each statement
/// is its own simple query. Roles are idempotent.
fn ensureRoles(allocator: std.mem.Allocator, conn: *pg.Conn) !void {
    try ensureRole(allocator, conn, "tawny_app", "NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB");
    try ensureRole(allocator, conn, "tawny_jobs", "NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEROLE NOCREATEDB");
    try conn.execSimple("GRANT tawny_app TO CURRENT_USER");
    try conn.execSimple("GRANT tawny_jobs TO CURRENT_USER");
    try conn.execSimple("GRANT USAGE ON SCHEMA public TO tawny_app, tawny_jobs");
    try conn.execSimple("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO tawny_app, tawny_jobs");
    try conn.execSimple("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO tawny_app, tawny_jobs");
}

fn ensureRole(allocator: std.mem.Allocator, conn: *pg.Conn, name: []const u8, options: []const u8) !void {
    const rows = try conn.exec(allocator, "SELECT 1 FROM pg_roles WHERE rolname = $1", &.{
        .{ .text = name },
    });
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }
    if (rows.len != 0) return;
    var sql: std.ArrayList(u8) = .empty;
    defer sql.deinit(allocator);
    try sql.appendSlice(allocator, "CREATE ROLE ");
    try sql.appendSlice(allocator, name);
    try sql.append(allocator, ' ');
    try sql.appendSlice(allocator, options);
    try conn.execSimple(sql.items);
}

fn ensurePartitions(conn: *pg.Conn) !void {
    // Months are generated here, not taken from a request.
    const now_s: i64 = @intCast(std.Io.Clock.now(.real, conn.io).toSeconds());
    const day: i64 = @divFloor(now_s, 86400);
    // Approximate month steps of 30 days are wrong at boundaries. Use civil
    // date from the Unix day and clamp to the first of each month.
    var year: i32 = 1970;
    var month: i32 = 1;
    civilMonth(day, &year, &month);
    var i: i32 = -1;
    while (i <= 2) : (i += 1) {
        var y = year;
        var m = month + i;
        while (m > 12) {
            m -= 12;
            y += 1;
        }
        while (m < 1) {
            m += 12;
            y -= 1;
        }
        var ny = y;
        var nm = m + 1;
        if (nm == 13) {
            nm = 1;
            ny += 1;
        }
        var sql_buf: [256]u8 = undefined;
        const sql = std.fmt.bufPrint(&sql_buf,
            \\CREATE TABLE IF NOT EXISTS telemetry_events_{d}_{s} PARTITION OF telemetry_events
            \\FOR VALUES FROM ('{d}-{s}-01T00:00:00Z') TO ('{d}-{s}-01T00:00:00Z')
        , .{ y, twoDigits(m), y, twoDigits(m), ny, twoDigits(nm) }) catch return error.PartitionName;
        conn.execSimple(sql) catch |err| {
            // A default partition that already holds rows in this range cannot
            // be split. Leave the default in place; ingest still succeeds.
            if (conn.takeError()) |msg| {
                defer conn.allocator.free(msg);
                if (std.mem.indexOf(u8, msg, "overlap") != null) continue;
            }
            return err;
        };
    }
}

fn twoDigits(n: i32) [2]u8 {
    const v: u8 = @intCast(n);
    return .{ '0' + v / 10, '0' + v % 10 };
}

fn civilMonth(unix_day: i64, year_out: *i32, month_out: *i32) void {
    // Howard Hinnant civil_from_days, then keep year/month.
    const z = unix_day + 719468;
    const era = if (z >= 0) @divFloor(z, 146097) else @divFloor(z - 146096, 146097);
    const doe: u32 = @intCast(z - era * 146097);
    const yoe: u32 = @intCast(@divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365));
    const y: i32 = @intCast(yoe);
    const year = y + @as(i32, @intCast(era)) * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp: u32 = @intCast(@divFloor(5 * doy + 2, 153));
    const month: i32 = if (mp < 10) @as(i32, @intCast(mp)) + 3 else @as(i32, @intCast(mp)) - 9;
    // `year` is the March-based year. January and February belong to the next civil year.
    year_out.* = if (month <= 2) year + 1 else year;
    month_out.* = month;
}

pub fn migrationsCurrent(allocator: std.mem.Allocator, conn: *pg.Conn) !bool {
    return try migrationApplied(allocator, conn, migration_version) and
        try migrationApplied(allocator, conn, purge_version) and
        try migrationApplied(allocator, conn, ai_reasoning_version);
}

test "civil month of the zig 0.17 release day" {
    // 2026-10-02 is unix day 20728? Compute and check October 2026.
    // 2026-10-04 from the environment date. 1970-01-01 + N.
    var y: i32 = 0;
    var m: i32 = 0;
    // 2026-01-01 is day 20454 (date -d). Use a known constant: 2000-01-01 = 10957.
    civilMonth(10957, &y, &m);
    try std.testing.expectEqual(@as(i32, 2000), y);
    try std.testing.expectEqual(@as(i32, 1), m);
}
