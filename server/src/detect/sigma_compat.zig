//! Sigma compatibility check. Compiles every rule in the pinned SigmaHQ
//! snapshot (`rules/sigma/sigmahq/`) and counts results by status and reason.
//!
//! Runs as a test from `server/`:
//!   zig test src/main.zig -lc --test-filter "sigma compatibility"
//! With TAWNY_SIGMA_COMPAT_WRITE=1 it rewrites docs/sigma-compatibility.md.
//! It always fails when the supported count (supported plus
//! supported_with_notes) is below rules/sigma/sigmahq/baseline-supported.txt.

const std = @import("std");
const sigma = @import("sigma.zig");

const snapshot_dir = "../rules/sigma/sigmahq/rules/windows/process_creation";
const commit_path = "../rules/sigma/sigmahq/COMMIT";
const baseline_path = "../rules/sigma/sigmahq/baseline-supported.txt";
const report_path = "../docs/sigma-compatibility.md";

pub const Counts = struct {
    total: usize = 0,
    supported: usize = 0,
    notes: usize = 0,
    rejected: usize = 0,
};

const ReasonCount = struct { key: []const u8, n: usize };

fn lessByCount(_: void, a: ReasonCount, b: ReasonCount) bool {
    if (a.n != b.n) return a.n > b.n;
    return std.mem.lessThan(u8, a.key, b.key);
}

/// Detailed reasons are grouped after removing the rule-specific tail, so
/// "unmapped field Foo" and "unmapped field Bar" count separately but the
/// same field across rules counts once per field.
fn reasonKey(arena: std.mem.Allocator, c: sigma.Compiled) ![]const u8 {
    if (std.mem.eql(u8, c.reason_kind, "regex")) {
        const colon = std.mem.lastIndexOf(u8, c.reason, ": ") orelse return c.reason;
        return std.fmt.allocPrint(arena, "regex: {s}", .{c.reason[colon + 2 ..]});
    }
    return c.reason;
}

test "sigma compatibility: SigmaHQ windows process_creation" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var dir = std.Io.Dir.cwd().openDir(io, snapshot_dir, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return, // not run from server/
        else => return err,
    };
    defer dir.close(io);

    const map = try arena.create(sigma.FieldMap);
    map.* = try sigma.FieldMap.load(arena);

    var names: std.ArrayList([]const u8) = .empty;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".yml")) continue;
        try names.append(arena, try arena.dupe(u8, entry.name));
    }
    std.mem.sort([]const u8, names.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);

    var counts: Counts = .{};
    var by_kind: std.StringArrayHashMapUnmanaged(usize) = .empty;
    var by_reason: std.StringArrayHashMapUnmanaged(usize) = .empty;
    var by_note: std.StringArrayHashMapUnmanaged(usize) = .empty;
    for (names.items) |name| {
        const text = try dir.readFileAlloc(io, name, arena, .limited(1 << 20));
        var rule_arena = std.heap.ArenaAllocator.init(gpa);
        defer rule_arena.deinit();
        const out = try sigma.compile(rule_arena.allocator(), map, text);
        counts.total += 1;
        switch (out.status) {
            .supported => counts.supported += 1,
            .supported_with_notes => {
                counts.notes += 1;
                for (out.notes) |n| {
                    const gop = try by_note.getOrPut(arena, try arena.dupe(u8, noteKey(n)));
                    if (!gop.found_existing) gop.value_ptr.* = 0;
                    gop.value_ptr.* += 1;
                }
            },
            .rejected => {
                counts.rejected += 1;
                const k = try by_kind.getOrPut(arena, try arena.dupe(u8, out.reason_kind));
                if (!k.found_existing) k.value_ptr.* = 0;
                k.value_ptr.* += 1;
                const r = try by_reason.getOrPut(arena, try arena.dupe(u8, try reasonKey(rule_arena.allocator(), out)));
                if (!r.found_existing) r.value_ptr.* = 0;
                r.value_ptr.* += 1;
            },
        }
    }
    std.debug.print("sigma_compat total={d} supported={d} supported_with_notes={d} rejected={d}\n", .{
        counts.total, counts.supported, counts.notes, counts.rejected,
    });

    const commit_raw = try std.Io.Dir.cwd().readFileAlloc(io, commit_path, arena, .limited(256));
    const commit = std.mem.trim(u8, commit_raw, " \r\n");

    if (std.testing.environ.getPosix("TAWNY_SIGMA_COMPAT_WRITE")) |flag| {
        if (std.mem.eql(u8, flag, "1")) {
            const doc = try renderReport(arena, commit, counts, &by_kind, &by_reason, &by_note);
            try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = report_path, .data = doc });
            std.debug.print("sigma_compat wrote {s}\n", .{report_path});
        }
    }

    const baseline_raw = try std.Io.Dir.cwd().readFileAlloc(io, baseline_path, arena, .limited(64));
    const baseline = try std.fmt.parseInt(usize, std.mem.trim(u8, baseline_raw, " \r\n"), 10);
    const compiled = counts.supported + counts.notes;
    if (compiled < baseline) {
        std.debug.print("sigma_compat regression: {d} rules compile, baseline is {d}\n", .{ compiled, baseline });
        return error.SigmaCompatibilityRegression;
    }
}

fn noteKey(n: []const u8) []const u8 {
    // Notes name a field or identifier; group by their fixed prefix.
    if (std.mem.startsWith(u8, n, "keyword search")) return "keyword search matches the logsource keyword field only";
    if (std.mem.startsWith(u8, n, "field ")) return "field is not a Sigma field and is used as a Tawny path";
    return n;
}

fn writeTable(w: *std.Io.Writer, arena: std.mem.Allocator, title: []const u8, head: []const u8, map: *std.StringArrayHashMapUnmanaged(usize), limit: usize) !void {
    var rows: std.ArrayList(ReasonCount) = .empty;
    var it = map.iterator();
    while (it.next()) |e| try rows.append(arena, .{ .key = e.key_ptr.*, .n = e.value_ptr.* });
    std.mem.sort(ReasonCount, rows.items, {}, lessByCount);
    try w.print("\n## {s}\n\n| {s} | Rules |\n| --- | ---: |\n", .{ title, head });
    var shown: usize = 0;
    var rest: usize = 0;
    for (rows.items) |r| {
        if (shown < limit) {
            try w.writeAll("| ");
            for (r.key) |ch| {
                if (ch == '|') try w.writeAll("\\|") else try w.writeByte(ch);
            }
            try w.print(" | {d} |\n", .{r.n});
            shown += 1;
        } else rest += r.n;
    }
    if (rest > 0) try w.print("| other ({d} smaller groups) | {d} |\n", .{ rows.items.len - shown, rest });
}

fn renderReport(
    arena: std.mem.Allocator,
    commit: []const u8,
    counts: Counts,
    by_kind: *std.StringArrayHashMapUnmanaged(usize),
    by_reason: *std.StringArrayHashMapUnmanaged(usize),
    by_note: *std.StringArrayHashMapUnmanaged(usize),
) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    try w.print(
        \\# Sigma compatibility
        \\
        \\Generated by `server/src/detect/sigma_compat.zig`. Do not edit by hand. To refresh, from `server/`:
        \\
        \\```sh
        \\TAWNY_SIGMA_COMPAT_WRITE=1 zig test src/main.zig -lc --test-filter "sigma compatibility"
        \\```
        \\
        \\Snapshot: SigmaHQ `rules/windows/process_creation` at commit `{s}` (`rules/sigma/sigmahq/`).
        \\Field and logsource map: `rules/sigma/field-map.yaml`.
        \\
        \\A rule compiles whole or is rejected whole. `supported_with_notes` rules compile, with a note on a
        \\mapping worth knowing (for example `Hashes` split by algorithm). CI fails when the number of rules that
        \\compile (supported plus supported_with_notes) drops below `rules/sigma/sigmahq/baseline-supported.txt`.
        \\
        \\## Counts
        \\
        \\| Status | Rules |
        \\| --- | ---: |
        \\| supported | {d} |
        \\| supported_with_notes | {d} |
        \\| rejected | {d} |
        \\| total | {d} |
        \\
    , .{ commit, counts.supported, counts.notes, counts.rejected, counts.total });
    try writeTable(w, arena, "Rejected by reason class", "Reason class", by_kind, 50);
    try writeTable(w, arena, "Rejected by reason", "Reason", by_reason, 40);
    try writeTable(w, arena, "Notes", "Note", by_note, 20);
    return out.toOwnedSlice();
}
