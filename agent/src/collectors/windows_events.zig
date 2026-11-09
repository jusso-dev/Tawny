//! Windows event log telemetry: Sysmon, Security, System and PowerShell.
//!
//! Everything except `Collector` and `dumpCommand` is pure (no Windows calls),
//! so the mappers, the 4104 script block reassembly, the health tracker and
//! the drop counters are tested on every host. Payload field names follow
//! docs/architecture/target-edr.md section 2.2 (`process.image`,
//! `parent.image`, `network.dst_ip`, `dns.query`, `registry.key`, ...).
const std = @import("std");
const builtin = @import("builtin");
const evtxml = @import("../platform/windows/evtxml.zig");
const privacy = @import("privacy.zig");
const entity = @import("../entity.zig");
const schema_check = @import("../schema_check.zig");
const iox = @import("../io_compat.zig");
const eventlog = if (builtin.target.os.tag == .windows) @import("../platform/windows/eventlog.zig") else struct {};
const tamper = @import("../tamper.zig");

const Jw = std.json.Stringify;

/// Hard cap on rendered events handled per channel per tick. Events past the
/// cap stay in the subscription and are read on the next tick.
pub const max_events_per_channel_tick: usize = 512;
/// Reassembled script blocks larger than this are cut and marked truncated.
pub const max_script_block_bytes: usize = 64 * 1024;
/// Script blocks waiting for their remaining parts.
pub const max_pending_script_blocks: usize = 64;
/// Parts kept per script block; later parts are counted but not stored.
pub const max_script_block_parts: usize = 256;
/// A partial script block is flushed this long after its first part.
pub const script_block_flush_seconds: i64 = 30;
/// A channel that delivers nothing for this long is reported silent.
pub const channel_silence_seconds: i64 = 15 * 60;
const max_field_bytes: usize = 2048;
const max_registry_data_bytes: usize = 1024;

// ---------------------------------------------------------------------------
// Channels

pub const Source = enum { sysmon, security, system, powershell, defender };

pub const Channel = struct {
    source: Source,
    path: []const u8,
    /// XPath event filter (no time bound).
    event_filter: []const u8,
};

pub const channels = [_]Channel{
    .{
        .source = .sysmon,
        .path = "Microsoft-Windows-Sysmon/Operational",
        .event_filter = "EventID=1 or EventID=3 or EventID=5 or EventID=7 or EventID=8 or EventID=10 or EventID=11 or EventID=12 or EventID=13 or EventID=14 or EventID=22 or EventID=23 or EventID=26",
    },
    .{
        .source = .security,
        .path = "Security",
        .event_filter = "EventID=4624 or EventID=4625 or EventID=4672 or EventID=4688",
    },
    .{
        .source = .system,
        .path = "System",
        .event_filter = "EventID=7045",
    },
    .{
        .source = .powershell,
        .path = "Microsoft-Windows-PowerShell/Operational",
        .event_filter = "EventID=4104",
    },
    // Defender configuration changes (#58). Only 5007 entries that add an
    // exclusion covering a Tawny path become events (agent_tamper).
    .{
        .source = .defender,
        .path = "Microsoft-Windows-Windows Defender/Operational",
        .event_filter = "EventID=5007",
    },
};

/// XPath query for one channel. `since_ms` bounds the query to recent events
/// (debug dump only); the agent itself relies on bookmarks.
pub fn buildQuery(alloc: std.mem.Allocator, ch: Channel, since_ms: ?u64) ![]u8 {
    if (since_ms) |ms| {
        return alloc.print("*[System[({s}) and TimeCreated[timediff(@SystemTime) <= {d}]]]", .{ ch.event_filter, ms });
    }
    return alloc.print("*[System[({s})]]", .{ch.event_filter});
}

pub fn sourceForChannel(path: []const u8) ?Source {
    for (channels) |ch| {
        if (std.ascii.eqlIgnoreCase(ch.path, path)) return ch.source;
    }
    return null;
}

/// File name for a channel's bookmark under the agent state directory.
/// `Microsoft-Windows-Sysmon/Operational` -> `eventlog-microsoft-windows-sysmon-operational.bookmark`.
pub fn bookmarkFileName(alloc: std.mem.Allocator, channel_path: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.appendSlice(alloc, "eventlog-");
    for (channel_path) |c| {
        try out.append(alloc, if (std.ascii.isAlphanumeric(c)) std.ascii.toLower(c) else '-');
    }
    try out.appendSlice(alloc, ".bookmark");
    return out.toOwnedSlice(alloc);
}

// ---------------------------------------------------------------------------
// Output items

pub const Item = struct {
    event_type: []const u8,
    occurred_at: i64,
    /// Derived from (channel, record id, time) so a replay after restart is
    /// deduplicated by the server. All zero means "pick a random id".
    client_event_id: [16]u8,
    payload: []u8,
};

pub fn freeItems(alloc: std.mem.Allocator, items: []Item) void {
    for (items) |it| alloc.free(it.payload);
    alloc.free(items);
}

/// Stable per-record id. Record ids restart when a log is recreated, so the
/// event time is part of the key.
pub fn recordEventId(channel: []const u8, record_id: u64, time_created: []const u8) [16]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("tawny-eventlog\x00");
    h.update(channel);
    h.update("\x00");
    var rid: [8]u8 = undefined;
    std.mem.writeInt(u64, &rid, record_id, .little);
    h.update(&rid);
    h.update(time_created);
    var digest: [32]u8 = undefined;
    h.final(&digest);
    var id: [16]u8 = digest[0..16].*;
    // RFC 9562 version 8 (custom), variant 10.
    id[6] = (id[6] & 0x0f) | 0x80;
    id[8] = (id[8] & 0x3f) | 0x80;
    return id;
}

/// `2026-11-09T01:12:44.5512031Z` -> unix seconds.
pub fn parseSystemTime(s: []const u8) ?i64 {
    if (s.len < 19 or s[4] != '-' or s[7] != '-' or (s[10] != 'T' and s[10] != ' ') or s[13] != ':' or s[16] != ':') return null;
    const y = std.fmt.parseInt(i64, s[0..4], 10) catch return null;
    const m = std.fmt.parseInt(u8, s[5..7], 10) catch return null;
    const d = std.fmt.parseInt(u8, s[8..10], 10) catch return null;
    const hh = std.fmt.parseInt(i64, s[11..13], 10) catch return null;
    const mm = std.fmt.parseInt(i64, s[14..16], 10) catch return null;
    const ss = std.fmt.parseInt(i64, s[17..19], 10) catch return null;
    if (m < 1 or m > 12 or d < 1 or d > 31 or hh > 23 or mm > 59 or ss > 60) return null;
    // Howard Hinnant's days_from_civil.
    const yy = if (m <= 2) y - 1 else y;
    const era = @divFloor(yy, 400);
    const yoe = yy - era * 400;
    const mp: i64 = if (m > 2) m - 3 else m + 9;
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    return days * 86400 + hh * 3600 + mm * 60 + ss;
}

// ---------------------------------------------------------------------------
// Drop counters

pub const Counters = struct {
    /// Events mapped and handed to the agent buffer.
    emitted: u64 = 0,
    /// Rendered XML that did not parse.
    dropped_parse: u64 = 0,
    /// Events whose payload could not be built.
    dropped_map: u64 = 0,
    /// Events the agent buffer refused (spool full, too large).
    dropped_queue: u64 = 0,
    /// Event IDs that reached the collector but have no mapper.
    dropped_unmapped: u64 = 0,
    /// Script block parts thrown away because the pending map was full.
    dropped_script_parts: u64 = 0,
    /// Security 4688 skipped because Sysmon 1 covers process creation.
    skipped_4688_with_sysmon: u64 = 0,
    /// Ticks that stopped reading a channel at the per-tick cap.
    capped_ticks: u64 = 0,

    pub fn totalDropped(self: Counters) u64 {
        return self.dropped_parse + self.dropped_map + self.dropped_queue + self.dropped_unmapped + self.dropped_script_parts;
    }

    pub fn write(self: Counters, jw: *Jw) !void {
        try jw.objectField("counters");
        try jw.beginObject();
        inline for (comptime std.meta.fieldNames(Counters)) |name| {
            try jw.objectField(name);
            try jw.write(@field(self, name));
        }
        try jw.endObject();
    }
};

// ---------------------------------------------------------------------------
// Mapping

pub const Mapped = struct {
    event_type: []const u8,
    payload: []u8,
};

/// Entity table for the mapping call in progress (set by `mapEventWith`).
/// Mapping is synchronous, so a thread-local keeps the helper signatures as
/// they are.
threadlocal var map_entities: ?*entity.Table = null;

/// Map one parsed event to a Tawny event type and JSON payload. Returns null
/// for event IDs this collector does not handle. Script blocks (4104) go
/// through `ScriptBlocks` instead.
pub fn mapEvent(alloc: std.mem.Allocator, ev: *const evtxml.Event) !?Mapped {
    return mapEventWith(alloc, ev, null);
}

/// As `mapEvent`, filling `process.entity_id` and `parent.entity_id` from
/// `table`. Process starts (Sysmon 1, Security 4688) are recorded in the table
/// first, so later events for the same pid and Sysmon ProcessGuid get the id.
pub fn mapEventWith(alloc: std.mem.Allocator, ev: *const evtxml.Event, table: ?*entity.Table) !?Mapped {
    map_entities = table;
    defer map_entities = null;
    const source = sourceForChannel(ev.channel) orelse return null;
    const event_type: []const u8 = switch (source) {
        .sysmon => switch (ev.event_id) {
            1 => "process_start",
            3 => "network_connect",
            5 => "process_exit",
            7 => "image_load",
            8 => "remote_thread",
            10 => "process_access",
            11 => "file_create",
            12 => if (isRegistryDelete(ev)) "registry_delete" else "registry_create",
            13 => "registry_set",
            14 => "registry_rename",
            22 => "dns_query",
            23, 26 => "file_delete",
            else => return null,
        },
        .security => switch (ev.event_id) {
            4624 => "user_logon",
            4625 => "user_logon_failed",
            4672 => "special_privileges",
            4688 => "process_start",
            else => return null,
        },
        .system => switch (ev.event_id) {
            7045 => "service_create",
            else => return null,
        },
        .powershell, .defender => return null,
    };

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    var jw: Jw = .{ .writer = &out.writer };
    try jw.beginObject();
    try writeEnvelope(&jw, source, ev);
    switch (source) {
        .sysmon => switch (ev.event_id) {
            1 => try mapSysmon1(alloc, &jw, ev),
            3 => try mapSysmon3(&jw, ev),
            5 => try mapSysmon5(&jw, ev),
            7 => try mapSysmon7(&jw, ev),
            8 => try mapSysmon8(&jw, ev),
            10 => try mapSysmon10(&jw, ev),
            11 => try mapSysmon11(&jw, ev),
            12 => try mapSysmon12(&jw, ev),
            13 => try mapSysmon13(&jw, ev),
            14 => try mapSysmon14(&jw, ev),
            22 => try mapSysmon22(&jw, ev),
            23 => try mapSysmon23(&jw, ev),
            26 => try mapSysmon26(&jw, ev),
            else => unreachable,
        },
        .security => switch (ev.event_id) {
            4624 => try mapSecurity4624(&jw, ev),
            4625 => try mapSecurity4625(&jw, ev),
            4672 => try mapSecurity4672(&jw, ev),
            4688 => try mapSecurity4688(alloc, &jw, ev),
            else => unreachable,
        },
        .system => try mapSystem7045(alloc, &jw, ev),
        .powershell, .defender => unreachable,
    }
    try jw.endObject();
    return .{ .event_type = event_type, .payload = try out.toOwnedSlice() };
}

fn writeEnvelope(jw: *Jw, source: Source, ev: *const evtxml.Event) !void {
    try jw.objectField("sensor");
    try jw.write(@tagName(source));
    try jw.objectField("channel");
    try jw.write(ev.channel);
    try jw.objectField("event_id");
    try jw.write(ev.event_id);
    try jw.objectField("record_id");
    try jw.write(ev.record_id);
    try str(jw, "ts", ev.time_created);
    try str(jw, "rule_name", ev.get("RuleName"));
}

/// Sysmon 1: process create.
fn mapSysmon1(alloc: std.mem.Allocator, jw: *Jw, ev: *const evtxml.Event) !void {
    // Sysmon UtcTime is the process creation time (millisecond precision).
    const start = entity.parseIso(ev.get("UtcTime") orelse "");
    _ = try observeStart(ev.get("ProcessId"), start, ev.get("ProcessGuid"));
    try jw.objectField("process");
    try jw.beginObject();
    try sysmonProcessCore(jw, ev, "ProcessGuid", "ProcessId", "Image", "User");
    try commandLine(alloc, jw, "command_line", ev.get("CommandLine"));
    try str(jw, "cwd", ev.get("CurrentDirectory"));
    try sysmonStartTime(jw, ev.get("UtcTime"));
    try int(jw, "session_id", ev.get("TerminalSessionId"));
    try str(jw, "integrity_level", ev.get("IntegrityLevel"));
    try str(jw, "logon_id", ev.get("LogonId"));
    try str(jw, "original_file_name", ev.get("OriginalFileName"));
    try str(jw, "company", ev.get("Company"));
    try str(jw, "description", ev.get("Description"));
    try hashes(jw, ev.get("Hashes"));
    try jw.endObject();

    try jw.objectField("parent");
    try jw.beginObject();
    try sysmonProcessCoreAt(jw, ev, "ParentProcessGuid", "ParentProcessId", "ParentImage", "ParentUser", start orelse std.math.maxInt(u64));
    try commandLine(alloc, jw, "command_line", ev.get("ParentCommandLine"));
    try jw.endObject();
}

/// Sysmon 3: network connection.
fn mapSysmon3(jw: *Jw, ev: *const evtxml.Event) !void {
    try sysmonProcess(jw, ev);
    try jw.objectField("network");
    try jw.beginObject();
    try str(jw, "protocol", ev.get("Protocol"));
    const initiated = ev.get("Initiated") orelse "";
    try jw.objectField("direction");
    try jw.write(if (std.ascii.eqlIgnoreCase(initiated, "true")) "outbound" else "inbound");
    try str(jw, "src_ip", ev.get("SourceIp"));
    try int(jw, "src_port", ev.get("SourcePort"));
    try str(jw, "src_hostname", ev.get("SourceHostname"));
    try str(jw, "dst_ip", ev.get("DestinationIp"));
    try int(jw, "dst_port", ev.get("DestinationPort"));
    try str(jw, "dst_hostname", ev.get("DestinationHostname"));
    try str(jw, "dst_port_name", ev.get("DestinationPortName"));
    try boolField(jw, "ipv6", ev.get("DestinationIsIpv6"));
    try jw.endObject();
}

/// Sysmon 5: process terminated.
fn mapSysmon5(jw: *Jw, ev: *const evtxml.Event) !void {
    try sysmonProcess(jw, ev);
}

/// Sysmon 7: image loaded.
fn mapSysmon7(jw: *Jw, ev: *const evtxml.Event) !void {
    try sysmonProcess(jw, ev);
    try jw.objectField("file");
    try jw.beginObject();
    try pathFields(jw, ev.get("ImageLoaded"));
    try str(jw, "original_file_name", ev.get("OriginalFileName"));
    try str(jw, "company", ev.get("Company"));
    try hashes(jw, ev.get("Hashes"));
    try jw.objectField("signature");
    try jw.beginObject();
    try boolField(jw, "signed", ev.get("Signed"));
    try str(jw, "status", ev.get("SignatureStatus"));
    try str(jw, "signer", ev.get("Signature"));
    try jw.endObject();
    try jw.endObject();
}

/// Sysmon 8: CreateRemoteThread.
fn mapSysmon8(jw: *Jw, ev: *const evtxml.Event) !void {
    try jw.objectField("process");
    try jw.beginObject();
    try sysmonProcessCore(jw, ev, "SourceProcessGuid", "SourceProcessId", "SourceImage", "SourceUser");
    try jw.endObject();
    try jw.objectField("target");
    try jw.beginObject();
    try sysmonProcessCore(jw, ev, "TargetProcessGuid", "TargetProcessId", "TargetImage", "TargetUser");
    try jw.endObject();
    try jw.objectField("thread");
    try jw.beginObject();
    try int(jw, "id", ev.get("NewThreadId"));
    try str(jw, "start_address", ev.get("StartAddress"));
    try str(jw, "start_module", ev.get("StartModule"));
    try str(jw, "start_function", ev.get("StartFunction"));
    try jw.endObject();
}

/// Sysmon 10: process accessed (handle opened to another process).
fn mapSysmon10(jw: *Jw, ev: *const evtxml.Event) !void {
    try jw.objectField("process");
    try jw.beginObject();
    try sysmonProcessCore(jw, ev, "SourceProcessGUID", "SourceProcessId", "SourceImage", "SourceUser");
    try int(jw, "thread_id", ev.get("SourceThreadId"));
    try jw.endObject();
    try jw.objectField("target");
    try jw.beginObject();
    try sysmonProcessCore(jw, ev, "TargetProcessGUID", "TargetProcessId", "TargetImage", "TargetUser");
    try jw.endObject();
    try str(jw, "granted_access", ev.get("GrantedAccess"));
    try str(jw, "call_trace", ev.get("CallTrace"));
}

/// Sysmon 11: file created.
fn mapSysmon11(jw: *Jw, ev: *const evtxml.Event) !void {
    try sysmonProcess(jw, ev);
    try jw.objectField("file");
    try jw.beginObject();
    try pathFields(jw, ev.get("TargetFilename"));
    try str(jw, "creation_time", ev.get("CreationUtcTime"));
    try jw.endObject();
}

fn isRegistryDelete(ev: *const evtxml.Event) bool {
    const kind = ev.get("EventType") orelse return false;
    return std.ascii.startsWithIgnoreCase(kind, "Delete");
}

/// Sysmon 12: registry key or value created or deleted.
fn mapSysmon12(jw: *Jw, ev: *const evtxml.Event) !void {
    try sysmonProcess(jw, ev);
    try jw.objectField("registry");
    try jw.beginObject();
    const kind = ev.get("EventType") orelse "";
    const target = ev.get("TargetObject");
    if (std.ascii.endsWithIgnoreCase(kind, "Value")) {
        try registryKeyValue(jw, target);
    } else {
        try str(jw, "key", target);
    }
    try str(jw, "operation", ev.get("EventType"));
    try jw.endObject();
}

/// Sysmon 13: registry value set.
fn mapSysmon13(jw: *Jw, ev: *const evtxml.Event) !void {
    try sysmonProcess(jw, ev);
    try jw.objectField("registry");
    try jw.beginObject();
    try registryKeyValue(jw, ev.get("TargetObject"));
    if (ev.get("Details")) |details| {
        const value_type = registryValueType(details);
        if (value_type) |t| {
            try jw.objectField("value_type");
            try jw.write(t);
        }
        const truncated = details.len > max_registry_data_bytes;
        try jw.objectField("data");
        try jw.write(truncUtf8(details, max_registry_data_bytes));
        if (truncated) {
            try jw.objectField("data_truncated");
            try jw.write(true);
        }
    }
    try str(jw, "operation", ev.get("EventType"));
    try jw.endObject();
}

/// Sysmon 14: registry key or value renamed.
fn mapSysmon14(jw: *Jw, ev: *const evtxml.Event) !void {
    try sysmonProcess(jw, ev);
    try jw.objectField("registry");
    try jw.beginObject();
    try str(jw, "key", ev.get("TargetObject"));
    try str(jw, "new_name", ev.get("NewName"));
    try str(jw, "operation", ev.get("EventType"));
    try jw.endObject();
}

/// Sysmon 22: DNS query.
fn mapSysmon22(jw: *Jw, ev: *const evtxml.Event) !void {
    try sysmonProcess(jw, ev);
    try jw.objectField("dns");
    try jw.beginObject();
    try str(jw, "query", ev.get("QueryName"));
    try int(jw, "status", ev.get("QueryStatus"));
    try jw.objectField("answers");
    try jw.beginArray();
    if (ev.get("QueryResults")) |results| {
        var it = std.mem.tokenizeScalar(u8, results, ';');
        var count: usize = 0;
        while (it.next()) |raw| : (count += 1) {
            if (count >= 64) break;
            const answer = dnsAnswer(raw) orelse continue;
            try jw.write(answer);
        }
    }
    try jw.endArray();
    try jw.endObject();
    // Existing DNS rules and IOC matching read the top-level qname.
    try str(jw, "qname", ev.get("QueryName"));
}

/// `type:  5 edge.example.net` -> `edge.example.net`; `::ffff:1.2.3.4` -> `1.2.3.4`.
fn dnsAnswer(raw: []const u8) ?[]const u8 {
    var s = std.mem.trim(u8, raw, " \t");
    if (std.mem.startsWith(u8, s, "type:")) {
        const last_space = std.mem.lastIndexOfScalar(u8, s, ' ') orelse return null;
        s = s[last_space + 1 ..];
    }
    if (std.ascii.startsWithIgnoreCase(s, "::ffff:") and std.mem.indexOfScalar(u8, s[7..], ':') == null) s = s[7..];
    return if (s.len == 0) null else s;
}

/// Sysmon 23: file deleted and archived.
fn mapSysmon23(jw: *Jw, ev: *const evtxml.Event) !void {
    try fileDelete(jw, ev);
    try boolField(jw, "archived", ev.get("Archived"));
}

/// Sysmon 26: file delete logged (not archived).
fn mapSysmon26(jw: *Jw, ev: *const evtxml.Event) !void {
    try fileDelete(jw, ev);
    try jw.objectField("archived");
    try jw.write(false);
}

fn fileDelete(jw: *Jw, ev: *const evtxml.Event) !void {
    try sysmonProcess(jw, ev);
    try jw.objectField("file");
    try jw.beginObject();
    try pathFields(jw, ev.get("TargetFilename"));
    try hashes(jw, ev.get("Hashes"));
    try boolField(jw, "is_executable", ev.get("IsExecutable"));
    try jw.endObject();
}

/// Security 4624: successful logon.
fn mapSecurity4624(jw: *Jw, ev: *const evtxml.Event) !void {
    try securityUser(jw, "user", ev, "TargetUserName", "TargetDomainName", "TargetUserSid");
    try securityUser(jw, "subject", ev, "SubjectUserName", "SubjectDomainName", "SubjectUserSid");
    try jw.objectField("logon");
    try jw.beginObject();
    try str(jw, "id", ev.get("TargetLogonId"));
    try logonType(jw, ev.get("LogonType"));
    try strTrim(jw, "process", ev.get("LogonProcessName"));
    try str(jw, "auth_package", ev.get("AuthenticationPackageName"));
    try str(jw, "workstation", ev.get("WorkstationName"));
    if (ev.get("ElevatedToken")) |e| {
        try jw.objectField("elevated");
        try jw.write(std.mem.eql(u8, e, "%%1842"));
    }
    try jw.endObject();
    try sourceNetwork(jw, ev);
    try securityProcess(jw, ev, "ProcessId", "ProcessName");
}

/// Security 4625: failed logon.
fn mapSecurity4625(jw: *Jw, ev: *const evtxml.Event) !void {
    try securityUser(jw, "user", ev, "TargetUserName", "TargetDomainName", "TargetUserSid");
    try jw.objectField("logon");
    try jw.beginObject();
    try logonType(jw, ev.get("LogonType"));
    try strTrim(jw, "process", ev.get("LogonProcessName"));
    try str(jw, "auth_package", ev.get("AuthenticationPackageName"));
    try str(jw, "workstation", ev.get("WorkstationName"));
    try str(jw, "status", ev.get("Status"));
    try str(jw, "sub_status", ev.get("SubStatus"));
    if (ev.get("SubStatus")) |sub| {
        if (logonFailureReason(sub)) |reason| {
            try jw.objectField("failure_reason");
            try jw.write(reason);
        }
    }
    try jw.endObject();
    try sourceNetwork(jw, ev);
    try securityProcess(jw, ev, "ProcessId", "ProcessName");
}

/// Security 4672: special privileges assigned to a new logon.
fn mapSecurity4672(jw: *Jw, ev: *const evtxml.Event) !void {
    try securityUser(jw, "user", ev, "SubjectUserName", "SubjectDomainName", "SubjectUserSid");
    try jw.objectField("logon");
    try jw.beginObject();
    try str(jw, "id", ev.get("SubjectLogonId"));
    try jw.endObject();
    try jw.objectField("privileges");
    try jw.beginArray();
    if (ev.get("PrivilegeList")) |list| {
        var it = std.mem.tokenizeAny(u8, list, " \t\r\n");
        var count: usize = 0;
        while (it.next()) |p| : (count += 1) {
            if (count >= 64) break;
            try jw.write(p);
        }
    }
    try jw.endArray();
}

/// Security 4688: process creation (fallback when Sysmon is missing).
fn mapSecurity4688(alloc: std.mem.Allocator, jw: *Jw, ev: *const evtxml.Event) !void {
    // 4688 is logged as the process is created; TimeCreated stands in for
    // the creation FILETIME.
    const start = entity.parseIso(ev.time_created);
    const id = try observeStart(ev.get("NewProcessId"), start, null);
    try jw.objectField("process");
    try jw.beginObject();
    try entityField(jw, id);
    try hexOrInt(jw, "pid", ev.get("NewProcessId"));
    if (start) |t| {
        var buf: [24]u8 = undefined;
        try jw.objectField("start_time");
        try jw.write(entity.formatIso(&buf, t));
    }
    try pathAsImage(jw, ev.get("NewProcessName"));
    try commandLine(alloc, jw, "command_line", ev.get("CommandLine"));
    // TargetUser* is filled when the process runs as a different account.
    const target_name = ev.get("TargetUserName");
    if (target_name != null and !isEmptyValue(target_name.?)) {
        try securityUser(jw, "user", ev, "TargetUserName", "TargetDomainName", "TargetUserSid");
    } else {
        try securityUser(jw, "user", ev, "SubjectUserName", "SubjectDomainName", "SubjectUserSid");
    }
    try str(jw, "logon_id", ev.get("SubjectLogonId"));
    if (ev.get("MandatoryLabel")) |label| {
        if (integrityFromLabel(label)) |level| {
            try jw.objectField("integrity_level");
            try jw.write(level);
        }
    }
    if (ev.get("TokenElevationType")) |t| {
        if (elevationType(t)) |name| {
            try jw.objectField("elevation_type");
            try jw.write(name);
            try jw.objectField("elevated");
            try jw.write(std.mem.eql(u8, name, "full"));
        }
    }
    try jw.endObject();
    try jw.objectField("parent");
    try jw.beginObject();
    try entityField(jw, lookupEntity(ev.get("ProcessId"), null, start orelse std.math.maxInt(u64)));
    try hexOrInt(jw, "pid", ev.get("ProcessId"));
    try pathAsImage(jw, ev.get("ParentProcessName"));
    try jw.endObject();
}

/// System 7045: a service was installed.
fn mapSystem7045(alloc: std.mem.Allocator, jw: *Jw, ev: *const evtxml.Event) !void {
    try jw.objectField("service");
    try jw.beginObject();
    try str(jw, "name", ev.get("ServiceName"));
    try commandLine(alloc, jw, "image_path", ev.get("ImagePath"));
    try str(jw, "type", ev.get("ServiceType"));
    try str(jw, "start_type", ev.get("StartType"));
    try str(jw, "account", ev.get("AccountName"));
    try jw.endObject();
    if (ev.user_sid.len > 0) {
        try jw.objectField("user");
        try jw.beginObject();
        try str(jw, "sid", ev.user_sid);
        try jw.endObject();
    }
}

// --- field helpers ---------------------------------------------------------

fn isEmptyValue(v: []const u8) bool {
    return v.len == 0 or std.mem.eql(u8, v, "-");
}

fn str(jw: *Jw, key: []const u8, value: ?[]const u8) !void {
    const v = value orelse return;
    if (isEmptyValue(v)) return;
    try jw.objectField(key);
    try jw.write(truncUtf8(v, max_field_bytes));
}

fn strTrim(jw: *Jw, key: []const u8, value: ?[]const u8) !void {
    const v = value orelse return;
    try str(jw, key, std.mem.trim(u8, v, " \t"));
}

fn int(jw: *Jw, key: []const u8, value: ?[]const u8) !void {
    const v = value orelse return;
    const n = std.fmt.parseInt(i64, std.mem.trim(u8, v, " "), 10) catch return;
    try jw.objectField(key);
    try jw.write(n);
}

/// Security log ids are rendered as `0x1abc`.
fn hexOrInt(jw: *Jw, key: []const u8, value: ?[]const u8) !void {
    const n = parseHexOrDec(value orelse return) orelse return;
    try jw.objectField(key);
    try jw.write(n);
}

fn parseHexOrDec(v: []const u8) ?u64 {
    const t = std.mem.trim(u8, v, " ");
    if (std.ascii.startsWithIgnoreCase(t, "0x")) return std.fmt.parseInt(u64, t[2..], 16) catch null;
    return std.fmt.parseInt(u64, t, 10) catch null;
}

fn boolField(jw: *Jw, key: []const u8, value: ?[]const u8) !void {
    const v = value orelse return;
    const b = if (std.ascii.eqlIgnoreCase(v, "true")) true else if (std.ascii.eqlIgnoreCase(v, "false")) false else return;
    try jw.objectField(key);
    try jw.write(b);
}

fn commandLine(alloc: std.mem.Allocator, jw: *Jw, key: []const u8, value: ?[]const u8) !void {
    const v = value orelse return;
    if (isEmptyValue(v)) return;
    const safe = try privacy.sanitizeCommandLine(alloc, v);
    defer alloc.free(safe);
    try jw.objectField(key);
    try jw.write(safe);
}

fn basename(path: []const u8) []const u8 {
    const i = std.mem.lastIndexOfAny(u8, path, "\\/") orelse return path;
    return path[i + 1 ..];
}

fn extension(name: []const u8) ?[]const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse return null;
    if (dot == 0 or dot + 1 >= name.len) return null;
    return name[dot + 1 ..];
}

/// `image` plus `name` from a full image path.
fn pathAsImage(jw: *Jw, value: ?[]const u8) !void {
    const v = value orelse return;
    if (isEmptyValue(v)) return;
    try str(jw, "image", v);
    try str(jw, "name", basename(v));
}

/// `path`, `name`, `extension` from a file path.
fn pathFields(jw: *Jw, value: ?[]const u8) !void {
    const v = value orelse return;
    if (isEmptyValue(v)) return;
    const name = basename(v);
    try str(jw, "path", v);
    try str(jw, "name", name);
    if (extension(name)) |ext| {
        var lower: [32]u8 = undefined;
        if (ext.len <= lower.len) {
            try jw.objectField("extension");
            try jw.write(std.ascii.lowerString(&lower, ext));
        }
    }
}

/// Sysmon `DOMAIN\name` -> `user{name,domain}`.
fn sysmonUser(jw: *Jw, value: ?[]const u8) !void {
    const v = value orelse return;
    if (isEmptyValue(v)) return;
    try jw.objectField("user");
    try jw.beginObject();
    if (std.mem.indexOfScalar(u8, v, '\\')) |sep| {
        try str(jw, "name", v[sep + 1 ..]);
        try str(jw, "domain", v[0..sep]);
    } else {
        try str(jw, "name", v);
    }
    try jw.endObject();
}

/// Record a process start in the entity table and return its id.
fn observeStart(pid_text: ?[]const u8, start_100ns: ?u64, guid: ?[]const u8) !?entity.Id {
    const t = map_entities orelse return null;
    const pid = parseHexOrDec(pid_text orelse return null) orelse return null;
    const start = start_100ns orelse return null;
    return try t.observe(@intCast(@min(pid, std.math.maxInt(u32))), start, guid orelse "");
}

/// Entity holding `pid` now. With `child_start`, the holder must have started
/// no later than the child (the parent case).
fn lookupEntity(pid_text: ?[]const u8, guid: ?[]const u8, child_start: ?u64) ?entity.Id {
    const t = map_entities orelse return null;
    const pid64 = parseHexOrDec(pid_text orelse return null) orelse return null;
    if (pid64 == 0 or pid64 > std.math.maxInt(u32)) return null;
    const pid: u32 = @intCast(pid64);
    const g = guid orelse "";
    if (t.lookup(pid, if (isEmptyValue(g)) "" else g) == null) return null;
    if (child_start) |c| return t.parentOf(pid, c);
    return t.lookup(pid, "");
}

fn entityField(jw: *Jw, id: ?entity.Id) !void {
    const v = id orelse return;
    try jw.objectField("entity_id");
    try jw.write(&v);
}

fn sysmonProcessCore(jw: *Jw, ev: *const evtxml.Event, guid: []const u8, pid: []const u8, image: []const u8, user: []const u8) !void {
    return sysmonProcessCoreAt(jw, ev, guid, pid, image, user, null);
}

fn sysmonProcessCoreAt(jw: *Jw, ev: *const evtxml.Event, guid: []const u8, pid: []const u8, image: []const u8, user: []const u8, child_start: ?u64) !void {
    try entityField(jw, lookupEntity(ev.get(pid), ev.get(guid), child_start));
    try str(jw, "guid", ev.get(guid));
    try int(jw, "pid", ev.get(pid));
    try pathAsImage(jw, ev.get(image));
    try sysmonUser(jw, ev.get(user));
}

/// `process{guid,pid,image,name,user}` for Sysmon events about one process.
fn sysmonProcess(jw: *Jw, ev: *const evtxml.Event) !void {
    try jw.objectField("process");
    try jw.beginObject();
    try sysmonProcessCore(jw, ev, "ProcessGuid", "ProcessId", "Image", "User");
    try jw.endObject();
}

/// Sysmon `UtcTime` `2026-11-09 01:12:44.548` -> `2026-11-09T01:12:44.548Z`.
fn sysmonStartTime(jw: *Jw, value: ?[]const u8) !void {
    const v = value orelse return;
    if (v.len < 19 or v.len > 40 or v[10] != ' ') return;
    var buf: [48]u8 = undefined;
    const iso = std.fmt.bufPrint(&buf, "{s}T{s}Z", .{ v[0..10], v[11..] }) catch return;
    try jw.objectField("start_time");
    try jw.write(iso);
}

/// `SHA1=..,MD5=..,SHA256=..,IMPHASH=..` -> `hashes{sha1,md5,sha256,imphash}`.
fn hashes(jw: *Jw, value: ?[]const u8) !void {
    const v = value orelse return;
    if (isEmptyValue(v)) return;
    try jw.objectField("hashes");
    try jw.beginObject();
    var it = std.mem.tokenizeScalar(u8, v, ',');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const algo = std.mem.trim(u8, pair[0..eq], " ");
        const digest = std.mem.trim(u8, pair[eq + 1 ..], " ");
        var key_buf: [16]u8 = undefined;
        var hex_buf: [128]u8 = undefined;
        if (algo.len == 0 or algo.len > key_buf.len or digest.len == 0 or digest.len > hex_buf.len) continue;
        try jw.objectField(std.ascii.lowerString(&key_buf, algo));
        try jw.write(std.ascii.lowerString(&hex_buf, digest));
    }
    try jw.endObject();
}

/// `HKLM\...\Run\Name` -> `key` = `HKLM\...\Run`, `value_name` = `Name`.
fn registryKeyValue(jw: *Jw, value: ?[]const u8) !void {
    const v = value orelse return;
    if (isEmptyValue(v)) return;
    if (std.mem.lastIndexOfScalar(u8, v, '\\')) |sep| {
        try str(jw, "key", v[0..sep]);
        try str(jw, "value_name", v[sep + 1 ..]);
    } else {
        try str(jw, "key", v);
    }
}

/// Sysmon renders non-string data as `DWORD (0x00000001)` or `QWORD (...)`.
fn registryValueType(details: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, details, "DWORD (")) return "REG_DWORD";
    if (std.mem.startsWith(u8, details, "QWORD (")) return "REG_QWORD";
    if (std.mem.eql(u8, details, "Binary Data")) return "REG_BINARY";
    return null;
}

fn securityUser(jw: *Jw, key: []const u8, ev: *const evtxml.Event, name: []const u8, domain: []const u8, sid: []const u8) !void {
    try jw.objectField(key);
    try jw.beginObject();
    try str(jw, "name", ev.get(name));
    try str(jw, "domain", ev.get(domain));
    const s = ev.get(sid);
    if (s != null and !std.mem.eql(u8, s.?, "S-1-0-0")) try str(jw, "sid", s);
    try jw.endObject();
}

fn securityProcess(jw: *Jw, ev: *const evtxml.Event, pid: []const u8, image: []const u8) !void {
    const pid_n = parseHexOrDec(ev.get(pid) orelse "") orelse 0;
    const img = ev.get(image) orelse "";
    if (pid_n == 0 and isEmptyValue(img)) return;
    try jw.objectField("process");
    try jw.beginObject();
    if (pid_n != 0) {
        try jw.objectField("pid");
        try jw.write(pid_n);
    }
    try pathAsImage(jw, img);
    try jw.endObject();
}

fn sourceNetwork(jw: *Jw, ev: *const evtxml.Event) !void {
    const ip = ev.get("IpAddress") orelse return;
    if (isEmptyValue(ip)) return;
    try jw.objectField("network");
    try jw.beginObject();
    try str(jw, "src_ip", ip);
    const port = std.fmt.parseInt(u16, ev.get("IpPort") orelse "", 10) catch 0;
    if (port != 0) {
        try jw.objectField("src_port");
        try jw.write(port);
    }
    try jw.endObject();
}

fn logonType(jw: *Jw, value: ?[]const u8) !void {
    const v = value orelse return;
    const n = std.fmt.parseInt(u8, v, 10) catch return;
    try jw.objectField("type");
    try jw.write(n);
    const name: ?[]const u8 = switch (n) {
        2 => "interactive",
        3 => "network",
        4 => "batch",
        5 => "service",
        7 => "unlock",
        8 => "network_cleartext",
        9 => "new_credentials",
        10 => "remote_interactive",
        11 => "cached_interactive",
        else => null,
    };
    if (name) |s| {
        try jw.objectField("type_name");
        try jw.write(s);
    }
}

fn logonFailureReason(sub_status: []const u8) ?[]const u8 {
    const code = parseHexOrDec(sub_status) orelse return null;
    return switch (code) {
        0xc0000064 => "unknown_user",
        0xc000006a => "bad_password",
        0xc0000234 => "account_locked",
        0xc0000072 => "account_disabled",
        0xc000006f => "outside_logon_hours",
        0xc0000070 => "workstation_restriction",
        0xc0000193 => "account_expired",
        0xc0000071 => "password_expired",
        0xc0000224 => "password_must_change",
        0xc000015b => "logon_type_not_granted",
        else => null,
    };
}

fn integrityFromLabel(label: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, label, "S-1-16-0")) return "Untrusted";
    if (std.mem.eql(u8, label, "S-1-16-4096")) return "Low";
    if (std.mem.eql(u8, label, "S-1-16-8192")) return "Medium";
    if (std.mem.eql(u8, label, "S-1-16-8448")) return "MediumPlus";
    if (std.mem.eql(u8, label, "S-1-16-12288")) return "High";
    if (std.mem.eql(u8, label, "S-1-16-16384")) return "System";
    if (std.mem.eql(u8, label, "S-1-16-20480")) return "Protected";
    return null;
}

fn elevationType(value: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, value, "%%1936")) return "default";
    if (std.mem.eql(u8, value, "%%1937")) return "full";
    if (std.mem.eql(u8, value, "%%1938")) return "limited";
    return null;
}

/// Longest prefix of `s` no longer than `max` that ends on a UTF-8 boundary.
pub fn truncUtf8(s: []const u8, max: usize) []const u8 {
    if (s.len <= max) return s;
    var end = max;
    while (end > 0 and (s[end] & 0xC0) == 0x80) end -= 1;
    return s[0..end];
}

// ---------------------------------------------------------------------------
// PowerShell 4104 script block reassembly

pub const ScriptBlocks = struct {
    allocator: std.mem.Allocator,
    pending: std.StringArrayHashMapUnmanaged(Pending) = .empty,
    dropped_parts: u64 = 0,

    const Pending = struct {
        first_seen: i64,
        total: u32,
        received: u32 = 0,
        parts: []?[]u8,
        /// Parts past `max_script_block_parts` (counted, not stored).
        overflow_parts: u32 = 0,
        path: []u8,
        pid: ?u32,
        user_sid: []u8,
        ts: []u8,
        record_id: u64,
        channel: []u8,

        fn deinit(self: *Pending, alloc: std.mem.Allocator) void {
            for (self.parts) |p| if (p) |text| alloc.free(text);
            alloc.free(self.parts);
            alloc.free(self.path);
            alloc.free(self.user_sid);
            alloc.free(self.ts);
            alloc.free(self.channel);
        }
    };

    pub fn init(alloc: std.mem.Allocator) ScriptBlocks {
        return .{ .allocator = alloc };
    }

    pub fn deinit(self: *ScriptBlocks) void {
        var it = self.pending.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            e.value_ptr.deinit(self.allocator);
        }
        self.pending.deinit(self.allocator);
    }

    pub fn len(self: *const ScriptBlocks) usize {
        return self.pending.count();
    }

    /// Add one 4104 part. Completed blocks (and any block evicted to make
    /// room) are appended to `out`.
    pub fn add(self: *ScriptBlocks, ev: *const evtxml.Event, now: i64, out: *std.array_list.Managed(Item)) !void {
        const id = ev.get("ScriptBlockId") orelse return error.MissingScriptBlockId;
        const number = std.fmt.parseInt(u32, ev.get("MessageNumber") orelse "1", 10) catch 1;
        const total_raw = std.fmt.parseInt(u32, ev.get("MessageTotal") orelse "1", 10) catch 1;
        const total = @max(total_raw, 1);
        if (number == 0 or number > total) return error.InvalidScriptBlockPart;

        if (!self.pending.contains(id) and self.pending.count() >= max_pending_script_blocks) {
            // Evict the oldest so a flood of unique ids stays bounded.
            try self.flushIndex(0, out);
        }

        if (!self.pending.contains(id)) {
            // Build the entry fully before inserting so a failed allocation
            // never leaves a half-made entry in the map.
            const key = try self.allocator.dupe(u8, id);
            errdefer self.allocator.free(key);
            const parts = try self.allocator.alloc(?[]u8, @min(total, max_script_block_parts));
            @memset(parts, null);
            var fresh: Pending = .{
                .first_seen = now,
                .total = total,
                .parts = parts,
                .path = &.{},
                .pid = ev.execution_pid,
                .user_sid = &.{},
                .ts = &.{},
                .record_id = ev.record_id,
                .channel = &.{},
            };
            errdefer fresh.deinit(self.allocator);
            fresh.path = try self.allocator.dupe(u8, ev.get("Path") orelse "");
            fresh.user_sid = try self.allocator.dupe(u8, ev.user_sid);
            fresh.ts = try self.allocator.dupe(u8, ev.time_created);
            fresh.channel = try self.allocator.dupe(u8, ev.channel);
            try self.pending.put(self.allocator, key, fresh);
        }
        const index = self.pending.getIndex(id).?;
        const p = &self.pending.values()[index];
        if (number <= p.parts.len) {
            if (p.parts[number - 1] == null) {
                p.parts[number - 1] = try self.allocator.dupe(u8, ev.get("ScriptBlockText") orelse "");
                p.received += 1;
            }
        } else {
            p.overflow_parts += 1;
            p.received += 1;
        }
        if (p.path.len == 0) {
            if (ev.get("Path")) |path| if (path.len > 0) {
                const owned = try self.allocator.dupe(u8, path);
                self.allocator.free(p.path);
                p.path = owned;
            };
        }
        if (p.received >= p.total) try self.flushIndex(index, out);
    }

    /// Flush every block older than `script_block_flush_seconds`.
    pub fn flushExpired(self: *ScriptBlocks, now: i64, out: *std.array_list.Managed(Item)) !void {
        var i: usize = 0;
        while (i < self.pending.count()) {
            if (now - self.pending.values()[i].first_seen >= script_block_flush_seconds) {
                try self.flushIndex(i, out);
            } else {
                i += 1;
            }
        }
    }

    /// Flush everything (shutdown, debug dump).
    pub fn flushAll(self: *ScriptBlocks, out: *std.array_list.Managed(Item)) !void {
        while (self.pending.count() > 0) try self.flushIndex(0, out);
    }

    fn flushIndex(self: *ScriptBlocks, index: usize, out: *std.array_list.Managed(Item)) !void {
        const key = self.pending.keys()[index];
        var p = self.pending.values()[index];
        // Remove first (preserving order so index 0 stays the oldest) so a
        // failure below cannot leave a freed entry in the map.
        self.pending.orderedRemoveAt(index);
        defer {
            self.allocator.free(key);
            p.deinit(self.allocator);
        }
        const payload = buildScriptBlockPayload(self.allocator, key, &p) catch |err| {
            self.dropped_parts += p.received;
            return err;
        };
        errdefer self.allocator.free(payload);
        try out.append(.{
            .event_type = "powershell_script_block",
            .occurred_at = parseSystemTime(p.ts) orelse iox.timestamp(),
            .client_event_id = recordEventId(p.channel, p.record_id, p.ts),
            .payload = payload,
        });
    }
};

fn buildScriptBlockPayload(alloc: std.mem.Allocator, id: []const u8, p: *const ScriptBlocks.Pending) ![]u8 {
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(alloc);
    var truncated = p.overflow_parts > 0;
    var missing: u32 = 0;
    for (p.parts) |part| {
        const t = part orelse {
            missing += 1;
            continue;
        };
        const room = max_script_block_bytes - text.items.len;
        if (t.len > room) {
            try text.appendSlice(alloc, truncUtf8(t, room));
            truncated = true;
            break;
        }
        try text.appendSlice(alloc, t);
    }

    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    var jw: Jw = .{ .writer = &out.writer };
    try jw.beginObject();
    try jw.objectField("sensor");
    try jw.write("powershell");
    try jw.objectField("channel");
    try jw.write(p.channel);
    try jw.objectField("event_id");
    try jw.write(@as(u32, 4104));
    try jw.objectField("record_id");
    try jw.write(p.record_id);
    try str(&jw, "ts", p.ts);
    try jw.objectField("script_block");
    try jw.beginObject();
    try jw.objectField("id");
    try jw.write(id);
    try jw.objectField("text");
    try jw.write(text.items);
    try str(&jw, "path", p.path);
    try jw.objectField("parts_total");
    try jw.write(p.total);
    try jw.objectField("parts_received");
    try jw.write(p.received);
    try jw.objectField("complete");
    try jw.write(missing == 0 and p.overflow_parts == 0);
    try jw.objectField("truncated");
    try jw.write(truncated or missing > 0);
    try jw.endObject();
    if (p.pid) |pid| {
        try jw.objectField("process");
        try jw.beginObject();
        try jw.objectField("pid");
        try jw.write(pid);
        try jw.endObject();
    }
    if (p.user_sid.len > 0) {
        try jw.objectField("user");
        try jw.beginObject();
        try str(&jw, "sid", p.user_sid);
        try jw.endObject();
    }
    try jw.endObject();
    return out.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Channel health

pub const ChannelState = enum { unknown, ok, missing, access_denied, silent, failed };

pub const Health = struct {
    state: [channels.len]ChannelState = @splat(.unknown),
    last_delivery: [channels.len]i64 = @splat(0),
    detail: [channels.len]u32 = @splat(0),

    pub const Transition = struct {
        channel: usize,
        from: ChannelState,
        to: ChannelState,
    };

    /// Record a subscription result. Returns a transition when the state
    /// changed, so callers report each change once.
    pub fn subscribed(self: *Health, channel: usize, result: ChannelState, win32_error: u32, now: i64) ?Transition {
        self.detail[channel] = win32_error;
        if (result == .ok and self.last_delivery[channel] == 0) self.last_delivery[channel] = now;
        return self.set(channel, result);
    }

    /// Note that a channel delivered `count` events this tick, then check for
    /// silence.
    pub fn tick(self: *Health, channel: usize, count: usize, now: i64) ?Transition {
        const s = self.state[channel];
        if (s != .ok and s != .silent) return null;
        if (count > 0) {
            self.last_delivery[channel] = now;
            return self.set(channel, .ok);
        }
        if (now - self.last_delivery[channel] >= channel_silence_seconds) return self.set(channel, .silent);
        return null;
    }

    /// Sysmon is delivering, so Security 4688 would duplicate Sysmon 1.
    pub fn sysmonDelivering(self: *const Health) bool {
        return self.state[sysmonIndex()] == .ok;
    }

    pub fn sysmonPresent(self: *const Health) bool {
        const s = self.state[sysmonIndex()];
        return s == .ok or s == .silent;
    }

    fn set(self: *Health, channel: usize, to: ChannelState) ?Transition {
        const from = self.state[channel];
        if (from == to) return null;
        self.state[channel] = to;
        return .{ .channel = channel, .from = from, .to = to };
    }
};

fn sysmonIndex() usize {
    inline for (channels, 0..) |ch, i| {
        if (ch.source == .sysmon) return i;
    }
    unreachable;
}

/// `sensor_health` payload for a channel state change.
pub fn healthPayload(alloc: std.mem.Allocator, health: *const Health, t: Health.Transition, counters: Counters) ![]u8 {
    const ch = channels[t.channel];
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    var jw: Jw = .{ .writer = &out.writer };
    try jw.beginObject();
    try jw.objectField("sensor");
    try jw.write("windows_eventlog");
    try jw.objectField("channel");
    try jw.write(ch.path);
    try jw.objectField("state");
    try jw.write(@tagName(t.to));
    try jw.objectField("previous_state");
    try jw.write(@tagName(t.from));
    try jw.objectField("status");
    const sysmon_ok = health.sysmonPresent();
    const degraded = !sysmon_ok or t.to != .ok;
    try jw.write(if (degraded) "degraded" else "ok");
    try jw.objectField("sysmon_present");
    try jw.write(sysmon_ok);
    if (!sysmon_ok) {
        try jw.objectField("process_start_source");
        try jw.write("security_4688");
    }
    if (health.detail[t.channel] != 0) {
        try jw.objectField("win32_error");
        try jw.write(health.detail[t.channel]);
    }
    if (t.to == .silent) {
        try jw.objectField("silent_seconds_threshold");
        try jw.write(channel_silence_seconds);
    }
    try jw.objectField("channels");
    try jw.beginObject();
    for (channels, 0..) |c, i| {
        try jw.objectField(c.path);
        try jw.write(@tagName(health.state[i]));
    }
    try jw.endObject();
    try counters.write(&jw);
    try jw.endObject();
    return out.toOwnedSlice();
}

// ---------------------------------------------------------------------------
// Event processing shared by the agent loop and the debug dump

pub const Processor = struct {
    allocator: std.mem.Allocator,
    blocks: ScriptBlocks,
    counters: Counters = .{},
    /// When true, Security 4688 is dropped because Sysmon 1 is delivering.
    sysmon_active: bool = false,
    /// pid -> entity table shared with the agent loop.
    entities: ?*entity.Table = null,

    pub fn init(alloc: std.mem.Allocator) Processor {
        return .{ .allocator = alloc, .blocks = ScriptBlocks.init(alloc) };
    }

    pub fn deinit(self: *Processor) void {
        self.blocks.deinit();
    }

    /// Parse, map and append one rendered event. Failures are counted.
    pub fn handleXml(self: *Processor, xml: []const u8, now: i64, out: *std.array_list.Managed(Item)) !void {
        var ev = evtxml.parse(self.allocator, xml) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {
                self.counters.dropped_parse += 1;
                return;
            },
        };
        defer ev.deinit();
        try self.handleEvent(&ev, now, out);
    }

    pub fn handleEvent(self: *Processor, ev: *const evtxml.Event, now: i64, out: *std.array_list.Managed(Item)) !void {
        const source = sourceForChannel(ev.channel);
        if (source == .powershell and ev.event_id == 4104) {
            const before = out.items.len;
            self.blocks.add(ev, now, out) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => {
                    self.counters.dropped_script_parts += 1;
                    return;
                },
            };
            self.counters.emitted += out.items.len - before;
            return;
        }
        if (source == .defender) {
            // 5007: configuration changed. Only a new exclusion that covers a
            // Tawny path is reported, as agent_tamper.
            const payload = (try tamper.defenderExclusionPayload(self.allocator, ev.get("Old Value"), ev.get("New Value"))) orelse {
                self.counters.dropped_unmapped += 1;
                return;
            };
            errdefer self.allocator.free(payload);
            try out.append(.{
                .event_type = "agent_tamper",
                .occurred_at = parseSystemTime(ev.time_created) orelse now,
                .client_event_id = recordEventId(ev.channel, ev.record_id, ev.time_created),
                .payload = payload,
            });
            self.counters.emitted += 1;
            return;
        }
        if (source == .security and ev.event_id == 4688 and self.sysmon_active) {
            self.counters.skipped_4688_with_sysmon += 1;
            return;
        }
        const mapped = mapEventWith(self.allocator, ev, self.entities) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {
                self.counters.dropped_map += 1;
                return;
            },
        } orelse {
            self.counters.dropped_unmapped += 1;
            return;
        };
        errdefer self.allocator.free(mapped.payload);
        try out.append(.{
            .event_type = mapped.event_type,
            .occurred_at = parseSystemTime(ev.time_created) orelse now,
            .client_event_id = recordEventId(ev.channel, ev.record_id, ev.time_created),
            .payload = mapped.payload,
        });
        self.counters.emitted += 1;
    }

    pub fn flushExpired(self: *Processor, now: i64, out: *std.array_list.Managed(Item)) !void {
        const before = out.items.len;
        try self.blocks.flushExpired(now, out);
        self.counters.emitted += out.items.len - before;
    }
};

// ---------------------------------------------------------------------------
// Windows-only: live subscriptions

const resubscribe_seconds: i64 = 60;

pub const Collector = if (builtin.target.os.tag == .windows) WindowsCollector else NullCollector;

const NullCollector = struct {
    pub fn init(_: std.mem.Allocator, _: []const u8) !NullCollector {
        return .{};
    }
    pub fn deinit(_: *NullCollector) void {}
    pub fn collect(_: *NullCollector) ![]Item {
        return &.{};
    }
    pub fn commit(_: *NullCollector) void {}
    pub fn noteQueueDrop(_: *NullCollector) void {}
    pub fn setEntities(_: *NullCollector, _: *entity.Table) void {}
};

const WindowsCollector = struct {
    allocator: std.mem.Allocator,
    state_dir: []u8,
    processor: Processor,
    health: Health = .{},
    subs: [channels.len]?eventlog.Subscription = @splat(null),
    last_attempt: [channels.len]i64 = @splat(0),
    /// Channels with events read since the last commit.
    dirty: [channels.len]bool = @splat(false),

    pub fn init(alloc: std.mem.Allocator, state_dir: []const u8) !WindowsCollector {
        return .{
            .allocator = alloc,
            .state_dir = try alloc.dupe(u8, state_dir),
            .processor = Processor.init(alloc),
        };
    }

    pub fn deinit(self: *WindowsCollector) void {
        self.commit();
        for (&self.subs) |*s| if (s.*) |*sub| sub.deinit();
        self.processor.deinit();
        self.allocator.free(self.state_dir);
    }

    pub fn noteQueueDrop(self: *WindowsCollector) void {
        self.processor.counters.dropped_queue += 1;
    }

    pub fn setEntities(self: *WindowsCollector, table: *entity.Table) void {
        self.processor.entities = table;
    }

    /// Pull up to the per-channel cap from every channel. Caller pushes the
    /// items, frees them with `freeItems`, then calls `commit`.
    pub fn collect(self: *WindowsCollector) ![]Item {
        const now = iox.timestamp();
        var out = std.array_list.Managed(Item).init(self.allocator);
        errdefer {
            for (out.items) |it| self.allocator.free(it.payload);
            out.deinit();
        }
        var xml_list = std.array_list.Managed([]u8).init(self.allocator);
        defer {
            for (xml_list.items) |x| self.allocator.free(x);
            xml_list.deinit();
        }

        for (channels, 0..) |ch, i| {
            if (self.subs[i] == null and now - self.last_attempt[i] >= resubscribe_seconds) {
                self.last_attempt[i] = now;
                try self.subscribe(i, ch, now, &out);
            }
            self.processor.sysmon_active = self.health.sysmonDelivering();
            const sub = if (self.subs[i]) |*s| s else continue;

            for (xml_list.items) |x| self.allocator.free(x);
            xml_list.clearRetainingCapacity();
            const pulled = sub.pull(&xml_list, max_events_per_channel_tick) catch |err| {
                std.debug.print("eventlog {s}: pull failed: {s} (win32 {d})\n", .{ ch.path, @errorName(err), eventlog.lastError() });
                sub.deinit();
                self.subs[i] = null;
                if (self.health.subscribed(i, .failed, eventlog.lastError(), now)) |t| try self.pushHealth(t, &out);
                continue;
            };
            if (pulled.capped) self.processor.counters.capped_ticks += 1;
            if (pulled.count > 0) self.dirty[i] = true;
            for (xml_list.items) |x| try self.processor.handleXml(x, now, &out);
            if (self.health.tick(i, pulled.count, now)) |t| try self.pushHealth(t, &out);
        }
        try self.processor.flushExpired(now, &out);
        return out.toOwnedSlice();
    }

    /// Persist bookmarks for channels read since the last commit. Called
    /// after the items have been written to the agent spool.
    pub fn commit(self: *WindowsCollector) void {
        for (channels, 0..) |ch, i| {
            if (!self.dirty[i]) continue;
            const sub = if (self.subs[i]) |*s| s else continue;
            saveBookmark(self.allocator, self.state_dir, ch.path, sub) catch |err| {
                std.debug.print("eventlog {s}: bookmark save failed: {s}\n", .{ ch.path, @errorName(err) });
                continue;
            };
            self.dirty[i] = false;
        }
    }

    fn subscribe(self: *WindowsCollector, i: usize, ch: Channel, now: i64, out: *std.array_list.Managed(Item)) !void {
        const query = try buildQuery(self.allocator, ch, null);
        defer self.allocator.free(query);
        const bookmark = loadBookmark(self.allocator, self.state_dir, ch.path);
        defer if (bookmark) |b| self.allocator.free(b);
        const result = eventlog.Subscription.open(self.allocator, ch.path, query, bookmark, .future);
        const t = if (result) |sub| blk: {
            self.subs[i] = sub;
            break :blk self.health.subscribed(i, .ok, 0, now);
        } else |err| blk: {
            const code = eventlog.lastError();
            const state: ChannelState = switch (err) {
                error.ChannelNotFound => .missing,
                error.AccessDenied => .access_denied,
                else => .failed,
            };
            break :blk self.health.subscribed(i, state, code, now);
        };
        if (t) |tr| try self.pushHealth(tr, out);
    }

    fn pushHealth(self: *WindowsCollector, t: Health.Transition, out: *std.array_list.Managed(Item)) !void {
        // A first successful subscription is not news; failures and changes are.
        if (t.from == .unknown and t.to == .ok and channels[t.channel].source != .sysmon) return;
        const payload = try healthPayload(self.allocator, &self.health, t, self.processor.counters);
        errdefer self.allocator.free(payload);
        try out.append(.{
            .event_type = "sensor_health",
            .occurred_at = iox.timestamp(),
            .client_event_id = @splat(0),
            .payload = payload,
        });
    }
};

fn bookmarkPath(alloc: std.mem.Allocator, state_dir: []const u8, channel: []const u8) ![]u8 {
    const name = try bookmarkFileName(alloc, channel);
    defer alloc.free(name);
    return std.fs.path.join(alloc, &.{ state_dir, name });
}

/// Saved bookmark XML for a channel, or null when none (or unreadable).
pub fn loadBookmark(alloc: std.mem.Allocator, state_dir: []const u8, channel: []const u8) ?[]u8 {
    const path = bookmarkPath(alloc, state_dir, channel) catch return null;
    defer alloc.free(path);
    const data = std.Io.Dir.cwd().readFileAlloc(iox.current(), path, alloc, .limited(64 * 1024)) catch return null;
    if (data.len == 0 or std.mem.indexOf(u8, data, "<BookmarkList") == null) {
        alloc.free(data);
        return null;
    }
    return data;
}

/// Atomically write bookmark XML (temp file + rename).
pub fn writeBookmark(alloc: std.mem.Allocator, state_dir: []const u8, channel: []const u8, xml: []const u8) !void {
    const io = iox.current();
    const path = try bookmarkPath(alloc, state_dir, channel);
    defer alloc.free(path);
    const tmp = try alloc.print("{s}.tmp", .{path});
    defer alloc.free(tmp);
    try std.Io.Dir.cwd().createDirPath(io, state_dir);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = tmp, .data = xml });
    try std.Io.Dir.cwd().rename(tmp, std.Io.Dir.cwd(), path, io);
}

fn saveBookmark(alloc: std.mem.Allocator, state_dir: []const u8, channel: []const u8, sub: anytype) !void {
    const xml = try sub.bookmarkXml();
    defer alloc.free(xml);
    try writeBookmark(alloc, state_dir, channel, xml);
}

/// `tawny-agent --eventlog-dump [--state-dir DIR] [--since-seconds N]
/// [--wait-ms N]`: read the four channels once, print each mapped event as
/// `event_type<TAB>json`, save bookmarks under DIR and exit. Used by CI to
/// prove the wevtapi path on a hosted runner.
pub fn dumpCommand(alloc: std.mem.Allocator, args: []const []const u8) !void {
    if (builtin.target.os.tag != .windows) {
        std.debug.print("--eventlog-dump is only available on Windows\n", .{});
        return error.UnsupportedPlatform;
    }
    var state_dir: []const u8 = ".";
    var since_seconds: u64 = 600;
    var wait_ms: u32 = 3000;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (i + 1 >= args.len) return error.InvalidArguments;
        if (std.mem.eql(u8, a, "--state-dir")) {
            state_dir = args[i + 1];
        } else if (std.mem.eql(u8, a, "--since-seconds")) {
            since_seconds = try std.fmt.parseInt(u64, args[i + 1], 10);
        } else if (std.mem.eql(u8, a, "--wait-ms")) {
            wait_ms = try std.fmt.parseInt(u32, args[i + 1], 10);
        } else return error.InvalidArguments;
        i += 1;
    }
    if (builtin.target.os.tag == .windows) try dumpWindows(alloc, state_dir, since_seconds, wait_ms);
}

fn dumpWindows(alloc: std.mem.Allocator, state_dir: []const u8, since_seconds: u64, wait_ms: u32) !void {
    var processor = Processor.init(alloc);
    defer processor.deinit();
    var health: Health = .{};
    const now = iox.timestamp();
    var items = std.array_list.Managed(Item).init(alloc);
    defer {
        for (items.items) |it| alloc.free(it.payload);
        items.deinit();
    }
    var xml_list = std.array_list.Managed([]u8).init(alloc);
    defer {
        for (xml_list.items) |x| alloc.free(x);
        xml_list.deinit();
    }

    for (channels, 0..) |ch, ci| {
        const bookmark = loadBookmark(alloc, state_dir, ch.path);
        defer if (bookmark) |b| alloc.free(b);
        // With a bookmark, resume after it; without one, read the recent
        // window from the oldest record.
        const query = try buildQuery(alloc, ch, if (bookmark == null) since_seconds * 1000 else null);
        defer alloc.free(query);
        var sub = eventlog.Subscription.open(alloc, ch.path, query, bookmark, .oldest) catch |err| {
            const state: ChannelState = switch (err) {
                error.ChannelNotFound => .missing,
                error.AccessDenied => .access_denied,
                else => .failed,
            };
            _ = health.subscribed(ci, state, eventlog.lastError(), now);
            std.debug.print("channel {s}: {s} (win32 {d})\n", .{ ch.path, @tagName(state), eventlog.lastError() });
            continue;
        };
        defer sub.deinit();
        _ = health.subscribed(ci, .ok, 0, now);
        processor.sysmon_active = health.sysmonDelivering();

        var total: usize = 0;
        var pull_failed = false;
        while (true) {
            for (xml_list.items) |x| alloc.free(x);
            xml_list.clearRetainingCapacity();
            const pulled = sub.pullWait(&xml_list, max_events_per_channel_tick, wait_ms) catch |err| {
                // Report the Win32 code and keep going, so one bad channel
                // doesn't hide the others.
                std.debug.print("channel {s}: pull failed {s} (win32 {d}) after {d} events\n", .{ ch.path, @errorName(err), eventlog.lastError(), total });
                for (xml_list.items) |x| try processor.handleXml(x, now, &items);
                pull_failed = true;
                break;
            };
            for (xml_list.items) |x| try processor.handleXml(x, now, &items);
            total += pulled.count;
            if (pulled.count == 0) break;
        }
        if (!pull_failed) std.debug.print("channel {s}: ok, {d} events\n", .{ ch.path, total });
        if (total > 0) try saveBookmark(alloc, state_dir, ch.path, &sub);
    }
    try processor.blocks.flushAll(&items);

    for (items.items) |it| {
        std.debug.print("EVENT\t{s}\t{s}\n", .{ it.event_type, it.payload });
    }
    if (!health.sysmonPresent()) {
        const t: Health.Transition = .{ .channel = sysmonIndex(), .from = .unknown, .to = health.state[sysmonIndex()] };
        const payload = try healthPayload(alloc, &health, t, processor.counters);
        defer alloc.free(payload);
        std.debug.print("EVENT\tsensor_health\t{s}\n", .{payload});
    }
    std.debug.print("SUMMARY\temitted={d}\tdropped={d}\tskipped_4688={d}\n", .{ processor.counters.emitted, processor.counters.totalDropped(), processor.counters.skipped_4688_with_sysmon });
}

// ---------------------------------------------------------------------------
// Tests

const samples = evtxml.samples;

fn mapSample(xml: []const u8) !struct { event_type: []const u8, parsed: std.json.Parsed(std.json.Value), raw: []u8 } {
    const alloc = std.testing.allocator;
    var ev = try evtxml.parse(alloc, xml);
    defer ev.deinit();
    const mapped = (try mapEvent(alloc, &ev)).?;
    errdefer alloc.free(mapped.payload);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, mapped.payload, .{});
    return .{ .event_type = mapped.event_type, .parsed = parsed, .raw = mapped.payload };
}

fn getPath(v: std.json.Value, path: []const u8) ?std.json.Value {
    var cur = v;
    var it = std.mem.splitScalar(u8, path, '.');
    while (it.next()) |seg| {
        if (cur != .object) return null;
        cur = cur.object.get(seg) orelse return null;
    }
    return cur;
}

fn expectStr(v: std.json.Value, path: []const u8, want: []const u8) !void {
    const got = getPath(v, path) orelse {
        std.debug.print("missing {s}\n", .{path});
        return error.TestExpectedEqual;
    };
    try std.testing.expectEqualStrings(want, got.string);
}

fn expectInt(v: std.json.Value, path: []const u8, want: i64) !void {
    const got = getPath(v, path) orelse {
        std.debug.print("missing {s}\n", .{path});
        return error.TestExpectedEqual;
    };
    try std.testing.expectEqual(want, got.integer);
}

fn freeSample(m: anytype) void {
    var p = m.parsed;
    p.deinit();
    std.testing.allocator.free(m.raw);
}

test "sysmon 1 maps to process_start with image, command line, user, parent, hashes and guid" {
    const m = try mapSample(samples.sysmon_1);
    defer freeSample(m);
    const v = m.parsed.value;
    try std.testing.expectEqualStrings("process_start", m.event_type);
    try expectStr(v, "sensor", "sysmon");
    try expectInt(v, "event_id", 1);
    try expectStr(v, "process.guid", "{4f3c6a1e-b7cc-672e-2c01-000000001e00}");
    try expectInt(v, "process.pid", 6844);
    try expectStr(v, "process.image", "C:\\Windows\\System32\\whoami.exe");
    try expectStr(v, "process.name", "whoami.exe");
    try expectStr(v, "process.command_line", "whoami /all");
    try expectStr(v, "process.cwd", "C:\\Users\\runneradmin\\");
    try expectStr(v, "process.user.name", "runneradmin");
    try expectStr(v, "process.user.domain", "WIN-TAWNY01");
    try expectStr(v, "process.integrity_level", "High");
    try expectInt(v, "process.session_id", 1);
    try expectStr(v, "process.start_time", "2026-11-09T01:12:44.548Z");
    try expectStr(v, "process.hashes.sha256", "1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1d2c");
    try expectStr(v, "process.hashes.md5", "a1b2c3d4e5f60718293a4b5c6d7e8f90");
    try expectStr(v, "parent.image", "C:\\Windows\\System32\\cmd.exe");
    try expectStr(v, "parent.guid", "{4f3c6a1e-b7cb-672e-2b01-000000001e00}");
    try expectInt(v, "parent.pid", 5532);
    try expectStr(v, "parent.command_line", "\"C:\\Windows\\system32\\cmd.exe\" /c whoami /all");
    // "-" placeholders are dropped rather than sent.
    try std.testing.expect(getPath(v, "rule_name") == null);
}

test "sysmon network, dns, registry, file and image events map to target-edr fields" {
    {
        const m = try mapSample(samples.sysmon_3);
        defer freeSample(m);
        try std.testing.expectEqualStrings("network_connect", m.event_type);
        try expectStr(m.parsed.value, "network.protocol", "tcp");
        try expectStr(m.parsed.value, "network.direction", "outbound");
        try expectStr(m.parsed.value, "network.src_ip", "10.1.0.4");
        try expectInt(m.parsed.value, "network.src_port", 51544);
        try expectStr(m.parsed.value, "network.dst_ip", "93.184.215.14");
        try expectInt(m.parsed.value, "network.dst_port", 443);
        try expectStr(m.parsed.value, "process.name", "powershell.exe");
        try expectStr(m.parsed.value, "rule_name", "technique_id=T1105,technique_name=Ingress Tool Transfer");
    }
    {
        const m = try mapSample(samples.sysmon_5);
        defer freeSample(m);
        try std.testing.expectEqualStrings("process_exit", m.event_type);
        try expectInt(m.parsed.value, "process.pid", 6844);
    }
    {
        const m = try mapSample(samples.sysmon_7);
        defer freeSample(m);
        try std.testing.expectEqualStrings("image_load", m.event_type);
        try expectStr(m.parsed.value, "file.name", "System.Management.Automation.ni.dll");
        try expectStr(m.parsed.value, "file.extension", "dll");
        try expectStr(m.parsed.value, "file.signature.status", "Valid");
        try expectStr(m.parsed.value, "file.signature.signer", "Microsoft Windows");
        try std.testing.expect(getPath(m.parsed.value, "file.signature.signed").?.bool);
    }
    {
        const m = try mapSample(samples.sysmon_8);
        defer freeSample(m);
        try std.testing.expectEqualStrings("remote_thread", m.event_type);
        try expectStr(m.parsed.value, "process.name", "inject.exe");
        try expectStr(m.parsed.value, "target.image", "C:\\Windows\\explorer.exe");
        try expectInt(m.parsed.value, "thread.id", 9100);
    }
    {
        const m = try mapSample(samples.sysmon_10);
        defer freeSample(m);
        try std.testing.expectEqualStrings("process_access", m.event_type);
        try expectStr(m.parsed.value, "target.name", "lsass.exe");
        try expectStr(m.parsed.value, "granted_access", "0x1010");
        try expectStr(m.parsed.value, "process.guid", "{4f3c6a1e-b7d0-672e-3001-000000001e00}");
    }
    {
        const m = try mapSample(samples.sysmon_11);
        defer freeSample(m);
        try std.testing.expectEqualStrings("file_create", m.event_type);
        try expectStr(m.parsed.value, "file.path", "C:\\Users\\runneradmin\\AppData\\Local\\Temp\\tawny-test.ps1");
        try expectStr(m.parsed.value, "file.extension", "ps1");
    }
    {
        const m = try mapSample(samples.sysmon_12);
        defer freeSample(m);
        try std.testing.expectEqualStrings("registry_create", m.event_type);
        try expectStr(m.parsed.value, "registry.key", "HKU\\S-1-5-21-1004336348-1177238915-682003330-500\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\TawnyTest");
        try expectStr(m.parsed.value, "registry.operation", "CreateKey");
    }
    {
        const m = try mapSample(samples.sysmon_13);
        defer freeSample(m);
        try std.testing.expectEqualStrings("registry_set", m.event_type);
        try expectStr(m.parsed.value, "registry.key", "HKU\\S-1-5-21-1004336348-1177238915-682003330-500\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        try expectStr(m.parsed.value, "registry.value_name", "TawnyTest");
        try expectStr(m.parsed.value, "registry.data", "C:\\Users\\runneradmin\\AppData\\Local\\Temp\\tawny-test.exe");
    }
    {
        const m = try mapSample(samples.sysmon_14);
        defer freeSample(m);
        try std.testing.expectEqualStrings("registry_rename", m.event_type);
        try expectStr(m.parsed.value, "registry.new_name", "HKLM\\System\\CurrentControlSet\\Services\\NewName");
    }
    {
        const m = try mapSample(samples.sysmon_22);
        defer freeSample(m);
        try std.testing.expectEqualStrings("dns_query", m.event_type);
        try expectStr(m.parsed.value, "dns.query", "tawny-test.example.com");
        try expectStr(m.parsed.value, "qname", "tawny-test.example.com");
        try expectInt(m.parsed.value, "dns.status", 0);
        const answers = getPath(m.parsed.value, "dns.answers").?.array.items;
        try std.testing.expectEqual(@as(usize, 2), answers.len);
        try std.testing.expectEqualStrings("edge.example.net", answers[0].string);
        try std.testing.expectEqualStrings("93.184.215.14", answers[1].string);
    }
    {
        const m = try mapSample(samples.sysmon_23);
        defer freeSample(m);
        try std.testing.expectEqualStrings("file_delete", m.event_type);
        try expectStr(m.parsed.value, "file.name", "tawny-test.exe");
        try std.testing.expect(getPath(m.parsed.value, "archived").?.bool);
        try std.testing.expect(getPath(m.parsed.value, "file.is_executable").?.bool);
    }
    {
        const m = try mapSample(samples.sysmon_26);
        defer freeSample(m);
        try std.testing.expectEqualStrings("file_delete", m.event_type);
        try expectStr(m.parsed.value, "file.extension", "evtx");
        try std.testing.expect(!getPath(m.parsed.value, "archived").?.bool);
    }
}

test "registry delete operations map to registry_delete" {
    const xml =
        \\<Event><System><EventID>12</EventID><EventRecordID>9</EventRecordID><TimeCreated SystemTime='2026-11-09T00:00:00.0Z'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System>
        \\<EventData><Data Name='EventType'>DeleteValue</Data><Data Name='TargetObject'>HKLM\Software\Run\Evil</Data></EventData></Event>
    ;
    const m = try mapSample(xml);
    defer freeSample(m);
    try std.testing.expectEqualStrings("registry_delete", m.event_type);
    try expectStr(m.parsed.value, "registry.key", "HKLM\\Software\\Run");
    try expectStr(m.parsed.value, "registry.value_name", "Evil");
}

test "security and system events map to logon, privilege, process and service types" {
    {
        const m = try mapSample(samples.security_4624);
        defer freeSample(m);
        try std.testing.expectEqualStrings("user_logon", m.event_type);
        try expectStr(m.parsed.value, "user.name", "runneradmin");
        try expectStr(m.parsed.value, "user.sid", "S-1-5-21-1004336348-1177238915-682003330-500");
        try expectInt(m.parsed.value, "logon.type", 10);
        try expectStr(m.parsed.value, "logon.type_name", "remote_interactive");
        try expectStr(m.parsed.value, "logon.process", "User32");
        try expectStr(m.parsed.value, "network.src_ip", "203.0.113.50");
        try std.testing.expect(getPath(m.parsed.value, "network.src_port") == null);
        try expectInt(m.parsed.value, "process.pid", 0x1a8c);
        try std.testing.expect(getPath(m.parsed.value, "logon.elevated").?.bool);
    }
    {
        const m = try mapSample(samples.security_4625);
        defer freeSample(m);
        try std.testing.expectEqualStrings("user_logon_failed", m.event_type);
        try expectStr(m.parsed.value, "user.name", "administrator");
        try std.testing.expect(getPath(m.parsed.value, "user.sid") == null);
        try expectStr(m.parsed.value, "logon.failure_reason", "bad_password");
        try expectStr(m.parsed.value, "network.src_ip", "198.51.100.23");
        try expectInt(m.parsed.value, "network.src_port", 49822);
        try std.testing.expect(getPath(m.parsed.value, "process") == null);
    }
    {
        const m = try mapSample(samples.security_4672);
        defer freeSample(m);
        try std.testing.expectEqualStrings("special_privileges", m.event_type);
        const privs = getPath(m.parsed.value, "privileges").?.array.items;
        try std.testing.expectEqual(@as(usize, 5), privs.len);
        try std.testing.expectEqualStrings("SeDebugPrivilege", privs[4].string);
    }
    {
        const m = try mapSample(samples.security_4688);
        defer freeSample(m);
        try std.testing.expectEqualStrings("process_start", m.event_type);
        try expectStr(m.parsed.value, "sensor", "security");
        try expectInt(m.parsed.value, "process.pid", 0x1abc);
        try expectStr(m.parsed.value, "process.image", "C:\\Windows\\System32\\whoami.exe");
        try expectStr(m.parsed.value, "process.command_line", "whoami /all");
        try expectStr(m.parsed.value, "process.user.name", "runneradmin");
        try expectStr(m.parsed.value, "process.integrity_level", "High");
        try expectStr(m.parsed.value, "process.elevation_type", "full");
        try expectInt(m.parsed.value, "parent.pid", 0x159c);
        try expectStr(m.parsed.value, "parent.image", "C:\\Windows\\System32\\cmd.exe");
    }
    {
        const m = try mapSample(samples.system_7045);
        defer freeSample(m);
        try std.testing.expectEqualStrings("service_create", m.event_type);
        try expectStr(m.parsed.value, "service.name", "TawnyTestSvc");
        try expectStr(m.parsed.value, "service.image_path", "C:\\Windows\\System32\\cmd.exe /c echo tawny");
        try expectStr(m.parsed.value, "service.account", "LocalSystem");
        try expectStr(m.parsed.value, "user.sid", "S-1-5-21-1004336348-1177238915-682003330-500");
    }
}

test "command lines in event payloads are sanitised" {
    const xml =
        \\<Event><System><EventID>4688</EventID><EventRecordID>1</EventRecordID><TimeCreated SystemTime='2026-11-09T00:00:00.0Z'/><Channel>Security</Channel></System>
        \\<EventData><Data Name='NewProcessName'>C:\t\tool.exe</Data><Data Name='CommandLine'>tool.exe --password hunter2 token=abc</Data></EventData></Event>
    ;
    const m = try mapSample(xml);
    defer freeSample(m);
    try std.testing.expect(std.mem.indexOf(u8, m.raw, "hunter2") == null);
    try std.testing.expect(std.mem.indexOf(u8, m.raw, "abc") == null);
    try std.testing.expect(std.mem.indexOf(u8, m.raw, "[REDACTED]") != null);
}

test "unknown event ids and channels are not mapped" {
    const alloc = std.testing.allocator;
    var ev = try evtxml.parse(alloc, "<Event><System><EventID>9999</EventID><Channel>Security</Channel></System></Event>");
    defer ev.deinit();
    try std.testing.expect((try mapEvent(alloc, &ev)) == null);
    var other = try evtxml.parse(alloc, "<Event><System><EventID>1</EventID><Channel>Application</Channel></System></Event>");
    defer other.deinit();
    try std.testing.expect((try mapEvent(alloc, &other)) == null);
}

fn freeItemList(list: *std.array_list.Managed(Item)) void {
    for (list.items) |it| std.testing.allocator.free(it.payload);
    list.deinit();
}

test "4104 parts reassemble in order once the last part arrives" {
    const alloc = std.testing.allocator;
    var p = Processor.init(alloc);
    defer p.deinit();
    var out = std.array_list.Managed(Item).init(alloc);
    defer freeItemList(&out);

    // Part 2 first: nothing is emitted until both parts are in.
    try p.handleXml(samples.powershell_4104_part2, 100, &out);
    try std.testing.expectEqual(@as(usize, 0), out.items.len);
    try std.testing.expectEqual(@as(usize, 1), p.blocks.len());
    try p.handleXml(samples.powershell_4104_part1, 101, &out);
    try std.testing.expectEqual(@as(usize, 1), out.items.len);
    try std.testing.expectEqual(@as(usize, 0), p.blocks.len());

    const item = out.items[0];
    try std.testing.expectEqualStrings("powershell_script_block", item.event_type);
    try std.testing.expectEqual(parseSystemTime("2026-11-09T01:12:55.1010000Z").?, item.occurred_at);
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, item.payload, .{});
    defer parsed.deinit();
    const v = parsed.value;
    const text = getPath(v, "script_block.text").?.string;
    try std.testing.expect(std.mem.startsWith(u8, text, "$a = 1; if ($a -lt 3 && \"x\" <# c #>)"));
    try std.testing.expect(std.mem.endsWith(u8, text, "}\nWrite-Output 'part two'"));
    try expectStr(v, "script_block.id", "{7c3c2f8e-1a2b-4c5d-9e0f-112233445566}");
    try expectStr(v, "script_block.path", "C:\\Users\\runneradmin\\AppData\\Local\\Temp\\tawny-test.ps1");
    try expectInt(v, "script_block.parts_total", 2);
    try std.testing.expect(getPath(v, "script_block.complete").?.bool);
    try std.testing.expect(!getPath(v, "script_block.truncated").?.bool);
    try expectInt(v, "process.pid", 7120);
    try expectStr(v, "user.sid", "S-1-5-21-1004336348-1177238915-682003330-500");

    // A duplicate part after completion starts a new block that times out.
    try p.handleXml(samples.powershell_4104_single, 102, &out);
    try std.testing.expectEqual(@as(usize, 2), out.items.len);
}

test "4104 partial blocks flush after 30 seconds marked truncated" {
    const alloc = std.testing.allocator;
    var p = Processor.init(alloc);
    defer p.deinit();
    var out = std.array_list.Managed(Item).init(alloc);
    defer freeItemList(&out);

    try p.handleXml(samples.powershell_4104_part1, 1000, &out);
    try p.flushExpired(1000 + script_block_flush_seconds - 1, &out);
    try std.testing.expectEqual(@as(usize, 0), out.items.len);
    try p.flushExpired(1000 + script_block_flush_seconds, &out);
    try std.testing.expectEqual(@as(usize, 1), out.items.len);
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, out.items[0].payload, .{});
    defer parsed.deinit();
    try std.testing.expect(!getPath(parsed.value, "script_block.complete").?.bool);
    try std.testing.expect(getPath(parsed.value, "script_block.truncated").?.bool);
    try expectInt(parsed.value, "script_block.parts_received", 1);
}

fn scriptPart(alloc: std.mem.Allocator, id: []const u8, n: u32, total: u32, text_len: usize, record: u64) ![]u8 {
    const text = try alloc.alloc(u8, text_len);
    defer alloc.free(text);
    @memset(text, 'x');
    return alloc.print(
        \\<Event><System><EventID>4104</EventID><EventRecordID>{d}</EventRecordID><TimeCreated SystemTime='2026-11-09T00:00:00.0Z'/><Channel>Microsoft-Windows-PowerShell/Operational</Channel></System>
        \\<EventData><Data Name='MessageNumber'>{d}</Data><Data Name='MessageTotal'>{d}</Data><Data Name='ScriptBlockText'>{s}</Data><Data Name='ScriptBlockId'>{s}</Data><Data Name='Path'></Data></EventData></Event>
    , .{ record, n, total, text, id });
}

test "4104 huge blocks are truncated and the pending map stays bounded" {
    const alloc = std.testing.allocator;
    var p = Processor.init(alloc);
    defer p.deinit();
    var out = std.array_list.Managed(Item).init(alloc);
    defer freeItemList(&out);

    // Three 30 KiB parts exceed the 64 KiB cap.
    for (1..4) |n| {
        const xml = try scriptPart(alloc, "{big}", @intCast(n), 3, 30 * 1024, n);
        defer alloc.free(xml);
        try p.handleXml(xml, 5, &out);
    }
    try std.testing.expectEqual(@as(usize, 1), out.items.len);
    {
        var parsed = try std.json.parseFromSlice(std.json.Value, alloc, out.items[0].payload, .{});
        defer parsed.deinit();
        try std.testing.expectEqual(max_script_block_bytes, getPath(parsed.value, "script_block.text").?.string.len);
        try std.testing.expect(getPath(parsed.value, "script_block.truncated").?.bool);
        try std.testing.expect(getPath(parsed.value, "script_block.complete").?.bool);
    }

    // Many unfinished blocks: the map never grows past the cap; the oldest
    // are flushed early instead of dropped silently.
    for (0..max_pending_script_blocks + 10) |i| {
        var id_buf: [32]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buf, "{{id-{d}}}", .{i});
        const xml = try scriptPart(alloc, id, 1, 2, 8, 100 + i);
        defer alloc.free(xml);
        try p.handleXml(xml, 10, &out);
        try std.testing.expect(p.blocks.len() <= max_pending_script_blocks);
    }
    try std.testing.expectEqual(@as(usize, 1 + 10), out.items.len);
}

test "processor counts drops and skips 4688 while sysmon delivers" {
    const alloc = std.testing.allocator;
    var p = Processor.init(alloc);
    defer p.deinit();
    var out = std.array_list.Managed(Item).init(alloc);
    defer freeItemList(&out);

    try p.handleXml("<not xml", 1, &out);
    try p.handleXml("<Event><System><EventID>4634</EventID><Channel>Security</Channel></System></Event>", 1, &out);
    try p.handleXml("<Event><System><EventID>4104</EventID><Channel>Microsoft-Windows-PowerShell/Operational</Channel></System><EventData><Data Name='MessageNumber'>1</Data></EventData></Event>", 1, &out);
    try std.testing.expectEqual(@as(u64, 1), p.counters.dropped_parse);
    try std.testing.expectEqual(@as(u64, 1), p.counters.dropped_unmapped);
    try std.testing.expectEqual(@as(u64, 1), p.counters.dropped_script_parts);
    try std.testing.expectEqual(@as(u64, 3), p.counters.totalDropped());

    try p.handleXml(samples.security_4688, 1, &out);
    try std.testing.expectEqual(@as(usize, 1), out.items.len);
    p.sysmon_active = true;
    try p.handleXml(samples.security_4688, 1, &out);
    try std.testing.expectEqual(@as(usize, 1), out.items.len);
    try std.testing.expectEqual(@as(u64, 1), p.counters.skipped_4688_with_sysmon);
    try std.testing.expectEqual(@as(u64, 1), p.counters.emitted);
}

test "replayed records get the same client event id" {
    const alloc = std.testing.allocator;
    var p = Processor.init(alloc);
    defer p.deinit();
    var out = std.array_list.Managed(Item).init(alloc);
    defer freeItemList(&out);
    try p.handleXml(samples.sysmon_1, 1, &out);
    try p.handleXml(samples.sysmon_1, 2, &out);
    try p.handleXml(samples.sysmon_3, 3, &out);
    try std.testing.expectEqualSlices(u8, &out.items[0].client_event_id, &out.items[1].client_event_id);
    try std.testing.expect(!std.mem.eql(u8, &out.items[0].client_event_id, &out.items[2].client_event_id));
    try std.testing.expectEqual(@as(u8, 0x80), out.items[0].client_event_id[6] & 0xf0);
    // Same record id after a log was recreated: the time keeps them apart.
    const a = recordEventId("Security", 7, "2026-01-01T00:00:00Z");
    const b = recordEventId("Security", 7, "2026-02-01T00:00:00Z");
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "channel health reports missing sysmon and silence once per change" {
    var h: Health = .{};
    const sysmon = sysmonIndex();
    const security: usize = 1;
    const missing = h.subscribed(sysmon, .missing, 15007, 0).?;
    try std.testing.expectEqual(ChannelState.missing, missing.to);
    try std.testing.expect(h.subscribed(sysmon, .missing, 15007, 60) == null);
    try std.testing.expect(!h.sysmonPresent());
    try std.testing.expect(!h.sysmonDelivering());

    _ = h.subscribed(security, .ok, 0, 0);
    try std.testing.expect(h.tick(security, 0, channel_silence_seconds - 1) == null);
    const silent = h.tick(security, 0, channel_silence_seconds).?;
    try std.testing.expectEqual(ChannelState.silent, silent.to);
    try std.testing.expect(h.tick(security, 0, channel_silence_seconds + 5) == null);
    const back = h.tick(security, 3, channel_silence_seconds + 10).?;
    try std.testing.expectEqual(ChannelState.ok, back.to);
    try std.testing.expectEqual(ChannelState.silent, back.from);
    // Missing channels never flip to silent.
    try std.testing.expect(h.tick(sysmon, 0, 10 * channel_silence_seconds) == null);

    const alloc = std.testing.allocator;
    const payload = try healthPayload(alloc, &h, missing, .{ .dropped_parse = 2 });
    defer alloc.free(payload);
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, payload, .{});
    defer parsed.deinit();
    try expectStr(parsed.value, "channel", "Microsoft-Windows-Sysmon/Operational");
    try expectStr(parsed.value, "state", "missing");
    try expectStr(parsed.value, "status", "degraded");
    try expectStr(parsed.value, "process_start_source", "security_4688");
    try expectInt(parsed.value, "win32_error", 15007);
    try expectInt(parsed.value, "counters.dropped_parse", 2);
    try std.testing.expect(!getPath(parsed.value, "sysmon_present").?.bool);
}

test "queries, bookmark names and time parsing" {
    const alloc = std.testing.allocator;
    const q = try buildQuery(alloc, channels[3], null);
    defer alloc.free(q);
    try std.testing.expectEqualStrings("*[System[(EventID=4104)]]", q);
    const q2 = try buildQuery(alloc, channels[2], 600000);
    defer alloc.free(q2);
    try std.testing.expectEqualStrings("*[System[(EventID=7045) and TimeCreated[timediff(@SystemTime) <= 600000]]]", q2);

    const name = try bookmarkFileName(alloc, "Microsoft-Windows-Sysmon/Operational");
    defer alloc.free(name);
    try std.testing.expectEqualStrings("eventlog-microsoft-windows-sysmon-operational.bookmark", name);

    try std.testing.expectEqual(@as(?i64, 0), parseSystemTime("1970-01-01T00:00:00Z"));
    try std.testing.expectEqual(@as(?i64, 1762650764), parseSystemTime("2025-11-09T01:12:44.5512031Z"));
    try std.testing.expectEqual(@as(?i64, 951782400), parseSystemTime("2000-02-29T00:00:00Z"));
    try std.testing.expect(parseSystemTime("garbage") == null);
    try std.testing.expectEqual(Source.sysmon, sourceForChannel("microsoft-windows-sysmon/operational").?);
}

test "bookmarks round-trip through the state directory" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fs.path.join(alloc, &.{ ".zig-cache", "tmp", &tmp.sub_path, "state" });
    defer alloc.free(dir);

    try std.testing.expect(loadBookmark(alloc, dir, "Security") == null);
    const xml = "<BookmarkList>\r\n  <Bookmark Channel='Security' RecordId='902300' IsCurrent='true'/>\r\n</BookmarkList>";
    try writeBookmark(alloc, dir, "Security", xml);
    const loaded = loadBookmark(alloc, dir, "Security").?;
    defer alloc.free(loaded);
    try std.testing.expectEqualStrings(xml, loaded);
    // Overwrite is atomic and replaces the old content.
    try writeBookmark(alloc, dir, "Security", "<BookmarkList><Bookmark RecordId='902301'/></BookmarkList>");
    const again = loadBookmark(alloc, dir, "Security").?;
    defer alloc.free(again);
    try std.testing.expect(std.mem.indexOf(u8, again, "902301") != null);
    // Junk is ignored rather than handed to EvtCreateBookmark.
    try writeBookmark(alloc, dir, "System", "junk");
    try std.testing.expect(loadBookmark(alloc, dir, "System") == null);
}

test "utf8 truncation keeps whole code points" {
    try std.testing.expectEqualStrings("ab", truncUtf8("ab\xc3\xa9", 3));
    try std.testing.expectEqualStrings("ab\xc3\xa9", truncUtf8("ab\xc3\xa9", 4));
}

test "sysmon 1 and 5 carry entity ids; the child joins the parent seeded from a snapshot" {
    const alloc = std.testing.allocator;
    var table = entity.Table.init(alloc, "0f8fad5b-d9cb-469f-a165-70867728950e", "3c1c4b5e-6d2a-4f0e-9b7a-2d1e5f6a7b8c", 64);
    defer table.deinit();
    // cmd.exe (pid 5532) was running when the agent started.
    const parent_start = entity.parseIso("2026-11-09T01:12:40.000Z").?;
    const parent_id = try table.observe(5532, parent_start, "");

    var ev = try evtxml.parse(alloc, samples.sysmon_1);
    defer ev.deinit();
    const start = (try mapEventWith(alloc, &ev, &table)).?;
    defer alloc.free(start.payload);
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, start.payload, .{});
    defer parsed.deinit();
    const want = entity.compute("0f8fad5b-d9cb-469f-a165-70867728950e", 6844, entity.parseIso("2026-11-09 01:12:44.548").?, "3c1c4b5e-6d2a-4f0e-9b7a-2d1e5f6a7b8c");
    try expectStr(parsed.value, "process.entity_id", &want);
    try expectStr(parsed.value, "parent.entity_id", &parent_id);
    // The Sysmon ProcessGuid stays as an extra field, not the id.
    try expectStr(parsed.value, "process.guid", "{4f3c6a1e-b7cc-672e-2c01-000000001e00}");
    try schema_check.expectValid(alloc, "process_start", start.payload);

    var exit_ev = try evtxml.parse(alloc, samples.sysmon_5);
    defer exit_ev.deinit();
    const exit = (try mapEventWith(alloc, &exit_ev, &table)).?;
    defer alloc.free(exit.payload);
    try schema_check.expectValid(alloc, "process_exit", exit.payload);
}

test "parent seeded after pid reuse is not used for an older child" {
    const alloc = std.testing.allocator;
    var table = entity.Table.init(alloc, "0f8fad5b-d9cb-469f-a165-70867728950e", "3c1c4b5e-6d2a-4f0e-9b7a-2d1e5f6a7b8c", 64);
    defer table.deinit();
    // pid 5532 now belongs to a process that started after the child.
    _ = try table.observe(5532, entity.parseIso("2026-11-09T02:00:00.000Z").?, "");
    var ev = try evtxml.parse(alloc, samples.sysmon_1);
    defer ev.deinit();
    const m = (try mapEventWith(alloc, &ev, &table)).?;
    defer alloc.free(m.payload);
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, m.payload, .{});
    defer parsed.deinit();
    try std.testing.expect(getPath(parsed.value, "parent.entity_id") == null);
    try std.testing.expect(getPath(parsed.value, "process.entity_id") != null);
}

test "security 4688 gets an entity id from TimeCreated" {
    const alloc = std.testing.allocator;
    var table = entity.Table.init(alloc, "0f8fad5b-d9cb-469f-a165-70867728950e", "3c1c4b5e-6d2a-4f0e-9b7a-2d1e5f6a7b8c", 64);
    defer table.deinit();
    var ev = try evtxml.parse(alloc, samples.security_4688);
    defer ev.deinit();
    const m = (try mapEventWith(alloc, &ev, &table)).?;
    defer alloc.free(m.payload);
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, m.payload, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, entity.len), getPath(parsed.value, "process.entity_id").?.string.len);
    try std.testing.expect(getPath(parsed.value, "process.start_time") != null);
    try schema_check.expectValid(alloc, "process_start", m.payload);
}

test "mapped Windows payloads match their schemas" {
    const alloc = std.testing.allocator;
    const cases = [_]struct { xml: []const u8, ty: []const u8 }{
        .{ .xml = samples.sysmon_3, .ty = "network_connect" },
        .{ .xml = samples.sysmon_11, .ty = "file_create" },
        .{ .xml = samples.sysmon_13, .ty = "registry_set" },
        .{ .xml = samples.sysmon_22, .ty = "dns_query" },
        .{ .xml = samples.security_4624, .ty = "user_logon" },
        .{ .xml = samples.system_7045, .ty = "service_create" },
    };
    for (cases) |c| {
        var ev = try evtxml.parse(alloc, c.xml);
        defer ev.deinit();
        const m = (try mapEvent(alloc, &ev)).?;
        defer alloc.free(m.payload);
        try std.testing.expectEqualStrings(c.ty, m.event_type);
        try schema_check.expectValid(alloc, c.ty, m.payload);
    }
}
