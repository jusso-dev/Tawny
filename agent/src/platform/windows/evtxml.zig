//! Parser for the XML that `EvtRender(EvtRenderEventXml)` produces.
//!
//! Pure code with no Windows calls, so its tests run on every host. It pulls
//! the `System` fields the collector needs plus every `EventData/Data[@Name]`
//! into a flat list. It is not a general XML parser: it relies on the fixed
//! shape the Windows event log renders (no DTDs, no namespaces on children,
//! attributes quoted with ' or ").
const std = @import("std");

pub const max_xml_bytes: usize = 1024 * 1024;
pub const max_fields: usize = 128;

pub const Field = struct {
    name: []u8,
    value: []u8,
};

pub const Event = struct {
    allocator: std.mem.Allocator,
    event_id: u32 = 0,
    record_id: u64 = 0,
    /// `System/TimeCreated/@SystemTime`, ISO 8601 UTC.
    time_created: []u8 = &.{},
    channel: []u8 = &.{},
    provider: []u8 = &.{},
    computer: []u8 = &.{},
    /// `System/Execution/@ProcessID`: the process that logged the event.
    execution_pid: ?u32 = null,
    /// `System/Security/@UserID`: SID of the user the event was logged for.
    user_sid: []u8 = &.{},
    fields: []Field = &.{},

    pub fn deinit(self: *Event) void {
        const a = self.allocator;
        a.free(self.time_created);
        a.free(self.channel);
        a.free(self.provider);
        a.free(self.computer);
        a.free(self.user_sid);
        for (self.fields) |f| {
            a.free(f.name);
            a.free(f.value);
        }
        a.free(self.fields);
        self.* = undefined;
    }

    /// Value of `EventData/Data[@Name=name]`, or null when absent.
    pub fn get(self: *const Event, name: []const u8) ?[]const u8 {
        for (self.fields) |f| {
            if (std.mem.eql(u8, f.name, name)) return f.value;
        }
        return null;
    }
};

pub const ParseError = error{ InvalidEventXml, EventXmlTooLarge, OutOfMemory };

/// Parse one rendered event. Caller owns the result and calls `deinit`.
pub fn parse(alloc: std.mem.Allocator, xml: []const u8) ParseError!Event {
    if (xml.len > max_xml_bytes) return error.EventXmlTooLarge;
    const system = findElement(xml, "System") orelse return error.InvalidEventXml;
    const system_inner = system.inner orelse return error.InvalidEventXml;

    var ev = Event{ .allocator = alloc };
    errdefer ev.deinit();

    const event_id_el = findElement(system_inner, "EventID") orelse return error.InvalidEventXml;
    ev.event_id = std.fmt.parseInt(u32, trimText(event_id_el.inner orelse ""), 10) catch return error.InvalidEventXml;

    if (findElement(system_inner, "EventRecordID")) |el| {
        ev.record_id = std.fmt.parseInt(u64, trimText(el.inner orelse ""), 10) catch 0;
    }
    if (findElement(system_inner, "TimeCreated")) |el| {
        if (attribute(el.attrs, "SystemTime")) |v| ev.time_created = try unescape(alloc, v);
    }
    if (findElement(system_inner, "Provider")) |el| {
        if (attribute(el.attrs, "Name")) |v| ev.provider = try unescape(alloc, v);
    }
    if (findElement(system_inner, "Channel")) |el| {
        ev.channel = try unescape(alloc, trimText(el.inner orelse ""));
    }
    if (findElement(system_inner, "Computer")) |el| {
        ev.computer = try unescape(alloc, trimText(el.inner orelse ""));
    }
    if (findElement(system_inner, "Execution")) |el| {
        if (attribute(el.attrs, "ProcessID")) |v| ev.execution_pid = std.fmt.parseInt(u32, v, 10) catch null;
    }
    if (findElement(system_inner, "Security")) |el| {
        if (attribute(el.attrs, "UserID")) |v| ev.user_sid = try unescape(alloc, v);
    }

    var fields = std.array_list.Managed(Field).init(alloc);
    errdefer {
        for (fields.items) |f| {
            alloc.free(f.name);
            alloc.free(f.value);
        }
        fields.deinit();
    }
    const after_system = xml[system.end..];
    if (findElement(after_system, "EventData")) |data_el| {
        var rest = data_el.inner orelse "";
        while (fields.items.len < max_fields) {
            const el = findElement(rest, "Data") orelse break;
            rest = rest[el.end..];
            const raw_name = attribute(el.attrs, "Name") orelse continue;
            const name = try unescape(alloc, raw_name);
            errdefer alloc.free(name);
            const value = try unescape(alloc, el.inner orelse "");
            errdefer alloc.free(value);
            try fields.append(.{ .name = name, .value = value });
        }
    }
    ev.fields = try fields.toOwnedSlice();
    return ev;
}

const Element = struct {
    /// Raw attribute text between the tag name and `>` / `/>`.
    attrs: []const u8,
    /// Raw content between the start and end tag; null when self-closing.
    inner: ?[]const u8,
    /// Offset just past the element in the searched slice.
    end: usize,
};

/// First element named `name` in `xml` (at any depth). Matching stops at the
/// matching close tag; nested elements of the same name are not expected in
/// rendered events.
fn findElement(xml: []const u8, name: []const u8) ?Element {
    var pos: usize = 0;
    while (std.mem.indexOfScalarPos(u8, xml, pos, '<')) |lt| {
        pos = lt + 1;
        const after = xml[lt + 1 ..];
        if (after.len == 0) return null;
        if (after[0] == '!' and std.mem.startsWith(u8, after, "!--")) {
            const close = std.mem.indexOfPos(u8, xml, lt, "-->") orelse return null;
            pos = close + 3;
            continue;
        }
        if (!std.mem.startsWith(u8, after, name)) continue;
        if (after.len == name.len) return null;
        const boundary = after[name.len];
        if (boundary != ' ' and boundary != '>' and boundary != '/' and boundary != '\t' and boundary != '\r' and boundary != '\n') continue;

        const tag_end = tagEnd(xml, lt + 1 + name.len) orelse return null;
        const self_closing = xml[tag_end - 1] == '/';
        const attrs_end = if (self_closing) tag_end - 1 else tag_end;
        const attrs = xml[lt + 1 + name.len .. attrs_end];
        if (self_closing) return .{ .attrs = attrs, .inner = null, .end = tag_end + 1 };

        const content_start = tag_end + 1;
        var close_buf: [64]u8 = undefined;
        const close_tag = std.fmt.bufPrint(&close_buf, "</{s}>", .{name}) catch return null;
        const close = std.mem.indexOfPos(u8, xml, content_start, close_tag) orelse return null;
        return .{ .attrs = attrs, .inner = xml[content_start..close], .end = close + close_tag.len };
    }
    return null;
}

/// Index of the `>` closing a start tag, skipping quoted attribute values.
fn tagEnd(xml: []const u8, start: usize) ?usize {
    var i = start;
    var quote: u8 = 0;
    while (i < xml.len) : (i += 1) {
        const c = xml[i];
        if (quote != 0) {
            if (c == quote) quote = 0;
        } else if (c == '\'' or c == '"') {
            quote = c;
        } else if (c == '>') {
            return i;
        }
    }
    return null;
}

/// Raw (still escaped) value of attribute `name` in a start tag.
fn attribute(attrs: []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < attrs.len) {
        while (i < attrs.len and std.ascii.isWhitespace(attrs[i])) i += 1;
        const name_start = i;
        while (i < attrs.len and attrs[i] != '=' and !std.ascii.isWhitespace(attrs[i])) i += 1;
        const attr_name = attrs[name_start..i];
        while (i < attrs.len and std.ascii.isWhitespace(attrs[i])) i += 1;
        if (i >= attrs.len or attrs[i] != '=') return null;
        i += 1;
        while (i < attrs.len and std.ascii.isWhitespace(attrs[i])) i += 1;
        if (i >= attrs.len) return null;
        const quote = attrs[i];
        if (quote != '\'' and quote != '"') return null;
        const value_start = i + 1;
        const value_end = std.mem.indexOfScalarPos(u8, attrs, value_start, quote) orelse return null;
        if (std.mem.eql(u8, attr_name, name)) return attrs[value_start..value_end];
        i = value_end + 1;
    }
    return null;
}

fn trimText(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r\n");
}

/// Decode the five predefined entities and numeric character references.
/// Unknown entities are copied through unchanged.
pub fn unescape(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    if (std.mem.indexOfScalar(u8, raw, '&') == null) return alloc.dupe(u8, raw);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.ensureTotalCapacity(alloc, raw.len);
    var i: usize = 0;
    while (i < raw.len) {
        if (raw[i] != '&') {
            out.appendAssumeCapacity(raw[i]);
            i += 1;
            continue;
        }
        const semi = std.mem.indexOfScalarPos(u8, raw, i, ';') orelse {
            out.appendAssumeCapacity('&');
            i += 1;
            continue;
        };
        const entity = raw[i + 1 .. semi];
        const named: ?u8 = if (std.mem.eql(u8, entity, "lt"))
            '<'
        else if (std.mem.eql(u8, entity, "gt"))
            '>'
        else if (std.mem.eql(u8, entity, "amp"))
            '&'
        else if (std.mem.eql(u8, entity, "quot"))
            '"'
        else if (std.mem.eql(u8, entity, "apos"))
            '\''
        else
            null;
        if (named) |c| {
            out.appendAssumeCapacity(c);
            i = semi + 1;
            continue;
        }
        if (entity.len > 1 and entity[0] == '#') {
            const cp: ?u21 = if (entity[1] == 'x' or entity[1] == 'X')
                std.fmt.parseInt(u21, entity[2..], 16) catch null
            else
                std.fmt.parseInt(u21, entity[1..], 10) catch null;
            if (cp) |code| {
                var enc: [4]u8 = undefined;
                if (std.unicode.utf8Encode(code, &enc)) |n| {
                    // Encoded form is never longer than the reference text.
                    out.appendSliceAssumeCapacity(enc[0..n]);
                    i = semi + 1;
                    continue;
                } else |_| {}
            }
        }
        out.appendAssumeCapacity('&');
        i += 1;
    }
    return out.toOwnedSlice(alloc);
}

// ---------------------------------------------------------------------------
// Tests. Samples under testdata/ follow the shape EvtRender produces on
// Windows 10/11 and Server 2022 (single-quoted attributes, one line per
// element as in the Event Viewer XML view).

pub const samples = struct {
    pub const sysmon_1 = @embedFile("testdata/sysmon_1_process_create.xml");
    pub const sysmon_3 = @embedFile("testdata/sysmon_3_network_connect.xml");
    pub const sysmon_5 = @embedFile("testdata/sysmon_5_process_terminate.xml");
    pub const sysmon_7 = @embedFile("testdata/sysmon_7_image_load.xml");
    pub const sysmon_8 = @embedFile("testdata/sysmon_8_create_remote_thread.xml");
    pub const sysmon_10 = @embedFile("testdata/sysmon_10_process_access.xml");
    pub const sysmon_11 = @embedFile("testdata/sysmon_11_file_create.xml");
    pub const sysmon_12 = @embedFile("testdata/sysmon_12_registry_create.xml");
    pub const sysmon_13 = @embedFile("testdata/sysmon_13_registry_set.xml");
    pub const sysmon_14 = @embedFile("testdata/sysmon_14_registry_rename.xml");
    pub const sysmon_22 = @embedFile("testdata/sysmon_22_dns_query.xml");
    pub const sysmon_23 = @embedFile("testdata/sysmon_23_file_delete.xml");
    pub const sysmon_26 = @embedFile("testdata/sysmon_26_file_delete_detected.xml");
    pub const security_4624 = @embedFile("testdata/security_4624_logon.xml");
    pub const security_4625 = @embedFile("testdata/security_4625_logon_failed.xml");
    pub const security_4672 = @embedFile("testdata/security_4672_special_privileges.xml");
    pub const security_4688 = @embedFile("testdata/security_4688_process_creation.xml");
    pub const system_7045 = @embedFile("testdata/system_7045_service_installed.xml");
    pub const powershell_4104_part1 = @embedFile("testdata/powershell_4104_part1.xml");
    pub const powershell_4104_part2 = @embedFile("testdata/powershell_4104_part2.xml");
    pub const powershell_4104_single = @embedFile("testdata/powershell_4104_single.xml");
};

test "every sample parses with its event id, record id and channel" {
    const Case = struct { xml: []const u8, id: u32, channel: []const u8 };
    const sysmon = "Microsoft-Windows-Sysmon/Operational";
    const cases = [_]Case{
        .{ .xml = samples.sysmon_1, .id = 1, .channel = sysmon },
        .{ .xml = samples.sysmon_3, .id = 3, .channel = sysmon },
        .{ .xml = samples.sysmon_5, .id = 5, .channel = sysmon },
        .{ .xml = samples.sysmon_7, .id = 7, .channel = sysmon },
        .{ .xml = samples.sysmon_8, .id = 8, .channel = sysmon },
        .{ .xml = samples.sysmon_10, .id = 10, .channel = sysmon },
        .{ .xml = samples.sysmon_11, .id = 11, .channel = sysmon },
        .{ .xml = samples.sysmon_12, .id = 12, .channel = sysmon },
        .{ .xml = samples.sysmon_13, .id = 13, .channel = sysmon },
        .{ .xml = samples.sysmon_14, .id = 14, .channel = sysmon },
        .{ .xml = samples.sysmon_22, .id = 22, .channel = sysmon },
        .{ .xml = samples.sysmon_23, .id = 23, .channel = sysmon },
        .{ .xml = samples.sysmon_26, .id = 26, .channel = sysmon },
        .{ .xml = samples.security_4624, .id = 4624, .channel = "Security" },
        .{ .xml = samples.security_4625, .id = 4625, .channel = "Security" },
        .{ .xml = samples.security_4672, .id = 4672, .channel = "Security" },
        .{ .xml = samples.security_4688, .id = 4688, .channel = "Security" },
        .{ .xml = samples.system_7045, .id = 7045, .channel = "System" },
        .{ .xml = samples.powershell_4104_part1, .id = 4104, .channel = "Microsoft-Windows-PowerShell/Operational" },
        .{ .xml = samples.powershell_4104_part2, .id = 4104, .channel = "Microsoft-Windows-PowerShell/Operational" },
        .{ .xml = samples.powershell_4104_single, .id = 4104, .channel = "Microsoft-Windows-PowerShell/Operational" },
    };
    for (cases) |c| {
        var ev = try parse(std.testing.allocator, c.xml);
        defer ev.deinit();
        try std.testing.expectEqual(c.id, ev.event_id);
        try std.testing.expectEqualStrings(c.channel, ev.channel);
        try std.testing.expect(ev.record_id > 0);
        try std.testing.expect(std.mem.endsWith(u8, ev.time_created, "Z"));
        try std.testing.expect(ev.fields.len > 0);
    }
}

test "sysmon process create exposes system and data fields" {
    var ev = try parse(std.testing.allocator, samples.sysmon_1);
    defer ev.deinit();
    try std.testing.expectEqual(@as(u64, 48211), ev.record_id);
    try std.testing.expectEqualStrings("2026-11-09T01:12:44.5512031Z", ev.time_created);
    try std.testing.expectEqualStrings("Microsoft-Windows-Sysmon", ev.provider);
    try std.testing.expectEqualStrings("WIN-TAWNY01", ev.computer);
    try std.testing.expectEqual(@as(?u32, 3120), ev.execution_pid);
    try std.testing.expectEqualStrings("S-1-5-18", ev.user_sid);
    try std.testing.expectEqualStrings("C:\\Windows\\System32\\whoami.exe", ev.get("Image").?);
    try std.testing.expectEqualStrings("whoami  /all", ev.get("CommandLine").?);
    try std.testing.expectEqualStrings("-", ev.get("RuleName").?);
    try std.testing.expect(ev.get("NoSuchField") == null);
}

test "qualifiers on EventID and empty Data elements are handled" {
    var ev = try parse(std.testing.allocator, samples.system_7045);
    defer ev.deinit();
    try std.testing.expectEqual(@as(u32, 7045), ev.event_id);
    try std.testing.expectEqualStrings("Service Control Manager", ev.provider);
    try std.testing.expectEqualStrings("TawnyTestSvc", ev.get("ServiceName").?);

    var ps = try parse(std.testing.allocator, samples.powershell_4104_part2);
    defer ps.deinit();
    try std.testing.expectEqualStrings("", ps.get("Path").?);
}

test "entities in data values are decoded" {
    var ev = try parse(std.testing.allocator, samples.powershell_4104_part1);
    defer ev.deinit();
    const text = ev.get("ScriptBlockText").?;
    try std.testing.expect(std.mem.indexOf(u8, text, "$a -lt 3 && \"x\" <# c #>") != null);

    const decoded = try unescape(std.testing.allocator, "a&#x41;&#66;&bogus;&");
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings("aAB&bogus;&", decoded);
}

test "malformed xml is rejected without leaking" {
    try std.testing.expectError(error.InvalidEventXml, parse(std.testing.allocator, ""));
    try std.testing.expectError(error.InvalidEventXml, parse(std.testing.allocator, "<Event><System><EventID>x</EventID></System></Event>"));
    try std.testing.expectError(error.InvalidEventXml, parse(std.testing.allocator, "<Event><System><EventID>4</EventID>"));
    // A cut-off EventData keeps the System fields and yields no data fields.
    var ev = try parse(std.testing.allocator, "<Event><System><EventID>4</EventID></System><EventData><Data Name='A'>1</Data><Data Name='B'");
    defer ev.deinit();
    try std.testing.expectEqual(@as(u32, 4), ev.event_id);
    try std.testing.expectEqual(@as(usize, 0), ev.fields.len);
    // A Data element with no closing tag is skipped, earlier ones are kept.
    var partial = try parse(std.testing.allocator, "<Event><System><EventID>4</EventID></System><EventData><Data Name='A'>1</Data><Data Name='B'></EventData></Event>");
    defer partial.deinit();
    try std.testing.expectEqualStrings("1", partial.get("A").?);
    try std.testing.expect(partial.get("B") == null);
}

test "comments and similarly named elements do not confuse lookup" {
    const xml =
        \\<Event><!-- <System><EventID>9</EventID></System> --><System><EventIDX>5</EventIDX><EventID>7</EventID></System>
        \\<EventData><DataX Name='no'>n</DataX><Data Name="Quoted" >v&amp;w</Data></EventData></Event>
    ;
    var ev = try parse(std.testing.allocator, xml);
    defer ev.deinit();
    try std.testing.expectEqual(@as(u32, 7), ev.event_id);
    try std.testing.expectEqual(@as(usize, 1), ev.fields.len);
    try std.testing.expectEqualStrings("v&w", ev.get("Quoted").?);
}
