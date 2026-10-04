//! Slack webhook body. `text` is plain. Block text escapes `&`, `<`, `>`.
const std = @import("std");

pub fn format(
    allocator: std.mem.Allocator,
    username: []const u8,
    icon_emoji: []const u8,
    severity: []const u8,
    status: []const u8,
    title: []const u8,
    description: []const u8,
    hostname: []const u8,
    event_type: []const u8,
    alert_id: i64,
    created_at: []const u8,
) ![]u8 {
    const user = if (username.len == 0) "Tawny" else username;
    const icon = if (icon_emoji.len == 0) ":rotating_light:" else icon_emoji;
    const sev = try lower(allocator, severity);
    defer allocator.free(sev);
    const st = try lower(allocator, status);
    defer allocator.free(st);
    const text = try std.fmt.allocPrint(allocator, "[{s}] {s} on {s}", .{ sev, title, hostname });
    defer allocator.free(text);
    const text_j = try escape(allocator, text);
    defer allocator.free(text_j);
    const user_j = try escape(allocator, user);
    defer allocator.free(user_j);
    const icon_j = try escape(allocator, icon);
    defer allocator.free(icon_j);
    const head = try blockText(allocator, title, description);
    defer allocator.free(head);
    const fields = try fieldsText(allocator, sev, st, hostname, event_type, alert_id, created_at);
    defer allocator.free(fields);
    return std.fmt.allocPrint(allocator,
        \\{{"text":{s},"username":{s},"icon_emoji":{s},"blocks":[{{"type":"section","text":{{"type":"mrkdwn","text":{s}}}}},{{"type":"section","fields":[{s}]}}]}}
    , .{ text_j, user_j, icon_j, head, fields });
}

fn blockText(allocator: std.mem.Allocator, title: []const u8, description: []const u8) ![]u8 {
    const desc = if (description.len > 1800) description[0..1800] else description;
    const et = try slackEscape(allocator, title);
    defer allocator.free(et);
    const ed = try slackEscape(allocator, desc);
    defer allocator.free(ed);
    const body = try std.fmt.allocPrint(allocator, "*{s}*\n{s}", .{ et, ed });
    defer allocator.free(body);
    return escape(allocator, body);
}

fn fieldsText(
    allocator: std.mem.Allocator,
    severity: []const u8,
    status: []const u8,
    hostname: []const u8,
    event_type: []const u8,
    alert_id: i64,
    created_at: []const u8,
) ![]u8 {
    var id_buf: [32]u8 = undefined;
    const id_s = std.fmt.bufPrint(&id_buf, "{d}", .{alert_id}) catch return error.OutOfMemory;
    const parts = [_]struct { []const u8, []const u8 }{
        .{ "Severity", severity },
        .{ "Status", status },
        .{ "Agent", hostname },
        .{ "Event", event_type },
        .{ "Alert ID", id_s },
        .{ "Created", created_at },
    };
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (parts, 0..) |part, i| {
        if (i > 0) try out.append(allocator, ',');
        const esc = try slackEscape(allocator, part[1]);
        defer allocator.free(esc);
        const line = try std.fmt.allocPrint(allocator, "*{s}:*\n{s}", .{ part[0], esc });
        defer allocator.free(line);
        const quoted = try escape(allocator, line);
        defer allocator.free(quoted);
        try out.appendSlice(allocator, "{\"type\":\"mrkdwn\",\"text\":");
        try out.appendSlice(allocator, quoted);
        try out.append(allocator, '}');
    }
    return out.toOwnedSlice(allocator);
}

fn slackEscape(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (value) |c| switch (c) {
        '&' => try out.appendSlice(allocator, "&amp;"),
        '<' => try out.appendSlice(allocator, "&lt;"),
        '>' => try out.appendSlice(allocator, "&gt;"),
        else => try out.append(allocator, c),
    };
    return out.toOwnedSlice(allocator);
}

fn escape(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, '"');
    for (value) |c| switch (c) {
        '"' => try out.appendSlice(allocator, "\\\""),
        '\\' => try out.appendSlice(allocator, "\\\\"),
        '\n' => try out.appendSlice(allocator, "\\n"),
        else => try out.append(allocator, c),
    };
    try out.append(allocator, '"');
    return out.toOwnedSlice(allocator);
}

fn lower(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, value.len);
    for (value, 0..) |c, i| {
        out[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
    }
    return out;
}

test "slack text and escaped block match the webhook shape" {
    const allocator = std.testing.allocator;
    const json = try format(
        allocator,
        "",
        "",
        "High",
        "Open",
        "Suspicious <process> on linux-host-01",
        "Matched processes Contains suspicious.exe.",
        "linux-host-01",
        "ProcessSnapshot",
        7,
        "2026-05-14 08:00:02Z",
    );
    defer allocator.free(json);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqualStrings("[high] Suspicious <process> on linux-host-01 on linux-host-01", root.get("text").?.string);
    try std.testing.expectEqualStrings("Tawny", root.get("username").?.string);
    try std.testing.expectEqualStrings(":rotating_light:", root.get("icon_emoji").?.string);
    const blocks = root.get("blocks").?.array.items;
    const head = blocks[0].object.get("text").?.object.get("text").?.string;
    try std.testing.expect(std.mem.indexOf(u8, head, "*Suspicious &lt;process&gt; on linux-host-01*") != null);
    const fields = blocks[1].object.get("fields").?.array.items;
    try std.testing.expectEqualStrings("*Severity:*\nhigh", fields[0].object.get("text").?.string);
    try std.testing.expectEqualStrings("*Event:*\nProcessSnapshot", fields[3].object.get("text").?.string);
    try std.testing.expectEqualStrings("*Alert ID:*\n7", fields[4].object.get("text").?.string);
}
