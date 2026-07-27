const std = @import("std");

pub const max_command_line_bytes: usize = 2048;
const max_input_bytes: usize = 32 * 1024;

/// Keep command-line telemetry useful without shipping common credential
/// values. Whitespace is normalized and output is hard-capped.
pub fn sanitizeCommandLine(alloc: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();

    const bounded = input[0..@min(input.len, max_input_bytes)];
    var tokens = std.mem.tokenizeAny(u8, bounded, " \t\r\n");
    var first = true;
    var redact_tokens: usize = 0;
    while (tokens.next()) |token| {
        if (out.written().len >= max_command_line_bytes) break;
        if (!first) try appendBounded(&out.writer, " ");
        first = false;

        if (redact_tokens > 0) {
            try appendBounded(&out.writer, "[REDACTED]");
            redact_tokens -= 1;
            continue;
        }

        if (authorizationValue(token)) |authorization| {
            try appendBounded(&out.writer, authorization.prefix);
            try appendBounded(&out.writer, "[REDACTED]");
            redact_tokens = authorization.following_tokens;
            continue;
        }

        if (std.mem.indexOfScalar(u8, token, '=')) |equals| {
            const key = token[0..equals];
            if (isSensitiveKey(key)) {
                try appendBounded(&out.writer, key);
                try appendBounded(&out.writer, "=[REDACTED]");
                continue;
            }
        }

        if (isSensitiveKey(token)) {
            try appendBounded(&out.writer, token);
            redact_tokens = 1;
            continue;
        }

        if (urlParts(token)) |parts| {
            try appendBounded(&out.writer, parts.prefix);
            if (parts.had_userinfo) try appendBounded(&out.writer, "[REDACTED]@");
            try appendBounded(&out.writer, parts.safe_suffix);
            if (parts.redacted_delimiter) |delimiter| {
                try appendBounded(&out.writer, delimiter);
                try appendBounded(&out.writer, "[REDACTED]");
            }
            continue;
        }

        try appendBounded(&out.writer, token);
    }
    if (input.len > bounded.len or tokens.peek() != null) {
        try appendBounded(&out.writer, " [TRUNCATED]");
    }
    return out.toOwnedSlice();
}

fn appendBounded(writer: *std.Io.Writer, value: []const u8) !void {
    const remaining = max_command_line_bytes -| writer.buffered().len;
    if (remaining == 0) return;
    try writer.writeAll(value[0..@min(value.len, remaining)]);
}

fn isSensitiveKey(raw: []const u8) bool {
    const key = std.mem.trimStart(u8, raw, "-/");
    const sensitive = [_][]const u8{
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "access_token",
        "access-token",
        "api_key",
        "api-key",
        "apikey",
        "authorization",
        "credential",
        "credentials",
        "client_secret",
        "client-secret",
        "private_key",
        "private-key",
        "aws_secret_access_key",
        "aws_session_token",
    };
    for (sensitive) |candidate| {
        if (std.ascii.eqlIgnoreCase(key, candidate)) return true;
    }
    return false;
}

const UrlParts = struct {
    prefix: []const u8,
    safe_suffix: []const u8,
    redacted_delimiter: ?[]const u8,
    had_userinfo: bool,
};

fn urlParts(token: []const u8) ?UrlParts {
    const scheme = std.mem.indexOf(u8, token, "://") orelse return null;
    const authority_start = scheme + 3;
    const authority_end_offset = std.mem.indexOfAny(u8, token[authority_start..], "/?#") orelse
        token.len - authority_start;
    const authority_end = authority_start + authority_end_offset;
    const at_offset = std.mem.lastIndexOfScalar(u8, token[authority_start..authority_end], '@');
    const safe_start = if (at_offset) |offset| authority_start + offset + 1 else authority_start;
    const sensitive_offset = std.mem.indexOfAny(u8, token[safe_start..], "?#");
    const safe_end = if (sensitive_offset) |offset| safe_start + offset else token.len;
    return .{
        .prefix = token[0..authority_start],
        .safe_suffix = token[safe_start..safe_end],
        .redacted_delimiter = if (sensitive_offset) |offset|
            token[safe_start + offset .. safe_start + offset + 1]
        else
            null,
        .had_userinfo = at_offset != null,
    };
}

const AuthorizationValue = struct {
    prefix: []const u8,
    following_tokens: usize,
};

fn authorizationValue(token: []const u8) ?AuthorizationValue {
    const marker = "authorization:";
    const start = indexOfIgnoreCase(token, marker) orelse return null;
    const value = std.mem.trim(u8, token[start + marker.len ..], "\"'");
    const following_tokens: usize = if (value.len == 0)
        2
    else if (std.ascii.eqlIgnoreCase(value, "bearer") or std.ascii.eqlIgnoreCase(value, "basic"))
        1
    else
        0;
    return .{
        .prefix = token[0 .. start + marker.len],
        .following_tokens = following_tokens,
    };
}

fn indexOfIgnoreCase(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0 or haystack.len < needle.len) return null;
    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[index .. index + needle.len], needle)) return index;
    }
    return null;
}

test "command line secrets are redacted and URLs keep destination" {
    const result = try sanitizeCommandLine(
        std.testing.allocator,
        "curl --token abc https://user:pass@example.com/path?key=value AWS_SECRET_ACCESS_KEY=xyz --safe yes",
    );
    defer std.testing.allocator.free(result);

    try std.testing.expectEqualStrings(
        "curl --token [REDACTED] https://[REDACTED]@example.com/path?[REDACTED] AWS_SECRET_ACCESS_KEY=[REDACTED] --safe yes",
        result,
    );
    try std.testing.expect(std.mem.indexOf(u8, result, "abc") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "pass") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "xyz") == null);
}

test "authorization header values are redacted across tokens" {
    const result = try sanitizeCommandLine(
        std.testing.allocator,
        "curl -H \"Authorization: Bearer top-secret\" https://example.com",
    );
    defer std.testing.allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "top-secret") == null);
    try std.testing.expect(std.mem.indexOf(u8, result, "Authorization:[REDACTED]") != null);
}

test "command line output is bounded" {
    const raw = try std.testing.allocator.alloc(u8, max_command_line_bytes * 2);
    defer std.testing.allocator.free(raw);
    @memset(raw, 'a');

    const result = try sanitizeCommandLine(std.testing.allocator, raw);
    defer std.testing.allocator.free(result);
    try std.testing.expect(result.len <= max_command_line_bytes);
}
