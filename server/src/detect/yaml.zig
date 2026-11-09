//! YAML subset for Sigma and Tawny rule files.
//!
//! Handles block maps, block lists (including lists of maps), plain and
//! quoted scalars, flow lists (`[a, b]`), simple flow maps, block scalars
//! (`|`, `>`, with `-` or `+` chomping) and comments. Anchors, aliases, tags
//! and multi-document files are refused with an error, never guessed at.
//! The tree lives in the caller's arena.

const std = @import("std");

pub const Error = error{
    OutOfMemory,
    YamlTab,
    YamlBadIndent,
    YamlUnterminatedQuote,
    YamlAlias,
    YamlTag,
    YamlMultiDocument,
    YamlBadFlow,
    YamlDuplicateKey,
    YamlTooDeep,
    YamlTooLarge,
};

pub const Scalar = struct {
    text: []const u8,
    /// Quoted scalars are always strings. Plain `null` or `~` is null.
    quoted: bool = false,
};

pub const Entry = struct {
    key: []const u8,
    value: Node,
};

pub const Node = union(enum) {
    null,
    scalar: Scalar,
    list: []const Node,
    map: []const Entry,

    pub fn get(self: Node, key: []const u8) ?Node {
        if (self != .map) return null;
        for (self.map) |e| {
            if (std.mem.eql(u8, e.key, key)) return e.value;
        }
        return null;
    }

    /// Text of a scalar, or null for anything else.
    pub fn str(self: Node) ?[]const u8 {
        return switch (self) {
            .scalar => |s| s.text,
            else => null,
        };
    }
};

/// Human-readable reason for a parse error.
pub fn describe(err: anyerror) []const u8 {
    return switch (err) {
        error.YamlTab => "yaml: tab used for indentation",
        error.YamlBadIndent => "yaml: indentation does not line up",
        error.YamlUnterminatedQuote => "yaml: unterminated quoted string",
        error.YamlAlias => "yaml: anchors and aliases are not supported",
        error.YamlTag => "yaml: tags are not supported",
        error.YamlMultiDocument => "yaml: more than one document in the file",
        error.YamlBadFlow => "yaml: flow collection could not be parsed",
        error.YamlDuplicateKey => "yaml: duplicate key",
        error.YamlTooDeep => "yaml: nesting too deep",
        error.YamlTooLarge => "yaml: file too large",
        error.OutOfMemory => "out of memory",
        else => "yaml: could not be parsed",
    };
}

const Line = struct {
    indent: usize,
    /// Text after the indent, comments not yet removed.
    text: []const u8,
    /// Whole raw line (for block scalars).
    raw: []const u8,
    blank: bool,
};

const max_depth = 64;
const max_bytes = 1 << 20;

const Parser = struct {
    arena: std.mem.Allocator,
    lines: []Line,
    i: usize = 0,
    depth: usize = 0,

    fn skipBlank(p: *Parser) void {
        while (p.i < p.lines.len and p.lines[p.i].blank) p.i += 1;
    }

    fn parseBlock(p: *Parser, min_indent: usize) Error!Node {
        p.depth += 1;
        defer p.depth -= 1;
        if (p.depth > max_depth) return error.YamlTooDeep;
        p.skipBlank();
        if (p.i >= p.lines.len) return .null;
        const line = p.lines[p.i];
        if (line.indent < min_indent) return .null;
        const text = stripComment(line.text);
        if (isDash(text)) return p.parseList(line.indent);
        if (keySplit(text) != null) return p.parseMap(line.indent);
        // A plain or quoted scalar on its own lines.
        p.i += 1;
        return p.scalarWithContinuation(text, line.indent);
    }

    fn parseList(p: *Parser, indent: usize) Error!Node {
        var items: std.ArrayList(Node) = .empty;
        while (true) {
            p.skipBlank();
            if (p.i >= p.lines.len) break;
            const line = p.lines[p.i];
            if (line.indent != indent) {
                if (line.indent > indent) return error.YamlBadIndent;
                break;
            }
            const text = stripComment(line.text);
            if (!isDash(text)) break;
            var rest = text[1..];
            var off: usize = 1;
            while (rest.len > 0 and rest[0] == ' ') {
                rest = rest[1..];
                off += 1;
            }
            if (rest.len == 0) {
                p.i += 1;
                p.skipBlank();
                if (p.i < p.lines.len and p.lines[p.i].indent > indent) {
                    try items.append(p.arena, try p.parseBlock(indent + 1));
                } else {
                    try items.append(p.arena, .null);
                }
                continue;
            }
            // Rewrite this line as the item content at a deeper indent and
            // parse it as a block. `- key: v` becomes a map item.
            p.lines[p.i].indent = indent + off;
            p.lines[p.i].text = line.text[off..];
            try items.append(p.arena, try p.parseBlock(indent + off));
        }
        return .{ .list = try items.toOwnedSlice(p.arena) };
    }

    fn parseMap(p: *Parser, indent: usize) Error!Node {
        var entries: std.ArrayList(Entry) = .empty;
        while (true) {
            p.skipBlank();
            if (p.i >= p.lines.len) break;
            const line = p.lines[p.i];
            if (line.indent != indent) {
                if (line.indent > indent) return error.YamlBadIndent;
                break;
            }
            const text = stripComment(line.text);
            if (isDash(text)) break;
            const split = keySplit(text) orelse return error.YamlBadIndent;
            const key = try p.keyText(split.key);
            for (entries.items) |e| {
                if (std.mem.eql(u8, e.key, key)) return error.YamlDuplicateKey;
            }
            const rest = std.mem.trim(u8, split.rest, " ");
            p.i += 1;
            var value: Node = undefined;
            if (rest.len == 0) {
                p.skipBlank();
                if (p.i < p.lines.len and p.lines[p.i].indent > indent) {
                    value = try p.parseBlock(indent + 1);
                } else if (p.i < p.lines.len and p.lines[p.i].indent == indent and isDash(stripComment(p.lines[p.i].text))) {
                    // `key:` followed by a list at the same indent.
                    value = try p.parseList(indent);
                } else {
                    value = .null;
                }
            } else if (rest[0] == '|' or rest[0] == '>') {
                value = try p.blockScalar(rest, indent);
            } else {
                value = try p.scalarWithContinuation(rest, indent);
            }
            try entries.append(p.arena, .{ .key = key, .value = value });
        }
        return .{ .map = try entries.toOwnedSlice(p.arena) };
    }

    fn keyText(p: *Parser, raw: []const u8) Error![]const u8 {
        const k = std.mem.trim(u8, raw, " ");
        if (k.len >= 2 and (k[0] == '\'' or k[0] == '"')) {
            const q = try parseQuoted(p.arena, k);
            return q.text;
        }
        return k;
    }

    /// Inline value, which may continue on more-indented lines (plain
    /// scalars fold with spaces; flow lists may span lines).
    fn scalarWithContinuation(p: *Parser, first: []const u8, indent: usize) Error!Node {
        var text = first;
        if (text.len > 0 and (text[0] == '[' or text[0] == '{')) {
            if (!flowBalanced(text)) {
                var buf: std.ArrayList(u8) = .empty;
                try buf.appendSlice(p.arena, text);
                while (p.i < p.lines.len and !flowBalanced(buf.items)) : (p.i += 1) {
                    if (p.lines[p.i].blank) continue;
                    try buf.append(p.arena, ' ');
                    try buf.appendSlice(p.arena, stripComment(p.lines[p.i].text));
                }
                text = buf.items;
            }
            var fp: FlowParser = .{ .arena = p.arena, .s = text };
            const node = try fp.value();
            fp.ws();
            if (fp.pos != fp.s.len) return error.YamlBadFlow;
            return node;
        }
        if (text.len > 0 and (text[0] == '\'' or text[0] == '"')) {
            const q = try parseQuoted(p.arena, text);
            const tail = std.mem.trim(u8, text[q.consumed..], " ");
            if (tail.len != 0) return error.YamlBadFlow;
            return .{ .scalar = .{ .text = q.text, .quoted = true } };
        }
        // Plain scalar. Fold continuation lines that are more indented and
        // are not keys or list items of their own.
        var buf: std.ArrayList(u8) = .empty;
        try buf.appendSlice(p.arena, std.mem.trimEnd(u8, text, " "));
        while (p.i < p.lines.len) {
            const l = p.lines[p.i];
            if (l.blank) {
                // A blank line inside a folded plain scalar is a newline.
                var j = p.i;
                while (j < p.lines.len and p.lines[j].blank) j += 1;
                if (j < p.lines.len and p.lines[j].indent > indent and keySplit(stripComment(p.lines[j].text)) == null) {
                    try buf.append(p.arena, '\n');
                    p.i = j;
                    continue;
                }
                break;
            }
            if (l.indent <= indent) break;
            const t = stripComment(l.text);
            if (keySplit(t) != null or isDash(t)) break;
            try buf.append(p.arena, ' ');
            try buf.appendSlice(p.arena, std.mem.trim(u8, t, " "));
            p.i += 1;
        }
        return plainScalar(buf.items);
    }

    fn blockScalar(p: *Parser, header: []const u8, indent: usize) Error!Node {
        const folded = header[0] == '>';
        var chomp: enum { clip, strip, keep } = .clip;
        for (header[1..]) |c| {
            switch (c) {
                '-' => chomp = .strip,
                '+' => chomp = .keep,
                '0'...'9', ' ' => {},
                '#' => break,
                else => return error.YamlBadFlow,
            }
        }
        // Content indent is the indent of the first non-blank line.
        var j = p.i;
        while (j < p.lines.len and p.lines[j].blank) j += 1;
        if (j >= p.lines.len or p.lines[j].indent <= indent) {
            return .{ .scalar = .{ .text = "", .quoted = true } };
        }
        const content_indent = p.lines[j].indent;
        var buf: std.ArrayList(u8) = .empty;
        var first = true;
        while (p.i < p.lines.len) {
            const l = p.lines[p.i];
            if (!l.blank and l.indent < content_indent) break;
            const body = if (l.blank) "" else l.raw[content_indent..];
            if (folded and !first and body.len > 0 and buf.items.len > 0 and buf.items[buf.items.len - 1] != '\n') {
                try buf.append(p.arena, ' ');
            } else if (!first) {
                try buf.append(p.arena, '\n');
            }
            try buf.appendSlice(p.arena, std.mem.trimEnd(u8, body, "\r"));
            first = false;
            p.i += 1;
        }
        var out: []const u8 = buf.items;
        switch (chomp) {
            .strip => out = std.mem.trimEnd(u8, out, "\n"),
            .clip => {
                out = std.mem.trimEnd(u8, out, "\n");
                const owned = try p.arena.alloc(u8, out.len + 1);
                @memcpy(owned[0..out.len], out);
                owned[out.len] = '\n';
                out = owned;
            },
            .keep => {
                const owned = try p.arena.alloc(u8, out.len + 1);
                @memcpy(owned[0..out.len], out);
                owned[out.len] = '\n';
                out = owned;
            },
        }
        return .{ .scalar = .{ .text = out, .quoted = true } };
    }
};

fn plainScalar(text: []const u8) Error!Node {
    if (text.len == 0) return .null;
    if (text[0] == '&' or text[0] == '*') return error.YamlAlias;
    if (text[0] == '!') return error.YamlTag;
    if (std.mem.eql(u8, text, "~") or std.mem.eql(u8, text, "null") or std.mem.eql(u8, text, "Null") or std.mem.eql(u8, text, "NULL")) return .null;
    return .{ .scalar = .{ .text = text } };
}

fn isDash(text: []const u8) bool {
    return text.len > 0 and text[0] == '-' and (text.len == 1 or text[1] == ' ');
}

const KeySplit = struct { key: []const u8, rest: []const u8 };

/// `key: rest` or `key:`. Quoted keys are allowed. Returns null when the
/// text is a scalar.
fn keySplit(text: []const u8) ?KeySplit {
    if (text.len == 0) return null;
    if (text[0] == '[' or text[0] == '{') return null;
    var i: usize = 0;
    if (text[0] == '\'' or text[0] == '"') {
        const q = text[0];
        i = 1;
        while (i < text.len) : (i += 1) {
            if (text[i] == '\\' and q == '"') {
                i += 1;
                continue;
            }
            if (text[i] == q) {
                if (q == '\'' and i + 1 < text.len and text[i + 1] == '\'') {
                    i += 1;
                    continue;
                }
                break;
            }
        }
        if (i >= text.len) return null;
        i += 1;
        if (i < text.len and text[i] == ':' and (i + 1 == text.len or text[i + 1] == ' ')) {
            return .{ .key = text[0..i], .rest = text[i + 1 ..] };
        }
        return null;
    }
    while (i < text.len) : (i += 1) {
        if (text[i] == ':' and (i + 1 == text.len or text[i + 1] == ' ')) {
            return .{ .key = text[0..i], .rest = text[i + 1 ..] };
        }
    }
    return null;
}

/// Remove a trailing comment that is outside quotes. A `#` starts a comment
/// at the start of the text or after a space.
fn stripComment(text: []const u8) []const u8 {
    var in_single = false;
    var in_double = false;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        if (in_double) {
            if (c == '\\') {
                i += 1;
            } else if (c == '"') in_double = false;
            continue;
        }
        if (in_single) {
            if (c == '\'') in_single = false;
            continue;
        }
        switch (c) {
            '"' => if (i == 0 or isQuoteStart(text, i)) {
                in_double = true;
            },
            '\'' => if (i == 0 or isQuoteStart(text, i)) {
                in_single = true;
            },
            '#' => if (i == 0 or text[i - 1] == ' ') return std.mem.trimEnd(u8, text[0..i], " "),
            else => {},
        }
    }
    return std.mem.trimEnd(u8, text, " \r");
}

/// A quote only opens a quoted scalar at the start of a value: after
/// `: `, `- `, `[`, `{` or `, `. Apostrophes inside plain text are literal.
fn isQuoteStart(text: []const u8, i: usize) bool {
    var j = i;
    while (j > 0 and text[j - 1] == ' ') j -= 1;
    if (j == 0) return true;
    const prev = text[j - 1];
    if (prev == '[' or prev == '{' or prev == ',') return true;
    if ((prev == ':' or prev == '-') and j < i) return true;
    return false;
}

const Quoted = struct { text: []const u8, consumed: usize };

fn parseQuoted(arena: std.mem.Allocator, s: []const u8) Error!Quoted {
    const q = s[0];
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 1;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (q == '\'') {
            if (c == '\'') {
                if (i + 1 < s.len and s[i + 1] == '\'') {
                    try out.append(arena, '\'');
                    i += 1;
                    continue;
                }
                return .{ .text = try out.toOwnedSlice(arena), .consumed = i + 1 };
            }
            try out.append(arena, c);
            continue;
        }
        if (c == '"') return .{ .text = try out.toOwnedSlice(arena), .consumed = i + 1 };
        if (c == '\\') {
            i += 1;
            if (i >= s.len) return error.YamlUnterminatedQuote;
            switch (s[i]) {
                'n' => try out.append(arena, '\n'),
                't' => try out.append(arena, '\t'),
                'r' => try out.append(arena, '\r'),
                '0' => try out.append(arena, 0),
                '\\', '"', '/', ' ' => try out.append(arena, s[i]),
                'x' => {
                    if (i + 2 >= s.len) return error.YamlUnterminatedQuote;
                    const b = std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16) catch return error.YamlBadFlow;
                    try out.append(arena, b);
                    i += 2;
                },
                'u' => {
                    if (i + 4 >= s.len) return error.YamlUnterminatedQuote;
                    const cp = std.fmt.parseInt(u21, s[i + 1 .. i + 5], 16) catch return error.YamlBadFlow;
                    var enc: [4]u8 = undefined;
                    const n = std.unicode.utf8Encode(cp, &enc) catch return error.YamlBadFlow;
                    try out.appendSlice(arena, enc[0..n]);
                    i += 4;
                },
                else => return error.YamlBadFlow,
            }
            continue;
        }
        try out.append(arena, c);
    }
    return error.YamlUnterminatedQuote;
}

fn flowBalanced(s: []const u8) bool {
    var depth: i32 = 0;
    var in_s = false;
    var in_d = false;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (in_d) {
            if (c == '\\') i += 1 else if (c == '"') in_d = false;
            continue;
        }
        if (in_s) {
            if (c == '\'') in_s = false;
            continue;
        }
        switch (c) {
            '"' => in_d = true,
            '\'' => in_s = true,
            '[', '{' => depth += 1,
            ']', '}' => depth -= 1,
            else => {},
        }
    }
    return depth <= 0;
}

const FlowParser = struct {
    arena: std.mem.Allocator,
    s: []const u8,
    pos: usize = 0,

    fn ws(fp: *FlowParser) void {
        while (fp.pos < fp.s.len and (fp.s[fp.pos] == ' ' or fp.s[fp.pos] == '\t')) fp.pos += 1;
    }

    fn value(fp: *FlowParser) Error!Node {
        fp.ws();
        if (fp.pos >= fp.s.len) return error.YamlBadFlow;
        switch (fp.s[fp.pos]) {
            '[' => {
                fp.pos += 1;
                var items: std.ArrayList(Node) = .empty;
                fp.ws();
                if (fp.pos < fp.s.len and fp.s[fp.pos] == ']') {
                    fp.pos += 1;
                    return .{ .list = &.{} };
                }
                while (true) {
                    try items.append(fp.arena, try fp.value());
                    fp.ws();
                    if (fp.pos >= fp.s.len) return error.YamlBadFlow;
                    if (fp.s[fp.pos] == ',') {
                        fp.pos += 1;
                        fp.ws();
                        if (fp.pos < fp.s.len and fp.s[fp.pos] == ']') {
                            fp.pos += 1;
                            break;
                        }
                        continue;
                    }
                    if (fp.s[fp.pos] == ']') {
                        fp.pos += 1;
                        break;
                    }
                    return error.YamlBadFlow;
                }
                return .{ .list = try items.toOwnedSlice(fp.arena) };
            },
            '{' => {
                fp.pos += 1;
                var entries: std.ArrayList(Entry) = .empty;
                fp.ws();
                if (fp.pos < fp.s.len and fp.s[fp.pos] == '}') {
                    fp.pos += 1;
                    return .{ .map = &.{} };
                }
                while (true) {
                    fp.ws();
                    const k = try fp.value();
                    const key = k.str() orelse return error.YamlBadFlow;
                    fp.ws();
                    if (fp.pos >= fp.s.len or fp.s[fp.pos] != ':') return error.YamlBadFlow;
                    fp.pos += 1;
                    const v = try fp.value();
                    try entries.append(fp.arena, .{ .key = key, .value = v });
                    fp.ws();
                    if (fp.pos >= fp.s.len) return error.YamlBadFlow;
                    if (fp.s[fp.pos] == ',') {
                        fp.pos += 1;
                        continue;
                    }
                    if (fp.s[fp.pos] == '}') {
                        fp.pos += 1;
                        break;
                    }
                    return error.YamlBadFlow;
                }
                return .{ .map = try entries.toOwnedSlice(fp.arena) };
            },
            '\'', '"' => {
                const q = try parseQuoted(fp.arena, fp.s[fp.pos..]);
                fp.pos += q.consumed;
                return .{ .scalar = .{ .text = q.text, .quoted = true } };
            },
            else => {
                const start = fp.pos;
                while (fp.pos < fp.s.len) : (fp.pos += 1) {
                    const c = fp.s[fp.pos];
                    if (c == ',' or c == ']' or c == '}') break;
                    if (c == ':' and (fp.pos + 1 == fp.s.len or fp.s[fp.pos + 1] == ' ')) break;
                }
                return plainScalar(std.mem.trim(u8, fp.s[start..fp.pos], " \t"));
            },
        }
    }
};

/// Parse `text` into a tree allocated in `arena`.
pub fn parse(arena: std.mem.Allocator, text: []const u8) Error!Node {
    if (text.len > max_bytes) return error.YamlTooLarge;
    var lines: std.ArrayList(Line) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    var seen_content = false;
    while (it.next()) |raw_line| {
        const raw = std.mem.trimEnd(u8, raw_line, "\r");
        var indent: usize = 0;
        while (indent < raw.len and raw[indent] == ' ') indent += 1;
        const rest = raw[indent..];
        if (rest.len > 0 and rest[0] == '\t') return error.YamlTab;
        const no_comment = stripComment(rest);
        const blank = no_comment.len == 0;
        if (indent == 0 and (std.mem.eql(u8, std.mem.trimEnd(u8, rest, " "), "---") or std.mem.startsWith(u8, rest, "--- "))) {
            if (seen_content) return error.YamlMultiDocument;
            continue;
        }
        if (indent == 0 and std.mem.eql(u8, std.mem.trimEnd(u8, rest, " "), "...")) break;
        if (!blank) seen_content = true;
        try lines.append(arena, .{ .indent = indent, .text = rest, .raw = raw, .blank = blank });
    }
    var p: Parser = .{ .arena = arena, .lines = lines.items };
    const node = try p.parseBlock(0);
    p.skipBlank();
    if (p.i != p.lines.len) return error.YamlBadIndent;
    return node;
}

test "maps, lists, lists of maps and quoted values" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const doc =
        \\title: Test rule # trailing comment
        \\tags:
        \\  - attack.execution
        \\  - attack.t1059.001
        \\detection:
        \\  selection:
        \\    - Image|endswith: '\cmd.exe'
        \\      CommandLine|contains:
        \\        - ' /c '
        \\        - "x\"y"
        \\    - OriginalFileName: 'it''s'
        \\  empty: null
        \\  inline: [a, 'b c', 3]
        \\  condition: selection
        \\description: |
        \\  line one
        \\  line two
        \\folded: >-
        \\  a
        \\  b
        \\list_same_indent:
        \\- one
        \\- two
    ;
    const root = try parse(arena, doc);
    try std.testing.expectEqualStrings("Test rule", root.get("title").?.str().?);
    const tags = root.get("tags").?.list;
    try std.testing.expectEqual(@as(usize, 2), tags.len);
    try std.testing.expectEqualStrings("attack.t1059.001", tags[1].str().?);
    const sel = root.get("detection").?.get("selection").?.list;
    try std.testing.expectEqual(@as(usize, 2), sel.len);
    try std.testing.expectEqualStrings("\\cmd.exe", sel[0].get("Image|endswith").?.str().?);
    const cl = sel[0].get("CommandLine|contains").?.list;
    try std.testing.expectEqualStrings(" /c ", cl[0].str().?);
    try std.testing.expectEqualStrings("x\"y", cl[1].str().?);
    try std.testing.expectEqualStrings("it's", sel[1].get("OriginalFileName").?.str().?);
    try std.testing.expect(root.get("detection").?.get("empty").? == .null);
    const inl = root.get("detection").?.get("inline").?.list;
    try std.testing.expectEqual(@as(usize, 3), inl.len);
    try std.testing.expectEqualStrings("b c", inl[1].str().?);
    try std.testing.expectEqualStrings("line one\nline two\n", root.get("description").?.str().?);
    try std.testing.expectEqualStrings("a b", root.get("folded").?.str().?);
    try std.testing.expectEqual(@as(usize, 2), root.get("list_same_indent").?.list.len);
}

test "plain scalars fold, hashes inside quotes and urls stay" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const root = try parse(arena,
        \\description: Detects a thing
        \\    across two lines
        \\references:
        \\    - https://example.com/a#frag
        \\value: '#not a comment'
        \\note: it's fine
    );
    try std.testing.expectEqualStrings("Detects a thing across two lines", root.get("description").?.str().?);
    try std.testing.expectEqualStrings("https://example.com/a#frag", root.get("references").?.list[0].str().?);
    try std.testing.expectEqualStrings("#not a comment", root.get("value").?.str().?);
    try std.testing.expectEqualStrings("it's fine", root.get("note").?.str().?);
}

test "unsupported yaml is refused" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try std.testing.expectError(error.YamlAlias, parse(arena, "a: &x 1\nb: *x\n"));
    try std.testing.expectError(error.YamlMultiDocument, parse(arena, "a: 1\n---\nb: 2\n"));
    try std.testing.expectError(error.YamlUnterminatedQuote, parse(arena, "a: 'oops\n"));
    try std.testing.expectError(error.YamlDuplicateKey, parse(arena, "a: 1\na: 2\n"));
    try std.testing.expectError(error.YamlTab, parse(arena, "a:\n\t- x\n"));
}
