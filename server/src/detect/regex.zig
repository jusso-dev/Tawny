//! Small regular expression engine for Sigma `re` values.
//!
//! The pattern compiles to a Thompson NFA and runs as a Pike VM, so time is
//! linear in input length times program size and there is no backtracking.
//! A step limit stops a match that runs too long (it counts as no match).
//!
//! Supported: literals, `.`, classes (`[a-z]`, `[^...]`, `\d \w \s` and their
//! negations), groups (`(...)`, `(?:...)`, `(?P<n>...)`, `(?<n>...)`),
//! alternation, `* + ? {n} {n,} {n,m}` (lazy forms are accepted and match the
//! same), anchors `^ $ \A \z \Z`, word boundaries `\b \B`, and a leading `(?i)`.
//! Refused with a reason: backreferences, lookaround, atomic groups,
//! possessive quantifiers, Unicode property classes and other inline flags.
//! Matching is on bytes. Search is unanchored, like Sigma.

const std = @import("std");

pub const max_program = 4096;
pub const default_step_limit: usize = 1_000_000;

pub const CompileError = error{ OutOfMemory, RegexUnsupported, RegexSyntax, RegexTooLarge };

const Range = struct { lo: u8, hi: u8 };

const Class = struct {
    ranges: []const Range,
    negated: bool,

    fn has(self: Class, c: u8, fold: bool) bool {
        var hit = inRanges(self.ranges, c);
        if (!hit and fold) {
            const alt = if (std.ascii.isLower(c)) std.ascii.toUpper(c) else std.ascii.toLower(c);
            if (alt != c) hit = inRanges(self.ranges, alt);
        }
        return hit != self.negated;
    }
};

fn inRanges(ranges: []const Range, c: u8) bool {
    for (ranges) |r| {
        if (c >= r.lo and c <= r.hi) return true;
    }
    return false;
}

const Inst = union(enum) {
    char: u8,
    any_not_nl,
    class: u32,
    split: struct { a: u32, b: u32 },
    jmp: u32,
    bol,
    eol,
    word_boundary,
    not_word_boundary,
    match,
};

pub const Regex = struct {
    prog: []Inst,
    classes: []Class,
    fold: bool,

    pub fn deinit(self: *Regex, allocator: std.mem.Allocator) void {
        for (self.classes) |c| allocator.free(c.ranges);
        allocator.free(self.classes);
        allocator.free(self.prog);
    }

    pub const Result = enum { match, no_match, step_limit };

    /// Unanchored search.
    pub fn search(self: *const Regex, allocator: std.mem.Allocator, input: []const u8, step_limit: usize) !Result {
        const n = self.prog.len;
        const buf = try allocator.alloc(u32, n * 2);
        defer allocator.free(buf);
        const marks = try allocator.alloc(usize, n);
        defer allocator.free(marks);
        @memset(marks, std.math.maxInt(usize));
        var cur: List = .{ .items = buf[0..n] };
        var next: List = .{ .items = buf[n..] };
        var steps: usize = 0;
        var gen: usize = 0;
        var pos: usize = 0;
        while (true) : (pos += 1) {
            // Unanchored: a new thread starts at every position.
            if (try self.addThread(&cur, marks, gen, 0, input, pos, &steps, step_limit)) return .match;
            if (steps > step_limit) return .step_limit;
            if (pos >= input.len) break;
            const c = input[pos];
            gen += 1;
            next.len = 0;
            for (cur.items[0..cur.len]) |pc| {
                steps += 1;
                const ok = switch (self.prog[pc]) {
                    .char => |want| if (self.fold) std.ascii.toLower(c) == want else c == want,
                    .any_not_nl => c != '\n',
                    .class => |ci| self.classes[ci].has(c, self.fold),
                    else => false,
                };
                if (ok) {
                    if (try self.addThread(&next, marks, gen, pc + 1, input, pos + 1, &steps, step_limit)) return .match;
                }
            }
            if (steps > step_limit) return .step_limit;
            std.mem.swap(List, &cur, &next);
        }
        return .no_match;
    }

    const List = struct { items: []u32, len: usize = 0 };

    /// Follow empty transitions from `pc` and add consuming instructions to
    /// `list`. Returns true when `match` is reachable.
    fn addThread(self: *const Regex, list: *List, marks: []usize, gen: usize, start: u32, input: []const u8, pos: usize, steps: *usize, limit: usize) !bool {
        var stack: [max_program]u32 = undefined;
        var sp: usize = 1;
        stack[0] = start;
        while (sp > 0) {
            sp -= 1;
            const pc = stack[sp];
            if (marks[pc] == gen) continue;
            marks[pc] = gen;
            steps.* += 1;
            if (steps.* > limit) return false;
            switch (self.prog[pc]) {
                .match => return true,
                .jmp => |t| {
                    stack[sp] = t;
                    sp += 1;
                },
                .split => |s| {
                    // Push b first so a is explored first.
                    stack[sp] = s.b;
                    stack[sp + 1] = s.a;
                    sp += 2;
                },
                .bol => if (pos == 0) {
                    stack[sp] = pc + 1;
                    sp += 1;
                },
                .eol => if (pos == input.len) {
                    stack[sp] = pc + 1;
                    sp += 1;
                },
                .word_boundary, .not_word_boundary => {
                    const before = pos > 0 and isWord(input[pos - 1]);
                    const after = pos < input.len and isWord(input[pos]);
                    const at = before != after;
                    if (at == (self.prog[pc] == .word_boundary)) {
                        stack[sp] = pc + 1;
                        sp += 1;
                    }
                },
                else => {
                    list.items[list.len] = pc;
                    list.len += 1;
                },
            }
        }
        return false;
    }
};

fn isWord(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

// --- parser -----------------------------------------------------------------

const Node = union(enum) {
    empty,
    char: u8,
    any,
    class: u32,
    bol,
    eol,
    wb,
    nwb,
    concat: []const *const Node,
    alt: []const *const Node,
    repeat: struct { sub: *const Node, min: u32, max: ?u32 },
};

const ParseCtx = struct {
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    s: []const u8,
    pos: usize = 0,
    classes: std.ArrayList(Class) = .empty,
    fold: bool = false,
    reason: []const u8 = "",
    depth: usize = 0,

    fn fail(self: *ParseCtx, reason: []const u8) CompileError {
        self.reason = reason;
        return error.RegexUnsupported;
    }

    fn syntax(self: *ParseCtx, reason: []const u8) CompileError {
        self.reason = reason;
        return error.RegexSyntax;
    }

    fn node(self: *ParseCtx, n: Node) !*const Node {
        const p = try self.arena.create(Node);
        p.* = n;
        return p;
    }

    fn peek(self: *ParseCtx) ?u8 {
        return if (self.pos < self.s.len) self.s[self.pos] else null;
    }

    fn parseAlt(self: *ParseCtx) CompileError!*const Node {
        self.depth += 1;
        defer self.depth -= 1;
        if (self.depth > 64) return self.fail("nesting too deep");
        var branches: std.ArrayList(*const Node) = .empty;
        try branches.append(self.arena, try self.parseConcat());
        while (self.peek() == '|') {
            self.pos += 1;
            try branches.append(self.arena, try self.parseConcat());
        }
        if (branches.items.len == 1) return branches.items[0];
        return self.node(.{ .alt = try branches.toOwnedSlice(self.arena) });
    }

    fn parseConcat(self: *ParseCtx) CompileError!*const Node {
        var items: std.ArrayList(*const Node) = .empty;
        while (self.peek()) |c| {
            if (c == '|' or c == ')') break;
            const atom = try self.parseAtom();
            try items.append(self.arena, try self.parseQuant(atom));
        }
        if (items.items.len == 0) return self.node(.empty);
        if (items.items.len == 1) return items.items[0];
        return self.node(.{ .concat = try items.toOwnedSlice(self.arena) });
    }

    fn parseQuant(self: *ParseCtx, atom: *const Node) CompileError!*const Node {
        var cur = atom;
        while (self.peek()) |c| {
            var min: u32 = 0;
            var max: ?u32 = null;
            switch (c) {
                '*' => self.pos += 1,
                '+' => {
                    min = 1;
                    self.pos += 1;
                },
                '?' => {
                    max = 1;
                    self.pos += 1;
                },
                '{' => {
                    const save = self.pos;
                    self.pos += 1;
                    const lo = self.number() orelse {
                        // Not a quantifier: a literal brace.
                        self.pos = save;
                        return cur;
                    };
                    min = lo;
                    max = lo;
                    if (self.peek() == ',') {
                        self.pos += 1;
                        max = self.number();
                    }
                    if (self.peek() != '}') return self.syntax("bad {n,m} quantifier");
                    self.pos += 1;
                    if (max != null and max.? < min) return self.syntax("bad {n,m} quantifier");
                    if (min > 1000 or (max orelse 0) > 1000) return self.fail("repeat count above 1000");
                },
                else => return cur,
            }
            switch (cur.*) {
                .bol, .eol, .wb, .nwb, .empty => return self.syntax("quantifier after an anchor"),
                else => {},
            }
            if (self.peek()) |n| {
                if (n == '?') {
                    self.pos += 1; // lazy, same result for a yes/no match
                } else if (n == '+') {
                    return self.fail("possessive quantifiers are not supported");
                }
            }
            cur = try self.node(.{ .repeat = .{ .sub = cur, .min = min, .max = max } });
        }
        return cur;
    }

    fn number(self: *ParseCtx) ?u32 {
        const start = self.pos;
        while (self.peek()) |c| {
            if (!std.ascii.isDigit(c)) break;
            self.pos += 1;
        }
        if (self.pos == start) return null;
        return std.fmt.parseInt(u32, self.s[start..self.pos], 10) catch null;
    }

    fn parseAtom(self: *ParseCtx) CompileError!*const Node {
        const c = self.s[self.pos];
        self.pos += 1;
        switch (c) {
            '.' => return self.node(.any),
            '^' => return self.node(.bol),
            '$' => return self.node(.eol),
            '(' => return self.parseGroup(),
            '[' => return self.parseClass(),
            '\\' => return self.parseEscape(false, null),
            '*', '+', '?' => return self.syntax("quantifier with nothing before it"),
            else => return self.literal(c),
        }
    }

    fn literal(self: *ParseCtx, c: u8) !*const Node {
        return self.node(.{ .char = if (self.fold) std.ascii.toLower(c) else c });
    }

    fn parseGroup(self: *ParseCtx) CompileError!*const Node {
        if (self.peek() == '?') {
            self.pos += 1;
            const k = self.peek() orelse return self.syntax("unterminated group");
            switch (k) {
                ':' => self.pos += 1,
                '=', '!' => return self.fail("lookahead is not supported"),
                '>' => return self.fail("atomic groups are not supported"),
                '#' => return self.fail("comment groups are not supported"),
                'P', '<' => {
                    if (k == 'P') self.pos += 1;
                    if (self.peek() == '=' and k == 'P') return self.fail("named backreferences are not supported");
                    if (self.peek() != '<') return self.syntax("bad named group");
                    self.pos += 1;
                    if (self.peek() == '=' or self.peek() == '!') return self.fail("lookbehind is not supported");
                    while (self.peek()) |n| {
                        self.pos += 1;
                        if (n == '>') break;
                        if (!isWord(n)) return self.syntax("bad group name");
                    } else return self.syntax("unterminated group name");
                },
                else => {
                    if (k == 'i' and self.pos + 1 < self.s.len and self.s[self.pos + 1] == ')' and self.pos == 2) {
                        // Leading (?i): handled before parsing.
                        return self.syntax("misplaced (?i)");
                    }
                    return self.fail("inline flags other than a leading (?i) are not supported");
                },
            }
        }
        const inner = try self.parseAlt();
        if (self.peek() != ')') return self.syntax("unterminated group");
        self.pos += 1;
        return inner;
    }

    fn parseEscape(self: *ParseCtx, in_class: bool, ranges: ?*std.ArrayList(Range)) CompileError!*const Node {
        const e = self.peek() orelse return self.syntax("trailing backslash");
        self.pos += 1;
        const shorthand: ?struct { r: []const Range, neg: bool } = switch (e) {
            'd' => .{ .r = &digit_ranges, .neg = false },
            'D' => .{ .r = &digit_ranges, .neg = true },
            'w' => .{ .r = &word_ranges, .neg = false },
            'W' => .{ .r = &word_ranges, .neg = true },
            's' => .{ .r = &space_ranges, .neg = false },
            'S' => .{ .r = &space_ranges, .neg = true },
            else => null,
        };
        if (shorthand) |sh| {
            if (in_class) {
                if (sh.neg) return self.fail("negated shorthand inside a class is not supported");
                try ranges.?.appendSlice(self.arena, sh.r);
                return self.node(.empty);
            }
            return self.addClass(sh.r, sh.neg);
        }
        if (!in_class) switch (e) {
            'b' => return self.node(.wb),
            'B' => return self.node(.nwb),
            'A' => return self.node(.bol),
            'z', 'Z' => return self.node(.eol),
            else => {},
        };
        const lit: u8 = switch (e) {
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            'f' => 0x0c,
            'v' => 0x0b,
            '0' => 0,
            'x' => blk: {
                if (self.pos + 2 > self.s.len) return self.syntax("bad \\x escape");
                const b = std.fmt.parseInt(u8, self.s[self.pos .. self.pos + 2], 16) catch return self.syntax("bad \\x escape");
                self.pos += 2;
                break :blk b;
            },
            '1'...'9' => return self.fail("backreferences are not supported"),
            'p', 'P' => return self.fail("Unicode property classes are not supported"),
            'k' => return self.fail("named backreferences are not supported"),
            'G', 'K', 'R', 'X', 'C', 'Q', 'E' => return self.fail("this escape is not supported"),
            else => blk: {
                if (std.ascii.isAlphanumeric(e)) return self.fail("unknown escape");
                break :blk e;
            },
        };
        if (in_class) {
            try ranges.?.append(self.arena, .{ .lo = lit, .hi = lit });
            return self.node(.{ .char = lit });
        }
        return self.literal(lit);
    }

    fn addClass(self: *ParseCtx, ranges: []const Range, negated: bool) !*const Node {
        const owned = try self.gpa.dupe(Range, ranges);
        errdefer self.gpa.free(owned);
        try self.classes.append(self.gpa, .{ .ranges = owned, .negated = negated });
        return self.node(.{ .class = @intCast(self.classes.items.len - 1) });
    }

    fn parseClass(self: *ParseCtx) CompileError!*const Node {
        var ranges: std.ArrayList(Range) = .empty;
        var negated = false;
        if (self.peek() == '^') {
            negated = true;
            self.pos += 1;
        }
        var first = true;
        while (true) {
            const c = self.peek() orelse return self.syntax("unterminated class");
            if (c == ']' and !first) {
                self.pos += 1;
                break;
            }
            first = false;
            if (c == '[' and self.pos + 1 < self.s.len and (self.s[self.pos + 1] == ':' or self.s[self.pos + 1] == '=' or self.s[self.pos + 1] == '.')) {
                return self.fail("POSIX classes are not supported");
            }
            var lo: u8 = c;
            self.pos += 1;
            if (c == '\\') {
                const before = ranges.items.len;
                const n = try self.parseEscape(true, &ranges);
                if (n.* != .char) continue; // shorthand appended
                lo = n.char;
                ranges.items.len = before;
            }
            if (self.peek() == '-' and self.pos + 1 < self.s.len and self.s[self.pos + 1] != ']') {
                self.pos += 1;
                var hi = self.s[self.pos];
                self.pos += 1;
                if (hi == '\\') {
                    const before = ranges.items.len;
                    const n = try self.parseEscape(true, &ranges);
                    if (n.* != .char) return self.syntax("bad class range");
                    hi = n.char;
                    ranges.items.len = before;
                }
                if (hi < lo) return self.syntax("bad class range");
                try ranges.append(self.arena, .{ .lo = lo, .hi = hi });
            } else {
                try ranges.append(self.arena, .{ .lo = lo, .hi = lo });
            }
        }
        return self.addClass(ranges.items, negated);
    }
};

const digit_ranges = [_]Range{.{ .lo = '0', .hi = '9' }};
const word_ranges = [_]Range{ .{ .lo = '0', .hi = '9' }, .{ .lo = 'A', .hi = 'Z' }, .{ .lo = 'a', .hi = 'z' }, .{ .lo = '_', .hi = '_' } };
const space_ranges = [_]Range{ .{ .lo = ' ', .hi = ' ' }, .{ .lo = '\t', .hi = '\r' } };

// --- compiler ---------------------------------------------------------------

const Emitter = struct {
    gpa: std.mem.Allocator,
    prog: std.ArrayList(Inst) = .empty,

    fn emit(self: *Emitter, inst: Inst) !u32 {
        if (self.prog.items.len >= max_program) return error.RegexTooLarge;
        try self.prog.append(self.gpa, inst);
        return @intCast(self.prog.items.len - 1);
    }

    fn pc(self: *Emitter) u32 {
        return @intCast(self.prog.items.len);
    }

    fn gen(self: *Emitter, n: *const Node) CompileError!void {
        switch (n.*) {
            .empty => {},
            .char => |c| _ = try self.emit(.{ .char = c }),
            .any => _ = try self.emit(.any_not_nl),
            .class => |ci| _ = try self.emit(.{ .class = ci }),
            .bol => _ = try self.emit(.bol),
            .eol => _ = try self.emit(.eol),
            .wb => _ = try self.emit(.word_boundary),
            .nwb => _ = try self.emit(.not_word_boundary),
            .concat => |items| for (items) |it| try self.gen(it),
            .alt => |branches| {
                var jumps: std.ArrayList(u32) = .empty;
                defer jumps.deinit(self.gpa);
                for (branches, 0..) |b, i| {
                    if (i + 1 < branches.len) {
                        const split = try self.emit(.{ .split = .{ .a = 0, .b = 0 } });
                        self.prog.items[split].split.a = self.pc();
                        try self.gen(b);
                        try jumps.append(self.gpa, try self.emit(.{ .jmp = 0 }));
                        self.prog.items[split].split.b = self.pc();
                    } else {
                        try self.gen(b);
                    }
                }
                for (jumps.items) |j| self.prog.items[j].jmp = self.pc();
            },
            .repeat => |r| {
                var i: u32 = 0;
                while (i < r.min) : (i += 1) try self.gen(r.sub);
                if (r.max) |max| {
                    // Optional copies: split over each.
                    var splits: std.ArrayList(u32) = .empty;
                    defer splits.deinit(self.gpa);
                    while (i < max) : (i += 1) {
                        const split = try self.emit(.{ .split = .{ .a = 0, .b = 0 } });
                        self.prog.items[split].split.a = self.pc();
                        try splits.append(self.gpa, split);
                        try self.gen(r.sub);
                    }
                    for (splits.items) |s| self.prog.items[s].split.b = self.pc();
                } else {
                    // Star loop.
                    const split = try self.emit(.{ .split = .{ .a = 0, .b = 0 } });
                    self.prog.items[split].split.a = self.pc();
                    try self.gen(r.sub);
                    _ = try self.emit(.{ .jmp = split });
                    self.prog.items[split].split.b = self.pc();
                }
            },
        }
    }
};

pub const Compiled = union(enum) {
    ok: Regex,
    /// Why the pattern was refused. Static text.
    refused: []const u8,
};

/// Compile `pattern`. `fold` makes it case-insensitive (Sigma `|re|i`).
pub fn compile(gpa: std.mem.Allocator, pattern: []const u8, fold_in: bool) error{OutOfMemory}!Compiled {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var s = pattern;
    var fold = fold_in;
    if (std.mem.startsWith(u8, s, "(?i)")) {
        fold = true;
        s = s[4..];
    }
    var ctx: ParseCtx = .{ .arena = arena_state.allocator(), .gpa = gpa, .s = s, .fold = fold };
    var ok = false;
    defer if (!ok) {
        for (ctx.classes.items) |c| gpa.free(c.ranges);
        ctx.classes.deinit(gpa);
    };
    const root = ctx.parseAlt() catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.RegexTooLarge => return .{ .refused = "pattern is too large" },
        else => return .{ .refused = ctx.reason },
    };
    if (ctx.pos != s.len) return .{ .refused = "unbalanced parenthesis" };
    var em: Emitter = .{ .gpa = gpa };
    errdefer em.prog.deinit(gpa);
    em.gen(root) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            em.prog.deinit(gpa);
            return .{ .refused = "pattern is too large after expanding repeats" };
        },
    };
    _ = em.emit(.match) catch {
        em.prog.deinit(gpa);
        return .{ .refused = "pattern is too large after expanding repeats" };
    };
    const prog = try em.prog.toOwnedSlice(gpa);
    errdefer gpa.free(prog);
    const classes = try ctx.classes.toOwnedSlice(gpa);
    ok = true;
    return .{ .ok = .{ .prog = prog, .classes = classes, .fold = fold } };
}

fn expectMatch(pattern: []const u8, input: []const u8, want: bool) !void {
    const a = std.testing.allocator;
    var c = try compile(a, pattern, false);
    switch (c) {
        .refused => |why| {
            std.debug.print("refused {s}: {s}\n", .{ pattern, why });
            return error.TestUnexpectedResult;
        },
        .ok => |*re| {
            defer re.deinit(a);
            const got = try re.search(a, input, default_step_limit);
            if ((got == .match) != want) {
                std.debug.print("pattern {s} input {s} got {s}\n", .{ pattern, input, @tagName(got) });
                return error.TestUnexpectedResult;
            }
        },
    }
}

fn expectRefused(pattern: []const u8) !void {
    const a = std.testing.allocator;
    var c = try compile(a, pattern, false);
    switch (c) {
        .refused => {},
        .ok => |*re| {
            re.deinit(a);
            return error.TestUnexpectedResult;
        },
    }
}

test "regex basics" {
    try expectMatch("abc", "xxabcxx", true);
    try expectMatch("^abc", "xxabc", false);
    try expectMatch("abc$", "xxabc", true);
    try expectMatch("a.c", "a-c", true);
    try expectMatch("a[0-9]+c", "a123c", true);
    try expectMatch("a[^0-9]c", "a1c", false);
    try expectMatch("(foo|bar)baz", "xbarbaz", true);
    try expectMatch("colou?r", "color", true);
    try expectMatch("x{2,3}y", "xxy", true);
    try expectMatch("^x{2,3}y", "xy", false);
    try expectMatch("\\bnet\\b", "c:\\net use", true);
    try expectMatch("\\bnet\\b", "netsh", false);
    try expectMatch("\\\\cmd\\.exe$", "C:\\Windows\\cmd.exe", true);
    try expectMatch("(?i)CMD", "cmd", true);
    try expectMatch("CMD", "cmd", false);
    try expectMatch("\\s-[eE][nN][cC]\\s", "powershell -EnC abc", true);
    try expectMatch("(?:a|b)*c", "ababc", true);
    try expectMatch("[\\w.-]+@[\\w-]+", "mail me: x.y@host", true);
    try expectMatch("a.*?b", "a___b", true);
    try expectMatch("{x}", "{x}", true);
    try expectMatch("", "anything", true);
}

test "regex refuses what it can't do" {
    try expectRefused("(a)\\1");
    try expectRefused("foo(?=bar)");
    try expectRefused("(?<!x)y");
    try expectRefused("(?>a)");
    try expectRefused("a++");
    try expectRefused("\\p{L}");
    try expectRefused("a(?s)b");
    try expectRefused("(abc");
    try expectRefused("abc)");
    try expectRefused("a{2000}");
}

test "regex runs in linear time on a classic blow-up pattern" {
    const a = std.testing.allocator;
    const c = try compile(a, "(a*)*b", false);
    var re = c.ok;
    defer re.deinit(a);
    const input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac";
    try std.testing.expectEqual(Regex.Result.no_match, try re.search(a, input, default_step_limit));
    // A tiny limit trips the guard.
    try std.testing.expectEqual(Regex.Result.step_limit, try re.search(a, input, 50));
}
