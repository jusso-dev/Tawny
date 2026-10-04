//! PostgreSQL protocol v3 client. SCRAM-SHA-256 and the extended query
//! protocol. No third-party packages. Values are bound as text parameters.
const std = @import("std");

pub const Error = error{
    BadUrl,
    Protocol,
    AuthFailed,
    AuthUnsupported,
    QueryFailed,
    MessageTooLarge,
    UnexpectedReady,
};

pub const Value = union(enum) {
    null,
    text: []const u8,
};

pub const Row = struct {
    cols: []?[]u8,

    pub fn deinit(self: Row, allocator: std.mem.Allocator) void {
        for (self.cols) |col| if (col) |c| allocator.free(c);
        allocator.free(self.cols);
    }
};

pub const Conn = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: std.Io.net.Stream,
    rbuf: [8192]u8,
    wbuf: [8192]u8,
    reader: std.Io.net.Stream.Reader,
    writer: std.Io.net.Stream.Writer,
    server_error: ?[]u8 = null,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, url: []const u8) !*Conn {
        const parsed = try parseUrl(url);
        const addr = resolveHost(io, parsed.host, parsed.port) catch |err| {
            std.debug.print("postgres resolve {s}: {s}\n", .{ parsed.host, @errorName(err) });
            return err;
        };
        const stream = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
        const conn = try allocator.create(Conn);
        conn.* = .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .rbuf = undefined,
            .wbuf = undefined,
            .reader = undefined,
            .writer = undefined,
        };
        conn.reader = stream.reader(io, &conn.rbuf);
        conn.writer = stream.writer(io, &conn.wbuf);
        conn.startup(parsed) catch |err| {
            conn.close();
            allocator.destroy(conn);
            return err;
        };
        return conn;
    }

    pub fn close(self: *Conn) void {
        if (self.server_error) |msg| self.allocator.free(msg);
        var term = [_]u8{ 'X', 0, 0, 0, 4 };
        self.writer.interface.writeAll(&term) catch {};
        self.writer.interface.flush() catch {};
        self.stream.close(self.io);
    }

    /// Trusted SQL only (migrations). May contain several statements.
    pub fn execSimple(self: *Conn, sql: []const u8) !void {
        self.clearError();
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);
        try buf.append(self.allocator, 'Q');
        const len: i32 = @intCast(4 + sql.len + 1);
        try writeI32(&buf, self.allocator, len);
        try buf.appendSlice(self.allocator, sql);
        try buf.append(self.allocator, 0);
        try self.writer.interface.writeAll(buf.items);
        try self.writer.interface.flush();
        try self.drainUntilReady();
    }

    pub fn exec(self: *Conn, arena: std.mem.Allocator, sql: []const u8, params: []const Value) ![]Row {
        self.clearError();
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);
        try writeParse(&buf, self.allocator, sql);
        try writeBind(&buf, self.allocator, params);
        try writeExecuteSync(&buf, self.allocator);
        try self.writer.interface.writeAll(buf.items);
        try self.writer.interface.flush();
        return try self.readRows(arena);
    }

    pub fn execNoRows(self: *Conn, sql: []const u8, params: []const Value) !void {
        const rows = try self.exec(self.allocator, sql, params);
        defer {
            for (rows) |row| row.deinit(self.allocator);
            self.allocator.free(rows);
        }
    }

    fn startup(self: *Conn, parsed: ParsedUrl) !void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        try writeI32(&body, self.allocator, 196608);
        try writeCString(&body, self.allocator, "user");
        try writeCString(&body, self.allocator, parsed.user);
        try writeCString(&body, self.allocator, "database");
        try writeCString(&body, self.allocator, parsed.database);
        try writeCString(&body, self.allocator, "application_name");
        try writeCString(&body, self.allocator, "tawny-server");
        try body.append(self.allocator, 0);

        var msg: std.ArrayList(u8) = .empty;
        defer msg.deinit(self.allocator);
        try writeI32(&msg, self.allocator, @intCast(4 + body.items.len));
        try msg.appendSlice(self.allocator, body.items);
        try self.writer.interface.writeAll(msg.items);
        try self.writer.interface.flush();

        while (true) {
            const message = try self.readMsg();
            defer self.allocator.free(message.payload);
            switch (message.tag) {
                'R' => {
                    if (message.payload.len < 4) return error.Protocol;
                    const kind = std.mem.readInt(i32, message.payload[0..4], .big);
                    switch (kind) {
                        0 => {},
                        3 => try self.sendCleartext(parsed.password),
                        10 => try self.scram(parsed.password, message.payload[4..]),
                        else => return error.AuthUnsupported,
                    }
                },
                'S', 'K' => {},
                'Z' => return,
                'E' => {
                    try self.noteError(message.payload);
                    return error.AuthFailed;
                },
                else => return error.Protocol,
            }
        }
    }

    fn sendCleartext(self: *Conn, password: []const u8) !void {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);
        try buf.append(self.allocator, 'p');
        try writeI32(&buf, self.allocator, @intCast(4 + password.len + 1));
        try buf.appendSlice(self.allocator, password);
        try buf.append(self.allocator, 0);
        try self.writer.interface.writeAll(buf.items);
        try self.writer.interface.flush();
    }

    fn scram(self: *Conn, password: []const u8, mechanisms: []const u8) !void {
        if (std.mem.indexOf(u8, mechanisms, "SCRAM-SHA-256") == null) return error.AuthUnsupported;
        var nonce_raw: [18]u8 = undefined;
        self.io.random(&nonce_raw);
        var nonce_buf: [32]u8 = undefined;
        const nonce = std.base64.standard.Encoder.encode(&nonce_buf, &nonce_raw);

        const client_first_bare = try std.fmt.allocPrint(self.allocator, "n=,r={s}", .{nonce});
        defer self.allocator.free(client_first_bare);
        const client_first = try std.fmt.allocPrint(self.allocator, "n,,{s}", .{client_first_bare});
        defer self.allocator.free(client_first);

        var initial: std.ArrayList(u8) = .empty;
        defer initial.deinit(self.allocator);
        try initial.append(self.allocator, 'p');
        const mech = "SCRAM-SHA-256";
        const len: i32 = @intCast(4 + mech.len + 1 + 4 + client_first.len);
        try writeI32(&initial, self.allocator, len);
        try initial.appendSlice(self.allocator, mech);
        try initial.append(self.allocator, 0);
        try writeI32(&initial, self.allocator, @intCast(client_first.len));
        try initial.appendSlice(self.allocator, client_first);
        try self.writer.interface.writeAll(initial.items);
        try self.writer.interface.flush();

        const cont = try self.readMsg();
        defer self.allocator.free(cont.payload);
        if (cont.tag != 'R' or cont.payload.len < 4) return error.Protocol;
        if (std.mem.readInt(i32, cont.payload[0..4], .big) != 11) return error.Protocol;
        const server_first = cont.payload[4..];

        const server_nonce = field(server_first, "r") orelse return error.Protocol;
        const salt_b64 = field(server_first, "s") orelse return error.Protocol;
        const iter_text = field(server_first, "i") orelse return error.Protocol;
        if (!std.mem.startsWith(u8, server_nonce, nonce)) return error.Protocol;
        const iterations = std.fmt.parseInt(u32, iter_text, 10) catch return error.Protocol;

        var salt_buf: [128]u8 = undefined;
        const salt_len = std.base64.standard.Decoder.calcSizeForSlice(salt_b64) catch return error.Protocol;
        if (salt_len > salt_buf.len) return error.Protocol;
        std.base64.standard.Decoder.decode(salt_buf[0..salt_len], salt_b64) catch return error.Protocol;
        const salt = salt_buf[0..salt_len];

        var salted: [32]u8 = undefined;
        try std.crypto.pwhash.pbkdf2(&salted, password, salt, iterations, std.crypto.auth.hmac.sha2.HmacSha256);

        var client_key: [32]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&client_key, "Client Key", &salted);
        var stored_key: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&client_key, &stored_key, .{});

        const client_final_wo = try std.fmt.allocPrint(self.allocator, "c=biws,r={s}", .{server_nonce});
        defer self.allocator.free(client_final_wo);
        const auth_message = try std.fmt.allocPrint(self.allocator, "{s},{s},{s}", .{
            client_first_bare,
            server_first,
            client_final_wo,
        });
        defer self.allocator.free(auth_message);

        var client_sig: [32]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&client_sig, auth_message, &stored_key);
        var proof: [32]u8 = undefined;
        for (&proof, client_key, client_sig) |*p, k, s| p.* = k ^ s;
        var proof_b64: [64]u8 = undefined;
        const proof_text = std.base64.standard.Encoder.encode(&proof_b64, &proof);
        const client_final = try std.fmt.allocPrint(self.allocator, "{s},p={s}", .{ client_final_wo, proof_text });
        defer self.allocator.free(client_final);

        var resp: std.ArrayList(u8) = .empty;
        defer resp.deinit(self.allocator);
        try resp.append(self.allocator, 'p');
        try writeI32(&resp, self.allocator, @intCast(4 + client_final.len));
        try resp.appendSlice(self.allocator, client_final);
        try self.writer.interface.writeAll(resp.items);
        try self.writer.interface.flush();

        const final = try self.readMsg();
        defer self.allocator.free(final.payload);
        if (final.tag == 'E') {
            try self.noteError(final.payload);
            return error.AuthFailed;
        }
        if (final.tag != 'R' or final.payload.len < 4) return error.Protocol;
        if (std.mem.readInt(i32, final.payload[0..4], .big) != 12) return error.Protocol;
        const server_final = final.payload[4..];
        const v = field(server_final, "v") orelse return error.Protocol;
        var server_sig_b64: [64]u8 = undefined;
        var server_key: [32]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&server_key, "Server Key", &salted);
        var server_sig: [32]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&server_sig, auth_message, &server_key);
        const expect = std.base64.standard.Encoder.encode(&server_sig_b64, &server_sig);
        if (!std.mem.eql(u8, v, expect)) return error.AuthFailed;
    }

    fn drainUntilReady(self: *Conn) !void {
        while (true) {
            const message = try self.readMsg();
            defer self.allocator.free(message.payload);
            switch (message.tag) {
                'Z' => {
                    if (self.server_error != null) return error.QueryFailed;
                    return;
                },
                'E' => try self.noteError(message.payload),
                else => {},
            }
        }
    }

    fn readRows(self: *Conn, arena: std.mem.Allocator) ![]Row {
        var rows: std.ArrayList(Row) = .empty;
        errdefer {
            for (rows.items) |row| row.deinit(arena);
            rows.deinit(arena);
        }
        var failed = false;
        while (true) {
            const message = try self.readMsg();
            defer self.allocator.free(message.payload);
            switch (message.tag) {
                'D' => {
                    if (message.payload.len < 2) return error.Protocol;
                    const n = std.mem.readInt(u16, message.payload[0..2], .big);
                    const cols = try arena.alloc(?[]u8, n);
                    var off: usize = 2;
                    for (cols) |*col| {
                        if (off + 4 > message.payload.len) return error.Protocol;
                        const clen = std.mem.readInt(i32, message.payload[off..][0..4], .big);
                        off += 4;
                        if (clen < 0) {
                            col.* = null;
                            continue;
                        }
                        const ulen: usize = @intCast(clen);
                        if (off + ulen > message.payload.len) return error.Protocol;
                        col.* = try arena.dupe(u8, message.payload[off .. off + ulen]);
                        off += ulen;
                    }
                    try rows.append(arena, .{ .cols = cols });
                },
                'E' => {
                    try self.noteError(message.payload);
                    failed = true;
                },
                'Z' => {
                    if (failed or self.server_error != null) return error.QueryFailed;
                    return try rows.toOwnedSlice(arena);
                },
                else => {},
            }
        }
    }

    const Msg = struct { tag: u8, payload: []u8 };

    fn readMsg(self: *Conn) !Msg {
        var tag: [1]u8 = undefined;
        try self.reader.interface.readSliceAll(&tag);
        var len_buf: [4]u8 = undefined;
        try self.reader.interface.readSliceAll(&len_buf);
        const len = std.mem.readInt(i32, &len_buf, .big);
        if (len < 4) return error.Protocol;
        const n: usize = @intCast(len - 4);
        if (n > 16 * 1024 * 1024) return error.MessageTooLarge;
        const payload = try self.allocator.alloc(u8, n);
        errdefer self.allocator.free(payload);
        if (n > 0) try self.reader.interface.readSliceAll(payload);
        return .{ .tag = tag[0], .payload = payload };
    }

    fn noteError(self: *Conn, payload: []const u8) !void {
        if (self.server_error) |old| self.allocator.free(old);
        var message: []const u8 = "postgres error";
        var i: usize = 0;
        while (i < payload.len) {
            const field_type = payload[i];
            if (field_type == 0) break;
            i += 1;
            const end = std.mem.indexOfScalarPos(u8, payload, i, 0) orelse payload.len;
            if (field_type == 'M') message = payload[i..end];
            i = @min(end + 1, payload.len);
        }
        self.server_error = try self.allocator.dupe(u8, message);
    }

    pub fn takeError(self: *Conn) ?[]u8 {
        const msg = self.server_error;
        self.server_error = null;
        return msg;
    }

    fn clearError(self: *Conn) void {
        if (self.server_error) |msg| self.allocator.free(msg);
        self.server_error = null;
    }
};

const ParsedUrl = struct {
    user: []const u8,
    password: []const u8,
    host: []const u8,
    port: u16,
    database: []const u8,
};

fn resolveHost(io: std.Io, host: []const u8, port: u16) Error!std.Io.net.IpAddress {
    if (std.Io.net.IpAddress.parse(host, port)) |addr| return addr else |_| {}
    const name = std.Io.net.HostName.init(host) catch return error.BadUrl;
    var storage: [16]std.Io.net.HostName.LookupResult = undefined;
    var queue = std.Io.Queue(std.Io.net.HostName.LookupResult).init(&storage);
    var canon: [std.Io.net.HostName.max_len]u8 = undefined;
    name.lookup(io, &queue, .{ .port = port, .canonical_name_buffer = &canon }) catch return error.BadUrl;
    var slot: [1]std.Io.net.HostName.LookupResult = undefined;
    while (true) {
        const n = queue.get(io, &slot, 0) catch break;
        if (n == 0) break;
        switch (slot[0]) {
            .address => |addr| return addr,
            .canonical_name => {},
        }
    }
    return error.BadUrl;
}

fn parseUrl(url: []const u8) Error!ParsedUrl {
    const rest = if (std.mem.startsWith(u8, url, "postgresql://"))
        url["postgresql://".len..]
    else if (std.mem.startsWith(u8, url, "postgres://"))
        url["postgres://".len..]
    else
        return error.BadUrl;
    const at = std.mem.lastIndexOfScalar(u8, rest, '@') orelse return error.BadUrl;
    const userinfo = rest[0..at];
    const hostpart = rest[at + 1 ..];
    const colon = std.mem.indexOfScalar(u8, userinfo, ':') orelse return error.BadUrl;
    const slash = std.mem.indexOfScalar(u8, hostpart, '/') orelse return error.BadUrl;
    const hostport = hostpart[0..slash];
    const database = hostpart[slash + 1 ..];
    if (database.len == 0) return error.BadUrl;
    var host: []const u8 = hostport;
    var port: u16 = 5432;
    if (std.mem.lastIndexOfScalar(u8, hostport, ':')) |c| {
        host = hostport[0..c];
        port = std.fmt.parseInt(u16, hostport[c + 1 ..], 10) catch return error.BadUrl;
    }
    if (host.len == 0) return error.BadUrl;
    return .{
        .user = userinfo[0..colon],
        .password = userinfo[colon + 1 ..],
        .host = host,
        .port = port,
        .database = database,
    };
}

fn field(msg: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, msg, ',');
    while (it.next()) |part| {
        if (std.mem.startsWith(u8, part, key) and part.len > key.len and part[key.len] == '=') {
            return part[key.len + 1 ..];
        }
    }
    return null;
}

fn writeI32(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, value: i32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(i32, &bytes, value, .big);
    try buf.appendSlice(allocator, &bytes);
}

fn writeI16(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, value: i16) !void {
    var bytes: [2]u8 = undefined;
    std.mem.writeInt(i16, &bytes, value, .big);
    try buf.appendSlice(allocator, &bytes);
}

fn writeCString(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    try buf.appendSlice(allocator, value);
    try buf.append(allocator, 0);
}

fn writeParse(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, sql: []const u8) !void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try body.append(allocator, 0); // unnamed statement
    try writeCString(&body, allocator, sql);
    try writeI16(&body, allocator, 0); // infer OIDs
    try buf.append(allocator, 'P');
    try writeI32(buf, allocator, @intCast(4 + body.items.len));
    try buf.appendSlice(allocator, body.items);
}

fn writeBind(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, params: []const Value) !void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try body.append(allocator, 0); // portal
    try body.append(allocator, 0); // statement
    try writeI16(&body, allocator, 1);
    try writeI16(&body, allocator, 0); // all text
    try writeI16(&body, allocator, @intCast(params.len));
    for (params) |param| {
        switch (param) {
            .null => try writeI32(&body, allocator, -1),
            .text => |text| {
                try writeI32(&body, allocator, @intCast(text.len));
                try body.appendSlice(allocator, text);
            },
        }
    }
    try writeI16(&body, allocator, 1);
    try writeI16(&body, allocator, 0); // results as text
    try buf.append(allocator, 'B');
    try writeI32(buf, allocator, @intCast(4 + body.items.len));
    try buf.appendSlice(allocator, body.items);
}

fn writeExecuteSync(buf: *std.ArrayList(u8), allocator: std.mem.Allocator) !void {
    try buf.append(allocator, 'E');
    try writeI32(buf, allocator, 4 + 1 + 4);
    try buf.append(allocator, 0); // unnamed portal
    try writeI32(buf, allocator, 0); // no row limit
    try buf.append(allocator, 'S');
    try writeI32(buf, allocator, 4);
}

test "parse postgres url" {
    const p = try parseUrl("postgres://tawny:s3cret@127.0.0.1:5432/tawny");
    try std.testing.expectEqualStrings("tawny", p.user);
    try std.testing.expectEqualStrings("s3cret", p.password);
    try std.testing.expectEqualStrings("127.0.0.1", p.host);
    try std.testing.expectEqual(@as(u16, 5432), p.port);
    try std.testing.expectEqualStrings("tawny", p.database);
}
