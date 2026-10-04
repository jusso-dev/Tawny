//! Thin bindings over libproc and the kern sysctls the macOS collectors use.
//! Layouts were checked against the macOS 26 SDK headers (arm64 and x86_64
//! share them); comptime asserts pin the sizes we rely on.
//!
//! Every call here is a plain syscall wrapper: failures (EPERM for other
//! users' processes when not root, ESRCH for processes that exited) come back
//! as `null`/`error`, never as a crash.

const std = @import("std");
const parse = @import("parse.zig");

pub const max_pids: usize = 65536;
pub const path_max: usize = 4096; // PROC_PIDPATHINFO_MAXSIZE
/// Bytes of KERN_PROCARGS2 we read per process. The kernel truncates to the
/// buffer we pass; argv sits before the environment, and privacy.zig only
/// looks at the first 32 KiB of a command line anyway.
pub const procargs_buffer_bytes: usize = 64 * 1024;

const PROC_PIDLISTFDS: c_int = 1;
const PROC_PIDTBSDINFO: c_int = 3;
const PROC_PIDT_SHORTBSDINFO: c_int = 13;
const PROC_PIDFDSOCKETINFO: c_int = 3;
pub const PROX_FDTYPE_SOCKET: u32 = 2;

const CTL_KERN: c_int = 1;
const KERN_PROC: c_int = 14;
const KERN_PROC_PID: c_int = 1;
const KERN_PROCARGS2: c_int = 49;

extern "c" fn proc_listallpids(buffer: ?*anyopaque, buffersize: c_int) c_int;
extern "c" fn proc_pidinfo(pid: c_int, flavor: c_int, arg: u64, buffer: ?*anyopaque, buffersize: c_int) c_int;
extern "c" fn proc_pidfdinfo(pid: c_int, fd: c_int, flavor: c_int, buffer: ?*anyopaque, buffersize: c_int) c_int;
extern "c" fn proc_pidpath(pid: c_int, buffer: ?*anyopaque, buffersize: u32) c_int;
extern "c" fn sysctl(name: [*]const c_int, namelen: c_uint, oldp: ?*anyopaque, oldlenp: ?*usize, newp: ?*anyopaque, newlen: usize) c_int;

/// struct proc_bsdinfo (sys/proc_info.h)
const BsdInfo = extern struct {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    rfu_1: u32,
    pbi_comm: [16]u8,
    pbi_name: [32]u8,
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
};

/// struct proc_bsdshortinfo — readable for nearly every process even when
/// PROC_PIDTBSDINFO is refused with EPERM.
const ShortBsdInfo = extern struct {
    pbsi_pid: u32,
    pbsi_ppid: u32,
    pbsi_pgid: u32,
    pbsi_status: u32,
    pbsi_comm: [16]u8,
    pbsi_flags: u32,
    pbsi_uid: u32,
    pbsi_gid: u32,
    pbsi_ruid: u32,
    pbsi_rgid: u32,
    pbsi_svuid: u32,
    pbsi_svgid: u32,
    pbsi_rfu: u32,
};

pub const FdInfo = extern struct {
    proc_fd: i32,
    proc_fdtype: u32,
};

pub const kinfo_proc_size: usize = 648;
pub const socket_fdinfo_size: usize = 792;

comptime {
    std.debug.assert(@sizeOf(BsdInfo) == 136);
    std.debug.assert(@offsetOf(BsdInfo, "pbi_comm") == 48);
    std.debug.assert(@offsetOf(BsdInfo, "pbi_start_tvsec") == 120);
    std.debug.assert(@sizeOf(ShortBsdInfo) == 64);
    std.debug.assert(@offsetOf(ShortBsdInfo, "pbsi_uid") == 36);
    std.debug.assert(@sizeOf(FdInfo) == 8);
}

/// Identity of one process as far as the caller is allowed to see it.
pub const Identity = struct {
    pid: u32,
    ppid: u32,
    uid: u32,
    /// Seconds since the epoch; 0 when unknown.
    start_sec: u64,
    start_usec: u64,
    /// `pbi_name` (up to 32 bytes) when readable, else the 16-byte `comm`.
    name_buf: [33]u8 = undefined,
    name_len: u8 = 0,

    fn setName(self: *Identity, value: []const u8) void {
        const n = @min(value.len, self.name_buf.len - 1);
        @memcpy(self.name_buf[0..n], value[0..n]);
        self.name_len = @intCast(n);
    }

    pub fn name(self: *const Identity) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    /// Diff key that survives PID reuse (like Linux /proc/<pid>/stat field 22).
    pub fn startKey(self: Identity) u64 {
        return self.start_sec *% 1_000_000 +% self.start_usec;
    }
};

/// Snapshot of live PIDs. Caller frees.
pub fn listAllPids(alloc: std.mem.Allocator) ![]i32 {
    const estimate = proc_listallpids(null, 0);
    if (estimate <= 0) return error.ProcListFailed;
    // Headroom for processes spawned between the two calls.
    const capacity: usize = @min(@as(usize, @intCast(estimate)) + 256, max_pids);
    const pids = try alloc.alloc(i32, capacity);
    errdefer alloc.free(pids);
    const count = proc_listallpids(pids.ptr, @intCast(capacity * @sizeOf(i32)));
    if (count <= 0) return error.ProcListFailed;
    const n: usize = @min(@as(usize, @intCast(count)), capacity);
    if (alloc.resize(pids, n)) return pids[0..n];
    const exact = try alloc.dupe(i32, pids[0..n]);
    alloc.free(pids);
    return exact;
}

/// Read pid/ppid/uid/name/start time. Falls back to the short BSD info (no
/// start time, 16-byte name) plus `kinfo_proc` for the start time when the
/// full record is refused. Returns null only when the process is gone.
pub fn identity(pid: i32) ?Identity {
    var full: BsdInfo = undefined;
    const got = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &full, @sizeOf(BsdInfo));
    if (got == @sizeOf(BsdInfo)) {
        var id = Identity{
            .pid = full.pbi_pid,
            .ppid = full.pbi_ppid,
            .uid = full.pbi_uid,
            .start_sec = full.pbi_start_tvsec,
            .start_usec = full.pbi_start_tvusec,
        };
        const long_name = parse.cString(&full.pbi_name);
        id.setName(if (long_name.len > 0) long_name else parse.cString(&full.pbi_comm));
        return id;
    }

    var short: ShortBsdInfo = undefined;
    const got_short = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &short, @sizeOf(ShortBsdInfo));
    if (got_short != @sizeOf(ShortBsdInfo)) return null;
    var id = Identity{
        .pid = short.pbsi_pid,
        .ppid = short.pbsi_ppid,
        .uid = short.pbsi_uid,
        .start_sec = 0,
        .start_usec = 0,
    };
    id.setName(parse.cString(&short.pbsi_comm));
    if (startTimeFromKinfo(pid)) |start| {
        id.start_sec = start[0];
        id.start_usec = start[1];
    }
    return id;
}

fn startTimeFromKinfo(pid: i32) ?[2]u64 {
    var buf: [kinfo_proc_size]u8 align(8) = undefined;
    var len: usize = buf.len;
    const mib = [_]c_int{ CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    if (sysctl(&mib, mib.len, &buf, &len, null, 0) != 0) return null;
    if (len < 16) return null;
    // kp_proc.p_un.__p_starttime is a struct timeval at offset 0.
    const sec = std.mem.readInt(i64, buf[0..8], .little);
    const usec = std.mem.readInt(i32, buf[8..12], .little);
    if (sec <= 0 or usec < 0) return null;
    return .{ @intCast(sec), @intCast(usec) };
}

/// Executable path via proc_pidpath; works for other users' processes.
pub fn pidPath(pid: i32, buf: *[path_max]u8) ?[]const u8 {
    const n = proc_pidpath(pid, buf, buf.len);
    if (n <= 0) return null;
    return buf[0..@intCast(n)];
}

/// Raw KERN_PROCARGS2 bytes, truncated to `buf`. Null on EPERM/EINVAL
/// (other users' processes when not root, zombies, kernel_task).
pub fn procArgs(pid: i32, buf: []u8) ?[]const u8 {
    var len: usize = buf.len;
    const mib = [_]c_int{ CTL_KERN, KERN_PROCARGS2, pid };
    if (sysctl(&mib, mib.len, buf.ptr, &len, null, 0) != 0) return null;
    return buf[0..@min(len, buf.len)];
}

/// List file descriptors into `scratch`, growing it (bounded) when needed.
/// Returns null when the process is not inspectable.
pub fn listFds(pid: i32, scratch: *std.array_list.Managed(FdInfo)) !?[]const FdInfo {
    const max_fds: usize = 1 << 16;
    const needed = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, null, 0);
    if (needed <= 0) return null;
    const want = @min(@as(usize, @intCast(needed)) / @sizeOf(FdInfo) + 32, max_fds);
    try scratch.resize(want);
    const got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, scratch.items.ptr, @intCast(want * @sizeOf(FdInfo)));
    if (got <= 0) return null;
    return scratch.items[0..@min(@as(usize, @intCast(got)) / @sizeOf(FdInfo), want)];
}

extern "c" fn if_indextoname(ifindex: c_uint, ifname: [*]u8) ?[*:0]u8;

/// Interface name for an index ("en0"); empty when unknown.
pub fn interfaceName(index: u16, buf: *[16]u8) []const u8 {
    const name = if_indextoname(index, buf) orelse return "";
    return std.mem.span(name);
}

/// ARP table dump: sysctl {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS,
/// RTF_LLINFO}. Parse with parse.NeighborIterator. Caller frees.
pub fn arpTable(alloc: std.mem.Allocator) ![]u8 {
    const max_bytes: usize = 4 * 1024 * 1024;
    const mib = [_]c_int{ 4, 17, 0, 2, 2, 0x400 };
    var len: usize = 0;
    if (sysctl(&mib, mib.len, null, &len, null, 0) != 0) return error.SysctlFailed;
    if (len == 0) return alloc.alloc(u8, 0);
    // The table can grow between calls; leave headroom and retry once.
    var attempt: usize = 0;
    while (attempt < 2) : (attempt += 1) {
        const cap = @min(len + len / 4 + 1024, max_bytes);
        const buf = try alloc.alloc(u8, cap);
        var got: usize = cap;
        if (sysctl(&mib, mib.len, buf.ptr, &got, null, 0) == 0) {
            if (alloc.resize(buf, got)) return buf[0..got];
            const exact = try alloc.dupe(u8, buf[0..got]);
            alloc.free(buf);
            return exact;
        }
        alloc.free(buf);
        if (cap == max_bytes) break;
        len = cap * 2;
    }
    return error.SysctlFailed;
}

/// Raw `struct socket_fdinfo` for one descriptor.
pub fn socketInfo(pid: i32, fd: i32, buf: *[socket_fdinfo_size]u8) bool {
    const got = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, buf, socket_fdinfo_size);
    return got == socket_fdinfo_size;
}
