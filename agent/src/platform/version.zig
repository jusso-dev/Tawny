//! Real OS version reporting for enrollment.
//!
//! The server stores `agents.os_version` from the enroll request, and
//! every agent used to enroll with the literal "unknown", hiding the
//! fleet's OS build distribution — the fact Windows endpoint security
//! platform (WESP) eligibility on Windows 11 depends on
//! (docs/windows-endpoint-security-platform.md).
//!
//! - Windows: `RtlGetVersion`, formatted `major.minor.build`
//!   (e.g. `10.0.26100`). `RtlGetVersion` is not manifest-faked like
//!   `GetVersionExW`; Windows 11 still reports 10.0 with build >= 22000,
//!   so the build number is the distinguishing fact.
//! - Linux: kernel release from `/proc/sys/kernel/osrelease`.
//! - macOS: product version via `kern.osproductversion` (e.g. `15.7.1`),
//!   falling back to the Darwin kernel release.
const std = @import("std");
const builtin = @import("builtin");
const iox = @import("../io_compat.zig");

/// Returns an allocated version string for the host OS. On error the
/// caller is free to fall back; enrollment sends "unknown".
pub fn osVersion(alloc: std.mem.Allocator) ![]u8 {
    return switch (builtin.target.os.tag) {
        .windows => windowsVersion(alloc),
        .macos => macosVersion(alloc),
        .linux => linuxVersion(alloc),
        else => error.OsVersionUnavailable,
    };
}

// ---------------------------------------------------------------- Windows

const RTL_OSVERSIONINFOW = extern struct {
    dwOSVersionInfoSize: u32,
    dwMajorVersion: u32,
    dwMinorVersion: u32,
    dwBuildNumber: u32,
    dwPlatformId: u32,
    szCSDVersion: [128]u16,
};

extern "ntdll" fn RtlGetVersion(lpVersionInformation: *RTL_OSVERSIONINFOW) callconv(.c) i32;

fn windowsVersion(alloc: std.mem.Allocator) ![]u8 {
    var version = std.mem.zeroes(RTL_OSVERSIONINFOW);
    version.dwOSVersionInfoSize = @sizeOf(RTL_OSVERSIONINFOW);
    if (RtlGetVersion(&version) != 0) return error.OsVersionUnavailable;
    return formatWindowsVersion(alloc, version.dwMajorVersion, version.dwMinorVersion, version.dwBuildNumber);
}

/// Pure formatting helper so the wire shape is unit-testable on every
/// platform, not just Windows runners.
pub fn formatWindowsVersion(alloc: std.mem.Allocator, major: u32, minor: u32, build: u32) ![]u8 {
    return alloc.print("{d}.{d}.{d}", .{ major, minor, build });
}

// ------------------------------------------------------------------- macOS

fn macosVersion(alloc: std.mem.Allocator) ![]u8 {
    if (sysctlString(alloc, "kern.osproductversion")) |product| {
        if (product.len > 0) return product;
        alloc.free(product);
    } else |_| {}
    const release = try sysctlString(alloc, "kern.osrelease");
    if (release.len == 0) return error.OsVersionUnavailable;
    return release;
}

fn sysctlString(alloc: std.mem.Allocator, name: [:0]const u8) ![]u8 {
    // @cImport was removed in Zig 0.17; std.c declares sysctlbyname.
    var len: usize = 0;
    if (std.c.sysctlbyname(name.ptr, null, &len, null, 0) != 0 or len == 0) {
        return error.OsVersionUnavailable;
    }
    var buf = try alloc.alloc(u8, len);
    defer alloc.free(buf);
    if (std.c.sysctlbyname(name.ptr, buf.ptr, &len, null, 0) != 0) {
        return error.OsVersionUnavailable;
    }
    return alloc.dupe(u8, std.mem.sliceTo(buf[0..len], 0));
}

// ------------------------------------------------------------------- Linux

fn linuxVersion(alloc: std.mem.Allocator) ![]u8 {
    const raw = try readFileAbsoluteAlloc(alloc, "/proc/sys/kernel/osrelease", 256);
    defer alloc.free(raw);
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return error.OsVersionUnavailable;
    return alloc.dupe(u8, trimmed);
}

fn readFileAbsoluteAlloc(alloc: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    const io = iox.current();
    var file = try std.Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);
    return iox.readToEndAlloc(file, alloc, max_bytes);
}

// ------------------------------------------------------------------- tests

test "windows version format is major.minor.build" {
    const alloc = std.testing.allocator;
    const v = try formatWindowsVersion(alloc, 10, 0, 26100);
    defer alloc.free(v);
    try std.testing.expectEqualStrings("10.0.26100", v);
}

test "osVersion reports a real macOS product version" {
    if (builtin.target.os.tag != .macos) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const v = try osVersion(alloc);
    defer alloc.free(v);
    try std.testing.expect(std.ascii.isDigit(v[0]));
    try std.testing.expect(std.mem.indexOfScalar(u8, v, '.') != null);
}

test "osVersion reports the kernel release on Linux" {
    if (builtin.target.os.tag != .linux) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const v = try osVersion(alloc);
    defer alloc.free(v);
    try std.testing.expect(std.ascii.isDigit(v[0]));
}

test "osVersion reports major.minor.build on Windows" {
    if (builtin.target.os.tag != .windows) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const v = try osVersion(alloc);
    defer alloc.free(v);
    // The build number (>= 22000 => Windows 11) is the WESP-relevant fact.
    try std.testing.expect(std.mem.startsWith(u8, v, "10."));
}
