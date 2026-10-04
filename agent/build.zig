const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = if (target.result.os.tag == .windows or target.result.os.tag == .macos or target.result.os.tag == .linux) true else null,
    });

    const exe = b.addExecutable(.{
        .name = "tawny-agent",
        .root_module = exe_mod,
    });

    linkPlatformLibraries(exe_mod, target.result.os.tag);

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();

    const run_step = b.step("run", "Run the agent");
    run_step.dependOn(&run_cmd.step);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = if (target.result.os.tag == .windows or target.result.os.tag == .macos or target.result.os.tag == .linux) true else null,
    });

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });
    linkPlatformLibraries(test_mod, target.result.os.tag);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);
}

fn linkPlatformLibraries(mod: *std.Build.Module, os: std.Target.Os.Tag) void {
    switch (os) {
        .windows => {
            mod.linkSystemLibrary("ws2_32", .{});
            mod.linkSystemLibrary("kernel32", .{});
            mod.linkSystemLibrary("advapi32", .{});
            mod.linkSystemLibrary("iphlpapi", .{});
            mod.linkSystemLibrary("wtsapi32", .{});
            mod.linkSystemLibrary("ntdll", .{});
        },
        // macOS: libproc and libdispatch come from libSystem (link_libc).
        // CoreServices/CoreFoundation (FSEvents) are dlopen'd at runtime by
        // platform/macos/fsevents.zig: linking frameworks needs the macOS SDK,
        // and release builds cross-compile both macOS targets on Linux.
        else => {},
    }
}
