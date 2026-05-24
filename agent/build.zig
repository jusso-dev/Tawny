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

    if (target.result.os.tag == .windows) {
        exe_mod.linkSystemLibrary("ws2_32", .{});
        exe_mod.linkSystemLibrary("kernel32", .{});
        exe_mod.linkSystemLibrary("advapi32", .{});
        exe_mod.linkSystemLibrary("iphlpapi", .{});
        exe_mod.linkSystemLibrary("wtsapi32", .{});
        exe_mod.linkSystemLibrary("ntdll", .{});
    }

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

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
    if (target.result.os.tag == .windows) {
        test_mod.linkSystemLibrary("ws2_32", .{});
        test_mod.linkSystemLibrary("kernel32", .{});
        test_mod.linkSystemLibrary("advapi32", .{});
        test_mod.linkSystemLibrary("iphlpapi", .{});
        test_mod.linkSystemLibrary("wtsapi32", .{});
        test_mod.linkSystemLibrary("ntdll", .{});
    }
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);
}
