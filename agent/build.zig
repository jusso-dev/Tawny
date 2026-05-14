const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "tawny-agent",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    if (target.result.os.tag == .windows) {
        exe.linkLibC();
        exe.linkSystemLibrary("ws2_32");
        exe.linkSystemLibrary("kernel32");
        exe.linkSystemLibrary("advapi32");
        exe.linkSystemLibrary("iphlpapi");
        exe.linkSystemLibrary("wtsapi32");
        exe.linkSystemLibrary("ntdll");
    } else if (target.result.os.tag == .macos) {
        exe.linkLibC();
    }

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run the agent");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (target.result.os.tag == .windows) {
        unit_tests.linkLibC();
        unit_tests.linkSystemLibrary("ws2_32");
        unit_tests.linkSystemLibrary("kernel32");
        unit_tests.linkSystemLibrary("advapi32");
        unit_tests.linkSystemLibrary("iphlpapi");
        unit_tests.linkSystemLibrary("wtsapi32");
        unit_tests.linkSystemLibrary("ntdll");
    } else if (target.result.os.tag == .macos) {
        unit_tests.linkLibC();
    }
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);
}
