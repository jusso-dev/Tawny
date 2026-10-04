const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const exe = b.addExecutable(.{
        .name = "tawny-server",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Run tawny-server");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{
        .root_module = exe_mod,
    });
    const test_step = b.step("test", "Run server unit tests");
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);
}
