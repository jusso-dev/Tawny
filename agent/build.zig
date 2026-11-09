const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const want_yara = b.option(bool, "yara", "Build in libyara for YARA file scanning (default off)") orelse false;

    const options = b.addOptions();
    options.addOption(bool, "yara", want_yara);
    // libyara, compiled once and linked into the agent and its tests.
    const yara_lib: ?*std.Build.Step.Compile = if (want_yara) buildYara(b, target, optimize) else null;

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
    exe_mod.addOptions("build_options", options);
    if (yara_lib) |lib| exe_mod.linkLibrary(lib);

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
    test_mod.addOptions("build_options", options);
    if (yara_lib) |lib| test_mod.linkLibrary(lib);
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
            mod.linkSystemLibrary("wevtapi", .{});
            // DPAPI keystore and TPM wrap (#58).
            mod.linkSystemLibrary("crypt32", .{});
            mod.linkSystemLibrary("ncrypt", .{});
            // WFP user-mode API for network isolation (#57).
            mod.linkSystemLibrary("fwpuclnt", .{});
        },
        // macOS: libproc and libdispatch come from libSystem (link_libc).
        // CoreServices/CoreFoundation (FSEvents) are dlopen'd at runtime by
        // platform/macos/fsevents.zig: linking frameworks needs the macOS SDK,
        // and release builds cross-compile both macOS targets on Linux.
        else => {},
    }
}

/// libyara 4.6.0 from the pinned source in build.zig.zon, built with Zig's
/// C compiler. Modules that need extra libraries (magic, cuckoo, hash,
/// authenticode, dotnet, dex, macho) are off, and so is OpenSSL, so pe
/// signatures and imphash are not available. Returns null while the lazy
/// dependency is still being fetched.
fn buildYara(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) ?*std.Build.Step.Compile {
    const dep = b.lazyDependency("yara", .{}) orelse return null;
    const os = target.result.os.tag;
    const mod = b.createModule(.{
        .target = target,
        // libyara has UB the safety checks trip on; build it optimised
        // without them, whatever the agent's mode.
        .optimize = if (optimize == .debug) .fast else optimize,
        .link_libc = true,
        .sanitize_c = .off,
    });
    mod.addIncludePath(dep.path("libyara/include"));
    mod.addIncludePath(dep.path("libyara"));
    mod.addCMacro("_GNU_SOURCE", "1");
    mod.addCMacro("NDEBUG", "1");
    mod.addCMacro("BUCKETS_128", "1");
    mod.addCMacro("CHECKSUM_1B", "1");
    mod.addCMacro("HAVE_STDBOOL_H", "1");
    mod.addCMacro("HAVE_CLOCK_GETTIME", "1");
    if (os == .windows) {
        mod.addCMacro("USE_WINDOWS_PROC", "1");
        mod.addCMacro("_CRT_SECURE_NO_WARNINGS", "1");
        mod.linkSystemLibrary("advapi32", .{});
    } else if (os == .linux) {
        mod.addCMacro("USE_LINUX_PROC", "1");
        mod.addCMacro("HAVE_MEMMEM", "1");
        mod.addCMacro("HAVE_TIMEGM", "1");
    } else if (os == .macos) {
        // proc/mach.c needs <mach/mach_vm.h> from the macOS SDK, which a
        // Linux cross build doesn't have. The agent scans files and buffers,
        // never process memory, so the no-op proc backend is enough.
        mod.addCMacro("USE_NO_PROC", "1");
        mod.addCMacro("HAVE_MEMMEM", "1");
        mod.addCMacro("HAVE_TIMEGM", "1");
    } else {
        mod.addCMacro("USE_NO_PROC", "1");
    }
    const proc_src: []const u8 = switch (os) {
        .windows => "libyara/proc/windows.c",
        .linux => "libyara/proc/linux.c",
        else => "libyara/proc/none.c",
    };
    mod.addCSourceFiles(.{
        .root = dep.path("."),
        .files = &yara_sources,
        .flags = &yara_flags,
    });
    mod.addCSourceFiles(.{
        .root = dep.path("."),
        .files = &.{proc_src},
        .flags = &yara_flags,
    });
    const lib = b.addLibrary(.{
        .name = "yara",
        .linkage = .static,
        .root_module = mod,
    });
    return lib;
}

const yara_flags = [_][]const u8{
    "-std=gnu99",
    "-fno-sanitize=undefined",
    "-Wno-everything",
};

const yara_sources = [_][]const u8{
    "libyara/modules/tests/tests.c",
    "libyara/modules/elf/elf.c",
    "libyara/modules/math/math.c",
    "libyara/modules/time/time.c",
    "libyara/modules/pe/pe.c",
    "libyara/modules/pe/pe_utils.c",
    "libyara/modules/console/console.c",
    "libyara/modules/string/string.c",
    "libyara/grammar.c",
    "libyara/ahocorasick.c",
    "libyara/arena.c",
    "libyara/atoms.c",
    "libyara/base64.c",
    "libyara/bitmask.c",
    "libyara/compiler.c",
    "libyara/endian.c",
    "libyara/exec.c",
    "libyara/exefiles.c",
    "libyara/filemap.c",
    "libyara/hash.c",
    "libyara/hex_grammar.c",
    "libyara/hex_lexer.c",
    "libyara/lexer.c",
    "libyara/libyara.c",
    "libyara/mem.c",
    "libyara/modules.c",
    "libyara/notebook.c",
    "libyara/object.c",
    "libyara/parser.c",
    "libyara/proc.c",
    "libyara/re.c",
    "libyara/re_grammar.c",
    "libyara/re_lexer.c",
    "libyara/rules.c",
    "libyara/scan.c",
    "libyara/scanner.c",
    "libyara/simple_str.c",
    "libyara/sizedstr.c",
    "libyara/stack.c",
    "libyara/stopwatch.c",
    "libyara/strutils.c",
    "libyara/stream.c",
    "libyara/tlshc/tlsh.c",
    "libyara/tlshc/tlsh_impl.c",
    "libyara/tlshc/tlsh_util.c",
    "libyara/threading.c",
};
