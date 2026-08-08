const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Compile the BPF program (CO-RE) with clang and install the object into
    // the source tree so @embedFile can embed it into the executable (single
    // binary).
    // Note: the source must be registered as an input with addFileArg so the
    // zig cache notices changes and recompiles.
    const clang_cmd = b.addSystemCommand(&.{
        "clang", "-target", "bpf", "-g", "-O2", "-c",
    });
    clang_cmd.addFileArg(b.path("src/probe.bpf.c"));
    const bpf_obj = clang_cmd.addPrefixedOutputFileArg("-o", "probe.bpf.o");
    const install_bpf = b.addInstallFileWithDir(bpf_obj, .{ .custom = ".." }, "src/probe.bpf.o");
    b.getInstallStep().dependOn(&install_bpf.step);

    const exe = b.addExecutable(.{
        .name = "varkaris",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            // Required: libbpf is built against glibc and accesses glibc's
            // TLS variables (%fs: negative offsets). Without linking libc the
            // binary has no PT_TLS segment, ld.so doesn't lay out the shared
            // library's static TLS area, and libbpf segfaults inside
            // __snprintf_chk (observed: SIGSEGV at mov %fs:(%rax),%eax).
            .link_libc = true,
        }),
    });
    // @embedFile reads src/probe.bpf.o, so the install step must finish first
    exe.step.dependOn(&install_bpf.step);
    exe.root_module.linkSystemLibrary("bpf", .{});
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
}
