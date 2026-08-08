const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // 用 clang 编译 BPF kprobe 程序（CO-RE），产物安装到 zig-out/bin。
    // 注意：源码必须用 addFileArg 注册为输入，zig 缓存才能感知变化并重编译。
    const clang_cmd = b.addSystemCommand(&.{
        "clang", "-target", "bpf", "-g", "-O2", "-c",
    });
    clang_cmd.addFileArg(b.path("src/probe.bpf.c"));
    const bpf_obj = clang_cmd.addPrefixedOutputFileArg("-o", "probe.bpf.o");
    const install_bpf = b.addInstallFile(bpf_obj, "bin/probe.bpf.o");
    b.getInstallStep().dependOn(&install_bpf.step);

    const exe = b.addExecutable(.{
        .name = "varkaris",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
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
