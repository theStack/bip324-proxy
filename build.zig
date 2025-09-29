const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // build secp256k1 dependency via CMake
    const secp256k1_dep = b.dependency("secp256k1", .{});
    const secp256k1_root_dir = secp256k1_dep.path(".");
    const secp256k1_build_dir = try secp256k1_root_dir.join(b.allocator, "build");
    const secp256k1_staticlib_file = try secp256k1_build_dir.join(b.allocator, "lib/libsecp256k1.a");
    const secp256k1_include_dir = try secp256k1_root_dir.join(b.allocator, "include");

    const secp256k1_cmake_config = b.addSystemCommand(&[_][]const u8{
        "cmake",
        "-B", secp256k1_build_dir.getPath(b),
        "-S", secp256k1_root_dir.getPath(b),
        "-DBUILD_SHARED_LIBS=OFF",
        "-DSECP256K1_BUILD_BENCHMARK=OFF",
        "-DSECP256K1_BUILD_TESTS=OFF",
        "-DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF",
        "-DSECP256K1_BUILD_CTIME_TESTS=OFF",
        "-DCMAKE_BUILD_TYPE=Release",
    });
    const secp256k1_cmake_build = b.addSystemCommand(&[_][]const u8{
        "cmake",
        "--build", secp256k1_build_dir.getPath(b),
        "--config", "Release",
    });
    secp256k1_cmake_build.step.dependOn(&secp256k1_cmake_config.step);

    const exe = b.addExecutable(.{
        .name = "bip324_proxy",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.step.dependOn(&secp256k1_cmake_build.step);
    exe.linkLibC();
    exe.addIncludePath(secp256k1_include_dir);
    exe.addObjectFile(secp256k1_staticlib_file);
    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
}
