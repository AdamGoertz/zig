const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});

    const dep_pkg = b.dependency("dep", .{
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "base",
        .root_source_file = .{ .path = "src/main.zig" },
        .optimize = optimize,
    });

    const dep_module = dep_pkg.module("dep");
    exe.addModule("dep", dep_module);

    const import_test = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
    });
    import_test.addModule("dep", dep_module);

    const test_step = b.step("test", "Run unit tests");
    b.default_step = test_step;
    test_step.dependOn(&import_test.step);
}
