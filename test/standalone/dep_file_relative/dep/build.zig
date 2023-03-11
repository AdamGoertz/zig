const std = @import("std");

pub fn build(b: *std.Build) void {
    _ = b.standardOptimizeOption(.{});

    const dep2_pkg = b.dependency("dep2", .{});
    const dep2_module = dep2_pkg.module("dep2");

    _ = b.addModule("dep", .{ .source_file = .{ .path = "src/main.zig" }, .dependencies = &.{
        .{
            .name = "dep2",
            .module = dep2_module,
        },
    } });
}
