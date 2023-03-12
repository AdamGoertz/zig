const std = @import("std");
const dep = @import("dep");

pub fn main() void {}

test "add" {
    try std.testing.expectEqual(@as(i32, 15), dep.add(5, 10));
}
