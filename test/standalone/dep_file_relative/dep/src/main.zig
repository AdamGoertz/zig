const dep2 = @import("dep2");

pub fn mul(a: i32, b: i32) i32 {
    return dep2.mul(a, b);
}
