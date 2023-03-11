const dep2 = @import("dep2");

pub fn add(a: i32, b: i32) i32 {
    return dep2.add(a, b);
}
