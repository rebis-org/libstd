const std = @import("std");

// LLVM lowers this to one ror; std.math.rotl emitted out-of-line calls per
// stripe round. Checksum.zig would form a seam cycle.
pub inline fn rotl(x: anytype, comptime n: std.math.Log2Int(@TypeOf(x))) @TypeOf(x) {
    comptime std.debug.assert(n != 0);
    const T = @TypeOf(x);
    const m: std.math.Log2Int(T) = @intCast(@as(u32, @bitSizeOf(T)) - n);
    return (x << n) | (x >> m);
}
