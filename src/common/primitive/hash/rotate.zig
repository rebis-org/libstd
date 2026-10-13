const std = @import("std");

// LLVM pattern-matches this to a single ror; std.math.rotl emitted an
// out-of-line call per round in the xxHash stripe loops. Shared by the
// xxh32 and xxh64 onprem implementations, which cannot import checksum.zig
// without a seam cycle.
pub inline fn rotl(x: anytype, comptime n: std.math.Log2Int(@TypeOf(x))) @TypeOf(x) {
    comptime std.debug.assert(n != 0);
    const T = @TypeOf(x);
    const m: std.math.Log2Int(T) = @intCast(@as(u32, @bitSizeOf(T)) - n);
    return (x << n) | (x >> m);
}
