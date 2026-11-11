// Deflate tops out at 288 symbols; the RAR5 writer reaches 306.
const std = @import("std");

const max_alphabet = 704; // Sized for the brotli command alphabet; rar uses 512, deflate/zstd 288.
const max_nodes = 2 * max_alphabet;
const max_code_len = 15;

// Fixed alphabets keep the Kraft check comptime: runtime asserts
// cannot survive ReleaseFast, and slices would make sizes runtime.
pub fn limitedLengths(freqs: anytype, lengths: anytype, comptime limit: u8) void {
    const FreqType = @TypeOf(freqs);
    const LenType = @TypeOf(lengths);
    comptime {
        if (limit < 1 or limit > max_code_len) @compileError("limitedLengths: limit must be in 1..15");
        if (@typeInfo(FreqType) != .pointer or @typeInfo(LenType) != .pointer)
            @compileError("limitedLengths needs fixed-size arrays, not slices");
        const freq_child = @typeInfo(FreqType).pointer.child;
        const len_child = @typeInfo(LenType).pointer.child;
        if (@typeInfo(freq_child) != .array or @typeInfo(len_child) != .array)
            @compileError("limitedLengths needs fixed-size arrays, not slices");
        const N = @typeInfo(freq_child).array.len;
        if (@typeInfo(len_child).array.len != N) @compileError("limitedLengths: length array must match the alphabet");
        if (N > max_alphabet) @compileError("limitedLengths: alphabet exceeds the sized tables");
        // Since count <= N, N <= 2^limit proves count <= 2^limit; the repair loop cannot underflow bl_count[0].
        if (N > (@as(usize, 1) << @intCast(limit)))
            @compileError("limitedLengths: alphabet exceeds 2^limit, no complete code exists");
    }
    const freq_slice: []const u32 = freqs;
    const len_slice: []u8 = lengths;
    @memset(len_slice, 0);
    var used: [max_alphabet]u16 = undefined;
    var count: usize = 0;
    for (freq_slice, 0..) |freq, symbol| {
        if (freq != 0) {
            used[count] = @intCast(symbol);
            count += 1;
        }
    }
    if (count == 0) return;
    if (count == 1) {
        len_slice[used[0]] = 1;
        return;
    }
    for (1..count) |hole| {
        const symbol = used[hole];
        var candidate = hole;
        while (candidate > 0 and freq_slice[used[candidate - 1]] > freq_slice[symbol]) : (candidate -= 1) used[candidate] = used[candidate - 1];
        used[candidate] = symbol;
    }
    var weight: [max_nodes]u32 = undefined;
    var parent: [max_nodes]u16 = undefined;
    for (used[0..count], 0..) |symbol, i| weight[i] = freq_slice[symbol];
    var leaf: usize = 0;
    var internal: usize = 0;
    var created: usize = 0;
    while (created < count - 1) : (created += 1) {
        const first = takeLightest(&weight, &leaf, &internal, count, created);
        parent[first] = @intCast(count + created);
        const second = takeLightest(&weight, &leaf, &internal, count, created);
        parent[second] = @intCast(count + created);
        weight[count + created] = weight[first] + weight[second];
    }
    var depth: [max_nodes]u16 = undefined;
    depth[2 * count - 2] = 0;
    var node = 2 * count - 2;
    while (node > 0) {
        node -= 1;
        depth[node] = depth[parent[node]] + 1;
    }
    var bl_count: [max_code_len + 2]u16 = @splat(0);
    // The reference underflows an odd count to -1, ending its loop there;
    // the unsigned loop must stop on that boundary.
    var overflow: i32 = 0;
    for (0..2 * count - 1) |node_index| overflow += @intFromBool(depth[node_index] > limit);
    for (0..count) |i| bl_count[@min(depth[i], limit)] += 1;
    // Overflow counts in 2^-limit units, so each pull-up repairs two units.
    while (overflow > 0) {
        var width: usize = limit - 1;
        while (width > 0 and bl_count[width] == 0) width -= 1;
        std.debug.assert(width > 0);
        bl_count[width] -= 1;
        bl_count[width + 1] += 2;
        bl_count[limit] -= 1;
        overflow -= 2;
    }
    var position: usize = 0;
    var width: usize = limit;
    while (width >= 1) : (width -= 1) {
        for (0..bl_count[width]) |_| {
            len_slice[used[position]] = @intCast(width);
            position += 1;
        }
    }
}

fn takeLightest(weight: *[max_nodes]u32, leaf: *usize, internal: *usize, count: usize, created: usize) u16 {
    const has_leaf = leaf.* < count;
    const has_internal = internal.* < created;
    if (has_internal and (!has_leaf or weight[count + internal.*] <= weight[leaf.*])) {
        const node = count + internal.*;
        internal.* += 1;
        return @intCast(node);
    }
    const node = leaf.*;
    leaf.* += 1;
    return @intCast(node);
}

test "limited lengths respects the kraft capacity bound" {
    // The dense side is a compile error, so only the solvable boundary runs.
    inline for ([_]u8{ 1, 2, 4, 8 }) |limit| {
        const capacity: usize = @as(usize, 1) << @intCast(limit);
        var freqs: [capacity]u32 = undefined;
        var lengths: [capacity]u8 = undefined;
        @memset(&freqs, 1);
        limitedLengths(&freqs, &lengths, limit);
        for (lengths) |len| try std.testing.expect(len >= 1 and len <= limit);
    }
}
