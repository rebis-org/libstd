const std = @import("std");

const max_alphabet = 288;
const max_nodes = 2 * max_alphabet;
const max_code_len = 15;

pub fn limitedLengths(freqs: []const u32, lengths: []u8, limit: u8) void {
    @memset(lengths, 0);
    var used: [max_alphabet]u16 = undefined;
    var count: usize = 0;
    for (freqs, 0..) |freq, symbol| {
        if (freq != 0) {
            used[count] = @intCast(symbol);
            count += 1;
        }
    }
    if (count == 0) return;
    if (count == 1) {
        lengths[used[0]] = 1;
        return;
    }
    for (1..count) |i| {
        const symbol = used[i];
        var j = i;
        while (j > 0 and freqs[used[j - 1]] > freqs[symbol]) : (j -= 1) used[j] = used[j - 1];
        used[j] = symbol;
    }
    var weight: [max_nodes]u32 = undefined;
    var parent: [max_nodes]u16 = undefined;
    for (used[0..count], 0..) |symbol, i| weight[i] = freqs[symbol];
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
    var overflow: u32 = 0;
    for (0..2 * count - 1) |node_index| overflow += @intFromBool(depth[node_index] > limit);
    for (0..count) |i| bl_count[@min(depth[i], limit)] += 1;
    // Every clamped node (leaf or internal) counts, so overflow is even and
    // the Kraft excess in 2^-limit units is exactly overflow/2; each pull-up
    // repairs two units and always finds a leaf below the limit.
    while (overflow > 0) {
        var bits: usize = limit - 1;
        while (bl_count[bits] == 0) bits -= 1;
        bl_count[bits] -= 1;
        bl_count[bits + 1] += 2;
        bl_count[limit] -= 1;
        overflow -= 2;
    }
    var position: usize = 0;
    var bits: usize = limit;
    while (bits >= 1) : (bits -= 1) {
        for (0..bl_count[bits]) |_| {
            lengths[used[position]] = @intCast(bits);
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
