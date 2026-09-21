const std = @import("std");
const mem = std.mem;
const math = std.math;

// BLAKE2sp, RAR5's optional file checksum. The stdlib Blake2s exposes no tree
// parameters (fanout, depth, inner length), so this follows the spec.

const iv = [8]u32{
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

const sigma = [10][16]u8{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

const State = struct {
    h: [8]u32,
    t: u64,
    buf: [64]u8,
    buf_len: u8,
    last_node: bool,

    fn initFromParams(param_block: [32]u8) State {
        var state: State = undefined;
        state.h = iv;
        for (&state.h, 0..) |*hword, i| {
            hword.* ^= mem.readInt(u32, param_block[i * 4 ..][0..4], .little);
        }
        state.t = 0;
        state.buf_len = 0;
        state.buf = [_]u8{0} ** 64;
        state.last_node = false;
        return state;
    }

    fn makeParamBlock(digest_length: u8, fanout: u8, depth: u8, node_offset: u32, node_depth: u8, inner_length: u8) [32]u8 {
        var p: [32]u8 = [_]u8{0} ** 32;
        p[0] = digest_length;
        p[2] = fanout;
        p[3] = depth;
        mem.writeInt(u32, p[8..12], node_offset, .little);
        p[14] = node_depth;
        p[15] = inner_length;
        return p;
    }

    fn update(self: *State, data: []const u8) void {
        var off: usize = 0;
        if (self.buf_len != 0 and @as(usize, self.buf_len) + data.len > 64) {
            off = 64 - @as(usize, self.buf_len);
            @memcpy(self.buf[self.buf_len..][0..off], data[0..off]);
            self.t += 64;
            self.compress(&self.buf, false);
            self.buf_len = 0;
        }
        while (off + 64 < data.len) : (off += 64) {
            self.t += 64;
            self.compress(data[off..][0..64], false);
        }
        const remainder = data[off..];
        @memcpy(self.buf[self.buf_len..][0..remainder.len], remainder);
        self.buf_len += @as(u8, @intCast(remainder.len));
    }

    fn final(self: *State, out: *[32]u8) void {
        @memset(self.buf[self.buf_len..], 0);
        self.t += self.buf_len;
        self.compress(&self.buf, true);
        for (self.h, 0..) |hword, i| {
            mem.writeInt(u32, out[i * 4 ..][0..4], hword, .little);
        }
    }

    fn compress(self: *State, block: *const [64]u8, last: bool) void {
        var m: [16]u32 = undefined;
        var v: [16]u32 = undefined;
        for (&m, 0..) |*r, i| r.* = mem.readInt(u32, block[4 * i ..][0..4], .little);
        for (0..8) |k| {
            v[k] = self.h[k];
            v[k + 8] = iv[k];
        }
        v[12] ^= @as(u32, @truncate(self.t));
        v[13] ^= @as(u32, @intCast(self.t >> 32));
        if (last) {
            v[14] = ~v[14];
            if (self.last_node) v[15] = ~v[15];
        }
        comptime var j: usize = 0;
        inline while (j < 10) : (j += 1) {
            g(&v, &m, sigma[j], 0, 4, 8, 12, 0, 1);
            g(&v, &m, sigma[j], 1, 5, 9, 13, 2, 3);
            g(&v, &m, sigma[j], 2, 6, 10, 14, 4, 5);
            g(&v, &m, sigma[j], 3, 7, 11, 15, 6, 7);
            g(&v, &m, sigma[j], 0, 5, 10, 15, 8, 9);
            g(&v, &m, sigma[j], 1, 6, 11, 12, 10, 11);
            g(&v, &m, sigma[j], 2, 7, 8, 13, 12, 13);
            g(&v, &m, sigma[j], 3, 4, 9, 14, 14, 15);
        }
        for (&self.h, 0..) |*r, i| r.* ^= v[i] ^ v[i + 8];
    }
};

fn g(v: *[16]u32, m: *const [16]u32, sigma_row: [16]u8, a: usize, b: usize, c: usize, d: usize, x: usize, y: usize) void {
    v[a] = v[a] +% v[b] +% m[sigma_row[x]];
    v[d] = math.rotr(u32, v[d] ^ v[a], 16);
    v[c] = v[c] +% v[d];
    v[b] = math.rotr(u32, v[b] ^ v[c], 12);
    v[a] = v[a] +% v[b] +% m[sigma_row[y]];
    v[d] = math.rotr(u32, v[d] ^ v[a], 8);
    v[c] = v[c] +% v[d];
    v[b] = math.rotr(u32, v[b] ^ v[c], 7);
}

const parallelism: usize = 8;
const block_size: usize = 64;
const buf_size: usize = parallelism * block_size;

fn initLeaf(leaf_index: u32) State {
    const param_block = State.makeParamBlock(32, parallelism, 2, leaf_index, 0, 32);
    var state = State.initFromParams(param_block);
    if (leaf_index == parallelism - 1) state.last_node = true;
    return state;
}

fn initRoot() State {
    const param_block = State.makeParamBlock(32, parallelism, 2, 0, 1, 32);
    var state = State.initFromParams(param_block);
    state.last_node = true;
    return state;
}

pub fn blake2sp(data: []const u8, out: *[32]u8) void {
    var leaves: [parallelism]State = undefined;
    for (&leaves, 0..) |*leaf, i| leaf.* = initLeaf(@intCast(i));

    var offset: usize = 0;
    while (offset + buf_size <= data.len) : (offset += buf_size) {
        for (&leaves, 0..) |*leaf, i| {
            leaf.update(data[offset + i * block_size ..][0..block_size]);
        }
    }
    const remaining = data[offset..];
    for (&leaves, 0..) |*leaf, i| {
        const block_start = i * block_size;
        if (block_start < remaining.len) {
            leaf.update(remaining[block_start..@min(block_start + block_size, remaining.len)]);
        }
    }

    var root = initRoot();
    var leaf_hash: [32]u8 = undefined;
    for (&leaves) |*leaf| {
        leaf.final(&leaf_hash);
        root.update(&leaf_hash);
    }
    root.final(out);
}

test "blake2sp known vectors" {
    // Vectors from the interop-verified rarz implementation (validated
    // against official rar -htb archives end to end).
    const empty = [32]u8{
        0xdd, 0x0e, 0x89, 0x17, 0x76, 0x93, 0x3f, 0x43,
        0xc7, 0xd0, 0x32, 0xb0, 0x8a, 0x91, 0x7e, 0x25,
        0x74, 0x1f, 0x8a, 0xa9, 0xa1, 0x2c, 0x12, 0xe1,
        0xca, 0xc8, 0x80, 0x15, 0x00, 0xf2, 0xca, 0x4f,
    };
    var out: [32]u8 = undefined;
    blake2sp("", &out);
    try std.testing.expectEqualSlices(u8, &empty, &out);

    const zero_block = [32]u8{
        0x09, 0xbd, 0x17, 0x7a, 0x1f, 0x54, 0x5d, 0xb1,
        0x3d, 0x5f, 0xf7, 0x41, 0x4e, 0x4a, 0x0e, 0xdd,
        0x9c, 0x14, 0x8a, 0x53, 0x52, 0x11, 0xb4, 0x8c,
        0x36, 0x60, 0x1a, 0x83, 0xe5, 0x05, 0x67, 0xbc,
    };
    var block = [_]u8{0} ** 64;
    blake2sp(&block, &out);
    try std.testing.expectEqualSlices(u8, &zero_block, &out);

    const ff_1000 = [32]u8{
        0xa5, 0xb6, 0x89, 0x18, 0xc4, 0x5f, 0xe0, 0x6a,
        0x04, 0x72, 0x94, 0x66, 0x2c, 0x9f, 0x04, 0x0c,
        0xfe, 0x48, 0xc1, 0xf2, 0x0a, 0xcd, 0x22, 0xad,
        0xa6, 0x51, 0x57, 0x4d, 0xb8, 0xb5, 0x16, 0x79,
    };
    var data: [1000]u8 = [_]u8{0xFF} ** 1000;
    blake2sp(&data, &out);
    try std.testing.expectEqualSlices(u8, &ff_1000, &out);
}
