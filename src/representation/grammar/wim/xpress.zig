const std = @import("std");

const exception_prim = @import("../../../common/primitive/exception.zig");
const bits = @import("bits.zig");

const Exception = exception_prim.Exception;

// WIM XPRESS codec, ported from wimlib src/xpress_decompress.c.
// Nibble header carries canonical Huffman lengths for 512 symbols.
// Symbols 0..255 are literals; 256..511 are matches.
// Length bytes after a 0xff marker come from the raw cursor.

const num_symbols: usize = 512;
const num_chars: usize = 256;
const max_codeword_len: usize = 15;
const min_match_len: usize = 3;
const end_of_data: usize = 256;
const max_match_len: usize = 65538;

const Code = bits.Code(max_codeword_len, num_symbols);

// Encoder workspace: hash heads (u16[1<<14]) plus a u16 chain per input
// byte, plus the parse item list (8 bytes per input position).
pub fn encodeWorkspaceSize(input_len: usize) usize {
    return (1 << 14) * 2 + input_len * 2 + (input_len + 8) * @sizeOf(Item) + 4096;
}

// Length-limited canonical Huffman code, ported from wimlib's
// make_canonical_huffman_code() in compress_common.c. Leaves-first tie
// breaking matches the LZMS adaptive-code contract; lengths clamp to the
// maximum the same way wimlib's compute_length_counts() does.
fn makeCanonicalCode(num_syms: usize, max_len: usize, freqs: []const u32, lens: []u8, codewords: []u32) void {
    const num_symbol_bits: u5 = 10;
    const symbol_mask: u32 = (1 << num_symbol_bits) - 1;
    const freq_mask: u32 = ~symbol_mask;

    var used: usize = 0;
    for (freqs, 0..) |f, sym| {
        if (f != 0) {
            codewords[used] = (@as(u32, @intCast(sym))) | (f << num_symbol_bits);
            used += 1;
        } else {
            lens[sym] = 0;
        }
    }
    if (used == 0) return;
    if (used == 1) {
        const sym: usize = @intCast(codewords[0] & symbol_mask);
        const other: usize = if (sym != 0) sym else 1;
        // Canonical: symbol 0 always takes codeword 0.
        codewords[0] = 0;
        lens[0] = 1;
        codewords[other] = 1;
        lens[other] = 1;
        return;
    }
    std.sort.pdq(u32, codewords[0..used], {}, struct {
        fn lessThan(_: void, a: u32, b: u32) bool {
            return a < b;
        }
    }.lessThan);
    // build_tree over the sorted entries.
    {
        var i: usize = 0;
        var b: usize = 0;
        var e: usize = 0;
        const last_idx: usize = used - 1;
        while (true) {
            var new_freq: u32 = undefined;
            if (i + 1 <= last_idx and
                (b == e or (codewords[i + 1] & freq_mask) <= (codewords[b] & freq_mask)))
            {
                new_freq = (codewords[i] & freq_mask) + (codewords[i + 1] & freq_mask);
                i += 2;
            } else if (b + 2 <= e and
                (i > last_idx or (codewords[b + 1] & freq_mask) < (codewords[i] & freq_mask)))
            {
                new_freq = (codewords[b] & freq_mask) + (codewords[b + 1] & freq_mask);
                codewords[b] = (@as(u32, @intCast(e)) << num_symbol_bits) | (codewords[b] & symbol_mask);
                codewords[b + 1] = (@as(u32, @intCast(e)) << num_symbol_bits) | (codewords[b + 1] & symbol_mask);
                b += 2;
            } else {
                new_freq = (codewords[i] & freq_mask) + (codewords[b] & freq_mask);
                codewords[b] = (@as(u32, @intCast(e)) << num_symbol_bits) | (codewords[b] & symbol_mask);
                i += 1;
                b += 1;
            }
            codewords[e] = new_freq | (codewords[e] & symbol_mask);
            e += 1;
            if (e >= last_idx) break;
        }
    }
    // compute_length_counts.
    var len_counts: [16]u32 = @splat(0);
    var a = codewords;
    const root_idx: usize = used - 2;
    len_counts[1] = 2;
    a[root_idx] &= symbol_mask;
    var node: i64 = @as(i64, @intCast(root_idx)) - 1;
    while (node >= 0) : (node -= 1) {
        const n: usize = @intCast(node);
        const parent: usize = @intCast(a[n] >> num_symbol_bits);
        const depth: u32 = (a[parent] >> num_symbol_bits) + 1;
        var len: u32 = depth;
        a[n] = (a[n] & symbol_mask) | (depth << num_symbol_bits);
        if (len >= @as(u32, @intCast(max_len))) {
            len = @intCast(max_len);
            len -= 1;
            while (len_counts[len] == 0) len -= 1;
        }
        len_counts[len] -= 1;
        len_counts[len + 1] += 2;
    }
    // gen_codewords: assign longest lengths to rarest symbols (the sorted
    // order), then canonical codewords in symbol order.
    {
        var idx: usize = 0;
        var len: usize = max_len;
        while (len >= 1) : (len -= 1) {
            var count = len_counts[len];
            while (count != 0) : (count -= 1) {
                lens[@intCast(a[idx] & symbol_mask)] = @intCast(len);
                idx += 1;
            }
        }
    }
    var next_codes: [16]u32 = undefined;
    next_codes[0] = 0;
    next_codes[1] = 0;
    for (2..max_len + 1) |len| {
        next_codes[len] = (next_codes[len - 1] + len_counts[len - 1]) << 1;
    }
    for (0..num_syms) |sym| {
        const l = lens[sym];
        codewords[sym] = next_codes[l];
        next_codes[l] += 1;
    }
}

// XPRESS output bitstream, ported from wimlib's xpress_output_bitstream.
// Words flush at the oldest pending slot; extra length bytes interleave at
// the raw cursor, which trails two words ahead.
const OutBits = struct {
    data: []u8,
    bitbuf: u32 = 0,
    bitcount: u6 = 0,
    next_bits: usize = 0,
    next_bits2: usize = 2,
    next_byte: usize = 4,
    overflow: bool = false,

    fn writeBits(self: *OutBits, value: u32, num_bits: u6) void {
        self.bitcount += num_bits;
        self.bitbuf = (self.bitbuf << @intCast(num_bits)) | value;
        if (self.bitcount > 16) {
            self.bitcount -= 16;
            if (self.next_byte + 2 <= self.data.len) {
                // The low 16 bits are the flushed word; older flushed bits
                // still sitting above the pending bits are shifted out and
                // discarded, exactly as wimlib's put_unaligned_le16 does.
                const flushed: u16 = @truncate(self.bitbuf >> @as(u5, @intCast(self.bitcount)));
                std.mem.writeInt(u16, self.data[self.next_bits..][0..2], flushed, .little);
                self.next_bits = self.next_bits2;
                self.next_bits2 = self.next_byte;
                self.next_byte += 2;
            } else {
                self.overflow = true;
            }
        }
    }

    fn writeByte(self: *OutBits, byte: u8) void {
        if (self.next_byte < self.data.len) {
            self.data[self.next_byte] = byte;
            self.next_byte += 1;
        } else {
            self.overflow = true;
        }
    }

    fn writeU16(self: *OutBits, value: u16) void {
        if (self.next_byte + 2 <= self.data.len) {
            std.mem.writeInt(u16, self.data[self.next_byte..][0..2], value, .little);
            self.next_byte += 2;
        } else {
            self.overflow = true;
        }
    }

    fn flush(self: *OutBits) Exception!usize {
        if (self.next_byte + 2 > self.data.len) return error.CapacityException;
        // Left-justify the pending bits in the final word; the low 16 bits
        // are written, so stale high bits truncate away like put_le16.
        const last: u16 = @truncate(self.bitbuf << @as(u5, @intCast(16 - self.bitcount)));
        std.mem.writeInt(u16, self.data[self.next_bits..][0..2], last, .little);
        std.mem.writeInt(u16, self.data[self.next_bits2..][0..2], 0, .little);
        return self.next_byte;
    }
};

const Item = union(enum) {
    literal: u8,
    match: struct { len: u32, offset: u32 },
};

const max_search_depth = 24;
const nice_match_length = 48;

fn hash4(data: []const u8, pos: usize) usize {
    const v = std.mem.readInt(u32, data[pos..][0..4], .little);
    return (v *% 2654435761) >> 18;
}

const Finder = struct {
    input: []const u8,
    head: []u16,
    chain: []u16,
    inserted: usize = 0,

    fn insertOne(self: *Finder, pos: usize) void {
        if (pos + 4 > self.input.len) return;
        const h = hash4(self.input, pos);
        self.chain[pos] = self.head[h];
        self.head[h] = @intCast(pos);
    }

    // Positions before pos are in the tables; pos itself is not.
    fn prepare(self: *Finder, pos: usize) void {
        while (self.inserted < pos) : (self.inserted += 1) {
            self.insertOne(self.inserted);
        }
    }

    fn find(self: *Finder, pos: usize, max_len: usize) ?Item {
        if (pos + 4 > self.input.len or max_len < min_match_len) return null;
        self.prepare(pos);
        var best_len: usize = min_match_len - 1;
        var best_offset: usize = 0;
        var candidate: usize = self.head[hash4(self.input, pos)];
        var depth: usize = max_search_depth;
        while (candidate != 0xFFFF and candidate < pos and depth != 0) : (depth -= 1) {
            if (self.input[candidate + best_len] != self.input[pos + best_len]) {
                candidate = self.chain[candidate];
                continue;
            }
            var l: usize = 0;
            while (l < max_len and self.input[candidate + l] == self.input[pos + l]) l += 1;
            if (l == max_len or l > best_len) {
                best_len = l;
                best_offset = pos - candidate;
                if (l >= nice_match_length or l == max_len) break;
            }
            candidate = self.chain[candidate];
        }
        if (best_offset == 0) return null;
        return Item{ .match = .{ .len = @intCast(best_len), .offset = @intCast(best_offset) } };
    }
};

// Greedy parse with one-position lazy evaluation over a hash chain.
fn parse(input: []const u8, items: []Item, head: []u16, chain: []u16, freqs: []u32) usize {
    @memset(head, 0xFFFF);
    const len = input.len;
    var i: usize = 0;
    var count: usize = 0;
    var finder = Finder{ .input = input, .head = head, .chain = chain };
    while (i < len) {
        const max_len = @min(len - i, max_match_len);
        const here = finder.find(i, max_len);
        if (here == null) {
            freqs[input[i]] += 1;
            items[count] = .{ .literal = input[i] };
            count += 1;
            i += 1;
            continue;
        }
        const m = here.?;
        // Lazy step: does the next position start a longer match?
        if (i + 1 < len) {
            const next = finder.find(i + 1, @min(len - (i + 1), max_match_len));
            if (next != null and next.?.match.len > m.match.len + 1) {
                freqs[input[i]] += 1;
                items[count] = .{ .literal = input[i] };
                count += 1;
                i += 1;
                continue;
            }
        }
        const adjusted = m.match.len - min_match_len;
        const log2_offset: u5 = @intCast(31 - @clz(m.match.offset));
        const len_hdr: u32 = @min(0xF, adjusted);
        freqs[num_chars + (@as(u32, log2_offset) << 4 | len_hdr)] += 1;
        items[count] = m;
        count += 1;
        i += m.match.len;
    }
    return count;
}

fn writeItem(os: *OutBits, item: Item, codewords: []const u32, lens: []const u8) void {
    switch (item) {
        .literal => |byte| os.writeBits(codewords[byte], @intCast(lens[byte])),
        .match => |m| {
            const adjusted = m.len - min_match_len;
            const log2_offset: u5 = @intCast(31 - @clz(m.offset));
            const len_hdr: u32 = @min(0xF, adjusted);
            const sym: usize = num_chars + (@as(usize, log2_offset) << 4 | len_hdr);
            os.writeBits(codewords[sym], @intCast(lens[sym]));
            if (adjusted >= 0xF) {
                const byte1: u32 = @min(adjusted - 0xF, 0xFF);
                os.writeByte(@intCast(byte1));
                if (byte1 == 0xFF) os.writeU16(@intCast(adjusted));
            }
            os.writeBits(m.offset - (@as(u32, 1) << log2_offset), log2_offset);
        },
    }
}

pub fn xpressEncode(input: []const u8, output: []u8, scratch: []u8) Exception!usize {
    if (input.len > 65536) return error.CallException;
    if (output.len < num_symbols / 2) return error.CapacityException;
    const head_len = 1 << 14;
    if (scratch.len < head_len * 2 + input.len * 2) return error.CapacityException;
    const head: []u16 = @alignCast(std.mem.bytesAsSlice(u16, scratch[0 .. head_len * 2]));
    const chain_bytes = head_len * 2;
    const chain: []u16 = @alignCast(std.mem.bytesAsSlice(u16, scratch[chain_bytes .. chain_bytes + input.len * 2]));
    const items_bytes = (chain_bytes + input.len * 2 + 7) & ~@as(usize, 7);
    if (scratch.len < items_bytes + (input.len + 1) * @sizeOf(Item)) return error.CapacityException;
    const items: []Item = @alignCast(std.mem.bytesAsSlice(Item, scratch[items_bytes .. items_bytes + (input.len + 1) * @sizeOf(Item)]));

    var freqs: [num_symbols]u32 = @splat(0);
    const count = parse(input, items, head, chain, &freqs);

    freqs[end_of_data] += 1;
    var lens: [num_symbols]u8 = undefined;
    var codewords: [num_symbols]u32 = undefined;
    makeCanonicalCode(num_symbols, max_codeword_len, &freqs, &lens, &codewords);

    for (0..num_symbols / 2) |i| {
        output[i] = (lens[2 * i + 1] << 4) | lens[2 * i];
    }
    var os = OutBits{ .data = output[num_symbols / 2 ..] };
    for (items[0..count]) |item| writeItem(&os, item, &codewords, &lens);
    os.writeBits(codewords[end_of_data], @intCast(lens[end_of_data]));
    const stream_len = try os.flush();
    return num_symbols / 2 + stream_len;
}

pub fn xpressDecode(input: []const u8, output: []u8) Exception!void {
    if (input.len < num_symbols / 2) return error.DataException;
    var lens: [num_symbols]u8 = undefined;
    for (0..num_symbols / 2) |i| {
        lens[2 * i] = input[i] & 0xf;
        lens[2 * i + 1] = input[i] >> 4;
    }
    const code = try Code.init(&lens);

    var stream = bits.Bits{ .data = input[num_symbols / 2 ..] };
    var op: usize = 0;
    while (op < output.len) {
        const sym = try code.read(&stream);
        if (sym < num_chars) {
            output[op] = @intCast(sym);
            op += 1;
            continue;
        }
        var length: u32 = sym & 0xf;
        const log2_offset: u5 = @intCast((sym >> 4) & 0xf);
        stream.ensure(16);
        const offset: u32 = (@as(u32, 1) << log2_offset) | stream.peek(log2_offset);
        stream.pop(log2_offset);
        if (length == 0xf) {
            length += stream.readByte();
            if (length == 0xf + 0xff) {
                length = stream.readU16();
            }
        }
        length += min_match_len;
        const off: usize = @intCast(offset);
        if (off > op or off == 0) return error.DataException;
        if (length > output.len - op) return error.CapacityException;
        var i: usize = 0;
        while (i < length) : (i += 1) {
            output[op + i] = output[op - off + i];
        }
        op += length;
    }
}

test "xpress encode roundtrip" {
    const allocator = std.testing.allocator;
    var rng: u64 = 0x9E3779B97F4A7C15;
    const cases = [_]usize{ 0, 1, 3, 17, 100, 4096, 65536 };
    for (cases) |n| {
        const input = try allocator.alloc(u8, n);
        defer allocator.free(input);
        for (input) |*b| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            b.* = @truncate(rng >> 32);
        }
        if (n > 64) {
            // Stir in repeats so matches exist.
            for (1..n / 64) |i| @memcpy(input[i * 64 ..][0..48], input[0..48]);
        }
        const workspace = try allocator.alignedAlloc(u8, .@"8", encodeWorkspaceSize(n));
        defer allocator.free(workspace);
        const compressed = try allocator.alloc(u8, n + 512);
        defer allocator.free(compressed);
        const written = try xpressEncode(input, compressed, workspace);
        const back = try allocator.alloc(u8, n);
        defer allocator.free(back);
        try xpressDecode(compressed[0..written], back);
        try std.testing.expectEqualSlices(u8, input, back);
    }
}
