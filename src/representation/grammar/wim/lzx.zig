const std = @import("std");

const exception_prim = @import("../../../common/primitive/exception.zig");
const bits = @import("bits.zig");

const Exception = exception_prim.Exception;

// WIM LZX codec, ported from wimlib src/lzx_decompress.c.
// Blocks carry precode-encoded lens for the main and length codes.
//
// Three recent offsets and delta-coded lens persist across blocks.
// Decoded data passes through the E8 CALL-target filter.

const num_chars: usize = 256;
const min_match_len: usize = 2;
const num_primary_lens: usize = 7;
const num_len_headers: usize = num_primary_lens + 1;
const num_len_syms: usize = 257 - min_match_len + 1 - num_primary_lens;
const max_offset_slots: usize = 50;
const num_recent_offsets: usize = 3;
const precode_num_symbols: usize = 20;
const precode_element_size: u5 = 4;
const aligned_num_symbols: usize = 8;
const aligned_element_size: u5 = 3;
const aligned_offset_bits: u5 = 3;
const min_aligned_offset_slot: usize = 8;
const max_main_codeword_len: usize = 16;
const max_len_codeword_len: usize = 16;
const max_pre_codeword_len: usize = 15;
const max_aligned_codeword_len: usize = 7;
const default_block_size: usize = 32768;
const magic_file_size: i32 = 12000000;
const max_main_num_symbols: usize = num_chars + max_offset_slots * num_len_headers;
// Length RLE runs may overshoot the array; wimlib tolerates 50 extra slots.
const len_overrun: usize = 50;

const block_verbatim: u32 = 1;
const block_aligned: u32 = 2;
const block_uncompressed: u32 = 3;

// First match offset of each offset slot; slots 0-2 map to repeat offsets.
const offset_slot_base = [max_offset_slots + 1]i32{
    -2,      -1,      0,       1,       2,
    4,       6,       10,      14,      22,
    30,      46,      62,      94,      126,
    190,     254,     382,     510,     766,
    1022,    1534,    2046,    3070,    4094,
    6142,    8190,    12286,   16382,   24574,
    32766,   49150,   65534,   98302,   131070,
    196606,  262142,  393214,  524286,  655358,
    786430,  917502,  1048574, 1179646, 1310718,
    1441790, 1572862, 1703934, 1835006, 1966078,
    2097150,
};

const extra_offset_bits = [max_offset_slots]u8{
    0,  0,  0,  0,  1,
    1,  2,  2,  3,  3,
    4,  4,  5,  5,  6,
    6,  7,  7,  8,  8,
    9,  9,  10, 10, 11,
    11, 12, 12, 13, 13,
    14, 14, 15, 15, 16,
    16, 17, 17, 17, 17,
    17, 17, 17, 17, 17,
    17, 17, 17, 17, 17,
};

const MainCode = bits.Code(max_main_codeword_len, max_main_num_symbols + len_overrun);
const LenCode = bits.Code(max_len_codeword_len, num_len_syms + len_overrun);
const PreCode = bits.Code(max_pre_codeword_len, precode_num_symbols);
const AlignedCode = bits.Code(max_aligned_codeword_len, aligned_num_symbols);

// In wimlib the window order derives from max_block_size (the WIM chunk
// size), never the actual uncompressed output length.
fn windowOrder(chunk_size: usize) Exception!u5 {
    if (chunk_size == 0 or chunk_size > (1 << 21)) return error.DataException;
    var order: u5 = 15;
    while (@as(usize, 1) << order < chunk_size) order += 1;
    return order;
}

fn numMainSymbols(order: u5) usize {
    const max_offset: i64 = (@as(i64, 1) << order) - min_match_len - 1;
    var slot: usize = 30;
    while (max_offset >= offset_slot_base[slot]) slot += 1;
    return num_chars + slot * num_len_headers;
}

fn deltaLen(prev: u8, presym: u16) u8 {
    var len: i16 = @as(i16, prev) - @as(i16, @intCast(presym));
    if (len < 0) len += 17;
    return @intCast(len);
}

// The precode arrives as 20 explicit 4-bit lengths; runs may write
// len_overrun slots past num_lens.
fn readCodewordLens(stream: *bits.Bits, lens: []u8, num_lens: usize, pre_lens: *[precode_num_symbols]u8) Exception!void {
    for (0..precode_num_symbols) |i| {
        pre_lens[i] = @intCast(stream.readBits(precode_element_size));
    }

    const pre = try PreCode.init(pre_lens);
    var pos: usize = 0;
    while (pos < num_lens) {
        const presym = try pre.read(stream);
        if (presym < 17) {
            lens[pos] = deltaLen(lens[pos], presym);
            pos += 1;
            continue;
        }
        var run_len: usize = undefined;
        var len: u8 = undefined;
        if (presym == 17) {
            run_len = 4 + stream.readBits(4);
            len = 0;
        } else if (presym == 18) {
            run_len = 20 + stream.readBits(5);
            len = 0;
        } else {
            run_len = 4 + stream.readBits(1);
            const next = try pre.read(stream);
            if (next > 17) return error.DataException;
            len = deltaLen(lens[pos], next);
        }
        for (0..run_len) |i| {
            lens[pos + i] = len;
        }
        pos += run_len;
    }
}

// E8 translation is undone because wimlib applies it unconditionally on encode.
fn e8Postprocess(data: []u8) void {
    if (data.len <= 10) return;
    const tail = data.len - 6;
    var p: usize = 0;
    while (p < tail) : (p += 1) {
        if (data[p] != 0xE8) continue;
        const abs = std.mem.readInt(i32, data[p + 1 ..][0..4], .little);
        if (abs >= 0) {
            if (abs < magic_file_size) {
                std.mem.writeInt(i32, data[p + 1 ..][0..4], abs - @as(i32, @intCast(p)), .little);
            }
        } else {
            if (abs >= -@as(i32, @intCast(p))) {
                std.mem.writeInt(i32, data[p + 1 ..][0..4], abs + magic_file_size, .little);
            }
        }
        p += 4;
    }
}

pub fn lzxDecode(chunk_size: usize, input: []const u8, output: []u8) Exception!void {
    const order = try windowOrder(chunk_size);
    const num_main_syms = numMainSymbols(order);
    var main_lens: [max_main_num_symbols + len_overrun]u8 = @splat(0);
    var len_lens: [num_len_syms + len_overrun]u8 = @splat(0);
    var aligned_lens: [aligned_num_symbols]u8 = @splat(0);
    var pre_lens: [precode_num_symbols]u8 = @splat(0);
    var recent: [num_recent_offsets]u32 = .{ 1, 1, 1 };
    var may_have_e8_byte = false;
    var stream = bits.Bits{ .data = input };
    var op: usize = 0;

    while (op < output.len) {
        stream.ensure(4);
        const block_type = stream.peek(3);
        stream.pop(3);
        var block_size: usize = undefined;
        if (stream.peek(1) != 0) {
            stream.pop(1);
            block_size = default_block_size;
        } else {
            stream.pop(1);
            block_size = stream.readBits(16);
            if (order >= 16) {
                block_size = (block_size << 8) | stream.readBits(8);
            }
        }
        if (block_size < 1 or block_size > output.len - op) return error.DataException;

        switch (block_type) {
            block_uncompressed => {
                stream.ensure(1);
                stream.dropToCursor();
                recent[0] = stream.readU32();
                recent[1] = stream.readU32();
                recent[2] = stream.readU32();
                if (recent[0] == 0 or recent[1] == 0 or recent[2] == 0) return error.DataException;
                try stream.readBytes(output[op..][0..block_size]);
                if (block_size & 1 != 0) _ = stream.readByte();
                may_have_e8_byte = true;
            },
            block_verbatim, block_aligned => {
                var extra_bits: [max_offset_slots]u8 = extra_offset_bits;
                var min_slot: usize = max_offset_slots;
                if (block_type == block_aligned) {
                    for (0..aligned_num_symbols) |i| {
                        aligned_lens[i] = @intCast(stream.readBits(aligned_element_size));
                    }
                    min_slot = min_aligned_offset_slot;
                    for (min_slot..max_offset_slots) |slot| {
                        extra_bits[slot] -= aligned_offset_bits;
                    }
                }
                try readCodewordLens(&stream, &main_lens, num_chars, &pre_lens);
                try readCodewordLens(&stream, main_lens[num_chars..], num_main_syms - num_chars, &pre_lens);
                try readCodewordLens(&stream, &len_lens, num_len_syms, &pre_lens);
                const main = try MainCode.init(main_lens[0..num_main_syms]);
                const len_code = try LenCode.init(len_lens[0..num_len_syms]);
                const aligned = try AlignedCode.init(&aligned_lens);
                may_have_e8_byte = may_have_e8_byte or main_lens[0xE8] != 0;

                const block_end = op + block_size;
                while (op < block_end) {
                    const mainsym = try main.read(&stream);
                    if (mainsym < num_chars) {
                        output[op] = @intCast(mainsym);
                        op += 1;
                        continue;
                    }
                    var length: u32 = @as(u32, mainsym) % @as(u32, num_len_headers);
                    const offset_slot: usize = (@as(usize, mainsym) - num_chars) / num_len_headers;
                    if (length == num_primary_lens) {
                        length += try len_code.read(&stream);
                    }
                    length += min_match_len;
                    var offset: u32 = undefined;
                    if (offset_slot < num_recent_offsets) {
                        offset = recent[offset_slot];
                        recent[offset_slot] = recent[0];
                    } else {
                        const extra = extra_bits[offset_slot];
                        offset = stream.readBits(@intCast(extra));
                        if (offset_slot >= min_slot) {
                            offset = (offset << aligned_offset_bits) | try aligned.read(&stream);
                        }
                        offset = @as(u32, @intCast(offset_slot_base[offset_slot] +
                            @as(i32, @intCast(offset))));
                        recent[2] = recent[1];
                        recent[1] = recent[0];
                    }
                    recent[0] = offset;
                    const off: usize = @intCast(offset);
                    if (off > op or off == 0) return error.DataException;
                    if (length > block_end - op) return error.DataException;
                    var i: usize = 0;
                    while (i < length) : (i += 1) {
                        output[op + i] = output[op - off + i];
                    }
                    op += length;
                }
            },
            else => return error.DataException,
        }
    }
    if (may_have_e8_byte) e8Postprocess(output);
}

// Encoder: verbatim blocks only; the format makes aligned-offset blocks optional.

const enc_min_match: usize = 2;
const enc_max_match: usize = 257;
const block_default: usize = 32768;
const enc_main_max_len: usize = 16;
const enc_len_max_len: usize = 16;

const EncItem = union(enum) {
    literal: u8,
    match: struct { len: u32, offset: u32 },
};

pub fn encodeWorkspaceSize(chunk_size: usize) usize {
    const aligned = (chunk_size + 7) & ~@as(usize, 7);
    const block: usize = @min(chunk_size, block_default);
    return aligned + (1 << 16) * 4 + chunk_size * 4 + (block + 1) * @sizeOf(EncItem) + 8192;
}

// Forward E8 translation (wimlib do_translate_target): turns relative CALL
// targets into absolute ones; the decoder's e8Postprocess inverts this.
fn e8Forward(data: []u8) void {
    if (data.len <= 10) return;
    const tail = data.len - 6;
    var p: usize = 0;
    while (p < tail) : (p += 1) {
        if (data[p] != 0xE8) continue;
        const i: i32 = @intCast(p);
        const rel = std.mem.readInt(i32, data[p + 1 ..][0..4], .little);
        if (rel >= -i and rel < magic_file_size) {
            const abs: i32 = if (rel < magic_file_size - i) rel + i else rel - magic_file_size;
            std.mem.writeInt(i32, data[p + 1 ..][0..4], abs, .little);
        }
        p += 4;
    }
}

const EncOut = struct {
    data: []u8,
    buf: u64 = 0,
    count: u6 = 0,
    next: usize = 0,
    overflow: bool = false,

    fn write(self: *EncOut, value: u64, num_bits: u6) void {
        self.count += num_bits;
        self.buf = (self.buf << num_bits) | value;
        while (self.count >= 16) {
            self.count -= 16;
            if (self.next + 2 <= self.data.len) {
                std.mem.writeInt(u16, self.data[self.next..][0..2], @truncate(self.buf >> @intCast(self.count)), .little);
                self.next += 2;
            } else {
                self.overflow = true;
            }
        }
    }

    fn finish(self: *EncOut) Exception!usize {
        if (self.overflow) return error.CapacityException;
        if (self.count != 0) {
            if (self.next + 2 > self.data.len) return error.CapacityException;
            std.mem.writeInt(u16, self.data[self.next..][0..2], @truncate(self.buf << @intCast(16 - self.count)), .little);
            self.next += 2;
        }
        return self.next;
    }
};

const EncFinder = struct {
    data: []const u8,
    head: []u32,
    chain: []u32,
    window_mask: usize,
    max_offset: usize,
    inserted: usize = 0,

    fn hash(self: *const EncFinder, pos: usize) usize {
        const v = std.mem.readInt(u32, self.data[pos..][0..4], .little);
        return (v *% 2654435761) >> 16;
    }

    fn insertOne(self: *EncFinder, pos: usize) void {
        if (pos + 4 > self.data.len) return;
        const h = self.hash(pos);
        self.chain[pos & self.window_mask] = self.head[h];
        self.head[h] = @intCast(pos);
    }

    fn prepare(self: *EncFinder, pos: usize) void {
        while (self.inserted < pos) : (self.inserted += 1) {
            self.insertOne(self.inserted);
        }
    }

    fn find(self: *EncFinder, pos: usize, max_len: usize) ?EncItem {
        if (pos + 4 > self.data.len or max_len < enc_min_match) return null;
        self.prepare(pos);
        var best_len: usize = enc_min_match - 1;
        var best_offset: usize = 0;
        var candidate: u32 = self.head[self.hash(pos)];
        var depth: usize = 32;
        while (candidate != 0xFFFFFFFF and depth != 0) : (depth -= 1) {
            const cand: usize = candidate;
            if (cand >= pos) break;
            const offset = pos - cand;
            if (offset > self.max_offset) break;
            if (self.data[cand + best_len] == self.data[pos + best_len]) {
                var l: usize = 0;
                while (l < max_len and self.data[cand + l] == self.data[pos + l]) l += 1;
                if (l > best_len) {
                    best_len = l;
                    best_offset = offset;
                    if (l >= 64 or l == max_len) break;
                }
            }
            candidate = self.chain[cand & self.window_mask];
        }
        if (best_offset == 0) return null;
        return EncItem{ .match = .{ .len = @intCast(best_len), .offset = @intCast(best_offset) } };
    }
};

// Length-limited canonical Huffman code; identical construction to the
// decoder-side requirement (leaf-first on ties).
fn makeEncCode(num_syms: usize, max_len: usize, freqs: []const u32, lens: []u8, codes: []u32) void {
    const num_symbol_bits: u5 = 10;
    const symbol_mask: u32 = (1 << num_symbol_bits) - 1;
    const freq_mask: u32 = ~symbol_mask;
    var used: usize = 0;
    for (freqs, 0..) |f, sym| {
        if (f != 0) {
            codes[used] = @as(u32, @intCast(sym)) | (f << num_symbol_bits);
            used += 1;
        } else {
            lens[sym] = 0;
        }
    }
    if (used == 0) return;
    if (used == 1) {
        const sym: usize = @intCast(codes[0] & symbol_mask);
        const other: usize = if (sym != 0) sym else 1;
        lens[0] = 1;
        lens[other] = 1;
        codes[0] = 0;
        codes[other] = 1;
        return;
    }
    std.sort.pdq(u32, codes[0..used], {}, struct {
        fn lessThan(_: void, a: u32, b: u32) bool {
            return a < b;
        }
    }.lessThan);
    var i: usize = 0;
    var b: usize = 0;
    var e: usize = 0;
    const last_idx: usize = used - 1;
    while (true) {
        var new_freq: u32 = undefined;
        if (i + 1 <= last_idx and
            (b == e or (codes[i + 1] & freq_mask) <= (codes[b] & freq_mask)))
        {
            new_freq = (codes[i] & freq_mask) + (codes[i + 1] & freq_mask);
            i += 2;
        } else if (b + 2 <= e and
            (i > last_idx or (codes[b + 1] & freq_mask) < (codes[i] & freq_mask)))
        {
            new_freq = (codes[b] & freq_mask) + (codes[b + 1] & freq_mask);
            codes[b] = (@as(u32, @intCast(e)) << num_symbol_bits) | (codes[b] & symbol_mask);
            codes[b + 1] = (@as(u32, @intCast(e)) << num_symbol_bits) | (codes[b + 1] & symbol_mask);
            b += 2;
        } else {
            new_freq = (codes[i] & freq_mask) + (codes[b] & freq_mask);
            codes[b] = (@as(u32, @intCast(e)) << num_symbol_bits) | (codes[b] & symbol_mask);
            i += 1;
            b += 1;
        }
        codes[e] = new_freq | (codes[e] & symbol_mask);
        e += 1;
        if (e >= last_idx) break;
    }
    var len_counts: [17]u32 = @splat(0);
    const root_idx: usize = used - 2;
    len_counts[1] = 2;
    codes[root_idx] &= symbol_mask;
    var node: i64 = @as(i64, @intCast(root_idx)) - 1;
    while (node >= 0) : (node -= 1) {
        const n: usize = @intCast(node);
        const parent: usize = @intCast(codes[n] >> num_symbol_bits);
        const depth: u32 = (codes[parent] >> num_symbol_bits) + 1;
        var len: u32 = depth;
        codes[n] = (codes[n] & symbol_mask) | (depth << num_symbol_bits);
        if (len >= @as(u32, @intCast(max_len))) {
            len = @intCast(max_len);
            len -= 1;
            while (len_counts[len] == 0) len -= 1;
        }
        len_counts[len] -= 1;
        len_counts[len + 1] += 2;
    }
    var idx: usize = 0;
    var len: usize = max_len;
    while (len >= 1) : (len -= 1) {
        var count = len_counts[len];
        while (count != 0) : (count -= 1) {
            lens[@intCast(codes[idx] & symbol_mask)] = @intCast(len);
            idx += 1;
        }
    }
    bits.canonicalCodewords(max_len, num_syms, lens, codes);
}

// The decoder deltas against the previous block's lens, so `prev`
// updates in place.
fn writeLensSection(out: *EncOut, lens: []const u8, prev: []u8) void {
    var pre_freqs: [precode_num_symbols]u32 = @splat(0);
    var pre_lens: [precode_num_symbols]u8 = @splat(0);
    var pre_codes: [precode_num_symbols]u32 = @splat(0);

    var pos: usize = 0;
    while (pos < lens.len) {
        const target = lens[pos];
        if (target == prev[pos]) {
            var run: usize = 1;
            while (pos + run < lens.len and lens[pos + run] == target) run += 1;
            if (target == 0) {
                var left = run;
                while (left >= 20) {
                    pre_freqs[18] += 1;
                    left -= @min(left, 51);
                }
                while (left >= 4) {
                    pre_freqs[17] += 1;
                    left -= @min(left, 19);
                }
                while (left > 0) : (left -= 1) pre_freqs[0] += 1;
            } else if (run >= 4) {
                var take: usize = 1;
                while (pos + take < lens.len and lens[pos + take] == target and take < 5) take += 1;
                if (take >= 4) {
                    pre_freqs[19] += 1;
                    pre_freqs[0] += 1;
                    pos += take;
                    continue;
                } else {
                    pre_freqs[deltaLen(prev[pos], target)] += 1;
                }
            } else {
                pre_freqs[deltaLen(prev[pos], target)] += 1;
            }
            pos += if (target == 0) run else 1;
            continue;
        }
        pre_freqs[deltaLen(prev[pos], target)] += 1;
        pos += 1;
    }

    makeEncCode(precode_num_symbols, max_pre_codeword_len, &pre_freqs, &pre_lens, &pre_codes);
    for (0..precode_num_symbols) |i| out.write(pre_lens[i], precode_element_size);

    pos = 0;
    while (pos < lens.len) {
        const target = lens[pos];
        if (target == prev[pos]) {
            var run: usize = 1;
            while (pos + run < lens.len and lens[pos + run] == target) run += 1;
            if (target == 0) {
                var left = run;
                while (left >= 20) {
                    const take = @min(left, 51);
                    out.write(pre_codes[18], @intCast(pre_lens[18]));
                    out.write(take - 20, 5);
                    left -= take;
                }
                while (left >= 4) {
                    const take = @min(left, 19);
                    out.write(pre_codes[17], @intCast(pre_lens[17]));
                    out.write(take - 4, 4);
                    left -= take;
                }
                while (left > 0) : (left -= 1) {
                    out.write(pre_codes[0], @intCast(pre_lens[0]));
                }
                for (pos..pos + run) |q| prev[q] = 0;
                pos += run;
                continue;
            }
            var take: usize = 1;
            while (pos + take < lens.len and lens[pos + take] == target and take < 5) take += 1;
            if (run >= 4 and take >= 4) {
                out.write(pre_codes[19], @intCast(pre_lens[19]));
                out.write(take - 4, 1);
                out.write(pre_codes[0], @intCast(pre_lens[0]));
                for (pos..pos + take) |q| prev[q] = target;
                pos += take;
                continue;
            }
            const d = deltaLen(prev[pos], target);
            out.write(pre_codes[d], @intCast(pre_lens[d]));
            prev[pos] = target;
            pos += 1;
            continue;
        }
        const d = deltaLen(prev[pos], target);
        out.write(pre_codes[d], @intCast(pre_lens[d]));
        prev[pos] = target;
        pos += 1;
    }
}

const Mapped = struct { mainsym: usize, len_sym: ?usize, slot: usize };

fn mapItem(item: EncItem, recent: *[num_recent_offsets]u32, max_slot: usize) Mapped {
    switch (item) {
        .literal => |byte| return .{ .mainsym = byte, .len_sym = null, .slot = 0 },
        .match => |m| {
            const length = m.len - enc_min_match;
            const primary: u32 = @min(length, num_primary_lens);
            var slot: usize = undefined;
            if (m.offset == recent[0]) {
                slot = 0;
            } else if (m.offset == recent[1]) {
                slot = 1;
            } else if (m.offset == recent[2]) {
                slot = 2;
            } else {
                // Largest slot whose base does not exceed the offset;
                // base[num_slots] is the first base beyond the window.
                var s: usize = 4;
                while (s <= max_slot and @as(i64, @intCast(m.offset)) >= offset_slot_base[s]) s += 1;
                slot = s - 1;
            }
            var len_sym: ?usize = null;
            if (primary == num_primary_lens) len_sym = @intCast(length - num_primary_lens);
            if (slot < num_recent_offsets) {
                if (slot != 0) {
                    const t = recent[slot];
                    recent[slot] = recent[0];
                    recent[0] = t;
                }
            } else {
                recent[2] = recent[1];
                recent[1] = recent[0];
                recent[0] = m.offset;
            }
            return .{ .mainsym = num_chars + slot * num_len_headers + primary, .len_sym = len_sym, .slot = slot };
        },
    }
}

pub fn lzxEncode(chunk_size: usize, input: []const u8, output: []u8, scratch: []u8) Exception!usize {
    if (chunk_size == 0 or (chunk_size & (chunk_size - 1)) != 0 or chunk_size > (1 << 21)) return error.CallException;
    if (input.len > chunk_size) return error.CallException;
    const order = try windowOrder(chunk_size);
    const num_main = numMainSymbols(order);
    const num_slots = (num_main - num_chars) / num_len_headers;
    // Offsets at or beyond base[num_slots] have no representable slot.
    const max_offset: usize = @intCast(offset_slot_base[num_slots] - 1);
    if (output.len < 32) return error.CapacityException;
    const aligned = (input.len + 7) & ~@as(usize, 7);
    const chain_base = aligned + (1 << 16) * 4;
    const items_base = (chain_base + chunk_size * 4 + 7) & ~@as(usize, 7);
    const max_items: usize = @min(chunk_size, block_default) + 1;
    if (scratch.len < items_base + max_items * @sizeOf(EncItem)) return error.CapacityException;

    const filtered = scratch[0..input.len];
    @memcpy(filtered, input);
    e8Forward(filtered);
    const head: []u32 = @alignCast(std.mem.bytesAsSlice(u32, scratch[aligned .. aligned + (1 << 16) * 4]));
    const chain: []u32 = @alignCast(std.mem.bytesAsSlice(u32, scratch[chain_base .. chain_base + chunk_size * 4]));
    const items: []EncItem = @alignCast(std.mem.bytesAsSlice(EncItem, scratch[items_base .. items_base + max_items * @sizeOf(EncItem)]));
    @memset(head, 0xFFFFFFFF);

    var finder = EncFinder{
        .data = filtered,
        .head = head,
        .chain = chain,
        .window_mask = chunk_size - 1,
        .max_offset = max_offset,
    };

    var out = EncOut{ .data = output };
    var main_prev: [num_chars]u8 = @splat(0);
    var main_prev2: [max_main_num_symbols]u8 = @splat(0);
    var len_prev: [num_len_syms]u8 = @splat(0);
    var recent: [num_recent_offsets]u32 = .{ 1, 1, 1 };

    var pos: usize = 0;
    while (pos < filtered.len) {
        const block_size: usize = @min(block_default, filtered.len - pos);
        const block_end = pos + block_size;

        var count: usize = 0;
        var p = pos;
        while (p < block_end) {
            const max_len = @min(block_end - p, enc_max_match);
            const here = finder.find(p, max_len);
            if (here == null) {
                items[count] = .{ .literal = filtered[p] };
                count += 1;
                p += 1;
                continue;
            }
            const m = here.?;
            if (p + 1 < block_end) {
                const next = finder.find(p + 1, @min(block_end - (p + 1), enc_max_match));
                if (next != null and next.?.match.len > m.match.len + 1) {
                    items[count] = .{ .literal = filtered[p] };
                    count += 1;
                    p += 1;
                    continue;
                }
            }
            items[count] = m;
            count += 1;
            p += m.match.len;
        }

        // Dry pass: tally frequencies with a throwaway recent set.
        var main_freqs: [max_main_num_symbols]u32 = @splat(0);
        var len_freqs: [num_len_syms]u32 = @splat(0);
        var tally_recent: [num_recent_offsets]u32 = recent;
        for (items[0..count]) |item| {
            const mapped = mapItem(item, &tally_recent, num_slots);
            main_freqs[mapped.mainsym] += 1;
            if (mapped.len_sym) |ls| len_freqs[ls] += 1;
        }
        var main_lens: [max_main_num_symbols]u8 = undefined;
        var len_lens: [num_len_syms]u8 = undefined;
        var main_codes: [max_main_num_symbols]u32 = undefined;
        var len_codes: [num_len_syms]u32 = undefined;
        makeEncCode(num_main, enc_main_max_len, main_freqs[0..num_main], main_lens[0..num_main], main_codes[0..num_main]);
        makeEncCode(num_len_syms, enc_len_max_len, len_freqs[0..num_len_syms], len_lens[0..num_len_syms], len_codes[0..num_len_syms]);

        out.write(block_verbatim, 3);
        out.write(0, 1);
        if (order >= 16) {
            // 24-bit size, high 16 bits first on the wire.
            out.write(block_size >> 8, 16);
            out.write(block_size & 0xFF, 8);
        } else {
            out.write(block_size, 16);
        }

        writeLensSection(&out, main_lens[0..num_chars], main_prev[0..]);
        writeLensSection(&out, main_lens[num_chars..num_main], main_prev2[num_chars..num_main]);
        writeLensSection(&out, len_lens[0..num_len_syms], len_prev[0..]);

        for (items[0..count]) |item| {
            const mapped = mapItem(item, &recent, num_slots);
            out.write(main_codes[mapped.mainsym], @intCast(main_lens[mapped.mainsym]));
            if (mapped.len_sym) |ls| {
                out.write(len_codes[ls], @intCast(len_lens[ls]));
            }
            switch (item) {
                .match => |m| {
                    if (mapped.slot >= num_recent_offsets) {
                        const extra = extra_offset_bits[mapped.slot];
                        const value: u64 = @intCast(@as(i64, @intCast(m.offset)) - offset_slot_base[mapped.slot]);
                        out.write(value, @intCast(extra));
                    }
                },
                .literal => {},
            }
        }
        pos = block_end;
    }
    return out.finish();
}

test "lzx encode roundtrip" {
    const allocator = std.testing.allocator;
    var rng: u64 = 0xB5297A4D3F84D5B5;
    const cases = [_]usize{ 0, 1, 3, 17, 100, 4096, 32768, 1 << 17 };
    for (cases) |n| {
        const chunk: usize = @max(4096, std.math.ceilPowerOfTwo(usize, @max(n, 1)) catch unreachable);
        const input = try allocator.alloc(u8, n);
        defer allocator.free(input);
        for (input) |*b| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            b.* = @truncate(rng >> 32);
        }
        if (n > 128) {
            for (1..n / 128) |i| @memcpy(input[i * 128 ..][0..96], input[0..96]);
        }
        const workspace = try allocator.alignedAlloc(u8, .@"8", encodeWorkspaceSize(chunk));
        defer allocator.free(workspace);
        const compressed = try allocator.alloc(u8, n + 4096);
        defer allocator.free(compressed);
        const written = try lzxEncode(chunk, input, compressed, workspace);
        const back = try allocator.alloc(u8, n);
        defer allocator.free(back);
        try lzxDecode(chunk, compressed[0..written], back);
        try std.testing.expectEqualSlices(u8, input, back);
    }
}

test "lzx lens section roundtrip" {
    var rng: u64 = 0x12345678;
    const num_len = num_len_syms;
    var enc_lens_len: [num_len]u8 = @splat(0);
    var prev_len: [num_len]u8 = @splat(0);
    var buf: [8192]u8 = undefined;
    for (0..num_len) |i| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        enc_lens_len[i] = if ((rng & 7) == 0) @intCast(rng % 10 + 1) else 0;
    }
    enc_lens_len[0] = 2;
    enc_lens_len[5] = 1;
    var out = EncOut{ .data = &buf };
    writeLensSection(&out, enc_lens_len[0..num_len], prev_len[0..num_len]);
    _ = try out.finish();
    var stream = bits.Bits{ .data = buf[0..] };
    var dec_len: [num_len]u8 = @splat(0);
    var pre_lens: [precode_num_symbols]u8 = @splat(0);
    try readCodewordLens(&stream, &dec_len, num_len, &pre_lens);
    try std.testing.expectEqualSlices(u8, &enc_lens_len, &dec_len);
}
