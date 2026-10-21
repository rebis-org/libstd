const std = @import("std");

const exception_prim = @import("../../../common/primitive/exception.zig");
const bits = @import("bits.zig");

const Exception = exception_prim.Exception;

// WIM LZX codec, ported from wimlib src/lzx_decompress.c.
// Blocks carry precode-encoded lens for the main and length codes.
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

// wimlib derives the window order from the decompressor's max_block_size
// (the WIM chunk size), never from the actual uncompressed output length.
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

// Reads one precode-encoded run of codeword lens; the precode itself is sent
// as 20 explicit 4-bit lengths. Runs may write up to len_overrun slots past
// num_lens, so the backing array must carry that slack, as wimlib's does.
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
