const std = @import("std");

const failure_prim = @import("../../common/primitive/failure.zig");

const Failure = failure_prim.Failure;

// WIM XPRESS resource codec, ported from wimlib's decompressor
// (src/xpress_decompress.c). A 256-byte nibble header carries canonical
// Huffman lengths for 512 symbols. Symbols 0..255 are literals; 256..511
// are matches: low nibble length code, high nibble offset bucket log2.
// The bit stream mirrors wimlib's input_bitstream: LE16 words, high byte
// first, MSB first. Extra length bytes after a 0xff marker come from the
// raw byte cursor with no realignment. Overrun reads yield zeroes.

const num_symbols: usize = 512;
const num_chars: usize = 256;
const max_codeword_len: usize = 15;
const min_match_len: usize = 3;

const Bits = struct {
    data: []const u8,
    bitbuf: u32 = 0,
    bitsleft: u6 = 0,
    next: usize = 0,

    fn ensure(b: *Bits, num_bits: u6) void {
        if (b.bitsleft >= num_bits) return;
        if (b.data.len - b.next < 2) {
            b.bitsleft = 32;
            return;
        }
        const word: u32 = b.data[b.next] | (@as(u32, b.data[b.next + 1]) << 8);
        b.bitbuf |= word << @intCast(16 - b.bitsleft);
        b.next += 2;
        b.bitsleft += 16;
    }

    fn peek(b: *Bits, width: u5) u32 {
        return if (width == 0) 0 else b.bitbuf >> @intCast(@as(u6, 32) - width);
    }

    fn pop(b: *Bits, width: u5) void {
        b.bitbuf <<= width;
        b.bitsleft -= width;
    }

    fn readBits(b: *Bits, width: u5) u32 {
        b.ensure(width);
        const v = b.peek(width);
        b.pop(width);
        return v;
    }

    // Interleaved length bytes read at the raw cursor, not the bit buffer.
    fn readByte(b: *Bits) u32 {
        if (b.next == b.data.len) return 0;
        defer b.next += 1;
        return b.data[b.next];
    }

    fn readU16(b: *Bits) u32 {
        if (b.data.len - b.next < 2) return 0;
        defer b.next += 2;
        return b.data[b.next] | (@as(u32, b.data[b.next + 1]) << 8);
    }
};

pub fn xpressDecode(input: []const u8, output: []u8) Failure!void {
    if (input.len < num_symbols / 2) return error.DataFailure;
    var lens: [num_symbols]u8 = undefined;
    for (0..num_symbols / 2) |i| {
        lens[2 * i] = input[i] & 0xf;
        lens[2 * i + 1] = input[i] >> 4;
    }

    // Canonical codes: per-length counts, first codes, and symbols sorted by
    // (length, symbol). Codewords accumulate most-significant bit first.
    var counts: [max_codeword_len + 1]u16 = @splat(0);
    for (lens) |l| {
        if (l > max_codeword_len) return error.DataFailure;
        counts[l] += 1;
    }
    counts[0] = 0;
    var first_code: [max_codeword_len + 1]u32 = @splat(0);
    var base: [max_codeword_len + 1]u16 = @splat(0);
    var code: u32 = 0;
    var idx: u16 = 0;
    for (1..max_codeword_len + 1) |l| {
        first_code[l] = code;
        base[l] = idx;
        code = (code + counts[l]) << 1;
        idx += counts[l];
    }
    if (counts[0] == num_symbols) return error.DataFailure;

    var sorted: [num_symbols]u16 = undefined;
    var cursor: [max_codeword_len + 1]u16 = base;
    for (lens, 0..) |l, sym| {
        if (l != 0) {
            sorted[cursor[l]] = @intCast(sym);
            cursor[l] += 1;
        }
    }

    var bits = Bits{ .data = input[num_symbols / 2 ..] };
    var op: usize = 0;
    while (op < output.len) {
        var c: u32 = 0;
        var len: usize = 0;
        var sym: u16 = 0;
        while (true) {
            len += 1;
            if (len > max_codeword_len) return error.DataFailure;
            bits.ensure(1);
            c = (c << 1) | bits.peek(1);
            bits.pop(1);
            const count = counts[len];
            if (c >= first_code[len] and c - first_code[len] < count) {
                sym = sorted[base[len] + @as(u16, @intCast(c - first_code[len]))];
                break;
            }
        }
        if (sym < num_chars) {
            output[op] = @intCast(sym);
            op += 1;
            continue;
        }
        var length: u32 = sym & 0xf;
        const log2_offset: u5 = @intCast((sym >> 4) & 0xf);
        bits.ensure(16);
        const offset: u32 = (@as(u32, 1) << log2_offset) | bits.peek(log2_offset);
        bits.pop(log2_offset);
        if (length == 0xf) {
            length += bits.readByte();
            if (length == 0xf + 0xff) {
                length = bits.readU16();
            }
        }
        length += min_match_len;
        const off: usize = @intCast(offset);
        if (off > op or off == 0) return error.DataFailure;
        if (length > output.len - op) return error.CapacityFailure;
        var i: usize = 0;
        while (i < length) : (i += 1) {
            output[op + i] = output[op - off + i];
        }
        op += length;
    }
}
