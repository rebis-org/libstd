const failure_prim = @import("../../common/primitive/failure.zig");

const bits = @import("bits.zig");

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

const Code = bits.Code(max_codeword_len, num_symbols);

pub fn xpressDecode(input: []const u8, output: []u8) Failure!void {
    if (input.len < num_symbols / 2) return error.DataFailure;
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
        if (off > op or off == 0) return error.DataFailure;
        if (length > output.len - op) return error.CapacityFailure;
        var i: usize = 0;
        while (i < length) : (i += 1) {
            output[op + i] = output[op - off + i];
        }
        op += length;
    }
}
