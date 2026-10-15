const std = @import("std");

const failure_prim = @import("../../common/primitive/failure.zig");

const Failure = failure_prim.Failure;

// Bit-level port of wimlib's input_bitstream, shared by the WIM codecs.
// Little-endian 16-bit words are drained high byte first, most-significant
// bit first. Interleaved extra bytes read at the raw byte cursor, not the
// bit buffer. Overrun reads yield zeroes, matching wimlib's contract.

pub const Bits = struct {
    data: []const u8,
    bitbuf: u32 = 0,
    bitsleft: u6 = 0,
    next: usize = 0,

    pub fn ensure(b: *Bits, num_bits: u6) void {
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

    pub fn peek(b: *Bits, width: u5) u32 {
        return if (width == 0) 0 else b.bitbuf >> @intCast(@as(u6, 32) - width);
    }

    pub fn pop(b: *Bits, width: u5) void {
        b.bitbuf <<= width;
        b.bitsleft -= width;
    }

    pub fn readBits(b: *Bits, width: u5) u32 {
        b.ensure(width);
        const v = b.peek(width);
        b.pop(width);
        return v;
    }

    // Reads at the raw byte cursor; used where the format interleaves bytes.
    pub fn readByte(b: *Bits) u32 {
        if (b.next == b.data.len) return 0;
        defer b.next += 1;
        return b.data[b.next];
    }

    pub fn readU16(b: *Bits) u32 {
        if (b.data.len - b.next < 2) return 0;
        defer b.next += 2;
        return b.data[b.next] | (@as(u32, b.data[b.next + 1]) << 8);
    }

    pub fn readU32(b: *Bits) u32 {
        if (b.data.len - b.next < 4) return 0;
        const v = std.mem.readInt(u32, b.data[b.next..][0..4], .little);
        b.next += 4;
        return v;
    }

    // Drops buffered bits so reads resume at the raw byte cursor.
    pub fn dropToCursor(b: *Bits) void {
        b.bitsleft = 0;
        b.bitbuf = 0;
    }

    pub fn readBytes(b: *Bits, dst: []u8) Failure!void {
        if (b.data.len - b.next < dst.len) return error.DataFailure;
        @memcpy(dst, b.data[b.next .. b.next + dst.len]);
        b.next += dst.len;
    }
};

// Canonical Huffman code over explicit codeword lengths. Decoding walks the
// code bit by bit; codewords accumulate most-significant bit first.
pub fn Code(comptime max_len: usize, comptime num_symbols: usize) type {
    return struct {
        counts: [max_len + 1]u16,
        first_code: [max_len + 1]u32,
        base: [max_len + 1]u16,
        sorted: [num_symbols]u16,

        const Self = @This();

        pub fn init(lens: []const u8) Failure!Self {
            if (lens.len > num_symbols) return error.DataFailure;
            var self: Self = undefined;
            self.counts = @splat(0);
            for (lens) |l| {
                if (l > max_len) return error.DataFailure;
                self.counts[l] += 1;
            }
            self.counts[0] = 0;
            var code: u32 = 0;
            var idx: u16 = 0;
            for (1..max_len + 1) |l| {
                self.first_code[l] = code;
                self.base[l] = idx;
                code = (code + self.counts[l]) << 1;
                idx += self.counts[l];
            }
            var cursor = self.base;
            for (lens, 0..) |l, sym| {
                if (l != 0) {
                    self.sorted[cursor[l]] = @intCast(sym);
                    cursor[l] += 1;
                }
            }
            return self;
        }

        pub fn read(self: *const Self, bits: *Bits) Failure!u16 {
            var c: u32 = 0;
            var len: usize = 0;
            while (true) {
                len += 1;
                if (len > max_len) return error.DataFailure;
                bits.ensure(1);
                c = (c << 1) | bits.peek(1);
                bits.pop(1);
                const count = self.counts[len];
                if (c >= self.first_code[len] and c - self.first_code[len] < count) {
                    return self.sorted[self.base[len] + @as(u16, @intCast(c - self.first_code[len]))];
                }
            }
        }
    };
}
