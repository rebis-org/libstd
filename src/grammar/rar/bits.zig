const std = @import("std");
const failure = @import("../../common/primitive/failure.zig");
const Failure = failure.Failure;

// RAR packs codes MSB-first within each byte, so every decode table in this
// library reads bits in that order. The reader is hard-bounded by default.
// V29 opts into zero padding because its end-of-block marker peeks 16 bits
// to reach the final 1 to 2 bits; the reference reads an over-allocated
// buffer the same way.

pub const default_pad_bytes: usize = 32;

pub const BitReader = struct {
    bytes: []const u8,
    bit_pos: usize,
    pending_bits: u64,
    pending_bit_count: u7,
    byte_pos: usize,
    pad_bytes: usize,

    pub fn init(bytes: []const u8) BitReader {
        return initPadded(bytes, 0);
    }

    pub fn initPadded(bytes: []const u8, pad_bytes: usize) BitReader {
        var reader = BitReader{
            .bytes = bytes,
            .bit_pos = 0,
            .pending_bits = 0,
            .pending_bit_count = 0,
            .byte_pos = 0,
            .pad_bytes = pad_bytes,
        };
        reader.refill();
        return reader;
    }

    inline fn bitLimit(self: *const BitReader) usize {
        return (self.bytes.len + self.pad_bytes) * 8;
    }

    // A stream that ends mid-code can still exit cleanly. This records whether
    // the reader moved into the padding, so a caller can tell a complete decode
    // from one that ran out instead of trusting the exit status.
    pub fn hasOverrun(self: *const BitReader) bool {
        return self.bit_pos > self.bytes.len * 8;
    }

    fn refill(self: *BitReader) void {
        if (self.pending_bit_count <= 56 and self.byte_pos + 8 <= self.bytes.len) {
            const raw = std.mem.readInt(u64, self.bytes[self.byte_pos..][0..8], .big);
            const shift: u6 = @intCast(self.pending_bit_count);
            self.pending_bits |= raw >> shift;
            const bytes_consumed: u7 = (64 - self.pending_bit_count) >> 3;
            self.byte_pos += bytes_consumed;
            self.pending_bit_count += bytes_consumed * 8;
        } else {
            while (self.pending_bit_count <= 56 and self.byte_pos < self.bytes.len) {
                const shift: u6 = @intCast(56 - self.pending_bit_count);
                self.pending_bits |= @as(u64, self.bytes[self.byte_pos]) << shift;
                self.byte_pos += 1;
                self.pending_bit_count += 8;
            }
        }
    }

    pub fn readBits(self: *BitReader, bit_count: u5) Failure!u32 {
        const count: u7 = bit_count;
        if (count == 0) return 0;
        if (self.bit_pos + @as(usize, count) > self.bitLimit()) return error.InvalidData;
        if (count > self.pending_bit_count) self.refill();
        const shift: u6 = @intCast(64 - count);
        const result: u32 = @intCast(self.pending_bits >> shift);
        self.pending_bits <<= @intCast(count);
        // Saturating: inside the padding region the bit buffer holds fewer bits
        // than the call asks for. The rest are implicit zeros.
        self.pending_bit_count -= @min(count, self.pending_bit_count);
        self.bit_pos += count;
        return result;
    }

    pub fn readBit(self: *BitReader) Failure!u1 {
        return @intCast(try self.readBits(1));
    }

    pub fn peekBits(self: *BitReader, bit_count: u5) Failure!u32 {
        const count: u7 = bit_count;
        if (count == 0) return 0;
        if (self.bit_pos + @as(usize, count) > self.bitLimit()) return error.InvalidData;
        if (count > self.pending_bit_count) self.refill();
        const shift: u6 = @intCast(64 - count);
        return @intCast(self.pending_bits >> shift);
    }

    pub fn skipBits(self: *BitReader, bit_count: usize) void {
        var remaining = bit_count;
        while (remaining > 0) {
            if (self.pending_bit_count == 0) {
                self.refill();
                if (self.pending_bit_count == 0) {
                    self.bit_pos += remaining;
                    break;
                }
            }
            const can_skip: u7 = @intCast(@min(remaining, self.pending_bit_count));
            self.pending_bits <<= @intCast(can_skip);
            self.pending_bit_count -= can_skip;
            self.bit_pos += can_skip;
            remaining -= can_skip;
        }
    }

    pub fn bytePosition(self: *const BitReader) usize {
        return self.bit_pos / 8;
    }

    pub fn remainingBits(self: *const BitReader) usize {
        const total_bits = self.bytes.len * 8;
        return if (self.bit_pos < total_bits) total_bits - self.bit_pos else 0;
    }

    pub fn alignByte(self: *BitReader) void {
        const bit_offset = self.bit_pos % 8;
        if (bit_offset != 0) {
            const skip: u7 = @intCast(8 - bit_offset);
            if (skip <= self.pending_bit_count) {
                self.pending_bits <<= @intCast(skip);
                self.pending_bit_count -= skip;
            } else {
                self.pending_bit_count = 0;
                self.pending_bits = 0;
            }
            self.bit_pos += skip;
            self.refill();
        }
    }
};

pub const BitWriter = struct {
    output: []u8,
    pending_bits: u64,
    pending_bit_count: u7,
    byte_pos: usize,
    total_bits: usize,

    pub fn init(output: []u8) BitWriter {
        return .{
            .output = output,
            .pending_bits = 0,
            .pending_bit_count = 0,
            .byte_pos = 0,
            .total_bits = 0,
        };
    }

    pub fn writeBits(self: *BitWriter, bit_value: u32, bit_count: u5) Failure!void {
        const count: u7 = bit_count;
        if (count == 0) return;
        const value_mask: u32 = (@as(u32, 1) << bit_count) - 1;
        const masked_value: u64 = bit_value & value_mask;
        const shift: u6 = @intCast(64 - self.pending_bit_count - count);
        self.pending_bits |= masked_value << shift;
        self.pending_bit_count += count;
        self.total_bits += count;
        try self.flushBytes();
    }

    pub fn writeBit(self: *BitWriter, bit: u1) Failure!void {
        try self.writeBits(bit, 1);
    }

    fn flushBytes(self: *BitWriter) Failure!void {
        if (self.pending_bit_count >= 8) {
            const bytes_to_flush: u7 = self.pending_bit_count >> 3;
            if (bytes_to_flush > 0 and self.byte_pos + 8 <= self.output.len) {
                std.mem.writeInt(u64, self.output[self.byte_pos..][0..8], self.pending_bits, .big);
                self.byte_pos += bytes_to_flush;
                if (bytes_to_flush < 8) {
                    const shift: u6 = @intCast(@as(u7, bytes_to_flush) * 8);
                    self.pending_bits <<= shift;
                } else {
                    self.pending_bits = 0;
                }
                self.pending_bit_count -= @as(u7, bytes_to_flush) * 8;
            } else {
                while (self.pending_bit_count >= 8) {
                    if (self.byte_pos >= self.output.len) return error.InsufficientCapacity;
                    self.output[self.byte_pos] = @intCast(self.pending_bits >> 56);
                    self.byte_pos += 1;
                    self.pending_bits <<= 8;
                    self.pending_bit_count -= 8;
                }
            }
        }
    }

    pub fn flush(self: *BitWriter) Failure!usize {
        if (self.pending_bit_count > 0) {
            if (self.byte_pos >= self.output.len) return error.InsufficientCapacity;
            self.output[self.byte_pos] = @intCast(self.pending_bits >> 56);
            self.byte_pos += 1;
            self.pending_bits = 0;
            self.pending_bit_count = 0;
        }
        return self.byte_pos;
    }

    pub fn totalBits(self: *const BitWriter) usize {
        return self.total_bits;
    }
};

test "bit reader reads bits msb first" {
    const data = [_]u8{ 0xA5, 0x3C };
    var br = BitReader.init(&data);
    try std.testing.expectEqual(@as(u32, 0xA53), try br.readBits(12));
    try std.testing.expectEqual(@as(u32, 0xC), try br.readBits(4));
}

test "bit reader fails past the end unless padded" {
    const data = [_]u8{0xFF};
    var br = BitReader.init(&data);
    _ = try br.readBits(8);
    try std.testing.expectError(error.InvalidData, br.readBit());

    var padded = BitReader.initPadded(&data, 2);
    try std.testing.expectEqual(@as(u32, 0xFF00), try padded.peekBits(16));
    _ = try padded.readBits(8);
    try std.testing.expect(!padded.hasOverrun());
    _ = try padded.readBits(8);
    _ = try padded.readBits(8);
    try std.testing.expect(padded.hasOverrun());
    try std.testing.expectError(error.InvalidData, padded.readBit());
}

test "bit writer round-trips through the reader" {
    var buf: [8]u8 = undefined;
    var bw = BitWriter.init(&buf);
    try bw.writeBits(0b101, 3);
    try bw.writeBits(0x1FF, 9);
    const n = try bw.flush();
    try std.testing.expectEqual(@as(usize, 2), n);
    var br = BitReader.init(buf[0..n]);
    try std.testing.expectEqual(@as(u32, 0b101), try br.readBits(3));
    try std.testing.expectEqual(@as(u32, 0x1FF), try br.readBits(9));
    try std.testing.expectEqual(@as(usize, 4), br.remainingBits());
}

test "bit writer refuses a full buffer" {
    var buf: [1]u8 = undefined;
    var bw = BitWriter.init(&buf);
    // The first byte flushes. The second trips the capacity check inside
    // writeBits, before flush.
    try std.testing.expectError(error.InsufficientCapacity, bw.writeBits(0xFFFF, 16));
}
