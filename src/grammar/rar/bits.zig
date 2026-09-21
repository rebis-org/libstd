const std = @import("std");
const failure = @import("../../common/primitive/failure.zig");
const Failure = failure.Failure;

// RAR packs codes MSB-first within each byte, fixing every table's bit
// order. The reader is hard-bounded by default; v29 opts into zero padding
// because its end-of-block marker peeks 16 bits to reach 1-2 final bits (the
// reference reads an over-allocated buffer the same way).

pub const default_pad_bytes: usize = 32;

pub const BitReader = struct {
    data: []const u8,
    bit_pos: usize,
    buffer: u64,
    bits_in_buffer: u7,
    byte_pos: usize,
    pad_bytes: usize,

    pub fn init(data: []const u8) BitReader {
        return initPadded(data, 0);
    }

    pub fn initPadded(data: []const u8, pad_bytes: usize) BitReader {
        var br = BitReader{
            .data = data,
            .bit_pos = 0,
            .buffer = 0,
            .bits_in_buffer = 0,
            .byte_pos = 0,
            .pad_bytes = pad_bytes,
        };
        br.refill();
        return br;
    }

    inline fn limitBits(self: *const BitReader) usize {
        return (self.data.len + self.pad_bytes) * 8;
    }

    // A stream that ends mid-code can still exit cleanly; this records whether
    // any padding byte was consumed, so callers can distinguish "finished"
    // from "ran out" instead of trusting the exit status.
    pub fn overran(self: *const BitReader) bool {
        return self.bit_pos > self.data.len * 8;
    }

    fn refill(self: *BitReader) void {
        if (self.bits_in_buffer <= 56 and self.byte_pos + 8 <= self.data.len) {
            const raw = std.mem.readInt(u64, self.data[self.byte_pos..][0..8], .big);
            const shift: u6 = @intCast(self.bits_in_buffer);
            self.buffer |= raw >> shift;
            const bytes_consumed: u7 = (64 - self.bits_in_buffer) >> 3;
            self.byte_pos += bytes_consumed;
            self.bits_in_buffer += bytes_consumed * 8;
        } else {
            while (self.bits_in_buffer <= 56 and self.byte_pos < self.data.len) {
                const shift: u6 = @intCast(56 - self.bits_in_buffer);
                self.buffer |= @as(u64, self.data[self.byte_pos]) << shift;
                self.byte_pos += 1;
                self.bits_in_buffer += 8;
            }
        }
    }

    pub fn readBits(self: *BitReader, n: u5) Failure!u32 {
        const count: u7 = n;
        if (count == 0) return 0;
        if (self.bit_pos + @as(usize, count) > self.limitBits()) return error.InvalidData;
        if (count > self.bits_in_buffer) self.refill();
        const shift: u6 = @intCast(64 - count);
        const result: u32 = @intCast(self.buffer >> shift);
        self.buffer <<= @intCast(count);
        // Saturating: inside the padding region the buffer holds fewer real
        // bits than served; the rest are implicit zeros.
        self.bits_in_buffer -= @min(count, self.bits_in_buffer);
        self.bit_pos += count;
        return result;
    }

    pub fn readBit(self: *BitReader) Failure!u1 {
        return @intCast(try self.readBits(1));
    }

    pub fn peekBits(self: *BitReader, n: u5) Failure!u32 {
        const count: u7 = n;
        if (count == 0) return 0;
        if (self.bit_pos + @as(usize, count) > self.limitBits()) return error.InvalidData;
        if (count > self.bits_in_buffer) self.refill();
        const shift: u6 = @intCast(64 - count);
        return @intCast(self.buffer >> shift);
    }

    pub fn skipBits(self: *BitReader, n: usize) void {
        var remaining = n;
        while (remaining > 0) {
            if (self.bits_in_buffer == 0) {
                self.refill();
                if (self.bits_in_buffer == 0) {
                    self.bit_pos += remaining;
                    break;
                }
            }
            const can_skip: u7 = @intCast(@min(remaining, self.bits_in_buffer));
            self.buffer <<= @intCast(can_skip);
            self.bits_in_buffer -= can_skip;
            self.bit_pos += can_skip;
            remaining -= can_skip;
        }
    }

    pub fn bytePosition(self: *const BitReader) usize {
        return self.bit_pos / 8;
    }

    pub fn remainingBits(self: *const BitReader) usize {
        const total = self.data.len * 8;
        return if (self.bit_pos < total) total - self.bit_pos else 0;
    }

    pub fn alignByte(self: *BitReader) void {
        const rem = self.bit_pos % 8;
        if (rem != 0) {
            const skip: u7 = @intCast(8 - rem);
            if (skip <= self.bits_in_buffer) {
                self.buffer <<= @intCast(skip);
                self.bits_in_buffer -= skip;
            } else {
                self.bits_in_buffer = 0;
                self.buffer = 0;
            }
            self.bit_pos += skip;
            self.refill();
        }
    }
};

pub const BitWriter = struct {
    output: []u8,
    buffer: u64,
    bits_in_buffer: u7,
    byte_pos: usize,
    total_bits: usize,

    pub fn init(output: []u8) BitWriter {
        return .{
            .output = output,
            .buffer = 0,
            .bits_in_buffer = 0,
            .byte_pos = 0,
            .total_bits = 0,
        };
    }

    pub fn writeBits(self: *BitWriter, value: u32, n: u5) Failure!void {
        const count: u7 = n;
        if (count == 0) return;
        const mask: u32 = (@as(u32, 1) << n) - 1;
        const masked_value: u64 = value & mask;
        const shift: u6 = @intCast(64 - self.bits_in_buffer - count);
        self.buffer |= masked_value << shift;
        self.bits_in_buffer += count;
        self.total_bits += count;
        try self.flushBytes();
    }

    pub fn writeBit(self: *BitWriter, bit: u1) Failure!void {
        try self.writeBits(bit, 1);
    }

    fn flushBytes(self: *BitWriter) Failure!void {
        if (self.bits_in_buffer >= 8) {
            const bytes_to_flush: u7 = self.bits_in_buffer >> 3;
            if (bytes_to_flush > 0 and self.byte_pos + 8 <= self.output.len) {
                std.mem.writeInt(u64, self.output[self.byte_pos..][0..8], self.buffer, .big);
                self.byte_pos += bytes_to_flush;
                if (bytes_to_flush < 8) {
                    const shift: u6 = @intCast(@as(u7, bytes_to_flush) * 8);
                    self.buffer <<= shift;
                } else {
                    self.buffer = 0;
                }
                self.bits_in_buffer -= @as(u7, bytes_to_flush) * 8;
            } else {
                while (self.bits_in_buffer >= 8) {
                    if (self.byte_pos >= self.output.len) return error.InsufficientCapacity;
                    self.output[self.byte_pos] = @intCast(self.buffer >> 56);
                    self.byte_pos += 1;
                    self.buffer <<= 8;
                    self.bits_in_buffer -= 8;
                }
            }
        }
    }

    pub fn flush(self: *BitWriter) Failure!usize {
        if (self.bits_in_buffer > 0) {
            if (self.byte_pos >= self.output.len) return error.InsufficientCapacity;
            self.output[self.byte_pos] = @intCast(self.buffer >> 56);
            self.byte_pos += 1;
            self.buffer = 0;
            self.bits_in_buffer = 0;
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
    // The real byte, then all 16 padding bits, are readable...
    _ = try padded.readBits(8);
    try std.testing.expect(!padded.overran());
    _ = try padded.readBits(8);
    _ = try padded.readBits(8);
    try std.testing.expect(padded.overran());
    // ...but bounded: slack is not an infinite stream of zeros.
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
    // The flushed buffer is 16 bits; 4 bits of zero padding remain unread.
    try std.testing.expectEqual(@as(usize, 4), br.remainingBits());
}

test "bit writer refuses a full buffer" {
    var buf: [1]u8 = undefined;
    var bw = BitWriter.init(&buf);
    // The first byte flushes; the second trips the capacity check inside the
    // write itself.
    try std.testing.expectError(error.InsufficientCapacity, bw.writeBits(0xFFFF, 16));
}
