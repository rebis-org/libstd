const std = @import("std");
const failure = @import("../../common/primitive/failure.zig");
const Failure = failure.Failure;
const bits = @import("bits.zig");
const BitReader = bits.BitReader;
const checksum = @import("../../common/primitive/checksum.zig");

// RAR3 ships data filters as bytecode programs, but only six are ever
// emitted and modern unrar dispatches them straight to native code — so do
// we, keyed by CRC32 and length. Anything else makes the entry unverifiable,
// never silently unfiltered.

pub const StandardFilter = enum {
    none,
    e8,
    e8e9,
    itanium,
    rgb,
    audio,
    delta,
};

const StdFilterEntry = struct { length: u32, crc: u32, filter: StandardFilter };
const std_filters = [_]StdFilterEntry{
    .{ .length = 53, .crc = 0xad576887, .filter = .e8 },
    .{ .length = 57, .crc = 0x3cd7e57e, .filter = .e8e9 },
    .{ .length = 120, .crc = 0x3769893f, .filter = .itanium },
    .{ .length = 29, .crc = 0x0e06077d, .filter = .delta },
    .{ .length = 149, .crc = 0x1c2c5dc8, .filter = .rgb },
    .{ .length = 216, .crc = 0xbc85e701, .filter = .audio },
};

// Identify a filter program, or .none if it is not one of the six. Both
// length and CRC must match: length alone is not distinguishing, and CRC
// alone would accept a truncated program. Byte 0 is an XOR checksum over
// bytes 1..n; a mismatch means corrupt code and yields .none (the reference
// bails out of Prepare()).
pub fn identifyFilter(code: []const u8) StandardFilter {
    if (code.len == 0) return .none;

    var xor_sum: u8 = 0;
    for (code[1..]) |b| xor_sum ^= b;
    if (xor_sum != code[0]) return .none;

    const code_crc = checksum.crc32(code);
    for (std_filters) |entry| {
        if (entry.crc == code_crc and entry.length == code.len) return entry.filter;
    }
    return .none;
}

// RarVM's variable-width integer encoding (RarVM::ReadData). The top two bits
// select the width, and the 0x4000 case has a sub-case that sign-extends a
// small negative value.
pub fn readData(br: *BitReader) Failure!u32 {
    const data = try br.peekBits(16);
    switch (data & 0xc000) {
        0 => {
            br.skipBits(6);
            return (data >> 10) & 0x0f;
        },
        0x4000 => {
            if ((data & 0x3c00) == 0) {
                br.skipBits(14);
                return 0xffffff00 | ((data >> 2) & 0xff);
            }
            br.skipBits(10);
            return (data >> 6) & 0xff;
        },
        0x8000 => {
            br.skipBits(2);
            const v = try br.peekBits(16);
            br.skipBits(16);
            return v;
        },
        else => {
            br.skipBits(2);
            const hi = try br.peekBits(16);
            br.skipBits(16);
            const lo = try br.peekBits(16);
            br.skipBits(16);
            return (hi << 16) | lo;
        },
    }
}

// False means out-of-range parameters: the caller must report the entry
// unverifiable. The reference filters into a VM image at Mem + BlockSize;
// reading from a copy of the input and writing back over `data` is the same
// transform without the scratch copy.
pub fn applyFilter(
    filter: StandardFilter,
    data: []u8,
    scratch: []u8,
    init_r: [7]u32,
) bool {
    if (data.len == 0) return true;
    if (scratch.len < data.len) return false;
    const data_size: usize = data.len;
    const channels: usize = init_r[0];

    switch (filter) {
        .delta => {
            if (channels == 0 or channels > max_channels) return false;
            @memcpy(scratch[0..data_size], data);
            var src_pos: usize = 0;
            var cur_channel: usize = 0;
            while (cur_channel < channels) : (cur_channel += 1) {
                var prev_byte: u8 = 0;
                var dest_pos: usize = cur_channel;
                while (dest_pos < data_size) : (dest_pos += channels) {
                    prev_byte -%= scratch[src_pos];
                    src_pos += 1;
                    data[dest_pos] = prev_byte;
                }
            }
            return true;
        },
        .audio => {
            if (channels == 0 or channels > 128) return false;
            @memcpy(scratch[0..data_size], data);
            var src_pos: usize = 0;
            var cur_channel: usize = 0;
            while (cur_channel < channels) : (cur_channel += 1) {
                var prev_byte: u32 = 0;
                var prev_delta: i32 = 0;
                var dif = [_]u32{0} ** 7;
                var d1: i32 = 0;
                var d2: i32 = 0;
                var d3: i32 = 0;
                var k1: i32 = 0;
                var k2: i32 = 0;
                var k3: i32 = 0;

                var i: usize = cur_channel;
                var byte_count: usize = 0;
                while (i < data_size) : ({
                    i += channels;
                    byte_count += 1;
                }) {
                    d3 = d2;
                    d2 = prev_delta -% d1;
                    d1 = prev_delta;

                    const predicted_wide: i64 = 8 * @as(i64, prev_byte) +
                        @as(i64, k1) * @as(i64, d1) +
                        @as(i64, k2) * @as(i64, d2) +
                        @as(i64, k3) * @as(i64, d3);
                    var predicted: u32 = @truncate(@as(u64, @bitCast(predicted_wide)) >> 3);
                    predicted &= 0xff;

                    const cur_byte: u8 = scratch[src_pos];
                    src_pos += 1;

                    predicted = (predicted -% cur_byte) & 0xff;
                    data[i] = @intCast(predicted);
                    prev_delta = @as(i8, @bitCast(@as(u8, @intCast((predicted -% prev_byte) & 0xff))));
                    prev_byte = predicted;

                    const d_signed: i32 = @as(i8, @bitCast(cur_byte));
                    const d: i32 = d_signed << 3;
                    dif[0] +%= @abs(d);
                    dif[1] +%= @abs(d - d1);
                    dif[2] +%= @abs(d + d1);
                    dif[3] +%= @abs(d - d2);
                    dif[4] +%= @abs(d + d2);
                    dif[5] +%= @abs(d - d3);
                    dif[6] +%= @abs(d + d3);

                    if ((byte_count & 0x1f) == 0) {
                        var min_dif = dif[0];
                        var num_min_dif: usize = 0;
                        dif[0] = 0;
                        for (1..dif.len) |j| {
                            if (dif[j] < min_dif) {
                                min_dif = dif[j];
                                num_min_dif = j;
                            }
                            dif[j] = 0;
                        }
                        switch (num_min_dif) {
                            1 => if (k1 >= -16) {
                                k1 -= 1;
                            },
                            2 => if (k1 < 16) {
                                k1 += 1;
                            },
                            3 => if (k2 >= -16) {
                                k2 -= 1;
                            },
                            4 => if (k2 < 16) {
                                k2 += 1;
                            },
                            5 => if (k3 >= -16) {
                                k3 -= 1;
                            },
                            6 => if (k3 < 16) {
                                k3 += 1;
                            },
                            else => {},
                        }
                    }
                }
            }
            return true;
        },
        .e8, .e8e9 => {
            // x86 call/jump target conversion: the encoder rewrote relative
            // targets as absolute to make them compress; undo that.
            if (data_size < 4) return false;
            const file_offset: u32 = init_r[6];
            const cmp_byte2: u8 = if (filter == .e8e9) 0xe9 else 0xe8;

            var cur_pos: usize = 0;
            while (cur_pos < data_size - 4) {
                const cur_byte = data[cur_pos];
                cur_pos += 1;
                if (cur_byte == 0xe8 or cur_byte == cmp_byte2) {
                    const offset: u32 = @truncate(@as(u64, cur_pos) +% file_offset);
                    const addr = std.mem.readInt(u32, data[cur_pos..][0..4], .little);
                    if (addr & 0x8000_0000 != 0) {
                        if ((addr +% offset) & 0x8000_0000 == 0) {
                            std.mem.writeInt(u32, data[cur_pos..][0..4], addr +% e8_file_size, .little);
                        }
                    } else if ((addr -% e8_file_size) & 0x8000_0000 != 0) {
                        std.mem.writeInt(u32, data[cur_pos..][0..4], addr -% offset, .little);
                    }
                    cur_pos += 4;
                }
            }
            return true;
        },
        .rgb => {
            // Bitmap predictor: three interleaved colour channels, each
            // predicted from the pixel to the left, the pixel above, and the
            // pixel above-left, choosing whichever the Paeth-style comparison
            // favours. Afterwards the red and blue channels have green added
            // back (they were stored as differences from it).
            const width_reg = init_r[0];
            if (width_reg < 3) return false;
            const width: usize = width_reg - 3;
            const pos_r: usize = init_r[1];
            if (data_size < 3 or width > data_size or pos_r > 2) return false;

            @memcpy(scratch[0..data_size], data);
            var src_pos: usize = 0;
            const rgb_channels: usize = 3;
            var cur_channel: usize = 0;
            while (cur_channel < rgb_channels) : (cur_channel += 1) {
                var prev_byte: u32 = 0;
                var i: usize = cur_channel;
                while (i < data_size) : (i += rgb_channels) {
                    var predicted: u32 = undefined;
                    if (i >= width + 3) {
                        const upper_byte: u32 = data[i - width];
                        const upper_left_byte: u32 = data[i - width - 3];
                        predicted = prev_byte +% upper_byte -% upper_left_byte;
                        const pa = absDiff(predicted, prev_byte);
                        const pb = absDiff(predicted, upper_byte);
                        const pc = absDiff(predicted, upper_left_byte);
                        if (pa <= pb and pa <= pc) {
                            predicted = prev_byte;
                        } else if (pb <= pc) {
                            predicted = upper_byte;
                        } else {
                            predicted = upper_left_byte;
                        }
                    } else {
                        predicted = prev_byte;
                    }
                    const v: u8 = @truncate((predicted -% scratch[src_pos]) & 0xff);
                    src_pos += 1;
                    data[i] = v;
                    prev_byte = v;
                }
            }
            if (data_size >= 2) {
                var i: usize = pos_r;
                const border = data_size - 2;
                while (i < border) : (i += 3) {
                    const g = data[i + 1];
                    data[i] = data[i] +% g;
                    data[i + 2] = data[i + 2] +% g;
                }
            }
            return true;
        },
        .itanium => {
            // IA-64 instruction bundles are 16 bytes holding three 41-bit
            // slots plus a 5-bit template. For slots whose opcode is a branch
            // (op type 5), the 20-bit target was converted to absolute;
            // convert it back.
            if (data_size < 21) return false;
            var file_offset: u32 = init_r[6] >> 4;

            const masks = [16]u8{ 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0 };
            var cur_pos: usize = 0;
            while (cur_pos < data_size - 21) : ({
                cur_pos += 16;
                file_offset +%= 1;
            }) {
                const block = data[cur_pos..];
                const template: i32 = @as(i32, block[0] & 0x1f) - 0x10;
                if (template < 0) continue;
                const cmd_mask = masks[@as(usize, @intCast(template))];
                if (cmd_mask == 0) continue;
                for (0..3) |i| {
                    if (cmd_mask & (@as(u8, 1) << @intCast(i)) == 0) continue;
                    const start_pos: usize = i * 41 + 5;
                    const op_type = itaniumGetBits(block, start_pos + 37, 4);
                    if (op_type != 5) continue;
                    const offset = itaniumGetBits(block, start_pos + 13, 20);
                    itaniumSetBits(block, (offset -% file_offset) & 0xfffff, start_pos + 13, 20);
                }
            }
            return true;
        },
        else => return false,
    }
}

// x86 image size the E8 filter normalises against (reference FileSize) — a
// FIXED 16 MB, not the size of the file being decoded.
const e8_file_size: u32 = 0x1000000;

// Reference cap on delta channels (MAX3_UNPACK_CHANNELS).
const max_channels: usize = 1024;

// |a - b| on the wrapped 32-bit values the RGB predictor compares, matching
// the reference's abs((int)(Predicted - X)).
fn absDiff(a: u32, b: u32) u32 {
    const d: i32 = @bitCast(a -% b);
    return @abs(d);
}

fn itaniumGetBits(data: []const u8, bit_pos: usize, bit_count: u5) u32 {
    const in_addr = bit_pos / 8;
    const in_bit: u5 = @intCast(bit_pos & 7);
    var bit_field: u32 = data[in_addr];
    bit_field |= @as(u32, data[in_addr + 1]) << 8;
    bit_field |= @as(u32, data[in_addr + 2]) << 16;
    bit_field |= @as(u32, data[in_addr + 3]) << 24;
    bit_field >>= in_bit;
    if (bit_count >= 32) return bit_field;
    return bit_field & ((@as(u32, 1) << bit_count) - 1);
}

fn itaniumSetBits(data: []u8, value: u32, bit_pos: usize, bit_count: u5) void {
    const in_addr = bit_pos / 8;
    const in_bit: u5 = @intCast(bit_pos & 7);
    var and_mask: u32 = if (bit_count >= 32) 0xffffffff else (@as(u32, 1) << bit_count) - 1;
    and_mask = ~(and_mask << in_bit);
    var bit_field: u32 = value << in_bit;

    for (0..4) |i| {
        data[in_addr + i] &= @truncate(and_mask);
        data[in_addr + i] |= @truncate(bit_field);
        and_mask = (and_mask >> 8) | 0xff000000;
        bit_field >>= 8;
    }
}

test "identifyFilter: checksum and both length and crc must match" {
    var code = [_]u8{ 0xFF, 0x01, 0x02 };
    try std.testing.expectEqual(StandardFilter.none, identifyFilter(&code));
    code[0] = 0x01 ^ 0x02;
    try std.testing.expectEqual(StandardFilter.none, identifyFilter(&code));
    try std.testing.expectEqual(StandardFilter.none, identifyFilter(&[_]u8{}));
}

test "readData: 4-bit and 16-bit forms consume exactly the reference widths" {
    {
        var buf = [_]u8{ 0b0010_1100, 0x00, 0x00, 0x00 };
        var br = BitReader.init(&buf);
        const before = br.remainingBits();
        try std.testing.expectEqual(@as(u32, 0b1011), try readData(&br));
        try std.testing.expectEqual(@as(usize, 6), before - br.remainingBits());
    }
    {
        var buf = [_]u8{ 0xAA, 0xF3, 0x40, 0x00 };
        var br = BitReader.init(&buf);
        const before = br.remainingBits();
        try std.testing.expectEqual(@as(u32, 0xABCD), try readData(&br));
        try std.testing.expectEqual(@as(usize, 18), before - br.remainingBits());
    }
}

test "readData: 8-bit form and its sign-extended sub-case" {
    {
        var buf = [_]u8{ 0x7C, 0xC0, 0x00, 0x00 };
        var br = BitReader.init(&buf);
        const before = br.remainingBits();
        const v = try readData(&br);
        try std.testing.expectEqual(@as(usize, 10), before - br.remainingBits());
        try std.testing.expectEqual(@as(u32, 0b11110011), v);
    }
    {
        var buf = [_]u8{ 0x40, 0x3C, 0x00, 0x00 };
        var br = BitReader.init(&buf);
        const before = br.remainingBits();
        const v = try readData(&br);
        try std.testing.expectEqual(@as(usize, 14), before - br.remainingBits());
        try std.testing.expect(v >= 0xffffff00);
    }
}
