const std = @import("std");
const failure = @import("../../common/primitive/failure.zig");
const Failure = failure.Failure;
const bits = @import("bits.zig");
const BitReader = bits.BitReader;

// file_offset is the region's offset WITHIN THE FILE: the E8/ARM transforms
// relocate against true file positions, not positions inside whatever region
// the filter happens to cover.

pub const FilterType = enum(u3) {
    delta = 0,
    e8 = 1,
    e8e9 = 2,
    arm = 3,
};

pub const Filter = struct {
    filter_type: FilterType,
    block_start: usize, // window-stream position of the region start
    block_length: usize,
    channels: u8, // delta filter only (1-32)
};

pub fn filterTypeFromRaw(raw: u3) ?FilterType {
    return switch (raw) {
        0 => .delta,
        1 => .e8,
        2 => .e8e9,
        3 => .arm,
        else => null,
    };
}

// Largest region one RAR5 filter may cover (reference MAX_FILTER_BLOCK_SIZE).
pub const max_filter_block: usize = 0x400000;

// The wrap constant the E8/E8E9 filter relocates against — a FIXED 16 MB.
// (An earlier reading used the file size here; every filtered region past the
// first then decoded to the wrong bytes. The constant and the file offset are
// different quantities that appear two lines apart in the reference.)
const e8_wrap: u32 = 0x1000000;

pub fn applyFilter(data: []u8, filter: Filter, file_offset: u64, scratch: []u8) Failure!void {
    if (filter.block_length > data.len) return error.InvalidData;
    const region = data[0..filter.block_length];
    switch (filter.filter_type) {
        .delta => try applyDelta(region, filter.channels, scratch),
        .e8 => applyE8E9(region, file_offset, false),
        .e8e9 => applyE8E9(region, file_offset, true),
        .arm => applyArm(region, file_offset),
    }
}

// Channel-sequential delta: the inverse is a per-channel prefix sum, and
// source and destination overlap, so the transform needs a scratch copy.
fn applyDelta(data: []u8, channels: u8, scratch: []u8) Failure!void {
    if (channels == 0 or data.len == 0) return;
    if (scratch.len < data.len) return error.InsufficientCapacity;
    const ch: usize = channels;
    const dst = scratch[0..data.len];

    var src_pos: usize = 0;
    var cur_channel: usize = 0;
    while (cur_channel < ch) : (cur_channel += 1) {
        var prev: u8 = 0;
        var dest_pos: usize = cur_channel;
        while (dest_pos < data.len) : (dest_pos += ch) {
            prev -%= data[src_pos];
            dst[dest_pos] = prev;
            src_pos += 1;
        }
    }

    @memcpy(data, dst);
}

pub fn applyE8E9(data: []u8, file_offset: u64, e9: bool) void {
    if (data.len < 5) return;
    var i: usize = 0;
    while (i + 4 < data.len) {
        if (data[i] == 0xE8 or (e9 and data[i] == 0xE9)) {
            // Truncating to u32 before the modulo is safe and matches the
            // reference's (uint)WrittenFileSize: E8_WRAP is a power of two
            // that divides 2^32.
            const offset: u32 = @truncate((@as(u64, i) + 1 +% file_offset) % e8_wrap);
            const addr = std.mem.readInt(u32, data[i + 1 ..][0..4], .little);

            if (addr & 0x80000000 != 0) {
                if ((addr +% offset) & 0x80000000 == 0) {
                    std.mem.writeInt(u32, data[i + 1 ..][0..4], addr +% e8_wrap, .little);
                }
            } else if (addr < e8_wrap) {
                std.mem.writeInt(u32, data[i + 1 ..][0..4], addr -% offset, .little);
            }
            i += 5;
        } else {
            i += 1;
        }
    }
}

pub fn applyArm(data: []u8, file_offset: u64) void {
    if (data.len < 4) return;
    var i: usize = 0;
    while (i + 3 < data.len) : (i += 4) {
        if (data[i + 3] == 0xEB) {
            // ARM BL with the 'always' condition. Plain unsigned 24-bit
            // arithmetic; only the low 24 bits are written back, so no sign
            // extension is needed (or performed by the reference). Branches
            // count in instruction units, hence the /4.
            const b0: u32 = data[i];
            const b1: u32 = data[i + 1];
            const b2: u32 = data[i + 2];
            var offset: u32 = (b2 << 16) | (b1 << 8) | b0;

            offset -%= @truncate((file_offset +% @as(u64, i)) / 4);

            data[i] = @truncate(offset);
            data[i + 1] = @truncate(offset >> 8);
            data[i + 2] = @truncate(offset >> 16);
        }
    }
}

// Wire format (reference ReadFilterData): a 2-bit prefix gives the byte count
// (1-4); the value assembles little-endian, first byte read = low 8 bits.
pub fn readFilterSize(br: *BitReader) Failure!usize {
    const byte_count: u3 = @intCast((try br.readBits(2)) + 1);
    var value: usize = 0;
    var i: u3 = 0;
    while (i < byte_count) : (i += 1) {
        const b: usize = try br.readBits(8);
        value += b << @intCast(@as(u6, i) * 8);
    }
    return value;
}

test "delta filter channels=1 cumulative subtract" {
    var data = [_]u8{ 0, 1, 1, 1, 1 };
    var scratch: [5]u8 = undefined;
    try applyDelta(&data, 1, &scratch);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 255, 254, 253, 252 }, &data);
}

test "delta filter channels=3 de-interleaves" {
    var data = [_]u8{ 10, 20, 30, 5, 5, 5, 3, 3, 3 };
    var scratch: [9]u8 = undefined;
    try applyDelta(&data, 3, &scratch);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 246, 251, 253, 226, 246, 250, 196, 241, 247 }, &data);
}

test "e8 filter relocates against the fixed wrap and the file offset" {
    const at_zero = blk: {
        var d = [_]u8{ 0xE8, 0x00, 0x10, 0x00, 0x00, 0x90 };
        applyE8E9(&d, 0, false);
        break :blk std.mem.readInt(u32, d[1..5], .little);
    };
    const at_offset = blk: {
        var d = [_]u8{ 0xE8, 0x00, 0x10, 0x00, 0x00, 0x90 };
        applyE8E9(&d, 0x400, false);
        break :blk std.mem.readInt(u32, d[1..5], .little);
    };
    // offset = (0 + 1 + file_offset) % E8_WRAP
    try std.testing.expectEqual(@as(u32, 0x0FFF), at_zero);
    try std.testing.expectEqual(@as(u32, 0x0BFF), at_offset);
}

test "e8 filter: negative address crossing zero gets the wrap constant" {
    var data = [_]u8{ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xE8, 0xFB, 0xFF, 0xFF, 0xFF, 0x90 };
    applyE8E9(&data, 0, false);
    try std.testing.expectEqual(@as(u32, 0x00FFFFFB), std.mem.readInt(u32, data[11..15], .little));
}

test "arm filter subtracts the instruction offset" {
    var data = [_]u8{
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0xEB,
    };
    applyArm(&data, 0);
    try std.testing.expectEqual(@as(u8, 0x0E), data[8]);
    try std.testing.expectEqual(@as(u8, 0xEB), data[11]);
}

test "readFilterSize assembles little-endian across 1-4 bytes" {
    {
        var data = [_]u8{ 0x10, 0x80 };
        var br = BitReader.init(&data);
        try std.testing.expectEqual(@as(usize, 0x42), try readFilterSize(&br));
    }
    {
        var data = [_]u8{ 0x4D, 0x04, 0x80 };
        var br = BitReader.init(&data);
        try std.testing.expectEqual(@as(usize, 0x1234), try readFilterSize(&br));
    }
    {
        var data = [_]u8{ 0xC0, 0xC0, 0x80, 0x40, 0x00 };
        var br = BitReader.init(&data);
        try std.testing.expectEqual(@as(usize, 0x00010203), try readFilterSize(&br));
    }
}
