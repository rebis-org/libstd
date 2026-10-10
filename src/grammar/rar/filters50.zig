const std = @import("std");
const failure = @import("../../common/primitive/failure.zig");
const Failure = failure.Failure;
const bits = @import("bits.zig");
const BitReader = bits.BitReader;

// The E8 and Arm transforms relocate against true file positions, so
// `file_offset` counts from the start of the file and not from the region.

pub const FilterType = enum(u3) {
    delta = 0,
    e8 = 1,
    e8e9 = 2,
    arm = 3,
};

pub const Filter = struct {
    filter_type: FilterType,
    start: usize, // Position in the window stream, not in the file.
    length: usize,
    channels: u8, // The delta filter uses 1 to 32 channels.
};

pub fn filterTypeFromRaw(filter_code: u3) ?FilterType {
    return switch (filter_code) {
        0 => .delta,
        1 => .e8,
        2 => .e8e9,
        3 => .arm,
        else => null,
    };
}

// Largest region one RAR5 filter may cover (reference MAX_FILTER_BLOCK_SIZE).
pub const max_filter_block: usize = 0x400000;

// The E8 and E8E9 filters relocate against a FIXED 16 MB wrap constant
// (E8_WRAP), not the file size, and the wrap constant is not the file offset.
const e8_wrap: u32 = 0x1000000;

pub fn applyFilter(data: []u8, filter: Filter, file_offset: u64, scratch: []u8) Failure!void {
    if (filter.length > data.len) return error.InvalidData;
    const region = data[0..filter.length];
    switch (filter.filter_type) {
        .delta => try applyDelta(region, filter.channels, scratch),
        .e8 => applyE8E9(region, file_offset, false),
        .e8e9 => applyE8E9(region, file_offset, true),
        .arm => applyArm(region, file_offset),
    }
}

// A channel-sequential delta inverts to a per-channel prefix sum. Source and
// destination overlap, so the transform writes to the scratch copy.
fn applyDelta(data: []u8, channels: u8, scratch: []u8) Failure!void {
    if (channels == 0 or data.len == 0) return;
    if (scratch.len < data.len) return error.InsufficientCapacity;
    const channel_count: usize = channels;
    const dst = scratch[0..data.len];

    var src_pos: usize = 0;
    var cur_channel: usize = 0;
    while (cur_channel < channel_count) : (cur_channel += 1) {
        var prev: u8 = 0;
        var dest_pos: usize = cur_channel;
        while (dest_pos < data.len) : (dest_pos += channel_count) {
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
            // Truncating to u32 before the modulo is safe because e8_wrap is a
            // power of two that divides 2^32.
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
            // The Arm BL offset is unsigned, occupies the low three bytes, and
            // counts instruction units, so the code must not sign extend it.
            const low_byte: u32 = data[i];
            const mid_byte: u32 = data[i + 1];
            const high_byte: u32 = data[i + 2];
            var offset: u32 = (high_byte << 16) | (mid_byte << 8) | low_byte;

            offset -%= @truncate((file_offset +% @as(u64, i)) / 4);

            data[i] = @truncate(offset);
            data[i + 1] = @truncate(offset >> 8);
            data[i + 2] = @truncate(offset >> 16);
        }
    }
}

// The wire size field (ReadFilterData) uses a 2-bit prefix for a byte count of
// 1 to 4, then assembles the value little-endian.
pub fn readFilterSize(br: *BitReader) Failure!usize {
    const byte_count: u3 = @intCast((try br.readBits(2)) + 1);
    var size: usize = 0;
    var i: u3 = 0;
    while (i < byte_count) : (i += 1) {
        const byte: usize = try br.readBits(8);
        size += byte << @intCast(@as(u6, i) * 8);
    }
    return size;
}

test "delta filter subtracts cumulatively with one channel" {
    var data = [_]u8{ 0, 1, 1, 1, 1 };
    var scratch: [5]u8 = undefined;
    try applyDelta(&data, 1, &scratch);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 255, 254, 253, 252 }, &data);
}

test "delta filter separates three interleaved channels" {
    var data = [_]u8{ 10, 20, 30, 5, 5, 5, 3, 3, 3 };
    var scratch: [9]u8 = undefined;
    try applyDelta(&data, 3, &scratch);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 246, 251, 253, 226, 246, 250, 196, 241, 247 }, &data);
}

test "e8 filter relocates against the wrap constant and the file offset" {
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
