const std = @import("std");

// Inverse of the unpack50 slot tables. Subtract the distance-dependent length
// bonus first, because a match with an adjusted length below 2 cannot be encoded.

pub const LengthSlotResult = struct {
    slot: u32, // The range is 0..43 and maps to the LD symbol 262+slot.
    extra: u32,
    extra_bits: u5,
};

pub const DistanceSlotResult = struct {
    dd_slot: u32,
    dd_extra: u32,
    dd_extra_bits: u5,
    use_ldd: bool,
    ldd_value: u32, // The low 4 bits come from the LDD table if use_ldd is set.
};

pub fn encodeLengthSlot(length: u32) LengthSlotResult {
    std.debug.assert(length >= 2);

    if (length <= 9) {
        return .{ .slot = length - 2, .extra = 0, .extra_bits = 0 };
    }

    // Scan the grouped slots with the decoder formula so the ranges cannot drift apart.
    var slot: u32 = 8;
    while (slot < 44) : (slot += 1) {
        const lbits: u5 = @intCast(slot / 4 - 1);
        const base: u32 = 2 + (@as(u32, 4 | @as(u32, slot & 3)) << lbits);
        const range: u32 = @as(u32, 1) << lbits;
        if (length >= base and length < base + range) {
            return .{ .slot = slot, .extra = length - base, .extra_bits = lbits };
        }
    }

    // Fallback for a length that no slot covers, which valid input must not produce.
    return .{ .slot = 43, .extra = 0, .extra_bits = 0 };
}

// Subtract the distance-dependent length bonus that the decoder adds back: 1 for a
// distance above 0x100, 2 above 0x2000, and 3 above 0x40000.
pub fn adjustLengthForDistance(length: u32, distance: u32) u32 {
    var adj = length;
    if (distance > 0x100) {
        adj -= 1;
        if (distance > 0x2000) {
            adj -= 1;
            if (distance > 0x40000) {
                adj -= 1;
            }
        }
    }
    return adj;
}

pub fn encodeDistanceSlot(distance: u32) DistanceSlotResult {
    std.debug.assert(distance >= 1);

    if (distance <= 4) {
        return .{ .dd_slot = distance - 1, .dd_extra = 0, .dd_extra_bits = 0, .use_ldd = false, .ldd_value = 0 };
    }

    const dist_base = distance - 1;
    var slot: u32 = 4;
    while (slot < 64) : (slot += 1) {
        const extra_bits: u5 = @intCast(slot / 2 - 1);
        const base: u32 = (2 | (slot & 1)) << extra_bits;
        const range: u32 = @as(u32, 1) << extra_bits;
        if (dist_base >= base and dist_base < base + range) {
            const extra_value = dist_base - base;

            if (extra_bits < 4) {
                return .{
                    .dd_slot = slot,
                    .dd_extra = extra_value,
                    .dd_extra_bits = extra_bits,
                    .use_ldd = false,
                    .ldd_value = 0,
                };
            }
            // High extra bits go to the bitstream, the low 4 via the LDD table.
            return .{
                .dd_slot = slot,
                .dd_extra = extra_value >> 4,
                .dd_extra_bits = extra_bits - 4,
                .use_ldd = true,
                .ldd_value = extra_value & 0xF,
            };
        }
    }

    return .{ .dd_slot = 63, .dd_extra = 0, .dd_extra_bits = 0, .use_ldd = false, .ldd_value = 0 };
}

test "encodeLengthSlot round-trips through the decoder table mapping" {
    for (0..8) |slot| {
        const r = encodeLengthSlot(@intCast(slot + 2));
        try std.testing.expectEqual(@as(u32, @intCast(slot)), r.slot);
        try std.testing.expectEqual(@as(u5, 0), r.extra_bits);
    }
    try std.testing.expectEqual(@as(u32, 8), encodeLengthSlot(10).slot);
    try std.testing.expectEqual(@as(u32, 1), encodeLengthSlot(11).extra);
    try std.testing.expectEqual(@as(u32, 9), encodeLengthSlot(12).slot);
    try std.testing.expectEqual(@as(u32, 12), encodeLengthSlot(18).slot);
    try std.testing.expectEqual(@as(u32, 16), encodeLengthSlot(34).slot);
}

test "adjustLengthForDistance removes the decoder's bonus" {
    try std.testing.expectEqual(@as(u32, 5), adjustLengthForDistance(5, 1));
    try std.testing.expectEqual(@as(u32, 5), adjustLengthForDistance(5, 0x100));
    try std.testing.expectEqual(@as(u32, 4), adjustLengthForDistance(5, 0x101));
    try std.testing.expectEqual(@as(u32, 3), adjustLengthForDistance(5, 0x2001));
    try std.testing.expectEqual(@as(u32, 2), adjustLengthForDistance(5, 0x40001));
}

test "encodeDistanceSlot direct distances and split extras" {
    for (1..5) |dist| {
        const r = encodeDistanceSlot(@intCast(dist));
        try std.testing.expectEqual(@as(u32, @intCast(dist - 1)), r.dd_slot);
        try std.testing.expect(!r.use_ldd);
    }
    const r5 = encodeDistanceSlot(5);
    try std.testing.expectEqual(@as(u32, 4), r5.dd_slot);
    try std.testing.expectEqual(@as(u5, 1), r5.dd_extra_bits);
    try std.testing.expect(!r5.use_ldd);
    // Distance 65536 gives dist_base 65535 in slot 31 (base 49152, 14 extra bits),
    // so extra_value 16383 splits into 1023 high bits and a low nibble of 15.
    const wide = encodeDistanceSlot(65536);
    try std.testing.expectEqual(@as(u32, 31), wide.dd_slot);
    try std.testing.expect(wide.use_ldd);
    try std.testing.expectEqual(@as(u32, 1023), wide.dd_extra);
    try std.testing.expectEqual(@as(u5, 10), wide.dd_extra_bits);
    try std.testing.expectEqual(@as(u32, 15), wide.ldd_value);
}
