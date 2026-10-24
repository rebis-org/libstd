const std = @import("std");

const checksum = @import("../../../common/primitive/checksum.zig");
const exception = @import("../../../common/primitive/exception.zig");

const Exception = exception.Exception;

// RAR5 recovery-record (RR) encoder. The wire form was recovered from
// archives produced by official RAR 7.23 and cross-checked against unrar's
// rs16 Reed-Solomon code: ECC words are 16-bit little-endian values over
// GF(2^16), the encoder matrix is rs16's inverse (Cauchy-style) matrix, and
// every sub-block carries a CRC-64/XZ checksum in the clear. The ECC data is
// a sequence of units; each unit holds one sub-block per 64 KiB slice of the
// protected region, and every sub-block can rebuild one missing chunk of that
// slice on its own.

// The exp table is double-width so gfMul needs no modular reduction, and the
// log table stores rs16's sentinel 131070 for element 0, which neither fits
// u16 nor should branch gfMul.
pub const gf_exp_len: usize = 262141;
pub const gf_log_len: usize = 65536;

pub const Layout = struct {
    p: usize,
    nd: usize,
    ch: usize,
    u: usize,
    nsub: usize,
    poff: usize,
    unit_size: usize,
    last_chunk: usize,

    pub fn dataLen(self: Layout) Exception!usize {
        return std.math.mul(usize, self.u, self.unit_size) catch error.InternalException;
    }
};

// Mirrors rs16SetupData: nd is ceil(p / 1024) capped at 200, u derives from
// the recovery percentage, and chunk sizes round up to even so every ECC
// word covers two whole bytes.
pub fn layoutFor(p: usize, percent: usize) Exception!Layout {
    if (p == 0) return error.InternalException;
    // The explicit usize matters: @min narrows the result type to the
    // smallest type holding a comptime-known bound (u8 for 200), which would
    // overflow the moment the layout arithmetic scales nd back up.
    const nd: usize = @min(@as(usize, 200), p / 1024 + @intFromBool(p % 1024 != 0));
    const u_prod = std.math.mul(usize, percent, 2 * nd) catch return error.InternalException;
    const u: usize = @max(@as(usize, 1), u_prod / 200);
    const ch0 = std.math.divCeil(usize, p, nd) catch return error.InternalException;
    const ch = ch0 + (ch0 & 1);
    const head = std.math.mul(usize, ch, nd - 1) catch return error.InternalException;
    if (head >= p) return error.InternalException;
    const last_chunk = p - head;
    const nsub = std.math.divCeil(usize, ch, 65536) catch return error.InternalException;
    const poff = 72 + nd * 8;
    const nsub_poff = std.math.mul(usize, nsub, poff) catch return error.InternalException;
    const unit_size = std.math.add(usize, nsub_poff, ch) catch return error.InternalException;
    return .{ .p = p, .nd = nd, .ch = ch, .u = u, .nsub = nsub, .poff = poff, .unit_size = unit_size, .last_chunk = last_chunk };
}

// Builds rs16's tables: exp is written double-width (l and l + 65535 both
// point at the same element), log[0] gets rs16's sentinel, and the tail of
// exp beyond the highest written index stays zero so gfMul(0, x) reads a
// zero. Length checks run before any mutation, so a rejected call leaves the
// caller's buffers untouched.
pub fn initTables(exp: []u16, log: []u32) Exception!void {
    if (exp.len < gf_exp_len) return error.InternalException;
    if (log.len < gf_log_len) return error.InternalException;
    @memset(exp, 0);
    @memset(log, 0);
    var e: u32 = 1;
    var l: u32 = 0;
    while (l < 65535) : ({
        l += 1;
        e <<= 1;
        if (e > 65535) e ^= 0x1100B;
    }) {
        log[e] = l;
        exp[l] = @intCast(e);
        exp[l + 65535] = @intCast(e);
    }
    log[0] = 131070;
}

fn gfMul(a: u16, b: u16, exp: []const u16, log: []const u32) u16 {
    return exp[@as(usize, log[a]) + log[b]];
}

fn gfInv(a: u16, exp: []const u16, log: []const u32) u16 {
    if (a == 0) return 0;
    return exp[65535 - @as(usize, log[a])];
}

// RAR's header checksums are CRC-64/XZ with init 0 and no xorout, i.e. the
// plain reflected table polynomial without the wrapper's masking.
const crc64_raw_table = blk: {
    @setEvalBranchQuota(1 << 14);
    var table: [256]u64 = undefined;
    for (0..256) |i| {
        var crc: u64 = i;
        for (0..8) |_| {
            if (crc & 1 != 0) {
                crc = (crc >> 1) ^ 0xC96C5795D7870F42;
            } else {
                crc >>= 1;
            }
        }
        table[i] = crc;
    }
    break :blk table;
};

pub fn crc64Raw(input: []const u8) u64 {
    var crc: u64 = 0;
    for (input) |b| {
        crc = crc64_raw_table[@as(u8, @truncate(crc)) ^ b] ^ (crc >> 8);
    }
    return crc;
}

// One 16-bit ECC word: column `col` of chunk k, zero-padded past the end of
// the chunk and of the protected region.
fn chunkWord(protected: []const u8, layout: Layout, k: usize, col: usize) u16 {
    const clen = if (k == layout.nd - 1) layout.last_chunk else layout.ch;
    const off = col * 2;
    if (off >= clen) return 0;
    const lo: u16 = protected[k * layout.ch + off];
    const hi: u16 = if (off + 1 >= clen) 0 else protected[k * layout.ch + off + 1];
    return lo | (hi << 8);
}

// Writes one sub-block: fixed header, per-chunk CRC entries, the slot, and
// the parity words for slice j of unit m. The trailing checksum covers
// everything except itself, so it is written last.
fn writeSubBlock(
    protected: []const u8,
    layout: Layout,
    mx: []const u16,
    slot: u64,
    exp: []const u16,
    log: []const u32,
    unit_index: usize,
    sub_index: usize,
    sb: []u8,
) void {
    const j = sub_index;
    const slice_len: usize = @min(@as(usize, 65536), layout.ch - j * 65536);
    const sub_size = layout.poff + slice_len;
    std.mem.writeInt(u32, sb[0..4], 0x7d42527b, .little);
    std.mem.writeInt(u32, sb[12..16], @intCast(sub_size), .little);
    std.mem.writeInt(u32, sb[16..20], @intCast(layout.poff), .little);
    sb[20] = 1;
    sb[21] = 1;
    std.mem.writeInt(u64, sb[22..30], @as(u64, j) * 65536, .little);
    std.mem.writeInt(u32, sb[30..34], @intCast(layout.last_chunk -| j * 65536), .little);
    std.mem.writeInt(u64, sb[34..42], layout.p, .little);
    std.mem.writeInt(u64, sb[42..50], layout.ch, .little);
    std.mem.writeInt(u64, sb[50..58], layout.unit_size, .little);
    std.mem.writeInt(u16, sb[58..60], @intCast(layout.nd), .little);
    std.mem.writeInt(u16, sb[60..62], @intCast(layout.u), .little);
    std.mem.writeInt(u16, sb[62..64], @intCast(unit_index), .little);
    var k: usize = 0;
    while (k < layout.nd) : (k += 1) {
        const clen = if (k == layout.nd - 1) layout.last_chunk else layout.ch;
        const lo = j * 65536;
        const entry: u64 = if (lo < clen)
            crc64Raw(protected[k * layout.ch + lo .. k * layout.ch + @min(lo + 65536, clen)])
        else
            0;
        std.mem.writeInt(u64, sb[64 + k * 8 ..][0..8], entry, .little);
    }
    std.mem.writeInt(u64, sb[64 + layout.nd * 8 ..][0..8], slot, .little);
    var w: usize = 0;
    while (w < slice_len / 2) : (w += 1) {
        const col = j * 32768 + w;
        var acc: u16 = 0;
        var k2: usize = 0;
        while (k2 < layout.nd) : (k2 += 1) {
            acc ^= gfMul(mx[k2], chunkWord(protected, layout, k2, col), exp, log);
        }
        std.mem.writeInt(u16, sb[layout.poff + w * 2 ..][0..2], acc, .little);
    }
    var crc = checksum.XzCrc64.init();
    crc.update(sb[12..sub_size]);
    std.mem.writeInt(u64, sb[4..12], crc.final(), .little);
}

// Encodes the protected region into `u` units of ECC data. `slot` is the
// per-archive random value every sub-block carries; it must be identical
// across calls for the same archive.
pub fn encodeUnits(
    protected: []const u8,
    layout: Layout,
    slot: u64,
    out: []u8,
    exp: []u16,
    log: []u32,
) Exception!void {
    if (protected.len != layout.p) return error.InternalException;
    if ((std.math.add(usize, layout.u, layout.nd) catch return error.InternalException) > 65535)
        return error.InternalException;
    const data_len = try layout.dataLen();
    if (out.len < data_len) return error.CapacityException;
    if (exp.len < gf_exp_len or log.len < gf_log_len) return error.InternalException;
    // Content probe: catches zeroed or stale tables that pass the length
    // checks, before the encoder multiplies anything by garbage.
    if (exp[0] != 1 or exp[1] != 2 or exp[2] != 4) return error.InternalException;
    if (layout.nd < 1 or layout.nd > 200) return error.InternalException;
    if (layout.u < 1) return error.InternalException;
    if (layout.nsub < 1) return error.InternalException;
    if (layout.ch < 2 or layout.ch % 2 != 0) return error.InternalException;
    if (layout.last_chunk < 1 or layout.last_chunk > layout.ch) return error.InternalException;
    const head = std.math.mul(usize, layout.ch, layout.nd - 1) catch return error.InternalException;
    if (head >= layout.p) return error.InternalException;
    const tail = std.math.add(usize, head, layout.last_chunk) catch return error.InternalException;
    if (tail != layout.p) return error.InternalException;
    if (layout.poff < 72 + layout.nd * 8) return error.InternalException;
    if (layout.poff > std.math.maxInt(u32) - 65536) return error.InternalException;
    const nsub_poff = std.math.mul(usize, layout.nsub, layout.poff) catch return error.InternalException;
    const unit_expect = std.math.add(usize, nsub_poff, layout.ch) catch return error.InternalException;
    if (layout.unit_size != unit_expect) return error.InternalException;
    const sub_span = std.math.mul(usize, layout.nsub, 65536) catch return error.InternalException;
    if (layout.ch > sub_span or layout.ch <= sub_span - 65536) return error.InternalException;
    var mx: [200]u16 = undefined;
    var m: usize = 0;
    while (m < layout.u) : (m += 1) {
        var k: usize = 0;
        while (k < layout.nd) : (k += 1) {
            mx[k] = gfInv(@intCast((m + layout.nd) ^ k), exp, log);
        }
        var j: usize = 0;
        while (j < layout.nsub) : (j += 1) {
            const slice_len: usize = @min(@as(usize, 65536), layout.ch - j * 65536);
            const sub_size = layout.poff + slice_len;
            const base = m * layout.unit_size + j * (65536 + layout.poff);
            const end = base + sub_size;
            if (end > out.len) return error.InternalException;
            writeSubBlock(protected, layout, mx[0..layout.nd], slot, exp, log, m, j, out[base..end]);
        }
    }
}

test "gf and crc64 pins" {
    const allocator = std.testing.allocator;
    const exp = try allocator.alloc(u16, gf_exp_len);
    const log = try allocator.alloc(u32, gf_log_len);
    defer allocator.free(exp);
    defer allocator.free(log);
    try initTables(exp, log);
    try std.testing.expectEqual(@as(u64, 0), crc64Raw(""));
    try std.testing.expectEqual(@as(u64, 0x50fa083a35fad784), crc64Raw("hello"));
    var crc = checksum.XzCrc64.init();
    crc.update("123456789");
    try std.testing.expectEqual(@as(u64, 0x995dc9bbdf1939fa), crc.final());
    // Short table surfaces are rejected before any mutation.
    try std.testing.expectError(error.InternalException, initTables(exp[0..10], log));
    try std.testing.expectError(error.InternalException, initTables(exp, log[0..10]));
    try std.testing.expectEqual(@as(u16, 6), gfMul(2, 3, exp, log));
    try std.testing.expectEqual(@as(u16, 0), gfMul(0, 7, exp, log));
    try std.testing.expectEqual(@as(u16, 0), gfMul(7, 0, exp, log));
    const inv_pins = [_]u16{ 0x0001, 0x8805, 0xf006, 0xcc07, 0x5002, 0x7803 };
    for (inv_pins, 1..) |want, a| {
        const inv = gfInv(@intCast(a), exp, log);
        try std.testing.expectEqual(want, inv);
        // A value times its inverse is the field identity.
        try std.testing.expectEqual(@as(u16, 1), gfMul(@intCast(a), inv, exp, log));
    }
}

test "recovery layout pins" {
    const Case = struct { p: usize, nd: usize, ch: usize, u: usize, last: usize, poff: usize, unit: usize, nsub: usize = 1 };
    const cases = [_]Case{
        .{ .p = 4157, .nd = 5, .ch = 832, .u = 1, .last = 829, .poff = 112, .unit = 944 },
        .{ .p = 4166, .nd = 5, .ch = 834, .u = 1, .last = 830, .poff = 112, .unit = 946 },
        .{ .p = 20141, .nd = 20, .ch = 1008, .u = 2, .last = 989, .poff = 232, .unit = 1240 },
        .{ .p = 200155, .nd = 196, .ch = 1022, .u = 19, .last = 865, .poff = 1640, .unit = 2662 },
        .{ .p = 1000151, .nd = 200, .ch = 5002, .u = 20, .last = 4753, .poff = 1672, .unit = 6674 },
        .{ .p = 16777384, .nd = 200, .ch = 83888, .u = 20, .last = 83672, .poff = 1672, .unit = 87232, .nsub = 2 },
    };
    for (cases) |c| {
        const layout = try layoutFor(c.p, 10);
        try std.testing.expectEqual(c.nd, layout.nd);
        try std.testing.expectEqual(c.ch, layout.ch);
        try std.testing.expectEqual(c.u, layout.u);
        try std.testing.expectEqual(c.nsub, layout.nsub);
        try std.testing.expectEqual(c.poff, layout.poff);
        try std.testing.expectEqual(c.unit, layout.unit_size);
        try std.testing.expectEqual(c.last, layout.last_chunk);
        try std.testing.expectEqual(c.p, layout.p);
    }
    const big = try layoutFor(20141, 1000);
    try std.testing.expectEqual(@as(usize, 200), big.u);
    const tiny = try layoutFor(1, 10);
    try std.testing.expectEqual(@as(usize, 1), tiny.nd);
    try std.testing.expectEqual(@as(usize, 2), tiny.ch);
    try std.testing.expectEqual(@as(usize, 1), tiny.last_chunk);
    try std.testing.expectEqual(@as(usize, 80), tiny.poff);
    try std.testing.expectEqual(@as(usize, 82), tiny.unit_size);
    try std.testing.expectError(error.InternalException, layoutFor(0, 10));
}

test "fabricated multi-slice encode pins the sub-block wire form" {
    const allocator = std.testing.allocator;
    const exp = try allocator.alloc(u16, gf_exp_len);
    const log = try allocator.alloc(u32, gf_log_len);
    defer allocator.free(exp);
    defer allocator.free(log);
    try initTables(exp, log);

    const layout = Layout{
        .p = 200000,
        .nd = 3,
        .ch = 70000,
        .u = 2,
        .nsub = 2,
        .poff = 96,
        .unit_size = 70192,
        .last_chunk = 60000,
    };
    try std.testing.expectEqual(@as(usize, 140384), try layout.dataLen());
    const protected = try allocator.alloc(u8, layout.p);
    defer allocator.free(protected);
    for (protected, 0..) |*b, i| b.* = @truncate(i *% 7 +% (i >> 9));
    const out = try allocator.alloc(u8, try layout.dataLen());
    defer allocator.free(out);
    const slot: u64 = 0x0123456789abcdef;
    try encodeUnits(protected, layout, slot, out, exp, log);

    const sb0 = out[0..65632];
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x7b, 0x52, 0x42, 0x7d }, sb0[0..4]);
    try std.testing.expectEqual(@as(u64, 0x1cdc1588015bbbbc), std.mem.readInt(u64, sb0[4..12], .little));
    try std.testing.expectEqual(@as(u32, 65632), std.mem.readInt(u32, sb0[12..16], .little));
    try std.testing.expectEqual(@as(u32, 96), std.mem.readInt(u32, sb0[16..20], .little));
    try std.testing.expectEqual(@as(u8, 1), sb0[20]);
    try std.testing.expectEqual(@as(u8, 1), sb0[21]);
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, sb0[22..30], .little));
    try std.testing.expectEqual(@as(u32, 60000), std.mem.readInt(u32, sb0[30..34], .little));
    try std.testing.expectEqual(@as(u64, 200000), std.mem.readInt(u64, sb0[34..42], .little));
    try std.testing.expectEqual(@as(u64, 70000), std.mem.readInt(u64, sb0[42..50], .little));
    try std.testing.expectEqual(@as(u64, 70192), std.mem.readInt(u64, sb0[50..58], .little));
    try std.testing.expectEqual(@as(u16, 3), std.mem.readInt(u16, sb0[58..60], .little));
    try std.testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, sb0[60..62], .little));
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, sb0[62..64], .little));
    const entries0 = [_]u64{ 0xc94960b04bbdab16, 0xf7cd6cd8d6c5207e, 0x8232cdd4e6e0d6e4 };
    for (entries0, 0..) |want, k| {
        try std.testing.expectEqual(want, std.mem.readInt(u64, sb0[64 + k * 8 ..][0..8], .little));
    }
    try std.testing.expectEqual(slot, std.mem.readInt(u64, sb0[88..96], .little));

    const sb1 = out[65632..70192];
    try std.testing.expectEqual(@as(u32, 4560), std.mem.readInt(u32, sb1[12..16], .little));
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, sb1[30..34], .little));
    try std.testing.expectEqual(@as(u64, 0), std.mem.readInt(u64, sb1[64 + 2 * 8 ..][0..8], .little));
    try std.testing.expectEqual(@as(u64, 0x0afb57515877cef7), std.mem.readInt(u64, sb1[4..12], .little));

    const unit1 = out[70192..140384];
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, unit1[62..64], .little));
    try std.testing.expectEqual(@as(u64, 0xb1231890c7623cac), std.mem.readInt(u64, unit1[4..12], .little));
    try std.testing.expectEqual(@as(u64, 0x421451d80401a913), std.mem.readInt(u64, unit1[65632 + 4 ..][0..8], .little));

    // Encoder matrix rows, pinned through gfInv.
    const mx_pins = [2][3]u16{
        .{ 0xf006, 0x8805, 0x0001 },
        .{ 0xcc07, 0x5002, 0x7803 },
    };
    for (mx_pins, 0..) |row, m| {
        for (row, 0..) |want, k| {
            try std.testing.expectEqual(want, gfInv(@intCast((m + layout.nd) ^ k), exp, log));
        }
    }

    // Parity words at slice boundaries and interior columns, plus the round
    // trip back to the first chunk through each unit's matrix row.
    const Pin = struct { col: usize, words: [3]u16, p0: u16, p1: u16 };
    const pins = [_]Pin{
        .{ .col = 5, .words = .{ 0x4d46, 0xe5de, 0x7e77 }, .p0 = 0xc7a3, .p1 = 0x922f },
        .{ .col = 32767, .words = .{ 0x7871, 0x110a, 0x0000 }, .p0 = 0x20aa, .p1 = 0xd719 },
        .{ .col = 33000, .words = .{ 0x3730, 0xd0c9, 0x0000 }, .p0 = 0x0288, .p1 = 0x975f },
        .{ .col = 34999, .words = .{ 0x918a, 0x2a23, 0x0000 }, .p0 = 0xed92, .p1 = 0x54c1 },
    };
    for (pins) |pin| {
        const words = [3]u16{
            chunkWord(protected, layout, 0, pin.col),
            chunkWord(protected, layout, 1, pin.col),
            chunkWord(protected, layout, 2, pin.col),
        };
        try std.testing.expectEqualSlices(u16, &pin.words, &words);
        const j = pin.col / 32768;
        const w = pin.col % 32768;
        const off0 = j * (65536 + layout.poff) + layout.poff + w * 2;
        const off1 = layout.unit_size + off0;
        try std.testing.expectEqual(pin.p0, std.mem.readInt(u16, out[off0..][0..2], .little));
        try std.testing.expectEqual(pin.p1, std.mem.readInt(u16, out[off1..][0..2], .little));
        for (mx_pins, 0..) |row, m| {
            const p = if (m == 0) pin.p0 else pin.p1;
            const acc = p ^ gfMul(row[1], words[1], exp, log) ^ gfMul(row[2], words[2], exp, log);
            try std.testing.expectEqual(words[0], gfMul(gfInv(row[0], exp, log), acc, exp, log));
        }
    }
}

test "encode guards reject fabricated layouts and short surfaces" {
    const allocator = std.testing.allocator;
    const exp = try allocator.alloc(u16, gf_exp_len);
    const log = try allocator.alloc(u32, gf_log_len);
    defer allocator.free(exp);
    defer allocator.free(log);
    try initTables(exp, log);

    const layout = try layoutFor(28, 10);
    try std.testing.expectEqual(@as(usize, 108), layout.unit_size);
    const protected = try allocator.alloc(u8, 28);
    defer allocator.free(protected);
    @memset(protected, 0xAB);
    const out = try allocator.alloc(u8, 108);
    defer allocator.free(out);
    try encodeUnits(protected, layout, 0, out, exp, log);
    try std.testing.expectEqual(@as(u32, 0x7d42527b), std.mem.readInt(u32, out[0..4], .little));
    try std.testing.expectError(error.CapacityException, encodeUnits(protected, layout, 0, out[0..107], exp, log));
    try std.testing.expectError(error.InternalException, encodeUnits(protected[0..27], layout, 0, out, exp, log));
    try std.testing.expectError(error.InternalException, encodeUnits(protected, layout, 0, out, &.{}, log));
    var bad = layout;
    bad.unit_size += 1;
    const big_out = try allocator.alloc(u8, 256);
    defer allocator.free(big_out);
    try std.testing.expectError(error.InternalException, encodeUnits(protected, bad, 0, big_out, exp, log));
    // Zeroed tables fail the content probe; do this last because it mutates exp.
    @memset(exp, 0);
    try std.testing.expectError(error.InternalException, encodeUnits(protected, layout, 0, out, exp, log));
}
