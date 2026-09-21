const std = @import("std");
const failure = @import("../../common/primitive/failure.zig");
const Failure = failure.Failure;
const bits = @import("bits.zig");
const BitReader = bits.BitReader;

// Range-boundary decode tables in the reference form (unrar's
// DecodeLen/DecodePos/DecodeNum), which accepts the slightly over-committed
// tables real archives contain. decode_num lives in caller storage so the
// whole decode context carves out of one workspace.

pub const max_code_length: u5 = 15;
pub const max_quick_bits: u5 = 9;
pub const quick_table_size: usize = 1 << max_quick_bits;

pub const QuickEntry = struct {
    symbol: u16 = 0,
    length: u5 = 0, // 0 means the full decode path must run
};

pub const DecodeTable = struct {
    quick_table: [quick_table_size]QuickEntry = [_]QuickEntry{.{}} ** quick_table_size,
    decode_len: [max_code_length + 2]u32 = [_]u32{0} ** (max_code_length + 2),
    decode_pos: [max_code_length + 2]u32 = [_]u32{0} ** (max_code_length + 2),
    decode_num: []u16 = &.{},
    max_num: u16 = 0,
    quick_bits: u5 = max_quick_bits,
    valid: bool = false,
};

// Reads a code-length-alphabet table: `count` 4-bit lengths, then the decode
// table built from them. With `escapes` (v29), a 15 is an ESCAPE — the next
// 4 bits are a zero-run count, 0 meaning the length really is 15 — and a run
// that overruns `count` is truncated, as in the reference. v20 has no escape
// and reads its lengths verbatim.
pub fn readCodeLengthTable(br: *BitReader, count: usize, comptime escapes: bool, storage: []u16) Failure!DecodeTable {
    var lengths = [_]u8{0} ** 64;
    var i: usize = 0;
    while (i < count) {
        const length: u8 = @intCast(try br.readBits(4));
        if (escapes and length == 15) {
            const zero_count: u8 = @intCast(try br.readBits(4));
            if (zero_count == 0) {
                lengths[i] = 15;
            } else {
                // ZeroCount+2 zeros; the loop increment lands past the run
                // (the reference does I-- after its inner while).
                var remaining: u32 = @as(u32, zero_count) + 2;
                while (remaining > 0 and i < count) : (remaining -= 1) {
                    lengths[i] = 0;
                    i += 1;
                }
                i -|= 1;
            }
        } else {
            lengths[i] = length;
        }
        i += 1;
    }
    return makeDecodeTables(lengths[0..count], storage);
}

// storage.len bounds the table: every present symbol must fit.
pub fn makeDecodeTables(code_lengths: []const u8, storage: []u16) Failure!DecodeTable {
    var table = DecodeTable{};
    table.max_num = @intCast(code_lengths.len);

    var len_count = [_]u32{0} ** (max_code_length + 2);
    for (code_lengths) |cl| {
        if (cl > 0 and cl <= max_code_length) len_count[cl] += 1;
    }

    table.decode_len[0] = 0;
    table.decode_pos[0] = 0;
    var total_symbols: u32 = 0;
    for (1..max_code_length + 1) |len| {
        table.decode_len[len] = table.decode_len[len - 1] + (len_count[len] << @intCast(16 - len));
        table.decode_pos[len] = total_symbols;
        total_symbols += len_count[len];
    }
    table.decode_len[max_code_length + 1] = 0x10000; // sentinel for the slow path
    table.decode_pos[max_code_length + 1] = total_symbols;

    if (total_symbols == 0) return table; // invalid: nothing to decode
    if (total_symbols > storage.len) return error.InternalFailure;

    table.decode_num = storage[0..total_symbols];
    var tmp_pos: [max_code_length + 2]u32 = undefined;
    for (0..max_code_length + 2) |i| tmp_pos[i] = table.decode_pos[i];
    for (code_lengths, 0..) |cl, i| {
        if (cl > 0 and cl <= max_code_length) {
            const pos = tmp_pos[cl];
            if (pos < total_symbols) table.decode_num[pos] = @intCast(i);
            tmp_pos[cl] += 1;
        }
    }

    // Large alphabets (v20/v29/v50 main tables) peek wider so short codes stay
    // on the single-lookup path; small ones keep a compact table.
    const size = code_lengths.len;
    table.quick_bits = if (size == 306 or size == 298 or size == 299)
        max_quick_bits
    else if (max_quick_bits > 3)
        max_quick_bits - 3
    else
        0;

    const quick_data_size: usize = @as(usize, 1) << table.quick_bits;
    var cur_bit_length: usize = 1;
    for (0..quick_data_size) |quick_val| {
        const bit_field: u32 = @as(u32, @intCast(quick_val)) << @intCast(16 - table.quick_bits);
        while (cur_bit_length < max_code_length + 1 and bit_field >= table.decode_len[cur_bit_length]) {
            cur_bit_length += 1;
        }
        table.quick_table[quick_val].length = @intCast(cur_bit_length);
        const prev_boundary = if (cur_bit_length > 0) table.decode_len[cur_bit_length - 1] else 0;
        const dist = (bit_field -| prev_boundary) >> @intCast(16 - cur_bit_length);
        const pos = table.decode_pos[cur_bit_length] + dist;
        if (cur_bit_length < max_code_length + 1 and pos < size) {
            table.quick_table[quick_val].symbol = table.decode_num[pos];
        } else {
            table.quick_table[quick_val].symbol = 0;
        }
    }

    table.valid = true;
    return table;
}

pub fn decodeNumber(br: *BitReader, table: *const DecodeTable) Failure!u16 {
    if (!table.valid) return error.InvalidData;

    const bits_available = br.remainingBits();
    if (bits_available == 0) return error.InvalidData;

    const peek_count: u5 = if (bits_available >= 16) 16 else @intCast(bits_available);
    const peeked = try br.peekBits(peek_count);
    const bit_field: u32 = if (peek_count < 16)
        peeked << @intCast(16 - peek_count)
    else
        peeked;

    const qb = table.quick_bits;
    if (bit_field < table.decode_len[qb]) {
        const quick_idx: u32 = bit_field >> @intCast(16 - qb);
        const quick = table.quick_table[@intCast(quick_idx)];
        if (quick.length > 0 and quick.length <= peek_count) {
            br.skipBits(quick.length);
            return quick.symbol;
        }
    }

    var code_len: u5 = max_code_length;
    {
        var len: usize = @as(usize, qb) + 1;
        while (len < max_code_length) : (len += 1) {
            if (bit_field < table.decode_len[len]) {
                code_len = @intCast(len);
                break;
            }
        }
    }

    if (code_len <= peek_count) {
        br.skipBits(code_len);
    } else {
        br.skipBits(peek_count);
    }

    const prev_boundary = if (code_len > 0) table.decode_len[code_len - 1] else 0;
    var n: u32 = table.decode_pos[code_len] + ((bit_field -| prev_boundary) >> @intCast(16 - code_len));
    if (n >= table.max_num or n >= table.decode_num.len) n = 0;

    return table.decode_num[@intCast(n)];
}

pub fn resetTable(table: *DecodeTable) void {
    table.* = .{};
}

test "decode table builds canonical ranges" {
    const code_lengths = [_]u8{ 1, 2, 2 };
    var storage: [3]u16 = undefined;
    const table = try makeDecodeTables(&code_lengths, &storage);
    try std.testing.expect(table.valid);
    try std.testing.expectEqual(@as(u32, 0x8000), table.decode_len[1]);
    try std.testing.expectEqual(@as(u32, 0x10000), table.decode_len[2]);
    try std.testing.expectEqualSlices(u16, &[_]u16{ 0, 1, 2 }, table.decode_num);
}

test "decode number round-trips short codes" {
    // Codes: A=0, B=10, C=11; stream A B C A = 0x58.
    const code_lengths = [_]u8{ 1, 2, 2 };
    var storage: [3]u16 = undefined;
    const table = try makeDecodeTables(&code_lengths, &storage);
    const data = [_]u8{0x58};
    var br = BitReader.init(&data);
    try std.testing.expectEqual(@as(u16, 0), try decodeNumber(&br, &table));
    try std.testing.expectEqual(@as(u16, 1), try decodeNumber(&br, &table));
    try std.testing.expectEqual(@as(u16, 2), try decodeNumber(&br, &table));
    try std.testing.expectEqual(@as(u16, 0), try decodeNumber(&br, &table));
}

test "decode number handles codes longer than the quick width" {
    const code_lengths = [_]u8{ 1, 2, 3, 11, 11 };
    var storage: [5]u16 = undefined;
    const table = try makeDecodeTables(&code_lengths, &storage);
    // Symbol 3 (code 1792) then symbol 4 (code 1793).
    const data = [_]u8{ 0xE0, 0x1C, 0x04 };
    var br = BitReader.init(&data);
    try std.testing.expectEqual(@as(u16, 3), try decodeNumber(&br, &table));
    try std.testing.expectEqual(@as(u16, 4), try decodeNumber(&br, &table));
}

test "all-zero lengths build an invalid table" {
    const code_lengths = [_]u8{ 0, 0, 0, 0 };
    var storage: [4]u16 = undefined;
    const table = try makeDecodeTables(&code_lengths, &storage);
    try std.testing.expect(!table.valid);
}

test "decode number on empty stream fails" {
    const code_lengths = [_]u8{ 1, 2, 2 };
    var storage: [3]u16 = undefined;
    const table = try makeDecodeTables(&code_lengths, &storage);
    var br = BitReader.init(&[_]u8{});
    try std.testing.expectError(error.InvalidData, decodeNumber(&br, &table));
}
