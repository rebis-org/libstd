const std = @import("std");

const exception_prim = @import("../../../common/primitive/exception.zig");

const Exception = exception_prim.Exception;

// BCJ2 branch converter (0x03 0x03 0x01 0x1B): x86 code splits into main, call,
// and jump streams plus a range-coded bitmap.

const num_probs = 258; // The E8 context comes from the previous byte, and E9 and Jcc need one each.
const bit_model_total: u16 = 1 << 11;
const num_move_bits: u5 = 5;
const rc_init_bytes = 5; // One discarded byte, then four bytes of initial code.
const top: u32 = 1 << 24;

pub fn decode(main_stream: []const u8, call_stream: []const u8, jump_stream: []const u8, rc_stream: []const u8, output: []u8) Exception!usize {
    if (rc_stream.len < rc_init_bytes) return error.DataException;
    // The vendor requires the discarded init byte to be zero.
    if (rc_stream[0] != 0) return error.DataException;

    var probs: [num_probs]u16 = undefined;
    for (&probs) |*prob| prob.* = bit_model_total / 2;

    var rc_pos: usize = rc_init_bytes;
    var range: u32 = 0xFFFFFFFF;
    var code: u32 = std.mem.readInt(u32, rc_stream[1..5], .big);
    // The vendor rejects a full-scale initial code.
    if (code == 0xFFFFFFFF) return error.DataException;

    var main_pos: usize = 0;
    var call_pos: usize = 0;
    var jump_pos: usize = 0;
    var out_pos: usize = 0;
    var prev_byte: u8 = 0;

    while (main_pos < main_stream.len) {
        const byte = main_stream[main_pos];
        main_pos += 1;
        if (out_pos >= output.len) return error.CapacityException;
        output[out_pos] = byte;
        out_pos += 1;

        var prob_index: ?usize = null;
        var use_call_stream = false;
        if (byte == 0xE8) {
            prob_index = prev_byte;
            use_call_stream = true;
        } else if (byte == 0xE9) {
            prob_index = 256;
        } else if (byte >= 0x80 and byte <= 0x8F and prev_byte == 0x0F) {
            prob_index = 257;
        }

        if (prob_index) |index| {
            const bit = try rangeDecode(&probs[index], &range, &code, rc_stream, &rc_pos);
            if (bit == 1) {
                // The call and jump streams store the target address big-endian; the
                // decode subtracts the byte-after-operand address.
                var address: u32 = undefined;
                if (use_call_stream) {
                    if (call_pos + 4 > call_stream.len) return error.DataException;
                    address = std.mem.readInt(u32, call_stream[call_pos..][0..4], .big);
                    call_pos += 4;
                } else {
                    if (jump_pos + 4 > jump_stream.len) return error.DataException;
                    address = std.mem.readInt(u32, jump_stream[jump_pos..][0..4], .big);
                    jump_pos += 4;
                }
                // Vendor keeps the instruction pointer in a u32 that wraps past 4 GiB.
                address -%= @truncate(out_pos + 4);
                if (out_pos + 4 > output.len) return error.CapacityException;
                output[out_pos] = @truncate(address);
                output[out_pos + 1] = @truncate(address >> 8);
                output[out_pos + 2] = @truncate(address >> 16);
                output[out_pos + 3] = @truncate(address >> 24);
                prev_byte = output[out_pos + 3];
                out_pos += 4;
                continue;
            }
        }
        prev_byte = byte;
    }

    // A finished stream leaves the range coder at code zero; 7-Zip's
    // Bcj2Dec_IsMaybeFinished_code rejects any other final state.
    if (code != 0) return error.DataException;
    return out_pos;
}

fn rangeDecode(prob: *u16, range: *u32, code: *u32, stream: []const u8, pos: *usize) Exception!u1 {
    const bound: u32 = (range.* >> 11) *% @as(u32, prob.*);
    var bit: u1 = undefined;
    if (code.* < bound) {
        range.* = bound;
        prob.* +%= @intCast((@as(u32, bit_model_total) - prob.*) >> num_move_bits);
        bit = 0;
    } else {
        range.* -= bound;
        code.* -= bound;
        prob.* -%= @intCast(prob.* >> num_move_bits);
        bit = 1;
    }
    if (range.* < top) {
        // 7-Zip stops when the rc stream runs dry; a one-shot complete
        // stream that needs another byte is truncated, not zero padded.
        if (pos.* >= stream.len) return error.DataException;
        range.* <<= 8;
        code.* = (code.* << 8) | stream[pos.*];
        pos.* += 1;
    }
    return bit;
}

pub const EncodedSizes = struct { main: usize, call: usize, jump: usize, rc: usize };

// Main, call, and jump never exceed the input; each rc bit at worst halves the range, a byte eight bits.
pub fn encodeSizesBound(input_len: usize) EncodedSizes {
    return .{
        .main = input_len,
        .call = input_len,
        .jump = input_len,
        .rc = input_len / 4 + 64,
    };
}

const relat_limit: u32 = @as(u32, 0x0f) << 24;

// The vendor's carry-aware Subbotin range encoder: pending 0xFF bytes ride in
// (cache, cache_size); the first byte is the discarded init.
const RangeEncoder = struct {
    low: u64 = 0,
    range: u32 = 0xFFFFFFFF,
    cache: u8 = 0,
    cache_size: u32 = 1,
    out: []u8 = &.{},
    len: usize = 0,

    fn shiftLow(self: *RangeEncoder) Exception!void {
        const low32: u32 = @truncate(self.low);
        const high: u32 = @truncate(self.low >> 32);
        if (low32 < 0xFF000000 or high != 0) {
            const carry: u8 = @truncate(high);
            if (self.len >= self.out.len) return error.CapacityException;
            self.out[self.len] = self.cache +% carry;
            self.len += 1;
            var remaining = self.cache_size - 1;
            while (remaining > 0) : (remaining -= 1) {
                if (self.len >= self.out.len) return error.CapacityException;
                // The carry reaches every pending byte, not only the first.
                self.out[self.len] = 0xFF +% carry;
                self.len += 1;
            }
            self.cache_size = 1;
            self.cache = @truncate(low32 >> 24);
        } else {
            self.cache_size += 1;
        }
        self.low = low32 << 8;
    }

    fn encodeBit(self: *RangeEncoder, prob: *u16, bit: u1) Exception!void {
        const bound: u32 = (self.range >> 11) *% @as(u32, prob.*);
        if (bit == 0) {
            self.range = bound;
            prob.* +%= @intCast((@as(u32, bit_model_total) - prob.*) >> num_move_bits);
        } else {
            self.low += bound;
            self.range -= bound;
            prob.* -%= @intCast(prob.* >> num_move_bits);
        }
        // The decoder mirrors this single-shift-per-symbol schedule, so the
        // two sides stay in lockstep even when range dips below the top.
        if (self.range < top) {
            try self.shiftLow();
            self.range <<= 8;
        }
    }
};

// Conversion decisions match vendor Bcj2Enc.c (fileIp 0, default relative
// limit, multi-block overlap guard); the probability layout is not wire format.
pub fn encode(input: []const u8, main_out: []u8, call_out: []u8, jump_out: []u8, rc_out: []u8) Exception!EncodedSizes {
    var probs: [num_probs]u16 = undefined;
    for (&probs) |*prob| prob.* = bit_model_total / 2;

    var rc = RangeEncoder{ .out = rc_out };
    var main_len: usize = 0;
    var call_len: usize = 0;
    var jump_len: usize = 0;

    var ip: u64 = 0;
    var v: u32 = 0;
    var pos: usize = 0;
    while (pos < input.len) {
        const b = input[pos];
        if (main_len >= main_out.len) return error.CapacityException;
        main_out[main_len] = b;
        main_len += 1;
        v = (v << 24) | b;
        const is_e8e9 = ((b +% (0x100 - 0xe8)) & 0xfe) == 0;
        const is_jcc = ((v -% ((@as(u32, 0x0f) << 24) + 0x80)) & 0xfffffff0) == 0;
        if (!is_e8e9 and !is_jcc) {
            pos += 1;
            ip += 1;
            continue;
        }
        pos += 1;
        ip += 1;
        const prob_index: usize = if (b == 0xe8) @as(usize, @intCast(v >> 24)) else if (b == 0xe9) 256 else 257;
        var convert = false;
        if (input.len - pos >= 4) {
            const relat = std.mem.readInt(u32, input[pos..][0..4], .little);
            if (ip > @as(u64, (v +% 0x20) >> 5 & 1) and ((relat +% relat_limit) >> 1) < relat_limit)
                convert = true;
        }
        if (convert) {
            const relat = std.mem.readInt(u32, input[pos..][0..4], .little);
            try rc.encodeBit(&probs[prob_index], 1);
            const absol: u32 = @as(u32, @truncate(ip)) +% relat +% 4;
            if (b == 0xe8) {
                if (call_len + 4 > call_out.len) return error.CapacityException;
                std.mem.writeInt(u32, call_out[call_len..][0..4], absol, .big);
                call_len += 4;
            } else {
                if (jump_len + 4 > jump_out.len) return error.CapacityException;
                std.mem.writeInt(u32, jump_out[jump_len..][0..4], absol, .big);
                jump_len += 4;
            }
            ip += 4;
            pos += 4;
            v = relat >> 24;
        } else {
            try rc.encodeBit(&probs[prob_index], 0);
        }
    }
    // The flush emits the four code bytes after the discarded init byte.
    for (0..5) |_| try rc.shiftLow();
    return .{ .main = main_len, .call = call_len, .jump = jump_len, .rc = rc.len };
}

// A finished range-coder tail sets the initial code to the sum of the decoded
// bounds, so the forced set bits leave code at zero (7-Zip finished state).
const finished_rc_one = [_]u8{ 0, 0x7F, 0xFF, 0xFC, 0x00 };
const finished_rc_two = [_]u8{ 0, 0xBF, 0xFF, 0xFC, 0x00 };

test "bcj2 no-branch passthrough" {
    const rc = [_]u8{ 0, 0, 0, 0, 0 };
    var out: [12]u8 = undefined;
    const n = try decode("hello world!", &.{}, &.{}, &rc, &out);
    try std.testing.expectEqual(@as(usize, 12), n);
    try std.testing.expectEqualSlices(u8, "hello world!", out[0..n]);
}

test "bcj2 single E8 call branch" {
    // NOP*10, E8, NOP*17; the call stream's absolute target address 0x64 decodes
    // to relative 0x55 at opcode position 15.
    var main_buf: [28]u8 = undefined;
    for (main_buf[0..10]) |*b| b.* = 0x90;
    main_buf[10] = 0xE8;
    for (main_buf[11..28]) |*b| b.* = 0x90;
    const call_buf = [_]u8{ 0, 0, 0, 0x64 };
    const rc_buf = finished_rc_one; // The initial code decodes the branch bit as 1 and finishes at code zero.

    var out: [32]u8 = undefined;
    const n = try decode(&main_buf, &call_buf, &.{}, &rc_buf, &out);
    try std.testing.expectEqual(@as(usize, 32), n);
    var expected: [32]u8 = undefined;
    for (expected[0..10]) |*b| b.* = 0x90;
    expected[10] = 0xE8;
    expected[11] = 0x55;
    expected[12] = 0;
    expected[13] = 0;
    expected[14] = 0;
    for (expected[15..32]) |*b| b.* = 0x90;
    try std.testing.expectEqualSlices(u8, &expected, out[0..n]);
}

test "bcj2 single E9 jump branch" {
    var main_buf: [8]u8 = undefined;
    for (main_buf[0..4]) |*b| b.* = 0x90;
    main_buf[4] = 0xE9;
    for (main_buf[5..8]) |*b| b.* = 0x90;
    const jump_buf = [_]u8{ 0, 0, 0, 0x0C }; // The absolute target address 12 becomes 3, since 12 - (5 + 4).
    const rc_buf = finished_rc_one;

    var out: [12]u8 = undefined;
    const n = try decode(&main_buf, &.{}, &jump_buf, &rc_buf, &out);
    try std.testing.expectEqual(@as(usize, 12), n);
    var expected: [12]u8 = undefined;
    for (expected[0..4]) |*b| b.* = 0x90;
    expected[4] = 0xE9;
    expected[5] = 3;
    expected[6] = 0;
    expected[7] = 0;
    expected[8] = 0;
    for (expected[9..12]) |*b| b.* = 0x90;
    try std.testing.expectEqualSlices(u8, &expected, out[0..n]);
}

test "bcj2 single 0F 8x conditional jump" {
    // A Jcc (0x0F 0x85) draws from the jump stream through context 257.
    const main_buf = [_]u8{ 0x0F, 0x85 };
    const jump_buf = [_]u8{ 0, 0, 0, 0x0B }; // The absolute target address 11 becomes 5, since 11 - (2 + 4).
    const rc_buf = finished_rc_one;

    var out: [6]u8 = undefined;
    const n = try decode(&main_buf, &.{}, &jump_buf, &rc_buf, &out);
    try std.testing.expectEqual(@as(usize, 6), n);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x0F, 0x85, 5, 0, 0, 0 }, out[0..n]);
}

test "bcj2 candidate opcode without a branch" {
    // A zero bit leaves the E8 literal and consumes no target bytes.
    const main_buf = [_]u8{ 0xE8, 1, 2, 3, 4 };
    const rc_buf = [_]u8{ 0, 0, 0, 0, 0 }; // The initial code decodes every bit as 0.

    var out: [5]u8 = undefined;
    const n = try decode(&main_buf, &.{}, &.{}, &rc_buf, &out);
    try std.testing.expectEqual(@as(usize, 5), n);
    try std.testing.expectEqualSlices(u8, &main_buf, out[0..n]);
}

test "bcj2 truncations are errors" {
    var main_buf: [4]u8 = undefined;
    for (&main_buf) |*b| b.* = 0x90;
    main_buf[0] = 0xE8;
    const rc_buf = finished_rc_one;
    var out: [16]u8 = undefined;
    // The rc stream is shorter than the five initialization bytes.
    try std.testing.expectError(error.DataException, decode(&main_buf, &.{}, &.{}, rc_buf[0..4], &out));
    // A confirmed branch has no 4-byte target in the call stream.
    try std.testing.expectError(error.DataException, decode(&main_buf, &.{}, &.{}, &rc_buf, &out));
    // The output holds less than one confirmed branch.
    try std.testing.expectError(error.CapacityException, decode(&main_buf, &[_]u8{ 0, 0, 0, 0x10 }, &.{}, &rc_buf, out[0..3]));
}

test "bcj2 call then jump through one range-code word" {
    // One rc word drives both branch bits without normalization, so both
    // probability contexts (E8, then E9) decode a set bit.
    var main_buf: [10]u8 = undefined;
    for (&main_buf) |*b| b.* = 0x90;
    main_buf[0] = 0xE8;
    main_buf[5] = 0xE9;
    const call_buf = [_]u8{ 0, 0, 0, 0x10 }; // The absolute target address 0x10 becomes 0x0B.
    const jump_buf = [_]u8{ 0, 0, 0, 0x20 }; // The absolute target address 0x20 becomes 0x12.
    const rc_buf = finished_rc_two;

    var out: [18]u8 = undefined;
    const n = try decode(&main_buf, &call_buf, &jump_buf, &rc_buf, &out);
    try std.testing.expectEqual(@as(usize, 18), n);
    try std.testing.expectEqual(@as(u8, 0xE8), out[0]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x0B, 0, 0, 0 }, out[1..5]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x90, 0x90, 0x90, 0x90 }, out[5..9]);
    try std.testing.expectEqual(@as(u8, 0xE9), out[9]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0, 0, 0 }, out[10..14]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x90, 0x90, 0x90, 0x90 }, out[14..18]);
}

test "bcj2 encode roundtrips through the decoder" {
    const allocator = std.testing.allocator;
    // Synthetic x86-ish code: NOP sleds, calls, jumps, a Jcc, and data
    // bytes that must stay literal.
    var input: [4096]u8 = undefined;
    var rng: u64 = 0x243F6A8885A308D3;
    for (&input) |*b| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        b.* = @as(u8, @truncate(rng)) & 3;
    }
    // Pad with sleds and plant branch instructions at varied offsets.
    for (0..16) |i| {
        const at = i * 256;
        @memset(input[at..][0..200], 0x90);
        input[at + 200] = 0xE8;
        std.mem.writeInt(u32, input[at + 201 ..][0..4], @intCast(1000 -% @as(u32, @intCast(at % 2000))), .little);
        @memset(input[at + 205 ..][0..40], 0x90);
        input[at + 245] = 0xE9;
        std.mem.writeInt(u32, input[at + 246 ..][0..4], @intCast(2000 -% @as(u32, @intCast(at % 3000))), .little);
        input[at + 250] = 0x0F;
        input[at + 251] = 0x85;
        std.mem.writeInt(u32, input[at + 252 ..][0..4], @intCast(3000 -% @as(u32, @intCast(at % 4000))), .little);
    }

    const bounds = encodeSizesBound(input.len);
    const main_buf = try allocator.alloc(u8, bounds.main);
    defer allocator.free(main_buf);
    const call_buf = try allocator.alloc(u8, bounds.call);
    defer allocator.free(call_buf);
    const jump_buf = try allocator.alloc(u8, bounds.jump);
    defer allocator.free(jump_buf);
    const rc_buf = try allocator.alloc(u8, bounds.rc);
    defer allocator.free(rc_buf);

    const sizes = try encode(&input, main_buf, call_buf, jump_buf, rc_buf);
    try std.testing.expect(sizes.call > 0);
    try std.testing.expect(sizes.jump > 0);
    // The branch targets left main: a filter that kept every byte in the
    // main stream would still roundtrip.
    try std.testing.expect(sizes.main < input.len);

    var out: [input.len]u8 = undefined;
    const n = try decode(main_buf[0..sizes.main], call_buf[0..sizes.call], jump_buf[0..sizes.jump], rc_buf[0..sizes.rc], &out);
    try std.testing.expectEqual(input.len, n);
    try std.testing.expectEqualSlices(u8, &input, out[0..n]);

    // A second pass over the same input is byte-identical (determinism).
    const main2 = try allocator.alloc(u8, bounds.main);
    defer allocator.free(main2);
    const call2 = try allocator.alloc(u8, bounds.call);
    defer allocator.free(call2);
    const jump2 = try allocator.alloc(u8, bounds.jump);
    defer allocator.free(jump2);
    const rc2 = try allocator.alloc(u8, bounds.rc);
    defer allocator.free(rc2);
    const sizes2 = try encode(&input, main2, call2, jump2, rc2);
    try std.testing.expectEqual(sizes.main, sizes2.main);
    try std.testing.expectEqualSlices(u8, main_buf[0..sizes.main], main2[0..sizes2.main]);
    try std.testing.expectEqualSlices(u8, rc_buf[0..sizes.rc], rc2[0..sizes2.rc]);
}

test "bcj2 encode stream sizes respect their bounds" {
    var input: [64]u8 = undefined;
    for (&input) |*b| b.* = 0xE8;
    var main: [64]u8 = undefined;
    var call: [64]u8 = undefined;
    var jump: [64]u8 = undefined;
    var rc: [16 + 64]u8 = undefined;
    const sizes = try encode(&input, &main, &call, &jump, &rc);
    // E8 at position 0 cannot convert (the ip guard requires ip > 0); the
    // relative limit rejects the zero-paged offsets.
    try std.testing.expect(sizes.main == 64);
}

test "bcj2 shiftLow propagates carry through pending bytes" {
    var out: [8]u8 = undefined;
    var rc = RangeEncoder{
        .cache = 0x12,
        .cache_size = 3,
        .low = 0x0000_0001_FF00_0000, // high is 1, low32 is 0xFF000000.
        .out = &out,
    };
    try rc.shiftLow();
    try std.testing.expectEqual(@as(usize, 3), rc.len);
    // Without the carry, the two pending bytes stay 0xFF.
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x13, 0x00, 0x00 }, out[0..rc.len]);
}

test "bcj2 encode roundtrips across range-coder carries" {
    const allocator = std.testing.allocator;
    var input: [512]u8 = undefined;
    var rng: u64 = 0x9E3779B97F4A7C15;

    const bounds = encodeSizesBound(input.len);
    const main_buf = try allocator.alloc(u8, bounds.main);
    defer allocator.free(main_buf);
    const call_buf = try allocator.alloc(u8, bounds.call);
    defer allocator.free(call_buf);
    const jump_buf = try allocator.alloc(u8, bounds.jump);
    defer allocator.free(jump_buf);
    const rc_buf = try allocator.alloc(u8, bounds.rc);
    defer allocator.free(rc_buf);
    var out: [input.len]u8 = undefined;

    // Plant markers with varied offsets so the range coder reaches carry states.
    for (0..256) |_| {
        for (&input) |*b| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            b.* = @truncate(rng);
        }
        var i: usize = 2;
        while (i + 5 <= input.len) : (i += 8) {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            input[i] = switch (@as(u8, @truncate(rng)) & 3) {
                0 => 0xE8,
                1 => 0xE9,
                else => 0x0F,
            };
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            std.mem.writeInt(u32, input[i + 1 ..][0..4], @truncate(rng), .little);
        }

        const sizes = try encode(&input, main_buf, call_buf, jump_buf, rc_buf);
        const n = try decode(main_buf[0..sizes.main], call_buf[0..sizes.call], jump_buf[0..sizes.jump], rc_buf[0..sizes.rc], &out);
        try std.testing.expectEqual(input.len, n);
        try std.testing.expectEqualSlices(u8, &input, out[0..n]);
    }
}

test "bcj2 decode rejects nonzero init byte" {
    var out: [8]u8 = undefined;
    try std.testing.expectError(error.DataException, decode("hi", &.{}, &.{}, &[_]u8{ 1, 0, 0, 0, 0 }, &out));
    const n = try decode("hi", &.{}, &.{}, &[_]u8{ 0, 0, 0, 0, 0 }, &out);
    try std.testing.expectEqual(@as(usize, 2), n);
}

test "bcj2 decode rejects full-scale initial code" {
    var out: [8]u8 = undefined;
    try std.testing.expectError(error.DataException, decode("hi", &.{}, &.{}, &[_]u8{ 0, 0xFF, 0xFF, 0xFF, 0xFF }, &out));
    // A completed no-branch stream carries a zero initial code.
    const n = try decode("hi", &.{}, &.{}, &[_]u8{ 0, 0, 0, 0, 0 }, &out);
    try std.testing.expectEqual(@as(usize, 2), n);
}

test "bcj2 decode rejects non-finished final range-coder state" {
    // A truncated-in-spirit stream decodes its branch bit but ends with a
    // non-zero code; 7-Zip rejects that state instead of returning output.
    const main_buf = [_]u8{ 0xE8, 0x90, 0x90, 0x90 };
    const rc_buf = [_]u8{ 0, 0xFF, 0xFF, 0xFF, 0xFE };
    var out: [16]u8 = undefined;
    try std.testing.expectError(error.DataException, decode(&main_buf, &[_]u8{ 0, 0, 0, 0x10 }, &.{}, &rc_buf, &out));
}

test "bcj2 truncated range-coder stream is rejected" {
    const allocator = std.testing.allocator;
    // Many E8 candidates drive the range coder into normalization, so the
    // rc stream runs past the five initialization bytes.
    var input: [256]u8 = undefined;
    for (&input) |*b| b.* = 0xE8;
    const bounds = encodeSizesBound(input.len);
    const main_buf = try allocator.alloc(u8, bounds.main);
    defer allocator.free(main_buf);
    const call_buf = try allocator.alloc(u8, bounds.call);
    defer allocator.free(call_buf);
    const jump_buf = try allocator.alloc(u8, bounds.jump);
    defer allocator.free(jump_buf);
    const rc_buf = try allocator.alloc(u8, bounds.rc);
    defer allocator.free(rc_buf);
    const sizes = try encode(&input, main_buf, call_buf, jump_buf, rc_buf);
    try std.testing.expect(sizes.rc > rc_init_bytes);

    var out: [input.len]u8 = undefined;
    const n = try decode(main_buf[0..sizes.main], call_buf[0..sizes.call], jump_buf[0..sizes.jump], rc_buf[0..sizes.rc], &out);
    try std.testing.expectEqual(input.len, n);
    // Cutting the last rc byte leaves a normalization read with no byte;
    // the decoder must report a data error, not pad with zero.
    try std.testing.expectError(error.DataException, decode(main_buf[0..sizes.main], call_buf[0..sizes.call], jump_buf[0..sizes.jump], rc_buf[0 .. sizes.rc - 1], &out));
}
