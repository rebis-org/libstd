const std = @import("std");

const failure_prim = @import("../common/primitive/failure.zig");
const Failure = failure_prim.Failure;

// BCJ2 (branch/call/jump filter, version 2), method ID 0x03 0x03 0x01 0x1B. The encoder
// splits x86 code into a main stream, a call stream, a jump stream, and a range-coded bitmap.

const num_probs = 258; // The E8 context comes from the previous byte, and E9 and Jcc need one each.
const bit_model_total: u16 = 1 << 11;
const num_move_bits: u5 = 5;
const rc_init_bytes = 5; // One discarded byte, then four bytes of initial code.
const top: u32 = 1 << 24;

pub fn decode(main_stream: []const u8, call_stream: []const u8, jump_stream: []const u8, rc_stream: []const u8, output: []u8) Failure!usize {
    if (rc_stream.len < rc_init_bytes) return error.InvalidData;

    var probs: [num_probs]u16 = undefined;
    for (&probs) |*prob| prob.* = bit_model_total / 2;

    var rc_pos: usize = rc_init_bytes;
    var range: u32 = 0xFFFFFFFF;
    var code: u32 = std.mem.readInt(u32, rc_stream[1..5], .big);

    var main_pos: usize = 0;
    var call_pos: usize = 0;
    var jump_pos: usize = 0;
    var out_pos: usize = 0;
    var prev_byte: u8 = 0;

    while (main_pos < main_stream.len) {
        const byte = main_stream[main_pos];
        main_pos += 1;
        if (out_pos >= output.len) return error.InsufficientCapacity;
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
            const bit = rangeDecode(&probs[index], &range, &code, rc_stream, &rc_pos);
            if (bit == 1) {
                // The call and jump streams store the target big-endian; the decoded
                // value subtracts the address of the byte after the operand.
                var address: u32 = undefined;
                if (use_call_stream) {
                    if (call_pos + 4 > call_stream.len) return error.InvalidData;
                    address = std.mem.readInt(u32, call_stream[call_pos..][0..4], .big);
                    call_pos += 4;
                } else {
                    if (jump_pos + 4 > jump_stream.len) return error.InvalidData;
                    address = std.mem.readInt(u32, jump_stream[jump_pos..][0..4], .big);
                    jump_pos += 4;
                }
                address -%= @as(u32, @intCast(out_pos + 4));
                if (out_pos + 4 > output.len) return error.InsufficientCapacity;
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

    return out_pos;
}

fn rangeDecode(prob: *u16, range: *u32, code: *u32, stream: []const u8, pos: *usize) u1 {
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
        range.* <<= 8;
        // The ip7z/7zip decoders read a missing byte of a short
        // range-code stream as zero.
        const next_byte: u32 = if (pos.* < stream.len) stream[pos.*] else 0;
        code.* = (code.* << 8) | next_byte;
        pos.* += 1;
    }
    return bit;
}

test "bcj2 no-branch passthrough" {
    const rc = [_]u8{ 0, 0, 0, 0, 0 };
    var out: [12]u8 = undefined;
    const n = try decode("hello world!", &.{}, &.{}, &rc, &out);
    try std.testing.expectEqual(@as(usize, 12), n);
    try std.testing.expectEqualSlices(u8, "hello world!", out[0..n]);
}

test "bcj2 single E8 call branch" {
    // The main stream is NOP*10, E8, NOP*17, the call stream carries the absolute target
    // 0x64 (= 0x55 relative + opcode position 15), and the range coder encodes a set bit.
    var main_buf: [28]u8 = undefined;
    for (main_buf[0..10]) |*b| b.* = 0x90;
    main_buf[10] = 0xE8;
    for (main_buf[11..28]) |*b| b.* = 0x90;
    const call_buf = [_]u8{ 0, 0, 0, 0x64 };
    const rc_buf = [_]u8{ 0, 0xFF, 0xFF, 0xFF, 0xFF }; // The initial code decodes every bit as 1.

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
    const jump_buf = [_]u8{ 0, 0, 0, 0x0C }; // The absolute target 12 becomes 3, since 12 - (5 + 4).
    const rc_buf = [_]u8{ 0, 0xFF, 0xFF, 0xFF, 0xFF };

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
    const jump_buf = [_]u8{ 0, 0, 0, 0x0B }; // The absolute target 11 becomes 5, since 11 - (2 + 4).
    const rc_buf = [_]u8{ 0, 0xFF, 0xFF, 0xFF, 0xFF };

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
    const rc_buf = [_]u8{ 0, 0xFF, 0xFF, 0xFF, 0xFF };
    var out: [16]u8 = undefined;
    // The rc stream is shorter than the five initialization bytes.
    try std.testing.expectError(error.InvalidData, decode(&main_buf, &.{}, &.{}, rc_buf[0..4], &out));
    // A confirmed branch has no 4-byte target in the call stream.
    try std.testing.expectError(error.InvalidData, decode(&main_buf, &.{}, &.{}, &rc_buf, &out));
    // The output holds less than one confirmed branch.
    try std.testing.expectError(error.InsufficientCapacity, decode(&main_buf, &[_]u8{ 0, 0, 0, 0x10 }, &.{}, &rc_buf, out[0..3]));
}

test "bcj2 call then jump through one range-code word" {
    // One rc word drives both branch bits without a normalization pull, so both
    // prob contexts (E8, then E9) decode a set bit from it.
    var main_buf: [10]u8 = undefined;
    for (&main_buf) |*b| b.* = 0x90;
    main_buf[0] = 0xE8;
    main_buf[5] = 0xE9;
    const call_buf = [_]u8{ 0, 0, 0, 0x10 }; // The absolute target 0x10 becomes 0x0B.
    const jump_buf = [_]u8{ 0, 0, 0, 0x20 }; // The absolute target 0x20 becomes 0x12.
    const rc_buf = [_]u8{ 0, 0xFF, 0xFF, 0xFF, 0xFF };

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
