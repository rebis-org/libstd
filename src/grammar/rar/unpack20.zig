const std = @import("std");
const failure = @import("../../common/primitive/failure.zig");
const Failure = failure.Failure;
const bits = @import("bits.zig");
const BitReader = bits.BitReader;
const huffman = @import("huffman.zig");
const DecodeTable = huffman.DecodeTable;
const window_mod = @import("window.zig");
const Window = window_mod.Window;
const sink = @import("../../common/sink.zig");
const Sink = sink.Sink;

// RAR 2.x (v20/v26) code length tables must stay literal, because no closed form reproduces DBits saturating at 16.
// Every match pushes its distance at the write cursor, so the old-distance ring must stay circular.

const nc20: u16 = 298;
const mc20: u16 = 257; // Audio alphabet: 256 deltas plus the table-refresh code.
const dc20: u16 = 48;
const rc20: u16 = 28;
const bc20: u16 = 19; // Not 20, because v29's BC30 is 20, and a 20th length desynchronises every table read.

const max_audio_channels: u8 = 4;

// Largest symbol-length table a v20 block can declare: four audio channels at 4*257 outsize the LZ layout of 374.
const old_table_size: usize = @as(usize, mc20) * @as(usize, max_audio_channels);

pub const table_pool_words: usize = @as(usize, nc20) + dc20 + rc20 + @as(usize, mc20) * max_audio_channels;

// Symbols 261 to 268 select a 2-byte match from these distances and extra bit counts.
const short_distances = [8]u32{ 0, 4, 8, 16, 32, 64, 128, 192 };
const short_distance_bits = [8]u5{ 2, 2, 3, 4, 5, 6, 6, 6 };

// The caller adds +3 for a new match (symbol 270 or above) or +2 for a rep-distance match (symbols 257 to 260).
const length_bases = [rc20]u32{
    0,   1,   2,   3,   4,  5,  6,  7,
    8,   10,  12,  14,  16, 20, 24, 28,
    32,  40,  48,  56,  64, 80, 96, 112,
    128, 160, 192, 224,
};
const length_match_base: u32 = 3;
const length_rep_base: u32 = 2;

// Extra bits rise in groups of four after the eight zero-width slots.
const length_extra_bits = [rc20]u5{
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4,
    5, 5, 5, 5,
};

// The RAR 2.x distance table is its own, so it is neither the v29 one nor slot/2-1.
const dist_decode = [dc20]u32{
    0,      1,      2,      3,      4,      6,      8,      12,
    16,     24,     32,     48,     64,     96,     128,    192,
    256,    384,    512,    768,    1024,   1536,   2048,   3072,
    4096,   6144,   8192,   12288,  16384,  24576,  32768,  49152,
    65536,  98304,  131072, 196608, 262144, 327680, 393216, 458752,
    524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
};

// The bit counts saturate at 16 for the high slots.
const dist_bits = [dc20]u5{
    0,  0,  0,  0,  1,  1,  2,  2,
    3,  3,  4,  4,  5,  5,  6,  6,
    7,  7,  8,  8,  9,  9,  10, 10,
    11, 11, 12, 12, 13, 13, 14, 14,
    15, 15, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16,
};

fn decodeDistance(slot: u32, br: *BitReader) Failure!u32 {
    if (slot >= dc20) return error.InvalidData;
    var distance: u32 = dist_decode[slot] + 1;
    const table_bits = dist_bits[slot];
    if (table_bits > 0) {
        distance += try br.readBits(table_bits);
    }
    return distance;
}

// The predictor adapts every 32 samples by nudging one coefficient toward the bucket with the smallest accumulated difference.
// The clamp is asymmetric, [-17, 16], because each guard tests `>= -16` before the decrement.
const AudioChannel = struct {
    k1: i32 = 0,
    k2: i32 = 0,
    k3: i32 = 0,
    k4: i32 = 0,
    k5: i32 = 0,
    d1: i32 = 0,
    d2: i32 = 0,
    d3: i32 = 0,
    d4: i32 = 0,
    last_delta: i32 = 0,
    dif: [11]u32 = @splat(0),
    byte_count: u32 = 0,
    last_char: i32 = 0,

    // The channel delta is shared across channels, so this pointer carries state between calls.
    fn decode(self: *AudioChannel, channel_delta: *i32, delta_symbol: u32) u8 {
        self.byte_count +%= 1;
        self.d4 = self.d3;
        self.d3 = self.d2;
        self.d2 = self.last_delta -% self.d1;
        self.d1 = self.last_delta;
        var predicted_sample: i32 = 8 *% self.last_char +%
            self.k1 *% self.d1 +% self.k2 *% self.d2 +%
            self.k3 *% self.d3 +% self.k4 *% self.d4 +%
            self.k5 *% channel_delta.*;
        predicted_sample = (predicted_sample >> 3) & 0xFF;

        const sample: u32 = @as(u32, @bitCast(predicted_sample)) -% delta_symbol;

        // The reference scales the difference as a sign-extended byte shifted left by 3.
        const signed_delta: i32 = @as(i8, @bitCast(@as(u8, @truncate(delta_symbol))));
        const scaled_delta: i32 = @bitCast(@as(u32, @bitCast(signed_delta)) << 3);

        self.dif[0] +%= @abs(scaled_delta);
        self.dif[1] +%= @abs(scaled_delta -% self.d1);
        self.dif[2] +%= @abs(scaled_delta +% self.d1);
        self.dif[3] +%= @abs(scaled_delta -% self.d2);
        self.dif[4] +%= @abs(scaled_delta +% self.d2);
        self.dif[5] +%= @abs(scaled_delta -% self.d3);
        self.dif[6] +%= @abs(scaled_delta +% self.d3);
        self.dif[7] +%= @abs(scaled_delta -% self.d4);
        self.dif[8] +%= @abs(scaled_delta +% self.d4);
        self.dif[9] +%= @abs(scaled_delta -% channel_delta.*);
        self.dif[10] +%= @abs(scaled_delta +% channel_delta.*);

        const new_delta: i32 = @as(i8, @bitCast(@as(u8, @truncate(sample -% @as(u32, @bitCast(self.last_char))))));
        channel_delta.* = new_delta;
        self.last_delta = new_delta;
        self.last_char = @bitCast(sample);

        if ((self.byte_count & 0x1F) == 0) {
            var min_dif: u32 = self.dif[0];
            var min_bucket: usize = 0;
            self.dif[0] = 0;
            for (1..11) |i| {
                if (self.dif[i] < min_dif) {
                    min_dif = self.dif[i];
                    min_bucket = i;
                }
                self.dif[i] = 0;
            }
            switch (min_bucket) {
                1 => if (self.k1 >= -16) {
                    self.k1 -= 1;
                },
                2 => if (self.k1 < 16) {
                    self.k1 += 1;
                },
                3 => if (self.k2 >= -16) {
                    self.k2 -= 1;
                },
                4 => if (self.k2 < 16) {
                    self.k2 += 1;
                },
                5 => if (self.k3 >= -16) {
                    self.k3 -= 1;
                },
                6 => if (self.k3 < 16) {
                    self.k3 += 1;
                },
                7 => if (self.k4 >= -16) {
                    self.k4 -= 1;
                },
                8 => if (self.k4 < 16) {
                    self.k4 += 1;
                },
                9 => if (self.k5 >= -16) {
                    self.k5 -= 1;
                },
                10 => if (self.k5 < 16) {
                    self.k5 += 1;
                },
                else => {},
            }
        }
        return @truncate(sample);
    }

    fn reset(self: *AudioChannel) void {
        self.* = .{};
    }
};

const Decoder = struct {
    // A solid session outlives a single file, and bit input restarts for every entry, so the reader is stored by value.
    br: BitReader,
    window: Window,
    literal_table: DecodeTable,
    distance_table: DecodeTable,
    length_table: DecodeTable,
    audio_tables: [max_audio_channels]DecodeTable,
    // The four distances form a circular buffer whose cursor wraps instead of rotating the slots.
    old_dist: [4]u32,
    old_dist_ptr: u32,
    last_distance: u32,
    last_length: u32,
    written_size: u64,
    unpacked_size: u64,
    stream_out: ?Sink,
    entry_start: usize,
    flushed: usize,
    audio_block: bool,
    audio_channels: u8,
    cur_channel: u8,
    // Each block encodes its lengths as a 4-bit delta against the previous block, so these lengths must persist.
    old_table: [old_table_size]u8,
    // The prediction delta is shared across all channels.
    channel_delta: i32,
    tables_loaded: bool,
    audio_state: [max_audio_channels]AudioChannel,
    table_pool: []u16,

    fn init(
        st: *Decoder,
        window_buffer: []u8,
        table_pool: []u16,
    ) Failure!void {
        if (table_pool.len < table_pool_words) return error.InternalFailure;
        st.* = .{
            .br = undefined,
            .window = Window.init(window_buffer),
            .literal_table = .{},
            .distance_table = .{},
            .length_table = .{},
            .audio_tables = @splat(.{}),
            .old_dist = [_]u32{ 0, 0, 0, 0 },
            .old_dist_ptr = 0,
            .last_distance = 0,
            .last_length = 0,
            .written_size = 0,
            .unpacked_size = 0,
            .stream_out = null,
            .entry_start = 0,
            .flushed = 0,
            .audio_block = false,
            .audio_channels = 0,
            .cur_channel = 0,
            .old_table = @splat(0),
            .channel_delta = 0,
            .tables_loaded = false,
            .audio_state = @splat(.{}),
            .table_pool = table_pool,
        };
    }

    fn freeTables(st: *Decoder) void {
        st.literal_table = .{};
        st.distance_table = .{};
        st.length_table = .{};
        st.audio_tables = @splat(.{});
    }
};

fn tablePoolSlice(st: *Decoder, index: usize, comptime size: usize) []u16 {
    var offset: usize = 0;
    var i: usize = 0;
    while (i < index) : (i += 1) {
        offset += switch (i) {
            0 => nc20,
            1 => dc20,
            2 => rc20,
            else => mc20,
        };
    }
    return st.table_pool[offset..][0..size];
}

fn readTables(st: *Decoder) Failure!void {
    const br = &st.br;

    // V20 reads tables without byte alignment, because aligning discards up to 7 bits.
    // The loss stays invisible until a table refresh (symbol 269) needs an entry that spans two blocks.

    // One peeked word holds the flag bits: 0x8000 marks an audio block and 0x4000 clear zeroes the old table.
    // Two more bits give the channel count of an audio block, so the table size is MC20 * channels.
    const bit_field = try br.peekBits(16);
    st.audio_block = (bit_field & 0x8000) != 0;

    if ((bit_field & 0x4000) == 0) {
        st.old_table = @splat(0);
    }
    br.skipBits(2);

    var table_size: u16 = undefined;
    if (st.audio_block) {
        st.audio_channels = @intCast(((bit_field >> 12) & 3) + 1);
        if (st.cur_channel >= st.audio_channels) st.cur_channel = 0;
        br.skipBits(2);
        table_size = @intCast(@as(u32, mc20) * @as(u32, st.audio_channels));
    } else {
        table_size = nc20 + dc20 + rc20;
    }

    // The code-length alphabet has no length-15 escape here, unlike the v29 one.
    var code_length_table = try huffman.readCodeLengthTable(br, bc20, false, tablePoolSlice(st, 0, bc20));

    // Lengths are 4-bit deltas against the previous block, so symbol 16 repeats 3 + read(2).
    // Symbols 17 to 19 zero 3 + read(3) or 11 + read(7), which is the v20 mapping, not the v29 one.
    var code_lengths: [old_table_size]u8 = @splat(0);
    var i: u16 = 0;
    while (i < table_size) {
        const symbol = try huffman.decodeNumber(br, &code_length_table);
        if (symbol < 16) {
            code_lengths[i] = @intCast((symbol + st.old_table[i]) & 0x0f);
            i += 1;
        } else if (symbol == 16) {
            if (i == 0) return error.InvalidData;
            var repeat_count: u32 = 3 + try br.readBits(2);
            while (repeat_count > 0 and i < table_size) : (repeat_count -= 1) {
                code_lengths[i] = code_lengths[i - 1];
                i += 1;
            }
        } else {
            var repeat_count: u32 = if (symbol == 17)
                3 + try br.readBits(3)
            else
                11 + try br.readBits(7);
            while (repeat_count > 0 and i < table_size) : (repeat_count -= 1) {
                code_lengths[i] = 0;
                i += 1;
            }
        }
    }

    if (st.audio_block) {
        st.audio_tables = @splat(.{});
        for (0..st.audio_channels) |channel| {
            const offset = channel * mc20;
            st.audio_tables[channel] = try huffman.makeDecodeTables(code_lengths[offset .. offset + mc20], tablePoolSlice(st, 3 + channel, mc20));
        }
    } else {
        st.literal_table = try huffman.makeDecodeTables(code_lengths[0..nc20], tablePoolSlice(st, 0, nc20));
        st.distance_table = try huffman.makeDecodeTables(code_lengths[nc20 .. nc20 + dc20], tablePoolSlice(st, 1, dc20));
        st.length_table = try huffman.makeDecodeTables(code_lengths[nc20 + dc20 .. nc20 + dc20 + rc20], tablePoolSlice(st, 2, rc20));
    }

    @memcpy(st.old_table[0..table_size], code_lengths[0..table_size]);

    st.tables_loaded = true;
}

fn decodeLength(br: *BitReader, length_table: *const DecodeTable) Failure!u32 {
    const slot = try huffman.decodeNumber(br, length_table);
    if (slot >= rc20) return error.InvalidData;

    const base = length_bases[slot] + length_rep_base;
    const extra = length_extra_bits[slot];
    if (extra > 0) {
        return base + try br.readBits(extra);
    }
    return base;
}

// V20 has no VM filters and its multimedia mode decodes inline, so nothing reaches backwards and no reserve is held back.
// Decoded bytes must be emitted before the circular window overwrites them.
fn flushDecoded(st: *Decoder, keep: usize) Failure!void {
    const out = st.stream_out orelse return;
    const produced = st.window.write_pos - st.entry_start;
    const emit_upto = @min(produced -| keep, st.unpacked_size);
    if (emit_upto <= st.flushed) return;

    const count = emit_upto - st.flushed;
    const back = produced - st.flushed;
    if (back > st.window.buffer.len) return error.InvalidData;
    if (!st.window.emitTo(out, back, count)) return error.InvalidData;
    st.flushed += count;
}

// Half the window keeps the emit cheap while leaving ample slack for a long match.
fn flushThreshold(st: *const Decoder) usize {
    return st.window.buffer.len / 2;
}

fn unpackLoop(st: *Decoder) Failure!void {
    while (st.written_size < st.unpacked_size) {
        if (!st.tables_loaded) {
            try readTables(st);
        }

        if (st.audio_block) {
            try unpackAudioBlock(st);
        } else {
            try unpackLzBlock(st);
        }
    }
}

fn unpackAudioBlock(st: *Decoder) Failure!void {
    const br = &st.br;

    while (st.written_size < st.unpacked_size) {
        if (st.stream_out != null and
            st.window.write_pos - st.entry_start - st.flushed > flushThreshold(st))
        {
            try flushDecoded(st, 0);
        }
        if (br.remainingBits() < 1) return error.InvalidData;

        const channel = st.cur_channel;
        const symbol = try huffman.decodeNumber(br, &st.audio_tables[channel]);

        if (symbol == 256) {
            st.tables_loaded = false;
            return;
        }

        const decoded_byte = st.audio_state[channel].decode(&st.channel_delta, symbol & 0xFF);
        st.window.putByte(decoded_byte);
        st.written_size += 1;

        st.cur_channel = (st.cur_channel + 1) % st.audio_channels;
    }
}

fn unpackLzBlock(st: *Decoder) Failure!void {
    const br = &st.br;

    while (st.written_size < st.unpacked_size) {
        if (st.stream_out != null and
            st.window.write_pos - st.entry_start - st.flushed > flushThreshold(st))
        {
            try flushDecoded(st, 0);
        }
        if (br.remainingBits() < 1) return error.InvalidData;

        const symbol = try huffman.decodeNumber(br, &st.literal_table);

        if (symbol < 256) {
            st.window.putByte(@intCast(symbol));
            st.written_size += 1;
        } else if (symbol == 256) {
            if (st.last_distance == 0 or st.last_length == 0) {
                continue;
            }
            // A rep match pushes its distance and advances the cursor, because a missing push makes every later rep match read a stale slot.
            st.old_dist[st.old_dist_ptr] = st.last_distance;
            st.old_dist_ptr = (st.old_dist_ptr +% 1) & 3;
            st.window.copyMatch(st.last_distance, st.last_length);
            st.written_size += st.last_length;
        } else if (symbol >= 257 and symbol <= 260) {
            const dist_idx: u32 = symbol - 257;

            // The old-distance slot counts back from the write cursor, because V20 never rotates the ring.
            const dist = st.old_dist[(st.old_dist_ptr -% (dist_idx + 1)) & 3];

            var length = try decodeLength(br, &st.length_table);

            // The bonus tiers start at 0x101, 0x2000, and 0x40000, one tier lower than v29.
            if (dist >= 0x101) {
                length += 1;
                if (dist >= 0x2000) {
                    length += 1;
                    if (dist >= 0x40000) length += 1;
                }
            }

            st.old_dist[st.old_dist_ptr] = dist;
            st.old_dist_ptr = (st.old_dist_ptr +% 1) & 3;
            st.last_distance = dist;
            st.last_length = length;
            st.window.copyMatch(dist, length);
            st.written_size += length;
        } else if (symbol >= 261 and symbol <= 268) {
            const short_idx: u32 = symbol - 261;
            var dist = short_distances[short_idx] + 1;
            const sd_bits = short_distance_bits[short_idx];
            if (sd_bits > 0) dist += try br.readBits(sd_bits);

            st.old_dist[st.old_dist_ptr] = dist;
            st.old_dist_ptr = (st.old_dist_ptr +% 1) & 3;

            st.last_distance = dist;
            st.last_length = 2;
            st.window.copyMatch(dist, 2);
            st.written_size += 2;
        } else if (symbol == 269) {
            st.tables_loaded = false;
            return;
        } else if (symbol >= 270) {
            const length_slot: u32 = symbol - 270;
            if (length_slot >= rc20) return error.InvalidData;

            var length: u32 = blk: {
                const base = length_bases[length_slot] + length_match_base;
                const extra = length_extra_bits[length_slot];
                if (extra > 0) {
                    break :blk base + try br.readBits(extra);
                }
                break :blk base;
            };

            const dist_sym = try huffman.decodeNumber(br, &st.distance_table);
            const dist = try decodeDistance(dist_sym, br);

            // A new match gains a byte past 0x2000 and another past 0x40000, and it has no tier at 0x101.
            if (dist >= 0x2000) {
                length += 1;
                if (dist >= 0x40000) length += 1;
            }

            st.old_dist[st.old_dist_ptr] = dist;
            st.old_dist_ptr = (st.old_dist_ptr +% 1) & 3;

            st.last_distance = dist;
            st.last_length = length;
            st.window.copyMatch(dist, length);
            st.written_size += length;
        } else {
            return error.InvalidData;
        }
    }
}

pub const State = Decoder;

pub const Session = struct {
    state: *Decoder,

    pub fn init(
        st: *Decoder,
        window_buffer: []u8,
        table_pool: []u16,
    ) Failure!Session {
        try Decoder.init(st, window_buffer, table_pool);
        return .{ .state = st };
    }

    // Only a non-solid entry resets this state, because a solid entry continues from the previous one.
    fn resetForNewStream(self: *Session) void {
        const st = self.state;
        st.window.reset();
        st.old_dist = [_]u32{ 0, 0, 0, 0 };
        st.old_dist_ptr = 0;
        st.last_distance = 0;
        st.last_length = 0;
        // Zero the tables so the next block re-reads them instead of inheriting stale lengths.
        st.freeTables();
        st.tables_loaded = false;
        st.audio_block = false;
        st.audio_channels = 1;
        st.cur_channel = 0;
        st.channel_delta = 0;
        st.audio_state = @splat(.{});
        st.old_table = @splat(0);
    }

    // A solid entry must neither re-read tables nor reset the window.
    pub fn decodeFile(
        self: *Session,
        packed_data: []const u8,
        unpacked_size: u64,
        solid: bool,
        out: Sink,
    ) Failure!void {
        const st = self.state;

        if (!solid) self.resetForNewStream();

        // Bit input restarts for every entry, solid or not, because each entry has its own packed region.
        st.br = BitReader.init(packed_data);
        st.written_size = 0;
        st.unpacked_size = unpacked_size;

        if (unpacked_size == 0) return;

        const start_pos = st.window.write_pos;

        // An entry larger than the window must stream out as it decodes, because a window-held entry loses its opening bytes.
        // A RAR 2.x dictionary ranges from 64 KB to 1 MB, so an ordinary file can exceed the window.
        st.entry_start = start_pos;
        st.flushed = 0;
        st.stream_out = if (unpacked_size > st.window.buffer.len) out else null;
        defer st.stream_out = null;

        unpackLoop(st) catch |err| {
            // Running out of input after the declared byte count is success, not truncation.
            if (st.written_size < st.unpacked_size) return err;
        };

        if (st.stream_out != null) {
            try flushDecoded(st, 0);
            return;
        }

        const out_size: usize = @intCast(@min(st.written_size, st.unpacked_size));
        // A trailing match can overshoot the declared size, so measure how far the cursor actually moved.
        const consumed = st.window.write_pos - start_pos;
        if (!st.window.emitTo(out, consumed, out_size)) {
            return error.InvalidData;
        }
    }
};

test "v20 tables match the reference verbatim" {
    const ref_ldecode = [rc20]u32{
        0,   1,   2,   3,   4,  5,  6,  7,
        8,   10,  12,  14,  16, 20, 24, 28,
        32,  40,  48,  56,  64, 80, 96, 112,
        128, 160, 192, 224,
    };
    try std.testing.expectEqualSlices(u32, &ref_ldecode, &length_bases);
    for (8..rc20) |i| {
        const want: u5 = @intCast((i - 8) / 4 + 1);
        try std.testing.expectEqual(want, length_extra_bits[i]);
    }
    try std.testing.expectEqualSlices(u32, &[8]u32{ 0, 4, 8, 16, 32, 64, 128, 192 }, &short_distances);
    try std.testing.expectEqualSlices(u5, &[8]u5{ 2, 2, 3, 4, 5, 6, 6, 6 }, &short_distance_bits);
    try std.testing.expectEqual(@as(u5, 16), dist_bits[dc20 - 1]);
    try std.testing.expectEqual(@as(u32, 983040), dist_decode[dc20 - 1]);
}

test "v20 distance decode for small slots" {
    const dummy = [_]u8{0xFF};
    var br = BitReader.init(&dummy);
    try std.testing.expectEqual(@as(u32, 1), try decodeDistance(0, &br));
    try std.testing.expectEqual(@as(u32, 2), try decodeDistance(1, &br));
    try std.testing.expectEqual(@as(u32, 3), try decodeDistance(2, &br));
    try std.testing.expectEqual(@as(u32, 4), try decodeDistance(3, &br));
}

test "audio decode traces the reference for the first samples" {
    var ch = AudioChannel{};
    var cd: i32 = 0;
    try std.testing.expectEqual(@as(u8, 214), ch.decode(&cd, 42));
    try std.testing.expectEqual(@as(i32, -42), cd);
    try std.testing.expectEqual(@as(i32, -42), ch.last_delta);
    try std.testing.expectEqual(@as(u8, 214), ch.decode(&cd, 0));
    try std.testing.expectEqual(@as(i32, 0), cd);
}

test "audio adaptation fires every 32 samples and clamps at [-17, 16]" {
    var ch = AudioChannel{};
    var cd: i32 = 0;
    for (0..32 * 40) |_| _ = ch.decode(&cd, 7);
    try std.testing.expect(ch.k1 >= -17 and ch.k1 <= 16);
    try std.testing.expect(ch.k2 >= -17 and ch.k2 <= 16);
    try std.testing.expect(ch.k5 >= -17 and ch.k5 <= 16);
    const moved = ch.k1 != 0 or ch.k2 != 0 or ch.k3 != 0 or ch.k4 != 0 or ch.k5 != 0;
    try std.testing.expect(moved);
}

test "old-distance ring: rep matches count back and every match pushes" {
    var st: Decoder = undefined;
    var window_buf: [64]u8 = undefined;
    var pool: [table_pool_words]u16 = undefined;
    var session = try Session.init(&st, &window_buf, &pool);
    session.resetForNewStream();
    st.old_dist = [_]u32{ 10, 20, 30, 40 };
    st.old_dist_ptr = 0;
    const dist = st.old_dist[(st.old_dist_ptr -% (0 + 1)) & 3];
    try std.testing.expectEqual(@as(u32, 40), dist);
    st.old_dist[st.old_dist_ptr] = dist;
    st.old_dist_ptr = (st.old_dist_ptr +% 1) & 3;
    try std.testing.expectEqual(@as(u32, 40), st.old_dist[0]);
    try std.testing.expectEqual(@as(u32, 1), st.old_dist_ptr);
}
