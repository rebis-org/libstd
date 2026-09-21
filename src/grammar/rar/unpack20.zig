const std = @import("std");
const failure = @import("../../common/primitive/failure.zig");
const Failure = failure.Failure;
const bits = @import("bits.zig");
const BitReader = bits.BitReader;
const huffman = @import("huffman.zig");
const DecodeTable = huffman.DecodeTable;
const window_mod = @import("window.zig");
const Window = window_mod.Window;
const sink = @import("sink.zig");
const Sink = sink.Sink;

// RAR 2.x (v20/v26) decoder. Unlike v29: no byte alignment before table
// reads, no length-15 escape, and its own rep-match bonus a tier lower. The
// old-distance ring is a true circular buffer — every match pushes its
// distance at the cursor — so v29-style rotation desynchronises it. Tables
// are verbatim from the reference (unpack20.cpp): derived versions agreed
// with the bugs they caused (DBits saturates at 16; no formula reproduces
// it).

const nc20: u16 = 298;
const mc20: u16 = 257; // audio alphabet: 256 deltas + the table-refresh code
const dc20: u16 = 48;
const rc20: u16 = 28;
const bc20: u16 = 19; // NOT 20 — v29's BC30 is 20; reading a 20th length desynchronises every table read

const max_audio_channels: u8 = 4;

// Largest symbol-length table a v20 block can declare: four audio channels
// (4*257) outsize the LZ layout (298+48+28 = 374) — reference UnpOldTable20.
const old_table_size: usize = @as(usize, mc20) * @as(usize, max_audio_channels);

pub const table_pool_words: usize = @as(usize, nc20) + dc20 + rc20 + @as(usize, mc20) * max_audio_channels;

// Reference SDDecode / SDBits for the 2-byte short matches (symbols 261..268).
const short_distances = [8]u32{ 0, 4, 8, 16, 32, 64, 128, 192 };
const short_distance_bits = [8]u5{ 2, 2, 3, 4, 5, 6, 6, 6 };

// Reference LDecode, RAW; the caller adds +3 (new match, symbol >= 270) or
// +2 (rep-distance match, symbols 257..260).
const length_bases = [rc20]u32{
    0,   1,   2,   3,   4,  5,  6,  7,
    8,   10,  12,  14,  16, 20, 24, 28,
    32,  40,  48,  56,  64, 80, 96, 112,
    128, 160, 192, 224,
};
const length_match_base: u32 = 3;
const length_rep_base: u32 = 2;

// Reference LBits — groups of FOUR after the eight zero-width slots.
const length_extra_bits = [rc20]u5{
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4,
    5, 5, 5, 5,
};

// Reference DDecode (48 entries). v20's distance table is its own — not the
// v29 one, and not slot/2-1 either.
const dist_decode = [dc20]u32{
    0,      1,      2,      3,      4,      6,      8,      12,
    16,     24,     32,     48,     64,     96,     128,    192,
    256,    384,    512,    768,    1024,   1536,   2048,   3072,
    4096,   6144,   8192,   12288,  16384,  24576,  32768,  49152,
    65536,  98304,  131072, 196608, 262144, 327680, 393216, 458752,
    524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
};

// Reference DBits — SATURATES at 16 for the high slots.
const dist_bits = [dc20]u5{
    0,  0,  0,  0,  1,  1,  2,  2,
    3,  3,  4,  4,  5,  5,  6,  6,
    7,  7,  8,  8,  9,  9,  10, 10,
    11, 11, 12, 12, 13, 13, 14, 14,
    15, 15, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16,
};

fn distanceDecode(slot: u32, br: *BitReader) Failure!u32 {
    if (slot >= dc20) return error.InvalidData;
    var distance: u32 = dist_decode[slot] + 1;
    const table_bits = dist_bits[slot];
    if (table_bits > 0) {
        distance += try br.readBits(table_bits);
    }
    return distance;
}

// RAR 2.0 audio-mode channel state — reference-exact (DecodeAudio /
// AudioVariables). The predictor adapts every 32 SAMPLES by scanning an
// 11-bucket accumulator of absolute prediction differences and nudging
// exactly ONE coefficient toward the winning hypothesis — with asymmetric
// clamps ([-17, 16]: the guard is `>= -16` BEFORE decrementing).
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
    dif: [11]u32 = [_]u32{0} ** 11,
    byte_count: u32 = 0,
    last_char: i32 = 0,

    // delta_raw is the Huffman-decoded symbol (0..255); channel_delta is the
    // SHARED cross-channel delta (reference UnpChannelDelta).
    fn decode(self: *AudioChannel, channel_delta: *i32, delta_raw: u32) u8 {
        self.byte_count +%= 1;
        self.d4 = self.d3;
        self.d3 = self.d2;
        self.d2 = self.last_delta -% self.d1;
        self.d1 = self.last_delta;
        var pch: i32 = 8 *% self.last_char +%
            self.k1 *% self.d1 +% self.k2 *% self.d2 +%
            self.k3 *% self.d3 +% self.k4 *% self.d4 +%
            self.k5 *% channel_delta.*;
        pch = (pch >> 3) & 0xFF;

        const ch: u32 = @as(u32, @bitCast(pch)) -% delta_raw;

        // D = ((signed char)Delta) << 3, via unsigned per the reference.
        const d_signed: i32 = @as(i8, @bitCast(@as(u8, @truncate(delta_raw))));
        const d: i32 = @bitCast(@as(u32, @bitCast(d_signed)) << 3);

        self.dif[0] +%= @abs(d);
        self.dif[1] +%= @abs(d -% self.d1);
        self.dif[2] +%= @abs(d +% self.d1);
        self.dif[3] +%= @abs(d -% self.d2);
        self.dif[4] +%= @abs(d +% self.d2);
        self.dif[5] +%= @abs(d -% self.d3);
        self.dif[6] +%= @abs(d +% self.d3);
        self.dif[7] +%= @abs(d -% self.d4);
        self.dif[8] +%= @abs(d +% self.d4);
        self.dif[9] +%= @abs(d -% channel_delta.*);
        self.dif[10] +%= @abs(d +% channel_delta.*);

        const new_delta: i32 = @as(i8, @bitCast(@as(u8, @truncate(ch -% @as(u32, @bitCast(self.last_char))))));
        channel_delta.* = new_delta;
        self.last_delta = new_delta;
        self.last_char = @bitCast(ch);

        if ((self.byte_count & 0x1F) == 0) {
            var min_dif: u32 = self.dif[0];
            var num_min: usize = 0;
            self.dif[0] = 0;
            for (1..11) |i| {
                if (self.dif[i] < min_dif) {
                    min_dif = self.dif[i];
                    num_min = i;
                }
                self.dif[i] = 0;
            }
            switch (num_min) {
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
        return @truncate(ch);
    }

    fn reset(self: *AudioChannel) void {
        self.* = .{};
    }
};

const Unpack20State = struct {
    // By value, not by pointer: a solid Session outlives any single file, and
    // the reference restarts bit input per entry (Inp.InitBitInput in
    // UnpInitData, called for solid entries too).
    br: BitReader,
    window: Window,
    ld: DecodeTable,
    dd: DecodeTable,
    rd: DecodeTable,
    md: [max_audio_channels]DecodeTable,
    // Reference OldDist — a CIRCULAR buffer of the last four match distances,
    // with old_dist_ptr as the write cursor.
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
    // Previous block's symbol lengths (reference UnpOldTable20); v20 encodes
    // each block as a 4-bit DELTA against this, so it must persist.
    old_table: [old_table_size]u8,
    // Shared cross-channel prediction delta (reference UnpChannelDelta).
    channel_delta: i32,
    tables_loaded: bool,
    audio_state: [max_audio_channels]AudioChannel,
    table_pool: []u16,

    fn init(
        st: *Unpack20State,
        window_buffer: []u8,
        table_pool: []u16,
    ) Failure!void {
        if (table_pool.len < table_pool_words) return error.InternalFailure;
        st.* = .{
            .br = undefined,
            .window = Window.init(window_buffer),
            .ld = .{},
            .dd = .{},
            .rd = .{},
            .md = [_]DecodeTable{.{}} ** max_audio_channels,
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
            .old_table = [_]u8{0} ** old_table_size,
            .channel_delta = 0,
            .tables_loaded = false,
            .audio_state = [_]AudioChannel{.{}} ** max_audio_channels,
            .table_pool = table_pool,
        };
    }

    fn freeTables(st: *Unpack20State) void {
        st.ld = .{};
        st.dd = .{};
        st.rd = .{};
        st.md = [_]DecodeTable{.{}} ** max_audio_channels;
    }
};

fn ldPool(st: *Unpack20State, index: usize, comptime size: usize) []u16 {
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

fn readTables(st: *Unpack20State) Failure!void {
    const br = &st.br;

    // NO byte alignment here — v20's ReadTables20 goes straight to getbits();
    // copying v29's align discards up to 7 bits. Invisible until a mid-stream
    // table refresh (symbol 269) needs an entry spanning two blocks.

    // Flag bits out of one peeked word (reference ReadTables20): 0x8000 =
    // audio block, 0x4000 clear = zero the old table, then 2 more bits give
    // the channel count when audio (TableSize = MC20 * channels).
    const bit_field = try br.peekBits(16);
    st.audio_block = (bit_field & 0x8000) != 0;

    if ((bit_field & 0x4000) == 0) {
        st.old_table = [_]u8{0} ** old_table_size;
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

    // The 19 code-length-alphabet lengths, 4 bits each. Unlike v29, v20 has
    // NO length-15 escape here.
    var bc_lengths: [bc20]u8 = undefined;
    for (0..bc20) |i| {
        bc_lengths[i] = @intCast(try br.readBits(4));
    }

    var bc_table = try huffman.makeDecodeTables(&bc_lengths, ldPool(st, 0, bc20));

    // 4-bit DELTAs against the previous block's table (why old_table must
    // persist). v20's escape mapping is its own — do not copy v29's: 16
    // repeats 3+read(2), 17 zeros 3+read(3), 18/19 zeros 11+read(7).
    var table: [old_table_size]u8 = [_]u8{0} ** old_table_size;
    var i: u16 = 0;
    while (i < table_size) {
        const sym = try huffman.decodeNumber(br, &bc_table);
        if (sym < 16) {
            table[i] = @intCast((sym + st.old_table[i]) & 0x0f);
            i += 1;
        } else if (sym == 16) {
            if (i == 0) return error.InvalidData; // nothing to repeat
            var n: u32 = 3 + try br.readBits(2);
            while (n > 0 and i < table_size) : (n -= 1) {
                table[i] = table[i - 1];
                i += 1;
            }
        } else {
            var n: u32 = if (sym == 17)
                3 + try br.readBits(3)
            else
                11 + try br.readBits(7);
            while (n > 0 and i < table_size) : (n -= 1) {
                table[i] = 0;
                i += 1;
            }
        }
    }

    if (st.audio_block) {
        st.md = [_]DecodeTable{.{}} ** max_audio_channels;
        for (0..st.audio_channels) |ch| {
            const off = ch * mc20;
            st.md[ch] = try huffman.makeDecodeTables(table[off .. off + mc20], ldPool(st, 3 + ch, mc20));
        }
    } else {
        st.ld = try huffman.makeDecodeTables(table[0..nc20], ldPool(st, 0, nc20));
        st.dd = try huffman.makeDecodeTables(table[nc20 .. nc20 + dc20], ldPool(st, 1, dc20));
        st.rd = try huffman.makeDecodeTables(table[nc20 + dc20 .. nc20 + dc20 + rc20], ldPool(st, 2, rc20));
    }

    @memcpy(st.old_table[0..table_size], table[0..table_size]);

    st.tables_loaded = true;
}

fn decodeLength(br: *BitReader, rd: *const DecodeTable) Failure!u32 {
    const slot = try huffman.decodeNumber(br, rd);
    if (slot >= rc20) return error.InvalidData;

    const base = length_bases[slot] + length_rep_base;
    const extra = length_extra_bits[slot];
    if (extra > 0) {
        return base + try br.readBits(extra);
    }
    return base;
}

// Emit decoded bytes before the circular window overwrites them. v20 has no
// VM filters — its multimedia mode is an inline decode path, not a
// post-transform over a finished region — so unlike unpack29 there is nothing
// that needs to reach backwards, and no reserve is held back.
fn flushDecoded(st: *Unpack20State, keep: usize) Failure!void {
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

// How much may accumulate unflushed before the window wraps over it. Half the
// window keeps the emit cheap while leaving ample slack for a long match.
fn flushThreshold(st: *const Unpack20State) usize {
    return st.window.buffer.len / 2;
}

fn unpackLoop(st: *Unpack20State) Failure!void {
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

fn unpackAudioBlock(st: *Unpack20State) Failure!void {
    const br = &st.br;

    while (st.written_size < st.unpacked_size) {
        if (st.stream_out != null and
            st.window.write_pos - st.entry_start - st.flushed > flushThreshold(st))
        {
            try flushDecoded(st, 0);
        }
        if (br.remainingBits() < 1) return error.InvalidData;

        const ch = st.cur_channel;
        const sym = try huffman.decodeNumber(br, &st.md[ch]);

        if (sym == 256) {
            st.tables_loaded = false;
            return;
        }

        const decoded_byte = st.audio_state[ch].decode(&st.channel_delta, sym & 0xFF);
        st.window.putByte(decoded_byte);
        st.written_size += 1;

        st.cur_channel = (st.cur_channel + 1) % st.audio_channels;
    }
}

fn unpackLzBlock(st: *Unpack20State) Failure!void {
    const br = &st.br;

    while (st.written_size < st.unpacked_size) {
        if (st.stream_out != null and
            st.window.write_pos - st.entry_start - st.flushed > flushThreshold(st))
        {
            try flushDecoded(st, 0);
        }
        if (br.remainingBits() < 1) return error.InvalidData;

        const sym = try huffman.decodeNumber(br, &st.ld);

        if (sym < 256) {
            st.window.putByte(@intCast(sym));
            st.written_size += 1;
        } else if (sym == 256) {
            if (st.last_distance == 0 or st.last_length == 0) {
                continue; // no previous match to repeat
            }
            // The reference routes this through CopyString20 too, so it ALSO
            // pushes the distance and advances the cursor. Omitting the push
            // leaves the circular buffer out of step with the encoder's, so
            // every later rep match reads a stale slot.
            st.old_dist[st.old_dist_ptr] = st.last_distance;
            st.old_dist_ptr = (st.old_dist_ptr +% 1) & 3;
            st.window.copyMatch(st.last_distance, st.last_length);
            st.written_size += st.last_length;
        } else if (sym >= 257 and sym <= 260) {
            const dist_idx: u32 = sym - 257;

            // Count back from the write cursor: OldDist[(ptr - (dist_idx+1))
            // & 3]. v20 never rotates; the next match push advances the cursor.
            const dist = st.old_dist[(st.old_dist_ptr -% (dist_idx + 1)) & 3];

            var length = try decodeLength(br, &st.rd);

            // v20's rep bonus starts a tier lower than v29's: +1 past 0x101,
            // then +1 past 0x2000, +1 past 0x40000.
            if (dist >= 0x101) {
                length += 1;
                if (dist >= 0x2000) {
                    length += 1;
                    if (dist >= 0x40000) length += 1;
                }
            }

            // A rep match pushes its distance back in as well — the reference
            // reaches CopyString20 here exactly as the new-match path does.
            st.old_dist[st.old_dist_ptr] = dist;
            st.old_dist_ptr = (st.old_dist_ptr +% 1) & 3;
            st.last_distance = dist;
            st.last_length = length;
            st.window.copyMatch(dist, length);
            st.written_size += length;
        } else if (sym >= 261 and sym <= 268) {
            const short_idx: u32 = sym - 261;
            var dist = short_distances[short_idx] + 1;
            const sd_bits = short_distance_bits[short_idx];
            if (sd_bits > 0) dist += try br.readBits(sd_bits);

            st.old_dist[st.old_dist_ptr] = dist;
            st.old_dist_ptr = (st.old_dist_ptr +% 1) & 3;

            st.last_distance = dist;
            st.last_length = 2;
            st.window.copyMatch(dist, 2);
            st.written_size += 2;
        } else if (sym == 269) {
            st.tables_loaded = false;
            return; // main loop re-reads tables
        } else if (sym >= 270) {
            const length_slot: u32 = sym - 270;
            if (length_slot >= rc20) return error.InvalidData;

            var length: u32 = blk: {
                const base = length_bases[length_slot] + length_match_base;
                const extra = length_extra_bits[length_slot];
                if (extra > 0) {
                    break :blk base + try br.readBits(extra);
                }
                break :blk base;
            };

            const dist_sym = try huffman.decodeNumber(br, &st.dd);
            const dist = try distanceDecode(dist_sym, br);

            // Distance-dependent length bonus, reference: if (Distance>=0x2000)
            // { Length++; if (Distance>=0x40000) Length++; }.
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

pub const State = Unpack20State;

pub const Session = struct {
    state: *Unpack20State,

    pub fn init(
        st: *Unpack20State,
        window_buffer: []u8,
        table_pool: []u16,
    ) Failure!Session {
        try Unpack20State.init(st, window_buffer, table_pool);
        return .{ .state = st };
    }

    // Reference UnpInitData(false) + UnpInitData20(false): everything a
    // non-solid entry starts over from. A solid entry runs NONE of this,
    // which is the whole point.
    fn resetForNewStream(self: *Session) void {
        const st = self.state;
        st.window.reset();
        st.old_dist = [_]u32{ 0, 0, 0, 0 };
        st.old_dist_ptr = 0;
        st.last_distance = 0;
        st.last_length = 0;
        // memset(&BlockTables,0,...) — force a re-read rather than inheriting.
        st.freeTables();
        st.tables_loaded = false;
        st.audio_block = false;
        st.audio_channels = 1;
        st.cur_channel = 0;
        st.channel_delta = 0;
        st.audio_state = [_]AudioChannel{.{}} ** max_audio_channels;
        st.old_table = [_]u8{0} ** old_table_size;
    }

    // The reference gate is `if ((!Solid || !TablesRead2) && !ReadTables20())`
    // — a solid entry neither re-reads tables nor resets the window.
    pub fn decodeFile(
        self: *Session,
        packed_data: []const u8,
        unpacked_size: u64,
        solid: bool,
        out: Sink,
    ) Failure!void {
        const st = self.state;

        if (!solid) self.resetForNewStream();

        // Always restarted, solid or not: each entry has its own packed
        // region (Inp.InitBitInput sits outside the `if (!Solid)`).
        st.br = BitReader.init(packed_data);
        st.written_size = 0;
        st.unpacked_size = unpacked_size;

        if (unpacked_size == 0) return;

        const start_pos = st.window.write_pos;

        // Entries larger than the window MUST stream out as they decode; held
        // entirely in the window they lose their opening bytes. v20
        // dictionaries are 64 KB-1 MB, so an ordinary file can exceed them.
        st.entry_start = start_pos;
        st.flushed = 0;
        st.stream_out = if (unpacked_size > st.window.buffer.len) out else null;
        defer st.stream_out = null;

        unpackLoop(st) catch |err| {
            // Producing the declared number of bytes and then running out of
            // input is success, not truncation.
            if (st.written_size < st.unpacked_size) return err;
        };

        if (st.stream_out != null) {
            try flushDecoded(st, 0);
            return;
        }

        const out_size: usize = @intCast(@min(st.written_size, st.unpacked_size));
        // A trailing match may overshoot the declared size, so measure how far
        // the cursor actually moved rather than assuming it moved out_size.
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
    try std.testing.expectEqual(@as(u32, 1), try distanceDecode(0, &br));
    try std.testing.expectEqual(@as(u32, 2), try distanceDecode(1, &br));
    try std.testing.expectEqual(@as(u32, 3), try distanceDecode(2, &br));
    try std.testing.expectEqual(@as(u32, 4), try distanceDecode(3, &br));
}

test "audio decode traces the reference for the first samples" {
    // Hand-traced from unrar DecodeAudio with all-zero initial state:
    // sample 1, Delta=42: prediction 0, Ch = -42, byte 214, ChannelDelta -42.
    // sample 2, Delta=0: prediction 8*(-42)>>3 = -42, Ch = -42, byte 214,
    // ChannelDelta decays to 0.
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
    var st: Unpack20State = undefined;
    var window_buf: [64]u8 = undefined;
    var pool: [table_pool_words]u16 = undefined;
    var session = try Session.init(&st, &window_buf, &pool);
    session.resetForNewStream();
    st.old_dist = [_]u32{ 10, 20, 30, 40 };
    st.old_dist_ptr = 0;
    // Symbol 257 (rep idx 0) reads OldDist[(ptr - 1) & 3] = OldDist[3].
    const dist = st.old_dist[(st.old_dist_ptr -% (0 + 1)) & 3];
    try std.testing.expectEqual(@as(u32, 40), dist);
    // Then pushes the used distance at the cursor.
    st.old_dist[st.old_dist_ptr] = dist;
    st.old_dist_ptr = (st.old_dist_ptr +% 1) & 3;
    try std.testing.expectEqual(@as(u32, 40), st.old_dist[0]);
    try std.testing.expectEqual(@as(u32, 1), st.old_dist_ptr);
}
