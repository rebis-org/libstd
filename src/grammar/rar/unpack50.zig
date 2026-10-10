const std = @import("std");
const failure = @import("../../common/primitive/failure.zig");
const Failure = failure.Failure;
const bits = @import("bits.zig");
const BitReader = bits.BitReader;
const huffman = @import("huffman.zig");
const DecodeTable = huffman.DecodeTable;
const window_mod = @import("window.zig");
const Window = window_mod.Window;
const filters = @import("filters50.zig");
const sink = @import("../../common/sink.zig");
const emit = @import("emit.zig");
const Sink = sink.Sink;

// A real entry carries only a handful of filters, so a full pending list means
// the stream is undecodable, and the parser refuses it instead of guessing.

pub const nc: u16 = 306; // The alphabet holds 256 literals, 6 control, and 44 length slots.
pub const dc_rar5: u16 = 64;
pub const dc_rar7: u16 = 80;
pub const ldc: u16 = 16;
pub const rc: u16 = 44;

const code_length_symbols: u16 = 20;
const max_total_symbols: usize = nc + dc_rar7 + ldc + rc;
pub const table_pool_words: usize = max_total_symbols; // One table's worth. The caller passes four.
pub const max_pending_filters: usize = 4096;

const LengthEntry = struct { base: u32, extra: u5 };

const length_table: [rc]LengthEntry = blk: {
    var table: [rc]LengthEntry = undefined;
    for (0..8) |i| {
        table[i] = .{ .base = @intCast(i + 2), .extra = 0 };
    }
    for (8..rc) |slot| {
        const lbits: u5 = @intCast(slot / 4 - 1);
        const base: u32 = 2 + (@as(u32, 4 | @as(u32, slot & 3)) << lbits);
        table[slot] = .{ .base = base, .extra = lbits };
    }
    break :blk table;
};

// MAX_INC_LZ_MATCH is the longest single LZ match. One symbol can grow the
// unflushed span by at most this, so it bounds the window headroom.
const max_lz_match: usize = 0x1001 + 3;

pub const State = struct {
    br: BitReader,
    window: Window,
    ld: DecodeTable,
    dd: DecodeTable,
    ldd: DecodeTable,
    rd: DecodeTable,
    prev_distances: [4]u64,
    last_length: u32,
    written_size: u64,
    is_rar7: bool,
    tables_loaded: bool,
    table_pool: []u16,
    pending: []filters.Filter,
    pending_count: usize,
    stream_out: ?Sink,
    entry_start: usize,
    flushed: usize,
    filter_scratch: []u8,

    pub fn init(
        st: *State,
        window_buffer: []u8,
        table_pool: []u16, // The byte size is table_pool_words * 4.
        pending: []filters.Filter,
        filter_scratch: []u8,
        is_rar7: bool,
    ) Failure!void {
        if (table_pool.len < table_pool_words * 4) return error.InternalFailure;
        st.* = .{
            .br = undefined,
            .window = Window.init(window_buffer),
            .ld = .{},
            .dd = .{},
            .ldd = .{},
            .rd = .{},
            .prev_distances = .{ 0, 0, 0, 0 },
            .last_length = 0,
            .written_size = 0,
            .is_rar7 = is_rar7,
            .tables_loaded = false,
            .table_pool = table_pool,
            .pending = pending,
            .pending_count = 0,
            .stream_out = null,
            .entry_start = 0,
            .flushed = 0,
            .filter_scratch = filter_scratch,
        };
    }

    fn tablePool(st: *State) []u16 {
        return st.table_pool;
    }

    pub fn freeTables(st: *State) void {
        st.ld = .{};
        st.dd = .{};
        st.ldd = .{};
        st.rd = .{};
        st.tables_loaded = false;
    }
};

pub fn decodeLengthSlot(br: *BitReader, slot: u32) Failure!u32 {
    if (slot >= rc) return error.InvalidData;
    const entry = length_table[@intCast(slot)];
    if (entry.extra == 0) return entry.base;
    return entry.base + try br.readBits(entry.extra);
}

// RAR7 distances need up to 38 extra bits. The earlier-read bits are the more
// significant ones, so the sequential reads below keep the wire bit order.
fn readWideBits(br: *BitReader, bit_count: u6) Failure!u64 {
    if (bit_count == 0) return 0;
    if (bit_count <= 31) return try br.readBits(@intCast(bit_count));
    const high: u64 = try br.readBits(@intCast(bit_count - 20));
    const low: u64 = try br.readBits(20);
    return (high << 20) | low;
}

pub fn decodeDistance(br: *BitReader, dd: *const DecodeTable, ldd: *const DecodeTable) Failure!u64 {
    const dist_slot: u32 = try huffman.decodeNumber(br, dd);
    if (dist_slot < 4) return @as(u64, dist_slot) + 1;

    const extra_bits: u6 = @intCast(dist_slot / 2 - 1);
    var distance: u64 = @as(u64, 2 | (dist_slot & 1)) << extra_bits;

    if (extra_bits < 4) {
        distance += try br.readBits(@intCast(extra_bits));
    } else {
        const high_extra: u6 = extra_bits - 4;
        if (high_extra > 0) {
            distance += (try readWideBits(br, high_extra)) << 4;
        }
        distance += try huffman.decodeNumber(br, ldd);
    }

    return distance + 1;
}

fn readTables(st: *State) Failure!void {
    const br = &st.br;
    const pool = st.tablePool();

    // The 20 CL lengths are 4 bits each. A 15 is an escape: a following 0 means
    // a real length of 15, and any other value is a zero run of (value + 2).
    var cl_lengths: [code_length_symbols]u8 = @splat(0);
    {
        var cl_index: usize = 0;
        while (cl_index < code_length_symbols) {
            const length: u8 = @intCast(try br.readBits(4));
            if (length == 15) {
                const zero_count_raw: u8 = @intCast(try br.readBits(4));
                if (zero_count_raw == 0) {
                    cl_lengths[cl_index] = 15;
                    cl_index += 1;
                } else {
                    var zeros_left: usize = @as(usize, zero_count_raw) + 2;
                    while (zeros_left > 0 and cl_index < code_length_symbols) : (zeros_left -= 1) {
                        cl_lengths[cl_index] = 0;
                        cl_index += 1;
                    }
                }
            } else {
                cl_lengths[cl_index] = length;
                cl_index += 1;
            }
        }
    }

    var cl_table = try huffman.makeDecodeTables(&cl_lengths, pool[0 * table_pool_words ..][0..table_pool_words]);
    if (!cl_table.valid) return error.InvalidData;

    // RAR5 assigns code lengths for the full alphabet directly, with no delta
    // across blocks. Symbols 16 to 19 encode repeat and zero runs.
    const dc: u16 = if (st.is_rar7) dc_rar7 else dc_rar5;
    const total_symbols: usize = @as(usize, nc) + dc + ldc + rc;
    var code_lengths: [max_total_symbols]u8 = @splat(0);

    var i: usize = 0;
    while (i < total_symbols) {
        const cl_symbol = try huffman.decodeNumber(br, &cl_table);

        if (cl_symbol < 16) {
            code_lengths[i] = @intCast(cl_symbol);
            i += 1;
        } else if (cl_symbol == 16) {
            const repeat_count = 3 + try br.readBits(3);
            if (i == 0) return error.InvalidData;
            const prev_len = code_lengths[i - 1];
            var j: u32 = 0;
            while (j < repeat_count and i < total_symbols) : (j += 1) {
                code_lengths[i] = prev_len;
                i += 1;
            }
        } else if (cl_symbol == 17) {
            const repeat_count = 11 + try br.readBits(7);
            if (i == 0) return error.InvalidData;
            const prev_len = code_lengths[i - 1];
            var j: u32 = 0;
            while (j < repeat_count and i < total_symbols) : (j += 1) {
                code_lengths[i] = prev_len;
                i += 1;
            }
        } else if (cl_symbol == 18) {
            const zero_count = 3 + try br.readBits(3);
            var j: u32 = 0;
            while (j < zero_count and i < total_symbols) : (j += 1) {
                code_lengths[i] = 0;
                i += 1;
            }
        } else if (cl_symbol == 19) {
            const zero_count = 11 + try br.readBits(7);
            var j: u32 = 0;
            while (j < zero_count and i < total_symbols) : (j += 1) {
                code_lengths[i] = 0;
                i += 1;
            }
        } else {
            return error.InvalidData;
        }
    }

    var offset: usize = 0;
    st.ld = try huffman.makeDecodeTables(code_lengths[offset .. offset + nc], pool[0 * table_pool_words ..][0..table_pool_words]);
    offset += nc;
    st.dd = try huffman.makeDecodeTables(code_lengths[offset .. offset + dc], pool[1 * table_pool_words ..][0..table_pool_words]);
    offset += dc;
    st.ldd = try huffman.makeDecodeTables(code_lengths[offset .. offset + ldc], pool[2 * table_pool_words ..][0..table_pool_words]);
    offset += ldc;
    st.rd = try huffman.makeDecodeTables(code_lengths[offset .. offset + rc], pool[3 * table_pool_words ..][0..table_pool_words]);

    st.tables_loaded = true;
}

// Filter descriptor wire format: start delta, length, 3-bit filter type, and for
// DELTA a 5-bit channel count minus one. The start delta is FORWARD.
fn parseFilterDescriptor(st: *State) Failure!void {
    const br = &st.br;

    const block_start_delta = try filters.readFilterSize(br);
    const block_start = @as(usize, @intCast(st.window.write_pos)) +% block_start_delta;

    const block_length = try filters.readFilterSize(br);
    if (block_length == 0) return error.InvalidData;

    const raw_filter_type: u3 = @intCast(try br.readBits(3));
    const filter_type = filters.filterTypeFromRaw(raw_filter_type) orelse return error.Unsupported;

    var channels: u8 = 1;
    if (filter_type == .delta) {
        channels = @intCast((try br.readBits(5)) + 1);
    }

    if (st.pending_count >= st.pending.len) return error.Unsupported;
    st.pending[st.pending_count] = .{
        .filter_type = filter_type,
        .start = block_start,
        .length = block_length,
        .channels = channels,
    };
    st.pending_count += 1;
}

// A filter start is a FORWARD delta from the position where its descriptor
// appears, so no look-back reserve is needed and the cap below covers them all.
fn flushDecoded(st: *State, limit: u64) Failure!void {
    const out = st.stream_out orelse return;
    const produced = st.window.write_pos - st.entry_start;
    var emit_upto: usize = @intCast(@min(@as(u64, produced), limit));

    // Never emit INTO an unapplied filter's region: cap the span at the first
    // filter it would split, and apply that filter whole on a later flush.
    for (st.pending[0..st.pending_count]) |filter| {
        if (filter.length == 0) continue;
        const filter_start = filter.start - st.entry_start;
        if (filter_start >= st.flushed and filter_start < emit_upto and
            filter_start + filter.length > emit_upto)
        {
            emit_upto = filter_start;
        }
    }

    if (emit_upto <= st.flushed) {
        // Nothing emittable while a filter's region is still decoding. Only a
        // filter larger than the window is fatal, and that is unverifiable rather than damaged.
        if (produced - st.flushed + max_lz_match >= st.window.buffer.len) {
            return error.Unsupported;
        }
        return;
    }

    const count = emit_upto - st.flushed;
    const back = produced - st.flushed;
    if (back > st.window.buffer.len) return error.InvalidData;

    // A filter starting BEFORE the flushed mark lost part of its region to an
    // earlier emit, so a stale assumption here fails as silent wrong output.
    for (st.pending[0..st.pending_count]) |filter| {
        if (filter.length == 0) continue;
        const filter_start = filter.start - st.entry_start;
        if (filter_start < st.flushed and filter_start + filter.length > st.flushed) {
            return error.InvalidData;
        }
    }

    // The staged copy sits above a max_filter_block transform scratch. The
    // buffer is window + max_filter_block, so both always fit.
    try emit.emitSpan(
        &st.window,
        out,
        back,
        st.flushed,
        count,
        st.pending[0..st.pending_count],
        st.filter_scratch[filters.max_filter_block..],
        st.filter_scratch[0..filters.max_filter_block],
        st.entry_start,
        applyFilter50,
    );
    st.flushed += count;
}

fn decodeBlock(st: *State, unpacked_size: u64) Failure!bool {
    const br = &st.br;

    br.alignByte();

    const flags: u8 = @intCast(try br.readBits(8));
    const block_bit_size: u4 = @intCast((flags & 7) + 1);
    // The u8 annotation lets the value reach 4, which the next check rejects.
    const byte_count: u8 = @intCast(((flags >> 3) & 3) + 1);
    if (byte_count == 4) return error.InvalidData;
    const is_last_block = (flags & 0x40) != 0;
    const table_present = (flags & 0x80) != 0;

    const saved_checksum: u8 = @intCast(try br.readBits(8));

    var block_size: u32 = 0;
    for (0..byte_count) |i| {
        const b: u32 = try br.readBits(8);
        block_size += b << @intCast(i * 8);
    }

    const computed_checksum: u8 = 0x5a ^ flags ^ @as(u8, @truncate(block_size)) ^ @as(u8, @truncate(block_size >> 8)) ^ @as(u8, @truncate(block_size >> 16));
    if (computed_checksum != saved_checksum) return error.InvalidData;

    const block_start_byte = br.bit_pos / 8;

    if (table_present) try readTables(st);
    if (!st.tables_loaded) return error.InvalidData;

    const block_end_byte = block_start_byte + block_size;

    while (st.written_size < unpacked_size) {
        // Only entries larger than the window set stream_out, so the common
        // path pays one null check per symbol.
        if (st.stream_out != null) {
            const produced = st.window.write_pos - st.entry_start;
            if (produced - st.flushed > st.window.buffer.len / 2) {
                try flushDecoded(st, unpacked_size);
            }
        }

        const cur_byte = br.bit_pos / 8;
        const cur_bit: u4 = @intCast(br.bit_pos % 8);
        if (cur_byte > block_end_byte -| 1) break;
        if (cur_byte == block_end_byte -| 1 and cur_bit >= block_bit_size) break;

        const symbol: u32 = try huffman.decodeNumber(br, &st.ld);

        if (symbol < 256) {
            st.window.putByte(@intCast(symbol));
            st.written_size += 1;
        } else if (symbol == 256) {
            try parseFilterDescriptor(st);
        } else if (symbol == 257) {
            if (st.last_length == 0) return error.InvalidData;
            st.window.copyMatch(@intCast(st.prev_distances[0]), @intCast(st.last_length));
            st.written_size += st.last_length;
        } else if (symbol >= 258 and symbol <= 261) {
            const dist_index: usize = symbol - 258;
            const distance = st.prev_distances[dist_index];

            var j: usize = dist_index;
            while (j > 0) : (j -= 1) {
                st.prev_distances[j] = st.prev_distances[j - 1];
            }
            st.prev_distances[0] = distance;

            const length_slot: u32 = try huffman.decodeNumber(br, &st.rd);
            const length = try decodeLengthSlot(br, length_slot);

            st.last_length = length;
            st.window.copyMatch(@intCast(distance), @intCast(length));
            st.written_size += @as(u64, length);
        } else {
            // A new match (symbol 262 and above) adds back the bonus the encoder
            // subtracted: +1 past 0x100, +2 past 0x2000, +3 past 0x40000.
            const length_slot: u32 = symbol - 262;
            var length = try decodeLengthSlot(br, length_slot);
            const distance = try decodeDistance(br, &st.dd, &st.ldd);
            if (distance > 0x100) {
                length += 1;
                if (distance > 0x2000) {
                    length += 1;
                    if (distance > 0x40000) {
                        length += 1;
                    }
                }
            }

            st.prev_distances[3] = st.prev_distances[2];
            st.prev_distances[2] = st.prev_distances[1];
            st.prev_distances[1] = st.prev_distances[0];
            st.prev_distances[0] = distance;
            st.last_length = length;

            st.window.copyMatch(@intCast(distance), @intCast(length));
            st.written_size += @as(u64, length);
        }
    }

    return !is_last_block;
}

pub const Session = struct {
    state: *State,

    // In place: the caller carves the State out of its own storage, because
    // the struct holds about 9 KB of decode tables, so nothing here allocates.
    pub fn init(
        st: *State,
        window_buffer: []u8,
        table_pool: []u16,
        pending: []filters.Filter,
        filter_scratch: []u8,
        is_rar7: bool,
    ) Failure!Session {
        try State.init(st, window_buffer, table_pool, pending, filter_scratch, is_rar7);
        return .{ .state = st };
    }

    fn resetForNewStream(self: *Session) void {
        const st = self.state;
        st.window.reset();
        st.prev_distances = .{ 0, 0, 0, 0 };
        st.last_length = 0;
        st.freeTables();
        st.tables_loaded = false;
    }

    // A solid entry keeps the window and the tables, so its first block decodes
    // even when the header lacks TablePresent. Filters stay per entry.
    pub fn decodeFile(
        self: *Session,
        packed_data: []const u8,
        unpacked_size: u64,
        solid: bool,
        out: Sink,
    ) Failure!void {
        const st = self.state;

        if (!solid) self.resetForNewStream();
        st.pending_count = 0;

        st.br = BitReader.init(packed_data);
        st.written_size = 0;

        if (unpacked_size == 0) return;

        const start_pos = st.window.write_pos;

        // Entries larger than the window MUST stream out as they decode. Held
        // entirely in the window they lose their opening bytes.
        st.entry_start = start_pos;
        st.flushed = 0;
        st.stream_out = if (unpacked_size > st.window.buffer.len) out else null;
        defer st.stream_out = null;

        var more_blocks = true;
        while (more_blocks and st.written_size < unpacked_size) {
            more_blocks = try decodeBlock(st, unpacked_size);
        }

        if (st.stream_out != null) {
            try flushDecoded(st, unpacked_size);
            return;
        }

        const out_size: usize = @intCast(@min(unpacked_size, st.written_size));
        // A trailing match may overshoot the declared size, so measure how far
        // the cursor actually moved rather than assuming it moved out_size.
        const consumed = st.window.write_pos - start_pos;

        // Filters MUST be staged, never applied in the window, because later
        // solid entries match back into earlier window regions. Staging also linearises wrapped regions in FILE coordinates.
        try emit.emitSpan(
            &st.window,
            out,
            consumed,
            0,
            out_size,
            st.pending[0..st.pending_count],
            st.filter_scratch[filters.max_filter_block..],
            st.filter_scratch[0..filters.max_filter_block],
            start_pos,
            applyFilter50,
        );
    }
};

// E8/E8E9 relocate branch targets by the block's offset WITHIN THE FILE, so the
// entry start converts the window-stream position in a solid stream too.
fn applyFilter50(entry_start: usize, f: *filters.Filter, region: []u8, scratch: []u8) Failure!void {
    try filters.applyFilter(region, f.*, @intCast(f.start - entry_start), scratch);
}

test "length table slots match the rar5 mapping" {
    for (0..8) |i| {
        try std.testing.expectEqual(@as(u32, @intCast(i + 2)), length_table[i].base);
        try std.testing.expectEqual(@as(u5, 0), length_table[i].extra);
    }
    try std.testing.expectEqual(@as(u32, 10), length_table[8].base);
    try std.testing.expectEqual(@as(u5, 1), length_table[8].extra);
    try std.testing.expectEqual(@as(u32, 18), length_table[12].base);
    try std.testing.expectEqual(@as(u5, 2), length_table[12].extra);
    try std.testing.expectEqual(@as(u32, 34), length_table[16].base);
    try std.testing.expectEqual(@as(u5, 3), length_table[16].extra);
}

test "decodeLengthSlot: direct and extra-bit slots" {
    var data = [_]u8{0x00};
    var br = BitReader.init(&data);
    try std.testing.expectEqual(@as(u32, 2), try decodeLengthSlot(&br, 0));
    try std.testing.expectEqual(@as(u32, 9), try decodeLengthSlot(&br, 7));
    try std.testing.expectError(error.InvalidData, decodeLengthSlot(&br, 44));
}

test "decodeDistance: slot 0 returns 1" {
    var dd_lengths: [dc_rar5]u8 = @splat(0);
    dd_lengths[0] = 1;
    var pool: [table_pool_words * 4]u16 = undefined;
    const dd = try huffman.makeDecodeTables(&dd_lengths, pool[0..dc_rar5]);
    var ldd_lengths: [ldc]u8 = @splat(0);
    ldd_lengths[0] = 1;
    const ldd = try huffman.makeDecodeTables(&ldd_lengths, pool[dc_rar5..][0..ldc]);
    var data = [_]u8{0x00};
    var br = BitReader.init(&data);
    const dist = try decodeDistance(&br, &dd, &ldd);
    try std.testing.expectEqual(@as(u64, 1), dist);
}
