const std = @import("std");

const exception = @import("../../../common/primitive/exception.zig");
const sink = @import("../../../common/sink.zig");
const bits = @import("bits.zig");
const emit = @import("emit.zig");
const filters = @import("filters50.zig");
const huffman = @import("huffman.zig");
const window_mod = @import("window.zig");

const Exception = exception.Exception;
const Sink = sink.Sink;
const BitReader = bits.BitReader;
const DecodeTable = huffman.DecodeTable;
const Window = window_mod.Window;

// Real entries carry a handful of filters, so a full pending list means an undecodable stream.

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

// MAX_INC_LZ_MATCH bounds the window headroom: one symbol grows the unflushed span by at most this.
const max_lz_match: usize = 0x1001 + 3;

pub const Unpacker = struct {
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
        st: *Unpacker,
        window_buffer: []u8,
        table_pool: []u16, // The byte size is table_pool_words * 4.
        pending: []filters.Filter,
        filter_scratch: []u8,
        is_rar7: bool,
    ) Exception!void {
        if (table_pool.len < table_pool_words * 4) return error.InternalException;
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

    fn tablePool(st: *Unpacker) []u16 {
        return st.table_pool;
    }

    pub fn freeTables(st: *Unpacker) void {
        st.ld = .{};
        st.dd = .{};
        st.ldd = .{};
        st.rd = .{};
        st.tables_loaded = false;
    }
};

pub fn decodeLengthSlot(br: *BitReader, slot: u32) Exception!u32 {
    if (slot >= rc) return error.DataException;
    const entry = length_table[@intCast(slot)];
    if (entry.extra == 0) return entry.base;
    return entry.base + try br.readBits(entry.extra);
}

// RAR7 distances read up to 38 extra bits; earlier-read bits are more
// significant, so the split reads keep wire order.
fn readWideBits(br: *BitReader, bit_count: u6) Exception!u64 {
    if (bit_count == 0) return 0;
    if (bit_count <= 31) return try br.readBits(@intCast(bit_count));
    const high: u64 = try br.readBits(@intCast(bit_count - 20));
    const low: u64 = try br.readBits(20);
    return (high << 20) | low;
}

pub fn decodeDistance(br: *BitReader, dd: *const DecodeTable, ldd: *const DecodeTable) Exception!u64 {
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

fn readTables(st: *Unpacker) Exception!void {
    const br = &st.br;
    const pool = st.tablePool();

    // Each CL length is 4 bits. A 15 is an escape: 0 means length 15, otherwise a zero run.
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
    if (!cl_table.valid) return error.DataException;

    // Code lengths cover the full alphabet with no cross-block delta; symbols
    // 16 to 19 encode repeat and zero runs.
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
            if (i == 0) return error.DataException;
            const prev_len = code_lengths[i - 1];
            var j: u32 = 0;
            while (j < repeat_count and i < total_symbols) : (j += 1) {
                code_lengths[i] = prev_len;
                i += 1;
            }
        } else if (cl_symbol == 17) {
            const repeat_count = 11 + try br.readBits(7);
            if (i == 0) return error.DataException;
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
            return error.DataException;
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

// Filter descriptor: start delta, length, 3-bit type, for DELTA a 5-bit channel
// count minus one. The start delta is FORWARD.
fn parseFilterDescriptor(st: *Unpacker) Exception!void {
    const br = &st.br;

    const block_start_delta = try filters.readFilterSize(br);
    const block_start = @as(usize, @intCast(st.window.write_pos)) +% block_start_delta;

    const block_length = try filters.readFilterSize(br);
    if (block_length == 0) return error.DataException;

    const raw_filter_type: u3 = @intCast(try br.readBits(3));
    const filter_type = filters.filterTypeFromRaw(raw_filter_type) orelse return error.UnsupportedException;

    var channels: u8 = 1;
    if (filter_type == .delta) {
        channels = @intCast((try br.readBits(5)) + 1);
    }

    if (st.pending_count >= st.pending.len) return error.UnsupportedException;
    st.pending[st.pending_count] = .{
        .filter_type = filter_type,
        .start = block_start,
        .length = block_length,
        .channels = channels,
    };
    st.pending_count += 1;
}

// Filter starts are FORWARD deltas, so no look-back reserve is needed and the
// cap below covers them all.
fn flushDecoded(st: *Unpacker, limit: u64) Exception!void {
    const out = st.stream_out orelse return;
    const produced = st.window.write_pos - st.entry_start;
    var emit_upto: usize = @intCast(@min(@as(u64, produced), limit));

    // Never emit into an unapplied filter's region; cap the span at the first filter it would split.
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
        // Nothing emittable while a filter's region decodes. Only a filter larger than
        // the window is fatal, and that is unverifiable.
        if (produced - st.flushed + max_lz_match >= st.window.buffer.len) {
            return error.UnsupportedException;
        }
        return;
    }

    const count = emit_upto - st.flushed;
    const back = produced - st.flushed;
    if (back > st.window.buffer.len) return error.DataException;

    // A filter starting before the flushed mark lost region to an earlier emit;
    // proceeding would silently corrupt output.
    for (st.pending[0..st.pending_count]) |filter| {
        if (filter.length == 0) continue;
        const filter_start = filter.start - st.entry_start;
        if (filter_start < st.flushed and filter_start + filter.length > st.flushed) {
            return error.DataException;
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
        st.entry_start,
        st.pending[0..st.pending_count],
        st.filter_scratch[filters.max_filter_block..],
        st.filter_scratch[0..filters.max_filter_block],
        st.entry_start,
        applyFilter50,
    );
    st.flushed += count;
}

fn decodeBlock(st: *Unpacker, unpacked_size: u64) Exception!bool {
    const br = &st.br;

    br.alignByte();

    const flags: u8 = @intCast(try br.readBits(8));
    const block_bit_size: u4 = @intCast((flags & 7) + 1);
    // The u8 annotation lets the value reach 4, which the next check rejects.
    const byte_count: u8 = @intCast(((flags >> 3) & 3) + 1);
    if (byte_count == 4) return error.DataException;
    const is_last_block = (flags & 0x40) != 0;
    const table_present = (flags & 0x80) != 0;

    const saved_checksum: u8 = @intCast(try br.readBits(8));

    var block_size: u32 = 0;
    for (0..byte_count) |i| {
        const b: u32 = try br.readBits(8);
        block_size += b << @intCast(i * 8);
    }

    const computed_checksum: u8 = 0x5a ^ flags ^ @as(u8, @truncate(block_size)) ^ @as(u8, @truncate(block_size >> 8)) ^ @as(u8, @truncate(block_size >> 16));
    if (computed_checksum != saved_checksum) return error.DataException;

    const block_start_byte = br.bit_pos / 8;

    if (table_present) try readTables(st);
    if (!st.tables_loaded) return error.DataException;

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
            if (st.last_length == 0) return error.DataException;
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
            // New matches (symbol 262 and up) add back the encoder's bonus: +1 past
            // 0x100, +2 past 0x2000, +3 past 0x40000.
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
    state: *Unpacker,

    // In place: the struct holds about 9 KB of decode tables, so the caller
    // provides storage and nothing here allocates.
    pub fn init(
        st: *Unpacker,
        window_buffer: []u8,
        table_pool: []u16,
        pending: []filters.Filter,
        filter_scratch: []u8,
        is_rar7: bool,
    ) Exception!Session {
        try Unpacker.init(st, window_buffer, table_pool, pending, filter_scratch, is_rar7);
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

    // A solid entry keeps window and tables, so its first block decodes without
    // TablePresent; filters stay per entry.
    pub fn decodeFile(
        self: *Session,
        packed_data: []const u8,
        unpacked_size: u64,
        solid: bool,
        out: Sink,
    ) Exception!void {
        const st = self.state;

        if (!solid) self.resetForNewStream();
        st.pending_count = 0;

        st.br = BitReader.init(packed_data);
        st.written_size = 0;

        if (unpacked_size == 0) return;

        const start_pos = st.window.write_pos;

        // Entries larger than the window must stream out as they decode; held in the
        // window they lose opening bytes.
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
        // A trailing match may overshoot the declared size, so measure the cursor's
        // actual movement, not out_size.
        const consumed = st.window.write_pos - start_pos;

        // Filters must be staged, never applied in the window: later solid entries
        // match back into earlier window regions.
        try emit.emitSpan(
            &st.window,
            out,
            consumed,
            0,
            out_size,
            start_pos,
            st.pending[0..st.pending_count],
            st.filter_scratch[filters.max_filter_block..],
            st.filter_scratch[0..filters.max_filter_block],
            start_pos,
            applyFilter50,
        );
    }
};

// E8/E8E9 relocate branch targets by file offset, so the entry start converts
// window positions in solid streams.
fn applyFilter50(entry_start: usize, f: *filters.Filter, region: []u8, scratch: []u8) Exception!void {
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
    try std.testing.expectError(error.DataException, decodeLengthSlot(&br, 44));
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
