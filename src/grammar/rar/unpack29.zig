const std = @import("std");
const failure = @import("../../common/primitive/failure.zig");
const Failure = failure.Failure;
const checksum = @import("../../common/primitive/checksum.zig");
const bits = @import("bits.zig");
const BitReader = bits.BitReader;
const huffman = @import("huffman.zig");
const DecodeTable = huffman.DecodeTable;
const window_mod = @import("window.zig");
const Window = window_mod.Window;
const ppm_mod = @import("ppm.zig");
const PpmModel = ppm_mod.PpmModel;
const rarvm = @import("rarvm.zig");
const sink = @import("../../common/sink.zig");
const emit = @import("emit.zig");
const Sink = sink.Sink;

// RAR3/4 (v29/v36): in a solid archive the window, tables, block mode, PPM
// model, and filter programs all persist across entries.

const mc: usize = 299; // 256 literals + 43 control codes.
const dc: usize = 60;
const ldc: usize = 17;
const rc: usize = 28;
const bc: usize = 20;
const total_code_lengths: usize = mc + dc + ldc + rc;
pub const table_pool_words: usize = total_code_lengths;

// The largest standard filter is 216 bytes, so a larger length field is corrupt.
const max_vm_code_size: usize = 0x1000;

// The cap only bounds memory: the reference allows 8192, real archives use a handful.
pub const max_filters: u32 = 1024;

pub const max_pending_filters: usize = 8192;

// VM memory is 0x40000, and a filter's data must fit in half of it.
pub const max_filter_block: usize = 0x20000;

pub const PendingFilter = struct {
    filter: rarvm.StandardFilter,
    start: u64,
    length: u32,
    init_r: [7]u32,
};

// Reference SDDecode / SDBits for the 2-byte short-match symbols 263..270.
const short_distances = [8]u32{ 0, 4, 8, 16, 32, 64, 128, 192 };
const short_distance_bits = [8]u5{ 2, 2, 3, 4, 5, 6, 6, 6 };

// How many times a repeated low distance may be reused (LOW_DIST_REP_COUNT).
const low_dist_rep_count: u32 = 16;

// DDecode/DBits: the width keeps growing through the last group, so the top
// slots carry 17-18 extra bits. Saturate the width at 16 and they decode wrong.
const d_bit_length_counts = [_]u32{ 4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 14, 0, 12 };

const dist_tables = blk: {
    var decode: [dc]u32 = undefined;
    var table_bits: [dc]u5 = undefined;
    var dist: u32 = 0;
    var bit_length: u5 = 0;
    var slot: usize = 0;
    for (d_bit_length_counts) |count| {
        var j: u32 = 0;
        while (j < count) : (j += 1) {
            decode[slot] = dist;
            table_bits[slot] = bit_length;
            slot += 1;
            dist += @as(u32, 1) << bit_length;
        }
        bit_length += 1;
    }
    break :blk .{ .decode = decode, .bits = table_bits };
};
const dist_decode = dist_tables.decode;
const dist_bits = dist_tables.bits;

// LDecode holds no folded constant: a new match (symbol >= 271) adds +3 and a
// rep-distance match (259..262) adds +2, so callers add their own base.
const length_bases = [rc]u32{
    0,   1,   2,   3,   4,  5,  6,  7,
    8,   10,  12,  14,  16, 20, 24, 28,
    32,  40,  48,  56,  64, 80, 96, 112,
    128, 160, 192, 224,
};
const length_match_base: u32 = 3;
const length_rep_base: u32 = 2;

// Reference LBits, groups of FOUR after the first eight zero-width slots.
const length_extra_bits = [rc]u5{
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4,
    5, 5, 5, 5,
};

const BlockMode = enum { lz, ppm_mode };

pub const State = struct {
    // By value: bit input restarts per entry, including for solid entries, so a
    // pointer would have to stay parked between files.
    provider: checksum.Provider,
    br: BitReader,
    window: Window,
    mc: DecodeTable,
    dc_t: DecodeTable,
    ldc_t: DecodeTable,
    rc_t: DecodeTable,
    prev_distances: [4]u32,
    last_distance: u32,
    last_length: u32,
    written_size: u64,
    block_mode: BlockMode,
    tables_loaded: bool,
    // Each block encodes code lengths as a 4-bit DELTA against this table, so it must
    // persist across readTables calls; bit 0x4000 keeps it, otherwise it is zeroed.
    old_table: [total_code_lengths]u8,
    // Set when a filter program matched one of the six standard filters.
    filter_seen: rarvm.StandardFilter,
    // Set when a filter program is not one of the six: the transform cannot be
    // reproduced, so report the output unverifiable instead of unfiltered.
    unsupported_filter_seen: bool,
    // PrevLowDist / LowDistRepCount: reset at each table read.
    prev_low_dist: u32,
    low_dist_rep_count: u32,
    // A program is transmitted only on a position's first use, so the identified
    // type must persist across later invocations of that position.
    filter_types: [max_filters]rarvm.StandardFilter,
    filter_count: u32,
    last_filter: u32,
    old_filter_lengths: [max_filters]u32,
    pending: []PendingFilter,
    pending_count: usize,
    // Holding an entry entirely in the window caps it at the dictionary size, so
    // entries larger than the window must flush continuously.
    stream_out: ?Sink,
    entry_start: usize,
    flushed: usize,
    flush_threshold: usize,
    // The model persists across blocks and solid files, and only the reset bit
    // rebuilds it. The escape byte resets to 2 at each entry start.
    ppm_model: ?PpmModel,
    ppm_heap: []u8,
    ppm_esc_char: u8,
    table_pool: []u16,
    filter_scratch: []u8,

    pub fn init(
        st: *State,
        window_buffer: []u8,
        table_pool: []u16,
        pending: []PendingFilter,
        filter_scratch: []u8,
        ppm_heap: []u8,
        provider: checksum.Provider,
    ) Failure!void {
        if (table_pool.len < table_pool_words * 4) return error.InternalFailure;
        st.* = .{
            .provider = provider,
            .br = undefined,
            .window = Window.init(window_buffer),
            .mc = .{},
            .dc_t = .{},
            .ldc_t = .{},
            .rc_t = .{},
            .prev_distances = [_]u32{ 0, 0, 0, 0 },
            .last_distance = 0,
            .last_length = 0,
            .written_size = 0,
            .block_mode = .lz,
            .tables_loaded = false,
            .old_table = @splat(0),
            .filter_seen = .none,
            .unsupported_filter_seen = false,
            .prev_low_dist = 0,
            .low_dist_rep_count = 0,
            .filter_types = @splat(.none),
            .filter_count = 0,
            .last_filter = 0,
            .old_filter_lengths = @splat(0),
            .pending = pending,
            .pending_count = 0,
            .stream_out = null,
            .entry_start = 0,
            .flushed = 0,
            .flush_threshold = 0,
            .ppm_model = null,
            .ppm_heap = ppm_heap,
            .ppm_esc_char = 2,
            .table_pool = table_pool,
            .filter_scratch = filter_scratch,
        };
    }

    // A non-solid entry discards inherited tables without tearing down the window
    // or the PPM model, so the table release stays separate from the full reset.
    pub fn freeTables(st: *State) void {
        st.mc = .{};
        st.dc_t = .{};
        st.ldc_t = .{};
        st.rc_t = .{};
        st.tables_loaded = false;
    }

    pub fn readTables(st: *State) Failure!bool {
        const pool = st.table_pool;

        st.br.alignByte();

        // Peek 16 bits but consume 2, because a peek that consumes fewer bits shifts
        // the rest of the stream and every later symbol decodes as garbage.
        const bit_field = try st.br.peekBits(16);
        if (bit_field & 0x8000 != 0) {
            // Consume nothing, because the first model character reads the same
            // byte, so any bit consumed here desynchronises the PPM stream.
            st.block_mode = .ppm_mode;
            if (st.ppm_model == null) {
                st.ppm_model = PpmModel.init();
            }
            const ok = st.ppm_model.?.decodeInit(&st.br, st.ppm_heap, &st.ppm_esc_char) catch false;
            if (!ok) return error.InvalidData;
            return false;
        }

        st.block_mode = .lz;

        // ReadTables30 clears these when entering an LZ block.
        st.prev_low_dist = 0;
        st.low_dist_rep_count = 0;

        // Bit 0x4000 clear means "start from a zeroed table" instead of
        // continuing the delta chain.
        if (bit_field & 0x4000 == 0) {
            st.old_table = @splat(0);
        }
        st.br.skipBits(2);

        // The 20 code-length-alphabet lengths are 4 bits each, and a 15 is an ESCAPE
        // rather than a literal length.
        var bc_table = try huffman.readCodeLengthTable(&st.br, bc, true, pool[0 * table_pool_words ..][0..table_pool_words]);
        if (!bc_table.valid) return error.InvalidData;

        var code_lengths: [total_code_lengths]u8 = @splat(0);
        var i: usize = 0;
        while (i < total_code_lengths) {
            const sym = try huffman.decodeNumber(&st.br, &bc_table);

            if (sym < 16) {
                code_lengths[i] = @intCast((sym + st.old_table[i]) & 0x0F);
                i += 1;
            } else if (sym < 18) {
                const n: u32 = if (sym == 16)
                    3 + try st.br.readBits(3)
                else
                    11 + try st.br.readBits(7);
                // Symbol 16 cannot appear first: there is nothing to repeat and
                // code_lengths[i - 1] would underflow.
                if (i == 0) return error.InvalidData;
                var remaining = n;
                while (remaining > 0 and i < total_code_lengths) : (remaining -= 1) {
                    code_lengths[i] = code_lengths[i - 1];
                    i += 1;
                }
            } else {
                const n: u32 = if (sym == 18)
                    3 + try st.br.readBits(3)
                else
                    11 + try st.br.readBits(7);
                var remaining = n;
                while (remaining > 0 and i < total_code_lengths) : (remaining -= 1) {
                    code_lengths[i] = 0;
                    i += 1;
                }
            }
        }

        st.old_table = code_lengths;

        st.mc = try huffman.makeDecodeTables(code_lengths[0..mc], pool[0 * table_pool_words ..][0..table_pool_words]);
        st.dc_t = try huffman.makeDecodeTables(code_lengths[mc .. mc + dc], pool[1 * table_pool_words ..][0..table_pool_words]);
        st.ldc_t = try huffman.makeDecodeTables(code_lengths[mc + dc .. mc + dc + ldc], pool[2 * table_pool_words ..][0..table_pool_words]);
        st.rc_t = try huffman.makeDecodeTables(code_lengths[mc + dc + ldc .. mc + dc + ldc + rc], pool[3 * table_pool_words ..][0..table_pool_words]);

        st.tables_loaded = true;
        return true;
    }

    // RAR guarantees a filter program never crosses a Huffman block boundary.
    fn readVMCode(st: *State) Failure!void {
        const first_byte: u32 = try st.br.readBits(8);
        var length: u32 = (first_byte & 7) + 1;
        if (length == 7) {
            length = (try st.br.readBits(8)) + 7;
        } else if (length == 8) {
            length = try st.br.readBits(16);
        }
        if (length == 0 or length > max_vm_code_size) return error.InvalidData;

        var code_buf: [max_vm_code_size]u8 = undefined;
        for (0..length) |j| {
            code_buf[j] = @intCast(try st.br.readBits(8));
        }

        try st.addVMCode(first_byte, code_buf[0..length]);
    }

    fn addVMCode(st: *State, first_byte: u32, code: []const u8) Failure!void {
        // RarVM::ReadData peeks 16 bits and consumes as few as 6, so a 7-byte
        // record overruns the buffer mid-read; zero padding makes that harmless.
        var padded: [max_vm_code_size + 8]u8 = undefined;
        @memcpy(padded[0..code.len], code);
        @memset(padded[code.len .. code.len + 8], 0);
        var cr = BitReader.init(padded[0 .. code.len + 8]);

        var filt_pos: u32 = undefined;
        if (first_byte & 0x80 != 0) {
            filt_pos = try rarvm.readData(&cr);
            if (filt_pos == 0) {
                st.filter_count = 0;
            } else {
                filt_pos -= 1;
            }
        } else {
            filt_pos = st.last_filter;
        }
        if (filt_pos > st.filter_count or filt_pos >= max_filters) {
            return error.InvalidData;
        }
        st.last_filter = filt_pos;
        const new_filter = (filt_pos == st.filter_count);
        if (new_filter) {
            st.filter_types[filt_pos] = .none;
            st.filter_count += 1;
        }

        var block_start = try rarvm.readData(&cr);
        if (first_byte & 0x40 != 0) block_start += 258;

        if (first_byte & 0x20 != 0) {
            st.old_filter_lengths[filt_pos] = try rarvm.readData(&cr);
        }
        const block_length = st.old_filter_lengths[filt_pos];

        // R[4] carries the block length and R[0] the channel count for the delta and
        // audio filters; both come from the optional-parameter block.
        var init_r: [7]u32 = @splat(0);
        init_r[4] = block_length;
        if (first_byte & 0x10 != 0) {
            const init_mask = try cr.readBits(7);
            for (0..7) |j| {
                if (init_mask & (@as(u32, 1) << @intCast(j)) != 0) {
                    init_r[j] = try rarvm.readData(&cr);
                }
            }
        }

        if (new_filter) {
            const code_size = try rarvm.readData(&cr);
            if (code_size == 0 or code_size >= 0x10000) return error.InvalidData;
            if (code_size > max_vm_code_size) return error.InvalidData;
            var prog: [max_vm_code_size]u8 = undefined;
            for (0..code_size) |j| {
                prog[j] = @intCast(try cr.readBits(8));
            }
            st.filter_types[filt_pos] = rarvm.identifyFilter(st.provider, prog[0..code_size]);
        }

        const filter = st.filter_types[filt_pos];
        if (filter == .none) {
            st.unsupported_filter_seen = true;
            return;
        }
        st.filter_seen = filter;

        // BlockStart is relative to the current output position, so resolve it
        // to an absolute offset now.
        if (st.pending_count >= st.pending.len) {
            st.unsupported_filter_seen = true; // Too many to track, so report unverifiable.
            return;
        }
        st.pending[st.pending_count] = .{
            .filter = filter,
            .start = st.written_size + block_start,
            .length = block_length,
            .init_r = init_r,
        };
        st.pending_count += 1;
    }

    // Rep-distance matches use the +2 base and no distance-dependent bonus.
    fn decodeLength(st: *State) Failure!u32 {
        const slot = try huffman.decodeNumber(&st.br, &st.rc_t);
        if (slot >= rc) return error.InvalidData;
        const base = length_bases[slot] + length_rep_base;
        const extra = length_extra_bits[slot];
        if (extra == 0) return base;
        return base + try st.br.readBits(extra);
    }

    fn decodeDistance(st: *State) Failure!u32 {
        const slot = try huffman.decodeNumber(&st.br, &st.dc_t);
        if (slot >= dc) return error.InvalidData;

        var distance: u32 = dist_decode[slot] + 1;
        const table_bits = dist_bits[slot];

        if (table_bits > 0) {
            if (slot > 9) {
                // A wide distance takes its high part from the bitstream and its low 4
                // bits from the LDC table, because consecutive matches share them.
                if (table_bits > 4) {
                    const high = try st.br.readBits(table_bits - 4);
                    distance += high << 4;
                }
                if (st.low_dist_rep_count > 0) {
                    st.low_dist_rep_count -= 1;
                    distance += st.prev_low_dist;
                } else {
                    const low_dist = try huffman.decodeNumber(&st.br, &st.ldc_t);
                    if (low_dist == 16) {
                        // Symbol 16 reuses the old distance for the next
                        // LOW_DIST_REP_COUNT matches.
                        st.low_dist_rep_count = low_dist_rep_count - 1;
                        distance += st.prev_low_dist;
                    } else {
                        distance += low_dist;
                        st.prev_low_dist = low_dist;
                    }
                }
            } else {
                distance += try st.br.readBits(table_bits);
            }
        }

        return distance;
    }

    fn rotatePrevDistances(st: *State, index: usize) void {
        const dist = st.prev_distances[index];
        var i: usize = index;
        while (i > 0) : (i -= 1) {
            st.prev_distances[i] = st.prev_distances[i - 1];
        }
        st.prev_distances[0] = dist;
    }

    fn processLzSymbol(st: *State) Failure!bool {
        const symbol = try huffman.decodeNumber(&st.br, &st.mc);

        if (symbol < 256) {
            st.window.putByte(@intCast(symbol));
            st.written_size += 1;
            return true;
        }

        if (symbol == 256) {
            // End-of-block marker: "1" means a new table here, "00" a new file without a
            // fresh table, "01" a new file with one; the first case consumes 1 bit, the others 2.
            const bit_field = try st.br.peekBits(16);
            if (bit_field & 0x8000 != 0) {
                st.br.skipBits(1);
                _ = try st.readTables();
                return true;
            }
            // The second bit records TablesRead3 = !NewTable for the next entry, and a solid
            // entry consults it without re-reading tables, so it must be consumed.
            const new_table = (bit_field & 0x4000) != 0;
            st.br.skipBits(2);
            st.tables_loaded = !new_table;
            return false;
        }

        if (symbol == 257) {
            try st.readVMCode();
            return true;
        }

        if (symbol == 258) {
            if (st.last_distance == 0 or st.last_length == 0) {
                return error.InvalidData;
            }
            st.window.copyMatch(st.last_distance, @intCast(st.last_length));
            st.written_size += st.last_length;
            return true;
        }

        if (symbol >= 259 and symbol <= 262) {
            const dist_index: usize = symbol - 259;
            st.rotatePrevDistances(dist_index);
            const distance = st.prev_distances[0];
            const length = try st.decodeLength();

            st.last_distance = distance;
            st.last_length = length;
            st.window.copyMatch(distance, @intCast(length));
            st.written_size += length;
            return true;
        }

        if (symbol >= 263 and symbol <= 270) {
            const dist_index = symbol - 263;
            var distance = short_distances[dist_index] + 1;
            const dbits = short_distance_bits[dist_index];
            if (dbits > 0) {
                distance += try st.br.readBits(dbits);
            }
            const length: u32 = 2;

            st.prev_distances[3] = st.prev_distances[2];
            st.prev_distances[2] = st.prev_distances[1];
            st.prev_distances[1] = st.prev_distances[0];
            st.prev_distances[0] = distance;

            st.last_distance = distance;
            st.last_length = length;
            st.window.copyMatch(distance, length);
            st.written_size += length;
            return true;
        }

        if (symbol >= 271) {
            const length_slot: u32 = symbol - 271;
            if (length_slot >= rc) return error.InvalidData;

            const base = length_bases[length_slot] + length_match_base;
            const extra = length_extra_bits[length_slot];
            var length: u32 = base;
            if (extra > 0) {
                length += try st.br.readBits(extra);
            }

            const distance = try st.decodeDistance();

            // Distance-dependent length bonus: the encoder cannot emit a 2-byte match at
            // a large distance, so it reuses those lengths and the decoder adds the bonus back.
            if (distance >= 0x2000) {
                length += 1;
                if (distance >= 0x40000) length += 1;
            }

            st.prev_distances[3] = st.prev_distances[2];
            st.prev_distances[2] = st.prev_distances[1];
            st.prev_distances[1] = st.prev_distances[0];
            st.prev_distances[0] = distance;

            st.last_distance = distance;
            st.last_length = length;
            st.window.copyMatch(distance, @intCast(length));
            st.written_size += length;
            return true;
        }

        return error.InvalidData;
    }

    // PPMEscChar selects the in-band escape: 0 ends the PPM encoding, 1 is the escape
    // byte, 2 ends the entry, 3 is a VM filter program, 4 an LZ match, and 5 an RLE run.
    fn processPpmSymbol(st: *State) Failure!bool {
        if (st.ppm_model == null) return error.Unsupported;
        var model = &st.ppm_model.?;
        const ch = model.decodeChar(&st.br) catch return error.InvalidData;

        if (ch == st.ppm_esc_char) {
            const next = model.decodeChar(&st.br) catch return error.InvalidData;
            switch (next) {
                0 => {
                    // End of the PPM encoding, not of the entry.
                    _ = try st.readTables();
                    return true;
                },
                2 => return false,
                3 => {
                    const first_byte = model.decodeChar(&st.br) catch return error.InvalidData;
                    var length: u32 = (first_byte & 7) + 1;
                    if (length == 7) {
                        const b1 = model.decodeChar(&st.br) catch return error.InvalidData;
                        length = b1 + 7;
                    } else if (length == 8) {
                        const b1 = model.decodeChar(&st.br) catch return error.InvalidData;
                        const b2 = model.decodeChar(&st.br) catch return error.InvalidData;
                        length = b1 * 256 + b2;
                    }
                    if (length == 0 or length > max_vm_code_size) return error.InvalidData;
                    var code_buf: [max_vm_code_size]u8 = undefined;
                    for (0..length) |j| {
                        const b = model.decodeChar(&st.br) catch return error.InvalidData;
                        code_buf[j] = @intCast(b & 0xFF);
                    }
                    try st.addVMCode(first_byte, code_buf[0..length]);
                    return true;
                },
                4 => {
                    var distance: u32 = 0;
                    for (0..3) |_| {
                        const b = model.decodeChar(&st.br) catch return error.InvalidData;
                        distance = (distance << 8) + (b & 0xFF);
                    }
                    const len_b = model.decodeChar(&st.br) catch return error.InvalidData;
                    const length = (len_b & 0xFF) + 32;
                    st.window.copyMatch(distance + 2, length);
                    st.written_size += length;
                    return true;
                },
                5 => {
                    const len_b = model.decodeChar(&st.br) catch return error.InvalidData;
                    const length = (len_b & 0xFF) + 4;
                    st.window.copyMatch(1, length);
                    st.written_size += length;
                    return true;
                },
                else => {
                    // Any other value means the byte is the escape character.
                    st.window.putByte(@intCast(ch & 0xFF));
                    st.written_size += 1;
                    return true;
                },
            }
        }

        st.window.putByte(@intCast(ch & 0xFF));
        st.written_size += 1;
        return true;
    }

    // The `keep` bytes stay unemitted so a filter recorded just after its data was
    // decoded still covers its region; a filter reaching further back is refused.
    fn flushDecoded(st: *State, keep: usize, limit: u64) Failure!void {
        const out = st.stream_out orelse return;
        const produced = st.window.write_pos - st.entry_start;
        // A final match may overshoot the declared size, so never emit past it.
        const emit_upto = @min(produced -| keep, limit);
        if (emit_upto <= st.flushed) return;

        const count = emit_upto - st.flushed;
        const back = produced - st.flushed;
        if (back > st.window.buffer.len) return error.InvalidData;

        // The staged copy sits above the max_filter_block transform scratch, so both always fit.
        try emit.emitSpan(
            &st.window,
            out,
            back,
            st.flushed,
            count,
            st.pending[0..st.pending_count],
            st.filter_scratch[max_filter_block..],
            st.filter_scratch[0..max_filter_block],
            {},
            applyFilter29,
        );
        st.flushed += count;
    }

    // Run to the end-of-block marker, not to unpacked_size: the marker carries the
    // "new table" bit the next solid entry needs, and a trailing match may overshoot.
    pub fn decompressLoop(st: *State, unpacked_size: u64) Failure!void {
        if (!st.tables_loaded) {
            _ = try st.readTables();
        }

        // The encoder emits the marker where the entry ends, so a legitimate
        // overshoot is at most one match; without a bound a crafted archive could spin here.
        const overshoot_limit = unpacked_size +| st.window.buffer.len;

        while (true) {
            const should_continue = switch (st.block_mode) {
                .lz => st.processLzSymbol(),
                .ppm_mode => st.processPpmSymbol(),
            } catch |err| {
                // Input exhaustion after the declared bytes are all produced
                // is a normal end, not truncation.
                if (st.written_size >= unpacked_size) break;
                return err;
            };

            if (!should_continue) break;

            // Only entries larger than the window set stream_out, so the common path
            // pays one null check.
            if (st.stream_out != null) {
                const produced = st.window.write_pos - st.entry_start;
                if (produced - st.flushed > st.flush_threshold) {
                    try st.flushDecoded(max_filter_block, unpacked_size);
                }
            }

            if (st.written_size > overshoot_limit) return error.InvalidData;
        }
    }
};

pub const Session = struct {
    state: *State,

    pub fn init(
        st: *State,
        window_buffer: []u8,
        table_pool: []u16,
        pending: []PendingFilter,
        filter_scratch: []u8,
        ppm_heap: []u8,
        provider: checksum.Provider,
    ) Failure!Session {
        try State.init(st, window_buffer, table_pool, pending, filter_scratch, ppm_heap, provider);
        return .{ .state = st };
    }

    fn resetForNewStream(self: *Session) void {
        const st = self.state;
        st.window.reset();
        st.prev_distances = [_]u32{ 0, 0, 0, 0 };
        st.last_distance = 0;
        st.last_length = 0;
        st.freeTables();
        st.old_table = @splat(0);
        st.block_mode = .lz;
        // This reset does not destroy the PPM model, because only DecodeInit's reset bit
        // rebuilds it and a non-solid file with that bit clear would then fail.
        st.ppm_esc_char = 2;
        st.filter_types = @splat(.none);
        st.filter_count = 0;
        st.last_filter = 0;
        st.old_filter_lengths = @splat(0);
        st.prev_low_dist = 0;
        st.low_dist_rep_count = 0;
    }

    // A solid entry neither re-reads tables nor resets the window.
    pub fn decodeFile(
        self: *Session,
        packed_data: []const u8,
        unpacked_size: u64,
        solid: bool,
        out: Sink,
    ) Failure!void {
        const st = self.state;

        if (!solid) self.resetForNewStream();

        // Filter invocations never share solid files, but filter programs do, so only
        // the invocation set resets here.
        st.pending_count = 0;
        st.filter_seen = .none;
        st.unsupported_filter_seen = false;

        // The end-of-block marker peeks 16 bits but consumes 1 or 2, so the reader needs
        // slack; the reference uses the same border (ReadBorder = ReadTop - 30).
        st.br = BitReader.initPadded(packed_data, bits.default_pad_bytes);
        st.written_size = 0;

        if (unpacked_size == 0) return;

        const start_pos = st.window.write_pos;

        // Entries larger than the window must stream out as they decode; smaller ones use
        // the single emit at the end.
        st.entry_start = start_pos;
        st.flushed = 0;
        const window_len = st.window.buffer.len;
        if (unpacked_size > window_len and window_len > max_filter_block * 2) {
            st.stream_out = out;
            st.flush_threshold = window_len - max_filter_block;
        } else {
            st.stream_out = null;
        }
        defer st.stream_out = null;

        try st.decompressLoop(unpacked_size);

        // An unidentified or unimplemented filter program makes the LZ output
        // incomplete, and incomplete output is the worst outcome for an integrity tool.
        if (st.unsupported_filter_seen) return error.Unsupported;

        if (st.stream_out != null) {
            try st.flushDecoded(0, unpacked_size);
            return;
        }

        const out_size: usize = @intCast(@min(st.written_size, unpacked_size));
        const consumed = st.window.write_pos - start_pos;

        // Filters must be staged, never applied in the window, because a later solid
        // entry matches back into an earlier entry's window region.
        try emit.emitSpan(
            &st.window,
            out,
            consumed,
            0,
            out_size,
            st.pending[0..st.pending_count],
            st.filter_scratch[max_filter_block..],
            st.filter_scratch[0..max_filter_block],
            {},
            applyFilter29,
        );
    }
};

// R[6] carries the region's byte offset within the file, while start is already
// file-absolute.
fn applyFilter29(_: void, pf: *PendingFilter, region: []u8, scratch: []u8) Failure!void {
    if (region.len > scratch.len) return error.Unsupported;
    var init_r = pf.init_r;
    init_r[6] = @truncate(pf.start);
    if (!rarvm.applyFilter(pf.filter, region, scratch, init_r)) return error.Unsupported;
}

test "length tables are the verbatim reference tables" {
    const reference_ldecode = [rc]u32{
        0,   1,   2,   3,   4,  5,  6,  7,
        8,   10,  12,  14,  16, 20, 24, 28,
        32,  40,  48,  56,  64, 80, 96, 112,
        128, 160, 192, 224,
    };
    try std.testing.expectEqualSlices(u32, &reference_ldecode, &length_bases);
    try std.testing.expectEqual(@as(u32, 3), length_match_base);
    try std.testing.expectEqual(@as(u32, 2), length_rep_base);
    for (8..rc) |i| {
        const expected: u5 = @intCast((i - 8) / 4 + 1);
        try std.testing.expectEqual(expected, length_extra_bits[i]);
    }
    try std.testing.expectEqualSlices(u32, &[8]u32{ 0, 4, 8, 16, 32, 64, 128, 192 }, &short_distances);
    try std.testing.expectEqualSlices(u5, &[8]u5{ 2, 2, 3, 4, 5, 6, 6, 6 }, &short_distance_bits);
    // The width keeps growing in the last group, so the top slots carry 18 bits
    // rather than 16.
    try std.testing.expectEqual(@as(u5, 16), dist_bits[47]);
    try std.testing.expectEqual(@as(u32, 983040), dist_decode[47]);
    try std.testing.expectEqual(@as(u5, 18), dist_bits[dc - 1]);
    try std.testing.expectEqual(@as(u32, 3932160), dist_decode[dc - 1]);
}

test "alphabet size constants" {
    try std.testing.expectEqual(@as(usize, 299), mc);
    try std.testing.expectEqual(@as(usize, 60), dc);
    try std.testing.expectEqual(@as(usize, 17), ldc);
    try std.testing.expectEqual(@as(usize, 28), rc);
    try std.testing.expectEqual(@as(usize, 20), bc);
    try std.testing.expectEqual(@as(usize, 404), total_code_lengths);
}

test "distance table slots 0-3 carry no extra bits" {
    for (0..4) |slot| {
        try std.testing.expectEqual(@as(u32, 0), dist_bits[slot]);
        try std.testing.expectEqual(@as(u32, @intCast(slot)), dist_decode[slot]);
    }
    try std.testing.expectEqual(@as(u32, 4), dist_decode[4]);
    try std.testing.expectEqual(@as(u5, 1), dist_bits[4]);
}
