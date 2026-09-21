const std = @import("std");
const failure = @import("../../common/primitive/failure.zig");
const Failure = failure.Failure;
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

// RAR3/4 (v29/v36) decoder. The stateful legacy engine: in a solid archive
// the window, tables, block mode, PPM model, and filter programs all persist
// across entries. Tables are verbatim from the reference (unpack30.cpp):
// every arithmetic derivation tried upstream grouped extra-bit widths in
// pairs where the real tables group in fours, and small payloads never reach
// the diverging slots — green unit tests, undecodable real archives.

const mc: usize = 299; // 256 literals + 43 control codes
const dc: usize = 60;
const ldc: usize = 17;
const rc: usize = 28;
const bc: usize = 20;
const total_code_lengths: usize = mc + dc + ldc + rc;
pub const table_pool_words: usize = total_code_lengths;

// Upper bound on a RAR3 filter program (the largest standard filter is 216
// bytes; the length field can encode more, which is rejected as corrupt).
const max_vm_code_size: usize = 0x1000;

// Distinct filter programs tracked per stream. The reference allows 8192;
// real archives use a handful, and the cap only needs to bound memory.
pub const max_filters: u32 = 1024;

// Filter applications tracked for one file.
pub const max_pending_filters: usize = 8192;

// Largest filter block processed in one go (reference VM memory is 0x40000
// and a filter's data must fit in half of it).
pub const max_filter_block: usize = 0x20000;

// Largest live table (the LD alphabet); one table's worth of decode_num words
// per table, four tables.
pub const PendingFilter = struct {
    filter: rarvm.StandardFilter,
    start: u64,
    length: u32,
    init_r: [7]u32,
};

// Reference SDDecode / SDBits for the 2-byte short-match symbols 263..270.
const short_distances = [8]u32{ 0, 4, 8, 16, 32, 64, 128, 192 };
const short_distance_bits = [8]u5{ 2, 2, 3, 4, 5, 6, 6, 6 };

// How many times a repeated low distance may be reused (reference
// LOW_DIST_REP_COUNT).
const low_dist_rep_count: u32 = 16;

// Reference DDecode/DBits (vendor/unrar/unpack30.cpp), built at comptime by
// the same DBitLengthCounts loop the reference runs: the bit width keeps
// growing through the last group, so the top slots carry 17-18 extra bits
// and reach past 4 MB. Do not "saturate" this at 16 — that is the v20 table.
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

// Reference LDecode, RAW — no constant folded in. The same table is used with
// two different bases: new match (symbol >= 271) adds +3, rep-distance match
// (259..262) adds +2. Callers add their own constant.
const length_bases = [rc]u32{
    0,   1,   2,   3,   4,  5,  6,  7,
    8,   10,  12,  14,  16, 20, 24, 28,
    32,  40,  48,  56,  64, 80, 96, 112,
    128, 160, 192, 224,
};
const length_match_base: u32 = 3;
const length_rep_base: u32 = 2;

// Reference LBits — groups of FOUR after the first eight zero-width slots.
const length_extra_bits = [rc]u5{
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4,
    5, 5, 5, 5,
};

const BlockMode = enum { lz, ppm_mode };

pub const State = struct {
    // By value, not by pointer: a solid Session outlives any single file, and
    // the reference restarts bit input per entry (Inp.InitBitInput in
    // UnpInitData, called for solid entries too). Holding a pointer would
    // mean parking a dangling one between files.
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
    // Previous block's code lengths (the reference UnpOldTable). v29 encodes
    // each block's lengths as a 4-bit DELTA against this, so it must persist
    // across readTables() calls. A block may also ask to keep it (BitField &
    // 0x4000); when that bit is clear the table is zeroed.
    old_table: [total_code_lengths]u8,
    // Set when a filter program was recognised as one of the six standard
    // filters; applying it is the next step.
    filter_seen: rarvm.StandardFilter,
    // Set when a filter program was NOT one of the six. The transform cannot
    // be reproduced at all, so the output must be reported unverifiable
    // rather than silently unfiltered.
    unsupported_filter_seen: bool,
    // Low-distance repeat state (reference PrevLowDist / LowDistRepCount).
    // Reset at each table read, as ReadTables30 does.
    prev_low_dist: u32,
    low_dist_rep_count: u32,
    // Identified type of each filter program, indexed by filter position. A
    // program is transmitted only on a position's first use; later
    // invocations reference it, so the type must persist.
    filter_types: [max_filters]rarvm.StandardFilter,
    filter_count: u32,
    last_filter: u32,
    old_filter_lengths: [max_filters]u32,
    pending: []PendingFilter,
    pending_count: usize,
    // Streaming-output state, used ONLY for entries larger than the window.
    // The reference flushes decoded bytes continuously (UnpWriteBuf); holding
    // an entry entirely in the window silently caps it at the dictionary size
    // and its opening bytes get overwritten by its own tail.
    stream_out: ?Sink,
    entry_start: usize,
    flushed: usize,
    flush_threshold: usize,
    // PPM state. The model persists across blocks and (solid) files; only
    // DecodeInit's reset bit rebuilds it. esc_char is the in-band escape
    // byte, reset to 2 per UnpInitData30.
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
    ) Failure!void {
        if (table_pool.len < table_pool_words * 4) return error.InternalFailure;
        st.* = .{
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
            .old_table = [_]u8{0} ** total_code_lengths,
            .filter_seen = .none,
            .unsupported_filter_seen = false,
            .prev_low_dist = 0,
            .low_dist_rep_count = 0,
            .filter_types = [_]rarvm.StandardFilter{.none} ** max_filters,
            .filter_count = 0,
            .last_filter = 0,
            .old_filter_lengths = [_]u32{0} ** max_filters,
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

    // Release the four LZ decode tables, leaving the state ready to rebuild
    // them. Separate from the full reset because a non-solid entry has to
    // discard inherited tables (reference: memset(&BlockTables,0,...) in
    // UnpInitData) without tearing down the window or the PPM model.
    pub fn freeTables(st: *State) void {
        st.mc = .{};
        st.dc_t = .{};
        st.ldc_t = .{};
        st.rc_t = .{};
        st.tables_loaded = false;
    }

    // Read Huffman tables from the bitstream (RAR3 format). Returns true if
    // tables were loaded (LZ mode), false if switching to PPM.
    pub fn readTables(st: *State) Failure!bool {
        const pool = st.table_pool;

        // Step 1: Align to byte boundary.
        st.br.alignByte();

        // Step 2: TWO flag bits, read by peeking 16 and consuming 2
        // (reference ReadTables30: fgetbits peeks, faddbits(2) consumes both).
        // The previous single-bit consumption shifted the entire rest of the
        // stream by one bit, so every table and symbol decoded as garbage.
        const bit_field = try st.br.peekBits(16);
        if (bit_field & 0x8000 != 0) {
            // PPM mode. Consume NOTHING: the reference peeks this flag and
            // then DecodeInit's first GetChar reads the SAME byte — its bits
            // 0-4 are the order, bit 5 the reset flag, bit 6 "escape char
            // follows". Consuming even one flag bit here desynchronises the
            // entire PPM stream from its first byte.
            st.block_mode = .ppm_mode;
            if (st.ppm_model == null) {
                // The MODEL persists across blocks and (solid) files; only
                // DecodeInit's reset bit rebuilds it.
                st.ppm_model = PpmModel.init();
            }
            const ok = st.ppm_model.?.decodeInit(&st.br, st.ppm_heap, &st.ppm_esc_char) catch false;
            if (!ok) return error.InvalidData;
            return false;
        }

        // LZ mode
        st.block_mode = .lz;

        // ReadTables30 clears these when entering an LZ block.
        st.prev_low_dist = 0;
        st.low_dist_rep_count = 0;

        // 0x4000 clear means "start from a zeroed table" rather than
        // continuing the delta chain from the previous block.
        if (bit_field & 0x4000 == 0) {
            st.old_table = [_]u8{0} ** total_code_lengths;
        }
        st.br.skipBits(2);

        // Step 3: the 20 code-length-alphabet lengths, 4 bits each; a 15 is
        // an ESCAPE, not a literal length (see readCodeLengthTable).
        var bc_table = try huffman.readCodeLengthTable(&st.br, bc, true, pool[0 * table_pool_words ..][0..table_pool_words]);
        if (!bc_table.valid) return error.InvalidData;

        // Symbol lengths via the CL table: 0..15 are DELTAs against the old
        // table; 16 repeats 3+read(3), 17 repeats 11+read(7), 18 zeros
        // 3+read(3), 19 zeros 11+read(7).
        var code_lengths: [total_code_lengths]u8 = [_]u8{0} ** total_code_lengths;
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
                // "Repeat previous" cannot appear first — there is nothing to
                // repeat, and reading code_lengths[i-1] would underflow.
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

        // Step 7: Split code lengths and build 4 tables.
        st.mc = try huffman.makeDecodeTables(code_lengths[0..mc], pool[0 * table_pool_words ..][0..table_pool_words]);
        st.dc_t = try huffman.makeDecodeTables(code_lengths[mc .. mc + dc], pool[1 * table_pool_words ..][0..table_pool_words]);
        st.ldc_t = try huffman.makeDecodeTables(code_lengths[mc + dc .. mc + dc + ldc], pool[2 * table_pool_words ..][0..table_pool_words]);
        st.rc_t = try huffman.makeDecodeTables(code_lengths[mc + dc + ldc .. mc + dc + ldc + rc], pool[3 * table_pool_words ..][0..table_pool_words]);

        st.tables_loaded = true;
        return true;
    }

    // Read a filter program from the bitstream (reference ReadVMCode). Layout:
    // one length byte whose low 3 bits give (len-1); the escape values 7 and 8
    // introduce an 8-bit or 16-bit length. The program bytes follow; RAR
    // guarantees a filter program never crosses a Huffman block boundary.
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

    // Filter invocation record (reference AddVMCode), bit-packed with its own
    // reader: optional new position (0 resets the set), block start (+258 if
    // 0x40), optional block length (else reuse), register-init mask + values,
    // and the program itself only on a position's first use.
    fn addVMCode(st: *State, first_byte: u32, code: []const u8) Failure!void {
        // RarVM::ReadData peeks 16 bits and consumes as few as 6, so a 7-byte
        // record overruns the buffer mid-read; the reference's over-allocated
        // zero padding makes that harmless there — reproduce it.
        var padded: [max_vm_code_size + 8]u8 = undefined;
        @memcpy(padded[0..code.len], code);
        @memset(padded[code.len .. code.len + 8], 0);
        var cr = BitReader.init(padded[0 .. code.len + 8]);

        var filt_pos: u32 = undefined;
        if (first_byte & 0x80 != 0) {
            filt_pos = try rarvm.readData(&cr);
            if (filt_pos == 0) {
                st.filter_count = 0; // filter set reset
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

        // R[4] carries the block length; R[0] is the channel count for the
        // delta/audio filters. Both come from the optional-parameter block.
        var init_r = [_]u32{0} ** 7;
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
            st.filter_types[filt_pos] = rarvm.identifyFilter(prog[0..code_size]);
        }

        const filter = st.filter_types[filt_pos];
        if (filter == .none) {
            // Not one of the six standard programs. We cannot reproduce the
            // transform, so the output must be reported unverifiable.
            st.unsupported_filter_seen = true;
            return;
        }
        st.filter_seen = filter;

        // Record where this filter applies. BlockStart is relative to the
        // current output position, so resolve it to an absolute offset now.
        if (st.pending_count >= st.pending.len) {
            st.unsupported_filter_seen = true; // too many to track; do not guess
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

    // Decode a length from the RC table (rep-distance path: LDecode[n] + 2 +
    // extra; no distance-dependent bonus — the reference applies that only to
    // new matches).
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
                // Wide distance: the high part comes from the bitstream, and
                // the low 4 bits come from the LDC table — with a repeat
                // mechanism, because consecutive matches often share them.
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
                        // Symbol 16 means "reuse the previous low distance for
                        // the next LOW_DIST_REP_COUNT matches".
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

    // Process one LZ symbol from the MC table. False means end of block/file.
    fn processLzSymbol(st: *State) Failure!bool {
        const symbol = try huffman.decodeNumber(&st.br, &st.mc);

        if (symbol < 256) {
            st.window.putByte(@intCast(symbol));
            st.written_size += 1;
            return true;
        }

        if (symbol == 256) {
            // End-of-block marker (reference ReadEndOfBlock): "1" = new table
            // here, "00" = new file without, "01" = new file with a fresh table
            // next. One bit in the first case, two in the others.
            const bit_field = try st.br.peekBits(16);
            if (bit_field & 0x8000 != 0) {
                st.br.skipBits(1);
                _ = try st.readTables();
                return true; // same file continues with the new table
            }
            // New file. The second bit records TablesRead3 = !NewTable for
            // the next entry; a solid entry consults it without re-reading
            // tables, so dropping it desynchronises the shared stream from its
            // first symbol.
            const new_table = (bit_field & 0x4000) != 0;
            st.br.skipBits(2);
            st.tables_loaded = !new_table;
            return false; // new file — this one is done
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

            // Distance-dependent length bonus. The encoder cannot emit a
            // 2-byte match at a large distance, so those short lengths are
            // reused to mean longer matches and the decoder adds the bonus
            // back (reference: if (Distance>=0x2000) { Length++; if
            // (Distance>=0x40000) Length++; }, applied to NEW matches only).
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

    // PPM in-band escape protocol (PPMEscChar): 0 = end of PPM encoding, an
    // LZ block may follow in the same entry; 1 = the escape byte itself;
    // 2 = end of file; 3 = VM filter code; 4 = LZ match (3 distance bytes +
    // length, +32/+2); 5 = RLE (len+4, distance 1). True continues, false ends
    // the entry.
    fn processPpmSymbol(st: *State) Failure!bool {
        if (st.ppm_model == null) return error.Unsupported;
        var model = &st.ppm_model.?;
        const ch = model.decodeChar(&st.br) catch return error.InvalidData;

        if (ch == st.ppm_esc_char) {
            const next = model.decodeChar(&st.br) catch return error.InvalidData;
            switch (next) {
                0 => {
                    // End of PPM encoding, NOT of the entry.
                    _ = try st.readTables();
                    return true;
                },
                2 => return false, // end of file
                3 => {
                    // ReadVMCodePPM: a filter program transported as PPM bytes.
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
                    // NextCh == 1 (or anything else, per the reference's
                    // fall-through): the byte IS the escape character.
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

    // Emit decoded bytes before the circular window overwrites them. `keep`
    // bytes are deliberately held back so a filter recorded slightly after
    // its data was decoded can still reach the region it covers. A filter
    // that reaches further back than that is refused rather than applied to
    // the wrong bytes — unverifiable, not damaged.
    fn flushDecoded(st: *State, keep: usize, limit: u64) Failure!void {
        const out = st.stream_out orelse return;
        const produced = st.window.write_pos - st.entry_start;
        // Never emit past the size the header declared; the tail of a final
        // match may overshoot it.
        const emit_upto = @min(produced -| keep, limit);
        if (emit_upto <= st.flushed) return;

        const count = emit_upto - st.flushed;
        const back = produced - st.flushed;
        if (back > st.window.buffer.len) return error.InvalidData;

        // The staged copy sits above a max_filter_block transform scratch;
        // the buffer is window + the shared filter slack, so both always fit.
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

    // Runs to the END-OF-BLOCK MARKER, not unpacked_size: the marker carries
    // the "next file starts with a new table" bit the next solid entry needs,
    // and a trailing match may overshoot the declared size — those bytes stay
    // in the window, where the next solid entry can match against them.
    pub fn decompressLoop(st: *State, unpacked_size: u64) Failure!void {
        if (!st.tables_loaded) {
            _ = try st.readTables();
        }

        // Termination guard. The encoder emits the marker where the entry
        // ends, so a legitimate overshoot is at most one match; a stream that
        // keeps producing well past that is corrupt, and without a bound a
        // crafted archive could spin here indefinitely.
        const overshoot_limit = unpacked_size +| st.window.buffer.len;

        while (true) {
            const should_continue = switch (st.block_mode) {
                .lz => st.processLzSymbol(),
                .ppm_mode => st.processPpmSymbol(),
            } catch |err| {
                // Input exhausted after the entry's declared bytes were all
                // produced is a normal end, not truncation.
                if (st.written_size >= unpacked_size) break;
                return err;
            };

            if (!should_continue) break; // marker consumed: end of this entry

            // Only true for entries larger than the window (stream_out is
            // null otherwise), so the common path pays one null check.
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
    ) Failure!Session {
        try State.init(st, window_buffer, table_pool, pending, filter_scratch, ppm_heap);
        return .{ .state = st };
    }

    // Reference UnpInitData(false) + UnpInitData30(false) + the !Solid half
    // of InitFilters30.
    fn resetForNewStream(self: *Session) void {
        const st = self.state;
        st.window.reset();
        st.prev_distances = [_]u32{ 0, 0, 0, 0 };
        st.last_distance = 0;
        st.last_length = 0;
        st.freeTables();
        st.old_table = [_]u8{0} ** total_code_lengths;
        st.block_mode = .lz;
        // Reference UnpInitData30(!Solid) resets PPMEscChar and the block type
        // but does NOT destroy the PPM model — it persists for the whole
        // unpack session, and only DecodeInit's reset bit rebuilds it. A
        // non-solid file whose first PPM block has reset clear would
        // otherwise find no allocator and fail on an archive unrar accepts.
        st.ppm_esc_char = 2;
        // InitFilters30(!Solid): the filter PROGRAM table.
        st.filter_types = [_]rarvm.StandardFilter{.none} ** max_filters;
        st.filter_count = 0;
        st.last_filter = 0;
        st.old_filter_lengths = [_]u32{0} ** max_filters;
        st.prev_low_dist = 0;
        st.low_dist_rep_count = 0;
    }

    // The reference gate is `if ((!Solid || !TablesRead3) && !ReadTables30())`:
    // a solid entry neither re-reads tables nor resets the window.
    pub fn decodeFile(
        self: *Session,
        packed_data: []const u8,
        unpacked_size: u64,
        solid: bool,
        out: Sink,
    ) Failure!void {
        const st = self.state;

        if (!solid) self.resetForNewStream();

        // Reset every entry, solid or not — filter INVOCATIONS never share
        // solid files (InitFilters: "Filters never share several solid
        // files"), while filter PROGRAMS do (InitFilters30 clears the program
        // table only when !Solid).
        st.pending_count = 0;
        st.filter_seen = .none;
        st.unsupported_filter_seen = false;

        // Padded, unlike the other decoders: the end-of-block marker peeks
        // 16 bits but consumes 1-2, and at a hard bound the peek fails — so
        // the marker (and the table flag it carries) was never read and the
        // next solid entry desynchronised. The reference has the same slack
        // (ReadBorder = ReadTop - 30).
        st.br = BitReader.initPadded(packed_data, bits.default_pad_bytes);
        st.written_size = 0;

        if (unpacked_size == 0) return;

        const start_pos = st.window.write_pos;

        // Entries larger than the window MUST stream out as they decode;
        // below that size the single-emit path at the end is used unchanged.
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

        // A filter program we could not identify — or one of the six whose
        // transform is not implemented — means we cannot reproduce the data.
        // The LZ output is real but incomplete, so returning it would be
        // silently wrong: the worst outcome for an integrity tool.
        if (st.unsupported_filter_seen) return error.Unsupported;

        // Streaming entry: emit whatever is still held back and we are done.
        if (st.stream_out != null) {
            try st.flushDecoded(0, unpacked_size);
            return;
        }

        const out_size: usize = @intCast(@min(st.written_size, unpacked_size));
        const consumed = st.window.write_pos - start_pos;

        // Filters MUST be staged, never applied in the window: later solid
        // entries match back into earlier entries' window regions (see
        // emit.zig). The staged copy sits above the transform scratch.
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

// R[6] carries the region's byte offset WITHIN THE FILE; `start` is already
// file-absolute here.
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
    // The reference builder keeps widening: slot 47 is the last 16-bit slot,
    // the top twelve slots carry 18 bits (matching unrar's own loop over
    // DBitLengthCounts, verified against vendor/unrar/unpack30.cpp).
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
    // The first four slots encode distances 1-4 directly: DBits[0..4] are 0,
    // so a decode never touches the bit reader for them.
    for (0..4) |slot| {
        try std.testing.expectEqual(@as(u32, 0), dist_bits[slot]);
        try std.testing.expectEqual(@as(u32, @intCast(slot)), dist_decode[slot]);
    }
    try std.testing.expectEqual(@as(u32, 4), dist_decode[4]);
    try std.testing.expectEqual(@as(u5, 1), dist_bits[4]);
}
