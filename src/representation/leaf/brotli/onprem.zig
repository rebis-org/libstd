// Brotli compressed data format (RFC 7932), algorithm-level port with the
// RFC sections cited inline.

const std = @import("std");

const kernels = @import("../../../common/kernels.zig");
// Complex prefix codes transmit lengths directly.
// That is larger but always valid.
const huffman = @import("../../../common/primitive/huffman.zig");
const dictionary = @import("dictionary.zig");

pub const DecodeError = error{ UnsupportedException, DataException, ResourceException, CapacityException, InternalException, IoException };
pub const EncodeError = error{ UnsupportedException, DataException, ResourceException, CapacityException, InternalException };

pub const Options = struct {
    quality: u32 = 5,
    max_decoded_bytes: u64 = std.math.maxInt(u64),
    // RFC 7932 large-window extension (vendor BROTLI_PARAM_LARGE_WINDOW):
    // decode accepts the reserved WBITS form; encode may emit windows past
    // 2^24 when the input needs one.
    large_window: bool = false,
    // Shared-dictionary raw LZ77 prefix (vendor
    // BrotliDecoderAttachDictionary RAW type): bytes are addressable as
    // history before the first stream position.
    custom_dictionary: ?[]const u8 = null,
    // Encode-side window cap in bytes; zero picks the smallest window that
    // covers the input (and dictionary), clamped by large_window.
    window_size: u32 = 0,
};

pub const window_size_min = 1 << 10;
pub const window_size_max = (1 << 24) - 16;
// The large-window extension raises the ceiling to lgwin 30 (1 GiB).
pub const window_size_large_max = (1 << 30) - 16;

pub fn encodedSizeBound(input_len: usize) usize {
    return input_len +| (input_len >> 1) +| 1024;
}

pub fn decodedSize(input: []const u8, scratch: []u8, options: Options) DecodeError!usize {
    // The windowed incremental decode counts without materializing: emit
    // spans are drained and discarded.
    var inc = try incrementalInit(scratch, options);
    var fed: usize = 0;
    var sink: [1]u8 = undefined;
    while (true) {
        const res = try inc.run(input[fed..], &sink, true);
        fed += res.consumed;
        if (res.status == .done) return inc.produced;
    }
}

// One-shot slice decode workspace: tables, symbols, context maps. The
// writer-staging lower bound is gone; the windowed incremental decode
// below needs only its own ring.
pub const decode_workspace_size: usize = blk: {
    const tables = max_trees * @sizeOf(HufTable);
    const symbols = max_trees * max_alphabet * @sizeOf(u16);
    const maps = 64 * 256 + 4 * 256;
    break :blk tables + symbols + maps + 4096 + 16;
};

fn alignedSlice(scratch_buffer: []u8, comptime size: usize) error{ResourceException}![]u8 {
    const off = std.mem.alignForward(usize, @intFromPtr(scratch_buffer.ptr), 16) - @intFromPtr(scratch_buffer.ptr);
    if (scratch_buffer.len < off + (size - 16)) return error.ResourceException;
    return scratch_buffer[off..];
}

fn alignedWorkspace(scratch_buffer: []u8) DecodeError!struct { buf: []u8 } {
    // The adapter hands over a []u8 from a sequentially-taken workspace;
    // the table records need natural alignment, so start past the padding.
    return .{ .buf = try alignedSlice(scratch_buffer, decode_workspace_size) };
}

pub fn decodeToWriter(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) DecodeError!void {
    var inc = try incrementalInit(scratch, options);
    var fed: usize = 0;
    var staging: [1 << 16]u8 = undefined;
    while (true) {
        const res = try inc.run(input[fed..], &staging, true);
        fed += res.consumed;
        if (res.produced > 0) writer.writeAll(staging[0..res.produced]) catch return error.IoException;
        if (res.status == .done) return;
    }
}

pub fn requiredSize(input: []const u8, scratch: []u8, options: Options) EncodeError!usize {
    return encodeCountedSize(input, scratch, options);
}

pub fn decodeWorkspaceSize(options: Options) usize {
    return incrementalWorkspaceSize(options);
}

fn hash4At(src: []const u8, pos: usize) usize {
    const w = std.mem.readInt(u32, src[pos..][0..4], .little);
    return (w *% 0x9E37_79B1) >> (32 - 17);
}

fn parseCommands(src: []const u8, dict: []const u8, commands: []Command, head: []u32, ring: *[4]u32, dist_cap: u32) usize {
    @memset(head, 0);
    // The dictionary is the virtual prefix of the stream: byte j sits at
    // position j - dict.len. Hash-chain entries store the position shifted
    // up by dict.len + 1 so zero stays the empty sentinel; a raw value below
    // dict.len is a dictionary position.
    for (0..dict.len -| 3) |j| {
        head[hash4At(dict, j)] = @intCast(j + 1);
    }
    var count: usize = 0;
    var pos: usize = 0;
    var anchor: usize = 0;
    while (pos + 4 <= src.len) {
        const h = hash4At(src, pos);
        const cand_plus1 = head[h];
        head[h] = @intCast(pos + dict.len + 1);
        if (cand_plus1 != 0) {
            const raw = cand_plus1 - 1;
            const cand: usize = if (raw < dict.len) raw else raw - dict.len;
            const dist: usize = if (raw < dict.len) pos + (dict.len - raw) else pos - cand;
            if (dist <= dist_cap) {
                var len: usize = 0;
                if (raw < dict.len) {
                    // A dictionary candidate compares through the
                    // dictionary/stream boundary: virtual bytes after the
                    // dictionary tail continue at src[0].
                    while (len < src.len - pos) {
                        const cb = if (cand + len < dict.len) dict[cand + len] else src[cand + len - dict.len];
                        if (cb != src[pos + len]) break;
                        len += 1;
                    }
                } else {
                    len = kernels.matchLen8(src, cand, pos, src.len - pos);
                }
                if (len >= 4) {
                    const ins = src[anchor..pos];
                    var cmd: Command = .{
                        .icode = 0,
                        .ins_extra = 0,
                        .ins_bits = 0,
                        .copy_extra = 0,
                        .copy_bits = 0,
                        .dcode = 0xFFFF,
                        .dextra = 0,
                        .d_bits = 0,
                        .lit_start = @intCast(anchor),
                        .ins_len = @intCast(ins.len),
                    };
                    const ins_code = lengthToCode(@intCast(ins.len), &insert_base);
                    const copy_code = lengthToCode(@intCast(len), &copy_base);
                    // The implicit distance-0 form exists only below icode 128:
                    // insert codes 0..7 and copy codes below 16.
                    const implicit = dist == ring[0] and ins_code < 8 and copy_code < 16;
                    cmd.icode = icodeFor(ins.len, len, implicit);
                    cmd.ins_extra = @intCast(ins.len - insert_base[ins_code]);
                    cmd.ins_bits = insert_extra[ins_code];
                    cmd.copy_extra = @intCast(len - copy_base[copy_code]);
                    cmd.copy_bits = copy_extra[copy_code];
                    // Implicit distances ride the icode; only explicit ones need a dcode.
                    if (!implicit) {
                        if (dist == ring[0]) {
                            cmd.dcode = 0;
                        } else {
                            if (trySpecialDistance(@intCast(dist), ring)) |dc| {
                                cmd.dcode = dc;
                            } else {
                                const nd = normalDistance(@intCast(dist));
                                cmd.dcode = nd.dcode;
                                cmd.dextra = nd.extra;
                                cmd.d_bits = nd.bits;
                            }
                            ring[3] = ring[2];
                            ring[2] = ring[1];
                            ring[1] = ring[0];
                            ring[0] = @intCast(dist);
                        }
                    }
                    commands[count] = cmd;
                    count += 1;
                    pos += len;
                    anchor = pos;
                    continue;
                }
            }
        }
        pos += 1;
    }
    // Trailing literals: a final command whose ignored copy ends the block.
    if (anchor < src.len or count == 0) {
        const ins = src[anchor..src.len];
        const ins_code = lengthToCode(@intCast(ins.len), &insert_base);
        var cmd: Command = .{
            .icode = 0,
            .ins_extra = @intCast(ins.len - insert_base[ins_code]),
            .ins_bits = insert_extra[ins_code],
            .copy_extra = 0,
            .copy_bits = 0,
            .dcode = 0xFFFF,
            .dextra = 0,
            .d_bits = 0,
            .lit_start = @intCast(anchor),
            .ins_len = @intCast(ins.len),
        };
        cmd.icode = icodeFor(ins.len, 2, true);
        commands[count] = cmd;
        count += 1;
    }
    return count;
}

const max_alphabet = 704; // insert-and-copy alphabet
const ring_slot = [16]u8{ 0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1 };
const ring_off = [16]i8{ 0, 0, 0, 0, -1, 1, -2, 2, -3, 3, -1, 1, -2, 2, -3, 3 };
const max_trees = 256 * 3 + 16;

// ---------------------------------------------------------------- bit io

const BitReader = struct {
    data: []const u8,
    pos: usize = 0,
    mask: u8 = 0, // consumed-bit mask within data[pos]; 0 = fresh byte

    fn readBit(self: *BitReader) DecodeError!u32 {
        if (self.mask == 0) {
            if (self.pos >= self.data.len) return error.DataException;
            self.mask = 1;
        }
        const bit = (self.data[self.pos] & self.mask) != 0;
        self.mask <<= 1;
        if (self.mask == 0) self.pos += 1;
        return @intFromBool(bit);
    }

    // LSB-first, n in 0..24 (block-count and distance extras top out at 24).
    fn readBits(self: *BitReader, n: u5) DecodeError!u32 {
        var v: u32 = 0;
        var i: u5 = 0;
        while (i < n) : (i += 1) {
            if (self.mask == 0) {
                if (self.pos >= self.data.len) return error.DataException;
                self.mask = 1;
            }
            const bit = (self.data[self.pos] & self.mask) != 0;
            self.mask <<= 1;
            if (self.mask == 0) self.pos += 1;
            v |= @as(u32, @intFromBool(bit)) << i;
        }
        return v;
    }

    // RFC 9.2: fill bits to the next byte boundary must be zero.
    fn alignToByte(self: *BitReader) DecodeError!void {
        if (self.mask != 0) {
            while (self.mask != 0) : (self.mask <<= 1) {
                if ((self.data[self.pos] & self.mask) != 0) return error.DataException;
            }
            self.pos += 1;
        }
    }

    fn atEnd(self: *const BitReader) bool {
        return self.mask == 0 and self.pos >= self.data.len;
    }
};

// ---------------------------------------------------------------- huffman

// Canonical prefix code (RFC 3.2/3.5), decoded bit-by-bit.
const HufTable = struct {
    count: [16]u32 = @splat(0),
    symbols: []u16 = &.{},
    single: u16 = std.math.maxInt(u16),

    fn decode(self: *const HufTable, br: *BitReader) DecodeError!u16 {
        if (self.single != std.math.maxInt(u16)) return self.single;
        var code: u32 = 0;
        var first: u32 = 0;
        var index: u32 = 0;
        var len: u32 = 1;
        while (len <= 15) : (len += 1) {
            code |= try br.readBit();
            const n = self.count[len];
            if (code -% first < n) {
                const idx = index + (code - first);
                if (idx >= self.symbols.len) return error.DataException;
                return self.symbols[idx];
            }
            index += n;
            first = (first + n) << 1;
            code <<= 1;
        }
        return error.DataException;
    }
};

const Scratch = struct {
    tables: []HufTable,
    symbols: []u16,
    trees_used: usize = 0,
    cmapl: []u8,
    cmapd: []u8,

    fn allocTree(self: *Scratch, alphabet: usize) DecodeError!struct { table: *HufTable, symbols: []u16 } {
        if (alphabet > max_alphabet) return error.DataException;
        if (self.trees_used >= self.tables.len) return error.ResourceException;
        const t = &self.tables[self.trees_used];
        const base = self.trees_used * max_alphabet;
        self.trees_used += 1;
        t.* = .{};
        t.symbols = self.symbols[base .. base + alphabet];
        return .{ .table = t, .symbols = t.symbols };
    }
};

fn canonicalOffsets(counts: [16]u32) [16]u32 {
    var offset: [16]u32 = undefined;
    offset[1] = 0;
    for (1..15) |l| offset[l + 1] = offset[l] + counts[l];
    return offset;
}

fn buildCodeLengthCode(br: *BitReader, hskip: u32, sc: *Scratch) DecodeError!*HufTable {
    // RFC 3.5: the 18 code-length symbols arrive in a fixed order. The
    // order table and the 2..4-bit prefix code come from the spec.
    var lengths: [18]u8 = @splat(0);
    const order = [18]u8{ 1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    // HSKIP arrived with the 2-bit simple/complex selector; value 1 means a
    // simple code and never reaches here (RFC 3.4/3.5).
    if (hskip == 1) return error.DataException;
    var i: usize = @intCast(hskip);
    var space: u32 = 32;
    var num_codes: u32 = 0;
    while (i < 18 and space > 0) : (i += 1) {
        const sym = order[i];
        // Code-length-symbol bit lengths use the spec's prefix code
        // (RFC 3.5), parsed one bit at a time. The bit patterns: 0->00,
        // 3->10, 4->01, 2->011, 1->0111, 5->1111 (stream order is
        // rightmost first).
        var len: u8 = undefined;
        if (try br.readBit() == 0) {
            len = if (try br.readBit() == 0) 0 else 3;
        } else if (try br.readBit() == 0) {
            len = 4;
        } else if (try br.readBit() == 0) {
            len = 2;
        } else {
            len = if (try br.readBit() == 0) 1 else 5;
        }
        lengths[sym] = len;
        if (len != 0) {
            const weight = @as(u32, 32) >> @intCast(len);
            if (space < weight) return error.DataException;
            space -= weight;
            num_codes += 1;
        }
    }
    // RFC 3.5: either the lengths sum to a complete code (space drains to
    // zero) or exactly one code-length symbol is nonzero; a single symbol
    // decodes with zero bits consumed (vendor huffman.c single-code case).
    if (space != 0 and num_codes != 1) return error.DataException;
    const tree = try sc.allocTree(18);
    const table = tree.table;
    if (num_codes == 1) {
        for (lengths, 0..) |l, sym| {
            if (l != 0) {
                table.single = @intCast(sym);
                break;
            }
        }
        return table;
    }
    for (lengths) |l| table.count[l] += 1;
    table.count[0] = 0;
    var offset = canonicalOffsets(table.count);
    for (lengths, 0..) |l, sym| {
        if (l != 0) {
            tree.symbols[offset[l]] = @intCast(sym);
            offset[l] += 1;
        }
    }
    return table;
}

// Symbol width comes from alphabet_size_max; symbol validation and the
// complex-code loop bound use alphabet_size_limit. The two differ only for
// the large-window distance code (vendor ReadHuffmanCode).
fn readPrefixCode(br: *BitReader, sc: *Scratch, alphabet: usize, alphabet_limit: usize) DecodeError!*HufTable {
    const hskip_bits = try br.readBits(2);
    if (hskip_bits == 1) {
        // Simple prefix code (RFC 3.4).
        const nsym = (try br.readBits(2)) + 1;
        const abits: u5 = @intCast(std.math.log2_int(usize, std.math.ceilPowerOfTwoAssert(usize, alphabet)));
        var lens: [4]u8 = @splat(0);
        const tree = try sc.allocTree(alphabet);
        var last: [4]u16 = undefined;
        for (0..nsym) |i| {
            const sym = try br.readBits(abits);
            if (sym >= alphabet_limit) return error.DataException;
            for (last[0..i]) |p| if (p == sym) return error.DataException;
            last[i] = @intCast(sym);
            tree.table.symbols[i] = @intCast(sym);
        }
        switch (nsym) {
            1 => {
                tree.table.single = tree.table.symbols[0];
            },
            2 => {
                lens[0] = 1;
                lens[1] = 1;
            },
            3 => {
                lens[0] = 1;
                lens[1] = 2;
                lens[2] = 2;
            },
            4 => {
                const ts = try br.readBit();
                if (ts == 0) {
                    lens = .{ 2, 2, 2, 2 };
                } else {
                    lens = .{ 1, 2, 3, 3 };
                }
            },
            else => return error.DataException,
        }
        for (0..nsym) |i| tree.table.count[lens[i]] += 1;
        // For NSYM > 1 the codes inside one length group are assigned in
        // symbol VALUE order (vendor BrotliBuildSimpleHuffmanTable), not
        // stream order: sort the (len, symbol) pairs canonically.
        if (nsym > 1) {
            var saved: [4]u16 = undefined;
            @memcpy(saved[0..nsym], tree.table.symbols[0..nsym]);
            var order: [4]usize = .{ 0, 1, 2, 3 };
            var a: usize = 1;
            while (a < nsym) : (a += 1) {
                var b = a;
                while (b > 0 and (lens[order[b]] < lens[order[b - 1]] or
                    (lens[order[b]] == lens[order[b - 1]] and saved[order[b]] < saved[order[b - 1]])))
                {
                    const t = order[b];
                    order[b] = order[b - 1];
                    order[b - 1] = t;
                    b -= 1;
                }
            }
            for (0..nsym) |i| tree.table.symbols[i] = saved[order[i]];
        }
        return tree.table;
    }
    // Complex prefix code (RFC 3.5); the 2 bits just read are the HSKIP.
    const clcode = try buildCodeLengthCode(br, hskip_bits, sc);
    var lengths = try sc.allocTree(alphabet);
    var symbol_count: usize = 0;
    var prev_len: u8 = 8;
    var repeat: u32 = 0;
    var repeat_len: u8 = 0;
    var space: u32 = 32768;
    while (symbol_count < alphabet_limit and space > 0) {
        const sym = try clcode.decode(br);
        if (sym < 16) {
            lengths.table.symbols[symbol_count] = sym;
            symbol_count += 1;
            repeat = 0;
            repeat_len = 0;
            if (sym != 0) {
                prev_len = @intCast(sym);
                // Guarded subtraction: the vendor relies on u32 wraparound
                // here and fails later on `space != 0`; the wrapped value
                // can never return to zero (drain bounded by 704*32768),
                // so failing early is equivalent.
                const weight = @as(u32, 32768) >> @intCast(sym);
                if (weight > space) return error.DataException;
                space -= weight;
            }
        } else if (sym == 16 or sym == 17) {
            // Repeat codes (RFC 3.5): the running `repeat` holds the TOTAL
            // count of the current run. A consecutive same-type repeat
            // replaces the count via repeat = ((repeat - 2) << extra) + 3+.
            // Only the DELTA over the old total appends new symbols. This
            // is the vendor's ProcessRepeatedCodeLength semantics.
            const new_len: u32 = if (sym == 16) prev_len else 0;
            const extra_bits: u5 = if (sym == 16) 2 else 3;
            const extra = try br.readBits(extra_bits);
            if (repeat_len != new_len) {
                repeat = 0;
                repeat_len = @intCast(new_len);
            }
            const old_repeat = repeat;
            if (repeat > 0) repeat = (repeat - 2) << extra_bits;
            repeat += 3 + extra;
            const delta = repeat - old_repeat;
            if (symbol_count + delta > alphabet) return error.DataException;
            if (new_len != 0) {
                const per = @as(u32, 32768) >> @as(u5, @intCast(new_len));
                if (per * delta > space) return error.DataException;
                for (0..delta) |_| {
                    lengths.table.symbols[symbol_count] = @intCast(new_len);
                    symbol_count += 1;
                }
                space -= per * delta;
            } else {
                @memset(lengths.table.symbols[symbol_count..][0..delta], 0);
                symbol_count += delta;
            }
        } else return error.DataException;
    }
    if (space != 0 or symbol_count > alphabet) return error.DataException;
    const total = symbol_count;
    var counts: [16]u32 = @splat(0);
    for (lengths.table.symbols[0..total]) |l| counts[l] += 1;
    const nonzero = counts[1] + counts[2] + counts[3] + counts[4] + counts[5] + counts[6] + counts[7] + counts[8] + counts[9] + counts[10] + counts[11] + counts[12] + counts[13] + counts[14] + counts[15];
    if (nonzero == 0) return error.DataException;
    if (nonzero == 1) {
        for (lengths.table.symbols[0..total], 0..) |l, s| {
            if (l != 0) {
                lengths.table.single = @intCast(s);
                return lengths.table;
            }
        }
        unreachable;
    }
    var offset = canonicalOffsets(counts);
    var len_copy: [max_alphabet]u16 = undefined;
    @memcpy(len_copy[0..total], lengths.table.symbols[0..total]);
    for (len_copy[0..total], 0..) |l, s| {
        if (l != 0) {
            lengths.table.symbols[offset[l]] = @intCast(s);
            offset[l] += 1;
        }
    }
    lengths.table.count = counts;
    return lengths.table;
}

// ---------------------------------------------------------------- tables

// RFC 5: insert-and-copy length code split into insert and copy codes.
const insert_base = [24]u32{ 0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210, 22594 };
const insert_extra = [24]u5{ 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24 };
const copy_base = [24]u32{ 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118 };
const copy_extra = [24]u5{ 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24 };

// RFC 6: block count code alphabet.
const block_count_base = [26]u32{ 1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209, 241, 305, 369, 497, 753, 1265, 2289, 4337, 8433, 16625 };
const block_count_extra = [26]u5{ 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24 };

// RFC 7.1: literal context lookup tables.
const lut0 = [256]u8{
    0,  0,  0,  0,  0,  0,  0,  0,  0,  4,  4,  0,  0,  4,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    8,  12, 16, 12, 12, 20, 12, 16, 24, 28, 12, 12, 32, 12, 36, 12,
    44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 32, 32, 24, 40, 28, 12,
    12, 48, 52, 52, 52, 48, 52, 52, 52, 48, 52, 52, 52, 52, 52, 48,
    52, 52, 52, 52, 52, 48, 52, 52, 52, 52, 52, 24, 12, 28, 12, 12,
    12, 56, 60, 60, 60, 56, 60, 60, 60, 56, 60, 60, 60, 60, 60, 56,
    60, 60, 60, 60, 60, 56, 60, 60, 60, 60, 60, 24, 12, 28, 12, 0,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
};
const lut1 = [256]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1,
    1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1,
    1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
};
const lut2 = [256]u8{
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7,
};

fn literalContext(mode: u8, p1: u8, p2: u8) usize {
    return switch (mode) {
        0 => p1 & 0x3f,
        1 => p1 >> 2,
        2 => @as(usize, lut0[p1]) | lut1[p2],
        3 => (@as(usize, lut2[p1]) << 3) | lut2[p2],
        else => unreachable,
    };
}

// RFC 9.2: NBLTYPES / NTREES variable-length code.
fn trackContext(p1: *u8, p2: *u8, output: []const u8, last: usize, n: usize) void {
    if (n >= 2) {
        p2.* = output[last - 1];
        p1.* = output[last];
    } else if (n == 1) {
        p2.* = p1.*;
        p1.* = output[last];
    }
}

fn readBlockCount(br: *BitReader) DecodeError!u32 {
    if (try br.readBit() == 0) return 1;
    const n = try br.readBits(3);
    return (@as(u32, 1) << @intCast(n)) + 1 + (try br.readBits(@intCast(n)));
}

// ------------------------------------------------------------ block switch

const BlockCategory = struct {
    num_types: u32 = 1,
    type_tree: ?*HufTable = null,
    count_tree: ?*HufTable = null,
    cur_type: u32 = 0,
    prev_type: u32 = 1,
    count: u32 = 0,

    fn readType(self: *BlockCategory, br: *BitReader) DecodeError!void {
        const tree = self.type_tree orelse return error.DataException;
        const sym = try tree.decode(br);
        if (sym == 0) {
            const swap = self.cur_type;
            self.cur_type = self.prev_type;
            self.prev_type = swap;
        } else if (sym == 1) {
            self.prev_type = self.cur_type;
            self.cur_type +%= 1;
            if (self.cur_type == self.num_types) self.cur_type = 0;
        } else {
            self.prev_type = self.cur_type;
            self.cur_type = @as(u32, sym) - 2;
            if (self.cur_type >= self.num_types) return error.DataException;
        }
    }

    fn readCount(self: *BlockCategory, br: *BitReader) DecodeError!void {
        const tree = self.count_tree orelse return error.DataException;
        const sym = try tree.decode(br);
        if (sym >= 26) return error.DataException;
        self.count = block_count_base[sym] + (try br.readBits(block_count_extra[sym]));
    }
};

// ------------------------------------------------------------- context map

fn readContextMap(br: *BitReader, sc: *Scratch, size: usize, num_trees: u32, map: []u8) DecodeError!void {
    var rlemax: u32 = 0;
    if (try br.readBit() != 0) {
        rlemax = (try br.readBits(4)) + 1;
    }
    const tree = try readPrefixCode(br, sc, @intCast(num_trees + rlemax), @intCast(num_trees + rlemax));
    var i: usize = 0;
    while (i < size) {
        const sym = try tree.decode(br);
        if (sym == 0) {
            map[i] = 0;
            i += 1;
        } else if (sym <= rlemax) {
            const rep = (@as(u32, 1) << @intCast(sym)) + (try br.readBits(@intCast(sym)));
            if (i + rep > size) return error.DataException;
            @memset(map[i .. i + rep], 0);
            i += rep;
        } else {
            const v = sym - rlemax;
            if (v >= num_trees) return error.DataException;
            map[i] = @intCast(v);
            i += 1;
        }
    }
    if (try br.readBit() != 0) {
        // IMTF (RFC 7.3).
        var mtf: [256]u8 = undefined;
        for (&mtf, 0..) |*b, j| b.* = @intCast(j);
        for (map) |*v| {
            const idx: usize = v.*;
            const value = mtf[idx];
            v.* = value;
            var j = idx;
            while (j > 0) : (j -= 1) mtf[j] = mtf[j - 1];
            mtf[0] = value;
        }
    }
}

// ------------------------------------------------------------- meta-block

// RFC 4: the last distance starts at 4.
// The earlier slots start at 11, 15, and 16.
const distance_ring_init = [4]u32{ 4, 11, 15, 16 };

const DistanceCodeLimit = struct { max_alphabet_size: usize, max_distance: u32 };

// Vendor common/constants.h BrotliCalculateDistanceCodeLimit: the largest
// complete distance-code group that cannot represent distances beyond
// max_distance. Only max_alphabet_size is needed here.
fn distanceCodeLimit(max_distance: u32, npostfix: u5, ndirect: u32) DistanceCodeLimit {
    const short_codes: usize = 16;
    if (max_distance <= ndirect) {
        return .{ .max_alphabet_size = @as(usize, max_distance) + short_codes, .max_distance = max_distance };
    }
    const forbidden: u64 = @as(u64, max_distance) + 1;
    var offset: u64 = forbidden - ndirect - 1;
    offset = (offset >> npostfix) + 4;
    var ndistbits: u32 = 0;
    var tmp: u64 = offset / 2;
    while (tmp != 0) : (tmp >>= 1) ndistbits += 1;
    ndistbits -= 1;
    const half: u64 = (offset >> @intCast(ndistbits)) & 1;
    var group: u64 = ((@as(u64, ndistbits) - 1) << 1) | half;
    if (group == 0) {
        return .{ .max_alphabet_size = @as(usize, ndirect) + short_codes, .max_distance = ndirect };
    }
    group -= 1;
    const ndb: u5 = @intCast((group >> 1) + 1);
    const extra: u64 = (@as(u64, 1) << ndb) - 1;
    var start: u64 = (@as(u64, 1) << (ndb + 1)) - 4;
    start += (group & 1) << ndb;
    const max_alphabet_size: usize = @intCast(((group << npostfix) | ((@as(u64, 1) << npostfix) - 1)) + ndirect + short_codes + 1);
    const max_distance_out: u64 = ((start + extra) << npostfix) + ((@as(u64, 1) << npostfix) - 1) + ndirect + 1;
    return .{ .max_alphabet_size = max_alphabet_size, .max_distance = @intCast(max_distance_out & 0xFFFFFFFF) };
}

fn decodeMetaBlock(
    br: *BitReader,
    sc: *Scratch,
    output: []u8,
    produced: *usize,
    stream_base: usize,
    dict: []const u8,
    p1: *u8,
    p2: *u8,
    ring: *[4]u32,
    window_size: u32,
    large_window: bool,
    is_last: *bool,
    empty_end: *bool,
) DecodeError!void {
    empty_end.* = false;
    // Prefix code tables are per-metablock state (RFC 7932 section 6): a
    // fresh set of trees begins here, so the scratch pool resets even though
    // the surrounding stream scratch outlives the metablock.
    sc.trees_used = 0;
    is_last.* = (try br.readBit()) != 0;
    if (is_last.* and (try br.readBit()) != 0) {
        // ISLASTEMPTY: the stream ends at this bit; the caller validates
        // the zero fill and the absence of trailing bytes.
        empty_end.* = true;
        return;
    }
    const mnib_code = try br.readBits(2);
    if (mnib_code == 3) {
        // Metadata meta-block (RFC 9.2).
        if (try br.readBit() != 0) return error.DataException;
        const mskipbytes = try br.readBits(2);
        var skiplen: usize = 0;
        if (mskipbytes > 0) {
            const v = try br.readBits(@intCast(mskipbytes * 8));
            // RFC 9.2: the top byte of MSKIPLEN must be nonzero whenever
            // the length spans more than one byte (vendor decode.c 340-344).
            if (mskipbytes > 1 and (v >> @intCast((mskipbytes - 1) * 8)) == 0) return error.DataException;
            skiplen = @intCast(v + 1);
        }
        try br.alignToByte();
        if (br.pos + skiplen > br.data.len) return error.DataException;
        br.pos += skiplen;
        return;
    }
    const nibbles: u5 = @intCast(mnib_code + 4);
    const mlen: usize = @as(usize, try br.readBits(nibbles * 4)) + 1;
    if (nibbles > 4 and ((mlen - 1) >> @intCast((nibbles - 1) * 4)) == 0) {
        // A zero top nibble for a length encoded in more than 16 bits.
        return error.DataException;
    }
    if (!is_last.*) {
        if ((try br.readBit()) != 0) {
            // Uncompressed meta-block: MLEN literal bytes after alignment.
            try br.alignToByte();
            if (br.pos + mlen > br.data.len) return error.DataException;
            if (produced.* + mlen > output.len) return error.CapacityException;
            @memcpy(output[produced.*..][0..mlen], br.data[br.pos..][0..mlen]);
            br.pos += mlen;
            trackContext(p1, p2, output, produced.* + mlen - 1, mlen);
            produced.* += mlen;
            return;
        }
    }
    // Compressed meta-block header.
    var lit = BlockCategory{};
    var ins = BlockCategory{};
    var dist = BlockCategory{};
    inline for (.{ &lit, &ins, &dist }) |cat| {
        cat.num_types = try readBlockCount(br);
        if (cat.num_types >= 2) {
            cat.type_tree = try readPrefixCode(br, sc, @intCast(cat.num_types + 2), @intCast(cat.num_types + 2));
            cat.count_tree = try readPrefixCode(br, sc, 26, 26);
            try cat.readCount(br);
        }
    }
    const npostfix: u5 = @intCast(try br.readBits(2));
    const ndirect: u32 = (try br.readBits(4)) << npostfix;
    const postfix_mask: u32 = (@as(u32, 1) << npostfix) - 1;

    // Distance code alphabet. The large-window extension widens the symbol
    // pool so distances up to BROTLI_MAX_ALLOWED_DISTANCE stay
    // representable: symbol width comes from the max size, validation and
    // the complex-code bound from the limit (vendor decode.c CONTEXT_MAP_2 /
    // BrotliCalculateDistanceCodeLimit in common/constants.h).
    var dist_alphabet_max: usize = 16 + ndirect + (@as(usize, 48) << npostfix);
    var dist_alphabet_limit: usize = dist_alphabet_max;
    if (large_window) {
        dist_alphabet_max = 16 + ndirect + (@as(usize, 124) << npostfix);
        dist_alphabet_limit = distanceCodeLimit(0x7FFFFFFC, npostfix, ndirect).max_alphabet_size;
    }

    var context_modes: [256]u8 = @splat(0);
    for (0..lit.num_types) |i| {
        context_modes[i] = @intCast(try br.readBits(2));
    }

    const ntreesl = try readBlockCount(br);
    if (ntreesl >= 2) {
        try readContextMap(br, sc, 64 * @as(usize, lit.num_types), ntreesl, sc.cmapl);
    } else {
        @memset(sc.cmapl[0 .. 64 * @as(usize, lit.num_types)], 0);
    }
    const ntreesd = try readBlockCount(br);
    if (ntreesd >= 2) {
        try readContextMap(br, sc, 4 * @as(usize, dist.num_types), ntreesd, sc.cmapd);
    } else {
        @memset(sc.cmapd[0 .. 4 * @as(usize, dist.num_types)], 0);
    }

    var lit_trees: [256]*HufTable = undefined;
    for (0..ntreesl) |i| lit_trees[i] = try readPrefixCode(br, sc, 256, 256);
    var ins_trees: [256]*HufTable = undefined;
    for (0..ins.num_types) |i| ins_trees[i] = try readPrefixCode(br, sc, 704, 704);
    var dist_trees: [256]*HufTable = undefined;
    for (0..ntreesd) |i| dist_trees[i] = try readPrefixCode(br, sc, dist_alphabet_max, dist_alphabet_limit);

    // Command loop (RFC 9.3).
    var pos: usize = 0;
    while (pos < mlen) {
        if (ins.num_types >= 2) {
            if (ins.count == 0) {
                try ins.readType(br);
                try ins.readCount(br);
            }
            ins.count -= 1;
        }
        const icode = try ins_trees[ins.cur_type].decode(br);
        if (icode >= 704) return error.DataException;
        // RFC 5 cell lookup.
        var ins_base_code: u32 = 0;
        var copy_base_code: u32 = 0;
        var implicit_dist0 = false;
        var cell = icode;
        if (cell < 128) {
            implicit_dist0 = true;
            cell += 128;
        }
        switch (cell >> 6) {
            2 => {
                ins_base_code = 0;
                copy_base_code = 0;
            },
            3 => {
                ins_base_code = 0;
                copy_base_code = 8;
            },
            4 => {
                ins_base_code = 8;
                copy_base_code = 0;
            },
            5 => {
                ins_base_code = 8;
                copy_base_code = 8;
            },
            6 => {
                ins_base_code = 0;
                copy_base_code = 16;
            },
            7 => {
                ins_base_code = 16;
                copy_base_code = 0;
            },
            8 => {
                ins_base_code = 8;
                copy_base_code = 16;
            },
            9 => {
                ins_base_code = 16;
                copy_base_code = 8;
            },
            10 => {
                ins_base_code = 16;
                copy_base_code = 16;
            },
            else => return error.DataException,
        }
        const ins_code: usize = @intCast(ins_base_code + ((cell >> 3) & 7));
        const copy_code: usize = @intCast(copy_base_code + (cell & 7));
        const ins_len: usize = @intCast(insert_base[ins_code] + (try br.readBits(insert_extra[ins_code])));
        const copy_len: usize = @intCast(copy_base[copy_code] + (try br.readBits(copy_extra[copy_code])));

        if (pos + ins_len > mlen) return error.DataException;
        for (0..ins_len) |_| {
            if (lit.num_types >= 2) {
                if (lit.count == 0) {
                    try lit.readType(br);
                    try lit.readCount(br);
                }
                lit.count -= 1;
            }
            const cid = literalContext(context_modes[lit.cur_type], p1.*, p2.*);
            const tree_idx = sc.cmapl[64 * @as(usize, lit.cur_type) + cid];
            const byte: u8 = @intCast(try lit_trees[tree_idx].decode(br));
            if (produced.* >= output.len) return error.CapacityException;
            output[produced.*] = byte;
            produced.* += 1;
            p2.* = p1.*;
            p1.* = byte;
            pos += 1;
        }
        if (pos == mlen) break; // trailing copy length is ignored

        // Distance. The ring push waits until the reference proves to be a
        // real backward copy: distances beyond max_backward are static
        // dictionary references and never enter the ring (RFC 4 and 8).
        var distance: u32 = 0;
        var push_ring = false;
        if (implicit_dist0) {
            distance = ring[0];
        } else {
            if (dist.num_types >= 2) {
                if (dist.count == 0) {
                    try dist.readType(br);
                    try dist.readCount(br);
                }
                dist.count -= 1;
            }
            const dcid: usize = if (copy_len > 4) 3 else copy_len - 2;
            const tree_idx = sc.cmapd[4 * @as(usize, dist.cur_type) + dcid];
            const dcode = try dist_trees[tree_idx].decode(br);
            if (dcode < 16) {
                const idx = ring_slot[dcode];
                const v = @as(i64, ring[idx]) + ring_off[dcode];
                if (v <= 0) return error.DataException;
                distance = @intCast(v);
                push_ring = dcode != 0;
            } else if (dcode < 16 + ndirect) {
                distance = dcode - 16 + 1;
                push_ring = true;
            } else {
                const dc: u32 = dcode - ndirect - 16;
                const ndistbits: u5 = @intCast(1 + (dc >> (npostfix + 1)));
                const dextra = try br.readBits(ndistbits);
                const hcode = dc >> npostfix;
                const lcode = dc & postfix_mask;
                const offset = ((@as(u32, 2) + (hcode & 1)) << ndistbits) - 4;
                distance = ((offset + dextra) << npostfix) + lcode + ndirect + 1;
                push_ring = true;
            }
        }
        const max_backward = @min(window_size, (produced.* - stream_base) + dict.len);
        if (distance > max_backward) {
            // RFC 8: a static dictionary reference. Implicit dist0 at a
            // position shorter than the initial ring value (4) is a valid
            // dictionary reference too (vendor decode.c 2202): the ring is
            // left untouched in either case.
            const dict_len = try copyDictionaryWord(output, produced, copy_len, distance, max_backward, p1, p2);
            if (pos + dict_len > mlen) return error.DataException;
            pos += dict_len;
            continue;
        }
        if (push_ring) {
            ring[3] = ring[2];
            ring[2] = ring[1];
            ring[1] = ring[0];
            ring[0] = distance;
        }
        if (pos + copy_len > mlen) return error.DataException;
        if (produced.* + copy_len > output.len) return error.CapacityException;
        const in_stream = produced.* - stream_base;
        if (distance > in_stream) {
            // The match reaches into the custom-dictionary prefix: the first
            // bytes come from the dictionary tail, the rest continue as an
            // ordinary (possibly overlapping) copy from produced output. The
            // equivalent distance stays valid because
            // distance == in_stream + (dict bytes sourced).
            const from_dict = distance - in_stream;
            const dict_part = @min(copy_len, from_dict);
            @memcpy(output[produced.*..][0..dict_part], dict[dict.len - from_dict ..][0..dict_part]);
            produced.* += dict_part;
            const rest = copy_len - dict_part;
            if (rest > 0) {
                kernels.copyMatch(output, produced.*, distance, @intCast(rest));
                produced.* += rest;
            }
        } else {
            kernels.copyMatch(output, produced.*, distance, @intCast(copy_len));
            produced.* += copy_len;
        }
        trackContext(p1, p2, output, produced.* - 1, copy_len);
        pos += copy_len;
    }
}

// ---------------------------------------------------------------- decode

fn readWbits(br: *BitReader, large_window: bool) DecodeError!u32 {
    // RFC 9.1 / vendor DecodeWindowBits: one leading 0 bit means 16;
    // otherwise a 3-bit value n selects 17+n, and when n is zero a second
    // 3-bit value m selects 17 (m == 0), a large-window stream (m == 1), or
    // 8+m. The large-window extension then reads one zero bit (a one bit is
    // invalid) and a 6-bit window size in [10, 30]
    // (vendor decode.c DecodeWindowBits / LARGE_WINDOW_BITS).
    if (try br.readBit() == 0) return 16;
    const n = try br.readBits(3);
    if (n != 0) return 17 + n;
    const m = try br.readBits(3);
    if (m == 1) {
        if (!large_window) return error.DataException;
        // Vendor DecodeWindowBits: one reserved bit (must be zero), then
        // the LARGE_WINDOW_BITS state reads a 6-bit window size in
        // [BROTLI_LARGE_MIN_WBITS, BROTLI_LARGE_MAX_WBITS] = [10, 30].
        if (try br.readBit() != 0) return error.DataException;
        const wbits = try br.readBits(6);
        if (wbits < 10 or wbits > 30) return error.DataException;
        return wbits;
    }
    if (m == 0) return 17;
    return 8 + m;
}

pub fn decodeInPlace(input: []const u8, output: []u8, scratch_buffer: []u8, options: Options) DecodeError!usize {
    return decode(input, output, scratch_buffer, options);
}

pub fn decode(input: []const u8, output: []u8, scratch_buffer: []u8, options: Options) DecodeError!usize {
    const ws = try alignedWorkspace(scratch_buffer);
    const table_bytes = max_trees * @sizeOf(HufTable);
    const symbol_bytes = max_trees * max_alphabet * @sizeOf(u16);
    var sc = Scratch{
        .tables = std.mem.bytesAsSlice(HufTable, @as([]align(8) u8, @alignCast(ws.buf[0..table_bytes]))),
        .symbols = std.mem.bytesAsSlice(u16, @as([]align(2) u8, @alignCast(ws.buf[table_bytes..][0..symbol_bytes]))),
        .cmapl = ws.buf[table_bytes + symbol_bytes ..][0 .. 64 * 256],
        .cmapd = ws.buf[table_bytes + symbol_bytes ..][64 * 256 ..][0 .. 4 * 256],
    };
    var br = BitReader{ .data = input };
    var produced: usize = 0;
    var p1: u8 = 0;
    var p2: u8 = 0;
    var ring = distance_ring_init;
    const dict = options.custom_dictionary orelse &.{};
    // Concatenated streams (gzip-style): each stream carries its own WBITS
    // header. The ring and context bytes reset per stream (RFC 4, 7.1);
    // the custom dictionary stays attached across the concatenation.
    while (true) {
        const wbits = try readWbits(&br, options.large_window);
        // window_size saturates: the 13-bit large-window form can carry
        // values past 31 (the system CLI writes 60 for --large_window=30);
        // distances are validated against produced output, which never
        // approaches the saturation point in practice.
        const window_size: u32 = if (wbits >= 31) std.math.maxInt(u32) else (@as(u32, 1) << @intCast(wbits)) - 16;
        // RFC 4 and 7.1: the distance ring, the literal context bytes, and
        // the addressable history reset at the beginning of every stream in
        // a concatenation.
        ring = distance_ring_init;
        p1 = 0;
        p2 = 0;
        const stream_base = produced;
        while (true) {
            var is_last = false;
            var empty_end = false;
            try decodeMetaBlock(&br, &sc, output, &produced, stream_base, dict, &p1, &p2, &ring, window_size, options.large_window, &is_last, &empty_end);
            if (empty_end) {
                // ISLASTEMPTY: zero fill to the byte boundary, no trailing
                // bytes except the start of a concatenated stream.
                try br.alignToByte();
                break;
            }
            if (produced > options.max_decoded_bytes) return error.ResourceException;
            if (is_last) break;
        }
        // The last meta-block may end mid-byte; the fill must be zero and
        // a concatenated stream starts at the next byte boundary.
        try br.alignToByte();
        if (br.atEnd()) break;
    }
    return produced;
}

fn pseudoText() [4096]u8 {
    var text: [4096]u8 = undefined;
    for (&text, 0..) |*b, i| b.* = @truncate((i *% 2654435761) >> 13);
    return text;
}

const pseudo_text_br = [_]u8{ 0x1f, 0xff, 0x0f, 0x00, 0x8c, 0xd4, 0x48, 0x4d, 0x73, 0xbb, 0x81, 0x71, 0x3a, 0x93, 0x67, 0x8a, 0x53, 0x8e, 0xaf, 0xae, 0xb3, 0x6f, 0x0f, 0xcc, 0x33, 0x94, 0xb8, 0x83, 0x60, 0x13, 0x61, 0x75, 0x91, 0x37, 0x7b, 0xb2, 0xe8, 0xc7, 0x3e, 0xf5, 0xc2, 0x1a, 0x71, 0x79, 0xa6, 0x83, 0x31, 0x4b, 0xb5, 0xfd, 0x6f, 0x2d, 0xe0, 0xa8, 0x64, 0xbe, 0xaf, 0x12, 0x44, 0xe3, 0xc8, 0x01, 0xf1, 0x6e, 0x8e, 0x02, 0x67, 0x65, 0xcb, 0x43, 0x8d, 0x28, 0x9e, 0x44, 0x0f, 0x49, 0x0f, 0x4b, 0x0c, 0x34, 0xaf, 0x58, 0x1f, 0xeb, 0x24, 0xc9, 0x34, 0x06, 0x22, 0x3f, 0xad, 0x71, 0xf0, 0xa2, 0x6a, 0x7b, 0x6a, 0x90, 0xa5, 0xb3, 0x38, 0x98, 0xf2, 0xb2, 0x25, 0x20, 0xcb, 0x9a, 0xfd, 0xb9, 0x49, 0x91, 0xcd, 0x13, 0x10, 0xda, 0xdb, 0x9e, 0x84, 0xae, 0x65, 0x8e, 0x97, 0x16, 0x4d, 0xbe, 0x48, 0x42, 0xe9, 0x75, 0x47, 0x0a, 0xb6, 0x91, 0x3b, 0x5f, 0xdb, 0x74, 0xc5, 0x32, 0x05, 0x63, 0x34, 0x9c, 0x69, 0xf8, 0x56, 0xe1, 0x7a, 0xeb, 0x30, 0x94, 0xab, 0x34, 0x9c, 0xd9, 0x74, 0x65, 0x10, 0x3b, 0xa5, 0xfb, 0xbd, 0xcb, 0x54, 0xad, 0x33, 0x08, 0x56, 0xcb, 0x9d, 0x45, 0x9e, 0xa8, 0x3c, 0x1f, 0x3d, 0x96, 0x66, 0x93, 0x45, 0xb2, 0x3b, 0x9e, 0x1c, 0xea, 0x54, 0xe3, 0xfd, 0xec, 0xb3, 0xb5, 0xdb, 0x1c, 0x8a, 0xd3, 0xf5, 0xe6, 0xd1, 0x47, 0xad, 0xef, 0x6b, 0xc0, 0xd1, 0x5d, 0xe6, 0xd1, 0xdc, 0xaf, 0xaf, 0x80, 0x39, 0xe9, 0xfc, 0xdf, 0x43, 0xae, 0xfe, 0xaa, 0x80, 0xe1, 0xfd, 0xfc, 0x45, 0xec, 0x85, 0x3e, 0xf0, 0x33, 0xe2, 0x19, 0xae, 0x8b, 0x58, 0xfe, 0x3f, 0xb0, 0x83, 0xbb, 0x18, 0x42, 0xbf, 0x63, 0xbe, 0xf1, 0xb6, 0x84, 0x13, 0x0c, 0x43, 0xbb, 0xf8, 0xab, 0x31, 0xfc, 0x37, 0x11, 0x98, 0xee, 0xca, 0x78, 0xe1, 0x28, 0xbc, 0x47, 0xb8, 0x99, 0x22, 0xff, 0x53, 0xa1, 0xf9, 0xbe, 0x42, 0x10, 0x8d, 0x23, 0xfb, 0xc4, 0xbb, 0x39, 0x0a, 0x98, 0x95, 0x2d, 0x0f, 0x55, 0xa2, 0x78, 0x12, 0x3d, 0x20, 0x3d, 0x2c, 0x31, 0xe0, 0xbc, 0x62, 0x7d, 0xac, 0xfd, 0x8d, 0x6a, 0x85, 0x8a, 0x66, 0x8d, 0x86, 0x9e, 0x6e, 0xa8, 0xb5, 0xa9, 0x69, 0x74, 0x68, 0x2a, 0x5a, 0x41, 0x37, 0x82, 0x42, 0x6e, 0x85, 0x2a, 0x61, 0x00, 0x90, 0x3a, 0x10, 0xb0, 0x46, 0x05, 0x8c, 0x8e, 0x61, 0x8b, 0x81, 0xe9, 0x38, 0x65, 0xfa, 0xd0, 0xd2, 0xf9, 0xd2, 0xd1, 0xfb, 0xa5, 0x7a, 0x77, 0xc2, 0x22, 0xee, 0x45, 0x44, 0x2b, 0x0f, 0x20, 0x9a, 0x20, 0xa0, 0x5a, 0xa0, 0x15, 0x18, 0x96, 0x13, 0x2c, 0x6c, 0x07, 0xec, 0x0a, 0x87, 0xc1, 0x80, 0x81, 0xd1, 0x90, 0x31, 0x35, 0x89, 0x8a, 0x79, 0x14, 0x13, 0xf7, 0x24, 0x9e, 0x26, 0xb4, 0xc1, 0xc0, 0x75, 0xc0, 0x21, 0x2a, 0x5d, 0x47, 0x1c, 0x5c, 0xe7, 0xb8, 0x78, 0x95, 0xb3, 0x11, 0x13, 0xb3, 0x31, 0x33, 0x4b, 0x65, 0xe2, 0x59, 0x42, 0xd2, 0x8b, 0xa4, 0x54, 0xfa, 0x0a, 0x01, 0xa9, 0x07, 0x09, 0xa5, 0x0f, 0x95, 0xa2, 0xf1, 0xf0, 0x5d, 0xf0, 0x09, 0x5c, 0x2b, 0x02, 0x16, 0x56, 0x53, 0x56, 0x36, 0xb3, 0x8a, 0x4d, 0x4a, 0xda, 0x9b, 0xb4, 0x8c, 0xf7, 0x4a, 0xc6, 0x00, 0x1a, 0xc6, 0x10, 0x06, 0x36, 0x1d, 0x11, 0xba, 0x29, 0x11, 0xb9, 0x2b, 0x13, 0xa7, 0x0f, 0x76, 0x73, 0x76, 0x0e, 0x0b, 0x8e, 0x8a, 0x53, 0xd6, 0x87, 0xac, 0x9c, 0x4f, 0xb9, 0x4a, 0x1e, 0x16, 0xce, 0x18, 0x0e, 0xde, 0xa4, 0x82, 0x57, 0x21, 0xf1, 0x54, 0x25, 0xf5, 0x4a, 0xa5, 0x96, 0x9c, 0x5c, 0x56, 0x5c, 0xdc, 0xd6, 0xa9, 0xdb, 0x97, 0xbc, 0x82, 0x6f, 0x05, 0xc5, 0xca, 0x0f, 0xc2, 0x61, 0xa6, 0x9c, 0xbb, 0x76, 0xee, 0xda, 0xa5, 0xaf, 0x34, 0xf8, 0xe3, 0x69, 0x36, 0x40, 0x35, 0xa0, 0x36, 0x10, 0x34, 0x50, 0xf7, 0x76, 0x3b, 0xa0, 0x33, 0x10, 0x31, 0x00, 0x31, 0xc0, 0xf2, 0xd6, 0x30, 0xf0, 0x68, 0x00, 0x6e, 0x80, 0x6b, 0xc0, 0xec, 0x6d, 0x72, 0xa0, 0x67, 0xe0, 0x62, 0x60, 0x6a, 0xe0, 0xcd, 0x5b, 0xcc, 0x80, 0xd0, 0x80, 0xdd, 0xed, 0x00 };

// Reference-encoder vectors (brotli CLI, quality 5). The random vector
// reproduces the generator inline; the concatenated pair checks the
// multi-stream loop.
test "brotli decodes reference vectors" {
    const allocator = std.testing.allocator;
    const text = pseudoText();
    const text_br = pseudo_text_br;

    const rep = "abcabcabcabcabcabcabcabcabcabc" ++ "abcabcabcabcabcabcabcabcabcabc" ++ "abcabcabcabcabcabcabcabcabcabc" ++ "abcabcabcabcabcabcabcabcabcabc" ++ "abcabcabcabcabcabcabcabcabcabc" ++ "abcabcabcabcabcabcabcabcabcabc" ++ "abcabcabcabcabcabcabcabcabcabc" ++ "abcabcabcabcabcabcabcabcabcabc" ++ "abcabcabcabcabcabcabcabcabcabc" ++ "abcabcabcabcabcabcabcabcabcabc";
    const rep_br = [_]u8{ 0x1f, 0x2b, 0x01, 0x00, 0x24, 0xc3, 0xc4, 0xc6, 0x62, 0xb3, 0x20, 0xc6, 0x1a };
    const empty_br = [_]u8{0x3f};

    // The text vector exercises the static dictionary (RFC 8) through real
    // reference-encoder output.
    const dict_text = "the quick brown fox jumps over the lazy dog. the quick brown fox jumps over the lazy dog again and again!";
    const dict_text_br = [_]u8{ 0x1f, 0x68, 0x00, 0x00, 0xc4, 0xda, 0x86, 0xa9, 0x9e, 0xa1, 0x18, 0xbb, 0xe2, 0xab, 0xc8, 0x38, 0x19, 0x13, 0x36, 0xe0, 0xc0, 0x21, 0x5b, 0x74, 0x92, 0x07, 0xd0, 0x15, 0x86, 0x8d, 0xb1, 0x33, 0x04, 0xa3, 0x31, 0x23, 0xcf, 0x28, 0xe8, 0x1c, 0x61, 0x3b, 0x4f, 0x85, 0xe7, 0x45, 0x5a, 0xa5, 0x0d, 0x70, 0x4b, 0x87, 0x72, 0x2a, 0x9b, 0xff, 0xe0, 0x18, 0x34, 0x02, 0x3d, 0xe5, 0x90, 0xbf, 0x0b, 0x21, 0x29 };
    try checkVector(allocator, &dict_text_br, dict_text);
    try checkVector(allocator, &empty_br, "");

    var random: [4096]u8 = undefined;
    for (&random, 0..) |*b, i| b.* = @truncate((i *% 2654435761) >> 13);
    // The matching reference output for the generator above.
    const random_br = pseudo_text_br;

    try checkVector(allocator, &random_br, &random);

    // Concatenated streams: two dictionary-free streams decode in sequence
    // with per-stream history.
    var concat: [text_br.len + empty_br.len]u8 = undefined;
    @memcpy(concat[0..text_br.len], &text_br);
    @memcpy(concat[text_br.len..], &empty_br);
    try checkVector(allocator, &concat, &text);
    // The repetitive q5 vector exercises a 704-symbol complex tree and
    // static-dictionary references.
    try checkVector(allocator, &rep_br, rep);
}

fn checkVector(allocator: std.mem.Allocator, encoded: []const u8, expected: []const u8) !void {
    const output = try allocator.alloc(u8, expected.len + 16);
    defer allocator.free(output);
    const scratch = try allocator.alloc(u8, decode_workspace_size);
    defer allocator.free(scratch);
    const n = try decode(encoded, output, scratch, .{});
    try std.testing.expectEqual(expected.len, n);
    try std.testing.expectEqualSlices(u8, expected, output[0..n]);
}

// The adapter asks decodedSize first and then decodes into the exact sink;
// the two runs share a scratch and must both succeed.
test "brotli decodedSize then exact decode" {
    const allocator = std.testing.allocator;
    const text = pseudoText();
    const text_br = pseudo_text_br;

    // decodedSize drives the windowed incremental decode, whose workspace
    // carries the history ring.
    const scratch = try allocator.alloc(u8, incrementalWorkspaceSize(.{}));
    defer allocator.free(scratch);
    const size = try decodedSize(&text_br, scratch, .{});
    try std.testing.expectEqual(text.len, size);
    const output = try allocator.alloc(u8, size);
    defer allocator.free(output);
    const n = try decode(&text_br, output, scratch, .{});
    try std.testing.expectEqualSlices(u8, &text, output[0..n]);
}

// Mimic the envelope workspace: one buffer, scratch at an odd offset, the
// staged input right after it.
test "brotli decode unaligned scratch with trailing input" {
    const allocator = std.testing.allocator;
    const text = pseudoText();
    const text_br = pseudo_text_br;

    const buffer = try allocator.alloc(u8, incrementalWorkspaceSize(.{}) + text_br.len + 3);
    defer allocator.free(buffer);
    @memset(buffer, 0xaa);
    const scratch = buffer[3..][0..incrementalWorkspaceSize(.{})];
    const staged = buffer[3 + decode_workspace_size ..][0..text_br.len];
    @memcpy(staged, &text_br);
    const size = try decodedSize(staged, scratch, .{});
    try std.testing.expectEqual(text.len, size);
    const output = try allocator.alloc(u8, size);
    defer allocator.free(output);
    const n = try decode(staged, output, scratch, .{});
    try std.testing.expectEqualSlices(u8, &text, output[0..n]);
}

// Scratch reuse across decodes must be safe: the first decode leaves real
// table state, the second must not see it.
test "brotli scratch reuse across vectors" {
    const allocator = std.testing.allocator;
    const text = pseudoText();
    const text_br = pseudo_text_br;

    const random_br = pseudo_text_br;

    const scratch = try allocator.alloc(u8, decode_workspace_size);
    defer allocator.free(scratch);
    @memset(scratch, 0);
    var first: [4096]u8 = undefined;
    const n1 = try decode(&random_br, &first, scratch, .{});
    try std.testing.expectEqual(@as(usize, 4096), n1);
    const output = try allocator.alloc(u8, text.len);
    defer allocator.free(output);
    const n = try decode(&text_br, output, scratch, .{});
    try std.testing.expectEqualSlices(u8, &text, output[0..n]);
}

// The adapter sizes the sink exactly; decode must not require slack.
test "brotli decode exact-size output" {
    const allocator = std.testing.allocator;
    const text = pseudoText();
    const text_br = pseudo_text_br;

    const output = try allocator.alloc(u8, text.len);
    defer allocator.free(output);
    const scratch = try allocator.alloc(u8, decode_workspace_size);
    defer allocator.free(scratch);
    const n = try decode(&text_br, output, scratch, .{});
    try std.testing.expectEqual(text.len, n);
    try std.testing.expectEqualSlices(u8, &text, output);
}

// ---------------------------------------------------- static dictionary (RFC 8)

fn ferment(word: []u8, pos: usize) usize {
    // RFC 8 Ferment: UTF-8 aware case toggle.
    if (word[pos] < 192) {
        if (word[pos] >= 97 and word[pos] <= 122) word[pos] ^= 32;
        return 1;
    }
    if (word[pos] < 224) {
        if (pos + 1 < word.len) word[pos + 1] ^= 32;
        return 2;
    }
    if (pos + 2 < word.len) word[pos + 2] ^= 5;
    return 3;
}

fn fermentFirst(word: []u8) void {
    if (word.len > 0) _ = ferment(word, 0);
}

fn fermentAll(word: []u8) void {
    var i: usize = 0;
    while (i < word.len) i += ferment(word, i);
}

fn poolString(offset: usize) []const u8 {
    // The pool is the vendor length-prefixed pool verbatim: map[offset]
    // points at a length byte, followed by that many string bytes
    // (transform.c kPrefixSuffix; entry 49 is the trailing 0x00 = empty).
    const start: usize = dictionary.prefix_suffix_map[offset];
    const len: usize = dictionary.prefix_suffix[start];
    return dictionary.prefix_suffix[start + 1 ..][0..len];
}

// RFC 9.3 counts the transformed length against MLEN, not the copy length.
fn copyDictionaryWord(
    output: []u8,
    produced: *usize,
    copy_len: usize,
    distance: u32,
    max_backward: u32,
    p1: *u8,
    p2: *u8,
) DecodeError!usize {
    if (copy_len < dictionary.min_word_length or copy_len > dictionary.max_word_length) return error.DataException;
    const word_id: u64 = @as(u64, distance) - max_backward - 1;
    const nd: u6 = @intCast(dictionary.ndbits[copy_len]);
    const nwords: u64 = @as(u64, 1) << nd;
    const index = word_id % nwords;
    const transform_id = word_id / nwords;
    if (transform_id >= dictionary.transform_count) return error.DataException;
    const base_off: usize = dictionary.doffset[copy_len] + @as(usize, @intCast(index)) * copy_len;
    const word = dictionary.data[base_off..][0..copy_len];

    var buf: [64]u8 = undefined;
    var total: usize = 0;
    const t: usize = std.math.cast(usize, transform_id *% 3) orelse return error.DataException;
    const prefix = poolString(dictionary.transforms[std.math.cast(usize, t) orelse return error.DataException]);
    if (prefix.len > buf.len) return error.InternalException;
    @memcpy(buf[total..][0..prefix.len], prefix);
    total += prefix.len;

    const op = dictionary.transforms[t + 1];
    var word_part: []const u8 = word;
    var bufw: [dictionary.max_word_length]u8 = undefined;
    switch (op) {
        0 => {},
        1 => {
            @memcpy(bufw[0..word.len], word);
            fermentFirst(bufw[0..word.len]);
            word_part = bufw[0..word.len];
        },
        2 => {
            @memcpy(bufw[0..word.len], word);
            fermentAll(bufw[0..word.len]);
            word_part = bufw[0..word.len];
        },
        3...11 => {
            const k: usize = op - 2;
            word_part = if (word.len < k) word[0..0] else word[k..];
        },
        12...20 => {
            const k: usize = op - 11;
            word_part = if (word.len < k) word[0..0] else word[0 .. word.len - k];
        },
        else => return error.DataException,
    }
    @memcpy(buf[total..][0..word_part.len], word_part);
    total += word_part.len;

    const suffix = poolString(dictionary.transforms[t + 2]);
    if (total + suffix.len > buf.len) return error.InternalException;
    @memcpy(buf[total..][0..suffix.len], suffix);
    total += suffix.len;

    if (produced.* + total > output.len) return error.CapacityException;
    @memcpy(output[produced.*..][0..total], buf[0..total]);
    produced.* += total;
    trackContext(p1, p2, output, produced.* - 1, total);
    return total;
}

// ---------------------------------------------------------------- incremental

// Refillable LSB-first bit reader over the caller's input window. The
// accumulator keeps live bits across step boundaries; when it cannot supply
// the requested width the decoder reports need_input and resumes from the
// same bit position once more input arrives.
const RefillReader = struct {
    data: []const u8 = &.{},
    pos: usize = 0,
    acc: u64 = 0,
    nbits: u6 = 0,
    // Cumulative across feed windows so consumed-byte accounting survives
    // the accumulator's live-bit leftovers at window switches.
    loaded_bytes: u64 = 0,

    fn refill(self: *RefillReader) bool {
        var advanced = false;
        while (self.nbits < 56 and self.pos < self.data.len) {
            self.acc |= @as(u64, self.data[self.pos]) << self.nbits;
            self.nbits += 8;
            self.pos += 1;
            self.loaded_bytes += 1;
            advanced = true;
        }
        return advanced;
    }

    fn have(self: *const RefillReader, n: u6) bool {
        return self.nbits >= n;
    }

    fn peek(self: *RefillReader, n: u6) u64 {
        return self.acc & ((@as(u64, 1) << n) - 1);
    }

    // Up to `want` bits without consuming; suspension stays whole-symbol.
    fn peekUpTo(self: *RefillReader, want: u6) struct { bits: u64, n: u6 } {
        if (self.nbits < want) _ = self.refill();
        const n = @min(self.nbits, want);
        return .{ .bits = self.peek(n), .n = n };
    }

    fn drop(self: *RefillReader, n: u6) void {
        self.acc >>= n;
        self.nbits -= n;
    }

    fn readBits(self: *RefillReader, n: u6) Status!u64 {
        if (self.nbits < n) {
            _ = self.refill();
            if (self.nbits < n) return error.NeedInput;
        }
        const v = self.peek(n);
        self.drop(n);
        return v;
    }

    fn readBit(self: *RefillReader) Status!u32 {
        return @intCast(try self.readBits(1));
    }

    // RFC 9.2: fill bits to the next byte boundary must be zero. Only the
    // bits already accumulated are checked; an empty accumulator has no
    // fill bits to validate.
    fn alignToByte(self: *RefillReader) Status!void {
        const rem: u6 = self.nbits & 7;
        if (rem != 0) {
            const fill = self.peek(rem);
            if (fill != 0) return error.DataException;
            self.drop(rem);
        }
    }

    fn bytePos(self: *const RefillReader) usize {
        return self.pos - self.nbits / 8;
    }

    fn bitCount(self: *const RefillReader) u64 {
        return self.loaded_bytes * 8 - self.nbits;
    }
};

const Status = error{ NeedInput, NeedDrain } || DecodeError;

// Resumable canonical prefix-code walk: mirrors HufTable.decode bit-for-bit.
const HuffWalk = struct {
    active: bool = false,
    single: u16 = std.math.maxInt(u16),
    code: u32 = 0,
    first: u32 = 0,
    index: u32 = 0,
    len: u32 = 1,
};

const TreePhase = enum { idle, clcode, simple, complex, done };

const TreeProgress = struct {
    phase: TreePhase = .idle,
    init_step: u8 = 0,
    alphabet: usize = 0,
    limit: usize = 0,
    hskip: u32 = 0,
    result: ?*HufTable = null,
    single: bool = false,
    cl_i: usize = 0,
    cl_space: u32 = 32,
    cl_num: u32 = 0,
    cl_lengths: [18]u8 = @splat(0),
    nsym: u32 = 0,
    simple_i: u32 = 0,
    syms: [4]u16 = undefined,
    lens: [4]u8 = @splat(0),
    sym_count: usize = 0,
    prev_len: u8 = 8,
    repeat: u32 = 0,
    repeat_len: u8 = 0,
    space: u32 = 32768,
    sym_pending: ?u16 = null,
    cl_table: ?*HufTable = null,
    lengths_table: ?*HufTable = null,
};

const CmapPhase = enum { idle, rle, tree, body, imtf, done };

const CmapProgress = struct {
    phase: CmapPhase = .idle,
    rlemax: u32 = 0,
    size: usize = 0,
    i: usize = 0,
    tree: ?*HufTable = null,
    pending_rep: u32 = 0,
    sym_pending: ?u16 = null,
    mtf: [256]u8 = undefined,
};

const CmdPhase = enum {
    ins_switch,
    icode,
    ins_extra,
    copy_extra,
    lits,
    dist_switch,
    dist_tree,
    dist_extra,
    copy,
    word,
};

const CmdProgress = struct {
    phase: CmdPhase = .icode,
    pos: usize = 0,
    ins_len: usize = 0,
    copy_len: usize = 0,
    ins_code: usize = 0,
    copy_code: usize = 0,
    icode: u16 = 0,
    dcode_pending: ?u16 = null,
    implicit: bool = false,
    distance: u32 = 0,
    push_ring: bool = false,
    lits_done: usize = 0,
    ins_sw_pending: bool = false,
    lit_sw_pending: bool = false,
    dist_sw_pending: bool = false,
    word: [64]u8 = undefined,
    word_len: usize = 0,
    word_off: usize = 0,
    copy_remaining: usize = 0,
    copy_from_dict: usize = 0,
    copy_dict_off: usize = 0,
    copy_src_pos: usize = 0,
    lit_pending: ?u8 = null,
};

const IncState = enum {
    wbits,
    metablock_header,
    metadata_skip,
    uncompressed,
    block_counts,
    block_header,
    context_maps,
    trees,
    command,
    stream_end,
    done,
};

pub const IncRunResult = struct {
    consumed: usize = 0,
    produced: usize = 0,
    status: enum { open, done } = .open,
};

// Windowed streaming brotli decode. History lives in a power-of-two ring
// (so distance lookups never cross the stream boundary), output drains
// through a caller-provided span, and every phase can suspend on input
// starvation or a full output span and resume transparently.
pub const Incremental = struct {
    br: RefillReader = .{},
    sc: Scratch = undefined,
    ring: []u8 = &.{},
    ring_mask: usize = 0,
    ring_pos: usize = 0,
    stream_ring_start: usize = 0,
    produced: usize = 0,
    stream_base: usize = 0,
    stream_produced: usize = 0,
    p1: u8 = 0,
    p2: u8 = 0,
    ring4: [4]u32 = distance_ring_init,
    dict: []const u8 = &.{},
    large_window: bool = false,
    window_size: u32 = 0,
    max_decoded: u64 = std.math.maxInt(u64),
    out: []u8 = &.{},
    out_len: usize = 0,
    input: []const u8 = &.{},
    input_pos: usize = 0,
    end_of_input: bool = false,
    state: IncState = .wbits,
    failed: ?DecodeError = null,

    is_last: bool = false,
    mlen: usize = 0,
    wb_step: u8 = 0,
    wb_first: u32 = 0,
    mb_step: u8 = 0,
    mb_mnib: u64 = 0,
    mb_nibbles: u6 = 0,
    mb_mskipbytes: u64 = 0,
    mb_mskipv: u64 = 0,
    bh_step: u8 = 0,
    bc_step: u8 = 0,
    bc_n: u64 = 0,
    rc_sym: u16 = 0xFFFF,
    mb_pos: usize = 0,
    skip_remaining: usize = 0,
    unc_remaining: usize = 0,
    npostfix: u5 = 0,
    ndirect: u32 = 0,
    postfix_mask: u32 = 0,
    cats: [3]BlockCategory = .{ .{}, .{}, .{} },
    cat_i: usize = 0,
    cat_count_pending: bool = false,
    context_modes: [256]u8 = @splat(0),
    ctx_i: usize = 0,
    ntreesl: u32 = 0,
    ntreesd: u32 = 0,
    tree_i: usize = 0,
    cm_stage: usize = 0,
    dist_alphabet_max: usize = 0,
    dist_alphabet_limit: usize = 0,
    lit_trees: [256]*HufTable = undefined,
    ins_trees: [256]*HufTable = undefined,
    dist_trees: [256]*HufTable = undefined,
    tr: TreeProgress = .{},
    cm: CmapProgress = .{},
    cmd: CmdProgress = .{},
    hw: HuffWalk = .{},
    // The code-length-code tree is transient (only live while one complex
    // prefix code reads its lengths), so a single dedicated table serves
    // every tree; the scratch pool budget then matches the one-shot
    // decoder exactly.
    cl_table_storage: HufTable = .{},
    cl_symbols: [18]u16 = undefined,

    fn ringByte(self: *const Incremental, pos: usize) u8 {
        return self.ring[pos & self.ring_mask];
    }

    fn emitByte(self: *Incremental, b: u8) Status!void {
        if (self.out_len >= self.out.len) return error.NeedDrain;
        self.out[self.out_len] = b;
        self.out_len += 1;
        self.ring[self.ring_pos & self.ring_mask] = b;
        self.ring_pos += 1;
        self.stream_produced += 1;
        self.produced += 1;
        if (self.produced > self.max_decoded) return error.ResourceException;
    }

    fn trackCtx(self: *Incremental, n: usize) void {
        if (n >= 2) {
            self.p2 = self.ringByte(self.ring_pos - 2);
            self.p1 = self.ringByte(self.ring_pos - 1);
        } else if (n == 1) {
            self.p2 = self.p1;
            self.p1 = self.ringByte(self.ring_pos - 1);
        }
    }

    pub fn run(self: *Incremental, input: []const u8, output: []u8, end_of_input: bool) DecodeError!IncRunResult {
        self.input = input;
        self.out = output;
        self.out_len = 0;
        self.end_of_input = end_of_input;
        // Leftover accumulator bits from the previous window stay live in
        // the reader; the caller drops every byte the reader loaded this
        // run (consumed == pos) and feeds only fresh bytes next call.
        self.br.data = input;
        self.br.pos = 0;

        var status: IncRunResult = .{};
        self.stepInner() catch |err| switch (err) {
            error.NeedInput => {
                if (end_of_input and self.state != .done and self.state != .stream_end) {
                    // A truncated stream: the one-shot decoder fails on the
                    // same input when the bit reader runs dry mid-phase.
                    return error.DataException;
                }
            },
            error.NeedDrain => {},
            else => |e| return @errorCast(e),
        };
        status.consumed = self.br.pos;
        status.produced = self.out_len;
        status.status = if (self.state == .done) .done else .open;
        return status;
    }

    fn stepInner(self: *Incremental) Status!void {
        while (true) {
            switch (self.state) {
                .wbits => try self.stWbits(),
                .metablock_header => try self.stMetablockHeader(),
                .metadata_skip => try self.stMetadataSkip(),
                .uncompressed => try self.stUncompressed(),
                .block_counts => try self.stBlockCounts(),
                .block_header => try self.stBlockHeader(),
                .context_maps => try self.stContextMaps(),
                .trees => try self.stTrees(),
                .command => try self.stCommand(),
                .stream_end => try self.stStreamEnd(),
                .done => return,
            }
        }
    }

    fn stWbits(self: *Incremental) Status!void {
        // Large-window and standard forms share the leading bit grammar;
        // the incremental form mirrors readWbits exactly. Each step is a
        // separate suspension point.
        var wbits: u32 = 16;
        switch (self.wb_step) {
            0 => {
                self.wb_first = try self.br.readBit();
                self.wb_step = 1;
                if (self.wb_first == 0) {
                    self.finishWbits(16);
                    return;
                }
            },
            1 => {},
            else => {},
        }
        if (self.wb_step == 1) {
            const n = try self.br.readBits(3);
            if (n != 0) {
                self.finishWbits(17 + @as(u32, @intCast(n)));
                return;
            }
            self.wb_step = 2;
        }
        if (self.wb_step == 2) {
            const m = try self.br.readBits(3);
            if (m == 0) {
                self.finishWbits(17);
                return;
            }
            if (m != 1) {
                self.finishWbits(8 + @as(u32, @intCast(m)));
                return;
            }
            if (!self.large_window) return error.DataException;
            self.wb_step = 3;
        }
        // Large window: one reserved bit (step 3), then the 6-bit window
        // size (step 4); each is its own suspension point.
        if (self.wb_step == 3) {
            if (try self.br.readBit() != 0) return error.DataException;
            self.wb_step = 4;
        }
        if (self.wb_step == 4) {
            const lw = try self.br.readBits(6);
            wbits = @intCast(lw);
            if (wbits < 10 or wbits > 30) return error.DataException;
            self.finishWbits(wbits);
        }
    }

    fn finishWbits(self: *Incremental, wbits: u32) void {
        self.window_size = if (wbits >= 31) std.math.maxInt(u32) else (@as(u32, 1) << @intCast(wbits)) - 16;
        self.ring4 = distance_ring_init;
        self.p1 = 0;
        self.p2 = 0;
        self.stream_base = self.produced;
        self.stream_ring_start = self.ring_pos;
        self.stream_produced = 0;
        self.wb_step = 0;
        self.mb_step = 0;
        self.state = .metablock_header;
    }

    fn stMetablockHeader(self: *Incremental) Status!void {
        // Stepwise so a starved run resumes mid-header: 0 = ISLAST,
        // 1 = ISLASTEMPTY (only when ISLAST), 2 = MNIB, 3.. = metadata
        // sub-reads, 6 = MLEN, 7 = ISUNCOMPRESSED.
        switch (self.mb_step) {
            0 => {
                self.sc.trees_used = 0;
                self.is_last = (try self.br.readBit()) != 0;
                self.mb_step = 1;
                if (!self.is_last) self.mb_step = 2;
            },
            1 => {
                if ((try self.br.readBit()) != 0) {
                    // ISLASTEMPTY.
                    self.mb_step = 0;
                    self.state = .stream_end;
                    return;
                }
                self.mb_step = 2;
            },
            else => {},
        }
        if (self.mb_step == 2) {
            self.mb_mnib = try self.br.readBits(2);
            if (self.mb_mnib == 3) {
                self.mb_step = 3;
            } else {
                self.mb_nibbles = @intCast(self.mb_mnib + 4);
                self.mb_step = 6;
            }
        }
        if (self.mb_step == 3) {
            if (try self.br.readBit() != 0) return error.DataException;
            self.mb_step = 4;
        }
        if (self.mb_step == 4) {
            self.mb_mskipbytes = try self.br.readBits(2);
            self.mb_step = 5;
        }
        if (self.mb_step == 5) {
            if (self.mb_mskipbytes > 0) {
                self.mb_mskipv = try self.br.readBits(@intCast(self.mb_mskipbytes * 8));
            }
            self.mb_step = 55;
        }
        if (self.mb_step == 55) {
            var skiplen: usize = 0;
            if (self.mb_mskipbytes > 0) {
                if (self.mb_mskipbytes > 1 and (self.mb_mskipv >> @intCast((self.mb_mskipbytes - 1) * 8)) == 0) return error.DataException;
                skiplen = @intCast(self.mb_mskipv + 1);
            }
            try self.br.alignToByte();
            self.skip_remaining = skiplen;
            self.mb_step = 0;
            self.state = .metadata_skip;
            return;
        }
        if (self.mb_step == 6) {
            self.mlen = @as(usize, @intCast(try self.br.readBits(self.mb_nibbles * 4))) + 1;
            if (self.mb_nibbles > 4 and ((self.mlen - 1) >> @intCast((self.mb_nibbles - 1) * 4)) == 0) {
                return error.DataException;
            }
            self.mb_step = 7;
        }
        if (self.mb_step == 7) {
            if (!self.is_last) {
                if ((try self.br.readBit()) != 0) {
                    try self.br.alignToByte();
                    self.unc_remaining = self.mlen;
                    self.mb_step = 0;
                    self.state = .uncompressed;
                    return;
                }
            }
            self.cats = .{ .{}, .{}, .{} };
            self.cat_i = 0;
            self.cat_count_pending = false;
            self.mb_step = 0;
            self.state = .block_counts;
        }
    }

    fn nextRawByte(self: *Incremental) Status!u8 {
        if (self.br.nbits >= 8) {
            const b: u8 = @intCast(self.br.peek(8));
            self.br.drop(8);
            return b;
        }
        if (self.br.pos < self.br.data.len) {
            const b = self.br.data[self.br.pos];
            self.br.pos += 1;
            return b;
        }
        _ = self.br.refill();
        if (self.br.nbits >= 8) {
            const b: u8 = @intCast(self.br.peek(8));
            self.br.drop(8);
            return b;
        }
        return error.NeedInput;
    }

    fn stMetadataSkip(self: *Incremental) Status!void {
        while (self.skip_remaining > 0) {
            _ = try self.nextRawByte();
            self.skip_remaining -= 1;
        }
        self.state = .metablock_header;
    }

    fn stUncompressed(self: *Incremental) Status!void {
        while (self.unc_remaining > 0) {
            const b = try self.nextRawByte();
            try self.emitByte(b);
            self.unc_remaining -= 1;
        }
        self.trackCtx(self.mlen);
        self.mb_step = 0;
        self.state = if (self.is_last) .stream_end else .metablock_header;
    }

    // Resumable canonical prefix-code walk; suspends bit-starved with the
    // partial code saved in self.hw.
    fn walk(self: *Incremental, table: *const HufTable) Status!u16 {
        if (!self.hw.active) {
            if (table.single != std.math.maxInt(u16)) return table.single;
            self.hw = .{ .active = true, .single = table.single };
        }
        while (self.hw.len <= 15) : (self.hw.len += 1) {
            self.hw.code |= try self.br.readBit();
            const n = table.count[self.hw.len];
            if (self.hw.code -% self.hw.first < n) {
                const idx = self.hw.index + (self.hw.code - self.hw.first);
                if (idx >= table.symbols.len) return error.DataException;
                self.hw.active = false;
                return table.symbols[idx];
            }
            self.hw.index += n;
            self.hw.first = (self.hw.first + n) << 1;
            self.hw.code <<= 1;
        }
        self.hw.active = false;
        return error.DataException;
    }

    fn readBlockCountInc(self: *Incremental) Status!u32 {
        // Suspension-safe: the selector bit and the 3-bit count width are
        // saved across starved runs.
        if (self.bc_step == 0) {
            if (try self.br.readBit() == 0) return 1;
            self.bc_step = 1;
        }
        if (self.bc_step == 1) {
            self.bc_n = try self.br.readBits(3);
            self.bc_step = 2;
        }
        const v = (@as(u32, 1) << @intCast(self.bc_n)) + 1 + @as(u32, @intCast(try self.br.readBits(@intCast(self.bc_n))));
        self.bc_step = 0;
        return v;
    }

    fn readTypeInc(self: *Incremental, cat: *BlockCategory) Status!void {
        const sym = try self.walk(cat.type_tree.?);
        if (sym == 0) {
            const swap = cat.cur_type;
            cat.cur_type = cat.prev_type;
            cat.prev_type = swap;
        } else if (sym == 1) {
            cat.prev_type = cat.cur_type;
            cat.cur_type +%= 1;
            if (cat.cur_type == cat.num_types) cat.cur_type = 0;
        } else {
            cat.prev_type = cat.cur_type;
            cat.cur_type = @as(u32, sym) - 2;
            if (cat.cur_type >= cat.num_types) return error.DataException;
        }
    }

    fn readCountInc(self: *Incremental, cat: *BlockCategory) Status!void {
        if (self.rc_sym == 0xFFFF) {
            self.rc_sym = try self.walk(cat.count_tree.?);
            if (self.rc_sym >= 26) return error.DataException;
        }
        const sym = self.rc_sym;
        const count = block_count_base[sym] + @as(u32, @intCast(try self.br.readBits(block_count_extra[sym])));
        self.rc_sym = 0xFFFF;
        cat.count = count;
    }

    fn stBlockCounts(self: *Incremental) Status!void {
        while (self.cat_i < 3) {
            const cat = &self.cats[self.cat_i];
            if (cat.num_types == 1 and cat.type_tree == null and !self.cat_count_pending and cat.count == 0) {
                // First visit: read NBLTYPES.
                cat.num_types = try self.readBlockCountInc();
                if (cat.num_types == 1) {
                    self.cat_i += 1;
                    continue;
                }
            }
            if (cat.type_tree == null) {
                cat.type_tree = try self.readTree(@intCast(cat.num_types + 2), @intCast(cat.num_types + 2));
                cat.count_tree = try self.readTree(26, 26);
            }
            if (!self.cat_count_pending) {
                try self.readTypeInc(cat);
                self.cat_count_pending = true;
            }
            try self.readCountInc(cat);
            self.cat_count_pending = false;
            self.cat_i += 1;
        }
        self.cat_i = 0;
        self.state = .block_header;
    }

    fn stBlockHeader(self: *Incremental) Status!void {
        if (self.bh_step == 0) {
            self.npostfix = @intCast(try self.br.readBits(2));
            self.bh_step = 1;
        }
        if (self.bh_step == 1) {
            self.ndirect = @as(u32, @intCast(try self.br.readBits(4))) << self.npostfix;
            self.bh_step = 0;
        }
        self.postfix_mask = (@as(u32, 1) << self.npostfix) - 1;

        var dist_alphabet_max: usize = 16 + self.ndirect + (@as(usize, 48) << self.npostfix);
        var dist_alphabet_limit: usize = dist_alphabet_max;
        if (self.large_window) {
            dist_alphabet_max = 16 + self.ndirect + (@as(usize, 124) << self.npostfix);
            dist_alphabet_limit = distanceCodeLimit(0x7FFFFFFC, self.npostfix, self.ndirect).max_alphabet_size;
        }
        self.dist_alphabet_max = dist_alphabet_max;
        self.dist_alphabet_limit = dist_alphabet_limit;

        self.ctx_i = 0;
        self.state = .context_maps;
    }

    // cm_stage: 0 = context modes, 1 = NTREESL + literal map,
    // 2 = NTREESD + distance map.
    fn stContextMaps(self: *Incremental) Status!void {
        if (self.cm_stage == 0) {
            while (self.ctx_i < self.cats[0].num_types) {
                self.context_modes[self.ctx_i] = @intCast(try self.br.readBits(2));
                self.ctx_i += 1;
            }
            self.cm_stage = 1;
        }
        // ntreesl / cmapl / ntreesd / cmapd are separate stages so a
        // suspended context map never re-reads the tree count.
        if (self.cm_stage == 1) {
            self.ntreesl = try self.readBlockCountInc();
            self.cm_stage = 2;
        }
        if (self.cm_stage == 2) {
            if (self.ntreesl >= 2) {
                try self.readContextMapInc(self.sc.cmapl[0 .. 64 * @as(usize, self.cats[0].num_types)], self.ntreesl);
                if (self.cm.phase != .done) return; // suspended mid-map
            } else {
                @memset(self.sc.cmapl[0 .. 64 * @as(usize, self.cats[0].num_types)], 0);
            }
            self.cm.phase = .idle;
            self.cm_stage = 3;
        }
        if (self.cm_stage == 3) {
            self.ntreesd = try self.readBlockCountInc();
            self.cm_stage = 4;
        }
        if (self.cm_stage == 4) {
            if (self.ntreesd >= 2) {
                try self.readContextMapInc(self.sc.cmapd[0 .. 4 * @as(usize, self.cats[2].num_types)], self.ntreesd);
                if (self.cm.phase != .done) return;
            } else {
                @memset(self.sc.cmapd[0 .. 4 * @as(usize, self.cats[2].num_types)], 0);
            }
            self.cm.phase = .idle;
        }
        self.cm_stage = 0;
        self.tree_i = 0;
        self.state = .trees;
    }

    fn readContextMapInc(self: *Incremental, map: []u8, num_trees: u32) Status!void {
        // cm.phase != idle means resuming a read already in progress.
        if (self.cm.phase == .idle) {
            self.cm.phase = .rle;
            self.cm.size = map.len;
            self.cm.i = 0;
            self.cm.rlemax = 0;
        }
        if (self.cm.phase == .rle) {
            if (try self.br.readBit() != 0) {
                self.cm.rlemax = @as(u32, @intCast(try self.br.readBits(4))) + 1;
            }
            self.cm.phase = .tree;
        }
        if (self.cm.phase == .tree) {
            self.cm.tree = try self.readTree(@intCast(num_trees + self.cm.rlemax), @intCast(num_trees + self.cm.rlemax));
            self.cm.phase = .body;
        }
        const tree = self.cm.tree.?;
        while (self.cm.i < self.cm.size) {
            if (self.cm.sym_pending == null) self.cm.sym_pending = try self.walk(tree);
            const sym = self.cm.sym_pending.?;
            if (sym == 0) {
                self.cm.sym_pending = null;
                map[self.cm.i] = 0;
                self.cm.i += 1;
            } else if (sym <= self.cm.rlemax) {
                const rep = (@as(u32, 1) << @intCast(sym)) + @as(u32, @intCast(try self.br.readBits(@intCast(sym))));
                self.cm.sym_pending = null;
                if (self.cm.i + rep > self.cm.size) return error.DataException;
                @memset(map[self.cm.i .. self.cm.i + rep], 0);
                self.cm.i += rep;
            } else {
                self.cm.sym_pending = null;
                const v = sym - self.cm.rlemax;
                if (v >= num_trees) return error.DataException;
                map[self.cm.i] = @intCast(v);
                self.cm.i += 1;
            }
        }
        if (try self.br.readBit() != 0) {
            // IMTF (RFC 7.3).
            for (&self.cm.mtf, 0..) |*b, j| b.* = @intCast(j);
            self.cm.phase = .imtf;
            self.cm.i = 0;
            while (self.cm.i < self.cm.size) {
                const idx: usize = map[self.cm.i];
                const value = self.cm.mtf[idx];
                map[self.cm.i] = value;
                var j = idx;
                while (j > 0) : (j -= 1) self.cm.mtf[j] = self.cm.mtf[j - 1];
                self.cm.mtf[0] = value;
                self.cm.i += 1;
            }
        }
        self.cm.phase = .done;
    }
    // Resumable prefix-code reader; mirrors readPrefixCode. Callers leave
    // self.tr.phase != .idle to resume a suspended read.
    fn readTree(self: *Incremental, alphabet: usize, limit: usize) Status!*HufTable {
        // A completed tree leaves .done; the next read starts fresh. The
        // result table is allocated exactly once per tree, up front, so
        // suspension resumes never double-advance the scratch pool.
        // init_step splits the selector reads so a starved run never
        // re-reads an already-consumed selector.
        if (self.tr.phase == .done) self.tr = .{};
        if (self.tr.init_step == 0 and self.tr.phase == .idle) {
            const rt = try self.sc.allocTree(alphabet);
            self.tr = .{
                .alphabet = alphabet,
                .limit = limit,
                .result = rt.table,
                .init_step = 1,
            };
            rt.table.symbols = rt.symbols;
        }
        if (self.tr.init_step == 1) {
            self.tr.hskip = @intCast(try self.br.readBits(2));
            self.tr.init_step = 2;
        }
        if (self.tr.init_step == 2) {
            if (self.tr.hskip == 1) {
                self.tr.nsym = @intCast((try self.br.readBits(2)) + 1);
                self.tr.simple_i = 0;
                self.tr.phase = .simple;
            } else {
                self.cl_table_storage = .{ .symbols = &self.cl_symbols };
                self.tr.cl_table = &self.cl_table_storage;
                self.tr.cl_i = @intCast(self.tr.hskip);
                self.tr.cl_space = 32;
                self.tr.cl_num = 0;
                self.tr.cl_lengths = @splat(0);
                self.tr.phase = .clcode;
            }
            self.tr.init_step = 0;
        }
        switch (self.tr.phase) {
            .idle => unreachable,
            .clcode => try self.treeClCode(),
            .simple => try self.treeSimple(),
            .complex => try self.treeComplex(),
            .done => return self.tr.result.?,
        }
        if (self.tr.phase == .done) return self.tr.result.?;
        return error.NeedInput; // a sub-phase suspended
    }

    fn treeClCode(self: *Incremental) Status!void {
        const order = [18]u8{ 1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        if (self.tr.hskip == 1) return error.DataException;
        var i = self.tr.cl_i;
        while (i < 18 and self.tr.cl_space > 0) : (i += 1) {
            // Save progress before the (possibly starved) read so a
            // suspended run resumes at this length, not the previous one.
            self.tr.cl_i = i;
            // The 2..4-bit length encodings are decodable from a 4-bit
            // window, which keeps suspension between whole lengths.
            const w = self.br.peekUpTo(4);
            var len: u8 = undefined;
            var used: u6 = undefined;
            if (w.bits & 1 == 0) {
                if (w.n < 2) return error.NeedInput;
                len = if ((w.bits >> 1) & 1 != 0) 3 else 0;
                used = 2;
            } else if ((w.bits >> 1) & 1 == 0) {
                if (w.n < 2) return error.NeedInput;
                len = 4;
                used = 2;
            } else if ((w.bits >> 2) & 1 == 0) {
                if (w.n < 3) return error.NeedInput;
                len = 2;
                used = 3;
            } else {
                if (w.n < 4) return error.NeedInput;
                len = if ((w.bits >> 3) & 1 != 0) 5 else 1;
                used = 4;
            }
            self.br.drop(used);
            const sym = order[i];
            self.tr.cl_lengths[sym] = len;
            if (len != 0) {
                const weight = @as(u32, 32) >> @intCast(len);
                if (self.tr.cl_space < weight) return error.DataException;
                self.tr.cl_space -= weight;
                self.tr.cl_num += 1;
            }
        }
        self.tr.cl_i = i;
        if (self.tr.cl_space != 0 and self.tr.cl_num != 1) return error.DataException;
        const table = self.tr.cl_table.?;
        if (self.tr.cl_num == 1) {
            for (self.tr.cl_lengths, 0..) |l, sym| {
                if (l != 0) {
                    table.single = @intCast(sym);
                    break;
                }
            }
        } else {
            for (self.tr.cl_lengths) |l| table.count[l] += 1;
            table.count[0] = 0;
            var offset = canonicalOffsets(table.count);
            for (self.tr.cl_lengths, 0..) |l, sym| {
                if (l != 0) {
                    table.symbols[offset[l]] = @intCast(sym);
                    offset[l] += 1;
                }
            }
        }
        const lt = self.tr.result.?;
        self.tr.lengths_table = lt;
        lt.single = std.math.maxInt(u16);
        @memset(lt.count[0..], 0);
        self.tr.sym_count = 0;
        self.tr.prev_len = 8;
        self.tr.repeat = 0;
        self.tr.repeat_len = 0;
        self.tr.space = 32768;
        self.tr.phase = .complex;
        try self.treeComplex();
    }

    fn treeSimple(self: *Incremental) Status!void {
        const tree = self.tr.result.?;
        const abits: u6 = @intCast(std.math.log2_int(usize, std.math.ceilPowerOfTwoAssert(usize, self.tr.alphabet)));
        while (self.tr.simple_i < self.tr.nsym) : (self.tr.simple_i += 1) {
            const sym = try self.br.readBits(abits);
            if (sym >= self.tr.limit) return error.DataException;
            const i = self.tr.simple_i;
            self.tr.syms[i] = @intCast(sym);
            tree.symbols[i] = @intCast(sym);
        }
        var lens: [4]u8 = @splat(0);
        switch (self.tr.nsym) {
            1 => {
                self.tr.result.?.single = self.tr.result.?.symbols[0];
                self.tr.single = true;
                self.tr.phase = .done;
                return;
            },
            2 => lens[0..2].* = .{ 1, 1 },
            3 => lens[0..3].* = .{ 1, 2, 2 },
            4 => {
                const ts = try self.br.readBit();
                if (ts == 0) {
                    lens[0..4].* = .{ 2, 2, 2, 2 };
                } else {
                    lens[0..4].* = .{ 1, 2, 3, 3 };
                }
            },
            else => return error.DataException,
        }
        const table = self.tr.result.?;
        for (0..self.tr.nsym) |i| table.count[lens[i]] += 1;
        // Canonical order: (len, symbol) sort, as in readPrefixCode.
        var saved: [4]u16 = undefined;
        @memcpy(saved[0..self.tr.nsym], table.symbols[0..self.tr.nsym]);
        var order: [4]usize = .{ 0, 1, 2, 3 };
        var a: usize = 1;
        while (a < self.tr.nsym) : (a += 1) {
            var b = a;
            while (b > 0 and (lens[order[b]] < lens[order[b - 1]] or
                (lens[order[b]] == lens[order[b - 1]] and saved[order[b]] < saved[order[b - 1]])))
            {
                const t = order[b];
                order[b] = order[b - 1];
                order[b - 1] = t;
                b -= 1;
            }
        }
        for (0..self.tr.nsym) |i| table.symbols[i] = saved[order[i]];
        self.tr.single = false;
        self.tr.phase = .done;
    }

    fn treeComplex(self: *Incremental) Status!void {
        const cl = self.tr.cl_table.?;
        const lt = self.tr.lengths_table.?;
        self.tr.result = lt;
        while (self.tr.sym_count < self.tr.limit and self.tr.space > 0) {
            if (self.tr.sym_pending == null) self.tr.sym_pending = try self.walk(cl);
            const sym = self.tr.sym_pending.?;
            if (sym < 16) {
                self.tr.sym_pending = null;
                lt.symbols[self.tr.sym_count] = sym;
                self.tr.sym_count += 1;
                self.tr.repeat = 0;
                self.tr.repeat_len = 0;
                if (sym != 0) {
                    self.tr.prev_len = @intCast(sym);
                    const weight = @as(u32, 32768) >> @intCast(sym);
                    if (weight > self.tr.space) return error.DataException;
                    self.tr.space -= weight;
                }
            } else if (sym == 16 or sym == 17) {
                const new_len: u32 = if (sym == 16) self.tr.prev_len else 0;
                const extra_bits: u6 = if (sym == 16) 2 else 3;
                const extra = try self.br.readBits(extra_bits);
                self.tr.sym_pending = null;
                if (self.tr.repeat_len != new_len) {
                    self.tr.repeat = 0;
                    self.tr.repeat_len = @intCast(new_len);
                }
                const old_repeat = self.tr.repeat;
                if (self.tr.repeat > 0) self.tr.repeat = (self.tr.repeat - 2) << @intCast(extra_bits);
                self.tr.repeat += 3 + @as(u32, @intCast(extra));
                const delta = self.tr.repeat - old_repeat;
                if (self.tr.sym_count + delta > self.tr.limit) return error.DataException;
                if (new_len != 0) {
                    const per = @as(u32, 32768) >> @intCast(new_len);
                    if (per * delta > self.tr.space) return error.DataException;
                    for (0..delta) |_| {
                        lt.symbols[self.tr.sym_count] = @intCast(new_len);
                        self.tr.sym_count += 1;
                    }
                    self.tr.space -= per * delta;
                } else {
                    @memset(lt.symbols[self.tr.sym_count..][0..delta], 0);
                    self.tr.sym_count += delta;
                }
            } else return error.DataException;
        }
        if (self.tr.space != 0 or self.tr.sym_count > self.tr.alphabet) return error.DataException;
        var cnt: [16]u32 = @splat(0);
        for (lt.symbols[0..self.tr.sym_count]) |l| cnt[l] += 1;
        const nonzero = cnt[1] + cnt[2] + cnt[3] + cnt[4] + cnt[5] + cnt[6] + cnt[7] + cnt[8] + cnt[9] + cnt[10] + cnt[11] + cnt[12] + cnt[13] + cnt[14] + cnt[15];
        if (nonzero == 0) return error.DataException;
        if (nonzero == 1) {
            for (lt.symbols[0..self.tr.sym_count], 0..) |l, sidx| {
                if (l != 0) {
                    lt.single = @intCast(sidx);
                    break;
                }
            }
            self.tr.single = true;
            self.tr.phase = .done;
            return;
        }
        var offset = canonicalOffsets(cnt);
        var len_copy: [max_alphabet]u16 = undefined;
        @memcpy(len_copy[0..self.tr.sym_count], lt.symbols[0..self.tr.sym_count]);
        for (len_copy[0..self.tr.sym_count], 0..) |l, sidx| {
            if (l != 0) {
                lt.symbols[offset[l]] = @intCast(sidx);
                offset[l] += 1;
            }
        }
        lt.count = cnt;
        self.tr.single = false;
        self.tr.phase = .done;
    }

    fn stTrees(self: *Incremental) Status!void {
        const total = @as(usize, self.ntreesl) + @as(usize, self.cats[1].num_types) + @as(usize, self.ntreesd);
        while (self.tree_i < total) {
            const idx = self.tree_i;
            if (idx < self.ntreesl) {
                const t = try self.readTree(256, 256);
                self.lit_trees[idx] = t;
            } else if (idx < self.ntreesl + self.cats[1].num_types) {
                const t = try self.readTree(704, 704);
                self.ins_trees[idx - self.ntreesl] = t;
            } else {
                const t = try self.readTree(self.dist_alphabet_max, self.dist_alphabet_limit);
                self.dist_trees[idx - self.ntreesl - self.cats[1].num_types] = t;
            }
            self.tree_i += 1;
        }
        self.cmd = .{};
        self.mb_pos = 0;
        self.state = .command;
    }

    fn endMetaBlock(self: *Incremental) void {
        self.state = if (self.is_last) .stream_end else .metablock_header;
    }

    fn stCommand(self: *Incremental) Status!void {
        while (self.mb_pos < self.mlen) {
            switch (self.cmd.phase) {
                .ins_switch => {
                    const ins = &self.cats[1];
                    if (ins.num_types >= 2) {
                        if (!self.cmd.ins_sw_pending and ins.count == 0) {
                            try self.readTypeInc(ins);
                            self.cmd.ins_sw_pending = true;
                        }
                        if (self.cmd.ins_sw_pending) {
                            try self.readCountInc(ins);
                            self.cmd.ins_sw_pending = false;
                        }
                        ins.count -= 1;
                    }
                    self.cmd.phase = .icode;
                },
                .icode => {
                    const icode = try self.walk(self.ins_trees[self.cats[1].cur_type]);
                    if (icode >= 704) return error.DataException;
                    self.cmd.icode = icode;
                    var cell: u32 = icode;
                    self.cmd.implicit = cell < 128;
                    if (cell < 128) cell += 128;
                    var ins_base_code: u32 = 0;
                    var copy_base_code: u32 = 0;
                    switch (cell >> 6) {
                        2 => {},
                        3 => copy_base_code = 8,
                        4 => ins_base_code = 8,
                        5 => {
                            ins_base_code = 8;
                            copy_base_code = 8;
                        },
                        6 => copy_base_code = 16,
                        7 => ins_base_code = 16,
                        8 => {
                            ins_base_code = 8;
                            copy_base_code = 16;
                        },
                        9 => {
                            ins_base_code = 16;
                            copy_base_code = 8;
                        },
                        10 => {
                            ins_base_code = 16;
                            copy_base_code = 16;
                        },
                        else => return error.DataException,
                    }
                    self.cmd.ins_code = ins_base_code + ((cell >> 3) & 7);
                    self.cmd.copy_code = copy_base_code + (cell & 7);
                    self.cmd.phase = .ins_extra;
                },
                .ins_extra => {
                    self.cmd.ins_len = @intCast(insert_base[self.cmd.ins_code] + try self.br.readBits(insert_extra[self.cmd.ins_code]));
                    self.cmd.phase = .copy_extra;
                },
                .copy_extra => {
                    self.cmd.copy_len = @intCast(copy_base[self.cmd.copy_code] + try self.br.readBits(copy_extra[self.cmd.copy_code]));
                    if (self.mb_pos + self.cmd.ins_len > self.mlen) return error.DataException;
                    self.cmd.lits_done = 0;
                    self.cmd.phase = .lits;
                },
                .lits => {
                    const lit = &self.cats[0];
                    while (self.cmd.lits_done < self.cmd.ins_len) {
                        if (self.cmd.lit_pending == null) {
                            // Starting a new literal: block switch, context
                            // id and the tree walk all complete before the
                            // emit can suspend.
                            if (lit.num_types >= 2) {
                                if (!self.cmd.lit_sw_pending and lit.count == 0) {
                                    try self.readTypeInc(lit);
                                    self.cmd.lit_sw_pending = true;
                                }
                                if (self.cmd.lit_sw_pending) {
                                    try self.readCountInc(lit);
                                    self.cmd.lit_sw_pending = false;
                                }
                                lit.count -= 1;
                            }
                            const cid = literalContext(self.context_modes[lit.cur_type], self.p1, self.p2);
                            const tree_idx = self.sc.cmapl[64 * @as(usize, lit.cur_type) + cid];
                            self.cmd.lit_pending = @intCast(try self.walk(self.lit_trees[tree_idx]));
                        }
                        try self.emitByte(self.cmd.lit_pending.?);
                        const byte = self.cmd.lit_pending.?;
                        self.cmd.lit_pending = null;
                        self.p2 = self.p1;
                        self.p1 = byte;
                        self.mb_pos += 1;
                        self.cmd.lits_done += 1;
                    }
                    if (self.mb_pos == self.mlen) {
                        self.endMetaBlock();
                        return;
                    }
                    self.cmd.phase = .dist_switch;
                },
                .dist_switch => {
                    if (!self.cmd.implicit) {
                        const dist = &self.cats[2];
                        if (dist.num_types >= 2) {
                            if (!self.cmd.dist_sw_pending and dist.count == 0) {
                                try self.readTypeInc(dist);
                                self.cmd.dist_sw_pending = true;
                            }
                            if (self.cmd.dist_sw_pending) {
                                try self.readCountInc(dist);
                                self.cmd.dist_sw_pending = false;
                            }
                            dist.count -= 1;
                        }
                    }
                    self.cmd.phase = .dist_tree;
                },
                .dist_tree => {
                    var distance: u32 = 0;
                    var push_ring = false;
                    if (self.cmd.implicit) {
                        distance = self.ring4[0];
                    } else {
                        const dcid: usize = if (self.cmd.copy_len > 4) 3 else self.cmd.copy_len - 2;
                        const tree_idx = self.sc.cmapd[4 * @as(usize, self.cats[2].cur_type) + dcid];
                        if (self.cmd.dcode_pending == null) self.cmd.dcode_pending = try self.walk(self.dist_trees[tree_idx]);
                        const dcode = self.cmd.dcode_pending.?;
                        if (dcode < 16) {
                            self.cmd.dcode_pending = null;
                            const idx = ring_slot[dcode];
                            const v = @as(i64, self.ring4[idx]) + ring_off[dcode];
                            if (v <= 0) return error.DataException;
                            distance = @intCast(v);
                            push_ring = dcode != 0;
                        } else if (dcode < 16 + self.ndirect) {
                            self.cmd.dcode_pending = null;
                            distance = dcode - 16 + 1;
                            push_ring = true;
                        } else {
                            const dc: u32 = dcode - self.ndirect - 16;
                            const ndistbits: u6 = @intCast(1 + (dc >> (self.npostfix + 1)));
                            const dextra = try self.br.readBits(ndistbits);
                            self.cmd.dcode_pending = null;
                            const hcode = dc >> self.npostfix;
                            const lcode = dc & self.postfix_mask;
                            const offset = ((@as(u32, 2) + (hcode & 1)) << @intCast(ndistbits)) - 4;
                            distance = ((offset + @as(u32, @intCast(dextra))) << self.npostfix) + lcode + self.ndirect + 1;
                            push_ring = true;
                        }
                    }
                    self.cmd.distance = distance;
                    self.cmd.push_ring = push_ring;
                    self.cmd.phase = .dist_extra;
                },
                .dist_extra => {
                    const max_backward = @min(self.window_size, self.stream_produced + self.dict.len);
                    if (self.cmd.distance > max_backward) {
                        // Static dictionary reference. Build the transformed
                        // word first (no input consumed), bound-check, then
                        // emit with drain suspension.
                        self.cmd.word_len = try self.buildDictionaryWord(self.cmd.copy_len, self.cmd.distance, max_backward);
                        if (self.mb_pos + self.cmd.word_len > self.mlen) return error.DataException;
                        self.cmd.word_off = 0;
                        self.cmd.phase = .word;
                    } else {
                        if (self.cmd.push_ring) {
                            self.ring4[3] = self.ring4[2];
                            self.ring4[2] = self.ring4[1];
                            self.ring4[1] = self.ring4[0];
                            self.ring4[0] = self.cmd.distance;
                        }
                        if (self.mb_pos + self.cmd.copy_len > self.mlen) return error.DataException;
                        const in_stream = self.stream_produced;
                        if (self.cmd.distance > in_stream) {
                            self.cmd.copy_from_dict = @min(self.cmd.copy_len, self.cmd.distance - in_stream);
                            self.cmd.copy_dict_off = self.dict.len - (self.cmd.distance - in_stream);
                        } else {
                            self.cmd.copy_from_dict = 0;
                        }
                        self.cmd.copy_remaining = self.cmd.copy_len - self.cmd.copy_from_dict;
                        self.cmd.copy_src_pos = self.ring_pos - self.cmd.distance;
                        self.cmd.phase = .copy;
                    }
                },
                .word => {
                    while (self.cmd.word_off < self.cmd.word_len) {
                        try self.emitByte(self.cmd.word[self.cmd.word_off]);
                        self.cmd.word_off += 1;
                    }
                    self.mb_pos += self.cmd.word_len;
                    self.trackCtx(self.cmd.word_len);
                    self.cmd = .{ .phase = .ins_switch };
                },
                .copy => {
                    while (self.cmd.copy_from_dict > 0) {
                        const b = self.dict[self.cmd.copy_dict_off];
                        try self.emitByte(b);
                        self.cmd.copy_dict_off += 1;
                        self.cmd.copy_from_dict -= 1;
                    }
                    while (self.cmd.copy_remaining > 0) {
                        const b = self.ringByte(self.cmd.copy_src_pos);
                        try self.emitByte(b);
                        self.cmd.copy_src_pos += 1;
                        self.cmd.copy_remaining -= 1;
                    }
                    self.mb_pos += self.cmd.copy_len;
                    self.trackCtx(self.cmd.copy_len);
                    self.cmd = .{ .phase = .ins_switch };
                },
            }
        }
        self.endMetaBlock();
    }

    // Transformed static-dictionary word; mirrors copyDictionaryWord but
    // writes into the command word buffer instead of the output slice.
    fn buildDictionaryWord(self: *Incremental, copy_len: usize, distance: u32, max_backward: u32) DecodeError!usize {
        if (copy_len < dictionary.min_word_length or copy_len > dictionary.max_word_length) return error.DataException;
        const word_id: u64 = @as(u64, distance) - max_backward - 1;
        const nd: u6 = @intCast(dictionary.ndbits[copy_len]);
        const nwords: u64 = @as(u64, 1) << nd;
        const index = word_id % nwords;
        const transform_id = word_id / nwords;
        if (transform_id >= dictionary.transform_count) return error.DataException;
        const base_off: usize = dictionary.doffset[copy_len] + @as(usize, @intCast(index)) * copy_len;
        const word = dictionary.data[base_off..][0..copy_len];
        var buf: [64]u8 = undefined;
        var total: usize = 0;
        const t: usize = std.math.cast(usize, transform_id *% 3) orelse return error.DataException;
        const prefix = poolString(dictionary.transforms[std.math.cast(usize, t) orelse return error.DataException]);
        if (prefix.len > buf.len) return error.InternalException;
        @memcpy(buf[total..][0..prefix.len], prefix);
        total += prefix.len;
        const op = dictionary.transforms[t + 1];
        var word_part: []const u8 = word;
        var bufw: [dictionary.max_word_length]u8 = undefined;
        switch (op) {
            0 => {},
            1 => {
                @memcpy(bufw[0..word.len], word);
                fermentFirst(bufw[0..word.len]);
                word_part = bufw[0..word.len];
            },
            2 => {
                @memcpy(bufw[0..word.len], word);
                fermentAll(bufw[0..word.len]);
                word_part = bufw[0..word.len];
            },
            3...11 => {
                const k: usize = op - 2;
                word_part = if (word.len < k) word[0..0] else word[k..];
            },
            12...20 => {
                const k: usize = op - 11;
                word_part = if (word.len < k) word[0..0] else word[0 .. word.len - k];
            },
            else => return error.DataException,
        }
        @memcpy(buf[total..][0..word_part.len], word_part);
        total += word_part.len;
        const suffix = poolString(dictionary.transforms[t + 2]);
        if (total + suffix.len > buf.len) return error.InternalException;
        @memcpy(buf[total..][0..suffix.len], suffix);
        total += suffix.len;
        @memcpy(self.cmd.word[0..total], buf[0..total]);
        return total;
    }

    fn stStreamEnd(self: *Incremental) Status!void {
        try self.br.alignToByte();
        // Pull in whatever the current window still holds before deciding
        // more input is needed, so the caller always sees progress.
        _ = self.br.refill();
        const leftover: usize = self.br.nbits + (self.br.data.len - self.br.pos) * 8;
        if (leftover == 0) {
            if (self.end_of_input) {
                self.state = .done;
                return;
            }
            // The window is exhausted and the accumulator is empty; a
            // concatenated stream may still arrive.
            return error.NeedInput;
        }
        // Match the one-shot loop: another stream header is attempted
        // immediately; garbage fails there per the format rules. This also
        // keeps run boundaries making progress when the accumulator is
        // full, since stream-end yields would otherwise spin.
        self.wb_step = 0;
        self.mb_step = 0;
        self.state = .wbits;
    }
};

fn ringSizeFor(options: Options) usize {
    if (!options.large_window) return 1 << 24;
    return @as(usize, 1) << 30;
}

pub fn incrementalWorkspaceSize(options: Options) usize {
    const tables = max_trees * @sizeOf(HufTable);
    const symbols = max_trees * max_alphabet * @sizeOf(u16);
    const maps = 64 * 256 + 4 * 256;
    const header = std.mem.alignForward(usize, @sizeOf(Incremental) + 4096 + 16, 16);
    return header + tables + symbols + maps + ringSizeFor(options) + 4096;
}

pub fn incrementalInit(storage: []u8, options: Options) error{ResourceException}!Incremental {
    if (storage.len < incrementalWorkspaceSize(options)) return error.ResourceException;
    var inc = Incremental{};
    inc.large_window = options.large_window;
    inc.max_decoded = options.max_decoded_bytes;
    inc.dict = options.custom_dictionary orelse &.{};
    const ring_len = ringSizeFor(options);
    inc.ring_mask = ring_len - 1;
    var buf = storage;
    const off = std.mem.alignForward(usize, @intFromPtr(buf.ptr), 16) - @intFromPtr(buf.ptr);
    buf = buf[off..];
    const header_bytes = std.mem.alignForward(usize, @sizeOf(Incremental) + 4096 + 16, 16);
    if (buf.len < header_bytes + 16) return error.ResourceException;
    inc.sc = .{
        .tables = std.mem.bytesAsSlice(HufTable, @as([]align(8) u8, @alignCast(buf[header_bytes..][0 .. max_trees * @sizeOf(HufTable)]))),
        .symbols = std.mem.bytesAsSlice(u16, @as([]align(2) u8, @alignCast(buf[header_bytes + max_trees * @sizeOf(HufTable) ..][0 .. max_trees * max_alphabet * @sizeOf(u16)]))),
        .cmapl = buf[header_bytes + max_trees * @sizeOf(HufTable) + max_trees * max_alphabet * @sizeOf(u16) ..][0 .. 64 * 256],
        .cmapd = buf[header_bytes + max_trees * @sizeOf(HufTable) + max_trees * max_alphabet * @sizeOf(u16) + 64 * 256 ..][0 .. 4 * 256],
    };
    const ring_start = header_bytes + max_trees * @sizeOf(HufTable) + max_trees * max_alphabet * @sizeOf(u16) + 64 * 256 + 4 * 256;
    if (buf.len < ring_start + ring_len) return error.ResourceException;
    inc.ring = buf[ring_start..][0..ring_len];
    return inc;
}

const encode_mb_cap = 1 << 20;

const BitWriter = struct {
    out: []u8,
    pos: usize = 0,
    mask: u8 = 0,
    count_only: bool = false,

    fn writeBit(self: *BitWriter, bit: u32) EncodeError!void {
        if (self.mask == 0) {
            if (!self.count_only) {
                if (self.pos >= self.out.len) return error.CapacityException;
                self.out[self.pos] = 0;
            }
            self.mask = 1;
        }
        if (bit != 0 and !self.count_only) self.out[self.pos] |= self.mask;
        self.mask <<= 1;
        if (self.mask == 0) self.pos += 1;
    }

    fn writeBits(self: *BitWriter, value: u32, n: u5) EncodeError!void {
        var i: u5 = 0;
        while (i < n) : (i += 1) {
            try self.writeBit((value >> i) & 1);
        }
    }

    fn alignToByte(self: *BitWriter) void {
        if (self.mask != 0) {
            self.mask = 0;
            self.pos += 1;
        }
    }

    fn finish(self: *BitWriter) usize {
        self.alignToByte();
        return self.pos;
    }
};

const Command = struct {
    icode: u16,
    ins_extra: u32,
    ins_bits: u8,
    copy_extra: u32,
    copy_bits: u8,
    dcode: u16, // 0xFFFF = implicit distance 0 (no distance symbol emitted)
    dextra: u32,
    d_bits: u8,
    lit_start: u32,
    ins_len: u32,
};

fn icodeFor(ins_len: usize, copy_len: usize, implicit: bool) u16 {
    const ins_code: u32 = lengthToCode(@intCast(ins_len), &insert_base);
    const copy_code: u32 = lengthToCode(@intCast(copy_len), &copy_base);
    if (implicit and ins_code < 8) {
        if (copy_code < 8) return @intCast(ins_code * 8 + copy_code);
        if (copy_code < 16) return @intCast(64 + ins_code * 8 + (copy_code - 8));
    }
    var cell: u32 = undefined;
    if (copy_code < 8) {
        cell = if (ins_code < 8) 128 else if (ins_code < 16) 256 else 448;
    } else if (copy_code < 16) {
        cell = if (ins_code < 8) 192 else if (ins_code < 16) 320 else 576;
    } else {
        cell = if (ins_code < 8) 384 else if (ins_code < 16) 512 else 640;
    }
    return @intCast(cell + (ins_code & 7) * 8 + (copy_code & 7));
}

fn lengthToCode(len: u32, base: []const u32) u32 {
    var code: u32 = @intCast(base.len - 1);
    while (code > 0) : (code -= 1) {
        if (len >= base[code]) break;
    }
    return code;
}

// Inverse distance encoding with NPOSTFIX and NDIRECT both zero.
// Special codes 0..15 cover ring matches; the caller maps them.
fn normalDistance(distance: u32) struct { dcode: u16, extra: u32, bits: u8 } {
    const d = distance;
    var n: u5 = 1;
    while (d >= ((@as(u32, 4) << n) - 3)) n += 1;
    const parity: u32 = if (d < ((@as(u32, 3) << n) - 3)) 0 else 1;
    const offset = ((@as(u32, 2) + parity) << n) - 4;
    return .{ .dcode = @intCast(16 + 2 * (@as(u32, n) - 1) + parity), .extra = d - offset - 1, .bits = n };
}

fn trySpecialDistance(distance: u32, ring: *const [4]u32) ?u16 {
    for (0..16) |dc| {
        if (@as(i64, ring[ring_slot[dc]]) + ring_off[dc] == distance) return @intCast(dc);
    }
    return null;
}

const encode_head_words = 1 << 17;
const encode_command_cap = encode_mb_cap / 4 + 64;
pub const encode_workspace_size: usize = encode_head_words * 4 + encode_command_cap * @sizeOf(Command) + 4096 + 16;

pub fn encodeWorkspaceSize(_: Options) usize {
    return encode_workspace_size;
}

const code_order = [18]u8{ 1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

fn writeCodeLengthLen(bw: *BitWriter, len: u8) EncodeError!void {
    switch (len) {
        0 => try bw.writeBits(0b00, 2),
        1 => try bw.writeBits(0b0111, 4),
        2 => try bw.writeBits(0b011, 3),
        3 => try bw.writeBits(0b10, 2),
        4 => try bw.writeBits(0b01, 2),
        5 => try bw.writeBits(0b1111, 4),
        else => unreachable,
    }
}

// Canonical codes: symbols sorted by (length, symbol); codes assigned in
// order within each length.
fn canonicalCodes(lens: []const u8, codes: []u16) void {
    var count: [16]u32 = @splat(0);
    for (lens) |l| count[l] += 1;
    count[0] = 0;
    var next_code: [16]u32 = undefined;
    var code: u32 = 0;
    for (1..16) |l| {
        code = (code + count[l - 1]) << 1;
        next_code[l] = code;
    }
    for (lens, 0..) |l, s| {
        if (l != 0) {
            codes[s] = @intCast(next_code[l]);
            next_code[l] += 1;
        }
    }
}

fn writeSymbol(bw: *BitWriter, code: u16, len: u8) EncodeError!void {
    var i: u8 = 0;
    while (i < len) : (i += 1) {
        try bw.writeBit((code >> @intCast(len - 1 - i)) & 1);
    }
}

// Returns true for a single-symbol code with zero bits.

// Codes with at most four symbols use the simple form.
// Its length shapes are fixed by the format.

// Longer codes use the complex form; every length is transmitted directly.
fn writePrefixCode(bw: *BitWriter, lens: []u8, alphabet: usize) EncodeError!bool {
    var nused: usize = 0;
    for (lens[0..alphabet]) |l| {
        if (l != 0) {
            nused += 1;
        }
    }
    if (nused == 0) {
        try bw.writeBits(1, 2);
        try bw.writeBits(0, 2);
        const abits: u5 = @intCast(std.math.log2_int(usize, std.math.ceilPowerOfTwoAssert(usize, alphabet)));
        try bw.writeBits(0, abits);
        return true;
    }
    if (nused <= 4) {
        // Emission order (length, symbol) reproduces position-based lengths.
        var order: [4]u16 = undefined;
        var oi: usize = 0;
        for (1..16) |l| {
            for (lens[0..alphabet], 0..) |ll, sym| {
                if (ll == l and oi < nused) {
                    order[oi] = @intCast(sym);
                    oi += 1;
                }
            }
        }
        // Force the format's fixed shapes over this order.
        const shape: []const u8 = switch (nused) {
            1 => &.{1},
            2 => &.{ 1, 1 },
            3 => &.{ 1, 2, 2 },
            4 => &.{ 2, 2, 2, 2 },
            else => unreachable,
        };
        const all2 = nused == 4 and lens[order[0]] == 2 and lens[order[1]] == 2 and lens[order[2]] == 2 and lens[order[3]] == 2;
        const use_shape: []const u8 = if (nused == 4 and !all2) &.{ 1, 2, 3, 3 } else shape;
        for (order[0..nused], 0..) |sym, i| lens[sym] = use_shape[i];
        try bw.writeBits(1, 2);
        try bw.writeBits(@intCast(nused - 1), 2);
        const abits: u5 = @intCast(std.math.log2_int(usize, std.math.ceilPowerOfTwoAssert(usize, alphabet)));
        for (order[0..nused]) |sym| try bw.writeBits(sym, abits);
        if (nused == 4) try bw.writeBit(@intFromBool(!all2));
        return nused == 1;
    }
    // Complex form.
    if (lens[alphabet - 1] == lens[0]) {
        // One-length alphabets fail the Kraft check in the cl code.
        // One symbol moves up a level; two move down.
        const l0 = lens[0];
        const all_equal = for (lens[0..alphabet]) |l| {
            if (l != l0) break false;
        } else true;
        if (all_equal) {
            lens[0] = l0 - 1;
            lens[1] = l0 + 1;
            lens[2] = l0 + 1;
        }
    }
    var cl_freq: [18]u32 = @splat(0);
    for (lens[0..alphabet]) |l| cl_freq[l] += 1;
    var cl_lens: [18]u8 = undefined;
    huffman.limitedLengths(cl_freq[0..18], cl_lens[0..18], 5);
    var cl_codes: [18]u16 = undefined;
    canonicalCodes(cl_lens[0..18], cl_codes[0..18]);
    try bw.writeBits(0, 2); // HSKIP 0
    var last_order: usize = 17;
    while (last_order > 0 and cl_lens[code_order[last_order]] == 0) last_order -= 1;
    for (0..last_order + 1) |i| try writeCodeLengthLen(bw, cl_lens[code_order[i]]);
    var last_sym = alphabet - 1;
    while (last_sym > 0 and lens[last_sym] == 0) last_sym -= 1;
    for (0..last_sym + 1) |sym| try writeSymbol(bw, cl_codes[lens[sym]], cl_lens[lens[sym]]);
    return false;
}

fn encodeMetaBlock(bw: *BitWriter, src: []const u8, is_last: bool, ring: *[4]u32, workspace: []u8, dict: []const u8, dist_cap: u32, dist_alphabet: usize) EncodeError!void {
    const head = std.mem.bytesAsSlice(u32, @as([]align(4) u8, @alignCast(workspace[0 .. encode_head_words * 4])));
    const commands = std.mem.bytesAsSlice(Command, @as([]align(4) u8, @alignCast(workspace[encode_head_words * 4 ..][0 .. encode_command_cap * @sizeOf(Command)])));
    const cmd_count = parseCommands(src, dict, commands, head, ring, dist_cap);

    var lit_lens: [256]u8 = undefined;
    var icode_lens: [704]u8 = undefined;
    // The large-window decoder reads distance simple symbols with the wide
    // alphabet (BROTLI_DISTANCE_ALPHABET_SIZE with LARGE_MAX_DISTANCE_BITS),
    // so the emitted tree must use the same width; codes beyond 63 stay
    // unused (the encoder never emits them).
    var dcode_lens: [140]u8 = @splat(0);
    var lit_freq: [256]u32 = @splat(0);
    var icode_freq: [704]u32 = @splat(0);
    var dcode_freq: [140]u32 = @splat(0);
    for (commands[0..cmd_count]) |cmd| {
        icode_freq[cmd.icode] += 1;
        if (cmd.dcode != 0xFFFF) dcode_freq[cmd.dcode] += 1;
        const lits = src[cmd.lit_start..][0..cmd.ins_len];
        for (lits) |b| lit_freq[b] += 1;
    }
    huffman.limitedLengths(lit_freq[0..256], lit_lens[0..256], 15);
    huffman.limitedLengths(icode_freq[0..704], icode_lens[0..704], 15);
    huffman.limitedLengths(dcode_freq[0..140], dcode_lens[0..140], 15);
    var lit_codes: [256]u16 = undefined;
    var icode_codes: [704]u16 = undefined;
    var dcode_codes: [140]u16 = undefined;

    // Meta-block header per RFC 9.2.
    // One block type and one tree per category keep the middle trivial.
    try bw.writeBit(@intFromBool(is_last));
    if (is_last) {
        try bw.writeBit(0); // ISLASTEMPTY: the block carries data.
    }
    const mlen_minus1: u64 = src.len - 1;
    const nibbles: u5 = if (mlen_minus1 <= 0xFFFF) 4 else if (mlen_minus1 <= 0xFFFFF) 5 else 6;
    try bw.writeBits(@intCast(nibbles - 4), 2);
    try bw.writeBits(@intCast(mlen_minus1), @intCast(nibbles * 4));
    if (!is_last) {
        try bw.writeBit(0); // ISUNCOMPRESSED: the block is compressed.
    }
    // NBLTYPESL, NBLTYPESI, NBLTYPESD (each value 1: one 0 bit).
    try bw.writeBit(0);
    try bw.writeBit(0);
    try bw.writeBit(0);
    try bw.writeBits(0, 2); // NPOSTFIX
    try bw.writeBits(0, 4); // NDIRECT
    try bw.writeBits(0, 2); // context mode LSB6 for the single literal type
    try bw.writeBit(0); // NTREESL = 1
    try bw.writeBit(0); // NTREESD = 1
    const lit_single = try writePrefixCode(bw, lit_lens[0..256], 256);
    const icode_single = try writePrefixCode(bw, icode_lens[0..704], 704);
    const dcode_single = try writePrefixCode(bw, dcode_lens[0..dist_alphabet], dist_alphabet);
    // The writer fixes the final lengths first.
    // Canonical codes for the symbol bits come after it.
    canonicalCodes(lit_lens[0..256], lit_codes[0..256]);
    canonicalCodes(icode_lens[0..704], icode_codes[0..704]);
    canonicalCodes(dcode_lens[0..dist_alphabet], dcode_codes[0..dist_alphabet]);

    for (commands[0..cmd_count]) |cmd| {
        if (!icode_single) try writeSymbol(bw, icode_codes[cmd.icode], icode_lens[cmd.icode]);
        try bw.writeBits(cmd.ins_extra, @as(u5, @intCast(cmd.ins_bits)));
        try bw.writeBits(cmd.copy_extra, @as(u5, @intCast(cmd.copy_bits)));
        const lits = src[cmd.lit_start..][0..cmd.ins_len];
        for (lits) |b| {
            if (!lit_single) try writeSymbol(bw, lit_codes[b], lit_lens[b]);
        }
        if (cmd.dcode != 0xFFFF) {
            if (!dcode_single) try writeSymbol(bw, dcode_codes[cmd.dcode], dcode_lens[cmd.dcode]);
            try bw.writeBits(cmd.dextra, @as(u5, @intCast(cmd.d_bits)));
        }
    }
}

fn writeWindowBits(bw: *BitWriter, wbits: u5, large_window: bool) EncodeError!void {
    // Vendor EncodeWindowBits (enc/encode.c), LSB-first.
    if (large_window) {
        try bw.writeBits(0x11, 8); // 1, n=0, m=1, zero bit
        try bw.writeBits(wbits, 6);
    } else if (wbits == 16) {
        try bw.writeBits(0, 1);
    } else if (wbits == 17) {
        try bw.writeBits(1, 7);
    } else if (wbits > 17) {
        try bw.writeBits((@as(u32, wbits) - 17) << 1 | 1, 4);
    } else {
        try bw.writeBits((@as(u32, wbits) - 8) << 4 | 1, 7);
    }
}

fn pickWindow(input_len: usize, dict_len: usize, options: Options) struct { wbits: u5, large: bool } {
    const hard_cap: u64 = if (options.window_size != 0)
        @min(@as(u64, options.window_size), window_size_large_max)
    else if (options.large_window)
        window_size_large_max
    else
        window_size_max;
    const needed: u64 = @min(@as(u64, input_len) + dict_len, hard_cap);
    var wbits: u5 = 10;
    while (wbits < 30 and (@as(u64, 1) << wbits) - 16 < needed) wbits += 1;
    if ((@as(u64, 1) << wbits) - 16 > hard_cap or (wbits > 24 and !options.large_window)) {
        wbits = 24;
        while (wbits > 10 and (@as(u64, 1) << (wbits - 1)) - 16 >= needed) wbits -= 1;
    }
    return .{ .wbits = wbits, .large = wbits > 24 };
}

fn encodeBits(input: []const u8, bw: *BitWriter, ws: []u8, options: Options) EncodeError!void {
    const dict = options.custom_dictionary orelse &.{};
    const window = pickWindow(input.len, dict.len, options);
    const dist_cap: u32 = (@as(u32, 1) << window.wbits) - 16;
    try writeWindowBits(bw, window.wbits, window.large);
    var ring = distance_ring_init;
    if (input.len == 0) {
        try bw.writeBit(1); // ISLAST
        try bw.writeBit(1); // ISLASTEMPTY
        return;
    }
    var offset: usize = 0;
    while (offset < input.len) {
        const chunk = @min(encode_mb_cap, input.len - offset);
        const is_last = offset + chunk == input.len;
        try encodeMetaBlock(bw, input[offset..][0..chunk], is_last, &ring, ws, dict, dist_cap, if (window.large) 140 else 64);
        offset += chunk;
    }
}

fn encodeWorkspace(scratch: []u8) EncodeError![]u8 {
    return alignedSlice(scratch, encode_workspace_size);
}

pub fn encode(input: []const u8, output: []u8, scratch: []u8, options: Options) EncodeError!usize {
    const ws = try encodeWorkspace(scratch);
    var bw = BitWriter{ .out = output };
    try encodeBits(input, &bw, ws, options);
    return bw.finish();
}

pub fn encodeCountedSize(input: []const u8, scratch: []u8, options: Options) EncodeError!usize {
    const ws = try encodeWorkspace(scratch);
    var bw = BitWriter{ .out = &.{}, .count_only = true };
    try encodeBits(input, &bw, ws, options);
    return bw.finish();
}

// The encoder is new; the hermetic gate is a full round trip through this decoder.
test "brotli decode rejects oversubscribed cl codes" {
    // Adversarial prefixes once overflowed the Kraft accumulator instead
    // of answering DataException.
    const allocator = std.testing.allocator;
    const inputs = [_][]const u8{
        "Squdgy fez, blank jimp crwth vox!",
        "I have a friend who is always full",
    };
    for (inputs) |input| {
        const scratch = try allocator.alloc(u8, decode_workspace_size);
        defer allocator.free(scratch);
        const output = try allocator.alloc(u8, 4096);
        defer allocator.free(output);
        try std.testing.expectError(error.DataException, decode(input, output, scratch, .{}));
    }
    // 0x06 is a valid empty stream (WBITS 16, ISLAST, ISLASTEMPTY).
    {
        const scratch = try allocator.alloc(u8, decode_workspace_size);
        defer allocator.free(scratch);
        const output = try allocator.alloc(u8, 16);
        defer allocator.free(output);
        try std.testing.expectEqual(0, try decode(&.{0x06}, output, scratch, .{}));
    }
}

test "brotli encode mozilla corpus" {
    const allocator = std.testing.allocator;
    // CI unit jobs without the benchmark cache lack the Silesia corpus.
    const input = std.Io.Dir.cwd().readFileAlloc(std.testing.io, "zig-out/benchmark/corpus/mozilla", allocator, .limited(1 << 27)) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer allocator.free(input);
    const scratch = try allocator.alloc(u8, encode_workspace_size + decode_workspace_size);
    defer allocator.free(scratch);
    const bound = encodedSizeBound(input.len);
    const encoded = try allocator.alloc(u8, bound);
    defer allocator.free(encoded);
    const enc_len = try encode(input, encoded, scratch[0..encode_workspace_size], .{});
    const output = try allocator.alloc(u8, input.len + 16);
    defer allocator.free(output);
    const n = try decode(encoded[0..enc_len], output, scratch[encode_workspace_size..], .{});
    try std.testing.expectEqual(input.len, n);
    try std.testing.expectEqualSlices(u8, input, output[0..n]);
}

test "brotli encode roundtrips multi-block" {
    const allocator = std.testing.allocator;
    const sizes = [_]usize{ (1 << 20) + 1, (1 << 20) + 2, (1 << 20) + 3, (1 << 20) + 4, (1 << 20) + 8, (1 << 20) + 64, (1 << 20) + 1024 };
    for (sizes) |size| {
        const big = try allocator.alloc(u8, size);
        defer allocator.free(big);
        var state: u64 = 0x243F6A8885A308D3;
        for (big) |*b| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            b.* = @as(u8, @truncate(state)) & 7;
        }
        var i: usize = 1;
        while ((i << 16) + 4096 <= big.len) : (i += 1) {
            @memcpy(big[(1 << 16) * i ..][0..4096], big[0..4096]);
        }
        const scratch = try allocator.alloc(u8, encode_workspace_size + decode_workspace_size);
        defer allocator.free(scratch);
        const bound = encodedSizeBound(big.len);
        const encoded = try allocator.alloc(u8, bound);
        defer allocator.free(encoded);
        const enc_len = try encode(big, encoded, scratch[0..encode_workspace_size], .{});
        const output = try allocator.alloc(u8, big.len + 16);
        defer allocator.free(output);
        const n = try decode(encoded[0..enc_len], output, scratch[encode_workspace_size..], .{});
        try std.testing.expectEqual(big.len, n);
        try std.testing.expectEqualSlices(u8, big, output[0..n]);
    }
}

test "brotli encode roundtrips" {
    const allocator = std.testing.allocator;
    const cases = [_][]const u8{
        "",
        "a",
        "hello world, hello world, hello world!",
        "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc",
    };
    for (cases) |input| {
        const scratch = try allocator.alloc(u8, encode_workspace_size + decode_workspace_size);
        defer allocator.free(scratch);
        const bound = encodedSizeBound(input.len);
        const encoded = try allocator.alloc(u8, bound);
        defer allocator.free(encoded);
        const enc_len = try encode(input, encoded, scratch[0..encode_workspace_size], .{});
        const output = try allocator.alloc(u8, input.len + 16);
        defer allocator.free(output);
        const n = try decode(encoded[0..enc_len], output, scratch[encode_workspace_size..], .{});
        try std.testing.expectEqual(input.len, n);
        try std.testing.expectEqualSlices(u8, input, output[0..n]);
    }
    // A larger mixed input crosses command and multi-byte extras.
    var big: [1 << 17]u8 = undefined;
    var state: u64 = 0x243F6A8885A308D3;
    for (&big) |*b| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        b.* = @as(u8, @truncate(state)) & 7;
    }
    for (1..8) |i| {
        @memcpy(big[(1 << 14) * i ..][0..4096], big[0..4096]);
    }
    const scratch = try allocator.alloc(u8, encode_workspace_size + decode_workspace_size);
    defer allocator.free(scratch);
    const bound = encodedSizeBound(big.len);
    const encoded = try allocator.alloc(u8, bound);
    defer allocator.free(encoded);
    const enc_len = try encode(&big, encoded, scratch[0..encode_workspace_size], .{});
    const output = try allocator.alloc(u8, big.len + 16);
    defer allocator.free(output);
    const n = try decode(encoded[0..enc_len], output, scratch[encode_workspace_size..], .{});
    try std.testing.expectEqual(big.len, n);
    try std.testing.expectEqualSlices(u8, &big, output[0..n]);
}

// Streams hand-assembled bit by bit, then cross-validated against the
// system brotli CLI before embedding: each one pins a decode path that a
// round trip through our own encoder cannot reach.
test "brotli decode hand-built vendor validated streams" {
    const allocator = std.testing.allocator;
    const scratch = try allocator.alloc(u8, decode_workspace_size);
    defer allocator.free(scratch);

    const Case = struct { input: []const u8, want: []const u8 };
    const ok_cases = [_]Case{
        // MLEN 5, implicit distance 4 falls into the static dictionary.
        .{ .input = &.{ 0x82, 0x00, 0x00, 0x00, 0x04, 0x40, 0x0c, 0x10, 0x00 }, .want = "world" },
        // Two-symbol simple literal tree: reads must return in sorted
        // (len, value) order, so 0x41 decodes before 0x42.
        .{ .input = &.{ 0x22, 0x00, 0x00, 0x00, 0x94, 0x50, 0x50, 0x40, 0x10, 0x80 }, .want = "AB" },
        // Complex path whose code-length code space holds a single code:
        // every subsequent read is a zero-width symbol.
        .{ .input = &.{ 0x22, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0x01, 0x08 }, .want = "\x00\x01" },
        // Metadata-only last metablock skipping one aligned byte.
        .{ .input = &.{ 0x5a, 0x00, 0x00 }, .want = "" },
    };
    for (ok_cases) |case| {
        const output = try allocator.alloc(u8, 4096);
        defer allocator.free(output);
        const n = try decode(case.input, output, scratch, .{});
        try std.testing.expectEqualSlices(u8, case.want, output[0..n]);
    }

    const bad_cases = [_][]const u8{
        // A third length-2 code overflows the literal code space; the
        // vendor wraps a u32, we must answer DataException instead.
        &.{ 0x22, 0x00, 0x00, 0x00, 0x70, 0x07, 0x00, 0x00, 0x00, 0x70 },
        // Metadata skip length whose two payload bytes carry a
        // redundant leading zero.
        &.{ 0x9a, 0x00, 0x00 },
    };
    for (bad_cases) |input| {
        const output = try allocator.alloc(u8, 4096);
        defer allocator.free(output);
        try std.testing.expectError(error.DataException, decode(input, output, scratch, .{}));
    }
}

// WBITS edge encodings produced by the system brotli CLI: 10 and 17 use
// the long forms, 16 the single zero bit, and --large_window sets the
// reserved flag that only the large-window opt-in accepts.
test "brotli decode wbits acceptance and rejection" {
    const allocator = std.testing.allocator;
    const scratch = try allocator.alloc(u8, decode_workspace_size);
    defer allocator.free(scratch);
    const expected = "hello hello hello hello";
    const vectors = [_][]const u8{
        &.{ 0xa1, 0xb0, 0x00, 0x00, 0x20, 0x01, 0x52, 0x83, 0x28, 0x53, 0x87, 0xe7, 0xf4, 0x01 },
        &.{ 0xc2, 0x02, 0x00, 0x80, 0x04, 0x48, 0x0d, 0xa2, 0x4c, 0x1d, 0x9e, 0xd3, 0x07 },
        &.{ 0x81, 0xb0, 0x00, 0x00, 0x20, 0x01, 0x52, 0x83, 0x28, 0x53, 0x87, 0xe7, 0xf4, 0x01 },
    };
    for (vectors) |input| {
        const output = try allocator.alloc(u8, 4096);
        defer allocator.free(output);
        const n = try decode(input, output, scratch, .{});
        try std.testing.expectEqualSlices(u8, expected, output[0..n]);
    }
    // CLI --large-window=30 output: the reserved marker plus a 6-bit window
    // size. Strict by default; accepted under the large-window opt-in.
    const large_window = [_]u8{ 0x11, 0x5e, 0x58, 0x00, 0x00, 0x90, 0x00, 0xa9, 0x41, 0x94, 0xa9, 0x03, 0x0f, 0xa7, 0x0f };
    const output = try allocator.alloc(u8, 4096);
    defer allocator.free(output);
    try std.testing.expectError(error.DataException, decode(&large_window, output, scratch, .{}));
    const n = try decode(&large_window, output, scratch, .{ .large_window = true });
    try std.testing.expectEqualSlices(u8, expected, output[0..n]);
    // A set reserved bit after the marker is invalid even with the opt-in.
    const large_window_bad = [_]u8{ 0x11, 0xde, 0x58, 0x00, 0x00, 0x90, 0x00, 0xa9, 0x41, 0x94, 0xa9, 0x03, 0x0f, 0xa7, 0x0f };
    try std.testing.expectError(error.DataException, decode(&large_window_bad, output, scratch, .{ .large_window = true }));
}

test "brotli large window encode roundtrip" {
    const allocator = std.testing.allocator;
    const scratch = try allocator.alloc(u8, encode_workspace_size + decode_workspace_size);
    defer allocator.free(scratch);
    // The window option is a cap: an empty input still picks the smallest
    // legal window (WBITS 10 in the long form).
    const encoded = try allocator.alloc(u8, 64);
    defer allocator.free(encoded);
    const enc_len = try encode("", encoded, scratch[0..encode_workspace_size], .{ .large_window = true, .window_size = 1 << 25 });
    try std.testing.expectEqual(@as(usize, 2), enc_len);
    try std.testing.expectEqualSlices(u8, &.{ 0xa1, 0x01 }, encoded[0..2]);
    try std.testing.expectEqual(0, try decode(encoded[0..enc_len], encoded[30..50], scratch[encode_workspace_size..], .{}));

    // A payload past the 2^24 RFC window forces the large-window header
    // (marker + reserved zero + 6-bit window size 25) and round-trips.
    const size = (1 << 24) + 1;
    const big = try allocator.alloc(u8, size);
    defer allocator.free(big);
    var state: u64 = 0x243F6A8885A308D3;
    for (big) |*b| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        b.* = @as(u8, @truncate(state)) & 7;
    }
    for (1..256) |i| @memcpy(big[(1 << 16) * i ..][0..4096], big[0..4096]);
    const bound = encodedSizeBound(big.len);
    const big_encoded = try allocator.alloc(u8, bound);
    defer allocator.free(big_encoded);
    const big_len = try encode(big, big_encoded, scratch[0..encode_workspace_size], .{ .large_window = true });
    try std.testing.expectEqual(@as(u8, 0x11), big_encoded[0]);
    try std.testing.expectEqual(@as(u8, 25), big_encoded[1] & 0x3f);
    const big_output = try allocator.alloc(u8, big.len + 16);
    defer allocator.free(big_output);
    const n = try decode(big_encoded[0..big_len], big_output, scratch[encode_workspace_size..], .{ .large_window = true });
    try std.testing.expectEqual(big.len, n);
    try std.testing.expectEqualSlices(u8, big, big_output[0..n]);
    // The same stream is rejected without the opt-in.
    try std.testing.expectError(error.DataException, decode(big_encoded[0..big_len], big_output, scratch[encode_workspace_size..], .{}));
}

test "brotli custom dictionary roundtrip and spanning copy" {
    const allocator = std.testing.allocator;
    const scratch = try allocator.alloc(u8, encode_workspace_size + decode_workspace_size);
    defer allocator.free(scratch);
    const dict = "0123456789abcdef the quick brown fox jumps over the lazy dog";
    // The payload begins with a repeat of the dictionary tail and then
    // crosses into newly produced output: one match spans the boundary.
    const input = "jumps over the lazy dog and jumps over the lazy dog again";
    const bound = encodedSizeBound(input.len);
    const encoded = try allocator.alloc(u8, bound);
    defer allocator.free(encoded);
    const enc_len = try encode(input, encoded, scratch[0..encode_workspace_size], .{ .custom_dictionary = dict });
    // Header is the smallest covering window (auto-picked, non-large).
    const output = try allocator.alloc(u8, input.len + 16);
    defer allocator.free(output);
    const n = try decode(encoded[0..enc_len], output, scratch[encode_workspace_size..], .{ .custom_dictionary = dict });
    try std.testing.expectEqual(input.len, n);
    try std.testing.expectEqualSlices(u8, input, output[0..n]);
    // Without the dictionary the distances reach before position zero and
    // either mis-decode or fail; they must never read out of bounds.
    if (decode(encoded[0..enc_len], output, scratch[encode_workspace_size..], .{})) |m| {
        try std.testing.expect(m != n or !std.mem.eql(u8, input, output[0..m]));
    } else |err| {
        try std.testing.expect(err == error.DataException);
    }
    // Encoded distance into the dictionary prefix: force a pure dictionary
    // match. "the quick brown fox" appears only in the dictionary.
    const dict2 = "the quick brown fox";
    const input2 = "the quick brown fox!";
    const enc2 = try allocator.alloc(u8, encodedSizeBound(input2.len));
    defer allocator.free(enc2);
    const enc2_len = try encode(input2, enc2, scratch[0..encode_workspace_size], .{ .custom_dictionary = dict2 });
    const n2 = try decode(enc2[0..enc2_len], output, scratch[encode_workspace_size..], .{ .custom_dictionary = dict2 });
    try std.testing.expectEqualSlices(u8, input2, output[0..n2]);
}

// Static-dictionary transforms, exercised directly: copy_len 5 words all
// start at dictionary index 3 ("world"), and word_id / 1024 selects the
// transform row. Prefixes and suffixes come from the vendor
// length-prefixed pool, so entry 49 is the empty string.
test "brotli copy dictionary word transforms" {
    var p1: u8 = 0;
    var p2: u8 = 0;
    const Case = struct { distance: u32, want: []const u8 };
    const cases = [_]Case{
        .{ .distance = 4, .want = "world" },
        .{ .distance = 1028, .want = "world " },
        .{ .distance = 4100, .want = "World " },
        .{ .distance = 15364, .want = " World " },
        .{ .distance = 33796, .want = " world, " },
    };
    for (cases) |case| {
        var output: [64]u8 = undefined;
        var produced: usize = 0;
        const total = try copyDictionaryWord(&output, &produced, 5, case.distance, 0, &p1, &p2);
        try std.testing.expectEqual(case.want.len, total);
        try std.testing.expectEqual(case.want.len, produced);
        try std.testing.expectEqualSlices(u8, case.want, output[0..total]);
    }
    // word_id 123904 selects transform 121, one past the table end.
    var output: [64]u8 = undefined;
    var produced: usize = 0;
    try std.testing.expectError(error.DataException, copyDictionaryWord(&output, &produced, 5, 123905, 0, &p1, &p2));
}

test "brotli incremental matches one-shot across chunkings" {
    const allocator = std.testing.allocator;
    const scratch = try allocator.alloc(u8, incrementalWorkspaceSize(.{}));
    defer allocator.free(scratch);
    const one_shot_scratch = try allocator.alloc(u8, decode_workspace_size);
    defer allocator.free(one_shot_scratch);

    const payloads = [_][]const u8{
        "A",
        "hello world, hello world, hello world!",
        "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc",
    };
    for (payloads) |input| {
        const bound = encodedSizeBound(input.len);
        const encoded = try allocator.alloc(u8, bound);
        defer allocator.free(encoded);
        const enc_len = try encode(input, encoded, scratch[0..encode_workspace_size], .{});
        var oracle: [256]u8 = undefined;
        const n = try decode(encoded[0..enc_len], &oracle, one_shot_scratch, .{});
        var inc = try incrementalInit(scratch, .{});
        var out: [256]u8 = undefined;
        const res = try inc.run(encoded[0..enc_len], &out, true);
        try std.testing.expect(res.status == .done);
        try std.testing.expectEqualSlices(u8, oracle[0..n], out[0..res.produced]);
    }

    // A multi-block stream plus a concatenated second stream, exercised
    // with adversarial (input chunk, output span) combinations including
    // 1-byte drains, which stress NeedDrain suspension on every emit.
    var big: [1 << 17]u8 = undefined;
    var state: u64 = 0x243F6A8885A308D3;
    for (&big) |*b| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        b.* = @as(u8, @truncate(state)) & 7;
    }
    for (1..8) |i| @memcpy(big[(1 << 14) * i ..][0..4096], big[0..4096]);
    const bound = encodedSizeBound(big.len) + encodedSizeBound(64);
    const stream = try allocator.alloc(u8, bound);
    defer allocator.free(stream);
    const part_len = try encode(&big, stream, scratch[0..encode_workspace_size], .{});
    const tail_len = try encode("tail stream two", stream[part_len..], scratch[0..encode_workspace_size], .{});
    const total_len = part_len + tail_len;

    var oracle: [big.len + 64]u8 = undefined;
    const n = try decode(stream[0..total_len], &oracle, one_shot_scratch, .{});
    try std.testing.expectEqual(big.len + "tail stream two".len, n);

    var out_buf: [big.len + 64]u8 = undefined;
    const chunk_sizes = [_]usize{ 1, 3, 7, 64, 1024, total_len };
    const span_sizes = [_]usize{ 1, 5, 4096, oracle.len };
    for (chunk_sizes) |chunk| {
        for (span_sizes) |span| {
            var inc = try incrementalInit(scratch, .{});
            var fed: usize = 0;
            var produced: usize = 0;
            var guard: usize = 0;
            while (true) {
                const end = @min(fed + chunk, total_len);
                const out_end = @min(produced + span, out_buf.len);
                const res = try inc.run(stream[fed..end], out_buf[produced..out_end], end == total_len);
                if (res.produced > 0) {
                    try std.testing.expectEqualSlices(u8, oracle[produced .. produced + res.produced], out_buf[produced .. produced + res.produced]);
                }
                fed += res.consumed;
                produced += res.produced;
                guard += 1;
                if (guard > 64 * (total_len + out_buf.len + 8)) return error.ResourceException;
                if (res.status == .done) break;
            }
            try std.testing.expectEqual(n, produced);
            try std.testing.expectEqualSlices(u8, oracle[0..n], out_buf[0..produced]);
        }
    }
    // Whole-input single-run equivalence with an independent buffer.
    var inc = try incrementalInit(scratch, .{});
    var produced_final: usize = 0;
    var fed: usize = 0;
    while (true) {
        const res = try inc.run(stream[fed..total_len], out_buf[produced_final..], true);
        fed += res.consumed;
        produced_final += res.produced;
        if (res.status == .done) break;
    }
    try std.testing.expectEqualSlices(u8, oracle[0..n], out_buf[0..produced_final]);
}
