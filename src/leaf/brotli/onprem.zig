// Brotli compressed data format (RFC 7932), algorithm-level port with the
// RFC sections cited inline.

const std = @import("std");

const kernels = @import("../../common/kernels.zig");
// Complex prefix codes transmit lengths directly.
// That is larger but always valid.
const huffman = @import("../../common/primitive/huffman.zig");
const dictionary = @import("dictionary.zig");

pub const DecodeError = error{ UnsupportedException, DataException, ResourceException, CapacityException, InternalException, IoException };
pub const EncodeError = error{ UnsupportedException, DataException, ResourceException, CapacityException, InternalException };

pub const Options = struct {
    quality: u32 = 5,
    max_decoded_bytes: u64 = std.math.maxInt(u64),
};

pub const window_size_min = 1 << 10;
pub const window_size_max = (1 << 24) - 16;

pub fn encodedSizeBound(input_len: usize) usize {
    return input_len +| (input_len >> 1) +| 1024;
}

pub fn decodedSize(input: []const u8, scratch: []u8, options: Options) DecodeError!usize {
    // No size field exists in the format, so the measured route decodes
    // into the writer staging and counts. Outputs beyond the staging
    // answer ResourceException; the windowed streaming decode is the
    // recorded follow-up.
    _ = try alignedWorkspace(scratch);
    const staging = scratch[scratch.len - writer_staging_size ..][0..writer_staging_size];
    return decode(input, staging, scratch, options);
}

// Writer-sink staging: the format carries no output size, and the v1
// decoder is one-shot over a slice. decodeToWriter therefore stages through
// the workspace. A windowed streaming decode is the recorded follow-up.
// Measured-size staging must cover the largest corpus output until the
// windowed streaming decode replaces the one-shot count.
const writer_staging_size = 64 << 20;

pub const decode_workspace_size: usize = blk: {
    const tables = max_trees * @sizeOf(HufTable);
    const symbols = max_trees * max_alphabet * @sizeOf(u16);
    const maps = 64 * 256 + 4 * 256;
    break :blk tables + symbols + maps + writer_staging_size + 4096 + 16;
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
    _ = try alignedWorkspace(scratch);
    const staging = scratch[scratch.len - writer_staging_size ..][0..writer_staging_size];
    const produced = try decode(input, staging, scratch, options);
    writer.writeAll(staging[0..produced]) catch return error.IoException;
}

pub fn requiredSize(input: []const u8, scratch: []u8, options: Options) EncodeError!usize {
    return encodeCountedSize(input, scratch, options);
}

pub fn decodeWorkspaceSize(_: Options) usize {
    return decode_workspace_size;
}

fn hash4At(src: []const u8, pos: usize) usize {
    const w = std.mem.readInt(u32, src[pos..][0..4], .little);
    return (w *% 0x9E37_79B1) >> (32 - 17);
}

fn parseCommands(src: []const u8, commands: []Command, head: []u32, ring: *[4]u32) usize {
    @memset(head, 0);
    var count: usize = 0;
    var pos: usize = 0;
    var anchor: usize = 0;
    while (pos + 4 <= src.len) {
        const h = hash4At(src, pos);
        const cand_plus1 = head[h];
        head[h] = @intCast(pos + 1);
        if (cand_plus1 != 0) {
            const cand: usize = cand_plus1 - 1;
            const dist = pos - cand;
            if (dist <= (1 << 22) - 16) {
                const len = kernels.matchLen8(src, cand, pos, src.len - pos);
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
            v |= (try self.readBit()) << i;
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
        }
    }
    if (space != 0) return error.DataException;
    const tree = try sc.allocTree(18);
    const table = tree.table;
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

fn readPrefixCode(br: *BitReader, sc: *Scratch, alphabet: usize) DecodeError!*HufTable {
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
            if (sym >= alphabet) return error.DataException;
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
        // For NSYM > 1 the symbols must be re-sorted per length for the
        // canonical decode walk: bit-walk order is (len, symbol).
        if (nsym > 1) {
            var offset = canonicalOffsets(tree.table.count);
            var saved: [4]u16 = undefined;
            @memcpy(saved[0..nsym], tree.table.symbols[0..nsym]);
            for (0..nsym) |i| {
                const l = lens[i];
                tree.table.symbols[offset[l]] = saved[i];
                offset[l] += 1;
            }
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
    while (symbol_count < alphabet and space > 0) {
        const sym = try clcode.decode(br);
        if (sym < 16) {
            lengths.table.symbols[symbol_count] = sym;
            symbol_count += 1;
            repeat = 0;
            repeat_len = 0;
            if (sym != 0) {
                prev_len = @intCast(sym);
                space -= @as(u32, 32768) >> @intCast(sym);
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
    const tree = try readPrefixCode(br, sc, @intCast(num_trees + rlemax));
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

fn decodeMetaBlock(
    br: *BitReader,
    sc: *Scratch,
    output: []u8,
    produced: *usize,
    stream_base: usize,
    p1: *u8,
    p2: *u8,
    ring: *[4]u32,
    window_size: u32,
    is_last: *bool,
    empty_end: *bool,
) DecodeError!void {
    empty_end.* = false;
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
            skiplen = @intCast(v + 1);
            if (mskipbytes > 1 and (v & 0xFF) == 0 and mskipbytes == ((v >> 8) + 1)) return error.DataException;
        }
        try br.alignToByte();
        if (br.pos + skiplen > br.data.len) return error.DataException;
        br.pos += skiplen;
        is_last.* = false;
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
            cat.type_tree = try readPrefixCode(br, sc, @intCast(cat.num_types + 2));
            cat.count_tree = try readPrefixCode(br, sc, 26);
            try cat.readCount(br);
        }
    }
    const npostfix: u5 = @intCast(try br.readBits(2));
    const ndirect: u32 = (try br.readBits(4)) << npostfix;
    const postfix_mask: u32 = (@as(u32, 1) << npostfix) - 1;

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
    for (0..ntreesl) |i| lit_trees[i] = try readPrefixCode(br, sc, 256);
    var ins_trees: [256]*HufTable = undefined;
    for (0..ins.num_types) |i| ins_trees[i] = try readPrefixCode(br, sc, 704);
    var dist_trees: [256]*HufTable = undefined;
    for (0..ntreesd) |i| dist_trees[i] = try readPrefixCode(br, sc, @intCast(16 + ndirect + (@as(u32, 48) << npostfix)));

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
        const max_backward = @min(window_size, produced.* - stream_base);
        if (distance > max_backward) {
            // RFC 8: a static dictionary reference.
            if (implicit_dist0) return error.DataException;
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
        kernels.copyMatch(output, produced.*, distance, @intCast(copy_len));
        produced.* += copy_len;
        trackContext(p1, p2, output, produced.* - 1, copy_len);
        pos += copy_len;
    }
}

// ---------------------------------------------------------------- decode

fn readWbits(br: *BitReader) DecodeError!u32 {
    if (try br.readBit() == 0) return 16;
    const n = try br.readBits(3);
    if (n != 0) return 17 + n;
    if (try br.readBit() == 0) return 17;
    const m = try br.readBits(3);
    if (m != 0) return 8 + m;
    return 10;
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
    // Concatenated streams (gzip-style): each stream carries its own WBITS
    // header. The ring and context bytes reset per stream (RFC 4, 7.1).
    while (true) {
        const wbits = try readWbits(&br);
        const window_size: u32 = (@as(u32, 1) << @intCast(wbits)) - 16;
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
            try decodeMetaBlock(&br, &sc, output, &produced, stream_base, &p1, &p2, &ring, window_size, &is_last, &empty_end);
            if (empty_end) {
                // ISLASTEMPTY: zero fill to the byte boundary, no trailing
                // bytes except the start of a concatenated stream.
                try br.alignToByte();
                break;
            }
            if (is_last) break;
            if (produced > options.max_decoded_bytes) return error.ResourceException;
        }
        // The last meta-block may end mid-byte; the fill must be zero and
        // a concatenated stream starts at the next byte boundary.
        try br.alignToByte();
        if (br.atEnd()) break;
    }
    return produced;
}

// Reference-encoder vectors (brotli CLI, quality 5). The random vector
// reproduces the generator inline; the concatenated pair checks the
// multi-stream loop.
test "brotli decodes reference vectors" {
    const allocator = std.testing.allocator;
    var text: [4096]u8 = undefined;
    for (&text, 0..) |*b, i| b.* = @truncate((i *% 2654435761) >> 13);
    const text_br = [_]u8{ 0x1f, 0xff, 0x0f, 0x00, 0x8c, 0xd4, 0x48, 0x4d, 0x73, 0xbb, 0x81, 0x71, 0x3a, 0x93, 0x67, 0x8a, 0x53, 0x8e, 0xaf, 0xae, 0xb3, 0x6f, 0x0f, 0xcc, 0x33, 0x94, 0xb8, 0x83, 0x60, 0x13, 0x61, 0x75, 0x91, 0x37, 0x7b, 0xb2, 0xe8, 0xc7, 0x3e, 0xf5, 0xc2, 0x1a, 0x71, 0x79, 0xa6, 0x83, 0x31, 0x4b, 0xb5, 0xfd, 0x6f, 0x2d, 0xe0, 0xa8, 0x64, 0xbe, 0xaf, 0x12, 0x44, 0xe3, 0xc8, 0x01, 0xf1, 0x6e, 0x8e, 0x02, 0x67, 0x65, 0xcb, 0x43, 0x8d, 0x28, 0x9e, 0x44, 0x0f, 0x49, 0x0f, 0x4b, 0x0c, 0x34, 0xaf, 0x58, 0x1f, 0xeb, 0x24, 0xc9, 0x34, 0x06, 0x22, 0x3f, 0xad, 0x71, 0xf0, 0xa2, 0x6a, 0x7b, 0x6a, 0x90, 0xa5, 0xb3, 0x38, 0x98, 0xf2, 0xb2, 0x25, 0x20, 0xcb, 0x9a, 0xfd, 0xb9, 0x49, 0x91, 0xcd, 0x13, 0x10, 0xda, 0xdb, 0x9e, 0x84, 0xae, 0x65, 0x8e, 0x97, 0x16, 0x4d, 0xbe, 0x48, 0x42, 0xe9, 0x75, 0x47, 0x0a, 0xb6, 0x91, 0x3b, 0x5f, 0xdb, 0x74, 0xc5, 0x32, 0x05, 0x63, 0x34, 0x9c, 0x69, 0xf8, 0x56, 0xe1, 0x7a, 0xeb, 0x30, 0x94, 0xab, 0x34, 0x9c, 0xd9, 0x74, 0x65, 0x10, 0x3b, 0xa5, 0xfb, 0xbd, 0xcb, 0x54, 0xad, 0x33, 0x08, 0x56, 0xcb, 0x9d, 0x45, 0x9e, 0xa8, 0x3c, 0x1f, 0x3d, 0x96, 0x66, 0x93, 0x45, 0xb2, 0x3b, 0x9e, 0x1c, 0xea, 0x54, 0xe3, 0xfd, 0xec, 0xb3, 0xb5, 0xdb, 0x1c, 0x8a, 0xd3, 0xf5, 0xe6, 0xd1, 0x47, 0xad, 0xef, 0x6b, 0xc0, 0xd1, 0x5d, 0xe6, 0xd1, 0xdc, 0xaf, 0xaf, 0x80, 0x39, 0xe9, 0xfc, 0xdf, 0x43, 0xae, 0xfe, 0xaa, 0x80, 0xe1, 0xfd, 0xfc, 0x45, 0xec, 0x85, 0x3e, 0xf0, 0x33, 0xe2, 0x19, 0xae, 0x8b, 0x58, 0xfe, 0x3f, 0xb0, 0x83, 0xbb, 0x18, 0x42, 0xbf, 0x63, 0xbe, 0xf1, 0xb6, 0x84, 0x13, 0x0c, 0x43, 0xbb, 0xf8, 0xab, 0x31, 0xfc, 0x37, 0x11, 0x98, 0xee, 0xca, 0x78, 0xe1, 0x28, 0xbc, 0x47, 0xb8, 0x99, 0x22, 0xff, 0x53, 0xa1, 0xf9, 0xbe, 0x42, 0x10, 0x8d, 0x23, 0xfb, 0xc4, 0xbb, 0x39, 0x0a, 0x98, 0x95, 0x2d, 0x0f, 0x55, 0xa2, 0x78, 0x12, 0x3d, 0x20, 0x3d, 0x2c, 0x31, 0xe0, 0xbc, 0x62, 0x7d, 0xac, 0xfd, 0x8d, 0x6a, 0x85, 0x8a, 0x66, 0x8d, 0x86, 0x9e, 0x6e, 0xa8, 0xb5, 0xa9, 0x69, 0x74, 0x68, 0x2a, 0x5a, 0x41, 0x37, 0x82, 0x42, 0x6e, 0x85, 0x2a, 0x61, 0x00, 0x90, 0x3a, 0x10, 0xb0, 0x46, 0x05, 0x8c, 0x8e, 0x61, 0x8b, 0x81, 0xe9, 0x38, 0x65, 0xfa, 0xd0, 0xd2, 0xf9, 0xd2, 0xd1, 0xfb, 0xa5, 0x7a, 0x77, 0xc2, 0x22, 0xee, 0x45, 0x44, 0x2b, 0x0f, 0x20, 0x9a, 0x20, 0xa0, 0x5a, 0xa0, 0x15, 0x18, 0x96, 0x13, 0x2c, 0x6c, 0x07, 0xec, 0x0a, 0x87, 0xc1, 0x80, 0x81, 0xd1, 0x90, 0x31, 0x35, 0x89, 0x8a, 0x79, 0x14, 0x13, 0xf7, 0x24, 0x9e, 0x26, 0xb4, 0xc1, 0xc0, 0x75, 0xc0, 0x21, 0x2a, 0x5d, 0x47, 0x1c, 0x5c, 0xe7, 0xb8, 0x78, 0x95, 0xb3, 0x11, 0x13, 0xb3, 0x31, 0x33, 0x4b, 0x65, 0xe2, 0x59, 0x42, 0xd2, 0x8b, 0xa4, 0x54, 0xfa, 0x0a, 0x01, 0xa9, 0x07, 0x09, 0xa5, 0x0f, 0x95, 0xa2, 0xf1, 0xf0, 0x5d, 0xf0, 0x09, 0x5c, 0x2b, 0x02, 0x16, 0x56, 0x53, 0x56, 0x36, 0xb3, 0x8a, 0x4d, 0x4a, 0xda, 0x9b, 0xb4, 0x8c, 0xf7, 0x4a, 0xc6, 0x00, 0x1a, 0xc6, 0x10, 0x06, 0x36, 0x1d, 0x11, 0xba, 0x29, 0x11, 0xb9, 0x2b, 0x13, 0xa7, 0x0f, 0x76, 0x73, 0x76, 0x0e, 0x0b, 0x8e, 0x8a, 0x53, 0xd6, 0x87, 0xac, 0x9c, 0x4f, 0xb9, 0x4a, 0x1e, 0x16, 0xce, 0x18, 0x0e, 0xde, 0xa4, 0x82, 0x57, 0x21, 0xf1, 0x54, 0x25, 0xf5, 0x4a, 0xa5, 0x96, 0x9c, 0x5c, 0x56, 0x5c, 0xdc, 0xd6, 0xa9, 0xdb, 0x97, 0xbc, 0x82, 0x6f, 0x05, 0xc5, 0xca, 0x0f, 0xc2, 0x61, 0xa6, 0x9c, 0xbb, 0x76, 0xee, 0xda, 0xa5, 0xaf, 0x34, 0xf8, 0xe3, 0x69, 0x36, 0x40, 0x35, 0xa0, 0x36, 0x10, 0x34, 0x50, 0xf7, 0x76, 0x3b, 0xa0, 0x33, 0x10, 0x31, 0x00, 0x31, 0xc0, 0xf2, 0xd6, 0x30, 0xf0, 0x68, 0x00, 0x6e, 0x80, 0x6b, 0xc0, 0xec, 0x6d, 0x72, 0xa0, 0x67, 0xe0, 0x62, 0x60, 0x6a, 0xe0, 0xcd, 0x5b, 0xcc, 0x80, 0xd0, 0x80, 0xdd, 0xed, 0x00 };
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
    const random_br = [_]u8{ 0x1f, 0xff, 0x0f, 0x00, 0x8c, 0xd4, 0x48, 0x4d, 0x73, 0xbb, 0x81, 0x71, 0x3a, 0x93, 0x67, 0x8a, 0x53, 0x8e, 0xaf, 0xae, 0xb3, 0x6f, 0x0f, 0xcc, 0x33, 0x94, 0xb8, 0x83, 0x60, 0x13, 0x61, 0x75, 0x91, 0x37, 0x7b, 0xb2, 0xe8, 0xc7, 0x3e, 0xf5, 0xc2, 0x1a, 0x71, 0x79, 0xa6, 0x83, 0x31, 0x4b, 0xb5, 0xfd, 0x6f, 0x2d, 0xe0, 0xa8, 0x64, 0xbe, 0xaf, 0x12, 0x44, 0xe3, 0xc8, 0x01, 0xf1, 0x6e, 0x8e, 0x02, 0x67, 0x65, 0xcb, 0x43, 0x8d, 0x28, 0x9e, 0x44, 0x0f, 0x49, 0x0f, 0x4b, 0x0c, 0x34, 0xaf, 0x58, 0x1f, 0xeb, 0x24, 0xc9, 0x34, 0x06, 0x22, 0x3f, 0xad, 0x71, 0xf0, 0xa2, 0x6a, 0x7b, 0x6a, 0x90, 0xa5, 0xb3, 0x38, 0x98, 0xf2, 0xb2, 0x25, 0x20, 0xcb, 0x9a, 0xfd, 0xb9, 0x49, 0x91, 0xcd, 0x13, 0x10, 0xda, 0xdb, 0x9e, 0x84, 0xae, 0x65, 0x8e, 0x97, 0x16, 0x4d, 0xbe, 0x48, 0x42, 0xe9, 0x75, 0x47, 0x0a, 0xb6, 0x91, 0x3b, 0x5f, 0xdb, 0x74, 0xc5, 0x32, 0x05, 0x63, 0x34, 0x9c, 0x69, 0xf8, 0x56, 0xe1, 0x7a, 0xeb, 0x30, 0x94, 0xab, 0x34, 0x9c, 0xd9, 0x74, 0x65, 0x10, 0x3b, 0xa5, 0xfb, 0xbd, 0xcb, 0x54, 0xad, 0x33, 0x08, 0x56, 0xcb, 0x9d, 0x45, 0x9e, 0xa8, 0x3c, 0x1f, 0x3d, 0x96, 0x66, 0x93, 0x45, 0xb2, 0x3b, 0x9e, 0x1c, 0xea, 0x54, 0xe3, 0xfd, 0xec, 0xb3, 0xb5, 0xdb, 0x1c, 0x8a, 0xd3, 0xf5, 0xe6, 0xd1, 0x47, 0xad, 0xef, 0x6b, 0xc0, 0xd1, 0x5d, 0xe6, 0xd1, 0xdc, 0xaf, 0xaf, 0x80, 0x39, 0xe9, 0xfc, 0xdf, 0x43, 0xae, 0xfe, 0xaa, 0x80, 0xe1, 0xfd, 0xfc, 0x45, 0xec, 0x85, 0x3e, 0xf0, 0x33, 0xe2, 0x19, 0xae, 0x8b, 0x58, 0xfe, 0x3f, 0xb0, 0x83, 0xbb, 0x18, 0x42, 0xbf, 0x63, 0xbe, 0xf1, 0xb6, 0x84, 0x13, 0x0c, 0x43, 0xbb, 0xf8, 0xab, 0x31, 0xfc, 0x37, 0x11, 0x98, 0xee, 0xca, 0x78, 0xe1, 0x28, 0xbc, 0x47, 0xb8, 0x99, 0x22, 0xff, 0x53, 0xa1, 0xf9, 0xbe, 0x42, 0x10, 0x8d, 0x23, 0xfb, 0xc4, 0xbb, 0x39, 0x0a, 0x98, 0x95, 0x2d, 0x0f, 0x55, 0xa2, 0x78, 0x12, 0x3d, 0x20, 0x3d, 0x2c, 0x31, 0xe0, 0xbc, 0x62, 0x7d, 0xac, 0xfd, 0x8d, 0x6a, 0x85, 0x8a, 0x66, 0x8d, 0x86, 0x9e, 0x6e, 0xa8, 0xb5, 0xa9, 0x69, 0x74, 0x68, 0x2a, 0x5a, 0x41, 0x37, 0x82, 0x42, 0x6e, 0x85, 0x2a, 0x61, 0x00, 0x90, 0x3a, 0x10, 0xb0, 0x46, 0x05, 0x8c, 0x8e, 0x61, 0x8b, 0x81, 0xe9, 0x38, 0x65, 0xfa, 0xd0, 0xd2, 0xf9, 0xd2, 0xd1, 0xfb, 0xa5, 0x7a, 0x77, 0xc2, 0x22, 0xee, 0x45, 0x44, 0x2b, 0x0f, 0x20, 0x9a, 0x20, 0xa0, 0x5a, 0xa0, 0x15, 0x18, 0x96, 0x13, 0x2c, 0x6c, 0x07, 0xec, 0x0a, 0x87, 0xc1, 0x80, 0x81, 0xd1, 0x90, 0x31, 0x35, 0x89, 0x8a, 0x79, 0x14, 0x13, 0xf7, 0x24, 0x9e, 0x26, 0xb4, 0xc1, 0xc0, 0x75, 0xc0, 0x21, 0x2a, 0x5d, 0x47, 0x1c, 0x5c, 0xe7, 0xb8, 0x78, 0x95, 0xb3, 0x11, 0x13, 0xb3, 0x31, 0x33, 0x4b, 0x65, 0xe2, 0x59, 0x42, 0xd2, 0x8b, 0xa4, 0x54, 0xfa, 0x0a, 0x01, 0xa9, 0x07, 0x09, 0xa5, 0x0f, 0x95, 0xa2, 0xf1, 0xf0, 0x5d, 0xf0, 0x09, 0x5c, 0x2b, 0x02, 0x16, 0x56, 0x53, 0x56, 0x36, 0xb3, 0x8a, 0x4d, 0x4a, 0xda, 0x9b, 0xb4, 0x8c, 0xf7, 0x4a, 0xc6, 0x00, 0x1a, 0xc6, 0x10, 0x06, 0x36, 0x1d, 0x11, 0xba, 0x29, 0x11, 0xb9, 0x2b, 0x13, 0xa7, 0x0f, 0x76, 0x73, 0x76, 0x0e, 0x0b, 0x8e, 0x8a, 0x53, 0xd6, 0x87, 0xac, 0x9c, 0x4f, 0xb9, 0x4a, 0x1e, 0x16, 0xce, 0x18, 0x0e, 0xde, 0xa4, 0x82, 0x57, 0x21, 0xf1, 0x54, 0x25, 0xf5, 0x4a, 0xa5, 0x96, 0x9c, 0x5c, 0x56, 0x5c, 0xdc, 0xd6, 0xa9, 0xdb, 0x97, 0xbc, 0x82, 0x6f, 0x05, 0xc5, 0xca, 0x0f, 0xc2, 0x61, 0xa6, 0x9c, 0xbb, 0x76, 0xee, 0xda, 0xa5, 0xaf, 0x34, 0xf8, 0xe3, 0x69, 0x36, 0x40, 0x35, 0xa0, 0x36, 0x10, 0x34, 0x50, 0xf7, 0x76, 0x3b, 0xa0, 0x33, 0x10, 0x31, 0x00, 0x31, 0xc0, 0xf2, 0xd6, 0x30, 0xf0, 0x68, 0x00, 0x6e, 0x80, 0x6b, 0xc0, 0xec, 0x6d, 0x72, 0xa0, 0x67, 0xe0, 0x62, 0x60, 0x6a, 0xe0, 0xcd, 0x5b, 0xcc, 0x80, 0xd0, 0x80, 0xdd, 0xed, 0x00 };
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
    var text: [4096]u8 = undefined;
    for (&text, 0..) |*b, i| b.* = @truncate((i *% 2654435761) >> 13);
    const text_br = [_]u8{ 0x1f, 0xff, 0x0f, 0x00, 0x8c, 0xd4, 0x48, 0x4d, 0x73, 0xbb, 0x81, 0x71, 0x3a, 0x93, 0x67, 0x8a, 0x53, 0x8e, 0xaf, 0xae, 0xb3, 0x6f, 0x0f, 0xcc, 0x33, 0x94, 0xb8, 0x83, 0x60, 0x13, 0x61, 0x75, 0x91, 0x37, 0x7b, 0xb2, 0xe8, 0xc7, 0x3e, 0xf5, 0xc2, 0x1a, 0x71, 0x79, 0xa6, 0x83, 0x31, 0x4b, 0xb5, 0xfd, 0x6f, 0x2d, 0xe0, 0xa8, 0x64, 0xbe, 0xaf, 0x12, 0x44, 0xe3, 0xc8, 0x01, 0xf1, 0x6e, 0x8e, 0x02, 0x67, 0x65, 0xcb, 0x43, 0x8d, 0x28, 0x9e, 0x44, 0x0f, 0x49, 0x0f, 0x4b, 0x0c, 0x34, 0xaf, 0x58, 0x1f, 0xeb, 0x24, 0xc9, 0x34, 0x06, 0x22, 0x3f, 0xad, 0x71, 0xf0, 0xa2, 0x6a, 0x7b, 0x6a, 0x90, 0xa5, 0xb3, 0x38, 0x98, 0xf2, 0xb2, 0x25, 0x20, 0xcb, 0x9a, 0xfd, 0xb9, 0x49, 0x91, 0xcd, 0x13, 0x10, 0xda, 0xdb, 0x9e, 0x84, 0xae, 0x65, 0x8e, 0x97, 0x16, 0x4d, 0xbe, 0x48, 0x42, 0xe9, 0x75, 0x47, 0x0a, 0xb6, 0x91, 0x3b, 0x5f, 0xdb, 0x74, 0xc5, 0x32, 0x05, 0x63, 0x34, 0x9c, 0x69, 0xf8, 0x56, 0xe1, 0x7a, 0xeb, 0x30, 0x94, 0xab, 0x34, 0x9c, 0xd9, 0x74, 0x65, 0x10, 0x3b, 0xa5, 0xfb, 0xbd, 0xcb, 0x54, 0xad, 0x33, 0x08, 0x56, 0xcb, 0x9d, 0x45, 0x9e, 0xa8, 0x3c, 0x1f, 0x3d, 0x96, 0x66, 0x93, 0x45, 0xb2, 0x3b, 0x9e, 0x1c, 0xea, 0x54, 0xe3, 0xfd, 0xec, 0xb3, 0xb5, 0xdb, 0x1c, 0x8a, 0xd3, 0xf5, 0xe6, 0xd1, 0x47, 0xad, 0xef, 0x6b, 0xc0, 0xd1, 0x5d, 0xe6, 0xd1, 0xdc, 0xaf, 0xaf, 0x80, 0x39, 0xe9, 0xfc, 0xdf, 0x43, 0xae, 0xfe, 0xaa, 0x80, 0xe1, 0xfd, 0xfc, 0x45, 0xec, 0x85, 0x3e, 0xf0, 0x33, 0xe2, 0x19, 0xae, 0x8b, 0x58, 0xfe, 0x3f, 0xb0, 0x83, 0xbb, 0x18, 0x42, 0xbf, 0x63, 0xbe, 0xf1, 0xb6, 0x84, 0x13, 0x0c, 0x43, 0xbb, 0xf8, 0xab, 0x31, 0xfc, 0x37, 0x11, 0x98, 0xee, 0xca, 0x78, 0xe1, 0x28, 0xbc, 0x47, 0xb8, 0x99, 0x22, 0xff, 0x53, 0xa1, 0xf9, 0xbe, 0x42, 0x10, 0x8d, 0x23, 0xfb, 0xc4, 0xbb, 0x39, 0x0a, 0x98, 0x95, 0x2d, 0x0f, 0x55, 0xa2, 0x78, 0x12, 0x3d, 0x20, 0x3d, 0x2c, 0x31, 0xe0, 0xbc, 0x62, 0x7d, 0xac, 0xfd, 0x8d, 0x6a, 0x85, 0x8a, 0x66, 0x8d, 0x86, 0x9e, 0x6e, 0xa8, 0xb5, 0xa9, 0x69, 0x74, 0x68, 0x2a, 0x5a, 0x41, 0x37, 0x82, 0x42, 0x6e, 0x85, 0x2a, 0x61, 0x00, 0x90, 0x3a, 0x10, 0xb0, 0x46, 0x05, 0x8c, 0x8e, 0x61, 0x8b, 0x81, 0xe9, 0x38, 0x65, 0xfa, 0xd0, 0xd2, 0xf9, 0xd2, 0xd1, 0xfb, 0xa5, 0x7a, 0x77, 0xc2, 0x22, 0xee, 0x45, 0x44, 0x2b, 0x0f, 0x20, 0x9a, 0x20, 0xa0, 0x5a, 0xa0, 0x15, 0x18, 0x96, 0x13, 0x2c, 0x6c, 0x07, 0xec, 0x0a, 0x87, 0xc1, 0x80, 0x81, 0xd1, 0x90, 0x31, 0x35, 0x89, 0x8a, 0x79, 0x14, 0x13, 0xf7, 0x24, 0x9e, 0x26, 0xb4, 0xc1, 0xc0, 0x75, 0xc0, 0x21, 0x2a, 0x5d, 0x47, 0x1c, 0x5c, 0xe7, 0xb8, 0x78, 0x95, 0xb3, 0x11, 0x13, 0xb3, 0x31, 0x33, 0x4b, 0x65, 0xe2, 0x59, 0x42, 0xd2, 0x8b, 0xa4, 0x54, 0xfa, 0x0a, 0x01, 0xa9, 0x07, 0x09, 0xa5, 0x0f, 0x95, 0xa2, 0xf1, 0xf0, 0x5d, 0xf0, 0x09, 0x5c, 0x2b, 0x02, 0x16, 0x56, 0x53, 0x56, 0x36, 0xb3, 0x8a, 0x4d, 0x4a, 0xda, 0x9b, 0xb4, 0x8c, 0xf7, 0x4a, 0xc6, 0x00, 0x1a, 0xc6, 0x10, 0x06, 0x36, 0x1d, 0x11, 0xba, 0x29, 0x11, 0xb9, 0x2b, 0x13, 0xa7, 0x0f, 0x76, 0x73, 0x76, 0x0e, 0x0b, 0x8e, 0x8a, 0x53, 0xd6, 0x87, 0xac, 0x9c, 0x4f, 0xb9, 0x4a, 0x1e, 0x16, 0xce, 0x18, 0x0e, 0xde, 0xa4, 0x82, 0x57, 0x21, 0xf1, 0x54, 0x25, 0xf5, 0x4a, 0xa5, 0x96, 0x9c, 0x5c, 0x56, 0x5c, 0xdc, 0xd6, 0xa9, 0xdb, 0x97, 0xbc, 0x82, 0x6f, 0x05, 0xc5, 0xca, 0x0f, 0xc2, 0x61, 0xa6, 0x9c, 0xbb, 0x76, 0xee, 0xda, 0xa5, 0xaf, 0x34, 0xf8, 0xe3, 0x69, 0x36, 0x40, 0x35, 0xa0, 0x36, 0x10, 0x34, 0x50, 0xf7, 0x76, 0x3b, 0xa0, 0x33, 0x10, 0x31, 0x00, 0x31, 0xc0, 0xf2, 0xd6, 0x30, 0xf0, 0x68, 0x00, 0x6e, 0x80, 0x6b, 0xc0, 0xec, 0x6d, 0x72, 0xa0, 0x67, 0xe0, 0x62, 0x60, 0x6a, 0xe0, 0xcd, 0x5b, 0xcc, 0x80, 0xd0, 0x80, 0xdd, 0xed, 0x00 };
    const scratch = try allocator.alloc(u8, decode_workspace_size);
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
    var text: [4096]u8 = undefined;
    for (&text, 0..) |*b, i| b.* = @truncate((i *% 2654435761) >> 13);
    const text_br = [_]u8{ 0x1f, 0xff, 0x0f, 0x00, 0x8c, 0xd4, 0x48, 0x4d, 0x73, 0xbb, 0x81, 0x71, 0x3a, 0x93, 0x67, 0x8a, 0x53, 0x8e, 0xaf, 0xae, 0xb3, 0x6f, 0x0f, 0xcc, 0x33, 0x94, 0xb8, 0x83, 0x60, 0x13, 0x61, 0x75, 0x91, 0x37, 0x7b, 0xb2, 0xe8, 0xc7, 0x3e, 0xf5, 0xc2, 0x1a, 0x71, 0x79, 0xa6, 0x83, 0x31, 0x4b, 0xb5, 0xfd, 0x6f, 0x2d, 0xe0, 0xa8, 0x64, 0xbe, 0xaf, 0x12, 0x44, 0xe3, 0xc8, 0x01, 0xf1, 0x6e, 0x8e, 0x02, 0x67, 0x65, 0xcb, 0x43, 0x8d, 0x28, 0x9e, 0x44, 0x0f, 0x49, 0x0f, 0x4b, 0x0c, 0x34, 0xaf, 0x58, 0x1f, 0xeb, 0x24, 0xc9, 0x34, 0x06, 0x22, 0x3f, 0xad, 0x71, 0xf0, 0xa2, 0x6a, 0x7b, 0x6a, 0x90, 0xa5, 0xb3, 0x38, 0x98, 0xf2, 0xb2, 0x25, 0x20, 0xcb, 0x9a, 0xfd, 0xb9, 0x49, 0x91, 0xcd, 0x13, 0x10, 0xda, 0xdb, 0x9e, 0x84, 0xae, 0x65, 0x8e, 0x97, 0x16, 0x4d, 0xbe, 0x48, 0x42, 0xe9, 0x75, 0x47, 0x0a, 0xb6, 0x91, 0x3b, 0x5f, 0xdb, 0x74, 0xc5, 0x32, 0x05, 0x63, 0x34, 0x9c, 0x69, 0xf8, 0x56, 0xe1, 0x7a, 0xeb, 0x30, 0x94, 0xab, 0x34, 0x9c, 0xd9, 0x74, 0x65, 0x10, 0x3b, 0xa5, 0xfb, 0xbd, 0xcb, 0x54, 0xad, 0x33, 0x08, 0x56, 0xcb, 0x9d, 0x45, 0x9e, 0xa8, 0x3c, 0x1f, 0x3d, 0x96, 0x66, 0x93, 0x45, 0xb2, 0x3b, 0x9e, 0x1c, 0xea, 0x54, 0xe3, 0xfd, 0xec, 0xb3, 0xb5, 0xdb, 0x1c, 0x8a, 0xd3, 0xf5, 0xe6, 0xd1, 0x47, 0xad, 0xef, 0x6b, 0xc0, 0xd1, 0x5d, 0xe6, 0xd1, 0xdc, 0xaf, 0xaf, 0x80, 0x39, 0xe9, 0xfc, 0xdf, 0x43, 0xae, 0xfe, 0xaa, 0x80, 0xe1, 0xfd, 0xfc, 0x45, 0xec, 0x85, 0x3e, 0xf0, 0x33, 0xe2, 0x19, 0xae, 0x8b, 0x58, 0xfe, 0x3f, 0xb0, 0x83, 0xbb, 0x18, 0x42, 0xbf, 0x63, 0xbe, 0xf1, 0xb6, 0x84, 0x13, 0x0c, 0x43, 0xbb, 0xf8, 0xab, 0x31, 0xfc, 0x37, 0x11, 0x98, 0xee, 0xca, 0x78, 0xe1, 0x28, 0xbc, 0x47, 0xb8, 0x99, 0x22, 0xff, 0x53, 0xa1, 0xf9, 0xbe, 0x42, 0x10, 0x8d, 0x23, 0xfb, 0xc4, 0xbb, 0x39, 0x0a, 0x98, 0x95, 0x2d, 0x0f, 0x55, 0xa2, 0x78, 0x12, 0x3d, 0x20, 0x3d, 0x2c, 0x31, 0xe0, 0xbc, 0x62, 0x7d, 0xac, 0xfd, 0x8d, 0x6a, 0x85, 0x8a, 0x66, 0x8d, 0x86, 0x9e, 0x6e, 0xa8, 0xb5, 0xa9, 0x69, 0x74, 0x68, 0x2a, 0x5a, 0x41, 0x37, 0x82, 0x42, 0x6e, 0x85, 0x2a, 0x61, 0x00, 0x90, 0x3a, 0x10, 0xb0, 0x46, 0x05, 0x8c, 0x8e, 0x61, 0x8b, 0x81, 0xe9, 0x38, 0x65, 0xfa, 0xd0, 0xd2, 0xf9, 0xd2, 0xd1, 0xfb, 0xa5, 0x7a, 0x77, 0xc2, 0x22, 0xee, 0x45, 0x44, 0x2b, 0x0f, 0x20, 0x9a, 0x20, 0xa0, 0x5a, 0xa0, 0x15, 0x18, 0x96, 0x13, 0x2c, 0x6c, 0x07, 0xec, 0x0a, 0x87, 0xc1, 0x80, 0x81, 0xd1, 0x90, 0x31, 0x35, 0x89, 0x8a, 0x79, 0x14, 0x13, 0xf7, 0x24, 0x9e, 0x26, 0xb4, 0xc1, 0xc0, 0x75, 0xc0, 0x21, 0x2a, 0x5d, 0x47, 0x1c, 0x5c, 0xe7, 0xb8, 0x78, 0x95, 0xb3, 0x11, 0x13, 0xb3, 0x31, 0x33, 0x4b, 0x65, 0xe2, 0x59, 0x42, 0xd2, 0x8b, 0xa4, 0x54, 0xfa, 0x0a, 0x01, 0xa9, 0x07, 0x09, 0xa5, 0x0f, 0x95, 0xa2, 0xf1, 0xf0, 0x5d, 0xf0, 0x09, 0x5c, 0x2b, 0x02, 0x16, 0x56, 0x53, 0x56, 0x36, 0xb3, 0x8a, 0x4d, 0x4a, 0xda, 0x9b, 0xb4, 0x8c, 0xf7, 0x4a, 0xc6, 0x00, 0x1a, 0xc6, 0x10, 0x06, 0x36, 0x1d, 0x11, 0xba, 0x29, 0x11, 0xb9, 0x2b, 0x13, 0xa7, 0x0f, 0x76, 0x73, 0x76, 0x0e, 0x0b, 0x8e, 0x8a, 0x53, 0xd6, 0x87, 0xac, 0x9c, 0x4f, 0xb9, 0x4a, 0x1e, 0x16, 0xce, 0x18, 0x0e, 0xde, 0xa4, 0x82, 0x57, 0x21, 0xf1, 0x54, 0x25, 0xf5, 0x4a, 0xa5, 0x96, 0x9c, 0x5c, 0x56, 0x5c, 0xdc, 0xd6, 0xa9, 0xdb, 0x97, 0xbc, 0x82, 0x6f, 0x05, 0xc5, 0xca, 0x0f, 0xc2, 0x61, 0xa6, 0x9c, 0xbb, 0x76, 0xee, 0xda, 0xa5, 0xaf, 0x34, 0xf8, 0xe3, 0x69, 0x36, 0x40, 0x35, 0xa0, 0x36, 0x10, 0x34, 0x50, 0xf7, 0x76, 0x3b, 0xa0, 0x33, 0x10, 0x31, 0x00, 0x31, 0xc0, 0xf2, 0xd6, 0x30, 0xf0, 0x68, 0x00, 0x6e, 0x80, 0x6b, 0xc0, 0xec, 0x6d, 0x72, 0xa0, 0x67, 0xe0, 0x62, 0x60, 0x6a, 0xe0, 0xcd, 0x5b, 0xcc, 0x80, 0xd0, 0x80, 0xdd, 0xed, 0x00 };
    const buffer = try allocator.alloc(u8, decode_workspace_size + text_br.len + 3);
    defer allocator.free(buffer);
    @memset(buffer, 0xaa);
    const scratch = buffer[3..][0..decode_workspace_size];
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
    var text: [4096]u8 = undefined;
    for (&text, 0..) |*b, i| b.* = @truncate((i *% 2654435761) >> 13);
    const text_br = [_]u8{ 0x1f, 0xff, 0x0f, 0x00, 0x8c, 0xd4, 0x48, 0x4d, 0x73, 0xbb, 0x81, 0x71, 0x3a, 0x93, 0x67, 0x8a, 0x53, 0x8e, 0xaf, 0xae, 0xb3, 0x6f, 0x0f, 0xcc, 0x33, 0x94, 0xb8, 0x83, 0x60, 0x13, 0x61, 0x75, 0x91, 0x37, 0x7b, 0xb2, 0xe8, 0xc7, 0x3e, 0xf5, 0xc2, 0x1a, 0x71, 0x79, 0xa6, 0x83, 0x31, 0x4b, 0xb5, 0xfd, 0x6f, 0x2d, 0xe0, 0xa8, 0x64, 0xbe, 0xaf, 0x12, 0x44, 0xe3, 0xc8, 0x01, 0xf1, 0x6e, 0x8e, 0x02, 0x67, 0x65, 0xcb, 0x43, 0x8d, 0x28, 0x9e, 0x44, 0x0f, 0x49, 0x0f, 0x4b, 0x0c, 0x34, 0xaf, 0x58, 0x1f, 0xeb, 0x24, 0xc9, 0x34, 0x06, 0x22, 0x3f, 0xad, 0x71, 0xf0, 0xa2, 0x6a, 0x7b, 0x6a, 0x90, 0xa5, 0xb3, 0x38, 0x98, 0xf2, 0xb2, 0x25, 0x20, 0xcb, 0x9a, 0xfd, 0xb9, 0x49, 0x91, 0xcd, 0x13, 0x10, 0xda, 0xdb, 0x9e, 0x84, 0xae, 0x65, 0x8e, 0x97, 0x16, 0x4d, 0xbe, 0x48, 0x42, 0xe9, 0x75, 0x47, 0x0a, 0xb6, 0x91, 0x3b, 0x5f, 0xdb, 0x74, 0xc5, 0x32, 0x05, 0x63, 0x34, 0x9c, 0x69, 0xf8, 0x56, 0xe1, 0x7a, 0xeb, 0x30, 0x94, 0xab, 0x34, 0x9c, 0xd9, 0x74, 0x65, 0x10, 0x3b, 0xa5, 0xfb, 0xbd, 0xcb, 0x54, 0xad, 0x33, 0x08, 0x56, 0xcb, 0x9d, 0x45, 0x9e, 0xa8, 0x3c, 0x1f, 0x3d, 0x96, 0x66, 0x93, 0x45, 0xb2, 0x3b, 0x9e, 0x1c, 0xea, 0x54, 0xe3, 0xfd, 0xec, 0xb3, 0xb5, 0xdb, 0x1c, 0x8a, 0xd3, 0xf5, 0xe6, 0xd1, 0x47, 0xad, 0xef, 0x6b, 0xc0, 0xd1, 0x5d, 0xe6, 0xd1, 0xdc, 0xaf, 0xaf, 0x80, 0x39, 0xe9, 0xfc, 0xdf, 0x43, 0xae, 0xfe, 0xaa, 0x80, 0xe1, 0xfd, 0xfc, 0x45, 0xec, 0x85, 0x3e, 0xf0, 0x33, 0xe2, 0x19, 0xae, 0x8b, 0x58, 0xfe, 0x3f, 0xb0, 0x83, 0xbb, 0x18, 0x42, 0xbf, 0x63, 0xbe, 0xf1, 0xb6, 0x84, 0x13, 0x0c, 0x43, 0xbb, 0xf8, 0xab, 0x31, 0xfc, 0x37, 0x11, 0x98, 0xee, 0xca, 0x78, 0xe1, 0x28, 0xbc, 0x47, 0xb8, 0x99, 0x22, 0xff, 0x53, 0xa1, 0xf9, 0xbe, 0x42, 0x10, 0x8d, 0x23, 0xfb, 0xc4, 0xbb, 0x39, 0x0a, 0x98, 0x95, 0x2d, 0x0f, 0x55, 0xa2, 0x78, 0x12, 0x3d, 0x20, 0x3d, 0x2c, 0x31, 0xe0, 0xbc, 0x62, 0x7d, 0xac, 0xfd, 0x8d, 0x6a, 0x85, 0x8a, 0x66, 0x8d, 0x86, 0x9e, 0x6e, 0xa8, 0xb5, 0xa9, 0x69, 0x74, 0x68, 0x2a, 0x5a, 0x41, 0x37, 0x82, 0x42, 0x6e, 0x85, 0x2a, 0x61, 0x00, 0x90, 0x3a, 0x10, 0xb0, 0x46, 0x05, 0x8c, 0x8e, 0x61, 0x8b, 0x81, 0xe9, 0x38, 0x65, 0xfa, 0xd0, 0xd2, 0xf9, 0xd2, 0xd1, 0xfb, 0xa5, 0x7a, 0x77, 0xc2, 0x22, 0xee, 0x45, 0x44, 0x2b, 0x0f, 0x20, 0x9a, 0x20, 0xa0, 0x5a, 0xa0, 0x15, 0x18, 0x96, 0x13, 0x2c, 0x6c, 0x07, 0xec, 0x0a, 0x87, 0xc1, 0x80, 0x81, 0xd1, 0x90, 0x31, 0x35, 0x89, 0x8a, 0x79, 0x14, 0x13, 0xf7, 0x24, 0x9e, 0x26, 0xb4, 0xc1, 0xc0, 0x75, 0xc0, 0x21, 0x2a, 0x5d, 0x47, 0x1c, 0x5c, 0xe7, 0xb8, 0x78, 0x95, 0xb3, 0x11, 0x13, 0xb3, 0x31, 0x33, 0x4b, 0x65, 0xe2, 0x59, 0x42, 0xd2, 0x8b, 0xa4, 0x54, 0xfa, 0x0a, 0x01, 0xa9, 0x07, 0x09, 0xa5, 0x0f, 0x95, 0xa2, 0xf1, 0xf0, 0x5d, 0xf0, 0x09, 0x5c, 0x2b, 0x02, 0x16, 0x56, 0x53, 0x56, 0x36, 0xb3, 0x8a, 0x4d, 0x4a, 0xda, 0x9b, 0xb4, 0x8c, 0xf7, 0x4a, 0xc6, 0x00, 0x1a, 0xc6, 0x10, 0x06, 0x36, 0x1d, 0x11, 0xba, 0x29, 0x11, 0xb9, 0x2b, 0x13, 0xa7, 0x0f, 0x76, 0x73, 0x76, 0x0e, 0x0b, 0x8e, 0x8a, 0x53, 0xd6, 0x87, 0xac, 0x9c, 0x4f, 0xb9, 0x4a, 0x1e, 0x16, 0xce, 0x18, 0x0e, 0xde, 0xa4, 0x82, 0x57, 0x21, 0xf1, 0x54, 0x25, 0xf5, 0x4a, 0xa5, 0x96, 0x9c, 0x5c, 0x56, 0x5c, 0xdc, 0xd6, 0xa9, 0xdb, 0x97, 0xbc, 0x82, 0x6f, 0x05, 0xc5, 0xca, 0x0f, 0xc2, 0x61, 0xa6, 0x9c, 0xbb, 0x76, 0xee, 0xda, 0xa5, 0xaf, 0x34, 0xf8, 0xe3, 0x69, 0x36, 0x40, 0x35, 0xa0, 0x36, 0x10, 0x34, 0x50, 0xf7, 0x76, 0x3b, 0xa0, 0x33, 0x10, 0x31, 0x00, 0x31, 0xc0, 0xf2, 0xd6, 0x30, 0xf0, 0x68, 0x00, 0x6e, 0x80, 0x6b, 0xc0, 0xec, 0x6d, 0x72, 0xa0, 0x67, 0xe0, 0x62, 0x60, 0x6a, 0xe0, 0xcd, 0x5b, 0xcc, 0x80, 0xd0, 0x80, 0xdd, 0xed, 0x00 };
    const random_br = [_]u8{ 0x1f, 0xff, 0x0f, 0x00, 0x8c, 0xd4, 0x48, 0x4d, 0x73, 0xbb, 0x81, 0x71, 0x3a, 0x93, 0x67, 0x8a, 0x53, 0x8e, 0xaf, 0xae, 0xb3, 0x6f, 0x0f, 0xcc, 0x33, 0x94, 0xb8, 0x83, 0x60, 0x13, 0x61, 0x75, 0x91, 0x37, 0x7b, 0xb2, 0xe8, 0xc7, 0x3e, 0xf5, 0xc2, 0x1a, 0x71, 0x79, 0xa6, 0x83, 0x31, 0x4b, 0xb5, 0xfd, 0x6f, 0x2d, 0xe0, 0xa8, 0x64, 0xbe, 0xaf, 0x12, 0x44, 0xe3, 0xc8, 0x01, 0xf1, 0x6e, 0x8e, 0x02, 0x67, 0x65, 0xcb, 0x43, 0x8d, 0x28, 0x9e, 0x44, 0x0f, 0x49, 0x0f, 0x4b, 0x0c, 0x34, 0xaf, 0x58, 0x1f, 0xeb, 0x24, 0xc9, 0x34, 0x06, 0x22, 0x3f, 0xad, 0x71, 0xf0, 0xa2, 0x6a, 0x7b, 0x6a, 0x90, 0xa5, 0xb3, 0x38, 0x98, 0xf2, 0xb2, 0x25, 0x20, 0xcb, 0x9a, 0xfd, 0xb9, 0x49, 0x91, 0xcd, 0x13, 0x10, 0xda, 0xdb, 0x9e, 0x84, 0xae, 0x65, 0x8e, 0x97, 0x16, 0x4d, 0xbe, 0x48, 0x42, 0xe9, 0x75, 0x47, 0x0a, 0xb6, 0x91, 0x3b, 0x5f, 0xdb, 0x74, 0xc5, 0x32, 0x05, 0x63, 0x34, 0x9c, 0x69, 0xf8, 0x56, 0xe1, 0x7a, 0xeb, 0x30, 0x94, 0xab, 0x34, 0x9c, 0xd9, 0x74, 0x65, 0x10, 0x3b, 0xa5, 0xfb, 0xbd, 0xcb, 0x54, 0xad, 0x33, 0x08, 0x56, 0xcb, 0x9d, 0x45, 0x9e, 0xa8, 0x3c, 0x1f, 0x3d, 0x96, 0x66, 0x93, 0x45, 0xb2, 0x3b, 0x9e, 0x1c, 0xea, 0x54, 0xe3, 0xfd, 0xec, 0xb3, 0xb5, 0xdb, 0x1c, 0x8a, 0xd3, 0xf5, 0xe6, 0xd1, 0x47, 0xad, 0xef, 0x6b, 0xc0, 0xd1, 0x5d, 0xe6, 0xd1, 0xdc, 0xaf, 0xaf, 0x80, 0x39, 0xe9, 0xfc, 0xdf, 0x43, 0xae, 0xfe, 0xaa, 0x80, 0xe1, 0xfd, 0xfc, 0x45, 0xec, 0x85, 0x3e, 0xf0, 0x33, 0xe2, 0x19, 0xae, 0x8b, 0x58, 0xfe, 0x3f, 0xb0, 0x83, 0xbb, 0x18, 0x42, 0xbf, 0x63, 0xbe, 0xf1, 0xb6, 0x84, 0x13, 0x0c, 0x43, 0xbb, 0xf8, 0xab, 0x31, 0xfc, 0x37, 0x11, 0x98, 0xee, 0xca, 0x78, 0xe1, 0x28, 0xbc, 0x47, 0xb8, 0x99, 0x22, 0xff, 0x53, 0xa1, 0xf9, 0xbe, 0x42, 0x10, 0x8d, 0x23, 0xfb, 0xc4, 0xbb, 0x39, 0x0a, 0x98, 0x95, 0x2d, 0x0f, 0x55, 0xa2, 0x78, 0x12, 0x3d, 0x20, 0x3d, 0x2c, 0x31, 0xe0, 0xbc, 0x62, 0x7d, 0xac, 0xfd, 0x8d, 0x6a, 0x85, 0x8a, 0x66, 0x8d, 0x86, 0x9e, 0x6e, 0xa8, 0xb5, 0xa9, 0x69, 0x74, 0x68, 0x2a, 0x5a, 0x41, 0x37, 0x82, 0x42, 0x6e, 0x85, 0x2a, 0x61, 0x00, 0x90, 0x3a, 0x10, 0xb0, 0x46, 0x05, 0x8c, 0x8e, 0x61, 0x8b, 0x81, 0xe9, 0x38, 0x65, 0xfa, 0xd0, 0xd2, 0xf9, 0xd2, 0xd1, 0xfb, 0xa5, 0x7a, 0x77, 0xc2, 0x22, 0xee, 0x45, 0x44, 0x2b, 0x0f, 0x20, 0x9a, 0x20, 0xa0, 0x5a, 0xa0, 0x15, 0x18, 0x96, 0x13, 0x2c, 0x6c, 0x07, 0xec, 0x0a, 0x87, 0xc1, 0x80, 0x81, 0xd1, 0x90, 0x31, 0x35, 0x89, 0x8a, 0x79, 0x14, 0x13, 0xf7, 0x24, 0x9e, 0x26, 0xb4, 0xc1, 0xc0, 0x75, 0xc0, 0x21, 0x2a, 0x5d, 0x47, 0x1c, 0x5c, 0xe7, 0xb8, 0x78, 0x95, 0xb3, 0x11, 0x13, 0xb3, 0x31, 0x33, 0x4b, 0x65, 0xe2, 0x59, 0x42, 0xd2, 0x8b, 0xa4, 0x54, 0xfa, 0x0a, 0x01, 0xa9, 0x07, 0x09, 0xa5, 0x0f, 0x95, 0xa2, 0xf1, 0xf0, 0x5d, 0xf0, 0x09, 0x5c, 0x2b, 0x02, 0x16, 0x56, 0x53, 0x56, 0x36, 0xb3, 0x8a, 0x4d, 0x4a, 0xda, 0x9b, 0xb4, 0x8c, 0xf7, 0x4a, 0xc6, 0x00, 0x1a, 0xc6, 0x10, 0x06, 0x36, 0x1d, 0x11, 0xba, 0x29, 0x11, 0xb9, 0x2b, 0x13, 0xa7, 0x0f, 0x76, 0x73, 0x76, 0x0e, 0x0b, 0x8e, 0x8a, 0x53, 0xd6, 0x87, 0xac, 0x9c, 0x4f, 0xb9, 0x4a, 0x1e, 0x16, 0xce, 0x18, 0x0e, 0xde, 0xa4, 0x82, 0x57, 0x21, 0xf1, 0x54, 0x25, 0xf5, 0x4a, 0xa5, 0x96, 0x9c, 0x5c, 0x56, 0x5c, 0xdc, 0xd6, 0xa9, 0xdb, 0x97, 0xbc, 0x82, 0x6f, 0x05, 0xc5, 0xca, 0x0f, 0xc2, 0x61, 0xa6, 0x9c, 0xbb, 0x76, 0xee, 0xda, 0xa5, 0xaf, 0x34, 0xf8, 0xe3, 0x69, 0x36, 0x40, 0x35, 0xa0, 0x36, 0x10, 0x34, 0x50, 0xf7, 0x76, 0x3b, 0xa0, 0x33, 0x10, 0x31, 0x00, 0x31, 0xc0, 0xf2, 0xd6, 0x30, 0xf0, 0x68, 0x00, 0x6e, 0x80, 0x6b, 0xc0, 0xec, 0x6d, 0x72, 0xa0, 0x67, 0xe0, 0x62, 0x60, 0x6a, 0xe0, 0xcd, 0x5b, 0xcc, 0x80, 0xd0, 0x80, 0xdd, 0xed, 0x00 };
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
    var text: [4096]u8 = undefined;
    for (&text, 0..) |*b, i| b.* = @truncate((i *% 2654435761) >> 13);
    const text_br = [_]u8{ 0x1f, 0xff, 0x0f, 0x00, 0x8c, 0xd4, 0x48, 0x4d, 0x73, 0xbb, 0x81, 0x71, 0x3a, 0x93, 0x67, 0x8a, 0x53, 0x8e, 0xaf, 0xae, 0xb3, 0x6f, 0x0f, 0xcc, 0x33, 0x94, 0xb8, 0x83, 0x60, 0x13, 0x61, 0x75, 0x91, 0x37, 0x7b, 0xb2, 0xe8, 0xc7, 0x3e, 0xf5, 0xc2, 0x1a, 0x71, 0x79, 0xa6, 0x83, 0x31, 0x4b, 0xb5, 0xfd, 0x6f, 0x2d, 0xe0, 0xa8, 0x64, 0xbe, 0xaf, 0x12, 0x44, 0xe3, 0xc8, 0x01, 0xf1, 0x6e, 0x8e, 0x02, 0x67, 0x65, 0xcb, 0x43, 0x8d, 0x28, 0x9e, 0x44, 0x0f, 0x49, 0x0f, 0x4b, 0x0c, 0x34, 0xaf, 0x58, 0x1f, 0xeb, 0x24, 0xc9, 0x34, 0x06, 0x22, 0x3f, 0xad, 0x71, 0xf0, 0xa2, 0x6a, 0x7b, 0x6a, 0x90, 0xa5, 0xb3, 0x38, 0x98, 0xf2, 0xb2, 0x25, 0x20, 0xcb, 0x9a, 0xfd, 0xb9, 0x49, 0x91, 0xcd, 0x13, 0x10, 0xda, 0xdb, 0x9e, 0x84, 0xae, 0x65, 0x8e, 0x97, 0x16, 0x4d, 0xbe, 0x48, 0x42, 0xe9, 0x75, 0x47, 0x0a, 0xb6, 0x91, 0x3b, 0x5f, 0xdb, 0x74, 0xc5, 0x32, 0x05, 0x63, 0x34, 0x9c, 0x69, 0xf8, 0x56, 0xe1, 0x7a, 0xeb, 0x30, 0x94, 0xab, 0x34, 0x9c, 0xd9, 0x74, 0x65, 0x10, 0x3b, 0xa5, 0xfb, 0xbd, 0xcb, 0x54, 0xad, 0x33, 0x08, 0x56, 0xcb, 0x9d, 0x45, 0x9e, 0xa8, 0x3c, 0x1f, 0x3d, 0x96, 0x66, 0x93, 0x45, 0xb2, 0x3b, 0x9e, 0x1c, 0xea, 0x54, 0xe3, 0xfd, 0xec, 0xb3, 0xb5, 0xdb, 0x1c, 0x8a, 0xd3, 0xf5, 0xe6, 0xd1, 0x47, 0xad, 0xef, 0x6b, 0xc0, 0xd1, 0x5d, 0xe6, 0xd1, 0xdc, 0xaf, 0xaf, 0x80, 0x39, 0xe9, 0xfc, 0xdf, 0x43, 0xae, 0xfe, 0xaa, 0x80, 0xe1, 0xfd, 0xfc, 0x45, 0xec, 0x85, 0x3e, 0xf0, 0x33, 0xe2, 0x19, 0xae, 0x8b, 0x58, 0xfe, 0x3f, 0xb0, 0x83, 0xbb, 0x18, 0x42, 0xbf, 0x63, 0xbe, 0xf1, 0xb6, 0x84, 0x13, 0x0c, 0x43, 0xbb, 0xf8, 0xab, 0x31, 0xfc, 0x37, 0x11, 0x98, 0xee, 0xca, 0x78, 0xe1, 0x28, 0xbc, 0x47, 0xb8, 0x99, 0x22, 0xff, 0x53, 0xa1, 0xf9, 0xbe, 0x42, 0x10, 0x8d, 0x23, 0xfb, 0xc4, 0xbb, 0x39, 0x0a, 0x98, 0x95, 0x2d, 0x0f, 0x55, 0xa2, 0x78, 0x12, 0x3d, 0x20, 0x3d, 0x2c, 0x31, 0xe0, 0xbc, 0x62, 0x7d, 0xac, 0xfd, 0x8d, 0x6a, 0x85, 0x8a, 0x66, 0x8d, 0x86, 0x9e, 0x6e, 0xa8, 0xb5, 0xa9, 0x69, 0x74, 0x68, 0x2a, 0x5a, 0x41, 0x37, 0x82, 0x42, 0x6e, 0x85, 0x2a, 0x61, 0x00, 0x90, 0x3a, 0x10, 0xb0, 0x46, 0x05, 0x8c, 0x8e, 0x61, 0x8b, 0x81, 0xe9, 0x38, 0x65, 0xfa, 0xd0, 0xd2, 0xf9, 0xd2, 0xd1, 0xfb, 0xa5, 0x7a, 0x77, 0xc2, 0x22, 0xee, 0x45, 0x44, 0x2b, 0x0f, 0x20, 0x9a, 0x20, 0xa0, 0x5a, 0xa0, 0x15, 0x18, 0x96, 0x13, 0x2c, 0x6c, 0x07, 0xec, 0x0a, 0x87, 0xc1, 0x80, 0x81, 0xd1, 0x90, 0x31, 0x35, 0x89, 0x8a, 0x79, 0x14, 0x13, 0xf7, 0x24, 0x9e, 0x26, 0xb4, 0xc1, 0xc0, 0x75, 0xc0, 0x21, 0x2a, 0x5d, 0x47, 0x1c, 0x5c, 0xe7, 0xb8, 0x78, 0x95, 0xb3, 0x11, 0x13, 0xb3, 0x31, 0x33, 0x4b, 0x65, 0xe2, 0x59, 0x42, 0xd2, 0x8b, 0xa4, 0x54, 0xfa, 0x0a, 0x01, 0xa9, 0x07, 0x09, 0xa5, 0x0f, 0x95, 0xa2, 0xf1, 0xf0, 0x5d, 0xf0, 0x09, 0x5c, 0x2b, 0x02, 0x16, 0x56, 0x53, 0x56, 0x36, 0xb3, 0x8a, 0x4d, 0x4a, 0xda, 0x9b, 0xb4, 0x8c, 0xf7, 0x4a, 0xc6, 0x00, 0x1a, 0xc6, 0x10, 0x06, 0x36, 0x1d, 0x11, 0xba, 0x29, 0x11, 0xb9, 0x2b, 0x13, 0xa7, 0x0f, 0x76, 0x73, 0x76, 0x0e, 0x0b, 0x8e, 0x8a, 0x53, 0xd6, 0x87, 0xac, 0x9c, 0x4f, 0xb9, 0x4a, 0x1e, 0x16, 0xce, 0x18, 0x0e, 0xde, 0xa4, 0x82, 0x57, 0x21, 0xf1, 0x54, 0x25, 0xf5, 0x4a, 0xa5, 0x96, 0x9c, 0x5c, 0x56, 0x5c, 0xdc, 0xd6, 0xa9, 0xdb, 0x97, 0xbc, 0x82, 0x6f, 0x05, 0xc5, 0xca, 0x0f, 0xc2, 0x61, 0xa6, 0x9c, 0xbb, 0x76, 0xee, 0xda, 0xa5, 0xaf, 0x34, 0xf8, 0xe3, 0x69, 0x36, 0x40, 0x35, 0xa0, 0x36, 0x10, 0x34, 0x50, 0xf7, 0x76, 0x3b, 0xa0, 0x33, 0x10, 0x31, 0x00, 0x31, 0xc0, 0xf2, 0xd6, 0x30, 0xf0, 0x68, 0x00, 0x6e, 0x80, 0x6b, 0xc0, 0xec, 0x6d, 0x72, 0xa0, 0x67, 0xe0, 0x62, 0x60, 0x6a, 0xe0, 0xcd, 0x5b, 0xcc, 0x80, 0xd0, 0x80, 0xdd, 0xed, 0x00 };
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
    // prefix_suffix_map[offset] indexes the NUL-terminated pool.
    const start: usize = dictionary.prefix_suffix_map[offset];
    var end = start;
    while (dictionary.prefix_suffix[end] != 0) end += 1;
    return dictionary.prefix_suffix[start..end];
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
    const t = transform_id * 3;
    const prefix = poolString(dictionary.transforms[t]);
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

fn encodeMetaBlock(bw: *BitWriter, src: []const u8, is_last: bool, ring: *[4]u32, workspace: []u8) EncodeError!void {
    const head = std.mem.bytesAsSlice(u32, @as([]align(4) u8, @alignCast(workspace[0 .. encode_head_words * 4])));
    const commands = std.mem.bytesAsSlice(Command, @as([]align(4) u8, @alignCast(workspace[encode_head_words * 4 ..][0 .. encode_command_cap * @sizeOf(Command)])));
    const cmd_count = parseCommands(src, commands, head, ring);

    var lit_lens: [256]u8 = undefined;
    var icode_lens: [704]u8 = undefined;
    var dcode_lens: [64]u8 = undefined;
    var lit_freq: [256]u32 = @splat(0);
    var icode_freq: [704]u32 = @splat(0);
    var dcode_freq: [64]u32 = @splat(0);
    for (commands[0..cmd_count]) |cmd| {
        icode_freq[cmd.icode] += 1;
        if (cmd.dcode != 0xFFFF) dcode_freq[cmd.dcode] += 1;
        const lits = src[cmd.lit_start..][0..cmd.ins_len];
        for (lits) |b| lit_freq[b] += 1;
    }
    huffman.limitedLengths(lit_freq[0..256], lit_lens[0..256], 15);
    huffman.limitedLengths(icode_freq[0..704], icode_lens[0..704], 15);
    huffman.limitedLengths(dcode_freq[0..64], dcode_lens[0..64], 15);
    var lit_codes: [256]u16 = undefined;
    var icode_codes: [704]u16 = undefined;
    var dcode_codes: [64]u16 = undefined;

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
    const dcode_single = try writePrefixCode(bw, dcode_lens[0..64], 64);
    // The writer fixes the final lengths first.
    // Canonical codes for the symbol bits come after it.
    canonicalCodes(lit_lens[0..256], lit_codes[0..256]);
    canonicalCodes(icode_lens[0..704], icode_codes[0..704]);
    canonicalCodes(dcode_lens[0..64], dcode_codes[0..64]);

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

fn encodeBits(input: []const u8, bw: *BitWriter, ws: []u8) EncodeError!void {
    try bw.writeBits(0b1011, 4); // WBITS 22
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
        try encodeMetaBlock(bw, input[offset..][0..chunk], is_last, &ring, ws);
        offset += chunk;
    }
}

fn encodeWorkspace(scratch: []u8) EncodeError![]u8 {
    return alignedSlice(scratch, encode_workspace_size);
}

pub fn encode(input: []const u8, output: []u8, scratch: []u8, options: Options) EncodeError!usize {
    _ = options;
    const ws = try encodeWorkspace(scratch);
    var bw = BitWriter{ .out = output };
    try encodeBits(input, &bw, ws);
    return bw.finish();
}

pub fn encodeCountedSize(input: []const u8, scratch: []u8, options: Options) EncodeError!usize {
    _ = options;
    const ws = try encodeWorkspace(scratch);
    var bw = BitWriter{ .out = &.{}, .count_only = true };
    try encodeBits(input, &bw, ws);
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
