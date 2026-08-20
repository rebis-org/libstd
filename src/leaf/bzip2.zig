const std = @import("std");

const checksum = @import("../common/primitive/checksum.zig");
const Bzip2Crc32 = checksum.Bzip2Crc32;
const failure_prim = @import("../common/primitive/failure.zig");
const Failure = failure_prim.Failure;
pub const DecodeError = Failure;
pub const EncodeError = Failure;
const io = @import("../common/primitive/io.zig");
const measurement = @import("../common/primitive/measurement.zig");

pub const block_size_min = 100_000;
pub const block_size_max = 900_000;

pub const Options = struct {
    block_size: u32 = 900_000,
    max_work: u64 = std.math.maxInt(u64),
};

pub fn decodeWorkspaceSize(max_block: u32) usize {
    var plan = io.WorkspacePlan.init(null);
    // RLE1 can expand a nominal block to at most 1.25x plus the run-count byte.
    plan.take(u8, max_block + max_block / 4 + 8) catch return 0;
    // The inverse-BWT traversal packs the successor position and byte into one
    // u32 so the pointer chase costs a single load per output byte.
    plan.take(u32, max_block) catch return 0;
    return plan.required();
}

pub fn decodeWorkspaceSizeFor(input: []const u8) Failure!usize {
    if (input.len < 4) return error.InvalidData;
    if (input[0] != 'B' or input[1] != 'Z' or input[2] != 'h') return error.InvalidData;
    const digit = input[3];
    if (digit < '1' or digit > '9') return error.InvalidData;
    const max_block = @as(u32, digit - '0') * 100_000;
    return decodeWorkspaceSize(max_block);
}

pub fn encodeWorkspaceSize(max_block: u32) usize {
    var plan = io.WorkspacePlan.init(null);
    // RLE expansion of length-4 runs needs a headroom over the decoded block size.
    plan.take(u8, max_block + max_block / 4 + 8) catch return 0;
    const doubled = @as(usize, max_block) * 2 + 1;
    plan.take(u16, doubled) catch return 0;
    plan.take(u32, doubled) catch return 0;
    plan.take(u8, 2 * doubled) catch return 0;
    plan.take(u32, doubled / 2 + 1) catch return 0;
    plan.take(u32, @max(doubled / 2 + 2, 258)) catch return 0;
    plan.take(u32, @max(doubled / 2 + 2, 258)) catch return 0;
    plan.take(u8, max_block) catch return 0;
    plan.take(u16, max_block + 1) catch return 0;
    return plan.required();
}

const block_magic = [_]u8{ 0x31, 0x41, 0x59, 0x26, 0x53, 0x59 };
const eos_magic = [_]u8{ 0x17, 0x72, 0x45, 0x38, 0x50, 0x90 };
const max_groups = 6;
const group_size = 50;
const max_alpha_size = 258;
const max_code_len = 20;
const max_selectors = 32768;
pub fn decodedSize(input: []const u8, scratch: []u8) Failure!usize {
    var counter = measurement.Counter.init(null);
    try decodeInner(input, &counter.writer, scratch);
    return @intCast(counter.written());
}

pub fn decode(input: []const u8, output: []u8, scratch: []u8) Failure!usize {
    var fixed_writer = std.Io.Writer.fixed(output);
    try decodeInner(input, &fixed_writer, scratch);
    return fixed_writer.end;
}

pub fn decodeToWriter(input: []const u8, writer: *std.Io.Writer, scratch: []u8) Failure!void {
    try decodeInner(input, writer, scratch);
}

pub fn requiredSize(input: []const u8, scratch: []u8, options: Options) Failure!usize {
    var counter = measurement.Counter.init(null);
    try encodeInner(input, &counter.writer, scratch, options);
    return @intCast(counter.written());
}

pub fn encode(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    var fixed_writer = std.Io.Writer.fixed(output);
    try encodeInner(input, &fixed_writer, scratch, options);
    return fixed_writer.end;
}

// No stored fallback exists, so the bound is structural on the symbol
// alphabet: RLE1 expands at most 5/4 (a 4-run gains one count symbol), every
// post-RLE1 symbol costs at most max_code_len bits, and per-block structures
// (selectors at 6 bits per 50-symbol group worst case, six table
// descriptions, CRCs) stay under 8 KiB per 100k-symbol minimum block.
// 13/4 covers the symbol bits plus the per-block trickle; the constant
// absorbs one block's tables for tiny inputs. Loose by design.
pub fn encodedSizeBound(input_len: usize) usize {
    return (input_len *| 13) / 4 +| 16384;
}

fn decodeInner(input: []const u8, writer: *std.Io.Writer, scratch: []u8) Failure!void {
    if (input.len < 4) return error.InvalidData;
    if (input[0] != 'B' or input[1] != 'Z' or input[2] != 'h') return error.InvalidData;
    const block_digit = input[3];
    if (block_digit < '1' or block_digit > '9') return error.InvalidData;
    const max_block = @as(u32, block_digit - '0') * 100_000;
    var br = BitReader.init(input[4..]);
    var combined_crc: u32 = 0;
    while (true) {
        const marker = try br.readBits(48);
        if (marker == 0x177245385090) {
            const stored_combined = try br.readU32be();
            if (combined_crc != stored_combined) return error.IntegrityFailure;
            break;
        }
        if (marker != 0x314159265359) return error.InvalidData;
        const stored_crc = try br.readU32be();
        const randomised = try br.readBit();
        if (randomised != 0) return error.Unsupported;
        const orig_ptr_u = try br.readBits(24);
        const orig_ptr = std.math.cast(u32, orig_ptr_u) orelse return error.InvalidData;
        const in_use16: u16 = @intCast(try br.readBits(16));
        var seq_to_unseq: [256]u8 = undefined;
        var n_in_use: u32 = 0;
        var group: u32 = 0;
        while (group < 16) : (group += 1) {
            if ((in_use16 >> @intCast(15 - group)) & 1 == 0) continue;
            const bits: u16 = @intCast(try br.readBits(16));
            var bit: u32 = 0;
            while (bit < 16) : (bit += 1) {
                if ((bits >> @intCast(15 - bit)) & 1 != 0) {
                    const value: u8 = @intCast(group * 16 + bit);
                    seq_to_unseq[n_in_use] = value;
                    n_in_use += 1;
                }
            }
        }
        if (n_in_use == 0) return error.InvalidData;
        const alpha_size = n_in_use + 2;
        const eob = alpha_size - 1;
        const n_groups_u = try br.readBits(3);
        const n_groups = std.math.cast(u32, n_groups_u) orelse return error.InvalidData;
        if (n_groups < 2 or n_groups > max_groups) return error.InvalidData;
        const n_selectors_u = try br.readBits(15);
        const n_selectors = std.math.cast(u32, n_selectors_u) orelse return error.InvalidData;
        if (n_selectors == 0) return error.InvalidData;
        var selectors: [max_selectors]u8 = undefined;
        {
            var pos: [max_groups]u8 = undefined;
            var i: u32 = 0;
            while (i < n_groups) : (i += 1) pos[i] = @intCast(i);
            i = 0;
            while (i < n_selectors) : (i += 1) {
                var v: u32 = 0;
                while (true) {
                    const bit = try br.readBit();
                    if (bit == 0) break;
                    v += 1;
                    if (v >= n_groups) return error.InvalidData;
                }
                const selected = pos[v];
                var j = v;
                while (j > 0) : (j -= 1) pos[j] = pos[j - 1];
                pos[0] = selected;
                if (i < max_selectors) selectors[i] = selected;
            }
        }
        if (n_selectors > max_selectors) return error.InvalidData;
        var lens: [max_groups][max_alpha_size]u8 = undefined;
        var tables: [max_groups]HuffTable = undefined;
        {
            var t: u32 = 0;
            while (t < n_groups) : (t += 1) {
                const curr_u = try br.readBits(5);
                var curr = std.math.cast(u32, curr_u) orelse return error.InvalidData;
                if (curr < 1 or curr > max_code_len) return error.InvalidData;
                var sym: u32 = 0;
                while (sym < alpha_size) : (sym += 1) {
                    while (true) {
                        const bit = try br.readBit();
                        if (bit == 0) break;
                        const sign = try br.readBit();
                        if (sign == 0) {
                            curr += 1;
                        } else {
                            curr -%= 1;
                        }
                        if (curr < 1 or curr > max_code_len) return error.InvalidData;
                    }
                    lens[t][sym] = @intCast(curr);
                }
                tables[t] = try buildHuffTable(&lens[t], alpha_size);
            }
        }
        var ws = try io.Workspace.init(scratch.ptr, scratch.len);
        const bwt_buffer = try ws.take(u8, max_block + max_block / 4 + 8);
        var nblock: u32 = 0;
        var mtf: [256]u8 = undefined;
        {
            var i: u32 = 0;
            while (i < n_in_use) : (i += 1) mtf[i] = @intCast(i);
        }
        var group_no: i32 = -1;
        var group_pos: u32 = 0;
        var run_accum: i64 = -1;
        var run_weight: i64 = 1;
        while (true) {
            if (group_pos == 0) {
                group_no += 1;
                if (group_no >= n_selectors) return error.InvalidData;
                group_pos = group_size;
            }
            group_pos -= 1;
            const sel = selectors[@intCast(group_no)];
            const table = &tables[sel];
            const sym = try decodeHuffman(&br, table);
            if (sym == 0 or sym == 1) {
                if (run_weight >= 2 * 1024 * 1024) return error.InvalidData;
                run_accum += (sym + 1) * run_weight;
                run_weight *= 2;
                continue;
            }
            if (run_accum != -1) {
                const copies = std.math.cast(u32, run_accum + 1) orelse return error.InvalidData;
                const byte = seq_to_unseq[mtf[0]];
                var k: u32 = 0;
                while (k < copies) : (k += 1) {
                    if (nblock >= bwt_buffer.len) return error.InvalidData;
                    bwt_buffer[nblock] = byte;
                    nblock += 1;
                }
                run_accum = -1;
                run_weight = 1;
            }
            if (sym == eob) break;
            const idx = sym - 1;
            const uc = mtfMove(&mtf, idx);
            if (nblock >= bwt_buffer.len) return error.InvalidData;
            bwt_buffer[nblock] = seq_to_unseq[uc];
            nblock += 1;
        }
        if (nblock == 0 or orig_ptr >= nblock) return error.InvalidData;
        var cftab: [256]u32 = undefined;
        @memset(&cftab, 0);
        var i: u32 = 0;
        while (i < nblock) : (i += 1) {
            cftab[bwt_buffer[i]] += 1;
        }
        var sum: u32 = 0;
        i = 0;
        while (i < 256) : (i += 1) {
            const count = cftab[i];
            cftab[i] = sum;
            sum += count;
        }
        const fwd = try ws.take(u32, nblock);
        {
            var occ: [256]u32 = @splat(0);
            i = 0;
            while (i < nblock) : (i += 1) {
                const b = bwt_buffer[i];
                fwd[cftab[b] + occ[b]] = (i << 8) | b;
                occ[b] += 1;
            }
        }
        // The packed forward successor yields one load per output byte, and
        // the RLE expansion rides the traversal instead of re-reading a
        // reconstructed buffer.
        var block_crc = Bzip2Crc32.init();
        var out_buf: [4096]u8 = undefined;
        var out_len: usize = 0;
        var cur: u32 = orig_ptr;
        var last: u8 = 0;
        var run: u32 = 0;
        var emitted: u32 = 0;
        while (emitted < nblock) {
            const entry = fwd[cur];
            const b: u8 = @truncate(entry);
            cur = entry >> 8;
            emitted += 1;
            var copies: u32 = 1;
            var out_byte = b;
            if (run == 4) {
                copies = b;
                out_byte = last;
                run = 0;
            } else {
                if (b == last) {
                    run += 1;
                } else {
                    last = b;
                    run = 1;
                }
            }
            if (copies == 1) {
                out_buf[out_len] = out_byte;
                out_len += 1;
                if (out_len == out_buf.len) {
                    try io.writeBytes(writer, &out_buf);
                    block_crc.update(&out_buf);
                    out_len = 0;
                }
                continue;
            }
            var remaining = copies;
            while (remaining > 0) {
                const take = @min(remaining, out_buf.len - out_len);
                @memset(out_buf[out_len..][0..take], out_byte);
                out_len += take;
                remaining -= take;
                if (out_len == out_buf.len) {
                    try io.writeBytes(writer, &out_buf);
                    block_crc.update(&out_buf);
                    out_len = 0;
                }
            }
        }
        if (out_len > 0) {
            try io.writeBytes(writer, out_buf[0..out_len]);
            block_crc.update(out_buf[0..out_len]);
        }
        if (block_crc.final() != stored_crc) {
            return error.IntegrityFailure;
        }
        combined_crc = (combined_crc << 1) | (combined_crc >> 31);
        combined_crc ^= stored_crc;
    }
}

fn encodeInner(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    if (options.block_size < block_size_min or options.block_size > block_size_max) return error.InvalidCall;
    const max_block = options.block_size;
    var bw = BitWriter.init(writer);
    try bw.writeByte('B');
    try bw.writeByte('Z');
    try bw.writeByte('h');
    const digit: u8 = @intCast(@max(1, @min(9, (max_block + 99_999) / 100_000)));
    try bw.writeByte('0' + digit);
    var combined_crc: u32 = 0;
    var offset: usize = 0;
    while (offset < input.len) {
        var ws = try io.Workspace.init(scratch.ptr, scratch.len);
        const rle_buffer = try ws.take(u8, max_block + max_block / 4 + 8);
        const chunk_input = input[offset..];
        var rle_len: usize = 0;
        var consumed: usize = 0;
        var full = false;
        var scan: usize = 0;
        while (scan < chunk_input.len) {
            const run_start = scan;
            const run_byte = chunk_input[run_start];
            const limit = @min(chunk_input.len, run_start + 259);
            var j = run_start + 1;
            while (j + 8 <= limit) {
                const match = std.mem.readInt(u64, chunk_input[j..][0..8], .little) ^ (@as(u64, run_byte) *% 0x0101010101010101);
                if (match != 0) {
                    j += @ctz(match) / 8;
                    break;
                }
                j += 8;
            }
            while (j < limit and chunk_input[j] == run_byte) j += 1;
            try appendRun(rle_buffer, &rle_len, run_byte, j - run_start);
            scan = j;
            consumed = scan;
            if (rle_len >= max_block - 19) {
                full = true;
                // Match the historic block split exactly: a flush crossing the
                // threshold also absorbed the first byte of the next run,
                // unless the run closed at the 259 cap or at the input end.
                if (j - run_start < 259 and j < chunk_input.len) {
                    try appendRun(rle_buffer, &rle_len, chunk_input[j], 1);
                    scan += 1;
                    consumed = scan;
                }
                break;
            }
        }
        // The block CRC covers the raw input, so one pass over the consumed
        // range replaces a per-byte update inside the RLE scan.
        var block_crc = Bzip2Crc32.init();
        block_crc.update(chunk_input[0..consumed]);
        if (rle_len == 0) break;
        offset += consumed;
        try encodeBlock(rle_buffer[0..rle_len], block_crc.final(), &bw, &ws, options);
        combined_crc = (combined_crc << 1) | (combined_crc >> 31);
        combined_crc ^= block_crc.final();
        if (!full and offset < input.len) return error.InternalFailure;
    }
    // End-of-stream marker continues the last block's bit stream.
    for (eos_magic) |b| try bw.writeByte(b);
    try bw.writeU32be(combined_crc);
    try bw.flush();
}

fn appendRun(buffer: []u8, len: *usize, byte: u8, count: usize) Failure!void {
    if (count == 0) return;
    if (count < 4) {
        var i: usize = 0;
        while (i < count) : (i += 1) {
            if (len.* >= buffer.len) return error.ResourceLimit;
            buffer[len.*] = byte;
            len.* += 1;
        }
        return;
    }
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        if (len.* >= buffer.len) return error.ResourceLimit;
        buffer[len.*] = byte;
        len.* += 1;
    }
    if (len.* >= buffer.len) return error.ResourceLimit;
    buffer[len.*] = @intCast(count - 4);
    len.* += 1;
}

const sais_empty = std.math.maxInt(u32);
const sais_type_s: u8 = 1;

// SA-IS suffix sort (Nong, Zhang, Chan 2009). text must end with the unique
// smallest symbol. The workspace arrays are shared across recursion levels:
// types uses disjoint per-level regions (each level at most halves), while
// pname/hist/bptr are dead in the parent while a child runs.
fn saisIsLms(types: []const u8, i: usize) bool {
    return i > 0 and types[i] == sais_type_s and types[i - 1] != sais_type_s;
}

fn saisLmsEqual(comptime T: type, text: []const T, types: []const u8, a: usize, b: usize) bool {
    var o: usize = 0;
    while (true) : (o += 1) {
        const a_lms = o > 0 and saisIsLms(types, a + o);
        const b_lms = o > 0 and saisIsLms(types, b + o);
        if (text[a + o] != text[b + o] or types[a + o] != types[b + o]) return false;
        if (a_lms or b_lms) return a_lms and b_lms;
    }
}

fn saisInduce(comptime T: type, text: []const T, sa: []u32, alphabet: u32, types: []const u8, hist: []const u32, bptr: []u32) void {
    const m = text.len;
    {
        var sum: u32 = 0;
        var c: usize = 0;
        while (c < alphabet) : (c += 1) {
            bptr[c] = sum;
            sum += hist[c];
        }
    }
    var i: usize = 0;
    while (i < m) : (i += 1) {
        const j = sa[i];
        if (j == sais_empty or j == 0) continue;
        const p = j - 1;
        if (types[p] != sais_type_s) {
            const ch = text[p];
            sa[bptr[ch]] = p;
            bptr[ch] += 1;
        }
    }
    {
        var sum: u32 = 0;
        var c: usize = 0;
        while (c < alphabet) : (c += 1) {
            sum += hist[c];
            bptr[c] = sum;
        }
    }
    i = m;
    while (i > 0) {
        i -= 1;
        const j = sa[i];
        if (j == sais_empty or j == 0) continue;
        const p = j - 1;
        if (types[p] == sais_type_s) {
            const ch = text[p];
            bptr[ch] -= 1;
            sa[bptr[ch]] = p;
        }
    }
}

fn sais(comptime T: type, text: []const T, sa: []u32, alphabet: u32, types: []u8, pname: []u32, hist: []u32, bptr: []u32) void {
    const m = text.len;
    if (m == 1) {
        sa[0] = 0;
        return;
    }
    // Classify S/L from the end while histogramming symbols.
    @memset(hist[0..alphabet], 0);
    {
        types[m - 1] = sais_type_s;
        var i = m - 1;
        while (i > 0) {
            i -= 1;
            types[i] = if (text[i] < text[i + 1] or (text[i] == text[i + 1] and types[i + 1] == sais_type_s)) sais_type_s else 0;
            hist[text[i]] += 1;
        }
        hist[text[m - 1]] += 1;
    }
    {
        var sum: u32 = 0;
        var c: usize = 0;
        while (c < alphabet) : (c += 1) {
            sum += hist[c];
            bptr[c] = sum;
        }
    }
    @memset(sa, sais_empty);
    var n1: usize = 0;
    var i: usize = 1;
    while (i < m) : (i += 1) {
        if (saisIsLms(types, i)) {
            const ch = text[i];
            bptr[ch] -= 1;
            sa[bptr[ch]] = @intCast(i);
            n1 += 1;
        }
    }
    saisInduce(T, text, sa, alphabet, types, hist, bptr);
    // Name the LMS substrings in sorted order. pname[p / 2] cannot collide:
    // two LMS positions are never adjacent.
    var name: u32 = 0;
    var prev: u32 = sais_empty;
    for (sa) |p| {
        if (!saisIsLms(types, p)) continue;
        if (prev != sais_empty and !saisLmsEqual(T, text, types, prev, p)) name += 1;
        prev = p;
        pname[p / 2] = name;
    }
    const num_names = name + 1;
    {
        var k: usize = 0;
        i = 1;
        while (i < m) : (i += 1) {
            if (saisIsLms(types, i)) {
                sa[m - n1 + k] = pname[i / 2];
                k += 1;
            }
        }
    }
    if (num_names == n1) {
        var k: usize = 0;
        while (k < n1) : (k += 1) {
            sa[sa[m - n1 + k]] = @intCast(k);
        }
    } else {
        sais(u32, sa[m - n1 .. m], sa[0..n1], num_names, types[m..], pname, hist, bptr);
    }
    // Rebuild hist (the recursion clobbers it) and relist LMS in text order.
    @memset(hist[0..alphabet], 0);
    for (text) |c| hist[c] += 1;
    {
        var k: usize = 0;
        i = 1;
        while (i < m) : (i += 1) {
            if (saisIsLms(types, i)) {
                pname[k] = @intCast(i);
                k += 1;
            }
        }
    }
    // sa1 (sorted LMS order as text-order indices) sits in sa[0..n1]. Read it
    // in reverse with clear-on-read: placements into bucket ends then only
    // land in slots already consumed, so no stale sa1 entry can survive.
    @memset(sa[n1..m], sais_empty);
    {
        var sum: u32 = 0;
        var c: usize = 0;
        while (c < alphabet) : (c += 1) {
            sum += hist[c];
            bptr[c] = sum;
        }
        var k = n1;
        while (k > 0) {
            k -= 1;
            const p = pname[sa[k]];
            sa[k] = sais_empty;
            const ch = text[p];
            bptr[ch] -= 1;
            sa[bptr[ch]] = p;
        }
    }
    saisInduce(T, text, sa, alphabet, types, hist, bptr);
}

fn encodeBlock(block: []const u8, block_crc: u32, bw: *BitWriter, ws: *io.Workspace, options: Options) Failure!void {
    const nblock = block.len;
    if (nblock == 0) return;
    // Enforce the caller-selected codec work budget against the BWT sort. The
    // constant bounds the linear-time SA-IS passes with room to spare.
    const log_n = std.math.log2_int_ceil(u32, @as(u32, @intCast(@max(2, nblock))));
    const estimate = @as(u64, nblock) * @as(u64, log_n) * 4;
    if (estimate > options.max_work) return error.ResourceLimit;
    var in_use = [_]bool{false} ** 256;
    for (block) |b| in_use[b] = true;
    var unseq_to_seq: [256]u8 = undefined;
    var n_in_use: u32 = 0;
    var value: u32 = 0;
    while (value < 256) : (value += 1) {
        if (in_use[value]) {
            unseq_to_seq[value] = @intCast(n_in_use);
            n_in_use += 1;
        }
    }
    if (n_in_use == 0) return error.InternalFailure;
    const alpha_size = n_in_use + 2;
    const eob = alpha_size - 1;
    // BWT via SA-IS on the doubled block: suffixes of (block+1)(block+1) plus
    // a zero sentinel that start below nblock are exactly the block rotations
    // in sorted order. Equal rotations share their preceding byte, so the
    // resulting L is independent of the tie order the suffix sort picks.
    const doubled: usize = 2 * nblock + 1;
    const t16 = try ws.take(u16, doubled);
    const sa = try ws.take(u32, doubled);
    const types = try ws.take(u8, 2 * doubled);
    const pname = try ws.take(u32, doubled / 2 + 1);
    const bucket_len = @max(doubled / 2 + 2, 258);
    const hist = try ws.take(u32, bucket_len);
    const bptr = try ws.take(u32, bucket_len);
    for (block, 0..) |b, i| {
        const v: u16 = @as(u16, b) + 1;
        t16[i] = v;
        t16[i + nblock] = v;
    }
    t16[2 * nblock] = 0;
    sais(u16, t16, sa, 257, types, pname, hist, bptr);
    var orig_ptr: u32 = 0;
    var found_orig = false;
    const l = try ws.take(u8, nblock);
    var out_rank: usize = 0;
    for (sa) |pos| {
        if (pos >= nblock) continue;
        if (pos == 0) {
            orig_ptr = @intCast(out_rank);
            found_orig = true;
        }
        const prev = if (pos == 0) nblock - 1 else pos - 1;
        l[out_rank] = block[prev];
        out_rank += 1;
    }
    if (!found_orig or out_rank != nblock) return error.InternalFailure;
    const mtfv = try ws.take(u16, ws.remaining() / @sizeOf(u16));
    var mtf: [256]u8 = undefined;
    {
        var i: u32 = 0;
        while (i < n_in_use) : (i += 1) mtf[i] = @intCast(i);
    }
    var wr: usize = 0;
    var z_pend: u32 = 0;
    for (l) |b| {
        const seq = unseq_to_seq[b];
        if (mtf[0] == seq) {
            z_pend += 1;
        } else {
            if (z_pend > 0) {
                try emitRun(&wr, mtfv, &z_pend);
            }
            const idx = mtfFindAndMove(&mtf, n_in_use, seq);
            mtfv[wr] = idx + 1;
            wr += 1;
        }
    }
    if (z_pend > 0) {
        try emitRun(&wr, mtfv, &z_pend);
    }
    mtfv[wr] = @intCast(eob);
    wr += 1;
    const n_mtf = wr;
    const n_selectors: u32 = @intCast((n_mtf + group_size - 1) / group_size);
    var group_lens: [max_groups][max_alpha_size]u8 = undefined;
    var group_codes: [max_groups][max_alpha_size]u32 = undefined;
    var selectors: [max_selectors]u8 = undefined;
    var n_groups: u32 = undefined;
    buildHuffmanGroups(mtfv[0..n_mtf], n_mtf, alpha_size, &group_lens, &group_codes, &selectors, &n_groups);
    for (block_magic) |b| try bw.writeByte(b);
    try bw.writeU32be(block_crc);
    try bw.writeBit(0); // randomised
    try bw.writeBits(24, orig_ptr);
    {
        var map16: u16 = 0;
        var g: u32 = 0;
        while (g < 16) : (g += 1) {
            var used = false;
            var b: u32 = 0;
            while (b < 16) : (b += 1) {
                if (in_use[g * 16 + b]) used = true;
            }
            if (used) map16 |= @as(u16, 1) << @intCast(15 - g);
        }
        try bw.writeBits(16, map16);
        g = 0;
        while (g < 16) : (g += 1) {
            var used = false;
            var b: u32 = 0;
            while (b < 16) : (b += 1) {
                if (in_use[g * 16 + b]) used = true;
            }
            if (!used) continue;
            var bits: u16 = 0;
            b = 0;
            while (b < 16) : (b += 1) {
                if (in_use[g * 16 + b]) bits |= @as(u16, 1) << @intCast(15 - b);
            }
            try bw.writeBits(16, bits);
        }
    }
    try bw.writeBits(3, n_groups);
    try bw.writeBits(15, n_selectors);
    // Selector indices are unary-coded after move-to-front over the group list.
    {
        var sel_pos: [max_groups]u8 = undefined;
        for (0..n_groups) |i| sel_pos[i] = @intCast(i);
        for (0..n_selectors) |s| {
            const sel = selectors[s];
            var idx: usize = 0;
            while (sel_pos[idx] != sel) idx += 1;
            for (0..idx) |_| try bw.writeBit(1);
            try bw.writeBit(0);
            const moved = sel_pos[idx];
            var j = idx;
            while (j > 0) : (j -= 1) sel_pos[j] = sel_pos[j - 1];
            sel_pos[0] = moved;
        }
    }
    {
        var t: u32 = 0;
        while (t < n_groups) : (t += 1) {
            try writeHuffmanTable(bw, group_lens[t][0..alpha_size], alpha_size);
        }
    }
    {
        var i: usize = 0;
        while (i < n_mtf) : (i += 1) {
            const sym = mtfv[i];
            const group = selectors[i / group_size];
            try bw.writeBits(@intCast(group_lens[group][sym]), group_codes[group][sym]);
        }
    }
}

fn buildHuffmanGroups(mtfv: []const u16, n_mtf: usize, alpha_size: u32, group_lens: *[max_groups][max_alpha_size]u8, group_codes: *[max_groups][max_alpha_size]u32, selectors: *[max_selectors]u8, n_groups_out: *u32) void {
    const n_selectors: usize = (n_mtf + group_size - 1) / group_size;
    const n_groups: u32 = if (n_mtf < 200) 2 else if (n_mtf < 600) 3 else if (n_mtf < 1200) 4 else if (n_mtf < 2400) 5 else 6;
    n_groups_out.* = n_groups;
    var group_freq: [max_groups][max_alpha_size]u32 = undefined;
    for (0..n_groups) |g| {
        for (0..alpha_size) |s| group_freq[g][s] = 1;
    }
    for (0..n_selectors) |s| {
        const group = @as(usize, s % n_groups);
        const chunk = mtfv[s * group_size .. @min((s + 1) * group_size, n_mtf)];
        for (chunk) |sym| group_freq[group][sym] += 1;
    }
    for (0..4) |_| {
        for (0..n_groups) |g| {
            buildLengthLimitedCode(group_freq[g][0..alpha_size], alpha_size, group_lens[g][0..alpha_size], group_codes[g][0..alpha_size]);
        }
        for (0..n_groups) |g| {
            for (0..alpha_size) |s| group_freq[g][s] = 1;
        }
        for (0..n_selectors) |s| {
            const chunk = mtfv[s * group_size .. @min((s + 1) * group_size, n_mtf)];
            // One pass over the chunk with independent accumulators; six
            // separate passes would serialize on the single cost register.
            var costs: [max_groups]u32 = @splat(0);
            for (chunk) |sym| {
                var g: usize = 0;
                while (g < n_groups) : (g += 1) costs[g] += group_lens[g][sym];
            }
            var best_group: usize = 0;
            var best_cost: u32 = std.math.maxInt(u32);
            for (0..n_groups) |g| {
                if (costs[g] < best_cost) {
                    best_cost = costs[g];
                    best_group = g;
                }
            }
            selectors[s] = @intCast(best_group);
            for (chunk) |sym| group_freq[best_group][sym] += 1;
        }
    }
    for (0..n_groups) |g| {
        buildLengthLimitedCode(group_freq[g][0..alpha_size], alpha_size, group_lens[g][0..alpha_size], group_codes[g][0..alpha_size]);
    }
}

fn emitRun(wr: *usize, mtfv: []u16, z_pend: *u32) Failure!void {
    z_pend.* -%= 1;
    while (true) {
        if (mtfv.len - wr.* < 1) return error.ResourceLimit;
        if (z_pend.* & 1 != 0) {
            mtfv[wr.*] = 1; // RUNB
        } else {
            mtfv[wr.*] = 0; // RUNA
        }
        wr.* += 1;
        if (z_pend.* < 2) break;
        z_pend.* = (z_pend.* - 2) / 2;
    }
    z_pend.* = 0;
}

fn buildLengthLimitedCode(freq: []const u32, alpha_size: u32, lens: []u8, codes: []u32) void {
    var weight: [max_alpha_size * 2]u32 = undefined;
    var parent: [max_alpha_size * 2]i32 = undefined;
    var heap: [max_alpha_size + 2]u32 = undefined;
    var n_nodes: u32 = 0;
    while (true) {
        weight[0] = 0;
        parent[0] = -2;
        heap[0] = 0;
        for (freq[0..alpha_size], 0..) |f, i| {
            weight[i + 1] = (if (f == 0) 1 else f) << 8;
        }
        var n_heap: u32 = 0;
        for (1..alpha_size + 1) |i| {
            parent[i] = -1;
            n_heap += 1;
            heap[n_heap] = @intCast(i);
            upHeap(&heap, &weight, n_heap);
        }
        n_nodes = alpha_size;
        while (n_heap > 1) {
            const n1 = heap[1];
            heap[1] = heap[n_heap];
            n_heap -= 1;
            downHeap(&heap, &weight, n_heap, 1);
            const n2 = heap[1];
            heap[1] = heap[n_heap];
            n_heap -= 1;
            downHeap(&heap, &weight, n_heap, 1);
            n_nodes += 1;
            parent[n1] = @intCast(n_nodes);
            parent[n2] = @intCast(n_nodes);
            weight[n_nodes] = addWeights(weight[n1], weight[n2]);
            parent[n_nodes] = -1;
            n_heap += 1;
            heap[n_heap] = n_nodes;
            upHeap(&heap, &weight, n_heap);
        }
        var too_long = false;
        for (0..alpha_size) |i| {
            var depth: u32 = 0;
            var node: u32 = @intCast(i + 1);
            while (parent[node] >= 0) {
                node = @intCast(parent[node]);
                depth += 1;
            }
            lens[i] = @intCast(depth);
            if (depth > max_code_len) too_long = true;
        }
        if (!too_long) break;
        for (1..alpha_size + 1) |i| {
            weight[i] = ((1 + (weight[i] >> 8) / 2) << 8) | (weight[i] & 0xff);
        }
    }
    var min_len: u32 = max_code_len;
    for (lens[0..alpha_size]) |l| {
        if (l < min_len) min_len = l;
    }
    const max_len = max_code_len;
    var vec: u32 = 0;
    var len = min_len;
    while (len <= max_len) : (len += 1) {
        for (0..alpha_size) |i| {
            if (lens[i] == len) {
                codes[i] = vec;
                vec += 1;
            }
        }
        vec <<= 1;
    }
}

fn addWeights(a: u32, b: u32) u32 {
    const fa = a & 0xffffff00;
    const fb = b & 0xffffff00;
    const da = a & 0xff;
    const db = b & 0xff;
    return (fa + fb) | (1 + @max(da, db));
}

fn upHeap(heap: *[max_alpha_size + 2]u32, weight: *const [max_alpha_size * 2]u32, z: u32) void {
    var zz = z;
    const tmp = heap[zz];
    while (weight[tmp] < weight[heap[zz >> 1]]) {
        heap[zz] = heap[zz >> 1];
        zz >>= 1;
    }
    heap[zz] = tmp;
}

fn downHeap(heap: *[max_alpha_size + 2]u32, weight: *const [max_alpha_size * 2]u32, n_heap: u32, start: u32) void {
    var zz = start;
    const tmp = heap[zz];
    while (true) {
        var yy = zz << 1;
        if (yy > n_heap) break;
        if (yy < n_heap and weight[heap[yy + 1]] < weight[heap[yy]]) yy += 1;
        if (weight[tmp] < weight[heap[yy]]) break;
        heap[zz] = heap[yy];
        zz = yy;
    }
    heap[zz] = tmp;
}

fn writeHuffmanTable(bw: *BitWriter, lens: []const u8, alpha_size: u32) Failure!void {
    var curr: i32 = lens[0];
    try bw.writeBits(5, @intCast(curr));
    var sym: u32 = 0;
    while (sym < alpha_size) : (sym += 1) {
        const target: i32 = lens[sym];
        while (curr < target) {
            try bw.writeBits(2, 2); // 10 -> increment
            curr += 1;
        }
        while (curr > target) {
            try bw.writeBits(2, 3); // 11 -> decrement
            curr -= 1;
        }
        try bw.writeBit(0); // end of delta for this symbol
    }
}

fn mtfFindAndMove(mtf: *[256]u8, n_in_use: u32, seq: u8) u16 {
    var idx: u16 = 0;
    // Vector scan: one 32-byte compare per step instead of per-byte tests.
    while (idx + 32 <= n_in_use) {
        const chunk: @Vector(32, u8) = mtf[idx..][0..32].*;
        const hits: u32 = @bitCast(chunk == @as(@Vector(32, u8), @splat(seq)));
        if (hits != 0) {
            idx += @ctz(hits);
            break;
        }
        idx += 32;
    }
    if (idx + 32 > n_in_use) {
        while (mtf[idx] != seq) idx += 1;
    }
    const uc = mtf[idx];
    var i = idx;
    // Backward 8-byte overlapping stores move the prefix without a byte loop.
    while (i >= 8) {
        const w = std.mem.readInt(u64, mtf[i - 8 ..][0..8], .little);
        std.mem.writeInt(u64, mtf[i - 7 ..][0..8], w, .little);
        i -= 8;
    }
    while (i > 0) : (i -= 1) {
        mtf[i] = mtf[i - 1];
    }
    mtf[0] = uc;
    return idx;
}

fn mtfMove(mtf: *[256]u8, index: u32) u8 {
    const uc = mtf[index];
    var i = index;
    while (i >= 8) {
        const w = std.mem.readInt(u64, mtf[i - 8 ..][0..8], .little);
        std.mem.writeInt(u64, mtf[i - 7 ..][0..8], w, .little);
        i -= 8;
    }
    while (i > 0) : (i -= 1) {
        mtf[i] = mtf[i - 1];
    }
    mtf[0] = uc;
    return uc;
}

const BitReader = struct {
    bytes: []const u8,
    byte_pos: usize,
    bits: u64,
    bit_count: u8,

    fn init(bytes: []const u8) BitReader {
        return .{ .bytes = bytes, .byte_pos = 0, .bits = 0, .bit_count = 0 };
    }

    fn refill(self: *BitReader) error{ InvalidData, ResourceLimit }!void {
        if (self.byte_pos >= self.bytes.len) return error.InvalidData;
        self.bits = (self.bits << 8) | self.bytes[self.byte_pos];
        self.byte_pos += 1;
        self.bit_count += 8;
    }

    fn readBit(self: *BitReader) error{ InvalidData, ResourceLimit }!u32 {
        if (self.bit_count == 0) try self.refill();
        self.bit_count -= 1;
        const remaining: u6 = @intCast(self.bit_count);
        const bit: u32 = @intCast((self.bits >> remaining) & 1);
        self.bits &= (@as(u64, 1) << remaining) - 1;
        return bit;
    }

    fn readBits(self: *BitReader, n: u6) error{ InvalidData, ResourceLimit }!u64 {
        while (self.bit_count < n) try self.refill();
        const shift: u6 = @intCast(self.bit_count - n);
        const value = (self.bits >> shift) & ((@as(u64, 1) << n) - 1);
        self.bits &= (@as(u64, 1) << shift) - 1;
        self.bit_count = shift;
        return value;
    }

    fn readU32be(self: *BitReader) error{ InvalidData, ResourceLimit }!u32 {
        return @intCast(try self.readBits(32));
    }
};

const BitWriter = struct {
    writer: *std.Io.Writer,
    buffer: u32,
    bits: u5,
    // Bytes are batched locally so the writer vtable is hit once per buffer
    // instead of once per byte.
    pending: [512]u8 = undefined,
    pending_len: usize = 0,

    fn init(writer: *std.Io.Writer) BitWriter {
        return .{ .writer = writer, .buffer = 0, .bits = 0 };
    }

    fn emit(self: *BitWriter, byte: u8) Failure!void {
        self.pending[self.pending_len] = byte;
        self.pending_len += 1;
        if (self.pending_len == self.pending.len) {
            try io.writeBytes(self.writer, &self.pending);
            self.pending_len = 0;
        }
    }

    fn writeByte(self: *BitWriter, byte: u8) Failure!void {
        try self.writeBits(8, byte);
    }

    fn writeU32be(self: *BitWriter, value: u32) Failure!void {
        try self.writeBits(8, value >> 24);
        try self.writeBits(8, value >> 16);
        try self.writeBits(8, value >> 8);
        try self.writeBits(8, value);
    }

    fn writeBit(self: *BitWriter, bit: u32) Failure!void {
        try self.writeBits(1, bit);
    }

    fn writeBits(self: *BitWriter, n: u6, value: u64) Failure!void {
        var remaining = n;
        const v = value;
        while (remaining > 0) {
            const take = @min(remaining, @as(u6, 31));
            self.buffer <<= @intCast(take);
            self.buffer |= @as(u32, @intCast(v >> (remaining - take))) & ((@as(u32, 1) << take) - 1);
            self.bits += take;
            remaining -= take;
            while (self.bits >= 8) {
                const byte: u8 = @intCast(self.buffer >> (self.bits - 8));
                try self.emit(byte);
                self.bits -= 8;
                self.buffer &= (@as(u32, 1) << self.bits) - 1;
            }
        }
    }

    fn flush(self: *BitWriter) Failure!void {
        if (self.bits > 0) {
            const byte: u8 = @intCast(self.buffer << (8 - self.bits));
            try self.emit(byte);
            self.bits = 0;
            self.buffer = 0;
        }
        if (self.pending_len > 0) {
            try io.writeBytes(self.writer, self.pending[0..self.pending_len]);
            self.pending_len = 0;
        }
    }
};

const HuffTable = struct {
    min_len: u8,
    max_len: u8,
    limit: [max_code_len + 1]u32,
    base: [max_code_len + 2]u32,
    perm: [max_alpha_size]u16,
};

fn buildHuffTable(lens: []const u8, alpha_size: u32) Failure!HuffTable {
    var table: HuffTable = undefined;
    @memset(&table.limit, 0);
    @memset(&table.base, 0);
    @memset(&table.perm, 0);
    table.min_len = max_code_len;
    table.max_len = 0;
    var sym: u32 = 0;
    while (sym < alpha_size) : (sym += 1) {
        const len = lens[sym];
        if (len < 1 or len > max_code_len) return error.InvalidData;
        if (len < table.min_len) table.min_len = len;
        if (len > table.max_len) table.max_len = len;
    }
    if (table.min_len > table.max_len) return error.InvalidData;
    var count: [max_code_len + 2]u32 = undefined;
    @memset(&count, 0);
    sym = 0;
    while (sym < alpha_size) : (sym += 1) {
        count[lens[sym] + 1] += 1;
    }
    var len: u32 = 1;
    while (len <= max_code_len + 1) : (len += 1) {
        count[len] += count[len - 1];
    }
    var pp: u32 = 0;
    len = table.min_len;
    while (len <= table.max_len) : (len += 1) {
        sym = 0;
        while (sym < alpha_size) : (sym += 1) {
            if (lens[sym] == len) {
                if (pp >= max_alpha_size) return error.InvalidData;
                table.perm[pp] = @intCast(sym);
                pp += 1;
            }
        }
    }
    if (pp != alpha_size) return error.InvalidData;
    @memset(&table.base, 0);
    sym = 0;
    while (sym < alpha_size) : (sym += 1) {
        table.base[lens[sym] + 1] += 1;
    }
    len = 1;
    while (len <= max_code_len + 1) : (len += 1) {
        table.base[len] += table.base[len - 1];
    }
    @memset(&table.limit, 0);
    var vec: u32 = 0;
    len = table.min_len;
    while (len <= table.max_len) : (len += 1) {
        vec += table.base[len + 1] - table.base[len];
        table.limit[len] = vec - 1;
        vec <<= 1;
    }
    len = table.min_len + 1;
    while (len <= table.max_len) : (len += 1) {
        table.base[len] = ((table.limit[len - 1] + 1) << 1) - table.base[len];
    }
    return table;
}

fn decodeHuffman(br: *BitReader, table: *const HuffTable) Failure!u32 {
    while (br.bit_count < 15 and br.byte_pos < br.bytes.len) try br.refill();
    if (br.bit_count >= 15) {
        const z15: u32 = @intCast((br.bits >> @intCast(br.bit_count - 15)) & 0x7FFF);
        var zn: u6 = @intCast(table.min_len);
        while (zn < 15 and (z15 >> @intCast(15 - zn)) > table.limit[zn]) zn += 1;
        if ((z15 >> @intCast(15 - zn)) <= table.limit[zn]) {
            br.bit_count -= zn;
            const idx = (z15 >> @intCast(15 - zn)) - table.base[zn];
            if (idx >= max_alpha_size) return error.InvalidData;
            return table.perm[idx];
        }
        if (zn >= table.max_len) return error.InvalidData;
        br.bit_count -= 15;
        var zvec: u32 = z15;
        while (zn < table.max_len and zvec > table.limit[zn]) {
            zn += 1;
            zvec = (zvec << 1) | try br.readBit();
        }
        if (zvec > table.limit[zn]) return error.InvalidData;
        const idx = zvec - table.base[zn];
        if (idx >= max_alpha_size) return error.InvalidData;
        return table.perm[idx];
    }
    var zn: u6 = @intCast(table.min_len);
    var zvec = try br.readBits(zn);
    while (zvec > table.limit[zn]) {
        if (zn >= table.max_len) return error.InvalidData;
        zn += 1;
        const bit = try br.readBit();
        zvec = (zvec << 1) | bit;
    }
    const idx = zvec - table.base[zn];
    if (idx >= max_alpha_size) return error.InvalidData;
    return table.perm[idx];
}
