const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("options");

const binary = @import("../common/primitive/binary.zig");
const ReadCursor = binary.ReadCursor;
const checksum = @import("../common/primitive/checksum.zig");
const huffman = @import("../common/primitive/huffman.zig");
const tee = @import("../common/primitive/tee.zig");
const kernels = @import("kernels.zig");

// NEON is baseline on aarch64, so the wide match-copy path needs no extra
// target feature; other targets keep the portable word-at-a-time path.
const vector_match_copy = !build_options.force_fallback and builtin.cpu.arch == .aarch64;

pub const block_size_max = 1 << 17;
pub const window_size_min = 1024;
pub const window_size_max = 1 << 30;
const frame_magic = 0xFD2FB528;
const dictionary_magic = 0xEC30A437;
const skippable_magic_min = 0x184D2A50;
const skippable_magic_max = 0x184D2A5F;
const start_repeated_offset_1 = 1;
const start_repeated_offset_2 = 4;
const start_repeated_offset_3 = 8;

pub const DecodeError = error{
    InvalidData,
    IntegrityFailure,
    Unsupported,
    ResourceLimit,
    IoFailure,
};

pub const Options = struct {
    window_size: u32,
    max_encoded_bytes: u64 = std.math.maxInt(u64),
    max_decoded_bytes: u64 = std.math.maxInt(u64),
    dictionary: ?[]const u8 = null,
    in_place: bool = false,
    hash_bits: u5 = 17,
    max_chain: u32 = 64,
    nice_len: u32 = 32,
    search_window: u32 = 32768,
    lazy: bool = false,
    skip_interior_insert: bool = false,
    double_hash: bool = true,
    row_match: bool = false,
};

const LimitedReader = struct {
    inner: *std.Io.Reader,
    limit: u64,
    consumed: u64,
    limit_reached: bool,
    buffer: [4096]u8,
    interface: std.Io.Reader,

    fn init(inner: *std.Io.Reader, limit: u64) LimitedReader {
        return .{
            .inner = inner,
            .limit = limit,
            .consumed = 0,
            .limit_reached = false,
            .buffer = undefined,
            .interface = .{
                .vtable = &.{
                    .stream = stream,
                    .discard = discard,
                },
                .buffer = &.{},
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *LimitedReader = @fieldParentPtr("interface", r);
        if (self.consumed >= self.limit) {
            self.limit_reached = true;
            return error.EndOfStream;
        }
        const remaining = self.limit - self.consumed;
        const effective = limit.min(std.Io.Limit.limited64(remaining));
        const n = try self.inner.stream(w, effective);
        self.consumed += n;
        return n;
    }

    fn discard(r: *std.Io.Reader, limit: std.Io.Limit) std.Io.Reader.Error!usize {
        const self: *LimitedReader = @fieldParentPtr("interface", r);
        if (self.consumed >= self.limit) {
            self.limit_reached = true;
            return error.EndOfStream;
        }
        const remaining = self.limit - self.consumed;
        const effective = limit.min(std.Io.Limit.limited64(remaining));
        const n = try self.inner.discard(effective);
        self.consumed += n;
        return n;
    }
};

pub fn decodeStream(input: *std.Io.Reader, output: *std.Io.Writer, history: []u8, options: Options) DecodeError!usize {
    return decodeWithOutput(input, output, history, options, false);
}

pub fn decodeInPlace(input: *std.Io.Reader, output: []u8, options: Options) DecodeError!usize {
    if (options.window_size < window_size_min or options.window_size > window_size_max) return error.Unsupported;
    if (output.len < @as(usize, options.window_size) + block_size_max) return error.Unsupported;
    var discard_buffer: [0]u8 = .{};
    var discard = std.Io.Writer.Discarding.init(&discard_buffer).writer;
    return decodeWithOutput(input, &discard, output, options, true);
}

fn decodeWithOutput(input: *std.Io.Reader, output: *std.Io.Writer, history: []u8, options: Options, in_place: bool) DecodeError!usize {
    if (options.window_size < window_size_min or options.window_size > window_size_max) return error.Unsupported;
    const needed_history = @as(usize, options.window_size) + block_size_max;
    if (history.len < needed_history) return error.Unsupported;
    var limited = LimitedReader.init(input, options.max_encoded_bytes);
    limited.interface.buffer = &limited.buffer;
    var decoder: Decoder = .{
        .input = &limited.interface,
        .output = output,
        .history = history,
        .window_size = options.window_size,
        .max_decoded = options.max_decoded_bytes,
        .history_end = 0,
        .output_base = 0,
        .dictionary = options.dictionary,
        .frame_output = 0,
        .total_output = 0,
        .content_size = null,
        .has_checksum = false,
        .in_place = in_place,
        .checksummer = checksum.XxHash64.init(0),
        .block_buffer = undefined,
        .literal_state = undefined,
        .match_state = undefined,
        .offset_state = undefined,
        .prev_literal_state = undefined,
        .prev_match_state = undefined,
        .prev_offset_state = undefined,
        .prev_tables_valid = false,
        .repeat_offsets = .{
            start_repeated_offset_1,
            start_repeated_offset_2,
            start_repeated_offset_3,
        },
        .huffman_tree = null,
        .lit_window = 0,
        .lit_window_bits = 0,
        .lit_stream_bytes = &.{},
        .lit_stream_remaining = 0,
        .lit_stream_count = 0,
        .literal_stream_index = 0,
    };
    while (true) {
        const magic = readU32le(&limited.interface) catch |err| switch (err) {
            error.EndOfStream => break,
            error.ReadFailed => return error.IoFailure,
        };
        if (magic == frame_magic) {
            decoder.decodeFrameBody() catch |err| {
                if (limited.limit_reached) return error.ResourceLimit;
                return err;
            };
        } else if (magic >= skippable_magic_min and magic <= skippable_magic_max) {
            const size = readU32le(&limited.interface) catch |err| switch (err) {
                error.EndOfStream => return error.InvalidData,
                error.ReadFailed => return error.IoFailure,
            };
            try skipBytes(&limited.interface, size);
        } else {
            return error.InvalidData;
        }
    }
    return std.math.cast(usize, decoder.total_output) orelse error.ResourceLimit;
}

pub fn frameContentSize(input: []const u8, max_window: u32) DecodeError!usize {
    var source = std.Io.Reader.fixed(input);
    return try scanContentSize(&source, max_window);
}

pub fn decodedSize(input: []const u8, history: []u8, options: Options) DecodeError!usize {
    var source = std.Io.Reader.fixed(input);
    var counter = tee.CountingTee(false, false).init(null);
    return try decodeStream(&source, &counter.writer, history, options);
}

pub const EncodeError = error{
    InvalidData,
    ResourceLimit,
    IoFailure,
};

pub fn encodeStream(input: *std.Io.Reader, output: *std.Io.Writer, history: []u8, workspace: []u32, options: Options) EncodeError!usize {
    if (options.window_size < window_size_min or options.window_size > window_size_max) return error.InvalidData;
    if (options.hash_bits < 10 or options.hash_bits > 17) return error.InvalidData;
    if (options.max_chain == 0) return error.InvalidData;
    if (options.nice_len < min_match_len) return error.InvalidData;
    if (options.search_window == 0) return error.InvalidData;
    const dictionary = options.dictionary orelse &.{};
    const needed_history = @as(usize, options.window_size) + block_size_max + dictionary.len;
    if (history.len < needed_history) return error.InvalidData;
    const frame_cap = if (useFixedTables(options))
        @min(history.len - dictionary.len - block_size_max, encoder_frame_size_max)
    else
        @min(options.window_size, encoder_frame_size_max);
    if (workspace.len < encoderWorkspaceU32Count(dictionary.len, frame_cap, options)) return error.InvalidData;
    var total_encoded: u64 = 0;
    var total_input: u64 = 0;
    var empty = true;
    @memcpy(history[0..dictionary.len], dictionary);
    while (true) {
        const frame_len = try readFrameInput(input, history[dictionary.len..], frame_cap, options.max_decoded_bytes, &total_input);
        if (frame_len == 0) {
            if (empty) {
                const written = try encodeFrame(output, history[dictionary.len..][0..0], workspace, options, 0);
                total_encoded = try checkedAdd(total_encoded, written, options.max_encoded_bytes);
            }
            break;
        }
        empty = false;
        const written = try encodeFrame(output, history[0 .. dictionary.len + frame_len], workspace, options, dictionary.len);
        total_encoded = try checkedAdd(total_encoded, written, options.max_encoded_bytes);
    }
    if (total_input > options.max_decoded_bytes) return error.ResourceLimit;
    if (total_encoded > options.max_encoded_bytes) return error.ResourceLimit;
    return std.math.cast(usize, total_encoded) orelse error.ResourceLimit;
}

fn readFrameInput(input: *std.Io.Reader, buffer: []u8, max_len: usize, max_total: u64, total: *u64) EncodeError!usize {
    var len: usize = 0;
    const target_max = @min(max_len, buffer.len);
    while (len < target_max) {
        const chunk = @min(target_max - len, 65536);
        var target = std.Io.Writer.fixed(buffer[len..][0..chunk]);
        const n = input.stream(&target, .limited(chunk)) catch |err| switch (err) {
            error.EndOfStream => break,
            error.ReadFailed, error.WriteFailed => return error.IoFailure,
        };
        if (n == 0) break;
        len += n;
    }
    total.* = std.math.add(u64, total.*, len) catch return error.ResourceLimit;
    if (total.* > max_total) return error.ResourceLimit;
    return len;
}

fn checkedAdd(a: u64, b: u64, limit: u64) EncodeError!u64 {
    const sum = std.math.add(u64, a, b) catch return error.ResourceLimit;
    if (sum > limit) return error.ResourceLimit;
    return sum;
}

fn encodeFrame(output: *std.Io.Writer, content: []const u8, workspace: []u32, options: Options, content_start: usize) EncodeError!usize {
    var counted = tee.CountingTee(false, false).init(output);
    try writeU32le(&counted.writer, frame_magic);
    const frame_len = content.len - content_start;
    try writeFrameHeader(&counted.writer, frame_len, options.window_size);
    try encodeBlocks(&counted.writer, content, content_start, workspace, options);
    var hasher = checksum.XxHash64.init(0);
    hasher.update(content[content_start..]);
    try writeU32le(&counted.writer, @truncate(hasher.final()));
    return std.math.cast(usize, counted.written()) orelse error.ResourceLimit;
}

fn writeFrameHeader(writer: *std.Io.Writer, content_size: usize, window_size: u32) EncodeError!void {
    var cs_flag: u2 = 0;
    var field_size: u4 = 1;
    var fcs: u64 = content_size;
    if (content_size > 0xFFFFFFFF) {
        cs_flag = 3;
        field_size = 8;
    } else if (content_size > 65791) {
        cs_flag = 2;
        field_size = 4;
    } else if (content_size > 255) {
        cs_flag = 1;
        field_size = 2;
        fcs -%= 256;
    }
    const single_segment = content_size <= 0xFFFF and content_size <= window_size;
    const descriptor: u8 = (@as(u8, cs_flag) << 6) | 0x04 | (if (single_segment) @as(u8, 0x20) else @as(u8, 0));
    try writeByte(writer, descriptor);
    if (!single_segment) {
        try writeByte(writer, encodeWindowDescriptor(window_size));
    }
    for (0..field_size) |i| {
        try writeByte(writer, @truncate(fcs >> @intCast(i * 8)));
    }
}

fn encodeWindowDescriptor(window_size: u32) u8 {
    if (window_size < 1024) return 0;
    const exponent: u5 = @intCast(31 - @clz(window_size) - 10);
    const base: u64 = @as(u64, 1) << @intCast(exponent + 10);
    const unit = base / 8;
    const mantissa_u = (window_size - base + unit - 1) / unit;
    const mantissa: u8 = @intCast(@min(mantissa_u, 7));
    return (@as(u8, exponent) << 3) | mantissa;
}

fn encodeBlocks(output: *std.Io.Writer, content: []const u8, content_start: usize, workspace: []u32, options: Options) EncodeError!void {
    var literal_table: [1 << 6]FseEntry = undefined;
    var match_table: [1 << 6]FseEntry = undefined;
    var offset_table: [1 << 5]FseEntry = undefined;
    buildFseTable(&default_literal_probs, &literal_table) catch return error.InvalidData;
    buildFseTable(&default_match_probs, &match_table) catch return error.InvalidData;
    buildFseTable(&default_offset_probs, &offset_table) catch return error.InvalidData;
    const frame_len = content.len - content_start;
    const head = workspace[0..hash_size];
    @memset(head, encoder_no_position);
    const chain = if (useFixedTables(options))
        workspace[hash_size .. hash_size + dfastShortTableSize(options)]
    else
        workspace[hash_size .. hash_size + @max(content.len, dfastShortTableSize(options))];
    if (useDfast(options)) @memset(chain, encoder_no_position);
    const block_workspace = workspace[hash_size + chain.len ..];
    var offset: usize = 0;
    var repeat_offsets = [3]u32{ start_repeated_offset_1, start_repeated_offset_2, start_repeated_offset_3 };
    var prev: PrevFseTables = .{};
    while (offset < frame_len) {
        const block_end = @min(offset + encoder_block_size_max, frame_len);
        const is_last = block_end == frame_len;
        try encodeBlock(output, content, content_start + offset, content_start + block_end, head, chain, &literal_table, &match_table, &offset_table, is_last, options, block_workspace, &repeat_offsets, &prev);
        offset = block_end;
    }
    if (frame_len == 0) {
        try writeBlockHeader(output, .raw, 0, true);
    }
}

pub const encoder_frame_size_max = 1 << 26;
const encoder_zip_frame_budget = 1 << 22;
const encoder_block_size_max = 128 * 1024;
const encoder_no_position = std.math.maxInt(u32);
const encoder_block_seq_u32s = (encoder_block_size_max * @sizeOf(SeqData) + 3) / 4;
const encoder_block_lit_u32s = (encoder_block_size_max + 3) / 4;
const encoder_block_section_u32s = (3 * encoder_block_size_max + 3) / 4;
const encoder_workspace_u32_count = hash_size + encoder_zip_frame_budget + encoder_block_section_u32s;

pub fn encoderWorkspaceU32Count(dictionary_len: usize, frame_budget: usize, options: Options) usize {
    const chain_size = if (useFixedTables(options)) dfastShortTableSize(options) else @max(dictionary_len + frame_budget, dfastShortTableSize(options));
    return hash_size + chain_size + encoder_block_seq_u32s + encoder_block_lit_u32s + encoder_block_section_u32s;
}

pub const encoder_workspace_size = encoder_workspace_u32_count * @sizeOf(u32);
const min_match_len = 3;
const min_take_len = 4;
const hash_size = 1 << 17;

fn dfastShortTableSize(options: Options) usize {
    return @as(usize, 1) << (options.hash_bits - 1);
}

pub fn useDfast(options: Options) bool {
    return options.double_hash and !options.lazy and !options.skip_interior_insert;
}

pub fn useRowMatch(options: Options) bool {
    return options.row_match;
}

// The dfast and row finders index fixed-size tables by hash, so a frame may
// fill the history regardless of window; the chain matcher indexes its table
// by absolute position and must cap the frame at the window.
fn useFixedTables(options: Options) bool {
    return useDfast(options) or useRowMatch(options);
}

// A block never exceeds its raw form (3-byte header + content): compressed
// blocks ship only when strictly smaller and RLE blocks are 4 bytes. Frames
// are capped at min(window, 2^26) by the adapter's history sizing, so the
// frame count adds one magic+header+checksum (<= 18 bytes) per frame. The
// plan's single-frame +64 constant ignored the multi-frame split at small
// windows.
pub fn encodedSizeBound(input_len: usize, options: Options) usize {
    const frame_cap = @max(@min(@as(usize, options.window_size), encoder_frame_size_max), 1);
    const frames = input_len / frame_cap + 1;
    return input_len +| 3 *| (input_len / encoder_block_size_max + frames) +| 18 *| frames +| 8;
}

const SeqData = struct {
    literal_length: u32,
    literal_code: u8,
    literal_extra: u32,
    literal_extra_bits: u5,
    match_length: u32,
    match_code: u8,
    match_extra: u32,
    match_extra_bits: u5,
    offset: u32,
    offset_code: u8,
    offset_extra: u32,
    offset_extra_bits: u5,
};

const LengthCode = struct {
    code: u8,
    extra: u32,
    bits: u5,
};

fn encodeBlock(output: *std.Io.Writer, content: []const u8, block_start: usize, block_end: usize, head: []u32, chain: []u32, literal_table: []const FseEntry, match_table: []const FseEntry, offset_table: []const FseEntry, is_last: bool, options: Options, block_workspace: []u32, repeat_offsets: *[3]u32, prev: *PrevFseTables) EncodeError!void {
    if (useRowMatch(options)) return encodeBlockRow(output, content, block_start, block_end, head, chain, literal_table, match_table, offset_table, is_last, options, block_workspace, repeat_offsets, prev);
    if (useDfast(options)) return encodeBlockDfast(output, content, block_start, block_end, head, chain, literal_table, match_table, offset_table, is_last, options, block_workspace, repeat_offsets, prev);
    const src = content[block_start..block_end];
    if (src.len == 0) {
        try writeBlockHeader(output, .raw, 0, is_last);
        return;
    }
    const first_byte = src[0];
    var all_same = true;
    for (src) |b| {
        if (b != first_byte) {
            all_same = false;
            break;
        }
    }
    if (all_same) {
        try writeBlockHeader(output, .rle, src.len, is_last);
        try writeByte(output, first_byte);
        return;
    }
    const seq_data = std.mem.bytesAsSlice(SeqData, std.mem.sliceAsBytes(block_workspace[0..encoder_block_seq_u32s]));
    const literal_buf = std.mem.sliceAsBytes(block_workspace[encoder_block_seq_u32s..][0..encoder_block_lit_u32s])[0..encoder_block_size_max];
    var literal_freq: [256]u32 = undefined;
    var literal_count: usize = 0;
    var seq_count: usize = 0;
    var lit_start: usize = 0;
    var pos: usize = 0;
    var insert_pos: usize = block_start;
    var pending_len: usize = 0;
    var pending_offset: usize = 0;
    var has_pending: bool = false;
    while (pos < src.len) {
        while (insert_pos < block_start + pos) {
            insertPosition(content, insert_pos, block_end, head, chain, options);
            insert_pos += 1;
        }
        var match_len: usize = undefined;
        var match_offset: usize = undefined;
        if (has_pending) {
            match_len = pending_len;
            match_offset = pending_offset;
            has_pending = false;
        } else {
            const match = findLongestMatch(content, block_start, block_end, pos, head, chain, options);
            if (options.lazy and match.len < options.nice_len and pos + 1 < src.len) {
                insertPosition(content, insert_pos, block_end, head, chain, options);
                insert_pos += 1;
                const next_match = findLongestMatch(content, block_start, block_end, pos + 1, head, chain, options);
                if (next_match.len > match.len) {
                    pending_len = next_match.len;
                    pending_offset = next_match.offset;
                    has_pending = true;
                    pos += 1;
                    continue;
                }
            }
            match_len = match.len;
            match_offset = match.offset;
        }
        if (match_len >= min_take_len) {
            appendSequence(seq_data, &seq_count, literal_buf, &literal_count, src, lit_start, pos, match_len, @intCast(match_offset), repeat_offsets);
            pos += match_len;
            if (options.skip_interior_insert) insert_pos = block_start + pos;
            lit_start = pos;
        } else {
            pos += 1;
        }
    }
    while (insert_pos < block_end) {
        insertPosition(content, insert_pos, block_end, head, chain, options);
        insert_pos += 1;
    }
    const tail = src[lit_start..];
    @memcpy(literal_buf[literal_count..][0..tail.len], tail);
    literal_count += tail.len;
    countLiteralFreqs(literal_buf[0..literal_count], &literal_freq);
    try finishBlock(output, src, literal_buf[0..literal_count], seq_data[0..seq_count], &literal_freq, literal_table, match_table, offset_table, is_last, block_workspace, prev);
}

fn countLiteralFreqs(literals: []const u8, freq: *[256]u32) void {
    var lanes: [4][256]u32 = @splat(@splat(0));
    var i: usize = 0;
    while (i + 4 <= literals.len) : (i += 4) {
        lanes[0][literals[i]] += 1;
        lanes[1][literals[i + 1]] += 1;
        lanes[2][literals[i + 2]] += 1;
        lanes[3][literals[i + 3]] += 1;
    }
    while (i < literals.len) : (i += 1) lanes[0][literals[i]] += 1;
    for (0..256) |s| freq[s] = lanes[0][s] + lanes[1][s] + lanes[2][s] + lanes[3][s];
}

fn appendSequence(seq_data: []SeqData, seq_count: *usize, literal_buf: []u8, literal_count: *usize, src: []const u8, lit_start: usize, lit_end: usize, match_len: usize, offset: u32, repeat_offsets: *[3]u32) void {
    // Literal histogram is counted in one pass over the finished buffer.
    const run = src[lit_start..lit_end];
    // Most runs are a few bytes; word-wise copies beat a memcpy call there.
    var k: usize = 0;
    while (k + 8 <= run.len) : (k += 8) {
        literal_buf[literal_count.* + k ..][0..8].* = run[k..][0..8].*;
    }
    while (k < run.len) : (k += 1) {
        literal_buf[literal_count.* + k] = run[k];
    }
    literal_count.* += run.len;
    const literal_len = @as(u32, @intCast(lit_end - lit_start));
    const lit_code = literalLengthCode(literal_len);
    const mat_code = matchLengthCode(@intCast(match_len));
    const off_code = encodeOffset(offset, literal_len, repeat_offsets);
    seq_data[seq_count.*] = .{
        .literal_length = literal_len,
        .literal_code = lit_code.code,
        .literal_extra = lit_code.extra,
        .literal_extra_bits = lit_code.bits,
        .match_length = @intCast(match_len),
        .match_code = mat_code.code,
        .match_extra = mat_code.extra,
        .match_extra_bits = mat_code.bits,
        .offset = offset,
        .offset_code = off_code.code,
        .offset_extra = off_code.extra,
        .offset_extra_bits = off_code.bits,
    };
    seq_count.* += 1;
}

fn finishBlock(output: *std.Io.Writer, src: []const u8, literal_buf: []const u8, seq_data: []const SeqData, literal_freq: *[256]u32, literal_table: []const FseEntry, match_table: []const FseEntry, offset_table: []const FseEntry, is_last: bool, block_workspace: []u32, prev: *PrevFseTables) EncodeError!void {
    const literal_count = literal_buf.len;
    const seq_count = seq_data.len;
    const raw_size = 3 + src.len;
    var literal_section: []const u8 = undefined;
    var seq_section: []const u8 = undefined;
    const section_buf = std.mem.sliceAsBytes(block_workspace[encoder_block_seq_u32s + encoder_block_lit_u32s ..])[0 .. 3 * encoder_block_size_max];
    const literal_section_buf = section_buf[0..encoder_block_size_max];
    const raw_literal_section_buf = section_buf[encoder_block_size_max .. 2 * encoder_block_size_max];
    const seq_section_buf = section_buf[2 * encoder_block_size_max .. 3 * encoder_block_size_max];
    const compressed_literal_ok = buildLiteralSection(literal_buf[0..literal_count], literal_freq, literal_section_buf, &literal_section);
    var raw_literal_section: []const u8 = undefined;
    // A raw section costs at least literal_count + 1 bytes; only build it when
    // it can still win against the compressed one.
    var raw_literal_ok = false;
    if (!compressed_literal_ok or literal_section.len >= literal_count + 1) {
        raw_literal_ok = buildRawLiteralSection(literal_buf[0..literal_count], raw_literal_section_buf, &raw_literal_section);
        if (raw_literal_ok and (!compressed_literal_ok or raw_literal_section.len <= literal_section.len)) {
            literal_section = raw_literal_section;
        }
    }
    const literal_ok = compressed_literal_ok or raw_literal_ok;
    const prev_saved = prev.*;
    const seq_ok = buildSequenceSection(seq_data[0..seq_count], literal_table, match_table, offset_table, prev, seq_section_buf, &seq_section);
    const compressed_size = if (literal_ok and seq_ok) 3 + literal_section.len + seq_section.len else raw_size;
    const use_compressed = literal_ok and seq_ok and compressed_size < raw_size;
    if (!use_compressed) prev.* = prev_saved;
    if (use_compressed) {
        try writeBlockHeader(output, .compressed, literal_section.len + seq_section.len, is_last);
        output.writeAll(literal_section) catch return error.IoFailure;
        output.writeAll(seq_section) catch return error.IoFailure;
    } else {
        try writeBlockHeader(output, .raw, src.len, is_last);
        output.writeAll(src) catch return error.IoFailure;
    }
}

fn encodeBlockDfast(output: *std.Io.Writer, content: []const u8, block_start: usize, block_end: usize, head: []u32, chain: []u32, literal_table: []const FseEntry, match_table: []const FseEntry, offset_table: []const FseEntry, is_last: bool, options: Options, block_workspace: []u32, repeat_offsets: *[3]u32, prev: *PrevFseTables) EncodeError!void {
    const src = content[block_start..block_end];
    if (src.len == 0) {
        try writeBlockHeader(output, .raw, 0, is_last);
        return;
    }
    const first_byte = src[0];
    var all_same = true;
    for (src) |b| {
        if (b != first_byte) {
            all_same = false;
            break;
        }
    }
    if (all_same) {
        try writeBlockHeader(output, .rle, src.len, is_last);
        try writeByte(output, first_byte);
        return;
    }
    const seq_data = std.mem.bytesAsSlice(SeqData, std.mem.sliceAsBytes(block_workspace[0..encoder_block_seq_u32s]));
    const literal_buf = std.mem.sliceAsBytes(block_workspace[encoder_block_seq_u32s..][0..encoder_block_lit_u32s])[0..encoder_block_size_max];
    var literal_freq: [256]u32 = undefined;
    var literal_count: usize = 0;
    var seq_count: usize = 0;
    var anchor: usize = 0;
    var ip: usize = 0;
    const long_bits = options.hash_bits;
    const short_bits = long_bits - 1;
    const step_incr: usize = 1 << 8;
    const min_abs: usize = if (block_end > options.window_size) block_end - options.window_size else 0;
    if (src.len >= 8) {
        const ilimit = src.len - 8;
        outer: while (true) {
            var step: usize = 1;
            // Step escalation is relative to the search restart point: probe
            // every position for step_incr bytes after each match, then skip.
            var next_step: usize = ip + step_incr;
            const ip1_0 = ip + step;
            if (ip1_0 > ilimit) break;
            var hl0 = hash8At(content, block_start + ip, long_bits);
            var idxl0 = head[hl0];
            var ip1 = ip1_0;
            inner: while (true) {
                const pos_abs = block_start + ip;
                const hs0 = hash5At(content, pos_abs, short_bits);
                const idxs0 = chain[hs0];
                head[hl0] = @intCast(pos_abs);
                chain[hs0] = @intCast(pos_abs);
                const curr: u32 = @intCast(pos_abs);
                var stored = false;
                var hl1: u32 = undefined;
                var idxl1: u32 = undefined;
                if (repeat_offsets[0] != 0 and pos_abs + 1 >= repeat_offsets[0] and pos_abs + 1 - repeat_offsets[0] >= min_abs and ip + 5 <= src.len and readU32At(content, pos_abs + 1 - repeat_offsets[0]) == readU32At(content, pos_abs + 1)) {
                    const mlen = 4 + countForward(content, pos_abs + 5 - repeat_offsets[0], pos_abs + 5, block_end);
                    const match_start = ip + 1;
                    appendSequence(seq_data, &seq_count, literal_buf, &literal_count, src, anchor, match_start, mlen, repeat_offsets[0], repeat_offsets);
                    ip = match_start + mlen;
                    anchor = ip;
                    stored = true;
                }
                if (!stored) {
                    hl1 = hash8At(content, block_start + ip1, long_bits);
                    if (idxl0 != encoder_no_position and idxl0 >= min_abs and idxl0 < pos_abs and readU64At(content, idxl0) == readU64At(content, pos_abs)) {
                        var mlen = 8 + countForward(content, idxl0 + 8, pos_abs + 8, block_end);
                        var mip = ip;
                        var midx = idxl0;
                        while (mip > anchor and midx > min_abs and content[block_start + mip - 1] == content[midx - 1]) {
                            mip -= 1;
                            midx -= 1;
                            mlen += 1;
                        }
                        if (step < 4) head[hl1] = @intCast(block_start + ip1);
                        appendSequence(seq_data, &seq_count, literal_buf, &literal_count, src, anchor, mip, mlen, @intCast((block_start + mip) - midx), repeat_offsets);
                        ip = mip + mlen;
                        anchor = ip;
                        stored = true;
                    } else {
                        idxl1 = head[hl1];
                        if (idxs0 != encoder_no_position and idxs0 >= min_abs and idxs0 < pos_abs and readU32At(content, idxs0) == readU32At(content, pos_abs)) {
                            var mlen = 4 + countForward(content, idxs0 + 4, pos_abs + 4, block_end);
                            var mip = ip;
                            var midx = idxs0;
                            const ip1_abs = block_start + ip1;
                            if (idxl1 != encoder_no_position and idxl1 >= min_abs and idxl1 < ip1_abs and readU64At(content, idxl1) == readU64At(content, ip1_abs)) {
                                const l1len = 8 + countForward(content, idxl1 + 8, ip1_abs + 8, block_end);
                                if (l1len > mlen) {
                                    mip = ip1;
                                    mlen = l1len;
                                    midx = idxl1;
                                }
                            }
                            while (mip > anchor and midx > min_abs and content[block_start + mip - 1] == content[midx - 1]) {
                                mip -= 1;
                                midx -= 1;
                                mlen += 1;
                            }
                            if (step < 4) head[hl1] = @intCast(block_start + ip1);
                            appendSequence(seq_data, &seq_count, literal_buf, &literal_count, src, anchor, mip, mlen, @intCast((block_start + mip) - midx), repeat_offsets);
                            ip = mip + mlen;
                            anchor = ip;
                            stored = true;
                        }
                    }
                }
                if (stored) {
                    if (ip <= ilimit) {
                        var after_abs = block_start + ip;
                        const insert_abs = curr + 2;
                        head[hash8At(content, @intCast(insert_abs), long_bits)] = insert_abs;
                        head[hash8At(content, after_abs - 2, long_bits)] = @intCast(after_abs - 2);
                        chain[hash5At(content, @intCast(insert_abs), short_bits)] = insert_abs;
                        chain[hash5At(content, after_abs - 1, short_bits)] = @intCast(after_abs - 1);
                        while (ip <= ilimit and repeat_offsets[1] != 0 and after_abs >= repeat_offsets[1] and after_abs - repeat_offsets[1] >= min_abs and readU32At(content, after_abs - repeat_offsets[1]) == readU32At(content, after_abs)) {
                            const rlen = 4 + countForward(content, after_abs + 4 - repeat_offsets[1], after_abs + 4, block_end);
                            head[hash8At(content, after_abs, long_bits)] = @intCast(after_abs);
                            chain[hash5At(content, after_abs, short_bits)] = @intCast(after_abs);
                            appendSequence(seq_data, &seq_count, literal_buf, &literal_count, src, anchor, anchor, rlen, repeat_offsets[1], repeat_offsets);
                            ip += rlen;
                            after_abs = block_start + ip;
                            anchor = ip;
                        }
                    }
                    continue :outer;
                }
                if (ip1 >= next_step) {
                    step += 1;
                    next_step += step_incr;
                }
                ip = ip1;
                ip1 += step;
                hl0 = hl1;
                idxl0 = idxl1;
                if (ip1 > ilimit) break :inner;
            }
        }
    }
    const tail = src[anchor..];
    @memcpy(literal_buf[literal_count..][0..tail.len], tail);
    literal_count += tail.len;
    countLiteralFreqs(literal_buf[0..literal_count], &literal_freq);
    try finishBlock(output, src, literal_buf[0..literal_count], seq_data[0..seq_count], &literal_freq, literal_table, match_table, offset_table, is_last, block_workspace, prev);
}

// Row-based matchfinder (the zstd row_match selector): the position table is
// split into rows of row_size slots selected by a 5-byte hash; a 16-bit tag
// from the same hash prefilters the row, and the NEON scan compares a whole
// row at once. The scalar path computes the identical mask, so fallback and
// vector builds encode byte-identically.
const row_log = 4;
const row_size = 1 << row_log;

const RowProbe = struct {
    base: u32,
    tag: u16,
};

fn rowProbeAt(content: []const u8, pos: usize, row_bits: u5) RowProbe {
    const u = readU64At(content, pos);
    const product = (u << 24) *% 889523592379;
    const shift: u6 = @intCast(64 - @as(u7, row_bits));
    const tag_shift: u6 = @intCast(64 - @as(u7, row_bits) - 16);
    return .{
        .base = @as(u32, @truncate(product >> shift)) << row_log,
        .tag = @truncate(product >> tag_shift),
    };
}

fn rowTagMask(tag_table: []const u16, base: u32, tag: u16) u16 {
    if (comptime vector_match_copy) {
        const tags: @Vector(row_size, u16) = tag_table[base..][0..row_size].*;
        return @bitCast(tags == @as(@Vector(row_size, u16), @splat(tag)));
    }
    var mask: u16 = 0;
    for (0..row_size) |k| {
        mask |= @as(u16, @intFromBool(tag_table[base + k] == tag)) << @intCast(k);
    }
    return mask;
}

// Insertion evicts the slot the position's low bits name: consecutive inserts
// cycle every slot, so eviction stays FIFO-like without a per-row cursor.
fn rowInsert(pos_table: []u32, tag_table: []u16, probe: RowProbe, pos_abs: usize) void {
    const slot = probe.base + @as(u32, @truncate(pos_abs & (row_size - 1)));
    tag_table[slot] = probe.tag;
    pos_table[slot] = @intCast(pos_abs);
}

// Longest tag-filtered candidate in the row, nearest offset on ties. Callers
// scan before inserting the query position, so the row read is pre-insert
// state and the evicted slot still competes. Depth counts only candidates
// that pass the position guards, keeping the decision independent of
// tag-table garbage in never-written slots (empty slots read back
// encoder_no_position from the per-frame position memset).
fn rowScan(content: []const u8, pos_table: []const u32, base: u32, mask: u16, pos_abs: usize, block_end: usize, min_abs: usize, options: Options) struct { len: usize, cand: usize } {
    const cur_word = readU32At(content, pos_abs);
    var best_len: usize = min_take_len - 1;
    var best_cand: usize = 0;
    var best_offset: usize = 0;
    var depth: u32 = 0;
    var rest = mask;
    while (rest != 0 and depth < options.max_chain) {
        const k: u4 = @intCast(@ctz(rest));
        rest &= rest - 1;
        const cand: usize = pos_table[base + k];
        if (cand == encoder_no_position or cand < min_abs or cand >= pos_abs) continue;
        depth += 1;
        if (readU32At(content, cand) != cur_word) continue;
        const mlen = 4 + countForward(content, cand + 4, pos_abs + 4, block_end);
        const offset = pos_abs - cand;
        if (mlen > best_len or (mlen == best_len and offset < best_offset)) {
            best_len = mlen;
            best_cand = cand;
            best_offset = offset;
            if (best_len >= options.nice_len) break;
        }
    }
    return .{ .len = best_len, .cand = best_cand };
}

fn encodeBlockRow(output: *std.Io.Writer, content: []const u8, block_start: usize, block_end: usize, head: []u32, chain: []u32, literal_table: []const FseEntry, match_table: []const FseEntry, offset_table: []const FseEntry, is_last: bool, options: Options, block_workspace: []u32, repeat_offsets: *[3]u32, prev: *PrevFseTables) EncodeError!void {
    const src = content[block_start..block_end];
    if (src.len == 0) {
        try writeBlockHeader(output, .raw, 0, is_last);
        return;
    }
    const first_byte = src[0];
    var all_same = true;
    for (src) |b| {
        if (b != first_byte) {
            all_same = false;
            break;
        }
    }
    if (all_same) {
        try writeBlockHeader(output, .rle, src.len, is_last);
        try writeByte(output, first_byte);
        return;
    }
    const seq_data = std.mem.bytesAsSlice(SeqData, std.mem.sliceAsBytes(block_workspace[0..encoder_block_seq_u32s]));
    const literal_buf = std.mem.sliceAsBytes(block_workspace[encoder_block_seq_u32s..][0..encoder_block_lit_u32s])[0..encoder_block_size_max];
    var literal_freq: [256]u32 = undefined;
    var literal_count: usize = 0;
    var seq_count: usize = 0;
    var anchor: usize = 0;
    var ip: usize = 0;
    const row_bits: u5 = options.hash_bits - row_log;
    const pos_table = head;
    const tag_table = std.mem.bytesAsSlice(u16, std.mem.sliceAsBytes(chain));
    const step_incr: usize = 1 << 8;
    const min_abs: usize = if (block_end > options.window_size) block_end - options.window_size else 0;
    if (src.len >= 8) {
        const ilimit = src.len - 8;
        outer: while (true) {
            var step: usize = 1;
            // Step escalation is relative to the search restart point, matching
            // the dfast finder: probe every position for step_incr bytes after
            // each match, then skip.
            var next_step: usize = ip + step_incr;
            const ip1_0 = ip + step;
            if (ip1_0 > ilimit) break;
            var probe0 = rowProbeAt(content, block_start + ip, row_bits);
            var ip1 = ip1_0;
            inner: while (true) {
                const pos_abs = block_start + ip;
                const curr: u32 = @intCast(pos_abs);
                var stored = false;
                var probe1: RowProbe = undefined;
                if (repeat_offsets[0] != 0 and pos_abs + 1 >= repeat_offsets[0] and pos_abs + 1 - repeat_offsets[0] >= min_abs and ip + 5 <= src.len and readU32At(content, pos_abs + 1 - repeat_offsets[0]) == readU32At(content, pos_abs + 1)) {
                    const mlen = 4 + countForward(content, pos_abs + 5 - repeat_offsets[0], pos_abs + 5, block_end);
                    const match_start = ip + 1;
                    appendSequence(seq_data, &seq_count, literal_buf, &literal_count, src, anchor, match_start, mlen, repeat_offsets[0], repeat_offsets);
                    ip = match_start + mlen;
                    anchor = ip;
                    stored = true;
                    rowInsert(pos_table, tag_table, probe0, pos_abs);
                }
                if (!stored) {
                    probe1 = rowProbeAt(content, block_start + ip1, row_bits);
                    const best = rowScan(content, pos_table, probe0.base, rowTagMask(tag_table, probe0.base, probe0.tag), pos_abs, block_end, min_abs, options);
                    rowInsert(pos_table, tag_table, probe0, pos_abs);
                    if (best.len >= min_take_len) {
                        var mlen = best.len;
                        var mip = ip;
                        var midx = best.cand;
                        const ip1_abs = block_start + ip1;
                        // The one-ahead rescan mirrors the dfast short-hit
                        // branch: only a weak match (< 8 bytes) justifies it.
                        if (best.len < 8) {
                            const next = rowScan(content, pos_table, probe1.base, rowTagMask(tag_table, probe1.base, probe1.tag), ip1_abs, block_end, min_abs, options);
                            if (next.len > mlen) {
                                mip = ip1;
                                mlen = next.len;
                                midx = next.cand;
                            }
                        }
                        if (step < 4) rowInsert(pos_table, tag_table, probe1, ip1_abs);
                        while (mip > anchor and midx > min_abs and content[block_start + mip - 1] == content[midx - 1]) {
                            mip -= 1;
                            midx -= 1;
                            mlen += 1;
                        }
                        appendSequence(seq_data, &seq_count, literal_buf, &literal_count, src, anchor, mip, mlen, @intCast((block_start + mip) - midx), repeat_offsets);
                        ip = mip + mlen;
                        anchor = ip;
                        stored = true;
                    }
                }
                if (stored) {
                    if (ip <= ilimit) {
                        var after_abs = block_start + ip;
                        rowInsert(pos_table, tag_table, rowProbeAt(content, curr + 2, row_bits), curr + 2);
                        rowInsert(pos_table, tag_table, rowProbeAt(content, after_abs - 2, row_bits), after_abs - 2);
                        rowInsert(pos_table, tag_table, rowProbeAt(content, after_abs - 1, row_bits), after_abs - 1);
                        while (ip <= ilimit and repeat_offsets[1] != 0 and after_abs >= repeat_offsets[1] and after_abs - repeat_offsets[1] >= min_abs and readU32At(content, after_abs - repeat_offsets[1]) == readU32At(content, after_abs)) {
                            const rlen = 4 + countForward(content, after_abs + 4 - repeat_offsets[1], after_abs + 4, block_end);
                            rowInsert(pos_table, tag_table, rowProbeAt(content, after_abs, row_bits), after_abs);
                            appendSequence(seq_data, &seq_count, literal_buf, &literal_count, src, anchor, anchor, rlen, repeat_offsets[1], repeat_offsets);
                            ip += rlen;
                            after_abs = block_start + ip;
                            anchor = ip;
                        }
                    }
                    continue :outer;
                }
                if (ip1 >= next_step) {
                    step += 1;
                    next_step += step_incr;
                }
                ip = ip1;
                ip1 += step;
                probe0 = probe1;
                if (ip1 > ilimit) break :inner;
            }
        }
    }
    const tail = src[anchor..];
    @memcpy(literal_buf[literal_count..][0..tail.len], tail);
    literal_count += tail.len;
    countLiteralFreqs(literal_buf[0..literal_count], &literal_freq);
    try finishBlock(output, src, literal_buf[0..literal_count], seq_data[0..seq_count], &literal_freq, literal_table, match_table, offset_table, is_last, block_workspace, prev);
}

fn readU32At(content: []const u8, pos: usize) u32 {
    return std.mem.readInt(u32, content[pos..][0..4], .little);
}

fn readU64At(content: []const u8, pos: usize) u64 {
    return std.mem.readInt(u64, content[pos..][0..8], .little);
}

fn hash5At(content: []const u8, pos: usize, bits: u5) u32 {
    const u = readU64At(content, pos);
    const shift: u6 = @intCast(64 - @as(u7, bits));
    return @truncate(((u << 24) *% 889523592379) >> shift);
}

fn hash8At(content: []const u8, pos: usize, bits: u5) u32 {
    const u = readU64At(content, pos);
    const shift: u6 = @intCast(64 - @as(u7, bits));
    return @truncate((u *% 0xCF1BBCDCB7A56463) >> shift);
}

fn countForward(content: []const u8, a: usize, b: usize, end: usize) usize {
    const max_len = end - @max(a, b);
    return kernels.matchLen8(content, a, b, max_len);
}

fn hash4(content: []const u8, pos: usize, mask: u32) u32 {
    const word = @as(u32, content[pos]) | (@as(u32, content[pos + 1]) << 8) | (@as(u32, content[pos + 2]) << 16) | (@as(u32, content[pos + 3]) << 24);
    var h = word *% 0x9E37_79B1;
    h ^= h >> 16;
    return h & mask;
}

fn insertPosition(content: []const u8, pos: usize, block_end: usize, head: []u32, chain: []u32, options: Options) void {
    if (pos + 4 > block_end) return;
    const mask = (@as(u32, 1) << options.hash_bits) - 1;
    const h = hash4(content, pos, mask);
    chain[pos] = head[h];
    head[h] = @intCast(pos);
}

fn findLongestMatch(content: []const u8, block_start: usize, block_end: usize, pos: usize, head: []u32, chain: []u32, options: Options) struct { len: usize, offset: usize } {
    const src_len = block_end - block_start;
    if (pos + min_take_len > src_len) return .{ .len = 0, .offset = 0 };
    const cur_abs = block_start + pos;
    const window_limit = @min(options.window_size, options.search_window);
    const limit = @min(cur_abs, window_limit);
    const min_abs = cur_abs - limit;
    const mask = (@as(u32, 1) << options.hash_bits) - 1;
    const h = hash4(content, cur_abs, mask);
    var best_len: usize = min_take_len - 1;
    var best_offset: usize = 0;
    var candidate = head[h];
    var steps: usize = 0;
    const cur_word = readU32At(content, cur_abs);
    while (candidate != encoder_no_position and candidate >= min_abs and steps < options.max_chain) : (steps += 1) {
        if (candidate < cur_abs) {
            const max_len = src_len - pos;
            if (readU32At(content, candidate) == cur_word) {
                const len = kernels.matchLen8(content, candidate, cur_abs, max_len);
                if (len > best_len) {
                    best_len = len;
                    best_offset = cur_abs - candidate;
                    if (len >= options.nice_len) break;
                }
            }
        }
        candidate = chain[candidate];
    }
    if (best_len >= min_take_len) return .{ .len = best_len, .offset = best_offset };
    return .{ .len = 0, .offset = 0 };
}

fn literalLengthCode(length: u32) LengthCode {
    if (length < 16) {
        return .{ .code = @intCast(length), .extra = 0, .bits = 0 };
    }
    var lo: usize = 16;
    var hi: usize = literals_length_code_table.len - 1;
    while (lo < hi) {
        const mid = (lo + hi + 1) >> 1;
        if (literals_length_code_table[mid][0] <= length) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    const base = literals_length_code_table[lo][0];
    const bits = literals_length_code_table[lo][1];
    return .{ .code = @intCast(lo), .extra = length - base, .bits = bits };
}

fn matchLengthCode(length: u32) LengthCode {
    var lo: usize = 0;
    var hi: usize = match_length_code_table.len - 1;
    while (lo < hi) {
        const mid = (lo + hi + 1) >> 1;
        if (match_length_code_table[mid][0] <= length) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    const base = match_length_code_table[lo][0];
    const bits = match_length_code_table[lo][1];
    return .{ .code = @intCast(lo), .extra = length - base, .bits = bits };
}

fn encodeOffset(offset: u32, literal_length: u32, reps: *[3]u32) LengthCode {
    const ll0 = literal_length == 0;
    const offset_value: u32 = if (!ll0 and offset == reps[0]) 1 else if (offset == reps[1]) @as(u32, 2) - @intFromBool(ll0) else if (offset == reps[2]) @as(u32, 3) - @intFromBool(ll0) else if (ll0 and offset == reps[0] - 1) 3 else offset + 3;
    switch (offset_value) {
        1 => {
            if (ll0) std.mem.swap(u32, &reps[0], &reps[1]);
        },
        2 => {
            if (ll0) {
                std.mem.swap(u32, &reps[0], &reps[2]);
                std.mem.swap(u32, &reps[1], &reps[2]);
            } else std.mem.swap(u32, &reps[0], &reps[1]);
        },
        3 => {
            if (ll0) {
                updateRepeatOffsets(offset, reps);
            } else {
                std.mem.swap(u32, &reps[0], &reps[2]);
                std.mem.swap(u32, &reps[1], &reps[2]);
            }
        },
        else => updateRepeatOffsets(offset, reps),
    }
    const code = std.math.log2_int(u32, offset_value);
    const extra = offset_value - (@as(u32, 1) << code);
    return .{ .code = @intCast(code), .extra = extra, .bits = @intCast(code) };
}

fn updateRepeatOffsets(offset: u32, reps: *[3]u32) void {
    reps[2] = reps[1];
    reps[1] = reps[0];
    reps[0] = offset;
}

fn writeBlockHeader(writer: *std.Io.Writer, block_type: BlockType, size: usize, is_last: bool) EncodeError!void {
    const last_bit: u24 = if (is_last) 1 else 0;
    const type_bits: u24 = @intFromEnum(block_type);
    const value: u24 = last_bit | (type_bits << 1) | (@as(u24, @intCast(size)) << 3);
    var bytes: [3]u8 = undefined;
    bytes[0] = @truncate(value);
    bytes[1] = @truncate(value >> 8);
    bytes[2] = @truncate(value >> 16);
    writer.writeAll(&bytes) catch return error.IoFailure;
}

fn writeByte(writer: *std.Io.Writer, byte: u8) EncodeError!void {
    const bytes = [1]u8{byte};
    writer.writeAll(&bytes) catch return error.IoFailure;
}

fn writeU32le(writer: *std.Io.Writer, value: u32) EncodeError!void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    writer.writeAll(&bytes) catch return error.IoFailure;
}

const HuffmanCode = struct {
    prefix: u16,
    bits: u4,
};

fn buildLiteralSection(literals: []const u8, freq: *[256]u32, out: []u8, section: *[]const u8) bool {
    const count = literals.len;
    if (count == 0) {
        if (out.len < 1) return false;
        out[0] = 0;
        section.* = out[0..1];
        return true;
    }
    const first = literals[0];
    var all_same = true;
    for (literals) |b| {
        if (b != first) {
            all_same = false;
            break;
        }
    }
    if (all_same) {
        // One repeated byte is an RLE_Literals_Block: a raw header would
        // declare `count` regenerated bytes but store one, which every
        // decoder rejects or misreads.
        const header_len = rawLiteralHeaderSize(count);
        if (out.len < header_len + 1) return false;
        writeRleLiteralHeader(out[0..header_len], count);
        out[header_len] = first;
        section.* = out[0 .. header_len + 1];
        return true;
    }
    var lengths: [256]u8 = undefined;
    huffman.limitedLengths(freq, &lengths, 11);
    var max_symbol: usize = 0;
    for (0..256) |i| {
        if (freq[i] > 0) max_symbol = i;
    }
    const symbol_count = max_symbol + 1;
    var max_bits: u4 = 0;
    for (lengths[0..symbol_count]) |len| {
        if (len > max_bits) max_bits = @intCast(len);
    }
    var weights: [256]u4 = undefined;
    for (0..symbol_count) |i| {
        weights[i] = if (lengths[i] == 0) 0 else @intCast(max_bits + 1 - lengths[i]);
    }
    {
        var weight_power_sum: u32 = 0;
        for (weights[0..max_symbol]) |value| {
            weight_power_sum += (@as(u16, 1) << @intCast(value)) >> 1;
        }
        const derived_max_bits: u4 = if (weight_power_sum == 0) 1 else @intCast(std.math.log2_int(u32, weight_power_sum) + 1);
        const next_power = @as(u32, 1) << derived_max_bits;
        const last_weight_value = next_power - weight_power_sum;
        if (last_weight_value == 0 or !std.math.isPowerOfTwo(last_weight_value)) return false;
        const derived_last: u4 = @intCast(std.math.log2_int(u32, last_weight_value) + 1);
        if (weights[max_symbol] != derived_last) return false;
        weights[max_symbol] = derived_last;
    }
    var tree: HuffmanTree = .{};
    buildHuffmanTree(weights[0..symbol_count], symbol_count, &tree) catch return false;
    var codes: [256]HuffmanCode = undefined;
    for (0..tree.symbol_count) |i| {
        const node = tree.nodes[i];
        const bits = tree.max_bits + 1 - node.weight;
        codes[node.symbol] = .{ .prefix = node.prefix, .bits = @intCast(bits) };
    }
    var tree_buf: [256]u8 = undefined;
    const tree_section = buildTreeSection(weights[0..symbol_count], symbol_count, &tree_buf) orelse return false;
    const tree_header_size = tree_section.len;
    if (count < 1024) {
        if (out.len < 3 + tree_header_size + (count + 7) / 8) return false;
        var stream_bits: [2048]u8 = undefined;
        var bit_writer = BitWriter.init(stream_bits[0..]);
        for (literals) |byte| {
            const code = codes[byte];
            bit_writer.writeBitsFast(code.prefix, code.bits) catch return false;
        }
        const stream = bit_writer.finish() catch return false;
        const compressed_size = tree_header_size + stream.len;
        if (compressed_size > 1023) return false;
        if (3 + tree_header_size + stream.len > out.len) return false;
        writeCompressedLiteralHeader(out[0..3], count, compressed_size);
        @memcpy(out[3..][0..tree_header_size], tree_section);
        @memcpy(out[3 + tree_header_size ..][0..stream.len], stream);
        section.* = out[0 .. 3 + tree_header_size + stream.len];
        return true;
    }
    const size_format: u2 = if (count < 16384) 2 else 3;
    const header_len: usize = if (size_format == 2) 4 else 5;
    const sizes_offset = header_len + tree_header_size;
    const streams_offset = sizes_offset + 6;
    if (out.len < streams_offset) return false;
    var stream_pos = streams_offset;
    var stream_sizes: [4]usize = undefined;
    const segment = (count + 3) / 4;
    for (0..3) |k| {
        const start = segment * k;
        const end = segment * (k + 1);
        var bit_writer = BitWriter.init(out[stream_pos..]);
        for (literals[start..end]) |byte| {
            const code = codes[byte];
            bit_writer.writeBitsFast(code.prefix, code.bits) catch return false;
        }
        const stream = bit_writer.finish() catch return false;
        stream_sizes[k] = stream.len;
        stream_pos += stream.len;
    }
    {
        var bit_writer = BitWriter.init(out[stream_pos..]);
        for (literals[segment * 3 ..]) |byte| {
            const code = codes[byte];
            bit_writer.writeBitsFast(code.prefix, code.bits) catch return false;
        }
        const stream = bit_writer.finish() catch return false;
        stream_sizes[3] = stream.len;
        stream_pos += stream.len;
    }
    const compressed_size = tree_header_size + 6 + (stream_pos - streams_offset);
    const max_compressed: usize = if (size_format == 2) 16383 else 262143;
    if (compressed_size > max_compressed or stream_sizes[0] > 0xFFFF or stream_sizes[1] > 0xFFFF or stream_sizes[2] > 0xFFFF) return false;
    if (stream_pos > out.len) return false;
    writeCompressedLiteralHeader(out[0..header_len], count, compressed_size);
    @memcpy(out[header_len..][0..tree_header_size], tree_section);
    std.mem.writeInt(u16, out[sizes_offset..][0..2], @intCast(stream_sizes[0]), .little);
    std.mem.writeInt(u16, out[sizes_offset + 2 ..][0..2], @intCast(stream_sizes[1]), .little);
    std.mem.writeInt(u16, out[sizes_offset + 4 ..][0..2], @intCast(stream_sizes[2]), .little);
    section.* = out[0..stream_pos];
    return true;
}

fn buildTreeSection(weights: []const u4, symbol_count: usize, out: []u8) ?[]const u8 {
    const stored = symbol_count - 1;
    var fse_scratch: [256]u8 = undefined;
    const fse = buildFseTreeSection(weights[0..stored], &fse_scratch);
    if (stored <= 128) {
        const direct_size = 1 + (stored + 1) / 2;
        const direct_fits = out.len >= direct_size;
        if (fse) |section| {
            if (direct_fits and direct_size <= section.len) {
                return writeDirectTree(out, weights, stored, direct_size);
            }
            if (out.len < section.len) return null;
            @memcpy(out[0..section.len], section);
            return out[0..section.len];
        }
        if (!direct_fits) return null;
        return writeDirectTree(out, weights, stored, direct_size);
    }
    if (fse) |section| {
        if (out.len < section.len) return null;
        @memcpy(out[0..section.len], section);
        return out[0..section.len];
    }
    return null;
}

fn writeDirectTree(out: []u8, weights: []const u4, stored: usize, size: usize) ?[]const u8 {
    out[0] = @intCast(127 + stored);
    for (0..stored / 2) |i| {
        const high: u8 = weights[2 * i];
        const low: u8 = weights[2 * i + 1];
        out[1 + i] = (high << 4) | low;
    }
    if (stored % 2 == 1) {
        const last: u8 = weights[stored - 1];
        out[1 + stored / 2] = last << 4;
    }
    return out[0..size];
}

fn buildFseTreeSection(weights: []const u4, out: []u8) ?[]const u8 {
    const stored = weights.len;
    var wfreq: [256]u32 = @splat(0);
    for (weights[0..stored]) |w| wfreq[w] += 1;
    var normalized: [256]i16 = undefined;
    const norm = normalizeFseCounts(&wfreq, 12, 6, 6, &normalized) orelse return null;
    const table_size: usize = @as(usize, 1) << norm.log;
    var table_buf: [64]FseEntry = undefined;
    buildFseTable(normalized[0..norm.count], table_buf[0..table_size]) catch return null;
    var ncount_buf: [128]u8 = undefined;
    const ncount = writeNCounts(&ncount_buf, normalized[0..norm.count], norm.log) orelse return null;
    var stream_buf: [256]u8 = undefined;
    const stream = fseEncodeWeightStream(weights[0..stored], normalized[0..norm.count], norm.log, table_buf[0..table_size], &stream_buf) orelse return null;
    const compressed_size = ncount.len + stream.len;
    // The FSE form is representable only below 128: header bytes >= 128 mean
    // direct weights to every decoder, so a larger description must fall
    // back (the caller then emits raw literals).
    if (compressed_size > 127 or out.len < 1 + compressed_size) return null;
    out[0] = @intCast(compressed_size);
    @memcpy(out[1..][0..ncount.len], ncount);
    @memcpy(out[1 + ncount.len ..][0..stream.len], stream);
    return out[0 .. 1 + compressed_size];
}

const FseEncoderTable = struct {
    state_values: [64]u16,
    delta_nb_bits: [12]u32,
    delta_find_state: [12]i32,
};

fn fseEncodeWeightStream(symbols: []const u4, normalized: []const i16, norm_log: u5, table: []const FseEntry, out: []u8) ?[]const u8 {
    var writer = ReverseBitWriter.init(out);
    const et = buildFseEncoderTable(normalized, table);
    var ip = symbols.len;
    var cstate1: u16 = undefined;
    var cstate2: u16 = undefined;
    if (ip % 2 == 1) {
        ip -= 1;
        cstate1 = fseInitCState(&et, @intCast(symbols[ip]));
        ip -= 1;
        cstate2 = fseInitCState(&et, @intCast(symbols[ip]));
        ip -= 1;
        if (!fseEncodeSymbol(&writer, &cstate1, @intCast(symbols[ip]), &et)) return null;
    } else {
        ip -= 1;
        cstate2 = fseInitCState(&et, @intCast(symbols[ip]));
        ip -= 1;
        cstate1 = fseInitCState(&et, @intCast(symbols[ip]));
    }
    if ((symbols.len - 2) & 2 != 0) {
        ip -= 1;
        if (!fseEncodeSymbol(&writer, &cstate2, @intCast(symbols[ip]), &et)) return null;
        ip -= 1;
        if (!fseEncodeSymbol(&writer, &cstate1, @intCast(symbols[ip]), &et)) return null;
    }
    while (ip > 0) {
        ip -= 1;
        if (!fseEncodeSymbol(&writer, &cstate2, @intCast(symbols[ip]), &et)) return null;
        ip -= 1;
        if (!fseEncodeSymbol(&writer, &cstate1, @intCast(symbols[ip]), &et)) return null;
        ip -= 1;
        if (!fseEncodeSymbol(&writer, &cstate2, symbols[ip], &et)) return null;
        ip -= 1;
        if (!fseEncodeSymbol(&writer, &cstate1, symbols[ip], &et)) return null;
    }
    writer.writeBits(cstate2, norm_log) catch return null;
    writer.writeBits(cstate1, norm_log) catch return null;
    return writer.finish() catch return null;
}

fn buildFseEncoderTable(normalized: []const i16, table: []const FseEntry) FseEncoderTable {
    var counts: [12]u8 = @splat(0);
    for (table) |entry| counts[entry.symbol] += 1;
    var first: [12]u8 = @splat(0);
    var running: u16 = 0;
    for (0..12) |s| {
        first[s] = @intCast(running);
        running += counts[s];
    }
    var state_values: [64]u16 = undefined;
    var next = first;
    for (table, 0..) |entry, state| {
        const slot = next[entry.symbol];
        next[entry.symbol] = slot + 1;
        state_values[slot] = @intCast(table.len + state);
    }
    var delta_nb_bits: [12]u32 = undefined;
    var delta_find_state: [12]i32 = undefined;
    const table_log: u5 = @intCast(std.math.log2_int(usize, table.len));
    for (0..normalized.len) |s| {
        const n = normalized[s];
        if (n == 0) continue;
        if (n == 1 or n == -1) {
            delta_nb_bits[s] = (@as(u32, table_log) << 16) - (@as(u32, 1) << table_log);
            delta_find_state[s] = @intCast(@as(i32, first[s]) - 1);
        } else {
            const max_bits_out: u32 = @as(u32, table_log) - std.math.log2_int(u32, @intCast(n - 1));
            const min_state_plus: u32 = @as(u32, @intCast(n)) << @intCast(max_bits_out);
            delta_nb_bits[s] = (max_bits_out << 16) - min_state_plus;
            delta_find_state[s] = @intCast(@as(i32, first[s]) - @as(i32, @intCast(n)));
        }
    }
    return .{
        .state_values = state_values,
        .delta_nb_bits = delta_nb_bits,
        .delta_find_state = delta_find_state,
    };
}

fn fseInitCState(et: *const FseEncoderTable, symbol: u8) u16 {
    const nb_bits_out: u32 = (et.delta_nb_bits[symbol] + (1 << 15)) >> 16;
    const value: u32 = (nb_bits_out << 16) - et.delta_nb_bits[symbol];
    const shift: u4 = @intCast(nb_bits_out);
    const idx = @as(i32, @intCast(value >> shift)) + et.delta_find_state[symbol];
    return et.state_values[@intCast(idx)];
}

fn fseEncodeSymbol(writer: *ReverseBitWriter, state: *u16, symbol: u8, et: *const FseEncoderTable) bool {
    const nb_bits_out: u32 = (@as(u32, state.*) + et.delta_nb_bits[symbol]) >> 16;
    const shift: u4 = @intCast(nb_bits_out);
    writer.writeBits(state.*, shift) catch return false;
    const idx = @as(i32, @intCast(state.* >> shift)) + et.delta_find_state[symbol];
    state.* = et.state_values[@intCast(idx)];
    return true;
}

fn buildRawLiteralSection(literals: []const u8, out: []u8, section: *[]const u8) bool {
    const count = literals.len;
    if (count == 0) {
        if (out.len < 1) return false;
        out[0] = 0;
        section.* = out[0..1];
        return true;
    }
    const header_len = rawLiteralHeaderSize(count);
    if (out.len < header_len + count) return false;
    writeRawLiteralHeader(out[0..header_len], count);
    @memcpy(out[header_len..][0..count], literals);
    section.* = out[0 .. header_len + count];
    return true;
}

fn rawLiteralHeaderSize(size: usize) usize {
    return if (size <= 31) 1 else if (size <= 4095) 2 else 3;
}

fn writeRawLiteralHeader(out: []u8, size: usize) void {
    if (size <= 31) {
        out[0] = @intCast(size << 3);
    } else if (size <= 4095) {
        out[0] = @intCast(((size & 0b1111) << 4) | 0b0100);
        out[1] = @intCast(size >> 4);
    } else {
        out[0] = @intCast(((size & 0b1111) << 4) | 0b1100);
        out[1] = @intCast((size >> 4) & 0xFF);
        out[2] = @intCast((size >> 12) & 0xFF);
    }
}

fn writeRleLiteralHeader(out: []u8, size: usize) void {
    if (size <= 31) {
        out[0] = @intCast((size << 3) | 0b01);
    } else if (size <= 4095) {
        out[0] = @intCast(((size & 0b1111) << 4) | 0b0101);
        out[1] = @intCast(size >> 4);
    } else {
        out[0] = @intCast(((size & 0b1111) << 4) | 0b1101);
        out[1] = @intCast((size >> 4) & 0xFF);
        out[2] = @intCast((size >> 12) & 0xFF);
    }
}

fn writeCompressedLiteralHeader(out: []u8, regen: usize, compressed: usize) void {
    if (out.len == 3) {
        out[0] = @intCast(((regen & 0b1111) << 4) | 0b0010);
        out[1] = @intCast(((regen >> 4) & 0b00111111) | ((compressed & 0b11) << 6));
        out[2] = @intCast(compressed >> 2);
    } else if (out.len == 4) {
        out[0] = @intCast(((regen & 0b1111) << 4) | 0b1010);
        out[1] = @intCast((regen >> 4) & 0xFF);
        out[2] = @intCast(((regen >> 12) & 0b11) | ((compressed & 0b111111) << 2));
        out[3] = @intCast(compressed >> 6);
    } else {
        out[0] = @intCast(((regen & 0b1111) << 4) | 0b1110);
        out[1] = @intCast((regen >> 4) & 0xFF);
        out[2] = @intCast(((regen >> 12) & 0b111111) | ((compressed & 0b11) << 6));
        out[3] = @intCast((compressed >> 2) & 0xFF);
        out[4] = @intCast(compressed >> 10);
    }
}

fn buildSequenceSection(seqs: []const SeqData, literal_table: []const FseEntry, match_table: []const FseEntry, offset_table: []const FseEntry, prev: *PrevFseTables, out: []u8, section: *[]const u8) bool {
    const n = seqs.len;
    if (n == 0) {
        if (out.len < 1) return false;
        out[0] = 0;
        section.* = out[0..1];
        return true;
    }
    var lit_symbols: [encoder_block_size_max]u8 = undefined;
    var match_symbols: [encoder_block_size_max]u8 = undefined;
    var offset_symbols: [encoder_block_size_max]u8 = undefined;
    var lit_freq: [256]u32 = @splat(0);
    var match_freq: [256]u32 = @splat(0);
    var offset_freq: [256]u32 = @splat(0);
    for (seqs, 0..) |seq, i| {
        lit_symbols[i] = seq.literal_code;
        match_symbols[i] = seq.match_code;
        offset_symbols[i] = seq.offset_code;
        lit_freq[seq.literal_code] += 1;
        match_freq[seq.match_code] += 1;
        offset_freq[seq.offset_code] += 1;
    }
    var lit_values: [encoder_block_size_max]u16 = undefined;
    var lit_counts: [encoder_block_size_max]u8 = undefined;
    var match_values: [encoder_block_size_max]u16 = undefined;
    var match_counts: [encoder_block_size_max]u8 = undefined;
    var offset_values: [encoder_block_size_max]u16 = undefined;
    var offset_counts: [encoder_block_size_max]u8 = undefined;
    var lit_table_buf: [512]FseEntry = undefined;
    var match_table_buf: [512]FseEntry = undefined;
    var offset_table_buf: [256]FseEntry = undefined;
    var lit_ncount: [256]u8 = undefined;
    var match_ncount: [256]u8 = undefined;
    var offset_ncount: [256]u8 = undefined;
    const lit_plan = planMode(n, &lit_symbols, &lit_freq, 36, 9, literal_table, if (prev.literal_valid) prev.literal[0 .. @as(usize, 1) << prev.literal_log] else null, prev.literal_log, &lit_values, &lit_counts, &lit_table_buf, &lit_ncount);
    const match_plan = planMode(n, &match_symbols, &match_freq, 53, 9, match_table, if (prev.match_valid) prev.match[0 .. @as(usize, 1) << prev.match_log] else null, prev.match_log, &match_values, &match_counts, &match_table_buf, &match_ncount);
    const offset_plan = planMode(n, &offset_symbols, &offset_freq, 32, 8, offset_table, if (prev.offset_valid) prev.offset[0 .. @as(usize, 1) << prev.offset_log] else null, prev.offset_log, &offset_values, &offset_counts, &offset_table_buf, &offset_ncount);
    if (!lit_plan.valid or !match_plan.valid or !offset_plan.valid) return false;
    prev.literal_valid = lit_plan.kind == .fse or lit_plan.kind == .predefined or lit_plan.kind == .repeat;
    prev.match_valid = match_plan.kind == .fse or match_plan.kind == .predefined or match_plan.kind == .repeat;
    prev.offset_valid = offset_plan.kind == .fse or offset_plan.kind == .predefined or offset_plan.kind == .repeat;
    // A repeat plan's table already aliases prev.*; copying it onto itself trips @memcpy's no-alias check.
    if (prev.literal_valid and lit_plan.kind != .repeat) {
        @memcpy(prev.literal[0..lit_plan.table.len], lit_plan.table);
        prev.literal_log = lit_plan.accuracy_log;
    }
    if (prev.match_valid and match_plan.kind != .repeat) {
        @memcpy(prev.match[0..match_plan.table.len], match_plan.table);
        prev.match_log = match_plan.accuracy_log;
    }
    if (prev.offset_valid and offset_plan.kind != .repeat) {
        @memcpy(prev.offset[0..offset_plan.table.len], offset_plan.table);
        prev.offset_log = offset_plan.accuracy_log;
    }
    const header_len = sequenceHeaderSize(n);
    const modes_byte = (@as(u8, @intFromEnum(lit_plan.kind)) << 6) | (@as(u8, @intFromEnum(offset_plan.kind)) << 4) | (@as(u8, @intFromEnum(match_plan.kind)) << 2);
    writeSequenceHeader(out[0..header_len], n, modes_byte);
    var tables_len: usize = 0;
    switch (lit_plan.kind) {
        .fse => {
            @memcpy(out[header_len + tables_len ..][0..lit_plan.ncount.len], lit_plan.ncount);
            tables_len += lit_plan.ncount.len;
        },
        .rle => {
            out[header_len + tables_len] = lit_plan.rle_symbol;
            tables_len += 1;
        },
        .predefined, .repeat => {},
    }
    switch (offset_plan.kind) {
        .fse => {
            @memcpy(out[header_len + tables_len ..][0..offset_plan.ncount.len], offset_plan.ncount);
            tables_len += offset_plan.ncount.len;
        },
        .rle => {
            out[header_len + tables_len] = offset_plan.rle_symbol;
            tables_len += 1;
        },
        .predefined, .repeat => {},
    }
    switch (match_plan.kind) {
        .fse => {
            @memcpy(out[header_len + tables_len ..][0..match_plan.ncount.len], match_plan.ncount);
            tables_len += match_plan.ncount.len;
        },
        .rle => {
            out[header_len + tables_len] = match_plan.rle_symbol;
            tables_len += 1;
        },
        .predefined, .repeat => {},
    }
    var seq_bits_buf: [encoder_block_size_max]u8 = undefined;
    var bit_writer = ReverseBitWriter.init(&seq_bits_buf);
    var j = n;
    while (j > 0) {
        j -= 1;
        if (j + 1 < n) {
            if (offset_plan.kind != .rle) bit_writer.writeBits(offset_values[j], @intCast(offset_counts[j])) catch return false;
            if (match_plan.kind != .rle) bit_writer.writeBits(match_values[j], @intCast(match_counts[j])) catch return false;
            if (lit_plan.kind != .rle) bit_writer.writeBits(lit_values[j], @intCast(lit_counts[j])) catch return false;
        }
        bit_writer.writeBits(seqs[j].literal_extra, seqs[j].literal_extra_bits) catch return false;
        bit_writer.writeBits(seqs[j].match_extra, seqs[j].match_extra_bits) catch return false;
        bit_writer.writeBits(seqs[j].offset_extra, seqs[j].offset_extra_bits) catch return false;
    }
    if (match_plan.kind != .rle) bit_writer.writeBits(match_plan.initial, match_plan.accuracy_log) catch return false;
    if (offset_plan.kind != .rle) bit_writer.writeBits(offset_plan.initial, offset_plan.accuracy_log) catch return false;
    if (lit_plan.kind != .rle) bit_writer.writeBits(lit_plan.initial, lit_plan.accuracy_log) catch return false;
    const bitstream = bit_writer.finish() catch return false;
    if (header_len + tables_len + bitstream.len > out.len) return false;
    @memcpy(out[header_len + tables_len ..][0..bitstream.len], bitstream);
    section.* = out[0 .. header_len + tables_len + bitstream.len];
    return true;
}

fn sequenceHeaderSize(n: usize) usize {
    return if (n < 128) 2 else if (n < 0x7F00) 3 else 4;
}

fn writeSequenceHeader(out: []u8, n: usize, modes: u8) void {
    if (n < 128) {
        out[0] = @intCast(n);
        out[1] = modes;
    } else if (n < 0x7F00) {
        out[0] = @intCast(128 + (n >> 8));
        out[1] = @intCast(n & 0xff);
        out[2] = modes;
    } else {
        out[0] = 0xFF;
        out[1] = @intCast(n & 0xff);
        out[2] = @intCast(n >> 8);
        out[3] = modes;
    }
}

const ModeKind = enum(u2) { predefined, rle, fse, repeat };

const PrevFseTables = struct {
    literal: [512]FseEntry = undefined,
    match: [512]FseEntry = undefined,
    offset: [256]FseEntry = undefined,
    literal_log: u5 = 0,
    match_log: u5 = 0,
    offset_log: u5 = 0,
    literal_valid: bool = false,
    match_valid: bool = false,
    offset_valid: bool = false,
};

const ModePlan = struct {
    kind: ModeKind = .predefined,
    valid: bool = true,
    rle_symbol: u8 = 0,
    accuracy_log: u5 = 0,
    table: []const FseEntry = &.{},
    values: []u16 = &.{},
    counts: []u8 = &.{},
    initial: usize = 0,
    ncount: []const u8 = &.{},
};

fn planMode(n: usize, symbols: []const u8, freq: *const [256]u32, symbol_count: usize, max_log: u5, default_table: []const FseEntry, prev_table: ?[]const FseEntry, prev_log: u5, values: []u16, counts: []u8, table_buf: []FseEntry, ncount_buf: []u8) ModePlan {
    var distinct: usize = 0;
    for (freq[0..symbol_count]) |f| {
        if (f > 0) distinct += 1;
    }
    if (distinct == 1) {
        for (0..symbol_count) |i| {
            if (freq[i] > 0) return .{ .kind = .rle, .rle_symbol = @intCast(i) };
        }
    }
    var best = ModePlan{ .valid = false };
    var best_bits: u64 = std.math.maxInt(u64);
    if (prev_table) |table| {
        if (estimateFseBits(table, freq, symbol_count, prev_log)) |bits| {
            best = .{ .kind = .repeat, .accuracy_log = prev_log, .table = table };
            best_bits = bits;
        }
    }
    const default_log: u5 = @intCast(std.math.log2_int(usize, default_table.len));
    const default_bits = estimateFseBits(default_table, freq, symbol_count, default_log);
    if (default_bits != null and default_bits.? < best_bits) {
        best = .{ .kind = .predefined, .accuracy_log = default_log, .table = default_table };
        best_bits = default_bits.?;
    }
    // Match the reference's table-log choice: no finer than needed for n symbols.
    var start_log: u5 = 5;
    if (n > 2) {
        const hb = std.math.log2_int(usize, n - 1);
        start_log = @intCast(@min(@as(usize, max_log), @max(5, hb -| 2)));
    }
    var normalized: [256]i16 = undefined;
    if (normalizeFseCounts(freq, symbol_count, max_log, start_log, &normalized)) |norm| {
        const table_size = @as(usize, 1) << norm.log;
        if (table_size <= table_buf.len) fse_candidate: {
            buildFseTable(normalized[0..norm.count], table_buf[0..table_size]) catch break :fse_candidate;
            if (estimateFseBits(table_buf[0..table_size], freq, symbol_count, norm.log)) |bits| {
                if (writeNCounts(ncount_buf, normalized[0..norm.count], norm.log)) |ncount| {
                    // The table description costs ncount.len bytes; compare total sizes in bits.
                    const total = bits + @as(u64, ncount.len) * 8;
                    if (total < best_bits) {
                        best = .{ .kind = .fse, .accuracy_log = norm.log, .table = table_buf[0..table_size], .ncount = ncount_buf[0..ncount.len] };
                        best_bits = total;
                    }
                }
            }
        }
    }
    if (!best.valid) return best;
    var initial: usize = undefined;
    var bits: u64 = 0;
    if (!evalFseTable(best.table, symbols, n, values, counts, &initial, &bits)) return .{ .kind = .predefined, .valid = false, .accuracy_log = default_log };
    best.values = values;
    best.counts = counts;
    best.initial = initial;
    return best;
}

fn normalizeFseCounts(freq: *const [256]u32, symbol_count: usize, max_log: u5, start_log: u5, norm: *[256]i16) ?struct { log: u5, count: usize } {
    var total: u64 = 0;
    var present: usize = 0;
    for (freq[0..symbol_count]) |f| {
        if (f > 0) present += 1;
        total += f;
    }
    if (present < 2 or total == 0) return null;
    // Every present symbol needs a slot, and the ncount header encodes log-5.
    const fit_log: u5 = @intCast(std.math.log2_int(usize, present - 1) + 1);
    var table_log: u5 = @min(max_log, @max(5, @max(start_log, fit_log)));
    while (true) {
        const table_size: u64 = @as(u64, 1) << table_log;
        var counts: [256]i16 = @splat(0);
        const scale: u6 = @as(u6, 62) - table_log;
        const step = (@as(u64, 1) << 62) / total;
        const v_step = @as(u64, 1) << @intCast(scale - 20);
        const rtb = [8]u64{ 0, 473195, 504333, 520860, 550000, 700000, 750000, 830000 };
        var still_to_distribute: i64 = @intCast(table_size);
        var largest: usize = 0;
        var largest_p: i64 = 0;
        const low_threshold: u32 = @intCast(total >> table_log);
        for (freq[0..symbol_count], 0..) |f, s| {
            if (f == 0) continue;
            if (f <= low_threshold) {
                // Low-probability symbols are stored as -1: one slot at the
                // high end of the table, cheaper ncount encoding.
                counts[s] = -1;
                still_to_distribute -= 1;
            } else {
                var proba: i64 = @intCast((@as(u64, f) * step) >> @intCast(scale));
                if (proba < 8) {
                    const rest_to_beat = v_step * rtb[@intCast(proba)];
                    const is_bigger = (@as(u64, f) * step) - (@as(u64, @intCast(proba)) << @intCast(scale)) > rest_to_beat;
                    proba += @intFromBool(is_bigger);
                }
                if (proba > largest_p) {
                    largest_p = proba;
                    largest = s;
                }
                counts[s] = @intCast(proba);
                still_to_distribute -= proba;
            }
        }
        if (-still_to_distribute >= @as(i64, counts[largest]) >> 1) {
            if (!normalizeFseM2(freq, symbol_count, table_log, &counts)) {
                if (table_log >= max_log) return null;
                table_log += 1;
                continue;
            }
        } else {
            counts[largest] += @intCast(still_to_distribute);
        }
        var last_present: usize = 0;
        for (0..symbol_count) |s| {
            if (counts[s] != 0) last_present = s;
        }
        // Absent symbols (count 0) occupy no table slot; only low-probability
        // symbols stored as -1 still consume one.
        var check: u64 = 0;
        for (0..last_present + 1) |s| {
            check += if (counts[s] < 0) 1 else @intCast(counts[s]);
        }
        if (check != table_size) {
            if (table_log >= max_log) return null;
            table_log += 1;
            continue;
        }
        @memcpy(norm[0..symbol_count], counts[0..symbol_count]);
        return .{ .log = table_log, .count = last_present + 1 };
    }
}

fn normalizeFseM2(freq: *const [256]u32, symbol_count: usize, table_log: u5, counts: *[256]i16) bool {
    const not_yet_assigned: i16 = -2;
    var total: u64 = 0;
    for (freq[0..symbol_count]) |f| total += f;
    var remaining_total = total;
    @memset(counts[0..symbol_count], 0);
    var distributed: u32 = 0;
    const low_threshold: u32 = @intCast(total >> table_log);
    var low_one: u32 = @intCast((total * 3) >> (table_log + 1));
    for (freq[0..symbol_count], 0..) |f, s| {
        if (f == 0) {
            counts[s] = 0;
        } else if (f <= low_threshold or f <= low_one) {
            counts[s] = 1;
            distributed += 1;
            remaining_total -= f;
        } else {
            counts[s] = not_yet_assigned;
        }
    }
    const table_size: u64 = @as(u64, 1) << table_log;
    var to_distribute: u64 = table_size - distributed;
    if (to_distribute != 0) {
        if (remaining_total / to_distribute > low_one) {
            low_one = @intCast((remaining_total * 3) / (to_distribute * 2));
            for (freq[0..symbol_count], 0..) |f, s| {
                if (counts[s] == not_yet_assigned and f <= low_one) {
                    counts[s] = 1;
                    distributed += 1;
                    remaining_total -= f;
                }
            }
            to_distribute = table_size - distributed;
        }
        if (distributed == symbol_count) {
            var max_v: usize = 0;
            var max_c: u64 = 0;
            for (freq[0..symbol_count], 0..) |f, s| {
                if (f > max_c) {
                    max_v = s;
                    max_c = f;
                }
            }
            counts[max_v] += @intCast(to_distribute);
        } else if (remaining_total == 0) {
            var rem = to_distribute;
            var s: usize = 0;
            while (rem > 0) {
                if (counts[s] > 0) {
                    counts[s] += 1;
                    rem -= 1;
                }
                s = (s + 1) % symbol_count;
            }
        } else {
            const v_step_log: u6 = @as(u6, 62) - table_log;
            const mid = (@as(u64, 1) << (v_step_log - 1)) - 1;
            const r_step = (((@as(u64, 1) << v_step_log) * to_distribute) + mid) / remaining_total;
            var tmp_total = mid;
            for (freq[0..symbol_count], 0..) |f, s| {
                if (counts[s] != not_yet_assigned) continue;
                const end = tmp_total + @as(u64, f) * r_step;
                const s_start: u32 = @intCast(tmp_total >> v_step_log);
                const s_end: u32 = @intCast(end >> v_step_log);
                const weight = s_end - s_start;
                if (weight < 1) return false;
                counts[s] = @intCast(weight);
                tmp_total = end;
            }
        }
    }
    return true;
}

fn writeNCounts(out: []u8, norm: []const i16, log: u5) ?[]const u8 {
    var bw = ReverseBitWriter.init(out);
    bw.writeBits(log - 5, 4) catch return null;
    const table_size: i32 = @as(i32, 1) << log;
    var remaining: i32 = table_size + 1;
    var threshold: i32 = table_size;
    var nb_bits: u5 = log + 1;
    var previous0 = false;
    var i: usize = 0;
    while (i < norm.len) {
        if (previous0) {
            const start = i;
            while (i < norm.len and norm[i] == 0) i += 1;
            var extra = i - start;
            while (extra >= 3) {
                bw.writeBits(3, 2) catch return null;
                extra -= 3;
            }
            bw.writeBits(extra, 2) catch return null;
            previous0 = false;
            if (i >= norm.len) break;
        }
        const raw = norm[i];
        i += 1;
        const max = (2 * threshold - 1) - remaining;
        var count: i32 = raw;
        remaining -= if (count < 0) -count else count;
        count += 1;
        if (count >= threshold) count += max;
        const bits: u5 = if (count < max) nb_bits - 1 else nb_bits;
        bw.writeBits(@intCast(count), bits) catch return null;
        previous0 = count == 1;
        if (remaining < 1) break;
        while (remaining < threshold) {
            nb_bits -= 1;
            threshold >>= 1;
        }
    }
    return bw.finishRaw() catch return null;
}

const FseTableIndex = struct {
    first: [256]u16 = @splat(0),
    count: [256]u16 = @splat(0),
    states: [512]u16 = undefined,
};

fn buildFseIndex(table: []const FseEntry, index: *FseTableIndex) void {
    @memset(index.count[0..], 0);
    for (table) |entry| index.count[entry.symbol] += 1;
    var running: u16 = 0;
    for (0..256) |symbol| {
        index.first[symbol] = running;
        running += index.count[symbol];
    }
    var next = index.first;
    for (table, 0..) |entry, state| {
        const slot = next[entry.symbol];
        next[entry.symbol] = slot + 1;
        index.states[slot] = @intCast(state);
    }
}

const FseEncodeStep = struct {
    state_values: [512]u16,
    delta_nb_bits: [256]u32,
    delta_find_state: [256]i32,
    cell_count: [256]u16,
    table_log: u5,

    fn build(step: *FseEncodeStep, table: []const FseEntry, index: *const FseTableIndex) void {
        const table_size = table.len;
        const table_log: u5 = @intCast(std.math.log2_int(usize, table_size));
        step.table_log = table_log;
        for (0..table_size) |k| step.state_values[k] = @intCast(table_size + index.states[k]);
        step.cell_count = index.count;
        var total: i32 = 0;
        for (0..256) |s| {
            const c = index.count[s];
            if (c == 0) {
                step.delta_nb_bits[s] = ((@as(u32, table_log) + 1) << 16) - @as(u32, @intCast(table_size));
                step.delta_find_state[s] = 0;
                continue;
            }
            if (c == 1) {
                step.delta_nb_bits[s] = (@as(u32, table_log) << 16) - @as(u32, @intCast(table_size));
                step.delta_find_state[s] = total - 1;
                total += 1;
            } else {
                const max_bits_out: u5 = table_log - std.math.log2_int(u16, c - 1);
                const min_state_plus = @as(u32, c) << max_bits_out;
                step.delta_nb_bits[s] = (@as(u32, max_bits_out) << 16) -% min_state_plus;
                step.delta_find_state[s] = total - @as(i32, c);
                total += c;
            }
        }
    }

    // Walk the symbol stream backwards, recording the transition value and bit
    // count the decoder reads after each symbol, plus the flushed state.
    fn pass(step: *const FseEncodeStep, symbols: []const u8, n: usize, values: []u16, counts: []u8, initial: *usize, bits: *u64) bool {
        if (n == 0) return true;
        const table_size = @as(u32, 1) << step.table_log;
        var s: usize = symbols[n - 1];
        if (step.cell_count[s] == 0) return false;
        var total: u64 = step.table_log;
        const nb0: u32 = (step.delta_nb_bits[s] + (1 << 15)) >> 16;
        const v0: u32 = (nb0 << 16) -% step.delta_nb_bits[s];
        var idx: i32 = @as(i32, @intCast(v0 >> @as(u5, @intCast(nb0)))) + step.delta_find_state[s];
        var v: u32 = step.state_values[@intCast(idx)];
        var j = n - 1;
        while (j > 0) {
            j -= 1;
            s = symbols[j];
            if (step.cell_count[s] == 0) return false;
            const nb: u32 = (v + step.delta_nb_bits[s]) >> 16;
            total += nb;
            values[j] = @intCast(v & ((@as(u32, 1) << @as(u5, @intCast(nb))) - 1));
            counts[j] = @intCast(nb);
            idx = @as(i32, @intCast(v >> @as(u5, @intCast(nb)))) + step.delta_find_state[s];
            v = step.state_values[@intCast(idx)];
        }
        initial.* = v - table_size;
        bits.* = total;
        return true;
    }
};

fn evalFseTable(table: []const FseEntry, symbols: []const u8, n: usize, values: []u16, counts: []u8, initial: *usize, bits: *u64) bool {
    var index: FseTableIndex = .{};
    buildFseIndex(table, &index);
    var step: FseEncodeStep = undefined;
    step.build(table, &index);
    return step.pass(symbols, n, values, counts, initial, bits);
}

// Average bits per occurrence of a symbol: its cells partition the state
// range, so cost_s = sum(2^bits * bits) / table_size over the symbol's cells.
fn estimateFseBits(table: []const FseEntry, freq: *const [256]u32, symbol_count: usize, log: u5) ?u64 {
    var cost: [256]u32 = @splat(0);
    var cells: [256]u16 = @splat(0);
    for (table) |entry| {
        cost[entry.symbol] += (@as(u32, 1) << @as(u4, @intCast(entry.bits))) * entry.bits;
        cells[entry.symbol] += 1;
    }
    var total: u64 = log;
    for (freq[0..symbol_count], 0..) |f, s| {
        if (f == 0) continue;
        if (cells[s] == 0) return null;
        total += (@as(u64, f) * cost[s]) >> log;
    }
    return total;
}

const BitWriter = struct {
    buf: []u8,
    pos: usize,
    used: u4,
    acc: u64 = 0,
    acc_bits: u5 = 0,

    fn init(buf: []u8) BitWriter {
        // writeBitsFast assigns every byte it covers; finish() only reads
        // those bytes, so the buffer needs no zeroing.
        return .{ .buf = buf, .pos = 0, .used = 0 };
    }

    fn writeBit(self: *BitWriter, value: u1) error{OutOfSpace}!void {
        if (self.pos >= self.buf.len) return error.OutOfSpace;
        self.buf[self.pos] |= @as(u8, value) << @intCast(7 - self.used);
        self.used += 1;
        if (self.used == 8) {
            self.used = 0;
            self.pos += 1;
        }
    }

    fn writeBits(self: *BitWriter, value: u64, count: u5) error{OutOfSpace}!void {
        if (count == 0) return;
        var i: u5 = count;
        while (i > 0) {
            i -= 1;
            try self.writeBit(@intCast((value >> @intCast(i)) & 1));
        }
    }

    fn writeBitsFast(self: *BitWriter, value: u64, count: u5) error{OutOfSpace}!void {
        if (count == 0) return;
        self.acc = (self.acc << count) | (value & ((@as(u64, 1) << count) - 1));
        self.acc_bits += count;
        while (self.acc_bits >= 8) {
            if (self.pos >= self.buf.len) return error.OutOfSpace;
            self.acc_bits -= 8;
            self.buf[self.pos] = @intCast((self.acc >> self.acc_bits) & 0xFF);
            self.acc &= ((@as(u64, 1) << self.acc_bits) - 1);
            self.pos += 1;
        }
    }

    fn finish(self: *BitWriter) error{OutOfSpace}![]u8 {
        if (self.acc_bits > 0) {
            if (self.pos >= self.buf.len) return error.OutOfSpace;
            self.buf[self.pos] = @intCast(self.acc << @intCast(8 - self.acc_bits));
            self.used = @intCast(self.acc_bits);
            self.acc_bits = 0;
        }
        // The zstd FSE/Huffman bitstream stores the data bytes in reverse
        // memory order, followed by the final-bit marker and zero padding.
        const n = self.pos * 8 + self.used;
        if (n == 0) {
            if (self.buf.len == 0) return error.OutOfSpace;
            self.buf[0] = 0x01;
            return self.buf[0..1];
        }
        const r: usize = n % 8;
        const data_bytes = (n + 7) / 8;
        const out_len = if (r == 0) data_bytes + 1 else data_bytes;
        if (out_len > self.buf.len) return error.OutOfSpace;
        if (r == 0) {
            var lo: usize = 0;
            var hi: usize = data_bytes - 1;
            while (lo < hi) : ({
                lo += 1;
                hi -= 1;
            }) {
                std.mem.swap(u8, &self.buf[lo], &self.buf[hi]);
            }
            self.buf[data_bytes] = 0x01;
        } else {
            const shift: u3 = @intCast(8 - r);
            const low_mask: u8 = lowBitMask(@intCast(8 - r));
            var carry: u8 = 0;
            for (0..data_bytes) |i| {
                const cur = self.buf[i];
                self.buf[i] = carry | (cur >> shift);
                carry = (cur & low_mask) << @intCast(r);
            }
            self.buf[0] |= @as(u8, 1) << @intCast(r);
            var lo: usize = 0;
            var hi: usize = data_bytes - 1;
            while (lo < hi) : ({
                lo += 1;
                hi -= 1;
            }) {
                std.mem.swap(u8, &self.buf[lo], &self.buf[hi]);
            }
        }
        return self.buf[0..out_len];
    }
};

const ReverseBitWriter = struct {
    buf: []u8,
    pos: usize,
    acc: u64,
    count: u6,

    fn init(buf: []u8) ReverseBitWriter {
        return .{ .buf = buf, .pos = 0, .acc = 0, .count = 0 };
    }

    fn writeBits(self: *ReverseBitWriter, value: u64, count: u5) error{OutOfSpace}!void {
        if (count == 0) return;
        self.acc |= (value & ((@as(u64, 1) << @intCast(count)) - 1)) << @intCast(self.count);
        self.count += count;
        // Flush whole bytes; the 8-byte store batch-flushes when space allows.
        if (self.count >= 8 and self.pos + 8 <= self.buf.len) {
            std.mem.writeInt(u64, self.buf[self.pos..][0..8], self.acc, .little);
            const full: u6 = self.count >> 3;
            self.pos += full;
            self.acc >>= @intCast(full * 8);
            self.count &= 7;
            return;
        }
        while (self.count >= 8) {
            if (self.pos >= self.buf.len) return error.OutOfSpace;
            self.buf[self.pos] = @intCast(self.acc & 0xFF);
            self.pos += 1;
            self.acc >>= 8;
            self.count -= 8;
        }
    }

    fn finish(self: *ReverseBitWriter) error{OutOfSpace}![]u8 {
        // Append the marker bit to the partial byte.
        if (self.count > 0) {
            if (self.pos >= self.buf.len) return error.OutOfSpace;
            self.buf[self.pos] = @intCast((self.acc & ((@as(u64, 1) << @intCast(self.count)) - 1)) | (@as(u64, 1) << @intCast(self.count)));
            self.pos += 1;
            self.count = 0;
        } else {
            if (self.pos >= self.buf.len) return error.OutOfSpace;
            self.buf[self.pos] = 0x01;
            self.pos += 1;
        }
        return self.buf[0..self.pos];
    }

    fn finishRaw(self: *ReverseBitWriter) error{OutOfSpace}![]u8 {
        if (self.count > 0) {
            if (self.pos >= self.buf.len) return error.OutOfSpace;
            self.buf[self.pos] = @intCast(self.acc & ((@as(u64, 1) << @intCast(self.count)) - 1));
            self.pos += 1;
            self.count = 0;
        }
        return self.buf[0..self.pos];
    }
};

pub fn scanContentSize(input: *std.Io.Reader, max_window: u32) DecodeError!usize {
    if (max_window < window_size_min or max_window > window_size_max) return error.Unsupported;
    var total: u64 = 0;
    while (true) {
        const magic = readU32le(input) catch |err| switch (err) {
            error.EndOfStream => break,
            error.ReadFailed => return error.IoFailure,
        };
        if (magic != frame_magic) {
            if (magic >= skippable_magic_min and magic <= skippable_magic_max) {
                const size = readU32le(input) catch |err| switch (err) {
                    error.EndOfStream => return error.InvalidData,
                    error.ReadFailed => return error.IoFailure,
                };
                try skipBytes(input, size);
                continue;
            }
            return error.InvalidData;
        }
        const header = try decodeFrameHeader(input, max_window);
        if (!header.has_content_size) return error.Unsupported;
        total = std.math.add(u64, total, header.content_size) catch return error.ResourceLimit;
        // Skip blocks until last block.
        while (true) {
            const block_header = try readBlockHeader(input);
            if (block_header.size > block_size_max) return error.Unsupported;
            switch (block_header.type) {
                .raw, .compressed => try skipBytes(input, block_header.size),
                .rle => try skipBytes(input, 1),
                .reserved => return error.InvalidData,
            }
            if (block_header.last) break;
        }
        if (header.has_checksum) {
            try skipBytes(input, 4);
        }
    }
    return std.math.cast(usize, total) orelse error.ResourceLimit;
}

// Backward bit reader for the zstd literal and sequence streams: bits are
// consumed most-significant-first from a 64-bit container loaded one
// little-endian word at a time from the tail of the stream toward the head.
// `pos` is the stream index the container was (conceptually) loaded at, so
// the number of unread bits is always 8 * pos + valid().
const BackwardBitStream = struct {
    bytes: []const u8,
    pos: usize,
    container: u64,
    consumed: u8,
    tail_pad: u8, // non-stream zero bits at the container bottom (short streams)

    fn init(bytes: []const u8) DecodeError!BackwardBitStream {
        var self: BackwardBitStream = .{ .bytes = bytes, .pos = 0, .container = 0, .consumed = 64, .tail_pad = 0 };
        if (bytes.len == 0) return self;
        const last = bytes[bytes.len - 1];
        if (last == 0) return error.InvalidData;
        const highbit = std.math.log2_int(u8, last);
        // Skip the end-marker bit and the padding above it.
        if (bytes.len >= 8) {
            self.container = std.mem.readInt(u64, bytes[bytes.len - 8 ..][0..8], .little);
            self.pos = bytes.len - 8;
            self.consumed = 8 - @as(u8, highbit);
        } else {
            var i: usize = 0;
            while (i < bytes.len) : (i += 1) {
                self.container |= @as(u64, bytes[bytes.len - 1 - i]) << @intCast(56 - 8 * i);
            }
            self.tail_pad = @intCast(8 * (8 - bytes.len));
            self.consumed = 8 - @as(u8, highbit);
        }
        return self;
    }

    inline fn valid(self: *const BackwardBitStream) u8 {
        return 64 - self.consumed - self.tail_pad;
    }

    inline fn remaining(self: *const BackwardBitStream) usize {
        return 8 * self.pos + self.valid();
    }

    inline fn refill(self: *BackwardBitStream) void {
        const byte_shift = self.consumed >> 3;
        if (byte_shift == 0) return;
        if (byte_shift <= self.pos) {
            self.pos -= byte_shift;
            self.consumed &= 7;
            self.container = std.mem.readInt(u64, self.bytes[self.pos..][0..8], .little);
        } else if (self.pos != 0) {
            // Fewer than byte_shift whole bytes remain unread; reload at the
            // stream head and keep the same bits consumed overall.
            self.consumed -= @intCast(8 * self.pos);
            self.pos = 0;
            self.container = std.mem.readInt(u64, self.bytes[0..8], .little);
        }
    }

    inline fn peek(self: *const BackwardBitStream, count: u6) u64 {
        if (count == 0) return 0;
        return (self.container << @as(u6, @intCast(self.consumed))) >> @as(u6, @intCast(63 - (count - 1)));
    }

    inline fn skip(self: *BackwardBitStream, count: u8) void {
        self.consumed += count;
    }

    inline fn read(self: *BackwardBitStream, count: u6) DecodeError!u64 {
        if (count == 0) return 0;
        self.refill();
        if (self.remaining() < count) return error.InvalidData;
        const value = self.peek(count);
        self.skip(count);
        return value;
    }
};

const Decoder = struct {
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    history: []u8,
    window_size: u32,
    max_decoded: u64,
    history_end: usize,
    output_base: usize,
    frame_output: u64,
    total_output: u64,
    content_size: ?u64,
    has_checksum: bool,
    in_place: bool,
    checksummer: checksum.XxHash64,
    block_buffer: [block_size_max]u8,
    literal_state: FseState,
    match_state: FseState,
    offset_state: FseState,
    prev_literal_state: FseState,
    prev_match_state: FseState,
    prev_offset_state: FseState,
    prev_tables_valid: bool,
    repeat_offsets: [3]u32,
    huffman_tree: ?HuffmanTree,
    lit_window: u64,
    lit_window_bits: u6,
    lit_stream_bytes: []const u8,
    lit_stream_remaining: usize,
    lit_stream_count: usize,
    literal_stream_index: usize,
    dictionary: ?[]const u8,

    fn decodeFrameBody(d: *Decoder) DecodeError!void {
        const header = try decodeFrameHeader(d.input, d.window_size);
        if (header.has_content_size and header.content_size > d.max_decoded) return error.ResourceLimit;
        d.content_size = if (header.has_content_size) header.content_size else null;
        d.has_checksum = header.has_checksum;
        d.checksummer = checksum.XxHash64.init(0);
        d.frame_output = 0;
        if (d.dictionary) |dictionary| {
            try d.loadDictionary(dictionary, header.dictionary_id);
        } else {
            if (header.dictionary_id != 0) return error.Unsupported;
            d.repeat_offsets = .{
                start_repeated_offset_1,
                start_repeated_offset_2,
                start_repeated_offset_3,
            };
            d.huffman_tree = null;
            d.prev_tables_valid = false;
        }
        var block_index: usize = 0;
        while (true) : (block_index += 1) {
            if (d.history_end + block_size_max > d.history.len) {
                try d.slideHistory();
            }
            const block_header = try readBlockHeader(d.input);
            if (block_header.size > block_size_max) return error.Unsupported;
            const block_output_before = d.history_end;
            switch (block_header.type) {
                .raw => try d.decodeRawBlock(block_header.size),
                .rle => try d.decodeRleBlock(block_header.size),
                .compressed => try d.decodeCompressedBlock(block_header.size),
                .reserved => return error.InvalidData,
            }
            const block_output_after = d.history_end;
            const block_produced = block_output_after - block_output_before;
            d.checksummer.update(d.history[block_output_before..block_output_after]);
            d.frame_output = std.math.add(u64, d.frame_output, block_produced) catch return error.ResourceLimit;
            if (d.content_size) |cs| {
                if (d.frame_output > cs) return error.InvalidData;
            }
            if (d.frame_output > d.max_decoded) return error.ResourceLimit;
            if (block_header.last) break;
        }
        if (d.content_size) |cs| {
            if (d.frame_output != cs) return error.InvalidData;
        }
        if (d.has_checksum) {
            const stored = try d.readU32le();
            const actual: u32 = @truncate(d.checksummer.final());
            if (stored != actual) return error.IntegrityFailure;
        }
        d.total_output = std.math.add(u64, d.total_output, d.frame_output) catch return error.ResourceLimit;
        try d.flushHistory();
    }

    fn loadDictionary(d: *Decoder, dictionary: []const u8, expected_id: u32) DecodeError!void {
        if (dictionary.len < 8) return error.InvalidData;
        const magic = std.mem.readInt(u32, dictionary[0..4], .little);
        if (magic != dictionary_magic) {
            if (expected_id != 0) return error.InvalidData;
            if (dictionary.len > d.history.len) return error.ResourceLimit;
            @memcpy(d.history[0..dictionary.len], dictionary);
            d.history_end = dictionary.len;
            d.output_base = dictionary.len;
            d.repeat_offsets = .{
                start_repeated_offset_1,
                start_repeated_offset_2,
                start_repeated_offset_3,
            };
            d.huffman_tree = null;
            d.prev_tables_valid = false;
            return;
        }
        const dictionary_id = std.mem.readInt(u32, dictionary[4..8], .little);
        if (dictionary_id == 0) return error.InvalidData;
        if (expected_id != 0 and dictionary_id != expected_id) return error.InvalidData;
        var cursor = binary.ReadCursor.init(dictionary[8..]);
        d.huffman_tree = .{};
        try decodeHuffmanTree(&cursor, &d.huffman_tree.?);
        {
            const decoded = try decodeFseTable(cursor.remainingSlice(), 32, 8, &d.offset_state.entries);
            cursor.pos += decoded.consumed;
            d.offset_state.accuracy_log = @intCast(std.math.log2_int(usize, decoded.table_size));
            d.offset_state.table = .{ .fse = d.offset_state.entries[0..decoded.table_size] };
        }
        {
            const decoded = try decodeFseTable(cursor.remainingSlice(), 53, 9, &d.match_state.entries);
            cursor.pos += decoded.consumed;
            d.match_state.accuracy_log = @intCast(std.math.log2_int(usize, decoded.table_size));
            d.match_state.table = .{ .fse = d.match_state.entries[0..decoded.table_size] };
        }
        {
            const decoded = try decodeFseTable(cursor.remainingSlice(), 36, 9, &d.literal_state.entries);
            cursor.pos += decoded.consumed;
            d.literal_state.accuracy_log = @intCast(std.math.log2_int(usize, decoded.table_size));
            d.literal_state.table = .{ .fse = d.literal_state.entries[0..decoded.table_size] };
        }
        const recent_offset_1 = try cursor.readU32le();
        const recent_offset_2 = try cursor.readU32le();
        const recent_offset_3 = try cursor.readU32le();
        const content = cursor.remainingSlice();
        if (content.len > d.history.len) return error.ResourceLimit;
        if (recent_offset_1 == 0 or recent_offset_2 == 0 or recent_offset_3 == 0) return error.InvalidData;
        if (recent_offset_1 > content.len or recent_offset_2 > content.len or recent_offset_3 > content.len) return error.InvalidData;
        @memcpy(d.history[0..content.len], content);
        d.history_end = content.len;
        d.output_base = content.len;
        d.repeat_offsets = .{ recent_offset_1, recent_offset_2, recent_offset_3 };
        d.savePrevTables();
    }

    fn decodeRawBlock(d: *Decoder, size: usize) DecodeError!void {
        if (d.history_end + size > d.history.len) return error.ResourceLimit;
        var target = std.Io.Writer.fixed(d.history[d.history_end..][0..size]);
        try streamExact(d.input, &target, size);
        d.history_end += size;
    }

    fn decodeRleBlock(d: *Decoder, size: usize) DecodeError!void {
        if (size == 0) return;
        if (d.history_end + size > d.history.len) return error.ResourceLimit;
        const byte = try d.readU8();
        @memset(d.history[d.history_end..][0..size], byte);
        d.history_end += size;
    }

    fn decodeCompressedBlock(d: *Decoder, block_size: usize) DecodeError!void {
        if (block_size > d.block_buffer.len) return error.Unsupported;
        var target = std.Io.Writer.fixed(d.block_buffer[0..block_size]);
        try streamExact(d.input, &target, block_size);
        var cursor = ReadCursor.init(d.block_buffer[0..block_size]);
        const literals = try decodeLiteralsSection(&cursor, d);
        // Literal and sequence bit reader state lives in locals so the hot
        // loops keep it in registers; the decoder fields take over only on
        // the non-canonical stream-split fallback.
        var lit_bits: BackwardBitStream = undefined;
        var lit_stream_index: usize = 0;
        var lit_legacy = false;
        // Raw and RLE literals carry no bitstream; only compressed streams are bit-packed.
        if (literals.block_type == .compressed or literals.block_type == .treeless) {
            const first = switch (literals.streams) {
                .one => |stream| stream,
                .four => |streams| streams[0],
            };
            if (first.len == 0) return error.InvalidData;
            lit_bits = try BackwardBitStream.init(first);
        }
        const sequences = try decodeSequencesHeader(&cursor);
        // Prepare FSE tables for sequences (forward read).
        try d.prepareFseTable(.literal, sequences.literal_mode, &cursor);
        try d.prepareFseTable(.offset, sequences.offset_mode, &cursor);
        try d.prepareFseTable(.match, sequences.match_mode, &cursor);
        // The sequence bitstream occupies the remainder of the block.
        const sequences_data = d.block_buffer[cursor.pos..block_size];
        var seq_bits = try BackwardBitStream.init(sequences_data);
        var lit_state: u16 = 0;
        var mat_state: u16 = 0;
        var off_state: u16 = 0;
        if (sequences.count > 0) {
            lit_state = @intCast(try seq_bits.read(d.literal_state.accuracy_log));
            off_state = @intCast(try seq_bits.read(d.offset_state.accuracy_log));
            mat_state = @intCast(try seq_bits.read(d.match_state.accuracy_log));
        }

        var lit_rle: [1]FseEntry = undefined;
        var mat_rle: [1]FseEntry = undefined;
        var off_rle: [1]FseEntry = undefined;
        const lit_table = fseTableOrRle(&d.literal_state, &lit_rle);
        const mat_table = fseTableOrRle(&d.match_state, &mat_rle);
        const off_table = fseTableOrRle(&d.offset_state, &off_rle);

        var reps = d.repeat_offsets;
        var literal_written: usize = 0;
        var decoded_count: usize = 0;
        const output_limit = d.history.len - d.history_end;
        if (output_limit < block_size_max) return error.ResourceLimit;
        for (0..sequences.count) |seq_index| {
            const last_sequence = seq_index == sequences.count - 1;

            // Decode the three sequence symbols from the current FSE states.
            const off_entry = off_table[off_state];
            const mat_entry = mat_table[mat_state];
            const lit_entry = lit_table[lit_state];

            const off_code = off_entry.symbol;
            const off_extra = @as(u32, @intCast(try seq_bits.read(@intCast(off_code))));
            const offset_value = (@as(u32, 1) << @intCast(off_code)) + off_extra;

            const mat_symbol = mat_entry.symbol;
            if (mat_symbol >= match_length_code_table.len) return error.InvalidData;
            const mat_len_code = match_length_code_table[mat_symbol];
            const mat_extra = @as(u32, @intCast(try seq_bits.read(@intCast(mat_len_code[1]))));
            const match_length = mat_len_code[0] + mat_extra;

            const lit_symbol = lit_entry.symbol;
            if (lit_symbol >= literals_length_code_table.len) return error.InvalidData;
            const lit_len_code = literals_length_code_table[lit_symbol];
            const lit_extra = @as(u32, @intCast(try seq_bits.read(@intCast(lit_len_code[1]))));
            const literal_length = lit_len_code[0] + lit_extra;

            const offset = computeOffsetValue(offset_value, literal_length, &reps);
            if (offset == 0) return error.InvalidData;

            // Copy literals.
            if (literal_length > 0) {
                if (literal_written + literal_length > literals.regenerated_size) return error.InvalidData;
                if (decoded_count + literal_length > block_size_max) return error.InvalidData;
                try d.copyLiteralRun(&literals, &lit_bits, &lit_stream_index, &lit_legacy, d.history[d.history_end + decoded_count ..][0..literal_length], literal_written);
                literal_written += literal_length;
                decoded_count += literal_length;
            }
            // Copy match.
            if (match_length > 0) {
                if (decoded_count + match_length > block_size_max) return error.InvalidData;
                try d.copyMatch(offset, match_length, decoded_count);
                decoded_count += match_length;
            }

            // Advance the three FSE states for the next sequence.
            // Bitstream order is lit transition, then match, then offset.
            if (!last_sequence) {
                const lit_next = @as(u16, @intCast(try seq_bits.read(@intCast(lit_entry.bits))));
                lit_state = lit_entry.baseline + lit_next;

                const mat_next = @as(u16, @intCast(try seq_bits.read(@intCast(mat_entry.bits))));
                mat_state = mat_entry.baseline + mat_next;

                const off_next = @as(u16, @intCast(try seq_bits.read(@intCast(off_entry.bits))));
                off_state = off_entry.baseline + off_next;
            }
        }
        d.literal_state.state = lit_state;
        d.match_state.state = mat_state;
        d.offset_state.state = off_state;
        d.repeat_offsets = reps;
        // Remaining literals after last sequence.
        if (literal_written < literals.regenerated_size) {
            const remaining_literals = literals.regenerated_size - literal_written;
            if (decoded_count + remaining_literals > block_size_max) return error.InvalidData;
            try d.copyLiteralRun(&literals, &lit_bits, &lit_stream_index, &lit_legacy, d.history[d.history_end + decoded_count ..][0..remaining_literals], literal_written);
            decoded_count += remaining_literals;
        }
        // Compressed/treeless literals must consume their bitstreams exactly.
        switch (literals.block_type) {
            .compressed, .treeless => {
                const empty = if (lit_legacy)
                    d.isLiteralStreamEmpty(&literals)
                else
                    lit_bits.remaining() == 0 and lit_stream_index + 1 >= litStreamCount(&literals);
                if (!empty) return error.InvalidData;
            },
            .raw, .rle => {},
        }
        if (seq_bits.remaining() != 0) return error.InvalidData;
        if (decoded_count > block_size_max) return error.InvalidData;
        d.savePrevTables();
        d.history_end += decoded_count;
    }

    inline fn copyLiteralRun(
        d: *Decoder,
        literals: *const LiteralsSection,
        bits: *BackwardBitStream,
        stream_index: *usize,
        legacy: *bool,
        dest: []u8,
        start: usize,
    ) DecodeError!void {
        switch (literals.block_type) {
            .raw => {
                const data = literals.streams.one[start..][0..dest.len];
                if (comptime vector_match_copy) {
                    if (dest.len > 512) @memcpy(dest, data) else copyShort16(dest, data);
                } else {
                    @memcpy(dest, data);
                }
            },
            .rle => {
                const byte = literals.streams.one[0];
                if (comptime vector_match_copy) {
                    if (dest.len >= 16) {
                        const v: @Vector(16, u8) = @splat(byte);
                        var i: usize = 0;
                        while (i + 16 <= dest.len) : (i += 16) {
                            dest[i..][0..16].* = v;
                        }
                        if (i < dest.len) dest[dest.len - 16 ..][0..16].* = v;
                    } else {
                        for (dest) |*out| out.* = byte;
                    }
                } else {
                    @memset(dest, byte);
                }
            },
            .compressed, .treeless => {
                if (legacy.*) {
                    try d.decodeLiterals(literals, dest, dest.len, start);
                    return;
                }
                const tree = &d.huffman_tree.?;
                const max_bits = tree.max_bits;
                var emitted: usize = 0;
                while (emitted < dest.len) {
                    if (bits.valid() < 11) {
                        bits.refill();
                        // Advance to the next stream only once the current one
                        // is consumed exactly; a handful of leftover bits is
                        // the normal tail of a stream and still decodes.
                        while (bits.pos == 0 and bits.valid() == 0) {
                            switch (literals.streams) {
                                .one => break,
                                .four => |streams| {
                                    if (stream_index.* + 1 >= streams.len) break;
                                    stream_index.* += 1;
                                    const next = streams[stream_index.*];
                                    if (next.len == 0) return error.InvalidData;
                                    bits.* = try BackwardBitStream.init(next);
                                },
                            }
                        }
                    }
                    const avail: u4 = @intCast(@min(bits.valid(), max_bits));
                    if (avail == 0) return error.InvalidData;
                    const index: u16 = @intCast(bits.peek(avail));
                    const entry = tree.lookup2[index << @intCast(max_bits - avail)];
                    const len1: u8 = @intCast((entry >> 16) & 0x1F);
                    const len2: u8 = @intCast((entry >> 21) & 0x1F);
                    if (len1 == 0) return error.InvalidData;
                    if (len1 > avail) {
                        // The next symbol does not fit in the current stream's
                        // remaining bits: a split the merged-window decoder
                        // handles; continue there for exact behavior.
                        if (literals.streams == .four and stream_index.* + 1 < literals.streams.four.len) {
                            d.lit_window = bits.container << @as(u6, @intCast(bits.consumed));
                            d.lit_window_bits = @intCast(bits.valid());
                            d.lit_stream_bytes = literals.streams.four[stream_index.*];
                            d.lit_stream_remaining = 0;
                            d.literal_stream_index = stream_index.*;
                            d.lit_stream_count = literals.streams.four.len;
                            legacy.* = true;
                            try d.decodeLiterals(literals, dest[emitted..], dest.len - emitted, 0);
                            return;
                        }
                        return error.InvalidData;
                    }
                    if (len2 != 0 and len1 + len2 <= avail and emitted + 2 <= dest.len) {
                        dest[emitted] = @truncate(entry);
                        dest[emitted + 1] = @truncate(entry >> 8);
                        bits.skip(len1 + len2);
                        emitted += 2;
                    } else {
                        dest[emitted] = @truncate(entry);
                        bits.skip(len1);
                        emitted += 1;
                    }
                }
            },
        }
    }

    inline fn copyMatch(d: *Decoder, offset: u32, length: usize, decoded_already: usize) DecodeError!void {
        if (offset == 0) return error.InvalidData;
        const write_base = d.history_end + decoded_already;
        if (offset > write_base) return error.InvalidData;
        const src = write_base - offset;
        const history = d.history;
        if (comptime vector_match_copy) {
            if (offset >= length) {
                if (length > 512) {
                    @memcpy(history[write_base..][0..length], history[src..][0..length]);
                } else {
                    copyShort16(history[write_base..][0..length], history[src..][0..length]);
                }
            } else if (offset >= 16) {
                // Chunks read only finalized bytes; the last chunk overlaps.
                var i: usize = 0;
                while (i + 16 <= length) : (i += 16) {
                    history[write_base + i ..][0..16].* = history[src + i ..][0..16].*;
                }
                if (i < length) {
                    history[write_base + length - 16 ..][0..16].* = history[src + length - 16 ..][0..16].*;
                }
            } else if (offset >= 8) {
                var i: usize = 0;
                while (i + 8 <= length) : (i += 8) {
                    history[write_base + i ..][0..8].* = history[src + i ..][0..8].*;
                }
                if (i < length) {
                    history[write_base + length - 8 ..][0..8].* = history[src + length - 8 ..][0..8].*;
                }
            } else if (offset == 1) {
                if (length >= 16) {
                    const v: @Vector(16, u8) = @splat(history[src]);
                    var i: usize = 0;
                    while (i + 16 <= length) : (i += 16) {
                        history[write_base + i ..][0..16].* = v;
                    }
                    if (i < length) history[write_base + length - 16 ..][0..16].* = v;
                } else {
                    @memset(history[write_base..][0..length], history[src]);
                }
            } else {
                copyMatchPeriodWiden(history, write_base, offset, length);
            }
        } else if (offset == 1) {
            @memset(history[write_base..][0..length], history[src]);
        } else if (offset >= length) {
            @memcpy(history[write_base..][0..length], history[src..][0..length]);
        } else {
            copyMatchOverlap(history, src, write_base, offset, length);
        }
    }

    fn fseState(d: *Decoder, choice: FseChoice) *FseState {
        return switch (choice) {
            .literal => &d.literal_state,
            .match => &d.match_state,
            .offset => &d.offset_state,
        };
    }

    fn savePrevTables(d: *Decoder) void {
        d.prev_literal_state.entries = d.literal_state.entries;
        d.prev_literal_state.accuracy_log = d.literal_state.accuracy_log;
        d.prev_literal_state.table = switch (d.literal_state.table) {
            .fse => |slice| .{ .fse = d.prev_literal_state.entries[0..slice.len] },
            .rle => |value| .{ .rle = value },
        };
        d.prev_match_state.entries = d.match_state.entries;
        d.prev_match_state.accuracy_log = d.match_state.accuracy_log;
        d.prev_match_state.table = switch (d.match_state.table) {
            .fse => |slice| .{ .fse = d.prev_match_state.entries[0..slice.len] },
            .rle => |value| .{ .rle = value },
        };
        d.prev_offset_state.entries = d.offset_state.entries;
        d.prev_offset_state.accuracy_log = d.offset_state.accuracy_log;
        d.prev_offset_state.table = switch (d.offset_state.table) {
            .fse => |slice| .{ .fse = d.prev_offset_state.entries[0..slice.len] },
            .rle => |value| .{ .rle = value },
        };
        d.prev_tables_valid = true;
    }

    fn applyRepeatTable(d: *Decoder, choice: FseChoice) void {
        const state = d.fseState(choice);
        const prev = switch (choice) {
            .literal => &d.prev_literal_state,
            .match => &d.prev_match_state,
            .offset => &d.prev_offset_state,
        };
        state.entries = prev.entries;
        state.accuracy_log = prev.accuracy_log;
        state.table = switch (prev.table) {
            .fse => |slice| .{ .fse = state.entries[0..slice.len] },
            .rle => |value| .{ .rle = value },
        };
    }

    fn prepareFseTable(d: *Decoder, choice: FseChoice, mode: SequenceMode, cursor: *ReadCursor) DecodeError!void {
        const state = d.fseState(choice);
        switch (mode) {
            .predefined => {
                const probs = switch (choice) {
                    .literal => &default_literal_probs,
                    .match => &default_match_probs,
                    .offset => &default_offset_probs,
                };
                const accuracy_log: u4 = switch (choice) {
                    .literal => 6,
                    .match => 6,
                    .offset => 5,
                };
                const table_size = @as(usize, 1) << accuracy_log;
                buildFseTable(probs, state.entries[0..table_size]) catch return error.InvalidData;
                state.table = .{ .fse = state.entries[0..table_size] };
                state.accuracy_log = accuracy_log;
            },
            .rle => {
                state.accuracy_log = 0;
                state.table = .{ .rle = try cursor.readU8() };
            },
            .fse => {
                const max_symbol_count: usize = switch (choice) {
                    .literal => 36,
                    .match => 53,
                    .offset => 32,
                };
                const max_log: u4 = switch (choice) {
                    .literal => 9,
                    .match => 9,
                    .offset => 8,
                };
                const decoded = decodeFseTable(cursor.remainingSlice(), max_symbol_count, max_log, &state.entries) catch return error.InvalidData;
                cursor.pos += decoded.consumed;
                state.table = .{ .fse = state.entries[0..decoded.table_size] };
                state.accuracy_log = @intCast(std.math.log2_int(usize, decoded.table_size));
            },
            .repeat => {
                if (!d.prev_tables_valid) return error.InvalidData;
                d.applyRepeatTable(choice);
            },
        }
    }

    inline fn decodeLiterals(d: *Decoder, literals: *const LiteralsSection, dest: []u8, length: usize, start: usize) DecodeError!void {
        switch (literals.block_type) {
            .raw => {
                const data = literals.streams.one[start..][0..length];
                @memcpy(dest[0..length], data);
            },
            .rle => {
                const byte = literals.streams.one[0];
                @memset(dest[0..length], byte);
            },
            .compressed, .treeless => {
                const tree = &d.huffman_tree.?;
                var emitted: usize = 0;
                while (emitted < length) {
                    try d.litRefill(literals);
                    const max_bits = tree.max_bits;
                    const available: u4 = @intCast(@min(d.lit_window_bits, max_bits));
                    if (available == 0) return error.InvalidData;
                    const index: u16 = @intCast(d.lit_window >> @intCast(@as(u7, 64) - available));
                    const index_aligned = index << @intCast(max_bits - available);
                    const entry = tree.lookup[index_aligned];
                    const bits: u4 = @intCast(entry >> 8);
                    if (bits == 0 or bits > d.lit_window_bits) return error.InvalidData;
                    d.litConsume(bits);
                    dest[emitted] = @intCast(entry & 0xFF);
                    emitted += 1;
                }
            },
        }
    }

    fn litInitStream(d: *Decoder, stream: []const u8) DecodeError!void {
        if (stream.len == 0) return error.InvalidData;
        const last = stream[stream.len - 1];
        if (last == 0) return error.InvalidData;
        const highbit = std.math.log2_int(u8, last);
        const k: u6 = @intCast(highbit);
        const new_bits: u64 = last & ((@as(u64, 1) << k) - 1);
        if (k != 0) d.lit_window |= new_bits << @intCast(@as(u7, 64) - d.lit_window_bits - k);
        d.lit_window_bits += k;
        d.lit_stream_bytes = stream;
        d.lit_stream_remaining = stream.len - 1;
    }

    inline fn litRefill(d: *Decoder, literals: *const LiteralsSection) DecodeError!void {
        while (d.lit_window_bits < 11) {
            if (d.lit_stream_remaining > 0) {
                d.lit_stream_remaining -= 1;
                const byte = d.lit_stream_bytes[d.lit_stream_remaining];
                d.lit_window |= @as(u64, byte) << @intCast(@as(u7, 64) - d.lit_window_bits - 8);
                d.lit_window_bits += 8;
            } else if (literals.streams == .four and d.literal_stream_index + 1 < d.lit_stream_count) {
                d.literal_stream_index += 1;
                try d.litInitStream(literals.streams.four[d.literal_stream_index]);
            } else {
                return;
            }
        }
    }

    inline fn litConsume(d: *Decoder, count: u4) void {
        d.lit_window <<= count;
        d.lit_window_bits -= count;
    }

    fn isLiteralStreamEmpty(d: *Decoder, literals: *const LiteralsSection) bool {
        const last_stream = literals.streams == .one or d.literal_stream_index + 1 >= d.lit_stream_count;
        return d.lit_window_bits == 0 and d.lit_stream_remaining == 0 and last_stream;
    }

    fn slideHistory(d: *Decoder) DecodeError!void {
        if (d.in_place) return;
        const keep = @min(d.history_end, d.window_size);
        const flush = d.history_end - keep;
        if (flush > 0) {
            if (flush > d.output_base) {
                d.output.writeAll(d.history[d.output_base..flush]) catch return error.IoFailure;
            }
            @memmove(d.history[0..keep], d.history[flush..d.history_end]);
            d.history_end = keep;
            d.output_base = if (flush >= d.output_base) 0 else d.output_base - flush;
        }
    }

    fn flushHistory(d: *Decoder) DecodeError!void {
        if (d.in_place) return;
        if (d.history_end > d.output_base) {
            d.output.writeAll(d.history[d.output_base..d.history_end]) catch return error.IoFailure;
        }
        d.history_end = 0;
        d.output_base = 0;
    }

    fn readU8(d: *Decoder) DecodeError!u8 {
        return d.input.takeByte() catch |err| switch (err) {
            error.EndOfStream => error.InvalidData,
            error.ReadFailed => error.IoFailure,
        };
    }

    fn readU32le(d: *Decoder) DecodeError!u32 {
        var bytes: [4]u8 = undefined;
        var target = std.Io.Writer.fixed(&bytes);
        try streamExact(d.input, &target, 4);
        return std.mem.readInt(u32, &bytes, .little);
    }
};

fn readU32le(reader: *std.Io.Reader) error{ EndOfStream, ReadFailed }!u32 {
    var bytes: [4]u8 = undefined;
    var target = std.Io.Writer.fixed(&bytes);
    reader.streamExact(&target, 4) catch |err| switch (err) {
        error.EndOfStream => return error.EndOfStream,
        error.ReadFailed => return error.ReadFailed,
        error.WriteFailed => return error.ReadFailed,
    };
    return std.mem.readInt(u32, &bytes, .little);
}

fn computeOffsetValue(offset_value: u32, literal_length: u32, reps: *[3]u32) u32 {
    if (offset_value > 3) {
        const offset = offset_value - 3;
        reps[2] = reps[1];
        reps[1] = reps[0];
        reps[0] = offset;
        return offset;
    }
    if (literal_length == 0) {
        if (offset_value == 3) {
            const offset = reps[0] - 1;
            reps[2] = reps[1];
            reps[1] = reps[0];
            reps[0] = offset;
            return offset;
        }
        return useRepeatOffsetValue(offset_value, reps);
    }
    return useRepeatOffsetValue(offset_value - 1, reps);
}

fn useRepeatOffsetValue(index: usize, reps: *[3]u32) u32 {
    if (index == 1) std.mem.swap(u32, &reps[0], &reps[1]);
    if (index == 2) {
        std.mem.swap(u32, &reps[0], &reps[2]);
        std.mem.swap(u32, &reps[1], &reps[2]);
    }
    return reps[0];
}

fn copyMatchOverlap(history: []u8, src: usize, dst: usize, offset: usize, length: usize) void {
    var i: usize = 0;
    const first = @min(offset, length);
    while (i + 8 <= first) : (i += 8) {
        const word = std.mem.readInt(u64, history[src + i ..][0..8], .little);
        std.mem.writeInt(u64, history[dst + i ..][0..8], word, .little);
    }
    while (i < first) : (i += 1) history[dst + i] = history[src + i];

    var copied = first;
    while (copied < length) {
        const take = @min(copied, length - copied);
        const chunk_src = dst;
        const chunk_dst = dst + copied;
        var j: usize = 0;
        while (j + 8 <= take) : (j += 8) {
            const word = std.mem.readInt(u64, history[chunk_src + j ..][0..8], .little);
            std.mem.writeInt(u64, history[chunk_dst + j ..][0..8], word, .little);
        }
        while (j < take) : (j += 1) history[chunk_dst + j] = history[chunk_src + j];
        copied += take;
    }
}

// Exact short copies that never call into the platform library: small
// per-sequence copies dominate the sequence loop.
inline fn copyShort16(dst: []u8, src: []const u8) void {
    const length = dst.len;
    if (length >= 16) {
        var i: usize = 0;
        while (i + 16 <= length) : (i += 16) {
            dst[i..][0..16].* = src[i..][0..16].*;
        }
        if (i < length) {
            dst[length - 16 ..][0..16].* = src[length - 16 ..][0..16].*;
        }
    } else if (length >= 8) {
        dst[0..8].* = src[0..8].*;
        dst[length - 8 ..][0..8].* = src[length - 8 ..][0..8].*;
    } else if (length >= 4) {
        dst[0..4].* = src[0..4].*;
        dst[length - 4 ..][0..4].* = src[length - 4 ..][0..4].*;
    } else {
        for (dst, src) |*dst_byte, src_byte| dst_byte.* = src_byte;
    }
}

// Small-offset overlap copy: byte-widen the period to a multiple of offset
// that is at least one word wide, then finish with word-at-a-time copies
// that read only finalized bytes.
fn copyMatchPeriodWiden(history: []u8, dst: usize, offset: usize, length: usize) void {
    var done: usize = 0;
    var period: usize = offset;
    while (period < 8 and done < length) {
        const take = @min(period, length - done);
        var j: usize = 0;
        while (j < take) : (j += 1) history[dst + done + j] = history[dst + done + j - period];
        done += take;
        period += take;
    }
    var i: usize = done;
    while (i + 8 <= length) : (i += 8) {
        const word = std.mem.readInt(u64, history[dst + i - period ..][0..8], .little);
        std.mem.writeInt(u64, history[dst + i ..][0..8], word, .little);
    }
    while (i < length) : (i += 1) history[dst + i] = history[dst + i - period];
}

fn litStreamCount(literals: *const LiteralsSection) usize {
    return switch (literals.streams) {
        .one => 1,
        .four => 4,
    };
}

const FseChoice = enum { literal, match, offset };

const FseEntry = struct {
    symbol: u8,
    baseline: u16,
    bits: u8,
};

const FseTable = union(enum) {
    fse: []const FseEntry,
    rle: u8,
};

const FseState = struct {
    state: u16,
    table: FseTable,
    accuracy_log: u4,
    entries: [1 << 9]FseEntry,
};

fn fseTableOrRle(state: *const FseState, storage: *[1]FseEntry) []const FseEntry {
    return switch (state.table) {
        .fse => |t| t,
        .rle => |s| {
            storage[0] = .{ .symbol = s, .bits = 0, .baseline = 0 };
            return storage[0..1];
        },
    };
}

const SequenceMode = enum(u2) {
    predefined,
    rle,
    fse,
    repeat,
};

const BlockType = enum(u2) {
    raw,
    rle,
    compressed,
    reserved,
};

const BlockHeader = struct {
    last: bool,
    type: BlockType,
    size: usize,
};

const FrameHeader = struct {
    has_content_size: bool,
    content_size: u64,
    has_checksum: bool,
    dictionary_id: u32,
    window_size: u64,
};

const LiteralsSection = struct {
    block_type: LiteralsBlockType,
    regenerated_size: usize,
    streams: LiteralsStreams,
};

const LiteralsBlockType = enum(u2) {
    raw,
    rle,
    compressed,
    treeless,
};

const LiteralsStreams = union(enum) {
    one: []const u8,
    four: [4][]const u8,
};

const SequencesHeader = struct {
    count: usize,
    literal_mode: SequenceMode,
    offset_mode: SequenceMode,
    match_mode: SequenceMode,
};

const HuffmanTree = struct {
    max_bits: u4 = 0,
    symbol_count: u16 = 0,
    nodes: [256]PrefixedSymbol = undefined,
    lookup: [2048]u16 = @splat(0xFFFF),
    // Two-symbol decode table: [7:0] first symbol, [15:8] second symbol,
    // [20:16] first code length, [26:21] second code length (0 = single).
    lookup2: [2048]u32 = @splat(0),
};

const PrefixedSymbol = struct {
    symbol: u8,
    prefix: u16,
    weight: u4,
};

const ReverseBitReader = struct {
    bytes: []const u8,
    remaining: usize,
    bits: u8,
    count: u4,

    fn init(bytes: []const u8) DecodeError!ReverseBitReader {
        var self: ReverseBitReader = .{
            .bytes = bytes,
            .remaining = bytes.len,
            .bits = 0,
            .count = 0,
        };
        if (bytes.len == 0) return self;
        while (self.remaining > 0 or self.count > 0) {
            const bit = self.readBitsAny(u1, 1) catch return error.InvalidData;
            if (bit.count == 0) return error.InvalidData;
            if (bit.value != 0) {
                return self;
            }
        }
        return error.InvalidData;
    }

    fn readBitsNoEof(self: *ReverseBitReader, comptime T: type, num: u16) DecodeError!T {
        const result = try self.readBitsAny(T, num);
        if (result.count < num) return error.InvalidData;
        return result.value;
    }

    fn readBitsAny(self: *ReverseBitReader, comptime T: type, num: u16) DecodeError!struct { value: T, count: u16 } {
        const UT = std.meta.Int(.unsigned, @bitSizeOf(T));
        const U = if (@bitSizeOf(T) < 8) u8 else UT;
        if (num <= self.count) {
            return .{
                .value = @intCast(self.removeBits(@intCast(num))),
                .count = num,
            };
        }
        var out_count: u16 = self.count;
        var out: U = self.removeBits(self.count);
        const full_bytes = (num - out_count) / 8;
        for (0..full_bytes) |_| {
            const byte = takeByte(self) catch return .{ .value = @intCast(out), .count = out_count };
            if (U != u8) out <<= 8;
            out |= byte;
            out_count += 8;
        }
        const bits_left: u16 = num - out_count;
        if (bits_left == 0) return .{ .value = @intCast(out), .count = num };
        const final_byte = takeByte(self) catch return .{ .value = @intCast(out), .count = out_count };
        const keep: u4 = @intCast(8 - bits_left);
        out = (out << @intCast(bits_left)) | (final_byte >> @intCast(keep));
        self.bits = final_byte & lowBitMask(keep);
        self.count = keep;
        return .{ .value = @intCast(out), .count = num };
    }

    fn takeByte(self: *ReverseBitReader) DecodeError!u8 {
        if (self.remaining == 0) return error.InvalidData;
        self.remaining -= 1;
        return self.bytes[self.remaining];
    }

    fn removeBits(self: *ReverseBitReader, num: u4) u8 {
        if (num == 8) {
            self.count = 0;
            return self.bits;
        }
        const keep = self.count - num;
        const bits = self.bits >> @intCast(keep);
        self.bits &= lowBitMask(keep);
        self.count = keep;
        return bits;
    }

    fn isEmpty(self: *const ReverseBitReader) bool {
        return self.remaining == 0 and self.count == 0;
    }
};

fn lowBitMask(bits: u4) u8 {
    return if (bits == 0) 0 else @as(u8, 0xFF) >> @intCast(8 - bits);
}

fn streamExact(reader: *std.Io.Reader, writer: *std.Io.Writer, count: usize) DecodeError!void {
    reader.streamExact(writer, count) catch |err| switch (err) {
        error.EndOfStream => return error.InvalidData,
        error.WriteFailed => return error.IoFailure,
        error.ReadFailed => return error.IoFailure,
    };
}

fn skipBytes(reader: *std.Io.Reader, count: usize) DecodeError!void {
    var remaining = count;
    while (remaining > 0) {
        const step = @min(remaining, 4096);
        const discarded = reader.discard(.limited(step)) catch |err| switch (err) {
            error.EndOfStream => return error.InvalidData,
            error.ReadFailed => return error.IoFailure,
        };
        remaining -= discarded;
    }
}

fn decodeFrameHeader(input: *std.Io.Reader, window_limit: u32) DecodeError!FrameHeader {
    const descriptor = try readU8(input);
    const dictionary_id_flag: u2 = @intCast(descriptor & 0b11);
    const content_size_flag: u2 = @intCast((descriptor >> 6) & 0b11);
    const single_segment_flag = (descriptor & 0b100000) != 0;
    const reserved_bit = (descriptor & 0b1000) != 0;
    const content_checksum_flag = (descriptor & 0b100) != 0;
    if (reserved_bit) return error.InvalidData;
    const window_descriptor = if (!single_segment_flag) try readU8(input) else 0;
    var window_size = computeWindowSize(window_descriptor);
    const dictionary_id: u32 = if (dictionary_id_flag == 0) 0 else blk: {
        const field_size: u4 = switch (dictionary_id_flag) {
            1 => 1,
            2 => 2,
            3 => 4,
            else => unreachable,
        };
        break :blk std.math.cast(u32, try readVarInt(input, field_size)) orelse return error.ResourceLimit;
    };
    var content_size: u64 = 0;
    var has_content_size = false;
    if (single_segment_flag) {
        const field_size: u4 = @as(u4, 1) << content_size_flag;
        content_size = try readVarInt(input, field_size);
        if (field_size == 2) content_size += 256;
        has_content_size = true;
        window_size = content_size;
    } else if (content_size_flag != 0) {
        const field_size: u4 = @as(u4, 1) << content_size_flag;
        content_size = try readVarInt(input, field_size);
        if (field_size == 2) content_size += 256;
        has_content_size = true;
    }
    if (window_size > window_limit) return error.Unsupported;
    return .{
        .has_content_size = has_content_size,
        .content_size = content_size,
        .has_checksum = content_checksum_flag,
        .dictionary_id = dictionary_id,
        .window_size = window_size,
    };
}

fn computeWindowSize(window_descriptor: u8) u64 {
    const exponent = window_descriptor >> 3;
    const mantissa = window_descriptor & 0b111;
    if (exponent == 0) return 1024;
    const window_log = 10 + exponent;
    const window_base = @as(u64, 1) << @intCast(window_log);
    const window_add = (window_base / 8) * mantissa;
    return window_base + window_add;
}

fn readBlockHeader(input: *std.Io.Reader) DecodeError!BlockHeader {
    var bytes: [3]u8 = undefined;
    var target = std.Io.Writer.fixed(&bytes);
    try streamExact(input, &target, 3);
    const value = @as(u24, bytes[0]) | (@as(u24, bytes[1]) << 8) | (@as(u24, bytes[2]) << 16);
    const last = (value & 1) != 0;
    const block_type: BlockType = @enumFromInt((value >> 1) & 0b11);
    const size = value >> 3;
    return .{ .last = last, .type = block_type, .size = size };
}

fn readU8(input: *std.Io.Reader) DecodeError!u8 {
    return input.takeByte() catch |err| switch (err) {
        error.EndOfStream => error.InvalidData,
        error.ReadFailed => error.IoFailure,
    };
}

fn readVarInt(input: *std.Io.Reader, bytes: u4) DecodeError!u64 {
    var value: u64 = 0;
    var shift: u6 = 0;
    for (0..bytes) |_| {
        const byte = try readU8(input);
        value |= @as(u64, byte) << shift;
        shift += 8;
    }
    return value;
}

fn decodeLiteralsSection(cursor: *ReadCursor, d: *Decoder) DecodeError!LiteralsSection {
    const byte0 = try cursor.readU8();
    const block_type: LiteralsBlockType = @enumFromInt(byte0 & 0b11);
    const size_format: u2 = @intCast((byte0 >> 2) & 0b11);
    var regenerated_size: usize = 0;
    var compressed_size: ?usize = null;
    switch (block_type) {
        .raw, .rle => {
            switch (size_format) {
                0, 2 => regenerated_size = byte0 >> 3,
                1 => {
                    const byte1 = try cursor.readU8();
                    regenerated_size = (byte0 >> 4) + (@as(usize, byte1) << 4);
                },
                3 => {
                    const byte1 = try cursor.readU8();
                    const byte2 = try cursor.readU8();
                    regenerated_size = (byte0 >> 4) + (@as(usize, byte1) << 4) + (@as(usize, byte2) << 12);
                },
            }
        },
        .compressed, .treeless => {
            const byte1 = try cursor.readU8();
            const byte2 = try cursor.readU8();
            switch (size_format) {
                0, 1 => {
                    regenerated_size = (byte0 >> 4) + ((@as(usize, byte1) & 0b00111111) << 4);
                    compressed_size = ((byte1 & 0b11000000) >> 6) + (@as(usize, byte2) << 2);
                },
                2 => {
                    const byte3 = try cursor.readU8();
                    regenerated_size = (byte0 >> 4) + (@as(usize, byte1) << 4) + ((@as(usize, byte2) & 0b00000011) << 12);
                    compressed_size = ((byte2 & 0b11111100) >> 2) + (@as(usize, byte3) << 6);
                },
                3 => {
                    const byte3 = try cursor.readU8();
                    const byte4 = try cursor.readU8();
                    regenerated_size = (byte0 >> 4) + (@as(usize, byte1) << 4) + ((@as(usize, byte2) & 0b00111111) << 12);
                    compressed_size = ((byte2 & 0b11000000) >> 6) + (@as(usize, byte3) << 2) + (@as(usize, byte4) << 10);
                },
            }
        },
    }
    var streams: LiteralsStreams = undefined;
    switch (block_type) {
        .raw => {
            streams = .{ .one = try cursor.readSlice(regenerated_size) };
        },
        .rle => {
            const byte = try cursor.readU8();
            d.block_buffer[0] = byte;
            streams = .{ .one = d.block_buffer[0..1] };
        },
        .compressed, .treeless => {
            if (block_type == .treeless and d.huffman_tree == null) return error.InvalidData;
            const huffman_tree_size = if (block_type == .compressed) b: {
                const before_huffman = cursor.pos;
                if (d.huffman_tree == null) d.huffman_tree = .{};
                try decodeHuffmanTree(cursor, &d.huffman_tree.?);
                break :b cursor.pos - before_huffman;
            } else 0;
            const cs = compressed_size.?;
            if (huffman_tree_size > cs) return error.InvalidData;
            const total_streams_size = cs - huffman_tree_size;
            const stream_data = try cursor.readSlice(total_streams_size);
            streams = try splitLiteralStreams(size_format, stream_data);
        },
    }
    return .{
        .block_type = block_type,
        .regenerated_size = regenerated_size,
        .streams = streams,
    };
}

fn splitLiteralStreams(size_format: u2, data: []const u8) DecodeError!LiteralsStreams {
    if (size_format == 0) return .{ .one = data };
    if (data.len < 6) return error.InvalidData;
    const s1 = std.mem.readInt(u16, data[0..2], .little);
    const s2 = std.mem.readInt(u16, data[2..4], .little);
    const s3 = std.mem.readInt(u16, data[4..6], .little);
    const start1 = 6;
    const start2 = start1 + s1;
    const start3 = start2 + s2;
    const start4 = start3 + s3;
    if (data.len < start4) return error.InvalidData;
    return .{ .four = .{
        data[start1..start2],
        data[start2..start3],
        data[start3..start4],
        data[start4..],
    } };
}

fn decodeHuffmanTree(cursor: *ReadCursor, tree: *HuffmanTree) DecodeError!void {
    const header = try cursor.readU8();
    var weights: [256]u4 = undefined;
    var symbol_count: usize = 0;
    if (header < 128) {
        // FSE-compressed weights.
        const compressed_size = header;
        const compressed = try cursor.readSlice(compressed_size);
        var entries: [1 << 6]FseEntry = undefined;
        const decoded = decodeFseTable(compressed, 256, 6, &entries) catch return error.InvalidData;
        const accuracy_log = std.math.log2_int(usize, decoded.table_size);
        const remaining = compressed[decoded.consumed..];
        symbol_count = assignHuffmanWeights(remaining, accuracy_log, &entries, &weights) catch return error.InvalidData;
    } else {
        // Direct weights: each nibble is a weight.
        const weight_count = header - 127;
        symbol_count = weight_count + 1;
        const byte_count = (weight_count + 1) / 2;
        const bytes = try cursor.readSlice(byte_count);
        var i: usize = 0;
        while (i < byte_count) : (i += 1) {
            weights[2 * i] = @intCast(bytes[i] >> 4);
            if (2 * i + 1 < weight_count) {
                weights[2 * i + 1] = @intCast(bytes[i] & 0xF);
            }
        }
    }
    try buildHuffmanTree(&weights, symbol_count, tree);
}

fn assignHuffmanWeights(
    buffer: []const u8,
    accuracy_log: u16,
    entries: []const FseEntry,
    weights: *[256]u4,
) DecodeError!usize {
    var reader = try ReverseBitReader.init(buffer);
    var i: usize = 0;
    var even_state = try reader.readBitsNoEof(u32, @intCast(accuracy_log));
    var odd_state = try reader.readBitsNoEof(u32, @intCast(accuracy_log));
    while (i < 254) {
        const even_data = entries[even_state];
        var read_bits: u16 = 0;
        const even_bits = reader.readBitsAny(u32, even_data.bits) catch return error.InvalidData;
        read_bits = even_bits.count;
        weights[i] = std.math.cast(u4, even_data.symbol) orelse return error.InvalidData;
        i += 1;
        if (read_bits < even_data.bits) {
            weights[i] = std.math.cast(u4, entries[odd_state].symbol) orelse return error.InvalidData;
            i += 1;
            break;
        }
        even_state = even_data.baseline + even_bits.value;
        const odd_data = entries[odd_state];
        const odd_bits = reader.readBitsAny(u32, odd_data.bits) catch return error.InvalidData;
        read_bits = odd_bits.count;
        weights[i] = std.math.cast(u4, odd_data.symbol) orelse return error.InvalidData;
        i += 1;
        if (read_bits < odd_data.bits) {
            if (i == 255) return error.InvalidData;
            weights[i] = std.math.cast(u4, entries[even_state].symbol) orelse return error.InvalidData;
            i += 1;
            break;
        }
        odd_state = odd_data.baseline + odd_bits.value;
    } else return error.InvalidData;
    if (!reader.isEmpty()) return error.InvalidData;
    return i + 1;
}

fn buildHuffmanTree(weights: []const u4, symbol_count: usize, tree: *HuffmanTree) error{InvalidData}!void {
    var weight_power_sum: u32 = 0;
    for (weights[0 .. symbol_count - 1]) |value| {
        weight_power_sum += (@as(u16, 1) << @intCast(value)) >> 1;
    }
    if (weight_power_sum >= 1 << 11) return error.InvalidData;
    const max_bits: u4 = if (weight_power_sum == 0) 1 else @intCast(std.math.log2_int(u32, weight_power_sum) + 1);
    const next_power = @as(u32, 1) << max_bits;
    const last_weight_value = next_power - weight_power_sum;
    if (last_weight_value == 0) return error.InvalidData;
    const last_weight = std.math.log2_int(u32, last_weight_value) + 1;
    var local_weights: [256]u4 = undefined;
    @memcpy(local_weights[0..symbol_count], weights[0..symbol_count]);
    local_weights[symbol_count - 1] = @intCast(last_weight);
    const nodes = &tree.nodes;
    for (0..symbol_count) |i| {
        nodes[i] = .{ .symbol = @intCast(i), .prefix = 0, .weight = local_weights[i] };
    }
    // Stable sort by weight.
    for (1..symbol_count) |i| {
        const key = nodes[i];
        var j = i;
        while (j > 0 and nodes[j - 1].weight > key.weight) {
            nodes[j] = nodes[j - 1];
            j -= 1;
        }
        nodes[j] = key;
    }
    var prefix: u16 = 0;
    var assigned: usize = 0;
    var index: usize = 0;
    while (index < symbol_count) {
        const weight = nodes[index].weight;
        if (weight == 0) {
            index += 1;
            continue;
        }
        while (index < symbol_count and nodes[index].weight == weight) : ({
            index += 1;
            assigned += 1;
            prefix += 1;
        }) {
            nodes[assigned].symbol = nodes[index].symbol;
            nodes[assigned].prefix = prefix;
            nodes[assigned].weight = weight;
        }
        if (index < symbol_count) {
            const next_weight = nodes[index].weight;
            prefix = ((prefix - 1) >> (next_weight - weight)) + 1;
        }
    }
    const table_size = @as(usize, 1) << max_bits;
    const lookup = tree.lookup[0..table_size];
    @memset(lookup, 0xFFFF);
    for (0..assigned) |i| {
        const node = nodes[i];
        const bits = max_bits + 1 - node.weight;
        const shift = max_bits - bits;
        const entry: u16 = @intCast(node.symbol | (@as(u16, bits) << 8));
        const base = @as(usize, node.prefix) << @intCast(shift);
        const span = @as(usize, 1) << @intCast(shift);
        for (0..span) |j| lookup[base + j] = entry;
    }
    for (lookup, 0..) |single, i| {
        const len1: u32 = single >> 8;
        var entry2: u32 = 0;
        if (len1 >= 1 and len1 <= max_bits) {
            entry2 = @as(u32, single & 0xFF) | (len1 << 16);
            if (len1 < max_bits) {
                const second = lookup[(i << @intCast(len1)) & (table_size - 1)];
                const len2: u32 = second >> 8;
                if (len2 >= 1 and len1 + len2 <= max_bits) {
                    entry2 = @as(u32, single & 0xFF) | (@as(u32, second & 0xFF) << 8) | (len1 << 16) | (len2 << 21);
                }
            }
        }
        tree.lookup2[i] = entry2;
    }
    tree.max_bits = max_bits;
    tree.symbol_count = @intCast(assigned);
}

fn decodeSequencesHeader(cursor: *ReadCursor) DecodeError!SequencesHeader {
    const byte0 = try cursor.readU8();
    if (byte0 == 0) {
        return .{
            .count = 0,
            .literal_mode = .predefined,
            .offset_mode = .predefined,
            .match_mode = .predefined,
        };
    }
    var count: usize = 0;
    if (byte0 < 128) {
        count = byte0;
    } else if (byte0 < 255) {
        const byte1 = try cursor.readU8();
        count = ((@as(usize, byte0) - 128) << 8) + byte1;
    } else {
        const byte1 = try cursor.readU8();
        const byte2 = try cursor.readU8();
        count = @as(usize, byte1) + (@as(usize, byte2) << 8) + 0x7F00;
    }
    const modes = try cursor.readU8();
    if ((modes & 0b11) != 0) return error.InvalidData;
    const match_mode: SequenceMode = @enumFromInt((modes >> 2) & 0b11);
    const offset_mode: SequenceMode = @enumFromInt((modes >> 4) & 0b11);
    const literal_mode: SequenceMode = @enumFromInt((modes >> 6) & 0b11);
    return .{
        .count = count,
        .literal_mode = literal_mode,
        .offset_mode = offset_mode,
        .match_mode = match_mode,
    };
}

const NCountWindow = struct {
    bytes: []const u8,
    pos: usize = 0,
    window: u32 = 0,
    wbits: u6 = 0,
    total: usize = 0,

    fn refill(self: *NCountWindow) void {
        while (self.wbits <= 24 and self.pos < self.bytes.len) {
            self.window |= @as(u32, self.bytes[self.pos]) << @as(u5, @intCast(self.wbits));
            self.wbits += 8;
            self.pos += 1;
        }
    }

    fn peek(self: *NCountWindow, n: u5) DecodeError!u32 {
        self.refill();
        if (self.wbits < n) return error.InvalidData;
        return self.window & ((@as(u32, 1) << n) - 1);
    }

    fn consume(self: *NCountWindow, n: u5) void {
        self.window >>= n;
        self.wbits -= n;
        self.total += n;
    }
};

fn decodeFseTable(
    bytes: []const u8,
    expected_symbol_count: usize,
    max_accuracy_log: u4,
    entries: []FseEntry,
) DecodeError!struct { table_size: usize, consumed: usize } {
    var window = NCountWindow{ .bytes = bytes };
    const accuracy_log_biased = try window.peek(4);
    window.consume(4);
    if (accuracy_log_biased > max_accuracy_log -| 5) return error.InvalidData;
    const accuracy_log: u4 = @intCast(accuracy_log_biased + 5);
    var norm: [256]i16 = @splat(0);
    var remaining: i32 = (@as(i32, 1) << accuracy_log) + 1;
    var threshold: i32 = @as(i32, 1) << accuracy_log;
    var nb_bits: u5 = accuracy_log + 1;
    var charnum: usize = 0;
    var previous0 = false;
    while (true) {
        if (previous0) {
            while (true) {
                const repeat_flag = try window.peek(2);
                window.consume(2);
                charnum += repeat_flag;
                if (repeat_flag < 3) break;
            }
            if (charnum >= expected_symbol_count) break;
        }
        if (charnum >= expected_symbol_count) break;
        const max = (2 * threshold - 1) - remaining;
        const low = try window.peek(nb_bits - 1);
        var count: i32 = undefined;
        if (low < max) {
            count = @intCast(low);
            window.consume(nb_bits - 1);
        } else {
            count = @intCast(try window.peek(nb_bits));
            window.consume(nb_bits);
            if (count >= threshold) count -= max;
        }
        count -= 1;
        if (count >= 0) remaining -= count else remaining += count;
        norm[charnum] = @intCast(count);
        charnum += 1;
        previous0 = count == 0;
        if (charnum >= expected_symbol_count) break;
        if (remaining < threshold) {
            if (remaining <= 1) break;
            const nb: u5 = @intCast(std.math.log2_int(u32, @intCast(remaining)) + 1);
            nb_bits = nb;
            threshold = @as(i32, 1) << (nb - 1);
        }
    }
    if (remaining != 1) return error.InvalidData;
    if (charnum > expected_symbol_count) return error.InvalidData;
    if (charnum < 2) return error.InvalidData;
    const table_size = @as(usize, 1) << accuracy_log;
    buildFseTable(norm[0..charnum], entries[0..table_size]) catch return error.InvalidData;
    return .{ .table_size = table_size, .consumed = (window.total + 7) / 8 };
}

fn buildFseTable(values: []const i16, entries: []FseEntry) error{InvalidData}!void {
    const total_probability: u16 = @intCast(entries.len);
    const accuracy_log = std.math.log2_int(u16, total_probability);
    const table_mask = entries.len - 1;
    const step = (entries.len >> 1) + (entries.len >> 3) + 3;
    var symbol_next: [256]u16 = undefined;
    var high_threshold = entries.len;
    // Place low-probability (-1) symbols at the high end of the table.
    for (values, 0..) |value, symbol| {
        if (value == -1) {
            if (high_threshold == 0) return error.InvalidData;
            high_threshold -= 1;
            entries[high_threshold] = .{
                .symbol = @intCast(symbol),
                .baseline = 0,
                .bits = accuracy_log,
            };
            symbol_next[symbol] = 1;
        } else if (value == 0) {
            symbol_next[symbol] = 0;
        } else {
            symbol_next[symbol] = @intCast(value);
        }
    }
    // Spread the remaining symbols using the FSE modular step.
    var position: usize = 0;
    for (values, 0..) |value, symbol| {
        if (value <= 0) continue;
        const probability: usize = @intCast(value);
        for (0..probability) |_| {
            entries[position].symbol = @intCast(symbol);
            position = (position + step) & table_mask;
            while (position >= high_threshold) {
                position = (position + step) & table_mask;
            }
        }
    }
    if (position != 0) return error.InvalidData;
    // Assign Number_of_Bits and Baseline following the reference decoder layout.
    for (0..entries.len) |u| {
        const symbol = entries[u].symbol;
        const next_state = symbol_next[symbol];
        symbol_next[symbol] = next_state + 1;
        const bits = accuracy_log - std.math.log2_int(u16, next_state);
        entries[u].bits = bits;
        entries[u].baseline = (@as(u16, next_state) << bits) - total_probability;
    }
}

const default_literal_probs = [36]i16{
    4,  3,  2,  2,  2, 2, 2, 2,
    2,  2,  2,  2,  2, 1, 1, 1,
    2,  2,  2,  2,  2, 2, 2, 2,
    2,  3,  2,  1,  1, 1, 1, 1,
    -1, -1, -1, -1,
};

const default_match_probs = [53]i16{
    1,  4,  3,  2,  2,  2, 2,  2,
    2,  1,  1,  1,  1,  1, 1,  1,
    1,  1,  1,  1,  1,  1, 1,  1,
    1,  1,  1,  1,  1,  1, 1,  1,
    1,  1,  1,  1,  1,  1, 1,  1,
    1,  1,  1,  1,  1,  1, -1, -1,
    -1, -1, -1, -1, -1,
};

const default_offset_probs = [29]i16{
    1,  1,  1,  1,  1,  1, 2, 2,
    2,  1,  1,  1,  1,  1, 1, 1,
    1,  1,  1,  1,  1,  1, 1, 1,
    -1, -1, -1, -1, -1,
};

const literals_length_code_table = [36]struct { u32, u5 }{
    .{ 0, 0 },     .{ 1, 0 },      .{ 2, 0 },      .{ 3, 0 },
    .{ 4, 0 },     .{ 5, 0 },      .{ 6, 0 },      .{ 7, 0 },
    .{ 8, 0 },     .{ 9, 0 },      .{ 10, 0 },     .{ 11, 0 },
    .{ 12, 0 },    .{ 13, 0 },     .{ 14, 0 },     .{ 15, 0 },
    .{ 16, 1 },    .{ 18, 1 },     .{ 20, 1 },     .{ 22, 1 },
    .{ 24, 2 },    .{ 28, 2 },     .{ 32, 3 },     .{ 40, 3 },
    .{ 48, 4 },    .{ 64, 6 },     .{ 128, 7 },    .{ 256, 8 },
    .{ 512, 9 },   .{ 1024, 10 },  .{ 2048, 11 },  .{ 4096, 12 },
    .{ 8192, 13 }, .{ 16384, 14 }, .{ 32768, 15 }, .{ 65536, 16 },
};

const match_length_code_table = [53]struct { u32, u5 }{
    .{ 3, 0 },     .{ 4, 0 },     .{ 5, 0 },      .{ 6, 0 },      .{ 7, 0 },      .{ 8, 0 },
    .{ 9, 0 },     .{ 10, 0 },    .{ 11, 0 },     .{ 12, 0 },     .{ 13, 0 },     .{ 14, 0 },
    .{ 15, 0 },    .{ 16, 0 },    .{ 17, 0 },     .{ 18, 0 },     .{ 19, 0 },     .{ 20, 0 },
    .{ 21, 0 },    .{ 22, 0 },    .{ 23, 0 },     .{ 24, 0 },     .{ 25, 0 },     .{ 26, 0 },
    .{ 27, 0 },    .{ 28, 0 },    .{ 29, 0 },     .{ 30, 0 },     .{ 31, 0 },     .{ 32, 0 },
    .{ 33, 0 },    .{ 34, 0 },    .{ 35, 1 },     .{ 37, 1 },     .{ 39, 1 },     .{ 41, 1 },
    .{ 43, 2 },    .{ 47, 2 },    .{ 51, 3 },     .{ 59, 3 },     .{ 67, 4 },     .{ 83, 4 },
    .{ 99, 5 },    .{ 131, 7 },   .{ 259, 8 },    .{ 515, 9 },    .{ 1027, 10 },  .{ 2051, 11 },
    .{ 4099, 12 }, .{ 8195, 13 }, .{ 16387, 14 }, .{ 32771, 15 }, .{ 65539, 16 },
};
