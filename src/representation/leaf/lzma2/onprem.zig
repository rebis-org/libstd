const std = @import("std");

const exception_prim = @import("../../../common/primitive/exception.zig");
const io = @import("../../../common/primitive/io.zig");
const measurement = @import("../../../common/primitive/measurement.zig");
const lzma = @import("../lzma/onprem.zig");

const Exception = exception_prim.Exception;

pub const chunk_max_unpacked: usize = 1 << 21;
const chunk_min_unpacked: usize = 4 * 1024;

pub fn defaultProperties(dictionary_size: u32) lzma.Properties {
    return .{ .lc = 3, .lp = 0, .pb = 2, .dictionary_size = dictionary_size };
}

pub fn dictionarySizeFromProperties(properties_byte: u8) u32 {
    if (properties_byte >= 40) return std.math.maxInt(u32);
    return @as(u32, 2 | (properties_byte & 1)) << @intCast(properties_byte / 2 + 11);
}

pub fn propertiesFromDictionarySize(dictionary: u32) u8 {
    var properties_byte: u8 = 0;
    while (properties_byte < 40) : (properties_byte += 1) {
        if (dictionarySizeFromProperties(properties_byte) >= dictionary) return properties_byte;
    }
    return 40;
}

const control_end: u8 = 0x00;
const control_copy_reset_dict: u8 = 0x01;
const control_copy: u8 = 0x02;
const control_lzma: u8 = 0x80;
const control_lzma_reset_state: u8 = 0xA0;
const control_lzma_new_props: u8 = 0xC0;
const control_lzma_new_props_reset_dict: u8 = 0xE0;
const max_pack_size = 1 << 16;

pub fn decodeWorkspaceSize(dictionary_size: u32) usize {
    const props = defaultProperties(dictionary_size);
    return lzma.decodeWorkspaceSize(props) + chunk_max_unpacked;
}

pub fn decodeInPlaceWorkspaceSize(dictionary_size: u32) usize {
    const props = defaultProperties(dictionary_size);
    return lzma.decodeInPlaceWorkspaceSize(props) + chunk_max_unpacked;
}

pub fn encodeWorkspaceSize(dictionary_size: u32) usize {
    const props = defaultProperties(dictionary_size);
    // The budget covers two encoder states: the persistent one and the per-chunk estimate.
    return 2 * lzma.encodeWorkspaceSize(props) + lzma.modelSize(props) + 4 * max_pack_size + 2 * @alignOf(u16);
}

pub fn encodeWorkspaceSizeBt(dictionary_size: u32) usize {
    const props = defaultProperties(dictionary_size);
    return 2 * lzma.encodeWorkspaceSizeBt(props) + lzma.modelSize(props) + 4 * max_pack_size + 2 * @alignOf(u16);
}

pub const Options = struct {
    dictionary_size: u32,
    properties: lzma.Properties,
    max_work: u64 = std.math.maxInt(u64),
    match_finder_depth: u32 = 32,
    lazy: bool = false,
    nice_len: u32 = 273,
    match_finder: lzma.MatchFinder = .bt4,
};

// A chunk halves to the 2 KiB floor before it goes out as a copy, so the chunk count is
// bounded by input_len/2048 + 1 with the copy and compressed headers covered.
pub fn encodedSizeBound(input_len: usize) usize {
    const chunks = input_len / (chunk_min_unpacked / 2) + 1;
    return input_len +| (input_len / 4) +| 72 *| chunks +| 8;
}

pub fn decode(input: []const u8, output: []u8, scratch: []u8, options: Options) Exception!usize {
    var source = std.Io.Reader.fixed(input);
    var dest = std.Io.Writer.fixed(output);
    try decodeStream(&source, &dest, scratch, options);
    return dest.end;
}

pub fn decodeToWriter(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Exception!void {
    var source = std.Io.Reader.fixed(input);
    _ = try decodeStreamImpl(&source, writer, &.{}, scratch, options, false);
}

pub fn decodeStream(reader: *std.Io.Reader, writer: *std.Io.Writer, scratch: []u8, options: Options) Exception!void {
    _ = try decodeStreamImpl(reader, writer, &.{}, scratch, options, false);
}

pub const InPlaceResult = struct { produced: usize, consumed: usize };

pub fn decodeInPlace(input: []const u8, output: []u8, scratch: []u8, options: Options) Exception!InPlaceResult {
    var source = std.Io.Reader.fixed(input);
    const produced = try decodeStreamImpl(&source, null, output, scratch, options, true);
    return .{ .produced = produced, .consumed = source.seek };
}

fn decodeStreamImpl(reader: *std.Io.Reader, writer: ?*std.Io.Writer, output: []u8, scratch: []u8, options: Options, in_place: bool) Exception!usize {
    const props = try validateProperties(options.properties);
    const lzma_scratch_size = if (in_place) lzma.decodeInPlaceWorkspaceSize(props) else lzma.decodeWorkspaceSize(props);
    if (scratch.len < lzma_scratch_size + chunk_max_unpacked) return error.CapacityException;
    const lzma_scratch = scratch[0..lzma_scratch_size];
    var copy_staging = scratch[lzma_scratch_size..][0..chunk_max_unpacked];
    const SliceDecoder = lzma.DecoderOf(true);
    var decoder = if (in_place)
        try SliceDecoder.initPropertiesInPlace(props, output, lzma_scratch)
    else
        try SliceDecoder.initProperties(props, lzma_scratch);
    if (writer) |sink| decoder.setWriter(sink);
    var need_properties = true;
    var need_dictionary_reset = true;
    while (true) {
        const control = try io.readByte(reader);
        if (control == control_end) return std.math.cast(usize, decoder.decoded) orelse return error.ResourceException;
        if (control >= control_lzma_new_props_reset_dict or control == control_copy_reset_dict) {
            need_properties = true;
            need_dictionary_reset = true;
        } else if (need_dictionary_reset) {
            return error.DataException;
        }
        if (control & 0x80 != 0) {
            const unpack_size = try readLzmaUnpackSize(reader, control);
            if (unpack_size > chunk_max_unpacked) return error.DataException;
            const pack_size = try readPackSize(reader);
            if (pack_size < 5 or pack_size > max_pack_size) return error.DataException;
            if (control >= control_lzma_new_props) {
                const properties_byte = try io.readByte(reader);
                const parsed = try lzma.Properties.decode(properties_byte, options.dictionary_size);
                // LZMA2 permits any valid lc/lp/pb combination per chunk; only
                // the lc+lp<=4 shape constraint applies (SDK behavior).
                if (parsed.lc + parsed.lp > 4) return error.UnsupportedException;
                decoder.setProperties(parsed);
                need_properties = false;
                decoder.resetState();
                decoder.resetProbabilities();
                if (control >= control_lzma_new_props_reset_dict) {
                    decoder.resetDictionary();
                    need_dictionary_reset = false;
                }
            } else {
                if (need_properties) return error.DataException;
                if (control >= control_lzma_reset_state) {
                    decoder.resetState();
                    decoder.resetProbabilities();
                }
                if (need_dictionary_reset) {
                    decoder.resetDictionary();
                    need_dictionary_reset = false;
                }
            }
            var chunk_buffer: [max_pack_size]u8 = undefined;
            var pack_iovecs = [_][]u8{chunk_buffer[0..pack_size]};
            const pack_read = reader.readVec(&pack_iovecs) catch return error.IoException;
            if (pack_read != pack_size) return error.IoException;
            try decoder.resetReaderSlice(chunk_buffer[0..pack_size]);
            try decoder.decodeToOutput(null, unpack_size, false);
        } else {
            if (control != control_copy_reset_dict and control != control_copy) return error.DataException;
            const unpack_size = try readCopyUnpackSize(reader);
            if (unpack_size > chunk_max_unpacked) return error.DataException;
            if (need_dictionary_reset) {
                decoder.resetDictionary();
                need_dictionary_reset = false;
            }
            var remaining = unpack_size;
            while (remaining > 0) {
                const batch = @min(remaining, copy_staging.len);
                var copy_iovecs = [_][]u8{copy_staging[0..batch]};
                const copy_read = reader.readVec(&copy_iovecs) catch return error.IoException;
                if (copy_read != batch) return error.IoException;
                if (writer) |sink| try io.writeBytes(sink, copy_staging[0..batch]);
                for (copy_staging[0..batch]) |byte| try decoder.feedByte(byte);
                remaining -= batch;
            }
        }
    }
    return std.math.cast(usize, decoder.decoded) orelse return error.ResourceException;
}

fn validateProperties(props: lzma.Properties) Exception!lzma.Properties {
    if (props.lc + props.lp > 4) return error.UnsupportedException;
    return props;
}

fn readCopyUnpackSize(reader: *std.Io.Reader) Exception!usize {
    const high = try io.readByte(reader);
    const low = try io.readByte(reader);
    const stored_size = (@as(usize, high) << 8) | low;
    return stored_size + 1;
}

fn readLzmaUnpackSize(reader: *std.Io.Reader, control: u8) Exception!usize {
    // Five control bits carry the size high bits, matching the SDK; four
    // bits would cap chunks at 1 MiB and reject SDK-produced 1..2 MiB blocks.
    const high = @as(usize, control & 0x1F) << 16;
    const mid = try io.readByte(reader);
    const low = try io.readByte(reader);
    return (high | (@as(usize, mid) << 8) | low) + 1;
}

fn readPackSize(reader: *std.Io.Reader) Exception!usize {
    const high = try io.readByte(reader);
    const low = try io.readByte(reader);
    return ((@as(usize, high) << 8) | low) + 1;
}

pub fn decodedSize(input: []const u8, scratch: []u8, options: Options) Exception!usize {
    if (try scanDecodedSize(input)) |size| return size;
    var source = std.Io.Reader.fixed(input);
    var counter = measurement.Counter.init(null);
    try decodeStream(&source, &counter.writer, scratch, options);
    return measurement.measuredLength(&counter);
}

fn scanDecodedSize(input: []const u8) Exception!?usize {
    var pos: usize = 0;
    var total: usize = 0;
    var need_properties = true;
    var need_dictionary_reset = true;
    while (pos < input.len) {
        const control = input[pos];
        pos += 1;
        if (control == control_end) return total;
        if (control >= control_lzma_new_props_reset_dict or control == control_copy_reset_dict) {
            need_properties = true;
            need_dictionary_reset = true;
        } else if (need_dictionary_reset) {
            return error.DataException;
        }
        if (control & 0x80 != 0) {
            if (pos + 2 > input.len) return error.DataException;
            const unpack_size = (((@as(usize, control & 0x1F) << 16) | (@as(usize, input[pos]) << 8) | input[pos + 1]) + 1);
            pos += 2;
            if (pos + 2 > input.len) return error.DataException;
            const pack_size = ((@as(usize, input[pos]) << 8) | input[pos + 1]) + 1;
            pos += 2;
            if (unpack_size > chunk_max_unpacked or pack_size < 5 or pack_size > max_pack_size) return error.DataException;
            if (control >= control_lzma_new_props) {
                if (pos >= input.len) return error.DataException;
                pos += 1;
                need_properties = false;
                if (control >= control_lzma_new_props_reset_dict) need_dictionary_reset = false;
            } else {
                if (need_properties) return error.DataException;
            }
            pos += pack_size;
            if (pos > input.len) return error.DataException;
            total = std.math.add(usize, total, unpack_size) catch return error.ResourceException;
        } else {
            if (control != control_copy_reset_dict and control != control_copy) return error.DataException;
            if (pos + 2 > input.len) return error.DataException;
            const unpack_size = ((@as(usize, input[pos]) << 8) | input[pos + 1]) + 1;
            pos += 2;
            if (unpack_size > chunk_max_unpacked) return error.DataException;
            if (need_dictionary_reset) need_dictionary_reset = false;
            pos += unpack_size;
            if (pos > input.len) return error.DataException;
            total = std.math.add(usize, total, unpack_size) catch return error.ResourceException;
        }
    }
    return error.DataException;
}

pub fn requiredSize(input: []const u8, scratch: []u8, options: Options) Exception!usize {
    var counter = measurement.Counter.init(null);
    try encodeStreamInner(input, &counter.writer, scratch, options);
    return measurement.measuredLength(&counter);
}

pub fn encode(input: []const u8, output: []u8, scratch: []u8, options: Options) Exception!usize {
    var dest = std.Io.Writer.fixed(output);
    try encodeStreamInner(input, &dest, scratch, options);
    return dest.end;
}

pub fn encodeToWriter(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Exception!void {
    if (input.len > options.max_work) return error.ResourceException;
    try encodeStreamInner(input, writer, scratch, options);
}

// The estimate is high by construction. A zero pack margin avoids copy cascades, and
// snapshot/restore covers the residual underestimates.
fn isChunkCompressible(chunk: []const u8, estimate_scratch: []u8, props: lzma.Properties, options: Options) bool {
    const estimate = lzma.estimatedSize(chunk, estimate_scratch, .{
        .properties = props,
        .unpack_size = chunk.len,
        .marker_required = false,
        .max_work = options.max_work,
        .match_finder_depth = 4,
        .lazy = false,
        .nice_len = 32,
        .match_finder = .hash_chain,
    }) catch return false;
    return estimate <= max_pack_size and estimate < chunk.len;
}

fn encodeStreamInner(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Exception!void {
    const props = try validateProperties(options.properties);
    const encoder_scratch_size = if (options.match_finder == .bt4) lzma.encodeWorkspaceSizeBt(props) else lzma.encodeWorkspaceSize(props);
    if (scratch.len < 2 * encoder_scratch_size) return error.CapacityException;
    const encoder_scratch = scratch[0..encoder_scratch_size];
    const estimate_scratch = scratch[encoder_scratch_size .. 2 * encoder_scratch_size];
    var model_workspace = try io.Workspace.init(scratch[2 * encoder_scratch_size ..].ptr, scratch[2 * encoder_scratch_size ..].len);
    const model_snapshot = try model_workspace.take(u16, lzma.modelProbCount(props));
    const pack_buffer = try model_workspace.take(u8, 4 * max_pack_size);
    var encoder = try lzma.Encoder.init(props, writer, encoder_scratch, .{
        .properties = props,
        .unpack_size = null,
        .marker_required = false,
        .max_work = options.max_work,
        .match_finder_depth = options.match_finder_depth,
        .lazy = options.lazy,
        .nice_len = options.nice_len,
        .match_finder = options.match_finder,
    });
    var offset: usize = 0;
    var is_first_chunk: bool = true;
    var props_sent: bool = false;
    var last_fitting_len: usize = chunk_max_unpacked;
    while (offset < input.len) {
        // The pack field caps a chunk at 64 KiB, so shrink the chunk until the estimate fits.
        var chunk_len = @min(last_fitting_len, input.len - offset);
        var compressible = isChunkCompressible(input[offset..][0..chunk_len], estimate_scratch, props, options);
        while (!compressible and chunk_len >= chunk_min_unpacked) {
            chunk_len >>= 1;
            compressible = isChunkCompressible(input[offset..][0..chunk_len], estimate_scratch, props, options);
        }
        if (compressible) last_fitting_len = chunk_len;
        const chunk = input[offset..][0..chunk_len];
        if (compressible) {
            var pack_writer = std.Io.Writer.fixed(pack_buffer);
            const snap_state = encoder.state;
            const snap_rep0 = encoder.rep0;
            const snap_rep1 = encoder.rep1;
            const snap_rep2 = encoder.rep2;
            const snap_rep3 = encoder.rep3;
            encoder.snapshotModel(model_snapshot);
            encoder.setRangeEncoder(lzma.RangeEncoder.init(&pack_writer));
            // The first compressed chunk after a copy must send the properties with a reset (0xC0).
            // The snapshot holds the model from before the reset for the oversize restore.
            const send_props = !props_sent;
            if (send_props and !is_first_chunk) encoder.resetModelKeepDictionary();
            try encoder.encodeInput(chunk, false);
            const packed_len = pack_writer.end;
            if (packed_len <= max_pack_size) {
                const raw_unpack_size = chunk.len - 1;
                const raw_pack_size = packed_len - 1;
                const control_base: u8 = if (is_first_chunk) control_lzma_new_props_reset_dict else if (send_props) control_lzma_new_props else control_lzma;
                const control: u8 = control_base |
                    @as(u8, @intCast((raw_unpack_size >> 16) & 0x1F));
                try io.writeByte(writer, control);
                try io.writeByte(writer, @intCast((raw_unpack_size >> 8) & 0xFF));
                try io.writeByte(writer, @intCast(raw_unpack_size & 0xFF));
                try io.writeByte(writer, @intCast((raw_pack_size >> 8) & 0xFF));
                try io.writeByte(writer, @intCast(raw_pack_size & 0xFF));
                if (send_props) try io.writeByte(writer, props.encode());
                try io.writeBytes(writer, pack_buffer[0..packed_len]);
                props_sent = true;
            } else {
                // The aborted encode already fed the dictionary, so restore the model state only.
                encoder.restoreModel(model_snapshot);
                encoder.state = snap_state;
                encoder.rep0 = snap_rep0;
                encoder.rep1 = snap_rep1;
                encoder.rep2 = snap_rep2;
                encoder.rep3 = snap_rep3;
                try writeCopyChunk(writer, chunk, is_first_chunk);
            }
        } else {
            try writeCopyChunk(writer, chunk, is_first_chunk);
            for (chunk) |byte| encoder.putByte(byte);
        }
        is_first_chunk = false;
        offset += chunk_len;
    }
    try io.writeByte(writer, control_end);
}

fn writeCopyChunk(writer: *std.Io.Writer, chunk: []const u8, reset_dictionary: bool) Exception!void {
    const control: u8 = if (reset_dictionary) control_copy_reset_dict else control_copy;
    var copy_offset: usize = 0;
    while (copy_offset < chunk.len) {
        const batch_len = @min(chunk.len - copy_offset, max_pack_size);
        const raw_size = batch_len - 1;
        try io.writeByte(writer, control);
        try io.writeByte(writer, @intCast((raw_size >> 8) & 0xFF));
        try io.writeByte(writer, @intCast(raw_size & 0xFF));
        try io.writeBytes(writer, chunk[copy_offset..][0..batch_len]);
        copy_offset += batch_len;
    }
}

// A multithreaded encoder shape: every group starts from an empty dictionary,
// a fresh model, and position zero, announced with a dict-reset chunk.
fn appendResetChunk(stream: *std.Io.Writer, props: lzma.Properties, input: []const u8, encoder_scratch: []u8) Exception!void {
    var pack_buffer: [max_pack_size]u8 = undefined;
    var pack_writer = std.Io.Writer.fixed(&pack_buffer);
    var encoder = try lzma.Encoder.init(props, &pack_writer, encoder_scratch, .{
        .properties = props,
        .unpack_size = null,
        .marker_required = false,
        .max_work = std.math.maxInt(u64),
        .match_finder_depth = 32,
        .lazy = false,
        .nice_len = 273,
        .match_finder = .bt4,
    });
    try encoder.encodeInput(input, false);
    const packed_len = pack_writer.end;
    const raw_unpack_size = input.len - 1;
    const raw_pack_size = packed_len - 1;
    const control: u8 = control_lzma_new_props_reset_dict |
        @as(u8, @intCast((raw_unpack_size >> 16) & 0x1F));
    try io.writeByte(stream, control);
    try io.writeByte(stream, @intCast((raw_unpack_size >> 8) & 0xFF));
    try io.writeByte(stream, @intCast(raw_unpack_size & 0xFF));
    try io.writeByte(stream, @intCast((raw_pack_size >> 8) & 0xFF));
    try io.writeByte(stream, @intCast(raw_pack_size & 0xFF));
    try io.writeByte(stream, props.encode());
    try io.writeBytes(stream, pack_buffer[0..packed_len]);
}

test "lzma2 decodes a mid-stream dictionary reset stream" {
    const alloc = std.testing.allocator;

    const dictionary: u32 = 1 << 20;
    const props = defaultProperties(dictionary);
    const options: Options = .{ .dictionary_size = dictionary, .properties = props };

    var prng = std.Random.DefaultPrng.init(0x5eed);
    const input_a = try alloc.alloc(u8, 2001);
    defer alloc.free(input_a);
    prng.random().bytes(input_a);
    const input_b = try alloc.alloc(u8, 2400);
    defer alloc.free(input_b);
    @memset(input_b[0..512], 'x');
    prng.random().bytes(input_b[512..]);

    const encoder_scratch = try alloc.alloc(u8, lzma.encodeWorkspaceSizeBt(props));
    defer alloc.free(encoder_scratch);

    const stream = try alloc.alloc(u8, input_a.len + input_b.len + 32);
    defer alloc.free(stream);
    var sink = std.Io.Writer.fixed(stream);
    try appendResetChunk(&sink, props, input_a, encoder_scratch);
    try appendResetChunk(&sink, props, input_b, encoder_scratch);
    try io.writeByte(&sink, control_end);

    const expected = try alloc.alloc(u8, input_a.len + input_b.len);
    defer alloc.free(expected);
    @memcpy(expected[0..input_a.len], input_a);
    @memcpy(expected[input_a.len..], input_b);

    // The stdlib decoder cross-validates the crafted two-group stream before
    // the onprem decode checks bit-exact agreement. A constant position-state
    // offset is decode-invariant in LZMA, so this covers the multithreaded
    // reset path and its stdlib parity, not an observable restart.
    var std_reader = std.Io.Reader.fixed(stream[0..sink.end]);
    var std_decoder = std.compress.lzma2.Decode.init(alloc) catch return error.TestUnexpectedResult;
    defer std_decoder.deinit(alloc);
    var std_sink: std.Io.Writer.Allocating = .init(alloc);
    defer std_sink.deinit();
    _ = std_decoder.decompress(&std_reader, &std_sink) catch return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, expected, std_sink.writer.buffer[0..std_sink.writer.end]);

    const output = try alloc.alloc(u8, expected.len);
    defer alloc.free(output);
    const decode_scratch = try alloc.alloc(u8, decodeWorkspaceSize(dictionary));
    defer alloc.free(decode_scratch);
    const produced = try decode(stream[0..sink.end], output, decode_scratch, options);
    try std.testing.expectEqual(expected.len, produced);
    try std.testing.expectEqualSlices(u8, expected, output);
}
