const std = @import("std");

const failure_prim = @import("../common/primitive/failure.zig");
const Failure = failure_prim.Failure;
const io = @import("../common/primitive/io.zig");
const measurement = @import("../common/primitive/measurement.zig");
const lzma = @import("lzma.zig");

pub const chunk_max_unpacked: usize = 1 << 20;
const chunk_min_unpacked: usize = 4 * 1024;

pub fn properties(dictionary_size: u32) lzma.Properties {
    return .{ .lc = 3, .lp = 0, .pb = 2, .dictionary_size = dictionary_size };
}

pub fn dictionaryFromProp(prop: u8) u32 {
    if (prop >= 40) return std.math.maxInt(u32);
    return @as(u32, 2 | (prop & 1)) << @intCast(prop / 2 + 11);
}

pub fn propFromDictionary(dictionary: u32) u8 {
    var prop: u8 = 0;
    while (prop < 40) : (prop += 1) {
        if (dictionaryFromProp(prop) >= dictionary) return prop;
    }
    return 40;
}

const control_end: u8 = 0x00;
const control_copy_reset_dic: u8 = 0x01;
const control_copy: u8 = 0x02;
const control_lzma: u8 = 0x80;
const control_lzma_reset_state: u8 = 0xA0;
const control_lzma_new_props: u8 = 0xC0;
const control_lzma_new_props_reset_dic: u8 = 0xE0;
const max_pack_size = 1 << 16;

pub fn decodeWorkspaceSize(dictionary_size: u32) usize {
    const props = properties(dictionary_size);
    return lzma.decodeWorkspaceSize(props) + chunk_max_unpacked;
}

pub fn decodeInPlaceWorkspaceSize(dictionary_size: u32) usize {
    const props = properties(dictionary_size);
    return lzma.decodeInPlaceWorkspaceSize(props) + chunk_max_unpacked;
}

pub fn encodeWorkspaceSize(dictionary_size: u32) usize {
    const props = properties(dictionary_size);
    // The streaming encoder holds one encoder state for the persistent encoder
    // and a second, equal-sized state for the per-chunk size estimate.
    return 2 * lzma.encodeWorkspaceSize(props) + lzma.modelSize(props) + 4 * max_pack_size + 2 * @alignOf(u16);
}

pub fn encodeWorkspaceSizeBt(dictionary_size: u32) usize {
    const props = properties(dictionary_size);
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

// Per chunk the output is either a copy chunk (3-byte header per 64 KiB
// batch) or a compressed chunk (lzma.encodedSizeBound payload plus a 6-byte
// header). The sizing probe halves incompressible chunks down to the
// chunk_min_unpacked/2 floor before they go out as copies, so the chunk count
// is bounded by input_len / 2048 + 1, not input_len / chunk_max_unpacked:
// the plan's 6-bytes-per-2-MiB form ignored the halving floor.
pub fn encodedSizeBound(input_len: usize) usize {
    const chunks = input_len / (chunk_min_unpacked / 2) + 1;
    return input_len +| (input_len / 4) +| 72 *| chunks +| 8;
}

pub fn decode(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    var source = std.Io.Reader.fixed(input);
    var dest = std.Io.Writer.fixed(output);
    try decodeStream(&source, &dest, scratch, options);
    return dest.end;
}

pub fn decodeToWriter(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    var source = std.Io.Reader.fixed(input);
    _ = try decodeStreamImpl(&source, writer, &.{}, scratch, options, false);
}

pub fn decodeStream(reader: *std.Io.Reader, writer: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    _ = try decodeStreamImpl(reader, writer, &.{}, scratch, options, false);
}

pub const InPlaceResult = struct { produced: usize, consumed: usize };

pub fn decodeInPlace(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!InPlaceResult {
    var source = std.Io.Reader.fixed(input);
    const produced = try decodeStreamImpl(&source, null, output, scratch, options, true);
    return .{ .produced = produced, .consumed = source.seek };
}

fn decodeStreamImpl(reader: *std.Io.Reader, writer: ?*std.Io.Writer, output: []u8, scratch: []u8, options: Options, in_place: bool) Failure!usize {
    const props = try validateProperties(options.properties);
    const lzma_scratch_size = if (in_place) lzma.decodeInPlaceWorkspaceSize(props) else lzma.decodeWorkspaceSize(props);
    if (scratch.len < lzma_scratch_size + chunk_max_unpacked) return error.InsufficientCapacity;
    const lzma_scratch = scratch[0..lzma_scratch_size];
    var temp = scratch[lzma_scratch_size..][0..chunk_max_unpacked];
    const SliceDecoder = lzma.DecoderOf(true);
    var decoder = if (in_place)
        try SliceDecoder.initPropertiesInPlace(props, output, lzma_scratch)
    else
        try SliceDecoder.initProperties(props, lzma_scratch);
    if (writer) |w| decoder.setWriter(w);
    var need_properties = true;
    var need_dictionary_reset = true;
    while (true) {
        const control = try io.readByte(reader);
        if (control == control_end) return decoder.total_pos;
        if (control >= control_lzma_new_props_reset_dic or control == control_copy_reset_dic) {
            need_properties = true;
            need_dictionary_reset = true;
        } else if (need_dictionary_reset) {
            return error.InvalidData;
        }
        if (control & 0x80 != 0) {
            const unpack_size = try readLzmaUnpackSize(reader, control);
            if (unpack_size > chunk_max_unpacked) return error.InvalidData;
            const pack_size = try readPackSize(reader);
            if (pack_size < 5 or pack_size > max_pack_size) return error.InvalidData;
            if (control >= control_lzma_new_props) {
                const prop_byte = try io.readByte(reader);
                const parsed = try lzma.Properties.decode(prop_byte, options.dictionary_size);
                if (parsed.lc != props.lc or parsed.lp != props.lp or parsed.pb != props.pb) return error.Unsupported;
                decoder.setProperties(parsed);
                need_properties = false;
                decoder.resetState();
                decoder.resetProbabilities();
                if (control >= control_lzma_new_props_reset_dic) {
                    decoder.resetDictionary();
                    need_dictionary_reset = false;
                }
            } else {
                if (need_properties) return error.InvalidData;
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
            var iovecs = [_][]u8{chunk_buffer[0..pack_size]};
            const n = reader.readVec(&iovecs) catch return error.IoFailure;
            if (n != pack_size) return error.IoFailure;
            try decoder.resetReaderSlice(chunk_buffer[0..pack_size]);
            try decoder.decodeToOutput(null, unpack_size, false);
        } else {
            if (control != control_copy_reset_dic and control != control_copy) return error.InvalidData;
            const unpack_size = try readSize(reader);
            if (unpack_size > chunk_max_unpacked) return error.InvalidData;
            if (need_dictionary_reset) {
                decoder.resetDictionary();
                need_dictionary_reset = false;
            }
            var remaining = unpack_size;
            while (remaining > 0) {
                const batch = @min(remaining, temp.len);
                var iovecs = [_][]u8{temp[0..batch]};
                const n = reader.readVec(&iovecs) catch return error.IoFailure;
                if (n != batch) return error.IoFailure;
                if (writer) |w| try io.writeBytes(w, temp[0..batch]);
                for (temp[0..batch]) |byte| decoder.feedByte(byte);
                remaining -= batch;
            }
        }
    }
    return decoder.total_pos;
}

fn validateProperties(props: lzma.Properties) Failure!lzma.Properties {
    if (props.lc + props.lp > 4) return error.Unsupported;
    return props;
}

fn readSize(reader: *std.Io.Reader) Failure!usize {
    const high = try io.readByte(reader);
    const low = try io.readByte(reader);
    const value = (@as(usize, high) << 8) | low;
    return value + 1;
}

fn readLzmaUnpackSize(reader: *std.Io.Reader, control: u8) Failure!usize {
    const high = @as(usize, control & 0x0F) << 16;
    const mid = try io.readByte(reader);
    const low = try io.readByte(reader);
    return (high | (@as(usize, mid) << 8) | low) + 1;
}

fn readPackSize(reader: *std.Io.Reader) Failure!usize {
    const high = try io.readByte(reader);
    const low = try io.readByte(reader);
    return ((@as(usize, high) << 8) | low) + 1;
}

pub fn decodedSize(input: []const u8, scratch: []u8, options: Options) Failure!usize {
    if (try scanSize(input)) |size| return size;
    var source = std.Io.Reader.fixed(input);
    var counter = measurement.Counter.init(null);
    try decodeStream(&source, &counter.writer, scratch, options);
    return std.math.cast(usize, counter.written()) orelse error.ResourceLimit;
}

fn scanSize(input: []const u8) Failure!?usize {
    var pos: usize = 0;
    var total: usize = 0;
    var need_properties = true;
    var need_dictionary_reset = true;
    while (pos < input.len) {
        const control = input[pos];
        pos += 1;
        if (control == control_end) return total;
        if (control >= control_lzma_new_props_reset_dic or control == control_copy_reset_dic) {
            need_properties = true;
            need_dictionary_reset = true;
        } else if (need_dictionary_reset) {
            return error.InvalidData;
        }
        if (control & 0x80 != 0) {
            if (pos + 2 > input.len) return error.InvalidData;
            const unpack_size = (((@as(usize, control & 0x0F) << 16) | (@as(usize, input[pos]) << 8) | input[pos + 1]) + 1);
            pos += 2;
            if (pos + 2 > input.len) return error.InvalidData;
            const pack_size = ((@as(usize, input[pos]) << 8) | input[pos + 1]) + 1;
            pos += 2;
            if (unpack_size > chunk_max_unpacked or pack_size < 5 or pack_size > max_pack_size) return error.InvalidData;
            if (control >= control_lzma_new_props) {
                if (pos >= input.len) return error.InvalidData;
                pos += 1;
                need_properties = false;
                if (control >= control_lzma_new_props_reset_dic) need_dictionary_reset = false;
            } else {
                if (need_properties) return error.InvalidData;
            }
            pos += pack_size;
            if (pos > input.len) return error.InvalidData;
            total = std.math.add(usize, total, unpack_size) catch return error.ResourceLimit;
        } else {
            if (control != control_copy_reset_dic and control != control_copy) return error.InvalidData;
            if (pos + 2 > input.len) return error.InvalidData;
            const unpack_size = ((@as(usize, input[pos]) << 8) | input[pos + 1]) + 1;
            pos += 2;
            if (unpack_size > chunk_max_unpacked) return error.InvalidData;
            if (need_dictionary_reset) need_dictionary_reset = false;
            pos += unpack_size;
            if (pos > input.len) return error.InvalidData;
            total = std.math.add(usize, total, unpack_size) catch return error.ResourceLimit;
        }
    }
    return error.InvalidData;
}

pub fn requiredSize(input: []const u8, scratch: []u8, options: Options) Failure!usize {
    var counter = measurement.Counter.init(null);
    try encodeStreamInner(input, &counter.writer, scratch, options);
    return std.math.cast(usize, counter.written()) orelse error.ResourceLimit;
}

pub fn encode(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    var dest = std.Io.Writer.fixed(output);
    try encodeStreamInner(input, &dest, scratch, options);
    return dest.end;
}

pub fn encodeToWriter(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    if (input.len > options.max_work) return error.ResourceLimit;
    try encodeStreamInner(input, writer, scratch, options);
}

// KTD5 calibration: the greedy estimate was diffed against the real
// per-chunk encode (persistent model, DP parse, bt4) across the benchmark
// corpus plus generated all-random, all-same-byte, period-4, and adversarial
// alternating-statistics blocks. The estimate errs high by construction:
// corpus median overestimate 2.1 KB, worst underestimate 222 bytes (p99.9 =
// 124), and underestimates only occur on compressible chunks with several
// KiB of boundary slack — never near 64 KiB, where chunks are
// literal-dominated and the estimate is accurate to ~0.1% (still over). A
// positive pack-test margin was measured to flip the censored est ~= 64 KiB
// pile-up into copy-chunk cascades (mozilla +6.5% at a 256-byte margin), so
// the calibrated margin is zero: the pack test stays `estimate <=
// max_pack_size`. Underestimates beyond it (flip blocks, up to ~4 KB) land
// on the snapshot/restore net below, which the oracle suite exercises.
fn probeChunk(chunk: []const u8, est_scratch: []u8, props: lzma.Properties, options: Options) bool {
    const estimate = lzma.estimatedSize(chunk, est_scratch, .{
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

fn encodeStreamInner(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    const props = try validateProperties(options.properties);
    const encoder_scratch_size = if (options.match_finder == .bt4) lzma.encodeWorkspaceSizeBt(props) else lzma.encodeWorkspaceSize(props);
    if (scratch.len < 2 * encoder_scratch_size) return error.InsufficientCapacity;
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
    var first: bool = true;
    var props_sent: bool = false;
    var last_fit: usize = chunk_max_unpacked;
    while (offset < input.len) {
        // The LZMA2 pack-size field caps each compressed chunk at 64 KiB, so
        // shrink the chunk until its estimate fits instead of falling back to
        // an uncompressed chunk for whole blocks of compressible data.
        var chunk_len = @min(last_fit, input.len - offset);
        var compressible = probeChunk(input[offset..][0..chunk_len], estimate_scratch, props, options);
        while (!compressible and chunk_len >= chunk_min_unpacked) {
            chunk_len >>= 1;
            compressible = probeChunk(input[offset..][0..chunk_len], estimate_scratch, props, options);
        }
        if (compressible) last_fit = chunk_len;
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
            // A first chunk that went down the copy path never carried
            // properties, so the first compressed chunk after it must send
            // them with a state reset (0xC0); the model reset happens before
            // the encode, and the snapshot above keeps the PRE-reset model,
            // which is what the oversize restore must put back.
            const send_props = !props_sent;
            if (send_props and !first) encoder.resetModelKeepDictionary();
            try encoder.encodeInput(chunk, false);
            const packed_len = pack_writer.end;
            if (packed_len <= max_pack_size) {
                const raw_unpack_size = chunk.len - 1;
                const raw_pack_size = packed_len - 1;
                const base: u8 = if (first) control_lzma_new_props_reset_dic else if (send_props) control_lzma_new_props else control_lzma;
                const control: u8 = base |
                    @as(u8, @intCast((raw_unpack_size >> 16) & 0x0F));
                try io.writeByte(writer, control);
                try io.writeByte(writer, @intCast((raw_unpack_size >> 8) & 0xFF));
                try io.writeByte(writer, @intCast(raw_unpack_size & 0xFF));
                try io.writeByte(writer, @intCast((raw_pack_size >> 8) & 0xFF));
                try io.writeByte(writer, @intCast(raw_pack_size & 0xFF));
                if (send_props) try io.writeByte(writer, props.encode());
                try io.writeBytes(writer, pack_buffer[0..packed_len]);
                props_sent = true;
            } else {
                // The persistent model can exceed the fresh-encoder estimate.
                // Discard the encoded symbols and emit a copy chunk instead;
                // the aborted encode already fed the dictionary, so only the
                // model state must return to the pre-chunk snapshot.
                encoder.restoreModel(model_snapshot);
                encoder.state = snap_state;
                encoder.rep0 = snap_rep0;
                encoder.rep1 = snap_rep1;
                encoder.rep2 = snap_rep2;
                encoder.rep3 = snap_rep3;
                try writeCopyChunk(writer, chunk, first);
            }
        } else {
            try writeCopyChunk(writer, chunk, first);
            for (chunk) |byte| encoder.putByte(byte);
        }
        first = false;
        offset += chunk_len;
    }
    try io.writeByte(writer, control_end);
}

fn writeCopyChunk(writer: *std.Io.Writer, chunk: []const u8, reset_dict: bool) Failure!void {
    const control: u8 = if (reset_dict) control_copy_reset_dic else control_copy;
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
