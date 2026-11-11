const std = @import("std");

const measurement = @import("../common/primitive/measurement.zig");
const node_graph = @import("../kernel/node.zig");
const resource = @import("../kernel/resource.zig");
const vocabulary = @import("../kernel/vocabulary.zig");
const gzip = @import("../representation/grammar/gzip/onprem.zig");
const lzma_file = @import("../representation/grammar/lzma/onprem.zig");
const xz = @import("../representation/grammar/xz/onprem.zig");
const zlib = @import("../representation/grammar/zlib/onprem.zig");
const zstd_seekable = @import("../representation/grammar/zstd_seekable/onprem.zig");
const bcj = @import("../representation/leaf/bcj/onprem.zig");
const bcj2 = @import("../representation/leaf/bcj2/onprem.zig");
const brotli = @import("../representation/leaf/brotli/onprem.zig");
const bzip2 = @import("../representation/leaf/bzip2/onprem.zig");
const deflate = @import("../representation/leaf/deflate/onprem.zig");
const deflate_seam = @import("../representation/leaf/deflate/seam.zig");
const delta = @import("../representation/leaf/delta/onprem.zig");
const lz4 = @import("../representation/leaf/lz4/onprem.zig");
const lzma = @import("../representation/leaf/lzma/onprem.zig");
const lzma2 = @import("../representation/leaf/lzma2/onprem.zig");
const lzo = @import("../representation/leaf/lzo/onprem.zig");
const ppmd = @import("../representation/leaf/ppmd/onprem.zig");
const zstd = @import("../representation/leaf/zstd/onprem.zig");
const zstd_seam = @import("../representation/leaf/zstd/seam.zig");
const common = @import("common.zig");
const zstd_sizing = @import("sizing.zig");
const echo = @import("transform/echo.zig");
const options = @import("transform/options.zig");
const plan = @import("transform/plan.zig");
const run = @import("transform/run.zig");
const zdict = @import("transform/zdict.zig");

const Exception = vocabulary.Exception;
const Invocation = common.Invocation;
const Run = run.Run;

// The gzip fixed-header flag bits, mirrored from the grammar leaf for the
// read-side inspect projection.
const flag_text: u8 = 0x01;
const flag_header_crc: u8 = 0x02;

fn serveDeflate(running: *Run) Exception!void {
    const call = running.call();
    const response = running.response();
    const source_resource = running.source();
    const sink = running.sink();
    const sizing = running.sizing();
    const limits = running.limits();
    const command_mask = running.commandMask();
    try run.requireReplay(running, false);
    const deflate_opts = try options.parseDeflateOptions(call.request, command_mask);
    const workspace = running.workspace();
    const history = try workspace.take(u8, deflate.history_size + @as(usize, if (deflate_opts.optimal) deflate.optimal_workspace_size else 0));
    if (command_mask == vocabulary.command_mask_read) {
        // The planning pass truncates at the encoded limit, so reject an
        // over-limit source here rather than mid-count as corrupt data.
        const input_len = try common.measureSource(source_resource, limits.encoded_bytes);
        const output_size = try plan.planDeflateDecode(source_resource, history, limits.encoded_bytes, limits.decoded_bytes);
        if ((std.math.add(usize, input_len, output_size) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(source_resource, limits.encoded_bytes);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.decoded_bytes);
            var inflater = deflate_seam.Decode.initBound(running.provider(), &bounded_source.reader, history) catch return error.UnsupportedException;
            _ = inflater.readerPtr().streamRemaining(&bounded_sink.writer) catch |err| return common.mapSinkError(switch (err) {
                error.WriteFailed => error.IoException,
                else => error.DataException,
            }, call, sink_resource);
        }
        response.byte_length = output_size;
    } else if (command_mask == vocabulary.command_mask_write) {
        const output_size = if (sizing == .bounded) blk: {
            const input_len = try common.measureSource(source_resource, limits.decoded_bytes);
            const bound = deflate.encodedSizeBound(input_len);
            if (bound > limits.encoded_bytes) return error.ResourceException;
            if ((std.math.add(usize, input_len, bound) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
            break :blk bound;
        } else try plan.planCountedEncode(source_resource, limits.decoded_bytes, limits.encoded_bytes, limits.codec_work, true, plan.deflateEncodeStream, .{ .history = history, .options = deflate_opts });
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(source_resource, limits.decoded_bytes);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.encoded_bytes);
            var compressor = try deflate.Compress.init(&bounded_sink.writer, history, deflate_opts);
            _ = std.Io.Reader.streamRemaining(&bounded_source.reader, &compressor.writer) catch return common.mapSinkError(error.IoException, call, sink_resource);
            compressor.finish() catch return common.mapSinkError(error.IoException, call, sink_resource);
            if (try common.respondWrite(response, sizing, &bounded_sink, limits.encoded_bytes, output_size)) return;
        }
        response.byte_length = output_size;
    } else {
        return error.UnsupportedException;
    }
}

fn serveGzip(running: *Run) Exception!void {
    const call = running.call();
    const response = running.response();
    const source_resource = running.source();
    const sink = running.sink();
    const sizing = running.sizing();
    const limits = running.limits();
    const command_mask = running.commandMask();
    const provider = running.provider();
    try run.requireReplay(running, false);
    const workspace = running.workspace();
    const gzip_options = blk: {
        var parsed = try options.parseGzipOptions(call.request, command_mask);
        parsed.provider = provider;
        break :blk parsed;
    };
    const history = try workspace.take(u8, gzip.deflate_history_size + @as(usize, if (gzip_options.deflate.optimal) deflate.optimal_workspace_size else 0));
    if (command_mask == vocabulary.command_mask_read) {
        const input = switch (source_resource.kind) {
            .direct_read => |bytes| bytes,
            .callback_read => try common.materializeSource(.budget, source_resource, workspace, limits.encoded_bytes),
            else => return error.UnsupportedException,
        };
        if (input.len > limits.encoded_bytes) return error.ResourceException;
        if (sink == null) {
            // Read-side header projection: a family-3 selector asks for a first-member
            // fixed-header field; absent selectors keep the decoded-size path.
            const header_requested = options.optNode(call.request, "gzip", "modification_time") != null or
                options.optNode(call.request, "gzip", "operating_system") != null or
                options.optNode(call.request, "gzip", "extra_flags") != null or
                options.optNode(call.request, "gzip", "text") != null or
                options.optNode(call.request, "gzip", "header_crc") != null;
            if (header_requested) {
                const info = try gzip.inspectStream(input);
                if (options.optNode(call.request, "gzip", "operating_system") != null) {
                    response.byte_length = info.operating_system;
                } else if (options.optNode(call.request, "gzip", "extra_flags") != null) {
                    response.byte_length = info.extra_flags;
                } else if (options.optNode(call.request, "gzip", "text") != null) {
                    response.byte_length = info.flags & flag_text;
                } else if (options.optNode(call.request, "gzip", "header_crc") != null) {
                    response.byte_length = info.flags & flag_header_crc;
                } else {
                    response.byte_length = info.modification_time;
                }
                return;
            }
        }
        if (sink) |sink_resource| {
            if (provider == .onprem and sink_resource.kind == .direct_write and sink_resource.hasCapability(resource.capability_bit_write)) {
                // A rejected read must leave the sink untouched, so narrower limits defer to the two-pass route.
                const work_cap = limits.codec_work -| input.len;
                const single_cap = @min(limits.decoded_bytes, work_cap);
                switch (try gzip.decodeSinglePass(input, sink_resource.kind.direct_write, history, provider, single_cap)) {
                    .decoded => |produced| {
                        if (produced > limits.decoded_bytes) return error.ResourceException;
                        response.byte_length = produced;
                        return;
                    },
                    .fallback => |tentative| @memset(sink_resource.kind.direct_write[0..tentative], 0),
                }
            }
        }
        const output_size = try gzip.decodedSize(input, history, provider);
        if (output_size > limits.decoded_bytes) return error.ResourceException;
        if ((std.math.add(usize, input.len, output_size) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.decoded_bytes);
            const produced = gzip.decode(input, &bounded_sink.writer, history, provider) catch |err| return common.mapSinkError(err, call, sink_resource);
            response.byte_length = produced;
        } else {
            response.byte_length = output_size;
        }
    } else if (command_mask == vocabulary.command_mask_write) {
        const output_size = if (sizing == .bounded) blk: {
            const input_len = try common.measureSource(source_resource, limits.decoded_bytes);
            const bound = gzip.encodedSizeBound(input_len, gzip_options);
            if (bound > limits.encoded_bytes) return error.ResourceException;
            if ((std.math.add(usize, input_len, bound) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
            break :blk bound;
        } else try plan.planCountedEncode(source_resource, limits.decoded_bytes, limits.encoded_bytes, limits.codec_work, true, plan.gzipEncodeStream, .{ .history = history, .options = gzip_options });
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(source_resource, limits.decoded_bytes);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.encoded_bytes);
            gzip.encodeStream(&bounded_source.reader, &bounded_sink.writer, history, gzip_options) catch |err| return common.mapSinkError(err, call, sink_resource);
            if (try common.respondWrite(response, sizing, &bounded_sink, limits.encoded_bytes, output_size)) return;
            response.byte_length = output_size;
        } else {
            response.byte_length = output_size;
        }
    } else {
        return error.UnsupportedException;
    }
}

fn serveZlib(running: *Run) Exception!void {
    const call = running.call();
    const response = running.response();
    const source_resource = running.source();
    const sink = running.sink();
    const sizing = running.sizing();
    const limits = running.limits();
    const command_mask = running.commandMask();
    const provider = running.provider();
    try run.requireReplay(running, false);
    const workspace = running.workspace();
    const zlib_options = zlib.Options{ .deflate = try options.parseDeflateOptions(call.request, command_mask), .provider = provider };
    const history = try workspace.take(u8, zlib.deflate_history_size + @as(usize, if (zlib_options.deflate.optimal) deflate.optimal_workspace_size else 0));
    if (command_mask == vocabulary.command_mask_read) {
        const input = switch (source_resource.kind) {
            .direct_read => |bytes| bytes,
            .callback_read => try common.materializeSource(.budget, source_resource, workspace, limits.encoded_bytes),
            else => return error.UnsupportedException,
        };
        if (input.len > limits.encoded_bytes) return error.ResourceException;
        const output_size = try zlib.decodedSize(input, history, provider);
        if (output_size > limits.decoded_bytes) return error.ResourceException;
        if ((std.math.add(usize, input.len, output_size) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.decoded_bytes);
            const produced = zlib.decode(input, &bounded_sink.writer, history, provider) catch |err| return common.mapSinkError(err, call, sink_resource);
            response.byte_length = produced;
        } else {
            response.byte_length = output_size;
        }
    } else if (command_mask == vocabulary.command_mask_write) {
        const output_size = if (sizing == .bounded) blk: {
            const input_len = try common.measureSource(source_resource, limits.decoded_bytes);
            const bound = zlib.encodedSizeBound(input_len, zlib_options);
            if (bound > limits.encoded_bytes) return error.ResourceException;
            if ((std.math.add(usize, input_len, bound) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
            break :blk bound;
        } else try plan.planCountedEncode(source_resource, limits.decoded_bytes, limits.encoded_bytes, limits.codec_work, true, plan.zlibEncodeStream, .{ .history = history, .options = zlib_options });
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(source_resource, limits.decoded_bytes);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.encoded_bytes);
            zlib.encodeStream(&bounded_source.reader, &bounded_sink.writer, history, zlib_options) catch |err| return common.mapSinkError(err, call, sink_resource);
            if (try common.respondWrite(response, sizing, &bounded_sink, limits.encoded_bytes, output_size)) return;
            response.byte_length = output_size;
        } else {
            response.byte_length = output_size;
        }
    } else {
        return error.UnsupportedException;
    }
}

fn serveLzo(running: *Run) Exception!void {
    return bufferCodecHook(lzo, running, lzo.decodeWorkspaceSize(), lzo.encodeWorkspaceSize(), .{});
}

fn serveLz4(running: *Run) Exception!void {
    var lz4_options = try options.parseLz4Options(running.call().request, running.commandMask());
    lz4_options.provider = running.provider();
    lz4_options.max_work = running.limits().codec_work;
    return bufferCodecHook(lz4, running, lz4.decodeWorkspaceSize(), lz4.encodeWorkspaceSize(), lz4_options);
}

fn servePpmd(running: *Run) Exception!void {
    var ppmd_options = try options.parsePpmdOptions(running.call().request);
    ppmd_options.max_work = running.limits().codec_work;
    const mem = ppmd_options.mem_size;
    return bufferCodecHook(ppmd, running, ppmd.decodeWorkspaceSize(mem), ppmd.encodeWorkspaceSize(mem), ppmd_options);
}

// A filter's output spans its input exactly: one staging copy, one in-place pass, the length answered before the transform runs.
fn filterHook(running: *Run, transform: anytype) Exception!void {
    const call = running.call();
    const response = running.response();
    const source_resource = running.source();
    const sink = running.sink();
    const sizing = running.sizing();
    const limits = running.limits();
    const command_mask = running.commandMask();
    const workspace = running.workspace();
    try run.requireReplay(running, false);
    if (command_mask == vocabulary.command_mask_read) {
        const input = try common.materializeSource(.require_size, source_resource, workspace, limits.encoded_bytes);
        if (input.len > limits.decoded_bytes) return error.ResourceException;
        if ((std.math.add(usize, input.len, input.len) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
        if (sink) |sink_resource| {
            try common.requireSinkCapacity(sink_resource, call, input.len);
            if (sink_resource.kind == .direct_write) {
                const output = try common.sinkDirectBuffer(sink_resource, input.len);
                @memcpy(output, input);
                transform.apply(output);
            } else {
                const staging = try workspace.take(u8, input.len);
                @memcpy(staging, input);
                transform.apply(staging);
                try common.commitBytesToSink(sink_resource, call, staging);
            }
        }
        response.byte_length = input.len;
    } else if (command_mask == vocabulary.command_mask_write) {
        const input = try common.materializeSource(.require_size, source_resource, workspace, limits.decoded_bytes);
        if (input.len > limits.encoded_bytes) return error.ResourceException;
        if ((std.math.add(usize, input.len, input.len) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, input.len);
            const target = try common.SinkTarget.open(sink_resource, workspace, input.len);
            @memcpy(target.output, input);
            transform.apply(target.output);
            response.byte_length = try target.publishSized(sink_resource, call, sizing, input.len, input.len);
            return;
        }
        response.byte_length = input.len;
    } else {
        return error.UnsupportedException;
    }
}

fn serveBcj(running: *Run) Exception!void {
    const id = (try options.optCast(running.call().request, "bcj", "kind", u8)) orelse return error.CallException;
    const kind = bcj.fromId(id) orelse return error.CallException;
    const start_offset = (try options.optCast(running.call().request, "bcj", "start_offset", u32)) orelse 0;
    if (start_offset % bcj.alignment(kind) != 0) return error.CallException;
    const encode = running.commandMask() == vocabulary.command_mask_write;
    return filterHook(running, struct {
        kind: bcj.Kind,
        start_offset: u32,
        encode: bool,
        pub fn apply(self: @This(), bytes: []u8) void {
            if (self.encode) bcj.encode(self.kind, self.start_offset, bytes) else bcj.decode(self.kind, self.start_offset, bytes);
        }
    }{ .kind = kind, .start_offset = start_offset, .encode = encode });
}

fn serveDelta(running: *Run) Exception!void {
    // The selector carries the wire distance 1..256; the leaf takes one less.
    var distance: u8 = 0;
    if (options.optNode(running.call().request, "delta", "distance")) |node| {
        if (node.value_low < 1 or node.value_low > 256) return error.CallException;
        distance = @intCast(node.value_low - 1);
    }
    const encode = running.commandMask() == vocabulary.command_mask_write;
    return filterHook(running, struct {
        distance: u8,
        encode: bool,
        pub fn apply(self: @This(), bytes: []u8) void {
            if (self.encode) delta.encode(bytes, self.distance) else delta.decode(bytes, self.distance);
        }
    }{ .distance = distance, .encode = encode });
}

fn serveBcj2(running: *Run) Exception!void {
    const call = running.call();
    const response = running.response();
    const source_resource = running.source();
    const sink = running.sink();
    const limits = running.limits();
    const command_mask = running.commandMask();
    const workspace = running.workspace();
    if (command_mask != vocabulary.command_mask_read) return error.UnsupportedException;
    try run.requireReplay(running, false);
    // The source is the main stream; the request carries the three
    // auxiliary streams, and the decode declares its output size.
    const main = try common.materializeSource(.require_size, source_resource, workspace, limits.encoded_bytes);
    const call_stream = (try options.optBytes(call.request, "bcj2", "call_stream")) orelse return error.CallException;
    const jump_stream = (try options.optBytes(call.request, "bcj2", "jump_stream")) orelse return error.CallException;
    const rc_stream = (try options.optBytes(call.request, "bcj2", "rc_stream")) orelse return error.CallException;
    const unpacked = (try options.optCast(call.request, "bcj2", "unpacked_size", u64)) orelse return error.CallException;
    const output_size = std.math.cast(usize, unpacked) orelse return error.ResourceException;
    if (output_size > limits.decoded_bytes) return error.ResourceException;
    var total = main.len;
    for ([_][]const u8{ call_stream, jump_stream, rc_stream }) |stream| {
        total = std.math.add(usize, total, stream.len) catch return error.ResourceException;
    }
    total = std.math.add(usize, total, output_size) catch return error.ResourceException;
    if (total > limits.codec_work) return error.ResourceException;
    if (sink) |sink_resource| {
        try common.requireSinkCapacity(sink_resource, call, output_size);
        const produced = if (sink_resource.kind == .direct_write) blk: {
            const output = try common.sinkDirectBuffer(sink_resource, output_size);
            break :blk try bcj2.decode(main, call_stream, jump_stream, rc_stream, output);
        } else blk: {
            const staging = try workspace.take(u8, output_size);
            const produced = try bcj2.decode(main, call_stream, jump_stream, rc_stream, staging);
            try common.commitBytesToSink(sink_resource, call, staging[0..produced]);
            break :blk produced;
        };
        if (produced != output_size) return error.DataException;
        response.byte_length = produced;
        return;
    }
    response.byte_length = output_size;
}

fn serveZstdSeekable(running: *Run) Exception!void {
    const call = running.call();
    const response = running.response();
    const source_resource = running.source();
    const sink = running.sink();
    const sizing = running.sizing();
    const limits = running.limits();
    const command_mask = running.commandMask();
    const provider = running.provider();
    try run.requireReplay(running, false);
    var seekable_options = zstd_seekable.Options{ .provider = provider };
    if (command_mask == vocabulary.command_mask_write or command_mask == vocabulary.command_mask_query) {
        if (try options.optCast(call.request, "zstd-seekable", "frame_size", u32)) |frame_size| {
            if (frame_size < zstd_seekable.frame_size_min or frame_size > zstd_seekable.frame_size_max) return error.CallException;
            seekable_options.frame_size = frame_size;
        }
    }
    const frame_options = zstd_seekable.frameOptions(seekable_options);
    const workspace = running.workspace();
    if (command_mask == vocabulary.command_mask_read) {
        const input = try common.materializeSource(.budget, source_resource, workspace, limits.encoded_bytes);
        if (input.len > limits.encoded_bytes) return error.ResourceException;
        const history = try workspace.take(u8, std.math.add(usize, @as(usize, frame_options.window_size), zstd.block_size_max) catch return error.ResourceException);
        const output_size = try zstd_seekable.decodedSize(input, history, seekable_options);
        if (output_size > limits.decoded_bytes) return error.ResourceException;
        if ((std.math.add(usize, input.len, output_size) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            const target = try common.SinkTarget.open(sink_resource, workspace, output_size);
            var fixed = std.Io.Writer.fixed(target.output);
            try zstd_seekable.decode(input, &fixed, history, seekable_options);
            _ = try target.publish(sink_resource, call, output_size);
        }
        response.byte_length = output_size;
    } else if (command_mask == vocabulary.command_mask_write) {
        const history = try workspace.take(u8, std.math.add(usize, @as(usize, frame_options.window_size), zstd.block_size_max) catch return error.ResourceException);
        const workspace_u32 = try workspace.take(u32, zstd.encoderWorkspaceU32Count(0, seekable_options.frame_size, frame_options));
        const input = try common.materializeSource(.require_size, source_resource, workspace, limits.decoded_bytes);
        const entries = try workspace.take(zstd_seekable.FrameEntry, zstd_seekable.frameCountFor(input.len, seekable_options));
        const output_size = if (sizing == .bounded) blk: {
            const bound = zstd_seekable.encodedSizeBound(input.len, seekable_options);
            if (bound > limits.encoded_bytes) return error.ResourceException;
            break :blk bound;
        } else blk: {
            var counter = measurement.Counter.init(null);
            try zstd_seekable.encodeToWriter(input, &counter.writer, history, workspace_u32, entries, seekable_options);
            const exact = try measurement.measuredLength(&counter);
            if (exact > limits.encoded_bytes) return error.ResourceException;
            break :blk exact;
        };
        if ((std.math.add(usize, input.len, output_size) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            const target = try common.SinkTarget.open(sink_resource, workspace, output_size);
            const produced = try zstd_seekable.encode(input, target.output, history, workspace_u32, entries, seekable_options);
            response.byte_length = try target.publishSized(sink_resource, call, sizing, output_size, produced);
            return;
        }
        response.byte_length = output_size;
    } else {
        return error.UnsupportedException;
    }
}

fn serveZstd(running: *Run) Exception!void {
    const call = running.call();
    const response = running.response();
    const source_resource = running.source();
    const sink = running.sink();
    const sizing = running.sizing();
    const limits = running.limits();
    const command_mask = running.commandMask();
    const provider = running.provider();
    try run.requireReplay(running, true);
    const zstd_options = blk: {
        var parsed = try options.parseZstdOptions(call.request, command_mask);
        parsed.provider = provider;
        break :blk parsed;
    };
    const window = zstd_options.window_size;
    const dictionary = zstd_options.dictionary;
    const window_history = std.math.add(usize, @as(usize, window), zstd.block_size_max) catch return error.ResourceException;
    const dictionary_history = if (dictionary) |dict| dict.len else 0;
    const history_base_size = std.math.add(usize, window_history, dictionary_history) catch return error.ResourceException;
    const workspace = running.workspace();
    if (command_mask == vocabulary.command_mask_read) {
        const input = try common.materializeSource(.replay, source_resource, workspace, limits.encoded_bytes);
        var planned_history: ?[]u8 = null;
        const output_size = zstd.frameContentSize(input, window) catch |err| switch (err) {
            error.UnsupportedException => blk: {
                const history = try workspace.take(u8, history_base_size);
                planned_history = history;
                break :blk try zstd_seam.decodedSize(provider, input, history, zstd_options);
            },
            else => return err,
        };
        if (output_size > limits.decoded_bytes) return error.ResourceException;
        if ((std.math.add(usize, input.len, output_size) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            var source_reader = std.Io.Reader.fixed(input);
            if (dictionary == null and output_size >= history_base_size) {
                if (sink_resource.kind == .direct_write and common.sinkCapacity(sink_resource) >= (std.math.add(usize, output_size, zstd.block_size_max) catch return error.ResourceException)) {
                    // In-place decode needs output plus one block of window slack;
                    // a corrupt frame can leave a tentative prefix.
                    const output = try common.sinkDirectBuffer(sink_resource, std.math.add(usize, output_size, zstd.block_size_max) catch return error.ResourceException);
                    var in_place_options = zstd_options;
                    in_place_options.max_decoded_bytes = output_size;
                    _ = zstd_seam.decodeInPlace(provider, &source_reader, output, in_place_options) catch |err| {
                        // A corrupt frame must not leave a tentative prefix and
                        // working suffix in the caller's buffer.
                        @memset(output, 0);
                        return err;
                    };
                } else {
                    const staging = try workspace.take(u8, std.math.add(usize, output_size, zstd.block_size_max) catch return error.ResourceException);
                    var in_place_options = zstd_options;
                    in_place_options.max_decoded_bytes = output_size;
                    _ = try zstd_seam.decodeInPlace(provider, &source_reader, staging, in_place_options);
                    try common.commitBytesToSink(sink_resource, call, staging[0..output_size]);
                }
            } else {
                const history = planned_history orelse try workspace.take(u8, history_base_size);
                const staging = try workspace.take(u8, output_size);
                var decode_sink = std.Io.Writer.fixed(staging);
                _ = try zstd_seam.decodeStream(provider, &source_reader, &decode_sink, history, zstd_options);
                try common.commitBytesToSink(sink_resource, call, staging);
            }
        }
        response.byte_length = output_size;
    } else if (command_mask == vocabulary.command_mask_write) {
        const dict_len = if (dictionary) |dict| dict.len else 0;
        const input_len = try common.measureSource(source_resource, limits.decoded_bytes);
        const frame_budget = if (zstd.useDfast(zstd_options) or zstd.useRowMatch(zstd_options))
            @min(input_len, zstd.encoder_frame_size_max)
        else
            @min(window, zstd.encoder_frame_size_max);
        const history = try workspace.take(u8, zstd_sizing.encodeHistoryLen(input_len, dict_len, zstd_options));
        const encoder_workspace = try workspace.take(u32, zstd.encoderWorkspaceU32Count(dict_len, frame_budget, zstd_options));
        var encode_options = zstd_options;
        encode_options.max_encoded_bytes = limits.encoded_bytes;
        encode_options.max_decoded_bytes = limits.decoded_bytes;
        const output_size = if (sizing == .bounded) blk: {
            const bound = zstd.encodedSizeBound(input_len, encode_options);
            if (bound > limits.encoded_bytes) return error.ResourceException;
            if ((std.math.add(usize, input_len, bound) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
            break :blk bound;
        } else try plan.planCountedEncode(source_resource, limits.decoded_bytes, limits.encoded_bytes, limits.codec_work, false, plan.zstdEncodeStream, .{ .history = history, .workspace = encoder_workspace, .options = encode_options });
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            const target = try common.SinkTarget.open(sink_resource, workspace, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(source_resource, limits.decoded_bytes);
            var sink_writer = std.Io.Writer.fixed(target.output);
            const produced = try zstd.encodeStream(&bounded_source.reader, &sink_writer, history, encoder_workspace, encode_options);
            response.byte_length = try target.publishSized(sink_resource, call, sizing, output_size, produced);
            return;
        }
        response.byte_length = output_size;
    } else {
        return error.UnsupportedException;
    }
}

fn serveBzip2(running: *Run) Exception!void {
    var bzip2_options = try options.parseBzip2Options(running.call().request, running.commandMask());
    bzip2_options.max_work = running.limits().codec_work;
    bzip2_options.provider = running.provider();
    return bufferCodecHook(bzip2, running, bzip2.decodeWorkspaceSize(bzip2.block_size_max), bzip2.encodeWorkspaceSize(bzip2_options.block_size), bzip2_options);
}

fn serveBrotli(running: *Run) Exception!void {
    const brotli_options = try options.parseBrotliOptions(running.call().request, running.commandMask());
    // The encoder lands with the dictionary support; read serves now.
    return bufferCodecHook(brotli, running, brotli.decodeWorkspaceSize(brotli_options), brotli.encodeWorkspaceSize(brotli_options), brotli_options);
}

fn lzmaFamilyHook(comptime Codec: type, running: *Run) Exception!void {
    const call = running.call();
    const limits = running.limits();
    const dictionary_size = try options.parseLzmaDictionary(call.request);
    const properties = lzma2.defaultProperties(dictionary_size);
    const params = try options.parseLzmaMatchParams(call.request, running.commandMask());
    if (Codec == lzma) {
        const encode_workspace = if (params.match_finder == .bt4) lzma.encodeWorkspaceSizeBt(properties) else lzma.encodeWorkspaceSize(properties);
        return bufferCodecHook(lzma, running, lzma.decodeWorkspaceSize(properties), encode_workspace, .{
            .properties = properties,
            .unpack_size = null,
            .marker_required = true,
            .max_work = limits.codec_work,
            .match_finder_depth = params.match_finder_depth,
            .lazy = params.lazy,
            .nice_len = params.nice_len,
            .match_finder = params.match_finder,
        });
    }
    const encode_workspace = if (params.match_finder == .bt4) lzma2.encodeWorkspaceSizeBt(dictionary_size) else lzma2.encodeWorkspaceSize(dictionary_size);
    return bufferCodecHook(lzma2, running, lzma2.decodeWorkspaceSize(dictionary_size), encode_workspace, .{
        .dictionary_size = dictionary_size,
        .properties = properties,
        .max_work = limits.codec_work,
        .match_finder_depth = params.match_finder_depth,
        .lazy = params.lazy,
        .nice_len = params.nice_len,
        .match_finder = params.match_finder,
    });
}

fn serveLzma(running: *Run) Exception!void {
    return lzmaFamilyHook(lzma, running);
}

fn serveLzma2(running: *Run) Exception!void {
    return lzmaFamilyHook(lzma2, running);
}

fn bufferCodecHook(comptime Codec: type, running: *Run, decode_workspace: usize, encode_workspace: usize, codec_options: Codec.Options) Exception!void {
    const call = running.call();
    const response = running.response();
    const source_resource = running.source();
    const sink = running.sink();
    const sizing = running.sizing();
    const limits = running.limits();
    const command_mask = running.commandMask();
    const workspace = running.workspace();
    try run.requireReplay(running, false);
    if (command_mask == vocabulary.command_mask_read) {
        const scratch = try workspace.take(u8, decode_workspace);
        const input = try common.materializeSource(.require_size, source_resource, workspace, limits.encoded_bytes);
        if (sink) |sink_resource| {
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.UnsupportedException;
            var direct_route = false;
            if (Codec == lz4 and sink_resource.kind == .direct_write) {
                // Decode into staging sized by the declared content size: a rejected
                // read leaves the sink untouched, like the counted route.
                if (try lz4.frameContentSize(input)) |declared| {
                    const size = std.math.cast(usize, declared) orelse return error.ResourceException;
                    if (size <= limits.decoded_bytes and (std.math.add(usize, input.len, size) catch return error.ResourceException) <= limits.codec_work and size <= workspace.remaining()) {
                        const staging = try workspace.take(u8, size);
                        if (codecDecodeDirectInPlace(Codec, input, staging, scratch, codec_options)) |produced| {
                            if (produced > limits.decoded_bytes) return error.ResourceException;
                            try common.requireSinkCapacity(sink_resource, call, produced);
                            try common.commitBytesToSink(sink_resource, call, staging[0..produced]);
                            response.byte_length = produced;
                            direct_route = true;
                        } else |err| switch (err) {
                            // A span overrun means the declared size lied small: the measured
                            // route counts the true size, reporting the exact status.
                            error.CapacityException => {},
                            else => return err,
                        }
                    }
                }
            }
            if (!direct_route and sink_resource.kind == .direct_write and common.sinkCapacity(sink_resource) <= limits.decoded_bytes and try codecKnownOutputSize(Codec, codec_options) == null and (Codec == lzma or Codec == bzip2)) {
                // lzma2 is excluded: chunk headers give its size cheaply. The span
                // bounds the decode, so it must fit the limit.
                const capacity = common.sinkCapacity(sink_resource);
                if ((std.math.add(usize, input.len, capacity) catch return error.ResourceException) <= limits.codec_work and capacity <= workspace.remaining()) {
                    // One decode into workspace staging: a rejected read leaves the
                    // sink untouched, exactly like the counted route.
                    const staging = try workspace.take(u8, capacity);
                    if (codecDecodeDirect(Codec, input, staging, scratch, codec_options)) |produced| {
                        if (produced > limits.decoded_bytes) return error.ResourceException;
                        try common.requireSinkCapacity(sink_resource, call, produced);
                        try common.commitBytesToSink(sink_resource, call, staging[0..produced]);
                        response.byte_length = produced;
                        direct_route = true;
                    } else |err| return err;
                }
            }
            if (!direct_route) {
                const output_size = if (try codecKnownOutputSize(Codec, codec_options)) |size| size else try codecDecodedSize(Codec, input, scratch, codec_options);
                if (output_size > limits.decoded_bytes) return error.ResourceException;
                if ((std.math.add(usize, input.len, output_size) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
                try common.requireSinkCapacity(sink_resource, call, output_size);
                // A short decode leaves stale bytes in the tail.
                const produced = if (sink_resource.kind == .direct_write) blk: {
                    const output = try common.sinkDirectBuffer(sink_resource, output_size);
                    break :blk try codecDecodeDirectInPlace(Codec, input, output, scratch, codec_options);
                } else blk: {
                    const staging = try workspace.take(u8, output_size);
                    var fixed_writer = std.Io.Writer.fixed(staging);
                    codecDecodeToWriter(Codec, input, &fixed_writer, scratch, codec_options) catch |err| return common.mapSinkError(err, call, sink_resource);
                    try common.commitBytesToSink(sink_resource, call, staging[0..fixed_writer.end]);
                    break :blk fixed_writer.end;
                };
                if (produced > limits.decoded_bytes) return error.ResourceException;
                response.byte_length = produced;
            }
        } else {
            const output_size = if (try codecKnownOutputSize(Codec, codec_options)) |size| size else try codecDecodedSize(Codec, input, scratch, codec_options);
            if (output_size > limits.decoded_bytes) return error.ResourceException;
            if ((std.math.add(usize, input.len, output_size) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
            response.byte_length = output_size;
        }
    } else if (command_mask == vocabulary.command_mask_write) {
        const scratch = try workspace.take(u8, encode_workspace);
        const input = try common.materializeSource(.require_size, source_resource, workspace, limits.decoded_bytes);
        const output_size = if (sizing == .bounded) blk: {
            // A codec without an analytic output bound refuses a bounded
            // write; its descriptor advertises measured sizing.
            if (!@hasDecl(Codec, "encodedSizeBound")) return error.UnsupportedException;
            break :blk Codec.encodedSizeBound(input.len);
        } else try Codec.requiredSize(input, scratch, codec_options);
        if (output_size > limits.encoded_bytes) return error.ResourceException;
        if ((std.math.add(usize, input.len, output_size) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            const target = try common.SinkTarget.open(sink_resource, workspace, output_size);
            const produced = try Codec.encode(input, target.output, scratch, codec_options);
            response.byte_length = try target.publishSized(sink_resource, call, sizing, output_size, produced);
            return;
        }
        response.byte_length = output_size;
    } else {
        return error.UnsupportedException;
    }
}

fn codecKnownOutputSize(comptime Codec: type, codec_options: Codec.Options) Exception!?usize {
    if (!@hasField(Codec.Options, "unpack_size")) return null;
    const size = codec_options.unpack_size orelse return null;
    return std.math.cast(usize, size) orelse error.ResourceException;
}

fn codecDecodedSize(comptime Codec: type, input: []const u8, scratch: []u8, codec_options: Codec.Options) Exception!usize {
    if (Codec == bzip2) return bzip2.decodedSize(input, scratch, codec_options.provider);
    return Codec.decodedSize(input, scratch, codec_options);
}

fn codecDecodeToWriter(comptime Codec: type, input: []const u8, writer: *std.Io.Writer, scratch: []u8, codec_options: Codec.Options) Exception!void {
    if (Codec == bzip2) return bzip2.decodeToWriter(input, writer, scratch, codec_options.provider);
    return Codec.decodeToWriter(input, writer, scratch, codec_options);
}

fn codecDecodeDirect(comptime Codec: type, input: []const u8, output: []u8, scratch: []u8, codec_options: Codec.Options) Exception!usize {
    if (Codec == bzip2) return bzip2.decode(input, output, scratch, codec_options.provider);
    return Codec.decode(input, output, scratch, codec_options);
}

fn codecDecodeDirectInPlace(comptime Codec: type, input: []const u8, output: []u8, scratch: []u8, codec_options: Codec.Options) Exception!usize {
    if (Codec == bzip2) return bzip2.decode(input, output, scratch, codec_options.provider);
    const result = try Codec.decodeInPlace(input, output, scratch, codec_options);
    return if (Codec == lzma2) result.produced else result;
}

fn serveLzmaFile(running: *Run) Exception!void {
    const call = running.call();
    const response = running.response();
    const source_resource = running.source();
    const sink = running.sink();
    const sizing = running.sizing();
    const limits = running.limits();
    const command_mask = running.commandMask();
    const provider = running.provider();
    const workspace = running.workspace();
    try run.requireReplay(running, false);
    if (command_mask == vocabulary.command_mask_read) {
        const input = try common.materializeSource(.require_size, source_resource, workspace, limits.encoded_bytes);
        if (input.len < lzma_file.header_size) return error.DataException;
        if (sink == null) {
            if (options.optNode(call.request, "lzma-file", "properties") != null) {
                // Read-side header projection: the properties byte of the
                // lzma-alone header, without decoding.
                response.byte_length = try lzma_file.inspectProperties(input);
                return;
            }
        }
        const decode_options = try lzma_file.decodeOptions(input);
        const scratch = try workspace.take(u8, lzma.decodeWorkspaceSize(decode_options.properties));
        const output_size = if (decode_options.unpack_size) |size| std.math.cast(usize, size) orelse return error.ResourceException else try lzma_file.decodedSize(input, scratch, provider);
        if (output_size > limits.decoded_bytes) return error.ResourceException;
        if ((std.math.add(usize, input.len, output_size) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            if (sink_resource.kind == .direct_write) {
                const output = try common.sinkDirectBuffer(sink_resource, output_size);
                const produced = try lzma_file.decodeInPlace(input, output, scratch, provider);
                if (produced > limits.decoded_bytes) return error.ResourceException;
                response.byte_length = produced;
                return;
            } else {
                var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.decoded_bytes);
                lzma_file.decodeToWriter(input, &bounded_sink.writer, scratch, provider) catch |err| return common.mapSinkError(err, call, sink_resource);
            }
        }
        response.byte_length = output_size;
    } else if (command_mask == vocabulary.command_mask_write) {
        const dictionary = try options.parseLzmaFileDictionary(call.request);
        var encode_options = try lzma_file.encodeOptions(dictionary);
        const params = try options.parseLzmaMatchParams(call.request, command_mask);
        encode_options.match_finder_depth = params.match_finder_depth;
        encode_options.lazy = params.lazy;
        encode_options.nice_len = params.nice_len;
        encode_options.match_finder = params.match_finder;
        const encode_workspace = if (params.match_finder == .bt4) lzma.encodeWorkspaceSizeBt(encode_options.properties) else lzma.encodeWorkspaceSize(encode_options.properties);
        const scratch = try workspace.take(u8, encode_workspace);
        const input = try common.materializeSource(.require_size, source_resource, workspace, limits.decoded_bytes);
        encode_options.unpack_size = input.len;
        const output_size = if (sizing == .bounded) lzma_file.encodedSizeBound(input.len) else try lzma_file.requiredSize(input, scratch, encode_options);
        if (output_size > limits.encoded_bytes) return error.ResourceException;
        if ((std.math.add(usize, input.len, output_size) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            const target = try common.SinkTarget.open(sink_resource, workspace, output_size);
            const produced = try lzma_file.encode(input, target.output, scratch, encode_options);
            response.byte_length = try target.publishSized(sink_resource, call, sizing, output_size, produced);
            return;
        }
        response.byte_length = output_size;
    } else {
        return error.UnsupportedException;
    }
}

fn serveXz(running: *Run) Exception!void {
    const call = running.call();
    const response = running.response();
    const source_resource = running.source();
    const sink = running.sink();
    const sizing = running.sizing();
    const limits = running.limits();
    const command_mask = running.commandMask();
    const provider = running.provider();
    const workspace = running.workspace();
    try run.requireReplay(running, true);
    const dictionary_size = try options.parseLzmaDictionary(call.request);
    const check = try options.parseXzCheck(options.optNode(call.request, "xz", "check"));
    const filters = try options.parseXzFilters(options.optNode(call.request, "xz", "filters"));
    var delta_distance: u16 = 1;
    if (filters == .delta) {
        // The delta component's own selector carries the distance; the block
        // header round-trips it so decoders apply the same transform.
        if (options.optNode(call.request, "delta", "distance")) |node| {
            if (node.value_low < 1 or node.value_low > 256) return error.CallException;
            delta_distance = @intCast(node.value_low);
        }
    }
    const params = try options.parseLzmaMatchParams(call.request, command_mask);
    const block_size = std.math.cast(u32, node_graph.parseU64(options.optNode(call.request, "xz", "block_size"))) orelse return error.CallException;
    if (command_mask == vocabulary.command_mask_read) {
        const scratch = try workspace.take(u8, xz.decodeWorkspaceSize(dictionary_size));
        const input = try common.materializeSource(.require_size, source_resource, workspace, limits.encoded_bytes);
        if (input.len > limits.encoded_bytes) return error.ResourceException;
        if (sink == null) {
            if (options.optNode(call.request, "xz", "check") != null) {
                // Read-side header projection: the check selector asks for the
                // stream's check type id without decoding anything.
                response.byte_length = try xz.inspectCheck(input, provider);
                return;
            }
        }
        const output_size = try xz.decodedSize(input, scratch, provider);
        if (output_size > limits.decoded_bytes) return error.ResourceException;
        if ((std.math.add(usize, input.len, output_size) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            const staging = try workspace.take(u8, output_size);
            _ = try xz.decodeInPlace(input, staging, scratch, provider);
            try common.commitBytesToSink(sink_resource, call, staging);
        }
        response.byte_length = output_size;
    } else if (command_mask == vocabulary.command_mask_write) {
        const input = try common.materializeSource(.require_size, source_resource, workspace, limits.decoded_bytes);
        if (input.len > limits.decoded_bytes) return error.ResourceException;
        const encode_workspace = if (params.match_finder == .bt4) xz.encodeWorkspaceSizeBt(dictionary_size) else xz.encodeWorkspaceSize(dictionary_size);
        // Beyond the encoder workspace: index records per block, plus the
        // 1:1 filter staging when a filter chain is active.
        const records = xz.blockRecordScratchSize(input.len, block_size);
        const staged = std.math.add(usize, encode_workspace, records) catch return error.ResourceException;
        const filters_size = if (filters != .none) input.len else 0;
        const scratch_size = std.math.add(usize, staged, filters_size) catch return error.ResourceException;
        const scratch = try workspace.take(u8, scratch_size);
        const xz_options = xz.Options{
            .dictionary_size = dictionary_size,
            .check = check,
            .filters = filters,
            .delta_distance = delta_distance,
            .match_finder_depth = params.match_finder_depth,
            .lazy = params.lazy,
            .nice_len = params.nice_len,
            .match_finder = params.match_finder,
            .block_size = block_size,
            .provider = provider,
        };
        const output_size = if (sizing == .bounded) xz.encodedSizeBound(input.len, xz_options.block_size) else try xz.requiredSize(input, scratch, xz_options);
        if (output_size > limits.encoded_bytes) return error.ResourceException;
        if ((std.math.add(usize, input.len, output_size) catch return error.ResourceException) > limits.codec_work) return error.ResourceException;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            const target = try common.SinkTarget.open(sink_resource, workspace, output_size);
            const produced = try xz.encode(input, target.output, scratch, xz_options);
            response.byte_length = try target.publishSized(sink_resource, call, sizing, output_size, produced);
            return;
        }
        response.byte_length = output_size;
    } else {
        return error.UnsupportedException;
    }
}

// Here hooks.zig resolves `<tag>Hook`; each wrapper is the one place
// a bound name meets the shape the map expects.
fn bind(comptime hook: run.Hook) *const fn (*Invocation) Exception!void {
    return struct {
        fn entry(invocation: *Invocation) Exception!void {
            return run.serve(invocation, hook);
        }
    }.entry;
}

pub const testHook = bind(echo.hook);
pub const deflateHook = bind(serveDeflate);
pub const gzipHook = bind(serveGzip);
pub const zlibHook = bind(serveZlib);
pub const lzoHook = bind(serveLzo);
pub const lz4Hook = bind(serveLz4);
pub const ppmdHook = bind(servePpmd);
pub const bcjHook = bind(serveBcj);
pub const bcj2Hook = bind(serveBcj2);
pub const deltaHook = bind(serveDelta);
pub const zstd_seekableHook = bind(serveZstdSeekable);
pub const zdictHook = bind(zdict.hook);
pub const zstdHook = bind(serveZstd);
pub const bzip2Hook = bind(serveBzip2);
pub const brotliHook = bind(serveBrotli);
pub const lzmaHook = bind(serveLzma);
pub const lzma2Hook = bind(serveLzma2);
pub const lzma_fileHook = bind(serveLzmaFile);
pub const xzHook = bind(serveXz);
