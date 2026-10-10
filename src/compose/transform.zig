const std = @import("std");

const node_graph = @import("../kernel/node.zig");
const measurement = @import("../common/primitive/measurement.zig");
const resource = @import("../kernel/resource.zig");
const Resource = resource.Resource;
const Limits = resource.Limits;
const gzip = @import("../grammar/gzip.zig");
const zlib = @import("../grammar/zlib.zig");
const zstd_seekable = @import("../grammar/zstd_seekable.zig");
const lzma_file = @import("../grammar/lzma.zig");
const xz = @import("../grammar/xz.zig");
const discovery = @import("../kernel/discovery.zig");
const abi = @import("../kernel/envelope.zig");
const Node = abi.Node;
const Call = abi.Call;
const vocabulary = @import("../kernel/vocabulary.zig");
const Failure = vocabulary.Failure;
const bzip2 = @import("../leaf/bzip2.zig");
const deflate = @import("../leaf/deflate.zig");
const lz4 = @import("../leaf/lz4.zig");
const lzma = @import("../leaf/lzma.zig");
const lzma2 = @import("../leaf/lzma2.zig");
const zstd = @import("../leaf/zstd.zig");
const common = @import("common.zig");
const zstd_sizing = @import("sizing.zig");

const deflate_options: deflate.Options = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 8 };

fn requireReplay(source: *Resource, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, comptime confirmed: bool) Failure!void {
    if (sizing != .measured and sizing != .bounded) return error.Unsupported;
    const expected: vocabulary.CommitMode = if (confirmed) .confirmed else .tentative;
    if (commit != expected) return error.Unsupported;
    if (!source.hasCapability(resource.capability_bit_read) or !source.hasCapability(resource.capability_bit_replay)) return error.Unsupported;
}

pub fn testHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    _ = command_mask;
    const source_resource = source orelse return error.InvalidCall;
    const sink_resource = sink orelse return error.InvalidCall;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    const output_size = try common.planOutputSize(source_resource, sizing, limits, &workspace);
    try common.requireSinkCapacity(sink_resource, call, output_size);
    const staging_required: usize = if (commit == .confirmed) output_size else 0;
    if (workspace.bytes.len < staging_required) {
        common.writeCapacityDiagnostic(call, staging_required, workspace.bytes.len);
        return error.InsufficientCapacity;
    }
    if (commit == .confirmed) {
        const staging = try workspace.take(u8, output_size);
        var offset: usize = 0;
        while (offset < staging.len) {
            const n = try source_resource.read(staging[offset..]);
            if (n == 0) return error.IoFailure;
            offset += n;
        }
        if (staging.len > 0 and staging[staging.len - 1] == 0xff) return error.IntegrityFailure;
        try common.commitBytesToSink(sink_resource, call, staging);
    } else {
        var buffer: [4096]u8 = undefined;
        var remaining = output_size;
        while (remaining > 0) {
            const chunk = @min(remaining, buffer.len);
            const n = try source_resource.read(buffer[0..chunk]);
            if (n == 0) return error.IoFailure;
            try common.commitBytesToSink(sink_resource, call, buffer[0..n]);
            remaining -= n;
        }
    }
    response.byte_length = output_size;
}

pub fn deflateHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const source_resource = source orelse return error.InvalidCall;
    try requireReplay(source_resource, sizing, commit, false);
    const deflate_opts = try parseDeflateOptions(call.request, command_mask);
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    const history = try workspace.take(u8, deflate.history_size + @as(usize, if (deflate_opts.optimal) deflate.optimal_workspace_size else 0));
    if (command_mask == vocabulary.command_mask_read) {
        const output_size = try planDeflateDecode(source_resource, history, limits.encoded_bytes, limits.decoded_bytes);
        if (sink) |sink_resource| {
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(sink_resource, call, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(source_resource, limits.encoded_bytes);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.decoded_bytes);
            var inflater = deflate.Decompress.init(&bounded_source.reader, history);
            _ = inflater.reader.streamRemaining(&bounded_sink.writer) catch |err| return common.mapSinkError(switch (err) {
                error.WriteFailed => error.IoFailure,
                else => error.InvalidData,
            }, call, sink_resource);
        }
        response.byte_length = output_size;
    } else if (command_mask == vocabulary.command_mask_write) {
        const output_size = if (sizing == .bounded) blk: {
            const input_len = try measureSourceLength(source_resource, limits.decoded_bytes);
            const bound = deflate.encodedSizeBound(input_len);
            if (bound > limits.encoded_bytes) return error.ResourceLimit;
            break :blk bound;
        } else try planCountedEncode(source_resource, limits.decoded_bytes, limits.encoded_bytes, true, deflateEncodeStream, .{ .history = history, .options = deflate_opts });
        if (sink) |sink_resource| {
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(sink_resource, call, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(source_resource, limits.decoded_bytes);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.encoded_bytes);
            var compressor = try deflate.Compress.init(&bounded_sink.writer, history, deflate_opts);
            _ = std.Io.Reader.streamRemaining(&bounded_source.reader, &compressor.writer) catch return common.mapSinkError(error.IoFailure, call, sink_resource);
            compressor.finish() catch return common.mapSinkError(error.IoFailure, call, sink_resource);
            if (sizing == .bounded) {
                response.byte_length = try common.boundedProduced(&bounded_sink, limits.encoded_bytes, output_size);
                return;
            }
        }
        response.byte_length = output_size;
    } else {
        return error.Unsupported;
    }
}

pub fn gzipHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const source_resource = source orelse return error.InvalidCall;
    try requireReplay(source_resource, sizing, commit, false);
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    const options = blk: {
        var parsed = try parseGzipOptions(call.request, command_mask);
        parsed.provider = plan.provider;
        break :blk parsed;
    };
    const history = try workspace.take(u8, gzip.deflate_history_size + @as(usize, if (options.deflate.optimal) deflate.optimal_workspace_size else 0));
    if (command_mask == vocabulary.command_mask_read) {
        const input = switch (source_resource.kind) {
            .direct_read => |bytes| bytes,
            .callback_read => try common.materializeSource(.budget, source_resource, &workspace, limits.encoded_bytes),
            else => return error.Unsupported,
        };
        if (input.len > limits.encoded_bytes) return error.ResourceLimit;
        if (sink) |sink_resource| {
            if (sink_resource.kind == .direct_write and sink_resource.hasCapability(resource.capability_bit_write)) {
                // Single-pass: fallback recomputes exact size before further writes, so capacity never fails post-write. Carve-out: aborted fast path may leave a tentative prefix.
                switch (try gzip.decodeSinglePass(input, sink_resource.kind.direct_write, history, plan.provider)) {
                    .decoded => |produced| {
                        if (produced > limits.decoded_bytes) return error.ResourceLimit;
                        response.byte_length = produced;
                        return;
                    },
                    .fallback => {},
                }
            }
        }
        const output_size = try gzip.decodedSize(input, history, plan.provider);
        if (output_size > limits.decoded_bytes) return error.ResourceLimit;
        if (sink) |sink_resource| {
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(sink_resource, call, output_size);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.decoded_bytes);
            const produced = gzip.decode(input, &bounded_sink.writer, history, plan.provider) catch |err| return common.mapSinkError(err, call, sink_resource);
            response.byte_length = produced;
        } else {
            response.byte_length = output_size;
        }
    } else if (command_mask == vocabulary.command_mask_write) {
        const output_size = if (sizing == .bounded) blk: {
            const input_len = try measureSourceLength(source_resource, limits.decoded_bytes);
            const bound = gzip.encodedSizeBound(input_len, options);
            if (bound > limits.encoded_bytes) return error.ResourceLimit;
            break :blk bound;
        } else try planCountedEncode(source_resource, limits.decoded_bytes, limits.encoded_bytes, true, gzipEncodeStream, .{ .history = history, .options = options });
        if (sink) |sink_resource| {
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(sink_resource, call, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(source_resource, limits.decoded_bytes);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.encoded_bytes);
            gzip.encodeStream(&bounded_source.reader, &bounded_sink.writer, history, options) catch |err| return common.mapSinkError(err, call, sink_resource);
            if (sizing == .bounded) {
                response.byte_length = try common.boundedProduced(&bounded_sink, limits.encoded_bytes, output_size);
                return;
            }
            response.byte_length = output_size;
        } else {
            response.byte_length = output_size;
        }
    } else {
        return error.Unsupported;
    }
}

fn parseGzipOptions(request: ?*Node, command_mask: u32) Failure!gzip.Options {
    var options: gzip.Options = .{
        .modification_time = 0,
        .extra_flags = 0,
        .operating_system = 255,
        .text = false,
        .header_crc = false,
        .extra = &.{},
        .name = &.{},
        .comment = &.{},
        .deflate = try parseDeflateOptions(request, command_mask),
    };
    if (node_graph.findSelector(request, comptime discovery.parameter("gzip", "modification_time").family, comptime discovery.parameter("gzip", "modification_time").ordinal)) |node| {
        options.modification_time = @truncate(node.value_low);
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("gzip", "extra_flags").family, comptime discovery.parameter("gzip", "extra_flags").ordinal)) |node| {
        options.extra_flags = @truncate(node.value_low);
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("gzip", "operating_system").family, comptime discovery.parameter("gzip", "operating_system").ordinal)) |node| {
        options.operating_system = @truncate(node.value_low);
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("gzip", "text").family, comptime discovery.parameter("gzip", "text").ordinal)) |node| {
        options.text = node.value_low != 0;
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("gzip", "header_crc").family, comptime discovery.parameter("gzip", "header_crc").ordinal)) |node| {
        options.header_crc = node.value_low != 0;
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("gzip", "extra").family, comptime discovery.parameter("gzip", "extra").ordinal)) |node| {
        options.extra = try resource.checkedConstBytes(node.bytes, node.byte_length);
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("gzip", "name").family, comptime discovery.parameter("gzip", "name").ordinal)) |node| {
        options.name = try resource.checkedConstBytes(node.bytes, node.byte_length);
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("gzip", "comment").family, comptime discovery.parameter("gzip", "comment").ordinal)) |node| {
        options.comment = try resource.checkedConstBytes(node.bytes, node.byte_length);
    }
    return options;
}

fn parseDeflateOptions(request: ?*Node, command_mask: u32) Failure!deflate.Options {
    var options = deflate_options;
    if (command_mask != vocabulary.command_mask_write and command_mask != vocabulary.command_mask_query) return options;
    if (node_graph.findSelector(request, comptime discovery.parameter("deflate", "good").family, comptime discovery.parameter("deflate", "good").ordinal)) |node| {
        options.good = std.math.cast(u16, node.value_low) orelse return error.InvalidCall;
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("deflate", "nice").family, comptime discovery.parameter("deflate", "nice").ordinal)) |node| {
        options.nice = std.math.cast(u16, node.value_low) orelse return error.InvalidCall;
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("deflate", "lazy").family, comptime discovery.parameter("deflate", "lazy").ordinal)) |node| {
        options.lazy = std.math.cast(u16, node.value_low) orelse return error.InvalidCall;
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("deflate", "chain").family, comptime discovery.parameter("deflate", "chain").ordinal)) |node| {
        options.chain = std.math.cast(u16, node.value_low) orelse return error.InvalidCall;
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("deflate", "optimal").family, comptime discovery.parameter("deflate", "optimal").ordinal)) |node| {
        options.optimal = node.value_low != 0;
    }
    return options;
}

// The counting pass replays the exact encode so the commit pass produces
// identical bytes. Codec policy errors propagate when map_io_failure is
// false. Transport failures on the counting sink carry no data.
fn planCountedEncode(source: *Resource, decoded_limit: u64, encoded_limit: u64, comptime map_io_failure: bool, comptime encode_fn: fn (input: *std.Io.Reader, output: *std.Io.Writer, args: anytype) Failure!void, args: anytype) Failure!usize {
    var bounded_source: resource.BoundedReader = undefined;
    bounded_source.init(source, decoded_limit);
    var counter = measurement.Counter.init(null);
    if (map_io_failure) {
        encode_fn(&bounded_source.reader, &counter.writer, args) catch return error.IoFailure;
    } else {
        try encode_fn(&bounded_source.reader, &counter.writer, args);
    }
    const output_size = counter.written();
    if (output_size > encoded_limit) return error.ResourceLimit;
    try source.rewind();
    return std.math.cast(usize, output_size) orelse error.ResourceLimit;
}

fn gzipEncodeStream(input: *std.Io.Reader, output: *std.Io.Writer, args: anytype) Failure!void {
    try gzip.encodeStream(input, output, args.history, args.options);
}

fn zlibEncodeStream(input: *std.Io.Reader, output: *std.Io.Writer, args: anytype) Failure!void {
    try zlib.encodeStream(input, output, args.history, args.options);
}

fn deflateEncodeStream(input: *std.Io.Reader, output: *std.Io.Writer, args: anytype) Failure!void {
    var compressor = try deflate.Compress.init(output, args.history, args.options);
    _ = std.Io.Reader.streamRemaining(input, &compressor.writer) catch return error.IoFailure;
    compressor.finish() catch return error.IoFailure;
}

fn zstdEncodeStream(input: *std.Io.Reader, output: *std.Io.Writer, args: anytype) Failure!void {
    _ = try zstd.encodeStream(input, output, args.history, args.workspace, args.options);
}

fn planDeflateDecode(source: *Resource, history: []u8, encoded_limit: u64, decoded_limit: u64) Failure!usize {
    var bounded_source: resource.BoundedReader = undefined;
    bounded_source.init(source, encoded_limit);
    var counter = measurement.Counter.init(null);
    var inflater = deflate.Decompress.init(&bounded_source.reader, history);
    _ = inflater.reader.streamRemaining(&counter.writer) catch return error.InvalidData;
    try source.rewind();
    const output_size = counter.written();
    if (output_size > decoded_limit) return error.ResourceLimit;
    return std.math.cast(usize, output_size) orelse error.ResourceLimit;
}

pub fn zlibHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const source_resource = source orelse return error.InvalidCall;
    try requireReplay(source_resource, sizing, commit, false);
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    const options = zlib.Options{ .deflate = try parseDeflateOptions(call.request, command_mask), .provider = plan.provider };
    const history = try workspace.take(u8, zlib.deflate_history_size + @as(usize, if (options.deflate.optimal) deflate.optimal_workspace_size else 0));
    if (command_mask == vocabulary.command_mask_read) {
        const input = switch (source_resource.kind) {
            .direct_read => |bytes| bytes,
            .callback_read => try common.materializeSource(.budget, source_resource, &workspace, limits.encoded_bytes),
            else => return error.Unsupported,
        };
        if (input.len > limits.encoded_bytes) return error.ResourceLimit;
        const output_size = try zlib.decodedSize(input, history, plan.provider);
        if (output_size > limits.decoded_bytes) return error.ResourceLimit;
        if (sink) |sink_resource| {
            try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(sink_resource, call, output_size);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.decoded_bytes);
            const produced = zlib.decode(input, &bounded_sink.writer, history, plan.provider) catch |err| return common.mapSinkError(err, call, sink_resource);
            response.byte_length = produced;
        } else {
            response.byte_length = output_size;
        }
    } else if (command_mask == vocabulary.command_mask_write) {
        const output_size = if (sizing == .bounded) blk: {
            const input_len = try measureSourceLength(source_resource, limits.decoded_bytes);
            const bound = zlib.encodedSizeBound(input_len, options);
            if (bound > limits.encoded_bytes) return error.ResourceLimit;
            break :blk bound;
        } else try planCountedEncode(source_resource, limits.decoded_bytes, limits.encoded_bytes, true, zlibEncodeStream, .{ .history = history, .options = options });
        if (sink) |sink_resource| {
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(sink_resource, call, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(source_resource, limits.decoded_bytes);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.encoded_bytes);
            zlib.encodeStream(&bounded_source.reader, &bounded_sink.writer, history, options) catch |err| return common.mapSinkError(err, call, sink_resource);
            if (sizing == .bounded) {
                response.byte_length = try common.boundedProduced(&bounded_sink, limits.encoded_bytes, output_size);
                return;
            }
            response.byte_length = output_size;
        } else {
            response.byte_length = output_size;
        }
    } else {
        return error.Unsupported;
    }
}

pub fn lz4Hook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    var options = try parseLz4Options(call.request, command_mask);
    options.provider = plan.provider;
    return bufferCodecHook(lz4, plan, source, sink, call, response, sizing, commit, limits, command_mask, lz4.decodeWorkspaceSize(), lz4.encodeWorkspaceSize(), options);
}

fn parseLz4Options(request: ?*Node, command_mask: u32) Failure!lz4.Options {
    var options: lz4.Options = .{};
    if (command_mask != vocabulary.command_mask_write and command_mask != vocabulary.command_mask_query) return options;
    if (node_graph.findSelector(request, comptime discovery.parameter("lz4", "block_size").family, comptime discovery.parameter("lz4", "block_size").ordinal)) |node| {
        options.block_size = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("lz4", "block_checksum").family, comptime discovery.parameter("lz4", "block_checksum").ordinal)) |node| {
        options.block_checksum = node.value_low != 0;
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("lz4", "content_checksum").family, comptime discovery.parameter("lz4", "content_checksum").ordinal)) |node| {
        options.content_checksum = node.value_low != 0;
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("lz4", "acceleration").family, comptime discovery.parameter("lz4", "acceleration").ordinal)) |node| {
        options.acceleration = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("lz4", "search_depth").family, comptime discovery.parameter("lz4", "search_depth").ordinal)) |node| {
        options.search_depth = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
    }
    return options;
}

pub fn zstd_seekableHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const source_resource = source orelse return error.InvalidCall;
    try requireReplay(source_resource, sizing, commit, false);
    var options = zstd_seekable.Options{ .provider = plan.provider };
    if (command_mask == vocabulary.command_mask_write or command_mask == vocabulary.command_mask_query) {
        if (node_graph.findSelector(call.request, comptime discovery.parameter("zstd-seekable", "frame_size").family, comptime discovery.parameter("zstd-seekable", "frame_size").ordinal)) |node| {
            options.frame_size = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
            if (options.frame_size < zstd_seekable.frame_size_min or options.frame_size > zstd_seekable.frame_size_max) return error.InvalidCall;
        }
    }
    const frame_options = zstd_seekable.frameOptions(options);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink) |sink_resource| try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const input = try common.materializeSource(.budget, source_resource, &workspace, limits.encoded_bytes);
        if (input.len > limits.encoded_bytes) return error.ResourceLimit;
        const history = try workspace.take(u8, @as(usize, frame_options.window_size) + zstd.block_size_max);
        const output_size = try zstd_seekable.decodedSize(input, history, options);
        if (output_size > limits.decoded_bytes) return error.ResourceLimit;
        if (sink) |sink_resource| {
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(sink_resource, call, output_size);
            if (sink_resource.kind == .direct_write) {
                const output = try common.sinkDirectBuffer(sink_resource, output_size);
                var fixed = std.Io.Writer.fixed(output);
                try zstd_seekable.decode(input, &fixed, history, options);
            } else {
                const staging = try workspace.take(u8, output_size);
                var fixed = std.Io.Writer.fixed(staging);
                try zstd_seekable.decode(input, &fixed, history, options);
                try common.commitBytesToSink(sink_resource, call, staging);
            }
        }
        response.byte_length = output_size;
    } else if (command_mask == vocabulary.command_mask_write) {
        if (sink) |sink_resource| try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const history = try workspace.take(u8, @as(usize, frame_options.window_size) + zstd.block_size_max);
        const workspace_u32 = try workspace.take(u32, zstd.encoderWorkspaceU32Count(0, options.frame_size, frame_options));
        const input = try common.materializeSource(.require_size, source_resource, &workspace, limits.decoded_bytes);
        const entries = try workspace.take(zstd_seekable.FrameEntry, zstd_seekable.frameCountFor(input.len, options));
        const output_size = if (sizing == .bounded) blk: {
            const bound = zstd_seekable.encodedSizeBound(input.len, options);
            if (bound > limits.encoded_bytes) return error.ResourceLimit;
            break :blk bound;
        } else blk: {
            var counter = measurement.Counter.init(null);
            try zstd_seekable.encodeToWriter(input, &counter.writer, history, workspace_u32, entries, options);
            const exact = std.math.cast(usize, counter.written()) orelse return error.ResourceLimit;
            if (exact > limits.encoded_bytes) return error.ResourceLimit;
            break :blk exact;
        };
        if (input.len + output_size > limits.codec_work) return error.ResourceLimit;
        if (sink) |sink_resource| {
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(sink_resource, call, output_size);
            const staging = try workspace.take(u8, output_size);
            const produced = try zstd_seekable.encode(input, staging, history, workspace_u32, entries, options);
            if (sizing == .bounded) {
                if (produced > output_size) return error.InternalFailure;
                try common.commitBytesToSink(sink_resource, call, staging[0..produced]);
                response.byte_length = produced;
                return;
            }
            try common.commitBytesToSink(sink_resource, call, staging);
        }
        response.byte_length = output_size;
    } else {
        return error.Unsupported;
    }
}

pub fn zdictHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const source_resource = source orelse return error.InvalidCall;
    try requireReplay(source_resource, sizing, commit, false);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink) |sink_resource| try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const input = try common.materializeSource(.require_size, source_resource, &workspace, limits.encoded_bytes);
        // Reading a dictionary extracts its content: the raw window bytes.
        const content = zstd.dictionaryContent(input) catch |err| switch (err) {
            error.InvalidData, error.Unsupported, error.ResourceLimit, error.IoFailure, error.IntegrityFailure => |e| return e,
        };
        if (content.len > limits.decoded_bytes) return error.ResourceLimit;
        if (sink) |sink_resource| {
            try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(sink_resource, call, content.len);
            try common.commitBytesToSink(sink_resource, call, content);
        }
        response.byte_length = content.len;
        return;
    }
    if (command_mask != vocabulary.command_mask_write and command_mask != vocabulary.command_mask_query) return error.Unsupported;
    const sample_node = node_graph.findSelector(call.request, comptime discovery.parameter("zdict", "sample_size").family, comptime discovery.parameter("zdict", "sample_size").ordinal) orelse return error.InvalidCall;
    const sample_size = std.math.cast(usize, sample_node.value_low) orelse return error.InvalidCall;
    if (sample_size == 0) return error.InvalidCall;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    const input = try common.materializeSource(.require_size, source_resource, &workspace, limits.decoded_bytes);
    if (input.len % sample_size != 0) return error.InvalidCall;
    const sample_count = input.len / sample_size;
    if (sample_count == 0 or sample_count > (1 << 20)) return error.InvalidCall;
    const samples = try workspace.take([]const u8, sample_count);
    for (0..sample_count) |index| {
        samples[index] = input[index * sample_size ..][0..sample_size];
    }
    const capacity = input.len + zstd.dictionary_header_size;
    const staging = try workspace.take(u8, capacity);
    const train_scratch = try workspace.take(u8, zstd.trainWorkspaceSize());
    const produced = try zstd.trainDictionary(samples, capacity, staging, train_scratch, plan.provider);
    if (produced > limits.encoded_bytes) return error.ResourceLimit;
    if (input.len + produced > limits.codec_work) return error.ResourceLimit;
    if (sink) |sink_resource| {
        try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
        try common.requireSinkCapacity(sink_resource, call, produced);
        try common.commitBytesToSink(sink_resource, call, staging[0..produced]);
    }
    response.byte_length = produced;
}

pub fn zstdHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const source_resource = source orelse return error.InvalidCall;
    try requireReplay(source_resource, sizing, commit, true);
    const options = blk: {
        var parsed = try parseZstdOptions(call.request, command_mask);
        parsed.provider = plan.provider;
        break :blk parsed;
    };
    const window = options.window_size;
    const dictionary = options.dictionary;
    const history_base_size = @as(usize, window) + zstd.block_size_max +
        (if (dictionary) |dict| dict.len else 0);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink) |sink_resource| try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const input = try common.materializeSource(.replay, source_resource, &workspace, limits.encoded_bytes);
        var planned_history: ?[]u8 = null;
        const output_size = zstd.frameContentSize(input, window) catch |err| switch (err) {
            error.Unsupported => blk: {
                const history = try workspace.take(u8, history_base_size);
                planned_history = history;
                break :blk try zstd.decodedSize(input, history, options);
            },
            else => return err,
        };
        if (output_size > limits.decoded_bytes) return error.ResourceLimit;
        if (sink) |sink_resource| {
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(sink_resource, call, output_size);
            var source_reader = std.Io.Reader.fixed(input);
            if (dictionary == null and output_size >= history_base_size) {
                const staging = try workspace.take(u8, output_size + zstd.block_size_max);
                var in_place_options = options;
                in_place_options.max_decoded_bytes = output_size;
                _ = try zstd.decodeInPlace(&source_reader, staging, in_place_options);
                try common.commitBytesToSink(sink_resource, call, staging[0..output_size]);
            } else {
                const history = planned_history orelse try workspace.take(u8, history_base_size);
                const staging = try workspace.take(u8, output_size);
                var decode_sink = std.Io.Writer.fixed(staging);
                _ = try zstd.decodeStream(&source_reader, &decode_sink, history, options);
                try common.commitBytesToSink(sink_resource, call, staging);
            }
        }
        response.byte_length = output_size;
    } else if (command_mask == vocabulary.command_mask_write) {
        if (sink) |sink_resource| try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const dict_len = if (dictionary) |dict| dict.len else 0;
        const input_len = try measureSourceLength(source_resource, limits.decoded_bytes);
        const frame_budget = if (zstd.useDfast(options) or zstd.useRowMatch(options))
            @min(input_len, zstd.encoder_frame_size_max)
        else
            @min(window, zstd.encoder_frame_size_max);
        const history = try workspace.take(u8, zstd_sizing.encodeHistoryLen(input_len, dict_len, options));
        const encoder_workspace = try workspace.take(u32, zstd.encoderWorkspaceU32Count(dict_len, frame_budget, options));
        var encode_options = options;
        encode_options.max_encoded_bytes = limits.encoded_bytes;
        encode_options.max_decoded_bytes = limits.decoded_bytes;
        const output_size = if (sizing == .bounded) blk: {
            const bound = zstd.encodedSizeBound(input_len, encode_options);
            if (bound > limits.encoded_bytes) return error.ResourceLimit;
            break :blk bound;
        } else try planCountedEncode(source_resource, limits.decoded_bytes, limits.encoded_bytes, false, zstdEncodeStream, .{ .history = history, .workspace = encoder_workspace, .options = encode_options });
        if (sink) |sink_resource| {
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(sink_resource, call, output_size);
            const staging = try workspace.take(u8, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(source_resource, limits.decoded_bytes);
            var staging_writer = std.Io.Writer.fixed(staging);
            const produced = try zstd.encodeStream(&bounded_source.reader, &staging_writer, history, encoder_workspace, encode_options);
            if (sizing == .bounded) {
                if (produced > output_size) return error.InternalFailure;
                try common.commitBytesToSink(sink_resource, call, staging[0..produced]);
                response.byte_length = produced;
                return;
            }
            try common.commitBytesToSink(sink_resource, call, staging);
        }
        response.byte_length = output_size;
    } else {
        return error.Unsupported;
    }
}

fn measureSourceLength(source: *Resource, limit: u64) Failure!usize {
    if (source.hasCapability(resource.capability_bit_size)) {
        const total = try source.size();
        if (total > limit) return error.ResourceLimit;
        return std.math.cast(usize, total) orelse error.ResourceLimit;
    }
    if (!source.hasCapability(resource.capability_bit_replay)) return error.Unsupported;
    var counter = measurement.Counter.init(null);
    var bounded_source: resource.BoundedReader = undefined;
    bounded_source.init(source, limit);
    _ = std.Io.Reader.streamRemaining(&bounded_source.reader, &counter.writer) catch return error.IoFailure;
    try source.rewind();
    const total = counter.written();
    if (total > limit) return error.ResourceLimit;
    return std.math.cast(usize, total) orelse error.ResourceLimit;
}

fn parseZstdOptions(request: ?*Node, command_mask: u32) Failure!zstd.Options {
    var options: zstd.Options = .{
        .window_size = try parseZstdWindow(node_graph.findSelector(request, comptime discovery.parameter("zstd", "window").family, comptime discovery.parameter("zstd", "window").ordinal)),
        .dictionary = try parseZstdDictionary(node_graph.findSelector(request, comptime discovery.parameter("zstd", "dictionary").family, comptime discovery.parameter("zstd", "dictionary").ordinal)),
    };
    if (command_mask == vocabulary.command_mask_write or command_mask == vocabulary.command_mask_query) {
        if (node_graph.findSelector(request, comptime discovery.parameter("zstd", "hash_bits").family, comptime discovery.parameter("zstd", "hash_bits").ordinal)) |node| {
            const hash_bits = std.math.cast(u5, node.value_low) orelse return error.InvalidCall;
            if (hash_bits < 10 or hash_bits > 17) return error.InvalidCall;
            options.hash_bits = hash_bits;
        }
        if (node_graph.findSelector(request, comptime discovery.parameter("zstd", "max_chain").family, comptime discovery.parameter("zstd", "max_chain").ordinal)) |node| {
            const max_chain = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
            if (max_chain == 0) return error.InvalidCall;
            options.max_chain = max_chain;
        }
        if (node_graph.findSelector(request, comptime discovery.parameter("zstd", "nice_len").family, comptime discovery.parameter("zstd", "nice_len").ordinal)) |node| {
            const nice_len = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
            if (nice_len < 3) return error.InvalidCall;
            options.nice_len = nice_len;
        }
        if (node_graph.findSelector(request, comptime discovery.parameter("zstd", "search_window").family, comptime discovery.parameter("zstd", "search_window").ordinal)) |node| {
            const search_window = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
            if (search_window == 0) return error.InvalidCall;
            options.search_window = search_window;
        }
        if (node_graph.findSelector(request, comptime discovery.parameter("zstd", "lazy").family, comptime discovery.parameter("zstd", "lazy").ordinal)) |node| {
            options.lazy = node.value_low != 0;
        }
        if (node_graph.findSelector(request, comptime discovery.parameter("zstd", "skip_interior_insert").family, comptime discovery.parameter("zstd", "skip_interior_insert").ordinal)) |node| {
            options.skip_interior_insert = node.value_low != 0;
        }
        if (node_graph.findSelector(request, comptime discovery.parameter("zstd", "double_hash").family, comptime discovery.parameter("zstd", "double_hash").ordinal)) |node| {
            options.double_hash = node.value_low != 0;
        }
        if (node_graph.findSelector(request, comptime discovery.parameter("zstd", "row_match").family, comptime discovery.parameter("zstd", "row_match").ordinal)) |node| {
            options.row_match = node.value_low != 0;
        }
    }
    return options;
}

fn parseZstdWindow(node: ?*Node) Failure!u32 {
    const n = node orelse return error.InvalidCall;
    const window = std.math.cast(u32, n.value_low) orelse return error.InvalidCall;
    if (window < zstd.window_size_min or window > zstd.window_size_max) return error.InvalidCall;
    return window;
}

fn parseZstdDictionary(node: ?*Node) Failure!?[]const u8 {
    const n = node orelse return null;
    if (n.value_low != 0 or n.child != null) return error.InvalidCall;
    return @as(?[]const u8, try resource.checkedConstBytes(n.bytes, n.byte_length));
}

pub fn bzip2Hook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    var options = try parseBzip2Options(call.request, command_mask);
    options.max_work = limits.codec_work;
    options.provider = plan.provider;
    return bufferCodecHook(bzip2, plan, source, sink, call, response, sizing, commit, limits, command_mask, bzip2.decodeWorkspaceSize(bzip2.block_size_max), bzip2.encodeWorkspaceSize(options.block_size), options);
}

fn parseBzip2Options(request: ?*Node, command_mask: u32) Failure!bzip2.Options {
    var options: bzip2.Options = .{};
    if (command_mask == vocabulary.command_mask_write or command_mask == vocabulary.command_mask_query) {
        if (node_graph.findSelector(request, comptime discovery.parameter("bzip2", "block_size").family, comptime discovery.parameter("bzip2", "block_size").ordinal)) |node| {
            const block_size = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
            if (block_size < bzip2.block_size_min or block_size > bzip2.block_size_max) return error.InvalidCall;
            options.block_size = block_size;
        }
    }
    return options;
}

fn parseLzmaDictionary(request: ?*Node) Failure!u32 {
    const node = node_graph.findSelector(request, comptime discovery.parameter("lzma", "dictionary").family, comptime discovery.parameter("lzma", "dictionary").ordinal) orelse return error.InvalidCall;
    const dictionary_size = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
    if (dictionary_size < lzma.dictionary_min or dictionary_size > lzma.dictionary_max) return error.InvalidCall;
    return dictionary_size;
}

const LzmaMatchParams = struct {
    match_finder_depth: u32 = 32,
    lazy: bool = false,
    lazy_set: bool = false,
    nice_len: u32 = 273,
    match_finder: lzma.MatchFinder = .bt4,
};

fn parseLzmaMatchParams(request: ?*Node, command_mask: u32) Failure!LzmaMatchParams {
    var params = LzmaMatchParams{};
    if (command_mask != vocabulary.command_mask_write and command_mask != vocabulary.command_mask_query) return params;
    if (node_graph.findSelector(request, comptime discovery.parameter("lzma", "match_finder_depth").family, comptime discovery.parameter("lzma", "match_finder_depth").ordinal)) |node| {
        params.match_finder_depth = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
        if (params.match_finder_depth == 0) return error.InvalidCall;
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("lzma", "lazy").family, comptime discovery.parameter("lzma", "lazy").ordinal)) |node| {
        params.lazy = node.value_low != 0;
        params.lazy_set = true;
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("lzma", "nice_len").family, comptime discovery.parameter("lzma", "nice_len").ordinal)) |node| {
        params.nice_len = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
        if (params.nice_len < 2 or params.nice_len > 273) return error.InvalidCall;
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("lzma", "match_finder").family, comptime discovery.parameter("lzma", "match_finder").ordinal)) |node| {
        params.match_finder = switch (node.value_low) {
            0 => .hash_chain,
            1 => .bt4,
            else => return error.InvalidCall,
        };
    }
    // BT4 defaults to lazy matching unless the caller explicitly opts into greedy.
    if (!params.lazy_set and params.match_finder == .bt4) {
        params.lazy = true;
    }
    return params;
}

pub fn lzmaHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const dictionary_size = try parseLzmaDictionary(call.request);
    const properties = lzma2.defaultProperties(dictionary_size);
    const params = try parseLzmaMatchParams(call.request, command_mask);
    const encode_workspace = if (params.match_finder == .bt4) lzma.encodeWorkspaceSizeBt(properties) else lzma.encodeWorkspaceSize(properties);
    return bufferCodecHook(lzma, plan, source, sink, call, response, sizing, commit, limits, command_mask, lzma.decodeWorkspaceSize(properties), encode_workspace, .{
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

pub fn lzma2Hook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const dictionary_size = try parseLzmaDictionary(call.request);
    const properties = lzma2.defaultProperties(dictionary_size);
    const params = try parseLzmaMatchParams(call.request, command_mask);
    const encode_workspace = if (params.match_finder == .bt4) lzma2.encodeWorkspaceSizeBt(dictionary_size) else lzma2.encodeWorkspaceSize(dictionary_size);
    return bufferCodecHook(lzma2, plan, source, sink, call, response, sizing, commit, limits, command_mask, lzma2.decodeWorkspaceSize(dictionary_size), encode_workspace, .{
        .dictionary_size = dictionary_size,
        .properties = properties,
        .max_work = limits.codec_work,
        .match_finder_depth = params.match_finder_depth,
        .lazy = params.lazy,
        .nice_len = params.nice_len,
        .match_finder = params.match_finder,
    });
}

fn bufferCodecHook(comptime Codec: type, plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32, decode_workspace: usize, encode_workspace: usize, options: Codec.Options) Failure!void {
    const source_resource = source orelse return error.InvalidCall;
    try requireReplay(source_resource, sizing, commit, false);
    if (sink == null) try common.checkSourceWorkspaceOverlap(call, source_resource);
    if (command_mask == vocabulary.command_mask_read) {
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const scratch = try workspace.take(u8, decode_workspace);
        const input = try common.materializeSource(.require_size, source_resource, &workspace, limits.encoded_bytes);
        if (sink) |sink_resource| {
            try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            if (sink_resource.kind == .direct_write and try codecKnownOutputSize(Codec, options) == null and (Codec == lzma or Codec == bzip2)) {
                // No size preflight: the produced length comes back from the codec. lzma2 is excluded because chunk headers give a cheap size and in-place is faster.
                const output = try common.sinkDirectBuffer(sink_resource, common.sinkCapacity(sink_resource));
                if (input.len + output.len > limits.codec_work) return error.ResourceLimit;
                const produced = try codecDecodeDirect(Codec, input, output, scratch, options);
                if (produced > limits.decoded_bytes) return error.ResourceLimit;
                response.byte_length = produced;
            } else {
                const output_size = if (try codecKnownOutputSize(Codec, options)) |size| size else try codecDecodedSize(Codec, input, scratch, options);
                if (output_size > limits.decoded_bytes) return error.ResourceLimit;
                if (input.len + output_size > limits.codec_work) return error.ResourceLimit;
                try common.requireSinkCapacity(sink_resource, call, output_size);
                if (sink_resource.kind == .direct_write) {
                    const output = try common.sinkDirectBuffer(sink_resource, output_size);
                    _ = try codecDecodeDirectInPlace(Codec, input, output, scratch, options);
                } else {
                    const staging = try workspace.take(u8, output_size);
                    var fixed_writer = std.Io.Writer.fixed(staging);
                    codecDecodeToWriter(Codec, input, &fixed_writer, scratch, options) catch |err| return common.mapSinkError(err, call, sink_resource);
                    try common.commitBytesToSink(sink_resource, call, staging);
                }
                response.byte_length = output_size;
            }
        } else {
            const output_size = if (try codecKnownOutputSize(Codec, options)) |size| size else try codecDecodedSize(Codec, input, scratch, options);
            if (output_size > limits.decoded_bytes) return error.ResourceLimit;
            if (input.len + output_size > limits.codec_work) return error.ResourceLimit;
            response.byte_length = output_size;
        }
    } else if (command_mask == vocabulary.command_mask_write) {
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const scratch = try workspace.take(u8, encode_workspace);
        const input = try common.materializeSource(.require_size, source_resource, &workspace, limits.decoded_bytes);
        const output_size = if (sizing == .bounded) Codec.encodedSizeBound(input.len) else try Codec.requiredSize(input, scratch, options);
        if (output_size > limits.encoded_bytes) return error.ResourceLimit;
        if (input.len + output_size > limits.codec_work) return error.ResourceLimit;
        if (sink) |sink_resource| {
            try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(sink_resource, call, output_size);
            if (sink_resource.kind == .direct_write) {
                const output = try common.sinkDirectBuffer(sink_resource, output_size);
                const produced = try Codec.encode(input, output, scratch, options);
                if (sizing == .bounded) {
                    if (produced > output_size) return error.InternalFailure;
                    response.byte_length = produced;
                    return;
                }
            } else {
                const staging = try workspace.take(u8, output_size);
                const produced = try Codec.encode(input, staging, scratch, options);
                if (sizing == .bounded) {
                    if (produced > output_size) return error.InternalFailure;
                    try common.commitBytesToSink(sink_resource, call, staging[0..produced]);
                    response.byte_length = produced;
                    return;
                }
                try common.commitBytesToSink(sink_resource, call, staging);
            }
        }
        response.byte_length = output_size;
    } else {
        return error.Unsupported;
    }
}

fn codecKnownOutputSize(comptime Codec: type, options: Codec.Options) Failure!?usize {
    if (!@hasField(Codec.Options, "unpack_size")) return null;
    const size = options.unpack_size orelse return null;
    return std.math.cast(usize, size) orelse error.ResourceLimit;
}

fn codecDecodedSize(comptime Codec: type, input: []const u8, scratch: []u8, options: Codec.Options) Failure!usize {
    if (Codec == bzip2) return bzip2.decodedSize(input, scratch, options.provider);
    return Codec.decodedSize(input, scratch, options);
}

fn codecDecodeToWriter(comptime Codec: type, input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Codec.Options) Failure!void {
    if (Codec == bzip2) return bzip2.decodeToWriter(input, writer, scratch, options.provider);
    return Codec.decodeToWriter(input, writer, scratch, options);
}

fn codecDecodeDirect(comptime Codec: type, input: []const u8, output: []u8, scratch: []u8, options: Codec.Options) Failure!usize {
    if (Codec == bzip2) return bzip2.decode(input, output, scratch, options.provider);
    return Codec.decode(input, output, scratch, options);
}

fn codecDecodeDirectInPlace(comptime Codec: type, input: []const u8, output: []u8, scratch: []u8, options: Codec.Options) Failure!usize {
    if (Codec == bzip2) return bzip2.decode(input, output, scratch, options.provider);
    const result = try Codec.decodeInPlace(input, output, scratch, options);
    return if (Codec == lzma2) result.produced else result;
}

pub fn lzma_fileHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const source_resource = source orelse return error.InvalidCall;
    try requireReplay(source_resource, sizing, commit, false);
    if (sink == null) try common.checkSourceWorkspaceOverlap(call, source_resource);
    if (command_mask == vocabulary.command_mask_read) {
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const input = try common.materializeSource(.require_size, source_resource, &workspace, limits.encoded_bytes);
        if (input.len < lzma_file.header_size) return error.InvalidData;
        const options = try lzma_file.decodeOptions(input);
        const scratch = try workspace.take(u8, lzma.decodeWorkspaceSize(options.properties));
        const output_size = if (options.unpack_size) |size| std.math.cast(usize, size) orelse return error.ResourceLimit else try lzma_file.decodedSize(input, scratch);
        if (output_size > limits.decoded_bytes) return error.ResourceLimit;
        if (sink) |sink_resource| {
            try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(sink_resource, call, output_size);
            if (sink_resource.kind == .direct_write) {
                const output = try common.sinkDirectBuffer(sink_resource, output_size);
                _ = try lzma_file.decodeInPlace(input, output, scratch);
            } else {
                var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.decoded_bytes);
                lzma_file.decodeToWriter(input, &bounded_sink.writer, scratch) catch |err| return common.mapSinkError(err, call, sink_resource);
            }
        }
        response.byte_length = output_size;
    } else if (command_mask == vocabulary.command_mask_write) {
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const dictionary = try parseLzmaFileDictionary(call.request);
        var options = try lzma_file.encodeOptions(dictionary);
        const params = try parseLzmaMatchParams(call.request, command_mask);
        options.match_finder_depth = params.match_finder_depth;
        options.lazy = params.lazy;
        options.nice_len = params.nice_len;
        options.match_finder = params.match_finder;
        const encode_workspace = if (params.match_finder == .bt4) lzma.encodeWorkspaceSizeBt(options.properties) else lzma.encodeWorkspaceSize(options.properties);
        const scratch = try workspace.take(u8, encode_workspace);
        const input = try common.materializeSource(.require_size, source_resource, &workspace, limits.decoded_bytes);
        options.unpack_size = input.len;
        const output_size = if (sizing == .bounded) lzma_file.encodedSizeBound(input.len) else try lzma_file.requiredSize(input, scratch, options);
        if (output_size > limits.encoded_bytes) return error.ResourceLimit;
        if (input.len + output_size > limits.codec_work) return error.ResourceLimit;
        if (sink) |sink_resource| {
            try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(sink_resource, call, output_size);
            const staging = try workspace.take(u8, output_size);
            const produced = try lzma_file.encode(input, staging, scratch, options);
            if (sizing == .bounded) {
                if (produced > output_size) return error.InternalFailure;
                try common.commitBytesToSink(sink_resource, call, staging[0..produced]);
                response.byte_length = produced;
                return;
            }
            try common.commitBytesToSink(sink_resource, call, staging);
        }
        response.byte_length = output_size;
    } else {
        return error.Unsupported;
    }
}

fn parseLzmaFileDictionary(request: ?*Node) Failure!u32 {
    const node = node_graph.findSelector(request, comptime discovery.parameter("lzma-file", "dictionary").family, comptime discovery.parameter("lzma-file", "dictionary").ordinal) orelse return lzma_file.default_dictionary;
    const dictionary_size = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
    if (dictionary_size < lzma.dictionary_min or dictionary_size > lzma.dictionary_max) return error.InvalidCall;
    return dictionary_size;
}

pub fn xzHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const source_resource = source orelse return error.InvalidCall;
    try requireReplay(source_resource, sizing, commit, true);
    if (sink) |sink_resource| try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
    const dictionary_size = try parseLzmaDictionary(call.request);
    const check = try parseXzCheck(node_graph.findSelector(
        call.request,
        comptime discovery.parameter("xz", "check").family,
        comptime discovery.parameter("xz", "check").ordinal,
    ));
    const filters = try parseXzFilters(node_graph.findSelector(
        call.request,
        comptime discovery.parameter("xz", "filters").family,
        comptime discovery.parameter("xz", "filters").ordinal,
    ));
    var delta_distance: u8 = 1;
    if (filters == .delta) {
        // The delta component's own selector carries the distance; the block
        // header round-trips it so decoders apply the same transform.
        if (node_graph.findSelector(
            call.request,
            comptime discovery.parameter("delta", "distance").family,
            comptime discovery.parameter("delta", "distance").ordinal,
        )) |node| {
            if (node.value_low < 1 or node.value_low > 255) return error.InvalidCall;
            delta_distance = @intCast(node.value_low);
        }
    }
    const params = try parseLzmaMatchParams(call.request, command_mask);
    if (command_mask == vocabulary.command_mask_read) {
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const scratch = try workspace.take(u8, xz.decodeWorkspaceSize(dictionary_size));
        const input = try common.materializeSource(.require_size, source_resource, &workspace, limits.encoded_bytes);
        if (input.len > limits.encoded_bytes) return error.ResourceLimit;
        const output_size = try xz.decodedSize(input, scratch, plan.provider);
        if (output_size > limits.decoded_bytes) return error.ResourceLimit;
        if (input.len + output_size > limits.codec_work) return error.ResourceLimit;
        if (sink) |sink_resource| {
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(sink_resource, call, output_size);
            const staging = try workspace.take(u8, output_size);
            _ = try xz.decodeInPlace(input, staging, scratch, plan.provider);
            try common.commitBytesToSink(sink_resource, call, staging);
        }
        response.byte_length = output_size;
    } else if (command_mask == vocabulary.command_mask_write) {
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const encode_workspace = if (params.match_finder == .bt4) xz.encodeWorkspaceSizeBt(dictionary_size) else xz.encodeWorkspaceSize(dictionary_size);
        const scratch = try workspace.take(u8, encode_workspace);
        const input = try common.materializeSource(.require_size, source_resource, &workspace, limits.decoded_bytes);
        if (input.len > limits.decoded_bytes) return error.ResourceLimit;
        const options = xz.Options{
            .dictionary_size = dictionary_size,
            .check = check,
            .filters = filters,
            .delta_distance = delta_distance,
            .match_finder_depth = params.match_finder_depth,
            .lazy = params.lazy,
            .nice_len = params.nice_len,
            .match_finder = params.match_finder,
            .provider = plan.provider,
        };
        const output_size = if (sizing == .bounded) xz.encodedSizeBound(input.len) else try xz.requiredSize(input, scratch, options);
        if (output_size > limits.encoded_bytes) return error.ResourceLimit;
        if (input.len + output_size > limits.codec_work) return error.ResourceLimit;
        if (sink) |sink_resource| {
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(sink_resource, call, output_size);
            const staging = try workspace.take(u8, output_size);
            const produced = try xz.encode(input, staging, scratch, options);
            if (sizing == .bounded) {
                if (produced > output_size) return error.InternalFailure;
                try common.commitBytesToSink(sink_resource, call, staging[0..produced]);
                response.byte_length = produced;
                return;
            }
            try common.commitBytesToSink(sink_resource, call, staging);
        }
        response.byte_length = output_size;
    } else {
        return error.Unsupported;
    }
}

fn parseXzCheck(node: ?*Node) Failure!xz.CheckType {
    const n = node orelse return .crc32;
    const value = n.value_low;
    return switch (value) {
        0 => .none,
        1 => .crc32,
        4 => .crc64,
        0x0A => .sha256,
        else => error.Unsupported,
    };
}

fn parseXzFilters(node: ?*Node) Failure!xz.FilterChoice {
    const n = node orelse return .none;
    const value: u32 = @truncate(n.value_low);
    return switch (value) {
        0 => .none,
        1 => .delta,
        2 => .x86,
        3 => .ppc,
        4 => .ia64,
        5 => .arm,
        6 => .armt,
        7 => .sparc,
        8 => .arm64,
        9 => .riscv,
        else => error.InvalidCall,
    };
}
