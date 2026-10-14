const std = @import("std");

const measurement = @import("../common/primitive/measurement.zig");
const gzip = @import("../grammar/gzip/onprem.zig");
const lzma_file = @import("../grammar/lzma/onprem.zig");
const xz = @import("../grammar/xz/onprem.zig");
const zlib = @import("../grammar/zlib/onprem.zig");
const zstd_seekable = @import("../grammar/zstd_seekable/onprem.zig");
const discovery = @import("../kernel/discovery.zig");
const abi = @import("../kernel/envelope.zig");
const node_graph = @import("../kernel/node.zig");
const resource = @import("../kernel/resource.zig");
const vocabulary = @import("../kernel/vocabulary.zig");
const bzip2 = @import("../leaf/bzip2/onprem.zig");
const brotli = @import("../leaf/brotli/onprem.zig");
const deflate = @import("../leaf/deflate/onprem.zig");
const deflate_seam = @import("../leaf/deflate/seam.zig");
const lz4 = @import("../leaf/lz4/onprem.zig");
const lzma = @import("../leaf/lzma/onprem.zig");
const lzma2 = @import("../leaf/lzma2/onprem.zig");
const zstd = @import("../leaf/zstd/onprem.zig");
const zstd_seam = @import("../leaf/zstd/seam.zig");
const common = @import("common.zig");
const zstd_sizing = @import("sizing.zig");

const Call = abi.Call;
const Node = abi.Node;
const Limits = resource.Limits;
const Resource = resource.Resource;
const Failure = vocabulary.Failure;

// gzip fixed-header flag bits, mirrored from the grammar leaf for the
// read-side inspect projection.
const flag_text: u8 = 0x01;
const flag_header_crc: u8 = 0x02;

const deflate_options: deflate.Options = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 8 };

fn requireReplay(source: *Resource, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, comptime confirmed: bool) Failure!void {
    if (sizing != .measured and sizing != .bounded) {
        std.debug.print("BRDBG requireReplay sizing\n", .{});
        return error.UnsupportedFailure;
    }
    const expected: vocabulary.CommitMode = if (confirmed) .confirmed else .tentative;
    if (commit != expected) {
        std.debug.print("BRDBG requireReplay commit\n", .{});
        return error.UnsupportedFailure;
    }
    if (!source.hasCapability(resource.capability_bit_read) or !source.hasCapability(resource.capability_bit_replay)) {
        std.debug.print("BRDBG requireReplay caps\n", .{});
        return error.UnsupportedFailure;
    }
}

fn optNode(request: ?*Node, comptime component: []const u8, comptime name: []const u8) ?*Node {
    const param = comptime discovery.parameter(component, name);
    return node_graph.findSelector(request, param.family, param.ordinal);
}

fn optCast(request: ?*Node, comptime component: []const u8, comptime name: []const u8, comptime T: type) Failure!?T {
    const node = optNode(request, component, name) orelse return null;
    return std.math.cast(T, node.value_low) orelse error.CallFailure;
}

fn optBool(request: ?*Node, comptime component: []const u8, comptime name: []const u8) bool {
    const node = optNode(request, component, name) orelse return false;
    return node.value_low != 0;
}

fn optBytes(request: ?*Node, comptime component: []const u8, comptime name: []const u8) Failure!?[]const u8 {
    const node = optNode(request, component, name) orelse return null;
    return try resource.checkedConstBytes(node.bytes, node.byte_length);
}

pub fn testHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    _ = command_mask;
    const source_resource = source orelse return error.CallFailure;
    const sink_resource = sink orelse return error.CallFailure;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    const output_size = try common.planOutputSize(source_resource, sizing, limits, &workspace);
    try common.requireSinkCapacity(sink_resource, call, output_size);
    const staging_required: usize = if (commit == .confirmed) output_size else 0;
    if (workspace.bytes.len < staging_required) {
        common.writeCapacityDiagnostic(call, staging_required, workspace.bytes.len);
        return error.CapacityFailure;
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
    const source_resource = source orelse return error.CallFailure;
    try requireReplay(source_resource, sizing, commit, false);
    const deflate_opts = try parseDeflateOptions(call.request, command_mask);
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    const history = try workspace.take(u8, deflate.history_size + @as(usize, if (deflate_opts.optimal) deflate.optimal_workspace_size else 0));
    if (command_mask == vocabulary.command_mask_read) {
        const output_size = try planDeflateDecode(source_resource, history, limits.encoded_bytes, limits.decoded_bytes);
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(source_resource, limits.encoded_bytes);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.decoded_bytes);
            var inflater = deflate_seam.Decode.initBound(plan.provider, &bounded_source.reader, history) catch return error.UnsupportedFailure;
            _ = inflater.readerPtr().streamRemaining(&bounded_sink.writer) catch |err| return common.mapSinkError(switch (err) {
                error.WriteFailed => error.IoFailure,
                else => error.DataFailure,
            }, call, sink_resource);
        }
        response.byte_length = output_size;
    } else if (command_mask == vocabulary.command_mask_write) {
        const output_size = if (sizing == .bounded) blk: {
            const input_len = try common.measureSource(source_resource, limits.decoded_bytes);
            const bound = deflate.encodedSizeBound(input_len);
            if (bound > limits.encoded_bytes) return error.ResourceFailure;
            break :blk bound;
        } else try planCountedEncode(source_resource, limits.decoded_bytes, limits.encoded_bytes, true, deflateEncodeStream, .{ .history = history, .options = deflate_opts });
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(source_resource, limits.decoded_bytes);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.encoded_bytes);
            var compressor = try deflate.Compress.init(&bounded_sink.writer, history, deflate_opts);
            _ = std.Io.Reader.streamRemaining(&bounded_source.reader, &compressor.writer) catch return common.mapSinkError(error.IoFailure, call, sink_resource);
            compressor.finish() catch return common.mapSinkError(error.IoFailure, call, sink_resource);
            if (try common.respondWrite(response, sizing, &bounded_sink, limits.encoded_bytes, output_size)) return;
        }
        response.byte_length = output_size;
    } else {
        return error.UnsupportedFailure;
    }
}

pub fn gzipHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const source_resource = source orelse return error.CallFailure;
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
            else => return error.UnsupportedFailure,
        };
        if (input.len > limits.encoded_bytes) return error.ResourceFailure;
        if (sink == null) {
            // Read-side header projection: a family-3 selector asks for the
            // named field of the first member's fixed header; absent
            // selectors keep the decoded-size path below.
            const header_requested = optNode(call.request, "gzip", "modification_time") != null or
                optNode(call.request, "gzip", "operating_system") != null or
                optNode(call.request, "gzip", "extra_flags") != null or
                optNode(call.request, "gzip", "text") != null or
                optNode(call.request, "gzip", "header_crc") != null;
            if (header_requested) {
                const info = try gzip.inspectStream(input);
                if (optNode(call.request, "gzip", "operating_system") != null) {
                    response.byte_length = info.operating_system;
                } else if (optNode(call.request, "gzip", "extra_flags") != null) {
                    response.byte_length = info.extra_flags;
                } else if (optNode(call.request, "gzip", "text") != null) {
                    response.byte_length = info.flags & flag_text;
                } else if (optNode(call.request, "gzip", "header_crc") != null) {
                    response.byte_length = info.flags & flag_header_crc;
                } else {
                    response.byte_length = info.modification_time;
                }
                return;
            }
        }
        if (sink) |sink_resource| {
            if (plan.provider == .onprem and sink_resource.kind == .direct_write and sink_resource.hasCapability(resource.capability_bit_write)) {
                // Single-pass: fallback recomputes exact size before further writes, so capacity never fails post-write. The abandoned fast path's bytes are erased so a failed call leaves no decoded prefix behind.
                switch (try gzip.decodeSinglePass(input, sink_resource.kind.direct_write, history, plan.provider)) {
                    .decoded => |produced| {
                        if (produced > limits.decoded_bytes) return error.ResourceFailure;
                        response.byte_length = produced;
                        return;
                    },
                    .fallback => |tentative| @memset(sink_resource.kind.direct_write[0..tentative], 0),
                }
            }
        }
        const output_size = try gzip.decodedSize(input, history, plan.provider);
        if (output_size > limits.decoded_bytes) return error.ResourceFailure;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.decoded_bytes);
            const produced = gzip.decode(input, &bounded_sink.writer, history, plan.provider) catch |err| return common.mapSinkError(err, call, sink_resource);
            response.byte_length = produced;
        } else {
            response.byte_length = output_size;
        }
    } else if (command_mask == vocabulary.command_mask_write) {
        const output_size = if (sizing == .bounded) blk: {
            const input_len = try common.measureSource(source_resource, limits.decoded_bytes);
            const bound = gzip.encodedSizeBound(input_len, options);
            if (bound > limits.encoded_bytes) return error.ResourceFailure;
            break :blk bound;
        } else try planCountedEncode(source_resource, limits.decoded_bytes, limits.encoded_bytes, true, gzipEncodeStream, .{ .history = history, .options = options });
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(source_resource, limits.decoded_bytes);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.encoded_bytes);
            gzip.encodeStream(&bounded_source.reader, &bounded_sink.writer, history, options) catch |err| return common.mapSinkError(err, call, sink_resource);
            if (try common.respondWrite(response, sizing, &bounded_sink, limits.encoded_bytes, output_size)) return;
            response.byte_length = output_size;
        } else {
            response.byte_length = output_size;
        }
    } else {
        return error.UnsupportedFailure;
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
    if (try optCast(request, "gzip", "modification_time", u32)) |value| options.modification_time = value;
    if (try optCast(request, "gzip", "extra_flags", u8)) |value| options.extra_flags = value;
    if (try optCast(request, "gzip", "operating_system", u8)) |value| options.operating_system = value;
    options.text = optBool(request, "gzip", "text");
    options.header_crc = optBool(request, "gzip", "header_crc");
    if (try optBytes(request, "gzip", "extra")) |value| options.extra = value;
    if (try optBytes(request, "gzip", "name")) |value| options.name = value;
    if (try optBytes(request, "gzip", "comment")) |value| options.comment = value;
    return options;
}

fn parseDeflateOptions(request: ?*Node, command_mask: u32) Failure!deflate.Options {
    var options = deflate_options;
    if (command_mask != vocabulary.command_mask_write and command_mask != vocabulary.command_mask_query) return options;
    if (try optCast(request, "deflate", "good", u16)) |value| options.good = value;
    if (try optCast(request, "deflate", "nice", u16)) |value| options.nice = value;
    if (try optCast(request, "deflate", "lazy", u16)) |value| options.lazy = value;
    if (try optCast(request, "deflate", "chain", u16)) |value| options.chain = value;
    if (optNode(request, "deflate", "optimal")) |node| options.optimal = node.value_low != 0;
    if (optNode(request, "deflate", "strategy")) |node| {
        if (node.value_low > @backingInt(deflate.Strategy.rle)) return error.CallFailure;
        options.strategy = @fromBackingInt(@intCast(node.value_low));
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
    if (output_size > encoded_limit) return error.ResourceFailure;
    try source.rewind();
    return std.math.cast(usize, output_size) orelse error.ResourceFailure;
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
    // The counting pass answers a size, so the arm choice is output-neutral;
    // the committing decode below binds the provider for real.
    var inflater = deflate.Decompress.init(&bounded_source.reader, history);
    _ = inflater.reader.streamRemaining(&counter.writer) catch return error.DataFailure;
    try source.rewind();
    const output_size = counter.written();
    if (output_size > decoded_limit) return error.ResourceFailure;
    return std.math.cast(usize, output_size) orelse error.ResourceFailure;
}

pub fn zlibHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const source_resource = source orelse return error.CallFailure;
    try requireReplay(source_resource, sizing, commit, false);
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    const options = zlib.Options{ .deflate = try parseDeflateOptions(call.request, command_mask), .provider = plan.provider };
    const history = try workspace.take(u8, zlib.deflate_history_size + @as(usize, if (options.deflate.optimal) deflate.optimal_workspace_size else 0));
    if (command_mask == vocabulary.command_mask_read) {
        const input = switch (source_resource.kind) {
            .direct_read => |bytes| bytes,
            .callback_read => try common.materializeSource(.budget, source_resource, &workspace, limits.encoded_bytes),
            else => return error.UnsupportedFailure,
        };
        if (input.len > limits.encoded_bytes) return error.ResourceFailure;
        const output_size = try zlib.decodedSize(input, history, plan.provider);
        if (output_size > limits.decoded_bytes) return error.ResourceFailure;
        if (sink) |sink_resource| {
            try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
            try common.requireSink(sink_resource, call, output_size);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.decoded_bytes);
            const produced = zlib.decode(input, &bounded_sink.writer, history, plan.provider) catch |err| return common.mapSinkError(err, call, sink_resource);
            response.byte_length = produced;
        } else {
            response.byte_length = output_size;
        }
    } else if (command_mask == vocabulary.command_mask_write) {
        const output_size = if (sizing == .bounded) blk: {
            const input_len = try common.measureSource(source_resource, limits.decoded_bytes);
            const bound = zlib.encodedSizeBound(input_len, options);
            if (bound > limits.encoded_bytes) return error.ResourceFailure;
            break :blk bound;
        } else try planCountedEncode(source_resource, limits.decoded_bytes, limits.encoded_bytes, true, zlibEncodeStream, .{ .history = history, .options = options });
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(source_resource, limits.decoded_bytes);
            var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.encoded_bytes);
            zlib.encodeStream(&bounded_source.reader, &bounded_sink.writer, history, options) catch |err| return common.mapSinkError(err, call, sink_resource);
            if (try common.respondWrite(response, sizing, &bounded_sink, limits.encoded_bytes, output_size)) return;
            response.byte_length = output_size;
        } else {
            response.byte_length = output_size;
        }
    } else {
        return error.UnsupportedFailure;
    }
}

pub fn lz4Hook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    var options = try parseLz4Options(call.request, command_mask);
    options.provider = plan.provider;
    options.max_work = limits.codec_work;
    return bufferCodecHook(lz4, plan, source, sink, call, response, sizing, commit, limits, command_mask, lz4.decodeWorkspaceSize(), lz4.encodeWorkspaceSize(), options);
}

fn parseLz4Options(request: ?*Node, command_mask: u32) Failure!lz4.Options {
    var options: lz4.Options = .{};
    if (command_mask != vocabulary.command_mask_write and command_mask != vocabulary.command_mask_query) return options;
    if (try optCast(request, "lz4", "block_size", u32)) |value| options.block_size = value;
    if (optNode(request, "lz4", "block_checksum")) |node| options.block_checksum = node.value_low != 0;
    if (optNode(request, "lz4", "content_checksum")) |node| options.content_checksum = node.value_low != 0;
    if (try optCast(request, "lz4", "acceleration", u32)) |value| options.acceleration = value;
    if (try optCast(request, "lz4", "search_depth", u32)) |value| options.search_depth = value;
    return options;
}

pub fn zstd_seekableHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const source_resource = source orelse return error.CallFailure;
    try requireReplay(source_resource, sizing, commit, false);
    var options = zstd_seekable.Options{ .provider = plan.provider };
    if (command_mask == vocabulary.command_mask_write or command_mask == vocabulary.command_mask_query) {
        if (try optCast(call.request, "zstd-seekable", "frame_size", u32)) |frame_size| {
            if (frame_size < zstd_seekable.frame_size_min or frame_size > zstd_seekable.frame_size_max) return error.CallFailure;
            options.frame_size = frame_size;
        }
    }
    const frame_options = zstd_seekable.frameOptions(options);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink) |sink_resource| try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const input = try common.materializeSource(.budget, source_resource, &workspace, limits.encoded_bytes);
        if (input.len > limits.encoded_bytes) return error.ResourceFailure;
        const history = try workspace.take(u8, @as(usize, frame_options.window_size) + zstd.block_size_max);
        const output_size = try zstd_seekable.decodedSize(input, history, options);
        if (output_size > limits.decoded_bytes) return error.ResourceFailure;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
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
            if (bound > limits.encoded_bytes) return error.ResourceFailure;
            break :blk bound;
        } else blk: {
            var counter = measurement.Counter.init(null);
            try zstd_seekable.encodeToWriter(input, &counter.writer, history, workspace_u32, entries, options);
            const exact = try measurement.measuredLength(&counter);
            if (exact > limits.encoded_bytes) return error.ResourceFailure;
            break :blk exact;
        };
        if (input.len + output_size > limits.codec_work) return error.ResourceFailure;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            const staging = try workspace.take(u8, output_size);
            const produced = try zstd_seekable.encode(input, staging, history, workspace_u32, entries, options);
            if (try common.verifiedCommitLength(sink_resource, call, sizing, staging, output_size, produced)) |produced_length| {
                response.byte_length = produced_length;
                return;
            }
        }
        response.byte_length = output_size;
    } else {
        return error.UnsupportedFailure;
    }
}

pub fn zdictHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const source_resource = source orelse return error.CallFailure;
    try requireReplay(source_resource, sizing, commit, false);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink) |sink_resource| try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const input = try common.materializeSource(.require_size, source_resource, &workspace, limits.encoded_bytes);
        const content = zstd.dictionaryContent(input) catch |err| switch (err) {
            error.DataFailure, error.UnsupportedFailure, error.ResourceFailure, error.IoFailure, error.IntegrityFailure => |e| return e,
        };
        if (content.len > limits.decoded_bytes) return error.ResourceFailure;
        if (sink) |sink_resource| {
            try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.UnsupportedFailure;
            try common.requireSinkCapacity(sink_resource, call, content.len);
            try common.commitBytesToSink(sink_resource, call, content);
        }
        response.byte_length = content.len;
        return;
    }
    if (command_mask != vocabulary.command_mask_write and command_mask != vocabulary.command_mask_query) return error.UnsupportedFailure;
    const sample_size = (try optCast(call.request, "zdict", "sample_size", usize)) orelse return error.CallFailure;
    if (sample_size == 0) return error.CallFailure;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    const input = try common.materializeSource(.require_size, source_resource, &workspace, limits.decoded_bytes);
    if (input.len % sample_size != 0) return error.CallFailure;
    const sample_count = input.len / sample_size;
    if (sample_count == 0 or sample_count > (1 << 20)) return error.CallFailure;
    const samples = try workspace.take([]const u8, sample_count);
    for (0..sample_count) |index| {
        samples[index] = input[index * sample_size ..][0..sample_size];
    }
    const capacity = input.len + zstd.dictionary_header_size;
    const staging = try workspace.take(u8, capacity);
    const train_scratch = try workspace.take(u8, zstd.trainWorkspaceSize());
    const produced = try zstd.trainDictionary(samples, capacity, staging, train_scratch, plan.provider);
    if (produced > limits.encoded_bytes) return error.ResourceFailure;
    if (input.len + produced > limits.codec_work) return error.ResourceFailure;
    if (sink) |sink_resource| {
        try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.UnsupportedFailure;
        try common.requireSinkCapacity(sink_resource, call, produced);
        try common.commitBytesToSink(sink_resource, call, staging[0..produced]);
    }
    response.byte_length = produced;
}

pub fn zstdHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const source_resource = source orelse return error.CallFailure;
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
            error.UnsupportedFailure => blk: {
                const history = try workspace.take(u8, history_base_size);
                planned_history = history;
                break :blk try zstd_seam.decodedSize(options.provider, input, history, options);
            },
            else => return err,
        };
        if (output_size > limits.decoded_bytes) return error.ResourceFailure;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            var source_reader = std.Io.Reader.fixed(input);
            if (dictionary == null and output_size >= history_base_size) {
                if (sink_resource.kind == .direct_write and common.sinkCapacity(sink_resource) >= output_size + zstd.block_size_max) {
                    // The decoder works in place, so the span holds the output plus one
                    // block of window slack. A corrupt frame can leave a tentative prefix
                    // and its working suffix.
                    const output = try common.sinkDirectBuffer(sink_resource, output_size + zstd.block_size_max);
                    var in_place_options = options;
                    in_place_options.max_decoded_bytes = output_size;
                    _ = zstd_seam.decodeInPlace(options.provider, &source_reader, output, in_place_options) catch |err| {
                        // A corrupt frame must not leave a tentative prefix and
                        // working suffix in the caller's buffer.
                        @memset(output, 0);
                        return err;
                    };
                } else {
                    const staging = try workspace.take(u8, output_size + zstd.block_size_max);
                    var in_place_options = options;
                    in_place_options.max_decoded_bytes = output_size;
                    _ = try zstd_seam.decodeInPlace(options.provider, &source_reader, staging, in_place_options);
                    try common.commitBytesToSink(sink_resource, call, staging[0..output_size]);
                }
            } else {
                const history = planned_history orelse try workspace.take(u8, history_base_size);
                const staging = try workspace.take(u8, output_size);
                var decode_sink = std.Io.Writer.fixed(staging);
                _ = try zstd_seam.decodeStream(options.provider, &source_reader, &decode_sink, history, options);
                try common.commitBytesToSink(sink_resource, call, staging);
            }
        }
        response.byte_length = output_size;
    } else if (command_mask == vocabulary.command_mask_write) {
        if (sink) |sink_resource| try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const dict_len = if (dictionary) |dict| dict.len else 0;
        const input_len = try common.measureSource(source_resource, limits.decoded_bytes);
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
            if (bound > limits.encoded_bytes) return error.ResourceFailure;
            break :blk bound;
        } else try planCountedEncode(source_resource, limits.decoded_bytes, limits.encoded_bytes, false, zstdEncodeStream, .{ .history = history, .workspace = encoder_workspace, .options = encode_options });
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            const staging = try workspace.take(u8, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(source_resource, limits.decoded_bytes);
            var staging_writer = std.Io.Writer.fixed(staging);
            const produced = try zstd.encodeStream(&bounded_source.reader, &staging_writer, history, encoder_workspace, encode_options);
            if (try common.verifiedCommitLength(sink_resource, call, sizing, staging, output_size, produced)) |produced_length| {
                response.byte_length = produced_length;
                return;
            }
        }
        response.byte_length = output_size;
    } else {
        return error.UnsupportedFailure;
    }
}

fn parseZstdOptions(request: ?*Node, command_mask: u32) Failure!zstd.Options {
    var options: zstd.Options = .{
        .window_size = try parseZstdWindow(optNode(request, "zstd", "window")),
        .dictionary = try parseZstdDictionary(optNode(request, "zstd", "dictionary")),
    };
    if (command_mask == vocabulary.command_mask_write or command_mask == vocabulary.command_mask_query) {
        if (try optCast(request, "zstd", "hash_bits", u5)) |hash_bits| {
            if (hash_bits < 10 or hash_bits > 17) return error.CallFailure;
            options.hash_bits = hash_bits;
        }
        if (try optCast(request, "zstd", "max_chain", u32)) |max_chain| {
            if (max_chain == 0) return error.CallFailure;
            options.max_chain = max_chain;
        }
        if (try optCast(request, "zstd", "nice_len", u32)) |nice_len| {
            if (nice_len < 3) return error.CallFailure;
            options.nice_len = nice_len;
        }
        if (try optCast(request, "zstd", "search_window", u32)) |search_window| {
            if (search_window == 0) return error.CallFailure;
            options.search_window = search_window;
        }
        if (optNode(request, "zstd", "lazy")) |node| options.lazy = node.value_low != 0;
        if (optNode(request, "zstd", "skip_interior_insert")) |node| options.skip_interior_insert = node.value_low != 0;
        if (optNode(request, "zstd", "double_hash")) |node| options.double_hash = node.value_low != 0;
        if (optNode(request, "zstd", "row_match")) |node| options.row_match = node.value_low != 0;
        if (try optCast(request, "zstd", "strategy", u32)) |strategy| {
            if (strategy > 3) return error.CallFailure;
            options.strategy = strategy;
        }
        if (try optCast(request, "zstd", "entropy", u32)) |entropy| {
            if (entropy > 1) return error.CallFailure;
            options.entropy = entropy;
        }
    }
    return options;
}

fn parseZstdWindow(node: ?*Node) Failure!u32 {
    const n = node orelse return error.CallFailure;
    const window = std.math.cast(u32, n.value_low) orelse return error.CallFailure;
    if (window < zstd.window_size_min or window > zstd.window_size_max) return error.CallFailure;
    return window;
}

fn parseZstdDictionary(node: ?*Node) Failure!?[]const u8 {
    const n = node orelse return null;
    if (n.value_low != 0 or n.child != null) return error.CallFailure;
    return @as(?[]const u8, try resource.checkedConstBytes(n.bytes, n.byte_length));
}

pub fn bzip2Hook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    var options = try parseBzip2Options(call.request, command_mask);
    options.max_work = limits.codec_work;
    options.provider = plan.provider;
    return bufferCodecHook(bzip2, plan, source, sink, call, response, sizing, commit, limits, command_mask, bzip2.decodeWorkspaceSize(bzip2.block_size_max), bzip2.encodeWorkspaceSize(options.block_size), options);
}

pub fn brotliHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const options = try parseBrotliOptions(call.request, command_mask);
    // The encoder lands with the dictionary support; read serves now.
    return bufferCodecHook(brotli, plan, source, sink, call, response, sizing, commit, limits, command_mask, brotli.decodeWorkspaceSize(options), 0, options);
}

fn parseBrotliOptions(request: ?*Node, command_mask: u32) Failure!brotli.Options {
    var options: brotli.Options = .{};
    if (command_mask == vocabulary.command_mask_write or command_mask == vocabulary.command_mask_query) {
        if (try optCast(request, "brotli", "quality", u32)) |quality| {
            if (quality > 11) return error.CallFailure;
            options.quality = quality;
        }
    }
    return options;
}

fn parseBzip2Options(request: ?*Node, command_mask: u32) Failure!bzip2.Options {
    var options: bzip2.Options = .{};
    if (command_mask == vocabulary.command_mask_write or command_mask == vocabulary.command_mask_query) {
        if (try optCast(request, "bzip2", "block_size", u32)) |block_size| {
            if (block_size < bzip2.block_size_min or block_size > bzip2.block_size_max) return error.CallFailure;
            options.block_size = block_size;
        }
    }
    return options;
}

fn parseDictionary(comptime component: []const u8, request: ?*Node, fallback: ?u32) Failure!u32 {
    const dictionary_size = (try optCast(request, component, "dictionary", u32)) orelse {
        if (fallback) |size| return size;
        return error.CallFailure;
    };
    if (dictionary_size < lzma.dictionary_min or dictionary_size > lzma.dictionary_max) return error.CallFailure;
    return dictionary_size;
}

fn parseLzmaDictionary(request: ?*Node) Failure!u32 {
    return parseDictionary("lzma", request, null);
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
    if (try optCast(request, "lzma", "match_finder_depth", u32)) |depth| {
        if (depth == 0) return error.CallFailure;
        params.match_finder_depth = depth;
    }
    if (optNode(request, "lzma", "lazy")) |node| {
        params.lazy = node.value_low != 0;
        params.lazy_set = true;
    }
    if (try optCast(request, "lzma", "nice_len", u32)) |nice_len| {
        if (nice_len < 2 or nice_len > 273) return error.CallFailure;
        params.nice_len = nice_len;
    }
    if (optNode(request, "lzma", "match_finder")) |node| {
        params.match_finder = switch (node.value_low) {
            0 => .hash_chain,
            1 => .bt4,
            else => return error.CallFailure,
        };
    }
    // BT4 defaults to lazy matching unless the caller explicitly opts into greedy.
    if (!params.lazy_set and params.match_finder == .bt4) {
        params.lazy = true;
    }
    return params;
}

fn lzmaFamilyHook(comptime Codec: type, plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const dictionary_size = try parseLzmaDictionary(call.request);
    const properties = lzma2.defaultProperties(dictionary_size);
    const params = try parseLzmaMatchParams(call.request, command_mask);
    if (Codec == lzma) {
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

pub fn lzmaHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    return lzmaFamilyHook(lzma, plan, source, sink, call, response, sizing, commit, limits, command_mask);
}

pub fn lzma2Hook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    return lzmaFamilyHook(lzma2, plan, source, sink, call, response, sizing, commit, limits, command_mask);
}

fn bufferCodecHook(comptime Codec: type, plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32, decode_workspace: usize, encode_workspace: usize, options: Codec.Options) Failure!void {
    const source_resource = source orelse return error.CallFailure;
    try requireReplay(source_resource, sizing, commit, false);
    if (sink == null) try common.checkSourceWorkspaceOverlap(call, source_resource);
    if (command_mask == vocabulary.command_mask_read) {
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const scratch = try workspace.take(u8, decode_workspace);
        const input = try common.materializeSource(.require_size, source_resource, &workspace, limits.encoded_bytes);
        if (sink) |sink_resource| {
            try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.UnsupportedFailure;
            var direct_route = false;
            if (Codec == lz4 and sink_resource.kind == .direct_write) {
                // One decode into workspace staging sized by the frame's declared
                // content size: a rejected read leaves the sink untouched, exactly like
                // the counted route, and the checksum failure still arrives from the leaf.
                if (try lz4.frameContentSize(input)) |declared| {
                    const size = std.math.cast(usize, declared) orelse return error.ResourceFailure;
                    if (size <= limits.decoded_bytes and input.len + size <= limits.codec_work) {
                        const staging = try workspace.take(u8, size);
                        if (codecDecodeDirectInPlace(Codec, input, staging, scratch, options)) |produced| {
                            if (produced > limits.decoded_bytes) return error.ResourceFailure;
                            try common.requireSinkCapacity(sink_resource, call, produced);
                            try common.commitBytesToSink(sink_resource, call, staging[0..produced]);
                            response.byte_length = produced;
                            direct_route = true;
                        } else |err| switch (err) {
                            // A span overrun means the declared size lied small: the measured
                            // route counts the true size and reports the exact status.
                            error.CapacityFailure => {},
                            else => return err,
                        }
                    }
                }
            }
            if (!direct_route and sink_resource.kind == .direct_write and try codecKnownOutputSize(Codec, options) == null and (Codec == lzma or Codec == bzip2)) {
                // No size preflight: the produced length comes back from the codec. lzma2 is excluded because chunk headers give a cheap size and in-place is faster.
                const output = try common.sinkDirectBuffer(sink_resource, common.sinkCapacity(sink_resource));
                if (input.len + output.len > limits.codec_work) return error.ResourceFailure;
                if (codecDecodeDirect(Codec, input, output, scratch, options)) |produced| {
                    if (produced > limits.decoded_bytes) return error.ResourceFailure;
                    response.byte_length = produced;
                    direct_route = true;
                } else |err| return err;
            }
            if (!direct_route) {
                const output_size = if (try codecKnownOutputSize(Codec, options)) |size| size else try codecDecodedSize(Codec, input, scratch, options);
                if (output_size > limits.decoded_bytes) return error.ResourceFailure;
                if (input.len + output_size > limits.codec_work) return error.ResourceFailure;
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
            if (output_size > limits.decoded_bytes) return error.ResourceFailure;
            if (input.len + output_size > limits.codec_work) return error.ResourceFailure;
            response.byte_length = output_size;
        }
    } else if (command_mask == vocabulary.command_mask_write) {
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const scratch = try workspace.take(u8, encode_workspace);
        const input = try common.materializeSource(.require_size, source_resource, &workspace, limits.decoded_bytes);
        const output_size = if (sizing == .bounded) Codec.encodedSizeBound(input.len) else try Codec.requiredSize(input, scratch, options);
        if (output_size > limits.encoded_bytes) return error.ResourceFailure;
        if (input.len + output_size > limits.codec_work) return error.ResourceFailure;
        if (sink) |sink_resource| {
            try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
            try common.requireSink(sink_resource, call, output_size);
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
                if (try common.verifiedCommitLength(sink_resource, call, sizing, staging, output_size, produced)) |produced_length| {
                    response.byte_length = produced_length;
                    return;
                }
            }
        }
        response.byte_length = output_size;
    } else {
        return error.UnsupportedFailure;
    }
}

fn codecKnownOutputSize(comptime Codec: type, options: Codec.Options) Failure!?usize {
    if (!@hasField(Codec.Options, "unpack_size")) return null;
    const size = options.unpack_size orelse return null;
    return std.math.cast(usize, size) orelse error.ResourceFailure;
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
    const source_resource = source orelse return error.CallFailure;
    try requireReplay(source_resource, sizing, commit, false);
    if (sink == null) try common.checkSourceWorkspaceOverlap(call, source_resource);
    if (command_mask == vocabulary.command_mask_read) {
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const input = try common.materializeSource(.require_size, source_resource, &workspace, limits.encoded_bytes);
        if (input.len < lzma_file.header_size) return error.DataFailure;
        if (sink == null and optNode(call.request, "lzma-file", "properties") != null) {
            // Read-side header projection: the properties byte of the
            // lzma-alone header, without decoding.
            response.byte_length = try lzma_file.inspectProperties(input);
            return;
        }
        const options = try lzma_file.decodeOptions(input);
        const scratch = try workspace.take(u8, lzma.decodeWorkspaceSize(options.properties));
        const output_size = if (options.unpack_size) |size| std.math.cast(usize, size) orelse return error.ResourceFailure else try lzma_file.decodedSize(input, scratch, plan.provider);
        if (output_size > limits.decoded_bytes) return error.ResourceFailure;
        if (sink) |sink_resource| {
            try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
            try common.requireSink(sink_resource, call, output_size);
            if (sink_resource.kind == .direct_write) {
                const output = try common.sinkDirectBuffer(sink_resource, output_size);
                _ = try lzma_file.decodeInPlace(input, output, scratch, plan.provider);
            } else {
                var bounded_sink = resource.BoundedWriter.init(sink_resource, limits.decoded_bytes);
                lzma_file.decodeToWriter(input, &bounded_sink.writer, scratch, plan.provider) catch |err| return common.mapSinkError(err, call, sink_resource);
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
        if (output_size > limits.encoded_bytes) return error.ResourceFailure;
        if (input.len + output_size > limits.codec_work) return error.ResourceFailure;
        if (sink) |sink_resource| {
            try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
            try common.requireSink(sink_resource, call, output_size);
            const staging = try workspace.take(u8, output_size);
            const produced = try lzma_file.encode(input, staging, scratch, options);
            if (try common.verifiedCommitLength(sink_resource, call, sizing, staging, output_size, produced)) |produced_length| {
                response.byte_length = produced_length;
                return;
            }
        }
        response.byte_length = output_size;
    } else {
        return error.UnsupportedFailure;
    }
}

fn parseLzmaFileDictionary(request: ?*Node) Failure!u32 {
    return parseDictionary("lzma-file", request, lzma_file.default_dictionary);
}

pub fn xzHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const source_resource = source orelse return error.CallFailure;
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
            if (node.value_low < 1 or node.value_low > 255) return error.CallFailure;
            delta_distance = @intCast(node.value_low);
        }
    }
    const params = try parseLzmaMatchParams(call.request, command_mask);
    const block_size = std.math.cast(u32, node_graph.parseU64(node_graph.findSelector(
        call.request,
        comptime discovery.parameter("xz", "block_size").family,
        comptime discovery.parameter("xz", "block_size").ordinal,
    ))) orelse return error.CallFailure;
    if (command_mask == vocabulary.command_mask_read) {
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const scratch = try workspace.take(u8, xz.decodeWorkspaceSize(dictionary_size));
        const input = try common.materializeSource(.require_size, source_resource, &workspace, limits.encoded_bytes);
        if (input.len > limits.encoded_bytes) return error.ResourceFailure;
        if (sink == null and optNode(call.request, "xz", "check") != null) {
            // Read-side header projection: the check selector asks for the
            // stream's check type id without decoding anything.
            response.byte_length = try xz.inspectCheck(input, plan.provider);
            return;
        }
        const output_size = try xz.decodedSize(input, scratch, plan.provider);
        if (output_size > limits.decoded_bytes) return error.ResourceFailure;
        if (input.len + output_size > limits.codec_work) return error.ResourceFailure;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            const staging = try workspace.take(u8, output_size);
            _ = try xz.decodeInPlace(input, staging, scratch, plan.provider);
            try common.commitBytesToSink(sink_resource, call, staging);
        }
        response.byte_length = output_size;
    } else if (command_mask == vocabulary.command_mask_write) {
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const input = try common.materializeSource(.require_size, source_resource, &workspace, limits.decoded_bytes);
        if (input.len > limits.decoded_bytes) return error.ResourceFailure;
        const encode_workspace = if (params.match_finder == .bt4) xz.encodeWorkspaceSizeBt(dictionary_size) else xz.encodeWorkspaceSize(dictionary_size);
        // Beyond the encoder workspace: index records per block, plus the
        // 1:1 filter staging when a filter chain is active.
        const scratch = try workspace.take(u8, encode_workspace + xz.blockRecordScratchSize(input.len, block_size) + (if (filters != .none) input.len else 0));
        const options = xz.Options{
            .dictionary_size = dictionary_size,
            .check = check,
            .filters = filters,
            .delta_distance = delta_distance,
            .match_finder_depth = params.match_finder_depth,
            .lazy = params.lazy,
            .nice_len = params.nice_len,
            .match_finder = params.match_finder,
            .block_size = block_size,
            .provider = plan.provider,
        };
        const output_size = if (sizing == .bounded) xz.encodedSizeBound(input.len, options.block_size) else try xz.requiredSize(input, scratch, options);
        if (output_size > limits.encoded_bytes) return error.ResourceFailure;
        if (input.len + output_size > limits.codec_work) return error.ResourceFailure;
        if (sink) |sink_resource| {
            try common.requireSink(sink_resource, call, output_size);
            const staging = try workspace.take(u8, output_size);
            const produced = try xz.encode(input, staging, scratch, options);
            if (try common.verifiedCommitLength(sink_resource, call, sizing, staging, output_size, produced)) |produced_length| {
                response.byte_length = produced_length;
                return;
            }
        }
        response.byte_length = output_size;
    } else {
        return error.UnsupportedFailure;
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
        else => error.UnsupportedFailure,
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
        else => error.CallFailure,
    };
}
