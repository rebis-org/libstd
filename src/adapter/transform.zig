const std = @import("std");

const abi = @import("../abi/contract.zig");
const Id = abi.Id;
const Node = abi.Node;
const Call = abi.Call;
const registry = @import("../catalog/registry.zig");
const Failure = registry.Failure;
const node_graph = @import("../common/node.zig");
const measurement = @import("../common/primitive/measurement.zig");
const resource = @import("../common/resource.zig");
const Resource = resource.Resource;
const Limits = resource.Limits;
const gzip = @import("../grammar/gzip.zig");
const lzma_file = @import("../grammar/lzma.zig");
const xz = @import("../grammar/xz.zig");
const bzip2 = @import("../leaf/bzip2.zig");
const deflate = @import("../leaf/deflate.zig");
const lzma = @import("../leaf/lzma.zig");
const lzma2 = @import("../leaf/lzma2.zig");
const zstd = @import("../leaf/zstd.zig");
const common = @import("common.zig");

const deflate_options: deflate.Options = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 8 };

fn requireReplay(source: *Resource, planning: registry.PlanningMode, delivery: registry.DeliveryMode, comptime verified: bool) Failure!void {
    if (planning != .replay_pass and planning != .bound) return error.Unsupported;
    const expected: registry.DeliveryMode = if (verified) .verified else .provisional;
    if (delivery != expected) return error.Unsupported;
    if (!source.hasCapability(resource.capability_bit_read) or !source.hasCapability(resource.capability_bit_replay)) return error.Unsupported;
}

pub fn testHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, planning: registry.PlanningMode, delivery: registry.DeliveryMode, limits: Limits, command_mask: u32) Failure!void {
    _ = command_mask;
    const src = source orelse return error.InvalidCall;
    const snk = sink orelse return error.InvalidCall;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    const output_size = try common.planOutputSize(src, planning, limits, &workspace);
    try common.requireSinkCapacity(snk, call, output_size);
    const staging_required: usize = if (delivery == .verified) output_size else 0;
    if (workspace.bytes.len < staging_required) {
        common.writeCapacityDiagnostic(call, staging_required, workspace.bytes.len);
        return error.InsufficientCapacity;
    }
    if (delivery == .verified) {
        const staging = try workspace.take(u8, output_size);
        var offset: usize = 0;
        while (offset < staging.len) {
            const n = try src.read(staging[offset..]);
            if (n == 0) return error.IoFailure;
            offset += n;
        }
        if (staging.len > 0 and staging[staging.len - 1] == 0xff) return error.IntegrityFailure;
        try common.deliver(snk, call, staging);
    } else {
        var buffer: [4096]u8 = undefined;
        var remaining = output_size;
        while (remaining > 0) {
            const chunk = @min(remaining, buffer.len);
            const n = try src.read(buffer[0..chunk]);
            if (n == 0) return error.IoFailure;
            try common.deliver(snk, call, buffer[0..n]);
            remaining -= n;
        }
    }
    response.byte_length = output_size;
}

pub fn deflateHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, planning: registry.PlanningMode, delivery: registry.DeliveryMode, limits: Limits, command_mask: u32) Failure!void {
    const src = source orelse return error.InvalidCall;
    try requireReplay(src, planning, delivery, false);
    const deflate_opts = try parseDeflateOptions(call.request, command_mask);
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    const history = try workspace.take(u8, deflate.history_size + @as(usize, if (deflate_opts.optimal) deflate.optimal_workspace_size else 0));
    if (command_mask == registry.command_mask_read) {
        const output_size = try planDeflateDecode(src, history, limits.encoded_bytes, limits.decoded_bytes);
        if (sink) |snk| {
            if (!snk.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(snk, call, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(src, limits.encoded_bytes);
            var bounded_sink = resource.BoundedWriter.init(snk, limits.decoded_bytes);
            var inflater = deflate.Decompress.init(&bounded_source.reader, history);
            _ = inflater.reader.streamRemaining(&bounded_sink.writer) catch |err| return common.mapSinkError(switch (err) {
                error.WriteFailed => error.IoFailure,
                else => error.InvalidData,
            }, call, snk);
        }
        response.byte_length = output_size;
    } else if (command_mask == registry.command_mask_write) {
        const output_size = if (planning == .bound) blk: {
            const input_len = try measureSourceLength(src, limits.decoded_bytes);
            const bound = deflate.encodedSizeBound(input_len);
            if (bound > limits.encoded_bytes) return error.ResourceLimit;
            break :blk bound;
        } else try planDeflateEncode(src, history, deflate_opts, limits.decoded_bytes, limits.encoded_bytes);
        if (sink) |snk| {
            if (!snk.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(snk, call, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(src, limits.decoded_bytes);
            var bounded_sink = resource.BoundedWriter.init(snk, limits.encoded_bytes);
            var compressor = deflate.Compress.init(&bounded_sink.writer, history, deflate_opts) catch |err| return err;
            _ = std.Io.Reader.streamRemaining(&bounded_source.reader, &compressor.writer) catch return common.mapSinkError(error.IoFailure, call, snk);
            compressor.finish() catch return common.mapSinkError(error.IoFailure, call, snk);
            if (planning == .bound) {
                const produced = limits.encoded_bytes - bounded_sink.limit;
                if (produced > output_size) return error.InternalFailure;
                response.byte_length = produced;
                return;
            }
        }
        response.byte_length = output_size;
    } else {
        return error.Unsupported;
    }
}

pub fn gzipHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, planning: registry.PlanningMode, delivery: registry.DeliveryMode, limits: Limits, command_mask: u32) Failure!void {
    const src = source orelse return error.InvalidCall;
    try requireReplay(src, planning, delivery, false);
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    const options = try parseGzipOptions(call.request, command_mask);
    const history = try workspace.take(u8, gzip.deflate_history_size + @as(usize, if (options.deflate.optimal) deflate.optimal_workspace_size else 0));
    if (command_mask == registry.command_mask_read) {
        const input = switch (src.kind) {
            .direct_read => |bytes| bytes,
            .callback_read => try common.materializeSource(.budget, src, &workspace, limits.encoded_bytes),
            else => return error.Unsupported,
        };
        if (input.len > limits.encoded_bytes) return error.ResourceLimit;
        if (sink) |snk| {
            if (snk.kind == .direct_write and snk.hasCapability(resource.capability_bit_write)) {
                // KD3 single-pass read: when the trailer ISIZE fits the direct
                // span, decode once into it. A .fallback restarts through the
                // two-pass route below, which recomputes the exact size and
                // answers capacity before any further write, so a capacity
                // failure is never reported after the write begins. KD2
                // carve-out: an aborted fast-path attempt may leave a
                // provisional prefix in the sink, so a capacity failure after
                // a fallback is not guaranteed to leave the output unchanged.
                switch (try gzip.decodeSinglePass(input, snk.kind.direct_write, history)) {
                    .decoded => |produced| {
                        if (produced > limits.decoded_bytes) return error.ResourceLimit;
                        response.byte_length = produced;
                        return;
                    },
                    .fallback => {},
                }
            }
        }
        const output_size = try gzip.decodedSize(input, history);
        if (output_size > limits.decoded_bytes) return error.ResourceLimit;
        if (sink) |snk| {
            if (!snk.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(snk, call, output_size);
            var bounded_sink = resource.BoundedWriter.init(snk, limits.decoded_bytes);
            const produced = gzip.decode(input, &bounded_sink.writer, history) catch |err| return common.mapSinkError(err, call, snk);
            response.byte_length = produced;
        } else {
            response.byte_length = output_size;
        }
    } else if (command_mask == registry.command_mask_write) {
        const output_size = if (planning == .bound) blk: {
            const input_len = try measureSourceLength(src, limits.decoded_bytes);
            const bound = gzip.encodedSizeBound(input_len, options);
            if (bound > limits.encoded_bytes) return error.ResourceLimit;
            break :blk bound;
        } else try planGzipEncode(src, history, options, limits.decoded_bytes, limits.encoded_bytes);
        if (sink) |snk| {
            if (!snk.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(snk, call, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(src, limits.decoded_bytes);
            var bounded_sink = resource.BoundedWriter.init(snk, limits.encoded_bytes);
            gzip.encodeStream(&bounded_source.reader, &bounded_sink.writer, history, options) catch |err| return common.mapSinkError(err, call, snk);
            if (planning == .bound) {
                const produced = limits.encoded_bytes - bounded_sink.limit;
                if (produced > output_size) return error.InternalFailure;
                response.byte_length = produced;
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
    if (node_graph.findSelector(request, registry.parameter_family_gzip, registry.gzip_parameter.modification_time)) |node| {
        options.modification_time = @truncate(node.value_low);
    }
    if (node_graph.findSelector(request, registry.parameter_family_gzip, registry.gzip_parameter.extra_flags)) |node| {
        options.extra_flags = @truncate(node.value_low);
    }
    if (node_graph.findSelector(request, registry.parameter_family_gzip, registry.gzip_parameter.operating_system)) |node| {
        options.operating_system = @truncate(node.value_low);
    }
    if (node_graph.findSelector(request, registry.parameter_family_gzip, registry.gzip_parameter.text)) |node| {
        options.text = node.value_low != 0;
    }
    if (node_graph.findSelector(request, registry.parameter_family_gzip, registry.gzip_parameter.header_crc)) |node| {
        options.header_crc = node.value_low != 0;
    }
    if (node_graph.findSelector(request, registry.parameter_family_gzip, registry.gzip_parameter.extra)) |node| {
        options.extra = try resource.checkedConstBytes(node.bytes, node.byte_length);
    }
    if (node_graph.findSelector(request, registry.parameter_family_gzip, registry.gzip_parameter.name)) |node| {
        options.name = try resource.checkedConstBytes(node.bytes, node.byte_length);
    }
    if (node_graph.findSelector(request, registry.parameter_family_gzip, registry.gzip_parameter.comment)) |node| {
        options.comment = try resource.checkedConstBytes(node.bytes, node.byte_length);
    }
    return options;
}

fn parseDeflateOptions(request: ?*Node, command_mask: u32) Failure!deflate.Options {
    var options = deflate_options;
    if (command_mask != registry.command_mask_write and command_mask != registry.command_mask_query) return options;
    if (node_graph.findSelector(request, registry.parameter_family_deflate, registry.deflate_parameter.good)) |node| {
        options.good = std.math.cast(u16, node.value_low) orelse return error.InvalidCall;
    }
    if (node_graph.findSelector(request, registry.parameter_family_deflate, registry.deflate_parameter.nice)) |node| {
        options.nice = std.math.cast(u16, node.value_low) orelse return error.InvalidCall;
    }
    if (node_graph.findSelector(request, registry.parameter_family_deflate, registry.deflate_parameter.lazy)) |node| {
        options.lazy = std.math.cast(u16, node.value_low) orelse return error.InvalidCall;
    }
    if (node_graph.findSelector(request, registry.parameter_family_deflate, registry.deflate_parameter.chain)) |node| {
        options.chain = std.math.cast(u16, node.value_low) orelse return error.InvalidCall;
    }
    if (node_graph.findSelector(request, registry.parameter_family_deflate, registry.deflate_parameter.optimal)) |node| {
        options.optimal = node.value_low != 0;
    }
    return options;
}

fn planGzipEncode(source: *Resource, history: []u8, options: gzip.Options, decoded_limit: u64, encoded_limit: u64) Failure!usize {
    var bounded_source: resource.BoundedReader = undefined;
    bounded_source.init(source, decoded_limit);
    var counter = measurement.Counter.init(null);
    gzip.encodeStream(&bounded_source.reader, &counter.writer, history, options) catch return error.IoFailure;
    const output_size = counter.written();
    if (output_size > encoded_limit) return error.ResourceLimit;
    try source.rewind();
    return std.math.cast(usize, output_size) orelse error.ResourceLimit;
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

fn planDeflateEncode(source: *Resource, history: []u8, options: deflate.Options, decoded_limit: u64, encoded_limit: u64) Failure!usize {
    var bounded_source: resource.BoundedReader = undefined;
    bounded_source.init(source, decoded_limit);
    var counter = measurement.Counter.init(null);
    var compressor = deflate.Compress.init(&counter.writer, history, options) catch |err| return err;
    _ = std.Io.Reader.streamRemaining(&bounded_source.reader, &compressor.writer) catch return error.IoFailure;
    compressor.finish() catch return error.IoFailure;
    try source.rewind();
    const output_size = counter.written();
    if (output_size > encoded_limit) return error.ResourceLimit;
    return std.math.cast(usize, output_size) orelse error.ResourceLimit;
}

pub fn zstdHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, planning: registry.PlanningMode, delivery: registry.DeliveryMode, limits: Limits, command_mask: u32) Failure!void {
    const src = source orelse return error.InvalidCall;
    try requireReplay(src, planning, delivery, true);
    const options = try parseZstdOptions(call.request, command_mask);
    const window = options.window_size;
    const dictionary = options.dictionary;
    const history_base_size = @as(usize, window) + zstd.block_size_max +
        (if (dictionary) |dict| dict.len else 0);
    if (command_mask == registry.command_mask_read) {
        if (sink) |snk| try common.checkWorkspaceOverlap(call, src, snk);
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const input = try common.materializeSource(.replay, src, &workspace, limits.encoded_bytes);
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
        if (sink) |snk| {
            if (!snk.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(snk, call, output_size);
            var source_reader = std.Io.Reader.fixed(input);
            if (dictionary == null and output_size >= history_base_size) {
                const staging = try workspace.take(u8, output_size + zstd.block_size_max);
                var in_place_options = options;
                in_place_options.max_decoded_bytes = output_size;
                _ = zstd.decodeInPlace(&source_reader, staging, in_place_options) catch |err| return err;
                try common.deliver(snk, call, staging[0..output_size]);
            } else {
                const history = planned_history orelse try workspace.take(u8, history_base_size);
                const staging = try workspace.take(u8, output_size);
                var decode_sink = std.Io.Writer.fixed(staging);
                _ = zstd.decodeStream(&source_reader, &decode_sink, history, options) catch |err| return err;
                try common.deliver(snk, call, staging);
            }
        }
        response.byte_length = output_size;
    } else if (command_mask == registry.command_mask_write) {
        if (sink) |snk| try common.checkWorkspaceOverlap(call, src, snk);
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const dict_len = if (dictionary) |dict| dict.len else 0;
        const input_len = try measureSourceLength(src, limits.decoded_bytes);
        const frame_budget = if (zstd.useDfast(options) or zstd.useRowMatch(options))
            @min(input_len, zstd.encoder_frame_size_max)
        else
            @min(window, zstd.encoder_frame_size_max);
        const history = try workspace.take(u8, dict_len + @max(frame_budget, window) + zstd.block_size_max);
        const encoder_workspace = try workspace.take(u32, zstd.encoderWorkspaceU32Count(dict_len, frame_budget, options));
        var encode_options = options;
        encode_options.max_encoded_bytes = limits.encoded_bytes;
        encode_options.max_decoded_bytes = limits.decoded_bytes;
        const output_size = if (planning == .bound) blk: {
            const bound = zstd.encodedSizeBound(input_len, encode_options);
            if (bound > limits.encoded_bytes) return error.ResourceLimit;
            break :blk bound;
        } else try planZstdEncode(src, history, encoder_workspace, encode_options, limits.decoded_bytes, limits.encoded_bytes);
        if (sink) |snk| {
            if (!snk.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(snk, call, output_size);
            const staging = try workspace.take(u8, output_size);
            var bounded_source: resource.BoundedReader = undefined;
            bounded_source.init(src, limits.decoded_bytes);
            var staging_writer = std.Io.Writer.fixed(staging);
            const produced = zstd.encodeStream(&bounded_source.reader, &staging_writer, history, encoder_workspace, encode_options) catch |err| return err;
            if (planning == .bound) {
                if (produced > output_size) return error.InternalFailure;
                try common.deliver(snk, call, staging[0..produced]);
                response.byte_length = produced;
                return;
            }
            try common.deliver(snk, call, staging);
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

fn planZstdEncode(source: *Resource, history: []u8, workspace: []u32, options: zstd.Options, decoded_limit: u64, encoded_limit: u64) Failure!usize {
    var bounded_source: resource.BoundedReader = undefined;
    bounded_source.init(source, decoded_limit);
    var counter = measurement.Counter.init(null);
    _ = zstd.encodeStream(&bounded_source.reader, &counter.writer, history, workspace, options) catch |err| return err;
    try source.rewind();
    const output_size = counter.written();
    if (output_size > encoded_limit) return error.ResourceLimit;
    return std.math.cast(usize, output_size) orelse error.ResourceLimit;
}

fn parseZstdOptions(request: ?*Node, command_mask: u32) Failure!zstd.Options {
    var options: zstd.Options = .{
        .window_size = try parseZstdWindow(node_graph.findSelector(request, registry.parameter_family_zstd, registry.zstd_parameter.window)),
        .dictionary = try parseZstdDictionary(node_graph.findSelector(request, registry.parameter_family_zstd, registry.zstd_parameter.dictionary)),
    };
    if (command_mask == registry.command_mask_write or command_mask == registry.command_mask_query) {
        if (node_graph.findSelector(request, registry.parameter_family_zstd, registry.zstd_parameter.hash_bits)) |node| {
            const hash_bits = std.math.cast(u5, node.value_low) orelse return error.InvalidCall;
            if (hash_bits < 10 or hash_bits > 17) return error.InvalidCall;
            options.hash_bits = hash_bits;
        }
        if (node_graph.findSelector(request, registry.parameter_family_zstd, registry.zstd_parameter.max_chain)) |node| {
            const max_chain = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
            if (max_chain == 0) return error.InvalidCall;
            options.max_chain = max_chain;
        }
        if (node_graph.findSelector(request, registry.parameter_family_zstd, registry.zstd_parameter.nice_len)) |node| {
            const nice_len = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
            if (nice_len < 3) return error.InvalidCall;
            options.nice_len = nice_len;
        }
        if (node_graph.findSelector(request, registry.parameter_family_zstd, registry.zstd_parameter.search_window)) |node| {
            const search_window = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
            if (search_window == 0) return error.InvalidCall;
            options.search_window = search_window;
        }
        if (node_graph.findSelector(request, registry.parameter_family_zstd, registry.zstd_parameter.lazy)) |node| {
            options.lazy = node.value_low != 0;
        }
        if (node_graph.findSelector(request, registry.parameter_family_zstd, registry.zstd_parameter.skip_interior_insert)) |node| {
            options.skip_interior_insert = node.value_low != 0;
        }
        if (node_graph.findSelector(request, registry.parameter_family_zstd, registry.zstd_parameter.double_hash)) |node| {
            options.double_hash = node.value_low != 0;
        }
        if (node_graph.findSelector(request, registry.parameter_family_zstd, registry.zstd_parameter.row_match)) |node| {
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

pub fn bzip2Hook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, planning: registry.PlanningMode, delivery: registry.DeliveryMode, limits: Limits, command_mask: u32) Failure!void {
    var options = try parseBzip2Options(call.request, command_mask);
    options.max_work = limits.codec_work;
    return bufferCodecHook(bzip2, plan, source, sink, call, response, planning, delivery, limits, command_mask, bzip2.decodeWorkspaceSize(bzip2.block_size_max), bzip2.encodeWorkspaceSize(options.block_size), options);
}

fn parseBzip2Options(request: ?*Node, command_mask: u32) Failure!bzip2.Options {
    var options: bzip2.Options = .{};
    if (command_mask == registry.command_mask_write or command_mask == registry.command_mask_query) {
        if (node_graph.findSelector(request, registry.parameter_family_bzip2, registry.bzip2_parameter.block_size)) |node| {
            const block_size = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
            if (block_size < bzip2.block_size_min or block_size > bzip2.block_size_max) return error.InvalidCall;
            options.block_size = block_size;
        }
    }
    return options;
}

fn parseLzmaDictionary(request: ?*Node) Failure!u32 {
    const node = node_graph.findSelector(request, registry.parameter_family_lzma, registry.lzma_parameter.dictionary) orelse return error.InvalidCall;
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
    if (command_mask != registry.command_mask_write and command_mask != registry.command_mask_query) return params;
    if (node_graph.findSelector(request, registry.parameter_family_lzma, registry.lzma_parameter.match_finder_depth)) |node| {
        params.match_finder_depth = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
        if (params.match_finder_depth == 0) return error.InvalidCall;
    }
    if (node_graph.findSelector(request, registry.parameter_family_lzma, registry.lzma_parameter.lazy)) |node| {
        params.lazy = node.value_low != 0;
        params.lazy_set = true;
    }
    if (node_graph.findSelector(request, registry.parameter_family_lzma, registry.lzma_parameter.nice_len)) |node| {
        params.nice_len = std.math.cast(u32, node.value_low) orelse return error.InvalidCall;
        if (params.nice_len < 2 or params.nice_len > 273) return error.InvalidCall;
    }
    if (node_graph.findSelector(request, registry.parameter_family_lzma, registry.lzma_parameter.match_finder)) |node| {
        params.match_finder = switch (node.value_low) {
            0 => .hash_chain,
            1 => .bt4,
            else => return error.InvalidCall,
        };
    }
    // BT4 is used for compression-quality tunings; enable classic lazy matching
    // by default unless the caller explicitly selected the simpler greedy path.
    if (!params.lazy_set and params.match_finder == .bt4) {
        params.lazy = true;
    }
    return params;
}

pub fn lzmaHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, planning: registry.PlanningMode, delivery: registry.DeliveryMode, limits: Limits, command_mask: u32) Failure!void {
    const dictionary_size = try parseLzmaDictionary(call.request);
    const properties = lzma2.properties(dictionary_size);
    const params = try parseLzmaMatchParams(call.request, command_mask);
    const encode_workspace = if (params.match_finder == .bt4) lzma.encodeWorkspaceSizeBt(properties) else lzma.encodeWorkspaceSize(properties);
    return bufferCodecHook(lzma, plan, source, sink, call, response, planning, delivery, limits, command_mask, lzma.decodeWorkspaceSize(properties), encode_workspace, .{
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

pub fn lzma2Hook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, planning: registry.PlanningMode, delivery: registry.DeliveryMode, limits: Limits, command_mask: u32) Failure!void {
    const dictionary_size = try parseLzmaDictionary(call.request);
    const properties = lzma2.properties(dictionary_size);
    const params = try parseLzmaMatchParams(call.request, command_mask);
    const encode_workspace = if (params.match_finder == .bt4) lzma2.encodeWorkspaceSizeBt(dictionary_size) else lzma2.encodeWorkspaceSize(dictionary_size);
    return bufferCodecHook(lzma2, plan, source, sink, call, response, planning, delivery, limits, command_mask, lzma2.decodeWorkspaceSize(dictionary_size), encode_workspace, .{
        .dictionary_size = dictionary_size,
        .properties = properties,
        .max_work = limits.codec_work,
        .match_finder_depth = params.match_finder_depth,
        .lazy = params.lazy,
        .nice_len = params.nice_len,
        .match_finder = params.match_finder,
    });
}

fn bufferCodecHook(comptime Codec: type, plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, planning: registry.PlanningMode, delivery: registry.DeliveryMode, limits: Limits, command_mask: u32, decode_workspace: usize, encode_workspace: usize, options: Codec.Options) Failure!void {
    const src = source orelse return error.InvalidCall;
    try requireReplay(src, planning, delivery, false);
    if (sink == null) try common.checkSourceWorkspaceOverlap(call, src);
    if (command_mask == registry.command_mask_read) {
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const scratch = try workspace.take(u8, decode_workspace);
        const input = try common.materializeSource(.require_size, src, &workspace, limits.encoded_bytes);
        if (sink) |snk| {
            try common.checkWorkspaceOverlap(call, src, snk);
            if (!snk.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            if (snk.kind == .direct_write and try codecKnownOutputSize(Codec, options) == null and (Codec == lzma or Codec == bzip2)) {
                // Single-pass decode into the caller's direct span. The span must
                // be large enough for the decoded stream; the produced length is
                // returned by the codec, so no size-preflight pass is needed.
                // lzma2 is excluded because its size is cheaply known from chunk
                // headers and its in-place path is faster than the writer path.
                const output = try common.sinkDirectBuffer(snk, common.sinkCapacity(snk));
                if (input.len + output.len > limits.codec_work) return error.ResourceLimit;
                const produced = try codecDecodeDirect(Codec, input, output, scratch, options);
                if (produced > limits.decoded_bytes) return error.ResourceLimit;
                response.byte_length = produced;
            } else {
                const output_size = if (try codecKnownOutputSize(Codec, options)) |size| size else try codecDecodedSize(Codec, input, scratch, options);
                if (output_size > limits.decoded_bytes) return error.ResourceLimit;
                if (input.len + output_size > limits.codec_work) return error.ResourceLimit;
                try common.requireSinkCapacity(snk, call, output_size);
                if (snk.kind == .direct_write) {
                    const output = try common.sinkDirectBuffer(snk, output_size);
                    _ = try codecDecodeDirectInPlace(Codec, input, output, scratch, options);
                } else {
                    const staging = try workspace.take(u8, output_size);
                    var fixed_writer = std.Io.Writer.fixed(staging);
                    codecDecodeToWriter(Codec, input, &fixed_writer, scratch, options) catch |err| return common.mapSinkError(err, call, snk);
                    try common.deliver(snk, call, staging);
                }
                response.byte_length = output_size;
            }
        } else {
            const output_size = if (try codecKnownOutputSize(Codec, options)) |size| size else try codecDecodedSize(Codec, input, scratch, options);
            if (output_size > limits.decoded_bytes) return error.ResourceLimit;
            if (input.len + output_size > limits.codec_work) return error.ResourceLimit;
            response.byte_length = output_size;
        }
    } else if (command_mask == registry.command_mask_write) {
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const scratch = try workspace.take(u8, encode_workspace);
        const input = try common.materializeSource(.require_size, src, &workspace, limits.decoded_bytes);
        const output_size = if (planning == .bound) Codec.encodedSizeBound(input.len) else try Codec.requiredSize(input, scratch, options);
        if (output_size > limits.encoded_bytes) return error.ResourceLimit;
        if (input.len + output_size > limits.codec_work) return error.ResourceLimit;
        if (sink) |snk| {
            try common.checkWorkspaceOverlap(call, src, snk);
            if (!snk.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(snk, call, output_size);
            if (snk.kind == .direct_write) {
                const output = try common.sinkDirectBuffer(snk, output_size);
                const produced = try Codec.encode(input, output, scratch, options);
                if (planning == .bound) {
                    if (produced > output_size) return error.InternalFailure;
                    response.byte_length = produced;
                    return;
                }
            } else {
                const staging = try workspace.take(u8, output_size);
                const produced = try Codec.encode(input, staging, scratch, options);
                if (planning == .bound) {
                    if (produced > output_size) return error.InternalFailure;
                    try common.deliver(snk, call, staging[0..produced]);
                    response.byte_length = produced;
                    return;
                }
                try common.deliver(snk, call, staging);
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
    if (Codec == bzip2) return bzip2.decodedSize(input, scratch);
    return Codec.decodedSize(input, scratch, options);
}

fn codecDecodeToWriter(comptime Codec: type, input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Codec.Options) Failure!void {
    if (Codec == bzip2) return bzip2.decodeToWriter(input, writer, scratch);
    return Codec.decodeToWriter(input, writer, scratch, options);
}

fn codecDecodeDirect(comptime Codec: type, input: []const u8, output: []u8, scratch: []u8, options: Codec.Options) Failure!usize {
    if (Codec == bzip2) return bzip2.decode(input, output, scratch);
    return Codec.decode(input, output, scratch, options);
}

fn codecDecodeDirectInPlace(comptime Codec: type, input: []const u8, output: []u8, scratch: []u8, options: Codec.Options) Failure!usize {
    if (Codec == bzip2) return bzip2.decode(input, output, scratch);
    const result = try Codec.decodeInPlace(input, output, scratch, options);
    return if (Codec == lzma2) result.produced else result;
}

pub fn lzmaFileHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, planning: registry.PlanningMode, delivery: registry.DeliveryMode, limits: Limits, command_mask: u32) Failure!void {
    const src = source orelse return error.InvalidCall;
    try requireReplay(src, planning, delivery, false);
    if (sink == null) try common.checkSourceWorkspaceOverlap(call, src);
    if (command_mask != registry.command_mask_read) return error.Unsupported;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    const input = try common.materializeSource(.require_size, src, &workspace, limits.encoded_bytes);
    if (input.len < lzma_file.header_size) return error.InvalidData;
    const options = try lzma_file.decodeOptions(input);
    const scratch = try workspace.take(u8, lzma.decodeWorkspaceSize(options.properties));
    const output_size = if (options.unpack_size) |size| std.math.cast(usize, size) orelse return error.ResourceLimit else try lzma_file.decodedSize(input, scratch);
    if (output_size > limits.decoded_bytes) return error.ResourceLimit;
    if (sink) |snk| {
        try common.checkWorkspaceOverlap(call, src, snk);
        if (!snk.hasCapability(resource.capability_bit_write)) return error.Unsupported;
        try common.requireSinkCapacity(snk, call, output_size);
        if (snk.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(snk, output_size);
            _ = try lzma_file.decodeInPlace(input, output, scratch);
        } else {
            var bounded_sink = resource.BoundedWriter.init(snk, limits.decoded_bytes);
            lzma_file.decodeToWriter(input, &bounded_sink.writer, scratch) catch |err| return common.mapSinkError(err, call, snk);
        }
    }
    response.byte_length = output_size;
}

pub fn xzHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, planning: registry.PlanningMode, delivery: registry.DeliveryMode, limits: Limits, command_mask: u32) Failure!void {
    const src = source orelse return error.InvalidCall;
    try requireReplay(src, planning, delivery, true);
    if (sink) |snk| try common.checkWorkspaceOverlap(call, src, snk);
    const dictionary_size = try parseLzmaDictionary(call.request);
    const check = try parseXzCheck(node_graph.findSelector(
        call.request,
        registry.parameter_family_xz,
        registry.xz_parameter.check,
    ));
    const filters = try parseXzFilters(node_graph.findSelector(
        call.request,
        registry.parameter_family_xz,
        registry.xz_parameter.filters,
    ));
    const params = try parseLzmaMatchParams(call.request, command_mask);
    if (command_mask == registry.command_mask_read) {
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const scratch = try workspace.take(u8, xz.decodeWorkspaceSize(dictionary_size));
        const input = try common.materializeSource(.require_size, src, &workspace, limits.encoded_bytes);
        if (input.len > limits.encoded_bytes) return error.ResourceLimit;
        const output_size = try xz.decodedSize(input, scratch);
        if (output_size > limits.decoded_bytes) return error.ResourceLimit;
        if (input.len + output_size > limits.codec_work) return error.ResourceLimit;
        if (sink) |snk| {
            if (!snk.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(snk, call, output_size);
            const staging = try workspace.take(u8, output_size);
            _ = try xz.decodeInPlace(input, staging, scratch);
            try common.deliver(snk, call, staging);
        }
        response.byte_length = output_size;
    } else if (command_mask == registry.command_mask_write) {
        var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
        const encode_workspace = if (params.match_finder == .bt4) xz.encodeWorkspaceSizeBt(dictionary_size) else xz.encodeWorkspaceSize(dictionary_size);
        const scratch = try workspace.take(u8, encode_workspace);
        const input = try common.materializeSource(.require_size, src, &workspace, limits.decoded_bytes);
        if (input.len > limits.decoded_bytes) return error.ResourceLimit;
        const options = xz.Options{
            .dictionary_size = dictionary_size,
            .check = check,
            .filters = filters,
            .match_finder_depth = params.match_finder_depth,
            .lazy = params.lazy,
            .nice_len = params.nice_len,
            .match_finder = params.match_finder,
        };
        const output_size = if (planning == .bound) xz.encodedSizeBound(input.len) else try xz.requiredSize(input, scratch, options);
        if (output_size > limits.encoded_bytes) return error.ResourceLimit;
        if (input.len + output_size > limits.codec_work) return error.ResourceLimit;
        if (sink) |snk| {
            if (!snk.hasCapability(resource.capability_bit_write)) return error.Unsupported;
            try common.requireSinkCapacity(snk, call, output_size);
            const staging = try workspace.take(u8, output_size);
            const produced = try xz.encode(input, staging, scratch, options);
            if (planning == .bound) {
                if (produced > output_size) return error.InternalFailure;
                try common.deliver(snk, call, staging[0..produced]);
                response.byte_length = produced;
                return;
            }
            try common.deliver(snk, call, staging);
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
