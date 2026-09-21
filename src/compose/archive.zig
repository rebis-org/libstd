const std = @import("std");

const abi = @import("../kernel/envelope.zig");
const Id = abi.Id;
const Node = abi.Node;
const Call = abi.Call;
const Status = abi.Status;
const vocabulary = @import("../kernel/vocabulary.zig");
const discovery = @import("../kernel/discovery.zig");
const kernel_catalog = @import("../kernel/catalog.zig");
const Failure = vocabulary.Failure;
const node_graph = @import("../common/node.zig");
const bounds = @import("../common/primitive/bounds.zig");
const crypto = @import("../common/primitive/crypto.zig");
const resource = @import("../common/resource.zig");
const Resource = resource.Resource;
const Limits = resource.Limits;
const rar = @import("../grammar/rar.zig");
const rar_writer = @import("../grammar/rar/writer.zig");
const seven_zip = @import("../grammar/sevenzip.zig");
const tar = @import("../grammar/tar.zig");
const zip = @import("../grammar/zip.zig");
const common = @import("common.zig");

fn requireTentative(commit: vocabulary.CommitMode) Failure!void {
    if (commit != .tentative) return error.Unsupported;
}

fn requireVerified(commit: vocabulary.CommitMode) Failure!void {
    if (commit != .confirmed) return error.Unsupported;
}

fn requireSink(sink: *Resource, call: *Call, size: usize) Failure!void {
    if (!sink.hasCapability(resource.capability_bit_write)) return error.Unsupported;
    try common.requireSinkCapacity(sink, call, size);
}

fn materializeArchive(source: *Resource, workspace: *resource.Workspace, limits: Limits) Failure![]const u8 {
    return common.materializeSource(.size_or_budget, source, workspace, limits.encoded_bytes);
}

fn writeCryptoFailure(call: *Call, cause: crypto.FailureCause) void {
    const entry: struct { id: Id, status: u32 } = switch (cause) {
        .none => return,
        .wrong_password => .{ .id = vocabulary.ids.crypto_wrong_password, .status = Status.invalid_data },
        .kdf_limit => .{ .id = vocabulary.ids.crypto_kdf_limit, .status = Status.resource_limit },
        .password_lifetime => .{ .id = vocabulary.ids.crypto_password_lifetime, .status = Status.resource_limit },
        .unsupported_algorithm => .{ .id = vocabulary.ids.crypto_unsupported_algorithm, .status = Status.unsupported },
    };
    common.writeDiagnosticScalar(call, entry.id, entry.status);
}

const CryptoParams = struct {
    password: []const u8,
    algorithm: u8 = 3,
    kdf_rounds_limit: u64 = 0,
    password_lifetime: u64 = 0,
};

fn parseCryptoParams(request: ?*Node, failure_cause: *crypto.FailureCause) Failure!?CryptoParams {
    failure_cause.* = .none;
    const profile_node = node_graph.findParameter(request, vocabulary.ids.crypto_profile);
    const password_node = node_graph.findSelector(
        request,
        comptime discovery.parameter("zip", "password").family,
        comptime discovery.parameter("zip", "password").ordinal,
    );
    if (profile_node == null and password_node == null) return null;
    const profile_id = if (profile_node) |node| blk: {
        const value: abi.Id = .{ .low = node.value_low, .high = node.value_high };
        const descriptor = kernel_catalog.descriptorFor(value) orelse return error.Unsupported;
        if (descriptor.kind != .profile) return error.InvalidCall;
        break :blk value;
    } else return error.InvalidCall;
    if (!vocabulary.idEqual(profile_id, vocabulary.ids.crypto)) return error.InvalidCall;
    const password_node2 = password_node orelse return error.InvalidCall;
    const password = try resource.checkedConstBytes(password_node2.bytes, password_node2.byte_length);
    if (password.len == 0) return error.InvalidCall;
    const algorithm = if (node_graph.findSelector(
        request,
        comptime discovery.parameter("zip", "algorithm").family,
        comptime discovery.parameter("zip", "algorithm").ordinal,
    )) |node| blk: {
        const value: u8 = @truncate(node.value_low);
        if (value > 3) {
            failure_cause.* = .unsupported_algorithm;
            return error.Unsupported;
        }
        break :blk value;
    } else 3;
    return .{
        .password = password,
        .algorithm = algorithm,
        .kdf_rounds_limit = node_graph.parseU64(node_graph.findSelector(
            request,
            comptime discovery.parameter("zip", "kdf_rounds_limit").family,
            comptime discovery.parameter("zip", "kdf_rounds_limit").ordinal,
        )),
        .password_lifetime = node_graph.parseU64(node_graph.findSelector(
            request,
            comptime discovery.parameter("zip", "password_lifetime").family,
            comptime discovery.parameter("zip", "password_lifetime").ordinal,
        )),
    };
}

pub fn tarHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    _ = sizing;
    const source_resource = source orelse return error.InvalidCall;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink == null) {
            const archive = try materializeArchive(source_resource, &workspace, limits);
            const count = try tar.tarInspectCount(archive);
            response.byte_length = count;
            return;
        }
        try requireTentative(commit);
        const sink_resource = sink.?;
        const ordinal = node_graph.parseU64(node_graph.findSelector(
            call.request,
            comptime discovery.parameter("tar", "ordinal").family,
            comptime discovery.parameter("tar", "ordinal").ordinal,
        ));
        const archive = try materializeArchive(source_resource, &workspace, limits);
        const info = try tar.tarInspectOrdinal(archive, ordinal);
        const size = std.math.cast(usize, info.size) orelse return error.ResourceLimit;
        if (size > limits.decoded_bytes) return error.ResourceLimit;
        try common.requireSinkCapacity(sink_resource, call, size);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, size);
            _ = try tar.tarDecodeOrdinal(archive, ordinal, output);
        } else {
            if (info.sparse != null) {
                const staged = try workspace.take(u8, size);
                _ = try tar.tarDecodeOrdinal(archive, ordinal, staged);
                try common.commitBytesToSink(sink_resource, call, staged);
            } else {
                const data = try bounds.slice(archive, info.data_offset, info.size);
                try common.commitBytesToSink(sink_resource, call, data);
            }
        }
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        const entries = try parseTarEntries(call.request, &workspace);
        const required = try tar.tarArchiveSize(entries);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.requireSinkCapacity(sink_resource, call, required);
        const scratch = try workspace.take(u8, tar.tar_scratch_size);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, required);
            const written = try tar.tarEncode(entries, output, scratch);
            response.byte_length = written;
        } else {
            const staging = try workspace.take(u8, required);
            const written = try tar.tarEncode(entries, staging, scratch);
            try common.commitBytesToSink(sink_resource, call, staging[0..written]);
            response.byte_length = written;
        }
    } else {
        return error.Unsupported;
    }
}

pub fn zipHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    _ = sizing;
    const source_resource = source orelse return error.InvalidCall;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    var crypto_cause: crypto.FailureCause = .none;
    const crypto_params = try parseCryptoParams(call.request, &crypto_cause);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink == null) {
            const archive = try materializeArchive(source_resource, &workspace, limits);
            const count = try zip.zipInspectCount(archive);
            response.byte_length = count;
            return;
        }
        try requireTentative(commit);
        const sink_resource = sink.?;
        const ordinal = node_graph.parseU64(node_graph.findSelector(
            call.request,
            comptime discovery.parameter("tar", "ordinal").family,
            comptime discovery.parameter("tar", "ordinal").ordinal,
        ));
        const archive = try materializeArchive(source_resource, &workspace, limits);
        const info = try zip.zipInspectOrdinal(archive, ordinal);
        const history = try workspace.take(u8, if (info.actual_method == 9) zip.deflate64_decode_history_size else zip.deflate_history_size);
        const size = info.uncompressed_size;
        if (size > limits.decoded_bytes) return error.ResourceLimit;
        try common.requireSinkCapacity(sink_resource, call, size);
        const decrypt_staging = if (info.encrypted) try workspace.take(u8, info.compressed_size) else @as([]u8, &.{});
        const callback_staging = if (sink_resource.kind == .callback_write) try workspace.take(u8, size) else @as([]u8, &.{});
        const scratch = try workspace.take(u8, workspace.remaining());
        const decode_options: zip.ZipDecodeOptions = .{
            .password = if (crypto_params) |params| params.password else null,
            .kdf_rounds_limit = if (crypto_params) |params| params.kdf_rounds_limit else 0,
            .password_lifetime = if (crypto_params) |params| params.password_lifetime else 0,
            .failure_cause = &crypto_cause,
            .staging = decrypt_staging,
            .scratch = scratch,
            .history = history,
        };
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, size);
            _ = zip.zipDecodeOrdinal(archive, ordinal, output, decode_options) catch |err| {
                writeCryptoFailure(call, crypto_cause);
                return err;
            };
        } else {
            _ = zip.zipDecodeOrdinal(archive, ordinal, callback_staging, decode_options) catch |err| {
                writeCryptoFailure(call, crypto_cause);
                return err;
            };
            try common.commitBytesToSink(sink_resource, call, callback_staging);
        }
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        if (crypto_params) |params| {
            if (params.algorithm != 0 and params.algorithm != 3) {
                writeCryptoFailure(call, .unsupported_algorithm);
                return error.Unsupported;
            }
        }
        const entries = try parseZipEntries(call.request, &workspace, crypto_params);
        const comment = try archiveComment(call.request);
        var needs_deflate64 = false;
        var scratch_required: usize = 0;
        for (entries) |entry| {
            if (entry.method == 9) needs_deflate64 = true;
            scratch_required = @max(scratch_required, zip.zipEncodeScratchSize(entry));
        }
        const history = try workspace.take(u8, if (needs_deflate64) zip.deflate64_history_size else zip.deflate_history_size);
        const measurement_buffer = try workspace.take(u8, zip.deflate_measurement_buffer_size);
        const scratch = try workspace.take(u8, scratch_required);
        var max_compressed: usize = 0;
        for (entries) |entry| {
            if (!entry.encrypted) continue;
            const compressed = try zip.zipCompressedSize(entry, history, measurement_buffer, scratch);
            max_compressed = @max(max_compressed, compressed);
        }
        const crypto_staging = if (max_compressed != 0) try workspace.take(u8, @max(max_compressed, zip.deflate_measurement_buffer_size)) else @as([]u8, &.{});
        const required = zip.zipRequiredSize(entries, comment, history, measurement_buffer, scratch, &crypto_cause) catch |err| {
            writeCryptoFailure(call, crypto_cause);
            return err;
        };
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.requireSinkCapacity(sink_resource, call, required);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, required);
            const written = zip.zipEncode(entries, comment, output, history, measurement_buffer, crypto_staging, scratch, &crypto_cause) catch |err| {
                writeCryptoFailure(call, crypto_cause);
                return err;
            };
            response.byte_length = written;
        } else {
            const staging = try workspace.take(u8, required);
            const written = zip.zipEncode(entries, comment, staging, history, measurement_buffer, crypto_staging, scratch, &crypto_cause) catch |err| {
                writeCryptoFailure(call, crypto_cause);
                return err;
            };
            try common.commitBytesToSink(sink_resource, call, staging[0..written]);
            response.byte_length = written;
        }
    } else {
        return error.Unsupported;
    }
}

pub fn sevenZipHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    // Single sevenzip profile unions decoded/coded sides: reads accept every method, writes pack; queries follow their target.
    return sevenZipGeneric(true, plan, source, sink, call, response, sizing, commit, limits, command_mask);
}

fn sevenZipGeneric(comptime coded: bool, plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    _ = sizing;
    const source_resource = source orelse return error.InvalidCall;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    var crypto_cause: crypto.FailureCause = .none;
    const crypto_params = try parseCryptoParams(call.request, &crypto_cause);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink == null) {
            try common.checkSourceWorkspaceOverlap(call, source_resource);
            const archive = try common.materializeSource(.replay, source_resource, &workspace, limits.encoded_bytes);
            const count = try seven_zip.sevenZipInspectCount(archive, &workspace, limits);
            response.byte_length = count;
            return;
        }
        try requireTentative(commit);
        const sink_resource = sink.?;
        try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        const ordinal = node_graph.parseU64(node_graph.findSelector(
            call.request,
            comptime discovery.parameter("tar", "ordinal").family,
            comptime discovery.parameter("tar", "ordinal").ordinal,
        ));
        const archive = try common.materializeSource(.replay, source_resource, &workspace, limits.encoded_bytes);
        const info = try seven_zip.sevenZipInspectOrdinal(archive, &workspace, limits, ordinal);
        if (!coded and info.method != .copy) return error.Unsupported;
        const size = std.math.cast(usize, info.size) orelse return error.ResourceLimit;
        if (size > limits.decoded_bytes) return error.ResourceLimit;
        try common.requireSinkCapacity(sink_resource, call, size);
        const decode_options: seven_zip.SevenZipDecodeOptions = .{
            .password = if (crypto_params) |params| params.password else null,
            .kdf_rounds_limit = if (crypto_params) |params| params.kdf_rounds_limit else 0,
            .password_lifetime = if (crypto_params) |params| params.password_lifetime else 0,
            .failure_cause = &crypto_cause,
        };
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, size);
            _ = seven_zip.sevenZipDecodeOrdinal(archive, &workspace, limits, ordinal, output, decode_options) catch |err| {
                writeCryptoFailure(call, crypto_cause);
                return err;
            };
        } else {
            const staging = try workspace.take(u8, size);
            _ = seven_zip.sevenZipDecodeOrdinal(archive, &workspace, limits, ordinal, staging, decode_options) catch |err| {
                writeCryptoFailure(call, crypto_cause);
                return err;
            };
            try common.commitBytesToSink(sink_resource, call, staging);
        }
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        const entries = try parseSevenZipEntries(call.request, &workspace, .copy, coded, crypto_params);
        const packed_entries = seven_zip.sevenZipPack(entries, &workspace, limits, &crypto_cause) catch |err| {
            writeCryptoFailure(call, crypto_cause);
            return err;
        };
        const required = try seven_zip.sevenZipPackedSize(entries, packed_entries, &workspace);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        try common.requireSinkCapacity(sink_resource, call, required);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, required);
            const written = try seven_zip.sevenZipWritePacked(entries, packed_entries, output, &workspace);
            response.byte_length = written;
        } else {
            const staging = try workspace.take(u8, required);
            const written = try seven_zip.sevenZipWritePacked(entries, packed_entries, staging, &workspace);
            try common.commitBytesToSink(sink_resource, call, staging[0..written]);
            response.byte_length = written;
        }
    } else {
        return error.Unsupported;
    }
}

fn entryCount(request: ?*Node) usize {
    var count: usize = 0;
    var cursor = request;
    while (cursor) |node| : (cursor = node.next) {
        if (isArchiveEntry(node)) count += 1;
    }
    return count;
}

fn isArchiveEntry(node: *abi.Node) bool {
    if (!vocabulary.idEqual(node.id, vocabulary.ids.parameter)) return false;
    const sel = vocabulary.selectorOf(node.value_high);
    const entry = comptime discovery.parameter("tar", "entry");
    return sel.family == entry.family and sel.ordinal == entry.ordinal;
}

fn parseSevenZipEntries(request: ?*Node, workspace: *resource.Workspace, default_method: seven_zip.CoderMethod, allow_method: bool, crypto_params: ?CryptoParams) Failure![]const seven_zip.SevenZipEntry {
    const entries = try workspace.take(seven_zip.SevenZipEntry, entryCount(request));
    var index: usize = 0;
    var cursor = request;
    while (cursor) |node| : (cursor = node.next) {
        if (!isArchiveEntry(node)) continue;
        const name_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_name").family, comptime discovery.parameter("tar", "entry_name").ordinal);
        const data_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_data").family, comptime discovery.parameter("tar", "entry_data").ordinal);
        const method_node = if (allow_method)
            node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_method").family, comptime discovery.parameter("tar", "entry_method").ordinal)
        else
            null;
        const name = if (name_node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{};
        const data = if (data_node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{};
        const method = if (method_node) |n| try parseSevenZipMethod(n) else default_method;
        var entry: seven_zip.SevenZipEntry = .{ .name = name, .data = data, .method = method };
        if (crypto_params) |params| {
            entry.encrypted = true;
            entry.password = params.password;
            entry.kdf_rounds_limit = params.kdf_rounds_limit;
            entry.password_lifetime = params.password_lifetime;
        }
        entries[index] = entry;
        index += 1;
    }
    return entries;
}

fn parseSevenZipMethod(node: *Node) Failure!seven_zip.CoderMethod {
    return switch (node.value_low) {
        0 => .copy,
        1 => .deflate,
        2 => .bzip2,
        3 => .lzma,
        4 => .lzma2,
        5 => .delta,
        6 => .x86,
        7 => .ppc,
        8 => .ia64,
        9 => .arm,
        10 => .armt,
        11 => .sparc,
        12 => .arm64,
        13 => .riscv,
        14 => .ppmd,
        else => error.InvalidCall,
    };
}

pub fn rarHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const source_resource = source orelse return error.InvalidCall;
    if (sizing != .metadata_exact) return error.Unsupported;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink == null) {
            try common.checkSourceWorkspaceOverlap(call, source_resource);
            const archive = try materializeArchive(source_resource, &workspace, limits);
            const count = try rar.rarInspectCount(archive, limits.entries);
            response.byte_length = count;
            return;
        }
        try requireTentative(commit);
        const sink_resource = sink.?;
        try sink_resource.requireCapability(resource.capability_bit_write);
        try common.checkSourceSinkOverlap(source_resource, sink_resource);
        try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        const ordinal = node_graph.parseU64(node_graph.findSelector(
            call.request,
            comptime discovery.parameter("tar", "ordinal").family,
            comptime discovery.parameter("tar", "ordinal").ordinal,
        ));
        const archive = try materializeArchive(source_resource, &workspace, limits);
        const info = try rar.rarInspectOrdinal(archive, ordinal, limits.entries);
        const size = std.math.cast(usize, info.size) orelse return error.ResourceLimit;
        if (size > limits.decoded_bytes) return error.ResourceLimit;
        try common.requireSinkCapacity(sink_resource, call, size);

        // The walk resolved the entry's declared needs into RarInfo; store
        // entries carve nothing. The PPMd heap is whatever workspace remains:
        // the stream names its model size at decode time and is refused
        // cleanly if the pool cannot hold it.
        const window_len = std.math.cast(usize, info.window_bytes) orelse return error.ResourceLimit;
        var bufs: rar.DecodeBuffers = .{
            .state = &.{},
            .window = &.{},
            .table_pool = &.{},
            .pending50 = &.{},
            .pending29 = &.{},
            .filter_scratch = &.{},
            .ppm_heap = &.{},
        };
        if (info.method != 0) {
            const state_words = try workspace.take(u64, (rar.max_state_bytes + 7) / 8);
            const window_buf = try workspace.take(u8, window_len);
            const table_pool = try workspace.take(u16, rar.table_pool_words);
            const pending50 = try workspace.take(rar.PendingFilter50, rar.max_pending50);
            const pending29 = try workspace.take(rar.PendingFilter29, rar.max_pending29);
            const filter_scratch = try workspace.take(u8, window_len + rar.filter_scratch_extra);
            const ppm_heap = try workspace.take(u8, workspace.remaining());
            bufs = .{
                .state = std.mem.sliceAsBytes(state_words),
                .window = window_buf,
                .table_pool = table_pool,
                .pending50 = pending50,
                .pending29 = pending29,
                .filter_scratch = filter_scratch,
                .ppm_heap = ppm_heap,
            };
        }

        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, size);
            _ = try rar.rarDecodeOrdinal(archive, ordinal, output, &bufs);
        } else {
            const staging = try workspace.take(u8, size);
            _ = try rar.rarDecodeOrdinal(archive, ordinal, staging, &bufs);
            try common.commitBytesToSink(sink_resource, call, staging);
        }
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        const entries = try parseRarEntries(call.request, &workspace);
        var max_input: usize = 0;
        var packed_total: usize = 0;
        for (entries) |entry| {
            max_input = @max(max_input, entry.data.len);
            packed_total = try bounds.add(packed_total, rar_writer.packedBound(entry));
        }
        const sizes = rar_writer.pack50Sizes(max_input);
        const hash = try workspace.take(u32, sizes.hash_words);
        const hash2 = try workspace.take(u32, sizes.hash2_words);
        const hash3 = try workspace.take(u32, sizes.hash3_words);
        const bt_left = try workspace.take(u32, sizes.bt_words);
        const bt_right = try workspace.take(u32, sizes.bt_words);
        const tokens = try workspace.take(rar_writer.LzToken, sizes.token_count);
        const staging = try workspace.take(u8, sizes.staging_bytes);
        const packed_buf = try workspace.take(u8, packed_total);
        const packed_sizes = try workspace.take(usize, entries.len);
        var ws: rar_writer.WriteBuffers = .{
            .hash = hash,
            .hash2 = hash2,
            .hash3 = hash3,
            .bt_left = bt_left,
            .bt_right = bt_right,
            .tokens = tokens,
            .staging = staging,
            .packed_buf = packed_buf,
            .packed_sizes = packed_sizes,
        };
        const required = try rar_writer.rarWriteSize(entries, &ws);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        try common.requireSinkCapacity(sink_resource, call, required);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, required);
            const written = try rar_writer.rarEncode(entries, output, &ws);
            response.byte_length = written;
        } else {
            const staging_out = try workspace.take(u8, required);
            const written = try rar_writer.rarEncode(entries, staging_out, &ws);
            try common.commitBytesToSink(sink_resource, call, staging_out[0..written]);
            response.byte_length = written;
        }
    } else {
        return error.Unsupported;
    }
}

fn parseRarEntries(request: ?*Node, workspace: *resource.Workspace) Failure![]const rar_writer.RarEntry {
    const entries = try workspace.take(rar_writer.RarEntry, entryCount(request));
    var index: usize = 0;
    var cursor = request;
    while (cursor) |node| : (cursor = node.next) {
        if (!isArchiveEntry(node)) continue;
        const name_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_name").family, comptime discovery.parameter("tar", "entry_name").ordinal);
        const data_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_data").family, comptime discovery.parameter("tar", "entry_data").ordinal);
        const method_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_method").family, comptime discovery.parameter("tar", "entry_method").ordinal);
        const mtime_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_mtime").family, comptime discovery.parameter("tar", "entry_mtime").ordinal);
        const name = if (name_node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{};
        const data = if (data_node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{};
        const method: u8 = if (method_node) |n| @truncate(n.value_low) else 0;
        const mtime: u64 = if (mtime_node) |n| node_graph.parseU64(n) else 0;
        entries[index] = .{
            .name = name,
            .data = data,
            .mtime = @truncate(mtime),
            .method = method,
        };
        index += 1;
    }
    return entries;
}

fn archiveComment(request: ?*Node) Failure![]const u8 {
    const node = node_graph.findSelector(request, comptime discovery.parameter("tar", "comment").family, comptime discovery.parameter("tar", "comment").ordinal);
    return if (node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{};
}

fn parseTarEntries(request: ?*Node, workspace: *resource.Workspace) Failure![]const tar.TarEntry {
    const entries = try workspace.take(tar.TarEntry, entryCount(request));
    var index: usize = 0;
    var cursor = request;
    while (cursor) |node| : (cursor = node.next) {
        if (!isArchiveEntry(node)) continue;
        const name_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_name").family, comptime discovery.parameter("tar", "entry_name").ordinal);
        const data_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_data").family, comptime discovery.parameter("tar", "entry_data").ordinal);
        const typeflag_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_typeflag").family, comptime discovery.parameter("tar", "entry_typeflag").ordinal);
        const link_name_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_link_name").family, comptime discovery.parameter("tar", "entry_link_name").ordinal);
        const uid_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_uid").family, comptime discovery.parameter("tar", "entry_uid").ordinal);
        const mtime_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_mtime").family, comptime discovery.parameter("tar", "entry_mtime").ordinal);
        const name = if (name_node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{};
        const data = if (data_node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{};
        const typeflag: u8 = if (typeflag_node) |n| blk: {
            break :blk @truncate(n.value_low);
        } else 0;
        const link_name = if (link_name_node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{};
        const uid: u32 = if (uid_node) |n| blk: {
            break :blk @truncate(n.value_low);
        } else 0;
        const mtime: u64 = if (mtime_node) |n| node_graph.parseU64(n) else 0;
        entries[index] = .{ .name = name, .data = data, .link_name = link_name, .uid = uid, .modification_time = mtime, .typeflag = typeflag };
        index += 1;
    }
    return entries;
}

fn parseZipEntries(request: ?*Node, workspace: *resource.Workspace, crypto_params: ?CryptoParams) Failure![]const zip.ZipEntry {
    const entries = try workspace.take(zip.ZipEntry, entryCount(request));
    var index: usize = 0;
    var cursor = request;
    while (cursor) |node| : (cursor = node.next) {
        if (!isArchiveEntry(node)) continue;
        const name_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_name").family, comptime discovery.parameter("tar", "entry_name").ordinal);
        const data_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_data").family, comptime discovery.parameter("tar", "entry_data").ordinal);
        const method_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_method").family, comptime discovery.parameter("tar", "entry_method").ordinal);
        const name = if (name_node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{};
        const data = if (data_node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{};
        const method: u16 = if (method_node) |n| @truncate(n.value_low) else 8;
        var entry: zip.ZipEntry = .{ .name = name, .data = data, .method = method };
        if (crypto_params) |params| {
            entry.encrypted = true;
            entry.password = params.password;
            entry.zipcrypto = params.algorithm == 0;
            if (!entry.zipcrypto) entry.aes_strength = params.algorithm;
            entry.kdf_rounds_limit = params.kdf_rounds_limit;
            entry.password_lifetime = params.password_lifetime;
        }
        entries[index] = entry;
        index += 1;
    }
    return entries;
}
