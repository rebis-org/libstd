const std = @import("std");

const abi = @import("../abi/contract.zig");
const Id = abi.Id;
const Node = abi.Node;
const Call = abi.Call;
const Status = abi.Status;
const registry = @import("../catalog/registry.zig");
const Failure = registry.Failure;
const node_graph = @import("../common/node.zig");
const bounds = @import("../common/primitive/bounds.zig");
const crypto = @import("../common/primitive/crypto.zig");
const resource = @import("../common/resource.zig");
const Resource = resource.Resource;
const Limits = resource.Limits;
const rar = @import("../grammar/rar.zig");
const seven_zip = @import("../grammar/sevenzip.zig");
const tar = @import("../grammar/tar.zig");
const zip = @import("../grammar/zip.zig");
const common = @import("common.zig");

fn requireProvisional(delivery: registry.DeliveryMode) Failure!void {
    if (delivery != .provisional) return error.Unsupported;
}

fn requireVerified(delivery: registry.DeliveryMode) Failure!void {
    if (delivery != .verified) return error.Unsupported;
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
        .wrong_password => .{ .id = registry.ids.crypto_wrong_password, .status = Status.invalid_data },
        .kdf_limit => .{ .id = registry.ids.crypto_kdf_limit, .status = Status.resource_limit },
        .password_lifetime => .{ .id = registry.ids.crypto_password_lifetime, .status = Status.resource_limit },
        .unsupported_algorithm => .{ .id = registry.ids.crypto_unsupported_algorithm, .status = Status.unsupported },
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
    const profile_node = node_graph.findParameter(request, registry.ids.crypto_profile);
    const password_node = node_graph.findSelector(
        request,
        registry.parameter_family_crypto,
        registry.crypto_parameter.password,
    );
    if (profile_node == null and password_node == null) return null;
    const profile_id = if (profile_node) |node| blk: {
        const value: abi.Id = .{ .low = node.value_low, .high = node.value_high };
        const descriptor = registry.descriptorFor(value) orelse return error.Unsupported;
        if (descriptor.kind != .profile) return error.InvalidCall;
        break :blk value;
    } else return error.InvalidCall;
    if (!registry.idEqual(profile_id, registry.ids.crypto)) return error.InvalidCall;
    const password_node2 = password_node orelse return error.InvalidCall;
    const password = try resource.checkedConstBytes(password_node2.bytes, password_node2.byte_length);
    if (password.len == 0) return error.InvalidCall;
    const algorithm = if (node_graph.findSelector(
        request,
        registry.parameter_family_crypto,
        registry.crypto_parameter.algorithm,
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
            registry.parameter_family_crypto,
            registry.crypto_parameter.kdf_rounds_limit,
        )),
        .password_lifetime = node_graph.parseU64(node_graph.findSelector(
            request,
            registry.parameter_family_crypto,
            registry.crypto_parameter.password_lifetime,
        )),
    };
}

pub fn tarHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, planning: registry.PlanningMode, delivery: registry.DeliveryMode, limits: Limits, command_mask: u32) Failure!void {
    _ = planning;
    const src = source orelse return error.InvalidCall;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    if (command_mask == registry.command_mask_read) {
        if (sink == null) {
            const archive = try materializeArchive(src, &workspace, limits);
            const count = try tar.tarInspectCount(archive);
            response.byte_length = count;
            return;
        }
        try requireProvisional(delivery);
        const snk = sink.?;
        const ordinal = node_graph.parseU64(node_graph.findSelector(
            call.request,
            registry.parameter_family_archive,
            registry.archive_parameter.ordinal,
        ));
        const archive = try materializeArchive(src, &workspace, limits);
        const info = try tar.tarInspectOrdinal(archive, ordinal);
        const size = std.math.cast(usize, info.size) orelse return error.ResourceLimit;
        if (size > limits.decoded_bytes) return error.ResourceLimit;
        try common.requireSinkCapacity(snk, call, size);
        if (snk.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(snk, size);
            _ = try tar.tarDecodeOrdinal(archive, ordinal, output);
        } else {
            if (info.sparse != null) {
                const staged = try workspace.take(u8, size);
                _ = try tar.tarDecodeOrdinal(archive, ordinal, staged);
                try common.deliver(snk, call, staged);
            } else {
                const data = try bounds.slice(archive, info.data_offset, info.size);
                try common.deliver(snk, call, data);
            }
        }
        response.byte_length = size;
    } else if (command_mask == registry.command_mask_write) {
        try requireVerified(delivery);
        const entries = try parseTarEntries(call.request, &workspace);
        const required = try tar.tarArchiveSize(entries);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const snk = sink.?;
        try common.requireSinkCapacity(snk, call, required);
        const scratch = try workspace.take(u8, tar.tar_scratch_size);
        if (snk.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(snk, required);
            const written = try tar.tarEncode(entries, output, scratch);
            response.byte_length = written;
        } else {
            const staging = try workspace.take(u8, required);
            const written = try tar.tarEncode(entries, staging, scratch);
            try common.deliver(snk, call, staging[0..written]);
            response.byte_length = written;
        }
    } else {
        return error.Unsupported;
    }
}

pub fn zipHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, planning: registry.PlanningMode, delivery: registry.DeliveryMode, limits: Limits, command_mask: u32) Failure!void {
    _ = planning;
    const src = source orelse return error.InvalidCall;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    var crypto_cause: crypto.FailureCause = .none;
    const crypto_params = try parseCryptoParams(call.request, &crypto_cause);
    if (command_mask == registry.command_mask_read) {
        if (sink == null) {
            const archive = try materializeArchive(src, &workspace, limits);
            const count = try zip.zipInspectCount(archive);
            response.byte_length = count;
            return;
        }
        try requireProvisional(delivery);
        const snk = sink.?;
        const ordinal = node_graph.parseU64(node_graph.findSelector(
            call.request,
            registry.parameter_family_archive,
            registry.archive_parameter.ordinal,
        ));
        const archive = try materializeArchive(src, &workspace, limits);
        const info = try zip.zipInspectOrdinal(archive, ordinal);
        const history = try workspace.take(u8, if (info.actual_method == 9) zip.deflate64_decode_history_size else zip.deflate_history_size);
        const size = info.uncompressed_size;
        if (size > limits.decoded_bytes) return error.ResourceLimit;
        try common.requireSinkCapacity(snk, call, size);
        const decrypt_staging = if (info.encrypted) try workspace.take(u8, info.compressed_size) else @as([]u8, &.{});
        const callback_staging = if (snk.kind == .callback_write) try workspace.take(u8, size) else @as([]u8, &.{});
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
        if (snk.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(snk, size);
            _ = zip.zipDecodeOrdinal(archive, ordinal, output, decode_options) catch |err| {
                writeCryptoFailure(call, crypto_cause);
                return err;
            };
        } else {
            _ = zip.zipDecodeOrdinal(archive, ordinal, callback_staging, decode_options) catch |err| {
                writeCryptoFailure(call, crypto_cause);
                return err;
            };
            try common.deliver(snk, call, callback_staging);
        }
        response.byte_length = size;
    } else if (command_mask == registry.command_mask_write) {
        try requireVerified(delivery);
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
        const snk = sink.?;
        try common.requireSinkCapacity(snk, call, required);
        if (snk.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(snk, required);
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
            try common.deliver(snk, call, staging[0..written]);
            response.byte_length = written;
        }
    } else {
        return error.Unsupported;
    }
}

pub fn sevenZipDecodedHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, planning: registry.PlanningMode, delivery: registry.DeliveryMode, limits: Limits, command_mask: u32) Failure!void {
    return sevenZipGeneric(false, plan, source, sink, call, response, planning, delivery, limits, command_mask);
}

pub fn sevenZipCodedHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, planning: registry.PlanningMode, delivery: registry.DeliveryMode, limits: Limits, command_mask: u32) Failure!void {
    return sevenZipGeneric(true, plan, source, sink, call, response, planning, delivery, limits, command_mask);
}

fn sevenZipGeneric(comptime coded: bool, plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, planning: registry.PlanningMode, delivery: registry.DeliveryMode, limits: Limits, command_mask: u32) Failure!void {
    _ = planning;
    const src = source orelse return error.InvalidCall;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    var crypto_cause: crypto.FailureCause = .none;
    const crypto_params = try parseCryptoParams(call.request, &crypto_cause);
    if (command_mask == registry.command_mask_read) {
        if (sink == null) {
            try common.checkSourceWorkspaceOverlap(call, src);
            const archive = try common.materializeSource(.replay, src, &workspace, limits.encoded_bytes);
            const count = try seven_zip.sevenZipInspectCount(archive, &workspace, limits);
            response.byte_length = count;
            return;
        }
        try requireProvisional(delivery);
        const snk = sink.?;
        try common.checkWorkspaceOverlap(call, src, snk);
        const ordinal = node_graph.parseU64(node_graph.findSelector(
            call.request,
            registry.parameter_family_archive,
            registry.archive_parameter.ordinal,
        ));
        const archive = try common.materializeSource(.replay, src, &workspace, limits.encoded_bytes);
        const info = try seven_zip.sevenZipInspectOrdinal(archive, &workspace, limits, ordinal);
        if (!coded and info.method != .copy) return error.Unsupported;
        const size = std.math.cast(usize, info.size) orelse return error.ResourceLimit;
        if (size > limits.decoded_bytes) return error.ResourceLimit;
        try common.requireSinkCapacity(snk, call, size);
        const decode_options: seven_zip.SevenZipDecodeOptions = .{
            .password = if (crypto_params) |params| params.password else null,
            .kdf_rounds_limit = if (crypto_params) |params| params.kdf_rounds_limit else 0,
            .password_lifetime = if (crypto_params) |params| params.password_lifetime else 0,
            .failure_cause = &crypto_cause,
        };
        if (snk.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(snk, size);
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
            try common.deliver(snk, call, staging);
        }
        response.byte_length = size;
    } else if (command_mask == registry.command_mask_write) {
        try requireVerified(delivery);
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
        const snk = sink.?;
        try common.checkWorkspaceOverlap(call, src, snk);
        try common.requireSinkCapacity(snk, call, required);
        if (snk.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(snk, required);
            const written = try seven_zip.sevenZipWritePacked(entries, packed_entries, output, &workspace);
            response.byte_length = written;
        } else {
            const staging = try workspace.take(u8, required);
            const written = try seven_zip.sevenZipWritePacked(entries, packed_entries, staging, &workspace);
            try common.deliver(snk, call, staging[0..written]);
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
    if (!registry.idEqual(node.id, registry.ids.parameter)) return false;
    const sel = registry.selectorOf(node.value_high);
    return sel.family == registry.parameter_family_archive and sel.ordinal == registry.archive_parameter.entry;
}

fn parseSevenZipEntries(request: ?*Node, workspace: *resource.Workspace, default_method: seven_zip.CoderMethod, allow_method: bool, crypto_params: ?CryptoParams) Failure![]const seven_zip.SevenZipEntry {
    const entries = try workspace.take(seven_zip.SevenZipEntry, entryCount(request));
    var index: usize = 0;
    var cursor = request;
    while (cursor) |node| : (cursor = node.next) {
        if (!isArchiveEntry(node)) continue;
        const name_node = node_graph.findSelector(node.child, registry.parameter_family_archive, registry.archive_parameter.entry_name);
        const data_node = node_graph.findSelector(node.child, registry.parameter_family_archive, registry.archive_parameter.entry_data);
        const method_node = if (allow_method)
            node_graph.findSelector(node.child, registry.parameter_family_archive, registry.archive_parameter.entry_method)
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

pub fn rarHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, planning: registry.PlanningMode, delivery: registry.DeliveryMode, limits: Limits, command_mask: u32) Failure!void {
    const src = source orelse return error.InvalidCall;
    if (planning != .metadata_exact) return error.Unsupported;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    if (command_mask == registry.command_mask_read) {
        if (sink == null) {
            try common.checkSourceWorkspaceOverlap(call, src);
            const archive = try materializeArchive(src, &workspace, limits);
            const count = try rar.rarInspectCount(archive, limits.entries);
            response.byte_length = count;
            return;
        }
        try requireProvisional(delivery);
        const snk = sink.?;
        try snk.requireCapability(resource.capability_bit_write);
        try common.checkSourceSinkOverlap(src, snk);
        try common.checkWorkspaceOverlap(call, src, snk);
        const ordinal = node_graph.parseU64(node_graph.findSelector(
            call.request,
            registry.parameter_family_archive,
            registry.archive_parameter.ordinal,
        ));
        const archive = try materializeArchive(src, &workspace, limits);
        const info = try rar.rarInspectOrdinal(archive, ordinal, limits.entries);
        const size = std.math.cast(usize, info.size) orelse return error.ResourceLimit;
        if (size > limits.decoded_bytes) return error.ResourceLimit;
        try common.requireSinkCapacity(snk, call, size);
        if (snk.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(snk, size);
            _ = try rar.rarDecodeOrdinal(archive, ordinal, output, limits.entries);
        } else {
            const staging = workspace.take(u8, size) catch |err| {
                const available = workspace.bytes.len - workspace.cursor;
                common.writeCapacityDiagnostic(call, std.math.cast(u64, size) orelse std.math.maxInt(u64), std.math.cast(u64, available) orelse std.math.maxInt(u64));
                return err;
            };
            _ = try rar.rarDecodeOrdinal(archive, ordinal, staging, limits.entries);
            try common.deliver(snk, call, staging);
        }
        response.byte_length = size;
    } else {
        return error.Unsupported;
    }
}

fn archiveComment(request: ?*Node) Failure![]const u8 {
    const node = node_graph.findSelector(request, registry.parameter_family_archive, registry.archive_parameter.comment);
    return if (node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{};
}

fn parseTarEntries(request: ?*Node, workspace: *resource.Workspace) Failure![]const tar.TarEntry {
    const entries = try workspace.take(tar.TarEntry, entryCount(request));
    var index: usize = 0;
    var cursor = request;
    while (cursor) |node| : (cursor = node.next) {
        if (!isArchiveEntry(node)) continue;
        const name_node = node_graph.findSelector(node.child, registry.parameter_family_archive, registry.archive_parameter.entry_name);
        const data_node = node_graph.findSelector(node.child, registry.parameter_family_archive, registry.archive_parameter.entry_data);
        const typeflag_node = node_graph.findSelector(node.child, registry.parameter_family_archive, registry.archive_parameter.entry_typeflag);
        const link_name_node = node_graph.findSelector(node.child, registry.parameter_family_archive, registry.archive_parameter.entry_link_name);
        const uid_node = node_graph.findSelector(node.child, registry.parameter_family_archive, registry.archive_parameter.entry_uid);
        const mtime_node = node_graph.findSelector(node.child, registry.parameter_family_archive, registry.archive_parameter.entry_mtime);
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
        const name_node = node_graph.findSelector(node.child, registry.parameter_family_archive, registry.archive_parameter.entry_name);
        const data_node = node_graph.findSelector(node.child, registry.parameter_family_archive, registry.archive_parameter.entry_data);
        const method_node = node_graph.findSelector(node.child, registry.parameter_family_archive, registry.archive_parameter.entry_method);
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
