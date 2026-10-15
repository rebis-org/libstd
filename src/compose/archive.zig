const std = @import("std");

const bounds = @import("../common/primitive/bounds.zig");
const crypto = @import("../common/primitive/crypto.zig");
const rar = @import("../grammar/rar/onprem.zig");
const rar_writer = @import("../grammar/rar/writer.zig");
const seven_zip = @import("../grammar/sevenzip/onprem.zig");
const cpio = @import("../grammar/cpio/onprem.zig");
const cpio_seam = @import("../grammar/cpio/seam.zig");
const tar = @import("../grammar/tar/onprem.zig");
const tar_seam = @import("../grammar/tar/seam.zig");
const dwarfs = @import("../volume/dwarfs/onprem.zig");
const dwarfs_seam = @import("../volume/dwarfs/seam.zig");
const iso = @import("../volume/iso/onprem.zig");
const iso_seam = @import("../volume/iso/seam.zig");
const squashfs = @import("../volume/squashfs/onprem.zig");
const squashfs_seam = @import("../volume/squashfs/seam.zig");
const wim = @import("../grammar/wim/onprem.zig");
const wim_seam = @import("../grammar/wim/seam.zig");
const xar = @import("../grammar/xar/onprem.zig");
const xar_seam = @import("../grammar/xar/seam.zig");
const zip = @import("../grammar/zip/onprem.zig");
const kernel_catalog = @import("../kernel/catalog.zig");
const discovery = @import("../kernel/discovery.zig");
const abi = @import("../kernel/envelope.zig");
const node_graph = @import("../kernel/node.zig");
const resource = @import("../kernel/resource.zig");
const vocabulary = @import("../kernel/vocabulary.zig");
const common = @import("common.zig");

const Call = abi.Call;
const Id = abi.Id;
const Node = abi.Node;
const Status = abi.Status;
const Limits = resource.Limits;
const Resource = resource.Resource;
const Failure = vocabulary.Failure;

fn requireCommit(commit: vocabulary.CommitMode, expected: vocabulary.CommitMode) Failure!void {
    if (commit != expected) return error.UnsupportedFailure;
}

const ReadHead = struct { sink: *Resource, ordinal: u64 };

// Tentative commit, sink presence, and the entry ordinal resolve identically
// for every archive read; formats with extra checks run them after this.
fn readHead(sink: ?*Resource, call: *Call, commit: vocabulary.CommitMode) Failure!ReadHead {
    try requireTentative(commit);
    return .{ .sink = sink.?, .ordinal = archiveOrdinal(call.request) };
}

fn requireTentative(commit: vocabulary.CommitMode) Failure!void {
    return requireCommit(commit, .tentative);
}

fn requireVerified(commit: vocabulary.CommitMode) Failure!void {
    return requireCommit(commit, .confirmed);
}

fn archiveOrdinal(request: ?*Node) u64 {
    return node_graph.parseU64(node_graph.findSelector(
        request,
        comptime discovery.parameter("tar", "ordinal").family,
        comptime discovery.parameter("tar", "ordinal").ordinal,
    ));
}

fn parseHeaderEncode(request: ?*Node, comptime component: []const u8) Failure!u64 {
    const header_encode = node_graph.parseU64(node_graph.findSelector(
        request,
        comptime discovery.parameter(component, "header_encode").family,
        comptime discovery.parameter(component, "header_encode").ordinal,
    ));
    if (header_encode > 2) return error.CallFailure;
    return header_encode;
}

fn entryMethod(child: ?*Node) ?*Node {
    return node_graph.findSelector(child, comptime discovery.parameter("tar", "entry_method").family, comptime discovery.parameter("tar", "entry_method").ordinal);
}

fn entryMtime(child: ?*Node) u64 {
    return node_graph.parseU64(node_graph.findSelector(child, comptime discovery.parameter("tar", "entry_mtime").family, comptime discovery.parameter("tar", "entry_mtime").ordinal));
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

// A selector arrives on the wire as a u64, so narrowing it to the field width
// is a checked conversion: a value the field cannot hold is a malformed
// request, not a number to wrap.
fn narrow(comptime T: type, value: u64) Failure!T {
    return std.math.cast(T, value) orelse error.CallFailure;
}

fn cryptoPassword(params: ?CryptoParams) ?[]const u8 {
    return if (params) |held| held.password else null;
}

fn cryptoPasswordOrEmpty(params: ?CryptoParams) []const u8 {
    return if (params) |held| held.password else &.{};
}

fn cryptoKdfLimit(params: ?CryptoParams) u64 {
    return if (params) |held| held.kdf_rounds_limit else 0;
}

fn cryptoLifetime(params: ?CryptoParams) u64 {
    return if (params) |held| held.password_lifetime else 0;
}

// Each descriptor owns its crypto selectors; a missing row fails comptime.
fn parseCryptoParams(comptime component: []const u8, request: ?*Node, failure_cause: *crypto.FailureCause) Failure!?CryptoParams {
    failure_cause.* = .none;
    const profile_node = node_graph.findParameter(request, vocabulary.ids.crypto_profile);
    const password_node = node_graph.findSelector(
        request,
        comptime discovery.parameter(component, "password").family,
        comptime discovery.parameter(component, "password").ordinal,
    );
    if (profile_node == null and password_node == null) return null;
    const profile_id = if (profile_node) |node| blk: {
        const value: abi.Id = .{ .low = node.value_low, .high = node.value_high };
        const descriptor = kernel_catalog.descriptorFor(value) orelse return error.UnsupportedFailure;
        if (descriptor.kind != .profile) return error.CallFailure;
        break :blk value;
    } else return error.CallFailure;
    if (!vocabulary.eql(profile_id, vocabulary.ids.crypto)) return error.CallFailure;
    const password_node2 = password_node orelse return error.CallFailure;
    const password = try resource.checkedConstBytes(password_node2.bytes, password_node2.byte_length);
    if (password.len == 0) return error.CallFailure;
    const algorithm = if (node_graph.findSelector(
        request,
        comptime discovery.parameter(component, "algorithm").family,
        comptime discovery.parameter(component, "algorithm").ordinal,
    )) |node| blk: {
        // Truncating a wide selector would answer a request for a stronger
        // algorithm with a weaker one, so an unrepresentable value is refused
        // alongside an out-of-range one.
        const value = narrow(u8, node.value_low) catch {
            failure_cause.* = .unsupported_algorithm;
            return error.UnsupportedFailure;
        };
        if (value > 3) {
            failure_cause.* = .unsupported_algorithm;
            return error.UnsupportedFailure;
        }
        break :blk value;
    } else 3;
    return .{
        .password = password,
        .algorithm = algorithm,
        .kdf_rounds_limit = node_graph.parseU64(node_graph.findSelector(
            request,
            comptime discovery.parameter(component, "kdf_rounds_limit").family,
            comptime discovery.parameter(component, "kdf_rounds_limit").ordinal,
        )),
        .password_lifetime = node_graph.parseU64(node_graph.findSelector(
            request,
            comptime discovery.parameter(component, "password_lifetime").family,
            comptime discovery.parameter(component, "password_lifetime").ordinal,
        )),
    };
}

// Structured inspect projection, phase one: the entry_size selector (family
// 2, ordinal 4) with an explicit ordinal asks for the entry's uncompressed
// size without decoding its data. Returns null when the selector is absent.
fn projectedEntrySize(request: ?*Node) Failure!?u64 {
    if (node_graph.findSelector(request, comptime discovery.parameter("rar", "entry_size").family, comptime discovery.parameter("rar", "entry_size").ordinal) == null) return null;
    const ordinal_node = node_graph.findSelector(request, comptime discovery.parameter("rar", "ordinal").family, comptime discovery.parameter("rar", "ordinal").ordinal) orelse return error.CallFailure;
    return node_graph.parseU64(ordinal_node);
}

pub fn tarHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    _ = sizing;
    const source_resource = source orelse return error.CallFailure;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink == null) {
            const archive = try materializeArchive(source_resource, &workspace, limits);
            if (try projectedEntrySize(call.request)) |ordinal| {
                const entry = try tar_seam.inspectOrdinal(plan.provider, archive, ordinal);
                response.byte_length = entry.size;
                return;
            }
            const count = try tar_seam.inspectCount(plan.provider, archive);
            response.byte_length = count;
            return;
        }
        const head = try readHead(sink, call, commit);
        const sink_resource = head.sink;
        const ordinal = head.ordinal;
        const archive = try materializeArchive(source_resource, &workspace, limits);
        const entry = try tar_seam.inspectOrdinal(plan.provider, archive, ordinal);
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceFailure;
        if (size > limits.decoded_bytes) return error.ResourceFailure;
        try common.requireSinkCapacity(sink_resource, call, size);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, size);
            _ = try tar_seam.decodeOrdinal(plan.provider, archive, ordinal, output);
        } else {
            if (entry.sparse != null) {
                const staged = try workspace.take(u8, size);
                _ = try tar_seam.decodeOrdinal(plan.provider, archive, ordinal, staged);
                try common.commitBytesToSink(sink_resource, call, staged);
            } else {
                const data = try bounds.slice(archive, entry.data_offset, entry.size);
                try common.commitBytesToSink(sink_resource, call, data);
            }
        }
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        const entries = try collectEntries(tar.Entry, call.request, &workspace, NoCtx{}, fillTarEntry);
        const required = try tar_seam.archiveSize(plan.provider, entries);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.requireSinkCapacity(sink_resource, call, required);
        const scratch = try workspace.take(u8, tar.scratch_size);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, required);
            const written = try tar_seam.encode(plan.provider, entries, output, scratch);
            response.byte_length = written;
        } else {
            const staging = try workspace.take(u8, required);
            const written = try tar_seam.encode(plan.provider, entries, staging, scratch);
            try common.commitBytesToSink(sink_resource, call, staging[0..written]);
            response.byte_length = written;
        }
    } else {
        return error.UnsupportedFailure;
    }
}

fn fillXarEntry(entry: *xar.Entry, node: *Node, _: NoCtx) Failure!void {
    const parts = try entryNameData(node.child);
    const uid: u32 = if (cpioSelector("entry_uid", node.child)) |n| blk: {
        break :blk try narrow(u32, n.value_low);
    } else 0;
    const mtime = node_graph.parseU64(cpioSelector("entry_mtime", node.child));
    entry.* = .{ .name = parts.name, .data = parts.data, .uid = uid, .modification_time = mtime };
}

pub fn xarHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    _ = sizing;
    const source_resource = source orelse return error.CallFailure;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink == null) {
            const archive = try materializeArchive(source_resource, &workspace, limits);
            const scratch = try workspace.take(u8, xar_seam.scratch_size);
            if (try projectedEntrySize(call.request)) |ordinal| {
                const entry = try xar_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
                response.byte_length = entry.size;
                return;
            }
            const count = try xar_seam.inspectCount(plan.provider, archive, scratch);
            response.byte_length = count;
            return;
        }
        const head = try readHead(sink, call, commit);
        const sink_resource = head.sink;
        const ordinal = head.ordinal;
        const archive = try materializeArchive(source_resource, &workspace, limits);
        const scratch = try workspace.take(u8, xar_seam.scratch_size);
        const entry = try xar_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceFailure;
        if (size > limits.decoded_bytes) return error.ResourceFailure;
        try common.requireSinkCapacity(sink_resource, call, size);
        const decode_scratch = try workspace.take(u8, xar_seam.scratch_size);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, size);
            _ = try xar_seam.decodeOrdinal(plan.provider, archive, ordinal, output, decode_scratch);
        } else {
            const staged = try workspace.take(u8, size);
            _ = try xar_seam.decodeOrdinal(plan.provider, archive, ordinal, staged, decode_scratch);
            try common.commitBytesToSink(sink_resource, call, staged);
        }
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        const entries = try collectEntries(xar.Entry, call.request, &workspace, NoCtx{}, fillXarEntry);
        const required = try xar_seam.archiveSize(plan.provider, entries);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.requireSinkCapacity(sink_resource, call, required);
        const scratch = try workspace.take(u8, xar_seam.scratch_size);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, required);
            const written = try xar_seam.encode(plan.provider, entries, output, scratch);
            response.byte_length = written;
        } else {
            const staging = try workspace.take(u8, required);
            const written = try xar_seam.encode(plan.provider, entries, staging, scratch);
            try common.commitBytesToSink(sink_resource, call, staging[0..written]);
            response.byte_length = written;
        }
    } else {
        return error.UnsupportedFailure;
    }
}

fn fillWimEntry(entry: *wim.Entry, node: *Node, _: NoCtx) Failure!void {
    const parts = try entryNameData(node.child);
    entry.* = .{ .name = parts.name, .data = parts.data };
}

fn fillSquashfsEntry(entry: *squashfs.Entry, node: *Node, _: NoCtx) Failure!void {
    const parts = try entryNameData(node.child);
    entry.* = .{ .name = parts.name, .data = parts.data };
}

fn fillDwarfsEntry(entry: *dwarfs.Entry, node: *Node, _: NoCtx) Failure!void {
    const parts = try entryNameData(node.child);
    entry.* = .{ .name = parts.name, .data = parts.data };
}

fn fillIsoEntry(entry: *iso.Entry, node: *Node, _: NoCtx) Failure!void {
    const parts = try entryNameData(node.child);
    entry.* = .{ .name = parts.name, .data = parts.data };
}

pub fn dwarfsHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    _ = sizing;
    const source_resource = source orelse return error.CallFailure;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink == null) {
            const archive = try materializeArchive(source_resource, &workspace, limits);
            const scratch = try workspace.take(u8, dwarfs_seam.scratch_size);
            if (try projectedEntrySize(call.request)) |ordinal| {
                const entry = try dwarfs_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
                response.byte_length = entry.size;
                return;
            }
            const count = try dwarfs_seam.inspectCount(plan.provider, archive, scratch);
            response.byte_length = count;
            return;
        }
        const head = try readHead(sink, call, commit);
        const sink_resource = head.sink;
        const ordinal = head.ordinal;
        const archive = try materializeArchive(source_resource, &workspace, limits);
        const scratch = try workspace.take(u8, dwarfs_seam.scratch_size);
        const entry = try dwarfs_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceFailure;
        if (size > limits.decoded_bytes) return error.ResourceFailure;
        try common.requireSinkCapacity(sink_resource, call, size);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, size);
            _ = try dwarfs_seam.decodeOrdinal(plan.provider, archive, ordinal, output, scratch);
        } else {
            const staged = try workspace.take(u8, size);
            _ = try dwarfs_seam.decodeOrdinal(plan.provider, archive, ordinal, staged, scratch);
            try common.commitBytesToSink(sink_resource, call, staged);
        }
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        const entries = try collectEntries(dwarfs.Entry, call.request, &workspace, NoCtx{}, fillDwarfsEntry);
        const required = try dwarfs_seam.archiveSize(plan.provider, entries);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.requireSinkCapacity(sink_resource, call, required);
        const scratch = try workspace.take(u8, dwarfs_seam.scratch_size);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, required);
            const written = try dwarfs_seam.encode(plan.provider, entries, output, scratch);
            response.byte_length = written;
        } else {
            const staging = try workspace.take(u8, required);
            const written = try dwarfs_seam.encode(plan.provider, entries, staging, scratch);
            try common.commitBytesToSink(sink_resource, call, staging[0..written]);
            response.byte_length = written;
        }
    } else {
        return error.UnsupportedFailure;
    }
}

pub fn isoHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    _ = sizing;
    const source_resource = source orelse return error.CallFailure;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink == null) {
            const archive = try materializeArchive(source_resource, &workspace, limits);
            const scratch = try workspace.take(u8, iso_seam.scratch_size);
            if (try projectedEntrySize(call.request)) |ordinal| {
                const entry = try iso_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
                response.byte_length = entry.size;
                return;
            }
            const count = try iso_seam.inspectCount(plan.provider, archive, scratch);
            response.byte_length = count;
            return;
        }
        const head = try readHead(sink, call, commit);
        const sink_resource = head.sink;
        const ordinal = head.ordinal;
        const archive = try materializeArchive(source_resource, &workspace, limits);
        const scratch = try workspace.take(u8, iso_seam.scratch_size);
        const entry = try iso_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceFailure;
        if (size > limits.decoded_bytes) return error.ResourceFailure;
        try common.requireSinkCapacity(sink_resource, call, size);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, size);
            _ = try iso_seam.decodeOrdinal(plan.provider, archive, ordinal, output, scratch);
        } else {
            const staged = try workspace.take(u8, size);
            _ = try iso_seam.decodeOrdinal(plan.provider, archive, ordinal, staged, scratch);
            try common.commitBytesToSink(sink_resource, call, staged);
        }
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        const entries = try collectEntries(iso.Entry, call.request, &workspace, NoCtx{}, fillIsoEntry);
        const required = try iso_seam.archiveSize(plan.provider, entries);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.requireSinkCapacity(sink_resource, call, required);
        const scratch = try workspace.take(u8, iso_seam.scratch_size);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, required);
            const written = try iso_seam.encode(plan.provider, entries, output, scratch);
            response.byte_length = written;
        } else {
            const staging = try workspace.take(u8, required);
            const written = try iso_seam.encode(plan.provider, entries, staging, scratch);
            try common.commitBytesToSink(sink_resource, call, staging[0..written]);
            response.byte_length = written;
        }
    } else {
        return error.UnsupportedFailure;
    }
}

pub fn squashfsHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    _ = sizing;
    const source_resource = source orelse return error.CallFailure;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink == null) {
            const archive = try materializeArchive(source_resource, &workspace, limits);
            const scratch = try workspace.take(u8, squashfs_seam.scratch_size);
            if (try projectedEntrySize(call.request)) |ordinal| {
                const entry = try squashfs_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
                response.byte_length = entry.size;
                return;
            }
            const count = try squashfs_seam.inspectCount(plan.provider, archive, scratch);
            response.byte_length = count;
            return;
        }
        const head = try readHead(sink, call, commit);
        const sink_resource = head.sink;
        const ordinal = head.ordinal;
        const archive = try materializeArchive(source_resource, &workspace, limits);
        const scratch = try workspace.take(u8, squashfs_seam.scratch_size);
        const entry = try squashfs_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceFailure;
        if (size > limits.decoded_bytes) return error.ResourceFailure;
        try common.requireSinkCapacity(sink_resource, call, size);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, size);
            _ = try squashfs_seam.decodeOrdinal(plan.provider, archive, ordinal, output, scratch);
        } else {
            const staged = try workspace.take(u8, size);
            _ = try squashfs_seam.decodeOrdinal(plan.provider, archive, ordinal, staged, scratch);
            try common.commitBytesToSink(sink_resource, call, staged);
        }
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        const entries = try collectEntries(squashfs.Entry, call.request, &workspace, NoCtx{}, fillSquashfsEntry);
        const scratch = try workspace.take(u8, squashfs_seam.scratch_size);
        const required = try squashfs_seam.archiveSize(plan.provider, entries, scratch);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.requireSinkCapacity(sink_resource, call, required);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, required);
            const written = try squashfs_seam.encode(plan.provider, entries, output, scratch);
            response.byte_length = written;
        } else {
            const staging = try workspace.take(u8, required);
            const written = try squashfs_seam.encode(plan.provider, entries, staging, scratch);
            try common.commitBytesToSink(sink_resource, call, staging[0..written]);
            response.byte_length = written;
        }
    } else {
        return error.UnsupportedFailure;
    }
}

pub fn wimHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    _ = sizing;
    const source_resource = source orelse return error.CallFailure;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink == null) {
            const archive = try materializeArchive(source_resource, &workspace, limits);
            const scratch = try workspace.take(u8, wim_seam.scratch_size);
            if (try projectedEntrySize(call.request)) |ordinal| {
                const entry = try wim_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
                response.byte_length = entry.size;
                return;
            }
            const count = try wim_seam.inspectCount(plan.provider, archive, scratch);
            response.byte_length = count;
            return;
        }
        const head = try readHead(sink, call, commit);
        const sink_resource = head.sink;
        const ordinal = head.ordinal;
        const archive = try materializeArchive(source_resource, &workspace, limits);
        const scratch = try workspace.take(u8, wim_seam.scratch_size);
        const entry = try wim_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceFailure;
        if (size > limits.decoded_bytes) return error.ResourceFailure;
        try common.requireSinkCapacity(sink_resource, call, size);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, size);
            _ = try wim_seam.decodeOrdinal(plan.provider, archive, ordinal, output, scratch);
        } else {
            const staged = try workspace.take(u8, size);
            _ = try wim_seam.decodeOrdinal(plan.provider, archive, ordinal, staged, scratch);
            try common.commitBytesToSink(sink_resource, call, staged);
        }
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        const entries = try collectEntries(wim.Entry, call.request, &workspace, NoCtx{}, fillWimEntry);
        const required = try wim_seam.archiveSize(plan.provider, entries);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.requireSinkCapacity(sink_resource, call, required);
        const scratch = try workspace.take(u8, wim_seam.scratch_size);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, required);
            const written = try wim_seam.encode(plan.provider, entries, output, scratch);
            response.byte_length = written;
        } else {
            const staging = try workspace.take(u8, required);
            const written = try wim_seam.encode(plan.provider, entries, staging, scratch);
            try common.commitBytesToSink(sink_resource, call, staging[0..written]);
            response.byte_length = written;
        }
    } else {
        return error.UnsupportedFailure;
    }
}

fn cpioSelector(comptime name: []const u8, child: ?*Node) ?*Node {
    return node_graph.findSelector(child, comptime discovery.parameter("cpio", name).family, comptime discovery.parameter("cpio", name).ordinal);
}

fn fillCpioEntry(entry: *cpio.Entry, node: *Node, _: NoCtx) Failure!void {
    const parts = try entryNameData(node.child);
    const uid: u32 = if (cpioSelector("entry_uid", node.child)) |n| blk: {
        break :blk try narrow(u32, n.value_low);
    } else 0;
    const mtime = node_graph.parseU64(cpioSelector("entry_mtime", node.child));
    entry.* = .{ .name = parts.name, .data = parts.data, .uid = uid, .modification_time = mtime };
}

pub fn cpioHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    _ = sizing;
    const source_resource = source orelse return error.CallFailure;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink == null) {
            const archive = try materializeArchive(source_resource, &workspace, limits);
            if (try projectedEntrySize(call.request)) |ordinal| {
                const entry = try cpio_seam.inspectOrdinal(plan.provider, archive, ordinal);
                response.byte_length = entry.size;
                return;
            }
            const count = try cpio_seam.inspectCount(plan.provider, archive);
            response.byte_length = count;
            return;
        }
        const head = try readHead(sink, call, commit);
        const sink_resource = head.sink;
        const ordinal = head.ordinal;
        const archive = try materializeArchive(source_resource, &workspace, limits);
        const entry = try cpio_seam.inspectOrdinal(plan.provider, archive, ordinal);
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceFailure;
        if (size > limits.decoded_bytes) return error.ResourceFailure;
        try common.requireSinkCapacity(sink_resource, call, size);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, size);
            _ = try cpio_seam.decodeOrdinal(plan.provider, archive, ordinal, output);
        } else {
            const staged = try workspace.take(u8, size);
            _ = try cpio_seam.decodeOrdinal(plan.provider, archive, ordinal, staged);
            try common.commitBytesToSink(sink_resource, call, staged);
        }
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        const entries = try collectEntries(cpio.Entry, call.request, &workspace, NoCtx{}, fillCpioEntry);
        const required = try cpio_seam.archiveSize(plan.provider, entries);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.requireSinkCapacity(sink_resource, call, required);
        const scratch = try workspace.take(u8, cpio.scratch_size);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, required);
            const written = try cpio_seam.encode(plan.provider, entries, output, scratch);
            response.byte_length = written;
        } else {
            const staging = try workspace.take(u8, required);
            const written = try cpio_seam.encode(plan.provider, entries, staging, scratch);
            try common.commitBytesToSink(sink_resource, call, staging[0..written]);
            response.byte_length = written;
        }
    } else {
        return error.UnsupportedFailure;
    }
}

pub fn zipHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    _ = sizing;
    const source_resource = source orelse return error.CallFailure;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    var crypto_cause: crypto.FailureCause = .none;
    const crypto_params = parseCryptoParams("zip", call.request, &crypto_cause) catch |err| {
        // A rejection inside the parser (e.g. algorithm > 3) already recorded
        // its cause; surface it before the error unwinds.
        writeCryptoFailure(call, crypto_cause);
        return err;
    };
    if (command_mask == vocabulary.command_mask_read) {
        if (sink == null) {
            const archive = try materializeArchive(source_resource, &workspace, limits);
            if (try projectedEntrySize(call.request)) |ordinal| {
                const entry = try zip.zipInspectOrdinalEx(archive, std.math.cast(usize, ordinal) orelse return error.CallFailure, limits);
                response.byte_length = entry.uncompressed_size;
                return;
            }
            const count = try zip.zipInspectCountEx(archive, limits);
            response.byte_length = count;
            return;
        }
        const head = try readHead(sink, call, commit);
        const sink_resource = head.sink;
        const ordinal = head.ordinal;
        const archive = try materializeArchive(source_resource, &workspace, limits);
        const entry = try zip.zipInspectOrdinalEx(archive, ordinal, limits);
        const history = try workspace.take(u8, if (entry.actual_method == 9) zip.deflate64_decode_history_size else zip.deflate_history_size);
        const size = entry.uncompressed_size;
        if (size > limits.decoded_bytes) return error.ResourceFailure;
        try common.requireSinkCapacity(sink_resource, call, size);
        const decrypt_staging = if (entry.encrypted) try workspace.take(u8, entry.compressed_size) else @as([]u8, &.{});
        const callback_staging = if (sink_resource.kind == .callback_write) try workspace.take(u8, size) else @as([]u8, &.{});
        const scratch = try workspace.take(u8, workspace.remaining());
        const decode_options: zip.ZipDecodeOptions = .{
            .password = cryptoPassword(crypto_params),
            .kdf_rounds_limit = cryptoKdfLimit(crypto_params),
            .password_lifetime = cryptoLifetime(crypto_params),
            .failure_cause = &crypto_cause,
            .staging = decrypt_staging,
            .scratch = scratch,
            .history = history,
            .provider = plan.provider,
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
            if (params.algorithm > 3) {
                writeCryptoFailure(call, .unsupported_algorithm);
                return error.UnsupportedFailure;
            }
        }
        const entries = try collectEntries(zip.Entry, call.request, &workspace, crypto_params, fillZipEntry);
        const comment = try archiveComment(call.request);
        var needs_deflate64 = false;
        var scratch_required: usize = 0;
        for (entries) |entry| {
            if (entry.method == 9) needs_deflate64 = true;
            scratch_required = @max(scratch_required, zip.encodeScratchSize(entry));
        }
        const history = try workspace.take(u8, if (needs_deflate64) zip.deflate64_history_size else zip.deflate_history_size);
        const measurement_buffer = try workspace.take(u8, zip.deflate_measurement_buffer_size);
        const scratch = try workspace.take(u8, scratch_required);
        var max_compressed: usize = 0;
        for (entries) |entry| {
            if (!entry.encrypted) continue;
            const compressed = try zip.compressedSize(entry, history, measurement_buffer, scratch);
            max_compressed = @max(max_compressed, compressed);
        }
        const crypto_staging = if (max_compressed != 0) try workspace.take(u8, @max(max_compressed, zip.deflate_measurement_buffer_size)) else @as([]u8, &.{});
        const required = zip.requiredSize(entries, comment, history, measurement_buffer, scratch, &crypto_cause) catch |err| {
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
            const written = zip.encode(entries, comment, output, plan.provider, history, measurement_buffer, crypto_staging, scratch, &crypto_cause) catch |err| {
                writeCryptoFailure(call, crypto_cause);
                return err;
            };
            response.byte_length = written;
        } else {
            const staging = try workspace.take(u8, required);
            const written = zip.encode(entries, comment, staging, plan.provider, history, measurement_buffer, crypto_staging, scratch, &crypto_cause) catch |err| {
                writeCryptoFailure(call, crypto_cause);
                return err;
            };
            try common.commitBytesToSink(sink_resource, call, staging[0..written]);
            response.byte_length = written;
        }
    } else {
        return error.UnsupportedFailure;
    }
}

pub fn sevenzipHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    // Single sevenzip profile unions decoded/coded sides: reads accept every method, writes pack. Queries follow their target.
    return sevenZipGeneric(true, plan, source, sink, call, response, sizing, commit, limits, command_mask);
}

fn sevenZipGeneric(comptime coded: bool, plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    _ = sizing;
    const source_resource = source orelse return error.CallFailure;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    var crypto_cause: crypto.FailureCause = .none;
    const crypto_params = parseCryptoParams("sevenzip", call.request, &crypto_cause) catch |err| {
        // A rejection inside the parser (e.g. algorithm > 3) already recorded
        // its cause; surface it before the error unwinds.
        writeCryptoFailure(call, crypto_cause);
        return err;
    };
    if (command_mask == vocabulary.command_mask_read) {
        const load_options: seven_zip.SevenZipLoadOptions = .{
            .password = cryptoPassword(crypto_params),
            .kdf_rounds_limit = cryptoKdfLimit(crypto_params),
            .password_lifetime = cryptoLifetime(crypto_params),
            .failure_cause = &crypto_cause,
            .provider = plan.provider,
        };
        if (sink == null) {
            try common.checkSourceWorkspaceOverlap(call, source_resource);
            const archive = try common.materializeSource(.replay, source_resource, &workspace, limits.encoded_bytes);
            if (try projectedEntrySize(call.request)) |ordinal| {
                const entry = seven_zip.sevenZipInspectOrdinalEx(archive, &workspace, limits, ordinal, &load_options) catch |err| {
                    writeCryptoFailure(call, crypto_cause);
                    return err;
                };
                response.byte_length = entry.size;
                return;
            }
            const count = seven_zip.sevenZipInspectCountEx(archive, &workspace, limits, &load_options) catch |err| {
                writeCryptoFailure(call, crypto_cause);
                return err;
            };
            response.byte_length = count;
            return;
        }
        try requireTentative(commit);
        const sink_resource = sink.?;
        try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        const ordinal = archiveOrdinal(call.request);
        const archive = try common.materializeSource(.replay, source_resource, &workspace, limits.encoded_bytes);
        const entry = seven_zip.sevenZipInspectOrdinalEx(archive, &workspace, limits, ordinal, &load_options) catch |err| {
            writeCryptoFailure(call, crypto_cause);
            return err;
        };
        if (!coded and entry.method != .copy) return error.UnsupportedFailure;
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceFailure;
        if (size > limits.decoded_bytes) return error.ResourceFailure;
        try common.requireSinkCapacity(sink_resource, call, size);
        const decode_options: seven_zip.SevenZipDecodeOptions = .{
            .password = cryptoPassword(crypto_params),
            .kdf_rounds_limit = cryptoKdfLimit(crypto_params),
            .password_lifetime = cryptoLifetime(crypto_params),
            .failure_cause = &crypto_cause,
            .provider = plan.provider,
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
        // -mhe stores the header without compression, matching the reference writer.
        const header_encode = try parseHeaderEncode(call.request, "sevenzip");
        const header_options: seven_zip.SevenZipHeaderOptions = .{
            .compress = header_encode == 1,
            .encrypt = header_encode == 2,
            .password = cryptoPasswordOrEmpty(crypto_params),
            .kdf_rounds_limit = cryptoKdfLimit(crypto_params),
            .password_lifetime = cryptoLifetime(crypto_params),
            .failure_cause = &crypto_cause,
        };
        const entries = try collectEntries(seven_zip.Entry, call.request, &workspace, SevenZipFillCtx{ .default_method = .copy, .allow_method = coded, .crypto = crypto_params }, fillSevenZipEntry);
        const packed_entries = seven_zip.sevenZipPack(entries, plan.provider, &workspace, limits, &crypto_cause) catch |err| {
            writeCryptoFailure(call, crypto_cause);
            return err;
        };
        const required = try seven_zip.sevenZipPackedSize(entries, packed_entries, &workspace, plan.provider, limits, header_options);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        try common.requireSinkCapacity(sink_resource, call, required);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, required);
            const written = try seven_zip.sevenZipWritePacked(entries, packed_entries, output, &workspace, plan.provider, limits, header_options);
            response.byte_length = written;
        } else {
            const staging = try workspace.take(u8, required);
            const written = try seven_zip.sevenZipWritePacked(entries, packed_entries, staging, &workspace, plan.provider, limits, header_options);
            try common.commitBytesToSink(sink_resource, call, staging[0..written]);
            response.byte_length = written;
        }
    } else {
        return error.UnsupportedFailure;
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
    if (!vocabulary.eql(node.id, vocabulary.ids.parameter)) return false;
    const sel = vocabulary.selectorOf(node.value_high);
    const entry = comptime discovery.parameter("tar", "entry");
    return sel.family == entry.family and sel.ordinal == entry.ordinal;
}

fn entryNameData(child: ?*Node) Failure!struct { name: []const u8, data: []const u8 } {
    const name_node = node_graph.findSelector(child, comptime discovery.parameter("tar", "entry_name").family, comptime discovery.parameter("tar", "entry_name").ordinal);
    const data_node = node_graph.findSelector(child, comptime discovery.parameter("tar", "entry_data").family, comptime discovery.parameter("tar", "entry_data").ordinal);
    return .{
        .name = if (name_node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{},
        .data = if (data_node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{},
    };
}

const NoCtx = struct {};

fn collectEntries(comptime E: type, request: ?*Node, workspace: *resource.Workspace, ctx: anytype, comptime fill: anytype) Failure![]const E {
    var entries = try workspace.take(E, entryCount(request));
    var index: usize = 0;
    var cursor = request;
    while (cursor) |node| : (cursor = node.next) {
        if (!isArchiveEntry(node)) continue;
        try fill(&entries[index], node, ctx);
        index += 1;
    }
    return entries;
}

const SevenZipFillCtx = struct {
    default_method: seven_zip.CoderMethod,
    allow_method: bool,
    crypto: ?CryptoParams,
};

fn fillSevenZipEntry(entry: *seven_zip.Entry, node: *Node, ctx: SevenZipFillCtx) Failure!void {
    const parts = try entryNameData(node.child);
    const method_node = if (ctx.allow_method) entryMethod(node.child) else null;
    const filter_node = if (ctx.allow_method)
        node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_filter").family, comptime discovery.parameter("tar", "entry_filter").ordinal)
    else
        null;
    const method = if (method_node) |n| try parseSevenZipMethod(n) else ctx.default_method;
    entry.* = .{ .name = parts.name, .data = parts.data, .method = method };
    if (filter_node) |n| entry.filter = try parseSevenZipMethod(n);
    if (ctx.crypto) |params| {
        entry.encrypted = true;
        entry.password = params.password;
        entry.kdf_rounds_limit = params.kdf_rounds_limit;
        entry.password_lifetime = params.password_lifetime;
    }
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
        else => error.CallFailure,
    };
}

// Largest decrypted-header staging either RAR family can need: RAR5 caps a
// header at 2 MiB, RAR4 headers are u16-sized aligned to the 16-byte block.
const rar_header_scratch_size = 2 * 1024 * 1024 + 16;

pub fn rarHook(plan: *common.ExecutionPlan, source: ?*Resource, sink: ?*Resource, call: *Call, response: *Node, sizing: vocabulary.SizingMode, commit: vocabulary.CommitMode, limits: Limits, command_mask: u32) Failure!void {
    const source_resource = source orelse return error.CallFailure;
    if (sizing != .metadata_exact) return error.UnsupportedFailure;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    if (command_mask == vocabulary.command_mask_read) {
        var failure_cause: crypto.FailureCause = .none;
        const crypto_params = parseCryptoParams("rar", call.request, &failure_cause) catch |err| {
            writeCryptoFailure(call, failure_cause);
            return err;
        };
        const decrypting = crypto_params != null;
        if (sink == null) {
            try common.checkSourceWorkspaceOverlap(call, source_resource);
            const archive = try materializeArchive(source_resource, &workspace, limits);
            // Archives with encrypted headers (-hp) need decrypted-header staging, capped by the archive size.
            const header_scratch = if (decrypting) try workspace.take(u8, @min(@as(usize, rar_header_scratch_size), archive.len + 16)) else try workspace.take(u8, 0);
            const inspect_opts: rar.DecodeOptions = .{
                .password = cryptoPassword(crypto_params),
                .scratch = header_scratch,
                .kdf_rounds_limit = cryptoKdfLimit(crypto_params),
                .password_lifetime = cryptoLifetime(crypto_params),
                .failure_cause = &failure_cause,
                .provider = plan.provider,
            };
            if (try projectedEntrySize(call.request)) |ordinal| {
                const entry = rar.rarInspectOrdinalOpts(archive, ordinal, limits.entries, inspect_opts) catch |err| {
                    writeCryptoFailure(call, failure_cause);
                    return err;
                };
                response.byte_length = entry.size;
                return;
            }
            const count = rar.rarInspectCountOpts(archive, limits.entries, inspect_opts) catch |err| {
                writeCryptoFailure(call, failure_cause);
                return err;
            };
            response.byte_length = count;
            return;
        }
        try requireTentative(commit);
        const sink_resource = sink.?;
        try sink_resource.requireCapability(resource.capability_bit_write);
        try common.checkSourceSinkOverlap(source_resource, sink_resource);
        try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        const ordinal = archiveOrdinal(call.request);
        const archive = try materializeArchive(source_resource, &workspace, limits);
        // Decryption needs a mutable copy of the packed data and, for -hp
        // archives, staging for the decrypted headers; both are capped by the
        // archive size. Plaintext reads carve nothing, keeping workspace
        // sizing byte-identical to before.
        const packed_stage = if (decrypting) try workspace.take(u8, @min(limits.encoded_bytes, archive.len)) else try workspace.take(u8, 0);
        const header_scratch = if (decrypting) try workspace.take(u8, @min(@as(usize, rar_header_scratch_size), archive.len + 16)) else try workspace.take(u8, 0);
        const decode_opts: rar.DecodeOptions = .{
            .password = cryptoPassword(crypto_params),
            .scratch = header_scratch,
            .kdf_rounds_limit = cryptoKdfLimit(crypto_params),
            .password_lifetime = cryptoLifetime(crypto_params),
            .failure_cause = &failure_cause,
            .provider = plan.provider,
        };
        const entry = rar.rarInspectOrdinalOpts(archive, ordinal, limits.entries, decode_opts) catch |err| {
            writeCryptoFailure(call, failure_cause);
            return err;
        };
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceFailure;
        if (size > limits.decoded_bytes) return error.ResourceFailure;
        try common.requireSinkCapacity(sink_resource, call, size);

        // The walk resolved the entry's declared needs into RarInfo. Store
        // entries carve nothing. The PPMd heap is whatever workspace remains:
        // the stream names its model size at decode time and is refused
        // cleanly if the pool cannot hold it.
        const window_len = std.math.cast(usize, entry.window_bytes) orelse return error.ResourceFailure;
        var bufs: rar.DecodeBuffers = .{
            .state = &.{},
            .window = &.{},
            .table_pool = &.{},
            .pending50 = &.{},
            .pending29 = &.{},
            .filter_scratch = &.{},
            .ppm_heap = &.{},
            .packed_stage = packed_stage,
        };
        if (entry.method != 0) {
            const state_words = try workspace.take(u64, (rar.max_unpacker_bytes + 7) / 8);
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
                .packed_stage = packed_stage,
            };
        }

        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, size);
            _ = rar.rarDecodeOrdinal(archive, ordinal, output, &bufs, decode_opts) catch |err| {
                writeCryptoFailure(call, failure_cause);
                return err;
            };
        } else {
            const staging = try workspace.take(u8, size);
            _ = rar.rarDecodeOrdinal(archive, ordinal, staging, &bufs, decode_opts) catch |err| {
                writeCryptoFailure(call, failure_cause);
                return err;
            };
            try common.commitBytesToSink(sink_resource, call, staging);
        }
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        var crypto_cause: crypto.FailureCause = .none;
        const crypto_params = parseCryptoParams("rar", call.request, &crypto_cause) catch |err| {
            writeCryptoFailure(call, crypto_cause);
            return err;
        };
        const header_encode = try parseHeaderEncode(call.request, "rar");
        // 1 encrypts file data, 2 also encrypts headers.
        const entries = try collectEntries(rar_writer.RarEntry, call.request, &workspace, NoCtx{}, fillRarEntry);
        const write_options: rar_writer.WriteOptions = .{
            .password = cryptoPasswordOrEmpty(crypto_params),
            .encrypt_headers = header_encode == 2,
            .kdf_rounds_limit = cryptoKdfLimit(crypto_params),
            .failure_cause = &crypto_cause,
        };
        if (write_options.encrypt_headers and write_options.password.len == 0) return error.CallFailure;
        var max_input: usize = 0;
        var packed_total: usize = 0;
        for (entries) |entry| {
            max_input = @max(max_input, entry.data.len);
            packed_total = try bounds.addUsize(packed_total, rar_writer.packedBoundEx(entry, write_options.password.len != 0 and !entry.is_directory));
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
        const crypt_salts = try workspace.take([16]u8, entries.len);
        const crypt_ivs = try workspace.take([16]u8, entries.len);
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
            .crypt_salts = crypt_salts,
            .crypt_ivs = crypt_ivs,
        };
        const required = rar_writer.rarWriteSizeEx(entries, &ws, write_options) catch |err| {
            writeCryptoFailure(call, crypto_cause);
            return err;
        };
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.checkWorkspaceOverlap(call, source_resource, sink_resource);
        try common.requireSinkCapacity(sink_resource, call, required);
        if (sink_resource.kind == .direct_write) {
            const output = try common.sinkDirectBuffer(sink_resource, required);
            const written = try rar_writer.rarEncodeEx(entries, output, &ws, plan.provider, write_options);
            response.byte_length = written;
        } else {
            const staging_out = try workspace.take(u8, required);
            const written = try rar_writer.rarEncodeEx(entries, staging_out, &ws, plan.provider, write_options);
            try common.commitBytesToSink(sink_resource, call, staging_out[0..written]);
            response.byte_length = written;
        }
    } else {
        return error.UnsupportedFailure;
    }
}

fn fillRarEntry(entry: *rar_writer.RarEntry, node: *Node, _: NoCtx) Failure!void {
    const parts = try entryNameData(node.child);
    const method_node = entryMethod(node.child);
    if (!std.unicode.utf8ValidateSlice(parts.name)) return error.CallFailure;
    const method: u8 = if (method_node) |n| try narrow(u8, n.value_low) else 0;
    const mtime = entryMtime(node.child);
    entry.* = .{
        .name = parts.name,
        .data = parts.data,
        .mtime = @truncate(mtime),
        .method = method,
    };
}

fn archiveComment(request: ?*Node) Failure![]const u8 {
    const node = node_graph.findSelector(request, comptime discovery.parameter("tar", "comment").family, comptime discovery.parameter("tar", "comment").ordinal);
    return if (node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{};
}

fn fillTarEntry(entry: *tar.Entry, node: *Node, _: NoCtx) Failure!void {
    const parts = try entryNameData(node.child);
    const typeflag_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_typeflag").family, comptime discovery.parameter("tar", "entry_typeflag").ordinal);
    const link_name_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_link_name").family, comptime discovery.parameter("tar", "entry_link_name").ordinal);
    const uid_node = node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_uid").family, comptime discovery.parameter("tar", "entry_uid").ordinal);
    const typeflag: u8 = if (typeflag_node) |n| blk: {
        break :blk try narrow(u8, n.value_low);
    } else 0;
    const link_name = if (link_name_node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{};
    const uid: u32 = if (uid_node) |n| blk: {
        break :blk try narrow(u32, n.value_low);
    } else 0;
    const mtime = entryMtime(node.child);
    entry.* = .{ .name = parts.name, .data = parts.data, .link_name = link_name, .uid = uid, .modification_time = mtime, .typeflag = typeflag };
}

fn fillZipEntry(entry: *zip.Entry, node: *Node, crypto_params: ?CryptoParams) Failure!void {
    const parts = try entryNameData(node.child);
    const method_node = entryMethod(node.child);
    const method: u16 = if (method_node) |n| try narrow(u16, n.value_low) else 8;
    entry.* = .{ .name = parts.name, .data = parts.data, .method = method };
    // A nonzero value writes the streaming shape: zeroed local sizes and
    // a data descriptor after the entry data.
    if (node_graph.parseU64(node_graph.findSelector(
        node.child,
        comptime discovery.parameter("zip", "data_descriptor").family,
        comptime discovery.parameter("zip", "data_descriptor").ordinal,
    )) != 0) {
        entry.flags |= 0x0008;
    }
    if (crypto_params) |params| {
        entry.encrypted = true;
        entry.password = params.password;
        entry.zipcrypto = params.algorithm == 0;
        if (!entry.zipcrypto) entry.aes_strength = params.algorithm;
        entry.kdf_rounds_limit = params.kdf_rounds_limit;
        entry.password_lifetime = params.password_lifetime;
    }
}
