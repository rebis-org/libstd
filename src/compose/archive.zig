const std = @import("std");

const bounds = @import("../common/primitive/bounds.zig");
const crypto = @import("../common/primitive/crypto.zig");
const kernel_catalog = @import("../kernel/catalog.zig");
const discovery = @import("../kernel/discovery.zig");
const abi = @import("../kernel/envelope.zig");
const node_graph = @import("../kernel/node.zig");
const resource = @import("../kernel/resource.zig");
const vocabulary = @import("../kernel/vocabulary.zig");
const age_seam = @import("../representation/grammar/age/seam.zig");
const cpio = @import("../representation/grammar/cpio/onprem.zig");
const cpio_seam = @import("../representation/grammar/cpio/seam.zig");
const pkg = @import("../representation/grammar/pkg/onprem.zig");
const rar = @import("../representation/grammar/rar/onprem.zig");
const rar_writer = @import("../representation/grammar/rar/writer.zig");
const seven_zip = @import("../representation/grammar/sevenzip/onprem.zig");
const tar = @import("../representation/grammar/tar/onprem.zig");
const tar_seam = @import("../representation/grammar/tar/seam.zig");
const wim = @import("../representation/grammar/wim/onprem.zig");
const wim_seam = @import("../representation/grammar/wim/seam.zig");
const xar = @import("../representation/grammar/xar/onprem.zig");
const xar_seam = @import("../representation/grammar/xar/seam.zig");
const xip = @import("../representation/grammar/xip/onprem.zig");
const xip_seam = @import("../representation/grammar/xip/seam.zig");
const zip = @import("../representation/grammar/zip/onprem.zig");
const apfs_seam = @import("../representation/volume/apfs/seam.zig");
const dwarfs = @import("../representation/volume/dwarfs/onprem.zig");
const dwarfs_seam = @import("../representation/volume/dwarfs/seam.zig");
const iso = @import("../representation/volume/iso/onprem.zig");
const iso_seam = @import("../representation/volume/iso/seam.zig");
const squashfs = @import("../representation/volume/squashfs/onprem.zig");
const squashfs_seam = @import("../representation/volume/squashfs/seam.zig");
const common = @import("common.zig");

const Call = abi.Call;
const Id = abi.Id;
const Node = abi.Node;
const Status = abi.Status;
const Limits = resource.Limits;
const Resource = resource.Resource;
const Exception = vocabulary.Exception;
// A format produces bytes into a buffer, then hands them to the sink;
// common.SinkTarget owns that protocol for every hook.
const SinkTarget = common.SinkTarget;

// Eight bytes at forced 8-byte alignment; u64 aligns to 4 on x86, so
// re-read buffers carve with it.

const StateOctet = extern struct { bytes: [8]u8 align(8) };

fn requireCommit(commit: vocabulary.CommitMode, expected: vocabulary.CommitMode) Exception!void {
    if (commit != expected) return error.UnsupportedException;
}

const ReadHead = struct { sink: *Resource, ordinal: u64 };

// Tentative commit, sink presence, and the entry ordinal resolve identically
// for every archive read; extra format checks follow.
fn readHead(sink: ?*Resource, call: *Call, commit: vocabulary.CommitMode) Exception!ReadHead {
    try requireTentative(commit);
    return .{ .sink = sink.?, .ordinal = archiveOrdinal(call.request) };
}

fn requireTentative(commit: vocabulary.CommitMode) Exception!void {
    return requireCommit(commit, .tentative);
}

fn requireVerified(commit: vocabulary.CommitMode) Exception!void {
    return requireCommit(commit, .confirmed);
}

fn archiveOrdinal(request: ?*Node) u64 {
    return node_graph.parseU64(node_graph.findSelector(
        request,
        comptime discovery.parameter("tar", "ordinal").family,
        comptime discovery.parameter("tar", "ordinal").ordinal,
    ));
}

fn parseHeaderEncode(request: ?*Node, comptime component: []const u8) Exception!u64 {
    const header_encode = node_graph.parseU64(node_graph.findSelector(
        request,
        comptime discovery.parameter(component, "header_encode").family,
        comptime discovery.parameter(component, "header_encode").ordinal,
    ));
    if (header_encode > 2) return error.CallException;
    return header_encode;
}

fn entryMethod(child: ?*Node) ?*Node {
    return node_graph.findSelector(child, comptime discovery.parameter("tar", "entry_method").family, comptime discovery.parameter("tar", "entry_method").ordinal);
}

fn entryMtime(child: ?*Node) u64 {
    return node_graph.parseU64(node_graph.findSelector(child, comptime discovery.parameter("tar", "entry_mtime").family, comptime discovery.parameter("tar", "entry_mtime").ordinal));
}

fn materializeArchive(source: *Resource, workspace: *resource.Workspace, limits: Limits) Exception![]const u8 {
    return common.materializeSource(.size_or_budget, source, workspace, limits.encoded_bytes);
}

// Bytes in hand need no staging: a callback sink publishes them as they
// are; a direct sink receives its copy.
fn publishReady(sink: *Resource, call: *Call, bytes: []const u8) Exception!usize {
    switch (sink.kind) {
        .direct_write => @memcpy(try common.sinkDirectBuffer(sink, bytes.len), bytes),
        else => try common.commitBytesToSink(sink, call, bytes),
    }
    return bytes.len;
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

// A selector arrives as a u64; narrowing is checked, so an
// unrepresentable value is a malformed request.
fn narrow(comptime T: type, value: u64) Exception!T {
    return std.math.cast(T, value) orelse error.CallException;
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
fn parseCryptoParams(comptime component: []const u8, request: ?*Node, failure_cause: *crypto.FailureCause) Exception!?CryptoParams {
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
        const descriptor = kernel_catalog.descriptorFor(value) orelse return error.UnsupportedException;
        if (descriptor.kind != .profile) return error.CallException;
        break :blk value;
    } else return error.CallException;
    if (!vocabulary.eql(profile_id, vocabulary.ids.crypto)) return error.CallException;
    const password_node2 = password_node orelse return error.CallException;
    const password = try resource.checkedConstBytes(password_node2.bytes, password_node2.byte_length);
    if (password.len == 0) return error.CallException;
    const algorithm = if (node_graph.findSelector(
        request,
        comptime discovery.parameter(component, "algorithm").family,
        comptime discovery.parameter(component, "algorithm").ordinal,
    )) |node| blk: {
        // Truncation would answer a request for a stronger algorithm with a
        // weaker one, so unrepresentable values are refused too.
        const value = narrow(u8, node.value_low) catch {
            failure_cause.* = .unsupported_algorithm;
            return error.UnsupportedException;
        };
        if (value > 3) {
            failure_cause.* = .unsupported_algorithm;
            return error.UnsupportedException;
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

// Inspect projection: the entry_size selector with an explicit ordinal
// asks for the uncompressed size without decoding. Null when absent.
fn projectedEntrySize(request: ?*Node) Exception!?u64 {
    if (node_graph.findSelector(request, comptime discovery.parameter("rar", "entry_size").family, comptime discovery.parameter("rar", "entry_size").ordinal) == null) return null;
    const ordinal_node = node_graph.findSelector(request, comptime discovery.parameter("rar", "ordinal").family, comptime discovery.parameter("rar", "ordinal").ordinal) orelse return error.CallException;
    return node_graph.parseU64(ordinal_node);
}

// Inspect metadata projection: `entry` plus `ordinal` on a sink-less read
// publishes the entry fields into the response child graph. Null when absent.
fn projectedEntryMetadata(request: ?*Node) Exception!?u64 {
    const entry = comptime discovery.parameter("tar", "entry");
    if (node_graph.findSelector(request, entry.family, entry.ordinal) == null) return null;
    const ordinal_sel = comptime discovery.parameter("tar", "ordinal");
    const ordinal_node = node_graph.findSelector(request, ordinal_sel.family, ordinal_sel.ordinal) orelse return error.CallException;
    return node_graph.parseU64(ordinal_node);
}

const EntryMetadata = struct {
    name: ?[]const u8 = null,
    size: ?u64 = null,
    mtime: ?u64 = null,
    uid: ?u64 = null,
    typeflag: ?u64 = null,
    link_name: ?[]const u8 = null,
};

// Fills whichever response child nodes the host chained; fields the format
// does not carry stay zero, and a short name buffer reports capacity.
fn publishEntryMetadata(call: *Call, response: *Node, meta: EntryMetadata) Exception!void {
    const name_sel = comptime discovery.parameter("tar", "entry_name");
    const size_sel = comptime discovery.parameter("tar", "entry_size");
    const mtime_sel = comptime discovery.parameter("tar", "entry_mtime");
    const uid_sel = comptime discovery.parameter("tar", "entry_uid");
    const typeflag_sel = comptime discovery.parameter("tar", "entry_typeflag");
    const link_sel = comptime discovery.parameter("tar", "entry_link_name");
    var cursor = response.child;
    while (cursor) |node| : (cursor = node.next) {
        if (!vocabulary.eql(node.id, vocabulary.ids.parameter)) continue;
        const selector = vocabulary.selectorOf(node.value_high);
        if (selector.family != name_sel.family) continue;
        if (selector.ordinal == name_sel.ordinal or selector.ordinal == link_sel.ordinal) {
            const bytes = if (selector.ordinal == name_sel.ordinal) meta.name else meta.link_name;
            if (bytes) |text| {
                if (node.byte_capacity < text.len) {
                    common.writeCapacityDiagnostic(call, text.len, node.byte_capacity);
                    return error.CapacityException;
                }
                const output = node.bytes orelse return error.CallException;
                @memcpy(output[0..text.len], text);
                node.byte_length = text.len;
            }
        } else {
            const value: ?u64 = switch (selector.ordinal) {
                size_sel.ordinal => meta.size,
                mtime_sel.ordinal => meta.mtime,
                uid_sel.ordinal => meta.uid,
                typeflag_sel.ordinal => meta.typeflag,
                else => null,
            };
            if (value) |scalar| node.value_low = scalar;
        }
    }
    if (meta.size) |size| response.byte_length = size;
}

pub fn tarHook(invocation: *common.Invocation) Exception!void {
    const plan = &invocation.plan;
    const call = invocation.call;
    const response = invocation.response;
    const source_resource = invocation.source;
    const sink = invocation.sink;
    const sizing = plan.sizing;
    const commit = plan.commit;
    const limits = plan.limits;
    const command_mask = plan.command_mask;
    _ = sizing;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink == null) {
            const archive = try materializeArchive(source_resource, &workspace, limits);
            if (try projectedEntrySize(call.request)) |ordinal| {
                const entry = try tar_seam.inspectOrdinal(plan.provider, archive, ordinal);
                response.byte_length = entry.size;
                return;
            }
            if (try projectedEntryMetadata(call.request)) |ordinal| {
                const entry = try tar_seam.inspectOrdinal(plan.provider, archive, ordinal);
                try publishEntryMetadata(call, response, .{
                    .name = entry.name,
                    .size = entry.size,
                    .mtime = entry.modification_time,
                    .uid = entry.uid,
                    .typeflag = entry.typeflag,
                    .link_name = entry.link_name,
                });
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
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceException;
        if (size > limits.decoded_bytes) return error.ResourceException;
        try common.requireSinkCapacity(sink_resource, call, size);
        // A stored entry is published straight from the archive; a sparse entry
        // must be materialized through a target.
        if (entry.sparse != null) {
            const target = try SinkTarget.open(sink_resource, &workspace, size);
            _ = try tar_seam.decodeOrdinal(plan.provider, archive, ordinal, target.output);
            _ = try target.publish(sink_resource, call, size);
        } else {
            const data = try bounds.slice(archive, entry.data_offset, entry.size);
            _ = try publishReady(sink_resource, call, data);
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
        const target = try SinkTarget.open(sink_resource, &workspace, required);
        const written = try tar_seam.encode(plan.provider, entries, target.output, scratch);
        response.byte_length = try target.publish(sink_resource, call, written);
    } else {
        return error.UnsupportedException;
    }
}

fn fillXarEntry(entry: *xar.Entry, node: *Node, _: NoCtx) Exception!void {
    const parts = try entryNameData(node.child);
    const uid: u32 = if (cpioSelector("entry_uid", node.child)) |n| blk: {
        break :blk try narrow(u32, n.value_low);
    } else 0;
    const mtime = node_graph.parseU64(cpioSelector("entry_mtime", node.child));
    entry.* = .{ .name = parts.name, .data = parts.data, .uid = uid, .modification_time = mtime };
}

pub fn xarHook(invocation: *common.Invocation) Exception!void {
    const plan = &invocation.plan;
    const call = invocation.call;
    const response = invocation.response;
    const source_resource = invocation.source;
    const sink = invocation.sink;
    const sizing = plan.sizing;
    const commit = plan.commit;
    const limits = plan.limits;
    const command_mask = plan.command_mask;
    _ = sizing;
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
            if (try projectedEntryMetadata(call.request)) |ordinal| {
                const entry = try xar_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
                try publishEntryMetadata(call, response, .{
                    .name = entry.name,
                    .size = entry.size,
                    .mtime = entry.modification_time,
                    .uid = entry.uid,
                });
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
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceException;
        if (size > limits.decoded_bytes) return error.ResourceException;
        try common.requireSinkCapacity(sink_resource, call, size);
        const decode_scratch = try workspace.take(u8, xar_seam.scratch_size);
        const target = try SinkTarget.open(sink_resource, &workspace, size);
        _ = try xar_seam.decodeOrdinal(plan.provider, archive, ordinal, target.output, decode_scratch);
        _ = try target.publish(sink_resource, call, size);
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        const entries = try collectEntries(xar.Entry, call.request, &workspace, NoCtx{}, fillXarEntry);
        const scratch = try workspace.take(u8, xar_seam.scratch_size);
        const required = try xar_seam.archiveSize(plan.provider, entries, scratch);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.requireSinkCapacity(sink_resource, call, required);
        const target = try SinkTarget.open(sink_resource, &workspace, required);
        const written = try xar_seam.encode(plan.provider, entries, target.output, scratch);
        response.byte_length = try target.publish(sink_resource, call, written);
    } else {
        return error.UnsupportedException;
    }
}

fn fillXipEntry(entry: *xip.Entry, node: *Node, _: NoCtx) Exception!void {
    const parts = try entryNameData(node.child);
    const uid: u32 = if (cpioSelector("entry_uid", node.child)) |n| blk: {
        break :blk try narrow(u32, n.value_low);
    } else 0;
    const mtime = node_graph.parseU64(cpioSelector("entry_mtime", node.child));
    entry.* = .{ .name = parts.name, .data = parts.data, .uid = uid, .modification_time = mtime };
}

pub fn xipHook(invocation: *common.Invocation) Exception!void {
    const plan = &invocation.plan;
    const call = invocation.call;
    const response = invocation.response;
    const source_resource = invocation.source;
    const sink = invocation.sink;
    const sizing = plan.sizing;
    const commit = plan.commit;
    const limits = plan.limits;
    const command_mask = plan.command_mask;
    _ = sizing;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    if (command_mask == vocabulary.command_mask_read) {
        const archive = try materializeArchive(source_resource, &workspace, limits);
        if (sink == null) {
            const scratch = try workspace.take(u8, xip_seam.scratch_size);
            if (try projectedEntrySize(call.request)) |ordinal| {
                const entry = try xip_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
                response.byte_length = entry.size;
                return;
            }
            if (try projectedEntryMetadata(call.request)) |ordinal| {
                const entry = try xip_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
                try publishEntryMetadata(call, response, .{
                    .name = entry.name,
                    .size = entry.size,
                    .mtime = entry.modification_time,
                    .uid = entry.uid,
                });
                return;
            }
            const count = try xip_seam.inspectCount(plan.provider, archive, scratch);
            response.byte_length = count;
            return;
        }
        const head = try readHead(sink, call, commit);
        const sink_resource = head.sink;
        const ordinal = head.ordinal;
        const scratch = try workspace.take(u8, xip_seam.scratch_size);
        const entry = try xip_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceException;
        if (size > limits.decoded_bytes) return error.ResourceException;
        try common.requireSinkCapacity(sink_resource, call, size);
        const target = try SinkTarget.open(sink_resource, &workspace, size);
        _ = try xip_seam.decodeOrdinal(plan.provider, archive, ordinal, target.output, scratch);
        _ = try target.publish(sink_resource, call, size);
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        const entries = try collectEntries(xip.Entry, call.request, &workspace, NoCtx{}, fillXipEntry);
        const scratch = try workspace.take(u8, xip_seam.scratch_size);
        const required = try xip_seam.archiveSize(plan.provider, entries, scratch);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.requireSinkCapacity(sink_resource, call, required);
        const target = try SinkTarget.open(sink_resource, &workspace, required);
        const written = try xip_seam.encode(plan.provider, entries, target.output, scratch);
        response.byte_length = try target.publish(sink_resource, call, written);
    } else {
        return error.UnsupportedException;
    }
}

fn fillPkgEntry(entry: *pkg.Entry, node: *Node, _: NoCtx) Exception!void {
    const parts = try entryNameData(node.child);
    const uid: u32 = if (cpioSelector("entry_uid", node.child)) |n| blk: {
        break :blk try narrow(u32, n.value_low);
    } else 0;
    const mtime = node_graph.parseU64(cpioSelector("entry_mtime", node.child));
    entry.* = .{ .name = parts.name, .data = parts.data, .uid = uid, .modification_time = mtime };
}

// The write path emits deterministic gzip; the read side sniffs,
// so every archive reads back.
const pkg_write_compression: pkg.Compression = .gzip;

pub fn pkgHook(invocation: *common.Invocation) Exception!void {
    const plan = &invocation.plan;
    const call = invocation.call;
    const response = invocation.response;
    const source_resource = invocation.source;
    const sink = invocation.sink;
    const sizing = plan.sizing;
    const commit = plan.commit;
    const limits = plan.limits;
    const command_mask = plan.command_mask;
    _ = sizing;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    if (command_mask == vocabulary.command_mask_read) {
        const archive = try materializeArchive(source_resource, &workspace, limits);
        if (sink == null) {
            const scratch = try workspace.take(u8, pkg.scratch_size);
            if (try projectedEntrySize(call.request)) |ordinal| {
                const entry = try pkg.inspectOrdinal(archive, ordinal, scratch);
                response.byte_length = entry.size;
                return;
            }
            if (try projectedEntryMetadata(call.request)) |ordinal| {
                const entry = try pkg.inspectOrdinal(archive, ordinal, scratch);
                try publishEntryMetadata(call, response, .{
                    .name = entry.name,
                    .size = entry.size,
                    .mtime = entry.modification_time,
                    .uid = entry.uid,
                });
                return;
            }
            const count = try pkg.inspectCount(archive, scratch);
            response.byte_length = count;
            return;
        }
        const head = try readHead(sink, call, commit);
        const sink_resource = head.sink;
        const ordinal = head.ordinal;
        const scratch = try workspace.take(u8, pkg.scratch_size);
        const entry = try pkg.inspectOrdinal(archive, ordinal, scratch);
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceException;
        if (size > limits.decoded_bytes) return error.ResourceException;
        try common.requireSinkCapacity(sink_resource, call, size);
        const target = try SinkTarget.open(sink_resource, &workspace, size);
        _ = try pkg.decodeOrdinal(archive, ordinal, target.output, scratch);
        _ = try target.publish(sink_resource, call, size);
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        const entries = try collectEntries(pkg.Entry, call.request, &workspace, NoCtx{}, fillPkgEntry);
        const content_len = std.math.cast(usize, try cpio.archiveSize(entries)) orelse return error.ResourceException;
        const scratch = try workspace.take(u8, pkg.writeScratchSize(content_len, pkg_write_compression));
        const required = try pkg.archiveSize(entries, scratch, pkg_write_compression);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.requireSinkCapacity(sink_resource, call, required);
        const target = try SinkTarget.open(sink_resource, &workspace, required);
        const written = try pkg.encode(entries, target.output, scratch, pkg_write_compression);
        response.byte_length = try target.publish(sink_resource, call, written);
    } else {
        return error.UnsupportedException;
    }
}

fn fillWimEntry(entry: *wim.Entry, node: *Node, _: NoCtx) Exception!void {
    const parts = try entryNameData(node.child);
    entry.* = .{ .name = parts.name, .data = parts.data };
}

fn fillSquashfsEntry(entry: *squashfs.Entry, node: *Node, _: NoCtx) Exception!void {
    const parts = try entryNameData(node.child);
    entry.* = .{ .name = parts.name, .data = parts.data };
}

fn fillDwarfsEntry(entry: *dwarfs.Entry, node: *Node, _: NoCtx) Exception!void {
    const parts = try entryNameData(node.child);
    entry.* = .{ .name = parts.name, .data = parts.data };
}

fn fillIsoEntry(entry: *iso.Entry, node: *Node, _: NoCtx) Exception!void {
    const parts = try entryNameData(node.child);
    entry.* = .{ .name = parts.name, .data = parts.data };
}

pub fn dwarfsHook(invocation: *common.Invocation) Exception!void {
    const plan = &invocation.plan;
    const call = invocation.call;
    const response = invocation.response;
    const source_resource = invocation.source;
    const sink = invocation.sink;
    const sizing = plan.sizing;
    const commit = plan.commit;
    const limits = plan.limits;
    const command_mask = plan.command_mask;
    _ = sizing;
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
            if (try projectedEntryMetadata(call.request)) |ordinal| {
                const entry = try dwarfs_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
                try publishEntryMetadata(call, response, .{ .name = entry.name, .size = entry.size });
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
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceException;
        if (size > limits.decoded_bytes) return error.ResourceException;
        try common.requireSinkCapacity(sink_resource, call, size);
        const target = try SinkTarget.open(sink_resource, &workspace, size);
        _ = try dwarfs_seam.decodeOrdinal(plan.provider, archive, ordinal, target.output, scratch);
        _ = try target.publish(sink_resource, call, size);
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
        const target = try SinkTarget.open(sink_resource, &workspace, required);
        const written = try dwarfs_seam.encode(plan.provider, entries, target.output, scratch);
        response.byte_length = try target.publish(sink_resource, call, written);
    } else {
        return error.UnsupportedException;
    }
}

// APFS writes are mkfs-shaped: a fresh single-volume image from the entry
// list, read back through the same ordinal surface.
pub fn apfsHook(invocation: *common.Invocation) Exception!void {
    const plan = &invocation.plan;
    const call = invocation.call;
    const response = invocation.response;
    const source_resource = invocation.source;
    const sink = invocation.sink;
    const sizing = plan.sizing;
    const commit = plan.commit;
    const limits = plan.limits;
    const command_mask = plan.command_mask;
    _ = sizing;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink == null) {
            const archive = try materializeArchive(source_resource, &workspace, limits);
            const scratch = try workspace.take(u8, apfs_seam.scratch_size);
            if (try projectedEntrySize(call.request)) |ordinal| {
                const entry = try apfs_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
                response.byte_length = entry.size;
                return;
            }
            if (try projectedEntryMetadata(call.request)) |ordinal| {
                const entry = try apfs_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
                try publishEntryMetadata(call, response, .{ .size = entry.size });
                return;
            }
            const count = try apfs_seam.inspectCount(plan.provider, archive, scratch);
            response.byte_length = count;
            return;
        }
        const head = try readHead(sink, call, commit);
        const sink_resource = head.sink;
        const ordinal = head.ordinal;
        const archive = try materializeArchive(source_resource, &workspace, limits);
        const scratch = try workspace.take(u8, apfs_seam.scratch_size);
        const entry = try apfs_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceException;
        if (size > limits.decoded_bytes) return error.ResourceException;
        try common.requireSinkCapacity(sink_resource, call, size);
        const target = try SinkTarget.open(sink_resource, &workspace, size);
        _ = try apfs_seam.decodeOrdinal(plan.provider, archive, ordinal, target.output, scratch);
        _ = try target.publish(sink_resource, call, size);
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        const entries = try collectEntries(apfs_seam.Entry, call.request, &workspace, NoCtx{}, fillApfsEntry);
        const scratch = try workspace.take(u8, apfs_seam.scratch_size);
        const required = try apfs_seam.archiveSize(plan.provider, entries, scratch);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.requireSinkCapacity(sink_resource, call, required);
        const target = try SinkTarget.open(sink_resource, &workspace, required);
        const written = try apfs_seam.encode(plan.provider, entries, target.output, scratch);
        response.byte_length = try target.publish(sink_resource, call, written);
    } else {
        return error.UnsupportedException;
    }
}

// The age store takes one entry; the parameters carry the recipient
// material: password for scrypt, identity or recipient for X25519.
fn ageOptions(crypto_params: ?CryptoParams, request: ?*Node) Exception!age_seam.Options {
    var options = age_seam.Options{ .password = cryptoPasswordOrEmpty(crypto_params) };
    if (node_graph.findSelector(request, comptime discovery.parameter("age", "identity").family, comptime discovery.parameter("age", "identity").ordinal)) |node| {
        options.identity = try resource.checkedConstBytes(node.bytes, node.byte_length);
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("age", "recipient").family, comptime discovery.parameter("age", "recipient").ordinal)) |node| {
        options.recipient = try resource.checkedConstBytes(node.bytes, node.byte_length);
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("age", "work_factor").family, comptime discovery.parameter("age", "work_factor").ordinal)) |node| {
        options.work_factor = try narrow(u8, node.value_low);
    }
    if (node_graph.findSelector(request, comptime discovery.parameter("age", "armor").family, comptime discovery.parameter("age", "armor").ordinal)) |node| {
        options.armor = node.value_low != 0;
    }
    return options;
}

fn ageScratch(workspace: *resource.Workspace, options: age_seam.Options) Exception![]u8 {
    // The take is doubled: the codec splits it, and scrypt peaks
    // at 1024 * N bytes in the back half.
    const peak = if (options.password.len != 0) @as(usize, 4096) + (@as(usize, 1024) << @intCast(options.work_factor)) else 0;
    return workspace.take(u8, @max(age_seam.scratch_size, peak) * 2);
}

pub fn ageHook(invocation: *common.Invocation) Exception!void {
    const plan = &invocation.plan;
    const call = invocation.call;
    const response = invocation.response;
    const source_resource = invocation.source;
    const sink = invocation.sink;
    const sizing = plan.sizing;
    const commit = plan.commit;
    const limits = plan.limits;
    const command_mask = plan.command_mask;
    _ = sizing;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    var crypto_cause: crypto.FailureCause = .none;
    const crypto_params = parseCryptoParams("age", call.request, &crypto_cause) catch |err| {
        writeCryptoFailure(call, crypto_cause);
        return err;
    };
    const options = try ageOptions(crypto_params, call.request);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink == null) {
            const archive = try materializeArchive(source_resource, &workspace, limits);
            const scratch = try ageScratch(&workspace, options);
            if (try projectedEntrySize(call.request)) |ordinal| {
                const info = age_seam.inspectOrdinal(plan.provider, archive, ordinal, options, scratch) catch |err| {
                    writeCryptoFailure(call, .wrong_password);
                    return err;
                };
                response.byte_length = info.size;
                return;
            }
            if (try projectedEntryMetadata(call.request)) |ordinal| {
                const info = age_seam.inspectOrdinal(plan.provider, archive, ordinal, options, scratch) catch |err| {
                    writeCryptoFailure(call, .wrong_password);
                    return err;
                };
                try publishEntryMetadata(call, response, .{ .size = info.size });
                return;
            }
            _ = age_seam.inspectCount(plan.provider, archive, scratch) catch |err| switch (err) {
                error.UnsupportedException => return error.UnsupportedException,
                else => return error.DataException,
            };
            response.byte_length = 1;
            return;
        }
        const head = try readHead(sink, call, commit);
        const sink_resource = head.sink;
        const archive = try materializeArchive(source_resource, &workspace, limits);
        const scratch = try ageScratch(&workspace, options);
        const info = age_seam.inspectOrdinal(plan.provider, archive, head.ordinal, options, scratch) catch |err| {
            writeCryptoFailure(call, .wrong_password);
            return err;
        };
        const size = std.math.cast(usize, info.size) orelse return error.ResourceException;
        if (size > limits.decoded_bytes) return error.ResourceException;
        try common.requireSinkCapacity(sink_resource, call, size);
        const target = try SinkTarget.open(sink_resource, &workspace, size);
        _ = age_seam.decodeOrdinal(plan.provider, archive, head.ordinal, target.output, scratch, options) catch |err| {
            writeCryptoFailure(call, .wrong_password);
            return err;
        };
        _ = try target.publish(sink_resource, call, size);
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        const entries = try collectEntries(age_seam.Entry, call.request, &workspace, NoCtx{}, fillAgeEntry);
        const scratch = try ageScratch(&workspace, options);
        const required = try age_seam.archiveSize(plan.provider, entries, options, scratch);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.requireSinkCapacity(sink_resource, call, required);
        const target = try SinkTarget.open(sink_resource, &workspace, required);
        const written = age_seam.encode(plan.provider, entries, target.output, scratch, options) catch |err| {
            writeCryptoFailure(call, crypto_cause);
            return err;
        };
        response.byte_length = try target.publish(sink_resource, call, written);
    } else {
        return error.UnsupportedException;
    }
}

fn fillAgeEntry(entry: *age_seam.Entry, node: *Node, _: NoCtx) Exception!void {
    const parts = try entryNameData(node.child);
    entry.* = .{ .name = parts.name, .data = parts.data };
}

fn fillApfsEntry(entry: *apfs_seam.Entry, node: *Node, _: NoCtx) Exception!void {
    const parts = try entryNameData(node.child);
    entry.* = .{ .name = parts.name, .data = parts.data };
}

pub fn isoHook(invocation: *common.Invocation) Exception!void {
    const plan = &invocation.plan;
    const call = invocation.call;
    const response = invocation.response;
    const source_resource = invocation.source;
    const sink = invocation.sink;
    const sizing = plan.sizing;
    const commit = plan.commit;
    const limits = plan.limits;
    const command_mask = plan.command_mask;
    _ = sizing;
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
            if (try projectedEntryMetadata(call.request)) |ordinal| {
                const entry = try iso_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
                try publishEntryMetadata(call, response, .{ .size = entry.size });
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
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceException;
        if (size > limits.decoded_bytes) return error.ResourceException;
        try common.requireSinkCapacity(sink_resource, call, size);
        const target = try SinkTarget.open(sink_resource, &workspace, size);
        _ = try iso_seam.decodeOrdinal(plan.provider, archive, ordinal, target.output, scratch);
        _ = try target.publish(sink_resource, call, size);
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
        const target = try SinkTarget.open(sink_resource, &workspace, required);
        const written = try iso_seam.encode(plan.provider, entries, target.output, scratch);
        response.byte_length = try target.publish(sink_resource, call, written);
    } else {
        return error.UnsupportedException;
    }
}

pub fn squashfsHook(invocation: *common.Invocation) Exception!void {
    const plan = &invocation.plan;
    const call = invocation.call;
    const response = invocation.response;
    const source_resource = invocation.source;
    const sink = invocation.sink;
    const sizing = plan.sizing;
    const commit = plan.commit;
    const limits = plan.limits;
    const command_mask = plan.command_mask;
    _ = sizing;
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
            if (try projectedEntryMetadata(call.request)) |ordinal| {
                const entry = try squashfs_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
                try publishEntryMetadata(call, response, .{ .name = entry.name, .size = entry.size });
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
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceException;
        if (size > limits.decoded_bytes) return error.ResourceException;
        try common.requireSinkCapacity(sink_resource, call, size);
        const target = try SinkTarget.open(sink_resource, &workspace, size);
        _ = try squashfs_seam.decodeOrdinal(plan.provider, archive, ordinal, target.output, scratch);
        _ = try target.publish(sink_resource, call, size);
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
        const target = try SinkTarget.open(sink_resource, &workspace, required);
        const written = try squashfs_seam.encode(plan.provider, entries, target.output, scratch);
        response.byte_length = try target.publish(sink_resource, call, written);
    } else {
        return error.UnsupportedException;
    }
}

pub fn wimHook(invocation: *common.Invocation) Exception!void {
    const plan = &invocation.plan;
    const call = invocation.call;
    const response = invocation.response;
    const source_resource = invocation.source;
    const sink = invocation.sink;
    const sizing = plan.sizing;
    const commit = plan.commit;
    const limits = plan.limits;
    const command_mask = plan.command_mask;
    _ = sizing;
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
            if (try projectedEntryMetadata(call.request)) |ordinal| {
                const entry = try wim_seam.inspectOrdinal(plan.provider, archive, ordinal, scratch);
                try publishEntryMetadata(call, response, .{ .name = entry.name, .size = entry.size });
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
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceException;
        if (size > limits.decoded_bytes) return error.ResourceException;
        try common.requireSinkCapacity(sink_resource, call, size);
        const target = try SinkTarget.open(sink_resource, &workspace, size);
        _ = try wim_seam.decodeOrdinal(plan.provider, archive, ordinal, target.output, scratch);
        _ = try target.publish(sink_resource, call, size);
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        const entries = try collectEntries(wim.Entry, call.request, &workspace, NoCtx{}, fillWimEntry);
        const scratch = try workspace.take(u8, wim_seam.scratch_size);
        const required = try wim_seam.archiveSize(plan.provider, entries, scratch);
        if (sink == null) {
            response.byte_length = required;
            return;
        }
        const sink_resource = sink.?;
        try common.requireSinkCapacity(sink_resource, call, required);
        const target = try SinkTarget.open(sink_resource, &workspace, required);
        const written = try wim_seam.encode(plan.provider, entries, target.output, scratch);
        response.byte_length = try target.publish(sink_resource, call, written);
    } else {
        return error.UnsupportedException;
    }
}

fn cpioSelector(comptime name: []const u8, child: ?*Node) ?*Node {
    return node_graph.findSelector(child, comptime discovery.parameter("cpio", name).family, comptime discovery.parameter("cpio", name).ordinal);
}

fn fillCpioEntry(entry: *cpio.Entry, node: *Node, _: NoCtx) Exception!void {
    const parts = try entryNameData(node.child);
    const uid: u32 = if (cpioSelector("entry_uid", node.child)) |n| blk: {
        break :blk try narrow(u32, n.value_low);
    } else 0;
    const mtime = node_graph.parseU64(cpioSelector("entry_mtime", node.child));
    entry.* = .{ .name = parts.name, .data = parts.data, .uid = uid, .modification_time = mtime };
}

pub fn cpioHook(invocation: *common.Invocation) Exception!void {
    const plan = &invocation.plan;
    const call = invocation.call;
    const response = invocation.response;
    const source_resource = invocation.source;
    const sink = invocation.sink;
    const sizing = plan.sizing;
    const commit = plan.commit;
    const limits = plan.limits;
    const command_mask = plan.command_mask;
    _ = sizing;
    var workspace = try resource.Workspace.initTracked(call.workspace, call.workspace_capacity, &plan.workspace_required);
    if (command_mask == vocabulary.command_mask_read) {
        if (sink == null) {
            const archive = try materializeArchive(source_resource, &workspace, limits);
            if (try projectedEntrySize(call.request)) |ordinal| {
                const entry = try cpio_seam.inspectOrdinal(plan.provider, archive, ordinal);
                response.byte_length = entry.size;
                return;
            }
            if (try projectedEntryMetadata(call.request)) |ordinal| {
                const entry = try cpio_seam.inspectOrdinal(plan.provider, archive, ordinal);
                try publishEntryMetadata(call, response, .{
                    .name = entry.name,
                    .size = entry.size,
                    .mtime = entry.modification_time,
                    .uid = entry.uid,
                });
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
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceException;
        if (size > limits.decoded_bytes) return error.ResourceException;
        try common.requireSinkCapacity(sink_resource, call, size);
        const target = try SinkTarget.open(sink_resource, &workspace, size);
        _ = try cpio_seam.decodeOrdinal(plan.provider, archive, ordinal, target.output);
        _ = try target.publish(sink_resource, call, size);
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
        const target = try SinkTarget.open(sink_resource, &workspace, required);
        const written = try cpio_seam.encode(plan.provider, entries, target.output);
        response.byte_length = try target.publish(sink_resource, call, written);
    } else {
        return error.UnsupportedException;
    }
}

pub fn zipHook(invocation: *common.Invocation) Exception!void {
    const plan = &invocation.plan;
    const call = invocation.call;
    const response = invocation.response;
    const source_resource = invocation.source;
    const sink = invocation.sink;
    const sizing = plan.sizing;
    const commit = plan.commit;
    const limits = plan.limits;
    const command_mask = plan.command_mask;
    _ = sizing;
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
                const entry = try zip.zipInspectOrdinalEx(archive, std.math.cast(usize, ordinal) orelse return error.CallException, limits);
                response.byte_length = entry.uncompressed_size;
                return;
            }
            if (try projectedEntryMetadata(call.request)) |ordinal| {
                const entry = try zip.zipInspectOrdinalEx(archive, std.math.cast(usize, ordinal) orelse return error.CallException, limits);
                try publishEntryMetadata(call, response, .{ .name = entry.name, .size = entry.uncompressed_size });
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
        const entry = try zip.zipInspectOrdinalEx(archive, std.math.cast(usize, ordinal) orelse return error.ResourceException, limits);
        const history = try workspace.take(u8, if (entry.actual_method == 9) zip.deflate64_decode_history_size else zip.deflate_history_size);
        const size = entry.uncompressed_size;
        if (size > limits.decoded_bytes) return error.ResourceException;
        try common.requireSinkCapacity(sink_resource, call, size);
        const decrypt_staging = if (entry.encrypted) try workspace.take(u8, entry.compressed_size) else @as([]u8, &.{});
        // The decode target opens before the scratch carve: a staged sink needs
        // its buffer ahead of the decoder's claim.
        const target = try SinkTarget.open(sink_resource, &workspace, size);
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
        _ = zip.zipDecodeOrdinal(archive, std.math.cast(usize, ordinal) orelse return error.ResourceException, target.output, decode_options) catch |err| {
            writeCryptoFailure(call, crypto_cause);
            return err;
        };
        _ = try target.publish(sink_resource, call, size);
        response.byte_length = size;
    } else if (command_mask == vocabulary.command_mask_write) {
        try requireVerified(commit);
        if (crypto_params) |params| {
            if (params.algorithm > 3) {
                writeCryptoFailure(call, .unsupported_algorithm);
                return error.UnsupportedException;
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
        const target = try SinkTarget.open(sink_resource, &workspace, required);
        const written = zip.encode(entries, comment, target.output, plan.provider, history, measurement_buffer, crypto_staging, scratch, &crypto_cause) catch |err| {
            writeCryptoFailure(call, crypto_cause);
            return err;
        };
        response.byte_length = try target.publish(sink_resource, call, written);
    } else {
        return error.UnsupportedException;
    }
}

pub fn sevenzipHook(invocation: *common.Invocation) Exception!void {
    // Single sevenzip profile unions decoded/coded sides: reads accept every method, writes pack.
    // Queries follow their target.
    return sevenZipGeneric(true, invocation);
}

fn sevenZipGeneric(comptime coded: bool, invocation: *common.Invocation) Exception!void {
    const plan = &invocation.plan;
    const call = invocation.call;
    const response = invocation.response;
    const source_resource = invocation.source;
    const sink = invocation.sink;
    const sizing = plan.sizing;
    const commit = plan.commit;
    const limits = plan.limits;
    const command_mask = plan.command_mask;
    _ = sizing;
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
            if (try projectedEntryMetadata(call.request)) |ordinal| {
                const entry = seven_zip.sevenZipInspectOrdinalEx(archive, &workspace, limits, ordinal, &load_options) catch |err| {
                    writeCryptoFailure(call, crypto_cause);
                    return err;
                };
                try publishEntryMetadata(call, response, .{ .name = entry.name, .size = entry.size });
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
        if (!coded and entry.method != .copy) return error.UnsupportedException;
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceException;
        if (size > limits.decoded_bytes) return error.ResourceException;
        try common.requireSinkCapacity(sink_resource, call, size);
        const decode_options: seven_zip.SevenZipDecodeOptions = .{
            .password = cryptoPassword(crypto_params),
            .kdf_rounds_limit = cryptoKdfLimit(crypto_params),
            .password_lifetime = cryptoLifetime(crypto_params),
            .failure_cause = &crypto_cause,
            .provider = plan.provider,
        };
        const target = try SinkTarget.open(sink_resource, &workspace, size);
        _ = seven_zip.sevenZipDecodeOrdinal(archive, &workspace, limits, ordinal, target.output, decode_options) catch |err| {
            writeCryptoFailure(call, crypto_cause);
            return err;
        };
        _ = try target.publish(sink_resource, call, size);
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
        const filter_slots = try workspace.take(seven_zip.CoderMethod, entryCount(call.request));
        var filter_next: usize = 0;
        const entries = try collectEntries(seven_zip.Entry, call.request, &workspace, SevenZipFillCtx{ .default_method = .copy, .allow_method = coded, .crypto = crypto_params, .filter_slots = filter_slots, .filter_next = &filter_next }, fillSevenZipEntry);
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
        const target = try SinkTarget.open(sink_resource, &workspace, required);
        const written = try seven_zip.sevenZipWritePacked(entries, packed_entries, target.output, &workspace, plan.provider, limits, header_options);
        response.byte_length = try target.publish(sink_resource, call, written);
    } else {
        return error.UnsupportedException;
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

fn entryNameData(child: ?*Node) Exception!struct { name: []const u8, data: []const u8 } {
    const name_node = node_graph.findSelector(child, comptime discovery.parameter("tar", "entry_name").family, comptime discovery.parameter("tar", "entry_name").ordinal);
    const data_node = node_graph.findSelector(child, comptime discovery.parameter("tar", "entry_data").family, comptime discovery.parameter("tar", "entry_data").ordinal);
    return .{
        .name = if (name_node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{},
        .data = if (data_node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{},
    };
}

const NoCtx = struct {};

fn collectEntries(comptime E: type, request: ?*Node, workspace: *resource.Workspace, ctx: anytype, comptime fill: anytype) Exception![]const E {
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
    filter_slots: []seven_zip.CoderMethod,
    filter_next: *usize,
};

fn fillSevenZipEntry(entry: *seven_zip.Entry, node: *Node, ctx: SevenZipFillCtx) Exception!void {
    const parts = try entryNameData(node.child);
    const method_node = if (ctx.allow_method) entryMethod(node.child) else null;
    const filter_node = if (ctx.allow_method)
        node_graph.findSelector(node.child, comptime discovery.parameter("tar", "entry_filter").family, comptime discovery.parameter("tar", "entry_filter").ordinal)
    else
        null;
    const method = if (method_node) |n| try parseSevenZipMethod(n) else ctx.default_method;
    entry.* = .{ .name = parts.name, .data = parts.data, .method = method };
    if (filter_node) |n| {
        const slot = ctx.filter_next.*;
        ctx.filter_next.* = slot + 1;
        ctx.filter_slots[slot] = try parseSevenZipMethod(n);
        entry.filters = ctx.filter_slots[slot..][0..1];
    }
    if (ctx.crypto) |params| {
        entry.encrypted = true;
        entry.password = params.password;
        entry.kdf_rounds_limit = params.kdf_rounds_limit;
        entry.password_lifetime = params.password_lifetime;
    }
}

fn parseSevenZipMethod(node: *Node) Exception!seven_zip.CoderMethod {
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
        else => error.CallException,
    };
}

// Largest decrypted-header staging either RAR family needs: RAR5 caps a
// header at 2 MiB; RAR4 headers are u16-sized, 16-byte aligned.
const rar_header_scratch_size = 2 * 1024 * 1024 + 16;

pub fn rarHook(invocation: *common.Invocation) Exception!void {
    const plan = &invocation.plan;
    const call = invocation.call;
    const response = invocation.response;
    const source_resource = invocation.source;
    const sink = invocation.sink;
    const sizing = plan.sizing;
    const commit = plan.commit;
    const limits = plan.limits;
    const command_mask = plan.command_mask;
    if (sizing != .metadata_exact) return error.UnsupportedException;
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
                const entry = rar.rarInspectOrdinalOpts(archive, std.math.cast(usize, ordinal) orelse return error.ResourceException, limits.entries, inspect_opts) catch |err| {
                    writeCryptoFailure(call, failure_cause);
                    return err;
                };
                response.byte_length = entry.size;
                return;
            }
            if (try projectedEntryMetadata(call.request)) |ordinal| {
                const entry = rar.rarInspectOrdinalOpts(archive, std.math.cast(usize, ordinal) orelse return error.ResourceException, limits.entries, inspect_opts) catch |err| {
                    writeCryptoFailure(call, failure_cause);
                    return err;
                };
                try publishEntryMetadata(call, response, .{ .name = entry.name, .size = entry.size, .mtime = entry.mtime });
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
        // Decryption stages a mutable packed copy and, for -hp, decrypted
        // headers, both capped by the archive size. Plaintext carves nothing.
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
        const entry = rar.rarInspectOrdinalOpts(archive, std.math.cast(usize, ordinal) orelse return error.ResourceException, limits.entries, decode_opts) catch |err| {
            writeCryptoFailure(call, failure_cause);
            return err;
        };
        const size = std.math.cast(usize, entry.size) orelse return error.ResourceException;
        if (size > limits.decoded_bytes) return error.ResourceException;
        try common.requireSinkCapacity(sink_resource, call, size);

        // Store entries carve nothing. The PPMd heap takes the remainder;
        // the stream bounds the model, so the target opens first.
        // Vendor unrar floors the v29/36 window at 0x40000 so any unpacked
        // size can stream; a smaller dictionary would decode into the ring
        // and then fail the oversized final emit.
        const declared_window = std.math.cast(usize, entry.window_bytes) orelse return error.ResourceException;
        const window_len = if (entry.family == .rar4 and (entry.unpack_version == 29 or entry.unpack_version == 36))
            @max(declared_window, rar.unpack29_min_window)
        else
            declared_window;
        const target = try SinkTarget.open(sink_resource, &workspace, size);
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
            // Unpacker states are re-read as u64 words and structs; u64 aligns to
            // 4 on x86, so the carve uses StateOctet.
            const state_octets = try workspace.take(StateOctet, (rar.max_unpacker_bytes + 7) / 8);
            const window_buf = try workspace.take(u8, window_len);
            const table_pool = try workspace.take(u16, rar.table_pool_words);
            const pending50 = try workspace.take(rar.PendingFilter50, rar.max_pending50);
            const pending29 = try workspace.take(rar.PendingFilter29, rar.max_pending29);
            const filter_scratch = try workspace.take(u8, window_len + rar.filter_scratch_extra);
            const ppm_heap = try workspace.take(u8, workspace.remaining());
            bufs = .{
                .state = std.mem.sliceAsBytes(state_octets),
                .window = window_buf,
                .table_pool = table_pool,
                .pending50 = pending50,
                .pending29 = pending29,
                .filter_scratch = filter_scratch,
                .ppm_heap = ppm_heap,
                .packed_stage = packed_stage,
            };
        }

        _ = rar.rarDecodeOrdinal(archive, std.math.cast(usize, ordinal) orelse return error.ResourceException, target.output, &bufs, decode_opts) catch |err| {
            writeCryptoFailure(call, failure_cause);
            return err;
        };
        _ = try target.publish(sink_resource, call, size);
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
        if (write_options.encrypt_headers and write_options.password.len == 0) return error.CallException;
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
        const target = try SinkTarget.open(sink_resource, &workspace, required);
        const written = try rar_writer.rarEncodeEx(entries, target.output, &ws, plan.provider, write_options);
        response.byte_length = try target.publish(sink_resource, call, written);
    } else {
        return error.UnsupportedException;
    }
}

fn fillRarEntry(entry: *rar_writer.RarEntry, node: *Node, _: NoCtx) Exception!void {
    const parts = try entryNameData(node.child);
    const method_node = entryMethod(node.child);
    if (!std.unicode.utf8ValidateSlice(parts.name)) return error.CallException;
    const method: u8 = if (method_node) |n| try narrow(u8, n.value_low) else 0;
    const mtime = entryMtime(node.child);
    entry.* = .{
        .name = parts.name,
        .data = parts.data,
        .mtime = @truncate(mtime),
        .method = method,
    };
}

fn archiveComment(request: ?*Node) Exception![]const u8 {
    const node = node_graph.findSelector(request, comptime discovery.parameter("tar", "comment").family, comptime discovery.parameter("tar", "comment").ordinal);
    return if (node) |n| try resource.checkedConstBytes(n.bytes, n.byte_length) else &.{};
}

fn fillTarEntry(entry: *tar.Entry, node: *Node, _: NoCtx) Exception!void {
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

fn fillZipEntry(entry: *zip.Entry, node: *Node, crypto_params: ?CryptoParams) Exception!void {
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
