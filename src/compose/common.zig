const std = @import("std");

const seam = @import("seam");

const measurement = @import("../common/primitive/measurement.zig");
const abi = @import("../kernel/envelope.zig");
const node_graph = @import("../kernel/node.zig");
const resource = @import("../kernel/resource.zig");
const vocabulary = @import("../kernel/vocabulary.zig");

const Call = abi.Call;
const Id = abi.Id;
const Node = abi.Node;
const Limits = resource.Limits;
const Resource = resource.Resource;
const Exception = vocabulary.Exception;

// A sink must accept writes and have the capacity before any byte is
// produced; every transform and archive hook states this pair first.
pub fn requireSink(sink: *Resource, call: *Call, required: usize) Exception!void {
    if (!sink.hasCapability(resource.capability_bit_write)) return error.UnsupportedException;
    return requireSinkCapacity(sink, call, required);
}

pub fn requireSinkCapacity(sink: *Resource, call: *Call, required: usize) Exception!void {
    const capacity = sinkCapacity(sink);
    if (required > capacity) {
        writeCapacityDiagnostic(call, required, capacity);
        return error.CapacityException;
    }
}

// Verified commit: a bounded write reports the produced length, and an
// overrun of the analytic bound is a correctness defect, never a silent truncation.
pub fn verifiedCommitLength(sink: *Resource, call: *Call, sizing: vocabulary.SizingMode, staged: []const u8, planned: usize, produced: usize) Exception!?usize {
    if (sizing == .bounded) {
        if (produced > planned) return error.InternalException;
        try commitBytesToSink(sink, call, staged[0..produced]);
        return produced;
    }
    try commitBytesToSink(sink, call, staged);
    return null;
}

pub fn commitBytesToSink(sink: *Resource, call: *Call, chunk: []const u8) Exception!void {
    sink.writeAll(chunk) catch |exception| return mapSinkError(exception, call, sink);
}

pub const SourceSizing = enum { budget, require_size, size_or_budget, replay };

pub const ExecutionPlan = struct {
    profile_id: Id,
    policy: vocabulary.CommandPolicy,
    limits: Limits,
    capabilities: u32,
    provider: seam.Provider = seam.default_provider,
    source_strategy: SourceSizing,
    workspace_plan: resource.WorkspacePlan,
    workspace_required: usize = 0,
    workspace_available: usize = 0,
};

fn budgetRequest(workspace: *resource.Workspace, limit: u64) usize {
    const remaining = workspace.bytes.len - workspace.cursor;
    const capped = std.math.cast(usize, limit) orelse remaining;
    return @min(remaining, capped);
}

pub fn materializeSource(comptime sizing: SourceSizing, source: *Resource, workspace: *resource.Workspace, limit: u64) Exception![]const u8 {
    return switch (source.kind) {
        .direct_read => |bytes| {
            if (bytes.len > limit) return error.ResourceException;
            return bytes;
        },
        .callback_read => materialize_block: {
            if (sizing != .budget) try source.requireCapability(resource.capability_bit_replay);
            const request = switch (sizing) {
                .budget => request_block: {
                    break :request_block budgetRequest(workspace, limit);
                },
                .require_size => request_block: {
                    try source.requireCapability(resource.capability_bit_size);
                    const total = try source.size();
                    if (total > limit) return error.ResourceException;
                    break :request_block std.math.cast(usize, total) orelse return error.ResourceException;
                },
                .size_or_budget => request_block: {
                    if (source.hasCapability(resource.capability_bit_size)) {
                        const total = try source.size();
                        if (total > limit) return error.ResourceException;
                        break :request_block std.math.cast(usize, total) orelse return error.ResourceException;
                    }
                    break :request_block budgetRequest(workspace, limit);
                },
                .replay => request_block: {
                    var buffer: [4096]u8 = undefined;
                    var total: u64 = 0;
                    while (true) {
                        const bytes_read = try source.read(&buffer);
                        if (bytes_read == 0) break;
                        total += bytes_read;
                        if (total > limit) return error.ResourceException;
                    }
                    try source.rewind();
                    break :request_block std.math.cast(usize, total) orelse return error.ResourceException;
                },
            };
            if ((sizing == .budget or sizing == .size_or_budget) and request == 0) return error.CapacityException;
            if (sizing == .require_size and request == 0) break :materialize_block &.{};
            const buffer = try workspace.take(u8, request);
            break :materialize_block try source.materialize(buffer);
        },
        else => return error.UnsupportedException,
    };
}

pub fn measureSource(source: *Resource, limit: u64) Exception!usize {
    if (source.hasCapability(resource.capability_bit_size)) {
        const total = try source.size();
        if (total > limit) return error.ResourceException;
        return std.math.cast(usize, total) orelse error.ResourceException;
    }
    if (!source.hasCapability(resource.capability_bit_replay)) return error.UnsupportedException;
    var counter = measurement.Counter.init(null);
    var bounded_source: resource.BoundedReader = undefined;
    bounded_source.init(source, limit);
    _ = std.Io.Reader.streamRemaining(&bounded_source.reader, &counter.writer) catch |exception| return mapStreamError(exception);
    try source.rewind();
    const total = counter.written();
    if (total > limit) return error.ResourceException;
    return std.math.cast(usize, total) orelse error.ResourceException;
}

pub fn measureOutputSize(source: *Resource, limits: Limits) Exception!u64 {
    return measureSource(source, limits.encoded_bytes);
}

fn mapStreamError(err: anyerror) Exception {
    return switch (err) {
        error.ReadFailed => error.IoException,
        error.WriteFailed => error.IoException,
        error.EndOfStream => error.IoException,
        else => error.InternalException,
    };
}

pub fn planOutputSize(source: *Resource, sizing: vocabulary.SizingMode, limits: Limits, workspace: *resource.Workspace) Exception!usize {
    switch (sizing) {
        .unavailable => return error.UnsupportedException,
        .metadata_exact => {
            try source.requireCapability(resource.capability_bit_size);
            const total = try source.size();
            if (total > limits.encoded_bytes) return error.ResourceException;
            return std.math.cast(usize, total) orelse error.ResourceException;
        },
        .measured => {
            try source.requireCapability(resource.capability_bit_replay);
            const total = try measureOutputSize(source, limits);
            return std.math.cast(usize, total) orelse error.ResourceException;
        },
        .bounded => return error.UnsupportedException,
        .materialization => {
            const budget = std.math.cast(usize, limits.encoded_bytes) orelse return error.ResourceException;
            const buffer = try workspace.take(u8, budget);
            const materialized = try source.materialize(buffer);
            return materialized.len;
        },
    }
}

pub fn writeDiagnostic(call: *Call, status: u32, id: Id) void {
    const diagnostic = call.diagnostic orelse return;
    if (!diagnostic.isValid()) return;
    diagnostic.id = id;
    diagnostic.value_low = status;
    diagnostic.value_high = 0;
    diagnostic.byte_length = 0;
    diagnostic.child = null;
}

fn writeDiagnosticValue(call: *Call, id: Id, low: u64, high: u64) void {
    const diagnostic = call.diagnostic orelse return;
    if (!diagnostic.isValid()) return;
    const output = node_graph.findChild(diagnostic, id) catch return orelse return;
    if (output.bytes != null or output.byte_capacity != 0 or output.byte_length != 0 or output.child != null) return;
    output.value_low = low;
    output.value_high = high;
}

pub fn writeDiagnosticScalar(call: *Call, id: Id, value: u64) void {
    writeDiagnosticValue(call, id, value, 0);
}

pub fn writeDiagnosticId(call: *Call, id: Id, value: Id) void {
    writeDiagnosticValue(call, id, value.low, value.high);
}

fn writeCapacityPair(call: *Call, required_id: Id, available_id: Id, required: u64, available: u64) void {
    writeDiagnosticScalar(call, required_id, required);
    writeDiagnosticScalar(call, available_id, available);
}

pub fn writeCapacityDiagnostic(call: *Call, required: u64, available: u64) void {
    writeCapacityPair(call, vocabulary.ids.diagnostic_required_capacity, vocabulary.ids.diagnostic_available_capacity, required, available);
}

pub fn writeWorkspaceCapacityDiagnostic(call: *Call, required: u64, available: u64) void {
    writeCapacityPair(call, vocabulary.ids.workspace_required_capacity, vocabulary.ids.workspace_available_capacity, required, available);
}

pub fn writeDownstreamDiagnostic(call: *Call, status: u32) void {
    writeDiagnosticScalar(call, vocabulary.ids.diagnostic_downstream_status, status);
}

fn overlapsWorkspace(workspace_ptr: usize, workspace_len: usize, ptr: usize, len: usize) Exception!void {
    if (try spanOverlap(workspace_ptr, workspace_len, ptr, len)) return error.CallException;
}

fn workspaceRange(call: *Call) ?struct { ptr: usize, len: usize } {
    if (call.workspace == null or call.workspace_capacity == 0) return null;
    return .{ .ptr = @intFromPtr(call.workspace.?), .len = call.workspace_capacity };
}

pub fn checkWorkspaceOverlap(call: *Call, source: *Resource, sink: *Resource) Exception!void {
    const range = workspaceRange(call) orelse return;
    if (source.kind == .direct_read) {
        try overlapsWorkspace(range.ptr, range.len, @intFromPtr(source.kind.direct_read.ptr), source.kind.direct_read.len);
    }
    if (sink.kind == .direct_write) {
        try overlapsWorkspace(range.ptr, range.len, @intFromPtr(sink.kind.direct_write.ptr), sink.kind.direct_write.len);
    }
}

pub fn checkSourceWorkspaceOverlap(call: *Call, source: *Resource) Exception!void {
    const range = workspaceRange(call) orelse return;
    if (source.kind != .direct_read) return;
    try overlapsWorkspace(range.ptr, range.len, @intFromPtr(source.kind.direct_read.ptr), source.kind.direct_read.len);
}

pub fn validateBoundary(call: *Call, plan: *const ExecutionPlan, source_node: ?*Node, sink_node: ?*Node) Exception!void {
    _ = plan;
    if (call.workspace) |workspace| {
        const workspace_ptr = @intFromPtr(workspace);
        const workspace_len = call.workspace_capacity;
        if (source_node) |node| {
            if ((node.flags & abi.node_flag_callback_resource) == 0 and node.byte_length != 0) {
                const bytes = try resource.checkedConstBytes(node.bytes, node.byte_length);
                if (try spanOverlap(workspace_ptr, workspace_len, @intFromPtr(bytes.ptr), bytes.len)) return error.CallException;
            }
        }
        if (sink_node) |node| {
            if ((node.flags & abi.node_flag_callback_resource) == 0 and node.byte_capacity != 0) {
                const bytes = try resource.checkedMutBytes(node.bytes, node.byte_capacity);
                if (try spanOverlap(workspace_ptr, workspace_len, @intFromPtr(bytes.ptr), bytes.len)) return error.CallException;
            }
        }
    }
    if (source_node) |source| {
        if (sink_node) |sink| {
            if ((source.flags & abi.node_flag_callback_resource) == 0 and (sink.flags & abi.node_flag_callback_resource) == 0 and source.byte_length != 0 and sink.byte_capacity != 0) {
                const source_bytes = try resource.checkedConstBytes(source.bytes, source.byte_length);
                const sink_bytes = try resource.checkedMutBytes(sink.bytes, sink.byte_capacity);
                if (try spanOverlap(@intFromPtr(source_bytes.ptr), source_bytes.len, @intFromPtr(sink_bytes.ptr), sink_bytes.len)) return error.CallException;
            }
        }
    }
}

// Interior checks report overflow, so the fallible form stands apart.
pub fn spanOverlap(first_ptr: usize, first_len: usize, second_ptr: usize, second_len: usize) Exception!bool {
    if (first_len == 0 or second_len == 0) return false;
    const first_end = std.math.add(usize, first_ptr, first_len) catch return error.ResourceException;
    const second_end = std.math.add(usize, second_ptr, second_len) catch return error.ResourceException;
    return first_ptr < second_end and second_ptr < first_end;
}

pub fn checkSourceSinkOverlap(source: *Resource, sink: *Resource) Exception!void {
    if (source.kind != .direct_read or sink.kind != .direct_write) return;
    const source_ptr = @intFromPtr(source.kind.direct_read.ptr);
    const source_len = source.kind.direct_read.len;
    const sink_ptr = @intFromPtr(sink.kind.direct_write.ptr);
    const sink_len = sink.kind.direct_write.len;
    if (try spanOverlap(source_ptr, source_len, sink_ptr, sink_len)) return error.CallException;
}

pub fn sinkCapacity(sink: *Resource) usize {
    return switch (sink.kind) {
        .direct_write => |destination| destination.len,
        .callback_write => std.math.maxInt(usize),
        else => 0,
    };
}

pub fn sinkDirectBuffer(sink: *Resource, required: usize) Exception![]u8 {
    return switch (sink.kind) {
        .direct_write => |destination| if (destination.len >= required) destination[0..required] else return error.CapacityException,
        else => return error.UnsupportedException,
    };
}

pub fn mapSinkError(exception: Exception, call: *Call, sink: *Resource) Exception {
    if (sink.downstream_status != 0) writeDownstreamDiagnostic(call, sink.downstream_status);
    return exception;
}

// Bound plan must never truncate. Overrun past it is an internal defect.
// Bounded writes report produced bytes; the plan stands for measured writes.
// True means the response is final and the caller returns.
pub fn respondWrite(response: *Node, sizing: vocabulary.SizingMode, produced: anytype, limit: u64, planned: usize) Exception!bool {
    if (sizing == .bounded) {
        response.byte_length = try boundedProduced(produced, limit, planned);
        return true;
    }
    return false;
}

pub fn boundedProduced(bounded_sink: *resource.BoundedWriter, encoded_limit: u64, planned: usize) Exception!usize {
    const produced = encoded_limit - bounded_sink.limit;
    if (produced > planned) return error.InternalException;
    return produced;
}
