const std = @import("std");

const abi = @import("../kernel/envelope.zig");
const Id = abi.Id;
const Node = abi.Node;
const Call = abi.Call;
const vocabulary = @import("../kernel/vocabulary.zig");
const Failure = vocabulary.Failure;
const node_graph = @import("../common/node.zig");
const measurement = @import("../common/primitive/measurement.zig");
const resource = @import("../common/resource.zig");
const Resource = resource.Resource;
const Limits = resource.Limits;

pub fn requireSinkCapacity(sink: *Resource, call: *Call, required: usize) Failure!void {
    const capacity = sinkCapacity(sink);
    if (required > capacity) {
        writeCapacityDiagnostic(call, required, capacity);
        return error.InsufficientCapacity;
    }
}

pub fn commitBytesToSink(sink: *Resource, call: *Call, bytes: []const u8) Failure!void {
    sink.writeAll(bytes) catch |failure| return mapSinkError(failure, call, sink);
}

pub const SourceSizing = enum { budget, require_size, size_or_budget, replay };
pub const Invocation = enum { query, read, write };

pub const ExecutionPlan = struct {
    invocation: Invocation,
    profile_id: Id,
    target_command: ?Id = null,
    policy: vocabulary.CommandPolicy,
    limits: Limits,
    capabilities: u32,
    source_strategy: SourceSizing,
    workspace_plan: resource.WorkspacePlan,
    output_requirement: ?u64 = null,
    workspace_required: usize = 0,
    workspace_available: usize = 0,
};

pub fn materializeSource(comptime sizing: SourceSizing, source: *Resource, workspace: *resource.Workspace, limit: u64) Failure![]const u8 {
    return switch (source.kind) {
        .direct_read => |bytes| {
            if (bytes.len > limit) return error.ResourceLimit;
            return bytes;
        },
        .callback_read => materialize_block: {
            if (sizing != .budget) try source.requireCapability(resource.capability_bit_replay);
            const request = switch (sizing) {
                .budget => request_block: {
                    const remaining = workspace.bytes.len - workspace.cursor;
                    const capped = std.math.cast(usize, limit) orelse remaining;
                    break :request_block @min(remaining, capped);
                },
                .require_size => request_block: {
                    try source.requireCapability(resource.capability_bit_size);
                    const total = try source.size();
                    if (total > limit) return error.ResourceLimit;
                    break :request_block std.math.cast(usize, total) orelse return error.ResourceLimit;
                },
                .size_or_budget => request_block: {
                    if (source.hasCapability(resource.capability_bit_size)) {
                        const total = try source.size();
                        if (total > limit) return error.ResourceLimit;
                        break :request_block std.math.cast(usize, total) orelse return error.ResourceLimit;
                    }
                    const remaining = workspace.bytes.len - workspace.cursor;
                    const capped = std.math.cast(usize, limit) orelse remaining;
                    break :request_block @min(remaining, capped);
                },
                .replay => request_block: {
                    var buffer: [4096]u8 = undefined;
                    var total: u64 = 0;
                    while (true) {
                        const bytes_read = try source.read(&buffer);
                        if (bytes_read == 0) break;
                        total += bytes_read;
                        if (total > limit) return error.ResourceLimit;
                    }
                    try source.rewind();
                    break :request_block std.math.cast(usize, total) orelse return error.ResourceLimit;
                },
            };
            if ((sizing == .budget or sizing == .size_or_budget) and request == 0) return error.InsufficientCapacity;
            if (sizing == .require_size and request == 0) break :materialize_block &.{};
            const buffer = try workspace.take(u8, request);
            break :materialize_block try source.materialize(buffer);
        },
        else => return error.Unsupported,
    };
}

pub fn measureOutputSize(source: *Resource, limits: Limits) Failure!u64 {
    if (source.hasCapability(resource.capability_bit_size)) {
        const total = try source.size();
        if (total > limits.encoded_bytes) return error.ResourceLimit;
        return total;
    }
    if (source.hasCapability(resource.capability_bit_replay)) {
        var counter = measurement.Counter.init(null);
        var bounded: resource.BoundedReader = undefined;
        bounded.init(source, limits.encoded_bytes);
        const bytes_produced = std.Io.Reader.streamRemaining(&bounded.reader, &counter.writer) catch |failure| return mapStreamError(failure);
        if (bytes_produced > limits.encoded_bytes) return error.ResourceLimit;
        try source.rewind();
        return bytes_produced;
    }
    return error.Unsupported;
}

fn mapStreamError(failure: anyerror) Failure {
    return switch (failure) {
        error.ReadFailed => error.IoFailure,
        error.WriteFailed => error.IoFailure,
        error.EndOfStream => error.IoFailure,
        else => error.InternalFailure,
    };
}

pub fn planOutputSize(source: *Resource, sizing: vocabulary.SizingMode, limits: Limits, workspace: *resource.Workspace) Failure!usize {
    switch (sizing) {
        .unavailable => return error.Unsupported,
        .metadata_exact => {
            try source.requireCapability(resource.capability_bit_size);
            const total = try source.size();
            if (total > limits.encoded_bytes) return error.ResourceLimit;
            return std.math.cast(usize, total) orelse error.ResourceLimit;
        },
        .measured => {
            try source.requireCapability(resource.capability_bit_replay);
            const total = try measureOutputSize(source, limits);
            return std.math.cast(usize, total) orelse error.ResourceLimit;
        },
        .bounded => return error.Unsupported,
        .materialization => {
            const budget = std.math.cast(usize, limits.encoded_bytes) orelse return error.ResourceLimit;
            const buffer = try workspace.take(u8, budget);
            const materialized = try source.materialize(buffer);
            return materialized.len;
        },
    }
}

pub fn writeDiagnostic(call: *Call, status: u32, id: Id) void {
    const diagnostic = call.diagnostic orelse return;
    if (!diagnostic.valid()) return;
    diagnostic.id = id;
    diagnostic.value_low = status;
    diagnostic.value_high = 0;
    diagnostic.byte_length = 0;
    diagnostic.child = null;
}

pub fn writeDiagnosticScalar(call: *Call, id: Id, value: u64) void {
    const diagnostic = call.diagnostic orelse return;
    if (!diagnostic.valid()) return;
    const output = node_graph.findChild(diagnostic, id) catch return orelse return;
    if (output.bytes != null or output.byte_capacity != 0 or output.byte_length != 0 or output.child != null) return;
    output.value_low = value;
    output.value_high = 0;
}

pub fn writeDiagnosticId(call: *Call, id: Id, value: Id) void {
    const diagnostic = call.diagnostic orelse return;
    if (!diagnostic.valid()) return;
    const output = node_graph.findChild(diagnostic, id) catch return orelse return;
    if (output.bytes != null or output.byte_capacity != 0 or output.byte_length != 0 or output.child != null) return;
    output.value_low = value.low;
    output.value_high = value.high;
}

pub fn writeCapacityDiagnostic(call: *Call, required: u64, available: u64) void {
    writeDiagnosticScalar(call, vocabulary.ids.diagnostic_required_capacity, required);
    writeDiagnosticScalar(call, vocabulary.ids.diagnostic_available_capacity, available);
}

pub fn writeWorkspaceCapacityDiagnostic(call: *Call, required: u64, available: u64) void {
    writeDiagnosticScalar(call, vocabulary.ids.workspace_required_capacity, required);
    writeDiagnosticScalar(call, vocabulary.ids.workspace_available_capacity, available);
}

pub fn writeDownstreamDiagnostic(call: *Call, status: u32) void {
    writeDiagnosticScalar(call, vocabulary.ids.diagnostic_downstream_status, status);
}

pub fn checkWorkspaceOverlap(call: *Call, source: *Resource, sink: *Resource) Failure!void {
    if (call.workspace == null or call.workspace_capacity == 0) return;
    const workspace_ptr = @intFromPtr(call.workspace.?);
    const workspace_len = call.workspace_capacity;
    if (source.kind == .direct_read) {
        const ptr = @intFromPtr(source.kind.direct_read.ptr);
        const len = source.kind.direct_read.len;
        if (try spanOverlap(workspace_ptr, workspace_len, ptr, len)) return error.InvalidCall;
    }
    if (sink.kind == .direct_write) {
        const ptr = @intFromPtr(sink.kind.direct_write.ptr);
        const len = sink.kind.direct_write.len;
        if (try spanOverlap(workspace_ptr, workspace_len, ptr, len)) return error.InvalidCall;
    }
}

pub fn checkSourceWorkspaceOverlap(call: *Call, source: *Resource) Failure!void {
    if (call.workspace == null or call.workspace_capacity == 0) return;
    if (source.kind != .direct_read) return;
    const workspace_ptr = @intFromPtr(call.workspace.?);
    const workspace_len = call.workspace_capacity;
    const ptr = @intFromPtr(source.kind.direct_read.ptr);
    const len = source.kind.direct_read.len;
    if (try spanOverlap(workspace_ptr, workspace_len, ptr, len)) return error.InvalidCall;
}

pub fn validateBoundary(call: *Call, plan: *const ExecutionPlan, source_node: ?*Node, sink_node: ?*Node) Failure!void {
    _ = plan;
    if (call.workspace) |workspace| {
        const workspace_ptr = @intFromPtr(workspace);
        const workspace_len = call.workspace_capacity;
        if (source_node) |node| {
            if ((node.flags & abi.node_flag_callback_resource) == 0 and node.byte_length != 0) {
                const bytes = try resource.checkedConstBytes(node.bytes, node.byte_length);
                if (try spanOverlap(workspace_ptr, workspace_len, @intFromPtr(bytes.ptr), bytes.len)) return error.InvalidCall;
            }
        }
        if (sink_node) |node| {
            if ((node.flags & abi.node_flag_callback_resource) == 0 and node.byte_capacity != 0) {
                const bytes = try resource.checkedMutBytes(node.bytes, node.byte_capacity);
                if (try spanOverlap(workspace_ptr, workspace_len, @intFromPtr(bytes.ptr), bytes.len)) return error.InvalidCall;
            }
        }
    }
    if (source_node) |source| {
        if (sink_node) |sink| {
            if ((source.flags & abi.node_flag_callback_resource) == 0 and (sink.flags & abi.node_flag_callback_resource) == 0 and source.byte_length != 0 and sink.byte_capacity != 0) {
                const source_bytes = try resource.checkedConstBytes(source.bytes, source.byte_length);
                const sink_bytes = try resource.checkedMutBytes(sink.bytes, sink.byte_capacity);
                if (try spanOverlap(@intFromPtr(source_bytes.ptr), source_bytes.len, @intFromPtr(sink_bytes.ptr), sink_bytes.len)) return error.InvalidCall;
            }
        }
    }
}

pub fn spanOverlap(a_ptr: usize, a_len: usize, b_ptr: usize, b_len: usize) Failure!bool {
    if (a_len == 0 or b_len == 0) return false;
    const a_end = std.math.add(usize, a_ptr, a_len) catch return error.ResourceLimit;
    const b_end = std.math.add(usize, b_ptr, b_len) catch return error.ResourceLimit;
    return a_ptr < b_end and b_ptr < a_end;
}

pub fn checkSourceSinkOverlap(source: *Resource, sink: *Resource) Failure!void {
    if (source.kind != .direct_read or sink.kind != .direct_write) return;
    const source_ptr = @intFromPtr(source.kind.direct_read.ptr);
    const source_len = source.kind.direct_read.len;
    const sink_ptr = @intFromPtr(sink.kind.direct_write.ptr);
    const sink_len = sink.kind.direct_write.len;
    if (try spanOverlap(source_ptr, source_len, sink_ptr, sink_len)) return error.InvalidCall;
}

pub fn sinkCapacity(sink: *Resource) usize {
    return switch (sink.kind) {
        .direct_write => |destination| destination.len,
        .callback_write => std.math.maxInt(usize),
        else => 0,
    };
}

pub fn sinkDirectBuffer(sink: *Resource, required: usize) Failure![]u8 {
    return switch (sink.kind) {
        .direct_write => |destination| if (destination.len >= required) destination[0..required] else return error.InsufficientCapacity,
        else => return error.Unsupported,
    };
}

pub fn mapSinkError(failure: Failure, call: *Call, sink: *Resource) Failure {
    if (sink.downstream_status != 0) writeDownstreamDiagnostic(call, sink.downstream_status);
    return failure;
}

// Bound plan must never truncate; overrun past it is an internal bug.
pub fn boundedProduced(bounded_sink: *resource.BoundedWriter, encoded_limit: u64, planned: usize) Failure!usize {
    const produced = encoded_limit - bounded_sink.limit;
    if (produced > planned) return error.InternalFailure;
    return produced;
}
