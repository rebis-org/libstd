const std = @import("std");

const abi = @import("../abi/contract.zig");
const Id = abi.Id;
const Node = abi.Node;
const Call = abi.Call;
const Status = abi.Status;
const registry = @import("../catalog/registry.zig");
const Failure = registry.Failure;
const node_graph = @import("../common/node.zig");
const measurement = @import("../common/primitive/measurement.zig");
const resource = @import("../common/resource.zig");
const Resource = resource.Resource;
const Workspace = resource.Workspace;
const Limits = resource.Limits;

pub fn requireSinkCapacity(sink: *Resource, call: *Call, required: usize) Failure!void {
    const capacity = sinkCapacity(sink);
    if (required > capacity) {
        writeCapacityDiagnostic(call, required, capacity);
        return error.InsufficientCapacity;
    }
}

pub fn deliver(sink: *Resource, call: *Call, bytes: []const u8) Failure!void {
    sink.writeAll(bytes) catch |err| return mapSinkError(err, call, sink);
}

pub const SourceSizing = enum { budget, require_size, size_or_budget, replay };
pub const Invocation = enum { query, read, write };

pub const ExecutionPlan = struct {
    invocation: Invocation,
    profile_id: Id,
    target_command: ?Id = null,
    policy: registry.CommandPolicy,
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
        .callback_read => blk: {
            if (sizing != .budget) try source.requireCapability(resource.capability_bit_replay);
            const request = switch (sizing) {
                .budget => blk2: {
                    const remaining = workspace.bytes.len - workspace.cursor;
                    const capped = std.math.cast(usize, limit) orelse remaining;
                    break :blk2 @min(remaining, capped);
                },
                .require_size => blk2: {
                    try source.requireCapability(resource.capability_bit_size);
                    const total = try source.size();
                    if (total > limit) return error.ResourceLimit;
                    break :blk2 std.math.cast(usize, total) orelse return error.ResourceLimit;
                },
                .size_or_budget => blk2: {
                    if (source.hasCapability(resource.capability_bit_size)) {
                        const total = try source.size();
                        if (total > limit) return error.ResourceLimit;
                        break :blk2 std.math.cast(usize, total) orelse return error.ResourceLimit;
                    }
                    const remaining = workspace.bytes.len - workspace.cursor;
                    const capped = std.math.cast(usize, limit) orelse remaining;
                    break :blk2 @min(remaining, capped);
                },
                .replay => blk2: {
                    var buffer: [4096]u8 = undefined;
                    var total: u64 = 0;
                    while (true) {
                        const n = try source.read(&buffer);
                        if (n == 0) break;
                        total += n;
                        if (total > limit) return error.ResourceLimit;
                    }
                    try source.rewind();
                    break :blk2 std.math.cast(usize, total) orelse return error.ResourceLimit;
                },
            };
            if ((sizing == .budget or sizing == .size_or_budget) and request == 0) return error.InsufficientCapacity;
            if (sizing == .require_size and request == 0) break :blk &.{};
            const buffer = try workspace.take(u8, request);
            break :blk try source.materialize(buffer);
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
        const n = std.Io.Reader.streamRemaining(&bounded.reader, &counter.writer) catch |err| return mapStreamError(err);
        if (n > limits.encoded_bytes) return error.ResourceLimit;
        try source.rewind();
        return n;
    }
    return error.Unsupported;
}

fn mapStreamError(err: anyerror) Failure {
    return switch (err) {
        error.ReadFailed => error.IoFailure,
        error.WriteFailed => error.IoFailure,
        error.EndOfStream => error.IoFailure,
        else => error.InternalFailure,
    };
}

pub fn planOutputSize(source: *Resource, planning: registry.PlanningMode, limits: Limits, workspace: *resource.Workspace) Failure!usize {
    switch (planning) {
        .unavailable => return error.Unsupported,
        .metadata_exact => {
            try source.requireCapability(resource.capability_bit_size);
            const total = try source.size();
            if (total > limits.encoded_bytes) return error.ResourceLimit;
            return std.math.cast(usize, total) orelse error.ResourceLimit;
        },
        .replay_pass => {
            try source.requireCapability(resource.capability_bit_replay);
            const total = try measureOutputSize(source, limits);
            return std.math.cast(usize, total) orelse error.ResourceLimit;
        },
        .bound => return error.Unsupported,
        .bounded_materialization => {
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
    writeDiagnosticScalar(call, registry.ids.diagnostic_required_capacity, required);
    writeDiagnosticScalar(call, registry.ids.diagnostic_available_capacity, available);
}

pub fn writeWorkspaceCapacityDiagnostic(call: *Call, required: u64, available: u64) void {
    writeDiagnosticScalar(call, registry.ids.workspace_required_capacity, required);
    writeDiagnosticScalar(call, registry.ids.workspace_available_capacity, available);
}

pub fn writeDownstreamDiagnostic(call: *Call, status: u32) void {
    writeDiagnosticScalar(call, registry.ids.diagnostic_downstream_status, status);
}

pub fn checkWorkspaceOverlap(call: *Call, src: *Resource, snk: *Resource) Failure!void {
    if (call.workspace == null or call.workspace_capacity == 0) return;
    const ws_ptr = @intFromPtr(call.workspace.?);
    const ws_len = call.workspace_capacity;
    if (src.kind == .direct_read) {
        const ptr = @intFromPtr(src.kind.direct_read.ptr);
        const len = src.kind.direct_read.len;
        if (try spanOverlap(ws_ptr, ws_len, ptr, len)) return error.InvalidCall;
    }
    if (snk.kind == .direct_write) {
        const ptr = @intFromPtr(snk.kind.direct_write.ptr);
        const len = snk.kind.direct_write.len;
        if (try spanOverlap(ws_ptr, ws_len, ptr, len)) return error.InvalidCall;
    }
}

pub fn checkSourceWorkspaceOverlap(call: *Call, src: *Resource) Failure!void {
    if (call.workspace == null or call.workspace_capacity == 0) return;
    if (src.kind != .direct_read) return;
    const ws_ptr = @intFromPtr(call.workspace.?);
    const ws_len = call.workspace_capacity;
    const ptr = @intFromPtr(src.kind.direct_read.ptr);
    const len = src.kind.direct_read.len;
    if (try spanOverlap(ws_ptr, ws_len, ptr, len)) return error.InvalidCall;
}

pub fn validateBoundary(call: *Call, plan: *const ExecutionPlan, source_node: ?*Node, sink_node: ?*Node) Failure!void {
    _ = plan;
    if (call.workspace) |workspace| {
        const ws_ptr = @intFromPtr(workspace);
        const ws_len = call.workspace_capacity;
        if (source_node) |node| {
            if ((node.flags & abi.node_flag_callback_resource) == 0 and node.byte_length != 0) {
                const bytes = try resource.checkedConstBytes(node.bytes, node.byte_length);
                if (try spanOverlap(ws_ptr, ws_len, @intFromPtr(bytes.ptr), bytes.len)) return error.InvalidCall;
            }
        }
        if (sink_node) |node| {
            if ((node.flags & abi.node_flag_callback_resource) == 0 and node.byte_capacity != 0) {
                const bytes = try resource.checkedMutBytes(node.bytes, node.byte_capacity);
                if (try spanOverlap(ws_ptr, ws_len, @intFromPtr(bytes.ptr), bytes.len)) return error.InvalidCall;
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

pub fn checkSourceSinkOverlap(src: *Resource, snk: *Resource) Failure!void {
    if (src.kind != .direct_read or snk.kind != .direct_write) return;
    const src_ptr = @intFromPtr(src.kind.direct_read.ptr);
    const src_len = src.kind.direct_read.len;
    const snk_ptr = @intFromPtr(snk.kind.direct_write.ptr);
    const snk_len = snk.kind.direct_write.len;
    if (try spanOverlap(src_ptr, src_len, snk_ptr, snk_len)) return error.InvalidCall;
}

pub fn sinkCapacity(sink: *Resource) usize {
    return switch (sink.kind) {
        .direct_write => |buf| buf.len,
        .callback_write => std.math.maxInt(usize),
        else => 0,
    };
}

pub fn sinkDirectBuffer(sink: *Resource, required: usize) Failure![]u8 {
    return switch (sink.kind) {
        .direct_write => |buf| if (buf.len >= required) buf[0..required] else return error.InsufficientCapacity,
        else => return error.Unsupported,
    };
}

pub fn mapSinkError(err: Failure, call: *Call, sink: *Resource) Failure {
    if (sink.downstream_status != 0) writeDownstreamDiagnostic(call, sink.downstream_status);
    return err;
}
