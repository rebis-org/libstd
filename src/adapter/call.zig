const std = @import("std");

const abi = @import("../abi/contract.zig");
const Id = abi.Id;
const Status = abi.Status;
const Node = abi.Node;
const Call = abi.Call;
const registry = @import("../catalog/registry.zig");
const Failure = registry.Failure;
const ids = registry.ids;
const idEqual = registry.idEqual;
const idIsZero = registry.idIsZero;
const knownId = registry.knownId;
const descriptorFor = registry.descriptorFor;
const commandBit = registry.commandBit;
const command_mask_query = registry.command_mask_query;
const command_mask_read = registry.command_mask_read;
const command_mask_write = registry.command_mask_write;
const catalog = @import("../catalog/render.zig").catalog;
const node_graph = @import("../common/node.zig");
const resource = @import("../common/resource.zig");
const Resource = resource.Resource;
const Limits = resource.Limits;
const common = @import("common.zig");
const hooks = @import("hooks.zig");

pub fn invoke(call: ?*Call) u32 {
    const envelope = call orelse return Status.invalid_call;
    if (!envelope.valid()) {
        if (envelope.structure_size >= @sizeOf(Call)) common.writeDiagnostic(envelope, Status.invalid_call, ids.invalid_call);
        return Status.invalid_call;
    }
    const response = envelope.response orelse {
        common.writeDiagnostic(envelope, Status.invalid_call, ids.invalid_call);
        return Status.invalid_call;
    };
    if (!response.valid() or !idIsZero(response.id)) {
        common.writeDiagnostic(envelope, Status.invalid_call, ids.invalid_call);
        return Status.invalid_call;
    }
    if (envelope.diagnostic) |diagnostic| {
        node_graph.validateGraph(diagnostic.child, .out, 0) catch |err| {
            return mapFailure(err).status;
        };
    }
    response.value_low = 0;
    response.value_high = 0;
    response.byte_length = 0;
    const command_mask = commandBit(envelope.operation);
    node_graph.validateGraph(envelope.request, .in, command_mask) catch |err| {
        const mapped = mapFailure(err);
        if (err == error.Unsupported) if (unknownRequired(envelope.request)) |id| common.writeDiagnosticId(envelope, ids.diagnostic_subject, id);
        common.writeDiagnostic(envelope, mapped.status, mapped.id);
        return mapped.status;
    };
    node_graph.validateGraph(response.child, .out, 0) catch |err| {
        const mapped = mapFailure(err);
        common.writeDiagnostic(envelope, mapped.status, mapped.id);
        return mapped.status;
    };
    if (idIsZero(envelope.operation)) return writeCatalog(envelope, response);
    dispatch(envelope, response) catch |err| {
        const mapped = mapFailure(err);
        if (err == error.Unsupported) if (unknownRequired(envelope.request)) |id| common.writeDiagnosticId(envelope, ids.diagnostic_subject, id);
        common.writeDiagnostic(envelope, mapped.status, mapped.id);
        return mapped.status;
    };
    return Status.ok;
}

fn writeCatalog(call: *Call, response: *Node) u32 {
    response.byte_length = catalog.len;
    if (response.byte_capacity < catalog.len) {
        common.writeCapacityDiagnostic(call, catalog.len, response.byte_capacity);
        return Status.insufficient_capacity;
    }
    const output = response.bytes orelse {
        common.writeDiagnostic(call, Status.invalid_call, ids.invalid_call);
        return Status.invalid_call;
    };
    @memcpy(output[0..catalog.len], catalog);
    return Status.ok;
}

fn dispatch(envelope: *Call, response: *Node) Failure!void {
    const command_id = envelope.operation;
    const command_bit = commandBit(command_id);
    if (command_bit == 0) return error.Unsupported;
    const profile_node = try requireParameter(envelope.request, ids.profile);
    const profile_id = parseId(profile_node);
    const profile = descriptorFor(profile_id) orelse return error.Unsupported;
    if (profile.kind != .profile or (profile.command_mask & command_bit) == 0) return error.Unsupported;
    if (registry.tagFor(profile_id) == null) return error.Unsupported;
    var effective_command_bit = command_bit;
    if (idEqual(command_id, ids.query)) {
        const target_node = try requireParameter(envelope.request, ids.target_command);
        const effective_command_id = parseId(target_node);
        effective_command_bit = commandBit(effective_command_id);
        if (effective_command_bit != command_mask_read and effective_command_bit != command_mask_write) return error.InvalidCall;
    }
    const policy = registry.commandPolicyFor(
        profile_id,
        if (idEqual(command_id, ids.query)) command_mask_query else effective_command_bit,
        if (idEqual(command_id, ids.query)) effective_command_bit else 0,
    ) orelse return error.Unsupported;
    const planning = try parsePlanningMode(
        node_graph.findSelector(envelope.request, registry.parameter_family_protocol, registry.protocol_parameter.planning_mode),
        policy.planning,
    );
    const delivery = try parseDeliveryMode(
        node_graph.findSelector(envelope.request, registry.parameter_family_protocol, registry.protocol_parameter.delivery_mode),
        policy.delivery,
    );
    const strict_modes = registry.tagFor(profile_id) != .test_echo and registry.tagFor(profile_id) != .test_read_only;
    if (strict_modes) {
        if (planning != policy.planning) return error.Unsupported;
        if (delivery != policy.delivery) return error.Unsupported;
    }
    // Bound planning is bound to the released replay_pass policies; anywhere
    // else (read target, archive/test profile) it is unsupported, matching
    // the existing parameter-misuse mapping.
    var effective_planning = planning;
    if (node_graph.findParameter(envelope.request, ids.planning_bound) != null) {
        if (policy.planning != .replay_pass or effective_command_bit != command_mask_write) return error.Unsupported;
        effective_planning = .bound;
    }
    const limits = Limits.fromScalar(node_graph.parseU64(node_graph.findSelector(
        envelope.request,
        registry.parameter_family_protocol,
        registry.protocol_parameter.resource_limit,
    )));
    const capabilities = parseCapabilities(node_graph.findSelector(
        envelope.request,
        registry.parameter_family_protocol,
        registry.protocol_parameter.resource_capabilities,
    ));
    const source_node = try requireParameter(envelope.request, ids.source);
    const sink_node = if (idEqual(command_id, ids.query)) null else try requireParameter(envelope.request, ids.sink);
    var plan = common.ExecutionPlan{
        .invocation = if (idEqual(command_id, ids.query)) .query else if (effective_command_bit == command_mask_read) .read else .write,
        .profile_id = profile_id,
        .target_command = if (idEqual(command_id, ids.query)) parseId(try requireParameter(envelope.request, ids.target_command)) else null,
        .policy = policy,
        .limits = limits,
        .capabilities = capabilities,
        .source_strategy = switch (policy.planning) {
            .metadata_exact => .require_size,
            .replay_pass => .replay,
            .bounded_materialization => .budget,
            .unavailable => .budget,
            .bound => .replay,
        },
        .workspace_plan = resource.WorkspacePlan.init(envelope.workspace),
        .workspace_available = std.math.cast(usize, envelope.workspace_capacity) orelse std.math.maxInt(usize),
    };
    try common.validateBoundary(envelope, &plan, source_node, sink_node);
    var source = try Resource.sourceFromNode(envelope, source_node, capabilities);
    var sink: ?Resource = if (sink_node) |node| try Resource.sinkFromNode(envelope, node, capabilities) else null;
    const primary = if (idEqual(command_id, ids.query)) &source else if (effective_command_bit == command_mask_read) &source else if (sink) |*snk| snk else return error.InvalidCall;
    if ((primary.capabilities & policy.capabilities) != policy.capabilities) return error.Unsupported;
    if (effective_planning == .unavailable) return error.Unsupported;
    hooks.dispatch(profile.id, &plan, &source, if (sink) |*snk| snk else null, envelope, response, effective_planning, delivery, limits, effective_command_bit) catch |err| {
        if (plan.workspace_required != 0) common.writeWorkspaceCapacityDiagnostic(envelope, plan.workspace_required, plan.workspace_available);
        return err;
    };
    if (plan.workspace_required != 0) common.writeWorkspaceCapacityDiagnostic(envelope, plan.workspace_required, plan.workspace_available);
}

fn unknownRequired(first: ?*Node) ?Id {
    var remaining: usize = 1024;
    return unknownRequiredInGraph(first, 0, &remaining);
}

fn unknownRequiredInGraph(first: ?*Node, depth: u16, remaining: *usize) ?Id {
    if (depth == 128) return null;
    var cursor = first;
    while (cursor) |node| : (cursor = node.next) {
        if (remaining.* == 0) return null;
        remaining.* -= 1;
        if (!knownId(node.id) and (node.flags & abi.node_flag_optional) == 0) return node.id;
        if (unknownRequiredInGraph(node.child, depth + 1, remaining)) |id| return id;
    }
    return null;
}

fn requireParameter(first: ?*Node, id: Id) Failure!*Node {
    return node_graph.findParameter(first, id) orelse error.InvalidCall;
}

fn parseId(node: *Node) Id {
    return .{ .low = node.value_low, .high = node.value_high };
}

fn parseCapabilities(node: ?*Node) u32 {
    const n = node orelse return 0;
    return @truncate(n.value_low);
}

fn parsePlanningMode(node: ?*Node, default: registry.PlanningMode) Failure!registry.PlanningMode {
    const n = node orelse return default;
    return switch (n.value_low) {
        0 => .unavailable,
        1 => .metadata_exact,
        2 => .replay_pass,
        3 => .bounded_materialization,
        else => error.InvalidCall,
    };
}

fn parseDeliveryMode(node: ?*Node, default: registry.DeliveryMode) Failure!registry.DeliveryMode {
    const n = node orelse return default;
    return switch (n.value_low) {
        0 => .provisional,
        1 => .verified,
        else => error.InvalidCall,
    };
}

const MappedFailure = struct { status: u32, id: Id };

fn mapFailure(failure: Failure) MappedFailure {
    inline for (registry.error_map) |entry| if (failure == entry.failure) return .{ .status = entry.status, .id = entry.diagnostic };
    return .{ .status = Status.internal_failure, .id = ids.internal_failure };
}
