const std = @import("std");

const node_graph = @import("../kernel/node.zig");
const resource = @import("../kernel/resource.zig");
const Resource = resource.Resource;
const Limits = resource.Limits;
const kernel_catalog = @import("../kernel/catalog.zig");
const knownId = kernel_catalog.knownId;
const descriptorFor = kernel_catalog.descriptorFor;
const catalog_json = @import("../kernel/catalog.zig").catalog_json;
const abi = @import("../kernel/envelope.zig");
const Id = abi.Id;
const Status = abi.Status;
const Node = abi.Node;
const Call = abi.Call;
const vocabulary = @import("../kernel/vocabulary.zig");
const Failure = vocabulary.Failure;
const ids = vocabulary.ids;
const idEqual = vocabulary.idEqual;
const idIsZero = vocabulary.idIsZero;
const commandMaskForId = vocabulary.commandMaskForId;
const command_mask_query = vocabulary.command_mask_query;
const command_mask_read = vocabulary.command_mask_read;
const command_mask_write = vocabulary.command_mask_write;
const common = @import("common.zig");
const compose_catalog = @import("catalog.zig");
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
    const command_mask = commandMaskForId(envelope.operation);
    node_graph.validateGraph(envelope.request, .in, command_mask) catch |failure| {
        const mapped = mapFailure(failure);
        if (failure == error.Unsupported) if (unknownRequired(envelope.request)) |id| common.writeDiagnosticId(envelope, ids.diagnostic_subject, id);
        common.writeDiagnostic(envelope, mapped.status, mapped.id);
        return mapped.status;
    };
    node_graph.validateGraph(response.child, .out, 0) catch |failure| {
        const mapped = mapFailure(failure);
        common.writeDiagnostic(envelope, mapped.status, mapped.id);
        return mapped.status;
    };
    if (idIsZero(envelope.operation)) return writeCatalog(envelope, response);
    dispatch(envelope, response) catch |failure| {
        const mapped = mapFailure(failure);
        if (failure == error.Unsupported) if (unknownRequired(envelope.request)) |id| common.writeDiagnosticId(envelope, ids.diagnostic_subject, id);
        common.writeDiagnostic(envelope, mapped.status, mapped.id);
        return mapped.status;
    };
    return Status.ok;
}

fn writeCatalog(call: *Call, response: *Node) u32 {
    response.byte_length = catalog_json.len;
    if (response.byte_capacity < catalog_json.len) {
        common.writeCapacityDiagnostic(call, catalog_json.len, response.byte_capacity);
        return Status.insufficient_capacity;
    }
    const output = response.bytes orelse {
        common.writeDiagnostic(call, Status.invalid_call, ids.invalid_call);
        return Status.invalid_call;
    };
    @memcpy(output[0..catalog_json.len], catalog_json);
    return Status.ok;
}

fn dispatch(envelope: *Call, response: *Node) Failure!void {
    const command_id = envelope.operation;
    const command_mask = commandMaskForId(command_id);
    if (command_mask == 0) return error.Unsupported;
    const profile_node = try requireParameter(envelope.request, ids.profile);
    const profile_id = parseId(profile_node);
    const profile = descriptorFor(profile_id) orelse return error.Unsupported;
    if (profile.kind != .profile or (profile.command_mask & command_mask) == 0) return error.Unsupported;
    const tag = compose_catalog.profileTagForId(profile_id) orelse return error.Unsupported;
    const is_query = idEqual(command_id, ids.query);
    var effective_command_mask = command_mask;
    if (is_query) {
        const target_node = try requireParameter(envelope.request, ids.target_command);
        const effective_command_id = parseId(target_node);
        effective_command_mask = commandMaskForId(effective_command_id);
        if (effective_command_mask != command_mask_read and effective_command_mask != command_mask_write) return error.InvalidCall;
    }
    const policy = compose_catalog.commandPolicyFor(
        profile_id,
        if (is_query) command_mask_query else effective_command_mask,
        if (is_query) effective_command_mask else 0,
    ) orelse return error.Unsupported;
    const sizing = try parseSizingMode(
        node_graph.findSelector(envelope.request, vocabulary.parameter_family_protocol, vocabulary.protocol_parameter.sizing_mode),
        policy.sizing,
    );
    const commit = try parseCommitMode(
        node_graph.findSelector(envelope.request, vocabulary.parameter_family_protocol, vocabulary.protocol_parameter.commit_mode),
        policy.commit,
    );
    const strict_modes = tag != .test_echo and tag != .test_read;
    if (strict_modes) {
        if (sizing != policy.sizing) return error.Unsupported;
        if (commit != policy.commit) return error.Unsupported;
    }
    // size_bound only opts measured writes into bounded sizing; other targets map to unsupported as parameter misuse.
    var effective_sizing = sizing;
    if (node_graph.findParameter(envelope.request, ids.size_bound) != null) {
        if (policy.sizing != .measured or effective_command_mask != command_mask_write) return error.Unsupported;
        effective_sizing = .bounded;
    }
    const limits = Limits.fromScalar(node_graph.parseU64(node_graph.findSelector(
        envelope.request,
        vocabulary.parameter_family_protocol,
        vocabulary.protocol_parameter.resource_limit,
    )));
    const capabilities = parseCapabilities(node_graph.findSelector(
        envelope.request,
        vocabulary.parameter_family_protocol,
        vocabulary.protocol_parameter.resource_capabilities,
    ));
    const source_node = try requireParameter(envelope.request, ids.source);
    const sink_node = if (is_query) null else try requireParameter(envelope.request, ids.sink);
    var plan = common.ExecutionPlan{
        .invocation = if (is_query) .query else if (effective_command_mask == command_mask_read) .read else .write,
        .profile_id = profile_id,
        .target_command = if (is_query) parseId(try requireParameter(envelope.request, ids.target_command)) else null,
        .policy = policy,
        .limits = limits,
        .capabilities = capabilities,
        .source_strategy = switch (policy.sizing) {
            .metadata_exact => .require_size,
            .measured => .replay,
            .materialization => .budget,
            .unavailable => .budget,
            .bounded => .replay,
        },
        .workspace_plan = resource.WorkspacePlan.init(envelope.workspace),
        .workspace_available = std.math.cast(usize, envelope.workspace_capacity) orelse std.math.maxInt(usize),
    };
    try common.validateBoundary(envelope, &plan, source_node, sink_node);
    var source = try Resource.sourceFromNode(envelope, source_node, capabilities);
    var sink: ?Resource = if (sink_node) |node| try Resource.sinkFromNode(envelope, node, capabilities) else null;
    const primary = if (is_query) &source else if (effective_command_mask == command_mask_read) &source else if (sink) |*sink_resource| sink_resource else return error.InvalidCall;
    if ((primary.capabilities & policy.capabilities) != policy.capabilities) return error.Unsupported;
    if (effective_sizing == .unavailable) return error.Unsupported;
    // Workspace requirement must be reported on every exit path, success or failure.
    defer if (plan.workspace_required != 0)
        common.writeWorkspaceCapacityDiagnostic(envelope, plan.workspace_required, plan.workspace_available);
    try hooks.dispatchToProfileHook(profile.id, &plan, &source, if (sink) |*sink_resource| sink_resource else null, envelope, response, effective_sizing, commit, limits, effective_command_mask);
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
    const present_node = node orelse return 0;
    return @truncate(present_node.value_low);
}

fn parseSizingMode(node: ?*Node, default: vocabulary.SizingMode) Failure!vocabulary.SizingMode {
    const present_node = node orelse return default;
    return switch (present_node.value_low) {
        0 => .unavailable,
        1 => .metadata_exact,
        2 => .measured,
        3 => .materialization,
        else => error.InvalidCall,
    };
}

fn parseCommitMode(node: ?*Node, default: vocabulary.CommitMode) Failure!vocabulary.CommitMode {
    const present_node = node orelse return default;
    return switch (present_node.value_low) {
        0 => .tentative,
        1 => .confirmed,
        else => error.InvalidCall,
    };
}

const MappedFailure = struct { status: u32, id: Id };

fn mapFailure(failure: Failure) MappedFailure {
    inline for (vocabulary.error_map) |entry| if (failure == entry.failure) return .{ .status = entry.status, .id = entry.diagnostic };
    return .{ .status = Status.internal_failure, .id = ids.internal_failure };
}
