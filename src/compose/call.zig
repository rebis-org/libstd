const std = @import("std");

const seam = @import("seam");

const kernel_catalog = @import("../kernel/catalog.zig");
const abi = @import("../kernel/envelope.zig");
const node_graph = @import("../kernel/node.zig");
const resource = @import("../kernel/resource.zig");
const vocabulary = @import("../kernel/vocabulary.zig");
const compose_catalog = @import("catalog.zig");
const common = @import("common.zig");
const hooks = @import("hooks.zig");

const catalog_json = kernel_catalog.catalog_json;
const descriptorFor = kernel_catalog.descriptorFor;
const isKnownId = kernel_catalog.isKnownId;
const Call = abi.Call;
const Id = abi.Id;
const Node = abi.Node;
const Status = abi.Status;
const Limits = resource.Limits;
const Resource = resource.Resource;
const Failure = vocabulary.Failure;
const commandMaskForId = vocabulary.commandMaskForId;
const command_mask_read = vocabulary.command_mask_read;
const command_mask_write = vocabulary.command_mask_write;
const eql = vocabulary.eql;
const ids = vocabulary.ids;
const isZero = vocabulary.isZero;

const MappedFailure = struct { status: u32, id: Id };

fn mapFailure(failure: Failure) MappedFailure {
    inline for (vocabulary.error_map) |entry| if (failure == entry.failure) return .{ .status = entry.status, .id = entry.diagnostic };
    return .{ .status = Status.internal_failure, .id = ids.internal_failure };
}

fn report(call: *Call, failure: Failure) u32 {
    const mapped = mapFailure(failure);
    common.writeDiagnostic(call, mapped.status, mapped.id);
    return mapped.status;
}

// An unsupported request usually names the id it could not place, and that id
// is more actionable than the generic diagnostic the status would otherwise carry.
fn fail(call: *Call, failure: Failure) u32 {
    if (failure == error.UnsupportedFailure) if (unknownRequiredId(call.request)) |id| common.writeDiagnosticId(call, ids.diagnostic_subject, id);
    return report(call, failure);
}

pub fn invoke(call: ?*Call) u32 {
    const envelope = call orelse return Status.invalid_call;
    if (!envelope.isValid()) return if (envelope.structure_size >= @sizeOf(Call)) report(envelope, error.CallFailure) else Status.invalid_call;
    const response = envelope.response orelse return report(envelope, error.CallFailure);
    if (!response.isValid() or !isZero(response.id)) return report(envelope, error.CallFailure);
    if (envelope.diagnostic) |diagnostic| {
        node_graph.validateGraph(diagnostic.child, .out, 0) catch |failure| return mapFailure(failure).status;
    }
    response.value_low = 0;
    response.value_high = 0;
    response.byte_length = 0;
    node_graph.validateGraph(envelope.request, .in, commandMaskForId(envelope.operation)) catch |failure| return fail(envelope, failure);
    node_graph.validateGraph(response.child, .out, 0) catch |failure| return report(envelope, failure);
    if (isZero(envelope.operation)) return writeCatalog(envelope, response);
    dispatch(envelope, response) catch |failure| return fail(envelope, failure);
    return Status.ok;
}

fn writeCatalog(call: *Call, response: *Node) u32 {
    // The length answers before the capacity check so a host that sized its
    // buffer from this call can retry without reading the diagnostics.
    response.byte_length = catalog_json.len;
    if (response.byte_capacity < catalog_json.len) {
        common.writeCapacityDiagnostic(call, catalog_json.len, response.byte_capacity);
        return Status.insufficient_capacity;
    }
    const output = response.bytes orelse return report(call, error.CallFailure);
    @memcpy(output[0..catalog_json.len], catalog_json);
    return Status.ok;
}

fn dispatch(envelope: *Call, response: *Node) Failure!void {
    const command_mask = commandMaskForId(envelope.operation);
    if (command_mask == 0) return error.UnsupportedFailure;
    const profile_id = nodeId(try requireParameter(envelope.request, ids.profile));
    const profile = descriptorFor(profile_id) orelse return error.UnsupportedFailure;
    if (profile.kind != .profile or (profile.command_mask & command_mask) == 0) return error.UnsupportedFailure;
    const tag = compose_catalog.profileTagForId(profile_id) orelse return error.UnsupportedFailure;
    const is_query = eql(envelope.operation, ids.query);
    const direction = if (is_query)
        try queryDirection(envelope.request)
    else
        command_mask;
    const policy = compose_catalog.commandPolicyFor(profile_id, direction) orelse return error.UnsupportedFailure;
    const sizing = try parseSizingMode(
        protocolParam(envelope.request, vocabulary.protocol_parameter.sizing_mode),
        policy.sizing,
    );
    const commit = try parseCommitMode(
        protocolParam(envelope.request, vocabulary.protocol_parameter.commit_mode),
        policy.commit,
    );
    // Fixtures run every sizing and commit pairing; released profiles do not.
    if (tag != .test_echo and tag != .test_read and (sizing != policy.sizing or commit != policy.commit)) return error.UnsupportedFailure;
    // size_bound only opts measured writes into bounded sizing. Other targets map to unsupported as parameter misuse.
    const effective_sizing = if (node_graph.findParameter(envelope.request, ids.size_bound) == null) sizing else bounded: {
        if (policy.sizing != .measured or direction != command_mask_write) return error.UnsupportedFailure;
        break :bounded vocabulary.SizingMode.bounded;
    };
    const limits = Limits.fromScalar(node_graph.parseU64(protocolParam(
        envelope.request,
        vocabulary.protocol_parameter.resource_limit,
    )));
    const capabilities = parseCapabilities(protocolParam(
        envelope.request,
        vocabulary.protocol_parameter.resource_capabilities,
    ));
    const source_node = try requireParameter(envelope.request, ids.source);
    const sink_node = if (is_query) null else try requireParameter(envelope.request, ids.sink);
    var plan = common.ExecutionPlan{
        .profile_id = profile_id,
        .policy = policy,
        .limits = limits,
        .capabilities = capabilities,
        .provider = try parseProvider(protocolParam(
            envelope.request,
            vocabulary.protocol_parameter.provider,
        )),
        .source_strategy = switch (policy.sizing) {
            .metadata_exact => .require_size,
            else => if (policy.sizing == .materialization or policy.sizing == .unavailable) .budget else .replay,
        },
        .workspace_plan = resource.WorkspacePlan.init(envelope.workspace),
        .workspace_available = std.math.cast(usize, envelope.workspace_capacity) orelse std.math.maxInt(usize),
    };
    try common.validateBoundary(envelope, &plan, source_node, sink_node);
    var source = try Resource.sourceFromNode(envelope, source_node, capabilities);
    var sink: ?Resource = if (sink_node) |node| try Resource.sinkFromNode(envelope, node, capabilities) else null;
    const selected = if (is_query) &source else if (direction == command_mask_read) &source else if (sink) |*sink_resource| sink_resource else return error.CallFailure;
    if ((selected.capabilities & policy.capabilities) != policy.capabilities) return error.UnsupportedFailure;
    if (effective_sizing == .unavailable) return error.UnsupportedFailure;
    // Workspace requirement must be reported on every exit path, success or failure.
    defer if (plan.workspace_required != 0)
        common.writeWorkspaceCapacityDiagnostic(envelope, plan.workspace_required, plan.workspace_available);
    try hooks.dispatchToProfileHook(profile.id, &plan, &source, if (sink) |*sink_resource| sink_resource else null, envelope, response, effective_sizing, commit, limits, direction);
}

// A query names the direction it measures, so the direction is resolved from
// the request before any policy or capability question is asked.
fn queryDirection(request: ?*Node) Failure!u32 {
    const direction = commandMaskForId(nodeId(try requireParameter(request, ids.target_command)));
    if (direction != command_mask_read and direction != command_mask_write) return error.CallFailure;
    return direction;
}

fn unknownRequiredId(first: ?*Node) ?Id {
    var remaining: usize = 1024;
    return unknownRequiredIdInGraph(first, 0, &remaining);
}

fn unknownRequiredIdInGraph(first: ?*Node, depth: u16, remaining: *usize) ?Id {
    if (depth == 128) return null;
    var cursor = first;
    while (cursor) |node| : (cursor = node.next) {
        if (remaining.* == 0) return null;
        remaining.* -= 1;
        if (!isKnownId(node.id) and (node.flags & abi.node_flag_optional) == 0) return node.id;
        if (unknownRequiredIdInGraph(node.child, depth + 1, remaining)) |id| return id;
    }
    return null;
}

fn requireParameter(first: ?*Node, id: Id) Failure!*Node {
    return node_graph.findParameter(first, id) orelse error.CallFailure;
}

fn nodeId(node: *Node) Id {
    return .{ .low = node.value_low, .high = node.value_high };
}

fn protocolParam(request: ?*Node, comptime field: u32) ?*Node {
    return node_graph.findSelector(request, vocabulary.parameter_family_protocol, field);
}

fn parseCapabilities(node: ?*Node) u32 {
    const present = node orelse return 0;
    return @truncate(present.value_low);
}

fn parseSizingMode(node: ?*Node, default: vocabulary.SizingMode) Failure!vocabulary.SizingMode {
    const present = node orelse return default;
    return switch (present.value_low) {
        0 => .unavailable,
        1 => .metadata_exact,
        2 => .measured,
        3 => .materialization,
        else => error.CallFailure,
    };
}

fn parseCommitMode(node: ?*Node, default: vocabulary.CommitMode) Failure!vocabulary.CommitMode {
    const present = node orelse return default;
    return switch (present.value_low) {
        0 => .tentative,
        1 => .confirmed,
        else => error.CallFailure,
    };
}

fn parseProvider(node: ?*Node) Failure!seam.Provider {
    const present = node orelse return seam.default_provider;
    const provider: seam.Provider = switch (present.value_low) {
        0 => .onprem,
        1 => .offprem,
        else => return error.CallFailure,
    };
    if (!seam.isServed(provider)) return error.UnsupportedFailure;
    return provider;
}
