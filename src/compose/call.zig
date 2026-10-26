const std = @import("std");

const seam = @import("seam");

const kernel_catalog = @import("../kernel/catalog.zig");
const abi = @import("../kernel/envelope.zig");
const node_graph = @import("../kernel/node.zig");
const resource = @import("../kernel/resource.zig");
const vocabulary = @import("../kernel/vocabulary.zig");
const compose_catalog = @import("catalog.zig");
const common = @import("common.zig");
const executor = @import("executor.zig");
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
const Exception = vocabulary.Exception;
const commandMaskForId = vocabulary.commandMaskForId;
const command_mask_read = vocabulary.command_mask_read;
const command_mask_write = vocabulary.command_mask_write;
const eql = vocabulary.eql;
const ids = vocabulary.ids;
const isZero = vocabulary.isZero;

const MappedException = struct { status: u32, id: Id };

fn mapException(exception: Exception) MappedException {
    inline for (vocabulary.error_map) |entry| if (exception == entry.exception) return .{ .status = entry.status, .id = entry.diagnostic };
    return .{ .status = Status.internal_failure, .id = ids.internal_failure };
}

fn report(call: *Call, exception: Exception) u32 {
    const mapped = mapException(exception);
    common.writeDiagnostic(call, mapped.status, mapped.id);
    return mapped.status;
}

// The unplaced id an unsupported request usually names is more
// actionable than the generic diagnostic.
fn fail(call: *Call, exception: Exception) u32 {
    if (exception == error.UnsupportedException) if (unknownRequiredId(call.request)) |id| common.writeDiagnosticId(call, ids.diagnostic_subject, id);
    return report(call, exception);
}

// stdk_call stays synchronous: the envelope runs on the inline executor.
// stdk_submit routes the same envelope through a caller-selected executor.
pub fn invoke(call: ?*Call) u32 {
    const envelope = call orelse return Status.invalid_call;
    return run(envelope, executor.inline_executor);
}

pub fn run(envelope: *Call, exec: executor.Executor) u32 {
    return exec.run(.{ .context = envelope, .invoke = runTask });
}

fn runTask(context: *anyopaque) callconv(.c) u32 {
    const envelope: *Call = @ptrCast(@alignCast(context));
    return runInner(envelope);
}

fn runInner(envelope: *Call) u32 {
    if (!envelope.isValid()) return if (envelope.structure_size >= @sizeOf(Call)) report(envelope, error.CallException) else Status.invalid_call;
    const response = envelope.response orelse return report(envelope, error.CallException);
    if (!response.isValid() or !isZero(response.id)) return report(envelope, error.CallException);
    if (envelope.diagnostic) |diagnostic| {
        node_graph.validateGraph(diagnostic.child, .out, 0) catch |exception| return mapException(exception).status;
    }
    response.value_low = 0;
    response.value_high = 0;
    response.byte_length = 0;
    node_graph.validateGraph(envelope.request, .in, commandMaskForId(envelope.operation)) catch |exception| return fail(envelope, exception);
    node_graph.validateGraph(response.child, .out, 0) catch |exception| return report(envelope, exception);
    if (isZero(envelope.operation)) return writeCatalog(envelope, response);
    dispatch(envelope, response) catch |exception| return fail(envelope, exception);
    return Status.ok;
}

fn writeCatalog(call: *Call, response: *Node) u32 {
    // The length answers before the capacity check, so hosts can size a
    // retry buffer without reading diagnostics.
    response.byte_length = catalog_json.len;
    if (response.byte_capacity < catalog_json.len) {
        common.writeCapacityDiagnostic(call, catalog_json.len, response.byte_capacity);
        return Status.insufficient_capacity;
    }
    const output = response.bytes orelse return report(call, error.CallException);
    @memcpy(output[0..catalog_json.len], catalog_json);
    return Status.ok;
}

fn dispatch(envelope: *Call, response: *Node) Exception!void {
    const command_mask = commandMaskForId(envelope.operation);
    if (command_mask == 0) return error.UnsupportedException;
    const profile_id = nodeId(try requireParameter(envelope.request, ids.profile));
    const profile = descriptorFor(profile_id) orelse return error.UnsupportedException;
    if (profile.kind != .profile or (profile.command_mask & command_mask) == 0) return error.UnsupportedException;
    const tag = compose_catalog.profileTagForId(profile_id) orelse return error.UnsupportedException;
    const is_query = eql(envelope.operation, ids.query);
    const direction = if (is_query)
        try queryDirection(envelope.request)
    else
        command_mask;
    const policy = compose_catalog.commandPolicyFor(profile_id, direction) orelse return error.UnsupportedException;
    const sizing = try parseSizingMode(
        protocolParam(envelope.request, vocabulary.protocol_parameter.sizing_mode),
        policy.sizing,
    );
    const commit = try parseCommitMode(
        protocolParam(envelope.request, vocabulary.protocol_parameter.commit_mode),
        policy.commit,
    );
    // Fixtures run every sizing and commit pairing; released profiles do not.
    if (tag != .test_echo and tag != .test_read and (sizing != policy.sizing or commit != policy.commit)) return error.UnsupportedException;
    // size_bound only opts measured writes into bounded sizing. Other targets map to unsupported as parameter misuse.
    const effective_sizing = if (node_graph.findParameter(envelope.request, ids.size_bound) == null) sizing else bounded: {
        if (policy.sizing != .measured or direction != command_mask_write) return error.UnsupportedException;
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
    const plan = common.ExecutionPlan{
        .profile_id = profile_id,
        .policy = policy,
        .sizing = effective_sizing,
        .commit = commit,
        .command_mask = direction,
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
    try common.validateBoundary(envelope, source_node, sink_node);
    var source = try Resource.sourceFromNode(envelope, source_node, capabilities);
    var sink: ?Resource = if (sink_node) |node| try Resource.sinkFromNode(envelope, node, capabilities) else null;
    const selected = if (is_query) &source else if (direction == command_mask_read) &source else if (sink) |*sink_resource| sink_resource else return error.CallException;
    if ((selected.capabilities & policy.capabilities) != policy.capabilities) return error.UnsupportedException;
    if (effective_sizing == .unavailable) return error.UnsupportedException;
    var invocation = common.Invocation{
        .plan = plan,
        .source = &source,
        .sink = if (sink) |*sink_resource| sink_resource else null,
        .call = envelope,
        .response = response,
    };
    // Workspace requirement must be reported on every exit path, success or exception.
    defer if (invocation.plan.workspace_required != 0)
        common.writeWorkspaceCapacityDiagnostic(envelope, invocation.plan.workspace_required, invocation.plan.workspace_available);
    try hooks.dispatchToProfileHook(profile.id, &invocation);
}

// A query names the direction it measures; resolution precedes
// every policy or capability check.
fn queryDirection(request: ?*Node) Exception!u32 {
    const direction = commandMaskForId(nodeId(try requireParameter(request, ids.target_command)));
    if (direction != command_mask_read and direction != command_mask_write) return error.CallException;
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

fn requireParameter(first: ?*Node, id: Id) Exception!*Node {
    return node_graph.findParameter(first, id) orelse error.CallException;
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

fn parseSizingMode(node: ?*Node, default: vocabulary.SizingMode) Exception!vocabulary.SizingMode {
    const present = node orelse return default;
    return switch (present.value_low) {
        0 => .unavailable,
        1 => .metadata_exact,
        2 => .measured,
        3 => .materialization,
        else => error.CallException,
    };
}

fn parseCommitMode(node: ?*Node, default: vocabulary.CommitMode) Exception!vocabulary.CommitMode {
    const present = node orelse return default;
    return switch (present.value_low) {
        0 => .tentative,
        1 => .confirmed,
        else => error.CallException,
    };
}

fn parseProvider(node: ?*Node) Exception!seam.Provider {
    const present = node orelse return seam.default_provider;
    const provider: seam.Provider = switch (present.value_low) {
        0 => .onprem,
        1 => .offprem,
        else => return error.CallException,
    };
    if (!seam.isServed(provider)) return error.UnsupportedException;
    return provider;
}
