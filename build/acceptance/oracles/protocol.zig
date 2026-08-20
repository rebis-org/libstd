const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const harness = @import("harness.zig");
const Runner = harness.Runner;

fn setup(r: *Runner) !void {
    harness.setup(r, harness.ids.test_echo, harness.mode_protocol);
    corpus.select(r.corpus_index, r.corpus_buffer[0..]);
    r.input = r.corpus_buffer[0..];
}

fn discoveryCapacity(r: *Runner) !void {
    var small_buffer = [_]u8{0xa5} ** 4;
    var required: harness.Node = undefined;
    var available: harness.Node = undefined;
    var diagnostic: harness.Node = undefined;
    harness.capacityDiagnostics(&required, &available, &diagnostic);
    var discovery_response = harness.node(&small_buffer, small_buffer.len);
    r.status = harness.invoke(
        .{ .low = 0, .high = 0 },
        null,
        &discovery_response,
        r.workspace.ptr,
        r.workspace.len,
        null,
        null,
        &diagnostic,
    );
    try harness.requireStatus(r, abi.Status.insufficient_capacity);
    if (!harness.allBytesEqual(&small_buffer, 0xa5)) return error.DiscoveryChangedBuffer;
    if (required.value_low == 0) return error.DiscoveryRequiredMissing;
    if (available.value_low != small_buffer.len) return error.DiscoveryAvailableMismatch;
}

fn unknownId(r: *Runner) !void {
    var unknown = harness.node(null, 0);
    unknown.id = .{ .low = 1, .high = 1 };
    var subject = harness.scalarNode(harness.ids.diagnostic_subject);
    var diagnostic = harness.node(null, 0);
    diagnostic.child = &subject;
    r.response = harness.node(null, 0);
    r.status = harness.invoke(harness.ids.read, &unknown, &r.response, r.workspace.ptr, r.workspace.len, null, null, &diagnostic);
    try harness.requireStatus(r, abi.Status.unsupported);
    if (subject.value_low != unknown.id.low or subject.value_high != unknown.id.high) return error.UnknownIdDiagnosticMismatch;
}

fn duplicateSource(r: *Runner) !void {
    var first_source = harness.scalarNode(harness.ids.source);
    var second_source = harness.scalarNode(harness.ids.source);
    first_source.next = &second_source;
    r.response = harness.node(null, 0);
    r.response.value_low = 0xff;
    r.response.value_high = 0xff;
    r.response.byte_length = 0xff;
    r.status = harness.invoke(harness.ids.read, &first_source, &r.response, r.workspace.ptr, r.workspace.len, null, null, null);
    try harness.requireStatus(r, abi.Status.invalid_call);
    if (r.response.value_low != 0 or r.response.value_high != 0 or r.response.byte_length != 0) return error.DuplicateSourceResponseNotCleared;
}

fn echoReadSpan(r: *Runner) !void {
    var output = [_]u8{0xa5} ** 64;
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(r.input),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != r.input.len or !std.mem.eql(u8, output[0..r.input.len], r.input)) return error.EchoReadSpanMismatch;
}

fn echoWriteSpan(r: *Runner) !void {
    var output = [_]u8{0xa5} ** 64;
    _ = harness.call(r, harness.ids.write, &.{
        harness.sourceSpan(r.input),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != r.input.len or !std.mem.eql(u8, output[0..r.input.len], r.input)) return error.EchoWriteSpanMismatch;
}

fn echoCallbackSource(r: *Runner) !void {
    var output = [_]u8{0xa5} ** 64;
    var source_ctx = harness.SourceCallbackContext{ .data = r.input };
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceCallbackNode(0, 0),
        harness.sinkSpan(&output),
    }, .{ .ctx = true, .callback = harness.sourceCallback, .context = &source_ctx });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != r.input.len or !std.mem.eql(u8, output[0..r.input.len], r.input)) return error.EchoCallbackSourceMismatch;
}

fn capabilityReject(r: *Runner) !void {
    var output = [_]u8{0xa5} ** 16;
    try harness.reject(r, harness.ids.read, &.{
        harness.sourceCallbackNode(0, 0),
        harness.sinkSpan(&output),
        harness.cap(harness.cap_read),
        harness.pln(harness.plan_metadata_exact),
    }, .{}, abi.Status.unsupported, &output);
}

fn capacityReject(r: *Runner) !void {
    const input = "too long";
    var output = [_]u8{0xa5} ** 4;
    try harness.expectCapacity(r, harness.ids.read, &.{
        harness.sourceSpan(input),
        harness.sinkSpan(&output),
    }, .{ .ctx = true }, harness.ids.diagnostic_required_capacity, harness.ids.diagnostic_available_capacity, input.len, output.len, &output);
}

fn integrityReject(r: *Runner) !void {
    const input = [_]u8{ 'a', 'b', 'c', 0xff };
    var output = [_]u8{0xa5} ** 16;
    try harness.reject(r, harness.ids.read, &.{
        harness.sourceSpan(&input),
        harness.sinkSpan(&output),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay | harness.cap_seek | harness.cap_range),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_verified),
    }, .{}, abi.Status.integrity_failure, &output);
}

fn limitReject(r: *Runner) !void {
    const input = "limited";
    var output = [_]u8{0xa5} ** 16;
    try harness.reject(r, harness.ids.read, &.{
        harness.sourceSpan(input),
        harness.sinkSpan(&output),
        harness.lim(2),
    }, .{ .ctx = true }, abi.Status.resource_limit, &output);
}

fn callbackDownstream(r: *Runner) !void {
    const input = "partial";
    var callback_ctx = harness.SinkCallbackContext{ .fail_after = 5 };
    var downstream = harness.scalarNode(harness.ids.diagnostic_downstream_status);
    var diagnostic = harness.node(null, 0);
    diagnostic.child = &downstream;
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(input),
        harness.sinkCallbackNode(0, 0),
    }, .{ .ctx = true, .callback = harness.sinkCallback, .context = &callback_ctx, .diagnostic = &diagnostic });
    try harness.requireStatus(r, abi.Status.io_failure);
    if (callback_ctx.accepted_total != 4) return error.CallbackAcceptedTotalMismatch;
    if (downstream.value_low != abi.Status.insufficient_capacity) return error.DownstreamStatusMismatch;
}

fn readOnlyReject(r: *Runner) !void {
    const input = "read-only";
    var output = [_]u8{0xa5} ** 16;
    try harness.reject(r, harness.ids.write, &.{
        harness.paramProfile(harness.ids.test_read_only),
        harness.sourceSpan(input),
        harness.sinkSpan(&output),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay | harness.cap_seek | harness.cap_range),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_provisional),
    }, .{ .profile = false }, abi.Status.unsupported, &output);
}

fn missingSource(r: *Runner) !void {
    var output = [_]u8{0xa5} ** 16;
    try harness.reject(r, harness.ids.read, &.{
        harness.sinkSpan(&output),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay | harness.cap_seek | harness.cap_range),
    }, .{}, abi.Status.invalid_call, &output);
}

fn missingSink(r: *Runner) !void {
    const input = "x";
    try harness.expect(r, harness.ids.read, &.{
        harness.sourceSpan(input),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay | harness.cap_seek | harness.cap_range),
    }, .{}, abi.Status.invalid_call);
}

fn duplicateProfile(r: *Runner) !void {
    try harness.expect(r, harness.ids.read, &.{
        harness.paramProfile(harness.ids.test_echo),
        harness.paramProfile(harness.ids.test_echo),
    }, .{ .profile = false }, abi.Status.invalid_call);
}

fn badPlanning(r: *Runner) !void {
    const input = "x";
    var output = [_]u8{0xa5} ** 16;
    try harness.reject(r, harness.ids.read, &.{
        harness.sourceSpan(input),
        harness.sinkSpan(&output),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay | harness.cap_seek | harness.cap_range),
        harness.pln(99),
        harness.dlv(harness.delivery_provisional),
    }, .{}, abi.Status.invalid_call, &output);
}

fn badDelivery(r: *Runner) !void {
    const input = "x";
    var output = [_]u8{0xa5} ** 16;
    try harness.reject(r, harness.ids.read, &.{
        harness.sourceSpan(input),
        harness.sinkSpan(&output),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay | harness.cap_seek | harness.cap_range),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(99),
    }, .{}, abi.Status.invalid_call, &output);
}

fn forgedSelector(r: *Runner) !void {
    const input = "x";
    var output = [_]u8{0xa5} ** 16;
    var forged = harness.scalarNode(harness.ids.parameter);
    forged.value_high = harness.paramSelector(99, 1, 0x11, harness.cmd_all);
    try harness.reject(r, harness.ids.read, &.{
        harness.paramProfile(harness.ids.test_echo),
        harness.sourceSpan(input),
        harness.sinkSpan(&output),
        forged,
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay | harness.cap_seek | harness.cap_range),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_provisional),
    }, .{ .profile = false }, abi.Status.unsupported, &output);
}

fn cryptoDirect(r: *Runner) !void {
    const input = "x";
    var output = [_]u8{0xa5} ** 16;
    try harness.reject(r, harness.ids.read, &.{
        harness.paramProfile(harness.ids.crypto),
        harness.sourceSpan(input),
        harness.sinkSpan(&output),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_verified),
    }, .{ .profile = false }, abi.Status.unsupported, &output);
}

fn modeMismatch(r: *Runner) !void {
    const input = "x";
    var output = [_]u8{0xa5} ** 16;
    try harness.reject(r, harness.ids.read, &.{
        harness.paramProfile(harness.ids.deflate),
        harness.sourceSpan(input),
        harness.sinkSpan(&output),
        harness.cap(harness.cap_read | harness.cap_size | harness.cap_replay),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_provisional),
    }, .{ .profile = false }, abi.Status.unsupported, &output);
}

fn depthLimit(r: *Runner) !void {
    var nodes: [40]harness.Node = undefined;
    for (&nodes, 0..) |*n, i| {
        n.* = harness.scalarNode(harness.ids.parameter);
        n.value_high = harness.paramSelector(harness.param_family_archive, harness.archive_entry, 0x17, harness.cmd_all);
        if (i + 1 < nodes.len) n.child = &nodes[i + 1];
    }
    r.response = harness.node(null, 0);
    r.status = harness.invoke(harness.ids.read, &nodes[0], &r.response, r.workspace.ptr, r.workspace.len, null, null, null);
    try harness.requireStatus(r, abi.Status.resource_limit);
}

fn cycleReject(r: *Runner) !void {
    var first = harness.scalarNode(harness.ids.parameter);
    first.value_high = harness.paramSelector(harness.param_family_archive, harness.archive_entry, 0x17, harness.cmd_all);
    var second = harness.scalarNode(harness.ids.parameter);
    second.value_high = first.value_high;
    first.child = &second;
    second.child = &first;
    r.response = harness.node(null, 0);
    r.status = harness.invoke(harness.ids.read, &first, &r.response, r.workspace.ptr, r.workspace.len, null, null, null);
    try harness.requireStatus(r, abi.Status.invalid_call);
}

fn diagnosticCycle(r: *Runner) !void {
    var diagnostic = harness.scalarNode(harness.ids.invalid_call);
    diagnostic.child = &diagnostic;
    r.response = harness.node(null, 0);
    r.status = harness.invoke(harness.ids.read, null, &r.response, r.workspace.ptr, r.workspace.len, null, null, &diagnostic);
    try harness.requireStatus(r, abi.Status.invalid_call);
}

fn workspaceOverlap(r: *Runner) !void {
    var buffer = [_]u8{0xa5} ** 16;
    var output = [_]u8{0xa5} ** 16;
    try harness.expect(r, harness.ids.read, &.{
        harness.sourceSpan(buffer[0..4]),
        harness.sinkSpan(&output),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay | harness.cap_seek | harness.cap_range),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_provisional),
    }, .{ .profile = false, .workspace = &buffer }, abi.Status.invalid_call);
}

fn sourceSinkOverlap(r: *Runner) !void {
    var buffer = [_]u8{0xa5} ** 16;
    try harness.reject(r, harness.ids.read, &.{
        harness.sourceSpan(buffer[0..4]),
        harness.sinkSpan(buffer[2..10]),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay | harness.cap_seek | harness.cap_range),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_provisional),
    }, .{}, abi.Status.invalid_call, &buffer);
}

fn nullSourceSpan(r: *Runner) !void {
    var output = [_]u8{0xa5} ** 16;
    var source = harness.node(null, 5);
    source.id = harness.ids.source;
    source.byte_length = 5;
    try harness.reject(r, harness.ids.read, &.{
        harness.paramProfile(harness.ids.test_echo),
        source,
        harness.sinkSpan(&output),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay | harness.cap_seek | harness.cap_range),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_provisional),
    }, .{ .profile = false }, abi.Status.invalid_call, &output);
}

fn workspaceCapacity(r: *Runner) !void {
    const input = "workspace";
    var output = [_]u8{0xa5} ** 64;
    var small_workspace = [_]u8{0} ** 1;
    try harness.expectCapacity(r, harness.ids.write, &.{
        harness.paramProfile(harness.ids.deflate),
        harness.sourceSpan(input),
        harness.sinkSpan(&output),
        harness.cap(harness.cap_read | harness.cap_size | harness.cap_replay),
        harness.pln(harness.plan_replay_pass),
        harness.dlv(harness.delivery_provisional),
    }, .{ .profile = false, .workspace = &small_workspace }, harness.ids.workspace_required_capacity, harness.ids.workspace_available_capacity, null, 1, &output);
}

pub fn run(r: *Runner) anyerror!void {
    try setup(r);
    try discoveryCapacity(r);
    try unknownId(r);
    try duplicateSource(r);
    try echoReadSpan(r);
    try echoWriteSpan(r);
    try echoCallbackSource(r);
    try capabilityReject(r);
    try capacityReject(r);
    try integrityReject(r);
    try limitReject(r);
    try callbackDownstream(r);
    try readOnlyReject(r);
    try missingSource(r);
    try missingSink(r);
    try duplicateProfile(r);
    try badPlanning(r);
    try badDelivery(r);
    try forgedSelector(r);
    try cryptoDirect(r);
    try modeMismatch(r);
    try depthLimit(r);
    try cycleReject(r);
    try diagnosticCycle(r);
    try workspaceOverlap(r);
    try sourceSinkOverlap(r);
    try nullSourceSpan(r);
    try workspaceCapacity(r);
}

pub const scenarios = harness.scenarios("protocol", &.{
    .{ .label = "protocol", .run = run, .workspace_size = 256, .output_size = 64, .encoded_size = 64 },
}, &.{});
