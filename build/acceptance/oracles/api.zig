const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const harness = @import("harness.zig");
const steps = @import("steps.zig");

// Exercises the session boundary through its C exports with caller-owned
// storage and no envelope.
//
// The contract: byte-identity with the kernel-mediated decode, idempotent
// destroy, invalid_call after destroy.

extern fn stdk_session_storage(component: [*:0]const u8, verb: [*:0]const u8) u64;
extern fn stdk_session_create(component: [*:0]const u8, verb: [*:0]const u8, storage: ?[*]u8, storage_len: u64) u32;
extern fn stdk_session_bounded(
    component: [*:0]const u8,
    verb: [*:0]const u8,
    storage: ?[*]u8,
    storage_len: u64,
    max_encoded: u64,
    max_decoded: u64,
    max_work: u64,
    max_entries: u64,
) u32;
extern fn stdk_session_step(
    session: ?*anyopaque,
    input: ?[*]const u8,
    input_len: u64,
    output: ?[*]u8,
    output_len: u64,
    end_of_input: c_int,
    counts_out: ?*[2]u64,
    state_out: ?*c_int,
) u32;
extern fn stdk_session_failure(session: ?*anyopaque, status_out: ?*u32, detail_out: ?*u64) u32;
extern fn stdk_session_catalog() [*:0]const u8;
extern fn stdk_session_destroy(session: ?*anyopaque) u32;

// Pumps a decode session chunk by chunk to its done state and pins the bytes.
fn pumpDecode(r: *harness.Runner, storage: ?*anyopaque, encoded: []const u8, decoded: []u8) !void {
    var counts: [2]u64 = undefined;
    var state: c_int = 0;
    var pos: usize = 0;
    var out_pos: usize = 0;
    var guard: usize = 0;
    while (guard < 64) : (guard += 1) {
        const take = @min(65536, encoded.len - pos);
        const chunk = encoded[pos..][0..take];
        const end = pos + take == encoded.len;
        const status = stdk_session_step(storage, chunk.ptr, chunk.len, decoded[out_pos..].ptr, decoded.len - out_pos, @intFromBool(end), &counts, &state);
        if (status != abi.Status.ok) return error.SessionStepFailed;
        pos += @intCast(counts[0]);
        out_pos += @intCast(counts[1]);
        if (state == 1) break;
        if (state < 0) return error.SessionStepCorrupt;
    }
    if (out_pos != r.input.len or !std.mem.eql(u8, decoded[0..out_pos], r.input)) return error.SessionDecodeMismatch;
}

fn run(r: *harness.Runner) anyerror!void {
    harness.setup(r, harness.ids.gzip, harness.mode_stream);
    corpus.fillTiled(r.corpus_index, r.corpus_buffer[0..]);
    r.input = r.corpus_buffer[0..];
    try steps.writeSpan(&steps.noParams, r);

    // Control: the envelope's readback must accept the same frame; failure
    // here blames the frame, not the boundary.
    try steps.queryRead(&steps.noParams, r);
    try steps.readSpan(&steps.noParams, r);

    const storage_len = stdk_session_storage("gzip", "decode");
    if (storage_len == 0 or storage_len > r.workspace.len) return error.StorageSize;
    if (stdk_session_storage("absent", "decode") != 0) return error.AbsentStorage;
    if (stdk_session_storage("gzip", "absent") != 0) return error.AbsentVerbStorage;

    const storage = r.workspace.ptr;
    if (stdk_session_create("gzip", "decode", storage, storage_len) != abi.Status.ok) return error.CreateFailed;

    var decoded: [64]u8 = undefined;
    try pumpDecode(r, storage, r.encoded[0..r.encoded_len], &decoded);

    if (stdk_session_destroy(storage) != abi.Status.ok) return error.DestroyFailed;
    if (stdk_session_destroy(storage) != abi.Status.ok) return error.DestroyNotIdempotent;
    var counts: [2]u64 = undefined;
    var state: c_int = 0;
    if (stdk_session_step(storage, null, 0, null, 0, 1, &counts, &state) != abi.Status.invalid_call) return error.StepAfterDestroy;

    // Discovery: the versioned catalog lists session pairs; the retired
    // tar/write pair stays out.
    const catalog = std.mem.span(stdk_session_catalog());
    if (!std.mem.startsWith(u8, catalog, "v1:")) return error.CatalogVersion;
    if (std.mem.find(u8, catalog, "gzip/decode") == null) return error.CatalogMissingGzip;
    if (std.mem.find(u8, catalog, "tar/write") != null) return error.CatalogRetiredPair;

    // Failure detail: an over-sized step reports the capacity shortfall.
    if (stdk_session_create("gzip", "decode", storage, storage_len) != abi.Status.ok) return error.CreateFailed;
    var oversized: [132096]u8 = undefined;
    @memset(&oversized, 0);
    const over_status = stdk_session_step(storage, &oversized, oversized.len, null, 0, 0, &counts, &state);
    if (over_status != abi.Status.insufficient_capacity) return error.CapacityStatus;
    var detail_status: u32 = 0;
    var detail: u64 = 0;
    if (stdk_session_failure(storage, &detail_status, &detail) != abi.Status.ok) return error.FailureReadback;
    if (detail_status != abi.Status.insufficient_capacity or detail == 0) return error.CapacityDetail;
    if (stdk_session_destroy(storage) != abi.Status.ok) return error.DestroyFailed;

    // Bounded create: a decoded ceiling trips resource_limit mid-pump and
    // the readback reports it.
    if (stdk_session_bounded(
        "gzip",
        "decode",
        storage,
        storage_len,
        std.math.maxInt(u64),
        8,
        std.math.maxInt(u64),
        std.math.maxInt(u64),
    ) != abi.Status.ok) return error.BoundedCreateFailed;
    var bounded_failed = false;
    var pos: usize = 0;
    while (pos < r.encoded_len) {
        const take = @min(4096, r.encoded_len - pos);
        const chunk2 = r.encoded[pos..][0..take];
        const end2 = pos + take == r.encoded_len;
        const step_status = stdk_session_step(
            storage,
            chunk2.ptr,
            chunk2.len,
            decoded[0..].ptr,
            decoded.len,
            @intFromBool(end2),
            &counts,
            &state,
        );
        pos += @intCast(counts[0]);
        if (step_status == abi.Status.resource_limit) {
            bounded_failed = true;
            break;
        }
        if (step_status != abi.Status.ok) return error.BoundedStepFailed;
        if (state == 1) break;
        if (state < 0) return error.BoundedStepCorrupt;
    }
    if (!bounded_failed) return error.BudgetNotEnforced;
    if (stdk_session_failure(storage, &detail_status, &detail) != abi.Status.ok) return error.FailureReadback;
    if (detail_status != abi.Status.resource_limit) return error.BudgetDetail;
    if (stdk_session_destroy(storage) != abi.Status.ok) return error.DestroyFailed;

    // Raw DEFLATE session: a deflate-profile stream decodes chunked through
    // the same boundary, and the pair is discoverable.
    harness.setup(r, harness.ids.deflate, harness.mode_stream);
    r.input = r.corpus_buffer[0..];
    try steps.writeSpan(&steps.noParams, r);
    const deflate_storage_len = stdk_session_storage("deflate", "decode");
    if (deflate_storage_len == 0 or deflate_storage_len > r.workspace.len) return error.DeflateStorageSize;
    const deflate_storage = r.workspace.ptr;
    if (stdk_session_create("deflate", "decode", deflate_storage, deflate_storage_len) != abi.Status.ok) return error.DeflateCreateFailed;
    @memset(&decoded, 0);
    try pumpDecode(r, deflate_storage, r.encoded[0..r.encoded_len], &decoded);
    if (stdk_session_destroy(deflate_storage) != abi.Status.ok) return error.DestroyFailed;
    const catalog_check = std.mem.span(stdk_session_catalog());
    if (std.mem.find(u8, catalog_check, "deflate/decode") == null) return error.CatalogMissingDeflate;
}

// Encode sessions pump the corpus chunked; the envelope reads each frame
// back. The zlib decode session walks an envelope-made frame.
fn runExtended(r: *harness.Runner) anyerror!void {
    var counts: [2]u64 = undefined;
    var state: c_int = 0;

    // The zlib decode path: the envelope's zlib frame decodes chunked
    // through the boundary.
    harness.setup(r, harness.ids.zlib, harness.mode_stream);
    corpus.fillTiled(r.corpus_index, r.corpus_buffer[0..]);
    r.input = r.corpus_buffer[0..];
    try steps.writeSpan(&steps.noParams, r);
    try steps.queryRead(&steps.noParams, r);
    try steps.readSpan(&steps.noParams, r);
    const zlib_storage_len = stdk_session_storage("zlib", "decode");
    if (zlib_storage_len == 0 or zlib_storage_len > r.workspace.len) return error.ZlibStorageSize;
    const zlib_storage = r.workspace.ptr;
    if (stdk_session_create("zlib", "decode", zlib_storage, zlib_storage_len) != abi.Status.ok) return error.ZlibCreateFailed;
    var decoded: [64]u8 = undefined;
    try pumpDecode(r, zlib_storage, r.encoded[0..r.encoded_len], &decoded);
    if (stdk_session_destroy(zlib_storage) != abi.Status.ok) return error.DestroyFailed;
    // A corrupted adler trailer fails as an integrity failure.
    if (stdk_session_create("zlib", "decode", zlib_storage, zlib_storage_len) != abi.Status.ok) return error.ZlibCreateFailed;
    r.encoded[r.encoded_len - 1] ^= 0xFF;
    const corrupt_status = stdk_session_step(zlib_storage, r.encoded.ptr, r.encoded_len, decoded[0..].ptr, decoded.len, 1, &counts, &state);
    r.encoded[r.encoded_len - 1] ^= 0xFF;
    if (corrupt_status != abi.Status.integrity_failure) return error.ZlibCorruptAccepted;
    if (stdk_session_destroy(zlib_storage) != abi.Status.ok) return error.DestroyFailed;

    // Encode sessions: deflate, gzip, and zlib frames built chunk by chunk
    // read back through the envelope byte-exact.
    const encode_cases = [_]struct { component: [*:0]const u8, profile: harness.Id }{
        .{ .component = "deflate", .profile = harness.ids.deflate },
        .{ .component = "gzip", .profile = harness.ids.gzip },
        .{ .component = "zlib", .profile = harness.ids.zlib },
        .{ .component = "lz4", .profile = harness.ids.lz4 },
    };
    for (encode_cases) |case| {
        const storage_len = stdk_session_storage(case.component, "encode");
        if (storage_len == 0 or storage_len > r.workspace.len) return error.EncodeStorageSize;
        const storage = r.workspace.ptr;
        if (stdk_session_create(case.component, "encode", storage, storage_len) != abi.Status.ok) return error.EncodeCreateFailed;
        var produced: usize = 0;
        var pos: usize = 0;
        var guard: usize = 0;
        var failed = false;
        while (guard < 64) : (guard += 1) {
            const take = @min(4096, r.input.len - pos);
            const end = pos + take == r.input.len;
            const status = stdk_session_step(storage, r.input[pos..].ptr, take, r.encoded[produced..].ptr, r.encoded.len - produced, @intFromBool(end), &counts, &state);
            if (status != abi.Status.ok) {
                failed = true;
                break;
            }
            pos += @intCast(counts[0]);
            produced += @intCast(counts[1]);
            if (state == 1) break;
        }
        if (failed or state != 1) return error.EncodeSessionFailed;
        if (stdk_session_destroy(storage) != abi.Status.ok) return error.DestroyFailed;

        harness.setup(r, case.profile, harness.mode_stream);
        const frame = r.encoded[0..produced];
        try harness.spanProduce(r, harness.ids.read, &.{
            harness.sourceSpan(frame),
            harness.sinkSpan(decoded[0..]),
        });
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length != r.input.len or !std.mem.eql(u8, decoded[0..r.input.len], r.input)) return error.EncodeRoundtripMismatch;
    }

    // lz4 decode: the envelope's lz4 frame decodes chunked through the
    // boundary, and a corrupt content checksum fails as integrity.
    harness.setup(r, harness.ids.lz4, harness.mode_stream);
    r.input = r.corpus_buffer[0..];
    try steps.writeSpan(&steps.noParams, r);
    const lz4_storage_len = stdk_session_storage("lz4", "decode");
    if (lz4_storage_len == 0 or lz4_storage_len > r.workspace.len) return error.Lz4StorageSize;
    const lz4_storage = r.workspace.ptr;
    if (stdk_session_create("lz4", "decode", lz4_storage, lz4_storage_len) != abi.Status.ok) return error.Lz4CreateFailed;
    @memset(&decoded, 0);
    try pumpDecode(r, lz4_storage, r.encoded[0..r.encoded_len], &decoded);
    if (stdk_session_destroy(lz4_storage) != abi.Status.ok) return error.DestroyFailed;
    if (stdk_session_create("lz4", "decode", lz4_storage, lz4_storage_len) != abi.Status.ok) return error.Lz4CreateFailed;
    r.encoded[r.encoded_len - 1] ^= 0xFF;
    const lz4_corrupt = stdk_session_step(lz4_storage, r.encoded.ptr, r.encoded_len, decoded[0..].ptr, decoded.len, 1, &counts, &state);
    r.encoded[r.encoded_len - 1] ^= 0xFF;
    if (lz4_corrupt != abi.Status.integrity_failure) return error.Lz4CorruptAccepted;
    if (stdk_session_destroy(lz4_storage) != abi.Status.ok) return error.DestroyFailed;

    const catalog = std.mem.span(stdk_session_catalog());
    for ([_][]const u8{ "zlib/decode", "deflate/encode", "gzip/encode", "zlib/encode", "lz4/decode", "lz4/encode" }) |pair| {
        if (std.mem.find(u8, catalog, pair) == null) return error.CatalogMissingPair;
    }
}

fn runSubmission(r: *harness.Runner) anyerror!void {
    harness.setup(r, harness.ids.gzip, harness.mode_stream);
    corpus.fillTiled(r.corpus_index, r.corpus_buffer[0..]);
    r.input = r.corpus_buffer[0..];

    var nodes: [6]harness.Node = undefined;
    nodes[0] = harness.paramProfile(r.profile_id);
    nodes[1] = harness.sourceSpan(r.input);
    nodes[2] = harness.sinkSpan(r.encoded);
    nodes[3] = harness.capabilityParam(r.caps_io);
    nodes[4] = harness.sizingModeParam(r.sizing);
    nodes[5] = harness.commitModeParam(r.commit_write);
    harness.linkNodes(&nodes);

    var envelope = abi.Call.init();
    envelope.operation = harness.ids.write;
    envelope.request = &nodes[0];
    envelope.response = &r.response;
    envelope.workspace = r.workspace.ptr;
    envelope.workspace_capacity = r.workspace.len;

    // A fresh record is pending; the cancellation boundary scenario owns
    // the cancel contract.
    var completion = abi.Completion.init();
    if (abi.stdk_poll(&completion) != abi.Completion.pending) return error.PollFreshNotPending;
    if (abi.stdk_submit(&envelope, &completion) != abi.Status.ok) return error.SubmitFailed;
    if (completion.state != abi.Completion.done) return error.SubmitNotDone;
    if (abi.stdk_poll(&completion) != abi.Status.ok) return error.PollSubmitNotOk;
    if (abi.stdk_cancel(&completion) != abi.Status.ok) return error.CancelDoneNotOk;
    r.encoded_len = @intCast(r.response.byte_length);
    if (r.encoded_len == 0 or r.encoded_len > r.encoded.len) return error.EncodedLength;

    // Malformed records fail closed; a null call completes its record as
    // invalid_call.
    var bad = abi.Completion.init();
    bad.reserved = 1;
    if (abi.stdk_submit(&envelope, &bad) != abi.Status.invalid_call) return error.BadRecordAccepted;
    var abandoned = abi.Completion.init();
    if (abi.stdk_submit(null, &abandoned) != abi.Status.invalid_call) return error.NullSubmitAccepted;
    if (abandoned.state != abi.Completion.done or abandoned.status != abi.Status.invalid_call) return error.NullRecordNotCompleted;

    // The submitted frame must read back through the synchronous boundary.
    try steps.queryRead(&steps.noParams, r);
    try steps.readSpan(&steps.noParams, r);

    // The group form completes every envelope: two identical writes must
    // produce byte-identical frames, one per record.
    var second_frame: [4096]u8 = undefined;
    var nodes_b: [6]harness.Node = undefined;
    nodes_b[0] = harness.paramProfile(r.profile_id);
    nodes_b[1] = harness.sourceSpan(r.input);
    nodes_b[2] = harness.sinkSpan(&second_frame);
    nodes_b[3] = harness.capabilityParam(r.caps_io);
    nodes_b[4] = harness.sizingModeParam(r.sizing);
    nodes_b[5] = harness.commitModeParam(r.commit_write);
    harness.linkNodes(&nodes_b);
    var envelope_b = abi.Call.init();
    envelope_b.operation = harness.ids.write;
    envelope_b.request = &nodes_b[0];
    envelope_b.response = &r.response;
    envelope_b.workspace = r.workspace.ptr;
    envelope_b.workspace_capacity = r.workspace.len;

    var responses: [2]abi.Completion = .{ abi.Completion.init(), abi.Completion.init() };
    var submissions: [2]abi.Submission = .{
        .{ .call = &envelope, .completion = &responses[0] },
        .{ .call = &envelope_b, .completion = &responses[1] },
    };
    if (abi.stdk_group(&submissions, 2, null) != abi.Status.ok) return error.GroupSubmitFailed;
    if (responses[0].status != abi.Status.ok or responses[1].status != abi.Status.ok) return error.GroupCallFailed;
    if (r.response.byte_length == 0 or !std.mem.eql(u8, r.encoded[0..r.encoded_len], second_frame[0..r.encoded_len])) return error.GroupFramesDiffer;

    // A host-provided executor in the C vtable shape drives the same group.
    const test_vtable: abi.ExecutorVtable = .{ .run = oracleRunInline };
    const test_executor: abi.Executor = .{ .ptr = @constCast(&test_vtable), .vtable = &test_vtable };
    var responses2: [2]abi.Completion = .{ abi.Completion.init(), abi.Completion.init() };
    var submissions2: [2]abi.Submission = .{
        .{ .call = &envelope, .completion = &responses2[0] },
        .{ .call = &envelope_b, .completion = &responses2[1] },
    };
    if (abi.stdk_group(&submissions2, 2, &test_executor) != abi.Status.ok) return error.GroupExecutorFailed;
    if (responses2[0].status != abi.Status.ok or responses2[1].status != abi.Status.ok) return error.GroupExecutorCallFailed;

    // One malformed record fails the group closed before any envelope runs.
    var bad_record = abi.Completion.init();
    bad_record.reserved = 1;
    var mixed: [2]abi.Submission = .{
        .{ .call = &envelope, .completion = &responses[0] },
        .{ .call = &envelope, .completion = &bad_record },
    };
    if (abi.stdk_group(&mixed, 2, null) != abi.Status.invalid_call) return error.BadGroupAccepted;
    if (abi.stdk_group(null, 2, null) != abi.Status.invalid_call) return error.NullGroupAccepted;
    if (abi.stdk_group(&submissions, 0, null) != abi.Status.invalid_call) return error.EmptyGroupAccepted;
}

// An oracle-side executor arm in the C vtable shape: run the task now.
fn oracleRunInline(_: *anyopaque, task: abi.Task) callconv(.c) u32 {
    return task.invoke(task.context);
}

// A deferred executor arm: run stores the task and returns, so a record
// stays pending until the oracle drains the queue by hand.
var deferred_task: ?abi.Task = null;

fn oracleRunDeferred(_: *anyopaque, task: abi.Task) callconv(.c) u32 {
    deferred_task = task;
    return abi.Status.ok;
}

// A withdrawing executor arm: a queued task cancelled before it starts is
// discarded; the executor flips the host-owned record itself, and the
// library never invokes the withdrawn task.
fn oracleRunWithdrawing(_: *anyopaque, task: abi.Task) callconv(.c) u32 {
    const submission: *abi.Submission = @ptrCast(@alignCast(task.context));
    const completion = submission.completion orelse return abi.Status.invalid_call;
    if (@atomicLoad(u32, &completion.state, .seq_cst) == abi.Completion.cancelling) {
        completion.status = abi.Status.cancelled;
        @atomicStore(u32, &completion.state, abi.Completion.done, .seq_cst);
        return abi.Status.ok;
    }
    deferred_task = task;
    return abi.Status.ok;
}

fn runCancel(r: *harness.Runner) anyerror!void {
    harness.setup(r, harness.ids.gzip, harness.mode_stream);
    corpus.fillTiled(r.corpus_index, r.corpus_buffer[0..]);
    r.input = r.corpus_buffer[0..];

    var nodes: [6]harness.Node = undefined;
    nodes[0] = harness.paramProfile(r.profile_id);
    nodes[1] = harness.sourceSpan(r.input);
    nodes[2] = harness.sinkSpan(r.encoded);
    nodes[3] = harness.capabilityParam(r.caps_io);
    nodes[4] = harness.sizingModeParam(r.sizing);
    nodes[5] = harness.commitModeParam(r.commit_write);
    harness.linkNodes(&nodes);
    var envelope = abi.Call.init();
    envelope.operation = harness.ids.write;
    envelope.request = &nodes[0];
    envelope.response = &r.response;
    envelope.workspace = r.workspace.ptr;
    envelope.workspace_capacity = r.workspace.len;

    const deferred_vtable: abi.ExecutorVtable = .{ .run = oracleRunDeferred };
    const deferred_executor: abi.Executor = .{ .ptr = @constCast(&deferred_vtable), .vtable = &deferred_vtable };

    // Drained without a cancel, the deferred task completes normally.
    var plain_record = abi.Completion.init();
    var plain_sub: [1]abi.Submission = .{.{ .call = &envelope, .completion = &plain_record }};
    if (abi.stdk_group(&plain_sub, 1, &deferred_executor) != abi.Status.ok) return error.DeferredSubmitFailed;
    if (plain_record.state != abi.Completion.in_progress) return error.DeferredRanEarly;
    if (deferred_task) |task| _ = task.invoke(task.context) else return error.DeferredTaskLost;
    if (plain_record.state != abi.Completion.done or plain_record.status != abi.Status.ok) return error.DeferredNotCompleted;

    // A cancel that lands before the task runs is honored at the boundary:
    // the envelope never executes and the record completes as cancelled.
    var pending_record = abi.Completion.init();
    var pending_sub: [1]abi.Submission = .{.{ .call = &envelope, .completion = &pending_record }};
    if (abi.stdk_group(&pending_sub, 1, &deferred_executor) != abi.Status.ok) return error.CancelSubmitFailed;
    if (abi.stdk_poll(&pending_record) != abi.Completion.pending) return error.CancelNotPending;
    if (abi.stdk_cancel(&pending_record) != abi.Status.ok) return error.CancelRequestFailed;
    if (abi.stdk_cancel(&pending_record) != abi.Status.ok) return error.CancelNotIdempotent;
    if (deferred_task) |task| _ = task.invoke(task.context) else return error.CancelTaskLost;
    if (pending_record.state != abi.Completion.done or pending_record.status != abi.Status.cancelled) return error.CancelNotHonored;

    // Withdrawal: the executor's queue pump discards a cancelled queued
    // task and flips the host-owned record itself; the task never runs.
    const withdrawing_vtable: abi.ExecutorVtable = .{ .run = oracleRunDeferred };
    const withdrawing_executor: abi.Executor = .{ .ptr = @constCast(&withdrawing_vtable), .vtable = &withdrawing_vtable };
    var withdrawn_record = abi.Completion.init();
    var withdrawn_sub: [1]abi.Submission = .{.{ .call = &envelope, .completion = &withdrawn_record }};
    if (abi.stdk_group(&withdrawn_sub, 1, &withdrawing_executor) != abi.Status.ok) return error.WithdrawSubmitFailed;
    if (abi.stdk_cancel(&withdrawn_record) != abi.Status.ok) return error.WithdrawCancelFailed;
    const queued = deferred_task orelse return error.WithdrawTaskLost;
    if (oracleRunWithdrawing(@constCast(&withdrawing_vtable), queued) != abi.Status.ok) return error.WithdrawPumpFailed;
    if (withdrawn_record.state != abi.Completion.done or withdrawn_record.status != abi.Status.cancelled) return error.WithdrawNotFlipped;
    if (abi.stdk_poll(&withdrawn_record) != abi.Status.cancelled) return error.WithdrawPollMismatch;

    // A late cancel finds the record done and is a no-op.
    if (abi.stdk_cancel(&plain_record) != abi.Status.ok) return error.LateCancelRejected;
}

pub const scenarios = harness.scenarios("api", &.{}, &.{
    .{
        .name = "submission cancellation boundary",
        .run = runCancel,
        .workspace_size = 1 << 20,
        .output_size = 64,
        .encoded_size = 4096,
    },
    .{
        .name = "submission api boundary",
        .run = runSubmission,
        .workspace_size = 1 << 20,
        .output_size = 64,
        .encoded_size = 4096,
    },
    .{
        .name = "session api boundary",
        .run = run,
        .workspace_size = 1 << 20,
        .output_size = 64,
        .encoded_size = 64,
    },
    .{
        .name = "session api extended boundary",
        .run = runExtended,
        // lz4 sessions stage a full 4 MiB block on each side, so the
        // stepped boundary needs multi-megabyte session storage.
        .workspace_size = 16 << 20,
        .output_size = 64,
        .encoded_size = 4096,
    },
});
