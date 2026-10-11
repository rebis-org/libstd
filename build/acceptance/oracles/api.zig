const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const harness = @import("harness.zig");
const steps = @import("steps.zig");

// The substrate session boundary exercised through its C exports: the same
// driver code the envelope path uses, reached with caller-owned storage and
// no envelope. Byte-identity with the kernel-mediated decode plus the
// lifecycle (idempotent destroy, invalid_call on step-after-destroy) is the
// contract.

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

fn run(r: *harness.Runner) anyerror!void {
    harness.setup(r, harness.ids.gzip, harness.mode_stream);
    corpus.fillTiled(r.corpus_index, r.corpus_buffer[0..]);
    r.input = r.corpus_buffer[0..];
    try steps.writeSpan(&steps.noParams, r);

    // Control: the envelope's own readback must accept the same frame. If
    // this fails the frame (not the session boundary) is at fault.
    try steps.queryRead(&steps.noParams, r);
    try steps.readSpan(&steps.noParams, r);

    const storage_len = stdk_session_storage("gzip", "decode");
    if (storage_len == 0 or storage_len > r.workspace.len) return error.StorageSize;
    if (stdk_session_storage("absent", "decode") != 0) return error.AbsentStorage;
    if (stdk_session_storage("gzip", "absent") != 0) return error.AbsentVerbStorage;

    const storage = r.workspace.ptr;
    if (stdk_session_create("gzip", "decode", storage, storage_len) != abi.Status.ok) return error.CreateFailed;

    var decoded: [64]u8 = undefined;
    var pos: usize = 0;
    var out_pos: usize = 0;
    var guard: usize = 0;
    while (guard < 64) : (guard += 1) {
        const take = @min(65536, r.encoded_len - pos);
        const chunk = r.encoded[pos..][0..take];
        const end = pos + take == r.encoded_len;
        var counts: [2]u64 = undefined;
        var state: c_int = 0;
        const status = stdk_session_step(storage, chunk.ptr, chunk.len, decoded[out_pos..].ptr, decoded.len - out_pos, @intFromBool(end), &counts, &state);
        if (status != abi.Status.ok) return error.StepFailed;
        pos += @intCast(counts[0]);
        out_pos += @intCast(counts[1]);
        if (state == 1) break;
        if (state < 0) return error.StepCorrupt;
    }
    if (out_pos != r.input.len or !std.mem.eql(u8, decoded[0..out_pos], r.input)) return error.SessionMismatch;

    if (stdk_session_destroy(storage) != abi.Status.ok) return error.DestroyFailed;
    if (stdk_session_destroy(storage) != abi.Status.ok) return error.DestroyNotIdempotent;
    var counts: [2]u64 = undefined;
    var state: c_int = 0;
    if (stdk_session_step(storage, null, 0, null, 0, 1, &counts, &state) != abi.Status.invalid_call) return error.StepAfterDestroy;

    // Discovery: the versioned catalog names the session-able pairs. The
    // removed tar/write pair stays out (retirement is part of the contract).
    const catalog = std.mem.span(stdk_session_catalog());
    if (!std.mem.startsWith(u8, catalog, "v1:")) return error.CatalogVersion;
    if (std.mem.indexOf(u8, catalog, "gzip/decode") == null) return error.CatalogMissingGzip;
    if (std.mem.indexOf(u8, catalog, "tar/write") != null) return error.CatalogRetiredPair;

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
    pos = 0;
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

    // Raw DEFLATE session: a stream produced by the deflate profile decodes
    // chunked through the same boundary, and the pair is discoverable.
    harness.setup(r, harness.ids.deflate, harness.mode_stream);
    r.input = r.corpus_buffer[0..];
    try steps.writeSpan(&steps.noParams, r);
    const deflate_storage_len = stdk_session_storage("deflate", "decode");
    if (deflate_storage_len == 0 or deflate_storage_len > r.workspace.len) return error.DeflateStorageSize;
    const deflate_storage = r.workspace.ptr;
    if (stdk_session_create("deflate", "decode", deflate_storage, deflate_storage_len) != abi.Status.ok) return error.DeflateCreateFailed;
    @memset(&decoded, 0);
    pos = 0;
    out_pos = 0;
    guard = 0;
    while (guard < 64) : (guard += 1) {
        const take = @min(65536, r.encoded_len - pos);
        const chunk = r.encoded[pos..][0..take];
        const end = pos + take == r.encoded_len;
        const status = stdk_session_step(deflate_storage, chunk.ptr, chunk.len, decoded[out_pos..].ptr, decoded.len - out_pos, @intFromBool(end), &counts, &state);
        if (status != abi.Status.ok) return error.DeflateStepFailed;
        pos += @intCast(counts[0]);
        out_pos += @intCast(counts[1]);
        if (state == 1) break;
        if (state < 0) return error.DeflateStepCorrupt;
    }
    if (out_pos != r.input.len or !std.mem.eql(u8, decoded[0..out_pos], r.input)) return error.DeflateSessionMismatch;
    if (stdk_session_destroy(deflate_storage) != abi.Status.ok) return error.DestroyFailed;
    const catalog_check = std.mem.span(stdk_session_catalog());
    if (std.mem.indexOf(u8, catalog_check, "deflate/decode") == null) return error.CatalogMissingDeflate;
}

// Encode sessions pump the corpus through in chunks and the envelope reads
// the frame back; the zlib decode session walks an envelope-made frame.
fn runExtended(r: *harness.Runner) anyerror!void {
    var counts: [2]u64 = undefined;
    var state: c_int = 0;

    // zlib decode: the envelope's zlib frame decodes chunked through the boundary.
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
    var pos: usize = 0;
    var out_pos: usize = 0;
    var guard: usize = 0;
    while (guard < 64) : (guard += 1) {
        const take = @min(65536, r.encoded_len - pos);
        const chunk = r.encoded[pos..][0..take];
        const end = pos + take == r.encoded_len;
        const status = stdk_session_step(zlib_storage, chunk.ptr, chunk.len, decoded[out_pos..].ptr, decoded.len - out_pos, @intFromBool(end), &counts, &state);
        if (status != abi.Status.ok) return error.ZlibStepFailed;
        pos += @intCast(counts[0]);
        out_pos += @intCast(counts[1]);
        if (state == 1) break;
        if (state < 0) return error.ZlibStepCorrupt;
    }
    if (out_pos != r.input.len or !std.mem.eql(u8, decoded[0..out_pos], r.input)) return error.ZlibSessionMismatch;
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
        pos = 0;
        guard = 0;
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
    pos = 0;
    out_pos = 0;
    guard = 0;
    while (guard < 64) : (guard += 1) {
        const take = @min(65536, r.encoded_len - pos);
        const chunk = r.encoded[pos..][0..take];
        const end = pos + take == r.encoded_len;
        const status = stdk_session_step(lz4_storage, chunk.ptr, chunk.len, decoded[out_pos..].ptr, decoded.len - out_pos, @intFromBool(end), &counts, &state);
        if (status != abi.Status.ok) return error.Lz4StepFailed;
        pos += @intCast(counts[0]);
        out_pos += @intCast(counts[1]);
        if (state == 1) break;
        if (state < 0) return error.Lz4StepCorrupt;
    }
    if (out_pos != r.input.len or !std.mem.eql(u8, decoded[0..out_pos], r.input)) return error.Lz4SessionMismatch;
    if (stdk_session_destroy(lz4_storage) != abi.Status.ok) return error.DestroyFailed;
    if (stdk_session_create("lz4", "decode", lz4_storage, lz4_storage_len) != abi.Status.ok) return error.Lz4CreateFailed;
    r.encoded[r.encoded_len - 1] ^= 0xFF;
    const lz4_corrupt = stdk_session_step(lz4_storage, r.encoded.ptr, r.encoded_len, decoded[0..].ptr, decoded.len, 1, &counts, &state);
    r.encoded[r.encoded_len - 1] ^= 0xFF;
    if (lz4_corrupt != abi.Status.integrity_failure) return error.Lz4CorruptAccepted;
    if (stdk_session_destroy(lz4_storage) != abi.Status.ok) return error.DestroyFailed;

    const catalog = std.mem.span(stdk_session_catalog());
    for ([_][]const u8{ "zlib/decode", "deflate/encode", "gzip/encode", "zlib/encode", "lz4/decode", "lz4/encode" }) |pair| {
        if (std.mem.indexOf(u8, catalog, pair) == null) return error.CatalogMissingPair;
    }
}

pub const scenarios = harness.scenarios("api", &.{}, &.{
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
