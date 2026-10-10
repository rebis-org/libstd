const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const harness = @import("harness.zig");
const lib = @import("lib.zig");
const Runner = harness.Runner;
const steps = @import("steps.zig");

fn setupContainer(r: *Runner, profile_id: harness.Id) void {
    harness.setup(r, profile_id, harness.mode_stream);
    r.input = r.corpus_buffer[0..32];
    r.sink_accept = 3;
    r.write_exact = true;
    r.invalid_status = abi.Status.invalid_data;
    r.invalid = &.{0x06};
    corpus.fillTiled(r.corpus_index, r.corpus_buffer[0..]);
}

fn runZlib(r: *Runner) anyerror!void {
    setupContainer(r, harness.ids.zlib);
    try steps.roundtrip(&steps.noParams, r);
    if (!lib.zlibValid(r.encoded[0..r.encoded_len])) return error.ReferenceToolRejectedOutput;
    // Reference encoder produces, our decoder reads.
    var fixture_input: [65536]u8 = undefined;
    var compressed: [131072]u8 = undefined;
    var decoded: [65536]u8 = undefined;
    corpus.fillTiled(r.corpus_index, &fixture_input);
    try harness.oracleFixture(r, lib.zlibCompress, &fixture_input, &compressed, &decoded);
    // Adler mismatch is an integrity failure, not silent corruption.
    r.encoded[r.encoded_len - 1] ^= 0xff;
    try harness.reject(r, harness.ids.read, &.{
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true }, abi.Status.integrity_failure, r.output);
}

fn runLz4(r: *Runner) anyerror!void {
    setupContainer(r, harness.ids.lz4);
    try steps.roundtrip(&steps.noParams, r);
    if (!lib.lz4Valid(r.encoded[0..r.encoded_len])) return error.ReferenceToolRejectedOutput;
    var fixture_input: [65536]u8 = undefined;
    var compressed: [131072]u8 = undefined;
    var decoded: [65536]u8 = undefined;
    corpus.fillTiled(r.corpus_index, &fixture_input);
    try harness.oracleFixture(r, lib.lz4Compress, &fixture_input, &compressed, &decoded);
    // Content-checksum mismatch is an integrity failure.
    r.encoded[r.encoded_len - 1] ^= 0xff;
    try harness.reject(r, harness.ids.read, &.{
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true }, abi.Status.integrity_failure, r.output);
}

fn hcParams(_: *Runner, out: *[steps.MaxExtra]harness.Node) usize {
    out[0] = harness.paramScalar(harness.param_family_lz4, harness.lz4_search_depth, harness.cmd_all, 256);
    return 1;
}

fn runLz4Hc(r: *Runner) anyerror!void {
    setupContainer(r, harness.ids.lz4);
    try steps.roundtrip(&hcParams, r);
    if (!lib.lz4Valid(r.encoded[0..r.encoded_len])) return error.ReferenceToolRejectedOutput;
}

fn runZstdSeekable(r: *Runner) anyerror!void {
    setupContainer(r, harness.ids.zstd_seekable);
    try steps.roundtrip(&steps.noParams, r);
    // The payload is a plain multi-frame zstd stream (seek table skippable)
    // and must decode with the reference library.
    if (!lib.zstdValid(r.encoded[0..r.encoded_len])) return error.ReferenceToolRejectedOutput;
    // The seek table footer magic must be the file's last bytes.
    r.encoded[r.encoded_len - 1] ^= 0xff;
    try harness.reject(r, harness.ids.read, &.{
        harness.sourceSpan(r.encoded[0..r.encoded_len]),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true }, abi.Status.invalid_data, r.output);
}

var zdict_sample_data: [8 * 2048]u8 = undefined;

fn runZdict(r: *Runner) anyerror!void {
    harness.setup(r, harness.ids.zdict, harness.mode_stream);
    // Deterministic sample corpus: shared sentence structure so the trained
    // content is genuinely referenceable by later encodes.
    const phrases = [_][]const u8{
        "the quick brown fox jumps over the lazy dog and runs through the forest. ",
        "pack my box with five dozen liquor jugs then seal the box with tape. ",
        "how vexingly quick daft zebras jump over the lazy dogs in the meadow. ",
    };
    for (&zdict_sample_data, 0..) |*byte, i| {
        const phrase = phrases[(i / 128) % phrases.len];
        byte.* = phrase[i % phrase.len];
    }
    const sample_size = 2048;
    _ = harness.call(r, harness.ids.write, &.{
        harness.paramScalar(harness.param_family_seekable, harness.zdict_sample_size, harness.cmd_query_write, sample_size),
        harness.sourceSpan(&zdict_sample_data),
        harness.sinkSpan(r.encoded),
        harness.capabilityParam(r.caps_io),
        harness.sizingModeParam(r.sizing),
        harness.commitModeParam(r.commit_write),
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    const dictionary = r.encoded[0..@intCast(r.response.byte_length)];
    const dictionary_header_size = 28; // magic/id(8) + huffman(2) + 3 FSE tables(6) + rep offsets(12)
    if (dictionary.len <= dictionary_header_size or std.mem.readInt(u32, dictionary[0..4], .little) != 0xEC30A437) return error.DictionaryShapeInvalid;
    // Reading the dictionary extracts its content (the window bytes).
    var content_out: [8 * 2048]u8 = undefined;
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(dictionary),
        harness.sinkSpan(&content_out),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    // Fastcover content: selected 50-byte windows of the samples, in a
    // deterministic order. The content length must match the header math,
    // every window must occur in the training data, and a second training
    // run must produce byte-identical output.
    const content = content_out[0..r.response.byte_length];
    if (r.response.byte_length != dictionary.len - dictionary_header_size) return error.DictionaryShapeInvalid;
    var offset: usize = 0;
    while (offset + 50 <= content.len) : (offset += 50) {
        var found = false;
        var at: usize = 0;
        while (at + 50 <= zdict_sample_data.len) : (at += 1) {
            if (std.mem.eql(u8, content[offset..][0..50], zdict_sample_data[at..][0..50])) {
                found = true;
                break;
            }
        }
        if (!found) return error.DictionaryContentMismatch;
    }
    var second_training: [16 * 1024]u8 = undefined;
    _ = harness.call(r, harness.ids.write, &.{
        harness.paramScalar(harness.param_family_seekable, harness.zdict_sample_size, harness.cmd_query_write, sample_size),
        harness.sourceSpan(&zdict_sample_data),
        harness.sinkSpan(&second_training),
        harness.capabilityParam(r.caps_io),
        harness.sizingModeParam(r.sizing),
        harness.commitModeParam(r.commit_write),
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != dictionary.len or !std.mem.eql(u8, second_training[0..r.response.byte_length], dictionary)) {
        return error.DictionaryTrainingNotDeterministic;
    }
    const input = zdict_sample_data[0..sample_size];

    // Ours encodes with the dictionary, the reference decodes with it.
    var encoded_with_dict: [4096]u8 = undefined;
    _ = harness.call(r, harness.ids.write, &.{
        harness.paramProfile(harness.ids.zstd),
        harness.paramScalar(harness.param_family_zstd, harness.zstd_window, harness.cmd_all, 1 << 16),
        harness.paramBytes(harness.param_family_zstd, harness.zstd_dictionary, harness.cmd_all, dictionary),
        harness.sourceSpan(input),
        harness.sinkSpan(&encoded_with_dict),
        harness.capabilityParam(r.caps_io),
        harness.sizingModeParam(r.sizing),
        harness.commitModeParam(harness.commit_confirmed),
    }, .{ .profile = false });
    try harness.requireStatus(r, abi.Status.ok);
    const encoded_len: usize = @intCast(r.response.byte_length);
    var decoded: [2048]u8 = undefined;
    const reference = lib.zstdDecompressUsingDict(encoded_with_dict[0..encoded_len], dictionary, &decoded);
    if (reference == null or reference.? != input.len or !std.mem.eql(u8, decoded[0..input.len], input)) {
        return error.ReferenceDecodeWithDictionaryMismatch;
    }

    // The reference encodes with the dictionary, ours decodes with it.
    var reference_encoded: [4096]u8 = undefined;
    const reference_len = lib.zstdCompressUsingDict(input, dictionary, &reference_encoded) orelse return error.ReferenceEncodeFailed;
    var ours_decoded: [2048]u8 = undefined;
    _ = harness.call(r, harness.ids.read, &.{
        harness.paramProfile(harness.ids.zstd),
        harness.paramScalar(harness.param_family_zstd, harness.zstd_window, harness.cmd_all, 1 << 16),
        harness.paramBytes(harness.param_family_zstd, harness.zstd_dictionary, harness.cmd_all, dictionary),
        harness.sourceSpan(reference_encoded[0..reference_len]),
        harness.sinkSpan(&ours_decoded),
        harness.capabilityParam(r.caps_io),
        harness.sizingModeParam(r.sizing),
        harness.commitModeParam(harness.commit_confirmed),
    }, .{ .profile = false });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != input.len or !std.mem.eql(u8, ours_decoded[0..input.len], input)) {
        return error.OurDecodeWithDictionaryMismatch;
    }
}

pub const scenarios = harness.scenarios("containers", &.{
    .{ .label = "zlib roundtrip", .run = runZlib, .workspace_size = 8 * 1024 * 1024, .output_size = 65536, .encoded_size = 65536 },
    .{ .label = "lz4 roundtrip", .run = runLz4, .workspace_size = 16 * 1024 * 1024, .output_size = 65536, .encoded_size = 65536 },
    .{ .label = "lz4 hc roundtrip", .run = runLz4Hc, .workspace_size = 16 * 1024 * 1024, .output_size = 65536, .encoded_size = 65536 },
    .{ .label = "zstd seekable", .run = runZstdSeekable, .workspace_size = 16 * 1024 * 1024, .output_size = 65536, .encoded_size = 65536 },
    .{ .label = "zdict train", .run = runZdict, .workspace_size = 8 * 1024 * 1024, .output_size = 4096, .encoded_size = 24 * 1024 },
}, &.{});
