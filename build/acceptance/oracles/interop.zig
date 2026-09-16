const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const harness = @import("harness.zig");
const lib = @import("lib.zig");
const steps = @import("steps.zig");

// Pins agreement per corpus file both ways: ours decodes under the reference and vice versa.

const RefCodec = struct {
    encode: *const fn (input: []const u8, output: []u8) ?usize,
    decode: *const fn (input: []const u8, output: []u8) ?usize,
};

extern fn ZSTD_decompress(dst: [*]u8, dstCapacity: usize, src: [*]const u8, compressedSize: usize) usize;
extern fn ZSTD_isError(code: usize) c_uint;

fn zstdRefEncode(input: []const u8, output: []u8) ?usize {
    return lib.zstdCompress(input, output);
}

fn zstdRefDecode(input: []const u8, output: []u8) ?usize {
    const len = ZSTD_decompress(output.ptr, output.len, input.ptr, input.len);
    if (ZSTD_isError(len) != 0) return null;
    return len;
}

fn xzRefEncode(input: []const u8, output: []u8) ?usize {
    return lib.xzEncode(input, output, 1, null, null, 1 << 20); // 1 is LZMA_CHECK_CRC32.
}

fn noParams(_: *harness.Runner, _: *[steps.MaxExtra]harness.Node) usize {
    return 0;
}

fn gzipRefEncode(input: []const u8, output: []u8) ?usize {
    return lib.gzipCompress(input, output);
}

fn gzipRefDecode(input: []const u8, output: []u8) ?usize {
    return lib.gzipDecompress(input, output);
}

fn bzip2RefEncode(input: []const u8, output: []u8) ?usize {
    return lib.bzip2Compress(input, output);
}

fn bzip2RefDecode(input: []const u8, output: []u8) ?usize {
    return lib.bzip2Decompress(input, output);
}

fn xzRefDecode(input: []const u8, output: []u8) ?usize {
    return lib.lzmaBufferDecode(input, output);
}

fn zstdParams(_: *harness.Runner, out: *[steps.MaxExtra]harness.Node) usize {
    out[0] = harness.paramScalar(harness.param_family_zstd, harness.zstd_window, harness.cmd_all, 1 << 22);
    out[1] = harness.paramScalar(harness.param_family_zstd, harness.zstd_hash_bits, harness.cmd_all, 17);
    out[2] = harness.paramScalar(harness.param_family_zstd, harness.zstd_double_hash, harness.cmd_all, 1);
    return 3;
}

fn xzParams(r: *harness.Runner, out: *[steps.MaxExtra]harness.Node) usize {
    out[0] = harness.lzmaDictionaryParam(r.lzma_dictionary);
    return 1;
}

fn cross(
    profile: harness.Id,
    mode: harness.Mode,
    comptime params: steps.Params,
    r: *harness.Runner,
    reference: RefCodec,
) anyerror!void {
    harness.setup(r, profile, mode);
    corpus.select(r.corpus_index, r.corpus_buffer[0..]);
    r.input = r.corpus_buffer[0..];
    r.sink_accept = 3;
    r.write_exact = true;
    r.invalid_status = abi.Status.invalid_data;
    r.invalid = &.{0x06};

    steps.queryWrite(params, r) catch return error.OursQueryWrite;
    {
        var subject = harness.scalarNode(harness.ids.diagnostic_subject);
        var diagnostic = harness.node(null, 0);
        diagnostic.child = &subject;
        const nodes = steps.build(params, r, &.{ harness.sourceSpan(r.input), harness.sinkSpan(r.encoded) });
        const status = harness.call(r, harness.ids.write, nodes.items[0..nodes.len], .{ .ctx = true, .diagnostic = &diagnostic });
        if (status != abi.Status.ok) {
            std.debug.print("interop write rejected: status {d}, subject low {x}, high {x}.\n", .{ status, subject.value_low, subject.value_high });
            return error.OursWrite;
        }
        r.encoded_len = @intCast(r.response.byte_length);
    }
    var decoded: [64]u8 = undefined;
    const decoded_len = reference.decode(r.encoded[0..r.encoded_len], &decoded) orelse return error.ReferenceRejectedOurs;
    if (decoded_len != r.input.len or !std.mem.eql(u8, decoded[0..decoded_len], r.input)) return error.ReferenceMismatchOurs;

    const encoded_len = reference.encode(r.input, r.encoded) orelse return error.ReferenceEncodeFailed;
    r.encoded_len = encoded_len;
    steps.queryRead(params, r) catch return error.OursQueryRead;
    steps.readSpan(params, r) catch return error.OursRead;
}

fn run(r: *harness.Runner) anyerror!void {
    try cross(harness.ids.zstd, harness.mode_xz, &zstdParams, r, .{ .encode = &zstdRefEncode, .decode = &zstdRefDecode });
    try cross(harness.ids.gzip, harness.mode_stream, &noParams, r, .{ .encode = &gzipRefEncode, .decode = &gzipRefDecode });
    try cross(harness.ids.bzip2, harness.mode_stream, &noParams, r, .{ .encode = &bzip2RefEncode, .decode = &bzip2RefDecode });
    r.lzma_dictionary = 1 << 20; // match xzRefEncode's dictionary
    try cross(harness.ids.xz, harness.mode_xz, &xzParams, r, .{ .encode = &xzRefEncode, .decode = &xzRefDecode });
}

pub const scenarios = harness.scenarios("interop", &.{
    .{ .label = "stream bidirectional", .run = run, .workspace_size = 256 * 1024 * 1024, .output_size = 64, .encoded_size = 256 },
}, &.{});
