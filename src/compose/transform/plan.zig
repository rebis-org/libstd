const std = @import("std");

const measurement = @import("../../common/primitive/measurement.zig");
const resource = @import("../../kernel/resource.zig");
const vocabulary = @import("../../kernel/vocabulary.zig");
const gzip = @import("../../representation/grammar/gzip/onprem.zig");
const zlib = @import("../../representation/grammar/zlib/onprem.zig");
const deflate = @import("../../representation/leaf/deflate/onprem.zig");
const deflate_seam = @import("../../representation/leaf/deflate/seam.zig");
const zstd = @import("../../representation/leaf/zstd/onprem.zig");
const common = @import("../common.zig");

const Exception = vocabulary.Exception;

// The counting pass replays the exact encode so the commit produces identical bytes, and both sides charge work.
pub fn planCountedEncode(source: *resource.Resource, decoded_limit: u64, encoded_limit: u64, work_limit: u64, comptime map_io_failure: bool, comptime encode_fn: fn (input: *std.Io.Reader, output: *std.Io.Writer, args: anytype) Exception!void, args: anytype) Exception!usize {
    var bounded_source: resource.BoundedReader = undefined;
    bounded_source.init(source, decoded_limit);
    var counter = measurement.Counter.init(null);
    if (map_io_failure) {
        encode_fn(&bounded_source.reader, &counter.writer, args) catch return error.IoException;
    } else {
        try encode_fn(&bounded_source.reader, &counter.writer, args);
    }
    const output_size = counter.written();
    if (output_size > encoded_limit) return error.ResourceException;
    const consumed = decoded_limit - bounded_source.limit;
    if (consumed + output_size > work_limit) return error.ResourceException;
    try common.rejectOverLimit(source, bounded_source.limit == 0);
    try source.rewind();
    return std.math.cast(usize, output_size) orelse error.ResourceException;
}

pub fn planDeflateDecode(source: *resource.Resource, history: []u8, encoded_limit: u64, decoded_limit: u64) Exception!usize {
    var bounded_source: resource.BoundedReader = undefined;
    bounded_source.init(source, encoded_limit);
    var counter = measurement.Counter.init(null);
    // The counting pass answers a size, so the arm choice is output-neutral;
    // the committing decode binds the provider.
    var inflater = deflate.Decompress.init(&bounded_source.reader, history);
    _ = inflater.reader.streamRemaining(&counter.writer) catch return error.DataException;
    try source.rewind();
    const output_size = counter.written();
    if (output_size > decoded_limit) return error.ResourceException;
    return std.math.cast(usize, output_size) orelse error.ResourceException;
}

pub fn gzipEncodeStream(input: *std.Io.Reader, output: *std.Io.Writer, args: anytype) Exception!void {
    try gzip.encodeStream(input, output, args.history, args.options);
}

pub fn zlibEncodeStream(input: *std.Io.Reader, output: *std.Io.Writer, args: anytype) Exception!void {
    try zlib.encodeStream(input, output, args.history, args.options);
}

pub fn deflateEncodeStream(input: *std.Io.Reader, output: *std.Io.Writer, args: anytype) Exception!void {
    var compressor = try deflate.Compress.init(output, args.history, args.options);
    _ = std.Io.Reader.streamRemaining(input, &compressor.writer) catch return error.IoException;
    compressor.finish() catch return error.IoException;
}

pub fn zstdEncodeStream(input: *std.Io.Reader, output: *std.Io.Writer, args: anytype) Exception!void {
    _ = try zstd.encodeStream(input, output, args.history, args.workspace, args.options);
}
