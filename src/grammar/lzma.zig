const std = @import("std");

const bounds = @import("../common/primitive/bounds.zig");
const failure_prim = @import("../common/primitive/failure.zig");
const Failure = failure_prim.Failure;
const io = @import("../common/primitive/io.zig");
const lzma = @import("../leaf/lzma.zig");

pub const header_size = 13;

pub fn decodeOptions(input: []const u8) Failure!lzma.Options {
    const header = try bounds.slice(input, 0, header_size);
    var dict_size = std.mem.readInt(u32, header[1..5], .little);
    if (dict_size < lzma.dictionary_min) dict_size = lzma.dictionary_min;
    if (dict_size > lzma.dictionary_max) return error.Unsupported;
    const unpack_size = std.mem.readInt(u64, header[5..13], .little);
    const marker_required = unpack_size == std.math.maxInt(u64);
    return .{
        .properties = try lzma.Properties.decode(header[0], dict_size),
        .unpack_size = if (marker_required) null else unpack_size,
        .marker_required = marker_required,
    };
}

pub fn decodedSize(input: []const u8, scratch: []u8) Failure!usize {
    const options = try decodeOptions(input);
    return lzma.decodedSize(input[header_size..], scratch, options);
}

pub fn decode(input: []const u8, output: []u8, scratch: []u8) Failure!usize {
    const options = try decodeOptions(input);
    return lzma.decode(input[header_size..], output, scratch, options);
}

pub fn decodeInPlace(input: []const u8, output: []u8, scratch: []u8) Failure!usize {
    const options = try decodeOptions(input);
    return lzma.decodeInPlace(input[header_size..], output, scratch, options);
}

pub fn decodeToWriter(input: []const u8, writer: *std.Io.Writer, scratch: []u8) Failure!void {
    const options = try decodeOptions(input);
    return lzma.decodeToWriter(input[header_size..], writer, scratch, options);
}
