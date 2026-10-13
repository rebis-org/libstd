const std = @import("std");

const bounds = @import("../../common/primitive/bounds.zig");
const failure_prim = @import("../../common/primitive/failure.zig");
const io = @import("../../common/primitive/io.zig");
const measurement = @import("../../common/primitive/measurement.zig");
const lzma = @import("../../leaf/lzma/onprem.zig");
const lzma_seam = @import("../../leaf/lzma/seam.zig");

const Failure = failure_prim.Failure;

pub const header_size = 13;
pub const default_dictionary: u32 = 1 << 20;

pub fn decodeOptions(input: []const u8) Failure!lzma.Options {
    const header = try bounds.slice(input, 0, header_size);
    var dictionary_size = std.mem.readInt(u32, header[1..5], .little);
    if (dictionary_size < lzma.dictionary_min) dictionary_size = lzma.dictionary_min;
    if (dictionary_size > lzma.dictionary_max) return error.UnsupportedFailure;
    const unpack_size = std.mem.readInt(u64, header[5..13], .little);
    // The lzma alone format marks an unknown size with the maximum u64 value, which requires the end marker.
    const marker_required = unpack_size == std.math.maxInt(u64);
    return .{
        .properties = try lzma.Properties.decode(header[0], dictionary_size),
        .unpack_size = if (marker_required) null else unpack_size,
        .marker_required = marker_required,
    };
}

// A declared size accompanies a markerless stream. A caller that sizes later
// passes unpack_size = null and gets the end marker.
pub fn encodeOptions(dictionary: u32) Failure!lzma.Options {
    if (dictionary < lzma.dictionary_min or dictionary > lzma.dictionary_max) return error.CallFailure;
    return .{
        .properties = .{ .lc = 3, .lp = 0, .pb = 2, .dictionary_size = dictionary },
        .unpack_size = null,
        .marker_required = false,
    };
}

pub fn encodeToWriter(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: lzma.Options) Failure!void {
    var header: [header_size]u8 = undefined;
    header[0] = options.properties.encode();
    std.mem.writeInt(u32, header[1..5], options.properties.dictionary_size, .little);
    if (options.unpack_size) |size| {
        std.mem.writeInt(u64, header[5..13], size, .little);
    } else {
        @memset(header[5..13], 0xff);
    }
    try io.writeBytes(writer, &header);
    try lzma.encodeToWriter(input, writer, scratch, options);
}

pub fn encode(input: []const u8, output: []u8, scratch: []u8, options: lzma.Options) Failure!usize {
    var writer = std.Io.Writer.fixed(output);
    try encodeToWriter(input, &writer, scratch, options);
    return writer.end;
}

pub fn requiredSize(input: []const u8, scratch: []u8, options: lzma.Options) Failure!usize {
    var counter = measurement.Counter.init(null);
    try encodeToWriter(input, &counter.writer, scratch, options);
    return measurement.measuredLength(&counter);
}

pub fn encodedSizeBound(input_len: usize) usize {
    return lzma.encodedSizeBound(input_len) +| header_size;
}

// The lzma-alone properties byte (lc + 9 * lp + 45 * pb) for the read-side
// inspect projection, parsed without decoding.
pub fn inspectProperties(input: []const u8) Failure!u8 {
    if (input.len < header_size) return error.DataFailure;
    if (input[0] >= 9 * 5 * 5) return error.DataFailure;
    return input[0];
}

pub fn decodedSize(input: []const u8, scratch: []u8, provider: lzma_seam.Provider) Failure!usize {
    const options = try decodeOptions(input);
    return lzma_seam.decodedSize(provider, input[header_size..], scratch, options);
}

pub fn decode(input: []const u8, output: []u8, scratch: []u8, provider: lzma_seam.Provider) Failure!usize {
    const options = try decodeOptions(input);
    return lzma_seam.decode(provider, input[header_size..], output, scratch, options);
}

pub fn decodeInPlace(input: []const u8, output: []u8, scratch: []u8, provider: lzma_seam.Provider) Failure!usize {
    const options = try decodeOptions(input);
    return lzma_seam.decodeInPlace(provider, input[header_size..], output, scratch, options);
}

pub fn decodeToWriter(input: []const u8, writer: *std.Io.Writer, scratch: []u8, provider: lzma_seam.Provider) Failure!void {
    const options = try decodeOptions(input);
    return lzma_seam.decodeToWriter(provider, input[header_size..], writer, scratch, options);
}

test "lzma file container round trip restores the original input" {
    var options = try encodeOptions(1 << 20);
    options.unpack_size = 2000;
    const scratch = try std.testing.allocator.alloc(u8, @max(lzma.encodeWorkspaceSizeBt(options.properties), lzma.decodeWorkspaceSize(options.properties)));
    defer std.testing.allocator.free(scratch);
    const input = comptime blk: {
        @setEvalBranchQuota(4000);
        const phrase = "the lzma alone container wraps a raw stream in a 13 byte header. ";
        var buf: [2000]u8 = undefined;
        for (&buf, 0..) |*byte, i| byte.* = phrase[i % phrase.len];
        break :blk buf;
    };
    options.unpack_size = input.len;
    const bound = encodedSizeBound(input.len);
    const encoded = try std.testing.allocator.alloc(u8, bound);
    defer std.testing.allocator.free(encoded);
    const encoded_len = try encode(&input, encoded, scratch, options);
    const header = try decodeOptions(encoded[0..encoded_len]);
    try std.testing.expectEqual(@as(?u64, input.len), header.unpack_size);
    try std.testing.expect(!header.marker_required);
    const decoded = try std.testing.allocator.alloc(u8, input.len);
    defer std.testing.allocator.free(decoded);
    const produced = try decode(encoded[0..encoded_len], decoded, scratch, lzma_seam.default_provider);
    try std.testing.expectEqualSlices(u8, &input, decoded[0..produced]);
}

pub const HeaderInfo = struct {
    properties: lzma.Properties,
    dictionary_size: u32,
    // null when the header declares the maximum u64, the marker form.
    unpack_size: ?u64,
    has_marker: bool,
};

// Parses the 13-byte lzma-alone header without touching the payload.
pub fn inspect(input: []const u8) Failure!HeaderInfo {
    const options = try decodeOptions(input);
    return .{
        .properties = options.properties,
        .dictionary_size = options.properties.dictionary_size,
        .unpack_size = options.unpack_size,
        .has_marker = options.marker_required,
    };
}

test "inspect parses the lzma-alone header" {
    const allocator = std.testing.allocator;
    const data = "header inspection payload, header inspection payload";
    const properties: lzma.Properties = .{ .lc = 3, .lp = 0, .pb = 2, .dictionary_size = default_dictionary };
    const bound = encodedSizeBound(data.len);
    const encoded = try allocator.alloc(u8, bound);
    defer allocator.free(encoded);
    const scratch = try allocator.alloc(u8, lzma.encodeWorkspaceSizeBt(properties));
    defer allocator.free(scratch);
    const encoded_len = try encode(data, encoded, scratch, .{
        .properties = properties,
        .unpack_size = data.len,
        .marker_required = false,
    });
    const info = try inspect(encoded[0..encoded_len]);
    try std.testing.expectEqual(@as(u64, data.len), info.unpack_size.?);
    try std.testing.expect(!info.has_marker);
    try std.testing.expectEqual(default_dictionary, info.dictionary_size);
    try std.testing.expectEqual(@as(u8, 3), info.properties.lc);
}
