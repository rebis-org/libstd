const std = @import("std");

const build_options = @import("options");
const seam = @import("seam");

const offprem = @import("offprem.zig");
const onprem = @import("onprem.zig");

const impl = build_options.leaf_impl;
// One dispatch per call, never per chunk or symbol; see offprem.zig for the
// incompleteness choosing stdlib accepts.
pub const Provider = seam.Provider;
pub const Exception = offprem.Exception;
pub const InPlaceResult = onprem.InPlaceResult;
pub const Options = onprem.Options;

// The stdlib decode shapes take no options; one shim per verb drops the
// parameter so a single dispatch carries both arms.
fn offDecode(input: []const u8, output: []u8, scratch: []u8, _: Options) Exception!usize {
    return offprem.decode(input, output, scratch);
}

fn offDecodeInPlace(input: []const u8, output: []u8, scratch: []u8, _: Options) Exception!InPlaceResult {
    return offprem.decodeInPlace(input, output, scratch);
}

fn offDecodeStream(reader: *std.Io.Reader, writer: *std.Io.Writer, scratch: []u8, _: Options) Exception!void {
    return offprem.decodeStream(reader, writer, scratch);
}

fn offDecodedSize(input: []const u8, scratch: []u8, _: Options) Exception!usize {
    return offprem.decodedSize(input, scratch);
}

pub fn decode(provider: Provider, input: []const u8, output: []u8, scratch: []u8, options: Options) Exception!usize {
    return seam.dispatch(impl, provider, onprem.decode, offDecode, .{ input, output, scratch, options });
}

pub fn decodeInPlace(provider: Provider, input: []const u8, output: []u8, scratch: []u8, options: Options) Exception!InPlaceResult {
    return seam.dispatch(impl, provider, onprem.decodeInPlace, offDecodeInPlace, .{ input, output, scratch, options });
}

pub fn decodeStream(provider: Provider, reader: *std.Io.Reader, writer: *std.Io.Writer, scratch: []u8, options: Options) Exception!void {
    return seam.dispatch(impl, provider, onprem.decodeStream, offDecodeStream, .{ reader, writer, scratch, options });
}

pub fn decodedSize(provider: Provider, input: []const u8, scratch: []u8, options: Options) Exception!usize {
    return seam.dispatch(impl, provider, onprem.decodedSize, offDecodedSize, .{ input, scratch, options });
}
