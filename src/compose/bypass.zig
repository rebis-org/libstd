const std = @import("std");

const interface = @import("interface");

const failure = @import("../common/primitive/failure.zig");
const zstd = @import("../leaf/zstd/onprem.zig");
const zstd_seam = @import("../leaf/zstd/seam.zig");
const sizing = @import("sizing.zig");

pub const Failure = failure.Failure;
pub const Options = zstd.Options;
pub const zstdEncodeHistoryLen = sizing.encodeHistoryLen;

pub fn zstdEncodeBound(input_len: usize, options: Options) usize {
    return zstd.encodedSizeBound(input_len, options);
}

// Caller wires spans straight to the leaf, so byte-identity is expected.
pub fn zstdEncode(input: interface.span.ConstSpan, output: interface.span.Span, history: interface.span.Span, workspace: interface.span.Span, options: Options) Failure!usize {
    const bound = zstd.encodedSizeBound(input.len, options);
    if (output.len < bound) return error.CapacityFailure;
    var source = std.Io.Reader.fixed(input.bytes());
    var sink = std.Io.Writer.fixed(output.bytes());
    const aligned = try alignWorkspace(workspace);
    return zstd.encodeStream(&source, &sink, history.bytes(), aligned, options) catch |err| mapFailure(err);
}

// Bounded sizing checks capacity a priori and encodes once.
pub fn zstdDecodeStream(input: interface.span.ConstSpan, output: interface.span.Span, history: interface.span.Span, options: Options) Failure!usize {
    var source = std.Io.Reader.fixed(input.bytes());
    var sink = std.Io.Writer.fixed(output.bytes());
    return zstd_seam.decodeStream(options.provider, &source, &sink, history.bytes(), options) catch |err| mapFailure(err);
}

// Only resource limits propagate; every other leaf failure is malformed input.
fn mapFailure(err: anyerror) Failure {
    return switch (err) {
        error.ResourceFailure => error.ResourceFailure,
        error.UnsupportedFailure => error.UnsupportedFailure,
        else => error.DataFailure,
    };
}

fn alignWorkspace(workspace: interface.span.Span) Failure![]u32 {
    const base = @intFromPtr(workspace.ptr);
    const aligned = std.mem.alignForward(usize, base, @alignOf(u32));
    const bytes = workspace.bytes()[(aligned - base)..];
    const trimmed: []align(4) u8 = @alignCast(bytes[0 .. bytes.len - bytes.len % @sizeOf(u32)]);
    return std.mem.bytesAsSlice(u32, trimmed);
}
