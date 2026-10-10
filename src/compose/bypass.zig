const std = @import("std");

const interface = @import("interface");
pub const Failure = interface.span.Failure;

const zstd = @import("../leaf/zstd.zig");
pub const Options = zstd.Options;
const sizing = @import("sizing.zig");
pub const zstdEncodeHistoryLen = sizing.encodeHistoryLen;
pub const zstdDecodeHistoryLen = sizing.decodeHistoryLen;

// Caller wires spans straight to the leaf, so byte-identity is expected.

pub fn zstdEncodeBound(input_len: usize, options: Options) usize {
    return zstd.encodedSizeBound(input_len, options);
}

// History sizing mirrors the kernel path: frame boundaries reset matchfinder history, so differing sizes change encoded bytes.
// Only resource limits propagate. All other leaf failures map to invalid input.
fn mapFailure(err: anyerror) Failure {
    return switch (err) {
        error.ResourceLimit => error.ResourceLimit,
        else => error.InvalidData,
    };
}

// Bounded sizing checks capacity a priori and encodes once.
pub fn zstdEncode(input: interface.span.ConstSpan, output: interface.span.Span, history: interface.span.Span, workspace: interface.span.Span, options: Options) Failure!usize {
    const bound = zstd.encodedSizeBound(input.len, options);
    if (output.len < bound) return error.InsufficientCapacity;
    var source = std.Io.Reader.fixed(input.bytes());
    var sink = std.Io.Writer.fixed(output.bytes());
    const aligned = try alignWorkspace(workspace);
    return zstd.encodeStream(&source, &sink, history.bytes(), aligned, options) catch |err| mapFailure(err);
}

// Caller supplies exactly-sized spans with no padded staging.
pub fn zstdDecodeStream(input: interface.span.ConstSpan, output: interface.span.Span, history: interface.span.Span, options: Options) Failure!usize {
    var source = std.Io.Reader.fixed(input.bytes());
    var sink = std.Io.Writer.fixed(output.bytes());
    return zstd.decodeStream(&source, &sink, history.bytes(), options) catch |err| mapFailure(err);
}

fn alignWorkspace(workspace: interface.span.Span) Failure![]u32 {
    const base = @intFromPtr(workspace.ptr);
    const aligned = std.mem.alignForward(usize, base, @alignOf(u32));
    const bytes = workspace.bytes()[(aligned - base)..];
    const trimmed: []align(4) u8 = @alignCast(bytes[0 .. bytes.len - bytes.len % @sizeOf(u32)]);
    return std.mem.bytesAsSlice(u32, trimmed);
}
