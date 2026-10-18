const std = @import("std");

const interface = @import("interface");

const exception = @import("../common/primitive/exception.zig");
const zstd = @import("../representation/leaf/zstd/onprem.zig");
const zstd_seam = @import("../representation/leaf/zstd/seam.zig");
const sizing = @import("sizing.zig");

pub const Exception = exception.Exception;
pub const Options = zstd.Options;
pub const zstdEncodeHistoryLen = sizing.encodeHistoryLen;

pub fn zstdEncodeBound(input_len: usize, options: Options) usize {
    return zstd.encodedSizeBound(input_len, options);
}

// Caller wires spans straight to the leaf, so byte-identity is expected.
pub fn zstdEncode(input: interface.span.ConstSpan, output: interface.span.Span, history: interface.span.Span, workspace: interface.span.Span, options: Options) Exception!usize {
    const bound = zstd.encodedSizeBound(input.len, options);
    if (output.len < bound) return error.CapacityException;
    var source = std.Io.Reader.fixed(input.bytes());
    var sink = std.Io.Writer.fixed(output.bytes());
    const aligned = try alignWorkspace(workspace);
    return zstd.encodeStream(&source, &sink, history.bytes(), aligned, options) catch |err| mapException(err);
}

// Bounded sizing checks capacity a priori and encodes once.
pub fn zstdDecodeStream(input: interface.span.ConstSpan, output: interface.span.Span, history: interface.span.Span, options: Options) Exception!usize {
    var source = std.Io.Reader.fixed(input.bytes());
    var sink = std.Io.Writer.fixed(output.bytes());
    return zstd_seam.decodeStream(options.provider, &source, &sink, history.bytes(), options) catch |err| mapException(err);
}

// Only resource limits propagate; every other leaf failure is malformed input.
fn mapException(err: anyerror) Exception {
    return switch (err) {
        error.ResourceException => error.ResourceException,
        error.UnsupportedException => error.UnsupportedException,
        else => error.DataException,
    };
}

fn alignWorkspace(workspace: interface.span.Span) Exception![]u32 {
    const base = @intFromPtr(workspace.ptr);
    const aligned = std.mem.alignForward(usize, base, @alignOf(u32));
    const gap = aligned - base;
    // A workspace smaller than the alignment padding cannot hold one word.
    if (workspace.len < gap + @sizeOf(u32)) return error.CapacityException;
    const bytes = workspace.bytes()[gap..];
    const trimmed: []align(4) u8 = @alignCast(bytes[0 .. bytes.len - bytes.len % @sizeOf(u32)]);
    return std.mem.bytesAsSlice(u32, trimmed);
}
