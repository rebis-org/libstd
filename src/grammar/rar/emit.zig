const std = @import("std");
const failure = @import("../../common/primitive/failure.zig");
const Failure = failure.Failure;
const sink = @import("../../common/sink.zig");
const window_mod = @import("window.zig");

// Filtered-emit discipline shared by the v29 and v50 unpackers. If no pending
// filter touches the span, the window emits straight to the sink; otherwise
// the span is materialised and every fully-contained filter is applied to the
// staged copy — the window must keep the RAW LZ bytes, because later solid
// entries match back into earlier entries' window regions. A filter that
// touches but is not contained in the span means block geometry disagrees
// with the stream: refuse rather than transform a partial range. The caller
// advances its flushed mark.
pub fn emitSpan(
    window: *window_mod.Window,
    out: sink.Sink,
    back: usize,
    span_start: usize,
    count: usize,
    pending: anytype,
    staged_buf: []u8,
    transform_scratch: []u8,
    ctx: anytype,
    comptime applyOne: fn (@TypeOf(ctx), *std.meta.Elem(@TypeOf(pending)), []u8, []u8) Failure!void,
) Failure!void {
    const span_end = span_start + count;
    var touches = false;
    for (pending) |*f| {
        if (f.length == 0) continue;
        const s: usize = @intCast(f.start);
        if (s < span_end and s + f.length > span_start) {
            touches = true;
            break;
        }
    }
    if (!touches) {
        if (!window.emitTo(out, back, count)) return error.InvalidData;
        return;
    }
    if (count > staged_buf.len) return error.InternalFailure;
    const staged = staged_buf[0..count];
    var staged_sink = sink.BufferSink.init(staged);
    if (!window.emitTo(staged_sink.sink(), back, count)) return error.InvalidData;
    if (staged_sink.overflowed) return error.InvalidData;
    for (pending) |*f| {
        if (f.length == 0) continue;
        const s: usize = @intCast(f.start);
        if (s + f.length <= span_start or s >= span_end) continue;
        if (s < span_start or s + f.length > span_end) return error.Unsupported;
        try applyOne(ctx, f, staged[s - span_start ..][0..f.length], transform_scratch);
        f.length = 0;
    }
    out.write(staged);
}
