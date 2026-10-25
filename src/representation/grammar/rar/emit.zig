const std = @import("std");

const exception = @import("../../../common/primitive/exception.zig");
const sink = @import("../../../common/sink.zig");
const window_mod = @import("window.zig");

const Exception = exception.Exception;

// The window must keep raw LZ bytes for later solid matches, so filters
// apply to a staged copy.
pub fn emitSpan(
    window: *window_mod.Window,
    out: sink.Sink,
    back: usize,
    span_start: usize,
    count: usize,
    start_base: usize,
    pending: anytype,
    staged_buf: []u8,
    transform_scratch: []u8,
    ctx: anytype,
    comptime applyOne: fn (@TypeOf(ctx), *std.meta.Elem(@TypeOf(pending)), []u8, []u8) Exception!void,
) Exception!void {
    const span_end = span_start + count;
    var touches = false;
    for (pending) |*f| {
        if (f.length == 0) continue;
        const s: usize = @intCast(f.start - start_base);
        if (s < span_end and s + f.length > span_start) {
            touches = true;
            break;
        }
    }
    if (!touches) {
        if (!window.emitTo(out, back, count)) return error.DataException;
        return;
    }
    if (count > staged_buf.len) return error.InternalException;
    const staged = staged_buf[0..count];
    var staged_sink = sink.BufferSink.init(staged);
    if (!window.emitTo(staged_sink.sink(), back, count)) return error.DataException;
    if (staged_sink.overflowed) return error.DataException;
    for (pending) |*f| {
        if (f.length == 0) continue;
        const s: usize = @intCast(f.start - start_base);
        if (s + f.length <= span_start or s >= span_end) continue;
        if (s < span_start or s + f.length > span_end) return error.UnsupportedException;
        try applyOne(ctx, f, staged[s - span_start ..][0..f.length], transform_scratch);
        f.length = 0;
    }
    out.write(staged);
}
