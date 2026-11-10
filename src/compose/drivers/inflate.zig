const std = @import("std");

const exception_prim = @import("../../common/primitive/exception.zig");
const deflate_seam = @import("../../representation/leaf/deflate/seam.zig");
const composition = @import("../composition.zig");
const sessions = @import("../sessions.zig");
const stage = @import("stage.zig");
const step = @import("step.zig");

const Exception = exception_prim.Exception;
const StepResult = sessions.StepResult;
const framingFailed = step.framingFailed;

// The three framings close a deflate stream identically; one tri-state
// answers, and each driver keeps only its own trailer semantics.

pub const Boundary = union(enum) {
    // The final block has not ended; the stream needs more input or output.
    streaming,
    // The final block ended, but the window still holds decoded bytes.
    draining,
    // The stream ends at this byte offset, epoch-relative.
    ended: usize,
};

pub fn finish(inflater: *deflate_seam.Decode) Boundary {
    if (!inflater.atEnd()) return .streaming;
    const reader = inflater.readerPtr();
    if (reader.seek < reader.end) return .draining;
    // The stream ends at consumed bits: word-granular refill over-reads
    // past the final block; the end offset is epoch-relative.
    const consumed_bits = inflater.inputBitsConsumed();
    return .{ .ended = (consumed_bits + 7) / 8 };
}

// Framing reads ahead through shared pending; per-step compaction bounds it.
// Step chunks must satisfy chunk_len <= pending_cap - 8.
pub const pending_cap: usize = 131072;

pub fn restageInflated(inflater: *deflate_seam.Decode, pending: []u8, pending_len: *usize, input: []const u8, result: *StepResult) Exception!void {
    const consumed = inflater.streamPosition();
    // Word-granular refill over-reads past logical floor; those bytes back live accumulator bits and must survive compaction, else end-of-stream conversion underflows.
    const floor = inflater.inputBitsConsumed() / 8;
    try stage.compactPending(pending, pending_len, floor);
    try stage.appendStaged(pending, pending_len, input, result);
    inflater.restage(pending[0..pending_len.*], consumed - floor);
}

// Suspension versus corruption is distinguishable only by position; flushed
// partials count first. A non-null return is terminal for the step.
pub fn pumpInflated(
    state: anytype,
    result: *StepResult,
    output: []u8,
    input_len: usize,
    end_of_input: bool,
    comptime note: fn (@TypeOf(state), []const u8) void,
) ?StepResult {
    var sink = std.Io.Writer.fixed(output[result.produced..]);
    const limit = composition.limitFor(output.len - result.produced);
    // Through the arm, not its reader: only the arm knows its own window bookkeeping.
    const emitted = state.inflater.streamTo(&sink, limit) catch |err| {
        const partial = sink.end;
        if (partial > 0) {
            result.produced += partial;
            note(state, output[result.produced - partial ..][0..partial]);
            state.budgets.addWork(partial) catch |exception| {
                return framingFailed(result, input_len, exception);
            };
            state.budgets.addDecoded(partial) catch |exception| {
                return framingFailed(result, input_len, exception);
            };
        }
        // Both arms report a finished member as end-of-stream; the caller reads atEnd() for the boundary.
        if (err == error.EndOfStream and state.inflater.atEnd()) return null;
        // Starvation suspends cleanly with the leaf resumable; a failed leaf is
        // corruption; starvation at input end is a short stream.
        if (err == error.ReadFailed and !state.inflater.isFailed() and !end_of_input) {
            state.inflater.clearFailure();
            result.consumed = input_len;
            result.status = .open;
            return result.*;
        }
        return framingFailed(result, input_len, error.DataException);
    };
    result.produced += emitted;
    note(state, output[result.produced - emitted ..][0..emitted]);
    state.budgets.addWork(emitted) catch |exception| {
        return framingFailed(result, input_len, exception);
    };
    state.budgets.addDecoded(emitted) catch |exception| {
        return framingFailed(result, input_len, exception);
    };
    return null;
}
