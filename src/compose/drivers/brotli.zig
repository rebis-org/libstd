const brotli = @import("../../representation/leaf/brotli/onprem.zig");
const sessions = @import("../sessions.zig");
const session = @import("session.zig");
const stage = @import("stage.zig");
const step = @import("step.zig");

const StepResult = sessions.StepResult;
const stateSize = session.stateSize;
const framingFailed = step.framingFailed;

// Incremental decode owns the history ring; the session stages input, drains
// output, and suspends on starvation or a full span.
const brotli_in_staging_len: usize = 4 << 20;
const brotli_out_staging_len: usize = 1 << 20;

pub const BrotliDecode = struct {
    inc: brotli.Incremental,
    pending: []u8 = &.{},
    pending_len: usize = 0,
    pending_read: usize = 0,
    out: []u8 = &.{},
    out_read: usize = 0,
    // The decoder reports done while staging still holds undrained output;
    // answer done only once the staging is empty.
    finishing: bool = false,
    budgets: sessions.Budgets,
};

pub fn brotliDecodeStorage() usize {
    return stateSize(BrotliDecode) + brotli.incrementalWorkspaceSize(.{}) + brotli_in_staging_len + brotli_out_staging_len;
}

pub fn brotliDecodeInit(storage: []u8, budgets: sessions.Budgets) error{ CapacityException, UnsupportedException }!*BrotliDecode {
    const size = stateSize(BrotliDecode);
    const ws = brotli.incrementalWorkspaceSize(.{});
    if (storage.len < size + ws + brotli_in_staging_len + brotli_out_staging_len) return error.CapacityException;
    const state: *BrotliDecode = @ptrCast(@alignCast(storage.ptr));
    const workspace = storage[size..][0..ws];
    state.* = .{
        .inc = brotli.incrementalInit(workspace, .{}) catch return error.CapacityException,
        .pending = storage[size + ws ..][0..brotli_in_staging_len],
        .out = storage[size + ws + brotli_in_staging_len ..][0..brotli_out_staging_len],
        .budgets = budgets,
    };
    return state;
}

const brotli_decode_pair = session.Pair(.{ .state = BrotliDecode, .storage = brotliDecodeStorage, .init = brotliDecodeInit, .step = brotliDecodeStep });
pub const brotliDecodeSession = brotli_decode_pair.session;

pub fn brotliDecodeStep(state: *BrotliDecode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
    var result = StepResult{};
    stage.compactPending(state.pending[0..], &state.pending_len, state.pending_read) catch |exception| {
        return framingFailed(&result, 0, exception);
    };
    state.pending_read = 0;
    var accepted: usize = 0;
    while (accepted < input.len and state.pending_len < state.pending.len) {
        state.pending[state.pending_len] = input[accepted];
        state.pending_len += 1;
        accepted += 1;
    }
    result.consumed = accepted;
    // The stream's own end flag reaches the decoder only once the caller's
    // input is fully staged.
    const stream_end = end_of_input and accepted == input.len;
    while (true) {
        const res = state.inc.run(state.pending[state.pending_read..state.pending_len], state.out[state.out_read..], stream_end) catch |exception| {
            return framingFailed(&result, accepted, exception);
        };
        state.pending_read += res.consumed;
        state.out_read += res.produced;
        state.budgets.addEncoded(res.consumed) catch |exception| {
            return framingFailed(&result, accepted, exception);
        };
        state.budgets.addWork(res.consumed) catch |exception| {
            return framingFailed(&result, accepted, exception);
        };
        const take = @min(state.out_read, output.len - result.produced);
        if (take > 0) {
            @memcpy(output[result.produced..][0..take], state.out[0..take]);
            result.produced += take;
            state.out_read -= take;
            if (state.out_read > 0) @memmove(state.out[0..state.out_read], state.out[take .. take + state.out_read]);
            state.budgets.addWork(take) catch |exception| {
                return framingFailed(&result, accepted, exception);
            };
            state.budgets.addDecoded(take) catch |exception| {
                return framingFailed(&result, accepted, exception);
            };
        }
        if (res.status == .done) state.finishing = true;
        if (state.finishing and state.out_read == 0) {
            result.status = .done;
            return result;
        }
        if (state.out_read > 0) return result; // Caller's output is full.
        if (accepted < input.len) return result; // Staging is full; the caller re-feeds.
        if (res.consumed == 0 and res.produced == 0) return result; // Starved, awaiting input.
    }
}
