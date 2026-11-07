const std = @import("std");

const tar = @import("../../representation/grammar/tar/onprem.zig");
const sessions = @import("../sessions.zig");
const session = @import("session.zig");
const step = @import("step.zig");

const testing = std.testing;
const StepResult = sessions.StepResult;
const stateSize = session.stateSize;
const framingFailed = step.framingFailed;

// Stepped tar writer: per entry the caller streams a 512-byte header then
// raw data. Pax spill entries pass through unchanged.
const TarEncodePhase = enum { header, data, pad, trailer, done };

pub const TarEncode = struct {
    phase: TarEncodePhase = .header,
    hold: [512]u8 = undefined,
    hold_len: usize = 0,
    entry_size: u64 = 0,
    data_remaining: u64 = 0,
    pad_len: usize = 0,
    trailer_remaining: usize = 0,
    budgets: sessions.Budgets,
};

pub fn tarEncodeStorage() usize {
    return stateSize(TarEncode);
}

pub fn tarEncodeInit(storage: []u8, budgets: sessions.Budgets) error{CapacityException}!*TarEncode {
    if (storage.len < stateSize(TarEncode)) return error.CapacityException;
    const state: *TarEncode = @ptrCast(@alignCast(storage.ptr));
    state.* = .{ .budgets = budgets };
    return state;
}

const tar_encode_pair = session.Pair(.{ .state = TarEncode, .storage = tarEncodeStorage, .init = tarEncodeInit, .step = tarEncodeStep });
pub const tarEncodeSession = tar_encode_pair.session;

pub fn tarEncodeStep(state: *TarEncode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
    var result = StepResult{};
    var in_off: usize = 0;
    var out_off: usize = 0;
    while (true) {
        switch (state.phase) {
            .header => {
                if (in_off >= input.len) {
                    if (end_of_input and state.hold_len == 0) {
                        state.phase = .trailer;
                        state.trailer_remaining = 1024;
                        continue;
                    }
                    if (end_of_input) return framingFailed(&result, in_off, error.DataException);
                    break;
                }
                if (state.hold_len == 0 and input.len - in_off >= 512 and output.len - out_off >= 512) {
                    // A whole block fits both sides, so the hold buffer stays out of the path.
                    @memcpy(output[out_off..][0..512], input[in_off..][0..512]);
                    in_off += 512;
                    out_off += 512;
                    const size = tar.parseHeaderDataSize(output[out_off - 512 ..][0..512]) catch |exception| {
                        return framingFailed(&result, in_off, exception);
                    };
                    state.entry_size = size;
                    state.data_remaining = size;
                    state.phase = .data;
                    continue;
                }
                const take = @min(512 - state.hold_len, input.len - in_off);
                @memcpy(state.hold[state.hold_len..][0..take], input[in_off..][0..take]);
                state.hold_len += take;
                in_off += take;
                if (state.hold_len == 512) {
                    if (output.len - out_off < 512) {
                        // The header block must land whole; ask the caller
                        // for more output room. Keep the hold.
                        result.status = .open;
                        break;
                    }
                    @memcpy(output[out_off..][0..512], &state.hold);
                    out_off += 512;
                    const size = tar.parseHeaderDataSize(&state.hold) catch |exception| {
                        return framingFailed(&result, in_off, exception);
                    };
                    state.hold_len = 0;
                    state.entry_size = size;
                    state.data_remaining = size;
                    state.phase = .data;
                }
            },
            .data => {
                if (state.data_remaining == 0) {
                    state.pad_len = @intCast((512 - (state.entry_size % 512)) % 512);
                    state.phase = .pad;
                    continue;
                }
                if (in_off >= input.len) {
                    if (end_of_input) return framingFailed(&result, in_off, error.DataException);
                    break;
                }
                const want: usize = @intCast(@min(state.data_remaining, std.math.maxInt(u32)));
                const take = @min(want, @min(input.len - in_off, output.len - out_off));
                if (take == 0) break;
                @memcpy(output[out_off..][0..take], input[in_off..][0..take]);
                in_off += take;
                out_off += take;
                state.data_remaining -= take;
            },
            .pad => {
                if (state.pad_len == 0) {
                    state.phase = .header;
                    continue;
                }
                if (output.len - out_off == 0) break;
                const take = @min(state.pad_len, output.len - out_off);
                @memset(output[out_off..][0..take], 0);
                out_off += take;
                state.pad_len -= take;
                if (state.pad_len == 0) {
                    state.phase = .header;
                    continue;
                }
            },
            .trailer => {
                if (state.trailer_remaining == 0) {
                    state.phase = .done;
                    result.status = .done;
                    break;
                }
                if (output.len - out_off == 0) break;
                const take = @min(state.trailer_remaining, output.len - out_off);
                @memset(output[out_off..][0..take], 0);
                out_off += take;
                state.trailer_remaining -= take;
                if (state.trailer_remaining == 0) {
                    state.phase = .done;
                    result.status = .done;
                }
            },
            .done => {
                // The slice encoder writes nothing after the trailer; any
                // further input is a caller error.
                if (in_off < input.len) return framingFailed(&result, in_off, error.DataException);
                result.status = .done;
                break;
            },
        }
        // Stall exits live inside each phase; reaching here means a phase
        // transition asked for another iteration.
    }
    result.consumed = in_off;
    result.produced = out_off;
    state.budgets.addDecoded(in_off) catch |exception| {
        return framingFailed(&result, in_off, exception);
    };
    state.budgets.addEncoded(out_off) catch |exception| {
        return framingFailed(&result, in_off, exception);
    };
    state.budgets.addWork(in_off + out_off) catch |exception| {
        return framingFailed(&result, in_off, exception);
    };
    return result;
}

test "tar encode closes with trailer blocks and rejects broken endings" {
    const fixtures = @import("../../testing/support.zig");
    const allocator = testing.allocator;
    const holder = try fixtures.allocStateStorage(TarEncode, tarEncodeStorage(), allocator);
    defer allocator.free(holder.raw);

    // Storage below the state plan never initializes.
    try testing.expectError(error.CapacityException, tarEncodeInit(holder.aligned[0 .. tarEncodeStorage() - 1], .{}));

    // End of input with nothing in flight emits only the two zero trailer blocks.
    {
        const state = try tarEncodeInit(holder.aligned, .{});
        var out: [1024]u8 = undefined;
        const result = tarEncodeStep(state, &.{}, &out, true);
        try testing.expectEqual(sessions.StepStatus.done, result.status);
        try testing.expectEqual(@as(usize, 1024), result.produced);
        for (out) |byte| try testing.expectEqual(@as(u8, 0), byte);
        // Input after the trailer is a caller error, not silence.
        const after = tarEncodeStep(state, "x", &out, true);
        try testing.expectEqual(sessions.StepStatus.failed, after.status);
        try testing.expectEqual(error.DataException, after.exception.?);
    }

    // A partial header at end of input is dangling plaintext, not end of stream.
    {
        const state = try tarEncodeInit(holder.aligned, .{});
        var out: [1024]u8 = undefined;
        const partial: [100]u8 = @splat(0x5a);
        const result = tarEncodeStep(state, &partial, &out, true);
        try testing.expectEqual(sessions.StepStatus.failed, result.status);
        try testing.expectEqual(error.DataException, result.exception.?);
    }

    // Framed plaintext charges the decoded budget as it is consumed.
    {
        var payload: [512]u8 = undefined;
        fixtures.fillPayload(&payload);
        const state = try tarEncodeInit(holder.aligned, .{ .max_decoded = 32 });
        var out: [512]u8 = undefined;
        const result = tarEncodeStep(state, payload[0..128], &out, false);
        try testing.expectEqual(sessions.StepStatus.failed, result.status);
        try testing.expectEqual(error.ResourceException, result.exception.?);
    }
}
