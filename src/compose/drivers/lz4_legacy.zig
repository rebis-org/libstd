const std = @import("std");

const lz4 = @import("../../representation/leaf/lz4/onprem.zig");
const sessions = @import("../sessions.zig");
const lz4_family = @import("lz4.zig");
const session = @import("session.zig");
const stage = @import("stage.zig");
const step = @import("step.zig");

const StepResult = sessions.StepResult;
const lz4BlockCompressBound = lz4_family.lz4BlockCompressBound;
const stateSize = session.stateSize;
const framingFailed = step.framingFailed;

// Pre-1.8 legacy frame (magic 0x184C2102 plus version nibble): raw LZ4
// blocks up to 8 MiB, no descriptor or checksums, EOF-terminated.
const lz4_legacy_block_size: usize = 8 * 1024 * 1024;
const lz4_legacy_bound: usize = lz4BlockCompressBound(lz4_legacy_block_size);
const lz4_legacy_magic: u32 = 0x184C2102;

const Lz4LegacyPhase = enum { magic, block_size, block_data, block_drain, done };

pub const Lz4LegacyDecode = struct {
    phase: Lz4LegacyPhase = .magic,
    stage: stage.Stage(lz4_legacy_bound) = .{},
    staging: []u8 = &.{},
    staging_len: usize = 0,
    out: []u8 = &.{},
    out_len: usize = 0,
    out_read: usize = 0,
    block_len: usize = 0,
    budgets: sessions.Budgets,
};

pub fn lz4LegacyDecodeStorage() usize {
    return stateSize(Lz4LegacyDecode) + lz4_legacy_bound + lz4_legacy_block_size;
}

pub fn lz4LegacyDecodeInit(storage: []u8, budgets: sessions.Budgets) error{CapacityException}!*Lz4LegacyDecode {
    const size = stateSize(Lz4LegacyDecode);
    if (storage.len < size + lz4_legacy_bound + lz4_legacy_block_size) return error.CapacityException;
    const state: *Lz4LegacyDecode = @ptrCast(@alignCast(storage.ptr));
    state.* = .{
        .staging = storage[size..][0..lz4_legacy_bound],
        .out = storage[size + lz4_legacy_bound ..][0..lz4_legacy_block_size],
        .budgets = budgets,
    };
    return state;
}

const lz4_legacy_decode_pair = session.Pair(.{ .state = Lz4LegacyDecode, .storage = lz4LegacyDecodeStorage, .init = lz4LegacyDecodeInit, .step = lz4LegacyDecodeStep });
pub const lz4LegacyDecodeSession = lz4_legacy_decode_pair.session;

pub fn lz4LegacyDecodeStep(state: *Lz4LegacyDecode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
    var result = StepResult{};
    if (state.phase == .done) {
        // The slice route requires the frame to end exactly at input end.
        if (input.len > 0) return framingFailed(&result, 0, error.DataException);
        result.consumed = 0;
        result.status = .done;
        return result;
    }
    state.stage.compact() catch |exception| {
        return framingFailed(&result, 0, exception);
    };
    var accepted: usize = 0;
    while (accepted < input.len and state.stage.len < state.stage.buf.len) {
        state.stage.buf[state.stage.len] = input[accepted];
        state.stage.len += 1;
        accepted += 1;
    }
    result.consumed = accepted;
    state.budgets.addEncoded(accepted) catch |exception| {
        return framingFailed(&result, accepted, exception);
    };
    var stalled = false;
    while (!stalled) {
        const avail = state.stage.available();
        switch (state.phase) {
            .magic => {
                switch (state.stage.need(4, end_of_input)) {
                    .enough => {},
                    .stall => {
                        stalled = true;
                        continue;
                    },
                    .truncated => return framingFailed(&result, accepted, error.DataException),
                }
                const magic_value = std.mem.readInt(u32, avail[0..4], .little);
                if (magic_value < lz4_legacy_magic or magic_value > lz4_legacy_magic + 7) return framingFailed(&result, accepted, error.DataException);
                state.stage.read += 4;
                state.phase = .block_size;
            },
            .block_size => {
                switch (state.stage.need(4, end_of_input)) {
                    .enough => {},
                    .stall => {
                        stalled = true;
                        continue;
                    },
                    .truncated => {
                        // EOF at a block boundary ends the frame; a partial
                        // size word is truncation.
                        if (state.stage.read == state.stage.len) {
                            state.phase = .done;
                            result.status = .done;
                            return result;
                        }
                        return framingFailed(&result, accepted, error.DataException);
                    },
                }
                const block_len: usize = std.mem.readInt(u32, avail[0..4], .little);
                state.stage.read += 4;
                if (block_len == 0) {
                    // The kernel terminator: nothing may follow, matching
                    // the slice route's exact-consumption check.
                    if (end_of_input and state.stage.read < state.stage.len) return framingFailed(&result, accepted, error.DataException);
                    state.phase = .done;
                    result.status = .done;
                    return result;
                }
                if (block_len > lz4_legacy_bound) return framingFailed(&result, accepted, error.DataException);
                state.block_len = block_len;
                state.staging_len = 0;
                state.phase = .block_data;
            },
            .block_data => {
                const want = state.block_len - state.staging_len;
                const take = @min(want, avail.len);
                @memcpy(state.staging[state.staging_len..][0..take], avail[0..take]);
                state.staging_len += take;
                state.stage.read += take;
                if (state.staging_len == state.block_len) {
                    state.out_len = lz4.decompressBlock(state.staging[0..state.staging_len], state.out, &[_]u8{}) catch |err| {
                        return framingFailed(&result, accepted, switch (err) {
                            error.DataException => error.DataException,
                            error.OutputTooSmall => error.DataException,
                        });
                    };
                    state.out_read = 0;
                    state.budgets.addDecoded(state.out_len) catch |exception| {
                        return framingFailed(&result, accepted, exception);
                    };
                    state.phase = .block_drain;
                } else if (end_of_input) {
                    return framingFailed(&result, accepted, error.DataException);
                } else {
                    stalled = true;
                }
            },
            .block_drain => {
                const take = @min(state.out_len - state.out_read, output.len - result.produced);
                if (take > 0) {
                    @memcpy(output[result.produced..][0..take], state.out[state.out_read..][0..take]);
                    result.produced += take;
                    state.out_read += take;
                }
                if (state.out_read == state.out_len) {
                    state.phase = .block_size;
                } else {
                    stalled = true;
                }
            },
            .done => {
                result.status = .done;
                return result;
            },
        }
    }
    return result;
}
