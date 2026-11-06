const std = @import("std");

const checksum = @import("../../common/primitive/checksum.zig");
const exception_prim = @import("../../common/primitive/exception.zig");
const deflate = @import("../../representation/leaf/deflate/onprem.zig");
const deflate_seam = @import("../../representation/leaf/deflate/seam.zig");
const sessions = @import("../sessions.zig");
const inflate = @import("inflate.zig");
const session = @import("session.zig");
const step = @import("step.zig");

const Exception = exception_prim.Exception;
const StepResult = sessions.StepResult;
const pending_cap = inflate.pending_cap;
const pumpInflated = inflate.pumpInflated;
const restageInflated = inflate.restageInflated;
const carveHistory = session.carveHistory;
const stateSize = session.stateSize;
const framingFailed = step.framingFailed;

const zlib_cm_deflate: u8 = 8;
const zlib_cinfo_max: u8 = 7;
const zlib_flag_dictionary: u8 = 0x20;
const zlib_header_size: usize = 2;
const zlib_trailer_size: usize = 4;

pub const ZlibDecode = struct {
    inflater: deflate_seam.Decode,
    history: []u8 = &.{},
    pending: [pending_cap]u8,
    pending_len: usize = 0,
    started: bool = false,
    adler: checksum.Adler32,
    budgets: sessions.Budgets,

    fn restage(self: *ZlibDecode, input: []const u8, result: *StepResult) Exception!void {
        return restageInflated(&self.inflater, self.pending[0..], &self.pending_len, input, result);
    }
};

pub fn zlibDecodeStorage() usize {
    return stateSize(ZlibDecode) + deflate.history_size;
}

pub fn zlibDecodeInit(storage: []u8, budgets: sessions.Budgets) error{ CapacityException, UnsupportedException }!*ZlibDecode {
    const carved = try carveHistory(ZlibDecode, storage, deflate.history_size);
    const state = carved.state;
    const history = carved.history;
    state.* = .{
        .inflater = undefined,
        .history = history,
        .pending = undefined,
        .adler = checksum.Adler32.init({}),
        .budgets = budgets,
    };
    state.inflater.initSliceBoundInPlace(deflate_seam.default_provider, &.{}, history) catch return error.UnsupportedException;
    return state;
}

const zlib_decode_pair = session.Pair(.{ .state = ZlibDecode, .storage = zlibDecodeStorage, .init = zlibDecodeInit, .step = zlibDecodeStep });
pub const zlibDecodeSession = zlib_decode_pair.session;

fn noteZlibDecoded(state: *ZlibDecode, slice: []const u8) void {
    state.adler.update(slice);
}

pub fn zlibDecodeStep(state: *ZlibDecode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
    var result = StepResult{};
    state.restage(input, &result) catch |exception| {
        return framingFailed(&result, 0, exception);
    };
    // The whole step input stages into pending, so the encoded side is charged once here.
    state.budgets.addEncoded(input.len) catch |exception| {
        return framingFailed(&result, 0, exception);
    };
    if (!state.started) {
        if (state.pending_len < zlib_header_size) {
            if (end_of_input) return framingFailed(&result, input.len, error.DataException);
            result.consumed = input.len;
            result.status = .open;
            return result;
        }
        const cmf = state.pending[0];
        const flg = state.pending[1];
        if (cmf & 0x0F != zlib_cm_deflate) return framingFailed(&result, input.len, error.UnsupportedException);
        if ((cmf >> 4) > zlib_cinfo_max) return framingFailed(&result, input.len, error.UnsupportedException);
        if ((@as(u32, cmf) * 256 + @as(u32, flg)) % 31 != 0) return framingFailed(&result, input.len, error.DataException);
        if (flg & zlib_flag_dictionary != 0) return framingFailed(&result, input.len, error.UnsupportedException);
        state.adler = checksum.Adler32.init({});
        state.inflater.initSliceBoundInPlace(deflate_seam.default_provider, state.pending[0..state.pending_len], state.history) catch |exception| return framingFailed(&result, input.len, exception);
        state.inflater.setFramePos(zlib_header_size);
        state.started = true;
    }
    if (output.len != 0 and result.produced < output.len) {
        if (pumpInflated(state, &result, output, input.len, end_of_input, noteZlibDecoded)) |terminal| return terminal;
    }
    switch (inflate.finish(&state.inflater)) {
        .streaming => {
            result.consumed = input.len;
            if (end_of_input and state.inflater.streamPosition() == state.pending_len) {
                return framingFailed(&result, input.len, error.DataException);
            }
            result.status = .open;
            return result;
        },
        .draining => {
            result.consumed = input.len;
            result.status = .open;
            return result;
        },
        .ended => |trailer_pos| {
            if (state.pending_len - trailer_pos < zlib_trailer_size) {
                if (end_of_input) return framingFailed(&result, input.len, error.DataException);
                result.consumed = input.len;
                result.status = .open;
                return result;
            }
            const stored_adler = std.mem.readInt(u32, state.pending[trailer_pos..][0..4], .big);
            if (stored_adler != state.adler.final({})) return framingFailed(&result, input.len, error.IntegrityException);
            const total = trailer_pos + zlib_trailer_size;
            if (total != state.pending_len) return framingFailed(&result, input.len, error.DataException);
            result.consumed = input.len;
            result.status = .done;
            return result;
        },
    }
}
