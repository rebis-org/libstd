const std = @import("std");

const checksum = @import("../../common/primitive/checksum.zig");
const exception_prim = @import("../../common/primitive/exception.zig");
const deflate = @import("../../representation/leaf/deflate/onprem.zig");
const deflate_seam = @import("../../representation/leaf/deflate/seam.zig");
const sessions = @import("../sessions.zig");
const inflate = @import("inflate.zig");
const session = @import("session.zig");
const stage = @import("stage.zig");
const step = @import("step.zig");

const testing = std.testing;
const Exception = exception_prim.Exception;
const StepResult = sessions.StepResult;
const pending_cap = inflate.pending_cap;
const pumpInflated = inflate.pumpInflated;
const restageInflated = inflate.restageInflated;
const carveHistory = session.carveHistory;
const stateSize = session.stateSize;
const encodeFailed = step.encodeFailed;
const framingFailed = step.framingFailed;

// Raw DEFLATE decode session: the gzip driver minus framing.
// Trailing bytes after the final block are an error.
pub const DeflateDecode = struct {
    inflater: deflate_seam.Decode,
    history: []u8 = &.{},
    pending: [pending_cap]u8,
    pending_len: usize = 0,
    started: bool = false,
    budgets: sessions.Budgets,

    fn restage(self: *DeflateDecode, input: []const u8, result: *StepResult) Exception!void {
        return restageInflated(&self.inflater, self.pending[0..], &self.pending_len, input, result);
    }
};

pub fn deflateDecodeStorage() usize {
    return stateSize(DeflateDecode) + deflate.history_size;
}

pub fn deflateDecodeInit(storage: []u8, budgets: sessions.Budgets) error{ CapacityException, UnsupportedException }!*DeflateDecode {
    const carved = try carveHistory(DeflateDecode, storage, deflate.history_size);
    const state = carved.state;
    const history = carved.history;
    state.* = .{
        .inflater = undefined,
        .history = history,
        .pending = undefined,
        .budgets = budgets,
    };
    state.inflater.initSliceBoundInPlace(deflate_seam.default_provider, &.{}, history) catch return error.UnsupportedException;
    return state;
}

const deflate_decode_pair = session.Pair(.{ .state = DeflateDecode, .storage = deflateDecodeStorage, .init = deflateDecodeInit, .step = deflateDecodeStep });
pub const deflateDecodeSession = deflate_decode_pair.session;

fn noteDeflateDecoded(state: *DeflateDecode, slice: []const u8) void {
    _ = state;
    _ = slice;
}

pub fn deflateDecodeStep(state: *DeflateDecode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
    var result = StepResult{};
    state.restage(input, &result) catch |exception| {
        return framingFailed(&result, 0, exception);
    };
    // The whole step input stages into pending, so the encoded side is charged once here.
    state.budgets.addEncoded(input.len) catch |exception| {
        return framingFailed(&result, 0, exception);
    };
    state.budgets.addWork(input.len) catch |exception| {
        return framingFailed(&result, 0, exception);
    };
    if (!state.started) {
        state.inflater.initSliceBoundInPlace(deflate_seam.default_provider, state.pending[0..state.pending_len], state.history) catch |exception| return framingFailed(&result, 0, exception);
        state.started = true;
    }
    if (output.len != 0 and result.produced < output.len) {
        if (pumpInflated(state, &result, output, input.len, end_of_input, noteDeflateDecoded)) |terminal| return terminal;
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
        .ended => |stream_end| {
            if (stream_end != state.pending_len) {
                return framingFailed(&result, input.len, error.DataException);
            }
            result.consumed = input.len;
            result.status = .done;
            return result;
        },
    }
}

// Pending output must absorb the worst case: the deflate bound plus
// staging flush granularity and one block's table overhead.
pub const encode_pending_len: usize = pending_cap + 32768;

const EncodeWrap = enum { raw, gzip, zlib };

const DeflateEncode = struct {
    const Self = @This();
    compressor: deflate.Compress,
    history: []u8 = &.{},
    downstream: std.Io.Writer,
    stage: stage.Stage(encode_pending_len),
    header_written: bool = false,
    finished: bool = false,
    hasher: checksum.Crc32,
    adler: checksum.Adler32,
    size: u64 = 0,
    budgets: sessions.Budgets,
};

fn writePrologue(comptime wrap: EncodeWrap, state: *DeflateEncode) Exception!void {
    switch (wrap) {
        .raw => {},
        .gzip => {
            if (state.stage.room() < 10) return error.CapacityException;
            const header = [10]u8{ 0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 255 };
            @memcpy(state.stage.buf[state.stage.len..][0..10], &header);
            state.stage.len += 10;
            state.hasher = checksum.Crc32.init({});
        },
        .zlib => {
            if (state.stage.room() < 2) return error.CapacityException;
            // The cinfo 7 (32 KiB window) with a valid fcheck: 0x78 0x9C.
            const header = [2]u8{ 0x78, 0x9C };
            @memcpy(state.stage.buf[state.stage.len..][0..2], &header);
            state.stage.len += 2;
            state.adler = checksum.Adler32.init({});
        },
    }
    state.header_written = true;
}

fn writeEpilogue(comptime wrap: EncodeWrap, state: *DeflateEncode) Exception!void {
    switch (wrap) {
        .raw => {},
        .gzip => {
            if (state.stage.room() < 8) return error.CapacityException;
            var trailer: [8]u8 = undefined;
            std.mem.writeInt(u32, trailer[0..4], state.hasher.final({}), .little);
            std.mem.writeInt(u32, trailer[4..8], @truncate(state.size), .little);
            @memcpy(state.stage.buf[state.stage.len..][0..8], &trailer);
            state.stage.len += 8;
        },
        .zlib => {
            if (state.stage.room() < 4) return error.CapacityException;
            var trailer: [4]u8 = undefined;
            std.mem.writeInt(u32, &trailer, state.adler.final({}), .big);
            @memcpy(state.stage.buf[state.stage.len..][0..4], &trailer);
            state.stage.len += 4;
        },
    }
}

const deflate_encode_options: deflate.Options = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 8 };

fn encodeStorage() usize {
    return stateSize(DeflateEncode) + deflate.history_size;
}

fn deflateEncodeInitImpl(storage: []u8, budgets: sessions.Budgets) error{CapacityException}!*DeflateEncode {
    const carved = try carveHistory(DeflateEncode, storage, deflate.history_size);
    const state = carved.state;
    const history = carved.history;
    state.* = .{
        .compressor = undefined,
        .history = history,
        .stage = .{},
        .downstream = undefined,
        .hasher = checksum.Crc32.init({}),
        .adler = checksum.Adler32.init({}),
        .budgets = budgets,
    };
    state.downstream = std.Io.Writer.fixed(&state.stage.buf);
    state.compressor = deflate.Compress.init(&state.downstream, history, deflate_encode_options) catch return error.CapacityException;
    return state;
}

fn deflateEncodeStep(comptime wrap: EncodeWrap, state: *DeflateEncode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
    var result = StepResult{};
    state.stage.drain(output, &result);
    if (!state.header_written) {
        writePrologue(wrap, state) catch |exception| {
            return encodeFailed(&result, exception);
        };
        state.stage.drain(output, &result);
    }
    if (input.len > 0) {
        if (!state.finished) {
            // The pending tail must absorb this step's worst-case expansion plus the
            // epilogue; the leaf's analytic bound is the honest requirement.
            const needed = deflate.encodedSizeBound(input.len);
            if (state.stage.room() < needed) {
                result.required_capacity = needed - state.stage.room();
                return encodeFailed(&result, error.CapacityException);
            }
            state.downstream.end = state.stage.len;
            state.downstream.buffer = state.stage.buf[0..];
            state.compressor.writer.writeAll(input) catch {
                return encodeFailed(&result, error.InternalException);
            };
            state.stage.len = state.downstream.end;
            switch (wrap) {
                .raw => {},
                .gzip => state.hasher.update(input),
                .zlib => state.adler.update(input),
            }
            state.size = std.math.add(u64, state.size, input.len) catch return encodeFailed(&result, error.ResourceException);
            state.budgets.addDecoded(input.len) catch |exception| return encodeFailed(&result, exception);
            state.budgets.addWork(input.len) catch |exception| return encodeFailed(&result, exception);
            result.consumed = input.len;
        } else {
            // The decode side errors on trailing input, so input after the
            // final block must be an error here too.
            return encodeFailed(&result, error.CallException);
        }
    }
    if (end_of_input and !state.finished) {
        state.downstream.end = state.stage.len;
        state.downstream.buffer = state.stage.buf[0..];
        state.compressor.finish() catch {
            return encodeFailed(&result, error.InternalException);
        };
        state.stage.len = state.downstream.end;
        writeEpilogue(wrap, state) catch |exception| {
            return encodeFailed(&result, exception);
        };
        state.finished = true;
    }
    state.stage.drain(output, &result);
    state.budgets.addEncoded(result.produced) catch |exception| return encodeFailed(&result, exception);
    state.budgets.addWork(result.produced) catch |exception| return encodeFailed(&result, exception);
    if (state.finished and state.stage.read == 0 and state.stage.len == 0) {
        result.status = .done;
        return result;
    }
    result.status = .open;
    return result;
}

// The session boundary names these wrappers, so their signatures are part of the seam.

fn deflateEncodeStepRaw(state: *DeflateEncode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
    return deflateEncodeStep(.raw, state, input, output, end_of_input);
}

fn gzipEncodeStepRaw(state: *DeflateEncode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
    return deflateEncodeStep(.gzip, state, input, output, end_of_input);
}

fn zlibEncodeStepRaw(state: *DeflateEncode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
    return deflateEncodeStep(.zlib, state, input, output, end_of_input);
}

const deflate_encode_pair = session.Pair(.{ .state = DeflateEncode, .storage = encodeStorage, .init = deflateEncodeInitImpl, .step = deflateEncodeStepRaw });
pub const deflateEncodeStorage = deflate_encode_pair.storage;
pub const deflateEncodeInit = deflate_encode_pair.init;
pub const deflateEncodeSession = deflate_encode_pair.session;

const gzip_encode_pair = session.Pair(.{ .state = DeflateEncode, .storage = encodeStorage, .init = deflateEncodeInitImpl, .step = gzipEncodeStepRaw });
pub const gzipEncodeStorage = gzip_encode_pair.storage;
pub const gzipEncodeInit = gzip_encode_pair.init;
pub const gzipEncodeSession = gzip_encode_pair.session;

const zlib_encode_pair = session.Pair(.{ .state = DeflateEncode, .storage = encodeStorage, .init = deflateEncodeInitImpl, .step = zlibEncodeStepRaw });
pub const zlibEncodeStorage = zlib_encode_pair.storage;
pub const zlibEncodeInit = zlib_encode_pair.init;
pub const zlibEncodeSession = zlib_encode_pair.session;

test "encode sessions wrap one core with distinct framing and budgets" {
    const fixtures = @import("../../testing/support.zig");
    const allocator = testing.allocator;
    const holder = try fixtures.allocStateStorage(DeflateEncode, encodeStorage(), allocator);
    defer allocator.free(holder.raw);
    var out: [4096]u8 = undefined;

    // Empty streams expose pure framing: one deflate core under three wraps, so each length differs by its prologue plus epilogue.
    var frames: [3][32]u8 = undefined;
    var lengths: [3]usize = undefined;
    inline for (.{ .raw, .gzip, .zlib }, 0..) |wrap, index| {
        const state = try deflateEncodeInitImpl(holder.aligned, .{});
        const result = deflateEncodeStep(wrap, state, &.{}, &out, true);
        try testing.expectEqual(sessions.StepStatus.done, result.status);
        @memcpy(frames[index][0..result.produced], out[0..result.produced]);
        lengths[index] = result.produced;
    }
    try testing.expectEqual(lengths[0] + 18, lengths[1]);
    try testing.expectEqual(lengths[0] + 6, lengths[2]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 255 }, frames[1][0..10]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x78, 0x9C }, frames[2][0..2]);

    var payload: [600]u8 = undefined;
    fixtures.fillPayload(&payload);

    // The encoded side charges compressed output.
    {
        const state = try gzipEncodeInit(holder.aligned, .{ .max_encoded = 64 });
        var pos: usize = 0;
        var tripped = false;
        var guard: usize = 0;
        while (guard < 100) : (guard += 1) {
            const take = @min(128, payload.len - pos);
            const result = deflateEncodeStep(.gzip, state, payload[pos..][0..take], &out, pos + take == payload.len);
            pos += result.consumed;
            if (result.status == .failed) {
                try testing.expectEqual(error.ResourceException, result.exception.?);
                tripped = true;
                break;
            }
            if (result.status == .done) break;
        }
        try testing.expect(tripped);
    }

    // The decoded side charges raw input before any compression happens.
    {
        const state = try gzipEncodeInit(holder.aligned, .{ .max_decoded = 32 });
        const result = deflateEncodeStep(.gzip, state, payload[0..128], &out, false);
        try testing.expectEqual(sessions.StepStatus.failed, result.status);
        try testing.expectEqual(error.ResourceException, result.exception.?);
    }

    // The work side charges consumed plus produced: input trips a small
    // ceiling; output trips one that passes the input.
    {
        const state = try gzipEncodeInit(holder.aligned, .{ .max_work = 32 });
        const result = deflateEncodeStep(.gzip, state, payload[0..128], &out, false);
        try testing.expectEqual(sessions.StepStatus.failed, result.status);
        try testing.expectEqual(error.ResourceException, result.exception.?);
    }
    {
        const state = try gzipEncodeInit(holder.aligned, .{ .max_work = 128 });
        const result = deflateEncodeStep(.gzip, state, payload[0..128], &out, false);
        try testing.expectEqual(sessions.StepStatus.failed, result.status);
        try testing.expectEqual(error.ResourceException, result.exception.?);
    }

    // Input after the finished stream is a call error, matching the decode side.
    {
        const state = try gzipEncodeInit(holder.aligned, .{});
        const first = deflateEncodeStep(.gzip, state, "hi", &out, true);
        try testing.expectEqual(sessions.StepStatus.done, first.status);
        const second = deflateEncodeStep(.gzip, state, "more", &out, true);
        try testing.expectEqual(sessions.StepStatus.failed, second.status);
        try testing.expectEqual(error.CallException, second.exception.?);
    }
}
