const std = @import("std");

const checksum = @import("../../common/primitive/checksum.zig");
const exception_prim = @import("../../common/primitive/exception.zig");
const measurement = @import("../../common/primitive/measurement.zig");
const gzip = @import("../../representation/grammar/gzip/onprem.zig");
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
const carveHistory = session.carveHistory;
const stateSize = session.stateSize;
const framingFailed = step.framingFailed;

const id1: u8 = 0x1f;
const id2: u8 = 0x8b;
const method_deflate: u8 = 8;
const flag_hcrc: u8 = 0x02;
const flag_extra: u8 = 0x04;
const flag_name: u8 = 0x08;
const flag_comment: u8 = 0x10;
const reserved_flags: u8 = 0xe0;

pub const Phase = enum { idle, fixed, extra_len, extra_skip, extra_field, name, comment, hcrc, deflate, trailer, done };

pub const GzipDecode = struct {
    inflater: deflate_seam.Decode,
    history: []u8 = &.{},
    pending: [pending_cap]u8,
    pending_len: usize = 0,
    frame_pos: usize = 0,
    phase: Phase = .idle,
    fixed: [10]u8,
    fixed_len: usize = 0,
    hcrc: [2]u8,
    hcrc_len: usize = 0,
    extra_low: u8 = 0,
    extra_remaining: usize = 0,
    header_crc: checksum.Crc32,
    member_crc: checksum.Crc32,
    member_size: u64 = 0,
    trailer: [8]u8,
    trailer_len: usize = 0,
    budgets: sessions.Budgets,

    fn nextByte(self: *GzipDecode) ?u8 {
        if (self.frame_pos >= self.pending_len) return null;
        const byte = self.pending[self.frame_pos];
        self.frame_pos += 1;
        return byte;
    }

    fn availableInput(self: *GzipDecode) []const u8 {
        return self.pending[self.frame_pos..self.pending_len];
    }

    fn restage(self: *GzipDecode, input: []const u8, result: *StepResult) Exception!void {
        const consumed = self.inflater.streamPosition();
        // Deflate keeps bytes backing live accumulator bits; framing phases
        // read pending directly, so their floor is frame_pos.
        const floor = if (self.phase == .deflate) self.inflater.inputBitsConsumed() / 8 else self.frame_pos;
        try stage.compactPending(self.pending[0..], &self.pending_len, floor);
        if (floor > 0) {
            if (self.phase == .deflate) {
                // frame_pos is stale while the inflater owns the stream.
                // Re-established from slice.pos at member end.
                self.frame_pos = 0;
            } else {
                self.frame_pos -= floor;
            }
        }
        try stage.appendStaged(self.pending[0..], &self.pending_len, input, result);
        if (self.phase == .deflate) {
            self.inflater.restage(self.pending[0..self.pending_len], consumed - floor);
        } else {
            self.inflater.restage(self.pending[0..self.pending_len], if (floor > 0) 0 else consumed);
        }
    }

    // Each step's whole chunk is accepted into pending.
    // Consumed is the accepted length and bytes are never re-sent.
    fn streamPosition(self: *const GzipDecode) usize {
        return if (self.phase == .deflate) self.inflater.streamPosition() else self.frame_pos;
    }
};

pub fn gzipDecodeStorage() usize {
    return stateSize(GzipDecode) + deflate.history_size;
}

pub fn gzipDecodeInit(storage: []u8, budgets: sessions.Budgets) error{ CapacityException, UnsupportedException }!*GzipDecode {
    const carved = try carveHistory(GzipDecode, storage, deflate.history_size);
    const state = carved.state;
    const history = carved.history;
    // The pending/fixed/trailer fields stay undefined until the header/trailer parse writes them before any read.
    state.* = .{
        .inflater = undefined,
        .history = history,
        .pending = undefined,
        .fixed = undefined,
        .hcrc = undefined,
        .header_crc = checksum.Crc32.init({}),
        .member_crc = checksum.Crc32.init({}),
        .trailer = undefined,
        .budgets = budgets,
    };
    state.inflater.initSliceBoundInPlace(deflate_seam.default_provider, &.{}, history) catch return error.UnsupportedException;
    return state;
}

// Each member starts a fresh deflate stream at frame_pos, where framing last read.
fn enterDeflate(state: *GzipDecode) error{UnsupportedException}!void {
    try state.inflater.initSliceBoundInPlace(deflate_seam.default_provider, state.pending[0..state.pending_len], state.history);
    state.inflater.setFramePos(state.frame_pos);
    state.phase = .deflate;
}

const gzip_decode_pair = session.Pair(.{ .state = GzipDecode, .storage = gzipDecodeStorage, .init = gzipDecodeInit, .step = gzipDecodeStep });
pub const gzipDecodeSession = gzip_decode_pair.session;

fn noteGzipDecoded(state: *GzipDecode, slice: []const u8) void {
    state.member_crc.update(slice);
    state.member_size += slice.len;
}

fn selectPostHeaderPhase(state: *GzipDecode) error{UnsupportedException}!void {
    const flags = state.fixed[3];
    if (flags & flag_extra != 0) {
        state.phase = .extra_len;
    } else if (flags & flag_name != 0) {
        state.phase = .name;
    } else if (flags & flag_comment != 0) {
        state.phase = .comment;
    } else if (flags & flag_hcrc != 0) {
        state.phase = .hcrc;
    } else {
        try enterDeflate(state);
    }
}

pub fn gzipDecodeStep(state: *GzipDecode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
    var result = StepResult{};
    state.restage(input, &result) catch |exception| {
        return framingFailed(&result, 0, exception);
    };
    // The whole step input stages into pending, so the encoded side is charged once here.
    state.budgets.addEncoded(input.len) catch |exception| {
        return framingFailed(&result, 0, exception);
    };

    // Trailer is read in the same step as end-of-stream so consumed accounting covers the whole member.
    outer: while (true) {
        framing: {
            while (true) {
                switch (state.phase) {
                    .done => break :framing,
                    .idle => {
                        const byte = state.nextByte() orelse break :framing;
                        state.fixed[0] = byte;
                        state.fixed_len = 1;
                        state.hcrc_len = 0;
                        state.header_crc = checksum.Crc32.init({});
                        state.header_crc.update(&.{byte});
                        state.phase = .fixed;
                    },
                    .fixed => {
                        while (state.fixed_len < state.fixed.len) {
                            const byte = state.nextByte() orelse break :framing;
                            state.fixed[state.fixed_len] = byte;
                            state.header_crc.update(&.{byte});
                            state.fixed_len += 1;
                        }
                        const fixed = &state.fixed;
                        if (fixed[0] != id1 or fixed[1] != id2) return framingFailed(&result, input.len, error.DataException);
                        if (fixed[2] != method_deflate) return framingFailed(&result, input.len, error.UnsupportedException);
                        if (fixed[3] & reserved_flags != 0) return framingFailed(&result, input.len, error.DataException);
                        state.member_crc = checksum.Crc32.init({});
                        state.member_size = 0;
                        selectPostHeaderPhase(state) catch |exception| return framingFailed(&result, input.len, exception);
                    },
                    .extra_len => {
                        const low = state.nextByte() orelse break :framing;
                        state.extra_low = low;
                        state.header_crc.update(&.{low});
                        state.phase = .extra_skip;
                    },
                    .extra_skip => {
                        const high = state.nextByte() orelse break :framing;
                        state.header_crc.update(&.{high});
                        state.extra_remaining = (@as(usize, high) << 8) | state.extra_low;
                        state.phase = .extra_field;
                    },
                    .extra_field => {
                        while (state.extra_remaining != 0) : (state.extra_remaining -= 1) {
                            const byte = state.nextByte() orelse break :framing;
                            state.header_crc.update(&.{byte});
                        }
                        // Once XLEN drains, the flag bits pick the next field.
                        if (state.fixed[3] & flag_name != 0) {
                            state.phase = .name;
                        } else if (state.fixed[3] & flag_comment != 0) {
                            state.phase = .comment;
                        } else if (state.fixed[3] & flag_hcrc != 0) {
                            state.phase = .hcrc;
                        } else {
                            enterDeflate(state) catch |exception| return framingFailed(&result, input.len, exception);
                        }
                    },
                    .name, .comment => {
                        while (true) {
                            const byte = state.nextByte() orelse break :framing;
                            state.header_crc.update(&.{byte});
                            if (byte == 0) break;
                        }
                        if (state.phase == .name and state.fixed[3] & flag_comment != 0) {
                            state.phase = .comment;
                        } else if (state.fixed[3] & flag_hcrc != 0) {
                            state.phase = .hcrc;
                        } else {
                            enterDeflate(state) catch |exception| return framingFailed(&result, input.len, exception);
                        }
                    },
                    .hcrc => {
                        // HCRC16 persists across suspension like the fixed header: a local
                        // buffer would drop a byte consumed at the staging boundary.
                        while (state.hcrc_len < state.hcrc.len) {
                            const byte = state.nextByte() orelse break :framing;
                            state.hcrc[state.hcrc_len] = byte;
                            state.hcrc_len += 1;
                        }
                        const expected = std.mem.readInt(u16, &state.hcrc, .little);
                        if (expected != @as(u16, @truncate(state.header_crc.final({})))) return framingFailed(&result, input.len, error.IntegrityException);
                        enterDeflate(state) catch |exception| return framingFailed(&result, input.len, exception);
                    },
                    .deflate => break :framing,
                    .trailer => {
                        while (state.trailer_len < state.trailer.len) {
                            const byte = state.nextByte() orelse break :framing;
                            state.trailer[state.trailer_len] = byte;
                            state.trailer_len += 1;
                        }
                        const stored_crc = std.mem.readInt(u32, state.trailer[0..4], .little);
                        const stored_size = std.mem.readInt(u32, state.trailer[4..8], .little);
                        if (stored_crc != state.member_crc.final({})) return framingFailed(&result, input.len, error.IntegrityException);
                        if (stored_size != @as(u32, @truncate(state.member_size))) return framingFailed(&result, input.len, error.IntegrityException);
                        state.phase = .idle;
                    },
                }
            }
        }

        if (state.phase == .done) {
            result.status = .done;
            result.consumed = input.len;
            return result;
        }

        if (state.phase != .deflate) {
            result.consumed = input.len;
            if (state.phase == .idle) {
                if (end_of_input and state.availableInput().len == 0) {
                    state.phase = .done;
                    result.status = .done;
                } else {
                    result.status = .open;
                }
            } else if (end_of_input) {
                return framingFailed(&result, input.len, error.DataException);
            } else {
                result.status = .open;
            }
            return result;
        }

        // Slice input suspends atomically with state written back, so refill and re-step resume mid-symbol.
        if (result.produced < output.len) {
            if (pumpInflated(state, &result, output, input.len, end_of_input, noteGzipDecoded)) |terminal| return terminal;
            switch (inflate.finish(&state.inflater)) {
                .streaming => break,
                .draining => {
                    if (result.produced < output.len) continue;
                    break;
                },
                .ended => |end_pos| {
                    state.frame_pos = end_pos;
                    state.inflater.setFramePos(end_pos);
                    state.phase = .trailer;
                    state.trailer_len = 0;
                    continue :outer;
                },
            }
        } else {
            // Output full (or empty): suspend mid-deflate with progress preserved.
            // The caller resumes with a fresh buffer.
            break;
        }
    }

    result.consumed = input.len;
    result.status = .open;
    return result;
}

// Bounded encodes once against the analytic bound; measured sizes
// exactly first. Output bytes are identical.
pub const GzipEncodeSizing = enum { measured, bounded };

pub const default_encode_options: gzip.Options = .{
    .modification_time = 0,
    .extra_flags = 0,
    .operating_system = 255,
    .text = false,
    .header_crc = false,
    .extra = &.{},
    .name = &.{},
    .comment = &.{},
    .deflate = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 8 },
};

pub fn gzipEncodedSizeBound(input_len: usize) usize {
    return gzip.encodedSizeBound(input_len, default_encode_options);
}

pub fn gzipEncode(output: []u8, input: []const u8, history: []u8, options: gzip.Options, sizing: GzipEncodeSizing) Exception!usize {
    if (history.len < gzip.deflate_history_size) return error.CapacityException;
    switch (sizing) {
        .bounded => {
            const bound = gzip.encodedSizeBound(input.len, options);
            if (output.len < bound) return error.CapacityException;
            var source = std.Io.Reader.fixed(input);
            var sink = std.Io.Writer.fixed(output);
            gzip.encodeStream(&source, &sink, history, options) catch return error.IoException;
            return sink.end;
        },
        .measured => {
            var counter = measurement.Counter.init(null);
            {
                var source = std.Io.Reader.fixed(input);
                gzip.encodeStream(&source, &counter.writer, history, options) catch return error.IoException;
            }
            const exact = try measurement.measuredLength(&counter);
            if (output.len < exact) return error.CapacityException;
            var source = std.Io.Reader.fixed(input);
            var sink = std.Io.Writer.fixed(output);
            gzip.encodeStream(&source, &sink, history, options) catch return error.IoException;
            return sink.end;
        },
    }
}

test "gzip decode charges both budget sides and refuses corrupt members" {
    const fixtures = @import("../../testing/support.zig");
    const allocator = testing.allocator;
    var payload: [600]u8 = undefined;
    fixtures.fillPayload(&payload);
    const history = try allocator.alloc(u8, gzip.deflate_history_size);
    defer allocator.free(history);
    const gzip_frame = try allocator.alloc(u8, gzipEncodedSizeBound(payload.len));
    defer allocator.free(gzip_frame);
    const gzip_len = try gzipEncode(gzip_frame, &payload, history, default_encode_options, .bounded);

    const holder = try fixtures.allocStateStorage(GzipDecode, gzipDecodeStorage(), allocator);
    defer allocator.free(holder.raw);

    // Storage below the state plan plus history never initializes.
    try testing.expectError(error.CapacityException, gzipDecodeInit(holder.aligned[0 .. gzipDecodeStorage() - 1], .{}));

    // Bad magic is a data error, not a crash or a silent stall.
    {
        const state = try gzipDecodeInit(holder.aligned, .{});
        var out: [64]u8 = undefined;
        const bad_magic = [_]u8{ 0x1f, 0x8a, 8, 0, 0, 0, 0, 0, 0, 255 };
        const result = gzipDecodeStep(state, &bad_magic, &out, true);
        try testing.expectEqual(sessions.StepStatus.failed, result.status);
        try testing.expectEqual(error.DataException, result.exception.?);
    }

    // A flipped trailer CRC byte is an integrity failure.
    {
        const corrupt = try allocator.alloc(u8, gzip_len);
        defer allocator.free(corrupt);
        @memcpy(corrupt, gzip_frame[0..gzip_len]);
        corrupt[gzip_len - 8] ^= 0x01;
        try testing.expectError(error.IntegrityException, fixtures.expectChunkedDecode(GzipDecode, gzipDecodeInit, gzipDecodeStep, holder.aligned, corrupt, &payload, gzip_len, 4096));
    }

    // The encoded side charges accepted input as it arrives.
    {
        const state = try gzipDecodeInit(holder.aligned, .{ .max_encoded = 128 });
        var out: [64]u8 = undefined;
        var pos: usize = 0;
        var tripped = false;
        var guard: usize = 0;
        while (guard < 100) : (guard += 1) {
            const take = @min(64, gzip_len - pos);
            const result = gzipDecodeStep(state, gzip_frame[pos..][0..take], &out, pos + take == gzip_len);
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

    // The decoded side charges decompressed output; flushed partials land first.
    {
        const state = try gzipDecodeInit(holder.aligned, .{ .max_decoded = 32 });
        var out: [4096]u8 = undefined;
        const result = gzipDecodeStep(state, gzip_frame[0..gzip_len], &out, true);
        try testing.expectEqual(sessions.StepStatus.failed, result.status);
        try testing.expectEqual(error.ResourceException, result.exception.?);
        try testing.expectEqual(payload.len, result.produced);
    }
}

test "gzip header crc field survives a mid-field suspension" {
    const fixtures = @import("../../testing/support.zig");
    const allocator = testing.allocator;
    var payload: [600]u8 = undefined;
    fixtures.fillPayload(&payload);

    const hcrc_options: gzip.Options = b: {
        var options = default_encode_options;
        options.header_crc = true;
        break :b options;
    };
    const history = try allocator.alloc(u8, gzip.deflate_history_size);
    defer allocator.free(history);
    const hcrc_size = gzip.encodedSizeBound(payload.len, hcrc_options);
    const hcrc_frame = try allocator.alloc(u8, hcrc_size);
    defer allocator.free(hcrc_frame);
    const hcrc_len = try gzipEncode(hcrc_frame, &payload, history, hcrc_options, .bounded);

    // The option must engage: FLG carries FHCRC, the HCRC16 sits at bytes ten and eleven, matching header CRC32's low half.
    try testing.expect(hcrc_frame[3] & flag_hcrc != 0);
    try testing.expect(hcrc_len > 12);
    var header_crc = checksum.Crc32.init({});
    header_crc.update(hcrc_frame[0..10]);
    try testing.expectEqual(@as(u16, @truncate(header_crc.final({}))), std.mem.readInt(u16, hcrc_frame[10..12], .little));

    const holder = try fixtures.allocStateStorage(GzipDecode, gzipDecodeStorage(), allocator);
    defer allocator.free(holder.raw);
    // Every split of the twelve-byte header region, including between
    // the HCRC16 halves and the deflate start.
    inline for (1..17) |chunk| {
        try fixtures.expectChunkedDecode(GzipDecode, gzipDecodeInit, gzipDecodeStep, holder.aligned, hcrc_frame[0..hcrc_len], &payload, chunk, 4096);
    }

    // Multi-member: the second member resets the HCRC accumulator mid-stream.
    const two_member = try allocator.alloc(u8, hcrc_len * 2);
    defer allocator.free(two_member);
    @memcpy(two_member[0..hcrc_len], hcrc_frame[0..hcrc_len]);
    @memcpy(two_member[hcrc_len..], hcrc_frame[0..hcrc_len]);
    var joined: [payload.len * 2]u8 = undefined;
    @memcpy(joined[0..payload.len], &payload);
    @memcpy(joined[payload.len..], &payload);
    try fixtures.expectChunkedDecode(GzipDecode, gzipDecodeInit, gzipDecodeStep, holder.aligned, two_member, &joined, 11, 4096);
}
