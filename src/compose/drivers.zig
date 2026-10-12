const std = @import("std");

const checksum = @import("../common/primitive/checksum.zig");
const failure_prim = @import("../common/primitive/failure.zig");
const measurement = @import("../common/primitive/measurement.zig");
const gzip = @import("../grammar/gzip/onprem.zig");
const zlib = @import("../grammar/zlib/onprem.zig");
const deflate = @import("../leaf/deflate/onprem.zig");
const deflate_seam = @import("../leaf/deflate/seam.zig");
const lz4 = @import("../leaf/lz4/onprem.zig");
const composition = @import("composition.zig");
const sessions = @import("sessions.zig");

const Failure = failure_prim.Failure;
const StepResult = sessions.StepResult;

const id1: u8 = 0x1f;
const id2: u8 = 0x8b;
const method_deflate: u8 = 8;
const flag_hcrc: u8 = 0x02;
const flag_extra: u8 = 0x04;
const flag_name: u8 = 0x08;
const flag_comment: u8 = 0x10;
const reserved_flags: u8 = 0xe0;

// Framing reads ahead of the inflater via shared pending with per-step compaction for bounded memory. Step chunks must satisfy chunk_len <= pending_cap - 8.
pub const pending_cap: usize = 131072;

pub const Phase = enum { idle, fixed, extra_len, extra_skip, extra_field, name, comment, hcrc, deflate, trailer, done };

pub const GzipDecode = struct {
    inflater: deflate_seam.Decode,
    history: []u8 = &.{},
    pending: [pending_cap]u8,
    pending_len: usize = 0,
    leftover: usize = 0,
    frame_pos: usize = 0,
    phase: Phase = .idle,
    fixed: [10]u8,
    fixed_len: usize = 0,
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

    // The leftover snapshot records its length before this step appends, so consumed reporting covers only this step's bytes.
    fn restage(self: *GzipDecode, input: []const u8, result: *StepResult) Failure!void {
        const consumed = self.inflater.streamPosition();
        const floor = if (self.phase == .deflate) consumed else self.frame_pos;
        try compactPending(self.pending[0..], &self.pending_len, floor);
        if (floor > 0) {
            if (self.phase == .deflate) {
                // frame_pos is stale while the inflater owns the stream. Re-established from slice.pos at member end.
                self.frame_pos = 0;
            } else {
                self.frame_pos -= floor;
            }
        }
        try appendStaged(self.pending[0..], &self.pending_len, &self.leftover, input, result);
        self.inflater.restage(self.pending[0..self.pending_len], if (floor > 0) 0 else consumed);
    }

    // Each step's whole chunk is accepted into pending. Consumed is the accepted length and bytes are never re-sent.
    fn streamPosition(self: *const GzipDecode) usize {
        return if (self.phase == .deflate) self.inflater.streamPosition() else self.frame_pos;
    }
};

fn compactPending(pending: []u8, pending_len: *usize, floor: usize) Failure!void {
    if (floor > pending_len.*) return error.InternalFailure;
    if (floor > 0) {
        @memmove(pending[0 .. pending_len.* - floor], pending[floor..pending_len.*]);
        pending_len.* -= floor;
    }
}

fn appendStaged(pending: []u8, pending_len: *usize, leftover: *usize, input: []const u8, result: *StepResult) Failure!void {
    leftover.* = pending_len.*;
    if (input.len > pending.len - pending_len.*) {
        result.required_capacity = input.len - (pending.len - pending_len.*);
        return error.InsufficientCapacity;
    }
    @memcpy(pending[pending_len.*..][0..input.len], input);
    pending_len.* += input.len;
}

fn stateSize(comptime T: type) usize {
    return std.mem.alignForward(usize, @sizeOf(T), 16);
}

fn carveHistory(comptime T: type, storage: []u8, comptime history_len: usize) error{InsufficientCapacity}!struct { state: *T, history: []u8 } {
    const size = stateSize(T);
    if (storage.len < size + history_len) return error.InsufficientCapacity;
    return .{
        .state = @ptrCast(@alignCast(storage.ptr)),
        .history = storage[size..][0..history_len],
    };
}

fn restageInflated(inflater: *deflate_seam.Decode, pending: []u8, pending_len: *usize, leftover: *usize, input: []const u8, result: *StepResult) Failure!void {
    const consumed = inflater.streamPosition();
    try compactPending(pending, pending_len, consumed);
    try appendStaged(pending, pending_len, leftover, input, result);
    inflater.restage(pending[0..pending_len.*], if (consumed > 0) 0 else consumed);
}

pub fn gzipDecodeStorage() usize {
    return stateSize(GzipDecode) + deflate.history_size;
}

pub fn gzipDecodeInit(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!*GzipDecode {
    const carved = try carveHistory(GzipDecode, storage, deflate.history_size);
    const state = carved.state;
    const history = carved.history;
    // pending/fixed/trailer stay undefined until the header/trailer parse writes them before any read.
    state.* = .{
        .inflater = undefined,
        .history = history,
        .pending = undefined,
        .fixed = undefined,
        .header_crc = checksum.Crc32.init(),
        .member_crc = checksum.Crc32.init(),
        .trailer = undefined,
        .budgets = budgets,
    };
    state.inflater = deflate_seam.Decode.initSliceBound(deflate_seam.default_provider, &.{}, history) catch unreachable;
    return state;
}

// Each member needs a fresh deflate stream resuming at frame_pos, where framing read ahead to.
fn enterDeflate(state: *GzipDecode) void {
    state.inflater = deflate_seam.Decode.initSliceBound(deflate_seam.default_provider, state.pending[0..state.pending_len], state.history) catch unreachable;
    state.inflater.setFramePos(state.frame_pos);
    state.phase = .deflate;
}

// Both kernel-mediated and bypass paths run identical leaf code, so byte-identity is expected.
fn destroyNoop(state: *anyopaque) void {
    _ = state;
}

fn StepOps(comptime Driver: type, comptime step: fn (*Driver, []const u8, []u8, bool) StepResult) sessions.Ops {
    const S = struct {
        fn call(state: *anyopaque, input: []const u8, output: []u8, end_of_input: bool) StepResult {
            return step(@ptrCast(@alignCast(state)), input, output, end_of_input);
        }
    };
    return .{ .step = S.call, .destroy = destroyNoop };
}

const decode_ops = StepOps(GzipDecode, gzipDecodeStep);

pub fn gzipDecodeSession(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!sessions.Session {
    const state = try gzipDecodeInit(storage, budgets);
    return .{ .state = state, .ops = &decode_ops };
}

fn framingFailed(result: *StepResult, consumed: usize, failure: Failure) StepResult {
    result.consumed = consumed;
    result.status = .failed;
    result.failure = failure;
    return result.*;
}

fn selectPostHeaderPhase(state: *GzipDecode) void {
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
        enterDeflate(state);
    }
}

pub fn gzipDecodeStep(state: *GzipDecode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
    var result = StepResult{};
    state.restage(input, &result) catch |failure| {
        return framingFailed(&result, 0, failure);
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
                        state.header_crc = checksum.Crc32.init();
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
                        if (fixed[0] != id1 or fixed[1] != id2) return framingFailed(&result, state.frame_pos, error.InvalidData);
                        if (fixed[2] != method_deflate) return framingFailed(&result, state.frame_pos, error.Unsupported);
                        if (fixed[3] & reserved_flags != 0) return framingFailed(&result, state.frame_pos, error.InvalidData);
                        state.member_crc = checksum.Crc32.init();
                        state.member_size = 0;
                        selectPostHeaderPhase(state);
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
                        // XLEN is consumed once. Later fields chain from name.
                        if (state.fixed[3] & flag_name != 0) {
                            state.phase = .name;
                        } else if (state.fixed[3] & flag_comment != 0) {
                            state.phase = .comment;
                        } else if (state.fixed[3] & flag_hcrc != 0) {
                            state.phase = .hcrc;
                        } else {
                            enterDeflate(state);
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
                            enterDeflate(state);
                        }
                    },
                    .hcrc => {
                        var stored: [2]u8 = undefined;
                        for (&stored) |*slot| {
                            const byte = state.nextByte() orelse break :framing;
                            slot.* = byte;
                        }
                        const expected = std.mem.readInt(u16, &stored, .little);
                        if (expected != @as(u16, @truncate(state.header_crc.final()))) return framingFailed(&result, state.frame_pos, error.IntegrityFailure);
                        enterDeflate(state);
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
                        if (stored_crc != state.member_crc.final()) return framingFailed(&result, state.frame_pos, error.IntegrityFailure);
                        if (stored_size != @as(u32, @truncate(state.member_size))) return framingFailed(&result, state.frame_pos, error.IntegrityFailure);
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
                return framingFailed(&result, state.frame_pos, error.InvalidData);
            } else {
                result.status = .open;
            }
            return result;
        }

        // Slice input suspends atomically with state written back, so refill and re-step resumes mid-symbol.
        if (result.produced < output.len) {
            var sink = std.Io.Writer.fixed(output[result.produced..]);
            const limit = composition.limitFor(output.len - result.produced);
            const emitted = state.inflater.readerPtr().vtable.stream(state.inflater.readerPtr(), &sink, limit) catch {
                // Suspension vs corruption is distinguishable only by position (pending end vs early fail). Flushed bytes are real output and count first.
                const partial = sink.end;
                if (partial > 0) {
                    result.produced += partial;
                    state.member_crc.update(output[0..partial]);
                    state.member_size += partial;
                    state.budgets.addDecoded(partial) catch |failure| {
                        return framingFailed(&result, input.len, failure);
                    };
                }
                const starved = state.inflater.streamPosition() == state.pending_len;
                if (!end_of_input and starved) {
                    state.inflater.clearFailure();
                    result.consumed = input.len;
                    result.status = .open;
                    return result;
                }
                return framingFailed(&result, input.len, error.InvalidData);
            };
            result.produced += emitted;
            state.member_crc.update(output[result.produced - emitted ..][0..emitted]);
            state.member_size += emitted;
            state.budgets.addDecoded(emitted) catch |failure| {
                return framingFailed(&result, input.len, failure);
            };
            if (state.inflater.atEnd()) {
                if (state.inflater.readerPtr().seek < state.inflater.readerPtr().end) {
                    if (result.produced < output.len) continue;
                    break;
                }
                // Member ends at consumed bits, not buffered bytes: word-granular refill over-reads up to seven bytes past the final block.
                const consumed_bits = state.inflater.inputBitsConsumed();
                state.frame_pos = (consumed_bits + 7) / 8;
                state.inflater.setFramePos(state.frame_pos);
                state.phase = .trailer;
                state.trailer_len = 0;
                continue :outer;
            }
            break;
        }
    }

    result.consumed = input.len;
    result.status = .open;
    return result;
}

// Bounded checks capacity against the analytic bound and encodes once. Measured sizes exactly first. Output bytes identical either way.
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

pub fn gzipEncode(output: []u8, input: []const u8, history: []u8, options: gzip.Options, sizing: GzipEncodeSizing) Failure!usize {
    if (history.len < gzip.deflate_history_size) return error.InsufficientCapacity;
    switch (sizing) {
        .bounded => {
            const bound = gzip.encodedSizeBound(input.len, options);
            if (output.len < bound) return error.InsufficientCapacity;
            var source = std.Io.Reader.fixed(input);
            var sink = std.Io.Writer.fixed(output);
            gzip.encodeStream(&source, &sink, history, options) catch return error.IoFailure;
            return sink.end;
        },
        .measured => {
            var counter = measurement.Counter.init(null);
            {
                var source = std.Io.Reader.fixed(input);
                gzip.encodeStream(&source, &counter.writer, history, options) catch return error.IoFailure;
            }
            const exact = try measurement.measuredLength(&counter);
            if (output.len < exact) return error.InsufficientCapacity;
            var source = std.Io.Reader.fixed(input);
            var sink = std.Io.Writer.fixed(output);
            gzip.encodeStream(&source, &sink, history, options) catch return error.IoFailure;
            return sink.end;
        },
    }
}

// Raw DEFLATE decode session: the gzip driver minus framing. One stream ends
// at the final block, trailing bytes are an error.
pub const DeflateDecode = struct {
    inflater: deflate_seam.Decode,
    history: []u8 = &.{},
    pending: [pending_cap]u8,
    pending_len: usize = 0,
    leftover: usize = 0,
    started: bool = false,
    stream_end: usize = 0,
    budgets: sessions.Budgets,

    fn restage(self: *DeflateDecode, input: []const u8, result: *StepResult) Failure!void {
        return restageInflated(&self.inflater, self.pending[0..], &self.pending_len, &self.leftover, input, result);
    }
};

pub fn deflateDecodeStorage() usize {
    return stateSize(DeflateDecode) + deflate.history_size;
}

pub fn deflateDecodeInit(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!*DeflateDecode {
    const carved = try carveHistory(DeflateDecode, storage, deflate.history_size);
    const state = carved.state;
    const history = carved.history;
    state.* = .{
        .inflater = deflate_seam.Decode.initSliceBound(deflate_seam.default_provider, &.{}, history) catch unreachable,
        .history = history,
        .pending = undefined,
        .budgets = budgets,
    };
    return state;
}

const deflate_decode_ops = StepOps(DeflateDecode, deflateDecodeStep);

pub fn deflateDecodeSession(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!sessions.Session {
    const state = try deflateDecodeInit(storage, budgets);
    return .{ .state = state, .ops = &deflate_decode_ops };
}

pub fn deflateDecodeStep(state: *DeflateDecode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
    var result = StepResult{};
    state.restage(input, &result) catch |failure| {
        return framingFailed(&result, 0, failure);
    };
    if (!state.started) {
        state.inflater = deflate_seam.Decode.initSliceBound(deflate_seam.default_provider, state.pending[0..state.pending_len], state.history) catch unreachable;
        state.started = true;
    }
    if (output.len != 0 and result.produced < output.len) {
        var sink = std.Io.Writer.fixed(output[result.produced..]);
        const limit = composition.limitFor(output.len - result.produced);
        const emitted = state.inflater.readerPtr().vtable.stream(state.inflater.readerPtr(), &sink, limit) catch {
            const partial = sink.end;
            if (partial > 0) {
                result.produced += partial;
                state.budgets.addDecoded(partial) catch |failure| {
                    return framingFailed(&result, input.len, failure);
                };
            }
            const starved = state.inflater.streamPosition() == state.pending_len;
            if (!end_of_input and starved) {
                state.inflater.clearFailure();
                result.consumed = input.len;
                result.status = .open;
                return result;
            }
            return framingFailed(&result, input.len, error.InvalidData);
        };
        result.produced += emitted;
        state.budgets.addDecoded(emitted) catch |failure| {
            return framingFailed(&result, input.len, failure);
        };
    }
    if (state.inflater.atEnd()) {
        if (state.inflater.readerPtr().seek < state.inflater.readerPtr().end) {
            result.consumed = input.len;
            result.status = .open;
            return result;
        }
        // The stream ends at consumed bits, not buffered bytes: word-granular
        // refill over-reads up to seven bytes past the final block. Trailing
        // bytes after the logical end are an error.
        const consumed_bits = state.inflater.inputBitsConsumed();
        state.stream_end = (consumed_bits + 7) / 8;
        if (state.stream_end != state.pending_len) {
            return framingFailed(&result, input.len, error.InvalidData);
        }
        result.consumed = input.len;
        result.status = .done;
        return result;
    }
    result.consumed = input.len;
    if (end_of_input and state.inflater.streamPosition() == state.pending_len) {
        return framingFailed(&result, input.len, error.InvalidData);
    }
    result.status = .open;
    return result;
}

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
    stream_end: usize = 0,
    adler: checksum.Adler32,
    leftover: usize = 0,
    budgets: sessions.Budgets,

    fn restage(self: *ZlibDecode, input: []const u8, result: *StepResult) Failure!void {
        return restageInflated(&self.inflater, self.pending[0..], &self.pending_len, &self.leftover, input, result);
    }
};

pub fn zlibDecodeStorage() usize {
    return stateSize(ZlibDecode) + deflate.history_size;
}

pub fn zlibDecodeInit(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!*ZlibDecode {
    const carved = try carveHistory(ZlibDecode, storage, deflate.history_size);
    const state = carved.state;
    const history = carved.history;
    state.* = .{
        .inflater = undefined,
        .history = history,
        .pending = undefined,
        .adler = checksum.Adler32.init(),
        .budgets = budgets,
    };
    state.inflater = deflate_seam.Decode.initSliceBound(deflate_seam.default_provider, &.{}, history) catch unreachable;
    return state;
}

const zlib_decode_ops = StepOps(ZlibDecode, zlibDecodeStep);

pub fn zlibDecodeSession(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!sessions.Session {
    const state = try zlibDecodeInit(storage, budgets);
    return .{ .state = state, .ops = &zlib_decode_ops };
}

pub fn zlibDecodeStep(state: *ZlibDecode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
    var result = StepResult{};
    state.restage(input, &result) catch |failure| {
        return framingFailed(&result, 0, failure);
    };
    if (!state.started) {
        if (state.pending_len < zlib_header_size) {
            if (end_of_input) return framingFailed(&result, input.len, error.InvalidData);
            result.consumed = input.len;
            result.status = .open;
            return result;
        }
        const cmf = state.pending[0];
        const flg = state.pending[1];
        if (cmf & 0x0F != zlib_cm_deflate) return framingFailed(&result, input.len, error.Unsupported);
        if ((cmf >> 4) > zlib_cinfo_max) return framingFailed(&result, input.len, error.Unsupported);
        if ((@as(u32, cmf) * 256 + @as(u32, flg)) % 31 != 0) return framingFailed(&result, input.len, error.InvalidData);
        if (flg & zlib_flag_dictionary != 0) return framingFailed(&result, input.len, error.Unsupported);
        state.adler = checksum.Adler32.init();
        state.inflater = deflate_seam.Decode.initSliceBound(deflate_seam.default_provider, state.pending[0..state.pending_len], state.history) catch unreachable;
        state.inflater.setFramePos(zlib_header_size);
        state.started = true;
    }
    if (output.len != 0 and result.produced < output.len) {
        var sink = std.Io.Writer.fixed(output[result.produced..]);
        const limit = composition.limitFor(output.len - result.produced);
        const emitted = state.inflater.readerPtr().vtable.stream(state.inflater.readerPtr(), &sink, limit) catch {
            const partial = sink.end;
            if (partial > 0) {
                result.produced += partial;
                state.budgets.addDecoded(partial) catch |failure| {
                    return framingFailed(&result, input.len, failure);
                };
            }
            const starved = state.inflater.streamPosition() == state.pending_len;
            if (!end_of_input and starved) {
                state.inflater.clearFailure();
                result.consumed = input.len;
                result.status = .open;
                return result;
            }
            return framingFailed(&result, input.len, error.InvalidData);
        };
        result.produced += emitted;
        state.adler.update(output[result.produced - emitted .. result.produced]);
        state.budgets.addDecoded(emitted) catch |failure| {
            return framingFailed(&result, input.len, failure);
        };
    }
    if (state.inflater.atEnd()) {
        if (state.inflater.readerPtr().seek < state.inflater.readerPtr().end) {
            result.consumed = input.len;
            result.status = .open;
            return result;
        }
        const consumed_bits = state.inflater.inputBitsConsumed();
        state.stream_end = (consumed_bits + 7) / 8;
        const trailer_pos = state.stream_end;
        if (state.pending_len - trailer_pos < zlib_trailer_size) {
            if (end_of_input) return framingFailed(&result, input.len, error.InvalidData);
            result.consumed = input.len;
            result.status = .open;
            return result;
        }
        const stored_adler = std.mem.readInt(u32, state.pending[trailer_pos..][0..4], .big);
        if (stored_adler != state.adler.final()) return framingFailed(&result, input.len, error.IntegrityFailure);
        const total = trailer_pos + zlib_trailer_size;
        if (total != state.pending_len) return framingFailed(&result, input.len, error.InvalidData);
        result.consumed = input.len;
        result.status = .done;
        return result;
    }
    result.consumed = input.len;
    if (end_of_input and state.inflater.streamPosition() == state.pending_len) {
        return framingFailed(&result, input.len, error.InvalidData);
    }
    result.status = .open;
    return result;
}

// Pending output must absorb one step's worst case: the deflate bound plus
// the staging flush granularity and one block's table overhead.
pub const encode_pending_len: usize = pending_cap + 32768;

fn drainPending(pending: []u8, pending_len: *usize, pending_read: *usize, output: []u8, result: *StepResult) void {
    const available = pending[pending_read.*..pending_len.*];
    const amount = @min(available.len, output.len - result.produced);
    if (amount > 0) {
        @memcpy(output[result.produced..][0..amount], available[0..amount]);
        result.produced += amount;
        pending_read.* += amount;
        if (pending_read.* == pending_len.*) {
            pending_len.* = 0;
            pending_read.* = 0;
        }
    }
}

const EncodeWrap = enum { raw, gzip, zlib };

const DeflateEncode = struct {
    const Self = @This();
    compressor: deflate.Compress,
    history: []u8 = &.{},
    downstream: std.Io.Writer,
    pending: [encode_pending_len]u8,
    pending_len: usize = 0,
    pending_read: usize = 0,
    header_written: bool = false,
    finished: bool = false,
    hasher: checksum.Crc32,
    adler: checksum.Adler32,
    size: u64 = 0,
    budgets: sessions.Budgets,

    fn room(self: *Self) usize {
        return self.pending.len - self.pending_len;
    }

    fn drain(self: *Self, output: []u8, result: *StepResult) void {
        drainPending(self.pending[0..], &self.pending_len, &self.pending_read, output, result);
    }
};

fn encodePrologueLen(comptime wrap: EncodeWrap) usize {
    return switch (wrap) {
        .raw => 0,
        .gzip => 10,
        .zlib => 2,
    };
}

fn writePrologue(comptime wrap: EncodeWrap, state: *DeflateEncode) Failure!void {
    switch (wrap) {
        .raw => {},
        .gzip => {
            if (state.room() < 10) return error.InsufficientCapacity;
            const header = [10]u8{ 0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 255 };
            @memcpy(state.pending[state.pending_len..][0..10], &header);
            state.pending_len += 10;
            state.hasher = checksum.Crc32.init();
        },
        .zlib => {
            if (state.room() < 2) return error.InsufficientCapacity;
            // cinfo 7 (32 KiB window) with a valid fcheck: 0x78 0x9C.
            const header = [2]u8{ 0x78, 0x9C };
            @memcpy(state.pending[state.pending_len..][0..2], &header);
            state.pending_len += 2;
            state.adler = checksum.Adler32.init();
        },
    }
    state.header_written = true;
}

fn writeEpilogue(comptime wrap: EncodeWrap, state: *DeflateEncode) Failure!void {
    switch (wrap) {
        .raw => {},
        .gzip => {
            if (state.room() < 8) return error.InsufficientCapacity;
            var trailer: [8]u8 = undefined;
            std.mem.writeInt(u32, trailer[0..4], state.hasher.final(), .little);
            std.mem.writeInt(u32, trailer[4..8], @truncate(state.size), .little);
            @memcpy(state.pending[state.pending_len..][0..8], &trailer);
            state.pending_len += 8;
        },
        .zlib => {
            if (state.room() < 4) return error.InsufficientCapacity;
            var trailer: [4]u8 = undefined;
            std.mem.writeInt(u32, &trailer, state.adler.final(), .big);
            @memcpy(state.pending[state.pending_len..][0..4], &trailer);
            state.pending_len += 4;
        },
    }
}

const deflate_encode_options: deflate.Options = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 8 };

fn deflateEncodeStorageImpl(wrap: EncodeWrap) usize {
    _ = wrap;
    return stateSize(DeflateEncode) + deflate.history_size;
}

fn deflateEncodeInitImpl(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!*DeflateEncode {
    const carved = try carveHistory(DeflateEncode, storage, deflate.history_size);
    const state = carved.state;
    const history = carved.history;
    state.* = .{
        .compressor = undefined,
        .history = history,
        .pending = undefined,
        .downstream = undefined,
        .hasher = checksum.Crc32.init(),
        .adler = checksum.Adler32.init(),
        .budgets = budgets,
    };
    state.downstream = std.Io.Writer.fixed(&state.pending);
    state.compressor = deflate.Compress.init(&state.downstream, history, deflate_encode_options) catch return error.InsufficientCapacity;
    return state;
}

fn deflateEncodeSessionImpl(comptime wrap: EncodeWrap, storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!sessions.Session {
    const state = try deflateEncodeInitImpl(storage, budgets);
    const ops = comptime deflateEncodeOps(wrap);
    return .{ .state = state, .ops = ops };
}

fn deflateEncodeOps(comptime wrap: EncodeWrap) *const sessions.Ops {
    const S = struct {
        fn call(state: *anyopaque, input: []const u8, output: []u8, end_of_input: bool) StepResult {
            return deflateEncodeStep(wrap, @ptrCast(@alignCast(state)), input, output, end_of_input);
        }
        const ops = sessions.Ops{ .step = call, .destroy = destroyNoop };
    };
    return &S.ops;
}

// The frame budget beyond the deflate payload for one step: prologue and
// epilogue never share a step with the whole pending buffer, but sizing the
// requirement generously keeps the host contract simple.
const encode_frame_slack: usize = 16;

fn deflateEncodeStep(comptime wrap: EncodeWrap, state: *DeflateEncode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
    var result = StepResult{};
    state.drain(output, &result);
    if (!state.header_written) {
        writePrologue(wrap, state) catch |failure| {
            return encodeFailed(&result, failure);
        };
        state.drain(output, &result);
    }
    if (input.len > 0) {
        if (!state.finished) {
            // The compressor appends at downstream.end; the pending tail after
            // it must absorb this step's worst-case expansion plus the epilogue.
            if (state.room() < input.len + encode_frame_slack) {
                result.required_capacity = input.len + encode_frame_slack - state.room();
                return encodeFailed(&result, error.InsufficientCapacity);
            }
            state.downstream.end = state.pending_len;
            state.downstream.buffer = state.pending[0..];
            state.compressor.writer.writeAll(input) catch {
                return encodeFailed(&result, error.InternalFailure);
            };
            state.pending_len = state.downstream.end;
            switch (wrap) {
                .raw => {},
                .gzip => state.hasher.update(input),
                .zlib => state.adler.update(input),
            }
            state.size = std.math.add(u64, state.size, input.len) catch return encodeFailed(&result, error.ResourceLimit);
            state.budgets.addDecoded(input.len) catch |failure| return encodeFailed(&result, failure);
            result.consumed = input.len;
        } else {
            result.consumed = 0;
        }
    }
    if (end_of_input and !state.finished) {
        state.downstream.end = state.pending_len;
        state.downstream.buffer = state.pending[0..];
        state.compressor.finish() catch {
            return encodeFailed(&result, error.InternalFailure);
        };
        state.pending_len = state.downstream.end;
        writeEpilogue(wrap, state) catch |failure| {
            return encodeFailed(&result, failure);
        };
        state.finished = true;
    }
    state.drain(output, &result);
    if (state.finished and state.pending_read == 0 and state.pending_len == 0) {
        result.status = .done;
        return result;
    }
    result.status = .open;
    return result;
}

fn encodeFailed(result: *StepResult, failure: Failure) StepResult {
    result.status = .failed;
    result.failure = failure;
    return result.*;
}

// Public per-pair entry points (referenced from the session boundary).

pub fn deflateEncodeStorage() usize {
    return deflateEncodeStorageImpl(.raw);
}
pub fn deflateEncodeInit(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!*DeflateEncode {
    return deflateEncodeInitImpl(storage, budgets);
}
pub fn deflateEncodeSession(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!sessions.Session {
    return deflateEncodeSessionImpl(.raw, storage, budgets);
}

pub fn gzipEncodeStorage() usize {
    return deflateEncodeStorageImpl(.gzip);
}
pub fn gzipEncodeInit(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!*DeflateEncode {
    return deflateEncodeInitImpl(storage, budgets);
}
pub fn gzipEncodeSession(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!sessions.Session {
    return deflateEncodeSessionImpl(.gzip, storage, budgets);
}

pub fn zlibEncodeStorage() usize {
    return deflateEncodeStorageImpl(.zlib);
}
pub fn zlibEncodeInit(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!*DeflateEncode {
    return deflateEncodeInitImpl(storage, budgets);
}
pub fn zlibEncodeSession(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!sessions.Session {
    return deflateEncodeSessionImpl(.zlib, storage, budgets);
}

// Stepped frames mirror the leaf's shape: the walker stages one block's
// bytes, decodes into a staging span, drains it across steps, and keeps the
// 64 KiB linked-block history in the state. Session storage is a fixed,
// knowable number: 4 MiB input staging plus 4 MiB output staging plus the
// window.
pub const lz4_pending_len: usize = lz4.block_size_max + 64;
const lz4_magic_value: u32 = 0x184D2204;
const lz4_window_len: usize = 64 * 1024;
// hash_log from the leaf (17): the greedy table words.
const lz4_hash_words: usize = 1 << 12;
// blockCompressBound from the leaf: worst-case compressed block.
fn lz4BlockCompressBound(block_len: usize) usize {
    return block_len + (block_len / 255) + 16;
}

const Lz4DecodePhase = enum { header, block_size, block_data, block_drain, block_checksum, content_checksum, done };

pub const Lz4Decode = struct {
    phase: Lz4DecodePhase = .header,
    pending: [lz4_pending_len]u8 = undefined,
    pending_len: usize = 0,
    pending_read: usize = 0,
    staging: []u8 = &.{},
    staging_read: usize = 0,
    staging_len: usize = 0,
    window: []u8 = &.{},
    window_len: usize = 0,
    flags: u8 = 0,
    max_block: usize = 0,
    block_is_stored: bool = false,
    block_remaining: usize = 0,
    content_size: ?u64 = null,
    content_hasher: checksum.XxHash32,
    block_checksum: u32 = 0,
    total: usize = 0,
    leftover: usize = 0,
    budgets: sessions.Budgets,

    fn restage(self: *Lz4Decode, input: []const u8, result: *StepResult) Failure!void {
        try compactPending(self.pending[0..], &self.pending_len, self.pending_read);
        self.pending_read = 0;
        try appendStaged(self.pending[0..], &self.pending_len, &self.leftover, input, result);
    }
};

pub fn lz4DecodeStorage() usize {
    return stateSize(Lz4Decode) + lz4.block_size_max + lz4_window_len;
}

pub fn lz4DecodeInit(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!*Lz4Decode {
    const state_size = stateSize(Lz4Decode);
    if (storage.len < state_size + lz4.block_size_max + lz4_window_len) return error.InsufficientCapacity;
    const state: *Lz4Decode = @ptrCast(@alignCast(storage.ptr));
    state.* = .{
        .staging = storage[state_size..][0..lz4.block_size_max],
        .window = storage[state_size + lz4.block_size_max ..][0..lz4_window_len],
        .content_hasher = checksum.XxHash32.init(0),
        .budgets = budgets,
    };
    return state;
}

const lz4_decode_ops = StepOps(Lz4Decode, lz4DecodeStep);

pub fn lz4DecodeSession(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!sessions.Session {
    const state = try lz4DecodeInit(storage, budgets);
    return .{ .state = state, .ops = &lz4_decode_ops };
}

fn lz4Available(state: *Lz4Decode) []const u8 {
    return state.pending[state.pending_read..state.pending_len];
}

pub fn lz4DecodeStep(state: *Lz4Decode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
    var result = StepResult{};
    state.restage(input, &result) catch |failure| {
        return framingFailed(&result, 0, failure);
    };
    var stalled = false;
    while (!stalled) {
        switch (state.phase) {
            .header => {
                const avail = lz4Available(state);
                if (avail.len < 7) {
                    if (end_of_input) return framingFailed(&result, input.len, error.InvalidData);
                    stalled = true;
                    continue;
                }
                if (std.mem.readInt(u32, avail[0..4], .little) != lz4_magic_value) return framingFailed(&result, input.len, error.InvalidData);
                state.flags = avail[4];
                if ((state.flags & 0xC0) != 0x40) return framingFailed(&result, input.len, error.Unsupported);
                const block_code = (avail[5] >> 4) & 0x07;
                if (block_code < 4 or block_code > 7) return framingFailed(&result, input.len, error.InvalidData);
                state.max_block = @as(usize, 65536) << @intCast(2 * (@as(usize, block_code) - 4));
                var offset: usize = 6;
                if (state.flags & 0x08 != 0) {
                    if (avail.len < 14) {
                        if (end_of_input) return framingFailed(&result, input.len, error.InvalidData);
                        stalled = true;
                        continue;
                    }
                    state.content_size = std.mem.readInt(u64, avail[6..14], .little);
                    offset = 14;
                }
                if (state.flags & 0x01 != 0) {
                    if (avail.len < offset + 4) {
                        if (end_of_input) return framingFailed(&result, input.len, error.InvalidData);
                        stalled = true;
                        continue;
                    }
                    offset += 4;
                }
                if (avail.len < offset + 1) {
                    if (end_of_input) return framingFailed(&result, input.len, error.InvalidData);
                    stalled = true;
                    continue;
                }
                const stored_sum = avail[offset];
                const computed: u8 = @truncate(checksum.xxh32With(checksum.default_provider, avail[4..offset]) >> 8);
                if (stored_sum != computed) return framingFailed(&result, input.len, error.IntegrityFailure);
                state.pending_read += offset + 1;
                state.content_hasher = checksum.XxHash32.init(0);
                state.phase = .block_size;
            },
            .block_size => {
                const avail = lz4Available(state);
                if (avail.len < 4) {
                    if (end_of_input) return framingFailed(&result, input.len, error.InvalidData);
                    stalled = true;
                    continue;
                }
                const field = std.mem.readInt(u32, avail[0..4], .little);
                state.pending_read += 4;
                if (field == 0) {
                    state.phase = .content_checksum;
                    continue;
                }
                state.block_is_stored = (field & 0x80000000) != 0;
                state.block_remaining = @intCast(field & ~@as(u32, 0x80000000));
                if (state.block_remaining > state.max_block) return framingFailed(&result, input.len, error.InvalidData);
                state.phase = .block_data;
            },
            .block_data => {
                const avail = lz4Available(state);
                if (avail.len < state.block_remaining) {
                    if (end_of_input) return framingFailed(&result, input.len, error.InvalidData);
                    stalled = true;
                    continue;
                }
                const block_data = avail[0..state.block_remaining];
                state.pending_read += state.block_remaining;
                if (state.flags & 0x10 != 0) {
                    state.block_checksum = checksum.xxh32With(checksum.default_provider, block_data);
                }
                const produced = if (state.block_is_stored) blk: {
                    @memcpy(state.staging[0..block_data.len], block_data);
                    break :blk block_data.len;
                } else lz4.decompressBlock(block_data, state.staging, state.window[0..state.window_len]) catch |err| {
                    return framingFailed(&result, input.len, switch (err) {
                        error.InvalidData => error.InvalidData,
                        error.OutputTooSmall => error.InternalFailure,
                    });
                };
                state.content_hasher.update(state.staging[0..produced]);
                state.total = std.math.add(usize, state.total, produced) catch return framingFailed(&result, input.len, error.ResourceLimit);
                state.budgets.addDecoded(produced) catch |failure| return framingFailed(&result, input.len, failure);
                // Linked frames read the last 64 KiB of history.
                if (state.flags & 0x20 == 0) {
                    const produced_bytes = state.staging[0..produced];
                    if (produced_bytes.len >= lz4_window_len) {
                        @memcpy(state.window, produced_bytes[produced_bytes.len - lz4_window_len ..][0..lz4_window_len]);
                        state.window_len = lz4_window_len;
                    } else {
                        const keep = @min(state.window_len, lz4_window_len - produced_bytes.len);
                        std.mem.copyForwards(u8, state.window[0..keep], state.window[state.window_len - keep ..][0..keep]);
                        @memcpy(state.window[keep..][0..produced_bytes.len], produced_bytes);
                        state.window_len = keep + produced_bytes.len;
                    }
                }
                state.staging_len = produced;
                state.staging_read = 0;
                state.phase = .block_drain;
            },
            .block_drain => {
                const amount = @min(state.staging_len - state.staging_read, output.len - result.produced);
                if (amount > 0) {
                    @memcpy(output[result.produced..][0..amount], state.staging[state.staging_read..][0..amount]);
                    result.produced += amount;
                    state.staging_read += amount;
                }
                if (state.staging_read < state.staging_len) {
                    stalled = true;
                    continue;
                }
                state.staging_len = 0;
                state.phase = if (state.flags & 0x10 != 0) .block_checksum else .block_size;
            },
            .block_checksum => {
                const avail = lz4Available(state);
                if (avail.len < 4) {
                    if (end_of_input) return framingFailed(&result, input.len, error.InvalidData);
                    stalled = true;
                    continue;
                }
                const stored_sum = std.mem.readInt(u32, avail[0..4], .little);
                if (stored_sum != state.block_checksum) return framingFailed(&result, input.len, error.IntegrityFailure);
                state.pending_read += 4;
                state.phase = .block_size;
            },
            .content_checksum => {
                if (state.flags & 0x04 == 0) {
                    if (state.content_size) |expected| {
                        if (expected != state.total) return framingFailed(&result, input.len, error.IntegrityFailure);
                    }
                    state.phase = .done;
                    continue;
                }
                const avail = lz4Available(state);
                if (avail.len < 4) {
                    if (end_of_input) return framingFailed(&result, input.len, error.InvalidData);
                    stalled = true;
                    continue;
                }
                const stored_sum = std.mem.readInt(u32, avail[0..4], .little);
                if (stored_sum != state.content_hasher.final()) return framingFailed(&result, input.len, error.IntegrityFailure);
                state.pending_read += 4;
                if (state.content_size) |expected| {
                    if (expected != state.total) return framingFailed(&result, input.len, error.IntegrityFailure);
                }
                state.phase = .done;
            },
            .done => {
                if (state.pending_read != state.pending_len) return framingFailed(&result, input.len, error.InvalidData);
                result.consumed = input.len;
                result.status = .done;
                return result;
            },
        }
    }
    result.consumed = input.len;
    if (end_of_input and state.phase != .done) {
        return framingFailed(&result, input.len, error.InvalidData);
    }
    result.status = .open;
    return result;
}

pub const Lz4Encode = struct {
    pending: [lz4_pending_len]u8 = undefined,
    pending_len: usize = 0,
    pending_read: usize = 0,
    hash_table: []u32 = &.{},
    block_buffer: []u8 = &.{},
    content_hasher: checksum.XxHash32,
    finished: bool = false,
    budgets: sessions.Budgets,

    fn room(self: *Lz4Encode) usize {
        return self.pending.len - self.pending_len;
    }

    fn drain(self: *Lz4Encode, output: []u8, result: *StepResult) void {
        drainPending(self.pending[0..], &self.pending_len, &self.pending_read, output, result);
    }
};

pub fn lz4EncodeStorage() usize {
    const state_size = stateSize(Lz4Encode);
    // Hash table for the greedy parser plus one block bound.
    return state_size + lz4.encodeWorkspaceSize();
}

pub fn lz4EncodeInit(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!*Lz4Encode {
    const state_size = stateSize(Lz4Encode);
    if (storage.len < state_size + lz4.encodeWorkspaceSize()) return error.InsufficientCapacity;
    const state: *Lz4Encode = @ptrCast(@alignCast(storage.ptr));
    const workspace = storage[state_size..][0..lz4.encodeWorkspaceSize()];
    state.* = .{
        .hash_table = std.mem.bytesAsSlice(u32, @as([]align(4) u8, @alignCast(workspace[0 .. lz4_hash_words * 4]))),
        .block_buffer = workspace[lz4_hash_words * 4 ..],
        .content_hasher = checksum.XxHash32.init(0),
        .budgets = budgets,
    };
    // Write the frame header: independent blocks, 4 MiB max, content size
    // omitted (a stream's total is not knowable at the first step), content
    // checksum on.
    var fixed = std.Io.Writer.fixed(state.pending[0..]);
    fixed.writeInt(u32, lz4_magic_value, .little) catch return error.InsufficientCapacity;
    const flags: u8 = 0x40 | 0x20 | 0x04;
    fixed.writeByte(flags) catch return error.InsufficientCapacity;
    fixed.writeByte(7 << 4) catch return error.InsufficientCapacity;
    state.content_hasher = checksum.XxHash32.init(0);
    var crc_state = checksum.XxHash32.init(0);
    crc_state.update(&.{ flags, 7 << 4 });
    fixed.writeByte(@truncate(crc_state.final() >> 8)) catch return error.InsufficientCapacity;
    state.pending_len = fixed.end;
    return state;
}

const lz4_encode_ops = StepOps(Lz4Encode, lz4EncodeStep);

pub fn lz4EncodeSession(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!sessions.Session {
    const state = try lz4EncodeInit(storage, budgets);
    return .{ .state = state, .ops = &lz4_encode_ops };
}

pub fn lz4EncodeStep(state: *Lz4Encode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
    var result = StepResult{};
    state.drain(output, &result);
    if (input.len > 0 and !state.finished) {
        // Compress this step's input as one or more blocks; each block's
        // bound plus its size words must fit the pending tail.
        var rest = input;
        while (rest.len > 0) {
            const take = @min(rest.len, lz4.block_size_max);
            const chunk = rest[0..take];
            const bound = lz4BlockCompressBound(take);
            if (state.room() < bound + 8) {
                if (result.consumed == 0 and result.produced == 0) {
                    result.required_capacity = bound + 8 - state.room();
                    return encodeFailed(&result, error.InsufficientCapacity);
                }
                break;
            }
            const compressed_len = lz4.compressBlock(chunk, state.block_buffer, state.hash_table, 1);
            const compressed = state.block_buffer[0..compressed_len];
            const is_stored = compressed_len >= take;
            var fixed = std.Io.Writer.fixed(state.pending[state.pending_len..]);
            if (is_stored) {
                fixed.writeInt(u32, 0x80000000 | @as(u32, @intCast(take)), .little) catch return encodeFailed(&result, error.InternalFailure);
                fixed.writeAll(chunk) catch return encodeFailed(&result, error.InternalFailure);
            } else {
                fixed.writeInt(u32, @as(u32, @intCast(compressed_len)), .little) catch return encodeFailed(&result, error.InternalFailure);
                fixed.writeAll(compressed) catch return encodeFailed(&result, error.InternalFailure);
            }
            state.pending_len += fixed.end;
            state.content_hasher.update(chunk);
            state.budgets.addDecoded(take) catch |failure| return encodeFailed(&result, failure);
            result.consumed += take;
            rest = rest[take..];
        }
    }
    if (end_of_input and !state.finished) {
        if (state.room() < 8) {
            result.required_capacity = 8 - state.room();
            return encodeFailed(&result, error.InsufficientCapacity);
        }
        var fixed = std.Io.Writer.fixed(state.pending[state.pending_len..]);
        fixed.writeInt(u32, 0, .little) catch return encodeFailed(&result, error.InternalFailure);
        fixed.writeInt(u32, state.content_hasher.final(), .little) catch return encodeFailed(&result, error.InternalFailure);
        state.pending_len += fixed.end;
        state.finished = true;
    }
    state.drain(output, &result);
    if (state.finished and state.pending_read == 0 and state.pending_len == 0) {
        result.status = .done;
        return result;
    }
    result.status = .open;
    return result;
}
