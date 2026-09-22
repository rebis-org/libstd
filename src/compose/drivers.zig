const std = @import("std");

const checksum = @import("../common/primitive/checksum.zig");
const failure_prim = @import("../common/primitive/failure.zig");
const Failure = failure_prim.Failure;
const measurement = @import("../common/primitive/measurement.zig");
const gzip = @import("../grammar/gzip.zig");
const deflate = @import("../leaf/deflate.zig");
const composition = @import("composition.zig");
const sessions = @import("sessions.zig");
const StepResult = sessions.StepResult;

const id1: u8 = 0x1f;
const id2: u8 = 0x8b;
const method_deflate: u8 = 8;
const flag_hcrc: u8 = 0x02;
const flag_extra: u8 = 0x04;
const flag_name: u8 = 0x08;
const flag_comment: u8 = 0x10;
const reserved_flags: u8 = 0xe0;

// Framing reads ahead of the inflater via shared pending with per-step compaction for bounded memory; step chunks must satisfy chunk_len <= pending_cap - 8.
pub const pending_cap: usize = 131072;

pub const Phase = enum { idle, fixed, extra_len, extra_skip, extra_field, name, comment, hcrc, deflate, trailer, done };

pub const GzipDecodeState = struct {
    inflater: deflate.Decompress,
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

    fn nextByte(self: *GzipDecodeState) ?u8 {
        if (self.frame_pos >= self.pending_len) return null;
        const byte = self.pending[self.frame_pos];
        self.frame_pos += 1;
        return byte;
    }

    fn availableInput(self: *GzipDecodeState) []const u8 {
        return self.pending[self.frame_pos..self.pending_len];
    }

    // leftover snapshots pre-append length so consumed reporting covers only this step's bytes.
    fn restage(self: *GzipDecodeState, input: []const u8, result: *StepResult) Failure!void {
        const consumed = self.inflater.input.slice.pos;
        const floor = if (self.phase == .deflate) consumed else self.frame_pos;
        if (floor > self.pending_len) return error.InternalFailure;
        if (floor > 0) {
            @memmove(self.pending[0 .. self.pending_len - floor], self.pending[floor..self.pending_len]);
            self.pending_len -= floor;
            if (self.phase == .deflate) {
                // frame_pos is stale while the inflater owns the stream; re-established from slice.pos at member end.
                self.frame_pos = 0;
            } else {
                self.frame_pos -= floor;
            }
            self.inflater.input.slice.pos = 0;
        }
        self.leftover = self.pending_len;
        if (input.len > self.pending.len - self.pending_len) {
            result.failure_value = input.len - (self.pending.len - self.pending_len);
            return error.InsufficientCapacity;
        }
        @memcpy(self.pending[self.pending_len..][0..input.len], input);
        self.pending_len += input.len;
        self.inflater.input.slice.data = self.pending[0..self.pending_len];
    }

    // Each step's whole chunk is accepted into pending; consumed is the accepted length and bytes are never re-sent.
    fn streamPosition(self: *const GzipDecodeState) usize {
        return if (self.phase == .deflate) self.inflater.input.slice.pos else self.frame_pos;
    }
};

pub fn gzipDecodeStorage() usize {
    return std.mem.alignForward(usize, @sizeOf(GzipDecodeState), 16) + deflate.history_size;
}

pub fn gzipDecodeStateInit(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!*GzipDecodeState {
    const state_size = std.mem.alignForward(usize, @sizeOf(GzipDecodeState), 16);
    if (storage.len < state_size + deflate.history_size) return error.InsufficientCapacity;
    const state: *GzipDecodeState = @ptrCast(@alignCast(storage.ptr));
    const history = storage[state_size..][0..deflate.history_size];
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
    state.inflater = deflate.Decompress.initSlice(&.{}, history);
    return state;
}

// Each member needs a fresh deflate stream resuming at frame_pos, where framing read ahead to.
fn enterDeflate(state: *GzipDecodeState) void {
    state.inflater = deflate.Decompress.initSlice(state.pending[0..state.pending_len], state.history);
    state.inflater.input.slice.pos = state.frame_pos;
    state.phase = .deflate;
}

// Both kernel-mediated and bypass paths run identical leaf code, so byte-identity is expected.
const decode_ops = sessions.Ops{
    .step = struct {
        fn call(state: *anyopaque, input: []const u8, output: []u8, end_of_input: bool) StepResult {
            return gzipDecodeStep(@ptrCast(@alignCast(state)), input, output, end_of_input);
        }
    }.call,
    .destroy = struct {
        fn call(state: *anyopaque) void {
            _ = state;
        }
    }.call,
};

pub fn gzipDecodeSession(storage: []u8, budgets: sessions.Budgets) error{InsufficientCapacity}!sessions.Session {
    const state = try gzipDecodeStateInit(storage, budgets);
    return .{ .state = state, .ops = &decode_ops };
}

fn framingFailed(result: *StepResult, consumed: usize, failure: Failure) StepResult {
    result.consumed = consumed;
    result.status = .failed;
    result.failure = failure;
    return result.*;
}

fn selectPostHeaderPhase(state: *GzipDecodeState) void {
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

pub fn gzipDecodeStep(state: *GzipDecodeState, input: []const u8, output: []u8, end_of_input: bool) StepResult {
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
                        // XLEN is consumed once; later fields chain from name.
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
            const emitted = state.inflater.reader.vtable.stream(&state.inflater.reader, &sink, limit) catch {
                // Suspension vs corruption is distinguishable only by position (pending end vs early fail); flushed bytes are real output and count first.
                const partial = sink.end;
                if (partial > 0) {
                    result.produced += partial;
                    state.member_crc.update(output[0..partial]);
                    state.member_size += partial;
                    state.budgets.addDecoded(partial) catch |failure| {
                        return framingFailed(&result, input.len, failure);
                    };
                }
                const starved = state.inflater.input.slice.pos == state.pending_len;
                if (!end_of_input and starved) {
                    state.inflater.failed = false;
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
            if (state.inflater.state == .end) {
                if (state.inflater.reader.seek < state.inflater.reader.end) {
                    if (result.produced < output.len) continue;
                    break;
                }
                // Member ends at consumed bits, not buffered bytes: word-granular refill over-reads up to seven bytes past the final block.
                const consumed_bits = state.inflater.inputBitsConsumed();
                state.frame_pos = (consumed_bits + 7) / 8;
                state.inflater.input.slice.pos = state.frame_pos;
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

// Bounded checks capacity against the analytic bound and encodes once; measured sizes exactly first. Output bytes identical either way.
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
            const exact = std.math.cast(usize, counter.written()) orelse return error.ResourceLimit;
            if (output.len < exact) return error.InsufficientCapacity;
            var source = std.Io.Reader.fixed(input);
            var sink = std.Io.Writer.fixed(output);
            gzip.encodeStream(&source, &sink, history, options) catch return error.IoFailure;
            return sink.end;
        },
    }
}
