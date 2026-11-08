const std = @import("std");

const checksum = @import("../../common/primitive/checksum.zig");
const exception_prim = @import("../../common/primitive/exception.zig");
const lz4 = @import("../../representation/leaf/lz4/onprem.zig");
const sessions = @import("../sessions.zig");
const session = @import("session.zig");
const stage = @import("stage.zig");
const step = @import("step.zig");

const testing = std.testing;
const Exception = exception_prim.Exception;
const StepResult = sessions.StepResult;
const stateSize = session.stateSize;
const encodeFailed = step.encodeFailed;
const framingFailed = step.framingFailed;

// Stepped frames mirror the leaf: stage one block, decode into staging,
// drain across steps, keep the 64 KiB linked-block history.
pub const lz4_pending_len: usize = lz4.block_size_max + 64;
const lz4_magic_value: u32 = 0x184D2204;
const lz4_window_len: usize = 64 * 1024;
// hash_log from the leaf (12): the greedy table words.
pub const lz4_hash_words: usize = 1 << 12;

// blockCompressBound from the leaf: worst-case compressed block.
pub fn lz4BlockCompressBound(block_len: usize) usize {
    return block_len + (block_len / 255) + 16;
}

const Lz4DecodePhase = enum { header, block_size, block_data, block_drain, block_checksum, content_checksum, done };

pub const Lz4Decode = struct {
    phase: Lz4DecodePhase = .header,
    stage: stage.Stage(lz4_pending_len) = .{},
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
    budgets: sessions.Budgets,

    fn restage(self: *Lz4Decode, input: []const u8, result: *StepResult) Exception!void {
        try self.stage.compact();
        try self.stage.append(input, result);
    }
};

pub fn lz4DecodeStorage() usize {
    return stateSize(Lz4Decode) + lz4.block_size_max + lz4_window_len;
}

pub fn lz4DecodeInit(storage: []u8, budgets: sessions.Budgets) error{CapacityException}!*Lz4Decode {
    const state_size = stateSize(Lz4Decode);
    if (storage.len < state_size + lz4.block_size_max + lz4_window_len) return error.CapacityException;
    const state: *Lz4Decode = @ptrCast(@alignCast(storage.ptr));
    state.* = .{
        .staging = storage[state_size..][0..lz4.block_size_max],
        .window = storage[state_size + lz4.block_size_max ..][0..lz4_window_len],
        .content_hasher = checksum.XxHash32.init(0),
        .budgets = budgets,
    };
    return state;
}

const lz4_decode_pair = session.Pair(.{ .state = Lz4Decode, .storage = lz4DecodeStorage, .init = lz4DecodeInit, .step = lz4DecodeStep });
pub const lz4DecodeSession = lz4_decode_pair.session;

pub fn lz4DecodeStep(state: *Lz4Decode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
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
    var stalled = false;
    while (!stalled) {
        switch (state.phase) {
            .header => {
                const avail = state.stage.available();
                if (state.stage.need(7, end_of_input) != .enough) break;
                if (std.mem.readInt(u32, avail[0..4], .little) != lz4_magic_value) return framingFailed(&result, input.len, error.DataException);
                state.flags = avail[4];
                if ((state.flags & 0xC0) != 0x40) return framingFailed(&result, input.len, error.UnsupportedException);
                // Reserved FLG bit and BD bits must read zero, as the leaf and
                // the reference decoder require.
                if (state.flags & 0x02 != 0) return framingFailed(&result, input.len, error.DataException);
                const bd = avail[5];
                if (bd & 0x8F != 0) return framingFailed(&result, input.len, error.DataException);
                const block_code = (bd >> 4) & 0x07;
                if (block_code < 4 or block_code > 7) return framingFailed(&result, input.len, error.DataException);
                state.max_block = @as(usize, 65536) << @intCast(2 * (@as(usize, block_code) - 4));
                var offset: usize = 6;
                if (state.flags & 0x08 != 0) {
                    if (state.stage.need(14, end_of_input) != .enough) break;
                    state.content_size = std.mem.readInt(u64, avail[6..14], .little);
                    offset = 14;
                }
                if (state.flags & 0x01 != 0) {
                    if (state.stage.need(offset + 4, end_of_input) != .enough) break;
                    offset += 4;
                }
                if (state.stage.need(offset + 1, end_of_input) != .enough) break;
                const stored_sum = avail[offset];
                const computed: u8 = @truncate(checksum.xxh32With(checksum.default_provider, avail[4..offset]) >> 8);
                if (stored_sum != computed) return framingFailed(&result, input.len, error.IntegrityException);
                state.stage.read += offset + 1;
                state.content_hasher = checksum.XxHash32.init(0);
                state.phase = .block_size;
            },
            .block_size => {
                const avail = state.stage.available();
                if (state.stage.need(4, end_of_input) != .enough) break;
                const field = std.mem.readInt(u32, avail[0..4], .little);
                state.stage.read += 4;
                if (field == 0) {
                    state.phase = .content_checksum;
                    continue;
                }
                state.block_is_stored = (field & 0x80000000) != 0;
                state.block_remaining = @intCast(field & ~@as(u32, 0x80000000));
                if (state.block_remaining > state.max_block) return framingFailed(&result, input.len, error.DataException);
                state.phase = .block_data;
            },
            .block_data => {
                const avail = state.stage.available();
                if (state.stage.need(state.block_remaining, end_of_input) != .enough) break;
                const block_data = avail[0..state.block_remaining];
                state.stage.read += state.block_remaining;
                if (state.flags & 0x10 != 0) {
                    state.block_checksum = checksum.xxh32With(checksum.default_provider, block_data);
                }
                const produced = if (state.block_is_stored) blk: {
                    @memcpy(state.staging[0..block_data.len], block_data);
                    break :blk block_data.len;
                } else lz4.decompressBlock(block_data, state.staging, state.window[0..state.window_len]) catch {
                    // A corrupt block answers DataException; so does an overrun of the
                    // staging buffer: invalid data, not an internal fault.
                    return framingFailed(&result, input.len, error.DataException);
                };
                state.content_hasher.update(state.staging[0..produced]);
                state.total = std.math.add(usize, state.total, produced) catch return framingFailed(&result, input.len, error.ResourceException);
                state.budgets.addDecoded(produced) catch |exception| return framingFailed(&result, input.len, exception);
                state.budgets.addWork(produced) catch |exception| return framingFailed(&result, input.len, exception);
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
                const avail = state.stage.available();
                if (state.stage.need(4, end_of_input) != .enough) break;
                const stored_sum = std.mem.readInt(u32, avail[0..4], .little);
                if (stored_sum != state.block_checksum) return framingFailed(&result, input.len, error.IntegrityException);
                state.stage.read += 4;
                state.phase = .block_size;
            },
            .content_checksum => {
                if (state.flags & 0x04 == 0) {
                    if (state.content_size) |expected| {
                        if (expected != state.total) return framingFailed(&result, input.len, error.IntegrityException);
                    }
                    state.phase = .done;
                    continue;
                }
                const avail = state.stage.available();
                if (state.stage.need(4, end_of_input) != .enough) break;
                const stored_sum = std.mem.readInt(u32, avail[0..4], .little);
                if (stored_sum != state.content_hasher.final({})) return framingFailed(&result, input.len, error.IntegrityException);
                state.stage.read += 4;
                if (state.content_size) |expected| {
                    if (expected != state.total) return framingFailed(&result, input.len, error.IntegrityException);
                }
                state.phase = .done;
            },
            .done => {
                if (state.stage.read != state.stage.len) return framingFailed(&result, input.len, error.DataException);
                result.consumed = input.len;
                result.status = .done;
                return result;
            },
        }
    }
    result.consumed = input.len;
    if (end_of_input and state.phase != .done) {
        return framingFailed(&result, input.len, error.DataException);
    }
    result.status = .open;
    return result;
}

pub const Lz4Encode = struct {
    stage: stage.Stage(lz4_pending_len) = .{},
    hash_table: []u32 = &.{},
    block_buffer: []u8 = &.{},
    content_hasher: checksum.XxHash32,
    finished: bool = false,
    budgets: sessions.Budgets,
};

pub fn lz4EncodeStorage() usize {
    const state_size = stateSize(Lz4Encode);
    // Hash table for the greedy parser plus one block bound.
    return state_size + lz4.encodeWorkspaceSize();
}

pub fn lz4EncodeInit(storage: []u8, budgets: sessions.Budgets) error{CapacityException}!*Lz4Encode {
    const state_size = stateSize(Lz4Encode);
    if (storage.len < state_size + lz4.encodeWorkspaceSize()) return error.CapacityException;
    const state: *Lz4Encode = @ptrCast(@alignCast(storage.ptr));
    const workspace = storage[state_size..][0..lz4.encodeWorkspaceSize()];
    state.* = .{
        .hash_table = std.mem.bytesAsSlice(u32, @as([]align(4) u8, @alignCast(workspace[0 .. lz4_hash_words * 4]))),
        .block_buffer = workspace[lz4_hash_words * 4 ..],
        .content_hasher = checksum.XxHash32.init(0),
        .budgets = budgets,
    };
    // Frame header: independent blocks, 4 MiB max, content checksum on; the
    // content size is unknowable at the first step.
    var fixed = std.Io.Writer.fixed(&state.stage.buf);
    fixed.writeInt(u32, lz4_magic_value, .little) catch return error.CapacityException;
    const flags: u8 = 0x40 | 0x20 | 0x04;
    fixed.writeByte(flags) catch return error.CapacityException;
    fixed.writeByte(7 << 4) catch return error.CapacityException;
    state.content_hasher = checksum.XxHash32.init(0);
    var crc_state = checksum.XxHash32.init(0);
    crc_state.update(&.{ flags, 7 << 4 });
    fixed.writeByte(@truncate(crc_state.final({}) >> 8)) catch return error.CapacityException;
    state.stage.len = fixed.end;
    return state;
}

const lz4_encode_pair = session.Pair(.{ .state = Lz4Encode, .storage = lz4EncodeStorage, .init = lz4EncodeInit, .step = lz4EncodeStep });
pub const lz4EncodeSession = lz4_encode_pair.session;

pub fn lz4EncodeStep(state: *Lz4Encode, input: []const u8, output: []u8, end_of_input: bool) StepResult {
    var result = StepResult{};
    state.stage.drain(output, &result);
    // Reject trailing input only once the finished frame's pending tail has
    // drained; an early error would drop EndMark and checksum bytes. A step
    // that drains nothing must still fail, or a zero-length output spins.
    if (state.finished and input.len > 0 and (state.stage.len == 0 or result.produced == 0))
        return encodeFailed(&result, error.DataException);
    if (input.len > 0 and !state.finished) {
        // Compress this step's input as blocks; each block's bound plus
        // size words must fit the pending tail.
        var rest = input;
        while (rest.len > 0) {
            const take = @min(rest.len, lz4.block_size_max);
            const chunk = rest[0..take];
            const bound = lz4BlockCompressBound(take);
            if (state.stage.room() < bound + 8) {
                if (result.consumed == 0 and result.produced == 0) {
                    result.required_capacity = bound + 8 - state.stage.room();
                    return encodeFailed(&result, error.CapacityException);
                }
                break;
            }
            const compressed_len = lz4.compressBlock(chunk, state.block_buffer, state.hash_table, 1);
            const compressed = state.block_buffer[0..compressed_len];
            const is_stored = compressed_len >= take;
            var fixed = std.Io.Writer.fixed(state.stage.buf[state.stage.len..]);
            if (is_stored) {
                fixed.writeInt(u32, 0x80000000 | @as(u32, @intCast(take)), .little) catch return encodeFailed(&result, error.InternalException);
                fixed.writeAll(chunk) catch return encodeFailed(&result, error.InternalException);
            } else {
                fixed.writeInt(u32, @as(u32, @intCast(compressed_len)), .little) catch return encodeFailed(&result, error.InternalException);
                fixed.writeAll(compressed) catch return encodeFailed(&result, error.InternalException);
            }
            state.stage.len += fixed.end;
            state.content_hasher.update(chunk);
            state.budgets.addDecoded(take) catch |exception| return encodeFailed(&result, exception);
            state.budgets.addWork(take) catch |exception| return encodeFailed(&result, exception);
            result.consumed += take;
            rest = rest[take..];
        }
    }
    if (end_of_input and !state.finished) {
        if (state.stage.room() < 8) {
            result.required_capacity = 8 - state.stage.room();
            return encodeFailed(&result, error.CapacityException);
        }
        var fixed = std.Io.Writer.fixed(state.stage.buf[state.stage.len..]);
        fixed.writeInt(u32, 0, .little) catch return encodeFailed(&result, error.InternalException);
        fixed.writeInt(u32, state.content_hasher.final({}), .little) catch return encodeFailed(&result, error.InternalException);
        state.stage.len += fixed.end;
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

test "lz4 sessions roundtrip both block shapes and reject corrupt frames" {
    const fixtures = @import("../../testing/support.zig");
    const allocator = testing.allocator;
    var payload: [600]u8 = undefined;
    fixtures.fillPayload(&payload);

    // The decode sweep below needs a known-good modern frame.
    const enc_holder = try fixtures.allocStateStorage(Lz4Encode, lz4EncodeStorage(), allocator);
    defer allocator.free(enc_holder.raw);
    const encoder = try lz4EncodeInit(enc_holder.aligned, .{});
    var frame: std.ArrayList(u8) = .empty;
    defer frame.deinit(allocator);
    var out: [4096]u8 = undefined;
    while (true) {
        const result = lz4EncodeStep(encoder, &payload, &out, true);
        try frame.appendSlice(allocator, out[0..result.produced]);
        if (result.status == .failed) return result.exception.?;
        if (result.status == .done) break;
    }
    // The frame contract the mutations below rely on: modern magic,
    // independent 4 MiB blocks, content checksum on.
    try testing.expectEqual(lz4_magic_value, std.mem.readInt(u32, frame.items[0..4], .little));
    try testing.expectEqual(@as(u8, 0x64), frame.items[4]);
    try testing.expectEqual(@as(u8, 0x70), frame.items[5]);

    // Every input boundary must decode to the same payload.
    const dec_holder = try fixtures.allocStateStorage(Lz4Decode, lz4DecodeStorage(), allocator);
    defer allocator.free(dec_holder.raw);
    inline for (1..17) |chunk| {
        try fixtures.expectChunkedDecode(Lz4Decode, lz4DecodeInit, lz4DecodeStep, dec_holder.aligned, frame.items, &payload, chunk, 4096);
    }

    // Incompressible input takes the stored-block shape and still roundtrips.
    {
        var noise: [600]u8 = undefined;
        var rng: u64 = 0x853C49E6748FEA9B;
        for (&noise) |*b| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            b.* = @truncate(rng >> 32);
        }
        const noise_encoder = try lz4EncodeInit(enc_holder.aligned, .{});
        var noise_frame: std.ArrayList(u8) = .empty;
        defer noise_frame.deinit(allocator);
        while (true) {
            const result = lz4EncodeStep(noise_encoder, &noise, &out, true);
            try noise_frame.appendSlice(allocator, out[0..result.produced]);
            if (result.status == .failed) return result.exception.?;
            if (result.status == .done) break;
        }
        // The high bit of the first block size word marks the stored shape.
        const first_size = std.mem.readInt(u32, noise_frame.items[7..11], .little);
        try testing.expect(first_size & 0x80000000 != 0);
        try fixtures.expectChunkedDecode(Lz4Decode, lz4DecodeInit, lz4DecodeStep, dec_holder.aligned, noise_frame.items, &noise, 13, 4096);
    }

    // Reserved FLG and BD bits stay invalid under any header checksum,
    // so each mutation recomputes HC.
    const mutations = [_]struct { offset: usize, mask: u8 }{
        .{ .offset = 4, .mask = 0x02 },
        .{ .offset = 5, .mask = 0x80 },
        .{ .offset = 5, .mask = 0x01 },
    };
    for (mutations) |mutation| {
        const bad = try allocator.alloc(u8, frame.items.len);
        defer allocator.free(bad);
        @memcpy(bad, frame.items);
        bad[mutation.offset] |= mutation.mask;
        bad[6] = @truncate(checksum.xxh32With(checksum.default_provider, bad[4..6]) >> 8);
        try testing.expectError(error.DataException, fixtures.expectChunkedDecode(Lz4Decode, lz4DecodeInit, lz4DecodeStep, dec_holder.aligned, bad, &payload, bad.len, 4096));
    }

    // A flipped content checksum byte fails integrity, not framing.
    {
        const bad = try allocator.alloc(u8, frame.items.len);
        defer allocator.free(bad);
        @memcpy(bad, frame.items);
        bad[bad.len - 1] ^= 0xFF;
        try testing.expectError(error.IntegrityException, fixtures.expectChunkedDecode(Lz4Decode, lz4DecodeInit, lz4DecodeStep, dec_holder.aligned, bad, &payload, bad.len, 4096));
    }

    // Legacy frames need their own 8 MiB staging; the modern session refuses them.
    var legacy: [8]u8 = undefined;
    std.mem.writeInt(u32, legacy[0..4], 0x184C2102, .little);
    try testing.expectError(error.DataException, fixtures.expectChunkedDecode(Lz4Decode, lz4DecodeInit, lz4DecodeStep, dec_holder.aligned, &legacy, &payload, legacy.len, 4096));
}

test "lz4 encode drains a finished frame before rejecting trailing input" {
    const fixtures = @import("../../testing/support.zig");
    const allocator = testing.allocator;
    var payload: [600]u8 = undefined;
    fixtures.fillPayload(&payload);

    const enc_holder = try fixtures.allocStateStorage(Lz4Encode, lz4EncodeStorage(), allocator);
    defer allocator.free(enc_holder.raw);
    const encoder = try lz4EncodeInit(enc_holder.aligned, .{});

    // An eight-byte output leaves the EndMark and checksum pending across
    // several steps once finished is latched.
    var frame: std.ArrayList(u8) = .empty;
    defer frame.deinit(allocator);
    var out: [8]u8 = undefined;
    var rest: []const u8 = &payload;
    while (true) {
        const result = lz4EncodeStep(encoder, rest, &out, true);
        try frame.appendSlice(allocator, out[0..result.produced]);
        if (result.status == .failed) return result.exception.?;
        rest = rest[result.consumed..];
        if (result.status == .done) break;
    }
    // Header, one size word, EndMark and content checksum all arrived.
    try testing.expect(frame.items.len >= 19);

    // No pending bytes remain: trailing input is an immediate error.
    const trailing = lz4EncodeStep(encoder, "x", &out, false);
    try testing.expectEqual(sessions.StepStatus.failed, trailing.status);
    try testing.expectEqual(error.DataException, trailing.exception.?);
    try testing.expectEqual(@as(usize, 0), trailing.consumed);
}
