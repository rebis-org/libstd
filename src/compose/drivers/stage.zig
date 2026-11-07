const std = @import("std");

const exception_prim = @import("../../common/primitive/exception.zig");
const sessions = @import("../sessions.zig");

const testing = std.testing;
const Exception = exception_prim.Exception;
const StepResult = sessions.StepResult;

pub fn compactPending(pending: []u8, pending_len: *usize, floor: usize) Exception!void {
    if (floor > pending_len.*) return error.InternalException;
    if (floor > 0) {
        @memmove(pending[0 .. pending_len.* - floor], pending[floor..pending_len.*]);
        pending_len.* -= floor;
    }
}

pub fn appendStaged(pending: []u8, pending_len: *usize, input: []const u8, result: *StepResult) Exception!void {
    if (input.len > pending.len - pending_len.*) {
        result.required_capacity = input.len - (pending.len - pending_len.*);
        return error.CapacityException;
    }
    @memcpy(pending[pending_len.*..][0..input.len], input);
    pending_len.* += input.len;
}

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

pub const Need = enum { enough, stall, truncated };

pub fn Stage(comptime cap: usize) type {
    return struct {
        const Self = @This();

        buf: [cap]u8 = undefined,
        len: usize = 0,
        read: usize = 0,

        pub fn room(self: *const Self) usize {
            return self.buf.len - self.len;
        }

        pub fn available(self: *const Self) []const u8 {
            return self.buf[self.read..self.len];
        }

        pub fn compact(self: *Self) Exception!void {
            try compactPending(self.buf[0..], &self.len, self.read);
            self.read = 0;
        }

        pub fn append(self: *Self, input: []const u8, result: *StepResult) Exception!void {
            try appendStaged(self.buf[0..], &self.len, input, result);
        }

        pub fn drain(self: *Self, output: []u8, result: *StepResult) void {
            drainPending(self.buf[0..], &self.len, &self.read, output, result);
        }

        pub fn need(self: *const Self, n: usize, end_of_input: bool) Need {
            if (self.len - self.read < n) {
                return if (end_of_input) .truncated else .stall;
            }
            return .enough;
        }
    };
}

test "stage compaction append and drain preserve buffered bytes" {
    var s: Stage(8) = .{};
    var result = StepResult{};
    try s.append("abcd", &result);
    try testing.expectEqual(@as(usize, 4), s.len);
    try testing.expectEqual(Need.stall, s.need(6, false));
    try testing.expectEqual(Need.truncated, s.need(6, true));

    var out: [8]u8 = undefined;
    s.drain(out[0..2], &result);
    try testing.expectEqualSlices(u8, "ab", out[0..2]);
    try testing.expectEqual(@as(usize, 2), s.read);

    try s.compact();
    try testing.expectEqualSlices(u8, "cd", s.available());
    try testing.expectEqual(@as(usize, 0), s.read);
    try testing.expectEqual(@as(usize, 2), s.len);

    try s.append("ef", &result);
    try testing.expectEqual(Need.enough, s.need(4, false));
    s.drain(&out, &result);
    try testing.expectEqualSlices(u8, "cdef", out[2..6]);
    try testing.expectEqual(@as(usize, 6), result.produced);
    try testing.expectEqual(@as(usize, 0), s.len);
    try testing.expectEqual(@as(usize, 8), s.room());

    // An append that cannot fit whole reports the shortfall and writes nothing.
    try s.append("12345", &result);
    try testing.expectError(error.CapacityException, s.append("1234", &result));
    try testing.expectEqual(@as(u64, 1), result.required_capacity);
    try testing.expectEqualSlices(u8, "12345", s.available());
    try testing.expectEqual(Need.stall, s.need(6, false));
    try testing.expectEqual(Need.truncated, s.need(6, true));
    try s.append("678", &result);
    try testing.expectEqual(Need.enough, s.need(6, false));

    // Compaction refuses a floor beyond the buffered length and tolerates zero.
    var scratch: [4]u8 = undefined;
    var scratch_len: usize = 2;
    try testing.expectError(error.InternalException, compactPending(scratch[0..], &scratch_len, 3));
    try compactPending(scratch[0..], &scratch_len, 0);
    try testing.expectEqual(@as(usize, 2), scratch_len);
    try compactPending(scratch[0..], &scratch_len, 2);
    try testing.expectEqual(@as(usize, 0), scratch_len);
}
