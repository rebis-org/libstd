// Shared test support: only test blocks and harness roots import this
// file; shipping modules never do.

const std = @import("std");

const sessions = @import("../compose/sessions.zig");

// Hex fixtures stay readable in tree; malformed vectors fail the build,
// not the test run.
pub fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    return comptime blk: {
        @setEvalBranchQuota(8 * hex.len + 1000);
        var out: [hex.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, hex) catch @compileError("malformed hex fixture");
        break :blk out;
    };
}

// Deterministic, compressible, non-periodic text: end-of-stream lands inside
// a step with buffered output left over, so boundary chunked decode must
// survive.
pub fn fillPayload(payload: []u8) void {
    var state: u32 = 0x1234567;
    for (payload, 0..) |*slot, index| {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        slot.* = @truncate('a' + ((state >> 8) % 26) + (index % 3));
    }
}

// A driver state plan plus the raw allocation it was carved from, so the
// caller frees exactly what it allocated.
pub const StateStorage = struct { raw: []u8, aligned: []u8 };

pub fn allocStateStorage(comptime Driver: type, plan: usize, allocator: std.mem.Allocator) !StateStorage {
    const raw = try allocator.alloc(u8, plan + @alignOf(Driver));
    const base = @intFromPtr(raw.ptr);
    const offset = std.mem.alignForward(usize, base, @alignOf(Driver)) - base;
    return .{ .raw = raw, .aligned = raw[offset..][0..plan] };
}

// Whatever chunk sizes the caller picks, a stepped decode must produce exactly the bytes a consumer expects from the frame.
pub fn expectChunkedDecode(
    comptime Driver: type,
    comptime initDriver: fn ([]u8, sessions.Budgets) error{ CapacityException, UnsupportedException }!*Driver,
    comptime stepDriver: fn (*Driver, []const u8, []u8, bool) sessions.StepResult,
    storage: []u8,
    compressed: []const u8,
    expected: []const u8,
    input_chunk: usize,
    output_chunk: usize,
) !void {
    const allocator = std.testing.allocator;
    const state = try initDriver(storage, .{});
    const scratch = try allocator.alloc(u8, output_chunk);
    defer allocator.free(scratch);
    var decoded: std.ArrayList(u8) = .empty;
    defer decoded.deinit(allocator);
    var pos: usize = 0;
    var guard: usize = 0;
    while (true) : (guard += 1) {
        try std.testing.expect(guard < 4_000_000);
        const take = @min(input_chunk, compressed.len - pos);
        const result = stepDriver(state, compressed[pos..][0..take], scratch, pos + take == compressed.len);
        try decoded.appendSlice(allocator, scratch[0..result.produced]);
        if (result.status == .failed) {
            if (result.exception) |exception| {
                return exception;
            }
            return error.TestUnexpectedResult;
        }
        pos += result.consumed;
        if (result.status == .done) break;
    }
    try std.testing.expectEqualSlices(u8, expected, decoded.items);
}
