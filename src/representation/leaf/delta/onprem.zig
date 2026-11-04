const builtin = @import("builtin");
const std = @import("std");

pub const Direction = enum { encode, decode };

// The wire semantics follow the ring below: decode folds
// out[i] = in[i] + out[i - D], encode folds out[i] = in[i] - in[i - D], with
// D = distance + 1 and out[j < 0] = 0. The leaf's parameter is the format's
// distance minus one (xz passes `delta_distance - 1`, 7-Zip the props byte).

// Distances with comptime vector arms; everything else runs the ring.
const scanned_distances = [_]usize{ 1, 2, 4, 8 };

fn apply(code: []u8, distance: u8, comptime dir: Direction) void {
    const D: usize = @as(usize, distance) + 1;
    if (comptime vector_width > 0) {
        inline for (scanned_distances) |comptime_d| {
            if (D == comptime_d) return applyScan(code, comptime_d, dir);
        }
        if (dir == .decode and D >= 16) return applyPredLoadDecode(code, D);
    }
    applyRing(code, distance, dir);
}

const vector_width = if ((builtin.target.cpu.arch == .aarch64 or
    builtin.target.cpu.arch == .x86_64) and builtin.zig_backend != .stage2_c) 16 else 0;

// The ring reference of record: decode keeps decoded bytes, encode keeps raw
// input bytes, both wrapped at 256 because D never exceeds it.
fn applyRing(code: []u8, distance: u8, comptime dir: Direction) void {
    var history: [256]u8 = @splat(0);
    var pos: u8 = 0;
    for (code, 0..) |byte, index| {
        const history_index = distance +% 1 +% pos;
        const out = switch (dir) {
            .decode => byte +% history[history_index],
            .encode => byte -% history[history_index],
        };
        history[pos] = switch (dir) {
            .decode => out,
            .encode => byte,
        };
        code[index] = out;
        pos -%= 1;
    }
}

fn Scan(comptime D: usize) type {
    return struct {
        const V = @Vector(16, u8);
        const zeros: V = @splat(0);

        // Decode unfolds out[i] = in[i] + out[i-D] into an in-block stride-D
        // prefix sum plus one boundary byte per residue chain.
        //
        // Encode unfolds out[i] = in[i] - in[i-D] into a plain stride-D
        // difference whose lookback reaches the saved raw tail.

        // Scan steps double the folded terms: s runs D, 2D, 4D, ... < 16.
        const steps = blk: {
            var count = 0;
            var s = D;
            while (s < 16) : (s *= 2) count += 1;
            break :blk count;
        };

        // mask[k] = k - s: lanes at or above s fold lane k - s, lanes below s
        // read the zero operand (negative picks the second vector).
        fn scanShift(v: V, comptime s: usize) V {
            const mask = comptime blk: {
                var m: [16]i32 = undefined;
                for (0..16) |k| m[k] = @as(i32, @intCast(k)) - @as(i32, @intCast(s));
                break :blk m;
            };
            const shuffle_mask: @Vector(16, i32) = @bitCast(mask);
            return @shuffle(u8, v, zeros, shuffle_mask);
        }

        // Decode boundary[k] = out[p + (k % D) - D]: the one already-written
        // byte each residue chain crosses below the block start.
        const boundary_mask = blk: {
            var m: [16]i32 = undefined;
            for (0..16) |k| m[k] = @intCast(16 + (k % D) - D);
            break :blk m;
        };

        fn decodeBlock(v: V, state: V) V {
            var scanned = v;
            comptime var s = D;
            comptime var round = 0;
            inline while (round < steps) : ({
                round += 1;
                s *= 2;
            }) {
                scanned +%= scanShift(scanned, s);
            }
            const shuffle_mask: @Vector(16, i32) = boundary_mask;
            scanned +%= @shuffle(u8, state, undefined, shuffle_mask);
            return scanned;
        }

        // Encode pred[k] = in[p + k - D]: in-block raw for lanes at or above D,
        // the previous block's raw tail below D. A negative mask reads the
        // second operand from its start, so raw_tail index j is mask -j-1.
        const pred_mask = blk: {
            var m: [16]i32 = undefined;
            for (0..16) |k| m[k] = if (k >= D)
                @as(i32, @intCast(k)) - @as(i32, @intCast(D))
            else
                @as(i32, @intCast(D)) - @as(i32, @intCast(k)) - 17;
            break :blk m;
        };

        fn encodeBlock(v: V, raw_tail: V) V {
            const shuffle_mask: @Vector(16, i32) = pred_mask;
            const pred = @shuffle(u8, v, raw_tail, shuffle_mask);
            return v -% pred;
        }
    };
}

fn applyScan(code: []u8, comptime D: usize, comptime dir: Direction) void {
    const Impl = Scan(D);
    const V = Impl.V;

    var carry: V = @splat(0);
    var p: usize = 0;
    while (p + 16 <= code.len) : (p += 16) {
        const v: V = @bitCast(code[p..][0..16].*);
        const out = switch (dir) {
            .decode => Impl.decodeBlock(v, carry),
            .encode => Impl.encodeBlock(v, carry),
        };
        code[p..][0..16].* = @bitCast(out);
        carry = switch (dir) {
            // Decode carries the written output; encode carries the raw input
            // the block just destroyed.
            .decode => out,
            .encode => v,
        };
    }
    // The tail runs as one zero-padded block, so its lookback sees the same
    // carry the loop blocks saw.
    const rest = code.len - p;
    if (rest > 0) {
        var tail: [16]u8 = @splat(0);
        @memcpy(tail[0..rest], code[p..]);
        const v: V = @bitCast(tail);
        const out = switch (dir) {
            .decode => Impl.decodeBlock(v, carry),
            .encode => Impl.encodeBlock(v, carry),
        };
        @memcpy(code[p..], @as([16]u8, @bitCast(out))[0..rest]);
    }
}

// Decode lookback lands entirely in already-written output once D >= 16, so
// one load, one add, one store per block.
fn applyPredLoadDecode(code: []u8, D: usize) void {
    // Bytes below D have no predecessor, so they pass through unchanged.
    if (code.len <= D) return;
    const V = @Vector(16, u8);
    var p: usize = D;
    while (p + 16 <= code.len) : (p += 16) {
        const input: V = @bitCast(code[p..][0..16].*);
        const pred: V = @bitCast(code[p - D ..][0..16].*);
        code[p..][0..16].* = @bitCast(input +% pred);
    }
    const rest = code.len - p;
    if (rest > 0) {
        var tail: [16]u8 = @splat(0);
        @memcpy(tail[0..rest], code[p..]);
        const input: V = @bitCast(tail);
        const pred: V = @bitCast(code[p - D ..][0..16].*);
        @memcpy(code[p..], @as([16]u8, @bitCast(input +% pred))[0..rest]);
    }
}

pub fn decode(code: []u8, distance: u8) void {
    apply(code, distance, .decode);
}

pub fn encode(code: []u8, distance: u8) void {
    apply(code, distance, .encode);
}

test "delta round trips across distances and tails" {
    var rng = std.Random.DefaultPrng.init(0xDE7A);
    const random = rng.random();
    for ([_]usize{ 0, 1, 2, 15, 16, 17, 31, 255, 256, 257, 4096, 65536 }) |size| {
        const original = try std.testing.allocator.alloc(u8, size);
        defer std.testing.allocator.free(original);
        random.bytes(original);
        for ([_]u8{ 0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 100, 254, 255 }) |distance| {
            const work = try std.testing.allocator.alloc(u8, size);
            defer std.testing.allocator.free(work);
            @memcpy(work, original);
            encode(work, distance);
            decode(work, distance);
            try std.testing.expectEqualSlices(u8, original, work);
        }
    }
}

// The ring formulation is the wire reference; the vector arms must agree with
// it byte for byte in both directions.
test "delta matches the ring reference across distances" {
    var rng = std.Random.DefaultPrng.init(0xDE7B);
    const random = rng.random();
    var work_a: [1024]u8 = undefined;
    var work_b: [1024]u8 = undefined;
    for ([_]u8{ 0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 100, 255 }) |distance| {
        random.bytes(&work_a);
        inline for ([_]Direction{ .encode, .decode }) |dir| {
            @memcpy(&work_b, &work_a);
            switch (dir) {
                .encode => encode(&work_a, distance),
                .decode => decode(&work_a, distance),
            }
            applyRing(&work_b, distance, dir);
            try std.testing.expectEqualSlices(u8, &work_b, &work_a);
        }
    }
}
