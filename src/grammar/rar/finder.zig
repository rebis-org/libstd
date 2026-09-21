const std = @import("std");
const failure = @import("../../common/primitive/failure.zig");
const Failure = failure.Failure;
const kernels = @import("../../leaf/kernels.zig");

// BT4 match finder. Positions inside matches get skip() updates (hash2/3
// only) — tree insertions there buy little. Nothing allocates: all tables are
// caller-provided, and token-buffer exhaustion is a clean
// InsufficientCapacity for the caller to size against.

pub const LzToken = union(enum) {
    literal: u8,
    match: struct {
        length: u32,
        distance: u32,
    },
};

pub const MatchFinder = struct {
    hash: []u32, // 1 << hash_bits
    hash2: []u32, // 1 << 16
    hash3: []u32, // 1 << hash3_bits
    window_size: u32,
    min_match: u32,
    max_match: u32,
    nice_len: u32,
    bt_depth: u32,
    insert_depth: u32,
    lazy: bool,

    pub const hash_bits: comptime_int = 20;
    pub const hash_size: usize = 1 << hash_bits;
    pub const hash2_size: usize = 1 << 16;
    pub const hash3_bits: comptime_int = 18;
    pub const hash3_size: usize = 1 << hash3_bits;

    pub fn windowSizeFor(_: u32) u32 {
        return 1 << 20; // 1 MiB dictionary, matching the writer's dict_bits=3
    }

    pub fn init(
        hash: []u32,
        hash2: []u32,
        hash3: []u32,
        window_size: u32,
        level: u3,
    ) Failure!MatchFinder {
        if (hash.len < hash_size or hash2.len < hash2_size or hash3.len < hash3_size)
            return error.InternalFailure;
        @memset(hash, 0);
        @memset(hash2, 0);
        @memset(hash3, 0);
        return .{
            .hash = hash,
            .hash2 = hash2,
            .hash3 = hash3,
            .window_size = window_size,
            .min_match = 2,
            .max_match = 4097,
            .nice_len = switch (level) {
                1 => 8,
                2 => 16,
                3 => 32,
                4 => 64,
                5 => 128,
                else => 32,
            },
            .bt_depth = switch (level) {
                1 => 4,
                2 => 8,
                3 => 16,
                4 => 24,
                5 => 32,
                else => 16,
            },
            .insert_depth = switch (level) {
                1 => 2,
                2 => 4,
                3 => 4,
                4 => 6,
                5 => 8,
                else => 4,
            },
            .lazy = level >= 3,
        };
    }

    fn hash2val(data: []const u8, pos: usize) u32 {
        return @as(u32, data[pos]) | (@as(u32, data[pos + 1]) << 8);
    }

    fn hash3val(data: []const u8, pos: usize) u32 {
        const v: u32 = @as(u32, data[pos]) |
            (@as(u32, data[pos + 1]) << 8) |
            (@as(u32, data[pos + 2]) << 16);
        return (v *% 0x56A3B17D) >> (32 - hash3_bits);
    }

    fn hash4(data: []const u8, pos: usize) u32 {
        if (pos + 3 >= data.len) return 0;
        const v: u32 = @as(u32, data[pos]) |
            (@as(u32, data[pos + 1]) << 8) |
            (@as(u32, data[pos + 2]) << 16) |
            (@as(u32, data[pos + 3]) << 24);
        return (v *% 0x9E3779B1) >> (32 - hash_bits);
    }

    fn extendMatch(data: []const u8, a: usize, b: usize, start: u32, max_len: u32) u32 {
        return @intCast(kernels.matchLen8(data, a + start, b + start, max_len - start) + start);
    }

    fn treeInsert(
        self: *MatchFinder,
        data: []const u8,
        pos: u32,
        bt_left: []u32,
        bt_right: []u32,
    ) void {
        if (pos + 3 >= data.len) {
            if (pos + 1 < data.len) self.hash2[hash2val(data, pos)] = pos + 1;
            if (pos + 2 < data.len) self.hash3[hash3val(data, pos)] = pos + 1;
            return;
        }

        self.hash2[hash2val(data, pos)] = pos + 1;
        self.hash3[hash3val(data, pos)] = pos + 1;

        const h = hash4(data, pos);
        var cur = self.hash[h];
        self.hash[h] = pos + 1;

        var left_ptr = &bt_left[pos];
        var right_ptr = &bt_right[pos];
        var best_left_len: u32 = 0;
        var best_right_len: u32 = 0;
        var depth: u32 = 0;

        while (cur > 0 and depth < self.insert_depth) : (depth += 1) {
            const match_pos = cur - 1;
            if (pos <= match_pos) break;
            if (pos - match_pos > self.window_size) break;

            const max_len = @min(self.max_match, @as(u32, @intCast(data.len - pos)));
            const max_src = @min(max_len, @as(u32, @intCast(data.len - match_pos)));
            const limit = @min(max_len, max_src);
            const common = extendMatch(data, pos, match_pos, @min(best_left_len, best_right_len), limit);

            if (common >= limit or common >= self.nice_len) {
                left_ptr.* = bt_left[match_pos];
                right_ptr.* = bt_right[match_pos];
                return;
            }

            if (common < limit and data[pos + common] < data[match_pos + common]) {
                right_ptr.* = cur;
                right_ptr = &bt_left[match_pos];
                cur = bt_left[match_pos];
                best_right_len = common;
            } else {
                left_ptr.* = cur;
                left_ptr = &bt_right[match_pos];
                cur = bt_right[match_pos];
                best_left_len = common;
            }
        }

        left_ptr.* = 0;
        right_ptr.* = 0;
    }

    const MatchResult = struct { length: u32, distance: u32 };

    fn findBT4Match(
        self: *MatchFinder,
        data: []const u8,
        pos: u32,
        bt_left: []u32,
        bt_right: []u32,
    ) ?MatchResult {
        if (pos + 3 >= data.len) return null;

        const h2 = hash2val(data, pos);
        const h2_prev = self.hash2[h2];
        self.hash2[h2] = pos + 1;

        const h3 = hash3val(data, pos);
        const h3_prev = self.hash3[h3];
        self.hash3[h3] = pos + 1;

        var best_len: u32 = self.min_match - 1;
        var best_dist: u32 = 0;

        if (h2_prev > 0) {
            const mp: u32 = h2_prev - 1;
            if (pos > mp) {
                const dist = pos - mp;
                if (dist <= self.window_size and data[mp] == data[pos] and data[mp + 1] == data[pos + 1]) {
                    best_len = 2;
                    best_dist = dist;
                }
            }
        }

        if (h3_prev > 0) {
            const mp: u32 = h3_prev - 1;
            if (pos > mp) {
                const dist = pos - mp;
                if (dist <= self.window_size and
                    data[mp] == data[pos] and
                    data[mp + 1] == data[pos + 1] and
                    data[mp + 2] == data[pos + 2])
                {
                    const max_len = @min(self.max_match, @as(u32, @intCast(data.len - pos)));
                    const max_src = @min(max_len, @as(u32, @intCast(data.len - mp)));
                    const limit = @min(max_len, max_src);
                    const actual_len = extendMatch(data, pos, mp, 3, limit);
                    if (actual_len > best_len) {
                        best_len = actual_len;
                        best_dist = dist;
                    }
                }
            }
        }

        // Adaptive depth: if neither hash found a 3+ byte match, use a
        // shallow tree walk. On incompressible data this saves enormous time
        // since deep BT4 walks find nothing useful.
        const effective_depth: u32 = if (best_len < 3) @min(self.bt_depth, 2) else self.bt_depth;

        const h = hash4(data, pos);
        var cur = self.hash[h];
        self.hash[h] = pos + 1;

        var left_ptr = &bt_left[pos];
        var right_ptr = &bt_right[pos];
        var best_left_len: u32 = 0;
        var best_right_len: u32 = 0;
        var depth: u32 = 0;

        while (cur > 0 and depth < effective_depth) : (depth += 1) {
            const match_pos = cur - 1;
            if (pos <= match_pos) break;
            const dist = pos - match_pos;
            if (dist > self.window_size) break;

            const max_len = @min(self.max_match, @as(u32, @intCast(data.len - pos)));
            const max_src = @min(max_len, @as(u32, @intCast(data.len - match_pos)));
            const limit = @min(max_len, max_src);
            const common = extendMatch(data, pos, match_pos, @min(best_left_len, best_right_len), limit);

            if (common > best_len) {
                best_len = common;
                best_dist = dist;
                if (common >= max_len or common >= self.nice_len) {
                    left_ptr.* = bt_left[match_pos];
                    right_ptr.* = bt_right[match_pos];
                    if (best_len >= self.min_match) {
                        return .{ .length = best_len, .distance = best_dist };
                    }
                    return null;
                }
            }

            if (common < limit and data[pos + common] < data[match_pos + common]) {
                right_ptr.* = cur;
                right_ptr = &bt_left[match_pos];
                cur = bt_left[match_pos];
                best_right_len = common;
            } else {
                left_ptr.* = cur;
                left_ptr = &bt_right[match_pos];
                cur = bt_right[match_pos];
                best_left_len = common;
            }
        }

        left_ptr.* = 0;
        right_ptr.* = 0;

        if (best_len >= self.min_match) {
            return .{ .length = best_len, .distance = best_dist };
        }
        return null;
    }

    pub fn compress(
        self: *MatchFinder,
        data: []const u8,
        tokens: []LzToken,
        bt_left: []u32,
        bt_right: []u32,
    ) Failure![]LzToken {
        if (bt_left.len < data.len or bt_right.len < data.len) return error.InternalFailure;
        @memset(bt_left, 0);
        @memset(bt_right, 0);

        if (data.len == 0) return tokens[0..0];

        var count: usize = 0;
        var pos: u32 = 0;
        while (pos < data.len) {
            const match_result = self.findBT4Match(data, pos, bt_left, bt_right);

            if (match_result) |m| {
                if (self.lazy and pos + 1 < data.len) {
                    const next_match = self.findBT4Match(data, pos + 1, bt_left, bt_right);
                    if (next_match) |nm| {
                        if (nm.length > m.length + 1) {
                            if (count >= tokens.len) return error.InsufficientCapacity;
                            tokens[count] = .{ .literal = data[pos] };
                            count += 1;
                            pos += 1;

                            if (count >= tokens.len) return error.InsufficientCapacity;
                            tokens[count] = .{ .match = .{ .length = nm.length, .distance = nm.distance } };
                            count += 1;
                            var i: u32 = 1;
                            while (i < nm.length) : (i += 1) {
                                if (pos + i < data.len) self.treeInsert(data, pos + i, bt_left, bt_right);
                            }
                            pos += nm.length;
                            continue;
                        }
                    }
                    // Original match was better or equal — emit it. pos was
                    // already inserted by findBT4Match, pos+1 by the lazy
                    // check above; insert the remaining positions.
                    if (count >= tokens.len) return error.InsufficientCapacity;
                    tokens[count] = .{ .match = .{ .length = m.length, .distance = m.distance } };
                    count += 1;
                    var i: u32 = 2;
                    while (i < m.length) : (i += 1) {
                        if (pos + i < data.len) self.treeInsert(data, pos + i, bt_left, bt_right);
                    }
                    pos += m.length;
                } else {
                    if (count >= tokens.len) return error.InsufficientCapacity;
                    tokens[count] = .{ .match = .{ .length = m.length, .distance = m.distance } };
                    count += 1;
                    var i: u32 = 1; // pos already in tree via findBT4Match
                    while (i < m.length) : (i += 1) {
                        if (pos + i < data.len) self.treeInsert(data, pos + i, bt_left, bt_right);
                    }
                    pos += m.length;
                }
            } else {
                // pos already inserted into the tree.
                if (count >= tokens.len) return error.InsufficientCapacity;
                tokens[count] = .{ .literal = data[pos] };
                count += 1;
                pos += 1;
            }
        }

        return tokens[0..count];
    }
};

test "match finder replays through the window byte-exactly" {
    var hash: [MatchFinder.hash_size]u32 = undefined;
    var hash2: [MatchFinder.hash2_size]u32 = undefined;
    var hash3: [MatchFinder.hash3_size]u32 = undefined;
    var bt_left: [1024]u32 = undefined;
    var bt_right: [1024]u32 = undefined;
    var tokens: [1024]LzToken = undefined;

    var mf = try MatchFinder.init(&hash, &hash2, &hash3, 4096, 3);
    const data = "The quick brown fox jumps over the lazy dog. The quick brown fox!";
    const toks = try mf.compress(data, &tokens, &bt_left, &bt_right);
    try std.testing.expect(toks.len < data.len);

    var window_buf: [1024]u8 = undefined;
    var win = @import("window.zig").Window.init(&window_buf);
    for (toks) |tok| {
        switch (tok) {
            .literal => |b| win.putByte(b),
            .match => |m| win.copyMatch(m.distance, m.length),
        }
    }
    var out: [1024]u8 = undefined;
    var bs = @import("../../common/sink.zig").BufferSink.init(&out);
    try std.testing.expect(win.emitTo(bs.sink(), win.write_pos, data.len));
    try std.testing.expectEqualSlices(u8, data, out[0..data.len]);
}

test "match finder handles all-literal data" {
    var hash: [MatchFinder.hash_size]u32 = undefined;
    var hash2: [MatchFinder.hash2_size]u32 = undefined;
    var hash3: [MatchFinder.hash3_size]u32 = undefined;
    var bt_left: [64]u32 = undefined;
    var bt_right: [64]u32 = undefined;
    var tokens: [64]LzToken = undefined;

    var mf = try MatchFinder.init(&hash, &hash2, &hash3, 4096, 3);
    const data = "abcdefghijklmnop";
    const toks = try mf.compress(data, &tokens, &bt_left, &bt_right);
    try std.testing.expectEqual(data.len, toks.len);
    for (toks) |tok| try std.testing.expect(tok == .literal);
}
