const std = @import("std");

const kernels = @import("../../common/kernels.zig");
const failure = @import("../../common/primitive/failure.zig");
const common_sink = @import("../../common/sink.zig");
const window_mod = @import("window.zig");

const Failure = failure.Failure;

// Nothing allocates: every table is caller-provided, and token-buffer
// exhaustion returns CapacityFailure so the caller can size the buffer.

pub const LzToken = union(enum) {
    literal: u8,
    match: struct {
        length: u32,
        distance: u32,
    },
};

pub const MatchFinder = struct {
    hash: []u32,
    hash2: []u32,
    hash3: []u32,
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

    // The window must match the writer's 1 MiB dictionary.
    pub const dictionary_window: u32 = 1 << 20;

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

    fn hash2val(bytes: []const u8, pos: usize) u32 {
        return @as(u32, bytes[pos]) | (@as(u32, bytes[pos + 1]) << 8);
    }

    fn hash3val(bytes: []const u8, pos: usize) u32 {
        const v: u32 = @as(u32, bytes[pos]) |
            (@as(u32, bytes[pos + 1]) << 8) |
            (@as(u32, bytes[pos + 2]) << 16);
        return (v *% 0x56A3B17D) >> (32 - hash3_bits);
    }

    fn hash4(bytes: []const u8, pos: usize) u32 {
        if (pos + 3 >= bytes.len) return 0;
        const v: u32 = @as(u32, bytes[pos]) |
            (@as(u32, bytes[pos + 1]) << 8) |
            (@as(u32, bytes[pos + 2]) << 16) |
            (@as(u32, bytes[pos + 3]) << 24);
        return (v *% 0x9E3779B1) >> (32 - hash_bits);
    }

    fn extendMatch(bytes: []const u8, a: usize, b: usize, start: u32, max_len: u32) u32 {
        return @intCast(kernels.matchLen8(bytes, a + start, b + start, max_len - start) + start);
    }

    fn treeInsert(
        self: *MatchFinder,
        bytes: []const u8,
        pos: u32,
        bt_left: []u32,
        bt_right: []u32,
    ) void {
        if (pos + 3 >= bytes.len) {
            if (pos + 1 < bytes.len) self.hash2[hash2val(bytes, pos)] = pos + 1;
            if (pos + 2 < bytes.len) self.hash3[hash3val(bytes, pos)] = pos + 1;
            return;
        }

        self.hash2[hash2val(bytes, pos)] = pos + 1;
        self.hash3[hash3val(bytes, pos)] = pos + 1;

        const h = hash4(bytes, pos);
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

            const max_len = @min(self.max_match, @as(u32, @intCast(bytes.len - pos)));
            const max_src = @min(max_len, @as(u32, @intCast(bytes.len - match_pos)));
            const limit = @min(max_len, max_src);
            const common = extendMatch(bytes, pos, match_pos, @min(best_left_len, best_right_len), limit);

            if (common >= limit or common >= self.nice_len) {
                left_ptr.* = bt_left[match_pos];
                right_ptr.* = bt_right[match_pos];
                return;
            }

            if (common < limit and bytes[pos + common] < bytes[match_pos + common]) {
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
        bytes: []const u8,
        pos: u32,
        bt_left: []u32,
        bt_right: []u32,
    ) ?MatchResult {
        if (pos + 3 >= bytes.len) return null;

        const h2 = hash2val(bytes, pos);
        const h2_prev = self.hash2[h2];
        self.hash2[h2] = pos + 1;

        const h3 = hash3val(bytes, pos);
        const h3_prev = self.hash3[h3];
        self.hash3[h3] = pos + 1;

        var best_len: u32 = self.min_match - 1;
        var best_dist: u32 = 0;

        if (h2_prev > 0) {
            const mp: u32 = h2_prev - 1;
            if (pos > mp) {
                const dist = pos - mp;
                if (dist <= self.window_size and bytes[mp] == bytes[pos] and bytes[mp + 1] == bytes[pos + 1]) {
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
                    bytes[mp] == bytes[pos] and
                    bytes[mp + 1] == bytes[pos + 1] and
                    bytes[mp + 2] == bytes[pos + 2])
                {
                    const max_len = @min(self.max_match, @as(u32, @intCast(bytes.len - pos)));
                    const max_src = @min(max_len, @as(u32, @intCast(bytes.len - mp)));
                    const limit = @min(max_len, max_src);
                    const actual_len = extendMatch(bytes, pos, mp, 3, limit);
                    if (actual_len > best_len) {
                        best_len = actual_len;
                        best_dist = dist;
                    }
                }
            }
        }

        // Adaptive depth: a deep BT4 walk finds nothing useful on incompressible
        // data, so use a shallow walk when neither hash found a 3-byte match.
        const effective_depth: u32 = if (best_len < 3) @min(self.bt_depth, 2) else self.bt_depth;

        const h = hash4(bytes, pos);
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

            const max_len = @min(self.max_match, @as(u32, @intCast(bytes.len - pos)));
            const max_src = @min(max_len, @as(u32, @intCast(bytes.len - match_pos)));
            const limit = @min(max_len, max_src);
            const common = extendMatch(bytes, pos, match_pos, @min(best_left_len, best_right_len), limit);

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

            if (common < limit and bytes[pos + common] < bytes[match_pos + common]) {
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
        bytes: []const u8,
        tokens: []LzToken,
        bt_left: []u32,
        bt_right: []u32,
    ) Failure![]LzToken {
        if (bt_left.len < bytes.len or bt_right.len < bytes.len) return error.InternalFailure;
        @memset(bt_left, 0);
        @memset(bt_right, 0);

        if (bytes.len == 0) return tokens[0..0];

        var count: usize = 0;
        var pos: u32 = 0;
        while (pos < bytes.len) {
            const match_result = self.findBT4Match(bytes, pos, bt_left, bt_right);

            if (match_result) |m| {
                if (self.lazy and pos + 1 < bytes.len) {
                    const next_match = self.findBT4Match(bytes, pos + 1, bt_left, bt_right);
                    if (next_match) |nm| {
                        if (nm.length > m.length + 1) {
                            if (count >= tokens.len) return error.CapacityFailure;
                            tokens[count] = .{ .literal = bytes[pos] };
                            count += 1;
                            pos += 1;

                            if (count >= tokens.len) return error.CapacityFailure;
                            tokens[count] = .{ .match = .{ .length = nm.length, .distance = nm.distance } };
                            count += 1;
                            var i: u32 = 1;
                            while (i < nm.length) : (i += 1) {
                                if (pos + i < bytes.len) self.treeInsert(bytes, pos + i, bt_left, bt_right);
                            }
                            pos += nm.length;
                            continue;
                        }
                    }
                    // Position pos is already in the tree from findBT4Match, and
                    // pos + 1 from the lazy check above, so the loop starts at 2.
                    if (count >= tokens.len) return error.CapacityFailure;
                    tokens[count] = .{ .match = .{ .length = m.length, .distance = m.distance } };
                    count += 1;
                    var i: u32 = 2;
                    while (i < m.length) : (i += 1) {
                        if (pos + i < bytes.len) self.treeInsert(bytes, pos + i, bt_left, bt_right);
                    }
                    pos += m.length;
                } else {
                    if (count >= tokens.len) return error.CapacityFailure;
                    tokens[count] = .{ .match = .{ .length = m.length, .distance = m.distance } };
                    count += 1;
                    var i: u32 = 1; // Position pos is already in the tree.
                    while (i < m.length) : (i += 1) {
                        if (pos + i < bytes.len) self.treeInsert(bytes, pos + i, bt_left, bt_right);
                    }
                    pos += m.length;
                }
            } else {
                // Position pos is already in the tree.
                if (count >= tokens.len) return error.CapacityFailure;
                tokens[count] = .{ .literal = bytes[pos] };
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
    const bytes = "The quick brown fox jumps over the lazy dog. The quick brown fox!";
    const toks = try mf.compress(bytes, &tokens, &bt_left, &bt_right);
    try std.testing.expect(toks.len < bytes.len);

    var window_buf: [1024]u8 = undefined;
    var win = window_mod.Window.init(&window_buf);
    for (toks) |tok| {
        switch (tok) {
            .literal => |b| win.putByte(b),
            .match => |m| win.copyMatch(m.distance, m.length),
        }
    }
    var out: [1024]u8 = undefined;
    var bs = common_sink.BufferSink.init(&out);
    try std.testing.expect(win.emitTo(bs.sink(), win.write_pos, bytes.len));
    try std.testing.expectEqualSlices(u8, bytes, out[0..bytes.len]);
}

test "match finder handles all-literal data" {
    var hash: [MatchFinder.hash_size]u32 = undefined;
    var hash2: [MatchFinder.hash2_size]u32 = undefined;
    var hash3: [MatchFinder.hash3_size]u32 = undefined;
    var bt_left: [64]u32 = undefined;
    var bt_right: [64]u32 = undefined;
    var tokens: [64]LzToken = undefined;

    var mf = try MatchFinder.init(&hash, &hash2, &hash3, 4096, 3);
    const bytes = "abcdefghijklmnop";
    const toks = try mf.compress(bytes, &tokens, &bt_left, &bt_right);
    try std.testing.expectEqual(bytes.len, toks.len);
    for (toks) |tok| try std.testing.expect(tok == .literal);
}
