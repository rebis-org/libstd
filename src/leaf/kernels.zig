const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("options");

// NEON is baseline on aarch64, so the wide match-copy path needs no extra
// target feature; other targets keep the portable word-at-a-time path.
const vector_match_copy = !build_options.force_fallback and builtin.cpu.arch == .aarch64;

pub fn matchLen8(buf: []const u8, a: usize, b: usize, max: usize) usize {
    var len: usize = 0;
    while (len + 8 <= max) {
        const xor = std.mem.readInt(u64, buf[a + len ..][0..8], .little) ^ std.mem.readInt(u64, buf[b + len ..][0..8], .little);
        if (xor != 0) return len + @ctz(xor) / 8;
        len += 8;
    }
    while (len < max and buf[a + len] == buf[b + len]) len += 1;
    return len;
}

// LZ77 match copy ending at `dst` (exclusive): replicates buf[dst-dist..]
// forward, so overlapping ranges with dist < len repeat with period dist.
// Short copies dominate the lzma decoder; the gated path uses exact inline
// ladders so no platform memcpy/memmove call overhead lands in the loop.
pub inline fn copyMatch(buf: []u8, dst: usize, dist: u32, len: u32) void {
    const src = dst - dist;
    if (comptime vector_match_copy) {
        if (len <= 273) {
            if (dist >= len) {
                copyShort16(buf[dst..][0..len], buf[src..][0..len]);
            } else if (dist >= 16) {
                var i: usize = 0;
                while (i + 16 <= len) : (i += 16) {
                    buf[dst + i ..][0..16].* = buf[src + i ..][0..16].*;
                }
                if (i < len) {
                    buf[dst + len - 16 ..][0..16].* = buf[src + len - 16 ..][0..16].*;
                }
            } else if (dist >= 8) {
                var i: usize = 0;
                while (i + 8 <= len) : (i += 8) {
                    buf[dst + i ..][0..8].* = buf[src + i ..][0..8].*;
                }
                if (i < len) {
                    buf[dst + len - 8 ..][0..8].* = buf[src + len - 8 ..][0..8].*;
                }
            } else if (dist == 1) {
                if (len >= 16) {
                    const v: @Vector(16, u8) = @splat(buf[src]);
                    var i: usize = 0;
                    while (i + 16 <= len) : (i += 16) {
                        buf[dst + i ..][0..16].* = v;
                    }
                    if (i < len) buf[dst + len - 16 ..][0..16].* = v;
                } else {
                    // Short runs widen the byte into a word; a platform
                    // memset call costs more than the copy at this size.
                    const w: u64 = @as(u64, buf[src]) * 0x0101_0101_0101_0101;
                    if (len >= 8) {
                        std.mem.writeInt(u64, buf[dst..][0..8], w, .little);
                        std.mem.writeInt(u64, buf[dst + len - 8 ..][0..8], w, .little);
                    } else if (len >= 4) {
                        const w32: u32 = @truncate(w);
                        std.mem.writeInt(u32, buf[dst..][0..4], w32, .little);
                        std.mem.writeInt(u32, buf[dst + len - 4 ..][0..4], w32, .little);
                    } else {
                        for (0..len) |i| buf[dst + i] = buf[src];
                    }
                }
            } else {
                copyMatchPeriodWiden(buf, dst, dist, len);
            }
            return;
        }
    }

    if (dist >= len) {
        @memcpy(buf[dst..][0..len], buf[src..][0..len]);
        return;
    }
    var out = dst;
    var rest: usize = len;
    var covered: usize = dist;
    while (rest > 0) {
        const chunk = @min(covered, rest);
        @memcpy(buf[out..][0..chunk], buf[out - covered ..][0..chunk]);
        out += chunk;
        rest -= chunk;
        covered += chunk;
    }
}

fn copyShort16(dst: []u8, src: []const u8) void {
    const length = dst.len;
    if (length >= 16) {
        var i: usize = 0;
        while (i + 16 <= length) : (i += 16) {
            dst[i..][0..16].* = src[i..][0..16].*;
        }
        if (i < length) {
            dst[length - 16 ..][0..16].* = src[length - 16 ..][0..16].*;
        }
    } else if (length >= 8) {
        dst[0..8].* = src[0..8].*;
        dst[length - 8 ..][0..8].* = src[length - 8 ..][0..8].*;
    } else if (length >= 4) {
        dst[0..4].* = src[0..4].*;
        dst[length - 4 ..][0..4].* = src[length - 4 ..][0..4].*;
    } else {
        for (0..length) |i| dst[i] = src[i];
    }
}

// Small-offset overlap copy: byte-widen the period to at least one word, then
// finish with word-at-a-time copies that read only finalized bytes.
fn copyMatchPeriodWiden(buf: []u8, dst: usize, offset: usize, length: usize) void {
    var done: usize = 0;
    var period: usize = offset;
    while (period < 8 and done < length) {
        const take = @min(period, length - done);
        var j: usize = 0;
        while (j < take) : (j += 1) buf[dst + done + j] = buf[dst + done + j - period];
        done += take;
        period += take;
    }
    var i: usize = done;
    while (i + 8 <= length) : (i += 8) {
        const word = std.mem.readInt(u64, buf[dst + i - period ..][0..8], .little);
        std.mem.writeInt(u64, buf[dst + i ..][0..8], word, .little);
    }
    while (i < length) : (i += 1) buf[dst + i] = buf[dst + i - period];
}
