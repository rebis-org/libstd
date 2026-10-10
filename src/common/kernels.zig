const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("options");

// NEON is baseline on aarch64, so the wide match-copy path needs no extra
// target feature. Other targets keep the portable word-at-a-time path.
const vector_match_copy = !build_options.portable and builtin.target.cpu.arch == .aarch64;

pub fn matchLen8(window: []const u8, first: usize, second: usize, max_len: usize) usize {
    var len: usize = 0;
    while (len + 8 <= max_len) {
        const xor = std.mem.readInt(u64, window[first + len ..][0..8], .little) ^ std.mem.readInt(u64, window[second + len ..][0..8], .little);
        if (xor != 0) return len + @ctz(xor) / 8;
        len += 8;
    }
    while (len < max_len and window[first + len] == window[second + len]) len += 1;
    return len;
}

pub const CopyMatchCfg = struct {
    Ret: type,
    short_one: enum { byte_widen, memset } = .byte_widen,
};

// Short copies dominate, so inline ladders avoid per-call memcpy/memset overhead.
// Wrappers gate length and supply their own fallback.
fn copyChunked(window: []u8, out_off: usize, src_off: usize, copy_len: usize, comptime width: usize) void {
    var pos: usize = 0;
    while (pos + width <= copy_len) : (pos += width) {
        window[out_off + pos ..][0..width].* = window[src_off + pos ..][0..width].*;
    }
    if (pos < copy_len) {
        window[out_off + copy_len - width ..][0..width].* = window[src_off + copy_len - width ..][0..width].*;
    }
}

pub inline fn copyMatchCore(comptime cfg: CopyMatchCfg, window: []u8, out_off: usize, distance: u32, copy_len: usize) cfg.Ret {
    const src_off = out_off - distance;
    if (distance >= copy_len) {
        copyShort16(window[out_off..][0..copy_len], window[src_off..][0..copy_len]);
    } else if (distance >= 16) {
        // Chunks read only finalized bytes. The last chunk overlaps.
        copyChunked(window, out_off, src_off, copy_len, 16);
    } else if (distance >= 8) {
        copyChunked(window, out_off, src_off, copy_len, 8);
    } else if (distance == 1) {
        if (copy_len >= 16) {
            const splat: @Vector(16, u8) = @splat(window[src_off]);
            var pos: usize = 0;
            while (pos + 16 <= copy_len) : (pos += 16) {
                window[out_off + pos ..][0..16].* = splat;
            }
            if (pos < copy_len) window[out_off + copy_len - 16 ..][0..16].* = splat;
        } else {
            switch (cfg.short_one) {
                .byte_widen => {
                    // Word widening beats a memset call at this size.
                    const repeated: u64 = @as(u64, window[src_off]) * 0x0101_0101_0101_0101;
                    if (copy_len >= 8) {
                        std.mem.writeInt(u64, window[out_off..][0..8], repeated, .little);
                        std.mem.writeInt(u64, window[out_off + copy_len - 8 ..][0..8], repeated, .little);
                    } else if (copy_len >= 4) {
                        const low32: u32 = @truncate(repeated);
                        std.mem.writeInt(u32, window[out_off..][0..4], low32, .little);
                        std.mem.writeInt(u32, window[out_off + copy_len - 4 ..][0..4], low32, .little);
                    } else {
                        for (0..copy_len) |i| window[out_off + i] = window[src_off];
                    }
                },
                .memset => {
                    @memset(window[out_off..][0..copy_len], window[src_off]);
                },
            }
        }
    } else {
        copyMatchPeriodWiden(window, out_off, distance, copy_len);
    }
    if (cfg.Ret == usize) return out_off + copy_len;
}

pub inline fn copyMatch(window: []u8, out_off: usize, distance: u32, copy_len: u32) void {
    if (comptime vector_match_copy) {
        if (copy_len <= 273) {
            return copyMatchCore(.{
                .Ret = void,
                .short_one = .byte_widen,
            }, window, out_off, distance, copy_len);
        }
    }

    const src_off = out_off - distance;
    if (distance >= copy_len) {
        @memcpy(window[out_off..][0..copy_len], window[src_off..][0..copy_len]);
        return;
    }
    var out = out_off;
    var rest: usize = copy_len;
    var covered: usize = distance;
    while (rest > 0) {
        const chunk = @min(covered, rest);
        @memcpy(window[out..][0..chunk], window[out - covered ..][0..chunk]);
        out += chunk;
        rest -= chunk;
        covered += chunk;
    }
}

pub inline fn copyShort16(dst: []u8, src: []const u8) void {
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
fn copyMatchPeriodWiden(window: []u8, out_off: usize, distance: usize, copy_len: usize) void {
    var done: usize = 0;
    var period: usize = distance;
    while (period < 8 and done < copy_len) {
        const take = @min(period, copy_len - done);
        var pos: usize = 0;
        while (pos < take) : (pos += 1) window[out_off + done + pos] = window[out_off + done + pos - period];
        done += take;
        period += take;
    }
    var cursor: usize = done;
    while (cursor + 8 <= copy_len) : (cursor += 8) {
        const word = std.mem.readInt(u64, window[out_off + cursor - period ..][0..8], .little);
        std.mem.writeInt(u64, window[out_off + cursor ..][0..8], word, .little);
    }
    while (cursor < copy_len) : (cursor += 1) window[out_off + cursor] = window[out_off + cursor - period];
}
