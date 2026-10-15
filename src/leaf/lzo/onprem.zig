const std = @import("std");

const failure_prim = @import("../../common/primitive/failure.zig");

const Failure = failure_prim.Failure;

// LZO1X decompression, ported from the reference decoder in vendor/lzo.

// Match classes span small offsets to 0x4000 plus the M4 bias.
// A zero computed offset marks the stream end.

// Compression lands in a follow-up slice; squashfs only reads LZO.

const m2_max_offset: usize = 0x0800;
const m4_bias: usize = 0x4000;

fn takeToken(input: []const u8, ip: *usize) Failure!usize {
    if (ip.* >= input.len) return error.DataFailure;
    const t = input[ip.*];
    ip.* += 1;
    return t;
}

// Long literal and match lengths share the zero-run extension.
// Each zero byte adds 255; a final byte terminates the run.
fn readExtended(input: []const u8, ip: *usize, base: usize) Failure!usize {
    var t = base;
    while (true) {
        const b = try takeToken(input, ip);
        if (b != 0) return t + b;
        t += 255;
    }
}

fn copyLiterals(input: []const u8, output: []u8, ip: *usize, op: *usize, len: usize) Failure!void {
    if (len > input.len - ip.*) return error.DataFailure;
    if (len > output.len - op.*) return error.CapacityFailure;
    @memcpy(output[op.* .. op.* + len], input[ip.* .. ip.* + len]);
    ip.* += len;
    op.* += len;
}

// Byte-granular history copy: LZO matches may overlap the output cursor.
fn copyMatch(output: []u8, op: *usize, m_pos: usize, len: usize) Failure!void {
    if (len > output.len - op.*) return error.CapacityFailure;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        output[op.* + i] = output[m_pos + i];
    }
    op.* += len;
}

const Phase = enum { literal, match };

// Small token after literals: three-byte M1 match.
// Returns the next match token; zero reopens the literal phase.
fn m1AfterLiteral(input: []const u8, output: []u8, ip: *usize, op: *usize, t: usize) Failure!usize {
    const b = try takeToken(input, ip);
    const back = (1 + m2_max_offset) + (t >> 2) + (@as(usize, b) << 2);
    if (back > op.*) return error.DataFailure;
    try copyMatch(output, op, op.* - back, 3);
    if (ip.* < 2) return error.DataFailure;
    var bridge: usize = input[ip.* - 2] & 3;
    if (bridge == 0) return 0;
    try copyLiterals(input, output, ip, op, bridge);
    bridge = try takeToken(input, ip);
    return bridge;
}

pub fn decodeInPlace(input: []const u8, output: []u8) Failure!usize {
    if (input.len == 0) return error.DataFailure;
    var ip: usize = 0;
    var op: usize = 0;
    var t: usize = try takeToken(input, &ip);
    var phase: Phase = .literal;

    // A first token above 17 opens a literal run without the usual length encoding.
    if (t > 17) {
        t -= 17;
        try copyLiterals(input, output, &ip, &op, t);
        t = try takeToken(input, &ip);
        if (t < 16) {
            t = try m1AfterLiteral(input, output, &ip, &op, t);
            if (t == 0) {
                t = try takeToken(input, &ip);
                phase = .literal;
            } else {
                phase = .match;
            }
        } else {
            phase = .match;
        }
    }

    while (true) {
        if (phase == .literal) {
            if (t < 16) {
                var len = t;
                if (len == 0) len = try readExtended(input, &ip, 15);
                try copyLiterals(input, output, &ip, &op, len + 3);
                t = try takeToken(input, &ip);
                if (t < 16) {
                    t = try m1AfterLiteral(input, output, &ip, &op, t);
                    if (t == 0) {
                        t = try takeToken(input, &ip);
                        continue;
                    }
                }
            }
            phase = .match;
            continue;
        }

        // Every match ends with a two-bit literal bridge count.
        if (t >= 64) {
            // M2: eleven-bit offset, length in the top token bits.
            const b = try takeToken(input, &ip);
            const back = 1 + ((t >> 2) & 7) + (@as(usize, b) << 3);
            if (back > op) return error.DataFailure;
            const len = (t >> 5) + 1;
            try copyMatch(output, &op, op - back, len);
            t = if (ip >= 2) input[ip - 2] & 3 else return error.DataFailure;
        } else if (t >= 32) {
            // M3: fourteen-bit offset in the following two bytes.
            var len = t & 31;
            if (len == 0) len = try readExtended(input, &ip, 31);
            if (ip + 2 > input.len) return error.DataFailure;
            const off = (@as(usize, input[ip] >> 2) + (@as(usize, input[ip + 1]) << 6)) + 1;
            ip += 2;
            if (off > op) return error.DataFailure;
            try copyMatch(output, &op, op - off, len + 2);
            t = input[ip - 2] & 3;
        } else if (t >= 16) {
            // M4 widens the offset by 8 KiB via the third token bit.
            // A computed offset of zero terminates the stream.
            var len = t & 7;
            if (len == 0) len = try readExtended(input, &ip, 7);
            if (ip + 2 > input.len) return error.DataFailure;
            const wide = (t & 8) << 11;
            const off = @as(usize, input[ip] >> 2) + (@as(usize, input[ip + 1]) << 6);
            ip += 2;
            if (wide == 0 and off == 0) {
                if (ip != input.len) return error.DataFailure;
                return op;
            }
            const back = wide + off + m4_bias;
            if (back > op) return error.DataFailure;
            try copyMatch(output, &op, op - back, len + 2);
            t = input[ip - 2] & 3;
        } else {
            // M1 inside the chain: a two-byte copy with a short offset.
            const b = try takeToken(input, &ip);
            const back = 1 + (t >> 2) + (@as(usize, b) << 2);
            if (back > op) return error.DataFailure;
            try copyMatch(output, &op, op - back, 2);
            t = if (ip >= 2) input[ip - 2] & 3 else return error.DataFailure;
        }
        if (t == 0) {
            t = try takeToken(input, &ip);
            phase = .literal;
            continue;
        }
        try copyLiterals(input, output, &ip, &op, t);
        t = try takeToken(input, &ip);
    }
}

// Reference fixtures from the system LZO 2.10 compressor.
// Verified against its safe decoder before embedding.
pub const fixture0_plain = [_]u8{0x68,0x65,0x6c,0x6c,0x6f,0x20,0x6c,0x7a,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64,0x2c,0x20,0x68,0x65,0x6c,0x6c,0x6f,0x20,0x6c,0x7a,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64,0x2c,0x20,0x68,0x65,0x6c,0x6c,0x6f,0x20,0x6c,0x7a,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64,0x21,};
pub const fixture0_comp = [_]u8{0x0e,0x68,0x65,0x6c,0x6c,0x6f,0x20,0x6c,0x7a,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64,0x2c,0x20,0x32,0x40,0x00,0x0a,0x6c,0x6f,0x20,0x6c,0x7a,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64,0x21,0x11,0x00,0x00,};
// case 1 in=32 comp=28
pub const fixture1_plain = [_]u8{0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,};
pub const fixture1_comp = [_]u8{0x05,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x2a,0x1c,0x00,0x09,0x45,0x46,0x47,0x48,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x11,0x00,0x00,};
// case 2 in=50 comp=39
pub const fixture2_plain = [_]u8{0x00,0x00,0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x00,0x00,0x00,0x00,0xff,0xfe,0xfd,0x7f,0x80,0x81,};
pub const fixture2_comp = [_]u8{0x08,0x00,0x00,0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x61,0x32,0x00,0x00,0x00,0x01,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x61,0x00,0x00,0x00,0x00,0xff,0xfe,0xfd,0x7f,0x80,0x81,0x11,0x00,0x00,};

test "lzo1x decompresses reference fixtures" {
    const testing = std.testing;
    var out: [128]u8 = undefined;
    for ([_][]const u8{ &fixture0_comp, &fixture1_comp, &fixture2_comp }, [_][]const u8{ &fixture0_plain, &fixture1_plain, &fixture2_plain }) |comp, plain| {
        @memset(&out, 0);
        const n = try decodeInPlace(comp, &out);
        try testing.expectEqual(plain.len, n);
        try testing.expectEqualSlices(u8, plain, out[0..n]);
    }
}



// LZO1X-1, ported from the reference greedy matcher in vendor/lzo
// (src/lzo1x_c.ch). A 14-bit hash over little-endian words feeds a u16
// offset dictionary. Matches encode as M2 short forms, M3 within 0x4000,
// or M4 with the 0x4000 bias. Chunks cap at 49152 bytes so every offset
// stays encodable.

const m2_max_len: usize = 8;
const m3_max_offset: usize = 0x4000;
const m3_max_len: usize = 33;
const m4_max_len: usize = 9;
const m3_marker: u8 = 32;
const m4_marker: u8 = 16;
const dict_bits: u6 = 14;
const chunk_max: usize = 49152;

pub const encode_workspace_size: usize = (1 << dict_bits) * @sizeOf(u16);

fn hash4(word: u32) usize {
    return @intCast((word *% 0x1824429d) >> @intCast(32 - dict_bits));
}

fn load32(data: []const u8, at: usize) u32 {
    return std.mem.readInt(u32, data[at..][0..4], .little);
}

const Encoder = struct {
    dict: []u16,
    out: []u8,
    op: usize = 0,
    pending: usize = 0,

    fn emitByte(e: *Encoder, b: u8) Failure!void {
        if (e.op >= e.out.len) return error.CapacityFailure;
        e.out[e.op] = b;
        e.op += 1;
    }

    fn emitLiterals(e: *Encoder, input: []const u8, start: usize, len: usize) Failure!void {
        const t = len;
        if (t == 0) return;
        if (t <= 3) {
            if (e.op < 2) return error.DataFailure;
            e.out[e.op - 2] |= @intCast(t);
        } else if (t <= 18) {
            try e.emitByte(@intCast(t - 3));
        } else {
            try e.emitByte(0);
            var tt = t - 18;
            while (tt > 255) {
                try e.emitByte(0);
                tt -= 255;
            }
            try e.emitByte(@intCast(tt));
        }
        if (e.op + t > e.out.len) return error.CapacityFailure;
        @memcpy(e.out[e.op .. e.op + t], input[start .. start + t]);
        e.op += t;
    }

    fn emitMatch(e: *Encoder, len_in: usize, off_in: usize) Failure!void {
        var m_len = len_in;
        var m_off = off_in;
        if (m_len <= m2_max_len and m_off <= m2_max_offset) {
            m_off -= 1;
            try e.emitByte(@intCast(((m_len - 1) << 5) | ((m_off & 7) << 2)));
            try e.emitByte(@intCast(m_off >> 3));
        } else if (m_off <= m3_max_offset) {
            m_off -= 1;
            if (m_len <= m3_max_len) {
                try e.emitByte(m3_marker | @as(u8, @intCast(m_len - 2)));
            } else {
                m_len -= m3_max_len;
                try e.emitByte(m3_marker);
                while (m_len > 255) {
                    try e.emitByte(0);
                    m_len -= 255;
                }
                try e.emitByte(@intCast(m_len));
            }
            try e.emitByte(@truncate(m_off << 2));
            try e.emitByte(@truncate(m_off >> 6));
        } else {
            if (m_off > 0xBFFF) return error.UnsupportedFailure;
            m_off -= 0x4000;
            if (m_len <= m4_max_len) {
                try e.emitByte(m4_marker | @as(u8, @intCast((m_off >> 11) & 8)) | @as(u8, @intCast(m_len - 2)));
            } else {
                m_len -= m4_max_len;
                try e.emitByte(m4_marker | @as(u8, @intCast((m_off >> 11) & 8)));
                while (m_len > 255) {
                    try e.emitByte(0);
                    m_len -= 255;
                }
                try e.emitByte(@intCast(m_len));
            }
            try e.emitByte(@truncate(m_off << 2));
            try e.emitByte(@truncate(m_off >> 6));
        }
    }
};

fn compressChunk(e: *Encoder, input: []const u8, start: usize, len: usize, carry: usize) Failure!usize {
    @memset(e.dict, 0);
    var ip = start;
    const in_end = start + len;
    const ip_end = in_end -| 20;
    var ii = ip;
    var ti = carry;
    if (ti < 4) ip += 4 - ti;
    while (true) {
        if (ip >= ip_end) break;
        const dv = load32(input, ip);
        const dindex = hash4(dv);
        const prev_off: usize = e.dict[dindex];
        e.dict[dindex] = @intCast(ip - start);
        const m_pos = start + prev_off;
        if (prev_off == 0 or dv != load32(input, m_pos) or ip - m_pos > 0xBFFF) {
            // Acceleration: advance one extra position per literal step.
            ip += 1 + ((ip - ii) >> 5);
            continue;
        }
        var m_len: usize = 4;
        while (ip + m_len < in_end and input[ip + m_len] == input[m_pos + m_len]) m_len += 1;
        const lit_start = ii - ti;
        ti = 0;
        try e.emitLiterals(input, lit_start, ip - lit_start);
        try e.emitMatch(m_len, ip - m_pos);
        ip += m_len;
        ii = ip;
    }
    return in_end - (ii - ti);
}

pub fn encode(input: []const u8, output: []u8, workspace: []u8) Failure!usize {
    if (workspace.len < encode_workspace_size) return error.CapacityFailure;
    var e = Encoder{
        .dict = @alignCast(std.mem.bytesAsSlice(u16, workspace[0..encode_workspace_size])),
        .out = output,
    };
    var at: usize = 0;
    var t: usize = 0;
    while (input.len - at > 20) {
        const len = @min(chunk_max, input.len - at);
        t = try compressChunk(&e, input, at, len, t);
        at += len;
    }
    t += input.len - at;
    if (t > 0) {
        const ii = input.len - t;
        if (e.op == 0 and t <= 238) {
            try e.emitByte(@intCast(17 + t));
        } else if (t <= 3) {
            if (e.op < 2) return error.DataFailure;
            e.out[e.op - 2] |= @intCast(t);
        } else if (t <= 18) {
            try e.emitByte(@intCast(t - 3));
        } else {
            try e.emitByte(0);
            var tt = t - 18;
            while (tt > 255) {
                try e.emitByte(0);
                tt -= 255;
            }
            try e.emitByte(@intCast(tt));
        }
        if (e.op + t > e.out.len) return error.CapacityFailure;
        @memcpy(e.out[e.op .. e.op + t], input[ii .. ii + t]);
        e.op += t;
    }
    try e.emitByte(m4_marker | 1);
    try e.emitByte(0);
    try e.emitByte(0);
    return e.op;
}

test "lzo1x roundtrips reference fixtures" {
    const testing = std.testing;
    var workspace: [encode_workspace_size]u8 = undefined;
    for ([_][]const u8{ &fixture0_plain, &fixture1_plain, &fixture2_plain }) |plain| {
        var comp: [512]u8 = undefined;
        const n = try encode(plain, &comp, &workspace);
        var back: [128]u8 = undefined;
        const m = try decodeInPlace(comp[0..n], &back);
        try testing.expectEqual(plain.len, m);
        try testing.expectEqualSlices(u8, plain, back[0..m]);
    }
}

