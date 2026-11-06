// Module integration cases across compose drivers and codecs: session framing, round trips, chunk-matrix properties; helpers live in support.zig.

const std = @import("std");

const brotli_driver = @import("../compose/drivers/brotli.zig");
const deflate_driver = @import("../compose/drivers/deflate.zig");
const gzip_driver = @import("../compose/drivers/gzip.zig");
const lz4_driver = @import("../compose/drivers/lz4.zig");
const lz4_legacy_driver = @import("../compose/drivers/lz4_legacy.zig");
const tar_driver = @import("../compose/drivers/tar.zig");
const zlib_driver = @import("../compose/drivers/zlib.zig");
const gzip = @import("../representation/grammar/gzip/onprem.zig");
const tar = @import("../representation/grammar/tar/onprem.zig");
const zlib = @import("../representation/grammar/zlib/onprem.zig");
const brotli = @import("../representation/leaf/brotli/onprem.zig");
const lz4 = @import("../representation/leaf/lz4/onprem.zig");
const support = @import("support.zig");

const testing = std.testing;
const allocStateStorage = support.allocStateStorage;
const expectChunkedDecode = support.expectChunkedDecode;
const fillPayload = support.fillPayload;

test "gzip zlib and deflate sessions round trip through tiny output chunks" {
    const allocator = testing.allocator;
    var payload: [600]u8 = undefined;
    fillPayload(&payload);

    const history = try allocator.alloc(u8, gzip.deflate_history_size);
    defer allocator.free(history);

    const gzip_size = gzip_driver.gzipEncodedSizeBound(payload.len);
    const gzip_frame = try allocator.alloc(u8, gzip_size);
    defer allocator.free(gzip_frame);
    const gzip_len = try gzip_driver.gzipEncode(gzip_frame, &payload, history, gzip_driver.default_encode_options, .bounded);

    const zlib_options: zlib.Options = .{ .deflate = gzip_driver.default_encode_options.deflate };
    const zlib_size = zlib.encodedSizeBound(payload.len, zlib_options);
    const zlib_frame = try allocator.alloc(u8, zlib_size);
    defer allocator.free(zlib_frame);
    var zlib_len: usize = 0;
    {
        var source = std.Io.Reader.fixed(&payload);
        var sink = std.Io.Writer.fixed(zlib_frame);
        try zlib.encodeStream(&source, &sink, history, zlib_options);
        zlib_len = sink.end;
    }
    const deflate_frame = zlib_frame[2 .. zlib_len - 4];

    {
        const holder = try allocStateStorage(gzip_driver.GzipDecode, gzip_driver.gzipDecodeStorage(), allocator);
        defer allocator.free(holder.raw);
        try expectChunkedDecode(gzip_driver.GzipDecode, gzip_driver.gzipDecodeInit, gzip_driver.gzipDecodeStep, holder.aligned, gzip_frame[0..gzip_len], &payload, gzip_len, 8);
    }
    {
        const holder = try allocStateStorage(zlib_driver.ZlibDecode, zlib_driver.zlibDecodeStorage(), allocator);
        defer allocator.free(holder.raw);
        try expectChunkedDecode(zlib_driver.ZlibDecode, zlib_driver.zlibDecodeInit, zlib_driver.zlibDecodeStep, holder.aligned, zlib_frame[0..zlib_len], &payload, zlib_len, 8);
    }
    {
        const holder = try allocStateStorage(deflate_driver.DeflateDecode, deflate_driver.deflateDecodeStorage(), allocator);
        defer allocator.free(holder.raw);
        try expectChunkedDecode(deflate_driver.DeflateDecode, deflate_driver.deflateDecodeInit, deflate_driver.deflateDecodeStep, holder.aligned, deflate_frame, &payload, deflate_frame.len, 8);
    }

    // Two concatenated gzip members round trip through one session: the decoder must resync on the second member.
    const multi_frame = try allocator.alloc(u8, gzip_len * 2);
    defer allocator.free(multi_frame);
    @memcpy(multi_frame[0..gzip_len], gzip_frame[0..gzip_len]);
    @memcpy(multi_frame[gzip_len..], gzip_frame[0..gzip_len]);
    var joined: [payload.len * 2]u8 = undefined;
    @memcpy(joined[0..payload.len], &payload);
    @memcpy(joined[payload.len..], &payload);
    {
        const holder = try allocStateStorage(gzip_driver.GzipDecode, gzip_driver.gzipDecodeStorage(), allocator);
        defer allocator.free(holder.raw);
        try expectChunkedDecode(gzip_driver.GzipDecode, gzip_driver.gzipDecodeInit, gzip_driver.gzipDecodeStep, holder.aligned, multi_frame, &joined, multi_frame.len, 8);
    }
}

test "gzip zlib and deflate round trips hold across the input chunk matrix" {
    const allocator = testing.allocator;
    var payload: [600]u8 = undefined;
    fillPayload(&payload);

    const history = try allocator.alloc(u8, gzip.deflate_history_size);
    defer allocator.free(history);

    const gzip_size = gzip_driver.gzipEncodedSizeBound(payload.len);
    const gzip_frame = try allocator.alloc(u8, gzip_size);
    defer allocator.free(gzip_frame);
    const gzip_len = try gzip_driver.gzipEncode(gzip_frame, &payload, history, gzip_driver.default_encode_options, .bounded);

    const zlib_options: zlib.Options = .{ .deflate = gzip_driver.default_encode_options.deflate };
    const zlib_size = zlib.encodedSizeBound(payload.len, zlib_options);
    const zlib_frame = try allocator.alloc(u8, zlib_size);
    defer allocator.free(zlib_frame);
    var zlib_len: usize = 0;
    {
        var source = std.Io.Reader.fixed(&payload);
        var sink = std.Io.Writer.fixed(zlib_frame);
        try zlib.encodeStream(&source, &sink, history, zlib_options);
        zlib_len = sink.end;
    }
    const deflate_frame = zlib_frame[2 .. zlib_len - 4];

    const gzip_holder = try allocStateStorage(gzip_driver.GzipDecode, gzip_driver.gzipDecodeStorage(), allocator);
    defer allocator.free(gzip_holder.raw);
    const zlib_holder = try allocStateStorage(zlib_driver.ZlibDecode, zlib_driver.zlibDecodeStorage(), allocator);
    defer allocator.free(zlib_holder.raw);
    const deflate_holder = try allocStateStorage(deflate_driver.DeflateDecode, deflate_driver.deflateDecodeStorage(), allocator);
    defer allocator.free(deflate_holder.raw);
    // For every input chunk size crossed with draining and bulk output chunks, the stepped session reproduces the exact payload.
    inline for (1..17) |chunk| {
        inline for ([_]usize{ 8, 4096 }) |out_chunk| {
            try expectChunkedDecode(gzip_driver.GzipDecode, gzip_driver.gzipDecodeInit, gzip_driver.gzipDecodeStep, gzip_holder.aligned, gzip_frame[0..gzip_len], &payload, chunk, out_chunk);
            try expectChunkedDecode(zlib_driver.ZlibDecode, zlib_driver.zlibDecodeInit, zlib_driver.zlibDecodeStep, zlib_holder.aligned, zlib_frame[0..zlib_len], &payload, chunk, out_chunk);
            try expectChunkedDecode(deflate_driver.DeflateDecode, deflate_driver.deflateDecodeInit, deflate_driver.deflateDecodeStep, deflate_holder.aligned, deflate_frame, &payload, chunk, out_chunk);
        }
    }
}

test "brotli sessions match the one shot oracle across chunk matrices and stream boundaries" {
    const allocator = testing.allocator;
    const dec_holder = try allocStateStorage(brotli_driver.BrotliDecode, brotli_driver.brotliDecodeStorage(), allocator);
    defer allocator.free(dec_holder.raw);
    const enc_holder = try allocStateStorage(brotli_driver.BrotliDecode, brotli.encodeWorkspaceSize(.{}) + 65536, allocator);
    defer allocator.free(enc_holder.raw);

    const inputs = [_][]const u8{
        "hello world, hello world, hello world!",
        "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc",
    };
    for (inputs) |input| {
        const bound = brotli.encodedSizeBound(input.len);
        const encoded = try allocator.alloc(u8, bound);
        defer allocator.free(encoded);
        const enc_len = try brotli.encode(input, encoded, enc_holder.aligned[0..brotli.encodeWorkspaceSize(.{})], .{});
        var oracle: [256]u8 = undefined;
        const oracle_scratch = try allocator.alloc(u8, brotli.decode_workspace_size);
        defer allocator.free(oracle_scratch);
        const n = try brotli.decode(encoded[0..enc_len], &oracle, oracle_scratch, .{});
        for ([_]usize{ 1, 7, 64, enc_len }) |chunk| {
            try expectChunkedDecode(brotli_driver.BrotliDecode, brotli_driver.brotliDecodeInit, brotli_driver.brotliDecodeStep, dec_holder.aligned, encoded[0..enc_len], oracle[0..n], chunk, 4096);
        }
    }

    // A multi-megablock stream plus a concatenated second stream exercise
    // metablock boundaries and the stream-boundary reset across steps.
    var big: [1 << 17]u8 = undefined;
    var state: u64 = 0x243F6A8885A308D3;
    for (&big) |*b| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        b.* = @as(u8, @truncate(state)) & 7;
    }
    for (1..8) |i| @memcpy(big[(1 << 14) * i ..][0..4096], big[0..4096]);
    const big_bound = brotli.encodedSizeBound(big.len) + brotli.encodedSizeBound(64);
    const stream = try allocator.alloc(u8, big_bound);
    defer allocator.free(stream);
    const part_len = try brotli.encode(&big, stream, enc_holder.aligned[0..brotli.encodeWorkspaceSize(.{})], .{});
    const tail_len = try brotli.encode("second stream", stream[part_len..], enc_holder.aligned[0..brotli.encodeWorkspaceSize(.{})], .{});
    const total = part_len + tail_len;
    const oracle = try allocator.alloc(u8, big.len + 16);
    defer allocator.free(oracle);
    const oracle_scratch = try allocator.alloc(u8, brotli.decode_workspace_size);
    defer allocator.free(oracle_scratch);
    const n = try brotli.decode(stream[0..total], oracle, oracle_scratch, .{});
    for ([_]usize{ 1, 13, 4096, total }) |chunk| {
        for ([_]usize{ 1, 1000, 65536 }) |out_chunk| {
            try expectChunkedDecode(brotli_driver.BrotliDecode, brotli_driver.brotliDecodeInit, brotli_driver.brotliDecodeStep, dec_holder.aligned, stream[0..total], oracle[0..n], chunk, out_chunk);
        }
    }
}

test "lz4 legacy sessions frame blocks honor termination and reject malformed sizes" {
    const allocator = testing.allocator;
    const holder = try allocStateStorage(lz4_legacy_driver.Lz4LegacyDecode, lz4_legacy_driver.lz4LegacyDecodeStorage(), allocator);
    defer allocator.free(holder.raw);

    const payload_a = try allocator.alloc(u8, 70000);
    defer allocator.free(payload_a);
    @memcpy(payload_a[0..16], "legacy block a: ");
    @memset(payload_a[16..], 'a');
    const payload_b = try allocator.alloc(u8, 1024 * 1024 - 13);
    defer allocator.free(payload_b);
    var rng: u64 = 0x9E3779B97F4A7C15;
    for (payload_b) |*b| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        b.* = @as(u8, @truncate(rng)) & 3;
    }
    for (1..15) |i| @memcpy(payload_b[i * 65536 ..][0..8192], payload_b[0..8192]);

    const hash_table = try allocator.alloc(u32, lz4_driver.lz4_hash_words);
    defer allocator.free(hash_table);
    const comp_a = try allocator.alloc(u8, lz4_driver.lz4BlockCompressBound(payload_a.len));
    defer allocator.free(comp_a);
    const comp_b = try allocator.alloc(u8, lz4_driver.lz4BlockCompressBound(payload_b.len));
    defer allocator.free(comp_b);
    const a_len = lz4.compressBlock(payload_a, comp_a, hash_table, 1);
    const b_len = lz4.compressBlock(payload_b, comp_b, hash_table, 1);

    var frame = try allocator.alloc(u8, 4 + 4 + a_len + 4 + b_len);
    defer allocator.free(frame);
    var len: usize = 0;
    std.mem.writeInt(u32, frame[len..][0..4], 0x184C2102, .little);
    len += 4;
    std.mem.writeInt(u32, frame[len..][0..4], @intCast(a_len), .little);
    len += 4;
    @memcpy(frame[len..][0..a_len], comp_a[0..a_len]);
    len += a_len;
    std.mem.writeInt(u32, frame[len..][0..4], @intCast(b_len), .little);
    len += 4;
    @memcpy(frame[len..][0..b_len], comp_b[0..b_len]);
    len += b_len;

    const expected = try allocator.alloc(u8, payload_a.len + payload_b.len);
    defer allocator.free(expected);
    @memcpy(expected[0..payload_a.len], payload_a);
    @memcpy(expected[payload_a.len..], payload_b);
    for ([_]usize{ 1, 7, 4096, frame.len }) |chunk| {
        try expectChunkedDecode(lz4_legacy_driver.Lz4LegacyDecode, lz4_legacy_driver.lz4LegacyDecodeInit, lz4_legacy_driver.lz4LegacyDecodeStep, holder.aligned, frame, expected, chunk, 65536);
    }

    // The near-8 MiB block exercises the staging bound; larger chunks keep
    // the step count sane.
    const payload_c = try allocator.alloc(u8, 8 * 1024 * 1024 - 13);
    defer allocator.free(payload_c);
    @memcpy(payload_c[0..16], "legacy block c: ");
    var rng_c: u64 = 0xD1B54A32D192ED03;
    for (payload_c[16..]) |*b| {
        rng_c ^= rng_c << 13;
        rng_c ^= rng_c >> 7;
        rng_c ^= rng_c << 17;
        b.* = @as(u8, @truncate(rng_c)) & 3;
    }
    for (1..128) |i| @memcpy(payload_c[i * 65536 ..][0..8192], payload_c[0..8192]);
    const comp_c = try allocator.alloc(u8, lz4_driver.lz4BlockCompressBound(payload_c.len));
    defer allocator.free(comp_c);
    const c_len = lz4.compressBlock(payload_c, comp_c, hash_table, 1);
    const frame_c = try allocator.alloc(u8, 4 + 4 + c_len + 4);
    defer allocator.free(frame_c);
    std.mem.writeInt(u32, frame_c[0..4], 0x184C2102, .little);
    std.mem.writeInt(u32, frame_c[4..8], @intCast(c_len), .little);
    @memcpy(frame_c[8..][0..c_len], comp_c[0..c_len]);
    std.mem.writeInt(u32, frame_c[8 + c_len ..][0..4], 0, .little);
    for ([_]usize{ 4096, frame_c.len }) |chunk| {
        try expectChunkedDecode(lz4_legacy_driver.Lz4LegacyDecode, lz4_legacy_driver.lz4LegacyDecodeInit, lz4_legacy_driver.lz4LegacyDecodeStep, holder.aligned, frame_c, payload_c, chunk, 1 << 20);
    }

    // The kernel zero terminator ends the frame; trailing bytes and
    // oversize blocks are format errors.
    var terminated: [8]u8 = undefined;
    std.mem.writeInt(u32, terminated[0..4], 0x184C2106, .little);
    std.mem.writeInt(u32, terminated[4..8], 0, .little);
    try expectChunkedDecode(lz4_legacy_driver.Lz4LegacyDecode, lz4_legacy_driver.lz4LegacyDecodeInit, lz4_legacy_driver.lz4LegacyDecodeStep, holder.aligned, &terminated, &[_]u8{}, terminated.len, 16);
    var trailing = terminated;
    trailing[0] = 0xAA;
    try testing.expectError(error.DataException, expectChunkedDecode(lz4_legacy_driver.Lz4LegacyDecode, lz4_legacy_driver.lz4LegacyDecodeInit, lz4_legacy_driver.lz4LegacyDecodeStep, holder.aligned, &trailing, &[_]u8{}, trailing.len, 16));
    var oversize: [8]u8 = undefined;
    std.mem.writeInt(u32, oversize[0..4], 0x184C2102, .little);
    std.mem.writeInt(u32, oversize[4..8], @intCast(lz4_driver.lz4BlockCompressBound(8 * 1024 * 1024) + 1), .little);
    try testing.expectError(error.DataException, expectChunkedDecode(lz4_legacy_driver.Lz4LegacyDecode, lz4_legacy_driver.lz4LegacyDecodeInit, lz4_legacy_driver.lz4LegacyDecodeStep, holder.aligned, &oversize, &[_]u8{}, oversize.len, 16));
    // Truncation inside a block is a data error at end of input.
    try testing.expectError(error.DataException, expectChunkedDecode(lz4_legacy_driver.Lz4LegacyDecode, lz4_legacy_driver.lz4LegacyDecodeInit, lz4_legacy_driver.lz4LegacyDecodeStep, holder.aligned, frame[0 .. len - 3], expected, 1, 65536));
}

test "tar encode sessions frame headers data and pax spill like the slice oracle" {
    const allocator = testing.allocator;
    const holder = try allocStateStorage(tar_driver.TarEncode, tar_driver.tarEncodeStorage(), allocator);
    defer allocator.free(holder.raw);

    const small = "hello tar streaming";
    var binary: [600]u8 = undefined;
    var rng: u64 = 0x2545F4914F6CDD1D;
    for (&binary) |*b| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        b.* = @as(u8, @truncate(rng));
    }
    const entries = [_]tar.Entry{
        .{ .name = "a.txt", .data = small, .modification_time = 1000000000 },
        .{ .name = "empty.bin", .data = &.{} },
        .{ .name = "dir/nested.bin", .data = &binary, .mode = 0o600, .uid = 7, .gid = 8 },
        .{ .name = "five", .data = "12345" },
    };
    // No pax fields: the slice encoder emits one header per entry, so
    // its output is the framing oracle.
    const oracle = try allocator.alloc(u8, try tar.archiveSize(&entries));
    defer allocator.free(oracle);
    const oracle_scratch = try allocator.alloc(u8, tar.scratch_size);
    defer allocator.free(oracle_scratch);
    const oracle_len = try tar.encode(&entries, oracle, oracle_scratch);

    var logical = try allocator.alloc(u8, oracle_len);
    defer allocator.free(logical);
    var logical_len: usize = 0;
    for (entries) |entry| {
        var header: [512]u8 = undefined;
        try tar.formatHeaderBlock(.posix, entry.name, &.{}, entry.link_name, entry.mode, entry.uid, entry.gid, entry.modification_time, entry.typeflag, entry.data.len, entry.devmajor, entry.devminor, &header);
        @memcpy(logical[logical_len..][0..512], &header);
        logical_len += 512;
        @memcpy(logical[logical_len..][0..entry.data.len], entry.data);
        logical_len += entry.data.len;
    }
    // formatHeaderBlock and the slice encoder must emit identical header
    // bytes for the same entry.
    var probe: [512]u8 = undefined;
    try tar.formatHeaderBlock(.posix, entries[2].name, &.{}, entries[2].link_name, entries[2].mode, entries[2].uid, entries[2].gid, entries[2].modification_time, entries[2].typeflag, entries[2].data.len, 0, 0, &probe);
    // The third entry begins at 1024 + 512: the first is aligned to
    // 1024, the second has no data.
    try testing.expectEqualSlices(u8, oracle[1536 .. 1536 + 512], &probe);

    for ([_]usize{ 1, 7, 511, 512, 513, 4096, logical_len }) |chunk| {
        const state = try tar_driver.tarEncodeInit(holder.aligned, .{});
        const out = try allocator.alloc(u8, 1024);
        defer allocator.free(out);
        const produced_all = try allocator.alloc(u8, oracle_len);
        defer allocator.free(produced_all);
        var in_pos: usize = 0;
        var out_pos: usize = 0;
        var guard: usize = 0;
        while (true) : (guard += 1) {
            try testing.expect(guard < 4_000_000);
            const take = @min(chunk, logical_len - in_pos);
            const result = tar_driver.tarEncodeStep(state, logical[in_pos..][0..take], out, in_pos + take == logical_len);
            try testing.expect(result.status != .failed);
            @memcpy(produced_all[out_pos..][0..result.produced], out[0..result.produced]);
            in_pos += result.consumed;
            out_pos += result.produced;
            if (result.status == .done) break;
        }
        try testing.expectEqual(oracle_len, out_pos);
        try testing.expectEqualSlices(u8, oracle[0..oracle_len], produced_all[0..out_pos]);
    }

    // A pax spill entry (an 'x' header carrying pax records) frames
    // through the driver like any size-carrying entry.
    const pax_data = "20 mtime=1700000000\n";
    var pax_header: [512]u8 = undefined;
    try tar.formatHeaderBlock(.posix, "././@PaxHeader", &.{}, &.{}, 0o644, 0, 0, 0, 'x', pax_data.len, 0, 0, &pax_header);
    const with_pax = [_]tar.Entry{
        .{ .name = "a.txt", .data = small, .modification_time = 1700000000 },
    };
    const pax_oracle = try allocator.alloc(u8, try tar.archiveSize(&with_pax));
    defer allocator.free(pax_oracle);
    const pax_oracle_len = try tar.encode(&with_pax, pax_oracle, oracle_scratch);
    var pax_logical = try allocator.alloc(u8, 512 + pax_data.len + 512 + with_pax[0].data.len);
    defer allocator.free(pax_logical);
    var pax_pos: usize = 0;
    @memcpy(pax_logical[pax_pos..][0..512], &pax_header);
    pax_pos += 512;
    @memcpy(pax_logical[pax_pos..][0..pax_data.len], pax_data);
    pax_pos += pax_data.len;
    var main_header: [512]u8 = undefined;
    try tar.formatHeaderBlock(.posix, with_pax[0].name, &.{}, with_pax[0].link_name, with_pax[0].mode, 0, 0, with_pax[0].modification_time, with_pax[0].typeflag, with_pax[0].data.len, 0, 0, &main_header);
    @memcpy(pax_logical[pax_pos..][0..512], &main_header);
    pax_pos += 512;
    @memcpy(pax_logical[pax_pos..][0..with_pax[0].data.len], with_pax[0].data);
    pax_pos += with_pax[0].data.len;
    const pax_state = try tar_driver.tarEncodeInit(holder.aligned, .{});
    const pax_out = try allocator.alloc(u8, 4096);
    defer allocator.free(pax_out);
    var pax_produced = try allocator.alloc(u8, pax_oracle_len);
    defer allocator.free(pax_produced);
    var pax_in: usize = 0;
    var pax_out_pos: usize = 0;
    while (true) {
        const take = @min(97, pax_logical.len - pax_in);
        const result = tar_driver.tarEncodeStep(pax_state, pax_logical[pax_in..][0..take], pax_out, pax_in + take == pax_logical.len);
        try testing.expect(result.status != .failed);
        @memcpy(pax_produced[pax_out_pos..][0..result.produced], pax_out[0..result.produced]);
        pax_in += result.consumed;
        pax_out_pos += result.produced;
        if (result.status == .done) break;
    }
    try testing.expectEqual(pax_oracle_len, pax_out_pos);
    try testing.expectEqualSlices(u8, pax_oracle[0..pax_oracle_len], pax_produced[0..pax_out_pos]);
}
