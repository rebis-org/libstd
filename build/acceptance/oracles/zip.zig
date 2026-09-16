const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const fixtures = @import("fixtures.zig");
const harness = @import("harness.zig");
const Runner = harness.Runner;
const EntryNodes = harness.ArchiveEntryNodes;
const entryWithMethod = harness.archiveEntryMethod;
const lib = @import("lib.zig");

const zip_caps: u64 = harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay;

// Output is poisoned first so a short write cannot match by luck.
fn zipReadOrdinal0(r: *Runner, archive: []const u8, output: []u8, expected: []const u8) !void {
    @memset(output, 0xa5);
    try harness.spanProduce(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(archive),
        harness.sinkSpan(output),
    });
    if (r.response.byte_length != expected.len or !std.mem.eql(u8, output[0..expected.len], expected)) {
        return error.ZipReadMismatch;
    }
}

fn expectCryptoRejection(r: *Runner, sink: []u8, password: []const u8, extra: harness.Node, entries: harness.Node, status: u32, diag: *harness.CryptoDiag, checked: *harness.Node) !void {
    try harness.expect(r, harness.ids.write, &.{
        harness.paramProfile(r.profile_id),
        harness.scalarNode(harness.ids.source),
        harness.sinkSpan(sink),
        harness.capabilityParam(zip_caps),
        harness.sizingModeParam(harness.size_metadata_exact),
        harness.commitModeParam(harness.commit_confirmed),
        harness.cryptoProfile(),
        harness.cryptoPasswordParam(password),
        extra,
        entries,
    }, .{ .profile = false, .diagnostic = &diag.diagnostic }, status);
    if (checked.value_low != status) return error.CryptoDiagnosticMismatch;
}

fn setupZip(r: *Runner) void {
    harness.setup(r, harness.ids.zip, harness.mode_archive);
}

var zip_small: [32]u8 = undefined;
var zip_large: [445]u8 = undefined;
var zip_big: [882]u8 = undefined;
var zip_encmethods_payload: [128]u8 = undefined;
var zip_enc_archive: [4096]u8 = undefined;
var zip_enc_archive_size: usize = 0;
var zip_trad_archive: [16384]u8 = undefined;
var zip_trad_archive_size: usize = 0;
var zip_methods_archive: [65536]u8 = undefined;

fn zipWrapOne(out: []u8, name: []const u8, method: u16, flags: u16, compressed: []const u8, crc: u32, uncompressed_size: u32) usize {
    @memset(out[0..512], 0);
    var pos: usize = 0;
    const put16 = struct {
        fn f(dst: []u8, cursor: *usize, value: u16) void {
            dst[cursor.*] = @truncate(value);
            dst[cursor.* + 1] = @truncate(value >> 8);
            cursor.* += 2;
        }
    }.f;
    const put32 = struct {
        fn f(dst: []u8, cursor: *usize, value: u32) void {
            dst[cursor.*] = @truncate(value);
            dst[cursor.* + 1] = @truncate(value >> 8);
            dst[cursor.* + 2] = @truncate(value >> 16);
            dst[cursor.* + 3] = @truncate(value >> 24);
            cursor.* += 4;
        }
    }.f;
    out[pos..][0..4].* = "PK\x03\x04".*;
    pos += 4;
    out[pos] = 20;
    pos += 1;
    out[pos] = 0;
    pos += 1;
    put16(out, &pos, flags);
    put16(out, &pos, method);
    put32(out, &pos, 0);
    put32(out, &pos, crc);
    put32(out, &pos, @intCast(compressed.len));
    put32(out, &pos, uncompressed_size);
    put16(out, &pos, @intCast(name.len));
    put16(out, &pos, 0);
    @memcpy(out[pos .. pos + name.len], name);
    pos += name.len;
    @memcpy(out[pos .. pos + compressed.len], compressed);
    pos += compressed.len;
    const local_size = pos;
    const central = pos;
    out[pos..][0..4].* = "PK\x01\x02".*;
    pos += 4;
    out[pos] = 20;
    pos += 1;
    out[pos] = 0;
    pos += 1;
    out[pos] = 20;
    pos += 1;
    out[pos] = 0;
    pos += 1;
    put16(out, &pos, flags);
    put16(out, &pos, method);
    put32(out, &pos, 0);
    put32(out, &pos, crc);
    put32(out, &pos, @intCast(compressed.len));
    put32(out, &pos, uncompressed_size);
    put16(out, &pos, @intCast(name.len));
    put16(out, &pos, 0);
    put16(out, &pos, 0);
    put16(out, &pos, 0);
    put16(out, &pos, 0);
    put32(out, &pos, 0);
    put32(out, &pos, 0);
    @memcpy(out[pos .. pos + name.len], name);
    pos += name.len;
    const central_end = pos;
    out[pos..][0..4].* = "PK\x05\x06".*;
    pos += 4;
    put32(out, &pos, 0);
    put16(out, &pos, 1);
    put16(out, &pos, 1);
    const central_size = central_end - central;
    put32(out, &pos, @intCast(central_size));
    put32(out, &pos, @intCast(local_size));
    put16(out, &pos, 0);
    return pos;
}

fn cryptoNodes(password: []const u8, algo: ?u64, kdf_limit: ?u64, lifetime: ?u64, out: *[5]harness.Node) usize {
    var count: usize = 0;
    if (password.len != 0) {
        out[count] = harness.cryptoProfile();
        count += 1;
        out[count] = harness.cryptoPasswordParam(password);
        count += 1;
    }
    if (algo) |value| {
        out[count] = harness.cryptoAlgorithmParam(value);
        count += 1;
    }
    if (kdf_limit) |value| {
        out[count] = harness.cryptoKdfLimitParam(value);
        count += 1;
    }
    if (lifetime) |value| {
        out[count] = harness.cryptoPasswordLifetimeParam(value);
        count += 1;
    }
    return count;
}

fn zipWriteWithCrypto(r: *Runner, entries: harness.Node, archive: []u8, password: []const u8, algo: ?u64, kdf_limit: ?u64, lifetime: ?u64) !usize {
    var crypto: [5]harness.Node = undefined;
    const crypto_count = cryptoNodes(password, algo, kdf_limit, lifetime, &crypto);
    var nodes: [12]harness.Node = undefined;
    var count: usize = 0;
    nodes[count] = harness.paramTargetCommand(harness.ids.write);
    count += 1;
    nodes[count] = harness.scalarNode(harness.ids.source);
    count += 1;
    nodes[count] = harness.capabilityParam(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay);
    count += 1;
    nodes[count] = harness.sizingModeParam(harness.size_metadata_exact);
    count += 1;
    nodes[count] = harness.commitModeParam(harness.commit_confirmed);
    count += 1;
    @memcpy(nodes[count..][0..crypto_count], crypto[0..crypto_count]);
    count += crypto_count;
    nodes[count] = entries;
    count += 1;
    _ = harness.call(r, harness.ids.query, nodes[0..count], .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length == 0 or r.response.byte_length > archive.len) return error.ZipQueryCapacity;
    const size: usize = @intCast(r.response.byte_length);
    count = 0;
    nodes[count] = harness.scalarNode(harness.ids.source);
    count += 1;
    nodes[count] = harness.sinkSpan(archive[0..size]);
    count += 1;
    nodes[count] = harness.capabilityParam(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay);
    count += 1;
    nodes[count] = harness.sizingModeParam(harness.size_metadata_exact);
    count += 1;
    nodes[count] = harness.commitModeParam(harness.commit_confirmed);
    count += 1;
    @memcpy(nodes[count..][0..crypto_count], crypto[0..crypto_count]);
    count += crypto_count;
    nodes[count] = entries;
    count += 1;
    _ = harness.call(r, harness.ids.write, nodes[0..count], .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != size) return error.ZipWriteLengthMismatch;
    return size;
}

fn zipReadWithPassword(r: *Runner, archive: []const u8, ordinal: u64, output: []u8, password: []const u8) !usize {
    var crypto: [5]harness.Node = undefined;
    const crypto_count = cryptoNodes(password, null, null, null, &crypto);
    var nodes: [7]harness.Node = undefined;
    var count: usize = 0;
    nodes[count] = harness.archiveOrdinalParam(ordinal);
    count += 1;
    nodes[count] = harness.sourceSpan(archive);
    count += 1;
    nodes[count] = harness.sinkSpan(output);
    count += 1;
    @memcpy(nodes[count..][0..crypto_count], crypto[0..crypto_count]);
    count += crypto_count;
    _ = harness.call(r, harness.ids.read, nodes[0..count], .{ .ctx = true });
    return @intCast(r.response.byte_length);
}

fn runEncrypted(r: *Runner) anyerror!void {
    setupZip(r);
    corpus.select(r.corpus_index, &zip_small);
    corpus.select(r.corpus_index, &zip_large);
    var store1: EntryNodes = undefined;
    var store2: EntryNodes = undefined;
    const entry1 = entryWithMethod(&store1, "a.txt", &zip_small, 8);
    const entry2 = entryWithMethod(&store2, "b.txt", &zip_large, 0);
    var entries = [_]harness.Node{ entry1, entry2 };
    entries[0].next = &entries[1];
    const password = "s3cret";
    zip_enc_archive_size = try zipWriteWithCrypto(r, entries[0], &zip_enc_archive, password, null, null, null);
    const version: u16 = @as(u16, zip_enc_archive[4]) | (@as(u16, zip_enc_archive[5]) << 8);
    const flags: u16 = @as(u16, zip_enc_archive[6]) | (@as(u16, zip_enc_archive[7]) << 8);
    const method: u16 = @as(u16, zip_enc_archive[8]) | (@as(u16, zip_enc_archive[9]) << 8);
    const crc: u32 = @as(u32, zip_enc_archive[14]) | (@as(u32, zip_enc_archive[15]) << 8) | (@as(u32, zip_enc_archive[16]) << 16) | (@as(u32, zip_enc_archive[17]) << 24);
    const name_length: u16 = @as(u16, zip_enc_archive[26]) | (@as(u16, zip_enc_archive[27]) << 8);
    const extra_length: u16 = @as(u16, zip_enc_archive[28]) | (@as(u16, zip_enc_archive[29]) << 8);
    if (method != 99 or (flags & 1) == 0 or version != 51 or crc != 0 or name_length != 5 or extra_length != 11) {
        return error.EncryptedLocalHeaderMismatch;
    }
    const extra = zip_enc_archive[30 + name_length ..];
    const ef_id: u16 = @as(u16, extra[0]) | (@as(u16, extra[1]) << 8);
    const ef_len: u16 = @as(u16, extra[2]) | (@as(u16, extra[3]) << 8);
    if (ef_id != 0x9901 or ef_len != 7 or extra[4] != 2 or extra[5] != 0 or extra[6] != 'A' or extra[7] != 'E' or extra[8] != 3) {
        return error.AesExtraFieldMismatch;
    }
    const actual_method: u16 = @as(u16, extra[9]) | (@as(u16, extra[10]) << 8);
    if (actual_method != 8) return error.AesActualMethodMismatch;
    var output: [1024]u8 = undefined;
    _ = try zipReadWithPassword(r, zip_enc_archive[0..zip_enc_archive_size], 0, &output, password);
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != zip_small.len or !std.mem.eql(u8, output[0..zip_small.len], &zip_small)) {
        return error.EncryptedSpanReadMismatch;
    }
    var output2: [512]u8 = undefined;
    _ = try zipReadWithPassword(r, zip_enc_archive[0..zip_enc_archive_size], 1, &output2, password);
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != zip_large.len or !std.mem.eql(u8, output2[0..zip_large.len], &zip_large)) {
        return error.EncryptedOrdinalMismatch;
    }
    var source_ctx = harness.SourceCallbackContext{ .data = zip_enc_archive[0..zip_enc_archive_size] };
    _ = harness.call(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceCallbackNode(0, 0),
        harness.sinkSpan(&output),
        harness.cryptoProfile(),
        harness.cryptoPasswordParam(password),
    }, .{ .ctx = true, .callback = harness.sourceCallback, .context = &source_ctx });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != zip_small.len or !std.mem.eql(u8, output[0..zip_small.len], &zip_small)) {
        return error.EncryptedCallbackReadMismatch;
    }
    try harness.reject(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(zip_enc_archive[0..zip_enc_archive_size]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true }, abi.Status.unsupported, &output);
    var diag: harness.CryptoDiag = undefined;
    harness.cryptoDiag(&diag);
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(zip_enc_archive[0..zip_enc_archive_size]),
        harness.sinkSpan(&output),
        harness.cryptoProfile(),
        harness.cryptoPasswordParam("wrong"),
    }, .{ .ctx = true, .diagnostic = &diag.diagnostic });
    try harness.requireStatus(r, abi.Status.invalid_data);
    if (diag.wrong_password.value_low != abi.Status.invalid_data or !harness.allBytesEqual(&output, 0xa5)) {
        return error.WrongPasswordDiagnosticMismatch;
    }
    zip_enc_archive[64] ^= 0xff;
    const corrupted_nodes = &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(zip_enc_archive[0..zip_enc_archive_size]),
        harness.sinkSpan(&output),
        harness.cryptoProfile(),
        harness.cryptoPasswordParam(password),
    };
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, corrupted_nodes, .{ .ctx = true });
    zip_enc_archive[64] ^= 0xff;
    try harness.requireStatus(r, abi.Status.integrity_failure);
    if (!harness.allBytesEqual(&output, 0xa5)) return error.EncryptedCorruptionChangedOutput;
    try harness.rejectAny(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(zip_enc_archive[0 .. zip_enc_archive_size / 2]),
        harness.sinkSpan(&output),
        harness.cryptoProfile(),
        harness.cryptoPasswordParam(password),
    }, .{ .ctx = true }, &output);
    var sink_buffer: [512]u8 = undefined;
    var diag2: harness.CryptoDiag = undefined;
    harness.cryptoDiag(&diag2);
    try expectCryptoRejection(r, &sink_buffer, password, harness.cryptoKdfLimitParam(500), entries[0], abi.Status.resource_limit, &diag2, &diag2.kdf_limit);
    var diag3: harness.CryptoDiag = undefined;
    harness.cryptoDiag(&diag3);
    try expectCryptoRejection(r, &sink_buffer, password, harness.cryptoPasswordLifetimeParam(1), entries[0], abi.Status.resource_limit, &diag3, &diag3.password_lifetime);
    var diag4: harness.CryptoDiag = undefined;
    harness.cryptoDiag(&diag4);
    try expectCryptoRejection(r, &sink_buffer, password, harness.cryptoAlgorithmParam(1), entries[0], abi.Status.unsupported, &diag4, &diag4.unsupported_algorithm);
    try harness.expect(r, harness.ids.write, &.{
        harness.scalarNode(harness.ids.source),
        harness.sinkSpan(&sink_buffer),
        harness.capabilityParam(zip_caps),
        harness.sizingModeParam(harness.size_metadata_exact),
        harness.commitModeParam(harness.commit_confirmed),
        harness.cryptoPasswordParam(password),
        entries[0],
    }, .{}, abi.Status.invalid_call);
    try harness.expect(r, harness.ids.write, &.{
        harness.scalarNode(harness.ids.source),
        harness.sinkSpan(&sink_buffer),
        harness.capabilityParam(zip_caps),
        harness.sizingModeParam(harness.size_metadata_exact),
        harness.commitModeParam(harness.commit_confirmed),
        harness.cryptoProfile(),
        entries[0],
    }, .{}, abi.Status.invalid_call);
    const expected = [_]lib.ExpectedEntry{
        .{ .name = "a.txt", .data = &zip_small },
        .{ .name = "b.txt", .data = &zip_large },
    };
    const oracle = lib.archiveReadMatches(zip_enc_archive[0..zip_enc_archive_size], &expected);
    if (oracle == .mismatch) return error.EncryptedOracleRejected;
    if (oracle == .unsupported) std.debug.print("zip encrypted oracle: unsupported (libarchive cannot read AES zip).\n", .{});
    const fixture_data = [_][]const u8{ &fixtures.zip_aes128_fixture, &fixtures.zip_aes192_fixture, &fixtures.zip_aes256_fixture };
    const fixture_expected = "encrypted\n";
    for (fixture_data) |fixture_bytes| {
        var fixture_output: [1024]u8 = undefined;
        @memset(&fixture_output, 0xa5);
        _ = harness.call(r, harness.ids.read, &.{
            harness.archiveOrdinalParam(1),
            harness.sourceSpan(fixture_bytes),
            harness.sinkSpan(&fixture_output),
            harness.cryptoProfile(),
            harness.cryptoPasswordParam("foofoofoo"),
        }, .{ .ctx = true });
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length != fixture_expected.len or !std.mem.eql(u8, fixture_output[0..fixture_expected.len], fixture_expected)) {
            return error.EncryptedFixtureReadMismatch;
        }
    }
    var eocd: usize = zip_enc_archive_size - 22;
    while (eocd > 0 and !(zip_enc_archive[eocd] == 0x50 and zip_enc_archive[eocd + 1] == 0x4b and zip_enc_archive[eocd + 2] == 0x05 and zip_enc_archive[eocd + 3] == 0x06)) {
        eocd -= 1;
    }
    if (eocd == 0) return error.EocdSignatureMissing;
    const central_offset: usize = @intCast(@as(u32, zip_enc_archive[eocd + 16]) | (@as(u32, zip_enc_archive[eocd + 17]) << 8) | (@as(u32, zip_enc_archive[eocd + 18]) << 16) | (@as(u32, zip_enc_archive[eocd + 19]) << 24));
    if (central_offset + 46 > zip_enc_archive_size or zip_enc_archive[central_offset] != 0x50 or zip_enc_archive[central_offset + 1] != 0x4b or zip_enc_archive[central_offset + 2] != 0x01 or zip_enc_archive[central_offset + 3] != 0x02) {
        return error.CentralHeaderSignatureMissing;
    }
    zip_enc_archive[central_offset + 8] |= 0x20;
    const bit5_nodes = &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(zip_enc_archive[0..zip_enc_archive_size]),
        harness.sinkSpan(&output),
    };
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, bit5_nodes, .{ .ctx = true });
    zip_enc_archive[central_offset + 8] &= ~@as(u8, 0x20);
    try harness.requireStatus(r, abi.Status.unsupported);
    if (!harness.allBytesEqual(&output, 0xa5)) return error.Bit5ReadChangedOutput;
}

fn makeTraditionalZip(r: *Runner, method: u64) !void {
    var store1: EntryNodes = undefined;
    var store2: EntryNodes = undefined;
    const entry1 = entryWithMethod(&store1, "a.txt", &zip_small, method);
    const entry2 = entryWithMethod(&store2, "b.txt", &zip_big, method);
    var entries = [_]harness.Node{ entry1, entry2 };
    entries[0].next = &entries[1];
    const password = "s3cret";
    zip_trad_archive_size = try zipWriteWithCrypto(r, entries[0], &zip_trad_archive, password, 0, null, null);
}

fn runTraditional(r: *Runner) anyerror!void {
    setupZip(r);
    corpus.select(r.corpus_index, &zip_small);
    corpus.select(r.corpus_index, &zip_big);
    try makeTraditionalZip(r, 0);
    var output: [1024]u8 = undefined;
    _ = try zipReadWithPassword(r, zip_trad_archive[0..zip_trad_archive_size], 0, &output, "s3cret");
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != zip_small.len or !std.mem.eql(u8, output[0..zip_small.len], &zip_small)) {
        return error.TraditionalSpanReadMismatch;
    }
    _ = try zipReadWithPassword(r, zip_trad_archive[0..zip_trad_archive_size], 1, &output, "s3cret");
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != zip_big.len or !std.mem.eql(u8, output[0..zip_big.len], &zip_big)) {
        return error.TraditionalCallbackReadMismatch;
    }
    var diag: harness.CryptoDiag = undefined;
    harness.cryptoDiag(&diag);
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(zip_trad_archive[0..zip_trad_archive_size]),
        harness.sinkSpan(&output),
        harness.cryptoProfile(),
        harness.cryptoPasswordParam("wrong"),
    }, .{ .ctx = true, .diagnostic = &diag.diagnostic });
    try harness.requireStatus(r, abi.Status.invalid_data);
    if (diag.wrong_password.value_low != abi.Status.invalid_data) return error.TraditionalWrongPasswordDiagnosticMissing;
    try makeTraditionalZip(r, 8);
    _ = try zipReadWithPassword(r, zip_trad_archive[0..zip_trad_archive_size], 0, &output, "s3cret");
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != zip_small.len or !std.mem.eql(u8, output[0..zip_small.len], &zip_small)) {
        return error.TraditionalDeflateSpanMismatch;
    }
    _ = try zipReadWithPassword(r, zip_trad_archive[0..zip_trad_archive_size], 1, &output, "s3cret");
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != zip_big.len or !std.mem.eql(u8, output[0..zip_big.len], &zip_big)) {
        return error.TraditionalDeflateCallbackMismatch;
    }
}

var zip_methods_bz_saved: [8192]u8 = undefined;
var zip_methods_bz_saved_size: usize = 0;
var zip_methods_saved: [4][8192]u8 = undefined;
var zip_methods_saved_sizes: [4]usize = .{0} ** 4;

fn runMethods(r: *Runner) anyerror!void {
    setupZip(r);
    corpus.select(r.corpus_index, &zip_large);
    const crc = harness.crc32Ieee(&zip_large);
    var output: [1024]u8 = undefined;
    if (lib.bzip2Compress(&zip_large, &zip_methods_bz_saved)) |bz_size| {
        zip_methods_bz_saved_size = bz_size;
        var direct_output: [1024]u8 = undefined;
        _ = harness.call(r, harness.ids.read, &.{
            harness.paramProfile(harness.ids.bzip2),
            harness.sourceSpan(zip_methods_bz_saved[0..bz_size]),
            harness.sinkSpan(&direct_output),
            harness.capabilityParam(harness.cap_read | harness.cap_size | harness.cap_replay),
            harness.sizingModeParam(harness.size_measured),
            harness.commitModeParam(harness.commit_tentative),
        }, .{ .profile = false });
        const archive_size = zipWrapOne(&zip_methods_archive, "in.txt", 12, 0, zip_methods_bz_saved[0..bz_size], crc, @intCast(zip_large.len));
        try zipReadOrdinal0(r, zip_methods_archive[0..archive_size], &output, &zip_large);
    }
    var lzma_payload: [8192]u8 = undefined;
    _ = harness.call(r, harness.ids.write, &.{
        harness.paramProfile(harness.ids.lzma),
        harness.lzmaDictionaryParam(1 << 20),
        harness.sourceSpan(&zip_large),
        harness.sinkSpan(&lzma_payload),
        harness.capabilityParam(zip_caps),
        harness.sizingModeParam(harness.size_measured),
        harness.commitModeParam(harness.commit_tentative),
    }, .{ .profile = false });
    if (r.status == abi.Status.ok) {
        const stream_size: usize = @intCast(r.response.byte_length);
        if (stream_size != 0 and stream_size + 9 <= zip_methods_saved[0].len) {
            std.mem.writeInt(u16, zip_methods_saved[0][0..2], 0x0306, .little);
            std.mem.writeInt(u16, zip_methods_saved[0][2..4], 5, .little);
            zip_methods_saved[0][4] = 0x5d;
            std.mem.writeInt(u32, zip_methods_saved[0][5..9], 1 << 20, .little);
            @memcpy(zip_methods_saved[0][9 .. 9 + stream_size], lzma_payload[0..stream_size]);
            zip_methods_saved_sizes[0] = 9 + stream_size;
        }
    }
    if (zip_methods_saved_sizes[0] != 0) {
        const archive_size = zipWrapOne(&zip_methods_archive, "in.txt", 14, 0, zip_methods_saved[0][0..zip_methods_saved_sizes[0]], crc, @intCast(zip_large.len));
        try zipReadOrdinal0(r, zip_methods_archive[0..archive_size], &output, &zip_large);
    }
    var damaged: [2048]u8 = undefined;
    if (zip_methods_bz_saved_size >= 8) {
        const sizes = [_]usize{ zip_methods_bz_saved_size, zip_methods_saved_sizes[0] };
        const datas = [_][]const u8{ zip_methods_bz_saved[0..zip_methods_bz_saved_size], zip_methods_saved[0][0..zip_methods_saved_sizes[0]] };
        const methods = [_]u16{ 12, 14 };
        for (0..2) |t| {
            if (sizes[t] == 0) continue;
            @memcpy(damaged[0..sizes[t]], datas[t]);
            const damaged_size = sizes[t] - sizes[t] / 4;
            const bad_size = zipWrapOne(&zip_methods_archive, "bad.txt", methods[t], 0, damaged[0..damaged_size], crc, @intCast(zip_large.len));
            @memset(&output, 0xa5);
            _ = harness.call(r, harness.ids.read, &.{
                harness.archiveOrdinalParam(0),
                harness.sourceSpan(zip_methods_archive[0..bad_size]),
                harness.sinkSpan(&output),
            }, .{ .ctx = true });
            if (r.status == abi.Status.ok) return error.DamagedMethodAccepted;
        }
    }
    var xz_payload: [4096]u8 = undefined;
    _ = harness.call(r, harness.ids.write, &.{
        harness.paramProfile(harness.ids.xz),
        harness.lzmaDictionaryParam(1 << 20),
        harness.sourceSpan(&zip_large),
        harness.sinkSpan(&xz_payload),
        harness.capabilityParam(zip_caps),
        harness.sizingModeParam(harness.size_measured),
        harness.commitModeParam(harness.commit_confirmed),
    }, .{ .profile = false });
    try harness.requireStatus(r, abi.Status.ok);
    const xz_size: usize = @intCast(r.response.byte_length);
    if (xz_size == 0 or xz_size >= xz_payload.len) return error.XzEncodeFailed;
    const archive_size = zipWrapOne(&zip_methods_archive, "in.txt", 95, 0, xz_payload[0..xz_size], crc, @intCast(zip_large.len));
    try zipReadOrdinal0(r, zip_methods_archive[0..archive_size], &output, &zip_large);
    const bad_size = zipWrapOne(&zip_methods_archive, "bad.txt", 95, 0, xz_payload[0 .. xz_size - 4], crc, @intCast(zip_large.len));
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(zip_methods_archive[0..bad_size]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    if (r.status == abi.Status.ok) return error.XzTruncatedAccepted;
    @memcpy(damaged[0..xz_size], xz_payload[0..xz_size]);
    damaged[xz_size / 2] ^= 0x20;
    const bad2_size = zipWrapOne(&zip_methods_archive, "bad.txt", 95, 0, damaged[0..xz_size], crc, @intCast(zip_large.len));
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(zip_methods_archive[0..bad2_size]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    if (r.status == abi.Status.ok) return error.XzDamagedAccepted;
}

fn runEncodeMethods(r: *Runner) anyerror!void {
    setupZip(r);
    corpus.select(r.corpus_index, &zip_encmethods_payload);
    const methods = [_]u16{ 12, 14, 93, 95, 9, 98 };
    var archive: [65536]u8 = undefined;
    var output: [1024]u8 = undefined;
    for (methods) |method| {
        var store: EntryNodes = undefined;
        const entry = entryWithMethod(&store, "enc.txt", &zip_encmethods_payload, method);
        const size = try zipWriteWithCrypto(r, entry, &archive, "", null, null, null);
        try zipReadOrdinal0(r, archive[0..size], &output, &zip_encmethods_payload);
        if (method != 95) {
            const expected = [_]lib.ExpectedEntry{
                .{ .name = "enc.txt", .data = &zip_encmethods_payload },
            };
            const oracle = lib.archiveReadMatches(archive[0..size], &expected);
            if (oracle == .mismatch) return error.EncmethodsOracleRejected;
            if (oracle == .unsupported) std.debug.print("zip method {d} oracle: unsupported (libarchive cannot read).\n", .{method});
        }
    }
    const empty_methods = [_]u16{ 14, 98 };
    for (empty_methods) |method| {
        var store: EntryNodes = undefined;
        const entry = entryWithMethod(&store, "empty.txt", &.{}, method);
        const size = try zipWriteWithCrypto(r, entry, &archive, "", null, null, null);
        try zipReadOrdinal0(r, archive[0..size], &output, "");
    }
    const password = "zipcrypto-secret";
    var store: EntryNodes = undefined;
    const entry = entryWithMethod(&store, "crypto.txt", &zip_encmethods_payload, 14);
    const size = try zipWriteWithCrypto(r, entry, &archive, password, 0, null, null);
    @memset(&output, 0xa5);
    _ = try zipReadWithPassword(r, archive[0..size], 0, &output, password);
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != zip_encmethods_payload.len or !std.mem.eql(u8, output[0..zip_encmethods_payload.len], &zip_encmethods_payload)) {
        return error.EncmethodsCryptoReadMismatch;
    }
}

fn runRobust(r: *Runner) anyerror!void {
    setupZip(r);
    corpus.select(r.corpus_index, &zip_small);
    var store: EntryNodes = undefined;
    const entry = entryWithMethod(&store, "sfx.txt", &zip_small, 8);
    const size = try zipWriteWithCrypto(r, entry, &zip_enc_archive, "", null, null, null);
    const prefix = "#!/bin/sh\nexec unzip\n";
    var prefixed: [2048]u8 = undefined;
    @memcpy(prefixed[0..prefix.len], prefix);
    @memcpy(prefixed[prefix.len .. prefix.len + size], zip_enc_archive[0..size]);
    var output: [1024]u8 = undefined;
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(prefixed[0 .. prefix.len + size]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != zip_small.len or !std.mem.eql(u8, output[0..zip_small.len], &zip_small)) {
        return error.SfxReadMismatch;
    }
    const data = "crc mismatch probe";
    var store2: EntryNodes = undefined;
    const entry2 = entryWithMethod(&store2, "crc.txt", data, 8);
    const size2 = try zipWriteWithCrypto(r, entry2, &zip_enc_archive, "", null, null, null);
    var index: usize = 0;
    while (index + 4 <= size2) : (index += 1) {
        if (zip_enc_archive[index] == 0x50 and zip_enc_archive[index + 1] == 0x4b and zip_enc_archive[index + 2] == 0x01 and zip_enc_archive[index + 3] == 0x02) {
            if (index + 20 <= size2) zip_enc_archive[index + 16] ^= 0xff;
            break;
        }
    }
    @memset(&output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(zip_enc_archive[0..size2]),
        harness.sinkSpan(&output),
    }, .{ .ctx = true });
    if (r.status != abi.Status.ok and !harness.allBytesEqual(&output, 0xa5)) return error.CentralCrcChangedOutput;
    var store3: EntryNodes = undefined;
    const entry3 = entryWithMethod(&store3, "bad.txt", "unsupported method", 99);
    try harness.expect(r, harness.ids.write, &.{
        harness.scalarNode(harness.ids.source),
        harness.sinkSpan(&zip_enc_archive),
        harness.capabilityParam(zip_caps),
        harness.sizingModeParam(harness.size_metadata_exact),
        harness.commitModeParam(r.commit_write),
        entry3,
    }, .{}, abi.Status.unsupported);
    const foreign_data = "system unzip check";
    var store4: EntryNodes = undefined;
    const entry4 = entryWithMethod(&store4, "system.txt", foreign_data, 8);
    const size4 = try zipWriteWithCrypto(r, entry4, &zip_enc_archive, "", null, null, null);
    const expected = [_]lib.ExpectedEntry{
        .{ .name = "system.txt", .data = foreign_data },
    };
    const oracle = lib.archiveReadMatches(zip_enc_archive[0..size4], &expected);
    if (oracle == .mismatch) return error.ZipForeignRejected;
}

pub const scenarios = harness.scenarios("zip", &.{
    .{ .label = "zip encrypted", .run = runEncrypted, .workspace_size = 65536 + 4096, .output_size = 1024, .encoded_size = 65536 },
    .{ .label = "zip traditional", .run = runTraditional, .workspace_size = 65536 + 4096, .output_size = 1024, .encoded_size = 65536 },
    .{ .label = "zip methods", .run = runMethods, .workspace_size = 48 * 1024 * 1024, .output_size = 1024, .encoded_size = 65536 },
    .{ .label = "zip encode methods", .run = runEncodeMethods, .workspace_size = 48 * 1024 * 1024, .output_size = 1024, .encoded_size = 65536 },
    .{ .label = "zip robustness", .run = runRobust, .workspace_size = 32 * 1024 * 1024, .output_size = 1024, .encoded_size = 65536 },
}, &.{});
