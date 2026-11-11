const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const fixtures = @import("fixtures.zig");
const harness = @import("harness.zig");
const lib = @import("lib.zig");

const EntryNodes = harness.ArchiveEntryNodes;
const Runner = harness.Runner;
const entryWithMethod = harness.archiveEntryMethod;

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

// The entry's check value, not the CRC, catches a wrong password.
// Miss rates: 1/65536 WinZip AES, 1/256 ZipCrypto.
fn expectWrongPasswordRejected(r: *Runner, diag: *harness.CryptoDiag) !void {
    if (r.status == abi.Status.integrity_failure) {
        if (diag.wrong_password.value_low != 0) return error.WrongPasswordDiagnosticMismatch;
        return;
    }
    try harness.requireStatus(r, abi.Status.invalid_data);
    if (diag.wrong_password.value_low != abi.Status.invalid_data) return error.WrongPasswordDiagnosticMismatch;
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

// Archive-family ordinals 14 and 15 reach zip through the tar
// convention: tail parts and split granularity.
const archive_volumes: u32 = 14;
const archive_volume_size: u32 = 15;

// The split granularity doubles as the volume size: a full head
// volume, then a short tail with the directory.
const zip_span_volume: u64 = 4096;

var zip_span_a: [32]u8 = undefined;
var zip_span_b: [6144]u8 = undefined;
var zip_span_archive: [16384]u8 = undefined;

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
    var list = harness.NodeList{ .nodes = &nodes };
    list.push(harness.paramTargetCommand(harness.ids.write));
    list.push(harness.scalarNode(harness.ids.source));
    list.push(harness.capabilityParam(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay));
    list.push(harness.sizingModeParam(harness.size_metadata_exact));
    list.push(harness.commitModeParam(harness.commit_confirmed));
    list.pushAll(crypto[0..crypto_count]);
    list.push(entries);
    _ = harness.call(r, harness.ids.query, list.items(), .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length == 0 or r.response.byte_length > archive.len) return error.ZipQueryCapacity;
    const size: usize = @intCast(r.response.byte_length);
    list.count = 0;
    list.push(harness.scalarNode(harness.ids.source));
    list.push(harness.sinkSpan(archive[0..size]));
    list.push(harness.capabilityParam(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay));
    list.push(harness.sizingModeParam(harness.size_metadata_exact));
    list.push(harness.commitModeParam(harness.commit_confirmed));
    list.pushAll(crypto[0..crypto_count]);
    list.push(entries);
    _ = harness.call(r, harness.ids.write, list.items(), .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != size) return error.ZipWriteLengthMismatch;
    return size;
}

fn zipReadWithPassword(r: *Runner, archive: []const u8, ordinal: u64, output: []u8, password: []const u8) !usize {
    var crypto: [5]harness.Node = undefined;
    const crypto_count = cryptoNodes(password, null, null, null, &crypto);
    var nodes: [7]harness.Node = undefined;
    var list = harness.NodeList{ .nodes = &nodes };
    list.push(harness.archiveOrdinalParam(ordinal));
    list.push(harness.sourceSpan(archive));
    list.push(harness.sinkSpan(output));
    list.pushAll(crypto[0..crypto_count]);
    _ = harness.call(r, harness.ids.read, list.items(), .{ .ctx = true });
    return @intCast(r.response.byte_length);
}

fn zipReadWithPasswordProvider(r: *Runner, archive: []const u8, ordinal: u64, output: []u8, password: []const u8, provider: u64) !usize {
    var crypto: [5]harness.Node = undefined;
    const crypto_count = cryptoNodes(password, null, null, null, &crypto);
    var nodes: [8]harness.Node = undefined;
    var list = harness.NodeList{ .nodes = &nodes };
    list.push(harness.archiveOrdinalParam(ordinal));
    list.push(harness.sourceSpan(archive));
    list.push(harness.sinkSpan(output));
    list.pushAll(crypto[0..crypto_count]);
    list.push(harness.providerParam(provider));
    _ = harness.call(r, harness.ids.read, list.items(), .{ .ctx = true });
    return @intCast(r.response.byte_length);
}

fn runProviderSelection(r: *Runner) anyerror!void {
    if (!harness.offprem_servable) return;
    setupZip(r);
    corpus.fillTiled(r.corpus_index, &zip_small);
    corpus.fillTiled(r.corpus_index, &zip_large);
    var store1: EntryNodes = undefined;
    var store2: EntryNodes = undefined;
    const entry1 = entryWithMethod(&store1, "a.txt", &zip_small, 8);
    const entry2 = entryWithMethod(&store2, "b.txt", &zip_large, 0);
    var entries = [_]harness.Node{ entry1, entry2 };
    harness.linkNodes(entries[0..]);
    zip_enc_archive_size = try zipWriteWithCrypto(r, entries[0], &zip_enc_archive, "s3cret", null, null, null);
    // The archive carries a random salt, so providers compare plaintexts, not archives.
    var default_output: [zip_large.len]u8 = undefined;
    const default_len = try zipReadWithPassword(r, zip_enc_archive[0..zip_enc_archive_size], 1, &default_output, "s3cret");
    var provider_output: [zip_large.len]u8 = undefined;
    const provider_len = try zipReadWithPasswordProvider(r, zip_enc_archive[0..zip_enc_archive_size], 1, &provider_output, "s3cret", 1);
    if (provider_len != default_len) return error.ProviderReadLengthMismatch;
    if (!std.mem.eql(u8, provider_output[0..provider_len], default_output[0..default_len])) return error.ProviderReadContentMismatch;
    if (!std.mem.eql(u8, provider_output[0..zip_large.len], &zip_large)) return error.ProviderPlaintextMismatch;
}

fn runEncrypted(r: *Runner) anyerror!void {
    setupZip(r);
    corpus.fillTiled(r.corpus_index, &zip_small);
    corpus.fillTiled(r.corpus_index, &zip_large);
    var store1: EntryNodes = undefined;
    var store2: EntryNodes = undefined;
    const entry1 = entryWithMethod(&store1, "a.txt", &zip_small, 8);
    const entry2 = entryWithMethod(&store2, "b.txt", &zip_large, 0);
    var entries = [_]harness.Node{ entry1, entry2 };
    harness.linkNodes(entries[0..]);
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
    var source_ctx = harness.SourceCursor{ .data = zip_enc_archive[0..zip_enc_archive_size] };
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
    try expectWrongPasswordRejected(r, &diag);
    if (!harness.allBytesEqual(&output, 0xa5)) return error.WrongPasswordDiagnosticMismatch;
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
    // AES-128 write is a supported mode: the archive must carry strength 1
    // in the AE record and round-trip.
    var aes128_archive: [4096]u8 = undefined;
    const aes128_size = try zipWriteWithCrypto(r, entries[0], &aes128_archive, password, 1, null, null);
    const aes128_extra = aes128_archive[30 + 5 ..];
    const aes128_id: u16 = @as(u16, aes128_extra[0]) | (@as(u16, aes128_extra[1]) << 8);
    if (aes128_id != 0x9901 or aes128_extra[4] != 2 or aes128_extra[8] != 1) return error.Aes128ExtraMismatch;
    var aes128_out: [1024]u8 = undefined;
    _ = try zipReadWithPassword(r, aes128_archive[0..aes128_size], 0, &aes128_out, password);
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != zip_small.len or !std.mem.eql(u8, aes128_out[0..zip_small.len], &zip_small)) {
        return error.Aes128RoundtripMismatch;
    }
    // Strengths beyond 3 stay refused with the unsupported_algorithm cause.
    var diag4: harness.CryptoDiag = undefined;
    harness.cryptoDiag(&diag4);
    try expectCryptoRejection(r, &sink_buffer, password, harness.cryptoAlgorithmParam(4), entries[0], abi.Status.unsupported, &diag4, &diag4.unsupported_algorithm);
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
    if (oracle == .unsupported) harness.unverified(r, "libarchive cannot read AES zip.");
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
    harness.linkNodes(entries[0..]);
    const password = "s3cret";
    zip_trad_archive_size = try zipWriteWithCrypto(r, entries[0], &zip_trad_archive, password, 0, null, null);
}

fn runTraditional(r: *Runner) anyerror!void {
    setupZip(r);
    corpus.fillTiled(r.corpus_index, &zip_small);
    corpus.fillTiled(r.corpus_index, &zip_big);
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
    try expectWrongPasswordRejected(r, &diag);
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
var zip_methods_saved_sizes: [4]usize = @splat(0);

fn runMethods(r: *Runner) anyerror!void {
    setupZip(r);
    corpus.fillTiled(r.corpus_index, &zip_large);
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
        // The compose write emits a marker-terminated stream; the wrap sets
        // the method-14 end-marker flag so the entry matches its payload.
        const archive_size = zipWrapOne(&zip_methods_archive, "in.txt", 14, 0x0002, zip_methods_saved[0][0..zip_methods_saved_sizes[0]], crc, @intCast(zip_large.len));
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
    corpus.fillTiled(r.corpus_index, &zip_encmethods_payload);
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
            if (oracle == .unsupported) harness.unverifiedPrint(r, "libarchive cannot read method {d}.", .{method});
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
    corpus.fillTiled(r.corpus_index, &zip_small);
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

// The data-descriptor (streaming) shape: bit 3 in both headers, zeroed
// local sizes, a trailing signature plus CRC and sizes.
fn runDataDescriptor(r: *Runner) anyerror!void {
    setupZip(r);
    corpus.fillTiled(r.corpus_index, &zip_large);
    var store: EntryNodes = undefined;
    const entry = entryWithMethod(&store, "dd.txt", &zip_large, 8);
    var dd_node: harness.Node = harness.zipDataDescriptorParam(1);
    store.method.next = &dd_node;
    var archive: [4096]u8 = undefined;
    const size = try zipWriteWithCrypto(r, entry, &archive, "", null, null, null);
    var output: [zip_large.len]u8 = undefined;
    try zipReadOrdinal0(r, archive[0..size], &output, &zip_large);
    if (archive[6] & 0x08 == 0) return error.DescriptorLocalFlagMissing;
    for (archive[14..26]) |byte| {
        if (byte != 0) return error.DescriptorLocalSizesNotZeroed;
    }
    var found = false;
    var scan: usize = 30 + "dd.txt".len;
    while (scan + 16 <= size) : (scan += 1) {
        if (std.mem.eql(u8, archive[scan..][0..4], &[4]u8{ 0x50, 0x4b, 0x07, 0x08 })) {
            const crc = std.mem.readInt(u32, archive[scan + 4 ..][0..4], .little);
            if (crc == harness.crc32Ieee(&zip_large)) found = true;
            break;
        }
    }
    if (!found) return error.DescriptorRecordMissing;
    const expected = [_]lib.ExpectedEntry{.{ .name = "dd.txt", .data = &zip_large }};
    const oracle = lib.archiveReadMatches(archive[0..size], &expected);
    if (oracle != .ok) return error.DescriptorOracleRejected;
}

fn zipSpannedRead(r: *Runner, head: []const u8, volume_nodes: []const harness.Node, ordinal: u64, expected: []const u8) !void {
    var read_req: [8]harness.Node = @splat(abi.Node.init());
    var count: usize = 0;
    read_req[count] = harness.archiveOrdinalParam(ordinal);
    count += 1;
    read_req[count] = harness.sourceSpan(head);
    count += 1;
    for (volume_nodes) |volume_node| {
        read_req[count] = volume_node;
        count += 1;
    }
    read_req[count] = harness.sinkSpan(r.output);
    count += 1;
    _ = harness.call(r, harness.ids.read, read_req[0..count], .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != expected.len or !std.mem.eql(u8, r.output[0..expected.len], expected)) {
        return error.SpannedReadMismatch;
    }
}

fn zipSpannedForeignFile(r: *Runner, out_path: []const u8, name: []const u8, expected: []const u8) !void {
    const oracle_io = harness.oracle_io;
    const got_path = try r.gpa.print("{s}/{s}", .{ out_path, name });
    defer r.gpa.free(got_path);
    const got = try std.Io.Dir.cwd().readFileAlloc(oracle_io, got_path, r.gpa, .limited(1 << 20));
    defer r.gpa.free(got);
    if (!std.mem.eql(u8, got, expected)) return error.SpannedForeignExtractMismatch;
}

// A spanned set under the full ABI: the sizing answers the set total;
// the response children carry the tail volumes.

// The byte fields pin the directory to its volume; the read joins
// the parts and 7-Zip extracts them.
fn runZipSpannedSet(r: *Runner) anyerror!void {
    setupZip(r);
    corpus.fillTiled(r.corpus_index, &zip_span_a);
    corpus.fillTiled(r.corpus_index, &zip_span_b);
    var store1: EntryNodes = undefined;
    var store2: EntryNodes = undefined;
    const entry1 = entryWithMethod(&store1, "span-a.txt", &zip_span_a, 0);
    const entry2 = entryWithMethod(&store2, "span-b.txt", &zip_span_b, 0);
    var entries = [_]harness.Node{ entry1, entry2 };
    harness.linkNodes(entries[0..]);

    // The granularity rides the write sizing query as well as the write, so
    // the mask spans both directions.
    const gran = harness.paramScalar(harness.param_family_archive, archive_volume_size, harness.cmds, zip_span_volume);
    _ = harness.call(r, harness.ids.query, &.{
        harness.paramTargetCommand(harness.ids.write),
        harness.scalarNode(harness.ids.source),
        harness.capabilityParam(zip_caps),
        harness.sizingModeParam(harness.size_metadata_exact),
        harness.commitModeParam(harness.commit_confirmed),
        gran,
        entries[0],
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    const total: usize = @intCast(r.response.byte_length);
    if (total <= zip_span_volume or total > zip_span_archive.len) return error.SpannedQueryShape;
    r.required = total;

    // A granularity under the writer's floor answers invalid_call; the set
    // never gets emitted.
    const under_floor = harness.paramScalar(harness.param_family_archive, archive_volume_size, harness.cmds, zip_span_volume / 4);
    try harness.expect(r, harness.ids.query, &.{
        harness.paramTargetCommand(harness.ids.write),
        harness.scalarNode(harness.ids.source),
        harness.capabilityParam(zip_caps),
        harness.sizingModeParam(harness.size_metadata_exact),
        harness.commitModeParam(harness.commit_confirmed),
        under_floor,
        entries[0],
    }, .{}, abi.Status.invalid_call);

    // The write leaves the set contiguous in the sink; the response children
    // carry the tail volumes as bytes.
    var tail_buffers: [4][4096]u8 = undefined;
    var tail_nodes: [4]harness.Node = undefined;
    for (&tail_nodes, &tail_buffers) |*t, *buf| {
        t.* = harness.node(buf, buf.len);
        t.*.id = harness.ids.parameter;
        // Repeated out-bytes selector: the response carries one node per
        // tail volume under the same ordinal.
        t.*.value_high = harness.paramSelector(harness.param_family_archive, archive_volumes, 0x26, 0);
    }
    harness.linkNodes(&tail_nodes);
    var response = abi.Node.init();
    response.child = &tail_nodes[0];

    var req: [8]harness.Node = undefined;
    req[0] = harness.paramProfile(harness.ids.zip);
    req[1] = harness.scalarNode(harness.ids.source);
    req[2] = harness.sinkSpan(zip_span_archive[0..total]);
    req[3] = harness.capabilityParam(zip_caps);
    req[4] = harness.sizingModeParam(harness.size_metadata_exact);
    req[5] = harness.commitModeParam(r.commit_write);
    req[6] = gran;
    req[7] = entries[0];
    harness.linkNodes(&req);
    const status = harness.invoke(harness.ids.write, &req[0], &response, r.workspace.ptr, r.workspace.len, null, null, null);
    if (status != abi.Status.ok) return error.SpannedWriteFailed;
    if (response.byte_length != total) return error.SpannedWriteLengthMismatch;

    var parts: [5][]const u8 = undefined;
    var tails: usize = 0;
    var tail_bytes: usize = 0;
    for (tail_nodes) |t| {
        if (t.byte_length == 0) break;
        parts[1 + tails] = t.bytes.?[0..@intCast(t.byte_length)];
        tail_bytes += @intCast(t.byte_length);
        tails += 1;
    }
    if (tails == 0 or total <= tail_bytes) return error.SpannedShapeMismatch;
    parts[0] = zip_span_archive[0 .. total - tail_bytes];
    // The physical model: every volume but the last holds exactly the
    // requested granularity.
    if (parts[0].len != zip_span_volume) return error.SpannedHeadVolumeMismatch;

    // The fields share one coordinate system: the spanning marker opens
    // the set and the EOCD sits on the last volume.

    // The directory's (disk, relative) pair lands on the first central
    // record in the joined stream.
    const set = zip_span_archive[0..total];
    if (std.mem.readInt(u32, set[0..4], .little) != 0x0807_4b50) return error.SpanningSignatureMismatch;
    const eocd = total - 22;
    if (std.mem.readInt(u32, set[eocd..][0..4], .little) != 0x0605_4b50) return error.EocdSignatureMismatch;
    if (std.mem.readInt(u16, set[eocd + 4 ..][0..2], .little) != tails) return error.EocdDiskMismatch;
    const cd_disk: usize = std.mem.readInt(u16, set[eocd + 6 ..][0..2], .little);
    if (cd_disk != 1) return error.CentralDiskMismatch;
    const cd_relative: usize = std.mem.readInt(u32, set[eocd + 16 ..][0..4], .little);
    const cd_absolute = cd_disk * @as(usize, @intCast(zip_span_volume)) + cd_relative;
    if (cd_absolute + 4 > eocd) return error.CentralPositionMismatch;
    if (std.mem.readInt(u32, set[cd_absolute..][0..4], .little) != 0x0201_4b50) return error.CentralPositionMismatch;

    // The read rides the tail parts back in volume order, decoding both
    // entries as a single archive would.
    var volume_nodes: [4]harness.Node = undefined;
    for (0..tails) |index| {
        // Repeated in-bytes selector: one parameter per tail volume.
        volume_nodes[index] = harness.paramBytesWithAttributes(harness.param_family_archive, archive_volumes, 0x16, harness.cmd_read, parts[1 + index]);
    }
    try zipSpannedRead(r, parts[0], volume_nodes[0..tails], 0, &zip_span_a);
    try zipSpannedRead(r, parts[0], volume_nodes[0..tails], 1, &zip_span_b);

    // 7-Zip extracts the set like a foreign reader: parts land under
    // split naming; the walk starts at the last volume.
    const bin = "zig-out/benchmark/bin/7zz";
    const oracle_io = harness.oracle_io;
    std.Io.Dir.cwd().access(oracle_io, bin, .{}) catch return error.ReferenceToolUnavailable;
    std.Io.Dir.cwd().createDirPath(oracle_io, "zig-out/oracles") catch {};
    const stem = try r.gpa.print("zig-out/oracles/zip-span-{d}", .{r.corpus_index});
    defer r.gpa.free(stem);
    const out_path = try r.gpa.print("zig-out/oracles/zip-span-out-{d}", .{r.corpus_index});
    defer r.gpa.free(out_path);
    _ = std.Io.Dir.cwd().deleteTree(oracle_io, out_path) catch {};
    try std.Io.Dir.cwd().createDirPath(oracle_io, out_path);
    var part_paths: [5][]const u8 = @splat("");
    defer {
        for (part_paths) |path| {
            if (path.len != 0) r.gpa.free(path);
        }
    }
    for (0..tails) |index| {
        const part_path = try r.gpa.print("{s}.z{d:0>2}", .{ stem, index + 1 });
        part_paths[index] = part_path;
        try std.Io.Dir.cwd().writeFile(oracle_io, .{ .sub_path = part_path, .data = parts[index] });
    }
    const last_path = try r.gpa.print("{s}.zip", .{stem});
    part_paths[tails] = last_path;
    try std.Io.Dir.cwd().writeFile(oracle_io, .{ .sub_path = last_path, .data = parts[tails] });
    const out_arg = try r.gpa.print("-o{s}", .{out_path});
    defer r.gpa.free(out_arg);
    var child = try std.process.spawn(oracle_io, .{ .argv = &.{ bin, "x", "-y", out_arg, last_path } });
    const term = try child.wait(oracle_io);
    if (term != .exited or term.exited != 0) return error.ReferenceToolExtractFailed;
    try zipSpannedForeignFile(r, out_path, "span-a.txt", &zip_span_a);
    try zipSpannedForeignFile(r, out_path, "span-b.txt", &zip_span_b);
    _ = std.Io.Dir.cwd().deleteTree(oracle_io, out_path) catch {};
    for (part_paths) |path| {
        if (path.len != 0) _ = std.Io.Dir.cwd().deleteFile(oracle_io, path) catch {};
    }
}

// Only output_size repeats across every row; workspace and encoded stay per row.
const zip_base: harness.Spec = .{ .label = "", .run = undefined, .workspace_size = undefined, .output_size = 1024, .encoded_size = undefined };

pub const scenarios = harness.scenarios("zip", harness.specRows(zip_base, &.{
    .{ .label = "zip encrypted", .run = runEncrypted, .workspace_size = 65536 + 4096, .encoded_size = 65536 },
    .{ .label = "zip data descriptor", .run = runDataDescriptor, .workspace_size = 65536 + 4096, .encoded_size = 4096 },
    .{ .label = "zip encrypted provider", .run = runProviderSelection, .workspace_size = 65536 + 4096, .encoded_size = 65536 },
    .{ .label = "zip traditional", .run = runTraditional, .workspace_size = 65536 + 4096, .encoded_size = 65536 },
    .{ .label = "zip methods", .run = runMethods, .workspace_size = 48 * 1024 * 1024, .encoded_size = 65536 },
    .{ .label = "zip encode methods", .run = runEncodeMethods, .workspace_size = 48 * 1024 * 1024, .encoded_size = 65536 },
    .{ .label = "zip robustness", .run = runRobust, .workspace_size = 32 * 1024 * 1024, .encoded_size = 65536 },
    .{ .label = "zip spanned set", .run = runZipSpannedSet, .workspace_size = 72 * 1024, .output_size = 8192, .encoded_size = 16384 },
}), &.{});
