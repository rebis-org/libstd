const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const fixtures = @import("fixtures.zig");
const harness = @import("harness.zig");
const Runner = harness.Runner;
const lib = @import("lib.zig");

fn setup7z(r: *Runner, profile_id: harness.Id) void {
    harness.setup(r, profile_id, harness.mode_archive);
}

const EntryNodes = struct {
    name: harness.Node,
    data: harness.Node,
    method: harness.Node,
    type: harness.Node,
};

const PlainNodes = struct {
    name: harness.Node,
    data: harness.Node,
};

fn entryPlain(nodes: *PlainNodes, name: []const u8, data: []const u8) harness.Node {
    return harness.archiveEntryNode(&nodes.name, &nodes.data, name, data);
}

fn entryWithMethod(nodes: *EntryNodes, name: []const u8, data: []const u8, method: u64) harness.Node {
    return harness.archiveEntryWithMethod(&nodes.name, &nodes.data, &nodes.method, name, data, method);
}

fn dirEntry(nodes: *EntryNodes, name: []const u8) harness.Node {
    const entry = harness.archiveEntryNode(&nodes.name, &nodes.data, name, &.{});
    nodes.data.next = &nodes.type;
    nodes.type = harness.tflag('5');
    return entry;
}

var sz_adv_payload: [445]u8 = undefined;
var sz_small: [32]u8 = undefined;
var sz_solid_data: [600]u8 = undefined;
var sz_enc_data: [97]u8 = undefined;
var sz_adv_archive: [65536]u8 = undefined;
var sz_adv_output: [1024]u8 = undefined;
var sz_adv_archive_size: usize = 0;
var sz_enc_archive: [4096]u8 = undefined;
var sz_enc_output: [512]u8 = undefined;
var sz_enc_archive_size: usize = 0;
var sz_dec_archive: [4096]u8 = undefined;
var sz_dec_output: [512]u8 = undefined;
var sz_dec_archive_size: usize = 0;
var sz_dec_data1_buf: [16]u8 = undefined;
var sz_dec_data2_buf: [16]u8 = undefined;
var sz_dec_data3_buf: [16]u8 = undefined;
var sz_coded_data2_buf: [100]u8 = undefined;
var sz_coded_data3_buf: [16]u8 = undefined;
var sz_coded_archive: [16384]u8 = undefined;
var sz_coded_output: [512]u8 = undefined;
var sz_coded_archive_size: usize = 0;

fn sevenZipWrite(r: *Runner, entries: harness.Node, archive: []u8, crypto_nodes: []const harness.Node) !usize {
    var nodes: [12]harness.Node = undefined;
    var count: usize = 0;
    nodes[count] = harness.paramTargetCommand(harness.ids.write);
    count += 1;
    nodes[count] = harness.scalarNode(harness.ids.source);
    count += 1;
    nodes[count] = harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay);
    count += 1;
    nodes[count] = harness.pln(harness.plan_metadata_exact);
    count += 1;
    nodes[count] = harness.dlv(harness.delivery_verified);
    count += 1;
    @memcpy(nodes[count..][0..crypto_nodes.len], crypto_nodes);
    count += crypto_nodes.len;
    nodes[count] = entries;
    count += 1;
    _ = harness.call(r, harness.ids.query, nodes[0..count], .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length == 0 or r.response.byte_length > archive.len) return error.SevenZipQueryCapacity;
    const size: usize = @intCast(r.response.byte_length);
    count = 0;
    nodes[count] = harness.scalarNode(harness.ids.source);
    count += 1;
    nodes[count] = harness.sinkSpan(archive[0..size]);
    count += 1;
    nodes[count] = harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay);
    count += 1;
    nodes[count] = harness.pln(harness.plan_metadata_exact);
    count += 1;
    nodes[count] = harness.dlv(harness.delivery_verified);
    count += 1;
    @memcpy(nodes[count..][0..crypto_nodes.len], crypto_nodes);
    count += crypto_nodes.len;
    nodes[count] = entries;
    count += 1;
    _ = harness.call(r, harness.ids.write, nodes[0..count], .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != size) return error.SevenZipWriteLengthMismatch;
    return size;
}

fn sevenZipRead(r: *Runner, archive: []const u8, ordinal: u64, output: []u8, crypto_nodes: []const harness.Node) !usize {
    var nodes: [7]harness.Node = undefined;
    var count: usize = 0;
    nodes[count] = harness.ord(ordinal);
    count += 1;
    nodes[count] = harness.sourceSpan(archive);
    count += 1;
    nodes[count] = harness.sinkSpan(output);
    count += 1;
    @memcpy(nodes[count..][0..crypto_nodes.len], crypto_nodes);
    count += crypto_nodes.len;
    _ = harness.call(r, harness.ids.read, nodes[0..count], .{ .ctx = true });
    return @intCast(r.response.byte_length);
}

fn runDecoded(r: *Runner) anyerror!void {
    setup7z(r, harness.ids.seven_zip_decoded);
    corpus.select(r.corpus_index, &sz_dec_data1_buf);
    corpus.select(r.corpus_index, &sz_dec_data2_buf);
    corpus.select(r.corpus_index, &sz_dec_data3_buf);
    var store1: EntryNodes = undefined;
    var store2: EntryNodes = undefined;
    var store3: EntryNodes = undefined;
    var store_dir: EntryNodes = undefined;
    const entry1 = entryWithMethod(&store1, "m1.txt", &sz_dec_data1_buf, 0);
    const entry2 = entryWithMethod(&store2, "m2.txt", &sz_dec_data2_buf, 0);
    const entry3 = entryWithMethod(&store3, "unicode/\xe4\xbd\xa0\xe5\xa5\xbd.txt", &sz_dec_data3_buf, 0);
    const entry_dir = dirEntry(&store_dir, "dir/");
    var entries = [_]harness.Node{ entry1, entry2, entry3, entry_dir };
    entries[0].next = &entries[1];
    entries[1].next = &entries[2];
    entries[2].next = &entries[3];
    sz_dec_archive_size = try sevenZipWrite(r, entries[0], &sz_dec_archive, &.{});
    _ = harness.call(r, harness.ids.query, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(sz_dec_archive[0..sz_dec_archive_size]),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_provisional),
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 4) return error.DecodedEntryCountMismatch;
    const expected_data = [_][]const u8{ &sz_dec_data1_buf, &sz_dec_data2_buf, &sz_dec_data3_buf };
    for (0..3) |i| {
        @memset(&sz_dec_output, 0xa5);
        _ = try sevenZipRead(r, sz_dec_archive[0..sz_dec_archive_size], i, &sz_dec_output, &.{});
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length != expected_data[i].len or !std.mem.eql(u8, sz_dec_output[0..expected_data[i].len], expected_data[i])) {
            return error.DecodedOrdinalMismatch;
        }
    }
    var downstream = harness.scalarNode(harness.ids.diagnostic_downstream_status);
    var diagnostic = harness.node(null, 0);
    diagnostic.child = &downstream;
    var fail_ctx = harness.SinkCallbackContext{ .fail_after = 5 };
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(sz_dec_archive[0..sz_dec_archive_size]),
        harness.sinkCallbackNode(0, 0),
    }, .{ .ctx = true, .callback = harness.sinkCallback, .context = &fail_ctx, .diagnostic = &diagnostic });
    try harness.requireStatus(r, abi.Status.io_failure);
    if (fail_ctx.accepted_total != 4 or downstream.value_low != abi.Status.insufficient_capacity) {
        return error.DecodedDownstreamDiagnosticMismatch;
    }
    sz_dec_archive[0] ^= 0xff;
    const corrupted_nodes = &.{
        harness.sourceSpan(sz_dec_archive[0..sz_dec_archive_size]),
        harness.sinkSpan(&sz_dec_output),
    };
    @memset(&sz_dec_output, 0xa5);
    _ = harness.call(r, harness.ids.read, corrupted_nodes, .{ .ctx = true });
    sz_dec_archive[0] ^= 0xff;
    if (r.status == abi.Status.ok or !harness.allBytesEqual(&sz_dec_output, 0xa5)) return error.DecodedCorruptionAccepted;
    @memset(&sz_dec_output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.sourceSpan(sz_dec_archive[0 .. sz_dec_archive_size - 1]),
        harness.sinkSpan(&sz_dec_output),
    }, .{ .ctx = true });
    if (r.status == abi.Status.ok or !harness.allBytesEqual(&sz_dec_output, 0xa5)) return error.DecodedTruncationAccepted;
    const expected = [_]lib.ExpectedEntry{
        .{ .name = "m1.txt", .data = &sz_dec_data1_buf },
        .{ .name = "m2.txt", .data = &sz_dec_data2_buf },
        .{ .name = "unicode/\xe4\xbd\xa0\xe5\xa5\xbd.txt", .data = &sz_dec_data3_buf },
        .{ .name = "dir/", .filetype = 0o040000 },
    };
    const oracle = lib.archiveReadMatches(sz_dec_archive[0..sz_dec_archive_size], &expected);
    if (oracle == .mismatch) return error.DecodedOracleRejected;
    if (oracle == .unsupported) std.debug.print("seven_zip decoded oracle: unsupported (libarchive cannot read)\n", .{});
}

fn runCoded(r: *Runner) anyerror!void {
    setup7z(r, harness.ids.seven_zip_coded);
    corpus.select(r.corpus_index, &sz_coded_data2_buf);
    corpus.select(r.corpus_index, &sz_coded_data3_buf);
    corpus.select(r.corpus_index, &sz_small);
    const methods = [_]u64{ 0, 1, 2, 3, 4 };
    for (methods) |method| {
        var store1: EntryNodes = undefined;
        var store2: EntryNodes = undefined;
        var store3: EntryNodes = undefined;
        var store_dir: EntryNodes = undefined;
        const entry1 = entryWithMethod(&store1, "m1.txt", &sz_small, method);
        const entry2 = entryWithMethod(&store2, "m2.txt", &sz_coded_data2_buf, method);
        const entry3 = entryWithMethod(&store3, "unicode/\xe4\xbd\xa0\xe5\xa5\xbd.txt", &sz_coded_data3_buf, method);
        const entry_dir = dirEntry(&store_dir, "dir/");
        var entries = [_]harness.Node{ entry1, entry2, entry3, entry_dir };
        entries[0].next = &entries[1];
        entries[1].next = &entries[2];
        entries[2].next = &entries[3];
        sz_coded_archive_size = try sevenZipWrite(r, entries[0], &sz_coded_archive, &.{});
        _ = harness.call(r, harness.ids.query, &.{
            harness.paramTargetCommand(harness.ids.read),
            harness.sourceSpan(sz_coded_archive[0..sz_coded_archive_size]),
            harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay),
            harness.pln(harness.plan_metadata_exact),
            harness.dlv(harness.delivery_provisional),
        }, .{});
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length != 4) return error.CodedEntryCountMismatch;
        const datas = [_][]const u8{ &sz_small, &sz_coded_data2_buf, &sz_coded_data3_buf };
        for (0..3) |i| {
            @memset(&sz_coded_output, 0xa5);
            _ = try sevenZipRead(r, sz_coded_archive[0..sz_coded_archive_size], i, &sz_coded_output, &.{});
            try harness.requireStatus(r, abi.Status.ok);
            if (r.response.byte_length != datas[i].len or !std.mem.eql(u8, sz_coded_output[0..datas[i].len], datas[i])) {
                return error.CodedOrdinalMismatch;
            }
        }
        const expected = [_]lib.ExpectedEntry{
            .{ .name = "m1.txt", .data = &sz_small },
            .{ .name = "m2.txt", .data = &sz_coded_data2_buf },
            .{ .name = "unicode/\xe4\xbd\xa0\xe5\xa5\xbd.txt", .data = &sz_coded_data3_buf },
            .{ .name = "dir/", .filetype = 0o040000 },
        };
        const oracle = lib.archiveReadMatches(sz_coded_archive[0..sz_coded_archive_size], &expected);
        if (oracle == .mismatch) return error.CodedOracleRejected;
        if (oracle == .unsupported) std.debug.print("seven_zip coded oracle method {d}: unsupported (libarchive cannot read)\n", .{method});
    }
    var store1: EntryNodes = undefined;
    var store2: EntryNodes = undefined;
    var store3: EntryNodes = undefined;
    var store_dir: EntryNodes = undefined;
    const entry1 = entryWithMethod(&store1, "copy.txt", &sz_small, 0);
    const entry2 = entryWithMethod(&store2, "deflate.txt", &sz_coded_data2_buf, 1);
    const entry3 = entryWithMethod(&store3, "bzip2.txt", &sz_coded_data3_buf, 2);
    const entry_dir = dirEntry(&store_dir, "dir/");
    var mixed = [_]harness.Node{ entry1, entry2, entry3, entry_dir };
    mixed[0].next = &mixed[1];
    mixed[1].next = &mixed[2];
    mixed[2].next = &mixed[3];
    sz_coded_archive_size = try sevenZipWrite(r, mixed[0], &sz_coded_archive, &.{});
    const datas = [_][]const u8{ &sz_small, &sz_coded_data2_buf, &sz_coded_data3_buf };
    for (0..3) |i| {
        @memset(&sz_coded_output, 0xa5);
        _ = try sevenZipRead(r, sz_coded_archive[0..sz_coded_archive_size], i, &sz_coded_output, &.{});
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length != datas[i].len or !std.mem.eql(u8, sz_coded_output[0..datas[i].len], datas[i])) {
            return error.CodedMixedOrdinalMismatch;
        }
    }
    if (lib.archiveWrite(.seven_zip, &.{
        .{ .name = "m1.txt", .data = &sz_small },
        .{ .name = "m2.txt", .data = &sz_coded_data2_buf },
    })) |external_bytes| {
        const external_expected = [_]lib.ExpectedEntry{
            .{ .name = "m1.txt", .data = &sz_small },
            .{ .name = "m2.txt", .data = &sz_coded_data2_buf },
        };
        const external_oracle = lib.archiveReadMatches(external_bytes, &external_expected);
        if (external_oracle == .mismatch) return error.CodedExternalReferenceRoundtripMismatch;
        if (external_oracle == .unsupported) std.debug.print("seven_zip coded external reference: skipped (libarchive cannot read its own 7z output)\n", .{});
        _ = harness.call(r, harness.ids.query, &.{
            harness.paramTargetCommand(harness.ids.read),
            harness.sourceSpan(external_bytes),
            harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay),
            harness.pln(harness.plan_metadata_exact),
            harness.dlv(harness.delivery_provisional),
        }, .{});
        if (r.status == abi.Status.unsupported) {
            std.debug.print("seven_zip coded external: unsupported (libarchive 7z encoding unsupported by decoder)\n", .{});
        } else {
            try harness.requireStatus(r, abi.Status.ok);
            if (r.response.byte_length != 2) return error.CodedExternalCountMismatch;
            const ext_datas = [_][]const u8{ &sz_small, &sz_coded_data2_buf };
            for (0..2) |i| {
                @memset(&sz_coded_output, 0xa5);
                _ = try sevenZipRead(r, external_bytes, i, &sz_coded_output, &.{});
                if (r.status == abi.Status.unsupported) {
                    std.debug.print("seven_zip coded external: unsupported (libarchive 7z encoding unsupported by decoder)\n", .{});
                    break;
                }
                try harness.requireStatus(r, abi.Status.ok);
                if (r.response.byte_length != ext_datas[i].len or !std.mem.eql(u8, sz_coded_output[0..ext_datas[i].len], ext_datas[i])) {
                    return error.CodedExternalOrdinalMismatch;
                }
            }
        }
        std.heap.page_allocator.free(external_bytes);
    } else {
        std.debug.print("seven_zip coded external: unsupported (libarchive cannot write 7z)\n", .{});
    }
}

fn runEncodeAdvanced(r: *Runner) anyerror!void {
    setup7z(r, harness.ids.seven_zip_coded);
    corpus.select(r.corpus_index, &sz_adv_payload);
    corpus.select(r.corpus_index, &sz_small);
    corpus.select(r.corpus_index, &sz_solid_data);
    const methods = [_]u64{ 5, 6, 14 };
    for (methods) |method| {
        var store: EntryNodes = undefined;
        const entry = entryWithMethod(&store, "adv.txt", &sz_adv_payload, method);
        sz_adv_archive_size = try sevenZipWrite(r, entry, &sz_adv_archive, &.{});
        @memset(&sz_adv_output, 0xa5);
        _ = try sevenZipRead(r, sz_adv_archive[0..sz_adv_archive_size], 0, &sz_adv_output, &.{});
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length != sz_adv_payload.len or !std.mem.eql(u8, sz_adv_output[0..sz_adv_payload.len], &sz_adv_payload)) {
            return error.AdvMethodsReadMismatch;
        }
        const expected = [_]lib.ExpectedEntry{
            .{ .name = "adv.txt", .data = &sz_adv_payload },
        };
        const oracle = lib.archiveReadMatches(sz_adv_archive[0..sz_adv_archive_size], &expected);
        if (oracle == .mismatch) return error.AdvMethodsOracleRejected;
        if (oracle == .unsupported) std.debug.print("seven_zip encode advanced oracle method {d}: unsupported (libarchive cannot read)\n", .{method});
    }
    const solids = [_][]const u8{ sz_solid_data[0..160], sz_solid_data[160..320], sz_solid_data[320..480] };
    var solid_stores: [3]EntryNodes = undefined;
    var solid_entries: [3]harness.Node = undefined;
    var name_buffers: [3][16]u8 = undefined;
    for (0..3) |i| {
        const name = std.fmt.bufPrint(&name_buffers[i], "s{d}.txt", .{i}) catch return error.NameFormat;
        solid_entries[i] = entryWithMethod(&solid_stores[i], name, solids[i], 4);
        if (i > 0) solid_entries[i - 1].next = &solid_entries[i];
    }
    sz_adv_archive_size = try sevenZipWrite(r, solid_entries[0], &sz_adv_archive, &.{});
    for (0..3) |i| {
        @memset(&sz_adv_output, 0xa5);
        _ = try sevenZipRead(r, sz_adv_archive[0..sz_adv_archive_size], i, &sz_adv_output, &.{});
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length != solids[i].len or !std.mem.eql(u8, sz_adv_output[0..solids[i].len], solids[i])) {
            return error.AdvSolidReadMismatch;
        }
    }
    var store_full: EntryNodes = undefined;
    var store_empty: EntryNodes = undefined;
    const entry_full = entryWithMethod(&store_full, "full.txt", &sz_small, 4);
    const entry_empty = entryWithMethod(&store_empty, "empty.txt", &.{}, 4);
    var entries = [_]harness.Node{ entry_full, entry_empty };
    entries[0].next = &entries[1];
    sz_adv_archive_size = try sevenZipWrite(r, entries[0], &sz_adv_archive, &.{});
    @memset(&sz_adv_output, 0xa5);
    _ = try sevenZipRead(r, sz_adv_archive[0..sz_adv_archive_size], 0, &sz_adv_output, &.{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != sz_small.len or !std.mem.eql(u8, sz_adv_output[0..sz_small.len], &sz_small)) {
        return error.AdvSolidEmptyFullMismatch;
    }
    @memset(&sz_adv_output, 0xa5);
    _ = try sevenZipRead(r, sz_adv_archive[0..sz_adv_archive_size], 1, &sz_adv_output, &.{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 0) return error.AdvSolidEmptyEmptyMismatch;
}

const sz_enc_password = "secret";

fn runEncrypted(r: *Runner) anyerror!void {
    setup7z(r, harness.ids.seven_zip_coded);
    corpus.select(r.corpus_index, &sz_enc_data);
    var store: PlainNodes = undefined;
    const entry = entryPlain(&store, "m.txt", &sz_enc_data);
    const crypto_nodes = [_]harness.Node{
        harness.cryptoProfile(),
        harness.pw(sz_enc_password),
    };
    sz_enc_archive_size = try sevenZipWrite(r, entry, &sz_enc_archive, &crypto_nodes);
    @memset(&sz_enc_output, 0xa5);
    _ = try sevenZipRead(r, sz_enc_archive[0..sz_enc_archive_size], 0, &sz_enc_output, &crypto_nodes);
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != sz_enc_data.len or !std.mem.eql(u8, sz_enc_output[0..sz_enc_data.len], &sz_enc_data)) {
        return error.EncryptedSpanReadMismatch;
    }
    var source_ctx = harness.SourceCallbackContext{ .data = sz_enc_archive[0..sz_enc_archive_size] };
    @memset(&sz_enc_output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.ord(0),
        harness.sourceCallbackNode(0, 0),
        harness.sinkSpan(&sz_enc_output),
        harness.cryptoProfile(),
        harness.pw(sz_enc_password),
    }, .{ .ctx = true, .callback = harness.sourceCallback, .context = &source_ctx });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != sz_enc_data.len or !std.mem.eql(u8, sz_enc_output[0..sz_enc_data.len], &sz_enc_data)) {
        return error.EncryptedCallbackReadMismatch;
    }
    try harness.reject(r, harness.ids.read, &.{
        harness.ord(0),
        harness.sourceSpan(sz_enc_archive[0..sz_enc_archive_size]),
        harness.sinkSpan(&sz_enc_output),
    }, .{ .ctx = true }, abi.Status.unsupported, &sz_enc_output);
    var wrong_password: harness.Node = undefined;
    var kdf_limit: harness.Node = undefined;
    var password_lifetime: harness.Node = undefined;
    var unsupported_algorithm: harness.Node = undefined;
    var diagnostic = harness.cryptoDiagnostic(&wrong_password, &kdf_limit, &password_lifetime, &unsupported_algorithm);
    @memset(&sz_enc_output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.ord(0),
        harness.sourceSpan(sz_enc_archive[0..sz_enc_archive_size]),
        harness.sinkSpan(&sz_enc_output),
        harness.cryptoProfile(),
        harness.pw("wrong"),
    }, .{ .ctx = true, .diagnostic = &diagnostic });
    try harness.requireStatus(r, abi.Status.integrity_failure);
    var diag2 = harness.cryptoDiagnostic(&wrong_password, &kdf_limit, &password_lifetime, &unsupported_algorithm);
    _ = harness.call(r, harness.ids.read, &.{
        harness.ord(0),
        harness.sourceSpan(sz_enc_archive[0..sz_enc_archive_size]),
        harness.sinkSpan(&sz_enc_output),
        harness.cryptoProfile(),
        harness.pw(sz_enc_password),
        harness.kdf(100),
    }, .{ .ctx = true, .diagnostic = &diag2 });
    try harness.requireStatus(r, abi.Status.resource_limit);
    if (kdf_limit.value_low != abi.Status.resource_limit) return error.EncryptedKdfLimitMismatch;
    var diag3 = harness.cryptoDiagnostic(&wrong_password, &kdf_limit, &password_lifetime, &unsupported_algorithm);
    _ = harness.call(r, harness.ids.read, &.{
        harness.ord(0),
        harness.sourceSpan(sz_enc_archive[0..sz_enc_archive_size]),
        harness.sinkSpan(&sz_enc_output),
        harness.cryptoProfile(),
        harness.pw(sz_enc_password),
        harness.plt(1),
    }, .{ .ctx = true, .diagnostic = &diag3 });
    try harness.requireStatus(r, abi.Status.resource_limit);
    if (password_lifetime.value_low != abi.Status.resource_limit) return error.EncryptedLifetimeMismatch;
    var store_lzma2: EntryNodes = undefined;
    const lzma2_entry = entryWithMethod(&store_lzma2, "l2.txt", &sz_enc_data, 4);
    const lzma2_size = try sevenZipWrite(r, lzma2_entry, &sz_enc_archive, &crypto_nodes);
    @memset(&sz_enc_output, 0xa5);
    _ = try sevenZipRead(r, sz_enc_archive[0..lzma2_size], 0, &sz_enc_output, &crypto_nodes);
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != sz_enc_data.len or !std.mem.eql(u8, sz_enc_output[0..sz_enc_data.len], &sz_enc_data)) {
        return error.EncryptedLzma2ReadMismatch;
    }
    const fixture_data = [_][]const u8{
        &fixtures.sz_lzma2_fixture,
        &fixtures.sz_copy97_fixture,
        &fixtures.sz_deflate_fixture,
        &fixtures.sz_bzip2_fixture,
        &fixtures.sz_lzma_fixture,
    };
    for (fixture_data) |fixture_bytes| {
        @memset(&sz_enc_output, 0xa5);
        _ = harness.call(r, harness.ids.read, &.{
            harness.ord(0),
            harness.sourceSpan(fixture_bytes),
            harness.sinkSpan(&sz_enc_output),
            harness.cryptoProfile(),
            harness.pw(sz_enc_password),
        }, .{ .ctx = true });
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length != 97) return error.EncryptedFixtureReadMismatch;
    }
    @memset(&sz_enc_output, 0xa5);
    _ = harness.call(r, harness.ids.read, &.{
        harness.ord(0),
        harness.sourceSpan(&fixtures.sz_copy53_fixture),
        harness.sinkSpan(&sz_enc_output),
        harness.cryptoProfile(),
        harness.pw(sz_enc_password),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 53) return error.Copy53FixtureMismatch;
}

fn runSkipped(r: *Runner, label: []const u8) anyerror!void {
    _ = r;
    std.debug.print("{s}: unsupported (no system library supports this interop)\n", .{label});
}

pub fn runFilters(r: *Runner) anyerror!void {
    try runSkipped(r, "seven_zip filters");
}

pub fn runSolid(r: *Runner) anyerror!void {
    try runSkipped(r, "seven_zip solid");
}

pub fn runPpmd(r: *Runner) anyerror!void {
    try runSkipped(r, "seven_zip ppmd");
}

pub fn runPpmdErrors(r: *Runner) anyerror!void {
    try runSkipped(r, "seven_zip ppmd errors");
}

pub const scenarios = harness.scenarios("seven_zip", &.{
    .{ .label = "seven_zip decoded", .run = runDecoded, .workspace_size = 65536, .output_size = 1024, .encoded_size = 65536 },
    .{ .label = "seven_zip coded", .run = runCoded, .workspace_size = 64 * 1024 * 1024, .output_size = 1024, .encoded_size = 65536 },
    .{ .label = "seven_zip encode advanced", .run = runEncodeAdvanced, .workspace_size = 48 * 1024 * 1024, .output_size = 1024, .encoded_size = 65536 },
    .{ .label = "seven_zip encrypted", .run = runEncrypted, .workspace_size = 64 * 1024 * 1024, .output_size = 1024, .encoded_size = 65536 },
    .{ .label = "seven_zip filters", .run = runFilters, .workspace_size = 8 * 1024 * 1024, .output_size = 1024, .encoded_size = 65536 },
    .{ .label = "seven_zip solid", .run = runSolid, .workspace_size = 8 * 1024 * 1024, .output_size = 1024, .encoded_size = 65536 },
    .{ .label = "seven_zip ppmd", .run = runPpmd, .workspace_size = 32 * 1024 * 1024, .output_size = 1024, .encoded_size = 65536 },
}, &.{
    .{ .name = "seven_zip ppmd errors", .run = runPpmdErrors, .workspace_size = 32 * 1024 * 1024, .output_size = 2048, .encoded_size = 16384 },
});
