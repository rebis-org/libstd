const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const harness = @import("harness.zig");
const Runner = harness.Runner;
const lib = @import("lib.zig");

fn setupTar(r: *Runner) void {
    harness.setup(r, harness.ids.tar, harness.mode_archive);
}

fn tarOctal(field: []u8, value: u64) void {
    @memset(field, 0);
    var index = field.len;
    var remaining = value;
    while (index > 0) {
        index -= 1;
        field[index] = '0' + @as(u8, @intCast(remaining & 7));
        remaining >>= 3;
    }
}

fn tarUpdateChecksum(block: *[512]u8) void {
    @memset(block[148..156], ' ');
    var sum: u64 = 0;
    for (block) |byte| sum += byte;
    var i: usize = 0;
    while (i < 6) : (i += 1) {
        block[153 - i] = '0' + @as(u8, @intCast(sum & 7));
        sum >>= 3;
    }
    block[154] = 0;
    block[155] = ' ';
}

fn tarFillHeader(block: *[512]u8, name: []const u8, typeflag: u8, size: u64, link_name: ?[]const u8) void {
    @memset(block, 0);
    @memcpy(block[0..name.len], name);
    tarOctal(block[100..108], 0o644);
    tarOctal(block[108..116], 0);
    tarOctal(block[116..124], 0);
    tarOctal(block[124..136], size);
    tarOctal(block[136..148], 0);
    block[156] = typeflag;
    if (link_name) |link| @memcpy(block[157 .. 157 + link.len], link);
    @memcpy(block[257..262], "ustar");
    @memcpy(block[263..265], "00");
    tarUpdateChecksum(block);
}

fn tarPaxRecord(buffer: []u8, key: []const u8, value: []const u8) usize {
    const content = key.len + 1 + value.len;
    var total: usize = 0;
    var digits: [32]u8 = undefined;
    for (1..64) |length| {
        const digit_text = std.fmt.bufPrint(&digits, "{d}", .{length}) catch return 0;
        total = digit_text.len + 1 + content + 1;
        if (total == length) break;
    }
    if (total >= buffer.len) return 0;
    const text = std.fmt.bufPrint(buffer[0..buffer.len], "{d} {s}={s}\n", .{ total, key, value }) catch return 0;
    return text.len;
}

const EntryNodes = struct {
    name: harness.Node,
    data: harness.Node,
    type: harness.Node,
    link: harness.Node,
    uid: harness.Node,
};

fn entryWithType(nodes: *EntryNodes, name: []const u8, data: []const u8, typeflag: u8, link_name: ?[]const u8, uid_value: ?u64) harness.Node {
    const entry = harness.archiveEntryNode(&nodes.name, &nodes.data, name, data);
    nodes.data.next = &nodes.type;
    nodes.type = harness.tflag(typeflag);
    if (link_name) |link| {
        nodes.type.next = &nodes.link;
        nodes.link = harness.link(link);
    }
    if (uid_value) |value| {
        if (link_name) |_| {
            nodes.link.next = &nodes.uid;
        } else {
            nodes.type.next = &nodes.uid;
        }
        nodes.uid = harness.uid(value);
    }
    return entry;
}

var tar_archive: [65536]u8 = undefined;
var tar_output: [1024]u8 = undefined;

fn tarEncEntryTypes(r: *Runner) !void {
    var tar_corpus_buffer: [445]u8 = undefined;
    corpus.select(r.corpus_index, &tar_corpus_buffer);
    var store_file: EntryNodes = undefined;
    var store_dir: EntryNodes = undefined;
    var store_link: EntryNodes = undefined;
    var store_hard: EntryNodes = undefined;
    const entry_file = entryWithType(&store_file, "afile.txt", &tar_corpus_buffer, 0, null, null);
    const entry_dir = entryWithType(&store_dir, "adir/", &.{}, '5', null, null);
    const entry_link = entryWithType(&store_link, "alink", &.{}, '2', "afile.txt", null);
    const entry_hard = entryWithType(&store_hard, "ahard", &.{}, '1', "afile.txt", null);
    var entries = [_]harness.Node{ entry_file, entry_dir, entry_link, entry_hard };
    entries[0].next = &entries[1];
    entries[1].next = &entries[2];
    entries[2].next = &entries[3];
    _ = harness.call(r, harness.ids.query, &.{
        harness.paramTargetCommand(harness.ids.write),
        harness.scalarNode(harness.ids.source),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_verified),
        entries[0],
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length == 0 or r.response.byte_length > tar_archive.len) return error.EntryTypesQueryFailed;
    const archive_size: usize = @intCast(r.response.byte_length);
    _ = harness.call(r, harness.ids.write, &.{
        harness.scalarNode(harness.ids.source),
        harness.sinkSpan(tar_archive[0..archive_size]),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_verified),
        entries[0],
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != archive_size) return error.EntryTypesWriteFailed;
    const expected_sizes = [_]usize{ tar_corpus_buffer.len, 0, 0, 0 };
    for (0..4) |i| {
        _ = harness.call(r, harness.ids.read, &.{
            harness.ord(i),
            harness.sourceSpan(tar_archive[0..archive_size]),
            harness.sinkSpan(&tar_output),
        }, .{ .ctx = true });
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length != expected_sizes[i]) return error.EntrySizeMismatch;
        if (i == 0 and !std.mem.eql(u8, tar_output[0..tar_corpus_buffer.len], &tar_corpus_buffer)) {
            return error.EntryContentMismatch;
        }
    }
    const expected = [_]lib.ExpectedEntry{
        .{ .name = "afile.txt", .data = &tar_corpus_buffer, .filetype = 0o100000 },
        .{ .name = "adir/", .filetype = 0o040000 },
        .{ .name = "alink", .symlink = "afile.txt", .filetype = 0o120000 },
        .{ .name = "ahard", .hardlink = "afile.txt" },
    };
    const result = lib.archiveReadMatches(tar_archive[0..archive_size], &expected);
    if (result == .mismatch) return error.TarListingMismatch;
}

fn tarEncPaxName(r: *Runner) !void {
    const long_name = "thisisaverylongfilenamethatexceedstheustarnamefieldcapacityandcannotbesplitintoprefixandnamepartssoapaxpathrecordisrequiredforthistest.txt";
    var payload: [32]u8 = undefined;
    corpus.select(r.corpus_index, &payload);
    var store: EntryNodes = undefined;
    const entry = entryWithType(&store, long_name, &payload, 0, null, null);
    _ = harness.call(r, harness.ids.query, &.{
        harness.paramTargetCommand(harness.ids.write),
        harness.scalarNode(harness.ids.source),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_verified),
        entry,
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length == 0 or r.response.byte_length > tar_archive.len) return error.PaxNameQueryFailed;
    const archive_size: usize = @intCast(r.response.byte_length);
    _ = harness.call(r, harness.ids.write, &.{
        harness.scalarNode(harness.ids.source),
        harness.sinkSpan(tar_archive[0..archive_size]),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_verified),
        entry,
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != archive_size) return error.PaxNameWriteFailed;
    _ = harness.call(r, harness.ids.read, &.{
        harness.ord(0),
        harness.sourceSpan(tar_archive[0..archive_size]),
        harness.sinkSpan(&tar_output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != payload.len or !std.mem.eql(u8, tar_output[0..payload.len], &payload)) {
        return error.PaxNameRoundtripMismatch;
    }
    if (!harness.containsBytes(tar_archive[0..archive_size], "path=")) return error.PaxPathRecordMissing;
    const expected = [_]lib.ExpectedEntry{
        .{ .name = long_name, .data = &payload },
    };
    const result = lib.archiveReadMatches(tar_archive[0..archive_size], &expected);
    if (result == .mismatch) return error.PaxExtractMismatch;
}

fn tarEncPaxUid(r: *Runner) !void {
    var tar_corpus_buffer: [445]u8 = undefined;
    corpus.select(r.corpus_index, &tar_corpus_buffer);
    var store: EntryNodes = undefined;
    const entry = entryWithType(&store, "uidpax.txt", &tar_corpus_buffer, 0, null, @as(u64, 1) << 22);
    _ = harness.call(r, harness.ids.query, &.{
        harness.paramTargetCommand(harness.ids.write),
        harness.scalarNode(harness.ids.source),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_verified),
        entry,
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length == 0 or r.response.byte_length > tar_archive.len) return error.PaxUidQueryFailed;
    const archive_size: usize = @intCast(r.response.byte_length);
    _ = harness.call(r, harness.ids.write, &.{
        harness.scalarNode(harness.ids.source),
        harness.sinkSpan(tar_archive[0..archive_size]),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_verified),
        entry,
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != archive_size) return error.PaxUidWriteFailed;
    if (!harness.containsBytes(tar_archive[0..archive_size], "uid=4194304")) return error.PaxUidRecordMissing;
    _ = harness.call(r, harness.ids.read, &.{
        harness.ord(0),
        harness.sourceSpan(tar_archive[0..archive_size]),
        harness.sinkSpan(&tar_output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != tar_corpus_buffer.len or !std.mem.eql(u8, tar_output[0..tar_corpus_buffer.len], &tar_corpus_buffer)) {
        return error.PaxUidRoundtripMismatch;
    }
    const expected = [_]lib.ExpectedEntry{
        .{ .name = "uidpax.txt", .data = &tar_corpus_buffer, .uid = @as(i64, 1) << 22 },
    };
    const result = lib.archiveReadMatches(tar_archive[0..archive_size], &expected);
    if (result == .mismatch) return error.TarUidListingMismatch;
}

fn tarEncErrors(r: *Runner) !void {
    var store_bad_link: EntryNodes = undefined;
    const entry_bad_link = entryWithType(&store_bad_link, "badlink", &.{}, '2', "", null);
    try harness.expect(r, harness.ids.write, &.{
        harness.scalarNode(harness.ids.source),
        harness.sinkSpan(tar_archive[0..tar_archive.len]),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_verified),
        entry_bad_link,
    }, .{}, abi.Status.invalid_call);
    var tar_corpus_buffer: [445]u8 = undefined;
    corpus.select(r.corpus_index, &tar_corpus_buffer);
    var store_bad_dir: EntryNodes = undefined;
    const entry_bad_dir = entryWithType(&store_bad_dir, "baddir/", &tar_corpus_buffer, '5', null, null);
    try harness.expect(r, harness.ids.write, &.{
        harness.scalarNode(harness.ids.source),
        harness.sinkSpan(tar_archive[0..tar_archive.len]),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_verified),
        entry_bad_dir,
    }, .{}, abi.Status.invalid_call);
    var store_bad_type: EntryNodes = undefined;
    const entry_bad_type = entryWithType(&store_bad_type, "badtype", &.{}, '9', null, null);
    try harness.expect(r, harness.ids.write, &.{
        harness.scalarNode(harness.ids.source),
        harness.sinkSpan(tar_archive[0..tar_archive.len]),
        harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay),
        harness.pln(harness.plan_metadata_exact),
        harness.dlv(harness.delivery_verified),
        entry_bad_type,
    }, .{}, abi.Status.invalid_call);
}

pub fn runEncode(r: *Runner) anyerror!void {
    setupTar(r);
    try tarEncEntryTypes(r);
    try tarEncPaxName(r);
    try tarEncPaxUid(r);
    try tarEncErrors(r);
}

fn tarSparseReadOrdinal(r: *Runner, archive: []const u8, ordinal: u64, output: []u8) void {
    _ = harness.call(r, harness.ids.read, &.{
        harness.ord(ordinal),
        harness.sourceSpan(archive),
        harness.sinkSpan(output),
    }, .{ .ctx = true });
}

fn sparseExpected(offset: usize, length: usize, output: []const u8, data: []const u8) bool {
    if (offset + length > output.len) return false;
    return std.mem.eql(u8, output[offset .. offset + length], data);
}

fn tarSparseOld(r: *Runner) !void {
    var archive: [16384]u8 = undefined;
    var output: [2048]u8 = undefined;
    var block: [512]u8 = undefined;
    @memset(&archive, 0);
    tarFillHeader(&block, "sparse.bin", 'S', 12, null);
    tarOctal(block[345..357], 0);
    tarOctal(block[357..369], 0);
    tarOctal(block[369..381], 0);
    tarOctal(block[386..398], 10);
    tarOctal(block[398..410], 5);
    tarOctal(block[410..422], 80);
    tarOctal(block[422..434], 7);
    block[482] = 0;
    tarOctal(block[483..495], 100);
    tarUpdateChecksum(&block);
    var pos: usize = 0;
    @memcpy(archive[pos .. pos + 512], &block);
    pos += 512;
    @memcpy(archive[pos .. pos + 5], "quick");
    pos += 5;
    @memcpy(archive[pos .. pos + 7], "brown!!");
    pos += 7;
    while (pos % 512 != 0) {
        archive[pos] = 0;
        pos += 1;
    }
    @memset(archive[pos .. pos + 1024], 0);
    pos += 1024;
    @memset(&output, 0xa5);
    tarSparseReadOrdinal(r, archive[0..pos], 0, &output);
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 100) return error.SparseOldLengthMismatch;
    for (0..100) |i| {
        const expected: u8 = if (i >= 10 and i < 15)
            "quick"[i - 10]
        else if (i >= 80 and i < 87)
            "brown!!"[i - 80]
        else
            0;
        if (output[i] != expected) return error.SparseOldContentMismatch;
    }
    var cb_output: [100]u8 = undefined;
    var cb = harness.SinkBufferContext{ .buffer = &cb_output, .accept_limit = cb_output.len };
    _ = harness.call(r, harness.ids.read, &.{
        harness.ord(0),
        harness.sourceSpan(archive[0..pos]),
        harness.sinkCallbackNode(0, 0),
    }, .{ .ctx = true, .callback = harness.sinkBufferCallback, .context = &cb });
    try harness.requireStatus(r, abi.Status.ok);
    if (cb.offset != 100 or !std.mem.eql(u8, &cb_output, output[0..100])) return error.SparseOldCallbackMismatch;
}

fn tarSparseExtension(r: *Runner) !void {
    var archive: [16384]u8 = undefined;
    var output: [2048]u8 = undefined;
    var block: [512]u8 = undefined;
    const data = [_][3]u8{
        .{ 1, 2, 3 },
        .{ 4, 5, 6 },
        .{ 7, 8, 9 },
        .{ 10, 11, 12 },
        .{ 13, 14, 15 },
        .{ 16, 17, 18 },
    };
    const offsets = [_]u64{ 0, 8, 16, 24, 32, 40 };
    @memset(&archive, 0);
    tarFillHeader(&block, "sparse6.bin", 'S', 18, null);
    for (0..4) |i| {
        tarOctal(block[386 + 24 * i .. 398 + 24 * i], offsets[i]);
        tarOctal(block[398 + 24 * i .. 410 + 24 * i], 3);
    }
    block[482] = 1;
    tarOctal(block[483..495], 50);
    tarUpdateChecksum(&block);
    var pos: usize = 0;
    @memcpy(archive[pos .. pos + 512], &block);
    pos += 512;
    @memset(&block, 0);
    for (4..6) |i| {
        tarOctal(block[24 * (i - 4) .. 12 + 24 * (i - 4)], offsets[i]);
        tarOctal(block[12 + 24 * (i - 4) .. 24 + 24 * (i - 4)], 3);
    }
    block[504] = 0;
    @memcpy(archive[pos .. pos + 512], &block);
    pos += 512;
    for (0..6) |i| {
        @memcpy(archive[pos .. pos + 3], &data[i]);
        pos += 3;
    }
    while (pos % 512 != 0) {
        archive[pos] = 0;
        pos += 1;
    }
    @memset(archive[pos .. pos + 1024], 0);
    pos += 1024;
    @memset(&output, 0xa5);
    tarSparseReadOrdinal(r, archive[0..pos], 0, &output);
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 50) return error.SparseExtensionLengthMismatch;
    for (0..50) |i| {
        const expected: u8 = if (i >= 0 and i < 3)
            data[0][i]
        else if (i >= 8 and i < 11)
            data[1][i - 8]
        else if (i >= 16 and i < 19)
            data[2][i - 16]
        else if (i >= 24 and i < 27)
            data[3][i - 24]
        else if (i >= 32 and i < 35)
            data[4][i - 32]
        else if (i >= 40 and i < 43)
            data[5][i - 40]
        else
            0;
        if (output[i] != expected) return error.SparseExtensionContentMismatch;
    }
}

fn buildPaxSparse(r: *Runner, pax_records: []const []const u8, file_name: []const u8, map_data: []const u8, file_data: []const u8, include_map_block: bool) !usize {
    var archive: [16384]u8 = undefined;
    var block: [512]u8 = undefined;
    var pax_data: [512]u8 = undefined;
    var pax_len: usize = 0;
    @memset(&archive, 0);
    @memset(&pax_data, 0);
    for (pax_records) |record| {
        const key = record[0..std.mem.indexOfScalar(u8, record, '=').?];
        const value = record[std.mem.indexOfScalar(u8, record, '=').? + 1 ..];
        pax_len += tarPaxRecord(pax_data[pax_len..], key, value);
    }
    tarFillHeader(&block, "pax/", 'x', pax_len, null);
    var pos: usize = 0;
    @memcpy(archive[pos .. pos + 512], &block);
    pos += 512;
    @memcpy(archive[pos .. pos + pax_len], pax_data[0..pax_len]);
    pos += pax_len;
    while (pos % 512 != 0) {
        archive[pos] = 0;
        pos += 1;
    }
    const file_size = if (include_map_block) map_data.len + 512 else file_data.len;
    tarFillHeader(&block, file_name, '0', file_size, null);
    @memcpy(archive[pos .. pos + 512], &block);
    pos += 512;
    if (include_map_block) {
        @memcpy(archive[pos .. pos + map_data.len], map_data);
        pos += map_data.len;
        while (pos % 512 != 0) {
            archive[pos] = 0;
            pos += 1;
        }
    }
    @memcpy(archive[pos .. pos + file_data.len], file_data);
    pos += file_data.len;
    while (pos % 512 != 0) {
        archive[pos] = 0;
        pos += 1;
    }
    @memset(archive[pos .. pos + 1024], 0);
    pos += 1024;
    var output: [2048]u8 = undefined;
    @memset(&output, 0xa5);
    tarSparseReadOrdinal(r, archive[0..pos], 0, &output);
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 100) return error.SparsePaxLengthMismatch;
    for (0..100) |i| {
        const expected: u8 = if (i >= 10 and i < 15)
            "quick"[i - 10]
        else if (i >= 80 and i < 87)
            "brown!!"[i - 80]
        else
            0;
        if (output[i] != expected) return error.SparsePaxContentMismatch;
    }
    return pos;
}

fn tarSparsePax10(r: *Runner) !void {
    const records = [_][]const u8{
        "GNU.sparse.major=1",
        "GNU.sparse.minor=0",
        "GNU.sparse.name=spax.bin",
        "GNU.sparse.realsize=100",
    };
    _ = try buildPaxSparse(r, &records, "0/GNUSparseFile.1/spax.bin", "2\n10\n5\n80\n7\n", "quickbrown!!", true);
}

fn tarSparsePax01(r: *Runner) !void {
    const records = [_][]const u8{
        "GNU.sparse.size=100",
        "GNU.sparse.numblocks=2",
        "GNU.sparse.map=10,5,80,7",
        "GNU.sparse.name=pax01.bin",
    };
    _ = try buildPaxSparse(r, &records, "0/GNUSparseFile.1/pax01.bin", "10,5,80,7", "quickbrown!!", false);
}

fn tarSparsePaxSize(r: *Runner) !void {
    var archive: [16384]u8 = undefined;
    var output: [2048]u8 = undefined;
    var block: [512]u8 = undefined;
    var pax_data: [64]u8 = undefined;
    var pax_len: usize = 0;
    @memset(&archive, 0);
    @memset(&pax_data, 0);
    pax_len += tarPaxRecord(pax_data[pax_len..], "size", "5");
    tarFillHeader(&block, "pax/", 'x', pax_len, null);
    var pos: usize = 0;
    @memcpy(archive[pos .. pos + 512], &block);
    pos += 512;
    @memcpy(archive[pos .. pos + pax_len], pax_data[0..pax_len]);
    pos += pax_len;
    while (pos % 512 != 0) {
        archive[pos] = 0;
        pos += 1;
    }
    tarFillHeader(&block, "override.txt", '0', 3, null);
    @memcpy(archive[pos .. pos + 512], &block);
    pos += 512;
    @memcpy(archive[pos .. pos + 5], "quick");
    pos += 5;
    while (pos % 512 != 0) {
        archive[pos] = 0;
        pos += 1;
    }
    tarFillHeader(&block, "after.txt", '0', 2, null);
    @memcpy(archive[pos .. pos + 512], &block);
    pos += 512;
    @memcpy(archive[pos .. pos + 2], "go");
    pos += 2;
    while (pos % 512 != 0) {
        archive[pos] = 0;
        pos += 1;
    }
    @memset(archive[pos .. pos + 1024], 0);
    pos += 1024;
    @memset(&output, 0xa5);
    tarSparseReadOrdinal(r, archive[0..pos], 0, &output);
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 5 or !std.mem.eql(u8, output[0..5], "quick")) return error.PaxSizeOverrideMismatch;
    @memset(&output, 0xa5);
    tarSparseReadOrdinal(r, archive[0..pos], 1, &output);
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 2 or !std.mem.eql(u8, output[0..2], "go")) return error.PaxSizeSecondEntryMismatch;
}

fn tarSparseMalformed(r: *Runner) !void {
    var archive: [16384]u8 = undefined;
    var output: [2048]u8 = undefined;
    var block: [512]u8 = undefined;
    @memset(&archive, 0);
    tarFillHeader(&block, "bad.bin", 'S', 5, null);
    tarOctal(block[386..398], 80);
    tarOctal(block[398..410], 5);
    block[482] = 0;
    tarOctal(block[483..495], 10);
    tarUpdateChecksum(&block);
    var pos: usize = 0;
    @memcpy(archive[pos .. pos + 512], &block);
    pos += 512;
    @memcpy(archive[pos .. pos + 5], "quick");
    pos += 5;
    while (pos % 512 != 0) {
        archive[pos] = 0;
        pos += 1;
    }
    @memset(archive[pos .. pos + 1024], 0);
    pos += 1024;
    @memset(&output, 0xa5);
    tarSparseReadOrdinal(r, archive[0..pos], 0, &output);
    if (r.status == abi.Status.ok) return error.MalformedSparseAccepted;
    pos = 0;
    @memset(&archive, 0);
    var pax_data: [64]u8 = undefined;
    @memset(&pax_data, 0);
    const pax_len = tarPaxRecord(&pax_data, "size", "9999");
    tarFillHeader(&block, "pax/", 'x', pax_len, null);
    @memcpy(archive[pos .. pos + 512], &block);
    pos += 512;
    @memcpy(archive[pos .. pos + pax_len], pax_data[0..pax_len]);
    pos += pax_len;
    while (pos % 512 != 0) {
        archive[pos] = 0;
        pos += 1;
    }
    tarFillHeader(&block, "huge.txt", '0', 3, null);
    @memcpy(archive[pos .. pos + 512], &block);
    pos += 512;
    @memcpy(archive[pos .. pos + 3], "abc");
    pos += 3;
    while (pos % 512 != 0) {
        archive[pos] = 0;
        pos += 1;
    }
    @memset(archive[pos .. pos + 1024], 0);
    pos += 1024;
    @memset(&output, 0xa5);
    tarSparseReadOrdinal(r, archive[0..pos], 0, &output);
    if (r.status == abi.Status.ok) return error.OversizedPaxSizeAccepted;
}

pub fn runSparse(r: *Runner) anyerror!void {
    setupTar(r);
    try tarSparseOld(r);
    try tarSparseExtension(r);
    try tarSparsePax10(r);
    try tarSparsePax01(r);
    try tarSparsePaxSize(r);
    try tarSparseMalformed(r);
}

pub const scenarios = harness.scenarios("tar", &.{
    .{ .label = "tar encode advanced", .run = runEncode, .workspace_size = 65536, .output_size = 1024, .encoded_size = 65536 },
}, &.{
    .{ .name = "tar sparse", .run = runSparse, .workspace_size = 65536, .output_size = 2048, .encoded_size = 16384 },
});
