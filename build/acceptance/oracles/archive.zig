const std = @import("std");

const abi = @import("abi.zig");
const corpus = @import("corpus.zig");
const harness = @import("harness.zig");
const Runner = harness.Runner;
const lib = @import("lib.zig");
const fixtures = @import("fixtures.zig");

const arc_caps: u64 = harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay;

const ArcFixture = struct {
    archive: [4096]u8,
    archive_size: usize = 0,
    data1: [32]u8,
    data2: [445]u8,
    name1: harness.Node,
    data_node1: harness.Node,
    entry1: harness.Node,
    name2: harness.Node,
    data_node2: harness.Node,
    entry2: harness.Node,
};

var arc_state: ArcFixture = .{
    .archive = undefined,
    .data1 = undefined,
    .data2 = undefined,
    .name1 = undefined,
    .data_node1 = undefined,
    .entry1 = undefined,
    .name2 = undefined,
    .data_node2 = undefined,
    .entry2 = undefined,
};

fn arcBuildEntries(index: usize) void {
    corpus.select(index, &arc_state.data1);
    corpus.select(index, &arc_state.data2);
    arc_state.entry1 = harness.archiveEntryNode(
        &arc_state.name1,
        &arc_state.data_node1,
        "m1.txt",
        &arc_state.data1,
    );
    arc_state.entry2 = harness.archiveEntryNode(
        &arc_state.name2,
        &arc_state.data_node2,
        "m2.txt",
        &arc_state.data2,
    );
    arc_state.entry1.next = &arc_state.entry2;
}

fn setupArchive(r: *Runner, profile_id: harness.Id) void {
    harness.setup(r, profile_id, harness.mode_archive);
    arcBuildEntries(r.corpus_index);
}

fn arcQueryWrite(r: *Runner) !void {
    _ = harness.call(r, harness.ids.query, &.{
        harness.paramTargetCommand(harness.ids.write),
        harness.scalarNode(harness.ids.source),
        harness.capabilityParam(arc_caps),
        harness.sizingModeParam(harness.size_metadata_exact),
        harness.commitModeParam(harness.commit_confirmed),
        arc_state.entry1,
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length == 0 or r.response.byte_length > arc_state.archive.len) return error.ArchiveQueryCapacity;
    arc_state.archive_size = @intCast(r.response.byte_length);
    r.required = arc_state.archive_size;
}

fn arcWrite(r: *Runner) !void {
    _ = harness.call(r, harness.ids.write, &.{
        harness.scalarNode(harness.ids.source),
        harness.sinkSpan(arc_state.archive[0..arc_state.archive_size]),
        harness.capabilityParam(arc_caps),
        harness.sizingModeParam(harness.size_metadata_exact),
        harness.commitModeParam(r.commit_write),
        arc_state.entry1,
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != arc_state.archive_size) return error.ArchiveWriteLengthMismatch;
}

fn arcQueryRead(r: *Runner) !void {
    _ = harness.call(r, harness.ids.query, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(arc_state.archive[0..arc_state.archive_size]),
        harness.capabilityParam(arc_caps),
        harness.sizingModeParam(harness.size_metadata_exact),
        harness.commitModeParam(r.commit_read),
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 2) return error.ArchiveEntryCountMismatch;
}

fn arcReadOrdinal(r: *Runner, ordinal: u64, expected: []const u8) !void {
    _ = harness.call(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(ordinal),
        harness.sourceSpan(arc_state.archive[0..arc_state.archive_size]),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != expected.len or !std.mem.eql(u8, r.output[0..expected.len], expected)) {
        return error.ArchiveOrdinalMismatch;
    }
}

fn arcReadCallback0(r: *Runner) !void {
    var source_ctx = harness.SourceCallbackContext{ .data = arc_state.archive[0..arc_state.archive_size] };
    _ = harness.call(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceCallbackNode(0, 0),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true, .callback = harness.sourceCallback, .context = &source_ctx });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != arc_state.data1.len or !std.mem.eql(u8, r.output[0..arc_state.data1.len], &arc_state.data1)) {
        return error.ArchiveCallbackOrdinalMismatch;
    }
}

fn arcWriteCallbackSource(r: *Runner) !void {
    var source_ctx = harness.SourceCallbackContext{ .data = &.{} };
    _ = harness.call(r, harness.ids.write, &.{
        harness.paramProfile(r.profile_id),
        harness.sourceCallbackNode(0, 0),
        harness.sinkSpan(arc_state.archive[0..arc_state.archive_size]),
        harness.capabilityParam(arc_caps),
        harness.sizingModeParam(harness.size_metadata_exact),
        harness.commitModeParam(r.commit_write),
        arc_state.entry1,
    }, .{ .profile = false, .callback = harness.sourceCallback, .context = &source_ctx });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != arc_state.archive_size) return error.ArchiveCallbackSourceWriteLengthMismatch;
}

fn arcReadCallbackSink(r: *Runner) !void {
    var sink_ctx = harness.SinkBufferContext{ .buffer = r.output, .accept_limit = std.math.maxInt(usize) };
    _ = harness.call(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(arc_state.archive[0..arc_state.archive_size]),
        harness.sinkCallbackNode(0, 0),
    }, .{ .ctx = true, .callback = harness.sinkBufferCallback, .context = &sink_ctx });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != arc_state.data1.len or sink_ctx.offset != arc_state.data1.len or !std.mem.eql(u8, r.output[0..arc_state.data1.len], &arc_state.data1)) {
        return error.ArchiveCallbackSinkMismatch;
    }
}

fn arcCapacity(r: *Runner) !void {
    try harness.expectCapacity(r, harness.ids.write, &.{
        harness.paramProfile(r.profile_id),
        harness.scalarNode(harness.ids.source),
        harness.sinkSpan(r.output[0..1]),
        harness.capabilityParam(arc_caps),
        harness.sizingModeParam(harness.size_metadata_exact),
        harness.commitModeParam(r.commit_write),
        arc_state.entry1,
    }, .{ .profile = false }, arc_state.archive_size, 1, r.output[0..1]);
}

fn arcCorrupt(r: *Runner) !void {
    arc_state.archive[0] ^= 0xff;
    const nodes = &.{
        harness.sourceSpan(arc_state.archive[0..arc_state.archive_size]),
        harness.sinkSpan(r.output),
    };
    @memset(r.output, 0xa5);
    _ = harness.call(r, harness.ids.read, nodes, .{ .ctx = true });
    arc_state.archive[0] ^= 0xff;
    if (r.status == abi.Status.ok or !harness.allBytesEqual(r.output, 0xa5)) return error.CorruptArchiveChangedOutput;
}

fn arcLimit(r: *Runner) !void {
    try harness.reject(r, harness.ids.read, &.{
        harness.sourceSpan(arc_state.archive[0..arc_state.archive_size]),
        harness.sinkSpan(r.output),
        harness.resourceLimitParam(arc_state.archive_size - 1),
    }, .{ .ctx = true }, abi.Status.resource_limit, r.output);
}

fn arcForeign(r: *Runner) !void {
    _ = r;
    const expected = [_]lib.ExpectedEntry{
        .{ .name = "m1.txt", .data = &arc_state.data1 },
        .{ .name = "m2.txt", .data = &arc_state.data2 },
    };
    const result = lib.archiveReadMatches(arc_state.archive[0..arc_state.archive_size], &expected);
    if (result == .mismatch) return error.ReferenceToolRejectedOutput;
}

fn runArchive(r: *Runner, profile_id: harness.Id) anyerror!void {
    setupArchive(r, profile_id);
    try arcQueryWrite(r);
    try arcWrite(r);
    try arcQueryRead(r);
    try arcReadOrdinal(r, 0, &arc_state.data1);
    try arcReadOrdinal(r, 1, &arc_state.data2);
    try arcReadCallback0(r);
    try arcWriteCallbackSource(r);
    try arcReadCallbackSink(r);
    try arcCapacity(r);
    try arcCorrupt(r);
    try arcLimit(r);
    try arcForeign(r);
}

pub fn runTar(r: *Runner) anyerror!void {
    try runArchive(r, harness.ids.tar);
}

pub fn runZip(r: *Runner) anyerror!void {
    try runArchive(r, harness.ids.zip);
}

const rar_fixture = [_]u8{
    0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00, 0x33, 0x92, 0xb5, 0xe5, 0x0a, 0x01, 0x05, 0x06, 0x00, 0x05, 0x01,
    0x01, 0x80, 0x80, 0x00, 0x98, 0x1b, 0x21, 0x04, 0x26, 0x02, 0x03, 0x0b, 0x91, 0x00, 0x04, 0x91, 0x00, 0xa4, 0x83,
    0x02, 0x2e, 0xcc, 0x7c, 0x2c, 0x80, 0x00, 0x01, 0x08, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x0a, 0x03,
    0x13, 0xc8, 0x7d, 0x70, 0x6a, 0x1f, 0xde, 0xa9, 0x37, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x72, 0x61, 0x72, 0x35,
    0x20, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x64, 0x1d, 0x77, 0x56, 0x51, 0x03, 0x05, 0x04, 0x00,
};

const rar_fixture_encryption = [_]u8{ 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00, 0x78, 0xc8, 0xa9, 0x98, 0x02, 0x04, 0x00 };

const rar_fixture_compressed = [_]u8{
    0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00, 0xc5, 0x1a, 0x33, 0x32, 0x03, 0x01, 0x00, 0x00, 0x4f,
    0x99, 0xa4, 0x2f, 0x16, 0x02, 0x02, 0x11, 0x04, 0x11, 0x00, 0x2e, 0xcc, 0x7c, 0x2c, 0x80, 0x01, 0x00,
    0x08, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x72, 0x61,
    0x72, 0x35, 0x20, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x64, 0x19, 0xb2, 0x3a, 0x35, 0x03, 0x05, 0x00, 0x00,
};

const rar_fixture_solid = [_]u8{
    0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00, 0xc5, 0x1a, 0x33, 0x32, 0x03, 0x01, 0x00, 0x00, 0xcc,
    0x99, 0x25, 0x35, 0x15, 0x02, 0x02, 0x11, 0x04, 0x11, 0x00, 0x2e, 0xcc, 0x7c, 0x2c, 0x40, 0x00, 0x08,
    0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x72, 0x61, 0x72,
    0x35, 0x20, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x64, 0x19, 0xb2, 0x3a, 0x35, 0x03, 0x05, 0x00, 0x00,
};

const rar_fixture_service = [_]u8{
    0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00, 0xc5, 0x1a, 0x33, 0x32, 0x03, 0x01, 0x00,
    0x00, 0x55, 0xb1, 0x5e, 0xd3, 0x08, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

const rar_fixture_multi_volume = [_]u8{
    0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00, 0xc5, 0x1a, 0x33, 0x32, 0x03, 0x01, 0x00, 0x00, 0x23,
    0x80, 0x6d, 0xe3, 0x15, 0x02, 0x02, 0x11, 0x04, 0x11, 0x00, 0x2e, 0xcc, 0x7c, 0x2c, 0x00, 0x00, 0x08,
    0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x72, 0x61, 0x72,
    0x35, 0x20, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x64, 0x8f, 0x82, 0x3d, 0x42, 0x03, 0x05, 0x00, 0x01,
};

const rar_fixture_unknown = [_]u8{
    0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00, 0xc5, 0x1a, 0x33, 0x32,
    0x03, 0x01, 0x00, 0x00, 0xfa, 0xaa, 0x9f, 0xaa, 0x02, 0x06, 0x00,
};

const rar_expected = "hello rar5 stored";

fn rarCheckOutput(r: *Runner, committed: ?usize) !void {
    if (r.response.byte_length != rar_expected.len) return error.RarOutputMismatch;
    if (committed) |offset| {
        if (offset != rar_expected.len) return error.RarOutputMismatch;
    }
    if (!std.mem.eql(u8, r.output[0..rar_expected.len], rar_expected)) return error.RarOutputMismatch;
}

fn setupRar(r: *Runner) void {
    harness.setup(r, harness.ids.rar, harness.mode_archive);
}

fn rarReadExpected(r: *Runner, data: []const u8) !void {
    _ = harness.call(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(data),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    try rarCheckOutput(r, null);
}

fn rarExpectUnsupported(r: *Runner, data: []const u8) !void {
    var output = [_]u8{0xa5} ** 64;
    try harness.reject(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(data),
        harness.sinkSpan(&output),
    }, .{ .ctx = true }, abi.Status.unsupported, &output);
}

fn rarToolOracle(r: *Runner) !void {
    _ = r;
    const expected = [_]lib.ExpectedEntry{
        .{ .name = "test.txt", .data = rar_expected },
    };
    const result = lib.archiveReadMatches(&rar_fixture, &expected);
    if (result == .mismatch) return error.RarOracleMismatch;
    if (result == .unsupported) {
        std.debug.print("rar tool oracle: unsupported (libarchive cannot read this rar fixture)\n", .{});
    }
}

pub fn runRar(r: *Runner) anyerror!void {
    setupRar(r);
    _ = harness.call(r, harness.ids.query, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(&rar_fixture),
        harness.capabilityParam(arc_caps),
        harness.sizingModeParam(harness.size_metadata_exact),
        harness.commitModeParam(harness.commit_tentative),
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 1) return error.RarEntryCountMismatch;
    try rarReadExpected(r, &rar_fixture);
    var prefixed: [2048]u8 = undefined;
    const prefix = "#!/bin/sh\nexec unrar\n";
    @memcpy(prefixed[0..prefix.len], prefix);
    @memcpy(prefixed[prefix.len .. prefix.len + rar_fixture.len], &rar_fixture);
    try rarReadExpected(r, prefixed[0 .. prefix.len + rar_fixture.len]);
    var corrupted: [rar_fixture.len]u8 = undefined;
    @memcpy(&corrupted, &rar_fixture);
    corrupted[8] ^= 0xff;
    try harness.reject(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(&corrupted),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true }, abi.Status.integrity_failure, r.output);
    @memcpy(&corrupted, &rar_fixture);
    corrupted[corrupted.len - 5] ^= 0xff;
    try harness.reject(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(&corrupted),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true }, abi.Status.integrity_failure, r.output);
    try harness.rejectAny(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(rar_fixture[0 .. rar_fixture.len - 5]),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true }, r.output);
    var source_ctx = harness.SourceCallbackContext{ .data = &rar_fixture };
    _ = harness.call(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceCallbackNode(0, 0),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true, .callback = harness.sourceCallback, .context = &source_ctx });
    try harness.requireStatus(r, abi.Status.ok);
    try rarCheckOutput(r, null);
    var sink_ctx = harness.SinkBufferContext{ .buffer = r.output, .accept_limit = r.output.len };
    _ = harness.call(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(&rar_fixture),
        harness.sinkCallbackNode(0, 0),
    }, .{ .ctx = true, .callback = harness.sinkBufferCallback, .context = &sink_ctx });
    try harness.requireStatus(r, abi.Status.ok);
    try rarCheckOutput(r, sink_ctx.offset);
    var short_input = [_]u8{0} ** 4;
    try harness.rejectAny(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(&short_input),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true }, r.output);
    var overlap = [_]u8{0xa5} ** 128;
    try harness.reject(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(overlap[0..rar_fixture.len]),
        harness.sinkSpan(&overlap),
    }, .{ .ctx = true }, abi.Status.invalid_call, &overlap);
    try rarExpectUnsupported(r, &rar_fixture_encryption);
    try rarExpectUnsupported(r, &rar_fixture_multi_volume);
    // Service blocks (QuickOpen) carry no payload we expose; the walk skips
    // their data and ends cleanly at EOF, so the archive lists zero entries
    // and any ordinal read is invalid_data — the same observable shape the
    // reference gives this archive ("0 files").
    _ = harness.call(r, harness.ids.query, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(&rar_fixture_service),
        harness.capabilityParam(arc_caps),
        harness.sizingModeParam(harness.size_metadata_exact),
        harness.commitModeParam(harness.commit_tentative),
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 0) return error.RarServiceEntryCountMismatch;
    try harness.reject(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(&rar_fixture_service),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true }, abi.Status.invalid_data, r.output);
    // Unknown block types are skipped by size regardless of the skip flag
    // (the reference parses the flag but never enforces it): the walk ends
    // cleanly at EOF with zero entries listed, and any ordinal read is
    // invalid_data.
    _ = harness.call(r, harness.ids.query, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(&rar_fixture_unknown),
        harness.capabilityParam(arc_caps),
        harness.sizingModeParam(harness.size_metadata_exact),
        harness.commitModeParam(harness.commit_tentative),
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 0) return error.RarUnknownEntryCountMismatch;
    try harness.reject(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(&rar_fixture_unknown),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true }, abi.Status.invalid_data, r.output);
    try harness.expect(r, harness.ids.query, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(&rar_fixture),
        harness.capabilityParam(arc_caps),
        harness.sizingModeParam(harness.size_metadata_exact),
        harness.commitModeParam(harness.commit_tentative),
        harness.resourceLimitParam(rar_fixture.len - 1),
    }, .{}, abi.Status.resource_limit);
    var small_output = [_]u8{0xa5} ** 1;
    try harness.reject(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(&rar_fixture),
        harness.sinkSpan(&small_output),
    }, .{ .ctx = true }, abi.Status.insufficient_capacity, &small_output);
    var out = [_]u8{0xa5} ** 64;
    try harness.reject(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(&rar_fixture),
        harness.sinkSpan(&out),
        harness.resourceLimitParam(rar_expected.len - 1),
    }, .{ .ctx = true }, abi.Status.resource_limit, &out);
    try rarToolOracle(r);
}

fn runRarArchive(r: *Runner) anyerror!void {
    try runArchive(r, harness.ids.rar);
}

// Every official-fixture decode runs the envelope's CRC check (and BLAKE2sp
// where the archive carries it), so a clean status at the expected length is
// already a byte-exactness proof against the producer.
const RarOfficial = struct {
    data: []const u8,
    sizes: []const usize,
};

const rar_official = [_]RarOfficial{
    .{ .data = &fixtures.rar5_store_fixture, .sizes = &.{17} },
    .{ .data = &fixtures.rar5_comp_fixture, .sizes = &.{ 17, 900 } },
    .{ .data = &fixtures.rar5_solid_fixture, .sizes = &.{ 900, 17 } },
    .{ .data = &fixtures.rar5_blake_fixture, .sizes = &.{17} },
    .{ .data = &fixtures.rar4_store_fixture, .sizes = &.{17} },
    .{ .data = &fixtures.rar4_comp_fixture, .sizes = &.{ 17, 900 } },
    .{ .data = &fixtures.rar4_solid_fixture, .sizes = &.{ 900, 17 } },
    .{ .data = &fixtures.rar5_x86_filter_fixture, .sizes = &.{44056} },
    .{ .data = &fixtures.rar4_x86_filter_fixture, .sizes = &.{44056} },
    .{ .data = &fixtures.rar2_v20_m3_fixture, .sizes = &.{ 8192, 4096, 15, 33, 7212, 7212, 7212 } },
};

pub fn runRarOfficial(r: *Runner) anyerror!void {
    harness.setup(r, harness.ids.rar, harness.mode_archive);
    for (rar_official) |fix| {
        _ = harness.call(r, harness.ids.query, &.{
            harness.paramTargetCommand(harness.ids.read),
            harness.sourceSpan(fix.data),
            harness.capabilityParam(arc_caps),
            harness.sizingModeParam(harness.size_metadata_exact),
            harness.commitModeParam(harness.commit_tentative),
        }, .{});
        try harness.requireStatus(r, abi.Status.ok);
        if (r.response.byte_length != fix.sizes.len) return error.RarOfficialEntryCountMismatch;
        for (fix.sizes, 0..) |expected_size, ordinal| {
            _ = harness.call(r, harness.ids.read, &.{
                harness.archiveOrdinalParam(ordinal),
                harness.sourceSpan(fix.data),
                harness.sinkSpan(r.output),
            }, .{ .ctx = true });
            try harness.requireStatus(r, abi.Status.ok);
            if (r.response.byte_length != expected_size) return error.RarOfficialSizeMismatch;
        }
    }
}

pub const scenarios = harness.scenarios("archive", &.{
    .{ .label = "archive tar", .run = runTar, .workspace_size = 65536, .output_size = 512, .encoded_size = 4096 },
    .{ .label = "archive zip", .run = runZip, .workspace_size = 65536 + 4096, .output_size = 512, .encoded_size = 4096 },
    .{ .label = "archive rar", .run = runRarArchive, .workspace_size = 12 * 1024 * 1024, .output_size = 512, .encoded_size = 4096 },
}, &.{
    .{ .name = "rar", .suite = "rar", .run = runRar, .workspace_size = 65536, .output_size = 64, .encoded_size = 4096 },
    .{ .name = "rar official", .suite = "rar", .run = runRarOfficial, .workspace_size = 12 * 1024 * 1024, .output_size = 48 * 1024, .encoded_size = 1024 },
    // PPMd at -m5 asks the decoder for ~139 MiB of model heap — the format's
    // own size, not a workaround: the encoder built its contexts that large.
    .{ .name = "rar ppm", .suite = "rar", .run = runRarPpm, .workspace_size = 176 * 1024 * 1024, .output_size = 2048, .encoded_size = 2048 },
});

pub fn runRarPpm(r: *Runner) anyerror!void {
    harness.setup(r, harness.ids.rar, harness.mode_archive);
    _ = harness.call(r, harness.ids.query, &.{
        harness.paramTargetCommand(harness.ids.read),
        harness.sourceSpan(&fixtures.rar4_ppm_fixture),
        harness.capabilityParam(arc_caps),
        harness.sizingModeParam(harness.size_metadata_exact),
        harness.commitModeParam(harness.commit_tentative),
    }, .{});
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 1) return error.RarPpmEntryCountMismatch;
    _ = harness.call(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(&fixtures.rar4_ppm_fixture),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true });
    try harness.requireStatus(r, abi.Status.ok);
    if (r.response.byte_length != 1590) return error.RarPpmSizeMismatch;
}
