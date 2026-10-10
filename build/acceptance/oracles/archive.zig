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
    var output: [64]u8 = @splat(0xa5);
    try harness.reject(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(data),
        harness.sinkSpan(&output),
    }, .{ .ctx = true }, abi.Status.unsupported, &output);
}

const rar5_p_fixture = [_]u8{
    0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00, 0x33, 0x92, 0xb5, 0xe5, 0x0a, 0x01, 0x05, 0x06,
    0x00, 0x05, 0x01, 0x01, 0x80, 0x80, 0x00, 0xd4, 0x86, 0x25, 0x69, 0x57, 0x02, 0x03, 0x3c, 0xd0,
    0x00, 0x04, 0xbd, 0x00, 0xa4, 0x83, 0x02, 0xde, 0x6f, 0x48, 0xc8, 0x80, 0x03, 0x01, 0x08, 0x74,
    0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x30, 0x01, 0x00, 0x03, 0x0f, 0x19, 0xc7, 0x2c, 0xe0,
    0x29, 0x11, 0xce, 0x34, 0x2f, 0xfc, 0x96, 0x28, 0x2c, 0x1c, 0x31, 0x6a, 0x0e, 0x1e, 0x69, 0x0c,
    0xe3, 0x1b, 0x91, 0xc9, 0xdc, 0x35, 0x2d, 0xa4, 0x08, 0x79, 0x1c, 0x61, 0xb7, 0x5c, 0x2f, 0x2a,
    0x68, 0x19, 0x57, 0x0e, 0x97, 0x37, 0x67, 0x36, 0x0a, 0x03, 0x13, 0x9f, 0xd9, 0xc1, 0x6a, 0x57,
    0xb4, 0xf9, 0x03, 0xf1, 0x72, 0x3a, 0xb8, 0x2e, 0x12, 0x48, 0x43, 0xaa, 0x9d, 0x05, 0x65, 0xaf,
    0x7f, 0x8b, 0xaf, 0x81, 0x3b, 0xfa, 0x1b, 0x93, 0x03, 0xde, 0x8d, 0x0e, 0x86, 0x66, 0xd0, 0x1b,
    0xe5, 0xc8, 0x22, 0x8d, 0x88, 0xeb, 0x6f, 0x6c, 0xa8, 0xb8, 0xd6, 0xe7, 0xf7, 0xe2, 0x22, 0xf5,
    0x50, 0x69, 0x66, 0xee, 0x07, 0xc5, 0xfd, 0x58, 0x5d, 0x09, 0x7c, 0x66, 0x8e, 0xa7, 0x68, 0x87,
    0x45, 0xe3, 0xf6, 0xf0, 0x9a, 0x2a, 0xf0, 0x76, 0x74, 0x05, 0xde, 0x00, 0xd9, 0x19, 0x6c, 0xbf,
    0x06, 0x38, 0x69, 0x1d, 0x77, 0x56, 0x51, 0x03, 0x05, 0x04, 0x00,
};

const rar5_hp_fixture = [_]u8{
    0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00, 0xb5, 0xd4, 0xc4, 0x20, 0x21, 0x04, 0x00, 0x00,
    0x01, 0x0f, 0x26, 0x95, 0x68, 0x25, 0xf0, 0x3e, 0x15, 0xa1, 0x92, 0xf9, 0x2e, 0xcc, 0xc5, 0xd2,
    0x6a, 0xe1, 0xcb, 0x3a, 0xe5, 0x35, 0x22, 0x16, 0x9a, 0x90, 0x93, 0xf7, 0x38, 0x0e, 0x0f, 0x66,
    0x2c, 0xb2, 0x1a, 0x80, 0x23, 0x6f, 0x8e, 0x8e, 0xcd, 0xcf, 0x8d, 0xee, 0xbc, 0x22, 0xff, 0x9d,
    0x94, 0x45, 0xcb, 0x1c, 0x1f, 0xd4, 0x91, 0x3f, 0xae, 0x46, 0x99, 0x99, 0x07, 0xcd, 0x08, 0x9c,
    0x1e, 0x31, 0x92, 0x63, 0x27, 0x81, 0x2b, 0xc8, 0x1c, 0x6c, 0x58, 0x1c, 0x3d, 0x05, 0xa0, 0xc4,
    0x87, 0xb7, 0xfd, 0x7c, 0x0c, 0xa7, 0xb3, 0x3b, 0x83, 0x13, 0xca, 0x04, 0x97, 0x94, 0x8f, 0x67,
    0x6e, 0xf3, 0xbc, 0x60, 0xb4, 0xd5, 0x2b, 0x33, 0x3d, 0x5d, 0x3b, 0x43, 0x09, 0x8b, 0x7c, 0xc3,
    0x2c, 0x55, 0xea, 0xb8, 0xab, 0x50, 0x47, 0xf4, 0x1a, 0x02, 0xa5, 0xa2, 0x13, 0xb6, 0xb7, 0x7e,
    0x44, 0x86, 0x24, 0x1d, 0x3c, 0x0e, 0x4c, 0xcf, 0x97, 0x36, 0xb8, 0x2b, 0x95, 0x4a, 0x83, 0x0b,
    0x83, 0x33, 0xe5, 0xef, 0xf1, 0x38, 0x3a, 0x78, 0x0d, 0x8e, 0x3a, 0x1b, 0x5f, 0x6c, 0xa8, 0x9d,
    0xff, 0x69, 0xf8, 0x58, 0x7e, 0xf3, 0x0a, 0x4a, 0x84, 0x08, 0xcc, 0x99, 0xfb, 0xd9, 0xc3, 0x77,
    0xe7, 0xba, 0x80, 0x67, 0x8a, 0xb3, 0x45, 0x8d, 0x9b, 0x35, 0x11, 0x50, 0xd8, 0x36, 0x1a, 0xb3,
    0xcd, 0x69, 0x2f, 0x89, 0x7a, 0xae, 0xd2, 0x13, 0x20, 0x6f, 0x8a, 0xab, 0x73, 0x9d, 0x05, 0xc3,
    0xf6, 0x18, 0xf8, 0xda, 0x49, 0x1f, 0xd7, 0xfd, 0x1e, 0x42, 0xb3, 0x76, 0xa5, 0xd3, 0x90, 0x5f,
    0xa0, 0x92, 0xb9, 0x45, 0x28, 0x92, 0xbf, 0x52, 0x2d, 0x90, 0x11, 0xb0, 0x7a, 0xd5, 0xcd, 0x72,
    0x61, 0xe0, 0xb2, 0x67, 0x7a, 0xcd, 0xd8, 0xf2, 0x1c, 0x15, 0xc6, 0xb9, 0x29, 0xc1, 0x37, 0xd7,
    0xd8, 0x12, 0x26, 0xf2, 0xa2, 0x14, 0xad, 0x27, 0x4f, 0x4b, 0x9a, 0x4f, 0x1c, 0x18, 0x64, 0xe6,
    0xdb, 0x9c, 0xc7, 0x4c, 0xae, 0x66, 0x60, 0x4f, 0x48, 0x1e, 0xb9, 0x8d, 0x88, 0x08,
};

const rar4_p_fixture = [_]u8{
    0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00, 0xcf, 0x90, 0x73, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xb2, 0xed, 0x74, 0x04, 0x84, 0x30, 0x00, 0x40, 0x00, 0x00, 0x00, 0x3d,
    0x00, 0x00, 0x00, 0x03, 0x5e, 0xa4, 0x11, 0x68, 0x00, 0x00, 0x00, 0x60, 0x1d, 0x30, 0x08, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74, 0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88, 0xf2, 0x0c, 0x07, 0xa7, 0x89, 0xa4, 0x20, 0xb7, 0x60, 0x98, 0xfd, 0x32,
    0x65, 0x49, 0x5e, 0x43, 0xc2, 0x9f, 0xf1, 0x25, 0xe8, 0x92, 0x4f, 0xe3, 0x90, 0xb6, 0x1e, 0xc7,
    0x5b, 0xf0, 0x59, 0x64, 0xa4, 0xb0, 0xad, 0x2c, 0x0d, 0x92, 0x47, 0x51, 0x75, 0x53, 0x51, 0x1f,
    0xec, 0xa1, 0x76, 0x21, 0x68, 0x17, 0x1b, 0x61, 0x0d, 0xcb, 0x3d, 0x19, 0xd2, 0xba, 0xb1, 0xb0,
    0x4e, 0x0c, 0x2a, 0xcd,
};

const rar4_hp_fixture = [_]u8{
    0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00, 0xce, 0x99, 0x73, 0x80, 0x00, 0x0d, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf0, 0x01, 0x02, 0x51, 0xd3, 0xb5, 0x46,
    0xf7, 0x62, 0xac, 0x34, 0x7b, 0xbf, 0x88, 0xb8, 0x55, 0x91, 0x67, 0x4b, 0xcd, 0x85, 0xa0, 0xb6,
    0x18, 0x8a, 0x7a, 0x9b, 0x02, 0x35, 0x44, 0x65, 0x9d, 0xad, 0xdb, 0xdd, 0x12, 0xe3, 0x65, 0x33,
    0x6c, 0xc1, 0x80, 0x43, 0x23, 0x51, 0x91, 0xfe, 0x7b, 0x97, 0xe4, 0xa2, 0xf2, 0x0c, 0x07, 0xa7,
    0x89, 0xa4, 0x20, 0xb7, 0x60, 0x98, 0xfd, 0x32, 0x65, 0x49, 0x5e, 0x43, 0xc2, 0x9f, 0xf1, 0x25,
    0xe8, 0x92, 0x4f, 0xe3, 0x90, 0xb6, 0x1e, 0xc7, 0x5b, 0xf0, 0x59, 0x64, 0xa4, 0xb0, 0xad, 0x2c,
    0x0d, 0x92, 0x47, 0x51, 0x75, 0x53, 0x51, 0x1f, 0xec, 0xa1, 0x76, 0x21, 0x68, 0x17, 0x1b, 0x61,
    0x0d, 0xcb, 0x3d, 0x19, 0xd2, 0xba, 0xb1, 0xb0, 0x4e, 0x0c, 0x2a, 0xcd,
};

const rar_encrypted_expected = "hello rar encrypted world. this entry is password protected.\n";

fn runRarEncryptedProvider(r: *Runner) anyerror!void {
    if (!harness.offprem_servable) return;
    setupRar(r);
    const encrypted_fixtures = [_]struct { bytes: []const u8, header_password: bool }{
        .{ .bytes = &rar5_p_fixture, .header_password = false },
        .{ .bytes = &rar5_hp_fixture, .header_password = true },
        .{ .bytes = &rar4_p_fixture, .header_password = false },
        .{ .bytes = &rar4_hp_fixture, .header_password = true },
    };
    for (encrypted_fixtures) |fixture| {
        _ = harness.call(r, harness.ids.read, &.{
            harness.archiveOrdinalParam(0),
            harness.sourceSpan(fixture.bytes),
            harness.sinkSpan(r.output),
            harness.cryptoProfile(),
            harness.cryptoPasswordParam("PASS"),
            harness.providerParam(1),
        }, .{ .ctx = true });
        try harness.requireStatus(r, abi.Status.ok);
        const produced = r.response.byte_length;
        if (produced != rar_encrypted_expected.len) return error.RarEncryptedSizeMismatch;
        if (!std.mem.eql(u8, r.output[0..produced], rar_encrypted_expected)) return error.RarEncryptedMismatch;
    }
}

fn runRarEncrypted(r: *Runner) anyerror!void {
    setupRar(r);
    const encrypted_fixtures = [_]struct { bytes: []const u8, header_password: bool }{
        .{ .bytes = &rar5_p_fixture, .header_password = false },
        .{ .bytes = &rar5_hp_fixture, .header_password = true },
        .{ .bytes = &rar4_p_fixture, .header_password = false },
        .{ .bytes = &rar4_hp_fixture, .header_password = true },
    };
    for (encrypted_fixtures) |fixture| {
        _ = harness.call(r, harness.ids.read, &.{
            harness.archiveOrdinalParam(0),
            harness.sourceSpan(fixture.bytes),
            harness.sinkSpan(r.output),
            harness.cryptoProfile(),
            harness.cryptoPasswordParam("PASS"),
        }, .{ .ctx = true });
        try harness.requireStatus(r, abi.Status.ok);
        const produced = r.response.byte_length;
        if (produced != rar_encrypted_expected.len) return error.RarEncryptedSizeMismatch;
        if (!std.mem.eql(u8, r.output[0..produced], rar_encrypted_expected)) return error.RarEncryptedMismatch;
        // A wrong password must fail (integrity or invalid data). RAR reads
        // are tentative-commit, so a late CRC failure may leave decoded
        // garbage in the sink; only the failure itself is asserted here.
        _ = harness.call(r, harness.ids.read, &.{
            harness.archiveOrdinalParam(0),
            harness.sourceSpan(fixture.bytes),
            harness.sinkSpan(r.output),
            harness.cryptoProfile(),
            harness.cryptoPasswordParam("WRONG"),
        }, .{ .ctx = true });
        if (r.status == abi.Status.ok) return error.WrongPasswordAccepted;
        // Header-encrypted archives refuse to walk without a password,
        // before any byte is written.
        if (fixture.header_password) {
            try harness.reject(r, harness.ids.read, &.{
                harness.archiveOrdinalParam(0),
                harness.sourceSpan(fixture.bytes),
                harness.sinkSpan(r.output),
            }, .{ .ctx = true }, abi.Status.unsupported, r.output);
        }
    }
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
    var short_input: [4]u8 = @splat(0);
    try harness.rejectAny(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(&short_input),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true }, r.output);
    var overlap: [128]u8 = @splat(0xa5);
    try harness.reject(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(overlap[0..rar_fixture.len]),
        harness.sinkSpan(&overlap),
    }, .{ .ctx = true }, abi.Status.invalid_call, &overlap);
    // A truncated encryption header is rejected as invalid data (the crypt
    // record no longer short-circuits to unsupported).
    try harness.rejectAny(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(&rar_fixture_encryption),
        harness.sinkSpan(r.output),
    }, .{ .ctx = true }, r.output);
    try rarExpectUnsupported(r, &rar_fixture_multi_volume);
    // Service blocks (QuickOpen) carry no payload we expose. The walk skips
    // their data and ends cleanly at EOF, so the archive lists zero entries
    // and any ordinal read is invalid_data, the same observable shape the
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
    var small_output: [1]u8 = @splat(0xa5);
    try harness.reject(r, harness.ids.read, &.{
        harness.archiveOrdinalParam(0),
        harness.sourceSpan(&rar_fixture),
        harness.sinkSpan(&small_output),
    }, .{ .ctx = true }, abi.Status.insufficient_capacity, &small_output);
    var out: [64]u8 = @splat(0xa5);
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
    .{ .name = "rar encrypted", .suite = "rar", .run = runRarEncrypted, .workspace_size = 32 * 1024 * 1024, .output_size = 1024, .encoded_size = 1024 },
    .{ .name = "rar encrypted provider", .suite = "rar", .run = runRarEncryptedProvider, .workspace_size = 32 * 1024 * 1024, .output_size = 1024, .encoded_size = 1024 },
    // PPMd at -m5 asks the decoder for ~139 MiB of model heap, the format's
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
