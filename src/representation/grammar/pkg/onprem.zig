const std = @import("std");

const entry_prim = @import("../../../common/entry.zig");
const bounds = @import("../../../common/primitive/bounds.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const session = @import("../../../common/session.zig");
const cpio = @import("../cpio/onprem.zig");
const gzip = @import("../gzip/onprem.zig");
const xar = @import("../xar/onprem.zig");
const xz = @import("../xz/onprem.zig");
const payload = @import("payload.zig");

pub const Entry = entry_prim.Entry;
const Exception = exception_prim.Exception;

// A XAR shell whose Payload member holds gzip, xz, or stored
// bytes over a cpio archive.

const member_name = "Payload";

// The read side is one session chain: XAR locates the payload,
// the transform decodes, cpio walks records.
const Chain = session.Nested(xar.Outer, payload.Payload, cpio.Inner);

pub const scratch_size: usize = Chain.scratch_size;

// The compression the writer emits; the reader sniffs on its own.
pub const Compression = enum { gzip, xz, stored };

// The xz dictionary the writer uses; the reader budgets for a larger
// one, so the round trip holds.
const write_dictionary: u32 = 1 << 20;
const xz_write_workspace: usize = blk: {
    @setEvalBranchQuota(1_000_000);
    break :blk xz.encodeWorkspaceSizeBt(write_dictionary);
};

// The gzip options make the writer deterministic: no time stamp, no
// name, and a fixed deflate effort.
const gzip_write_options: gzip.Options = .{
    .modification_time = 0,
    .extra_flags = 0,
    .operating_system = 255,
    .text = false,
    .header_crc = false,
    .extra = &.{},
    .name = &.{},
    .comment = &.{},
    .deflate = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 8 },
};

const xz_write_options: xz.Options = .{
    .dictionary_size = write_dictionary,
    .check = .crc64,
};

// The records walk comes from the shared cpio-chain walker; the chain is
// the only per-format input.
const records_walker = @import("../cpio/chain.zig").Walker(Chain, member_name);

pub const EntryInfo = records_walker.EntryInfo;
pub const LinkMode = records_walker.LinkMode;
pub const Link = records_walker.Link;
pub const Cursor = records_walker.Cursor;
pub const inspectCount = records_walker.inspectCount;
pub const inspectOrdinal = records_walker.inspectOrdinal;
pub const decodeOrdinal = records_walker.decodeOrdinal;

// The write scratch: cpio bytes, compressor machinery, the
// compressed bound, and the XAR staging area.
pub fn writeScratchSize(content_len: usize, compression: Compression) usize {
    return content_len +| machinerySize(compression) +| payloadBound(compression, content_len) +| xar.scratch_size;
}

fn machinerySize(compression: Compression) usize {
    return switch (compression) {
        .gzip => gzip.deflate_history_size,
        .xz => xz_write_workspace,
        .stored => 0,
    };
}

fn payloadBound(compression: Compression, content_len: usize) usize {
    return switch (compression) {
        .gzip => gzip.encodedSizeBound(content_len, gzip_write_options),
        .xz => xz.encodedSizeBound(content_len, 0),
        .stored => content_len,
    };
}

const WritePlan = struct {
    // The payload member bytes, ready for the XAR shell.
    payload: []const u8,
    // The staging area the XAR writer needs.
    xar_area: []u8,
};

// Both sizes run the same pipeline; a second run produces the
// same bytes, so a measured size replays exactly.
fn runPipeline(entries: []const Entry, scratch: []u8, compression: Compression) Exception!WritePlan {
    const content_len = std.math.cast(usize, try cpio.archiveSize(entries)) orelse return error.ResourceException;
    if (scratch.len < writeScratchSize(content_len, compression)) return error.ResourceException;

    const content_area = scratch[0..content_len];
    const machinery_at = content_len;
    const machinery = machinerySize(compression);
    const payload_at = machinery_at + machinery;
    const bound = payloadBound(compression, content_len);
    const xar_at = payload_at + bound;
    const xar_area = scratch[xar_at..][0..xar.scratch_size];

    const encoded_len = try cpio.encode(entries, content_area);
    if (encoded_len != content_len) return error.InternalException;

    switch (compression) {
        .stored => return .{ .payload = content_area, .xar_area = xar_area },
        .gzip => {
            var source = std.Io.Reader.fixed(content_area);
            var sink = std.Io.Writer.fixed(scratch[payload_at..][0..bound]);
            try gzip.encodeStream(&source, &sink, scratch[machinery_at..][0..machinery], gzip_write_options);
            return .{ .payload = scratch[payload_at..][0..sink.end], .xar_area = xar_area };
        },
        .xz => {
            const written = try xz.encode(content_area, scratch[payload_at..][0..bound], scratch[machinery_at..][0..machinery], xz_write_options);
            return .{ .payload = scratch[payload_at..][0..written], .xar_area = xar_area };
        },
    }
}

// The shell holds one member; the heap offset is the writer's layout.
fn shellEntries(plan: WritePlan) [1]xar.Entry {
    return .{.{ .name = member_name, .data = plan.payload }};
}

pub fn archiveSize(entries: []const Entry, scratch: []u8, compression: Compression) Exception!u64 {
    const plan = try runPipeline(entries, scratch, compression);
    const shell = shellEntries(plan);
    return xar.archiveSize(&shell, plan.xar_area);
}

pub fn encode(entries: []const Entry, output: []u8, scratch: []u8, compression: Compression) Exception!usize {
    const plan = try runPipeline(entries, scratch, compression);
    const shell = shellEntries(plan);
    const written = try xar.encode(&shell, output, plan.xar_area);
    if (written != try xar.archiveSize(&shell, plan.xar_area)) return error.InternalException;
    return written;
}

fn roundTrip(compression: Compression) !void {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "dir/first.bin", .data = "first payload", .uid = 501, .modification_time = 1700000000 },
        .{ .name = "dir/second.txt", .data = "second payload", .mode = 0o755 },
    };
    const content_len: usize = @intCast(try cpio.archiveSize(&entries));
    const scratch = try testing.allocator.alloc(u8, writeScratchSize(content_len, compression));
    defer testing.allocator.free(scratch);
    var output: [64 * 1024]u8 = undefined;
    const written = try encode(&entries, &output, scratch, compression);

    // A measured size replays exactly, and the shell opens with the
    // XAR magic.
    try testing.expectEqual(try archiveSize(&entries, scratch, compression), written);
    try testing.expectEqualSlices(u8, "xar!", output[0..4]);

    const read_scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(read_scratch);
    try testing.expectEqual(@as(u64, 2), try inspectCount(output[0..written], read_scratch));
    const first = try inspectOrdinal(output[0..written], 0, read_scratch);
    try testing.expectEqualSlices(u8, "dir/first.bin", first.name);
    try testing.expectEqual(@as(u64, 13), first.size);
    try testing.expectEqual(@as(u32, 501), first.uid);
    try testing.expectEqual(@as(u64, 1700000000), first.modification_time);
    var decoded: [32]u8 = undefined;
    const size = try decodeOrdinal(output[0..written], 0, &decoded, read_scratch);
    try testing.expectEqualSlices(u8, "first payload", decoded[0..size]);
    const second = try decodeOrdinal(output[0..written], 1, &decoded, read_scratch);
    try testing.expectEqualSlices(u8, "second payload", decoded[0..second]);

    // A full walk serves the records through the trailer; the closing
    // 512-alignment padding stays unserved because the trailer ends it.
    var walker = try Cursor.init(output[0..written], read_scratch);
    while (try walker.next()) |info| {
        if (info.ordinal == 1) try walker.readData(decoded[0..info.size]);
    }
    try testing.expect(walker.decodedBytes() > 0);
    try testing.expect(walker.decodedBytes() <= content_len);
    const chunk_ceiling: u64 = switch (compression) {
        .stored => 0,
        else => 1,
    };
    try testing.expect(walker.decodedChunks() <= chunk_ceiling);
}

test "pkg roundtrips entries through a stored payload" {
    try roundTrip(.stored);
}

test "pkg roundtrips entries through a gzip payload" {
    try roundTrip(.gzip);
}

test "pkg roundtrips entries through an xz payload" {
    try roundTrip(.xz);
}

test "pkg reads only the payload of a multi-member shell" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "a.txt", .data = "alpha" },
        .{ .name = "b.txt", .data = "beta" },
    };
    var content: [4096]u8 = undefined;
    const content_len = try cpio.encode(&entries, &content);
    const shell = [_]xar.Entry{
        .{ .name = "Bom", .data = "bom" },
        .{ .name = "PackageInfo", .data = "info" },
        .{ .name = "Payload", .data = content[0..content_len] },
        .{ .name = "Scripts", .data = "scripts" },
    };
    var output: [32 * 1024]u8 = undefined;
    const xar_scratch = try testing.allocator.alloc(u8, xar.scratch_size);
    defer testing.allocator.free(xar_scratch);
    const written = try xar.encode(&shell, &output, xar_scratch);
    const read_scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(read_scratch);

    try testing.expectEqual(@as(u64, 2), try inspectCount(output[0..written], read_scratch));
    const second = try inspectOrdinal(output[0..written], 1, read_scratch);
    try testing.expectEqualSlices(u8, "b.txt", second.name);
    var decoded: [8]u8 = undefined;
    const size = try decodeOrdinal(output[0..written], 1, &decoded, read_scratch);
    try testing.expectEqualSlices(u8, "beta", decoded[0..size]);
}

test "pkg rejects a shell without a payload member" {
    const testing = std.testing;
    const shell = [_]xar.Entry{.{ .name = "Content", .data = "not a payload" }};
    var output: [4096]u8 = undefined;
    const xar_scratch = try testing.allocator.alloc(u8, xar.scratch_size);
    defer testing.allocator.free(xar_scratch);
    const written = try xar.encode(&shell, &output, xar_scratch);
    const read_scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(read_scratch);
    try testing.expectError(error.DataException, inspectCount(output[0..written], read_scratch));
}

test "pkg rejects an unknown payload format" {
    const testing = std.testing;
    const shell = [_]xar.Entry{.{ .name = "Payload", .data = "plainly neither gzip nor xz" }};
    var output: [4096]u8 = undefined;
    const xar_scratch = try testing.allocator.alloc(u8, xar.scratch_size);
    defer testing.allocator.free(xar_scratch);
    const written = try xar.encode(&shell, &output, xar_scratch);
    const read_scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(read_scratch);
    try testing.expectError(error.DataException, inspectCount(output[0..written], read_scratch));
}

test "pkg rejects a truncated payload" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "one", .data = "one" },
        .{ .name = "two", .data = "two" },
    };
    const content_len: usize = @intCast(try cpio.archiveSize(&entries));
    const scratch = try testing.allocator.alloc(u8, writeScratchSize(content_len, .gzip));
    defer testing.allocator.free(scratch);
    var output: [64 * 1024]u8 = undefined;
    const written = try encode(&entries, &output, scratch, .gzip);
    const read_scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(read_scratch);

    // The TOC states the member length, so a cut inside the payload is
    // caught before the cpio layer reads it.
    try testing.expectError(error.DataException, inspectCount(output[0 .. written - 1], read_scratch));
    try testing.expectError(error.DataException, inspectCount(output[0 .. written - 16], read_scratch));
    // The intact archive still reads.
    try testing.expectEqual(@as(u64, 2), try inspectCount(output[0..written], read_scratch));
}

test "pkg reports ino and nlink and folds groups only on request" {
    const testing = std.testing;
    // One group with payloads that disagree: folding rewrites the stream.
    const entries = [_]Entry{
        .{ .name = "group/first.bin", .data = "first", .ino = 7, .nlink = 2 },
        .{ .name = "group/second.bin", .data = "second", .ino = 7, .nlink = 2 },
    };
    const content_len: usize = @intCast(try cpio.archiveSize(&entries));
    const scratch = try testing.allocator.alloc(u8, writeScratchSize(content_len, .stored));
    defer testing.allocator.free(scratch);
    var output: [64 * 1024]u8 = undefined;
    const written = try encode(&entries, &output, scratch, .stored);
    const read_scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(read_scratch);

    var flat = try Cursor.init(output[0..written], read_scratch);
    var seen: usize = 0;
    var data: [8]u8 = undefined;
    while (try flat.next()) |info| {
        seen += 1;
        try testing.expectEqual(@as(u32, 7), info.ino);
        try testing.expectEqual(@as(u32, 2), info.nlink);
        try testing.expect(info.link_ordinal == null);
        try flat.readData(data[0..info.size]);
        try testing.expectEqualSlices(u8, if (info.ordinal == 0) "first" else "second", data[0..info.size]);
    }
    try testing.expectEqual(@as(usize, 2), seen);

    var links: [4]Link = undefined;
    var folded = try Cursor.initWithLinks(output[0..written], read_scratch, .collapse, &links);
    const owner = try folded.next() orelse return error.UnexpectedEnd;
    try testing.expect(owner.link_ordinal == null);
    const duplicate = try folded.next() orelse return error.UnexpectedEnd;
    try testing.expectEqual(@as(u64, 0), duplicate.link_ordinal.?);
    // Its payload was dropped with the fold, so a read is a caller error.
    try testing.expectError(error.CallException, folded.readData(data[0..duplicate.size]));
    try testing.expect(try folded.next() == null);

    // A table that is not a power of two cannot serve as the group index.
    try testing.expectError(error.CallException, Cursor.initWithLinks(output[0..written], read_scratch, .collapse, links[0..3]));
}

test "pkg opens only with a full scratch budget" {
    const testing = std.testing;
    const entries = [_]Entry{.{ .name = "a.txt", .data = "data" }};
    const content_len: usize = @intCast(try cpio.archiveSize(&entries));
    const scratch = try testing.allocator.alloc(u8, writeScratchSize(content_len, .gzip));
    defer testing.allocator.free(scratch);
    var output: [64 * 1024]u8 = undefined;
    const written = try encode(&entries, &output, scratch, .gzip);
    const read_scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(read_scratch);

    // One byte short is a capacity failure, never a data error.
    try testing.expectError(error.CapacityException, Cursor.init(output[0..written], read_scratch[0 .. read_scratch.len - 1]));
    try testing.expectError(error.CapacityException, inspectCount(output[0..written], read_scratch[0 .. read_scratch.len - 1]));

    // The write side states its own budget the same way.
    const need = writeScratchSize(content_len, .gzip);
    try testing.expectError(error.ResourceException, encode(&entries, &output, scratch[0 .. need - 1], .gzip));
    try testing.expectError(error.ResourceException, archiveSize(&entries, scratch[0 .. need - 1], .gzip));
}

test "pkg ends cleanly at the trailer" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "one", .data = "one" },
        .{ .name = "two", .data = "two" },
    };
    const content_len: usize = @intCast(try cpio.archiveSize(&entries));
    const scratch = try testing.allocator.alloc(u8, writeScratchSize(content_len, .xz));
    defer testing.allocator.free(scratch);
    var output: [64 * 1024]u8 = undefined;
    const written = try encode(&entries, &output, scratch, .xz);
    const read_scratch = try testing.allocator.alloc(u8, scratch_size);
    defer testing.allocator.free(read_scratch);

    var cursor = try Cursor.init(output[0..written], read_scratch);
    try testing.expect((try cursor.next()) != null);
    try testing.expect((try cursor.next()) != null);
    // The trailer ends the walk, and the call after stays ended.
    try testing.expect((try cursor.next()) == null);
    try testing.expect((try cursor.next()) == null);
    try testing.expect(cursor.decodedBytes() > 0);
    try testing.expect(cursor.decodedBytes() <= content_len);
}
