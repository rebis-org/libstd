const std = @import("std");

const onprem = @import("onprem.zig");
pub const Failure = @import("../../common/primitive/failure.zig").Failure;

const std_tar = std.tar;
// std's Iterator.File lacks mtime/uid/gid/typeflag, so inspectOrdinal stays
// onprem; encode serves only what std.tar.Writer carries faithfully.
pub const Entry = onprem.Entry;
pub const EntryInfo = onprem.EntryInfo;

fn mapError(err: anyerror) Failure {
    return switch (err) {
        error.UnexpectedEndOfStream, error.TarInsufficientBuffer => error.DataFailure,
        error.NameTooLong => error.UnsupportedFailure,
        error.WriteFailed => error.CapacityFailure,
        error.OctalOverflow => error.UnsupportedFailure,
        else => error.DataFailure,
    };
}

// std.tar.Iterator borrows caller-owned name buffers (its Options demand
// them); the decode surface takes no scratch, so the fs path cap on the
// stack is the documented shape, matching std's own expectation.
pub fn inspectCount(archive: []const u8) Failure!u64 {
    var reader = std.Io.Reader.fixed(archive);
    var name_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var link_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var it = std_tar.Iterator.init(&reader, .{ .file_name_buffer = &name_buffer, .link_name_buffer = &link_buffer });
    var count: u64 = 0;
    while (true) {
        const maybe = it.next() catch |err| return mapError(err);
        if (maybe == null) break;
        count += 1;
    }
    return count;
}

pub fn decodeOrdinal(archive: []const u8, ordinal: u64, output: []u8) Failure!usize {
    var reader = std.Io.Reader.fixed(archive);
    var name_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var link_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var it = std_tar.Iterator.init(&reader, .{ .file_name_buffer = &name_buffer, .link_name_buffer = &link_buffer });
    var index: u64 = 0;
    while (true) {
        const maybe = it.next() catch |err| return mapError(err);
        const file = maybe orelse break;
        if (index == ordinal) {
            const size: usize = std.math.cast(usize, file.size) orelse return error.ResourceFailure;
            if (output.len < size) return error.CapacityFailure;
            var sink = std.Io.Writer.fixed(output[0..size]);
            it.streamRemaining(file, &sink) catch |err| return mapError(err);
            return size;
        }
        index += 1;
    }
    return error.CallFailure;
}

// archiveSize runs the same encode into a counting writer; the write arm
// only serves shapes it can carry, so the count matches what encode emits.
pub fn archiveSize(entries: []const Entry) Failure!u64 {
    const measurement = @import("../../common/primitive/measurement.zig");
    var counter = measurement.Counter.init(null);
    try encodeTo(entries, &counter.writer);
    return counter.written();
}

pub fn encode(entries: []const Entry, output: []u8, scratch: []u8) Failure!usize {
    _ = scratch;
    var sink = std.Io.Writer.fixed(output);
    try encodeTo(entries, &sink);
    return sink.end;
}

fn encodeTo(entries: []const Entry, writer: *std.Io.Writer) Failure!void {
    var tar_writer: std_tar.Writer = .{ .underlying_writer = writer };
    for (entries) |entry| {
        if (entry.uid != 0 or entry.gid != 0) return error.UnsupportedFailure;
        if (entry.name.len > 100) return error.UnsupportedFailure;
        if (entry.link_name.len > 100) return error.UnsupportedFailure;
        const options: std_tar.Writer.Options = .{ .mode = entry.mode, .mtime = entry.modification_time };
        switch (entry.typeflag) {
            // The boundary sends a bare zero where the onprem arm reads a regular file.
            0, onprem.typeflag_regular, '7' => tar_writer.writeFileBytes(entry.name, entry.data, options) catch |err| return mapError(err),
            '5' => tar_writer.writeDir(entry.name, options) catch |err| return mapError(err),
            '2' => tar_writer.writeLink(entry.name, entry.link_name, options) catch |err| return mapError(err),
            else => return error.UnsupportedFailure,
        }
    }
    tar_writer.finishPedantically() catch |err| return mapError(err);
}

test "offprem tar count and content match onprem across shapes" {
    const alloc = std.testing.allocator;

    const zeros: [5000]u8 = @splat(0);
    const entries = [_]Entry{
        .{ .name = "dir/", .data = &.{}, .typeflag = '5', .mode = 0o755 },
        .{ .name = "dir/regular.txt", .data = "the quick brown fox jumps over the lazy dog" },
        .{ .name = "dir/zeros.bin", .data = &zeros, .mode = 0o600 },
        .{ .name = "link", .data = &.{}, .typeflag = '2', .link_name = "dir/regular.txt" },
    };

    const onprem_archive = try alloc.alloc(u8, 65536);
    defer alloc.free(onprem_archive);
    const scratch = try alloc.alloc(u8, onprem.scratch_size);
    defer alloc.free(scratch);

    const onprem_len = try onprem.encode(&entries, onprem_archive, scratch);
    const onprem_count = try onprem.inspectCount(onprem_archive[0..onprem_len]);
    const offprem_count = try inspectCount(onprem_archive[0..onprem_len]);
    try std.testing.expectEqual(onprem_count, offprem_count);

    const offprem_archive = try alloc.alloc(u8, 65536);
    defer alloc.free(offprem_archive);
    const offprem_len = try encode(&entries, offprem_archive, scratch);
    const back = try alloc.alloc(u8, 8192);
    defer alloc.free(back);
    const decoded = try decodeOrdinal(offprem_archive[0..offprem_len], 1, back);
    try std.testing.expectEqual(entries[1].data.len, decoded);
    try std.testing.expectEqualSlices(u8, entries[1].data, back[0..decoded]);
}
