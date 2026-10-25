const std = @import("std");

const bounds = @import("../../../common/primitive/bounds.zig");
const checksum = @import("../../../common/primitive/checksum.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const io = @import("../../../common/primitive/io.zig");
const measurement = @import("../../../common/primitive/measurement.zig");
const tee = @import("../../../common/primitive/tee.zig");
const deflate = @import("../../leaf/deflate/onprem.zig");
const deflate_seam = @import("../../leaf/deflate/seam.zig");

const Exception = exception_prim.Exception;
pub const deflate_history_size = deflate.history_size;

const Crc32Tee = tee.CountingTee(.{ .crc32 = true });
pub const Options = struct {
    modification_time: u32,
    extra_flags: u8,
    operating_system: u8,
    text: bool,
    header_crc: bool,
    extra: []const u8,
    name: []const u8,
    comment: []const u8,
    deflate: deflate.Options,
    provider: checksum.Provider = checksum.default_provider,
};

const magic_1 = 0x1f;
const magic_2 = 0x8b;
const cm_deflate = 8;
const flag_text = 0x01;
const flag_header_crc = 0x02;
const flag_extra = 0x04;
const flag_name = 0x08;
const flag_comment = 0x10;
const reserved_flags = 0xe0;
const trailer_len = 8;
// The 10-byte header and 8-byte trailer need 18 bytes before any deflate data.
const minimum_member_len = 18;

pub fn encodedSizeBound(input_len: usize, options: Options) usize {
    var wrapper_size: usize = 18;
    if (options.extra.len != 0) wrapper_size +|= 2 +| options.extra.len;
    if (options.name.len != 0) wrapper_size +|= options.name.len +| 1;
    if (options.comment.len != 0) wrapper_size +|= options.comment.len +| 1;
    if (options.header_crc) wrapper_size +|= 2;
    return deflate.encodedSizeBound(input_len) +| wrapper_size;
}

pub const StreamInfo = struct {
    flags: u8,
    modification_time: u32,
    extra_flags: u8,
    operating_system: u8,
};

// First-member fixed-header fields for the read-side inspect projection,
// parsed without walking the payload.
pub fn inspectStream(input: []const u8) Exception!StreamInfo {
    if (input.len < 10) return error.DataException;
    if (input[0] != magic_1 or input[1] != magic_2) return error.DataException;
    if (input[2] != cm_deflate) return error.UnsupportedException;
    const flags = input[3];
    if (flags & reserved_flags != 0) return error.DataException;
    return .{
        .flags = flags,
        .modification_time = std.mem.readInt(u32, input[4..8], .little),
        .extra_flags = input[8],
        .operating_system = input[9],
    };
}

pub fn decodedSize(input: []const u8, history: []u8, provider: checksum.Provider) Exception!usize {
    if (history.len < deflate_history_size) return error.CapacityException;
    var counter = measurement.Counter.init(null);
    _ = try decode(input, &counter.writer, history, provider);
    return measurement.measuredLength(&counter);
}

pub const SinglePass = union(enum) {
    decoded: usize,
    fallback: usize,
};

const Member = struct {
    header: HeaderTail,
    data_start: usize,
    data_size: usize,
    decoded_size: usize,
    crc32: u32,

    fn total(self: Member) usize {
        return self.data_start + self.data_size + trailer_len;
    }
};

// Every path resolves a member here, so decode passes and the inspector
// cannot disagree on member boundaries or verification.
fn readMember(input: []const u8, at: usize, history: []u8, output: *std.Io.Writer, provider: checksum.Provider) Exception!Member {
    const header = try parseHeader(input[at..], provider);
    const data_start = at + header.len;
    var tee_writer = Crc32Tee.initWithProvider(output, provider);
    const inflated = inflatePayload(input, data_start, history, &tee_writer.writer, provider) catch |err| return switch (err) {
        error.WriteFailed => error.IoException,
        else => error.DataException,
    };
    const trailer_at = data_start + inflated.consumed;
    if (input.len - trailer_at < trailer_len) return error.DataException;
    const stored_crc = std.mem.readInt(u32, input[trailer_at..][0..4], .little);
    const stored_size = std.mem.readInt(u32, input[trailer_at + 4 ..][0..4], .little);
    if (stored_crc != tee_writer.crc32Value() or stored_size != @as(u32, @truncate(tee_writer.size))) return error.IntegrityException;
    // ISIZE wraps modulo 2^32 (RFC 1952), so the check accepts the claim
    // plus multiples; decoded_size carries the tee's true count.
    return .{
        .header = header,
        .data_start = data_start,
        .data_size = inflated.consumed,
        .decoded_size = std.math.cast(usize, tee_writer.size) orelse return error.ResourceException,
        .crc32 = stored_crc,
    };
}

// ISIZE only seeds the fit; a fallback carries the bytes written for
// erasure, and the limit is checked before commit.
pub fn decodeSinglePass(input: []const u8, output: []u8, history: []u8, provider: checksum.Provider, max_decoded_bytes: u64) Exception!SinglePass {
    if (history.len < deflate_history_size) return error.CapacityException;
    if (input.len >= std.math.maxInt(u32)) return .{ .fallback = 0 };
    if (input.len < minimum_member_len) return .{ .fallback = 0 };
    const claimed_size = std.mem.readInt(u32, input[input.len - 4 ..][0..4], .little);
    if (output.len < claimed_size) return .{ .fallback = 0 };
    if (claimed_size > max_decoded_bytes) return .{ .fallback = 0 };
    var sink_writer = std.Io.Writer.fixed(output);
    const member = readMember(input, 0, history, &sink_writer, provider) catch return .{ .fallback = sink_writer.end };
    if (member.total() != input.len) return .{ .fallback = sink_writer.end };
    // A wrapped ISIZE can hide a member past the limit; the true count
    // is checked before commit.
    if (member.decoded_size > max_decoded_bytes) return .{ .fallback = sink_writer.end };
    return .{ .decoded = member.decoded_size };
}

pub fn decode(input: []const u8, output: *std.Io.Writer, history: []u8, provider: checksum.Provider) Exception!usize {
    if (history.len < deflate_history_size) return error.CapacityException;
    // An empty input is not a gzip stream; accepting it would validate
    // empty non-archives as zero-member decodes.
    if (input.len == 0) return error.DataException;
    var total: usize = 0;
    var at: usize = 0;
    while (at < input.len) {
        const member = try readMember(input, at, history, output, provider);
        total = try bounds.addUsize(total, member.decoded_size);
        at = member.total();
    }
    return total;
}

pub fn encodeStream(source: *std.Io.Reader, output: *std.Io.Writer, history: []u8, options: Options) Exception!void {
    if (history.len < deflate_history_size) return error.CapacityException;
    try writeHeader(output, options);
    // Optimal mode carves scratch past deflate_history_size, so the full slice is required.
    var compressor = try deflate.Compress.init(output, history, options.deflate);
    var crc32 = checksum.Crc32.bind(options.provider, {});
    const total = try deflate.feed(checksum.Crc32, source, &compressor, &crc32);
    compressor.finish() catch return error.IoException;
    try writeTrailer(output, crc32.final({}), total);
}

fn parseHeader(input: []const u8, provider: checksum.Provider) Exception!HeaderTail {
    if (input.len < 10) return error.DataException;
    const fixed = input[0..10];
    if (fixed[0] != magic_1 or fixed[1] != magic_2) return error.DataException;
    if (fixed[2] != cm_deflate) return error.UnsupportedException;
    const flags = fixed[3];
    if (flags & reserved_flags != 0) return error.DataException;
    var hasher = checksum.Crc32.bind(provider, {});
    hasher.update(fixed);
    var cursor: usize = fixed.len;
    var extra: []const u8 = &.{};
    var name: []const u8 = &.{};
    var comment: []const u8 = &.{};
    if (flags & flag_extra != 0) {
        if (input.len - cursor < 2) return error.DataException;
        const remaining: usize = (@as(usize, input[cursor + 1]) << 8) | input[cursor];
        hasher.update(input[cursor..][0..2]);
        cursor += 2;
        if (input.len - cursor < remaining) return error.DataException;
        extra = input[cursor .. cursor + remaining];
        hasher.update(extra);
        cursor += remaining;
    }
    if (flags & flag_name != 0) {
        const end = std.mem.findScalarPos(u8, input, cursor, 0) orelse return error.DataException;
        name = input[cursor..end];
        hasher.update(input[cursor .. end + 1]);
        cursor = end + 1;
    }
    if (flags & flag_comment != 0) {
        const end = std.mem.findScalarPos(u8, input, cursor, 0) orelse return error.DataException;
        comment = input[cursor..end];
        hasher.update(input[cursor .. end + 1]);
        cursor = end + 1;
    }
    if (flags & flag_header_crc != 0) {
        if (input.len - cursor < 2) return error.DataException;
        const stored_crc = (@as(u16, input[cursor + 1]) << 8) | input[cursor];
        if (stored_crc != @as(u16, @truncate(hasher.final({})))) return error.IntegrityException;
        cursor += 2;
    }
    return .{ .extra = extra, .name = name, .comment = comment, .len = cursor };
}

const HeaderTail = struct {
    extra: []const u8,
    name: []const u8,
    comment: []const u8,
    len: usize,
};

const Inflated = struct {
    produced: usize,
    consumed: usize,
};

fn inflatePayload(input: []const u8, data_start: usize, history: []u8, output: *std.Io.Writer, provider: checksum.Provider) !Inflated {
    var inflater: deflate_seam.Decode = undefined;
    inflater.initSliceBoundInPlace(provider, input[data_start..], history) catch return error.UnsupportedException;
    const produced = try inflater.readerPtr().streamRemaining(output);
    return .{ .produced = produced, .consumed = (inflater.inputBitsConsumed() + 7) / 8 };
}

fn writeHeader(writer: *std.Io.Writer, options: Options) Exception!void {
    if (options.extra.len > std.math.maxInt(u16)) return error.CallException;
    if (std.mem.findScalar(u8, options.name, 0) != null or std.mem.findScalar(u8, options.comment, 0) != null) return error.CallException;
    var flags: u8 = 0;
    if (options.text) flags |= flag_text;
    if (options.header_crc) flags |= flag_header_crc;
    if (options.extra.len != 0) flags |= flag_extra;
    if (options.name.len != 0) flags |= flag_name;
    if (options.comment.len != 0) flags |= flag_comment;
    var hasher = checksum.Crc32.bind(options.provider, {});
    var fixed_header: [10]u8 = undefined;
    fixed_header[0] = magic_1;
    fixed_header[1] = magic_2;
    fixed_header[2] = cm_deflate;
    fixed_header[3] = flags;
    std.mem.writeInt(u32, fixed_header[4..8], options.modification_time, .little);
    fixed_header[8] = options.extra_flags;
    fixed_header[9] = options.operating_system;
    hasher.update(&fixed_header);
    try io.writeBytes(writer, &fixed_header);
    if (options.extra.len != 0) {
        var xlen: [2]u8 = undefined;
        std.mem.writeInt(u16, &xlen, @intCast(options.extra.len), .little);
        hasher.update(&xlen);
        hasher.update(options.extra);
        try io.writeBytes(writer, &xlen);
        try io.writeBytes(writer, options.extra);
    }
    for ([_][]const u8{ options.name, options.comment }) |field| {
        if (field.len == 0) continue;
        hasher.update(field);
        try io.writeBytes(writer, field);
        const zero = [_]u8{0};
        hasher.update(&zero);
        try io.writeBytes(writer, &zero);
    }
    if (options.header_crc) {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, @truncate(hasher.final({})), .little);
        try io.writeBytes(writer, &bytes);
    }
}

fn writeTrailer(writer: *std.Io.Writer, crc32: u32, uncompressed_size: u64) Exception!void {
    writer.writeInt(u32, crc32, .little) catch return error.IoException;
    writer.writeInt(u32, @truncate(uncompressed_size), .little) catch return error.IoException;
}

pub const MemberInfo = struct {
    modification_time: u32,
    extra_flags: u8,
    operating_system: u8,
    text: bool,
    header_crc: bool,
    extra: []const u8,
    name: []const u8,
    comment: []const u8,
    // Compressed payload span, including the byte-aligned padding bit.
    data_offset: usize,
    data_size: usize,
    decoded_size: usize,
    crc32: u32,
    // The whole member: header, payload, and trailer.
    total_size: usize,
};

pub const MemberIterator = struct {
    input: []const u8,
    history: []u8,
    provider: checksum.Provider,
    offset: usize = 0,

    pub fn next(self: *MemberIterator) Exception!?MemberInfo {
        if (self.offset >= self.input.len) return null;
        if (self.input.len - self.offset < minimum_member_len) return error.DataException;
        const member = try inspectMember(self.input[self.offset..], self.history, self.provider);
        self.offset = try bounds.addUsize(self.offset, member.total_size);
        return member;
    }
};

// Each member decodes strictly with the trailer CRC and ISIZE verified,
// so a corrupt member fails at its ordinal.
pub fn inspectMembers(input: []const u8, history: []u8, provider: checksum.Provider) MemberIterator {
    return .{ .input = input, .history = history, .provider = provider };
}

fn inspectMember(input: []const u8, history: []u8, provider: checksum.Provider) Exception!MemberInfo {
    if (history.len < deflate_history_size) return error.CapacityException;
    var counter = measurement.Counter.init(null);
    const member = try readMember(input, 0, history, &counter.writer, provider);
    return .{
        .modification_time = std.mem.readInt(u32, input[4..8], .little),
        .extra_flags = input[8],
        .operating_system = input[9],
        .text = input[3] & flag_text != 0,
        .header_crc = input[3] & flag_header_crc != 0,
        .extra = member.header.extra,
        .name = member.header.name,
        .comment = member.header.comment,
        .data_offset = member.data_start,
        .data_size = member.data_size,
        .decoded_size = member.decoded_size,
        .crc32 = member.crc32,
        .total_size = member.total(),
    };
}

test "inspectMembers enumerates concatenated members with their fields" {
    // A mixed provider build serves no single tag for both arms; run
    // only where the default tag serves them.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;

    var first: [256]u8 = undefined;
    var second: [256]u8 = undefined;
    const options_a: Options = .{
        .modification_time = 0x01020304,
        .extra_flags = 2,
        .operating_system = 3,
        .text = false,
        .header_crc = true,
        .extra = &.{ 1, 2, 3 },
        .name = "first.bin",
        .comment = "note",
        .deflate = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 8 },
    };
    const options_b: Options = .{
        .modification_time = 0,
        .extra_flags = 0,
        .operating_system = 255,
        .text = false,
        .header_crc = false,
        .extra = &.{},
        .name = "",
        .comment = "",
        .deflate = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 8 },
    };
    const payload_a = "first member payload, first member payload, first";
    const payload_b = "second!";
    var history: [deflate_history_size]u8 = undefined;
    var r1 = std.Io.Reader.fixed(payload_a);
    var w1 = std.Io.Writer.fixed(&first);
    try encodeStream(&r1, &w1, &history, options_a);
    var r2 = std.Io.Reader.fixed(payload_b);
    var w2 = std.Io.Writer.fixed(&second);
    try encodeStream(&r2, &w2, &history, options_b);
    var combined: [512]u8 = undefined;
    @memcpy(combined[0..w1.end], first[0..w1.end]);
    @memcpy(combined[w1.end .. w1.end + w2.end], second[0..w2.end]);
    const total = w1.end + w2.end;

    var iterator = inspectMembers(combined[0..total], &history, checksum.default_provider);
    const m1 = (try iterator.next()).?;
    try std.testing.expectEqualSlices(u8, "first.bin", m1.name);
    try std.testing.expectEqualSlices(u8, "note", m1.comment);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, m1.extra);
    try std.testing.expectEqual(@as(u32, 0x01020304), m1.modification_time);
    try std.testing.expectEqual(payload_a.len, m1.decoded_size);
    try std.testing.expect(m1.data_offset < total and m1.total_size < total);
    const m2 = (try iterator.next()).?;
    try std.testing.expectEqual(payload_b.len, m2.decoded_size);
    try std.testing.expectEqual(@as(usize, 255), m2.operating_system);
    try std.testing.expectEqual(total, m1.total_size + m2.total_size);
    try std.testing.expect((try iterator.next()) == null);
}

test "decodeSinglePass defers to the two-pass route when the decoded limit excludes the member" {
    // A mixed provider build serves no single tag for both arms; run
    // only where the default tag serves them.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;

    const payload = "single pass payload that a decoded limit must exclude";
    const options: Options = .{
        .modification_time = 0,
        .extra_flags = 0,
        .operating_system = 3,
        .text = false,
        .header_crc = false,
        .extra = &.{},
        .name = "",
        .comment = "",
        .deflate = .{ .good = 8, .nice = 128, .lazy = 16, .chain = 8 },
    };
    var history: [deflate_history_size]u8 = undefined;
    var encoded: [128]u8 = undefined;
    var reader = std.Io.Reader.fixed(payload);
    var writer = std.Io.Writer.fixed(&encoded);
    try encodeStream(&reader, &writer, &history, options);
    const input = encoded[0..writer.end];

    var output: [256]u8 = @splat(0xa5);
    switch (try decodeSinglePass(input, &output, &history, checksum.default_provider, payload.len - 1)) {
        .fallback => |tentative| try std.testing.expectEqual(@as(usize, 0), tentative),
        .decoded => return error.LimitNotApplied,
    }
    for (output) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);

    switch (try decodeSinglePass(input, &output, &history, checksum.default_provider, payload.len)) {
        .decoded => |produced| try std.testing.expectEqual(payload.len, produced),
        .fallback => return error.LimitRejectedFit,
    }
    try std.testing.expectEqualSlices(u8, payload, output[0..payload.len]);
}
