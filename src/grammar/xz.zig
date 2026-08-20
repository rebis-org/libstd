const std = @import("std");

const binary = @import("../common/primitive/binary.zig");
const bounds = @import("../common/primitive/bounds.zig");
const checksum = @import("../common/primitive/checksum.zig");
const crypto = @import("../common/primitive/crypto.zig");
const failure_prim = @import("../common/primitive/failure.zig");
const Failure = failure_prim.Failure;
const io = @import("../common/primitive/io.zig");
const measurement = @import("../common/primitive/measurement.zig");
const tee = @import("../common/primitive/tee.zig");
const bcj = @import("../leaf/bcj.zig");
const delta = @import("../leaf/delta.zig");
const lzma = @import("../leaf/lzma.zig");
const lzma2 = @import("../leaf/lzma2.zig");

pub const header_magic = [6]u8{ 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 };
pub const footer_magic = [2]u8{ 0x59, 0x5A };
pub const stream_header_size = 12;
pub const stream_footer_size = 12;

pub const CheckType = enum(u8) {
    none = 0,
    crc32 = 1,
    crc64 = 4,
    sha256 = 0x0A,
};

pub const FilterChoice = enum(u32) {
    none = 0,
    delta = 1,
    x86 = 2,
    ppc = 3,
    ia64 = 4,
    arm = 5,
    armt = 6,
    sparc = 7,
    arm64 = 8,
    riscv = 9,
};

pub const Options = struct {
    dictionary_size: u32,
    check: CheckType,
    filters: FilterChoice = .none,
    match_finder_depth: u32 = 32,
    lazy: bool = false,
    nice_len: u32 = 273,
    match_finder: lzma.MatchFinder = .bt4,
};

// One stream, one block: 12-byte stream header, block header with padding,
// the check (<= 32 bytes for sha256), the index, and the 12-byte footer all
// fit in the constant; filters are 1:1 transforms and add no bytes.
pub fn encodedSizeBound(input_len: usize) usize {
    return lzma2.encodedSizeBound(input_len) +| 128;
}

pub fn decodeWorkspaceSize(dictionary_size: u32) usize {
    return lzma2.decodeWorkspaceSize(dictionary_size) + 65536;
}

pub fn decodeInPlaceWorkspaceSize(dictionary_size: u32) usize {
    return lzma2.decodeInPlaceWorkspaceSize(dictionary_size) + 65536;
}

pub fn encodeWorkspaceSize(dictionary_size: u32) usize {
    return lzma2.encodeWorkspaceSize(dictionary_size) + 65536;
}

pub fn encodeWorkspaceSizeBt(dictionary_size: u32) usize {
    return lzma2.encodeWorkspaceSizeBt(dictionary_size) + 65536;
}

pub fn decodedSize(input: []const u8, scratch: []u8) Failure!usize {
    if (try scanStreamSize(input)) |size| return size;
    var counter = measurement.Counter.init(null);
    var sink = Sink{ .writer = &counter.writer, .buffer = null };
    try decodeInternal(input, &sink, scratch);
    return std.math.cast(usize, counter.written()) orelse error.ResourceLimit;
}

fn scanStreamSize(input: []const u8) Failure!?usize {
    var cursor = binary.ReadCursor.init(input);
    var total: u64 = 0;
    while (cursor.remaining() > 0) {
        const check = try decodeStreamHeader(&cursor);
        var records: IndexRecordList = .{};
        while (cursor.remaining() > 0 and cursor.buffer[cursor.pos] != 0x00) {
            const info = try decodeBlockHeader(&cursor);
            const uncompressed_size = info.uncompressed_size orelse return null;
            const compressed_size = if (info.compressed_size) |size|
                size
            else blk: {
                const data_start = cursor.pos;
                while (true) {
                    const control = try cursor.readU8();
                    if (control == 0x00) break;
                    if (control & 0x80 != 0) {
                        try cursor.advance(2);
                        const pack_hi = try cursor.readU8();
                        const pack_lo = try cursor.readU8();
                        const pack_size = (@as(usize, pack_hi) << 8 | pack_lo) + 1;
                        if (control >= 0xC0) try cursor.advance(1);
                        try cursor.advance(pack_size);
                    } else {
                        if (control != 0x01 and control != 0x02) return error.InvalidData;
                        const size_hi = try cursor.readU8();
                        const size_lo = try cursor.readU8();
                        try cursor.advance((@as(usize, size_hi) << 8 | size_lo) + 1);
                    }
                }
                break :blk cursor.pos - data_start;
            };
            try cursor.advance(blockPadding(compressed_size));
            try cursor.advance(checkSize(check));
            const unpadded_size = try bounds.add(info.header_size, try bounds.add(compressed_size, checkSize(check)));
            try records.append(.{
                .unpadded_size = std.math.cast(u64, unpadded_size) orelse return error.ResourceLimit,
                .uncompressed_size = @as(u64, uncompressed_size),
            });
            total = std.math.add(u64, total, uncompressed_size) catch return error.ResourceLimit;
        }
        const index_start = cursor.pos;
        try decodeIndex(&cursor, records);
        const index_size = cursor.pos - index_start;
        try decodeStreamFooter(&cursor, check, index_size);
        try skipStreamPadding(&cursor);
    }
    return std.math.cast(usize, total) orelse return error.ResourceLimit;
}

pub fn decode(input: []const u8, output: []u8, scratch: []u8) Failure!usize {
    var sink = Sink{ .writer = null, .buffer = output };
    try decodeInternal(input, &sink, scratch);
    return sink.offset;
}

pub fn decodeInPlace(input: []const u8, output: []u8, scratch: []u8) Failure!usize {
    var sink = Sink{ .writer = null, .buffer = output };
    try decodeInternalImpl(input, &sink, scratch, true);
    return sink.offset;
}

const Sink = struct {
    writer: ?*std.Io.Writer,
    buffer: ?[]u8,
    offset: usize = 0,

    fn blockBuffer(self: *Sink, length: usize) Failure![]u8 {
        const buffer = self.buffer orelse return error.InternalFailure;
        if (length > buffer.len - self.offset) return error.InsufficientCapacity;
        return buffer[self.offset..][0..length];
    }

    fn blockBufferRemaining(self: *Sink) []u8 {
        const buffer = self.buffer orelse return &.{};
        return buffer[self.offset..];
    }

    fn commitBlock(self: *Sink, length: usize) void {
        if (self.buffer != null) self.offset += length;
    }
};

fn decodeInternal(input: []const u8, sink: *Sink, scratch: []u8) Failure!void {
    try decodeInternalImpl(input, sink, scratch, false);
}

fn decodeInternalImpl(input: []const u8, sink: *Sink, scratch: []u8, in_place: bool) Failure!void {
    var cursor = binary.ReadCursor.init(input);
    while (cursor.remaining() > 0) {
        const check = try decodeStreamHeader(&cursor);
        var records: IndexRecordList = .{};
        while (true) {
            if (cursor.remaining() == 0 or cursor.buffer[cursor.pos] == 0x00) break;
            const record = try decodeBlock(&cursor, sink, scratch, check, in_place);
            try records.append(record);
        }
        const index_start = cursor.pos;
        try decodeIndex(&cursor, records);
        const index_size = cursor.pos - index_start;
        try decodeStreamFooter(&cursor, check, index_size);
        try skipStreamPadding(&cursor);
    }
}

fn decodeStreamHeader(cursor: *binary.ReadCursor) Failure!CheckType {
    const bytes = try cursor.readSlice(stream_header_size);
    if (!std.mem.eql(u8, bytes[0..6], &header_magic)) return error.InvalidData;
    const check_value = std.mem.readInt(u32, bytes[8..12], .little);
    try verifyCrc32(bytes[6..8], check_value);
    if (bytes[6] != 0x00) return error.InvalidData;
    const check_type: u8 = bytes[7];
    if (check_type & 0xF0 != 0) return error.InvalidData;
    return checkTypeFromInt(check_type);
}

fn checkTypeFromInt(value: u8) Failure!CheckType {
    return switch (value) {
        0 => .none,
        1 => .crc32,
        4 => .crc64,
        0x0A => .sha256,
        else => error.Unsupported,
    };
}

fn verifyCrc32(data: []const u8, expected: u32) Failure!void {
    var crc = checksum.Crc32.init();
    crc.update(data);
    if (crc.final() != expected) return error.IntegrityFailure;
}

const IndexRecord = struct {
    unpadded_size: u64,
    uncompressed_size: u64,
};

const max_index_records = 1024;

const IndexRecordList = struct {
    records: [max_index_records]IndexRecord = undefined,
    len: usize = 0,

    fn append(self: *IndexRecordList, record: IndexRecord) Failure!void {
        if (self.len >= self.records.len) return error.ResourceLimit;
        self.records[self.len] = record;
        self.len += 1;
    }

    fn slice(self: *const IndexRecordList) []const IndexRecord {
        return self.records[0..self.len];
    }
};

const BlockInfo = struct {
    header_size: usize,
    compressed_size: ?usize,
    uncompressed_size: ?usize,
    filters: [4]Filter,
    filter_count: usize,
};

const Filter = union(enum) {
    delta: u8,
    bcj: struct { kind: bcj.Kind, start_offset: u32 },
    lzma2: u8,
};

fn decodeBlock(cursor: *binary.ReadCursor, sink: *Sink, scratch: []u8, check: CheckType, in_place: bool) Failure!IndexRecord {
    const info = try decodeBlockHeader(cursor);
    const compressed_data: ?[]const u8 = if (info.compressed_size) |size|
        try cursor.readSlice(size)
    else
        null;
    const dictionary_size = lzma2.dictionaryFromProp(info.filters[info.filter_count - 1].lzma2);
    if (dictionary_size < lzma.dictionary_min or dictionary_size > lzma.dictionary_max) return error.Unsupported;
    const lzma_scratch_size = if (in_place) lzma2.decodeInPlaceWorkspaceSize(dictionary_size) else lzma2.decodeWorkspaceSize(dictionary_size);
    if (scratch.len < lzma_scratch_size) return error.InsufficientCapacity;
    const options = lzma2.Options{
        .dictionary_size = dictionary_size,
        .properties = lzma2.properties(dictionary_size),
        .max_work = std.math.maxInt(u64),
    };
    var compressed_size: usize = undefined;
    var uncompressed_size: usize = undefined;
    var decode_tee: ?tee.Tee = null;
    if (sink.buffer != null) {
        const block_output = if (info.uncompressed_size) |size|
            try sink.blockBuffer(size)
        else
            sink.blockBufferRemaining();
        if (in_place) {
            const in_place_scratch_size = lzma2.decodeInPlaceWorkspaceSize(dictionary_size);
            if (scratch.len < in_place_scratch_size) return error.InsufficientCapacity;
            const result = try lzma2.decodeInPlace(if (compressed_data) |data| data else cursor.remainingSlice(), block_output, scratch[0..in_place_scratch_size], options);
            uncompressed_size = result.produced;
            compressed_size = info.compressed_size orelse result.consumed;
        } else {
            var fixed_writer = std.Io.Writer.fixed(block_output);
            var chunk_reader = std.Io.Reader.fixed(if (compressed_data) |data| data else cursor.remainingSlice());
            try lzma2.decodeStream(&chunk_reader, &fixed_writer, scratch[0..lzma2.decodeWorkspaceSize(dictionary_size)], options);
            compressed_size = info.compressed_size orelse chunk_reader.seek;
            uncompressed_size = fixed_writer.end;
        }
        if (info.uncompressed_size) |size| {
            if (uncompressed_size != size) return error.IntegrityFailure;
        }
        applyDecodeFilters(info.filters[0..info.filter_count], block_output[0..uncompressed_size]);
        sink.commitBlock(uncompressed_size);
    } else {
        decode_tee = tee.Tee.init(sink.writer);
        var chunk_reader = std.Io.Reader.fixed(if (compressed_data) |data| data else cursor.remainingSlice());
        try lzma2.decodeStream(&chunk_reader, &decode_tee.?.writer, scratch[0..lzma_scratch_size], options);
        compressed_size = info.compressed_size orelse chunk_reader.seek;
        uncompressed_size = std.math.cast(usize, decode_tee.?.size) orelse return error.ResourceLimit;
        if (info.uncompressed_size) |size| {
            if (uncompressed_size != size) return error.IntegrityFailure;
        }
    }
    if (info.compressed_size == null) try cursor.advance(compressed_size);
    try cursor.advance(blockPadding(compressed_size));
    const check_bytes = try cursor.readSlice(checkSize(check));
    if (sink.buffer != null) {
        const block_output = sink.buffer.?[sink.offset - uncompressed_size ..][0..uncompressed_size];
        try verifyFilteredCheck(check, block_output, check_bytes);
    } else if (info.filter_count == 1 and check != .sha256) {
        try verifyCheck(check, decode_tee.?.crc32Value(), decode_tee.?.crc64Value(), check_bytes);
    }
    const unpadded_size = try bounds.add(info.header_size, try bounds.add(compressed_size, checkSize(check)));
    return .{
        .unpadded_size = std.math.cast(u64, unpadded_size) orelse return error.ResourceLimit,
        .uncompressed_size = @as(u64, uncompressed_size),
    };
}

fn decodeBlockHeader(cursor: *binary.ReadCursor) Failure!BlockInfo {
    const header_start = cursor.pos;
    const size_byte = try cursor.readU8();
    const header_size = (@as(usize, size_byte & 0x3F) + 1) * 4;
    if (header_size < 8) return error.InvalidData;
    // The size byte is the first byte of the header, which the CRC covers.
    const header_end = try bounds.add(header_start, header_size);
    if (header_end > cursor.buffer.len) return error.InvalidData;
    const header_bytes = cursor.buffer[header_start..header_end];
    cursor.pos = header_end;
    const flags_byte = header_bytes[1];
    if (flags_byte & 0x3C != 0) return error.InvalidData;
    const has_compressed_size = (flags_byte & 0x40) != 0;
    const has_uncompressed_size = (flags_byte & 0x80) != 0;
    const requested_filter_count: usize = @as(usize, flags_byte & 0x03) + 1;
    const header_crc = std.mem.readInt(u32, header_bytes[header_size - 4 ..][0..4], .little);
    try verifyCrc32(header_bytes[0 .. header_size - 4], header_crc);
    var sub = binary.ReadCursor.init(header_bytes[2 .. header_size - 4]);
    const compressed_size: ?usize = if (has_compressed_size) blk: {
        const value = try sub.readULEB128();
        if (value == 0) return error.InvalidData;
        break :blk std.math.cast(usize, value) orelse return error.ResourceLimit;
    } else null;
    const uncompressed_size: ?usize = if (has_uncompressed_size)
        std.math.cast(usize, try sub.readULEB128()) orelse return error.ResourceLimit
    else
        null;
    var dictionary_props: ?u8 = null;
    var filters: [4]Filter = undefined;
    var filter_count: usize = 0;
    for (0..requested_filter_count) |_| {
        const filter_id = try sub.readULEB128();
        const props_size = try sub.readULEB128();
        if (props_size > sub.remaining()) return error.InvalidData;
        switch (filter_id) {
            0x21 => {
                if (props_size != 1 or dictionary_props != null) return error.Unsupported;
                dictionary_props = try sub.readU8();
                filters[filter_count] = .{ .lzma2 = dictionary_props.? };
            },
            0x03 => {
                if (props_size != 1) return error.Unsupported;
                filters[filter_count] = .{ .delta = try sub.readU8() };
            },
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B => {
                const kind: bcj.Kind = switch (filter_id) {
                    0x04 => .x86,
                    0x05 => .ppc,
                    0x06 => .ia64,
                    0x07 => .arm,
                    0x08 => .armt,
                    0x09 => .sparc,
                    0x0A => .arm64,
                    0x0B => .riscv,
                    else => unreachable,
                };
                const start_offset: u32 = if (props_size == 0) 0 else if (props_size == 4) blk: {
                    const props = try sub.readBytes(4);
                    break :blk std.mem.readInt(u32, &props, .little);
                } else return error.Unsupported;
                if (start_offset % bcj.alignment(kind) != 0) return error.InvalidData;
                filters[filter_count] = .{ .bcj = .{ .kind = kind, .start_offset = start_offset } };
            },
            else => {
                try sub.advance(props_size);
                return error.Unsupported;
            },
        }
        filter_count += 1;
    }
    while (sub.remaining() > 0) {
        if (try sub.readU8() != 0) return error.InvalidData;
    }
    if (filter_count == 0 or filters[filter_count - 1] != .lzma2) return error.Unsupported;
    return .{
        .header_size = header_size,
        .compressed_size = compressed_size,
        .uncompressed_size = uncompressed_size,
        .filters = filters,
        .filter_count = filter_count,
    };
}

fn applyDecodeFilters(filters: []const Filter, data: []u8) void {
    var index = filters.len;
    while (index > 1) {
        index -= 1;
        switch (filters[index - 1]) {
            .delta => |distance| delta.decode(data, distance),
            .bcj => |options| bcj.decode(options.kind, options.start_offset, data),
            .lzma2 => return,
        }
    }
}

fn verifyFilteredCheck(check: CheckType, data: []const u8, expected: []const u8) Failure!void {
    if (check == .sha256) {
        var sha = crypto.Sha256.init(.{});
        sha.update(data);
        var digest: [32]u8 = undefined;
        sha.final(&digest);
        if (!std.mem.eql(u8, &digest, expected)) return error.IntegrityFailure;
        return;
    }
    switch (check) {
        .none => {},
        .crc32 => {
            var crc = checksum.Crc32.init();
            crc.update(data);
            const actual: u32 = crc.final();
            const stored = std.mem.readInt(u32, expected[0..4], .little);
            if (actual != stored) return error.IntegrityFailure;
        },
        .crc64 => {
            var crc = checksum.XZCrc64.init();
            crc.update(data);
            const actual: u64 = crc.final();
            const stored = std.mem.readInt(u64, expected[0..8], .little);
            if (actual != stored) return error.IntegrityFailure;
        },
        .sha256 => unreachable,
    }
}

fn decodeIndex(cursor: *binary.ReadCursor, records: IndexRecordList) Failure!void {
    const index_start = cursor.pos;
    if (cursor.remaining() == 0 or cursor.buffer[cursor.pos] != 0x00) return error.InvalidData;
    _ = try cursor.readU8();
    const record_count = try cursor.readULEB128();
    if (record_count != records.len) return error.IntegrityFailure;
    for (records.slice()) |expected| {
        const unpadded = try cursor.readULEB128();
        const uncompressed = try cursor.readULEB128();
        if (unpadded != expected.unpadded_size or uncompressed != expected.uncompressed_size) return error.IntegrityFailure;
    }
    const content_size = cursor.pos - index_start;
    const padding = (4 - (content_size % 4)) % 4;
    for (0..padding) |_| {
        if (cursor.pos >= cursor.buffer.len or cursor.buffer[cursor.pos] != 0x00) return error.InvalidData;
        cursor.pos += 1;
    }
    const index_end = try bounds.add(cursor.pos, 4);
    if (index_end > cursor.buffer.len) return error.InvalidData;
    const index_crc = std.mem.readInt(u32, cursor.buffer[cursor.pos..][0..4], .little);
    try verifyCrc32(cursor.buffer[index_start..cursor.pos], index_crc);
    cursor.pos = index_end;
}

fn decodeStreamFooter(cursor: *binary.ReadCursor, check: CheckType, index_size: usize) Failure!void {
    const footer = try cursor.readSlice(stream_footer_size);
    const footer_crc = std.mem.readInt(u32, footer[0..4], .little);
    try verifyCrc32(footer[4..10], footer_crc);
    const backward_size = @as(usize, std.mem.readInt(u32, footer[4..8], .little));
    if (index_size < 4 or index_size % 4 != 0) return error.IntegrityFailure;
    if (@as(u64, backward_size) + 1 != index_size / 4) return error.IntegrityFailure;
    if (footer[8] != 0x00) return error.InvalidData;
    const check_type: u8 = footer[9];
    if (check_type & 0xF0 != 0) return error.InvalidData;
    if (@intFromEnum(check) != check_type) return error.IntegrityFailure;
    if (!std.mem.eql(u8, footer[10..12], &footer_magic)) return error.InvalidData;
}

fn skipStreamPadding(cursor: *binary.ReadCursor) Failure!void {
    while (cursor.remaining() > 0 and cursor.buffer[cursor.pos] == 0x00) {
        if (cursor.remaining() < 4) return error.InvalidData;
        const padding = try cursor.readSlice(4);
        for (padding) |byte| {
            if (byte != 0) return error.InvalidData;
        }
    }
}

fn verifyCheck(check: CheckType, crc32: u32, crc64: u64, expected: []const u8) Failure!void {
    switch (check) {
        .none => {},
        .crc32 => {
            if (crc32 != std.mem.readInt(u32, expected[0..4], .little)) return error.IntegrityFailure;
        },
        .crc64 => {
            if (crc64 != std.mem.readInt(u64, expected[0..8], .little)) return error.IntegrityFailure;
        },
        .sha256 => return error.InternalFailure,
    }
}

fn writeCheck(writer: *std.Io.Writer, check: CheckType, crc32: u32, crc64: u64) Failure!void {
    switch (check) {
        .none => {},
        .crc32 => writer.writeInt(u32, crc32, .little) catch return error.IoFailure,
        .crc64 => writer.writeInt(u64, crc64, .little) catch return error.IoFailure,
        .sha256 => return error.Unsupported,
    }
}

pub fn requiredSize(input: []const u8, scratch: []u8, options: Options) Failure!usize {
    var counter = measurement.Counter.init(null);
    try encodeInternal(input, &counter.writer, scratch, options);
    return std.math.cast(usize, counter.written()) orelse error.ResourceLimit;
}

pub fn encode(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    var writer = std.Io.Writer.fixed(output);
    try encodeInternal(input, &writer, scratch, options);
    return writer.end;
}

fn encodeInternal(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    // One stream keeps a single LZMA2 encoder, so the configured dictionary
    // stays continuous across the whole input instead of resetting every chunk.
    try encodeStream(writer, input, scratch, options);
}

fn encodeStream(writer: *std.Io.Writer, input: []const u8, scratch: []u8, options: Options) Failure!void {
    const dictionary_props = lzma2.propFromDictionary(options.dictionary_size);
    const dictionary_size = lzma2.dictionaryFromProp(dictionary_props);
    const lzma_scratch_size = if (options.match_finder == .bt4) lzma2.encodeWorkspaceSizeBt(dictionary_size) else lzma2.encodeWorkspaceSize(dictionary_size);
    if (scratch.len < lzma_scratch_size) return error.InsufficientCapacity;
    const lzma_scratch = scratch[0..lzma_scratch_size];
    const remaining_scratch = scratch[lzma_scratch_size..];
    const lzma_options = lzma2.Options{
        .dictionary_size = dictionary_size,
        .properties = lzma2.properties(dictionary_size),
        .max_work = std.math.maxInt(u64),
        .match_finder_depth = options.match_finder_depth,
        .lazy = options.lazy,
        .nice_len = options.nice_len,
        .match_finder = options.match_finder,
    };
    const filtered = if (options.filters != .none) blk: {
        if (remaining_scratch.len < input.len) return error.InsufficientCapacity;
        const buffer = remaining_scratch[0..input.len];
        @memcpy(buffer, input);
        try applyEncodeFilter(options.filters, buffer);
        break :blk buffer;
    } else input;
    try writeStreamHeader(writer, options.check);
    const block_header = try buildBlockHeader(input.len, dictionary_props, options.filters);
    try io.writeBytes(writer, block_header.slice());
    var count_tee = tee.Tee.init(writer);
    try lzma2.encodeToWriter(filtered, &count_tee.writer, lzma_scratch, lzma_options);
    const compressed_size = std.math.cast(usize, count_tee.size) orelse return error.ResourceLimit;
    const block_padding = blockPadding(compressed_size);
    if (block_padding > 0) {
        const zeroes = [_]u8{0} ** 3;
        try io.writeBytes(writer, zeroes[0..block_padding]);
    }
    var tee_writer = tee.Tee.init(null);
    _ = tee_writer.writer.write(input) catch return error.IoFailure;
    if (options.check == .sha256) {
        var sha = crypto.Sha256.init(.{});
        sha.update(input);
        var digest: [32]u8 = undefined;
        sha.final(&digest);
        try io.writeBytes(writer, &digest);
    } else {
        try writeCheck(writer, options.check, tee_writer.crc32Value(), tee_writer.crc64Value());
    }
    const check_size = checkSize(options.check);
    const unpadded_size = try bounds.add(block_header.slice().len, try bounds.add(compressed_size, check_size));
    const index_size = try writeIndex(writer, unpadded_size, input.len);
    try writeStreamFooter(writer, options.check, index_size);
}

fn applyEncodeFilter(filter: FilterChoice, data: []u8) Failure!void {
    switch (filter) {
        .none => {},
        .delta => delta.encode(data, 1),
        .x86, .ppc, .ia64, .arm, .armt, .sparc, .arm64, .riscv => bcj.encode(bcjKindFromChoice(filter), 0, data),
    }
}

fn bcjKindFromChoice(filter: FilterChoice) bcj.Kind {
    return switch (filter) {
        .x86 => .x86,
        .ppc => .ppc,
        .ia64 => .ia64,
        .arm => .arm,
        .armt => .armt,
        .sparc => .sparc,
        .arm64 => .arm64,
        .riscv => .riscv,
        else => unreachable,
    };
}

fn writeStreamHeader(writer: *std.Io.Writer, check: CheckType) Failure!void {
    const flags_bytes = [_]u8{ 0x00, @intFromEnum(check) };
    var crc = checksum.Crc32.init();
    crc.update(&flags_bytes);
    try io.writeBytes(writer, &header_magic);
    try io.writeBytes(writer, &flags_bytes);
    var crc_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &crc_bytes, crc.final(), .little);
    try io.writeBytes(writer, &crc_bytes);
}

const BlockHeader = struct {
    bytes: [64]u8,
    len: usize,

    fn slice(self: *const BlockHeader) []const u8 {
        return self.bytes[0..self.len];
    }
};

fn buildBlockHeader(uncompressed_size: usize, dictionary_props: u8, filters: FilterChoice) Failure!BlockHeader {
    var content: [60]u8 = undefined;
    var cursor = binary.WriteCursor.init(&content);
    cursor.writeULEB128(uncompressed_size) catch return error.InternalFailure;
    if (filters != .none) {
        cursor.writeULEB128(filterId(filters)) catch return error.InternalFailure;
        cursor.writeULEB128(filterPropsSize(filters)) catch return error.InternalFailure;
        if (filters == .delta) cursor.writeU8(1) catch return error.InternalFailure;
    }
    cursor.writeULEB128(0x21) catch return error.InternalFailure;
    cursor.writeULEB128(1) catch return error.InternalFailure;
    cursor.writeU8(dictionary_props) catch return error.InternalFailure;
    const content_size = cursor.written();
    const header_without_crc = 2 + content_size;
    const header_size = std.mem.alignForward(usize, header_without_crc + 4, 4);
    const padding = header_size - header_without_crc - 4;
    var header: BlockHeader = .{ .bytes = undefined, .len = header_size };
    header.bytes[0] = @intCast((header_size / 4) - 1);
    header.bytes[1] = @as(u8, 0x80) | @as(u8, if (filters != .none) 1 else 0);
    @memcpy(header.bytes[2 .. 2 + content_size], content[0..content_size]);
    var index: usize = 2 + content_size;
    for (0..padding) |_| {
        header.bytes[index] = 0;
        index += 1;
    }
    var crc = checksum.Crc32.init();
    crc.update(header.bytes[0..index]);
    std.mem.writeInt(u32, header.bytes[index..][0..4], crc.final(), .little);
    return header;
}

fn filterId(filter: FilterChoice) u64 {
    return switch (filter) {
        .delta => 0x03,
        .x86 => 0x04,
        .ppc => 0x05,
        .ia64 => 0x06,
        .arm => 0x07,
        .armt => 0x08,
        .sparc => 0x09,
        .arm64 => 0x0A,
        .riscv => 0x0B,
        .none => unreachable,
    };
}

fn filterPropsSize(filter: FilterChoice) u64 {
    return switch (filter) {
        .delta => 1,
        else => 0,
    };
}

fn blockPadding(data_size: usize) usize {
    const rem = data_size % 4;
    return if (rem == 0) 0 else 4 - rem;
}

fn writeIndex(writer: *std.Io.Writer, unpadded_size: usize, uncompressed_size: usize) Failure!usize {
    var content: [48]u8 = undefined;
    var cursor = binary.WriteCursor.init(&content);
    cursor.writeU8(0x00) catch return error.InternalFailure;
    cursor.writeULEB128(1) catch return error.InternalFailure;
    cursor.writeULEB128(unpadded_size) catch return error.InternalFailure;
    cursor.writeULEB128(uncompressed_size) catch return error.InternalFailure;
    const content_size = cursor.written();
    const padding = blockPadding(content_size);
    var crc = checksum.Crc32.init();
    crc.update(content[0..content_size]);
    if (padding > 0) {
        const zeroes = [_]u8{0} ** 3;
        crc.update(zeroes[0..padding]);
    }
    var crc_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &crc_bytes, crc.final(), .little);
    try io.writeBytes(writer, content[0..content_size]);
    if (padding > 0) {
        const zeroes = [_]u8{0} ** 3;
        try io.writeBytes(writer, zeroes[0..padding]);
    }
    try io.writeBytes(writer, &crc_bytes);
    return content_size + padding + 4;
}

fn writeStreamFooter(writer: *std.Io.Writer, check: CheckType, index_size: usize) Failure!void {
    if (index_size < 4 or index_size % 4 != 0) return error.InternalFailure;
    const backward_size = (index_size / 4) - 1;
    const backward_size_u32 = std.math.cast(u32, backward_size) orelse return error.InternalFailure;
    var footer_tail: [8]u8 = undefined;
    std.mem.writeInt(u32, footer_tail[0..4], backward_size_u32, .little);
    footer_tail[4] = 0x00;
    footer_tail[5] = @intFromEnum(check);
    footer_tail[6] = footer_magic[0];
    footer_tail[7] = footer_magic[1];
    var crc = checksum.Crc32.init();
    crc.update(footer_tail[0..6]);
    var footer: [12]u8 = undefined;
    std.mem.writeInt(u32, footer[0..4], crc.final(), .little);
    @memcpy(footer[4..12], &footer_tail);
    try io.writeBytes(writer, &footer);
}

fn checkSize(check: CheckType) usize {
    return switch (check) {
        .none => 0,
        .crc32 => 4,
        .crc64 => 8,
        .sha256 => 32,
    };
}
