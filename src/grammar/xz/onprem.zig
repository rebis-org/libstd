const std = @import("std");

const binary = @import("../../common/primitive/binary.zig");
const bounds = @import("../../common/primitive/bounds.zig");
const checksum = @import("../../common/primitive/checksum.zig");
const crypto = @import("../../common/primitive/crypto.zig");
const failure_prim = @import("../../common/primitive/failure.zig");
const io = @import("../../common/primitive/io.zig");
const measurement = @import("../../common/primitive/measurement.zig");
const tee = @import("../../common/primitive/tee.zig");
const bcj = @import("../../leaf/bcj/onprem.zig");
const deflate_seam = @import("../../leaf/deflate/seam.zig");
const delta = @import("../../leaf/delta/onprem.zig");
const lzma = @import("../../leaf/lzma/onprem.zig");
const lzma2 = @import("../../leaf/lzma2/onprem.zig");
const lzma2_seam = @import("../../leaf/lzma2/seam.zig");

const Failure = failure_prim.Failure;

pub const header_magic = [6]u8{ 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 };
pub const footer_magic = [2]u8{ 0x59, 0x5A };
pub const stream_header_size = 12;
pub const stream_footer_size = 12;
const delta_filter_id: u8 = 0x03;

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
    delta_distance: u8 = 1,
    match_finder_depth: u32 = 32,
    lazy: bool = false,
    nice_len: u32 = 273,
    match_finder: lzma.MatchFinder = .bt4,
    // 0 writes one block; otherwise the input splits into independent blocks
    // of this size, each with header, check, and index records.
    block_size: u32 = 0,
    provider: checksum.Provider = checksum.default_provider,
};

// Record scratch the multi-block index needs: one 16-byte (unpadded,
// uncompressed) pair per block. Callers add this to the encode workspace
// when Options.block_size is nonzero.
pub fn blockRecordScratchSize(input_len: usize, block_size: u32) usize {
    if (block_size == 0) return 0;
    const blocks = (input_len + block_size - 1) / block_size;
    return @max(1, blocks) * 16;
}

// One stream and one block fit the constant, and 1:1 filters add no bytes.
// Every additional block adds a bounded header, padding, check, and index
// record; 192 bytes covers the worst case with margin.
pub fn encodedSizeBound(input_len: usize, block_size: u32) usize {
    const base = lzma2.encodedSizeBound(input_len) +| 128;
    if (block_size == 0) return base;
    const blocks = (input_len + block_size - 1) / block_size;
    return base +| @max(1, blocks) *| 192;
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

pub fn decodedSize(input: []const u8, scratch: []u8, provider: checksum.Provider) Failure!usize {
    if (try scanStreamSize(input, provider)) |size| return size;
    var counter = measurement.Counter.init(null);
    var sink = Sink{ .writer = &counter.writer, .buffer = null };
    try decodeOutOfPlace(input, &sink, scratch, provider);
    return measurement.measuredLength(&counter);
}

fn scanStreamSize(input: []const u8, provider: checksum.Provider) Failure!?usize {
    var cursor = binary.ReadCursor.init(input);
    var total: u64 = 0;
    while (cursor.remaining() > 0) {
        const check = try decodeStreamHeader(&cursor, provider);
        // Append writes every backing slot and reads only below len, so undefined init is safe.
        var records: IndexRecordList = .{ .records = undefined };
        while (cursor.remaining() > 0 and cursor.buffer[cursor.pos] != 0x00) {
            const block_header = try decodeBlockHeader(&cursor, provider);
            const uncompressed_size = block_header.uncompressed_size orelse return null;
            const compressed_size = if (block_header.compressed_size) |size|
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
                        if (control != 0x01 and control != 0x02) return error.DataFailure;
                        const size_hi = try cursor.readU8();
                        const size_lo = try cursor.readU8();
                        try cursor.advance((@as(usize, size_hi) << 8 | size_lo) + 1);
                    }
                }
                break :blk cursor.pos - data_start;
            };
            try cursor.advance(blockPadding(compressed_size));
            try cursor.advance(checkSize(check));
            const unpadded_size = try bounds.addUsize(block_header.header_size, try bounds.addUsize(compressed_size, checkSize(check)));
            try records.append(.{
                .unpadded_size = std.math.cast(u64, unpadded_size) orelse return error.ResourceFailure,
                .uncompressed_size = @as(u64, uncompressed_size),
            });
            total = std.math.add(u64, total, uncompressed_size) catch return error.ResourceFailure;
        }
        const index_start = cursor.pos;
        try decodeIndex(&cursor, records, provider);
        const index_size = cursor.pos - index_start;
        try decodeStreamFooter(&cursor, check, index_size, provider);
        try skipStreamPadding(&cursor);
    }
    return std.math.cast(usize, total) orelse return error.ResourceFailure;
}

pub fn decode(input: []const u8, output: []u8, scratch: []u8, provider: checksum.Provider) Failure!usize {
    var sink = Sink{ .writer = null, .buffer = output };
    try decodeOutOfPlace(input, &sink, scratch, provider);
    return sink.offset;
}

pub fn decodeInPlace(input: []const u8, output: []u8, scratch: []u8, provider: checksum.Provider) Failure!usize {
    var sink = Sink{ .writer = null, .buffer = output };
    try decodeStreams(input, &sink, scratch, true, provider);
    return sink.offset;
}

const Sink = struct {
    writer: ?*std.Io.Writer,
    buffer: ?[]u8,
    offset: usize = 0,

    fn blockBuffer(self: *Sink, length: usize) Failure![]u8 {
        const buffer = self.buffer orelse return error.InternalFailure;
        if (length > buffer.len - self.offset) return error.CapacityFailure;
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

// Measurement-path writer: forwards to the downstream writer and hashes
// whatever passes through, so single-filter SHA-256 blocks verify on the
// streaming path instead of skipping their check. The digest state lives
// behind a pointer to keep this struct's layout writer-friendly.
const Sha256Tee = struct {
    writer: std.Io.Writer,
    downstream: *std.Io.Writer,
    sha256: *crypto.Sha256,
    size: u64,

    fn init(downstream: *std.Io.Writer, sha256: *crypto.Sha256) Sha256Tee {
        return .{
            .writer = .{ .vtable = &vtable, .buffer = &.{}, .end = 0 },
            .downstream = downstream,
            .sha256 = sha256,
            .size = 0,
        };
    }

    fn feed(self: *Sha256Tee, part: []const u8) std.Io.Writer.Error!void {
        self.downstream.writeAll(part) catch return error.WriteFailed;
        self.sha256.update(part);
    }

    fn drain(writer: *std.Io.Writer, chunks: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Sha256Tee = @fieldParentPtr("writer", writer);
        if (chunks.len == 0) return 0;
        var total: usize = 0;
        for (chunks[0 .. chunks.len - 1]) |part| total += part.len;
        total += chunks[chunks.len - 1].len * splat;
        if (total == 0) return 0;
        for (chunks[0 .. chunks.len - 1]) |part| try self.feed(part);
        const last = chunks[chunks.len - 1];
        for (0..splat) |_| try self.feed(last);
        self.size = std.math.add(u64, self.size, total) catch return error.WriteFailed;
        return total;
    }

    const vtable = std.Io.Writer.VTable{
        .drain = drain,
        .flush = std.Io.Writer.noopFlush,
        .rebase = std.Io.Writer.failingRebase,
    };
};

fn decodeOutOfPlace(input: []const u8, sink: *Sink, scratch: []u8, provider: checksum.Provider) Failure!void {
    try decodeStreams(input, sink, scratch, false, provider);
}

fn decodeStreams(input: []const u8, sink: *Sink, scratch: []u8, in_place: bool, provider: checksum.Provider) Failure!void {
    var cursor = binary.ReadCursor.init(input);
    while (cursor.remaining() > 0) {
        const check = try decodeStreamHeader(&cursor, provider);
        // Append writes every backing slot and reads only below len, so undefined init is safe.
        var records: IndexRecordList = .{ .records = undefined };
        while (true) {
            if (cursor.remaining() == 0 or cursor.buffer[cursor.pos] == 0x00) break;
            const record = try decodeBlock(&cursor, sink, scratch, check, in_place, provider);
            try records.append(record);
        }
        const index_start = cursor.pos;
        try decodeIndex(&cursor, records, provider);
        const index_size = cursor.pos - index_start;
        try decodeStreamFooter(&cursor, check, index_size, provider);
        try skipStreamPadding(&cursor);
    }
}

fn decodeStreamHeader(cursor: *binary.ReadCursor, provider: checksum.Provider) Failure!CheckType {
    const bytes = try cursor.readSlice(stream_header_size);
    if (!std.mem.eql(u8, bytes[0..6], &header_magic)) return error.DataFailure;
    const flags_crc = std.mem.readInt(u32, bytes[8..12], .little);
    try verifyCrc32(bytes[6..8], flags_crc, provider);
    if (bytes[6] != 0x00) return error.DataFailure;
    const check_type: u8 = bytes[7];
    if (check_type & 0xF0 != 0) return error.DataFailure;
    return checkTypeFromInt(check_type);
}

fn checkTypeFromInt(value: u8) Failure!CheckType {
    return switch (value) {
        0 => .none,
        1 => .crc32,
        4 => .crc64,
        0x0A => .sha256,
        else => error.UnsupportedFailure,
    };
}

fn verifyCrc32(bytes: []const u8, expected: u32, provider: checksum.Provider) Failure!void {
    var crc = checksum.Crc32.bind(provider);
    crc.update(bytes);
    if (crc.final() != expected) return error.IntegrityFailure;
}

const IndexRecord = struct {
    unpadded_size: u64,
    uncompressed_size: u64,
};

const max_index_records = 1024;

const IndexRecordList = struct {
    records: [max_index_records]IndexRecord,
    len: usize = 0,

    fn append(self: *IndexRecordList, record: IndexRecord) Failure!void {
        if (self.len >= self.records.len) return error.ResourceFailure;
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

fn decodeBlock(cursor: *binary.ReadCursor, sink: *Sink, scratch: []u8, check: CheckType, in_place: bool, provider: checksum.Provider) Failure!IndexRecord {
    const block_header = try decodeBlockHeader(cursor, provider);
    const compressed_data: ?[]const u8 = if (block_header.compressed_size) |size|
        try cursor.readSlice(size)
    else
        null;
    const dictionary_size = lzma2.dictionarySizeFromProperties(block_header.filters[block_header.filter_count - 1].lzma2);
    if (dictionary_size < lzma.dictionary_min or dictionary_size > lzma.dictionary_max) return error.UnsupportedFailure;
    const lzma_scratch_size = if (in_place) lzma2.decodeInPlaceWorkspaceSize(dictionary_size) else lzma2.decodeWorkspaceSize(dictionary_size);
    if (scratch.len < lzma_scratch_size) return error.CapacityFailure;
    const options = lzma2.Options{
        .dictionary_size = dictionary_size,
        .properties = lzma2.defaultProperties(dictionary_size),
        .max_work = std.math.maxInt(u64),
    };
    // Both sizes are assigned in every branch below before any read.
    var compressed_size: usize = undefined;
    var uncompressed_size: usize = undefined;
    var decode_tee: ?tee.Tee = null;
    if (sink.buffer != null) {
        const block_output = if (block_header.uncompressed_size) |size|
            try sink.blockBuffer(size)
        else
            sink.blockBufferRemaining();
        if (in_place) {
            const in_place_scratch_size = lzma2.decodeInPlaceWorkspaceSize(dictionary_size);
            if (scratch.len < in_place_scratch_size) return error.CapacityFailure;
            const result = try lzma2_seam.decodeInPlace(provider, if (compressed_data) |data| data else cursor.remainingSlice(), block_output, scratch[0..in_place_scratch_size], options);
            uncompressed_size = result.produced;
            compressed_size = block_header.compressed_size orelse result.consumed;
        } else {
            var fixed_writer = std.Io.Writer.fixed(block_output);
            var chunk_reader = std.Io.Reader.fixed(if (compressed_data) |data| data else cursor.remainingSlice());
            try lzma2_seam.decodeStream(provider, &chunk_reader, &fixed_writer, scratch[0..lzma2.decodeWorkspaceSize(dictionary_size)], options);
            compressed_size = block_header.compressed_size orelse chunk_reader.seek;
            uncompressed_size = fixed_writer.end;
        }
        if (block_header.uncompressed_size) |size| {
            if (uncompressed_size != size) return error.IntegrityFailure;
        }
        applyDecodeFilters(block_header.filters[0..block_header.filter_count], block_output[0..uncompressed_size]);
        sink.commitBlock(uncompressed_size);
    } else {
        var chunk_reader = std.Io.Reader.fixed(if (compressed_data) |data| data else cursor.remainingSlice());
        if (check == .sha256 and block_header.filter_count == 1) {
            // Single-filter SHA-256 blocks verify fully on the streaming path:
            // the check covers exactly the bytes observed here, with no filter
            // between decode and check.
            var sha256 = crypto.Sha256.bind(provider, .{});
            var hash_tee = Sha256Tee.init(sink.writer.?, &sha256);
            try lzma2_seam.decodeStream(provider, &chunk_reader, &hash_tee.writer, scratch[0..lzma_scratch_size], options);
            compressed_size = block_header.compressed_size orelse chunk_reader.seek;
            uncompressed_size = std.math.cast(usize, hash_tee.size) orelse return error.ResourceFailure;
            if (block_header.uncompressed_size) |size| {
                if (uncompressed_size != size) return error.IntegrityFailure;
            }
            const check_bytes = try cursor.readSlice(checkSize(check));
            var digest: [32]u8 = sha256.finalResult();
            if (!std.mem.eql(u8, &digest, check_bytes)) return error.IntegrityFailure;
        } else {
            decode_tee = tee.Tee.initWithProvider(sink.writer, provider);
            try lzma2_seam.decodeStream(provider, &chunk_reader, &decode_tee.?.writer, scratch[0..lzma_scratch_size], options);
            compressed_size = block_header.compressed_size orelse chunk_reader.seek;
            uncompressed_size = std.math.cast(usize, decode_tee.?.size) orelse return error.ResourceFailure;
            if (block_header.uncompressed_size) |size| {
                if (uncompressed_size != size) return error.IntegrityFailure;
            }
        }
    }
    if (block_header.compressed_size == null) try cursor.advance(compressed_size);
    try cursor.advance(blockPadding(compressed_size));
    if (sink.buffer != null) {
        const block_output = sink.buffer.?[sink.offset - uncompressed_size ..][0..uncompressed_size];
        const check_bytes = try cursor.readSlice(checkSize(check));
        try verifyFilteredCheck(check, block_output, check_bytes, provider);
    } else if (decode_tee) |*dt| {
        const check_bytes = try cursor.readSlice(checkSize(check));
        // Multi-filter streaming blocks cannot be verified without staging:
        // the check covers filtered bytes this path never materializes, and
        // staging would defeat the bounded memory the measurement oracle
        // exists for. Only decodedSize streams; every decode entry point
        // stages the block and verifies it above.
        if (block_header.filter_count == 1 and check != .sha256) {
            try verifyCheck(check, dt.crc32Value(), dt.crc64Value(), check_bytes);
        }
    }
    // The SHA-256 streaming branch consumed and verified its check bytes above.
    const unpadded_size = try bounds.addUsize(block_header.header_size, try bounds.addUsize(compressed_size, checkSize(check)));
    return .{
        .unpadded_size = std.math.cast(u64, unpadded_size) orelse return error.ResourceFailure,
        .uncompressed_size = @as(u64, uncompressed_size),
    };
}

fn decodeBlockHeader(cursor: *binary.ReadCursor, provider: checksum.Provider) Failure!BlockInfo {
    const header_start = cursor.pos;
    const size_byte = try cursor.readU8();
    const header_size = (@as(usize, size_byte & 0x3F) + 1) * 4;
    if (header_size < 8) return error.DataFailure;
    // The CRC covers the size byte, so a rewritten header size fails verification.
    const header_end = try bounds.addUsize(header_start, header_size);
    if (header_end > cursor.buffer.len) return error.DataFailure;
    const header_bytes = cursor.buffer[header_start..header_end];
    cursor.pos = header_end;
    const flags_byte = header_bytes[1];
    if (flags_byte & 0x3C != 0) return error.DataFailure;
    const has_compressed_size = (flags_byte & 0x40) != 0;
    const has_uncompressed_size = (flags_byte & 0x80) != 0;
    const requested_filter_count: usize = @as(usize, flags_byte & 0x03) + 1;
    const header_crc = std.mem.readInt(u32, header_bytes[header_size - 4 ..][0..4], .little);
    try verifyCrc32(header_bytes[0 .. header_size - 4], header_crc, provider);
    var sub = binary.ReadCursor.init(header_bytes[2 .. header_size - 4]);
    const compressed_size: ?usize = if (has_compressed_size) blk: {
        const value = try sub.readUleb128();
        if (value == 0) return error.DataFailure;
        break :blk std.math.cast(usize, value) orelse return error.ResourceFailure;
    } else null;
    const uncompressed_size: ?usize = if (has_uncompressed_size)
        std.math.cast(usize, try sub.readUleb128()) orelse return error.ResourceFailure
    else
        null;
    var dictionary_props: ?u8 = null;
    var filters: [4]Filter = undefined;
    var filter_count: usize = 0;
    for (0..requested_filter_count) |_| {
        const filter_id = try sub.readUleb128();
        const props_size = try sub.readUleb128();
        if (props_size > sub.remaining()) return error.DataFailure;
        switch (filter_id) {
            0x21 => {
                if (props_size != 1 or dictionary_props != null) return error.UnsupportedFailure;
                dictionary_props = try sub.readU8();
                filters[filter_count] = .{ .lzma2 = dictionary_props.? };
            },
            delta_filter_id => {
                if (props_size != 1) return error.UnsupportedFailure;
                filters[filter_count] = .{ .delta = try sub.readU8() };
            },
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B => {
                const kind: bcj.Kind = bcj.fromId(@intCast(filter_id)).?;
                const start_offset: u32 = if (props_size == 0) 0 else if (props_size == 4) blk: {
                    const props = try sub.readBytes(4);
                    break :blk std.mem.readInt(u32, &props, .little);
                } else return error.UnsupportedFailure;
                if (start_offset % bcj.alignment(kind) != 0) return error.DataFailure;
                filters[filter_count] = .{ .bcj = .{ .kind = kind, .start_offset = start_offset } };
            },
            else => {
                try sub.advance(props_size);
                return error.UnsupportedFailure;
            },
        }
        filter_count += 1;
    }
    while (sub.remaining() > 0) {
        if (try sub.readU8() != 0) return error.DataFailure;
    }
    if (filter_count == 0 or filters[filter_count - 1] != .lzma2) return error.UnsupportedFailure;
    return .{
        .header_size = header_size,
        .compressed_size = compressed_size,
        .uncompressed_size = uncompressed_size,
        .filters = filters,
        .filter_count = filter_count,
    };
}

fn applyDecodeFilters(filters: []const Filter, block: []u8) void {
    var index = filters.len;
    while (index > 1) {
        index -= 1;
        switch (filters[index - 1]) {
            .delta => |distance| delta.decode(block, distance),
            .bcj => |options| bcj.decode(options.kind, options.start_offset, block),
            .lzma2 => return,
        }
    }
}

fn verifyFilteredCheck(check: CheckType, block: []const u8, expected: []const u8, provider: checksum.Provider) Failure!void {
    if (check == .sha256) {
        var sha = crypto.Sha256.bind(provider, .{});
        sha.update(block);
        var digest: [32]u8 = undefined;
        digest = sha.finalResult();
        if (!std.mem.eql(u8, &digest, expected)) return error.IntegrityFailure;
        return;
    }
    switch (check) {
        .none => {},
        .crc32 => {
            var crc = checksum.Crc32.bind(provider);
            crc.update(block);
            const actual: u32 = crc.final();
            const stored = std.mem.readInt(u32, expected[0..4], .little);
            if (actual != stored) return error.IntegrityFailure;
        },
        .crc64 => {
            var crc = checksum.XzCrc64.bind(provider);
            crc.update(block);
            const actual: u64 = crc.final();
            const stored = std.mem.readInt(u64, expected[0..8], .little);
            if (actual != stored) return error.IntegrityFailure;
        },
        .sha256 => unreachable,
    }
}

fn decodeIndex(cursor: *binary.ReadCursor, records: IndexRecordList, provider: checksum.Provider) Failure!void {
    const index_start = cursor.pos;
    if (cursor.remaining() == 0 or cursor.buffer[cursor.pos] != 0x00) return error.DataFailure;
    _ = try cursor.readU8();
    const record_count = try cursor.readUleb128();
    if (record_count != records.len) return error.IntegrityFailure;
    for (records.slice()) |expected| {
        const unpadded = try cursor.readUleb128();
        const uncompressed = try cursor.readUleb128();
        if (unpadded != expected.unpadded_size or uncompressed != expected.uncompressed_size) return error.IntegrityFailure;
    }
    const content_size = cursor.pos - index_start;
    const padding = (4 - (content_size % 4)) % 4;
    for (0..padding) |_| {
        if (cursor.pos >= cursor.buffer.len or cursor.buffer[cursor.pos] != 0x00) return error.DataFailure;
        cursor.pos += 1;
    }
    const index_end = try bounds.addUsize(cursor.pos, 4);
    if (index_end > cursor.buffer.len) return error.DataFailure;
    const index_crc = std.mem.readInt(u32, cursor.buffer[cursor.pos..][0..4], .little);
    try verifyCrc32(cursor.buffer[index_start..cursor.pos], index_crc, provider);
    cursor.pos = index_end;
}

fn decodeStreamFooter(cursor: *binary.ReadCursor, check: CheckType, index_size: usize, provider: checksum.Provider) Failure!void {
    const footer = try cursor.readSlice(stream_footer_size);
    const footer_crc = std.mem.readInt(u32, footer[0..4], .little);
    try verifyCrc32(footer[4..10], footer_crc, provider);
    const backward_size: usize = std.mem.readInt(u32, footer[4..8], .little);
    if (index_size < 4 or index_size % 4 != 0) return error.IntegrityFailure;
    if (@as(u64, backward_size) + 1 != index_size / 4) return error.IntegrityFailure;
    if (footer[8] != 0x00) return error.DataFailure;
    const check_type: u8 = footer[9];
    if (check_type & 0xF0 != 0) return error.DataFailure;
    if (@backingInt(check) != check_type) return error.IntegrityFailure;
    if (!std.mem.eql(u8, footer[10..12], &footer_magic)) return error.DataFailure;
}

fn skipStreamPadding(cursor: *binary.ReadCursor) Failure!void {
    while (cursor.remaining() > 0 and cursor.buffer[cursor.pos] == 0x00) {
        if (cursor.remaining() < 4) return error.DataFailure;
        const padding = try cursor.readSlice(4);
        for (padding) |byte| {
            if (byte != 0) return error.DataFailure;
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
        .sha256 => return error.UnsupportedFailure,
    }
}

pub fn requiredSize(input: []const u8, scratch: []u8, options: Options) Failure!usize {
    var counter = measurement.Counter.init(null);
    try encodeInternal(input, &counter.writer, scratch, options);
    return measurement.measuredLength(&counter);
}

pub fn encode(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    var writer = std.Io.Writer.fixed(output);
    try encodeInternal(input, &writer, scratch, options);
    return writer.end;
}

fn encodeInternal(input: []const u8, writer: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    if (options.filters == .delta and (options.delta_distance < 1 or options.delta_distance > 255)) return error.CallFailure;
    // One LZMA2 encoder keeps the dictionary continuous instead of resetting it per chunk.
    try encodeStream(writer, input, scratch, options);
}

fn encodeStream(writer: *std.Io.Writer, input: []const u8, scratch: []u8, options: Options) Failure!void {
    if (options.block_size != 0 and options.block_size < 4096) return error.CallFailure;
    const dictionary_props = lzma2.propertiesFromDictionarySize(options.dictionary_size);
    const dictionary_size = lzma2.dictionarySizeFromProperties(dictionary_props);
    const lzma_scratch_size = if (options.match_finder == .bt4) lzma2.encodeWorkspaceSizeBt(dictionary_size) else lzma2.encodeWorkspaceSize(dictionary_size);
    // The index needs one (unpadded, uncompressed) pair per block even for
    // the single-block default, so the record carve is never empty.
    const record_size = @max(16, blockRecordScratchSize(input.len, options.block_size));
    if (scratch.len < lzma_scratch_size + record_size) return error.CapacityFailure;
    const lzma_scratch = scratch[0..lzma_scratch_size];
    const remaining_scratch = scratch[lzma_scratch_size..];
    const records = remaining_scratch[0..record_size];
    const lzma_options = lzma2.Options{
        .dictionary_size = dictionary_size,
        .properties = lzma2.defaultProperties(dictionary_size),
        .max_work = std.math.maxInt(u64),
        .match_finder_depth = options.match_finder_depth,
        .lazy = options.lazy,
        .nice_len = options.nice_len,
        .match_finder = options.match_finder,
    };
    const filtered = if (options.filters != .none) blk: {
        if (remaining_scratch.len < record_size + input.len) return error.CapacityFailure;
        const buffer = remaining_scratch[record_size..][0..input.len];
        @memcpy(buffer, input);
        try applyEncodeFilter(options.filters, options.delta_distance, buffer);
        break :blk buffer;
    } else input;
    try writeStreamHeader(writer, options.check, options.provider);
    const check_size = checkSize(options.check);
    const chunk_count: usize = if (options.block_size == 0) 1 else @max(1, (input.len + options.block_size - 1) / options.block_size);
    var chunk_start: usize = 0;
    for (0..chunk_count) |chunk_index| {
        const chunk_end = if (options.block_size == 0) input.len else @min(input.len, chunk_start + options.block_size);
        const chunk = if (options.filters != .none) filtered[chunk_start..chunk_end] else input[chunk_start..chunk_end];
        const plain_chunk = input[chunk_start..chunk_end];
        const block_header = try buildBlockHeader(plain_chunk.len, dictionary_props, options.filters, options.delta_distance, options.provider);
        try io.writeBytes(writer, block_header.slice());
        var count_tee = tee.Tee.initWithProvider(writer, options.provider);
        try lzma2.encodeToWriter(chunk, &count_tee.writer, lzma_scratch, lzma_options);
        const compressed_size = std.math.cast(usize, count_tee.size) orelse return error.ResourceFailure;
        const block_padding = blockPadding(compressed_size);
        if (block_padding > 0) {
            const zeroes: [3]u8 = @splat(0);
            try io.writeBytes(writer, zeroes[0..block_padding]);
        }
        var tee_writer = tee.Tee.initWithProvider(null, options.provider);
        _ = tee_writer.writer.write(plain_chunk) catch return error.IoFailure;
        if (options.check == .sha256) {
            var sha = crypto.Sha256.bind(options.provider, .{});
            sha.update(plain_chunk);
            var digest: [32]u8 = undefined;
            digest = sha.finalResult();
            try io.writeBytes(writer, &digest);
        } else {
            try writeCheck(writer, options.check, tee_writer.crc32Value(), tee_writer.crc64Value());
        }
        const unpadded = try bounds.addUsize(block_header.slice().len, try bounds.addUsize(compressed_size, check_size));
        std.mem.writeInt(u64, records[chunk_index * 16 ..][0..8], std.math.cast(u64, unpadded) orelse return error.ResourceFailure, .little);
        std.mem.writeInt(u64, records[chunk_index * 16 ..][8..16], std.math.cast(u64, plain_chunk.len) orelse return error.ResourceFailure, .little);
        chunk_start = chunk_end;
    }
    const index_size = try writeIndex(writer, records[0 .. chunk_count * 16], options.provider);
    try writeStreamFooter(writer, options.check, index_size, options.provider);
}

fn applyEncodeFilter(filter: FilterChoice, delta_distance: u8, buffer: []u8) Failure!void {
    switch (filter) {
        .none => {},
        .delta => delta.encode(buffer, delta_distance),
        .x86, .ppc, .ia64, .arm, .armt, .sparc, .arm64, .riscv => bcj.encode(bcjKindFromChoice(filter), 0, buffer),
    }
}

fn bcjKindFromChoice(filter: FilterChoice) bcj.Kind {
    // The choice enum is dense and the wire ids are not, so the delta id anchors
    // the offset and the leaf owns the other end of it.
    return bcj.fromId(@intCast(@backingInt(filter) + delta_filter_id - @backingInt(FilterChoice.delta))).?;
}

fn writeStreamHeader(writer: *std.Io.Writer, check: CheckType, provider: checksum.Provider) Failure!void {
    const flags_bytes = [_]u8{ 0x00, @backingInt(check) };
    var crc = checksum.Crc32.bind(provider);
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

fn buildBlockHeader(uncompressed_size: usize, dictionary_props: u8, filters: FilterChoice, delta_distance: u8, provider: checksum.Provider) Failure!BlockHeader {
    var content: [60]u8 = undefined;
    var cursor = binary.WriteCursor.init(&content);
    cursor.writeUleb128(uncompressed_size) catch return error.InternalFailure;
    if (filters != .none) {
        cursor.writeUleb128(filterId(filters)) catch return error.InternalFailure;
        cursor.writeUleb128(filterPropsSize(filters)) catch return error.InternalFailure;
        if (filters == .delta) cursor.writeU8(delta_distance) catch return error.InternalFailure;
    }
    cursor.writeUleb128(0x21) catch return error.InternalFailure;
    cursor.writeUleb128(1) catch return error.InternalFailure;
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
    var crc = checksum.Crc32.bind(provider);
    crc.update(header.bytes[0..index]);
    std.mem.writeInt(u32, header.bytes[index..][0..4], crc.final(), .little);
    return header;
}

fn filterId(filter: FilterChoice) u64 {
    return if (filter == .delta)
        delta_filter_id
    else
        @backingInt(bcjKindFromChoice(filter));
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

fn writeIndex(writer: *std.Io.Writer, records: []const u8, provider: checksum.Provider) Failure!usize {
    var crc = checksum.Crc32.bind(provider);
    var content_size: usize = 0;
    var indicator = [_]u8{0x00};
    try io.writeBytes(writer, &indicator);
    crc.update(&indicator);
    content_size += 1;
    var count_buf: [10]u8 = undefined;
    const count_len = uleb128(records.len / 16, &count_buf);
    try io.writeBytes(writer, count_buf[0..count_len]);
    crc.update(count_buf[0..count_len]);
    content_size += count_len;
    var number_buf: [10]u8 = undefined;
    for (0..records.len / 16) |index| {
        const unpadded = std.mem.readInt(u64, records[index * 16 ..][0..8], .little);
        const unpacked = std.mem.readInt(u64, records[index * 16 ..][8..16], .little);
        const unpadded_len = uleb128(unpadded, &number_buf);
        try io.writeBytes(writer, number_buf[0..unpadded_len]);
        crc.update(number_buf[0..unpadded_len]);
        content_size += unpadded_len;
        const unpacked_len = uleb128(unpacked, &number_buf);
        try io.writeBytes(writer, number_buf[0..unpacked_len]);
        crc.update(number_buf[0..unpacked_len]);
        content_size += unpacked_len;
    }
    const padding = blockPadding(content_size);
    if (padding > 0) {
        const zeroes: [3]u8 = @splat(0);
        try io.writeBytes(writer, zeroes[0..padding]);
        crc.update(zeroes[0..padding]);
    }
    var crc_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &crc_bytes, crc.final(), .little);
    try io.writeBytes(writer, &crc_bytes);
    return content_size + padding + 4;
}

fn uleb128(value: u64, buffer: *[10]u8) usize {
    var v = value;
    var len: usize = 0;
    while (true) {
        var byte: u8 = @truncate(v & 0x7F);
        v >>= 7;
        if (v != 0) byte |= 0x80;
        buffer[len] = byte;
        len += 1;
        if (v == 0) break;
    }
    return len;
}

fn writeStreamFooter(writer: *std.Io.Writer, check: CheckType, index_size: usize, provider: checksum.Provider) Failure!void {
    if (index_size < 4 or index_size % 4 != 0) return error.InternalFailure;
    const backward_size = (index_size / 4) - 1;
    const backward_size_u32 = std.math.cast(u32, backward_size) orelse return error.InternalFailure;
    var footer_tail: [8]u8 = undefined;
    std.mem.writeInt(u32, footer_tail[0..4], backward_size_u32, .little);
    footer_tail[4] = 0x00;
    footer_tail[5] = @backingInt(check);
    footer_tail[6] = footer_magic[0];
    footer_tail[7] = footer_magic[1];
    var crc = checksum.Crc32.bind(provider);
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

test "xz delta filter honors the requested distance" {
    // A mixed provider build serves no single tag for both the checksum
    // and codec arms; run where the default tag serves the codec.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;
    const allocator = std.testing.allocator;
    var input: [512]u8 = undefined;
    for (&input, 0..) |*byte, i| byte.* = @truncate(i *% 7 +% 3);
    const dictionary_size: u32 = 1 << 20;
    const scratch = try allocator.alloc(u8, encodeWorkspaceSizeBt(dictionary_size));
    defer allocator.free(scratch);
    const options: Options = .{
        .dictionary_size = dictionary_size,
        .check = .crc32,
        .filters = .delta,
        .delta_distance = 4,
    };
    const bound = encodedSizeBound(input.len, options.block_size);
    const encoded = try allocator.alloc(u8, bound);
    defer allocator.free(encoded);
    const encoded_len = try encode(&input, encoded, scratch, options);

    const decode_scratch = try allocator.alloc(u8, decodeWorkspaceSize(dictionary_size));
    defer allocator.free(decode_scratch);
    const output = try allocator.alloc(u8, input.len);
    defer allocator.free(output);
    const decoded = try decode(encoded[0..encoded_len], output, decode_scratch, checksum.default_provider);
    try std.testing.expectEqualSlices(u8, &input, output[0..decoded]);

    // The delta distance is carried in the block header, not hardcoded to 1.
    const header = findBlockHeader(encoded[0..encoded_len]) orelse return error.TestUnexpectedError;
    try std.testing.expectEqual(@as(u8, 4), header);
}

test "xz delta filter rejects zero distance" {
    var input: [16]u8 = @splat(1);
    var output: [256]u8 = undefined;
    var scratch: [4096]u8 = undefined;
    const options: Options = .{
        .dictionary_size = 1 << 20,
        .check = .crc32,
        .filters = .delta,
        .delta_distance = 0,
    };
    try std.testing.expectError(error.CallFailure, encode(&input, &output, &scratch, options));
}

// The delta filter props byte lives in the first block header, after the
// ULEB128 uncompressed size and the filter id / props-size bytes.
fn findBlockHeader(stream: []const u8) ?u8 {
    if (stream.len < 16) return null;
    const header_size = @as(usize, stream[12]) * 4;
    const end = 12 + header_size;
    if (stream.len < end) return null;
    var i: usize = 13;
    while (i < end and (stream[i] & 0x80) != 0) i += 1;
    i += 1; // final ULEB size byte
    if (i + 2 >= end) return null;
    if (stream[i] != 0x03 or stream[i + 1] != 1) return null;
    return stream[i + 2];
}

test "xz multi-block output roundtrips through our decoder and the index" {
    // A mixed provider build serves no single tag for both the checksum
    // and codec arms; run where the default tag serves the codec.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;
    const allocator = std.testing.allocator;
    var input: [100 * 1024]u8 = undefined;
    for (&input, 0..) |*byte, i| byte.* = @truncate(i *% 31 +% (i >> 7));
    const dictionary_size: u32 = 1 << 20;
    const options: Options = .{
        .dictionary_size = dictionary_size,
        .check = .crc32,
        .block_size = 32 * 1024,
    };
    const scratch = try allocator.alloc(u8, encodeWorkspaceSizeBt(dictionary_size) + blockRecordScratchSize(input.len, options.block_size));
    defer allocator.free(scratch);
    const bound = encodedSizeBound(input.len, options.block_size);
    const encoded = try allocator.alloc(u8, bound);
    defer allocator.free(encoded);
    const encoded_len = try encode(&input, encoded, scratch, options);

    const decode_scratch = try allocator.alloc(u8, decodeWorkspaceSize(dictionary_size));
    defer allocator.free(decode_scratch);
    const output = try allocator.alloc(u8, input.len);
    defer allocator.free(output);
    const decoded = try decode(encoded[0..encoded_len], output, decode_scratch, checksum.default_provider);
    try std.testing.expectEqualSlices(u8, &input, output[0..decoded]);

    // The index names four blocks (three full, one remainder).
    const footer = encoded_len - stream_footer_size;
    const backward_size = @as(usize, std.mem.readInt(u32, encoded[footer + 4 ..][0..4], .little)) + 1;
    const index_size = backward_size * 4;
    const index = encoded[footer - index_size .. footer];
    try std.testing.expectEqual(@as(u8, 0x00), index[0]);
    try std.testing.expectEqual(@as(u8, 4), index[1]);

    // The block size floor is enforced.
    var rejected: Options = options;
    rejected.block_size = 1024;
    try std.testing.expectError(error.CallFailure, encode(&input, encoded, scratch, rejected));
}

pub const BlockRecord = struct {
    unpadded_size: u64,
    uncompressed_size: u64,
};

// Blocks decode into a discard sink — headerless streams still walk;
// `records` bounds the count, overflow answers resource_limit.
pub fn inspectBlocks(input: []const u8, records: []BlockRecord, scratch: []u8, provider: checksum.Provider) Failure!usize {
    var cursor = binary.ReadCursor.init(input);
    const check = try decodeStreamHeader(&cursor, provider);
    var counter = measurement.Counter.init(null);
    var sink = Sink{ .writer = &counter.writer, .buffer = null };
    var count: usize = 0;
    while (true) {
        if (cursor.remaining() == 0 or cursor.buffer[cursor.pos] == 0x00) break;
        const record = try decodeBlock(&cursor, &sink, scratch, check, false, provider);
        if (count >= records.len) return error.ResourceFailure;
        records[count] = .{ .unpadded_size = record.unpadded_size, .uncompressed_size = record.uncompressed_size };
        count += 1;
    }
    return count;
}

test "inspectBlocks enumerates a multi-block stream" {
    // A mixed provider build serves no single tag for both the checksum
    // and codec arms; run where the default tag serves the codec.
    if (!deflate_seam.decodeServed(checksum.default_provider)) return;
    const allocator = std.testing.allocator;
    var input: [100 * 1024]u8 = undefined;
    for (&input, 0..) |*byte, i| byte.* = @truncate(i *% 31 +% (i >> 7));
    const dictionary_size: u32 = 1 << 20;
    const options: Options = .{
        .dictionary_size = dictionary_size,
        .check = .crc32,
        .block_size = 32 * 1024,
    };
    const scratch = try allocator.alloc(u8, encodeWorkspaceSizeBt(dictionary_size) + blockRecordScratchSize(input.len, options.block_size));
    defer allocator.free(scratch);
    const encoded = try allocator.alloc(u8, encodedSizeBound(input.len, options.block_size));
    defer allocator.free(encoded);
    const encoded_len = try encode(&input, encoded, scratch, options);
    const decode_scratch = try allocator.alloc(u8, decodeWorkspaceSize(dictionary_size));
    defer allocator.free(decode_scratch);

    var records: [8]BlockRecord = undefined;
    const count = try inspectBlocks(encoded[0..encoded_len], &records, decode_scratch, checksum.default_provider);
    try std.testing.expectEqual(@as(usize, 4), count);
    var total: u64 = 0;
    for (records[0..count]) |record| {
        try std.testing.expect(record.unpadded_size > 0 and record.uncompressed_size > 0);
        total += record.uncompressed_size;
    }
    try std.testing.expectEqual(@as(u64, input.len), total);
}
