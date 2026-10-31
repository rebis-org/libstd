const std = @import("std");

const binary = @import("../../../common/primitive/binary.zig");
const bounds = @import("../../../common/primitive/bounds.zig");
const checksum = @import("../../../common/primitive/checksum.zig");
const crypto = @import("../../../common/primitive/crypto.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const io = @import("../../../common/primitive/io.zig");
const deflate = @import("../../leaf/deflate/onprem.zig");
const deflate_seam = @import("../../leaf/deflate/seam.zig");
const lzma = @import("../../leaf/lzma/onprem.zig");
const lzma2 = @import("../../leaf/lzma2/onprem.zig");
const xz = @import("../xz/onprem.zig");

const Exception = exception_prim.Exception;

// A located member of gzip, xz, or stored bytes over cpio.
// Engines live in stable slots; pointers never move.

// The gzip member header and trailer.
const gzip_magic_1 = 0x1f;
const gzip_magic_2 = 0x8b;
const gzip_header_size = 10;
const gzip_cm_deflate = 8;
const gzip_flag_header_crc = 0x02;
const gzip_flag_extra = 0x04;
const gzip_flag_name = 0x08;
const gzip_flag_comment = 0x10;
const gzip_reserved_flags = 0xe0;
const gzip_trailer_len = 8;

// The lzma2 chunk controls and bounds.
const control_end: u8 = 0x00;
const control_copy_reset_dict: u8 = 0x01;
const control_copy: u8 = 0x02;
const control_lzma: u8 = 0x80;
const control_lzma_reset_state: u8 = 0xA0;
const control_lzma_new_props: u8 = 0xC0;
const control_lzma_new_props_reset_dict: u8 = 0xE0;
const max_pack_size = 1 << 16;

// The lzma2 filter id.
const filter_id_lzma2 = 0x21;

// The decode window: one xz chunk or the gzip history plus stage.
const window_size: usize = lzma2.chunk_max_unpacked;

// The xz dictionary the transform budgets for; the value is what
// pkgbuild writes.
const dictionary_seed: u32 = 8 << 20;
const xz_workspace_size: usize = blk: {
    @setEvalBranchQuota(1_000_000);
    break :blk lzma.decodeWorkspaceSize(lzma2.defaultProperties(dictionary_seed));
};

fn checkSize(check: xz.CheckType) usize {
    return switch (check) {
        .none => 0,
        .crc32 => 4,
        .crc64 => 8,
        .sha256 => 32,
    };
}

fn checkTypeFromInt(value: u8) Exception!xz.CheckType {
    return switch (value) {
        0 => .none,
        1 => .crc32,
        4 => .crc64,
        0x0A => .sha256,
        else => error.UnsupportedException,
    };
}

fn blockPadding(data_size: u64) u64 {
    const rem = data_size % 4;
    return if (rem == 0) 0 else 4 - rem;
}

fn verifyCrc32(bytes: []const u8, expected: u32) Exception!void {
    var crc = checksum.Crc32.bind(checksum.default_provider, {});
    crc.update(bytes);
    if (crc.final({}) != expected) return error.IntegrityException;
}

const IndexRecord = struct {
    unpadded_size: u64,
    uncompressed_size: u64,
};

const max_index_records = 1024;

const IndexRecordList = struct {
    records: [max_index_records]IndexRecord,
    len: usize = 0,

    fn append(self: *align(1) IndexRecordList, record: IndexRecord) Exception!void {
        if (self.len >= self.records.len) return error.ResourceException;
        self.records[self.len] = record;
        self.len += 1;
    }

    fn slice(self: *align(1) const IndexRecordList) []align(1) const IndexRecord {
        return self.records[0..self.len];
    }
};

// A read stops only when the destination fills; a payload that ends
// early is truncated.
fn parseGzipHeader(input: []const u8, at: usize) Exception!usize {
    if (input.len - at < gzip_header_size) return error.DataException;
    const fixed = input[at..][0..gzip_header_size];
    if (fixed[0] != gzip_magic_1 or fixed[1] != gzip_magic_2) return error.DataException;
    if (fixed[2] != gzip_cm_deflate) return error.UnsupportedException;
    const flags = fixed[3];
    if (flags & gzip_reserved_flags != 0) return error.DataException;
    var hasher = checksum.Crc32.bind(checksum.default_provider, {});
    hasher.update(fixed);
    var cursor = at + gzip_header_size;
    if (flags & gzip_flag_extra != 0) {
        if (input.len - cursor < 2) return error.DataException;
        const extra_len: usize = (@as(usize, input[cursor + 1]) << 8) | input[cursor];
        hasher.update(input[cursor..][0..2]);
        cursor += 2;
        if (input.len - cursor < extra_len) return error.DataException;
        hasher.update(input[cursor..][0..extra_len]);
        cursor += extra_len;
    }
    if (flags & gzip_flag_name != 0) {
        const end = std.mem.findScalarPos(u8, input, cursor, 0) orelse return error.DataException;
        hasher.update(input[cursor .. end + 1]);
        cursor = end + 1;
    }
    if (flags & gzip_flag_comment != 0) {
        const end = std.mem.findScalarPos(u8, input, cursor, 0) orelse return error.DataException;
        hasher.update(input[cursor .. end + 1]);
        cursor = end + 1;
    }
    if (flags & gzip_flag_header_crc != 0) {
        if (input.len - cursor < 2) return error.DataException;
        const stored_crc = (@as(u16, input[cursor + 1]) << 8) | input[cursor];
        if (stored_crc != @as(u16, @truncate(hasher.final({})))) return error.IntegrityException;
        cursor += 2;
    }
    return cursor;
}

const GzipState = struct {
    input: []const u8,
    data_start: usize,
    member_done: bool,
    eof: bool,
    member_size: u64,
    history: []u8,
    stage: []u8,
    stage_pos: usize,
    stage_len: usize,
    inflater: []deflate_seam.Decode,
    crc: []checksum.Crc32,
    members: u64,

    fn init(input: []const u8, inflater: []deflate_seam.Decode, crc: []checksum.Crc32, window: []u8) Exception!GzipState {
        const header_end = try parseGzipHeader(input, 0);
        var self = GzipState{
            .input = input,
            .data_start = header_end,
            .member_done = false,
            .eof = false,
            .member_size = 0,
            .history = window[0..deflate.history_size],
            .stage = window[deflate.history_size..],
            .stage_pos = 0,
            .stage_len = 0,
            .inflater = inflater,
            .crc = crc,
            .members = 0,
        };
        try self.newMember();
        return self;
    }

    fn newMember(self: *align(1) GzipState) Exception!void {
        try self.inflater[0].initSliceBoundInPlace(deflate_seam.default_provider, self.input[self.data_start..], self.history);
        self.crc[0] = checksum.Crc32.bind(checksum.default_provider, {});
    }

    // A fill stages inflater output and ends the member at the
    // end-of-stream marker.
    fn fill(self: *align(1) GzipState) Exception!void {
        var sink = std.Io.Writer.fixed(self.stage);
        const produced = self.inflater[0].streamTo(&sink, std.Io.Limit.limited64(self.stage.len)) catch |err| switch (err) {
            error.EndOfStream => {
                self.member_done = true;
                self.stage_pos = 0;
                self.stage_len = 0;
                return;
            },
            else => return error.DataException,
        };
        // A fill that stages nothing without the end marker is a livelock.
        if (produced == 0) return error.DataException;
        self.crc[0].update(self.stage[0..produced]);
        self.member_size += produced;
        self.stage_pos = 0;
        self.stage_len = produced;
    }

    fn finishMember(self: *align(1) GzipState) Exception!void {
        const consumed = (self.inflater[0].inputBitsConsumed() + 7) / 8;
        const trailer_at = try bounds.addUsize(self.data_start, consumed);
        if (self.input.len - trailer_at < gzip_trailer_len) return error.DataException;
        const stored_crc = std.mem.readInt(u32, self.input[trailer_at..][0..4], .little);
        const stored_size = std.mem.readInt(u32, self.input[trailer_at + 4 ..][0..4], .little);
        if (stored_crc != self.crc[0].final({})) return error.IntegrityException;
        if (stored_size != @as(u32, @truncate(self.member_size))) return error.IntegrityException;
        self.members += 1;
        self.member_done = false;
        self.member_size = 0;
        self.stage_pos = 0;
        self.stage_len = 0;
        const at = try bounds.addUsize(trailer_at, gzip_trailer_len);
        if (at == self.input.len) {
            self.eof = true;
            return;
        }
        self.data_start = try parseGzipHeader(self.input, at);
        try self.newMember();
    }

    fn read(self: *align(1) GzipState, destination: []u8) Exception!usize {
        var written: usize = 0;
        while (written < destination.len) {
            if (self.stage_pos < self.stage_len) {
                const step = @min(self.stage_len - self.stage_pos, destination.len - written);
                @memcpy(destination[written..][0..step], self.stage[self.stage_pos..][0..step]);
                self.stage_pos += step;
                written += step;
                continue;
            }
            if (self.member_done) {
                try self.finishMember();
                continue;
            }
            if (self.eof) return error.DataException;
            try self.fill();
        }
        return written;
    }

    fn drop(self: *align(1) GzipState, count: u64) Exception!void {
        var remaining: usize = std.math.cast(usize, count) orelse return error.ResourceException;
        while (remaining > 0) {
            if (self.stage_pos < self.stage_len) {
                const step = @min(self.stage_len - self.stage_pos, remaining);
                self.stage_pos += step;
                remaining -= step;
                continue;
            }
            if (self.member_done) {
                try self.finishMember();
                continue;
            }
            if (self.eof) return error.DataException;
            try self.fill();
        }
    }
};

const XzState = struct {
    input: []const u8,
    pos: usize,
    eof: bool,
    check: xz.CheckType,
    expect_stream_header: bool,
    in_block: bool,
    header_size: usize,
    compressed_bound: ?usize,
    uncompressed_bound: ?usize,
    block_data_start: usize,
    block_compressed: usize,
    block_uncompressed: usize,
    need_props: bool,
    need_dict_reset: bool,
    dict_size: u32,
    serve: []u8,
    serve_pos: usize,
    serve_len: usize,
    decoder: []lzma.DecoderOf(true),
    crc32: []checksum.Crc32,
    crc64: []checksum.XzCrc64,
    sha256: []crypto.Sha256,
    records: IndexRecordList,
    workspace: []u8,
    blocks: u64,

    fn init(input: []const u8, decoder: []lzma.DecoderOf(true), crc32s: []checksum.Crc32, crc64s: []checksum.XzCrc64, sha256s: []crypto.Sha256, window: []u8, workspace: []u8) Exception!XzState {
        var self = XzState{
            .input = input,
            .pos = 0,
            .eof = false,
            .check = .none,
            .expect_stream_header = false,
            .in_block = false,
            .header_size = 0,
            .compressed_bound = null,
            .uncompressed_bound = null,
            .block_data_start = 0,
            .block_compressed = 0,
            .block_uncompressed = 0,
            .need_props = true,
            .need_dict_reset = true,
            .dict_size = 0,
            .serve = window,
            .serve_pos = 0,
            .serve_len = 0,
            .decoder = decoder,
            .crc32 = crc32s,
            .crc64 = crc64s,
            .sha256 = sha256s,
            .records = .{ .records = undefined },
            .workspace = workspace,
            .blocks = 0,
        };
        try self.startStream();
        return self;
    }

    fn startStream(self: *align(1) XzState) Exception!void {
        if (self.input.len - self.pos < xz.stream_header_size) return error.DataException;
        const header = self.input[self.pos..][0..xz.stream_header_size];
        if (!std.mem.eql(u8, header[0..6], &xz.header_magic)) return error.DataException;
        const flags_crc = std.mem.readInt(u32, header[8..12], .little);
        try verifyCrc32(header[6..8], flags_crc);
        if (header[6] != 0x00) return error.DataException;
        const check_type = header[7];
        if (check_type & 0xF0 != 0) return error.DataException;
        self.check = try checkTypeFromInt(check_type);
        self.records = .{ .records = undefined };
        self.pos += xz.stream_header_size;
    }

    // A block header declares one plain lzma2 filter; a pkg payload
    // never carries a delta or bcj chain.
    fn startBlock(self: *align(1) XzState) Exception!void {
        const header_start = self.pos;
        if (self.pos >= self.input.len) return error.DataException;
        const size_byte = self.input[self.pos];
        const header_size = (@as(usize, size_byte & 0x3F) + 1) * 4;
        if (header_size < 8) return error.DataException;
        const header_end = try bounds.addUsize(header_start, header_size);
        if (header_end > self.input.len) return error.DataException;
        const header_bytes = self.input[header_start..header_end];
        const flags_byte = header_bytes[1];
        if (flags_byte & 0x3C != 0) return error.DataException;
        if (flags_byte & 0x03 != 0) return error.UnsupportedException;
        const has_compressed_size = (flags_byte & 0x40) != 0;
        const has_uncompressed_size = (flags_byte & 0x80) != 0;
        const header_crc = std.mem.readInt(u32, header_bytes[header_size - 4 ..][0..4], .little);
        try verifyCrc32(header_bytes[0 .. header_size - 4], header_crc);
        var sub = binary.ReadCursor.init(header_bytes[2 .. header_size - 4]);
        const compressed_bound: ?usize = if (has_compressed_size) blk: {
            const value = try sub.readUleb128();
            if (value == 0) return error.DataException;
            break :blk std.math.cast(usize, value) orelse return error.ResourceException;
        } else null;
        const uncompressed_bound: ?usize = if (has_uncompressed_size)
            std.math.cast(usize, try sub.readUleb128()) orelse return error.ResourceException
        else
            null;
        const filter_id = try sub.readUleb128();
        const props_size = try sub.readUleb128();
        if (props_size > sub.remaining()) return error.DataException;
        if (filter_id != filter_id_lzma2) return error.UnsupportedException;
        if (props_size != 1) return error.UnsupportedException;
        const props_byte = try sub.readU8();
        while (sub.remaining() > 0) {
            if (try sub.readU8() != 0) return error.DataException;
        }
        const dict_size = lzma2.dictionarySizeFromProperties(props_byte);
        if (dict_size < lzma.dictionary_min or dict_size > lzma.dictionary_max) return error.UnsupportedException;
        // The workspace is the transform budget: a block that declares a
        // bigger dictionary is a capacity failure, not corrupt data.
        if (self.workspace.len < lzma.decodeWorkspaceSize(lzma2.defaultProperties(dict_size))) return error.CapacityException;
        self.decoder[0] = try lzma.DecoderOf(true).initProperties(lzma2.defaultProperties(dict_size), self.workspace);
        self.crc32[0] = checksum.Crc32.bind(checksum.default_provider, {});
        self.crc64[0] = checksum.XzCrc64.bind(checksum.default_provider, {});
        self.sha256[0] = crypto.Sha256.bind(checksum.default_provider, .{});
        self.pos = header_end;
        self.header_size = header_size;
        self.compressed_bound = compressed_bound;
        self.uncompressed_bound = uncompressed_bound;
        self.block_data_start = header_end;
        self.block_compressed = 0;
        self.block_uncompressed = 0;
        self.need_props = true;
        self.need_dict_reset = true;
        self.dict_size = dict_size;
        self.in_block = true;
        self.serve_pos = 0;
        self.serve_len = 0;
    }

    // The check accumulates before any take or discard drains;
    // a skipped record still feeds it.
    fn accumulate(self: *align(1) XzState) void {
        switch (self.check) {
            .none => {},
            .crc32 => self.crc32[0].update(self.serve[0..self.serve_len]),
            .crc64 => self.crc64[0].update(self.serve[0..self.serve_len]),
            .sha256 => self.sha256[0].update(self.serve[0..self.serve_len]),
        }
    }

    fn decodeChunk(self: *align(1) XzState, control: u8) Exception!void {
        if (control >= control_lzma_new_props_reset_dict or control == control_copy_reset_dict) {
            self.need_props = true;
            self.need_dict_reset = true;
        } else if (self.need_dict_reset) {
            return error.DataException;
        }
        if (control & 0x80 != 0) {
            if (self.input.len - self.pos < 4) return error.DataException;
            const unpack = ((@as(usize, control & 0x1F) << 16) | (@as(usize, self.input[self.pos]) << 8) | self.input[self.pos + 1]) + 1;
            const pack = (@as(usize, self.input[self.pos + 2]) << 8 | self.input[self.pos + 3]) + 1;
            if (unpack > lzma2.chunk_max_unpacked) return error.DataException;
            if (pack < 5 or pack > max_pack_size) return error.DataException;
            self.pos += 4;
            if (control >= control_lzma_new_props) {
                if (self.pos >= self.input.len) return error.DataException;
                const parsed = try lzma.Properties.decode(self.input[self.pos], self.dict_size);
                if (parsed.lc + parsed.lp > 4) return error.UnsupportedException;
                self.decoder[0].setProperties(parsed);
                self.need_props = false;
                self.decoder[0].resetState();
                self.decoder[0].resetProbabilities();
                if (control >= control_lzma_new_props_reset_dict) {
                    self.decoder[0].resetDictionary();
                    self.need_dict_reset = false;
                }
                self.pos += 1;
            } else {
                if (self.need_props) return error.DataException;
                if (control >= control_lzma_reset_state) {
                    self.decoder[0].resetState();
                    self.decoder[0].resetProbabilities();
                }
                if (self.need_dict_reset) {
                    self.decoder[0].resetDictionary();
                    self.need_dict_reset = false;
                }
            }
            const packed_data = try bounds.slice(self.input, self.pos, pack);
            self.pos += pack;
            try self.decoder[0].resetReaderSlice(packed_data);
            try self.decoder[0].decodeToOutput(self.serve[0..unpack], unpack, false);
            self.serve_pos = 0;
            self.serve_len = unpack;
            // The control, the two size fields, the properties byte, and
            // the packed data all belong to the compressed size.
            self.block_compressed += 5 + pack;
            self.block_uncompressed += unpack;
            if (control >= control_lzma_new_props) self.block_compressed += 1;
        } else {
            if (control != control_copy_reset_dict and control != control_copy) return error.DataException;
            if (self.input.len - self.pos < 2) return error.DataException;
            const unpack = ((@as(usize, self.input[self.pos]) << 8) | self.input[self.pos + 1]) + 1;
            if (unpack > lzma2.chunk_max_unpacked) return error.DataException;
            self.pos += 2;
            if (self.need_dict_reset) {
                self.decoder[0].resetDictionary();
                self.need_dict_reset = false;
            }
            const copied = try bounds.slice(self.input, self.pos, unpack);
            self.pos += unpack;
            @memcpy(self.serve[0..unpack], copied);
            for (copied) |byte| try self.decoder[0].feedByte(byte);
            self.serve_pos = 0;
            self.serve_len = unpack;
            // The control and the unpack size field belong to the
            // compressed size together with the copied data.
            self.block_compressed += 3 + unpack;
            self.block_uncompressed += unpack;
        }
        self.accumulate();
        if (self.compressed_bound) |bound| {
            if (self.block_compressed > bound) return error.DataException;
        }
    }

    fn finishBlock(self: *align(1) XzState) Exception!void {
        // The end control belongs to the compressed size.
        const data_size = try bounds.addUsize(self.block_compressed, 1);
        var effective: usize = undefined;
        if (self.compressed_bound) |bound| {
            if (data_size > bound) return error.DataException;
            // A declared bound is the authority: leftover bytes inside
            // it drop unseen.
            effective = bound;
            self.pos = try bounds.addUsize(self.block_data_start, bound);
        } else {
            effective = data_size;
        }
        const padding: usize = @intCast(blockPadding(effective));
        _ = try bounds.slice(self.input, self.pos, padding);
        self.pos += padding;
        const check_len = checkSize(self.check);
        const check_bytes = try bounds.slice(self.input, self.pos, check_len);
        self.pos += check_len;
        switch (self.check) {
            .none => {},
            .crc32 => {
                if (std.mem.readInt(u32, check_bytes[0..4], .little) != self.crc32[0].final({})) return error.IntegrityException;
            },
            .crc64 => {
                if (std.mem.readInt(u64, check_bytes[0..8], .little) != self.crc64[0].final({})) return error.IntegrityException;
            },
            .sha256 => {
                if (!std.mem.eql(u8, check_bytes[0..32], &self.sha256[0].finalResult())) return error.IntegrityException;
            },
        }
        if (self.uncompressed_bound) |bound| {
            if (self.block_uncompressed != bound) return error.IntegrityException;
        }
        const unpadded = try bounds.addUsize(self.header_size, try bounds.addUsize(effective, check_len));
        try self.records.append(.{
            .unpadded_size = std.math.cast(u64, unpadded) orelse return error.ResourceException,
            .uncompressed_size = @as(u64, self.block_uncompressed),
        });
        self.blocks += 1;
        self.in_block = false;
        self.serve_pos = 0;
        self.serve_len = 0;
    }

    fn finishStream(self: *align(1) XzState) Exception!void {
        var cursor = binary.ReadCursor.init(self.input[self.pos..]);
        if (cursor.remaining() == 0 or cursor.buffer[cursor.pos] != 0x00) return error.DataException;
        _ = try cursor.readU8();
        const record_count = try cursor.readUleb128();
        if (record_count != self.records.len) return error.IntegrityException;
        for (self.records.slice()) |expected| {
            const unpadded = try cursor.readUleb128();
            const uncompressed = try cursor.readUleb128();
            if (unpadded != expected.unpadded_size or uncompressed != expected.uncompressed_size) return error.IntegrityException;
        }
        const content_size = cursor.pos;
        const padding = (4 - (content_size % 4)) % 4;
        for (0..padding) |_| {
            if (cursor.pos >= cursor.buffer.len or cursor.buffer[cursor.pos] != 0x00) return error.DataException;
            cursor.pos += 1;
        }
        const index_end = try bounds.addUsize(cursor.pos, 4);
        if (index_end > cursor.buffer.len) return error.DataException;
        const index_crc = std.mem.readInt(u32, cursor.buffer[cursor.pos..][0..4], .little);
        try verifyCrc32(cursor.buffer[0..cursor.pos], index_crc);
        cursor.pos = index_end;
        const index_size = cursor.pos;
        const footer = try cursor.readSlice(xz.stream_footer_size);
        const footer_crc = std.mem.readInt(u32, footer[0..4], .little);
        try verifyCrc32(footer[4..10], footer_crc);
        const backward_size: usize = std.mem.readInt(u32, footer[4..8], .little);
        if (index_size < 4 or index_size % 4 != 0) return error.IntegrityException;
        if (@as(u64, backward_size) + 1 != index_size / 4) return error.IntegrityException;
        if (footer[8] != 0x00) return error.DataException;
        const check_type = footer[9];
        if (check_type & 0xF0 != 0) return error.DataException;
        if (@backingInt(self.check) != check_type) return error.IntegrityException;
        if (!std.mem.eql(u8, footer[10..12], &xz.footer_magic)) return error.DataException;
        self.pos += cursor.pos;
        // Stream padding comes in multiples of four zero bytes.
        while (self.pos < self.input.len and self.input[self.pos] == 0x00) {
            if (self.input.len - self.pos < 4) return error.DataException;
            if (self.input[self.pos + 1] != 0 or self.input[self.pos + 2] != 0 or self.input[self.pos + 3] != 0) return error.DataException;
            self.pos += 4;
        }
        if (self.pos == self.input.len) {
            self.eof = true;
        } else {
            self.expect_stream_header = true;
        }
    }

    // One step: fill the serve with the next chunk, or cross the next
    // structural boundary.
    fn advance(self: *align(1) XzState) Exception!void {
        if (self.in_block) {
            if (self.pos >= self.input.len) return error.DataException;
            const control = self.input[self.pos];
            self.pos += 1;
            if (control == control_end) {
                try self.finishBlock();
            } else {
                try self.decodeChunk(control);
            }
            return;
        }
        if (self.expect_stream_header) {
            try self.startStream();
            self.expect_stream_header = false;
            return;
        }
        if (self.pos >= self.input.len) return error.DataException;
        if (self.input[self.pos] == control_end) {
            try self.finishStream();
            return;
        }
        try self.startBlock();
    }

    fn read(self: *align(1) XzState, destination: []u8) Exception!usize {
        var written: usize = 0;
        while (written < destination.len) {
            if (self.serve_pos < self.serve_len) {
                const step = @min(self.serve_len - self.serve_pos, destination.len - written);
                @memcpy(destination[written..][0..step], self.serve[self.serve_pos..][0..step]);
                self.serve_pos += step;
                written += step;
                continue;
            }
            if (self.eof) return error.DataException;
            try self.advance();
        }
        return written;
    }

    fn drop(self: *align(1) XzState, count: u64) Exception!void {
        var remaining: usize = std.math.cast(usize, count) orelse return error.ResourceException;
        while (remaining > 0) {
            if (self.serve_pos < self.serve_len) {
                const step = @min(self.serve_len - self.serve_pos, remaining);
                self.serve_pos += step;
                remaining -= step;
                continue;
            }
            if (self.eof) return error.DataException;
            try self.advance();
        }
    }
};

const StoredState = struct {
    input: []const u8,
    pos: usize = 0,

    fn read(self: *align(1) StoredState, destination: []u8) Exception!usize {
        if (self.input.len - self.pos < destination.len) return error.DataException;
        @memcpy(destination, self.input[self.pos..][0..destination.len]);
        self.pos += destination.len;
        return destination.len;
    }

    fn drop(self: *align(1) StoredState, count: u64) Exception!void {
        const n = std.math.cast(usize, count) orelse return error.ResourceException;
        if (self.input.len - self.pos < n) return error.DataException;
        self.pos += n;
    }
};

const Kind = enum { gzip, xz, stored };

const State = struct {
    kind: Kind,
    leg: union(Kind) { gzip: GzipState, xz: XzState, stored: StoredState },
    decoded_bytes: u64 = 0,

    fn init(input: []const u8, segment: []u8) Exception!State {
        var workspace = try io.Workspace.init(segment.ptr, segment.len);
        // The carve order matches the plan order; every slot
        // lands on its own boundary.
        const inflater = try workspace.take(deflate_seam.Decode, 1);
        const decoder = try workspace.take(lzma.DecoderOf(true), 1);
        const crc32s = try workspace.take(checksum.Crc32, 1);
        const crc64s = try workspace.take(checksum.XzCrc64, 1);
        const sha256s = try workspace.take(crypto.Sha256, 1);
        const window = try workspace.take(u8, window_size);
        const block_workspace = try workspace.take(u8, xz_workspace_size);
        if (input.len >= xz.header_magic.len and std.mem.eql(u8, input[0..xz.header_magic.len], &xz.header_magic)) {
            const leg = try XzState.init(input, decoder, crc32s, crc64s, sha256s, window, block_workspace);
            return .{ .kind = .xz, .leg = .{ .xz = leg } };
        }
        if (input.len >= 2 and input[0] == gzip_magic_1 and input[1] == gzip_magic_2) {
            const leg = try GzipState.init(input, inflater, crc32s, window);
            return .{ .kind = .gzip, .leg = .{ .gzip = leg } };
        }
        return .{ .kind = .stored, .leg = .{ .stored = .{ .input = input } } };
    }

    fn read(self: *align(1) State, destination: []u8) Exception!usize {
        const written: usize = switch (self.kind) {
            .gzip => blk: {
                const leg: *align(1) GzipState = &self.leg.gzip;
                break :blk try leg.read(destination);
            },
            .xz => blk: {
                const leg: *align(1) XzState = &self.leg.xz;
                break :blk try leg.read(destination);
            },
            .stored => blk: {
                const leg: *align(1) StoredState = &self.leg.stored;
                break :blk try leg.read(destination);
            },
        };
        self.decoded_bytes = try bounds.addU64(self.decoded_bytes, written);
        return written;
    }

    fn drop(self: *align(1) State, count: u64) Exception!void {
        switch (self.kind) {
            .gzip => {
                const leg: *align(1) GzipState = &self.leg.gzip;
                try leg.drop(count);
            },
            .xz => {
                const leg: *align(1) XzState = &self.leg.xz;
                try leg.drop(count);
            },
            .stored => {
                const leg: *align(1) StoredState = &self.leg.stored;
                try leg.drop(count);
            },
        }
        self.decoded_bytes = try bounds.addU64(self.decoded_bytes, count);
    }
};

// The segment the plan sizes: the engine slots, the decode window, and
// the xz workspace, in decreasing alignment order.
fn segmentSize() usize {
    var plan = io.WorkspacePlan.init(null);
    plan.take(deflate_seam.Decode, 1) catch return 0;
    plan.take(lzma.DecoderOf(true), 1) catch return 0;
    plan.take(checksum.Crc32, 1) catch return 0;
    plan.take(checksum.XzCrc64, 1) catch return 0;
    plan.take(crypto.Sha256, 1) catch return 0;
    plan.take(u8, window_size) catch return 0;
    plan.take(u8, xz_workspace_size) catch return 0;
    // A segment whose base is misaligned for the slots needs worst-case
    // padding for each alignment class the carve crosses.
    const slack = (@alignOf(deflate_seam.Decode) - 1) +
        (@alignOf(lzma.DecoderOf(true)) - 1) +
        (@alignOf(checksum.Crc32) - 1) +
        (@alignOf(checksum.XzCrc64) - 1) +
        (@alignOf(crypto.Sha256) - 1);
    return std.mem.alignForward(usize, plan.required() + slack, @alignOf(u64));
}

// The instance is one byte array; the chain alignment stays one.
// State and engines live in the wrap's scratch.
pub fn Payload(comptime Located: type) type {
    return struct {
        const Self = @This();

        const state_size: usize = @sizeOf(State);

        pub const scratch_size: usize = state_size + segmentSize();

        raw: [state_size]u8,

        fn state(self: *Self) *align(1) State {
            return @ptrCast(&self.raw);
        }

        pub fn wrap(located: Located, scratch: []u8) Exception!*Self {
            if (scratch.len < scratch_size) return error.CapacityException;
            const self: *Self = @ptrCast(scratch.ptr);
            const st = self.state();
            st.* = try State.init(located, scratch[state_size..]);
            return self;
        }

        pub fn reader(self: *Self) *Self {
            return self;
        }

        pub fn take(self: *Self, destination: []u8) Exception!usize {
            return self.state().read(destination);
        }

        pub fn discard(self: *Self, count: u64) Exception!void {
            return self.state().drop(count);
        }

        // The observability counters prove what a walk decoded: a
        // member for gzip, a block for xz, nothing for stored.
        pub fn decodedChunks(self: *Self) u64 {
            const st = self.state();
            return switch (st.kind) {
                .gzip => st.leg.gzip.members,
                .xz => st.leg.xz.blocks,
                .stored => 0,
            };
        }

        pub fn decodedBytes(self: *Self) u64 {
            return self.state().decoded_bytes;
        }
    };
}
