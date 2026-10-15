const std = @import("std");

const bounds = @import("../../common/primitive/bounds.zig");
const failure_prim = @import("../../common/primitive/failure.zig");

const deflate = @import("../../leaf/deflate/onprem.zig");
const lz4_leaf = @import("../../leaf/lz4/onprem.zig");
const lzo_leaf = @import("../../leaf/lzo/onprem.zig");
const zstd_leaf = @import("../../leaf/zstd/onprem.zig");
const xz_grammar = @import("../../grammar/xz/onprem.zig");
const lzma_grammar = @import("../../grammar/lzma/onprem.zig");
const lzma_seam = @import("../../leaf/lzma/seam.zig");
const checksum = @import("../../common/primitive/checksum.zig");

const Failure = failure_prim.Failure;

// Squashfs 4.0 slice: one root directory of regular files.
// Read covers every compressor for data and metadata alike.

// Dictionaries are capped at one MiB; larger ones fail explicitly.

// Write emits the mksquashfs -noI -noD -noF -no-fragments shape.
// Layout follows squashfs_fs.h.

const xz_dictionary_cap: u32 = 1 << 20;
pub const scratch_size: usize = 2 * metadata_size + frag_buffer_size + deflate.history_size + xz_grammar.decodeWorkspaceSize(xz_dictionary_cap);

const compression_lzma: u16 = 2;
const compression_lzo: u16 = 3;
const compression_xz: u16 = 4;
const compression_lz4: u16 = 5;
const compression_zstd: u16 = 6;

const magic: u32 = 0x7371_7368;
const major_version: u16 = 4;
const block_size_default: u32 = 128 * 1024;
const block_log_default: u16 = 17;
const block_log_min: u16 = 12;
const block_log_max: u16 = 20;
const metadata_size: usize = 8192;
const frag_buffer_size: usize = block_size_default;
const super_disk_size: u64 = 96;
const compression_gzip: u16 = 1;
const invalid_fragment: u32 = 0xffff_ffff;
const invalid_table: u64 = 0xffff_ffff_ffff_ffff;

const flag_uncompressed_metadata: u16 = 1 << 15;
const data_uncompressed_bit: u32 = 1 << 24;
const data_size_mask: u32 = 0x00ff_ffff;

const inode_type_dir: u16 = 1;
const inode_type_reg: u16 = 2;
const inode_type_lreg: u16 = 9;

const flag_noi: u16 = 1 << 0;
const flag_nod: u16 = 1 << 1;
const flag_nof: u16 = 1 << 3;
const flag_no_frag: u16 = 1 << 4;
const flag_no_xattr: u16 = 1 << 9;
const flag_noid: u16 = 1 << 11;
const write_flags: u16 = flag_noi | flag_nod | flag_nof | flag_no_frag | flag_no_xattr | flag_noid;

const max_entries = 256;
const mode_file: u16 = 0o644;
const mode_dir: u16 = 0o755;
const uid_index: u16 = 0;
const guid_index: u16 = 1;

pub const Entry = struct {
    name: []const u8,
    data: []const u8,
};

pub const EntryInfo = struct {
    size: u64,
    ordinal: u64,
};

const Super = struct {
    inode_count: u32,
    block_size: u32,
    fragments: u32,
    compression: u16,
    root_ref: u64,
    bytes_used: u64,
    inode_table_start: u64,
    dir_table_start: u64,
    fragment_table_start: u64,
};

const Scratch = struct {
    meta: []u8,
    dir: []u8,
    frag: []u8,
    history: []u8,
    aux: []u8,

    fn carve(scratch: []u8) Failure!Scratch {
        if (scratch.len < scratch_size) return error.CapacityFailure;
        return .{
            .meta = scratch[0..metadata_size],
            .dir = scratch[metadata_size .. 2 * metadata_size],
            .frag = scratch[2 * metadata_size ..][0..frag_buffer_size],
            .history = scratch[2 * metadata_size + frag_buffer_size ..][0..deflate.history_size],
            .aux = scratch[2 * metadata_size + frag_buffer_size + deflate.history_size ..],
        };
    }
};

fn parseSuper(archive: []const u8) Failure!Super {
    if (archive.len < super_disk_size) return error.DataFailure;
    if (std.mem.readInt(u32, archive[0..4], .little) != magic) return error.DataFailure;
    const major = std.mem.readInt(u16, archive[28..30], .little);
    const minor = std.mem.readInt(u16, archive[30..32], .little);
    const block_log = std.mem.readInt(u16, archive[22..24], .little);
    const block_size = std.mem.readInt(u32, archive[12..16], .little);
    if (major != major_version or minor != 0) return error.UnsupportedFailure;
    if (block_log < block_log_min or block_log > block_log_max) return error.DataFailure;
    if (@as(u64, 1) << @intCast(block_log) != block_size) return error.DataFailure;
    const bytes_used = std.mem.readInt(u64, archive[40..48], .little);
    if (bytes_used > archive.len) return error.DataFailure;
    return .{
        .inode_count = std.mem.readInt(u32, archive[4..8], .little),
        .block_size = block_size,
        .fragments = std.mem.readInt(u32, archive[16..20], .little),
        .compression = std.mem.readInt(u16, archive[20..22], .little),
        .root_ref = std.mem.readInt(u64, archive[32..40], .little),
        .bytes_used = bytes_used,
        .inode_table_start = std.mem.readInt(u64, archive[64..72], .little),
        .dir_table_start = std.mem.readInt(u64, archive[72..80], .little),
        .fragment_table_start = std.mem.readInt(u64, archive[80..88], .little),
    };
}

const MetaBlock = struct {
    len: usize,
    disk_size: u64,
};

// Bit 15 set means the metadata payload is stored raw.
// Compressed payloads must fit the 8 KiB block cap.
fn inflateMeta(compression: u16, archive: []const u8, at: u64, out: []u8, history: []u8, aux: []u8) Failure!MetaBlock {
    const head = try bounds.slice(archive, at, 2);
    const header = std.mem.readInt(u16, head[0..2], .little);
    const size: usize = header & ~flag_uncompressed_metadata;
    const payload = try bounds.slice(archive, try bounds.addU64(at, 2), size);
    if (header & flag_uncompressed_metadata != 0) {
        if (size > out.len) return error.DataFailure;
        @memcpy(out[0..size], payload);
        return .{ .len = size, .disk_size = 2 + size };
    }
    const len = try inflateBlock(compression, payload, out, history, aux);
    return .{ .len = len, .disk_size = 2 + size };
}

// One compressed payload lands in an exact-size output slice.
// `aux` carries dictionary-sized workspaces and zstd's rolling history.
fn inflateBlock(compression: u16, payload: []const u8, out: []u8, history: []u8, aux: ?[]u8) Failure!usize {
    switch (compression) {
        compression_gzip => return inflateZlib(payload, out, history),
        compression_lzma => return lzma_grammar.decodeInPlace(payload, out, aux orelse return error.CapacityFailure, lzma_seam.default_provider),
        compression_lzo => return lzo_leaf.decodeInPlace(payload, out, &.{}, .{}),
        compression_xz => return xz_grammar.decode(payload, out, aux orelse return error.CapacityFailure, checksum.default_provider),
        compression_lz4 => {
            return lz4_leaf.decompressBlock(payload, out, &.{}) catch |err| return switch (err) {
                error.DataFailure => error.DataFailure,
                error.OutputTooSmall => error.CapacityFailure,
            };
        },
        compression_zstd => {
            const workspace = aux orelse return error.CapacityFailure;
            var reader = std.Io.Reader.fixed(payload);
            var writer = std.Io.Writer.fixed(out);
            return zstd_leaf.decodeStream(&reader, &writer, workspace, .{ .window_size = xz_dictionary_cap }) catch return error.DataFailure;
        },
        else => return error.UnsupportedFailure,
    }
}

fn inflateZlib(payload: []const u8, out: []u8, history: []u8) Failure!usize {
    if (payload.len < 2 + 4 + 1) return error.DataFailure;
    const cmf = payload[0];
    const flg = payload[1];
    if (cmf & 0x0f != 8) return error.UnsupportedFailure;
    if ((@as(u32, cmf) << 8 | flg) % 31 != 0) return error.DataFailure;
    if (flg & 0x20 != 0) return error.UnsupportedFailure;
    var fixed = std.Io.Writer.fixed(out);
    var inflater = deflate.Decompress.initSlice(payload[2..], history);
    _ = inflater.reader.streamRemaining(&fixed) catch return error.DataFailure;
    return fixed.end;
}

fn inflateData(compression: u16, payload: []const u8, out: []u8, history: []u8, aux: ?[]u8) Failure!void {
    switch (compression) {
        compression_gzip => {
            if (try inflateZlib(payload, out, history) != out.len) return error.DataFailure;
        },
        compression_zstd => {
            _ = try inflateBlock(compression, payload, out, history, aux);
        },
        else => {
            if (try inflateBlock(compression, payload, out, history, aux) != out.len) return error.DataFailure;
        },
    }
}

const Inode = struct {
    file_size: u64,
    start_block: u64,
    fragment: u32 = invalid_fragment,
    frag_offset: u32 = 0,
    block_list: []const u8 = &.{},
    dir_start: u32 = 0,
    dir_offset: u16 = 0,
    dir_file_size: u32 = 0,
};

fn fullBlockCount(file_size: u64, block_size: u32, fragment: u32) Failure!usize {
    if (fragment != invalid_fragment) {
        return std.math.cast(usize, file_size / block_size) orelse return error.DataFailure;
    }
    if (file_size == 0) return 0;
    return std.math.cast(usize, (file_size + block_size - 1) / block_size) orelse return error.DataFailure;
}

fn readInode(archive: []const u8, super: Super, ref: u64, scratch: *Scratch) Failure!Inode {
    const rel = ref >> 16;
    const off: usize = @intCast(ref & 0xffff);
    if (rel > super.bytes_used) return error.DataFailure;
    const at = try bounds.addU64(super.inode_table_start, rel);
    const block = try inflateMeta(super.compression, archive, at, scratch.meta, scratch.history, scratch.aux);
    if (off >= block.len) return error.DataFailure;
    const raw = scratch.meta[off..block.len];
    if (raw.len < 16) return error.DataFailure;
    const inode_number = std.mem.readInt(u32, raw[12..16], .little);
    if (inode_number == 0 or inode_number > super.inode_count) return error.DataFailure;
    switch (std.mem.readInt(u16, raw[0..2], .little)) {
        inode_type_dir => {
            if (raw.len < 32) return error.DataFailure;
            return .{
                .file_size = 0,
                .start_block = 0,
                .dir_start = std.mem.readInt(u32, raw[16..20], .little),
                .dir_offset = std.mem.readInt(u16, raw[26..28], .little),
                .dir_file_size = std.mem.readInt(u16, raw[24..26], .little),
            };
        },
        inode_type_reg => {
            if (raw.len < 32) return error.DataFailure;
            const file_size = std.mem.readInt(u32, raw[28..32], .little);
            const fragment = std.mem.readInt(u32, raw[20..24], .little);
            const list_len = try fullBlockCount(file_size, super.block_size, fragment);
            if (raw.len < 32 + 4 * list_len) return error.DataFailure;
            return .{
                .file_size = file_size,
                .start_block = std.mem.readInt(u32, raw[16..20], .little),
                .fragment = fragment,
                .frag_offset = std.mem.readInt(u32, raw[24..28], .little),
                .block_list = raw[32 .. 32 + 4 * list_len],
            };
        },
        inode_type_lreg => {
            if (raw.len < 56) return error.DataFailure;
            const file_size = std.mem.readInt(u64, raw[24..32], .little);
            const fragment = std.mem.readInt(u32, raw[44..48], .little);
            const list_len = try fullBlockCount(file_size, super.block_size, fragment);
            if (raw.len < 56 + 4 * list_len) return error.DataFailure;
            return .{
                .file_size = file_size,
                .start_block = std.mem.readInt(u64, raw[16..24], .little),
                .fragment = fragment,
                .frag_offset = std.mem.readInt(u32, raw[48..52], .little),
                .block_list = raw[56 .. 56 + 4 * list_len],
            };
        },
        else => return error.UnsupportedFailure,
    }
}

const FragmentEntry = struct {
    start_block: u64,
    size: u32,
};

fn readFragmentEntry(archive: []const u8, super: Super, index: u32, scratch: *Scratch) Failure!FragmentEntry {
    if (super.fragments == 0 or index >= super.fragments) return error.DataFailure;
    const table_bytes = std.math.mul(u64, super.fragments, 16) catch return error.DataFailure;
    const indexes = table_bytes / metadata_size + 1;
    const index_bytes = std.math.mul(u64, indexes, 8) catch return error.ResourceFailure;
    const table = try bounds.slice(archive, super.fragment_table_start, index_bytes);
    const slot = std.math.mul(u64, index, 16) catch return error.DataFailure;
    const block_ptr = std.mem.readInt(u64, table[(slot / metadata_size) * 8 ..][0..8], .little);
    const block = try inflateMeta(super.compression, archive, block_ptr, scratch.frag[0..metadata_size], scratch.history, scratch.aux);
    const off: usize = @intCast(slot % metadata_size);
    if (off + 16 > block.len) return error.DataFailure;
    return .{
        .start_block = std.mem.readInt(u64, scratch.frag[off..][0..8], .little),
        .size = std.mem.readInt(u32, scratch.frag[off + 8 ..][0..4], .little),
    };
}

const MetaStream = struct {
    archive: []const u8,
    compression: u16,
    disk: u64,
    buf: []u8,
    aux: []u8,
    len: usize = 0,
    pos: usize = 0,

    fn refill(self: *MetaStream, history: []u8) Failure!void {
        const block = try inflateMeta(self.compression, self.archive, self.disk, self.buf, history, self.aux);
        self.disk = try bounds.addU64(self.disk, block.disk_size);
        self.len = block.len;
        self.pos = 0;
    }

    fn read(self: *MetaStream, dest: []u8, history: []u8) Failure!void {
        var filled: usize = 0;
        while (filled < dest.len) {
            if (self.pos == self.len) try self.refill(history);
            const take = @min(dest.len - filled, self.len - self.pos);
            @memcpy(dest[filled .. filled + take], self.buf[self.pos .. self.pos + take]);
            filled += take;
            self.pos += take;
        }
    }

    fn skip(self: *MetaStream, count: usize, history: []u8) Failure!void {
        var left = count;
        while (left > 0) {
            if (self.pos == self.len) try self.refill(history);
            const take = @min(left, self.len - self.pos);
            self.pos += take;
            left -= take;
        }
    }
};

const DirTarget = union(enum) {
    count,
    resolve: struct { ordinal: u64, info: *EntryInfo, output: ?[]u8 },
};

fn walkDir(archive: []const u8, super: Super, scratch: *Scratch, target: DirTarget) Failure!u64 {
    const root = try readInode(archive, super, super.root_ref, scratch);
    if (root.dir_file_size < 3) return error.DataFailure;
    var stream = MetaStream{
        .archive = archive,
        .compression = super.compression,
        .disk = try bounds.addU64(super.dir_table_start, root.dir_start),
        .buf = scratch.dir,
        .aux = scratch.aux,
    };
    try stream.skip(root.dir_offset, scratch.history);
    var remaining: u64 = root.dir_file_size - 3;
    var entries_in_header: u32 = 0;
    var header_block: u64 = 0;
    var prev_inode: u32 = 0;
    var ordinal: u64 = 0;
    var name_buf: [256]u8 = undefined;
    while (remaining > 0) {
        if (entries_in_header == 0) {
            if (remaining < 12) return error.DataFailure;
            var head: [12]u8 = undefined;
            try stream.read(&head, scratch.history);
            remaining -= 12;
            entries_in_header = std.mem.readInt(u32, head[0..4], .little) + 1;
            header_block = std.mem.readInt(u32, head[4..8], .little);
            prev_inode = std.mem.readInt(u32, head[8..12], .little);
            if (entries_in_header > max_entries) return error.DataFailure;
        }
        if (remaining < 8) return error.DataFailure;
        var ent: [8]u8 = undefined;
        try stream.read(&ent, scratch.history);
        remaining -= 8;
        const name_len: usize = std.mem.readInt(u16, ent[6..8], .little) + 1;
        if (name_len > name_buf.len or remaining < name_len) return error.DataFailure;
        try stream.read(name_buf[0..name_len], scratch.history);
        remaining -= name_len;
        const delta = std.mem.readInt(i16, ent[2..4], .little);
        const next_inode = @as(i64, prev_inode) + delta;
        if (next_inode < 1 or next_inode > std.math.maxInt(u32)) return error.DataFailure;
        prev_inode = @intCast(next_inode);
        const entry_type = std.mem.readInt(u16, ent[4..6], .little);
        if (entry_type != inode_type_reg and entry_type != inode_type_lreg) return error.UnsupportedFailure;
        const off_in_block = std.mem.readInt(u16, ent[0..2], .little);
        if (off_in_block >= metadata_size) return error.DataFailure;
        switch (target) {
            .count => {},
            .resolve => |res| {
                if (ordinal == res.ordinal) {
                    const ref = (header_block << 16) | @as(u64, off_in_block);
                    const inode = try readInode(archive, super, ref, scratch);
                    res.info.size = inode.file_size;
                    res.info.ordinal = ordinal;
                    if (res.output) |out| {
                        if (out.len < inode.file_size) return error.CapacityFailure;
                        try readFile(archive, super, inode, out[0..@intCast(inode.file_size)], scratch);
                    }
                    return ordinal;
                }
            },
        }
        entries_in_header -= 1;
        ordinal += 1;
    }
    return switch (target) {
        .count => ordinal,
        .resolve => error.DataFailure,
    };
}

fn readFile(archive: []const u8, super: Super, inode: Inode, output: []u8, scratch: *Scratch) Failure!void {
    var written: u64 = 0;
    var data_pos = inode.start_block;
    for (0..inode.block_list.len / 4) |i| {
        const head = std.mem.readInt(u32, inode.block_list[4 * i ..][0..4], .little);
        const take = @min(@as(u64, super.block_size), inode.file_size - written);
        const take_usize: usize = @intCast(take);
        if (head == 0) {
            @memset(output[written..][0..take_usize], 0);
        } else {
            const c_byte = head & data_size_mask;
            const payload = try bounds.slice(archive, data_pos, c_byte);
            if (head & data_uncompressed_bit != 0) {
                if (c_byte != take) return error.DataFailure;
                @memcpy(output[written..][0..take_usize], payload);
            } else {
                try inflateData(super.compression, payload, output[written..][0..take_usize], scratch.history, scratch.aux);
            }
            data_pos = try bounds.addU64(data_pos, c_byte);
        }
        written += take;
    }
    if (inode.fragment != invalid_fragment) {
        const frag_bytes = inode.file_size - written;
        if (frag_bytes > 0) {
            if (inode.frag_offset > scratch.frag.len) return error.DataFailure;
            const entry = try readFragmentEntry(archive, super, inode.fragment, scratch);
            const c_byte = entry.size & data_size_mask;
            const payload = try bounds.slice(archive, entry.start_block, c_byte);
            if (entry.size & data_uncompressed_bit != 0) {
                const off: usize = @intCast(inode.frag_offset);
                if (off + frag_bytes > c_byte) return error.DataFailure;
                @memcpy(output[written..][0..@intCast(frag_bytes)], payload[off..][0..@intCast(frag_bytes)]);
            } else {
                if (super.block_size > scratch.frag.len) return error.UnsupportedFailure;
                const produced = try inflateBlock(super.compression, payload, scratch.frag[0..super.block_size], scratch.history, scratch.aux);
                const off: usize = @intCast(inode.frag_offset);
                if (off + frag_bytes > produced) return error.DataFailure;
                @memcpy(output[written..][0..@intCast(frag_bytes)], scratch.frag[off..][0..@intCast(frag_bytes)]);
            }
            written += frag_bytes;
        }
    }
    if (written != output.len) return error.DataFailure;
}

pub fn inspectCount(archive: []const u8, scratch: []u8) Failure!u64 {
    var carved = try Scratch.carve(scratch);
    const super = try parseSuper(archive);
    return walkDir(archive, super, &carved, .count);
}

pub fn inspectOrdinal(archive: []const u8, ordinal: u64, scratch: []u8) Failure!EntryInfo {
    var carved = try Scratch.carve(scratch);
    const super = try parseSuper(archive);
    var info: EntryInfo = undefined;
    _ = try walkDir(archive, super, &carved, .{ .resolve = .{ .ordinal = ordinal, .info = &info, .output = null } });
    return info;
}

pub fn decodeOrdinal(archive: []const u8, ordinal: u64, output: []u8, scratch: []u8) Failure!usize {
    var carved = try Scratch.carve(scratch);
    const super = try parseSuper(archive);
    var info: EntryInfo = undefined;
    _ = try walkDir(archive, super, &carved, .{ .resolve = .{ .ordinal = ordinal, .info = &info, .output = output } });
    return @intCast(info.size);
}

const Layout = struct {
    total: u64,
    data_total: u64,
    inode_table_total: u64,
    dir_table_total: u64,
    count: usize,
    sorted: [max_entries]u16,
    file_data_off: [max_entries]u64,
    file_blocks: [max_entries]u32,
    inode_block_rel: [max_entries + 1]u64,
    inode_block_off: [max_entries + 1]u16,
    root_dir_size: u32,
};

fn validateName(name: []const u8) Failure!void {
    if (name.len == 0 or name.len > 256) return error.CallFailure;
    if (std.mem.findScalar(u8, name, '/') != null) return error.CallFailure;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.CallFailure;
}

fn dirPayloadSize(entries: []const Entry, lay: *const Layout, upto: usize) u32 {
    var size: u32 = 0;
    var chunk: u32 = 0;
    var prev_block: ?u64 = null;
    for (0..upto) |rank| {
        if (chunk == 0 or chunk == max_entries or prev_block != lay.inode_block_rel[rank]) {
            size += 12;
            chunk = 0;
        }
        prev_block = lay.inode_block_rel[rank];
        size += @intCast(8 + entries[lay.sorted[rank]].name.len);
        chunk += 1;
    }
    return size;
}

fn inodeTableSize(entries: []const Entry, sorted: []const u16) u64 {
    var total: u64 = 0;
    var used: u64 = 0;
    for (0..sorted.len + 1) |rank| {
        const inode_size: u64 = if (rank < sorted.len)
            32 + 4 * ((entries[sorted[rank]].data.len + block_size_default - 1) / block_size_default)
        else
            32;
        if (used > 0 and used + inode_size > metadata_size) {
            total += 2 + used;
            used = 0;
        }
        used += inode_size;
    }
    return total + 2 + used;
}

fn layoutEntries(entries: []const Entry) Failure!Layout {
    if (entries.len == 0 or entries.len > max_entries) return error.UnsupportedFailure;
    var lay: Layout = undefined;
    lay.count = entries.len;
    // Rank selection keeps the layout pass allocator-free.
    for (0..entries.len) |rank| {
        try validateName(entries[rank].name);
        var best: ?usize = null;
        for (entries, 0..) |entry, i| {
            var taken = false;
            for (lay.sorted[0..rank]) |used| taken = taken or used == i;
            if (taken) continue;
            if (best == null or std.mem.order(u8, entry.name, entries[best.?].name) == .lt) best = i;
        }
        lay.sorted[rank] = @intCast(best.?);
    }
    for (0..entries.len - 1) |rank| {
        if (std.mem.eql(u8, entries[lay.sorted[rank]].name, entries[lay.sorted[rank + 1]].name)) return error.CallFailure;
    }
    var data_off: u64 = super_disk_size;
    for (0..entries.len) |rank| {
        const entry = entries[lay.sorted[rank]];
        if (entry.data.len > std.math.maxInt(u32)) return error.UnsupportedFailure;
        lay.file_data_off[rank] = data_off;
        lay.file_blocks[rank] = @intCast((entry.data.len + block_size_default - 1) / block_size_default);
        data_off = try bounds.addU64(data_off, entry.data.len);
    }
    lay.data_total = data_off - super_disk_size;
    lay.inode_table_total = inodeTableSize(entries, lay.sorted[0..entries.len]);
    var block_rel: u64 = 0;
    var used: u64 = 0;
    for (0..entries.len + 1) |rank| {
        const inode_size: u64 = if (rank < entries.len)
            32 + 4 * @as(u64, lay.file_blocks[rank])
        else
            32;
        if (used > 0 and used + inode_size > metadata_size) {
            block_rel += 2 + used;
            used = 0;
        }
        lay.inode_block_rel[rank] = block_rel;
        lay.inode_block_off[rank] = @intCast(used);
        used += inode_size;
    }
    lay.root_dir_size = dirPayloadSize(entries, &lay, entries.len);
    const dir_payload = lay.root_dir_size;
    // The dir inode's size field is u16.
    // The count includes the 3 bytes readers subtract for the synthetic dots.
    if (dir_payload + 3 > std.math.maxInt(u16)) return error.UnsupportedFailure;
    const dir_blocks = (dir_payload + metadata_size - 1) / metadata_size;
    lay.dir_table_total = dir_payload + 2 * @as(u64, @intCast(dir_blocks));
    lay.total = super_disk_size + lay.data_total + lay.inode_table_total + lay.dir_table_total + (8 + 2 + 8);
    return lay;
}

pub fn archiveSize(entries: []const Entry) Failure!u64 {
    const lay = try layoutEntries(entries);
    return lay.total;
}

const Sink = struct {
    bytes: []u8,
    pos: usize = 0,

    fn write(self: *Sink, data: []const u8) Failure!void {
        if (self.pos + data.len > self.bytes.len) return error.CapacityFailure;
        @memcpy(self.bytes[self.pos .. self.pos + data.len], data);
        self.pos += data.len;
    }
};

fn writeSuper(sink: *Sink, lay: *const Layout) Failure!void {
    var raw: [super_disk_size]u8 = @splat(0);
    const id_start = lay.total - 8;
    std.mem.writeInt(u32, raw[0..4], magic, .little);
    std.mem.writeInt(u32, raw[4..8], @intCast(lay.count + 1), .little);
    std.mem.writeInt(u32, raw[12..16], block_size_default, .little);
    std.mem.writeInt(u16, raw[20..22], compression_gzip, .little);
    std.mem.writeInt(u16, raw[22..24], block_log_default, .little);
    std.mem.writeInt(u16, raw[24..26], write_flags, .little);
    std.mem.writeInt(u16, raw[26..28], 2, .little);
    std.mem.writeInt(u16, raw[28..30], major_version, .little);
    const root_ref = (lay.inode_block_rel[lay.count] << 16) | lay.inode_block_off[lay.count];
    std.mem.writeInt(u64, raw[32..40], root_ref, .little);
    std.mem.writeInt(u64, raw[40..48], lay.total, .little);
    std.mem.writeInt(u64, raw[48..56], id_start, .little);
    std.mem.writeInt(u64, raw[56..64], invalid_table, .little);
    std.mem.writeInt(u64, raw[64..72], super_disk_size + lay.data_total, .little);
    std.mem.writeInt(u64, raw[72..80], super_disk_size + lay.data_total + lay.inode_table_total, .little);
    std.mem.writeInt(u64, raw[80..88], invalid_table, .little);
    std.mem.writeInt(u64, raw[88..96], invalid_table, .little);
    try sink.write(&raw);
}

fn flushMetaBlock(sink: *Sink, block: []const u8, used: usize) Failure!void {
    var head: [2]u8 = undefined;
    std.mem.writeInt(u16, &head, flag_uncompressed_metadata | @as(u16, @intCast(used)), .little);
    try sink.write(&head);
    try sink.write(block[0..used]);
}

fn writeInodeTable(sink: *Sink, entries: []const Entry, lay: *const Layout) Failure!void {
    var block: [metadata_size]u8 = undefined;
    var used: usize = 0;
    var raw: [32]u8 = undefined;
    for (0..lay.count + 1) |rank| {
        const inode_size: usize = if (rank < lay.count) 32 + 4 * @as(usize, lay.file_blocks[rank]) else 32;
        if (used > 0 and used + inode_size > metadata_size) {
            try flushMetaBlock(sink, &block, used);
            used = 0;
        }
        @memset(&raw, 0);
        std.mem.writeInt(u16, raw[4..6], uid_index, .little);
        std.mem.writeInt(u16, raw[6..8], guid_index, .little);
        if (rank < lay.count) {
            const entry = entries[lay.sorted[rank]];
            std.mem.writeInt(u16, raw[0..2], inode_type_reg, .little);
            std.mem.writeInt(u16, raw[2..4], mode_file, .little);
            std.mem.writeInt(u32, raw[12..16], @intCast(rank + 1), .little);
            std.mem.writeInt(u32, raw[16..20], @intCast(lay.file_data_off[rank]), .little);
            std.mem.writeInt(u32, raw[20..24], invalid_fragment, .little);
            std.mem.writeInt(u32, raw[28..32], @intCast(entry.data.len), .little);
            @memcpy(block[used .. used + 32], &raw);
            var off = used + 32;
            var data_off: u64 = 0;
            for (0..lay.file_blocks[rank]) |_| {
                const take = @min(@as(u64, block_size_default), entry.data.len - data_off);
                std.mem.writeInt(u32, block[off..][0..4], @as(u32, @intCast(take)) | data_uncompressed_bit, .little);
                off += 4;
                data_off = try bounds.addU64(data_off, take);
            }
        } else {
            std.mem.writeInt(u16, raw[0..2], inode_type_dir, .little);
            std.mem.writeInt(u16, raw[2..4], mode_dir, .little);
            std.mem.writeInt(u32, raw[12..16], @intCast(lay.count + 1), .little);
            std.mem.writeInt(u32, raw[16..20], 0, .little);
            std.mem.writeInt(u32, raw[20..24], 2, .little);
            std.mem.writeInt(u16, raw[24..26], @intCast(lay.root_dir_size + 3), .little);
            std.mem.writeInt(u32, raw[28..32], @intCast(lay.count + 1), .little);
            @memcpy(block[used .. used + 32], &raw);
        }
        used += inode_size;
    }
    if (used > 0) try flushMetaBlock(sink, &block, used);
}

fn writeDirTable(sink: *Sink, entries: []const Entry, lay: *const Layout) Failure!void {
    var block: [metadata_size]u8 = undefined;
    var used: usize = 0;
    var chunk: u32 = 0;
    var prev_block: ?u64 = null;
    var prev_inode: u32 = 0;
    for (0..lay.count) |rank| {
        if (chunk == 0 or chunk == max_entries or prev_block != lay.inode_block_rel[rank]) {
            if (used > 0 and used + 12 > metadata_size) {
                try flushMetaBlock(sink, &block, used);
                used = 0;
            }
            var count: u32 = 0;
            var scan = rank;
            while (scan < lay.count and count < max_entries and lay.inode_block_rel[scan] == lay.inode_block_rel[rank]) {
                count += 1;
                scan += 1;
            }
            var hdr: [12]u8 = @splat(0);
            std.mem.writeInt(u32, hdr[0..4], count - 1, .little);
            std.mem.writeInt(u32, hdr[4..8], @intCast(lay.inode_block_rel[rank]), .little);
            std.mem.writeInt(u32, hdr[8..12], @intCast(rank + 1), .little);
            @memcpy(block[used .. used + 12], &hdr);
            used += 12;
            prev_inode = @intCast(rank + 1);
            prev_block = lay.inode_block_rel[rank];
            chunk = 0;
        }
        const entry = entries[lay.sorted[rank]];
        const need = 8 + entry.name.len;
        if (used + need > metadata_size) return error.UnsupportedFailure;
        var ent: [8]u8 = undefined;
        std.mem.writeInt(u16, ent[0..2], lay.inode_block_off[rank], .little);
        std.mem.writeInt(i16, ent[2..4], @intCast(@as(i64, @intCast(rank + 1)) - prev_inode), .little);
        std.mem.writeInt(u16, ent[4..6], inode_type_reg, .little);
        std.mem.writeInt(u16, ent[6..8], @intCast(entry.name.len - 1), .little);
        prev_inode = @intCast(rank + 1);
        @memcpy(block[used .. used + 8], &ent);
        @memcpy(block[used + 8 .. used + need], entry.name);
        used += need;
        chunk += 1;
    }
    if (used > 0) try flushMetaBlock(sink, &block, used);
}

fn writeIdTable(sink: *Sink) Failure!void {
    // unsquashfs checks bytes_used - id_table_start == index_bytes.
    // The id block comes first; the index last.
    const block_start: u64 = @intCast(sink.pos);
    var head: [2]u8 = undefined;
    std.mem.writeInt(u16, &head, flag_uncompressed_metadata | 8, .little);
    try sink.write(&head);
    const ids = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 };
    try sink.write(&ids);
    var index: [8]u8 = undefined;
    std.mem.writeInt(u64, &index, block_start, .little);
    try sink.write(&index);
}

pub fn encode(entries: []const Entry, output: []u8, scratch: []u8) Failure!usize {
    _ = scratch;
    const lay = try layoutEntries(entries);
    if (output.len < lay.total) return error.CapacityFailure;
    var sink = Sink{ .bytes = output };
    try writeSuper(&sink, &lay);
    for (0..lay.count) |rank| {
        try sink.write(entries[lay.sorted[rank]].data);
    }
    try writeInodeTable(&sink, entries, &lay);
    try writeDirTable(&sink, entries, &lay);
    try writeIdTable(&sink);
    if (sink.pos != lay.total) return error.DataFailure;
    return sink.pos;
}

test "squashfs store roundtrips flat files" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "hello.txt", .data = "hello squashfs" },
        .{ .name = "data.bin", .data = "ABCABCABCABC" },
    };
    var archive: [4096]u8 = undefined;
    var scratch: [scratch_size]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    try testing.expectEqual(written, try archiveSize(&entries));
    try testing.expectEqual(@as(u64, 2), try inspectCount(archive[0..written], &scratch));
    const first = try inspectOrdinal(archive[0..written], 0, &scratch);
    try testing.expectEqual(@as(u64, 12), first.size);
    var out: [16]u8 = undefined;
    const n = try decodeOrdinal(archive[0..written], 1, &out, &scratch);
    try testing.expectEqualSlices(u8, "hello squashfs", out[0..n]);
}

const mksquashfs_fixture = [_]u8{
    0x68, 0x73, 0x71, 0x73, 0x03, 0x00, 0x00, 0x00, 0xf7, 0x54, 0xd0, 0x6a, 0x00, 0x00, 0x02, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x11, 0x00, 0xc0, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x23, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x78, 0xda, 0x0b, 0x2e, 0x2c, 0x4d, 0x49, 0xaf, 0x54, 0x48, 0x4b, 0xad, 0xd2, 0x51, 0x48, 0xca,
    0x49, 0xcc, 0xcb, 0x56, 0xc8, 0xca, 0xcc, 0x2d, 0x50, 0x48, 0x2e, 0x2a, 0x2f, 0xc9, 0x50, 0x28,
    0xcb, 0xaf, 0x08, 0x26, 0x20, 0xaf, 0x38, 0xaa, 0x60, 0xf0, 0x2a, 0x00, 0x00, 0x68, 0x75, 0xac,
    0x93, 0x33, 0x00, 0x78, 0xda, 0x63, 0x62, 0x58, 0xc2, 0xc8, 0xc0, 0xc0, 0xc8, 0xf0, 0x3d, 0xe4,
    0x42, 0x16, 0x90, 0x81, 0x02, 0x14, 0x80, 0x98, 0x09, 0x49, 0x9e, 0x09, 0x4d, 0x6e, 0x2f, 0x58,
    0xe6, 0x2d, 0x98, 0x7c, 0x06, 0x94, 0x67, 0x86, 0xca, 0x81, 0xd4, 0x69, 0x03, 0x31, 0x0b, 0x10,
    0x03, 0x00, 0x49, 0xc2, 0x0a, 0xf4, 0x1f, 0x00, 0x78, 0xda, 0x63, 0x64, 0x80, 0x00, 0x46, 0x28,
    0xcd, 0xc4, 0xc0, 0xca, 0x90, 0x6b, 0xa8, 0x57, 0x52, 0x51, 0xa2, 0x00, 0x14, 0x03, 0xf3, 0x8c,
    0x40, 0x3c, 0x00, 0x2f, 0x79, 0x04, 0x8b, 0x0e, 0x00, 0x78, 0xda, 0x4b, 0x60, 0x80, 0x00, 0x43,
    0x28, 0x0d, 0x00, 0x07, 0x98, 0x00, 0x92, 0xe7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    0x00, 0x78, 0xda, 0x63, 0x60, 0x80, 0x00, 0x05, 0x28, 0xed, 0x00, 0xa5, 0x01, 0x04, 0x18, 0x00,
    0x61, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x80, 0xf5, 0x01, 0x00, 0x00, 0x14,
    0x00, 0x00, 0x00, 0x19, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

test "squashfs reads mksquashfs gzip image" {
    const testing = std.testing;
    var scratch: [scratch_size]u8 = undefined;
    const count = try inspectCount(&mksquashfs_fixture, &scratch);
    try testing.expectEqual(@as(u64, 2), count);
    var out0: [32]u8 = undefined;
    const n0 = try decodeOrdinal(&mksquashfs_fixture, 0, &out0, &scratch);
    try testing.expectEqual(@as(usize, 32), n0);
    var out: [445]u8 = undefined;
    const n = try decodeOrdinal(&mksquashfs_fixture, 1, &out, &scratch);
    try testing.expectEqual(@as(usize, 445), n);
}

