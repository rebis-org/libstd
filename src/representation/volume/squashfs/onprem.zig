const std = @import("std");

const bounds = @import("../../../common/primitive/bounds.zig");
const checksum = @import("../../../common/primitive/checksum.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const tree_order = @import("../../../common/primitive/order.zig");
const lzma_grammar = @import("../../grammar/lzma/onprem.zig");
const xz_grammar = @import("../../grammar/xz/onprem.zig");
const deflate = @import("../../leaf/deflate/onprem.zig");
const lz4_leaf = @import("../../leaf/lz4/onprem.zig");
const lzma_seam = @import("../../leaf/lzma/seam.zig");
const lzo_leaf = @import("../../leaf/lzo/onprem.zig");
const zstd_leaf = @import("../../leaf/zstd/onprem.zig");

const Exception = exception_prim.Exception;

// Squashfs 4.0 slice: one root directory of regular files.
// Read covers every compressor for data and metadata alike.

// Dictionaries are capped at one MiB; larger ones fail explicitly.

// Write emits the mksquashfs -comp zstd -no-fragments shape.
// Metadata blocks are zstd frames, stored verbatim on expand.
// Layout follows squashfs_fs.h.

const xz_dictionary_cap: u32 = 1 << 20;

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
const max_dir_depth: u32 = 64;
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

const flag_no_frag: u16 = 1 << 4;
const flag_no_xattr: u16 = 1 << 9;
const flag_noid: u16 = 1 << 11;
// Compressed write keeps fragments, xattrs, and id tables disabled,
// matching the slice shape.
const write_flags: u16 = flag_no_frag | flag_no_xattr | flag_noid;

// Read carving stays at the front of scratch; the zstd encoder workspace
// and write staging live behind it. The workspace bound covers the hash
// and double-fast tables plus block slack. Frames use the reader's
// one-MiB window so write and read agree on scratch.
const zstd_window: u32 = 1 << 20;
const zstd_options: zstd_leaf.Options = .{ .window_size = zstd_window };
const max_data_blocks: usize = 4096;
const meta_staging_size: usize = 48 * 1024;
const block_staging_size: usize = block_size_default + 64;
const zstd_workspace_extra: usize = 3 << 20;
const write_staging_size: usize = block_staging_size + meta_staging_size + max_data_blocks * 4;
const read_scratch_size: usize = 2 * metadata_size + frag_buffer_size + deflate.history_size + xz_grammar.decodeWorkspaceSize(xz_dictionary_cap);
pub const scratch_size: usize = read_scratch_size + zstd_workspace_extra + write_staging_size;

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

    fn carve(scratch: []u8) Exception!Scratch {
        if (scratch.len < scratch_size) return error.CapacityException;
        return .{
            .meta = scratch[0..metadata_size],
            .dir = scratch[metadata_size .. 2 * metadata_size],
            .frag = scratch[2 * metadata_size ..][0..frag_buffer_size],
            .history = scratch[2 * metadata_size + frag_buffer_size ..][0..deflate.history_size],
            .aux = scratch[2 * metadata_size + frag_buffer_size + deflate.history_size ..],
        };
    }
};

fn parseSuper(archive: []const u8) Exception!Super {
    if (archive.len < super_disk_size) return error.DataException;
    if (std.mem.readInt(u32, archive[0..4], .little) != magic) return error.DataException;
    const major = std.mem.readInt(u16, archive[28..30], .little);
    const minor = std.mem.readInt(u16, archive[30..32], .little);
    const block_log = std.mem.readInt(u16, archive[22..24], .little);
    const block_size = std.mem.readInt(u32, archive[12..16], .little);
    if (major != major_version or minor != 0) return error.UnsupportedException;
    if (block_log < block_log_min or block_log > block_log_max) return error.DataException;
    if (@as(u64, 1) << @intCast(block_log) != block_size) return error.DataException;
    const bytes_used = std.mem.readInt(u64, archive[40..48], .little);
    if (bytes_used > archive.len) return error.DataException;
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
fn inflateMeta(compression: u16, archive: []const u8, at: u64, out: []u8, history: []u8, aux: []u8) Exception!MetaBlock {
    const head = try bounds.slice(archive, at, 2);
    const header = std.mem.readInt(u16, head[0..2], .little);
    const size: usize = header & ~flag_uncompressed_metadata;
    const payload = try bounds.slice(archive, try bounds.addU64(at, 2), size);
    if (header & flag_uncompressed_metadata != 0) {
        if (size > out.len) return error.DataException;
        @memcpy(out[0..size], payload);
        return .{ .len = size, .disk_size = 2 + size };
    }
    const len = try inflateBlock(compression, payload, out, history, aux);
    return .{ .len = len, .disk_size = 2 + size };
}

// `aux` carries dictionary-sized workspaces and zstd's rolling history.
fn inflateBlock(compression: u16, payload: []const u8, out: []u8, history: []u8, aux: ?[]u8) Exception!usize {
    switch (compression) {
        compression_gzip => return inflateZlib(payload, out, history),
        compression_lzma => return lzma_grammar.decodeInPlace(payload, out, aux orelse return error.CapacityException, lzma_seam.default_provider),
        compression_lzo => return lzo_leaf.decodeInPlace(payload, out, &.{}, .{}),
        compression_xz => return xz_grammar.decode(payload, out, aux orelse return error.CapacityException, checksum.default_provider),
        compression_lz4 => {
            return lz4_leaf.decompressBlock(payload, out, &.{}) catch |err| return switch (err) {
                error.DataException => error.DataException,
                error.OutputTooSmall => error.CapacityException,
            };
        },
        compression_zstd => {
            const workspace = aux orelse return error.CapacityException;
            var reader = std.Io.Reader.fixed(payload);
            var writer = std.Io.Writer.fixed(out);
            return zstd_leaf.decodeStream(&reader, &writer, workspace, .{ .window_size = zstd_window }) catch return error.DataException;
        },
        else => return error.UnsupportedException,
    }
}

fn inflateZlib(payload: []const u8, out: []u8, history: []u8) Exception!usize {
    if (payload.len < 2 + 4 + 1) return error.DataException;
    const cmf = payload[0];
    const flg = payload[1];
    if (cmf & 0x0f != 8) return error.UnsupportedException;
    if ((@as(u32, cmf) << 8 | flg) % 31 != 0) return error.DataException;
    if (flg & 0x20 != 0) return error.UnsupportedException;
    var fixed = std.Io.Writer.fixed(out);
    var inflater = deflate.Decompress.initSlice(payload[2..], history);
    _ = inflater.reader.streamRemaining(&fixed) catch return error.DataException;
    return fixed.end;
}

fn inflateData(compression: u16, payload: []const u8, out: []u8, history: []u8, aux: ?[]u8) Exception!void {
    // Every compressor must fill the destination exactly: a short frame is
    // corruption, not a license to leave stale bytes in the block buffer.
    if (try inflateBlock(compression, payload, out, history, aux) != out.len) return error.DataException;
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

fn fullBlockCount(file_size: u64, block_size: u32, fragment: u32) Exception!usize {
    // Overflow-safe ceil division: a hostile length must not wrap the count.
    if (fragment != invalid_fragment) {
        return std.math.cast(usize, file_size / block_size) orelse return error.DataException;
    }
    const blocks = file_size / block_size + @intFromBool(file_size % block_size != 0);
    return std.math.cast(usize, blocks) orelse return error.DataException;
}

fn readInode(archive: []const u8, super: Super, ref: u64, scratch: *Scratch) Exception!Inode {
    const rel = ref >> 16;
    const off: usize = @intCast(ref & 0xffff);
    if (rel > super.bytes_used) return error.DataException;
    const at = try bounds.addU64(super.inode_table_start, rel);
    const block = try inflateMeta(super.compression, archive, at, scratch.meta, scratch.history, scratch.aux);
    if (off >= block.len) return error.DataException;
    const raw = scratch.meta[off..block.len];
    if (raw.len < 16) return error.DataException;
    const inode_number = std.mem.readInt(u32, raw[12..16], .little);
    if (inode_number == 0 or inode_number > super.inode_count) return error.DataException;
    switch (std.mem.readInt(u16, raw[0..2], .little)) {
        inode_type_dir => {
            if (raw.len < 32) return error.DataException;
            return .{
                .file_size = 0,
                .start_block = 0,
                .dir_start = std.mem.readInt(u32, raw[16..20], .little),
                .dir_offset = std.mem.readInt(u16, raw[26..28], .little),
                .dir_file_size = std.mem.readInt(u16, raw[24..26], .little),
            };
        },
        inode_type_reg => {
            if (raw.len < 32) return error.DataException;
            const file_size = std.mem.readInt(u32, raw[28..32], .little);
            const fragment = std.mem.readInt(u32, raw[20..24], .little);
            const list_len = try fullBlockCount(file_size, super.block_size, fragment);
            if (raw.len < 32 + 4 * list_len) return error.DataException;
            return .{
                .file_size = file_size,
                .start_block = std.mem.readInt(u32, raw[16..20], .little),
                .fragment = fragment,
                .frag_offset = std.mem.readInt(u32, raw[24..28], .little),
                .block_list = raw[32 .. 32 + 4 * list_len],
            };
        },
        inode_type_lreg => {
            if (raw.len < 56) return error.DataException;
            const file_size = std.mem.readInt(u64, raw[24..32], .little);
            const fragment = std.mem.readInt(u32, raw[44..48], .little);
            const list_len = try fullBlockCount(file_size, super.block_size, fragment);
            if (raw.len < 56 + 4 * list_len) return error.DataException;
            return .{
                .file_size = file_size,
                .start_block = std.mem.readInt(u64, raw[16..24], .little),
                .fragment = fragment,
                .frag_offset = std.mem.readInt(u32, raw[48..52], .little),
                .block_list = raw[56 .. 56 + 4 * list_len],
            };
        },
        else => return error.UnsupportedException,
    }
}

const FragmentEntry = struct {
    start_block: u64,
    size: u32,
};

fn readFragmentEntry(archive: []const u8, super: Super, index: u32, scratch: *Scratch) Exception!FragmentEntry {
    if (super.fragments == 0 or index >= super.fragments) return error.DataException;
    const table_bytes = std.math.mul(u64, super.fragments, 16) catch return error.DataException;
    // unsquashfs sizes the index by ceil(bytes / 8 KiB); floor + 1 reads a
    // slot past the table whenever the byte count is an exact multiple.
    const indexes = (table_bytes + metadata_size - 1) / metadata_size;
    const index_bytes = std.math.mul(u64, indexes, 8) catch return error.ResourceException;
    const table = try bounds.slice(archive, super.fragment_table_start, index_bytes);
    const slot = std.math.mul(u64, index, 16) catch return error.DataException;
    const block_ptr = std.mem.readInt(u64, table[@as(usize, @intCast((slot / metadata_size) * 8))..][0..8], .little);
    const block = try inflateMeta(super.compression, archive, block_ptr, scratch.frag[0..metadata_size], scratch.history, scratch.aux);
    const off: usize = @intCast(slot % metadata_size);
    if (off + 16 > block.len) return error.DataException;
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

    fn refill(self: *MetaStream, history: []u8) Exception!void {
        const block = try inflateMeta(self.compression, self.archive, self.disk, self.buf, history, self.aux);
        self.disk = try bounds.addU64(self.disk, block.disk_size);
        self.len = block.len;
        self.pos = 0;
    }

    fn read(self: *MetaStream, dest: []u8, history: []u8) Exception!void {
        var filled: usize = 0;
        while (filled < dest.len) {
            if (self.pos == self.len) try self.refill(history);
            const take = @min(dest.len - filled, self.len - self.pos);
            @memcpy(dest[filled .. filled + take], self.buf[self.pos .. self.pos + take]);
            filled += take;
            self.pos += take;
        }
    }

    fn skip(self: *MetaStream, count: usize, history: []u8) Exception!void {
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
    resolve: struct { ordinal: u64, info: *EntryInfo, output: ?[]u8, found: *bool = undefined },
};

const WalkState = struct {
    ordinal: u64 = 0,
};

fn walkDir(archive: []const u8, super: Super, scratch: *Scratch, target: DirTarget) Exception!u64 {
    var state = WalkState{};
    var found = false;
    const resolved = switch (target) {
        .count => target,
        .resolve => |res| DirTarget{ .resolve = .{ .ordinal = res.ordinal, .info = res.info, .output = res.output, .found = &found } },
    };
    try walkInodeDir(archive, super, scratch, super.root_ref, resolved, &state, 0);
    return switch (target) {
        .count => state.ordinal,
        .resolve => if (found) state.ordinal else error.DataException,
    };
}

fn walkInodeDir(archive: []const u8, super: Super, scratch: *Scratch, ref: u64, target: DirTarget, state: *WalkState, depth: u32) Exception!void {
    if (depth > max_dir_depth) return error.DataException;
    const dir_inode = try readInode(archive, super, ref, scratch);
    if (dir_inode.dir_file_size < 3) return error.DataException;
    const content_len = dir_inode.dir_file_size - 3;
    if (content_len > scratch.frag.len) return error.ResourceException;
    var stream = MetaStream{
        .archive = archive,
        .compression = super.compression,
        .disk = try bounds.addU64(super.dir_table_start, dir_inode.dir_start),
        .buf = scratch.dir,
        .aux = scratch.aux,
    };
    try stream.skip(dir_inode.dir_offset, scratch.history);
    try stream.read(scratch.frag[0..content_len], scratch.history);

    // Collect children first: recursion would clobber staged bytes
    // mid-parse. Names carry no meaning for counting or resolution.
    var refs: [max_entries]u64 = undefined;
    var types: [max_entries]u16 = undefined;
    var count: usize = 0;
    var remaining: u64 = content_len;
    var entries_in_header: u32 = 0;
    var header_block: u64 = 0;
    var prev_inode: u32 = 0;
    var cursor: usize = 0;
    var name_len: usize = 0;
    while (remaining > 0) {
        if (entries_in_header == 0) {
            if (remaining < 12) return error.DataException;
            var head: [12]u8 = undefined;
            @memcpy(&head, scratch.frag[cursor..][0..12]);
            cursor += 12;
            remaining -= 12;
            entries_in_header = std.mem.readInt(u32, head[0..4], .little) + 1;
            header_block = std.mem.readInt(u32, head[4..8], .little);
            prev_inode = std.mem.readInt(u32, head[8..12], .little);
            if (entries_in_header > max_entries) return error.DataException;
        }
        if (remaining < 8) return error.DataException;
        var ent: [8]u8 = undefined;
        @memcpy(&ent, scratch.frag[cursor..][0..8]);
        cursor += 8;
        remaining -= 8;
        name_len = std.mem.readInt(u16, ent[6..8], .little) + 1;
        if (name_len > 256 or remaining < name_len) return error.DataException;
        cursor += name_len;
        remaining -= name_len;
        const delta = std.mem.readInt(i16, ent[2..4], .little);
        const next_inode = @as(i64, prev_inode) + delta;
        if (next_inode < 1 or next_inode > std.math.maxInt(u32)) return error.DataException;
        prev_inode = @intCast(next_inode);
        const off_in_block = std.mem.readInt(u16, ent[0..2], .little);
        if (off_in_block >= metadata_size) return error.DataException;
        if (count >= max_entries) return error.DataException;
        refs[count] = (header_block << 16) | @as(u64, off_in_block);
        types[count] = std.mem.readInt(u16, ent[4..6], .little);
        count += 1;
        entries_in_header -= 1;
    }

    const found_ptr = switch (target) {
        .resolve => |res| res.found,
        .count => null,
    };
    for (refs[0..count], types[0..count]) |child_ref, entry_type| {
        if (found_ptr) |fp| {
            if (fp.*) return;
        }
        switch (entry_type) {
            inode_type_dir => try walkInodeDir(archive, super, scratch, child_ref, target, state, depth + 1),
            inode_type_reg, inode_type_lreg => {
                switch (target) {
                    .count => {},
                    .resolve => |res| {
                        if (state.ordinal == res.ordinal) {
                            const inode = try readInode(archive, super, child_ref, scratch);
                            res.info.size = inode.file_size;
                            res.info.ordinal = state.ordinal;
                            if (res.output) |out| {
                                if (out.len < inode.file_size) return error.CapacityException;
                                try readFile(archive, super, inode, out[0..@intCast(inode.file_size)], scratch);
                            }
                            res.found.* = true;
                            return;
                        }
                    },
                }
                state.ordinal += 1;
            },
            else => return error.UnsupportedException,
        }
    }
}

fn readFile(archive: []const u8, super: Super, inode: Inode, output: []u8, scratch: *Scratch) Exception!void {
    var written: u64 = 0;
    var data_pos = inode.start_block;
    for (0..inode.block_list.len / 4) |i| {
        const head = std.mem.readInt(u32, inode.block_list[4 * i ..][0..4], .little);
        const take = @min(@as(u64, super.block_size), inode.file_size - written);
        const written_usize: usize = std.math.cast(usize, written) orelse return error.CapacityException;
        const take_usize: usize = @intCast(take);
        if (head == 0) {
            @memset(output[written_usize..][0..take_usize], 0);
        } else {
            const c_byte = head & data_size_mask;
            const payload = try bounds.slice(archive, data_pos, c_byte);
            if (head & data_uncompressed_bit != 0) {
                if (c_byte != take) return error.DataException;
                @memcpy(output[written_usize..][0..take_usize], payload);
            } else {
                try inflateData(super.compression, payload, output[written_usize..][0..take_usize], scratch.history, scratch.aux);
            }
            data_pos = try bounds.addU64(data_pos, c_byte);
        }
        written += take;
    }
    if (inode.fragment != invalid_fragment) {
        const frag_bytes = inode.file_size - written;
        if (frag_bytes > 0) {
            const written_usize: usize = std.math.cast(usize, written) orelse return error.CapacityException;
            // unsquashfs bounds the fragment offset by block_size, not by any
            // decoder buffer: a foreign image with block_log above 17 carries
            // valid offsets past 128 KiB.
            if (inode.frag_offset >= super.block_size) return error.DataException;
            const entry = try readFragmentEntry(archive, super, inode.fragment, scratch);
            const c_byte = entry.size & data_size_mask;
            const payload = try bounds.slice(archive, entry.start_block, c_byte);
            if (entry.size & data_uncompressed_bit != 0) {
                const off: usize = @intCast(inode.frag_offset);
                if (off + frag_bytes > c_byte) return error.DataException;
                @memcpy(output[written_usize..][0..@intCast(frag_bytes)], payload[off..][0..@intCast(frag_bytes)]);
            } else {
                if (super.block_size > scratch.frag.len) return error.UnsupportedException;
                const produced = try inflateBlock(super.compression, payload, scratch.frag[0..super.block_size], scratch.history, scratch.aux);
                const off: usize = @intCast(inode.frag_offset);
                if (off + frag_bytes > produced) return error.DataException;
                @memcpy(output[written_usize..][0..@intCast(frag_bytes)], scratch.frag[off..][0..@intCast(frag_bytes)]);
            }
            written += frag_bytes;
        }
    }
    if (written != output.len) return error.DataException;
}

fn walkChosen(archive: []const u8, scratch: []u8, target: DirTarget) Exception!u64 {
    var carved = try Scratch.carve(scratch);
    const super = try parseSuper(archive);
    return walkDir(archive, super, &carved, target);
}

pub fn inspectCount(archive: []const u8, scratch: []u8) Exception!u64 {
    return walkChosen(archive, scratch, .count);
}

pub fn inspectOrdinal(archive: []const u8, ordinal: u64, scratch: []u8) Exception!EntryInfo {
    var info: EntryInfo = undefined;
    _ = try walkChosen(archive, scratch, .{ .resolve = .{ .ordinal = ordinal, .info = &info, .output = null } });
    return info;
}

pub fn decodeOrdinal(archive: []const u8, ordinal: u64, output: []u8, scratch: []u8) Exception!usize {
    var info: EntryInfo = undefined;
    _ = try walkChosen(archive, scratch, .{ .resolve = .{ .ordinal = ordinal, .info = &info, .output = output } });
    return @intCast(info.size);
}

fn validateName(name: []const u8) Exception!void {
    if (name.len == 0 or name.len > 512) return error.CallException;
    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |part| {
        if (part.len == 0 or part.len > 256) return error.CallException;
        if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.CallException;
    }
}

const Node = struct {
    kind: enum { dir, file },
    name: []const u8,
    parent: u32,
    data: []const u8 = &.{},
    blocks: u32 = 0,
    data_off: u64 = 0,
    number: u32 = 0,
    first_child: u32 = 0,
    child_count: u32 = 0,
    subdir_count: u32 = 0,
    dir_start: u32 = 0,
    dir_size: u32 = 0,
};

const max_nodes = 512;

const Plan = struct {
    nodes: []Node,
    order: []u32,
    kids: []u32,
    inode_block_rel: []u64,
    inode_block_off: []u16,
    block_head: []u32,
    dir_raw: []u8,
    dir_spans: []Span,
    data_total: u64,
    inode_table_total: u64,
    dir_table_total: u64,
    total: u64,
};

const Sink = struct {
    bytes: []u8,
    pos: usize = 0,

    fn write(self: *Sink, data: []const u8) Exception!void {
        if (self.pos + data.len > self.bytes.len) return error.CapacityException;
        @memcpy(self.bytes[self.pos .. self.pos + data.len], data);
        self.pos += data.len;
    }
};

const Span = struct { start: u32, len: u32 };

// Spans arrays are zero-filled; the first empty entry terminates.
fn spanCount(spans: []const Span) usize {
    for (spans, 0..) |span, i| {
        if (span.len == 0) return i;
    }
    return spans.len;
}

fn pushSpan(spans: []Span, start: usize, len: usize) Exception!void {
    const n = spanCount(spans);
    if (n >= spans.len) return error.ResourceException;
    spans[n] = .{ .start = @intCast(start), .len = @intCast(len) };
}

// Write staging carved from scratch behind the read carving;
// alignment resolves dynamically.
const WriteWs = struct {
    stage: []u8,
    meta: []u8,
    block_head_pad: []u8,
    ws: []u32,

    fn carve(scratch: []u8) Exception!WriteWs {
        if (scratch.len < scratch_size) return error.CapacityException;
        const tail = scratch[read_scratch_size..];
        var at: usize = 0;
        const stage = tail[at..][0..block_staging_size];
        at += block_staging_size;
        const meta = tail[at..][0..meta_staging_size];
        at += meta_staging_size;
        const block_pad = tail[at..][0 .. max_data_blocks * 4];
        at += max_data_blocks * 4;
        if (tail.len - at < zstd_workspace_extra) return error.ResourceException;
        const base = tail[at..][0..zstd_workspace_extra];
        const pad = (4 - (@intFromPtr(base.ptr) & 3)) & 3;
        if (base.len < pad) return error.ResourceException;
        const region = base[pad..];
        const ws_u32s = zstd_leaf.encoderWorkspaceU32Count(0, block_size_default, zstd_options);
        if (region.len < ws_u32s * 4) return error.ResourceException;
        const ws: []u32 = @alignCast(std.mem.bytesAsSlice(u32, region[0 .. ws_u32s * 4]));
        return .{ .stage = stage, .meta = meta, .block_head_pad = block_pad, .ws = ws };
    }
};

fn zstdCompress(ws: []u32, stage: []u8, block: []const u8) Exception!usize {
    var sink = std.Io.Writer.fixed(stage);
    return zstd_leaf.encodeFrame(&sink, block, ws, zstd_options, 0) catch return error.DataException;
}

const BlockFrame = struct { head: u32, bytes: []const u8, disk: u64 };

fn blockFrame(ws: *WriteWs, block: []const u8) Exception!BlockFrame {
    const compressed = try zstdCompress(ws.ws, ws.stage, block);
    if (compressed < block.len) return .{ .head = @intCast(compressed), .bytes = ws.stage[0..compressed], .disk = compressed };
    return .{ .head = @as(u32, @intCast(block.len)) | data_uncompressed_bit, .bytes = block, .disk = block.len };
}

const MetaSpan = union(enum) { compressed: []const u8, raw: []const u8 };

fn metaSpan(ws: []u32, stage: []u8, block: []const u8) Exception!MetaSpan {
    const compressed = try zstdCompress(ws, stage, block);
    if (compressed < block.len) return .{ .compressed = stage[0..compressed] };
    return .{ .raw = block };
}

// Measures one metadata span; blocks that expand are stored raw per the
// format. The header size field carries the full byte count, unlike data blocks.
fn metaSpanDisk(ws: []u32, stage: []u8, block: []const u8) Exception!u64 {
    return switch (try metaSpan(ws, stage, block)) {
        .compressed => |c| 2 + c.len,
        .raw => |r| 2 + r.len,
    };
}

fn emitMetaSpan(sink: *Sink, ws: []u32, stage: []u8, block: []const u8) Exception!void {
    switch (try metaSpan(ws, stage, block)) {
        .compressed => |c| {
            var head: [2]u8 = undefined;
            std.mem.writeInt(u16, &head, @intCast(c.len), .little);
            try sink.write(&head);
            try sink.write(c);
        },
        .raw => |r| {
            var head: [2]u8 = undefined;
            std.mem.writeInt(u16, &head, flag_uncompressed_metadata | @as(u16, @intCast(r.len)), .little);
            try sink.write(&head);
            try sink.write(r);
        },
    }
}

fn writeSuper(sink: *Sink, plan: *const Plan) Exception!void {
    var raw: [super_disk_size]u8 = @splat(0);
    const id_start = plan.total - 8;
    std.mem.writeInt(u32, raw[0..4], magic, .little);
    std.mem.writeInt(u32, raw[4..8], @intCast(plan.nodes.len), .little);
    std.mem.writeInt(u32, raw[12..16], block_size_default, .little);
    std.mem.writeInt(u16, raw[20..22], compression_zstd, .little);
    std.mem.writeInt(u16, raw[22..24], block_log_default, .little);
    std.mem.writeInt(u16, raw[24..26], write_flags, .little);
    std.mem.writeInt(u16, raw[26..28], 2, .little);
    std.mem.writeInt(u16, raw[28..30], major_version, .little);
    const root_ref = (plan.inode_block_rel[0] << 16) | plan.inode_block_off[0];
    std.mem.writeInt(u64, raw[32..40], root_ref, .little);
    std.mem.writeInt(u64, raw[40..48], plan.total, .little);
    std.mem.writeInt(u64, raw[48..56], id_start, .little);
    std.mem.writeInt(u64, raw[56..64], invalid_table, .little);
    std.mem.writeInt(u64, raw[64..72], super_disk_size + plan.data_total, .little);
    std.mem.writeInt(u64, raw[72..80], super_disk_size + plan.data_total + plan.inode_table_total, .little);
    std.mem.writeInt(u64, raw[80..88], invalid_table, .little);
    std.mem.writeInt(u64, raw[88..96], invalid_table, .little);
    try sink.write(&raw);
}

fn nodeInodeSize(node: *const Node) usize {
    return if (node.kind == .dir) 32 else 32 + 4 * @as(usize, node.blocks);
}

// Directory inodes embed their dir_start/dir_size.
fn buildInodeTableRaw(plan: *const Plan, buf: []u8, spans: []Span) Exception!usize {
    var used: usize = 0;
    var span_start: usize = 0;
    for (plan.order) |ni| {
        const node = &plan.nodes[ni];
        const inode_size = nodeInodeSize(node);
        if (used > 0 and used + inode_size > metadata_size) {
            try pushSpan(spans, span_start, used - span_start);
            span_start = used;
        }
        if (used + inode_size > buf.len) return error.ResourceException;
        var raw: [32]u8 = @splat(0);
        std.mem.writeInt(u16, raw[4..6], uid_index, .little);
        std.mem.writeInt(u16, raw[6..8], guid_index, .little);
        std.mem.writeInt(u32, raw[12..16], node.number, .little);
        if (node.kind == .file) {
            std.mem.writeInt(u16, raw[0..2], inode_type_reg, .little);
            std.mem.writeInt(u16, raw[2..4], mode_file, .little);
            std.mem.writeInt(u32, raw[16..20], @intCast(node.data_off), .little);
            std.mem.writeInt(u32, raw[20..24], invalid_fragment, .little);
            std.mem.writeInt(u32, raw[28..32], @intCast(node.data.len), .little);
        } else {
            std.mem.writeInt(u16, raw[0..2], inode_type_dir, .little);
            std.mem.writeInt(u16, raw[2..4], mode_dir, .little);
            std.mem.writeInt(u32, raw[16..20], node.dir_start, .little);
            std.mem.writeInt(u32, raw[20..24], 2 + node.subdir_count, .little);
            std.mem.writeInt(u16, raw[24..26], @intCast(node.dir_size + 3), .little);
            std.mem.writeInt(u16, raw[26..28], 0, .little);
            std.mem.writeInt(u32, raw[28..32], if (node.number == 1) 1 else node.parent + 1, .little);
        }
        @memcpy(buf[used .. used + 32], &raw);
        var off = used + 32;
        if (node.kind == .file) {
            const start_index = fileBlockBase(plan, ni);
            for (0..node.blocks) |blk| {
                std.mem.writeInt(u32, buf[off..][0..4], plan.block_head[start_index + blk], .little);
                off += 4;
            }
        }
        used += inode_size;
    }
    spans[spanCount(spans)] = .{ .start = @intCast(span_start), .len = @intCast(used - span_start) };
    return used;
}

fn fileBlockBase(plan: *const Plan, node_index: u32) usize {
    var base: usize = 0;
    for (plan.order) |ni| {
        const node = &plan.nodes[ni];
        if (ni == node_index) return base;
        if (node.kind == .file) base += node.blocks;
    }
    return base;
}

// Inodes are addressed by disk offset, so a span that compresses advances
// the next span by its compressed size, not its raw length. Recompute rel
// from the measured layout once the raw table exists.
fn recomputeInodeDiskRels(plan: *Plan, spans: []const Span, buf: []const u8, ws: *WriteWs) Exception!void {
    const count = spanCount(spans);
    var span_i: usize = 0;
    var span_end_raw: usize = if (count > 0) spans[0].len else 0;
    var span_base: u64 = 0;
    for (plan.order) |ni| {
        const rank = orderRank(plan, ni);
        const off = plan.inode_block_off[rank];
        while (span_i + 1 < count and off >= span_end_raw) {
            span_base = try bounds.addU64(span_base, 2 + try metaSpanDisk(ws.ws, ws.stage, buf[spans[span_i].start..][0..spans[span_i].len]));
            span_i += 1;
            span_end_raw = try bounds.addUsize(span_end_raw, spans[span_i].len);
        }
        plan.inode_block_rel[rank] = span_base;
    }
}

// Every directory starts a fresh 8 KiB block. dir_offset stays zero;
// dir_start sums preceding compressed sizes.
fn buildDirTableRaw(plan: *Plan, ws: *WriteWs, buf: []u8, spans: []Span) Exception!usize {
    var used: usize = 0;
    var span_start: usize = 0;
    var dir_start: u32 = 0;
    for (plan.order) |ni| {
        const node = &plan.nodes[ni];
        if (node.kind != .dir) continue;
        // Flush before each directory so it starts at a block boundary.
        if (used > span_start) {
            try pushSpan(spans, span_start, used - span_start);
            const span_disk = try metaSpanDisk(ws.ws, ws.stage, buf[span_start..used]);
            dir_start = std.math.cast(u32, dir_start + span_disk) orelse return error.DataException;
            span_start = used;
        }
        node.dir_start = dir_start;
        const start = plan.kids[node.first_child .. node.first_child + node.child_count];
        const dir_size = dirPayloadSizeFor(plan, start);
        node.dir_size = dir_size;
        if (dir_size + 3 > std.math.maxInt(u16)) return error.UnsupportedException;
        var chunk: u32 = 0;
        var prev_block: ?u64 = null;
        var prev_inode: i64 = 0;
        for (start, 0..) |child_idx, ci| {
            const child = &plan.nodes[child_idx];
            const rank = orderRank(plan, child_idx);
            const rel = plan.inode_block_rel[rank];
            if (chunk == 0 or chunk == max_entries or prev_block != rel) {
                if (used + 12 > buf.len or used - span_start + 12 > metadata_size) return error.ResourceException;
                var run: u32 = 0;
                var scan = ci;
                while (scan < start.len and run < max_entries and plan.inode_block_rel[orderRank(plan, start[scan])] == rel) {
                    run += 1;
                    scan += 1;
                }
                var hdr: [12]u8 = @splat(0);
                std.mem.writeInt(u32, hdr[0..4], run - 1, .little);
                std.mem.writeInt(u32, hdr[4..8], @intCast(rel), .little);
                std.mem.writeInt(u32, hdr[8..12], child.number, .little);
                @memcpy(buf[used .. used + 12], &hdr);
                used += 12;
                prev_inode = child.number;
                prev_block = rel;
                chunk = 0;
            }
            const need = 8 + child.name.len;
            if (used + need > buf.len or used - span_start + need > metadata_size) return error.UnsupportedException;
            var ent: [8]u8 = undefined;
            std.mem.writeInt(u16, ent[0..2], plan.inode_block_off[rank], .little);
            const delta: i64 = @as(i64, child.number) - prev_inode;
            if (delta < std.math.minInt(i16) or delta > std.math.maxInt(i16)) return error.UnsupportedException;
            std.mem.writeInt(i16, ent[2..4], @intCast(delta), .little);
            std.mem.writeInt(u16, ent[4..6], if (child.kind == .dir) inode_type_dir else inode_type_reg, .little);
            std.mem.writeInt(u16, ent[6..8], @intCast(child.name.len - 1), .little);
            prev_inode = child.number;
            @memcpy(buf[used .. used + 8], &ent);
            @memcpy(buf[used + 8 .. used + need], child.name);
            used += need;
            chunk += 1;
        }
    }
    if (used > span_start) {
        try pushSpan(spans, span_start, used - span_start);
    }
    return used;
}

fn dirPayloadSizeFor(plan: *const Plan, start: []const u32) u32 {
    var size: u32 = 0;
    var chunk: u32 = 0;
    var prev_block: ?u64 = null;
    for (start) |child_idx| {
        const rel = plan.inode_block_rel[orderRank(plan, child_idx)];
        if (chunk == 0 or chunk == max_entries or prev_block != rel) {
            size += 12;
            chunk = 0;
        }
        prev_block = rel;
        size += @intCast(8 + plan.nodes[child_idx].name.len);
        chunk += 1;
    }
    return size;
}

fn orderRank(plan: *const Plan, node_index: u32) usize {
    return orderRankSlice(plan.order, node_index);
}

fn writeIdTable(sink: *Sink) Exception!void {
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

fn buildPlan(entries: []const Entry, ws: *WriteWs, alloc: std.mem.Allocator) Exception!Plan {
    // Tree build: nodes[0] roots the directory tree.
    var nodes: std.ArrayList(Node) = .empty;
    nodes.append(alloc, .{ .kind = .dir, .name = "", .parent = 0 }) catch return error.ResourceException;
    for (entries) |entry| {
        try validateName(entry.name);
        if (entry.data.len > std.math.maxInt(u32)) return error.UnsupportedException;
        var parent: u32 = 0;
        var it = std.mem.splitScalar(u8, entry.name, '/');
        var comp = it.next().?;
        while (it.next()) |next| {
            parent = try findOrCreateDir(&nodes, alloc, parent, comp);
            comp = next;
        }
        nodes.append(alloc, .{ .kind = .file, .name = comp, .parent = parent, .data = entry.data }) catch return error.ResourceException;
        nodes.items[parent].child_count += 1;
    }
    if (nodes.items.len > max_nodes) return error.UnsupportedException;

    // Per-directory child lists in name order.
    var counts = alloc.alloc(u32, nodes.items.len) catch return error.ResourceException;
    @memset(counts, 0);
    for (nodes.items, 0..) |node, i| {
        if (i == 0) continue;
        counts[node.parent] += 1;
    }
    var starts = alloc.alloc(u32, nodes.items.len) catch return error.ResourceException;
    var acc: u32 = 0;
    for (counts, 0..) |c, i| {
        starts[i] = acc;
        acc += c;
    }
    var kids = alloc.alloc(u32, acc) catch return error.ResourceException;
    var fill = alloc.alloc(u32, nodes.items.len) catch return error.ResourceException;
    @memcpy(fill, starts);
    for (nodes.items, 0..) |node, i| {
        if (i == 0) continue;
        kids[fill[node.parent]] = @intCast(i);
        fill[node.parent] += 1;
    }
    for (nodes.items, 0..) |*node, i| {
        node.first_child = starts[i];
        const slice = kids[node.first_child .. node.first_child + counts[i]];
        std.mem.sort(u32, slice, &nodes, struct {
            fn less(ns: *std.ArrayList(Node), a: u32, b: u32) bool {
                return std.mem.order(u8, ns.items[a].name, ns.items[b].name) == .lt;
            }
        }.less);
    }

    // Inode numbers follow DFS pre-order, one-based.
    var order: std.ArrayList(u32) = .empty;
    try tree_order.orderTree(Node, &nodes, kids, 0, &order, null, alloc);
    for (nodes.items) |*node| {
        node.number = 0;
    }
    for (order.items, 0..) |ni, rank| {
        nodes.items[ni].number = @intCast(rank + 1);
    }

    var block_head = alloc.alloc(u32, totalFileBlocks(nodes.items)) catch return error.ResourceException;
    var data_total: u64 = 0;
    var k: usize = 0;
    for (order.items) |ni| {
        const node = &nodes.items[ni];
        if (node.kind != .file) continue;
        node.blocks = @intCast((node.data.len + block_size_default - 1) / block_size_default);
        node.data_off = super_disk_size + data_total;
        var data_off: u64 = 0;
        for (0..node.blocks) |_| {
            const take: usize = @intCast(@min(@as(u64, block_size_default), node.data.len - data_off));
            const block = node.data[@intCast(data_off)..][0..take];
            const frame = try blockFrame(ws, block);
            block_head[k] = frame.head;
            data_total = try bounds.addU64(data_total, frame.disk);
            k += 1;
            data_off = try bounds.addU64(data_off, take);
        }
    }

    var rel = alloc.alloc(u64, order.items.len) catch return error.ResourceException;
    var ioff = alloc.alloc(u16, order.items.len) catch return error.ResourceException;
    var block_rel: u64 = 0;
    var used: u64 = 0;
    for (order.items) |ni| {
        const size = nodeInodeSize(&nodes.items[ni]);
        if (used > 0 and used + size > metadata_size) {
            block_rel += 2 + used;
            used = 0;
        }
        rel[orderRankSlice(order.items, ni)] = block_rel;
        ioff[orderRankSlice(order.items, ni)] = @intCast(used);
        used += size;
    }

    // Compression measure assigns each dir its dir_start.
    const dir_buf = ws.meta[0 .. ws.meta.len / 2];
    const inode_buf = ws.meta[ws.meta.len / 2 ..];
    var plan = Plan{
        .nodes = nodes.items,
        .order = order.items,
        .kids = kids,
        .inode_block_rel = rel,
        .inode_block_off = ioff,
        .block_head = block_head,
        .dir_raw = dir_buf,
        .dir_spans = alloc.alloc(Span, 16) catch return error.ResourceException,
        .data_total = data_total,
        .inode_table_total = 0,
        .dir_table_total = 0,
        .total = 0,
    };
    @memset(plan.dir_spans, .{ .start = 0, .len = 0 });
    _ = try buildDirTableRaw(&plan, ws, dir_buf, plan.dir_spans);
    var dir_table_total: u64 = 0;
    for (plan.dir_spans[0..spanCount(plan.dir_spans)]) |span| {
        dir_table_total = try bounds.addU64(dir_table_total, try metaSpanDisk(ws.ws, ws.stage, dir_buf[span.start..][0..span.len]));
    }
    plan.dir_table_total = dir_table_total;

    var inode_spans = alloc.alloc(Span, 16) catch return error.ResourceException;
    @memset(inode_spans, .{ .start = 0, .len = 0 });
    _ = try buildInodeTableRaw(&plan, inode_buf, inode_spans);
    var inode_table_total: u64 = 0;
    for (inode_spans[0..spanCount(inode_spans)]) |span| {
        inode_table_total = try bounds.addU64(inode_table_total, try metaSpanDisk(ws.ws, ws.stage, inode_buf[span.start..][0..span.len]));
    }
    plan.inode_table_total = inode_table_total;
    plan.total = super_disk_size + data_total + inode_table_total + dir_table_total + (8 + 2 + 8);
    return plan;
}

fn orderRankSlice(order: []const u32, node_index: u32) usize {
    for (order, 0..) |ni, rank| {
        if (ni == node_index) return rank;
    }
    unreachable;
}

fn totalFileBlocks(nodes: []const Node) usize {
    var n: usize = 0;
    for (nodes) |node| {
        if (node.kind == .file) n += (node.data.len + block_size_default - 1) / block_size_default;
    }
    return n;
}

fn findOrCreateDir(nodes: *std.ArrayList(Node), alloc: std.mem.Allocator, parent: u32, name: []const u8) Exception!u32 {
    for (nodes.items, 0..) |node, i| {
        if (node.kind == .dir and node.parent == parent and std.mem.eql(u8, node.name, name)) return @intCast(i);
    }
    const idx: u32 = @intCast(nodes.items.len);
    nodes.append(alloc, .{ .kind = .dir, .name = name, .parent = parent }) catch return error.ResourceException;
    nodes.items[parent].child_count += 1;
    // mksquashfs writes directory nlink as 2 + subdirectory count.
    nodes.items[parent].subdir_count += 1;
    return idx;
}

test "squashfs zstd write roundtrips flat files" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "hello.txt", .data = "hello squashfs hello squashfs hello squashfs" },
        .{ .name = "data.bin", .data = "ABCABCABCABCABCABCABCABCABCABCABCABC" },
    };
    var archive: [4096]u8 = undefined;
    var scratch: [scratch_size]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    try testing.expectEqual(written, try archiveSize(&entries, &scratch));
    // The store shape would cost 96 + 80 data + ~142 tables; zstd must win.
    try testing.expect(written < 318);
    try testing.expect(written > 96);
    try testing.expectEqual(@as(u64, 2), try inspectCount(archive[0..written], &scratch));
    // Ordinal zero is data.bin: names sort before writes, like mksquashfs.
    const first = try inspectOrdinal(archive[0..written], 0, &scratch);
    try testing.expectEqual(@as(u64, 36), first.size);
    var out: [36]u8 = undefined;
    const n = try decodeOrdinal(archive[0..written], 0, &out, &scratch);
    try testing.expectEqualSlices(u8, entries[1].data, out[0..n]);
    var out1: [44]u8 = undefined;
    const n1 = try decodeOrdinal(archive[0..written], 1, &out1, &scratch);
    try testing.expectEqualSlices(u8, entries[0].data, out1[0..n1]);
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

pub fn archiveSize(entries: []const Entry, scratch: []u8) Exception!u64 {
    var ws = try WriteWs.carve(scratch);
    // The plan allocator borrows the read carving; encode never reads.
    var fba = std.heap.FixedBufferAllocator.init(scratch[0..read_scratch_size]);
    const plan = try buildPlan(entries, &ws, fba.allocator());
    return plan.total;
}

pub fn encode(entries: []const Entry, output: []u8, scratch: []u8) Exception!usize {
    var ws = try WriteWs.carve(scratch);
    // The plan allocator borrows the read carving; encode never reads.
    var fba = std.heap.FixedBufferAllocator.init(scratch[0..read_scratch_size]);
    const alloc = fba.allocator();
    var plan = try buildPlan(entries, &ws, alloc);
    if (output.len < plan.total) return error.CapacityException;
    var sink = Sink{ .bytes = output };
    try writeSuper(&sink, &plan);
    for (plan.order) |ni| {
        const node = &plan.nodes[ni];
        if (node.kind != .file) continue;
        var data_off: u64 = 0;
        for (0..node.blocks) |_| {
            const take: usize = @intCast(@min(@as(u64, block_size_default), node.data.len - data_off));
            const block = node.data[@intCast(data_off)..][0..take];
            try sink.write((try blockFrame(&ws, block)).bytes);
            data_off = try bounds.addU64(data_off, take);
        }
    }
    const inode_buf = ws.meta[ws.meta.len / 2 ..];
    var inode_spans: [16]Span = @splat(.{ .start = 0, .len = 0 });
    _ = try buildInodeTableRaw(&plan, inode_buf, &inode_spans);
    // Directory entries embed rel, so the table must be rebuilt once rel
    // reflects the compressed on-disk layout.
    try recomputeInodeDiskRels(&plan, &inode_spans, inode_buf, &ws);
    @memset(plan.dir_spans, .{ .start = 0, .len = 0 });
    _ = try buildDirTableRaw(&plan, &ws, plan.dir_raw, plan.dir_spans);
    for (inode_spans[0..spanCount(&inode_spans)]) |span| {
        try emitMetaSpan(&sink, ws.ws, ws.stage, inode_buf[span.start..][0..span.len]);
    }
    for (plan.dir_spans[0..spanCount(plan.dir_spans)]) |span| {
        try emitMetaSpan(&sink, ws.ws, ws.stage, plan.dir_raw[span.start..][0..span.len]);
    }
    try writeIdTable(&sink);
    if (sink.pos != plan.total) return error.DataException;
    return sink.pos;
}

test "squashfs zstd write roundtrips nested directories" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "a/b/deep.txt", .data = "nested payload" },
        .{ .name = "a/sib.txt", .data = "sibling" },
        .{ .name = "top.txt", .data = "root file" },
    };
    var archive: [8192]u8 = undefined;
    var scratch: [scratch_size]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    try testing.expectEqual(written, try archiveSize(&entries, &scratch));
    try testing.expectEqual(@as(u64, 3), try inspectCount(archive[0..written], &scratch));
    var out: [16]u8 = undefined;
    const n0 = try decodeOrdinal(archive[0..written], 0, &out, &scratch);
    try testing.expectEqualSlices(u8, "nested payload", out[0..n0]);
    const n1 = try decodeOrdinal(archive[0..written], 1, &out, &scratch);
    try testing.expectEqualSlices(u8, "sibling", out[0..n1]);
    const n2 = try decodeOrdinal(archive[0..written], 2, &out, &scratch);
    try testing.expectEqualSlices(u8, "root file", out[0..n2]);
}

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

test "squashfs fragment index count uses ceil like unsquashfs" {
    const testing = std.testing;
    var image: [mksquashfs_fixture.len]u8 = undefined;
    @memcpy(&image, &mksquashfs_fixture);
    // 512 fragments make the entry table an exact 8 KiB: one index slot.
    std.mem.writeInt(u32, image[16..20], 512, .little);
    // Trim the archive to the end of the 8-byte index. The old floor + 1
    // formula demanded a second slot and failed past the archive end.
    std.mem.writeInt(u64, image[40..48], 255, .little);
    const trimmed = image[0..255];
    var scratch: [scratch_size]u8 = undefined;
    try testing.expectEqual(@as(u64, 2), try inspectCount(trimmed, &scratch));
    var out: [445]u8 = undefined;
    const n = try decodeOrdinal(trimmed, 1, &out, &scratch);
    try testing.expectEqual(@as(usize, 445), n);
}

test "squashfs fragment offset bound follows block size" {
    const testing = std.testing;
    // A foreign image with block_log 18: valid fragment offsets reach past
    // the 128 KiB scratch bound the old check used. All blocks are stored
    // raw, so no compressor runs.
    const bs: u32 = 256 * 1024;
    const file1_len: usize = 131073; // just past the old scratch bound.
    const file2_len: usize = 100;
    const frag_total = file1_len + file2_len;
    const inode_meta_at: u64 = 96 + frag_total;
    const dir_meta_at: u64 = inode_meta_at + 2 + 96;
    const frag_meta_at: u64 = dir_meta_at + 2 + 42;
    const frag_index_at: u64 = frag_meta_at + 2 + 16;
    const total: usize = @intCast(frag_index_at + 8);
    var image: [131437]u8 = @splat(0);
    try testing.expect(image.len == total);
    std.mem.writeInt(u32, image[0..4], magic, .little);
    std.mem.writeInt(u32, image[4..8], 3, .little);
    std.mem.writeInt(u32, image[12..16], bs, .little);
    std.mem.writeInt(u32, image[16..20], 1, .little);
    std.mem.writeInt(u16, image[20..22], compression_gzip, .little);
    std.mem.writeInt(u16, image[22..24], 18, .little);
    std.mem.writeInt(u16, image[26..28], 1, .little);
    std.mem.writeInt(u16, image[28..30], major_version, .little);
    std.mem.writeInt(u64, image[40..48], total, .little);
    std.mem.writeInt(u64, image[64..72], inode_meta_at, .little);
    std.mem.writeInt(u64, image[72..80], dir_meta_at, .little);
    std.mem.writeInt(u64, image[80..88], frag_index_at, .little);
    @memset(image[96 .. 96 + file1_len], 0xd1);
    @memset(image[96 + file1_len .. 96 + frag_total], 0xe2);
    // Inode metadata block: root dir, file1, file2.
    std.mem.writeInt(u16, image[@intCast(inode_meta_at)..][0..2], flag_uncompressed_metadata | 96, .little);
    const inodes = image[@intCast(inode_meta_at + 2)..];
    std.mem.writeInt(u16, inodes[0..2], inode_type_dir, .little);
    std.mem.writeInt(u16, inodes[2..4], mode_dir, .little);
    std.mem.writeInt(u32, inodes[12..16], 1, .little);
    std.mem.writeInt(u32, inodes[16..20], 0, .little);
    std.mem.writeInt(u32, inodes[20..24], 1, .little);
    std.mem.writeInt(u16, inodes[24..26], 45, .little);
    std.mem.writeInt(u32, inodes[28..32], 1, .little);
    std.mem.writeInt(u16, inodes[32..34], inode_type_reg, .little);
    std.mem.writeInt(u16, inodes[34..36], mode_file, .little);
    std.mem.writeInt(u32, inodes[44..48], 2, .little);
    std.mem.writeInt(u32, inodes[48..52], 0, .little);
    std.mem.writeInt(u32, inodes[52..56], 0, .little);
    std.mem.writeInt(u32, inodes[56..60], 0, .little);
    std.mem.writeInt(u32, inodes[60..64], file1_len, .little);
    std.mem.writeInt(u16, inodes[64..66], inode_type_reg, .little);
    std.mem.writeInt(u16, inodes[66..68], mode_file, .little);
    std.mem.writeInt(u32, inodes[76..80], 3, .little);
    std.mem.writeInt(u32, inodes[80..84], 0, .little);
    std.mem.writeInt(u32, inodes[84..88], 0, .little);
    std.mem.writeInt(u32, inodes[88..92], file1_len, .little);
    std.mem.writeInt(u32, inodes[92..96], file2_len, .little);
    // Directory metadata block: one header, two 7-byte names.
    std.mem.writeInt(u16, image[@intCast(dir_meta_at)..][0..2], flag_uncompressed_metadata | 42, .little);
    const dir = image[@intCast(dir_meta_at + 2)..];
    std.mem.writeInt(u32, dir[0..4], 1, .little);
    std.mem.writeInt(u32, dir[4..8], 0, .little);
    std.mem.writeInt(u32, dir[8..12], 2, .little);
    std.mem.writeInt(u16, dir[12..14], 32, .little);
    std.mem.writeInt(i16, dir[14..16], 0, .little);
    std.mem.writeInt(u16, dir[16..18], inode_type_reg, .little);
    std.mem.writeInt(u16, dir[18..20], 6, .little);
    @memcpy(dir[20..27], "one.bin");
    std.mem.writeInt(u16, dir[27..29], 64, .little);
    std.mem.writeInt(i16, dir[29..31], 1, .little);
    std.mem.writeInt(u16, dir[31..33], inode_type_reg, .little);
    std.mem.writeInt(u16, dir[33..35], 6, .little);
    @memcpy(dir[35..42], "two.bin");
    // Fragment table: raw entry block plus index.
    std.mem.writeInt(u16, image[@intCast(frag_meta_at)..][0..2], flag_uncompressed_metadata | 16, .little);
    std.mem.writeInt(u64, image[@intCast(frag_meta_at + 2)..][0..8], 96, .little);
    std.mem.writeInt(u32, image[@intCast(frag_meta_at + 10)..][0..4], data_uncompressed_bit | frag_total, .little);
    std.mem.writeInt(u64, image[@intCast(frag_index_at)..][0..8], frag_meta_at, .little);
    var scratch: [scratch_size]u8 = undefined;
    try testing.expectEqual(@as(u64, 2), try inspectCount(&image, &scratch));
    var out1: [file1_len]u8 = undefined;
    const n0 = try decodeOrdinal(&image, 0, &out1, &scratch);
    try testing.expectEqual(@as(usize, file1_len), n0);
    try testing.expect(std.mem.allEqual(u8, &out1, 0xd1));
    var out2: [file2_len]u8 = undefined;
    const n1 = try decodeOrdinal(&image, 1, &out2, &scratch);
    try testing.expectEqual(@as(usize, file2_len), n1);
    try testing.expect(std.mem.allEqual(u8, &out2, 0xe2));
}

test "squashfs written directories carry mksquashfs nlink" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "a/b/deep.txt", .data = "nested payload" },
        .{ .name = "a/sib.txt", .data = "sibling" },
        .{ .name = "top.txt", .data = "root file" },
    };
    var archive: [8192]u8 = undefined;
    var scratch: [scratch_size]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    const image = archive[0..written];
    var carved = try Scratch.carve(&scratch);
    const super = try parseSuper(image);
    try testing.expectEqual(@as(u64, 0), super.root_ref);
    const block = try inflateMeta(super.compression, image, super.inode_table_start, carved.meta, carved.history, carved.aux);
    try testing.expect(block.len >= 128);
    const raw = carved.meta[0..block.len];
    // DFS order: root, a, b. mksquashfs writes nlink = 2 + subdirs.
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, raw[20..24], .little));
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, raw[52..56], .little));
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, raw[84..88], .little));
}
