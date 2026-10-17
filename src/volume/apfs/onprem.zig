const std = @import("std");

const bounds = @import("../../common/primitive/bounds.zig");
const exception_prim = @import("../../common/primitive/exception.zig");

const Exception = exception_prim.Exception;

// Layouts: apfs_raw.h (linux-apfs/linux-apfs-rw); ApfsHandler (vendor/7zip).
// Checksum: APFS Fletcher-64, libfsapfs_checksum.c (libyal/libfsapfs), over block[8..] with initial value 0.
// Read-only.

pub const scratch_size: usize = 4096;

pub const Entry = struct {
    name: []const u8,
    data: []const u8,
};

pub const EntryInfo = struct {
    size: u64,
    ordinal: u64,
};

const max_dir_depth: u32 = 64;
const max_descriptor_blocks = 10000;
const max_tree_depth = 64;

const nx_magic: u32 = 0x4253584E; // "NXSB"
const fs_magic: u32 = 0x42535041; // "APSB"

const obj_type_btree: u32 = 0x2;
const obj_type_btree_node: u32 = 0x3;
const obj_type_omap: u32 = 0xb;
const obj_type_checkpoint_map: u32 = 0xc;
const obj_type_fs: u32 = 0xd;

const obj_subtype_omap: u32 = 0xb;
const obj_subtype_fs_tree: u32 = 0xe;

const obj_flag_ephemeral: u32 = 0x80000000;
const obj_flag_physical: u32 = 0x40000000;
const obj_storagetype_mask: u32 = 0xc0000000;

const btn_flag_root: u16 = 0x1;
const btn_flag_leaf: u16 = 0x2;
const btn_flag_fixed_kv: u16 = 0x4;

const btinfo_flag_ephemeral: u32 = 0x8;
const btinfo_flag_physical: u32 = 0x10;

const rec_type_inode: u64 = 3;
const rec_type_file_extent: u64 = 8;
const rec_type_dir_rec: u64 = 9;

const incompat_case_insensitive: u64 = 0x1;
const incompat_normalization_insensitive: u64 = 0x8;

const drec_len_mask: u32 = 0x3ff;

const mode_fmt_mask: u32 = 0xf000;
const mode_dir: u32 = 0x4000;
const mode_reg: u32 = 0x8000;

const key_id_mask: u64 = 0x0fffffffffffffff;
const key_type_shift = 60;

const root_dir_ino: u64 = 2;

const checkpoint_map_entry_size = 0x28;
const btree_info_size = 0x28;
const btree_node_header_size = 0x38;

fn le16(p: []const u8) u16 {
    return std.mem.readInt(u16, p[0..2], .little);
}
fn le32(p: []const u8) u32 {
    return std.mem.readInt(u32, p[0..4], .little);
}
fn le64(p: []const u8) u64 {
    return std.mem.readInt(u64, p[0..8], .little);
}

fn fletcher64(data: []const u8) u64 {
    var lower: u64 = 0;
    var upper: u64 = 0;
    var i: usize = 0;
    while (i + 4 <= data.len) : (i += 4) {
        lower += le32(data[i..][0..4]);
        upper += lower;
    }
    const modulus: u64 = 0xffffffff;
    lower %= modulus;
    upper %= modulus;
    const lo32 = modulus - ((lower + upper) % modulus);
    const hi32 = modulus - ((lower + lo32) % modulus);
    return (hi32 << 32) | lo32;
}

fn checksumValid(block: []const u8) bool {
    return le64(block[0..8]) == fletcher64(block[8..]);
}

const Image = struct {
    bytes: []const u8,
    block_size: u64,
    block_count: u64,

    fn block(self: *const Image, paddr: u64) Exception![]const u8 {
        if (paddr >= self.block_count) return error.DataException;
        return bounds.slice(self.bytes, paddr * self.block_size, self.block_size);
    }
};

fn objType(block_bytes: []const u8) u32 {
    return le32(block_bytes[24..28]);
}

fn objSubtype(block_bytes: []const u8) u32 {
    return le32(block_bytes[28..32]);
}

fn objXid(block_bytes: []const u8) u64 {
    return le64(block_bytes[16..24]);
}

// Fletcher-64 (APFS flavor) test vectors, hand-computed from the algorithm.
test "apfs fletcher64 reference vectors" {
    var zeros: [64]u8 = @splat(0);
    try std.testing.expectEqual(@as(u64, 0xffffffffffffffff), fletcher64(&zeros));
    @memset(&zeros, 0);
    zeros[0] = 1;
    try std.testing.expectEqual(@as(u64, 0x00000001fffffffd), fletcher64(zeros[0..4]));
    @memset(&zeros, 0);
    zeros[0] = 1;
    zeros[4] = 2;
    try std.testing.expectEqual(@as(u64, 0x00000004fffffff8), fletcher64(zeros[0..8]));
}

// Checkpoint map: raw entries kept as a slice into the archive block.
const CheckpointMap = struct {
    entries: []const u8,

    fn resolve(self: CheckpointMap, oid: u64) ?u64 {
        var pos: usize = 0;
        while (pos + checkpoint_map_entry_size <= self.entries.len) : (pos += checkpoint_map_entry_size) {
            const entry = self.entries[pos..][0..checkpoint_map_entry_size];
            if (le64(entry[24..32]) == oid) return le64(entry[32..40]);
        }
        return null;
    }
};

const Footer = struct { flags: u32, node_size: u32, key_size: u32, val_size: u32 };

const Node = struct {
    bytes: []const u8,
    flags: u16,
    level: u16,
    nkeys: u32,
    fixed_kv: bool,
    key_area: usize,

    fn parse(bytes: []const u8, subtype: u32) Exception!Node {
        if (bytes.len < btree_node_header_size) return error.DataException;
        const flags = le16(bytes[32..34]);
        const is_root = flags & btn_flag_root != 0;
        // Roots carry OBJECT_TYPE_BTREE, children OBJECT_TYPE_BTREE_NODE;
        // the type and the root flag must agree,
        // and the subtype selects the tree the node belongs to.
        const ty = objType(bytes) & 0xffff;
        if (ty != obj_type_btree and ty != obj_type_btree_node) return error.DataException;
        if ((ty == obj_type_btree) != is_root) return error.DataException;
        if (objSubtype(bytes) != subtype) return error.DataException;
        const level = le16(bytes[34..36]);
        if ((flags & btn_flag_leaf != 0) != (level == 0)) return error.DataException;
        const table_off = le16(bytes[40..42]);
        const table_len = le16(bytes[42..44]);
        const key_area = btree_node_header_size + table_off + table_len;
        if (key_area > bytes.len) return error.DataException;
        return .{
            .bytes = bytes,
            .flags = flags,
            .level = level,
            .nkeys = le32(bytes[36..40]),
            .fixed_kv = flags & btn_flag_fixed_kv != 0,
            .key_area = key_area,
        };
    }

    fn isRoot(self: Node) bool {
        return self.flags & btn_flag_root != 0;
    }

    fn isLeaf(self: Node) bool {
        return self.flags & btn_flag_leaf != 0;
    }

    const Loc = struct { off: usize, len: usize };

    fn keyLoc(self: Node, index: u32, ft: Footer) Exception!Loc {
        if (index >= self.nkeys) return error.DataException;
        if (self.fixed_kv) {
            const base = btree_node_header_size + @as(usize, index) * 4;
            if (base + 4 > self.bytes.len) return error.DataException;
            return .{ .off = self.key_area + le16(self.bytes[base..][0..2]), .len = ft.key_size };
        }
        const base = btree_node_header_size + @as(usize, index) * 8;
        if (base + 8 > self.bytes.len) return error.DataException;
        return .{
            .off = self.key_area + le16(self.bytes[base..][0..2]),
            .len = le16(self.bytes[base + 2 ..][0..2]),
        };
    }

    fn valueLoc(self: Node, index: u32, ft: Footer) Exception!Loc {
        if (index >= self.nkeys) return error.DataException;
        // Value offsets count backwards, from the footer when the node is a
        // root and from the end of the block otherwise.
        const end = self.bytes.len - @as(usize, if (self.isRoot()) btree_info_size else 0);
        if (self.fixed_kv) {
            const base = btree_node_header_size + @as(usize, index) * 4;
            if (base + 4 > self.bytes.len) return error.DataException;
            const v_off = le16(self.bytes[base + 2 ..][0..2]);
            if (end < v_off) return error.DataException;
            return .{ .off = end - v_off, .len = ft.val_size };
        }
        const base = btree_node_header_size + @as(usize, index) * 8;
        if (base + 8 > self.bytes.len) return error.DataException;
        const v_off = le16(self.bytes[base + 4 ..][0..2]);
        if (end < v_off) return error.DataException;
        return .{
            .off = end - v_off,
            .len = le16(self.bytes[base + 6 ..][0..2]),
        };
    }

    fn key(self: Node, index: u32, ft: Footer) Exception![]const u8 {
        const loc = try self.keyLoc(index, ft);
        if (loc.off + loc.len > self.bytes.len) return error.DataException;
        return self.bytes[loc.off..][0..loc.len];
    }

    fn value(self: Node, index: u32, ft: Footer) Exception![]const u8 {
        const loc = try self.valueLoc(index, ft);
        if (loc.off + loc.len > self.bytes.len) return error.DataException;
        return self.bytes[loc.off..][0..loc.len];
    }

    fn footer(self: Node) Exception!Footer {
        if (!self.isRoot()) return error.DataException;
        const base = self.bytes.len - btree_info_size;
        if (base < btree_node_header_size) return error.DataException;
        return .{
            .flags = le32(self.bytes[base..][0..4]),
            .node_size = le32(self.bytes[base + 4 ..][0..4]),
            .key_size = le32(self.bytes[base + 8 ..][0..4]),
            .val_size = le32(self.bytes[base + 12 ..][0..4]),
        };
    }
};

const Mount = struct {
    image: Image,
    xid: u64,
    cp_map: CheckpointMap,
    superblock: []const u8,
    container_omap_root: u64,
    volume_omap_root: u64,
    fs_root: u64,
    hashed_drec: bool,
};

pub fn inspectCount(archive: []const u8, scratch: []u8) Exception!u64 {
    _ = scratch;
    return walk(archive, .count);
}

pub fn inspectOrdinal(archive: []const u8, ordinal: u64, scratch: []u8) Exception!EntryInfo {
    _ = scratch;
    var info: EntryInfo = undefined;
    var found = false;
    _ = try walk(archive, .{ .resolve = .{ .ordinal = ordinal, .info = &info, .output = null, .found = &found } });
    return info;
}

pub fn decodeOrdinal(archive: []const u8, ordinal: u64, output: []u8, scratch: []u8) Exception!usize {
    _ = scratch;
    var info: EntryInfo = undefined;
    var found = false;
    _ = try walk(archive, .{ .resolve = .{ .ordinal = ordinal, .info = &info, .output = output, .found = &found } });
    return @intCast(info.size);
}

const Target = union(enum) {
    count,
    resolve: struct { ordinal: u64, info: *EntryInfo, output: ?[]u8, found: *bool },
};

const WalkState = struct { ordinal: u64 = 0 };

fn walk(archive: []const u8, target: Target) Exception!u64 {
    var mount = try open(archive);
    var state = WalkState{};
    var found = false;
    const resolved = switch (target) {
        .count => target,
        .resolve => |res| Target{ .resolve = .{ .ordinal = res.ordinal, .info = res.info, .output = res.output, .found = &found } },
    };
    const max_volumes = le32(mount.superblock[0xb4..0xb8]);
    if (max_volumes > 100) return error.DataException;
    for (0..max_volumes) |index| {
        const fs_oid = le64(mount.superblock[0xb8 + 8 * index ..][0..8]);
        if (fs_oid == 0) continue;
        try walkVolume(&mount, fs_oid, resolved, &state);
        switch (resolved) {
            .resolve => |res| if (res.found.*) return state.ordinal,
            .count => {},
        }
    }
    return switch (target) {
        .count => state.ordinal,
        .resolve => if (found) state.ordinal else error.DataException,
    };
}

fn open(archive: []const u8) Exception!Mount {
    const head = try bounds.slice(archive, 0, 4096);
    if (le32(head[0x20..0x24]) != nx_magic) return error.DataException;
    const block_size = le32(head[0x24..0x28]);
    if (block_size < 4096 or block_size > 65536 or !std.math.isPowerOfTwo(block_size)) return error.UnsupportedException;
    if (archive.len % block_size != 0) return error.DataException;
    const image = Image{ .bytes = archive, .block_size = block_size, .block_count = archive.len / block_size };

    const sb0 = try image.block(0);
    if (!checksumValid(sb0)) return error.DataException;

    var mount = Mount{
        .image = image,
        .xid = 0,
        .cp_map = .{ .entries = &.{} },
        .superblock = sb0,
        .container_omap_root = 0,
        .volume_omap_root = 0,
        .fs_root = 0,
        .hashed_drec = false,
    };
    try selectCheckpoint(&mount);

    // The container object map is a physical object:
    // nx_omap_oid holds its block number.
    const omap_paddr = le64(mount.superblock[0xa0..0xa8]);
    mount.container_omap_root = try omapRootAt(image, omap_paddr);
    return mount;
}

// Returns the omap tree root block number from the object map object at
// paddr. The object map object and its tree are physical.
fn omapRootAt(image: Image, paddr: u64) Exception!u64 {
    const block_bytes = try image.block(paddr);
    if (objType(block_bytes) & 0xffff != obj_type_omap) return error.DataException;
    if (objType(block_bytes) & obj_storagetype_mask != obj_flag_physical) return error.DataException;
    if (le64(block_bytes[8..16]) != paddr) return error.DataException;
    if (le32(block_bytes[0x28..0x2c]) != obj_flag_physical | obj_type_btree) return error.DataException;
    return le64(block_bytes[0x30..0x38]);
}

// A set most-significant bit in either checkpoint area count or base turns
// the area into a B-tree, which this reader does not implement.
fn checkpointAreasLinear(sb: []const u8) Exception!void {
    const desc_blocks = le32(sb[0x68..0x6c]);
    const data_blocks = le32(sb[0x6c..0x70]);
    const desc_base = le64(sb[0x70..0x78]);
    const data_base = le64(sb[0x78..0x80]);
    if (desc_blocks >> 31 != 0 or data_blocks >> 31 != 0 or
        desc_base >> 63 != 0 or data_base >> 63 != 0) return error.UnsupportedException;
}

fn selectCheckpoint(mount: *Mount) Exception!void {
    try checkpointAreasLinear(mount.superblock);
    const desc_base = le64(mount.superblock[0x70..0x78]);
    const desc_blocks = le32(mount.superblock[0x68..0x6c]);
    if (desc_blocks > max_descriptor_blocks) return error.DataException;
    const end = std.math.add(u64, desc_base, desc_blocks) catch return error.DataException;
    if (end > mount.image.block_count) return error.DataException;

    var best_xid = objXid(mount.superblock);
    var best_block: u64 = 0;
    var map_xid: u64 = 0;
    var map_entries: []const u8 = &.{};

    var i: u64 = 0;
    while (i < desc_blocks) : (i += 1) {
        const candidate = try mount.image.block(desc_base + i);
        const otype = objType(candidate);
        const xid = objXid(candidate);
        if (le32(candidate[0x20..0x24]) == nx_magic and xid > best_xid and checksumValid(candidate)) {
            best_xid = xid;
            best_block = desc_base + i;
        }
        if (otype & 0xffff == obj_type_checkpoint_map and otype & obj_flag_physical != 0 and xid > map_xid) {
            map_xid = xid;
            const count = le32(candidate[0x24..0x28]);
            const begin: usize = 0x28;
            const avail = candidate.len - begin;
            map_entries = candidate[begin .. begin + @min(avail, @as(usize, count) * checkpoint_map_entry_size)];
        }
    }
    if (best_block != 0) {
        const checkpoint = try mount.image.block(best_block);
        try checkpointAreasLinear(checkpoint);
        mount.superblock = checkpoint;
        mount.xid = best_xid;
    } else {
        mount.xid = best_xid;
    }
    mount.cp_map = .{ .entries = map_entries };
}

// B-tree node oid resolution. Physical trees use the oid as a block number;
// ephemeral trees ask the checkpoint map; virtual trees go through the
// owning object map. A miss is corruption, never resolved by identity.
fn resolveNode(mount: *const Mount, tree_flags: u32, owning_omap_root: u64, oid: u64) Exception!u64 {
    if (tree_flags & btinfo_flag_physical != 0) return oid;
    if (tree_flags & btinfo_flag_ephemeral != 0)
        return mount.cp_map.resolve(oid) orelse error.DataException;
    if (owning_omap_root == 0) return error.DataException;
    return (try omapLookup(mount, owning_omap_root, oid)) orelse error.DataException;
}

// Walk the object map B-tree. It is a physical tree:
// a branch value is a block number, and its root footer carries BTREE_PHYSICAL.
// Returns the entry with the largest xid not above mount.xid.
fn omapLookup(mount: *const Mount, root_paddr: u64, oid: u64) Exception!?u64 {
    const key_size = 16;
    const val_size = 16;
    var footer: Footer = .{ .flags = 0, .node_size = 0, .key_size = key_size, .val_size = val_size };
    var have_footer = false;
    var paddr = root_paddr;
    var guard: u32 = 0;
    while (true) {
        if (guard >= max_tree_depth) return error.DataException;
        guard += 1;
        const node = try Node.parse(try mount.image.block(paddr), obj_subtype_omap);
        if (objType(node.bytes) & obj_storagetype_mask != obj_flag_physical) return error.DataException;
        if (!have_footer) {
            if (!node.isRoot()) return error.DataException;
            footer = try node.footer();
            if (footer.flags & btinfo_flag_physical == 0) return error.DataException;
            have_footer = true;
        } else if (node.isRoot()) {
            return error.DataException; // Only the root carries the footer.
        }
        if (node.isLeaf()) {
            var best: ?u64 = null;
            var best_xid: u64 = 0;
            var i: u32 = 0;
            while (i < node.nkeys) : (i += 1) {
                const k = try node.key(i, footer);
                if (k.len < key_size or le64(k[0..8]) != oid) continue;
                const key_xid = le64(k[8..16]);
                if (key_xid > mount.xid) continue;
                if (best != null and key_xid <= best_xid) continue;
                const v = try node.value(i, footer);
                if (v.len < val_size) return error.DataException;
                best = le64(v[8..16]);
                best_xid = key_xid;
            }
            return best;
        }
        // Internal node: descend the rightmost entry with key <= (oid, xid).
        var i: u32 = node.nkeys;
        while (i > 0) {
            i -= 1;
            const k = try node.key(i, footer);
            if (k.len < key_size) return error.DataException;
            const k_oid = le64(k[0..8]);
            if (k_oid < oid or (k_oid == oid and le64(k[8..16]) <= mount.xid)) {
                const v = try node.value(i, footer);
                if (v.len < 8) return error.DataException;
                paddr = le64(v[0..8]);
                break;
            }
            if (i == 0) {
                const v = try node.value(0, footer);
                if (v.len < 8) return error.DataException;
                paddr = le64(v[0..8]);
            }
        }
    }
}

fn walkVolume(mount: *Mount, fs_oid: u64, target: Target, state: *WalkState) Exception!void {
    const vol_paddr = (try omapLookup(mount, mount.container_omap_root, fs_oid)) orelse
        return error.DataException;
    const vol = try mount.image.block(vol_paddr);
    if (objType(vol) & 0xffff != obj_type_fs) return error.DataException;
    if (le32(vol[0x20..0x24]) != fs_magic) return error.DataException;

    const incompat = le64(vol[0x38..0x40]);
    mount.hashed_drec = incompat & (incompat_case_insensitive | incompat_normalization_insensitive) != 0;

    const vol_omap_paddr = le64(vol[0x80..0x88]);
    mount.volume_omap_root = try omapRootAt(mount.image, vol_omap_paddr);

    // The root tree type carries its storage class.
    const fs_tree_type = le32(vol[0x74..0x78]);
    if (fs_tree_type & ~obj_storagetype_mask != obj_type_btree) return error.DataException;
    const fs_tree_flags: u32 = switch (fs_tree_type & obj_storagetype_mask) {
        obj_flag_physical => btinfo_flag_physical,
        obj_flag_ephemeral => btinfo_flag_ephemeral,
        else => 0,
    };
    mount.fs_root = try resolveNode(mount, fs_tree_flags, mount.volume_omap_root, le64(vol[0x88..0x90]));

    try walkDir(mount, root_dir_ino, target, state, 0);
}

const Inode = struct {
    mode: u32,
    private_id: u64,
    size: u64,
};

fn inodeFromValue(val: []const u8) Exception!Inode {
    if (val.len < 0x60) return error.DataException;
    const num_exts = le16(val[0x5c..0x5e]);
    const ext_table_end = 0x5c + 4 + @as(usize, num_exts) * 4;
    if (ext_table_end > val.len) return error.DataException;
    var size: u64 = 0;
    var pos: usize = ext_table_end;
    var ext: usize = 0x5c + 4;
    while (ext < ext_table_end) : (ext += 4) {
        const x_type = val[ext];
        const x_size = le16(val[ext + 2 ..][0..2]);
        if (pos + x_size > val.len) return error.DataException;
        if (x_type == 8 and x_size >= 8) size = le64(val[pos..][0..8]);
        pos += x_size;
    }
    return .{ .mode = le16(val[0x50..0x52]), .private_id = le64(val[8..16]), .size = size };
}

// Catalog keys order by object id, then type, then the payload.
// The packed header compares id and type separately, not as one u64.
fn fsKeyCompare(a: []const u8, b: []const u8, hashed: bool) std.math.Order {
    const ah = le64(a[0..8]);
    const bh = le64(b[0..8]);
    const a_id = ah & key_id_mask;
    const b_id = bh & key_id_mask;
    if (a_id != b_id) return std.math.order(a_id, b_id);
    const a_type = ah >> key_type_shift;
    const b_type = bh >> key_type_shift;
    if (a_type != b_type) return std.math.order(a_type, b_type);
    switch (a_type) {
        rec_type_dir_rec => {
            if (hashed) {
                const a_len_hash = if (a.len >= 0xc) le32(a[8..12]) else 0;
                const b_len_hash = if (b.len >= 0xc) le32(b[8..12]) else 0;
                const a_hash = a_len_hash & ~drec_len_mask;
                const b_hash = b_len_hash & ~drec_len_mask;
                if (a_hash != b_hash) return std.math.order(a_hash, b_hash);
                const a_name = a[@min(a.len, 0xc)..];
                const b_name = b[@min(b.len, 0xc)..];
                return std.mem.order(u8, a_name, b_name);
            }
            const a_name = a[@min(a.len, 0xa)..];
            const b_name = b[@min(b.len, 0xa)..];
            return std.mem.order(u8, a_name, b_name);
        },
        rec_type_file_extent => {
            const a_log = if (a.len >= 0x10) le64(a[8..16]) else 0;
            const b_log = if (b.len >= 0x10) le64(b[8..16]) else 0;
            return std.math.order(a_log, b_log);
        },
        else => return std.mem.order(u8, a[8..], b[8..]),
    }
}

const ScanCtx = struct {
    mount: *const Mount,
    lo: []const u8,
    hi: []const u8,
    footer: Footer = undefined,
    aborted: bool = false,
    user: *anyopaque,
    yield: *const fn (raw: *ScanCtx, key: []const u8, val: []const u8) Exception!void,
};

// Catalog keys carry the packed header first; a shorter key is corruption.
fn fsKey(node: Node, index: u32, footer: Footer) Exception![]const u8 {
    const k = try node.key(index, footer);
    if (k.len < 8) return error.DataException;
    return k;
}

// In-order enumeration of fs-tree records with keys in [lo, hi) per fsKeyCompare.
fn fsScanNode(ctx: *ScanCtx, paddr: u64, depth: u32) Exception!void {
    if (depth >= max_tree_depth) return error.DataException;
    const node = try Node.parse(try ctx.mount.image.block(paddr), obj_subtype_fs_tree);
    const footer = if (node.isRoot()) try node.footer() else ctx.footer;
    ctx.footer = footer;
    var i: u32 = 0;
    if (node.isLeaf()) {
        // The first leaf record at or above the lower bound.
        while (i < node.nkeys) : (i += 1) {
            const k = try fsKey(node, i, footer);
            if (fsKeyCompare(k, ctx.lo, ctx.mount.hashed_drec) != .lt) break;
        }
        while (i < node.nkeys) : (i += 1) {
            const k = try fsKey(node, i, footer);
            if (fsKeyCompare(k, ctx.hi, ctx.mount.hashed_drec) != .lt) break;
            const v = try node.value(i, footer);
            try ctx.yield(ctx, k, v);
            if (ctx.aborted) return;
        }
        return;
    }
    // An internal entry holds the first key of its child, so the child that
    // covers the lower bound is the last entry not above it; the first child
    // owns the range when every entry starts above the bound.
    while (i + 1 < node.nkeys) : (i += 1) {
        const k = try fsKey(node, i + 1, footer);
        if (fsKeyCompare(k, ctx.lo, ctx.mount.hashed_drec) == .gt) break;
    }
    while (i < node.nkeys) : (i += 1) {
        const v = try node.value(i, footer);
        if (v.len < 8) return error.DataException;
        const child = try resolveNode(ctx.mount, footer.flags, ctx.mount.volume_omap_root, le64(v[0..8]));
        try fsScanNode(ctx, child, depth + 1);
        if (ctx.aborted) return;
        const k = try fsKey(node, i, footer);
        if (fsKeyCompare(k, ctx.hi, ctx.mount.hashed_drec) != .lt) break;
    }
}

fn fsScan(
    mount: *const Mount,
    lo: []const u8,
    hi: []const u8,
    comptime Ctx: type,
    user: *Ctx,
    comptime yieldFn: fn (ctx: *Ctx, key: []const u8, val: []const u8) Exception!void,
) Exception!void {
    var ctx = ScanCtx{
        .mount = mount,
        .lo = lo,
        .hi = hi,
        .user = user,
        .yield = struct {
            fn call(raw: *ScanCtx, key: []const u8, val: []const u8) Exception!void {
                if (raw.aborted) return;
                const typed: *Ctx = @ptrCast(@alignCast(raw.user));
                try yieldFn(typed, key, val);
                if (@hasField(Ctx, "aborted") and typed.aborted) raw.aborted = true;
            }
        }.call,
    };
    try fsScanNode(&ctx, mount.fs_root, 0);
}

const WalkCtx = struct {
    mount: *const Mount,
    target: Target,
    state: *WalkState,
    depth: u32,
    aborted: bool = false,
};

fn drecName(key: []const u8, hashed: bool) Exception![]const u8 {
    if (key.len < 8) return error.DataException;
    if (hashed) {
        if (key.len < 0xc) return error.DataException;
        const name_len = le32(key[8..12]) & drec_len_mask;
        if (0xc + name_len > key.len) return error.DataException;
        return key[0xc..][0..name_len];
    }
    if (key.len < 0xa) return error.DataException;
    const name_len = le16(key[8..10]);
    if (0xa + name_len > key.len) return error.DataException;
    return key[0xa..][0..name_len];
}

fn makeLoKey(buffer: *[0x10]u8, id: u64, rec_type: u64) []const u8 {
    std.mem.writeInt(u64, buffer[0..8], (rec_type << key_type_shift) | id, .little);
    @memset(buffer[8..], 0);
    return buffer[0..8];
}

// Range end for (id, rec_type): the next type, or the next id at the maximum type.
fn makeHiKey(buffer: *[0x10]u8, id: u64, rec_type: u64) []const u8 {
    if (rec_type == 15) {
        std.mem.writeInt(u64, buffer[0..8], id + 1, .little);
    } else {
        std.mem.writeInt(u64, buffer[0..8], ((rec_type + 1) << key_type_shift) | id, .little);
    }
    @memset(buffer[8..], 0);
    return buffer[0..8];
}

fn walkDir(mount: *const Mount, dir_ino: u64, target: Target, state: *WalkState, depth: u32) Exception!void {
    if (depth > max_dir_depth) return error.DataException;
    var lo: [0x10]u8 = undefined;
    var hi: [0x10]u8 = undefined;
    var ctx = WalkCtx{ .mount = mount, .target = target, .state = state, .depth = depth };
    try fsScan(mount, makeLoKey(&lo, dir_ino, rec_type_dir_rec), makeHiKey(&hi, dir_ino, rec_type_dir_rec), WalkCtx, &ctx, dirYield);
}

fn dirYield(walk_ctx: *WalkCtx, key: []const u8, val: []const u8) Exception!void {
    const name = try drecName(key, walk_ctx.mount.hashed_drec);
    _ = name;
    if (val.len < 8) return error.DataException;
    const file_id = le64(val[0..8]);
    const inode = try lookupInode(walk_ctx.mount, file_id);
    const fmt = inode.mode & mode_fmt_mask;
    if (fmt == mode_dir) {
        try walkDir(walk_ctx.mount, file_id, walk_ctx.target, walk_ctx.state, walk_ctx.depth + 1);
        switch (walk_ctx.target) {
            .resolve => |res| if (res.found.*) {
                walk_ctx.aborted = true;
                return;
            },
            .count => {},
        }
        return;
    }
    if (fmt != mode_reg) return;
    switch (walk_ctx.target) {
        .count => {},
        .resolve => |res| {
            if (walk_ctx.state.ordinal == res.ordinal) {
                res.info.size = inode.size;
                res.info.ordinal = walk_ctx.state.ordinal;
                if (res.output) |out| {
                    if (out.len < inode.size) return error.CapacityException;
                    try readFile(walk_ctx.mount, inode.private_id, inode.size, out);
                }
                res.found.* = true;
                walk_ctx.aborted = true;
                return;
            }
        },
    }
    walk_ctx.state.ordinal += 1;
}

fn lookupInode(mount: *const Mount, ino: u64) Exception!Inode {
    var result: ?Inode = null;
    var lo: [0x10]u8 = undefined;
    var hi: [0x10]u8 = undefined;
    var ctx = InodeCtx{ .result = &result };
    try fsScan(mount, makeLoKey(&lo, ino, rec_type_inode), makeHiKey(&hi, ino, rec_type_inode), InodeCtx, &ctx, inodeYield);
    return result orelse error.DataException;
}

const InodeCtx = struct { result: *?Inode, aborted: bool = false };

fn inodeYield(ctx: *InodeCtx, key: []const u8, val: []const u8) Exception!void {
    _ = key;
    ctx.result.* = try inodeFromValue(val);
    ctx.aborted = true;
}

fn readFile(mount: *const Mount, private_id: u64, size: u64, output: []u8) Exception!void {
    var lo: [0x10]u8 = undefined;
    var hi: [0x10]u8 = undefined;
    var ctx = FileCtx{ .mount = mount, .size = size, .output = output, .written = 0 };
    try fsScan(mount, makeLoKey(&lo, private_id, rec_type_file_extent), makeHiKey(&hi, private_id, rec_type_file_extent), FileCtx, &ctx, extentYield);
    if (ctx.written < size) {
        @memset(output[@intCast(ctx.written)..@intCast(size)], 0);
    }
}

const FileCtx = struct {
    mount: *const Mount,
    size: u64,
    output: []u8,
    written: u64,
};

fn extentYield(ctx: *FileCtx, key: []const u8, val: []const u8) Exception!void {
    if (key.len < 0x10 or val.len < 0x18) return error.DataException;
    const logical = le64(key[8..16]);
    const length = le64(val[0..8]) & 0x00ffffffffffffff;
    const phys = le64(val[8..16]);
    if (logical > ctx.size) return;
    const take = @min(length, ctx.size - logical);
    const end = std.math.add(u64, logical, take) catch return error.DataException;
    if (end > ctx.output.len) return error.CapacityException;
    if (logical > ctx.written) {
        @memset(ctx.output[@intCast(ctx.written)..@intCast(logical)], 0);
    }
    const block_size = ctx.mount.image.block_size;
    const phys_off = std.math.mul(u64, phys, block_size) catch return error.DataException;
    const data = try bounds.slice(ctx.mount.image.bytes, phys_off, take);
    @memcpy(ctx.output[@intCast(logical)..@intCast(end)], data);
    ctx.written = end;
}

// Synthetic single-volume image: a newer checkpoint, a checkpoint map, a
// two-level fs tree whose internal root must be searched for the bound, and
// an internal object map root over one leaf.
const fixture_block_count = 15;
const fixture_block_size = 4096;

const hello_size: u64 = 4096 + 904;
const inner_size: u64 = 100;

fn fixtureImage(alloc: std.mem.Allocator) ![]u8 {
    const image = try alloc.alloc(u8, fixture_block_count * fixture_block_size);
    @memset(image, 0);

    const nx = image[0..fixture_block_size];
    const checkpoint = image[fixture_block_size .. 2 * fixture_block_size];
    const cpmap = image[2 * fixture_block_size .. 3 * fixture_block_size];
    const omap = image[3 * fixture_block_size .. 4 * fixture_block_size];
    const omap_tree = image[4 * fixture_block_size .. 5 * fixture_block_size];
    const vol = image[5 * fixture_block_size .. 6 * fixture_block_size];
    const fs_root = image[6 * fixture_block_size .. 7 * fixture_block_size];
    const vol_omap = image[7 * fixture_block_size .. 8 * fixture_block_size];
    const vol_omap_tree = image[8 * fixture_block_size .. 9 * fixture_block_size];
    const hello0 = image[9 * fixture_block_size .. 10 * fixture_block_size];
    const hello1 = image[10 * fixture_block_size .. 11 * fixture_block_size];
    const inner = image[11 * fixture_block_size .. 12 * fixture_block_size];
    const fs_leaf_a = image[12 * fixture_block_size .. 13 * fixture_block_size];
    const fs_leaf_b = image[13 * fixture_block_size .. 14 * fixture_block_size];
    const vol_omap_leaf = image[14 * fixture_block_size .. 15 * fixture_block_size];

    for (hello0, 0..) |*b, i| b.* = @truncate(i *% 31 + 7);
    for (hello1, 0..) |*b, i| b.* = @truncate(i *% 13 + 5);
    for (inner, 0..) |*b, i| b.* = @truncate(255 -| @as(u8, @intCast(i % 256)));

    // Block 0: container superblock, older xid.
    writeObj(nx, 1, 5, 0x1, 0);
    std.mem.writeInt(u32, nx[0x20..0x24], nx_magic, .little);
    std.mem.writeInt(u32, nx[0x24..0x28], fixture_block_size, .little);
    std.mem.writeInt(u64, nx[0x28..0x30], fixture_block_count, .little);
    std.mem.writeInt(u64, nx[0x60..0x68], 6, .little);
    std.mem.writeInt(u32, nx[0x68..0x6c], 4, .little);
    std.mem.writeInt(u64, nx[0x70..0x78], 1, .little);
    std.mem.writeInt(u64, nx[0xa0..0xa8], 3, .little); // Container omap block number.
    std.mem.writeInt(u32, nx[0xb4..0xb8], 1, .little); // Maximum file system count.
    std.mem.writeInt(u64, nx[0xb8..0xc0], 200, .little); // First file system oid.
    seal(nx);

    // Block 1: same superblock at a newer xid (the mountable checkpoint).
    @memcpy(checkpoint[8..], nx[8..]);
    std.mem.writeInt(u64, checkpoint[16..24], 6, .little);
    std.mem.writeInt(u32, checkpoint[24..28], obj_flag_ephemeral | 0x1, .little);
    seal(checkpoint);

    // Block 2: checkpoint map. The object maps are physical objects, so no
    // entry is needed for them.
    writeObj(cpmap, 0, 6, obj_flag_physical | 0xc, 0);
    std.mem.writeInt(u32, cpmap[0x20..0x24], 0, .little);
    std.mem.writeInt(u32, cpmap[0x24..0x28], 0, .little);
    seal(cpmap);

    // Block 3: container object map; its tree root lives at block 4.
    writeObj(omap, 3, 6, obj_flag_physical | obj_type_omap, 0);
    std.mem.writeInt(u32, omap[0x28..0x2c], obj_flag_physical | obj_type_btree, .little);
    std.mem.writeInt(u64, omap[0x30..0x38], 4, .little);
    seal(omap);

    // Block 4: container omap b-tree root (single leaf) mapping volume 200 -> block 5.
    buildOmapTree(omap_tree, 4, &.{.{ .oid = 200, .paddr = 5 }});

    // Block 5: volume superblock (virtual, oid 200).
    writeObj(vol, 200, 6, obj_type_fs, 0);
    std.mem.writeInt(u32, vol[0x20..0x24], fs_magic, .little);
    std.mem.writeInt(u64, vol[0x38..0x40], 0, .little); // Case-sensitive: plain drec keys.
    std.mem.writeInt(u32, vol[0x74..0x78], obj_type_btree, .little); // Root tree type: virtual b-tree.
    std.mem.writeInt(u64, vol[0x80..0x88], 7, .little); // Volume omap block number.
    std.mem.writeInt(u64, vol[0x88..0x90], 300, .little); // Root tree oid.
    @memcpy(vol[0x2c0..][0..4], "tank");
    seal(vol);

    // Block 7: volume object map; its tree root lives at block 8.
    writeObj(vol_omap, 7, 6, obj_flag_physical | obj_type_omap, 0);
    std.mem.writeInt(u32, vol_omap[0x28..0x2c], obj_flag_physical | obj_type_btree, .little);
    std.mem.writeInt(u64, vol_omap[0x30..0x38], 8, .little);
    seal(vol_omap);

    // Block 8: volume omap b-tree root; an internal node over the block 14
    // leaf, with the leaf's first key as its only branch key.
    buildOmapRoot(vol_omap_tree, 8, 14, .{ .oid = 300, .paddr = 6 });

    // Block 14: volume omap leaf mapping the fs boot records.
    buildOmapLeaf(vol_omap_leaf, 14, &.{
        .{ .oid = 300, .paddr = 6 },
        .{ .oid = 301, .paddr = 12 },
        .{ .oid = 302, .paddr = 13 },
    });

    // Blocks 6, 12, and 13: the fs tree, an internal root over two leaves.
    buildFsTree(fs_root, fs_leaf_a, fs_leaf_b);

    return image;
}

fn writeObj(block: []u8, oid: u64, xid: u64, otype: u32, osubtype: u32) void {
    std.mem.writeInt(u64, block[8..16], oid, .little);
    std.mem.writeInt(u64, block[16..24], xid, .little);
    std.mem.writeInt(u32, block[24..28], otype, .little);
    std.mem.writeInt(u32, block[28..32], osubtype, .little);
}

fn seal(block: []u8) void {
    std.mem.writeInt(u64, block[0..8], fletcher64(block[8..]), .little);
}

fn writeBtreeFooter(node: []u8, flags: u32, key_size: u32, val_size: u32, key_count: u64, node_count: u64) void {
    const base = node.len - btree_info_size;
    std.mem.writeInt(u32, node[base..][0..4], flags, .little);
    std.mem.writeInt(u32, node[base + 4 ..][0..4], fixture_block_size, .little);
    std.mem.writeInt(u32, node[base + 8 ..][0..4], key_size, .little);
    std.mem.writeInt(u32, node[base + 12 ..][0..4], val_size, .little);
    std.mem.writeInt(u32, node[base + 16 ..][0..4], key_size, .little);
    std.mem.writeInt(u32, node[base + 20 ..][0..4], val_size, .little);
    std.mem.writeInt(u64, node[base + 24 ..][0..8], key_count, .little);
    std.mem.writeInt(u64, node[base + 32 ..][0..8], node_count, .little);
}

const FsRec = struct {
    id: u64,
    rec_type: u64,
    name: []const u8 = "",
    val_kind: enum { inode_dir, inode_file, drec, extent },
    file_id: u64 = 0,
    size: u64 = 0,
    phys: u64 = 0,
    logical: u64 = 0,
};

// The directory scan bound (2, 9) falls between the first keys of the two
// leaves, [2, 3] and [17, 3], so the descent must pick the last entry at or
// below it instead of the first entry above it.
const fs_records_a = [_]FsRec{
    .{ .id = 2, .rec_type = rec_type_inode, .val_kind = .inode_dir },
    .{ .id = 2, .rec_type = rec_type_dir_rec, .name = "dir", .val_kind = .drec, .file_id = 17 },
    .{ .id = 2, .rec_type = rec_type_dir_rec, .name = "hello.txt", .val_kind = .drec, .file_id = 16 },
    .{ .id = 16, .rec_type = rec_type_inode, .val_kind = .inode_file, .size = hello_size },
    .{ .id = 16, .rec_type = rec_type_file_extent, .val_kind = .extent, .size = 4096, .phys = 9 },
    .{ .id = 16, .rec_type = rec_type_file_extent, .val_kind = .extent, .size = 904, .phys = 10, .logical = 4096 },
};

const fs_records_b = [_]FsRec{
    .{ .id = 17, .rec_type = rec_type_inode, .val_kind = .inode_dir },
    .{ .id = 17, .rec_type = rec_type_dir_rec, .name = "inner.bin", .val_kind = .drec, .file_id = 18 },
    .{ .id = 18, .rec_type = rec_type_inode, .val_kind = .inode_file, .size = inner_size },
    .{ .id = 18, .rec_type = rec_type_file_extent, .val_kind = .extent, .size = inner_size, .phys = 11 },
};

const KVPair = struct { key: []const u8, val: []const u8 };

// Lays out a variable-size b-tree node: table of contents, keys forward from
// the key area, and values backwards from the footer or the block end.
fn writeVarNode(
    node: []u8,
    oid: u64,
    subtype: u32,
    physical: bool,
    node_flags: u16,
    level: u16,
    tree_flags: u32,
    pairs: []const KVPair,
    root: bool,
    key_count: u64,
    node_count: u64,
) void {
    writeObj(node, oid, 6, (if (physical) obj_flag_physical else 0) | (if (root) obj_type_btree else obj_type_btree_node), subtype);
    std.mem.writeInt(u16, node[0x20..0x22], node_flags, .little);
    std.mem.writeInt(u16, node[0x22..0x24], level, .little);
    std.mem.writeInt(u32, node[0x24..0x28], @intCast(pairs.len), .little);
    const table_len = pairs.len * 8;
    std.mem.writeInt(u16, node[0x28..0x2a], 0, .little);
    std.mem.writeInt(u16, node[0x2a..0x2c], @intCast(table_len), .little);
    const key_area = btree_node_header_size + table_len;
    const end = if (root) node.len - btree_info_size else node.len;
    var key_pos = key_area;
    var val_pos = end;
    var toc: usize = btree_node_header_size;
    for (pairs) |pair| {
        val_pos -= pair.val.len;
        @memcpy(node[key_pos..][0..pair.key.len], pair.key);
        @memcpy(node[val_pos..][0..pair.val.len], pair.val);
        std.mem.writeInt(u16, node[toc..][0..2], @intCast(key_pos - key_area), .little);
        std.mem.writeInt(u16, node[toc + 2 ..][0..2], @intCast(pair.key.len), .little);
        std.mem.writeInt(u16, node[toc + 4 ..][0..2], @intCast(end - val_pos), .little);
        std.mem.writeInt(u16, node[toc + 6 ..][0..2], @intCast(pair.val.len), .little);
        key_pos += pair.key.len;
        toc += 8;
    }
    if (root) writeBtreeFooter(node, tree_flags, 0, 0, key_count, node_count);
    seal(node);
}

const OmapEntry = struct { oid: u64, paddr: u64 };

fn fillOmapPairs(entries: []const OmapEntry, keys: [][16]u8, vals: [][16]u8, pairs: []KVPair) void {
    for (entries, 0..) |entry, j| {
        std.mem.writeInt(u64, keys[j][0..8], entry.oid, .little);
        std.mem.writeInt(u64, keys[j][8..16], 6, .little);
        std.mem.writeInt(u32, vals[j][0..4], 0, .little);
        std.mem.writeInt(u32, vals[j][4..8], fixture_block_size, .little);
        std.mem.writeInt(u64, vals[j][8..16], entry.paddr, .little);
        pairs[j] = .{ .key = &keys[j], .val = &vals[j] };
    }
}

fn buildOmapTree(node: []u8, oid: u64, entries: []const OmapEntry) void {
    std.debug.assert(entries.len <= 4);
    var keys: [4][16]u8 = undefined;
    var vals: [4][16]u8 = undefined;
    var pairs: [4]KVPair = undefined;
    fillOmapPairs(entries, &keys, &vals, &pairs);
    writeFixedNode(node, oid, obj_subtype_omap, true, btn_flag_root | btn_flag_leaf | btn_flag_fixed_kv, 0, btinfo_flag_physical, 16, 16, pairs[0..entries.len], true, entries.len, 1);
}

// Lays out a fixed-size b-tree node: 4-byte table-of-contents entries,
// sequential keys, and values backwards from the footer or the block end.
fn writeFixedNode(
    node: []u8,
    oid: u64,
    subtype: u32,
    physical: bool,
    node_flags: u16,
    level: u16,
    tree_flags: u32,
    key_size: u16,
    val_size: u16,
    pairs: []const KVPair,
    root: bool,
    key_count: u64,
    node_count: u64,
) void {
    writeObj(node, oid, 6, (if (physical) obj_flag_physical else 0) | (if (root) obj_type_btree else obj_type_btree_node), subtype);
    std.mem.writeInt(u16, node[0x20..0x22], node_flags, .little);
    std.mem.writeInt(u16, node[0x22..0x24], level, .little);
    std.mem.writeInt(u32, node[0x24..0x28], @intCast(pairs.len), .little);
    const table_len = pairs.len * 4;
    std.mem.writeInt(u16, node[0x28..0x2a], 0, .little);
    std.mem.writeInt(u16, node[0x2a..0x2c], @intCast(table_len), .little);
    const key_area = btree_node_header_size + table_len;
    const end = if (root) node.len - btree_info_size else node.len;
    var key_pos = key_area;
    var val_pos = end;
    var toc: usize = btree_node_header_size;
    for (pairs) |pair| {
        std.debug.assert(pair.key.len == key_size);
        val_pos -= pair.val.len;
        @memcpy(node[key_pos..][0..pair.key.len], pair.key);
        @memcpy(node[val_pos..][0..pair.val.len], pair.val);
        std.mem.writeInt(u16, node[toc..][0..2], @intCast(key_pos - key_area), .little);
        std.mem.writeInt(u16, node[toc + 2 ..][0..2], @intCast(end - val_pos), .little);
        key_pos += pair.key.len;
        toc += 4;
    }
    if (root) writeBtreeFooter(node, tree_flags, key_size, val_size, key_count, node_count);
    seal(node);
}

// The volume omap tree: an internal fixed-size root over one fixed-size leaf.
// The branch value is the child block number.
fn buildOmapRoot(node: []u8, oid: u64, child_paddr: u64, first: OmapEntry) void {
    var key: [16]u8 = undefined;
    var val: [8]u8 = undefined;
    std.mem.writeInt(u64, key[0..8], first.oid, .little);
    std.mem.writeInt(u64, key[8..16], 6, .little);
    std.mem.writeInt(u64, val[0..8], child_paddr, .little);
    const pairs = [1]KVPair{.{ .key = &key, .val = &val }};
    writeFixedNode(node, oid, obj_subtype_omap, true, btn_flag_root | btn_flag_fixed_kv, 1, btinfo_flag_physical, 16, 16, &pairs, true, 3, 2);
}

fn buildOmapLeaf(node: []u8, oid: u64, entries: []const OmapEntry) void {
    std.debug.assert(entries.len <= 4);
    var keys: [4][16]u8 = undefined;
    var vals: [4][16]u8 = undefined;
    var pairs: [4]KVPair = undefined;
    fillOmapPairs(entries, &keys, &vals, &pairs);
    writeFixedNode(node, oid, obj_subtype_omap, true, btn_flag_leaf | btn_flag_fixed_kv, 0, 0, 16, 16, pairs[0..entries.len], false, 3, 2);
}

fn fillFsPairs(records: []const FsRec, key_bufs: [][64]u8, val_bufs: [][160]u8, pairs: []KVPair) void {
    for (records, 0..) |rec, j| {
        const key_len = writeFsKey(&key_bufs[j], rec);
        const val_len = writeFsVal(&val_bufs[j], rec);
        pairs[j] = .{ .key = key_bufs[j][0..key_len], .val = val_bufs[j][0..val_len] };
    }
}

fn writeFsKey(buf: *[64]u8, rec: FsRec) u32 {
    std.mem.writeInt(u64, buf[0..8], (rec.rec_type << key_type_shift) | rec.id, .little);
    return switch (rec.rec_type) {
        rec_type_inode => 8,
        rec_type_dir_rec => blk: {
            std.mem.writeInt(u16, buf[8..10], @intCast(rec.name.len), .little);
            @memcpy(buf[10..][0..rec.name.len], rec.name);
            break :blk @intCast(10 + rec.name.len);
        },
        rec_type_file_extent => blk: {
            std.mem.writeInt(u64, buf[8..16], rec.logical, .little);
            break :blk 16;
        },
        else => unreachable,
    };
}

fn writeFsVal(buf: *[160]u8, rec: FsRec) u32 {
    return switch (rec.val_kind) {
        .inode_dir => inodeVal(buf[0..], rec.id, mode_dir | 0o755, 0),
        .inode_file => inodeValDstream(buf[0..], rec.id, mode_reg | 0o644, rec.size),
        .drec => blk: {
            std.mem.writeInt(u64, buf[0..8], rec.file_id, .little);
            std.mem.writeInt(u64, buf[8..16], 0, .little);
            std.mem.writeInt(u16, buf[16..18], 0, .little);
            break :blk 18;
        },
        .extent => blk: {
            std.mem.writeInt(u64, buf[0..8], rec.size, .little);
            std.mem.writeInt(u64, buf[8..16], rec.phys, .little);
            std.mem.writeInt(u64, buf[16..24], 0, .little);
            break :blk 24;
        },
    };
}

fn buildFsTree(root: []u8, leaf_a: []u8, leaf_b: []u8) void {
    var keys_a: [fs_records_a.len][64]u8 = undefined;
    var vals_a: [fs_records_a.len][160]u8 = undefined;
    var pairs_a: [fs_records_a.len]KVPair = undefined;
    fillFsPairs(&fs_records_a, &keys_a, &vals_a, &pairs_a);
    writeVarNode(leaf_a, 301, obj_subtype_fs_tree, false, btn_flag_leaf, 0, 0, &pairs_a, false, 0, 0);

    var keys_b: [fs_records_b.len][64]u8 = undefined;
    var vals_b: [fs_records_b.len][160]u8 = undefined;
    var pairs_b: [fs_records_b.len]KVPair = undefined;
    fillFsPairs(&fs_records_b, &keys_b, &vals_b, &pairs_b);
    writeVarNode(leaf_b, 302, obj_subtype_fs_tree, false, btn_flag_leaf, 0, 0, &pairs_b, false, 0, 0);

    // The root repeats the first key of each leaf; the values are child oids.
    var root_keys: [2][64]u8 = undefined;
    var root_vals: [2][16]u8 = undefined;
    var root_pairs: [2]KVPair = undefined;
    const first_records = [2]FsRec{ fs_records_a[0], fs_records_b[0] };
    const child_oids = [2]u64{ 301, 302 };
    for (first_records, child_oids, 0..) |rec, child_oid, j| {
        const key_len = writeFsKey(&root_keys[j], rec);
        std.mem.writeInt(u64, root_vals[j][0..8], child_oid, .little);
        root_pairs[j] = .{ .key = root_keys[j][0..key_len], .val = root_vals[j][0..8] };
    }
    writeVarNode(root, 300, obj_subtype_fs_tree, false, btn_flag_root, 1, 0, &root_pairs, true, fs_records_a.len + fs_records_b.len, 3);
}

fn inodeVal(out: []u8, private_id: u64, mode: u16, nchildren: u32) u32 {
    return inodeValCommon(out, private_id, mode, nchildren, 0, false);
}

fn inodeValDstream(out: []u8, private_id: u64, mode: u16, size: u64) u32 {
    return inodeValCommon(out, private_id, mode, 1, size, true);
}

fn inodeValCommon(out: []u8, private_id: u64, mode: u16, nchildren: u32, size: u64, with_dstream: bool) u32 {
    @memset(out[0..0x8c], 0);
    std.mem.writeInt(u64, out[0..8], 1, .little); // Parent id: the root directory parent.
    std.mem.writeInt(u64, out[8..16], private_id, .little);
    std.mem.writeInt(u32, out[0x38..0x3c], nchildren, .little);
    std.mem.writeInt(u16, out[0x50..0x52], mode, .little);
    const num_exts: u16 = if (with_dstream) 1 else 0;
    std.mem.writeInt(u16, out[0x5c..0x5e], num_exts, .little);
    std.mem.writeInt(u16, out[0x5e..0x60], if (with_dstream) 0x28 else 0, .little);
    if (with_dstream) {
        out[0x60] = 8; // Dstream extended field type.
        out[0x61] = 0;
        std.mem.writeInt(u16, out[0x62..0x64], 0x28, .little);
        std.mem.writeInt(u64, out[0x64..0x6c], size, .little); // Dstream size.
        std.mem.writeInt(u64, out[0x6c..0x74], size, .little); // Dstream allocated size.
        return 0x8c;
    }
    return 0x60;
}

test "apfs rejects undersized keys and inode values" {
    const alloc = std.testing.allocator;
    const image = try fixtureImage(alloc);
    defer alloc.free(image);

    // The first record key loses its packed header.
    const leaf_a = image[12 * fixture_block_size .. 13 * fixture_block_size];
    std.mem.writeInt(u16, leaf_a[0x3a..0x3c], 4, .little);
    try std.testing.expectError(error.DataException, inspectCount(image, &.{}));

    // The file inode value loses its extended-field header.
    std.mem.writeInt(u16, leaf_a[0x3a..0x3c], 8, .little);
    std.mem.writeInt(u16, leaf_a[0x56..0x58], 0x5c, .little);
    try std.testing.expectError(error.DataException, inspectCount(image, &.{}));
}

test "apfs rejects nodes that contradict their tree" {
    const alloc = std.testing.allocator;
    const image = try fixtureImage(alloc);
    defer alloc.free(image);

    // The fs tree root claims to be a non-root b-tree node.
    const fs_root = image[6 * fixture_block_size .. 7 * fixture_block_size];
    std.mem.writeInt(u32, fs_root[24..28], obj_type_btree_node, .little);
    try std.testing.expectError(error.DataException, inspectCount(image, &.{}));

    // Restore the type and give the fs tree root a foreign subtype.
    std.mem.writeInt(u32, fs_root[24..28], obj_type_btree, .little);
    std.mem.writeInt(u32, fs_root[28..32], obj_subtype_omap, .little);
    try std.testing.expectError(error.DataException, inspectCount(image, &.{}));
}

test "apfs rejects an object map without the physical tree flag" {
    const alloc = std.testing.allocator;
    const image = try fixtureImage(alloc);
    defer alloc.free(image);

    // The volume omap root loses BTREE_PHYSICAL while its branch value stays
    // a block number.
    const vol_omap_tree = image[8 * fixture_block_size .. 9 * fixture_block_size];
    const footer_base = vol_omap_tree.len - btree_info_size;
    const flags = le32(vol_omap_tree[footer_base..][0..4]) & ~btinfo_flag_physical;
    std.mem.writeInt(u32, vol_omap_tree[footer_base..][0..4], flags, .little);
    seal(vol_omap_tree);

    try std.testing.expectError(error.DataException, inspectCount(image, &.{}));
}

test "apfs rejects object map objects that contradict their address" {
    const alloc = std.testing.allocator;
    const image = try fixtureImage(alloc);
    defer alloc.free(image);

    // The container object map loses its physical storage class.
    const omap = image[3 * fixture_block_size .. 4 * fixture_block_size];
    std.mem.writeInt(u32, omap[24..28], obj_type_omap, .little);
    try std.testing.expectError(error.DataException, inspectCount(image, &.{}));
    std.mem.writeInt(u32, omap[24..28], obj_flag_physical | obj_type_omap, .little);

    // The volume object map claims an object identifier other than its block.
    const vol_omap = image[7 * fixture_block_size .. 8 * fixture_block_size];
    std.mem.writeInt(u64, vol_omap[8..16], 8, .little);
    try std.testing.expectError(error.DataException, inspectCount(image, &.{}));
    std.mem.writeInt(u64, vol_omap[8..16], 7, .little);

    // The container object map names a tree that is not physical.
    std.mem.writeInt(u32, omap[0x28..0x2c], obj_type_btree, .little);
    try std.testing.expectError(error.DataException, inspectCount(image, &.{}));
}

test "apfs rejects checkpoint area b-trees" {
    const alloc = std.testing.allocator;
    const image = try fixtureImage(alloc);
    defer alloc.free(image);

    const nx = image[0..fixture_block_size];
    std.mem.writeInt(u32, nx[0x68..0x6c], 0x80000004, .little);
    seal(nx);
    try std.testing.expectError(error.UnsupportedException, inspectCount(image, &.{}));
    std.mem.writeInt(u32, nx[0x68..0x6c], 4, .little);

    std.mem.writeInt(u32, nx[0x6c..0x70], 0x80000000, .little);
    seal(nx);
    try std.testing.expectError(error.UnsupportedException, inspectCount(image, &.{}));
    std.mem.writeInt(u32, nx[0x6c..0x70], 0, .little);

    std.mem.writeInt(u64, nx[0x78..0x80], @as(u64, 1) << 63, .little);
    seal(nx);
    try std.testing.expectError(error.UnsupportedException, inspectCount(image, &.{}));
}

test "apfs rejects an unresolvable file system tree root" {
    const alloc = std.testing.allocator;
    const image = try fixtureImage(alloc);
    defer alloc.free(image);

    // A virtual root tree oid that the volume object map does not know names
    // no block; it must not be read as a physical address.
    const vol = image[5 * fixture_block_size .. 6 * fixture_block_size];
    std.mem.writeInt(u64, vol[0x88..0x90], 6, .little);
    try std.testing.expectError(error.DataException, inspectCount(image, &.{}));

    // An ephemeral root tree resolves through the checkpoint map alone,
    // which is empty, even though the oid is in the object map.
    std.mem.writeInt(u64, vol[0x88..0x90], 300, .little);
    std.mem.writeInt(u32, vol[0x74..0x78], obj_flag_ephemeral | obj_type_btree, .little);
    try std.testing.expectError(error.DataException, inspectCount(image, &.{}));

    // A root tree type without the b-tree bits is not a tree.
    std.mem.writeInt(u32, vol[0x74..0x78], obj_flag_physical, .little);
    try std.testing.expectError(error.DataException, inspectCount(image, &.{}));
}

test "apfs rejects extent block numbers outside the image" {
    const alloc = std.testing.allocator;
    const image = try fixtureImage(alloc);
    defer alloc.free(image);

    // The first hello.txt extent points one block past the end of the image.
    const leaf_a = image[12 * fixture_block_size .. 13 * fixture_block_size];
    const v_off = le16(leaf_a[0x5c..0x5e]);
    const phys = leaf_a[leaf_a.len - v_off + 8 ..][0..8];
    std.mem.writeInt(u64, phys, fixture_block_count, .little);
    var out: [hello_size]u8 = undefined;
    try std.testing.expectError(error.DataException, decodeOrdinal(image, 1, &out, &.{}));

    // The highest possible block number must not wrap the address arithmetic.
    std.mem.writeInt(u64, phys, std.math.maxInt(u64), .little);
    try std.testing.expectError(error.DataException, decodeOrdinal(image, 1, &out, &.{}));
}

test "apfs synthetic image round trip" {
    const alloc = std.testing.allocator;
    const image = try fixtureImage(alloc);
    defer alloc.free(image);

    try std.testing.expectEqual(@as(u64, 2), try inspectCount(image, &.{}));

    const first = try inspectOrdinal(image, 0, &.{});
    try std.testing.expectEqual(@as(u64, inner_size), first.size);
    const second = try inspectOrdinal(image, 1, &.{});
    try std.testing.expectEqual(@as(u64, hello_size), second.size);

    var inner_out: [inner_size]u8 = undefined;
    const inner_read = try decodeOrdinal(image, 0, &inner_out, &.{});
    try std.testing.expectEqual(@as(usize, inner_size), inner_read);
    for (inner_out, 0..) |byte, i| try std.testing.expectEqual(@as(u8, @truncate(255 -| @as(u8, @intCast(i % 256)))), byte);

    var hello_out: [hello_size]u8 = undefined;
    const hello_read = try decodeOrdinal(image, 1, &hello_out, &.{});
    try std.testing.expectEqual(@as(usize, hello_size), hello_read);
    for (hello_out[0..4096], 0..) |byte, i| try std.testing.expectEqual(@as(u8, @truncate(i *% 31 + 7)), byte);
    for (hello_out[4096..], 0..) |byte, i| try std.testing.expectEqual(@as(u8, @truncate(i *% 13 + 5)), byte);

    try std.testing.expectError(error.DataException, inspectOrdinal(image, 2, &.{}));
}

test "apfs rejects non-apfs data" {
    const alloc = std.testing.allocator;
    const image = try alloc.alloc(u8, 4 * fixture_block_size);
    defer alloc.free(image);
    @memset(image, 0);
    try std.testing.expectError(error.DataException, inspectCount(image, &.{}));
}
