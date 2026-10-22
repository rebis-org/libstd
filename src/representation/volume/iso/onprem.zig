const std = @import("std");

const bounds = @import("../../../common/primitive/bounds.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const tree_order = @import("../../../common/primitive/order.zig");

const Exception = exception_prim.Exception;

// ISO 9660 slice: one root directory of regular files.
// Read prefers a Joliet supplementary descriptor.

// Rock Ridge entries are ignored; layout is unchanged.
// Write emits a 1999-layout descriptor with Rock Ridge NM/PX.

pub const scratch_size: usize = 64 * 1024;

const sector_size: usize = 2048;
const max_dir_depth: u32 = 64;
const pvd_sector: u64 = 16;
const descriptor_terminator: u8 = 255;
const descriptor_primary: u8 = 1;
const descriptor_supplementary: u8 = 2;
const volume_descriptor_magic = "CD001";

const flag_directory: u8 = 1 << 1;

const joliet_escape_1 = [3]u8{ '%', '/', '@' };
const joliet_escape_2 = [3]u8{ '%', '/', 'C' };
const joliet_escape_3 = [3]u8{ '%', '/', 'E' };

const max_entries = 256;
const path_table_lba: u32 = 18;
const dir_lba: u32 = 20;

pub const Entry = struct {
    name: []const u8,
    data: []const u8,
};

pub const EntryInfo = struct {
    size: u64,
    ordinal: u64,
};

const Descriptor = struct {
    block_size: u32,
    root_extent: u32,
    root_size: u32,
    joliet: bool,
};

fn bothEndianU32(raw: []const u8) Exception!u32 {
    const le = std.mem.readInt(u32, raw[0..4], .little);
    const be = std.mem.readInt(u32, raw[4..8], .big);
    if (le != be) return error.DataException;
    return le;
}

fn bothEndianU16(raw: []const u8) Exception!u16 {
    const le = std.mem.readInt(u16, raw[0..2], .little);
    const be = std.mem.readInt(u16, raw[2..4], .big);
    if (le != be) return error.DataException;
    return le;
}

fn findDescriptor(archive: []const u8, want: u8) Exception!?Descriptor {
    var sector: u64 = pvd_sector;
    while (true) {
        const base = std.math.mul(u64, sector, sector_size) catch return error.DataException;
        const sec = try bounds.slice(archive, base, sector_size);
        const dtype = sec[0];
        if (!std.mem.eql(u8, sec[1..6], volume_descriptor_magic)) return error.DataException;
        if (dtype == descriptor_terminator) return null;
        if (dtype == want) {
            const block_size = try bothEndianU16(sec[128..132]);
            if (block_size != sector_size) return error.UnsupportedException;
            const escape = sec[88..120];
            const joliet = std.mem.eql(u8, escape[0..3], &joliet_escape_1) or
                std.mem.eql(u8, escape[0..3], &joliet_escape_2) or
                std.mem.eql(u8, escape[0..3], &joliet_escape_3);
            const root = sec[156..190];
            if (root[0] == 0) return error.DataException;
            return .{
                .block_size = block_size,
                .root_extent = try bothEndianU32(root[2..10]),
                .root_size = try bothEndianU32(root[10..18]),
                .joliet = joliet,
            };
        }
        sector += 1;
        if (sector > pvd_sector + 16) return error.DataException;
    }
}

fn chosenDescriptor(archive: []const u8) Exception!Descriptor {
    if (try findDescriptor(archive, descriptor_supplementary)) |svd| {
        if (svd.joliet) return svd;
    }
    return (try findDescriptor(archive, descriptor_primary)) orelse error.DataException;
}

const Record = struct {
    extent: u32,
    size: u32,
    flags: u8,
    skip: usize,
    is_dot: bool,
    is_dotdot: bool,
};

fn parseRecord(dir: []const u8, at: usize) Exception!?Record {
    if (at >= dir.len) return null;
    const len = dir[at];
    if (len == 0) return null;
    if (at + len > dir.len or len < 33 + 1) return error.DataException;
    const raw = dir[at .. at + len];
    const name_len = raw[32];
    if (33 + name_len > len) return error.DataException;
    return .{
        .extent = try bothEndianU32(raw[2..10]),
        .size = try bothEndianU32(raw[10..18]),
        .flags = raw[25],
        .skip = len,
        .is_dot = name_len == 1 and raw[33] == 0,
        .is_dotdot = name_len == 1 and raw[33] == 1,
    };
}

const Target = union(enum) {
    count,
    resolve: struct { ordinal: u64, info: *EntryInfo, output: ?[]u8, found: *bool = undefined },
};

const WalkState = struct { ordinal: u64 = 0 };

fn walkRoot(archive: []const u8, desc: Descriptor, target: Target) Exception!u64 {
    var state = WalkState{};
    var found = false;
    const resolved = switch (target) {
        .count => target,
        .resolve => |res| Target{ .resolve = .{ .ordinal = res.ordinal, .info = res.info, .output = res.output, .found = &found } },
    };
    try walkIsoDir(archive, desc.root_extent, desc.root_size, resolved, &state, 0);
    return switch (target) {
        .count => state.ordinal,
        .resolve => if (found) state.ordinal else error.DataException,
    };
}

fn walkIsoDir(archive: []const u8, extent: u32, size: u32, target: Target, state: *WalkState, depth: u32) Exception!void {
    if (depth > max_dir_depth) return error.DataException;
    const dir = try bounds.slice(archive, std.math.mul(u64, extent, sector_size) catch return error.DataException, size);
    const dot = (try parseRecord(dir, 0)) orelse return error.DataException;
    if (!dot.is_dot) return error.DataException;
    const dotdot = (try parseRecord(dir, dot.skip)) orelse return error.DataException;
    if (!dotdot.is_dotdot) return error.DataException;
    var pos: usize = dot.skip + dotdot.skip;
    const found_ptr = switch (target) {
        .resolve => |res| res.found,
        .count => null,
    };
    while (pos < dir.len) {
        if (found_ptr) |fp| {
            if (fp.*) return;
        }
        // Records never cross sector boundaries: a zero length byte or an
        // over-long record pads the sector, and records resume at the next.
        const remain = sector_size - (pos % sector_size);
        if (dir[pos] == 0 or dir[pos] > remain) {
            pos += remain;
            continue;
        }
        const rec = (try parseRecord(dir, pos)) orelse break;
        pos += rec.skip;
        if (rec.is_dot or rec.is_dotdot) continue;
        // Multi-extent and interleaved records change the data layout; the
        // slice covers contiguous single-extent regular files.
        if (rec.flags & ((1 << 7) | (1 << 2)) != 0) return error.UnsupportedException;
        if (rec.flags & flag_directory != 0) {
            try walkIsoDir(archive, rec.extent, rec.size, target, state, depth + 1);
            continue;
        }
        switch (target) {
            .count => {},
            .resolve => |res| {
                if (state.ordinal == res.ordinal) {
                    res.info.size = rec.size;
                    res.info.ordinal = state.ordinal;
                    if (res.output) |out| {
                        if (out.len < rec.size) return error.CapacityException;
                        const data = try bounds.slice(archive, std.math.mul(u64, rec.extent, sector_size) catch return error.DataException, rec.size);
                        @memcpy(out[0..rec.size], data);
                    }
                    res.found.* = true;
                    return;
                }
            },
        }
        state.ordinal += 1;
    }
}

fn walkChosen(archive: []const u8, target: Target) Exception!u64 {
    return walkRoot(archive, try chosenDescriptor(archive), target);
}

pub fn inspectCount(archive: []const u8, scratch: []u8) Exception!u64 {
    _ = scratch;
    return walkChosen(archive, .count);
}

pub fn inspectOrdinal(archive: []const u8, ordinal: u64, scratch: []u8) Exception!EntryInfo {
    _ = scratch;
    var info: EntryInfo = undefined;
    _ = try walkChosen(archive, .{ .resolve = .{ .ordinal = ordinal, .info = &info, .output = null } });
    return info;
}

pub fn decodeOrdinal(archive: []const u8, ordinal: u64, output: []u8, scratch: []u8) Exception!usize {
    _ = scratch;
    var info: EntryInfo = undefined;
    _ = try walkChosen(archive, .{ .resolve = .{ .ordinal = ordinal, .info = &info, .output = output } });
    return @intCast(info.size);
}

const IsoNode = struct {
    kind: enum { dir, file },
    name: []const u8,
    parent: u32,
    data: []const u8 = &.{},
    first_child: u32 = 0,
    child_count: u32 = 0,
};

const max_tree_nodes = 128;

const IsoPlan = struct {
    nodes: []IsoNode,
    dir_order: []u32,
    file_order: []u32,
    kids: []u32,
    dir_content: []u32,
    dir_lba_of: []u32,
    file_lba_of: []u32,
    path_table_size: u32,
    total: u64,
};

fn isoFindOrCreateDir(nodes: *std.ArrayList(IsoNode), alloc: std.mem.Allocator, parent: u32, name: []const u8) Exception!u32 {
    for (nodes.items, 0..) |node, i| {
        if (node.kind == .dir and node.parent == parent and std.mem.eql(u8, node.name, name)) return @intCast(i);
    }
    const idx: u32 = @intCast(nodes.items.len);
    nodes.append(alloc, .{ .kind = .dir, .name = name, .parent = parent }) catch return error.ResourceException;
    nodes.items[parent].child_count += 1;
    return idx;
}

fn buildIsoPlan(entries: []const Entry, alloc: std.mem.Allocator) Exception!IsoPlan {
    if (entries.len == 0 or entries.len > max_entries) return error.UnsupportedException;
    var nodes: std.ArrayList(IsoNode) = .empty;
    nodes.append(alloc, .{ .kind = .dir, .name = "", .parent = 0 }) catch return error.ResourceException;
    for (entries) |entry| {
        try validateName(entry.name);
        if (entry.data.len > std.math.maxInt(u32)) return error.UnsupportedException;
        var parent: u32 = 0;
        var depth: u32 = 1;
        var it = std.mem.splitScalar(u8, entry.name, '/');
        var comp = it.next().?;
        while (it.next()) |next| {
            parent = try isoFindOrCreateDir(&nodes, alloc, parent, comp);
            comp = next;
            depth += 1;
        }
        // The deepest directory sits at walk depth components - 1.
        if (depth > max_dir_depth + 1) return error.UnsupportedException;
        nodes.append(alloc, .{ .kind = .file, .name = comp, .parent = parent, .data = entry.data }) catch return error.ResourceException;
        nodes.items[parent].child_count += 1;
    }
    if (nodes.items.len > max_tree_nodes) return error.UnsupportedException;

    const counts = alloc.alloc(u32, nodes.items.len) catch return error.ResourceException;
    @memset(counts, 0);
    for (nodes.items, 0..) |node, i| {
        if (i != 0) counts[node.parent] += 1;
    }
    const starts = alloc.alloc(u32, nodes.items.len) catch return error.ResourceException;
    var acc: u32 = 0;
    for (counts, 0..) |c, i| {
        starts[i] = acc;
        acc += c;
    }
    const kids = alloc.alloc(u32, acc) catch return error.ResourceException;
    const fill = alloc.alloc(u32, nodes.items.len) catch return error.ResourceException;
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
            fn less(ns: *std.ArrayList(IsoNode), a: u32, b: u32) bool {
                return std.mem.order(u8, ns.items[a].name, ns.items[b].name) == .lt;
            }
        }.less);
    }

    var dir_order: std.ArrayList(u32) = .empty;
    var file_order: std.ArrayList(u32) = .empty;
    try tree_order.orderTree(IsoNode, &nodes, kids, 0, &dir_order, &file_order, alloc);

    const dir_content = alloc.alloc(u32, dir_order.items.len) catch return error.ResourceException;
    for (dir_order.items, 0..) |ni, di| {
        const node = &nodes.items[ni];
        var size: u32 = 33 + 1; // dot record
        size += if (di == 0) 33 + 1 + rr_size_dot_sua else 33 + 1; // dotdot record
        for (kids[node.first_child .. node.first_child + node.child_count]) |ci| {
            const child = &nodes.items[ci];
            // Planning and encoding must reject the same record sets.
            const rec_len = dirRecordSize(child.name.len, true, child.kind == .file);
            if (rec_len > 255) return error.UnsupportedException;
            size += @intCast(rec_len);
        }
        if (size > sector_size) return error.UnsupportedException;
        // Directory data lengths are multiples of the block size.
        dir_content[di] = @intCast(std.mem.alignForward(usize, size, sector_size));
    }

    const dir_lba_of = alloc.alloc(u32, dir_order.items.len) catch return error.ResourceException;
    for (dir_order.items, 0..) |_, di| {
        dir_lba_of[di] = dir_lba + @as(u32, @intCast(di));
    }
    const file_lba_of = alloc.alloc(u32, file_order.items.len) catch return error.ResourceException;
    var lba: u32 = dir_lba + @as(u32, @intCast(dir_order.items.len));
    for (file_order.items, 0..) |ni, fi| {
        file_lba_of[fi] = lba;
        lba += @intCast((nodes.items[ni].data.len + sector_size - 1) / sector_size);
    }

    var path_table_size: u32 = 0;
    for (dir_order.items) |ni| {
        const len: u32 = if (nodes.items[ni].name.len == 0) 1 else @intCast(nodes.items[ni].name.len);
        path_table_size += 8 + len + (len & 1);
    }
    // The writer emits one 2048-byte sector per byte-order table.
    if (path_table_size > sector_size) return error.UnsupportedException;

    return .{
        .nodes = nodes.items,
        .dir_order = dir_order.items,
        .file_order = file_order.items,
        .kids = kids,
        .dir_content = dir_content,
        .dir_lba_of = dir_lba_of,
        .file_lba_of = file_lba_of,
        .path_table_size = path_table_size,
        // libarchive's bid reads the reserved area plus eight descriptor sectors.
        // Shorter images never reach the parser; pad to 32 sectors.
        .total = @as(u64, @max(lba, 32)) * sector_size,
    };
}

pub fn archiveSize(entries: []const Entry) Exception!u64 {
    var stack: [32 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack);
    const plan = try buildIsoPlan(entries, fba.allocator());
    return plan.total;
}

fn validateName(name: []const u8) Exception!void {
    if (name.len == 0 or name.len > 250) return error.CallException;
    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |part| {
        if (part.len == 0) return error.CallException;
        if (std.mem.findScalar(u8, part, ';') != null) return error.CallException;
    }
}

// File identifiers carry the ";1" version suffix; directory identifiers
// never do. Even-length names take a padding byte.
fn nameArea(name_len: usize, with_version: bool) usize {
    const stored = if (with_version) name_len + 2 else name_len;
    return stored + (1 - (stored & 1));
}

fn rrSizeNm(name_len: usize) usize {
    const total = 4 + 1 + name_len;
    return total + (total & 1);
}

const rr_size_px: usize = 44;

fn dirRecordSize(name_len: usize, has_nm: bool, with_version: bool) usize {
    var size = 33 + nameArea(name_len, with_version) + rr_size_px;
    if (has_nm) size += rrSizeNm(name_len);
    return size;
}

fn writeU16Both(out: []u8, value: u16) void {
    std.mem.writeInt(u16, out[0..2], value, .little);
    std.mem.writeInt(u16, out[2..4], value, .big);
}

fn writeU32Both(out: []u8, value: u32) void {
    std.mem.writeInt(u32, out[0..4], value, .little);
    std.mem.writeInt(u32, out[4..8], value, .big);
}

fn writeTimestamp(out: []u8) void {
    @memcpy(out[0..16], "2026010100000000");
    out[16] = 0;
}

fn writeFixedText(out: []u8) void {
    @memset(out, ' ');
}

fn writePvd(out: []u8, plan: *const IsoPlan) void {
    @memset(out, 0);
    out[0] = descriptor_primary;
    @memcpy(out[1..6], volume_descriptor_magic);
    out[6] = 1;
    writeFixedText(out[8..40]);
    writeFixedText(out[40..72]);
    @memcpy(out[40..48], "LIBSTD10");
    const total_sectors: u32 = @intCast(plan.total / sector_size);
    writeU32Both(out[80..88], total_sectors);
    writeU16Both(out[120..124], 1);
    writeU16Both(out[124..128], 1);
    writeU16Both(out[128..132], @intCast(sector_size));
    writeU32Both(out[132..140], plan.path_table_size);
    std.mem.writeInt(u32, out[140..144], path_table_lba, .little);
    std.mem.writeInt(u32, out[144..148], 0, .little);
    std.mem.writeInt(u32, out[148..152], path_table_lba + 1, .big);
    std.mem.writeInt(u32, out[152..156], 0, .big);
    writeBaseRecord(out[156..190], dir_lba, plan.dir_content[0], true, 1, 0);
    for ([_][2]usize{ .{ 190, 318 }, .{ 318, 446 }, .{ 446, 574 }, .{ 574, 702 }, .{ 702, 739 }, .{ 739, 776 }, .{ 776, 813 } }) |r| {
        writeFixedText(out[r[0]..r[1]]);
    }
    for ([_][2]usize{ .{ 813, 830 }, .{ 830, 847 }, .{ 847, 864 }, .{ 864, 881 } }) |r| {
        writeTimestamp(out[r[0]..r[1]]);
    }
    out[881] = 1;
}

fn writeBaseRecord(out: []u8, extent: u32, size: u32, directory: bool, name_len: u8, name_byte: u8) void {
    @memset(out[0..34], 0);
    out[0] = 34;
    out[1] = 0;
    writeU32Both(out[2..10], extent);
    writeU32Both(out[10..18], size);
    const rec_date = [_]u8{ 126, 1, 1, 0, 0, 0, 0 };
    @memcpy(out[18..25], &rec_date);
    out[25] = if (directory) flag_directory else 0;
    out[26] = 0;
    out[27] = 0;
    writeU16Both(out[28..32], 1);
    out[32] = name_len;
    out[33] = name_byte;
}

// One path table entry per directory, parent before child in DFS order.
fn writePathTable(sector: []u8, plan: *const IsoPlan, big_endian: bool) void {
    @memset(sector, 0);
    var pos: usize = 0;
    for (plan.dir_order, 0..) |ni, di| {
        const node = &plan.nodes[ni];
        const parent_rank: u32 = if (di == 0) 1 else parentRank(plan, node.parent);
        const name_len: u8 = if (node.name.len == 0) 1 else @intCast(node.name.len);
        sector[pos] = name_len;
        sector[pos + 1] = 0;
        if (big_endian) {
            std.mem.writeInt(u32, sector[pos + 2 ..][0..4], plan.dir_lba_of[di], .big);
            std.mem.writeInt(u16, sector[pos + 6 ..][0..2], @intCast(parent_rank), .big);
        } else {
            std.mem.writeInt(u32, sector[pos + 2 ..][0..4], plan.dir_lba_of[di], .little);
            std.mem.writeInt(u16, sector[pos + 6 ..][0..2], @intCast(parent_rank), .little);
        }
        if (node.name.len == 0) {
            sector[pos + 8] = 0;
        } else {
            @memcpy(sector[pos + 8 ..][0..node.name.len], node.name);
        }
        pos += 8 + @as(usize, name_len) + (name_len & 1);
    }
}

fn rankOf(order: []const u32, node: u32) usize {
    for (order, 0..) |ni, i| if (ni == node) return i;
    unreachable;
}

fn parentRank(plan: *const IsoPlan, parent_node: u32) u32 {
    return @intCast(rankOf(plan.dir_order, parent_node) + 1);
}

const rr_size_sp: usize = 7;
// The ER payload mirrors the reference writer, keeping Rock Ridge readers satisfied.
const rr_er_payload = "IEEE_P1282" ++
    "THE IEEE P1282 PROTOCOL PROVIDES SUPPORT FOR POSIX FILE SYSTEM SEMANTICS." ++
    "PLEASE CONTACT THE IEEE STANDARDS DEPARTMENT, PISCATAWAY, NJ, USA FOR THE P1282 SPECIFICATION.";
const rr_size_er: usize = 4 + 4 + rr_er_payload.len;
const rr_size_dot_sua: usize = rr_size_sp + rr_size_er;

fn rrHead(out: []u8, a: u8, b: u8, len: usize) void {
    out[0] = a;
    out[1] = b;
    out[2] = @intCast(len);
    out[3] = 1;
}

fn writeRrSp(out: []u8) usize {
    rrHead(out, 'S', 'P', rr_size_sp);
    out[4] = 0xbe;
    out[5] = 0xef;
    out[6] = 0;
    return rr_size_sp;
}

fn writeRrEr(out: []u8) usize {
    rrHead(out, 'E', 'R', rr_size_er);
    out[4] = 10;
    out[5] = 73;
    out[6] = @intCast(rr_er_payload.len - 73 - 10);
    out[7] = 0;
    @memcpy(out[8..][0..rr_er_payload.len], rr_er_payload);
    return rr_size_er;
}

fn writeRrPx(out: []u8, mode: u32, serial: u32) usize {
    rrHead(out, 'P', 'X', rr_size_px);
    writeU32Both(out[4..12], mode);
    writeU32Both(out[12..20], 1);
    writeU32Both(out[20..28], 0);
    writeU32Both(out[28..36], 0);
    writeU32Both(out[36..44], serial);
    return rr_size_px;
}

fn writeRrNm(out: []u8, name: []const u8) usize {
    const len = rrSizeNm(name.len);
    rrHead(out, 'N', 'M', len);
    out[4] = 0;
    @memcpy(out[5 .. 5 + name.len], name);
    if (len != 5 + name.len) out[5 + name.len] = 0;
    return len;
}

// One directory record: 33-byte header, stored name, even-name padding,
// then the Rock Ridge system-use area.
fn writeDirRecord(
    block: []u8,
    pos: *usize,
    extent: u32,
    size: u32,
    directory: bool,
    stored_name: []const u8,
    stored_name_len: u8,
    rr_name: ?[]const u8,
    serial: u32,
) Exception!void {
    var sua: [320]u8 = undefined;
    var sua_len: usize = 0;
    // A PX mode there would override the directory mode and hide every child.
    // The root dot record alone carries SUSP and ER.
    if (directory and stored_name_len == 1 and stored_name[0] == 0 and serial == 0) {
        sua_len += writeRrSp(&sua);
        sua_len += writeRrEr(sua[sua_len..]);
    } else if (!(directory and stored_name_len == 1 and (stored_name[0] == 0 or stored_name[0] == 1))) {
        sua_len += writeRrPx(sua[sua_len..], if (directory) 0o40755 else 0o100644, serial);
        if (rr_name) |name| sua_len += writeRrNm(sua[sua_len..], name);
    }
    if (sua_len & 1 != 0) {
        sua[sua_len] = 0;
        sua_len += 1;
    }
    const pad: usize = if (stored_name_len & 1 == 0) 1 else 0;
    const record_len = 33 + stored_name_len + pad + sua_len;
    if (record_len > 255) return error.UnsupportedException;
    const at = pos.*;
    writeBaseRecord(block[at .. at + 34], extent, size, directory, stored_name_len, stored_name[0]);
    block[at] = @intCast(record_len);
    var off = at + 33;
    @memcpy(block[off .. off + stored_name_len], stored_name);
    off += stored_name_len;
    if (pad != 0) {
        block[off] = 0;
        off += 1;
    }
    @memcpy(block[off .. off + sua_len], sua[0..sua_len]);
    pos.* = at + record_len;
}

pub fn encode(entries: []const Entry, output: []u8, scratch: []u8) Exception!usize {
    // The plan lives in caller scratch; archiveSize accepts exactly the
    // sets this budget holds.
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const plan = try buildIsoPlan(entries, fba.allocator());
    if (output.len < plan.total) return error.CapacityException;
    @memset(output[0..@as(usize, @intCast(plan.total))], 0);
    writePvd(output[16 * sector_size ..][0..sector_size], &plan);
    const vdst = output[17 * sector_size ..][0..sector_size];
    @memset(vdst, 0);
    vdst[0] = descriptor_terminator;
    @memcpy(vdst[1..6], volume_descriptor_magic);
    vdst[6] = 1;
    writePathTable(output[18 * sector_size ..][0..sector_size], &plan, false);
    writePathTable(output[19 * sector_size ..][0..sector_size], &plan, true);
    // PX serials must be unique per file or Rock Ridge readers collapse them into hardlinks.
    var serial: u32 = 2;
    for (plan.dir_order, 0..) |ni, di| {
        const node = &plan.nodes[ni];
        var dir: [sector_size]u8 = undefined;
        @memset(&dir, 0);
        var pos: usize = 0;
        const parent_rank: u32 = if (di == 0) 1 else parentRank(&plan, node.parent);
        const parent_lba: u32 = plan.dir_lba_of[parent_rank - 1];
        try writeDirRecord(&dir, &pos, plan.dir_lba_of[di], plan.dir_content[di], true, "\x00", 1, null, if (di == 0) 0 else 1);
        try writeDirRecord(&dir, &pos, parent_lba, plan.dir_content[parent_rank - 1], true, "\x01", 1, null, if (di == 0) 0 else 1);
        for (plan.kids[node.first_child .. node.first_child + node.child_count]) |ci| {
            const child = &plan.nodes[ci];
            var stored: [252]u8 = undefined;
            @memcpy(stored[0..child.name.len], child.name);
            if (child.kind == .dir) {
                // Directory identifiers never carry a version suffix.
                const child_rank = childRank(&plan, ci);
                try writeDirRecord(&dir, &pos, plan.dir_lba_of[child_rank], plan.dir_content[child_rank], true, stored[0..child.name.len], @intCast(child.name.len), child.name, serial);
                serial += 1;
            } else {
                if (child.name.len + 2 > stored.len) return error.UnsupportedException;
                stored[child.name.len] = ';';
                stored[child.name.len + 1] = '1';
                const file_rank = fileRank(&plan, ci);
                try writeDirRecord(&dir, &pos, plan.file_lba_of[file_rank], @intCast(child.data.len), false, stored[0 .. child.name.len + 2], @intCast(child.name.len + 2), child.name, serial);
                serial += 1;
            }
        }
        const dir_at: usize = std.math.cast(usize, std.math.mul(u64, plan.dir_lba_of[di], sector_size) catch return error.DataException) orelse return error.DataException;
        @memcpy(output[dir_at..][0..sector_size], &dir);
    }
    for (plan.file_order, 0..) |ni, fi| {
        const node = &plan.nodes[ni];
        const at = std.math.mul(u64, plan.file_lba_of[fi], sector_size) catch return error.DataException;
        const at_usize: usize = std.math.cast(usize, at) orelse return error.DataException;
        @memcpy(output[at_usize .. at_usize + node.data.len], node.data);
    }
    return @intCast(plan.total);
}

fn childRank(plan: *const IsoPlan, node_index: u32) usize {
    return rankOf(plan.dir_order, node_index);
}

fn fileRank(plan: *const IsoPlan, node_index: u32) usize {
    return rankOf(plan.file_order, node_index);
}

test "iso write roundtrips nested directories" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "a/b/deep.txt", .data = "nested payload" },
        .{ .name = "a/sib.txt", .data = "sibling" },
        .{ .name = "top.txt", .data = "root file" },
    };
    var archive: [64 * sector_size]u8 = undefined;
    var scratch: [scratch_size]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    try testing.expectEqual(written, try archiveSize(&entries));
    try testing.expectEqual(@as(u64, 3), try inspectCount(archive[0..written], &scratch));
    var out: [16]u8 = undefined;
    const n0 = try decodeOrdinal(archive[0..written], 0, &out, &scratch);
    try testing.expectEqualSlices(u8, "nested payload", out[0..n0]);
    const n1 = try decodeOrdinal(archive[0..written], 1, &out, &scratch);
    try testing.expectEqualSlices(u8, "sibling", out[0..n1]);
    const n2 = try decodeOrdinal(archive[0..written], 2, &out, &scratch);
    try testing.expectEqualSlices(u8, "root file", out[0..n2]);
}

test "iso prefers a joliet supplementary descriptor" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "hello.txt", .data = "hello iso" },
        .{ .name = "data.bin", .data = "ABCABCABCABC" },
    };
    var archive: [32 * sector_size]u8 = undefined;
    var scratch: [scratch_size]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    const svd = archive[17 * sector_size ..][0..sector_size];
    @memcpy(svd[0..], archive[16 * sector_size ..][0..sector_size]);
    svd[0] = descriptor_supplementary;
    svd[88] = '%';
    svd[89] = '/';
    svd[90] = '@';
    try testing.expectEqual(@as(u64, 2), try inspectCount(archive[0..written], &scratch));
    var out: [16]u8 = undefined;
    const n = try decodeOrdinal(archive[0..written], 1, &out, &scratch);
    try testing.expectEqualSlices(u8, "hello iso", out[0..n]);
}

test "iso store roundtrips flat files" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "hello.txt", .data = "hello iso" },
        .{ .name = "data.bin", .data = "ABCABCABCABC" },
    };
    var archive: [32 * sector_size]u8 = undefined;
    var scratch: [scratch_size]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    try testing.expectEqual(written, try archiveSize(&entries));
    try testing.expectEqual(@as(u64, 2), try inspectCount(archive[0..written], &scratch));
    const first = try inspectOrdinal(archive[0..written], 0, &scratch);
    try testing.expectEqual(@as(u64, 12), first.size);
    var out: [16]u8 = undefined;
    const n = try decodeOrdinal(archive[0..written], 1, &out, &scratch);
    try testing.expectEqualSlices(u8, "hello iso", out[0..n]);
}

test "iso directory records resume at sector boundaries" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "a.txt", .data = "AAA" },
        .{ .name = "b.txt", .data = "BBB" },
    };
    var archive: [64 * sector_size]u8 = undefined;
    var scratch: [scratch_size]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    // Move the second file's record into the second sector of the root
    // directory: zero padding ends the first sector, records resume at 2048.
    const pvd = archive[16 * sector_size ..][0..sector_size];
    const root = archive[dir_lba * sector_size ..][0 .. 2 * sector_size];
    var pos: usize = 0;
    var second: [255]u8 = undefined;
    var second_len: usize = 0;
    var cut: usize = 0;
    while (pos < sector_size and root[pos] != 0) : (pos += root[pos]) {
        const rec = root[pos .. pos + root[pos]];
        if (rec[32] > 2 and rec[33] == 'b') {
            second_len = rec.len;
            @memcpy(second[0..second_len], rec);
            cut = pos;
            break;
        }
    }
    try testing.expect(second_len > 0);
    @memset(root[cut..sector_size], 0);
    @memcpy(root[sector_size .. sector_size + second_len], second[0..second_len]);
    @memset(root[sector_size + second_len .. 2 * sector_size], 0);
    std.mem.writeInt(u32, pvd[166..170], 2 * sector_size, .little);
    std.mem.writeInt(u32, pvd[170..174], 2 * sector_size, .big);
    try testing.expectEqual(@as(u64, 2), try inspectCount(archive[0..written], &scratch));
    var out: [8]u8 = undefined;
    const n = try decodeOrdinal(archive[0..written], 1, &out, &scratch);
    try testing.expectEqualSlices(u8, "BBB", out[0..n]);
}

test "iso rejects multi-extent and interleaved records" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "a.txt", .data = "AAA" },
        .{ .name = "b.txt", .data = "BBB" },
    };
    var archive: [64 * sector_size]u8 = undefined;
    var scratch: [scratch_size]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    const root = archive[dir_lba * sector_size ..][0..sector_size];
    const first_at = 226 + 34; // dot record then dotdot record.
    try testing.expect(root[first_at] != 0);
    for ([_]u8{ 1 << 7, 1 << 2 }) |flag| {
        root[first_at + 25] |= flag;
        try testing.expectError(error.UnsupportedException, inspectCount(archive[0..written], &scratch));
        root[first_at + 25] &= ~flag;
    }
}

test "iso directory sizes are block multiples and directory names carry no version" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "top.txt", .data = "root file" },
        .{ .name = "sub/inner.txt", .data = "inner" },
    };
    var archive: [64 * sector_size]u8 = undefined;
    var scratch: [scratch_size]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    const pvd = archive[16 * sector_size ..][0..sector_size];
    try testing.expectEqual(@as(u32, sector_size), std.mem.readInt(u32, pvd[166..170], .little));
    // The sub-directory record carries the plain identifier; the file
    // record keeps the ";1" interchange suffix.
    const root = archive[dir_lba * sector_size ..][0..sector_size];
    var pos: usize = 226 + 34;
    var saw_dir = false;
    var saw_file = false;
    while (pos < sector_size and root[pos] != 0) : (pos += root[pos]) {
        const rec = root[pos .. pos + root[pos]];
        const name = rec[33..][0..rec[32]];
        if (std.mem.eql(u8, name, "sub")) {
            saw_dir = true;
            try testing.expectEqual(@as(u32, sector_size), std.mem.readInt(u32, rec[10..14], .little));
        }
        if (std.mem.eql(u8, name, "top.txt;1")) saw_file = true;
    }
    try testing.expect(saw_dir and saw_file);
    try testing.expectEqual(@as(u64, 2), try inspectCount(archive[0..written], &scratch));
}

test "iso rejects oversized directory records at planning time" {
    const testing = std.testing;
    var name_buf: [90]u8 = undefined;
    @memset(&name_buf, 'n');
    const entries = [_]Entry{.{ .name = name_buf[0..], .data = "x" }};
    // The 33-byte header, name area, PX and NM exceed the 255-byte record
    // limit; sizing and encoding must agree on the rejection.
    try testing.expectError(error.UnsupportedException, archiveSize(&entries));
    var archive: [64 * sector_size]u8 = undefined;
    var scratch: [scratch_size]u8 = undefined;
    try testing.expectError(error.UnsupportedException, encode(&entries, &archive, &scratch));
}

test "iso write depth stays within the reader walk limit" {
    const testing = std.testing;
    var deep: [300]u8 = undefined;
    var len: usize = 0;
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        @memcpy(deep[len .. len + 2], "a/");
        len += 2;
    }
    @memcpy(deep[len .. len + 5], "f.txt");
    // 65 path components: the deepest directory sits at walk depth 64.
    const ok_entries = [_]Entry{.{ .name = deep[0 .. len + 5], .data = "deep" }};
    var archive: [128 * sector_size]u8 = undefined;
    var scratch: [scratch_size]u8 = undefined;
    const written = try encode(&ok_entries, &archive, &scratch);
    try testing.expectEqual(@as(u64, 1), try inspectCount(archive[0..written], &scratch));
    // One more component would push the deepest directory past the limit.
    @memcpy(deep[len .. len + 2], "a/");
    @memcpy(deep[len + 2 .. len + 7], "f.txt");
    const too_deep = [_]Entry{.{ .name = deep[0 .. len + 7], .data = "deep" }};
    try testing.expectError(error.UnsupportedException, archiveSize(&too_deep));
    try testing.expectError(error.UnsupportedException, encode(&too_deep, &archive, &scratch));
}
