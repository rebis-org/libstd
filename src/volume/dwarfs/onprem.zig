const std = @import("std");

const bounds = @import("../../common/primitive/bounds.zig");
const exception_prim = @import("../../common/primitive/exception.zig");
const tree_order = @import("../../common/primitive/order.zig");
const lz4_leaf = @import("../../leaf/lz4/onprem.zig");
const zstd_leaf = @import("../../leaf/zstd/onprem.zig");

const Exception = exception_prim.Exception;

// DwarFS v2 slice: one root directory of regular files.
// Fidelity target is mkdwarfs output, verified with dwarfsck.

pub const scratch_size: usize = 2 * 1024 * 1024;

const section_type_block: u16 = 0;
const section_type_schema: u16 = 7;
const section_type_metadata: u16 = 8;
const compression_none: u16 = 0;
const compression_zstd: u16 = 2;
const compression_lz4: u16 = 3;
const section_header_size: usize = 64;
const section_magic = "DWARFS";

const zstd_window: u32 = 256 * 1024;
const zstd_history: usize = zstd_window + zstd_leaf.block_size_max;

pub const Entry = struct {
    name: []const u8,
    data: []const u8,
};

pub const EntryInfo = struct {
    size: u64,
    ordinal: u64,
};

const Sections = struct {
    blocks_at: u64,
    blocks_len: u64,
    blocks_compression: u16,
    schema_at: u64,
    schema_len: u64,
    schema_compression: u16,
    metadata_at: u64,
    metadata_len: u64,
    metadata_compression: u16,
};

fn parseSections(archive: []const u8) Exception!Sections {
    if (archive.len < section_header_size) return error.DataException;
    if (!std.mem.eql(u8, archive[0..6], section_magic)) return error.DataException;
    var out: Sections = undefined;
    var have_blocks = false;
    var have_schema = false;
    var have_metadata = false;
    var at: u64 = 0;
    while (at + section_header_size <= archive.len) {
        const head = archive[at .. at + section_header_size];
        if (!std.mem.eql(u8, head[0..6], section_magic)) return error.DataException;
        const stype = std.mem.readInt(u16, head[52..54], .little);
        const compression = std.mem.readInt(u16, head[54..56], .little);
        const length = std.mem.readInt(u64, head[56..64], .little);
        const payload_at = try bounds.addU64(at, section_header_size);
        switch (stype) {
            section_type_block => {
                if (!have_blocks) {
                    out.blocks_at = payload_at;
                    out.blocks_len = length;
                    out.blocks_compression = compression;
                    have_blocks = true;
                }
            },
            section_type_schema => {
                out.schema_at = payload_at;
                out.schema_len = length;
                out.schema_compression = compression;
                have_schema = true;
            },
            section_type_metadata => {
                out.metadata_at = payload_at;
                out.metadata_len = length;
                out.metadata_compression = compression;
                have_metadata = true;
            },
            else => {},
        }
        at = try bounds.addU64(payload_at, length);
    }
    if (!have_blocks or !have_schema or !have_metadata) return error.DataException;
    return out;
}

fn sectionPayload(archive: []const u8, at: u64, len: u64, compression: u16, arena: std.mem.Allocator) Exception![]const u8 {
    const raw = try bounds.slice(archive, at, len);
    if (compression == compression_none) return raw;
    const out = arena.alloc(u8, raw.len * 16 + (1 << 16)) catch return error.ResourceException;
    var writer = std.Io.Writer.fixed(out);
    switch (compression) {
        compression_zstd => {
            const history = arena.alloc(u8, zstd_history) catch return error.ResourceException;
            var reader = std.Io.Reader.fixed(raw);
            _ = zstd_leaf.decodeStream(&reader, &writer, history, .{ .window_size = zstd_window }) catch return error.DataException;
        },
        compression_lz4 => {
            lz4_leaf.decodeToWriter(raw, &writer, out, .{}) catch return error.DataException;
        },
        else => return error.UnsupportedException,
    }
    return out[0..writer.end];
}

// Dwarfs thrift dialect: map size precedes the key/value type byte.
// Booleans ride inline in field headers.
const Compact = struct {
    data: []const u8,
    pos: usize = 0,
    partial: u64 = 0,

    fn take(c: *Compact) Exception!u8 {
        if (c.pos >= c.data.len) return error.DataException;
        const b = c.data[c.pos];
        c.pos += 1;
        return b;
    }

    fn varint(c: *Compact) Exception!u64 {
        var shift: u6 = 0;
        var result: u64 = 0;
        while (true) {
            const b = try c.take();
            if (shift > 63) return error.DataException;
            result |= @as(u64, b & 0x7f) << shift;
            if (b & 0x80 == 0) return result;
            shift += 7;
        }
    }

    fn zigzag(c: *Compact) Exception!i64 {
        const v = try c.varint();
        return @bitCast((v >> 1) ^ (0 -% (v & 1)));
    }

    fn listSize(c: *Compact, nibble: u8) Exception!usize {
        if (nibble == 0x0f) return castUsize(try c.varint());
        return nibble;
    }

    const StructField = struct { id: i16, val: Value };
    const MapEntry = struct { key: Value, val: Value };

    const Value = union(enum) {
        boolean: bool,
        int: u64,
        bytes: []const u8,
        map: []MapEntry,
        structure: []StructField,
    };

    fn value(c: *Compact, arena: std.mem.Allocator, ttype: u8) Exception!Value {
        switch (ttype) {
            1, 2 => return .{ .boolean = ttype == 1 },
            3 => return .{ .int = try c.take() },
            4, 5, 6 => return .{ .int = @as(u64, @bitCast(try c.zigzag())) },
            8 => {
                const n = try castUsize(try c.varint());
                if (n > c.data.len - c.pos) return error.DataException;
                const s = c.data[c.pos .. c.pos + n];
                c.pos += n;
                return .{ .bytes = s };
            },
            9, 10 => {
                const b = try c.take();
                const n = try c.listSize(b >> 4);
                if (b & 0x0f == 0 or b & 0x0f == 1 or b & 0x0f == 2) return error.UnsupportedException;
                const items = try c.values(arena, b & 0x0f, n);
                return .{ .map = items.map };
            },
            11 => {
                const n = try castUsize(try c.varint());
                if (n == 0) return .{ .map = &.{} };
                const b = try c.take();
                return .{ .map = try c.mapEntries(arena, b >> 4, b & 0x0f, n) };
            },
            12 => return .{ .structure = try c.structure(arena) },
            else => return error.UnsupportedException,
        }
    }

    fn values(c: *Compact, arena: std.mem.Allocator, ttype: u8, n: usize) Exception!struct { map: []MapEntry } {
        const entries = arena.alloc(MapEntry, n) catch return error.ResourceException;
        for (entries) |*e| {
            e.key = .{ .int = 0 };
            e.val = try c.value(arena, ttype);
        }
        return .{ .map = entries };
    }

    fn mapEntries(c: *Compact, arena: std.mem.Allocator, kt: u8, vt: u8, n: usize) Exception![]MapEntry {
        const entries = arena.alloc(MapEntry, n) catch return error.ResourceException;
        for (entries) |*e| {
            e.key = try c.value(arena, kt);
            e.val = try c.value(arena, vt);
        }
        return entries;
    }

    fn structure(c: *Compact, arena: std.mem.Allocator) Exception![]StructField {
        var last: i16 = 0;
        var fields: [128]StructField = undefined;
        var count: usize = 0;
        while (true) {
            const h = try c.take();
            if (h == 0) break;
            const t = h & 0x0f;
            if (t == 0) return error.DataException;
            const d = h >> 4;
            if (d != 0) {
                last += @intCast(d);
            } else {
                last = @intCast(try c.zigzag());
            }
            if (count >= fields.len) return error.UnsupportedException;
            fields[count] = .{ .id = last, .val = try c.value(arena, t) };
            count += 1;
        }
        const out = arena.alloc(StructField, count) catch return error.ResourceException;
        @memcpy(out, fields[0..count]);
        return out;
    }
};

fn castUsize(v: u64) Exception!usize {
    return std.math.cast(usize, v) orelse error.DataException;
}

const Field = struct {
    id: i16,
    layout: i16,
    offset: i16,
};

const Layout = struct {
    size: u32,
    bits: u16,
    fields: []Field,
};

const Schema = struct {
    layouts: []Layout,
    root: i16,
};

fn structField(s: []const Compact.StructField, id: i16) ?Compact.Value {
    for (s) |f| {
        if (f.id == id) return f.val;
    }
    return null;
}

fn fieldInt(structure: []const Compact.StructField, id: i16) u64 {
    return (structField(structure, id) orelse @as(Compact.Value, .{ .int = 0 })).int;
}

fn parseSchema(raw: []const u8, arena: std.mem.Allocator) Exception!Schema {
    var c = Compact{ .data = raw };
    const root_val = try c.value(arena, 12);
    const layouts_val = structField(root_val.structure, 2) orelse return error.DataException;
    const root_id = structField(root_val.structure, 3) orelse return error.DataException;
    const layouts = arena.alloc(Layout, layouts_val.map.len) catch return error.ResourceException;
    for (layouts_val.map, 0..) |entry, i| {
        const ls = entry.val.structure;
        var layout = Layout{
            .size = @intCast(fieldInt(ls, 1)),
            .bits = @intCast(fieldInt(ls, 2)),
            .fields = &.{},
        };
        if (structField(ls, 3)) |fv| {
            const fs = arena.alloc(Field, fv.map.len) catch return error.ResourceException;
            for (fv.map, 0..) |fe, j| {
                const f2 = fe.val.structure;
                fs[j] = .{
                    .id = @intCast(fe.key.int),
                    .layout = @intCast(fieldInt(f2, 1)),
                    .offset = @as(i16, @truncate(@as(i64, @bitCast(fieldInt(f2, 2))))),
                };
            }
            std.mem.sort(Field, fs, {}, struct {
                fn less(_: void, a: Field, b: Field) bool {
                    return a.id < b.id;
                }
            }.less);
            layout.fields = fs;
        }
        layouts[i] = layout;
    }
    return .{ .layouts = layouts, .root = @intCast(root_id.int) };
}

// The schema alone fixes widths and offsets; bits pack LSB-first.
const Bits = struct {
    data: []const u8,

    fn read(b: Bits, pos: usize, width: u16) Exception!u64 {
        if (width == 0) return 0;
        var v: u64 = 0;
        for (0..width) |i| {
            const at = pos + i;
            if ((at >> 3) >= b.data.len) return error.DataException;
            v |= @as(u64, (b.data[at >> 3] >> @intCast(at & 7)) & 1) << @intCast(i);
        }
        return v;
    }
};

fn fpos(base: usize, off: i16) usize {
    return if (off < 0) base + @as(usize, @intCast(-off)) else base + @as(usize, @intCast(off)) * 8;
}

const Chunk = struct { offset: u32, size: u32 };
const DirEntry = struct { name_index: u32, inode_num: u32 };

const Metadata = struct {
    chunks: []Chunk = &.{},
    chunk_table: []u32 = &.{},
    directories: []u32 = &.{},
    inodes: []u32 = &.{},
    modes: []u32 = &.{},
    dir_entries: []DirEntry = &.{},
    names_buffer: []const u8 = &.{},
    names_index: []u32 = &.{},
    block_size: u32 = 0,
};

const Decoder = struct {
    bits: Bits,
    layouts: []Layout,
    arena: std.mem.Allocator,

    fn find(l: Layout, id: i16) ?Field {
        for (l.fields) |f| {
            if (f.id == id) return f;
        }
        return null;
    }

    fn integral(d: *Decoder, lid: i16, pos: usize) Exception!u64 {
        return d.bits.read(pos, d.layouts[@intCast(lid)].bits);
    }

    fn u32At(d: *Decoder, lid: i16, pos: usize) Exception!u32 {
        return std.math.cast(u32, try d.integral(lid, pos)) orelse error.DataException;
    }

    // Vector headers: field 2 is the count, field 1 a blob-relative byte address.
    fn vectorHead(d: *Decoder, lid: i16, pos: usize) Exception!struct { count: usize, dist: usize, item: ?Field } {
        const l = d.layouts[@intCast(lid)];
        const cf = find(l, 2) orelse return error.DataException;
        const count = try castUsize(try d.integral(cf.layout, fpos(pos, cf.offset)));
        var dist: usize = 0;
        if (find(l, 1)) |df| dist = try castUsize(try d.integral(df.layout, fpos(pos, df.offset)));
        return .{ .count = count, .dist = dist, .item = find(l, 3) };
    }

    fn u32Vector(d: *Decoder, count: usize, layout: i16, start: usize, stride: u16) Exception![]u32 {
        const out = d.arena.alloc(u32, count) catch return error.ResourceException;
        for (out, 0..) |*o, i| o.* = try d.u32At(layout, start + i * stride);
        return out;
    }

    fn scalarVector(d: *Decoder, lid: i16, pos: usize) Exception![]u32 {
        const head = try d.vectorHead(lid, pos);
        if (head.item) |item| {
            const stride = d.layouts[@intCast(item.layout)].bits;
            return d.u32Vector(head.count, item.layout, head.dist * 8, stride);
        } else {
            const out = d.arena.alloc(u32, head.count) catch return error.ResourceException;
            @memset(out, 0);
            return out;
        }
    }

    fn structFieldVector(d: *Decoder, lid: i16, pos: usize, field_id: i16) Exception![]u32 {
        const head = try d.vectorHead(lid, pos);
        const item = head.item orelse return error.DataException;
        const stride = d.layouts[@intCast(item.layout)].bits;
        const inner = d.layouts[@intCast(item.layout)];
        const inner_field = find(inner, field_id) orelse return error.DataException;
        return d.u32Vector(head.count, inner_field.layout, fpos(head.dist * 8, inner_field.offset), stride);
    }

    fn pairVector(d: *Decoder, comptime T: type, lid: i16, pos: usize, comptime ida: i16, comptime ma: []const u8, comptime idb: i16, comptime mb: []const u8) Exception![]T {
        const head = try d.vectorHead(lid, pos);
        const item = head.item orelse return error.DataException;
        const stride = d.layouts[@intCast(item.layout)].bits;
        const start = head.dist * 8;
        const out = d.arena.alloc(T, head.count) catch return error.ResourceException;
        for (out, 0..) |*o, i| {
            const at = start + i * stride;
            o.* = std.mem.zeroes(T);
            if (find(d.layouts[@intCast(item.layout)], ida)) |f| @field(o, ma) = try d.u32At(f.layout, fpos(at, f.offset));
            if (find(d.layouts[@intCast(item.layout)], idb)) |f| @field(o, mb) = try d.u32At(f.layout, fpos(at, f.offset));
        }
        return out;
    }

    fn chunkVector(d: *Decoder, lid: i16, pos: usize) Exception![]Chunk {
        return d.pairVector(Chunk, lid, pos, 2, "offset", 3, "size");
    }

    fn dirEntryVector(d: *Decoder, lid: i16, pos: usize) Exception![]DirEntry {
        return d.pairVector(DirEntry, lid, pos, 1, "name_index", 2, "inode_num");
    }

    fn frozenString(d: *Decoder, lid: i16, pos: usize) Exception![]const u8 {
        const l = d.layouts[@intCast(lid)];
        const df = find(l, 1) orelse return error.DataException;
        const cf = find(l, 2) orelse return error.DataException;
        const dist = try castUsize(try d.integral(df.layout, fpos(pos, df.offset)));
        const count = try castUsize(try d.integral(cf.layout, fpos(pos, cf.offset)));
        if (dist + count > d.bits.data.len) return error.DataException;
        return d.bits.data[dist .. dist + count];
    }

    fn presence(d: *Decoder, lid: i16, pos: usize) Exception!struct { present: bool, value_field: ?Field } {
        const l = d.layouts[@intCast(lid)];
        const pf = find(l, 1) orelse return error.DataException;
        const present = (try d.integral(pf.layout, fpos(pos, pf.offset))) != 0;
        return .{ .present = present, .value_field = find(l, 2) };
    }
};

fn decodeMetadata(meta_raw: []const u8, schema: Schema, arena: std.mem.Allocator) Exception!Metadata {
    var dec = Decoder{ .bits = .{ .data = meta_raw }, .layouts = schema.layouts, .arena = arena };
    const root = schema.layouts[@intCast(schema.root)];
    var md: Metadata = .{};
    for (root.fields) |f| {
        const pos = fpos(0, f.offset);
        switch (f.id) {
            1 => md.chunks = try dec.chunkVector(f.layout, pos),
            2 => md.directories = try dec.structFieldVector(f.layout, pos, 2),
            3 => md.inodes = try dec.structFieldVector(f.layout, pos, 2),
            4 => md.chunk_table = try dec.scalarVector(f.layout, pos),
            6 => if ((try dec.vectorHead(f.layout, pos)).count > 0) return error.UnsupportedException,
            9 => md.modes = try dec.scalarVector(f.layout, pos),
            10 => if ((try dec.vectorHead(f.layout, pos)).count > 0) return error.UnsupportedException,
            15 => md.block_size = try dec.u32At(f.layout, pos),
            19 => {
                const p = try dec.presence(f.layout, pos);
                if (p.present) {
                    const vf = p.value_field orelse return error.DataException;
                    md.dir_entries = try dec.dirEntryVector(vf.layout, fpos(pos, vf.offset));
                }
            },
            20 => {
                const p = try dec.presence(f.layout, pos);
                if (p.present) {
                    const vf = p.value_field orelse continue;
                    if ((try dec.vectorHead(vf.layout, fpos(pos, vf.offset))).count > 0) return error.UnsupportedException;
                }
            },
            24 => {
                const p = try dec.presence(f.layout, pos);
                if (p.present) {
                    const vf = p.value_field orelse return error.DataException;
                    const table = dec.layouts[@intCast(vf.layout)];
                    for (table.fields) |inf| {
                        if (inf.id == 1) md.names_buffer = try dec.frozenString(inf.layout, fpos(fpos(pos, vf.offset), inf.offset));
                        if (inf.id == 3) md.names_index = try dec.scalarVector(inf.layout, fpos(fpos(pos, vf.offset), inf.offset));
                    }
                }
            },
            else => {},
        }
    }
    return md;
}

const Target = union(enum) {
    count,
    resolve: struct { ordinal: u64, info: *EntryInfo, output: ?[]u8, found: *bool = undefined },
};

fn runTarget(archive: []const u8, scratch: []u8, target: Target) Exception!u64 {
    var found = false;
    const resolved = switch (target) {
        .count => target,
        .resolve => |res| Target{ .resolve = .{ .ordinal = res.ordinal, .info = res.info, .output = res.output, .found = &found } },
    };
    if (scratch.len < scratch_size) return error.CapacityException;
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const arena = fba.allocator();
    const sections = try parseSections(archive);
    const schema_raw = try sectionPayload(archive, sections.schema_at, sections.schema_len, sections.schema_compression, arena);
    const schema = try parseSchema(schema_raw, arena);
    const meta_raw = try sectionPayload(archive, sections.metadata_at, sections.metadata_len, sections.metadata_compression, arena);
    const md = try decodeMetadata(meta_raw, schema, arena);
    if (md.block_size == 0 or md.names_index.len == 0) return error.DataException;
    const blocks = try sectionPayload(archive, sections.blocks_at, sections.blocks_len, sections.blocks_compression, arena);
    if (md.directories.len < 2) return error.DataException;
    const dir_count = md.directories.len - 1;
    const file_off: u32 = @intCast(dir_count);
    var state = WalkState{};
    try walkDwarfsDir(md, blocks, 0, file_off, resolved, &state, 0);
    return switch (target) {
        .count => state.ordinal,
        .resolve => if (found) state.ordinal else error.DataException,
    };
}

const WalkState = struct { ordinal: u64 = 0 };

fn walkDwarfsDir(md: Metadata, blocks: []const u8, dir_index: usize, file_off: u32, target: Target, state: *WalkState, depth: u32) Exception!void {
    if (depth > max_dir_depth) return error.DataException;
    const start = md.directories[dir_index];
    const end = md.directories[dir_index + 1];
    if (end < start or end > md.dir_entries.len) return error.DataException;
    const found_ptr = switch (target) {
        .resolve => |res| res.found,
        .count => null,
    };
    var e = start;
    while (e < end) : (e += 1) {
        if (found_ptr) |fp| {
            if (fp.*) return;
        }
        const entry = md.dir_entries[e];
        if (entry.inode_num < file_off) {
            if (@as(u64, entry.inode_num) + 1 >= md.directories.len) return error.DataException;
            try walkDwarfsDir(md, blocks, entry.inode_num, file_off, target, state, depth + 1);
            continue;
        }
        if (entry.inode_num >= md.inodes.len) return error.DataException;
        const mode_index = md.inodes[entry.inode_num];
        if (mode_index >= md.modes.len) return error.DataException;
        if (md.modes[mode_index] & 0o170000 != 0o100000) return error.UnsupportedException;
        const idx: usize = entry.inode_num - file_off;
        if (idx + 1 >= md.chunk_table.len) return error.DataException;
        const c0 = md.chunk_table[idx];
        const c1 = md.chunk_table[idx + 1];
        if (c1 != c0 + 1) return error.UnsupportedException;
        if (c0 >= md.chunks.len) return error.DataException;
        const chunk = md.chunks[c0];
        switch (target) {
            .count => {},
            .resolve => |res| {
                if (state.ordinal == res.ordinal) {
                    res.info.size = chunk.size;
                    res.info.ordinal = state.ordinal;
                    if (res.output) |out| {
                        if (out.len < chunk.size) return error.CapacityException;
                        const data = try bounds.slice(blocks, chunk.offset, chunk.size);
                        @memcpy(out[0..chunk.size], data);
                    }
                    res.found.* = true;
                    return;
                }
            },
        }
        state.ordinal += 1;
    }
}

pub fn inspectCount(archive: []const u8, scratch: []u8) Exception!u64 {
    return runTarget(archive, scratch, .count);
}

pub fn inspectOrdinal(archive: []const u8, ordinal: u64, scratch: []u8) Exception!EntryInfo {
    var info: EntryInfo = undefined;
    _ = try runTarget(archive, scratch, .{ .resolve = .{ .ordinal = ordinal, .info = &info, .output = null } });
    return info;
}

pub fn decodeOrdinal(archive: []const u8, ordinal: u64, output: []u8, scratch: []u8) Exception!usize {
    var info: EntryInfo = undefined;
    _ = try runTarget(archive, scratch, .{ .resolve = .{ .ordinal = ordinal, .info = &info, .output = output } });
    return @intCast(info.size);
}

// The writer emits mkdwarfs' v2 section chain for the flat shape.
// Payloads stay uncompressed; total data is capped.

const write_block_size: u32 = 16 * 1024 * 1024;
const max_dir_depth: u32 = 64;
const write_data_cap: usize = 512 * 1024;
const section_type_index: u16 = 9;
const section_offset_mask: u64 = (1 << 48) - 1;
const root_bytes: usize = 101;
const root_bits: usize = 802;

const wl_u32: i16 = 0;
const wl_u64: i16 = 1;
const wl_bool: i16 = 2;
const wl_vec_u32: i16 = 3;
const wl_chunk: i16 = 4;
const wl_vec_chunk: i16 = 5;
const wl_directory: i16 = 6;
const wl_vec_dir: i16 = 7;
const wl_inode: i16 = 8;
const wl_vec_inode: i16 = 9;
const wl_dirent: i16 = 10;
const wl_vec_dirent: i16 = 11;
const wl_opt_dirent: i16 = 12;
const wl_fstring: i16 = 13;
const wl_names: i16 = 14;
const wl_opt_names: i16 = 15;
const wl_root: i16 = 16;

const WField = struct { id: i16, layout: i16, offset: i16 };
const WLayout = struct {
    size: u32,
    bits: u16,
    fields: []const WField,
};

// Offsets are bit positions; the schema encodes them negative.
const wlayouts = [_]WLayout{
    .{ .size = 0, .bits = 32, .fields = &.{} },
    .{ .size = 0, .bits = 64, .fields = &.{} },
    .{ .size = 0, .bits = 1, .fields = &.{} },
    .{ .size = 0, .bits = 64, .fields = &.{ .{ .id = 2, .layout = wl_u32, .offset = 0 }, .{ .id = 1, .layout = wl_u32, .offset = -32 }, .{ .id = 3, .layout = wl_u32, .offset = 0 } } },
    .{ .size = 0, .bits = 96, .fields = &.{ .{ .id = 1, .layout = wl_u32, .offset = 0 }, .{ .id = 2, .layout = wl_u32, .offset = -32 }, .{ .id = 3, .layout = wl_u32, .offset = -64 } } },
    .{ .size = 0, .bits = 64, .fields = &.{ .{ .id = 2, .layout = wl_u32, .offset = 0 }, .{ .id = 1, .layout = wl_u32, .offset = -32 }, .{ .id = 3, .layout = wl_chunk, .offset = 0 } } },
    .{ .size = 0, .bits = 96, .fields = &.{ .{ .id = 1, .layout = wl_u32, .offset = 0 }, .{ .id = 2, .layout = wl_u32, .offset = -32 }, .{ .id = 3, .layout = wl_u32, .offset = -64 } } },
    .{ .size = 0, .bits = 64, .fields = &.{ .{ .id = 2, .layout = wl_u32, .offset = 0 }, .{ .id = 1, .layout = wl_u32, .offset = -32 }, .{ .id = 3, .layout = wl_directory, .offset = 0 } } },
    .{ .size = 0, .bits = 192, .fields = &.{ .{ .id = 1, .layout = wl_u32, .offset = 0 }, .{ .id = 2, .layout = wl_u32, .offset = -32 }, .{ .id = 3, .layout = wl_u32, .offset = -64 }, .{ .id = 4, .layout = wl_u32, .offset = -96 }, .{ .id = 5, .layout = wl_u32, .offset = -128 }, .{ .id = 14, .layout = wl_u32, .offset = -160 } } },
    .{ .size = 0, .bits = 64, .fields = &.{ .{ .id = 2, .layout = wl_u32, .offset = 0 }, .{ .id = 1, .layout = wl_u32, .offset = -32 }, .{ .id = 3, .layout = wl_inode, .offset = 0 } } },
    .{ .size = 0, .bits = 64, .fields = &.{ .{ .id = 1, .layout = wl_u32, .offset = 0 }, .{ .id = 2, .layout = wl_u32, .offset = -32 } } },
    .{ .size = 0, .bits = 64, .fields = &.{ .{ .id = 2, .layout = wl_u32, .offset = 0 }, .{ .id = 1, .layout = wl_u32, .offset = -32 }, .{ .id = 3, .layout = wl_dirent, .offset = 0 } } },
    .{ .size = 0, .bits = 65, .fields = &.{ .{ .id = 1, .layout = wl_bool, .offset = 0 }, .{ .id = 2, .layout = wl_vec_dirent, .offset = -1 } } },
    .{ .size = 0, .bits = 64, .fields = &.{ .{ .id = 1, .layout = wl_u32, .offset = 0 }, .{ .id = 2, .layout = wl_u32, .offset = -32 } } },
    .{ .size = 0, .bits = 128, .fields = &.{ .{ .id = 1, .layout = wl_fstring, .offset = 0 }, .{ .id = 3, .layout = wl_vec_u32, .offset = -64 } } },
    .{ .size = 0, .bits = 129, .fields = &.{ .{ .id = 1, .layout = wl_bool, .offset = 0 }, .{ .id = 2, .layout = wl_names, .offset = -1 } } },
    .{ .size = 101, .bits = 802, .fields = &.{ .{ .id = 1, .layout = wl_vec_chunk, .offset = 0 }, .{ .id = 2, .layout = wl_vec_dir, .offset = -64 }, .{ .id = 3, .layout = wl_vec_inode, .offset = -128 }, .{ .id = 4, .layout = wl_vec_u32, .offset = -192 }, .{ .id = 7, .layout = wl_vec_u32, .offset = -256 }, .{ .id = 8, .layout = wl_vec_u32, .offset = -320 }, .{ .id = 9, .layout = wl_vec_u32, .offset = -384 }, .{ .id = 12, .layout = wl_u64, .offset = -448 }, .{ .id = 15, .layout = wl_u32, .offset = -512 }, .{ .id = 16, .layout = wl_u64, .offset = -544 }, .{ .id = 19, .layout = wl_opt_dirent, .offset = -608 }, .{ .id = 24, .layout = wl_opt_names, .offset = -673 } } },
};

// LSB-first bit writer over the frozen blob.
const BitWriter = struct {
    bytes: []u8,
    bit: usize = 0,

    fn write(b: *BitWriter, value: u64, width: u16) void {
        var i: u16 = 0;
        while (i < width) : (i += 1) {
            const at = b.bit + i;
            if ((value >> @intCast(i)) & 1 != 0) {
                b.bytes[at >> 3] |= @as(u8, 1) << @intCast(at & 7);
            }
        }
        b.bit += width;
    }
};

fn writeU32List(dst: []u8, at: usize, list: []const u32) void {
    for (list, 0..) |v, i| std.mem.writeInt(u32, dst[at + 4 * i ..][0..4], v, .little);
}

fn sectionHeader(out: *[section_header_size]u8, number: u32, stype: u16, payload: []const u8) void {
    @memset(out, 0);
    @memcpy(out[0..6], section_magic);
    out[6] = 2;
    out[7] = 5;
    std.mem.writeInt(u32, out[48..52], number, .little);
    std.mem.writeInt(u16, out[52..54], stype, .little);
    std.mem.writeInt(u16, out[54..56], compression_none, .little);
    std.mem.writeInt(u64, out[56..64], payload.len, .little);
    // xxh3 covers the header from the number field through the payload.
    var xxh = std.hash.XxHash3.init(0);
    xxh.update(out[48..64]);
    xxh.update(payload);
    std.mem.writeInt(u64, out[40..48], xxh.final(), .little);
    // sha2-512/256 covers the header from the xxh3 field through the payload.
    var sha = std.crypto.hash.sha2.Sha512_256.init(.{});
    sha.update(out[40..64]);
    sha.update(payload);
    var digest: [32]u8 = undefined;
    sha.final(&digest);
    @memcpy(out[8..40], &digest);
}

fn writeSchema(out: *std.ArrayList(u8), alloc0: std.mem.Allocator) Exception!void {
    const w = struct {
        fn byte(list: *std.ArrayList(u8), a: std.mem.Allocator, b: u8) Exception!void {
            list.append(a, b) catch return error.ResourceException;
        }
        fn varint(list: *std.ArrayList(u8), a: std.mem.Allocator, v0: u64) Exception!void {
            var v = v0;
            while (v >= 0x80) {
                try byte(list, a, @as(u8, @truncate(v)) | 0x80);
                v >>= 7;
            }
            try byte(list, a, @intCast(v));
        }
        fn zz(list: *std.ArrayList(u8), a: std.mem.Allocator, v: i64) Exception!void {
            try varint(list, a, @as(u64, @bitCast((v << 1) ^ (v >> 63))));
        }
    };
    // Field 1: relaxTypeChecks = true.
    try w.byte(out, alloc0, (1 << 4) | 1);
    // Field 2: layouts map<i16, Layout>.
    try w.byte(out, alloc0, (1 << 4) | 11);
    try w.varint(out, alloc0, wlayouts.len);
    try w.byte(out, alloc0, 0x4c);
    for (wlayouts, 0..) |lay, lid| {
        try w.zz(out, alloc0, @as(i64, @intCast(lid)));
        var last: i16 = 0;
        try w.byte(out, alloc0, (1 << 4) | 5);
        try w.zz(out, alloc0, lay.size);
        last = 1;
        try w.byte(out, alloc0, @as(u8, @intCast((2 - last) << 4)) | 4);
        try w.zz(out, alloc0, lay.bits);
        last = 2;
        try w.byte(out, alloc0, @as(u8, @intCast((3 - last) << 4)) | 11);
        try w.varint(out, alloc0, lay.fields.len);
        if (lay.fields.len > 0) try w.byte(out, alloc0, 0x4c);
        for (lay.fields) |f| {
            try w.zz(out, alloc0, f.id);
            try w.byte(out, alloc0, (1 << 4) | 4);
            try w.zz(out, alloc0, f.layout);
            try w.byte(out, alloc0, (1 << 4) | 4);
            try w.zz(out, alloc0, f.offset);
            try w.byte(out, alloc0, 0);
        }
        last = 3;
        try w.byte(out, alloc0, @as(u8, @intCast((4 - last) << 4)) | 8);
        try w.varint(out, alloc0, 0);
        try w.byte(out, alloc0, 0);
    }
    // Field 3: rootLayout i16, field 4: fileVersion i32 = 1.
    try w.byte(out, alloc0, (1 << 4) | 4);
    try w.zz(out, alloc0, wl_root);
    try w.byte(out, alloc0, (1 << 4) | 5);
    try w.zz(out, alloc0, 1);
    try w.byte(out, alloc0, 0);
}

const DwNode = struct {
    kind: enum { dir, file },
    name: []const u8,
    parent: u32,
    data: []const u8 = &.{},
    number: u32 = 0,
    first_child: u32 = 0,
    child_count: u32 = 0,
};

const max_tree_nodes = 512;

fn dwFindOrCreateDir(nodes: *std.ArrayList(DwNode), alloc: std.mem.Allocator, parent: u32, name: []const u8) Exception!u32 {
    for (nodes.items, 0..) |node, i| {
        if (node.kind == .dir and node.parent == parent and std.mem.eql(u8, node.name, name)) return @intCast(i);
    }
    const idx: u32 = @intCast(nodes.items.len);
    nodes.append(alloc, .{ .kind = .dir, .name = name, .parent = parent }) catch return error.ResourceException;
    nodes.items[parent].child_count += 1;
    return idx;
}

fn dwValidate(name: []const u8) Exception!void {
    if (name.len == 0 or name.len > 512) return error.CallException;
    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |part| {
        if (part.len == 0 or part.len > 256) return error.CallException;
        if (std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.CallException;
    }
}

pub fn encode(entries: []const Entry, output: []u8, scratch: []u8) Exception!usize {
    // Caller scratch backs the whole build; the scratch_size constant
    // covers the declared entry and data caps.
    if (entries.len == 0 or entries.len > 4096) return error.UnsupportedException;
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const alloc = fba.allocator();

    // Tree build: nodes[0] roots the directory tree.
    var nodes: std.ArrayList(DwNode) = .empty;
    nodes.append(alloc, .{ .kind = .dir, .name = "", .parent = 0 }) catch return error.ResourceException;
    for (entries) |entry| {
        try dwValidate(entry.name);
        if (entry.data.len > write_block_size) return error.UnsupportedException;
        var parent: u32 = 0;
        var it = std.mem.splitScalar(u8, entry.name, '/');
        var comp = it.next().?;
        while (it.next()) |next| {
            parent = try dwFindOrCreateDir(&nodes, alloc, parent, comp);
            comp = next;
        }
        nodes.append(alloc, .{ .kind = .file, .name = comp, .parent = parent, .data = entry.data }) catch return error.ResourceException;
        nodes.items[parent].child_count += 1;
    }
    if (nodes.items.len > max_tree_nodes) return error.UnsupportedException;

    // Per-directory child lists in name order.
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
            fn less(ns: *std.ArrayList(DwNode), a: u32, b: u32) bool {
                return std.mem.order(u8, ns.items[a].name, ns.items[b].name) == .lt;
            }
        }.less);
    }

    // Number directories first (dwarfs numbers directories before files),
    // each group in DFS order.
    var dir_order: std.ArrayList(u32) = .empty;
    var file_order: std.ArrayList(u32) = .empty;
    try tree_order.orderTree(DwNode, &nodes, kids, 0, &dir_order, &file_order, alloc);
    for (dir_order.items, 0..) |ni, i| {
        nodes.items[ni].number = @intCast(i);
    }
    const dir_count: u32 = @intCast(dir_order.items.len);
    for (file_order.items, 0..) |ni, i| {
        nodes.items[ni].number = dir_count + @as(u32, @intCast(i));
    }

    // Metadata vectors.
    var chunks: std.ArrayList(u8) = .empty;
    var chunk_table: std.ArrayList(u32) = .empty;
    var inodes: std.ArrayList(u32) = .empty;
    var directories: std.ArrayList(u32) = .empty;
    var dir_entries: std.ArrayList(u32) = .empty;
    var names: std.ArrayList(u8) = .empty;
    var names_index: std.ArrayList(u32) = .empty;

    var total_size: u64 = 0;
    var chunk_off: u32 = 0;
    chunk_table.append(alloc, 0) catch return error.ResourceException;
    for (file_order.items) |ni| {
        const node = &nodes.items[ni];
        for ([_]u32{ 0, chunk_off, @intCast(node.data.len) }) |v| {
            var raw: [4]u8 = undefined;
            std.mem.writeInt(u32, &raw, v, .little);
            chunks.appendSlice(alloc, &raw) catch return error.ResourceException;
        }
        chunk_off = std.math.add(u32, chunk_off, @intCast(node.data.len)) catch return error.UnsupportedException;
        chunk_table.append(alloc, node.number - dir_count + 1) catch return error.ResourceException;
        total_size += node.data.len;
    }
    if (total_size > write_data_cap) return error.UnsupportedException;
    // Inodes: directories first, then files, each in DFS order.
    for (dir_order.items) |_| {
        for ([_]u32{ 0, 0, 0, 0, 0, 0 }) |v| {
            inodes.append(alloc, v) catch return error.ResourceException;
        }
    }
    for (file_order.items) |_| {
        for ([_]u32{ 0, 1, 0, 0, 0, 0 }) |v| {
            inodes.append(alloc, v) catch return error.ResourceException;
        }
    }
    // Directory records plus a sentinel, emitted directory by directory,
    // so every record index computes up front.
    dir_entries.appendSlice(alloc, &.{ 0, 0 }) catch return error.ResourceException;
    const first_entry_of = alloc.alloc(u32, dir_order.items.len) catch return error.ResourceException;
    const record_of = alloc.alloc(u32, nodes.items.len) catch return error.ResourceException;
    record_of[0] = 0;
    var rec_acc: u32 = 1;
    for (dir_order.items, 0..) |ni, di| {
        first_entry_of[di] = rec_acc;
        rec_acc += nodes.items[ni].child_count;
    }
    for (dir_order.items, 0..) |ni, di| {
        const node = &nodes.items[ni];
        for (kids[node.first_child .. node.first_child + node.child_count], 0..) |ci, k| {
            record_of[ci] = first_entry_of[di] + @as(u32, @intCast(k));
        }
    }
    names_index.append(alloc, 0) catch return error.ResourceException;
    var name_off: u32 = 0;
    for (dir_order.items, 0..) |ni, di| {
        const node = &nodes.items[ni];
        const self_entry: u32 = if (di == 0) 0 else record_of[ni];
        const parent_entry: u32 = if (di == 0) 0 else record_of[node.parent];
        directories.appendSlice(alloc, &.{ parent_entry, first_entry_of[di], self_entry }) catch return error.ResourceException;
        const s = node.first_child;
        const e = s + node.child_count;
        for (kids[s..e]) |ci| {
            const child = &nodes.items[ci];
            const record_index: u32 = record_of[ci];
            dir_entries.appendSlice(alloc, &.{ record_index, child.number }) catch return error.ResourceException;
            names_index.append(alloc, name_off) catch return error.ResourceException;
            name_off = std.math.add(u32, name_off, @intCast(child.name.len)) catch return error.UnsupportedException;
            names.appendSlice(alloc, child.name) catch return error.ResourceException;
        }
    }
    // Sentinel directory closes the last directory's entry range.
    directories.appendSlice(alloc, &.{ 0, @intCast(dir_entries.items.len / 2), 0 }) catch return error.ResourceException;
    names_index.append(alloc, name_off) catch return error.ResourceException;
    const modes = [_]u32{ 0o40755, 0o100644 };

    const chunks_at = root_bytes;
    const chunk_table_at = chunks_at + chunks.items.len;
    const directories_at = chunk_table_at + 4 * chunk_table.items.len;
    const inodes_at = directories_at + 4 * directories.items.len;
    const modes_at = inodes_at + 4 * inodes.items.len;
    const uids_at = modes_at + 4 * modes.len;
    const gids_at = uids_at + 4;
    const dir_entries_at = gids_at + 4;
    const names_at = dir_entries_at + 4 * dir_entries.items.len;
    const names_index_at = names_at + names.items.len;
    const blob_len = names_index_at + 4 * names_index.items.len;

    var blob_bytes: std.ArrayList(u8) = .empty;
    blob_bytes.resize(alloc, blob_len) catch return error.ResourceException;
    @memset(blob_bytes.items, 0);
    @memcpy(blob_bytes.items[chunks_at..][0..chunks.items.len], chunks.items);
    writeU32List(blob_bytes.items, chunk_table_at, chunk_table.items);
    writeU32List(blob_bytes.items, directories_at, directories.items);
    writeU32List(blob_bytes.items, inodes_at, inodes.items);
    writeU32List(blob_bytes.items, modes_at, &modes);
    std.mem.writeInt(u32, blob_bytes.items[uids_at..][0..4], 0, .little);
    std.mem.writeInt(u32, blob_bytes.items[gids_at..][0..4], 0, .little);
    writeU32List(blob_bytes.items, dir_entries_at, dir_entries.items);
    @memcpy(blob_bytes.items[names_at..][0..names.items.len], names.items);
    writeU32List(blob_bytes.items, names_index_at, names_index.items);

    var bw = BitWriter{ .bytes = blob_bytes.items };
    bw.write(@intCast(chunks.items.len / 12), 32);
    bw.write(chunks_at, 32);
    bw.write(@intCast(dir_order.items.len + 1), 32);
    bw.write(directories_at, 32);
    bw.write(@intCast(dir_count + file_order.items.len), 32);
    bw.write(inodes_at, 32);
    bw.write(@intCast(chunk_table.items.len), 32);
    bw.write(chunk_table_at, 32);
    bw.write(1, 32);
    bw.write(uids_at, 32);
    bw.write(1, 32);
    bw.write(gids_at, 32);
    bw.write(@intCast(modes.len), 32);
    bw.write(modes_at, 32);
    bw.write(0, 64); // timestamp_base
    bw.write(write_block_size, 32); // block_size
    bw.write(total_size, 64); // total_fs_size
    bw.write(1, 1); // dir_entries present
    bw.write(@intCast(dir_entries.items.len / 2), 32);
    bw.write(dir_entries_at, 32);
    bw.write(1, 1); // names present
    bw.write(names_at, 32);
    bw.write(names.items.len, 32);
    bw.write(@intCast(names_index.items.len), 32);
    bw.write(names_index_at, 32);
    if (bw.bit != root_bits) return error.DataException;

    var block_data: std.ArrayList(u8) = .empty;
    for (file_order.items) |ni| {
        block_data.appendSlice(alloc, nodes.items[ni].data) catch return error.ResourceException;
    }

    var schema_bytes: std.ArrayList(u8) = .empty;
    try writeSchema(&schema_bytes, alloc);

    const block_at: u64 = 0;
    const schema_at = block_at + section_header_size + block_data.items.len;
    const metadata_at = schema_at + section_header_size + schema_bytes.items.len;
    const index_at = metadata_at + section_header_size + blob_bytes.items.len;
    const index_count = 4;

    var sink: std.ArrayList(u8) = .empty;
    var head: [section_header_size]u8 = undefined;
    const sections = [_]struct { number: u32, stype: u16, payload: []const u8 }{
        .{ .number = 0, .stype = section_type_block, .payload = block_data.items },
        .{ .number = 1, .stype = section_type_schema, .payload = schema_bytes.items },
        .{ .number = 2, .stype = section_type_metadata, .payload = blob_bytes.items },
    };
    for (sections) |s| {
        sectionHeader(&head, s.number, s.stype, s.payload);
        sink.appendSlice(alloc, &head) catch return error.ResourceException;
        sink.appendSlice(alloc, s.payload) catch return error.ResourceException;
    }
    const kinds = [_]u16{ section_type_block, section_type_schema, section_type_metadata, section_type_index };
    const offs = [_]u64{ block_at, schema_at, metadata_at, index_at };
    for (0..index_count) |i| {
        var raw: [8]u8 = undefined;
        std.mem.writeInt(u64, &raw, (@as(u64, kinds[i]) << 48) | (offs[i] & section_offset_mask), .little);
        sink.appendSlice(alloc, &raw) catch return error.ResourceException;
    }
    const index_len = 8 * index_count;
    sectionHeader(&head, 3, section_type_index, sink.items[sink.items.len - index_len ..]);
    sink.insertSlice(alloc, sink.items.len - index_len, &head) catch return error.ResourceException;
    var tail: [8]u8 = undefined;
    std.mem.writeInt(u64, &tail, (@as(u64, section_type_index) << 48) | (index_at & section_offset_mask), .little);
    sink.appendSlice(alloc, &tail) catch return error.ResourceException;

    if (output.len < sink.items.len) return error.CapacityException;
    @memcpy(output[0..sink.items.len], sink.items);
    return sink.items.len;
}

// The schema is data-independent and measured into a stack buffer.
pub fn archiveSize(entries: []const Entry) Exception!u64 {
    if (entries.len == 0 or entries.len > 4096) return error.UnsupportedException;
    var stack: [64 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack);
    const alloc = fba.allocator();
    var nodes: std.ArrayList(DwNode) = .empty;
    nodes.append(alloc, .{ .kind = .dir, .name = "", .parent = 0 }) catch return error.ResourceException;
    for (entries) |entry| {
        try dwValidate(entry.name);
        if (entry.data.len > write_block_size) return error.UnsupportedException;
        var parent: u32 = 0;
        var it = std.mem.splitScalar(u8, entry.name, '/');
        var comp = it.next().?;
        while (it.next()) |next| {
            parent = try dwFindOrCreateDir(&nodes, alloc, parent, comp);
            comp = next;
        }
        nodes.append(alloc, .{ .kind = .file, .name = comp, .parent = parent, .data = entry.data }) catch return error.ResourceException;
        nodes.items[parent].child_count += 1;
    }
    if (nodes.items.len > max_tree_nodes) return error.UnsupportedException;
    var dirs: u64 = 0;
    var files: u64 = 0;
    var names_len: u64 = 0;
    var data_len: u64 = 0;
    for (nodes.items) |node| {
        names_len = try bounds.addU64(names_len, node.name.len);
        if (node.kind == .dir) {
            dirs += 1;
        } else {
            files += 1;
            data_len = try bounds.addU64(data_len, node.data.len);
        }
    }
    if (data_len > write_data_cap) return error.UnsupportedException;
    const records: u64 = files + dirs; // root self + every child record
    var schema_buf: [2048]u8 = undefined;
    var sfba = std.heap.FixedBufferAllocator.init(&schema_buf);
    var schema_bytes: std.ArrayList(u8) = .empty;
    try writeSchema(&schema_bytes, sfba.allocator());
    const blob_len: u64 = root_bytes + 12 * files + 4 * (files + 1) + 12 * (dirs + 1) + 24 * (dirs + files) + 8 + 4 + 4 + 8 * records + names_len + 4 * (records + 1);
    return 4 * section_header_size + data_len + schema_bytes.items.len + blob_len + 8 * 4 + 8;
}

const mkdwarfs_fixture = [_]u8{
    0x44, 0x57, 0x41, 0x52, 0x46, 0x53, 0x02, 0x05, 0x4d, 0x4d, 0xd4, 0x9e, 0x53, 0x23, 0xe5, 0xfb,
    0x96, 0x7c, 0x91, 0xf5, 0x2d, 0x71, 0xa2, 0xa7, 0xae, 0xba, 0xf8, 0x34, 0x65, 0xe0, 0xf3, 0x2c,
    0x73, 0x6f, 0x09, 0xd5, 0x08, 0x44, 0x7d, 0xd9, 0x97, 0x1a, 0x48, 0x86, 0xa1, 0x07, 0x75, 0xd3,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x64, 0x77, 0x61, 0x72, 0x66, 0x73, 0x0a, 0x41, 0x42, 0x43,
    0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x41, 0x42, 0x43, 0x44, 0x57, 0x41, 0x52, 0x46, 0x53, 0x02,
    0x05, 0x15, 0xd6, 0xcc, 0xff, 0xa5, 0xe6, 0x50, 0xff, 0x2c, 0x58, 0xff, 0x10, 0x11, 0x42, 0x58,
    0x65, 0x35, 0x85, 0x3a, 0xff, 0x2d, 0xc5, 0x52, 0xb5, 0xf4, 0x51, 0xf9, 0x1f, 0xc3, 0xd0, 0x4e,
    0x2d, 0x99, 0x96, 0x64, 0xcf, 0x5b, 0x65, 0x21, 0xc3, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x02,
    0x00, 0x7e, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0xb5, 0x2f, 0xfd, 0x60, 0x76, 0x02,
    0xa5, 0x0b, 0x00, 0x86, 0xd2, 0x3c, 0x2c, 0x70, 0x6d, 0x1a, 0x03, 0xfc, 0xe3, 0x59, 0xc5, 0x91,
    0x8b, 0x5c, 0x55, 0x55, 0x25, 0x03, 0xe3, 0xaa, 0xaa, 0xa2, 0x1f, 0x08, 0x71, 0x00, 0x02, 0x21,
    0x02, 0x12, 0xde, 0x85, 0xe6, 0x4d, 0x01, 0x80, 0xa8, 0x9f, 0x24, 0xd7, 0x16, 0xde, 0x4e, 0x4c,
    0xc8, 0xde, 0x32, 0x31, 0x00, 0x35, 0x00, 0x2c, 0x00, 0xe1, 0x61, 0x33, 0x14, 0xb8, 0xf9, 0xf6,
    0x75, 0x05, 0x7a, 0xed, 0x38, 0x5a, 0x29, 0x17, 0xd8, 0xe8, 0x0c, 0xec, 0x19, 0x1d, 0xdb, 0xeb,
    0x9d, 0x7a, 0x2e, 0x90, 0xd3, 0x00, 0xd9, 0xee, 0xd8, 0x98, 0x87, 0x82, 0x35, 0xd3, 0x30, 0x8c,
    0xee, 0x7e, 0x0b, 0x06, 0x5e, 0x6f, 0x3d, 0x22, 0x48, 0x08, 0x9b, 0xad, 0x19, 0x03, 0x77, 0xa9,
    0xac, 0xa5, 0x9e, 0x55, 0x26, 0x0c, 0x8a, 0xb7, 0xe4, 0xc9, 0xc7, 0xc9, 0x42, 0x2e, 0x09, 0x07,
    0x09, 0x2d, 0x0f, 0xf2, 0x2b, 0x05, 0xef, 0x52, 0xb0, 0x40, 0x36, 0x3a, 0x07, 0xa3, 0x41, 0x19,
    0xe2, 0x58, 0x36, 0xce, 0xba, 0x54, 0x5c, 0xaa, 0x28, 0x13, 0x95, 0xf0, 0x60, 0xa8, 0x88, 0xa6,
    0x15, 0x27, 0x76, 0x96, 0xde, 0xc3, 0x9d, 0xa2, 0x13, 0x23, 0xf6, 0x73, 0xf8, 0xb7, 0x9a, 0x11,
    0x77, 0x8b, 0xb9, 0x5e, 0x37, 0xf2, 0x37, 0xb7, 0x8b, 0x5f, 0x5b, 0xf0, 0xee, 0x6c, 0x07, 0x6f,
    0x6b, 0x1e, 0x78, 0x8d, 0x7e, 0x78, 0x9d, 0x0d, 0x27, 0x73, 0x0d, 0x4b, 0xbd, 0xce, 0xbb, 0xdf,
    0x5e, 0xa0, 0x39, 0x53, 0x96, 0xb6, 0x20, 0x4b, 0x59, 0x5f, 0x7e, 0x2c, 0x5d, 0x6d, 0xb9, 0x5c,
    0x4a, 0x9a, 0x32, 0xb9, 0x34, 0xf4, 0x63, 0xc7, 0x4e, 0xd5, 0xe5, 0x8d, 0x9d, 0xa9, 0x71, 0x27,
    0x6a, 0xc7, 0xe2, 0xce, 0xd3, 0xe3, 0x8a, 0x9d, 0x01, 0x65, 0xa8, 0x11, 0x30, 0x53, 0x29, 0x2a,
    0x29, 0x14, 0xb6, 0xd6, 0x40, 0x25, 0xc8, 0x70, 0x73, 0x71, 0x9d, 0xf5, 0x26, 0x28, 0x58, 0xaa,
    0x3b, 0x6f, 0x48, 0x6d, 0x10, 0x7c, 0xbb, 0x04, 0x21, 0x07, 0x00, 0x45, 0x27, 0x22, 0xc1, 0xcb,
    0x3a, 0xc1, 0xaf, 0x57, 0x7b, 0x81, 0xf1, 0x04, 0xd5, 0x58, 0x3f, 0x71, 0x47, 0xb9, 0x06, 0x37,
    0xa8, 0x9f, 0x9a, 0xdc, 0xf2, 0x01, 0xbb, 0x36, 0xee, 0xe1, 0xdd, 0x0a, 0x3f, 0xdc, 0x7d, 0xb7,
    0xa2, 0xa4, 0x24, 0xd2, 0x7c, 0xd5, 0x3c, 0x0c, 0x1a, 0x8e, 0x01, 0x8c, 0x1e, 0x1d, 0xa1, 0x15,
    0x7f, 0xb0, 0x75, 0x34, 0x3a, 0x75, 0xe8, 0x20, 0x73, 0x45, 0x61, 0xac, 0x5d, 0x07, 0x22, 0x7a,
    0xee, 0x88, 0x5f, 0xcb, 0x2f, 0x86, 0xa4, 0x5e, 0xb4, 0xa5, 0xae, 0x96, 0xc0, 0xb7, 0x74, 0x20,
    0x82, 0xc1, 0xab, 0xbd, 0x07, 0xfb, 0x03, 0x44, 0x57, 0x41, 0x52, 0x46, 0x53, 0x02, 0x05, 0x4e,
    0x6f, 0x12, 0x3b, 0x66, 0x6c, 0x60, 0x01, 0x41, 0x09, 0xf6, 0x17, 0xb2, 0x5c, 0xd1, 0xe7, 0x33,
    0x95, 0x09, 0x32, 0x76, 0xb0, 0x95, 0xcd, 0x27, 0x8c, 0x10, 0xbc, 0x0d, 0xfd, 0x56, 0x6e, 0x8f,
    0x10, 0x24, 0x7c, 0x40, 0x54, 0x70, 0x45, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x53,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6a, 0xf9, 0x7d, 0xff, 0x37, 0xb4, 0xd8, 0x83, 0x56,
    0x03, 0x00, 0x00, 0xcc, 0xff, 0xf2, 0x33, 0xae, 0xde, 0x83, 0x56, 0xc7, 0xe3, 0xc9, 0xbf, 0x03,
    0x02, 0xcd, 0xd0, 0x0d, 0x06, 0x24, 0xf5, 0x01, 0xed, 0x41, 0xa4, 0x81, 0x50, 0x01, 0x6c, 0x69,
    0x62, 0x64, 0x77, 0x61, 0x72, 0x66, 0x73, 0x20, 0x76, 0x30, 0x2e, 0x31, 0x31, 0x2e, 0x33, 0x64,
    0x61, 0x74, 0x61, 0x2e, 0x62, 0x69, 0x6e, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x2e, 0x74, 0x78, 0x74,
    0x00, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x57, 0x41, 0x52, 0x46, 0x53,
    0x02, 0x05, 0x22, 0xbb, 0xc4, 0xb5, 0x2e, 0xf8, 0xc7, 0xfa, 0x65, 0xe7, 0xc7, 0x3a, 0x4c, 0x52,
    0x85, 0xd6, 0x08, 0x87, 0xf9, 0xa6, 0xc1, 0xff, 0xb0, 0x80, 0xe6, 0xb4, 0x1d, 0x47, 0x7a, 0xf2,
    0xd8, 0xa2, 0x43, 0xf9, 0x4a, 0x6a, 0xc2, 0x2d, 0xa8, 0x25, 0x03, 0x00, 0x00, 0x00, 0x0a, 0x00,
    0x02, 0x00, 0x42, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0xb5, 0x2f, 0xfd, 0x60, 0x68,
    0x00, 0xc5, 0x09, 0x00, 0x46, 0x52, 0x43, 0x2c, 0x60, 0x77, 0x03, 0x30, 0x0c, 0xc3, 0x30, 0x0c,
    0xf0, 0x06, 0x41, 0x80, 0xa8, 0xfe, 0x67, 0x49, 0x1a, 0x25, 0x41, 0x77, 0x44, 0x0b, 0xad, 0x0a,
    0x80, 0x12, 0x8c, 0x52, 0x67, 0x6c, 0x28, 0x66, 0x69, 0x53, 0x92, 0x93, 0x82, 0xb8, 0xf3, 0x2e,
    0x7f, 0xf4, 0xc7, 0x90, 0x39, 0x00, 0x36, 0x00, 0x36, 0x00, 0x18, 0xe3, 0xdc, 0x61, 0x9b, 0xbb,
    0xc7, 0xc9, 0xd4, 0xa4, 0x65, 0x93, 0xe7, 0x59, 0x69, 0x70, 0xa5, 0x2f, 0x52, 0x7a, 0x4d, 0x7a,
    0x98, 0x7c, 0xe5, 0xf5, 0xe5, 0xc0, 0x69, 0x9e, 0xcd, 0xd9, 0x62, 0xd5, 0x80, 0xbb, 0x54, 0x30,
    0x9a, 0x00, 0x17, 0xca, 0x70, 0x3e, 0xa3, 0x8d, 0x67, 0xc0, 0x25, 0x04, 0x8a, 0x85, 0x42, 0x53,
    0x38, 0x1c, 0x8c, 0xa1, 0xb9, 0xc1, 0x8b, 0xa6, 0xbd, 0x9e, 0xb8, 0xeb, 0x8a, 0xe8, 0x07, 0x39,
    0x59, 0x71, 0x0e, 0x37, 0xaa, 0xfb, 0xcf, 0xfd, 0x1c, 0xdc, 0xa0, 0x0b, 0xa6, 0x1a, 0x94, 0x67,
    0xee, 0x47, 0xcd, 0x5d, 0xa6, 0x61, 0xbf, 0x5c, 0x4c, 0xa7, 0xe2, 0x01, 0x61, 0x42, 0xa2, 0xfb,
    0xfd, 0xfe, 0xa2, 0xab, 0x47, 0xc6, 0xe7, 0x79, 0x01, 0x36, 0x57, 0xf4, 0xf7, 0x0e, 0x16, 0x60,
    0x0d, 0x83, 0xec, 0x35, 0x8b, 0x2d, 0xfe, 0xdf, 0xfe, 0xd4, 0xfd, 0x59, 0xbb, 0x59, 0xab, 0xc1,
    0x42, 0x56, 0xe2, 0xd6, 0x2b, 0xa0, 0x0b, 0xfd, 0xaf, 0x67, 0x89, 0xde, 0x02, 0xaf, 0x80, 0x54,
    0x79, 0xbf, 0xc9, 0xeb, 0x95, 0x78, 0x45, 0x92, 0xa7, 0xe0, 0x4d, 0x79, 0x5d, 0x8e, 0x01, 0x9a,
    0x26, 0xb1, 0x10, 0x9b, 0xab, 0x6b, 0xc3, 0x75, 0xfc, 0x7a, 0x64, 0xb1, 0xea, 0xa9, 0xcb, 0xf1,
    0x24, 0x7c, 0x76, 0x62, 0x21, 0x55, 0x97, 0x38, 0x7f, 0x2e, 0x72, 0xb3, 0x5d, 0x69, 0xda, 0x3c,
    0x8b, 0xed, 0x57, 0x3b, 0x7a, 0xb6, 0x7c, 0x58, 0x30, 0x77, 0xb8, 0x45, 0x4e, 0xa2, 0xdd, 0x83,
    0x08, 0x6c, 0x3b, 0x4a, 0x10, 0x08, 0x50, 0x67, 0x5d, 0x0d, 0x58, 0x03, 0x98, 0x27, 0x77, 0x25,
    0x78, 0xbd, 0xba, 0x6c, 0x45, 0x65, 0x10, 0xdb, 0x0a, 0x16, 0x58, 0x7c, 0x85, 0xd2, 0x7c, 0x19,
    0x94, 0xbf, 0x13, 0x7c, 0x2c, 0x0a, 0xe6, 0xdc, 0x44, 0xd4, 0x45, 0x01, 0x44, 0x57, 0x41, 0x52,
    0x46, 0x53, 0x02, 0x05, 0x3a, 0x1f, 0x10, 0xdd, 0x27, 0x21, 0x24, 0x47, 0x8a, 0x9b, 0x14, 0xae,
    0x5e, 0x4f, 0x4a, 0x88, 0x42, 0x0f, 0xd6, 0xa0, 0xce, 0x22, 0xff, 0x39, 0x09, 0xea, 0xa1, 0xbb,
    0x56, 0xe6, 0x1d, 0x97, 0x07, 0xce, 0xd1, 0xe1, 0xf5, 0x3e, 0x03, 0x51, 0x04, 0x00, 0x00, 0x00,
    0x09, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x59, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x17, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x08, 0x00, 0xaa, 0x02, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x2c, 0x04, 0x00, 0x00,
    0x00, 0x00, 0x09, 0x00,
};

test "dwarfs reads a mkdwarfs image" {
    const testing = std.testing;
    var scratch: [scratch_size]u8 = undefined;
    const count = try inspectCount(&mkdwarfs_fixture, &scratch);
    try testing.expectEqual(@as(u64, 2), count);
    var out: [16]u8 = undefined;
    const n = try decodeOrdinal(&mkdwarfs_fixture, 0, &out, &scratch);
    try testing.expectEqualSlices(u8, "ABCABCABCABC", out[0..n]);
    const n1 = try decodeOrdinal(&mkdwarfs_fixture, 1, &out, &scratch);
    try testing.expectEqualSlices(u8, "hello dwarfs\n", out[0..n1]);
}

test "dwarfs write roundtrips and mirrors the fixture shape" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "data.bin", .data = "ABCABCABCABC" },
        .{ .name = "hello.txt", .data = "hello dwarfs\n" },
    };
    var archive: [4096]u8 = undefined;
    var scratch: [scratch_size]u8 = undefined;
    const written = try encode(&entries, &archive, &scratch);
    try testing.expectEqual(@as(u64, 2), try inspectCount(archive[0..written], &scratch));
    var out: [16]u8 = undefined;
    const n = try decodeOrdinal(archive[0..written], 0, &out, &scratch);
    try testing.expectEqualSlices(u8, "ABCABCABCABC", out[0..n]);
    const n1 = try decodeOrdinal(archive[0..written], 1, &out, &scratch);
    try testing.expectEqualSlices(u8, "hello dwarfs\n", out[0..n1]);
}

test "dwarfs write roundtrips nested directories" {
    const testing = std.testing;
    const entries = [_]Entry{
        .{ .name = "a/b/deep.txt", .data = "nested payload" },
        .{ .name = "a/sib.txt", .data = "sibling" },
        .{ .name = "top.txt", .data = "root file" },
    };
    var archive: [8192]u8 = undefined;
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
