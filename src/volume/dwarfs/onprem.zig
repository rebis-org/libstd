const std = @import("std");

const bounds = @import("../../common/primitive/bounds.zig");
const failure_prim = @import("../../common/primitive/failure.zig");

const lz4_leaf = @import("../../leaf/lz4/onprem.zig");
const zstd_leaf = @import("../../leaf/zstd/onprem.zig");

const Failure = failure_prim.Failure;

// DwarFS v2 slice in the flat-file shape: one root directory of regular
// files. Fidelity target is mkdwarfs output, verified with dwarfsck.

pub const scratch_size: usize = 1 * 1024 * 1024;

const section_type_block: u16 = 0;
const section_type_schema: u16 = 7;
const section_type_metadata: u16 = 8;
const compression_none: u16 = 0;
const compression_zstd: u16 = 2;
const compression_lz4: u16 = 3;
const section_header_size: usize = 64;
const section_magic = "DWARFS";

// LZ4 magics are duplicated here so the format layer stays leaf-free.
const lz4_frame_magic: u32 = 0x184D2204;
const lz4_legacy_magic: u32 = 0x184C2102;

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

fn parseSections(archive: []const u8) Failure!Sections {
    if (archive.len < section_header_size) return error.DataFailure;
    if (!std.mem.eql(u8, archive[0..6], section_magic)) return error.DataFailure;
    var out: Sections = undefined;
    var have_blocks = false;
    var have_schema = false;
    var have_metadata = false;
    var at: u64 = 0;
    while (at + section_header_size <= archive.len) {
        const head = archive[at .. at + section_header_size];
        if (!std.mem.eql(u8, head[0..6], section_magic)) return error.DataFailure;
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
    if (!have_blocks or !have_schema or !have_metadata) return error.DataFailure;
    return out;
}

fn sectionPayload(archive: []const u8, at: u64, len: u64, compression: u16, arena: std.mem.Allocator) Failure![]const u8 {
    const raw = try bounds.slice(archive, at, len);
    switch (compression) {
        compression_none => return raw,
        compression_zstd => {
            const out = arena.alloc(u8, raw.len * 16 + (1 << 16)) catch return error.ResourceFailure;
            const history = arena.alloc(u8, zstd_history) catch return error.ResourceFailure;
            var reader = std.Io.Reader.fixed(raw);
            var writer = std.Io.Writer.fixed(out);
            _ = zstd_leaf.decodeStream(&reader, &writer, history, .{ .window_size = zstd_window }) catch return error.DataFailure;
            return out[0..writer.end];
        },
        compression_lz4 => {
            const out = arena.alloc(u8, raw.len * 16 + (1 << 16)) catch return error.ResourceFailure;
            var writer = std.Io.Writer.fixed(out);
            lz4_leaf.decodeToWriter(raw, &writer, out, .{}) catch return error.DataFailure;
            return out[0..writer.end];
        },
        else => return error.UnsupportedFailure,
    }
}

// Dwarfs thrift dialect: map size precedes the key/value type byte.
// Booleans ride inline in field headers.
const Compact = struct {
    data: []const u8,
    pos: usize = 0,
    partial: u64 = 0,

    fn take(c: *Compact) Failure!u8 {
        if (c.pos >= c.data.len) return error.DataFailure;
        const b = c.data[c.pos];
        c.pos += 1;
        return b;
    }

    fn varint(c: *Compact) Failure!u64 {
        var shift: u6 = 0;
        var result: u64 = 0;
        while (true) {
            const b = try c.take();
            if (shift > 63) return error.DataFailure;
            result |= @as(u64, b & 0x7f) << shift;
            if (b & 0x80 == 0) return result;
            shift += 7;
        }
    }

    fn zigzag(c: *Compact) Failure!i64 {
        const v = try c.varint();
        return @bitCast((v >> 1) ^ (0 -% (v & 1)));
    }

    fn listSize(c: *Compact, nibble: u8) Failure!usize {
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

    fn value(c: *Compact, arena: std.mem.Allocator, ttype: u8) Failure!Value {
        switch (ttype) {
            1, 2 => return .{ .boolean = ttype == 1 },
            3 => return .{ .int = try c.take() },
            4, 5, 6 => return .{ .int = @as(u64, @bitCast(try c.zigzag())) },
            8 => {
                const n = try castUsize(try c.varint());
                if (n > c.data.len - c.pos) return error.DataFailure;
                const s = c.data[c.pos .. c.pos + n];
                c.pos += n;
                return .{ .bytes = s };
            },
            9, 10 => {
                const b = try c.take();
                const n = try c.listSize(b >> 4);
                if (b & 0x0f == 0 or b & 0x0f == 1 or b & 0x0f == 2) return error.UnsupportedFailure;
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
            else => return error.UnsupportedFailure,
        }
    }

    fn values(c: *Compact, arena: std.mem.Allocator, ttype: u8, n: usize) Failure!struct { map: []MapEntry } {
        const entries = arena.alloc(MapEntry, n) catch return error.ResourceFailure;
        for (entries) |*e| {
            e.key = .{ .int = 0 };
            e.val = try c.value(arena, ttype);
        }
        return .{ .map = entries };
    }

    fn mapEntries(c: *Compact, arena: std.mem.Allocator, kt: u8, vt: u8, n: usize) Failure![]MapEntry {
        const entries = arena.alloc(MapEntry, n) catch return error.ResourceFailure;
        for (entries) |*e| {
            e.key = try c.value(arena, kt);
            e.val = try c.value(arena, vt);
        }
        return entries;
    }

    fn structure(c: *Compact, arena: std.mem.Allocator) Failure![]StructField {
        var last: i16 = 0;
        var fields: [128]StructField = undefined;
        var count: usize = 0;
        while (true) {
            const h = try c.take();
            if (h == 0) break;
            const t = h & 0x0f;
            if (t == 0) return error.DataFailure;
            const d = h >> 4;
            if (d != 0) {
                last += @intCast(d);
            } else {
                last = @intCast(try c.zigzag());
            }
            if (count >= fields.len) return error.UnsupportedFailure;
            fields[count] = .{ .id = last, .val = try c.value(arena, t) };
            count += 1;
        }
        const out = arena.alloc(StructField, count) catch return error.ResourceFailure;
        @memcpy(out, fields[0..count]);
        return out;
    }
};

fn castUsize(v: u64) Failure!usize {
    return std.math.cast(usize, v) orelse error.DataFailure;
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

fn parseSchema(raw: []const u8, arena: std.mem.Allocator) Failure!Schema {
    var c = Compact{ .data = raw };
    const root_val = try c.value(arena, 12);
    const layouts_val = structField(root_val.structure, 2) orelse return error.DataFailure;
    const root_id = structField(root_val.structure, 3) orelse return error.DataFailure;
    const layouts = arena.alloc(Layout, layouts_val.map.len) catch return error.ResourceFailure;
    for (layouts_val.map, 0..) |entry, i| {
        const ls = entry.val.structure;
        var layout = Layout{
            .size = @intCast((structField(ls, 1) orelse @as(Compact.Value, .{ .int = 0 })).int),
            .bits = @intCast((structField(ls, 2) orelse @as(Compact.Value, .{ .int = 0 })).int),
            .fields = &.{},
        };
        if (structField(ls, 3)) |fv| {
            const fs = arena.alloc(Field, fv.map.len) catch return error.ResourceFailure;
            for (fv.map, 0..) |fe, j| {
                const f2 = fe.val.structure;
                fs[j] = .{
                    .id = @intCast(fe.key.int),
                    .layout = @intCast((structField(f2, 1) orelse @as(Compact.Value, .{ .int = 0 })).int),
                    .offset = @as(i16, @truncate(@as(i64, @bitCast((structField(f2, 2) orelse @as(Compact.Value, .{ .int = 0 })).int)))),
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

    fn read(b: Bits, pos: usize, width: u16) Failure!u64 {
        if (width == 0) return 0;
        var v: u64 = 0;
        for (0..width) |i| {
            const at = pos + i;
            if ((at >> 3) >= b.data.len) return error.DataFailure;
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

    fn integral(d: *Decoder, lid: i16, pos: usize) Failure!u64 {
        return d.bits.read(pos, d.layouts[@intCast(lid)].bits);
    }

    fn u32At(d: *Decoder, lid: i16, pos: usize) Failure!u32 {
        return std.math.cast(u32, try d.integral(lid, pos)) orelse error.DataFailure;
    }

    // Vector headers: field 2 is the count, field 1 a blob-relative byte address.
    fn vectorHead(d: *Decoder, lid: i16, pos: usize) Failure!struct { count: usize, dist: usize, item: ?Field } {
        const l = d.layouts[@intCast(lid)];
        const cf = find(l, 2) orelse return error.DataFailure;
        const count = try castUsize(try d.integral(cf.layout, fpos(pos, cf.offset)));
        var dist: usize = 0;
        if (find(l, 1)) |df| dist = try castUsize(try d.integral(df.layout, fpos(pos, df.offset)));
        return .{ .count = count, .dist = dist, .item = find(l, 3) };
    }

    fn scalarVector(d: *Decoder, lid: i16, pos: usize) Failure![]u32 {
        const head = try d.vectorHead(lid, pos);
        const out = d.arena.alloc(u32, head.count) catch return error.ResourceFailure;
        if (head.item) |item| {
            const stride = d.layouts[@intCast(item.layout)].bits;
            const start = head.dist * 8;
            for (out, 0..) |*o, i| o.* = try d.u32At(item.layout, start + i * stride);
        } else {
            @memset(out, 0);
        }
        return out;
    }

    fn structFieldVector(d: *Decoder, lid: i16, pos: usize, field_id: i16) Failure![]u32 {
        const head = try d.vectorHead(lid, pos);
        const item = head.item orelse return error.DataFailure;
        const stride = d.layouts[@intCast(item.layout)].bits;
        const inner = d.layouts[@intCast(item.layout)];
        const inner_field = find(inner, field_id) orelse return error.DataFailure;
        const start = head.dist * 8;
        const out = d.arena.alloc(u32, head.count) catch return error.ResourceFailure;
        for (out, 0..) |*o, i| {
            o.* = try d.u32At(inner_field.layout, fpos(start + i * stride, inner_field.offset));
        }
        return out;
    }

    fn chunkVector(d: *Decoder, lid: i16, pos: usize) Failure![]Chunk {
        const head = try d.vectorHead(lid, pos);
        const item = head.item orelse return error.DataFailure;
        const stride = d.layouts[@intCast(item.layout)].bits;
        const start = head.dist * 8;
        const out = d.arena.alloc(Chunk, head.count) catch return error.ResourceFailure;
        for (out, 0..) |*o, i| {
            const at = start + i * stride;
            var chunk: Chunk = .{ .offset = 0, .size = 0 };
            if (find(d.layouts[@intCast(item.layout)], 2)) |f| chunk.offset = try d.u32At(f.layout, fpos(at, f.offset));
            if (find(d.layouts[@intCast(item.layout)], 3)) |f| chunk.size = try d.u32At(f.layout, fpos(at, f.offset));
            o.* = chunk;
        }
        return out;
    }

    fn dirEntryVector(d: *Decoder, lid: i16, pos: usize) Failure![]DirEntry {
        const head = try d.vectorHead(lid, pos);
        const item = head.item orelse return error.DataFailure;
        const stride = d.layouts[@intCast(item.layout)].bits;
        const start = head.dist * 8;
        const out = d.arena.alloc(DirEntry, head.count) catch return error.ResourceFailure;
        for (out, 0..) |*o, i| {
            const at = start + i * stride;
            var entry: DirEntry = .{ .name_index = 0, .inode_num = 0 };
            if (find(d.layouts[@intCast(item.layout)], 1)) |f| entry.name_index = try d.u32At(f.layout, fpos(at, f.offset));
            if (find(d.layouts[@intCast(item.layout)], 2)) |f| entry.inode_num = try d.u32At(f.layout, fpos(at, f.offset));
            o.* = entry;
        }
        return out;
    }

    fn frozenString(d: *Decoder, lid: i16, pos: usize) Failure![]const u8 {
        const l = d.layouts[@intCast(lid)];
        const df = find(l, 1) orelse return error.DataFailure;
        const cf = find(l, 2) orelse return error.DataFailure;
        const dist = try castUsize(try d.integral(df.layout, fpos(pos, df.offset)));
        const count = try castUsize(try d.integral(cf.layout, fpos(pos, cf.offset)));
        if (dist + count > d.bits.data.len) return error.DataFailure;
        return d.bits.data[dist .. dist + count];
    }

    fn presence(d: *Decoder, lid: i16, pos: usize) Failure!struct { present: bool, value_field: ?Field } {
        const l = d.layouts[@intCast(lid)];
        const pf = find(l, 1) orelse return error.DataFailure;
        const present = (try d.integral(pf.layout, fpos(pos, pf.offset))) != 0;
        return .{ .present = present, .value_field = find(l, 2) };
    }
};

fn decodeMetadata(meta_raw: []const u8, schema: Schema, arena: std.mem.Allocator) Failure!Metadata {
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
            6 => if ((try dec.vectorHead(f.layout, pos)).count > 0) return error.UnsupportedFailure,
            9 => md.modes = try dec.scalarVector(f.layout, pos),
            10 => if ((try dec.vectorHead(f.layout, pos)).count > 0) return error.UnsupportedFailure,
            15 => md.block_size = try dec.u32At(f.layout, pos),
            19 => {
                const p = try dec.presence(f.layout, pos);
                if (p.present) {
                    const vf = p.value_field orelse return error.DataFailure;
                    md.dir_entries = try dec.dirEntryVector(vf.layout, fpos(pos, vf.offset));
                }
            },
            20 => {
                const p = try dec.presence(f.layout, pos);
                if (p.present) {
                    const vf = p.value_field orelse continue;
                    if ((try dec.vectorHead(vf.layout, fpos(pos, vf.offset))).count > 0) return error.UnsupportedFailure;
                }
            },
            24 => {
                const p = try dec.presence(f.layout, pos);
                if (p.present) {
                    const vf = p.value_field orelse return error.DataFailure;
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
    resolve: struct { ordinal: u64, info: *EntryInfo, output: ?[]u8 },
};

fn runTarget(archive: []const u8, scratch: []u8, target: Target) Failure!u64 {
    if (scratch.len < scratch_size) return error.CapacityFailure;
    var fba = std.heap.FixedBufferAllocator.init(scratch);
    const arena = fba.allocator();
    const sections = try parseSections(archive);
    const schema_raw = try sectionPayload(archive, sections.schema_at, sections.schema_len, sections.schema_compression, arena);
    const schema = try parseSchema(schema_raw, arena);
    const meta_raw = try sectionPayload(archive, sections.metadata_at, sections.metadata_len, sections.metadata_compression, arena);
    const md = try decodeMetadata(meta_raw, schema, arena);
    if (md.block_size == 0 or md.names_index.len == 0) return error.DataFailure;
    const blocks = try sectionPayload(archive, sections.blocks_at, sections.blocks_len, sections.blocks_compression, arena);
    if (md.directories.len < 2) return error.DataFailure;
    const file_off: u32 = @intCast(md.directories.len - 1);
    var ordinal: u64 = 0;
    var e: usize = md.directories[0];
    const end: usize = md.directories[1];
    if (end < e or end > md.dir_entries.len) return error.DataFailure;
    while (e < end) : (e += 1) {
        const entry = md.dir_entries[e];
        if (entry.inode_num >= md.inodes.len) return error.DataFailure;
        const mode_index = md.inodes[entry.inode_num];
        if (mode_index >= md.modes.len) return error.DataFailure;
        if (md.modes[mode_index] & 0o170000 != 0o100000) return error.UnsupportedFailure;
        const idx: usize = entry.inode_num - file_off;
        if (idx + 1 >= md.chunk_table.len) return error.DataFailure;
        const c0 = md.chunk_table[idx];
        const c1 = md.chunk_table[idx + 1];
        if (c1 != c0 + 1) return error.UnsupportedFailure;
        if (c0 >= md.chunks.len) return error.DataFailure;
        const chunk = md.chunks[c0];
        switch (target) {
            .count => {},
            .resolve => |res| {
                if (ordinal == res.ordinal) {
                    res.info.size = chunk.size;
                    res.info.ordinal = ordinal;
                    if (res.output) |out| {
                        if (out.len < chunk.size) return error.CapacityFailure;
                        const data = try bounds.slice(blocks, chunk.offset, chunk.size);
                        @memcpy(out[0..chunk.size], data);
                    }
                    return ordinal;
                }
            },
        }
        ordinal += 1;
    }
    return switch (target) {
        .count => ordinal,
        .resolve => error.DataFailure,
    };
}

pub fn inspectCount(archive: []const u8, scratch: []u8) Failure!u64 {
    return runTarget(archive, scratch, .count);
}

pub fn inspectOrdinal(archive: []const u8, ordinal: u64, scratch: []u8) Failure!EntryInfo {
    var info: EntryInfo = undefined;
    _ = try runTarget(archive, scratch, .{ .resolve = .{ .ordinal = ordinal, .info = &info, .output = null } });
    return info;
}

pub fn decodeOrdinal(archive: []const u8, ordinal: u64, output: []u8, scratch: []u8) Failure!usize {
    var info: EntryInfo = undefined;
    _ = try runTarget(archive, scratch, .{ .resolve = .{ .ordinal = ordinal, .info = &info, .output = output } });
    return @intCast(info.size);
}

pub fn archiveSize(entries: []const Entry) Failure!u64 {
    _ = entries;
    return error.UnsupportedFailure;
}

pub fn encode(entries: []const Entry, output: []u8, scratch: []u8) Failure!usize {
    _ = entries;
    _ = output;
    _ = scratch;
    return error.UnsupportedFailure;
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
