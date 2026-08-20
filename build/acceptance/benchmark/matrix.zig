const std = @import("std");

const harness = @import("harness");

pub const Kind = enum { gzip, bzip2, lzma, lzma2, lzma_file, xz, zstd, tar, zip, seven_zip, rar };
pub const Cmd = enum { sevenzz, zstd, xz, bzip2, gzip, tar, ziptool, unrar, lzma };
pub const Lib = enum { sevenzip, zstd, bzip2, xz, lzma7z, libzip, unrar, fast_lzma2 };

pub const Param = struct { family: u16, ordinal: u32, value: u64 };
pub const Tuning = struct {
    name: []const u8,
    params: []const Param,
    ref_params: []const u8 = "",
    cmd_args: []const []const u8 = &.{},
    lib_level: ?i32 = null,
};

const p = struct {
    fn scalar(family: u16, ordinal: u32, value: u64) Param {
        return .{ .family = family, .ordinal = ordinal, .value = value };
    }
    fn lzma(ordinal: u32, value: u64) Param {
        return scalar(harness.param_family_lzma, ordinal, value);
    }
    fn zstd(ordinal: u32, value: u64) Param {
        return scalar(harness.param_family_zstd, ordinal, value);
    }
    fn deflate(ordinal: u32, value: u64) Param {
        return scalar(harness.param_family_deflate, ordinal, value);
    }
};

pub const tuning = struct {
    pub const none = Tuning{ .name = "", .params = &.{} };
    pub const lzma_dict = Tuning{ .name = "", .params = &.{ p.lzma(harness.lzma_dictionary, 1 << 23), p.lzma(harness.lzma_match_finder_depth, 48) }, .ref_params = "lzma preset 6, dict 8 MiB, depth 48" };
    pub const lzma_bt = Tuning{ .name = "bt", .params = &.{ p.lzma(harness.lzma_dictionary, 1 << 23), p.lzma(harness.lzma_match_finder, 1), p.lzma(harness.lzma_match_finder_depth, 48) }, .ref_params = "lzma preset 6, bt4, depth 48" };
    pub const lzma_bt_lazy = Tuning{ .name = "bt-lazy", .params = &.{ p.lzma(harness.lzma_dictionary, 1 << 23), p.lzma(harness.lzma_match_finder, 1), p.lzma(harness.lzma_lazy, 1), p.lzma(harness.lzma_match_finder_depth, 48) }, .ref_params = "lzma preset 6, bt4 lazy, depth 48" };
    pub const lzma2_dict = Tuning{ .name = "", .params = &.{ p.lzma(harness.lzma_dictionary, 1 << 23), p.lzma(harness.lzma_match_finder_depth, 48) }, .ref_params = "fast-lzma2 level 9" };
    pub const zstd_window = Tuning{ .name = "", .params = &.{ p.zstd(harness.zstd_window, 1 << 22), p.zstd(harness.zstd_hash_bits, 17), p.zstd(harness.zstd_double_hash, 1) }, .ref_params = "zstd level 3, window 4 MiB, dfast", .cmd_args = &.{"--long=22"} };
    pub const zstd_lazy = Tuning{ .name = "lazy", .params = &.{ p.zstd(harness.zstd_window, 1 << 20), p.zstd(harness.zstd_row_match, 1) }, .ref_params = "zstd --lazy, row matchfinder", .cmd_args = &.{"--long=20"} };
    pub const zstd_fast = Tuning{ .name = "fast", .params = &.{ p.zstd(harness.zstd_window, 1 << 20), p.zstd(harness.zstd_skip_interior_insert, 1) }, .ref_params = "zstd --fast=1", .cmd_args = &.{"--fast=1"}, .lib_level = -1 };
    pub const zstd_dfast = Tuning{ .name = "dfast", .params = &.{ p.zstd(harness.zstd_window, 1 << 21), p.zstd(harness.zstd_double_hash, 1) }, .ref_params = "zstd dfast", .cmd_args = &.{"--long=21"} };
    pub const deflate_high = Tuning{ .name = "high", .params = &.{
        p.deflate(harness.deflate_good, 16),
        p.deflate(harness.deflate_nice, 258),
        p.deflate(harness.deflate_lazy, 48),
        p.deflate(harness.deflate_chain, 32),
        p.deflate(harness.deflate_optimal, 1),
    }, .ref_params = "gzip -6 high-compression" };
};

pub const Base = struct {
    name: []const u8,
    kind: Kind,
    ext: []const u8,
    cmd: ?Cmd = null,
    lib: ?Lib = null,
    tunings: []const Tuning,
    bin: ?Cmd = null,
    fmt: u8 = 0,
    store: bool = false,
    archive: bool = false,
    method: bool = false,
    decode_only: bool = false,
    ref_params: []const u8 = "",
};

pub const bases = [_]Base{
    .{ .name = "gzip", .kind = .gzip, .ext = "gz", .cmd = .gzip, .lib = .sevenzip, .fmt = 0xef, .tunings = &.{ tuning.none, tuning.deflate_high }, .ref_params = "gzip -6" },
    .{ .name = "bzip2", .kind = .bzip2, .ext = "bz2", .cmd = .bzip2, .lib = .bzip2, .tunings = &.{tuning.none}, .ref_params = "bzip2 default (block 900k)" },
    .{ .name = "xz", .kind = .xz, .ext = "xz", .cmd = .xz, .lib = .xz, .tunings = &.{ tuning.lzma_dict, tuning.lzma_bt } },
    .{ .name = "lzma", .kind = .lzma, .ext = "lzma", .cmd = .lzma, .lib = .lzma7z, .fmt = 0x0a, .tunings = &.{ tuning.lzma_dict, tuning.lzma_bt, tuning.lzma_bt_lazy } },
    .{ .name = "lzma2", .kind = .lzma2, .ext = "lzma2", .cmd = null, .lib = .fast_lzma2, .tunings = &.{tuning.lzma2_dict} },
    .{ .name = "lzma_file", .kind = .lzma_file, .ext = "lzma", .cmd = .lzma, .bin = .sevenzz, .lib = .lzma7z, .fmt = 0x0a, .decode_only = true, .tunings = &.{tuning.none}, .ref_params = "decode-only" },
    .{ .name = "zstd", .kind = .zstd, .ext = "zst", .cmd = .zstd, .lib = .zstd, .tunings = &.{ tuning.zstd_window, tuning.zstd_lazy, tuning.zstd_fast, tuning.zstd_dfast } },
    .{ .name = "tar", .kind = .tar, .ext = "tar", .cmd = .tar, .archive = true, .tunings = &.{tuning.none}, .ref_params = "store" },
    .{ .name = "zip", .kind = .zip, .ext = "zip", .cmd = .ziptool, .lib = .libzip, .store = true, .archive = true, .method = true, .tunings = &.{tuning.none}, .ref_params = "store" },
    .{ .name = "7z", .kind = .seven_zip, .ext = "7z", .cmd = .sevenzz, .bin = .sevenzz, .lib = .sevenzip, .fmt = 7, .store = true, .archive = true, .method = true, .tunings = &.{tuning.none}, .ref_params = "store" },
    .{ .name = "rar", .kind = .rar, .ext = "rar", .cmd = .unrar, .bin = .unrar, .lib = .unrar, .archive = true, .decode_only = true, .tunings = &.{tuning.none}, .ref_params = "decode-only" },
};

pub const Row = struct {
    name: []const u8,
    kind: Kind,
    ext: []const u8,
    cmd: ?Cmd,
    bin: ?Cmd,
    lib: ?Lib,
    fmt: u8,
    store: bool,
    archive: bool,
    method: bool,
    decode_only: bool,
    params: []const Param,
    ref_params: []const u8,
    row_type: []const u8,
    cmd_args: []const []const u8,
    lib_level: ?i32,
};

const row_count = blk: {
    var n: usize = 0;
    for (bases) |base| n += base.tunings.len;
    break :blk n;
};

const row_array = blk: {
    var list: [row_count]Row = undefined;
    var i: usize = 0;
    for (bases) |base| {
        for (base.tunings) |t| {
            const row_type: []const u8 = if (base.decode_only)
                "decode-only"
            else if (base.archive and base.method)
                "archive-method"
            else if (base.archive)
                "archive-store"
            else
                "stream";
            list[i] = .{
                .name = if (t.name.len == 0) base.name else base.name ++ "-" ++ t.name,
                .kind = base.kind,
                .ext = base.ext,
                .cmd = base.cmd,
                .bin = base.bin,
                .lib = base.lib,
                .fmt = base.fmt,
                .store = base.store,
                .archive = base.archive,
                .method = base.method,
                .decode_only = base.decode_only,
                .params = t.params,
                .ref_params = if (t.ref_params.len != 0) t.ref_params else base.ref_params,
                .row_type = row_type,
                .cmd_args = t.cmd_args,
                .lib_level = t.lib_level,
            };
            i += 1;
        }
    }
    break :blk list;
};

pub const rows: []const Row = &row_array;
