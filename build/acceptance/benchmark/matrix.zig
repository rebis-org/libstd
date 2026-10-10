const std = @import("std");

// Kind uses the released profile stem (seven_zip); Cmd mirrors the
// reference binary name (7zz); Lib mirrors the bridge module name.
pub const Kind = enum { gzip, bzip2, lzma, lzma2, lzma_file, xz, zstd, tar, zip, seven_zip, rar, zlib, lz4 };
pub const Cmd = enum { sevenzz, zstd, xz, bzip2, gzip, tar, ziptool, unrar, lzma, lz4 };
pub const Lib = enum { sevenzip, zstd, bzip2, xz, lzma7z, libzip, unrar, fast_lzma2, zlib, lz4 };

pub const Param = struct { family: u16, ordinal: u32, value: u64 };
pub const Tuning = struct {
    name: []const u8,
    params: []const Param,
    ref_params: []const u8 = "",
    cmd_args: []const []const u8 = &.{},
    lib_level: ?i32 = null,
    bypass: bool = false,
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

// Rows derive from descriptors, so removing one removes its rows with no central edits.
const generated = @import("components");

fn enumFor(comptime T: type, comptime what: []const u8, comptime name: []const u8) T {
    return std.meta.stringToEnum(T, name) orelse @compileError("unknown benchmark " ++ what ++ ": " ++ name ++ ".");
}

fn kindFor(comptime name: []const u8) Kind {
    if (std.mem.eql(u8, name, "7z")) return .seven_zip;
    return enumFor(Kind, "kind", name);
}

fn cmdFor(comptime name: []const u8) Cmd {
    return enumFor(Cmd, "cmd", name);
}

fn libFor(comptime name: []const u8) Lib {
    return enumFor(Lib, "lib", name);
}

const derived_bases = blk: {
    @setEvalBranchQuota(100_000);
    var list: []const Base = &.{};
    for (generated.benchmarks) |benchmark| {
        const tuning_list: []const Tuning = blk2: {
            var tunings: []const Tuning = &.{};
            for (benchmark.tunings) |raw_tuning| {
                const param_list: []const Param = blk3: {
                    var params: []const Param = &.{};
                    for (raw_tuning.params) |param| {
                        params = params ++ &[_]Param{.{ .family = param.family, .ordinal = param.ordinal, .value = param.value }};
                    }
                    break :blk3 params;
                };
                tunings = tunings ++ &[_]Tuning{.{ .name = raw_tuning.name, .params = param_list, .ref_params = raw_tuning.ref_params, .cmd_args = raw_tuning.cmd_args, .lib_level = raw_tuning.lib_level, .bypass = raw_tuning.bypass }};
            }
            break :blk2 tunings;
        };
        list = list ++ &[_]Base{.{ .name = benchmark.row, .kind = kindFor(benchmark.kind), .ext = benchmark.ext, .cmd = if (benchmark.cmd) |value| cmdFor(value) else null, .lib = if (benchmark.lib) |value| libFor(value) else null, .bin = if (benchmark.bin) |value| cmdFor(value) else null, .fmt = benchmark.fmt, .store = benchmark.store, .archive = benchmark.archive, .method = benchmark.method, .decode_only = benchmark.decode_only, .ref_params = benchmark.ref_params, .tunings = tuning_list }};
    }
    break :blk list;
};

pub const bases = derived_bases;

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
    bypass: bool = false,
};

const row_count = blk: {
    var count: usize = 0;
    for (bases) |base| count += base.tunings.len;
    break :blk count;
};

const row_array = blk: {
    @setEvalBranchQuota(100_000);
    var list: [row_count]Row = undefined;
    var index: usize = 0;
    for (bases) |base| {
        for (base.tunings) |tuning| {
            const row_type: []const u8 = if (base.decode_only)
                "decode-only"
            else if (base.archive and base.method)
                "archive-method"
            else if (base.archive)
                "archive-store"
            else
                "stream";
            list[index] = .{
                .name = if (tuning.name.len == 0) base.name else base.name ++ "-" ++ tuning.name,
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
                .params = tuning.params,
                .ref_params = if (tuning.ref_params.len != 0) tuning.ref_params else base.ref_params,
                .row_type = row_type,
                .cmd_args = tuning.cmd_args,
                .lib_level = tuning.lib_level,
                .bypass = tuning.bypass,
            };
            index += 1;
        }
    }
    break :blk list;
};

pub const rows: []const Row = &row_array;
