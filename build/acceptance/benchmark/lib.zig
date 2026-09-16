const std = @import("std");

const env_mod = @import("env.zig");
const matrix = @import("matrix.zig");
const metric = @import("metric.zig");

extern fn ref_archive_create(format: u8, data: [*]const u8, size: usize, name: [*:0]const u8, store: c_int, output: [*]u8, capacity: usize, output_size: *usize) c_int;
extern fn ref_archive_extract(format: u8, data: [*]const u8, size: usize, output: [*]u8, capacity: usize, output_size: *usize) c_int;
extern fn ref_zip_create(data: [*]const u8, size: usize, name: [*:0]const u8, store: c_int, temp_path: [*:0]const u8, output: [*]u8, capacity: usize, output_size: *usize) c_int;
extern fn ref_zip_extract(data: [*]const u8, size: usize, output: [*]u8, capacity: usize, output_size: *usize) c_int;
extern fn ref_unrar_extract(data: [*]const u8, size: usize, temp_path: [*:0]const u8, destination_dir: [*:0]const u8, output: [*]u8, capacity: usize, output_size: *usize) c_int;
extern fn ZSTD_compress(destination: [*]u8, destination_capacity: usize, source: [*]const u8, source_size: usize, level: c_int) usize;
extern fn ZSTD_decompress(destination: [*]u8, destination_capacity: usize, source: [*]const u8, compressed_size: usize) usize;
extern fn ZSTD_isError(code: usize) c_uint;
extern fn BZ2_bzBuffToBuffCompress(destination: [*]u8, destLen: *u32, source: [*]const u8, sourceLen: u32, blockSize100k: c_int, verbosity: c_int, workFactor: c_int) c_int;
extern fn BZ2_bzBuffToBuffDecompress(destination: [*]u8, destLen: *u32, source: [*]const u8, sourceLen: u32, small: c_int, verbosity: c_int) c_int;
extern fn lzma_easy_buffer_encode(preset: u32, check: u32, allocator: ?*anyopaque, input: [*]const u8, in_size: usize, output: [*]u8, out_pos: *usize, output_size: usize) u32;
extern fn lzma_stream_buffer_decode(memlimit: ?*u64, flags: u32, allocator: ?*anyopaque, input: [*]const u8, in_pos: *usize, in_size: usize, output: [*]u8, out_pos: *usize, output_size: usize) u32;
extern fn FL2_compress(destination: [*]u8, destination_capacity: usize, source: [*]const u8, source_size: usize, compressionLevel: c_int) usize;
extern fn FL2_decompress(destination: [*]u8, destination_capacity: usize, source: [*]const u8, source_size: usize) usize;
extern fn FL2_isError(code: usize) c_uint;

pub const Console = struct { path: []const u8, encode_ns: u64 };

pub const Ref = struct {
    kind: matrix.Lib,
    fmt: u8 = 0,
    store: bool = false,
    console: ?Console = null,
    level: i32 = 0,
};

const Enc = struct { len: usize, ns: ?u64 = null };

const Spec = struct {
    encode: ?*const fn (env: *env_mod.Env, ref: Ref, input: []const u8, output: []u8) anyerror!Enc = null,
    decode: ?*const fn (env: *env_mod.Env, ref: Ref, data: []const u8, output: []u8) anyerror!usize = null,
};

const sevenzip = struct {
    fn encode(_: *env_mod.Env, ref: Ref, input: []const u8, output: []u8) anyerror!Enc {
        var len: usize = 0;
        if (ref_archive_create(ref.fmt, input.ptr, input.len, "input.bin", @intFromBool(ref.store), output.ptr, output.len, &len) != 0) return error.EncodeFailed;
        return .{ .len = len };
    }
    fn decode(_: *env_mod.Env, ref: Ref, data: []const u8, output: []u8) anyerror!usize {
        var len: usize = 0;
        if (ref_archive_extract(ref.fmt, data.ptr, data.len, output.ptr, output.len, &len) != 0) return error.DecodeFailed;
        return len;
    }
};

const lzma7z = struct {
    fn encode(env: *env_mod.Env, ref: Ref, input: []const u8, output: []u8) anyerror!Enc {
        var len: usize = 0;
        if (ref_archive_create(0x0a, input.ptr, input.len, "input.bin", 0, output.ptr, output.len, &len) != 0 or len == 0 or len > output.len) {
            const console = ref.console orelse return error.NoConsoleArchive;
            const bytes = try env.readFile(console.path, 1 << 31);
            defer env.allocator.free(bytes);
            if (bytes.len > output.len) return error.OutTooSmall;
            @memcpy(output[0..bytes.len], bytes);
            return .{ .len = bytes.len, .ns = console.encode_ns };
        }
        return .{ .len = len };
    }
    fn decode(_: *env_mod.Env, _: Ref, data: []const u8, output: []u8) anyerror!usize {
        var len: usize = 0;
        if (ref_archive_extract(0x0a, data.ptr, data.len, output.ptr, output.len, &len) != 0) return error.DecodeFailed;
        return len;
    }
};

const zstd = struct {
    fn encode(_: *env_mod.Env, ref: Ref, input: []const u8, output: []u8) anyerror!Enc {
        const len = ZSTD_compress(output.ptr, output.len, input.ptr, input.len, @intCast(ref.level));
        if (ZSTD_isError(len) != 0) return error.EncodeFailed;
        return .{ .len = len };
    }
    fn decode(_: *env_mod.Env, _: Ref, data: []const u8, output: []u8) anyerror!usize {
        const len = ZSTD_decompress(output.ptr, output.len, data.ptr, data.len);
        if (ZSTD_isError(len) != 0) return error.DecodeFailed;
        return len;
    }
};

const bzip2 = struct {
    fn encode(_: *env_mod.Env, ref: Ref, input: []const u8, output: []u8) anyerror!Enc {
        var len: u32 = @intCast(output.len);
        if (BZ2_bzBuffToBuffCompress(output.ptr, &len, input.ptr, @intCast(input.len), @intCast(ref.level), 0, 30) != 0) return error.EncodeFailed;
        return .{ .len = len };
    }
    fn decode(_: *env_mod.Env, _: Ref, data: []const u8, output: []u8) anyerror!usize {
        var len: u32 = @intCast(output.len);
        if (BZ2_bzBuffToBuffDecompress(output.ptr, &len, data.ptr, @intCast(data.len), 0, 0) != 0) return error.DecodeFailed;
        return len;
    }
};

const xz = struct {
    fn encode(_: *env_mod.Env, ref: Ref, input: []const u8, output: []u8) anyerror!Enc {
        var pos: usize = 0;
        if (lzma_easy_buffer_encode(@intCast(ref.level), 4, null, input.ptr, input.len, output.ptr, &pos, output.len) != 0) return error.EncodeFailed;
        return .{ .len = pos };
    }
    fn decode(_: *env_mod.Env, _: Ref, data: []const u8, output: []u8) anyerror!usize {
        var in_pos: usize = 0;
        var pos: usize = 0;
        var memlimit: u64 = 1 << 30;
        if (lzma_stream_buffer_decode(&memlimit, 0, null, data.ptr, &in_pos, data.len, output.ptr, &pos, output.len) != 0) return error.DecodeFailed;
        return pos;
    }
};

const fl2 = struct {
    fn encode(_: *env_mod.Env, ref: Ref, input: []const u8, output: []u8) anyerror!Enc {
        const len = FL2_compress(output.ptr, output.len, input.ptr, input.len, @intCast(ref.level));
        if (FL2_isError(len) != 0) return error.EncodeFailed;
        return .{ .len = len };
    }
    fn decode(_: *env_mod.Env, _: Ref, data: []const u8, output: []u8) anyerror!usize {
        const len = FL2_decompress(output.ptr, output.len, data.ptr, data.len);
        if (FL2_isError(len) != 0) return error.DecodeFailed;
        return len;
    }
};

const libzip = struct {
    fn encode(env: *env_mod.Env, ref: Ref, input: []const u8, output: []u8) anyerror!Enc {
        const temp = try env.makePathZ("{s}/ref-libzip.zip", .{env_mod.paths.work});
        defer env.allocator.free(temp);
        var len: usize = 0;
        if (ref_zip_create(input.ptr, input.len, "input.bin", @intFromBool(ref.store), temp.ptr, output.ptr, output.len, &len) != 0) return error.EncodeFailed;
        return .{ .len = len };
    }
    fn decode(_: *env_mod.Env, _: Ref, data: []const u8, output: []u8) anyerror!usize {
        var len: usize = 0;
        if (ref_zip_extract(data.ptr, data.len, output.ptr, output.len, &len) != 0) return error.DecodeFailed;
        return len;
    }
};

const unrar = struct {
    fn decode(env: *env_mod.Env, _: Ref, data: []const u8, output: []u8) anyerror!usize {
        const temp = try env.makePathZ("{s}/ref-unrar.temp", .{env_mod.paths.work});
        defer env.allocator.free(temp);
        const destination = try env.makePathZ("{s}", .{env_mod.paths.work});
        defer env.allocator.free(destination);
        var len: usize = 0;
        if (ref_unrar_extract(data.ptr, data.len, temp.ptr, destination.ptr, output.ptr, output.len, &len) != 0) return error.DecodeFailed;
        return len;
    }
};

fn get(kind: matrix.Lib) Spec {
    return switch (kind) {
        .sevenzip => .{ .encode = sevenzip.encode, .decode = sevenzip.decode },
        .zstd => .{ .encode = zstd.encode, .decode = zstd.decode },
        .bzip2 => .{ .encode = bzip2.encode, .decode = bzip2.decode },
        .xz => .{ .encode = xz.encode, .decode = xz.decode },
        .lzma7z => .{ .encode = lzma7z.encode, .decode = lzma7z.decode },
        .libzip => .{ .encode = libzip.encode, .decode = libzip.decode },
        .unrar => .{ .decode = unrar.decode },
        .fast_lzma2 => .{ .encode = fl2.encode, .decode = fl2.decode },
    };
}

pub fn refOf(row: matrix.Row) Ref {
    const level: i32 = row.lib_level orelse switch (row.lib.?) {
        .zstd => 3,
        .bzip2 => 9,
        .xz => 6,
        .fast_lzma2 => 9,
        else => 0,
    };
    return .{ .kind = row.lib.?, .fmt = row.fmt, .store = row.store, .level = level };
}

fn timedDecode(env: *env_mod.Env, f: *const fn (env: *env_mod.Env, ref: Ref, data: []const u8, output: []u8) anyerror!usize, ref: Ref, data: []const u8, expected: []const u8, decoded: []u8, m: *metric.Metric) void {
    const t1 = env.now();
    const len = f(env, ref, data, decoded) catch {
        m.decode_ns = env.now() - t1;
        return;
    };
    m.decode_ns = env.now() - t1;
    m.ok = len == expected.len and std.mem.eql(u8, decoded[0..expected.len], expected);
}

pub fn measure(env: *env_mod.Env, ref: Ref, input: []const u8, encoded: []u8, decoded: []u8) metric.Metric {
    var m = metric.Metric{};
    const spec = get(ref.kind);
    if (spec.encode) |f| {
        const t0 = env.now();
        const enc = f(env, ref, input, encoded) catch {
            m.encode_ns = env.now() - t0;
            return m;
        };
        m.encode_ns = enc.ns orelse env.now() - t0;
        m.encoded = enc.len;
        if (enc.len == 0 or enc.len > encoded.len) return m;
    }
    if (spec.decode) |f| {
        timedDecode(env, f, ref, encoded[0..m.encoded], input, decoded, &m);
    }
    return m;
}

pub fn decodeOnly(env: *env_mod.Env, ref: Ref, archive: []const u8, expected: []const u8, decoded: []u8) metric.Metric {
    var m = metric.Metric{};
    const f = get(ref.kind).decode orelse return m;
    timedDecode(env, f, ref, archive, expected, decoded, &m);
    return m;
}
