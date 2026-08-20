const std = @import("std");

const run = @import("run");

const env_mod = @import("env.zig");
const matrix = @import("matrix.zig");
const metric = @import("metric.zig");

const Arg = union(enum) {
    lit: []const u8,
    bin,
    input,
    output,
    archive,
    size,
    store,
    lzma,
    extra,
    work,
    outfile,
};

const Spec = struct {
    out: Out,
    args: []const Arg,
    store: []const Arg = &.{},
    lzma: []const Arg = &.{},

    const Out = enum { stdout, file };
};

pub const Cmd = struct {
    exe: []const u8,
    encode: ?Spec = null,
    decode: ?Spec = null,
};

const cmds = struct {
    const sevenzz = Cmd{
        .exe = "7zz",
        .encode = .{ .out = .file, .args = &.{ .bin, .{ .lit = "a" }, .{ .lit = "-y" }, .{ .lit = "-bso0" }, .{ .lit = "-bsp0" }, .store, .{ .lit = "-t%" }, .output, .input }, .store = &.{.{ .lit = "-mx=0" }} },
        .decode = .{ .out = .stdout, .args = &.{ .bin, .{ .lit = "x" }, .{ .lit = "-so" }, .{ .lit = "-y" }, .{ .lit = "-bso0" }, .{ .lit = "-bsp0" }, .archive } },
    };
    const zstd = Cmd{
        .exe = "zstd",
        .encode = .{ .out = .stdout, .args = &.{ .bin, .{ .lit = "-q" }, .{ .lit = "-c" }, .extra, .input } },
        .decode = .{ .out = .stdout, .args = &.{ .bin, .{ .lit = "-q" }, .{ .lit = "-dc" }, .archive } },
    };
    const xz = Cmd{
        .exe = "xz",
        .encode = .{ .out = .stdout, .args = &.{ .bin, .{ .lit = "-q" }, .lzma, .{ .lit = "-c" }, .extra, .input }, .lzma = &.{.{ .lit = "--format=lzma" }} },
        .decode = .{ .out = .stdout, .args = &.{ .bin, .{ .lit = "-q" }, .{ .lit = "-dc" }, .archive } },
    };
    const bzip2 = Cmd{
        .exe = "bzip2",
        .encode = .{ .out = .stdout, .args = &.{ .bin, .{ .lit = "-c" }, .extra, .input } },
        .decode = .{ .out = .stdout, .args = &.{ .bin, .{ .lit = "-dc" }, .archive } },
    };
    const gzip = Cmd{
        .exe = "gzip",
        .encode = .{ .out = .stdout, .args = &.{ .bin, .{ .lit = "-c" }, .extra, .input } },
        .decode = .{ .out = .stdout, .args = &.{ .bin, .{ .lit = "-dc" }, .archive } },
    };
    const tar = Cmd{
        .exe = "tar",
        .encode = .{ .out = .file, .args = &.{ .bin, .{ .lit = "-cf" }, .output, .{ .lit = "-C" }, .work, .{ .lit = "input.bin" } } },
        .decode = .{ .out = .stdout, .args = &.{ .bin, .{ .lit = "-xOf" }, .archive, .{ .lit = "input.bin" } } },
    };
    const ziptool = Cmd{
        .exe = "ziptool",
        .encode = .{ .out = .file, .args = &.{ .bin, .{ .lit = "-n" }, .output, .{ .lit = "add_file" }, .{ .lit = "input.bin" }, .input, .{ .lit = "0" }, .size, .store }, .store = &.{ .{ .lit = "set_file_compression" }, .{ .lit = "0" }, .{ .lit = "store" }, .{ .lit = "0" } } },
        .decode = .{ .out = .stdout, .args = &.{ .bin, .archive, .{ .lit = "cat" }, .{ .lit = "0" } } },
    };
    const unrar = Cmd{
        .exe = "unrar",
        .decode = .{ .out = .stdout, .args = &.{ .bin, .{ .lit = "p" }, .{ .lit = "-inul" }, .archive } },
    };
    const lzma = Cmd{
        .exe = "lzma",
        .encode = .{ .out = .file, .args = &.{ .bin, .{ .lit = "e" }, .input, .output, .extra } },
        .decode = .{ .out = .file, .args = &.{ .bin, .{ .lit = "d" }, .archive, .outfile } },
    };
};

pub fn get(comptime id: matrix.Cmd) Cmd {
    return switch (id) {
        .sevenzz => cmds.sevenzz,
        .zstd => cmds.zstd,
        .xz => cmds.xz,
        .bzip2 => cmds.bzip2,
        .gzip => cmds.gzip,
        .tar => cmds.tar,
        .ziptool => cmds.ziptool,
        .unrar => cmds.unrar,
        .lzma => cmds.lzma,
    };
}

fn buildLen(comptime spec: []const Arg, comptime store: []const Arg, comptime lzma: []const Arg, extra: usize) usize {
    var n: usize = 0;
    for (spec) |arg| n += switch (arg) {
        .store => store.len,
        .lzma => lzma.len,
        .extra => extra,
        else => 1,
    };
    return n;
}

const max_extra_args = 4;
const max_args = blk: {
    var n: usize = 0;
    for (std.meta.fields(matrix.Cmd)) |field| {
        const cmd = get(@enumFromInt(field.value));
        if (cmd.encode) |spec| n = @max(n, buildLen(spec.args, spec.store, spec.lzma, 0));
        if (cmd.decode) |spec| n = @max(n, buildLen(spec.args, spec.store, spec.lzma, 0));
    }
    break :blk n + max_extra_args;
};

const Argv = struct {
    items: [max_args][]const u8 = undefined,
    len: usize = 0,
};

fn argv(
    env: *env_mod.Env,
    comptime spec: []const Arg,
    comptime store: []const Arg,
    comptime lzma: []const Arg,
    extra: []const []const u8,
    bin: []const u8,
    input: []const u8,
    output: []const u8,
    archive: []const u8,
    ext: []const u8,
    store_on: bool,
) !Argv {
    _ = env.arena.reset(.retain_capacity);
    var result = Argv{};
    var n: usize = 0;
    for (spec) |arg| switch (arg) {
        .lit => |s| {
            result.items[n] = if (std.mem.indexOfScalar(u8, s, '%')) |i| try env.print("{s}{s}{s}", .{ s[0..i], ext, s[i + 1 ..] }) else s;
            n += 1;
        },
        .bin => {
            result.items[n] = bin;
            n += 1;
        },
        .input => {
            result.items[n] = input;
            n += 1;
        },
        .output => {
            result.items[n] = output;
            n += 1;
        },
        .archive => {
            result.items[n] = archive;
            n += 1;
        },
        .work => {
            result.items[n] = env_mod.paths.work;
            n += 1;
        },
        .outfile => {
            result.items[n] = env_mod.paths.out_bin;
            n += 1;
        },
        .size => {
            result.items[n] = try env.print("{d}", .{try env.size(input)});
            n += 1;
        },
        .store => if (store_on) inline for (store) |s| {
            result.items[n] = s.lit;
            n += 1;
        },
        .lzma => if (std.mem.eql(u8, ext, "lzma")) inline for (lzma) |s| {
            result.items[n] = s.lit;
            n += 1;
        },
        .extra => for (extra) |s| {
            result.items[n] = s;
            n += 1;
        },
    };
    result.len = n;
    return result;
}

pub fn encode(env: *env_mod.Env, comptime cmd: Cmd, bin: []const u8, input: []const u8, output: []const u8, ext: []const u8, store: bool, extra: []const []const u8) !usize {
    const spec = cmd.encode orelse return error.Unsupported;
    const args = try argv(env, spec.args, spec.store, spec.lzma, extra, bin, input, output, "", ext, store);
    const stdout = try run.output(env.init, args.items[0..args.len]);
    defer env.allocator.free(stdout);
    if (spec.out == .stdout) try env.writeFile(output, stdout);
    return env.size(output);
}

pub fn decode(env: *env_mod.Env, comptime cmd: Cmd, bin: []const u8, archive: []const u8) ![]u8 {
    const spec = cmd.decode orelse return error.Unsupported;
    const args = try argv(env, spec.args, &.{}, &.{}, &.{}, bin, "", "", archive, "", false);
    const stdout = try run.output(env.init, args.items[0..args.len]);
    if (spec.out == .stdout) return stdout;
    env.allocator.free(stdout);
    const data = try env.readFile(env_mod.paths.out_bin, 1 << 31);
    env.delete(env_mod.paths.out_bin);
    return data;
}

pub fn measure(env: *env_mod.Env, comptime id: matrix.Cmd, bin: []const u8, input_path: []const u8, output_path: []const u8, ext: []const u8, store: bool, extra: []const []const u8, input: []const u8) metric.Metric {
    var m = metric.Metric{};
    const cmd = comptime get(id);
    const t0 = env.now();
    const encoded = encode(env, cmd, bin, input_path, output_path, ext, store, extra) catch {
        m.encode_ns = env.now() - t0;
        return m;
    };
    m.encode_ns = env.now() - t0;
    m.encoded = encoded;
    const t1 = env.now();
    const bytes = decode(env, cmd, bin, output_path) catch {
        m.decode_ns = env.now() - t1;
        return m;
    };
    defer env.allocator.free(bytes);
    m.decode_ns = env.now() - t1;
    m.ok = bytes.len == input.len and std.mem.eql(u8, bytes[0..input.len], input);
    return m;
}

pub fn decodeMeasure(env: *env_mod.Env, comptime id: matrix.Cmd, bin: []const u8, archive_path: []const u8, input: []const u8) metric.Metric {
    var m = metric.Metric{};
    const cmd = comptime get(id);
    const t1 = env.now();
    const bytes = decode(env, cmd, bin, archive_path) catch {
        m.decode_ns = env.now() - t1;
        return m;
    };
    defer env.allocator.free(bytes);
    m.decode_ns = env.now() - t1;
    m.ok = bytes.len == input.len and std.mem.eql(u8, bytes[0..input.len], input);
    return m;
}
