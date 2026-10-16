const std = @import("std");

const run = @import("run");

const env_mod = @import("env.zig");
const matrix = @import("matrix.zig");
const metric = @import("metric.zig");

const CommandArg = union(enum) {
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

const CommandSpec = struct {
    output: Output,
    args: []const CommandArg,
    store: []const CommandArg = &.{},
    lzma: []const CommandArg = &.{},

    const Output = enum { stdout, file };
};

pub const Cmd = struct {
    exe: []const u8,
    encode: ?CommandSpec = null,
    decode: ?CommandSpec = null,
};

const encode_qc: []const CommandArg = &.{ .bin, .{ .lit = "-q" }, .{ .lit = "-c" }, .extra, .input };
const decode_qdc: []const CommandArg = &.{ .bin, .{ .lit = "-q" }, .{ .lit = "-dc" }, .archive };
const encode_c: []const CommandArg = &.{ .bin, .{ .lit = "-c" }, .extra, .input };
const decode_dc: []const CommandArg = &.{ .bin, .{ .lit = "-dc" }, .archive };

const cmds = struct {
    const sevenzz = Cmd{
        .exe = "7zz",
        .encode = .{ .output = .file, .args = &.{ .bin, .{ .lit = "a" }, .{ .lit = "-y" }, .{ .lit = "-bso0" }, .{ .lit = "-bsp0" }, .store, .{ .lit = "-t%" }, .output, .input }, .store = &.{.{ .lit = "-mx=0" }} },
        .decode = .{ .output = .stdout, .args = &.{ .bin, .{ .lit = "x" }, .{ .lit = "-so" }, .{ .lit = "-y" }, .{ .lit = "-bso0" }, .{ .lit = "-bsp0" }, .archive } },
    };
    const zstd = Cmd{
        .exe = "zstd",
        .encode = .{ .output = .stdout, .args = encode_qc },
        .decode = .{ .output = .stdout, .args = decode_qdc },
    };
    const xz = Cmd{
        .exe = "xz",
        .encode = .{ .output = .stdout, .args = &.{ .bin, .{ .lit = "-q" }, .lzma, .{ .lit = "-c" }, .extra, .input }, .lzma = &.{.{ .lit = "--format=lzma" }} },
        .decode = .{ .output = .stdout, .args = decode_qdc },
    };
    const bzip2 = Cmd{
        .exe = "bzip2",
        .encode = .{ .output = .stdout, .args = encode_c },
        .decode = .{ .output = .stdout, .args = decode_dc },
    };
    const gzip = Cmd{
        .exe = "gzip",
        .encode = .{ .output = .stdout, .args = encode_c },
        .decode = .{ .output = .stdout, .args = decode_dc },
    };
    const tar = Cmd{
        .exe = "tar",
        .encode = .{ .output = .file, .args = &.{ .bin, .{ .lit = "-cf" }, .output, .{ .lit = "-C" }, .work, .{ .lit = "input.bin" } } },
        .decode = .{ .output = .stdout, .args = &.{ .bin, .{ .lit = "-xOf" }, .archive, .{ .lit = "input.bin" } } },
    };
    const ziptool = Cmd{
        .exe = "ziptool",
        .encode = .{ .output = .file, .args = &.{ .bin, .{ .lit = "-n" }, .output, .{ .lit = "add_file" }, .{ .lit = "input.bin" }, .input, .{ .lit = "0" }, .size, .store }, .store = &.{ .{ .lit = "set_file_compression" }, .{ .lit = "0" }, .{ .lit = "store" }, .{ .lit = "0" } } },
        .decode = .{ .output = .stdout, .args = &.{ .bin, .archive, .{ .lit = "cat" }, .{ .lit = "0" } } },
    };
    const unrar = Cmd{
        .exe = "unrar",
        .decode = .{ .output = .stdout, .args = &.{ .bin, .{ .lit = "p" }, .{ .lit = "-inul" }, .archive } },
    };
    const lzma = Cmd{
        .exe = "lzma",
        .encode = .{ .output = .file, .args = &.{ .bin, .{ .lit = "e" }, .input, .output, .extra } },
        .decode = .{ .output = .file, .args = &.{ .bin, .{ .lit = "d" }, .archive, .outfile } },
    };
    const lz4 = Cmd{
        .exe = "lz4",
        .encode = .{ .output = .stdout, .args = encode_qc },
        .decode = .{ .output = .stdout, .args = decode_qdc },
    };
    const brotli = Cmd{
        .exe = "brotli",
        .encode = .{ .output = .stdout, .args = &.{ .bin, .extra, .{ .lit = "-c" }, .input } },
        .decode = .{ .output = .stdout, .args = &.{ .bin, .{ .lit = "-d" }, .{ .lit = "-c" }, .archive } },
    };
};

pub fn getCommand(comptime id: matrix.Cmd) Cmd {
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
        .lz4 => cmds.lz4,
        .brotli => cmds.brotli,
    };
}

fn buildLen(comptime spec: []const CommandArg, comptime store: []const CommandArg, comptime lzma: []const CommandArg, extra: usize) usize {
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
    const cmd_info = @typeInfo(matrix.Cmd).@"enum";
    for (cmd_info.field_names, cmd_info.field_values) |_, field_value| {
        const cmd = getCommand(@fromBackingInt(@intCast(field_value)));
        if (cmd.encode) |spec| n = @max(n, buildLen(spec.args, spec.store, spec.lzma, 0));
        if (cmd.decode) |spec| n = @max(n, buildLen(spec.args, spec.store, spec.lzma, 0));
    }
    break :blk n + max_extra_args;
};

const ArgList = struct {
    items: [max_args][]const u8,
    len: usize = 0,
};

fn appendArg(result: *ArgList, n: *usize, item: []const u8) void {
    result.items[n.*] = item;
    n.* += 1;
}

fn buildArgv(
    env: *env_mod.Env,
    comptime spec: []const CommandArg,
    comptime store: []const CommandArg,
    comptime lzma: []const CommandArg,
    extra: []const []const u8,
    bin: []const u8,
    input: []const u8,
    output: []const u8,
    archive: []const u8,
    ext: []const u8,
    store_on: bool,
) !ArgList {
    _ = env.arena.reset(.retain_capacity);
    var result = ArgList{ .items = undefined };
    var n: usize = 0;
    for (spec) |arg| switch (arg) {
        .lit => |s| {
            appendArg(&result, &n, if (std.mem.findScalar(u8, s, '%')) |i| try env.format("{s}{s}{s}", .{ s[0..i], ext, s[i + 1 ..] }) else s);
        },
        .bin => appendArg(&result, &n, bin),
        .input => appendArg(&result, &n, input),
        .output => appendArg(&result, &n, output),
        .archive => appendArg(&result, &n, archive),
        .work => appendArg(&result, &n, env_mod.paths.work),
        .outfile => appendArg(&result, &n, env_mod.paths.out_bin),
        .size => appendArg(&result, &n, try env.format("{d}", .{try env.fileSize(input)})),
        .store => if (store_on) inline for (store) |s| {
            appendArg(&result, &n, s.lit);
        },
        .lzma => if (std.mem.eql(u8, ext, "lzma")) inline for (lzma) |s| {
            appendArg(&result, &n, s.lit);
        },
        .extra => for (extra) |s| {
            appendArg(&result, &n, s);
        },
    };
    result.len = n;
    return result;
}

pub fn encode(env: *env_mod.Env, comptime cmd: Cmd, bin: []const u8, input: []const u8, output: []const u8, ext: []const u8, store: bool, extra: []const []const u8) !usize {
    const spec = cmd.encode orelse return error.unsupported;
    const args = try buildArgv(env, spec.args, spec.store, spec.lzma, extra, bin, input, output, "", ext, store);
    const stdout = try run.output(env.init, args.items[0..args.len]);
    defer env.allocator.free(stdout);
    if (spec.output == .stdout) try env.writeFile(output, stdout);
    return env.fileSize(output);
}

pub fn decode(env: *env_mod.Env, comptime cmd: Cmd, bin: []const u8, archive: []const u8) ![]u8 {
    const spec = cmd.decode orelse return error.unsupported;
    const args = try buildArgv(env, spec.args, &.{}, &.{}, &.{}, bin, "", "", archive, "", false);
    const stdout = try run.output(env.init, args.items[0..args.len]);
    if (spec.output == .stdout) return stdout;
    env.allocator.free(stdout);
    const data = try env.readFile(env_mod.paths.out_bin, 1 << 31);
    env.delete(env_mod.paths.out_bin);
    return data;
}

fn timedDecode(env: *env_mod.Env, comptime cmd: Cmd, started: u64, bin: []const u8, archive: []const u8, input: []const u8, m: *metric.Metric) void {
    const bytes = decode(env, cmd, bin, archive) catch {
        m.decode_ns = env.nowNs() - started;
        return;
    };
    defer env.allocator.free(bytes);
    m.decode_ns = env.nowNs() - started;
    m.ok = metric.isDecodeOk(bytes.len, input, bytes);
}

pub fn measure(env: *env_mod.Env, comptime id: matrix.Cmd, bin: []const u8, input_path: []const u8, output_path: []const u8, ext: []const u8, store: bool, extra: []const []const u8, input: []const u8) metric.Metric {
    var m = metric.Metric{};
    const cmd = comptime getCommand(id);
    const t0 = env.nowNs();
    const encoded = encode(env, cmd, bin, input_path, output_path, ext, store, extra) catch {
        m.encode_ns = env.nowNs() - t0;
        return m;
    };
    m.encode_ns = env.nowNs() - t0;
    m.encoded = encoded;
    timedDecode(env, cmd, env.nowNs(), bin, output_path, input, &m);
    return m;
}

pub fn decodeMeasure(env: *env_mod.Env, comptime id: matrix.Cmd, bin: []const u8, archive_path: []const u8, input: []const u8) metric.Metric {
    var m = metric.Metric{};
    const cmd = comptime getCommand(id);
    timedDecode(env, cmd, env.nowNs(), bin, archive_path, input, &m);
    return m;
}
