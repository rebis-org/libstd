const std = @import("std");

pub const silesia_url = "https://sun.aei.polsl.pl/~sdeor/corpus/silesia.zip";
pub const silesia_files = [_][]const u8{ "dickens", "mozilla", "mr", "nci", "ooffice", "osdb", "reymont", "samba", "sao", "webster", "xml", "x-ray" };

pub const paths = struct {
    pub const corpus_dir = "zig-out/benchmark/corpus";
    pub const corpus_zip = corpus_dir ++ "/silesia.zip";
    pub const corpus = corpus_dir ++ "/silesia";
    pub const corpus_candidates = [_][]const u8{ corpus_dir ++ "/silesia", corpus_dir };
    pub const cmd = "zig-out/benchmark/bin";
    pub const bins = cmd ++ "/bins";
    pub const work = "zig-out/benchmark/cmd";
    pub const out_bin = work ++ "/out.bin";
    pub const report = "zig-out/benchmark/report.txt";
    pub const gate = "zig-out/benchmark/gate.txt";
    pub const debug_ours = "zig-out/benchmark/debug/ours.bin";
    pub const debug_input = "zig-out/benchmark/debug/input.bin";
};

pub const Env = struct {
    io: std.Io,
    init: std.process.Init,
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    corpus: []const u8,
    row: ?[]const u8 = null,
    file: ?[]const u8 = null,
    limit: usize = silesia_files.len,
    bound: bool = true,

    pub fn now(self: *const Env) u64 {
        return @intCast(std.Io.Clock.Timestamp.now(self.io, .awake).raw.nanoseconds);
    }

    pub fn makePath(self: *Env, comptime fmt: []const u8, args: anytype) ![]u8 {
        return std.fmt.allocPrint(self.allocator, fmt, args);
    }

    pub fn makePathZ(self: *Env, comptime fmt: []const u8, args: anytype) ![:0]u8 {
        return std.fmt.allocPrintSentinel(self.allocator, fmt, args, 0);
    }

    pub fn print(self: *Env, comptime fmt: []const u8, args: anytype) ![]u8 {
        return std.fmt.allocPrint(self.arena.allocator(), fmt, args);
    }

    pub fn exists(self: *const Env, path: []const u8) bool {
        std.Io.Dir.cwd().access(self.io, path, .{}) catch return false;
        return true;
    }

    pub fn existsPath(self: *Env, comptime fmt: []const u8, args: anytype) bool {
        const path = self.makePath(fmt, args) catch return false;
        defer self.allocator.free(path);
        return self.exists(path);
    }

    pub fn readFile(self: *Env, path: []const u8, max: u64) ![]u8 {
        return std.Io.Dir.cwd().readFileAlloc(self.io, path, self.allocator, .limited(max));
    }

    pub fn writeFile(self: *Env, path: []const u8, data: []const u8) !void {
        try std.Io.Dir.cwd().writeFile(self.io, .{ .sub_path = path, .data = data });
    }

    pub fn size(self: *Env, path: []const u8) !usize {
        return @intCast((try std.Io.Dir.cwd().statFile(self.io, path, .{})).size);
    }

    pub fn delete(self: *Env, path: []const u8) void {
        std.Io.Dir.cwd().deleteFile(self.io, path) catch {};
    }
};

pub fn parseRuns(maybe: ?[]const u8) usize {
    const v = maybe orelse return 1;
    return std.fmt.parseInt(usize, v, 10) catch 1;
}

pub const Gate = struct {
    enabled: bool = false,
    fatal: bool = false,
    speed_pct: f64 = 95.0,
    ratio_pct: f64 = 101.0,
};

pub fn parseFlag(maybe: ?[]const u8) bool {
    const v = maybe orelse return false;
    return !(v.len == 0 or std.mem.eql(u8, v, "0") or std.mem.eql(u8, v, "false") or std.mem.eql(u8, v, "no") or std.mem.eql(u8, v, "off"));
}

pub fn parseDefaultOn(maybe: ?[]const u8) bool {
    const v = maybe orelse return true;
    return parseFlag(v);
}

pub fn parsePercent(maybe: ?[]const u8, default: f64) f64 {
    const v = maybe orelse return default;
    return std.fmt.parseFloat(f64, v) catch default;
}

pub fn gate(environ_map: *const std.process.Environ.Map) Gate {
    return .{
        .enabled = parseFlag(environ_map.get("STDK_BENCH_GATE")),
        .fatal = parseFlag(environ_map.get("STDK_BENCH_GATE_FATAL")),
        .speed_pct = parsePercent(environ_map.get("STDK_BENCH_GATE_SPEED_PCT"), 95.0),
        .ratio_pct = parsePercent(environ_map.get("STDK_BENCH_GATE_RATIO_PCT"), 101.0),
    };
}
