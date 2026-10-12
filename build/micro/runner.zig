//! Time-budgeted runner borrowing four hendriknielaender/zBench designs (MIT): budget
//! calibration, percentiles, allocation counts, opt-in shuffling. Own code.

const std = @import("std");

const shuffling = @import("shuffling.zig");

pub const Config = struct {
    time_budget_ns: u64 = 500_000_000,
    max_iterations: usize = 100_000,
    shuffle: bool = false,
    shuffle_seed: u64 = 0x5eed,
};

pub const AllocReading = struct {
    count: usize = 0,
    live_bytes: usize = 0,
    peak_bytes: usize = 0,
};

pub const CountingAllocator = struct {
    underlying: std.mem.Allocator,
    count: usize = 0,
    live: usize = 0,
    peak: usize = 0,

    pub fn init(underlying: std.mem.Allocator) CountingAllocator {
        return .{ .underlying = underlying };
    }

    pub fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub fn reset(self: *CountingAllocator) void {
        self.count = 0;
        self.live = 0;
        self.peak = 0;
    }

    pub fn reading(self: *const CountingAllocator) AllocReading {
        return .{ .count = self.count, .live_bytes = self.live, .peak_bytes = self.peak };
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = allocFn,
        .resize = resizeFn,
        .remap = remapFn,
        .free = freeFn,
    };

    fn allocFn(self_ptr: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(self_ptr));
        const ptr = std.mem.Allocator.rawAlloc(self.underlying, len, alignment, ret_addr) orelse return null;
        self.count += 1;
        self.live += len;
        if (self.live > self.peak) self.peak = self.live;
        return ptr;
    }

    fn resizeFn(self_ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(self_ptr));
        if (!std.mem.Allocator.rawResize(self.underlying, memory, alignment, new_len, ret_addr)) return false;
        self.live = self.live - memory.len + new_len;
        if (self.live > self.peak) self.peak = self.live;
        return true;
    }

    fn remapFn(self_ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(self_ptr));
        const ptr = std.mem.Allocator.rawRemap(self.underlying, memory, alignment, new_len, ret_addr) orelse return null;
        self.live = self.live - memory.len + new_len;
        if (self.live > self.peak) self.peak = self.live;
        return ptr;
    }

    fn freeFn(self_ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(self_ptr));
        std.mem.Allocator.rawFree(self.underlying, memory, alignment, ret_addr);
        self.live -= memory.len;
    }
};

const Erased = struct {
    ctx: *anyopaque,
    invoke: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator) void,
};

pub const Definition = struct {
    name: []const u8,
    erased: Erased,
};

const Result = struct {
    runs: usize,
    timings: []u64,
    allocations: []AllocReading,
};

pub const Benchmark = struct {
    allocator: std.mem.Allocator,
    config: Config,
    defs: std.ArrayList(Definition) = .empty,

    pub fn init(allocator: std.mem.Allocator, config: Config) Benchmark {
        return .{ .allocator = allocator, .config = config };
    }

    pub fn deinit(self: *Benchmark) void {
        self.defs.deinit(self.allocator);
    }

    pub fn add(self: *Benchmark, name: []const u8, comptime func: *const fn (std.mem.Allocator) void) !void {
        const S = struct {
            fn invoke(_: *anyopaque, allocator: std.mem.Allocator) void {
                func(allocator);
            }
        };
        try self.defs.append(self.allocator, .{ .name = name, .erased = .{ .ctx = undefined, .invoke = S.invoke } });
    }

    // instance must be a pointer to a struct declaring
    // `pub fn run(self: @TypeOf(instance), allocator: std.mem.Allocator) void`.
    pub fn addParam(self: *Benchmark, name: []const u8, instance: anytype) !void {
        const P = @TypeOf(instance);
        const T = switch (@typeInfo(P)) {
            .pointer => |ptr| ptr.child,
            else => @compileError("instance must be a pointer to a struct with a run method"),
        };
        const run_fn: fn (P, std.mem.Allocator) void = T.run;
        const S = struct {
            fn invoke(ctx: *anyopaque, allocator: std.mem.Allocator) void {
                const ptr: P = @ptrCast(@alignCast(ctx));
                run_fn(ptr, allocator);
            }
        };
        try self.defs.append(self.allocator, .{ .name = name, .erased = .{ .ctx = @constCast(@as(*const anyopaque, instance)), .invoke = S.invoke } });
    }

    pub fn run(self: *Benchmark, io: std.Io) !void {
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        defer out.deinit();
        const w = &out.writer;

        var max_name_len: usize = "benchmark".len;
        for (self.defs.items) |def| max_name_len = @max(max_name_len, def.name.len);

        try w.print("micro: budget={d}ms max_iterations={d} allocator={s}\n", .{
            self.config.time_budget_ns / std.time.ns_per_ms,
            self.config.max_iterations,
            if (self.config.shuffle) "shuffling" else "counting",
        });
        try printName(w, "benchmark", max_name_len);
        try w.print(" {s:>8} {s:>12} {s:>12} {s:>12} {s:>12} {s:>12} {s:>12} {s:>8} {s:>10}\n", .{
            "runs", "avg ns", "sd ns", "min ns", "max ns", "p75 ns", "p99 ns", "allocs", "peak B",
        });

        for (self.defs.items) |*def| {
            const result = try self.runOne(io, def);
            defer self.allocator.free(result.timings);
            defer self.allocator.free(result.allocations);
            try printRow(w, max_name_len, def.name, result);
        }

        var list = out.toArrayList();
        defer list.deinit(self.allocator);
        try std.Io.File.stdout().writeStreamingAll(io, list.items);
    }

    fn runOne(self: *Benchmark, io: std.Io, def: *const Definition) !Result {
        var counting = CountingAllocator.init(self.allocator);
        var shuffler: ?shuffling.ShufflingAllocator = if (self.config.shuffle)
            shuffling.ShufflingAllocator.init(counting.allocator(), self.config.shuffle_seed)
        else
            null;
        defer if (shuffler) |*s| s.deinit();
        const bench_alloc = if (shuffler) |*s| s.allocator() else counting.allocator();

        // Calibration: single iterations until the budget is spent, then the
        // iteration count that a budget's worth of wall time should hold.
        var loops: u64 = 0;
        var elapsed: u64 = 0;
        while (elapsed < self.config.time_budget_ns and loops < self.config.max_iterations) {
            const start = nowNs(io);
            def.erased.invoke(def.erased.ctx, bench_alloc);
            elapsed += nowNs(io) - start;
            loops += 1;
        }
        const n = calibrationN(loops, elapsed, self.config.time_budget_ns, self.config.max_iterations);

        const timings = try self.allocator.alloc(u64, n);
        errdefer self.allocator.free(timings);
        const allocations = try self.allocator.alloc(AllocReading, n);
        errdefer self.allocator.free(allocations);
        for (0..n) |i| {
            counting.reset();
            const start = nowNs(io);
            def.erased.invoke(def.erased.ctx, bench_alloc);
            timings[i] = nowNs(io) - start;
            allocations[i] = counting.reading();
        }
        return .{ .runs = n, .timings = timings, .allocations = allocations };
    }
};

fn nowNs(io: std.Io) u64 {
    const ts = std.Io.Clock.Timestamp.now(io, .awake);
    return @intCast(ts.raw.toNanoseconds());
}

fn calibrationN(loops: u64, elapsed_ns: u64, time_budget_ns: u64, max_iterations: usize) usize {
    const safe_elapsed = if (elapsed_ns == 0) 1 else elapsed_ns;
    var n: u64 = @intCast((@as(u128, loops) * time_budget_ns) / safe_elapsed);
    if (n == 0) n = 1;
    if (n > max_iterations) n = max_iterations;
    return @intCast(n);
}

fn percentile(sorted: []const u64, p: f64) u64 {
    std.debug.assert(sorted.len > 0);
    const rank = @ceil(p / 100.0 * @as(f64, @floatFromInt(sorted.len)));
    const index: usize = @intFromFloat(rank);
    return sorted[@min(index, sorted.len) - 1];
}

fn printName(w: *std.Io.Writer, name: []const u8, width: usize) !void {
    var buf: [64]u8 = undefined;
    const len = @min(name.len, buf.len);
    @memcpy(buf[0..len], name[0..len]);
    const pad = @min(width, buf.len);
    if (pad > len) @memset(buf[len..pad], ' ');
    try w.writeAll(buf[0..@max(pad, len)]);
}

fn printRow(w: *std.Io.Writer, max_name_len: usize, name: []const u8, result: Result) !void {
    const sorted = result.timings;
    std.sort.pdq(u64, sorted, {}, std.sort.asc(u64));

    var sum: u128 = 0;
    for (result.timings) |t| sum += t;
    const mean: u64 = @intCast(sum / result.runs);
    var sq: u128 = 0;
    for (result.timings) |t| {
        const d: i128 = @as(i128, t) - @as(i128, mean);
        sq += @intCast(d * d);
    }
    const sd: u64 = @intFromFloat(@sqrt(@as(f64, @floatFromInt(sq / result.runs))));

    var alloc_count: usize = 0;
    var peak: usize = 0;
    for (result.allocations) |a| {
        alloc_count += a.count;
        if (a.peak_bytes > peak) peak = a.peak_bytes;
    }
    const alloc_avg = @as(f64, @floatFromInt(alloc_count)) / @as(f64, @floatFromInt(result.runs));

    try printName(w, name, max_name_len);
    try w.print(" {d:>8} {d:>12} {d:>12} {d:>12} {d:>12} {d:>12} {d:>12} {d:>8.2} {d:>10}\n", .{
        result.runs,
        mean,
        sd,
        sorted[0],
        sorted[sorted.len - 1],
        percentile(sorted, 75),
        percentile(sorted, 99),
        alloc_avg,
        peak,
    });
}

test "calibration lands inside the clamp for fast and slow benches" {
    try std.testing.expectEqual(@as(usize, 100), calibrationN(10, 50, 500, 100));
    try std.testing.expectEqual(@as(usize, 1), calibrationN(10, 10_000, 500, 100));
    try std.testing.expectEqual(@as(usize, 100), calibrationN(100, 500, 500, 100));
    try std.testing.expectEqual(@as(usize, 1), calibrationN(1, 0, 500, 100));
}

test "percentile is the nearest rank over sorted readings" {
    const sorted = [_]u64{ 10, 20, 30, 40, 50, 60, 70, 80, 90, 100 };
    try std.testing.expectEqual(@as(u64, 80), percentile(&sorted, 75));
    try std.testing.expectEqual(@as(u64, 100), percentile(&sorted, 99));
    try std.testing.expectEqual(@as(u64, 10), percentile(&sorted, 1));
}

test "counting allocator tracks count and peak live bytes" {
    var counting = CountingAllocator.init(std.testing.allocator);
    const alloc = counting.allocator();

    const a = try alloc.alloc(u8, 64);
    const b = try alloc.alloc(u8, 32);
    alloc.free(a);
    const c = try alloc.alloc(u8, 16);
    defer alloc.free(b);
    defer alloc.free(c);

    const r = counting.reading();
    try std.testing.expectEqual(@as(usize, 3), r.count);
    try std.testing.expectEqual(@as(usize, 48), r.live_bytes);
    try std.testing.expectEqual(@as(usize, 96), r.peak_bytes);
}
