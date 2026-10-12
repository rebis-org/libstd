//! Noisy: any reference above 0.15 rel-sd or 1.5 max/mean, or two above
//! 0.10 at once — one graze is jitter.

const std = @import("std");

const rel_sd_max = 0.15;
const rel_sd_mild = 0.10;
const outlier_max = 1.5;

const Report = struct {
    results: []const Result,

    const Result = struct {
        command: []const u8,
        measurements: []const Measurement,

        const Measurement = struct {
            time_wall_clock: struct { value: f64 },
        };
    };
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var args = init.minimal.args.iterate();
    defer args.deinit();
    _ = args.skip();
    const path = args.next() orelse {
        try std.Io.File.stderr().writeStreamingAll(init.io, "usage: audit <hyperfine.json>\n");
        std.process.exit(2);
    };

    const file = try std.Io.Dir.cwd().openFile(init.io, path, .{});
    defer file.close(init.io);
    const size: usize = @intCast(try file.length(init.io));
    const text = try allocator.alloc(u8, size);
    defer allocator.free(text);
    const got = try std.Io.File.readPositionalAll(file, init.io, text, 0);
    if (got != size) return error.TruncatedRead;

    const parsed = try std.json.parseFromSlice(Report, allocator, text, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    const w = &out.writer;

    var noisy: usize = 0;
    var mild: usize = 0;
    for (parsed.value.results) |result| {
        var sum: f64 = 0;
        for (result.measurements) |m| sum += m.time_wall_clock.value;
        const mean = sum / @as(f64, @floatFromInt(result.measurements.len));
        var sq: f64 = 0;
        for (result.measurements) |m| {
            const d = m.time_wall_clock.value - mean;
            sq += d * d;
        }
        const rel_sd = @sqrt(sq / @as(f64, @floatFromInt(result.measurements.len))) / mean;
        var max: f64 = 0;
        for (result.measurements) |m| max = @max(max, m.time_wall_clock.value);
        const outlier = max / mean;
        const bad = rel_sd > rel_sd_max or outlier > outlier_max;
        if (rel_sd > rel_sd_mild) mild += 1;
        if (bad) noisy += 1;
        try w.print("  {s}: rel_sd={d:.3} max/mean={d:.2} {s}\n", .{
            result.command,
            rel_sd,
            outlier,
            if (bad) "NOISY" else "ok",
        });
    }
    if (mild >= 2) noisy += 1;

    var list = out.toArrayList();
    defer list.deinit(allocator);
    try std.Io.File.stdout().writeStreamingAll(init.io, list.items);

    if (noisy > 0) {
        try std.Io.File.stderr().writeStreamingAll(init.io, "bench: NOISY host; settle the machine before an evidence session\n");
        std.process.exit(1);
    }
    try std.Io.File.stdout().writeStreamingAll(init.io, "bench: quiet\n");
}
