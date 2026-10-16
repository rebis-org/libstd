const std = @import("std");

const rel_sd_max = 0.15;
const rel_sd_mild = 0.10;
const outlier_max = 1.5;

const Report = struct {
    results: []const Entry,

    const Entry = struct {
        command: []const u8,
        measurements: []const Sample,

        const Sample = struct {
            time_wall_clock: struct { value: f64 },
        };
    };
};

fn stats(measurements: []const Report.Entry.Sample) struct { mean: f64, rel_sd: f64, outlier: f64 } {
    var mean: f64 = 0;
    var m2: f64 = 0;
    var max: f64 = 0;
    for (measurements, 1..) |sample, count| {
        const value = sample.time_wall_clock.value;
        max = @max(max, value);
        const delta = value - mean;
        mean += delta / @as(f64, @floatFromInt(count));
        m2 += delta * (value - mean);
    }
    const variance = if (measurements.len > 0) m2 / @as(f64, @floatFromInt(measurements.len)) else 0;
    const rel_sd = if (mean != 0) @sqrt(variance) / mean else 0;
    return .{ .mean = mean, .rel_sd = rel_sd, .outlier = if (mean != 0) max / mean else 0 };
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var args = init.minimal.args.iterate();
    defer args.deinit();
    _ = args.skip();
    const path = args.next() orelse {
        try std.Io.File.stderr().writeStreamingAll(init.io, "usage: audit <hyperfine.json>.\n");
        std.process.exit(2);
    };

    const file = try std.Io.Dir.cwd().openFile(init.io, path, .{});
    defer file.close(init.io);
    const size: usize = @intCast(try file.length(init.io));
    const text = try allocator.alloc(u8, size);
    defer allocator.free(text);
    const got = try std.Io.File.readPositionalAll(file, init.io, text, 0);
    if (got != size) return error.truncated_read;

    const parsed = try std.json.parseFromSlice(Report, allocator, text, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    const writer = &out.writer;

    var noisy: usize = 0;
    var mild: usize = 0;
    for (parsed.value.results) |result| {
        const reading = stats(result.measurements);
        const bad = reading.rel_sd > rel_sd_max or reading.outlier > outlier_max;
        if (reading.rel_sd > rel_sd_mild) mild += 1;
        if (bad) noisy += 1;
        try writer.print("  {s}: rel_sd={d:.3} max/mean={d:.2} {s}\n", .{
            result.command,
            reading.rel_sd,
            reading.outlier,
            if (bad) "NOISY" else "ok",
        });
    }
    if (mild >= 2) noisy += 1;

    var list = out.toArrayList();
    defer list.deinit(allocator);
    try std.Io.File.stdout().writeStreamingAll(init.io, list.items);

    if (noisy > 0) {
        try std.Io.File.stderr().writeStreamingAll(init.io, "bench: NOISY host; settle the machine before an evidence session.\n");
        std.process.exit(1);
    }
    try std.Io.File.stdout().writeStreamingAll(init.io, "bench: quiet.\n");
}
