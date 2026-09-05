const std = @import("std");

const env_mod = @import("env.zig");
const matrix = @import("matrix.zig");
const metric = @import("metric.zig");
const tsv = @import("tsv.zig");

pub const Class = enum { pass, fail, noisy, unmeasurable, unhealthy };

pub const Result = struct {
    name: []const u8,
    class: Class,
    ratio_gap: ?f64 = null,
    compress_gap: ?f64 = null,
    decompress_gap: ?f64 = null,
    worst_gap: ?f64 = null,
};

pub const Summary = struct {
    pass: usize = 0,
    fail: usize = 0,
    noisy: usize = 0,
    unmeasurable: usize = 0,
    unhealthy: usize = 0,

    pub fn fatalRows(self: Summary) usize {
        return self.fail + self.unhealthy;
    }
};

pub const header = "class\tworst_gap_pct\tformat\tratio_gap_pct\tc_mibps_gap_pct\td_mibps_gap_pct\n";

fn bestRatio(totals: metric.Totals, available: [4]bool) ?f64 {
    var best: f64 = 0;
    for (1..4) |side| {
        // A failed reference has partial totals and must not lower the target.
        if (!available[side] or !totals.ok[side]) continue;
        best = @max(best, metric.ratio(totals.input_bytes, totals.encoded[side]));
    }
    return if (best > 0) best else null;
}

fn bestSpeed(ns: [4]u64, totals: metric.Totals, available: [4]bool) ?f64 {
    var best: f64 = 0;
    for (1..4) |side| {
        if (!available[side] or !totals.ok[side]) continue;
        best = @max(best, metric.mibps(totals.input_bytes, ns[side]));
    }
    return if (best > 0) best else null;
}

fn speedGap(ours: f64, target: ?f64) ?f64 {
    const t = target orelse return null;
    if (ours <= 0) return null;
    return (t - ours) / t;
}

pub fn classify(r: matrix.Row, totals: metric.Totals, available: [4]bool, cfg: env_mod.Gate) Result {
    const ours = @intFromEnum(metric.Side.ours);
    var result = Result{ .name = r.name, .class = .pass };
    if (!totals.ok[ours]) {
        result.class = .fail;
        result.worst_gap = std.math.inf(f64);
        return result;
    }
    var any_ref = false;
    var ref_failed = false;
    for (1..4) |side| {
        if (available[side]) {
            any_ref = true;
            if (!totals.ok[side]) ref_failed = true;
        }
    }
    if (!any_ref) {
        result.class = .unmeasurable;
        return result;
    }
    if (!r.decode_only) {
        if (bestRatio(totals, available)) |target| {
            const ours_ratio = metric.ratio(totals.input_bytes, totals.encoded[ours]);
            if (ours_ratio > 0) result.ratio_gap = target / ours_ratio - 1.0;
        }
        result.compress_gap = speedGap(metric.mibps(totals.input_bytes, totals.encode_ns[ours]), bestSpeed(totals.encode_ns, totals, available));
    }
    result.decompress_gap = speedGap(metric.mibps(totals.input_bytes, totals.decode_ns[ours]), bestSpeed(totals.decode_ns, totals, available));
    for ([_]?f64{ result.ratio_gap, result.compress_gap, result.decompress_gap }) |gap| {
        if (gap) |g| result.worst_gap = @max(result.worst_gap orelse g, g);
    }
    if (ref_failed) {
        // A broken reference outranks the never-fatal store rows: it must not mask a regression.
        result.class = .unhealthy;
    } else if (r.archive and !r.decode_only) {
        result.class = .noisy;
    } else {
        const speed_limit = 1.0 - cfg.speed_pct / 100.0;
        const ratio_limit = cfg.ratio_pct / 100.0 - 1.0;
        var measurable = false;
        var beyond = false;
        if (result.ratio_gap) |g| {
            measurable = true;
            if (g > ratio_limit) beyond = true;
        }
        if (result.compress_gap) |g| {
            measurable = true;
            if (g > speed_limit) beyond = true;
        }
        if (result.decompress_gap) |g| {
            measurable = true;
            if (g > speed_limit) beyond = true;
        }
        result.class = if (!measurable) .unmeasurable else if (beyond) .fail else .pass;
    }
    return result;
}

fn rankedGap(result: Result) f64 {
    return result.worst_gap orelse -std.math.inf(f64);
}

fn worseFirst(_: void, a: Result, b: Result) bool {
    return rankedGap(a) > rankedGap(b);
}

pub fn sort(results: []Result) void {
    std.mem.sort(Result, results, {}, worseFirst);
}

pub fn summarize(results: []const Result) Summary {
    var summary = Summary{};
    for (results) |result| switch (result.class) {
        .pass => summary.pass += 1,
        .fail => summary.fail += 1,
        .noisy => summary.noisy += 1,
        .unmeasurable => summary.unmeasurable += 1,
        .unhealthy => summary.unhealthy += 1,
    };
    return summary;
}

pub fn row(report: *std.ArrayList(u8), allocator: std.mem.Allocator, result: Result) !void {
    var cells: [4][16]u8 = undefined;
    const values = [_][]const u8{
        tsv.gap(&cells[0], result.worst_gap),
        tsv.gap(&cells[1], result.ratio_gap),
        tsv.gap(&cells[2], result.compress_gap),
        tsv.gap(&cells[3], result.decompress_gap),
    };
    try tsv.emitRow(report, allocator, &.{ @tagName(result.class), values[0], result.name }, values[1..]);
}
