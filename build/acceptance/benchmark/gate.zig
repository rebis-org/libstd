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

fn bestBy(totals: metric.Totals, available: [4]bool, context: anytype, score: fn (@TypeOf(context), metric.Totals, usize) f64) ?f64 {
    var best: f64 = 0;
    for (1..4) |side| {
        if (!available[side] or !totals.ok[side]) continue;
        best = @max(best, score(context, totals, side));
    }
    return if (best > 0) best else null;
}

fn ratioScore(_: void, totals: metric.Totals, side: usize) f64 {
    return metric.ratio(totals.input_bytes, totals.encoded[side]);
}

fn speedScore(ns: [4]u64, totals: metric.Totals, side: usize) f64 {
    return metric.mibps(totals.input_bytes, ns[side]);
}

fn bestRatio(totals: metric.Totals, available: [4]bool) ?f64 {
    return bestBy(totals, available, {}, ratioScore);
}

fn bestSpeed(ns: [4]u64, totals: metric.Totals, available: [4]bool) ?f64 {
    return bestBy(totals, available, ns, speedScore);
}

fn speedGap(ours: f64, target: ?f64) ?f64 {
    const wanted = target orelse return null;
    if (ours <= 0) return null;
    return (wanted - ours) / wanted;
}

fn checkGap(gap_value: ?f64, limit: f64, measurable: *bool, beyond: *bool) void {
    const value = gap_value orelse return;
    measurable.* = true;
    if (value > limit) beyond.* = true;
}

pub fn classify(candidate: matrix.Row, totals: metric.Totals, available: [4]bool, cfg: env_mod.Gate) Result {
    const ours = @backingInt(metric.Side.ours);
    var result = Result{ .name = candidate.name, .class = .pass };
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
    if (!candidate.decode_only) {
        if (bestRatio(totals, available)) |target| {
            const ours_ratio = metric.ratio(totals.input_bytes, totals.encoded[ours]);
            if (ours_ratio > 0) result.ratio_gap = target / ours_ratio - 1.0;
        }
        result.compress_gap = speedGap(metric.mibps(totals.input_bytes, totals.encode_ns[ours]), bestSpeed(totals.encode_ns, totals, available));
    }
    result.decompress_gap = speedGap(metric.mibps(totals.input_bytes, totals.decode_ns[ours]), bestSpeed(totals.decode_ns, totals, available));
    for ([_]?f64{ result.ratio_gap, result.compress_gap, result.decompress_gap }) |gap_value| {
        if (gap_value) |value| result.worst_gap = @max(result.worst_gap orelse value, value);
    }
    if (ref_failed) {
        // Broken references must not mask a regression, outranking never-fatal store rows.
        result.class = .unhealthy;
    } else if (candidate.archive and !candidate.decode_only) {
        result.class = .noisy;
    } else {
        const speed_limit = 1.0 - cfg.speed_pct / 100.0;
        const ratio_limit = cfg.ratio_pct / 100.0 - 1.0;
        var measurable = false;
        var beyond = false;
        checkGap(result.ratio_gap, ratio_limit, &measurable, &beyond);
        checkGap(result.compress_gap, speed_limit, &measurable, &beyond);
        checkGap(result.decompress_gap, speed_limit, &measurable, &beyond);
        result.class = if (!measurable) .unmeasurable else if (beyond) .fail else .pass;
    }
    return result;
}

fn rankedGap(result: Result) f64 {
    return result.worst_gap orelse -std.math.inf(f64);
}

fn isWorse(_: void, left: Result, right: Result) bool {
    return rankedGap(left) > rankedGap(right);
}

pub fn sort(results: []Result) void {
    std.mem.sort(Result, results, {}, isWorse);
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

pub fn emitGateRow(report: *std.ArrayList(u8), allocator: std.mem.Allocator, result: Result) !void {
    var cells: [4][16]u8 = undefined;
    const gaps = [_]?f64{ result.worst_gap, result.ratio_gap, result.compress_gap, result.decompress_gap };
    var values: [4][]const u8 = undefined;
    for (gaps, 0..) |gap_value, index| values[index] = tsv.gap(&cells[index], gap_value);
    try tsv.emitRow(report, allocator, &.{ @tagName(result.class), values[0], result.name }, values[1..]);
}
