const std = @import("std");

const env_mod = @import("env.zig");
const matrix = @import("matrix.zig");
const metric = @import("metric.zig");
const tsv = @import("tsv.zig");

pub const GateClass = enum { pass, fail, noisy, unmeasurable, unhealthy };

pub const GateResult = struct {
    name: []const u8,
    class: GateClass,
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

pub const gate_header = "class\tworst_gap_pct\tformat\tratio_gap_pct\tc_mibps_gap_pct\td_mibps_gap_pct\n";

fn bestMetric(totals: metric.Totals, available: [4]bool, comptime side_kind: enum { ratio, speed }, ns: [4]u64) ?f64 {
    var best: f64 = 0;
    for (1..4) |side| {
        if (!available[side] or !totals.ok[side]) continue;
        const value = switch (side_kind) {
            .ratio => metric.compressionRatio(totals.input_bytes, totals.encoded[side]),
            .speed => metric.throughputMibps(totals.input_bytes, ns[side]),
        };
        best = @max(best, value);
    }
    return if (best > 0) best else null;
}

fn bestRatio(totals: metric.Totals, available: [4]bool) ?f64 {
    return bestMetric(totals, available, .ratio, .{ 0, 0, 0, 0 });
}

fn bestSpeed(ns: [4]u64, totals: metric.Totals, available: [4]bool) ?f64 {
    return bestMetric(totals, available, .speed, ns);
}

fn exceedsGap(gap_value: ?f64, limit: f64) ?bool {
    const value = gap_value orelse return null;
    return value > limit;
}

pub fn classify(candidate: matrix.BenchmarkRow, totals: metric.Totals, available: [4]bool, cfg: env_mod.Gate) GateResult {
    const ours = @backingInt(metric.Side.ours);
    var result = GateResult{ .name = candidate.name, .class = .pass };
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
            const ours_ratio = metric.compressionRatio(totals.input_bytes, totals.encoded[ours]);
            if (ours_ratio > 0) result.ratio_gap = target / ours_ratio - 1.0;
        }
        result.compress_gap = speedGap(metric.throughputMibps(totals.input_bytes, totals.encode_ns[ours]), bestSpeed(totals.encode_ns, totals, available));
    }
    result.decompress_gap = speedGap(metric.throughputMibps(totals.input_bytes, totals.decode_ns[ours]), bestSpeed(totals.decode_ns, totals, available));
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
        for ([_]?bool{ exceedsGap(result.ratio_gap, ratio_limit), exceedsGap(result.compress_gap, speed_limit), exceedsGap(result.decompress_gap, speed_limit) }) |exceeded| {
            if (exceeded) |is_beyond| {
                measurable = true;
                beyond = beyond or is_beyond;
            }
        }
        result.class = if (!measurable) .unmeasurable else if (beyond) .fail else .pass;
    }
    return result;
}

fn speedGap(ours: f64, target: ?f64) ?f64 {
    const wanted = target orelse return null;
    if (ours <= 0) return null;
    return (wanted - ours) / wanted;
}

fn rankedGap(result: GateResult) f64 {
    return result.worst_gap orelse -std.math.inf(f64);
}

fn isWorse(_: void, left: GateResult, right: GateResult) bool {
    return rankedGap(left) > rankedGap(right);
}

pub fn sortByWorstGap(results: []GateResult) void {
    std.mem.sort(GateResult, results, {}, isWorse);
}

pub fn summarize(results: []const GateResult) Summary {
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

pub fn emitGateRow(report: *std.ArrayList(u8), allocator: std.mem.Allocator, result: GateResult) !void {
    var cells: [4][16]u8 = undefined;
    const gaps = [_]?f64{ result.worst_gap, result.ratio_gap, result.compress_gap, result.decompress_gap };
    var values: [4][]const u8 = undefined;
    for (gaps, 0..) |gap_value, index| values[index] = tsv.formatGap(&cells[index], gap_value);
    try tsv.emitRow(report, allocator, &.{ @tagName(result.class), values[0], result.name }, values[1..]);
}
