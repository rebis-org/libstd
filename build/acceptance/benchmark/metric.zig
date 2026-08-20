const std = @import("std");

const matrix = @import("matrix.zig");

pub const Side = enum { ours, cmd, lib, bin };

pub const Metric = struct {
    encoded: usize = 0,
    encode_ns: u64 = 0,
    decode_ns: u64 = 0,
    ok: bool = false,
};

pub const Totals = struct {
    input_bytes: usize = 0,
    encoded: [4]usize = .{ 0, 0, 0, 0 },
    encode_ns: [4]u64 = .{ 0, 0, 0, 0 },
    decode_ns: [4]u64 = .{ 0, 0, 0, 0 },
    ok: [4]bool = .{ true, true, true, true },

    pub fn add(self: *Totals, side: Side, m: Metric) void {
        const i = @intFromEnum(side);
        self.encoded[i] += m.encoded;
        self.encode_ns[i] += m.encode_ns;
        self.decode_ns[i] += m.decode_ns;
        self.ok[i] = self.ok[i] and m.ok;
    }
};

pub const header = "type\tparams\tformat\tours_ratio\tours_c_mibps\tours_d_mibps\tcmd_ratio\tcmd_c_mibps\tcmd_d_mibps\tlib_ratio\tlib_c_mibps\tlib_d_mibps\tbin_ratio\tbin_c_mibps\tbin_d_mibps\tcoverage\n";

fn medianOfSorted(comptime T: type, sorted: []const T) T {
    const mid = sorted.len / 2;
    if (sorted.len % 2 == 1) return sorted[mid];
    const a = sorted[mid - 1];
    const b = sorted[mid];
    return @intFromFloat((@as(f64, @floatFromInt(a)) + @as(f64, @floatFromInt(b))) / 2.0);
}

fn medianValue(comptime T: type, allocator: std.mem.Allocator, values: []const T) !T {
    if (values.len == 0) return 0;
    var sorted = try allocator.alloc(T, values.len);
    defer allocator.free(sorted);
    @memcpy(sorted, values);
    std.mem.sort(T, sorted, {}, comptime std.sort.asc(T));
    const med0 = medianOfSorted(T, sorted);
    if (med0 == 0) return med0;
    const fmed = @as(f64, @floatFromInt(med0));
    var keep: usize = 0;
    for (sorted) |v| {
        const fv = @as(f64, @floatFromInt(v));
        const delta = if (fv > fmed) fv - fmed else fmed - fv;
        if (delta / fmed <= 0.05) {
            sorted[keep] = v;
            keep += 1;
        }
    }
    if (keep == 0) return med0;
    return medianOfSorted(T, sorted[0..keep]);
}

pub fn medianTotals(allocator: std.mem.Allocator, runs: []const Totals, skip: usize) !Totals {
    if (runs.len <= skip) return Totals{};
    var result = Totals{ .input_bytes = runs[skip].input_bytes };
    var enc_values = std.ArrayList(usize).empty;
    defer enc_values.deinit(allocator);
    var encode_ns_values = std.ArrayList(u64).empty;
    defer encode_ns_values.deinit(allocator);
    var decode_ns_values = std.ArrayList(u64).empty;
    defer decode_ns_values.deinit(allocator);
    for (0..4) |side| {
        enc_values.clearRetainingCapacity();
        encode_ns_values.clearRetainingCapacity();
        decode_ns_values.clearRetainingCapacity();
        var all_ok = true;
        var any = false;
        for (runs[skip..]) |r| {
            if (r.ok[side]) {
                any = true;
                try enc_values.append(allocator, r.encoded[side]);
                try encode_ns_values.append(allocator, r.encode_ns[side]);
                try decode_ns_values.append(allocator, r.decode_ns[side]);
            } else {
                all_ok = false;
            }
        }
        result.encoded[side] = if (enc_values.items.len > 0) try medianValue(usize, allocator, enc_values.items) else 0;
        result.encode_ns[side] = if (encode_ns_values.items.len > 0) try medianValue(u64, allocator, encode_ns_values.items) else 0;
        result.decode_ns[side] = if (decode_ns_values.items.len > 0) try medianValue(u64, allocator, decode_ns_values.items) else 0;
        result.ok[side] = all_ok and any;
    }
    return result;
}

pub fn mibps(bytes: usize, ns: u64) f64 {
    if (ns == 0) return 0;
    return @as(f64, @floatFromInt(bytes)) * 1_000_000_000.0 / (@as(f64, @floatFromInt(ns)) * 1048576.0);
}

pub fn ratio(bytes: usize, encoded: usize) f64 {
    if (encoded == 0) return 0;
    return @as(f64, @floatFromInt(bytes)) / @as(f64, @floatFromInt(encoded));
}

fn cell(buf: *[16]u8, comptime fmt: []const u8, value: f64, show: bool) []const u8 {
    if (!show) return "missing";
    return std.fmt.bufPrint(buf, fmt, .{value}) catch "missing";
}

fn cellRatio(buf: *[16]u8, totals: Totals, side: Side, show: bool) []const u8 {
    return cell(buf, "{d:.3}", ratio(totals.input_bytes, totals.encoded[@intFromEnum(side)]), show);
}

fn cellMibps(buf: *[16]u8, bytes: usize, ns: u64, show: bool) []const u8 {
    return cell(buf, "{d:.1}", mibps(bytes, ns), show);
}

fn coverage(allocator: std.mem.Allocator, totals: Totals, available: [4]bool) ![]const u8 {
    if (!totals.ok[@intFromEnum(Side.ours)]) return "failed";
    var parts: [3][]const u8 = undefined;
    var n: usize = 0;
    if (!available[1]) {
        parts[n] = "cmd missing";
        n += 1;
    }
    if (!available[2]) {
        parts[n] = "lib missing";
        n += 1;
    }
    if (!available[3]) {
        parts[n] = "bin missing";
        n += 1;
    }
    if (n > 0) return std.mem.join(allocator, ", ", parts[0..n]);
    if (!totals.ok[1] or !totals.ok[2] or !totals.ok[3]) return "ref failed";
    return "ok";
}

pub fn row(report: *std.ArrayList(u8), allocator: std.mem.Allocator, r: matrix.Row, totals: Totals, available: [4]bool) !void {
    const show = !r.decode_only;
    const coverage_text = try coverage(allocator, totals, available);
    var cells: [13][16]u8 = undefined;
    const values = [_][]const u8{
        cellRatio(&cells[0], totals, .ours, show),
        cellMibps(&cells[1], totals.input_bytes, totals.encode_ns[0], show),
        cellMibps(&cells[2], totals.input_bytes, totals.decode_ns[0], true),
        cellRatio(&cells[3], totals, .cmd, available[1] and show),
        cellMibps(&cells[4], totals.input_bytes, totals.encode_ns[1], available[1] and show),
        cellMibps(&cells[5], totals.input_bytes, totals.decode_ns[1], available[1]),
        cellRatio(&cells[6], totals, .lib, available[2] and show),
        cellMibps(&cells[7], totals.input_bytes, totals.encode_ns[2], available[2] and show),
        cellMibps(&cells[8], totals.input_bytes, totals.decode_ns[2], available[2]),
        cellRatio(&cells[9], totals, .bin, available[3] and show),
        cellMibps(&cells[10], totals.input_bytes, totals.encode_ns[3], available[3] and show),
        cellMibps(&cells[11], totals.input_bytes, totals.decode_ns[3], available[3]),
        coverage_text,
    };
    try report.appendSlice(allocator, r.row_type);
    try report.appendSlice(allocator, "\t");
    try report.appendSlice(allocator, r.ref_params);
    try report.appendSlice(allocator, "\t");
    try report.appendSlice(allocator, r.name);
    for (values) |value| {
        try report.appendSlice(allocator, "\t");
        try report.appendSlice(allocator, value);
    }
    try report.appendSlice(allocator, "\n");
}
