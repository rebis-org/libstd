const std = @import("std");

const crypto = @import("common/primitive/crypto.zig");

const traces = 1_000_000;
const partitions = 64;
const threshold = 4.5;

fn mean(samples: []const u64) f64 {
    var sum: u128 = 0;
    for (samples) |s| sum += s;
    return @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(samples.len));
}

fn variance(samples: []const u64, m: f64) f64 {
    var acc: f64 = 0;
    for (samples) |s| {
        const d = @as(f64, @floatFromInt(s)) - m;
        acc += d * d;
    }
    return acc / @as(f64, @floatFromInt(samples.len));
}

fn welchT(fixed: []const u64, random: []const u64) f64 {
    const mf = mean(fixed);
    const mr = mean(random);
    const vf = variance(fixed, mf) / @as(f64, @floatFromInt(fixed.len));
    const vr = variance(random, mr) / @as(f64, @floatFromInt(random.len));
    return (mf - mr) / @sqrt(vf + vr);
}

const Subject = struct {
    name: []const u8,
    fixed_ns: []u64,
    random_ns: []u64,
};

fn report(subject: Subject, noise_t: f64, io: std.Io, pool: []u64, random: std.Random) !void {
    const t = welchT(subject.fixed_ns, subject.random_ns);
    var max_partition: f64 = 0;
    var i: usize = 0;
    while (i < partitions) : (i += 1) {
        const pt = partitionT(subject.fixed_ns, subject.random_ns, random, pool);
        if (pt > max_partition) max_partition = pt;
    }
    const mf = mean(subject.fixed_ns);
    const mr = mean(subject.random_ns);
    const verdict = if (@abs(t) > threshold or max_partition > threshold) "SUSPECTED LEAK" else "constant-time (no leak detected)";
    var buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "{s}: fixed {d:.1} ns, random {d:.1} ns, delta {d:.2} ns, t {d:.2}, partition max-t {d:.2}, noise-floor t {d:.2} -> {s}\n", .{
        subject.name, mf, mr, mf - mr, t, max_partition, noise_t, verdict,
    }) catch unreachable;
    try std.Io.File.stdout().writeStreamingAll(io, line);
    if (@abs(t) > threshold or max_partition > threshold) std.process.exit(1);
}

fn partitionT(fixed: []const u64, random: []const u64, random_gen: std.Random, pool: []u64) f64 {
    // Pool both classes, split into two halves at random, and t-test the
    // halves: a null probe that should stay near zero catches drift-driven
    // artifacts the two-class test can mask.
    @memcpy(pool[0..fixed.len], fixed);
    @memcpy(pool[fixed.len..][0..random.len], random);
    const total = fixed.len + random.len;
    random_gen.shuffle(u64, pool[0..total]);
    const half = total / 2;
    return @abs(welchT(pool[0..half], pool[half..][0..half]));
}

pub fn main(init: std.process.Init) !void {
    const alloc = std.heap.page_allocator;

    var seed: [8]u8 = undefined;
    std.mem.writeInt(u64, &seed, @as(u64, @truncate(@as(u128, @intCast(std.Io.Timestamp.now(init.io, .real).nanoseconds)))), .little);
    var prng = std.Random.DefaultPrng.init(std.mem.readInt(u64, &seed, .little));
    const random = prng.random();

    var secret_a: [32]u8 = undefined;
    var secret_b: [32]u8 = undefined;
    random.bytes(&secret_a);
    random.bytes(&secret_b);
    const fixed_a = secret_a;

    const key = crypto.default_provider;
    var aes_key: [16]u8 = undefined;
    var iv: [16]u8 = undefined;
    var ct_fixed: [16]u8 = undefined;
    var ct_random: [16]u8 = undefined;
    var pt: [16]u8 = undefined;
    random.bytes(&aes_key);
    random.bytes(&iv);
    random.bytes(&ct_fixed);
    random.bytes(&ct_random);

    // Both classes walk a same-sized pool at the same index, so the memory
    // system cost is identical and only the compared content differs:
    // fixed compares equal halves, random compares against random bytes.
    // Input construction stays outside the timed region.
    var random_inputs = try alloc.alloc([32]u8, traces / 2);
    for (random_inputs) |*buf| random.bytes(buf);
    var fixed_inputs = try alloc.alloc([32]u8, traces / 2);
    for (fixed_inputs) |*buf| @memcpy(buf, &fixed_a);
    var eql_fixed = try alloc.alloc(u64, traces / 2);
    var eql_random = try alloc.alloc(u64, traces / 2);
    var cbc_fixed = try alloc.alloc(u64, traces / 2);
    var cbc_random = try alloc.alloc(u64, traces / 2);
    var empty_probe = try alloc.alloc(u64, traces);
    const pool = try alloc.alloc(u64, traces);
    var fixed_count: usize = 0;
    var random_count: usize = 0;
    var stat_prng = std.Random.DefaultPrng.init(0x9E3779B97F4A7C15);
    const stat_random = stat_prng.random();

    var i: usize = 0;
    while (i < traces) : (i += 1) {
        // Fill each class to exactly half the traces: the class behind its
        // quota takes the next draw, so binomial fluctuation cannot overrun
        // the arrays and both classes stay interleaved.
        const use_fixed = if (fixed_count == traces / 2)
            false
        else if (random_count == traces / 2)
            true
        else
            random.boolean();
        const fi = if (use_fixed) fixed_count else random_count;
        var t0 = std.Io.Timestamp.now(init.io, .awake);
        if (use_fixed) {
            std.mem.doNotOptimizeAway(crypto.constantTimeEql(&fixed_a, &fixed_inputs[fi]));
        } else {
            std.mem.doNotOptimizeAway(crypto.constantTimeEql(&fixed_a, &random_inputs[fi]));
        }
        (if (use_fixed) &eql_fixed else &eql_random).*[fi] = @intCast(t0.durationTo(std.Io.Timestamp.now(init.io, .awake)).nanoseconds);

        t0 = std.Io.Timestamp.now(init.io, .awake);
        if (use_fixed) {
            try crypto.aesCbcDecrypt(key, &aes_key, iv, &pt, &ct_fixed);
        } else {
            try crypto.aesCbcDecrypt(key, &aes_key, iv, &pt, &ct_random);
        }
        (if (use_fixed) &cbc_fixed else &cbc_random).*[fi] = @intCast(t0.durationTo(std.Io.Timestamp.now(init.io, .awake)).nanoseconds);

        t0 = std.Io.Timestamp.now(init.io, .awake);
        std.mem.doNotOptimizeAway(&pt);
        empty_probe[i] = @intCast(t0.durationTo(std.Io.Timestamp.now(init.io, .awake)).nanoseconds);
        if (use_fixed) {
            fixed_count += 1;
        } else {
            random_count += 1;
        }
    }

    const fixed_samples = eql_fixed[0..fixed_count];
    const random_samples = eql_random[0..random_count];
    const cbc_fixed_samples = cbc_fixed[0..fixed_count];
    const cbc_random_samples = cbc_random[0..random_count];
    try report(.{ .name = "constantTimeEql(32B)", .fixed_ns = fixed_samples, .random_ns = random_samples }, @abs(welchT(empty_probe[0 .. traces / 2], empty_probe[traces / 2 ..])), init.io, pool, stat_random);
    try report(.{ .name = "aesCbcDecrypt(1 block)", .fixed_ns = cbc_fixed_samples, .random_ns = cbc_random_samples }, @abs(welchT(empty_probe[0 .. traces / 2], empty_probe[traces / 2 ..])), init.io, pool, stat_random);
}
