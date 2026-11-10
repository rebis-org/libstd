// The smoke pass asserts survival only: no trap, panic, or leak; smoke and campaign both resolve through targets.zig.

const std = @import("std");

const targets = @import("targets.zig");

const testing = std.testing;

// Compile-time lookup into the shared target table: a smoke block naming an unknown format fails the build, never silently skips.
fn targetIndex(comptime name: []const u8) comptime_int {
    for (targets.targets, 0..) |target, index| {
        if (std.mem.eql(u8, target.name, name)) return index;
    }
    @compileError("fuzz target missing from targets.targets: " ++ name);
}

fn drive(smith: *testing.Smith, run: *const fn (data: []const u8) anyerror!void) anyerror!void {
    var input: [targets.max_input]u8 = undefined;
    const len = smith.slice(&input);
    try run(input[0..len]);
}

// The ledger enforces table-to-smoke: every campaign target must own a smoke block, and the coverage test fails on uncovered entries.
var covered: [targets.targets.len]bool = @splat(false);

// One wrapper keeps smoke blocks to their table entry alone; the return is the assertion: the runner survived.
fn smoke(comptime name: []const u8) !void {
    const index = targetIndex(name);
    covered[index] = true;
    try testing.fuzz({}, struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            try drive(smith, targets.targets[index].run);
        }
    }.f, .{ .corpus = &.{targets.targets[index].seed} });
}

test "gzip decode survives arbitrary input without trapping" {
    try smoke("gzip");
}

test "zlib decode survives arbitrary input without trapping" {
    try smoke("zlib");
}

test "deflate decode survives arbitrary input without trapping" {
    try smoke("deflate");
}

test "zstd decode survives arbitrary input without trapping" {
    try smoke("zstd");
}

test "lz4 decode survives arbitrary input without trapping" {
    try smoke("lz4");
}

test "xz decode survives arbitrary input without trapping" {
    try smoke("xz");
}

test "lzma alone decode survives arbitrary input without trapping" {
    try smoke("lzma-alone");
}

test "bzip2 decode survives arbitrary input without trapping" {
    try smoke("bzip2");
}

test "sevenzip header walk survives arbitrary input without trapping" {
    try smoke("sevenzip");
}

test "zip decode survives arbitrary input without trapping" {
    try smoke("zip");
}

test "rar decode survives arbitrary input without trapping" {
    try smoke("rar");
}

test "tar decode survives arbitrary input without trapping" {
    try smoke("tar");
}

test "cpio decode survives arbitrary input without trapping" {
    try smoke("cpio");
}

test "wim decode survives arbitrary input without trapping" {
    try smoke("wim");
}

test "xar decode survives arbitrary input without trapping" {
    try smoke("xar");
}

test "xip decode survives arbitrary input without trapping" {
    try smoke("xip");
}

test "xip window decode survives arbitrary input without trapping" {
    try smoke("xip_view");
}

test "pkg decode survives arbitrary input without trapping" {
    try smoke("pkg");
}

test "age decode survives arbitrary input without trapping" {
    try smoke("age");
}

test "iso decode survives arbitrary input without trapping" {
    try smoke("iso");
}

test "squashfs decode survives arbitrary input without trapping" {
    try smoke("squashfs");
}

test "dwarfs decode survives arbitrary input without trapping" {
    try smoke("dwarfs");
}

test "apfs decode survives arbitrary input without trapping" {
    try smoke("apfs");
}

test "fuzz smoke matches the campaign target table exactly" {
    for (targets.targets, covered) |target, is_covered| {
        if (!is_covered) std.debug.print("missing smoke block for fuzz target: {s}\n", .{target.name});
        try testing.expect(is_covered);
    }
}
