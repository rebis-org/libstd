const std = @import("std");
const checksum = @import("checksum");
const harness = @import("harness.zig");

fn fillBuffer(buffer: []u8) void {
    var seed: u64 = 0x9e3779b97f4a7c15;
    for (buffer) |*byte| {
        byte.* = @truncate(seed >> 56);
        seed = seed *% 0x9e3779b97f4a7c15 +% 0x70d5e2f72d5a9c0b;
    }
}

fn crc32Ref(input: []const u8) u32 {
    var crc: u32 = 0xffff_ffff;
    for (input) |byte| {
        var value = crc ^ byte;
        var bit: u5 = 0;
        while (bit < 8) : (bit += 1) {
            crc = if ((value & 1) != 0) (value >> 1) ^ 0xedb8_8320 else value >> 1;
            value = crc;
        }
    }
    return ~crc;
}

fn runSizes(r: *harness.Runner) !void {
    _ = r;
    const gpa = std.heap.page_allocator;
    const page = try gpa.alloc(u8, 2 * 1024 * 1024 + 4096);
    defer gpa.free(page);
    fillBuffer(page);

    const sizes = [_]usize{
        0,       1,   3,   7,   8,   15,  16,  31,   32,   33,   63,   64,   65,
        127,     128, 255, 256, 257, 511, 512, 1024, 4095, 4096, 4097, 8192, 65536,
        1048576,
    };
    const alignments = [_]usize{ 0, 1, 3, 7, 8, 15 };
    for (sizes) |size| {
        for (alignments) |off| {
            if (off + size > page.len) continue;
            const input = page[off..][0..size];
            const expected = crc32Ref(input);
            const got = checksum.crc32(input);
            if (got != expected) {
                std.debug.print("checksum mismatch size={d} off={d}: got {x:0>8}, want {x:0>8}\n", .{ size, off, got, expected });
                return error.ChecksumMismatch;
            }
        }
    }
}

fn runSplitUpdates(r: *harness.Runner, chunk_size: usize) !void {
    _ = r;
    const gpa = std.heap.page_allocator;
    const data = try gpa.alloc(u8, 1048576);
    defer gpa.free(data);
    fillBuffer(data);

    var split = checksum.Crc32.init();
    var offset: usize = 0;
    while (offset < data.len) {
        const end = @min(offset + chunk_size, data.len);
        split.update(data[offset..end]);
        offset = end;
    }
    const split_digest = split.final();

    var whole = checksum.Crc32.init();
    whole.update(data);
    const whole_digest = whole.final();

    if (split_digest != whole_digest or split_digest != crc32Ref(data)) {
        std.debug.print("split/whole mismatch chunk={d}: split={x:0>8} whole={x:0>8} ref={x:0>8}\n", .{ chunk_size, split_digest, whole_digest, crc32Ref(data) });
        return error.SplitMismatch;
    }
}

pub fn run(r: *harness.Runner) anyerror!void {
    try runSizes(r);
    try runSplitUpdates(r, 123); // sub-threshold chunks: serial path only
    try runSplitUpdates(r, 300); // straddles 256 B threshold: exercises PMULL continuation
}

pub const scenarios = harness.scenarios("checksum", &.{
    .{ .label = "crc32 kernel equivalence", .run = run, .workspace_size = 0, .output_size = 0, .encoded_size = 0 },
}, &.{});
