const std = @import("std");

const bounds = @import("../common/primitive/bounds.zig");
const checksum = @import("../common/primitive/checksum.zig");
const failure_prim = @import("../common/primitive/failure.zig");
const Failure = failure_prim.Failure;
const kernels = @import("kernels.zig");
const measurement = @import("../common/primitive/measurement.zig");

// LZ4 frame format (spec: "LZ4 Frame Format Description") with independent
// blocks. The block codec mirrors the reference greedy parser in vendor/lz4.

pub const block_size_min: u32 = 64 * 1024;
pub const block_size_max: u32 = 4 * 1024 * 1024;
pub const block_size_default: u32 = block_size_max;

const magic: u32 = 0x184D2204;
const version_bits: u8 = 0x40; // LZ4 frame spec fixes the version field at 01.
const flag_block_independence: u8 = 0x20;
const flag_block_checksum: u8 = 0x10;
const flag_content_size: u8 = 0x08;
const flag_content_checksum: u8 = 0x04;
const flag_dict_id: u8 = 0x01;
const uncompressed_block: u32 = 0x80000000;

const min_match = 4;
const mf_limit = 12;
const last_literals = 5;
const min_length = mf_limit + 1;
const run_mask = 15;
const ml_mask = 15;
const skip_trigger = 6;
const distance_max: u32 = 65535;
const hash_log = 12;
const hash_size = 1 << hash_log;
const hash_prime: u32 = 2654435761;
const header_size_max = 4 + 2 + 8 + 4 + 1;

pub const Options = struct {
    block_size: u32 = block_size_default,
    content_checksum: bool = true,
    block_checksum: bool = false,
    acceleration: u32 = 1,
};

fn blockCode(block_size: u32) Failure!u8 {
    return switch (block_size) {
        64 * 1024 => 4,
        256 * 1024 => 5,
        1024 * 1024 => 6,
        4 * 1024 * 1024 => 7,
        else => error.InvalidCall,
    };
}

pub fn encodeWorkspaceSize() usize {
    return hash_size * @sizeOf(u32) + blockBound(block_size_max);
}

pub fn decodeWorkspaceSize() usize {
    return block_size_max;
}

// Worst case: every block stores raw plus its size word. Compressed blocks
// stay under compressBound (n + n/255 + 16) which the stored path dominates.
pub fn encodedSizeBound(input_len: usize) usize {
    const blocks = input_len / block_size_max + 1;
    return header_size_max + 4 + input_len + input_len / 255 + blocks * 20 + checksum_length;
}

const checksum_length = 4;

fn blockBound(block_len: usize) usize {
    return block_len + block_len / 255 + 16;
}

pub fn frameContentSize(input: []const u8) Failure!?u64 {
    if (input.len < 7) return error.InvalidData;
    if (std.mem.readInt(u32, input[0..4], .little) != magic) return error.InvalidData;
    const flg = input[4];
    if (flg & flag_content_size == 0) return null;
    if (input.len < 14) return error.InvalidData;
    return std.mem.readInt(u64, input[6..14], .little);
}

pub fn decodedSize(input: []const u8, scratch: []u8, options: Options) Failure!usize {
    _ = options;
    var counter = measurement.Counter.init(null);
    return try decodeBlocks(input, &counter.writer, scratch);
}

pub fn requiredSize(input: []const u8, scratch: []u8, options: Options) Failure!usize {
    // Exact encoded size: one counting encode pass, mirroring the measured policy.
    var counter = measurement.Counter.init(null);
    try encodeToWriter(input, &counter.writer, scratch, options);
    return std.math.cast(usize, counter.written()) orelse error.ResourceLimit;
}

pub fn encode(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    var fixed = std.Io.Writer.fixed(output);
    try encodeToWriter(input, &fixed, scratch, options);
    return fixed.end;
}

pub fn decode(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    _ = options;
    var fixed = std.Io.Writer.fixed(output);
    return try decodeBlocks(input, &fixed, scratch);
}

pub fn decodeInPlace(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    return try decode(input, output, scratch, options);
}

pub fn encodeToWriter(input: []const u8, output: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    if (scratch.len < encodeWorkspaceSize()) return error.InsufficientCapacity;
    _ = try blockCode(options.block_size);
    var acceleration = options.acceleration;
    if (acceleration < 1) acceleration = 1;
    output.writeInt(u32, magic, .little) catch return error.IoFailure;
    var flg: u8 = version_bits | flag_block_independence;
    if (options.block_checksum) flg |= flag_block_checksum;
    flg |= flag_content_size;
    if (options.content_checksum) flg |= flag_content_checksum;
    const bd = try blockCode(options.block_size);
    var header_hasher = checksum.XxHash32.init(0);
    output.writeByte(flg) catch return error.IoFailure;
    header_hasher.update(&.{flg});
    output.writeByte(bd << 4) catch return error.IoFailure;
    header_hasher.update(&.{bd << 4});
    var size_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &size_bytes, input.len, .little);
    output.writeAll(&size_bytes) catch return error.IoFailure;
    header_hasher.update(&size_bytes);
    output.writeByte(@truncate(header_hasher.final() >> 8)) catch return error.IoFailure;
    const table: []u32 = @alignCast(std.mem.bytesAsSlice(u32, scratch[0 .. hash_size * @sizeOf(u32)]));
    const work = scratch[hash_size * @sizeOf(u32) ..];
    var offset: usize = 0;
    while (offset < input.len) {
        const chunk_len: usize = @min(input.len - offset, options.block_size);
        const chunk = input[offset .. offset + chunk_len];
        const compressed_len = compressBlock(chunk, work, table, acceleration);
        if (compressed_len >= chunk_len) {
            output.writeInt(u32, uncompressed_block | (std.math.cast(u32, chunk_len) orelse return error.ResourceLimit), .little) catch return error.IoFailure;
            output.writeAll(chunk) catch return error.IoFailure;
            if (options.block_checksum) output.writeInt(u32, checksum.xxh32(chunk), .little) catch return error.IoFailure;
        } else {
            output.writeInt(u32, std.math.cast(u32, compressed_len) orelse return error.ResourceLimit, .little) catch return error.IoFailure;
            output.writeAll(work[0..compressed_len]) catch return error.IoFailure;
            if (options.block_checksum) output.writeInt(u32, checksum.xxh32(work[0..compressed_len]), .little) catch return error.IoFailure;
        }
        offset += chunk_len;
    }
    if (input.len == 0) {
        // One empty block (single zero token) keeps the block stream well-formed.
        output.writeInt(u32, 1, .little) catch return error.IoFailure;
        output.writeByte(0) catch return error.IoFailure;
    }
    output.writeInt(u32, 0, .little) catch return error.IoFailure;
    if (options.content_checksum) output.writeInt(u32, checksum.xxh32(input), .little) catch return error.IoFailure;
}

pub fn decodeToWriter(input: []const u8, output: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    _ = options;
    _ = try decodeBlocks(input, output, scratch);
}

fn decodeBlocks(input: []const u8, output: *std.Io.Writer, scratch: []u8) Failure!usize {
    if (scratch.len < block_size_max) return error.InsufficientCapacity;
    if (input.len < 7) return error.InvalidData;
    if (std.mem.readInt(u32, input[0..4], .little) != magic) return error.InvalidData;
    const flg = input[4];
    if ((flg & 0xC0) != version_bits) return error.Unsupported;
    if (flg & flag_block_independence == 0) return error.Unsupported;
    if (flg & flag_dict_id != 0) return error.Unsupported;
    const bd = input[5];
    const block_code = (bd >> 4) & 0x07;
    if (block_code < 4 or block_code > 7) return error.InvalidData;
    const max_block: usize = @as(usize, 65536) << @intCast(2 * (@as(usize, block_code) - 4));
    var offset: usize = 6;
    if (flg & flag_content_size != 0) {
        if (input.len < offset + 8) return error.InvalidData;
        offset += 8;
    }
    if (flg & flag_dict_id != 0) offset += 4;
    if (input.len <= offset) return error.InvalidData;
    offset += 1; // header checksum
    var content_hasher = checksum.XxHash32.init(0);
    var total: usize = 0;
    while (true) {
        if (input.len < offset + 4) return error.InvalidData;
        const block_size_field = std.mem.readInt(u32, input[offset..][0..4], .little);
        offset += 4;
        if (block_size_field == 0) break;
        const stored = (block_size_field & uncompressed_block) != 0;
        const payload_len: usize = @intCast(block_size_field & ~uncompressed_block);
        if (input.len < offset + payload_len) return error.InvalidData;
        const payload = input[offset .. offset + payload_len];
        offset += payload_len;
        if (flg & flag_block_checksum != 0) {
            if (input.len < offset + 4) return error.InvalidData;
            const stored_sum = std.mem.readInt(u32, input[offset..][0..4], .little);
            if (stored_sum != checksum.xxh32(payload)) return error.IntegrityFailure;
            offset += 4;
        }
        if (stored) {
            if (payload_len > max_block) return error.InvalidData;
            output.writeAll(payload) catch return error.IoFailure;
            content_hasher.update(payload);
            total = try bounds.add(total, payload_len);
        } else {
            const produced = decompressBlock(payload, scratch[0..max_block]) catch return error.InvalidData;
            output.writeAll(scratch[0..produced]) catch return error.IoFailure;
            content_hasher.update(scratch[0..produced]);
            total = try bounds.add(total, produced);
        }
    }
    if (flg & flag_content_checksum != 0) {
        if (input.len < offset + 4) return error.InvalidData;
        const stored_sum = std.mem.readInt(u32, input[offset..][0..4], .little);
        if (stored_sum != content_hasher.final()) return error.IntegrityFailure;
        offset += 4;
    }
    if (offset != input.len) return error.InvalidData;
    return total;
}

fn hash4(value: u32) usize {
    return (value *% hash_prime) >> @intCast(32 - hash_log);
}

// Mirrors LZ4_compress_generic_validated for a single segment (no dict): skip
// escalation on incompressible runs, catch-up, and the test-next-position step.
// The carried forward_hash chain matches the reference: a search probe reads
// and writes the same slot, and the first probe after a match uses the hash
// carried from the search that found it, never the slot the test-next step
// just wrote for the current position (that self-match would emit offset 0).
fn compressBlock(input: []const u8, output: []u8, table: []u32, acceleration: u32) usize {
    @memset(table, 0);
    var op: usize = 0;
    const len = input.len;
    if (len == 0) {
        output[0] = 0;
        return 1;
    }
    if (len < min_length) {
        op = emitLastLiterals(input, output, 0);
        return op;
    }
    var ip: usize = 1;
    var anchor: usize = 0;
    const mflimit_plus_one = len - mf_limit + 1;
    const match_limit = len - last_literals;
    var token_pos: usize = 0;
    table[hash4(std.mem.readInt(u32, input[0..4], .little))] = 1;
    var forward_hash = hash4(std.mem.readInt(u32, input[1..][0..4], .little));
    outer: while (true) {
        var match: usize = 0;
        var match_index: usize = 0;
        {
            var forward_ip = ip;
            var step: usize = 1;
            var search_match_nb = acceleration << skip_trigger;
            while (true) {
                const h = forward_hash;
                ip = forward_ip;
                forward_ip += step;
                step = search_match_nb >> skip_trigger;
                search_match_nb += 1;
                if (forward_ip > mflimit_plus_one) break :outer;
                forward_hash = hash4(std.mem.readInt(u32, input[forward_ip..][0..4], .little));
                match_index = table[h];
                table[h] = @intCast(ip + 1);
                if (match_index == 0) continue;
                match_index -= 1;
                if (match_index >= ip) continue;
                if (match_index + distance_max < ip) continue;
                match = match_index;
                if (std.mem.readInt(u32, input[match..][0..4], .little) == std.mem.readInt(u32, input[ip..][0..4], .little)) break;
            }
        }
        while (ip > anchor and match > 0 and input[ip - 1] == input[match - 1]) {
            ip -= 1;
            match -= 1;
        }
        token_pos = op;
        op += 1;
        {
            const lit_len = ip - anchor;
            if (lit_len >= run_mask) {
                output[token_pos] = run_mask << 4;
                var rest = lit_len - run_mask;
                while (rest >= 255) : (rest -= 255) {
                    output[op] = 255;
                    op += 1;
                }
                output[op] = @intCast(rest);
                op += 1;
            } else {
                output[token_pos] = @as(u8, @intCast(lit_len)) << 4;
            }
            @memcpy(output[op .. op + lit_len], input[anchor .. anchor + lit_len]);
            op += lit_len;
        }
        while (true) {
            std.mem.writeInt(u16, output[op..][0..2], @intCast(ip - match), .little);
            op += 2;
            const match_len = kernels.matchLen8(input, match + min_match, ip + min_match, match_limit - ip);
            ip += match_len + min_match;
            if (match_len >= ml_mask) {
                output[token_pos] += ml_mask;
                var rest = match_len - ml_mask;
                while (rest >= 255) : (rest -= 255) {
                    output[op] = 255;
                    op += 1;
                }
                output[op] = @intCast(rest);
                op += 1;
            } else {
                output[token_pos] += @as(u8, @intCast(match_len));
            }
            anchor = ip;
            if (ip >= mflimit_plus_one) break :outer;
            table[hash4(std.mem.readInt(u32, input[ip - 2 ..][0..4], .little))] = @intCast(ip - 1);
            const h = hash4(std.mem.readInt(u32, input[ip..][0..4], .little));
            match_index = table[h];
            table[h] = @intCast(ip + 1);
            if (match_index != 0) {
                match_index -= 1;
                if (match_index < ip and match_index + distance_max >= ip and std.mem.readInt(u32, input[match_index..][0..4], .little) == std.mem.readInt(u32, input[ip..][0..4], .little)) {
                    match = match_index;
                    token_pos = op;
                    op += 1;
                    output[token_pos] = 0;
                    continue;
                }
            }
            break;
        }
    }
    return emitLastLiterals(input[anchor..], output, op);
}

fn emitLastLiterals(literals: []const u8, output: []u8, op_start: usize) usize {
    var op = op_start;
    const lit_len = literals.len;
    if (lit_len >= run_mask) {
        output[op] = run_mask << 4;
        op += 1;
        var rest = lit_len - run_mask;
        while (rest >= 255) : (rest -= 255) {
            output[op] = 255;
            op += 1;
        }
        output[op] = @intCast(rest);
        op += 1;
    } else {
        output[op] = @as(u8, @intCast(lit_len)) << 4;
        op += 1;
    }
    @memcpy(output[op .. op + lit_len], literals);
    return op + lit_len;
}

fn decompressBlock(input: []const u8, output: []u8) error{InvalidData}!usize {
    var ip: usize = 0;
    var op: usize = 0;
    while (true) {
        if (ip >= input.len) return error.InvalidData;
        const token = input[ip];
        ip += 1;
        var lit_len: usize = token >> 4;
        if (lit_len == run_mask) {
            while (true) {
                if (ip >= input.len) return error.InvalidData;
                const value = input[ip];
                ip += 1;
                if (value != 255 and lit_len > std.math.maxInt(usize) - 510) return error.InvalidData;
                lit_len += value;
                if (value != 255) break;
            }
        }
        if (input.len - ip < lit_len) return error.InvalidData;
        if (output.len - op < lit_len) return error.InvalidData;
        @memcpy(output[op .. op + lit_len], input[ip .. ip + lit_len]);
        op += lit_len;
        ip += lit_len;
        if (ip == input.len) break;
        if (input.len - ip < 2) return error.InvalidData;
        const offset = std.mem.readInt(u16, input[ip..][0..2], .little);
        ip += 2;
        if (offset == 0 or offset > op) return error.InvalidData;
        var match_len: usize = (token & 0x0f) + min_match;
        if ((token & 0x0f) == ml_mask) {
            while (true) {
                if (ip >= input.len) return error.InvalidData;
                const value = input[ip];
                ip += 1;
                if (value != 255 and match_len > std.math.maxInt(usize) - 510) return error.InvalidData;
                match_len += value;
                if (value != 255) break;
            }
        }
        if (output.len - op < match_len) return error.InvalidData;
        kernels.copyMatch(output, op, offset, std.math.cast(u32, match_len) orelse return error.InvalidData);
        op += match_len;
    }
    return op;
}

test "lz4 block roundtrip repetitive" {
    var prng = std.Random.DefaultPrng.init(0x1234);
    const random = prng.random();
    const input = try std.testing.allocator.alloc(u8, 300000);
    defer std.testing.allocator.free(input);
    for (input, 0..) |*byte, i| {
        byte.* = if (i % 97 < 60) @as(u8, @truncate(i / 4096)) else random.int(u8);
    }
    const scratch = try std.testing.allocator.alloc(u8, @max(encodeWorkspaceSize(), decodeWorkspaceSize()));
    defer std.testing.allocator.free(scratch);
    const bound = encodedSizeBound(input.len);
    const encoded = try std.testing.allocator.alloc(u8, bound);
    defer std.testing.allocator.free(encoded);
    const encoded_len = try encode(input, encoded, scratch, .{});
    const decoded = try std.testing.allocator.alloc(u8, input.len);
    defer std.testing.allocator.free(decoded);
    const produced = try decode(encoded[0..encoded_len], decoded, scratch, .{});
    try std.testing.expectEqual(input.len, produced);
    try std.testing.expectEqualSlices(u8, input, decoded);
}

test "lz4 block roundtrip incompressible stores raw" {
    var prng = std.Random.DefaultPrng.init(0x9e37);
    const random = prng.random();
    const input = try std.testing.allocator.alloc(u8, 100000);
    defer std.testing.allocator.free(input);
    for (input) |*byte| byte.* = random.int(u8);
    const scratch = try std.testing.allocator.alloc(u8, @max(encodeWorkspaceSize(), decodeWorkspaceSize()));
    defer std.testing.allocator.free(scratch);
    const encoded = try std.testing.allocator.alloc(u8, encodedSizeBound(input.len));
    defer std.testing.allocator.free(encoded);
    const encoded_len = try encode(input, encoded, scratch, .{});
    try std.testing.expectEqual(input.len + 27, encoded_len);
    const decoded = try std.testing.allocator.alloc(u8, input.len);
    defer std.testing.allocator.free(decoded);
    const produced = try decode(encoded[0..encoded_len], decoded, scratch, .{});
    try std.testing.expectEqualSlices(u8, input, decoded[0..produced]);
}

test "lz4 empty input roundtrip" {
    const scratch = try std.testing.allocator.alloc(u8, @max(encodeWorkspaceSize(), decodeWorkspaceSize()));
    defer std.testing.allocator.free(scratch);
    var encoded: [64]u8 = undefined;
    const encoded_len = try encode("", &encoded, scratch, .{});
    const produced = try decode(encoded[0..encoded_len], &.{}, scratch, .{});
    try std.testing.expectEqual(@as(usize, 0), produced);
}

test "lz4 corrupt blocks rejected" {
    const scratch = try std.testing.allocator.alloc(u8, @max(encodeWorkspaceSize(), decodeWorkspaceSize()));
    defer std.testing.allocator.free(scratch);
    var encoded: [256]u8 = undefined;
    const input = "abcabcabcabcabcabcabcabcabcabc";
    const encoded_len = try encode(input, &encoded, scratch, .{});
    var output: [64]u8 = undefined;
    try std.testing.expectError(error.InvalidData, decode(encoded[0 .. encoded_len - 3], &output, scratch, .{}));
    encoded[19] ^= 0xff;
    const result = decode(encoded[0..encoded_len], &output, scratch, .{});
    if (result) |produced| {
        try std.testing.expect(!std.mem.eql(u8, input, output[0..produced]));
    } else |err| {
        try std.testing.expect(err == error.InvalidData or err == error.IntegrityFailure);
    }
}
