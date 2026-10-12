const std = @import("std");

const kernels = @import("../../common/kernels.zig");
const bounds = @import("../../common/primitive/bounds.zig");
const checksum = @import("../../common/primitive/checksum.zig");
const failure_prim = @import("../../common/primitive/failure.zig");
const measurement = @import("../../common/primitive/measurement.zig");

const Failure = failure_prim.Failure;

// Frame layout follows the "LZ4 Frame Format Description" spec; the block codec
// mirrors the reference greedy parser in vendor/lz4.

pub const block_size_max: u32 = 4 * 1024 * 1024;
pub const block_size_default: u32 = block_size_max;

const magic: u32 = 0x184D2204;
const version_bits: u8 = 0x40; // LZ4 frame spec fixes the version field at 01.
const flag_block_independence: u8 = 0x20;
const flag_block_checksum: u8 = 0x10;
// Linked blocks reach at most a 16-bit offset back across block boundaries.
const window_size: usize = 64 * 1024;
const flag_content_size: u8 = 0x08;
const flag_content_checksum: u8 = 0x04;
const flag_dict_id: u8 = 0x01;
const uncompressed_block: u32 = 0x80000000;

const min_match = 4;
const match_finder_guard = 12;
const last_literals = 5;
const min_length = match_finder_guard + 1;
const lit_len_mask = 15;
const match_len_mask = 15;
const skip_trigger = 6;
const distance_max: u32 = 65535;
const hash_log = 12;
const hash_size = 1 << hash_log;
const hash_prime: u32 = 2654435761;
// The LZ4HC matcher needs a wider hash plus a chain slot per position, so its
// tables cost more than the greedy tables. The chain window is the format's
// 64 KiB distance: a 32 KiB window aliases after 32768 positions and can never
// emit the offsets in (32768, 65535] (the reference's chainTable is 1<<16).
const hc_hash_log = 16;
const hc_hash_size = 1 << hc_hash_log;
const hc_mask = hc_hash_size - 1;
const header_size_max = 4 + 2 + 8 + 4 + 1;

pub const Options = struct {
    block_size: u32 = block_size_default,
    content_checksum: bool = true,
    block_checksum: bool = false,
    acceleration: u32 = 1,
    provider: checksum.Provider = checksum.default_provider,
    // Hash-chain search attempt budget per position, LZ4HC searchNum semantics
    // (0 keeps the default greedy parser).
    search_depth: u32 = 0,
    // Decode work ceiling charged as input plus produced bytes, mirroring the
    // adapter's bound so a one-pass read and the measured route agree.
    max_work: u64 = std.math.maxInt(u64),
};

// LZ4 length extension: a length at or above the 15 nibble cap emits 255
// bytes per the block format until the remainder fits one byte.
fn writeLengthExtension(output: []u8, op: *usize, length: usize) void {
    var rest = length;
    while (rest >= 255) : (rest -= 255) {
        output[op.*] = 255;
        op.* += 1;
    }
    output[op.*] = @intCast(rest);
    op.* += 1;
}

fn blockSizeCode(block_size: u32) Failure!u8 {
    return switch (block_size) {
        64 * 1024 => 4,
        256 * 1024 => 5,
        1024 * 1024 => 6,
        4 * 1024 * 1024 => 7,
        else => error.InvalidCall,
    };
}

pub fn encodeWorkspaceSize() usize {
    return (hash_size + 2 * hc_hash_size) * @sizeOf(u32) + blockCompressBound(block_size_max);
}

pub fn decodeWorkspaceSize() usize {
    // The 64 KiB history is part of the contract: dependent (linked) frames
    // reach into it across block boundaries.
    return block_size_max + window_size;
}

// Worst case: every block stores raw plus its size word. Compressed blocks stay
// under compressBound (n + n/255 + 16), so the stored path sets this bound.
pub fn encodedSizeBound(input_len: usize) usize {
    const blocks = input_len / block_size_max + 1;
    return header_size_max + 4 + input_len + input_len / 255 + blocks * 20 + checksum_length;
}

const checksum_length = 4;

fn blockCompressBound(block_len: usize) usize {
    return block_len + block_len / 255 + 16;
}

pub fn frameContentSize(input: []const u8) Failure!?u64 {
    if (input.len < 7) return error.InvalidData;
    if (std.mem.readInt(u32, input[0..4], .little) != magic) return error.InvalidData;
    const flags = input[4];
    if (flags & flag_content_size == 0) return null;
    if (input.len < 14) return error.InvalidData;
    return std.mem.readInt(u64, input[6..14], .little);
}

pub fn decodedSize(input: []const u8, scratch: []u8, options: Options) Failure!usize {
    var counter = measurement.Counter.init(null);
    return try decodeBlocks(input, &counter.writer, scratch, options.provider);
}

pub fn requiredSize(input: []const u8, scratch: []u8, options: Options) Failure!usize {
    // Exact encoded size: one counting encode pass, mirroring the measured policy.
    var counter = measurement.Counter.init(null);
    try encodeToWriter(input, &counter.writer, scratch, options);
    return measurement.measuredLength(&counter);
}

pub fn encode(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    var fixed = std.Io.Writer.fixed(output);
    try encodeToWriter(input, &fixed, scratch, options);
    return fixed.end;
}

pub fn decode(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    _ = scratch;
    return decodeBlocksInto(input, output, options);
}

pub fn decodeInPlace(input: []const u8, output: []u8, scratch: []u8, options: Options) Failure!usize {
    return decode(input, output, scratch, options);
}

// Blocks decode straight into the caller's span, so a read of a frame with a
// direct sink needs no counting pass and no per-block staging. A span overrun
// answers insufficient_capacity: the adapter re-runs the measured route, which
// separates a too-small sink from a corrupt stream. Dependent (linked) blocks
// read their history from the decoded span itself.
fn decodeBlocksInto(input: []const u8, output: []u8, options: Options) Failure!usize {
    if (input.len < 7) return error.InvalidData;
    if (std.mem.readInt(u32, input[0..4], .little) != magic) return error.InvalidData;
    const flags = input[4];
    if ((flags & 0xC0) != version_bits) return error.Unsupported;
    const linked = flags & flag_block_independence == 0;
    const block_size_byte = input[5];
    const block_code = (block_size_byte >> 4) & 0x07;
    if (block_code < 4 or block_code > 7) return error.InvalidData;
    const max_block: usize = @as(usize, 65536) << @intCast(2 * (@as(usize, block_code) - 4));
    var offset: usize = 6;
    var content_size: ?u64 = null;
    if (flags & flag_content_size != 0) {
        if (input.len < offset + 8) return error.InvalidData;
        content_size = std.mem.readInt(u64, input[offset..][0..8], .little);
        offset += 8;
    }
    // A dictionary ID declares an external dictionary the frame may
    // reference; without it, matches reaching before the frame start still
    // fail as invalid data below.
    if (flags & flag_dict_id != 0) offset += 4;
    if (input.len <= offset) return error.InvalidData;
    // Header_Checksum: the high byte of xxh32 over FLG..end-of-header.
    const stored_header_sum = input[offset];
    if (stored_header_sum != @as(u8, @truncate(checksum.xxh32With(options.provider, input[4..offset]) >> 8))) return error.IntegrityFailure;
    offset += 1;
    var content_hasher = checksum.XxHash32.bind(options.provider, 0);
    var total: usize = 0;
    while (true) {
        if (input.len < offset + 4) return error.InvalidData;
        const block_size_field = std.mem.readInt(u32, input[offset..][0..4], .little);
        offset += 4;
        if (block_size_field == 0) break;
        const is_stored = (block_size_field & uncompressed_block) != 0;
        const block_len: usize = @intCast(block_size_field & ~uncompressed_block);
        if (input.len < offset + block_len) return error.InvalidData;
        const block_data = input[offset .. offset + block_len];
        offset += block_len;
        if (flags & flag_block_checksum != 0) {
            if (input.len < offset + 4) return error.InvalidData;
            const stored_sum = std.mem.readInt(u32, input[offset..][0..4], .little);
            if (stored_sum != checksum.xxh32With(options.provider, block_data)) return error.IntegrityFailure;
            offset += 4;
        }
        const room = output.len - total;
        const prefix_len = if (linked) @min(total, window_size) else 0;
        const prefix = output[total - prefix_len .. total];
        if (is_stored) {
            if (block_len > max_block) return error.InvalidData;
            if (block_len > room) return error.InsufficientCapacity;
            @memcpy(output[total..][0..block_len], block_data);
            content_hasher.update(block_data);
            total += block_len;
        } else {
            const produced = decompressBlock(block_data, output[total..], prefix) catch |err| return switch (err) {
                error.InvalidData => error.InvalidData,
                error.OutputTooSmall => error.InsufficientCapacity,
            };
            content_hasher.update(output[total .. total + produced]);
            total += produced;
        }
        if (input.len + total > options.max_work) return error.ResourceLimit;
    }
    if (flags & flag_content_checksum != 0) {
        if (input.len < offset + 4) return error.InvalidData;
        const stored_sum = std.mem.readInt(u32, input[offset..][0..4], .little);
        if (stored_sum != content_hasher.final()) return error.IntegrityFailure;
        offset += 4;
    }
    if (offset != input.len) return error.InvalidData;
    if (content_size) |expected| {
        if (expected != total) return error.IntegrityFailure;
    }
    return total;
}

pub fn encodeToWriter(input: []const u8, output: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    if (scratch.len < encodeWorkspaceSize()) return error.InsufficientCapacity;
    const block_size_byte = try blockSizeCode(options.block_size) << 4;
    var acceleration = options.acceleration;
    if (acceleration < 1) acceleration = 1;
    output.writeInt(u32, magic, .little) catch return error.IoFailure;
    var flags: u8 = version_bits | flag_block_independence;
    if (options.block_checksum) flags |= flag_block_checksum;
    flags |= flag_content_size;
    if (options.content_checksum) flags |= flag_content_checksum;
    var header_hasher = checksum.XxHash32.bind(options.provider, 0);
    output.writeByte(flags) catch return error.IoFailure;
    header_hasher.update(&.{flags});
    output.writeByte(block_size_byte) catch return error.IoFailure;
    header_hasher.update(&.{block_size_byte});
    var size_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &size_bytes, input.len, .little);
    output.writeAll(&size_bytes) catch return error.IoFailure;
    header_hasher.update(&size_bytes);
    output.writeByte(@truncate(header_hasher.final() >> 8)) catch return error.IoFailure;
    const hash_table: []u32 = @alignCast(std.mem.bytesAsSlice(u32, scratch[0 .. hash_size * @sizeOf(u32)]));
    const hc_tables: []u32 = @alignCast(std.mem.bytesAsSlice(u32, scratch[hash_size * @sizeOf(u32) .. (hash_size + 2 * hc_hash_size) * @sizeOf(u32)]));
    const block_buffer = scratch[(hash_size + 2 * hc_hash_size) * @sizeOf(u32) ..];
    var offset: usize = 0;
    while (offset < input.len) {
        const block_len: usize = @min(input.len - offset, options.block_size);
        const block = input[offset .. offset + block_len];
        const compressed_len = if (options.search_depth == 0)
            compressBlock(block, block_buffer, hash_table, acceleration)
        else
            compressBlockHc(block, block_buffer, hc_tables[0..hc_hash_size], hc_tables[hc_hash_size..], options.search_depth);
        if (compressed_len >= block_len) {
            output.writeInt(u32, uncompressed_block | (std.math.cast(u32, block_len) orelse return error.ResourceLimit), .little) catch return error.IoFailure;
            output.writeAll(block) catch return error.IoFailure;
            if (options.block_checksum) output.writeInt(u32, checksum.xxh32With(options.provider, block), .little) catch return error.IoFailure;
        } else {
            output.writeInt(u32, std.math.cast(u32, compressed_len) orelse return error.ResourceLimit, .little) catch return error.IoFailure;
            output.writeAll(block_buffer[0..compressed_len]) catch return error.IoFailure;
            if (options.block_checksum) output.writeInt(u32, checksum.xxh32With(options.provider, block_buffer[0..compressed_len]), .little) catch return error.IoFailure;
        }
        offset += block_len;
    }
    if (input.len == 0) {
        // One empty block (single zero token) keeps the block stream well-formed.
        output.writeInt(u32, 1, .little) catch return error.IoFailure;
        output.writeByte(0) catch return error.IoFailure;
    }
    output.writeInt(u32, 0, .little) catch return error.IoFailure;
    if (options.content_checksum) output.writeInt(u32, checksum.xxh32With(options.provider, input), .little) catch return error.IoFailure;
}

pub fn decodeToWriter(input: []const u8, output: *std.Io.Writer, scratch: []u8, options: Options) Failure!void {
    _ = try decodeBlocks(input, output, scratch, options.provider);
}

fn decodeBlocks(input: []const u8, output: *std.Io.Writer, scratch: []u8, provider: checksum.Provider) Failure!usize {
    if (scratch.len < decodeWorkspaceSize()) return error.InsufficientCapacity;
    if (input.len < 7) return error.InvalidData;
    if (std.mem.readInt(u32, input[0..4], .little) != magic) return error.InvalidData;
    const flags = input[4];
    if ((flags & 0xC0) != version_bits) return error.Unsupported;
    const linked = flags & flag_block_independence == 0;
    const block_size_byte = input[5];
    const block_code = (block_size_byte >> 4) & 0x07;
    if (block_code < 4 or block_code > 7) return error.InvalidData;
    const max_block: usize = @as(usize, 65536) << @intCast(2 * (@as(usize, block_code) - 4));
    var offset: usize = 6;
    var content_size: ?u64 = null;
    if (flags & flag_content_size != 0) {
        if (input.len < offset + 8) return error.InvalidData;
        content_size = std.mem.readInt(u64, input[offset..][0..8], .little);
        offset += 8;
    }
    // A dictionary ID declares an external dictionary the frame may
    // reference; without it, matches reaching before the frame start still
    // fail as invalid data in the block decode.
    if (flags & flag_dict_id != 0) offset += 4;
    if (input.len <= offset) return error.InvalidData;
    // Header_Checksum: the high byte of xxh32 over FLG..end-of-header.
    const stored_header_sum = input[offset];
    if (stored_header_sum != @as(u8, @truncate(checksum.xxh32With(provider, input[4..offset]) >> 8))) return error.IntegrityFailure;
    offset += 1;
    var content_hasher = checksum.XxHash32.bind(provider, 0);
    const block_buffer = scratch[0..max_block];
    const history = scratch[max_block..][0..window_size];
    var history_len: usize = 0;
    var total: usize = 0;
    while (true) {
        if (input.len < offset + 4) return error.InvalidData;
        const block_size_field = std.mem.readInt(u32, input[offset..][0..4], .little);
        offset += 4;
        if (block_size_field == 0) break;
        const is_stored = (block_size_field & uncompressed_block) != 0;
        const block_len: usize = @intCast(block_size_field & ~uncompressed_block);
        if (input.len < offset + block_len) return error.InvalidData;
        const block_data = input[offset .. offset + block_len];
        offset += block_len;
        if (flags & flag_block_checksum != 0) {
            if (input.len < offset + 4) return error.InvalidData;
            const stored_sum = std.mem.readInt(u32, input[offset..][0..4], .little);
            if (stored_sum != checksum.xxh32With(provider, block_data)) return error.IntegrityFailure;
            offset += 4;
        }
        const produced: usize = blk: {
            if (is_stored) {
                if (block_len > max_block) return error.InvalidData;
                output.writeAll(block_data) catch return error.IoFailure;
                content_hasher.update(block_data);
                break :blk block_len;
            }
            const decoded = decompressBlock(block_data, block_buffer, history[0..history_len]) catch return error.InvalidData;
            output.writeAll(block_buffer[0..decoded]) catch return error.IoFailure;
            content_hasher.update(block_buffer[0..decoded]);
            break :blk decoded;
        };
        total = try bounds.addUsize(total, produced);
        if (linked) {
            const produced_bytes = if (is_stored) block_data else block_buffer[0..produced];
            if (produced_bytes.len >= window_size) {
                @memcpy(history, produced_bytes[produced_bytes.len - window_size ..][0..window_size]);
                history_len = window_size;
            } else {
                const keep = @min(history_len, window_size - produced_bytes.len);
                std.mem.copyForwards(u8, history[0..keep], history[history_len - keep ..][0..keep]);
                @memcpy(history[keep..][0..produced_bytes.len], produced_bytes);
                history_len = keep + produced_bytes.len;
            }
        }
    }
    if (flags & flag_content_checksum != 0) {
        if (input.len < offset + 4) return error.InvalidData;
        const stored_sum = std.mem.readInt(u32, input[offset..][0..4], .little);
        if (stored_sum != content_hasher.final()) return error.IntegrityFailure;
        offset += 4;
    }
    if (offset != input.len) return error.InvalidData;
    if (content_size) |expected| {
        if (expected != total) return error.IntegrityFailure;
    }
    return total;
}

fn hash4(value: u32) usize {
    return (value *% hash_prime) >> @intCast(32 - hash_log);
}

// Mirrors LZ4_compress_generic_validated: the carried hash keeps fresh searches from self-matching.
// A self-match would emit the corrupt offset 0 the reference never produces.
// Exposed for the session boundary's stepped encode: compresses one
// independent block; the caller owns the frame framing.
pub fn compressBlock(input: []const u8, output: []u8, hash_table: []u32, acceleration: u32) usize {
    @memset(hash_table, 0);
    var op: usize = 0;
    const input_len = input.len;
    if (input_len == 0) {
        output[0] = 0;
        return 1;
    }
    if (input_len < min_length) {
        op = emitLastLiterals(input, output, 0);
        return op;
    }
    var ip: usize = 1;
    var anchor: usize = 0;
    const search_stop = input_len - match_finder_guard + 1;
    const match_limit = input_len - last_literals;
    var token_pos: usize = 0;
    hash_table[hash4(std.mem.readInt(u32, input[0..4], .little))] = 1;
    var forward_hash = hash4(std.mem.readInt(u32, input[1..][0..4], .little));
    outer: while (true) {
        var match: usize = 0;
        var match_index: usize = 0;
        {
            var forward_ip = ip;
            var step: usize = 1;
            var search_match_nb = acceleration << skip_trigger;
            while (true) {
                const hash_slot = forward_hash;
                ip = forward_ip;
                forward_ip += step;
                step = search_match_nb >> skip_trigger;
                search_match_nb += 1;
                if (forward_ip > search_stop) break :outer;
                forward_hash = hash4(std.mem.readInt(u32, input[forward_ip..][0..4], .little));
                match_index = hash_table[hash_slot];
                hash_table[hash_slot] = @intCast(ip + 1);
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
            if (lit_len >= lit_len_mask) {
                output[token_pos] = lit_len_mask << 4;
                writeLengthExtension(output, &op, lit_len - lit_len_mask);
            } else {
                output[token_pos] = @as(u8, @intCast(lit_len)) << 4;
            }
            @memcpy(output[op .. op + lit_len], input[anchor .. anchor + lit_len]);
            op += lit_len;
        }
        while (true) {
            std.mem.writeInt(u16, output[op..][0..2], @intCast(ip - match), .little);
            op += 2;
            // The match must end by match_limit so the last 5 bytes stay
            // literals; the compared span starts past the 4-byte prefix, so
            // the cap is match_limit - ip - min_match.
            const match_len = kernels.matchLen8(input, match + min_match, ip + min_match, match_limit - ip - min_match);
            ip += match_len + min_match;
            if (match_len >= match_len_mask) {
                output[token_pos] += match_len_mask;
                writeLengthExtension(output, &op, match_len - match_len_mask);
            } else {
                output[token_pos] += @as(u8, @intCast(match_len));
            }
            anchor = ip;
            if (ip >= search_stop) break :outer;
            hash_table[hash4(std.mem.readInt(u32, input[ip - 2 ..][0..4], .little))] = @intCast(ip - 1);
            const hash_slot = hash4(std.mem.readInt(u32, input[ip..][0..4], .little));
            match_index = hash_table[hash_slot];
            hash_table[hash_slot] = @intCast(ip + 1);
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

// LZ4HC-class parser: per-bucket chains with a one-position lazy step.
// Attempt budget bounds every chain walk.
fn compressBlockHc(input: []const u8, output: []u8, head: []u32, chain: []u32, search_depth: u32) usize {
    @memset(head, 0);
    const input_len = input.len;
    if (input_len < min_length) return emitLastLiterals(input, output, 0);
    var op: usize = 0;
    var anchor: usize = 0;
    var ip: usize = 0;
    const search_stop = input_len - match_finder_guard;
    const match_limit = input_len - last_literals;
    var attempts = search_depth;

    while (true) {
        var best = hcSearch(input, head, chain, ip, &attempts, match_limit);
        if (best.match_len == 0) {
            ip += 1;
            if (ip > search_stop) break;
            attempts = search_depth;
            continue;
        }
        if (best.match_len < match_limit - ip and ip + 1 <= search_stop) {
            var probe_attempts = search_depth;
            const probe = hcSearch(input, head, chain, ip + 1, &probe_attempts, match_limit);
            if (probe.match_len > best.match_len) {
                ip += 1;
                best = probe;
            }
        }
        op = emitSequence(input, output, op, anchor, ip, best.match_index, best.match_len);
        ip += best.match_len;
        anchor = ip;
        if (ip > search_stop) break;
        attempts = search_depth;
    }
    return emitLastLiterals(input[anchor..], output, op);
}

const HcMatch = struct { match_index: usize, match_len: usize };

// Insert-then-search per LZ4HC_InsertAndGetWiderMatch, so the walk never self-matches.
// Decreasing chains plus the window check bound every walk.
fn hcSearch(input: []const u8, head: []u32, chain: []u32, ip: usize, attempts: *u32, match_limit: usize) HcMatch {
    const hash_slot = hash4(std.mem.readInt(u32, input[ip..][0..4], .little));
    var candidate = head[hash_slot];
    chain[ip & hc_mask] = candidate;
    head[hash_slot] = @intCast(ip + 1);
    const needle = std.mem.readInt(u32, input[ip..][0..4], .little);
    var best: HcMatch = .{ .match_index = 0, .match_len = 0 };
    while (candidate != 0 and attempts.* > 0) : (attempts.* -= 1) {
        const index = candidate - 1;
        candidate = chain[index & hc_mask];
        if (index + distance_max < ip) break;
        if (std.mem.readInt(u32, input[index..][0..4], .little) != needle) continue;
        const extra = kernels.matchLen8(input, index + min_match, ip + min_match, match_limit - ip);
        if (min_match + extra > best.match_len) {
            best = .{ .match_index = index, .match_len = min_match + extra };
            if (ip + best.match_len >= match_limit) break;
        }
    }
    return best;
}

fn emitSequence(input: []const u8, output: []u8, op_start: usize, anchor: usize, ip: usize, match_index: usize, match_len: usize) usize {
    var op = op_start;
    const token_pos = op;
    op += 1;
    const lit_len = ip - anchor;
    if (lit_len >= lit_len_mask) {
        output[token_pos] = lit_len_mask << 4;
        writeLengthExtension(output, &op, lit_len - lit_len_mask);
    } else {
        output[token_pos] = @as(u8, @intCast(lit_len)) << 4;
    }
    @memcpy(output[op .. op + lit_len], input[anchor..ip]);
    op += lit_len;
    std.mem.writeInt(u16, output[op..][0..2], @intCast(ip - match_index), .little);
    op += 2;
    const encoded_match_len = match_len - min_match;
    if (encoded_match_len >= match_len_mask) {
        output[token_pos] += match_len_mask;
        writeLengthExtension(output, &op, encoded_match_len - match_len_mask);
    } else {
        output[token_pos] += @as(u8, @intCast(encoded_match_len));
    }
    return op;
}

fn emitLastLiterals(literals: []const u8, output: []u8, op_start: usize) usize {
    var op = op_start;
    const lit_len = literals.len;
    if (lit_len >= lit_len_mask) {
        output[op] = lit_len_mask << 4;
        op += 1;
        writeLengthExtension(output, &op, lit_len - lit_len_mask);
    } else {
        output[op] = @as(u8, @intCast(lit_len)) << 4;
        op += 1;
    }
    @memcpy(output[op .. op + lit_len], literals);
    return op + lit_len;
}

// Decompresses one block. `prefix` is up to 64 KiB of already-decoded
// history (empty for independent blocks or the first block of a dependent
// frame); matches may reach into it when the frame links blocks.
// Exposed for the session boundary's stepped decode: decodes one block with
// `prefix` as up-to-64 KiB of linked-block history.
pub fn decompressBlock(input: []const u8, output: []u8, prefix: []const u8) error{ InvalidData, OutputTooSmall }!usize {
    var ip: usize = 0;
    var op: usize = 0;
    while (true) {
        if (ip >= input.len) return error.InvalidData;
        const token = input[ip];
        ip += 1;
        var lit_len: usize = token >> 4;
        if (lit_len == lit_len_mask) {
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
        if (output.len - op < lit_len) return error.OutputTooSmall;
        if (lit_len <= 16 and input.len - ip >= 16 and output.len - op >= 16) {
            // Short literal runs dominate, so the reference copies 16 bytes unconditionally
            // behind an end guard rather than call memcpy per sequence.
            output[op..][0..16].* = input[ip..][0..16].*;
        } else {
            @memcpy(output[op .. op + lit_len], input[ip .. ip + lit_len]);
        }
        op += lit_len;
        ip += lit_len;
        if (ip == input.len) break;
        if (input.len - ip < 2) return error.InvalidData;
        const offset = std.mem.readInt(u16, input[ip..][0..2], .little);
        ip += 2;
        var match_len: usize = (token & 0x0f) + min_match;
        if ((token & 0x0f) == match_len_mask) {
            while (true) {
                if (ip >= input.len) return error.InvalidData;
                const value = input[ip];
                ip += 1;
                if (value != 255 and match_len > std.math.maxInt(usize) - 510) return error.InvalidData;
                match_len += value;
                if (value != 255) break;
            }
        }
        if (output.len - op < match_len) return error.OutputTooSmall;
        if (offset == 0) return error.InvalidData;
        if (offset <= op) {
            kernels.copyMatch(output, op, offset, std.math.cast(u32, match_len) orelse return error.InvalidData);
        } else {
            // The match reaches before this block into the linked history.
            const reach = offset - op;
            if (reach > prefix.len) return error.InvalidData;
            var src_pos: usize = prefix.len - reach;
            var remaining = match_len;
            var dst = op;
            while (remaining > 0) {
                if (src_pos < prefix.len) {
                    const n = @min(remaining, prefix.len - src_pos);
                    @memcpy(output[dst..][0..n], prefix[src_pos..][0..n]);
                    dst += n;
                    src_pos += n;
                    remaining -= n;
                } else {
                    // The source crossed into this block; the offset against
                    // freshly written bytes stays constant, and chunking at
                    // the current distance keeps overlapping copies correct.
                    const rel = src_pos - prefix.len;
                    const n = @min(remaining, dst - rel);
                    @memcpy(output[dst..][0..n], output[rel..][0..n]);
                    dst += n;
                    src_pos += n;
                    remaining -= n;
                }
            }
        }
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
        // A corrupted block either fails its input-side checks or overruns the span,
        // which the leaf reports as insufficient_capacity and the adapter resolves.
        try std.testing.expect(err == error.InvalidData or err == error.IntegrityFailure or err == error.InsufficientCapacity);
    }
}

test "lz4 hc roundtrip beats greedy on repetitive data" {
    var prng = std.Random.DefaultPrng.init(0x5a);
    const random = prng.random();
    const input = try std.testing.allocator.alloc(u8, 300000);
    defer std.testing.allocator.free(input);
    // Mixed periodic content separates hash-chain search from greedy skips.
    for (input, 0..) |*byte, i| {
        byte.* = if (i % 211 < 150) @as(u8, @truncate(i / 8192)) else random.int(u8);
    }
    const scratch = try std.testing.allocator.alloc(u8, @max(encodeWorkspaceSize(), decodeWorkspaceSize()));
    defer std.testing.allocator.free(scratch);
    const bound = encodedSizeBound(input.len);
    const greedy = try std.testing.allocator.alloc(u8, bound);
    defer std.testing.allocator.free(greedy);
    const hc = try std.testing.allocator.alloc(u8, bound);
    defer std.testing.allocator.free(hc);
    const greedy_len = try encode(input, greedy, scratch, .{});
    const hc_len = try encode(input, hc, scratch, .{ .search_depth = 256 });
    try std.testing.expect(hc_len < greedy_len);
    const decoded = try std.testing.allocator.alloc(u8, input.len);
    defer std.testing.allocator.free(decoded);
    const produced = try decode(hc[0..hc_len], decoded, scratch, .{});
    try std.testing.expectEqual(input.len, produced);
    try std.testing.expectEqualSlices(u8, input, decoded);
}

test "lz4 hc is deterministic" {
    var prng = std.Random.DefaultPrng.init(0x77);
    const random = prng.random();
    const input = try std.testing.allocator.alloc(u8, 150000);
    defer std.testing.allocator.free(input);
    for (input) |*byte| byte.* = random.int(u8) & 0x3f;
    const scratch = try std.testing.allocator.alloc(u8, @max(encodeWorkspaceSize(), decodeWorkspaceSize()));
    defer std.testing.allocator.free(scratch);
    const bound = encodedSizeBound(input.len);
    const first = try std.testing.allocator.alloc(u8, bound);
    defer std.testing.allocator.free(first);
    const second = try std.testing.allocator.alloc(u8, bound);
    defer std.testing.allocator.free(second);
    const first_len = try encode(input, first, scratch, .{ .search_depth = 64 });
    const second_len = try encode(input, second, scratch, .{ .search_depth = 64 });
    try std.testing.expectEqual(first_len, second_len);
    try std.testing.expectEqualSlices(u8, first[0..first_len], second[0..second_len]);
}

test "lz4 hc roundtrip incompressible" {
    var prng = std.Random.DefaultPrng.init(0x9e37);
    const random = prng.random();
    const input = try std.testing.allocator.alloc(u8, 100000);
    defer std.testing.allocator.free(input);
    for (input) |*byte| byte.* = random.int(u8);
    const scratch = try std.testing.allocator.alloc(u8, @max(encodeWorkspaceSize(), decodeWorkspaceSize()));
    defer std.testing.allocator.free(scratch);
    const encoded = try std.testing.allocator.alloc(u8, encodedSizeBound(input.len));
    defer std.testing.allocator.free(encoded);
    const encoded_len = try encode(input, encoded, scratch, .{ .search_depth = 256 });
    const decoded = try std.testing.allocator.alloc(u8, input.len);
    defer std.testing.allocator.free(decoded);
    const produced = try decode(encoded[0..encoded_len], decoded, scratch, .{});
    try std.testing.expectEqualSlices(u8, input, decoded[0..produced]);
}

test "lz4 frame verifies content size and header checksum" {
    const allocator = std.testing.allocator;
    const input = "lz4 frame with content size and header checksum, repeated: abcabcabcabc";
    const scratch = try allocator.alloc(u8, encodeWorkspaceSize());
    defer allocator.free(scratch);
    const bound = encodedSizeBound(input.len);
    const encoded = try allocator.alloc(u8, bound);
    defer allocator.free(encoded);
    const encoded_len = try encode(input, encoded, scratch, .{});
    const decode_scratch = try allocator.alloc(u8, decodeWorkspaceSize());
    defer allocator.free(decode_scratch);
    const output = try allocator.alloc(u8, input.len);
    defer allocator.free(output);
    const decoded = try decode(encoded[0..encoded_len], output, decode_scratch, .{});
    try std.testing.expectEqualSlices(u8, input, output[0..decoded]);

    // The encoder always writes Content_Size; corrupting it must fail.
    // Header layout: magic(4) FLG(1) BD(1) Content_Size(8) Header_Checksum(1).
    var bad_size = try allocator.dupe(u8, encoded[0..encoded_len]);
    defer allocator.free(bad_size);
    bad_size[6] ^= 0x01;
    try std.testing.expectError(error.IntegrityFailure, decode(bad_size, output, decode_scratch, .{}));

    // Corrupting the Header_Checksum byte itself must fail too.
    var bad_sum = try allocator.dupe(u8, encoded[0..encoded_len]);
    defer allocator.free(bad_sum);
    bad_sum[14] ^= 0xFF;
    try std.testing.expectError(error.IntegrityFailure, decode(bad_sum, output, decode_scratch, .{}));
}

test "lz4 dependent blocks reach into the previous block" {
    const allocator = std.testing.allocator;
    // Frame: 64 KiB block size, linked blocks, content size present.
    // Block 0 is stored (64 bytes of 0x11). Block 1 is compressed: four
    // literals then an 8-byte match whose 68-byte offset reaches back into
    // block 0's history.
    var frame: [256]u8 = undefined;
    var len: usize = 0;
    std.mem.writeInt(u32, frame[len..][0..4], magic, .little);
    len += 4;
    const flags: u8 = version_bits | flag_content_size;
    frame[len] = flags;
    len += 1;
    frame[len] = 4 << 4; // BD: 64 KiB max block
    len += 1;
    std.mem.writeInt(u64, frame[len..][0..8], 77, .little);
    len += 8;
    frame[len] = @truncate(checksum.xxh32With(checksum.default_provider, frame[4..len]) >> 8);
    len += 1;
    std.mem.writeInt(u32, frame[len..][0..4], uncompressed_block | 64, .little);
    len += 4;
    @memset(frame[len..][0..64], 0x11);
    len += 64;
    // Sequence 1: four literals then an 8-byte match reaching 68 back into
    // block 0. Sequence 2 (final): one literal, as the block format requires.
    const block1 = [_]u8{ 0x44, 'a', 'b', 'c', 'd', 68, 0, 0x10, 'z' };
    std.mem.writeInt(u32, frame[len..][0..4], block1.len, .little);
    len += 4;
    @memcpy(frame[len..][0..block1.len], &block1);
    len += block1.len;
    std.mem.writeInt(u32, frame[len..][0..4], 0, .little);
    len += 4;

    const decode_scratch = try allocator.alloc(u8, decodeWorkspaceSize());
    defer allocator.free(decode_scratch);
    var output: [77]u8 = undefined;
    const decoded = try decode(frame[0..len], &output, decode_scratch, .{});
    try std.testing.expectEqual(@as(usize, 77), decoded);
    try std.testing.expectEqualSlices(u8, "abcd", output[64..68]);
    for (output[68..76]) |byte| try std.testing.expectEqual(@as(u8, 0x11), byte);
    try std.testing.expectEqual(@as(u8, 'z'), output[76]);
    const expected_block0: [64]u8 = @splat(0x11);
    try std.testing.expectEqualSlices(u8, &expected_block0, output[0..64]);

    // A match reaching before the frame start (no history there) is invalid.
    var bad = frame;
    const block1_at = 4 + 1 + 1 + 8 + 1 + 4 + 64 + 4;
    bad[block1_at + 5] = 200; // offset 200 > 4 + 64 of available history
    try std.testing.expectError(error.InvalidData, decode(bad[0..len], &output, decode_scratch, .{}));
}

test "lz4 dictionary id flag parses and skips" {
    const allocator = std.testing.allocator;
    var frame: [128]u8 = undefined;
    var len: usize = 0;
    std.mem.writeInt(u32, frame[len..][0..4], magic, .little);
    len += 4;
    const flags: u8 = version_bits | flag_content_size | flag_dict_id;
    frame[len] = flags;
    len += 1;
    frame[len] = 7 << 4; // BD: 4 MiB max block
    len += 1;
    std.mem.writeInt(u64, frame[len..][0..8], 5, .little);
    len += 8;
    std.mem.writeInt(u32, frame[len..][0..4], 0xDEADBEEF, .little); // dictionary ID
    len += 4;
    frame[len] = @truncate(checksum.xxh32With(checksum.default_provider, frame[4..len]) >> 8);
    len += 1;
    std.mem.writeInt(u32, frame[len..][0..4], uncompressed_block | 5, .little);
    len += 4;
    @memcpy(frame[len..][0..5], "hello");
    len += 5;
    std.mem.writeInt(u32, frame[len..][0..4], 0, .little);
    len += 4;

    const decode_scratch = try allocator.alloc(u8, decodeWorkspaceSize());
    defer allocator.free(decode_scratch);
    var output: [5]u8 = undefined;
    const decoded = try decode(frame[0..len], &output, decode_scratch, .{});
    try std.testing.expectEqual(@as(usize, 5), decoded);
    try std.testing.expectEqualSlices(u8, "hello", &output);

    // The dictionary ID participates in the header checksum.
    var bad = frame;
    bad[4 + 1 + 1 + 8] ^= 0x01;
    try std.testing.expectError(error.IntegrityFailure, decode(bad[0..len], &output, decode_scratch, .{}));
}
