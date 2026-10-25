const std = @import("std");

const kernels = @import("../../../common/kernels.zig");
const bounds = @import("../../../common/primitive/bounds.zig");
const checksum = @import("../../../common/primitive/checksum.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const measurement = @import("../../../common/primitive/measurement.zig");

const Exception = exception_prim.Exception;

// Frame layout follows the "LZ4 Frame Format Description" spec; the block codec
// mirrors the reference greedy parser in vendor/lz4.

pub const block_size_max: u32 = 4 * 1024 * 1024;
pub const block_size_default: u32 = block_size_max;

const magic: u32 = 0x184D2204;
// The pre-1.8 legacy format: magic (low nibble carried a version digit),
// then independent raw LZ4 blocks, no header descriptor.
const legacy_magic: u32 = 0x184C2102;
// No valid block's size word exceeds 8 MiB, so a larger word can only
// be the next frame's magic.
const legacy_block_size: usize = 8 * 1024 * 1024;
const version_bits: u8 = 0x40; // LZ4 frame spec fixes the version field at 01.
const flag_block_independence: u8 = 0x20;
const flag_block_checksum: u8 = 0x10;
// Linked blocks reach at most a 16-bit offset back across block boundaries.
const window_size: usize = 64 * 1024;
const flag_content_size: u8 = 0x08;
const flag_content_checksum: u8 = 0x04;
const flag_dict_id: u8 = 0x01;
// FLG bit 1 and BD bit 7 plus BD's low nibble stay zero; the reference
// decoder rejects anything else.
const flag_reserved: u8 = 0x02;
const bd_reserved_mask: u8 = 0x8F;
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
// HC needs the format's 64 KiB chain window; a 32 KiB window aliases and
// cannot emit offsets above 32767.
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
    // Decode work ceiling, charged as input plus produced bytes, mirrors
    // the adapter's bound so both routes agree.
    max_work: u64 = std.math.maxInt(u64),
};

// The block format extends a saturated 15 length nibble with 255 bytes
// until the remainder fits one byte.
fn writeLengthExtension(output: []u8, op: *usize, length: usize) void {
    var rest = length;
    while (rest >= 255) : (rest -= 255) {
        output[op.*] = 255;
        op.* += 1;
    }
    output[op.*] = @intCast(rest);
    op.* += 1;
}

fn blockSizeCode(block_size: u32) Exception!u8 {
    return switch (block_size) {
        64 * 1024 => 4,
        256 * 1024 => 5,
        1024 * 1024 => 6,
        4 * 1024 * 1024 => 7,
        else => error.CallException,
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

// Worst case: every block stores raw plus its size word; compressed
// blocks stay under compressBound (n + n/255 + 16).
pub fn encodedSizeBound(input_len: usize) usize {
    const blocks = input_len / block_size_max + 1;
    return header_size_max + 4 + input_len + input_len / 255 + blocks * 20 + checksum_length;
}

const checksum_length = 4;

fn blockCompressBound(block_len: usize) usize {
    return block_len + block_len / 255 + 16;
}

pub fn frameContentSize(input: []const u8) Exception!?u64 {
    if (input.len < 7) return error.DataException;
    if (std.mem.readInt(u32, input[0..4], .little) != magic) return error.DataException;
    const flags = input[4];
    if (flags & flag_content_size == 0) return null;
    if (input.len < 14) return error.DataException;
    return std.mem.readInt(u64, input[6..14], .little);
}

pub fn decodedSize(input: []const u8, scratch: []u8, options: Options) Exception!usize {
    var counter = measurement.Counter.init(null);
    return try decodeBlocks(input, &counter.writer, scratch, options.provider, options.max_work);
}

pub fn requiredSize(input: []const u8, scratch: []u8, options: Options) Exception!usize {
    // Exact encoded size: one counting encode pass, mirroring the measured policy.
    var counter = measurement.Counter.init(null);
    try encodeToWriter(input, &counter.writer, scratch, options);
    return measurement.measuredLength(&counter);
}

pub fn encode(input: []const u8, output: []u8, scratch: []u8, options: Options) Exception!usize {
    var fixed = std.Io.Writer.fixed(output);
    try encodeToWriter(input, &fixed, scratch, options);
    return fixed.end;
}

pub fn decode(input: []const u8, output: []u8, scratch: []u8, options: Options) Exception!usize {
    _ = scratch;
    return decodeBlocksInto(input, output, options);
}

pub fn decodeInPlace(input: []const u8, output: []u8, scratch: []u8, options: Options) Exception!usize {
    return decode(input, output, scratch, options);
}

const FrameDescriptor = struct {
    flags: u8,
    linked: bool,
    max_block: usize,
    content_size: ?u64,
    offset: usize, // First block-size field.
};

// FLG/BD validation, optional content size and dictionary ID, and the header
// checksum read identically on every modern-frame decode route.
fn readFrameDescriptor(input: []const u8, provider: checksum.Provider) Exception!FrameDescriptor {
    if (input.len < 7) return error.DataException;
    if (std.mem.readInt(u32, input[0..4], .little) != magic) return error.DataException;
    const flags = input[4];
    if ((flags & 0xC0) != version_bits) return error.UnsupportedException;
    if (flags & flag_reserved != 0) return error.DataException;
    const block_size_byte = input[5];
    if (block_size_byte & bd_reserved_mask != 0) return error.DataException;
    const block_code = (block_size_byte >> 4) & 0x07;
    if (block_code < 4 or block_code > 7) return error.DataException;
    const max_block: usize = @as(usize, 65536) << @intCast(2 * (@as(usize, block_code) - 4));
    var offset: usize = 6;
    var content_size: ?u64 = null;
    if (flags & flag_content_size != 0) {
        if (input.len < offset + 8) return error.DataException;
        content_size = std.mem.readInt(u64, input[offset..][0..8], .little);
        offset += 8;
    }
    // The dictionary is external and stays unresolved; matches reaching
    // before the frame start fail in the block decode.
    if (flags & flag_dict_id != 0) offset += 4;
    if (input.len <= offset) return error.DataException;
    // Header_Checksum: the high byte of xxh32 over FLG..end-of-header.
    const stored_header_sum = input[offset];
    if (stored_header_sum != @as(u8, @truncate(checksum.xxh32With(provider, input[4..offset]) >> 8))) return error.IntegrityException;
    offset += 1;
    return .{
        .flags = flags,
        .linked = flags & flag_block_independence == 0,
        .max_block = max_block,
        .content_size = content_size,
        .offset = offset,
    };
}

// A span overrun answers insufficient_capacity: the adapter re-runs the
// measured route, separating a too-small sink from a corrupt stream.
fn decodeBlocksInto(input: []const u8, output: []u8, options: Options) Exception!usize {
    if (input.len < 4) return error.DataException;
    const magic_value = std.mem.readInt(u32, input[0..4], .little);
    // The legacy frame format (pre-1.8): fixed magic, then independent LZ4
    // blocks with no header fields, checksums, or block-size descriptor.
    if (magic_value >= legacy_magic and magic_value <= legacy_magic + 7)
        return decodeLegacyBlocksInto(input, output, options);
    const header = try readFrameDescriptor(input, options.provider);
    const flags = header.flags;
    const max_block = header.max_block;
    var offset = header.offset;
    const content_size = header.content_size;
    var content_hasher = checksum.XxHash32.bind(options.provider, 0);
    var total: usize = 0;
    while (true) {
        if (input.len < offset + 4) return error.DataException;
        const block_size_field = std.mem.readInt(u32, input[offset..][0..4], .little);
        offset += 4;
        if (block_size_field == 0) break;
        const is_stored = (block_size_field & uncompressed_block) != 0;
        const block_len: usize = @intCast(block_size_field & ~uncompressed_block);
        if (input.len < offset + block_len) return error.DataException;
        const block_data = input[offset .. offset + block_len];
        offset += block_len;
        if (flags & flag_block_checksum != 0) {
            if (input.len < offset + 4) return error.DataException;
            const stored_sum = std.mem.readInt(u32, input[offset..][0..4], .little);
            if (stored_sum != checksum.xxh32With(options.provider, block_data)) return error.IntegrityException;
            offset += 4;
        }
        const room = output.len - total;
        const prefix_len = if (header.linked) @min(total, window_size) else 0;
        const prefix = output[total - prefix_len .. total];
        if (is_stored) {
            if (block_len > max_block) return error.DataException;
            if (block_len > room) return error.CapacityException;
            @memcpy(output[total..][0..block_len], block_data);
            content_hasher.update(block_data);
            total += block_len;
        } else {
            // The Block_Size field is bounded by Block_MaxSize whether the
            // block is stored or compressed, as in the reference.
            if (block_len > max_block) return error.DataException;
            const produced = decompressBlock(block_data, output[total..], prefix) catch |err| return switch (err) {
                error.DataException => error.DataException,
                error.OutputTooSmall => error.CapacityException,
            };
            content_hasher.update(output[total .. total + produced]);
            total += produced;
        }
        if (try bounds.addUsize(input.len, total) > options.max_work) return error.ResourceException;
    }
    if (flags & flag_content_checksum != 0) {
        if (input.len < offset + 4) return error.DataException;
        const stored_sum = std.mem.readInt(u32, input[offset..][0..4], .little);
        if (stored_sum != content_hasher.final({})) return error.IntegrityException;
        offset += 4;
    }
    if (offset != input.len) return error.DataException;
    if (content_size) |expected| {
        if (expected != total) return error.IntegrityException;
    }
    return total;
}

// Pre-1.8 interop: raw blocks up to 8 MiB, no descriptor, no checksums,
// fresh history per block. Decode-only.
fn decodeLegacyBlocksInto(input: []const u8, output: []u8, options: Options) Exception!usize {
    var offset: usize = 4;
    var total: usize = 0;
    while (true) {
        // Real legacy files end at the last block; fewer than four trailing
        // bytes cannot start another one.
        if (input.len < offset + 4) break;
        const block_len: usize = std.mem.readInt(u32, input[offset..][0..4], .little);
        offset += 4;
        if (block_len == 0) break;
        if (block_len > blockCompressBound(legacy_block_size)) return error.DataException;
        if (input.len < offset + block_len) return error.DataException;
        const block_data = input[offset .. offset + block_len];
        offset += block_len;
        const room = output.len - total;
        const cap = @min(room, legacy_block_size);
        const produced = decompressBlock(block_data, output[total..][0..cap], &[_]u8{}) catch |err| return switch (err) {
            error.DataException => error.DataException,
            // With full 8 MiB headroom an overrun breaks the format's
            // block-size limit; below it the output is merely short.
            error.OutputTooSmall => if (room >= legacy_block_size) error.DataException else error.CapacityException,
        };
        total += produced;
        if (try bounds.addUsize(input.len, total) > options.max_work) return error.ResourceException;
    }
    if (offset != input.len) return error.DataException;
    return total;
}

pub fn encodeToWriter(input: []const u8, output: *std.Io.Writer, scratch: []u8, options: Options) Exception!void {
    if (scratch.len < encodeWorkspaceSize()) return error.CapacityException;
    const block_size_byte = try blockSizeCode(options.block_size) << 4;
    var acceleration = options.acceleration;
    if (acceleration < 1) acceleration = 1;
    output.writeInt(u32, magic, .little) catch return error.IoException;
    var flags: u8 = version_bits | flag_block_independence;
    if (options.block_checksum) flags |= flag_block_checksum;
    flags |= flag_content_size;
    if (options.content_checksum) flags |= flag_content_checksum;
    var header_hasher = checksum.XxHash32.bind(options.provider, 0);
    output.writeByte(flags) catch return error.IoException;
    header_hasher.update(&.{flags});
    output.writeByte(block_size_byte) catch return error.IoException;
    header_hasher.update(&.{block_size_byte});
    var size_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &size_bytes, input.len, .little);
    output.writeAll(&size_bytes) catch return error.IoException;
    header_hasher.update(&size_bytes);
    output.writeByte(@truncate(header_hasher.final({}) >> 8)) catch return error.IoException;
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
            output.writeInt(u32, uncompressed_block | (std.math.cast(u32, block_len) orelse return error.ResourceException), .little) catch return error.IoException;
            output.writeAll(block) catch return error.IoException;
            if (options.block_checksum) output.writeInt(u32, checksum.xxh32With(options.provider, block), .little) catch return error.IoException;
        } else {
            output.writeInt(u32, std.math.cast(u32, compressed_len) orelse return error.ResourceException, .little) catch return error.IoException;
            output.writeAll(block_buffer[0..compressed_len]) catch return error.IoException;
            if (options.block_checksum) output.writeInt(u32, checksum.xxh32With(options.provider, block_buffer[0..compressed_len]), .little) catch return error.IoException;
        }
        offset += block_len;
    }
    if (input.len == 0) {
        // One empty block (single zero token) keeps the block stream well-formed.
        output.writeInt(u32, 1, .little) catch return error.IoException;
        output.writeByte(0) catch return error.IoException;
    }
    output.writeInt(u32, 0, .little) catch return error.IoException;
    if (options.content_checksum) output.writeInt(u32, checksum.xxh32With(options.provider, input), .little) catch return error.IoException;
}

pub fn decodeToWriter(input: []const u8, output: *std.Io.Writer, scratch: []u8, options: Options) Exception!void {
    _ = try decodeBlocks(input, output, scratch, options.provider, options.max_work);
}

// Modern frames only: this route lacks the 8 MiB legacy staging, so
// callers use decode or decodeInPlace.
fn decodeBlocks(input: []const u8, output: *std.Io.Writer, scratch: []u8, provider: checksum.Provider, max_work: u64) Exception!usize {
    if (scratch.len < decodeWorkspaceSize()) return error.CapacityException;
    const header = try readFrameDescriptor(input, provider);
    const flags = header.flags;
    const max_block = header.max_block;
    var offset = header.offset;
    const content_size = header.content_size;
    var content_hasher = checksum.XxHash32.bind(provider, 0);
    const block_buffer = scratch[0..max_block];
    const history = scratch[max_block..][0..window_size];
    var history_len: usize = 0;
    var total: usize = 0;
    while (true) {
        if (input.len < offset + 4) return error.DataException;
        const block_size_field = std.mem.readInt(u32, input[offset..][0..4], .little);
        offset += 4;
        if (block_size_field == 0) break;
        const is_stored = (block_size_field & uncompressed_block) != 0;
        const block_len: usize = @intCast(block_size_field & ~uncompressed_block);
        if (input.len < offset + block_len) return error.DataException;
        const block_data = input[offset .. offset + block_len];
        offset += block_len;
        if (flags & flag_block_checksum != 0) {
            if (input.len < offset + 4) return error.DataException;
            const stored_sum = std.mem.readInt(u32, input[offset..][0..4], .little);
            if (stored_sum != checksum.xxh32With(provider, block_data)) return error.IntegrityException;
            offset += 4;
        }
        const produced: usize = blk: {
            if (is_stored) {
                if (block_len > max_block) return error.DataException;
                output.writeAll(block_data) catch return error.IoException;
                content_hasher.update(block_data);
                break :blk block_len;
            }
            // The Block_Size field is bounded by Block_MaxSize whether the
            // block is stored or compressed, as in the reference.
            if (block_len > max_block) return error.DataException;
            const decoded = decompressBlock(block_data, block_buffer, history[0..history_len]) catch return error.DataException;
            output.writeAll(block_buffer[0..decoded]) catch return error.IoException;
            content_hasher.update(block_buffer[0..decoded]);
            break :blk decoded;
        };
        total = try bounds.addUsize(total, produced);
        if (try bounds.addUsize(input.len, total) > max_work) return error.ResourceException;
        if (header.linked) {
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
        if (input.len < offset + 4) return error.DataException;
        const stored_sum = std.mem.readInt(u32, input[offset..][0..4], .little);
        if (stored_sum != content_hasher.final({})) return error.IntegrityException;
        offset += 4;
    }
    if (offset != input.len) return error.DataException;
    if (content_size) |expected| {
        if (expected != total) return error.IntegrityException;
    }
    return total;
}

fn hash4(value: u32) usize {
    return (value *% hash_prime) >> @intCast(32 - hash_log);
}

// Mirrors LZ4_compress_generic_validated: the carried hash prevents a
// self-match; the reference never emits offset 0.
//
// Exposed for the session boundary's stepped encode: compresses one
// independent block; the caller owns the framing.
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
            // The match must end by match_limit so the last 5 bytes stay literals.
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

// The prefix is up to 64 KiB of decoded history; matches may reach
// into it when the frame links blocks.
//
// Exposed for the session boundary's stepped decode.
pub fn decompressBlock(input: []const u8, output: []u8, prefix: []const u8) error{ DataException, OutputTooSmall }!usize {
    var ip: usize = 0;
    var op: usize = 0;
    while (true) {
        if (ip >= input.len) return error.DataException;
        const token = input[ip];
        ip += 1;
        var lit_len: usize = token >> 4;
        if (lit_len == lit_len_mask) {
            while (true) {
                if (ip >= input.len) return error.DataException;
                const value = input[ip];
                ip += 1;
                if (value != 255 and lit_len > std.math.maxInt(usize) - 510) return error.DataException;
                lit_len += value;
                if (value != 255) break;
            }
        }
        if (input.len - ip < lit_len) return error.DataException;
        if (output.len - op < lit_len) return error.OutputTooSmall;
        if (lit_len <= 16 and input.len - ip >= 16 and output.len - op >= 16) {
            // Short literal runs dominate, so one guarded 16-byte copy replaces memcpy per sequence.
            output[op..][0..16].* = input[ip..][0..16].*;
        } else {
            @memcpy(output[op .. op + lit_len], input[ip .. ip + lit_len]);
        }
        op += lit_len;
        ip += lit_len;
        if (ip == input.len) break;
        if (input.len - ip < 2) return error.DataException;
        const offset = std.mem.readInt(u16, input[ip..][0..2], .little);
        ip += 2;
        var match_len: usize = (token & 0x0f) + min_match;
        if ((token & 0x0f) == match_len_mask) {
            while (true) {
                if (ip >= input.len) return error.DataException;
                const value = input[ip];
                ip += 1;
                if (value != 255 and match_len > std.math.maxInt(usize) - 510) return error.DataException;
                match_len += value;
                if (value != 255) break;
            }
        }
        if (output.len - op < match_len) return error.OutputTooSmall;
        if (offset == 0) return error.DataException;
        if (offset <= op) {
            kernels.copyMatch(output, op, offset, std.math.cast(u32, match_len) orelse return error.DataException);
        } else {
            // The match reaches before this block into the linked history.
            const reach = offset - op;
            if (reach > prefix.len) return error.DataException;
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
                    // The source crossed into this block; chunking at the
                    // current distance keeps overlapping copies correct.
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
    try std.testing.expectError(error.DataException, decode(encoded[0 .. encoded_len - 3], &output, scratch, .{}));
    encoded[19] ^= 0xff;
    const result = decode(encoded[0..encoded_len], &output, scratch, .{});
    if (result) |produced| {
        try std.testing.expect(!std.mem.eql(u8, input, output[0..produced]));
    } else |err| {
        // A corrupted block either fails its input-side checks or overruns
        // the span, which surfaces as CapacityException.
        try std.testing.expect(err == error.DataException or err == error.IntegrityException or err == error.CapacityException);
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
    try std.testing.expectError(error.IntegrityException, decode(bad_size, output, decode_scratch, .{}));

    // Corrupting the Header_Checksum byte itself must fail too.
    var bad_sum = try allocator.dupe(u8, encoded[0..encoded_len]);
    defer allocator.free(bad_sum);
    bad_sum[14] ^= 0xFF;
    try std.testing.expectError(error.IntegrityException, decode(bad_sum, output, decode_scratch, .{}));
}

test "lz4 dependent blocks reach into the previous block" {
    const allocator = std.testing.allocator;
    // Frame: linked blocks.
    // Block 0 is stored; block 1 is compressed.
    var frame: [256]u8 = undefined;
    var len: usize = 0;
    std.mem.writeInt(u32, frame[len..][0..4], magic, .little);
    len += 4;
    const flags: u8 = version_bits | flag_content_size;
    frame[len] = flags;
    len += 1;
    frame[len] = 4 << 4; // BD: 64 KiB max block.
    len += 1;
    std.mem.writeInt(u64, frame[len..][0..8], 77, .little);
    len += 8;
    frame[len] = @truncate(checksum.xxh32With(checksum.default_provider, frame[4..len]) >> 8);
    len += 1;
    std.mem.writeInt(u32, frame[len..][0..4], uncompressed_block | 64, .little);
    len += 4;
    @memset(frame[len..][0..64], 0x11);
    len += 64;
    // Sequence 1: an 8-byte match reaching 68 back into block 0.
    // Sequence 2 (final): one literal, as the format requires.
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
    bad[block1_at + 5] = 200; // Offset 200 > 4 + 64 of available history.
    try std.testing.expectError(error.DataException, decode(bad[0..len], &output, decode_scratch, .{}));
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
    frame[len] = 7 << 4; // BD: 4 MiB max block.
    len += 1;
    std.mem.writeInt(u64, frame[len..][0..8], 5, .little);
    len += 8;
    std.mem.writeInt(u32, frame[len..][0..4], 0xDEADBEEF, .little); // Dictionary ID.
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
    try std.testing.expectError(error.IntegrityException, decode(bad[0..len], &output, decode_scratch, .{}));
}

test "lz4 legacy frame decodes eof-terminated blocks" {
    const allocator = std.testing.allocator;
    var block_a: [16 + 300]u8 = undefined;
    @memcpy(block_a[0..16], "legacy block a: ");
    @memset(block_a[16..], 'a');
    var block_b: [16 + 300]u8 = undefined;
    @memcpy(block_b[0..16], "legacy block b: ");
    @memset(block_b[16..], 'b');
    const hash_table = try allocator.alloc(u32, hash_size);
    defer allocator.free(hash_table);
    var comp_a: [blockCompressBound(block_a.len)]u8 = undefined;
    var comp_b: [blockCompressBound(block_b.len)]u8 = undefined;
    const a_compressed = compressBlock(&block_a, &comp_a, hash_table, 1);
    const b_compressed = compressBlock(&block_b, &comp_b, hash_table, 1);
    // No terminator: real legacy files end at the last block.
    var frame: [4 + 4 + comp_a.len + 4 + comp_b.len + 4]u8 = undefined;
    var len: usize = 0;
    std.mem.writeInt(u32, frame[len..][0..4], legacy_magic, .little);
    len += 4;
    std.mem.writeInt(u32, frame[len..][0..4], @intCast(a_compressed), .little);
    len += 4;
    @memcpy(frame[len..][0..a_compressed], comp_a[0..a_compressed]);
    len += a_compressed;
    std.mem.writeInt(u32, frame[len..][0..4], @intCast(b_compressed), .little);
    len += 4;
    @memcpy(frame[len..][0..b_compressed], comp_b[0..b_compressed]);
    len += b_compressed;
    const decode_scratch = try allocator.alloc(u8, decodeWorkspaceSize());
    defer allocator.free(decode_scratch);
    var output: [block_a.len + block_b.len]u8 = undefined;
    const produced = try decode(frame[0..len], &output, decode_scratch, .{});
    try std.testing.expectEqual(block_a.len + block_b.len, produced);
    try std.testing.expectEqualSlices(u8, &block_a, output[0..block_a.len]);
    try std.testing.expectEqualSlices(u8, &block_b, output[block_a.len..]);

    // One to three trailing bytes cannot start another block.
    frame[len] = 0xAA;
    frame[len + 1] = 0xBB;
    try std.testing.expectError(error.DataException, decode(frame[0 .. len + 2], &output, decode_scratch, .{}));
}

test "lz4 legacy blocks are independent" {
    // Block 1's match reaches 8 bytes into block 0's content; the
    // reference decodes legacy blocks independently and rejects it.
    const block0 = "12345678";
    const hash_table = try std.testing.allocator.alloc(u32, hash_size);
    defer std.testing.allocator.free(hash_table);
    var comp0: [blockCompressBound(block0.len)]u8 = undefined;
    const compressed = compressBlock(block0, &comp0, hash_table, 1);
    const block1 = [_]u8{ 0x40, 'A', 'B', 'C', 'D', 8, 0, 0x10, 'E' };
    var frame: [4 + 4 + blockCompressBound(block0.len) + 4 + block1.len]u8 = undefined;
    var len: usize = 0;
    std.mem.writeInt(u32, frame[len..][0..4], legacy_magic, .little);
    len += 4;
    std.mem.writeInt(u32, frame[len..][0..4], @intCast(compressed), .little);
    len += 4;
    @memcpy(frame[len..][0..compressed], comp0[0..compressed]);
    len += compressed;
    std.mem.writeInt(u32, frame[len..][0..4], block1.len, .little);
    len += 4;
    @memcpy(frame[len..][0..block1.len], &block1);
    len += block1.len;
    const decode_scratch = try std.testing.allocator.alloc(u8, decodeWorkspaceSize());
    defer std.testing.allocator.free(decode_scratch);
    var output: [32]u8 = undefined;
    try std.testing.expectError(error.DataException, decode(frame[0..len], &output, decode_scratch, .{}));
}

test "lz4 legacy frame accepts the kernel zero terminator" {
    const allocator = std.testing.allocator;
    const payload = "kernel variant terminator payload 0123456789";
    const hash_table = try allocator.alloc(u32, hash_size);
    defer allocator.free(hash_table);
    var comp: [blockCompressBound(payload.len)]u8 = undefined;
    const compressed = compressBlock(payload, &comp, hash_table, 1);
    var frame: [4 + 4 + blockCompressBound(payload.len) + 4]u8 = undefined;
    var len: usize = 0;
    std.mem.writeInt(u32, frame[len..][0..4], legacy_magic, .little);
    len += 4;
    std.mem.writeInt(u32, frame[len..][0..4], @intCast(compressed), .little);
    len += 4;
    @memcpy(frame[len..][0..compressed], comp[0..compressed]);
    len += compressed;
    std.mem.writeInt(u32, frame[len..][0..4], 0, .little);
    len += 4;
    const decode_scratch = try allocator.alloc(u8, decodeWorkspaceSize());
    defer allocator.free(decode_scratch);
    var output: [64]u8 = undefined;
    const produced = try decode(frame[0..len], &output, decode_scratch, .{});
    try std.testing.expectEqualSlices(u8, payload, output[0..produced]);

    // A magic-sized size word is the next frame's start, not a block: this
    // buffer API takes exactly one frame.
    std.mem.writeInt(u32, frame[len - 4 ..][0..4], magic, .little);
    try std.testing.expectError(error.DataException, decode(frame[0..len], &output, decode_scratch, .{}));

    // The magic alone is a well-formed empty legacy frame.
    try std.testing.expectEqual(@as(usize, 0), try decode(frame[0..4], &output, decode_scratch, .{}));
}

test "lz4 frame rejects reserved descriptor bits" {
    const allocator = std.testing.allocator;
    const input = "reserved descriptor bit frame payload";
    const scratch = try allocator.alloc(u8, encodeWorkspaceSize());
    defer allocator.free(scratch);
    const encoded = try allocator.alloc(u8, encodedSizeBound(input.len));
    defer allocator.free(encoded);
    const encoded_len = try encode(input, encoded, scratch, .{});
    const decode_scratch = try allocator.alloc(u8, decodeWorkspaceSize());
    defer allocator.free(decode_scratch);
    var output: [64]u8 = undefined;

    // Header layout: magic(4) FLG(1) BD(1) Content_Size(8) Header_Checksum(1).
    // Each corruption re-seals the checksum so only the reserved bits can fail.
    {
        var frame = try allocator.dupe(u8, encoded[0..encoded_len]);
        defer allocator.free(frame);
        frame[4] |= flag_reserved;
        frame[14] = @truncate(checksum.xxh32With(checksum.default_provider, frame[4..14]) >> 8);
        try std.testing.expectError(error.DataException, decode(frame, &output, decode_scratch, .{}));
    }
    {
        var frame = try allocator.dupe(u8, encoded[0..encoded_len]);
        defer allocator.free(frame);
        frame[5] |= 0x80;
        frame[14] = @truncate(checksum.xxh32With(checksum.default_provider, frame[4..14]) >> 8);
        try std.testing.expectError(error.DataException, decode(frame, &output, decode_scratch, .{}));
    }
    {
        var frame = try allocator.dupe(u8, encoded[0..encoded_len]);
        defer allocator.free(frame);
        frame[5] |= 0x01;
        frame[14] = @truncate(checksum.xxh32With(checksum.default_provider, frame[4..14]) >> 8);
        try std.testing.expectError(error.DataException, decode(frame, &output, decode_scratch, .{}));
    }
}
