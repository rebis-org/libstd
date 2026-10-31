const std = @import("std");

const bounds = @import("../../../common/primitive/bounds.zig");
const checksum = @import("../../../common/primitive/checksum.zig");
const exception_prim = @import("../../../common/primitive/exception.zig");
const xz = @import("../xz/onprem.zig");
const onprem = @import("onprem.zig");

const Exception = exception_prim.Exception;

// A located member of sized chunks, each stored or one xz stream.
// Untouched chunks drop on their declared size.

const block_size_max = onprem.block_size_max;
const chunk_header_size = onprem.chunk_header_size;
const pbzx_header_size = onprem.pbzx_header_size;
const dictionary_seed = onprem.dictionary_seed;
const xz_magic = onprem.xz_magic;

// The chunk state: what the pre-session cursor owned beside its records.
// The counters keep their meaning: a skip decodes nothing.
const State = struct {
    pbzx: []const u8,
    block_size: u64,
    buffer: []u8,
    workspace: []u8,
    cursor: u64 = pbzx_header_size,
    chunk_start: u64 = 0,
    chunk_len: u64 = 0,
    payload_start: u64 = 0,
    payload_len: u64 = 0,
    loaded: bool = false,
    byte_pos: u64 = 0,
    decoded_chunks: u64 = 0,
    decoded_bytes: u64 = 0,

    fn init(pbzx: []const u8, buffer: []u8, workspace: []u8) Exception!State {
        if (pbzx.len < pbzx_header_size) return error.DataException;
        if (!std.mem.eql(u8, pbzx[0..4], "pbzx")) return error.UnsupportedException;
        const block_size = std.mem.readInt(u64, pbzx[4..12], .big);
        if (block_size == 0) return error.DataException;
        return .{ .pbzx = pbzx, .block_size = block_size, .buffer = buffer, .workspace = workspace };
    }

    fn nextChunk(self: *align(1) State) Exception!bool {
        if (self.cursor == self.pbzx.len) return false;
        const header = try bounds.slice(self.pbzx, self.cursor, chunk_header_size);
        const decoded_size = std.mem.readInt(u64, header[0..8], .big);
        const stored_size = std.mem.readInt(u64, header[8..16], .big);
        if (decoded_size == 0 or decoded_size > self.block_size) return error.DataException;
        if (decoded_size > self.buffer.len) return error.ResourceException;
        const payload_start = try bounds.addU64(self.cursor, chunk_header_size);
        _ = try bounds.slice(self.pbzx, payload_start, stored_size);
        // Chunks arrive in order, so the previous end starts the next one.
        self.chunk_start = try bounds.addU64(self.chunk_start, self.chunk_len);
        self.chunk_len = decoded_size;
        self.payload_start = payload_start;
        self.payload_len = stored_size;
        self.loaded = false;
        self.cursor = try bounds.addU64(payload_start, stored_size);
        return true;
    }

    fn decodeChunk(self: *align(1) State) Exception!void {
        const payload = try bounds.slice(self.pbzx, self.payload_start, self.payload_len);
        const output = self.buffer[0..@intCast(self.chunk_len)];
        if (self.payload_len == self.chunk_len) {
            @memcpy(output, payload);
        } else {
            if (payload.len < xz_magic.len or !std.mem.eql(u8, payload[0..xz_magic.len], &xz_magic)) return error.UnsupportedException;
            const written = try xz.decodeInPlace(payload, output, self.workspace, checksum.default_provider);
            if (written != output.len) return error.IntegrityException;
        }
        self.decoded_chunks = try bounds.addU64(self.decoded_chunks, 1);
        self.decoded_bytes = try bounds.addU64(self.decoded_bytes, self.chunk_len);
        self.loaded = true;
    }

    fn load(self: *align(1) State) Exception!void {
        while (!(self.loaded and self.byte_pos < self.chunk_start + self.chunk_len)) {
            if (!try self.nextChunk()) return error.DataException;
            try self.decodeChunk();
        }
    }

    // A read fills exactly what the caller asked or the stream is short.
    fn read(self: *align(1) State, destination: []u8) Exception!usize {
        var written: usize = 0;
        while (written < destination.len) {
            try self.load();
            const offset: usize = @intCast(self.byte_pos - self.chunk_start);
            const available: usize = @as(usize, @intCast(self.chunk_len)) - offset;
            const step = @min(available, destination.len - written);
            @memcpy(destination[written..][0..step], self.buffer[offset..][0..step]);
            self.byte_pos += step;
            written += step;
        }
        return written;
    }

    // A skip drops whole chunks; a chunk no read touches needs no decode.
    fn drop(self: *align(1) State, count: u64) Exception!void {
        var remaining = count;
        while (remaining > 0) {
            if (self.loaded and self.byte_pos < self.chunk_start + self.chunk_len) {
                const available = self.chunk_start + self.chunk_len - self.byte_pos;
                const step = @min(available, remaining);
                self.byte_pos += step;
                remaining -= step;
                continue;
            }
            if (!try self.nextChunk()) return error.DataException;
            // A chunk no read touches needs no decode, only its size.
            if (remaining >= self.chunk_len) {
                self.byte_pos = self.chunk_start + self.chunk_len;
                remaining -= self.chunk_len;
                continue;
            }
            try self.decodeChunk();
        }
    }
};

// The instance is one byte array; the chain alignment stays one.
// The state lives in the wrap's scratch.
pub fn Pbzx(comptime Located: type) type {
    return struct {
        const Self = @This();

        pub const scratch_size: usize = block_size_max + xz.decodeInPlaceWorkspaceSize(dictionary_seed);

        const state_size: usize = @sizeOf(State);

        // The in-place formula always leaves this much slack;
        // the state must fit inside it.
        comptime {
            if (state_size > 65536) @compileError("pbzx: the chunk state outgrew the workspace slack");
        }

        raw: [state_size]u8,

        fn state(self: *Self) *align(1) State {
            return @ptrCast(&self.raw);
        }

        // The transform owns its whole segment: the state, the chunk the
        // cursor decodes, and the xz window, in that order.
        pub fn wrap(located: Located, scratch: []u8) Exception!*Self {
            if (scratch.len < scratch_size) return error.CapacityException;
            const self: *Self = @ptrCast(scratch.ptr);
            const st = self.state();
            st.* = try State.init(located, scratch[state_size..][0..block_size_max], scratch[state_size + block_size_max ..]);
            return self;
        }

        pub fn reader(self: *Self) *Self {
            return self;
        }

        pub fn take(self: *Self, destination: []u8) Exception!usize {
            return self.state().read(destination);
        }

        pub fn discard(self: *Self, count: u64) Exception!void {
            return self.state().drop(count);
        }

        // The observability counters prove what a walk decoded.
        pub fn decodedChunks(self: *Self) u64 {
            return self.state().decoded_chunks;
        }

        pub fn decodedBytes(self: *Self) u64 {
            return self.state().decoded_bytes;
        }
    };
}
