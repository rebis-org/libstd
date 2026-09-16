const std = @import("std");
const drivers = @import("compose/drivers.zig");
const sessions = @import("compose/sessions.zig");
const gzip = @import("grammar/gzip.zig");
const tar = @import("grammar/tar.zig");

// Both paths run the same leaf code, so outputs and step counts must match; input is
// non-periodic xorshift because repeating corpora hide composition bugs.
// Rooted at src/: module confinement requires it for mains reaching the whole tree.
var failures: usize = 0;

fn check(ok_condition: bool, label: []const u8) void {
    if (ok_condition) {
        std.debug.print("ok {s}\n", .{label});
    } else {
        std.debug.print("FAIL {s}\n", .{label});
        failures += 1;
    }
}

fn makeCorpus(allocator: std.mem.Allocator, size: usize) ![]u8 {
    const corpus = try allocator.alloc(u8, size);
    var state: u64 = 0x9e3779b97f4a7c15;
    var index: usize = 0;
    while (index < size) : (index += 8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        const word = std.mem.toBytes(state);
        const count = @min(8, size - index);
        @memcpy(corpus[index..][0..count], word[0..count]);
    }
    return corpus;
}

fn encodeCorpus(allocator: std.mem.Allocator, corpus: []const u8) ![]u8 {
    const bound = drivers.gzipEncodedSizeBound(corpus.len);
    const out = try allocator.alloc(u8, bound);
    var history: [gzip.deflate_history_size]u8 = undefined;
    const size = drivers.gzipEncode(out, corpus, &history, drivers.default_encode_options, .bounded) catch return error.EncodeFailed;
    return out[0..size];
}

const DecodeOutcome = struct {
    bytes: []u8,
    steps: usize,
};

fn allocStateStorage(allocator: std.mem.Allocator) ![]u8 {
    const plan = drivers.gzipDecodeStorage();
    const raw = try allocator.alloc(u8, plan + @alignOf(drivers.GzipDecodeState));
    const base = @intFromPtr(raw.ptr);
    const aligned = std.mem.alignForward(usize, base, @alignOf(drivers.GzipDecodeState));
    return raw[aligned - base ..][0..plan];
}

fn decodeKernel(allocator: std.mem.Allocator, compressed: []const u8, budgets: sessions.Budgets, expect_budget_failure: bool) !?DecodeOutcome {
    const storage = try allocStateStorage(allocator);
    var session = try drivers.gzipDecodeSession(storage, budgets);
    var output: std.ArrayList(u8) = .empty;
    var steps: usize = 0;
    var pos: usize = 0;
    while (steps < 100000) {
        steps += 1;
        const take = @min(65536, compressed.len - pos);
        const chunk = compressed[pos..][0..take];
        const end_of_input = pos + take == compressed.len;
        var scratch: [98304]u8 = undefined;
        const result = session.step(chunk, &scratch, end_of_input);
        try output.appendSlice(allocator, scratch[0..result.produced]);
        if (result.status == .failed) {
            if (expect_budget_failure) {
                if (result.failure) |failure| {
                    if (failure == error.ResourceLimit) return null;
                }
            }
            return error.UnexpectedFailure;
        }
        if (result.status == .done) return DecodeOutcome{ .bytes = output.items, .steps = steps };
        if (result.consumed == 0 and result.produced == 0) return error.NoProgress;
        pos += result.consumed;
    }
    return error.NoProgress;
}

fn decodeBypass(allocator: std.mem.Allocator, compressed: []const u8) !DecodeOutcome {
    const storage = try allocStateStorage(allocator);
    const state = try drivers.gzipDecodeStateInit(storage, .{});
    var output: std.ArrayList(u8) = .empty;
    var steps: usize = 0;
    var pos: usize = 0;
    while (steps < 100000) {
        steps += 1;
        const take = @min(65536, compressed.len - pos);
        const chunk = compressed[pos..][0..take];
        const end_of_input = pos + take == compressed.len;
        var scratch: [98304]u8 = undefined;
        const result = drivers.gzipDecodeStep(state, chunk, &scratch, end_of_input);
        try output.appendSlice(allocator, scratch[0..result.produced]);
        if (result.status == .failed) return error.UnexpectedFailure;
        if (result.status == .done) return DecodeOutcome{ .bytes = output.items, .steps = steps };
        if (result.consumed == 0 and result.produced == 0) return error.NoProgress;
        pos += result.consumed;
    }
    return error.NoProgress;
}

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();

    const corpus = try makeCorpus(allocator, 1 << 20);
    const compressed = try encodeCorpus(allocator, corpus);

    // Same leaf code cannot diverge far, so bypass must stay within 2x of kernel.
    const kernel_start = std.Io.Clock.Timestamp.now(init.io, .awake).raw.nanoseconds;
    const kernel = try decodeKernel(allocator, compressed, .{}, false);
    const kernel_end = std.Io.Clock.Timestamp.now(init.io, .awake).raw.nanoseconds;
    const bypass_start = kernel_end;
    const bypass = try decodeBypass(allocator, compressed);
    const bypass_end = std.Io.Clock.Timestamp.now(init.io, .awake).raw.nanoseconds;
    const kernel_mibps = @as(f64, @floatFromInt(corpus.len)) / @as(f64, @floatFromInt(kernel_end - kernel_start)) * 1e3;
    const bypass_mibps = @as(f64, @floatFromInt(corpus.len)) / @as(f64, @floatFromInt(bypass_end - bypass_start)) * 1e3;
    std.debug.print("Bypass row: kernel {d:.1} MiB/s, bypass {d:.1} MiB/s.\n", .{ kernel_mibps, bypass_mibps });
    check(bypass_mibps >= kernel_mibps * 0.5, "bypass throughput within 2x of kernel");
    check(kernel != null and bypass.steps == kernel.?.steps, "kernel and bypass step counts match");
    check(std.mem.eql(u8, kernel.?.bytes, corpus), "kernel decode matches corpus");
    check(std.mem.eql(u8, bypass.bytes, corpus), "bypass decode matches corpus");
    check(std.mem.eql(u8, kernel.?.bytes, bypass.bytes), "kernel and bypass byte-identical");

    var multi: std.ArrayList(u8) = .empty;
    try multi.appendSlice(allocator, compressed);
    try multi.appendSlice(allocator, compressed);
    var joined_corpus: std.ArrayList(u8) = .empty;
    try joined_corpus.appendSlice(allocator, corpus);
    try joined_corpus.appendSlice(allocator, corpus);
    const kernel_multi = try decodeKernel(allocator, multi.items, .{}, false);
    check(kernel_multi != null and std.mem.eql(u8, kernel_multi.?.bytes, joined_corpus.items), "multi-member decode");

    const budget_limited = try decodeKernel(allocator, compressed, .{ .max_decoded = corpus.len - 1 }, true);
    check(budget_limited == null, "decoded budget trips mid-stream");

    const storage = try allocStateStorage(allocator);
    var session = try drivers.gzipDecodeSession(storage, .{});
    session.destroy();
    session.destroy();
    const after_destroy = session.step(compressed, &.{}, false);
    var destroy_invalid_call = false;
    if (after_destroy.failure) |failure| {
        destroy_invalid_call = failure == error.InvalidCall;
    }
    check(after_destroy.status == .failed and destroy_invalid_call, "step after destroy returns invalid_call");

    var truncated_failed = false;
    _ = decodeKernel(allocator, compressed[0 .. compressed.len - 5], .{}, false) catch |err| {
        truncated_failed = err == error.UnexpectedFailure;
    };
    check(truncated_failed, "truncated stream fails");

    var encode_history: [gzip.deflate_history_size]u8 = undefined;
    const bound = drivers.gzipEncodedSizeBound(corpus.len);
    const one_out = try allocator.alloc(u8, bound);
    const one_size = try drivers.gzipEncode(one_out, corpus, &encode_history, drivers.default_encode_options, .bounded);
    const two_out = try allocator.alloc(u8, one_size);
    const two_size = try drivers.gzipEncode(two_out, corpus, &encode_history, drivers.default_encode_options, .measured);
    check(one_size == two_size, "sizing modes produce identical sizes");
    check(std.mem.eql(u8, one_out[0..one_size], two_out[0..two_size]), "bounded encode byte-identical to measured");
    check(one_size <= bound, "one-pass within analytic bound");
    const tight_two = try allocator.alloc(u8, two_size);
    const tight_size = try drivers.gzipEncode(tight_two, corpus, &encode_history, drivers.default_encode_options, .measured);
    check(tight_size == two_size, "measured mode accepts exact-size sink");
    const undersized = drivers.gzipEncode(one_out[0 .. bound - 1], corpus, &encode_history, drivers.default_encode_options, .bounded);
    check(undersized == error.InsufficientCapacity, "bounded mode capacity enforced a priori");
    const roundtrip = try decodeKernel(allocator, one_out[0..one_size], .{}, false);
    check(roundtrip != null and std.mem.eql(u8, roundtrip.?.bytes, corpus), "bounded-mode output decodes through the session");

    var framed: std.ArrayList(u8) = .empty;
    const tar_entries = [_]tar.TarEntry{
        .{ .name = "a.txt", .data = corpus[0..100] },
        .{ .name = "b.bin", .data = corpus[100..800] },
        .{ .name = "empty", .data = &.{} },
    };
    for (&tar_entries) |*entry| {
        try framed.append(allocator, @intCast(entry.name.len));
        try framed.appendSlice(allocator, entry.name);
        var size_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &size_bytes, entry.data.len, .little);
        try framed.appendSlice(allocator, &size_bytes);
        try framed.appendSlice(allocator, entry.data);
    }
    {
        const tar_storage = try allocator.alignedAlloc(u8, .@"8", drivers.tarWriteStorage() + 8);
        const base = @intFromPtr(tar_storage.ptr);
        const aligned = std.mem.alignForward(usize, base, @alignOf(drivers.TarWriteState));
        var tar_session = try drivers.tarWriteSession(tar_storage[aligned - base ..][0..drivers.tarWriteStorage()], .{});
        var produced: std.ArrayList(u8) = .empty;
        var pos: usize = 0;
        var guard: usize = 0;
        while (guard < 100000) {
            guard += 1;
            const take = @min(5000, framed.items.len - pos);
            var scratch: [4096]u8 = undefined;
            const result = tar_session.step(framed.items[pos..][0..take], &scratch, pos + take == framed.items.len);
            try produced.appendSlice(allocator, scratch[0..result.produced]);
            if (result.status == .failed) return error.UnexpectedFailure;
            if (result.status == .done) break;
            if (result.consumed == 0 and result.produced == 0 and pos + take == framed.items.len) return error.NoProgress;
            pos += result.consumed;
        }
        const reference = try allocator.alloc(u8, tar.tarArchiveSize(&tar_entries) catch return error.UnexpectedFailure);
        var scratch: [tar.tar_scratch_size]u8 = undefined;
        const reference_size = tar.tarEncode(&tar_entries, reference, &scratch) catch return error.UnexpectedFailure;
        check(produced.items.len == reference_size, "tar write session matches grammar encode size");
        check(std.mem.eql(u8, produced.items, reference[0..reference_size]), "tar write session byte-identical to grammar encode");
        const count = tar.tarInspectCount(produced.items) catch return error.UnexpectedFailure;
        check(count == 3, "tar session output inspects as three entries");
        for (&tar_entries, 0..) |*entry, ordinal| {
            const info = tar.tarInspectOrdinal(produced.items, ordinal) catch return error.UnexpectedFailure;
            check(std.mem.eql(u8, info.name, entry.name), "tar entry name round-trips");
            const data = try allocator.alloc(u8, info.size);
            const decoded = tar.tarDecodeOrdinal(produced.items, ordinal, data) catch return error.UnexpectedFailure;
            check(decoded == entry.data.len and std.mem.eql(u8, data, entry.data), "tar entry data round-trips");
        }
    }
    {
        const tar_storage = try allocator.alignedAlloc(u8, .@"8", drivers.tarWriteStorage() + 8);
        const base = @intFromPtr(tar_storage.ptr);
        const aligned = std.mem.alignForward(usize, base, @alignOf(drivers.TarWriteState));
        var tar_session = try drivers.tarWriteSession(tar_storage[aligned - base ..][0..drivers.tarWriteStorage()], .{ .max_encoded = 100 });
        var scratch: [4096]u8 = undefined;
        var tripped = false;
        var pos: usize = 0;
        while (pos < framed.items.len) {
            const take = @min(5000, framed.items.len - pos);
            const result = tar_session.step(framed.items[pos..][0..take], &scratch, false);
            if (result.status == .failed) {
                if (result.failure) |failure| tripped = failure == error.ResourceLimit;
                break;
            }
            pos += result.consumed;
        }
        check(tripped, "encoded budget trips mid-entry");
    }
    {
        // Partial output carries no trailer, so it must not inspect as complete.
        const tar_storage = try allocator.alignedAlloc(u8, .@"8", drivers.tarWriteStorage() + 8);
        const base = @intFromPtr(tar_storage.ptr);
        const aligned = std.mem.alignForward(usize, base, @alignOf(drivers.TarWriteState));
        var tar_session = try drivers.tarWriteSession(tar_storage[aligned - base ..][0..drivers.tarWriteStorage()], .{});
        var scratch: [4096]u8 = undefined;
        const partial_take = @min(9000, framed.items.len);
        _ = tar_session.step(framed.items[0..partial_take], &scratch, false);
        tar_session.destroy();
        var incomplete = true;
        if (tar.tarInspectCount(scratch[0..@min(4096, partial_take)])) |count| {
            incomplete = count != 3;
        } else |_| {
            incomplete = true;
        }
        check(incomplete, "cancelled partial archive is not a complete tar");
    }

    {
        const pipe_storage = try allocStateStorage(allocator);
        var pipe_session = try drivers.gzipDecodeSession(pipe_storage, .{});
        var upper: std.ArrayList(u8) = .empty;
        var pos: usize = 0;
        while (true) {
            const take = @min(65536, compressed.len - pos);
            var scratch: [98304]u8 = undefined;
            const result = pipe_session.step(compressed[pos..][0..take], &scratch, pos + take == compressed.len);
            for (scratch[0..result.produced]) |byte| {
                try upper.append(allocator, if (byte >= 'a' and byte <= 'z') byte - 32 else byte);
            }
            if (result.status == .failed) return error.UnexpectedFailure;
            if (result.status == .done) break;
            pos += result.consumed;
        }
        var expected_upper: std.ArrayList(u8) = .empty;
        for (corpus) |byte| {
            try expected_upper.append(allocator, if (byte >= 'a' and byte <= 'z') byte - 32 else byte);
        }
        check(std.mem.eql(u8, upper.items, expected_upper.items), "caller-built filter pipeline matches transformed corpus");
    }
    {
        const cancel_storage = try allocStateStorage(allocator);
        var cancel_session = try drivers.gzipDecodeSession(cancel_storage, .{});
        var prefix: std.ArrayList(u8) = .empty;
        var pos: usize = 0;
        var steps: usize = 0;
        while (steps < 5) {
            steps += 1;
            const take = @min(65536, compressed.len - pos);
            var scratch: [98304]u8 = undefined;
            const result = cancel_session.step(compressed[pos..][0..take], &scratch, false);
            try prefix.appendSlice(allocator, scratch[0..result.produced]);
            if (result.status == .failed) return error.UnexpectedFailure;
            pos += result.consumed;
        }
        cancel_session.destroy();
        check(std.mem.eql(u8, prefix.items, corpus[0..prefix.items.len]), "mid-stream cancel prefix is exact corpus prefix");
        const after = cancel_session.step(compressed, &.{}, false);
        check(after.status == .failed, "cancelled session rejects further steps");
    }
    // Sessions share no library state, so interleaved sessions must stay isolated.
    {
        const reent_a = try allocStateStorage(allocator);
        const reent_b = try allocStateStorage(allocator);
        var session_a = try drivers.gzipDecodeSession(reent_a, .{});
        const state_b = try drivers.gzipDecodeStateInit(reent_b, .{});
        var out_a: std.ArrayList(u8) = .empty;
        var out_b: std.ArrayList(u8) = .empty;
        var pos_a: usize = 0;
        var pos_b: usize = 0;
        var guard: usize = 0;
        while (guard < 100000) {
            guard += 1;
            const take_a = @min(32768, compressed.len - pos_a);
            const take_b = @min(32768, compressed.len - pos_b);
            var scratch: [65536]u8 = undefined;
            const ra = session_a.step(compressed[pos_a..][0..take_a], &scratch, pos_a + take_a == compressed.len);
            try out_a.appendSlice(allocator, scratch[0..ra.produced]);
            pos_a += ra.consumed;
            var scratch_b: [65536]u8 = undefined;
            const rb = drivers.gzipDecodeStep(state_b, compressed[pos_b..][0..take_b], &scratch_b, pos_b + take_b == compressed.len);
            try out_b.appendSlice(allocator, scratch_b[0..rb.produced]);
            pos_b += rb.consumed;
            if (ra.status == .done and rb.status == .done) break;
        }
        check(std.mem.eql(u8, out_a.items, corpus) and std.mem.eql(u8, out_b.items, corpus), "interleaved sessions stay isolated");
    }

    if (failures != 0) std.process.exit(1);
    std.debug.print("Compose AB suite: all checks passed.\n", .{});
}
