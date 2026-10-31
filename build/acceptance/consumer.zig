const std = @import("std");

// Package consumers import only the libstd module. Nothing below reaches
// into src/ internal paths: every type comes from the public assembly and
// bypass facades.
const libstd = @import("libstd");

const assembly = libstd.assembly;
const bypass = libstd.bypass;

test "assembly descriptor projection covers every representation descriptor" {
    // The projection excludes exactly the three protocol fixtures.
    try std.testing.expectEqual(@as(usize, 32), assembly.descriptors.len);
    try std.testing.expect(!@hasDecl(assembly.leaf, "test_echo"));
    try std.testing.expect(!@hasDecl(assembly.leaf, "test_read"));
    try std.testing.expect(!@hasDecl(assembly.grammar, "crypto"));
    // Every projected descriptor resolves to a public namespace with a real
    // implementation entry; the compile-time check in assembly backs this.
    comptime {
        for (assembly.descriptors) |descriptor| {
            const tag = assembly.tagForName(descriptor.name) orelse
                @compileError("descriptor without a tag: " ++ descriptor.name);
            if (assembly.namespaceFor(tag) == null)
                @compileError("descriptor without a public namespace: " ++ descriptor.name);
        }
    }
    // The special mappings stay reachable: zdict is the zstd dictionary
    // surface, hyphenated wire names map to their modules, and RAR keeps
    // its writer alongside the reader.
    try std.testing.expect(assembly.leaf.zdict == assembly.leaf.zstd);
    try std.testing.expect(@hasDecl(assembly.leaf.zdict, "trainDictionary"));
    try std.testing.expect(@hasDecl(assembly.leaf.zdict, "dictionaryContent"));
    try std.testing.expect(@hasDecl(assembly.grammar.lzma_file, "encode"));
    try std.testing.expect(@hasDecl(assembly.grammar.zstd_seekable, "encode"));
    try std.testing.expect(@hasDecl(assembly.grammar.rar.onprem, "rarInspectCountOpts"));
    try std.testing.expect(@hasDecl(assembly.grammar.rar.writer, "rarEncodeEx"));
}

test "xip roundtrip through assembly" {
    const xip = assembly.grammar.xip;
    const entries = [_]xip.Entry{
        .{ .name = "Xcode.app/Contents/Info.plist", .data = "plist bytes" },
        .{ .name = "Xcode.app/MacOS/Xcode", .data = "mach-o bytes" },
    };
    const scratch = try std.testing.allocator.alloc(u8, xip.scratch_size);
    defer std.testing.allocator.free(scratch);
    const planned = try xip.archiveSize(&entries, scratch);
    const archive = try std.testing.allocator.alloc(u8, planned);
    defer std.testing.allocator.free(archive);
    const written = try xip.encode(&entries, archive, scratch);
    try std.testing.expectEqual(planned, written);
    try std.testing.expectEqualSlices(u8, "xar!", archive[0..4]);
    try std.testing.expectEqual(@as(u64, 2), try xip.inspectCount(archive[0..written], scratch));
    const first = try xip.inspectOrdinal(archive[0..written], 0, scratch);
    try std.testing.expectEqualSlices(u8, "Xcode.app/Contents/Info.plist", first.name);
    var out: [16]u8 = undefined;
    const size = try xip.decodeOrdinal(archive[0..written], 1, &out, scratch);
    try std.testing.expectEqualSlices(u8, "mach-o bytes", out[0..size]);
}

test "pkg roundtrip through assembly" {
    const pkg = assembly.grammar.pkg;
    const entries = [_]pkg.Entry{
        .{ .name = "Applications/Tool.app/Contents/Info.plist", .data = "plist bytes" },
        .{ .name = "Applications/Tool.app/Contents/MacOS/Tool", .data = "mach-o bytes" },
    };
    const content_len: usize = @intCast(try assembly.grammar.cpio.archiveSize(&entries));
    const write_scratch = try std.testing.allocator.alloc(u8, pkg.writeScratchSize(content_len, .gzip));
    defer std.testing.allocator.free(write_scratch);
    const read_scratch = try std.testing.allocator.alloc(u8, pkg.scratch_size);
    defer std.testing.allocator.free(read_scratch);
    const planned = try pkg.archiveSize(&entries, write_scratch, .gzip);
    const archive = try std.testing.allocator.alloc(u8, planned);
    defer std.testing.allocator.free(archive);
    const written = try pkg.encode(&entries, archive, write_scratch, .gzip);
    try std.testing.expectEqual(planned, written);
    try std.testing.expectEqualSlices(u8, "xar!", archive[0..4]);
    try std.testing.expectEqual(@as(u64, 2), try pkg.inspectCount(archive[0..written], read_scratch));
    const first = try pkg.inspectOrdinal(archive[0..written], 0, read_scratch);
    try std.testing.expectEqualSlices(u8, "Applications/Tool.app/Contents/Info.plist", first.name);
    var out: [16]u8 = undefined;
    const size = try pkg.decodeOrdinal(archive[0..written], 1, &out, read_scratch);
    try std.testing.expectEqualSlices(u8, "mach-o bytes", out[0..size]);
}

test "zstd bypass round trip through assembly types" {
    // Options and spans cross the facades without conversion: the types
    // are the shared substrate, not parallel definitions.
    comptime {
        std.debug.assert(bypass.Options == assembly.leaf.zstd.Options);
    }
    const options: bypass.Options = .{ .window_size = 1 << 21 };
    const sentence = "the quick brown fox jumps over the lazy dog. ";
    var input_storage: [sentence.len * 40]u8 = undefined;
    for (&input_storage, 0..) |*byte, index| byte.* = sentence[index % sentence.len];
    const input = input_storage[0..];

    const history = try std.testing.allocator.alloc(u8, bypass.zstdEncodeHistoryLen(input.len, 0, options));
    defer std.testing.allocator.free(history);
    const encoded = try std.testing.allocator.alloc(u8, bypass.zstdEncodeBound(input.len, options));
    defer std.testing.allocator.free(encoded);
    const frame_budget = if (assembly.leaf.zstd.useDfast(options) or assembly.leaf.zstd.useRowMatch(options))
        @min(input.len, assembly.leaf.zstd.encoder_frame_size_max)
    else
        @min(@as(usize, options.window_size), assembly.leaf.zstd.encoder_frame_size_max);
    const workspace = try std.testing.allocator.alloc(u32, assembly.leaf.zstd.encoderWorkspaceU32Count(0, frame_budget, options));
    defer std.testing.allocator.free(workspace);
    const workspace_bytes = std.mem.sliceAsBytes(workspace);

    const encoded_len = try bypass.zstdEncode(
        .{ .ptr = input.ptr, .len = input.len },
        .{ .ptr = encoded.ptr, .len = encoded.len },
        .{ .ptr = history.ptr, .len = history.len },
        .{ .ptr = workspace_bytes.ptr, .len = workspace_bytes.len },
        options,
    );
    try std.testing.expect(encoded_len != 0);

    // Decode reuses the encode history: it needs no more than that.
    const decoded = try std.testing.allocator.alloc(u8, input.len);
    defer std.testing.allocator.free(decoded);
    const decoded_len = try bypass.zstdDecodeStream(
        .{ .ptr = encoded.ptr, .len = encoded_len },
        .{ .ptr = decoded.ptr, .len = decoded.len },
        .{ .ptr = history.ptr, .len = history.len },
        options,
    );
    try std.testing.expectEqual(input.len, decoded_len);
    try std.testing.expectEqualSlices(u8, input, decoded[0..decoded_len]);
}

fn makeCorpus(buffer: []u8) void {
    var state: u64 = 0x9e3779b97f4a7c15;
    var index: usize = 0;
    while (index < buffer.len) : (index += 8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        const word = std.mem.toBytes(state);
        @memcpy(buffer[index..][0..@min(8, buffer.len - index)], word[0..@min(8, buffer.len - index)]);
    }
}

fn upper(byte: u8) u8 {
    return if (byte >= 'a' and byte <= 'z') byte - 32 else byte;
}

test "gzip session decode and caller filter pipeline through assembly" {
    const drivers = assembly.drivers;
    const gzip = assembly.grammar.gzip;

    var corpus: [1 << 16]u8 = undefined;
    makeCorpus(&corpus);

    const compressed = try std.testing.allocator.alloc(u8, drivers.gzipEncodedSizeBound(corpus.len));
    defer std.testing.allocator.free(compressed);
    var history: [gzip.deflate_history_size]u8 = undefined;
    const compressed_len = try drivers.gzipEncode(compressed, &corpus, &history, drivers.default_encode_options, .bounded);

    // Decode in steps through a session while applying a caller-built
    // filter; the filtered output must match the filter over the raw
    // corpus, and the plain output must match the corpus byte for byte.
    const storage_plan = drivers.gzipDecodeStorage();
    const raw_storage = try std.testing.allocator.alloc(u8, storage_plan + @alignOf(drivers.GzipDecode));
    defer std.testing.allocator.free(raw_storage);
    const base = @intFromPtr(raw_storage.ptr);
    const aligned = std.mem.alignForward(usize, base, @alignOf(drivers.GzipDecode));
    const storage = raw_storage[aligned - base ..][0..storage_plan];
    var session = try drivers.gzipDecodeSession(storage, .{});

    var filtered: std.ArrayList(u8) = .empty;
    defer filtered.deinit(std.testing.allocator);
    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(std.testing.allocator);
    var pos: usize = 0;
    var steps: usize = 0;
    while (steps < 100000) {
        steps += 1;
        const take = @min(65536, compressed_len - pos);
        var scratch: [98304]u8 = undefined;
        const result = session.step(compressed[pos..][0..take], &scratch, pos + take == compressed_len);
        try filtered.appendSlice(std.testing.allocator, scratch[0..result.produced]);
        try plain.appendSlice(std.testing.allocator, scratch[0..result.produced]);
        if (result.status == .failed) return error.UnexpectedFailure;
        pos += result.consumed;
        if (result.status == .done) break;
        if (result.consumed == 0 and result.produced == 0) return error.NoProgress;
    }
    try std.testing.expectEqual(compressed_len, pos);
    for (filtered.items) |*byte| byte.* = upper(byte.*);
    var expected: std.ArrayList(u8) = .empty;
    defer expected.deinit(std.testing.allocator);
    for (&corpus) |byte| try expected.append(std.testing.allocator, upper(byte));
    try std.testing.expectEqualSlices(u8, expected.items, filtered.items);
    try std.testing.expectEqualSlices(u8, &corpus, plain.items);
}

test "iso flat file write inspect decode through assembly" {
    const iso = assembly.volume.iso;
    const entries = [_]iso.Entry{
        .{ .name = "hello.txt", .data = "hello iso" },
        .{ .name = "data.bin", .data = "ABCABCABCABC" },
    };
    const planned = try iso.archiveSize(&entries);
    const archive = try std.testing.allocator.alloc(u8, planned);
    defer std.testing.allocator.free(archive);
    var scratch: [iso.scratch_size]u8 = undefined;
    const written = try iso.encode(&entries, archive, &scratch);
    try std.testing.expectEqual(planned, written);
    try std.testing.expectEqual(@as(u64, 2), try iso.inspectCount(archive[0..written], &scratch));
    // Ordinal order is the format's own; locate each entry by its size.
    const first = try iso.inspectOrdinal(archive[0..written], 0, &scratch);
    const second = try iso.inspectOrdinal(archive[0..written], 1, &scratch);
    try std.testing.expect((first.size == 9 and second.size == 12) or (first.size == 12 and second.size == 9));
    const hello_ordinal: u64 = if (first.size == 9) 0 else 1;
    const data_ordinal: u64 = if (first.size == 9) 1 else 0;
    var out: [16]u8 = undefined;
    const n = try iso.decodeOrdinal(archive[0..written], hello_ordinal, &out, &scratch);
    try std.testing.expectEqualSlices(u8, "hello iso", out[0..n]);
    const m = try iso.decodeOrdinal(archive[0..written], data_ordinal, &out, &scratch);
    try std.testing.expectEqualSlices(u8, "ABCABCABCABC", out[0..m]);
}

test "truncated gzip fails through the public session" {
    const drivers = assembly.drivers;
    const stream = "a steady stream of compressible text, repeated. ";
    var input_storage: [stream.len * 20]u8 = undefined;
    for (&input_storage, 0..) |*byte, index| byte.* = stream[index % stream.len];
    const input = input_storage[0..];
    const compressed = try std.testing.allocator.alloc(u8, drivers.gzipEncodedSizeBound(input.len));
    defer std.testing.allocator.free(compressed);
    var history: [assembly.grammar.gzip.deflate_history_size]u8 = undefined;
    const compressed_len = try drivers.gzipEncode(compressed, input, &history, drivers.default_encode_options, .bounded);
    try std.testing.expect(compressed_len > 5);

    const storage_plan = drivers.gzipDecodeStorage();
    const raw_storage = try std.testing.allocator.alloc(u8, storage_plan + @alignOf(drivers.GzipDecode));
    defer std.testing.allocator.free(raw_storage);
    const base = @intFromPtr(raw_storage.ptr);
    const aligned = std.mem.alignForward(usize, base, @alignOf(drivers.GzipDecode));
    const storage = raw_storage[aligned - base ..][0..storage_plan];
    var session = try drivers.gzipDecodeSession(storage, .{});

    var scratch: [98304]u8 = undefined;
    const truncated = compressed[0 .. compressed_len - 5];
    var pos: usize = 0;
    var saw_done = false;
    var saw_failed = false;
    var guard: usize = 0;
    while (guard < 100000) {
        guard += 1;
        const take = @min(65536, truncated.len - pos);
        const step = session.step(truncated[pos..][0..take], &scratch, pos + take == truncated.len);
        if (step.status == .done) {
            saw_done = true;
            break;
        }
        if (step.status == .failed) {
            saw_failed = true;
            try std.testing.expect(step.exception != null);
            break;
        }
        if (step.consumed == 0 and step.produced == 0) break;
        pos += step.consumed;
    }
    try std.testing.expect(!saw_done);
    try std.testing.expect(saw_failed);
}
