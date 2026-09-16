const std = @import("std");

const harness = @import("harness");

const bypass = @import("bypass");
const env_mod = @import("env.zig");
const matrix = @import("matrix.zig");
const metric = @import("metric.zig");

const ours_caps: u64 = harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay;

const Buf = struct {
    // Worst case is 12 nodes on the bound-query shape, hence 16 slots.
    nodes: [16]harness.Node,
    len: usize = 0,
    entry: harness.ArchiveEntryNodes,
};

// Filled by the query and entry builders before either is read.
fn freshBuf() Buf {
    return .{ .nodes = undefined, .entry = undefined };
}

const Invoke = struct {
    status: u32,
    len: usize,
    ns: u64,
};

fn profileOf(kind: matrix.Kind) harness.Id {
    return switch (kind) {
        .gzip => harness.ids.gzip,
        .bzip2 => harness.ids.bzip2,
        .lzma => harness.ids.lzma,
        .lzma2 => harness.ids.lzma2,
        .lzma_file => harness.ids.lzma_file,
        .xz => harness.ids.xz,
        .zstd => harness.ids.zstd,
        .tar => harness.ids.tar,
        .zip => harness.ids.zip,
        .seven_zip => harness.ids.sevenzip,
        .rar => harness.ids.rar,
    };
}

fn confirmed(kind: matrix.Kind) bool {
    return kind == .xz or kind == .zstd;
}

fn add(buffer: *Buf, node: harness.Node) void {
    buffer.nodes[buffer.len] = node;
    buffer.len += 1;
}

fn build(buffer: *Buf, write: bool, row: matrix.Row, source: []const u8, sink: []u8, bound: bool) void {
    buffer.len = 0;
    add(buffer, harness.paramProfile(profileOf(row.kind)));
    add(buffer, if (row.archive and write) harness.scalarNode(harness.ids.source) else harness.sourceSpan(source));
    add(buffer, harness.sinkSpan(sink));
    for (row.params) |param| {
        add(buffer, harness.paramScalar(param.family, param.ordinal, harness.cmd_all, param.value));
    }
    add(buffer, harness.capabilityParam(ours_caps));
    add(buffer, harness.sizingModeParam(if (row.archive) harness.size_metadata_exact else harness.size_measured));
    add(buffer, harness.commitModeParam(if (write and row.archive or confirmed(row.kind)) harness.commit_confirmed else harness.commit_tentative));
    if (bound and write and !row.archive) add(buffer, harness.scalarNode(harness.ids.size_bound));
    if (row.archive) {
        if (write) {
            const entry = if (row.method)
                harness.archiveEntryMethod(&buffer.entry, "input.bin", source, 0)
            else
                harness.archiveEntryNode(&buffer.entry.name, &buffer.entry.data, "input.bin", source);
            add(buffer, entry);
        } else {
            add(buffer, harness.archiveOrdinalParam(0));
        }
    }
}

fn invoke(env: *env_mod.Env, buffer: *Buf, write: bool, workspace: []u8) Invoke {
    harness.linkNodes(buffer.nodes[0..buffer.len]);
    var response = harness.Node.init();
    const t0 = env.now();
    const status = harness.invoke(if (write) harness.ids.write else harness.ids.read, &buffer.nodes[0], &response, workspace.ptr, workspace.len, null, null, null);
    return .{ .status = status, .len = @intCast(response.byte_length), .ns = env.now() - t0 };
}

fn decode(env: *env_mod.Env, buffer: *Buf, row: matrix.Row, archive: []const u8, expected: []const u8, decoded: []u8, workspace: []u8) metric.Metric {
    build(buffer, false, row, archive, decoded, false);
    const result = invoke(env, buffer, false, workspace);
    if (result.status != 0) {
        std.debug.print("Benchmark read failed: status {d}, output length {d}, input length {d}.\n", .{ result.status, result.len, archive.len });
    }
    return .{
        .decode_ns = result.ns,
        .ok = result.status == 0 and result.len == expected.len and std.mem.eql(u8, decoded[0..expected.len], expected),
    };
}

pub fn transform(env: *env_mod.Env, row: matrix.Row, input: []const u8, encoded: []u8, decoded: []u8, workspace: []u8) metric.Metric {
    if (row.bypass) return bypassTransform(env, row, input, encoded, decoded, workspace);
    var buffer = freshBuf();
    build(&buffer, true, row, input, encoded, env.bounded);
    const write_result = invoke(env, &buffer, true, workspace);
    if (write_result.status != 0 or write_result.len == 0 or write_result.len > encoded.len) {
        std.debug.print("Benchmark write failed: status {d}, output length {d}.\n", .{ write_result.status, write_result.len });
        return .{ .encode_ns = write_result.ns, .ok = false };
    }
    const read_result = decode(env, &buffer, row, encoded[0..write_result.len], input, decoded, workspace);
    return .{ .encode_ns = write_result.ns, .decode_ns = read_result.decode_ns, .encoded = write_result.len, .ok = read_result.ok };
}

// Bypass row caller-wires the zstd leaf with no kernel in the loop; the untimed kernel transform proves byte-identity.
fn bypassOptions(row: matrix.Row) bypass.Options {
    var options: bypass.Options = .{ .window_size = 1 << 21 };
    for (row.params) |param| {
        switch (param.ordinal) {
            1 => options.window_size = std.math.cast(u32, param.value) orelse options.window_size,
            2 => {},
            3 => options.hash_bits = std.math.cast(u5, param.value) orelse options.hash_bits,
            4 => options.max_chain = std.math.cast(u32, param.value) orelse options.max_chain,
            5 => options.nice_len = std.math.cast(u32, param.value) orelse options.nice_len,
            6 => options.search_window = std.math.cast(u32, param.value) orelse options.search_window,
            7 => options.lazy = param.value != 0,
            8 => options.skip_interior_insert = param.value != 0,
            9 => options.double_hash = param.value != 0,
            10 => options.row_match = param.value != 0,
            else => {},
        }
    }
    return options;
}

fn bypassTransform(env: *env_mod.Env, row: matrix.Row, input: []const u8, encoded: []u8, decoded: []u8, workspace: []u8) metric.Metric {
    const options = bypassOptions(row);
    // Decode needs no more than the encode history: size once, reuse for both.
    const history_len = bypass.zstdEncodeHistoryLen(input.len, 0, options);

    // Untimed kernel reference: byte-identity is the contract.
    const kernel_encoded = env.allocator.alloc(u8, encoded.len) catch return .{ .ok = false };
    defer env.allocator.free(kernel_encoded);
    const kernel_decoded = env.allocator.alloc(u8, input.len) catch return .{ .ok = false };
    defer env.allocator.free(kernel_decoded);
    var kernel_row = row;
    kernel_row.bypass = false;
    const kernel = transform(env, kernel_row, input, kernel_encoded, kernel_decoded, workspace);
    if (!kernel.ok) {
        std.debug.print("bypass {s}: kernel reference failed\n", .{row.name});
        return .{ .ok = false };
    }

    const history = env.allocator.alloc(u8, history_len) catch return .{ .ok = false };
    defer env.allocator.free(history);

    const t0 = env.now();
    const encoded_size = bypass.zstdEncode(.{ .ptr = input.ptr, .len = input.len }, .{ .ptr = encoded.ptr, .len = encoded.len }, .{ .ptr = history.ptr, .len = history.len }, .{ .ptr = workspace.ptr, .len = workspace.len }, options) catch |err| {
        std.debug.print("bypass {s}: encode failed: {s}\n", .{ row.name, @errorName(err) });
        return .{ .ok = false };
    };
    const t1 = env.now();
    const decoded_size = bypass.zstdDecodeStream(.{ .ptr = encoded.ptr, .len = encoded_size }, .{ .ptr = decoded.ptr, .len = decoded.len }, .{ .ptr = history.ptr, .len = history.len }, options) catch |err| {
        std.debug.print("bypass {s}: decode failed: {s}\n", .{ row.name, @errorName(err) });
        return .{ .encode_ns = t1 - t0, .encoded = encoded_size, .ok = false };
    };
    const t2 = env.now();

    const identical = encoded_size == kernel.encoded and
        std.mem.eql(u8, encoded[0..encoded_size], kernel_encoded[0..kernel.encoded]) and
        decoded_size == input.len and
        std.mem.eql(u8, decoded[0..decoded_size], kernel_decoded[0..input.len]);
    if (!identical) std.debug.print("bypass {s}: kernel/bypass bytes differ (enc {d}/{d} dec {d}/{d})\n", .{ row.name, encoded_size, kernel.encoded, decoded_size, input.len });
    return .{ .encode_ns = t1 - t0, .decode_ns = t2 - t1, .encoded = encoded_size, .ok = identical };
}

// Buffer carries the analytic bound: the bzip2 bound alone exceeds the 1.5x heuristic.
pub fn encodedBound(row: matrix.Row, input: []const u8, workspace: []u8) !usize {
    var buffer = freshBuf();
    buffer.len = 0;
    add(&buffer, harness.paramProfile(profileOf(row.kind)));
    add(&buffer, harness.paramTargetCommand(harness.ids.write));
    add(&buffer, harness.sourceSpan(input));
    for (row.params) |param| {
        add(&buffer, harness.paramScalar(param.family, param.ordinal, harness.cmd_all, param.value));
    }
    add(&buffer, harness.capabilityParam(harness.cap_read | harness.cap_size | harness.cap_replay));
    add(&buffer, harness.sizingModeParam(harness.size_measured));
    add(&buffer, harness.commitModeParam(if (confirmed(row.kind)) harness.commit_confirmed else harness.commit_tentative));
    add(&buffer, harness.scalarNode(harness.ids.size_bound));
    harness.linkNodes(buffer.nodes[0..buffer.len]);
    var response = harness.Node.init();
    const status = harness.invoke(harness.ids.query, &buffer.nodes[0], &response, workspace.ptr, workspace.len, null, null, null);
    if (status != 0) return error.BoundQueryFailed;
    return @intCast(response.byte_length);
}

pub fn decodeOnly(env: *env_mod.Env, row: matrix.Row, archive: []const u8, expected: []const u8, decoded: []u8, workspace: []u8) metric.Metric {
    var buffer = freshBuf();
    return decode(env, &buffer, row, archive, expected, decoded, workspace);
}
