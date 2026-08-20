const std = @import("std");

const harness = @import("harness");

const env_mod = @import("env.zig");
const matrix = @import("matrix.zig");
const metric = @import("metric.zig");

const Buf = struct {
    // Worst case today: profile + target/source + sink + 5 tuning params +
    // cap/pln/dlv + planning_bound = 12 on the bound-query shape.
    nodes: [16]harness.Node = undefined,
    len: usize = 0,
    entry: harness.ArchiveEntryNodes = undefined,
};

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
        .seven_zip => harness.ids.seven_zip_coded,
        .rar => harness.ids.rar,
    };
}

fn verified(kind: matrix.Kind) bool {
    return kind == .xz or kind == .zstd;
}

fn add(buf: *Buf, node: harness.Node) void {
    buf.nodes[buf.len] = node;
    buf.len += 1;
}

fn build(buf: *Buf, write: bool, row: matrix.Row, source: []const u8, sink: []u8, bound: bool) void {
    buf.len = 0;
    add(buf, harness.paramProfile(profileOf(row.kind)));
    add(buf, if (row.archive and write) harness.scalarNode(harness.ids.source) else harness.sourceSpan(source));
    add(buf, harness.sinkSpan(sink));
    for (row.params) |param| {
        add(buf, harness.paramScalar(param.family, param.ordinal, harness.cmd_all, param.value));
    }
    add(buf, harness.cap(harness.cap_read | harness.cap_write | harness.cap_size | harness.cap_replay));
    add(buf, harness.pln(if (row.archive) harness.plan_metadata_exact else harness.plan_replay_pass));
    add(buf, harness.dlv(if (write and row.archive or verified(row.kind)) harness.delivery_verified else harness.delivery_provisional));
    if (bound and write and !row.archive) add(buf, harness.scalarNode(harness.ids.planning_bound));
    if (row.archive) {
        if (write) {
            const entry = if (row.method)
                harness.archiveEntryMethod(&buf.entry, "input.bin", source, 0)
            else
                harness.archiveEntryNode(&buf.entry.name, &buf.entry.data, "input.bin", source);
            add(buf, entry);
        } else {
            add(buf, harness.ord(0));
        }
    }
}

fn invoke(env: *env_mod.Env, buf: *Buf, write: bool, workspace: []u8) Invoke {
    harness.linkNodes(buf.nodes[0..buf.len]);
    var response = harness.Node.init();
    const t0 = env.now();
    const status = harness.invoke(if (write) harness.ids.write else harness.ids.read, &buf.nodes[0], &response, workspace.ptr, workspace.len, null, null, null);
    return .{ .status = status, .len = @intCast(response.byte_length), .ns = env.now() - t0 };
}

fn decode(env: *env_mod.Env, buf: *Buf, row: matrix.Row, archive: []const u8, expected: []const u8, decoded: []u8, workspace: []u8) metric.Metric {
    build(buf, false, row, archive, decoded, false);
    const read = invoke(env, buf, false, workspace);
    if (read.status != 0) {
        std.debug.print("ours read status={d} len={d} input={d}\n", .{ read.status, read.len, archive.len });
    }
    return .{
        .decode_ns = read.ns,
        .ok = read.status == 0 and read.len == expected.len and std.mem.eql(u8, decoded[0..expected.len], expected),
    };
}

pub fn transform(env: *env_mod.Env, row: matrix.Row, input: []const u8, encoded: []u8, decoded: []u8, workspace: []u8) metric.Metric {
    var buf = Buf{};
    build(&buf, true, row, input, encoded, env.bound);
    const write = invoke(env, &buf, true, workspace);
    if (write.status != 0 or write.len == 0 or write.len > encoded.len) {
        std.debug.print("ours write status={d} len={d}\n", .{ write.status, write.len });
        return .{ .encode_ns = write.ns, .ok = false };
    }
    const read = decode(env, &buf, row, encoded[0..write.len], input, decoded, workspace);
    return .{ .encode_ns = write.ns, .decode_ns = read.decode_ns, .encoded = write.len, .ok = read.ok };
}

// The encode buffer carries the analytic bound, not the 1.5x heuristic: the
// bzip2 bound alone exceeds the heuristic, and the query is the same call a
// bound-planning consumer makes.
pub fn encodedBound(row: matrix.Row, input: []const u8, workspace: []u8) !usize {
    var buf = Buf{};
    buf.len = 0;
    add(&buf, harness.paramProfile(profileOf(row.kind)));
    add(&buf, harness.paramTargetCommand(harness.ids.write));
    add(&buf, harness.sourceSpan(input));
    for (row.params) |param| {
        add(&buf, harness.paramScalar(param.family, param.ordinal, harness.cmd_all, param.value));
    }
    add(&buf, harness.cap(harness.cap_read | harness.cap_size | harness.cap_replay));
    add(&buf, harness.pln(harness.plan_replay_pass));
    add(&buf, harness.dlv(if (verified(row.kind)) harness.delivery_verified else harness.delivery_provisional));
    add(&buf, harness.scalarNode(harness.ids.planning_bound));
    harness.linkNodes(buf.nodes[0..buf.len]);
    var response = harness.Node.init();
    const status = harness.invoke(harness.ids.query, &buf.nodes[0], &response, workspace.ptr, workspace.len, null, null, null);
    if (status != 0) return error.BoundQueryFailed;
    return @intCast(response.byte_length);
}

pub fn decodeOnly(env: *env_mod.Env, row: matrix.Row, archive: []const u8, expected: []const u8, decoded: []u8, workspace: []u8) metric.Metric {
    var buf = Buf{};
    return decode(env, &buf, row, archive, expected, decoded, workspace);
}
