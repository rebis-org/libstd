const std = @import("std");

const bounds = @import("../../common/primitive/bounds.zig");
const abi = @import("../../kernel/envelope.zig");
const resource = @import("../../kernel/resource.zig");
const vocabulary = @import("../../kernel/vocabulary.zig");
const common = @import("../common.zig");
const request = @import("request.zig");
const response = @import("response.zig");
const run = @import("run.zig");
const volumes = @import("volumes.zig");

const Call = abi.Call;
const Exception = vocabulary.Exception;
pub const Info = response.Info;
const Run = run.Run;

// A read is one inspect or one decode, never both.
fn materialization(comptime F: type) common.SourceSizing {
    return if (@hasDecl(F, "materialization")) F.materialization else .size_or_budget;
}

pub fn serve(comptime F: type, running: *Run) Exception!void {
    const tail = try request.volumeParts(running.requestNode(), running.limits(), running.core.workspace);
    try volumes.checkOverlap(running.core.workspace, running.sink(), tail);
    if (running.sink() == null) return inspect(F, running, tail);
    return decode(F, running, tail);
}

fn inspect(comptime F: type, running: *Run, tail: []const []const u8) Exception!void {
    const opened = try open(F, running, tail);
    var source = opened.source;
    switch (try request.projection(running.requestNode())) {
        .count => running.response().byte_length = try source.count(),
        .size => |ordinal| running.response().byte_length = (try source.locate(ordinal)).size,
        .metadata => |ordinal| try response.publishInfo(running.core.invocation.call, running.response(), try source.locate(ordinal)),
        .manifest => running.response().byte_length = try manifest(F, running, tail),
    }
}

// The whole-set metadata projection: one walk fills one group node per
// entry. Formats without a one-pass walk refuse rather than rescan.
fn manifest(comptime F: type, running: *Run, tail: []const []const u8) Exception!u64 {
    if (!comptime @hasDecl(F.Read, "manifest")) return error.UnsupportedException;
    const opened = try open(F, running, tail);
    var source = opened.source;
    return source.manifest(running.core.invocation.call, running.response());
}

fn decode(comptime F: type, running: *Run, tail: []const []const u8) Exception!void {
    const call = running.core.invocation.call;
    const sink = running.sink().?;
    try common.requireCommit(running.plan().commit, .tentative);
    const ordinal = request.ordinal(call.request);
    var opened = try open(F, running, tail);
    const info = try opened.source.locate(ordinal);
    const size = std.math.cast(usize, info.size) orelse return error.ResourceException;
    if (size > running.limits().decoded_bytes) return error.ResourceException;
    try common.requireSinkCapacity(sink, call, size);
    if (info.ready) |span| {
        if (span.len != size) return error.InternalException;
        _ = try publishReady(sink, call, try bounds.slice(opened.archive, span.offset, span.len));
    } else {
        const target = try common.SinkTarget.open(sink, running.core.workspace, size);
        _ = try opened.source.read(ordinal, target.output);
        _ = try target.publish(sink, call, size);
    }
    running.response().byte_length = size;
}

fn materialize(comptime F: type, running: *Run) Exception![]const u8 {
    return common.materializeSource(materialization(F), running.core.invocation.source, running.core.workspace, running.limits().encoded_bytes);
}

// A format with initView reads a callback source through its own window;
// every other source still materializes, so direct spans stay zero-copy.
// The archive rides along because a ready span publishes from it directly.
fn Opened(comptime F: type) type {
    return struct {
        archive: []const u8,
        source: F.Read,
    };
}

fn open(comptime F: type, running: *Run, tail: []const []const u8) Exception!Opened(F) {
    if (@hasDecl(F.Read, "initView") and running.core.invocation.source.kind == .callback_read) {
        return .{ .archive = &.{}, .source = try F.Read.initView(running, tail) };
    }
    const archive = try materialize(F, running);
    return .{ .archive = archive, .source = try F.Read.init(running, archive, tail) };
}

// Bytes in hand need no staging: a direct sink receives its copy.
fn publishReady(sink: *resource.Resource, call: *Call, bytes: []const u8) Exception!usize {
    switch (sink.kind) {
        .direct_write => @memcpy(try common.sinkDirectBuffer(sink, bytes.len), bytes),
        else => try common.commitBytesToSink(sink, call, bytes),
    }
    return bytes.len;
}
