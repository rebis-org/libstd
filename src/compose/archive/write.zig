const std = @import("std");

const resource = @import("../../kernel/resource.zig");
const vocabulary = @import("../../kernel/vocabulary.zig");
const common = @import("../common.zig");
const request = @import("request.zig");
const response = @import("response.zig");
const run = @import("run.zig");
const volumes = @import("volumes.zig");

const Exception = vocabulary.Exception;
const Run = run.Run;

// One carve serves size and encode; a split plans before the target opens.
pub const Extent = struct { total: u64, count: usize };

pub fn serve(comptime F: type, running: *Run) Exception!void {
    const call = running.core.invocation.call;
    try common.requireCommit(running.plan().commit, .confirmed);
    const entries = try run.collect(F.Entry, F.fill, running);
    var writer = try F.Write.init(running, entries);
    const volume_size = try request.volumeSize(call.request);
    if (volume_size != 0) {
        if (comptime @hasDecl(F.Write, "volumePlan")) return split(F, running, &writer, volume_size);
        return error.UnsupportedException;
    }
    const required = try writer.size();
    if (running.sink() == null) {
        running.response().byte_length = required;
        return;
    }
    const sink = running.sink().?;
    try common.requireSinkCapacity(sink, call, required);
    const target = try common.SinkTarget.open(sink, running.core.workspace, required);
    const written = try writer.encode(target.output);
    running.response().byte_length = try target.publish(sink, call, written);
}

fn split(comptime F: type, running: *Run, writer: *F.Write, volume_size: u64) Exception!void {
    const call = running.core.invocation.call;
    const extent = try writer.volumePlan(volume_size);
    if (running.sink() == null) {
        running.response().byte_length = extent.total;
        return;
    }
    const total = std.math.cast(usize, extent.total) orelse return error.ResourceException;
    const sink = running.sink().?;
    try common.requireSinkCapacity(sink, call, total);
    const target = try common.SinkTarget.open(sink, running.core.workspace, total);
    const parts = try writer.volumeEmit(target.output, volume_size, extent);
    if (parts.len != extent.count) return error.InternalException;
    if (try volumes.totalBytes(parts) != total) return error.InternalException;
    running.response().byte_length = try target.publish(sink, call, total);
    try response.publishVolumeParts(call, running.response(), parts[1..]);
}
