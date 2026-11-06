const std = @import("std");

const resource = @import("../../kernel/resource.zig");
const vocabulary = @import("../../kernel/vocabulary.zig");
const zstd = @import("../../representation/leaf/zstd/onprem.zig");
const common = @import("../common.zig");
const options = @import("options.zig");
const run = @import("run.zig");

const Exception = vocabulary.Exception;

// The trainer is a codec by envelope only: a read extracts a frame's dictionary, a write trains one; neither streams.
pub fn hook(running: *run.Run) Exception!void {
    const call = running.call();
    const response = running.response();
    const source_resource = running.source();
    const sink = running.sink();
    const limits = running.limits();
    const command_mask = running.commandMask();
    const provider = running.provider();
    const workspace = running.workspace();
    try run.requireReplay(running, false);
    if (command_mask == vocabulary.command_mask_read) {
        const input = try common.materializeSource(.require_size, source_resource, workspace, limits.encoded_bytes);
        const content = zstd.dictionaryContent(input) catch |err| switch (err) {
            error.DataException, error.UnsupportedException, error.ResourceException, error.IoException, error.IntegrityException => |e| return e,
        };
        if (content.len > limits.decoded_bytes) return error.ResourceException;
        if (input.len + content.len > limits.codec_work) return error.ResourceException;
        if (sink) |sink_resource| {
            if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.UnsupportedException;
            try common.requireSinkCapacity(sink_resource, call, content.len);
            try common.commitBytesToSink(sink_resource, call, content);
        }
        response.byte_length = content.len;
        return;
    }
    if (command_mask != vocabulary.command_mask_write and command_mask != vocabulary.command_mask_query) return error.UnsupportedException;
    const sample_size = (try options.optCast(call.request, "zdict", "sample_size", usize)) orelse return error.CallException;
    if (sample_size == 0) return error.CallException;
    const input = try common.materializeSource(.require_size, source_resource, workspace, limits.decoded_bytes);
    if (input.len % sample_size != 0) return error.CallException;
    const sample_count = input.len / sample_size;
    if (sample_count == 0 or sample_count > (1 << 20)) return error.CallException;
    const samples = try workspace.take([]const u8, sample_count);
    for (0..sample_count) |index| {
        samples[index] = input[index * sample_size ..][0..sample_size];
    }
    // An explicit cap serves a small dictionary from a large corpus; the
    // trainer needs room for its header either way.
    var capacity = std.math.add(usize, input.len, zstd.dictionary_header_size) catch return error.ResourceException;
    if (try options.optCast(call.request, "zdict", "dictionary_size", usize)) |wanted| {
        if (wanted < zstd.dictionary_header_size + 8) return error.CallException;
        capacity = @min(capacity, wanted);
    }
    const staging = try workspace.take(u8, capacity);
    const train_scratch = try workspace.take(u8, zstd.trainWorkspaceSize());
    const produced = try zstd.trainDictionary(samples, capacity, staging, train_scratch, provider);
    if (produced > limits.encoded_bytes) return error.ResourceException;
    if (input.len + produced > limits.codec_work) return error.ResourceException;
    if (sink) |sink_resource| {
        if (!sink_resource.hasCapability(resource.capability_bit_write)) return error.UnsupportedException;
        try common.requireSinkCapacity(sink_resource, call, produced);
        try common.commitBytesToSink(sink_resource, call, staging[0..produced]);
    }
    response.byte_length = produced;
}
