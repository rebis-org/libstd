const vocabulary = @import("../../kernel/vocabulary.zig");
const common = @import("../common.zig");
const run = @import("run.zig");

const Exception = vocabulary.Exception;

// The echo fixture probes the protocol: confirmed commits stage the payload, tentative ones stream it, exercising both publish routes.
pub fn hook(running: *run.Run) Exception!void {
    const call = running.call();
    const response = running.response();
    const source_resource = running.source();
    const sink = running.sink();
    const sizing = running.sizing();
    const commit = running.commit();
    const limits = running.limits();
    const workspace = running.workspace();
    const sink_resource = sink orelse return error.CallException;
    const output_size = try common.planOutputSize(source_resource, sizing, limits, workspace);
    try common.requireSinkCapacity(sink_resource, call, output_size);
    const staging_required: usize = if (commit == .confirmed) output_size else 0;
    if (workspace.bytes.len < staging_required) {
        common.writeCapacityDiagnostic(call, staging_required, workspace.bytes.len);
        return error.CapacityException;
    }
    if (commit == .confirmed) {
        const staging = try workspace.take(u8, output_size);
        var offset: usize = 0;
        while (offset < staging.len) {
            const n = try source_resource.read(staging[offset..]);
            if (n == 0) return error.IoException;
            offset += n;
        }
        if (staging.len > 0 and staging[staging.len - 1] == 0xff) return error.IntegrityException;
        try common.commitBytesToSink(sink_resource, call, staging);
    } else {
        var buffer: [4096]u8 = undefined;
        var remaining = output_size;
        while (remaining > 0) {
            const chunk = @min(remaining, buffer.len);
            const n = try source_resource.read(buffer[0..chunk]);
            if (n == 0) return error.IoException;
            try common.commitBytesToSink(sink_resource, call, buffer[0..n]);
            remaining -= n;
        }
    }
    response.byte_length = output_size;
}
