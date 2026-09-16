const std = @import("std");

const envelope = @import("../kernel/envelope.zig");
const drivers = @import("drivers.zig");
const sessions = @import("sessions.zig");
const Failure = @import("../common/primitive/failure.zig").Failure;

// Caller-owned storage: the handle IS the storage pointer, so no allocator, registry, or global state and sessions stay isolated.
// Destroy nulls the ops word so post-destroy steps fail deterministically; no span constructor since it would be a no-op.

const Session = sessions.Session;

fn failureStatus(failure: Failure) u32 {
    return switch (failure) {
        error.InvalidCall => envelope.Status.invalid_call,
        error.Unsupported => envelope.Status.unsupported,
        error.InsufficientCapacity => envelope.Status.insufficient_capacity,
        error.InvalidData => envelope.Status.invalid_data,
        error.IntegrityFailure => envelope.Status.integrity_failure,
        error.ResourceLimit => envelope.Status.resource_limit,
        else => envelope.Status.internal_failure,
    };
}

const SessionKind = enum { gzip_decode, tar_write };

fn matchSessionKind(component: [*:0]const u8, verb: [*:0]const u8) ?SessionKind {
    const component_name = std.mem.span(component);
    const verb_name = std.mem.span(verb);
    if (std.mem.eql(u8, component_name, "gzip") and std.mem.eql(u8, verb_name, "decode")) return .gzip_decode;
    if (std.mem.eql(u8, component_name, "tar") and std.mem.eql(u8, verb_name, "write")) return .tar_write;
    return null;
}

export fn stdk_session_storage(component: [*:0]const u8, verb: [*:0]const u8) callconv(.c) u64 {
    return switch (matchSessionKind(component, verb) orelse return 0) {
        .gzip_decode => driverStateOffset() + drivers.gzipDecodeStorage(),
        .tar_write => driverStateOffset() + drivers.tarWriteStorage(),
    };
}

// Layout is [Session record][driver state] so creation never collides with managed state.
export fn stdk_session_create(
    component: [*:0]const u8,
    verb: [*:0]const u8,
    storage: ?[*]u8,
    storage_len: u64,
) callconv(.c) u32 {
    const kind = matchSessionKind(component, verb) orelse return envelope.Status.unsupported;
    const bytes = storage orelse return envelope.Status.invalid_call;
    if (storage_len < driverStateOffset()) return envelope.Status.insufficient_capacity;
    const state_storage = bytes[driverStateOffset()..storage_len];
    const session = switch (kind) {
        .gzip_decode => drivers.gzipDecodeSession(state_storage, .{}) catch |failure| return failureStatus(failure),
        .tar_write => drivers.tarWriteSession(state_storage, .{}) catch |failure| return failureStatus(failure),
    };
    std.mem.bytesAsValue(Session, bytes[0..@sizeOf(Session)]).* = session;
    return envelope.Status.ok;
}

fn driverStateOffset() usize {
    return std.mem.alignForward(usize, @sizeOf(Session), 16);
}

export fn stdk_session_step(
    handle: ?*anyopaque,
    input: ?[*]const u8,
    input_len: u64,
    output: ?[*]u8,
    output_len: u64,
    end_of_input: c_int,
    counts_out: ?*[2]u64,
    state_out: ?*c_int,
) callconv(.c) u32 {
    const session: *Session = @ptrCast(@alignCast(handle orelse return envelope.Status.invalid_call));
    const counts = counts_out orelse return envelope.Status.invalid_call;
    if (session.ops == &destroyed_ops) return envelope.Status.invalid_call;
    const input_slice: []const u8 = if (input) |ptr| ptr[0..input_len] else &.{};
    const output_slice: []u8 = if (output) |ptr| ptr[0..output_len] else &.{};
    const result = session.step(input_slice, output_slice, end_of_input != 0);
    counts[0] = result.consumed;
    counts[1] = result.produced;
    if (state_out) |state| state.* = switch (result.status) {
        .open => 0,
        .done => 1,
        .failed => -1,
    };
    if (result.status == .failed) return failureStatus(result.failure orelse error.InternalFailure);
    return envelope.Status.ok;
}

// Destroy is idempotent; stepping a destroyed session is invalid_call.
export fn stdk_session_destroy(handle: ?*anyopaque) callconv(.c) u32 {
    const session: *Session = @ptrCast(@alignCast(handle orelse return envelope.Status.invalid_call));
    if (session.ops == &destroyed_ops) return envelope.Status.ok;
    session.destroy();
    session.ops = &destroyed_ops;
    return envelope.Status.ok;
}

// Sentinel ops for destroyed sessions; function pointers are never called since callers check first.
const destroyed_ops = sessions.Ops{
    .step = struct {
        fn call(state: *anyopaque, input: []const u8, output: []u8, end_of_input: bool) sessions.StepResult {
            _ = state;
            _ = input;
            _ = output;
            _ = end_of_input;
            unreachable;
        }
    }.call,
    .destroy = struct {
        fn call(state: *anyopaque) void {
            _ = state;
        }
    }.call,
};
