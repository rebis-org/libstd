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

// The session-able surface, single-sourced for matchSessionKind, sizing, and
// the catalog projection. Ordering is ABI once released: append only.
const session_pair = struct { component: [:0]const u8, verb: [:0]const u8 };
// The write-side pair (tar/write) was removed from the public boundary: its
// store-only, fixed-mode framing could not express the tar profile's
// typeflags, links, modes, or pax long names, and misled hosts away from the
// envelope path. A full-surface tar write session can re-enter as a v2 pair.
const session_pairs = [_]session_pair{
    .{ .component = "gzip", .verb = "decode" },
};

const SessionKind = enum { gzip_decode };

fn matchSessionKind(component: [*:0]const u8, verb: [*:0]const u8) ?SessionKind {
    const component_name = std.mem.span(component);
    const verb_name = std.mem.span(verb);
    for (session_pairs) |pair| {
        if (std.mem.eql(u8, component_name, pair.component) and std.mem.eql(u8, verb_name, pair.verb)) {
            return .gzip_decode;
        }
    }
    return null;
}

export fn stdk_session_storage(component: [*:0]const u8, verb: [*:0]const u8) callconv(.c) u64 {
    return switch (matchSessionKind(component, verb) orelse return 0) {
        .gzip_decode => driverStateOffset() + drivers.gzipDecodeStorage(),
    };
}

// Layout is [Session record][driver state] so creation never collides with managed state.
fn createWithBudgets(
    component: [*:0]const u8,
    verb: [*:0]const u8,
    storage: ?[*]u8,
    storage_len: u64,
    budgets: sessions.Budgets,
) u32 {
    const kind = matchSessionKind(component, verb) orelse return envelope.Status.unsupported;
    const bytes = storage orelse return envelope.Status.invalid_call;
    if (storage_len < driverStateOffset()) return envelope.Status.insufficient_capacity;
    const state_storage = bytes[driverStateOffset()..storage_len];
    const session = switch (kind) {
        .gzip_decode => drivers.gzipDecodeSession(state_storage, budgets) catch |failure| return failureStatus(failure),
    };
    std.mem.bytesAsValue(Session, bytes[0..@sizeOf(Session)]).* = session;
    return envelope.Status.ok;
}

export fn stdk_session_create(
    component: [*:0]const u8,
    verb: [*:0]const u8,
    storage: ?[*]u8,
    storage_len: u64,
) callconv(.c) u32 {
    return createWithBudgets(component, verb, storage, storage_len, .{});
}

// Bounded variant of stdk_session_create: per-session ceilings on encoded,
// decoded, work, and entry bytes. Hosts that run untrusted archives through
// the stepped boundary pass their zip-bomb limits here instead of policing
// produced bytes themselves; the unbounded create keeps the old behavior.
export fn stdk_session_bounded(
    component: [*:0]const u8,
    verb: [*:0]const u8,
    storage: ?[*]u8,
    storage_len: u64,
    max_encoded: u64,
    max_decoded: u64,
    max_work: u64,
    max_entries: u64,
) callconv(.c) u32 {
    return createWithBudgets(component, verb, storage, storage_len, .{
        .max_encoded = max_encoded,
        .max_decoded = max_decoded,
        .max_work = max_work,
        .max_entries = max_entries,
    });
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
    if (result.status == .failed) {
        session.failure_status = failureStatus(result.failure orelse error.InternalFailure);
        session.failure_detail = result.failure_value;
        return failureStatus(result.failure orelse error.InternalFailure);
    }
    return envelope.Status.ok;
}

// Failure detail for the last failed step: the envelope status vocabulary
// plus a driver-defined scalar (the required capacity for
// insufficient_capacity, 0 where undefined). Callers read it while the
// storage is alive, immediately after a failed step.
export fn stdk_session_failure(
    handle: ?*anyopaque,
    status_out: ?*u32,
    detail_out: ?*u64,
) callconv(.c) u32 {
    const session: *Session = @ptrCast(@alignCast(handle orelse return envelope.Status.invalid_call));
    if (session.ops == &destroyed_ops) return envelope.Status.invalid_call;
    if (status_out) |status| status.* = session.failure_status;
    if (detail_out) |detail| detail.* = session.failure_detail;
    return envelope.Status.ok;
}

// The session-able (component, verb) pairs as a versioned, comma-separated
// "component/verb" list, so hosts discover streamable codecs at runtime
// instead of hardcoding them. The leading "v1:" is the format version and
// the retirement mechanism: pairs are append-only within a version, and a
// breaking change (removal or new field shape) bumps the prefix so hosts
// can gate on it. Ordering matches session_pairs and is ABI once released.
export fn stdk_session_catalog() callconv(.c) [*:0]const u8 {
    return session_catalog_text;
}

const session_catalog_text: [:0]const u8 = blk: {
    var text: [:0]const u8 = "v1:";
    for (session_pairs, 0..) |pair, index| {
        const entry = pair.component ++ "/" ++ pair.verb;
        text = if (index == 0) text ++ entry else text ++ "," ++ entry;
    }
    break :blk text;
};

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
