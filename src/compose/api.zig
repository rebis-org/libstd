const std = @import("std");

const envelope = @import("../kernel/envelope.zig");
const vocabulary = @import("../kernel/vocabulary.zig");
const drivers = @import("drivers.zig");
const sessions = @import("sessions.zig");
const Exception = @import("../common/primitive/exception.zig").Exception;

// Caller-owned storage: the handle IS the storage pointer, so no allocator, registry, or global state and sessions stay isolated.
// Destroy clears the cookie so post-destroy steps fail deterministically. No span constructor because it would be a no-op.
const Session = sessions.Session;

// Handle identity. A live session carries the alive cookie; destroy and
// failed-create storage carry the dead cookie, so the boundary never
// dispatches through a garbage ops pointer.
const alive_cookie: u64 = 0x5354_444b_5f31_0001;
const dead_cookie: u64 = 0x5354_444b_5f31_dead;

// Generous-but-bounded default ceilings for stdk_session_create: zip-bomb
// protection holds without host policing, and unbounded streaming stays
// available through stdk_session_bounded with explicit maxInt values.
const default_max_encoded: u64 = 16 << 30;
const default_max_decoded: u64 = 16 << 30;
const default_max_work: u64 = 4 << 30;
const default_max_entries: u64 = 1 << 20;

fn exceptionStatus(exception: Exception) u32 {
    inline for (vocabulary.error_map) |entry| if (exception == entry.exception) return entry.status;
    return envelope.Status.internal_failure;
}

// The session-able surface, single-sourced for matchSessionIndex, sizing, and
// the catalog projection. Ordering is ABI once released: append only.
const SessionDef = struct {
    component: [:0]const u8,
    verb: [:0]const u8,
    storage: *const fn () usize,
    session: *const fn ([]u8, sessions.Budgets) Exception!Session,
};
// tar/write left the boundary: store-only fixed-mode framing cannot express
// typeflags, links, modes, or pax names.
// A full tar write can re-enter as a v2 pair.
const session_defs = [_]SessionDef{
    .{ .component = "gzip", .verb = "decode", .storage = drivers.gzipDecodeStorage, .session = drivers.gzipDecodeSession },
    .{ .component = "deflate", .verb = "decode", .storage = drivers.deflateDecodeStorage, .session = drivers.deflateDecodeSession },
    .{ .component = "zlib", .verb = "decode", .storage = drivers.zlibDecodeStorage, .session = drivers.zlibDecodeSession },
    .{ .component = "deflate", .verb = "encode", .storage = drivers.deflateEncodeStorage, .session = drivers.deflateEncodeSession },
    .{ .component = "gzip", .verb = "encode", .storage = drivers.gzipEncodeStorage, .session = drivers.gzipEncodeSession },
    .{ .component = "zlib", .verb = "encode", .storage = drivers.zlibEncodeStorage, .session = drivers.zlibEncodeSession },
    .{ .component = "lz4", .verb = "decode", .storage = drivers.lz4DecodeStorage, .session = drivers.lz4DecodeSession },
    .{ .component = "lz4", .verb = "encode", .storage = drivers.lz4EncodeStorage, .session = drivers.lz4EncodeSession },
};

fn matchSessionIndex(component: ?[*:0]const u8, verb: ?[*:0]const u8) ?usize {
    const component_name = if (component) |ptr| std.mem.span(ptr) else return null;
    const verb_name = if (verb) |ptr| std.mem.span(ptr) else return null;
    for (session_defs, 0..) |def, index| {
        if (std.mem.eql(u8, component_name, def.component) and std.mem.eql(u8, verb_name, def.verb)) {
            return index;
        }
    }
    return null;
}

// Poison storage after any create failure so later step/destroy calls observe
// the dead sentinel instead of recycled or garbage bytes. Storage too small to
// hold a Session record cannot be helped; the handle contract then requires
// the caller not to reuse it.
fn markDead(bytes: [*]u8, storage_len: u64) void {
    const len: usize = std.math.cast(usize, storage_len) orelse return;
    if (len < @sizeOf(Session)) return;
    std.mem.bytesAsValue(Session, bytes[0..@sizeOf(Session)]).* = .{
        .state = undefined,
        .ops = &destroyed_ops,
        .alive = false,
        .failed = true,
        .cookie = dead_cookie,
        .storage_len = 0,
    };
}

fn checkAlive(handle: ?*anyopaque) ?*Session {
    const session: *Session = @ptrCast(@alignCast(handle orelse return null));
    if (session.cookie != alive_cookie) return null;
    if (session.ops == &destroyed_ops) return null;
    return session;
}

export fn stdk_session_storage(component: ?[*:0]const u8, verb: ?[*:0]const u8) callconv(.c) u64 {
    const index = matchSessionIndex(component, verb) orelse return 0;
    return driverStateOffset() + session_defs[index].storage();
}

// Layout is [Session record][driver state] so creation never collides with managed state.
fn createWithBudgets(
    component: ?[*:0]const u8,
    verb: ?[*:0]const u8,
    storage: ?[*]u8,
    storage_len: u64,
    budgets: sessions.Budgets,
) u32 {
    const index = matchSessionIndex(component, verb) orelse return envelope.Status.unsupported;
    const bytes = storage orelse {
        return envelope.Status.invalid_call;
    };
    // The Session record carries pointers and u64 words; a misaligned storage
    // would otherwise be UB in release-fast.
    if (@intFromPtr(bytes) % @alignOf(Session) != 0) return envelope.Status.invalid_call;
    if (storage_len < driverStateOffset()) {
        markDead(bytes, storage_len);
        return envelope.Status.insufficient_capacity;
    }
    const state_storage = bytes[driverStateOffset() .. std.math.cast(usize, storage_len) orelse return envelope.Status.insufficient_capacity];
    const session = session_defs[index].session(state_storage, budgets) catch |exception| {
        markDead(bytes, storage_len);
        return exceptionStatus(exception);
    };
    std.mem.bytesAsValue(Session, bytes[0..@sizeOf(Session)]).* = session;
    const live = std.mem.bytesAsValue(Session, bytes[0..@sizeOf(Session)]);
    live.cookie = alive_cookie;
    live.storage_len = storage_len;
    return envelope.Status.ok;
}

export fn stdk_session_create(
    component: ?[*:0]const u8,
    verb: ?[*:0]const u8,
    storage: ?[*]u8,
    storage_len: u64,
) callconv(.c) u32 {
    return createWithBudgets(component, verb, storage, storage_len, .{
        .max_encoded = default_max_encoded,
        .max_decoded = default_max_decoded,
        .max_work = default_max_work,
        .max_entries = default_max_entries,
    });
}

// Per-session ceilings on encoded, decoded, work, and entry bytes.
// Hosts pass zip-bomb limits here instead of policing produced bytes
// themselves.
export fn stdk_session_bounded(
    component: ?[*:0]const u8,
    verb: ?[*:0]const u8,
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

// u128 arithmetic keeps the end computation overflow-free for hostile lengths.
// The C boundary reports no failure, so the check stays infallible.
fn rangesOverlap(a: ?[*]const u8, a_len: u64, b: ?[*]const u8, b_len: u64) bool {
    const a_start = if (a) |ptr| @as(u128, @intFromPtr(ptr)) else return false;
    const b_start = if (b) |ptr| @as(u128, @intFromPtr(ptr)) else return false;
    return a_start < b_start + b_len and b_start < a_start + a_len;
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
    const session = checkAlive(handle) orelse return envelope.Status.invalid_call;
    const counts = counts_out orelse return envelope.Status.invalid_call;
    // Aliasing input, output, or the session's own storage silently corrupts
    // state mid-copy, so refuse overlapping ranges up front.
    const storage_start: ?[*]const u8 = @ptrCast(handle.?);
    if (rangesOverlap(input, input_len, output, output_len) or
        rangesOverlap(input, input_len, storage_start, session.storage_len) or
        rangesOverlap(output, output_len, storage_start, session.storage_len))
    {
        return envelope.Status.invalid_call;
    }
    const input_slice: []const u8 = if (input) |ptr| ptr[0 .. std.math.cast(usize, input_len) orelse return envelope.Status.invalid_call] else &.{};
    const output_slice: []u8 = if (output) |ptr| ptr[0 .. std.math.cast(usize, output_len) orelse return envelope.Status.invalid_call] else &.{};
    const result = session.step(input_slice, output_slice, end_of_input != 0);
    counts[0] = result.consumed;
    counts[1] = result.produced;
    if (state_out) |state| state.* = switch (result.status) {
        .open => 0,
        .done => 1,
        .failed => -1,
    };
    if (result.status == .failed) {
        session.failed = true;
        session.failure_status = exceptionStatus(result.exception orelse error.InternalException);
        session.failure_detail = result.required_capacity;
        return exceptionStatus(result.exception orelse error.InternalException);
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
    const session = checkAlive(handle) orelse return envelope.Status.invalid_call;
    if (status_out) |status| status.* = session.failure_status;
    if (detail_out) |detail| detail.* = session.failure_detail;
    return envelope.Status.ok;
}

// "v1:" is the version and retirement mechanism: pairs are append-only
// within a version, and a breaking change bumps the prefix.
export fn stdk_session_catalog() callconv(.c) [*:0]const u8 {
    return session_catalog_text;
}

const session_catalog_text: [:0]const u8 = blk: {
    var text: [:0]const u8 = "v1:";
    for (session_defs, 0..) |def, index| {
        const entry = def.component ++ "/" ++ def.verb;
        text = if (index == 0) text ++ entry else text ++ "," ++ entry;
    }
    break :blk text;
};

// Destroy is idempotent and total: live sessions are destroyed, dead sessions
// (already destroyed or failed-create) report ok, and storage that was never
// successfully created is refused rather than dispatched through garbage.
export fn stdk_session_destroy(handle: ?*anyopaque) callconv(.c) u32 {
    const session: *Session = @ptrCast(@alignCast(handle orelse return envelope.Status.invalid_call));
    if (session.cookie == dead_cookie or session.ops == &destroyed_ops) return envelope.Status.ok;
    if (session.cookie != alive_cookie) return envelope.Status.invalid_call;
    session.destroy();
    session.cookie = dead_cookie;
    session.ops = &destroyed_ops;
    return envelope.Status.ok;
}

// Sentinel ops for destroyed sessions. Function pointers are never called since callers check first.
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
