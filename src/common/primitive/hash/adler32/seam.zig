const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");
const seam = @import("seam");

pub const Onprem = onprem.Adler32;
pub const Offprem = std.hash.Adler32;

pub const Inner = switch (options.adler32_impl) {
    .onprem => FixedAdler(.onprem, Onprem),
    .offprem => FixedAdler(.offprem, Offprem),
    .mergeable => MergeableAdler(Onprem, Offprem),
};

// Both implementations expose the state as `adler`, so the wrapper in
// checksum.zig stays implementation-neutral.
fn FixedAdler(comptime tag: seam.Provider, comptime Impl: type) type {
    return struct {
        inner: Impl = .{},

        pub fn bind(provider: seam.Provider) @This() {
            std.debug.assert(provider == tag);
            return .{};
        }

        pub fn update(self: *@This(), input: []const u8) void {
            self.inner.update(input);
        }

        pub fn adler(self: *const @This()) u32 {
            return self.inner.adler;
        }
    };
}

fn MergeableAdler(comptime On: type, comptime Off: type) type {
    return struct {
        state: seam.Pair(On, Off) = .{ .onprem = .{} },

        pub fn bind(provider: seam.Provider) @This() {
            return switch (provider) {
                .onprem => .{ .state = .{ .onprem = .{} } },
                .offprem => .{ .state = .{ .offprem = .{} } },
            };
        }

        pub fn update(self: *@This(), input: []const u8) void {
            switch (self.state) {
                inline else => |*inner| inner.update(input),
            }
        }

        pub fn adler(self: *const @This()) u32 {
            switch (self.state) {
                inline else => |*inner| return inner.adler,
            }
        }
    };
}
