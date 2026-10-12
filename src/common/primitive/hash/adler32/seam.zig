const std = @import("std");

const options = @import("options");
const seam = @import("seam");

const onprem = @import("onprem.zig");

pub const Onprem = onprem.Adler32;

// std.hash.Adler32 exposes its running state instead of an init/final pair.

pub const Offprem = struct {
    inner: std.hash.Adler32 = .{},

    pub fn init() @This() {
        return .{};
    }

    pub fn update(self: *@This(), input: []const u8) void {
        self.inner.update(input);
    }

    pub fn final(self: *const @This()) u32 {
        return self.inner.adler;
    }
};

pub const Adler32 = seam.Checksum(options.adler32_impl, Onprem, Offprem);

pub const Inner = Adler32;
