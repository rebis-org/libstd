const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");

pub const Implementation = enum { onprem, offprem };

pub const WeakParametersError = error{WeakParameters};
pub const OutputTooLongError = error{OutputTooLong};

pub fn pbkdf2(dk: []u8, password: []const u8, salt: []const u8, rounds: u32, comptime Prf: type) (WeakParametersError || OutputTooLongError)!void {
    switch (options.pbkdf2_impl) {
        .onprem => try onprem.pbkdf2(dk, password, salt, rounds, Prf),
        .offprem => try std.crypto.pwhash.pbkdf2(dk, password, salt, rounds, Prf),
    }
}
