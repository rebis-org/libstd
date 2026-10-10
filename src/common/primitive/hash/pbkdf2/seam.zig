const std = @import("std");
const options = @import("options");
const onprem = @import("onprem.zig");
const seam = @import("seam");

pub const WeakParametersError = error{WeakParameters};
pub const OutputTooLongError = error{OutputTooLong};

// Whole-operation monomorphization: the PRF pair travels with the provider, so
// the rounds loop never dispatches per iteration.
pub fn pbkdf2(comptime PrfOnprem: type, comptime PrfOffprem: type, provider: seam.Provider, dk: []u8, password: []const u8, salt: []const u8, rounds: u32) (WeakParametersError || OutputTooLongError)!void {
    switch (options.pbkdf2_impl) {
        .onprem => {
            std.debug.assert(provider == seam.default_provider);
            return onprem.pbkdf2(dk, password, salt, rounds, PrfOnprem);
        },
        .offprem => {
            std.debug.assert(provider == seam.default_provider);
            return std.crypto.pwhash.pbkdf2(dk, password, salt, rounds, PrfOffprem);
        },
        .mergeable => switch (provider) {
            .onprem => return onprem.pbkdf2(dk, password, salt, rounds, PrfOnprem),
            .offprem => return std.crypto.pwhash.pbkdf2(dk, password, salt, rounds, PrfOffprem),
        },
    }
}
