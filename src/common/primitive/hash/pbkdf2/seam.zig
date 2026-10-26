const std = @import("std");

const options = @import("options");
const seam = @import("seam");

const onprem = @import("onprem.zig");

pub const OutputTooLongError = onprem.OutputTooLongError;
pub const WeakParametersError = onprem.WeakParametersError;

// The PRF pair travels with the provider, so the rounds loop never dispatches
// per iteration.
pub fn pbkdf2(comptime PrfOnprem: type, comptime PrfOffprem: type, provider: seam.Provider, dk: []u8, password: []const u8, salt: []const u8, rounds: u32) (WeakParametersError || OutputTooLongError)!void {
    // A fixed build serves one arm; the tag must match the build's default.
    if (options.pbkdf2_impl != .mergeable) std.debug.assert(provider == seam.default_provider);
    return switch (options.pbkdf2_impl) {
        .onprem => onprem.pbkdf2(dk, password, salt, rounds, PrfOnprem),
        .offprem => std.crypto.pwhash.pbkdf2(dk, password, salt, rounds, PrfOffprem),
        .mergeable => switch (provider) {
            .onprem => onprem.pbkdf2(dk, password, salt, rounds, PrfOnprem),
            .offprem => std.crypto.pwhash.pbkdf2(dk, password, salt, rounds, PrfOffprem),
        },
    };
}
