const std = @import("std");

const campaign = @import("testing/fuzz/campaign.zig");

pub fn main(init: std.process.Init) !void {
    try campaign.main(init);
}
