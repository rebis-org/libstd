const std = @import("std");

const run = @import("run.zig");
const symbols = @import("symbols.zig");

pub fn main(init: std.process.Init) !void {
    var args = run.Args.init(init.minimal.args);
    const library = try args.next(error.MissingArgument);
    try args.done(error.UnexpectedArgument);
    try symbols.assertSingleExport(init, library);
}
