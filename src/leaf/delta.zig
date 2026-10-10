pub const max_distance: u8 = 255;

pub const Direction = enum { encode, decode };

fn apply(code: []u8, distance: u8, comptime dir: Direction) void {
    var history: [256]u8 = @splat(0);
    var pos: u8 = 0;
    for (code, 0..) |byte, index| {
        const history_index = distance +% 1 +% pos;
        const out = switch (dir) {
            .decode => byte +% history[history_index],
            .encode => byte -% history[history_index],
        };
        history[pos] = switch (dir) {
            .decode => out,
            .encode => byte,
        };
        code[index] = out;
        pos -%= 1;
    }
}

pub fn decode(code: []u8, distance: u8) void {
    apply(code, distance, .decode);
}

pub fn encode(code: []u8, distance: u8) void {
    apply(code, distance, .encode);
}
