// Shared PPMd model machinery; each variant passes its Model type in.

pub const unit_size = 12;
pub const num_indexes = 38;
pub const int_bits = 7;
pub const period_bits = 7;
pub const bin_scale = 1 << (int_bits + period_bits);
pub const bin_shift = int_bits + period_bits;
pub const top_value = 1 << 24;
pub const max_freq = 124;
pub const init_bin_esc = [_]u16{ 0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051 };
pub const exp_escape = [_]u8{ 25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2 };

pub const Occurrence = extern struct {
    symbol: u8,
    freq: u8,
    successor_low: u16,
    successor_high: u16,
};

pub const See = extern struct {
    summ: u16,
    shift: u8,
    count: u8,
};

pub inline fn successor(s: *const Occurrence) u32 {
    return @as(u32, s.successor_low) | (@as(u32, s.successor_high) << 16);
}

pub inline fn setSuccessor(s: *Occurrence, succ_off: u32) void {
    s.successor_low = @truncate(succ_off);
    s.successor_high = @truncate(succ_off >> 16);
}

// Unit allocator shared by both variants; M keeps the divergent node links,
// free-list bookkeeping and glue policy.
pub fn Allocator(comptime M: type) type {
    return struct {
        pub inline fn i2u(self: *const M, indx: usize) u32 {
            return self.tables.indx2_units[indx];
        }

        pub inline fn u2i(self: *const M, nu: u32) usize {
            return self.tables.units2_indx[nu - 1];
        }

        pub fn splitBlock(self: *M, ptr_off: u32, old_indx: usize, new_indx: usize) void {
            const nu = i2u(self, old_indx) - i2u(self, new_indx);
            const start = ptr_off + i2u(self, new_indx) * unit_size;
            var i = u2i(self, nu);
            if (i2u(self, i) != nu) {
                i -= 1;
                const k = i2u(self, i);
                self.insertNode(start + k * unit_size, nu - k - 1);
            }
            self.insertNode(start, i);
        }

        pub fn allocUnitsRare(self: *M, indx: usize) ?u32 {
            if (self.glue_count == 0) {
                self.glueFreeBlocks();
                if (self.tables.free_list[indx] != 0) return self.removeNode(indx);
            }
            var i = indx;
            while (true) {
                i += 1;
                if (i == num_indexes) {
                    const num_bytes = i2u(self, indx) * unit_size;
                    self.glue_count -= 1;
                    if (self.units_start - self.text > num_bytes) {
                        self.units_start -= num_bytes;
                        return self.units_start;
                    }
                    return null;
                }
                if (self.tables.free_list[i] != 0) break;
            }
            const ret = self.removeNode(i);
            splitBlock(self, ret, i, indx);
            return ret;
        }

        pub fn allocUnits(self: *M, indx: usize) ?u32 {
            if (self.tables.free_list[indx] != 0) return self.removeNode(indx);
            const num_bytes = i2u(self, indx) * unit_size;
            if (self.hi_unit - self.lo_unit >= num_bytes) {
                const ret = self.lo_unit;
                self.lo_unit += num_bytes;
                return ret;
            }
            return allocUnitsRare(self, indx);
        }
    };
}
