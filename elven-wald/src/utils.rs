use elven_parser::Addr;

pub trait AlignExt<T>: Copy {
    fn align_down(self, align: T) -> Self;
    fn align_up(self, align: T) -> Self;
}

impl AlignExt<u64> for u64 {
    fn align_down(self, align: Self) -> Self {
        assert!(align.is_power_of_two() && align > 0);
        // We want to set all the aligment bits to zero.
        // 0b0101 aligned to 0b0100 => 0b0100
        // mask is !0b0011 = 0b1100
        let mask = !(align - 1);
        self & mask
    }
    fn align_up(self, align: Self) -> Self {
        assert!(align.is_power_of_two() && align > 0);
        // 0b0101 aligned to 0b0100 => 0b1000
        (self + align - 1) & !(align - 1)
    }
}

impl AlignExt<u64> for Addr {
    fn align_down(self, align: u64) -> Self {
        Addr(self.u64().align_down(align))
    }

    fn align_up(self, align: u64) -> Self {
        Addr(self.u64().align_up(align))
    }
}
