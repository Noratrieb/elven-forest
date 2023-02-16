use std::{
    fmt::{Debug, Display},
    ops::Add,
};

use crate::idx::ToIdxUsize;
use bytemuck::{Pod, Zeroable};

/// A _run time_ address inside an object file.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Zeroable, Pod)]
#[repr(transparent)]
pub struct Addr {
    value: u64,
}

#[allow(non_snake_case)]
pub const fn Addr(value: u64) -> Addr {
    Addr { value }
}

impl Debug for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.value)
    }
}

impl Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.value)
    }
}

impl Add<Self> for Addr {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self + rhs.value
    }
}

impl Add<u64> for Addr {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Addr(self.value + rhs)
    }
}

/// An offset into an object file. Either absolut or relative to a particular section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Zeroable, Pod)]
#[repr(transparent)]
pub struct Offset(pub u64);

impl ToIdxUsize for Offset {
    fn to_idx_usize(self) -> usize {
        self.0.to_idx_usize()
    }
}

impl Display for Offset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}
