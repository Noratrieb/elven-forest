use std::{
    fmt::{Debug, Display},
    ops::{Add, AddAssign, Sub},
};

use crate::idx::ToIdxUsize;
use bytemuck::{Pod, Zeroable};

/// A _run time_ address inside an object file.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroable, Pod)]
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
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroable, Pod)]
#[repr(transparent)]
pub struct Offset {
    value: u64,
}

#[allow(non_snake_case)]
pub const fn Offset(value: u64) -> Offset {
    Offset { value }
}

impl Offset {
    pub fn usize(self) -> usize {
        self.value.try_into().unwrap()
    }

    pub fn u64(self) -> u64 {
        self.value
    }
}

impl ToIdxUsize for Offset {
    fn to_idx_usize(self) -> usize {
        self.value.to_idx_usize()
    }
}

impl Debug for Offset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.value)
    }
}

impl Display for Offset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.value)
    }
}

impl Add<Self> for Offset {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self + rhs.value
    }
}

impl Add<u64> for Offset {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        Offset(self.value + rhs)
    }
}

impl Add<usize> for Offset {
    type Output = Self;

    fn add(self, rhs: usize) -> Self::Output {
        Offset(self.value + rhs as u64)
    }
}

impl Sub<usize> for Offset {
    type Output = Self;

    fn sub(self, rhs: usize) -> Self::Output {
        Offset(self.value - rhs as u64)
    }
}

impl Sub<Self> for Offset {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Offset(self.value - rhs.u64())
    }
}

impl AddAssign<usize> for Offset {
    fn add_assign(&mut self, rhs: usize) {
        *self = *self + rhs;
    }
}

impl From<Offset> for u64 {
    fn from(value: Offset) -> Self {
        value.value
    }
}

impl From<u64> for Offset {
    fn from(value: u64) -> Self {
        Offset(value)
    }
}
