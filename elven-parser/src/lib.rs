#![allow(clippy::must_use_candidate, clippy::missing_errors_doc)]

use std::fmt::{Debug, Display};

use bytemuck::{Pod, Zeroable};
use idx::ToIdxUsize;

pub mod consts;
mod idx;
pub mod read;
pub mod write;

/// A _run time_ address inside an object file.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Zeroable, Pod)]
#[repr(transparent)]
pub struct Addr(pub u64);

impl Debug for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

impl Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.0)
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
