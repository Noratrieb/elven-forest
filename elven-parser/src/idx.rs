use std::{
    ops::{RangeFrom, RangeTo},
    slice::SliceIndex,
};

use crate::{ElfParseError, Result};

macro_rules! define_idx {
    (
        $vis:vis struct $name:ident($ty:ty);
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, bytemuck::Zeroable, bytemuck::Pod)]
        #[repr(transparent)]
        $vis struct $name(pub $ty);

        impl crate::idx::ToIdxUsize for $name {
            fn to_idx_usize(self) -> usize {
                self.0 as usize
            }
        }
    };
}
pub(crate) use define_idx;

pub(crate) trait ElfIndex<T: ?Sized> {
    type SliceIdx: SliceIndex<T>;

    fn bound(&self) -> usize;
    fn to_slice_idx(self) -> Self::SliceIdx;
}

impl<T, U: ToIdxUsize> ElfIndex<[T]> for U {
    type SliceIdx = usize;
    fn bound(&self) -> usize {
        self.to_idx_usize()
    }
    fn to_slice_idx(self) -> Self::SliceIdx {
        self.to_idx_usize()
    }
}

impl<T, U: ToIdxUsize> ElfIndex<[T]> for RangeFrom<U> {
    type SliceIdx = RangeFrom<usize>;
    fn bound(&self) -> usize {
        self.start.to_idx_usize()
    }
    fn to_slice_idx(self) -> Self::SliceIdx {
        RangeFrom {
            start: self.start.to_idx_usize(),
        }
    }
}

impl<T, U: ToIdxUsize> ElfIndex<[T]> for RangeTo<U> {
    type SliceIdx = RangeTo<usize>;
    fn bound(&self) -> usize {
        self.end.to_idx_usize()
    }
    fn to_slice_idx(self) -> Self::SliceIdx {
        RangeTo {
            end: self.end.to_idx_usize(),
        }
    }
}

pub(crate) trait ToIdxUsize: Copy {
    fn to_idx_usize(self) -> usize;
}

impl ToIdxUsize for usize {
    fn to_idx_usize(self) -> usize {
        self
    }
}
impl ToIdxUsize for u64 {
    fn to_idx_usize(self) -> usize {
        self as usize
    }
}

pub(crate) trait ElfIndexExt {
    fn get_elf<I: ElfIndex<Self>>(
        &self,
        idx: I,
        msg: &'static str,
    ) -> Result<&<I::SliceIdx as SliceIndex<Self>>::Output>;
}

impl<T> ElfIndexExt for [T] {
    fn get_elf<I: ElfIndex<Self>>(
        &self,
        idx: I,
        msg: &'static str,
    ) -> Result<&<I::SliceIdx as SliceIndex<Self>>::Output> {
        let bound = idx.bound();
        self.get(idx.to_slice_idx())
            .ok_or(ElfParseError::IndexOutOfBounds(msg, bound))
    }
}
