#![allow(clippy::must_use_candidate, clippy::missing_errors_doc)]

mod addrs;
pub mod consts;
mod idx;
pub mod read;
pub mod write;

pub use crate::addrs::{Addr, Offset};
