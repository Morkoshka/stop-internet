//! Windows integration of stop-internet.

#![cfg(windows)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod plan;

pub use plan::{Environment, Plan};
