//! Windows integration of stop-internet: the WFP firewall.
//!
//! All `unsafe` code of the project lives in this crate. Every unsafe block
//! states why it is sound.

#![cfg(windows)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod firewall;
pub mod plan;
pub mod wfp;
mod wide;

pub use firewall::{ApplyReport, Firewall};
pub use plan::{Environment, Plan};
pub use wfp::WfpError;
