//! Windows integration of stop-internet: the WFP firewall and the tunnel
//! adapter lookup.
//!
//! All `unsafe` code of the project lives in this crate, in the [`wfp`] and
//! [`adapter`] modules. Every unsafe block states why it is sound.

#![cfg(windows)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod adapter;
pub mod firewall;
pub mod plan;
pub mod wfp;
mod wide;

pub use adapter::{TunnelLookup, find_tunnel};
pub use firewall::{ApplyReport, Firewall};
pub use plan::{Environment, Plan};
pub use wfp::WfpError;
