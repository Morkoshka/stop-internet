//! Windows integration of stop-internet: the WFP firewall, the persistent
//! baseline, the tunnel adapter lookup and interface notifications.
//!
//! All `unsafe` code of the project lives in this crate, in the [`wfp`],
//! [`adapter`] and [`watch`] modules. Every unsafe block states why it is
//! sound.

#![cfg(windows)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod adapter;
pub mod firewall;
pub mod persistent;
pub mod plan;
pub mod watch;
pub mod wfp;
mod wide;

pub use adapter::{Observation, TunnelLookup, find_tunnel, observe_tunnel};
pub use firewall::{ApplyReport, Firewall};
pub use persistent::{BaselineReport, Inventory, RemovalReport};
pub use plan::{Environment, Plan};
pub use watch::InterfaceWatch;
pub use wfp::{Lifetime, WfpError};
