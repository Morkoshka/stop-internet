//! Windows integration of stop-internet: the WFP firewall, the persistent
//! baseline, the tunnel adapter lookup and interface notifications.
//!
//! The `unsafe` code of the project lives in this crate, in the [`wfp`],
//! [`adapter`], [`watch`] and [`clock`] modules, apart from what the
//! `windows-service` crate generates for the service entry point. Every
//! unsafe block states why it is sound.

#![cfg(windows)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod adapter;
pub mod clock;
pub mod firewall;
pub mod persistent;
pub mod plan;
pub mod watch;
pub mod wfp;
mod wide;

pub use adapter::{Observation, TunnelLookup, find_tunnel, observe_tunnel};
pub use clock::LocalTime;
pub use firewall::{ApplyReport, Firewall};
pub use persistent::{BaselineReport, Inventory, RemovalReport};
pub use plan::{Environment, Plan};
pub use watch::InterfaceWatch;
pub use wfp::{Lifetime, WfpError};
