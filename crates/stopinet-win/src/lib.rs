//! Windows integration of stop-internet: the WFP firewall, the persistent
//! baseline, the tunnel adapter lookup, interface notifications, the named
//! pipe between the service and its clients, and what the installer does
//! about the tray icon.
//!
//! The `unsafe` code of the service and the CLI lives in this crate, in the
//! [`wfp`], [`adapter`], [`watch`], [`clock`], [`security`], [`pipe`] and
//! [`tray`] modules, apart from what the `windows-service` crate generates
//! for the service entry point. The tray icon keeps its window code to
//! itself.
//! Every unsafe block states why it is sound.

#![cfg(windows)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod adapter;
pub mod clock;
pub mod firewall;
pub mod persistent;
pub mod pipe;
pub mod plan;
pub mod security;
pub mod tray;
pub mod watch;
pub mod wfp;
mod wide;

pub use adapter::{Observation, TunnelLookup, find_tunnel, observe_tunnel};
pub use clock::LocalTime;
pub use firewall::{ApplyReport, Firewall};
pub use persistent::{BaselineReport, Inventory, RemovalReport};
pub use pipe::{Caller, ClientError, PipeServer};
pub use plan::{Environment, Plan};
pub use watch::InterfaceWatch;
pub use wfp::{Lifetime, WfpError};
