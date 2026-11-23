//! Core logic of stop-internet: configuration, the firewall policy model,
//! the mode chosen by the user and the protocol of the named pipe.
//!
//! This crate has no side effects on the system. It decides *which* rules
//! must be active for a given mode and tunnel state; the service translates
//! those rules into Windows Filtering Platform filters.

#![forbid(unsafe_code)]

pub mod config;
pub mod control;
pub mod policy;
pub mod protocol;

pub use config::{Config, ConfigError};
pub use control::{Choice, Refusal, Remaining, Selection};
pub use policy::{Action, Matcher, Mode, Policy, Rule, Scope, TunnelState};
pub use protocol::{Request, Response, Status};

/// Name of the Windows service.
pub const SERVICE_NAME: &str = "stopinet";

/// Service argument for session-only mode, meant for testing: the service
/// installs nothing persistent, so every filter disappears when it stops.
pub const SESSION_ONLY_ARG: &str = "--session-only";

/// Window class of the tray icon. The installer closes windows of this
/// class before it replaces or removes the program.
pub const TRAY_WINDOW_CLASS: &str = "stopinet-tray";
