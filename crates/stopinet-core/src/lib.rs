//! Core logic of stop-internet: configuration and the firewall policy model.
//!
//! This crate has no side effects on the system. It decides *which* rules
//! must be active for a given mode and tunnel state; the service translates
//! those rules into Windows Filtering Platform filters.

#![forbid(unsafe_code)]

pub mod config;
pub mod policy;

pub use config::{Config, ConfigError};
pub use policy::{Action, Matcher, Mode, Policy, Rule, Scope, TunnelState};

/// Name of the Windows service.
pub const SERVICE_NAME: &str = "stopinet";

/// Service argument for session-only mode, meant for testing: the service
/// installs nothing persistent, so every filter disappears when it stops.
pub const SESSION_ONLY_ARG: &str = "--session-only";
