//! Windows service of stop-internet.
//!
//! Planned responsibilities (see `docs/design.md`):
//! - keep the WFP filters of the active policy;
//! - watch the tunnel adapter and power events;
//! - serve the tray icon and the CLI over a named pipe.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("stopinet-service is not implemented yet");
    ExitCode::FAILURE
}
