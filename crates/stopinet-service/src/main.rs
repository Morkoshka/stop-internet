//! Windows service of stop-internet.
//!
//! Runs as LocalSystem, started automatically at boot. It installs the
//! persistent baseline of WFP filters, follows the tunnel adapter and keeps
//! the session rules on top of the baseline. The tray icon and the CLI
//! switch modes over a named pipe. "Normal internet" ends when its time is
//! up, on wake-up and when a user logs on. See `docs/design.md`.
//!
//! The binary takes one optional argument, `--session-only`, set by
//! `stopinet install --session-only`: nothing persistent is installed, so
//! stopping the service removes every filter. It is meant for testing.

mod log;
mod run;

use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::Duration;

use stopinet_core::config::{DEFAULT_PATH, LOG_PATH};
use stopinet_core::{SERVICE_NAME, SESSION_ONLY_ARG};
use windows_service::service::{
    PowerEventParam, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
    ServiceStatus, ServiceType, SessionChangeReason,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::log::Log;
use crate::run::{Event, Options};

/// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`: started from a console, not by
/// the service control manager.
const NOT_STARTED_AS_SERVICE: i32 = 1063;

/// Exit code reported to the service control manager after a failure.
const FAILURE: ServiceExitCode = ServiceExitCode::ServiceSpecific(1);

/// How long the service control manager should wait for a start.
const START_WAIT: Duration = Duration::from_secs(30);

define_windows_service!(ffi_service_main, service_main);

fn main() -> ExitCode {
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => ExitCode::SUCCESS,
        Err(windows_service::Error::Winapi(error))
            if error.raw_os_error() == Some(NOT_STARTED_AS_SERVICE) =>
        {
            eprintln!(
                "stopinet-service runs as a Windows service.\n\
                 Install it from an elevated terminal with `stopinet install`."
            );
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("cannot start the service dispatcher: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Entry point called by the service control manager on its own thread.
fn service_main(_arguments: Vec<OsString>) {
    let mut log = Log::open(LOG_PATH);
    // Launch arguments come from the command line in the service
    // configuration, not from `StartService`.
    let options = Options {
        config: DEFAULT_PATH.into(),
        session_only: std::env::args_os()
            .skip(1)
            .any(|arg| arg == SESSION_ONLY_ARG),
    };
    log.write(format_args!(
        "starting stop-internet {}{}",
        env!("CARGO_PKG_VERSION"),
        if options.session_only {
            " (session-only)"
        } else {
            ""
        }
    ));
    if let Err(error) = serve(&options, &mut log) {
        log.write(format_args!("service failed: {error}"));
    }
}

/// Talks to the service control manager around [`run::run`].
fn serve(options: &Options, log: &mut Log) -> Result<(), String> {
    let (sender, events) = mpsc::channel();

    let control_sender = sender.clone();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = control_sender.send(Event::Stop);
            ServiceControlHandlerResult::NoError
        }
        // Sent on every wake-up, also without user input.
        ServiceControl::PowerEvent(PowerEventParam::ResumeAutomatic) => {
            let _ = control_sender.send(Event::Wake);
            ServiceControlHandlerResult::NoError
        }
        // A boot that resumes the service instead of starting it anew still
        // ends with a logon, and so does a sign-in after a sign-out.
        ServiceControl::SessionChange(change)
            if change.reason == SessionChangeReason::SessionLogon =>
        {
            let _ = control_sender.send(Event::Logon);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::PowerEvent(_)
        | ServiceControl::SessionChange(_)
        | ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(SERVICE_NAME, handler)
        .map_err(|e| format!("cannot register the control handler: {e}"))?;

    let report = |state: ServiceState, exit_code: ServiceExitCode| {
        let accepted = if state == ServiceState::Running {
            ServiceControlAccept::STOP
                | ServiceControlAccept::SHUTDOWN
                | ServiceControlAccept::POWER_EVENT
                | ServiceControlAccept::SESSION_CHANGE
        } else {
            ServiceControlAccept::empty()
        };
        let wait_hint = if state == ServiceState::StartPending {
            START_WAIT
        } else {
            Duration::ZERO
        };
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accepted,
            exit_code,
            checkpoint: 0,
            wait_hint,
            process_id: None,
        });
    };

    report(ServiceState::StartPending, ServiceExitCode::NO_ERROR);
    let result = run::run(options, log, sender, &events, || {
        report(ServiceState::Running, ServiceExitCode::NO_ERROR);
    });
    // A failure exit code makes the service control manager restart the
    // service, following the recovery actions set by `stopinet install`.
    let exit_code = if result.is_ok() {
        ServiceExitCode::NO_ERROR
    } else {
        FAILURE
    };
    report(ServiceState::Stopped, exit_code);
    result
}
