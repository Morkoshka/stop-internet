//! Tray icon of stop-internet: shows the protection status and switches
//! modes through the named pipe of the service.
//!
//! - Green: protected, the internet works through the VPN client. Red:
//!   blocked, because the tunnel is down in tunnel-only mode, or the
//!   service cannot be asked. Grey: "normal internet", protection is off.
//! - The menu switches between tunnel-only and proxy mode directly. For
//!   "normal internet" the tray starts itself again with administrator
//!   rights through a UAC prompt, as `stopinet-tray.exe --normal <minutes>`;
//!   that instance only sends the request and shows a message if it fails.
//! - It asks the service for its state once a second. Closing the icon
//!   does not change the protection.
//!
//! `stopinet install` starts it at every sign-in. See `docs/design.md`.

#![windows_subsystem = "windows"]
#![warn(clippy::undocumented_unsafe_blocks)]

mod icon;
mod shell;
mod theme;
mod view;

use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use stopinet_core::config::LOG_PATH;
use stopinet_core::control::Choice;
use stopinet_core::protocol::{Request, Response};
use stopinet_win::pipe;

use crate::shell::Notifier;
use crate::view::{Action, Problem, View};

/// How often the tray asks the service for its state.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Argument of the elevated instance that switches to normal internet.
const NORMAL_ARG: &str = "--normal";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => tray(),
        [flag, minutes] if flag == NORMAL_ARG => normal(minutes),
        _ => {
            shell::message_box(&format!(
                "Неизвестные параметры: {}.\n\nЗначок запускается без параметров.",
                args.join(" ")
            ));
            ExitCode::FAILURE
        }
    }
}

fn tray() -> ExitCode {
    let Some(_instance) = shell::first_instance() else {
        return ExitCode::SUCCESS;
    };
    let latest = Arc::new(Mutex::new(ask_status()));
    let for_poller = Arc::clone(&latest);
    let for_actions = Arc::clone(&latest);
    let result = shell::run(
        latest,
        move |notifier| {
            thread::spawn(move || poll(&for_poller, notifier));
        },
        move |action, notifier| act(action, &for_actions, notifier),
    );
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            shell::message_box(&format!("Значок stop-internet не запустился: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn ask_status() -> View {
    match pipe::ask(&Request::Status) {
        Ok(Response::Status(status)) => View::Status(status),
        Ok(Response::Refused(_)) => View::Unreachable(Problem::NoAnswer),
        Err(error) => View::Unreachable(Problem::from(&error)),
    }
}

/// Asks the service once a second until the window is gone.
fn poll(latest: &Mutex<View>, notifier: Notifier) {
    loop {
        if !publish(latest, ask_status(), notifier) {
            return;
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Stores a new view and tells the window. Returns `false` once the window
/// is gone.
fn publish(latest: &Mutex<View>, view: View, notifier: Notifier) -> bool {
    let mut current = latest.lock().unwrap_or_else(PoisonError::into_inner);
    if *current == view {
        return true;
    }
    *current = view;
    drop(current);
    notifier.notify()
}

/// Carries out a menu choice on a thread of its own, so that the icon stays
/// responsive.
fn act(action: Action, latest: &Arc<Mutex<View>>, notifier: Notifier) {
    let latest = Arc::clone(latest);
    thread::spawn(move || match action {
        Action::Choose(Choice::Normal { minutes }) => {
            // The elevated instance reports its own errors; the next poll
            // shows the result.
            if let Err(error) = shell::run_elevated(&format!("{NORMAL_ARG} {minutes}")) {
                shell::message_box(&format!(
                    "Не удалось запросить права администратора: {error}"
                ));
            }
        }
        Action::Choose(choice) => match pipe::ask(&Request::Choose(choice)) {
            Ok(Response::Status(status)) => {
                publish(&latest, View::Status(status), notifier);
            }
            Ok(Response::Refused(refusal)) => failed(view::refusal_text(refusal)),
            Err(error) => failed(view::problem_text(Problem::from(&error))),
        },
        Action::OpenLog => {
            if let Err(error) = shell::open(Path::new(LOG_PATH)) {
                shell::message_box(&format!("Не удалось открыть журнал {LOG_PATH}: {error}"));
            }
        }
        // Handled by the window.
        Action::Close => {}
    });
}

/// The elevated instance: switches to normal internet and exits.
fn normal(minutes: &str) -> ExitCode {
    let Ok(minutes) = minutes.parse() else {
        failed("Неверная длительность обычного интернета.");
        return ExitCode::FAILURE;
    };
    match pipe::ask(&Request::Choose(Choice::Normal { minutes })) {
        Ok(Response::Status(_)) => ExitCode::SUCCESS,
        Ok(Response::Refused(refusal)) => {
            failed(view::refusal_text(refusal));
            ExitCode::FAILURE
        }
        Err(error) => {
            failed(view::problem_text(Problem::from(&error)));
            ExitCode::FAILURE
        }
    }
}

fn failed(reason: &str) {
    shell::message_box(&format!("Режим не переключён.\n\n{reason}"));
}
