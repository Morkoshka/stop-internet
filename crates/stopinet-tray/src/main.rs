//! Tray icon of stop-internet: shows the protection status and switches
//! modes through the named pipe of the service.
//!
//! - A green shield with a check mark: protected, the internet works
//!   through the VPN client. A red one with a cross: blocked, because the
//!   tunnel is down in tunnel-only mode, or the service cannot be asked. A
//!   grey one with a dash: "normal internet", protection is off.
//! - The menu follows the dark or light theme of Windows and opens to the
//!   right of the cursor, outside the taskbar. It switches between
//!   tunnel-only and proxy mode directly. For
//!   "normal internet" the tray starts itself again with administrator
//!   rights through a UAC prompt, as `stopinet-tray.exe --normal <minutes>`;
//!   that instance only sends the request and shows a message if it fails.
//! - The menu is in Russian or English, like the display language of
//!   Windows.
//! - "Automatic" ("Автоматически") in the menu keeps the protected mode in line with the
//!   system proxy of the user: proxy mode while it points to this computer,
//!   tunnel-only mode otherwise. It is on until a protected mode is chosen
//!   by hand, and stays so across restarts. See [`auto`].
//! - It asks the service for its state once a second. Closing the icon
//!   does not change the protection.
//! - `--panic`, for a shortcut in the Start menu, switches protection off
//!   in an emergency, also without the service. See [`emergency`].
//!
//! `stopinet install` starts it at every sign-in. See `docs/design.md`.

#![windows_subsystem = "windows"]
#![warn(clippy::undocumented_unsafe_blocks)]

mod auto;
mod emergency;
mod lang;
mod place;
mod proxy;
mod settings;
mod shell;
mod theme;
mod view;

use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use stopinet_core::config::LOG_PATH;
use stopinet_core::control::Choice;
use stopinet_core::protocol::{Request, Response};
use stopinet_win::pipe;

use crate::auto::SystemProxy;
use crate::lang::Lang;
use crate::shell::Notifier;
use crate::view::{Action, Problem, View};

/// How often the tray asks the service for its state.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// How long the tray waits after a change of the proxy settings before it
/// reads them: a VPN client writes several values one after another.
const SETTLE: Duration = Duration::from_millis(300);

/// Argument of the elevated instance that switches to normal internet.
const NORMAL_ARG: &str = "--normal";

/// What the threads of the tray share.
struct Shared {
    /// The last state of the service; the icon shows it.
    view: Arc<Mutex<View>>,
    /// Whether the protected mode follows the system proxy; the menu shows
    /// it.
    follow: Arc<AtomicBool>,
    /// The system proxy as last read; `None` until then, or if it cannot be
    /// read.
    proxy: Mutex<Option<SystemProxy>>,
    /// Held while a mode request is on its way, so that an automatic and a
    /// manual switch never cross.
    switching: Mutex<()>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => tray(),
        [flag, minutes] if flag == NORMAL_ARG => normal(minutes),
        [flag] if flag == emergency::ASK_ARG => emergency::ask(),
        [flag] if flag == emergency::RUN_ARG => emergency::run(),
        _ => {
            let text = Lang::current().pick(
                "Неизвестные параметры: {}.\n\nЗначок запускается без параметров.",
                "Unknown parameters: {}.\n\nThe icon starts without parameters.",
            );
            shell::message_box(&text.replace("{}", &args.join(" ")));
            ExitCode::FAILURE
        }
    }
}

fn tray() -> ExitCode {
    let Some(_instance) = shell::first_instance() else {
        return ExitCode::SUCCESS;
    };
    let shared = Arc::new(Shared {
        view: Arc::new(Mutex::new(ask_status())),
        follow: Arc::new(AtomicBool::new(settings::follow_proxy())),
        proxy: Mutex::new(None),
        switching: Mutex::new(()),
    });
    let for_threads = Arc::clone(&shared);
    let for_actions = Arc::clone(&shared);
    let result = shell::run(
        Arc::clone(&shared.view),
        Arc::clone(&shared.follow),
        move |notifier| {
            let for_poller = Arc::clone(&for_threads);
            thread::spawn(move || poll(&for_poller, notifier));
            thread::spawn(move || watch_proxy(&for_threads, notifier));
        },
        move |action, notifier| act(action, &for_actions, notifier),
    );
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let text = Lang::current().pick(
                "Значок stop-internet не запустился",
                "The stop-internet icon did not start",
            );
            shell::message_box(&format!("{text}: {error}"));
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

/// Asks the service once a second until the window is gone. The mode is
/// checked against the system proxy each time, so that it is right again
/// after a service start or the end of "normal internet".
fn poll(shared: &Shared, notifier: Notifier) {
    loop {
        if !publish(&shared.view, ask_status(), notifier) {
            return;
        }
        follow(shared, notifier);
        thread::sleep(POLL_INTERVAL);
    }
}

/// Reads the system proxy at every change of it and switches the mode if
/// needed. If the registry cannot be watched, it reads the proxy once a
/// second instead. The thread ends with the process.
fn watch_proxy(shared: &Shared, notifier: Notifier) {
    let watch = proxy::Watch::open().ok();
    loop {
        // Armed before the read, so that no change is missed.
        let armed = watch.as_ref().is_some_and(|watch| watch.arm().is_ok());
        let read = proxy::read()
            .ok()
            .map(|settings| SystemProxy::of(&settings));
        *lock(&shared.proxy) = read;
        follow(shared, notifier);
        match &watch {
            Some(watch) if armed => {
                watch.wait();
                thread::sleep(SETTLE);
            }
            _ => thread::sleep(POLL_INTERVAL),
        }
    }
}

/// Switches to the protected mode that fits the system proxy, if the tray
/// follows it and the mode is not right. Failures are not shown: the next
/// poll tries again.
fn follow(shared: &Shared, notifier: Notifier) {
    let _switching = lock(&shared.switching);
    let on = shared.follow.load(Ordering::Relaxed);
    let proxy = *lock(&shared.proxy);
    let step = |view: &View| auto::next_step(on, view, proxy);
    if step(&lock(&shared.view)).is_none() {
        return;
    }
    // The shown state may be a second old, and "normal internet" may have
    // begun since: decide on a fresh one.
    let view = ask_status();
    let choice = step(&view);
    publish(&shared.view, view, notifier);
    let Some(choice) = choice else {
        return;
    };
    if let Ok(Response::Status(status)) = pipe::ask(&Request::Choose(choice)) {
        publish(&shared.view, View::Status(status), notifier);
    }
}

/// Stores a new view and tells the window. Returns `false` once the window
/// is gone.
fn publish(latest: &Mutex<View>, view: View, notifier: Notifier) -> bool {
    let mut current = lock(latest);
    if *current == view {
        return true;
    }
    *current = view;
    drop(current);
    notifier.notify()
}

/// Carries out a menu choice on a thread of its own, so that the icon stays
/// responsive.
fn act(action: Action, shared: &Arc<Shared>, notifier: Notifier) {
    let shared = Arc::clone(shared);
    thread::spawn(move || match action {
        Action::Choose(Choice::Normal { minutes }) => {
            // The elevated instance reports its own errors; the next poll
            // shows the result. The tray keeps following the proxy: that
            // waits until normal internet ends.
            if let Err(error) = shell::run_elevated(&format!("{NORMAL_ARG} {minutes}")) {
                let text = Lang::current().pick(
                    "Не удалось запросить права администратора",
                    "Could not ask for administrator rights",
                );
                shell::message_box(&format!("{text}: {error}"));
            }
        }
        Action::Choose(choice) => {
            let (answer, stopped) = {
                let _switching = lock(&shared.switching);
                // A protected mode chosen by hand stops following the proxy.
                let stopped = shared.follow.swap(false, Ordering::Relaxed);
                (pipe::ask(&Request::Choose(choice)), stopped)
            };
            if stopped {
                remember(false);
            }
            match answer {
                Ok(Response::Status(status)) => {
                    publish(&shared.view, View::Status(status), notifier);
                }
                Ok(Response::Refused(refusal)) => {
                    failed(view::refusal_text(refusal, Lang::current()))
                }
                Err(error) => failed(view::problem_text(Problem::from(&error), Lang::current())),
            }
        }
        Action::FollowProxy(on) => {
            shared.follow.store(on, Ordering::Relaxed);
            remember(on);
            follow(&shared, notifier);
        }
        Action::OpenLog => {
            if let Err(error) = shell::open(Path::new(LOG_PATH)) {
                let text =
                    Lang::current().pick("Не удалось открыть журнал", "Could not open the log");
                shell::message_box(&format!("{text} {LOG_PATH}: {error}"));
            }
        }
        // Handled by the window.
        Action::Close => {}
    });
}

/// Keeps the choice for the next start of the tray.
fn remember(follow: bool) {
    if let Err(error) = settings::set_follow_proxy(follow) {
        let text = Lang::current().pick(
            "Настройка «Автоматически» не сохранилась и после перезапуска значка \
             будет прежней",
            "The \"Automatic\" setting was not saved and will be as before after \
             the icon restarts",
        );
        shell::message_box(&format!("{text}: {error}"));
    }
}

/// The elevated instance: switches to normal internet and exits.
fn normal(minutes: &str) -> ExitCode {
    let Ok(minutes) = minutes.parse() else {
        failed(Lang::current().pick(
            "Неверная длительность обычного интернета.",
            "Wrong duration of normal internet.",
        ));
        return ExitCode::FAILURE;
    };
    match pipe::ask(&Request::Choose(Choice::Normal { minutes })) {
        Ok(Response::Status(_)) => ExitCode::SUCCESS,
        Ok(Response::Refused(refusal)) => {
            failed(view::refusal_text(refusal, Lang::current()));
            ExitCode::FAILURE
        }
        Err(error) => {
            failed(view::problem_text(Problem::from(&error), Lang::current()));
            ExitCode::FAILURE
        }
    }
}

fn failed(reason: &str) {
    let text = Lang::current().pick("Режим не переключён.", "The mode was not switched.");
    shell::message_box(&format!("{text}\n\n{reason}"));
}

/// The data stays usable if another thread panicked while holding the lock.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
