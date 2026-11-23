//! What the service does between start and stop.
//!
//! 1. Load the configuration.
//! 2. Install the persistent baseline (unless session-only) and open a
//!    dynamic WFP session for the session rules.
//! 3. Follow the tunnel adapter, through interface notifications and a
//!    periodic check, and rebuild the session rules when it changes.
//! 4. On stop, close the dynamic session. The baseline keeps blocking.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

use stopinet_core::config::Config;
use stopinet_core::policy::{Mode, Policy, Scope, TunnelState};
use stopinet_win::persistent::install_baseline;
use stopinet_win::{Environment, Firewall, InterfaceWatch, Plan, WfpError, observe_tunnel};

use crate::log::Log;

/// Safety net for missed interface notifications.
const CHECK_INTERVAL: Duration = Duration::from_secs(2);

/// What the main loop reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The service control manager asks the service to stop.
    Stop,
    /// The machine woke up from sleep or hibernation.
    Wake,
    /// An IP interface appeared, disappeared or changed.
    Interfaces,
}

/// How the service was started.
#[derive(Debug, Clone)]
pub struct Options {
    /// Configuration file.
    pub config: PathBuf,
    /// Keep every filter in the dynamic session; install nothing persistent.
    pub session_only: bool,
}

/// Runs the service until [`Event::Stop`]. `running` is called once the
/// filters are in place. An error means the service must exit with a
/// failure, so that the service control manager restarts it.
pub fn run(
    options: &Options,
    log: &mut Log,
    sender: Sender<Event>,
    events: &Receiver<Event>,
    running: impl FnOnce(),
) -> Result<(), String> {
    let config = Config::load(&options.config).map_err(|e| e.to_string())?;
    log.write(format_args!(
        "configuration loaded, tunnel adapter \"{}\"",
        config.tunnel.adapter_name
    ));

    let mut firewall = if options.session_only {
        log.write(
            "session-only mode: nothing persistent, all filters go away when the service stops",
        );
        Firewall::open_dynamic().map_err(|e| explain(&e))?
    } else {
        baseline(&config, log)?;
        Firewall::attach().map_err(|e| explain(&e))?
    };

    let watch = match InterfaceWatch::start(move || {
        let _ = sender.send(Event::Interfaces);
    }) {
        Ok(watch) => Some(watch),
        Err(error) => {
            log.write(format_args!(
                "no interface notifications ({error}), checking every {} s",
                CHECK_INTERVAL.as_secs()
            ));
            None
        }
    };

    let mut follower = Follower::new(options.session_only);
    follower.update(&config, &mut firewall, log)?;
    running();
    log.write("running");

    loop {
        match next(events) {
            Next::Stop => break,
            Next::Check { woke } => {
                if woke {
                    let mode = follower.mode.after_wake();
                    log.write(format_args!("woke up, mode {mode:?}"));
                    follower.mode = mode;
                }
                follower.update(&config, &mut firewall, log)?;
            }
        }
    }

    drop(watch);
    drop(firewall);
    log.write(if options.session_only {
        "stopped, all filters removed"
    } else {
        "stopped, session rules removed, the baseline keeps blocking"
    });
    Ok(())
}

/// Installs the persistent part of the policy. It is the same for every
/// mode and tunnel state.
fn baseline(config: &Config, log: &mut Log) -> Result<(), String> {
    let policy = Policy::build(config, Mode::TunnelOnly, TunnelState::Down);
    let plan = Plan::build(&policy, &Environment::default());
    let report = install_baseline(&plan).map_err(|e| explain(&e))?;
    log.write(format_args!(
        "baseline installed: {} persistent filters, {} boot-time copies",
        report.persistent, report.boot_time
    ));
    for warning in &report.warnings {
        log.write(format_args!("  note: {warning}"));
    }
    Ok(())
}

/// Keeps the session rules in line with the mode and the tunnel.
struct Follower {
    session_only: bool,
    mode: Mode,
    /// Mode, tunnel state and adapter of the rules in place.
    applied: Option<(Mode, TunnelState, Option<u64>)>,
    last_note: Option<String>,
}

impl Follower {
    fn new(session_only: bool) -> Self {
        Self {
            session_only,
            mode: Mode::TunnelOnly,
            applied: None,
            last_note: None,
        }
    }

    /// Looks at the tunnel and rebuilds the rules if anything changed.
    fn update(
        &mut self,
        config: &Config,
        firewall: &mut Firewall,
        log: &mut Log,
    ) -> Result<(), String> {
        let now = observe_tunnel(&config.tunnel);
        let key = (self.mode, now.state, now.luid);

        if self.applied != Some(key) {
            let policy = Policy::build(config, self.mode, now.state);
            let plan = Plan::build(&policy, &now.environment());
            // Without the persistent baseline the dynamic session carries
            // all rules; otherwise only the session rules on top of it.
            let plan = if self.session_only {
                plan
            } else {
                plan.only(Scope::Session)
            };
            let report = firewall
                .apply(&plan)
                .map_err(|e| format!("cannot apply the rules: {}", explain(&e)))?;
            let tunnel = match now.state {
                TunnelState::Up => "up",
                TunnelState::Down => "down",
            };
            log.write(format_args!(
                "mode {:?}, tunnel {tunnel}: {} filters in the session",
                self.mode, report.filters
            ));
            for warning in &report.warnings {
                log.write(format_args!("  note: {warning}"));
            }
            self.applied = Some(key);
        }

        if now.note != self.last_note {
            if let Some(note) = &now.note {
                log.write(format_args!("tunnel: {note}"));
            }
            self.last_note = now.note;
        }
        Ok(())
    }
}

/// What to do after waiting for events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Next {
    Stop,
    Check { woke: bool },
}

/// Waits for the next event or the periodic check, then takes every event
/// already queued, so that a burst of notifications costs one check.
fn next(events: &Receiver<Event>) -> Next {
    let first = match events.recv_timeout(CHECK_INTERVAL) {
        Ok(event) => Some(event),
        Err(RecvTimeoutError::Timeout) => None,
        Err(RecvTimeoutError::Disconnected) => return Next::Stop,
    };
    let mut woke = false;
    for event in first.into_iter().chain(events.try_iter()) {
        match event {
            Event::Stop => return Next::Stop,
            Event::Wake => woke = true,
            Event::Interfaces => {}
        }
    }
    Next::Check { woke }
}

fn explain(error: &WfpError) -> String {
    if error.is_access_denied() {
        format!("{error}: the service must run as LocalSystem")
    } else if error.is_already_exists() {
        format!(
            "{error}: stop-internet objects of another kind are present. A trial may be \
             running, or the persistent baseline is left from a full install while the \
             service runs session-only; `stopinet panic` removes them"
        )
    } else {
        error.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;

    #[test]
    fn a_burst_of_events_is_one_check() {
        let (sender, events) = mpsc::channel();
        for _ in 0..5 {
            sender.send(Event::Interfaces).unwrap();
        }
        sender.send(Event::Wake).unwrap();
        assert_eq!(next(&events), Next::Check { woke: true });
        assert!(events.try_recv().is_err());
    }

    #[test]
    fn stop_wins_over_queued_events() {
        let (sender, events) = mpsc::channel();
        sender.send(Event::Interfaces).unwrap();
        sender.send(Event::Stop).unwrap();
        sender.send(Event::Wake).unwrap();
        assert_eq!(next(&events), Next::Stop);
    }

    #[test]
    fn a_closed_channel_stops() {
        let (sender, events) = mpsc::channel::<Event>();
        drop(sender);
        assert_eq!(next(&events), Next::Stop);
    }
}
