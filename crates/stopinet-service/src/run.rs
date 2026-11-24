//! What the service does between start and stop.
//!
//! 1. Load the configuration.
//! 2. Install the persistent baseline (unless session-only) and open a
//!    dynamic WFP session for the session rules.
//! 3. Serve the named pipe for the tray icon and the CLI.
//! 4. Follow the tunnel adapter, through interface notifications and a
//!    periodic check, and the mode chosen by the user, and rebuild the
//!    session rules when either changes. "Normal internet" ends when its
//!    time is up, on wake-up and when a user logs on.
//! 5. On stop, close the pipe and the dynamic session. The baseline keeps
//!    blocking.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use stopinet_core::config::Config;
use stopinet_core::control::{Choice, Refusal, Selection};
use stopinet_core::policy::{Mode, Policy, Scope, TunnelState};
use stopinet_core::protocol::{PIPE_NAME, Request, Response, Status};
use stopinet_win::persistent::install_baseline;
use stopinet_win::{
    Caller, Environment, Firewall, InterfaceWatch, PipeServer, Plan, WfpError, observe_tunnel,
};

use crate::log::Log;

/// Safety net for missed interface notifications. It is also how often a
/// timed "normal internet" is checked, so it may end this much late.
const CHECK_INTERVAL: Duration = Duration::from_secs(2);

/// How long the pipe server waits for the main loop to carry out a request.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

/// What the main loop reacts to.
#[derive(Debug)]
pub enum Event {
    /// The service control manager asks the service to stop.
    Stop,
    /// The machine woke up from sleep or hibernation.
    Wake,
    /// A user logged on.
    Logon,
    /// An IP interface appeared, disappeared or changed.
    Interfaces,
    /// A client of the named pipe sent a request.
    Request(Command),
}

/// A request from the named pipe, with the way back to its client.
#[derive(Debug)]
pub struct Command {
    /// What the client asks for.
    pub request: Request,
    /// Who asks.
    pub caller: Caller,
    /// Takes the answer.
    pub reply: Sender<Response>,
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

    let interface_sender = sender.clone();
    let watch = match InterfaceWatch::start(move || {
        let _ = interface_sender.send(Event::Interfaces);
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

    let mut selection = Selection::default();
    let mut follower = Follower::new(options.session_only);
    follower.update(&config, selection.mode(), &mut firewall, log)?;
    let pipe = serve_pipe(sender, log);
    running();
    log.write("running");

    loop {
        let batch = next(events);
        if batch.stop {
            break;
        }
        let now = Instant::now();
        if batch.woke {
            selection.reset();
            log.write(format_args!("woke up, mode {:?}", selection.mode()));
        }
        if batch.logon {
            selection.reset();
            log.write(format_args!("user logged on, mode {:?}", selection.mode()));
        }
        if selection.expire(now) {
            log.write("normal internet time is up, mode TunnelOnly");
        }
        follower.update(&config, selection.mode(), &mut firewall, log)?;

        for command in batch.commands {
            let result = carry_out(&mut selection, &command, now, log);
            // The new rules are in place before the client hears about them.
            follower.update(&config, selection.mode(), &mut firewall, log)?;
            let response = match result {
                Ok(()) => Response::Status(Status {
                    mode: selection.mode(),
                    tunnel: follower.tunnel,
                    left: selection.remaining(Instant::now()),
                    durations: config.normal_mode.durations_min.clone(),
                }),
                Err(refusal) => Response::Refused(refusal),
            };
            let _ = command.reply.send(response);
        }
    }

    // Requests still queued are dropped, so their clients hear at once that
    // the service is unavailable.
    for _ in events.try_iter() {}
    drop(pipe);
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

/// Starts the named pipe. Without it the service still protects, so a
/// failure is only logged.
fn serve_pipe(sender: Sender<Event>, log: &mut Log) -> Option<PipeServer> {
    let handler = move |line: &str, caller: Caller| {
        let response = match Request::parse(line) {
            Ok(request) => forward(&sender, request, caller),
            Err(_) => Response::Refused(Refusal::BadRequest),
        };
        response.to_string()
    };
    match PipeServer::start(PIPE_NAME, handler) {
        Ok(server) => Some(server),
        Err(error) => {
            log.write(format_args!(
                "named pipe not available ({error}): the tray icon and `stopinet mode` \
                 will not work until the service restarts"
            ));
            None
        }
    }
}

/// Hands a request to the main loop and waits for the answer.
fn forward(sender: &Sender<Event>, request: Request, caller: Caller) -> Response {
    let (reply, answer) = mpsc::channel();
    let command = Command {
        request,
        caller,
        reply,
    };
    if sender.send(Event::Request(command)).is_err() {
        return Response::Refused(Refusal::Unavailable);
    }
    answer
        .recv_timeout(ANSWER_TIMEOUT)
        .unwrap_or(Response::Refused(Refusal::Unavailable))
}

/// Applies a mode change and logs it. A status request changes nothing.
fn carry_out(
    selection: &mut Selection,
    command: &Command,
    now: Instant,
    log: &mut Log,
) -> Result<(), Refusal> {
    let Request::Choose(choice) = command.request else {
        return Ok(());
    };
    let result = selection.choose(choice, command.caller.admin, now);
    match (result, choice) {
        (Ok(()), Choice::Normal { minutes: 0 }) => {
            log.write("normal internet until reboot, wake-up or logon, asked by an administrator");
        }
        (Ok(()), Choice::Normal { minutes }) => log.write(format_args!(
            "normal internet for {minutes} min, asked by an administrator"
        )),
        (Ok(()), choice) => log.write(format_args!("mode {:?} asked", choice.mode())),
        (Err(Refusal::NotElevated), _) => {
            log.write("normal internet refused: the client is not an elevated administrator");
        }
        (Err(refusal), _) => log.write(format_args!("request refused: {refusal:?}")),
    }
    result
}

/// Keeps the session rules in line with the mode and the tunnel.
struct Follower {
    session_only: bool,
    /// The tunnel as last seen.
    tunnel: TunnelState,
    /// Mode, tunnel state and adapter of the rules in place.
    applied: Option<(Mode, TunnelState, Option<u64>, Vec<IpAddr>)>,
    last_note: Option<String>,
}

impl Follower {
    fn new(session_only: bool) -> Self {
        Self {
            session_only,
            tunnel: TunnelState::Down,
            applied: None,
            last_note: None,
        }
    }

    /// Looks at the tunnel and rebuilds the rules if anything changed.
    fn update(
        &mut self,
        config: &Config,
        mode: Mode,
        firewall: &mut Firewall,
        log: &mut Log,
    ) -> Result<(), String> {
        let now = observe_tunnel(&config.tunnel);
        self.tunnel = now.state;
        let key = (mode, now.state, now.luid, now.addresses.clone());

        if self.applied.as_ref() != Some(&key) {
            let policy = Policy::build(config, mode, now.state);
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
            log.write(format_args!(
                "mode {mode:?}, tunnel {}: {} filters in the session",
                now.state.word(),
                report.filters
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

/// Events taken from the queue at once.
#[derive(Debug, Default)]
struct Batch {
    /// Stop now; the rest of the batch does not matter.
    stop: bool,
    woke: bool,
    logon: bool,
    /// Requests in the order they came.
    commands: Vec<Command>,
}

/// Waits for the next event or the periodic check, then takes every event
/// already queued, so that a burst of notifications costs one check.
fn next(events: &Receiver<Event>) -> Batch {
    let mut batch = Batch::default();
    let first = match events.recv_timeout(CHECK_INTERVAL) {
        Ok(event) => Some(event),
        Err(RecvTimeoutError::Timeout) => None,
        Err(RecvTimeoutError::Disconnected) => {
            batch.stop = true;
            return batch;
        }
    };
    for event in first.into_iter().chain(events.try_iter()) {
        match event {
            Event::Stop => {
                batch.stop = true;
                return batch;
            }
            Event::Wake => batch.woke = true,
            Event::Logon => batch.logon = true,
            Event::Interfaces => {}
            Event::Request(command) => batch.commands.push(command),
        }
    }
    batch
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
    use std::thread;

    use super::*;

    const USER: Caller = Caller { admin: false };

    fn command(request: Request) -> (Command, Receiver<Response>) {
        let (reply, answer) = mpsc::channel();
        let command = Command {
            request,
            caller: USER,
            reply,
        };
        (command, answer)
    }

    #[test]
    fn a_burst_of_events_is_one_check() {
        let (sender, events) = mpsc::channel();
        for _ in 0..5 {
            sender.send(Event::Interfaces).unwrap();
        }
        sender.send(Event::Wake).unwrap();
        let batch = next(&events);
        assert!(batch.woke && !batch.logon && !batch.stop);
        assert!(batch.commands.is_empty());
        assert!(events.try_recv().is_err());
    }

    #[test]
    fn requests_keep_their_order() {
        let (sender, events) = mpsc::channel();
        sender
            .send(Event::Request(command(Request::Status).0))
            .unwrap();
        sender.send(Event::Logon).unwrap();
        sender
            .send(Event::Request(command(Request::Choose(Choice::Proxy)).0))
            .unwrap();
        let batch = next(&events);
        assert!(batch.logon);
        let requests: Vec<Request> = batch.commands.iter().map(|c| c.request).collect();
        assert_eq!(requests, [Request::Status, Request::Choose(Choice::Proxy)]);
    }

    #[test]
    fn stop_wins_over_queued_events() {
        let (sender, events) = mpsc::channel();
        sender.send(Event::Interfaces).unwrap();
        sender.send(Event::Stop).unwrap();
        sender.send(Event::Wake).unwrap();
        assert!(next(&events).stop);
    }

    #[test]
    fn a_closed_channel_stops() {
        let (sender, events) = mpsc::channel::<Event>();
        drop(sender);
        assert!(next(&events).stop);
    }

    #[test]
    fn requests_reach_the_main_loop_and_come_back() {
        let (sender, events) = mpsc::channel();
        let main_loop = thread::spawn(move || {
            let Ok(Event::Request(command)) = events.recv() else {
                panic!("expected a request");
            };
            assert_eq!(command.request, Request::Status);
            command
                .reply
                .send(Response::Refused(Refusal::BadRequest))
                .unwrap();
        });
        assert_eq!(
            forward(&sender, Request::Status, USER),
            Response::Refused(Refusal::BadRequest)
        );
        main_loop.join().unwrap();
    }

    #[test]
    fn a_stopped_main_loop_is_unavailable() {
        let (sender, events) = mpsc::channel();
        drop(events);
        assert_eq!(
            forward(&sender, Request::Status, USER),
            Response::Refused(Refusal::Unavailable)
        );

        // Dropping a queued request answers its client at once.
        let (sender, events) = mpsc::channel();
        let dropper = thread::spawn(move || drop(events.recv()));
        assert_eq!(
            forward(&sender, Request::Status, USER),
            Response::Refused(Refusal::Unavailable)
        );
        dropper.join().unwrap();
    }

    #[test]
    fn normal_internet_needs_an_administrator() {
        let path =
            std::env::temp_dir().join(format!("stopinet-run-test-{}.log", std::process::id()));
        let mut log = Log::open(&path);
        let mut selection = Selection::default();
        let now = Instant::now();

        let (request, _) = command(Request::Choose(Choice::Normal { minutes: 15 }));
        assert_eq!(
            carry_out(&mut selection, &request, now, &mut log),
            Err(Refusal::NotElevated)
        );
        assert_eq!(selection.mode(), Mode::TunnelOnly);

        let (mut request, _) = command(Request::Choose(Choice::Normal { minutes: 15 }));
        request.caller = Caller { admin: true };
        assert_eq!(carry_out(&mut selection, &request, now, &mut log), Ok(()));
        assert_eq!(selection.mode(), Mode::Normal);

        drop(log);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("normal internet refused"), "{text}");
        assert!(text.contains("normal internet for 15 min"), "{text}");
        std::fs::remove_file(&path).unwrap();
    }
}
