//! `stopinet` command-line tool.
//!
//! - `policy` prints the rules for a mode and a tunnel state; it changes
//!   nothing.
//! - `trial` applies the rules for a limited time through a dynamic WFP
//!   session; they disappear when the trial ends or the process exits.

use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use stopinet_core::config::{self, Config};
use stopinet_core::policy::{Mode, Policy, TunnelState};
use stopinet_win::{Environment, Firewall, Plan, TunnelLookup, WfpError, find_tunnel};

const USAGE: &str = "\
Usage:
  stopinet policy [--config <file>] [--mode tunnel|proxy|normal] [--tunnel up|down]
      Print the firewall rules for a mode and a tunnel state. Changes nothing.

  stopinet trial [--config <file>] [--mode tunnel|proxy] [--seconds <10-900>]
      Apply the rules temporarily (default 120 s) and follow the tunnel.
      The rules disappear when the time is over, on Ctrl+C or when the
      window is closed. Needs an elevated terminal.

Planned: status, mode, install, uninstall, panic.";

const DEFAULT_TRIAL_SECONDS: u64 = 120;
const TRIAL_SECONDS: std::ops::RangeInclusive<u64> = 10..=900;
const POLL_INTERVAL: Duration = Duration::from_millis(500);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("policy") => policy(&args[1..]),
        Some("trial") => trial(&args[1..]),
        Some("-h" | "--help" | "help") | None => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown command '{other}'\n\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

/// Options shared by the commands.
struct Options {
    config: PathBuf,
    mode: Mode,
    tunnel: TunnelState,
    seconds: u64,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        config: PathBuf::from(config::DEFAULT_PATH),
        mode: Mode::TunnelOnly,
        tunnel: TunnelState::Down,
        seconds: DEFAULT_TRIAL_SECONDS,
    };
    let mut args = args.iter();
    while let Some(option) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("option '{option}' needs a value"))?;
        match option.as_str() {
            "--config" => options.config = PathBuf::from(value),
            "--mode" => options.mode = value.parse()?,
            "--tunnel" => options.tunnel = value.parse()?,
            "--seconds" => {
                options.seconds = value
                    .parse()
                    .ok()
                    .filter(|s| TRIAL_SECONDS.contains(s))
                    .ok_or_else(|| {
                        format!(
                            "--seconds must be between {} and {}",
                            TRIAL_SECONDS.start(),
                            TRIAL_SECONDS.end()
                        )
                    })?;
            }
            other => return Err(format!("unknown option '{other}'\n\n{USAGE}")),
        }
    }
    Ok(options)
}

fn policy(args: &[String]) -> Result<(), String> {
    let options = parse(args)?;
    let config = Config::load(&options.config).map_err(|e| e.to_string())?;
    let policy = Policy::build(&config, options.mode, options.tunnel);

    println!("mode: {:?}, tunnel: {:?}", options.mode, options.tunnel);
    println!("rules, highest precedence first:");
    for (index, rule) in policy.rules().iter().enumerate() {
        println!("{:>3}  {rule}", index + 1);
    }
    Ok(())
}

/// What the trial last saw of the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Observation {
    state: TunnelState,
    luid: Option<u64>,
    note: Option<String>,
}

fn observe(config: &Config) -> Observation {
    let down = |note: Option<String>| Observation {
        state: TunnelState::Down,
        luid: None,
        note,
    };
    match find_tunnel(&config.tunnel.adapter_name, &config.tunnel.driver) {
        Ok(TunnelLookup::Found { luid, up: true }) => Observation {
            state: TunnelState::Up,
            luid: Some(luid),
            note: None,
        },
        Ok(TunnelLookup::Found { up: false, .. }) => {
            down(Some("adapter is not operational".into()))
        }
        Ok(TunnelLookup::Missing) => down(None),
        Ok(TunnelLookup::WrongDriver { driver }) => down(Some(format!(
            "adapter found, but its driver is '{driver}', expected '{}'",
            config.tunnel.driver
        ))),
        Err(error) => down(Some(error.to_string())),
    }
}

fn trial(args: &[String]) -> Result<(), String> {
    let options = parse(args)?;
    if options.mode == Mode::Normal {
        return Err("a trial needs a protected mode: tunnel or proxy".into());
    }
    let config = Config::load(&options.config).map_err(|e| e.to_string())?;
    let mut firewall = Firewall::open_dynamic().map_err(explain)?;

    println!(
        "stop-internet trial: mode {:?}, adapter \"{}\".",
        options.mode, config.tunnel.adapter_name
    );
    println!(
        "All rules are temporary: they disappear after {} s, on Ctrl+C or when this window is closed.\n",
        options.seconds
    );

    let started = Instant::now();
    let deadline = started + Duration::from_secs(options.seconds);
    let mut last: Option<Observation> = None;

    while Instant::now() < deadline {
        let now = observe(&config);
        if last.as_ref() != Some(&now) {
            let policy = Policy::build(&config, options.mode, now.state);
            let plan = Plan::build(
                &policy,
                &Environment {
                    tunnel_luid: now.luid,
                },
            );
            let report = firewall.apply(&plan).map_err(explain)?;

            let state = match now.state {
                TunnelState::Up => "up",
                TunnelState::Down => "down",
            };
            println!(
                "[{:>4}s] tunnel {state}: {} filters active",
                started.elapsed().as_secs(),
                report.filters
            );
            for line in now.note.iter().chain(&report.warnings) {
                println!("         note: {line}");
            }
            last = Some(now);
        }
        thread::sleep(POLL_INTERVAL);
    }

    drop(firewall);
    println!(
        "[{:>4}s] trial over, all rules removed.",
        started.elapsed().as_secs()
    );
    Ok(())
}

fn explain(error: WfpError) -> String {
    if error.is_access_denied() {
        "administrator rights are needed: run this from an elevated terminal".into()
    } else if error.is_already_exists() {
        format!("another stop-internet trial or service is already active ({error})")
    } else {
        error.to_string()
    }
}
