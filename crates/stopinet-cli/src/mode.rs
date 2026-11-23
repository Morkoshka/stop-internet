//! `mode` switches the mode of the running service over its named pipe;
//! `status` uses [`line`] to show the mode.

use stopinet_core::config::MAX_DURATION_MIN;
use stopinet_core::control::{Choice, Refusal, Remaining};
use stopinet_core::policy::{Mode, TunnelState};
use stopinet_core::protocol::{Request, Response, Status};
use stopinet_win::pipe;

use crate::USAGE;

pub fn run(args: &[String]) -> Result<(), String> {
    let (mode, minutes) = parse(args)?;
    let choice = choice(mode, minutes, || {
        let status = status()?;
        status.durations.first().copied().ok_or_else(|| {
            "normal_mode.durations_min is empty in the configuration; pass --minutes".into()
        })
    })?;
    match pipe::ask(&Request::Choose(choice)).map_err(|e| e.to_string())? {
        Response::Status(status) => {
            println!("mode:     {}", describe(&status));
            Ok(())
        }
        Response::Refused(refusal) => Err(refused(refusal)),
    }
}

/// The mode line of `status`.
pub fn line() -> String {
    match status() {
        Ok(status) => describe(&status),
        Err(error) => format!("unknown ({error})"),
    }
}

fn status() -> Result<Status, String> {
    match pipe::ask(&Request::Status).map_err(|e| e.to_string())? {
        Response::Status(status) => Ok(status),
        Response::Refused(refusal) => Err(refused(refusal)),
    }
}

fn parse(args: &[String]) -> Result<(Mode, Option<u32>), String> {
    let (word, rest) = args
        .split_first()
        .ok_or_else(|| format!("mode needs tunnel, proxy or normal\n\n{USAGE}"))?;
    let mode = word.parse::<Mode>()?;
    let mut minutes = None;
    let mut rest = rest.iter();
    while let Some(option) = rest.next() {
        match option.as_str() {
            "--minutes" => {
                let value = rest.next().ok_or("option '--minutes' needs a value")?;
                minutes = Some(
                    value
                        .parse::<u32>()
                        .ok()
                        .filter(|&m| m <= MAX_DURATION_MIN)
                        .ok_or_else(|| {
                            format!("--minutes must be between 0 and {MAX_DURATION_MIN}")
                        })?,
                );
            }
            other => return Err(format!("unknown option '{other}'\n\n{USAGE}")),
        }
    }
    Ok((mode, minutes))
}

/// `default` gives the duration of normal internet without `--minutes`; it
/// is asked only then.
fn choice(
    mode: Mode,
    minutes: Option<u32>,
    default: impl FnOnce() -> Result<u32, String>,
) -> Result<Choice, String> {
    match (mode, minutes) {
        (Mode::TunnelOnly, None) => Ok(Choice::TunnelOnly),
        (Mode::Proxy, None) => Ok(Choice::Proxy),
        (Mode::Normal, Some(minutes)) => Ok(Choice::Normal { minutes }),
        (Mode::Normal, None) => Ok(Choice::Normal {
            minutes: default()?,
        }),
        (Mode::TunnelOnly | Mode::Proxy, Some(_)) => Err("--minutes goes only with normal".into()),
    }
}

fn describe(status: &Status) -> String {
    let tunnel = match status.tunnel {
        TunnelState::Up => "tunnel up",
        TunnelState::Down => "tunnel down",
    };
    match (status.mode, status.left) {
        (Mode::TunnelOnly, _) => format!("tunnel only, {tunnel}"),
        (Mode::Proxy, _) => format!("proxy, {tunnel}"),
        (Mode::Normal, Some(Remaining::Time(left))) => {
            let minutes = left.as_secs().div_ceil(60);
            format!("normal internet, protection off, {minutes} min left")
        }
        (Mode::Normal, _) => {
            "normal internet, protection off until reboot, sleep or sign-in".into()
        }
    }
}

fn refused(refusal: Refusal) -> String {
    match refusal {
        Refusal::NotElevated => {
            "normal internet lowers protection: run this from an elevated terminal".into()
        }
        Refusal::BadRequest => "the service did not accept the request".into(),
        Refusal::Unavailable => "the service did not answer in time, try again".into(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(String::from).collect()
    }

    fn no_default() -> Result<u32, String> {
        panic!("the default duration must not be asked for")
    }

    #[test]
    fn protected_modes_take_no_minutes() {
        let (mode, minutes) = parse(&args("tunnel")).unwrap();
        assert_eq!(choice(mode, minutes, no_default), Ok(Choice::TunnelOnly));
        let (mode, minutes) = parse(&args("proxy")).unwrap();
        assert_eq!(choice(mode, minutes, no_default), Ok(Choice::Proxy));
        let (mode, minutes) = parse(&args("proxy --minutes 15")).unwrap();
        assert!(choice(mode, minutes, no_default).is_err());
    }

    #[test]
    fn normal_uses_the_minutes_or_the_first_configured_duration() {
        let (mode, minutes) = parse(&args("normal --minutes 0")).unwrap();
        assert_eq!(
            choice(mode, minutes, no_default),
            Ok(Choice::Normal { minutes: 0 })
        );
        let (mode, minutes) = parse(&args("normal")).unwrap();
        assert_eq!(
            choice(mode, minutes, || Ok(15)),
            Ok(Choice::Normal { minutes: 15 })
        );
    }

    #[test]
    fn bad_arguments_are_rejected() {
        for line in [
            "",
            "off",
            "normal --minutes",
            "normal --minutes 1441",
            "normal --minutes soon",
            "normal --hours 1",
        ] {
            assert!(parse(&args(line)).is_err(), "{line:?}");
        }
    }

    #[test]
    fn describes_the_state() {
        let mut status = Status {
            mode: Mode::Normal,
            tunnel: TunnelState::Down,
            left: Some(Remaining::Time(Duration::from_secs(61))),
            durations: vec![15],
        };
        assert_eq!(
            describe(&status),
            "normal internet, protection off, 2 min left"
        );
        status.left = Some(Remaining::UntilReset);
        assert!(describe(&status).contains("until reboot"));
        status.mode = Mode::TunnelOnly;
        status.left = None;
        assert_eq!(describe(&status), "tunnel only, tunnel down");
    }
}
