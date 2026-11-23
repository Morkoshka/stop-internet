//! Messages between the service and its clients, the tray icon and the CLI,
//! over the named pipe [`PIPE_NAME`].
//!
//! A connection carries one request and one response. Each is one line of
//! ASCII text, at most [`MAX_LINE`] bytes, ending with `\n`.
//!
//! | Request | Meaning |
//! |---|---|
//! | `status` | report the state |
//! | `mode tunnel`, `mode proxy` | switch to a protected mode |
//! | `mode normal <minutes>` | "normal internet", `0` without a time limit; needs an elevated administrator |
//!
//! The answer is the state after the request,
//! `ok mode=normal tunnel=up left=840 durations=15,60,0`, or a refusal,
//! `refused not-elevated`, `refused bad-request` or `refused unavailable`.
//! `left` is in seconds, `reset` without a time limit and `-` in the
//! protected modes; `durations` are the choices offered for "normal
//! internet". Clients ignore keys they do not know, so that new keys do not
//! break older clients.

use std::fmt;
use std::time::Duration;

use crate::config::MAX_DURATION_MIN;
use crate::control::{Choice, Refusal, Remaining};
use crate::policy::{Mode, TunnelState};

/// Name of the pipe served by the service.
pub const PIPE_NAME: &str = r"\\.\pipe\stopinet";

/// Longest request or response line, without the final `\n`.
pub const MAX_LINE: usize = 512;

/// A request of a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// Report the state.
    Status,
    /// Switch the mode.
    Choose(Choice),
}

/// State of the service, sent in answer to every accepted request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// The selected mode.
    pub mode: Mode,
    /// The tunnel as the service last saw it.
    pub tunnel: TunnelState,
    /// Time left of "normal internet"; `None` in the protected modes.
    pub left: Option<Remaining>,
    /// Durations of "normal internet" offered in the tray menu, in minutes;
    /// `0` means without a time limit.
    pub durations: Vec<u32>,
}

/// The answer of the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// The request was carried out; the state after it.
    Status(Status),
    /// The request was not carried out.
    Refused(Refusal),
}

/// A line that does not follow the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError(String);

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unexpected message from the other side: {}", self.0)
    }
}

impl std::error::Error for ProtocolError {}

fn error(message: impl Into<String>) -> ProtocolError {
    ProtocolError(message.into())
}

impl Request {
    /// Parses a request line; a final `\n` or `\r\n` is allowed.
    pub fn parse(line: &str) -> Result<Self, ProtocolError> {
        let words: Vec<&str> = line.split_ascii_whitespace().collect();
        match words.as_slice() {
            ["status"] => Ok(Self::Status),
            ["mode", "tunnel"] => Ok(Self::Choose(Choice::TunnelOnly)),
            ["mode", "proxy"] => Ok(Self::Choose(Choice::Proxy)),
            ["mode", "normal", minutes] => {
                let minutes = minutes
                    .parse()
                    .ok()
                    .filter(|&m| m <= MAX_DURATION_MIN)
                    .ok_or_else(|| error(format!("minutes out of range: {minutes}")))?;
                Ok(Self::Choose(Choice::Normal { minutes }))
            }
            _ => Err(error(format!("unknown request: {}", shorten(line)))),
        }
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status => f.write_str("status"),
            Self::Choose(Choice::TunnelOnly) => f.write_str("mode tunnel"),
            Self::Choose(Choice::Proxy) => f.write_str("mode proxy"),
            Self::Choose(Choice::Normal { minutes }) => write!(f, "mode normal {minutes}"),
        }
    }
}

impl Response {
    /// Parses a response line; a final `\n` or `\r\n` is allowed.
    pub fn parse(line: &str) -> Result<Self, ProtocolError> {
        let mut words = line.split_ascii_whitespace();
        match (words.next(), words.next(), words.next()) {
            (Some("ok"), ..) => parse_status(line.split_ascii_whitespace().skip(1)),
            (Some("refused"), Some(reason), None) => Ok(Self::Refused(match reason {
                "not-elevated" => Refusal::NotElevated,
                "bad-request" => Refusal::BadRequest,
                "unavailable" => Refusal::Unavailable,
                other => return Err(error(format!("unknown refusal: {}", shorten(other)))),
            })),
            _ => Err(error(format!("unknown response: {}", shorten(line)))),
        }
    }
}

fn parse_status<'a>(pairs: impl Iterator<Item = &'a str>) -> Result<Response, ProtocolError> {
    let (mut mode, mut tunnel, mut left, mut durations) = (None, None, None, Vec::new());
    for pair in pairs {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| error(format!("not a key=value pair: {}", shorten(pair))))?;
        match key {
            "mode" => mode = Some(value.parse::<Mode>().map_err(error)?),
            "tunnel" => tunnel = Some(value.parse::<TunnelState>().map_err(error)?),
            "left" => {
                left = Some(match value {
                    "-" => None,
                    "reset" => Some(Remaining::UntilReset),
                    seconds => Some(Remaining::Time(Duration::from_secs(
                        seconds
                            .parse()
                            .map_err(|_| error(format!("bad left={}", shorten(seconds))))?,
                    ))),
                });
            }
            "durations" => {
                durations = value
                    .split(',')
                    .filter(|d| !d.is_empty())
                    .map(|d| d.parse().map_err(|_| error(format!("bad duration {d}"))))
                    .collect::<Result<_, _>>()?;
            }
            // Newer services may add keys.
            _ => {}
        }
    }
    match (mode, tunnel, left) {
        (Some(mode), Some(tunnel), Some(left)) => Ok(Response::Status(Status {
            mode,
            tunnel,
            left,
            durations,
        })),
        _ => Err(error("mode, tunnel or left is missing")),
    }
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status(status) => {
                write!(
                    f,
                    "ok mode={} tunnel={} left=",
                    status.mode.word(),
                    status.tunnel.word()
                )?;
                match status.left {
                    None => f.write_str("-")?,
                    Some(Remaining::UntilReset) => f.write_str("reset")?,
                    // Rounded up: "0 seconds left" never shows while the
                    // mode is still on.
                    Some(Remaining::Time(left)) => {
                        write!(f, "{}", left.as_secs() + u64::from(left.subsec_nanos() > 0))?;
                    }
                }
                f.write_str(" durations=")?;
                for (index, minutes) in status.durations.iter().enumerate() {
                    if index > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{minutes}")?;
                }
                Ok(())
            }
            Self::Refused(reason) => f.write_str(match reason {
                Refusal::NotElevated => "refused not-elevated",
                Refusal::BadRequest => "refused bad-request",
                Refusal::Unavailable => "refused unavailable",
            }),
        }
    }
}

/// Keeps error messages short when the other side sends garbage.
fn shorten(text: &str) -> String {
    const LIMIT: usize = 40;
    let text = text.trim_end();
    match text.char_indices().nth(LIMIT) {
        Some((end, _)) => format!("{}...", &text[..end]),
        None => text.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(mode: Mode, left: Option<Remaining>) -> Response {
        Response::Status(Status {
            mode,
            tunnel: TunnelState::Up,
            left,
            durations: vec![15, 60, 0],
        })
    }

    #[test]
    fn requests_round_trip() {
        let requests = [
            Request::Status,
            Request::Choose(Choice::TunnelOnly),
            Request::Choose(Choice::Proxy),
            Request::Choose(Choice::Normal { minutes: 0 }),
            Request::Choose(Choice::Normal { minutes: 15 }),
        ];
        for request in requests {
            let line = request.to_string();
            assert!(line.len() <= MAX_LINE);
            assert_eq!(Request::parse(&line), Ok(request), "{line}");
            assert_eq!(Request::parse(&format!("{line}\r\n")), Ok(request));
        }
    }

    #[test]
    fn requests_are_parsed_strictly() {
        for line in [
            "",
            "status now",
            "STATUS",
            "mode",
            "mode off",
            "mode normal",
            "mode normal -1",
            "mode normal 1441",
            "mode normal 15 extra",
            "mode tunnel 15",
        ] {
            assert!(Request::parse(line).is_err(), "{line:?}");
        }
    }

    #[test]
    fn responses_round_trip() {
        let responses = [
            status(Mode::TunnelOnly, None),
            status(Mode::Proxy, None),
            status(Mode::Normal, Some(Remaining::UntilReset)),
            status(
                Mode::Normal,
                Some(Remaining::Time(Duration::from_secs(840))),
            ),
            Response::Refused(Refusal::NotElevated),
            Response::Refused(Refusal::BadRequest),
            Response::Refused(Refusal::Unavailable),
        ];
        for response in responses {
            let line = response.to_string();
            assert!(line.len() <= MAX_LINE);
            assert_eq!(Response::parse(&line), Ok(response.clone()), "{line}");
            assert_eq!(Response::parse(&format!("{line}\n")), Ok(response));
        }
    }

    #[test]
    fn status_line_is_readable() {
        let response = status(
            Mode::Normal,
            Some(Remaining::Time(Duration::from_millis(839_001))),
        );
        assert_eq!(
            response.to_string(),
            "ok mode=normal tunnel=up left=840 durations=15,60,0"
        );
    }

    #[test]
    fn unknown_keys_are_ignored_and_order_does_not_matter() {
        let parsed = Response::parse("ok durations= health=good left=- tunnel=down mode=proxy");
        assert_eq!(
            parsed,
            Ok(Response::Status(Status {
                mode: Mode::Proxy,
                tunnel: TunnelState::Down,
                left: None,
                durations: Vec::new(),
            }))
        );
    }

    #[test]
    fn broken_responses_are_errors() {
        for line in [
            "",
            "ok",
            "ok mode=tunnel tunnel=up",
            "ok mode=off tunnel=up left=-",
            "ok mode=tunnel tunnel=up left=soon",
            "ok mode=tunnel tunnel=up left=- durations=15,x",
            "ok mode tunnel",
            "refused",
            "refused angry",
            "refused not-elevated now",
            "hello",
        ] {
            assert!(Response::parse(line).is_err(), "{line:?}");
        }
    }

    #[test]
    fn errors_quote_garbage_briefly() {
        let garbage = "x".repeat(1000);
        let message = Request::parse(&garbage).unwrap_err().to_string();
        assert!(message.len() < 120, "{message}");
    }
}
