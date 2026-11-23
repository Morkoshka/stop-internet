//! The mode chosen by the user and how long "normal internet" lasts.
//!
//! The service keeps one [`Selection`]. It starts in tunnel-only mode, so
//! every service start, and with it every boot, returns to protection.
//! A timed "normal internet" ends by itself; a wake-up from sleep or a user
//! logon ends it too, with or without a time limit ([`Selection::reset`]).
//! It always ends in tunnel-only mode.
//!
//! Only an elevated administrator may lower protection. Switching between
//! the protected modes is open to every client of the service.

use std::time::{Duration, Instant};

use crate::config::MAX_DURATION_MIN;
use crate::policy::Mode;

/// What a client asks the service to switch to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// [`Mode::TunnelOnly`].
    TunnelOnly,
    /// [`Mode::Proxy`].
    Proxy,
    /// [`Mode::Normal`] for this many minutes; `0` means until the next
    /// reboot, wake-up or logon.
    Normal {
        /// Duration in minutes, at most [`MAX_DURATION_MIN`].
        minutes: u32,
    },
}

impl Choice {
    /// The mode this choice selects.
    pub fn mode(self) -> Mode {
        match self {
            Self::TunnelOnly => Mode::TunnelOnly,
            Self::Proxy => Mode::Proxy,
            Self::Normal { .. } => Mode::Normal,
        }
    }

    /// Whether only an elevated administrator may ask for it.
    pub fn lowers_protection(self) -> bool {
        matches!(self, Self::Normal { .. })
    }
}

/// How long "normal internet" still lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remaining {
    /// No time limit: it ends with the next reboot, wake-up or logon.
    UntilReset,
    /// It ends after this time, or earlier with a reboot, wake-up or logon.
    Time(Duration),
}

/// Why a choice was not applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Lowering protection needs an elevated administrator.
    NotElevated,
    /// The request is malformed or out of range.
    BadRequest,
    /// The service could not answer, for example because it is stopping.
    Unavailable,
}

/// The mode selected by the user, with the end of a timed "normal internet".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    mode: Mode,
    /// End of a timed "normal internet"; `None` without a time limit and in
    /// the protected modes.
    until: Option<Instant>,
}

impl Default for Selection {
    fn default() -> Self {
        Self {
            mode: Mode::TunnelOnly,
            until: None,
        }
    }
}

impl Selection {
    /// The selected mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Time left of "normal internet"; `None` in the protected modes.
    pub fn remaining(&self, now: Instant) -> Option<Remaining> {
        if self.mode != Mode::Normal {
            return None;
        }
        Some(match self.until {
            Some(until) => Remaining::Time(until.saturating_duration_since(now)),
            None => Remaining::UntilReset,
        })
    }

    /// Applies a client's choice. `admin` says whether the client holds an
    /// elevated administrator token.
    pub fn choose(&mut self, choice: Choice, admin: bool, now: Instant) -> Result<(), Refusal> {
        if choice.lowers_protection() && !admin {
            return Err(Refusal::NotElevated);
        }
        self.until = match choice {
            Choice::Normal { minutes } if minutes > MAX_DURATION_MIN => {
                return Err(Refusal::BadRequest);
            }
            Choice::Normal { minutes: 0 } => None,
            Choice::Normal { minutes } => Some(now + Duration::from_secs(u64::from(minutes) * 60)),
            Choice::TunnelOnly | Choice::Proxy => None,
        };
        self.mode = choice.mode();
        Ok(())
    }

    /// Ends a timed "normal internet" whose time is up. Returns whether it
    /// ended now.
    pub fn expire(&mut self, now: Instant) -> bool {
        match self.until {
            Some(until) if self.mode == Mode::Normal && now >= until => {
                *self = Self::default();
                true
            }
            _ => false,
        }
    }

    /// After a wake-up from sleep or a user logon: ends "normal internet",
    /// the protected modes stay. Returns whether the mode changed.
    pub fn reset(&mut self) -> bool {
        let mode = self.mode.after_reset();
        if mode == self.mode {
            return false;
        }
        *self = Self::default();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    fn normal(minutes: u32, now: Instant) -> Selection {
        let mut selection = Selection::default();
        selection
            .choose(Choice::Normal { minutes }, true, now)
            .unwrap();
        selection
    }

    #[test]
    fn starts_protected() {
        let selection = Selection::default();
        assert_eq!(selection.mode(), Mode::TunnelOnly);
        assert_eq!(selection.remaining(Instant::now()), None);
    }

    #[test]
    fn only_an_elevated_administrator_lowers_protection() {
        let now = Instant::now();
        let mut selection = Selection::default();
        assert_eq!(
            selection.choose(Choice::Normal { minutes: 15 }, false, now),
            Err(Refusal::NotElevated)
        );
        assert_eq!(selection.mode(), Mode::TunnelOnly);

        // Protected modes are open to everyone, also to leave normal internet.
        assert_eq!(selection.choose(Choice::Proxy, false, now), Ok(()));
        assert_eq!(selection.mode(), Mode::Proxy);
        let mut selection = normal(15, now);
        assert_eq!(selection.choose(Choice::TunnelOnly, false, now), Ok(()));
        assert_eq!(selection.mode(), Mode::TunnelOnly);
    }

    #[test]
    fn timed_normal_internet_counts_down_and_ends_in_tunnel_mode() {
        let start = Instant::now();
        let mut selection = normal(15, start);
        assert_eq!(
            selection.remaining(start + 5 * MINUTE),
            Some(Remaining::Time(10 * MINUTE))
        );

        assert!(!selection.expire(start + 15 * MINUTE - Duration::from_secs(1)));
        assert_eq!(selection.mode(), Mode::Normal);

        assert!(selection.expire(start + 15 * MINUTE));
        assert_eq!(selection.mode(), Mode::TunnelOnly);
        assert_eq!(selection.remaining(start + 15 * MINUTE), None);
        assert!(!selection.expire(start + 16 * MINUTE));
    }

    #[test]
    fn remaining_time_never_goes_below_zero() {
        let start = Instant::now();
        let selection = normal(1, start);
        assert_eq!(
            selection.remaining(start + 2 * MINUTE),
            Some(Remaining::Time(Duration::ZERO))
        );
    }

    #[test]
    fn zero_minutes_lasts_until_a_reset() {
        let start = Instant::now();
        let mut selection = normal(0, start);
        assert_eq!(
            selection.remaining(start + 1000 * MINUTE),
            Some(Remaining::UntilReset)
        );
        assert!(!selection.expire(start + 1000 * MINUTE));
        assert!(selection.reset());
        assert_eq!(selection.mode(), Mode::TunnelOnly);
    }

    #[test]
    fn a_reset_ends_normal_internet_and_keeps_proxy_mode() {
        let now = Instant::now();
        let mut selection = normal(60, now);
        assert!(selection.reset());
        assert_eq!(selection, Selection::default());

        let mut selection = Selection::default();
        selection.choose(Choice::Proxy, false, now).unwrap();
        assert!(!selection.reset());
        assert_eq!(selection.mode(), Mode::Proxy);

        let mut selection = Selection::default();
        assert!(!selection.reset());
    }

    #[test]
    fn a_new_choice_replaces_the_timer() {
        let start = Instant::now();
        let mut selection = normal(15, start);
        selection
            .choose(Choice::Normal { minutes: 60 }, true, start + 10 * MINUTE)
            .unwrap();
        assert_eq!(
            selection.remaining(start + 10 * MINUTE),
            Some(Remaining::Time(60 * MINUTE))
        );

        selection.choose(Choice::Proxy, false, start).unwrap();
        selection
            .choose(Choice::Normal { minutes: 0 }, true, start)
            .unwrap();
        assert!(!selection.expire(start + 100 * MINUTE));
    }

    #[test]
    fn too_long_normal_internet_is_refused() {
        let now = Instant::now();
        let mut selection = Selection::default();
        assert_eq!(
            selection.choose(
                Choice::Normal {
                    minutes: MAX_DURATION_MIN + 1
                },
                true,
                now
            ),
            Err(Refusal::BadRequest)
        );
        assert_eq!(selection, Selection::default());
        assert_eq!(
            selection.choose(
                Choice::Normal {
                    minutes: MAX_DURATION_MIN
                },
                true,
                now
            ),
            Ok(())
        );
    }
}
