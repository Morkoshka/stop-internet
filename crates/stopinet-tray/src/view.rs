//! What the tray shows: the color of the icon, the tooltip and the menu, in
//! Russian. No system calls, so all of it is covered by unit tests.
//!
//! The menu:
//!
//! ```text
//! Только туннель            state, two lines
//! интернет через VPN
//! ──────────────────
//! ✓ Автоматически           follow the system proxy
//! ● Только туннель          the mode, as the service reports it
//!   Прокси
//!   Обычный интернет  >     one item per configured duration
//! ──────────────────
//!   Журнал службы
//!   Закрыть значок
//! ```

use stopinet_core::control::{Choice, Refusal, Remaining};
use stopinet_core::policy::{Mode, TunnelState};
use stopinet_core::protocol::Status;
use stopinet_win::ClientError;

/// What the tray knows about the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum View {
    /// The last answer of the service.
    Status(Status),
    /// The service could not be asked.
    Unreachable(Problem),
}

/// Why the service could not be asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    NotInstalled,
    NotRunning,
    /// The service runs without the named pipe: an older version.
    OldService,
    /// The pipe belongs to another program.
    Impostor,
    /// No answer, or an answer the tray does not understand.
    NoAnswer,
}

impl From<&ClientError> for Problem {
    fn from(error: &ClientError) -> Self {
        match error {
            ClientError::NotInstalled => Self::NotInstalled,
            ClientError::NotRunning => Self::NotRunning,
            ClientError::NoPipe => Self::OldService,
            ClientError::Impostor => Self::Impostor,
            _ => Self::NoAnswer,
        }
    }
}

/// Color of the icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    /// Protected, and the internet works through the VPN client.
    Green,
    /// Blocked: the tunnel is down in tunnel-only mode, or the service
    /// cannot be asked.
    Red,
    /// Protection is off.
    Grey,
}

/// What a menu item does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Switch the mode; normal internet goes through a UAC prompt. A
    /// protected mode chosen this way stops following the system proxy.
    Choose(Choice),
    /// Start or stop following the system proxy with the protected mode,
    /// see [`crate::auto`].
    FollowProxy(bool),
    /// Open the log of the service.
    OpenLog,
    /// Close the tray icon. Protection is not affected.
    Close,
}

/// One line of the menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// Grey text, not clickable.
    Text(String),
    Separator,
    Item {
        label: String,
        action: Action,
        /// Shown with a round mark for a mode, with a check mark otherwise.
        checked: bool,
        enabled: bool,
    },
    Submenu {
        label: String,
        checked: bool,
        enabled: bool,
        entries: Vec<Entry>,
    },
}

impl View {
    pub fn color(&self) -> Color {
        match self {
            Self::Status(status) => match (status.mode, status.tunnel) {
                (Mode::Normal, _) => Color::Grey,
                (Mode::TunnelOnly, TunnelState::Down) => Color::Red,
                // In proxy mode the proxy core of the client may go out
                // directly with or without the tunnel; whether it runs is
                // not checked.
                (Mode::TunnelOnly, TunnelState::Up) | (Mode::Proxy, _) => Color::Green,
            },
            Self::Unreachable(_) => Color::Red,
        }
    }

    /// Two short lines about the state, for the tooltip and the top of the
    /// menu: what holds and what it means now. Short lines keep the menu
    /// narrow.
    pub fn lines(&self) -> (&'static str, String) {
        let status = match self {
            Self::Status(status) => status,
            Self::Unreachable(problem) => {
                let (title, detail) = problem_lines(*problem);
                return (title, detail.into());
            }
        };
        match (status.mode, status.tunnel, status.left) {
            (Mode::TunnelOnly, TunnelState::Up, _) => {
                ("Только туннель", "интернет через VPN".into())
            }
            (Mode::TunnelOnly, TunnelState::Down, _) => {
                ("Только туннель", "туннеля нет, интернет закрыт".into())
            }
            (Mode::Proxy, TunnelState::Up, _) => ("Прокси", "интернет через VPN".into()),
            (Mode::Proxy, TunnelState::Down, _) => {
                ("Прокси", "открыт только прокси клиента".into())
            }
            (Mode::Normal, _, Some(Remaining::Time(left))) => ("Защита выключена", left_text(left)),
            (Mode::Normal, _, _) => ("Защита выключена", "до перезагрузки или сна".into()),
        }
    }

    /// Tooltip of the icon.
    pub fn tooltip(&self) -> String {
        let (title, detail) = self.lines();
        format!("stop-internet\n{title}\n{detail}")
    }

    /// The menu; `follow` says whether the mode follows the system proxy.
    pub fn menu(&self, follow: bool) -> Vec<Entry> {
        let (mode, durations, enabled) = match self {
            Self::Status(status) => (Some(status.mode), status.durations.as_slice(), true),
            Self::Unreachable(_) => (None, &[][..], false),
        };
        let item = |label: &str, choice: Choice| Entry::Item {
            label: label.into(),
            action: Action::Choose(choice),
            checked: mode == Some(choice.mode()),
            enabled,
        };
        let normal = durations
            .iter()
            .map(|&minutes| Entry::Item {
                label: duration_label(minutes),
                action: Action::Choose(Choice::Normal { minutes }),
                checked: false,
                enabled,
            })
            .collect::<Vec<_>>();
        let (title, detail) = self.lines();
        vec![
            Entry::Text(title.into()),
            Entry::Text(detail),
            Entry::Separator,
            Entry::Item {
                label: "Автоматически".into(),
                action: Action::FollowProxy(!follow),
                checked: follow,
                enabled,
            },
            item("Только туннель", Choice::TunnelOnly),
            item("Прокси", Choice::Proxy),
            Entry::Submenu {
                label: "Обычный интернет".into(),
                checked: mode == Some(Mode::Normal),
                enabled: enabled && !normal.is_empty(),
                entries: normal,
            },
            Entry::Separator,
            Entry::Item {
                label: "Журнал службы".into(),
                action: Action::OpenLog,
                checked: false,
                enabled: true,
            },
            Entry::Item {
                label: "Закрыть значок".into(),
                action: Action::Close,
                checked: false,
                enabled: true,
            },
        ]
    }
}

/// The state lines when the service cannot be asked.
fn problem_lines(problem: Problem) -> (&'static str, &'static str) {
    match problem {
        Problem::NotInstalled => ("Служба не установлена", "установите stop-internet"),
        Problem::NotRunning => ("Служба остановлена", "запустится после перезагрузки"),
        Problem::OldService => ("Служба старой версии", "установите stop-internet заново"),
        Problem::Impostor => ("Канал службы занят", "другой программой"),
        Problem::NoAnswer => ("Служба не отвечает", "проверка раз в секунду"),
    }
}

/// A full sentence for a message box.
pub fn problem_text(problem: Problem) -> &'static str {
    match problem {
        Problem::NotInstalled => "Служба stop-internet не установлена",
        Problem::NotRunning => "Служба stop-internet остановлена",
        Problem::OldService => "Служба stop-internet старой версии: установите её заново",
        Problem::Impostor => "Канал службы занят другой программой",
        Problem::NoAnswer => "Служба stop-internet не отвечает",
    }
}

pub fn refusal_text(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::NotElevated => "Для обычного интернета нужны права администратора.",
        Refusal::BadRequest => "Служба не приняла запрос.",
        Refusal::Unavailable => "Служба не ответила вовремя, попробуйте ещё раз.",
    }
}

/// "На 15 минут", "На 1 час", "До перезагрузки или сна".
pub fn duration_label(minutes: u32) -> String {
    match minutes {
        0 => "До перезагрузки или сна".into(),
        m if m % 60 == 0 => {
            let hours = m / 60;
            format!("На {hours} {}", plural(hours, "час", "часа", "часов"))
        }
        m => format!("На {m} {}", plural(m, "минуту", "минуты", "минут")),
    }
}

/// "ещё 14 мин", "ещё 1 ч 5 мин", rounded up to a whole minute.
fn left_text(left: std::time::Duration) -> String {
    let minutes = left.as_secs().div_ceil(60);
    match (minutes / 60, minutes % 60) {
        (0, m) => format!("ещё {m} мин"),
        (h, 0) => format!("ещё {h} ч"),
        (h, m) => format!("ещё {h} ч {m} мин"),
    }
}

/// Russian plural: 1 минуту, 2 минуты, 5 минут, 21 минуту, 11 минут.
fn plural(n: u32, one: &'static str, few: &'static str, many: &'static str) -> &'static str {
    match (n % 10, n % 100) {
        (1, rest) if rest != 11 => one,
        (2..=4, rest) if !(12..=14).contains(&rest) => few,
        _ => many,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn status(mode: Mode, tunnel: TunnelState, left: Option<Remaining>) -> View {
        View::Status(Status {
            mode,
            tunnel,
            left,
            durations: vec![15, 60, 0],
        })
    }

    #[test]
    fn colors_follow_the_state() {
        use Mode::*;
        use TunnelState::*;
        assert_eq!(status(TunnelOnly, Up, None).color(), Color::Green);
        assert_eq!(status(TunnelOnly, Down, None).color(), Color::Red);
        assert_eq!(status(Proxy, Up, None).color(), Color::Green);
        assert_eq!(status(Proxy, Down, None).color(), Color::Green);
        assert_eq!(
            status(Normal, Down, Some(Remaining::UntilReset)).color(),
            Color::Grey
        );
        assert_eq!(View::Unreachable(Problem::NotRunning).color(), Color::Red);
    }

    #[test]
    fn lines_show_the_time_left() {
        let view = status(
            Mode::Normal,
            TunnelState::Up,
            Some(Remaining::Time(Duration::from_secs(13 * 60 + 1))),
        );
        assert_eq!(view.lines(), ("Защита выключена", "ещё 14 мин".into()));
        assert_eq!(
            view.tooltip(),
            "stop-internet\nЗащита выключена\nещё 14 мин"
        );
    }

    #[test]
    fn state_lines_are_short_to_keep_the_menu_narrow() {
        let mut views = Vec::new();
        for mode in [Mode::TunnelOnly, Mode::Proxy] {
            for tunnel in [TunnelState::Up, TunnelState::Down] {
                views.push(status(mode, tunnel, None));
            }
        }
        views.push(status(
            Mode::Normal,
            TunnelState::Down,
            Some(Remaining::UntilReset),
        ));
        views.push(status(
            Mode::Normal,
            TunnelState::Down,
            Some(Remaining::Time(Duration::from_secs(1440 * 60))),
        ));
        for problem in [
            Problem::NotInstalled,
            Problem::NotRunning,
            Problem::OldService,
            Problem::Impostor,
            Problem::NoAnswer,
        ] {
            views.push(View::Unreachable(problem));
        }
        for view in views {
            let (title, detail) = view.lines();
            assert!(title.chars().count() <= 32, "{title}");
            assert!(detail.chars().count() <= 32, "{detail}");
        }
    }

    #[test]
    fn tooltip_fits_the_notification_area() {
        let views = [
            status(Mode::TunnelOnly, TunnelState::Down, None),
            status(Mode::Proxy, TunnelState::Down, None),
            status(Mode::Normal, TunnelState::Down, Some(Remaining::UntilReset)),
            View::Unreachable(Problem::OldService),
        ];
        for view in views {
            // szTip holds 128 UTF-16 units with the final NUL.
            assert!(view.tooltip().encode_utf16().count() < 128, "{view:?}");
        }
    }

    fn checked(menu: &[Entry]) -> Vec<&str> {
        menu.iter()
            .filter_map(|entry| match entry {
                Entry::Item {
                    label,
                    checked: true,
                    ..
                } => Some(label.as_str()),
                _ => None,
            })
            .collect()
    }

    fn follow_action(menu: &[Entry]) -> Option<Action> {
        menu.iter().find_map(|entry| match entry {
            Entry::Item {
                action: action @ Action::FollowProxy(_),
                ..
            } => Some(*action),
            _ => None,
        })
    }

    #[test]
    fn menu_marks_the_mode_and_offers_the_configured_durations() {
        let menu = status(Mode::Proxy, TunnelState::Up, None).menu(false);
        assert_eq!(checked(&menu), ["Прокси"]);

        let normal = menu
            .iter()
            .find_map(|entry| match entry {
                Entry::Submenu {
                    entries, enabled, ..
                } => Some((entries, *enabled)),
                _ => None,
            })
            .unwrap();
        assert!(normal.1);
        let actions: Vec<Action> = normal
            .0
            .iter()
            .filter_map(|entry| match entry {
                Entry::Item { action, .. } => Some(*action),
                _ => None,
            })
            .collect();
        assert_eq!(
            actions,
            [15, 60, 0].map(|minutes| Action::Choose(Choice::Normal { minutes }))
        );
    }

    #[test]
    fn the_automatic_choice_is_a_check_mark_that_toggles() {
        let view = status(Mode::TunnelOnly, TunnelState::Up, None);
        let on = view.menu(true);
        assert_eq!(checked(&on), ["Автоматически", "Только туннель"]);
        assert_eq!(follow_action(&on), Some(Action::FollowProxy(false)));
        let off = view.menu(false);
        assert_eq!(checked(&off), ["Только туннель"]);
        assert_eq!(follow_action(&off), Some(Action::FollowProxy(true)));
    }

    #[test]
    fn without_the_service_only_the_log_and_close_work() {
        let menu = View::Unreachable(Problem::NotRunning).menu(true);
        for entry in &menu {
            match entry {
                Entry::Item {
                    action: Action::Choose(_) | Action::FollowProxy(_),
                    enabled,
                    ..
                }
                | Entry::Submenu { enabled, .. } => assert!(!enabled, "{entry:?}"),
                Entry::Item { enabled, .. } => assert!(enabled, "{entry:?}"),
                _ => {}
            }
        }
        assert_eq!(
            menu.first(),
            Some(&Entry::Text("Служба остановлена".into()))
        );
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(duration_label(15), "На 15 минут");
        assert_eq!(duration_label(1), "На 1 минуту");
        assert_eq!(duration_label(2), "На 2 минуты");
        assert_eq!(duration_label(11), "На 11 минут");
        assert_eq!(duration_label(21), "На 21 минуту");
        assert_eq!(duration_label(90), "На 90 минут");
        assert_eq!(duration_label(60), "На 1 час");
        assert_eq!(duration_label(120), "На 2 часа");
        assert_eq!(duration_label(300), "На 5 часов");
        assert_eq!(duration_label(1440), "На 24 часа");
        assert_eq!(duration_label(0), "До перезагрузки или сна");
    }

    #[test]
    fn time_left_is_rounded_up() {
        assert_eq!(left_text(Duration::from_secs(1)), "ещё 1 мин");
        assert_eq!(left_text(Duration::from_secs(60)), "ещё 1 мин");
        assert_eq!(left_text(Duration::from_secs(3600)), "ещё 1 ч");
        assert_eq!(left_text(Duration::from_secs(3601)), "ещё 1 ч 1 мин");
    }
}
