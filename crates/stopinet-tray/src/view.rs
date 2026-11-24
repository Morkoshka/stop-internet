//! What the tray shows: the color of the icon, the tooltip and the menu, in
//! Russian or English (see [`Lang`]). No system calls, so all of it is
//! covered by unit tests.
//!
//! The menu:
//!
//! ```text
//! Tunnel only                 state, two lines
//! internet through the VPN
//! ──────────────────
//! ✓ Automatic                 follow the system proxy
//! ● Tunnel only               the mode, as the service reports it
//!   Proxy
//!   Normal internet  >        one item per configured duration
//! ──────────────────
//!   Service log
//!   Close icon
//! ```

use stopinet_core::control::{Choice, Refusal, Remaining};
use stopinet_core::policy::{Mode, TunnelState};
use stopinet_core::protocol::Status;
use stopinet_win::ClientError;

use crate::lang::Lang;

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
pub use stopinet_icon::Color;

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
    pub fn lines(&self, lang: Lang) -> (&'static str, String) {
        let status = match self {
            Self::Status(status) => status,
            Self::Unreachable(problem) => {
                let (title, detail) = problem_lines(*problem, lang);
                return (title, detail.into());
            }
        };
        let t = |russian, english| lang.pick(russian, english);
        let through_vpn = t("интернет через VPN", "internet through the VPN");
        let (title, detail) = match (status.mode, status.tunnel, status.left) {
            (Mode::TunnelOnly, TunnelState::Up, _) => (TUNNEL_ONLY, through_vpn.into()),
            (Mode::TunnelOnly, TunnelState::Down, _) => (
                TUNNEL_ONLY,
                t(
                    "туннеля нет, интернет закрыт",
                    "no tunnel, internet blocked",
                )
                .into(),
            ),
            (Mode::Proxy, TunnelState::Up, _) => (PROXY, through_vpn.into()),
            (Mode::Proxy, TunnelState::Down, _) => (
                PROXY,
                t(
                    "открыт только прокси клиента",
                    "only the client's proxy is open",
                )
                .into(),
            ),
            (Mode::Normal, _, Some(Remaining::Time(left))) => (OFF, left_text(left, lang)),
            (Mode::Normal, _, _) => (
                OFF,
                t("до перезагрузки или сна", "until reboot or sleep").into(),
            ),
        };
        (lang.pick(title.0, title.1), detail)
    }

    /// Tooltip of the icon.
    pub fn tooltip(&self, lang: Lang) -> String {
        let (title, detail) = self.lines(lang);
        format!("stop-internet\n{title}\n{detail}")
    }

    /// The menu; `follow` says whether the mode follows the system proxy.
    pub fn menu(&self, follow: bool, lang: Lang) -> Vec<Entry> {
        let (mode, durations, enabled) = match self {
            Self::Status(status) => (Some(status.mode), status.durations.as_slice(), true),
            Self::Unreachable(_) => (None, &[][..], false),
        };
        let t = |(russian, english): (&str, &str)| String::from(lang.pick(russian, english));
        let item = |label: (&str, &str), choice: Choice| Entry::Item {
            label: t(label),
            action: Action::Choose(choice),
            checked: mode == Some(choice.mode()),
            enabled,
        };
        let normal = durations
            .iter()
            .map(|&minutes| Entry::Item {
                label: duration_label(minutes, lang),
                action: Action::Choose(Choice::Normal { minutes }),
                checked: false,
                enabled,
            })
            .collect::<Vec<_>>();
        let (title, detail) = self.lines(lang);
        vec![
            Entry::Text(title.into()),
            Entry::Text(detail),
            Entry::Separator,
            Entry::Item {
                label: t(("Автоматически", "Automatic")),
                action: Action::FollowProxy(!follow),
                checked: follow,
                enabled,
            },
            item(TUNNEL_ONLY, Choice::TunnelOnly),
            item(PROXY, Choice::Proxy),
            Entry::Submenu {
                label: t(("Обычный интернет", "Normal internet")),
                checked: mode == Some(Mode::Normal),
                enabled: enabled && !normal.is_empty(),
                entries: normal,
            },
            Entry::Separator,
            Entry::Item {
                label: t(("Журнал службы", "Service log")),
                action: Action::OpenLog,
                checked: false,
                enabled: true,
            },
            Entry::Item {
                label: t(("Закрыть значок", "Close icon")),
                action: Action::Close,
                checked: false,
                enabled: true,
            },
        ]
    }
}

/// Names that the state lines and the menu share, in Russian and English.
const TUNNEL_ONLY: (&str, &str) = ("Только туннель", "Tunnel only");
const PROXY: (&str, &str) = ("Прокси", "Proxy");
const OFF: (&str, &str) = ("Защита выключена", "Protection off");

/// The state lines when the service cannot be asked.
fn problem_lines(problem: Problem, lang: Lang) -> (&'static str, &'static str) {
    let (russian, english) = match problem {
        Problem::NotInstalled => (
            ("Служба не установлена", "установите stop-internet"),
            ("Service not installed", "install stop-internet"),
        ),
        Problem::NotRunning => (
            ("Служба остановлена", "запустится после перезагрузки"),
            ("Service stopped", "starts again after a reboot"),
        ),
        Problem::OldService => (
            ("Служба старой версии", "установите stop-internet заново"),
            ("Old service version", "install stop-internet again"),
        ),
        Problem::Impostor => (
            ("Канал службы занят", "другой программой"),
            ("Service pipe taken", "by another program"),
        ),
        Problem::NoAnswer => (
            ("Служба не отвечает", "проверка раз в секунду"),
            ("Service not answering", "checking once a second"),
        ),
    };
    match lang {
        Lang::Russian => russian,
        Lang::English => english,
    }
}

/// A full sentence for a message box.
pub fn problem_text(problem: Problem, lang: Lang) -> &'static str {
    let (russian, english) = match problem {
        Problem::NotInstalled => (
            "Служба stop-internet не установлена",
            "The stop-internet service is not installed",
        ),
        Problem::NotRunning => (
            "Служба stop-internet остановлена",
            "The stop-internet service is stopped",
        ),
        Problem::OldService => (
            "Служба stop-internet старой версии: установите её заново",
            "The stop-internet service is an older version: install it again",
        ),
        Problem::Impostor => (
            "Канал службы занят другой программой",
            "The pipe of the service is taken by another program",
        ),
        Problem::NoAnswer => (
            "Служба stop-internet не отвечает",
            "The stop-internet service does not answer",
        ),
    };
    lang.pick(russian, english)
}

pub fn refusal_text(refusal: Refusal, lang: Lang) -> &'static str {
    let (russian, english) = match refusal {
        Refusal::NotElevated => (
            "Для обычного интернета нужны права администратора.",
            "Normal internet needs administrator rights.",
        ),
        Refusal::BadRequest => (
            "Служба не приняла запрос.",
            "The service did not accept the request.",
        ),
        Refusal::Unavailable => (
            "Служба не ответила вовремя, попробуйте ещё раз.",
            "The service did not answer in time, try again.",
        ),
    };
    lang.pick(russian, english)
}

/// "На 15 минут", "На 1 час", "До перезагрузки или сна"; "For 15 minutes",
/// "For 1 hour", "Until reboot or sleep".
pub fn duration_label(minutes: u32, lang: Lang) -> String {
    match (lang, minutes) {
        (Lang::Russian, 0) => "До перезагрузки или сна".into(),
        (Lang::English, 0) => "Until reboot or sleep".into(),
        (Lang::Russian, m) if m % 60 == 0 => {
            let hours = m / 60;
            format!("На {hours} {}", plural(hours, "час", "часа", "часов"))
        }
        (Lang::Russian, m) => format!("На {m} {}", plural(m, "минуту", "минуты", "минут")),
        (Lang::English, m) if m % 60 == 0 => {
            let hours = m / 60;
            format!("For {hours} hour{}", if hours == 1 { "" } else { "s" })
        }
        (Lang::English, m) => format!("For {m} minute{}", if m == 1 { "" } else { "s" }),
    }
}

/// "ещё 14 мин", "ещё 1 ч 5 мин"; "14 min left", "1 h 5 min left";
/// rounded up to a whole minute.
fn left_text(left: std::time::Duration, lang: Lang) -> String {
    let minutes = left.as_secs().div_ceil(60);
    let (h_unit, m_unit) = (lang.pick("ч", "h"), lang.pick("мин", "min"));
    let time = match (minutes / 60, minutes % 60) {
        (0, m) => format!("{m} {m_unit}"),
        (h, 0) => format!("{h} {h_unit}"),
        (h, m) => format!("{h} {h_unit} {m} {m_unit}"),
    };
    match lang {
        Lang::Russian => format!("ещё {time}"),
        Lang::English => format!("{time} left"),
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

    const LANGS: [Lang; 2] = [Lang::Russian, Lang::English];
    use Lang::{English, Russian};

    fn status(mode: Mode, tunnel: TunnelState, left: Option<Remaining>) -> View {
        View::Status(Status {
            mode,
            tunnel,
            left,
            durations: vec![15, 60, 0],
        })
    }

    fn every_view() -> Vec<View> {
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
            Some(Remaining::Time(Duration::from_secs(1439 * 60 + 1))),
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
        views
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
        assert_eq!(
            view.lines(Russian),
            ("Защита выключена", "ещё 14 мин".into())
        );
        assert_eq!(
            view.tooltip(Russian),
            "stop-internet\nЗащита выключена\nещё 14 мин"
        );
        assert_eq!(
            view.lines(English),
            ("Protection off", "14 min left".into())
        );
    }

    #[test]
    fn state_lines_are_short_to_keep_the_menu_narrow() {
        for lang in LANGS {
            for view in every_view() {
                let (title, detail) = view.lines(lang);
                assert!(title.chars().count() <= 32, "{title}");
                assert!(detail.chars().count() <= 32, "{detail}");
            }
        }
    }

    #[test]
    fn tooltip_fits_the_notification_area() {
        for lang in LANGS {
            for view in every_view() {
                // szTip holds 128 UTF-16 units with the final NUL.
                assert!(view.tooltip(lang).encode_utf16().count() < 128, "{view:?}");
            }
        }
    }

    #[test]
    fn every_language_has_its_own_words() {
        for view in every_view() {
            assert_ne!(view.lines(Russian), view.lines(English), "{view:?}");
            let (title, detail) = view.lines(English);
            assert!(title.is_ascii() && detail.is_ascii(), "{view:?}");
        }
        let labels = |lang| -> Vec<String> {
            status(Mode::TunnelOnly, TunnelState::Up, None)
                .menu(true, lang)
                .into_iter()
                .filter_map(|entry| match entry {
                    Entry::Item { label, .. } | Entry::Submenu { label, .. } => Some(label),
                    _ => None,
                })
                .collect()
        };
        assert_eq!(
            labels(English),
            [
                "Automatic",
                "Tunnel only",
                "Proxy",
                "Normal internet",
                "Service log",
                "Close icon"
            ]
        );
        assert_eq!(
            labels(Russian),
            [
                "Автоматически",
                "Только туннель",
                "Прокси",
                "Обычный интернет",
                "Журнал службы",
                "Закрыть значок"
            ]
        );
        for problem in [Problem::NotInstalled, Problem::Impostor] {
            assert!(problem_text(problem, English).is_ascii());
            assert!(!problem_text(problem, Russian).is_ascii());
        }
        for refusal in [
            Refusal::NotElevated,
            Refusal::BadRequest,
            Refusal::Unavailable,
        ] {
            assert!(refusal_text(refusal, English).is_ascii());
            assert!(!refusal_text(refusal, Russian).is_ascii());
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
        let menu = status(Mode::Proxy, TunnelState::Up, None).menu(false, Russian);
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
        let on = view.menu(true, Russian);
        assert_eq!(checked(&on), ["Автоматически", "Только туннель"]);
        assert_eq!(follow_action(&on), Some(Action::FollowProxy(false)));
        let off = view.menu(false, English);
        assert_eq!(checked(&off), ["Tunnel only"]);
        assert_eq!(follow_action(&off), Some(Action::FollowProxy(true)));
    }

    #[test]
    fn without_the_service_only_the_log_and_close_work() {
        let menu = View::Unreachable(Problem::NotRunning).menu(true, Russian);
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
        let ru = |minutes| duration_label(minutes, Russian);
        assert_eq!(ru(15), "На 15 минут");
        assert_eq!(ru(1), "На 1 минуту");
        assert_eq!(ru(2), "На 2 минуты");
        assert_eq!(ru(11), "На 11 минут");
        assert_eq!(ru(21), "На 21 минуту");
        assert_eq!(ru(90), "На 90 минут");
        assert_eq!(ru(60), "На 1 час");
        assert_eq!(ru(120), "На 2 часа");
        assert_eq!(ru(300), "На 5 часов");
        assert_eq!(ru(1440), "На 24 часа");
        assert_eq!(ru(0), "До перезагрузки или сна");

        let en = |minutes| duration_label(minutes, English);
        assert_eq!(en(15), "For 15 minutes");
        assert_eq!(en(1), "For 1 minute");
        assert_eq!(en(90), "For 90 minutes");
        assert_eq!(en(60), "For 1 hour");
        assert_eq!(en(120), "For 2 hours");
        assert_eq!(en(0), "Until reboot or sleep");
    }

    #[test]
    fn time_left_is_rounded_up() {
        let ru = |seconds| left_text(Duration::from_secs(seconds), Russian);
        assert_eq!(ru(1), "ещё 1 мин");
        assert_eq!(ru(60), "ещё 1 мин");
        assert_eq!(ru(3600), "ещё 1 ч");
        assert_eq!(ru(3601), "ещё 1 ч 1 мин");
        let en = |seconds| left_text(Duration::from_secs(seconds), English);
        assert_eq!(en(1), "1 min left");
        assert_eq!(en(3600), "1 h left");
        assert_eq!(en(3601), "1 h 1 min left");
    }
}
