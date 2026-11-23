//! Automatic choice between the protected modes, following the system proxy
//! of Windows. No system calls, so all of it is covered by unit tests; the
//! settings are read in [`crate::proxy`].
//!
//! A VPN client in system proxy mode, Happ for example, points the proxy of
//! the user at its own core on this computer. While it does, proxy mode is
//! needed; otherwise tunnel-only mode is the right one. The tray keeps the
//! mode in line with that, but it never selects "normal internet" and
//! leaves it alone while it lasts: when it ends, the service returns to
//! tunnel-only mode and the tray picks the right protected mode again.

use std::net::IpAddr;

use stopinet_core::control::Choice;
use stopinet_core::policy::Mode;

use crate::view::View;

/// The proxy settings of the user, as Windows hands them out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxySettings {
    /// The manual proxy, if it is turned on: `host:port`, or proxies per
    /// scheme such as `http=host:port;https=host:port`.
    pub proxy: Option<String>,
    /// The address of a proxy script, if it is turned on.
    pub script: Option<String>,
}

/// Where the system proxy sends programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemProxy {
    /// To a proxy on this computer, such as the core of a VPN client.
    Local,
    /// Elsewhere, or there is no proxy.
    NotLocal,
}

impl SystemProxy {
    /// Reads the settings. A proxy or a proxy script on a loopback address
    /// makes it [`SystemProxy::Local`].
    pub fn of(settings: &ProxySettings) -> Self {
        let proxies = settings
            .proxy
            .iter()
            .flat_map(|list| list.split(|c: char| c == ';' || c.is_whitespace()))
            .filter(|entry| !entry.is_empty())
            .map(|entry| entry.split_once('=').map_or(entry, |(_, proxy)| proxy));
        let script = settings.script.as_deref().filter(|url| url.contains("://"));
        if proxies
            .chain(script)
            .any(|address| is_loopback(host(address)))
        {
            Self::Local
        } else {
            Self::NotLocal
        }
    }

    /// The protected mode that fits.
    pub fn choice(self) -> Choice {
        match self {
            Self::Local => Choice::Proxy,
            Self::NotLocal => Choice::TunnelOnly,
        }
    }
}

/// What the tray should ask the service for: `None` when nothing has to
/// change, the tray does not follow the proxy, the proxy or the service is
/// unknown, or "normal internet" is on.
pub fn next_step(follow: bool, view: &View, proxy: Option<SystemProxy>) -> Option<Choice> {
    let View::Status(status) = view else {
        return None;
    };
    if !follow {
        return None;
    }
    let wanted = proxy?.choice();
    match status.mode {
        Mode::Normal => None,
        mode if mode == wanted.mode() => None,
        _ => Some(wanted),
    }
}

/// The host of `http://user@host:port/path`, `host:port`, `[::1]:8080` or
/// a bare host.
fn host(address: &str) -> &str {
    let address = address.split_once("://").map_or(address, |(_, rest)| rest);
    let authority = address.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(host, _)| host);
    }
    match authority.split_once(':') {
        // A bare IPv6 address has more than one colon.
        Some((host, port)) if !port.contains(':') => host,
        _ => authority,
    }
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use stopinet_core::policy::TunnelState;
    use stopinet_core::protocol::Status;

    use super::*;
    use crate::view::Problem;

    fn manual(proxy: &str) -> SystemProxy {
        SystemProxy::of(&ProxySettings {
            proxy: Some(proxy.into()),
            script: None,
        })
    }

    fn script(url: &str) -> SystemProxy {
        SystemProxy::of(&ProxySettings {
            proxy: None,
            script: Some(url.into()),
        })
    }

    fn status(mode: Mode) -> View {
        View::Status(Status {
            mode,
            tunnel: TunnelState::Down,
            left: None,
            durations: vec![15, 60, 0],
        })
    }

    #[test]
    fn a_proxy_on_this_computer_is_local() {
        for proxy in [
            "127.0.0.1:10809",
            "127.0.0.2:8080",
            "localhost:8080",
            "LOCALHOST",
            "[::1]:8080",
            "::1",
            "http://127.0.0.1:10809",
            "socks=127.0.0.1:10808",
            "http=127.0.0.1:10809;https=127.0.0.1:10809",
            "http=127.0.0.1:10809 https=127.0.0.1:10809",
            // One local entry is enough: that traffic needs proxy mode.
            "ftp=198.51.100.7:21;http=127.0.0.1:10809",
        ] {
            assert_eq!(manual(proxy), SystemProxy::Local, "{proxy}");
        }
    }

    #[test]
    fn a_proxy_elsewhere_is_not_local() {
        for proxy in [
            "",
            "198.51.100.7:3128",
            "proxy.example.com:8080",
            "http=192.0.2.1:80;https=192.0.2.1:443",
            "[2001:db8::1]:8080",
            "2001:db8::1",
            // Only the host counts, not a port or a user name.
            "http://127.0.0.1@198.51.100.7:8080",
            "localhost.example.com:8080",
        ] {
            assert_eq!(manual(proxy), SystemProxy::NotLocal, "{proxy}");
        }
    }

    #[test]
    fn a_proxy_script_counts_by_its_host() {
        assert_eq!(script("http://127.0.0.1:10809/pac"), SystemProxy::Local);
        assert_eq!(script("http://localhost/proxy.pac"), SystemProxy::Local);
        assert_eq!(
            script("http://wpad.example.com/wpad.dat"),
            SystemProxy::NotLocal
        );
        assert_eq!(script("file:///C:/proxy.pac"), SystemProxy::NotLocal);
        assert_eq!(script("proxy.pac"), SystemProxy::NotLocal);
    }

    #[test]
    fn no_settings_means_no_local_proxy() {
        assert_eq!(
            SystemProxy::of(&ProxySettings::default()),
            SystemProxy::NotLocal
        );
    }

    #[test]
    fn the_mode_follows_the_proxy() {
        let local = Some(SystemProxy::Local);
        let not_local = Some(SystemProxy::NotLocal);
        assert_eq!(
            next_step(true, &status(Mode::TunnelOnly), local),
            Some(Choice::Proxy)
        );
        assert_eq!(
            next_step(true, &status(Mode::Proxy), not_local),
            Some(Choice::TunnelOnly)
        );
        assert_eq!(next_step(true, &status(Mode::Proxy), local), None);
        assert_eq!(next_step(true, &status(Mode::TunnelOnly), not_local), None);
    }

    #[test]
    fn normal_internet_is_never_touched() {
        for proxy in [SystemProxy::Local, SystemProxy::NotLocal] {
            assert_eq!(next_step(true, &status(Mode::Normal), Some(proxy)), None);
            assert_ne!(proxy.choice().mode(), Mode::Normal);
            assert!(!proxy.choice().lowers_protection());
        }
    }

    #[test]
    fn nothing_happens_without_the_setting_the_proxy_or_the_service() {
        let local = Some(SystemProxy::Local);
        assert_eq!(next_step(false, &status(Mode::TunnelOnly), local), None);
        assert_eq!(next_step(true, &status(Mode::TunnelOnly), None), None);
        assert_eq!(
            next_step(true, &View::Unreachable(Problem::NotRunning), local),
            None
        );
    }
}
