//! Firewall policy model.
//!
//! [`Policy::build`] turns the configuration, the selected [`Mode`] and the
//! observed [`TunnelState`] into an ordered list of abstract rules. The
//! service maps every rule to Windows Filtering Platform filters in its own
//! sublayer: earlier rules get higher weights, and the first matching rule
//! decides.
//!
//! Invariant: the persistent part of a policy never depends on the mode or
//! on the tunnel. The Base Filtering Engine enforces it on its own after a
//! reboot or a crash of the service, so it must always be the safe baseline
//! that blocks everything except a few essentials.

use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use crate::config::Config;

/// Process of the Windows DNS client: the DNS Client service runs in
/// `svchost.exe` and sends the queries of all programs that use the system
/// resolver.
pub const SYSTEM_DNS_APP: &str = r"C:\Windows\System32\svchost.exe";

/// Protection mode selected by the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Internet only through the tunnel. Active after every boot and wake-up.
    TunnelOnly,
    /// Like [`Mode::TunnelOnly`], and the proxy core of the VPN client may
    /// reach the network directly, so the client's system proxy works
    /// without TUN.
    Proxy,
    /// Protection is off.
    Normal,
}

impl Mode {
    /// All modes, for exhaustive checks.
    pub const ALL: [Self; 3] = [Self::TunnelOnly, Self::Proxy, Self::Normal];

    /// Mode after the machine wakes up from sleep or hibernation, or after a
    /// user logs on: "normal internet" never survives it, the protected
    /// modes stay. A service start always begins with [`Mode::TunnelOnly`].
    pub fn after_reset(self) -> Self {
        match self {
            Self::Normal => Self::TunnelOnly,
            protected => protected,
        }
    }

    /// Word used on the command line and in the named pipe protocol.
    pub fn word(self) -> &'static str {
        match self {
            Self::TunnelOnly => "tunnel",
            Self::Proxy => "proxy",
            Self::Normal => "normal",
        }
    }
}

impl FromStr for Mode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tunnel" => Ok(Self::TunnelOnly),
            "proxy" => Ok(Self::Proxy),
            "normal" => Ok(Self::Normal),
            other => Err(format!(
                "unknown mode '{other}', expected tunnel, proxy or normal"
            )),
        }
    }
}

/// State of the tunnel adapter as observed by the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TunnelState {
    /// The adapter exists and is operational.
    Up,
    /// The adapter is missing or not operational.
    Down,
}

impl TunnelState {
    /// All states, for exhaustive checks.
    pub const ALL: [Self; 2] = [Self::Up, Self::Down];

    /// Word used on the command line and in the named pipe protocol.
    pub fn word(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
        }
    }
}

impl FromStr for TunnelState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "up" => Ok(Self::Up),
            "down" => Ok(Self::Down),
            other => Err(format!(
                "unknown tunnel state '{other}', expected up or down"
            )),
        }
    }
}

/// Lifetime of a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Kept by the Base Filtering Engine across reboots and service crashes.
    Persistent,
    /// Exists only while the service is running.
    Session,
}

/// Decision of a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Let the traffic through.
    Permit,
    /// Drop the traffic.
    Block,
}

/// Traffic matched by a rule.
///
/// Unless stated otherwise a matcher covers IPv4 and IPv6, outbound
/// connections and inbound accepts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Matcher {
    /// Everything, including forwarded traffic.
    All,
    /// The loopback interface.
    Loopback,
    /// DHCPv4 (UDP 68 to 67) and DHCPv6 (UDP 546 to 547).
    Dhcp,
    /// IPv6 neighbor discovery: ICMPv6 types 133 to 137.
    NeighborDiscovery,
    /// Any traffic on the tunnel adapter with this interface alias.
    TunnelInterface(String),
    /// Outbound packets with an address of the tunnel adapter with this
    /// interface alias that leave through another interface, loopback
    /// excluded. Windows checks a connection once, when it opens: one opened
    /// through the tunnel keeps its address and goes on sending when the
    /// routes of the tunnel go away, after a wake-up for example, and its
    /// packets then take the physical adapter. This matcher looks at every
    /// packet.
    TunnelAddressElsewhere(String),
    /// Any traffic of the process with this image path, on any interface.
    App(PathBuf),
    /// Private, link-local and multicast ranges, except DNS.
    Lan,
    /// Outbound DNS queries (remote port 53, UDP and TCP) of the Windows
    /// DNS client, [`SYSTEM_DNS_APP`]. It resolves names for every program
    /// that uses the system resolver.
    SystemDns,
}

/// One rule of a policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rule {
    /// What happens to matching traffic.
    pub action: Action,
    /// Which traffic the rule matches.
    pub matcher: Matcher,
    /// How long the rule lives.
    pub scope: Scope,
}

impl Rule {
    fn persistent(action: Action, matcher: Matcher) -> Self {
        Self {
            action,
            matcher,
            scope: Scope::Persistent,
        }
    }

    fn session(action: Action, matcher: Matcher) -> Self {
        Self {
            action,
            matcher,
            scope: Scope::Session,
        }
    }
}

/// Ordered list of rules; earlier rules take precedence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    rules: Vec<Rule>,
}

impl Policy {
    /// Builds the policy for a mode and a tunnel state.
    pub fn build(config: &Config, mode: Mode, tunnel: TunnelState) -> Self {
        let mut rules = Vec::new();

        match mode {
            Mode::Normal => {
                // Overrides the baseline without removing it: if the service
                // stops or the machine reboots, the baseline blocks again.
                rules.push(Rule::session(Action::Permit, Matcher::All));
            }
            Mode::TunnelOnly | Mode::Proxy => {
                if tunnel == TunnelState::Up {
                    rules.push(Rule::session(
                        Action::Block,
                        Matcher::TunnelAddressElsewhere(config.tunnel.adapter_name.clone()),
                    ));
                    rules.push(Rule::session(
                        Action::Permit,
                        Matcher::TunnelInterface(config.tunnel.adapter_name.clone()),
                    ));
                    rules.extend(permit_apps(&config.client.tunnel_apps, Scope::Session));
                }
                if mode == Mode::Proxy {
                    rules.extend(permit_apps(&config.client.proxy_apps, Scope::Session));
                    // Without TUN the proxy core finds its server through the
                    // system resolver, so DNS has to work. The router and the
                    // provider see the names programs look up; their traffic
                    // stays blocked unless it goes through the proxy. With the
                    // tunnel up, DNS goes through the tunnel, and this rule
                    // would let Windows send the same queries to the router
                    // as well.
                    if tunnel == TunnelState::Down {
                        rules.push(Rule::session(Action::Permit, Matcher::SystemDns));
                    }
                }
            }
        }

        rules.extend(baseline(config));
        Self { rules }
    }

    /// All rules, highest precedence first.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Rules kept by the Base Filtering Engine.
    pub fn persistent(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(|r| r.scope == Scope::Persistent)
    }

    /// Rules that exist only while the service runs.
    pub fn session(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(|r| r.scope == Scope::Session)
    }

    /// Whether the policy explicitly permits this traffic.
    pub fn permits(&self, matcher: &Matcher) -> bool {
        self.rules
            .iter()
            .filter(|r| r.action == Action::Permit)
            .any(|r| r.matcher == Matcher::All || &r.matcher == matcher)
    }
}

/// Rules that do not depend on mode or tunnel state.
fn baseline(config: &Config) -> Vec<Rule> {
    let mut rules = vec![
        Rule::persistent(Action::Permit, Matcher::Loopback),
        Rule::persistent(Action::Permit, Matcher::Dhcp),
        Rule::persistent(Action::Permit, Matcher::NeighborDiscovery),
    ];
    // Apps excluded from the tunnel keep working when the tunnel drops.
    rules.extend(permit_apps(&config.direct.apps, Scope::Persistent));
    if config.network.allow_lan {
        rules.push(Rule::persistent(Action::Permit, Matcher::Lan));
    }
    rules.push(Rule::persistent(Action::Block, Matcher::All));
    rules
}

fn permit_apps(apps: &[PathBuf], scope: Scope) -> impl Iterator<Item = Rule> {
    apps.iter().map(move |app| Rule {
        action: Action::Permit,
        matcher: Matcher::App(app.clone()),
        scope,
    })
}

impl fmt::Display for Matcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => f.write_str("all traffic"),
            Self::Loopback => f.write_str("loopback"),
            Self::Dhcp => f.write_str("DHCP and DHCPv6"),
            Self::NeighborDiscovery => f.write_str("IPv6 neighbor discovery"),
            Self::TunnelInterface(name) => write!(f, "tunnel adapter \"{name}\""),
            Self::TunnelAddressElsewhere(name) => {
                write!(
                    f,
                    "addresses of tunnel adapter \"{name}\" on other interfaces"
                )
            }
            Self::App(path) => write!(f, "app {}", path.display()),
            Self::Lan => f.write_str("local network (DNS excluded)"),
            Self::SystemDns => f.write_str("Windows DNS client (svchost.exe, port 53)"),
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action = match self.action {
            Action::Permit => "permit",
            Action::Block => "block",
        };
        let scope = match self.scope {
            Scope::Persistent => "persistent",
            Scope::Session => "session",
        };
        write!(f, "{action:<6}  {scope:<10}  {}", self.matcher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAEMON: &str = r"C:\vpn\daemon.exe";
    const CORE: &str = r"C:\vpn\core.exe";
    const GAME: &str = r"C:\games\game.exe";

    fn config(allow_lan: bool) -> Config {
        Config::from_toml(&format!(
            r#"
[tunnel]
adapter_name = "vpn-tun"
driver = "Wintun"

[client]
tunnel_apps = ['{DAEMON}']
proxy_apps = ['{CORE}']

[direct]
apps = ['{GAME}']

[network]
allow_lan = {allow_lan}
"#
        ))
        .unwrap()
    }

    fn app(path: &str) -> Matcher {
        Matcher::App(PathBuf::from(path))
    }

    fn tunnel() -> Matcher {
        Matcher::TunnelInterface("vpn-tun".into())
    }

    fn all_states() -> impl Iterator<Item = (Mode, TunnelState)> {
        Mode::ALL
            .into_iter()
            .flat_map(|m| TunnelState::ALL.into_iter().map(move |t| (m, t)))
    }

    #[test]
    fn persistent_rules_are_the_same_in_every_state() {
        let config = config(false);
        let reference: Vec<Rule> = Policy::build(&config, Mode::TunnelOnly, TunnelState::Down)
            .persistent()
            .cloned()
            .collect();
        for (mode, state) in all_states() {
            let persistent: Vec<Rule> = Policy::build(&config, mode, state)
                .persistent()
                .cloned()
                .collect();
            assert_eq!(persistent, reference, "{mode:?} / {state:?}");
        }
    }

    #[test]
    fn last_rule_always_blocks_everything() {
        let config = config(true);
        for (mode, state) in all_states() {
            let policy = Policy::build(&config, mode, state);
            assert_eq!(
                policy.rules().last(),
                Some(&Rule::persistent(Action::Block, Matcher::All)),
                "{mode:?} / {state:?}"
            );
        }
    }

    #[test]
    fn tunnel_down_blocks_the_client() {
        let policy = Policy::build(&config(false), Mode::TunnelOnly, TunnelState::Down);
        assert!(!policy.permits(&tunnel()));
        assert!(!policy.permits(&app(DAEMON)));
        assert!(!policy.permits(&app(CORE)));
        assert_eq!(policy.session().count(), 0);
    }

    #[test]
    fn tunnel_up_permits_the_tunnel_and_its_daemon_only() {
        let policy = Policy::build(&config(false), Mode::TunnelOnly, TunnelState::Up);
        assert!(policy.permits(&tunnel()));
        assert!(policy.permits(&app(DAEMON)));
        assert!(!policy.permits(&app(CORE)));
    }

    #[test]
    fn a_protected_mode_keeps_tunnel_addresses_on_the_tunnel() {
        let guard = Rule::session(
            Action::Block,
            Matcher::TunnelAddressElsewhere("vpn-tun".into()),
        );
        let config = config(false);
        for (mode, state) in all_states() {
            let policy = Policy::build(&config, mode, state);
            let expected = mode != Mode::Normal && state == TunnelState::Up;
            // First, so that nothing the tunnel permits comes before it.
            assert_eq!(
                policy.rules().first() == Some(&guard),
                expected,
                "{mode:?} / {state:?}"
            );
            assert_eq!(
                policy.rules().contains(&guard),
                expected,
                "{mode:?} / {state:?}"
            );
        }
    }

    #[test]
    fn proxy_mode_permits_the_core_without_tunnel() {
        let policy = Policy::build(&config(false), Mode::Proxy, TunnelState::Down);
        assert!(policy.permits(&app(CORE)));
        assert!(!policy.permits(&app(DAEMON)));
        assert!(!policy.permits(&tunnel()));
    }

    #[test]
    fn only_proxy_mode_without_the_tunnel_lets_the_system_resolver_out() {
        let config = config(false);
        let proxy = Policy::build(&config, Mode::Proxy, TunnelState::Down);
        assert!(proxy.permits(&Matcher::SystemDns));
        assert!(
            proxy
                .session()
                .any(|r| r.matcher == Matcher::SystemDns && r.action == Action::Permit)
        );
        // With the tunnel up, DNS goes through the tunnel only.
        let proxy = Policy::build(&config, Mode::Proxy, TunnelState::Up);
        assert!(!proxy.permits(&Matcher::SystemDns));
        for state in TunnelState::ALL {
            let tunnel = Policy::build(&config, Mode::TunnelOnly, state);
            assert!(!tunnel.permits(&Matcher::SystemDns), "{state:?}");
        }
    }

    #[test]
    fn direct_apps_keep_working_when_the_tunnel_drops() {
        let config = config(false);
        for (mode, state) in all_states() {
            assert!(
                Policy::build(&config, mode, state).permits(&app(GAME)),
                "{mode:?} / {state:?}"
            );
        }
    }

    #[test]
    fn normal_mode_overrides_but_keeps_the_baseline() {
        let policy = Policy::build(&config(false), Mode::Normal, TunnelState::Down);
        assert_eq!(
            policy.rules().first(),
            Some(&Rule::session(Action::Permit, Matcher::All))
        );
        assert!(policy.persistent().any(|r| r.action == Action::Block));
    }

    #[test]
    fn lan_is_closed_unless_enabled() {
        let closed = Policy::build(&config(false), Mode::TunnelOnly, TunnelState::Up);
        let open = Policy::build(&config(true), Mode::TunnelOnly, TunnelState::Up);
        assert!(!closed.permits(&Matcher::Lan));
        assert!(open.permits(&Matcher::Lan));
    }

    #[test]
    fn a_reset_ends_normal_internet_only() {
        assert_eq!(Mode::Normal.after_reset(), Mode::TunnelOnly);
        assert_eq!(Mode::TunnelOnly.after_reset(), Mode::TunnelOnly);
        assert_eq!(Mode::Proxy.after_reset(), Mode::Proxy);
    }

    #[test]
    fn modes_and_states_parse_from_cli_words() {
        assert_eq!("tunnel".parse::<Mode>(), Ok(Mode::TunnelOnly));
        assert_eq!("proxy".parse::<Mode>(), Ok(Mode::Proxy));
        assert_eq!("normal".parse::<Mode>(), Ok(Mode::Normal));
        assert!("off".parse::<Mode>().is_err());
        assert_eq!("up".parse::<TunnelState>(), Ok(TunnelState::Up));
        assert!("maybe".parse::<TunnelState>().is_err());
    }

    #[test]
    fn words_parse_back() {
        for mode in Mode::ALL {
            assert_eq!(mode.word().parse::<Mode>(), Ok(mode));
        }
        for state in TunnelState::ALL {
            assert_eq!(state.word().parse::<TunnelState>(), Ok(state));
        }
    }
}
