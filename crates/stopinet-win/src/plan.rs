//! Translation of a [`Policy`] into concrete WFP filters.
//!
//! This module is pure: it only decides layers, conditions and weights. The
//! [`wfp`](crate::wfp) module turns the result into API calls.

use std::fmt;
use std::path::PathBuf;

use stopinet_core::policy::{Action, Matcher, Policy, Rule, SYSTEM_DNS_APP, Scope};

/// `FWP_CONDITION_FLAG_IS_LOOPBACK`.
pub const LOOPBACK_FLAG: u32 = 0x1;

const PROTOCOL_UDP: u8 = 17;
const PROTOCOL_ICMPV6: u8 = 58;
const DNS_PORT: u16 = 53;

/// Private, link-local, multicast and broadcast IPv4 ranges.
const LAN_V4: [([u8; 4], u8); 6] = [
    ([10, 0, 0, 0], 8),
    ([172, 16, 0, 0], 12),
    ([192, 168, 0, 0], 16),
    ([169, 254, 0, 0], 16),
    ([224, 0, 0, 0], 4),
    ([255, 255, 255, 255], 32),
];

/// Link-local, unique local and multicast IPv6 ranges.
const LAN_V6: [([u8; 16], u8); 3] = [
    ([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10),
    ([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 7),
    ([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8),
];

/// WFP layer a filter is attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Layer {
    /// `FWPM_LAYER_ALE_AUTH_CONNECT_V4`: outbound connections.
    ConnectV4,
    /// `FWPM_LAYER_ALE_AUTH_CONNECT_V6`.
    ConnectV6,
    /// `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4`: inbound connections.
    RecvAcceptV4,
    /// `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6`.
    RecvAcceptV6,
    /// `FWPM_LAYER_IPFORWARD_V4`: traffic forwarded between interfaces.
    ForwardV4,
    /// `FWPM_LAYER_IPFORWARD_V6`.
    ForwardV6,
}

impl Layer {
    const ALE_V4: [Self; 2] = [Self::ConnectV4, Self::RecvAcceptV4];
    const ALE_V6: [Self; 2] = [Self::ConnectV6, Self::RecvAcceptV6];
    const ALE: [Self; 4] = [
        Self::ConnectV4,
        Self::ConnectV6,
        Self::RecvAcceptV4,
        Self::RecvAcceptV6,
    ];
    /// Every layer stop-internet uses.
    pub const ALL: [Self; 6] = [
        Self::ConnectV4,
        Self::ConnectV6,
        Self::RecvAcceptV4,
        Self::RecvAcceptV6,
        Self::ForwardV4,
        Self::ForwardV6,
    ];

    fn is_v6(self) -> bool {
        matches!(self, Self::ConnectV6 | Self::RecvAcceptV6 | Self::ForwardV6)
    }
}

/// Field tested by a condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Field {
    /// `FWPM_CONDITION_FLAGS`.
    Flags,
    /// `FWPM_CONDITION_IP_LOCAL_INTERFACE`: interface LUID.
    LocalInterface,
    /// `FWPM_CONDITION_ALE_APP_ID`: process image.
    AppId,
    /// `FWPM_CONDITION_IP_PROTOCOL`.
    Protocol,
    /// `FWPM_CONDITION_IP_LOCAL_PORT`; the ICMP type for ICMP traffic.
    LocalPort,
    /// `FWPM_CONDITION_IP_REMOTE_PORT`; the ICMP code for ICMP traffic.
    RemotePort,
    /// `FWPM_CONDITION_IP_REMOTE_ADDRESS`.
    RemoteAddress,
}

/// How a condition compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatchKind {
    /// `FWP_MATCH_EQUAL`. Several equal conditions on one field are OR-ed.
    Equal,
    /// `FWP_MATCH_NOT_EQUAL`.
    NotEqual,
    /// `FWP_MATCH_FLAGS_ALL_SET`.
    FlagsAllSet,
    /// `FWP_MATCH_RANGE`, bounds included.
    Range,
}

/// Value of a condition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Value {
    /// 8-bit number.
    U8(u8),
    /// 16-bit number.
    U16(u16),
    /// 32-bit number.
    U32(u32),
    /// 64-bit number.
    U64(u64),
    /// Inclusive range of 16-bit numbers.
    U16Range(u16, u16),
    /// IPv4 prefix: address and prefix length.
    V4Prefix([u8; 4], u8),
    /// IPv6 prefix: address and prefix length.
    V6Prefix([u8; 16], u8),
    /// Executable, resolved to a WFP application id when the filter is added.
    AppPath(PathBuf),
}

/// One condition of a filter. Conditions on different fields are AND-ed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Condition {
    /// Field to test.
    pub field: Field,
    /// Comparison.
    pub kind: MatchKind,
    /// Value to compare with.
    pub value: Value,
}

impl Condition {
    fn equal(field: Field, value: Value) -> Self {
        Self {
            field,
            kind: MatchKind::Equal,
            value,
        }
    }
}

/// A filter ready to be added to the stop-internet sublayer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterSpec {
    /// Display name, for `netsh wfp show filters` and logs.
    pub name: String,
    /// Layer of the filter.
    pub layer: Layer,
    /// Permit or block.
    pub action: Action,
    /// Weight inside the sublayer; the higher, the earlier evaluated.
    pub weight: u64,
    /// Lifetime of the rule the filter comes from.
    pub scope: Scope,
    /// Conditions; an empty list matches all traffic of the layer.
    pub conditions: Vec<Condition>,
}

impl FilterSpec {
    /// Executable this filter refers to, if any.
    pub fn app_path(&self) -> Option<&PathBuf> {
        self.conditions.iter().find_map(|c| match &c.value {
            Value::AppPath(path) => Some(path),
            _ => None,
        })
    }
}

/// Facts about the system that a policy needs to become filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Environment {
    /// LUID of the tunnel adapter, when it is up.
    pub tunnel_luid: Option<u64>,
}

/// A rule that could not become filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// Lifetime of the rule.
    pub scope: Scope,
    /// Why it was left out.
    pub reason: String,
}

/// Filters for one policy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    /// Filters to add.
    pub filters: Vec<FilterSpec>,
    /// Rules that could not become filters.
    pub skipped: Vec<Skipped>,
}

impl Plan {
    /// Translates every rule of the policy into filters.
    ///
    /// Rule order becomes filter weight: the first rule gets the highest
    /// weight, the last one (block everything) gets weight 1.
    pub fn build(policy: &Policy, env: &Environment) -> Self {
        let mut plan = Self::default();
        let count = policy.rules().len() as u64;
        for (index, rule) in policy.rules().iter().enumerate() {
            plan.add_rule(rule, count - index as u64, env);
        }
        plan
    }

    /// The part of the plan with rules of one scope: the persistent baseline
    /// or the session rules on top of it. Weights stay as they are, so both
    /// parts can live in one sublayer.
    pub fn only(&self, scope: Scope) -> Self {
        Self {
            filters: self
                .filters
                .iter()
                .filter(|f| f.scope == scope)
                .cloned()
                .collect(),
            skipped: self
                .skipped
                .iter()
                .filter(|s| s.scope == scope)
                .cloned()
                .collect(),
        }
    }

    fn add_rule(&mut self, rule: &Rule, weight: u64, env: &Environment) {
        let mut add = |layers: &[Layer], conditions: &dyn Fn(Layer) -> Vec<Condition>| {
            for &layer in layers {
                self.filters.push(FilterSpec {
                    name: RuleName(rule).to_string(),
                    layer,
                    action: rule.action,
                    weight,
                    scope: rule.scope,
                    conditions: conditions(layer),
                });
            }
        };

        match &rule.matcher {
            Matcher::All => add(&Layer::ALL, &|_| Vec::new()),
            Matcher::Loopback => add(&Layer::ALE, &|_| {
                vec![Condition {
                    field: Field::Flags,
                    kind: MatchKind::FlagsAllSet,
                    value: Value::U32(LOOPBACK_FLAG),
                }]
            }),
            Matcher::Dhcp => {
                add(&Layer::ALE_V4, &|_| udp_ports(68, 67));
                add(&Layer::ALE_V6, &|_| udp_ports(546, 547));
            }
            Matcher::NeighborDiscovery => add(&Layer::ALE_V6, &|_| {
                vec![
                    Condition::equal(Field::Protocol, Value::U8(PROTOCOL_ICMPV6)),
                    Condition {
                        field: Field::LocalPort,
                        kind: MatchKind::Range,
                        value: Value::U16Range(133, 137),
                    },
                ]
            }),
            Matcher::TunnelInterface(name) => match env.tunnel_luid {
                Some(luid) => add(&Layer::ALE, &|_| {
                    vec![Condition::equal(Field::LocalInterface, Value::U64(luid))]
                }),
                None => self.skipped.push(Skipped {
                    scope: rule.scope,
                    reason: format!("tunnel adapter \"{name}\" is not available"),
                }),
            },
            Matcher::App(path) => add(&Layer::ALE, &|_| {
                vec![Condition::equal(Field::AppId, Value::AppPath(path.clone()))]
            }),
            Matcher::Lan => add(&Layer::ALE, &lan_conditions),
            // Outbound only: answers come back on the same flow.
            Matcher::SystemDns => add(&[Layer::ConnectV4, Layer::ConnectV6], &|_| {
                vec![
                    Condition::equal(Field::AppId, Value::AppPath(SYSTEM_DNS_APP.into())),
                    Condition::equal(Field::RemotePort, Value::U16(DNS_PORT)),
                ]
            }),
        }
    }
}

fn udp_ports(local: u16, remote: u16) -> Vec<Condition> {
    vec![
        Condition::equal(Field::Protocol, Value::U8(PROTOCOL_UDP)),
        Condition::equal(Field::LocalPort, Value::U16(local)),
        Condition::equal(Field::RemotePort, Value::U16(remote)),
    ]
}

fn lan_conditions(layer: Layer) -> Vec<Condition> {
    let mut conditions: Vec<Condition> = if layer.is_v6() {
        LAN_V6
            .iter()
            .map(|&(addr, len)| Condition::equal(Field::RemoteAddress, Value::V6Prefix(addr, len)))
            .collect()
    } else {
        LAN_V4
            .iter()
            .map(|&(addr, len)| Condition::equal(Field::RemoteAddress, Value::V4Prefix(addr, len)))
            .collect()
    };
    conditions.push(Condition {
        field: Field::RemotePort,
        kind: MatchKind::NotEqual,
        value: Value::U16(DNS_PORT),
    });
    conditions
}

/// Short filter name: "permit loopback", "block all traffic".
struct RuleName<'a>(&'a Rule);

impl fmt::Display for RuleName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action = match self.0.action {
            Action::Permit => "permit",
            Action::Block => "block",
        };
        write!(f, "stop-internet: {action} {}", self.0.matcher)
    }
}

#[cfg(test)]
mod tests {
    use stopinet_core::config::Config;
    use stopinet_core::policy::{Mode, TunnelState};

    use super::*;

    const LUID: u64 = 0x0035_0000_0000_0001;

    fn config(allow_lan: bool) -> Config {
        Config::from_toml(&format!(
            r#"
[tunnel]
adapter_name = "vpn-tun"
driver = "Wintun"

[client]
tunnel_apps = ['C:\vpn\daemon.exe']

[direct]
apps = ['C:\games\game.exe']

[network]
allow_lan = {allow_lan}
"#
        ))
        .unwrap()
    }

    fn plan(mode: Mode, tunnel: TunnelState, env: Environment) -> Plan {
        Plan::build(&Policy::build(&config(false), mode, tunnel), &env)
    }

    fn with_field(plan: &Plan, field: Field) -> Vec<&FilterSpec> {
        plan.filters
            .iter()
            .filter(|f| f.conditions.iter().any(|c| c.field == field))
            .collect()
    }

    #[test]
    fn tunnel_down_has_no_tunnel_filters() {
        let plan = plan(Mode::TunnelOnly, TunnelState::Down, Environment::default());
        assert!(with_field(&plan, Field::LocalInterface).is_empty());
        assert!(plan.skipped.is_empty());
        // loopback 4, DHCP 4, neighbor discovery 2, game 4, block all 6
        assert_eq!(plan.filters.len(), 20);
    }

    #[test]
    fn tunnel_up_permits_its_interface_on_all_ale_layers() {
        let env = Environment {
            tunnel_luid: Some(LUID),
        };
        let plan = plan(Mode::TunnelOnly, TunnelState::Up, env);
        let tunnel = with_field(&plan, Field::LocalInterface);
        assert_eq!(tunnel.len(), 4);
        assert!(tunnel.iter().all(|f| f.action == Action::Permit));
        assert!(
            tunnel
                .iter()
                .all(|f| f.conditions[0].value == Value::U64(LUID))
        );
    }

    #[test]
    fn tunnel_up_without_luid_is_reported() {
        let plan = plan(Mode::TunnelOnly, TunnelState::Up, Environment::default());
        assert!(with_field(&plan, Field::LocalInterface).is_empty());
        assert_eq!(plan.skipped.len(), 1);
    }

    #[test]
    fn block_all_has_the_lowest_weight_and_covers_forwarding() {
        let plan = plan(Mode::TunnelOnly, TunnelState::Down, Environment::default());
        let blocks: Vec<_> = plan
            .filters
            .iter()
            .filter(|f| f.action == Action::Block)
            .collect();
        assert_eq!(blocks.len(), 6);
        assert!(
            blocks
                .iter()
                .all(|f| f.weight == 1 && f.conditions.is_empty())
        );
        assert!(blocks.iter().any(|f| f.layer == Layer::ForwardV4));
        assert!(blocks.iter().any(|f| f.layer == Layer::ForwardV6));
        assert!(
            plan.filters
                .iter()
                .filter(|f| f.action == Action::Permit)
                .all(|f| f.weight > 1)
        );
    }

    #[test]
    fn earlier_rules_get_higher_weights() {
        let env = Environment {
            tunnel_luid: Some(LUID),
        };
        let plan = plan(Mode::TunnelOnly, TunnelState::Up, env);
        let weights: Vec<u64> = plan.filters.iter().map(|f| f.weight).collect();
        assert!(weights.windows(2).all(|w| w[0] >= w[1]), "{weights:?}");
    }

    #[test]
    fn apps_are_matched_by_path_on_ale_layers() {
        let plan = plan(Mode::TunnelOnly, TunnelState::Down, Environment::default());
        let apps = with_field(&plan, Field::AppId);
        assert_eq!(apps.len(), 4);
        assert!(
            apps.iter()
                .all(|f| f.app_path() == Some(&PathBuf::from(r"C:\games\game.exe")))
        );
    }

    #[test]
    fn neighbor_discovery_is_ipv6_only() {
        let plan = plan(Mode::TunnelOnly, TunnelState::Down, Environment::default());
        let ndp: Vec<_> = plan
            .filters
            .iter()
            .filter(|f| f.conditions.iter().any(|c| c.kind == MatchKind::Range))
            .collect();
        assert_eq!(ndp.len(), 2);
        assert!(ndp.iter().all(|f| f.layer.is_v6()));
    }

    #[test]
    fn persistent_filters_are_the_same_in_every_state() {
        let env = Environment {
            tunnel_luid: Some(LUID),
        };
        let reference = plan(Mode::TunnelOnly, TunnelState::Down, env).only(Scope::Persistent);
        assert!(!reference.filters.is_empty());
        for mode in Mode::ALL {
            for state in TunnelState::ALL {
                let persistent = plan(mode, state, env).only(Scope::Persistent);
                assert_eq!(persistent, reference, "{mode:?} / {state:?}");
            }
        }
    }

    #[test]
    fn session_filters_outweigh_the_baseline() {
        let env = Environment {
            tunnel_luid: Some(LUID),
        };
        let plan = plan(Mode::TunnelOnly, TunnelState::Up, env);
        let session = plan.only(Scope::Session);
        let persistent = plan.only(Scope::Persistent);
        assert_eq!(
            session.filters.len() + persistent.filters.len(),
            plan.filters.len()
        );
        let lowest_session = session.filters.iter().map(|f| f.weight).min().unwrap();
        let highest_persistent = persistent.filters.iter().map(|f| f.weight).max().unwrap();
        assert!(lowest_session > highest_persistent);
    }

    #[test]
    fn unavailable_tunnel_is_a_session_skip() {
        let plan = plan(Mode::TunnelOnly, TunnelState::Up, Environment::default());
        assert_eq!(plan.only(Scope::Session).skipped.len(), 1);
        assert!(plan.only(Scope::Persistent).skipped.is_empty());
    }

    #[test]
    fn proxy_mode_lets_the_dns_client_send_queries_out() {
        let proxy = plan(Mode::Proxy, TunnelState::Down, Environment::default());
        let dns: Vec<_> = proxy
            .filters
            .iter()
            .filter(|f| f.app_path() == Some(&PathBuf::from(SYSTEM_DNS_APP)))
            .collect();
        assert_eq!(dns.len(), 2);
        for filter in &dns {
            assert!(matches!(filter.layer, Layer::ConnectV4 | Layer::ConnectV6));
            assert_eq!(filter.action, Action::Permit);
            assert_eq!(filter.scope, Scope::Session);
            assert!(
                filter
                    .conditions
                    .contains(&Condition::equal(Field::RemotePort, Value::U16(DNS_PORT)))
            );
        }

        let tunnel = plan(Mode::TunnelOnly, TunnelState::Down, Environment::default());
        assert!(
            tunnel
                .filters
                .iter()
                .all(|f| f.app_path() != Some(&PathBuf::from(SYSTEM_DNS_APP)))
        );
    }

    #[test]
    fn lan_excludes_dns() {
        let policy = Policy::build(&config(true), Mode::TunnelOnly, TunnelState::Down);
        let plan = Plan::build(&policy, &Environment::default());
        let lan = with_field(&plan, Field::RemoteAddress);
        assert_eq!(lan.len(), 4);
        for filter in lan {
            assert!(filter.conditions.contains(&Condition {
                field: Field::RemotePort,
                kind: MatchKind::NotEqual,
                value: Value::U16(DNS_PORT),
            }));
        }
    }
}
