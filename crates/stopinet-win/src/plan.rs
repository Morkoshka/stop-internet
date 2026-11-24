//! Translation of a [`Policy`] into concrete WFP filters.
//!
//! This module is pure: it only decides layers, conditions and weights. The
//! [`wfp`](crate::wfp) module turns the result into API calls.

use std::fmt;
use std::net::IpAddr;
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
    /// `FWPM_LAYER_OUTBOUND_IPPACKET_V4`: every outbound IP packet, also of
    /// connections that are already open.
    OutboundPacketV4,
    /// `FWPM_LAYER_OUTBOUND_IPPACKET_V6`.
    OutboundPacketV6,
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
    /// Layers of a rule for all traffic: connections both ways and
    /// forwarding. Not the packet layers: a filter there without conditions
    /// would drop the packets of permitted connections too.
    const ALL_TRAFFIC: [Self; 6] = [
        Self::ConnectV4,
        Self::ConnectV6,
        Self::RecvAcceptV4,
        Self::RecvAcceptV6,
        Self::ForwardV4,
        Self::ForwardV6,
    ];
    const OUTBOUND_PACKETS: [Self; 2] = [Self::OutboundPacketV4, Self::OutboundPacketV6];
    /// Every layer stop-internet uses.
    pub const ALL: [Self; 8] = [
        Self::ConnectV4,
        Self::ConnectV6,
        Self::RecvAcceptV4,
        Self::RecvAcceptV6,
        Self::ForwardV4,
        Self::ForwardV6,
        Self::OutboundPacketV4,
        Self::OutboundPacketV6,
    ];

    fn is_v6(self) -> bool {
        matches!(
            self,
            Self::ConnectV6 | Self::RecvAcceptV6 | Self::ForwardV6 | Self::OutboundPacketV6
        )
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
    /// `FWPM_CONDITION_IP_LOCAL_ADDRESS`.
    LocalAddress,
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
    /// `FWP_MATCH_FLAGS_NONE_SET`.
    FlagsNoneSet,
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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Environment {
    /// LUID of the tunnel adapter, when it is up.
    pub tunnel_luid: Option<u64>,
    /// Unicast addresses of the tunnel adapter, when it is up.
    pub tunnel_addresses: Vec<IpAddr>,
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
            Matcher::All => add(&Layer::ALL_TRAFFIC, &|_| Vec::new()),
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
            // Without the adapter nothing is added; the rule for the tunnel
            // interface already says so.
            Matcher::TunnelAddressElsewhere(name) => {
                if let Some(luid) = env.tunnel_luid {
                    let addresses = &env.tunnel_addresses;
                    // One filter per address family the tunnel has.
                    let layers: Vec<Layer> = Layer::OUTBOUND_PACKETS
                        .into_iter()
                        .filter(|&layer| addresses.iter().any(|a| a.is_ipv6() == layer.is_v6()))
                        .collect();
                    if layers.is_empty() {
                        self.skipped.push(Skipped {
                            scope: rule.scope,
                            reason: format!("tunnel adapter \"{name}\" has no addresses yet"),
                        });
                    }
                    add(&layers, &|layer| {
                        tunnel_address_conditions(layer, luid, addresses)
                    });
                }
            }
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

/// A packet from one of the tunnel addresses of the layer's family, on an
/// interface other than the tunnel, that is not loopback.
fn tunnel_address_conditions(layer: Layer, luid: u64, addresses: &[IpAddr]) -> Vec<Condition> {
    let mut conditions: Vec<Condition> = addresses
        .iter()
        .filter_map(|address| match (address, layer.is_v6()) {
            (IpAddr::V4(v4), false) => Some(Value::V4Prefix(v4.octets(), 32)),
            (IpAddr::V6(v6), true) => Some(Value::V6Prefix(v6.octets(), 128)),
            _ => None,
        })
        .map(|value| Condition::equal(Field::LocalAddress, value))
        .collect();
    conditions.push(Condition {
        field: Field::LocalInterface,
        kind: MatchKind::NotEqual,
        value: Value::U64(luid),
    });
    conditions.push(Condition {
        field: Field::Flags,
        kind: MatchKind::FlagsNoneSet,
        value: Value::U32(LOOPBACK_FLAG),
    });
    conditions
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
    const TUNNEL_V4: [u8; 4] = [10, 6, 7, 1];
    const TUNNEL_V6: [u8; 16] = [
        0xfd, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];

    /// The tunnel up, with an IPv4 and an IPv6 address.
    fn up() -> Environment {
        Environment {
            tunnel_luid: Some(LUID),
            tunnel_addresses: vec![IpAddr::from(TUNNEL_V4), IpAddr::from(TUNNEL_V6)],
        }
    }

    /// Filters on the packet layers.
    fn guard(plan: &Plan) -> Vec<&FilterSpec> {
        plan.filters
            .iter()
            .filter(|f| Layer::OUTBOUND_PACKETS.contains(&f.layer))
            .collect()
    }

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
        let plan = plan(Mode::TunnelOnly, TunnelState::Up, up());
        let tunnel: Vec<_> = with_field(&plan, Field::LocalInterface)
            .into_iter()
            .filter(|f| f.action == Action::Permit)
            .collect();
        assert_eq!(tunnel.len(), 4);
        assert!(tunnel.iter().all(|f| Layer::ALE.contains(&f.layer)));
        assert!(
            tunnel.iter().all(
                |f| f.conditions == [Condition::equal(Field::LocalInterface, Value::U64(LUID))]
            )
        );
    }

    #[test]
    fn tunnel_up_without_luid_is_reported() {
        let plan = plan(Mode::TunnelOnly, TunnelState::Up, Environment::default());
        assert!(with_field(&plan, Field::LocalInterface).is_empty());
        // Once: the guard of the tunnel addresses leaves it to the tunnel rule.
        assert_eq!(plan.skipped.len(), 1);
    }

    #[test]
    fn tunnel_addresses_may_not_leave_through_another_interface() {
        let plan = plan(Mode::TunnelOnly, TunnelState::Up, up());
        let guard = guard(&plan);
        assert_eq!(guard.len(), 2);
        for filter in &guard {
            assert_eq!(filter.action, Action::Block);
            assert_eq!(filter.scope, Scope::Session);
            let address = if filter.layer.is_v6() {
                Value::V6Prefix(TUNNEL_V6, 128)
            } else {
                Value::V4Prefix(TUNNEL_V4, 32)
            };
            assert_eq!(
                filter.conditions,
                [
                    Condition::equal(Field::LocalAddress, address),
                    Condition {
                        field: Field::LocalInterface,
                        kind: MatchKind::NotEqual,
                        value: Value::U64(LUID),
                    },
                    Condition {
                        field: Field::Flags,
                        kind: MatchKind::FlagsNoneSet,
                        value: Value::U32(LOOPBACK_FLAG),
                    },
                ]
            );
        }
        // First, before anything the tunnel permits.
        let top = plan.filters.iter().map(|f| f.weight).max().unwrap();
        assert!(guard.iter().all(|f| f.weight == top));
    }

    #[test]
    fn the_guard_follows_the_address_families_of_the_tunnel() {
        let only_v4 = Environment {
            tunnel_addresses: vec![IpAddr::from(TUNNEL_V4)],
            ..up()
        };
        let plan_v4 = plan(Mode::Proxy, TunnelState::Up, only_v4);
        let layers: Vec<Layer> = guard(&plan_v4).iter().map(|f| f.layer).collect();
        assert_eq!(layers, [Layer::OutboundPacketV4]);
        assert!(plan_v4.skipped.is_empty());

        let none = Environment {
            tunnel_addresses: Vec::new(),
            ..up()
        };
        let plan_none = plan(Mode::TunnelOnly, TunnelState::Up, none);
        assert!(guard(&plan_none).is_empty());
        assert_eq!(plan_none.skipped.len(), 1);
        assert!(
            plan_none.skipped[0].reason.contains("no addresses"),
            "{:?}",
            plan_none.skipped
        );
    }

    #[test]
    fn packet_layers_only_get_the_guard() {
        let config = config(true);
        for mode in Mode::ALL {
            for state in TunnelState::ALL {
                let plan = Plan::build(&Policy::build(&config, mode, state), &up());
                for filter in &plan.filters {
                    // Every layer in use is enumerated by status and removal.
                    assert!(Layer::ALL.contains(&filter.layer), "{filter:?}");
                    if Layer::OUTBOUND_PACKETS.contains(&filter.layer) {
                        assert_eq!(filter.action, Action::Block, "{filter:?}");
                        assert!(
                            filter
                                .conditions
                                .iter()
                                .any(|c| c.field == Field::LocalAddress),
                            "{filter:?}"
                        );
                    }
                }
                let guarded = mode != Mode::Normal && state == TunnelState::Up;
                assert_eq!(!guard(&plan).is_empty(), guarded, "{mode:?} / {state:?}");
            }
        }
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
        let env = up();
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
        let env = up();
        let reference =
            plan(Mode::TunnelOnly, TunnelState::Down, env.clone()).only(Scope::Persistent);
        assert!(!reference.filters.is_empty());
        for mode in Mode::ALL {
            for state in TunnelState::ALL {
                let persistent = plan(mode, state, env.clone()).only(Scope::Persistent);
                assert_eq!(persistent, reference, "{mode:?} / {state:?}");
            }
        }
    }

    #[test]
    fn session_filters_outweigh_the_baseline() {
        let env = up();
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
