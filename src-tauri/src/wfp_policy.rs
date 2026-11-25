//! Pure, fail-closed policy model for the future Windows Filtering Platform backend.
//!
//! This module deliberately performs no WFP/OS mutations. It validates the narrow
//! VPN transport exception set and produces an auditable filter intent. A Windows
//! backend must install, verify, journal, and recover these intents before this
//! model can be considered active leak protection.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

const MAX_PHYSICAL_INTERFACES: usize = 32;
const MAX_ENDPOINTS: usize = 64;
const MAX_PLANNED_FILTERS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct VpnEndpoint {
    pub address: IpAddr,
    pub port: u16,
    pub protocol: TransportProtocol,
}

/// One exact VPN endpoint exception bound to the interface Windows selected
/// for that endpoint's current route. A binding must match a candidate by both
/// stable LUID and current interface index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EndpointEgressBinding {
    pub endpoint: VpnEndpoint,
    pub egress: PhysicalInterface,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysicalInterface {
    /// Stable Windows NET_LUID value used by FWPM_CONDITION_IP_LOCAL_INTERFACE.
    pub interface_luid: u64,
    /// Current interface index for diagnostics and route-table correlation only.
    pub interface_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressPolicySpec {
    /// Physical adapters identified by stable LUID; indexes are diagnostic only.
    pub physical_interfaces: Vec<PhysicalInterface>,
    /// Numeric endpoints only: hostname resolution belongs to the encrypted
    /// bootstrap stage and must finish before this policy is compiled.
    pub vpn_endpoints: Vec<VpnEndpoint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpLayer {
    AleAuthConnectV4,
    AleAuthConnectV6,
    OutboundTransportV4,
    OutboundTransportV6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterIntent {
    /// Permit only the exact VPN transport tuple on the selected physical NIC.
    PermitVpnEndpoint(VpnEndpoint),
    /// Deny all other outbound user-data connections on the selected physical NIC.
    BlockOtherPhysicalEgress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedFilter {
    pub interface_index: u32,
    pub interface_luid: u64,
    pub layer: WfpLayer,
    pub intent: FilterIntent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpPolicyPlan {
    pub filters: Vec<PlannedFilter>,
}

impl EgressPolicySpec {
    fn validate_common(&self) -> Result<(), String> {
        if self.physical_interfaces.is_empty()
            || self.physical_interfaces.len() > MAX_PHYSICAL_INTERFACES
        {
            return Err("The WFP policy must name a bounded, non-empty physical interface set.".into());
        }
        let interfaces: BTreeSet<_> = self.physical_interfaces.iter().copied().collect();
        if interfaces.len() != self.physical_interfaces.len()
            || self.physical_interfaces.iter().any(|interface| {
                interface.interface_luid == 0 || interface.interface_index == 0
            })
        {
            return Err("The WFP policy contains an invalid or duplicate physical interface identity.".into());
        }
        let luids: BTreeSet<_> = self.physical_interfaces.iter().map(|item| item.interface_luid).collect();
        let indexes: BTreeSet<_> = self.physical_interfaces.iter().map(|item| item.interface_index).collect();
        if luids.len() != self.physical_interfaces.len() || indexes.len() != self.physical_interfaces.len() {
            return Err("The WFP policy contains duplicate interface LUIDs or indexes.".into());
        }
        if self.vpn_endpoints.is_empty() || self.vpn_endpoints.len() > MAX_ENDPOINTS {
            return Err("The WFP policy requires a bounded, non-empty VPN endpoint allowlist.".into());
        }
        let endpoints: BTreeSet<_> = self.vpn_endpoints.iter().copied().collect();
        if endpoints.len() != self.vpn_endpoints.len()
            || self.vpn_endpoints.iter().any(|endpoint| endpoint.port == 0)
        {
            return Err("The VPN endpoint allowlist contains a duplicate or invalid transport tuple.".into());
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validate_common()?;
        let planned_filter_count = self
            .physical_interfaces
            .len()
            .checked_mul(2 * (self.vpn_endpoints.len() + 2))
            .ok_or_else(|| "The WFP filter plan size overflowed.".to_string())?;
        if planned_filter_count > MAX_PLANNED_FILTERS {
            return Err("The WFP policy exceeds the bounded maximum filter count.".into());
        }
        Ok(())
    }

    /// Compile the intended dual-stack filter set. This is not proof of WFP
    /// precedence or installation: the backend must use explicit weights,
    /// persistent provider/sublayer ownership, read-back verification, and
    /// packet-capture tests before enabling this policy in production.
    pub fn compile_plan(&self) -> Result<WfpPolicyPlan, String> {
        self.validate()?;
        let mut filters = Vec::with_capacity(
            self.physical_interfaces.len() * 2 * (self.vpn_endpoints.len() + 2),
        );

        // ALE rejects new outbound authorizations that do not match the exact
        // VPN endpoint. Outbound transport also sees packets from third-party
        // transports and raw sockets, including packets in previously
        // authorized ALE flows. WFP arbitration is per-layer, so each layer
        // needs its own exact VPN endpoint exception.
        for interface in &self.physical_interfaces {
            for (ale_layer, transport_layer) in [
                (WfpLayer::AleAuthConnectV4, WfpLayer::OutboundTransportV4),
                (WfpLayer::AleAuthConnectV6, WfpLayer::OutboundTransportV6),
            ] {
                for layer in [ale_layer, transport_layer] {
                    filters.push(PlannedFilter {
                        interface_index: interface.interface_index,
                        interface_luid: interface.interface_luid,
                        layer,
                        intent: FilterIntent::BlockOtherPhysicalEgress,
                    });
                    for endpoint in self.vpn_endpoints.iter().filter(|endpoint| {
                        matches!((ale_layer, endpoint.address),
                            (WfpLayer::AleAuthConnectV4, IpAddr::V4(_))
                            | (WfpLayer::AleAuthConnectV6, IpAddr::V6(_)))
                    }) {
                        filters.push(PlannedFilter {
                            interface_index: interface.interface_index,
                            interface_luid: interface.interface_luid,
                            layer,
                            intent: FilterIntent::PermitVpnEndpoint(*endpoint),
                        });
                    }
                }
            }
        }

        Ok(WfpPolicyPlan { filters })
    }

    /// Compile a route-bound dual-stack WFP plan. Block filters cover every
    /// candidate physical interface, but each VPN endpoint permit is emitted
    /// only on the single interface Windows selected for that endpoint.
    ///
    /// This is the only plan builder suitable for a route-resolved production
    /// transaction. The unbound `compile_plan` remains for rollback-only
    /// synthetic WFP acceptance tests.
    pub fn compile_plan_with_resolved_egress(
        &self,
        bindings: &[EndpointEgressBinding],
    ) -> Result<WfpPolicyPlan, String> {
        self.validate_common()?;
        if bindings.len() != self.vpn_endpoints.len() {
            return Err("Every VPN endpoint must have exactly one Windows-resolved egress binding.".into());
        }

        let endpoints: BTreeSet<_> = self.vpn_endpoints.iter().copied().collect();
        let mut seen_endpoints = BTreeSet::new();
        for binding in bindings {
            if !endpoints.contains(&binding.endpoint) {
                return Err("An egress binding references an endpoint outside the configured VPN endpoint set.".into());
            }
            if !seen_endpoints.insert(binding.endpoint) {
                return Err("A VPN endpoint has more than one egress-interface binding.".into());
            }
            if !self.physical_interfaces.iter().any(|interface| {
                interface.interface_luid == binding.egress.interface_luid
                    && interface.interface_index == binding.egress.interface_index
            }) {
                return Err("A route-resolved endpoint egress does not exactly match a discovered physical-interface identity.".into());
            }
            if binding.endpoint.address.is_unspecified()
                || binding.endpoint.address.is_loopback()
                || binding.endpoint.address.is_multicast()
                || binding.endpoint.address == IpAddr::V4(Ipv4Addr::BROADCAST)
                || matches!(binding.endpoint.address, IpAddr::V6(address) if address.is_unicast_link_local())
            {
                return Err("A route-bound VPN endpoint is not a supported unicast destination.".into());
            }
        }
        if seen_endpoints != endpoints {
            return Err("The endpoint-to-egress bindings do not cover the configured VPN endpoint set exactly.".into());
        }

        // Four mandatory block filters per physical NIC plus two exact permit
        // filters per endpoint (ALE + outbound transport, one address family).
        let block_count = self.physical_interfaces.len().checked_mul(4)
            .ok_or_else(|| "The route-bound WFP filter count overflowed.".to_string())?;
        let permit_count = bindings.len().checked_mul(2)
            .ok_or_else(|| "The route-bound WFP permit count overflowed.".to_string())?;
        let filter_count = block_count.checked_add(permit_count)
            .ok_or_else(|| "The route-bound WFP filter count overflowed.".to_string())?;
        if filter_count > MAX_PLANNED_FILTERS {
            return Err("The route-bound WFP policy exceeds the bounded 256-filter recovery journal.".into());
        }

        let mut filters = Vec::with_capacity(filter_count);
        for interface in &self.physical_interfaces {
            for layer in [
                WfpLayer::AleAuthConnectV4,
                WfpLayer::AleAuthConnectV6,
                WfpLayer::OutboundTransportV4,
                WfpLayer::OutboundTransportV6,
            ] {
                filters.push(PlannedFilter {
                    interface_index: interface.interface_index,
                    interface_luid: interface.interface_luid,
                    layer,
                    intent: FilterIntent::BlockOtherPhysicalEgress,
                });
            }
        }

        for binding in bindings {
            let layers = match binding.endpoint.address {
                IpAddr::V4(_) => [WfpLayer::AleAuthConnectV4, WfpLayer::OutboundTransportV4],
                IpAddr::V6(_) => [WfpLayer::AleAuthConnectV6, WfpLayer::OutboundTransportV6],
            };
            for layer in layers {
                filters.push(PlannedFilter {
                    interface_index: binding.egress.interface_index,
                    interface_luid: binding.egress.interface_luid,
                    layer,
                    intent: FilterIntent::PermitVpnEndpoint(binding.endpoint),
                });
            }
        }

        Ok(WfpPolicyPlan { filters })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> EgressPolicySpec {
        EgressPolicySpec {
            physical_interfaces: vec![
                PhysicalInterface { interface_luid: 0x0001_0000_0000_0007, interface_index: 7 },
                PhysicalInterface { interface_luid: 0x0001_0000_0000_000B, interface_index: 11 },
            ],
            vpn_endpoints: vec![
                VpnEndpoint {
                    address: "203.0.113.8".parse().unwrap(),
                    port: 443,
                    protocol: TransportProtocol::Tcp,
                },
                VpnEndpoint {
                    address: "2001:db8::8".parse().unwrap(),
                    port: 8443,
                    protocol: TransportProtocol::Udp,
                },
            ],
        }
    }

    #[test]
    fn compiles_both_address_families_and_blocks_other_egress() {
        let plan = spec().compile_plan().unwrap();
        assert_eq!(plan.filters.len(), 16);
        for interface in [
            PhysicalInterface { interface_luid: 0x0001_0000_0000_0007, interface_index: 7 },
            PhysicalInterface { interface_luid: 0x0001_0000_0000_000B, interface_index: 11 },
        ] {
            for layer in [
                WfpLayer::AleAuthConnectV4,
                WfpLayer::AleAuthConnectV6,
                WfpLayer::OutboundTransportV4,
                WfpLayer::OutboundTransportV6,
            ] {
                assert!(plan.filters.iter().any(|filter| {
                    filter.interface_index == interface.interface_index
                        && filter.interface_luid == interface.interface_luid
                        && filter.layer == layer
                        && filter.intent == FilterIntent::BlockOtherPhysicalEgress
                }));
            }
        }
        assert!(plan.filters.iter().any(|filter| matches!(
            filter.intent,
            FilterIntent::PermitVpnEndpoint(VpnEndpoint { address: IpAddr::V4(_), .. })
        )));
        assert!(plan.filters.iter().any(|filter| matches!(
            filter.intent,
            FilterIntent::PermitVpnEndpoint(VpnEndpoint { address: IpAddr::V6(_), .. })
        )));
    }

    #[test]
    fn rejects_empty_or_unbounded_interface_and_endpoint_sets() {
        let mut value = spec();
        value.physical_interfaces.clear();
        assert!(value.validate().is_err());

        let mut value = spec();
        value.vpn_endpoints.clear();
        assert!(value.validate().is_err());

        let mut value = spec();
        value.physical_interfaces = vec![
            PhysicalInterface { interface_luid: 7, interface_index: 1 },
            PhysicalInterface { interface_luid: 7, interface_index: 2 },
        ];
        assert!(value.validate().is_err());

        let mut value = spec();
        value.physical_interfaces = vec![
            PhysicalInterface { interface_luid: 7, interface_index: 1 },
            PhysicalInterface { interface_luid: 8, interface_index: 1 },
        ];
        assert!(value.validate().is_err());

        let mut value = spec();
        value.physical_interfaces[0].interface_luid = 0;
        assert!(value.validate().is_err());

        let mut value = spec();
        value.physical_interfaces[0].interface_index = 0;
        assert!(value.validate().is_err());

        let mut value = spec();
        value.physical_interfaces = (1..=32)
            .map(|index| PhysicalInterface {
                interface_luid: index as u64,
                interface_index: index,
            })
            .collect();
        value.vpn_endpoints = (1..=64)
            .map(|port| VpnEndpoint {
                address: "203.0.113.8".parse().unwrap(),
                port,
                protocol: TransportProtocol::Udp,
            })
            .collect();
        assert!(value.validate().is_err());

        let mut value = spec();
        value.vpn_endpoints[0].port = 0;
        assert!(value.validate().is_err());
    }

    #[test]
    fn accepts_the_exact_journal_capacity_and_rejects_one_filter_over() {
        let mut value = EgressPolicySpec {
            physical_interfaces: (1..=4)
                .map(|index| PhysicalInterface {
                    interface_luid: index as u64,
                    interface_index: index,
                })
                .collect(),
            vpn_endpoints: (1..=30)
                .map(|port| VpnEndpoint {
                    address: "203.0.113.8".parse().unwrap(),
                    port,
                    protocol: TransportProtocol::Udp,
                })
                .collect(),
        };
        let plan = value.compile_plan().expect("256 filters fit the recovery journal");
        assert_eq!(plan.filters.len(), 256);

        value.vpn_endpoints.push(VpnEndpoint {
            address: "203.0.113.8".parse().unwrap(),
            port: 31,
            protocol: TransportProtocol::Udp,
        });
        assert!(value.compile_plan().is_err(), "the policy must not exceed the 256-record journal bound");
    }

    #[test]
    fn route_bound_plan_permits_each_endpoint_only_on_its_selected_interface() {
        let value = spec();
        let bindings = vec![
            EndpointEgressBinding { endpoint: value.vpn_endpoints[0], egress: value.physical_interfaces[0] },
            EndpointEgressBinding { endpoint: value.vpn_endpoints[1], egress: value.physical_interfaces[1] },
        ];
        let plan = value.compile_plan_with_resolved_egress(&bindings).unwrap();
        assert_eq!(plan.filters.len(), 12);

        for interface in &value.physical_interfaces {
            for layer in [
                WfpLayer::AleAuthConnectV4,
                WfpLayer::AleAuthConnectV6,
                WfpLayer::OutboundTransportV4,
                WfpLayer::OutboundTransportV6,
            ] {
                assert!(plan.filters.iter().any(|filter| {
                    filter.interface_luid == interface.interface_luid
                        && filter.interface_index == interface.interface_index
                        && filter.layer == layer
                        && filter.intent == FilterIntent::BlockOtherPhysicalEgress
                }));
            }
        }

        for (endpoint, selected) in [
            (value.vpn_endpoints[0], value.physical_interfaces[0]),
            (value.vpn_endpoints[1], value.physical_interfaces[1]),
        ] {
            let expected_layers: &[WfpLayer] = match endpoint.address {
                IpAddr::V4(_) => &[WfpLayer::AleAuthConnectV4, WfpLayer::OutboundTransportV4],
                IpAddr::V6(_) => &[WfpLayer::AleAuthConnectV6, WfpLayer::OutboundTransportV6],
            };
            for layer in expected_layers {
                assert!(plan.filters.iter().any(|filter| {
                    filter.interface_luid == selected.interface_luid
                        && filter.interface_index == selected.interface_index
                        && filter.layer == *layer
                        && filter.intent == FilterIntent::PermitVpnEndpoint(endpoint)
                }));
            }
            assert!(!plan.filters.iter().any(|filter| {
                filter.interface_luid != selected.interface_luid
                    && filter.intent == FilterIntent::PermitVpnEndpoint(endpoint)
            }));
        }
    }

    #[test]
    fn route_bound_plan_rejects_missing_duplicate_unknown_and_stale_bindings() {
        let value = spec();
        let first = EndpointEgressBinding { endpoint: value.vpn_endpoints[0], egress: value.physical_interfaces[0] };
        let second = EndpointEgressBinding { endpoint: value.vpn_endpoints[1], egress: value.physical_interfaces[1] };
        assert!(value.compile_plan_with_resolved_egress(&[first]).is_err());
        assert!(value.compile_plan_with_resolved_egress(&[first, first]).is_err());

        let mut unknown = first;
        unknown.endpoint.port += 1;
        assert!(value.compile_plan_with_resolved_egress(&[unknown, second]).is_err());

        let mut stale = first;
        stale.egress.interface_index += 100;
        assert!(value.compile_plan_with_resolved_egress(&[stale, second]).is_err());
    }

    #[test]
    fn route_bound_plan_supports_exact_256_filter_capacity_without_cross_nic_permits() {
        let interfaces: Vec<_> = (1..=32)
            .map(|index| PhysicalInterface { interface_luid: index as u64, interface_index: index })
            .collect();
        let endpoints: Vec<_> = (1..=64)
            .map(|port| VpnEndpoint {
                address: "198.51.100.9".parse().unwrap(),
                port,
                protocol: TransportProtocol::Udp,
            })
            .collect();
        let bindings: Vec<_> = endpoints.iter().enumerate()
            .map(|(index, endpoint)| EndpointEgressBinding {
                endpoint: *endpoint,
                egress: interfaces[index % interfaces.len()],
            })
            .collect();
        let value = EgressPolicySpec { physical_interfaces: interfaces, vpn_endpoints: endpoints };
        let plan = value.compile_plan_with_resolved_egress(&bindings).unwrap();
        assert_eq!(plan.filters.len(), 256);
        assert_eq!(
            plan.filters.iter().filter(|item| matches!(item.intent, FilterIntent::PermitVpnEndpoint(_))).count(),
            128
        );
    }

    #[test]
    fn route_bound_plan_rejects_link_local_ipv6_without_scope() {
        let value = EgressPolicySpec {
            physical_interfaces: vec![PhysicalInterface { interface_luid: 7, interface_index: 7 }],
            vpn_endpoints: vec![VpnEndpoint {
                address: "fe80::1".parse().unwrap(),
                port: 443,
                protocol: TransportProtocol::Tcp,
            }],
        };
        let binding = EndpointEgressBinding { endpoint: value.vpn_endpoints[0], egress: value.physical_interfaces[0] };
        assert!(value.compile_plan_with_resolved_egress(&[binding]).is_err());
    }

    #[test]
    fn rejects_duplicate_endpoint_tuples() {
        let mut value = spec();
        value.vpn_endpoints.push(value.vpn_endpoints[0]);
        assert!(value.validate().is_err());
    }
}
