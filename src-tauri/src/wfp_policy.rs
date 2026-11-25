//! Pure, fail-closed policy model for the future Windows Filtering Platform backend.
//!
//! This module deliberately performs no WFP/OS mutations. It validates the narrow
//! VPN transport exception set and produces an auditable filter intent. A Windows
//! backend must install, verify, journal, and recover these intents before this
//! model can be considered active leak protection.

use std::collections::BTreeSet;
use std::net::IpAddr;

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
    pub fn validate(&self) -> Result<(), String> {
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
    fn rejects_duplicate_endpoint_tuples() {
        let mut value = spec();
        value.vpn_endpoints.push(value.vpn_endpoints[0]);
        assert!(value.validate().is_err());
    }
}
