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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressPolicySpec {
    /// Interface indexes for physical adapters only. The caller must resolve and
    /// verify these against adapter GUID/LUID identities before installing WFP.
    pub physical_interface_indexes: Vec<u32>,
    /// Numeric endpoints only: hostname resolution belongs to the encrypted
    /// bootstrap stage and must finish before this policy is compiled.
    pub vpn_endpoints: Vec<VpnEndpoint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfpLayer {
    AleAuthConnectV4,
    AleAuthConnectV6,
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
    pub layer: WfpLayer,
    pub intent: FilterIntent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpPolicyPlan {
    pub filters: Vec<PlannedFilter>,
}

impl EgressPolicySpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.physical_interface_indexes.is_empty()
            || self.physical_interface_indexes.len() > MAX_PHYSICAL_INTERFACES
        {
            return Err("The WFP policy must name a bounded, non-empty physical interface set.".into());
        }
        let interfaces: BTreeSet<_> = self.physical_interface_indexes.iter().copied().collect();
        if interfaces.len() != self.physical_interface_indexes.len()
            || interfaces.contains(&0)
        {
            return Err("The WFP policy contains an invalid or duplicate interface index.".into());
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

    /// Compile the intended dual-stack filter set. This is not proof of WFP
    /// precedence or installation: the backend must use explicit weights,
    /// persistent provider/sublayer ownership, read-back verification, and
    /// packet-capture tests before enabling this policy in production.
    pub fn compile_plan(&self) -> Result<WfpPolicyPlan, String> {
        self.validate()?;
        let mut filters = Vec::with_capacity(
            self.physical_interface_indexes.len() * (self.vpn_endpoints.len() * 2 + 2),
        );

        for interface_index in &self.physical_interface_indexes {
            for layer in [WfpLayer::AleAuthConnectV4, WfpLayer::AleAuthConnectV6] {
                filters.push(PlannedFilter {
                    interface_index: *interface_index,
                    layer,
                    intent: FilterIntent::BlockOtherPhysicalEgress,
                });
                for endpoint in self.vpn_endpoints.iter().filter(|endpoint| {
                    matches!((layer, endpoint.address),
                        (WfpLayer::AleAuthConnectV4, IpAddr::V4(_))
                        | (WfpLayer::AleAuthConnectV6, IpAddr::V6(_)))
                }) {
                    filters.push(PlannedFilter {
                        interface_index: *interface_index,
                        layer,
                        intent: FilterIntent::PermitVpnEndpoint(*endpoint),
                    });
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
            physical_interface_indexes: vec![7, 11],
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
        assert_eq!(plan.filters.len(), 8);
        for interface in [7, 11] {
            for layer in [WfpLayer::AleAuthConnectV4, WfpLayer::AleAuthConnectV6] {
                assert!(plan.filters.iter().any(|filter| {
                    filter.interface_index == interface
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
        value.physical_interface_indexes.clear();
        assert!(value.validate().is_err());

        let mut value = spec();
        value.vpn_endpoints.clear();
        assert!(value.validate().is_err());

        let mut value = spec();
        value.physical_interface_indexes = vec![1, 1];
        assert!(value.validate().is_err());

        let mut value = spec();
        value.vpn_endpoints[0].port = 0;
        assert!(value.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_endpoint_tuples() {
        let mut value = spec();
        value.vpn_endpoints.push(value.vpn_endpoints[0]);
        assert!(value.validate().is_err());
    }
}
