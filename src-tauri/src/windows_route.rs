//! Read-only Windows route-to-interface correlation for VPN endpoint bootstrap.
//!
//! This module never changes routes, DNS, WFP, interfaces, or traffic. It asks
//! IP Helper which interface currently has the best route to each pinned VPN
//! endpoint, then re-reads that interface by index and requires its fresh stable
//! LUID and physical-hardware flags to match the earlier hardware inventory.
//! Any mismatch or virtual/filter/endpoint result is rejected.

use crate::wfp_policy::{PhysicalInterface, VpnEndpoint};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

const MAX_PHYSICAL_INTERFACES: usize = 32;
const MAX_VPN_ENDPOINTS: usize = 64;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;

const HARDWARE_INTERFACE: u8 = 1 << 0;
const FILTER_INTERFACE: u8 = 1 << 1;
const CONNECTOR_PRESENT: u8 = 1 << 2;
const ENDPOINT_INTERFACE: u8 = 1 << 7;

const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
const IF_TYPE_PROP_VIRTUAL: u32 = 53;
const IF_TYPE_TUNNEL: u32 = 131;
const IF_TYPE_L2_VLAN: u32 = 135;
const IF_TYPE_L3_IPVLAN: u32 = 136;
const IF_TYPE_L3_IPXVLAN: u32 = 137;
const IF_TYPE_MPLS_TUNNEL: u32 = 150;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrV4 {
    family: u16,
    port: u16,
    address: [u8; 4],
    zero: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockAddrV6 {
    family: u16,
    port: u16,
    flowinfo: u32,
    address: [u8; 16],
    scope_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
union SockAddrStorage {
    v4: SockAddrV4,
    v6: SockAddrV6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InterfaceFacts {
    interface_luid: u64,
    interface_index: u32,
    interface_type: u32,
    flags: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedVpnEndpointEgress {
    pub endpoint: VpnEndpoint,
    pub egress: PhysicalInterface,
}

fn is_known_logical_interface_type(interface_type: u32) -> bool {
    matches!(
        interface_type,
        IF_TYPE_SOFTWARE_LOOPBACK
            | IF_TYPE_PROP_VIRTUAL
            | IF_TYPE_TUNNEL
            | IF_TYPE_L2_VLAN
            | IF_TYPE_L3_IPVLAN
            | IF_TYPE_L3_IPXVLAN
            | IF_TYPE_MPLS_TUNNEL
    )
}

fn is_hardware_egress_candidate(row: InterfaceFacts) -> bool {
    row.flags & HARDWARE_INTERFACE != 0
        && row.flags & CONNECTOR_PRESENT != 0
        && row.flags & FILTER_INTERFACE == 0
        && row.flags & ENDPOINT_INTERFACE == 0
        && !is_known_logical_interface_type(row.interface_type)
}

fn validate_inputs(
    endpoints: &[VpnEndpoint],
    candidates: &[PhysicalInterface],
) -> Result<(), String> {
    if endpoints.is_empty() || endpoints.len() > MAX_VPN_ENDPOINTS {
        return Err("Route resolution requires a bounded, non-empty VPN endpoint set.".into());
    }
    if candidates.is_empty() || candidates.len() > MAX_PHYSICAL_INTERFACES {
        return Err("Route resolution requires a bounded, non-empty physical-interface inventory.".into());
    }

    let endpoint_set: BTreeSet<_> = endpoints.iter().copied().collect();
    if endpoint_set.len() != endpoints.len()
        || endpoints.iter().any(|endpoint| {
            endpoint.port == 0
                || endpoint.address.is_unspecified()
                || endpoint.address.is_loopback()
                || endpoint.address.is_multicast()
                || endpoint.address == IpAddr::V4(Ipv4Addr::BROADCAST)
        })
    {
        return Err("The VPN endpoint set contains a duplicate or non-unicast/invalid destination tuple.".into());
    }

    let mut seen_luids = BTreeSet::new();
    let mut seen_indexes = BTreeSet::new();
    for candidate in candidates {
        if candidate.interface_luid == 0
            || candidate.interface_index == 0
            || !seen_luids.insert(candidate.interface_luid)
            || !seen_indexes.insert(candidate.interface_index)
        {
            return Err("The physical-interface inventory contains an invalid or duplicate identity.".into());
        }
    }
    Ok(())
}

fn map_best_interface_to_candidate(
    best_interface_index: u32,
    row: InterfaceFacts,
    candidates: &[PhysicalInterface],
) -> Result<PhysicalInterface, String> {
    if best_interface_index == 0 || row.interface_index != best_interface_index {
        return Err("The route lookup interface index changed before it could be verified.".into());
    }
    if row.interface_luid == 0 || !is_hardware_egress_candidate(row) {
        return Err("Windows selected a non-physical, virtual, filter, or endpoint interface for the VPN endpoint.".into());
    }

    let candidate = candidates
        .iter()
        .find(|candidate| candidate.interface_luid == row.interface_luid)
        .copied()
        .ok_or_else(|| {
            "The Windows-selected route interface is absent from the physical-interface inventory.".to_string()
        })?;
    if candidate.interface_index != row.interface_index {
        return Err("The physical interface index changed since inventory discovery; refresh the inventory.".into());
    }
    Ok(candidate)
}

#[cfg(windows)]
fn sockaddr_for_endpoint(address: IpAddr) -> SockAddrStorage {
    // The union preserves native SOCKADDR_IN / SOCKADDR_IN6 alignment;
    // a byte array would not provide the alignment required by GetBestInterfaceEx.
    match address {
        IpAddr::V4(ip) => SockAddrStorage {
            v4: SockAddrV4 {
                family: AF_INET,
                port: 0,
                address: ip.octets(),
                zero: [0; 8],
            },
        },
        IpAddr::V6(ip) => SockAddrStorage {
            v6: SockAddrV6 {
                family: AF_INET6,
                port: 0,
                flowinfo: 0,
                address: ip.octets(),
                scope_id: 0,
            },
        },
    }
}

/// Resolve every pinned endpoint to the interface Windows currently selects
/// for its best route, and verify the result against a fresh MIB_IF_ROW2 read.
///
/// This is a point-in-time read-only check, not a route lock. Callers must repeat
/// it after network/interface/route changes and immediately before any future
/// WFP transaction. Any selected adapter outside the conservative physical
/// inventory fails closed; do not fall back to a name-based guess.
#[cfg(windows)]
pub fn resolve_vpn_endpoint_egress(
    endpoints: &[VpnEndpoint],
    candidates: &[PhysicalInterface],
) -> Result<Vec<ResolvedVpnEndpointEgress>, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetBestInterfaceEx, GetIfEntry2, MIB_IF_ROW2,
    };
    use windows_sys::Win32::Networking::WinSock::SOCKADDR;

    validate_inputs(endpoints, candidates)?;
    let mut resolved = Vec::with_capacity(endpoints.len());

    for endpoint in endpoints {
        let address = sockaddr_for_endpoint(endpoint.address);
        let mut best_interface_index = 0u32;
        let status = unsafe {
            GetBestInterfaceEx(
                (&address as *const SockAddrStorage).cast::<SOCKADDR>(),
                &mut best_interface_index,
            )
        };
        if status != 0 {
            return Err(format!(
                "GetBestInterfaceEx failed for VPN endpoint {} with Windows error {status}.",
                endpoint.address
            ));
        }
        if best_interface_index == 0 {
            return Err(format!(
                "Windows returned a zero route interface index for VPN endpoint {}.",
                endpoint.address
            ));
        }

        let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
        row.InterfaceIndex = best_interface_index;
        let row_status = unsafe { GetIfEntry2(&mut row) };
        if row_status != 0 {
            return Err(format!(
                "GetIfEntry2 failed for route interface {best_interface_index} with Windows error {row_status}."
            ));
        }

        let facts = InterfaceFacts {
            interface_luid: unsafe { row.InterfaceLuid.Value },
            interface_index: row.InterfaceIndex,
            interface_type: row.Type,
            flags: row.InterfaceAndOperStatusFlags._bitfield,
        };
        let egress = map_best_interface_to_candidate(best_interface_index, facts, candidates)
            .map_err(|error| format!("{error} VPN endpoint: {}.", endpoint.address))?;
        resolved.push(ResolvedVpnEndpointEgress {
            endpoint: *endpoint,
            egress,
        });
    }

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wfp_policy::TransportProtocol;

    fn candidate(luid: u64, index: u32) -> PhysicalInterface {
        PhysicalInterface {
            interface_luid: luid,
            interface_index: index,
        }
    }

    fn facts(luid: u64, index: u32) -> InterfaceFacts {
        InterfaceFacts {
            interface_luid: luid,
            interface_index: index,
            interface_type: 6,
            flags: HARDWARE_INTERFACE | CONNECTOR_PRESENT,
        }
    }

    fn endpoint(address: &str, port: u16) -> VpnEndpoint {
        VpnEndpoint {
            address: address.parse().unwrap(),
            port,
            protocol: TransportProtocol::Tcp,
        }
    }

    #[test]
    fn maps_windows_best_route_to_the_matching_fresh_hardware_identity() {
        assert_eq!(
            map_best_interface_to_candidate(7, facts(0x10007, 7), &[candidate(0x10007, 7)]),
            Ok(candidate(0x10007, 7))
        );
    }

    #[test]
    fn rejects_a_route_through_virtual_filter_and_endpoint_interfaces() {
        let mut virtual_adapter = facts(1, 1);
        virtual_adapter.interface_type = IF_TYPE_TUNNEL;
        assert!(map_best_interface_to_candidate(1, virtual_adapter, &[candidate(1, 1)]).is_err());

        let mut filter = facts(2, 2);
        filter.flags |= FILTER_INTERFACE;
        assert!(map_best_interface_to_candidate(2, filter, &[candidate(2, 2)]).is_err());

        let mut endpoint_device = facts(3, 3);
        endpoint_device.flags |= ENDPOINT_INTERFACE;
        assert!(map_best_interface_to_candidate(3, endpoint_device, &[candidate(3, 3)]).is_err());
    }

    #[test]
    fn rejects_unlisted_or_stale_route_interfaces() {
        assert!(map_best_interface_to_candidate(7, facts(0x10007, 7), &[candidate(0x10008, 8)]).is_err());
        assert!(map_best_interface_to_candidate(8, facts(0x10007, 8), &[candidate(0x10007, 7)]).is_err());
        assert!(map_best_interface_to_candidate(0, facts(0x10007, 7), &[candidate(0x10007, 7)]).is_err());
    }

    #[test]
    fn validates_endpoint_and_candidate_bounds_and_duplicates() {
        let endpoint_a = endpoint("203.0.113.8", 443);
        assert!(validate_inputs(&[], &[candidate(1, 1)]).is_err());
        assert!(validate_inputs(&[endpoint_a], &[]).is_err());
        assert!(validate_inputs(&[endpoint_a, endpoint_a], &[candidate(1, 1)]).is_err());
        assert!(validate_inputs(&[endpoint_a], &[candidate(1, 1), candidate(1, 2)]).is_err());
        assert!(validate_inputs(&[endpoint_a], &[candidate(1, 1), candidate(2, 1)]).is_err());
        assert!(validate_inputs(&[endpoint("0.0.0.0", 443)], &[candidate(1, 1)]).is_err());
        assert!(validate_inputs(&[endpoint("127.0.0.1", 443)], &[candidate(1, 1)]).is_err());
        assert!(validate_inputs(&[endpoint("224.0.0.1", 443)], &[candidate(1, 1)]).is_err());
        assert!(validate_inputs(&[endpoint("203.0.113.8", 0)], &[candidate(1, 1)]).is_err());
    }

    #[test]
    fn validates_multiple_endpoints_independently_and_preserves_transport_tuple() {
        let first = endpoint("203.0.113.8", 443);
        let second = VpnEndpoint {
            address: "2001:db8::8".parse().unwrap(),
            port: 8443,
            protocol: TransportProtocol::Udp,
        };
        assert_eq!(
            validate_inputs(&[first, second], &[candidate(1, 1), candidate(2, 2)]),
            Ok(())
        );
        assert_ne!(first.address, second.address);
        assert_eq!(first.port, 443);
        assert_eq!(second.protocol, TransportProtocol::Udp);
    }

    #[test]
    fn rejects_known_logical_interface_types() {
        for (index, interface_type) in [
            IF_TYPE_SOFTWARE_LOOPBACK,
            IF_TYPE_PROP_VIRTUAL,
            IF_TYPE_TUNNEL,
            IF_TYPE_L2_VLAN,
            IF_TYPE_L3_IPVLAN,
            IF_TYPE_L3_IPXVLAN,
            IF_TYPE_MPLS_TUNNEL,
        ]
        .into_iter()
        .enumerate()
        {
            let mut row = facts(index as u64 + 1, index as u32 + 1);
            row.interface_type = interface_type;
            assert!(!is_hardware_egress_candidate(row));
        }
    }

    #[test]
    fn socket_address_layout_matches_windows_abi_sizes_and_alignment() {
        assert_eq!(std::mem::size_of::<SockAddrV4>(), 16);
        assert_eq!(std::mem::size_of::<SockAddrV6>(), 28);
        assert_eq!(std::mem::offset_of!(SockAddrV4, address), 4);
        assert_eq!(std::mem::offset_of!(SockAddrV6, address), 8);
        assert!(std::mem::align_of::<SockAddrStorage>() >= 4);
    }

    #[test]
    fn route_lookup_validation_fails_closed_after_inventory_changes() {
        let mut row = facts(0x20007, 7);
        row.flags &= !CONNECTOR_PRESENT;
        assert!(map_best_interface_to_candidate(7, row, &[candidate(0x20007, 7)]).is_err());
    }
}
