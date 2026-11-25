//! Read-only Windows interface inventory for a future Agent-owned egress policy.
//!
//! This module does not change routes, DNS, WFP, interface state, or traffic. It
//! returns conservative hardware-interface candidates; callers must still
//! complete route correlation and packet-capture acceptance before using the
//! result in a production kill switch.

use crate::wfp_policy::PhysicalInterface;
use std::collections::BTreeSet;

const MAX_ENUMERATED_INTERFACES: usize = 4096;
const MAX_PHYSICAL_INTERFACES: usize = 32;
const MAX_ADAPTER_BUFFER_BYTES: usize = 16 * 1024 * 1024;
const ERROR_BUFFER_OVERFLOW: u32 = 111;
const AF_UNSPEC: u32 = 0;
const GAA_FLAG_INCLUDE_ALL_INTERFACES: u32 = 0x0100;

const HARDWARE_INTERFACE: u8 = 1 << 0;
const FILTER_INTERFACE: u8 = 1 << 1;
const CONNECTOR_PRESENT: u8 = 1 << 2;
const ENDPOINT_INTERFACE: u8 = 1 << 7;

// IANA interface types exposed by Windows IP Helper. These identify logical
// interface kinds that must not become physical-egress enforcement targets.
const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
const IF_TYPE_PROP_VIRTUAL: u32 = 53;
const IF_TYPE_TUNNEL: u32 = 131;
const IF_TYPE_L2_VLAN: u32 = 135;
const IF_TYPE_L3_IPVLAN: u32 = 136;
const IF_TYPE_L3_IPXVLAN: u32 = 137;
const IF_TYPE_MPLS_TUNNEL: u32 = 150;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InterfaceFacts {
    interface_luid: u64,
    interface_index: u32,
    interface_type: u32,
    flags: u8,
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

/// Select conservative physical-egress candidates from IP Helper interface facts.
///
/// The HardwareInterface and ConnectorPresent flags are required; interface
/// names and descriptions are deliberately never used as classification signals.
/// OperStatus and MediaConnectState are deliberately ignored so a temporarily
/// disconnected physical adapter is still included in the policy inventory.
fn select_hardware_egress_candidates(
    rows: impl IntoIterator<Item = InterfaceFacts>,
) -> Result<Vec<PhysicalInterface>, String> {
    let mut candidates = Vec::new();
    let mut seen_luids = BTreeSet::new();
    let mut seen_indexes = BTreeSet::new();

    for row in rows {
        if !is_hardware_egress_candidate(row) {
            continue;
        }
        if row.interface_luid == 0 || row.interface_index == 0 {
            return Err("Windows returned a hardware interface with a zero LUID or index.".into());
        }
        if !seen_luids.insert(row.interface_luid) || !seen_indexes.insert(row.interface_index) {
            return Err("Windows returned duplicate hardware interface LUIDs or indexes.".into());
        }
        candidates.push(PhysicalInterface {
            interface_luid: row.interface_luid,
            interface_index: row.interface_index,
        });
        if candidates.len() > MAX_PHYSICAL_INTERFACES {
            return Err("The hardware interface inventory exceeds the WFP policy limit of 32.".into());
        }
    }

    if candidates.is_empty() {
        return Err(
            "No conservative hardware egress interfaces were found; refusing to infer adapters from names."
                .into(),
        );
    }

    candidates.sort_by_key(|item| item.interface_luid);
    Ok(candidates)
}

/// Enumerate all NDIS adapters as a caller-owned linked list, then ask IP Helper
/// for each row's full MIB_IF_ROW2 metadata by stable LUID.
///
/// GetAdaptersAddresses owns no memory after this function returns: its linked
/// list lives in the aligned Vec buffer below. GetIfEntry2 fills a single local
/// row and avoids walking the variable-alignment MIB_IF_TABLE2 array.
#[cfg(windows)]
pub fn discover_hardware_egress_interfaces() -> Result<Vec<PhysicalInterface>, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GetIfEntry2, IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2,
    };

    let mut required_bytes = 0u32;
    let sizing_status = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_INCLUDE_ALL_INTERFACES,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut required_bytes,
        )
    };
    if sizing_status != ERROR_BUFFER_OVERFLOW && sizing_status != 0 {
        return Err(format!(
            "GetAdaptersAddresses sizing call failed with Windows error {sizing_status}."
        ));
    }
    if required_bytes == 0 || required_bytes as usize > MAX_ADAPTER_BUFFER_BYTES {
        return Err(format!(
            "GetAdaptersAddresses returned an invalid or oversized buffer length: {required_bytes}."
        ));
    }

    // Vec<usize> guarantees pointer alignment for IP_ADAPTER_ADDRESSES_LH,
    // unlike Vec<u8>. Retrying is bounded in case adapters change during sizing.
    for _attempt in 0..3 {
        let words = (required_bytes as usize)
            .checked_add(std::mem::size_of::<usize>() - 1)
            .ok_or_else(|| "The adapter buffer size overflowed.".to_string())?
            / std::mem::size_of::<usize>();
        let mut storage = vec![0usize; words];
        let capacity_bytes = storage
            .len()
            .checked_mul(std::mem::size_of::<usize>())
            .ok_or_else(|| "The adapter buffer allocation size overflowed.".to_string())?;
        let mut supplied_bytes = u32::try_from(capacity_bytes)
            .map_err(|_| "The adapter buffer exceeds the Windows API size limit.".to_string())?;
        let first = storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();

        let status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                GAA_FLAG_INCLUDE_ALL_INTERFACES,
                std::ptr::null(),
                first,
                &mut supplied_bytes,
            )
        };
        if status == ERROR_BUFFER_OVERFLOW {
            if supplied_bytes == 0 || supplied_bytes as usize > MAX_ADAPTER_BUFFER_BYTES {
                return Err(format!(
                    "GetAdaptersAddresses requested an invalid retry size: {supplied_bytes}."
                ));
            }
            required_bytes = supplied_bytes;
            continue;
        }
        if status != 0 {
            return Err(format!(
                "GetAdaptersAddresses failed with Windows error {status}."
            ));
        }

        let buffer_start = first as usize;
        let buffer_end = buffer_start
            .checked_add(capacity_bytes)
            .ok_or_else(|| "The adapter buffer address range overflowed.".to_string())?;
        let mut current = first;
        let mut seen_nodes = BTreeSet::new();
        let mut rows = Vec::new();

        while !current.is_null() {
            let address = current as usize;
            let row_end = address
                .checked_add(std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>())
                .ok_or_else(|| "An adapter row address overflowed.".to_string())?;
            if address < buffer_start
                || row_end > buffer_end
                || address % std::mem::align_of::<IP_ADAPTER_ADDRESSES_LH>() != 0
            {
                return Err("GetAdaptersAddresses returned a linked-list node outside its aligned buffer.".into());
            }
            if !seen_nodes.insert(address) {
                return Err("GetAdaptersAddresses returned a cyclic adapter linked list.".into());
            }
            if seen_nodes.len() > MAX_ENUMERATED_INTERFACES {
                return Err("The adapter inventory exceeds the defensive 4096-row limit.".into());
            }

            let adapter = unsafe { &*current };
            let luid = unsafe { adapter.Luid.Value };
            if luid == 0 {
                return Err("GetAdaptersAddresses returned an adapter with a zero LUID.".into());
            }

            let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
            unsafe {
                row.InterfaceLuid.Value = luid;
            }
            let row_status = unsafe { GetIfEntry2(&mut row) };
            if row_status != 0 {
                return Err(format!(
                    "GetIfEntry2 failed for interface LUID {luid:#x} with Windows error {row_status}; the interface inventory may have changed."
                ));
            }

            rows.push(InterfaceFacts {
                interface_luid: unsafe { row.InterfaceLuid.Value },
                interface_index: row.InterfaceIndex,
                interface_type: row.Type,
                flags: row.InterfaceAndOperStatusFlags._bitfield,
            });
            current = adapter.Next;
        }

        return select_hardware_egress_candidates(rows);
    }

    Err("The network adapter inventory changed during all three bounded enumeration attempts.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hardware(luid: u64, index: u32) -> InterfaceFacts {
        InterfaceFacts {
            interface_luid: luid,
            interface_index: index,
            interface_type: 6, // IF_TYPE_ETHERNET_CSMACD
            flags: HARDWARE_INTERFACE | CONNECTOR_PRESENT,
        }
    }

    #[test]
    fn selects_hardware_candidates_and_sorts_by_stable_luid() {
        let mut disconnected = hardware(20, 2);
        // NotMediaConnected / OperStatusDown are intentionally not exclusion flags.
        disconnected.flags |= 1 << 4;

        let selected = select_hardware_egress_candidates([
            hardware(40, 4),
            disconnected,
            InterfaceFacts {
                interface_type: 71, // IF_TYPE_IEEE80211
                ..hardware(10, 1)
            },
        ])
        .unwrap();

        assert_eq!(
            selected,
            vec![
                PhysicalInterface { interface_luid: 10, interface_index: 1 },
                PhysicalInterface { interface_luid: 20, interface_index: 2 },
                PhysicalInterface { interface_luid: 40, interface_index: 4 },
            ]
        );
    }

    #[test]
    fn requires_hardware_and_physical_connector_flags() {
        let mut software = hardware(1, 1);
        software.flags &= !HARDWARE_INTERFACE;
        let mut no_connector = hardware(2, 2);
        no_connector.flags &= !CONNECTOR_PRESENT;

        assert!(select_hardware_egress_candidates([software, no_connector]).is_err());
    }

    #[test]
    fn rejects_filter_and_endpoint_interfaces() {
        let mut filter = hardware(1, 1);
        filter.flags |= FILTER_INTERFACE;
        let mut endpoint = hardware(2, 2);
        endpoint.flags |= ENDPOINT_INTERFACE;

        assert!(select_hardware_egress_candidates([filter, endpoint]).is_err());
    }

    #[test]
    fn rejects_known_logical_interface_types() {
        let logical_types = [
            IF_TYPE_SOFTWARE_LOOPBACK,
            IF_TYPE_PROP_VIRTUAL,
            IF_TYPE_TUNNEL,
            IF_TYPE_L2_VLAN,
            IF_TYPE_L3_IPVLAN,
            IF_TYPE_L3_IPXVLAN,
            IF_TYPE_MPLS_TUNNEL,
        ];
        for (index, interface_type) in logical_types.into_iter().enumerate() {
            let row = InterfaceFacts {
                interface_type,
                ..hardware(index as u64 + 1, index as u32 + 1)
            };
            assert!(!is_hardware_egress_candidate(row));
        }
    }

    #[test]
    fn fails_closed_on_zero_or_duplicate_identity() {
        assert!(select_hardware_egress_candidates([hardware(0, 1)]).is_err());
        assert!(select_hardware_egress_candidates([hardware(1, 0)]).is_err());
        assert!(select_hardware_egress_candidates([
            hardware(1, 1),
            hardware(1, 2),
        ])
        .is_err());
        assert!(select_hardware_egress_candidates([
            hardware(1, 1),
            hardware(2, 1),
        ])
        .is_err());
    }

    #[test]
    fn rejects_inventories_above_the_policy_bound_without_truncating() {
        let rows = (1..=MAX_PHYSICAL_INTERFACES + 1)
            .map(|index| hardware(index as u64, index as u32));
        assert!(select_hardware_egress_candidates(rows).is_err());
    }

    #[test]
    fn ignores_interface_names_and_never_guesses_when_no_candidate_exists() {
        assert!(select_hardware_egress_candidates(std::iter::empty()).is_err());
    }
}
