//! Read-only Windows interface inventory for a future Agent-owned egress policy.
//!
//! This module does not change routes, DNS, WFP, interface state, or traffic. It
//! returns conservative hardware-interface candidates using the flags supplied
//! by IP Helper; callers must still complete route correlation and packet-capture
//! acceptance before using the result in a production kill switch.

use crate::wfp_policy::PhysicalInterface;
use std::collections::BTreeSet;

const MAX_ENUMERATED_INTERFACES: usize = 4096;
const MAX_PHYSICAL_INTERFACES: usize = 32;

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

#[cfg(windows)]
struct MibIfTable(*mut windows_sys::Win32::NetworkManagement::IpHelper::MIB_IF_TABLE2);

#[cfg(windows)]
impl Drop for MibIfTable {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::NetworkManagement::IpHelper::FreeMibTable(
                    self.0.cast::<core::ffi::c_void>(),
                );
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

/// Enumerate Windows interfaces using GetIfTable2 and return conservative
/// hardware-egress candidates with stable NET_LUID values.
///
/// This function is read-only. It fails closed on API errors, malformed table
/// pointers, oversized inventories, duplicate identities, or an empty candidate
/// set. The caller must not treat this inventory alone as proof of a complete
/// physical-egress kill switch.
#[cfg(windows)]
pub fn discover_hardware_egress_interfaces() -> Result<Vec<PhysicalInterface>, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, MIB_IF_TABLE2,
    };

    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    let status = unsafe { GetIfTable2(&mut table) };
    if status != 0 {
        if !table.is_null() {
            unsafe { FreeMibTable(table.cast::<core::ffi::c_void>()) };
        }
        return Err(format!("GetIfTable2 failed with Windows error {status}."));
    }
    if table.is_null() {
        return Err("GetIfTable2 succeeded without returning an interface table.".into());
    }

    let table = MibIfTable(table);
    let count = unsafe { (*table.0).NumEntries as usize };
    if count > MAX_ENUMERATED_INTERFACES {
        return Err(format!(
            "GetIfTable2 returned {count} rows, above the defensive limit of {MAX_ENUMERATED_INTERFACES}."
        ));
    }

    // MIB_IF_TABLE2 exposes a one-element flexible-array placeholder. The
    // Win32 binding's repr(C) field supplies the required first-row alignment;
    // each following MIB_IF_ROW2 has the same C array stride.
    let first_row = unsafe { (*table.0).Table.as_ptr() };
    let rows = unsafe { std::slice::from_raw_parts(first_row, count) };
    let facts = rows.iter().map(|row| InterfaceFacts {
        interface_luid: unsafe { row.InterfaceLuid.Value },
        interface_index: row.InterfaceIndex,
        interface_type: row.Type,
        flags: row.InterfaceAndOperStatusFlags._bitfield,
    });

    select_hardware_egress_candidates(facts)
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
        // MediaDisconnected / OperStatusDown are intentionally not represented
        // as exclusion flags: unplugged hardware still needs a WFP policy.
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
