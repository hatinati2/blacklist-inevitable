//! Read-only Windows observations used by crash recovery.
//!
//! Probes return Unknown on access or API failures. Unknown is never treated as
//! absent by the recovery assessment planner. This module never terminates a
//! process, changes an adapter, edits routes/DNS, changes WFP, or removes journals.

use crate::recovery_assessment::Observation;
use crate::recovery_journal::{EngineProcessRecord, FirewallFilterRecord};

/// Observe one journaled process by PID and kernel creation time.
///
/// PID alone is not a stable identity. Access denied, API errors, invalid
/// timestamps, and unexpected wait results all remain Unknown (fail closed).
#[cfg(windows)]
pub fn observe_recorded_engine_process(
    expected: &EngineProcessRecord,
) -> Result<Observation<EngineProcessRecord>, String> {
    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_INVALID_PARAMETER, FILETIME, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE,
    };

    if expected.process_id == 0 || expected.creation_time_100ns == 0 {
        return Ok(Observation::Unknown);
    }

    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            expected.process_id,
        )
    };
    if handle.is_null() {
        let error = unsafe { GetLastError() };
        if error == ERROR_INVALID_PARAMETER {
            return Ok(Observation::Absent);
        }
        return Err(format!(
            "OpenProcess could not inspect journaled engine PID {} (Windows error {}).",
            expected.process_id, error
        ));
    }
    let process = OwnedProcessHandle(handle);

    match unsafe { WaitForSingleObject(process.0, 0) } {
        WAIT_OBJECT_0 => return Ok(Observation::Absent),
        WAIT_TIMEOUT => {}
        _ => return Err("The journaled engine process wait query was inconclusive.".into()),
    }

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe {
        GetProcessTimes(
            process.0,
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err("GetProcessTimes could not verify the journaled engine identity.".into());
    }

    let creation_time_100ns = filetime_to_ticks(creation.dwLowDateTime, creation.dwHighDateTime);
    if creation_time_100ns == 0 {
        return Err("Windows returned an invalid engine process creation timestamp.".into());
    }

    // Re-check liveness after reading the timestamp to avoid reporting a process
    // as live when it exited while the observation was being assembled.
    match unsafe { WaitForSingleObject(process.0, 0) } {
        WAIT_OBJECT_0 => Ok(Observation::Absent),
        WAIT_TIMEOUT => Ok(Observation::Present(EngineProcessRecord {
            process_id: expected.process_id,
            creation_time_100ns,
        })),
        _ => Err("The journaled engine process changed state during observation.".into()),
    }
}

#[cfg(windows)]
fn filetime_to_ticks(low: u32, high: u32) -> u64 {
    (u64::from(high) << 32) | u64::from(low)
}

#[cfg(windows)]
struct OwnedProcessHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for OwnedProcessHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

/// Read the current product-provider WFP filter inventory using a read-only
/// transaction. The vector is Present(empty) only after a complete successful
/// provider-scoped enumeration; any access, enumeration, truncation, or cleanup
/// error returns Err and must be represented as Observation::Unknown.
#[cfg(windows)]
pub fn observe_agent_wfp_filters(
    engine: &mut crate::wfp_engine::WfpEngine,
) -> Result<Observation<Vec<FirewallFilterRecord>>, String> {
    engine
        .enumerate_owned_filters()
        .map(Observation::Present)
}



/// Observe a recorded TUN adapter by stable interface GUID. The interface index
/// is treated as a live consistency check, not as the durable identity. Alias
/// and MTU must also match; assigned address enumeration is a separate probe
/// and is not claimed by this function.
#[cfg(windows)]
pub fn observe_recorded_tunnel_interface(
    expected: &crate::recovery_journal::TunnelInterfaceRecord,
) -> Result<Observation<String>, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, MIB_IF_ROW2, MIB_IF_TABLE2,
    };
    const MAX_INTERFACES: usize = 2048;

    let expected_guid = uuid::Uuid::parse_str(&expected.interface_guid)
        .map_err(|_| "The recorded tunnel GUID is invalid.".to_string())?;
    if !expected_guid.to_string().eq_ignore_ascii_case(&expected.interface_guid) {
        return Ok(Observation::Unknown);
    }

    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    let status = unsafe { GetIfTable2(&mut table) };
    if status != 0 {
        if !table.is_null() {
            unsafe { FreeMibTable(table.cast()) };
        }
        return Err(format!("GetIfTable2 failed with Windows error {status}."));
    }
    if table.is_null() {
        return Err("GetIfTable2 succeeded without an interface table.".into());
    }
    let _table = OwnedIpHelperTable(table.cast());

    let table_ref = unsafe { &*table };
    let count = table_ref.NumEntries as usize;
    if count > MAX_INTERFACES {
        return Err("The Windows interface inventory exceeds its safe bound.".into());
    }

    let rows = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).Table).cast::<MIB_IF_ROW2>(),
            count,
        )
    };

    let mut found = None;
    for row in rows {
        let guid = uuid::Uuid::from_u128(guid_to_u128(&row.InterfaceGuid));
        if guid != expected_guid {
            continue;
        }
        if found.is_some() {
            return Err("Windows returned duplicate rows for the recorded tunnel GUID.".into());
        }

        let alias_end = row.Alias.iter().position(|unit| *unit == 0)
            .unwrap_or(row.Alias.len());
        let alias = String::from_utf16(&row.Alias[..alias_end])
            .map_err(|_| "Windows returned an invalid tunnel interface alias.".to_string())?;

        if row.InterfaceIndex == 0
            || row.InterfaceIndex != expected.interface_index
            || row.Mtu != expected.mtu
            || !alias.eq_ignore_ascii_case(&expected.alias)
        {
            return Ok(Observation::Unknown);
        }

        found = Some(guid.to_string());
    }

    Ok(match found {
        Some(guid) => Observation::Present(guid),
        None => Observation::Absent,
    })
}

/// Read every IPv4 and IPv6 route row in one IP Helper snapshot, then return
/// observations only for destinations present in the supplied journal. A
/// destination with multiple routes is Unknown because the current journal
/// schema cannot distinguish same-prefix routes on different interfaces.
#[cfg(windows)]
pub fn observe_recorded_routes(
    journal: &crate::recovery_journal::RecoveryJournal,
) -> Result<std::collections::BTreeMap<String, Observation<crate::recovery_journal::RouteState>>, String> {
    use std::collections::BTreeMap;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    };
    use windows_sys::Win32::Networking::WinSock::{
        AF_UNSPEC,
    };

    const MAX_ROUTE_ROWS: usize = 16_384;

    let mut routes = BTreeMap::new();
    let mut expected_by_canonical: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for record in &journal.routes {
        let canonical = canonicalize_prefix(&record.destination_prefix)?;
        routes.insert(record.destination_prefix.clone(), Observation::Absent);
        expected_by_canonical
            .entry(canonical)
            .or_default()
            .push(record.destination_prefix.clone());
    }

    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let status = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    if status != 0 {
        if !table.is_null() {
            unsafe { FreeMibTable(table.cast()) };
        }
        return Err(format!("GetIpForwardTable2 failed with Windows error {status}."));
    }
    if table.is_null() {
        return Err("GetIpForwardTable2 succeeded without a route table.".into());
    }
    let _table = OwnedIpHelperTable(table.cast());

    let table_ref = unsafe { &*table };
    let count = table_ref.NumEntries as usize;
    if count > MAX_ROUTE_ROWS {
        return Err("The Windows route inventory exceeds its safe bound.".into());
    }

    let rows = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>(),
            count,
        )
    };

    for row in rows {
        let prefix_address = sockaddr_address(&row.DestinationPrefix.Prefix)?;
        let prefix_length = row.DestinationPrefix.PrefixLength;
        let canonical = canonicalize_ip_prefix(prefix_address, prefix_length)?;

        let Some(journal_keys) = expected_by_canonical.get(&canonical) else {
            continue;
        };
        if journal_keys.len() != 1 {
            for key in journal_keys {
                routes.insert(key.clone(), Observation::Unknown);
            }
            continue;
        }

        if row.InterfaceIndex == 0 {
            routes.insert(journal_keys[0].clone(), Observation::Unknown);
            continue;
        }

        let next_hop_address = sockaddr_address(&row.NextHop)?;
        if next_hop_address.is_ipv4() != prefix_address.is_ipv4() {
            routes.insert(journal_keys[0].clone(), Observation::Unknown);
            continue;
        }
        let next_hop = if next_hop_address.is_unspecified() {
            None
        } else {
            Some(next_hop_address)
        };

        let state = crate::recovery_journal::RouteState {
            interface_index: row.InterfaceIndex,
            next_hop,
            metric: row.Metric,
        };

        let key = &journal_keys[0];
        match routes.get(key) {
            Some(Observation::Absent) => {
                routes.insert(key.clone(), Observation::Present(state));
            }
            Some(Observation::Present(_)) | Some(Observation::Unknown) => {
                routes.insert(key.clone(), Observation::Unknown);
            }
            None => {
                return Err("The route observation snapshot lost a requested journal key.".into());
            }
        }
    }

    Ok(routes)
}

#[cfg(windows)]
fn sockaddr_address(
    address: &windows_sys::Win32::Networking::WinSock::SOCKADDR_INET,
) -> Result<std::net::IpAddr, String> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    let family = unsafe { address.si_family };
    match family {
        AF_INET => {
            let raw = unsafe { address.Ipv4.sin_addr.S_un.S_addr };
            Ok(IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes())))
        }
        AF_INET6 => {
            let bytes = unsafe { address.Ipv6.sin6_addr.u.Byte };
            Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => Err("Windows returned a route address with an unsupported address family.".into()),
    }
}

#[cfg(windows)]
fn canonicalize_prefix(value: &str) -> Result<String, String> {
    let (address, length) = value
        .split_once('/')
        .ok_or_else(|| "The journal contains an invalid route prefix.".to_string())?;
    let address = address
        .parse::<std::net::IpAddr>()
        .map_err(|_| "The journal contains an invalid route address.".to_string())?;
    let length = length
        .parse::<u8>()
        .map_err(|_| "The journal contains an invalid route prefix length.".to_string())?;
    canonicalize_ip_prefix(address, length)
}

#[cfg(windows)]
fn canonicalize_ip_prefix(
    address: std::net::IpAddr,
    length: u8,
) -> Result<String, String> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let canonical = match address {
        IpAddr::V4(address) if length <= 32 => {
            let bits = u32::from_be_bytes(address.octets());
            let mask = if length == 0 { 0 } else { u32::MAX << (32 - length) };
            IpAddr::V4(Ipv4Addr::from((bits & mask).to_be_bytes()))
        }
        IpAddr::V6(address) if length <= 128 => {
            let bits = u128::from_be_bytes(address.octets());
            let mask = if length == 0 { 0 } else { u128::MAX << (128 - length) };
            IpAddr::V6(Ipv6Addr::from((bits & mask).to_be_bytes()))
        }
        _ => return Err("A route prefix length is outside its address-family range.".into()),
    };

    Ok(format!("{canonical}/{length}"))
}

#[cfg(windows)]
fn guid_to_u128(value: &windows_sys::core::GUID) -> u128 {
    ((value.data1 as u128) << 96)
        | ((value.data2 as u128) << 80)
        | ((value.data3 as u128) << 64)
        | (u64::from_be_bytes(value.data4) as u128)
}

#[cfg(windows)]
struct OwnedIpHelperTable(*const std::ffi::c_void);

#[cfg(windows)]
impl Drop for OwnedIpHelperTable {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::NetworkManagement::IpHelper::FreeMibTable(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn filetime_conversion_preserves_high_and_low_words() {
        assert_eq!(
            super::filetime_to_ticks(0x89AB_CDEF, 0x0123_4567),
            0x0123_4567_89AB_CDEF
        );
    }

    #[cfg(windows)]
    #[test]
    fn route_prefixes_are_compared_in_canonical_network_form() {
        assert_eq!(
            super::canonicalize_ip_prefix("203.0.113.129".parse().unwrap(), 24).unwrap(),
            "203.0.113.0/24"
        );
        assert_eq!(
            super::canonicalize_ip_prefix("2001:db8::abcd".parse().unwrap(), 64).unwrap(),
            "2001:db8::/64"
        );
        assert!(super::canonicalize_ip_prefix("203.0.113.1".parse().unwrap(), 33).is_err());
        assert!(super::canonicalize_ip_prefix("2001:db8::1".parse().unwrap(), 129).is_err());
    }
}
