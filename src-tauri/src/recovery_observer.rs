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



/// Read one authoritative per-interface DNS settings snapshot and the
/// effective resolver addresses returned by GetAdaptersAddresses.
///
/// GetInterfaceDnsSettings v3 returns the stack selected by its IPV6 flag;
/// this API does not document a caller-selectable second family (input Flags
/// must be zero). Therefore this observer deliberately returns only the stack
/// positively identified by Windows and leaves the other stack None. The pure
/// recovery assessor will keep such a partial observation Unknown; it can
/// never authorize journal removal or DNS restoration.
#[cfg(windows)]
pub fn observe_recorded_dns(
    expected: &crate::recovery_journal::DnsMutationRecord,
) -> Result<Observation<crate::recovery_journal::DnsConfiguration>, String> {
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeInterfaceDnsSettings, GetAdaptersAddresses, GetIfTable2, GetInterfaceDnsSettings,
        MIB_IF_ROW2, MIB_IF_TABLE2, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS3,
        DNS_INTERFACE_SETTINGS_VERSION3,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST,
    };

    const MAX_INTERFACES: usize = 2048;

    let Some(expected_guid_text) = expected.interface_guid.as_deref() else {
        return Ok(Observation::Unknown);
    };
    let expected_guid = uuid::Uuid::parse_str(expected_guid_text)
        .map_err(|_| "The recorded DNS interface GUID is invalid.".to_string())?;
    if !expected_guid.to_string().eq_ignore_ascii_case(expected_guid_text) {
        return Ok(Observation::Unknown);
    }

    let (interface_index, interface_luid) = {
        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        let status = unsafe { GetIfTable2(&mut table) };
        if status != 0 {
            if !table.is_null() {
                unsafe {
                    windows_sys::Win32::NetworkManagement::IpHelper::FreeMibTable(table.cast())
                };
            }
            return Err(format!("GetIfTable2 failed while identifying the DNS interface (Windows error {status})."));
        }
        if table.is_null() {
            return Err("GetIfTable2 returned a null DNS interface table.".into());
        }
        let _table = OwnedIpHelperTable(table.cast());

        let count = unsafe { (*table).NumEntries as usize };
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
            let actual_guid = uuid::Uuid::from_u128(guid_to_u128(&row.InterfaceGuid));
            if actual_guid != expected_guid {
                continue;
            }
            if found.is_some() {
                return Err("Windows returned duplicate rows for the recorded DNS interface GUID.".into());
            }
            let luid = unsafe { row.InterfaceLuid.Value };
            if row.InterfaceIndex == 0 || luid == 0 {
                return Err("Windows returned an invalid DNS interface identity.".into());
            }
            found = Some((row.InterfaceIndex, luid));
        }
        let Some(found) = found else {
            return Ok(Observation::Absent);
        };
        found
    };

    // GetInterfaceDnsSettings requires Version only on input and Flags zero.
    // Version 3 is required for complete per-server DoH properties; older
    // systems that cannot return it remain Unknown instead of silently
    // downgrading to a DHCP/static-only representation.
    let mut settings = DNS_INTERFACE_SETTINGS3::default();
    settings.Version = DNS_INTERFACE_SETTINGS_VERSION3;
    settings.Flags = 0;
    let status = unsafe {
        GetInterfaceDnsSettings(
            uuid_to_windows_guid(expected_guid),
            (&mut settings as *mut DNS_INTERFACE_SETTINGS3).cast::<DNS_INTERFACE_SETTINGS>(),
        )
    };
    if status != 0 {
        return Err(format!("GetInterfaceDnsSettings v3 failed with Windows error {status}."));
    }
    let settings_ptr = (&mut settings as *mut DNS_INTERFACE_SETTINGS3).cast::<DNS_INTERFACE_SETTINGS>();
    let _settings = OwnedInterfaceDnsSettings(settings_ptr);

    // The address list provides effective DNS servers (including dynamic
    // configuration); it is deliberately separate from configured and profile
    // name-server lists returned by GetInterfaceDnsSettings.
    let effective = observe_effective_dns_servers(interface_luid)?;
    let is_ipv6 = settings.Flags
        & windows_sys::Win32::NetworkManagement::IpHelper::DNS_SETTING_IPV6 as u64
        != 0;
    let effective_name_servers = if is_ipv6 {
        effective.ipv6
    } else {
        effective.ipv4
    };

    let stack = copy_dns_stack(&settings, effective_name_servers)?;
    let interface = crate::recovery_journal::DnsInterfaceConfiguration {
        interface_guid: expected_guid.to_string(),
        ipv4: (!is_ipv6).then_some(stack.clone()),
        ipv6: is_ipv6.then_some(stack),
    };

    // Keep the current index as a consistency check. Interface GUID is the
    // durable identity and the assessor also compares it before using a result.
    if interface_index == 0 {
        return Ok(Observation::Unknown);
    }

    Ok(Observation::Present(
        crate::recovery_journal::DnsConfiguration::Interface(interface),
    ))
}

#[cfg(windows)]
struct OwnedInterfaceDnsSettings(*mut windows_sys::Win32::NetworkManagement::IpHelper::DNS_INTERFACE_SETTINGS);

#[cfg(windows)]
impl Drop for OwnedInterfaceDnsSettings {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::NetworkManagement::IpHelper::FreeInterfaceDnsSettings(self.0);
            }
        }
    }
}

#[cfg(windows)]
struct EffectiveDnsServers {
    ipv4: Vec<std::net::IpAddr>,
    ipv6: Vec<std::net::IpAddr>,
}

#[cfg(windows)]
fn observe_effective_dns_servers(
    expected_interface_luid: u64,
) -> Result<EffectiveDnsServers, String> {
    use std::collections::BTreeSet;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    const MAX_ADAPTERS: usize = 2048;
    const MAX_DNS_SERVERS: usize = 64;
    const MAX_BUFFER_RETRIES: usize = 3;
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_UNICAST;

    let mut required_size = 0u32;
    let initial_status = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            flags,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut required_size,
        )
    };
    if initial_status != ERROR_BUFFER_OVERFLOW || required_size == 0 {
        return Err(format!(
            "GetAdaptersAddresses size query was inconclusive (Windows error {initial_status})."
        ));
    }

    let mut buffer = vec![0u64; (required_size as usize).div_ceil(std::mem::size_of::<u64>())];
    let mut adapters = std::ptr::null_mut::<IP_ADAPTER_ADDRESSES_LH>();
    let mut completed = false;
    for _ in 0..MAX_BUFFER_RETRIES {
        required_size = (buffer.len() * std::mem::size_of::<u64>()) as u32;
        let status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &mut required_size,
            )
        };
        if status == ERROR_BUFFER_OVERFLOW {
            if required_size == 0 {
                return Err("GetAdaptersAddresses returned an invalid required buffer size.".into());
            }
            buffer.resize(
                (required_size as usize).div_ceil(std::mem::size_of::<u64>()),
                0,
            );
            continue;
        }
        if status != 0 {
            return Err(format!("GetAdaptersAddresses failed with Windows error {status}."));
        }
        adapters = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        completed = true;
        break;
    }
    if !completed || adapters.is_null() {
        return Err("GetAdaptersAddresses did not produce a complete adapter snapshot.".into());
    }

    let mut current = adapters;
    let mut visited = BTreeSet::new();
    let mut matched = None;
    for _ in 0..MAX_ADAPTERS {
        if current.is_null() {
            break;
        }
        if !visited.insert(current as usize) {
            return Err("GetAdaptersAddresses returned a cyclic adapter list.".into());
        }
        let adapter = unsafe { &*current };
        let luid = unsafe { adapter.Luid.Value };
        if luid == expected_interface_luid {
            if matched.is_some() {
                return Err("GetAdaptersAddresses returned duplicate rows for the DNS interface LUID.".into());
            }
            matched = Some(adapter.FirstDnsServerAddress);
        }
        current = adapter.Next;
    }
    if !current.is_null() {
        return Err("The Windows adapter inventory exceeds its safe bound.".into());
    }
    let Some(mut server) = matched else {
        return Err("GetAdaptersAddresses did not return the DNS interface LUID.".into());
    };

    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    let mut all_seen = BTreeSet::new();
    let mut visited_servers = BTreeSet::new();
    for _ in 0..MAX_DNS_SERVERS {
        if server.is_null() {
            break;
        }
        if !visited_servers.insert(server as usize) {
            return Err("GetAdaptersAddresses returned a cyclic DNS server list.".into());
        }
        let entry = unsafe { &*server };
        let address = socket_address_to_ip(&entry.Address)?;
        if !all_seen.insert(address) {
            return Err("GetAdaptersAddresses returned duplicate DNS server addresses.".into());
        }
        if address.is_ipv4() {
            ipv4.push(address);
        } else {
            ipv6.push(address);
        }
        server = entry.Next;
    }
    if !server.is_null() {
        return Err("The DNS server list exceeds its safe bound.".into());
    }

    Ok(EffectiveDnsServers { ipv4, ipv6 })
}

#[cfg(windows)]
fn socket_address_to_ip(
    address: &windows_sys::Win32::Networking::WinSock::SOCKET_ADDRESS,
) -> Result<std::net::IpAddr, String> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
    };

    if address.lpSockaddr.is_null() || address.iSockaddrLength < std::mem::size_of::<u16>() as i32 {
        return Err("Windows returned an invalid DNS socket address.".into());
    }
    let family = unsafe { (*address.lpSockaddr).sa_family };
    match family {
        AF_INET if address.iSockaddrLength as usize >= std::mem::size_of::<SOCKADDR_IN>() => {
            let sockaddr = unsafe { &*(address.lpSockaddr.cast::<SOCKADDR_IN>()) };
            Ok(IpAddr::V4(Ipv4Addr::from(
                unsafe { sockaddr.sin_addr.S_un.S_addr }.to_ne_bytes(),
            )))
        }
        AF_INET6 if address.iSockaddrLength as usize >= std::mem::size_of::<SOCKADDR_IN6>() => {
            let sockaddr = unsafe { &*(address.lpSockaddr.cast::<SOCKADDR_IN6>()) };
            Ok(IpAddr::V6(Ipv6Addr::from(unsafe {
                sockaddr.sin6_addr.u.Byte
            })))
        }
        _ => {
            let _ = std::mem::size_of::<SOCKADDR>();
            Err("Windows returned a DNS socket address with an unsupported family or length.".into())
        }
    }
}

#[cfg(windows)]
fn copy_dns_stack(
    settings: &windows_sys::Win32::NetworkManagement::IpHelper::DNS_INTERFACE_SETTINGS3,
    effective_name_servers: Vec<std::net::IpAddr>,
) -> Result<crate::recovery_journal::DnsStackConfiguration, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        DNS_SERVER_PROPERTY_VERSION1, DnsServerDohProperty,
    };

    const MAX_DNS_PROPERTIES: usize = 8;
    let name_servers_text = unsafe { copy_pwstr(settings.NameServer, 2048)? };
    let profile_servers_text = unsafe { copy_pwstr(settings.ProfileNameServer, 2048)? };
    let domain = unsafe { copy_pwstr(settings.Domain, 512)? };
    let search_list = unsafe { copy_pwstr(settings.SearchList, 4096)? };
    let supplemental_search_list = unsafe { copy_pwstr(settings.SupplementalSearchList, 4096)? };

    let name_servers = parse_dns_ip_list(name_servers_text.as_deref())?;
    let profile_name_servers = parse_dns_ip_list(profile_servers_text.as_deref())?;
    let search_list = parse_dns_name_list(search_list.as_deref())?;
    let supplemental_search_list = parse_dns_name_list(supplemental_search_list.as_deref())?;

    let copy_properties = |count: u32,
                           properties: *const windows_sys::Win32::NetworkManagement::IpHelper::DNS_SERVER_PROPERTY|
     -> Result<Vec<crate::recovery_journal::DnsDohServerProperty>, String> {
        if count as usize > MAX_DNS_PROPERTIES {
            return Err("The Windows DNS-over-HTTPS property array exceeds its safe bound.".into());
        }
        if count == 0 {
            if !properties.is_null() {
                return Err("Windows returned a non-null DNS property array with zero entries.".into());
            }
            return Ok(Vec::new());
        }
        if properties.is_null() {
            return Err("Windows returned a null DNS property array with non-zero entries.".into());
        }
        let rows = unsafe { std::slice::from_raw_parts(properties, count as usize) };
        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            if row.Version != DNS_SERVER_PROPERTY_VERSION1 || row.Type != DnsServerDohProperty {
                return Err("Windows returned an unsupported DNS server property type/version.".into());
            }
            let doh = unsafe { row.Property.DohSettings };
            if doh.is_null() {
                return Err("Windows returned a null DNS-over-HTTPS settings pointer.".into());
            }
            let template = unsafe { copy_pwstr((*doh).Template, 2048)? };
            result.push(crate::recovery_journal::DnsDohServerProperty {
                version: row.Version,
                server_index: row.ServerIndex,
                property_type: row.Type as u32,
                flags: unsafe { (*doh).Flags },
                template,
            });
        }
        Ok(result)
    };

    let server_properties = copy_properties(settings.cServerProperties, settings.ServerProperties)?;
    let profile_server_properties =
        copy_properties(settings.cProfileServerProperties, settings.ProfileServerProperties)?;

    Ok(crate::recovery_journal::DnsStackConfiguration {
        settings_version: settings.Version,
        encrypted_dns_adapter_flags: None,
        name_servers,
        profile_name_servers,
        effective_name_servers,
        domain,
        search_list,
        supplemental_search_list,
        registration_enabled: settings.RegistrationEnabled,
        register_adapter_name: settings.RegisterAdapterName,
        enable_llmnr: settings.EnableLLMNR,
        query_adapter_name: settings.QueryAdapterName,
        disable_unconstrained_queries: settings.DisableUnconstrainedQueries,
        settings_flags: settings.Flags,
        server_properties,
        profile_server_properties,
    })
}

#[cfg(windows)]
unsafe fn copy_pwstr(
    value: windows_sys::core::PWSTR,
    maximum_units: usize,
) -> Result<Option<String>, String> {
    if value.is_null() {
        return Ok(None);
    }
    let mut length = 0usize;
    while length < maximum_units {
        if *value.add(length) == 0 {
            let units = std::slice::from_raw_parts(value, length);
            return String::from_utf16(units)
                .map(Some)
                .map_err(|_| "Windows returned an invalid UTF-16 DNS setting.".to_string());
        }
        length += 1;
    }
    Err("A Windows DNS string exceeded its safe bound or was not terminated.".into())
}

#[cfg(windows)]
fn parse_dns_ip_list(value: Option<&str>) -> Result<Option<Vec<std::net::IpAddr>>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let mut result = Vec::new();
    for token in value.split(|ch: char| ch == ',' || ch.is_ascii_whitespace()).filter(|s| !s.is_empty()) {
        result.push(token.parse().map_err(|_| "Windows returned an invalid DNS server address.".to_string())?);
        if result.len() > 8 {
            return Err("A Windows DNS server list exceeded its safe bound.".into());
        }
    }
    Ok(Some(result))
}

#[cfg(windows)]
fn parse_dns_name_list(value: Option<&str>) -> Result<Option<Vec<String>>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let result: Vec<String> = value
        .split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if result.len() > 32 || result.iter().any(|s| s.len() > 253) {
        return Err("A Windows DNS search list exceeded its safe bound.".into());
    }
    Ok(Some(result))
}

#[cfg(windows)]
fn uuid_to_windows_guid(value: uuid::Uuid) -> windows_sys::core::GUID {
    let bytes = value.as_bytes();
    windows_sys::core::GUID {
        data1: u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
        data2: u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
        data3: u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
        data4: bytes[8..16].try_into().unwrap(),
    }
}

#[cfg(windows)]
/// Observe a recorded TUN adapter and its complete IPv4/IPv6 unicast address
/// inventory. The stable interface GUID selects the adapter; its NET_LUID
/// correlates address-table rows so a reused interface index cannot steal them.
#[cfg(windows)]
pub fn observe_recorded_tunnel_interface(
    expected: &crate::recovery_journal::TunnelInterfaceRecord,
) -> Result<Observation<crate::recovery_journal::TunnelInterfaceRecord>, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, MIB_IF_ROW2, MIB_IF_TABLE2,
    };

    const MAX_INTERFACES: usize = 2048;

    let expected_guid = uuid::Uuid::parse_str(&expected.interface_guid)
        .map_err(|_| "The recorded tunnel GUID is invalid.".to_string())?;
    if !expected_guid.to_string().eq_ignore_ascii_case(&expected.interface_guid) {
        return Ok(Observation::Unknown);
    }

    let found = {
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

            let interface_index = row.InterfaceIndex;
            let interface_luid = unsafe { row.InterfaceLuid.Value };
            if interface_index == 0 || interface_luid == 0 {
                return Err("Windows returned an invalid TUN interface identity.".into());
            }

            let alias_end = row.Alias.iter().position(|unit| *unit == 0)
                .unwrap_or(row.Alias.len());
            let alias = String::from_utf16(&row.Alias[..alias_end])
                .map_err(|_| "Windows returned an invalid tunnel interface alias.".to_string())?;

            found = Some((guid.to_string(), interface_index, interface_luid, alias, row.Mtu));
        }
        found
    };

    let Some((interface_guid, interface_index, interface_luid, alias, mtu)) = found else {
        return Ok(Observation::Absent);
    };

    let address_details = observe_tunnel_unicast_addresses(interface_luid, interface_index)?;
    let addresses = address_details.iter().map(|item| item.address).collect();

    Ok(Observation::Present(
        crate::recovery_journal::TunnelInterfaceRecord {
            interface_guid,
            interface_index,
            alias,
            mtu,
            addresses,
            address_details,
        },
    ))
}

/// Read both IP families in one snapshot. All rows are correlated by NET_LUID;
/// the index is checked only as a live consistency value. Any incomplete,
/// duplicate, oversized, or invalid inventory is an error and therefore Unknown.
#[cfg(windows)]
fn observe_tunnel_unicast_addresses(
    expected_interface_luid: u64,
    expected_interface_index: u32,
) -> Result<Vec<crate::recovery_journal::TunnelAddressRecord>, String> {
    use std::collections::BTreeSet;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetUnicastIpAddressTable, MIB_UNICASTIPADDRESS_ROW,
        MIB_UNICASTIPADDRESS_TABLE,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    const MAX_UNICAST_ADDRESSES: usize = 16_384;
    const MAX_TUN_ADDRESSES: usize = 8;

    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    let status = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) };
    if status != 0 {
        if !table.is_null() {
            unsafe { FreeMibTable(table.cast()) };
        }
        return Err(format!(
            "GetUnicastIpAddressTable failed with Windows error {status}."
        ));
    }
    if table.is_null() {
        return Err("GetUnicastIpAddressTable succeeded without an address table.".into());
    }
    let _table = OwnedIpHelperTable(table.cast());

    let table_ref = unsafe { &*table };
    let count = table_ref.NumEntries as usize;
    if count > MAX_UNICAST_ADDRESSES {
        return Err("The Windows unicast address inventory exceeds its safe bound.".into());
    }

    let rows = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).Table).cast::<MIB_UNICASTIPADDRESS_ROW>(),
            count,
        )
    };

    let mut addresses = Vec::new();
    let mut seen = BTreeSet::new();
    for row in rows {
        let interface_luid = unsafe { row.InterfaceLuid.Value };
        if interface_luid != expected_interface_luid {
            continue;
        }
        if row.InterfaceIndex != expected_interface_index {
            return Err("The TUN unicast address table contains a mismatched interface index.".into());
        }

        let address = sockaddr_address(&row.Address)?;
        let maximum_prefix = if address.is_ipv4() { 32 } else { 128 };
        if row.OnLinkPrefixLength > maximum_prefix {
            return Err("Windows returned an invalid TUN unicast prefix length.".into());
        }
        if !seen.insert(address) {
            return Err("Windows returned a duplicate TUN unicast address.".into());
        }

        addresses.push(crate::recovery_journal::TunnelAddressRecord {
            address,
            prefix_length: row.OnLinkPrefixLength,
        });
        if addresses.len() > MAX_TUN_ADDRESSES {
            return Err("The TUN unicast address inventory exceeds its journal bound.".into());
        }
    }

    addresses.sort_unstable();
    Ok(addresses)
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

        // Interface indexes are reusable. Preserve the kernel NET_LUID so the
        // assessment planner can reject a route that now points at another NIC.
        let interface_luid = unsafe { row.InterfaceLuid.Value };
        if interface_luid == 0 {
            routes.insert(journal_keys[0].clone(), Observation::Unknown);
            continue;
        }
        let state = crate::recovery_journal::RouteState {
            interface_index: row.InterfaceIndex,
            interface_luid: Some(interface_luid),
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
