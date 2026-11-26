//! Read-only WMI corroboration for Windows DNS diagnostics.
//!
//! This module intentionally returns a distinct evidence type. It is not a
//! DnsConfiguration, is not imported by the recovery assessor, and cannot
//! authorize restore intents or journal removal. WMI exposes only a subset of
//! the per-interface DNS state required by the recovery journal.

use std::collections::BTreeSet;
use std::net::IpAddr;

const MAX_WMI_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_SERVER_ROWS: usize = 64;
const MAX_CLIENT_ROWS: usize = 64;
const MAX_GLOBAL_ROWS: usize = 16;
const MAX_SERVERS_PER_FAMILY: usize = 8;
const MAX_SUFFIXES: usize = 32;
const MAX_SUFFIX_BYTES: usize = 253;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsWmiCrossCheck {
    pub interface_guid: String,
    pub interface_luid: u64,
    pub interface_index: u32,
    pub interface_alias: String,
    /// Only families explicitly returned by MSFT_DNSClientServerAddress appear.
    pub server_addresses: Vec<DnsWmiServerFamily>,
    /// WMI client properties are preserved as cross-check evidence, not
    /// translated into the authoritative recovery-journal representation.
    pub client_settings: Vec<DnsWmiClientSettings>,
    /// Global policy remains separate from per-interface configuration.
    pub global_settings: Vec<DnsWmiGlobalSettings>,
    /// True only after every returned WMI family matched the contemporaneous
    /// GetAdaptersAddresses list for the same stable NET_LUID.
    pub effective_server_lists_match: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsWmiServerFamily {
    /// Raw MSFT_DNSClientServerAddress.AddressFamily value (AF_INET=2,
    /// AF_INET6=23). It is retained rather than inferred from interface state.
    pub address_family: u16,
    pub addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsWmiClientSettings {
    pub protocol_if_type: u16,
    pub connection_specific_suffix: Option<String>,
    pub connection_specific_suffix_search_list: Option<Vec<String>>,
    pub register_this_connections_address: Option<bool>,
    pub use_suffix_when_registering: Option<bool>,
    pub dhcp_options_to_use: Option<Vec<u16>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsWmiGlobalSettings {
    pub protocol_if_type: u16,
    pub append_primary_suffixes: Option<bool>,
    pub append_parent_suffixes: Option<bool>,
    pub dns_suffixes_to_append: Option<Vec<String>>,
    pub use_suffix_search_list: Option<bool>,
    pub suffix_search_list: Option<Vec<String>>,
    pub use_devolution: Option<bool>,
    pub devolution_level: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InterfaceIdentity {
    guid: String,
    luid: u64,
    index: u32,
    alias: String,
}

#[derive(Debug, serde::Deserialize)]
struct RawWmiSnapshot {
    ok: bool,
    error: Option<String>,
    #[serde(rename = "serverAddresses")]
    server_addresses: Option<Vec<RawServerAddress>>,
    clients: Option<Vec<RawDnsClient>>,
    #[serde(rename = "globalSettings")]
    global_settings: Option<Vec<RawGlobalSetting>>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawServerAddress {
    interface_index: Option<u32>,
    interface_alias: Option<String>,
    address_family: Option<u16>,
    server_addresses: Option<Vec<String>>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawDnsClient {
    interface_index: Option<u32>,
    interface_alias: Option<String>,
    protocol_if_type: Option<u16>,
    connection_specific_suffix: Option<String>,
    connection_specific_suffix_search_list: Option<Vec<String>>,
    register_this_connections_address: Option<bool>,
    use_suffix_when_registering: Option<bool>,
    dhcp_options_to_use: Option<Vec<u16>>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawGlobalSetting {
    protocol_if_type: Option<u16>,
    append_primary_suffixes: Option<bool>,
    append_parent_suffixes: Option<bool>,
    #[serde(rename = "DNSSuffixesToAppend")]
    dns_suffixes_to_append: Option<Vec<String>>,
    use_suffix_search_list: Option<bool>,
    suffix_search_list: Option<Vec<String>>,
    use_devolution: Option<bool>,
    devolution_level: Option<u32>,
}

fn decode_wmi_snapshot(bytes: &[u8], process_succeeded: bool) -> Result<RawWmiSnapshot, String> {
    if bytes.is_empty() || bytes.len() > MAX_WMI_OUTPUT_BYTES {
        return Err("The DNS WMI provider returned an empty or oversized response.".into());
    }

    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| "The DNS WMI provider returned malformed JSON.".to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "The DNS WMI provider returned a non-object response.".to_string())?;
    for key in ["ok", "serverAddresses", "clients", "globalSettings"] {
        if !object.contains_key(key) {
            return Err(format!("The DNS WMI response omitted the required {key} field."));
        }
    }

    let snapshot: RawWmiSnapshot = serde_json::from_value(value)
        .map_err(|_| "The DNS WMI response did not match the expected bounded schema.".to_string())?;
    if !process_succeeded || !snapshot.ok {
        let detail = snapshot.error.unwrap_or_else(|| "provider query failed".into());
        return Err(format!("The read-only DNS WMI query failed: {}", detail.chars().take(256).collect::<String>()));
    }
    if snapshot.server_addresses.is_none()
        || snapshot.clients.is_none()
        || snapshot.global_settings.is_none()
    {
        return Err("The DNS WMI response omitted one or more result inventories.".into());
    }
    Ok(snapshot)
}

fn validate_suffix_list(values: &Option<Vec<String>>, field: &str) -> Result<(), String> {
    if let Some(values) = values {
        if values.len() > MAX_SUFFIXES {
            return Err(format!("The DNS WMI {field} exceeds its safe entry bound."));
        }
        for value in values {
            if value.len() > MAX_SUFFIX_BYTES || value.contains('\0') {
                return Err(format!("The DNS WMI {field} contains an invalid or oversized value."));
            }
        }
    }
    Ok(())
}

fn is_supported_protocol_if_type(value: u16) -> bool {
    // MSFT_DNSClient documents 4096 (IPv4), 4097 (IPv6), and 4098 (IPv4/v6).
    matches!(value, 4096 | 4097 | 4098)
}

fn validate_snapshot(
    snapshot: RawWmiSnapshot,
    identity: &InterfaceIdentity,
    native_ipv4: &[IpAddr],
    native_ipv6: &[IpAddr],
) -> Result<DnsWmiCrossCheck, String> {
    let server_rows = snapshot.server_addresses
        .ok_or_else(|| "The DNS WMI server-address inventory is missing.".to_string())?;
    let client_rows = snapshot.clients
        .ok_or_else(|| "The DNS WMI client inventory is missing.".to_string())?;
    let global_rows = snapshot.global_settings
        .ok_or_else(|| "The DNS WMI global-settings inventory is missing.".to_string())?;

    if server_rows.is_empty() || server_rows.len() > MAX_SERVER_ROWS {
        return Err("The DNS WMI server-address inventory is empty or exceeds its safe bound.".into());
    }
    if client_rows.is_empty() || client_rows.len() > MAX_CLIENT_ROWS {
        return Err("The DNS WMI client inventory is empty or exceeds its safe bound.".into());
    }
    if global_rows.len() > MAX_GLOBAL_ROWS {
        return Err("The DNS WMI global-settings inventory exceeds its safe bound.".into());
    }

    let mut seen_families = BTreeSet::new();
    let mut all_servers = BTreeSet::new();
    let mut server_addresses = Vec::with_capacity(server_rows.len());
    for row in server_rows {
        if row.interface_index != Some(identity.index)
            || row.interface_alias.as_deref() != Some(identity.alias.as_str())
        {
            return Err("The DNS WMI server-address row does not match the contemporaneous interface index and alias.".into());
        }

        let family = row.address_family
            .ok_or_else(|| "The DNS WMI server-address row omitted AddressFamily.".to_string())?;
        let expected_v4 = match family {
            2 => true,
            23 => false,
            _ => return Err("The DNS WMI server-address row returned an unsupported address family.".into()),
        };
        if !seen_families.insert(family) {
            return Err("The DNS WMI server-address inventory contains a duplicate family row.".into());
        }

        let raw_addresses = row.server_addresses
            .ok_or_else(|| "The DNS WMI server-address row omitted ServerAddresses.".to_string())?;
        if raw_addresses.len() > MAX_SERVERS_PER_FAMILY {
            return Err("The DNS WMI server-address row exceeds its safe address bound.".into());
        }

        let mut addresses = Vec::with_capacity(raw_addresses.len());
        for raw in raw_addresses {
            if raw.is_empty() || raw.len() > 64 || raw.contains('\0') {
                return Err("The DNS WMI server-address row contains an invalid address string.".into());
            }
            let address: IpAddr = raw.parse()
                .map_err(|_| "The DNS WMI server-address row contains a malformed IP address.".to_string())?;
            if address.is_ipv4() != expected_v4 {
                return Err("The DNS WMI AddressFamily disagrees with a returned server address.".into());
            }
            if !all_servers.insert(address) {
                return Err("The DNS WMI server-address inventory contains a duplicate address.".into());
            }
            addresses.push(address);
        }

        server_addresses.push(DnsWmiServerFamily { address_family: family, addresses });
    }

    let native_v4: BTreeSet<_> = native_ipv4.iter().copied().collect();
    let native_v6: BTreeSet<_> = native_ipv6.iter().copied().collect();
    for row in &server_addresses {
        let observed: BTreeSet<_> = row.addresses.iter().copied().collect();
        let native = if row.address_family == 2 { &native_v4 } else { &native_v6 };
        if &observed != native {
            return Err("The DNS WMI server list disagrees with the contemporaneous GetAdaptersAddresses snapshot.".into());
        }
    }

    let mut seen_client_protocols = BTreeSet::new();
    let mut client_settings = Vec::with_capacity(client_rows.len());
    for row in client_rows {
        if row.interface_index != Some(identity.index)
            || row.interface_alias.as_deref() != Some(identity.alias.as_str())
        {
            return Err("The DNS WMI client row does not match the contemporaneous interface index and alias.".into());
        }
        let protocol = row.protocol_if_type
            .ok_or_else(|| "The DNS WMI client row omitted ProtocolIFType.".to_string())?;
        if !is_supported_protocol_if_type(protocol) || !seen_client_protocols.insert(protocol) {
            return Err("The DNS WMI client inventory contains an unsupported or duplicate protocol row.".into());
        }
        if row.connection_specific_suffix.as_ref().is_some_and(|v| v.len() > MAX_SUFFIX_BYTES || v.contains('\0')) {
            return Err("The DNS WMI connection suffix is malformed or oversized.".into());
        }
        validate_suffix_list(&row.connection_specific_suffix_search_list, "connection suffix list")?;
        if row.dhcp_options_to_use.as_ref().is_some_and(|v| v.len() > 32) {
            return Err("The DNS WMI DHCP option list exceeds its safe bound.".into());
        }

        client_settings.push(DnsWmiClientSettings {
            protocol_if_type: protocol,
            connection_specific_suffix: row.connection_specific_suffix,
            connection_specific_suffix_search_list: row.connection_specific_suffix_search_list,
            register_this_connections_address: row.register_this_connections_address,
            use_suffix_when_registering: row.use_suffix_when_registering,
            dhcp_options_to_use: row.dhcp_options_to_use,
        });
    }

    let mut seen_global_protocols = BTreeSet::new();
    let mut global_settings = Vec::with_capacity(global_rows.len());
    for row in global_rows {
        let protocol = row.protocol_if_type
            .ok_or_else(|| "The DNS WMI global-settings row omitted ProtocolIFType.".to_string())?;
        if !is_supported_protocol_if_type(protocol) || !seen_global_protocols.insert(protocol) {
            return Err("The DNS WMI global-settings inventory contains an unsupported or duplicate protocol row.".into());
        }
        validate_suffix_list(&row.dns_suffixes_to_append, "global suffix list")?;
        validate_suffix_list(&row.suffix_search_list, "global suffix search list")?;
        global_settings.push(DnsWmiGlobalSettings {
            protocol_if_type: protocol,
            append_primary_suffixes: row.append_primary_suffixes,
            append_parent_suffixes: row.append_parent_suffixes,
            dns_suffixes_to_append: row.dns_suffixes_to_append,
            use_suffix_search_list: row.use_suffix_search_list,
            suffix_search_list: row.suffix_search_list,
            use_devolution: row.use_devolution,
            devolution_level: row.devolution_level,
        });
    }

    Ok(DnsWmiCrossCheck {
        interface_guid: identity.guid.clone(),
        interface_luid: identity.luid,
        interface_index: identity.index,
        interface_alias: identity.alias.clone(),
        server_addresses,
        client_settings,
        global_settings,
        effective_server_lists_match: true,
    })
}

/// Query the documented root\StandardCimv2 DNS Client classes for one journaled
/// interface. The result is diagnostic evidence only; it is not a recovery
/// snapshot and is never inserted into RecoverySnapshot.
#[cfg(windows)]
pub fn observe_recorded_dns_wmi(
    expected: &crate::recovery_journal::DnsMutationRecord,
) -> Result<DnsWmiCrossCheck, String> {
    let identity_before = windows::find_interface_identity(expected)?;
    let (process_succeeded, bytes) = windows::run_read_only_query(identity_before.index)?;
    let snapshot = decode_wmi_snapshot(&bytes, process_succeeded)?;

    // Read the stable identity again after the WMI query. An index reuse,
    // adapter removal, LUID change, GUID change, or alias change is rejected.
    let identity_after = windows::find_interface_identity(expected)?;
    if identity_before != identity_after {
        return Err("The DNS interface identity changed during the WMI query.".into());
    }

    let effective = crate::recovery_observer::observe_effective_dns_servers(identity_before.luid)?;
    validate_snapshot(snapshot, &identity_before, &effective.ipv4, &effective.ipv6)
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::io::Read;
    use std::os::windows::process::CommandExt;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, MIB_IF_ROW2, MIB_IF_TABLE2,
    };
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    const MAX_INTERFACES: usize = 2048;
    const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

    pub(super) fn find_interface_identity(
        expected: &crate::recovery_journal::DnsMutationRecord,
    ) -> Result<InterfaceIdentity, String> {
        let guid_text = expected.interface_guid.as_deref()
            .ok_or_else(|| "The DNS journal record has no stable interface GUID.".to_string())?;
        let expected_guid = uuid::Uuid::parse_str(guid_text)
            .map_err(|_| "The DNS journal interface GUID is malformed.".to_string())?;
        if !expected_guid.to_string().eq_ignore_ascii_case(guid_text) {
            return Err("The DNS journal interface GUID is not canonical.".into());
        }

        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        let status = unsafe { GetIfTable2(&mut table) };
        if status != 0 {
            if !table.is_null() {
                unsafe { FreeMibTable(table.cast()) };
            }
            return Err(format!("GetIfTable2 failed while correlating DNS WMI data (Windows error {status})."));
        }
        if table.is_null() {
            return Err("GetIfTable2 returned a null interface inventory.".into());
        }
        struct TableGuard(*mut MIB_IF_TABLE2);
        impl Drop for TableGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe { FreeMibTable(self.0.cast()) };
                }
            }
        }
        let _guard = TableGuard(table);

        let count = unsafe { (*table).NumEntries as usize };
        if count == 0 || count > MAX_INTERFACES {
            return Err("The Windows interface inventory is empty or exceeds its safe bound.".into());
        }
        let rows = unsafe {
            std::slice::from_raw_parts(
                std::ptr::addr_of!((*table).Table).cast::<MIB_IF_ROW2>(),
                count,
            )
        };

        let mut found: Option<InterfaceIdentity> = None;
        for row in rows {
            let guid = uuid::Uuid::from_u128(guid_to_u128(&row.InterfaceGuid));
            if guid != expected_guid {
                continue;
            }
            if found.is_some() {
                return Err("GetIfTable2 returned duplicate rows for the journaled interface GUID.".into());
            }
            let index = row.InterfaceIndex;
            let luid = unsafe { row.InterfaceLuid.Value };
            if index == 0 || luid == 0 || expected.interface_index != index {
                return Err("The journaled DNS interface index is stale or inconsistent with its stable GUID.".into());
            }
            let alias_end = row.Alias.iter().position(|unit| *unit == 0)
                .ok_or_else(|| "GetIfTable2 returned an unterminated interface alias.".to_string())?;
            if alias_end == 0 {
                return Err("GetIfTable2 returned an empty interface alias.".into());
            }
            let alias = String::from_utf16(&row.Alias[..alias_end])
                .map_err(|_| "GetIfTable2 returned an invalid UTF-16 interface alias.".to_string())?;

            if rows.iter().filter(|other| other.InterfaceIndex == index).count() != 1
                || rows.iter().filter(|other| unsafe { other.InterfaceLuid.Value } == luid).count() != 1
            {
                return Err("The Windows interface inventory contains an ambiguous index or NET_LUID.".into());
            }
            found = Some(InterfaceIdentity {
                guid: guid.to_string(),
                luid,
                index,
                alias,
            });
        }
        found.ok_or_else(|| "The journaled DNS interface GUID is not present in GetIfTable2.".into())
    }

    pub(super) fn guid_to_u128(value: &windows_sys::core::GUID) -> u128 {
        ((value.data1 as u128) << 96)
            | ((value.data2 as u128) << 80)
            | ((value.data3 as u128) << 64)
            | (u64::from_be_bytes(value.data4) as u128)
    }

    pub(super) fn run_read_only_query(interface_index: u32) -> Result<(bool, Vec<u8>), String> {
        let system_root = std::env::var_os("SystemRoot")
            .ok_or_else(|| "The Windows SystemRoot environment variable is unavailable.".to_string())?;
        let system_root = PathBuf::from(system_root);
        if !system_root.is_absolute() {
            return Err("The Windows SystemRoot path is not absolute.".into());
        }
        let powershell = system_root.join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        if !powershell.is_file() {
            return Err("The system Windows PowerShell executable is unavailable.".into());
        }

        // The only interpolated value is a validated u32 from GetIfTable2.
        // The script calls Get-CimInstance only; it never invokes WMI methods,
        // PowerShell setters, registry writes, or DNS mutation commands.
        let script = format!(r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {{
    $namespace = 'root/StandardCimv2'
    $serverAddresses = @(Get-CimInstance -Namespace $namespace -ClassName 'MSFT_DNSClientServerAddress' -Filter 'InterfaceIndex = {interface_index}' -ErrorAction Stop | Select-Object -First 65 -Property InterfaceIndex,InterfaceAlias,AddressFamily,ServerAddresses)
    $clients = @(Get-CimInstance -Namespace $namespace -ClassName 'MSFT_DNSClient' -Filter 'InterfaceIndex = {interface_index}' -ErrorAction Stop | Select-Object -First 65 -Property InterfaceIndex,InterfaceAlias,ProtocolIFType,ConnectionSpecificSuffix,ConnectionSpecificSuffixSearchList,RegisterThisConnectionsAddress,UseSuffixWhenRegistering,DHCPOptionsToUse)
    $globalSettings = @(Get-CimInstance -Namespace $namespace -ClassName 'MSFT_DNSClientGlobalSetting' -ErrorAction Stop | Select-Object -First 17 -Property ProtocolIFType,AppendPrimarySuffixes,AppendParentSuffixes,DNSSuffixesToAppend,UseSuffixSearchList,SuffixSearchList,UseDevolution,DevolutionLevel)
    $result = [ordered]@{{ ok = $true; error = $null; serverAddresses = $serverAddresses; clients = $clients; globalSettings = $globalSettings }}
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $result -Depth 6 -Compress))
}} catch {{
    $result = [ordered]@{{ ok = $false; error = $_.Exception.Message; serverAddresses = @(); clients = @(); globalSettings = @() }}
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $result -Depth 6 -Compress))
    exit 2
}}
"#);

        let mut child = Command::new(&powershell)
            .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command"])
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|error| format!("Could not start the system Windows PowerShell host: {error}"))?;

        let stdout = child.stdout.take()
            .ok_or_else(|| "The Windows PowerShell host did not expose its output stream.".to_string())?;
        let reader = thread::spawn(move || {
            let mut limited = stdout.take((MAX_WMI_OUTPUT_BYTES + 1) as u64);
            let mut bytes = Vec::new();
            limited.read_to_end(&mut bytes).map(|_| bytes)
        });

        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() < QUERY_TIMEOUT => thread::sleep(Duration::from_millis(20)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err("The read-only DNS WMI query exceeded its 10-second time limit.".into());
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err(format!("Could not monitor the DNS WMI query process: {error}"));
                }
            }
        };

        let bytes = reader.join()
            .map_err(|_| "The DNS WMI output reader terminated unexpectedly.".to_string())?
            .map_err(|error| format!("Could not read the DNS WMI response: {error}"))?;
        if bytes.len() > MAX_WMI_OUTPUT_BYTES {
            return Err("The DNS WMI response exceeded its 64-KiB output bound.".into());
        }
        Ok((status.success(), bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> InterfaceIdentity {
        InterfaceIdentity {
            guid: "11111111-2222-3333-4444-555555555555".into(),
            luid: 0x1234,
            index: 7,
            alias: "Ethernet".into(),
        }
    }

    fn raw_snapshot() -> RawWmiSnapshot {
        RawWmiSnapshot {
            ok: true,
            error: None,
            server_addresses: Some(vec![
                RawServerAddress {
                    interface_index: Some(7),
                    interface_alias: Some("Ethernet".into()),
                    address_family: Some(2),
                    server_addresses: Some(vec!["192.0.2.53".into()]),
                },
                RawServerAddress {
                    interface_index: Some(7),
                    interface_alias: Some("Ethernet".into()),
                    address_family: Some(23),
                    server_addresses: Some(vec!["2001:db8::53".into()]),
                },
            ]),
            clients: Some(vec![
                RawDnsClient {
                    interface_index: Some(7),
                    interface_alias: Some("Ethernet".into()),
                    protocol_if_type: Some(4098),
                    connection_specific_suffix: Some("corp.example".into()),
                    connection_specific_suffix_search_list: Some(vec!["corp.example".into()]),
                    register_this_connections_address: Some(true),
                    use_suffix_when_registering: Some(false),
                    dhcp_options_to_use: Some(vec![8, 14, 17]),
                },
            ]),
            global_settings: Some(vec![
                RawGlobalSetting {
                    protocol_if_type: Some(4096),
                    append_primary_suffixes: Some(true),
                    append_parent_suffixes: Some(false),
                    dns_suffixes_to_append: Some(vec!["global.example".into()]),
                    use_suffix_search_list: Some(true),
                    suffix_search_list: Some(vec!["global.example".into()]),
                    use_devolution: Some(false),
                    devolution_level: Some(0),
                },
            ]),
        }
    }

    #[test]
    fn preserves_ipv4_ipv6_and_separates_global_policy() {
        let v4: IpAddr = "192.0.2.53".parse().unwrap();
        let v6: IpAddr = "2001:db8::53".parse().unwrap();
        let result = validate_snapshot(raw_snapshot(), &identity(), &[v4], &[v6]).unwrap();
        assert_eq!(result.server_addresses.len(), 2);
        assert_eq!(result.client_settings.len(), 1);
        assert_eq!(result.global_settings.len(), 1);
        assert_eq!(result.global_settings[0].suffix_search_list.as_ref().unwrap(), &vec!["global.example".to_string()]);
        assert!(result.effective_server_lists_match);
    }

    #[test]
    fn rejects_stale_index_or_alias() {
        let mut snapshot = raw_snapshot();
        snapshot.server_addresses.as_mut().unwrap()[0].interface_index = Some(8);
        let v4: IpAddr = "192.0.2.53".parse().unwrap();
        let v6: IpAddr = "2001:db8::53".parse().unwrap();
        assert!(validate_snapshot(snapshot, &identity(), &[v4], &[v6]).is_err());

        let mut snapshot = raw_snapshot();
        snapshot.clients.as_mut().unwrap()[0].interface_alias = Some("Renamed".into());
        assert!(validate_snapshot(snapshot, &identity(), &[v4], &[v6]).is_err());
    }

    #[test]
    fn rejects_duplicate_families_and_oversized_inventories() {
        let mut snapshot = raw_snapshot();
        let duplicate = snapshot.server_addresses.as_ref().unwrap()[0].clone();
        snapshot.server_addresses.as_mut().unwrap().push(duplicate);
        let v4: IpAddr = "192.0.2.53".parse().unwrap();
        let v6: IpAddr = "2001:db8::53".parse().unwrap();
        assert!(validate_snapshot(snapshot, &identity(), &[v4], &[v6]).is_err());

        let mut snapshot = raw_snapshot();
        snapshot.clients = Some((0..=MAX_CLIENT_ROWS).map(|_| RawDnsClient {
            interface_index: Some(7),
            interface_alias: Some("Ethernet".into()),
            protocol_if_type: Some(4098),
            connection_specific_suffix: None,
            connection_specific_suffix_search_list: None,
            register_this_connections_address: None,
            use_suffix_when_registering: None,
            dhcp_options_to_use: None,
        }).collect());
        assert!(validate_snapshot(snapshot, &identity(), &[v4], &[v6]).is_err());
    }

    #[test]
    fn rejects_native_disagreement_and_malformed_addresses() {
        let snapshot = raw_snapshot();
        let v4: IpAddr = "192.0.2.54".parse().unwrap();
        let v6: IpAddr = "2001:db8::53".parse().unwrap();
        assert!(validate_snapshot(snapshot, &identity(), &[v4], &[v6]).is_err());

        let mut snapshot = raw_snapshot();
        snapshot.server_addresses.as_mut().unwrap()[0].server_addresses = Some(vec!["not-an-ip".into()]);
        let v4: IpAddr = "192.0.2.53".parse().unwrap();
        assert!(validate_snapshot(snapshot, &identity(), &[v4], &[v6]).is_err());
    }

    #[test]
    fn incomplete_or_failed_provider_response_is_unknown_to_this_layer() {
        assert!(decode_wmi_snapshot(br#"{"ok":true,"clients":[],"globalSettings":[]}"#, true).is_err());
        assert!(decode_wmi_snapshot(br#"{"ok":false,"error":"access denied","serverAddresses":[],"clients":[],"globalSettings":[]}"#, false).is_err());
        assert!(decode_wmi_snapshot(&vec![b'x'; MAX_WMI_OUTPUT_BYTES + 1], true).is_err());
    }

    #[test]
    fn partial_family_inventory_does_not_synthesize_the_missing_family() {
        let mut snapshot = raw_snapshot();
        snapshot.server_addresses = Some(vec![RawServerAddress {
            interface_index: Some(7),
            interface_alias: Some("Ethernet".into()),
            address_family: Some(23),
            server_addresses: Some(vec!["2001:db8::53".into()]),
        }]);
        let v6: IpAddr = "2001:db8::53".parse().unwrap();
        let result = validate_snapshot(snapshot, &identity(), &[], &[v6]).unwrap();
        assert_eq!(result.server_addresses.len(), 1);
        assert_eq!(result.server_addresses[0].address_family, 23);
    }

    #[cfg(windows)]
    #[test]
    fn live_read_only_dns_wmi_cross_check_matches_a_current_adapter() {
        use crate::recovery_journal::{DnsConfiguration, DnsMutationRecord};
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetIfTable2, MIB_IF_ROW2, MIB_IF_TABLE2,
        };

        let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
        let status = unsafe { GetIfTable2(&mut table) };
        assert_eq!(status, 0, "GetIfTable2 failed with Windows error {status}");
        assert!(!table.is_null(), "GetIfTable2 returned a null table");
        struct Guard(*mut MIB_IF_TABLE2);
        impl Drop for Guard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe {
                        windows_sys::Win32::NetworkManagement::IpHelper::FreeMibTable(self.0.cast())
                    };
                }
            }
        }
        let _guard = Guard(table);
        let count = unsafe { (*table).NumEntries as usize };
        assert!(count <= 2048);
        let rows = unsafe {
            std::slice::from_raw_parts(std::ptr::addr_of!((*table).Table).cast::<MIB_IF_ROW2>(), count)
        };

        let mut success = None;
        let mut errors = Vec::new();
        for row in rows {
            let index = row.InterfaceIndex;
            let luid = unsafe { row.InterfaceLuid.Value };
            if index == 0 || luid == 0 {
                continue;
            }
            let guid = uuid::Uuid::from_u128(super::windows::guid_to_u128(&row.InterfaceGuid)).to_string();
            let record = DnsMutationRecord {
                interface_index: index,
                interface_guid: Some(guid.clone()),
                applied: DnsConfiguration::Dhcp,
                previous: DnsConfiguration::Dhcp,
            };
            match super::observe_recorded_dns_wmi(&record) {
                Ok(result) => {
                    assert_eq!(result.interface_guid, guid);
                    assert_eq!(result.interface_luid, luid);
                    assert_eq!(result.interface_index, index);
                    assert!(result.effective_server_lists_match);
                    success = Some(result);
                    break;
                }
                Err(error) if errors.len() < 8 => errors.push(error),
                Err(_) => {}
            }
        }
        assert!(
            success.is_some(),
            "No Windows interface produced a complete bounded WMI cross-check: {}",
            errors.join(" | ")
        );
    }
}
