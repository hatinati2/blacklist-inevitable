//! Read-only machine-wide DNS-over-HTTPS known-server inventory.
//!
//! This is supplemental diagnostic evidence only. It is intentionally separate
//! from per-interface DNS settings and is not consumed by recovery assessment,
//! restore-intent planning, or journal-removal decisions.

use std::collections::BTreeSet;
use std::net::IpAddr;
use url::Url;

pub const DNS_DOH_INVENTORY_SOURCE: &str = "Get-DnsClientDohServerAddress";
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_SERVER_ROWS: usize = 64;
const MAX_SERVER_ADDRESS_BYTES: usize = 64;
const MAX_TEMPLATE_BYTES: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsDohServerInventory {
    /// Identifies the local, machine-wide PowerShell read surface.
    pub source: String,
    /// A successful query may legitimately return an empty known-server list.
    /// Query failure or incomplete output is represented by Err, never empty.
    pub servers: Vec<DnsDohServer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsDohServer {
    /// Exact address string emitted by the Windows provider.
    pub server_address: String,
    /// Parsed address used only for validation and address-equality cross-checks.
    pub address: IpAddr,
    pub doh_template: String,
    pub auto_upgrade: bool,
    pub allow_fallback_to_udp: bool,
    /// CIM type names observed from the returned Windows object.
    pub property_types: DnsDohPropertyTypes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsDohPropertyTypes {
    pub server_address: String,
    pub doh_template: String,
    pub auto_upgrade: String,
    pub allow_fallback_to_udp: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsDohEffectiveAddressMatch {
    pub server_address: String,
    /// Address equality only. This does not associate a DoH entry with an
    /// adapter, profile, NRPT rule, or active resolver configuration.
    pub matches_effective_ipv4_list: bool,
    /// Address equality only. This does not associate a DoH entry with an
    /// adapter, profile, NRPT rule, or active resolver configuration.
    pub matches_effective_ipv6_list: bool,
}

#[derive(Debug, serde::Deserialize)]
struct RawDohSnapshot {
    ok: bool,
    error: Option<String>,
    source: Option<String>,
    rows: Option<Vec<RawDohRow>>,
}

#[derive(Debug, serde::Deserialize)]
struct RawDohRow {
    values: Option<RawDohValues>,
    types: Option<RawDohPropertyTypes>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawDohValues {
    server_address: Option<String>,
    doh_template: Option<String>,
    auto_upgrade: Option<bool>,
    allow_fallback_to_udp: Option<bool>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawDohPropertyTypes {
    server_address: Option<String>,
    doh_template: Option<String>,
    auto_upgrade: Option<String>,
    allow_fallback_to_udp: Option<String>,
}

fn decode_snapshot(bytes: &[u8], process_succeeded: bool) -> Result<RawDohSnapshot, String> {
    if bytes.is_empty() || bytes.len() > MAX_OUTPUT_BYTES {
        return Err("The Windows DoH inventory returned an empty or oversized response.".into());
    }

    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| "The Windows DoH inventory returned malformed JSON.".to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "The Windows DoH inventory response is not an object.".to_string())?;
    for key in ["ok", "error", "source", "rows"] {
        if !object.contains_key(key) {
            return Err(format!("The Windows DoH inventory omitted the required {key} field."));
        }
    }
    if !object.get("rows").is_some_and(serde_json::Value::is_array) {
        return Err("The Windows DoH inventory rows field is not an array.".into());
    }

    let snapshot: RawDohSnapshot = serde_json::from_value(value)
        .map_err(|_| "The Windows DoH inventory did not match its bounded response schema.".to_string())?;
    if !process_succeeded || !snapshot.ok {
        let detail = snapshot.error.unwrap_or_else(|| "provider query failed".into());
        return Err(format!(
            "The read-only Windows DoH inventory query failed: {}",
            detail.chars().take(256).collect::<String>()
        ));
    }
    Ok(snapshot)
}

fn validate_template(raw: &str) -> Result<(), String> {
    if raw.is_empty()
        || raw.len() > MAX_TEMPLATE_BYTES
        || raw.trim() != raw
        || raw.contains('\0')
        || raw.chars().any(char::is_control)
        || raw.contains('#')
    {
        return Err("A Windows DoH URI template is empty, malformed, or oversized.".into());
    }

    // Windows DoH templates commonly use the RFC 6570 {?dns} expression.
    // Replace only the known DNS variables before URL validation; unknown
    // template expressions remain inconclusive rather than being guessed.
    let sanitized = raw.replace("{?dns}", "?dns=").replace("{dns}", "dns");
    if sanitized.contains('{') || sanitized.contains('}') {
        return Err("A Windows DoH URI template contains an unsupported template expression.".into());
    }
    let parsed = Url::parse(&sanitized)
        .map_err(|_| "A Windows DoH URI template is not a valid absolute URL.".to_string())?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err("A Windows DoH URI template must be HTTPS and contain no credentials or fragment.".into());
    }
    Ok(())
}

fn validate_snapshot(
    snapshot: RawDohSnapshot,
    process_succeeded: bool,
) -> Result<DnsDohServerInventory, String> {
    if !process_succeeded || !snapshot.ok {
        let detail = snapshot.error.unwrap_or_else(|| "provider query failed".into());
        return Err(format!(
            "The read-only Windows DoH inventory query failed: {}",
            detail.chars().take(256).collect::<String>()
        ));
    }
    let source = snapshot
        .source
        .ok_or_else(|| "The Windows DoH inventory omitted source provenance.".to_string())?;
    if source != DNS_DOH_INVENTORY_SOURCE {
        return Err("The Windows DoH inventory has unexpected source provenance.".into());
    }
    let rows = snapshot
        .rows
        .ok_or_else(|| "The Windows DoH inventory omitted its result rows.".to_string())?;
    if rows.len() > MAX_SERVER_ROWS {
        return Err("The Windows DoH inventory exceeds its 64-server bound.".into());
    }

    let mut seen_addresses = BTreeSet::new();
    let mut servers = Vec::with_capacity(rows.len());
    for row in rows {
        let values = row
            .values
            .ok_or_else(|| "A Windows DoH row omitted its property values.".to_string())?;
        let types = row
            .types
            .ok_or_else(|| "A Windows DoH row omitted its property type metadata.".to_string())?;

        let server_address = values
            .server_address
            .ok_or_else(|| "A Windows DoH row omitted ServerAddress.".to_string())?;
        if server_address.is_empty()
            || server_address.len() > MAX_SERVER_ADDRESS_BYTES
            || server_address.trim() != server_address
            || server_address.contains('\0')
        {
            return Err("A Windows DoH row contains an invalid or oversized ServerAddress.".into());
        }
        let address: IpAddr = server_address
            .parse()
            .map_err(|_| "A Windows DoH row contains a malformed server IP address.".to_string())?;
        if address.is_unspecified() || address.is_multicast() {
            return Err("A Windows DoH row contains a non-unicast server IP address.".into());
        }
        if !seen_addresses.insert(address) {
            return Err("The Windows DoH inventory contains a duplicate server IP address.".into());
        }

        let doh_template = values
            .doh_template
            .ok_or_else(|| "A Windows DoH row omitted DohTemplate.".to_string())?;
        validate_template(&doh_template)?;
        let auto_upgrade = values
            .auto_upgrade
            .ok_or_else(|| "A Windows DoH row omitted AutoUpgrade.".to_string())?;
        let allow_fallback_to_udp = values
            .allow_fallback_to_udp
            .ok_or_else(|| "A Windows DoH row omitted AllowFallbackToUdp.".to_string())?;

        let property_types = DnsDohPropertyTypes {
            server_address: types
                .server_address
                .ok_or_else(|| "A Windows DoH row omitted the ServerAddress CIM type.".to_string())?,
            doh_template: types
                .doh_template
                .ok_or_else(|| "A Windows DoH row omitted the DohTemplate CIM type.".to_string())?,
            auto_upgrade: types
                .auto_upgrade
                .ok_or_else(|| "A Windows DoH row omitted the AutoUpgrade CIM type.".to_string())?,
            allow_fallback_to_udp: types
                .allow_fallback_to_udp
                .ok_or_else(|| "A Windows DoH row omitted the AllowFallbackToUdp CIM type.".to_string())?,
        };
        if property_types.server_address != "String"
            || property_types.doh_template != "String"
            || property_types.auto_upgrade != "Boolean"
            || property_types.allow_fallback_to_udp != "Boolean"
        {
            return Err("The Windows DoH provider returned an unexpected property type schema.".into());
        }

        servers.push(DnsDohServer {
            server_address,
            address,
            doh_template,
            auto_upgrade,
            allow_fallback_to_udp,
            property_types,
        });
    }

    Ok(DnsDohServerInventory { source, servers })
}

/// Compare known global DoH addresses to one effective resolver list.
/// A positive result records address equality only; it never means this DoH
/// configuration is attached to the adapter or profile exposing that address.
pub fn cross_check_effective_resolver_addresses(
    inventory: &DnsDohServerInventory,
    effective_ipv4: &[IpAddr],
    effective_ipv6: &[IpAddr],
) -> Vec<DnsDohEffectiveAddressMatch> {
    inventory
        .servers
        .iter()
        .map(|server| DnsDohEffectiveAddressMatch {
            server_address: server.server_address.clone(),
            matches_effective_ipv4_list: server.address.is_ipv4()
                && effective_ipv4.contains(&server.address),
            matches_effective_ipv6_list: server.address.is_ipv6()
                && effective_ipv6.contains(&server.address),
        })
        .collect()
}

#[cfg(windows)]
pub fn observe_global_doh_server_inventory() -> Result<DnsDohServerInventory, String> {
    let (process_succeeded, bytes) = windows::run_read_only_query()?;
    let snapshot = decode_snapshot(&bytes, process_succeeded)?;
    validate_snapshot(snapshot, process_succeeded)
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
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

    pub(super) fn run_read_only_query() -> Result<(bool, Vec<u8>), String> {
        let system_root = std::env::var_os("SystemRoot")
            .ok_or_else(|| "The Windows SystemRoot environment variable is unavailable.".to_string())?;
        let system_root = PathBuf::from(system_root);
        if !system_root.is_absolute() {
            return Err("The Windows SystemRoot path is not absolute.".into());
        }
        let powershell = system_root
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        if !powershell.is_file() {
            return Err("The system Windows PowerShell executable is unavailable.".into());
        }

        // Local, read-only query only. No Add-, Set-, or Remove-DoH cmdlet runs.
        let script = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
    $command = Get-Command -Name 'Get-DnsClientDohServerAddress' -CommandType Cmdlet -ErrorAction Stop
    if ($null -eq $command) { throw 'The Get-DnsClientDohServerAddress cmdlet is unavailable.' }
    $items = @(Get-DnsClientDohServerAddress -ErrorAction Stop | Select-Object -First 65)
    $rows = @()
    foreach ($item in $items) {
        $values = [ordered]@{}
        $types = [ordered]@{}
        foreach ($name in @('ServerAddress', 'DohTemplate', 'AutoUpgrade', 'AllowFallbackToUdp')) {
            $property = $null
            foreach ($candidate in @($item.CimInstanceProperties)) {
                if ($candidate.Name -ceq $name) { $property = $candidate; break }
            }
            if ($null -eq $property) {
                foreach ($candidate in @($item.PSObject.Properties)) {
                    if ($candidate.Name -ceq $name) { $property = $candidate; break }
                }
            }
            if ($null -ne $property) {
                $value = $property.Value
                $values[$name] = $value
                if ($null -ne $property.CimType) {
                    $types[$name] = [string]$property.CimType
                } elseif ($null -ne $value) {
                    $types[$name] = [string]$value.GetType().Name
                } else {
                    $types[$name] = $null
                }
            }
        }
        $rows += [pscustomobject]@{
            values = [pscustomobject]$values
            types = [pscustomobject]$types
        }
    }
    $result = [ordered]@{
        ok = $true
        error = $null
        source = 'Get-DnsClientDohServerAddress'
        rows = $rows
    }
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $result -Depth 8 -Compress))
} catch {
    $result = [ordered]@{
        ok = $false
        error = $_.Exception.Message
        source = 'Get-DnsClientDohServerAddress'
        rows = @()
    }
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $result -Depth 8 -Compress))
    exit 2
}
"#;

        let mut child = Command::new(&powershell)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-Command",
            ])
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|error| format!("Could not start the system Windows PowerShell host: {error}"))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "The Windows PowerShell host did not expose its output stream.".to_string())?;
        let reader = thread::spawn(move || {
            let mut limited = stdout.take((MAX_OUTPUT_BYTES + 1) as u64);
            let mut bytes = Vec::new();
            limited.read_to_end(&mut bytes).map(|_| bytes)
        });

        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() < QUERY_TIMEOUT => {
                    thread::sleep(Duration::from_millis(20))
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err("The read-only Windows DoH inventory exceeded its 10-second time limit.".into());
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return Err(format!("Could not monitor the Windows DoH query process: {error}"));
                }
            }
        };

        let bytes = reader
            .join()
            .map_err(|_| "The Windows DoH output reader terminated unexpectedly.".to_string())?
            .map_err(|error| format!("Could not read the Windows DoH response: {error}"))?;
        if bytes.len() > MAX_OUTPUT_BYTES {
            return Err("The Windows DoH response exceeded its 64-KiB output bound.".into());
        }
        Ok((status.success(), bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> RawDohSnapshot {
        RawDohSnapshot {
            ok: true,
            error: None,
            source: Some(DNS_DOH_INVENTORY_SOURCE.into()),
            rows: Some(vec![
                RawDohRow {
                    values: Some(RawDohValues {
                        server_address: Some("1.1.1.1".into()),
                        doh_template: Some("https://cloudflare-dns.com/dns-query{?dns}".into()),
                        auto_upgrade: Some(true),
                        allow_fallback_to_udp: Some(false),
                    }),
                    types: Some(RawDohPropertyTypes {
                        server_address: Some("String".into()),
                        doh_template: Some("String".into()),
                        auto_upgrade: Some("Boolean".into()),
                        allow_fallback_to_udp: Some("Boolean".into()),
                    }),
                },
                RawDohRow {
                    values: Some(RawDohValues {
                        server_address: Some("2606:4700:4700::1111".into()),
                        doh_template: Some("https://cloudflare-dns.com/dns-query".into()),
                        auto_upgrade: Some(false),
                        allow_fallback_to_udp: Some(false),
                    }),
                    types: Some(RawDohPropertyTypes {
                        server_address: Some("String".into()),
                        doh_template: Some("String".into()),
                        auto_upgrade: Some("Boolean".into()),
                        allow_fallback_to_udp: Some("Boolean".into()),
                    }),
                },
            ]),
        }
    }

    #[test]
    fn preserves_ipv4_ipv6_flags_template_and_source_provenance() {
        let inventory = validate_snapshot(fixture(), true).unwrap();
        assert_eq!(inventory.source, DNS_DOH_INVENTORY_SOURCE);
        assert_eq!(inventory.servers.len(), 2);
        assert_eq!(inventory.servers[0].server_address, "1.1.1.1");
        assert!(inventory.servers[0].auto_upgrade);
        assert!(!inventory.servers[0].allow_fallback_to_udp);
        assert_eq!(
            inventory.servers[1].address,
            "2606:4700:4700::1111".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn successful_empty_inventory_is_distinct_from_missing_or_failed_query() {
        let mut snapshot = fixture();
        snapshot.rows = Some(Vec::new());
        assert!(validate_snapshot(snapshot, true).unwrap().servers.is_empty());

        let mut snapshot = fixture();
        snapshot.rows = None;
        assert!(validate_snapshot(snapshot, true).is_err());

        let mut snapshot = fixture();
        snapshot.ok = false;
        snapshot.error = Some("cmdlet unavailable".into());
        assert!(validate_snapshot(snapshot, false).is_err());
    }

    #[test]
    fn rejects_duplicate_or_malformed_server_addresses() {
        let mut snapshot = fixture();
        snapshot.rows.as_mut().unwrap()[1]
            .values
            .as_mut()
            .unwrap()
            .server_address = Some("1.1.1.1".into());
        assert!(validate_snapshot(snapshot, true).is_err());

        let mut snapshot = fixture();
        snapshot.rows.as_mut().unwrap()[0]
            .values
            .as_mut()
            .unwrap()
            .server_address = Some("not-an-ip".into());
        assert!(validate_snapshot(snapshot, true).is_err());
    }

    #[test]
    fn rejects_missing_values_bad_types_and_unsafe_templates() {
        let mut snapshot = fixture();
        snapshot.rows.as_mut().unwrap()[0]
            .values
            .as_mut()
            .unwrap()
            .allow_fallback_to_udp = None;
        assert!(validate_snapshot(snapshot, true).is_err());

        let mut snapshot = fixture();
        snapshot.rows.as_mut().unwrap()[0]
            .types
            .as_mut()
            .unwrap()
            .auto_upgrade = Some("String".into());
        assert!(validate_snapshot(snapshot, true).is_err());

        for template in [
            "http://resolver.example/dns-query",
            "https://user:pass@resolver.example/dns-query",
            "https://resolver.example/dns-query#fragment",
            "https://resolver.example/{unsupported}",
        ] {
            let mut snapshot = fixture();
            snapshot.rows.as_mut().unwrap()[0]
                .values
                .as_mut()
                .unwrap()
                .doh_template = Some(template.into());
            assert!(validate_snapshot(snapshot, true).is_err(), "{template}");
        }
    }

    #[test]
    fn incomplete_schema_and_oversized_output_remain_unknown() {
        assert!(decode_snapshot(br#"{"ok":true,"error":null,"source":"Get-DnsClientDohServerAddress"}"#, true).is_err());
        assert!(decode_snapshot(&vec![b'x'; MAX_OUTPUT_BYTES + 1], true).is_err());
    }

    #[test]
    fn address_match_is_only_a_global_list_cross_check() {
        let inventory = validate_snapshot(fixture(), true).unwrap();
        let v4: IpAddr = "1.1.1.1".parse().unwrap();
        let v6: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        let matches = cross_check_effective_resolver_addresses(&inventory, &[v4], &[v6]);
        assert_eq!(matches.len(), 2);
        assert!(matches[0].matches_effective_ipv4_list);
        assert!(!matches[0].matches_effective_ipv6_list);
        assert!(!matches[1].matches_effective_ipv4_list);
        assert!(matches[1].matches_effective_ipv6_list);
    }

    #[cfg(windows)]
    #[test]
    fn live_read_only_global_doh_inventory_reports_observed_property_schema() {
        let inventory = observe_global_doh_server_inventory()
            .expect("the local Get-DnsClientDohServerAddress read must return a complete bounded result");
        assert_eq!(inventory.source, DNS_DOH_INVENTORY_SOURCE);
        assert!(inventory.servers.len() <= MAX_SERVER_ROWS);
        // A legitimately empty system list is valid. When rows exist, validation
        // above confirms every actual returned name and CIM type.
        for server in &inventory.servers {
            assert_eq!(server.property_types.server_address, "String");
            assert_eq!(server.property_types.doh_template, "String");
            assert_eq!(server.property_types.auto_upgrade, "Boolean");
            assert_eq!(server.property_types.allow_fallback_to_udp, "Boolean");
        }
    }
}
