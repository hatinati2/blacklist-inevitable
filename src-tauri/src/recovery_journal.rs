//! Crash-recovery journal for resources owned by the privileged Windows VPN agent.
//!
//! The store is deliberately independent from the Tauri UI. The caller must place
//! its directory under a service-owned location whose ACL denies modification to
//! ordinary users. This module never creates that directory or changes its ACL.
//! A committed journal contains resource identities and previous network settings,
//! never credentials, profile URLs, engine JSON, or arbitrary filesystem paths.
//!
//! Network mutation must not begin until the first checkpoint has been persisted.
//! A journal may be removed only after the caller has verified that every resource
//! recorded by the session has been stopped or restored.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

pub const RECOVERY_JOURNAL_VERSION: u16 = 1;
pub const MAX_RECOVERY_JOURNAL_BYTES: u64 = 256 * 1024;

const MAX_ROUTES: usize = 128;
const MAX_DNS_INTERFACES: usize = 32;
const MAX_DNS_SERVERS: usize = 8;
const MAX_TUN_ADDRESSES: usize = 8;
const MAX_FIREWALL_FILTERS: usize = 256;
const MAX_INTERFACE_ALIAS_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JournalPhase {
    Preparing,
    EngineStarted,
    TunnelCreated,
    NetworkConfigured,
    Disconnecting,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EngineProcessRecord {
    /// PID is paired with the kernel process creation timestamp to avoid PID reuse.
    pub process_id: u32,
    /// Windows FILETIME creation value, in 100-nanosecond ticks since 1601-01-01.
    pub creation_time_100ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TunnelAddressRecord {
    /// Assigned IPv4 or IPv6 unicast address.
    pub address: IpAddr,
    /// On-link prefix length returned by the Windows unicast address table.
    pub prefix_length: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TunnelInterfaceRecord {
    /// The stable adapter GUID, not a user-controlled interface alias.
    pub interface_guid: String,
    pub interface_index: u32,
    pub alias: String,
    pub mtu: u32,
    /// Compatibility address list retained for existing version-1 journals.
    pub addresses: Vec<IpAddr>,
    /// Complete address/prefix identities. Empty only in legacy journals that
    /// predate address-prefix recording; those journals are never fully verified.
    #[serde(default)]
    pub address_details: Vec<TunnelAddressRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteState {
    /// Current Windows interface index; diagnostic only because indexes can be reused.
    pub interface_index: u32,
    /// Stable NET_LUID identity of the interface. Legacy journals omit this and
    /// must remain Unknown during reconciliation rather than trusting an index.
    #[serde(default)]
    pub interface_luid: Option<u64>,
    pub next_hop: Option<IpAddr>,
    pub metric: u32,
    /// Raw NL_ROUTE_PROTOCOL value returned by Windows. Unknown values are retained.
    /// Legacy journals omit this and must remain Unknown during reconciliation.
    #[serde(default)]
    pub protocol: Option<i32>,
    /// Raw NL_ROUTE_ORIGIN value returned by Windows. Unknown values are retained.
    /// Legacy journals omit this and must remain Unknown during reconciliation.
    #[serde(default)]
    pub origin: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteMutationRecord {
    /// IPv4 or IPv6 destination prefix, for example "0.0.0.0/0".
    pub destination_prefix: String,
    /// Exact state applied by this session.
    pub applied: RouteState,
    /// Exact prior state to restore; None means this session created the route.
    pub previous: Option<RouteState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsDohServerProperty {
    /// DNS_SERVER_PROPERTY_VERSION1.
    pub version: u32,
    /// Index into the matching adapter or profile name-server list.
    pub server_index: u32,
    /// DnsServerDohProperty; unknown property types are never discarded.
    pub property_type: u32,
    /// Exact DNS_DOH_SERVER_SETTINGS flags returned by Windows.
    pub flags: u64,
    /// Explicit HTTPS URI template; None is valid for auto/disengaged policy.
    pub template: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsStackConfiguration {
    /// Version of DNS_INTERFACE_SETTINGS returned by the observer (3 or 4).
    pub settings_version: u32,
    /// Present only when a documented/verified v4 settings structure was read.
    #[serde(default)]
    pub encrypted_dns_adapter_flags: Option<u32>,
    /// Raw adapter-configured name servers for this stack. None means Windows
    /// did not return an explicit static list (for example DHCP/automatic).
    pub name_servers: Option<Vec<IpAddr>>,
    /// Profile-specific name servers are kept separate from adapter servers.
    pub profile_name_servers: Option<Vec<IpAddr>>,
    /// Effective resolver addresses observed for this stack, including dynamic
    /// configuration. This is distinct from static and profile configuration.
    pub effective_name_servers: Vec<IpAddr>,
    pub domain: Option<String>,
    pub search_list: Option<Vec<String>>,
    pub supplemental_search_list: Option<Vec<String>>,
    pub registration_enabled: u32,
    pub register_adapter_name: u32,
    pub enable_llmnr: u32,
    pub query_adapter_name: u32,
    pub disable_unconstrained_queries: u32,
    /// Adapter settings flags returned by Windows, preserved for exact comparison.
    pub settings_flags: u64,
    pub server_properties: Vec<DnsDohServerProperty>,
    pub profile_server_properties: Vec<DnsDohServerProperty>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsInterfaceConfiguration {
    /// Stable adapter GUID. Interface indexes are diagnostic only.
    pub interface_guid: String,
    /// None means the observer could not establish a complete stack snapshot.
    pub ipv4: Option<DnsStackConfiguration>,
    pub ipv6: Option<DnsStackConfiguration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "servers", rename_all = "camelCase")]
pub enum DnsConfiguration {
    /// Legacy version-1 representation retained for backward deserialization.
    Dhcp,
    Static(Vec<IpAddr>),
    /// Complete dual-stack configuration. Both stack snapshots are required
    /// before recovery assessment can positively compare or restore DNS.
    Interface(DnsInterfaceConfiguration),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsMutationRecord {
    pub interface_index: u32,
    /// Stable adapter identity. Missing only in legacy version-1 journals.
    #[serde(default)]
    pub interface_guid: Option<String>,
    pub applied: DnsConfiguration,
    pub previous: DnsConfiguration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FirewallFilterRecord {
    /// GUID identifying the WFP provider created/owned by this agent.
    pub provider_key: String,
    /// Stable key assigned to the exact WFP filter; preferred for read-back and deletion.
    /// None is accepted only for legacy journals created before this field existed.
    #[serde(default)]
    pub filter_key: Option<String>,
    pub layer_key: String,
    /// Runtime ID returned by BFE. Useful for diagnostics, but not a durable identity.
    pub filter_id: u64,
}

/// A non-secret snapshot of resources owned or changed by one VPN session.
///
/// The schema intentionally has no credential, profile, command-line, config
/// content, executable path, or arbitrary path field. Additions must preserve
/// that boundary and remain bounded by validate().
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryJournal {
    pub version: u16,
    pub session_id: u64,
    /// Monotonically increasing checkpoint number within this session.
    pub revision: u64,
    pub phase: JournalPhase,
    pub engine: Option<EngineProcessRecord>,
    pub tunnel: Option<TunnelInterfaceRecord>,
    pub routes: Vec<RouteMutationRecord>,
    pub dns: Vec<DnsMutationRecord>,
    pub firewall_filters: Vec<FirewallFilterRecord>,
}

impl RecoveryJournal {
    pub fn new(session_id: u64) -> Self {
        Self {
            version: RECOVERY_JOURNAL_VERSION,
            session_id,
            revision: 1,
            phase: JournalPhase::Preparing,
            engine: None,
            tunnel: None,
            routes: Vec::new(),
            dns: Vec::new(),
            firewall_filters: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != RECOVERY_JOURNAL_VERSION {
            return Err("The recovery journal version is not supported.".to_string());
        }
        if self.session_id == 0 || self.revision == 0 {
            return Err("The recovery journal session and revision must be non-zero.".to_string());
        }
        if let Some(engine) = &self.engine {
            if engine.process_id == 0 || engine.creation_time_100ns == 0 {
                return Err("The recovery journal contains an invalid engine process identity.".to_string());
            }
        }
        if let Some(tunnel) = &self.tunnel {
            validate_guid(&tunnel.interface_guid)?;
            if tunnel.interface_index == 0
                || tunnel.alias.trim().is_empty()
                || tunnel.alias.len() > MAX_INTERFACE_ALIAS_BYTES
                || tunnel.alias.chars().any(char::is_control)
                || !(576..=9000).contains(&tunnel.mtu)
                || tunnel.addresses.is_empty()
                || tunnel.addresses.len() > MAX_TUN_ADDRESSES
            {
                return Err("The recovery journal contains invalid tunnel interface details.".to_string());
            }
            let unique: BTreeSet<_> = tunnel.addresses.iter().collect();
            if unique.len() != tunnel.addresses.len() {
                return Err("The recovery journal contains duplicate tunnel addresses.".to_string());
            }
            if !tunnel.address_details.is_empty() {
                if tunnel.address_details.len() != tunnel.addresses.len() {
                    return Err("The recovery journal tunnel address details are incomplete.".to_string());
                }
                let mut detail_addresses = BTreeSet::new();
                for detail in &tunnel.address_details {
                    let maximum = if detail.address.is_ipv4() { 32 } else { 128 };
                    if detail.prefix_length > maximum || !detail_addresses.insert(detail.address) {
                        return Err("The recovery journal contains invalid or duplicate tunnel address details.".to_string());
                    }
                }
                let address_set: BTreeSet<_> = tunnel.addresses.iter().copied().collect();
                if detail_addresses != address_set {
                    return Err("The recovery journal tunnel address details do not match its address list.".to_string());
                }
            }
        }
        if self.routes.len() > MAX_ROUTES {
            return Err("The recovery journal contains too many route mutations.".to_string());
        }
        let mut destinations = BTreeSet::new();
        for route in &self.routes {
            let (network, _) = parse_prefix(&route.destination_prefix)?;
            if !destinations.insert(route.destination_prefix.as_str()) {
                return Err("The recovery journal contains a duplicate route destination.".to_string());
            }
            validate_route_state(&route.applied, network)?;
            if let Some(previous) = &route.previous {
                validate_route_state(previous, network)?;
            }
        }
        if self.dns.len() > MAX_DNS_INTERFACES {
            return Err("The recovery journal contains too many DNS interface mutations.".to_string());
        }
        let mut dns_interfaces = BTreeSet::new();
        for change in &self.dns {
            if change.interface_index == 0 || !dns_interfaces.insert(change.interface_index) {
                return Err("The recovery journal contains an invalid or duplicate DNS interface.".to_string());
            }
            if let Some(interface_guid) = &change.interface_guid {
                validate_guid(interface_guid)?;
            }
            validate_dns_configuration(&change.applied)?;
            validate_dns_configuration(&change.previous)?;
            for configuration in [&change.applied, &change.previous] {
                if let DnsConfiguration::Interface(snapshot) = configuration {
                    validate_guid(&snapshot.interface_guid)?;
                    if change.interface_guid.as_deref() != Some(snapshot.interface_guid.as_str()) {
                        return Err("The DNS snapshot GUID does not match its journaled interface identity.".to_string());
                    }
                }
            }
        }
        if self.firewall_filters.len() > MAX_FIREWALL_FILTERS {
            return Err("The recovery journal contains too many firewall filter identities.".to_string());
        }
        let mut filter_ids = BTreeSet::new();
        let mut filter_keys = BTreeSet::new();
        for filter in &self.firewall_filters {
            validate_guid(&filter.provider_key)?;
            validate_guid(&filter.layer_key)?;
            if let Some(filter_key) = &filter.filter_key {
                validate_guid(filter_key)?;
                if !filter_keys.insert(filter_key.as_str()) {
                    return Err("The recovery journal contains a duplicate stable firewall filter key.".to_string());
                }
            }
            if filter.filter_id == 0 || !filter_ids.insert(filter.filter_id) {
                return Err("The recovery journal contains an invalid or duplicate firewall filter ID.".to_string());
            }
        }

        if self.phase == JournalPhase::NetworkConfigured {
            if self.routes.is_empty() || self.dns.is_empty() {
                return Err(
                    "The network-configured journal phase requires recorded route and DNS mutations."
                        .to_string(),
                );
            }
            if self.routes.iter().any(|route| {
                route.applied.interface_luid.is_none()
                    || route.applied.protocol.is_none()
                    || route.applied.origin.is_none()
                    || route.previous.as_ref().is_some_and(|previous| {
                        previous.interface_luid.is_none()
                            || previous.protocol.is_none()
                            || previous.origin.is_none()
                    })
            }) {
                return Err(
                    "NetworkConfigured requires stable NET_LUID and route protocol/origin evidence for every applied and previous route state."
                        .to_string(),
                );
            }
            if self.dns.iter().any(|change| {
                change.interface_guid.is_none()
                    || !is_complete_dual_stack_dns(&change.applied)
                    || !is_complete_dual_stack_dns(&change.previous)
            }) {
                return Err(
                    "NetworkConfigured requires stable-GUID DNS snapshots with complete IPv4 and IPv6 state for both previous and applied settings."
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

fn is_complete_dual_stack_dns(configuration: &DnsConfiguration) -> bool {
    matches!(
        configuration,
        DnsConfiguration::Interface(snapshot)
            if snapshot.ipv4.is_some() && snapshot.ipv6.is_some()
    )
}

fn validate_guid(value: &str) -> Result<(), String> {
    let parsed = uuid::Uuid::parse_str(value)
        .map_err(|_| "The recovery journal contains an invalid Windows GUID.".to_string())?;
    if parsed.to_string().eq_ignore_ascii_case(value) {
        Ok(())
    } else {
        Err("The recovery journal contains a non-canonical Windows GUID.".to_string())
    }
}

fn parse_prefix(value: &str) -> Result<(IpAddr, u8), String> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| "The recovery journal contains an invalid route prefix.".to_string())?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| "The recovery journal contains an invalid route address.".to_string())?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| "The recovery journal contains an invalid route prefix length.".to_string())?;
    let maximum = if address.is_ipv4() { 32 } else { 128 };
    if prefix > maximum {
        return Err("The recovery journal route prefix length is out of range.".to_string());
    }
    Ok((address, prefix))
}

fn validate_route_state(state: &RouteState, destination: IpAddr) -> Result<(), String> {
    if state.interface_index == 0
        || state.interface_luid == Some(0)
        || state.next_hop.is_some_and(|gateway| gateway.is_ipv4() != destination.is_ipv4())
    {
        return Err("The recovery journal contains an invalid route state.".to_string());
    }
    Ok(())
}

fn validate_dns_configuration(configuration: &DnsConfiguration) -> Result<(), String> {
    match configuration {
        DnsConfiguration::Dhcp => Ok(()),
        DnsConfiguration::Static(servers) => {
            validate_dns_servers(servers, None, false)
        }
        DnsConfiguration::Interface(snapshot) => {
            validate_guid(&snapshot.interface_guid)?;
            let ipv4 = snapshot.ipv4.as_ref().ok_or_else(|| {
                "The recovery journal is missing the IPv4 DNS snapshot.".to_string()
            })?;
            let ipv6 = snapshot.ipv6.as_ref().ok_or_else(|| {
                "The recovery journal is missing the IPv6 DNS snapshot.".to_string()
            })?;
            validate_dns_stack(ipv4, false)?;
            validate_dns_stack(ipv6, true)?;
            Ok(())
        }
    }
}

fn validate_dns_servers(
    servers: &[IpAddr],
    ipv6: Option<bool>,
    allow_empty: bool,
) -> Result<(), String> {
    if servers.len() > MAX_DNS_SERVERS || (!allow_empty && servers.is_empty()) {
        return Err("The recovery journal contains an invalid DNS server list.".to_string());
    }
    let unique: BTreeSet<_> = servers.iter().collect();
    if unique.len() != servers.len() {
        return Err("The recovery journal contains duplicate DNS servers.".to_string());
    }
    if let Some(ipv6) = ipv6 {
        if servers.iter().any(|server| server.is_ipv6() != ipv6) {
            return Err("The recovery journal contains a DNS server in the wrong IP family.".to_string());
        }
    }
    Ok(())
}

fn validate_dns_names(
    values: &[String],
    maximum: usize,
) -> Result<(), String> {
    if values.len() > maximum
        || values.iter().any(|value| {
            value.is_empty()
                || value.len() > 253
                || value.chars().any(char::is_control)
                || value.trim() != value
        })
    {
        return Err("The recovery journal contains an invalid DNS search-name list.".to_string());
    }
    Ok(())
}

fn validate_dns_doh_properties(
    properties: &[DnsDohServerProperty],
    server_count: usize,
) -> Result<(), String> {
    const DOH_AUTO: u64 = 0x0001;
    const DOH_ENABLED: u64 = 0x0002;
    const DOH_FALLBACK_TO_UDP: u64 = 0x0004;
    const DOH_AUTO_UPGRADE: u64 = 0x0008;
    const DOH_KNOWN_FLAGS: u64 =
        DOH_AUTO | DOH_ENABLED | DOH_FALLBACK_TO_UDP | DOH_AUTO_UPGRADE;

    if properties.len() > MAX_DNS_SERVERS {
        return Err("The recovery journal contains too many DNS-over-HTTPS properties.".to_string());
    }
    let mut indexes = BTreeSet::new();
    for property in properties {
        let auto = property.flags & DOH_AUTO != 0;
        let enabled = property.flags & DOH_ENABLED != 0;
        let has_base_policy = auto || enabled;
        if property.version != 1
            || property.property_type != 1
            || property.flags & !DOH_KNOWN_FLAGS != 0
            || (auto && enabled)
            || property.server_index as usize >= server_count
            || !indexes.insert(property.server_index)
            || (auto && property.template.is_some())
            || (enabled && property.template.as_ref().is_none_or(|template| {
                template.len() > 2048
                    || !template.starts_with("https://")
                    || template.chars().any(char::is_control)
            }))
            || (!has_base_policy && property.template.is_some())
            || (property.flags & (DOH_FALLBACK_TO_UDP | DOH_AUTO_UPGRADE) != 0
                && !has_base_policy)
        {
            return Err("The recovery journal contains an invalid DNS-over-HTTPS server property.".to_string());
        }
    }
    Ok(())
}

fn validate_dns_stack(
    stack: &DnsStackConfiguration,
    ipv6: bool,
) -> Result<(), String> {
    const DNS_SETTING_IPV6: u64 = 0x0001;
    const DNS_SETTING_NAMESERVER: u64 = 0x0002;
    const DNS_SETTING_SEARCHLIST: u64 = 0x0004;
    const DNS_SETTING_REGISTRATION_ENABLED: u64 = 0x0008;
    const DNS_SETTING_DOMAIN: u64 = 0x0020;
    const DNS_SETTINGS_ENABLE_LLMNR: u64 = 0x0080;
    const DNS_SETTINGS_QUERY_ADAPTER_NAME: u64 = 0x0100;
    const DNS_SETTING_PROFILE_NAMESERVER: u64 = 0x0200;
    const DNS_SETTING_SUPPLEMENTAL_SEARCH_LIST: u64 = 0x0800;
    const DNS_SETTING_DOH: u64 = 0x1000;
    const DNS_SETTING_DOH_PROFILE: u64 = 0x2000;
    const KNOWN_FLAGS: u64 = DNS_SETTING_IPV6
        | DNS_SETTING_NAMESERVER
        | DNS_SETTING_SEARCHLIST
        | DNS_SETTING_REGISTRATION_ENABLED
        | DNS_SETTING_DOMAIN
        | DNS_SETTINGS_ENABLE_LLMNR
        | DNS_SETTINGS_QUERY_ADAPTER_NAME
        | DNS_SETTING_PROFILE_NAMESERVER
        | DNS_SETTING_SUPPLEMENTAL_SEARCH_LIST
        | DNS_SETTING_DOH
        | DNS_SETTING_DOH_PROFILE;

    let flags = stack.settings_flags;
    if !matches!(stack.settings_version, 3 | 4)
        || (stack.settings_version == 3 && stack.encrypted_dns_adapter_flags.is_some())
        || (stack.settings_version == 4 && stack.encrypted_dns_adapter_flags.is_none())
        || flags & !KNOWN_FLAGS != 0
        || (flags & DNS_SETTING_IPV6 != 0) != ipv6
        || (flags & DNS_SETTING_NAMESERVER != 0) != stack.name_servers.is_some()
        || (flags & DNS_SETTING_PROFILE_NAMESERVER != 0)
            != stack.profile_name_servers.is_some()
        || (flags & DNS_SETTING_DOMAIN != 0) != stack.domain.is_some()
        || (flags & DNS_SETTING_SEARCHLIST != 0) != stack.search_list.is_some()
        || (flags & DNS_SETTING_SUPPLEMENTAL_SEARCH_LIST != 0)
            != stack.supplemental_search_list.is_some()
        || (flags & DNS_SETTING_DOH == 0 && !stack.server_properties.is_empty())
        || (flags & DNS_SETTING_DOH_PROFILE == 0
            && !stack.profile_server_properties.is_empty())
        || (flags & DNS_SETTING_DOH != 0 && stack.name_servers.is_none())
        || (flags & DNS_SETTING_DOH_PROFILE != 0 && stack.profile_name_servers.is_none())
        || stack.registration_enabled > 1
        || stack.register_adapter_name > 1
        || stack.enable_llmnr > 1
        || stack.query_adapter_name > 1
    {
        return Err("The DNS stack flags and returned fields are inconsistent.".to_string());
    }
    if let Some(servers) = &stack.name_servers {
        validate_dns_servers(servers, Some(ipv6), false)?;
    }
    if let Some(servers) = &stack.profile_name_servers {
        validate_dns_servers(servers, Some(ipv6), false)?;
    }
    validate_dns_servers(&stack.effective_name_servers, Some(ipv6), true)?;
    if let Some(domain) = &stack.domain {
        validate_dns_names(std::slice::from_ref(domain), 1)?;
    }
    if let Some(names) = &stack.search_list {
        validate_dns_names(names, 32)?;
    }
    if let Some(names) = &stack.supplemental_search_list {
        validate_dns_names(names, 32)?;
    }
    validate_dns_doh_properties(
        &stack.server_properties,
        stack.name_servers.as_ref().map_or(0, Vec::len),
    )?;
    validate_dns_doh_properties(
        &stack.profile_server_properties,
        stack.profile_name_servers.as_ref().map_or(0, Vec::len),
    )?;
    Ok(())
}

/// Validate that a new checkpoint cannot make previously recorded resources disappear.
///
/// The newest committed checkpoint is the recovery source of truth. Resource
/// inventories therefore grow monotonically; a caller must not rewrite an old
/// mutation or omit it merely because cleanup is believed to have succeeded.
/// The complete session journal is removed only after an OS reconciler verifies
/// every recorded resource.
fn validate_checkpoint_progress(
    previous: &RecoveryJournal,
    next: &RecoveryJournal,
) -> Result<(), String> {
    if previous.session_id != next.session_id {
        return Err("A recovery checkpoint cannot change its session identity.".to_string());
    }

    let phase_can_advance = match (previous.phase, next.phase) {
        (left, right) if left == right => true,
        (JournalPhase::Preparing, JournalPhase::EngineStarted)
        | (JournalPhase::Preparing, JournalPhase::Disconnecting)
        | (JournalPhase::Preparing, JournalPhase::RecoveryRequired)
        | (JournalPhase::EngineStarted, JournalPhase::TunnelCreated)
        | (JournalPhase::EngineStarted, JournalPhase::Disconnecting)
        | (JournalPhase::EngineStarted, JournalPhase::RecoveryRequired)
        | (JournalPhase::TunnelCreated, JournalPhase::NetworkConfigured)
        | (JournalPhase::TunnelCreated, JournalPhase::Disconnecting)
        | (JournalPhase::TunnelCreated, JournalPhase::RecoveryRequired)
        | (JournalPhase::NetworkConfigured, JournalPhase::Disconnecting)
        | (JournalPhase::NetworkConfigured, JournalPhase::RecoveryRequired)
        | (JournalPhase::Disconnecting, JournalPhase::RecoveryRequired) => true,
        _ => false,
    };
    if !phase_can_advance {
        return Err("The recovery journal phase cannot move backwards or leave RecoveryRequired.".to_string());
    }

    if previous.engine.is_some() && previous.engine != next.engine {
        return Err("A checkpoint cannot replace or remove the recorded engine process identity.".to_string());
    }
    if previous.tunnel.is_some() && previous.tunnel != next.tunnel {
        return Err("A checkpoint cannot replace or remove the recorded tunnel identity.".to_string());
    }
    if previous.routes.iter().any(|record| !next.routes.contains(record)) {
        return Err("A checkpoint cannot rewrite or remove a recorded route mutation.".to_string());
    }
    if previous.dns.iter().any(|record| !next.dns.contains(record)) {
        return Err("A checkpoint cannot rewrite or remove a recorded DNS mutation.".to_string());
    }

    for previous_filter in &previous.firewall_filters {
        let retained = match previous_filter.filter_key.as_deref() {
            Some(stable_key) => next.firewall_filters.iter().any(|candidate| {
                candidate.filter_key.as_deref() == Some(stable_key)
                    && candidate.provider_key == previous_filter.provider_key
                    && candidate.layer_key == previous_filter.layer_key
            }),
            // A legacy record has no durable filter key. Preserve the entire
            // record; a runtime filter ID alone is never enough to re-identify it.
            None => next.firewall_filters.contains(previous_filter),
        };
        if !retained {
            return Err("A checkpoint cannot rewrite or remove a recorded WFP filter identity.".to_string());
        }
    }

    Ok(())
}

pub struct RecoveryJournalStore {
    root: PathBuf,
    gate: Mutex<()>,
}

impl RecoveryJournalStore {
    /// Open an existing directory created by the privileged service installer.
    /// The directory must already have a restrictive service-owned Windows DACL.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, String> {
        let root = root.into();
        validate_store_root(&root)?;
        Ok(Self {
            root,
            gate: Mutex::new(()),
        })
    }

    /// Persist a complete checkpoint before performing the corresponding OS
    /// mutation. A unique revision file is written, flushed, and atomically
    /// renamed into place; an interrupted pending write is ignored on recovery.
    pub fn persist(&self, journal: &RecoveryJournal) -> Result<(), String> {
        journal.validate()?;
        let _guard = self
            .gate
            .lock()
            .map_err(|_| "The recovery journal lock is unavailable.".to_string())?;
        validate_store_root(&self.root)?;

        let current = self.load_unresolved_unlocked()?;
        if let Some(previous) = current.iter().find(|item| item.session_id == journal.session_id) {
            if journal.revision <= previous.revision {
                return Err("Recovery journal revisions must increase monotonically.".to_string());
            }
            validate_checkpoint_progress(previous, journal)?;
        }

        let bytes = serde_json::to_vec(journal)
            .map_err(|_| "The recovery journal could not be serialized.".to_string())?;
        if bytes.len() as u64 > MAX_RECOVERY_JOURNAL_BYTES {
            return Err("The recovery journal exceeds the maximum file size.".to_string());
        }

        let name = journal_file_name(journal.session_id, journal.revision);
        let destination = self.root.join(&name);
        let pending = self.root.join(format!(
            ".{name}.{}.pending",
            uuid::Uuid::new_v4().simple()
        ));

        let write_result = (|| -> Result<(), String> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&pending)
                .map_err(|_| "The recovery journal staging file could not be created.".to_string())?;
            file.write_all(&bytes)
                .map_err(|_| "The recovery journal checkpoint could not be written.".to_string())?;
            file.sync_all()
                .map_err(|_| "The recovery journal checkpoint could not be flushed.".to_string())?;
            drop(file);
            commit_pending_file(&pending, &destination)?;
            sync_directory(&self.root)?;
            Ok(())
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&pending);
        }
        write_result
    }

    /// Return the newest committed checkpoint for every session. Any malformed
    /// committed record causes an error; callers must fail closed, not skip it.
    pub fn load_unresolved(&self) -> Result<Vec<RecoveryJournal>, String> {
        let _guard = self
            .gate
            .lock()
            .map_err(|_| "The recovery journal lock is unavailable.".to_string())?;
        validate_store_root(&self.root)?;
        self.load_unresolved_unlocked()
    }

    /// Remove all checkpoints for a session. Call only after engine exit, tunnel
    /// teardown, route/DNS restoration, and WFP cleanup have all been verified.
    /// Missing sessions are treated as already removed.
    pub(crate) fn remove_session(&self, session_id: u64) -> Result<(), String> {
        if session_id == 0 {
            return Err("A valid recovery journal session is required.".to_string());
        }
        let _guard = self
            .gate
            .lock()
            .map_err(|_| "The recovery journal lock is unavailable.".to_string())?;
        validate_store_root(&self.root)?;

        for entry in fs::read_dir(&self.root)
            .map_err(|_| "The recovery journal directory could not be read.".to_string())?
        {
            let entry = entry
                .map_err(|_| "A recovery journal directory entry could not be read.".to_string())?;
            let path = entry.path();
            let Some((file_session, _)) = parse_journal_file_name(&path) else {
                continue;
            };
            if file_session != session_id {
                continue;
            }
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| "A recovery journal file could not be inspected.".to_string())?;
            if is_reparse_point(&metadata) || !metadata.file_type().is_file() {
                return Err("A recovery journal entry is not a regular file.".to_string());
            }
            fs::remove_file(&path)
                .map_err(|_| "A recovered session journal could not be removed.".to_string())?;
        }
        sync_directory(&self.root)
    }

    fn load_unresolved_unlocked(&self) -> Result<Vec<RecoveryJournal>, String> {
        let mut sessions: BTreeMap<u64, BTreeMap<u64, RecoveryJournal>> = BTreeMap::new();
        for entry in fs::read_dir(&self.root)
            .map_err(|_| "The recovery journal directory could not be read.".to_string())?
        {
            let entry = entry
                .map_err(|_| "A recovery journal directory entry could not be read.".to_string())?;
            let path = entry.path();
            let Some((file_session, file_revision)) = parse_journal_file_name(&path) else {
                continue;
            };
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| "A recovery journal file could not be inspected.".to_string())?;
            if is_reparse_point(&metadata)
                || !metadata.file_type().is_file()
                || metadata.len() > MAX_RECOVERY_JOURNAL_BYTES
            {
                return Err("A committed recovery journal file is unsafe or oversized.".to_string());
            }

            let mut file = File::open(&path)
                .map_err(|_| "A committed recovery journal file could not be opened.".to_string())?;
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            file.take(MAX_RECOVERY_JOURNAL_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "A committed recovery journal file could not be read.".to_string())?;
            if bytes.len() as u64 > MAX_RECOVERY_JOURNAL_BYTES {
                return Err("A committed recovery journal file exceeds the size limit.".to_string());
            }
            let journal: RecoveryJournal = serde_json::from_slice(&bytes)
                .map_err(|_| "A committed recovery journal is corrupt; recovery is blocked.".to_string())?;
            journal.validate()?;
            if journal.session_id != file_session || journal.revision != file_revision {
                return Err("A recovery journal filename does not match its contents.".to_string());
            }
            if sessions
                .entry(file_session)
                .or_default()
                .insert(file_revision, journal)
                .is_some()
            {
                return Err("Duplicate recovery journal revisions were found.".to_string());
            }
        }

        Ok(sessions
            .into_values()
            .filter_map(|revisions| revisions.into_values().next_back())
            .collect())
    }
}

fn validate_store_root(root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|_| "The privileged recovery journal directory is unavailable.".to_string())?;
    if is_reparse_point(&metadata) || !metadata.file_type().is_dir() {
        return Err("The recovery journal root must be a real directory.".to_string());
    }
    Ok(())
}

fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(windows)]
fn commit_pending_file(source: &Path, destination: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination.as_os_str().encode_wide().chain(Some(0)).collect();
    let moved = unsafe {
        MoveFileExW(source.as_ptr(), destination.as_ptr(), MOVEFILE_WRITE_THROUGH)
    };
    if moved == 0 {
        Err("The recovery journal checkpoint could not be committed.".to_string())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn commit_pending_file(source: &Path, destination: &Path) -> Result<(), String> {
    fs::rename(source, destination)
        .map_err(|_| "The recovery journal checkpoint could not be committed.".to_string())
}

fn journal_file_name(session_id: u64, revision: u64) -> String {
    format!("session-{session_id:016x}-revision-{revision:016x}.json")
}

fn parse_journal_file_name(path: &Path) -> Option<(u64, u64)> {
    let name = path.file_name()?.to_str()?;
    let name = name.strip_prefix("session-")?.strip_suffix(".json")?;
    let (session, revision) = name.split_once("-revision-")?;
    if session.len() != 16 || revision.len() != 16 {
        return None;
    }
    Some((
        u64::from_str_radix(session, 16).ok()?,
        u64::from_str_radix(revision, 16).ok()?,
    ))
}

fn sync_directory(root: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "The recovery journal directory update could not be flushed.".to_string())?;
    }
    #[cfg(windows)]
    {
        let _ = root;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (PathBuf, RecoveryJournalStore) {
        let root = std::env::temp_dir().join(format!(
            "blacklist-inevitable-recovery-journal-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).expect("create test journal directory");
        let store = RecoveryJournalStore::open(&root).expect("open test journal directory");
        (root, store)
    }

    fn example_journal(session_id: u64, revision: u64) -> RecoveryJournal {
        let mut journal = RecoveryJournal::new(session_id);
        journal.revision = revision;
        journal.engine = Some(EngineProcessRecord {
            process_id: 4321,
            creation_time_100ns: 133700000000000000,
        });
        journal.tunnel = Some(TunnelInterfaceRecord {
            interface_guid: "4d36e972-e325-11ce-bfc1-08002be10318".to_string(),
            interface_index: 17,
            alias: "blacklist-inevitable".to_string(),
            mtu: 1500,
            addresses: vec!["198.18.0.1".parse().unwrap(), "fd00::1".parse().unwrap()],
            address_details: vec![
                TunnelAddressRecord { address: "198.18.0.1".parse().unwrap(), prefix_length: 30 },
                TunnelAddressRecord { address: "fd00::1".parse().unwrap(), prefix_length: 64 },
            ],
        });
        journal.routes.push(RouteMutationRecord {
            destination_prefix: "0.0.0.0/0".to_string(),
            applied: RouteState {
                interface_index: 17,
                interface_luid: Some(0x0001_0000_0000_0011),
                next_hop: None,
                metric: 5,
                protocol: Some(3),
                origin: Some(0),
            },
            previous: Some(RouteState {
                interface_index: 12,
                interface_luid: Some(0x0001_0000_0000_000C),
                next_hop: Some("192.0.2.1".parse().unwrap()),
                metric: 25,
                protocol: Some(19),
                origin: Some(2),
            }),
        });
        journal.dns.push(DnsMutationRecord {
            interface_index: 12,
            interface_guid: Some("4d36e972-e325-11ce-bfc1-08002be10318".into()),
            applied: DnsConfiguration::Static(vec!["198.18.0.1".parse().unwrap()]),
            previous: DnsConfiguration::Dhcp,
        });
        journal.firewall_filters.push(FirewallFilterRecord {
            provider_key: "4d36e972-e325-11ce-bfc1-08002be10318".to_string(),
            filter_key: Some("ac9af5e4-5e27-4dce-8b6a-19c175e233d1".to_string()),
            layer_key: "6d6f8e80-62d4-4b90-a1b8-10ac74e55e20".to_string(),
            filter_id: 77,
        });
        journal
    }

    #[test]
    fn persists_and_loads_the_latest_complete_checkpoint() {
        let (root, store) = store();
        let mut first = RecoveryJournal::new(42);
        store.persist(&first).unwrap();

        first.revision = 2;
        first.phase = JournalPhase::EngineStarted;
        first.engine = Some(EngineProcessRecord {
            process_id: 100,
            creation_time_100ns: 133700000000000000,
        });
        store.persist(&first).unwrap();

        let loaded = store.load_unresolved().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].session_id, 42);
        assert_eq!(loaded[0].revision, 2);
        assert_eq!(loaded[0].phase, JournalPhase::EngineStarted);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_non_monotonic_revisions() {
        let (root, store) = store();
        store.persist(&example_journal(7, 3)).unwrap();
        assert!(store.persist(&example_journal(7, 2)).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn assert_checkpoint_mutation_rejected(
        mutate: impl FnOnce(&mut RecoveryJournal),
        expected_error: &str,
    ) {
        let (root, store) = store();
        let first = example_journal(81, 1);
        store.persist(&first).unwrap();

        let mut next = first.clone();
        next.revision = 2;
        mutate(&mut next);
        let error = store.persist(&next).unwrap_err();
        assert!(error.contains(expected_error), "unexpected error: {error}");

        let latest = store.load_unresolved().unwrap();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0], first);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn checkpoint_cannot_drop_or_rewrite_recorded_resources() {
        assert_checkpoint_mutation_rejected(
            |journal| journal.engine = None,
            "engine process identity",
        );
        assert_checkpoint_mutation_rejected(
            |journal| journal.tunnel = None,
            "tunnel identity",
        );
        assert_checkpoint_mutation_rejected(
            |journal| journal.routes.clear(),
            "route mutation",
        );
        assert_checkpoint_mutation_rejected(
            |journal| journal.dns.clear(),
            "DNS mutation",
        );
        assert_checkpoint_mutation_rejected(
            |journal| journal.firewall_filters.clear(),
            "WFP filter identity",
        );
    }

    #[test]
    fn checkpoint_phase_cannot_regress() {
        let (root, store) = store();
        let mut first = RecoveryJournal::new(82);
        first.phase = JournalPhase::EngineStarted;
        store.persist(&first).unwrap();

        let mut regressed = first.clone();
        regressed.revision = 2;
        regressed.phase = JournalPhase::Preparing;
        assert!(store
            .persist(&regressed)
            .unwrap_err()
            .contains("phase cannot move backwards"));
        assert_eq!(store.load_unresolved().unwrap()[0], first);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stable_wfp_key_allows_only_runtime_id_refresh() {
        let (root, store) = store();
        let first = example_journal(83, 1);
        store.persist(&first).unwrap();

        let mut refreshed = first.clone();
        refreshed.revision = 2;
        refreshed.firewall_filters[0].filter_id = 88;
        store.persist(&refreshed).unwrap();
        assert_eq!(store.load_unresolved().unwrap()[0], refreshed);
        fs::remove_dir_all(root).unwrap();
    }

    fn dns_stack(ipv6: bool, nameserver: &str) -> DnsStackConfiguration {
        DnsStackConfiguration {
            settings_version: 3,
            encrypted_dns_adapter_flags: None,
            name_servers: Some(vec![nameserver.parse().unwrap()]),
            profile_name_servers: None,
            effective_name_servers: vec![nameserver.parse().unwrap()],
            domain: Some("vpn.example.test".into()),
            search_list: Some(vec!["example.test".into()]),
            supplemental_search_list: Some(vec!["internal.example.test".into()]),
            registration_enabled: 0,
            register_adapter_name: 0,
            enable_llmnr: 0,
            query_adapter_name: 0,
            disable_unconstrained_queries: 1,
            settings_flags: if ipv6 { 0x0001 | 0x0002 | 0x0004 | 0x0020 | 0x0800 } else { 0x0002 | 0x0004 | 0x0020 | 0x0800 },
            server_properties: vec![],
            profile_server_properties: vec![],
        }
    }

    fn complete_dns_configuration() -> DnsConfiguration {
        DnsConfiguration::Interface(DnsInterfaceConfiguration {
            interface_guid: "4d36e972-e325-11ce-bfc1-08002be10318".into(),
            ipv4: Some(dns_stack(false, "192.0.2.53")),
            ipv6: Some(dns_stack(true, "2001:db8::53")),
        })
    }

    fn network_configured_journal(session_id: u64) -> RecoveryJournal {
        let mut journal = example_journal(session_id, 1);
        journal.phase = JournalPhase::NetworkConfigured;
        journal.dns[0].interface_guid =
            Some("4d36e972-e325-11ce-bfc1-08002be10318".into());
        journal.dns[0].applied = complete_dns_configuration();
        journal.dns[0].previous = complete_dns_configuration();
        journal
    }

    #[test]
    fn network_configured_requires_stable_route_luid_and_full_dual_stack_dns() {
        let valid = network_configured_journal(94);
        valid.validate().unwrap();

        let mut missing_applied_luid = network_configured_journal(95);
        missing_applied_luid.routes[0].applied.interface_luid = None;
        assert!(missing_applied_luid.validate().unwrap_err().contains("NET_LUID"));

        let mut missing_previous_luid = network_configured_journal(96);
        missing_previous_luid.routes[0].previous.as_mut().unwrap().interface_luid = None;
        assert!(missing_previous_luid.validate().unwrap_err().contains("NET_LUID"));

        let mut missing_applied_protocol = network_configured_journal(100);
        missing_applied_protocol.routes[0].applied.protocol = None;
        assert!(missing_applied_protocol.validate().unwrap_err().contains("protocol/origin"));

        let mut missing_applied_origin = network_configured_journal(101);
        missing_applied_origin.routes[0].applied.origin = None;
        assert!(missing_applied_origin.validate().unwrap_err().contains("protocol/origin"));

        let mut missing_previous_protocol = network_configured_journal(102);
        missing_previous_protocol.routes[0].previous.as_mut().unwrap().protocol = None;
        assert!(missing_previous_protocol.validate().unwrap_err().contains("protocol/origin"));

        let mut missing_previous_origin = network_configured_journal(103);
        missing_previous_origin.routes[0].previous.as_mut().unwrap().origin = None;
        assert!(missing_previous_origin.validate().unwrap_err().contains("protocol/origin"));

        let mut legacy_dns = network_configured_journal(97);
        legacy_dns.dns[0].applied = DnsConfiguration::Static(vec![
            "198.18.0.1".parse().unwrap(),
        ]);
        assert!(legacy_dns.validate().unwrap_err().contains("complete IPv4 and IPv6"));

        let mut missing_dns_guid = network_configured_journal(98);
        missing_dns_guid.dns[0].interface_guid = None;
        assert!(missing_dns_guid.validate().unwrap_err().contains("snapshot GUID"));

        let mut no_routes = network_configured_journal(99);
        no_routes.routes.clear();
        assert!(no_routes.validate().unwrap_err().contains("route and DNS mutations"));
    }

    #[test]
    fn validates_route_dns_tunnel_and_filter_resource_identities() {
        let mut journal = example_journal(1, 1);
        journal.validate().unwrap();

        journal.routes[0].destination_prefix = "0.0.0.0/33".to_string();
        assert!(journal.validate().is_err());

        let mut journal = example_journal(1, 1);
        journal.routes[0].applied.interface_luid = Some(0);
        assert!(journal.validate().is_err());

        let mut journal = example_journal(1, 1);
        journal.dns[0].interface_index = 0;
        assert!(journal.validate().is_err());

        let mut journal = example_journal(1, 1);
        journal.tunnel.as_mut().unwrap().interface_guid = "not-a-guid".to_string();
        assert!(journal.validate().is_err());

        let mut journal = example_journal(1, 1);
        journal.tunnel.as_mut().unwrap().address_details[0].prefix_length = 33;
        assert!(journal.validate().is_err());

        let mut journal = example_journal(1, 1);
        journal.tunnel.as_mut().unwrap().address_details.pop();
        assert!(journal.validate().is_err());

        let mut journal = example_journal(1, 1);
        journal.firewall_filters[0].filter_id = 0;
        assert!(journal.validate().is_err());
    }

    #[test]
    fn complete_dual_stack_dns_configuration_round_trips() {
        let mut journal = RecoveryJournal::new(76);
        journal.dns.push(DnsMutationRecord {
            interface_index: 12,
            interface_guid: Some("4d36e972-e325-11ce-bfc1-08002be10318".into()),
            applied: complete_dns_configuration(),
            previous: complete_dns_configuration(),
        });

        journal.validate().unwrap();
        let encoded = serde_json::to_vec(&journal).unwrap();
        let decoded: RecoveryJournal = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, journal);
    }

    #[test]
    fn rejects_incomplete_or_family_mismatched_dual_stack_dns_journals() {
        let mut journal = RecoveryJournal::new(77);
        let mut incomplete = match complete_dns_configuration() {
            DnsConfiguration::Interface(config) => config,
            _ => unreachable!(),
        };
        incomplete.ipv6 = None;
        journal.dns.push(DnsMutationRecord {
            interface_index: 12,
            interface_guid: Some(incomplete.interface_guid.clone()),
            applied: DnsConfiguration::Interface(incomplete),
            previous: complete_dns_configuration(),
        });
        assert!(journal.validate().is_err());

        let mut journal = RecoveryJournal::new(78);
        let mut mismatched = match complete_dns_configuration() {
            DnsConfiguration::Interface(config) => config,
            _ => unreachable!(),
        };
        mismatched.ipv6.as_mut().unwrap().name_servers =
            Some(vec!["192.0.2.53".parse().unwrap()]);
        journal.dns.push(DnsMutationRecord {
            interface_index: 12,
            interface_guid: Some(mismatched.interface_guid.clone()),
            applied: DnsConfiguration::Interface(mismatched),
            previous: complete_dns_configuration(),
        });
        assert!(journal.validate().is_err());
    }

    #[test]
    fn validates_doh_server_property_index_and_template_mode() {
        let mut journal = RecoveryJournal::new(79);
        let mut configuration = match complete_dns_configuration() {
            DnsConfiguration::Interface(config) => config,
            _ => unreachable!(),
        };
        configuration.ipv4.as_mut().unwrap().settings_flags |= 0x1000;
        configuration.ipv4.as_mut().unwrap().server_properties.push(
            DnsDohServerProperty {
                version: 1,
                server_index: 0,
                property_type: 1,
                flags: 0x0002,
                template: Some("https://dns.example.test/dns-query{?dns}".into()),
            },
        );
        journal.dns.push(DnsMutationRecord {
            interface_index: 12,
            interface_guid: Some(configuration.interface_guid.clone()),
            applied: DnsConfiguration::Interface(configuration.clone()),
            previous: complete_dns_configuration(),
        });
        journal.validate().unwrap();

        let mut invalid = configuration;
        invalid.ipv4.as_mut().unwrap().server_properties[0].server_index = 1;
        journal.dns[0].applied = DnsConfiguration::Interface(invalid);
        assert!(journal.validate().is_err());

        let mut invalid = match complete_dns_configuration() {
            DnsConfiguration::Interface(config) => config,
            _ => unreachable!(),
        };
        invalid.ipv4.as_mut().unwrap().settings_flags |= 0x1000;
        invalid.ipv4.as_mut().unwrap().server_properties.push(
            DnsDohServerProperty {
                version: 1,
                server_index: 0,
                property_type: 1,
                flags: 0x0003,
                template: Some("https://dns.example.test/dns-query".into()),
            },
        );
        journal.dns[0].applied = DnsConfiguration::Interface(invalid);
        assert!(journal.validate().is_err());
    }

    #[test]
    fn dns_version_four_preserves_encrypted_adapter_flags() {
        let mut journal = RecoveryJournal::new(81);
        let mut configuration = match complete_dns_configuration() {
            DnsConfiguration::Interface(config) => config,
            _ => unreachable!(),
        };
        configuration.ipv4.as_mut().unwrap().settings_version = 4;
        configuration.ipv4.as_mut().unwrap().encrypted_dns_adapter_flags = Some(0x0000_0003);
        journal.dns.push(DnsMutationRecord {
            interface_index: 12,
            interface_guid: Some(configuration.interface_guid.clone()),
            applied: DnsConfiguration::Interface(configuration.clone()),
            previous: DnsConfiguration::Interface(configuration),
        });
        journal.validate().unwrap();
    }

    #[test]
    fn doh_enabled_without_custom_server_property_is_preserved() {
        let mut journal = RecoveryJournal::new(82);
        let mut configuration = match complete_dns_configuration() {
            DnsConfiguration::Interface(config) => config,
            _ => unreachable!(),
        };
        configuration.ipv4.as_mut().unwrap().settings_flags |= 0x1000;
        configuration.ipv4.as_mut().unwrap().server_properties.clear();
        journal.dns.push(DnsMutationRecord {
            interface_index: 12,
            interface_guid: Some(configuration.interface_guid.clone()),
            applied: DnsConfiguration::Interface(configuration.clone()),
            previous: DnsConfiguration::Interface(configuration),
        });
        journal.validate().unwrap();
    }

    #[test]
    fn legacy_dns_record_without_stable_guid_remains_readable() {
        let mut legacy = serde_json::to_value(example_journal(80, 1)).unwrap();
        legacy["dns"][0]
            .as_object_mut()
            .unwrap()
            .remove("interfaceGuid");
        let decoded: RecoveryJournal = serde_json::from_value(legacy).unwrap();
        assert_eq!(decoded.dns[0].interface_guid, None);
        decoded.validate().unwrap();
    }

    #[test]
    fn legacy_route_records_decode_without_stable_luid() {
        let mut legacy = serde_json::to_value(example_journal(73, 1)).unwrap();
        legacy["routes"][0]["applied"]
            .as_object_mut()
            .unwrap()
            .remove("interfaceLuid");
        legacy["routes"][0]["previous"]
            .as_object_mut()
            .unwrap()
            .remove("interfaceLuid");
        legacy["routes"][0]["applied"]
            .as_object_mut()
            .unwrap()
            .remove("protocol");
        legacy["routes"][0]["applied"]
            .as_object_mut()
            .unwrap()
            .remove("origin");
        legacy["routes"][0]["previous"]
            .as_object_mut()
            .unwrap()
            .remove("protocol");
        legacy["routes"][0]["previous"]
            .as_object_mut()
            .unwrap()
            .remove("origin");

        let decoded: RecoveryJournal = serde_json::from_value(legacy).unwrap();
        assert_eq!(decoded.routes[0].applied.interface_luid, None);
        assert_eq!(decoded.routes[0].previous.as_ref().unwrap().interface_luid, None);
        assert_eq!(decoded.routes[0].applied.protocol, None);
        assert_eq!(decoded.routes[0].applied.origin, None);
        assert_eq!(decoded.routes[0].previous.as_ref().unwrap().protocol, None);
        assert_eq!(decoded.routes[0].previous.as_ref().unwrap().origin, None);
        decoded.validate().unwrap();
    }

    #[test]
    fn route_protocol_and_origin_preserve_unknown_raw_values() {
        let mut journal = example_journal(74, 1);
        journal.routes[0].applied.protocol = Some(i32::MIN);
        journal.routes[0].applied.origin = Some(i32::MAX);
        journal.routes[0].previous.as_mut().unwrap().protocol = Some(-123_456_789);
        journal.routes[0].previous.as_mut().unwrap().origin = Some(123_456_789);

        let encoded = serde_json::to_vec(&journal).unwrap();
        let decoded: RecoveryJournal = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.routes[0].applied.protocol, Some(i32::MIN));
        assert_eq!(decoded.routes[0].applied.origin, Some(i32::MAX));
        assert_eq!(decoded.routes[0].previous.as_ref().unwrap().protocol, Some(-123_456_789));
        assert_eq!(decoded.routes[0].previous.as_ref().unwrap().origin, Some(123_456_789));
    }

    #[test]
    fn legacy_tunnel_records_decode_without_address_prefix_details() {
        let mut legacy = serde_json::to_value(example_journal(75, 1)).unwrap();
        legacy["tunnel"]
            .as_object_mut()
            .unwrap()
            .remove("addressDetails");

        let decoded: RecoveryJournal = serde_json::from_value(legacy).unwrap();
        assert!(decoded.tunnel.as_ref().unwrap().address_details.is_empty());
        decoded.validate().unwrap();
    }

    #[test]
    fn persists_stable_filter_guid_and_reads_legacy_records_without_it() {
        let mut journal = example_journal(71, 1);
        journal.firewall_filters[0].filter_key =
            Some("ac9af5e4-5e27-4dce-8b6a-19c175e233d1".to_string());
        journal.validate().unwrap();

        let encoded = serde_json::to_vec(&journal).unwrap();
        let decoded: RecoveryJournal = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.firewall_filters[0].filter_key, journal.firewall_filters[0].filter_key);

        let mut legacy = serde_json::to_value(example_journal(72, 1)).unwrap();
        legacy["firewallFilters"][0]
            .as_object_mut()
            .unwrap()
            .remove("filterKey");
        let decoded: RecoveryJournal = serde_json::from_value(legacy).unwrap();
        assert_eq!(decoded.firewall_filters[0].filter_key, None);
        decoded.validate().unwrap();
    }

    #[test]
    fn rejects_invalid_or_duplicate_stable_filter_guids() {
        let mut invalid = example_journal(73, 1);
        invalid.firewall_filters[0].filter_key = Some("not-a-guid".to_string());
        assert!(invalid.validate().is_err());

        let mut duplicate = example_journal(74, 1);
        duplicate.firewall_filters.push(duplicate.firewall_filters[0].clone());
        duplicate.firewall_filters[1].filter_id = 78;
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn fails_closed_when_a_committed_journal_is_corrupt() {
        let (root, store) = store();
        let path = root.join(journal_file_name(9, 1));
        fs::write(path, b"{truncated").unwrap();
        let error = store.load_unresolved().unwrap_err();
        assert!(error.contains("corrupt"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn removes_a_session_idempotently_and_preserves_other_sessions() {
        let (root, store) = store();
        store.persist(&example_journal(10, 1)).unwrap();
        store.persist(&RecoveryJournal::new(11)).unwrap();

        store.remove_session(10).unwrap();
        store.remove_session(10).unwrap();
        let remaining = store.load_unresolved().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].session_id, 11);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_unknown_fields_and_journal_versions() {
        let mut value = serde_json::to_value(RecoveryJournal::new(1)).unwrap();
        value["unexpectedCommand"] = serde_json::json!("powershell");
        assert!(serde_json::from_value::<RecoveryJournal>(value).is_err());

        let mut journal = RecoveryJournal::new(2);
        journal.version += 1;
        assert!(journal.validate().is_err());
    }
}
