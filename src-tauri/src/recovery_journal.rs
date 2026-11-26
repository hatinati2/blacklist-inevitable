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
    /// The complete Agent-owned egress policy is committed and read-back verified.
    EgressProtected,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TunnelInterfaceRecord {
    /// The stable adapter GUID, not a user-controlled interface alias.
    pub interface_guid: String,
    pub interface_index: u32,
    pub alias: String,
    pub mtu: u32,
    pub addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteState {
    pub interface_index: u32,
    pub next_hop: Option<IpAddr>,
    pub metric: u32,
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

/// One per-server DNS-over-HTTPS setting returned by the Windows DNS API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsDohServerProperty {
    pub version: u32,
    pub server_index: u32,
    pub property_type: u32,
    pub flags: u32,
    pub template: Option<String>,
}

/// Exact settings returned for one address family. Optional strings/lists
/// preserve the distinction between an absent Windows value and an explicit
/// configured list. Effective resolver addresses remain separate from the
/// adapter/profile-configured name-server lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsStackConfiguration {
    pub settings_version: u32,
    pub encrypted_dns_adapter_flags: Option<u32>,
    pub name_servers: Option<Vec<IpAddr>>,
    pub profile_name_servers: Option<Vec<IpAddr>>,
    pub effective_name_servers: Vec<IpAddr>,
    pub domain: Option<String>,
    pub search_list: Option<Vec<String>>,
    pub supplemental_search_list: Option<Vec<String>>,
    pub registration_enabled: u32,
    pub register_adapter_name: u32,
    pub enable_llmnr: u32,
    pub query_adapter_name: u32,
    pub disable_unconstrained_queries: u32,
    pub settings_flags: u64,
    pub server_properties: Vec<DnsDohServerProperty>,
    pub profile_server_properties: Vec<DnsDohServerProperty>,
}

/// A recovery-grade DNS snapshot is complete only when Windows returned both
/// family settings for the same stable interface GUID. A missing family is
/// Unknown, never an implicit "no DNS" configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsInterfaceConfiguration {
    pub interface_guid: String,
    pub ipv4: Option<DnsStackConfiguration>,
    pub ipv6: Option<DnsStackConfiguration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "servers", rename_all = "camelCase")]
pub enum DnsConfiguration {
    /// Legacy version-1 representation. It is not sufficient for
    /// NetworkConfigured recovery acceptance.
    Dhcp,
    Static(Vec<IpAddr>),
    /// Complete configured and effective DNS state for both IP families.
    Interface(DnsInterfaceConfiguration),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsMutationRecord {
    pub interface_index: u32,
    /// Stable interface identity; absent only in legacy records.
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
    /// Runtime ID returned by BFE after the filter is committed. This is
    /// diagnostic only and may be absent in the durable intent checkpoint
    /// written before the WFP mutation.
    #[serde(default)]
    pub filter_id: Option<u64>,
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
        let mut dns_interface_guids = BTreeSet::new();
        for change in &self.dns {
            if change.interface_index == 0 || !dns_interfaces.insert(change.interface_index) {
                return Err("The recovery journal contains an invalid or duplicate DNS interface index.".to_string());
            }
            if let Some(guid) = &change.interface_guid {
                validate_guid(guid)?;
                if !dns_interface_guids.insert(guid.as_str()) {
                    return Err("The recovery journal contains a duplicate stable DNS interface GUID.".to_string());
                }
            }
            validate_dns_configuration(&change.applied)?;
            validate_dns_configuration(&change.previous)?;
            validate_dns_interface_binding(change)?;
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
            } else if filter.filter_id.is_none() {
                return Err("A pre-mutation WFP intent must include a stable filter GUID before the runtime ID exists.".to_string());
            }
            if let Some(filter_id) = filter.filter_id {
                if filter_id == 0 || !filter_ids.insert(filter_id) {
                    return Err("The recovery journal contains an invalid or duplicate firewall filter ID.".to_string());
                }
            }
        }

        self.validate_phase_requirements()?;
        Ok(())
    }

    /// Enforce the minimum resource evidence associated with each durable phase.
    /// These checks do not replace live Windows observation during recovery.
    fn validate_phase_requirements(&self) -> Result<(), String> {
        let needs_protected_egress = matches!(
            self.phase,
            JournalPhase::EgressProtected
                | JournalPhase::EngineStarted
                | JournalPhase::TunnelCreated
                | JournalPhase::NetworkConfigured
        );
        if needs_protected_egress
            && (self.firewall_filters.is_empty()
                || self.firewall_filters.iter().any(|filter| {
                    filter.filter_key.is_none() || filter.filter_id.is_none()
                }))
        {
            return Err(
                "The journal phase requires a complete, committed WFP filter set with stable keys and runtime IDs."
                    .to_string(),
            );
        }

        if matches!(
            self.phase,
            JournalPhase::EngineStarted
                | JournalPhase::TunnelCreated
                | JournalPhase::NetworkConfigured
        ) && self.engine.is_none()
        {
            return Err("The journal phase requires an exact engine process identity.".to_string());
        }

        if matches!(
            self.phase,
            JournalPhase::TunnelCreated | JournalPhase::NetworkConfigured
        ) && self.tunnel.is_none()
        {
            return Err("The journal phase requires a verified tunnel interface identity.".to_string());
        }

        if self.phase == JournalPhase::NetworkConfigured {
            if self.routes.is_empty() || self.dns.is_empty() {
                return Err(
                    "The network-configured journal phase requires recorded route and DNS mutations."
                        .to_string(),
                );
            }
            if self.dns.iter().any(|change| {
                change.interface_guid.is_none()
                    || !is_complete_dual_stack(&change.previous)
                    || !is_complete_dual_stack(&change.applied)
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
        || state.next_hop.is_some_and(|gateway| gateway.is_ipv4() != destination.is_ipv4())
    {
        return Err("The recovery journal contains an invalid route state.".to_string());
    }
    Ok(())
}

const MAX_DNS_EFFECTIVE_SERVERS: usize = 64;
const MAX_DNS_PROPERTIES: usize = 8;
const MAX_DNS_SEARCH_NAMES: usize = 32;
const MAX_DNS_TEXT_BYTES: usize = 4096;
const DNS_INTERFACE_SETTINGS_VERSION3: u32 = 3;
const DNS_SERVER_PROPERTY_VERSION1: u32 = 1;

fn validate_dns_configuration(configuration: &DnsConfiguration) -> Result<(), String> {
    match configuration {
        DnsConfiguration::Dhcp => Ok(()),
        DnsConfiguration::Static(servers) => validate_dns_ip_list(servers, None, MAX_DNS_SERVERS),
        DnsConfiguration::Interface(interface) => {
            validate_guid(&interface.interface_guid)?;
            let ipv4 = interface.ipv4.as_ref().ok_or_else(|| {
                "The DNS interface snapshot is missing its IPv4 settings.".to_string()
            })?;
            let ipv6 = interface.ipv6.as_ref().ok_or_else(|| {
                "The DNS interface snapshot is missing its IPv6 settings.".to_string()
            })?;
            validate_dns_stack(ipv4, true)?;
            validate_dns_stack(ipv6, false)
        }
    }
}

fn validate_dns_interface_binding(change: &DnsMutationRecord) -> Result<(), String> {
    for configuration in [&change.applied, &change.previous] {
        if let DnsConfiguration::Interface(interface) = configuration {
            let Some(recorded_guid) = change.interface_guid.as_deref() else {
                return Err("A full DNS snapshot requires a stable interface GUID in its mutation record.".into());
            };
            if !interface.interface_guid.eq_ignore_ascii_case(recorded_guid) {
                return Err("The DNS snapshot GUID does not match its mutation-record interface GUID.".into());
            }
        }
    }
    Ok(())
}

fn is_complete_dual_stack(configuration: &DnsConfiguration) -> bool {
    matches!(
        configuration,
        DnsConfiguration::Interface(DnsInterfaceConfiguration {
            ipv4: Some(_),
            ipv6: Some(_),
            ..
        })
    )
}

fn validate_dns_stack(stack: &DnsStackConfiguration, ipv4: bool) -> Result<(), String> {
    if stack.settings_version != DNS_INTERFACE_SETTINGS_VERSION3 {
        return Err("The DNS snapshot uses an unsupported interface-settings version.".into());
    }
    validate_dns_ip_list(
        stack.effective_name_servers.as_slice(),
        Some(ipv4),
        MAX_DNS_EFFECTIVE_SERVERS,
    )?;
    if let Some(servers) = &stack.name_servers {
        validate_dns_ip_list(servers, Some(ipv4), MAX_DNS_SERVERS)?;
    }
    if let Some(servers) = &stack.profile_name_servers {
        validate_dns_ip_list(servers, Some(ipv4), MAX_DNS_SERVERS)?;
    }

    for flag in [
        stack.registration_enabled,
        stack.register_adapter_name,
        stack.enable_llmnr,
        stack.query_adapter_name,
        stack.disable_unconstrained_queries,
    ] {
        if flag > 1 {
            return Err("The DNS snapshot contains a non-boolean setting flag.".into());
        }
    }

    if let Some(domain) = stack.domain.as_deref() {
        validate_dns_text(domain, 253)?;
    }
    for names in [
        stack.search_list.as_ref(),
        stack.supplemental_search_list.as_ref(),
    ].into_iter().flatten() {
        if names.len() > MAX_DNS_SEARCH_NAMES {
            return Err("The DNS snapshot contains too many search-list entries.".into());
        }
        let mut unique = BTreeSet::new();
        for name in names {
            validate_dns_text(name, 253)?;
            if !unique.insert(name.to_ascii_lowercase()) {
                return Err("The DNS snapshot contains duplicate search-list entries.".into());
            }
        }
    }

    validate_dns_doh_properties(&stack.server_properties, stack.name_servers.as_deref())?;
    validate_dns_doh_properties(
        &stack.profile_server_properties,
        stack.profile_name_servers.as_deref(),
    )?;
    Ok(())
}

fn validate_dns_ip_list(
    servers: &[IpAddr],
    ipv4: Option<bool>,
    maximum: usize,
) -> Result<(), String> {
    if servers.len() > maximum || (maximum == MAX_DNS_SERVERS && servers.is_empty()) {
        return Err("The recovery journal contains an invalid DNS server list.".to_string());
    }
    let mut unique = BTreeSet::new();
    for server in servers {
        if server.is_unspecified()
            || server.is_multicast()
            || ipv4.is_some_and(|expected| server.is_ipv4() != expected)
            || !unique.insert(*server)
        {
            return Err("The DNS server list contains an invalid, duplicate, or wrong-family address.".into());
        }
    }
    Ok(())
}

fn validate_dns_text(value: &str, maximum: usize) -> Result<(), String> {
    if value.len() > maximum.min(MAX_DNS_TEXT_BYTES)
        || value.trim().is_empty()
        || value.chars().any(char::is_control)
    {
        return Err("The DNS snapshot contains an invalid or oversized text value.".into());
    }
    Ok(())
}

fn validate_dns_doh_properties(
    properties: &[DnsDohServerProperty],
    servers: Option<&[IpAddr]>,
) -> Result<(), String> {
    if properties.len() > MAX_DNS_PROPERTIES {
        return Err("The DNS-over-HTTPS property list exceeds its safe bound.".into());
    }
    if !properties.is_empty() && servers.is_none() {
        return Err("DNS-over-HTTPS properties require their corresponding configured server list.".into());
    }
    let mut indexes = BTreeSet::new();
    for property in properties {
        let Some(servers) = servers else {
            return Err("A DNS-over-HTTPS property has no corresponding server list.".into());
        };
        if property.version != DNS_SERVER_PROPERTY_VERSION1
            || property.server_index as usize >= servers.len()
            || !indexes.insert(property.server_index)
        {
            return Err("The DNS-over-HTTPS property version or server index is invalid.".into());
        }
        let Some(template) = property.template.as_deref() else {
            return Err("A DNS-over-HTTPS property is missing its template.".into());
        };
        validate_dns_text(template, 2048)?;
    }
    Ok(())
}

/// Validate the only permitted durable phase transitions. Checkpoints within
/// one phase are allowed; operational phases may not be skipped or reversed.
/// RecoveryRequired is terminal except for additional RecoveryRequired
/// checkpoints, and Disconnecting may only advance to RecoveryRequired.
fn validate_phase_transition(previous: JournalPhase, next: JournalPhase) -> Result<(), String> {
    if previous == next || next == JournalPhase::RecoveryRequired {
        return Ok(());
    }

    let allowed = matches!(
        (previous, next),
        (JournalPhase::Preparing, JournalPhase::EgressProtected)
            | (JournalPhase::EgressProtected, JournalPhase::EngineStarted)
            | (JournalPhase::EngineStarted, JournalPhase::TunnelCreated)
            | (JournalPhase::TunnelCreated, JournalPhase::NetworkConfigured)
    ) || (next == JournalPhase::Disconnecting
        && previous != JournalPhase::RecoveryRequired
        && previous != JournalPhase::Disconnecting);

    if allowed {
        Ok(())
    } else {
        Err(format!(
            "Invalid recovery journal phase transition from {previous:?} to {next:?}; refusing to persist an out-of-order checkpoint."
        ))
    }
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
        match current.iter().find(|item| item.session_id == journal.session_id) {
            Some(previous) => {
                if journal.revision <= previous.revision {
                    return Err("Recovery journal revisions must increase monotonically.".to_string());
                }
                validate_phase_transition(previous.phase, journal.phase)?;
            }
            None if journal.phase != JournalPhase::Preparing => {
                return Err(
                    "A new recovery journal session must begin in the Preparing phase."
                        .to_string(),
                );
            }
            None => {}
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
    pub fn remove_session(&self, session_id: u64) -> Result<(), String> {
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
        });
        journal.routes.push(RouteMutationRecord {
            destination_prefix: "0.0.0.0/0".to_string(),
            applied: RouteState {
                interface_index: 17,
                next_hop: None,
                metric: 5,
            },
            previous: Some(RouteState {
                interface_index: 12,
                next_hop: Some("192.0.2.1".parse().unwrap()),
                metric: 25,
            }),
        });
        journal.dns.push(DnsMutationRecord {
            interface_index: 12,
            interface_guid: None,
            applied: DnsConfiguration::Static(vec!["198.18.0.1".parse().unwrap()]),
            previous: DnsConfiguration::Dhcp,
        });
        journal.firewall_filters.push(FirewallFilterRecord {
            provider_key: "4d36e972-e325-11ce-bfc1-08002be10318".to_string(),
            filter_key: Some("ac9af5e4-5e27-4dce-8b6a-19c175e233d1".to_string()),
            layer_key: "6d6f8e80-62d4-4b90-a1b8-10ac74e55e20".to_string(),
            filter_id: Some(77),
        });
        journal
    }

    fn example_dns_stack(ipv4: bool) -> DnsStackConfiguration {
        let server = if ipv4 {
            "192.0.2.53".parse().unwrap()
        } else {
            "2001:db8::53".parse().unwrap()
        };
        DnsStackConfiguration {
            settings_version: DNS_INTERFACE_SETTINGS_VERSION3,
            encrypted_dns_adapter_flags: None,
            name_servers: Some(vec![server]),
            profile_name_servers: None,
            effective_name_servers: vec![server],
            domain: Some("example.test".to_string()),
            search_list: Some(vec!["example.test".to_string()]),
            supplemental_search_list: Some(Vec::new()),
            registration_enabled: 1,
            register_adapter_name: 1,
            enable_llmnr: 0,
            query_adapter_name: 1,
            disable_unconstrained_queries: 0,
            settings_flags: 0,
            server_properties: Vec::new(),
            profile_server_properties: Vec::new(),
        }
    }

    fn example_dns_interface(guid: &str) -> DnsInterfaceConfiguration {
        DnsInterfaceConfiguration {
            interface_guid: guid.to_string(),
            ipv4: Some(example_dns_stack(true)),
            ipv6: Some(example_dns_stack(false)),
        }
    }

    fn make_network_configured_dns_complete(journal: &mut RecoveryJournal) {
        let guid = "4d36e972-e325-11ce-bfc1-08002be10318";
        let full = DnsConfiguration::Interface(example_dns_interface(guid));
        journal.dns[0].interface_guid = Some(guid.to_string());
        journal.dns[0].applied = full.clone();
        journal.dns[0].previous = full;
    }

    #[test]
    fn persists_and_loads_the_latest_complete_checkpoint() {
        let (root, store) = store();
        let first = RecoveryJournal::new(42);
        store.persist(&first).unwrap();

        let mut protected = example_journal(42, 2);
        protected.phase = JournalPhase::EgressProtected;
        store.persist(&protected).unwrap();

        let mut engine_started = protected.clone();
        engine_started.revision = 3;
        engine_started.phase = JournalPhase::EngineStarted;
        store.persist(&engine_started).unwrap();

        let loaded = store.load_unresolved().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].session_id, 42);
        assert_eq!(loaded[0].revision, 3);
        assert_eq!(loaded[0].phase, JournalPhase::EngineStarted);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn accepts_only_the_complete_ordered_session_phase_sequence() {
        let (root, store) = store();
        store.persist(&RecoveryJournal::new(85)).unwrap();

        let mut protected = example_journal(85, 2);
        protected.phase = JournalPhase::EgressProtected;
        store.persist(&protected).unwrap();

        let mut engine = protected.clone();
        engine.revision = 3;
        engine.phase = JournalPhase::EngineStarted;
        store.persist(&engine).unwrap();

        let mut tunnel = engine.clone();
        tunnel.revision = 4;
        tunnel.phase = JournalPhase::TunnelCreated;
        store.persist(&tunnel).unwrap();

        let mut network = tunnel;
        network.revision = 5;
        network.phase = JournalPhase::NetworkConfigured;
        make_network_configured_dns_complete(&mut network);
        store.persist(&network).unwrap();

        let loaded = store.load_unresolved().unwrap();
        assert_eq!(loaded[0].phase, JournalPhase::NetworkConfigured);
        assert_eq!(loaded[0].revision, 5);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_network_configured_phase_with_legacy_or_partial_dns_state() {
        let mut legacy = example_journal(86, 1);
        legacy.phase = JournalPhase::NetworkConfigured;
        assert!(legacy.validate().is_err());

        let mut partial = example_journal(87, 1);
        partial.phase = JournalPhase::NetworkConfigured;
        make_network_configured_dns_complete(&mut partial);
        let DnsConfiguration::Interface(interface) = &mut partial.dns[0].applied else {
            panic!("test fixture must use an interface DNS snapshot");
        };
        interface.ipv6 = None;
        assert!(partial.validate().is_err());

        let mut no_stable_guid = example_journal(88, 1);
        no_stable_guid.phase = JournalPhase::NetworkConfigured;
        make_network_configured_dns_complete(&mut no_stable_guid);
        no_stable_guid.dns[0].interface_guid = None;
        assert!(no_stable_guid.validate().is_err());
    }

    #[test]
    fn validates_dual_stack_dns_family_identity_and_effective_lists() {
        let guid = "4d36e972-e325-11ce-bfc1-08002be10318";
        let mut journal = example_journal(89, 1);
        let full = DnsConfiguration::Interface(example_dns_interface(guid));
        journal.dns[0].interface_guid = Some(guid.to_string());
        journal.dns[0].applied = full.clone();
        journal.dns[0].previous = full.clone();
        journal.validate().unwrap();

        let mut wrong_family = full.clone();
        let DnsConfiguration::Interface(interface) = &mut wrong_family else {
            unreachable!();
        };
        interface.ipv6.as_mut().unwrap().effective_name_servers =
            vec!["192.0.2.54".parse().unwrap()];
        assert!(validate_dns_configuration(&wrong_family).is_err());

        let mut mismatched_guid = journal.clone();
        mismatched_guid.dns[0].interface_guid =
            Some("6d36e972-e325-11ce-bfc1-08002be10318".to_string());
        assert!(mismatched_guid.validate().is_err());
    }

    #[test]
    fn validates_doh_properties_against_the_exact_server_list() {
        let mut stack = example_dns_stack(true);
        stack.server_properties.push(DnsDohServerProperty {
            version: DNS_SERVER_PROPERTY_VERSION1,
            server_index: 0,
            property_type: 1,
            flags: 0,
            template: Some("https://dns.example.test/dns-query{?dns}".to_string()),
        });
        validate_dns_stack(&stack, true).unwrap();

        stack.server_properties[0].server_index = 2;
        assert!(validate_dns_stack(&stack, true).is_err());
    }

    #[test]
    fn missing_legacy_interface_guid_deserializes_but_cannot_authorize_network_configured() {
        let json = r#"{
            "interfaceIndex": 12,
            "applied": {"kind": "dhcp"},
            "previous": {"kind": "dhcp"}
        }"#;
        let record: DnsMutationRecord = serde_json::from_str(json).unwrap();
        assert!(record.interface_guid.is_none());
    }

    #[test]
    fn rejects_skipped_or_reversed_operational_phase_transitions() {
        let (root, store) = store();
        store.persist(&RecoveryJournal::new(81)).unwrap();

        let mut engine_started = example_journal(81, 2);
        engine_started.phase = JournalPhase::EngineStarted;
        assert!(store.persist(&engine_started).is_err());

        let mut protected = example_journal(81, 2);
        protected.phase = JournalPhase::EgressProtected;
        store.persist(&protected).unwrap();

        let mut regressed = protected.clone();
        regressed.revision = 3;
        regressed.phase = JournalPhase::Preparing;
        assert!(store.persist(&regressed).is_err());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn requires_resource_evidence_for_each_operational_phase() {
        let mut journal = example_journal(82, 1);
        journal.phase = JournalPhase::EgressProtected;
        journal.validate().unwrap();

        let mut missing_wfp = journal.clone();
        missing_wfp.firewall_filters.clear();
        assert!(missing_wfp.validate().is_err());

        let mut missing_engine = journal.clone();
        missing_engine.phase = JournalPhase::EngineStarted;
        missing_engine.engine = None;
        assert!(missing_engine.validate().is_err());

        let mut missing_tunnel = journal.clone();
        missing_tunnel.phase = JournalPhase::TunnelCreated;
        missing_tunnel.tunnel = None;
        assert!(missing_tunnel.validate().is_err());

        let mut missing_network_state = journal;
        missing_network_state.phase = JournalPhase::NetworkConfigured;
        missing_network_state.routes.clear();
        assert!(missing_network_state.validate().is_err());
        missing_network_state.routes = example_journal(82, 1).routes;
        missing_network_state.dns.clear();
        assert!(missing_network_state.validate().is_err());
    }

    #[test]
    fn disconnecting_and_recovery_required_are_terminal_fail_closed_phases() {
        let (root, store) = store();
        store.persist(&RecoveryJournal::new(83)).unwrap();

        let mut disconnecting = RecoveryJournal::new(83);
        disconnecting.revision = 2;
        disconnecting.phase = JournalPhase::Disconnecting;
        store.persist(&disconnecting).unwrap();

        let mut recovery = disconnecting.clone();
        recovery.revision = 3;
        recovery.phase = JournalPhase::RecoveryRequired;
        store.persist(&recovery).unwrap();

        let mut more_diagnostics = recovery.clone();
        more_diagnostics.revision = 4;
        store.persist(&more_diagnostics).unwrap();

        let mut resurrected = more_diagnostics;
        resurrected.revision = 5;
        resurrected.phase = JournalPhase::EgressProtected;
        assert!(store.persist(&resurrected).is_err());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_new_session_cannot_be_persisted_in_an_advanced_phase() {
        let (root, store) = store();
        let mut advanced = example_journal(84, 1);
        advanced.phase = JournalPhase::EgressProtected;
        assert!(store.persist(&advanced).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_non_monotonic_revisions() {
        let (root, store) = store();
        store.persist(&example_journal(7, 3)).unwrap();
        assert!(store.persist(&example_journal(7, 2)).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn validates_route_dns_tunnel_and_filter_resource_identities() {
        let mut journal = example_journal(1, 1);
        journal.validate().unwrap();

        journal.routes[0].destination_prefix = "0.0.0.0/33".to_string();
        assert!(journal.validate().is_err());

        let mut journal = example_journal(1, 1);
        journal.dns[0].interface_index = 0;
        assert!(journal.validate().is_err());

        let mut journal = example_journal(1, 1);
        journal.tunnel.as_mut().unwrap().interface_guid = "not-a-guid".to_string();
        assert!(journal.validate().is_err());

        let mut journal = example_journal(1, 1);
        journal.firewall_filters[0].filter_id = Some(0);
        assert!(journal.validate().is_err());
    }

    #[test]
    fn rejects_pre_mutation_filter_intents_without_a_stable_guid() {
        let mut journal = example_journal(69, 1);
        journal.firewall_filters[0].filter_key = None;
        journal.firewall_filters[0].filter_id = None;
        assert!(journal.validate().is_err());
    }

    #[test]
    fn accepts_pre_mutation_filter_intent_without_a_runtime_id() {
        let mut journal = example_journal(70, 1);
        journal.firewall_filters[0].filter_id = None;
        journal.firewall_filters[0].filter_key =
            Some("ac9af5e4-5e27-4dce-8b6a-19c175e233d1".to_string());

        journal.validate().unwrap();
        let encoded = serde_json::to_vec(&journal).unwrap();
        let decoded: RecoveryJournal = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.firewall_filters[0].filter_id, None);
        assert_eq!(
            decoded.firewall_filters[0].filter_key.as_deref(),
            Some("ac9af5e4-5e27-4dce-8b6a-19c175e233d1")
        );
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
        duplicate.firewall_filters[1].filter_id = Some(78);
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
