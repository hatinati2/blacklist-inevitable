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
#[serde(tag = "kind", content = "servers", rename_all = "camelCase")]
pub enum DnsConfiguration {
    Dhcp,
    Static(Vec<IpAddr>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsMutationRecord {
    pub interface_index: u32,
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
            validate_dns_configuration(&change.applied)?;
            validate_dns_configuration(&change.previous)?;
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
        || state.interface_luid == Some(0)
        || state.next_hop.is_some_and(|gateway| gateway.is_ipv4() != destination.is_ipv4())
    {
        return Err("The recovery journal contains an invalid route state.".to_string());
    }
    Ok(())
}

fn validate_dns_configuration(configuration: &DnsConfiguration) -> Result<(), String> {
    if let DnsConfiguration::Static(servers) = configuration {
        if servers.is_empty() || servers.len() > MAX_DNS_SERVERS {
            return Err("The recovery journal contains an invalid DNS server list.".to_string());
        }
        let unique: BTreeSet<_> = servers.iter().collect();
        if unique.len() != servers.len() {
            return Err("The recovery journal contains duplicate DNS servers.".to_string());
        }
    }
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
            },
            previous: Some(RouteState {
                interface_index: 12,
                interface_luid: Some(0x0001_0000_0000_000C),
                next_hop: Some("192.0.2.1".parse().unwrap()),
                metric: 25,
            }),
        });
        journal.dns.push(DnsMutationRecord {
            interface_index: 12,
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

        let decoded: RecoveryJournal = serde_json::from_value(legacy).unwrap();
        assert_eq!(decoded.routes[0].applied.interface_luid, None);
        assert_eq!(decoded.routes[0].previous.as_ref().unwrap().interface_luid, None);
        decoded.validate().unwrap();
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
