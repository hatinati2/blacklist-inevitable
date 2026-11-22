//! Pure, read-only assessment of journaled Windows resources against an OS snapshot.
//!
//! This module never mutates processes, interfaces, routes, DNS, WFP, or journal files.
//! A Windows reconciler must gather each observation with checked OS APIs, perform
//! one mutation at a time, then take a fresh snapshot and assess again. The journal
//! may only be removed when every disposition is VerifiedClean.

use std::collections::{BTreeMap, BTreeSet};

use crate::recovery_journal::{
    DnsConfiguration, DnsMutationRecord, EngineProcessRecord, FirewallFilterRecord,
    RecoveryJournal, RouteMutationRecord, RouteState, TunnelInterfaceRecord,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation<T> {
    /// The OS query failed, was incomplete, or could not establish ownership.
    Unknown,
    /// The queried resource was positively confirmed absent.
    Absent,
    /// The OS query returned a concrete resource state.
    Present(T),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceDisposition {
    /// A fresh OS observation proves the recorded resource is already absent
    /// or the previous configuration has already been restored.
    VerifiedClean,
    /// The recorded resource still exists and must be stopped or removed.
    NeedsCleanup,
    /// The recorded mutation is still applied and its exact previous state
    /// must be restored before the journal can be removed.
    NeedsRestore,
    /// The observed state conflicts with the journal; do not mutate it.
    Conflict,
    /// The observation is incomplete or cannot identify the resource safely.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverySnapshot {
    /// Process identity must include PID and creation time to detect PID reuse.
    pub engine: Observation<EngineProcessRecord>,
    /// Full journaled tunnel identity and assigned unicast address inventory.
    pub tunnel: Observation<TunnelInterfaceRecord>,
    /// Entries are keyed by the exact destination prefix stored in the journal.
    /// An omitted key is Unknown, never implicitly Absent.
    pub routes: BTreeMap<String, Observation<RouteState>>,
    /// Entries are keyed by Windows interface index. An omitted key is Unknown.
    pub dns: BTreeMap<u32, Observation<DnsConfiguration>>,
    /// This must be a complete provider-scoped WFP enumeration. Runtime filter
    /// IDs are diagnostic only; stable filter GUIDs establish identity.
    pub firewall_filters: Observation<Vec<FirewallFilterRecord>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAssessment {
    pub destination_prefix: String,
    pub disposition: ResourceDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAssessment {
    pub interface_index: u32,
    pub disposition: ResourceDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryAssessment {
    pub engine: ResourceDisposition,
    pub tunnel: ResourceDisposition,
    pub routes: Vec<RouteAssessment>,
    pub dns: Vec<DnsAssessment>,
    pub firewall_filters: ResourceDisposition,
    /// True only when every journaled resource and the complete WFP provider
    /// inventory are positively verified clean.
    pub can_remove_journal: bool,
}

pub fn assess_recovery(
    journal: &RecoveryJournal,
    snapshot: &RecoverySnapshot,
) -> RecoveryAssessment {
    let engine = assess_engine(journal.engine.as_ref(), &snapshot.engine);
    let tunnel = assess_tunnel(journal.tunnel.as_ref(), &snapshot.tunnel);

    let routes: Vec<_> = journal
        .routes
        .iter()
        .map(|record| RouteAssessment {
            destination_prefix: record.destination_prefix.clone(),
            disposition: assess_route(
                record,
                snapshot.routes.get(&record.destination_prefix),
            ),
        })
        .collect();

    let dns: Vec<_> = journal
        .dns
        .iter()
        .map(|record| DnsAssessment {
            interface_index: record.interface_index,
            disposition: assess_dns(record, snapshot.dns.get(&record.interface_index)),
        })
        .collect();

    let firewall_filters = assess_firewall_filters(
        &journal.firewall_filters,
        &snapshot.firewall_filters,
    );

    let can_remove_journal = engine == ResourceDisposition::VerifiedClean
        && tunnel == ResourceDisposition::VerifiedClean
        && routes
            .iter()
            .all(|item| item.disposition == ResourceDisposition::VerifiedClean)
        && dns
            .iter()
            .all(|item| item.disposition == ResourceDisposition::VerifiedClean)
        && firewall_filters == ResourceDisposition::VerifiedClean;

    RecoveryAssessment {
        engine,
        tunnel,
        routes,
        dns,
        firewall_filters,
        can_remove_journal,
    }
}

fn assess_engine(
    expected: Option<&EngineProcessRecord>,
    observed: &Observation<EngineProcessRecord>,
) -> ResourceDisposition {
    let Some(expected) = expected else {
        return ResourceDisposition::VerifiedClean;
    };

    match observed {
        Observation::Unknown => ResourceDisposition::Unknown,
        Observation::Absent => ResourceDisposition::VerifiedClean,
        Observation::Present(actual) if actual == expected => {
            ResourceDisposition::NeedsCleanup
        }
        // A PID with a different creation time is a different process. Never
        // terminate it as a substitute for the journaled engine process.
        Observation::Present(_) => ResourceDisposition::Conflict,
    }
}

fn assess_tunnel(
    expected: Option<&TunnelInterfaceRecord>,
    observed: &Observation<TunnelInterfaceRecord>,
) -> ResourceDisposition {
    let Some(expected) = expected else {
        return ResourceDisposition::VerifiedClean;
    };

    match observed {
        Observation::Unknown => ResourceDisposition::Unknown,
        Observation::Absent => ResourceDisposition::VerifiedClean,
        Observation::Present(actual) => {
            // Older version-1 journals recorded only the IP values, not their
            // prefix lengths. They remain readable, but cannot authorize a
            // positive identity match while the adapter is still present.
            if expected.address_details.is_empty() {
                return ResourceDisposition::Unknown;
            }

            let expected_guid = normalize_guid(&expected.interface_guid);
            let actual_guid = normalize_guid(&actual.interface_guid);
            if expected_guid.is_none() || actual_guid.is_none() {
                return ResourceDisposition::Unknown;
            }
            if expected_guid != actual_guid {
                return ResourceDisposition::Conflict;
            }

            let expected_addresses: BTreeSet<_> = expected.addresses.iter().copied().collect();
            let actual_addresses: BTreeSet<_> = actual.addresses.iter().copied().collect();
            let expected_details: BTreeSet<_> =
                expected.address_details.iter().cloned().collect();
            let actual_details: BTreeSet<_> = actual.address_details.iter().cloned().collect();

            if expected.interface_index == actual.interface_index
                && expected.alias.eq_ignore_ascii_case(&actual.alias)
                && expected.mtu == actual.mtu
                && expected_addresses == actual_addresses
                && expected_details == actual_details
            {
                ResourceDisposition::NeedsCleanup
            } else {
                ResourceDisposition::Conflict
            }
        }
    }
}

fn assess_route(
    record: &RouteMutationRecord,
    observed: Option<&Observation<RouteState>>,
) -> ResourceDisposition {
    let Some(observed) = observed else {
        return ResourceDisposition::Unknown;
    };

    // A route's interface index can be reused after adapter removal or reboot.
    // Both the applied route and any previous route must carry a stable NET_LUID
    // before a match can authorize cleanup or journal removal.
    if record.applied.interface_luid.is_none()
        || record.previous.as_ref().is_some_and(|previous| previous.interface_luid.is_none())
    {
        return ResourceDisposition::Unknown;
    }

    match observed {
        Observation::Unknown => ResourceDisposition::Unknown,
        Observation::Absent => {
            if record.previous.is_none() {
                ResourceDisposition::VerifiedClean
            } else {
                // A route that existed before the session must be restored,
                // even when the session's route is now absent.
                ResourceDisposition::NeedsRestore
            }
        }
        Observation::Present(actual) => {
            if record.previous.as_ref() == Some(actual) {
                ResourceDisposition::VerifiedClean
            } else if actual == &record.applied {
                if record.previous.is_some() {
                    ResourceDisposition::NeedsRestore
                } else {
                    ResourceDisposition::NeedsCleanup
                }
            } else {
                ResourceDisposition::Conflict
            }
        }
    }
}

fn assess_dns(
    record: &DnsMutationRecord,
    observed: Option<&Observation<DnsConfiguration>>,
) -> ResourceDisposition {
    let Some(observed) = observed else {
        return ResourceDisposition::Unknown;
    };

    // Compact DHCP/static records predate the complete DNS model. They remain
    // deserializable, but cannot prove profile, search-list, and DoH state.
    let Some(expected_guid) = record.interface_guid.as_deref().and_then(normalize_guid) else {
        return ResourceDisposition::Unknown;
    };
    if complete_dns_interface(&record.previous, &expected_guid).is_none()
        || complete_dns_interface(&record.applied, &expected_guid).is_none()
    {
        return ResourceDisposition::Unknown;
    }

    match observed {
        // An absent/unavailable interface does not prove what DNS state Windows
        // will apply if that interface returns; keep recovery blocked.
        Observation::Unknown | Observation::Absent => ResourceDisposition::Unknown,
        Observation::Present(actual) => {
            if let DnsConfiguration::Interface(interface) = actual {
                if normalize_guid(&interface.interface_guid)
                    .is_some_and(|guid| guid != expected_guid)
                {
                    return ResourceDisposition::Conflict;
                }
            }
            if complete_dns_interface(actual, &expected_guid).is_none() {
                return ResourceDisposition::Unknown;
            }

            if actual == &record.previous {
                ResourceDisposition::VerifiedClean
            } else if actual == &record.applied {
                ResourceDisposition::NeedsRestore
            } else {
                ResourceDisposition::Conflict
            }
        }
    }
}

fn complete_dns_interface<'a>(
    configuration: &'a DnsConfiguration,
    expected_guid: &str,
) -> Option<&'a crate::recovery_journal::DnsInterfaceConfiguration> {
    let DnsConfiguration::Interface(interface) = configuration else {
        return None;
    };
    if interface.ipv4.is_none() || interface.ipv6.is_none() {
        return None;
    }
    let actual_guid = normalize_guid(&interface.interface_guid)?;
    if actual_guid == expected_guid {
        Some(interface)
    } else {
        None
    }
}

fn normalize_guid(value: &str) -> Option<String> {
    let parsed = uuid::Uuid::parse_str(value).ok()?;
    if !parsed.to_string().eq_ignore_ascii_case(value) {
        return None;
    }
    Some(parsed.to_string())
}

fn assess_firewall_filters(
    expected: &[FirewallFilterRecord],
    observed: &Observation<Vec<FirewallFilterRecord>>,
) -> ResourceDisposition {
    let Observation::Present(observed) = observed else {
        return match observed {
            Observation::Unknown => ResourceDisposition::Unknown,
            // No provider object does not prove that its persistent filters
            // are absent. Only a successful complete enumeration can do that.
            Observation::Absent => ResourceDisposition::Unknown,
            Observation::Present(_) => unreachable!(),
        };
    };

    // A successful complete provider-scoped inventory with zero entries
    // proves every product filter is absent, even for legacy journal records
    // that predate stable filter GUIDs. Unknown/failed enumeration never reaches
    // this branch because it is represented as Observation::Unknown.
    if observed.is_empty() {
        return ResourceDisposition::VerifiedClean;
    }

    let mut expected_by_key = BTreeMap::new();
    for record in expected {
        let Some(filter_key) = record.filter_key.as_deref().and_then(normalize_guid) else {
            // A legacy runtime filter ID is never a durable identity.
            return ResourceDisposition::Unknown;
        };
        let Some(provider_key) = normalize_guid(&record.provider_key) else {
            return ResourceDisposition::Unknown;
        };
        let Some(layer_key) = normalize_guid(&record.layer_key) else {
            return ResourceDisposition::Unknown;
        };
        expected_by_key.insert(filter_key, (provider_key, layer_key));
    }

    let mut seen = BTreeSet::new();
    let mut any_expected_filter_present = false;
    for record in observed {
        let Some(filter_key) = record.filter_key.as_deref().and_then(normalize_guid) else {
            return ResourceDisposition::Unknown;
        };
        let Some(provider_key) = normalize_guid(&record.provider_key) else {
            return ResourceDisposition::Unknown;
        };
        let Some(layer_key) = normalize_guid(&record.layer_key) else {
            return ResourceDisposition::Unknown;
        };
        if !seen.insert(filter_key.clone()) {
            return ResourceDisposition::Conflict;
        }
        match expected_by_key.get(&filter_key) {
            Some((expected_provider, expected_layer))
                if expected_provider == &provider_key && expected_layer == &layer_key =>
            {
                // Stable identity is authoritative. A BFE runtime filter ID may
                // change after restart and is deliberately not used for matching.
                any_expected_filter_present = true;
            }
            _ => {
                // An unjournaled filter in the product namespace, or a filter
                // whose provider/layer differs, makes ownership incomplete.
                return ResourceDisposition::Conflict;
            }
        }
    }

    if any_expected_filter_present {
        ResourceDisposition::NeedsCleanup
    } else {
        ResourceDisposition::VerifiedClean
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery_journal::{RecoveryJournal, TunnelInterfaceRecord};
    use std::net::IpAddr;

    fn engine() -> EngineProcessRecord {
        EngineProcessRecord {
            process_id: 1234,
            creation_time_100ns: 133700000000000000,
        }
    }

    fn route_record() -> RouteMutationRecord {
        RouteMutationRecord {
            destination_prefix: "0.0.0.0/0".into(),
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
        }
    }

    fn dns_record() -> DnsMutationRecord {
        DnsMutationRecord {
            interface_index: 12,
            interface_guid: Some("4d36e972-e325-11ce-bfc1-08002be10318".into()),
            applied: DnsConfiguration::Static(vec!["198.18.0.1".parse().unwrap()]),
            previous: DnsConfiguration::Dhcp,
        }
    }

    fn dns_stack(ipv6: bool, server: &str, effective: &str) -> crate::recovery_journal::DnsStackConfiguration {
        crate::recovery_journal::DnsStackConfiguration {
            name_servers: Some(vec![server.parse().unwrap()]),
            profile_name_servers: None,
            effective_name_servers: vec![effective.parse().unwrap()],
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

    fn complete_dns(server4: &str, server6: &str) -> DnsConfiguration {
        DnsConfiguration::Interface(crate::recovery_journal::DnsInterfaceConfiguration {
            interface_guid: "4d36e972-e325-11ce-bfc1-08002be10318".into(),
            ipv4: Some(dns_stack(false, server4, server4)),
            ipv6: Some(dns_stack(true, server6, server6)),
        })
    }

    fn filter_record(filter_id: u64) -> FirewallFilterRecord {
        FirewallFilterRecord {
            provider_key: "9d45d56a-6b31-48aa-9c45-72c8b25e2f10".into(),
            filter_key: Some("ac9af5e4-5e27-4dce-8b6a-19c175e233d1".into()),
            layer_key: "6d6f8e80-62d4-4b90-a1b8-10ac74e55e20".into(),
            filter_id,
        }
    }

    fn empty_snapshot() -> RecoverySnapshot {
        RecoverySnapshot {
            engine: Observation::Absent,
            tunnel: Observation::Absent,
            routes: BTreeMap::new(),
            dns: BTreeMap::new(),
            firewall_filters: Observation::Present(Vec::new()),
        }
    }

    #[test]
    fn empty_journal_can_be_removed_only_after_complete_wfp_inventory() {
        let journal = RecoveryJournal::new(1);
        let mut snapshot = empty_snapshot();
        assert!(assess_recovery(&journal, &snapshot).can_remove_journal);

        snapshot.firewall_filters = Observation::Unknown;
        let result = assess_recovery(&journal, &snapshot);
        assert!(!result.can_remove_journal);
        assert_eq!(result.firewall_filters, ResourceDisposition::Unknown);

        snapshot.firewall_filters = Observation::Absent;
        let absent_provider = assess_recovery(&journal, &snapshot);
        assert_eq!(absent_provider.firewall_filters, ResourceDisposition::Unknown);
        assert!(!absent_provider.can_remove_journal);
    }

    #[test]
    fn engine_identity_requires_creation_time_match() {
        let mut journal = RecoveryJournal::new(2);
        journal.engine = Some(engine());

        let mut snapshot = empty_snapshot();
        snapshot.engine = Observation::Present(engine());
        let result = assess_recovery(&journal, &snapshot);
        assert_eq!(result.engine, ResourceDisposition::NeedsCleanup);
        assert!(!result.can_remove_journal);

        let mut reused_pid = engine();
        reused_pid.creation_time_100ns += 1;
        snapshot.engine = Observation::Present(reused_pid);
        assert_eq!(
            assess_recovery(&journal, &snapshot).engine,
            ResourceDisposition::Conflict
        );
    }

    #[test]
    fn tunnel_is_matched_by_stable_guid_not_alias() {
        let mut journal = RecoveryJournal::new(3);
        journal.tunnel = Some(TunnelInterfaceRecord {
            interface_guid: "4d36e972-e325-11ce-bfc1-08002be10318".into(),
            interface_index: 17,
            alias: "product-tun".into(),
            mtu: 1500,
            addresses: vec!["198.18.0.1".parse::<IpAddr>().unwrap()],
            address_details: vec![crate::recovery_journal::TunnelAddressRecord {
                address: "198.18.0.1".parse().unwrap(),
                prefix_length: 30,
            }],
        });

        let mut snapshot = empty_snapshot();
        snapshot.tunnel = Observation::Present(journal.tunnel.clone().unwrap());
        assert_eq!(
            assess_recovery(&journal, &snapshot).tunnel,
            ResourceDisposition::NeedsCleanup
        );

        let mut changed_address = journal.tunnel.clone().unwrap();
        changed_address.address_details[0].prefix_length = 29;
        snapshot.tunnel = Observation::Present(changed_address);
        assert_eq!(
            assess_recovery(&journal, &snapshot).tunnel,
            ResourceDisposition::Conflict
        );

        let mut different_adapter = journal.tunnel.clone().unwrap();
        different_adapter.interface_guid =
            "6d6f8e80-62d4-4b90-a1b8-10ac74e55e20".into();
        snapshot.tunnel = Observation::Present(different_adapter);
        assert_eq!(
            assess_recovery(&journal, &snapshot).tunnel,
            ResourceDisposition::Conflict
        );

        let mut legacy = journal.tunnel.clone().unwrap();
        legacy.address_details.clear();
        journal.tunnel = Some(legacy.clone());
        snapshot.tunnel = Observation::Absent;
        assert_eq!(
            assess_recovery(&journal, &snapshot).tunnel,
            ResourceDisposition::VerifiedClean
        );

        snapshot.tunnel = Observation::Present(legacy);
        assert_eq!(
            assess_recovery(&journal, &snapshot).tunnel,
            ResourceDisposition::Unknown
        );
    }

    #[test]
    fn route_must_be_restored_to_exact_previous_value() {
        let mut journal = RecoveryJournal::new(4);
        let record = route_record();
        let previous = record.previous.clone().unwrap();
        let applied = record.applied.clone();
        journal.routes.push(record);
        let mut snapshot = empty_snapshot();

        snapshot.routes.insert(
            "0.0.0.0/0".into(),
            Observation::Present(applied),
        );
        assert_eq!(
            assess_recovery(&journal, &snapshot).routes[0].disposition,
            ResourceDisposition::NeedsRestore
        );

        snapshot.routes.insert(
            "0.0.0.0/0".into(),
            Observation::Present(previous),
        );
        assert_eq!(
            assess_recovery(&journal, &snapshot).routes[0].disposition,
            ResourceDisposition::VerifiedClean
        );
    }

    #[test]
    fn route_created_by_session_must_be_absent() {
        let mut journal = RecoveryJournal::new(5);
        let mut record = route_record();
        record.previous = None;
        journal.routes.push(record.clone());

        let mut snapshot = empty_snapshot();
        snapshot.routes.insert(
            record.destination_prefix.clone(),
            Observation::Present(record.applied.clone()),
        );
        assert_eq!(
            assess_recovery(&journal, &snapshot).routes[0].disposition,
            ResourceDisposition::NeedsCleanup
        );

        snapshot.routes.insert(
            record.destination_prefix,
            Observation::Absent,
        );
        assert_eq!(
            assess_recovery(&journal, &snapshot).routes[0].disposition,
            ResourceDisposition::VerifiedClean
        );
    }

    #[test]
    fn complete_dual_stack_dns_requires_exact_ipv4_ipv6_and_profile_state() {
        let previous = complete_dns("192.0.2.53", "2001:db8::53");
        let applied = complete_dns("198.18.0.1", "fd00::53");
        let mut journal = RecoveryJournal::new(101);
        journal.dns.push(DnsMutationRecord {
            interface_index: 12,
            interface_guid: Some("4d36e972-e325-11ce-bfc1-08002be10318".into()),
            applied: applied.clone(),
            previous: previous.clone(),
        });
        let mut snapshot = empty_snapshot();

        snapshot.dns.insert(12, Observation::Present(previous));
        assert_eq!(
            assess_recovery(&journal, &snapshot).dns[0].disposition,
            ResourceDisposition::VerifiedClean
        );

        snapshot.dns.insert(12, Observation::Present(applied));
        assert_eq!(
            assess_recovery(&journal, &snapshot).dns[0].disposition,
            ResourceDisposition::NeedsRestore
        );

        snapshot.dns.insert(
            12,
            Observation::Present(complete_dns("198.18.0.1", "2001:db8::99")),
        );
        assert_eq!(
            assess_recovery(&journal, &snapshot).dns[0].disposition,
            ResourceDisposition::Conflict
        );
    }

    #[test]
    fn dns_with_missing_stack_or_reused_interface_index_is_not_clean() {
        let previous = complete_dns("192.0.2.53", "2001:db8::53");
        let applied = complete_dns("198.18.0.1", "fd00::53");
        let mut journal = RecoveryJournal::new(102);
        journal.dns.push(DnsMutationRecord {
            interface_index: 12,
            interface_guid: Some("4d36e972-e325-11ce-bfc1-08002be10318".into()),
            applied,
            previous,
        });
        let mut snapshot = empty_snapshot();

        let mut incomplete = match complete_dns("192.0.2.53", "2001:db8::53") {
            DnsConfiguration::Interface(config) => config,
            _ => unreachable!(),
        };
        incomplete.ipv6 = None;
        snapshot.dns.insert(
            12,
            Observation::Present(DnsConfiguration::Interface(incomplete)),
        );
        assert_eq!(
            assess_recovery(&journal, &snapshot).dns[0].disposition,
            ResourceDisposition::Unknown
        );

        let different_interface = DnsConfiguration::Interface(
            crate::recovery_journal::DnsInterfaceConfiguration {
                interface_guid: "6d6f8e80-62d4-4b90-a1b8-10ac74e55e20".into(),
                ipv4: Some(dns_stack(false, "192.0.2.53", "192.0.2.53")),
                ipv6: Some(dns_stack(true, "2001:db8::53", "2001:db8::53")),
            },
        );
        snapshot.dns.insert(12, Observation::Present(different_interface));
        assert_eq!(
            assess_recovery(&journal, &snapshot).dns[0].disposition,
            ResourceDisposition::Conflict
        );
    }

    #[test]
    fn legacy_dns_records_without_stable_guid_remain_unknown() {
        let mut journal = RecoveryJournal::new(103);
        let mut record = dns_record();
        record.interface_guid = None;
        journal.dns.push(record.clone());

        let mut snapshot = empty_snapshot();
        snapshot.dns.insert(
            record.interface_index,
            Observation::Present(record.previous),
        );
        assert_eq!(
            assess_recovery(&journal, &snapshot).dns[0].disposition,
            ResourceDisposition::Unknown
        );
        assert!(!assess_recovery(&journal, &snapshot).can_remove_journal);

        // Even with a stable GUID, the pre-dual-stack DHCP/static model omits
        // profile servers, search settings, and DoH policy and cannot prove clean.
        let mut legacy_compact = dns_record();
        legacy_compact.interface_guid =
            Some("4d36e972-e325-11ce-bfc1-08002be10318".into());
        journal.dns = vec![legacy_compact.clone()];
        snapshot.dns.insert(
            legacy_compact.interface_index,
            Observation::Present(legacy_compact.previous),
        );
        assert_eq!(
            assess_recovery(&journal, &snapshot).dns[0].disposition,
            ResourceDisposition::Unknown
        );
    }

    #[test]
    fn missing_route_or_unknown_dns_observation_never_counts_as_clean() {
        let mut journal = RecoveryJournal::new(6);
        journal.routes.push(route_record());
        journal.dns.push(dns_record());
        let snapshot = empty_snapshot();
        let result = assess_recovery(&journal, &snapshot);
        assert_eq!(result.routes[0].disposition, ResourceDisposition::Unknown);
        assert_eq!(result.dns[0].disposition, ResourceDisposition::Unknown);
        assert!(!result.can_remove_journal);
    }

    #[test]
    fn reused_interface_index_with_a_different_luid_is_a_route_conflict() {
        let mut journal = RecoveryJournal::new(92);
        let record = route_record();
        let previous = record.previous.clone().unwrap();
        journal.routes.push(record.clone());

        let mut snapshot = empty_snapshot();
        let mut observed = previous;
        observed.interface_index = record.previous.as_ref().unwrap().interface_index;
        observed.interface_luid = Some(0x0001_0000_0000_FFFF);
        snapshot.routes.insert(
            record.destination_prefix,
            Observation::Present(observed),
        );

        let result = assess_recovery(&journal, &snapshot);
        assert_eq!(result.routes[0].disposition, ResourceDisposition::Conflict);
        assert!(!result.can_remove_journal);
    }

    #[test]
    fn legacy_route_without_stable_interface_luid_blocks_recovery() {
        let mut journal = RecoveryJournal::new(91);
        let mut record = route_record();
        record.applied.interface_luid = None;
        journal.routes.push(record.clone());

        let mut snapshot = empty_snapshot();
        snapshot.routes.insert(
            record.destination_prefix,
            Observation::Present(record.applied),
        );

        let result = assess_recovery(&journal, &snapshot);
        assert_eq!(result.routes[0].disposition, ResourceDisposition::Unknown);
        assert!(!result.can_remove_journal);
    }

    #[test]
    fn dns_requires_exact_previous_dual_stack_configuration() {
        let mut journal = RecoveryJournal::new(7);
        let record = DnsMutationRecord {
            interface_index: 12,
            interface_guid: Some("4d36e972-e325-11ce-bfc1-08002be10318".into()),
            applied: complete_dns("198.18.0.1", "fd00::53"),
            previous: complete_dns("192.0.2.53", "2001:db8::53"),
        };
        journal.dns.push(record.clone());

        let mut snapshot = empty_snapshot();
        snapshot.dns.insert(
            record.interface_index,
            Observation::Present(record.applied.clone()),
        );
        assert_eq!(
            assess_recovery(&journal, &snapshot).dns[0].disposition,
            ResourceDisposition::NeedsRestore
        );

        snapshot.dns.insert(
            record.interface_index,
            Observation::Present(record.previous),
        );
        assert_eq!(
            assess_recovery(&journal, &snapshot).dns[0].disposition,
            ResourceDisposition::VerifiedClean
        );
    }

    #[test]
    fn wfp_uses_stable_keys_and_ignores_runtime_filter_id_changes() {
        let mut journal = RecoveryJournal::new(8);
        journal.firewall_filters.push(filter_record(77));
        let mut snapshot = empty_snapshot();
        snapshot.firewall_filters = Observation::Present(vec![filter_record(999)]);

        assert_eq!(
            assess_recovery(&journal, &snapshot).firewall_filters,
            ResourceDisposition::NeedsCleanup
        );

        snapshot.firewall_filters = Observation::Present(Vec::new());
        assert_eq!(
            assess_recovery(&journal, &snapshot).firewall_filters,
            ResourceDisposition::VerifiedClean
        );
    }

    #[test]
    fn complete_empty_wfp_inventory_clears_legacy_filter_records() {
        let mut journal = RecoveryJournal::new(93);
        let mut legacy = filter_record(77);
        legacy.filter_key = None;
        journal.firewall_filters.push(legacy);

        let mut snapshot = empty_snapshot();
        snapshot.firewall_filters = Observation::Present(Vec::new());

        assert_eq!(
            assess_recovery(&journal, &snapshot).firewall_filters,
            ResourceDisposition::VerifiedClean
        );
    }

    #[test]
    fn wfp_unjournaled_or_ambiguous_filters_block_recovery() {
        let mut journal = RecoveryJournal::new(9);
        journal.firewall_filters.push(filter_record(77));
        let mut snapshot = empty_snapshot();

        let mut unexpected = filter_record(88);
        unexpected.filter_key = Some("d3c2a1b0-1111-4222-8333-444455556666".into());
        snapshot.firewall_filters = Observation::Present(vec![unexpected]);
        assert_eq!(
            assess_recovery(&journal, &snapshot).firewall_filters,
            ResourceDisposition::Conflict
        );

        let mut legacy = filter_record(77);
        legacy.filter_key = None;
        journal.firewall_filters = vec![legacy];
        snapshot.firewall_filters = Observation::Present(vec![filter_record(77)]);
        assert_eq!(
            assess_recovery(&journal, &snapshot).firewall_filters,
            ResourceDisposition::Unknown
        );
    }

    #[test]
    fn journal_removal_requires_every_resource_to_be_verified_clean() {
        let mut journal = RecoveryJournal::new(10);
        journal.engine = Some(engine());
        journal.routes.push(route_record());
        let route = journal.routes[0].clone();
        let expected_engine = journal.engine.clone().unwrap();

        let mut snapshot = empty_snapshot();
        snapshot.engine = Observation::Present(expected_engine);
        snapshot.routes.insert(
            route.destination_prefix,
            Observation::Present(route.previous.unwrap()),
        );

        let result = assess_recovery(&journal, &snapshot);
        assert_eq!(result.engine, ResourceDisposition::NeedsCleanup);
        assert!(!result.can_remove_journal);

        snapshot.engine = Observation::Absent;
        assert!(assess_recovery(&journal, &snapshot).can_remove_journal);
    }
}
