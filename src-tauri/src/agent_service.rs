//! Dedicated Windows Service Control Manager host for the privileged Agent.
//!
//! The service owns the local authenticated status-only named pipe. Startup may
//! remove exact Agent-owned WFP filters for isolated WFP-only recovery journals;
//! installing traffic policy, starting an engine, TUN, route and DNS operations
//! remain disabled until the full recovery and packet-capture release gates pass.

#[cfg(windows)]
mod windows_service {
    use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use crate::connection_state::{ConnectionCoordinator, ConnectionPhase};
    use crate::recovery_journal::RecoveryJournalStore;

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_CALL_NOT_IMPLEMENTED, ERROR_GEN_FAILURE, HANDLE,
    };
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
        SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
        SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOPPED,
        SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
        SetServiceStatus, StartServiceCtrlDispatcherW,
    };
    use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent};

    const SERVICE_NAME: [u16; 25] = [
        66, 108, 97, 99, 107, 108, 105, 115, 116, 73, 110, 101, 118, 105, 116, 97, 98, 108, 101,
        65, 103, 101, 110, 116, 0,
    ];

    static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);
    static STOP_EVENT: AtomicIsize = AtomicIsize::new(0);
    static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
    static EVENT_LOCK: Mutex<()> = Mutex::new(());

    fn status(state: u32, accepted: u32, win32_exit: u32, service_exit: u32, wait_hint_ms: u32) -> SERVICE_STATUS {
        SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: accepted,
            dwWin32ExitCode: win32_exit,
            dwServiceSpecificExitCode: service_exit,
            dwCheckPoint: 0,
            dwWaitHint: wait_hint_ms,
        }
    }

    fn report_status(value: &SERVICE_STATUS) -> bool {
        let handle = STATUS_HANDLE.load(Ordering::Acquire)
            as windows_sys::Win32::System::Services::SERVICE_STATUS_HANDLE;
        if handle.is_null() {
            return false;
        }
        unsafe { SetServiceStatus(handle, value) != 0 }
    }

    fn signal_stop() {
        STOP_REQUESTED.store(true, Ordering::Release);
        let _guard = EVENT_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let event = STOP_EVENT.load(Ordering::Acquire) as HANDLE;
        if !event.is_null() {
            // The overlapped pipe listener waits on this event alongside each
            // connection/read/write completion event. Stop therefore cancels
            // that exact I/O operation and drains its OVERLAPPED before exit.
            unsafe { SetEvent(event) };
        }
    }

    unsafe extern "system" fn control_handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut core::ffi::c_void,
        _context: *mut core::ffi::c_void,
    ) -> u32 {
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                signal_stop();
                0
            }
            SERVICE_CONTROL_INTERROGATE => 0,
            _ => ERROR_CALL_NOT_IMPLEMENTED,
        }
    }

    fn close_owned_handles(pipe: HANDLE, event: HANDLE) {
        if !pipe.is_null() && pipe != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(pipe) };
        }
        let _guard = EVENT_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        STOP_EVENT.store(0, Ordering::Release);
        if !event.is_null() {
            unsafe { CloseHandle(event) };
        }
    }

    fn open_recovery_journal_store() -> Result<(RecoveryJournalStore, usize), String> {
        let program_data = std::env::var_os("ProgramData")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "The Windows ProgramData directory is unavailable to the Agent service.".to_string())?;
        open_recovery_journal_store_at(&PathBuf::from(program_data))
    }

    fn open_recovery_journal_store_at(
        program_data: &Path,
    ) -> Result<(RecoveryJournalStore, usize), String> {
        let journal_directory = program_data
            .join("blacklist-inevitable")
            .join("Agent");
        let store = RecoveryJournalStore::open(journal_directory)?;
        let unresolved = store.load_unresolved()?;
        Ok((store, unresolved.len()))
    }

    #[derive(Default)]
    struct StartupRecoveryOutcome {
        recovered_wfp_only_sessions: usize,
        failure: Option<String>,
    }

    fn is_wfp_only_recovery_session(
        journal: &crate::recovery_journal::RecoveryJournal,
    ) -> bool {
        journal.engine.is_none()
            && journal.tunnel.is_none()
            && journal.routes.is_empty()
            && journal.dns.is_empty()
            && !journal.firewall_filters.is_empty()
    }

    /// Reconcile only journals that contain WFP filters and no process, TUN,
    /// route, or DNS state. The injected callback must remove exact journalled
    /// filter keys and independently verify absence before this function clears
    /// the journal. Mixed-resource sessions are deliberately deferred.
    fn reconcile_wfp_only_sessions<F>(
        store: &RecoveryJournalStore,
        mut remove_exact_filters: F,
    ) -> StartupRecoveryOutcome
    where
        F: FnMut(&[crate::recovery_journal::FirewallFilterRecord]) -> Result<(), String>,
    {
        let journals = match store.load_unresolved() {
            Ok(journals) => journals,
            Err(error) => {
                return StartupRecoveryOutcome {
                    recovered_wfp_only_sessions: 0,
                    failure: Some(error),
                };
            }
        };

        let mut outcome = StartupRecoveryOutcome::default();
        for journal in journals.iter().filter(|item| is_wfp_only_recovery_session(item)) {
            if let Err(error) = remove_exact_filters(&journal.firewall_filters) {
                outcome.failure = Some(error);
                break;
            }
            if let Err(error) = store.remove_session(journal.session_id) {
                outcome.failure = Some(format!(
                    "WFP filters were verified absent, but recovery journal cleanup failed: {error}"
                ));
                break;
            }
            outcome.recovered_wfp_only_sessions += 1;
        }
        outcome
    }

    fn reconcile_startup_wfp_filters(
        store: &RecoveryJournalStore,
    ) -> StartupRecoveryOutcome {
        let mut engine: Option<crate::wfp_engine::WfpEngine> = None;
        reconcile_wfp_only_sessions(store, |records| {
            if engine.is_none() {
                engine = Some(crate::wfp_engine::WfpEngine::open_local()?);
            }
            engine
                .as_mut()
                .expect("WFP engine was opened for an actionable recovery journal")
                .remove_owned_filters(records)
                .map(|_| ())
        })
    }

    fn connection_coordinator_after_startup_recovery(
        unresolved_sessions: usize,
        recovery_failure: Option<&str>,
    ) -> Result<ConnectionCoordinator, String> {
        let coordinator = ConnectionCoordinator::new();
        let recovery_id = coordinator.begin_recovery()?;
        let cleanup_confirmed = unresolved_sessions == 0 && recovery_failure.is_none();
        let detail = if cleanup_confirmed {
            None
        } else {
            Some(format!(
                "Startup recovery is incomplete: {unresolved_sessions} unresolved session(s); {}",
                recovery_failure.unwrap_or("one or more network resources remain unverified")
            ))
        };
        coordinator.finish_recovery(recovery_id, cleanup_confirmed, detail)?;
        Ok(coordinator)
    }

    fn recovery_diagnostics_detail(
        unresolved_sessions: usize,
        recovered_wfp_only_sessions: usize,
        recovery_failure: Option<&str>,
    ) -> String {
        let journal_state = if unresolved_sessions == 0 {
            "no unresolved committed sessions remain".to_string()
        } else {
            format!("{unresolved_sessions} unresolved session(s) remain")
        };
        let recovery_state = if recovered_wfp_only_sessions == 0 {
            "no WFP-only session required recovery".to_string()
        } else {
            format!("recovered {recovered_wfp_only_sessions} WFP-only session(s)")
        };
        let failure_state = recovery_failure
            .map(|detail| format!(" WFP recovery is incomplete: {detail}."))
            .unwrap_or_default();
        format!(
            "The privileged Agent is running in status-only mode. Startup journal result: {recovery_state}; {journal_state}. Sessions containing engine, TUN, route, or DNS state are not auto-cleaned. Connect, Disconnect, and Recover remain disabled.{failure_state}"
        )
    }

    #[cfg(test)]
    mod recovery_startup_tests {
        use std::fs;
        use std::path::Path;

        use crate::recovery_journal::{
            DnsConfiguration, DnsMutationRecord, FirewallFilterRecord, RecoveryJournal,
            RecoveryJournalStore, RouteMutationRecord, RouteState,
        };

        use super::{
            connection_coordinator_after_startup_recovery, is_wfp_only_recovery_session,
            open_recovery_journal_store_at, reconcile_wfp_only_sessions,
            recovery_diagnostics_detail,
        };
        use crate::connection_state::ConnectionPhase;

        fn test_program_data() -> std::path::PathBuf {
            std::env::temp_dir().join(format!(
                "blacklist-agent-recovery-bootstrap-{}",
                uuid::Uuid::new_v4()
            ))
        }

        fn create_journal_directory(program_data: &Path) {
            fs::create_dir_all(program_data.join("blacklist-inevitable").join("Agent"))
                .expect("create test journal directory");
        }

        #[test]
        fn clean_startup_recovery_exposes_a_disconnected_healthy_agent_state() {
            let coordinator =
                connection_coordinator_after_startup_recovery(0, None).expect("initialize clean state");
            let snapshot = coordinator.snapshot();
            assert_eq!(snapshot.phase, ConnectionPhase::Disconnected);
            assert!(snapshot.cleanup_healthy);
            assert!(snapshot.session_id.is_none());
        }

        #[test]
        fn unresolved_startup_journal_exposes_failed_state_and_blocks_connect() {
            let coordinator = connection_coordinator_after_startup_recovery(1, None)
                .expect("initialize unresolved state");
            let snapshot = coordinator.snapshot();
            assert_eq!(snapshot.phase, ConnectionPhase::Failed);
            assert!(!snapshot.cleanup_healthy);
            assert!(snapshot.detail.as_deref().unwrap().contains("1 unresolved session"));
            assert!(
                coordinator.begin_connect("profile-1").is_err(),
                "unresolved startup state must never allow a new connection"
            );
        }

        #[test]
        fn startup_recovery_error_blocks_connect_even_without_loaded_journals() {
            let coordinator = connection_coordinator_after_startup_recovery(
                0,
                Some("WFP access denied"),
            )
            .expect("initialize failed recovery state");
            let snapshot = coordinator.snapshot();
            assert_eq!(snapshot.phase, ConnectionPhase::Failed);
            assert!(!snapshot.cleanup_healthy);
            assert!(
                coordinator.begin_connect("profile-1").is_err(),
                "a recovery error must block new sessions"
            );
        }

        #[test]
        fn startup_recovery_removes_only_wfp_only_sessions() {
            let program_data = test_program_data();
            create_journal_directory(&program_data);
            let journal_directory = program_data.join("blacklist-inevitable").join("Agent");
            let store = RecoveryJournalStore::open(&journal_directory).expect("open test store");

            let mut wfp_only = RecoveryJournal::new(74);
            wfp_only.firewall_filters.push(test_filter_record());
            store.persist(&wfp_only).expect("persist WFP-only journal");

            let mut mixed = RecoveryJournal::new(75);
            mixed.firewall_filters.push(test_filter_record_with_key(
                "f0a00000-0000-4000-8000-000000000075",
            ));
            mixed.routes.push(RouteMutationRecord {
                destination_prefix: "0.0.0.0/0".to_string(),
                applied: RouteState {
                    interface_index: 7,
                    next_hop: None,
                    metric: 10,
                },
                previous: Some(RouteState {
                    interface_index: 3,
                    next_hop: Some("192.0.2.1".parse().expect("valid test gateway")),
                    metric: 25,
                }),
            });
            store.persist(&mixed).expect("persist mixed-resource journal");

            let mut removed_keys = Vec::new();
            let outcome = reconcile_wfp_only_sessions(&store, |records| {
                removed_keys.extend(records.iter().filter_map(|record| record.filter_key.clone()));
                Ok(())
            });
            assert_eq!(outcome.recovered_wfp_only_sessions, 1);
            assert!(outcome.failure.is_none());
            assert_eq!(removed_keys, vec![
                "f0a00000-0000-4000-8000-000000000074".to_string()
            ]);
            let unresolved = store.load_unresolved().expect("reload unresolved");
            assert_eq!(unresolved.len(), 1);
            assert_eq!(unresolved[0].session_id, 75);

            fs::remove_dir_all(program_data).expect("remove test ProgramData directory");
        }

        #[test]
        fn startup_recovery_retains_journal_when_exact_filter_removal_fails() {
            let program_data = test_program_data();
            create_journal_directory(&program_data);
            let journal_directory = program_data.join("blacklist-inevitable").join("Agent");
            let store = RecoveryJournalStore::open(&journal_directory).expect("open test store");
            let mut journal = RecoveryJournal::new(76);
            journal.firewall_filters.push(test_filter_record());
            store.persist(&journal).expect("persist WFP-only journal");

            let outcome = reconcile_wfp_only_sessions(&store, |_records| {
                Err("simulated WFP access denied".to_string())
            });
            assert_eq!(outcome.recovered_wfp_only_sessions, 0);
            assert_eq!(
                outcome.failure.as_deref(),
                Some("simulated WFP access denied")
            );
            assert_eq!(store.load_unresolved().expect("reload journal").len(), 1);

            fs::remove_dir_all(program_data).expect("remove test ProgramData directory");
        }

        #[test]
        fn startup_recovery_does_not_treat_empty_or_dns_sessions_as_wfp_only() {
            let mut empty = RecoveryJournal::new(77);
            assert!(!is_wfp_only_recovery_session(&empty));
            empty.dns.push(DnsMutationRecord {
                interface_index: 7,
                applied: DnsConfiguration::Static(vec![
                    "203.0.113.53".parse().expect("valid test DNS"),
                ]),
                previous: DnsConfiguration::Dhcp,
            });
            empty.firewall_filters.push(test_filter_record());
            assert!(!is_wfp_only_recovery_session(&empty));
        }

        fn test_filter_record() -> FirewallFilterRecord {
            test_filter_record_with_key("f0a00000-0000-4000-8000-000000000074")
        }

        fn test_filter_record_with_key(key: &str) -> FirewallFilterRecord {
            FirewallFilterRecord {
                provider_key: "9d45d56a-6b31-48aa-9c45-72c8b25e2f10".to_string(),
                filter_key: Some(key.to_string()),
                layer_key: "b2f9b5a0-5e8a-4c6f-9d2b-77c0f4a25a01".to_string(),
                filter_id: None,
            }
        }

        #[test]
        fn startup_opens_an_existing_empty_program_data_journal() {
            let program_data = test_program_data();
            create_journal_directory(&program_data);

            let (_store, unresolved) =
                open_recovery_journal_store_at(&program_data).expect("open empty recovery journal");
            assert_eq!(unresolved, 0);

            fs::remove_dir_all(program_data).expect("remove test ProgramData directory");
        }

        #[test]
        fn startup_counts_unresolved_committed_sessions() {
            let program_data = test_program_data();
            create_journal_directory(&program_data);
            let journal_directory = program_data.join("blacklist-inevitable").join("Agent");
            let store = RecoveryJournalStore::open(&journal_directory).expect("open test store");
            store
                .persist(&RecoveryJournal::new(73))
                .expect("persist unresolved recovery journal");
            drop(store);

            let (_store, unresolved) =
                open_recovery_journal_store_at(&program_data).expect("load unresolved journal");
            assert_eq!(unresolved, 1);

            fs::remove_dir_all(program_data).expect("remove test ProgramData directory");
        }

        #[test]
        fn startup_rejects_corrupt_committed_journal_files() {
            let program_data = test_program_data();
            create_journal_directory(&program_data);
            let journal_directory = program_data.join("blacklist-inevitable").join("Agent");
            fs::write(
                journal_directory.join(
                    "session-0000000000000049-revision-0000000000000001.json",
                ),
                b"{",
            )
            .expect("write corrupt committed journal");

            assert!(open_recovery_journal_store_at(&program_data).is_err());

            fs::remove_dir_all(program_data).expect("remove test ProgramData directory");
        }

        #[test]
        fn startup_diagnostics_report_an_empty_journal_without_claiming_network_recovery() {
            let detail = recovery_diagnostics_detail(0, 0, None);
            assert!(detail.contains("no unresolved committed sessions remain"));
            assert!(detail.contains("no WFP-only session required recovery"));
            assert!(detail.contains("Connect, Disconnect, and Recover remain disabled"));
        }

        #[test]
        fn startup_diagnostics_surface_unresolved_session_count() {
            let detail = recovery_diagnostics_detail(3, 1, Some("access denied"));
            assert!(detail.contains("1 WFP-only session(s)"));
            assert!(detail.contains("3 unresolved session(s) remain"));
            assert!(detail.contains("WFP recovery is incomplete: access denied"));
            assert!(detail.contains("Connect, Disconnect, and Recover remain disabled"));
        }
    }

    unsafe extern "system" fn service_main(
        _argument_count: u32,
        _arguments: *mut windows_sys::core::PWSTR,
    ) {
        STOP_REQUESTED.store(false, Ordering::Release);

        let service_status_handle = unsafe {
            RegisterServiceCtrlHandlerExW(
                SERVICE_NAME.as_ptr(),
                Some(control_handler),
                std::ptr::null(),
            )
        };
        if service_status_handle.is_null() {
            return;
        }
        STATUS_HANDLE.store(service_status_handle as isize, Ordering::Release);

        let start_pending = status(SERVICE_START_PENDING, 0, 0, 0, 10_000);
        if !report_status(&start_pending) {
            STATUS_HANDLE.store(0, Ordering::Release);
            return;
        }

        let stop_event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if stop_event.is_null() {
            let error = unsafe { GetLastError() };
            report_status(&status(SERVICE_STOPPED, 0, error, 0, 0));
            STATUS_HANDLE.store(0, Ordering::Release);
            return;
        }

        {
            let _guard = EVENT_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            STOP_EVENT.store(stop_event as isize, Ordering::Release);
        }
        // The installer provisions this directory with a protected DACL for
        // SYSTEM, Administrators, and this restricted service SID. Open it before
        // accepting clients; a missing, corrupt, oversized, or unsafe journal
        // blocks service startup rather than being silently ignored.
        let (recovery_journal_store, _) = match open_recovery_journal_store() {
            Ok(state) => state,
            Err(error) => {
                eprintln!("Agent recovery journal validation failed; service startup is blocked: {error}");
                close_owned_handles(std::ptr::null_mut(), stop_event);
                report_status(&status(SERVICE_STOPPED, 0, ERROR_GEN_FAILURE, 2, 0));
                STATUS_HANDLE.store(0, Ordering::Release);
                return;
            }
        };

        // Only an isolated WFP-only journal is actionable here. If any session
        // also records an engine, tunnel, route, or DNS mutation, it remains
        // unresolved and no partial cleanup is attempted.
        let recovery = reconcile_startup_wfp_filters(&recovery_journal_store);
        let unresolved_sessions = match recovery_journal_store.load_unresolved() {
            Ok(journals) => journals.len(),
            Err(error) => {
                eprintln!("Agent recovery journal re-validation failed; service startup is blocked: {error}");
                close_owned_handles(std::ptr::null_mut(), stop_event);
                report_status(&status(SERVICE_STOPPED, 0, ERROR_GEN_FAILURE, 2, 0));
                STATUS_HANDLE.store(0, Ordering::Release);
                return;
            }
        };
        if let Some(error) = recovery.failure.as_deref() {
            eprintln!("Agent WFP-only startup recovery remains unresolved: {error}");
        }
        if unresolved_sessions > 0 {
            eprintln!(
                "Agent recovery journal contains {unresolved_sessions} unresolved session(s); network operations remain disabled."
            );
        }
        let startup_detail = recovery_diagnostics_detail(
            unresolved_sessions,
            recovery.recovered_wfp_only_sessions,
            recovery.failure.as_deref(),
        );
        let connection_coordinator = match connection_coordinator_after_startup_recovery(
            unresolved_sessions,
            recovery.failure.as_deref(),
        ) {
            Ok(coordinator) => coordinator,
            Err(error) => {
                eprintln!("Agent connection state initialization failed; service startup is blocked: {error}");
                close_owned_handles(std::ptr::null_mut(), stop_event);
                report_status(&status(SERVICE_STOPPED, 0, ERROR_GEN_FAILURE, 3, 0));
                STATUS_HANDLE.store(0, Ordering::Release);
                return;
            }
        };

        // The service is not reported as RUNNING until both its recovery journal
        // and its protected, local-only pipe endpoint have been validated.
        let pipe = match crate::agent_pipe::create_listener() {
            Ok(pipe) => pipe,
            Err(error) => {
                eprintln!("Agent named-pipe initialization failed: {error}");
                close_owned_handles(std::ptr::null_mut(), stop_event);
                report_status(&status(SERVICE_STOPPED, 0, ERROR_GEN_FAILURE, 1, 0));
                STATUS_HANDLE.store(0, Ordering::Release);
                return;
            }
        };

        let mut exit_code = 0u32;
        if STOP_REQUESTED.load(Ordering::Acquire) {
            exit_code = 0;
        } else {
            let running = status(
                SERVICE_RUNNING,
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
                0,
                0,
                0,
            );
            if !report_status(&running) {
                signal_stop();
                exit_code = ERROR_GEN_FAILURE;
            } else if !STOP_REQUESTED.load(Ordering::Acquire) {
                if let Err(error) = crate::agent_pipe::serve(
                    pipe,
                    stop_event,
                    &startup_detail,
                    &connection_coordinator,
                ) {
                    if error.starts_with(crate::agent_pipe::FATAL_REVERT_ERROR_PREFIX) {
                        // The service thread may still carry a client impersonation
                        // token. Do not run any further cleanup/status code under it.
                        std::process::exit(ERROR_GEN_FAILURE as i32);
                    }
                    if !STOP_REQUESTED.load(Ordering::Acquire) {
                        eprintln!("Agent named-pipe listener stopped unexpectedly: {error}");
                        exit_code = ERROR_GEN_FAILURE;
                    }
                }
            }
        }

        report_status(&status(SERVICE_STOP_PENDING, 0, 0, 0, 10_000));
        close_owned_handles(pipe, stop_event);
        report_status(&status(SERVICE_STOPPED, 0, exit_code, 0, 0));
        STATUS_HANDLE.store(0, Ordering::Release);
    }

    fn wfp_acl_probe_service_sid_path() -> Result<PathBuf, String> {
        let program_data = std::env::var_os("ProgramData")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "ProgramData is unavailable to the WFP ACL probe service.".to_string())?;
        Ok(PathBuf::from(program_data)
            .join("blacklist-inevitable")
            .join("Agent")
            .join("wfp-acl-probe-service-sid.txt"))
    }

    #[derive(Default)]
    struct WfpAclProbeOutcome {
        access_granted: bool,
        detail: String,
        installed_filter_count: usize,
        removed_filter_count: usize,
        already_absent_filter_count: usize,
        runtime_ids_checkpointed: bool,
        journal_removed: bool,
        synthetic_filters_may_remain: bool,
    }

    fn run_wfp_acl_probe_once() -> WfpAclProbeOutcome {
        let service_sid = match wfp_acl_probe_service_sid_path()
            .and_then(|path| std::fs::read_to_string(path)
                .map_err(|error| format!("Could not read the restricted Agent service SID supplied by the disposable test harness: {error}")))
        {
            Ok(value) => value.trim().to_string(),
            Err(error) => return WfpAclProbeOutcome { detail: error, ..Default::default() },
        };
        let program_data = match std::env::var_os("ProgramData").filter(|value| !value.is_empty()) {
            Some(value) => PathBuf::from(value),
            None => return WfpAclProbeOutcome {
                detail: "ProgramData is unavailable to the WFP recovery acceptance probe.".into(),
                ..Default::default()
            },
        };
        let (journal_store, unresolved) = match open_recovery_journal_store_at(&program_data) {
            Ok(value) => value,
            Err(error) => return WfpAclProbeOutcome { detail: error, ..Default::default() },
        };
        if unresolved != 0 {
            return WfpAclProbeOutcome {
                detail: format!("The disposable WFP probe runner unexpectedly contains {unresolved} unresolved recovery session(s); refusing to share its journal namespace."),
                ..Default::default()
            };
        }

        let mut engine = match crate::wfp_engine::WfpEngine::open_local() {
            Ok(engine) => engine,
            Err(error) => return WfpAclProbeOutcome {
                detail: format!("FwpmEngineOpen0: {error}"),
                ..Default::default()
            },
        };

        // Test-only persistent filters use TEST-NET destinations and an
        // intentionally non-existent synthetic LUID/index. They are committed
        // only on the disposable CI runner, then exact-key removed in a
        // separate transaction using the reloaded recovery journal.
        let spec = crate::wfp_policy::EgressPolicySpec {
            physical_interfaces: vec![crate::wfp_policy::PhysicalInterface {
                interface_luid: u64::MAX,
                interface_index: u32::MAX,
            }],
            vpn_endpoints: vec![
                crate::wfp_policy::VpnEndpoint {
                    address: "198.51.100.7".parse().expect("valid TEST-NET-2 IPv4 address"),
                    port: 443,
                    protocol: crate::wfp_policy::TransportProtocol::Tcp,
                },
                crate::wfp_policy::VpnEndpoint {
                    address: "2001:db8::7".parse().expect("valid documentation IPv6 address"),
                    port: 443,
                    protocol: crate::wfp_policy::TransportProtocol::Tcp,
                },
            ],
        };
        let session_id = (uuid::Uuid::new_v4().as_u128() as u64).max(1);
        match engine.exercise_journaled_filter_recovery_for_service_sid(
            &spec,
            &service_sid,
            &journal_store,
            session_id,
        ) {
            Ok(report) => WfpAclProbeOutcome {
                access_granted: true,
                detail: format!(
                    "The restricted Agent SID persisted stable-key intent, committed {}, reloaded the journal, removed {}, confirmed {} already absent on an idempotent second pass, and removed the journal. Runtime-ID checkpoint: {}.",
                    report.installed_filter_count,
                    report.removed_filter_count,
                    report.already_absent_filter_count,
                    report.runtime_ids_checkpointed
                ),
                installed_filter_count: report.installed_filter_count,
                removed_filter_count: report.removed_filter_count,
                already_absent_filter_count: report.already_absent_filter_count,
                runtime_ids_checkpointed: report.runtime_ids_checkpointed,
                journal_removed: report.journal_removed,
                synthetic_filters_may_remain: false,
            },
            Err(error) => WfpAclProbeOutcome {
                detail: error,
                // A failure after the commit point may leave test filters in
                // the ephemeral hosted runner. Keep the journal; never claim
                // cleanup unless exact-key absence was independently proven.
                synthetic_filters_may_remain: true,
                ..Default::default()
            },
        }
    }

    fn wfp_acl_probe_report_path() -> Result<PathBuf, String> {
        let program_data = std::env::var_os("ProgramData")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "ProgramData is unavailable to the WFP ACL probe service.".to_string())?;
        Ok(PathBuf::from(program_data)
            .join("blacklist-inevitable")
            .join("Agent")
            .join("wfp-acl-probe.json"))
    }

    unsafe extern "system" fn wfp_acl_probe_service_main(
        _argument_count: u32,
        _arguments: *mut windows_sys::core::PWSTR,
    ) {
        let service_status_handle = unsafe {
            RegisterServiceCtrlHandlerExW(
                SERVICE_NAME.as_ptr(),
                Some(control_handler),
                std::ptr::null(),
            )
        };
        if service_status_handle.is_null() {
            return;
        }
        STATUS_HANDLE.store(service_status_handle as isize, Ordering::Release);

        if !report_status(&status(SERVICE_START_PENDING, 0, 0, 0, 10_000))
            || !report_status(&status(SERVICE_RUNNING, 0, 0, 0, 0))
        {
            STATUS_HANDLE.store(0, Ordering::Release);
            return;
        }

        let outcome = run_wfp_acl_probe_once();
        let report = serde_json::json!({
            "schema_version": 2,
            "service_name": "BlacklistInevitableAgent",
            "service_account": "LocalSystem",
            "service_sid_type": "RESTRICTED",
            "outcome": if outcome.access_granted { "access_granted" } else { "access_blocked" },
            "detail": outcome.detail,
            "installed_filter_count": outcome.installed_filter_count,
            "removed_filter_count": outcome.removed_filter_count,
            "already_absent_filter_count": outcome.already_absent_filter_count,
            "runtime_ids_checkpointed": outcome.runtime_ids_checkpointed,
            "journal_removed": outcome.journal_removed,
            "synthetic_filters_committed_during_test": outcome.installed_filter_count > 0,
            "synthetic_filters_may_remain": outcome.synthetic_filters_may_remain
        });

        let write_result = wfp_acl_probe_report_path().and_then(|path| {
            let parent = path
                .parent()
                .ok_or_else(|| "The WFP ACL probe report path has no parent directory.".to_string())?;
            if !parent.is_dir() {
                return Err("The WFP ACL probe report directory was not provisioned.".to_string());
            }
            let bytes = serde_json::to_vec_pretty(&report)
                .map_err(|error| format!("Could not serialize WFP ACL probe report: {error}"))?;
            std::fs::write(path, bytes)
                .map_err(|error| format!("Could not write WFP ACL probe report: {error}"))
        });

        let (win32_exit, service_exit) = match write_result {
            Ok(()) => (0, 0),
            Err(error) => {
                eprintln!("{error}");
                (ERROR_GEN_FAILURE, 3)
            }
        };
        report_status(&status(SERVICE_STOP_PENDING, 0, 0, 0, 1_000));
        report_status(&status(SERVICE_STOPPED, 0, win32_exit, service_exit, 0));
        STATUS_HANDLE.store(0, Ordering::Release);
    }

    pub fn run_wfp_acl_probe() -> Result<(), String> {
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: SERVICE_NAME.as_ptr() as *mut u16,
                lpServiceProc: Some(wfp_acl_probe_service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: std::ptr::null_mut(),
                lpServiceProc: None,
            },
        ];

        let started = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
        if started == 0 {
            let error = unsafe { GetLastError() };
            return Err(format!(
                "The WFP ACL probe could not connect to the Windows Service Control Manager (error {error})."
            ));
        }
        Ok(())
    }

    pub fn run() -> Result<(), String> {
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: SERVICE_NAME.as_ptr() as *mut u16,
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: std::ptr::null_mut(),
                lpServiceProc: None,
            },
        ];

        let started = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
        if started == 0 {
            let error = unsafe { GetLastError() };
            return Err(format!(
                "The Agent could not connect to the Windows Service Control Manager (error {error}). Run it through the installed service entry, not as a desktop process."
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn service_has_a_stable_non_empty_name() {
            assert_eq!(SERVICE_NAME.last(), Some(&0));
            assert_eq!(
                &SERVICE_NAME[..SERVICE_NAME.len() - 1],
                &[
                    66, 108, 97, 99, 107, 108, 105, 115, 116, 73, 110, 101, 118, 105, 116, 97, 98,
                    108, 101, 65, 103, 101, 110, 116,
                ]
            );
        }

        #[test]
        fn stop_state_starts_disabled_until_server_is_ready() {
            let starting = status(SERVICE_START_PENDING, 0, 0, 0, 10_000);
            assert_eq!(starting.dwControlsAccepted, 0);
            let running = status(SERVICE_RUNNING, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN, 0, 0, 0);
            assert_eq!(running.dwControlsAccepted, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
        }
    }
}

#[cfg(windows)]
pub fn run_wfp_acl_probe_service() -> Result<(), String> {
    windows_service::run_wfp_acl_probe()
}

#[cfg(not(windows))]
pub fn run_wfp_acl_probe_service() -> Result<(), String> {
    Err("The WFP ACL probe is supported only on Windows.".to_string())
}

#[cfg(windows)]
pub fn run_service() -> Result<(), String> {
    windows_service::run()
}

#[cfg(not(windows))]
pub fn run_service() -> Result<(), String> {
    Err("The privileged Agent host is supported only on Windows.".to_string())
}
