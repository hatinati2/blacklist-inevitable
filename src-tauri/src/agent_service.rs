//! Dedicated Windows Service Control Manager host for the privileged Agent.
//!
//! The service owns the local authenticated status-only named pipe. VPN engine,
//! WFP, TUN, route and DNS operations remain disabled until the recovery runtime
//! and packet-capture release gates are implemented.

#[cfg(windows)]
mod windows_service {
    use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

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

    fn recovery_diagnostics_detail(unresolved_sessions: usize) -> String {
        let journal_state = if unresolved_sessions == 0 {
            "no unresolved committed sessions were found".to_string()
        } else {
            format!("{unresolved_sessions} unresolved session(s) require recovery")
        };
        format!(
            "The privileged Agent is running in status-only mode. Recovery journal validation completed: {journal_state}. No automatic network recovery is performed, and VPN connection operations remain disabled."
        )
    }

    #[cfg(test)]
    mod recovery_startup_tests {
        use std::fs;
        use std::path::Path;

        use crate::recovery_journal::{RecoveryJournal, RecoveryJournalStore};

        use super::{open_recovery_journal_store_at, recovery_diagnostics_detail};

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
            let detail = recovery_diagnostics_detail(0);
            assert!(detail.contains("no unresolved committed sessions were found"));
            assert!(detail.contains("No automatic network recovery is performed"));
            assert!(detail.contains("VPN connection operations remain disabled"));
        }

        #[test]
        fn startup_diagnostics_surface_unresolved_session_count() {
            let detail = recovery_diagnostics_detail(3);
            assert!(detail.contains("3 unresolved session(s) require recovery"));
            assert!(detail.contains("VPN connection operations remain disabled"));
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
        let (_recovery_journal_store, unresolved_sessions) = match open_recovery_journal_store() {
            Ok(state) => state,
            Err(error) => {
                eprintln!("Agent recovery journal validation failed; service startup is blocked: {error}");
                close_owned_handles(std::ptr::null_mut(), stop_event);
                report_status(&status(SERVICE_STOPPED, 0, ERROR_GEN_FAILURE, 2, 0));
                STATUS_HANDLE.store(0, Ordering::Release);
                return;
            }
        };
        if unresolved_sessions > 0 {
            eprintln!(
                "Agent recovery journal contains {unresolved_sessions} unresolved session(s); network operations remain disabled."
            );
        }
        let startup_detail = recovery_diagnostics_detail(unresolved_sessions);

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
                if let Err(error) = crate::agent_pipe::serve(pipe, stop_event, &startup_detail) {
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

    fn run_wfp_acl_probe_once() -> (bool, String, usize, usize) {
        let service_sid = match wfp_acl_probe_service_sid_path()
            .and_then(|path| std::fs::read_to_string(path)
                .map_err(|error| format!("Could not read the restricted service SID supplied by the disposable test harness: {error}")))
        {
            Ok(value) => value.trim().to_string(),
            Err(error) => return (false, error, 0, 0),
        };
        let mut engine = match crate::wfp_engine::WfpEngine::open_local() {
            Ok(engine) => engine,
            Err(error) => return (false, format!("FwpmEngineOpen0: {error}"), 0, 0),
        };

        // TEST-NET endpoints and a synthetic interface identity are used only
        // to exercise BFE object access. The enclosing WFP transaction is
        // aborted; no traffic filter is committed.
        let spec = crate::wfp_policy::EgressPolicySpec {
            physical_interfaces: vec![crate::wfp_policy::PhysicalInterface {
                interface_luid: 1,
                interface_index: 1,
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

        match engine.validate_egress_policy_transaction_for_service_sid(&spec, &service_sid) {
            Ok(report) => (
                true,
                format!(
                    "The restricted Agent service token completed BFE add/read-back/exact-delete/abort for {} filters; {} were confirmed rolled back.",
                    report.validated_filter_count, report.rolled_back_filter_count
                ),
                report.validated_filter_count,
                report.rolled_back_filter_count,
            ),
            Err(error) => (false, error, 0, 0),
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

        let (access_granted, detail, validated_filter_count, rolled_back_filter_count) =
            run_wfp_acl_probe_once();
        let report = serde_json::json!({
            "schema_version": 1,
            "service_name": "BlacklistInevitableAgent",
            "service_account": "LocalSystem",
            "service_sid_type": "RESTRICTED",
            "outcome": if access_granted { "access_granted" } else { "access_blocked" },
            "detail": detail,
            "validated_filter_count": if access_granted { Some(validated_filter_count) } else { None },
            "rolled_back_filter_count": if access_granted { Some(rolled_back_filter_count) } else { None },
            "traffic_filters_committed": false
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
