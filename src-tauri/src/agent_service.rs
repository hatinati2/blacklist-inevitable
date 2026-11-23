//! Dedicated Windows Service Control Manager host for the privileged Agent.
//!
//! Startup recovery performs read-only observations only. It never stops a
//! process, mutates routes/DNS/WFP, restores configuration, or removes journals.
//! VPN connection operations remain separately disabled.

#[cfg(windows)]
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use crate::agent_protocol::{
    AgentRecoveryDispositionCounts, AgentRecoverySessionStatus, AgentRecoveryState,
    AgentRecoveryStatus,
};
use crate::recovery_assessment::{Observation, ResourceDisposition};
use crate::recovery_journal::{RecoveryJournal, RecoveryJournalStore};

static STARTUP_RECOVERY_STATUS: OnceLock<AgentRecoveryStatus> = OnceLock::new();

fn empty_blocked_status(diagnostic: String) -> AgentRecoveryStatus {
    AgentRecoveryStatus {
        state: AgentRecoveryState::Blocked,
        journal_inventory_complete: false,
        total_sessions: 0,
        verified_clean_sessions: 0,
        blocked_sessions: 1,
        omitted_sessions: 0,
        journal_retained: true,
        sessions: Vec::new(),
        diagnostics: vec![diagnostic.chars().take(120).collect()],
    }
}

fn inspect_startup_recovery_journal() -> AgentRecoveryStatus {
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let journal_root = program_data
        .join("BlacklistInevitable")
        .join("Agent");
    let store = match RecoveryJournalStore::open(journal_root) {
        Ok(store) => store,
        Err(error) => {
            return empty_blocked_status(format!("Recovery journal store unavailable: {error}"));
        }
    };
    let unresolved = match store.load_unresolved() {
        Ok(journals) => journals,
        Err(error) => {
            return empty_blocked_status(format!("Recovery journal inventory is unsafe or unreadable: {error}"));
        }
    };
    assess_startup_journals(&unresolved)
}

#[cfg(windows)]
fn add_bounded_diagnostic(diagnostics: &mut Vec<String>, message: impl Into<String>) {
    const MAX_DIAGNOSTICS: usize = 2;
    if diagnostics.len() >= MAX_DIAGNOSTICS {
        return;
    }
    let safe: String = message
        .into()
        .chars()
        .filter(|character| !character.is_control())
        .take(120)
        .collect();
    diagnostics.push(safe);
}

#[cfg(windows)]
fn disposition_counts(
    dispositions: impl IntoIterator<Item = ResourceDisposition>,
) -> AgentRecoveryDispositionCounts {
    let mut counts = AgentRecoveryDispositionCounts::default();
    for disposition in dispositions {
        match disposition {
            ResourceDisposition::VerifiedClean => counts.verified_clean = counts.verified_clean.saturating_add(1),
            ResourceDisposition::NeedsCleanup => counts.needs_cleanup = counts.needs_cleanup.saturating_add(1),
            ResourceDisposition::NeedsRestore => counts.needs_restore = counts.needs_restore.saturating_add(1),
            ResourceDisposition::Conflict => counts.conflict = counts.conflict.saturating_add(1),
            ResourceDisposition::Unknown => counts.unknown = counts.unknown.saturating_add(1),
        }
    }
    counts
}

#[cfg(windows)]
fn assess_startup_journals(journals: &[RecoveryJournal]) -> AgentRecoveryStatus {
    use crate::recovery_assessment::{assess_recovery, RecoverySnapshot};
    use crate::recovery_observer::{
        observe_agent_wfp_filters, observe_recorded_dns, observe_recorded_engine_process,
        observe_recorded_routes, observe_recorded_tunnel_interface,
    };

    if journals.is_empty() {
        return AgentRecoveryStatus {
            state: AgentRecoveryState::Clear,
            journal_inventory_complete: true,
            total_sessions: 0,
            verified_clean_sessions: 0,
            blocked_sessions: 0,
            omitted_sessions: 0,
            journal_retained: false,
            sessions: Vec::new(),
            diagnostics: Vec::new(),
        };
    }

    // WFP inventory is scoped to the product's stable provider/sublayer and is
    // read inside a read-only transaction. Failure remains Unknown for every
    // session; an absent/unverifiable provider is not treated as an empty set.
    let (mut wfp_engine, wfp_open_error) = match crate::wfp_engine::WfpEngine::open_local() {
        Ok(engine) => (Some(engine), None),
        Err(error) => (None, Some(error)),
    };
    let mut diagnostics = Vec::new();
    if let Some(error) = wfp_open_error {
        add_bounded_diagnostic(&mut diagnostics, format!("WFP inventory unavailable: {error}"));
    }

    let mut verified_clean_sessions = 0u32;
    let mut blocked_sessions = 0u32;
    let mut session_summaries = Vec::new();

    for journal in journals {
        let engine = match journal.engine.as_ref() {
            Some(expected) => match observe_recorded_engine_process(expected) {
                Ok(observed) => observed,
                Err(error) => {
                    add_bounded_diagnostic(&mut diagnostics, format!("Engine observer: {error}"));
                    Observation::Unknown
                }
            },
            None => Observation::Absent,
        };

        let tunnel = match journal.tunnel.as_ref() {
            Some(expected) => match observe_recorded_tunnel_interface(expected) {
                Ok(observed) => observed,
                Err(error) => {
                    add_bounded_diagnostic(&mut diagnostics, format!("Tunnel observer: {error}"));
                    Observation::Unknown
                }
            },
            None => Observation::Absent,
        };

        let mut routes = match observe_recorded_routes(journal) {
            Ok(observed) => observed,
            Err(error) => {
                add_bounded_diagnostic(&mut diagnostics, format!("Route observer: {error}"));
                journal.routes.iter().map(|record| {
                    (record.destination_prefix.clone(), Observation::Unknown)
                }).collect::<BTreeMap<_, _>>()
            }
        };
        // An omitted key is never equivalent to Absent, even if an observer
        // implementation changes later to return a partial map.
        for record in &journal.routes {
            routes.entry(record.destination_prefix.clone())
                .or_insert(Observation::Unknown);
        }

        let mut dns = BTreeMap::new();
        for record in &journal.dns {
            let observed = match observe_recorded_dns(record) {
                Ok(observed) => observed,
                Err(error) => {
                    add_bounded_diagnostic(&mut diagnostics, format!("DNS observer: {error}"));
                    Observation::Unknown
                }
            };
            dns.insert(record.interface_index, observed);
        }

        let firewall_filters = match wfp_engine.as_mut() {
            Some(engine) => match observe_agent_wfp_filters(engine) {
                Ok(observed) => observed,
                Err(error) => {
                    add_bounded_diagnostic(&mut diagnostics, format!("WFP observer: {error}"));
                    Observation::Unknown
                }
            },
            None => Observation::Unknown,
        };

        let snapshot = RecoverySnapshot {
            engine,
            tunnel,
            routes,
            dns,
            firewall_filters,
        };
        let assessment = assess_recovery(journal, &snapshot);
        let verified_clean = assessment.can_remove_journal;

        if verified_clean {
            verified_clean_sessions = verified_clean_sessions.saturating_add(1);
        } else {
            blocked_sessions = blocked_sessions.saturating_add(1);
        }

        // The full assessment is computed for every session. Only the first two
        // compact summaries cross IPC; aggregate counts cover every journal.
        if session_summaries.len() < 2 {
            session_summaries.push(AgentRecoverySessionStatus {
                session_id: journal.session_id,
                revision: journal.revision,
                phase: format!("{:?}", journal.phase),
                engine: assessment.engine,
                tunnel: assessment.tunnel,
                routes: disposition_counts(assessment.routes.iter().map(|item| item.disposition)),
                dns: disposition_counts(assessment.dns.iter().map(|item| item.disposition)),
                firewall_filters: assessment.firewall_filters,
                verified_clean,
            });
        }
    }

    let total_sessions = u32::try_from(journals.len()).unwrap_or(u32::MAX);
    let omitted_sessions = total_sessions.saturating_sub(session_summaries.len() as u32);
    let state = if blocked_sessions > 0 {
        AgentRecoveryState::Blocked
    } else {
        AgentRecoveryState::VerifiedCleanRetained
    };

    AgentRecoveryStatus {
        state,
        journal_inventory_complete: true,
        total_sessions,
        verified_clean_sessions,
        blocked_sessions,
        omitted_sessions,
        journal_retained: true,
        sessions: session_summaries,
        diagnostics,
    }
}

#[cfg(not(windows))]
fn assess_startup_journals(journals: &[RecoveryJournal]) -> AgentRecoveryStatus {
    if journals.is_empty() {
        return AgentRecoveryStatus {
            state: AgentRecoveryState::Clear,
            journal_inventory_complete: true,
            total_sessions: 0,
            verified_clean_sessions: 0,
            blocked_sessions: 0,
            omitted_sessions: 0,
            journal_retained: false,
            sessions: Vec::new(),
            diagnostics: Vec::new(),
        };
    }

    let unknown_routes = |journal: &RecoveryJournal| AgentRecoveryDispositionCounts {
        unknown: journal.routes.len() as u32,
        ..AgentRecoveryDispositionCounts::default()
    };
    let unknown_dns = |journal: &RecoveryJournal| AgentRecoveryDispositionCounts {
        unknown: journal.dns.len() as u32,
        ..AgentRecoveryDispositionCounts::default()
    };
    let sessions = journals.iter().take(2).map(|journal| AgentRecoverySessionStatus {
        session_id: journal.session_id,
        revision: journal.revision,
        phase: format!("{:?}", journal.phase),
        engine: ResourceDisposition::Unknown,
        tunnel: ResourceDisposition::Unknown,
        routes: unknown_routes(journal),
        dns: unknown_dns(journal),
        firewall_filters: ResourceDisposition::Unknown,
        verified_clean: false,
    }).collect::<Vec<_>>();

    AgentRecoveryStatus {
        state: AgentRecoveryState::Blocked,
        journal_inventory_complete: true,
        total_sessions: u32::try_from(journals.len()).unwrap_or(u32::MAX),
        verified_clean_sessions: 0,
        blocked_sessions: u32::try_from(journals.len()).unwrap_or(u32::MAX),
        omitted_sessions: u32::try_from(journals.len().saturating_sub(sessions.len())).unwrap_or(u32::MAX),
        journal_retained: true,
        sessions,
        diagnostics: vec!["Live Windows recovery observers are unavailable on this platform.".to_string()],
    }
}

/// Called exactly once per Agent service process, before the pipe listener is
/// marked RUNNING. This method performs observation only and never mutates OS
/// resources or removes a journal.
pub(crate) fn initialize_startup_recovery() -> AgentRecoveryStatus {
    STARTUP_RECOVERY_STATUS
        .get_or_init(inspect_startup_recovery_journal)
        .clone()
}

/// The status endpoint receives a compact structured copy of the read-only
/// assessment. Even a verified-clean session keeps its journal for a separate,
/// explicitly reviewed cleanup protocol.
pub(crate) fn startup_recovery_status() -> AgentRecoveryStatus {
    STARTUP_RECOVERY_STATUS
        .get()
        .cloned()
        .unwrap_or_else(|| empty_blocked_status(
            "Agent startup recovery assessment has not completed.".to_string()
        ))
}

#[cfg(test)]
mod startup_recovery_tests {
    use super::*;
    use crate::recovery_journal::JournalPhase;

    #[test]
    fn empty_journal_set_reports_clear_inventory() {
        let status = assess_startup_journals(&[]);
        assert!(matches!(status.state, AgentRecoveryState::Clear));
        assert_eq!(status.total_sessions, 0);
        assert!(!status.journal_retained);
        assert!(status.journal_inventory_complete);
    }

    #[test]
    fn unresolved_journals_are_never_assumed_clean_without_live_observers() {
        let mut journal = RecoveryJournal::new(41);
        journal.phase = JournalPhase::RecoveryRequired;
        let status = assess_startup_journals(&[journal]);
        assert!(status.is_blocked());
        assert_eq!(status.total_sessions, 1);
        assert_eq!(status.blocked_sessions, 1);
        assert!(status.journal_retained);
    }

    #[test]
    fn diagnostic_output_is_bounded_and_does_not_change_status() {
        let status = empty_blocked_status("x".repeat(512));
        assert!(status.is_blocked());
        assert!(status.diagnostics[0].len() <= 120);
        assert!(status.detail_summary().len() <= 1100);
    }
}

#[cfg(windows)]
mod windows_service {
    use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
    use std::sync::Mutex;

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

        // Load every committed checkpoint before exposing the pipe as RUNNING.
        // A missing, unsafe, corrupt, or unresolved journal leaves the service
        // available for read-only diagnostics but its status endpoint is rejected.
        let recovery = crate::agent_service::initialize_startup_recovery();
        if recovery.is_blocked() {
            eprintln!("Agent startup recovery is blocked: {}", recovery.detail_summary());
        }

        // The service is not reported as RUNNING until its protected, local-only
        // pipe endpoint exists. A missing/invalid ACL therefore fails startup.
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
                if let Err(error) = crate::agent_pipe::serve(pipe, stop_event) {
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
pub fn run_service() -> Result<(), String> {
    windows_service::run()
}

#[cfg(not(windows))]
pub fn run_service() -> Result<(), String> {
    Err("The privileged Agent host is supported only on Windows.".to_string())
}
