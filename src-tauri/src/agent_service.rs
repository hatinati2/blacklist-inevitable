//! Dedicated Windows Service Control Manager host for the privileged Agent.
//!
//! The service owns the local authenticated status-only named pipe. VPN engine,
//! WFP, TUN, route and DNS operations remain disabled until the recovery runtime
//! and packet-capture release gates are implemented.

use std::path::PathBuf;
use std::sync::OnceLock;

use crate::recovery_journal::{RecoveryJournal, RecoveryJournalStore};

static STARTUP_RECOVERY_STATUS: OnceLock<Result<(), String>> = OnceLock::new();

fn validate_startup_journals(journals: &[RecoveryJournal]) -> Result<(), String> {
    if journals.is_empty() {
        return Ok(());
    }

    let phases = journals
        .iter()
        .map(|journal| format!("{:?}", journal.phase))
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "{} unresolved recovery journal(s) were found (phases: {}). The Agent is fail-closed until every previous session is reconciled against actual Windows process, tunnel, route, DNS, and WFP state.",
        journals.len(),
        phases
    ))
}

fn inspect_startup_recovery_journal() -> Result<(), String> {
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let journal_root = program_data
        .join("BlacklistInevitable")
        .join("Agent");
    let store = RecoveryJournalStore::open(journal_root)?;
    let unresolved = store.load_unresolved()?;
    validate_startup_journals(&unresolved)
}

/// Called exactly once for each Agent service process before its pipe listener
/// is marked RUNNING. The service still exposes read-only status when blocked,
/// but never treats unresolved/corrupt recovery state as a clean startup.
pub(crate) fn initialize_startup_recovery() -> Result<(), String> {
    STARTUP_RECOVERY_STATUS
        .get_or_init(inspect_startup_recovery_journal)
        .clone()
}

/// The status endpoint can report clean only after the service startup gate has
/// loaded and validated the protected journal directory in this process.
pub(crate) fn startup_recovery_status() -> Result<(), String> {
    STARTUP_RECOVERY_STATUS
        .get()
        .cloned()
        .unwrap_or_else(|| Err("Agent startup recovery validation has not completed.".to_string()))
}

#[cfg(test)]
mod startup_recovery_tests {
    use super::*;
    use crate::recovery_journal::{JournalPhase, RecoveryJournal};

    #[test]
    fn empty_journal_set_allows_clean_startup() {
        assert!(validate_startup_journals(&[]).is_ok());
    }

    #[test]
    fn any_unresolved_session_blocks_clean_startup() {
        let mut journal = RecoveryJournal::new(41);
        journal.phase = JournalPhase::RecoveryRequired;
        let error = validate_startup_journals(&[journal]).unwrap_err();
        assert!(error.contains("1 unresolved recovery journal"));
        assert!(error.contains("RecoveryRequired"));
        assert!(error.contains("fail-closed"));
    }

    #[test]
    fn multiple_unresolved_sessions_are_all_reported_as_blocking() {
        let journals = [RecoveryJournal::new(41), RecoveryJournal::new(42)];
        let error = validate_startup_journals(&journals).unwrap_err();
        assert!(error.contains("2 unresolved recovery journal"));
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
        if let Err(error) = crate::agent_service::initialize_startup_recovery() {
            eprintln!("Agent startup recovery is blocked: {error}");
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
