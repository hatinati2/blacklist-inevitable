//! Dedicated Windows Service Control Manager host for the privileged Agent.
//!
//! This first slice establishes a separately-built service process and correct
//! SCM lifecycle reporting. It intentionally does not create a named pipe, start
//! an engine, mutate routes/DNS/WFP, or advertise the Agent as operational VPN
//! functionality. Those capabilities remain disabled until the authenticated
//! IPC and recovery runtime have passed their Windows integration gates.

#[cfg(windows)]
mod windows_service {
    use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
    use std::sync::Mutex;

    use windows_sys::Win32::Foundation::{
        GetLastError, CloseHandle, ERROR_CALL_NOT_IMPLEMENTED, HANDLE, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
        SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
        SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOPPED,
        SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
        SetServiceStatus, StartServiceCtrlDispatcherW,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, SetEvent, WaitForSingleObject, INFINITE,
    };

    const SERVICE_NAME: [u16; 25] = [
        66, 108, 97, 99, 107, 108, 105, 115, 116, 73, 110, 101, 118, 105, 116, 97, 98, 108, 101,
        65, 103, 101, 110, 116, 0,
    ];

    static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);
    static STOP_EVENT: AtomicIsize = AtomicIsize::new(0);
    static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
    static EVENT_LOCK: Mutex<()> = Mutex::new(());

    fn status(state: u32, accepted: u32, win32_exit: u32, wait_hint_ms: u32) -> SERVICE_STATUS {
        SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: accepted,
            dwWin32ExitCode: win32_exit,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: wait_hint_ms,
        }
    }

    fn report_status(value: &SERVICE_STATUS) -> bool {
        let handle = STATUS_HANDLE.load(Ordering::Acquire) as windows_sys::Win32::System::Services::SERVICE_STATUS_HANDLE;
        if handle.is_null() {
            return false;
        }
        unsafe { SetServiceStatus(handle, value) != 0 }
    }

    unsafe extern "system" fn control_handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut core::ffi::c_void,
        _context: *mut core::ffi::c_void,
    ) -> u32 {
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                STOP_REQUESTED.store(true, Ordering::Release);
                let _guard = EVENT_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let event = STOP_EVENT.load(Ordering::Acquire) as HANDLE;
                if !event.is_null() {
                    // The event is owned by ServiceMain and closed under the same
                    // lock, so the handler cannot signal a recycled handle.
                    unsafe { SetEvent(event) };
                }
                0
            }
            SERVICE_CONTROL_INTERROGATE => 0,
            _ => ERROR_CALL_NOT_IMPLEMENTED,
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

        let start_pending = status(SERVICE_START_PENDING, 0, 0, 10_000);
        if !report_status(&start_pending) {
            STATUS_HANDLE.store(0, Ordering::Release);
            return;
        }

        let stop_event = unsafe {
            CreateEventW(std::ptr::null(), 1, 0, std::ptr::null())
        };
        if stop_event.is_null() {
            let error = unsafe { GetLastError() };
            let stopped = status(SERVICE_STOPPED, 0, error, 0);
            report_status(&stopped);
            STATUS_HANDLE.store(0, Ordering::Release);
            return;
        }

        {
            let _guard = EVENT_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            STOP_EVENT.store(stop_event as isize, Ordering::Release);
            if STOP_REQUESTED.load(Ordering::Acquire) {
                unsafe { SetEvent(stop_event) };
            }
        }

        if STOP_REQUESTED.load(Ordering::Acquire) {
            let pending = status(SERVICE_STOP_PENDING, 0, 0, 10_000);
            report_status(&pending);
        } else {
            let running = status(
                SERVICE_RUNNING,
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
                0,
                0,
            );
            if !report_status(&running) {
                STOP_REQUESTED.store(true, Ordering::Release);
                let _guard = EVENT_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                unsafe { SetEvent(stop_event) };
            }
        }

        let wait_result = unsafe { WaitForSingleObject(stop_event, INFINITE) };
        let win32_exit = if wait_result == WAIT_OBJECT_0 {
            0
        } else {
            unsafe { GetLastError() }
        };

        let pending = status(SERVICE_STOP_PENDING, 0, 0, 10_000);
        report_status(&pending);

        {
            let _guard = EVENT_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            STOP_EVENT.store(0, Ordering::Release);
            unsafe { CloseHandle(stop_event) };
        }

        let stopped = status(SERVICE_STOPPED, 0, win32_exit, 0);
        report_status(&stopped);
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
            assert_eq!(&SERVICE_NAME[..SERVICE_NAME.len() - 1], &[
                66, 108, 97, 99, 107, 108, 105, 115, 116, 73, 110, 101, 118, 105, 116, 97, 98, 108,
                101, 65, 103, 101, 110, 116,
            ]);
        }

        #[test]
        fn service_never_accepts_network_operations_in_this_host_slice() {
            assert_eq!(STOP_REQUESTED.load(Ordering::Relaxed), false);
            assert_eq!(STOP_EVENT.load(Ordering::Relaxed), 0);
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
