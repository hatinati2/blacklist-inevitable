//! Read-only Windows observations used by crash recovery.
//!
//! Probes return Unknown on access or API failures. Unknown is never treated as
//! absent by the recovery assessment planner. This module never terminates a
//! process, changes an adapter, edits routes/DNS, changes WFP, or removes journals.

use crate::recovery_assessment::Observation;
use crate::recovery_journal::{EngineProcessRecord, FirewallFilterRecord};

/// Observe one journaled process by PID and kernel creation time.
///
/// PID alone is not a stable identity. Access denied, API errors, invalid
/// timestamps, and unexpected wait results all remain Unknown (fail closed).
#[cfg(windows)]
pub fn observe_recorded_engine_process(
    expected: &EngineProcessRecord,
) -> Result<Observation<EngineProcessRecord>, String> {
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_INVALID_PARAMETER, FILETIME, SYNCHRONIZE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, WaitForSingleObject,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    if expected.process_id == 0 || expected.creation_time_100ns == 0 {
        return Ok(Observation::Unknown);
    }

    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            0,
            expected.process_id,
        )
    };
    if handle.is_null() {
        let error = unsafe { GetLastError() };
        if error == ERROR_INVALID_PARAMETER {
            return Ok(Observation::Absent);
        }
        return Err(format!(
            "OpenProcess could not inspect journaled engine PID {} (Windows error {}).",
            expected.process_id, error
        ));
    }
    let process = OwnedProcessHandle(handle);

    match unsafe { WaitForSingleObject(process.0, 0) } {
        WAIT_OBJECT_0 => return Ok(Observation::Absent),
        WAIT_TIMEOUT => {}
        _ => return Err("The journaled engine process wait query was inconclusive.".into()),
    }

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe {
        GetProcessTimes(
            process.0,
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err("GetProcessTimes could not verify the journaled engine identity.".into());
    }

    let creation_time_100ns = filetime_to_ticks(creation.dwLowDateTime, creation.dwHighDateTime);
    if creation_time_100ns == 0 {
        return Err("Windows returned an invalid engine process creation timestamp.".into());
    }

    // Re-check liveness after reading the timestamp to avoid reporting a process
    // as live when it exited while the observation was being assembled.
    match unsafe { WaitForSingleObject(process.0, 0) } {
        WAIT_OBJECT_0 => Ok(Observation::Absent),
        WAIT_TIMEOUT => Ok(Observation::Present(EngineProcessRecord {
            process_id: expected.process_id,
            creation_time_100ns,
        })),
        _ => Err("The journaled engine process changed state during observation.".into()),
    }
}

#[cfg(windows)]
fn filetime_to_ticks(low: u32, high: u32) -> u64 {
    (u64::from(high) << 32) | u64::from(low)
}

#[cfg(windows)]
struct OwnedProcessHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for OwnedProcessHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

/// Read the current product-provider WFP filter inventory using a read-only
/// transaction. The vector is Present(empty) only after a complete successful
/// provider-scoped enumeration; any access, enumeration, truncation, or cleanup
/// error returns Err and must be represented as Observation::Unknown.
#[cfg(windows)]
pub fn observe_agent_wfp_filters(
    engine: &mut crate::wfp_engine::WfpEngine,
) -> Result<Observation<Vec<FirewallFilterRecord>>, String> {
    engine
        .enumerate_owned_filters()
        .map(Observation::Present)
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn filetime_conversion_preserves_high_and_low_words() {
        assert_eq!(
            super::filetime_to_ticks(0x89AB_CDEF, 0x0123_4567),
            0x0123_4567_89AB_CDEF
        );
    }
}
