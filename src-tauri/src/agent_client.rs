//! Read-only desktop client for the privileged Windows Agent status endpoint.
//!
//! This module deliberately sends no profile data or credentials. Mutating
//! operations remain disabled in the service until server identity validation,
//! credential handoff, and the connection/recovery runtime are implemented.

use serde::Deserialize;

use crate::agent_protocol::{
    write_agent_message, AgentOperation, AgentRequest, AGENT_PROTOCOL_VERSION,
    AGENT_RESPONSE_ACK_BYTE, MAX_AGENT_REQUEST_BYTES,
};


/// The pipe name and its DACL are not sufficient to authenticate the server.
/// Before sending even a read-only request, bind the connected pipe to the
/// process that the Service Control Manager reports for our installed service,
/// then verify that process is running the Agent executable beside this app.
#[cfg(windows)]
mod windows_server_identity {
    use std::ffi::{c_void, OsString};
    use std::mem::MaybeUninit;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::PathBuf;
    use std::ptr::{null, null_mut};

    use tokio::net::windows::named_pipe::NamedPipeClient;

    type Handle = *mut c_void;

    const SC_MANAGER_CONNECT: u32 = 0x0001;
    const SERVICE_QUERY_STATUS: u32 = 0x0004;
    const SERVICE_RUNNING: u32 = 0x0004;
    const SC_STATUS_PROCESS_INFO: u32 = 0;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const IMAGE_PATH_CAPACITY: usize = 32768;

    #[repr(C)]
    struct ServiceStatusProcess {
        service_type: u32,
        current_state: u32,
        controls_accepted: u32,
        win32_exit_code: u32,
        service_specific_exit_code: u32,
        checkpoint: u32,
        wait_hint: u32,
        process_id: u32,
        service_flags: u32,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenSCManagerW(machine_name: *const u16, database_name: *const u16, desired_access: u32) -> Handle;
        fn OpenServiceW(manager: Handle, service_name: *const u16, desired_access: u32) -> Handle;
        fn QueryServiceStatusEx(service: Handle, info_level: u32, buffer: *mut u8, buffer_size: u32, bytes_needed: *mut u32) -> i32;
        fn CloseServiceHandle(handle: Handle) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetNamedPipeServerProcessId(pipe: Handle, server_process_id: *mut u32) -> i32;
        fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> Handle;
        fn QueryFullProcessImageNameW(process: Handle, flags: u32, image_name: *mut u16, size: *mut u32) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    struct ServiceHandle(Handle);
    impl Drop for ServiceHandle {
        fn drop(&mut self) {
            if !self.0.is_null() { unsafe { CloseServiceHandle(self.0) }; }
        }
    }

    struct ProcessHandle(Handle);
    impl Drop for ProcessHandle {
        fn drop(&mut self) {
            if !self.0.is_null() { unsafe { CloseHandle(self.0) }; }
        }
    }

    fn wide_null(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn query_service_process_id() -> Result<u32, String> {
        let manager = ServiceHandle(unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) });
        if manager.0.is_null() {
            return Err("Windows could not open the Service Control Manager for Agent identity verification.".into());
        }
        let service_name = wide_null("BlacklistInevitableAgent");
        let service = ServiceHandle(unsafe { OpenServiceW(manager.0, service_name.as_ptr(), SERVICE_QUERY_STATUS) });
        if service.0.is_null() {
            return Err("The installed privileged Agent service could not be queried.".into());
        }

        let mut status = MaybeUninit::<ServiceStatusProcess>::zeroed();
        let mut bytes_needed = 0u32;
        let ok = unsafe {
            QueryServiceStatusEx(
                service.0,
                SC_STATUS_PROCESS_INFO,
                status.as_mut_ptr().cast::<u8>(),
                std::mem::size_of::<ServiceStatusProcess>() as u32,
                &mut bytes_needed,
            )
        };
        if ok == 0 {
            return Err("Windows could not read the privileged Agent service process identity.".into());
        }
        let status = unsafe { status.assume_init() };
        if status.current_state != SERVICE_RUNNING || status.process_id == 0 {
            return Err("The privileged Agent service is not in the running state.".into());
        }
        Ok(status.process_id)
    }

    fn query_process_image_path(process_id: u32) -> Result<(ProcessHandle, PathBuf), String> {
        // Keep the process handle alive through the SCM PID comparison so Windows
        // cannot recycle the observed process object while identity is checked.
        let process = ProcessHandle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) });
        if process.0.is_null() {
            return Err("Windows could not open the named-pipe server process for identity verification.".into());
        }
        let mut image = vec![0u16; IMAGE_PATH_CAPACITY];
        let mut length = image.len() as u32;
        let ok = unsafe { QueryFullProcessImageNameW(process.0, 0, image.as_mut_ptr(), &mut length) };
        if ok == 0 || length == 0 || length as usize > image.len() {
            return Err("Windows could not read the named-pipe server executable path.".into());
        }
        let image = OsString::from_wide(&image[..length as usize]);
        Ok((process, PathBuf::from(image)))
    }

    pub fn verify(pipe: &NamedPipeClient) -> Result<(), String> {
        let mut pipe_server_pid = 0u32;
        let ok = unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pipe_server_pid) };
        if ok == 0 || pipe_server_pid == 0 {
            return Err("Windows could not identify the process serving the Agent named pipe.".into());
        }
        let (process_handle, actual_image) = query_process_image_path(pipe_server_pid)?;
        let service_pid = query_service_process_id()?;

        let current_exe = std::env::current_exe()
            .map_err(|_| "The desktop executable path could not be resolved for Agent verification.".to_string())?;
        let install_directory = current_exe.parent()
            .ok_or_else(|| "The desktop executable has no installation directory.".to_string())?;
        let expected_image = install_directory.join("blacklist-inevitable-agent.exe")
            .canonicalize().map_err(|_| "The installed Agent executable could not be resolved.".to_string())?;
        let actual_image = actual_image.canonicalize()
            .map_err(|_| "The named-pipe server executable could not be resolved.".to_string())?;

        super::validate_server_identity_values(
            pipe_server_pid,
            SERVICE_RUNNING,
            service_pid,
            &actual_image.to_string_lossy(),
            &expected_image.to_string_lossy(),
        )?;
        drop(process_handle);
        Ok(())
    }
}

#[cfg(windows)]
fn verify_connected_server(pipe: &tokio::net::windows::named_pipe::NamedPipeClient) -> Result<(), String> {
    windows_server_identity::verify(pipe)
}

#[cfg(not(windows))]
fn verify_connected_server<T>(_pipe: &T) -> Result<(), String> {
    Err("The privileged Agent server identity can only be verified on Windows.".into())
}

fn normalize_windows_image_path(path: &str) -> String {
    let replaced = path.replace('/', "\\");
    let without_extended_prefix = replaced.strip_prefix(r"\\?\").unwrap_or(&replaced);
    let mut normalized = without_extended_prefix.to_string();
    while normalized.len() > 3 && normalized.ends_with('\\') {
        normalized.pop();
    }
    normalized
}

fn validate_server_identity_values(
    pipe_server_pid: u32,
    service_state: u32,
    service_pid: u32,
    actual_image_path: &str,
    expected_image_path: &str,
) -> Result<(), String> {
    if service_state != 4 || service_pid == 0 {
        return Err("The privileged Agent service is not running.".into());
    }
    if pipe_server_pid == 0 || pipe_server_pid != service_pid {
        return Err("The named-pipe server process is not the registered privileged Agent service.".into());
    }
    if actual_image_path.is_empty() || expected_image_path.is_empty()
        || !normalize_windows_image_path(actual_image_path)
            .eq_ignore_ascii_case(&normalize_windows_image_path(expected_image_path))
    {
        return Err("The named-pipe server executable is not the installed Agent beside this desktop application.".into());
    }
    Ok(())
}

const PIPE_NAME: &str = r"\\.\pipe\BlacklistInevitable.Agent.v1";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentResponseEnvelope {
    version: u16,
    request_id: String,
    status: String,
    detail: Option<String>,
}

fn decode_agent_response(payload: &[u8], expected_request_id: &str) -> Result<String, String> {
    if payload.is_empty() || payload.len() > MAX_AGENT_REQUEST_BYTES {
        return Err("The Agent response is empty or exceeds the protocol size limit.".to_string());
    }

    let response: AgentResponseEnvelope = serde_json::from_slice(payload)
        .map_err(|_| "The Agent returned an invalid status response.".to_string())?;

    if response.version != AGENT_PROTOCOL_VERSION {
        return Err("The Agent response protocol version is not supported.".to_string());
    }
    if response.request_id != expected_request_id {
        return Err("The Agent response did not match the outstanding request.".to_string());
    }
    if response.status != "ok" {
        return Err(response
            .detail
            .unwrap_or_else(|| "The Agent rejected the status request.".to_string()));
    }

    Ok(response
        .detail
        .unwrap_or_else(|| "The Agent service is responding.".to_string())
        .chars()
        .filter(|character| !character.is_control() || matches!(*character, '\n' | '\t'))
        .take(1200)
        .collect())
}

#[cfg(windows)]
pub async fn query_status() -> Result<String, String> {
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ClientOptions;
    use tokio::time::{sleep, timeout};
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut pipe = loop {
        match ClientOptions::new().open(PIPE_NAME) {
            Ok(pipe) => break pipe,
            Err(error)
                if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                    && Instant::now() < deadline =>
            {
                sleep(Duration::from_millis(50)).await;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err("The privileged Agent service is not installed or running.".to_string());
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err("Windows denied access to the privileged Agent status pipe.".to_string());
            }
            Err(_) => {
                return Err("The privileged Agent service is not reachable.".to_string());
            }
        }
    };

    // Reject a spoofed pipe before sending any protocol bytes.
    verify_connected_server(&pipe)?;

    let request_id = uuid::Uuid::new_v4().to_string();
    let request = AgentRequest {
        version: AGENT_PROTOCOL_VERSION,
        request_id: request_id.clone(),
        operation: AgentOperation::GetStatus,
    };

    timeout(Duration::from_secs(5), async {
        write_agent_message(&mut pipe, &request).await?;

        let mut header = [0u8; 4];
        pipe.read_exact(&mut header)
            .await
            .map_err(|_| "The Agent closed the status response before its frame header arrived.".to_string())?;
        let length = u32::from_le_bytes(header) as usize;
        if length == 0 || length > MAX_AGENT_REQUEST_BYTES {
            return Err("The Agent response frame length is invalid.".to_string());
        }

        let mut payload = vec![0u8; length];
        pipe.read_exact(&mut payload)
            .await
            .map_err(|_| "The Agent closed the status response before its payload arrived.".to_string())?;
        let detail = decode_agent_response(&payload, &request_id)?;
        pipe.write_all(&[AGENT_RESPONSE_ACK_BYTE])
            .await
            .map_err(|_| "The Agent response acknowledgement could not be sent.".to_string())?;
        pipe.flush()
            .await
            .map_err(|_| "The Agent response acknowledgement could not be flushed.".to_string())?;
        Ok(detail)
    })
    .await
    .map_err(|_| "The Agent status request timed out.".to_string())?
}

#[cfg(not(windows))]
pub async fn query_status() -> Result<String, String> {
    Err("The privileged Agent service is available only in the Windows desktop build.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_running_scm_agent_process_and_expected_image() {
        assert!(validate_server_identity_values(
            8124, 4, 8124,
            r"\\?\C:\Program Files\BlacklistInevitable\blacklist-inevitable-agent.exe",
            r"C:\Program Files\BlacklistInevitable\blacklist-inevitable-agent.exe"
        ).is_ok());
    }

    #[test]
    fn rejects_a_named_pipe_owned_by_another_process() {
        assert!(validate_server_identity_values(
            8125, 4, 8124,
            r"C:\Program Files\BlacklistInevitable\blacklist-inevitable-agent.exe",
            r"C:\Program Files\BlacklistInevitable\blacklist-inevitable-agent.exe"
        ).is_err());
    }

    #[test]
    fn rejects_a_service_that_is_not_running() {
        assert!(validate_server_identity_values(
            8124, 2, 8124,
            r"C:\Program Files\BlacklistInevitable\blacklist-inevitable-agent.exe",
            r"C:\Program Files\BlacklistInevitable\blacklist-inevitable-agent.exe"
        ).is_err());
    }

    #[test]
    fn rejects_a_different_executable_image() {
        assert!(validate_server_identity_values(
            8124, 4, 8124,
            r"C:\Users\Public\agent.exe",
            r"C:\Program Files\BlacklistInevitable\blacklist-inevitable-agent.exe"
        ).is_err());
    }

    #[test]
    fn accepts_extended_and_win32_forms_of_the_same_path() {
        assert!(validate_server_identity_values(
            8124, 4, 8124,
            r"\\?\C:\Program Files\BlacklistInevitable\blacklist-inevitable-agent.exe",
            r"C:\Program Files\BlacklistInevitable\blacklist-inevitable-agent.exe"
        ).is_ok());
    }

    #[test]
    fn accepts_a_correlated_status_response() {
        let payload = br#"{"version":1,"requestId":"status-1","status":"ok","connection":null,"detail":"Agent ready"}"#;
        assert_eq!(
            decode_agent_response(payload, "status-1").unwrap(),
            "Agent ready"
        );
    }

    #[test]
    fn rejects_a_response_for_another_request() {
        let payload = br#"{"version":1,"requestId":"other","status":"ok","detail":"Agent ready"}"#;
        assert!(decode_agent_response(payload, "status-1").is_err());
    }

    #[test]
    fn rejects_an_unsupported_response_version() {
        let payload = br#"{"version":2,"requestId":"status-1","status":"ok"}"#;
        assert!(decode_agent_response(payload, "status-1").is_err());
    }

    #[test]
    fn rejects_non_success_responses() {
        let payload = br#"{"version":1,"requestId":"status-1","status":"rejected","detail":"disabled"}"#;
        assert!(decode_agent_response(payload, "status-1").is_err());
    }

    #[test]
    fn bounds_and_sanitizes_response_details() {
        let payload = serde_json::json!({
            "version": 1,
            "requestId": "status-1",
            "status": "ok",
            "detail": "ready\r\n".repeat(300),
        })
        .to_string();
        let decoded = decode_agent_response(payload.as_bytes(), "status-1").unwrap();
        assert!(decoded.len() <= 1200);
        assert!(!decoded.chars().any(|character| character == '\r'));
    }
}
