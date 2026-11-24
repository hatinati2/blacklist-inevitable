//! Unelevated desktop client for the privileged Windows Agent.
//!
//! Requests use a local authenticated named pipe. Connect credentials are
//! sent only after verifying the LocalSystem service peer and are held in
//! zeroizing containers for the one-shot request lifetime. The current Agent
//! intentionally rejects Connect until its recovery and tunnel runtime exist.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;
use zeroize::Zeroizing;

use crate::agent_protocol::{
    encode_agent_frame, AgentConnectPayload, AgentOperation, AgentProfile, AgentRequest,
    AgentSecret,
    AgentResponse, AgentResponseStatus, AGENT_PROTOCOL_VERSION,
};

const PIPE_NAME: &str = r"\\.\pipe\BlacklistInevitable.Agent.v1";
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopAgentStatus {
    pub available: bool,
    pub connection: Option<crate::connection_state::ConnectionSnapshot>,
    pub detail: String,
}

pub async fn get_status() -> DesktopAgentStatus {
    match request_status().await {
        Ok(response) => DesktopAgentStatus {
            available: true,
            connection: response.connection,
            detail: response
                .detail
                .unwrap_or_else(|| "The privileged Agent service responded.".to_string()),
        },
        Err(error) => DesktopAgentStatus {
            available: false,
            connection: None,
            detail: error,
        },
    }
}

/// Send a single profile and its credentials to the authenticated Agent.
/// The Agent currently rejects the operation; this transport slice establishes
/// the bounded one-shot handoff without enabling network mutations.
pub async fn connect_profile(
    profile: AgentProfile,
    credentials: BTreeMap<String, String>,
) -> Result<AgentResponse, String> {
    let credentials = credentials
        .into_iter()
        .map(|(name, value)| (name, AgentSecret::new(value)))
        .collect();
    let request = AgentRequest {
        version: AGENT_PROTOCOL_VERSION,
        request_id: uuid::Uuid::new_v4().simple().to_string(),
        operation: AgentOperation::Connect {
            payload: AgentConnectPayload {
                profile,
                credentials,
            },
        },
    };
    send_request(request).await
}

async fn request_status() -> Result<AgentResponse, String> {
    let request = AgentRequest {
        version: AGENT_PROTOCOL_VERSION,
        request_id: uuid::Uuid::new_v4().simple().to_string(),
        operation: AgentOperation::GetStatus,
    };
    let response = send_request(request).await?;
    if response.status != AgentResponseStatus::Ok {
        return Err(response
            .detail
            .unwrap_or_else(|| "The Agent rejected the status request.".to_string()));
    }
    Ok(response)
}

async fn send_request(request: AgentRequest) -> Result<AgentResponse, String> {
    #[cfg(windows)]
    {
        request_windows(request).await
    }
    #[cfg(not(windows))]
    {
        drop(request);
        Err("The privileged Windows Agent is available only on Windows.".to_string())
    }
}

#[cfg(windows)]
async fn request_windows(request: AgentRequest) -> Result<AgentResponse, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ClientOptions;
    use tokio::time::{sleep, timeout};
    use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

    timeout(CLIENT_TIMEOUT, async move {
        let expected_request_id = request.request_id.clone();
        // ClientOptions::open returns an already-connected client. Retry only
        // the transient busy condition while the single-instance Agent pipe is
        // serving another request; all other errors fail closed.
        let mut pipe = loop {
            match ClientOptions::new().open(PIPE_NAME) {
                Ok(pipe) => break pipe,
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                    sleep(Duration::from_millis(50)).await;
                }
                Err(_) => {
                    return Err("The privileged Agent service is not installed or is not accepting connections.".to_string());
                }
            }
        };

        verify_system_service_peer(&pipe)?;

        // The serialized request contains credentials for Connect. Zeroize it
        // on every return path, including timeout and pipe errors.
        let frame = encode_agent_frame(&request)?;
        pipe.write_all(&frame)
            .await
            .map_err(|_| "The Agent IPC request could not be written.".to_string())?;
        pipe.flush()
            .await
            .map_err(|_| "The Agent IPC request could not be flushed.".to_string())?;

        let mut header = [0u8; 4];
        pipe.read_exact(&mut header)
            .await
            .map_err(|_| "The Agent closed the pipe before returning a complete response.".to_string())?;
        let length = u32::from_le_bytes(header) as usize;
        if length == 0 || length > crate::agent_protocol::MAX_AGENT_REQUEST_BYTES {
            return Err("The Agent response exceeds the protocol size limit.".to_string());
        }

        let mut payload = Zeroizing::new(vec![0u8; length]);
        pipe.read_exact(&mut payload)
            .await
            .map_err(|_| "The Agent response was truncated.".to_string())?;
        let response: AgentResponse = serde_json::from_slice(&payload)
            .map_err(|_| "The Agent returned an invalid response.".to_string())?;

        if response.version != AGENT_PROTOCOL_VERSION
            || response.request_id != expected_request_id
        {
            return Err("The Agent response does not match the active protocol request.".to_string());
        }
        Ok(response)
    })
    .await
    .map_err(|_| "The privileged Agent did not respond within 5 seconds.".to_string())?
}

#[cfg(windows)]
fn verify_system_service_peer(
    pipe: &tokio::net::windows::named_pipe::NamedPipeClient,
) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenSessionId, TokenUser, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Pipes::{
        GetNamedPipeServerProcessId, GetNamedPipeServerSessionId,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    let pipe_handle = pipe.as_raw_handle() as HANDLE;
    let mut server_pid = 0u32;
    if unsafe { GetNamedPipeServerProcessId(pipe_handle, &mut server_pid) } == 0 || server_pid == 0 {
        return Err("The Agent pipe server identity could not be verified.".to_string());
    }
    let mut server_session = u32::MAX;
    if unsafe { GetNamedPipeServerSessionId(pipe_handle, &mut server_session) } == 0
        || server_session != 0
    {
        return Err("The Agent pipe server is not running in Windows service session 0.".to_string());
    }

    let process = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, server_pid)
    };
    if process.is_null() {
        // Medium-integrity desktop processes can be denied access to a
        // LocalSystem process token. In that case verify the named-pipe
        // object's owner SID instead, matching the Windows IPC broker pattern.
        return verify_local_system_pipe_owner(pipe_handle);
    }
    let process = Handle(process);

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 || token.is_null() {
        return verify_local_system_pipe_owner(pipe_handle);
    }
    let token = Handle(token);

    let mut required = 0u32;
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required < std::mem::size_of::<TOKEN_USER>() as u32 || required > 4096 {
        return Err("The Agent service returned an invalid user-token size.".to_string());
    }
    let mut token_buffer = vec![0u8; required as usize];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            token_buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err("The Agent service user identity could not be read.".to_string());
    }

    let token_user = unsafe { &*(token_buffer.as_ptr().cast::<TOKEN_USER>()) };
    if token_user.User.Sid.is_null() {
        return Err("The Agent service token has no user SID.".to_string());
    }
    // LocalSystem is the well-known SID S-1-5-18:
    // revision=1, one sub-authority, NT authority=5, sub-authority=18.
    let sid_length = unsafe { windows_sys::Win32::Security::GetLengthSid(token_user.User.Sid) };
    if sid_length != 12 {
        return Err("The named-pipe server is not running as the required LocalSystem service identity.".to_string());
    }
    let sid = unsafe {
        std::slice::from_raw_parts(token_user.User.Sid.cast::<u8>(), sid_length as usize)
    };
    if !is_local_system_sid(sid) {
        return Err("The named-pipe server is not running as the required LocalSystem service identity.".to_string());
    }

    let mut session_id = u32::MAX;
    let mut returned = 0u32;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenSessionId,
            (&mut session_id as *mut u32).cast(),
            std::mem::size_of::<u32>() as u32,
            &mut returned,
        )
    } == 0
        || returned != std::mem::size_of::<u32>() as u32
        || session_id != 0
    {
        return Err("The named-pipe server is not running in the expected Windows service session.".to_string());
    }

    Ok(())
}

fn is_local_system_sid(sid: &[u8]) -> bool {
    sid == [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]
}

#[cfg(windows)]
fn verify_local_system_pipe_owner(pipe_handle: windows_sys::Win32::Foundation::HANDLE) -> Result<(), String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::GetLengthSid;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION;

    let mut owner_sid = std::ptr::null_mut();
    let mut security_descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            pipe_handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner_sid,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if status != 0 {
        return Err("The Agent pipe owner could not be verified.".to_string());
    }

    let is_system_owner = !owner_sid.is_null()
        && unsafe { GetLengthSid(owner_sid) } == 12
        && is_local_system_sid(unsafe { std::slice::from_raw_parts(owner_sid.cast::<u8>(), 12) });
    if !security_descriptor.is_null() {
        unsafe { LocalFree(security_descriptor) };
    }
    if is_system_owner {
        Ok(())
    } else {
        Err("The named-pipe object is not owned by the required LocalSystem identity.".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_the_exact_local_system_sid() {
        assert!(is_local_system_sid(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]));
        assert!(!is_local_system_sid(&[1, 1, 0, 0, 0, 0, 0, 5, 19, 0, 0, 0]));
        assert!(!is_local_system_sid(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0]));
    }

    #[test]
    fn pipe_endpoint_is_local_and_versioned() {
        assert!(PIPE_NAME.starts_with(r"\\.\pipe\"));
        assert!(PIPE_NAME.ends_with(".v1"));
    }

    #[test]
    fn client_timeout_is_finite() {
        assert!(CLIENT_TIMEOUT.as_secs() > 0);
        assert!(CLIENT_TIMEOUT.as_secs() <= 10);
    }
}
