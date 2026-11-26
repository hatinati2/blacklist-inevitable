//! Windows-only authenticated named-pipe transport for the privileged Agent.
//!
//! The listener exposes status and read-only endpoint preparation in this milestone.
//! It accepts only the active physical-console user's token/session, rejects remote
//! pipe clients, uses a protected DACL, and never forwards network-mutating operations.

use std::collections::BTreeMap;
use std::slice;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED,
    ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER, TokenSessionId, TokenUser,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Storage::FileSystem::{
    ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientSessionId,
    ImpersonateNamedPipeClient, PeekNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::RemoteDesktop::{
    WTSGetActiveConsoleSessionId, WTSQueryUserToken,
};
use windows_sys::Win32::System::IO::{
    CancelIoEx, GetOverlappedResult, OVERLAPPED,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentThread, OpenThreadToken, Sleep, WaitForMultipleObjects,
    WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::Foundation::HANDLE;

use crate::agent_protocol::{
    AgentOperation, AgentRequestReplayGuard, AgentResponse, MAX_AGENT_REQUEST_BYTES,
};
use crate::connection_state::{ConnectionCoordinator, ConnectionPhase};

const PIPE_NAME: &str = r"\\.\pipe\BlacklistInevitable.Agent.v1";

const PIPE_BUFFER_BYTES: u32 = 4096;
const FRAME_TIMEOUT: Duration = Duration::from_secs(30);
const TOKEN_BUFFER_BYTES: usize = 4096;
const MAX_SID_BYTES: usize = 128;
pub(crate) const FATAL_REVERT_ERROR_PREFIX: &str = "fatal: RevertToSelf failed";

/// Create the single protected local pipe instance. The Interactive Users ACE is
/// only the outer connection gate; every accepted connection is additionally
/// impersonated and compared against the current active-console user's SID and
/// session ID before a request is read.
pub fn create_listener() -> Result<HANDLE, String> {
    let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"
        .encode_utf16()
        .chain(Some(0))
        .collect();

    let mut descriptor = std::ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if converted == 0 || descriptor.is_null() {
        let error = unsafe { GetLastError() };
        return Err(format!("The Agent pipe security descriptor could not be created (Windows error {error})."));
    }

    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED;
    let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;

    let pipe_name: Vec<u16> = PIPE_NAME.encode_utf16().chain(Some(0)).collect();
    let pipe = unsafe {
        CreateNamedPipeW(
            pipe_name.as_ptr(),
            open_mode,
            pipe_mode,
            1,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            5000,
            &attributes,
        )
    };
    unsafe { LocalFree(descriptor) };

    if pipe == INVALID_HANDLE_VALUE || pipe.is_null() {
        let error = unsafe { GetLastError() };
        return Err(format!("The protected Agent named pipe could not be created (Windows error {error})."));
    }
    Ok(pipe)
}

/// Serve one request per authenticated connection. The service-control layer
/// owns cancellation of synchronous ConnectNamedPipe/ReadFile/WriteFile calls.
pub fn serve(
    pipe: HANDLE,
    stop_event: HANDLE,
    startup_detail: &str,
    connection: &ConnectionCoordinator,
) -> Result<(), String> {
    if pipe.is_null() || pipe == INVALID_HANDLE_VALUE || stop_event.is_null() {
        return Err("The Agent named pipe or stop event handle is invalid.".into());
    }

    // This runtime is owned by the service listener thread. Preparation is
    // synchronous at the IPC boundary and all network work has explicit timeouts.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "The Agent could not initialize its bounded preparation runtime.".to_string())?;
    let mut prepared_snapshot: Option<PreparedConnectSnapshot> = None;

    loop {
        if stop_requested(stop_event) {
            return Ok(());
        }

        if !connect_client_overlapped(pipe, stop_event)? {
            return Ok(());
        }

        let request_result = if stop_requested(stop_event) {
            Ok(())
        } else {
            handle_authenticated_connection(
                pipe,
                stop_event,
                startup_detail,
                connection,
                &runtime,
                &mut prepared_snapshot,
            )
        };

        // Continuing on a thread that failed to revert impersonation would risk
        // running the next request under the prior client token. Stop the service
        // process instead; Windows will close the pipe handle on process exit.
        if let Err(error) = &request_result {
            if error.starts_with(FATAL_REVERT_ERROR_PREFIX) {
                return Err(error.clone());
            }
        }

        unsafe { DisconnectNamedPipe(pipe) };

        if stop_requested(stop_event) {
            return Ok(());
        }

        // An unauthorized or malformed local client is dropped without a
        // diagnostic response. The next instance remains available.
        if request_result.is_err() {
            unsafe { Sleep(100) };
        }
    }
}

fn stop_requested(stop_event: HANDLE) -> bool {
    unsafe { WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0 }
}

struct PreparedConnectSnapshot {
    profile_id: String,
    snapshot: crate::windows_egress_snapshot::WindowsEgressSnapshot,
}

/// Temporary credential copies are erased even if endpoint preparation returns early.
struct WipingCredentials(BTreeMap<String, String>);

impl Drop for WipingCredentials {
    fn drop(&mut self) {
        for secret in self.0.values_mut() {
            secret.zeroize();
        }
    }
}

fn discard_stale_preparation(
    prepared: &mut Option<PreparedConnectSnapshot>,
) -> Option<String> {
    let stale = prepared
        .as_ref()
        .is_some_and(|item| item.snapshot.ensure_current().is_err());
    if !stale {
        return None;
    }

    let previous = prepared.take()?;
    let profile_id = previous.profile_id;
    Some(match previous.snapshot.shutdown() {
        Ok(()) => format!(
            "The prepared endpoint snapshot for profile '{profile_id}' was invalidated by a route/interface change and discarded."
        ),
        Err(error) => format!(
            "The prepared endpoint snapshot for profile '{profile_id}' was invalidated and discarded; notification cleanup reported: {error}"
        ),
    })
}

fn prepare_connect_snapshot(
    request_id: String,
    payload: crate::agent_protocol::AgentConnectPayload,
    connection: &ConnectionCoordinator,
    runtime: &tokio::runtime::Runtime,
    prepared: &mut Option<PreparedConnectSnapshot>,
) -> AgentResponse {
    let current = connection.snapshot();
    if current.phase != ConnectionPhase::Disconnected || !current.cleanup_healthy {
        return AgentResponse::rejected_with_connection(
            request_id,
            Some(current),
            "Endpoint preparation is allowed only while the Agent is cleanly Disconnected.",
        );
    }

    if let Some(previous) = prepared.take() {
        if let Err(error) = previous.snapshot.shutdown() {
            return AgentResponse::rejected_with_connection(
                request_id,
                Some(current),
                format!("The previous endpoint snapshot could not be retired safely: {error}"),
            );
        }
    }

    let crate::agent_protocol::AgentConnectPayload {
        profile,
        credentials: agent_credentials,
    } = payload;
    let profile_id = profile.id.clone();
    let profile = crate::profiles::ProfileSummary::from(profile);
    let credentials = WipingCredentials(
        agent_credentials
            .iter()
            .map(|(name, value)| (name.clone(), value.expose_secret().to_string()))
            .collect(),
    );

    let capture = runtime.block_on(
        crate::windows_egress_snapshot::WindowsEgressSnapshot::capture_for_profile(
            &profile,
            &credentials.0,
        ),
    );
    drop(credentials);

    match capture {
        Ok(snapshot) => {
            let endpoint_count = match snapshot.resolved_endpoints() {
                Ok(endpoints) => endpoints.len(),
                Err(error) => {
                    let _ = snapshot.shutdown();
                    return AgentResponse::failed_redacted(
                        request_id,
                        Some(connection.snapshot()),
                        error,
                        &agent_credentials,
                    );
                }
            };
            if let Err(error) = snapshot.ensure_current() {
                let _ = snapshot.shutdown();
                return AgentResponse::failed_redacted(
                    request_id,
                    Some(connection.snapshot()),
                    error,
                    &agent_credentials,
                );
            }

            let latest = connection.snapshot();
            if latest.phase != ConnectionPhase::Disconnected || !latest.cleanup_healthy {
                let _ = snapshot.shutdown();
                return AgentResponse::rejected_with_connection(
                    request_id,
                    Some(latest),
                    "Agent state changed during endpoint preparation; the snapshot was discarded.",
                );
            }

            let generation = snapshot.network_generation();
            *prepared = Some(PreparedConnectSnapshot { profile_id: profile_id.clone(), snapshot });
            let mut response = AgentResponse::ok(request_id, Some(latest));
            response.detail = Some(format!(
                "Endpoint preparation succeeded for profile '{profile_id}': {endpoint_count} route-bound endpoint binding(s), network generation {generation}. The snapshot is retained by the Agent. This did not connect, install WFP policy, or modify routes/DNS."
            ));
            response
        }
        Err(error) => AgentResponse::failed_redacted(
            request_id,
            Some(connection.snapshot()),
            error,
            &agent_credentials,
        ),
    }
}

fn handle_authenticated_connection(
    pipe: HANDLE,
    stop_event: HANDLE,
    startup_detail: &str,
    connection: &ConnectionCoordinator,
    runtime: &tokio::runtime::Runtime,
    prepared: &mut Option<PreparedConnectSnapshot>,
) -> Result<(), String> {
    authenticate_active_console_client(pipe)?;

    let mut replay_guard = AgentRequestReplayGuard::default();
    let request = read_one_request(pipe, stop_event)?;
    replay_guard.accept(&request)?;

    let invalidation_detail = discard_stale_preparation(prepared);
    let response = match request.operation {
        AgentOperation::GetStatus | AgentOperation::GetDiagnostics => {
            let mut response =
                AgentResponse::ok(request.request_id, Some(connection.snapshot()));
            response.detail = Some(match invalidation_detail {
                Some(detail) => format!("{startup_detail} {detail}"),
                None => startup_detail.to_string(),
            });
            response
        }
        AgentOperation::PrepareConnect { payload } => {
            prepare_connect_snapshot(request.request_id, payload, connection, runtime, prepared)
        }
        AgentOperation::Connect { .. }
        | AgentOperation::Disconnect { .. }
        | AgentOperation::Recover => AgentResponse::rejected_with_connection(
            request.request_id,
            Some(connection.snapshot()),
            "Connect, Disconnect, and Recover remain disabled until the Agent-owned WFP, route, DNS, engine, and recovery transaction is implemented.",
        ),
    };

    write_one_response(pipe, stop_event, &response)
}

fn create_io_event() -> Result<HANDLE, String> {
    let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if event.is_null() {
        let error = unsafe { GetLastError() };
        return Err(format!("The Agent could not create an overlapped I/O event (Windows error {error})."));
    }
    Ok(event)
}

/// Wait for a specific overlapped operation or service-stop signal. Cancellation
/// is scoped to this OVERLAPPED record, and the event is drained before the
/// caller releases its stack-backed OVERLAPPED/buffer storage.
fn wait_for_overlapped(
    pipe: HANDLE,
    stop_event: HANDLE,
    io_event: HANDLE,
    overlapped: &OVERLAPPED,
    deadline: Option<Instant>,
) -> Result<(), String> {
    let timeout = match deadline {
        Some(deadline) => {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                0
            } else {
                remaining.as_millis().min(u32::MAX as u128) as u32
            }
        }
        None => INFINITE,
    };
    let handles = [stop_event, io_event];
    let wait = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, timeout) };
    if wait == WAIT_OBJECT_0 + 1 {
        return Ok(());
    }

    if wait == WAIT_OBJECT_0 || wait == WAIT_TIMEOUT || wait == WAIT_FAILED {
        let wait_error = if wait == WAIT_FAILED {
            unsafe { GetLastError() }
        } else {
            0
        };
        unsafe { CancelIoEx(pipe, overlapped) };
        // Do not return while Windows can still reference the OVERLAPPED or the
        // I/O buffer on this stack frame.
        unsafe { WaitForSingleObject(io_event, INFINITE) };
        let mut transferred = 0u32;
        unsafe { GetOverlappedResult(pipe, overlapped, &mut transferred, 0) };
        if wait == WAIT_OBJECT_0 || stop_requested(stop_event) {
            return Err("The Agent service is stopping.".into());
        }
        if wait == WAIT_TIMEOUT {
            return Err("The Agent IPC frame timed out.".into());
        }
        return Err(format!("Waiting for Agent pipe I/O failed (Windows error {wait_error})."));
    }

    unsafe { CancelIoEx(pipe, overlapped) };
    unsafe { WaitForSingleObject(io_event, INFINITE) };
    let mut transferred = 0u32;
    unsafe { GetOverlappedResult(pipe, overlapped, &mut transferred, 0) };
    Err(format!("The Agent pipe returned an unexpected wait status {wait}."))
}

fn connect_client_overlapped(pipe: HANDLE, stop_event: HANDLE) -> Result<bool, String> {
    if stop_requested(stop_event) {
        return Ok(false);
    }
    let io_event = create_io_event()?;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = io_event;

    let connected = unsafe { ConnectNamedPipe(pipe, &mut overlapped) };
    if connected != 0 {
        unsafe { CloseHandle(io_event) };
        return Ok(true);
    }

    let error = unsafe { GetLastError() };
    if error == ERROR_PIPE_CONNECTED {
        unsafe { CloseHandle(io_event) };
        return Ok(true);
    }
    if error != ERROR_IO_PENDING {
        unsafe { CloseHandle(io_event) };
        if error == ERROR_OPERATION_ABORTED && stop_requested(stop_event) {
            return Ok(false);
        }
        return Err(format!("The Agent pipe listener failed while accepting a client (Windows error {error})."));
    }

    let waited = wait_for_overlapped(pipe, stop_event, io_event, &overlapped, None);
    let mut transferred = 0u32;
    let completed = if waited.is_ok() {
        unsafe { GetOverlappedResult(pipe, &overlapped, &mut transferred, 0) }
    } else {
        0
    };
    unsafe { CloseHandle(io_event) };

    if stop_requested(stop_event) {
        return Ok(false);
    }
    waited?;
    if completed == 0 {
        let error = unsafe { GetLastError() };
        return Err(format!("The Agent pipe connection did not complete (Windows error {error})."));
    }
    Ok(true)
}

fn read_pipe_chunk_overlapped(
    pipe: HANDLE,
    stop_event: HANDLE,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<usize, String> {
    let io_event = create_io_event()?;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = io_event;
    let mut transferred = 0u32;
    let read = unsafe {
        ReadFile(
            pipe,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut transferred,
            &mut overlapped,
        )
    };

    let outcome = if read != 0 {
        Ok(())
    } else {
        let error = unsafe { GetLastError() };
        if error == ERROR_IO_PENDING {
            wait_for_overlapped(pipe, stop_event, io_event, &overlapped, Some(deadline))
        } else if error == ERROR_OPERATION_ABORTED && stop_requested(stop_event) {
            Err("The Agent service is stopping.".into())
        } else {
            Err(format!("The Agent IPC frame could not be read (Windows error {error})."))
        }
    };

    if outcome.is_ok() {
        if unsafe { GetOverlappedResult(pipe, &overlapped, &mut transferred, 0) } == 0 {
            let error = unsafe { GetLastError() };
            unsafe { CloseHandle(io_event) };
            return Err(format!("The Agent IPC read could not be completed (Windows error {error})."));
        }
    }
    unsafe { CloseHandle(io_event) };
    outcome?;
    Ok(transferred as usize)
}

fn write_pipe_chunk_overlapped(
    pipe: HANDLE,
    stop_event: HANDLE,
    buffer: &[u8],
    deadline: Instant,
) -> Result<usize, String> {
    let io_event = create_io_event()?;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = io_event;
    let mut transferred = 0u32;
    let written = unsafe {
        WriteFile(
            pipe,
            buffer.as_ptr(),
            buffer.len() as u32,
            &mut transferred,
            &mut overlapped,
        )
    };

    let outcome = if written != 0 {
        Ok(())
    } else {
        let error = unsafe { GetLastError() };
        if error == ERROR_IO_PENDING {
            wait_for_overlapped(pipe, stop_event, io_event, &overlapped, Some(deadline))
        } else if error == ERROR_OPERATION_ABORTED && stop_requested(stop_event) {
            Err("The Agent service is stopping.".into())
        } else {
            Err(format!("The Agent IPC response could not be written (Windows error {error})."))
        }
    };

    if outcome.is_ok()
        && unsafe { GetOverlappedResult(pipe, &overlapped, &mut transferred, 0) } == 0
    {
        let error = unsafe { GetLastError() };
        unsafe { CloseHandle(io_event) };
        return Err(format!("The Agent IPC response write could not be completed (Windows error {error})."));
    }
    unsafe { CloseHandle(io_event) };
    outcome?;
    Ok(transferred as usize)
}

fn read_one_request(pipe: HANDLE, stop_event: HANDLE) -> Result<crate::agent_protocol::AgentRequest, String> {
    let deadline = Instant::now() + FRAME_TIMEOUT;
    let mut header = [0u8; 4];
    read_exact_pipe(pipe, stop_event, &mut header, deadline)?;

    let announced = u32::from_le_bytes(header) as usize;
    if announced == 0 || announced > MAX_AGENT_REQUEST_BYTES {
        return Err("The Agent IPC frame length is invalid.".into());
    }

    let mut payload = Zeroizing::new(vec![0u8; announced]);
    read_exact_pipe(pipe, stop_event, &mut payload, deadline)?;

    crate::agent_protocol::decode_agent_request(&payload)
}

/// Read exactly the requested byte count while draining the bounded pipe buffer.
/// Do not wait for the whole JSON payload to become available before reading:
/// payloads may be much larger than the pipe's kernel buffer.
fn read_exact_pipe(
    pipe: HANDLE,
    stop_event: HANDLE,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), String> {
    let mut total = 0usize;
    while total < buffer.len() {
        if stop_requested(stop_event) {
            return Err("The Agent service is stopping.".into());
        }
        let mut available = 0u32;
        let peeked = unsafe {
            PeekNamedPipe(
                pipe,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if peeked == 0 {
            let error = unsafe { GetLastError() };
            return Err(format!("The Agent pipe client closed or became unavailable (Windows error {error})."));
        }
        if available == 0 {
            if Instant::now() >= deadline {
                return Err("The Agent IPC frame timed out before all announced bytes arrived.".into());
            }
            unsafe { Sleep(10) };
            continue;
        }

        let remaining = buffer.len() - total;
        let chunk = remaining.min(available as usize).min(u32::MAX as usize);
        let read = read_pipe_chunk_overlapped(
            pipe,
            stop_event,
            &mut buffer[total..total + chunk],
            deadline,
        )?;
        if read == 0 {
            return Err("The Agent IPC read returned an empty chunk.".into());
        }
        total = total
            .checked_add(read)
            .ok_or_else(|| "The Agent IPC byte count overflowed.".to_string())?;
    }
    Ok(())
}

fn write_one_response(pipe: HANDLE, stop_event: HANDLE, response: &AgentResponse) -> Result<(), String> {
    let payload = serde_json::to_vec(response)
        .map_err(|_| "The Agent IPC response could not be serialized.".to_string())?;
    if payload.is_empty() || payload.len() > 2048 {
        return Err("The Agent IPC response exceeded its strict response bound.".into());
    }

    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);

    let mut total = 0usize;
    let deadline = Instant::now() + FRAME_TIMEOUT;
    while total < frame.len() {
        let written = write_pipe_chunk_overlapped(
            pipe,
            stop_event,
            &frame[total..],
            deadline,
        )?;
        if written == 0 {
            return Err("The Agent IPC write returned an empty chunk.".into());
        }
        total = total
            .checked_add(written)
            .ok_or_else(|| "The Agent IPC response byte count overflowed.".to_string())?;
    }
    Ok(())
}

fn authenticate_active_console_client(pipe: HANDLE) -> Result<(), String> {
    let active_session = unsafe { WTSGetActiveConsoleSessionId() };
    if active_session == u32::MAX {
        return Err("There is no active physical-console user session.".into());
    }

    let mut pipe_session = u32::MAX;
    if unsafe { GetNamedPipeClientSessionId(pipe, &mut pipe_session) } == 0
        || pipe_session != active_session
    {
        return Err("The Agent pipe client is not in the active console session.".into());
    }

    // WTSQueryUserToken is deliberately used only in the highly trusted
    // LocalSystem service context; failure means no client is authorized.
    let mut active_user_token: HANDLE = std::ptr::null_mut();
    if unsafe { WTSQueryUserToken(active_session, &mut active_user_token) } == 0
        || active_user_token.is_null()
    {
        let error = unsafe { GetLastError() };
        return Err(format!("The active console user's token could not be queried (Windows error {error})."));
    }
    let expected_identity = token_identity(active_user_token);
    unsafe { CloseHandle(active_user_token) };
    let (expected_sid, expected_session) = expected_identity?;
    if expected_session != active_session {
        return Err("The active console token session identity did not match the console session.".into());
    }

    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        let error = unsafe { GetLastError() };
        return Err(format!("The Agent could not impersonate the named-pipe client (Windows error {error})."));
    }

    let mut client_token: HANDLE = std::ptr::null_mut();
    let opened = unsafe {
        OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut client_token)
    };
    let client_identity = if opened != 0 && !client_token.is_null() {
        token_identity(client_token)
    } else {
        let error = unsafe { GetLastError() };
        Err(format!("The Agent could not query the impersonated client token (Windows error {error})."))
    };

    let reverted = unsafe { RevertToSelf() } != 0;
    if !client_token.is_null() {
        unsafe { CloseHandle(client_token) };
    }
    if !reverted {
        // The service thread must not continue executing with a client token.
        return Err(format!("{FATAL_REVERT_ERROR_PREFIX}; the service process must terminate."));
    }

    let (client_sid, client_session) = client_identity?;
    if client_session != active_session || client_sid != expected_sid {
        return Err("The named-pipe client SID or session did not match the active console user.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_name_is_local_and_versioned() {
        assert!(PIPE_NAME.starts_with(r"\\.\pipe\"));
        assert!(PIPE_NAME.ends_with(".v1"));
        assert!(!PIPE_NAME.contains('/'));
    }

    #[test]
    fn response_limit_is_below_the_kernel_pipe_buffer() {
        assert!(2048 < PIPE_BUFFER_BYTES as usize);
    }

    #[test]
    fn frame_timeout_is_finite() {
        assert!(FRAME_TIMEOUT > Duration::ZERO);
        assert!(FRAME_TIMEOUT <= Duration::from_secs(60));
    }
}

fn token_identity(token: HANDLE) -> Result<(Vec<u8>, u32), String> {
    let mut token_buffer = vec![0u8; TOKEN_BUFFER_BYTES];
    let mut returned = 0u32;
    let token_user_ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            token_buffer.as_mut_ptr().cast(),
            token_buffer.len() as u32,
            &mut returned,
        )
    };
    if token_user_ok == 0 || returned as usize > token_buffer.len() {
        let error = unsafe { GetLastError() };
        return Err(format!("A Windows token user SID could not be read (Windows error {error})."));
    }

    if (returned as usize) < std::mem::size_of::<TOKEN_USER>() {
        return Err("The Windows token user SID record was truncated.".into());
    }
    let user = unsafe { &*(token_buffer.as_ptr().cast::<TOKEN_USER>()) };
    let sid_ptr = user.User.Sid;
    if sid_ptr.is_null() {
        return Err("The Windows token did not contain a user SID.".into());
    }

    // TOKEN_USER contains a pointer into the same GetTokenInformation buffer.
    // Validate that pointer against the returned byte count before asking the
    // SID APIs to dereference it.
    let buffer_start = token_buffer.as_ptr() as usize;
    let buffer_end = buffer_start
        .checked_add(returned as usize)
        .ok_or_else(|| "The Windows token information length overflowed.".to_string())?;
    let minimum_sid_address = buffer_start
        .checked_add(std::mem::size_of::<TOKEN_USER>())
        .ok_or_else(|| "The Windows token user record length overflowed.".to_string())?;
    let sid_address = sid_ptr as usize;
    if sid_address < minimum_sid_address
        || sid_address.checked_add(8).is_none_or(|address| address > buffer_end)
    {
        return Err("The Windows token SID pointer is outside the returned token buffer.".into());
    }

    let sid_length = unsafe { GetLengthSid(sid_ptr) } as usize;
    if sid_length == 0
        || sid_length > MAX_SID_BYTES
        || sid_address
            .checked_add(sid_length)
            .is_none_or(|address| address > buffer_end)
    {
        return Err("The Windows token contained an invalid SID length.".into());
    }
    let sid = unsafe { slice::from_raw_parts(sid_ptr.cast::<u8>(), sid_length) }.to_vec();

    let mut session_id = u32::MAX;
    returned = 0;
    let session_ok = unsafe {
        GetTokenInformation(
            token,
            TokenSessionId,
            (&mut session_id as *mut u32).cast(),
            std::mem::size_of::<u32>() as u32,
            &mut returned,
        )
    };
    if session_ok == 0 || returned as usize != std::mem::size_of::<u32>() {
        let error = unsafe { GetLastError() };
        return Err(format!("The Windows token session ID could not be read (Windows error {error})."));
    }
    Ok((sid, session_id))
}
