//! Read-only desktop client for the privileged Windows Agent status endpoint.
//!
//! This module deliberately sends no profile data or credentials. Mutating
//! operations remain disabled in the service until server identity validation,
//! credential handoff, and the connection/recovery runtime are implemented.

use serde::Deserialize;

use crate::agent_protocol::{
    write_agent_message, AgentOperation, AgentRequest, AGENT_PROTOCOL_VERSION,
    MAX_AGENT_REQUEST_BYTES,
};

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

    use tokio::io::AsyncReadExt;
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
        decode_agent_response(&payload, &request_id)
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
