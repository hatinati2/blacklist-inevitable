use std::collections::{BTreeMap, HashSet};
use std::sync::Mutex;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use serde::{Deserialize, Serialize};

use crate::connection_state::ConnectionSnapshot;
use crate::profiles::ProfileSummary;

pub const AGENT_PROTOCOL_VERSION: u16 = 1;
/// One-byte acknowledgement sent only after the client has consumed the full response frame.
pub const AGENT_RESPONSE_ACK_BYTE: u8 = 0x06;
pub const MAX_AGENT_REQUEST_BYTES: usize = 128 * 1024;
pub const AGENT_FRAME_HEADER_BYTES: usize = 4;
pub const MAX_AGENT_REQUESTS_PER_CONNECTION: usize = 4096;
const MAX_REQUEST_ID_BYTES: usize = 64;
const MAX_PROFILE_ID_BYTES: usize = 128;
const MAX_PROFILE_NAME_BYTES: usize = 256;
const MAX_SERVER_NAME_BYTES: usize = 253;
const MAX_PROFILE_OPTIONS: usize = 64;
const MAX_OPTION_KEY_BYTES: usize = 64;
const MAX_OPTION_VALUE_BYTES: usize = 4096;
const MAX_CREDENTIALS: usize = 4;
const MAX_CREDENTIAL_KEY_BYTES: usize = 32;
const MAX_CREDENTIAL_VALUE_BYTES: usize = 8192;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AgentRecoveryState {
    Clear,
    VerifiedCleanRetained,
    Blocked,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRecoveryDispositionCounts {
    pub verified_clean: u32,
    pub needs_cleanup: u32,
    pub needs_restore: u32,
    pub conflict: u32,
    pub unknown: u32,
}

impl AgentRecoveryDispositionCounts {
    pub fn compact(&self) -> String {
        format!(
            "clean:{},cleanup:{},restore:{},conflict:{},unknown:{}",
            self.verified_clean, self.needs_cleanup, self.needs_restore,
            self.conflict, self.unknown
        )
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRecoverySessionStatus {
    pub session_id: u64,
    pub revision: u64,
    pub phase: String,
    pub engine: crate::recovery_assessment::ResourceDisposition,
    pub tunnel: crate::recovery_assessment::ResourceDisposition,
    pub routes: AgentRecoveryDispositionCounts,
    pub dns: AgentRecoveryDispositionCounts,
    pub firewall_filters: crate::recovery_assessment::ResourceDisposition,
    pub verified_clean: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRecoveryStatus {
    pub state: AgentRecoveryState,
    pub journal_inventory_complete: bool,
    pub total_sessions: u32,
    pub verified_clean_sessions: u32,
    pub blocked_sessions: u32,
    pub omitted_sessions: u32,
    pub journal_retained: bool,
    pub sessions: Vec<AgentRecoverySessionStatus>,
    pub diagnostics: Vec<String>,
}

impl AgentRecoveryStatus {
    pub fn is_blocked(&self) -> bool {
        // A journal is not considered reconciled merely because the current
        // read-only snapshot looks clean. Until a separate reviewed cleanup
        // protocol disposes of retained journals, startup remains blocked.
        !matches!(self.state, AgentRecoveryState::Clear)
    }

    pub fn detail_summary(&self) -> String {
        let state = match self.state {
            AgentRecoveryState::Clear => "clear",
            AgentRecoveryState::VerifiedCleanRetained => "verified-clean-journal-retained",
            AgentRecoveryState::Blocked => "blocked",
        };
        let headline = match self.state {
            AgentRecoveryState::Clear => "Agent startup recovery is clean.".to_string(),
            AgentRecoveryState::VerifiedCleanRetained => {
                "Agent startup recovery is blocked pending journal disposition: unresolved recovery journals are verified clean but retained.".to_string()
            }
            AgentRecoveryState::Blocked if self.total_sessions > 0 => format!(
                "Agent startup recovery is blocked: {} unresolved recovery journal(s) require review.",
                self.total_sessions
            ),
            AgentRecoveryState::Blocked => {
                "Agent startup recovery is blocked: the unresolved recovery journal inventory is unavailable.".to_string()
            }
        };
        format!(
            "{headline} Read-only assessment: state={state}; sessions={}; verifiedClean={}; blocked={}; inventoryComplete={}; journalRetained={}. No cleanup, rollback, or journal deletion was performed; VPN operations remain disabled.",
            self.total_sessions, self.verified_clean_sessions, self.blocked_sessions,
            self.journal_inventory_complete, self.journal_retained
        )
    }
}

/// A strict, secret-free profile representation supplied by the unelevated UI.
/// The agent re-validates this data and never accepts an arbitrary engine JSON,
/// executable path, working directory, or shell command from the IPC client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentProfile {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub server: String,
    pub port: u16,
    pub options: BTreeMap<String, String>,
    #[serde(default)]
    pub unsupported_options: Vec<String>,
}

impl From<AgentProfile> for ProfileSummary {
    fn from(profile: AgentProfile) -> Self {
        Self {
            id: profile.id,
            name: profile.name,
            protocol: profile.protocol,
            server: profile.server,
            port: profile.port,
            options: profile.options,
            unsupported_options: profile.unsupported_options,
        }
    }
}

/// The credential map is only accepted on a single Connect request. The
/// service must use it in memory to build its per-session engine config and
/// must never log, persist, or echo this object.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentConnectPayload {
    pub profile: AgentProfile,
    pub credentials: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub enum AgentOperation {
    GetStatus,
    GetDiagnostics,
    Connect {
        payload: AgentConnectPayload,
    },
    Disconnect {
        session_id: u64,
    },
    Recover,
}

/// Versioned JSON request carried over an authenticated local IPC channel.
/// Do not derive Debug: Connect requests contain credentials.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentRequest {
    pub version: u16,
    pub request_id: String,
    pub operation: AgentOperation,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AgentResponseStatus {
    Ok,
    Rejected,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentResponse {
    pub version: u16,
    pub request_id: String,
    pub status: AgentResponseStatus,
    pub connection: Option<ConnectionSnapshot>,
    /// Sanitized text only. Never include raw engine config, credentials, file
    /// paths containing secret material, or unfiltered child-process output.
    pub detail: Option<String>,
    /// Bounded, secret-free read-only assessment. Never authorizes mutation by itself.
    pub recovery: Option<AgentRecoveryStatus>,
}

impl AgentResponse {
    pub fn ok(request_id: String, connection: Option<ConnectionSnapshot>) -> Self {
        Self {
            version: AGENT_PROTOCOL_VERSION,
            request_id,
            status: AgentResponseStatus::Ok,
            connection,
            detail: None,
            recovery: None,
        }
    }

    pub fn rejected(request_id: String, detail: impl Into<String>) -> Self {
        Self {
            version: AGENT_PROTOCOL_VERSION,
            request_id,
            status: AgentResponseStatus::Rejected,
            connection: None,
            detail: Some(sanitize_detail(detail.into(), &BTreeMap::new())),
            recovery: None,
        }
    }

    pub fn failed_redacted(
        request_id: String,
        connection: Option<ConnectionSnapshot>,
        detail: impl Into<String>,
        credentials: &BTreeMap<String, String>,
    ) -> Self {
        Self {
            version: AGENT_PROTOCOL_VERSION,
            request_id,
            status: AgentResponseStatus::Failed,
            connection,
            detail: Some(sanitize_detail(detail.into(), credentials)),
            recovery: None,
        }
    }
}

pub fn decode_agent_request(bytes: &[u8]) -> Result<AgentRequest, String> {
    if bytes.is_empty() || bytes.len() > MAX_AGENT_REQUEST_BYTES {
        return Err("The agent request is empty or exceeds the maximum message size.".to_string());
    }

    let request: AgentRequest = serde_json::from_slice(bytes)
        .map_err(|_| "The agent request is not valid protocol JSON.".to_string())?;
    validate_agent_request(&request)?;
    Ok(request)
}

/// Encode exactly one message for a byte-stream transport such as a Windows
/// named pipe. The four-byte little-endian prefix is the JSON payload length.
pub fn encode_agent_frame(request: &AgentRequest) -> Result<Vec<u8>, String> {
    validate_agent_request(request)?;
    let payload = serde_json::to_vec(request)
        .map_err(|_| "The agent request could not be serialized.".to_string())?;
    if payload.is_empty() || payload.len() > MAX_AGENT_REQUEST_BYTES {
        return Err("The agent request is empty or exceeds the maximum message size.".to_string());
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| "The agent request exceeds the framing limit.".to_string())?;
    let mut frame = Vec::with_capacity(AGENT_FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decode one complete frame. A transport must first read exactly the four-byte
/// header, validate the announced length, then read exactly that payload. This
/// helper rejects truncated frames, concatenated frames, and trailing bytes.
pub fn decode_agent_frame(frame: &[u8]) -> Result<AgentRequest, String> {
    if frame.len() < AGENT_FRAME_HEADER_BYTES {
        return Err("The agent frame header is incomplete.".to_string());
    }
    let announced = u32::from_le_bytes(
        frame[..AGENT_FRAME_HEADER_BYTES]
            .try_into()
            .map_err(|_| "The agent frame header is invalid.".to_string())?,
    ) as usize;
    if announced == 0 || announced > MAX_AGENT_REQUEST_BYTES {
        return Err("The agent frame length is empty or exceeds the maximum message size.".to_string());
    }
    let expected = AGENT_FRAME_HEADER_BYTES
        .checked_add(announced)
        .ok_or_else(|| "The agent frame length is invalid.".to_string())?;
    if frame.len() != expected {
        return Err("The agent frame is truncated or contains trailing data.".to_string());
    }
    decode_agent_request(&frame[AGENT_FRAME_HEADER_BYTES..])
}

/// Read exactly one framed request from a byte stream. The announced payload
/// length is checked before allocating memory; the next frame remains unread.
pub async fn read_agent_message<R>(reader: &mut R) -> Result<AgentRequest, String>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; AGENT_FRAME_HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|_| "The agent IPC connection closed before a complete frame header arrived.".to_string())?;

    let announced = u32::from_le_bytes(header) as usize;
    if announced == 0 || announced > MAX_AGENT_REQUEST_BYTES {
        return Err("The agent frame length is empty or exceeds the maximum message size.".to_string());
    }

    let mut payload = vec![0u8; announced];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|_| "The agent IPC connection closed before the complete frame arrived.".to_string())?;
    decode_agent_request(&payload)
}

/// Write one complete framed request and flush it before returning.
pub async fn write_agent_message<W>(writer: &mut W, request: &AgentRequest) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    let frame = encode_agent_frame(request)?;
    writer
        .write_all(&frame)
        .await
        .map_err(|_| "The agent IPC request could not be written.".to_string())?;
    writer
        .flush()
        .await
        .map_err(|_| "The agent IPC request could not be flushed.".to_string())
}

/// Tracks request IDs for one authenticated IPC connection. The listener must
/// create a fresh guard only after authenticating the pipe peer and retain it
/// until that connection closes. Once the bounded request budget is exhausted,
/// the connection must be closed rather than evicting IDs and weakening replay
/// detection. This is not a substitute for Windows pipe ACLs or peer-token checks.
#[derive(Default)]
pub struct AgentRequestReplayGuard {
    request_ids: Mutex<HashSet<String>>,
}

impl AgentRequestReplayGuard {
    pub fn accept(&self, request: &AgentRequest) -> Result<(), String> {
        validate_agent_request(request)?;
        let mut request_ids = self
            .request_ids
            .lock()
            .map_err(|_| "The agent replay guard is unavailable; the connection must close.".to_string())?;

        if request_ids.contains(&request.request_id) {
            return Err("The agent request identifier was already used on this connection.".to_string());
        }
        if request_ids.len() >= MAX_AGENT_REQUESTS_PER_CONNECTION {
            return Err("The agent connection reached its request limit and must be closed.".to_string());
        }
        request_ids.insert(request.request_id.clone());
        Ok(())
    }

    pub fn accepted_count(&self) -> Result<usize, String> {
        self.request_ids
            .lock()
            .map(|request_ids| request_ids.len())
            .map_err(|_| "The agent replay guard is unavailable.".to_string())
    }
}

pub fn validate_agent_request(request: &AgentRequest) -> Result<(), String> {
    if request.version != AGENT_PROTOCOL_VERSION {
        return Err("The agent IPC protocol version is not supported.".to_string());
    }
    validate_request_id(&request.request_id)?;

    if let AgentOperation::Connect { payload } = &request.operation {
        validate_profile(&payload.profile)?;
        validate_credentials(&payload.profile.protocol, &payload.credentials)?;
    }

    if let AgentOperation::Disconnect { session_id } = &request.operation {
        if *session_id == 0 {
            return Err("A valid connection session identifier is required.".to_string());
        }
    }

    Ok(())
}

fn validate_request_id(request_id: &str) -> Result<(), String> {
    if request_id.is_empty()
        || request_id.len() > MAX_REQUEST_ID_BYTES
        || !request_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err("The agent request identifier is invalid.".to_string());
    }
    Ok(())
}

fn is_valid_server_host(value: &str) -> bool {
    if value.trim() != value || value.is_empty() || value.len() > MAX_SERVER_NAME_BYTES {
        return false;
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }

    let hostname = value.strip_suffix('.').unwrap_or(value);
    !hostname.is_empty()
        && hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && label.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn validate_profile(profile: &AgentProfile) -> Result<(), String> {
    if profile.id.is_empty() || profile.id.len() > MAX_PROFILE_ID_BYTES {
        return Err("The profile identifier is invalid.".to_string());
    }
    if profile.name.trim().is_empty() || profile.name.len() > MAX_PROFILE_NAME_BYTES {
        return Err("The profile name is invalid.".to_string());
    }
    if !is_valid_server_host(&profile.server) {
        return Err("The proxy server address is invalid.".to_string());
    }
    if profile.port == 0 {
        return Err("The proxy server port is invalid.".to_string());
    }
    if !matches!(
        profile.protocol.as_str(),
        "vless" | "vmess" | "trojan" | "shadowsocks" | "hysteria2" | "tuic" | "naive"
    ) {
        return Err("The selected profile protocol is not enabled for the Windows engine.".to_string());
    }
    if !profile.unsupported_options.is_empty() {
        return Err("The selected profile contains options that are not mapped by the Windows engine.".to_string());
    }
    if profile.options.len() > MAX_PROFILE_OPTIONS {
        return Err("The profile contains too many engine options.".to_string());
    }
    for (key, value) in &profile.options {
        if key.is_empty()
            || key.len() > MAX_OPTION_KEY_BYTES
            || value.len() > MAX_OPTION_VALUE_BYTES
        {
            return Err("The profile contains an oversized engine option.".to_string());
        }
    }
    Ok(())
}

fn validate_credentials(
    protocol: &str,
    credentials: &BTreeMap<String, String>,
) -> Result<(), String> {
    if credentials.len() > MAX_CREDENTIALS {
        return Err("The profile contains too many credential fields.".to_string());
    }
    for (key, value) in credentials {
        if key.len() > MAX_CREDENTIAL_KEY_BYTES
            || value.is_empty()
            || value.len() > MAX_CREDENTIAL_VALUE_BYTES
        {
            return Err("A profile credential is empty or exceeds the size limit.".to_string());
        }
    }

    let permitted: &[&str] = match protocol {
        "vless" | "vmess" => &["uuid"],
        "trojan" | "shadowsocks" => &["password"],
        "hysteria2" => &["password", "obfsPassword"],
        "tuic" => &["uuid", "password"],
        "naive" => &["username", "password"],
        _ => return Err("The selected profile protocol is not supported.".to_string()),
    };

    if credentials.keys().any(|key| !permitted.contains(&key.as_str())) {
        return Err("The credential map contains a field not used by this protocol.".to_string());
    }

    let required: &[&str] = match protocol {
        "vless" | "vmess" => &["uuid"],
        "trojan" | "shadowsocks" | "hysteria2" | "naive" => &["password"],
        "tuic" => &["uuid", "password"],
        _ => return Err("The selected profile protocol is not supported.".to_string()),
    };
    if required.iter().any(|key| !credentials.contains_key(*key)) {
        return Err("A required credential is missing for the selected profile.".to_string());
    }
    Ok(())
}

fn sanitize_detail(
    mut detail: String,
    credentials: &BTreeMap<String, String>,
) -> String {
    for secret in credentials.values().filter(|value| !value.is_empty()) {
        detail = detail.replace(secret, "[redacted]");
    }
    detail
        .chars()
        .filter(|ch| !ch.is_control() || matches!(*ch, '\n' | '\t'))
        .take(1200)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect_request() -> AgentRequest {
        AgentRequest {
            version: AGENT_PROTOCOL_VERSION,
            request_id: "request-01".to_string(),
            operation: AgentOperation::Connect {
                payload: AgentConnectPayload {
                    profile: AgentProfile {
                        id: "profile-1".to_string(),
                        name: "Test Trojan".to_string(),
                        protocol: "trojan".to_string(),
                        server: "proxy.example.org".to_string(),
                        port: 443,
                        options: BTreeMap::from([(
                            "sni".to_string(),
                            "proxy.example.org".to_string(),
                        )]),
                        unsupported_options: Vec::new(),
                    },
                    credentials: BTreeMap::from([(
                        "password".to_string(),
                        "one-shot-secret".to_string(),
                    )]),
                },
            },
        }
    }

    #[test]
    fn status_request_uses_the_nested_operation_tag_on_the_wire() {
        let request = AgentRequest {
            version: AGENT_PROTOCOL_VERSION,
            request_id: "status-1".to_string(),
            operation: AgentOperation::GetStatus,
        };
        let encoded = serde_json::to_value(&request).unwrap();
        assert_eq!(
            encoded,
            serde_json::json!({
                "version": 1,
                "requestId": "status-1",
                "operation": {
                    "operation": "getStatus"
                }
            })
        );

        let decoded = decode_agent_request(&serde_json::to_vec(&encoded).unwrap()).unwrap();
        assert!(matches!(decoded.operation, AgentOperation::GetStatus));

        let old_flat_shape =
            br#"{"version":1,"requestId":"status-1","operation":"getStatus"}"#;
        assert!(decode_agent_request(old_flat_shape).is_err());
    }

    #[test]
    fn decodes_a_valid_connect_request_without_putting_secrets_in_profile_metadata() {
        let bytes = serde_json::to_vec(&connect_request()).unwrap();
        let request = decode_agent_request(&bytes).unwrap();

        let AgentOperation::Connect { payload } = request.operation else {
            panic!("expected Connect operation");
        };
        assert_eq!(payload.profile.protocol, "trojan");
        assert_eq!(payload.credentials.get("password").map(String::as_str), Some("one-shot-secret"));

        let public_profile = serde_json::to_string(&ProfileSummary::from(payload.profile)).unwrap();
        assert!(!public_profile.contains("one-shot-secret"));
    }

    #[test]
    fn validates_ipv4_ipv6_and_dns_server_hostnames() {
        assert!(is_valid_server_host("203.0.113.10"));
        assert!(is_valid_server_host("2001:db8::1"));
        assert!(is_valid_server_host("proxy.example.org"));
        assert!(is_valid_server_host("proxy.example.org."));
        assert!(!is_valid_server_host("https://proxy.example.org"));
        assert!(!is_valid_server_host("proxy..example.org"));
        assert!(!is_valid_server_host("-proxy.example.org"));
        assert!(!is_valid_server_host("proxy.example.org:443"));
    }

    #[test]
    fn rejects_unsupported_protocol_and_unmapped_options() {
        let mut request = connect_request();
        if let AgentOperation::Connect { payload } = &mut request.operation {
            payload.profile.protocol = "mieru".to_string();
        }
        assert!(validate_agent_request(&request).is_err());

        let mut request = connect_request();
        if let AgentOperation::Connect { payload } = &mut request.operation {
            payload.profile.unsupported_options.push("custom_transport".to_string());
        }
        assert!(validate_agent_request(&request).is_err());
    }

    #[test]
    fn rejects_credentials_not_allowed_for_the_selected_protocol() {
        let mut request = connect_request();
        if let AgentOperation::Connect { payload } = &mut request.operation {
            payload.credentials.insert("uuid".to_string(), "unexpected".to_string());
        }
        assert!(validate_agent_request(&request).is_err());
    }

    #[test]
    fn rejects_missing_and_oversized_credentials() {
        let mut request = connect_request();
        if let AgentOperation::Connect { payload } = &mut request.operation {
            payload.credentials.clear();
        }
        assert!(validate_agent_request(&request).is_err());

        let mut request = connect_request();
        if let AgentOperation::Connect { payload } = &mut request.operation {
            payload.credentials.insert("password".to_string(), "x".repeat(MAX_CREDENTIAL_VALUE_BYTES + 1));
        }
        assert!(validate_agent_request(&request).is_err());
    }

    #[test]
    fn rejects_unknown_operation_fields_and_oversized_frames() {
        let unknown = br#"{"version":1,"requestId":"a","operation":"disconnect","sessionId":1,"command":"powershell"}"#;
        assert!(decode_agent_request(unknown).is_err());

        let oversized = vec![b'a'; MAX_AGENT_REQUEST_BYTES + 1];
        assert!(decode_agent_request(&oversized).is_err());
    }

    #[test]
    fn rejects_stale_or_invalid_session_ids_and_request_ids() {
        let mut request = AgentRequest {
            version: AGENT_PROTOCOL_VERSION,
            request_id: "bad request id".to_string(),
            operation: AgentOperation::GetStatus,
        };
        assert!(validate_agent_request(&request).is_err());

        request.request_id = "valid-id".to_string();
        request.operation = AgentOperation::Disconnect { session_id: 0 };
        assert!(validate_agent_request(&request).is_err());
    }

    #[test]
    fn frames_round_trip_and_reject_truncation_or_trailing_bytes() {
        let request = connect_request();
        let frame = encode_agent_frame(&request).unwrap();
        assert_eq!(
            u32::from_le_bytes(frame[..AGENT_FRAME_HEADER_BYTES].try_into().unwrap()) as usize,
            frame.len() - AGENT_FRAME_HEADER_BYTES
        );
        let decoded = decode_agent_frame(&frame).unwrap();
        assert_eq!(decoded.request_id, request.request_id);

        assert!(decode_agent_frame(&frame[..3]).is_err());
        assert!(decode_agent_frame(&frame[..frame.len() - 1]).is_err());

        let mut trailing = frame.clone();
        trailing.push(0);
        assert!(decode_agent_frame(&trailing).is_err());

        let mut zero_length = vec![0; AGENT_FRAME_HEADER_BYTES];
        assert!(decode_agent_frame(&zero_length).is_err());

        zero_length.copy_from_slice(&((MAX_AGENT_REQUEST_BYTES as u32) + 1).to_le_bytes());
        assert!(decode_agent_frame(&zero_length).is_err());
    }

    #[tokio::test]
    async fn async_stream_helpers_read_and_write_one_complete_message() {
        let request = connect_request();
        let (mut writer, mut reader) = tokio::io::duplex(4096);

        let expected_id = request.request_id.clone();
        let write = tokio::spawn(async move {
            write_agent_message(&mut writer, &request).await.unwrap();
        });
        let decoded = read_agent_message(&mut reader).await.unwrap();
        write.await.unwrap();

        assert_eq!(decoded.request_id, expected_id);
    }

    #[tokio::test]
    async fn async_reader_rejects_oversized_length_before_allocating_payload() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer
            .write_all(&((MAX_AGENT_REQUEST_BYTES as u32) + 1).to_le_bytes())
            .await
            .unwrap();

        let error = match read_agent_message(&mut reader).await {
            Err(error) => error,
            Ok(_) => panic!("an oversized frame must be rejected"),
        };
        assert!(error.contains("maximum message size"));
    }

    #[test]
    fn replay_guard_rejects_duplicate_ids_and_counts_accepted_requests() {
        let guard = AgentRequestReplayGuard::default();
        let request = connect_request();
        assert_eq!(guard.accepted_count().unwrap(), 0);
        guard.accept(&request).unwrap();
        assert_eq!(guard.accepted_count().unwrap(), 1);
        assert!(guard.accept(&request).unwrap_err().contains("already used"));

        let mut another = connect_request();
        another.request_id = "request-02".to_string();
        guard.accept(&another).unwrap();
        assert_eq!(guard.accepted_count().unwrap(), 2);
    }

    #[test]
    fn replay_guard_fails_closed_after_connection_budget() {
        let guard = AgentRequestReplayGuard::default();
        for index in 0..MAX_AGENT_REQUESTS_PER_CONNECTION {
            let mut request = connect_request();
            request.request_id = format!("req-{index}");
            guard.accept(&request).unwrap();
        }
        let mut over_budget = connect_request();
        over_budget.request_id = "final-request".to_string();
        assert!(guard.accept(&over_budget).unwrap_err().contains("request limit"));
        assert_eq!(guard.accepted_count().unwrap(), MAX_AGENT_REQUESTS_PER_CONNECTION);
    }

    #[test]
    fn rejects_protocol_version_mismatch() {
        let mut request = connect_request();
        request.version = AGENT_PROTOCOL_VERSION + 1;
        assert!(validate_agent_request(&request).is_err());
    }

    #[test]
    fn verified_clean_but_retained_journals_still_block_startup_status() {
        let status = AgentRecoveryStatus {
            state: AgentRecoveryState::VerifiedCleanRetained,
            journal_inventory_complete: true,
            total_sessions: 1,
            verified_clean_sessions: 1,
            blocked_sessions: 0,
            omitted_sessions: 0,
            journal_retained: true,
            sessions: Vec::new(),
            diagnostics: Vec::new(),
        };
        assert!(status.is_blocked());
        let detail = status.detail_summary();
        assert!(detail.contains("startup recovery"));
        assert!(detail.contains("unresolved recovery journal"));
        assert!(detail.contains("verified clean but retained"));
    }

    #[test]
    fn blocked_recovery_summary_preserves_installer_diagnostic_contract() {
        let status = AgentRecoveryStatus {
            state: AgentRecoveryState::Blocked,
            journal_inventory_complete: true,
            total_sessions: 1,
            verified_clean_sessions: 0,
            blocked_sessions: 1,
            omitted_sessions: 0,
            journal_retained: true,
            sessions: Vec::new(),
            diagnostics: Vec::new(),
        };
        let detail = status.detail_summary();
        assert!(detail.contains("startup recovery"));
        assert!(detail.contains("unresolved recovery journal"));
        assert!(detail.contains("No cleanup, rollback, or journal deletion was performed"));
    }

    #[test]
    fn structured_recovery_status_fits_the_bounded_agent_response_frame() {
        let counts = AgentRecoveryDispositionCounts {
            verified_clean: u32::MAX,
            needs_cleanup: u32::MAX,
            needs_restore: u32::MAX,
            conflict: u32::MAX,
            unknown: u32::MAX,
        };
        let session = AgentRecoverySessionStatus {
            session_id: u64::MAX,
            revision: u64::MAX,
            phase: "RecoveryRequired".to_string(),
            engine: crate::recovery_assessment::ResourceDisposition::Unknown,
            tunnel: crate::recovery_assessment::ResourceDisposition::Conflict,
            routes: counts.clone(),
            dns: counts,
            firewall_filters: crate::recovery_assessment::ResourceDisposition::Unknown,
            verified_clean: false,
        };
        let recovery = AgentRecoveryStatus {
            state: AgentRecoveryState::Blocked,
            journal_inventory_complete: false,
            total_sessions: u32::MAX,
            verified_clean_sessions: u32::MAX,
            blocked_sessions: u32::MAX,
            omitted_sessions: u32::MAX,
            journal_retained: true,
            sessions: vec![session.clone(), session],
            diagnostics: vec!["x".repeat(120), "y".repeat(120)],
        };
        let mut response = AgentResponse::rejected(
            "recovery-01".to_string(),
            recovery.detail_summary(),
        );
        response.recovery = Some(recovery);
        let encoded = serde_json::to_vec(&response).unwrap();
        assert!(encoded.len() <= 2048, "response frame was {} bytes", encoded.len());

        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(value["recovery"]["state"], "blocked");
        assert_eq!(value["recovery"]["sessions"][0]["routes"]["unknown"], u32::MAX);
    }

    #[test]
    fn agent_response_does_not_include_credentials() {
        let credentials =
            BTreeMap::from([("password".to_string(), "sensitive-passphrase".to_string())]);
        let response = AgentResponse::failed_redacted(
            "request-01".to_string(),
            None,
            "The proxy engine failed to start; secret=sensitive-passphrase".to_string(),
            &credentials,
        );
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(!encoded.contains("password"));
        assert!(encoded.contains("proxy engine failed"));
        assert!(!encoded.contains("sensitive-passphrase"));
        assert!(encoded.contains("[redacted]"));
    }
}
