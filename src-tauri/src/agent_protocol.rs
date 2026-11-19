use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::connection_state::{ConnectionSnapshot, ConnectionPhase};
use crate::profiles::ProfileSummary;

pub const AGENT_PROTOCOL_VERSION: u16 = 1;
pub const MAX_AGENT_REQUEST_BYTES: usize = 128 * 1024;
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
}

impl AgentResponse {
    pub fn ok(request_id: String, connection: Option<ConnectionSnapshot>) -> Self {
        Self {
            version: AGENT_PROTOCOL_VERSION,
            request_id,
            status: AgentResponseStatus::Ok,
            connection,
            detail: None,
        }
    }

    pub fn rejected(request_id: String, detail: impl Into<String>) -> Self {
        Self {
            version: AGENT_PROTOCOL_VERSION,
            request_id,
            status: AgentResponseStatus::Rejected,
            connection: None,
            detail: Some(sanitize_detail(detail.into())),
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
        .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\t'))
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
    fn rejects_protocol_version_mismatch() {
        let mut request = connect_request();
        request.version = AGENT_PROTOCOL_VERSION + 1;
        assert!(validate_agent_request(&request).is_err());
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
