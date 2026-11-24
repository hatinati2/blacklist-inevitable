use std::collections::BTreeMap;

use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroize;

const MAX_IMPORT_BYTES: usize = 2 * 1024 * 1024;
const MAX_IMPORT_LINES: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSummary {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub server: String,
    pub port: u16,
    pub options: BTreeMap<String, String>,
    #[serde(default)]
    pub unsupported_options: Vec<String>,
}

pub struct ParsedProfile {
    pub profile: ProfileSummary,
    pub credentials: BTreeMap<String, String>,
}

impl Drop for ParsedProfile {
    fn drop(&mut self) {
        zeroize_credentials(&mut self.credentials);
    }
}

fn zeroize_credentials(credentials: &mut BTreeMap<String, String>) {
    for secret in credentials.values_mut() {
        secret.zeroize();
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportIssue {
    pub line: usize,
    pub reason: String,
}

pub struct ParsedImport {
    pub profiles: Vec<ParsedProfile>,
    pub rejected: Vec<ImportIssue>,
}

pub fn parse_import_text(input: &str) -> Result<ParsedImport, String> {
    if input.len() > MAX_IMPORT_BYTES {
        return Err("Import text is larger than 2 MiB.".to_string());
    }

    let mut profiles = Vec::new();
    let mut rejected = Vec::new();
    let mut non_empty_lines = 0usize;

    for (index, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        non_empty_lines += 1;
        if non_empty_lines > MAX_IMPORT_LINES {
            return Err("An import can contain at most 500 entries.".to_string());
        }

        match parse_share_uri(line) {
            Ok(profile) => profiles.push(profile),
            Err(reason) => rejected.push(ImportIssue {
                line: index + 1,
                reason,
            }),
        }
    }

    if non_empty_lines == 0 {
        return Err("Paste one or more supported share links first.".to_string());
    }

    Ok(ParsedImport { profiles, rejected })
}

fn parse_share_uri(input: &str) -> Result<ParsedProfile, String> {
    if input.starts_with("naive+https://") || input.starts_with("naive+quic://") {
        return parse_naive(input);
    }

    if input.starts_with("vmess://") {
        return parse_vmess(input);
    }

    let mut url = Url::parse(input).map_err(|_| "Malformed share link.".to_string())?;
    let scheme = url.scheme().to_ascii_lowercase();

    if scheme == "ss" && (url.host_str().is_none() || url.port().is_none()) {
        let payload = input
            .strip_prefix("ss://")
            .unwrap_or(input)
            .split(['?', '#'])
            .next()
            .unwrap_or_default();
        let decoded = decode_base64(payload)
            .and_then(|bytes| String::from_utf8(bytes).map_err(|_| "Invalid Shadowsocks link.".to_string()))?;
        url = Url::parse(&format!("ss://{decoded}"))
            .map_err(|_| "Malformed legacy Shadowsocks link.".to_string())?;
    }

    let protocol = match scheme.as_str() {
        "vless" => "vless",
        "trojan" => "trojan",
        "ss" => "shadowsocks",
        "hysteria2" | "hy2" => "hysteria2",
        "tuic" => "tuic",
        _ => return Err("Unsupported link scheme.".to_string()),
    };

    if url.query_pairs().any(|(key, _)| key == "plugin") {
        return Err("Shadowsocks plugin links are not supported yet.".to_string());
    }

    let server = url
        .host_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "The link has no server hostname.".to_string())?
        .to_string();
    let port = url
        .port()
        .filter(|port| *port > 0)
        .ok_or_else(|| "The link must include an explicit non-zero port.".to_string())?;

    let mut options = BTreeMap::new();
    copy_query_options(&url, &mut options);
    let unsupported_options = collect_unsupported_query_options(&url);

    let mut credentials = BTreeMap::new();
    match protocol {
        "vless" => {
            let user_id = decode_component(url.username());
            if user_id.is_empty() {
                return Err("The VLESS link has no user ID.".to_string());
            }
            credentials.insert("uuid".to_string(), user_id);
        }
        "trojan" => {
            let secret = if let Some(password) = url.password() {
                decode_component(password)
            } else {
                decode_component(url.username())
            };
            if secret.is_empty() {
                return Err("The Trojan link has no password.".to_string());
            }
            credentials.insert("password".to_string(), secret);
        }
        "shadowsocks" => {
            let user_info = decode_component(url.username());
            let (method, password) = if let Some(password) = url.password() {
                // SIP002 user-info is sometimes provided in its plain method:password
                // form. Prefer the explicit URL password before trying Base64 because
                // common cipher names can also be valid Base64URL characters.
                (user_info, decode_component(password))
            } else if let Some(decoded) = try_decode_base64(&user_info) {
                let decoded = String::from_utf8(decoded)
                    .map_err(|_| "Invalid Shadowsocks credentials.".to_string())?;
                split_method_password(&decoded)?
            } else {
                split_method_password(&user_info)?
            };
            if method.is_empty() || password.is_empty() {
                return Err("The Shadowsocks link is missing its method or password.".to_string());
            }
            options.insert("method".to_string(), method);
            credentials.insert("password".to_string(), password);
        }
        "hysteria2" => {
            let secret = if let Some(password) = url.password() {
                decode_component(password)
            } else {
                decode_component(url.username())
            };
            if secret.is_empty() {
                return Err("The Hysteria2 link has no password.".to_string());
            }
            credentials.insert("password".to_string(), secret);
        }
        "tuic" => {
            let uuid = decode_component(url.username());
            let password = url.password().map(decode_component).unwrap_or_default();
            if uuid.is_empty() || password.is_empty() {
                return Err("The TUIC link must include both UUID and password.".to_string());
            }
            credentials.insert("uuid".to_string(), uuid);
            credentials.insert("password".to_string(), password);
        }
        _ => return Err("Unsupported link scheme.".to_string()),
    }

    if protocol_is_hysteria2(&scheme) {
        if let Some((_, value)) = url.query_pairs().find(|(key, _)| key == "obfs-password") {
            if !value.is_empty() {
                credentials.insert("obfsPassword".to_string(), value.to_string());
            }
        }
    }

    let name = url
        .fragment()
        .map(decode_component)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("{protocol} · {server}:{port}"));

    Ok(ParsedProfile {
        profile: ProfileSummary {
            id: Uuid::new_v4().to_string(),
            name,
            protocol: protocol.to_string(),
            server,
            port,
            options,
            unsupported_options,
        },
        credentials,
    })
}

fn parse_vmess(input: &str) -> Result<ParsedProfile, String> {
    let encoded = input
        .strip_prefix("vmess://")
        .ok_or_else(|| "Malformed VMess link.".to_string())?
        .trim();
    let decoded = decode_base64(encoded)?;
    let value: Value = serde_json::from_slice(&decoded)
        .map_err(|_| "The VMess payload is not valid JSON.".to_string())?;

    let server = json_string(&value, "add")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "The VMess link has no server hostname.".to_string())?;
    let port = json_string(&value, "port")
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port > 0)
        .ok_or_else(|| "The VMess link has no valid port.".to_string())?;
    let uuid = json_string(&value, "id")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "The VMess link has no user ID.".to_string())?;

    let mut options = BTreeMap::new();
    let unsupported_options = collect_unsupported_vmess_fields(&value);
    for (source, target) in [
        ("net", "transport"),
        ("type", "headerType"),
        ("host", "host"),
        ("path", "path"),
        ("tls", "tls"),
        ("sni", "sni"),
        ("scy", "security"),
        ("aid", "alterId"),
        ("fp", "fingerprint"),
        ("alpn", "alpn"),
    ] {
        if let Some(value) = json_string(&value, source).filter(|value| !value.is_empty()) {
            options.insert(target.to_string(), value);
        }
    }

    let name = json_string(&value, "ps")
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("vmess · {server}:{port}"));

    let mut credentials = BTreeMap::new();
    credentials.insert("uuid".to_string(), uuid);

    Ok(ParsedProfile {
        profile: ProfileSummary {
            id: Uuid::new_v4().to_string(),
            name,
            protocol: "vmess".to_string(),
            server,
            port,
            options,
            unsupported_options,
        },
        credentials,
    })
}

fn parse_naive(input: &str) -> Result<ParsedProfile, String> {
    let url = Url::parse(input).map_err(|_| "Malformed Naive share link.".to_string())?;
    let quic = match url.scheme() {
        "naive+https" => false,
        "naive+quic" => true,
        _ => return Err("Unsupported Naive transport.".to_string()),
    };

    let server = url
        .host_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "The Naive link has no server hostname.".to_string())?
        .to_string();
    let port = match url.port() {
        Some(0) => return Err("The Naive link must not use port zero.".to_string()),
        Some(port) => port,
        None => 443,
    };
    if !url.path().is_empty() && url.path() != "/" {
        return Err("Naive share links do not support a URL path.".to_string());
    }

    // Split userinfo before percent-decoding. A colon may be part of a password
    // or username and must not be mistaken for the username/password separator.
    let (username, password) = match url.password() {
        Some(password) => (decode_component(url.username()), decode_component(password)),
        None => (String::new(), decode_component(url.username())),
    };
    if password.is_empty() {
        return Err("The Naive link has no password.".to_string());
    }

    let mut options = BTreeMap::new();
    if quic {
        options.insert("quic".to_string(), "true".to_string());
    }
    let mut unsupported_options = Vec::new();

    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "sni" if !value.is_empty() => {
                options.insert("sni".to_string(), value.to_string());
            }
            "sni" => {}
            "insecure-concurrency" => {
                let concurrency = value.parse::<u32>().map_err(|_| {
                    "Naive insecure-concurrency must be a non-negative integer.".to_string()
                })?;
                if concurrency > 32 {
                    return Err("Naive insecure-concurrency must not exceed 32.".to_string());
                }
                if concurrency > 0 {
                    options.insert("insecureConcurrency".to_string(), concurrency.to_string());
                }
            }
            // v2rayN includes these neutral transport defaults when exporting
            // Naive links. They do not change Naive's HTTP/2 or QUIC transport.
            "type" if value == "tcp" || value == "raw" => {}
            "headerType" if value == "none" => {}
            _ => unsupported_options.push(key.to_string()),
        }
    }
    unsupported_options.sort();
    unsupported_options.dedup();

    let name = url
        .fragment()
        .map(decode_component)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("naive · {server}:{port}"));

    let mut credentials = BTreeMap::new();
    if !username.is_empty() {
        credentials.insert("username".to_string(), username);
    }
    credentials.insert("password".to_string(), password);

    Ok(ParsedProfile {
        profile: ProfileSummary {
            id: Uuid::new_v4().to_string(),
            name,
            protocol: "naive".to_string(),
            server,
            port,
            options,
            unsupported_options,
        },
        credentials,
    })
}

fn json_string(value: &Value, key: &str) -> Option<String> {
    match value.get(key)? {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn copy_query_options(url: &Url, output: &mut BTreeMap<String, String>) {
    const ALLOWED: &[&str] = &[
        "type",
        "security",
        "sni",
        "host",
        "path",
        "serviceName",
        "flow",
        "fp",
        "alpn",
        "encryption",
        "packetEncoding",
        "headerType",
        "mode",
        "congestion_control",
        "udp_relay_mode",
        "obfs",
        "obfs-password",
        "insecure",
        "pbk",
        "sid",
        "spx",
        "ed",
        "eh",
        "allowInsecure",
    ];

    for (key, value) in url.query_pairs() {
        if ALLOWED.contains(&key.as_ref()) && key != "obfs-password" {
            output.insert(key.to_string(), value.to_string());
        }
    }
}


fn collect_unsupported_query_options(url: &Url) -> Vec<String> {
    const KNOWN: &[&str] = &[
        "type",
        "security",
        "sni",
        "host",
        "path",
        "serviceName",
        "flow",
        "fp",
        "alpn",
        "encryption",
        "packetEncoding",
        "headerType",
        "mode",
        "congestion_control",
        "udp_relay_mode",
        "obfs",
        "obfs-password",
        "insecure",
        "pbk",
        "sid",
        "spx",
        "ed",
        "eh",
        "allowInsecure",
    ];

    let mut unsupported = url
        .query_pairs()
        .filter(|(key, _)| !KNOWN.contains(&key.as_ref()))
        .map(|(key, _)| key.to_string())
        .collect::<Vec<_>>();
    unsupported.sort();
    unsupported.dedup();
    unsupported
}

fn collect_unsupported_vmess_fields(value: &Value) -> Vec<String> {
    const KNOWN: &[&str] = &[
        "v", "ps", "add", "port", "id", "aid", "net", "type", "host",
        "path", "tls", "sni", "scy", "fp", "alpn",
    ];

    let mut unsupported = value
        .as_object()
        .map(|object| {
            object
                .keys()
                .filter(|key| !KNOWN.contains(&key.as_str()))
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    unsupported.sort();
    unsupported
}

fn protocol_is_hysteria2(scheme: &str) -> bool {
    scheme == "hysteria2" || scheme == "hy2"
}

fn split_method_password(value: &str) -> Result<(String, String), String> {
    value
        .split_once(':')
        .map(|(method, password)| (method.to_string(), password.to_string()))
        .ok_or_else(|| "The Shadowsocks credentials are malformed.".to_string())
}

fn decode_component(value: &str) -> String {
    percent_decode_str(value).decode_utf8_lossy().into_owned()
}

fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    try_decode_base64(input).ok_or_else(|| "The link contains invalid Base64 data.".to_string())
}

fn try_decode_base64(input: &str) -> Option<Vec<u8>> {
    let compact: String = input.chars().filter(|character| !character.is_whitespace()).collect();
    if compact.is_empty() {
        return None;
    }

    let mut padded = compact.clone();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    STANDARD
        .decode(&compact)
        .or_else(|_| STANDARD.decode(&padded))
        .or_else(|_| URL_SAFE.decode(&compact))
        .or_else(|_| URL_SAFE.decode(&padded))
        .or_else(|_| URL_SAFE_NO_PAD.decode(&compact))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vless_without_exposing_uuid_in_metadata() {
        let parsed = parse_share_uri(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:443?security=tls&type=ws&host=cdn.example.com&path=%2Fedge#Fast%20Node",
        )
        .expect("valid VLESS URI");

        assert_eq!(parsed.profile.protocol, "vless");
        assert_eq!(parsed.profile.name, "Fast Node");
        assert_eq!(parsed.profile.server, "example.com");
        assert_eq!(parsed.profile.port, 443);
        assert!(parsed.profile.unsupported_options.is_empty());
        assert_eq!(parsed.profile.options.get("security").unwrap(), "tls");
        assert_eq!(
            parsed.credentials.get("uuid").unwrap(),
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        );

        let public_json = serde_json::to_string(&parsed.profile).unwrap();
        assert!(!public_json.contains("aaaaaaaa-bbbb"));
    }

    #[test]
    fn parses_trojan_password_as_a_secret() {
        let parsed = parse_share_uri(
            "trojan://super-secret@example.net:443?sni=example.net#Trojan",
        )
        .expect("valid Trojan URI");

        assert_eq!(parsed.profile.protocol, "trojan");
        assert_eq!(parsed.credentials.get("password").unwrap(), "super-secret");
        assert!(!serde_json::to_string(&parsed.profile).unwrap().contains("super-secret"));
    }

    #[test]
    fn parses_shadowsocks_sip002_credentials() {
        let parsed = parse_share_uri(
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@ss.example.org:8388#SS",
        )
        .expect("valid Shadowsocks URI");

        assert_eq!(parsed.profile.protocol, "shadowsocks");
        assert_eq!(parsed.profile.options.get("method").unwrap(), "aes-256-gcm");
        assert_eq!(parsed.credentials.get("password").unwrap(), "password");
    }

    #[test]
    fn parses_plain_shadowsocks_method_and_password() {
        let parsed = parse_share_uri(
            "ss://aes-128-gcm:plain-password@ss.example.org:8388#Plain%20SS",
        )
        .expect("valid plain Shadowsocks URI");

        assert_eq!(parsed.profile.options.get("method").unwrap(), "aes-128-gcm");
        assert_eq!(parsed.credentials.get("password").unwrap(), "plain-password");
    }

    #[test]
    fn parses_vmess_json_payload() {
        let payload = r#"{"v":"2","ps":"VMess node","add":"vmess.example.org","port":"8443","id":"12345678-1234-1234-1234-123456789012","aid":"0","net":"ws","path":"/gateway","tls":"tls"}"#;
        let encoded = STANDARD.encode(payload.as_bytes());
        let parsed = parse_share_uri(&format!("vmess://{encoded}")).expect("valid VMess URI");

        assert_eq!(parsed.profile.protocol, "vmess");
        assert_eq!(parsed.profile.server, "vmess.example.org");
        assert_eq!(parsed.profile.port, 8443);
        assert_eq!(parsed.profile.options.get("transport").unwrap(), "ws");
        assert_eq!(
            parsed.credentials.get("uuid").unwrap(),
            "12345678-1234-1234-1234-123456789012"
        );
    }

    #[test]
    fn reports_bad_lines_without_aborting_valid_imports() {
        let batch = parse_import_text(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:443#ok\nnot-a-link",
        )
        .expect("batch import");

        assert_eq!(batch.profiles.len(), 1);
        assert_eq!(batch.rejected.len(), 1);
        assert_eq!(batch.rejected[0].line, 2);
    }


    #[test]
    fn preserves_unrecognized_query_keys_for_adapter_validation() {
        let parsed = parse_share_uri(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:443?security=tls&xhttp=1#node",
        )
        .expect("valid URI with an unsupported adapter option");

        assert_eq!(parsed.profile.unsupported_options, vec!["xhttp".to_string()]);
    }

    #[test]
    fn refuses_zero_port_in_share_links() {
        let error = parse_share_uri(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:0",
        )
        .unwrap_err();
        assert_eq!(error, "The link must include an explicit non-zero port.");
    }

    #[test]
    fn refuses_unknown_schemes() {
        let error = parse_share_uri("madeup://user@example.com:443").unwrap_err();
        assert_eq!(error, "Unsupported link scheme.");
    }

    #[test]
    fn parses_hysteria2_and_keeps_both_passwords_out_of_metadata() {
        let parsed = parse_share_uri(
            "hysteria2://hy2-secret@hy2.example.org:443?sni=hy2.example.org&obfs=salamander&obfs-password=obfs-secret#HY2",
        )
        .expect("valid Hysteria2 URI");

        assert_eq!(parsed.profile.protocol, "hysteria2");
        assert_eq!(parsed.profile.options.get("obfs").map(String::as_str), Some("salamander"));
        assert_eq!(parsed.credentials.get("password").map(String::as_str), Some("hy2-secret"));
        assert_eq!(parsed.credentials.get("obfsPassword").map(String::as_str), Some("obfs-secret"));

        let metadata = serde_json::to_string(&parsed.profile).expect("serialize profile metadata");
        assert!(!metadata.contains("hy2-secret"));
        assert!(!metadata.contains("obfs-secret"));
    }

    #[test]
    fn parses_tuic_uuid_and_password_as_separate_secrets() {
        let parsed = parse_share_uri(
            "tuic://12345678-1234-1234-1234-123456789012:tuic-secret@tuic.example.org:443?congestion_control=bbr&udp_relay_mode=quic#TUIC",
        )
        .expect("valid TUIC URI");

        assert_eq!(parsed.profile.protocol, "tuic");
        assert_eq!(parsed.profile.options.get("congestion_control").map(String::as_str), Some("bbr"));
        assert_eq!(parsed.profile.options.get("udp_relay_mode").map(String::as_str), Some("quic"));
        assert_eq!(parsed.credentials.get("uuid").map(String::as_str), Some("12345678-1234-1234-1234-123456789012"));
        assert_eq!(parsed.credentials.get("password").map(String::as_str), Some("tuic-secret"));

        let metadata = serde_json::to_string(&parsed.profile).expect("serialize profile metadata");
        assert!(!metadata.contains("12345678-1234"));
        assert!(!metadata.contains("tuic-secret"));
    }

    #[test]
    fn vmess_unknown_field_names_are_kept_without_their_values() {
        let payload = r#"{"v":"2","ps":"VMess","add":"vmess.example.org","port":"443","id":"12345678-1234-1234-1234-123456789012","extra_auth":"must-not-be-copied"}"#;
        let encoded = STANDARD.encode(payload.as_bytes());
        let parsed = parse_share_uri(&format!("vmess://{encoded}")).expect("valid VMess URI");

        assert_eq!(parsed.profile.unsupported_options, vec!["extra_auth".to_string()]);
        let metadata = serde_json::to_string(&parsed.profile).expect("serialize profile metadata");
        assert!(metadata.contains("extra_auth"));
        assert!(!metadata.contains("must-not-be-copied"));
    }

    #[test]
    fn rejects_shadowsocks_plugin_links_explicitly() {
        let error = parse_share_uri(
            "ss://aes-128-gcm:password@ss.example.org:8388/?plugin=v2ray-plugin%3Bmode%3Dwebsocket",
        )
        .unwrap_err();
        assert_eq!(error, "Shadowsocks plugin links are not supported yet.");
    }

    #[test]
    fn parses_naive_https_with_credentials_and_optional_settings() {
        let parsed = parse_share_uri(
            "naive+https://us%3Aer:pa%3Ass@naive.example.org:8443?sni=edge.example.org&insecure-concurrency=2&type=tcp&headerType=none#Naive%20HTTPS",
        )
        .expect("valid Naive HTTPS URI");

        assert_eq!(parsed.profile.protocol, "naive");
        assert_eq!(parsed.profile.name, "Naive HTTPS");
        assert_eq!(parsed.profile.port, 8443);
        assert_eq!(parsed.profile.options.get("sni").map(String::as_str), Some("edge.example.org"));
        assert_eq!(parsed.profile.options.get("insecureConcurrency").map(String::as_str), Some("2"));
        assert!(!parsed.profile.options.contains_key("quic"));
        assert_eq!(parsed.credentials.get("username").map(String::as_str), Some("us:er"));
        assert_eq!(parsed.credentials.get("password").map(String::as_str), Some("pa:ss"));

        let metadata = serde_json::to_string(&parsed.profile).expect("serialize metadata");
        assert!(!metadata.contains("us:er"));
        assert!(!metadata.contains("pa:ss"));
    }

    #[test]
    fn parses_naive_quic_with_default_port_and_password_only_userinfo() {
        let parsed = parse_share_uri("naive+quic://pa%3Ass@quic.example.org#Naive%20QUIC")
            .expect("valid Naive QUIC URI");

        assert_eq!(parsed.profile.protocol, "naive");
        assert_eq!(parsed.profile.port, 443);
        assert_eq!(parsed.profile.options.get("quic").map(String::as_str), Some("true"));
        assert!(!parsed.credentials.contains_key("username"));
        assert_eq!(parsed.credentials.get("password").map(String::as_str), Some("pa:ss"));
    }

    #[test]
    fn parses_naive_quic_with_custom_nonstandard_port() {
        let parsed = parse_share_uri("naive+quic://secret@quic.example.org:9443")
            .expect("valid Naive QUIC URI with a custom port");

        assert_eq!(parsed.profile.port, 9443);
        assert_eq!(parsed.profile.options.get("quic").map(String::as_str), Some("true"));
    }

    #[test]
    fn rejects_naive_zero_port_invalid_concurrency_and_unmapped_fields() {
        assert!(parse_share_uri("naive+https://secret@naive.example.org:0").is_err());
        assert!(parse_share_uri("naive+https://secret@naive.example.org?insecure-concurrency=-1").is_err());
        let parsed = parse_share_uri("naive+https://secret@naive.example.org?extra_headers=x")
            .expect("unknown fields are kept for adapter validation");
        assert_eq!(parsed.profile.unsupported_options, vec!["extra_headers".to_string()]);
    }

    #[test]
    fn enforces_import_entry_limit_before_parsing_every_line() {
        let input = vec!["not-a-link"; MAX_IMPORT_LINES + 1].join("\n");
        let error = parse_import_text(&input).unwrap_err();
        assert_eq!(error, "An import can contain at most 500 entries.");
    }

    #[test]
    fn enforces_import_byte_limit() {
        let input = "x".repeat(MAX_IMPORT_BYTES + 1);
        let error = parse_import_text(&input).unwrap_err();
        assert_eq!(error, "Import text is larger than 2 MiB.");
    }
}
