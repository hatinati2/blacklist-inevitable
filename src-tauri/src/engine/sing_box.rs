use std::collections::BTreeMap;

use futures_util::StreamExt;
use serde_json::{json, Map, Value};

use crate::process_supervisor::ProcessSupervisor;
use crate::profiles::ProfileSummary;

const OUTBOUND_TAG: &str = "blacklist-profile";

pub fn build_probe_config(
    profile: &ProfileSummary,
    credentials: &BTreeMap<String, String>,
    listen_port: u16,
) -> Result<Value, String> {
    if listen_port == 0 {
        return Err("The temporary local proxy port is invalid.".to_string());
    }
    if !profile.unsupported_options.is_empty() {
        return Err(format!(
            "The imported link contains options not handled by this engine: {}.",
            profile.unsupported_options.join(", ")
        ));
    }
    validate_profile_options(profile, credentials)?;

    let mut outbound = Map::new();
    outbound.insert("type".to_string(), json!(profile.protocol));
    outbound.insert("tag".to_string(), json!(OUTBOUND_TAG));
    outbound.insert("server".to_string(), json!(profile.server));
    outbound.insert("server_port".to_string(), json!(profile.port));

    match profile.protocol.as_str() {
        "vless" => {
            ensure_allowed_options(profile, &[
                "security", "sni", "host", "path", "serviceName", "flow", "fp",
                "fingerprint", "alpn", "encryption", "packetEncoding", "type",
                "transport", "ed", "eh", "pbk", "sid", "spx", "insecure",
                "allowInsecure",
            ])?;
            if profile.options.get("encryption").is_some_and(|value| value != "none") {
                return Err("The current sing-box adapter supports only VLESS encryption=none.".to_string());
            }
            if profile.options.contains_key("spx") {
                return Err("The sing-box adapter does not currently map the Reality spiderX (spx) option.".to_string());
            }
            outbound.insert("uuid".to_string(), json!(required(credentials, "uuid")?));
            insert_option(&mut outbound, "flow", &profile.options, "flow");
            insert_option(&mut outbound, "packet_encoding", &profile.options, "packetEncoding");
            insert_tls(&mut outbound, profile, false)?;
            insert_transport(&mut outbound, &profile.options)?;
        }
        "vmess" => {
            ensure_allowed_options(profile, &[
                "transport", "headerType", "host", "path", "tls", "sni",
                "security", "alterId", "fingerprint", "alpn", "fp",
                "packetEncoding", "ed", "eh", "insecure", "allowInsecure",
            ])?;
            if profile.options.get("headerType").is_some_and(|value| value != "none" && !value.is_empty()) {
                return Err("VMess header types other than 'none' are not supported by the sing-box adapter.".to_string());
            }
            outbound.insert("uuid".to_string(), json!(required(credentials, "uuid")?));
            outbound.insert(
                "security".to_string(),
                json!(profile.options.get("security").map(String::as_str).unwrap_or("auto")),
            );
            outbound.insert(
                "alter_id".to_string(),
                json!(parse_u16_option(&profile.options, "alterId").unwrap_or(0)),
            );
            insert_option(&mut outbound, "packet_encoding", &profile.options, "packetEncoding");
            insert_tls(&mut outbound, profile, false)?;
            insert_transport(&mut outbound, &profile.options)?;
        }
        "trojan" => {
            ensure_allowed_options(profile, &[
                "security", "sni", "host", "path", "serviceName", "flow", "fp",
                "fingerprint", "alpn", "insecure", "allowInsecure", "type",
                "transport", "ed", "eh",
            ])?;
            outbound.insert("password".to_string(), json!(required(credentials, "password")?));
            insert_tls(&mut outbound, profile, true)?;
            insert_transport(&mut outbound, &profile.options)?;
        }
        "shadowsocks" => {
            ensure_allowed_options(profile, &["method"])?;
            outbound.insert(
                "method".to_string(),
                json!(profile.options.get("method").ok_or_else(|| "Shadowsocks encryption method is missing.".to_string())?),
            );
            outbound.insert("password".to_string(), json!(required(credentials, "password")?));
        }
        "hysteria2" => {
            ensure_allowed_options(profile, &[
                "sni", "alpn", "fp", "fingerprint", "insecure",
                "allowInsecure", "obfs",
            ])?;
            outbound.insert("password".to_string(), json!(required(credentials, "password")?));
            insert_tls(&mut outbound, profile, true)?;
            if let Some(kind) = profile.options.get("obfs") {
                let password = required(credentials, "obfsPassword")?;
                outbound.insert(
                    "obfs".to_string(),
                    json!({"type":kind,"password":password}),
                );
            }
        }
        "tuic" => {
            ensure_allowed_options(profile, &[
                "sni", "alpn", "fp", "fingerprint", "insecure", "allowInsecure",
                "congestion_control", "udp_relay_mode",
            ])?;
            outbound.insert("uuid".to_string(), json!(required(credentials, "uuid")?));
            outbound.insert("password".to_string(), json!(required(credentials, "password")?));
            outbound.insert(
                "congestion_control".to_string(),
                json!(profile.options.get("congestion_control").map(String::as_str).unwrap_or("cubic")),
            );
            outbound.insert(
                "udp_relay_mode".to_string(),
                json!(profile.options.get("udp_relay_mode").map(String::as_str).unwrap_or("native")),
            );
            insert_tls(&mut outbound, profile, true)?;
        }
        _ => return Err("This protocol is not supported by the sing-box adapter.".to_string()),
    }

    Ok(json!({
        "log": {"disabled": true},
        "inbounds": [{
            "type": "socks",
            "tag": "preflight-in",
            "listen": "127.0.0.1",
            "listen_port": listen_port
        }],
        "outbounds": [Value::Object(outbound)],
        "route": {"final": OUTBOUND_TAG}
    }))
}



fn validate_profile_options(
    profile: &ProfileSummary,
    credentials: &BTreeMap<String, String>,
) -> Result<(), String> {
    let options = &profile.options;
    let transport = options
        .get("transport")
        .or_else(|| options.get("type"))
        .map(String::as_str)
        .unwrap_or("tcp")
        .to_ascii_lowercase();

    let is_websocket = matches!(transport.as_str(), "ws" | "websocket");
    let is_grpc = transport == "grpc";
    let supports_path_and_host = matches!(
        transport.as_str(),
        "ws" | "websocket" | "grpc" | "http" | "h2" | "httpupgrade" | "http-upgrade"
    );

    if (options.contains_key("path") || options.contains_key("host")) && !supports_path_and_host {
        return Err("Path/Host transport options were supplied without a compatible transport.".to_string());
    }
    if options.contains_key("serviceName") && !is_grpc {
        return Err("serviceName is only supported with the gRPC transport.".to_string());
    }
    if (options.contains_key("ed") || options.contains_key("eh")) && !is_websocket {
        return Err("WebSocket early-data options (ed/eh) require the WebSocket transport.".to_string());
    }

    if let Some(value) = options.get("insecure").or_else(|| options.get("allowInsecure")) {
        if !["0", "1", "true", "false"].contains(&value.to_ascii_lowercase().as_str()) {
            return Err("The insecure/allowInsecure option must be true, false, 1, or 0.".to_string());
        }
    }

    if let Some(encoding) = options.get("packetEncoding") {
        if !["", "packetaddr", "xudp"].contains(&encoding.as_str()) {
            return Err(format!("Packet encoding '{encoding}' is not supported by this sing-box adapter."));
        }
    }

    if let Some(flow) = options.get("flow") {
        if profile.protocol != "vless" || !flow.is_empty() && flow != "xtls-rprx-vision" {
            return Err(format!("Flow '{flow}' is not supported for this profile."));
        }
    }

    match profile.protocol.as_str() {
        "vless" => {
            let security = options.get("security").map(String::as_str).unwrap_or("");
            if !["", "none", "tls", "reality"].contains(&security.to_ascii_lowercase().as_str()) {
                return Err(format!("VLESS security mode '{security}' is not supported."));
            }
            if options.get("encryption").is_some_and(|value| value != "none") {
                return Err("Only VLESS encryption=none is currently supported.".to_string());
            }
            let reality = security.eq_ignore_ascii_case("reality");
            if !reality && (options.contains_key("pbk") || options.contains_key("sid") || options.contains_key("spx")) {
                return Err("Reality-only options (pbk/sid/spx) require security=reality.".to_string());
            }
            if reality && options.contains_key("spx") {
                return Err("Reality spiderX (spx) is not mapped by the current sing-box adapter.".to_string());
            }
        }
        "vmess" => {
            if options.get("tls").is_some_and(|value| {
                !value.is_empty() && !["tls", "none"].contains(&value.to_ascii_lowercase().as_str())
            }) {
                return Err("Only VMess tls=tls or tls=none is currently supported.".to_string());
            }
            if let Some(alter_id) = options.get("alterId") {
                if alter_id.parse::<u16>().is_err() {
                    return Err("VMess alterId must be a valid 16-bit integer.".to_string());
                }
            }
            if options.get("headerType").is_some_and(|value| !value.is_empty() && value != "none") {
                return Err("VMess header types other than 'none' are not supported.".to_string());
            }
        }
        "trojan" | "hysteria2" | "tuic" => {
            if options.get("security").is_some_and(|value| {
                !value.is_empty() && !["tls", "none"].contains(&value.to_ascii_lowercase().as_str())
            }) {
                return Err("This protocol requires TLS; only the standard TLS security mode is supported.".to_string());
            }
        }
        "shadowsocks" => {}
        _ => return Err("This protocol is not supported by the sing-box adapter.".to_string()),
    }

    let tls_enabled = matches!(profile.protocol.as_str(), "trojan" | "hysteria2" | "tuic")
        || options.get("security").is_some_and(|value| {
            ["tls", "reality"].contains(&value.to_ascii_lowercase().as_str())
        })
        || options.get("tls").is_some_and(|value| value.eq_ignore_ascii_case("tls"));

    if !tls_enabled
        && [
            "sni", "fp", "fingerprint", "alpn", "insecure", "allowInsecure",
        ]
        .iter()
        .any(|key| options.contains_key(*key))
    {
        return Err("TLS-related options were supplied while TLS is disabled.".to_string());
    }

    if let Some(obfs) = options.get("obfs") {
        if profile.protocol != "hysteria2" || obfs != "salamander" {
            return Err("Only Hysteria2 salamander obfuscation is supported by this adapter.".to_string());
        }
        if !credentials.contains_key("obfsPassword") {
            return Err("Hysteria2 salamander obfuscation is missing its password.".to_string());
        }
    } else if credentials.contains_key("obfsPassword") {
        return Err("An obfuscation password was supplied without a supported obfuscation mode.".to_string());
    }

    if let Some(mode) = options.get("mode") {
        return Err(format!("The source mode option '{mode}' is not mapped by this adapter."));
    }

    Ok(())
}

fn ensure_allowed_options(profile: &ProfileSummary, allowed: &[&str]) -> Result<(), String> {
    let unsupported = profile
        .options
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if unsupported.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "The sing-box adapter does not yet map these {} options: {}.",
            profile.protocol,
            unsupported.join(", ")
        ))
    }
}

fn required<'a>(
    credentials: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, String> {
    credentials
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("Required credential '{key}' is missing."))
}

fn insert_option(
    outbound: &mut Map<String, Value>,
    field: &str,
    options: &BTreeMap<String, String>,
    key: &str,
) {
    if let Some(value) = options.get(key).filter(|value| !value.is_empty()) {
        outbound.insert(field.to_string(), json!(value));
    }
}

fn parse_u16_option(options: &BTreeMap<String, String>, key: &str) -> Option<u16> {
    options.get(key).and_then(|value| value.parse::<u16>().ok())
}

fn insert_tls(
    outbound: &mut Map<String, Value>,
    profile: &ProfileSummary,
    tls_required: bool,
) -> Result<(), String> {
    let security = profile.options.get("security").map(String::as_str).unwrap_or("");
    let vmess_tls = profile.options.get("tls").map(String::as_str).unwrap_or("");
    let reality = security.eq_ignore_ascii_case("reality");
    let tls_enabled = tls_required
        || reality
        || security.eq_ignore_ascii_case("tls")
        || vmess_tls.eq_ignore_ascii_case("tls");

    if profile.protocol == "vless"
        && !security.is_empty()
        && !["tls", "reality", "none"].contains(&security.to_ascii_lowercase().as_str())
    {
        return Err(format!("VLESS security mode '{security}' is not supported by the sing-box adapter."));
    }
    if profile.protocol == "vmess"
        && !vmess_tls.is_empty()
        && !["tls", "none"].contains(&vmess_tls.to_ascii_lowercase().as_str())
    {
        return Err(format!("VMess TLS mode '{vmess_tls}' is not supported by the sing-box adapter."));
    }
    if !tls_enabled {
        if profile.options.contains_key("sni") || profile.options.contains_key("fp") || profile.options.contains_key("alpn") {
            return Err("TLS-related options were supplied for a profile without TLS enabled.".to_string());
        }
        return Ok(());
    }

    let server_name = profile
        .options
        .get("sni")
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .unwrap_or(&profile.server);
    let insecure = profile.options.get("insecure").or_else(|| profile.options.get("allowInsecure"))
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let mut tls = json!({
        "enabled": true,
        "server_name": server_name,
        "insecure": insecure
    });

    if let Some(alpn) = profile.options.get("alpn").filter(|value| !value.is_empty()) {
        tls["alpn"] = Value::Array(
            alpn.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| json!(value))
                .collect(),
        );
    }

    if let Some(fingerprint) = profile.options.get("fp").filter(|value| !value.is_empty()) {
        tls["utls"] = json!({"enabled": true, "fingerprint": fingerprint});
    } else if let Some(fingerprint) = profile.options.get("fingerprint").filter(|value| !value.is_empty()) {
        tls["utls"] = json!({"enabled": true, "fingerprint": fingerprint});
    }

    if reality {
        let public_key = profile.options.get("pbk").filter(|value| !value.is_empty())
            .ok_or_else(|| "VLESS Reality link has no public key (pbk).".to_string())?;
        let short_id = profile.options.get("sid").map(String::as_str).unwrap_or("");
        tls["reality"] = json!({
            "enabled": true,
            "public_key": public_key,
            "short_id": short_id
        });
    }

    outbound.insert("tls".to_string(), tls);
    Ok(())
}

fn insert_transport(
    outbound: &mut Map<String, Value>,
    options: &BTreeMap<String, String>,
) -> Result<(), String> {
    let transport = options
        .get("transport")
        .or_else(|| options.get("type"))
        .map(String::as_str)
        .unwrap_or("tcp")
        .to_ascii_lowercase();

    let host = options.get("host").filter(|value| !value.is_empty()).cloned();
    let path = options.get("path").cloned().unwrap_or_default();

    let value = match transport.as_str() {
        "" | "none" | "tcp" | "raw" => return Ok(()),
        "quic" => json!({"type":"quic"}),
        "ws" | "websocket" => {
            let mut headers = Map::new();
            if let Some(host) = host {
                headers.insert("Host".to_string(), json!(host));
            }
            let mut websocket = json!({"type":"ws","path":path,"headers":headers});
            if let Some(early_data) = options.get("ed") {
                let size = early_data
                    .parse::<u32>()
                    .map_err(|_| "WebSocket early-data (ed) must be a valid non-negative integer.".to_string())?;
                websocket["max_early_data"] = json!(size);
            }
            if let Some(header_name) = options.get("eh").filter(|value| !value.is_empty()) {
                websocket["early_data_header_name"] = json!(header_name);
            }
            websocket
        }
        "grpc" => {
            let service = options.get("serviceName").cloned().unwrap_or_default();
            json!({"type":"grpc","service_name":service})
        }
        "http" | "h2" => {
            let hosts = host.map(|value| vec![value]).unwrap_or_default();
            json!({"type":"http","path":path,"host":hosts})
        }
        "httpupgrade" | "http-upgrade" => {
            json!({"type":"httpupgrade","path":path,"host":host.unwrap_or_default()})
        }
        unsupported => {
            return Err(format!("The sing-box adapter does not support the '{unsupported}' transport yet."));
        }
    };

    outbound.insert("transport".to_string(), value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile(protocol: &str) -> ProfileSummary {
        ProfileSummary {
            id: "profile-test".to_string(),
            name: "Test".to_string(),
            protocol: protocol.to_string(),
            server: "proxy.example.com".to_string(),
            port: 443,
            options: BTreeMap::new(),
            unsupported_options: Vec::new(),
        }
    }

    #[test]
    fn refuses_profiles_with_unmapped_source_options() {
        let mut profile = sample_profile("vless");
        profile.unsupported_options.push("xhttp".to_string());
        let credentials = BTreeMap::from([("uuid".to_string(), "uuid-value".to_string())]);

        assert!(build_probe_config(&profile, &credentials, 10080)
            .unwrap_err()
            .contains("xhttp"));
    }

    #[test]
    fn maps_websocket_early_data_fields() {
        let mut profile = sample_profile("vless");
        profile.options = BTreeMap::from([
            ("type".to_string(), "ws".to_string()),
            ("ed".to_string(), "2048".to_string()),
            ("eh".to_string(), "Sec-WebSocket-Protocol".to_string()),
        ]);
        let credentials = BTreeMap::from([("uuid".to_string(), "uuid-value".to_string())]);
        let config = build_probe_config(&profile, &credentials, 10080).unwrap();

        assert_eq!(config["outbounds"][0]["transport"]["max_early_data"], 2048);
        assert_eq!(
            config["outbounds"][0]["transport"]["early_data_header_name"],
            "Sec-WebSocket-Protocol"
        );
    }

    #[test]
    fn builds_loopback_only_probe_config() {
        let profile = sample_profile("trojan");
        let credentials = BTreeMap::from([("password".to_string(), "secret".to_string())]);
        let config = build_probe_config(&profile, &credentials, 12345).unwrap();

        assert_eq!(config["inbounds"][0]["type"], "socks");
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["listen_port"], 12345);
        assert_eq!(config["outbounds"][0]["type"], "trojan");
        assert_eq!(config["outbounds"][0]["password"], "secret");
        assert!(config.get("tun").is_none());
    }

    #[test]
    fn maps_vless_reality_and_websocket_fields() {
        let mut profile = sample_profile("vless");
        profile.options = BTreeMap::from([
            ("security".to_string(), "reality".to_string()),
            ("sni".to_string(), "cdn.example.com".to_string()),
            ("pbk".to_string(), "public-key".to_string()),
            ("sid".to_string(), "abcd".to_string()),
            ("type".to_string(), "ws".to_string()),
            ("path".to_string(), "/gateway".to_string()),
            ("host".to_string(), "cdn.example.com".to_string()),
        ]);
        let credentials = BTreeMap::from([("uuid".to_string(), "uuid-value".to_string())]);
        let config = build_probe_config(&profile, &credentials, 10080).unwrap();

        assert_eq!(config["outbounds"][0]["tls"]["reality"]["public_key"], "public-key");
        assert_eq!(config["outbounds"][0]["transport"]["type"], "ws");
        assert_eq!(config["outbounds"][0]["transport"]["path"], "/gateway");
    }

    #[test]
    fn refuses_reality_without_public_key() {
        let mut profile = sample_profile("vless");
        profile.options.insert("security".to_string(), "reality".to_string());
        let credentials = BTreeMap::from([("uuid".to_string(), "uuid-value".to_string())]);

        assert!(build_probe_config(&profile, &credentials, 10080).is_err());
    }

    #[test]
    fn refuses_unsupported_transports_instead_of_dropping_them() {
        let mut profile = sample_profile("vmess");
        profile.options.insert("transport".to_string(), "mkcp".to_string());
        profile.options.insert("security".to_string(), "auto".to_string());
        let credentials = BTreeMap::from([("uuid".to_string(), "uuid-value".to_string())]);

        assert!(build_probe_config(&profile, &credentials, 10080).is_err());
    }
}


use std::fs::{self, File};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};
use uuid::Uuid;
use zip::ZipArchive;

pub const SING_BOX_VERSION: &str = "1.14.4";
const WINDOWS_AMD64_ARCHIVE_URL: &str =
    "https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-windows-amd64.zip";
const WINDOWS_AMD64_ARCHIVE_SHA256: &str =
    "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df";
const CONFIG_CHECK_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_ENGINE_ARCHIVE_BYTES: usize = 128 * 1024 * 1024;
const MAX_ENGINE_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;

pub fn installed_binary_path(app: &AppHandle) -> Result<PathBuf, String> {
    let root = app
        .path()
        .app_data_dir()
        .map_err(|_| "Could not resolve the application data directory.".to_string())?;
    Ok(root
        .join("engines")
        .join(format!("sing-box-{SING_BOX_VERSION}"))
        .join("sing-box.exe"))
}

pub async fn is_installed(app: &AppHandle) -> bool {
    let Ok(path) = installed_binary_path(app) else {
        return false;
    };
    if !path.is_file() {
        return false;
    }
    read_engine_version(&path)
        .await
        .map(|reported| matches_expected_engine_version(&reported))
        .unwrap_or(false)
}

fn matches_expected_engine_version(reported: &str) -> bool {
    reported.split_whitespace().any(|token| {
        token == SING_BOX_VERSION || token.strip_prefix('v') == Some(SING_BOX_VERSION)
    })
}

pub async fn install(app: &AppHandle) -> Result<String, String> {
    let binary_path = installed_binary_path(app)?;
    if binary_path.is_file() {
        if let Ok(version) = read_engine_version(&binary_path).await {
            if matches_expected_engine_version(&version) {
                return Ok(version);
            }
        }
    }

    let directory = binary_path
        .parent()
        .ok_or_else(|| "Could not resolve the engine installation directory.".to_string())?;
    fs::create_dir_all(directory)
        .map_err(|_| "Could not create the engine installation directory.".to_string())?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()
        .map_err(|_| "Could not initialize the secure download client.".to_string())?;
    let response = client
        .get(WINDOWS_AMD64_ARCHIVE_URL)
        .send()
        .await
        .map_err(|_| "Could not download the official sing-box release.".to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "The sing-box download server returned HTTP {}.",
            response.status().as_u16()
        ));
    }

    if response
        .content_length()
        .is_some_and(|length| length > MAX_ENGINE_ARCHIVE_BYTES as u64)
    {
        return Err("The sing-box archive exceeds the 128 MiB download limit.".to_string());
    }

    let expected_length = response.content_length();
    let mut archive_stream = response.bytes_stream();
    let mut archive_bytes = Vec::new();
    while let Some(chunk) = archive_stream.next().await {
        let chunk = chunk
            .map_err(|_| "The sing-box archive download was incomplete.".to_string())?;
        if archive_bytes.len().saturating_add(chunk.len()) > MAX_ENGINE_ARCHIVE_BYTES {
            return Err("The sing-box archive exceeds the 128 MiB download limit.".to_string());
        }
        archive_bytes.extend_from_slice(&chunk);
    }
    if archive_bytes.is_empty()
        || expected_length.is_some_and(|expected| expected != archive_bytes.len() as u64)
    {
        return Err("The sing-box archive download was empty or incomplete.".to_string());
    }

    let actual_hash = Sha256::digest(&archive_bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual_hash != WINDOWS_AMD64_ARCHIVE_SHA256 {
        return Err("The downloaded sing-box archive failed its SHA-256 verification.".to_string());
    }

    let temporary_binary = directory.join(format!("sing-box-{}.partial", Uuid::new_v4()));
    let extract_result = extract_verified_executable(&archive_bytes, &temporary_binary);
    if let Err(error) = extract_result {
        let _ = fs::remove_file(&temporary_binary);
        return Err(error);
    }

    let version = match read_engine_version(&temporary_binary).await {
        Ok(version) if matches_expected_engine_version(&version) => version,
        Ok(_) => {
            let _ = fs::remove_file(&temporary_binary);
            return Err("The downloaded executable reports an unexpected sing-box version.".to_string());
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary_binary);
            return Err(error);
        }
    };

    if binary_path.exists() {
        fs::remove_file(&binary_path)
            .map_err(|_| "Could not replace the previously installed sing-box engine.".to_string())?;
    }
    fs::rename(&temporary_binary, &binary_path)
        .map_err(|_| "Could not install the verified sing-box executable.".to_string())?;

    let notice_path = directory.join("THIRD_PARTY_NOTICE.txt");
    let notice = format!(
        "sing-box {SING_BOX_VERSION}\n         Upstream: https://github.com/SagerNet/sing-box\n         Release: https://github.com/SagerNet/sing-box/releases/tag/v{SING_BOX_VERSION}\n         License: GNU GPL version 3 or later (GPL-3.0-or-later).\n         Upstream license: https://github.com/SagerNet/sing-box/blob/v{SING_BOX_VERSION}/LICENSE\n         Additional upstream condition: no derivative work may use the name or imply\n         association with the upstream application without prior consent.\n         This unmodified executable was downloaded from the upstream release and verified\n         against the pinned SHA-256 of its Windows AMD64 archive.\n"
    );
    fs::write(notice_path, notice)
        .map_err(|_| "The engine was installed but its third-party notice could not be saved.".to_string())?;

    Ok(version)
}

fn extract_verified_executable(archive_bytes: &[u8], destination: &Path) -> Result<(), String> {
    let mut archive = ZipArchive::new(Cursor::new(archive_bytes))
        .map_err(|_| "The verified sing-box release archive is not a valid ZIP file.".to_string())?;
    let mut found = false;

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|_| "Could not read an entry in the sing-box release archive.".to_string())?;
        if !entry.is_file()
            || Path::new(entry.name())
                .file_name()
                .and_then(|name| name.to_str())
                != Some("sing-box.exe")
        {
            continue;
        }
        if found {
            return Err("The sing-box archive contains more than one executable.".to_string());
        }
        if entry.size() == 0 || entry.size() > MAX_ENGINE_EXECUTABLE_BYTES {
            return Err("The sing-box executable has an invalid or excessive uncompressed size.".to_string());
        }

        let mut output = File::create(destination)
            .map_err(|_| "Could not create the temporary sing-box executable.".to_string())?;
        std::io::copy(&mut entry, &mut output)
            .map_err(|_| "Could not extract the sing-box executable.".to_string())?;
        output
            .flush()
            .map_err(|_| "Could not flush the extracted sing-box executable.".to_string())?;
        found = true;
    }

    if !found {
        return Err("The sing-box release archive does not contain sing-box.exe.".to_string());
    }

    Ok(())
}

async fn read_engine_version(binary: &Path) -> Result<String, String> {
    let output = timeout(
        Duration::from_secs(10),
        Command::new(binary)
            .arg("version")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| "The sing-box version check timed out.".to_string())?
    .map_err(|_| "Could not execute the sing-box engine.".to_string())?;

    if !output.status.success() {
        return Err("The sing-box executable did not start successfully.".to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub async fn validate_profile_config(
    app: &AppHandle,
    profile: &ProfileSummary,
    credentials: &BTreeMap<String, String>,
    supervisor: &ProcessSupervisor,
) -> Result<(), String> {
    let binary = installed_binary_path(app)?;
    if !binary.is_file() {
        return Err("The sing-box engine is not installed.".to_string());
    }

    let config = build_probe_config(profile, credentials, 17381)?;
    let cache = app
        .path()
        .app_cache_dir()
        .map_err(|_| "Could not resolve the temporary test directory.".to_string())?
        .join("preflight");
    fs::create_dir_all(&cache)
        .map_err(|_| "Could not create the temporary test directory.".to_string())?;
    let config_path = cache.join(format!("config-{}.json", Uuid::new_v4()));
    // Install the guard before the write so a cancelled/failed write cannot leave
    // a partial credential-bearing configuration behind.
    let _config_guard = ProbeConfigFile {
        path: config_path.clone(),
        supervisor: supervisor.clone(),
    };
    let config_bytes = serde_json::to_vec(&config)
        .map_err(|_| "Could not encode the temporary engine configuration.".to_string())?;
    tokio::fs::write(&config_path, config_bytes)
        .await
        .map_err(|_| "Could not write the temporary engine configuration.".to_string())?;

    let command_result = timeout(
        CONFIG_CHECK_TIMEOUT,
        Command::new(&binary)
            .arg("check")
            .arg("-c")
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output(),
    )
    .await;

    let cleanup_result = tokio::fs::remove_file(&config_path).await;
    if cleanup_result.is_err() {
        supervisor.mark_cleanup_unhealthy();
        return Err(
            "The temporary configuration could not be removed; preflight cleanup needs attention."
                .to_string(),
        );
    }

    match command_result {
        Err(_) => {
            supervisor.mark_cleanup_unhealthy();
            Err("sing-box config validation timed out; child termination could not be confirmed.".to_string())
        }
        Ok(Err(_)) => Err("Could not start sing-box config validation.".to_string()),
        Ok(Ok(output)) if output.status.success() => Ok(()),
        Ok(Ok(output)) => {
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            Err(redact_diagnostic(&diagnostic, credentials))
        }
    }
}

fn redact_diagnostic(
    diagnostic: &str,
    credentials: &BTreeMap<String, String>,
) -> String {
    let mut sanitized = diagnostic.trim().to_string();
    // Even short credentials are secrets; never echo them back in engine diagnostics.
    for secret in credentials.values().filter(|secret| !secret.is_empty()) {
        sanitized = sanitized.replace(secret, "[redacted]");
    }
    if sanitized.is_empty() {
        "The sing-box engine rejected this configuration.".to_string()
    } else {
        sanitized.chars().take(1200).collect()
    }
}


#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub config_status: String,
    pub config_detail: String,
    pub real_delay_ms: Option<u64>,
    pub real_delay_detail: String,
    pub tested_url: Option<String>,
}

const REAL_DELAY_PRIMARY_URL: &str = "https://www.gstatic.com/generate_204";
const REAL_DELAY_FALLBACK_URL: &str = "https://cp.cloudflare.com/generate_204";
const REAL_DELAY_REQUEST_TIMEOUT: Duration = Duration::from_secs(9);
const ENGINE_START_TIMEOUT: Duration = Duration::from_secs(10);

struct ProbeDirectory {
    path: PathBuf,
    supervisor: ProcessSupervisor,
}

impl Drop for ProbeDirectory {
    fn drop(&mut self) {
        // Synchronous fallback cleanup also runs if the Tauri command future is cancelled.
        if self.path.exists() && fs::remove_dir_all(&self.path).is_err() {
            self.supervisor.mark_cleanup_unhealthy();
        }
    }
}

struct ProbeConfigFile {
    path: PathBuf,
    supervisor: ProcessSupervisor,
}

impl Drop for ProbeConfigFile {
    fn drop(&mut self) {
        // Config validation stores credentials in this file. Remove it even when
        // the invoking command future is cancelled.
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => self.supervisor.mark_cleanup_unhealthy(),
        }
    }
}


pub async fn measure_real_delay(
    app: &AppHandle,
    profile: &ProfileSummary,
    credentials: &BTreeMap<String, String>,
    supervisor: &ProcessSupervisor,
) -> Result<ProbeOutcome, String> {
    let mut operation = supervisor.begin_operation()?;
    let binary = installed_binary_path(app)?;
    if !binary.is_file() {
        return Err("The pinned sing-box engine is not installed.".to_string());
    }

    let port = pick_loopback_port()?;
    let config = match build_probe_config(profile, credentials, port) {
        Ok(config) => config,
        Err(detail) => {
            return Ok(ProbeOutcome {
                config_status: "unsupported".to_string(),
                config_detail: detail,
                real_delay_ms: None,
                real_delay_detail: "Not run because this profile cannot be represented safely by the sing-box adapter.".to_string(),
                tested_url: None,
            });
        }
    };

    let cache = app
        .path()
        .app_cache_dir()
        .map_err(|_| "Could not resolve the temporary preflight directory.".to_string())?
        .join("preflight");
    tokio::fs::create_dir_all(&cache)
        .await
        .map_err(|_| "Could not create the temporary preflight directory.".to_string())?;

    let run_dir = cache.join(format!("probe-{}", Uuid::new_v4()));
    tokio::fs::create_dir(&run_dir)
        .await
        .map_err(|_| "Could not create an isolated directory for this node test.".to_string())?;
    let _directory_guard = ProbeDirectory {
        path: run_dir.clone(),
        supervisor: supervisor.clone(),
    };
    let config_path = run_dir.join("config.json");

    let config_bytes = match serde_json::to_vec(&config) {
        Ok(bytes) => bytes,
        Err(_) => {
            cleanup_probe_dir(&run_dir).await?;
            return Err("Could not encode the isolated sing-box configuration.".to_string());
        }
    };
    if tokio::fs::write(&config_path, config_bytes).await.is_err() {
        cleanup_probe_dir(&run_dir).await?;
        return Err("Could not write the isolated sing-box configuration.".to_string());
    }

    let validation = timeout(
        CONFIG_CHECK_TIMEOUT,
        Command::new(&binary)
            .arg("check")
            .arg("-c")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output(),
    )
    .await;

    let validation = match validation {
        Err(_) => {
            operation.mark_cleanup_unhealthy();
            cleanup_probe_dir(&run_dir).await?;
            return Ok(ProbeOutcome {
                config_status: "invalid".to_string(),
                config_detail: "sing-box configuration validation timed out; child termination could not be confirmed.".to_string(),
                real_delay_ms: None,
                real_delay_detail: "Not run because configuration validation did not finish.".to_string(),
                tested_url: None,
            });
        }
        Ok(Err(_)) => {
            cleanup_probe_dir(&run_dir).await?;
            return Err("Could not start sing-box configuration validation.".to_string());
        }
        Ok(Ok(output)) if output.status.success() => output,
        Ok(Ok(output)) => {
            let diagnostic = String::from_utf8_lossy(&output.stderr);
            let detail = redact_diagnostic(&diagnostic, credentials);
            cleanup_probe_dir(&run_dir).await?;
            return Ok(ProbeOutcome {
                config_status: "invalid".to_string(),
                config_detail: detail,
                real_delay_ms: None,
                real_delay_detail: "Not run because sing-box rejected this node configuration.".to_string(),
                tested_url: None,
            });
        }
    };
    drop(validation);

    // Shutdown waits for short, bounded config validation to finish. A cancelled
    // operation must not start a new long-lived engine process afterwards.
    if operation.is_cancelled() {
        if cleanup_probe_dir(&run_dir).await.is_err() {
            operation.mark_cleanup_unhealthy();
            return Err("Temporary preflight files could not be removed during shutdown.".to_string());
        }
        return Err("Real Delay was cancelled because the application is shutting down.".to_string());
    }

    let mut child = match Command::new(&binary)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(_) => {
            cleanup_probe_dir(&run_dir).await?;
            return Err("Could not start the temporary sing-box probe process.".to_string());
        }
    };

    let measurement = tokio::select! {
        _ = operation.cancelled() => {
            Err("Real Delay was cancelled because the application is shutting down.".to_string())
        }
        result = async {
            wait_for_local_socks(&mut child, port).await?;
            measure_request_through_socks(port).await
        } => result,
    };

    let process_cleanup = stop_probe_process(&mut child).await;
    let directory_cleanup = cleanup_probe_dir(&run_dir).await;

    if let Err(error) = process_cleanup {
        operation.mark_cleanup_unhealthy();
        return Err(error);
    }
    if let Err(error) = directory_cleanup {
        operation.mark_cleanup_unhealthy();
        return Err(error);
    }

    match measurement {
        Ok((delay_ms, tested_url)) => Ok(ProbeOutcome {
            config_status: "valid".to_string(),
            config_detail: "sing-box accepted the generated configuration.".to_string(),
            real_delay_ms: Some(delay_ms),
            real_delay_detail: "HTTP 204 was received through this node's temporary local proxy.".to_string(),
            tested_url: Some(tested_url),
        }),
        Err(detail) => Ok(ProbeOutcome {
            config_status: "valid".to_string(),
            config_detail: "sing-box accepted the generated configuration.".to_string(),
            real_delay_ms: None,
            real_delay_detail: detail,
            tested_url: None,
        }),
    }
}

fn pick_loopback_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|_| "Could not reserve a loopback port for the temporary proxy.".to_string())?;
    let port = listener
        .local_addr()
        .map_err(|_| "Could not read the temporary loopback port.".to_string())?
        .port();
    drop(listener);
    Ok(port)
}

async fn wait_for_local_socks(child: &mut Child, port: u16) -> Result<(), String> {
    let address = ("127.0.0.1", port);
    for _ in 0..100 {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(format!(
                    "The temporary sing-box process exited before its local proxy was ready (code: {}).",
                    status.code().map(|code| code.to_string()).unwrap_or_else(|| "unknown".to_string())
                ));
            }
            Ok(None) => {}
            Err(_) => return Err("Could not inspect the temporary sing-box process.".to_string()),
        }

        if let Ok(Ok(stream)) =
            timeout(Duration::from_millis(200), TcpStream::connect(address)).await
        {
            drop(stream);
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }

    Err("The temporary sing-box local proxy did not become ready within 10 seconds.".to_string())
}

async fn measure_request_through_socks(port: u16) -> Result<(u64, String), String> {
    let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
        .map_err(|_| "Could not configure the isolated SOCKS5 probe proxy.".to_string())?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .connect_timeout(Duration::from_secs(6))
        .timeout(REAL_DELAY_REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "Could not create the isolated HTTP probe client.".to_string())?;

    let mut failures = Vec::new();
    for url in [REAL_DELAY_PRIMARY_URL, REAL_DELAY_FALLBACK_URL] {
        let started = Instant::now();
        let response = client
            .get(url)
            .header("Cache-Control", "no-cache")
            .send()
            .await;

        match response {
            Ok(response) if response.status() == reqwest::StatusCode::NO_CONTENT => {
                let elapsed = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
                return Ok((elapsed, url.to_string()));
            }
            Ok(response) => failures.push(format!(
                "{} returned HTTP {} instead of 204",
                url,
                response.status().as_u16()
            )),
            Err(error) if error.is_timeout() => {
                failures.push(format!("{url} timed out"));
            }
            Err(error) if error.is_connect() => {
                failures.push(format!("{url} could not connect through the proxy"));
            }
            Err(_) => failures.push(format!("{url} failed through the proxy")),
        }
    }

    Err(format!(
        "Real Delay failed: {}. The proxy protocol, credentials, remote server, DNS, or TLS may be unavailable.",
        failures.join("; ")
    ))
}

async fn stop_probe_process(child: &mut Child) -> Result<(), String> {
    match child.try_wait() {
        Ok(Some(_)) => Ok(()),
        Ok(None) => {
            child
                .start_kill()
                .map_err(|_| "Could not stop the temporary sing-box process.".to_string())?;
            timeout(Duration::from_secs(4), child.wait())
                .await
                .map_err(|_| "The temporary sing-box process did not stop within 4 seconds.".to_string())?
                .map_err(|_| "Could not confirm termination of the temporary sing-box process.".to_string())?;
            Ok(())
        }
        Err(_) => Err("Could not inspect the temporary sing-box process during cleanup.".to_string()),
    }
}

async fn cleanup_probe_dir(path: &Path) -> Result<(), String> {
    if path.exists() {
        tokio::fs::remove_dir_all(path)
            .await
            .map_err(|_| "Temporary preflight files could not be removed; connection startup must remain blocked.".to_string())?;
    }
    Ok(())
}


#[cfg(test)]
mod runtime_guard_tests {
    use super::*;

    #[test]
    fn installed_version_check_requires_an_exact_version_token() {
        assert!(matches_expected_engine_version("sing-box version 1.14.4"));
        assert!(matches_expected_engine_version("sing-box version v1.14.4"));
        assert!(!matches_expected_engine_version("sing-box version 1.14.40"));
        assert!(!matches_expected_engine_version("sing-box version 1.14.3"));
        assert!(!matches_expected_engine_version("sing-box version 1.14.4-beta"));
        assert!(!matches_expected_engine_version("sing-box version vv1.14.4"));
        assert!(!matches_expected_engine_version("sing-box version 1.14.4v"));
    }

    #[test]
    fn diagnostics_redact_short_credentials() {
        let credentials = BTreeMap::from([("password".to_string(), "s3!".to_string())]);
        let diagnostic = redact_diagnostic("invalid password value: s3!", &credentials);

        assert!(!diagnostic.contains("s3!"));
        assert!(diagnostic.contains("[redacted]"));
    }
}
