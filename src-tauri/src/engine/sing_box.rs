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

    #[test]
    fn maps_hysteria2_password_obfuscation_and_tls() {
        let mut profile = sample_profile("hysteria2");
        profile.options = BTreeMap::from([
            ("sni".to_string(), "hy2.example.org".to_string()),
            ("obfs".to_string(), "salamander".to_string()),
        ]);
        let credentials = BTreeMap::from([
            ("password".to_string(), "hy2-secret".to_string()),
            ("obfsPassword".to_string(), "obfs-secret".to_string()),
        ]);
        let config = build_probe_config(&profile, &credentials, 10080).unwrap();
        let outbound = &config["outbounds"][0];

        assert_eq!(outbound["type"], "hysteria2");
        assert_eq!(outbound["password"], "hy2-secret");
        assert_eq!(outbound["obfs"]["type"], "salamander");
        assert_eq!(outbound["obfs"]["password"], "obfs-secret");
        assert_eq!(outbound["tls"]["enabled"], true);
        assert_eq!(outbound["tls"]["server_name"], "hy2.example.org");
    }

    #[test]
    fn maps_tuic_credentials_congestion_and_relay_mode() {
        let mut profile = sample_profile("tuic");
        profile.options = BTreeMap::from([
            ("congestion_control".to_string(), "bbr".to_string()),
            ("udp_relay_mode".to_string(), "quic".to_string()),
            ("sni".to_string(), "tuic.example.org".to_string()),
        ]);
        let credentials = BTreeMap::from([
            ("uuid".to_string(), "12345678-1234-1234-1234-123456789012".to_string()),
            ("password".to_string(), "tuic-secret".to_string()),
        ]);
        let config = build_probe_config(&profile, &credentials, 10080).unwrap();
        let outbound = &config["outbounds"][0];

        assert_eq!(outbound["type"], "tuic");
        assert_eq!(outbound["uuid"], "12345678-1234-1234-1234-123456789012");
        assert_eq!(outbound["password"], "tuic-secret");
        assert_eq!(outbound["congestion_control"], "bbr");
        assert_eq!(outbound["udp_relay_mode"], "quic");
        assert_eq!(outbound["tls"]["enabled"], true);
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

#[derive(Debug)]
enum EngineCommandError {
    Spawn,
    Containment(String),
    TimedOut,
    Wait,
}

impl EngineCommandError {
    fn message(self, label: &str) -> String {
        match self {
            Self::Spawn => format!("Could not start {label}."),
            Self::Containment(error) => error,
            Self::TimedOut => format!(
                "{label} timed out; child termination could not be confirmed."
            ),
            Self::Wait => format!(
                "Could not collect {label} output; child termination could not be confirmed."
            ),
        }
    }
}

/// Starts an engine command, assigns it to the app-owned Windows Job Object,
/// then collects output under a hard timeout. The job is the crash-time
/// containment backstop; kill_on_drop remains the per-command fallback.
async fn run_engine_command_output(
    command: &mut Command,
    supervisor: &ProcessSupervisor,
    command_timeout: Duration,
) -> Result<std::process::Output, EngineCommandError> {
    supervisor.prepare_child_command(command);
    let mut child = command.spawn().map_err(|_| EngineCommandError::Spawn)?;
    supervisor
        .assign_child(&mut child)
        .await
        .map_err(EngineCommandError::Containment)?;

    match timeout(command_timeout, child.wait_with_output()).await {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(_)) => {
            supervisor.mark_cleanup_unhealthy();
            Err(EngineCommandError::Wait)
        }
        Err(_) => {
            supervisor.mark_cleanup_unhealthy();
            Err(EngineCommandError::TimedOut)
        }
    }
}


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

pub async fn is_installed(app: &AppHandle, supervisor: &ProcessSupervisor) -> bool {
    let Ok(path) = installed_binary_path(app) else {
        return false;
    };
    if !path.is_file() {
        return false;
    }
    read_engine_version(&path, supervisor)
        .await
        .map(|reported| matches_expected_engine_version(&reported))
        .unwrap_or(false)
}

fn matches_expected_engine_version(reported: &str) -> bool {
    reported.split_whitespace().any(|token| {
        token == SING_BOX_VERSION || token.strip_prefix('v') == Some(SING_BOX_VERSION)
    })
}

pub async fn install(app: &AppHandle, supervisor: &ProcessSupervisor) -> Result<String, String> {
    let binary_path = installed_binary_path(app)?;
    if binary_path.is_file() {
        match read_engine_version(&binary_path, supervisor).await {
            Ok(version) if matches_expected_engine_version(&version) => return Ok(version),
            // A timeout means the previous version-check child may not have been
            // reaped. Do not download/replace an engine while cleanup is uncertain.
            Err(error) if error.contains("timed out") => return Err(error),
            _ => {}
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

    let version = match read_engine_version(&temporary_binary, supervisor).await {
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
        if !entry.is_file() {
            continue;
        }
        let entry_name = entry
            .name()
            .map_err(|_| "Could not read an entry name in the sing-box release archive.".to_string())?;
        if Path::new(entry_name.as_ref())
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

async fn read_engine_version(
    binary: &Path,
    supervisor: &ProcessSupervisor,
) -> Result<String, String> {
    let output = run_engine_command_output(
        Command::new(binary)
            .arg("version")
            .stdout(Stdio::piped())
            .stderr(Stdio::null()),
        supervisor,
        Duration::from_secs(10),
    )
    .await
    .map_err(|error| error.message("The sing-box version check"))?;

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

    let command_result = run_engine_command_output(
        Command::new(&binary)
            .arg("check")
            .arg("-c")
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
        supervisor,
        CONFIG_CHECK_TIMEOUT,
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
        Err(error) => Err(error.message("sing-box config validation")),
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
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

    let validation = run_engine_command_output(
        Command::new(&binary)
            .arg("check")
            .arg("-c")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped()),
        supervisor,
        CONFIG_CHECK_TIMEOUT,
    )
    .await;

    let validation = match validation {
        Err(EngineCommandError::TimedOut) => {
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
        Err(error) => {
            cleanup_probe_dir(&run_dir).await?;
            return Err(error.message("sing-box configuration validation"));
        }
        Ok(output) if output.status.success() => output,
        Ok(output) => {
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

    let mut run_command = Command::new(&binary);
    run_command
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    supervisor.prepare_child_command(&mut run_command);
    let mut child = match run_command.spawn() {
        Ok(child) => child,
        Err(_) => {
            cleanup_probe_dir(&run_dir).await?;
            return Err("Could not start the temporary sing-box probe process.".to_string());
        }
    };

    if let Err(error) = supervisor.assign_child(&mut child).await {
        cleanup_probe_dir(&run_dir).await?;
        return Err(error);
    }

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
    wait_for_local_socks_with_timeout(child, port, ENGINE_START_TIMEOUT).await
}

async fn wait_for_local_socks_with_timeout(
    child: &mut Child,
    port: u16,
    startup_timeout: Duration,
) -> Result<(), String> {
    let address = ("127.0.0.1", port);
    let startup = timeout(startup_timeout, async {
        loop {
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
    })
    .await;

    match startup {
        Ok(result) => result,
        Err(_) => Err(format!(
            "The temporary sing-box local proxy did not become ready within {} seconds.",
            startup_timeout.as_secs()
        )),
    }
}

async fn measure_request_through_socks(port: u16) -> Result<(u64, String), String> {
    let client = build_probe_http_client(port, REAL_DELAY_REQUEST_TIMEOUT)?;
    measure_request_with_client(&client, &[REAL_DELAY_PRIMARY_URL, REAL_DELAY_FALLBACK_URL]).await
}

fn build_probe_http_client(
    port: u16,
    request_timeout: Duration,
) -> Result<reqwest::Client, String> {
    let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
        .map_err(|_| "Could not configure the isolated SOCKS5 probe proxy.".to_string())?;
    reqwest::Client::builder()
        .proxy(proxy)
        .connect_timeout(Duration::from_secs(6))
        .timeout(request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "Could not create the isolated HTTP probe client.".to_string())
}

async fn measure_request_with_client(
    client: &reqwest::Client,
    urls: &[&str],
) -> Result<(u64, String), String> {
    let mut failures = Vec::new();
    for url in urls {
        let started = Instant::now();
        let response = client
            .get(*url)
            .header("Cache-Control", "no-cache")
            .send()
            .await;

        match response {
            Ok(response) if response.status() == reqwest::StatusCode::NO_CONTENT => {
                let elapsed = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
                return Ok((elapsed, (*url).to_string()));
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

    const CONFIG_CHECK_CHILD_STARTED_ENV: &str = "BLACKLIST_INEVITABLE_CONFIG_CHECK_CHILD_STARTED";
    const CONFIG_CHECK_CHILD_FINISHED_ENV: &str = "BLACKLIST_INEVITABLE_CONFIG_CHECK_CHILD_FINISHED";

    #[test]
    fn bounded_config_check_child_process() {
        let Some(started_path) = std::env::var_os(CONFIG_CHECK_CHILD_STARTED_ENV) else {
            return;
        };
        let finished_path = std::env::var_os(CONFIG_CHECK_CHILD_FINISHED_ENV)
            .expect("config-check child finished marker path");

        std::fs::write(started_path, b"started").expect("publish config-check start");
        std::thread::sleep(Duration::from_millis(900));
        std::fs::write(finished_path, b"finished").expect("publish config-check completion");
    }

    fn bounded_config_check_child_command(started_path: &Path, finished_path: &Path) -> Command {
        let executable = std::env::current_exe().expect("resolve current test executable");
        let mut command = Command::new(executable);
        command
            .args([
                "--exact",
                "engine::sing_box::runtime_guard_tests::bounded_config_check_child_process",
                "--nocapture",
            ])
            .env(CONFIG_CHECK_CHILD_STARTED_ENV, started_path)
            .env(CONFIG_CHECK_CHILD_FINISHED_ENV, finished_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    #[tokio::test]
    async fn graceful_shutdown_waits_for_bounded_config_check_child_to_finish() {
        let supervisor = ProcessSupervisor::default();
        let operation = supervisor
            .begin_operation()
            .expect("register config-check operation");
        let root = std::env::temp_dir().join(format!(
            "blacklist-inevitable-config-check-shutdown-{}",
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create config-check test directory");
        let started_path = root.join("child.started");
        let finished_path = root.join("child.finished");
        let mut command = bounded_config_check_child_command(&started_path, &finished_path);
        let worker_supervisor = supervisor.clone();

        let worker = tokio::spawn(async move {
            let output = run_engine_command_output(
                &mut command,
                &worker_supervisor,
                Duration::from_secs(5),
            )
            .await
            .expect("bounded config check should finish before its hard timeout");
            assert!(output.status.success(), "config-check child should exit successfully");
            drop(operation);
        });

        timeout(Duration::from_secs(10), async {
            while !started_path.is_file() {
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("config-check child should start before shutdown");

        assert!(supervisor.request_shutdown(), "first shutdown request must win");
        assert!(
            supervisor.begin_operation().is_err(),
            "shutdown must reject new engine operations"
        );
        assert!(
            timeout(Duration::from_millis(150), supervisor.wait_for_idle())
                .await
                .is_err(),
            "shutdown must continue waiting while bounded config validation is running"
        );

        timeout(Duration::from_secs(5), worker)
            .await
            .expect("config-check worker should complete")
            .expect("config-check worker task should not panic");
        assert_eq!(
            std::fs::read(&finished_path).expect("read config-check completion marker"),
            b"finished",
            "the child must finish its bounded validation before the operation lease is released"
        );
        assert!(
            timeout(Duration::from_secs(5), supervisor.wait_for_idle())
                .await
                .expect("supervisor should drain after config-check child exits"),
            "normal config-check completion must leave cleanup healthy"
        );
        assert!(
            supervisor.shutdown_complete(),
            "shutdown is complete only after the config-check operation releases its lease"
        );

        std::fs::remove_dir_all(root).expect("remove config-check test directory");
    }


    #[cfg(windows)]
    const SLEEPING_CHILD_PID_ENV: &str = "BLACKLIST_INEVITABLE_PREFLIGHT_CHILD_PID_PATH";

    #[cfg(windows)]
    #[test]
    fn sleeping_preflight_child_process() {
        let Some(path) = std::env::var_os(SLEEPING_CHILD_PID_ENV) else {
            return;
        };

        std::fs::write(path, std::process::id().to_string())
            .expect("write sleeping child PID");
        std::thread::sleep(Duration::from_secs(30));
    }

    #[cfg(windows)]
    fn sleeping_child_command(pid_path: &Path) -> Command {
        let executable = std::env::current_exe().expect("resolve current test executable");
        let mut command = Command::new(executable);
        command
            .args([
                "--exact",
                "engine::sing_box::runtime_guard_tests::sleeping_preflight_child_process",
                "--nocapture",
            ])
            .env(SLEEPING_CHILD_PID_ENV, pid_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    #[cfg(windows)]
    async fn wait_for_child_pid(path: &Path) -> u32 {
        timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(value) = tokio::fs::read_to_string(path).await {
                    if let Ok(pid) = value.trim().parse::<u32>() {
                        return pid;
                    }
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("sleeping child should publish its PID")
    }

    #[cfg(windows)]
    fn windows_process_is_active(pid: u32) -> Result<bool, String> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return Ok(false);
        }

        let mut exit_code = 0;
        let queried = unsafe { GetExitCodeProcess(process, &mut exit_code) };
        let error = if queried == 0 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        unsafe { CloseHandle(process) };

        match error {
            Some(error) => Err(format!("GetExitCodeProcess({pid}) failed: {error}")),
            None => Ok(exit_code == 259), // STILL_ACTIVE
        }
    }

    #[cfg(windows)]
    async fn wait_for_child_exit(pid: u32) {
        timeout(Duration::from_secs(5), async {
            loop {
                if !windows_process_is_active(pid).expect("query child process state") {
                    return;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("preflight child should have exited after cleanup");
    }

    #[test]
    fn probe_config_drop_guard_removes_credential_bearing_file() {
        let supervisor = ProcessSupervisor::default();
        let root = std::env::temp_dir().join(format!(
            "blacklist-inevitable-config-cleanup-{}",
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create test cache");
        let path = root.join("config.json");
        std::fs::write(&path, br#"{"password":"test-secret"}"#)
            .expect("write test config");

        drop(ProbeConfigFile {
            path: path.clone(),
            supervisor: supervisor.clone(),
        });

        assert!(!path.exists(), "credential-bearing config must be deleted on Drop");
        assert!(supervisor.cleanup_healthy());
        std::fs::remove_dir_all(root).expect("remove test cache");
    }

    #[test]
    fn probe_config_drop_guard_marks_cleanup_unhealthy_on_removal_failure() {
        let supervisor = ProcessSupervisor::default();
        let path = std::env::temp_dir().join(format!(
            "blacklist-inevitable-config-not-a-file-{}",
            Uuid::new_v4()
        ));
        std::fs::create_dir(&path).expect("create directory at config path");

        drop(ProbeConfigFile {
            path: path.clone(),
            supervisor: supervisor.clone(),
        });

        assert!(!supervisor.cleanup_healthy(), "failed credential cleanup must close the safety gate");
        std::fs::remove_dir(path).expect("remove test directory");
    }

    #[test]
    fn probe_directory_drop_guard_removes_nested_temporary_files() {
        let supervisor = ProcessSupervisor::default();
        let path = std::env::temp_dir().join(format!(
            "blacklist-inevitable-probe-cleanup-{}",
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(path.join("nested")).expect("create nested probe directory");
        std::fs::write(path.join("nested").join("config.json"), b"test").expect("write test config");

        drop(ProbeDirectory {
            path: path.clone(),
            supervisor: supervisor.clone(),
        });

        assert!(!path.exists(), "probe Drop guard must remove its entire temporary tree");
        assert!(supervisor.cleanup_healthy());
    }

    #[test]
    fn probe_directory_drop_guard_marks_cleanup_unhealthy_on_removal_failure() {
        let supervisor = ProcessSupervisor::default();
        let path = std::env::temp_dir().join(format!(
            "blacklist-inevitable-probe-not-a-directory-{}",
            Uuid::new_v4()
        ));
        std::fs::write(&path, b"not a directory").expect("create regular file");

        drop(ProbeDirectory {
            path: path.clone(),
            supervisor: supervisor.clone(),
        });

        assert!(!supervisor.cleanup_healthy(), "failed directory cleanup must close the safety gate");
        std::fs::remove_file(path).expect("remove test file");
    }

    #[tokio::test]
    async fn cleanup_probe_dir_is_idempotent_for_an_absent_directory() {
        let path = std::env::temp_dir().join(format!(
            "blacklist-inevitable-absent-probe-{}",
            Uuid::new_v4()
        ));

        cleanup_probe_dir(&path)
            .await
            .expect("cleanup should accept an already-removed probe directory");
        assert!(!path.exists());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn config_check_timeout_kills_child_and_marks_runtime_unhealthy() {
        let supervisor = ProcessSupervisor::default();
        let pid_path = std::env::temp_dir().join(format!(
            "blacklist-inevitable-config-timeout-child-{}.txt",
            Uuid::new_v4()
        ));
        let mut command = sleeping_child_command(&pid_path);

        let result = run_engine_command_output(
            &mut command,
            &supervisor,
            Duration::from_secs(2),
        )
        .await;

        assert!(matches!(result, Err(EngineCommandError::TimedOut)));
        assert!(!supervisor.cleanup_healthy(), "an unconfirmed config timeout must close the safety gate");
        let pid = wait_for_child_pid(&pid_path).await;
        wait_for_child_exit(pid).await;
        std::fs::remove_file(pid_path).expect("remove child PID marker");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn proxy_startup_timeout_stops_child_and_removes_probe_directory() {
        let supervisor = ProcessSupervisor::default();
        let root = std::env::temp_dir().join(format!(
            "blacklist-inevitable-startup-timeout-{}",
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create probe directory");
        let _directory_guard = ProbeDirectory {
            path: root.clone(),
            supervisor: supervisor.clone(),
        };

        let pid_path = root.join("child.pid");
        let mut command = sleeping_child_command(&pid_path);
        supervisor.prepare_child_command(&mut command);
        let mut child = command.spawn().expect("spawn supervised preflight child");
        supervisor
            .assign_child(&mut child)
            .await
            .expect("contain preflight child before startup test");

        let pid = wait_for_child_pid(&pid_path).await;
        let unused_listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("reserve loopback port");
        let unused_port = unused_listener.local_addr().expect("read loopback port").port();
        drop(unused_listener);

        let startup = wait_for_local_socks_with_timeout(
            &mut child,
            unused_port,
            Duration::from_millis(250),
        )
        .await;
        assert!(
            startup
                .as_ref()
                .is_err_and(|error| error.contains("did not become ready")),
            "a proxy that never listens must time out"
        );

        stop_probe_process(&mut child)
            .await
            .expect("startup timeout must stop and reap the child");
        assert!(
            child.try_wait().expect("inspect stopped child").is_some(),
            "the child must be reaped after startup timeout"
        );
        cleanup_probe_dir(&root)
            .await
            .expect("remove credential-bearing probe directory");
        assert!(!root.exists(), "probe files must be gone after timeout cleanup");
        wait_for_child_exit(pid).await;
    }

    #[cfg(windows)]
    const LISTENER_CHILD_READY_ENV: &str = "BLACKLIST_INEVITABLE_PREFLIGHT_LISTENER_READY_PATH";

    #[cfg(windows)]
    #[test]
    fn listening_preflight_child_process() {
        let Some(path) = std::env::var_os(LISTENER_CHILD_READY_ENV) else {
            return;
        };

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("bind controlled preflight listener");
        let port = listener
            .local_addr()
            .expect("read controlled listener address")
            .port();
        std::fs::write(path, port.to_string()).expect("publish controlled listener port");
        std::thread::sleep(Duration::from_secs(30));
        drop(listener);
    }

    #[cfg(windows)]
    fn listening_child_command(ready_path: &Path) -> Command {
        let executable = std::env::current_exe().expect("resolve current test executable");
        let mut command = Command::new(executable);
        command
            .args([
                "--exact",
                "engine::sing_box::runtime_guard_tests::listening_preflight_child_process",
                "--nocapture",
            ])
            .env(LISTENER_CHILD_READY_ENV, ready_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    #[cfg(windows)]
    async fn wait_for_listener_port(path: &Path) -> u16 {
        timeout(Duration::from_secs(10), async {
            loop {
                if let Ok(value) = tokio::fs::read_to_string(path).await {
                    if let Ok(port) = value.trim().parse::<u16>() {
                        return port;
                    }
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("controlled child should publish its listening port")
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn stopping_preflight_child_releases_its_loopback_listener() {
        let supervisor = ProcessSupervisor::default();
        let root = std::env::temp_dir().join(format!(
            "blacklist-inevitable-listener-cleanup-{}",
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create listener test directory");
        let ready_path = root.join("listener.port");
        let mut command = listening_child_command(&ready_path);
        supervisor.prepare_child_command(&mut command);
        let mut child = command.spawn().expect("spawn supervised listener child");
        supervisor
            .assign_child(&mut child)
            .await
            .expect("contain listener child before it can run");

        let port = wait_for_listener_port(&ready_path).await;
        let address = ("127.0.0.1", port);
        let connection = timeout(Duration::from_secs(2), TcpStream::connect(address))
            .await
            .expect("listener connection timed out")
            .expect("controlled child should accept loopback connections");
        drop(connection);

        stop_probe_process(&mut child)
            .await
            .expect("stop and reap listener child");
        assert!(
            child.try_wait().expect("inspect listener child").is_some(),
            "listener child must be reaped before checking the port"
        );

        assert!(
            TcpStream::connect(address).await.is_err(),
            "the stopped child must no longer accept connections on its former port"
        );
        let released_listener = timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(listener) = std::net::TcpListener::bind(address) {
                    return listener;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("loopback port must become bindable after child exit");
        drop(released_listener);
        std::fs::remove_dir_all(root).expect("remove listener test directory");
    }


    #[cfg(windows)]
    #[tokio::test]
    async fn graceful_shutdown_during_proxy_startup_stops_child_and_cleans_probe_files() {
        use tokio::sync::oneshot;

        let supervisor = ProcessSupervisor::default();
        let operation = supervisor
            .begin_operation()
            .expect("register Real Delay startup operation");
        let root = std::env::temp_dir().join(format!(
            "blacklist-inevitable-startup-shutdown-{}",
            Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create probe directory");
        let config_path = root.join("config.json");
        std::fs::write(&config_path, br#"{"password":"test-only-secret"}"#)
            .expect("write credential-bearing test config");

        let ready_path = root.join("listener.port");
        let mut command = listening_child_command(&ready_path);
        supervisor.prepare_child_command(&mut command);
        let mut child = command.spawn().expect("spawn supervised proxy startup child");
        supervisor
            .assign_child(&mut child)
            .await
            .expect("contain proxy startup child before it can run");
        let child_pid = child.id().expect("read proxy startup child PID");

        let listener_port = wait_for_listener_port(&ready_path).await;
        let listener_address = ("127.0.0.1", listener_port);
        let connection = timeout(Duration::from_secs(2), TcpStream::connect(listener_address))
            .await
            .expect("controlled startup child listener timed out")
            .expect("controlled startup child must be listening");
        drop(connection);

        // This port remains unbound, so the startup waiter cannot mistake the
        // helper's separate listener for a ready SOCKS proxy.
        let unavailable_listener =
            std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve startup probe port");
        let startup_port = unavailable_listener
            .local_addr()
            .expect("read startup probe port")
            .port();
        drop(unavailable_listener);

        let (startup_wait_started_tx, startup_wait_started_rx) = oneshot::channel();
        let (cleanup_paused_tx, cleanup_paused_rx) = oneshot::channel();
        let (allow_cleanup_tx, allow_cleanup_rx) = oneshot::channel();
        let worker_root = root.clone();

        let worker = tokio::spawn(async move {
            let _ = startup_wait_started_tx.send(());
            let cancelled = tokio::select! {
                _ = operation.cancelled() => true,
                result = wait_for_local_socks_with_timeout(
                    &mut child,
                    startup_port,
                    Duration::from_secs(30),
                ) => {
                    panic!("proxy startup should be cancelled, not complete: {result:?}");
                }
            };

            stop_probe_process(&mut child)
                .await
                .expect("shutdown must stop and reap the proxy startup child");
            assert!(
                child.try_wait().expect("inspect stopped startup child").is_some(),
                "startup child must be reaped before its operation lease is released"
            );

            // Hold the lease after process cleanup to prove the supervisor also
            // waits for the credential-bearing directory cleanup below.
            let _ = cleanup_paused_tx.send(());
            allow_cleanup_rx
                .await
                .expect("test must release the temporary-file cleanup gate");
            cleanup_probe_dir(&worker_root)
                .await
                .expect("shutdown must remove the temporary probe directory");
            drop(operation);
            cancelled
        });

        startup_wait_started_rx
            .await
            .expect("startup worker should enter the readiness wait");
        // Allow the readiness loop to make at least one failed connection
        // attempt before requesting shutdown.
        sleep(Duration::from_millis(150)).await;

        assert!(
            supervisor.request_shutdown(),
            "the first shutdown request must begin cancellation"
        );
        assert!(
            supervisor.begin_operation().is_err(),
            "new engine operations must be rejected after shutdown starts"
        );
        let drain_supervisor = supervisor.clone();
        let drain = tokio::spawn(async move { drain_supervisor.wait_for_idle().await });

        timeout(Duration::from_secs(5), cleanup_paused_rx)
            .await
            .expect("startup child cleanup should reach the directory-cleanup gate")
            .expect("startup worker should signal completed process cleanup");
        assert!(
            !drain.is_finished(),
            "shutdown must keep waiting while the temporary probe directory still exists"
        );
        assert!(root.exists(), "temporary config must remain until its cleanup completes");

        wait_for_child_exit(child_pid).await;
        assert!(
            TcpStream::connect(listener_address).await.is_err(),
            "shutdown must release the child-owned listener"
        );
        let released_listener = timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(listener) = std::net::TcpListener::bind(listener_address) {
                    return listener;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("listener port must be reusable after startup child termination");
        drop(released_listener);

        allow_cleanup_tx
            .send(())
            .expect("release temporary-file cleanup gate");
        assert!(
            timeout(Duration::from_secs(5), drain)
                .await
                .expect("supervisor should drain after probe directory cleanup")
                .expect("supervisor drain task should not panic"),
            "successful startup cancellation must leave cleanup healthy"
        );
        assert!(
            worker.await.expect("startup cancellation worker should not panic"),
            "the readiness wait must observe graceful shutdown cancellation"
        );
        assert!(!root.exists(), "credential-bearing probe files must be removed");
        assert!(
            supervisor.shutdown_complete(),
            "shutdown completes only after child and temporary-file cleanup"
        );
        assert!(supervisor.cleanup_healthy());
    }

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


#[cfg(test)]
mod socks_probe_cancellation_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::mpsc::{self, Receiver};

    fn start_stalled_socks_proxy() -> (
        u16,
        Receiver<()>,
        Receiver<bool>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("bind local SOCKS5 test proxy");
        let port = listener.local_addr().expect("read proxy address").port();
        let (connected_tx, connected_rx) = mpsc::channel();
        let (disconnected_tx, disconnected_rx) = mpsc::channel();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept SOCKS5 client");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set bounded proxy read timeout");

            let mut greeting = [0_u8; 2];
            stream.read_exact(&mut greeting).expect("read SOCKS5 greeting");
            assert_eq!(greeting[0], 5, "client must negotiate SOCKS5");
            let mut methods = vec![0_u8; greeting[1] as usize];
            stream.read_exact(&mut methods).expect("read SOCKS5 methods");
            assert!(methods.contains(&0), "client must offer no-auth SOCKS5");
            stream.write_all(&[5, 0]).expect("accept no-auth SOCKS5");

            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).expect("read SOCKS5 CONNECT request");
            assert_eq!(&request[..3], &[5, 1, 0]);
            match request[3] {
                1 => {
                    let mut address = [0_u8; 4];
                    stream.read_exact(&mut address).expect("read IPv4 destination");
                }
                3 => {
                    let mut length = [0_u8; 1];
                    stream.read_exact(&mut length).expect("read domain length");
                    let mut address = vec![0_u8; length[0] as usize];
                    stream.read_exact(&mut address).expect("read domain destination");
                }
                4 => {
                    let mut address = [0_u8; 16];
                    stream.read_exact(&mut address).expect("read IPv6 destination");
                }
                atyp => panic!("unexpected SOCKS5 address type: {atyp}"),
            }
            let mut destination_port = [0_u8; 2];
            stream
                .read_exact(&mut destination_port)
                .expect("read destination port");

            // Tell reqwest that the SOCKS tunnel is established, but deliberately
            // never send an HTTP response. This holds the request inside the
            // controlled proxy so timeout and future cancellation are observable.
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .expect("complete SOCKS5 handshake");

            // Wait until the HTTP request has crossed the SOCKS tunnel. Tests
            // may then trigger cancellation knowing the request is truly in flight,
            // not merely waiting for SOCKS negotiation to complete.
            let mut buffer = [0_u8; 1024];
            let request_bytes = stream
                .read(&mut buffer)
                .expect("receive HTTP probe request");
            assert!(request_bytes > 0, "HTTP probe request must reach the proxy");
            assert!(
                buffer[..request_bytes].starts_with(b"GET "),
                "the tunneled payload must be the HTTP probe request"
            );
            connected_tx.send(()).expect("notify received HTTP request");

            let disconnected_cleanly = loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break true,
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break false,
                }
            };
            let _ = disconnected_tx.send(disconnected_cleanly);
        });

        (port, connected_rx, disconnected_rx, server)
    }

    async fn receive_signal<T: Send + 'static>(receiver: Receiver<T>) -> T {
        tokio::task::spawn_blocking(move || {
            receiver
                .recv_timeout(Duration::from_secs(4))
                .expect("SOCKS5 test proxy signal timeout")
        })
        .await
        .expect("SOCKS5 signal worker panicked")
    }

    #[tokio::test]
    async fn http_probe_request_times_out_inside_controlled_socks_proxy() {
        let (port, connected, disconnected, server) = start_stalled_socks_proxy();
        let client = build_probe_http_client(port, Duration::from_secs(1))
            .expect("build test HTTP client");
        let request_client = client.clone();
        let request = tokio::spawn(async move {
            measure_request_with_client(&request_client, &["http://probe.invalid/generate_204"])
                .await
        });

        // Wait for a completed SOCKS5 handshake before evaluating the HTTP timeout,
        // so slow Windows scheduling cannot turn this into a pre-connect timeout test.
        receive_signal(connected).await;
        let result = tokio::time::timeout(Duration::from_secs(4), request)
            .await
            .expect("HTTP request timeout test did not finish")
            .expect("HTTP request task panicked");
        assert!(
            result.unwrap_err().contains("timed out"),
            "a stalled upstream response must be reported as a timeout"
        );
        assert!(
            receive_signal(disconnected).await,
            "the HTTP timeout must release the SOCKS tunnel while the client remains alive"
        );
        drop(client);
        server.join().expect("join SOCKS5 test proxy");
    }

    #[tokio::test]
    async fn graceful_shutdown_cancels_http_probe_and_waits_for_socks_release() {
        let (port, connected, disconnected, server) = start_stalled_socks_proxy();
        let supervisor = ProcessSupervisor::default();
        let mut operation = supervisor
            .begin_operation()
            .expect("register active Real Delay operation");
        let client = build_probe_http_client(port, Duration::from_secs(30))
            .expect("build test HTTP client");
        let request_client = client.clone();
        let worker = tokio::spawn(async move {
            let cancelled = tokio::select! {
                _ = operation.cancelled() => true,
                result = measure_request_with_client(
                    &request_client,
                    &["http://probe.invalid/generate_204"],
                ) => {
                    panic!("stalled HTTP request completed before shutdown: {result:?}");
                }
            };

            // The select branch drops the in-flight request future before the
            // operation lease is released. Keep the test's other client clone
            // alive so tunnel release cannot be attributed to Client::drop.
            drop(request_client);
            drop(operation);
            cancelled
        });

        receive_signal(connected).await;
        assert!(supervisor.request_shutdown(), "first shutdown request must win");
        assert!(
            supervisor.begin_operation().is_err(),
            "shutdown must reject new engine operations"
        );

        let cleanup_healthy = tokio::time::timeout(
            Duration::from_secs(4),
            supervisor.wait_for_idle(),
        )
        .await
        .expect("supervisor did not drain the cancelled HTTP operation");
        assert!(cleanup_healthy, "HTTP cancellation must leave runtime cleanup healthy");
        assert!(supervisor.shutdown_complete(), "shutdown must finish after cleanup");
        assert!(
            worker.await.expect("HTTP probe worker panicked"),
            "the operation must observe graceful shutdown cancellation"
        );
        assert!(
            receive_signal(disconnected).await,
            "graceful shutdown must release the SOCKS tunnel before the operation lease ends"
        );

        drop(client);
        server.join().expect("join SOCKS5 test proxy");
    }

    #[tokio::test]
    async fn cancelling_http_probe_future_releases_controlled_socks_proxy() {
        let (port, connected, disconnected, server) = start_stalled_socks_proxy();
        let client = build_probe_http_client(port, Duration::from_secs(30))
            .expect("build test HTTP client");
        let request_client = client.clone();
        let request = tokio::spawn(async move {
            measure_request_with_client(
                &request_client,
                &["http://probe.invalid/generate_204"],
            )
            .await
        });

        receive_signal(connected).await;
        request.abort();
        let _ = request.await;

        assert!(
            receive_signal(disconnected).await,
            "cancelling the request must release its SOCKS tunnel while the client remains alive"
        );
        drop(client);
        server.join().expect("join SOCKS5 test proxy");
    }
}
