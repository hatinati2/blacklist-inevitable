use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

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

    let mut outbound = Map::new();
    outbound.insert("type".to_string(), json!(profile.protocol));
    outbound.insert("tag".to_string(), json!(OUTBOUND_TAG));
    outbound.insert("server".to_string(), json!(profile.server));
    outbound.insert("server_port".to_string(), json!(profile.port));

    match profile.protocol.as_str() {
        "vless" => {
            outbound.insert("uuid".to_string(), json!(required(credentials, "uuid")?));
            insert_option(&mut outbound, "flow", &profile.options, "flow");
            insert_tls(&mut outbound, profile, false)?;
            insert_transport(&mut outbound, &profile.options)?;
        }
        "vmess" => {
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
            outbound.insert("password".to_string(), json!(required(credentials, "password")?));
            insert_tls(&mut outbound, profile, true)?;
            insert_transport(&mut outbound, &profile.options)?;
        }
        "shadowsocks" => {
            outbound.insert(
                "method".to_string(),
                json!(profile.options.get("method").ok_or_else(|| "Shadowsocks encryption method is missing.".to_string())?),
            );
            outbound.insert("password".to_string(), json!(required(credentials, "password")?));
        }
        "hysteria2" => {
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

    if !tls_enabled {
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
        "" | "tcp" | "raw" => return Ok(()),
        "ws" | "websocket" => {
            let mut headers = Map::new();
            if let Some(host) = host {
                headers.insert("Host".to_string(), json!(host));
            }
            json!({"type":"ws","path":path,"headers":headers})
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
        }
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
