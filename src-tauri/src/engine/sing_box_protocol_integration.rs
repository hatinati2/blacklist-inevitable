use super::{build_probe_config, build_probe_http_client, measure_request_with_client};
use crate::profiles::ProfileSummary;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::net::{TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Child;
use tokio::time::{sleep, timeout};

// Chromium/Naive rejects server certificates valid for more than 398 days.
// A 30-day self-signed certificate is required by Chromium's Naive client.
const TEST_CERTIFICATE: &str = r#"-----BEGIN CERTIFICATE-----
MIIDKTCCAhGgAwIBAgIUa6nTWpQoVSmDtDDdKio9rC1iKSAwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTEyNjAwMDAwMFoXDTI2MTIy
NjAwMDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAwwhj8/toIfaicijKHviKnI2Xl8nHrYaHfIu7+Mx5vi6R
tYXZmmMfDv2pcMxilnxPwlti6gsCrKFDWLYBhlSYrGTqgWuMDSTpO7qqwr1fHDcY
pSl24hsFLzRbBWNKJTJh8nwxD1/X0i6r/GbSyjiyCj145hz+p9rVl6UpTxDQxnCB
0BAbmNGqy8YvvvD2CNIdqoG6XicCMcUkH7/97gt1co7mUS3gGFuWv2tUODkjj8EM
/ShJqbzhTHeyfn9Hh8pqP0BJa9yYEw9Kh2q4RXQkbJ7zctRWSxb8HN6rbxGWFgvo
q13SuH0F7i1FOZxmKlY9jSEHZrb+rrQ7lUWF4zXStwIDAQABo3MwcTAaBgNVHREE
EzARgglsb2NhbGhvc3SHBH8AAAEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E
BAMCAaYwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFDBbut1VMywRkBbt
ypR76WqFjGs3MA0GCSqGSIb3DQEBCwUAA4IBAQBZjVVkPkuGh8ru+C/OElf6+nmc
JU7igRgIVy0jwN7xMN0O6RoCZO7Ax3EnuinryE04jtG+y4NeUyhYQIC5QJanw1TZ
9AtyU5WR6rxEg7aLTFEVjkNooPty2cXES085TB4rDWWRYqDudckNATRcSigrXm2E
cr73XM1TyIqycyYa7VV9e3dB+9+wseppuXTo5PDrNcXzC/Nh/6X2AmvnZBT1yadz
vX3cmPCsL7VrZB93gTpkUV3LgRrJawCHAIM6NcBaEEiuzXrdmgPrfPhvQNOq2i6h
R6dK/XX/OUZzKnmcV8GNGq9XF9ts4xQTB7OPRjgYAxLNUOPcfZko0/sWOSWK
-----END CERTIFICATE-----"#;

const TEST_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDDCGPz+2gh9qJy
KMoe+IqcjZeXycethod8i7v4zHm+LpG1hdmaYx8O/alwzGKWfE/CW2LqCwKsoUNY
tgGGVJisZOqBa4wNJOk7uqrCvV8cNxilKXbiGwUvNFsFY0olMmHyfDEPX9fSLqv8
ZtLKOLIKPXjmHP6n2tWXpSlPENDGcIHQEBuY0arLxi++8PYI0h2qgbpeJwIxxSQf
v/3uC3VyjuZRLeAYW5a/a1Q4OSOPwQz9KEmpvOFMd7J+f0eHymo/QElr3JgTD0qH
arhFdCRsnvNy1FZLFvwc3qtvEZYWC+irXdK4fQXuLUU5nGYqVj2NIQdmtv6utDuV
RYXjNdK3AgMBAAECggEAA6ZDizbiyEfqMEKtIuPkYXDmK56d+umaiBfBSQg30E7k
xnBzwEd8jEuY1mssqRjjETBOldyQ4elpQ4lcVpwnTd/cN4HArs+drFLI4TipRUjj
+tXfdfRVe4BPomEs66yZV+/qUcRUWzLTtbcNg1/eN6zWIfrcP7MrmK6BgGDrLIYO
q8agnLt3eA1lqdGO8cu4o6peZO53eOYNe2R2rvrsBH7OvD6iK34qeo29r1/gm1C+
9QvqN7R9IgoLRb6b58zlHaJv01d0t7xsEVwg8PWytsXQGFrhAk+NUwpaFfZyXQO4
XYiN5dQGCYAOMagoyZ1QtKey7h3QucaLWBwV73xd0QKBgQD7vhsXU8YwrnYRWCqi
hWdVkQl2lqq+REPCI09rypa1T6ahqF8Ro1KLghYIuvrFaJlnxJ6cXohVRYSlsZ3j
K9TX5FLXycyqMKa6j2GialnO/L5LHKslGG0GJLznMWdKOoNxrOFrs/Dup6iOceYb
WU9zg6yLAfn8bbNwEsIdjjG0+QKBgQDGVMPg/Cx8yh5JSjLtSjgaaAdRN0Q8RE5v
8vzWKzFS8Pt+roGe56POEGfS8gcNZSZ5ooqGwQC9mZiGjA2DB6o6xwP2ciEseFVC
SfbuPnmF+mERX6E36HCPfMHacS97W1d3xrI9dz0Ae1A95yjxllh71KAzpaTTlCta
/rNpQa2hLwKBgEYkDcBOIyZlNZhXjGmD6eq5Yn2cNS6WLprk47gQ1jTmYHMiSnrL
mrAsKp98GWrvXe6/pcHDxRCdMfxIpMkq6T7N6xccrt2seIf6cyWhpCw713luH3FS
gO35RnjUFwdjjkQZ+yTbGgIkzJ4Dti1gkPaKdYS1pEVk+136nANIHylhAoGAf+a6
S6VUq0VNMsZ/ATgT5jOgRGf3wUXrr5ZsJ1HDhVGTXqb7QJbxtDowOoGKusC4h0ij
PTPKXntnOZ2oORAAX9doXs5LRnpzwUQh0pLHm/dUEfgx5/QmYuJ5wX2suUi2p6+j
0q/Kzzy3CrTAWswyU+lTRvtTyH6NVylaWk7YwlECgYBVQfqizALehqx94HmVLC7h
wTep+HcVrOpcCvXNnhX6bM9EOn6T4VgEf6LLiwD5zQhExuRNki02xgsfyoiOGg9s
CWx6zLWkl05DcHIFdNq3sb/9gG/42rrzhCTC3jETmWvMQgwAt19bv5AyOVBUnyHA
LuOa8J3AV+z5VISsN/NuRg==
-----END PRIVATE KEY-----"#;

struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    fn create() -> Self {
        let path = std::env::temp_dir().join(format!(
            "blacklist-controlled-protocols-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("create controlled protocol test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ManagedChild(Child);

impl ManagedChild {
    fn spawn(binary: &str, config_path: &Path) -> Self {
        let child = tokio::process::Command::new(binary)
            .arg("run")
            .arg("-c")
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start pinned sing-box test process");
        Self(child)
    }

    async fn stop(&mut self, label: &str) {
        match self.0.try_wait().expect("inspect sing-box test process") {
            Some(status) => {
                assert!(
                    status.success(),
                    "{label} sing-box process exited unexpectedly: {status}"
                );
            }
            None => {
                self.0.start_kill().expect("request sing-box process stop");
                timeout(Duration::from_secs(5), self.0.wait())
                    .await
                    .expect("sing-box test process did not stop within five seconds")
                    .expect("wait for sing-box test process");
            }
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.start_kill();
        }
    }
}

#[derive(Clone, Copy)]
enum Network {
    Tcp,
    Udp,
}

struct ProtocolCase {
    label: &'static str,
    profile: ProfileSummary,
    credentials: BTreeMap<String, String>,
    inbound: Value,
    network: Network,
}

fn options(values: &[(&str, &str)]) -> BTreeMap<String, String> {
    values
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

fn credentials(values: &[(&str, &str)]) -> BTreeMap<String, String> {
    options(values)
}

fn profile(protocol: &str, port: u16, values: &[(&str, &str)]) -> ProfileSummary {
    ProfileSummary {
        id: format!("controlled-{protocol}-{port}"),
        name: format!("Controlled {protocol}"),
        protocol: protocol.to_string(),
        server: "127.0.0.1".to_string(),
        port,
        options: options(values),
        unsupported_options: Vec::new(),
    }
}

fn inbound_tls(certificate: &Path, private_key: &Path, alpn: &[&str]) -> Value {
    let mut tls = json!({
        "enabled": true,
        "certificate_path": certificate.to_string_lossy(),
        "key_path": private_key.to_string_lossy()
    });
    if !alpn.is_empty() {
        tls["alpn"] = json!(alpn);
    }
    tls
}

fn tcp_port(used: &mut Vec<u16>) -> u16 {
    loop {
        let port = StdTcpListener::bind(("127.0.0.1", 0))
            .expect("reserve controlled TCP port")
            .local_addr()
            .expect("read controlled TCP port")
            .port();
        if !used.contains(&port) {
            used.push(port);
            return port;
        }
    }
}

fn udp_port(used: &mut Vec<u16>) -> u16 {
    loop {
        let port = StdUdpSocket::bind(("127.0.0.1", 0))
            .expect("reserve controlled UDP port")
            .local_addr()
            .expect("read controlled UDP port")
            .port();
        if !used.contains(&port) {
            used.push(port);
            return port;
        }
    }
}

fn make_cases(certificate: &Path, private_key: &Path) -> Vec<ProtocolCase> {
    let mut used_tcp_ports = Vec::new();
    let mut used_udp_ports = Vec::new();
    let uuid = "12345678-1234-1234-1234-123456789012";
    let mut cases = Vec::new();

    let port = tcp_port(&mut used_tcp_ports);
    let tls = inbound_tls(certificate, private_key, &[]);
    cases.push(ProtocolCase {
        label: "vless-tls",
        profile: profile("vless", port, &[("security", "tls"), ("sni", "localhost")]),
        credentials: credentials(&[("uuid", uuid)]),
        inbound: json!({
            "type": "vless", "tag": "vless-in", "listen": "127.0.0.1",
            "listen_port": port, "users": [{"uuid": uuid}], "tls": tls
        }),
        network: Network::Tcp,
    });

    let port = tcp_port(&mut used_tcp_ports);
    let tls = inbound_tls(certificate, private_key, &[]);
    cases.push(ProtocolCase {
        label: "vmess-websocket-tls",
        profile: profile("vmess", port, &[
            ("tls", "tls"), ("sni", "localhost"), ("transport", "ws"),
            ("host", "localhost"), ("path", "/edge"), ("security", "auto"),
        ]),
        credentials: credentials(&[("uuid", uuid)]),
        inbound: json!({
            "type": "vmess", "tag": "vmess-in", "listen": "127.0.0.1",
            "listen_port": port, "users": [{"uuid": uuid, "alterId": 0}],
            "tls": tls, "transport": {"type": "ws", "path": "/edge"}
        }),
        network: Network::Tcp,
    });

    let port = tcp_port(&mut used_tcp_ports);
    let tls = inbound_tls(certificate, private_key, &[]);
    cases.push(ProtocolCase {
        label: "trojan-tls",
        profile: profile("trojan", port, &[("sni", "localhost")]),
        credentials: credentials(&[("password", "controlled-trojan-secret")]),
        inbound: json!({
            "type": "trojan", "tag": "trojan-in", "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{"password": "controlled-trojan-secret"}], "tls": tls
        }),
        network: Network::Tcp,
    });

    let port = tcp_port(&mut used_tcp_ports);
    cases.push(ProtocolCase {
        label: "shadowsocks-aes-256-gcm",
        profile: profile("shadowsocks", port, &[("method", "aes-256-gcm")]),
        credentials: credentials(&[("password", "controlled-shadowsocks-secret")]),
        inbound: json!({
            "type": "shadowsocks", "tag": "shadowsocks-in", "network": "tcp",
            "listen": "127.0.0.1", "listen_port": port,
            "method": "aes-256-gcm", "password": "controlled-shadowsocks-secret"
        }),
        network: Network::Tcp,
    });

    let port = udp_port(&mut used_udp_ports);
    let tls = inbound_tls(certificate, private_key, &["h3"]);
    cases.push(ProtocolCase {
        label: "hysteria2-salamander",
        profile: profile("hysteria2", port, &[
            ("sni", "localhost"), ("alpn", "h3"), ("obfs", "salamander"),
        ]),
        credentials: credentials(&[
            ("password", "controlled-hysteria-secret"),
            ("obfsPassword", "controlled-obfs-secret"),
        ]),
        inbound: json!({
            "type": "hysteria2", "tag": "hysteria2-in", "listen": "127.0.0.1",
            "listen_port": port, "up_mbps": 100, "down_mbps": 100,
            "obfs": {"type": "salamander", "password": "controlled-obfs-secret"},
            "users": [{"password": "controlled-hysteria-secret"}], "tls": tls
        }),
        network: Network::Udp,
    });

    let port = udp_port(&mut used_udp_ports);
    let tls = inbound_tls(certificate, private_key, &["h3"]);
    cases.push(ProtocolCase {
        label: "tuic",
        profile: profile("tuic", port, &[
            ("sni", "localhost"), ("alpn", "h3"),
            ("congestion_control", "cubic"), ("udp_relay_mode", "native"),
        ]),
        credentials: credentials(&[
            ("uuid", uuid), ("password", "controlled-tuic-secret"),
        ]),
        inbound: json!({
            "type": "tuic", "tag": "tuic-in", "listen": "127.0.0.1",
            "listen_port": port,
            "users": [{"uuid": uuid, "password": "controlled-tuic-secret"}],
            "congestion_control": "cubic", "tls": tls
        }),
        network: Network::Udp,
    });

    let port = tcp_port(&mut used_tcp_ports);
    let tls = inbound_tls(certificate, private_key, &["h2"]);
    cases.push(ProtocolCase {
        label: "naive-https",
        profile: profile("naive", port, &[("sni", "localhost"), ("insecureConcurrency", "0")]),
        credentials: credentials(&[
            ("username", "controlled-naive-user"),
            ("password", "controlled-naive-secret"),
        ]),
        inbound: json!({
            "type": "naive", "tag": "naive-https-in", "network": "tcp",
            "listen": "127.0.0.1", "listen_port": port,
            "users": [{
                "username": "controlled-naive-user",
                "password": "controlled-naive-secret"
            }],
            "tls": tls
        }),
        network: Network::Tcp,
    });

    let port = udp_port(&mut used_udp_ports);
    let tls = inbound_tls(certificate, private_key, &["h3"]);
    cases.push(ProtocolCase {
        label: "naive-quic",
        // Cronet resolves loopback to IPv6 (::1) for its QUIC socket on Windows.
        // Bind the controlled test listener on the same address family to avoid
        // an IPv4-only listener rejecting the otherwise-local QUIC handshake.
        profile: ProfileSummary {
            server: "::1".to_string(),
            ..profile("naive", port, &[
                ("sni", "localhost"), ("insecureConcurrency", "0"), ("quic", "true"),
            ])
        },
        credentials: credentials(&[
            ("username", "controlled-naive-quic-user"),
            ("password", "controlled-naive-quic-secret"),
        ]),
        inbound: json!({
            "type": "naive", "tag": "naive-quic-in", "network": "udp",
            "listen": "::1", "listen_port": port,
            "users": [{
                "username": "controlled-naive-quic-user",
                "password": "controlled-naive-quic-secret"
            }],
            "tls": tls
        }),
        network: Network::Udp,
    });

    cases
}

fn write_json(path: &Path, value: &Value) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("serialize controlled sing-box config"),
    )
    .expect("write controlled sing-box config");
}

fn check_config(binary: &str, path: &Path, label: &str) {
    let output = std::process::Command::new(binary)
        .arg("check")
        .arg("-c")
        .arg(path)
        .output()
        .expect("run pinned sing-box config check");
    assert!(
        output.status.success(),
        "sing-box rejected {label} integration config: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn wait_for_tcp_listener(child: &mut Child, port: u16, label: &str) {
    timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = child.try_wait().expect("inspect controlled server process") {
                panic!("{label} controlled server exited before listening: {status}");
            }
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{label} controlled server did not start listening"));
}

async fn wait_for_socks(child: &mut Child, port: u16, label: &str) {
    timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = child.try_wait().expect("inspect controlled client process") {
                panic!("{label} client exited before SOCKS startup: {status}");
            }
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{label} client SOCKS listener did not start"));
}

async fn start_http_204_origin() -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind controlled HTTP origin");
    let port = listener.local_addr().expect("read HTTP origin address").port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut request = [0_u8; 4096];
                let _ = timeout(Duration::from_secs(3), stream.read(&mut request)).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (port, task)
}

#[tokio::test]
async fn every_supported_outbound_completes_an_authenticated_controlled_http_roundtrip() {
    let Ok(binary) = std::env::var("SING_BOX_VALIDATOR") else {
        // The Windows workflow supplies the pinned official binary and its runtime.
        return;
    };

    let directory = TemporaryDirectory::create();
    let certificate_path = directory.path().join("localhost.crt");
    let private_key_path = directory.path().join("localhost.key");
    fs::write(&certificate_path, TEST_CERTIFICATE).expect("write local test CA certificate");
    fs::write(&private_key_path, TEST_PRIVATE_KEY).expect("write local test private key");

    let cases = make_cases(&certificate_path, &private_key_path);
    let server_log_path = directory.path().join("controlled-server.log");
    let server_config = json!({
        "log": {
            "level": "debug",
            "output": server_log_path.to_string_lossy(),
            "timestamp": true
        },
        "inbounds": cases.iter().map(|case| case.inbound.clone()).collect::<Vec<_>>(),
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    });
    let server_config_path = directory.path().join("controlled-server.json");
    write_json(&server_config_path, &server_config);
    check_config(&binary, &server_config_path, "multi-protocol server");

    let mut server = ManagedChild::spawn(&binary, &server_config_path);
    for case in &cases {
        if matches!(case.network, Network::Tcp) {
            wait_for_tcp_listener(&mut server.0, case.profile.port, case.label).await;
        }
    }
    sleep(Duration::from_millis(300)).await;
    assert!(
        server.0.try_wait().expect("inspect controlled server").is_none(),
        "multi-protocol controlled server must remain running"
    );

    let (origin_port, origin_task) = start_http_204_origin().await;
    let url = format!("http://127.0.0.1:{origin_port}/generate_204");

    for case in &cases {
        let socks_port = tcp_port(&mut Vec::new());
        let mut client_config =
            build_probe_config(&case.profile, &case.credentials, socks_port)
                .unwrap_or_else(|error| panic!("{} adapter rejected its test profile: {error}", case.label));

        // Trust only the ephemeral test certificate. Production adapters retain
        // their normal certificate validation behavior.
        if let Some(tls) = client_config["outbounds"][0].get_mut("tls") {
            tls["certificate_path"] = json!(certificate_path.to_string_lossy());
        } else if case.profile.protocol != "shadowsocks" {
            panic!("{} client config is missing its expected TLS object", case.label);
        }

        let client_log_path = directory.path().join(format!("client-{}.log", case.label));
        client_config["log"] = json!({
            "level": "debug",
            "output": client_log_path.to_string_lossy(),
            "timestamp": true
        });
        let client_config_path = directory.path().join(format!("client-{}.json", case.label));
        write_json(&client_config_path, &client_config);
        check_config(&binary, &client_config_path, case.label);

        let mut client = ManagedChild::spawn(&binary, &client_config_path);
        wait_for_socks(&mut client.0, socks_port, case.label).await;

        let http_client = build_probe_http_client(socks_port, Duration::from_secs(12))
            .expect("build controlled HTTP client");
        let measured = timeout(
            Duration::from_secs(15),
            measure_request_with_client(&http_client, &[url.as_str()]),
        )
        .await;
        let (result, failure) = match measured {
            Ok(Ok(result)) => (Some(result), None),
            Ok(Err(error)) => (None, Some(error)),
            Err(_) => (None, Some("end-to-end request timed out".to_string())),
        };
        if let Some(error) = failure {
            let _ = client.0.start_kill();
            let _ = timeout(Duration::from_secs(5), client.0.wait()).await;
            let client_logs = fs::read_to_string(&client_log_path).unwrap_or_else(|_| {
                "No client diagnostics were written.".to_string()
            });
            let server_logs = fs::read_to_string(&server_log_path).unwrap_or_else(|_| {
                "No controlled server diagnostics were written.".to_string()
            });
            panic!(
                "{} authenticated tunnel failed: {error}\nclient sing-box diagnostics:\n{}\nserver sing-box diagnostics:\n{}",
                case.label, client_logs, server_logs
            );
        }
        let result = result.expect("successful HTTP 204 result");
        assert_eq!(result.1, url, "{} must return the controlled HTTP 204 URL", case.label);
        assert!(result.0 < 15_000, "{} response must remain bounded", case.label);
        client.stop(case.label).await;
        drop(http_client);
        eprintln!("controlled protocol roundtrip passed: {}", case.label);
    }

    origin_task.abort();
    server.stop("multi-protocol server").await;
}
