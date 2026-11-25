use std::collections::BTreeMap;
use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Manager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, Notify};
use tokio::time::{sleep, timeout};
use zeroize::{Zeroize, Zeroizing};

use crate::process_supervisor::{OperationLease, ProcessSupervisor};
use crate::profiles::ProfileSummary;

const START_TIMEOUT: Duration = Duration::from_secs(8);
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const CONFIG_DIRECTORY: &str = "local-proxy";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalProxyStatus {
    pub active: bool,
    pub profile_id: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub detail: String,
}

impl LocalProxyStatus {
    fn inactive(detail: impl Into<String>) -> Self {
        Self {
            active: false,
            profile_id: None,
            host: None,
            port: None,
            username: None,
            password: None,
            detail: detail.into(),
        }
    }
}

struct Session {
    profile_id: String,
    port: u16,
    username: String,
    password: String,
    child: Child,
    config_path: PathBuf,
    _lease: OperationLease,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

#[derive(Default)]
struct Inner {
    starting: bool,
    active: Option<Session>,
}

#[derive(Clone, Default)]
pub struct LocalProxyRuntime {
    inner: Arc<Mutex<Inner>>,
    changed: Arc<Notify>,
}

impl LocalProxyRuntime {
    pub async fn status(&self, supervisor: &ProcessSupervisor) -> LocalProxyStatus {
        let mut inner = self.inner.lock().await;
        let process_state = inner
            .active
            .as_mut()
            .map(|session| session.child.try_wait());
        match process_state {
            Some(Ok(Some(_))) => {
                let mut exited = inner.active.take().expect("the exited session was present");
                let config_path = exited.config_path.clone();
                drop(inner);
                if remove_config_file(&config_path, supervisor).is_err() {
                    supervisor.mark_cleanup_unhealthy();
                    return LocalProxyStatus::inactive(
                        "The proxy engine exited, but its credential-bearing config could not be removed; engine cleanup is blocked.",
                    );
                }
                exited.username.zeroize();
                exited.password.zeroize();
                drop(exited);
                self.changed.notify_one();
                return LocalProxyStatus::inactive(
                    "The local proxy engine exited. Its temporary configuration was removed.",
                );
            }
            Some(Err(_)) => {
                supervisor.mark_cleanup_unhealthy();
                return LocalProxyStatus::inactive(
                    "The local proxy process state could not be verified; engine cleanup is blocked.",
                );
            }
            Some(Ok(None)) | None => {}
        }

        match inner.active.as_ref() {
            Some(session) => LocalProxyStatus {
                active: true,
                profile_id: Some(session.profile_id.clone()),
                host: Some("127.0.0.1".to_string()),
                port: Some(session.port),
                username: Some(session.username.clone()),
                password: Some(session.password.clone()),
                detail: format!(
                    "Authenticated local SOCKS5 proxy is listening on 127.0.0.1:{}; system routing and TUN are unchanged.",
                    session.port
                ),
            },
            None if inner.starting => {
                LocalProxyStatus::inactive("The local proxy engine is starting.")
            }
            None => LocalProxyStatus::inactive("No local proxy session is running."),
        }
    }

    pub async fn start(
        &self,
        app: &AppHandle,
        profile: ProfileSummary,
        credentials: &BTreeMap<String, String>,
        supervisor: &ProcessSupervisor,
    ) -> Result<LocalProxyStatus, String> {
        {
            let mut inner = self.inner.lock().await;
            if inner.starting || inner.active.is_some() {
                return Err(
                    "A local proxy session is already starting or running. Stop it before starting another profile."
                        .to_string(),
                );
            }
            inner.starting = true;
        }

        let result = self
            .start_reserved(app, &profile, credentials, supervisor)
            .await;

        let mut inner = self.inner.lock().await;
        inner.starting = false;
        let response = match result {
            Ok(session) => {
                let status = LocalProxyStatus {
                    active: true,
                    profile_id: Some(session.profile_id.clone()),
                    host: Some("127.0.0.1".to_string()),
                    port: Some(session.port),
                    username: Some(session.username.clone()),
                    password: Some(session.password.clone()),
                    detail: format!(
                        "Local SOCKS5 proxy is listening on 127.0.0.1:{}; system routing and TUN are unchanged.",
                        session.port
                    ),
                };
                inner.active = Some(session);
                Ok(status)
            }
            Err(error) => Err(error),
        };
        drop(inner);
        self.changed.notify_one();
        response
    }

    async fn start_reserved(
        &self,
        app: &AppHandle,
        profile: &ProfileSummary,
        credentials: &BTreeMap<String, String>,
        supervisor: &ProcessSupervisor,
    ) -> Result<Session, String> {
        let lease = supervisor.begin_operation()?;
        let binary = crate::engine::sing_box::installed_binary_path(app)?;
        if !binary.is_file() {
            return Err(
                "Install the verified sing-box engine before starting a local proxy.".to_string(),
            );
        }
        if !binary
            .parent()
            .map(|directory| directory.join("libcronet.dll").is_file())
            .unwrap_or(false)
        {
            return Err(
                "The sing-box Windows runtime library is missing. Reinstall the engine first."
                    .to_string(),
            );
        }

        // Validate with sing-box itself before creating a long-lived session.
        crate::engine::sing_box::validate_profile_config(app, profile, credentials, supervisor)
            .await?;

        let config_directory = app
            .path()
            .app_data_dir()
            .map_err(|_| "Could not resolve the local application data directory.".to_string())?
            .join(CONFIG_DIRECTORY);
        fs::create_dir_all(&config_directory)
            .map_err(|_| "Could not create the local proxy configuration directory.".to_string())?;

        let config_path = config_directory.join(format!(
            "session-{}.json",
            uuid::Uuid::new_v4().simple()
        ));
        let port = reserve_loopback_port()?;
        let mut config = crate::engine::sing_box::build_probe_config(profile, credentials, port)?;
        // The listener is loopback-only and additionally requires a per-session
        // credential so another local Windows user cannot reuse the proxy.
        let username = uuid::Uuid::new_v4().simple().to_string();
        let password = uuid::Uuid::new_v4().simple().to_string();
        if let Err(error) = configure_local_socks_auth(&mut config, &username, &password) {
            zeroize_json(&mut config);
            return Err(error);
        }
        let encoded = serde_json::to_vec(&config);
        // Clear every generated config field before propagating a serialization error.
        zeroize_json(&mut config);
        let bytes = Zeroizing::new(
            encoded.map_err(|_| "Could not encode the local proxy configuration.".to_string())?,
        );
        if fs::write(&config_path, &bytes).is_err() {
            let _ = remove_config_file(&config_path, supervisor);
            return Err("Could not write the temporary local proxy configuration.".to_string());
        }

        let mut command = Command::new(&binary);
        command
            .arg("run")
            .arg("-c")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        supervisor.prepare_child_command(&mut command);

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                remove_config_file(&config_path, supervisor)?;
                return Err("The sing-box local proxy process could not be started.".to_string());
            }
        };

        if let Err(error) = supervisor.assign_child(&mut child).await {
            if stop_child(&mut child).await {
                let _ = remove_config_file(&config_path, supervisor);
            } else {
                supervisor.mark_cleanup_unhealthy();
            }
            return Err(error);
        }

        let ready = wait_for_proxy(&mut child, port, &username, &password).await;
        if let Err(error) = ready {
            let stopped = stop_child(&mut child).await;
            if !stopped {
                supervisor.mark_cleanup_unhealthy();
                // Retain the config until process termination is confirmed.
                return Err(format!(
                    "{error} The engine could not be stopped with certainty; process cleanup is unhealthy."
                ));
            }
            remove_config_file(&config_path, supervisor)?;
            return Err(error);
        }

        Ok(Session {
            profile_id: profile.id.clone(),
            port,
            username,
            password,
            child,
            config_path,
            _lease: lease,
        })
    }

    pub async fn stop(&self, supervisor: &ProcessSupervisor) -> Result<LocalProxyStatus, String> {
        let session = loop {
            let notified = self.changed.notified();
            let mut inner = self.inner.lock().await;
            if inner.starting {
                drop(inner);
                notified.await;
                continue;
            }
            break inner.active.take();
        };

        let Some(mut session) = session else {
            return Ok(LocalProxyStatus::inactive("No local proxy session is running."));
        };

        if !stop_child(&mut session.child).await {
            supervisor.mark_cleanup_unhealthy();
            // The config contains credentials. Keep it in place until engine exit
            // is confirmed; the Job Object remains the final process containment.
            return Err(
                "The local proxy engine did not stop within the cleanup deadline. New engine work is blocked."
                    .to_string(),
            );
        }

        if let Err(error) = remove_config_file(&session.config_path, supervisor) {
            supervisor.mark_cleanup_unhealthy();
            return Err(error);
        }

        drop(session);
        self.changed.notify_one();
        Ok(LocalProxyStatus::inactive("The local proxy was stopped and its temporary configuration was removed."))
    }
}



fn configure_local_socks_auth(
    config: &mut serde_json::Value,
    username: &str,
    password: &str,
) -> Result<(), String> {
    if username.is_empty()
        || password.is_empty()
        || username.len() > u8::MAX as usize
        || password.len() > u8::MAX as usize
    {
        return Err("The generated local proxy credentials are invalid.".to_string());
    }
    let inbounds = config["inbounds"]
        .as_array_mut()
        .ok_or_else(|| "The generated proxy config has no inbound list.".to_string())?;
    let inbound = inbounds
        .first_mut()
        .ok_or_else(|| "The generated proxy config has no local inbound.".to_string())?;
    if inbound["type"] != "socks" || inbound["listen"] != "127.0.0.1" {
        return Err(
            "The generated local proxy inbound is not the expected loopback-only SOCKS listener."
                .to_string(),
        );
    }
    inbound["users"] = serde_json::json!([{
        "username": username,
        "password": password
    }]);
    Ok(())
}

fn zeroize_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(value) => value.zeroize(),
        serde_json::Value::Array(values) => {
            for value in values {
                zeroize_json(value);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                zeroize_json(value);
            }
        }
        _ => {}
    }
}

fn reserve_loopback_port() -> Result<u16, String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|_| "A free local loopback port could not be reserved.".to_string())?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|_| "The selected loopback port could not be read.".to_string())
}

async fn wait_for_proxy(
    child: &mut Child,
    port: u16,
    username: &str,
    password: &str,
) -> Result<(), String> {
    timeout(START_TIMEOUT, async {
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    return Err(
                        "sing-box exited before its local SOCKS5 listener became ready. Check the profile configuration."
                            .to_string(),
                    );
                }
                Ok(None) => {}
                Err(_) => {
                    return Err("The sing-box process state could not be checked.".to_string());
                }
            }

            match timeout(
                Duration::from_millis(500),
                verify_socks_authentication(port, username, password),
            )
            .await
            {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(_)) | Err(_) => sleep(Duration::from_millis(100)).await,
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        Err("sing-box did not open its local SOCKS5 listener within 8 seconds.".to_string())
    })
}


async fn verify_socks_authentication(
    port: u16,
    username: &str,
    password: &str,
) -> Result<(), String> {
    if username.is_empty()
        || password.is_empty()
        || username.len() > u8::MAX as usize
        || password.len() > u8::MAX as usize
    {
        return Err("The generated local proxy credentials are invalid.".to_string());
    }
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|_| "The local SOCKS5 listener is not accepting connections.".to_string())?;

    stream
        .write_all(&[0x05, 0x01, 0x02])
        .await
        .map_err(|_| "The local SOCKS5 authentication negotiation failed.".to_string())?;
    let mut method = [0u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .map_err(|_| "The local SOCKS5 authentication negotiation was incomplete.".to_string())?;
    if method != [0x05, 0x02] {
        return Err("The local SOCKS5 listener did not require username/password authentication.".to_string());
    }

    let mut auth = Zeroizing::new(Vec::with_capacity(3 + username.len() + password.len()));
    auth.push(0x01);
    auth.push(username.len() as u8);
    auth.extend_from_slice(username.as_bytes());
    auth.push(password.len() as u8);
    auth.extend_from_slice(password.as_bytes());
    stream
        .write_all(&auth)
        .await
        .map_err(|_| "The local SOCKS5 credential check could not be sent.".to_string())?;
    auth.fill(0);

    let mut result = [0u8; 2];
    stream
        .read_exact(&mut result)
        .await
        .map_err(|_| "The local SOCKS5 credential check did not complete.".to_string())?;
    if result == [0x01, 0x00] {
        Ok(())
    } else {
        Err("The local SOCKS5 listener rejected its generated credentials.".to_string())
    }
}

async fn stop_child(child: &mut Child) -> bool {
    match child.try_wait() {
        Ok(Some(_)) => true,
        Ok(None) => {
            if child.start_kill().is_err() {
                return false;
            }
            matches!(timeout(STOP_TIMEOUT, child.wait()).await, Ok(Ok(_)))
        }
        Err(_) => false,
    }
}

fn remove_config_file(path: &PathBuf, supervisor: &ProcessSupervisor) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => {
            supervisor.mark_cleanup_unhealthy();
            Err(
                "The credential-bearing local proxy configuration could not be removed. Engine cleanup is blocked."
                    .to_string(),
            )
        }
    }
}

/// A previous desktop process owns a kill-on-close Job Object, so its child
/// engine is terminated when the desktop exits. Only then is it safe to remove
/// abandoned credential-bearing configs from the app-owned runtime directory.
pub fn recover_stale_configs(app: &AppHandle) -> Result<(), String> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|_| "Could not resolve the local application data directory.".to_string())?
        .join(CONFIG_DIRECTORY);
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err("The local proxy runtime directory could not be inspected.".to_string())
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(
            "The local proxy runtime directory is not a regular application-owned directory."
                .to_string(),
        );
    }

    for entry in fs::read_dir(&directory)
        .map_err(|_| "The local proxy runtime directory could not be read.".to_string())?
    {
        let entry = entry
            .map_err(|_| "A stale local proxy configuration entry could not be read.".to_string())?;
        let entry_type = entry
            .file_type()
            .map_err(|_| "A stale local proxy configuration type could not be read.".to_string())?;
        if entry_type.is_symlink() || !entry_type.is_file() {
            return Err(
                "The local proxy runtime directory contains an unexpected entry; cleanup was stopped."
                    .to_string(),
            );
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("session-") && name.ends_with(".json") {
            fs::remove_file(entry.path()).map_err(|_| {
                "A stale credential-bearing local proxy configuration could not be removed."
                    .to_string()
            })?;
        } else {
            return Err(
                "The local proxy runtime directory contains an unrecognized file; cleanup was stopped."
                    .to_string(),
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_json_clears_nested_credential_strings() {
        let mut value = serde_json::json!({
            "inbounds": [{"users": [{"username": "local-user", "password": "local-password"}]}],
            "nested": ["another-secret", {"token": "test-token"}]
        });
        zeroize_json(&mut value);
        assert_eq!(value["inbounds"][0]["users"][0]["username"], "");
        assert_eq!(value["inbounds"][0]["users"][0]["password"], "");
        assert_eq!(value["nested"][0], "");
        assert_eq!(value["nested"][1]["token"], "");
    }


    #[test]
    fn local_auth_requires_loopback_socks_inbound() {
        let mut config = serde_json::json!({
            "inbounds": [{
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": 12345
            }]
        });
        configure_local_socks_auth(&mut config, "local-user", "local-password")
            .expect("configure authenticated loopback inbound");
        assert_eq!(config["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(config["inbounds"][0]["users"][0]["username"], "local-user");
        assert_eq!(config["inbounds"][0]["users"][0]["password"], "local-password");

        let mut non_loopback = serde_json::json!({
            "inbounds": [{
                "type": "socks",
                "listen": "0.0.0.0",
                "listen_port": 12345
            }]
        });
        assert!(configure_local_socks_auth(&mut non_loopback, "u", "p").is_err());

        let mut wrong_type = serde_json::json!({
            "inbounds": [{
                "type": "http",
                "listen": "127.0.0.1",
                "listen_port": 12345
            }]
        });
        assert!(configure_local_socks_auth(&mut wrong_type, "u", "p").is_err());
    }

    #[test]
    fn loopback_port_reservation_returns_an_available_local_port() {
        let port = reserve_loopback_port().expect("reserve a loopback port");
        assert_ne!(port, 0);
        let listener = TcpListener::bind(("127.0.0.1", port))
            .expect("the returned port is released and bindable");
        drop(listener);
    }

    #[tokio::test]
    async fn startup_probe_requires_and_verifies_socks_username_password() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock SOCKS listener");
        let port = listener.local_addr().expect("read mock address").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept probe");
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.expect("read greeting");
            assert_eq!(greeting, [0x05, 0x01, 0x02]);
            stream.write_all(&[0x05, 0x02]).await.expect("select auth");

            let mut version_and_user_len = [0u8; 2];
            stream.read_exact(&mut version_and_user_len).await.expect("read auth header");
            assert_eq!(version_and_user_len[0], 0x01);
            let mut username = vec![0u8; version_and_user_len[1] as usize];
            stream.read_exact(&mut username).await.expect("read username");
            let mut password_len = [0u8; 1];
            stream.read_exact(&mut password_len).await.expect("read password length");
            let mut password = vec![0u8; password_len[0] as usize];
            stream.read_exact(&mut password).await.expect("read password");
            assert_eq!(username, b"local-user");
            assert_eq!(password, b"local-password");
            username.fill(0);
            password.fill(0);
            stream.write_all(&[0x01, 0x00]).await.expect("accept auth");
        });

        verify_socks_authentication(port, "local-user", "local-password")
            .await
            .expect("SOCKS server accepts generated credentials");
        server.await.expect("mock SOCKS task completes");
    }

    #[tokio::test]
    async fn startup_probe_rejects_a_listener_without_username_password_auth() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock SOCKS listener");
        let port = listener.local_addr().expect("read mock address").port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept probe");
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.expect("read greeting");
            stream.write_all(&[0x05, 0x00]).await.expect("select no auth");
        });

        let result = verify_socks_authentication(port, "local-user", "local-password").await;
        assert!(result
            .expect_err("unauthenticated listener is rejected")
            .contains("did not require username/password"));
        server.await.expect("mock SOCKS task completes");
    }
}

