use std::collections::BTreeMap;
use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Manager};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, Notify};
use tokio::time::{sleep, timeout};
use zeroize::Zeroizing;

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
    pub async fn status(&self) -> LocalProxyStatus {
        let inner = self.inner.lock().await;
        match inner.active.as_ref() {
            Some(session) => LocalProxyStatus {
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
        self.changed.notify_waiters();
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

        let port = reserve_loopback_port()?;
        let mut config = crate::engine::sing_box::build_probe_config(profile, credentials, port)?;
        // The listener is loopback-only and additionally requires a per-session
        // credential so another local Windows user cannot reuse the proxy.
        let username = uuid::Uuid::new_v4().simple().to_string();
        let password = uuid::Uuid::new_v4().simple().to_string();
        config["inbounds"][0]["users"] = serde_json::json!([{
            "username": username,
            "password": password
        }]);
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
        let bytes = Zeroizing::new(
            serde_json::to_vec(&config)
                .map_err(|_| "Could not encode the local proxy configuration.".to_string())?,
        );
        fs::write(&config_path, &bytes)
            .map_err(|_| "Could not write the temporary local proxy configuration.".to_string())?;

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
            let _ = child.start_kill();
            let _ = timeout(STOP_TIMEOUT, child.wait()).await;
            let _ = remove_config_file(&config_path, supervisor);
            return Err(error);
        }

        let ready = wait_for_proxy(&mut child, port).await;
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

        drop(session._lease);
        self.changed.notify_waiters();
        Ok(LocalProxyStatus::inactive("The local proxy was stopped and its temporary configuration was removed."))
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

async fn wait_for_proxy(child: &mut Child, port: u16) -> Result<(), String> {
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

            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                return Ok(());
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        Err("sing-box did not open its local SOCKS5 listener within 8 seconds.".to_string())
    })
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
