use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Manager};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::engine::{EngineDescriptor, ENGINE_TARGETS};
use crate::profile_store;
use crate::process_supervisor::ProcessSupervisor;
use crate::profiles::{parse_import_text, ImportIssue, ProfileSummary};

static REAL_DELAY_SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();

fn real_delay_semaphore() -> Arc<Semaphore> {
    Arc::clone(REAL_DELAY_SEMAPHORE.get_or_init(|| Arc::new(Semaphore::new(4))))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStatus {
    app_name: &'static str,
    version: &'static str,
    development_stage: &'static str,
    connection_implemented: bool,
    preflight_testing_implemented: bool,
    profile_management_implemented: bool,
    endpoint_tcp_test_implemented: bool,
    sing_box_installed: bool,
    runtime_cleanup_healthy: bool,
    engines: Vec<EngineDescriptor>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResponse {
    imported: Vec<ProfileSummary>,
    rejected: Vec<ImportIssue>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointTestResult {
    profile_id: String,
    name: String,
    protocol: String,
    server: String,
    port: u16,
    supported: bool,
    reachable: bool,
    latency_ms: Option<u64>,
    detail: String,
}

#[tauri::command]
pub async fn get_app_status(app: AppHandle) -> AppStatus {
    let supervisor = app.state::<ProcessSupervisor>().inner().clone();
    // Version checks start a short-lived engine subprocess. Register it so app
    // shutdown cannot race an untracked child process.
    let _operation = supervisor.begin_operation().ok();
    let sing_box_installed = if _operation.is_some() {
        crate::engine::sing_box::is_installed(&app, &supervisor).await
    } else {
        false
    };
    AppStatus {
        app_name: "blacklist-inevitable",
        version: env!("CARGO_PKG_VERSION"),
        development_stage: "sing-box preflight with supervised shutdown",
        connection_implemented: false,
        preflight_testing_implemented: true,
        profile_management_implemented: true,
        endpoint_tcp_test_implemented: true,
        sing_box_installed,
        runtime_cleanup_healthy: app.state::<ProcessSupervisor>().cleanup_healthy(),
        engines: ENGINE_TARGETS.to_vec(),
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentServiceStatus {
    available: bool,
    state: String,
    detail: String,
}

/// Query only the Agent's non-mutating status endpoint. No profile data or
/// credentials cross this boundary; all network-mutating RPCs remain disabled.
#[tauri::command]
pub async fn get_agent_service_status() -> AgentServiceStatus {
    match crate::agent_client::query_status().await {
        Ok(detail) => AgentServiceStatus {
            available: true,
            state: "running".to_string(),
            detail,
        },
        Err(detail) => AgentServiceStatus {
            available: false,
            state: if cfg!(windows) { "unavailable" } else { "unsupported" }.to_string(),
            detail,
        },
    }
}

#[tauri::command]
pub fn get_profiles(app: AppHandle) -> Result<Vec<ProfileSummary>, String> {
    profile_store::list_profiles(&app)
}

#[tauri::command]
pub fn import_profiles(app: AppHandle, input: String) -> Result<ImportResponse, String> {
    let parsed = parse_import_text(&input)?;
    let rejected = parsed.rejected;
    let imported = profile_store::add_profiles(&app, parsed.profiles)?;

    Ok(ImportResponse { imported, rejected })
}

#[tauri::command]
pub fn delete_profile(app: AppHandle, profile_id: String) -> Result<(), String> {
    profile_store::remove_profile(&app, &profile_id)
}

#[tauri::command]
pub async fn test_all_profile_endpoints(
    app: AppHandle,
) -> Result<Vec<EndpointTestResult>, String> {
    let profiles = profile_store::list_profiles(&app)?;
    let semaphore = Arc::new(Semaphore::new(24));
    let mut tasks = JoinSet::new();

    for profile in profiles {
        let semaphore = Arc::clone(&semaphore);
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok();
            test_one_endpoint(profile).await
        });
    }

    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok(result) = result {
            results.push(result);
        }
    }

    results.sort_by(|left, right| {
        match (left.reachable, right.reachable) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            (true, true) => left.latency_ms.cmp(&right.latency_ms),
            (false, false) => left.name.cmp(&right.name),
        }
    });

    Ok(results)
}

async fn test_one_endpoint(profile: ProfileSummary) -> EndpointTestResult {
    let naive_quic = profile.protocol == "naive"
        && profile.options.get("quic").is_some_and(|value| value == "true");
    let tcp_supported = matches!(
        profile.protocol.as_str(),
        "vless" | "vmess" | "trojan" | "shadowsocks" | "naive"
    ) && !naive_quic;

    if !tcp_supported {
        return EndpointTestResult {
            profile_id: profile.id,
            name: profile.name,
            protocol: profile.protocol,
            server: profile.server,
            port: profile.port,
            supported: false,
            reachable: false,
            latency_ms: None,
            detail: "This protocol needs a UDP-aware probe; TCP was not attempted.".to_string(),
        };
    }

    let started = Instant::now();
    let connection = timeout(
        Duration::from_secs(5),
        TcpStream::connect((profile.server.as_str(), profile.port)),
    )
    .await;

    match connection {
        Ok(Ok(stream)) => {
            drop(stream);
            EndpointTestResult {
                profile_id: profile.id,
                name: profile.name,
                protocol: profile.protocol,
                server: profile.server,
                port: profile.port,
                supported: true,
                reachable: true,
                latency_ms: Some(started.elapsed().as_millis().min(u64::MAX as u128) as u64),
                detail: "TCP port accepted a connection. Protocol authentication was not tested.".to_string(),
            }
        }
        Ok(Err(_)) => EndpointTestResult {
            profile_id: profile.id,
            name: profile.name,
            protocol: profile.protocol,
            server: profile.server,
            port: profile.port,
            supported: true,
            reachable: false,
            latency_ms: None,
            detail: "TCP connection failed; the endpoint may be offline or unreachable.".to_string(),
        },
        Err(_) => EndpointTestResult {
            profile_id: profile.id,
            name: profile.name,
            protocol: profile.protocol,
            server: profile.server,
            port: profile.port,
            supported: true,
            reachable: false,
            latency_ms: None,
            detail: "TCP connection timed out after 5 seconds.".to_string(),
        },
    }
}


#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigValidationResult {
    profile_id: String,
    valid: bool,
    detail: String,
}

#[tauri::command]
pub async fn install_sing_box_engine(app: AppHandle) -> Result<String, String> {
    let supervisor = app.state::<ProcessSupervisor>().inner().clone();
    // Installation includes a bounded version-check subprocess and mutates the
    // engine installation directory; drain it before app shutdown.
    let _operation = supervisor.begin_operation()?;
    crate::engine::sing_box::install(&app, &supervisor).await
}

#[tauri::command]
pub async fn validate_profile_config(
    app: AppHandle,
    profile_id: String,
) -> Result<ConfigValidationResult, String> {
    let supervisor = app.state::<ProcessSupervisor>().inner().clone();
    let _operation = supervisor.begin_operation()?;
    let profiles = profile_store::list_profiles(&app)?;
    let profile = profiles
        .into_iter()
        .find(|profile| profile.id == profile_id)
        .ok_or_else(|| "Profile not found.".to_string())?;
    let credentials = profile_store::get_credentials(&profile.id)?;
    match crate::engine::sing_box::validate_profile_config(&app, &profile, &credentials, &supervisor).await {
        Ok(()) => Ok(ConfigValidationResult {
            profile_id: profile.id,
            valid: true,
            detail: "sing-box accepted this generated configuration.".to_string(),
        }),
        Err(detail) => Ok(ConfigValidationResult {
            profile_id: profile.id,
            valid: false,
            detail,
        }),
    }
}


#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RealDelayResult {
    profile_id: String,
    name: String,
    server: String,
    port: u16,
    config_status: String,
    config_detail: String,
    real_delay_ms: Option<u64>,
    real_delay_detail: String,
    tested_url: Option<String>,
}

#[tauri::command]
pub fn get_real_delay_settings(
    app: AppHandle,
) -> Result<crate::real_delay_settings::RealDelaySettings, String> {
    crate::real_delay_settings::load(&app)
}

#[tauri::command]
pub fn save_real_delay_settings(
    app: AppHandle,
    settings: crate::real_delay_settings::RealDelaySettings,
) -> Result<crate::real_delay_settings::RealDelaySettings, String> {
    crate::real_delay_settings::save(&app, settings)
}

#[tauri::command]
pub async fn test_all_profile_real_delays(
    app: AppHandle,
) -> Result<Vec<RealDelayResult>, String> {
    let settings = crate::real_delay_settings::load(&app)?;
    let profiles = profile_store::list_profiles(&app)?;
    // Shared across every invocation, including detached workers from a cancelled
    // command, so the process cap applies to the entire app rather than one batch.
    let semaphore = real_delay_semaphore();
    let supervisor = app.state::<ProcessSupervisor>().inner().clone();
    let mut tasks = Vec::new();

    for profile in profiles {
        let app = app.clone();
        let semaphore = Arc::clone(&semaphore);
        let supervisor = supervisor.clone();
        let settings = settings.clone();
        let fallback = RealDelayResult {
            profile_id: profile.id.clone(),
            name: profile.name.clone(),
            server: profile.server.clone(),
            port: profile.port,
            config_status: "not_checked".to_string(),
            config_detail: "The preflight worker did not complete normally.".to_string(),
            real_delay_ms: None,
            real_delay_detail: "No delay result is available for this profile.".to_string(),
            tested_url: None,
        };
        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok();
            let profile_id = profile.id.clone();
            let name = profile.name.clone();
            let server = profile.server.clone();
            let port = profile.port;
            let base = |config_status: &str, config_detail: String, delay_detail: String| {
                RealDelayResult {
                    profile_id: profile_id.clone(),
                    name: name.clone(),
                    server: server.clone(),
                    port,
                    config_status: config_status.to_string(),
                    config_detail,
                    real_delay_ms: None,
                    real_delay_detail: delay_detail,
                    tested_url: None,
                }
            };

            let credentials = match profile_store::get_credentials(&profile.id) {
                Ok(credentials) => credentials,
                Err(error) => {
                    return base(
                        "not_checked",
                        error,
                        "Not run because profile credentials could not be retrieved.".to_string(),
                    );
                }
            };

            match crate::engine::sing_box::measure_real_delay(
                &app,
                &profile,
                &credentials,
                &settings,
                &supervisor,
            )
            .await
            {
                Ok(outcome) => RealDelayResult {
                    profile_id: profile_id.clone(),
                    name: name.clone(),
                    server: server.clone(),
                    port,
                    config_status: outcome.config_status,
                    config_detail: outcome.config_detail,
                    real_delay_ms: outcome.real_delay_ms,
                    real_delay_detail: outcome.real_delay_detail,
                    tested_url: outcome.tested_url,
                },
                Err(error) => base(
                    "not_checked",
                    error,
                    "Not run because the preflight runtime could not be prepared safely.".to_string(),
                ),
            }
        });
        // Dropping this JoinHandle detaches the worker instead of aborting it. If the
        // invoking window closes or the command future is cancelled, the worker can
        // still stop and reap its child process and remove its temporary directory.
        tasks.push((task, fallback));
    }

    let mut results = Vec::new();
    for (task, fallback) in tasks {
        results.push(task.await.unwrap_or(fallback));
    }

    results.sort_by(|left, right| {
        match (left.real_delay_ms, right.real_delay_ms) {
            (Some(left), Some(right)) => left.cmp(&right),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => left.name.cmp(&right.name),
        }
    });
    Ok(results)
}
