use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::AppHandle;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::engine::{EngineDescriptor, ENGINE_TARGETS};
use crate::profile_store;
use crate::profiles::{parse_import_text, ImportIssue, ProfileSummary};

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
pub fn get_app_status(app: AppHandle) -> AppStatus {
    AppStatus {
        app_name: "blacklist-inevitable",
        version: env!("CARGO_PKG_VERSION"),
        development_stage: "profile management foundation",
        connection_implemented: false,
        preflight_testing_implemented: false,
        profile_management_implemented: true,
        endpoint_tcp_test_implemented: true,
        sing_box_installed: crate::engine::sing_box::is_installed(&app),
        engines: ENGINE_TARGETS.to_vec(),
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
    let tcp_supported = matches!(
        profile.protocol.as_str(),
        "vless" | "vmess" | "trojan" | "shadowsocks"
    );

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
    crate::engine::sing_box::install(&app).await
}

#[tauri::command]
pub async fn validate_profile_config(
    app: AppHandle,
    profile_id: String,
) -> Result<ConfigValidationResult, String> {
    let profiles = profile_store::list_profiles(&app)?;
    let profile = profiles
        .into_iter()
        .find(|profile| profile.id == profile_id)
        .ok_or_else(|| "Profile not found.".to_string())?;
    let credentials = profile_store::get_credentials(&profile.id)?;
    match crate::engine::sing_box::validate_profile_config(&app, &profile, &credentials).await {
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
pub async fn test_all_profile_real_delays(
    app: AppHandle,
) -> Result<Vec<RealDelayResult>, String> {
    let profiles = profile_store::list_profiles(&app)?;
    let semaphore = Arc::new(Semaphore::new(4));
    let mut tasks = JoinSet::new();

    for profile in profiles {
        let app = app.clone();
        let semaphore = Arc::clone(&semaphore);
        tasks.spawn(async move {
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

            match crate::engine::sing_box::measure_real_delay(&app, &profile, &credentials).await {
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
    }

    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok(result) = result {
            results.push(result);
        }
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
