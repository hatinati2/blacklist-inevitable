use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::destination_routing::{validate_destination_routing_policy, DestinationRoutingPolicy};
use crate::split_tunnel::{validate_split_tunnel_policy, SplitTunnelPolicy};

const SETTINGS_SCHEMA_VERSION: u32 = 1;
const SETTINGS_FILE_NAME: &str = "routing-settings.json";

static SETTINGS_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn lock_settings() -> Result<MutexGuard<'static, ()>, String> {
    SETTINGS_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| "Routing settings are temporarily unavailable.".to_string())
}

/// User-selected routing preferences persisted by the desktop app only.
/// These values are not sent to the privileged Agent or applied to Windows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoutingSettings {
    pub destination: DestinationRoutingPolicy,
    pub split_tunnel: SplitTunnelPolicy,
}

impl Default for RoutingSettings {
    fn default() -> Self {
        Self {
            destination: DestinationRoutingPolicy::default(),
            split_tunnel: SplitTunnelPolicy::default(),
        }
    }
}

impl RoutingSettings {
    pub fn validate(&self) -> Result<(), String> {
        validate_destination_routing_policy(&self.destination)?;
        validate_split_tunnel_policy(&self.split_tunnel)?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsFile {
    schema_version: u32,
    settings: RoutingSettings,
}

fn settings_file_path(app: &AppHandle) -> Result<PathBuf, String> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|_| "Could not resolve the application data directory for routing settings.".to_string())?;
    fs::create_dir_all(&directory)
        .map_err(|_| "Could not create the application data directory for routing settings.".to_string())?;
    Ok(directory.join(SETTINGS_FILE_NAME))
}

fn read_file(path: &Path) -> Result<RoutingSettings, String> {
    let content = fs::read_to_string(path)
        .map_err(|_| "Could not read the saved routing settings.".to_string())?;
    let file: SettingsFile = serde_json::from_str(&content)
        .map_err(|_| "The saved routing settings are invalid or corrupted.".to_string())?;

    if file.schema_version != SETTINGS_SCHEMA_VERSION {
        return Err("The saved routing settings use an unsupported schema version.".to_string());
    }

    file.settings.validate()?;
    Ok(file.settings)
}

fn write_file(path: &Path, settings: &RoutingSettings) -> Result<(), String> {
    settings.validate()?;
    let file = SettingsFile {
        schema_version: SETTINGS_SCHEMA_VERSION,
        settings: settings.clone(),
    };
    let json = serde_json::to_vec_pretty(&file)
        .map_err(|_| "Could not encode the routing settings.".to_string())?;
    let temporary_path = path.with_extension("json.tmp");

    fs::write(&temporary_path, json)
        .map_err(|_| "Could not write the temporary routing settings file.".to_string())?;
    fs::rename(&temporary_path, path)
        .map_err(|_| "Could not commit the routing settings file.".to_string())?;

    Ok(())
}

pub fn load(app: &AppHandle) -> Result<RoutingSettings, String> {
    let _guard = lock_settings()?;
    let path = settings_file_path(app)?;

    if !path.exists() {
        let defaults = RoutingSettings::default();
        write_file(&path, &defaults)?;
        return Ok(defaults);
    }

    read_file(&path)
}

pub fn save(app: &AppHandle, settings: RoutingSettings) -> Result<RoutingSettings, String> {
    settings.validate()?;
    let _guard = lock_settings()?;
    let path = settings_file_path(app)?;
    write_file(&path, &settings)?;
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination_routing::{DestinationAction, DestinationRule, TrafficRoutingMode};
    use crate::split_tunnel::{ApplicationRoute, SplitTunnelApplication, SplitTunnelMode};

    #[test]
    fn defaults_are_global_and_full_tunnel_and_validate() {
        let settings = RoutingSettings::default();
        assert_eq!(settings.destination.mode, TrafficRoutingMode::Global);
        assert_eq!(settings.split_tunnel.mode, SplitTunnelMode::FullTunnel);
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn validates_destination_matches_and_application_paths() {
        let mut settings = RoutingSettings::default();
        settings.destination.mode = TrafficRoutingMode::Rule;
        settings.destination.custom_rules.push(DestinationRule {
            domains: vec!["example.com".to_string()],
            domain_suffixes: vec![],
            ip_cidrs: vec!["2001:db8::/32".to_string()],
            action: DestinationAction::Direct,
        });
        settings.split_tunnel.applications.push(SplitTunnelApplication {
            executable_path: r"C:\Apps\Example.exe".to_string(),
            action: ApplicationRoute::Block,
        });
        assert!(settings.validate().is_ok());

        settings.destination.custom_rules[0].domains = vec!["*.bad.example".to_string()];
        assert!(settings.validate().is_err());

        let mut invalid_path = RoutingSettings::default();
        invalid_path.split_tunnel.mode = SplitTunnelMode::Custom;
        invalid_path.split_tunnel.applications.push(SplitTunnelApplication {
            executable_path: r"..\Example.exe".to_string(),
            action: ApplicationRoute::Vpn,
        });
        assert!(invalid_path.validate().is_err());
    }

    #[test]
    fn persists_and_reloads_versioned_routing_settings() {
        let root = std::env::temp_dir().join(format!(
            "blacklist-inevitable-routing-settings-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).expect("create isolated settings directory");
        let path = root.join(SETTINGS_FILE_NAME);

        let mut settings = RoutingSettings::default();
        settings.destination.mode = TrafficRoutingMode::Rule;
        settings.destination.custom_rules.push(DestinationRule {
            domains: vec!["special.example".to_string()],
            domain_suffixes: vec!["*.trusted.example".to_string()],
            ip_cidrs: vec!["203.0.113.0/24".to_string()],
            action: DestinationAction::Block,
        });
        settings.split_tunnel.mode = SplitTunnelMode::Custom;
        settings.split_tunnel.default_route = ApplicationRoute::Direct;
        settings.split_tunnel.applications.push(SplitTunnelApplication {
            executable_path: r"C:\Tools\Example.exe".to_string(),
            action: ApplicationRoute::Vpn,
        });

        write_file(&path, &settings).expect("persist settings");
        let loaded = read_file(&path).expect("read persisted settings");
        assert_eq!(loaded, settings);

        let mut updated = settings.clone();
        updated.destination.bypass_private = false;
        updated.split_tunnel.mode = SplitTunnelMode::ExcludeSelected;
        write_file(&path, &updated).expect("replace existing settings");
        assert_eq!(read_file(&path).expect("read updated settings"), updated);

        fs::remove_dir_all(root).expect("remove isolated settings directory");
    }

    #[test]
    fn rejects_unsupported_schema_and_corrupted_files() {
        let root = std::env::temp_dir().join(format!(
            "blacklist-inevitable-routing-settings-invalid-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).expect("create isolated settings directory");
        let path = root.join(SETTINGS_FILE_NAME);
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "schema_version": SETTINGS_SCHEMA_VERSION + 1,
                "settings": RoutingSettings::default()
            })).unwrap()
        ).expect("write unsupported schema");
        assert!(read_file(&path).unwrap_err().contains("unsupported schema"));

        fs::write(&path, b"{").expect("write corrupted json");
        assert!(read_file(&path).unwrap_err().contains("invalid or corrupted"));
        fs::remove_dir_all(root).expect("remove isolated settings directory");
    }
}
