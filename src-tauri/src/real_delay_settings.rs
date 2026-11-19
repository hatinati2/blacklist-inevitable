use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use url::Url;

const SETTINGS_SCHEMA_VERSION: u32 = 1;
const SETTINGS_FILE_NAME: &str = "real-delay-settings.json";
pub const MIN_TIMEOUT_SECONDS: u64 = 2;
pub const MAX_TIMEOUT_SECONDS: u64 = 30;

static SETTINGS_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn lock_settings() -> Result<MutexGuard<'static, ()>, String> {
    SETTINGS_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| "Real Delay settings are temporarily unavailable.".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RealDelaySettings {
    pub primary_url: String,
    pub fallback_url: String,
    pub timeout_seconds: u64,
}

impl Default for RealDelaySettings {
    fn default() -> Self {
        Self {
            primary_url: "https://www.gstatic.com/generate_204".to_string(),
            fallback_url: "https://cp.cloudflare.com/generate_204".to_string(),
            timeout_seconds: 9,
        }
    }
}

impl RealDelaySettings {
    pub fn validate(&self) -> Result<(), String> {
        validate_endpoint("Primary", &self.primary_url)?;
        validate_endpoint("Fallback", &self.fallback_url)?;

        if !(MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&self.timeout_seconds) {
            return Err(format!(
                "Real Delay timeout must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS} seconds."
            ));
        }

        Ok(())
    }
}

fn validate_endpoint(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 2048 || value.trim() != value {
        return Err(format!("{label} Real Delay endpoint must be a valid HTTPS URL no longer than 2048 characters."));
    }

    let parsed = Url::parse(value)
        .map_err(|_| format!("{label} Real Delay endpoint must be a valid HTTPS URL."))?;

    if parsed.scheme() != "https" {
        return Err(format!("{label} Real Delay endpoint must use HTTPS."));
    }
    if parsed.host_str().is_none() {
        return Err(format!("{label} Real Delay endpoint must include a host."));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!("{label} Real Delay endpoint must not contain embedded credentials."));
    }
    if parsed.fragment().is_some() {
        return Err(format!("{label} Real Delay endpoint must not contain a URL fragment."));
    }

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct SettingsFile {
    schema_version: u32,
    real_delay: RealDelaySettings,
}

fn settings_file_path(app: &AppHandle) -> Result<PathBuf, String> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|_| "Could not resolve the application data directory for Real Delay settings.".to_string())?;
    fs::create_dir_all(&directory)
        .map_err(|_| "Could not create the application data directory for Real Delay settings.".to_string())?;
    Ok(directory.join(SETTINGS_FILE_NAME))
}

fn read_file(path: &Path) -> Result<RealDelaySettings, String> {
    let content = fs::read_to_string(path)
        .map_err(|_| "Could not read the saved Real Delay settings.".to_string())?;
    let file: SettingsFile = serde_json::from_str(&content)
        .map_err(|_| "The saved Real Delay settings are invalid or corrupted.".to_string())?;

    if file.schema_version != SETTINGS_SCHEMA_VERSION {
        return Err("The saved Real Delay settings use an unsupported schema version.".to_string());
    }

    file.real_delay.validate()?;
    Ok(file.real_delay)
}

fn write_file(path: &Path, settings: &RealDelaySettings) -> Result<(), String> {
    settings.validate()?;
    let file = SettingsFile {
        schema_version: SETTINGS_SCHEMA_VERSION,
        real_delay: settings.clone(),
    };
    let json = serde_json::to_vec_pretty(&file)
        .map_err(|_| "Could not encode the Real Delay settings.".to_string())?;
    let temporary_path = path.with_extension("json.tmp");

    fs::write(&temporary_path, json)
        .map_err(|_| "Could not write the temporary Real Delay settings file.".to_string())?;
    fs::rename(&temporary_path, path)
        .map_err(|_| "Could not commit the Real Delay settings file.".to_string())?;

    Ok(())
}

pub fn load(app: &AppHandle) -> Result<RealDelaySettings, String> {
    let _guard = lock_settings()?;
    let path = settings_file_path(app)?;

    if !path.exists() {
        let defaults = RealDelaySettings::default();
        write_file(&path, &defaults)?;
        return Ok(defaults);
    }

    read_file(&path)
}

pub fn save(app: &AppHandle, settings: RealDelaySettings) -> Result<RealDelaySettings, String> {
    settings.validate()?;
    let _guard = lock_settings()?;
    let path = settings_file_path(app)?;
    write_file(&path, &settings)?;
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_preserve_the_existing_endpoints_and_timeout() {
        let settings = RealDelaySettings::default();
        assert_eq!(settings.primary_url, "https://www.gstatic.com/generate_204");
        assert_eq!(settings.fallback_url, "https://cp.cloudflare.com/generate_204");
        assert_eq!(settings.timeout_seconds, 9);
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn accepts_custom_https_endpoints_and_bounded_timeout() {
        let settings = RealDelaySettings {
            primary_url: "https://probe.example.test/204".to_string(),
            fallback_url: "https://backup.example.test/status?mode=204".to_string(),
            timeout_seconds: MAX_TIMEOUT_SECONDS,
        };
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn rejects_non_https_and_malformed_endpoints() {
        for endpoint in ["http://probe.example.test/204", "not-a-url", "https:///missing-host"] {
            let settings = RealDelaySettings {
                primary_url: endpoint.to_string(),
                ..RealDelaySettings::default()
            };
            assert!(settings.validate().is_err(), "endpoint should be rejected: {endpoint}");
        }
    }

    #[test]
    fn rejects_embedded_credentials_and_fragments() {
        for endpoint in [
            "https://user:password@probe.example.test/204",
            "https://probe.example.test/204#fragment",
        ] {
            let settings = RealDelaySettings {
                primary_url: endpoint.to_string(),
                ..RealDelaySettings::default()
            };
            assert!(settings.validate().is_err(), "endpoint should be rejected: {endpoint}");
        }
    }

    #[test]
    fn rejects_timeout_outside_the_safe_range() {
        for timeout_seconds in [0, MIN_TIMEOUT_SECONDS - 1, MAX_TIMEOUT_SECONDS + 1, 120] {
            let settings = RealDelaySettings {
                timeout_seconds,
                ..RealDelaySettings::default()
            };
            assert!(settings.validate().is_err());
        }
    }

    #[test]
    fn settings_round_trip_through_the_versioned_file() {
        let root = std::env::temp_dir().join(format!(
            "blacklist-inevitable-settings-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).expect("create isolated settings directory");
        let path = root.join(SETTINGS_FILE_NAME);
        let settings = RealDelaySettings {
            primary_url: "https://custom.example.test/generate_204".to_string(),
            fallback_url: "https://backup.example.test/generate_204".to_string(),
            timeout_seconds: 12,
        };

        write_file(&path, &settings).expect("persist settings");
        let loaded = read_file(&path).expect("read persisted settings");
        assert_eq!(loaded, settings);

        fs::remove_dir_all(root).expect("remove isolated settings directory");
    }
}
