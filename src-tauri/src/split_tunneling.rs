use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Manager};

const SETTINGS_SCHEMA_VERSION: u32 = 1;
const SETTINGS_FILE_NAME: &str = "split-tunneling-settings.json";
const MAX_APPLICATIONS: usize = 256;
const MAX_PATH_BYTES: usize = 2048;
const DIRECT_OUTBOUND_TAG: &str = "blacklist-direct";
const DIRECT_DNS_TAG: &str = "blacklist-direct-dns";
const VPN_DNS_TAG: &str = "blacklist-remote-dns";
const VPN_OUTBOUND_TAG: &str = "blacklist-profile";

static SETTINGS_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn lock_settings() -> Result<MutexGuard<'static, ()>, String> {
    SETTINGS_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| "Split Tunneling settings are temporarily unavailable.".to_string())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SplitTunnelingMode {
    FullTunnel,
    DirectOnly,
    IncludeSelected,
    ExcludeSelected,
    Custom,
}

impl Default for SplitTunnelingMode {
    fn default() -> Self {
        Self::FullTunnel
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AppRoutingAction {
    Tunnel,
    Direct,
    Block,
}

impl Default for AppRoutingAction {
    fn default() -> Self {
        Self::Tunnel
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationRule {
    pub id: String,
    pub executable_path: String,
    #[serde(default)]
    pub action: AppRoutingAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelingSettings {
    #[serde(default)]
    pub mode: SplitTunnelingMode,
    #[serde(default)]
    pub default_action: AppRoutingAction,
    #[serde(default)]
    pub applications: Vec<ApplicationRule>,
}

impl Default for SplitTunnelingSettings {
    fn default() -> Self {
        Self {
            mode: SplitTunnelingMode::FullTunnel,
            default_action: AppRoutingAction::Tunnel,
            applications: Vec::new(),
        }
    }
}

impl SplitTunnelingSettings {
    pub fn normalize(&mut self) -> Result<(), String> {
        if self.applications.len() > MAX_APPLICATIONS {
            return Err(format!(
                "At most {MAX_APPLICATIONS} Windows applications can be configured."
            ));
        }

        let mut ids = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for application in &mut self.applications {
            application.id = application.id.trim().to_string();
            if application.id.is_empty()
                || application.id.len() > 64
                || !application
                    .id
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
            {
                return Err("Each application rule needs a valid, unique identifier.".to_string());
            }
            if !ids.insert(application.id.clone()) {
                return Err("Application rule identifiers must be unique.".to_string());
            }

            application.executable_path =
                normalize_windows_executable_path(&application.executable_path)?;
            let key = application.executable_path.to_ascii_lowercase();
            if !paths.insert(key) {
                return Err(
                    "The same executable path cannot be added more than once.".to_string(),
                );
            }
        }

        self.validate_mode_defaults()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.applications.len() > MAX_APPLICATIONS {
            return Err(format!(
                "At most {MAX_APPLICATIONS} Windows applications can be configured."
            ));
        }

        let mut ids = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for application in &self.applications {
            if application.id.trim().is_empty()
                || application.id.len() > 64
                || !application
                    .id
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
                || !ids.insert(application.id.as_str())
            {
                return Err("Each application rule needs a valid, unique identifier.".to_string());
            }

            let path = normalize_windows_executable_path(&application.executable_path)?;
            if !paths.insert(path.to_ascii_lowercase()) {
                return Err(
                    "The same executable path cannot be added more than once.".to_string(),
                );
            }
        }

        self.validate_mode_defaults()
    }

    fn validate_mode_defaults(&self) -> Result<(), String> {
        let valid_default = match self.mode {
            SplitTunnelingMode::FullTunnel | SplitTunnelingMode::ExcludeSelected => {
                self.default_action == AppRoutingAction::Tunnel
            }
            SplitTunnelingMode::DirectOnly | SplitTunnelingMode::IncludeSelected => {
                self.default_action == AppRoutingAction::Direct
            }
            SplitTunnelingMode::Custom => true,
        };
        if !valid_default {
            return Err(
                "The default action is fixed by the selected Split Tunneling preset.".to_string(),
            );
        }
        Ok(())
    }

    pub fn effective_default_action(&self) -> AppRoutingAction {
        match self.mode {
            SplitTunnelingMode::FullTunnel | SplitTunnelingMode::ExcludeSelected => {
                AppRoutingAction::Tunnel
            }
            SplitTunnelingMode::DirectOnly | SplitTunnelingMode::IncludeSelected => {
                AppRoutingAction::Direct
            }
            SplitTunnelingMode::Custom => self.default_action,
        }
    }

    pub fn effective_application_action(
        &self,
        application: &ApplicationRule,
    ) -> Option<AppRoutingAction> {
        match self.mode {
            SplitTunnelingMode::FullTunnel | SplitTunnelingMode::DirectOnly => None,
            SplitTunnelingMode::IncludeSelected => Some(AppRoutingAction::Tunnel),
            SplitTunnelingMode::ExcludeSelected => Some(AppRoutingAction::Direct),
            SplitTunnelingMode::Custom => Some(application.action),
        }
    }

    pub fn needs_direct_dns(&self) -> bool {
        self.effective_default_action() == AppRoutingAction::Direct
            || self.applications.iter().any(|application| {
                self.effective_application_action(application) == Some(AppRoutingAction::Direct)
            })
    }
}

pub fn normalize_windows_executable_path(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.trim() != value
        || value.chars().any(|ch| ch.is_control() || matches!(ch, '*' | '?' | '"' | '<' | '>' | '|'))
    {
        return Err("Select a valid Windows .exe path (maximum 2048 bytes).".to_string());
    }

    let normalized = value.replace('/', "\\");
    let bytes = normalized.as_bytes();
    if bytes.len() < 7
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
    {
        return Err("The executable path must be an absolute drive path such as C:\\Apps\\app.exe.".to_string());
    }

    if !normalized.to_ascii_lowercase().ends_with(".exe") {
        return Err("Only Windows executable (.exe) files can be added.".to_string());
    }

    let components = normalized[3..].split('\\').collect::<Vec<_>>();
    if components.is_empty()
        || components.iter().any(|component| {
            component.is_empty() || *component == "." || *component == ".."
        })
    {
        return Err("The executable path contains an invalid or relative path component.".to_string());
    }

    Ok(normalized)
}

fn route_rule(path: &str, action: AppRoutingAction) -> Value {
    match action {
        AppRoutingAction::Tunnel => json!({
            "process_path": [path],
            "action": "route",
            "outbound": VPN_OUTBOUND_TAG
        }),
        AppRoutingAction::Direct => json!({
            "process_path": [path],
            "action": "route",
            "outbound": DIRECT_OUTBOUND_TAG
        }),
        AppRoutingAction::Block => json!({
            "process_path": [path],
            "action": "reject"
        }),
    }
}

fn dns_rule(path: &str, action: AppRoutingAction) -> Value {
    match action {
        AppRoutingAction::Tunnel => json!({
            "process_path": [path],
            "action": "route",
            "server": VPN_DNS_TAG
        }),
        AppRoutingAction::Direct => json!({
            "process_path": [path],
            "action": "route",
            "server": DIRECT_DNS_TAG
        }),
        AppRoutingAction::Block => json!({
            "process_path": [path],
            "action": "reject"
        }),
    }
}

/// Apply the Windows process-based routing policy to a generated TUN config.
/// Windows sing-box process matching is based on the Win32 executable path.
/// The Direct DNS endpoint must be discovered from the physical adapter before
/// TUN/DNS hijack is activated; it is never guessed here.
pub fn apply_to_tun_config(
    config: &mut Value,
    settings: &SplitTunnelingSettings,
    direct_dns_server_ip: Option<&str>,
) -> Result<(), String> {
    settings.validate()?;

    if settings.needs_direct_dns() {
        let dns_ip = direct_dns_server_ip
            .ok_or_else(|| "A physical-interface DNS server IP is required for Direct application routing.".to_string())?
            .parse::<std::net::IpAddr>()
            .map_err(|_| "The physical-interface DNS server must be a numeric IP address.".to_string())?;

        let servers = config["dns"]["servers"]
            .as_array_mut()
            .ok_or_else(|| "The generated TUN config has no DNS server list.".to_string())?;
        servers.push(json!({
            "type": "udp",
            "tag": DIRECT_DNS_TAG,
            "server": dns_ip.to_string(),
            "server_port": 53,
            "detour": DIRECT_OUTBOUND_TAG
        }));
    }

    let outbounds = config["outbounds"]
        .as_array_mut()
        .ok_or_else(|| "The generated TUN config has no outbound list.".to_string())?;
    if outbounds
        .iter()
        .any(|outbound| outbound.get("tag").and_then(Value::as_str) == Some(DIRECT_OUTBOUND_TAG))
    {
        return Err("The generated TUN config already contains the reserved Direct outbound tag.".to_string());
    }
    outbounds.push(json!({
        "type": "direct",
        "tag": DIRECT_OUTBOUND_TAG
    }));

    let default_action = settings.effective_default_action();
    let mut route_rules = Vec::new();
    let mut dns_rules = Vec::new();

    if !matches!(
        settings.mode,
        SplitTunnelingMode::FullTunnel | SplitTunnelingMode::DirectOnly
    ) {
        for application in &settings.applications {
            let action = settings
                .effective_application_action(application)
                .ok_or_else(|| "An application routing rule is not active in this mode.".to_string())?;
            let path = normalize_windows_executable_path(&application.executable_path)?;
            route_rules.push(route_rule(&path, action));
            dns_rules.push(dns_rule(&path, action));
        }
    }

    if default_action == AppRoutingAction::Block {
        route_rules.push(json!({"action":"reject"}));
        dns_rules.push(json!({"action":"reject"}));
    }

    config["route"]["rules"] = Value::Array(route_rules);
    config["route"]["final"] = json!(match default_action {
        AppRoutingAction::Tunnel => VPN_OUTBOUND_TAG,
        AppRoutingAction::Direct | AppRoutingAction::Block => DIRECT_OUTBOUND_TAG,
    });

    config["dns"]["rules"] = Value::Array(dns_rules);
    config["dns"]["final"] = json!(match default_action {
        AppRoutingAction::Tunnel => VPN_DNS_TAG,
        AppRoutingAction::Direct | AppRoutingAction::Block => {
            if settings.needs_direct_dns() {
                DIRECT_DNS_TAG
            } else {
                VPN_DNS_TAG
            }
        }
    });

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct SettingsFile {
    schema_version: u32,
    settings: SplitTunnelingSettings,
}

fn settings_file_path(app: &AppHandle) -> Result<PathBuf, String> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|_| "Could not resolve the application data directory for Split Tunneling.".to_string())?;
    fs::create_dir_all(&directory)
        .map_err(|_| "Could not create the application data directory for Split Tunneling.".to_string())?;
    Ok(directory.join(SETTINGS_FILE_NAME))
}

fn read_file(path: &Path) -> Result<SplitTunnelingSettings, String> {
    let content = fs::read_to_string(path)
        .map_err(|_| "Could not read the saved Split Tunneling settings.".to_string())?;
    let mut file: SettingsFile = serde_json::from_str(&content)
        .map_err(|_| "The saved Split Tunneling settings are invalid or corrupted.".to_string())?;
    if file.schema_version != SETTINGS_SCHEMA_VERSION {
        return Err("The saved Split Tunneling settings use an unsupported schema version.".to_string());
    }
    file.settings.normalize()?;
    Ok(file.settings)
}

fn write_file(path: &Path, settings: &SplitTunnelingSettings) -> Result<(), String> {
    let mut settings = settings.clone();
    settings.normalize()?;
    let file = SettingsFile {
        schema_version: SETTINGS_SCHEMA_VERSION,
        settings,
    };
    let json = serde_json::to_vec_pretty(&file)
        .map_err(|_| "Could not encode the Split Tunneling settings.".to_string())?;
    let temporary_path = path.with_extension("json.tmp");
    fs::write(&temporary_path, json)
        .map_err(|_| "Could not write the temporary Split Tunneling settings file.".to_string())?;
    fs::rename(&temporary_path, path)
        .map_err(|_| "Could not commit the Split Tunneling settings file.".to_string())?;
    Ok(())
}

pub fn load(app: &AppHandle) -> Result<SplitTunnelingSettings, String> {
    let _guard = lock_settings()?;
    let path = settings_file_path(app)?;
    if !path.exists() {
        let defaults = SplitTunnelingSettings::default();
        write_file(&path, &defaults)?;
        return Ok(defaults);
    }
    read_file(&path)
}

pub fn save(
    app: &AppHandle,
    settings: SplitTunnelingSettings,
) -> Result<SplitTunnelingSettings, String> {
    let _guard = lock_settings()?;
    let path = settings_file_path(app)?;
    write_file(&path, &settings)?;
    read_file(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(id: &str, path: &str, action: AppRoutingAction) -> ApplicationRule {
        ApplicationRule {
            id: id.to_string(),
            executable_path: path.to_string(),
            action,
        }
    }

    #[test]
    fn defaults_to_full_tunnel_without_application_overrides() {
        let settings = SplitTunnelingSettings::default();
        assert_eq!(settings.mode, SplitTunnelingMode::FullTunnel);
        assert_eq!(settings.effective_default_action(), AppRoutingAction::Tunnel);
        assert!(!settings.needs_direct_dns());
    }

    #[test]
    fn normalizes_slashes_and_rejects_relative_or_non_executable_paths() {
        assert_eq!(
            normalize_windows_executable_path("C:/Program Files/Discord/Discord.exe").unwrap(),
            "C:\\Program Files\\Discord\\Discord.exe"
        );
        for path in [
            "Discord.exe",
            "C:relative\\app.exe",
            "C:\\apps\\..\\app.exe",
            "C:\\apps\\wild*.exe",
            "C:\\apps\\readme.txt",
        ] {
            assert!(normalize_windows_executable_path(path).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn rejects_duplicate_paths_even_when_case_differs() {
        let mut settings = SplitTunnelingSettings {
            mode: SplitTunnelingMode::Custom,
            default_action: AppRoutingAction::Tunnel,
            applications: vec![
                app("one", "C:\\Apps\\Chat.exe", AppRoutingAction::Direct),
                app("two", "c:\\apps\\chat.EXE", AppRoutingAction::Block),
            ],
        };
        assert!(settings.normalize().is_err());
    }

    #[test]
    fn covers_full_direct_include_exclude_and_custom_modes() {
        let applications = vec![app("discord", "C:\\Apps\\Discord.exe", AppRoutingAction::Tunnel)];
        let cases = [
            (
                SplitTunnelingSettings { mode: SplitTunnelingMode::FullTunnel, default_action: AppRoutingAction::Tunnel, applications: applications.clone() },
                AppRoutingAction::Tunnel,
                None,
            ),
            (
                SplitTunnelingSettings { mode: SplitTunnelingMode::DirectOnly, default_action: AppRoutingAction::Direct, applications: applications.clone() },
                AppRoutingAction::Direct,
                None,
            ),
            (
                SplitTunnelingSettings { mode: SplitTunnelingMode::IncludeSelected, default_action: AppRoutingAction::Direct, applications: applications.clone() },
                AppRoutingAction::Direct,
                Some(AppRoutingAction::Tunnel),
            ),
            (
                SplitTunnelingSettings { mode: SplitTunnelingMode::ExcludeSelected, default_action: AppRoutingAction::Tunnel, applications: applications.clone() },
                AppRoutingAction::Tunnel,
                Some(AppRoutingAction::Direct),
            ),
            (
                SplitTunnelingSettings { mode: SplitTunnelingMode::Custom, default_action: AppRoutingAction::Block, applications },
                AppRoutingAction::Block,
                Some(AppRoutingAction::Tunnel),
            ),
        ];

        for (settings, default_action, app_action) in cases {
            assert_eq!(settings.effective_default_action(), default_action);
            assert_eq!(
                settings.effective_application_action(&settings.applications[0]),
                app_action
            );
        }
    }

    #[test]
    fn custom_mode_supports_tunnel_direct_and_block_for_each_application() {
        let mut settings = SplitTunnelingSettings {
            mode: SplitTunnelingMode::Custom,
            default_action: AppRoutingAction::Block,
            applications: vec![
                app("vpn", "C:\\Apps\\Vpn.exe", AppRoutingAction::Tunnel),
                app("direct", "C:\\Apps\\Direct.exe", AppRoutingAction::Direct),
                app("blocked", "C:\\Apps\\Blocked.exe", AppRoutingAction::Block),
            ],
        };
        settings.normalize().unwrap();
        assert!(settings.needs_direct_dns());
        assert_eq!(settings.applications.len(), 3);
    }

    #[test]
    fn persists_and_reloads_versioned_policy_file() {
        let root = std::env::temp_dir().join(format!(
            "blacklist-split-policy-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join(SETTINGS_FILE_NAME);
        let settings = SplitTunnelingSettings {
            mode: SplitTunnelingMode::IncludeSelected,
            default_action: AppRoutingAction::Direct,
            applications: vec![app("discord", "C:\\Apps\\Discord.exe", AppRoutingAction::Tunnel)],
        };
        write_file(&path, &settings).unwrap();
        assert_eq!(read_file(&path).unwrap(), settings);
        fs::remove_dir_all(root).unwrap();
    }
}
