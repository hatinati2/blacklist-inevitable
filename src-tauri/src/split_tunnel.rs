//! Windows per-application routing policy for the normal TUN session.
//!
//! Process-path routing is evaluated by the pinned sing-box engine. Paths are
//! exact Win32 executable paths (the same form returned by
//! QueryFullProcessImageNameW), never shell fragments or regular expressions.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const MAX_APPLICATIONS: usize = 256;
const MAX_EXECUTABLE_PATH_CHARS: usize = 1024;
const VPN_OUTBOUND_TAG: &str = "blacklist-profile";
const DIRECT_OUTBOUND_TAG: &str = "blacklist-direct";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SplitTunnelMode {
    /// Every application uses the configured proxy.
    FullTunnel,
    /// Every application connects directly; DNS remains encrypted but is not
    /// sent through the selected proxy.
    DirectOnly,
    /// Only listed applications use the proxy; all other applications are direct.
    IncludeSelected,
    /// Listed applications connect directly; all other applications use the proxy.
    ExcludeSelected,
    /// Each listed application gets an explicit VPN, Direct, or Block action.
    /// Unlisted applications follow default_route.
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ApplicationRoute {
    Vpn,
    Direct,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplitTunnelApplication {
    pub executable_path: String,
    #[serde(default = "default_application_route")]
    pub action: ApplicationRoute,
}

fn default_application_route() -> ApplicationRoute {
    ApplicationRoute::Vpn
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplitTunnelPolicy {
    pub mode: SplitTunnelMode,
    /// Fallback for unlisted processes in Custom mode. Block is intentionally
    /// not a fallback: the UI must make a positive per-application Block choice.
    #[serde(default = "default_route")]
    pub default_route: ApplicationRoute,
    #[serde(default)]
    pub applications: Vec<SplitTunnelApplication>,
}

fn default_route() -> ApplicationRoute {
    ApplicationRoute::Vpn
}

impl Default for SplitTunnelPolicy {
    fn default() -> Self {
        Self {
            mode: SplitTunnelMode::FullTunnel,
            default_route: ApplicationRoute::Vpn,
            applications: Vec::new(),
        }
    }
}

fn normalize_executable_path(path: &str) -> Result<String, String> {
    if path.is_empty()
        || path.len() > MAX_EXECUTABLE_PATH_CHARS * 4
        || path.trim() != path
        || path.chars().any(|ch| ch.is_control() || matches!(ch, '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return Err("An application executable path is empty, malformed, or too long.".to_string());
    }

    let normalized = path.replace('/', "\\");
    let bytes = normalized.as_bytes();
    let is_drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\';
    let is_unc_absolute = normalized.starts_with("\\\\");
    if !is_drive_absolute && !is_unc_absolute {
        return Err("Applications must use an absolute Windows executable path.".to_string());
    }
    if normalized.chars().count() > MAX_EXECUTABLE_PATH_CHARS
        || !normalized.to_ascii_lowercase().ends_with(".exe")
    {
        return Err("Application paths must identify an .exe file within the path length limit.".to_string());
    }
    if normalized[2..].contains(':') {
        return Err("Application paths cannot contain alternate data stream syntax.".to_string());
    }

    let components: Vec<&str> = if is_drive_absolute {
        normalized[3..].split('\\').collect()
    } else {
        normalized[2..].split('\\').collect()
    };
    if components.iter().any(|part| {
        part.is_empty()
            || *part == "."
            || *part == ".."
            || part.ends_with(' ')
            || part.ends_with('.')
    }) {
        return Err("Application paths cannot contain empty, relative, or ambiguous path components.".to_string());
    }
    if is_unc_absolute && components.len() < 3 {
        return Err("A UNC executable path must include a server, share, and executable.".to_string());
    }
    Ok(normalized)
}

fn validated_applications(
    policy: &SplitTunnelPolicy,
) -> Result<Vec<(String, ApplicationRoute)>, String> {
    if policy.applications.len() > MAX_APPLICATIONS {
        return Err(format!("At most {MAX_APPLICATIONS} applications can be selected."));
    }
    if policy.mode == SplitTunnelMode::Custom && policy.default_route == ApplicationRoute::Block {
        return Err("Custom mode requires VPN or Direct as the default for unlisted applications.".to_string());
    }

    let mut seen = HashSet::new();
    let mut applications = Vec::with_capacity(policy.applications.len());
    for app in &policy.applications {
        let path = normalize_executable_path(&app.executable_path)?;
        let identity = path.to_lowercase();
        if !seen.insert(identity) {
            return Err("The same executable has been added more than once.".to_string());
        }
        applications.push((path, app.action));
    }
    Ok(applications)
}

/// Apply an app-routing policy to a generated TUN configuration. This function
/// only edits the sing-box JSON; the Windows agent still has to start the
/// engine and own the actual network transaction.
pub fn apply_split_tunnel_policy(
    config: &mut Value,
    policy: &SplitTunnelPolicy,
) -> Result<(), String> {
    let applications = validated_applications(policy)?;
    let outbounds = config
        .get_mut("outbounds")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "The TUN configuration has no outbound list.".to_string())?;

    if !outbounds.iter().any(|outbound| outbound["tag"] == DIRECT_OUTBOUND_TAG) {
        outbounds.push(json!({"type": "direct", "tag": DIRECT_OUTBOUND_TAG}));
    }

    let (default, selected_action) = match policy.mode {
        SplitTunnelMode::FullTunnel => (ApplicationRoute::Vpn, None),
        SplitTunnelMode::DirectOnly => (ApplicationRoute::Direct, None),
        SplitTunnelMode::IncludeSelected => (ApplicationRoute::Direct, Some(ApplicationRoute::Vpn)),
        SplitTunnelMode::ExcludeSelected => (ApplicationRoute::Vpn, Some(ApplicationRoute::Direct)),
        SplitTunnelMode::Custom => (policy.default_route, None),
    };

    let default_outbound = match default {
        ApplicationRoute::Vpn => VPN_OUTBOUND_TAG,
        ApplicationRoute::Direct => DIRECT_OUTBOUND_TAG,
        ApplicationRoute::Block => unreachable!("validated Custom default cannot be Block"),
    };
    config["route"]["final"] = json!(default_outbound);

    let mut vpn_paths = Vec::new();
    let mut direct_paths = Vec::new();
    let mut block_paths = Vec::new();
    for (path, action) in applications {
        let action = selected_action.unwrap_or(action);
        match action {
            ApplicationRoute::Vpn => vpn_paths.push(path),
            ApplicationRoute::Direct => direct_paths.push(path),
            ApplicationRoute::Block => block_paths.push(path),
        }
    }

    let mut rules = Vec::new();
    if !vpn_paths.is_empty() {
        rules.push(json!({
            "process_path": vpn_paths,
            "action": "route",
            "outbound": VPN_OUTBOUND_TAG
        }));
    }
    if !direct_paths.is_empty() {
        rules.push(json!({
            "process_path": direct_paths,
            "action": "route",
            "outbound": DIRECT_OUTBOUND_TAG
        }));
    }
    if !block_paths.is_empty() {
        rules.push(json!({
            "process_path": block_paths,
            "action": "reject",
            "method": "default"
        }));
    }
    config["route"]["rules"] = Value::Array(rules);

    // DirectOnly uses the direct outbound for encrypted DNS as well. Other
    // policies keep DNS on the proxy path so split routing cannot silently
    // turn selected-app DNS queries into plaintext or physical-interface DNS.
    if policy.mode == SplitTunnelMode::DirectOnly {
        if let Some(servers) = config["dns"]["servers"].as_array_mut() {
            for server in servers {
                if server["tag"] == "blacklist-remote-dns" {
                    server["detour"] = json!(DIRECT_OUTBOUND_TAG);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn application(path: &str, action: ApplicationRoute) -> SplitTunnelApplication {
        SplitTunnelApplication {
            executable_path: path.to_string(),
            action,
        }
    }

    fn base_config() -> Value {
        json!({
            "outbounds": [{"type": "trojan", "tag": VPN_OUTBOUND_TAG}],
            "route": {"final": VPN_OUTBOUND_TAG},
            "dns": {"servers": [{"tag": "blacklist-remote-dns", "detour": VPN_OUTBOUND_TAG}]}
        })
    }

    #[test]
    fn full_tunnel_and_direct_only_select_the_correct_default_route() {
        let mut config = base_config();
        apply_split_tunnel_policy(&mut config, &SplitTunnelPolicy::default()).unwrap();
        assert_eq!(config["route"]["final"], VPN_OUTBOUND_TAG);
        assert_eq!(config["route"]["rules"].as_array().unwrap().len(), 0);
        assert_eq!(config["outbounds"][1]["type"], "direct");

        let mut config = base_config();
        let policy = SplitTunnelPolicy {
            mode: SplitTunnelMode::DirectOnly,
            ..SplitTunnelPolicy::default()
        };
        apply_split_tunnel_policy(&mut config, &policy).unwrap();
        assert_eq!(config["route"]["final"], DIRECT_OUTBOUND_TAG);
        assert_eq!(config["dns"]["servers"][0]["detour"], DIRECT_OUTBOUND_TAG);
    }

    #[test]
    fn include_and_exclude_selected_modes_invert_the_fallback_route() {
        let apps = vec![application(r"C:\\Apps\\Discord\\Discord.exe", ApplicationRoute::Vpn)];

        let mut include = base_config();
        apply_split_tunnel_policy(&mut include, &SplitTunnelPolicy {
            mode: SplitTunnelMode::IncludeSelected,
            applications: apps.clone(),
            ..SplitTunnelPolicy::default()
        }).unwrap();
        assert_eq!(include["route"]["final"], DIRECT_OUTBOUND_TAG);
        assert_eq!(include["route"]["rules"][0]["outbound"], VPN_OUTBOUND_TAG);

        let mut exclude = base_config();
        apply_split_tunnel_policy(&mut exclude, &SplitTunnelPolicy {
            mode: SplitTunnelMode::ExcludeSelected,
            applications: apps,
            ..SplitTunnelPolicy::default()
        }).unwrap();
        assert_eq!(exclude["route"]["final"], VPN_OUTBOUND_TAG);
        assert_eq!(exclude["route"]["rules"][0]["outbound"], DIRECT_OUTBOUND_TAG);
    }

    #[test]
    fn custom_mode_supports_per_application_vpn_direct_and_block() {
        let mut config = base_config();
        let policy = SplitTunnelPolicy {
            mode: SplitTunnelMode::Custom,
            default_route: ApplicationRoute::Direct,
            applications: vec![
                application(r"C:\\Apps\\Discord\\Discord.exe", ApplicationRoute::Vpn),
                application(r"C:\\Apps\\Telegram\\Telegram.exe", ApplicationRoute::Direct),
                application(r"C:\\Tools\\Restricted.exe", ApplicationRoute::Block),
            ],
        };
        apply_split_tunnel_policy(&mut config, &policy).unwrap();
        assert_eq!(config["route"]["final"], DIRECT_OUTBOUND_TAG);
        assert_eq!(config["route"]["rules"][0]["action"], "route");
        assert_eq!(config["route"]["rules"][0]["outbound"], VPN_OUTBOUND_TAG);
        assert_eq!(config["route"]["rules"][1]["outbound"], DIRECT_OUTBOUND_TAG);
        assert_eq!(config["route"]["rules"][2]["action"], "reject");
    }

    #[test]
    fn rejects_relative_invalid_duplicate_and_oversized_application_paths() {
        for path in ["Discord.exe", r"C:\\Apps\\..\\Discord.exe", r"C:\\bad|name.exe", r"C:\\folder\\file.txt"] {
            let policy = SplitTunnelPolicy {
                mode: SplitTunnelMode::IncludeSelected,
                applications: vec![application(path, ApplicationRoute::Vpn)],
                ..SplitTunnelPolicy::default()
            };
            assert!(validated_applications(&policy).is_err(), "accepted invalid path {path}");
        }

        let duplicate = SplitTunnelPolicy {
            mode: SplitTunnelMode::Custom,
            applications: vec![
                application(r"C:\\Apps\\Discord.exe", ApplicationRoute::Vpn),
                application(r"c:\\apps\\DISCORD.exe", ApplicationRoute::Direct),
            ],
            ..SplitTunnelPolicy::default()
        };
        assert!(validated_applications(&duplicate).is_err());

        let oversized = SplitTunnelPolicy {
            mode: SplitTunnelMode::Custom,
            applications: (0..=MAX_APPLICATIONS)
                .map(|index| application(&format!(r"C:\\Apps\\{index}.exe"), ApplicationRoute::Vpn))
                .collect(),
            ..SplitTunnelPolicy::default()
        };
        assert!(validated_applications(&oversized).is_err());
    }

    #[test]
    fn custom_mode_rejects_block_as_the_default_route() {
        let policy = SplitTunnelPolicy {
            mode: SplitTunnelMode::Custom,
            default_route: ApplicationRoute::Block,
            ..SplitTunnelPolicy::default()
        };
        assert!(apply_split_tunnel_policy(&mut base_config(), &policy).is_err());
    }
}
