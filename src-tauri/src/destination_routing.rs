//! Destination-based Global / Rule routing for Windows TUN sessions.
//!
//! Rule mode uses maintained Iranian domain/IP rule sets plus validated
//! user-defined domain and CIDR exceptions. Remote rule sets are fetched
//! through the physical Direct outbound and cached in the protected agent data
//! directory supplied by the caller.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;

const VPN_OUTBOUND_TAG: &str = "blacklist-profile";
const DIRECT_OUTBOUND_TAG: &str = "blacklist-direct";
const RULESET_HTTP_CLIENT_TAG: &str = "blacklist-rule-set-http";
const GEOSITE_IR_TAG: &str = "blacklist-geosite-ir";
const GEOIP_IR_TAG: &str = "blacklist-geoip-ir";
const GEOSITE_IR_URL: &str = "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/1597f121656f3e63f2624a471401002941d888c4/geosite-ir.srs";
const GEOIP_IR_URL: &str = "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/1597f121656f3e63f2624a471401002941d888c4/geoip-ir.srs";
const MAX_CUSTOM_RULES: usize = 256;
const MAX_VALUES_PER_RULE: usize = 128;
const MAX_DOMAIN_BYTES: usize = 253;
const MAX_CACHE_PATH_CHARS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TrafficRoutingMode {
    /// Karing-style Global: all traffic uses the selected proxy, except any
    /// separate per-application overrides applied by the caller.
    Global,
    /// Karing-style Rule: private/local and Iranian destinations are direct;
    /// other destinations use the selected proxy by default.
    Rule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DestinationAction {
    Direct,
    Vpn,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DestinationRule {
    /// Exact DNS names, e.g. "example.com".
    #[serde(default)]
    pub domains: Vec<String>,
    /// Domain suffixes, e.g. "example.com" or "*.example.com".
    #[serde(default)]
    pub domain_suffixes: Vec<String>,
    /// IPv4/IPv6 addresses or CIDRs, e.g. "203.0.113.0/24".
    #[serde(default)]
    pub ip_cidrs: Vec<String>,
    pub action: DestinationAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DestinationRoutingPolicy {
    pub mode: TrafficRoutingMode,
    #[serde(default = "default_true")]
    pub bypass_private: bool,
    #[serde(default = "default_true")]
    pub bypass_iran: bool,
    #[serde(default)]
    pub custom_rules: Vec<DestinationRule>,
}

fn default_true() -> bool {
    true
}

impl Default for DestinationRoutingPolicy {
    fn default() -> Self {
        Self {
            mode: TrafficRoutingMode::Global,
            bypass_private: true,
            bypass_iran: true,
            custom_rules: Vec::new(),
        }
    }
}

fn validate_domain(value: &str) -> Result<String, String> {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() || value.len() > MAX_DOMAIN_BYTES || value.trim() != value {
        return Err("A routing rule contains an empty or oversized domain.".to_string());
    }
    let normalized = value.to_ascii_lowercase();
    if normalized.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || !label.as_bytes()[0].is_ascii_alphanumeric()
            || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            || !label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err("A routing rule contains an invalid domain name.".to_string());
    }
    Ok(normalized)
}

fn validate_exact_domain(value: &str) -> Result<String, String> {
    if value.contains('*') || value.starts_with('.') {
        return Err("Exact domain rules must not contain wildcards or a leading dot.".to_string());
    }
    validate_domain(value)
}

fn validate_domain_suffix(value: &str) -> Result<String, String> {
    let suffix = value
        .strip_prefix("*.")
        .or_else(|| value.strip_prefix('.'))
        .unwrap_or(value);
    Ok(format!(".{}", validate_domain(suffix)?))
}

fn validate_ip_cidr(value: &str) -> Result<String, String> {
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (value, None),
    };
    let ip = address
        .parse::<std::net::IpAddr>()
        .map_err(|_| "A routing rule contains an invalid IP address or CIDR.".to_string())?;
    let max_prefix = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(prefix) => prefix
            .parse::<u8>()
            .map_err(|_| "A routing rule contains an invalid CIDR prefix.".to_string())?,
        None => max_prefix,
    };
    if prefix > max_prefix {
        return Err("A routing rule contains a CIDR prefix outside the address family range.".to_string());
    }
    Ok(format!("{ip}/{prefix}"))
}

fn validated_rules(policy: &DestinationRoutingPolicy) -> Result<Vec<DestinationRule>, String> {
    if policy.custom_rules.len() > MAX_CUSTOM_RULES {
        return Err(format!("At most {MAX_CUSTOM_RULES} custom destination rules are allowed."));
    }

    let mut result = Vec::with_capacity(policy.custom_rules.len());
    for rule in &policy.custom_rules {
        if rule.domains.len() > MAX_VALUES_PER_RULE
            || rule.domain_suffixes.len() > MAX_VALUES_PER_RULE
            || rule.ip_cidrs.len() > MAX_VALUES_PER_RULE
        {
            return Err(format!("Each destination rule is limited to {MAX_VALUES_PER_RULE} values per match type."));
        }
        if rule.domains.is_empty() && rule.domain_suffixes.is_empty() && rule.ip_cidrs.is_empty() {
            return Err("A custom destination rule must contain at least one domain or IP match.".to_string());
        }

        let domains = rule.domains.iter().map(|item| validate_exact_domain(item)).collect::<Result<Vec<_>, _>>()?;
        let suffixes = rule.domain_suffixes.iter().map(|item| validate_domain_suffix(item)).collect::<Result<Vec<_>, _>>()?;
        let cidrs = rule.ip_cidrs.iter().map(|item| validate_ip_cidr(item)).collect::<Result<Vec<_>, _>>()?;

        let mut seen = HashSet::new();
        for item in domains.iter().chain(suffixes.iter()).chain(cidrs.iter()) {
            if !seen.insert(item.to_ascii_lowercase()) {
                return Err("A custom destination rule contains duplicate match values.".to_string());
            }
        }

        result.push(DestinationRule {
            domains,
            domain_suffixes: suffixes,
            ip_cidrs: cidrs,
            action: rule.action,
        });
    }
    Ok(result)
}

/// Validate a destination policy without generating or applying an engine configuration.
pub fn validate_destination_routing_policy(policy: &DestinationRoutingPolicy) -> Result<(), String> {
    validated_rules(policy).map(|_| ())
}

fn validate_cache_path(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > MAX_CACHE_PATH_CHARS * 4
        || value.trim() != value
        || value.chars().any(|ch| ch.is_control() || matches!(ch, '"' | '|' | '<' | '>' | '?' | '*'))
    {
        return Err("The rule-set cache path is empty or invalid.".to_string());
    }
    let normalized = value.replace('/', "\\");
    let bytes = normalized.as_bytes();
    let is_drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\';
    let is_unc_absolute = normalized.starts_with("\\\\");
    if !is_drive_absolute && !is_unc_absolute {
        return Err("The rule-set cache must use an absolute Windows path.".to_string());
    }
    if normalized.chars().count() > MAX_CACHE_PATH_CHARS {
        return Err("The rule-set cache path exceeds the maximum length.".to_string());
    }
    let components = if is_drive_absolute { &normalized[3..] } else { &normalized[2..] };
    if components.split('\\').any(|part| part == "." || part == "..") {
        return Err("The rule-set cache path cannot contain relative path components.".to_string());
    }
    Ok(normalized)
}

fn route_rule_for(
    rule: &DestinationRule,
    vpn_tag: &str,
    direct_tag: &str,
) -> Value {
    let mut value = json!({});
    if !rule.domains.is_empty() {
        value["domain"] = json!(rule.domains);
    }
    if !rule.domain_suffixes.is_empty() {
        value["domain_suffix"] = json!(rule.domain_suffixes);
    }
    if !rule.ip_cidrs.is_empty() {
        value["ip_cidr"] = json!(rule.ip_cidrs);
    }

    match rule.action {
        DestinationAction::Vpn => {
            value["action"] = json!("route");
            value["outbound"] = json!(vpn_tag);
        }
        DestinationAction::Direct => {
            value["action"] = json!("route");
            value["outbound"] = json!(direct_tag);
        }
        DestinationAction::Block => {
            value["action"] = json!("reject");
            value["method"] = json!("default");
        }
    }
    value
}

/// Apply destination-based routing to a previously generated TUN config.
///
/// The caller supplies a cache path owned by the elevated Agent under its
/// protected ProgramData directory. This method does not download lists or
/// change OS networking itself.
pub fn apply_destination_routing_policy(
    config: &mut Value,
    policy: &DestinationRoutingPolicy,
    cache_file_path: &str,
) -> Result<(), String> {
    let custom_rules = validated_rules(policy)?;
    if policy.mode == TrafficRoutingMode::Global {
        // Global intentionally means no destination exceptions. App-level
        // process rules already present in the config are left intact.
        return Ok(());
    }

    let cache_path = validate_cache_path(cache_file_path)?;
    let outbounds = config
        .get_mut("outbounds")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "The TUN configuration has no outbound list.".to_string())?;
    if !outbounds.iter().any(|outbound| outbound["tag"] == VPN_OUTBOUND_TAG) {
        return Err("The TUN configuration is missing the selected VPN outbound.".to_string());
    }
    if !outbounds.iter().any(|outbound| outbound["tag"] == DIRECT_OUTBOUND_TAG) {
        outbounds.push(json!({"type": "direct", "tag": DIRECT_OUTBOUND_TAG}));
    }

    let route = config
        .get_mut("route")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "The TUN configuration has no route object.".to_string())?;

    let mut rules = vec![json!({"action": "sniff"})];
    if policy.bypass_private {
        rules.push(json!({
            "ip_is_private": true,
            "action": "route",
            "outbound": DIRECT_OUTBOUND_TAG
        }));
    }

    // Preserve process-based split-tunnel rules before destination rules. Thus
    // an explicit application's VPN/Direct/Block selection takes precedence
    // over geographic defaults, while local/private destinations stay direct.
    if let Some(existing) = route.get("rules").and_then(Value::as_array) {
        rules.extend(existing.iter().cloned());
    }

    // User exceptions are evaluated before the built-in Iran defaults.
    for rule in &custom_rules {
        rules.push(route_rule_for(rule, VPN_OUTBOUND_TAG, DIRECT_OUTBOUND_TAG));
    }

    if policy.bypass_iran {
        rules.push(json!({
            "domain_suffix": [".ir"],
            "action": "route",
            "outbound": DIRECT_OUTBOUND_TAG
        }));
        rules.push(json!({
            "rule_set": [GEOSITE_IR_TAG, GEOIP_IR_TAG],
            "action": "route",
            "outbound": DIRECT_OUTBOUND_TAG
        }));

        route.insert("rule_set".to_string(), json!([
            {
                "type": "remote",
                "tag": GEOSITE_IR_TAG,
                "format": "binary",
                "url": GEOSITE_IR_URL,
                "http_client": RULESET_HTTP_CLIENT_TAG,
                "update_interval": "24h"
            },
            {
                "type": "remote",
                "tag": GEOIP_IR_TAG,
                "format": "binary",
                "url": GEOIP_IR_URL,
                "http_client": RULESET_HTTP_CLIENT_TAG,
                "update_interval": "24h"
            }
        ]));
        route.insert("default_http_client".to_string(), json!(RULESET_HTTP_CLIENT_TAG));
    }

    route.insert("rules".to_string(), Value::Array(rules));

    if policy.bypass_iran {
        let mut clients = config
            .get("http_clients")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if clients.iter().any(|client| client["tag"] == RULESET_HTTP_CLIENT_TAG) {
            return Err("The rule-set HTTP client tag is already in use.".to_string());
        }
        clients.push(json!({
            "tag": RULESET_HTTP_CLIENT_TAG,
            "detour": DIRECT_OUTBOUND_TAG
        }));
        config["http_clients"] = Value::Array(clients);
    }

    config["dns"]["reverse_mapping"] = json!(true);
    config["experimental"]["cache_file"] = json!({
        "enabled": true,
        "path": cache_path,
        "store_dns": true
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CACHE_PATH: &str = r"C:\ProgramData\blacklist-inevitable\cache\sing-box.db";

    fn base_config() -> Value {
        json!({
            "inbounds": [{"type": "tun", "tag": "tun-in"}],
            "outbounds": [{"type": "trojan", "tag": VPN_OUTBOUND_TAG}],
            "route": {
                "final": VPN_OUTBOUND_TAG,
                "auto_detect_interface": true,
                "rules": [{
                    "process_path": [r"C:\Apps\Discord\Discord.exe"],
                    "action": "route",
                    "outbound": VPN_OUTBOUND_TAG
                }]
            },
            "dns": {
                "servers": [{"type": "https", "tag": "blacklist-remote-dns"}],
                "final": "blacklist-remote-dns"
            }
        })
    }

    #[test]
    fn global_mode_does_not_add_destination_bypass_rules() {
        let mut config = base_config();
        let original_rules = config["route"]["rules"].clone();
        apply_destination_routing_policy(&mut config, &DestinationRoutingPolicy::default(), CACHE_PATH).unwrap();
        assert_eq!(config["route"]["rules"], original_rules);
        assert!(config["route"].get("rule_set").is_none());
        assert!(config.get("http_clients").is_none());
    }

    #[test]
    fn rule_mode_routes_iran_private_and_unknown_destinations_correctly() {
        let mut config = base_config();
        let policy = DestinationRoutingPolicy {
            mode: TrafficRoutingMode::Rule,
            ..DestinationRoutingPolicy::default()
        };
        apply_destination_routing_policy(&mut config, &policy, CACHE_PATH).unwrap();

        let rules = config["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[1]["ip_is_private"], true);
        assert_eq!(rules[1]["outbound"], DIRECT_OUTBOUND_TAG);
        assert_eq!(rules[2]["process_path"][0], r"C:\Apps\Discord\Discord.exe");
        assert_eq!(rules[3]["domain_suffix"][0], ".ir");
        assert_eq!(rules[4]["rule_set"][0], GEOSITE_IR_TAG);
        assert_eq!(config["route"]["final"], VPN_OUTBOUND_TAG);
        assert_eq!(config["route"]["rule_set"][0]["type"], "remote");
        assert_eq!(config["route"]["rule_set"][1]["format"], "binary");
        assert_eq!(config["route"]["default_http_client"], RULESET_HTTP_CLIENT_TAG);
        assert_eq!(config["http_clients"][0]["detour"], DIRECT_OUTBOUND_TAG);
        assert_eq!(config["dns"]["reverse_mapping"], true);
        assert_eq!(config["experimental"]["cache_file"]["path"], CACHE_PATH);
        assert_eq!(config["experimental"]["cache_file"]["store_dns"], true);
    }

    #[test]
    fn custom_domain_ip_and_block_exceptions_precede_iran_defaults() {
        let mut config = base_config();
        let policy = DestinationRoutingPolicy {
            mode: TrafficRoutingMode::Rule,
            custom_rules: vec![
                DestinationRule {
                    domains: vec!["special.example".to_string()],
                    domain_suffixes: vec!["*.trusted.example".to_string()],
                    ip_cidrs: vec!["203.0.113.0/24".to_string()],
                    action: DestinationAction::Vpn,
                },
                DestinationRule {
                    domains: vec!["malware.example".to_string()],
                    domain_suffixes: Vec::new(),
                    ip_cidrs: Vec::new(),
                    action: DestinationAction::Block,
                },
            ],
            ..DestinationRoutingPolicy::default()
        };
        apply_destination_routing_policy(&mut config, &policy, CACHE_PATH).unwrap();

        let rules = config["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[3]["domain"][0], "special.example");
        assert_eq!(rules[3]["domain_suffix"][0], ".trusted.example");
        assert_eq!(rules[3]["ip_cidr"][0], "203.0.113.0/24");
        assert_eq!(rules[3]["outbound"], VPN_OUTBOUND_TAG);
        assert_eq!(rules[4]["action"], "reject");
        assert_eq!(rules[5]["domain_suffix"][0], ".ir");
    }

    #[test]
    fn can_disable_iran_bypass_but_keep_private_direct() {
        let mut config = base_config();
        let policy = DestinationRoutingPolicy {
            mode: TrafficRoutingMode::Rule,
            bypass_iran: false,
            ..DestinationRoutingPolicy::default()
        };
        apply_destination_routing_policy(&mut config, &policy, CACHE_PATH).unwrap();
        assert_eq!(config["route"]["rules"].as_array().map_or(0, |rules| rules.len()), 3);
        assert!(config["route"].get("rule_set").is_none());
        assert!(config["route"]["rules"][1]["ip_is_private"].as_bool().unwrap());
    }

    #[test]
    fn rejects_invalid_domains_cidrs_and_empty_rules() {
        assert!(validate_exact_domain("*.example.com").is_err());
        assert!(validate_exact_domain("bad..example.com").is_err());
        assert!(validate_domain_suffix("*").is_err());
        assert!(validate_ip_cidr("203.0.113.1/33").is_err());
        assert!(validate_ip_cidr("not-an-ip").is_err());
        assert!(validated_rules(&DestinationRoutingPolicy {
            mode: TrafficRoutingMode::Rule,
            custom_rules: vec![DestinationRule {
                domains: Vec::new(),
                domain_suffixes: Vec::new(),
                ip_cidrs: Vec::new(),
                action: DestinationAction::Direct,
            }],
            ..DestinationRoutingPolicy::default()
        }).is_err());
    }

    #[test]
    fn rejects_relative_and_traversal_cache_paths() {
        assert!(validate_cache_path("cache.db").is_err());
        assert!(validate_cache_path(r"C:\ProgramData\..\cache.db").is_err());
        assert!(validate_cache_path(r"C:\ProgramData\blacklist-inevitable\cache.db").is_ok());
    }
}
