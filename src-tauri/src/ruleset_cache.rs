//! Pinned, bounded cache for the two Iran SRS rule-set seed assets.
//!
//! This module is deliberately not called from service startup, status IPC, or
//! the desktop UI. A future, separately reviewed Connect transaction may call
//! ensure_current() before generating a Rule-mode engine configuration.
//!
//! The cache root is created only beneath the installer-provisioned,
//! service-protected ProgramData\\BlacklistInevitable\\Agent directory.
//! This module never changes ACLs, system networking, DNS, routes, WFP, or
//! process state.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use futures_util::StreamExt;
use sha2::{Digest, Sha256};

const SOURCE_REVISION: &str = "1597f121656f3e63f2624a471401002941d888c4";
const MAX_RULE_SET_BYTES: usize = 512 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const RULE_SET_DIRECTORY: &str = "RuleSets";

#[derive(Debug, Clone, Copy)]
struct RuleSetAsset {
    stem: &'static str,
    url: &'static str,
    sha256: &'static str,
    size: usize,
}

const GEOIP_IR: RuleSetAsset = RuleSetAsset {
    stem: "geoip-ir",
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/1597f121656f3e63f2624a471401002941d888c4/geoip-ir.srs",
    sha256: "2c32f50294216355ba41a2defb6c8d9896903ef07837668f5002f53f2cd8912c",
    size: 14_288,
};

const GEOSITE_IR: RuleSetAsset = RuleSetAsset {
    stem: "geosite-ir",
    url: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/1597f121656f3e63f2624a471401002941d888c4/geosite-ir.srs",
    sha256: "59ad4f15d78b27017315da1de79ebb3250ad1ba7a870b2424319285f7864cbe0",
    size: 310_185,
};

static CACHE_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

/// Verified local seed assets for sing-box's remote rule-set initial_path fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSetCacheFiles {
    pub geoip_path: PathBuf,
    pub geosite_path: PathBuf,
    pub source_revision: &'static str,
}

fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        return metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }

    #[cfg(not(windows))]
    {
        false
    }
}

fn require_existing_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| format!("The installer-provisioned Agent {label} directory is unavailable."))?;
    if !metadata.file_type().is_dir() || is_reparse_point(&metadata) {
        return Err(format!("The Agent {label} directory is not a safe ordinary directory."));
    }
    Ok(())
}

/// Resolve an existing protected Agent root and create only its inheriting cache child.
/// The installer owns and verifies the parent DACL; this function never changes ACLs.
fn cache_directory(program_data: &Path) -> Result<PathBuf, String> {
    require_existing_directory(program_data, "ProgramData")?;
    let product_root = program_data.join("BlacklistInevitable");
    let agent_root = product_root.join("Agent");
    require_existing_directory(&product_root, "product data")?;
    require_existing_directory(&agent_root, "service data")?;

    let cache_root = agent_root.join(RULE_SET_DIRECTORY);
    match fs::create_dir(&cache_root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err("The protected Agent rule-set cache directory could not be created.".to_string()),
    }
    require_existing_directory(&cache_root, "rule-set cache")?;
    Ok(cache_root)
}

fn cache_file_path(directory: &Path, asset: &RuleSetAsset) -> PathBuf {
    directory.join(format!(
        "{}-{}-{}.srs",
        asset.stem,
        SOURCE_REVISION,
        &asset.sha256[..16]
    ))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_asset_bytes(asset: &RuleSetAsset, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() != asset.size || bytes.len() > MAX_RULE_SET_BYTES {
        return Err(format!("The pinned {} rule-set has an unexpected size.", asset.stem));
    }
    if !bytes.starts_with(b"SRS\x01") || bytes.len() <= 4 {
        return Err(format!("The pinned {} rule-set is not a binary SRS asset.", asset.stem));
    }
    if sha256_hex(bytes) != asset.sha256 {
        return Err(format!("The pinned {} rule-set failed SHA-256 verification.", asset.stem));
    }
    Ok(())
}

fn verify_cached_file(path: &Path, asset: &RuleSetAsset) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| format!("The cached {} rule-set cannot be inspected.", asset.stem))?;
    if !metadata.file_type().is_file() || is_reparse_point(&metadata) || metadata.len() != asset.size as u64 {
        return Err(format!("The cached {} rule-set file is unsafe or has the wrong size.", asset.stem));
    }
    let bytes = fs::read(path)
        .map_err(|_| format!("The cached {} rule-set could not be read.", asset.stem))?;
    validate_asset_bytes(asset, &bytes)
}

fn write_verified_asset(
    directory: &Path,
    asset: &RuleSetAsset,
    bytes: &[u8],
) -> Result<PathBuf, String> {
    validate_asset_bytes(asset, bytes)?;
    let destination = cache_file_path(directory, asset);

    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            verify_cached_file(&destination, asset)?;
            return Ok(destination);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(format!("The cached {} rule-set path could not be inspected.", asset.stem)),
    }

    let temporary = directory.join(format!(".{}-{}.tmp", asset.stem, uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| format!("A temporary {} rule-set file could not be created.", asset.stem))?;
        file.write_all(bytes)
            .map_err(|_| format!("The temporary {} rule-set file could not be written.", asset.stem))?;
        file.sync_all()
            .map_err(|_| format!("The temporary {} rule-set file could not be flushed.", asset.stem))?;
        drop(file);

        fs::rename(&temporary, &destination)
            .map_err(|_| format!("The verified {} rule-set could not be committed atomically.", asset.stem))?;
        verify_cached_file(&destination, asset)?;
        Ok(destination.clone())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

async fn ensure_asset(
    client: &reqwest::Client,
    directory: &Path,
    asset: &RuleSetAsset,
) -> Result<PathBuf, String> {
    let destination = cache_file_path(directory, asset);
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            verify_cached_file(&destination, asset)?;
            return Ok(destination);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(format!("The cached {} rule-set path could not be inspected.", asset.stem)),
    }

    let response = client
        .get(asset.url)
        .send()
        .await
        .map_err(|_| format!("The pinned {} rule-set download failed.", asset.stem))?;

    if response.status() != reqwest::StatusCode::OK || response.url().as_str() != asset.url {
        return Err(format!("The pinned {} rule-set returned an unexpected HTTP response.", asset.stem));
    }
    if response.content_length().is_some_and(|length| length != asset.size as u64) {
        return Err(format!("The pinned {} rule-set advertised an unexpected content length.", asset.stem));
    }

    let mut stream = response.bytes_stream();
    let mut bytes = Vec::with_capacity(asset.size);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|_| format!("The pinned {} rule-set download was interrupted.", asset.stem))?;
        if bytes.len().saturating_add(chunk.len()) > MAX_RULE_SET_BYTES
            || bytes.len().saturating_add(chunk.len()) > asset.size
        {
            return Err(format!("The pinned {} rule-set exceeded its size limit.", asset.stem));
        }
        bytes.extend_from_slice(&chunk);
    }

    validate_asset_bytes(asset, &bytes)?;
    write_verified_asset(directory, asset, &bytes)
}

/// Download or reuse the two immutable, SHA-256-pinned seed assets.
///
/// This primitive is intentionally not invoked by startup, status IPC, or the
/// desktop UI. A future connection transaction must call it explicitly and must
/// treat any error as a hard block for Rule mode; it must never silently fall
/// back to a mutable URL, an empty ruleset, or Global mode.
#[allow(dead_code)]
pub(crate) async fn ensure_current() -> Result<RuleSetCacheFiles, String> {
    let lock = CACHE_LOCK.get_or_init(|| tokio::sync::Mutex::new(()));
    let _guard = lock.lock().await;

    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let directory = cache_directory(&program_data)?;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|_| "The bounded rule-set HTTP client could not be created.".to_string())?;

    // Fetch sequentially. A cache result is returned only when both assets pass
    // the pinned size, SRS-header, and SHA-256 checks.
    let geoip_path = ensure_asset(&client, &directory, &GEOIP_IR).await?;
    let geosite_path = ensure_asset(&client, &directory, &GEOSITE_IR).await?;

    Ok(RuleSetCacheFiles {
        geoip_path,
        geosite_path,
        source_revision: SOURCE_REVISION,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_asset(bytes: &[u8]) -> RuleSetAsset {
        RuleSetAsset {
            stem: "fixture",
            url: "https://raw.githubusercontent.com/example/fixture.srs",
            sha256: sha256_hex(bytes).leak(),
            size: bytes.len(),
        }
    }

    #[test]
    fn source_assets_are_immutable_https_pins_with_bounded_sizes() {
        for asset in [GEOIP_IR, GEOSITE_IR] {
            assert!(asset.url.starts_with("https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/"));
            assert!(asset.url.contains(SOURCE_REVISION));
            assert_eq!(asset.sha256.len(), 64);
            assert!(asset.sha256.chars().all(|ch| ch.is_ascii_hexdigit()));
            assert!(asset.size <= MAX_RULE_SET_BYTES);
        }
        assert_eq!(GEOIP_IR.size, 14_288);
        assert_eq!(GEOSITE_IR.size, 310_185);
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn validates_srs_header_exact_size_and_sha256() {
        let bytes = b"SRS\x01fixture-payload";
        let asset = fixture_asset(bytes);
        assert!(validate_asset_bytes(&asset, bytes).is_ok());

        let wrong_hash = RuleSetAsset { sha256: "0".repeat(64).leak(), ..asset };
        assert!(validate_asset_bytes(&wrong_hash, bytes).is_err());
        assert!(validate_asset_bytes(&asset, b"not-an-srs-file").is_err());
    }

    #[test]
    fn writes_once_atomically_and_rejects_a_tampered_cache_file() {
        let root = std::env::temp_dir().join(format!("blacklist-ruleset-cache-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).expect("create isolated cache directory");
        let bytes = b"SRS\x01fixture-payload";
        let asset = fixture_asset(bytes);

        let path = write_verified_asset(&root, &asset, bytes).expect("store verified SRS");
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(write_verified_asset(&root, &asset, bytes).unwrap(), path);

        fs::write(&path, b"SRS\x01tampered").expect("tamper isolated fixture");
        assert!(verify_cached_file(&path, &asset).is_err());
        assert!(write_verified_asset(&root, &asset, bytes).is_err());

        fs::remove_dir_all(root).expect("remove isolated cache directory");
    }

    #[test]
    fn cache_is_created_only_beneath_an_installer_provisioned_agent_root() {
        let root = std::env::temp_dir().join(format!("blacklist-ruleset-root-{}", uuid::Uuid::new_v4()));
        let agent_root = root.join("BlacklistInevitable").join("Agent");
        fs::create_dir_all(&agent_root).expect("create installer-style Agent root");

        let cache = cache_directory(&root).expect("create inheriting RuleSets directory");
        assert_eq!(cache, agent_root.join(RULE_SET_DIRECTORY));
        assert!(cache.is_dir());

        let missing = root.join("missing");
        assert!(cache_directory(&missing).is_err());

        fs::remove_dir_all(root).expect("remove isolated Agent root");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlinked_agent_root() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("blacklist-ruleset-symlink-{}", uuid::Uuid::new_v4()));
        let product_root = root.join("BlacklistInevitable");
        let real_agent = root.join("real-agent");
        fs::create_dir_all(&product_root).expect("create product root");
        fs::create_dir_all(&real_agent).expect("create real Agent directory");
        symlink(&real_agent, product_root.join("Agent")).expect("create Agent symlink");

        assert!(cache_directory(&root).is_err());
        fs::remove_file(product_root.join("Agent")).expect("remove Agent symlink");
        fs::remove_dir_all(root).expect("remove isolated symlink fixture");
    }
}
