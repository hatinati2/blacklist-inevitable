use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::profiles::{ParsedProfile, ProfileSummary};

const SERVICE_NAME: &str = "blacklist-inevitable";

#[derive(Debug, Serialize, Deserialize)]
struct ProfileFile {
    schema_version: u32,
    profiles: Vec<ProfileSummary>,
}

impl Default for ProfileFile {
    fn default() -> Self {
        Self {
            schema_version: 1,
            profiles: Vec::new(),
        }
    }
}

fn profile_file_path(app: &AppHandle) -> Result<PathBuf, String> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|_| "Could not resolve the application data directory.".to_string())?;
    fs::create_dir_all(&directory)
        .map_err(|_| "Could not create the application data directory.".to_string())?;
    Ok(directory.join("profiles.json"))
}

fn read_file(path: &Path) -> Result<ProfileFile, String> {
    if !path.exists() {
        return Ok(ProfileFile::default());
    }

    let content = fs::read_to_string(path)
        .map_err(|_| "Could not read the local profile index.".to_string())?;
    let file: ProfileFile = serde_json::from_str(&content)
        .map_err(|_| "The local profile index is invalid or corrupted.".to_string())?;

    if file.schema_version != 1 {
        return Err("This profile index version is not supported.".to_string());
    }

    Ok(file)
}

fn write_file(path: &Path, file: &ProfileFile) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(file)
        .map_err(|_| "Could not encode the profile index.".to_string())?;
    let temporary_path = path.with_extension("json.tmp");

    fs::write(&temporary_path, json)
        .map_err(|_| "Could not write the temporary profile index.".to_string())?;
    fs::rename(&temporary_path, path)
        .map_err(|_| "Could not commit the profile index.".to_string())?;

    Ok(())
}

#[cfg(windows)]
fn store_credentials(profile_id: &str, credentials: &std::collections::BTreeMap<String, String>) -> Result<(), String> {
    let entry = keyring::Entry::new(SERVICE_NAME, profile_id)
        .map_err(|_| "Windows Credential Manager is not available.".to_string())?;
    let serialized = serde_json::to_string(credentials)
        .map_err(|_| "Could not encode profile credentials.".to_string())?;
    entry
        .set_password(&serialized)
        .map_err(|_| "Windows Credential Manager could not store this profile's credentials.".to_string())
}

#[cfg(not(windows))]
fn store_credentials(
    _profile_id: &str,
    _credentials: &std::collections::BTreeMap<String, String>,
) -> Result<(), String> {
    Err("Secure profile storage is currently supported on Windows only.".to_string())
}

#[cfg(windows)]
fn delete_credentials(profile_id: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(SERVICE_NAME, profile_id)
        .map_err(|_| "Windows Credential Manager entry could not be opened for deletion.".to_string())?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err("Windows Credential Manager could not delete this profile's credentials.".to_string()),
    }
}

#[cfg(not(windows))]
fn delete_credentials(_profile_id: &str) -> Result<(), String> {
    Ok(())
}

fn cleanup_added_credentials(profiles: &[ProfileSummary]) -> Result<(), String> {
    let mut failed = 0usize;
    for profile in profiles {
        if delete_credentials(&profile.id).is_err() {
            failed += 1;
        }
    }

    if failed == 0 {
        Ok(())
    } else {
        Err(format!(
            "Secure credential cleanup failed for {failed} profile(s); orphaned credentials may remain in the OS credential store."
        ))
    }
}

pub fn list_profiles(app: &AppHandle) -> Result<Vec<ProfileSummary>, String> {
    let path = profile_file_path(app)?;
    Ok(read_file(&path)?.profiles)
}

pub fn add_profiles(app: &AppHandle, incoming: Vec<ParsedProfile>) -> Result<Vec<ProfileSummary>, String> {
    let path = profile_file_path(app)?;
    let mut file = read_file(&path)?;
    let mut added: Vec<ProfileSummary> = Vec::new();

    for parsed in incoming {
        let profile_id = parsed.profile.id.clone();
        if let Err(error) = store_credentials(&profile_id, &parsed.credentials) {
            return match cleanup_added_credentials(&added) {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(format!("{error} {cleanup_error}")),
            };
        }
        file.profiles.push(parsed.profile.clone());
        added.push(parsed.profile);
    }

    if let Err(error) = write_file(&path, &file) {
        return match cleanup_added_credentials(&added) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(format!("{error} {cleanup_error}")),
        };
    }

    Ok(added)
}

pub fn remove_profile(app: &AppHandle, profile_id: &str) -> Result<(), String> {
    let path = profile_file_path(app)?;
    let mut file = read_file(&path)?;
    let initial_length = file.profiles.len();
    file.profiles.retain(|profile| profile.id != profile_id);

    if file.profiles.len() == initial_length {
        return Err("Profile not found.".to_string());
    }

    write_file(&path, &file)?;
    delete_credentials(profile_id).map_err(|error| {
        format!(
            "The profile was removed from the local list, but its saved credential could not be deleted: {error}"
        )
    })?;
    Ok(())
}

#[cfg(windows)]
pub fn get_credentials(profile_id: &str) -> Result<BTreeMap<String, String>, String> {
    let entry = keyring::Entry::new(SERVICE_NAME, profile_id)
        .map_err(|_| "Windows Credential Manager is not available.".to_string())?;
    let serialized = entry
        .get_password()
        .map_err(|_| "Credentials for this profile are missing from Windows Credential Manager.".to_string())?;
    serde_json::from_str(&serialized)
        .map_err(|_| "Stored profile credentials are corrupted.".to_string())
}

#[cfg(not(windows))]
pub fn get_credentials(_profile_id: &str) -> Result<BTreeMap<String, String>, String> {
    Err("Secure profile storage is currently supported on Windows only.".to_string())
}
