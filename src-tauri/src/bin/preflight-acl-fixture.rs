#[path = "../engine/preflight_acl.rs"]
mod preflight_acl;

use std::path::PathBuf;

fn main() -> Result<(), String> {
    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| "Expected one temporary root directory argument.".to_string())?;
    let run_dir = root.join("run");
    let config = run_dir.join("config.json");

    preflight_acl::create_private_directory(&root)?;
    preflight_acl::create_private_directory(&run_dir)?;
    preflight_acl::create_private_file(&config, b"ACL-ACCEPTANCE-SENTINEL")?;

    println!("PRELIGHT_ACL_ROOT={}", root.display());
    println!("PREFLIGHT_ACL_CONFIG={}", config.display());
    Ok(())
}
