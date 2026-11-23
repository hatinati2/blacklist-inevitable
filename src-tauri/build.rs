fn main() {
    // The dedicated Agent binary shares the package's library but does not need
    // Tauri's desktop bundle/resource validation. In particular, the desktop
    // bundle contains the Agent executable, so running tauri_build while
    // producing that executable would create a circular build dependency.
    println!("cargo:rerun-if-env-changed=BLACKLIST_AGENT_ONLY_BUILD");
    if std::env::var_os("BLACKLIST_AGENT_ONLY_BUILD").is_some() {
        return;
    }

    tauri_build::build()
}
