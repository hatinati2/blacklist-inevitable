fn main() {
    let attributes = tauri_build::Attributes::new();

    #[cfg(windows)]
    let attributes = {
        add_windows_test_manifest();
        attributes.windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest())
    };

    tauri_build::try_build(attributes).expect("failed to run tauri-build");
}

#[cfg(windows)]
fn add_windows_test_manifest() {
    let manifest = std::path::PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"),
    )
    .join("windows-app-manifest.xml");

    println!("cargo:rerun-if-changed={}", manifest.display());

    // Cargo's rustc-link-arg applies to all binary targets, including
    // #[test] executables. Tauri's default resource compilation only embeds
    // the manifest into the desktop binary, which makes Windows test binaries
    // fail to start with STATUS_ENTRYPOINT_NOT_FOUND.
    println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
    println!("cargo:rustc-link-arg=/WX");
}
