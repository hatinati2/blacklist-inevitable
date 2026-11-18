mod commands;
mod engine;
mod profile_store;
mod profiles;

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::get_app_status,
            commands::get_profiles,
            commands::import_profiles,
            commands::delete_profile,
            commands::test_all_profile_endpoints,
            commands::install_sing_box_engine,
            commands::validate_profile_config
        ])
        .run(tauri::generate_context!())
        .expect("failed to run blacklist-inevitable");
}
