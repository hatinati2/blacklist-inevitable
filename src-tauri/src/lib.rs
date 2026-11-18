mod commands;
mod engine;

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![commands::get_app_status])
        .run(tauri::generate_context!())
        .expect("failed to run blacklist-inevitable");
}
