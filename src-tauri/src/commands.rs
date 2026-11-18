use serde::Serialize;

use crate::engine::{EngineDescriptor, ENGINE_TARGETS};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStatus {
    app_name: &'static str,
    version: &'static str,
    development_stage: &'static str,
    connection_implemented: bool,
    preflight_testing_implemented: bool,
    engines: Vec<EngineDescriptor>,
}

#[tauri::command]
pub fn get_app_status() -> AppStatus {
    AppStatus {
        app_name: "blacklist-inevitable",
        version: env!("CARGO_PKG_VERSION"),
        development_stage: "early foundation",
        connection_implemented: false,
        preflight_testing_implemented: false,
        engines: ENGINE_TARGETS.to_vec(),
    }
}
