use tauri::Manager;

mod commands;
mod engine;
mod process_supervisor;
mod profile_store;
mod profiles;

pub fn run() {
    let app = tauri::Builder::default()
        .manage(process_supervisor::ProcessSupervisor::default())
        .setup(|app| {
            let supervisor = app
                .state::<process_supervisor::ProcessSupervisor>()
                .inner()
                .clone();
            if let Err(error) = supervisor.attach_current_process_to_job() {
                eprintln!("Windows process containment is unavailable for this app instance: {error}");
                supervisor.mark_cleanup_unhealthy();
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_app_status,
            commands::get_profiles,
            commands::import_profiles,
            commands::delete_profile,
            commands::test_all_profile_endpoints,
            commands::install_sing_box_engine,
            commands::validate_profile_config,
            commands::test_all_profile_real_delays
        ])
        .build(tauri::generate_context!())
        .expect("failed to build blacklist-inevitable");

    app.run(|app_handle, event| {
        if let tauri::RunEvent::ExitRequested { api, code, .. } = event {
            let supervisor = app_handle
                .state::<process_supervisor::ProcessSupervisor>()
                .inner()
                .clone();

            // The second exit request is issued only after all supervised operations
            // have completed their cleanup.
            if supervisor.shutdown_complete() {
                return;
            }

            api.prevent_exit();
            if supervisor.request_shutdown() {
                let app_handle = app_handle.clone();
                tauri::async_runtime::spawn(async move {
                    // Real Delay workers receive cancellation, stop and reap their
                    // sing-box child, remove temporary data, then release their lease.
                    // Short config-check commands are bounded by their own timeout.
                    let _cleanup_healthy = supervisor.wait_for_idle().await;
                    app_handle.exit(code.unwrap_or(0));
                });
            }
        }
    });
}
