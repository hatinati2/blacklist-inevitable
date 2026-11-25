use tauri::Manager;

pub mod agent_client;
pub mod agent_protocol;
pub mod agent_service;
#[cfg(windows)]
pub mod agent_pipe;
pub mod connection_state;
pub mod destination_routing;
pub mod recovery_journal;
pub mod wfp_policy;
#[cfg(windows)]
pub mod wfp_engine;
pub mod split_tunnel;
mod commands;
mod engine;
mod local_proxy;
mod process_supervisor;
mod profile_store;
mod profiles;
mod real_delay_settings;

pub fn run() {
    let app = tauri::Builder::default()
        .manage(process_supervisor::ProcessSupervisor::for_app())
        .manage(local_proxy::LocalProxyRuntime::default())
        .setup(|app| {
            let supervisor = app
                .state::<process_supervisor::ProcessSupervisor>()
                .inner()
                .clone();
            if let Err(error) = supervisor.attach_current_process_to_job() {
                eprintln!("Windows process containment is unavailable for this app instance: {error}");
                supervisor.mark_cleanup_unhealthy();
            }
            if let Err(error) =
                crate::engine::sing_box::recover_stale_preflight_data(app.handle(), &supervisor)
            {
                eprintln!("Stale preflight recovery failed; engine startup remains blocked: {error}");
            }
            if let Err(error) = crate::local_proxy::recover_stale_configs(app.handle()) {
                eprintln!("Stale local proxy recovery failed; engine startup remains blocked: {error}");
                supervisor.mark_cleanup_unhealthy();
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_app_status,
            commands::get_agent_status,
            commands::get_local_proxy_status,
            commands::start_local_proxy,
            commands::stop_local_proxy,
            commands::submit_agent_connect_request,
            commands::get_profiles,
            commands::import_profiles,
            commands::delete_profile,
            commands::test_all_profile_endpoints,
            commands::get_real_delay_settings,
            commands::save_real_delay_settings,
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
            let local_proxy = app_handle
                .state::<local_proxy::LocalProxyRuntime>()
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
                    // Stop the long-lived local proxy before waiting for all
                    // supervised children and short-lived preflight workers.
                    if let Err(error) = local_proxy.stop(&supervisor).await {
                        eprintln!("Local proxy shutdown cleanup failed: {error}");
                    }
                    let _cleanup_healthy = supervisor.wait_for_idle().await;
                    app_handle.exit(code.unwrap_or(0));
                });
            }
        }
    });
}
