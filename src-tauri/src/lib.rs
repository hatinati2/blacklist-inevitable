use tauri::Manager;

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
mod process_supervisor;
mod profile_store;
mod profiles;
mod real_delay_settings;

pub fn run() {
    let app = tauri::Builder::default()
        .manage(process_supervisor::ProcessSupervisor::for_app())
        .setup(|app| {
            let supervisor = app
                .state::<process_supervisor::ProcessSupervisor>()
                .inner()
                .clone();
            let instance_ready = match supervisor.attach_current_process_to_job() {
                Ok(()) => true,
                Err(error) => {
                    eprintln!("Windows process containment or desktop instance lease is unavailable: {error}");
                    supervisor.mark_cleanup_unhealthy();
                    false
                }
            };
            // Never run shared-cache recovery unless this process owns the
            // exclusive OS-backed instance lease. A second launch must not
            // delete another live instance's credential-bearing probe files.
            if instance_ready {
                if let Err(error) =
                    crate::engine::sing_box::recover_stale_preflight_data(app.handle(), &supervisor)
                {
                    eprintln!("Stale preflight recovery failed; engine startup remains blocked: {error}");
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_app_status,
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
