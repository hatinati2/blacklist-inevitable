#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if std::env::args_os()
        .skip(1)
        .any(|argument| argument == "--agent-status-smoke-test")
    {
        let result = run_agent_status_smoke_test();
        if let Some(path) = std::env::var_os("BLACKLIST_AGENT_STATUS_SMOKE_RESULT") {
            let message = match &result {
                Ok(detail) => format!("success: {detail}\n"),
                Err(error) => format!("failure: {error}\n"),
            };
            let _ = std::fs::write(path, message);
        }
        std::process::exit(if result.is_ok() { 0 } else { 1 });
    }

    blacklist_inevitable_lib::run();
}

fn run_agent_status_smoke_test() -> Result<String, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "The Agent smoke-test runtime could not be started.".to_string())?;
    runtime
        .block_on(blacklist_inevitable_lib::agent_client::query_status())
        .and_then(|response| {
            if response.status == "ok" {
                Ok(response.detail)
            } else {
                Err(response.detail)
            }
        })
}
