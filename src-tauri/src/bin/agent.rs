fn main() {
    let wfp_acl_probe = std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == "--wfp-acl-probe");

    let result = if wfp_acl_probe {
        blacklist_inevitable_lib::agent_service::run_wfp_acl_probe_service()
    } else {
        blacklist_inevitable_lib::agent_service::run_service()
    };

    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
