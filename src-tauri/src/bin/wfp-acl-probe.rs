fn main() {
    if let Err(error) = blacklist_inevitable_lib::agent_service::run_wfp_acl_probe_service() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
