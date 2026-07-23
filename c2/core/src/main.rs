use c2_core::C2Core;
use std::env;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let args: Vec<String> = env::args().collect();
    let addr = args.get(1).cloned().unwrap_or_else(|| "0.0.0.0:9000".to_string());

    let core = C2Core::new();
    log::info!("Starting Rust Remote Admin C2 server on {}", addr);
    log::info!("Platform: {}", std::env::consts::OS);

    if let Err(e) = core.run_listener(&addr).await {
        log::error!("C2 server error: {e}");
        std::process::exit(1);
    }
}
