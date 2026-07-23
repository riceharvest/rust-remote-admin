use std::env;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: rust-remote-admin-relay <listen_addr> <upstream_addr>");
        eprintln!("Example: rust-remote-admin-relay 0.0.0.0:8080 127.0.0.1:9000");
        std::process::exit(1);
    }

    let listen = &args[1];
    let upstream = &args[2];

    log::info!("Starting relay: {} -> {}", listen, upstream);

    let relay = c2_relay::Relay::new(listen, upstream);
    if let Err(e) = relay.run().await {
        log::error!("Relay error: {e}");
        std::process::exit(1);
    }
}
