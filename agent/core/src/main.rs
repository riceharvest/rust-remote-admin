use agent_core::AgentCore;
use std::env;

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let args: Vec<String> = env::args().collect();
    let agent_id = args
        .get(1)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(1);

    let agent = AgentCore::new(agent_id);
    log::info!("Starting Rust Remote Admin agent (ID={})", agent_id);
    log::info!("Platform: {}", std::env::consts::OS);
    log::info!("Arch: {}", std::env::consts::ARCH);

    // Run the agent loop — connect, heartbeat, reconnect
    if let Err(e) = agent.run().await {
        log::error!("Agent error: {e}");
        std::process::exit(1);
    }
}
