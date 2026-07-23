use agent_core::{ConnectionConfig, AgentCore};
use protocol::config::{AgentConfig, CONFIG_SIZE};
use std::fs;

// Include the build-script generated config slot.
mod embedded_config;

const CONFIG_MARKER: &[u8] = b"RRA_CONFIG_V1";

/// Read the embedded config from this executable's own binary.
///
/// Scans the running binary for RRA_CONFIG_V1 marker. If the marker
/// is followed by a valid config (length > 0), parse and return it.
fn read_embedded_config(exe: &std::path::Path) -> Option<AgentConfig> {
    let raw = fs::read(exe).ok()?;
    for chunk in raw.windows(CONFIG_SIZE) {
        if chunk.starts_with(CONFIG_MARKER) {
            // Only accept if it contains real config data
            if let Ok(cfg) = AgentConfig::from_bytes(chunk) {
                if cfg.agent_id != 0 || cfg.c2_address.len() > 2 {
                    return Some(cfg);
                }
            }
        }
    }
    None
}

/// Helper: build an AgentCore from an AgentConfig.
fn agent_from_embedded_config(ac: &AgentConfig) -> AgentCore {
    let conn_cfg = ConnectionConfig {
        server_addr: ac.c2_address.clone(),
        heartbeat_interval: ac.heartbeat_interval,
        reconnect_base_delay: 1,
        reconnect_max_delay: 300,
        reconnect_multiplier: 2.0,
    };
    AgentCore::with_config(ac.agent_id, conn_cfg)
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let agent = if let Ok(exe) = std::env::current_exe() {
        if let Some(cfg) = read_embedded_config(&exe) {
            log::info!(
                "Embedded config: C2={}, agent_id={}",
                cfg.c2_address,
                cfg.agent_id
            );
            agent_from_embedded_config(&cfg)
        } else {
            // Fallback: use CLI arg for agent_id, default C2 address
            let args: Vec<String> = std::env::args().collect();
            let agent_id = args.get(1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(1);
            log::info!("No embedded config — using defaults (agent_id={})", agent_id);
            AgentCore::new(agent_id)
        }
    } else {
        let args: Vec<String> = std::env::args().collect();
        let agent_id = args.get(1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(1);
        log::info!("No embedded config — using defaults (agent_id={})", agent_id);
        AgentCore::new(agent_id)
    };

    log::info!("Starting Rust Remote Admin agent (ID={})", agent.id);
    log::info!("Platform: {}", std::env::consts::OS);
    log::info!("Arch: {}", std::env::consts::ARCH);

    if let Err(e) = agent.run().await {
        log::error!("Agent error: {e}");
        std::process::exit(1);
    }
}
