use crypto::tls::{build_mtls_acceptor, load_certs, load_private_key, TlsError};
use protocol::messages::Command;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Active TLS session state for an agent connection.
#[derive(Debug, Clone)]
pub enum ConnectionState {
    /// Agent is connected and healthy.
    Connected,
    /// Agent has missed N heartbeats.
    Stale,
    /// Agent has timed out or disconnected.
    Disconnected,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::Connected
    }
}

pub struct Agent {
    pub id: u32,
    pub ip: String,
    pub state: ConnectionState,
}

/// TLS configuration for the C2 listener.
#[derive(Clone)]
pub enum ListenerTls {
    /// No TLS — accept plain TCP.
    Disabled,
    /// Server-authentication only TLS.
    ServerOnly(TlsAcceptor),
    /// Mutual TLS — server and client both authenticate.
    Mutual(TlsAcceptor),
}

/// A queue of commands waiting to be sent to a specific agent.
#[derive(Default)]
pub struct CommandQueue {
    pub pending: VecDeque<Command>,
}

impl CommandQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, cmd: Command) {
        self.pending.push_back(cmd);
    }

    pub fn pop(&mut self) -> Option<Command> {
        self.pending.pop_front()
    }
}

#[derive(Default)]
pub struct C2Core {
    /// Tracks all connected agents with their IDs, IPs, and individual command queues
    pub clients: Arc<Mutex<HashMap<u32, (Agent, CommandQueue)>>>,
    /// Optional TLS acceptor for wrapped connections.
    pub tls: Option<ListenerTls>,
}

impl C2Core {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure mTLS on this core from PEM file paths.
    ///
    /// The CA cert is used to verify client certificates; the server cert/key
    /// are presented to clients during the handshake.
    pub fn configure_mtls(
        &mut self,
        server_cert_path: &str,
        server_key_path: &str,
        ca_cert_path: &str,
    ) -> Result<(), TlsError> {
        let server_certs = load_certs(server_cert_path)?;
        let server_key = load_private_key(server_key_path)?;
        let ca_cert = load_certs(ca_cert_path)?
            .into_iter()
            .next()
            .ok_or_else(|| TlsError::CertParse("CA certificate file is empty".into()))?;

        let acceptor = build_mtls_acceptor(server_certs, server_key, ca_cert)?;
        self.tls = Some(ListenerTls::Mutual(acceptor));
        log::info!("mTLS configured on C2 core");
        Ok(())
    }

    /// Configure server-only TLS (no client certificate required).
    pub fn configure_tls(
        &mut self,
        server_cert_path: &str,
        server_key_path: &str,
    ) -> Result<(), TlsError> {
        let server_certs = load_certs(server_cert_path)?;
        let server_key = load_private_key(server_key_path)?;

        let acceptor = crypto::tls::build_tls_acceptor(server_certs, server_key)?;
        self.tls = Some(ListenerTls::ServerOnly(acceptor));
        log::info!("TLS configured on C2 core (server-auth only)");
        Ok(())
    }

    /// Listens for incoming agent connections on the specified port.
    ///
    /// If TLS is configured, connections are wrapped before being accepted.
    pub async fn run_listener(&self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await?;
        let tls = self.tls.clone();
        log::info!("C2 Core listening on port {port}");

        loop {
            let (socket, addr) = listener.accept().await?;

            match &tls {
                Some(ListenerTls::Mutual(acceptor)) => {
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(socket).await {
                            Ok(_tls_stream) => {
                                log::info!("mTLS connection from {addr}");
                            }
                            Err(e) => {
                                log::error!("mTLS handshake failed from {addr}: {e}");
                            }
                        }
                    });
                }
                Some(ListenerTls::ServerOnly(acceptor)) => {
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(socket).await {
                            Ok(_tls_stream) => {
                                log::info!("TLS connection from {addr}");
                            }
                            Err(e) => {
                                log::error!("TLS handshake failed from {addr}: {e}");
                            }
                        }
                    });
                }
                Some(ListenerTls::Disabled) | None => {
                    log::info!("New (cleartext) connection from: {addr}");
                    tokio::spawn(async move {
                        // Connection handling logic goes here
                    });
                }
            }
        }
    }

    /// Registers a new agent into the pool with its own command queue
    pub fn register_client(&self, id: u32, ip: String) {
        let mut clients = self.clients.lock().expect("C2Core lock poisoned");
        log::info!("Registered client {id} from {ip}");
        clients.insert(
            id,
            (
                Agent {
                    id,
                    ip,
                    state: ConnectionState::Connected,
                },
                CommandQueue::new(),
            ),
        );
    }

    /// Mark an agent as stale (missed heartbeats).
    pub fn mark_stale(&self, id: u32) {
        if let Some((agent, _)) = self
            .clients
            .lock()
            .expect("C2Core lock poisoned")
            .get_mut(&id)
        {
            agent.state = ConnectionState::Stale;
            log::warn!("Agent {id} marked stale");
        }
    }

    /// Mark an agent as disconnected.
    pub fn mark_disconnected(&self, id: u32) {
        if let Some((agent, _)) = self
            .clients
            .lock()
            .expect("C2Core lock poisoned")
            .get_mut(&id)
        {
            agent.state = ConnectionState::Disconnected;
            log::warn!("Agent {id} disconnected");
        }
    }

    /// Remove a disconnected agent from the pool.
    pub fn remove_client(&self, id: u32) {
        let mut clients = self.clients.lock().expect("C2Core lock poisoned");
        if clients.remove(&id).is_some() {
            log::info!("Removed agent {id} from pool");
        }
    }

    /// Queues a command for a specific agent
    pub fn queue_command(&self, id: u32, cmd: Command) {
        let mut clients = self.clients.lock().expect("C2Core lock poisoned");
        if let Some((_, queue)) = clients.get_mut(&id) {
            queue.push(cmd);
        } else {
            log::warn!("queue_command: unknown agent {id}");
        }
    }

    /// Processes all pending commands for a specific agent
    pub fn dispatch_commands(&self, id: u32) {
        let mut clients = self.clients.lock().expect("C2Core lock poisoned");
        if let Some((_, queue)) = clients.get_mut(&id) {
            while let Some(cmd) = queue.pop() {
                log::info!("Dispatching {cmd:?} to agent {id}");
            }
        } else {
            log::warn!("dispatch_commands: unknown agent {id}");
        }
    }

    /// Returns the number of agents in each connection state.
    pub fn connection_summary(&self) -> (usize, usize, usize) {
        let clients = self.clients.lock().expect("C2Core lock poisoned");
        let connected = clients
            .values()
            .filter(|(a, _)| matches!(a.state, ConnectionState::Connected))
            .count();
        let stale = clients
            .values()
            .filter(|(a, _)| matches!(a.state, ConnectionState::Stale))
            .count();
        let disconnected = clients
            .values()
            .filter(|(a, _)| matches!(a.state, ConnectionState::Disconnected))
            .count();
        (connected, stale, disconnected)
    }
}

#[cfg(test)]
mod tests {
    use super::C2Core;
    use crate::ConnectionState;

    #[test]
    fn register_client_stores_the_agent_address() {
        let core = C2Core::new();
        core.register_client(7, "127.0.0.1".to_string());

        let clients = core.clients.lock().expect("C2Core lock poisoned");
        let (agent, queue) = clients.get(&7).expect("client should be registered");
        assert_eq!(agent.id, 7);
        assert_eq!(agent.ip, "127.0.0.1");
        assert!(matches!(agent.state, ConnectionState::Connected));
        assert!(queue.pending.is_empty());
    }

    #[test]
    fn mark_stale_updates_agent_state() {
        let core = C2Core::new();
        core.register_client(1, "10.0.0.1".to_string());
        core.mark_stale(1);
        let clients = core.clients.lock().expect("C2Core lock poisoned");
        assert!(matches!(
            clients.get(&1).unwrap().0.state,
            ConnectionState::Stale
        ));
    }

    #[test]
    fn remove_client_cleans_pool() {
        let core = C2Core::new();
        core.register_client(5, "10.0.0.5".to_string());
        core.remove_client(5);
        let clients = core.clients.lock().expect("C2Core lock poisoned");
        assert!(clients.get(&5).is_none());
    }

    #[test]
    fn connection_summary_counts_states() {
        let core = C2Core::new();
        core.register_client(1, "a".to_string());
        core.register_client(2, "b".to_string());
        core.register_client(3, "c".to_string());
        core.mark_stale(2);
        assert_eq!(core.connection_summary(), (2, 1, 0));
    }
}
