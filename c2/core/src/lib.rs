use crypto::tls::{build_mtls_acceptor, load_certs, load_private_key, TlsError};
use protocol::messages::Command;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
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

/// Maximum time since last heartbeat before an agent is considered stale.
const DEFAULT_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);

/// Maximum time since last heartbeat before an agent is considered disconnected.
const DEFAULT_DISCONNECT_TIMEOUT: Duration = Duration::from_secs(300);

pub struct Agent {
    pub id: u32,
    pub ip: String,
    pub last_heartbeat: Instant,
    pub state: ConnectionState,
}

impl Agent {
    fn new(id: u32, ip: String) -> Self {
        Self {
            id,
            ip,
            last_heartbeat: Instant::now(),
            state: ConnectionState::Connected,
        }
    }
}

/// A queue of commands waiting to be sent to a specific agent.
#[derive(Default)]
pub struct CommandQueue {
    pending: VecDeque<Command>,
}

impl CommandQueue {
    fn new() -> Self {
        Self { pending: VecDeque::new() }
    }
    fn push(&mut self, cmd: Command) {
        self.pending.push_back(cmd);
    }

    fn pop(&mut self) -> Option<Command> {
        self.pending.pop_front()
    }
}

/// The C2 server core: holds registered agents, command queues, and TLS config.
pub struct C2Core {
    pub clients: Arc<Mutex<HashMap<u32, (Agent, CommandQueue)>>>,
    pub tls: Option<ListenerTls>,
}

impl Default for C2Core {
    fn default() -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            tls: None,
        }
    }
}

impl C2Core {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the listener for plain TCP (no TLS).
    pub fn configure_plain(&mut self) {
        self.tls = Some(ListenerTls::Disabled);
    }

    /// Configure the listener for TLS (server-auth only).
    pub fn configure_tls(
        &mut self,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), TlsError> {
        let certs = load_certs(cert_path)?;
        let key = load_private_key(key_path)?;
        let acceptor = crypto::tls::build_tls_acceptor(certs, key)?;
        self.tls = Some(ListenerTls::ServerOnly(acceptor));
        Ok(())
    }

    /// Configure the listener for mutual TLS (client cert required).
    pub fn configure_mtls(
        &mut self,
        cert_path: &str,
        key_path: &str,
        ca_cert_path: &str,
    ) -> Result<(), TlsError> {
        let certs = load_certs(cert_path)?;
        let key = load_private_key(key_path)?;
        let ca_certs = load_certs(ca_cert_path)?;
        let acceptor = build_mtls_acceptor(certs, key, ca_certs.into_iter().next()
            .ok_or_else(|| TlsError::CertParse("CA certificate file is empty".into()))?)?;
        self.tls = Some(ListenerTls::Mutual(acceptor));
        Ok(())
    }

    /// Bind and listen on the given address, accepting connections.
    pub async fn run_listener(&self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(addr).await?;
        log::info!("C2 listener bound on {addr}");

        loop {
            let (socket, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    log::error!("Accept failed: {e}");
                    continue;
                }
            };
            log::info!("New connection from {peer}");
            match &self.tls {
                Some(ListenerTls::Disabled) | None => {
                    log::info!("New (cleartext) connection from: {peer}");
                    tokio::spawn(async move {
                        // Connection handling logic goes here.
                        let _ = socket;
                    });
                }
                Some(ListenerTls::ServerOnly(acceptor)) => {
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(socket).await {
                            Ok(_tls_stream) => {
                                log::info!("TLS handshake completed with {peer}");
                                // Handle the TLS-wrapped connection.
                            }
                            Err(e) => {
                                log::error!("TLS handshake failed with {peer}: {e}");
                            }
                        }
                    });
                }
                Some(ListenerTls::Mutual(acceptor)) => {
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(socket).await {
                            Ok(_tls_stream) => {
                                log::info!("mTLS handshake completed with {peer}");
                                // Handle the mTLS-wrapped connection.
                            }
                            Err(e) => {
                                log::error!("mTLS handshake failed with {peer}: {e}");
                            }
                        }
                    });
                }
            }
        }
    }

    /// Registers a new agent into the pool with its own command queue
    pub fn register_client(&self, id: u32, ip: String) {
        let mut clients = self.clients.lock().expect("C2Core lock poisoned");
        log::info!("Registered client {id} from {ip}");
        clients.insert(id, (Agent::new(id, ip), CommandQueue::new()));
    }

    /// Record a heartbeat from an agent, updating its last-seen timestamp.
    pub fn record_heartbeat(&self, id: u32) {
        let mut clients = self.clients.lock().expect("C2Core lock poisoned");
        if let Some((agent, _)) = clients.get_mut(&id) {
            agent.last_heartbeat = Instant::now();
            log::info!("Heartbeat received from agent {id}");
        } else {
            log::warn!("Heartbeat from unknown agent {id}");
        }
    }

    /// Returns the number of agents in each health state.
    ///
    /// Returns `(healthy, stale, disconnected)` based on heartbeat timeouts.
    pub fn health_summary(&self) -> (usize, usize, usize) {
        let clients = self.clients.lock().expect("C2Core lock poisoned");
        let now = Instant::now();
        let mut healthy = 0usize;
        let mut stale = 0usize;
        let mut disconnected = 0usize;

        for (_, (agent, _)) in clients.iter() {
            let elapsed = now.duration_since(agent.last_heartbeat);
            if elapsed > DEFAULT_DISCONNECT_TIMEOUT {
                disconnected += 1;
            } else if elapsed > DEFAULT_HEARTBEAT_TIMEOUT {
                stale += 1;
            } else {
                healthy += 1;
            }
        }

        (healthy, stale, disconnected)
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
    fn record_heartbeat_updates_timestamp() {
        let core = C2Core::new();
        core.register_client(1, "10.0.0.1".to_string());
        core.record_heartbeat(1);

        let clients = core.clients.lock().expect("C2Core lock poisoned");
        let (agent, _) = clients.get(&1).expect("client should exist");
        // The timestamp should be recent (within the last second)
        assert!(
            std::time::Instant::now().duration_since(agent.last_heartbeat).as_secs() < 2
        );
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
