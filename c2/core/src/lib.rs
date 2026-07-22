use protocol::messages::Command;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

/// Maximum time since last heartbeat before an agent is considered stale.
const DEFAULT_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(90);

/// Maximum time since last heartbeat before an agent is considered disconnected.
const DEFAULT_DISCONNECT_TIMEOUT: Duration = Duration::from_secs(300);

pub struct Agent {
    pub id: u32,
    pub ip: String,
    pub last_heartbeat: Instant,
}

impl Agent {
    fn new(id: u32, ip: String) -> Self {
        Self {
            id,
            ip,
            last_heartbeat: Instant::now(),
        }
    }
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
}

impl C2Core {
    pub fn new() -> Self {
        Self::default()
    }

    /// Listens for incoming agent connections on the specified port.
    pub async fn run_listener(&self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        log::info!("C2 Core listening on port {port}");

        loop {
            let (_socket, addr) = listener.accept().await?;
            log::info!("New connection from: {addr}");

            // In a real implementation, we would perform the mTLS handshake here
            // and then spawn a task to handle the communication with this specific agent.
            tokio::spawn(async move {
                // Connection handling logic goes here
            });
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
}

#[cfg(test)]
mod tests {
    use super::C2Core;

    #[test]
    fn register_client_stores_the_agent_address() {
        let core = C2Core::new();
        core.register_client(7, "127.0.0.1".to_string());

        let clients = core.clients.lock().expect("C2Core lock poisoned");
        let (agent, queue) = clients.get(&7).expect("client should be registered");
        assert_eq!(agent.id, 7);
        assert_eq!(agent.ip, "127.0.0.1");
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
    fn remove_client_cleans_pool() {
        let core = C2Core::new();
        core.register_client(5, "10.0.0.5".to_string());
        core.remove_client(5);
        let clients = core.clients.lock().expect("C2Core lock poisoned");
        assert!(clients.get(&5).is_none());
    }
}
