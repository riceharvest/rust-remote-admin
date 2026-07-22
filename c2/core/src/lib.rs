use protocol::messages::Command;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

pub struct Agent {
    pub id: u32,
    pub ip: String,
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
    // Tracks all connected agents with their IDs, IPs, and individual command queues
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
        clients.insert(id, (Agent { id, ip }, CommandQueue::new()));
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
}
