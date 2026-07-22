use tokio::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use protocol::messages::Command;

pub struct Agent {
    pub id: u32,
    pub ip: String,
}

/// A queue of commands waiting to be sent to a specific agent.
pub struct CommandQueue {
    pub pending: Vec<Command>,
}

impl CommandQueue {
    pub fn new() -> Self {
        Self { pending: Vec::new() }
    }

    pub fn push(&mut self, cmd: Command) {
        self.pending.push(cmd);
    }

    pub fn pop(&mut self) -> Option<Command> {
        if self.pending.is_empty() {
            None
        } else {
            Some(self.pending.remove(0))
        }
    }
}

pub struct C2Core {
    // Tracks all connected agents with their IDs, IPs, and individual command queues
    pub clients: Arc<Mutex<HashMap<u32, (Agent, CommandQueue)>>>,
}

impl C2Core {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Listens for incoming agent connections on the specified port.
    pub async fn run_listener(&self, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        println!("C2 Core listening on port {}", port);

        loop {
            let (socket, addr) = listener.accept().await?;
            println!("New connection from: {}", addr);
            
            // In a real implementation, we would perform the mTLS handshake here
            // and then spawn a task to handle the communication with this specific agent.
            tokio::spawn(async move {
                // Connection handling logic goes here
            });
        }
    }

    /// Registers a new agent into the pool with its own command queue
    pub fn register_client(&self, id: u32, ip: String) {
        let mut clients = self.clients.lock().unwrap();
        clients.insert(id, (Agent { id, ip }, CommandQueue::new()));
        println!("Registered client {} from {}", id, ip);
    }

    /// Queues a command for a specific agent
    pub fn queue_command(&self, id: u32, cmd: Command) {
        let mut clients = self.clients.lock().unwrap();
        if let Some((_, queue)) = clients.get_mut(&id) {
            queue.push(cmd);
        }
    }

    /// Processes all pending commands for a specific agent
    pub fn dispatch_commands(&self, id: u32) {
        let mut clients = self.clients.lock().unwrap();
        if let Some((_, queue)) = clients.get_mut(&id) {
            while let Some(cmd) = queue.pop() {
                println!("Dispatching {:?} to agent {}", cmd, id);
            }
        }
    }
}
