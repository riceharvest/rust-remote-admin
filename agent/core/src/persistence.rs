use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;

/// Agent state that persists across restarts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentState {
    /// Agent ID.
    pub id: u32,
    /// C2 server address.
    pub server_addr: String,
    /// Heartbeat interval in seconds.
    pub heartbeat_interval: u64,
    /// Connection mode (Plain, Tls, Mtls).
    pub connection_mode: String,
    /// TLS server name (if applicable).
    pub server_name: Option<String>,
    /// CA cert path (if applicable).
    pub ca_cert_path: Option<String>,
    /// Client cert path (if applicable).
    pub client_cert_path: Option<String>,
    /// Client key path (if applicable).
    pub client_key_path: Option<String>,
    /// Last known connected time (Unix timestamp).
    pub last_connected: Option<i64>,
    /// Number of successful connections.
    pub connection_count: u64,
    /// Number of failed connection attempts.
    pub failed_attempts: u64,
}

/// C2 server state that persists across restarts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct C2State {
    /// Connected agent IDs.
    pub connected_agents: Vec<u32>,
    /// Serialized command queues (as JSON strings) for each agent.
    #[serde(default)]
    pub command_queues_json: std::collections::HashMap<u32, Vec<String>>,
    /// Server start time (Unix timestamp).
    pub started_at: i64,
    /// Total commands sent.
    pub total_commands_sent: u64,
}

/// State manager for persisting agent and C2 state.
pub struct StateManager {
    state_dir: PathBuf,
}

impl StateManager {
    /// Create a new state manager using the default config directory.
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let state_dir = Self::default_state_dir()?;
        fs::create_dir_all(&state_dir).await?;
        Ok(Self { state_dir })
    }

    /// Create a state manager with a custom directory.
    pub async fn with_dir(state_dir: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        fs::create_dir_all(&state_dir).await?;
        Ok(Self { state_dir })
    }

    /// Get the default state directory (~/.config/rust-remote-admin/state).
    fn default_state_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let config_dir = if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            PathBuf::from(xdg)
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".config")
        } else {
            PathBuf::from(".config")
        };
        Ok(config_dir.join("rust-remote-admin").join("state"))
    }

    /// Save agent state to disk.
    pub async fn save_agent_state(&self, state: &AgentState) -> Result<(), Box<dyn std::error::Error>> {
        let path = self.state_dir.join(format!("agent_{}.json", state.id));
        let json = serde_json::to_string_pretty(state)?;
        fs::write(&path, json).await?;
        Ok(())
    }

    /// Load agent state from disk.
    pub async fn load_agent_state(&self, agent_id: u32) -> Result<Option<AgentState>, Box<dyn std::error::Error>> {
        let path = self.state_dir.join(format!("agent_{}.json", agent_id));
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&path).await?;
        let state: AgentState = serde_json::from_str(&content)?;
        Ok(Some(state))
    }

    /// Delete agent state from disk.
    pub async fn delete_agent_state(&self, agent_id: u32) -> Result<(), Box<dyn std::error::Error>> {
        let path = self.state_dir.join(format!("agent_{}.json", agent_id));
        if path.exists() {
            fs::remove_file(&path).await?;
        }
        Ok(())
    }

    /// Save C2 state to disk.
    pub async fn save_c2_state(&self, state: &C2State) -> Result<(), Box<dyn std::error::Error>> {
        let path = self.state_dir.join("c2_state.json");
        let json = serde_json::to_string_pretty(state)?;
        fs::write(&path, json).await?;
        Ok(())
    }

    /// Load C2 state from disk.
    pub async fn load_c2_state(&self) -> Result<Option<C2State>, Box<dyn std::error::Error>> {
        let path = self.state_dir.join("c2_state.json");
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&path).await?;
        let state: C2State = serde_json::from_str(&content)?;
        Ok(Some(state))
    }

    /// List all agent IDs that have persisted state.
    pub async fn list_agent_ids(&self) -> Result<Vec<u32>, Box<dyn std::error::Error>> {
        let mut ids = Vec::new();
        let mut entries = fs::read_dir(&self.state_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(id_str) = name.strip_prefix("agent_").and_then(|s| s.strip_suffix(".json")) {
                if let Ok(id) = id_str.parse::<u32>() {
                    ids.push(id);
                }
            }
        }
        ids.sort();
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn state_manager_save_load_agent() {
        let dir = tempdir().unwrap();
        let manager = StateManager::with_dir(dir.path().to_path_buf()).await.unwrap();

        let state = AgentState {
            id: 42,
            server_addr: "127.0.0.1:9000".to_string(),
            heartbeat_interval: 30,
            connection_mode: "Plain".to_string(),
            server_name: None,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            last_connected: Some(1234567890),
            connection_count: 5,
            failed_attempts: 1,
        };

        manager.save_agent_state(&state).await.unwrap();
        let loaded = manager.load_agent_state(42).await.unwrap().unwrap();

        assert_eq!(loaded.id, 42);
        assert_eq!(loaded.server_addr, "127.0.0.1:9000");
        assert_eq!(loaded.connection_count, 5);
    }

    #[tokio::test]
    async fn state_manager_list_agents() {
        let dir = tempdir().unwrap();
        let manager = StateManager::with_dir(dir.path().to_path_buf()).await.unwrap();

        for id in [1, 5, 10] {
            let state = AgentState {
                id,
                ..Default::default()
            };
            manager.save_agent_state(&state).await.unwrap();
        }

        let ids = manager.list_agent_ids().await.unwrap();
        assert_eq!(ids, vec![1, 5, 10]);
    }

    #[tokio::test]
    async fn state_manager_c2_state() {
        let dir = tempdir().unwrap();
        let manager = StateManager::with_dir(dir.path().to_path_buf()).await.unwrap();

        let state = C2State {
            connected_agents: vec![1, 2, 3],
            started_at: 1234567890,
            total_commands_sent: 100,
            ..Default::default()
        };

        manager.save_c2_state(&state).await.unwrap();
        let loaded = manager.load_c2_state().await.unwrap().unwrap();

        assert_eq!(loaded.connected_agents, vec![1, 2, 3]);
        assert_eq!(loaded.total_commands_sent, 100);
    }
}