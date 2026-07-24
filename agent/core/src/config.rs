use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, interval};

/// Runtime configuration that can be loaded from file, env vars, and hot-reloaded.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeConfig {
    /// Agent-specific configuration.
    #[serde(default)]
    pub agent: AgentConfig,
    
    /// C2 server configuration.
    #[serde(default)]
    pub c2: C2Config,
    
    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,
    
    /// Security/hardening configuration.
    #[serde(default)]
    pub security: SecurityConfig,
}

/// Agent connection and behavior configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Agent ID (0 = auto-assign on connect).
    pub id: u32,
    
    /// C2 server address (host:port).
    pub server_addr: String,
    
    /// Heartbeat interval in seconds.
    #[serde(default = "default_heartbeat")]
    pub heartbeat_interval: u64,
    
    /// Reconnection base delay in seconds.
    #[serde(default = "default_reconnect_base")]
    pub reconnect_base_delay: u64,
    
    /// Maximum reconnection delay in seconds.
    #[serde(default = "default_reconnect_max")]
    pub reconnect_max_delay: u64,
    
    /// Reconnection delay multiplier.
    #[serde(default = "default_reconnect_mult")]
    pub reconnect_multiplier: f64,
    
    /// Connection mode: "plain", "tls", or "mtls".
    #[serde(default = "default_connection_mode")]
    pub connection_mode: String,
    
    /// TLS server name (for TLS/mTLS).
    pub server_name: Option<String>,
    
    /// CA certificate path (for TLS/mTLS).
    pub ca_cert_path: Option<String>,
    
    /// Client certificate path (for mTLS).
    pub client_cert_path: Option<String>,
    
    /// Client private key path (for mTLS).
    pub client_key_path: Option<String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            id: 0,
            server_addr: "127.0.0.1:9000".to_string(),
            heartbeat_interval: default_heartbeat(),
            reconnect_base_delay: default_reconnect_base(),
            reconnect_max_delay: default_reconnect_max(),
            reconnect_multiplier: default_reconnect_mult(),
            connection_mode: default_connection_mode(),
            server_name: None,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
        }
    }
}

/// C2 server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct C2Config {
    /// C2 server listen address.
    #[serde(default = "default_c2_listen")]
    pub listen_addr: String,
    
    /// TLS certificate path for C2 server.
    pub cert_path: Option<String>,
    
    /// TLS private key path for C2 server.
    pub key_path: Option<String>,
    
    /// Require client certificates (mTLS).
    #[serde(default)]
    pub require_client_cert: bool,
    
    /// CA certificate path for client verification.
    pub client_ca_path: Option<String>,
    
    /// Maximum number of concurrent agent connections.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

impl Default for C2Config {
    fn default() -> Self {
        Self {
            listen_addr: default_c2_listen(),
            cert_path: None,
            key_path: None,
            require_client_cert: false,
            client_ca_path: None,
            max_connections: default_max_connections(),
        }
    }
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level: "trace", "debug", "info", "warn", "error".
    #[serde(default = "default_log_level")]
    pub level: String,
    
    /// Log format: "json" or "text".
    #[serde(default = "default_log_format")]
    pub format: String,
    
    /// Log output: "stdout", "stderr", or a file path.
    #[serde(default = "default_log_output")]
    pub output: String,
    
    /// Enable structured audit logging.
    #[serde(default)]
    pub audit_enabled: bool,
    
    /// Audit log file path (if audit_enabled).
    pub audit_log_path: Option<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            output: default_log_output(),
            audit_enabled: false,
            audit_log_path: None,
        }
    }
}

/// Security/hardening configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable anti-debugging checks.
    #[serde(default = "default_true")]
    pub anti_debug: bool,
    
    /// Enable VM detection.
    #[serde(default = "default_true")]
    pub vm_detection: bool,
    
    /// Enable sandbox detection.
    #[serde(default = "default_true")]
    pub sandbox_detection: bool,
    
    /// Enable timing checks.
    #[serde(default)]
    pub timing_checks: bool,
    
    /// Timing check threshold in milliseconds.
    #[serde(default = "default_timing_threshold")]
    pub timing_threshold_ms: u64,
    
    /// String obfuscation key.
    pub obfuscation_key: Option<u8>,
    
    /// Allowed command prefixes (whitelist).
    #[serde(default = "default_allowed_commands")]
    pub allowed_commands: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            anti_debug: default_true(),
            vm_detection: default_true(),
            sandbox_detection: default_true(),
            timing_checks: false,
            timing_threshold_ms: default_timing_threshold(),
            obfuscation_key: None,
            allowed_commands: default_allowed_commands(),
        }
    }
}

// Default value functions for serde.
fn default_heartbeat() -> u64 { 30 }
fn default_reconnect_base() -> u64 { 1 }
fn default_reconnect_max() -> u64 { 300 }
fn default_reconnect_mult() -> f64 { 2.0 }
fn default_connection_mode() -> String { "plain".to_string() }
fn default_c2_listen() -> String { "0.0.0.0:9000".to_string() }
fn default_max_connections() -> usize { 1000 }
fn default_log_level() -> String { "info".to_string() }
fn default_log_format() -> String { "text".to_string() }
fn default_log_output() -> String { "stdout".to_string() }
fn default_true() -> bool { true }
fn default_timing_threshold() -> u64 { 100 }
fn default_allowed_commands() -> Vec<String> {
    vec![
        "echo ".to_string(),
        "ls ".to_string(),
        "cat ".to_string(),
        "df ".to_string(),
        "ps ".to_string(),
        "uptime".to_string(),
        "whoami".to_string(),
        "uname ".to_string(),
        "ip ".to_string(),
        "ss ".to_string(),
        "ping -c ".to_string(),
        "systemctl status ".to_string(),
        "journalctl ".to_string(),
        "free ".to_string(),
        "du ".to_string(),
        "date".to_string(),
        "id".to_string(),
    ]
}

/// Configuration manager with hot-reload support.
pub struct ConfigManager {
    config: Arc<RwLock<RuntimeConfig>>,
    config_path: Option<PathBuf>,
    watch_interval: Duration,
}

impl ConfigManager {
    /// Create a new config manager with default configuration.
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(RuntimeConfig::default())),
            config_path: None,
            watch_interval: Duration::from_secs(30),
        }
    }
    
    /// Create a config manager and load from a file.
    pub async fn from_file(path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let mut manager = Self::new();
        manager.config_path = Some(path.clone());
        manager.load_from_file(&path).await?;
        Ok(manager)
    }
    
    /// Load configuration from a TOML file.
    pub async fn load_from_file(&self, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let content = tokio::fs::read_to_string(path).await?;
        let mut config: RuntimeConfig = toml::from_str(&content)?;
        
        // Apply environment variable overrides
        Self::apply_env_overrides(&mut config);
        
        // Update the config atomically
        *self.config.write().await = config;
        Ok(())
    }
    
    /// Apply environment variable overrides to config.
    fn apply_env_overrides(config: &mut RuntimeConfig) {
        // Agent config overrides
        if let Ok(v) = std::env::var("RRA_AGENT_ID") {
            if let Ok(id) = v.parse() { config.agent.id = id; }
        }
        if let Ok(v) = std::env::var("RRA_SERVER_ADDR") {
            config.agent.server_addr = v;
        }
        if let Ok(v) = std::env::var("RRA_HEARTBEAT_INTERVAL") {
            if let Ok(i) = v.parse() { config.agent.heartbeat_interval = i; }
        }
        if let Ok(v) = std::env::var("RRA_CONNECTION_MODE") {
            config.agent.connection_mode = v;
        }
        if let Ok(v) = std::env::var("RRA_SERVER_NAME") {
            config.agent.server_name = Some(v);
        }
        if let Ok(v) = std::env::var("RRA_CA_CERT_PATH") {
            config.agent.ca_cert_path = Some(v);
        }
        if let Ok(v) = std::env::var("RRA_CLIENT_CERT_PATH") {
            config.agent.client_cert_path = Some(v);
        }
        if let Ok(v) = std::env::var("RRA_CLIENT_KEY_PATH") {
            config.agent.client_key_path = Some(v);
        }
        
        // C2 config overrides
        if let Ok(v) = std::env::var("RRA_C2_LISTEN_ADDR") {
            config.c2.listen_addr = v;
        }
        if let Ok(v) = std::env::var("RRA_C2_CERT_PATH") {
            config.c2.cert_path = Some(v);
        }
        if let Ok(v) = std::env::var("RRA_C2_KEY_PATH") {
            config.c2.key_path = Some(v);
        }
        if let Ok(v) = std::env::var("RRA_C2_REQUIRE_CLIENT_CERT") {
            config.c2.require_client_cert = v.parse().unwrap_or(false);
        }
        if let Ok(v) = std::env::var("RRA_C2_CLIENT_CA_PATH") {
            config.c2.client_ca_path = Some(v);
        }
        
        // Logging config overrides
        if let Ok(v) = std::env::var("RRA_LOG_LEVEL") {
            config.logging.level = v;
        }
        if let Ok(v) = std::env::var("RRA_LOG_FORMAT") {
            config.logging.format = v;
        }
        if let Ok(v) = std::env::var("RRA_LOG_OUTPUT") {
            config.logging.output = v;
        }
        if let Ok(v) = std::env::var("RRA_AUDIT_ENABLED") {
            config.logging.audit_enabled = v.parse().unwrap_or(false);
        }
        if let Ok(v) = std::env::var("RRA_AUDIT_LOG_PATH") {
            config.logging.audit_log_path = Some(v);
        }
        
        // Security config overrides
        if let Ok(v) = std::env::var("RRA_ANTI_DEBUG") {
            config.security.anti_debug = v.parse().unwrap_or(true);
        }
        if let Ok(v) = std::env::var("RRA_VM_DETECTION") {
            config.security.vm_detection = v.parse().unwrap_or(true);
        }
        if let Ok(v) = std::env::var("RRA_SANDBOX_DETECTION") {
            config.security.sandbox_detection = v.parse().unwrap_or(true);
        }
        if let Ok(v) = std::env::var("RRA_TIMING_CHECKS") {
            config.security.timing_checks = v.parse().unwrap_or(false);
        }
        if let Ok(v) = std::env::var("RRA_OBFUSCATION_KEY") {
            if let Ok(k) = v.parse() { config.security.obfuscation_key = Some(k); }
        }
        if let Ok(v) = std::env::var("RRA_ALLOWED_COMMANDS") {
            config.security.allowed_commands = v.split(',').map(|s| s.trim().to_string()).collect();
        }
    }
    
    /// Get a read-only snapshot of the current configuration.
    pub async fn get(&self) -> RuntimeConfig {
        self.config.read().await.clone()
    }
    
    /// Get a reference to the internal config for reading.
    pub fn config_ref(&self) -> Arc<RwLock<RuntimeConfig>> {
        self.config.clone()
    }
    
    /// Update configuration programmatically and optionally persist to file.
    pub async fn update<F>(&self, f: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: FnOnce(&mut RuntimeConfig),
    {
        {
            let mut config = self.config.write().await;
            f(&mut config);
        }
        
        // Persist to file if we have a path
        if let Some(path) = &self.config_path {
            self.persist_to_file(path).await?;
        }
        Ok(())
    }
    
    /// Persist current config to file.
    async fn persist_to_file(&self, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let config = self.config.read().await;
        let content = toml::to_string_pretty(&*config)?;
        tokio::fs::write(path, content).await?;
        Ok(())
    }
    
    /// Start background hot-reload task. Returns a handle to stop it.
    pub async fn start_hot_reload(&self) -> tokio::task::JoinHandle<()> {
        let config_path = self.config_path.clone();
        let config = self.config.clone();
        let interval = self.watch_interval;
        
        tokio::spawn(async move {
            if config_path.is_none() {
                return; // No file to watch
            }
            let path = config_path.unwrap();
            
            let mut tick_interval = tokio::time::interval(interval);
            let mut last_modified: Option<std::time::SystemTime> = None;
            
            // Get initial modification time
            if let Ok(metadata) = tokio::fs::metadata(&path).await {
                if let Ok(modified) = metadata.modified() {
                    last_modified = Some(modified);
                }
            }
            
            loop {
                tick_interval.tick().await;
                
                // Check if file was modified
                if let Ok(metadata) = tokio::fs::metadata(&path).await {
                    if let Ok(modified) = metadata.modified() {
                        if last_modified != Some(modified) {
                            // File changed, reload
                            if let Ok(content) = tokio::fs::read_to_string(&path).await {
                                if let Ok(new_config) = toml::from_str::<RuntimeConfig>(&content) {
                                    let mut config = config.write().await;
                                    *config = new_config;
                                    Self::apply_env_overrides(&mut config);
                                    last_modified = Some(modified);
                                    log::info!("Configuration hot-reloaded from {}", path.display());
                                }
                            }
                        }
                    }
                }
            }
        })
    }
    
    /// Export current configuration to TOML string.
    pub async fn to_toml(&self) -> String {
        let config = self.config.read().await;
        toml::to_string_pretty(&*config).unwrap_or_default()
    }
    
    /// Validate the current configuration.
    pub async fn validate(&self) -> Result<(), String> {
        let config = self.config.read().await;
        
        // Validate agent config
        if config.agent.server_addr.is_empty() {
            return Err("agent.server_addr cannot be empty".to_string());
        }
        
        if config.agent.heartbeat_interval == 0 {
            return Err("agent.heartbeat_interval must be > 0".to_string());
        }
        
        match config.agent.connection_mode.as_str() {
            "plain" | "tls" | "mtls" => {}
            _ => return Err(format!("agent.connection_mode must be 'plain', 'tls', or 'mtls', got '{}'", config.agent.connection_mode)),
        }
        
        if matches!(config.agent.connection_mode.as_str(), "tls" | "mtls") {
            if config.agent.ca_cert_path.is_none() {
                return Err("agent.ca_cert_path is required for TLS/mTLS".to_string());
            }
            if config.agent.connection_mode == "mtls" {
                if config.agent.client_cert_path.is_none() {
                    return Err("agent.client_cert_path is required for mTLS".to_string());
                }
                if config.agent.client_key_path.is_none() {
                    return Err("agent.client_key_path is required for mTLS".to_string());
                }
            }
        }
        
        // Validate C2 config
        if config.c2.listen_addr.is_empty() {
            return Err("c2.listen_addr cannot be empty".to_string());
        }
        
        if config.c2.require_client_cert && config.c2.client_ca_path.is_none() {
            return Err("c2.client_ca_path is required when require_client_cert is true".to_string());
        }
        
        if config.c2.cert_path.is_some() != config.c2.key_path.is_some() {
            return Err("c2.cert_path and c2.key_path must both be set or both unset".to_string());
        }
        
        // Validate logging config
        match config.logging.level.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            _ => return Err(format!("Invalid log level: {}", config.logging.level)),
        }
        
        match config.logging.format.as_str() {
            "json" | "text" => {}
            _ => return Err(format!("Invalid log format: {}", config.logging.format)),
        }
        
        if config.logging.audit_enabled && config.logging.audit_log_path.is_none() {
            return Err("logging.audit_log_path is required when audit_enabled is true".to_string());
        }
        
        Ok(())
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn config_manager_defaults() {
        let manager = ConfigManager::new();
        let config = manager.get().await;
        
        assert_eq!(config.agent.server_addr, "127.0.0.1:9000");
        assert_eq!(config.agent.heartbeat_interval, 30);
        assert_eq!(config.agent.connection_mode, "plain");
        assert_eq!(config.c2.listen_addr, "0.0.0.0:9000");
        assert_eq!(config.logging.level, "info");
        assert!(!config.logging.audit_enabled);
    }
    
    #[tokio::test]
    async fn config_manager_load_from_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        
        let toml_content = r#"
[agent]
id = 42
server_addr = "192.168.1.100:9000"
heartbeat_interval = 60
connection_mode = "mtls"
server_name = "c2.example.com"
ca_cert_path = "/etc/certs/ca.pem"
client_cert_path = "/etc/certs/client.pem"
client_key_path = "/etc/certs/client.key"

[c2]
listen_addr = "0.0.0.0:9000"
cert_path = "/etc/certs/server.pem"
key_path = "/etc/certs/server.key"
require_client_cert = true
client_ca_path = "/etc/certs/ca.pem"

[logging]
level = "debug"
format = "json"
output = "stdout"
audit_enabled = true
audit_log_path = "/var/log/audit.log"

[security]
anti_debug = true
vm_detection = true
sandbox_detection = false
timing_checks = true
timing_threshold_ms = 50
obfuscation_key = 0x5A
allowed_commands = ["echo ", "ls ", "custom_cmd "]
"#;
        
        tokio::fs::write(&path, toml_content).await.unwrap();
        
        let manager = ConfigManager::from_file(path).await.unwrap();
        let config = manager.get().await;
        
        assert_eq!(config.agent.id, 42);
        assert_eq!(config.agent.server_addr, "192.168.1.100:9000");
        assert_eq!(config.agent.heartbeat_interval, 60);
        assert_eq!(config.agent.connection_mode, "mtls");
        assert_eq!(config.agent.server_name, Some("c2.example.com".to_string()));
        assert_eq!(config.c2.require_client_cert, true);
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.logging.format, "json");
        assert!(config.logging.audit_enabled);
        assert_eq!(config.security.timing_threshold_ms, 50);
        assert_eq!(config.security.allowed_commands, vec!["echo ", "ls ", "custom_cmd "]);
    }
    
    #[tokio::test]
    async fn config_manager_env_overrides() {
        std::env::set_var("RRA_AGENT_ID", "99");
        std::env::set_var("RRA_SERVER_ADDR", "10.0.0.1:8080");
        std::env::set_var("RRA_CONNECTION_MODE", "tls");
        std::env::set_var("RRA_LOG_LEVEL", "trace");
        std::env::set_var("RRA_AUDIT_ENABLED", "true");
        
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        
        // Empty config - env vars should fill in
        tokio::fs::write(&path, "").await.unwrap();
        
        let manager = ConfigManager::from_file(path).await.unwrap();
        let config = manager.get().await;
        
        assert_eq!(config.agent.id, 99);
        assert_eq!(config.agent.server_addr, "10.0.0.1:8080");
        assert_eq!(config.agent.connection_mode, "tls");
        assert_eq!(config.logging.level, "trace");
        assert!(config.logging.audit_enabled);
        
        // Cleanup
        std::env::remove_var("RRA_AGENT_ID");
        std::env::remove_var("RRA_SERVER_ADDR");
        std::env::remove_var("RRA_CONNECTION_MODE");
        std::env::remove_var("RRA_LOG_LEVEL");
        std::env::remove_var("RRA_AUDIT_ENABLED");
    }
    
    #[tokio::test]
    async fn config_manager_update_and_persist() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        
        // Write initial config
        tokio::fs::write(&path, "").await.unwrap();
        
        let manager = ConfigManager::from_file(path.clone()).await.unwrap();
        
        manager.update(|config| {
            config.agent.id = 123;
            config.agent.heartbeat_interval = 45;
            config.logging.level = "warn".to_string();
        }).await.unwrap();
        
        let config = manager.get().await;
        assert_eq!(config.agent.id, 123);
        assert_eq!(config.agent.heartbeat_interval, 45);
        assert_eq!(config.logging.level, "warn");
        
        // Verify persisted
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(content.contains("id = 123"));
        assert!(content.contains("heartbeat_interval = 45"));
        assert!(content.contains("level = \"warn\""));
    }
    
    #[tokio::test]
    async fn config_manager_validation() {
        let mut manager = ConfigManager::new();
        
        // Valid default config
        assert!(manager.validate().await.is_ok());
        
        // Invalid: empty server_addr
        manager.update(|c| c.agent.server_addr = "".to_string()).await.unwrap();
        assert!(manager.validate().await.is_err());
        
        // Invalid: zero heartbeat
        manager.update(|c| {
            c.agent.server_addr = "127.0.0.1:9000".to_string();
            c.agent.heartbeat_interval = 0;
        }).await.unwrap();
        assert!(manager.validate().await.is_err());
        
        // Invalid: unknown connection mode
        manager.update(|c| {
            c.agent.heartbeat_interval = 30;
            c.agent.connection_mode = "unknown".to_string();
        }).await.unwrap();
        assert!(manager.validate().await.is_err());
        
        // Invalid: TLS without CA cert
        manager.update(|c| {
            c.agent.connection_mode = "tls".to_string();
            c.agent.ca_cert_path = None;
        }).await.unwrap();
        assert!(manager.validate().await.is_err());
        
        // Invalid: mTLS without client cert
        manager.update(|c| {
            c.agent.connection_mode = "mtls".to_string();
            c.agent.ca_cert_path = Some("/tmp/ca.pem".to_string());
            c.agent.client_cert_path = None;
        }).await.unwrap();
        assert!(manager.validate().await.is_err());
        
        // Invalid: audit enabled without path
        manager.update(|c| {
            c.agent.connection_mode = "plain".to_string();
            c.logging.audit_enabled = true;
            c.logging.audit_log_path = None;
        }).await.unwrap();
        assert!(manager.validate().await.is_err());
    }
}