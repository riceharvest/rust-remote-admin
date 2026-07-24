use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Audit event types for structured logging.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Agent connected to C2.
    AgentConnected,
    /// Agent disconnected from C2.
    AgentDisconnected,
    /// Agent sent heartbeat.
    Heartbeat,
    /// Command received from C2.
    CommandReceived,
    /// Command execution result.
    CommandExecuted,
    /// Agent self-update initiated.
    SelfUpdateStarted,
    /// Agent self-update completed.
    SelfUpdateCompleted,
    /// Agent self-update failed.
    SelfUpdateFailed,
    /// File operation (read/write/list).
    FileOperation,
    /// Process operation (list/kill).
    ProcessOperation,
    /// Registry operation.
    RegistryOperation,
    /// Authentication/authorization event.
    AuthEvent,
    /// Security detection event (debugger, VM, sandbox).
    SecurityDetection,
    /// Configuration changed.
    ConfigChanged,
    /// Agent state persisted.
    StatePersisted,
    /// Agent state loaded.
    StateLoaded,
    /// TLS handshake completed.
    TlsHandshake,
    /// Connection error.
    ConnectionError,
}

/// Audit event severity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Structured audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique event ID.
    pub id: u64,
    /// Unix timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Event type.
    pub event_type: AuditEventType,
    /// Severity level.
    pub severity: AuditSeverity,
    /// Agent ID (if applicable).
    pub agent_id: Option<u32>,
    /// Session ID (for correlating related events).
    pub session_id: Option<String>,
    /// Human-readable message.
    pub message: String,
    /// Additional structured fields.
    #[serde(flatten)]
    pub fields: HashMap<String, serde_json::Value>,
}

/// Audit logger configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable audit logging.
    pub enabled: bool,
    /// Output path (file). If None, logs to stdout.
    pub log_path: Option<PathBuf>,
    /// Also output to stdout/stderr.
    pub also_stdout: bool,
    /// Minimum severity to log.
    pub min_severity: AuditSeverity,
    /// Buffer size for async writer.
    pub buffer_size: usize,
    /// Flush interval in milliseconds.
    pub flush_interval_ms: u64,
    /// Rotate log file when it exceeds this size (bytes).
    pub max_file_size: u64,
    /// Maximum number of rotated files to keep.
    pub max_files: usize,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_path: None,
            also_stdout: false,
            min_severity: AuditSeverity::Info,
            buffer_size: 8192,
            flush_interval_ms: 1000,
            max_file_size: 100 * 1024 * 1024, // 100 MB
            max_files: 10,
        }
    }
}

/// Async audit logger with buffered writing and optional file rotation.
pub struct AuditLogger {
    config: AuditConfig,
    writer: Option<Arc<Mutex<BufWriter<std::fs::File>>>>,
    event_tx: mpsc::UnboundedSender<AuditEntry>,
    _worker_handle: tokio::task::JoinHandle<()>,
    next_id: Arc<Mutex<u64>>,
}

impl AuditLogger {
    /// Create a new audit logger from config.
    pub fn new(config: AuditConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let config_clone = config.clone();
        let next_id = Arc::new(Mutex::new(1u64));
        let next_id_clone = next_id.clone();

        // Initialize file writer if path specified
        let writer = if let Some(ref path) = config.log_path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            Some(Arc::new(Mutex::new(BufWriter::with_capacity(config.buffer_size, file))))
        } else {
            None
        };
        let writer_clone = writer.clone();

        // Background worker for async writing
        let worker_handle = tokio::spawn(async move {
            let mut flush_interval = tokio::time::interval(
                std::time::Duration::from_millis(config_clone.flush_interval_ms)
            );
            
            loop {
                tokio::select! {
                    Some(entry) = event_rx.recv() => {
                        if let Err(e) = Self::write_entry(&writer_clone, &entry, config_clone.also_stdout) {
                            eprintln!("Audit log write error: {}", e);
                        }
                    }
                    _ = flush_interval.tick() => {
                        if let Some(ref w) = writer_clone {
                            if let Ok(mut guard) = w.lock() {
                                let _ = guard.flush();
                            }
                        }
                    }
                    else => break, // channel closed
                }
            }
        });

        Ok(Self {
            config,
            writer,
            event_tx,
            _worker_handle: worker_handle,
            next_id,
        })
    }

    /// Write a single audit entry to the output.
    fn write_entry(
        writer: &Option<Arc<Mutex<BufWriter<std::fs::File>>>>,
        entry: &AuditEntry,
        also_stdout: bool,
    ) -> std::io::Result<()> {
        let json = serde_json::to_string(entry)?;
        let line = format!("{}\n", json);

        if let Some(ref w) = writer {
            let mut guard = w.lock().map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "mutex poisoned"))?;
            guard.write_all(line.as_bytes())?;
        }

        if also_stdout {
            println!("{}", line);
        }

        Ok(())
    }

    /// Log an audit event.
    pub fn log(&self, event: AuditEntry) {
        let _ = self.event_tx.send(event);
    }

    /// Log an event with the given type, severity, and message.
    pub fn log_event(
        &self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        message: &str,
        agent_id: Option<u32>,
        session_id: Option<String>,
        fields: HashMap<String, serde_json::Value>,
    ) {
        if !self.config.enabled {
            return;
        }
        
        // Check severity threshold
        let severity_order = [
            AuditSeverity::Info,
            AuditSeverity::Warning,
            AuditSeverity::Error,
            AuditSeverity::Critical,
        ];
        let min_idx = severity_order.iter().position(|s| s == &self.config.min_severity).unwrap_or(0);
        let event_idx = severity_order.iter().position(|s| s == &severity).unwrap_or(0);
        if event_idx < min_idx {
            return;
        }

        let id = {
            let mut guard = self.next_id.lock().unwrap();
            let id = *guard;
            *guard = guard.wrapping_add(1);
            id
        };

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let entry = AuditEntry {
            id,
            timestamp_ms,
            event_type,
            severity,
            agent_id,
            session_id,
            message: message.to_string(),
            fields,
        };

        self.log(entry);
    }

    /// Convenience method for agent connection events.
    pub fn agent_connected(&self, agent_id: u32, server_addr: &str) {
        let mut fields = HashMap::new();
        fields.insert("server_addr".to_string(), serde_json::Value::String(server_addr.to_string()));
        self.log_event(
            AuditEventType::AgentConnected,
            AuditSeverity::Info,
            &format!("Agent {} connected to {}", agent_id, server_addr),
            Some(agent_id),
            None,
            fields,
        );
    }

    /// Convenience method for agent disconnection events.
    pub fn agent_disconnected(&self, agent_id: u32, reason: &str) {
        let mut fields = HashMap::new();
        fields.insert("reason".to_string(), serde_json::Value::String(reason.to_string()));
        self.log_event(
            AuditEventType::AgentDisconnected,
            AuditSeverity::Info,
            &format!("Agent {} disconnected: {}", agent_id, reason),
            Some(agent_id),
            None,
            fields,
        );
    }

    /// Convenience method for command execution events.
    pub fn command_executed(&self, agent_id: u32, command: &str, success: bool, output_len: usize) {
        let mut fields = HashMap::new();
        fields.insert("command".to_string(), serde_json::Value::String(command.to_string()));
        fields.insert("success".to_string(), serde_json::Value::Bool(success));
        fields.insert("output_length".to_string(), serde_json::Value::Number(serde_json::Number::from(output_len)));
        self.log_event(
            AuditEventType::CommandExecuted,
            if success { AuditSeverity::Info } else { AuditSeverity::Warning },
            &format!("Command executed by agent {}: {} (success={})", agent_id, command, success),
            Some(agent_id),
            None,
            fields,
        );
    }

    /// Convenience method for self-update events.
    pub fn self_update(&self, agent_id: u32, stage: &str, success: bool, details: &str) {
        let (event_type, severity) = match (stage, success) {
            ("started", _) => (AuditEventType::SelfUpdateStarted, AuditSeverity::Info),
            ("completed", true) => (AuditEventType::SelfUpdateCompleted, AuditSeverity::Info),
            ("completed", false) => (AuditEventType::SelfUpdateFailed, AuditSeverity::Error),
            ("failed", _) => (AuditEventType::SelfUpdateFailed, AuditSeverity::Error),
            _ => (AuditEventType::SelfUpdateStarted, AuditSeverity::Info),
        };
        
        let mut fields = HashMap::new();
        fields.insert("stage".to_string(), serde_json::Value::String(stage.to_string()));
        fields.insert("success".to_string(), serde_json::Value::Bool(success));
        fields.insert("details".to_string(), serde_json::Value::String(details.to_string()));
        
        self.log_event(
            event_type,
            severity,
            &format!("Self-update {} for agent {}: {}", stage, agent_id, details),
            Some(agent_id),
            None,
            fields,
        );
    }

    /// Convenience method for security detection events.
    pub fn security_detection(&self, agent_id: Option<u32>, detection_type: &str, detected: bool, details: &str) {
        let mut fields = HashMap::new();
        fields.insert("detection_type".to_string(), serde_json::Value::String(detection_type.to_string()));
        fields.insert("detected".to_string(), serde_json::Value::Bool(detected));
        fields.insert("details".to_string(), serde_json::Value::String(details.to_string()));
        
        self.log_event(
            AuditEventType::SecurityDetection,
            if detected { AuditSeverity::Warning } else { AuditSeverity::Info },
            &format!("Security detection: {} (detected={})", detection_type, detected),
            agent_id,
            None,
            fields,
        );
    }

    /// Convenience method for configuration change events.
    pub fn config_changed(&self, agent_id: Option<u32>, changed_keys: &[&str]) {
        let mut fields = HashMap::new();
        fields.insert("changed_keys".to_string(), serde_json::to_value(changed_keys).unwrap_or_default());
        
        self.log_event(
            AuditEventType::ConfigChanged,
            AuditSeverity::Info,
            &format!("Configuration changed: {} keys", changed_keys.len()),
            agent_id,
            None,
            fields,
        );
    }

    /// Convenience method for connection errors.
    pub fn connection_error(&self, agent_id: Option<u32>, error: &str, context: &str) {
        let mut fields = HashMap::new();
        fields.insert("error".to_string(), serde_json::Value::String(error.to_string()));
        fields.insert("context".to_string(), serde_json::Value::String(context.to_string()));
        
        self.log_event(
            AuditEventType::ConnectionError,
            AuditSeverity::Error,
            &format!("Connection error ({}): {}", context, error),
            agent_id,
            None,
            fields,
        );
    }

    /// Flush any buffered writes.
    pub fn flush(&self) -> std::io::Result<()> {
        if let Some(ref w) = self.writer {
            if let Ok(mut guard) = w.lock() {
                guard.flush()?;
            }
        }
        Ok(())
    }
}

/// Global audit logger instance.
static AUDIT_LOGGER: once_cell::sync::OnceCell<AuditLogger> = once_cell::sync::OnceCell::new();

/// Initialize the global audit logger.
pub fn init_global_audit(config: AuditConfig) -> Result<(), Box<dyn std::error::Error>> {
    let logger = AuditLogger::new(config)?;
    AUDIT_LOGGER.set(logger).map_err(|_| "Audit logger already initialized")?;
    Ok(())
}

/// Get the global audit logger.
pub fn global_audit() -> Option<&'static AuditLogger> {
    AUDIT_LOGGER.get()
}

/// Log an audit event using the global logger.
pub fn audit_log(
    event_type: AuditEventType,
    severity: AuditSeverity,
    message: &str,
    agent_id: Option<u32>,
    session_id: Option<String>,
    fields: HashMap<String, serde_json::Value>,
) {
    if let Some(logger) = AUDIT_LOGGER.get() {
        logger.log_event(
            event_type,
            severity,
            message,
            agent_id,
            session_id,
            fields,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::time::Duration;

    #[tokio::test]
    async fn audit_logger_basic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        
        let config = AuditConfig {
            enabled: true,
            log_path: Some(path.clone()),
            also_stdout: false,
            min_severity: AuditSeverity::Info,
            buffer_size: 1024,
            flush_interval_ms: 100,
            max_file_size: 1024 * 1024,
            max_files: 5,
        };
        
        let logger = AuditLogger::new(config).unwrap();
        
        logger.log_event(
            AuditEventType::AgentConnected,
            AuditSeverity::Info,
            "Test connection",
            Some(42),
            Some("session-123".to_string()),
            HashMap::new(),
        );
        
        logger.flush().unwrap();
        
        // Give worker time to write
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("agent_connected"));
        assert!(content.contains("Test connection"));
        assert!(content.contains("42"));
    }

    #[tokio::test]
    async fn audit_logger_severity_filter() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        
        let config = AuditConfig {
            enabled: true,
            log_path: Some(path.clone()),
            also_stdout: false,
            min_severity: AuditSeverity::Warning,
            buffer_size: 1024,
            flush_interval_ms: 100,
            max_file_size: 1024 * 1024,
            max_files: 5,
        };
        
        let logger = AuditLogger::new(config).unwrap();
        
        // This should be filtered out (Info < Warning)
        logger.log_event(
            AuditEventType::Heartbeat,
            AuditSeverity::Info,
            "Heartbeat",
            None,
            None,
            HashMap::new(),
        );
        
        // This should pass (Warning >= Warning)
        logger.log_event(
            AuditEventType::SecurityDetection,
            AuditSeverity::Warning,
            "VM detected",
            None,
            None,
            HashMap::new(),
        );
        
        logger.flush().unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.contains("Heartbeat"));
        assert!(content.contains("VM detected"));
    }

    #[tokio::test]
    async fn audit_logger_convenience_methods() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        
        let config = AuditConfig {
            enabled: true,
            log_path: Some(path.clone()),
            also_stdout: false,
            min_severity: AuditSeverity::Info,
            buffer_size: 1024,
            flush_interval_ms: 100,
            max_file_size: 1024 * 1024,
            max_files: 5,
        };
        
        let logger = AuditLogger::new(config).unwrap();
        
        logger.agent_connected(1, "127.0.0.1:9000");
        logger.agent_disconnected(1, "timeout");
        logger.command_executed(1, "echo test", true, 5);
        logger.self_update(1, "started", true, "downloading");
        logger.security_detection(Some(1), "vm", true, "VMware detected");
        logger.config_changed(Some(1), &["heartbeat_interval", "server_addr"]);
        logger.connection_error(Some(1), "connection refused", "reconnect");
        
        logger.flush().unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 7);
        
        // Verify each event type is present
        let content_str = content;
        assert!(content_str.contains("agent_connected"));
        assert!(content_str.contains("agent_disconnected"));
        assert!(content_str.contains("command_executed"));
        assert!(content_str.contains("self_update_started"));
        assert!(content_str.contains("security_detection"));
        assert!(content_str.contains("config_changed"));
        assert!(content_str.contains("connection_error"));
    }

    #[test]
    fn audit_entry_serialization() {
        let entry = AuditEntry {
            id: 1,
            timestamp_ms: 1234567890000,
            event_type: AuditEventType::CommandExecuted,
            severity: AuditSeverity::Info,
            agent_id: Some(42),
            session_id: Some("sess-123".to_string()),
            message: "Command executed".to_string(),
            fields: {
                let mut m = HashMap::new();
                m.insert("command".to_string(), serde_json::Value::String("echo test".to_string()));
                m.insert("success".to_string(), serde_json::Value::Bool(true));
                m
            },
        };
        
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();
        
        assert_eq!(parsed.id, 1);
        assert_eq!(parsed.timestamp_ms, 1234567890000);
        assert_eq!(parsed.event_type, AuditEventType::CommandExecuted);
        assert_eq!(parsed.severity, AuditSeverity::Info);
        assert_eq!(parsed.agent_id, Some(42));
        assert_eq!(parsed.session_id, Some("sess-123".to_string()));
        assert_eq!(parsed.fields.get("command").unwrap().as_str().unwrap(), "echo test");
    }
}