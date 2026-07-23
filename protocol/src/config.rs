//! Shared configuration structures for agent-C2 communication.
//!
//! This module defines the embedded configuration that gets patched into
//! agent binaries at generation time. Both the C2 (generator) and agent
//! (runtime) use these structures.

use serde::{Deserialize, Serialize};
use std::io;

/// Magic marker to identify the config section in the agent binary.
pub const CONFIG_MARKER: &[u8] = b"RRA_CONFIG_V1";

/// Size of the config section in bytes (fixed for binary patching).
pub const CONFIG_SIZE: usize = 512;

/// Configuration embedded in the agent binary at generation time.
///
/// The agent reads this from a known offset in its own executable.
/// The C2 patches this into the agent template during `generate-agent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// C2 server address in "host:port" format.
    pub c2_address: String,
    /// TLS certificate fingerprint (hex-encoded SHA256).
    pub cert_fingerprint: String,
    /// Unique agent identifier.
    pub agent_id: u32,
    /// Heartbeat interval in seconds.
    pub heartbeat_interval: u64,
    /// Optional path to a client TLS certificate (PEM) on the target.
    /// When set, the agent uses this cert for mTLS authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_path: Option<String>,
    /// Optional path to a client TLS private key (PEM) on the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,
}

impl AgentConfig {
    /// Create a new agent configuration.
    pub fn new(
        c2_address: String,
        cert_fingerprint: String,
        agent_id: u32,
    ) -> Self {
        Self {
            c2_address,
            cert_fingerprint,
            agent_id,
            heartbeat_interval: 30,
            cert_path: None,
            key_path: None,
        }
    }

    /// Build a config with optional mTLS cert/key paths.
    pub fn with_tls_paths(
        c2_address: String,
        cert_fingerprint: String,
        agent_id: u32,
        cert_path: Option<String>,
        key_path: Option<String>,
    ) -> Self {
        Self {
            c2_address,
            cert_fingerprint,
            agent_id,
            heartbeat_interval: 30,
            cert_path,
            key_path,
        }
    }

    /// Serialize to bytes for embedding in the agent binary.
    ///
    /// Returns a fixed-size buffer of CONFIG_SIZE bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, io::Error> {
        let json = serde_json::to_string(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        
        if json.len() > CONFIG_SIZE - 16 { // reserve space for marker + length
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Config too large: {} bytes (max {})", json.len(), CONFIG_SIZE - 16),
            ));
        }

        let mut buffer = vec![0u8; CONFIG_SIZE];
        let mut cursor = 0;

        // Write marker
        buffer[cursor..cursor + CONFIG_MARKER.len()].copy_from_slice(CONFIG_MARKER);
        cursor += CONFIG_MARKER.len();

        // Write length (u32, little-endian)
        let len = json.len() as u32;
        buffer[cursor..cursor + 4].copy_from_slice(&len.to_le_bytes());
        cursor += 4;

        // Write JSON config
        buffer[cursor..cursor + json.len()].copy_from_slice(json.as_bytes());

        Ok(buffer)
    }

    /// Deserialize from bytes read from the agent binary.
    ///
    /// Searches for the CONFIG_MARKER and parses the following JSON.
    pub fn from_bytes(data: &[u8]) -> Result<Self, io::Error> {
        // Find the marker
        let marker_pos = data
            .windows(CONFIG_MARKER.len())
            .position(|w| w == CONFIG_MARKER)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Config marker not found"))?;

        let cursor = marker_pos + CONFIG_MARKER.len();

        // Read length
        if cursor + 4 > data.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Config length missing"));
        }
        let len_bytes: [u8; 4] = data[cursor..cursor + 4]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid length bytes"))?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        let json_start = cursor + 4;
        if json_start + len > data.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Config data truncated"));
        }

        // Parse JSON
        let json = std::str::from_utf8(&data[json_start..json_start + len])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        
        let config: AgentConfig = serde_json::from_str(json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_roundtrip() {
        let config = AgentConfig::new(
            "192.168.1.100:9000".to_string(),
            "abcd1234".to_string(),
            42,
        );

        let bytes = config.to_bytes().unwrap();
        assert_eq!(bytes.len(), CONFIG_SIZE);

        let parsed = AgentConfig::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.c2_address, "192.168.1.100:9000");
        assert_eq!(parsed.cert_fingerprint, "abcd1234");
        assert_eq!(parsed.agent_id, 42);
        assert_eq!(parsed.heartbeat_interval, 30);
    }

    #[test]
    fn test_config_marker_detection() {
        let config = AgentConfig::new("test:8080".to_string(), "fingerprint".to_string(), 1);
        let bytes = config.to_bytes().unwrap();

        // Verify marker is present
        assert!(bytes.windows(CONFIG_MARKER.len()).any(|w| w == CONFIG_MARKER));
    }
}
