use anyhow::{Context, Result};
use protocol::config::{AgentConfig, CONFIG_MARKER, CONFIG_SIZE};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Patches embedded configuration into a template agent binary.
#[derive(Debug)]
pub struct AgentGenerator {
    pub template: Vec<u8>,
}

impl AgentGenerator {
    /// Load a template agent binary and verify it contains the config marker.
    pub fn from_file(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).context("Failed to read agent template")?;
        Self::new(bytes)
    }

    pub fn new(template: Vec<u8>) -> Result<Self> {
        if !Self::has_config_marker(&template) {
            anyhow::bail!("Template does not contain config marker");
        }
        Ok(Self { template })
    }

    /// Generate a configured agent binary from a config struct.
    pub fn generate(&self, config: &AgentConfig, output_path: &Path) -> Result<()> {
        let config_bytes = config.to_bytes().context("Failed to serialize config")?;

        // Find marker position in template
        let marker_pos = self
            .find_config_marker(&self.template)
            .context("Config marker not found in template")?;

        // Clone template and patch the config section
        let mut output = self.template.clone();
        output[marker_pos..marker_pos + CONFIG_SIZE].copy_from_slice(&config_bytes);

        fs::write(output_path, &output)
            .with_context(|| format!("Failed to write agent to {:?}", output_path))?;

        log::info!(
            "Generated agent {} at {:?} ({} bytes)",
            config.agent_id,
            output_path,
            output.len()
        );

        Ok(())
    }

    /// Generate a batch of agents with sequential IDs.
    ///
    /// `base_output` is the template path. When `count > 1`, the agent ID
    /// is inserted before the extension: `base-1.exe`, `base-2.exe`, etc.
    /// When `count == 1` (or the extra suffix is empty), uses `base_output` as-is.
    /// `config` is cloned per agent with its `agent_id` incremented from `start_id`.
    pub fn generate_batch(
        &self,
        config: &AgentConfig,
        base_output: &Path,
        count: u32,
    ) -> Result<Vec<PathBuf>> {
        let mut outputs = Vec::with_capacity(count as usize);
        for i in 0..count {
            let agent_id = config.agent_id + i;
            let mut cfg = config.clone();
            cfg.agent_id = agent_id;

            let path = if count > 1 {
                let stem = base_output
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "agent".to_string());
                let ext = base_output
                    .extension()
                    .map(|e| format!(".{}", e.to_string_lossy()))
                    .unwrap_or_default();
                base_output.with_file_name(format!("{}-{}{}", stem, agent_id, ext))
            } else {
                base_output.to_path_buf()
            };

            self.generate(&cfg, &path)?;
            outputs.push(path);
        }
        Ok(outputs)
    }

    /// Check if the binary contains the config marker.
    fn has_config_marker(data: &[u8]) -> bool {
        data.windows(CONFIG_MARKER.len())
            .any(|w| w == CONFIG_MARKER)
    }

    /// Find the position of the config marker.
    fn find_config_marker(&self, data: &[u8]) -> Option<usize> {
        data.windows(CONFIG_MARKER.len()).position(|w| w == CONFIG_MARKER)
    }

    /// Generate a configured agent binary (convenience wrapper).
    ///
    /// Creates an `AgentConfig` from individual parameters and patches it.
    pub fn generate_simple(
        &self,
        c2_address: &str,
        cert_fingerprint: &str,
        agent_id: u32,
        cert_path: Option<&str>,
        key_path: Option<&str>,
        output_path: &Path,
    ) -> Result<()> {
        let config = AgentConfig::with_tls_paths(
            c2_address.to_string(),
            cert_fingerprint.to_string(),
            agent_id,
            cert_path.map(|s| s.to_string()),
            key_path.map(|s| s.to_string()),
        );
        self.generate(&config, output_path)
    }

    /// Calculate SHA256 hash of the template.
    pub fn hash_template(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.template);
        format!("{:x}", hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal fake template with the config marker at a known offset.
    fn fake_template() -> Vec<u8> {
        // 4096 bytes of zeros, then two copies of the marker + config slot padding
        let mut tpl = vec![0u8; 8192 + CONFIG_SIZE];
        let marker_start = 4096;
        // Write marker
        tpl[marker_start..marker_start + CONFIG_MARKER.len()].copy_from_slice(CONFIG_MARKER);
        // Write a placeholder config (length=0, all zeros after marker)
        let after_marker = marker_start + CONFIG_MARKER.len();
        // u32 LE length = 0 (no config yet)
        tpl[after_marker..after_marker + 4].copy_from_slice(&0u32.to_le_bytes());
        tpl
    }

    #[test]
    fn test_generator_detects_marker() {
        let tpl = fake_template();
        let gen = AgentGenerator::new(tpl).unwrap();
        assert!(gen.template.len() > 0);
    }

    #[test]
    fn test_generator_rejects_no_marker() {
        let bad = vec![0u8; 1024];
        let result = AgentGenerator::new(bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("marker"));
    }

    #[test]
    fn test_generate_single_agent() {
        let tpl = fake_template();
        let gen = AgentGenerator::new(tpl).unwrap();

        let config = AgentConfig::with_tls_paths(
            "10.0.0.1:9000".to_string(),
            "abc123".to_string(),
            7,
            Some("/etc/client.pem".to_string()),
            Some("/etc/client.key".to_string()),
        );

        let tmp = tempfile::NamedTempFile::new().unwrap();
        gen.generate(&config, tmp.path()).unwrap();

        // Read back and verify config
        let output = std::fs::read(tmp.path()).unwrap();
        let parsed = AgentConfig::from_bytes(&output).unwrap();
        assert_eq!(parsed.c2_address, "10.0.0.1:9000");
        assert_eq!(parsed.cert_fingerprint, "abc123");
        assert_eq!(parsed.agent_id, 7);
        assert_eq!(parsed.heartbeat_interval, 30);
        assert_eq!(parsed.cert_path, Some("/etc/client.pem".to_string()));
        assert_eq!(parsed.key_path, Some("/etc/client.key".to_string()));
    }

    #[test]
    fn test_generate_batch() {
        let tpl = fake_template();
        let gen = AgentGenerator::new(tpl).unwrap();

        let config = AgentConfig::new(
            "10.0.0.1:9000".to_string(),
            "abc123".to_string(),
            10,
        );

        let tmpdir = tempfile::tempdir().unwrap();
        let base = tmpdir.path().join("agent.exe");
        let paths = gen.generate_batch(&config, &base, 3).unwrap();

        assert_eq!(paths.len(), 3);
        assert_eq!(paths[0].file_name().unwrap().to_str().unwrap(), "agent-10.exe");
        assert_eq!(paths[1].file_name().unwrap().to_str().unwrap(), "agent-11.exe");
        assert_eq!(paths[2].file_name().unwrap().to_str().unwrap(), "agent-12.exe");

        // Verify each agent has the right ID
        for (i, path) in paths.iter().enumerate() {
            let data = std::fs::read(path).unwrap();
            let cfg = AgentConfig::from_bytes(&data).unwrap();
            assert_eq!(cfg.agent_id, 10 + i as u32);
            assert_eq!(cfg.c2_address, "10.0.0.1:9000");
        }
    }

    #[test]
    fn test_generate_simple_wrapper() {
        let tpl = fake_template();
        let gen = AgentGenerator::new(tpl).unwrap();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        gen.generate_simple(
            "192.168.1.1:4443",
            "def456",
            42,
            None,
            None,
            tmp.path(),
        ).unwrap();

        let data = std::fs::read(tmp.path()).unwrap();
        let cfg = AgentConfig::from_bytes(&data).unwrap();
        assert_eq!(cfg.agent_id, 42);
        assert!(cfg.cert_path.is_none());
        assert!(cfg.key_path.is_none());
    }

    #[test]
    fn test_batch_single_output() {
        let tpl = fake_template();
        let gen = AgentGenerator::new(tpl).unwrap();

        let config = AgentConfig::new("1.2.3.4:9000".to_string(), "fp".to_string(), 1);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let paths = gen.generate_batch(&config, tmp.path(), 1).unwrap();

        // count=1 → use base path as-is (no suffix)
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].file_name(), tmp.path().file_name());
    }
}
