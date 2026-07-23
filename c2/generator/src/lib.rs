use anyhow::{Context, Result};
use protocol::config::{AgentConfig, CONFIG_MARKER, CONFIG_SIZE};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Patches embedded configuration into a template agent binary.
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

    /// Generate a configured agent binary.
    ///
    /// Writes the config into the first 512 bytes after the RRA_CONFIG_V1 marker.
    pub fn generate(
        &self,
        c2_address: &str,
        cert_fingerprint: &str,
        agent_id: u32,
        output_path: &Path,
    ) -> Result<()> {
        let config = AgentConfig::new(c2_address.to_string(), cert_fingerprint.to_string(), agent_id);
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
            agent_id,
            output_path,
            output.len()
        );

        Ok(())
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

    /// Calculate SHA256 hash of the template.
    pub fn hash_template(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.template);
        format!("{:x}", hasher.finalize())
    }
}
