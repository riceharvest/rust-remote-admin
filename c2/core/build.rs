//! Build script for c2-core.
//!
//! Searches for a pre-compiled agent template binary and embeds it into
//! the C2 binary so `generate-agent` works without an external file.
//!
//! Search order:
//!   1. RRA_AGENT_TEMPLATE env var (absolute path)
//!   2. ../target/x86_64-pc-windows-gnu/release/rust-remote-admin-agent.exe
//!   3. ../target/release/rust-remote-admin-agent
//!   4. ../target/release/rust-remote-admin-agent.exe
//!   5. ../../target/x86_64-pc-windows-gnu/release/rust-remote-admin-agent.exe
//!   6. ../../target/release/rust-remote-admin-agent
//!
//! CI build order: agent-core first, then c2-core picks it up.

use std::env;
use std::fs;
use std::path::PathBuf;

const CANDIDATES: &[&str] = &[
    "../target/x86_64-pc-windows-gnu/release/rust-remote-admin-agent.exe",
    "../target/release/rust-remote-admin-agent",
    "../target/release/rust-remote-admin-agent.exe",
    "../../target/x86_64-pc-windows-gnu/release/rust-remote-admin-agent.exe",
    "../../target/release/rust-remote-admin-agent",
];

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let src_dir = manifest_dir.join("src");
    let rs_path = src_dir.join("embedded_agent.rs");

    // Try env var first, then known paths
    let found = env::var("RRA_AGENT_TEMPLATE")
        .ok()
        .and_then(|p| {
            let pb = PathBuf::from(&p);
            if pb.exists() { Some(pb) } else { None }
        })
        .or_else(|| {
            CANDIDATES
                .iter()
                .map(|c| manifest_dir.join(c))
                .find(|p| p.exists())
        });

    let content = if let Some(template_path) = found {
        let abs = template_path.canonicalize().unwrap_or(template_path);
        println!("cargo:warning=Embedding agent template from {}", abs.display());
        format!(
            "/// Pre-compiled agent template embedded at build time.\npub const AGENT_TEMPLATE: &[u8] = include_bytes!({path:?});\n",
            path = abs
        )
    } else {
        println!("cargo:warning=No agent template found — generate-agent will require --template");
        "pub const AGENT_TEMPLATE: &[u8] = &[];\n".to_string()
    };

    fs::write(&rs_path, &content).expect("Failed to write embedded_agent.rs");
    println!("cargo:rerun-if-env-changed=RRA_AGENT_TEMPLATE");
    println!("cargo:rerun-if-changed=build.rs");
}
