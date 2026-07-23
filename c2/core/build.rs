//! Build script for c2-core.
//!
//! Searches for a pre-compiled agent template binary and embeds it into
//! the C2 binary so `generate-agent` works without an external file.
//!
//! CI build order: agent-core first, then c2-core picks it up.
//!
//! The template must be a Windows .exe built for x86_64-pc-windows-gnu
//! (the agent target). The Linux C2 embeds the Windows agent template.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Find the workspace root by looking for the workspace Cargo.toml.
fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let mut dir = manifest.as_path();
    loop {
        let candidate = dir.join("Cargo.toml");
        if candidate.exists() {
            // Heuristic: workspace Cargo.toml contains [workspace]
            if let Ok(content) = fs::read_to_string(&candidate) {
                if content.contains("[workspace]") {
                    return dir.to_path_buf();
                }
            }
        }
        match dir.parent() {
            Some(p) => dir = p,
            None => break,
        }
    }
    // Fallback: assume manifest_dir/..
    manifest
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or(manifest)
}

fn main() {
    let ws_root = workspace_root();
    let src_dir = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("src");
    let rs_path = src_dir.join("embedded_agent.rs");

    // Search candidates relative to workspace root
    let env_candidate = env::var("RRA_AGENT_TEMPLATE").ok().map(|p| {
        let pb = PathBuf::from(&p);
        if pb.is_relative() { ws_root.join(&p) } else { pb }
    });
    let candidates: Vec<PathBuf> = vec![
        env_candidate,
        // Windows cross-compile target (release)
        Some(ws_root.join("target/x86_64-pc-windows-gnu/release/rust-remote-admin-agent.exe")),
        // Native Linux release
        Some(ws_root.join("target/release/rust-remote-admin-agent")),
        // Native release .exe (Windows host)
        Some(ws_root.join("target/release/rust-remote-admin-agent.exe")),
        // Debug targets
        Some(ws_root.join("target/x86_64-pc-windows-gnu/debug/rust-remote-admin-agent.exe")),
        Some(ws_root.join("target/debug/rust-remote-admin-agent")),
    ]
    .into_iter()
    .flatten()
    .collect();

    let found = candidates.into_iter().find(|p| p.exists());

    let content = if let Some(ref template_path) = found {
        let abs = template_path.canonicalize().unwrap_or_else(|_| template_path.clone());
        println!(
            "cargo:warning=Embedding agent template ({}) from {}",
            humansize(&abs),
            abs.display()
        );
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

fn humansize(path: &Path) -> String {
    fs::metadata(path)
        .ok()
        .map(|m| {
            let s = m.len();
            if s > 1024 * 1024 {
                format!("{:.1} MiB", s as f64 / (1024.0 * 1024.0))
            } else if s > 1024 {
                format!("{:.1} KiB", s as f64 / 1024.0)
            } else {
                format!("{s} B")
            }
        })
        .unwrap_or_default()
}
