# Rust Remote Admin

Enterprise remote system administration framework with mTLS-secured agent management, endpoint inventory, and secure command dispatch. Designed for authorised infrastructure monitoring and management.

All operations require explicit consent from the system owner and are scoped to user-level permissions.

## Binaries

Two shipped artifacts per platform:

| Component | Purpose |
|-----------|---------|
| `rust-remote-admin-c2` | Management server: listens for agents, queues commands, tracks health, generates agent binaries |
| `rust-remote-admin-agent` | Pre-compiled template for `generate-agent` command — not a standalone release artifact |

The agent binary is not a standalone executable. It ships as a template and the C2 patches it with connection details at generation time. This ensures every deployed agent knows where to connect without config files or CLI arguments.

Download both from [GitHub Releases](https://github.com/riceharvest/rust-remote-admin/releases).

### Using the C2

```sh
# 1. Start the C2 server
rust-remote-admin-c2 server 0.0.0.0:9000

# 2. (in another terminal) Generate a single configured agent
rust-remote-admin-c2 generate-agent \
  --c2-address 192.168.1.100:9000 \
  --cert-fingerprint sha256:abc123... \
  --agent-id 1 \
  --output client.exe

# (--template is optional — defaults to embedded template, use to override)
#   --template custom-agent.exe

# 3. Batch generation: 10 agents with sequential IDs
rust-remote-admin-c2 generate-agent \
  --c2-address 10.0.0.1:9000 \
  --cert-fingerprint sha256:abc123... \
  --agent-id 100 \
  --count 10 \
  --output agent.exe
# Produces: agent-100.exe, agent-101.exe, ..., agent-109.exe

# 4. mTLS: embed client certificate paths
rust-remote-admin-c2 generate-agent \
  --c2-address 10.0.0.1:9000 \
  --cert-fingerprint sha256:abc123... \
  --agent-id 50 \
  --cert-path /etc/client.pem \
  --key-path /etc/client.key \
  --output agent-golden.exe

# 5. Deploy the generated agent on the target machine
#    It connects to the C2 and waits for commands

# 6. Verify template integrity
rust-remote-admin-c2 generate-agent --hash-template
```

**How it works:**
- A pre-compiled agent template is embedded in the C2 binary at build time
- The template has a `RRA_CONFIG_V1` marker in its data section
- `generate-agent` (without `--template`) uses the embedded template, locates the marker, and writes JSON config (C2 address, TLS fingerprint, agent ID, heartbeat interval) into the 512-byte config slot
- The resulting binary is standalone — the agent reads its own binary at startup, finds the marker, and parses the config
- Falls back to CLI args or defaults if no embedded config is present
- Use `--template <path>` to override with an external binary

### Release artifacts

Download `rust-remote-admin-c2` (or `rust-remote-admin-c2.exe` for Windows) from [GitHub Releases](https://github.com/riceharvest/rust-remote-admin/releases). That single binary is all you need — the agent template is already inside it.

The agent template is also published as a build artifact for inspection or override, but you do not need to download it separately.

## Crates

| Crate | Role |
|-------|------|
| `c2/core` | Client registry, per-client command queues, mTLS listener, heartbeat health tracking, agent generator CLI |
| `c2/generator` | Libraries for patching connection config into template agent binaries |
| `c2/gui` | Tauri v2 dashboard (client list, logs, live events, agent generation form) |
| `c2/plugins` | Operator-side plugin trait with echo example |
| `c2/relay` | Tokio TCP relay — cleartext, TLS-ingress, TLS-egress forwarding |
| `agent/core` | Command routing, heartbeat loop, exponential-backoff reconnect, mTLS/TLS/plain modes, embedded config reader, **self-update**, **state persistence**, **runtime config (TOML/env/hot-reload)**, **structured audit logging** |
| `agent/modules` | Process listing, file I/O with path validation, registry access, sysinfo, remote command execution with whitelist |
| `agent/hardening` | Passive endpoint security monitoring (debugger detection, VM/platform detection, sandbox detection) |
| `protocol` | Shared command/response types, config marker and AgentConfig serialization |
| `crypto` | AES-GCM payload encryption with random nonces, **KeyManager (HKDF-SHA256)**, mTLS session handling (cert loading, acceptor/connector builders, dev cert generation) |

## Config marker format

The `RRA_CONFIG_V1` marker occupies 512 bytes in the agent binary:

```
Offset  0: "RRA_CONFIG_V1"  (13 bytes, magic marker)
Offset 13: <u32 LE length>  (4 bytes, JSON payload length)
Offset 17: <JSON payload>   (up to 495 bytes of AgentConfig)
Remainder: <zero padding>   (filled to 512 bytes total)
```

The agent scans its own executable at startup for the marker. The C2 generator finds the same marker and replaces the block.

## Security and access control

- All remote command execution is subject to a **command whitelist** — only registered safe commands (`echo`, `ls`, `cat`, `df`, `ps`, `uptime`, `whoami`, `uname`, `ip`, `ss`, `ping`, `systemctl status`, `journalctl`, `free`, `du`, `date`, `id`) are accepted. Network-capable commands (`curl`, `wget`) are explicitly excluded.
- File operations are restricted to allowed directories (`/tmp`, `/home`, `/var/tmp`).
- Process management only supports listing — termination is platform-restricted (Windows FFI with safety documentation) and documented as such.
- All communication can be encrypted with TLS or mutual TLS.
- Payload encryption uses AES-GCM with **random nonces** per operation.
- **KeyManager** derives AES-128-GCM keys via HKDF-SHA256 from password + salt; hardcoded test key isolated to test module only.
- **Structured audit logging** (JSONL) with 17 event types, 4 severity levels, async buffered writer, file rotation, and severity filtering.

## Security boundary

This project is intended for **lawful, authorised administration of systems you own or have written permission to manage**. It is not a penetration testing tool or remote access trojan. The agent does not perform any active evasion, surveillance, data exfiltration, privilege escalation, or persistence without explicit operator configuration.

## Build

```sh
cargo check --workspace
cargo test --workspace
```

### Cross-compile Windows executables

```sh
rustup target add x86_64-pc-windows-gnu
sudo dnf install mingw64-gcc mingw64-winpthreads-static   # Fedora

# Build C2 + agent template
cargo build --release --target x86_64-pc-windows-gnu -p c2-core -p agent-core
```

Produces standalone `.exe` files with `+crt-static` — no external DLLs required.

### GUI (Tauri v2)

```sh
sudo dnf install webkit2gtk4.1-devel   # Linux dev deps
cargo build -p c2-gui
```

## Implementation status

### Done (v0.1.0 → v0.3.0)

#### Core functionality
- ✅ Process listing, file I/O with path validation, sysinfo reporting
- ✅ Config marker (`RRA_CONFIG_V1`) embedded in agent binary at build time
- ✅ Agent scans own executable for config at startup
- ✅ `c2-generator` crate patches template binaries with connection config
- ✅ CLI `generate-agent` subcommand with `--template`, `--c2-address`, `--cert-fingerprint`, `--agent-id`, `--hash-template`
- ✅ Release workflow builds 2 artifacts per platform (C2 + agent template)
- ✅ Relay with cleartext, TLS-ingress, and TLS-egress modes
- ✅ Agent template embedded directly in C2 binary — `--template` is optional
- ✅ mTLS cert/key paths can be embedded in agent config (`--cert-path`, `--key-path`)
- ✅ Batch `generate-agent` mode (`--count N` generates sequential agents)
- ✅ Integration tests for generator (marker detection, single/batch, mTLS fields)
- ✅ Web UI for agent generation in Tauri GUI (generate_agent command + form)
- ✅ Command execution whitelist for remote scripting
- ✅ Passive endpoint security monitoring (debugger, VM, sandbox detection)
- ✅ AES-GCM encryption with random nonces

#### Production readiness (v0.2.0 → v0.3.0)
- ✅ **Agent self-update mechanism** — `SelfUpdate` command with URL + expected SHA256, HTTP download, hash verification, atomic binary replacement, Unix executable bit preservation
- ✅ **State persistence** — `AgentState` / `C2State` / `StateManager` with JSON serialization to `~/.config/rust-remote-admin/state/`; survives restarts
- ✅ **Runtime configuration** — TOML config file + `RRA_*` environment variable overrides + file-watching hot-reload + validation
- ✅ **Structured audit logging** — `AuditLogger` with 17 event types, 4 severity levels, JSONL output, async buffered writer, file rotation, severity filtering, global singleton
- ✅ **Key management** — `KeyManager` with `new(key)` and `from_password(password, salt)` (HKDF-SHA256); hardcoded test key `[0x11; 16]` moved to `#[cfg(test)]` only
- ✅ **Whitelist hardening** — removed `curl` and `wget` from execution whitelist to prevent network exfiltration
- ✅ **Windows kill_process safety** — FFI `TerminateProcess` documented with `// SAFETY` comments; `kill_process_available()` public API
- ✅ **C2 relay tests** — 4 tests covering Cleartext, TLS, and forwarding
- ✅ **CI pipeline** — `.github/workflows/ci.yml` runs `cargo check`, `cargo test`, `cargo clippy --no-deps` on push/PR
- ✅ **C2 GUI connection UI** — server address input, connect button, status indicator, prototype notice banner

### Next
- ⬜ Windows tests for generated agent config loading
- ⬜ Windows agent self-update integration test
- ⬜ Tauri GUI: live agent monitoring + command dispatch

## License

MIT.