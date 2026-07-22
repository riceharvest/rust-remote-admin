# Rust Remote Admin (RAT)

A remote administration tool built entirely in Rust, targeting Windows 10/11. The design separates the C2 Server (operator panel) from the Agent (implant), with an optional Relay Server for traffic redirection.

## Architecture

```
┌───────────────────┐       TLS (mTLS)        ┌───────────────────┐
│  C2 Server        │◄──────────────────────►│  Agent (Windows)  │
│ ┌───────────────┐ │                         │ ┌───────────────┐ │
│ │ GUI (Tauri)   │ │      ┌───────────┐      │ │ Core          │ │
│ │ - Dashboard   │ │      │  Relay    │      │ │ - Heartbeat   │ │
│ │ - i18n (8 lf) │ │      │  Server   │      │ │ - Command     │ │
│ │ - Live Logs   │ │      └─────┬─────┘      │ │   Dispatch    │ │
│ └──────┬────────┘ │            │            │ └──────┬────────┘ │
│        │          │            │            │        │          │
│ ┌──────▼────────┐ │            │            │ ┌──────▼────────┐ │
│ │ C2 Core       │ │◄───────────┘            │ │ Feature       │ │
│ │ - Listener    │ │                         │ │ Modules       │ │
│ │ - Client Mgr  │ │                         │ │ - Monitoring  │ │
│ │ - Plugins     │ │                         │ │ - Manager     │ │
│ └───────────────┘ │                         │ │ - Execution   │ │
└───────────────────┘                         │ └───────────────┘ │
                                              └───────────────────┘
```

## Project Layout

```
├── Cargo.toml          # Workspace root
├── c2/
│   ├── core/           # Listener, client pool, command queue
│   ├── gui/            # Tauri desktop app (dashboard)
│   ├── plugins/        # Operator-side plugins (cdylib)
│   └── relay/          # Standalone TCP/TLS relay binary
├── agent/
│   ├── core/           # Connection manager, dispatcher
│   ├── modules/        # Feature modules (process, file, registry, monitoring)
│   ├── hardening/      # Anti-debug, anti-vm, string obfuscation
│   ├── plugins/        # Agent-side plugin SDK
│   └── inject/         # Optional DLL injector stubs
├── protocol/           # Shared message types (serde-based)
├── crypto/             # TLS utilities, AES-GCM encryption
├── sdk/                # Plugin SDK shared crate
└── tools/              # Builder, stub generator
```

## Build

**Prerequisites:**
- Rust toolchain (nightly recommended for agent builds)
- For C2 GUI: Tauri system dependencies (see [tauri.app](https://tauri.app))

**Build all components:**
```sh
cargo build --release
```

**Build specific binaries:**
```sh
cargo build -p c2-core --release
cargo build -p agent-core --release
cargo build -p c2-relay --release
```

**Cross-compile agent for Windows from Linux:**
```sh
rustup target add x86_64-pc-windows-msvc
cargo build -p agent-core --target x86_64-pc-windows-msvc --release
```

## Communication

- **Transport**: Tokio-based TCP (async), multi-port binding
- **Encryption**: TLS 1.3 via rustls, mutual TLS (mTLS) for authentication
- **Payload**: AES-GCM encrypted messages inside the TLS stream (defense-in-depth)
- **Protocol**: Serde-based binary messages, typed and compressed

## Components

### C2 Server
Tauri desktop app with a reactive dashboard for managing agents. Features:
- Real-time agent status and live logs
- Internationalization (English, Chinese, Russian, Spanish, French, Turkish, Hindi, Vietnamese)
- Plugin host for custom operator commands
- Embedded relay server and reverse proxy

### Agent
Lightweight Windows service/process that executes commands. Features:
- Persistent TLS tunnel with automatic reconnection
- Modular design: each feature set is an independent module
- Process, file, and registry management
- Keylogging, hidden VNC, and remote shell capture
- String obfuscation and anti-debug/anti-vm hardening
- Multiple persistence mechanisms (service, scheduled task, WMI)

### Relay Server
Optional transparent TCP/TLS relay for hiding the C2 IP address and multiplexing connections.

## License

MIT
