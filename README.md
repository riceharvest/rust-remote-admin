# Rust Remote Admin

A remote administration tool built entirely in Rust, targeting Windows 10/11.

## Features

- **C2 Server**: Tauri Desktop GUI for operators.
- **Agent**: Lightweight Windows implant with modular architecture.
- **Relay Server**: Optional TCP/TLS relay for traffic redirection and anonymity.

## Modules (Agent)

| Category   | Features                                      |
|------------|------------------------------------------------|
| Monitoring | Hidden VNC/RDP, Webcam, Microphone, Keylogger    |
| Manager    | Process, File, Registry, Network, Startup        |
| Execution  | Remote CMD, Reflective DLL Injection, Self-Update|

## Quick Start

```bash
# Build all crates
cargo build

# Run C2 server (Linux/macOS)
cargo run -p c2-core
```

## License

MIT (for educational/research purposes)