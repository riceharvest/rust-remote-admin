# Rust Remote Admin

A Rust research scaffold for authenticated remote-management components.

This repository is not a production remote-administration system. Agent operations that could access files, processes, registries, system information, or execute code are intentionally disabled until they have a documented design, authorization model, and platform-specific implementation.

## Components

- `c2/core`: Client registry and per-client command queues.
- `c2/gui`: Tauri dashboard with client and log views.
- `c2/plugins`: Minimal operator-side plugin trait and echo example.
- `c2/relay`: Tokio TCP relay library.
- `agent/core`: Command routing and heartbeat scaffold.
- `agent/modules`: Explicit failure responses for unsupported agent operations.
- `agent/hardening`: Placeholder capability checks. It does not provide stealth or evasion.
- `protocol`: Shared command and response types.
- `crypto`: AES-GCM payload encryption with a fresh nonce per message and typed errors.

## Current status

Implemented and tested:

- Workspace manifest and local crate paths.
- FIFO command queues using `VecDeque`.
- Bidirectional relay copying.
- GUI client and log state updates.
- GUI `log-update` events with polling fallback.
- AES-GCM round trips, nonce uniqueness, wrong-key rejection, and tamper rejection.
- Truthful failure responses for unsupported agent operations.

Not implemented:

- mTLS session handling.
- Agent connection management.
- Process, file, registry, or system-information collection.
- Remote command execution.
- DLL injection, persistence, keylogging, webcam, microphone, hidden desktop capture, or anti-analysis behavior.

## Build and test

The full workspace builds and tests with:

```sh
cargo check --workspace
cargo test --workspace
```

The GUI requires Tauri v2 Linux development dependencies: `webkit2gtk4.1-devel` (brings in `libsoup3-devel` and `javascriptcoregtk4.1-devel`). Install with:

```sh
sudo dnf install webkit2gtk4.1-devel
```

## License

MIT. Use this scaffold only for lawful, authorized research and administration.
