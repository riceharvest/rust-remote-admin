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

The non-GUI workspace can be checked and tested with:

```sh
cargo check --workspace --exclude c2-gui
cargo test --workspace --exclude c2-gui
```

The GUI requires the Tauri v1 Linux development dependencies, including GTK/WebKitGTK and `libsoup-2.4`. After installing those system packages, run:

```sh
cargo check -p c2-gui
cargo test -p c2-gui
```

## License

MIT. Use this scaffold only for lawful, authorized research and administration.
