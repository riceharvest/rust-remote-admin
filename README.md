# Rust Remote Admin

A Rust research scaffold for authenticated remote-administration components.

This repository is a research/educational project implementing common remote-administration primitives. It is not a production system. All sensitive capabilities (injection, keylogging, capture, persistence, anti-analysis) are documented research examples with platform-specific code behind `#[cfg()]` attributes and stub returns where the platform crate is unavailable.

## Components

- `c2/core`: Client registry, per-client command queues, mTLS listener, heartbeat health tracking.
- `c2/gui`: Tauri v2 dashboard with client and log views.
- `c2/plugins`: Minimal operator-side plugin trait and echo example.
- `c2/relay`: Tokio TCP relay library with cleartext, TLS-ingress, and TLS-egress modes.
- `agent/core`: Command routing, heartbeat loop, exponential-backoff reconnection, mTLS/TLS/plain connection modes.
- `agent/modules`: Process listing/kill, file list/read/write, registry (Windows stub), sysinfo collection, remote command execution.
- `agent/hardening`: Anti-analysis detection, persistence, DLL injection, keylogging, webcam/mic capture, desktop capture (all research examples).
- `protocol`: Shared command and response types.
- `crypto`: AES-GCM payload encryption, mTLS session handling (cert loading, acceptor/connector builders, dev cert generation).

## Current status

Implemented and tested:

- Workspace manifest and local crate paths.
- FIFO command queues using `VecDeque`.
- Bidirectional relay copying with TLS relay modes.
- GUI client and log state updates.
- GUI `log-update` events with polling fallback.
- AES-GCM round trips, nonce uniqueness, wrong-key rejection, and tamper rejection.
- mTLS session handling with mutual authentication (rustls + tokio-rustls).
- Agent connection management: exponential-backoff reconnection, periodic heartbeats, C2-side health tracking (stale/disconnected thresholds).
- Process listing via `sysinfo`, process kill (Windows API), file list/read/write, sysinfo collection (CPU, memory, OS, kernel).
- Remote command execution via `std::process::Command` (`cmd /C` on Windows, `sh -c` on Linux).
- Anti-analysis detection: `IsDebuggerPresent`, ptrace `TracerPid`, timing-based debugger detection, VM detection (DMI vendor, CPU hypervisor flag, MAC OUI), sandbox detection (low CPU count, low memory, known analysis process names), XOR string obfuscation.
- Persistence mechanisms: systemd user services, crontab entries, autostart desktop entries (Linux); registry Run keys and scheduled tasks (Windows stubs).
- DLL injection research module: `CreateRemoteThread` + `LoadLibraryW` flow documented (Windows), ptrace-based injection notes (Linux).
- Keylogging research module: evdev `/dev/input/event*` reading with keycode-to-char mapping (Linux, root required), `SetWindowsHookEx(WH_KEYBOARD_LL)` outlined (Windows).
- Webcam and microphone capture: device enumeration via `/dev/video*` and `/dev/snd/` (Linux), V4L2/ALSA/Media Foundation/WASAPI capture flows documented in comments.
- Hidden desktop capture: display subsystem detection (X11/PipeWire/GDI/DXGI), `BitBlt`/`IDXGIOutputDuplication` flows documented, raw RGB24 frame saving.

## Build and test

The full workspace builds and tests with:

```sh
cargo check --workspace
cargo test --workspace
```

62 tests across all crates.

The GUI requires Tauri v2 Linux development dependencies: `webkit2gtk4.1-devel` (brings in `libsoup3-devel` and `javascriptcoregtk4.1-devel`). Install with:

```sh
sudo dnf install webkit2gtk4.1-devel
```

## Research documentation

The following capabilities are implemented as documented research/educational examples. They use platform-specific code behind `#[cfg()]` attributes and return stub errors where the platform crate is unavailable on the build host. Capture functions include full API flow documentation in comments but do not perform actual capture without the required platform crates (`x11rb`, `pipewire`, `alsa`, `windows`, etc.).

- `agent/hardening/src/persistence.rs` — systemd/crontab/autostart (Linux), registry Run keys/scheduled tasks (Windows stubs)
- `agent/hardening/src/injection.rs` — `CreateRemoteThread`+`LoadLibraryW` (Windows), ptrace injection (Linux)
- `agent/hardening/src/keylog.rs` — evdev input event reading (Linux, root required), `WH_KEYBOARD_LL` (Windows)
- `agent/hardening/src/capture.rs` — webcam via V4L2 (Linux) / Media Foundation (Windows), microphone via ALSA (Linux) / WASAPI (Windows)
- `agent/hardening/src/desktop_capture.rs` — X11/PipeWire (Linux), GDI `BitBlt` / DXGI Desktop Duplication (Windows)

## License

MIT. Use this scaffold only for lawful, authorized research and administration.
