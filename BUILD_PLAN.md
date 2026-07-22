# Build Plan - rust-remote-admin

## Phase 1: Foundations ✅
- [x] Initialize Workspace & Repository structure. (`rust_remote_admin/` folder with workspace `Cargo.toml`)
- [x] Define Core Protobuf Messages (`protocol/src/lib.rs`).
- [x] Implement mTLS and Encryption primitives (`crypto/src/lib.rs`).

## Phase 2: C2 Infrastructure
- [ ] Build `c2/core`: Listener, Client Pool, Command Queue.
- [ ] Build `c2/relay`: Basic TCP forwarding logic.
- [ ] Build `c2/plugins`: Base SDK for operator plugins.

## Phase 3: Agent Development
- [ ] Build `agent/core`: Connection Manager & Dispatcher.
- [ ] Implement Module Group: Monitoring (Sysinfo, Keylogger).
- [ ] Implement Module Group: Manager (Process, File, Registry).
- [ ] Implement Module Group: Execution (Remote Command, DLL Injection).

## Phase 4: GUI & UX
- [ ] Build `c2/gui`: Tauri + Svelte/SolidJS Dashboard.
- [ ] Integrate Real-time Logs and Agent Status view.
- [ ] Implement i18n support for 8 languages.

## Phase 5: Polish & Hardening
- [ ] Add Anti-Debug / Anti-VM checks to `agent`.
- [ ] String Obfuscation pass.
- [ ] Final Documentation and Example Plugins.
