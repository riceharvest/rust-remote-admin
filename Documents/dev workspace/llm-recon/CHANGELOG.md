# Changelog

All notable changes to the Silicon Recon project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- 11-fixture localhost test lab (vllm, ollama, llamacpp, honeypot, authwall, gateway, sglang, tgi, aphrodite, litellm, triton)
- Trend chart visualization for scan history
- Scan comparison view with NEW/GONE/CHANGED classification
- Verify result badges in results table
- Score reasons tooltips
- `ARCHITECTURE.md` documentation

## [0.4.0] - 2026-08-04

### Added
- Engine hardening: per-host overall deadline, adaptive timeout regrowth, verify worker pool, cooperative cancellation, engine error visibility
- Fingerprinting round 2: version extraction, model depth, inventory hash broadening, IMPOSSIBLE_INVENTORY refinement, honeypot heuristics (MISSING_SERVER_HEADER, IMPOSSIBLE_LATENCY, CANNED_BANNER)
- CLI `scans`, `diff`, `import` subcommands
- Report `--format json` and `--scans` mode
- 175 unit tests

### Changed
- Score normalization capped at 0-100
- `score_reasons` list added to results

### Fixed
- TGI detection (was misclassified as tgwui)
- Auth-wall detection now properly classified as UNKNOWN
- Frontend/backend combo suppression (openwebui+tgi, openwebui+vllm, litellm+ollama, openwebui+litellm)

## [0.3.0] - 2026-08-04

### Added
- Scan session lifecycle (`start_scan`, `finish_scan`, `get_scan`, `list_scans`)
- Shodan/Censys offline importer with freshness-aware dedup
- 6-fixture localhost test lab (vllm, ollama, llamacpp, honeypot, authwall, gateway)
- `--no-enrich` flag for zero-external-packet scans
- Database migration framework (PRAGMA user_version)
- Rich field persistence (model, version, verify_result, latency_ms, asn, etc.)
- WAL journal mode and busy_timeout
- Blocklist normalization (host:port → bare IP)

### Changed
- `report --scan-id` now uses scans table (falls back to rowid on legacy DBs)
- Web history hydrated from DB (survives restart)
- Framework chips injected server-side from `config.FRAMEWORKS`

### Fixed
- Header byte-string decoding bug (_Conn.get returned bytes keys, breaking detect_sigs)

## [0.2.0] - 2026-08-04

### Added
- 7 new frameworks: aphrodite, trtllm (triton), localai, xinference, litellm, tabbyapi, mlc
- Response header capture and sniffing (Server, x-*, vllm, litellm, x-mlc-llm)
- Generic `openai-compat` family (vLLM false-positive factory killed)
- Priority-based primary selection
- Frontend/backend combo suppression
- Database schema v2 (scans table, scan_id, rich columns, indexes, WAL)
- Web UI filters (flag, verify_result, score range)
- Richer free-text search (models_served, owned_by, ptr)
- PTR column in results table
- Response snippets in detail row
- Clickable fleet/ASN intel panels
- Pagination past 500-row cap
- 111 unit tests

### Changed
- `/v1/models` envelope now emits `openai-compat` (not vllm) unless vLLM-specific markers present
- `verify_inference` is now framework-aware (ollama/v1-completions/llamacpp/TGI)
- TGI detection uses `/v1/internal/model/info` (was misattributed to tgwui)

### Removed
- Stale 4-framework sub-header

## [0.1.0] - 2026-08-04

### Added
- Initial test suite (74 unittest tests, stdlib-only)
- Offline report generator (`report` subcommand: html/md/csv)
- Result schema with verify_result, score_reasons
- Framework-aware verification
- Generic `openai-compat` family
- 7 new framework fingerprints
- Response header capture
- Database schema v2 with migrations
- Web UI filters and pagination

### Fixed
- vLLM false-positive factory (bare `/v1/models` envelope no longer auto-classified as vllm)
- Header byte-string decoding bug
- TGI/tgwui detection swap

## [0.0.1] - 2026-07-31

### Added
- Initial workspace structure
- Retarget: reload live responders into target list for deep follow-up scans
- Heartbeat for silent scan phases
- 9 framework fingerprints (vllm, llamacpp, sglang, ollama, lmstudio, koboldcpp, tgwui, tgi, openwebui)
- SQLite state database
- NDJSON scan events
- Web console

[Unreleased]: https://github.com/riceharvest/silicon-recon/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/riceharvest/silicon-recon/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/riceharvest/silicon-recon/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/riceharvest/silicon-recon/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/riceharvest/silicon-recon/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/riceharvest/silicon-recon/releases/tag/v0.0.1
