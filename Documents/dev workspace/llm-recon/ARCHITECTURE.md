# Silicon Recon — Architecture

> **Pipeline overview** (ASCII flow from target sources to outputs)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SILICON RECON SCAN PIPELINE                         │
└─────────────────────────────────────────────────────────────────────────────┘

TARGET SOURCES
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ expand_targets()  ──►  [(ip, port), ...]  (deduped, excluded, capped)      │
│   • host / host:port / CIDR                                                 │
│   • --pack (ASN → RIPEstat prefixes → hosts)                               │
│   • --cidrs (raw CIDR ranges)                                              │
│   • --targets-file                                                         │
│   • CT / Shodan seed (optional)                                            │
│   • DoD excludes (default), user excludes, ASN prefilter (residential)     │
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ ASYNC ENGINE  (engine.py)                                                   │
│                                                                             │
│  run_async_engine()  ──►  scan_events generator                             │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ _Conn (per-host connection pool)                                    │   │
│  │   • asyncio.open_connection with reconnect retry                    │   │
│  │   • HTTP/1.1 GET with keep-alive                                    │   │
│  │   • Header decoding: latin-1 → str (lowercased keys)               │   │
│  │   • Body capped at 64 KiB; header map capped at 24 entries         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Concurrency control                                                 │   │
│  │   • Semaphore(workers) — bounds concurrent probe_host tasks         │   │
│  │   • VERIFY_WORKERS=32 — separate semaphore for 45s inference POSTs │   │
│  │   • live_conns registry — tracks sockets for cancel-time cleanup    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Timeouts & deadlines                                                │   │
│  │   • CONNECT_TIMEOUT = 1.0s (TCP preflight)                         │   │
│  │   • PROBE_TIMEOUT (default 3.0s) per I/O operation                 │   │
│  │   • _overall_deadline = timeout * max(4, len(paths)) — bounds the  │   │
│  │     entire probe_host exchange so one slow host can never stall    │   │
│  │     a worker slot indefinitely                                      │   │
│  │   • Adaptive timeout controller (_adaptive_timeout_step):          │   │
│  │     - Shrinks toward 3× P95 latency when samples ≥200              │   │
│  │     - Regrows toward original when P50 ≥ 50% of current or         │   │
│  │       timeout-share ≥ 25%                                           │   │
│  │     - Floor 1.0s, never exceeds original                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Verification pool (separate from scan workers)                      │   │
│  │   • Only runs on GENUINE/UNKNOWN verdicts                          │   │
│  │   • POST /v1/completions (OpenAI-compat), /api/generate (Ollama),  │   │
│  │     /completion (llama.cpp), /generate (TGI)                       │   │
│  │   • 45s VERIFY_TIMEOUT (cold-start model load)                     │   │
│  │   • Verdicts: live / auth-walled / honeypot / timeout / error      │   │
│  │   • On honeypot: flips verdict to IMPOSTOR, adds 50 to score       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ probe.analyze()  ──►  verdict, score, flags, evidence                      │
│   (srecon/probe.py)                                                         │
│                                                                             │
│  detect_sigs(endpoints) — framework fingerprinting:                        │
│    • vLLM: /version (v-prefixed semver), x-vllm header, root "vllm"        │
│    • Ollama: /api/tags (models list, :cloud suffix), /api/version          │
│    • llama.cpp: /props (REAL_LLAMACPP_MARKERS), build banner               │
│    • SGLang: /get_model_info, /get_server_info, x-sglang header            │
│    • TGI: /info, /v1/internal/model/info                                   │
│    • OpenAI-compat family: /v1/models envelope (data[].id + owned_by)      │
│       - vLLM when vLLM marker present & no other backend                   │
│       - custom-gateway when /version carries "model" field                 │
│       - openai-compat otherwise                                            │
│    • Triton: /v2/health/ready + /v2/models (no /v1 paths)                  │
│    • LiteLLM: /health/liveliness=LIVE, Server: litellm, mixed owned_by     │
│    • Aphrodite: /version app_name, /v1/models                              │
│    • LocalAI: /readyz=READY                                                │
│    • Xinference: /api/models model_uid, owned_by=xinference                │
│    • TabbyAPI: /v1/model_template, /v1/profile                             │
│    • MLC-LLM: x-mlc-llm header                                             │
│    • text-gen-webui: /api/v1/model, /run/predict (Gradio)                  │
│    • KoboldCpp: /api/extra/version, x-koboldcpp header                     │
│    • LM Studio: /api/v0/models                                             │
│    • Open WebUI: /api/config status=True + /api/version                    │
│                                                                             │
│  _header_evidence() — Server / x-* headers across all endpoints            │
│                                                                             │
│  Honeypot heuristics (round 2):                                            │
│    • MISSING_SERVER_HEADER: openai-compat with /v1/models 200 but no       │
│      identifying header and no /version pin                                │
│    • IMPOSSIBLE_LATENCY: <5ms model-listing from non-localhost             │
│    • CANNED_BANNER: root HTML <title> but all API paths 404 with           │
│      identical tiny body                                                   │
│                                                                             │
│  Scoring (SCORE_WEIGHTS):                                                  │
│    • FAKE_LLAMACPP=40, MULTI_PERSONA=35, IMPOSSIBLE_INVENTORY=40          │
│    • WEAK_OLLAMA=15, SUSPICIOUS_INVENTORY=10                               │
│    • Round-2 heuristics: MISSING_SERVER_HEADER=15,                         │
│      IMPOSSIBLE_LATENCY=30, CANNED_BANNER=20 (all <40, no single flip)    │
│    • Score capped at 100; ≥40 ⇒ IMPOSTOR                                   │
│    • score_reasons = list of fired weight keys                             │
│                                                                             │
│  Verdict logic:                                                            │
│    • 1 signature OR legit combo/stack ⇒ GENUINE (primary by SIG_PRIORITY)  │
│    • >1 signature, not legit ⇒ IMPOSTOR                                    │
│    • 0 signatures but live HTTP ⇒ UNKNOWN                                  │
│    • No HTTP response ⇒ DARK                                               │
│    • Engine exception ⇒ ERROR                                              │
│                                                                             │
│  Inventory hash (fleet clustering): SHA256(product|version|sorted_models)  │
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ DATABASE (srecon/db.py) — SQLite, schema v2 (PRAGMA user_version=2)        │
│                                                                             │
│  targets table (PRIMARY KEY ip, port — INSERT OR REPLACE):                 │
│    ip, port, verdict, product, score, scanned_at, fp,                      │
│    scan_id, model, models_served (JSON), version,                          │
│    verify_result, verify_detail, latency_ms,                               │
│    asn, as_name, bgp_prefix, net_type, error                               │
│    INDEX: idx_targets_scanned_at, idx_targets_scan_id                      │
│                                                                             │
│  scans table (scan session history):                                       │
│    scan_id (PK), started_at, finished_at, target_count,                    │
│    params_json, stats_json                                                 │
│                                                                             │
│  honeypot_fleets table (learned clusters):                                 │
│    inv_hash (PK), member_count, verdicts (JSON), first_seen, last_seen     │
│                                                                             │
│  Migrations:                                                                │
│    v1: base schema (targets, honeypot_fleets, fp column)                   │
│    v2: scans table + 12 dropped-field columns on targets + indexes         │
│                                                                             │
│  Blocklist (honeypot_blocklist.txt): bare IPs learned from                 │
│  IMPOSTOR fleets (majority ≥60% with score ≥40), auto-skipped on scans     │
└─────────────────────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ OUTPUTS                                                                     │
│                                                                             │
│  1. NDJSON event stream (engine.scan_events generator)                     │
│     • {"type":"start",  "total":N, "frameworks":[...], "ports":[...],      │
│       "scan_id":N, "workers":N, "fd_capped":bool, ...}                     │
│     • {"type":"result", "data":{...result schema...}}                      │
│     • {"type":"enrich", "target":"ip:port", "asn":"...",                   │
│       "as_name":"...", "bgp_prefix":"...", "net_type":"..."}               │
│     • {"type":"ptr",    "target":"ip:port", "ptr":"hostname"}              │
│     • {"type":"log",    "message":"...", "cls":"warn|error"}               │
│     • {"type":"probe",  "target":"ip:port", "path":"/...",                 │
│       "status":200, "err":null}  (debug, only with --json)                 │
│     • {"type":"engine_error", "target":"...", "exc_type":"...",            │
│       "message":"...", "count":N}  (unexpected engine bugs)                │
│     • {"type":"enrich_done"}  (internal marker)                            │
│     • {"type":"done",    "requests":N, "elapsed_s":X, "hosts_per_s":Y,    │
│       "scan_id":N}                                                          │
│     • {"type":"stopped", "done":N, "requests":N, "elapsed_s":X,           │
│       "hosts_per_s":Y, "scan_id":N}  (on cancel)                          │
│     • {"type":"summary", "scan_id":N, "total_results":N, "elapsed_s":X}   │
│                                                                             │
│  2. Web console (srecon/web.py) — browser UI at http://127.0.0.1:7777      │
│     • Interactive scan builder (packs, frameworks, options)                │
│     • Live results table (NDJSON-driven)                                   │
│     • Scan history, diff, export                                           │
│                                                                             │
│  3. Offline reports (srecon/report.py)                                     │
│     • HTML — self-contained dark theme, sortable table, verdict bars,      │
│       framework/ASN breakdown, scan-session header (--scans)               │
│     • Markdown — summary + tables                                          │
│     • CSV — header + one row per result (CSV_COLUMNS)                      │
│     • JSON — canonical _RESULT_COLUMNS + summary + optional scans          │
│     Sources: scan -o JSON file OR DB (--scan-id N or full history)         │
│                                                                             │
│  4. Offline import (srecon/imports.py + CLI `import`)                      │
│     • Shodan JSONL, Censys JSON, Censys CSV → DB (UNKNOWN verdict,        │
│       IMPORTED_* flag, never auto-GENUINE)                                 │
│     • Fresher existing rows are never overwritten                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## NDJSON Event Types (Complete Reference)

| Type | When Emitted | Key Fields |
|------|--------------|------------|
| `start` | Scan begins | `total`, `frameworks`, `ports`, `scan_id`, `workers`, `fd_capped`, `dedup_skipped`, `prefiltered`, `blocklisted`, `seeded`, `progressive_dropped`, `engine`, `profile` |
| `result` | Each classified endpoint | `data` (see Result Schema below) |
| `enrich` | ASN enrichment completes for a target | `target`, `asn`, `as_name`, `bgp_prefix`, `net_type` |
| `ptr` | PTR lookup completes | `target`, `ptr` |
| `log` | Progress / phase messages | `message`, `cls` (`warn`\|`error`) |
| `probe` | Individual HTTP request (debug) | `target`, `path`, `status`, `err` |
| `engine_error` | Unexpected engine exception (bug) | `target`, `exc_type`, `message`, `count` |
| `enrich_done` | Bulk ASN flush finished | *(internal, not streamed to CLI)* |
| `done` | Scan completes normally | `requests`, `elapsed_s`, `hosts_per_s`, `scan_id` |
| `stopped` | Scan cancelled | `done`, `requests`, `elapsed_s`, `hosts_per_s`, `scan_id` |
| `summary` | Final CLI summary line | `scan_id`, `total_results`, `elapsed_s` |

---

## Result Schema (Complete Field Reference)

Every `result` event's `data` object and every row persisted to `targets`:

```json
{
  "target": "192.222.55.177:8000",           // "ip:port"
  "verdict": "GENUINE",                      // GENUINE | IMPOSTOR | UNKNOWN | DARK | ERROR
  "product": "vllm",                         // framework name or "openai-compat" | "custom-gateway" | "unknown-http"
  "version": "0.6.6",                        // best-effort version string
  "model": "meta-llama/Llama-3.1-8B-Instruct", // primary model (first in models_served)
  "models_served": [                         // full model list (up to 20)
    "meta-llama/Llama-3.1-8B-Instruct"
  ],
  "score": 60,                               // suspicion score (0-100)
  "latency_ms": 412,                         // probe latency (ms)
  "flags": [                                 // human-readable evidence tags
    "FAKE_LLAMACPP",
    "MULTI_PERSONA: poses as vllm+ollama"
  ],
  "asn": "398090",                           // autonomous system number
  "as_name": "LAMBDA - Lambda",              // AS holder name
  "bgp_prefix": "192.222.54.0/24",           // announced prefix
  "net_type": "hosting",                     // hosting | residential | unknown
  "ptr": "gpu-123.lambda.cloud",             // reverse DNS
  "inventory_hash": "a1b2c3d4e5f67890",      // SHA256(product|version|models)[:16]
  "verify_result": "live",                   // live | auth-walled | honeypot | timeout | error | skipped
  "verify_detail": "model=...: Say hi...",   // verification detail string
  "error": null,                             // error message if DARK/ERROR
  "score_reasons": [                         // weight keys that fired
    "MULTI_PERSONA",
    "IMPOSSIBLE_LATENCY"
  ]
}
```

### Field Notes

- **verify_result**: Only populated when `--verify` flag is used. `skipped` means no verify schema for the detected product (e.g., Triton).
- **score_reasons**: The *keys* from `SCORE_WEIGHTS` that contributed to the score (not the full flag strings). Empty if score < 40.
- **inventory_hash**: Stable across runs; used for honeypot fleet learning and diff mode (`UNCHANGED` flag).
- **models_served**: JSON array in DB; decoded to list on load. Legacy rows (schema v0) lack this column — treated as `None`.

---

## Scans Table Lifecycle

```
scan_events() entry
       │
       ▼
start_scan(target_count=N, params_json={...})
       │  • INSERT INTO scans (started_at, target_count, params_json)
       │  • Returns scan_id (AUTOINCREMENT)
       ▼
yield {"type":"start", "scan_id":scan_id, ...}

       │          (for each live result)
       ▼
store_scan_result(dossier, scan_id=scan_id)
       │  • INSERT OR REPLACE INTO targets
       │    (ip,port,verdict,product,score,scanned_at,fp,scan_id,
       │     model,models_served,version,verify_result,verify_detail,
       │     latency_ms,asn,as_name,bgp_prefix,net_type,error)
       ▼

       │          (on scan finish / cancel / error)
       ▼
finish_scan(scan_id, stats={requests, elapsed_s, verdicts, status})
       │  • UPDATE scans SET finished_at=now, stats_json=... WHERE scan_id=?
       ▼
yield {"type":"done|stopped", "scan_id":scan_id, ...}
```

### Scan Session Queries

- `scans` CLI: `list_scans()` → all sessions, newest first (UTC timestamps, verdict counts from `stats_json`).
- `diff` CLI: `diff_scans(a, b)` → loads target rows via `load_db_results(scan_id)` (uses `targets.scan_id` column; falls back to `rowid` on legacy v0 DB).
- `report --scan-id N`: renders the rows linked to scan N.
- `report` (no source): full history, most recent first.

> **Note**: `targets` table uses `PRIMARY KEY (ip, port)` with `INSERT OR REPLACE`. Only the *last* scan that touched a given `ip:port` retains its row. Two live scans share a target only where the newer scan has not yet re-recorded it — `diff` detects `CHANGED` across such overlapping snapshots.

---

## Threat Model & Safety Notes

### Probe Discipline (GET-Only)

- **All active probes are HTTP GET requests.** No POST, PUT, DELETE, or state-changing verbs are used during the scan phase.
- The only POST is the optional **deep verification** (`--verify`), which sends a minimal `{"prompt":"Say hi","max_tokens":3}` to a confirmed live endpoint to distinguish real inference from stubs/honeypots. This is explicitly opt-in and runs under a separate bounded semaphore (`VERIFY_WORKERS=32`).

### DoD Exclusion (Default)

- The following US DoD /8 blocks are excluded by default (`DEFAULT_DOD_EXCLUDES`):
  ```
  6.0.0.0/8, 7.0.0.0/8, 11.0.0.0/8, 21.0.0.0/8, 22.0.0.0/8,
  26.0.0.0/8, 28.0.0.0/8, 29.0.0.0/8, 30.0.0.0/8, 33.0.0.0/8,
  55.0.0.0/8, 56.0.0.0/8, 214.0.0.0/8, 215.0.0.0/8
  ```
- Override with `--include-dod` (explicit opt-in required).

### Learned Honeypot Blocklist

- Persistent file: `srecon/data/honeypot_blocklist.txt` (bare IPs, one per line).
- Populated by `learn_honeypots()` when a fleet (≥3 members sharing an `inventory_hash`) has ≥60% `IMPOSTOR` verdicts with score ≥40.
- Loaded at scan start via `load_blocklist()` (normalizes any `host:port` lines to bare IPs in memory).
- Blocklisted targets are skipped entirely (no probe, no result row).

### User Excludes

- `--exclude CIDR` (repeatable) adds custom exclusion networks.
- Parsed via `targets.parse_excludes()` → `ipaddress.ip_network` objects.
- Applied during `expand_targets()` before any probe.

### ASN Residential Prefilter

- `--asn-prefilter` classifies each /24's ASN via bulk RIPEstat/RDAP lookup.
- Targets in `RESIDENTIAL` net_type ASNs are dropped before probing.
- Runs one bulk whois call per scan (batched 1000 IPs/socket).

### Cancellation & Resource Bounds

- `cancel` event (threading.Event) propagates to:
  - Engine thread: cancels pending `asyncio` tasks, closes `live_conns` sockets.
  - ASN flusher: aborts bulk whois on cancel.
  - Verification pool: respects cancel before each POST.
- `ENGINE_JOIN_TIMEOUT=20s` bounds the engine thread join; a hung `to_thread` (e.g., 45s verify) warns but does not block the caller.
- File descriptor limit raised toward 65536 on startup (`serve.raise_fd_limit()`); worker cap derived from `(soft - 256) // 4`.

---

## Module Map (srecon/ package)

| Module | Responsibility |
|--------|----------------|
| `__init__.py` | Package metadata |
| `__main__.py` | CLI entry point (argparse subcommands) |
| `config.py` | Frameworks, ports, timeouts, score weights, paths, constants |
| `db.py` | SQLite state: scans, targets, honeypot_fleets, migrations, blocklist |
| `engine.py` | Async scan engine, `scan_events` generator, `_Conn`, adaptive timeout, verify pool |
| `probe.py` | Fingerprinting (`detect_sigs`), classification (`analyze`), verification (`verify_inference`) |
| `targets.py` | Target expansion (CIDR/host), excludes, RIR/RIPEstat ASN resolution |
| `asn.py` | ASN/BGP enrichment (RIPEstat, DNS TXT, Team Cymru keywords) |
| `packs.py` | Cloud provider target packs (single source of truth) |
| `serve.py` | FD limit raise + web server bootstrap |
| `web.py` | HTTP handler + embedded browser console |
| `report.py` | Offline reports: HTML / Markdown / CSV / JSON, scan diff, scan history |
| `imports.py` | Offline Shodan/Censys ingestion (UNKNOWN verdict, IMPORTED_* flags) |
| `net.py` | Low-level HTTP/TCP, CT & Shodan seeds |
| `silicon_recon.py` | Backward-compat launcher (delegates to `srecon.serve`) |

### Test / Lab Infrastructure

| Path | Purpose |
|------|---------|
| `tests/` | 175 unit tests (config, db, imports, packs, probe, report, targets) |
| `lab/fixtures.py` | 11 fake LLM servers (vLLM, Ollama, llama.cpp, honeypot, authwall, gateway, SGLang, TGI, Aphrodite, LiteLLM, Triton) |
| `lab/run_lab.py` | End-to-end harness: starts fixtures → runs real `srecon scan --verify` → asserts verdicts/products/verify → renders `report --format md` from DB → PASS/FAIL table |

All tests pass (`python3 -m unittest discover -s tests` → 175 OK). Lab passes (`python3 lab/run_lab.py` → ALL PASS).