# Silicon Recon

Fingerprint and classify internet-exposed LLM inference servers. Silicon Recon probes
host:port targets across a dozen common serving frameworks, inspects HTTP responses,
and returns a verdict for each endpoint: **GENUINE**, **IMPOSTOR**, **UNKNOWN**, or **DARK**.

It distinguishes real model-serving deployments (vLLM, llama.cpp, Ollama, SGLang, TGI,
etc.) from honeypots, impostor banners, and dead ports — then enriches live hits with
ASN/BGP data and PTR records.

- **Stdlib only.** No third-party dependencies. Runs on Python 3.9+.
- **Two interfaces.** A browser-based console and an agent-friendly CLI.
- **Async engine.** Thousands of concurrent sockets; raises its fd limit on startup.

---

## Quick start

```bash
# Web console (default http://127.0.0.1:7777)
python3 -m srecon serve

# Or run a scan straight from the command line
python3 -m srecon scan --pack hetzner --framework vllm
```

Both share the same scan engine and fingerprinting logic.

---

## Installation

No build step. Clone and run from the repo root:

```bash
git clone https://github.com/riceharvest/silicon-recon.git
cd silicon-recon
python3 -m srecon --help
```

Requires Python 3.9+. All functionality uses the standard library only.

> **Note on file descriptors.** The async engine holds many concurrent sockets and
> raises the process fd soft limit toward 65536 on startup. If your environment
> blocks `setrlimit`, start with `ulimit -n 65536` for maximum throughput.

---

## CLI

The CLI is the primary interface for AI agents and automation. All subcommands emit
machine-readable JSON unless stated otherwise.

```
python3 -m srecon <command> [options]

  scan         Run a scan against targets
  serve        Start the web console
  report       Render an offline report (HTML / Markdown / CSV / JSON)
  scans        List scan sessions (UTC times, verdict counts)
  diff         Compare two scan sessions' target rows (NEW / GONE / CHANGED)
  import       Ingest an offline Shodan/Censys export into the history DB
  packs        List cloud provider target packs
  frameworks   List known LLM serving frameworks and their ports
  prefixes     Resolve ASN(s) to announced IPv4 prefixes
  cidrs        Resolve a country code to IPv4 CIDR ranges
```

### `scan` — the main command

Targets can be combined from several sources:

```bash
# Explicit host:port targets (comma-separated)
python3 -m srecon scan --targets 1.2.3.4:8000,5.6.7.8:11434

# A whole cloud provider (resolves ASNs → prefixes → hosts)
python3 -m srecon scan --pack lambda

# Multiple packs at once
python3 -m srecon scan --pack hetzner,vultr --framework ollama

# Raw CIDR ranges
python3 -m srecon scan --cidrs 192.222.54.0/24,68.209.76.0/22

# Targets from a file (one host:port or CIDR per line)
python3 -m srecon scan --targets-file targets.txt
```

Common options:

| Option | Description |
|---|---|
| `-f, --framework` | Comma-separated framework filter (e.g. `vllm,llamacpp`) |
| `-w, --workers` | Concurrent workers (default 1000) |
| `--timeout` | Per-probe timeout in seconds (default 3.0) |
| `--sweep-all-ports` | Probe all known LLM ports, ignoring framework port narrowing |
| `--progressive` | TCP pre-sweep before deep HTTP probe (faster on large ranges) |
| `--enrich` / `--no-enrich` | ASN/BGP enrichment (on by default) |
| `--genuine-only` | Only show GENUINE results in the table |
| `--live-only` | Only show live (non-DARK) results |
| `--json` | Stream every event as NDJSON (machine-readable) |
| `-o, --output FILE` | Write full results JSON to a file |
| `-q, --quiet` | Suppress progress output |

### Machine-readable output for agents

`--json` streams the scan as NDJSON — one JSON object per line. Agents can pipe or parse
it incrementally:

```bash
python3 -m srecon scan --pack coreweave --framework vllm --json --quiet
```

Emitted event types:

- `{"type":"start", ...}` — scan parameters and resolved target count
- `{"type":"result", "data":{...}}` — one classified endpoint (see schema below)
- `{"type":"enrich", ...}` — ASN/BGP enrichment for a target
- `{"type":"ptr", ...}` — PTR record for a target
- `{"type":"log", ...}` — progress messages
- `{"type":"done", ...}` — final stats (`requests`, `elapsed_s`, `hosts_per_s`)
- `{"type":"summary", ...}` — terminal result count

Write full results to disk for downstream processing:

```bash
python3 -m srecon scan --pack lambda --framework vllm -o results.json
```

### Result schema

Each `result` event's `data` object:

```json
{
  "target": "192.222.55.177:8000",
  "verdict": "GENUINE",
  "product": "vllm",
  "version": "0.6.4",
  "model": "meta-llama/Llama-3.1-8B-Instruct",
  "models_served": ["meta-llama/Llama-3.1-8B-Instruct"],
  "score": 60,
  "latency_ms": 412,
  "flags": [],
  "asn": "398090",
  "as_name": "LAMBDA - Lambda",
  "bgp_prefix": "192.222.54.0/24",
  "net_type": "hosting",
  "ptr": null,
  "inventory_hash": "…"
}
```

### Helper subcommands

```bash
# List cloud packs and the ASNs behind them
python3 -m srecon packs

# List frameworks, their default ports, and probe paths
python3 -m srecon frameworks

# Resolve an ASN to its announced IPv4 prefixes (via RIPEstat)
python3 -m srecon prefixes --asn 24940 --limit 100

# Resolve a country to delegated IPv4 ranges (via RIR stats)
python3 -m srecon cidrs --cc DE --limit 64
```

### `scan` history: `scans`, `diff`, `import`

Every `scan` run records a session row in the history DB (`srecon/data/state.db`,
`scans` table) with start/finish UTC timestamps, target count, run params
(`params_json`) and verdict counts (`stats_json`). The `scans` command lists
them:

```bash
# All sessions, newest first (human table)
python3 -m srecon scans

# Only the 5 most recent, as NDJSON (one object per line)
python3 -m srecon scans --last 5 --json
```

`diff` compares two session IDs' target rows and groups them into **NEW**
(in B not A), **GONE** (in A not B) and **CHANGED** (same target, changed
verdict/product/model-set/version), with a summary count line. Changes are
detected from the rich columns now persisted (model, models_served, version,
verify_result, latency_ms, asn, …); when either row of a pair lacks model data
(a legacy row), the model-change is reported as `unknown` rather than false.

```bash
python3 -m srecon diff 1 2              # human grouped output
python3 -m srecon diff 1 2 --json       # machine-readable
```

> Note: the `targets` table persists only the last recorded row per `ip:port`
> (PRIMARY KEY, INSERT OR REPLACE), so two live sessions share a target only
> where the newer scan has not re-recorded it — CHANGED is thus detected across
> snapshots that both retained the target.

`import` ingests an exported Shodan (JSONL) or Censys (JSON/CSV) dataset without
probing — imported rows are always `UNKNOWN` verdict and tagged with an
`IMPORTED_*` flag. It wraps `srecon/imports.py` (whose standalone entry point
`python3 -m srecon.imports` keeps working):

```bash
python3 -m srecon import shodan.jsonl --format shodan --scan-id 3
python3 -m srecon import censys.csv --dry-run          # parse only, no DB write
```

### `report` — offline rendering

`report` renders results from a `scan -o` JSON file or directly from the
history DB. Full history (no source flags), a specific session, or a file:

```bash
python3 -m srecon report                      # full history, HTML (stdout)
python3 -m srecon report --scan-id 5 --format md -o report.md
python3 -m srecon report --input results.json --format csv
python3 -m srecon report --scan-id 5 --format json --scans
```

| Flag | Description |
|---|---|
| `-i, --input FILE` | Results JSON file as produced by `scan -o` |
| `--scan-id N` | Render the rows recorded for scan session N |
| `--format html\|md\|csv\|json` | Output format (default `html`) |
| `--scans` | Embed the scan-session list as a header section (params pretty-printed) in a DB report |
| `-o, --output FILE` | Write to FILE (default stdout) |

When the source rows carry the richer columns (model, version, verify_result,
latency_ms, asn, …), the report table includes them; the HTML report adds a
**Verify** badge column. `--format json` emits the full normalized result rows,
the summary, and (with `--scans`) the decoded scan-session list as a single JSON
document.

---

## Web console

```bash
python3 -m srecon serve --port 7777
```

The console provides an interactive scan builder (packs, frameworks, option presets),
a live NDJSON-driven results table, scan history, and export. It uses the same engine
as the CLI.

The legacy single-file entry point still works:

```bash
python3 silicon_recon.py --port 7777
```

---

## Supported frameworks

Frameworks match `FRAMEWORKS` in `srecon/config.py`:

| Framework | Default port(s) |
|---|---|
| vLLM | 8000, 8001 |
| llama.cpp server | 8080 |
| SGLang | 30000 |
| Ollama | 11434 |
| LM Studio | 1234 |
| KoboldCpp | 5001 |
| Text Generation WebUI | 5000, 7860 |
| Text Generation Inference (TGI) | 80, 3000 |
| Open WebUI | 3000 |
| Aphrodite Engine | 2242 |
| Triton Inference Server | 8000 |
| LocalAI | 8080 |
| Xinference | 9997 |
| LiteLLM | 4000 |
| TabbyAPI | 5000 |
| MLC-LLM | 8080 |

`--sweep-all-ports` probes every known LLM port regardless of the framework filter —
useful for discovery when you don't know what a host is running.

---

## Architecture

The codebase is organized as the `srecon` package:

```
srecon/
├── __init__.py     # package metadata
├── __main__.py     # CLI entry point (argparse subcommands)
├── config.py       # frameworks, ports, timeouts, score weights, paths
├── db.py           # SQLite state: scan cache, blocklist, history
├── net.py          # low-level HTTP/TCP probing, CT & Shodan seeds
├── probe.py        # per-host fingerprinting and classification logic
├── targets.py      # target expansion, CIDR/host resolution, excludes
├── asn.py          # ASN/BGP enrichment (RIPEstat, DNS TXT, RIR stats)
├── engine.py       # async scan engine + scan_events generator
├── packs.py        # cloud provider target packs (single source of truth)
├── serve.py        # fd-limit raise + web server bootstrap
└── web.py          # HTTP handler + embedded browser console

silicon_recon.py    # backward-compat launcher (delegates to srecon.serve)
```

**Data flow:** `__main__` / `web` → `engine.scan_events()` → `targets.expand_targets()`
→ async probe loop (`net` + `probe.analyze()`) → ASN enrichment (`asn`) → streamed
`result` events. State persists to `srecon/data/state.db`.

---

## Notes

- **Classification verdicts.** `GENUINE` = real model-serving endpoint confirmed by
  framework-specific markers. `IMPOSTOR` = mimics a framework but fails validation
  (likely honeypot). `UNKNOWN` = live HTTP but unrecognized. `DARK` = no response.
- **DoD ranges are excluded by default** to avoid scanning government space. Use
  `--include-dod` to override.
- **Enrichment** uses RIPEstat and DNS; no API keys required. Rate limits apply on
  very large scans.

---

## Local test lab

Consent-free, fully-offline testing of the whole pipeline. `lab/fixtures.py`
stands up fake vLLM / Ollama / llama.cpp / honeypot / auth-walled / bare-gateway
servers on `127.0.0.1`, and `python3 lab/run_lab.py` points a REAL
`python3 -m srecon scan --targets <the lab's own 127.0.0.1 ports> --verify` at
them, then renders the results back out of SQLite via `srecon report` — so
`engine → fingerprint → verify → db → report` is exercised end-to-end with zero
packets leaving the machine (ASN enrichment is disabled). It prints a PASS/FAIL
table of expected verdicts and exits non-zero on any mismatch.

```bash
# from the repo root
python3 lab/run_lab.py
```

The lab isolates the DB by swapping the real `srecon/data/` aside for a fresh
temp copy during the run and restoring it afterwards — the real `state.db` and
honeypot blocklist are never touched. See `lab/README.md` for what each fixture
proves, the run instructions, and how to add a new fixture.

> **Known issue (as of this writing):** the async scan engine currently marks
> every live host `ERROR` because `engine._Conn.get()` stores response-header
> keys as bytes and `probe._header_evidence()` crashes on them. `run_lab.py`
> detects this and prints the root cause; the lab's fixtures are independently
> verified via the sync probe path and classify exactly as the table expects.

---

## Legal

This tool is for authorized reconnaissance of infrastructure you own or have explicit
permission to test. Scanning third-party hosts without authorization may violate law
and the terms of service of cloud providers. Use responsibly.

---

## License

This repository is private. All rights reserved unless otherwise stated.
