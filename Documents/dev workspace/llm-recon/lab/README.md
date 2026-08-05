# srecon Local Test Lab

A consent-free, fully-offline test lab for Silicon Recon. It stands up **fake LLM
servers on `127.0.0.1`** and runs the REAL `srecon` scan pipeline against them:

```
engine -> fingerprint (detect_sigs) -> verify (verify_inference) -> db (SQLite) -> report
```

Zero packets leave the machine:

- every fixture binds `127.0.0.1` only;
- the only targets ever scanned are the lab's own `127.0.0.1` fixture ports;
- ASN/BGP enrichment (which would hit RIPEstat/DNS) is disabled with `--no-enrich`;
- no `--pack` / `--cidrs` / seed flags are used.

## What it proves

| Fixture | What it fakes | Expected verdict | Expected verify |
|---|---|---|---|
| `vllm` | vLLM `/version` + OpenAI `/v1/models` envelope + `/v1/completions` | `GENUINE` / `vllm` | `live` |
| `ollama` | Ollama `/api/tags`, `/api/version`, `/api/generate` | `GENUINE` / `ollama` | `live` |
| `llamacpp` | llama.cpp `/props` (real markers) + `/completion` | `GENUINE` / `llamacpp` | `live` |
| `honeypot` | Ollama-lookalike that answers `/api/generate` with `done=true` and an **empty** response | `IMPOSTOR` (flipped by verify) | `honeypot` |
| `authwall` | `401` + sign-in HTML on every path | `UNKNOWN` | `skipped`* |
| `gateway` | Bare OpenAI-compat gateway: `/v1/models` only, generic `Server: nginx` | `GENUINE` / `openai-compat` — **NOT vllm** | `live` |
| `sglang` | SGLang `/get_model_info` (model_path), `/get_server_info`, `/version`, POST `/generate` | `GENUINE` / `sglang` | `live` |
| `tgi` | TGI `/info` (model_id+version), `/` router banner, POST `/generate` | `GENUINE` / `tgi` | `tgi` |
| `aphrodite` | Aphrodite Engine root JSON `app_name`, `/version`, `/v1/models` | `GENUINE` / `aphrodite` | `live` |
| `litellm` | LiteLLM proxy: `/health/liveliness`=LIVE, `/models`, `/v1/models` mixed owned_by (openai+anthropic), `Server: litellm` | `GENUINE` / `litellm` — **NOT IMPOSTOR** (PROXY_INVENTORY suppresses) | `live` |
| `triton` | Triton / TensorRT-LLM: `/v2/health/ready` 200, `/v2/models`, **no `/v1` paths** | `GENUINE` / `triton` | `skipped`† |
| `https-vllm` | vLLM over **HTTPS (TLS)** with self-signed cert: same `/version`, `/v1/models`, `/v1/completions` on 127.0.0.1 high port | `GENUINE` / `vllm` ‡ | `live` ‡ |

* **Spec note:** the parent spec asked for `verify=auth-walled` on the authwall
fixture. Current srecon cannot produce that for an all-401 server: status-200
JSON is required for signature detection, so no sig → verdict `UNKNOWN`, and
`verify_inference()` gets an empty sig set → no verify schema → `skipped`. The
`auth-walled` branch is only reachable when a GET-visible sig exists (e.g.
Ollama `:cloud` or a gateway that lists models publicly). See the FINDINGS block
printed by `run_lab.py`.

† **Note:** triton (TensorRT-LLM) has no verify schema defined in `_verify_schema()`
(currently only ollama, llamacpp, tgi, and OpenAI-compat families have one).
The fixture correctly expects `verify='skipped'`. If a verify schema is added
later, update `CHECKS['triton']` in `run_lab.py`.

‡ **FIXME:** `https-vllm` is a TLS fixture that serves valid vLLM routes over
HTTPS with a self-signed certificate. However, the srecon engine currently
**lacks TLS support**: `_Conn.open()` uses plain `asyncio.open_connection` with
no `ssl` parameter, and no `--tls`/`--no-tls` CLI flags exist. The fixture runs
and is reachable (testable with `curl -k` or Python `ssl`), but the scan will
yield `ERROR` or `DARK`. This is marked `FIXME` in `run_lab.py` and is **not
counted as a lab failure**. When the sibling TLS task lands (engine `_Conn ssl`
param + `--tls` flag), this fixture should classify `GENUINE`/`vllm` with
`verify=live` and TLS metadata flags (`self_signed`, `cert_valid`, etc.)
populated.

The harness additionally checks the **db → report round-trip**: after the scan,
it runs `srecon report --format md` and asserts every fixture's target and
verdict appear in the report rendered from SQLite.

## How to run

From the repo root:

```bash
python3 lab/run_lab.py
```

Requirements: Python 3.9+ (stdlib only, like srecon itself). The lab must be
started from the repo root so `python3 -m srecon` resolves.

### DB isolation (important)

`srecon/config.py` resolves `DATA_DIR`/`STATE_DB` from `__file__` at import time
with **no env or CLI override**, so scan/report subprocesses would write the
REAL `srecon/data/state.db`. The lab therefore:

1. moves the real `srecon/data/` aside (to a temp dir),
2. creates a fresh empty `srecon/data/`,
3. runs the scan + report against that,
4. deletes the fresh dir and restores the original in a `finally` block.

The real DB and honeypot blocklist are never touched. If the lab crashes hard
(kill -9), a stale `srecon_lab_db_backup_*` temp dir may remain — restore
manually if ever needed.

## Fixtures

`lab/fixtures.py` defines twelve fixtures. Each is a `ThreadingHTTPServer` bound to
`127.0.0.1:0` (ephemeral port). Every request is logged to the shared
`REQUEST_LOG` as `(fixture_name, method, path, status)`.

Routes are `(method, path) -> handler(post_body_bytes) -> (status, headers, body)`
tables with `("*", path)` / `(method, "*")` wildcards, plus a per-fixture
`default` route (e.g. the authwall's 401 HTML). `jresp()` is the JSON response
helper; `_read_model()` echoes the `model` field from POST bodies.

### Fixture list

| Name | Key endpoints | Server header | Verify schema |
|---|---|---|---|
| `vllm` | `/version`, `/v1/models`, `/v1/completions` | `vllm/0.6.6` | openai |
| `ollama` | `/api/tags`, `/api/version`, `/api/generate` | — | ollama |
| `llamacpp` | `/props`, `/health`, `/completion` | — | llamacpp |
| `honeypot` | `/api/tags` (fake), `/api/generate` (empty) | — | ollama → honeypot |
| `authwall` | *all paths* → 401 HTML | — | skipped |
| `gateway` | `/v1/models`, `/v1/completions` | `nginx` | openai |
| `sglang` | `/get_model_info`, `/get_server_info`, `/version`, `/generate` | `sglang/0.3.0` | openai |
| `tgi` | `/info`, `/v1/internal/model/info`, `/generate` | `tgi/2.0.0` | tgi |
| `aphrodite` | `/` (app_name), `/version`, `/v1/models`, `/v1/completions` | — | openai |
| `litellm` | `/health/liveliness`, `/models`, `/v1/models`, `/v1/completions` | `litellm` | openai |
| `triton` | `/v2/health/ready`, `/v2/models` (no `/v1/*`) | `triton/24.08` | skipped |
| `https-vllm` | `/version`, `/v1/models`, `/v1/completions` over **TLS** | `vllm/0.6.6` | openai (FIXME) |

### HTTPS fixture + self-signed cert handling

`https-vllm` is an **HTTPS variant of the vLLM fixture**: the exact same route
table, served over TLS on `127.0.0.1`. It is implemented by `HTTPSFixture` in
`lab/fixtures.py`, which:

1. generates a **self-signed certificate at fixture start** via the `openssl`
   command (`openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj
   /CN=127.0.0.1`) into a temp dir;
2. builds an `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)` and calls
   `ctx.load_cert_chain(certfile, keyfile)`;
3. wraps the `ThreadingHTTPServer` socket with `ctx.wrap_socket(server_side=True)`
   before `serve_forever()`.

The cert pair is cached process-wide (`_CERT_CACHE`) so every HTTPS fixture
reuses one cert. Port 443 cannot be bound unprivileged, so the fixture binds a
high ephemeral port and the scan target is set explicitly as
`127.0.0.1:<port>` — this is the target form that will exercise the engine's
TLS path (port-443-or-fallback) via the explicit target once TLS lands.

**openssl dependency:** the lab now needs `openssl` in `PATH` (it is not
stdlib). All other lab behaviour remains stdlib-only. If `openssl` is missing,
`start_all()` raises a clear `RuntimeError` — install it with your system
package manager (`dnf install openssl`, `apt install openssl`, `brew install
openssl`, ...).

Manual smoke-test of the TLS fixture (self-signed ⇒ skip verification):

```bash
python3 - <<'EOF'
import sys, ssl, urllib.request
sys.path.insert(0, "lab")
from fixtures import start_all, stop_all
fx = start_all()
try:
    f = [x for x in fx if x.name == "https-vllm"][0]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    print(urllib.request.urlopen(f"https://{f.target}/version", context=ctx).read())
finally:
    stop_all(fx)
EOF
```

**Current status (FIXME):** the srecon engine has no TLS support yet
(`_Conn.open()` uses plain `asyncio.open_connection`; no `--tls`/`--no-tls`
flags), so the scan currently classifies this fixture `ERROR`/`DARK`. The
assertion in `run_lab.py` is marked `FIXME` and does not fail the lab. The
moment the sibling TLS work lands, flip `CHECKS["https-vllm"]` to a real
assertion (`GENUINE` / `vllm` / `verify=live`, TLS flags present).

## How to add a fixture

1. In `lab/fixtures.py`, write a `_yourname_routes()` builder returning the
   route table (and a `default` if it should not be a plain 404).
2. Register it in `FIXTURE_SPECS` (the order there is the order fixtures start).
3. In `lab/run_lab.py`, add an entry to `CHECKS`:
   `"yourname": (expected_verdict, product_substr, forbidden_product_substr, expected_verify)`.
4. (Optional) bump `VERDICT_COUNTS_REPORT` if the report-level verdict counts
   change.
5. Run `python3 lab/run_lab.py` and confirm the new row passes.

Sanity-check a fixture in isolation (sync probe path, useful when the async
engine is broken):

```bash
python3 - <<'EOF'
import sys; sys.path.insert(0, "lab")
from fixtures import start_all, stop_all
from srecon import probe
fx = start_all()
try:
    f = [x for x in fx if x.name == "ollama"][0]
    d = probe.classify("127.0.0.1", f.port)
    print(d["verdict"], d["product"], probe.verify_inference("127.0.0.1", f.port, probe.detect_sigs(d["endpoints"])))
finally:
    stop_all(fx)
EOF
```

## Current status

**BLOCKED by a real srecon bug** (reported to parent, srecon intentionally NOT
modified):

`srecon/engine.py` `_Conn.get()` builds the response `headers` dict with **bytes
keys/values** (it never decodes the header lines), and `srecon/probe.py`
`_header_evidence()` (line 123) runs `kl.startswith("x-")` on that bytes key →
`TypeError` → `detect_sigs()` throws for **every live host** → the async scan
engine marks every live target `ERROR`. The sync `probe.classify()` path (used
by tests) is unaffected. Fixture-side behaviour is fully validated via the sync
path: all six fixtures classify exactly as the table above expects, so the lab
should go green the moment the engine decodes header keys to `str`.
