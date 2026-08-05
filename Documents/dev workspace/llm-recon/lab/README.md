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
| `https-vllm` | vLLM over **HTTPS (TLS)** with self-signed cert: same `/version`, `/v1/models`, `/v1/completions` on 127.0.0.1 high port | `GENUINE` / `vllm` | `live` |
| `https-ollama` | Ollama over **HTTPS (TLS)** with self-signed cert: `/api/tags`, `/api/version`, `/api/generate` | `GENUINE` / `ollama` | `live` |
| `https-llamacpp` | llama.cpp over **HTTPS (TLS)** with self-signed cert: `/props`, `/health`, `/completion` | `GENUINE` / `llamacpp` | `live` |
| `https-vllm-expired` | vLLM over **HTTPS (TLS) serving an EXPIRED cert** (notAfter 2020-01-01) | `GENUINE` / `vllm` — still classified | `live` |

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

The harness additionally checks the **db → report round-trip**: after the scan,
it runs `srecon report --format md` and asserts every fixture's target and
verdict appear in the report rendered from SQLite.

## TLS fixtures and the expired-cert (CERT VARIANT) behaviour

All four `https-*` fixtures are plain `ThreadingHTTPServer`s whose socket is
wrapped with `ssl.SSLContext(PROTOCOL_TLS_SERVER)` and a **self-signed** cert
generated at fixture start via `openssl`. They bind **127.0.0.1 on high
ephemeral ports** (port 443 needs root), so the engine never sees a
`p == 443` TLS-first target. Instead they exercise the **TLS_FALLBACK path**:

1. the engine's plaintext connect to the TLS socket **succeeds** (TCP handshake);
2. the first HTTP exchange returns **zero responses** (the TLS server speaks TLS,
   not HTTP — the exchange fails at the byte level);
3. with `TLS_FALLBACK=True` and `HTTPS_ENABLED=True`, `probe_host()` closes the
   plaintext conns and **retries the whole exchange over an unverified TLS
   socket** (`verify_mode=CERT_NONE` because `TLS_VERIFY=False`);
4. the TLS round succeeds, the dossier carries the `TLS_FALLBACK` flag and a
   populated `tls` dict `{enabled, fingerprint_sha256, issuer, subject,
   not_after, self_signed}` captured from the peer certificate, and
   classification + inference verification proceed exactly as over plaintext
   (verify runs through `HTTPSConnection` with the same unverified context).

`run_lab.py` asserts on **every** TLS fixture: `tls.enabled` true,
`fingerprint_sha256` present, and the `TLS_FALLBACK` flag set — on top of the
normal `GENUINE`/product/`live` checks.

**Expired cert (https-vllm-expired):** the CERT VARIANT serves a certificate
whose validity window is `notBefore=2019-01-01`, `notAfter=2020-01-01` — years
in the past (baked in with `openssl req -x509 -not_before ... -not_after ...`;
`-days 0`/negative days are rejected by OpenSSL 3.x). Because the client
context is `CERT_NONE`, the TLS handshake **succeeds anyway**: an unverified
client never rejects the peer cert, so the server is still probed, classified
(`GENUINE`/`vllm`) and verified (`live`). The only observable difference is the
captured `tls.not_after` being in the past — which the lab asserts
(`not_after < now`). This pins the intended srecon behaviour: **reach and
fingerprint any TLS server even with a bad/expired certificate**, and surface
the cert validity in the result instead of dropping the host.

Observational note: the `https-ollama` fixture may carry the informational
`WEAK_OLLAMA` flag (`/api/tags` answered but no "Ollama is running" banner at
`/`, +15 score, below the IMPOSTOR threshold). Root cause: in the TLS-fallback
round the aux-path list was already filtered down by the failed plaintext
round, so the `/` banner is not re-probed over TLS. Verdict/verify are
unaffected (`GENUINE`/`ollama`/`live`); the flag is cosmetic.

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

`lab/fixtures.py` defines fifteen fixtures. Each is a `ThreadingHTTPServer`
(`HTTPSFixture` for the four TLS ones) bound to `127.0.0.1:0` (ephemeral port).
Every request is logged to the shared `REQUEST_LOG` as
`(fixture_name, method, path, status)`.

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
| `https-vllm` | `/version`, `/v1/models`, `/v1/completions` over **TLS** | `vllm/0.6.6` | openai |
| `https-ollama` | `/api/tags`, `/api/version`, `/api/generate` over **TLS** | — | ollama |
| `https-llamacpp` | `/props`, `/health`, `/completion` over **TLS** | — | llamacpp |
| `https-vllm-expired` | `/version`, `/v1/models`, `/v1/completions` over **TLS with an EXPIRED cert** | `vllm/0.6.6` | openai |

The HTTPS variants reuse the **exact same route tables** as their plaintext
counterparts (`_ollama_routes`, `_llamacpp_routes`, `_vllm_routes`), so a TLS
fixture differs from the plaintext one only in transport and (for the expired
variant) certificate validity.

### HTTPS fixture + self-signed cert handling

The TLS fixtures are implemented by `HTTPSFixture` in `lab/fixtures.py`, which:

1. generates a **self-signed certificate at fixture start** via the `openssl`
   command into a temp dir. The normal cert is
   `openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj /CN=127.0.0.1`;
   the **expired** variant instead passes
   `-not_before 20190101000000Z -not_after 20200101000000Z` (OpenSSL 3.x
   ASN1_UTCTIME args; `-days 0` is rejected as non-positive);
2. builds an `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)` and calls
   `ctx.load_cert_chain(certfile, keyfile)`;
3. wraps the `ThreadingHTTPServer` socket with `ctx.wrap_socket(server_side=True)`
   before `serve_forever()`.

Cert pairs are cached process-wide (`_CERT_CACHE` for the valid cert,
`_CERT_CACHE_EXPIRED` for the expired one) so every HTTPS fixture reuses one
cert of each kind. Port 443 cannot be bound unprivileged, so the fixtures bind
high ephemeral ports and are scanned as explicit `127.0.0.1:<port>` targets —
which is what exercises the engine's TLS_FALLBACK path.

**openssl dependency:** the lab needs `openssl` in `PATH` (it is not stdlib).
All other lab behaviour remains stdlib-only. If `openssl` is missing,
`start_all()` raises a clear `RuntimeError` — install it with your system
package manager (`dnf install openssl`, `apt install openssl`,
`brew install openssl`, ...).

Manual smoke-test of a TLS fixture (self-signed ⇒ skip verification):

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

The expired fixture behaves identically at the TLS layer: a `CERT_NONE` client
still completes the handshake. The difference only shows up in the captured
`tls.not_after` (2020-01-01, i.e. in the past), which `run_lab.py` asserts is
`< now`.

## How to add a fixture

1. In `lab/fixtures.py`, write a `_yourname_routes()` builder returning the
   route table (and a `default` if it should not be a plain 404).
2. Register it in `FIXTURE_SPECS` (the order there is the order fixtures start).
   For a TLS variant, also add the name to `HTTPS_NAMES` (and to
   `EXPIRED_CERT_NAMES` if it should serve the expired cert).
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

**ALL PASS** — all fifteen fixtures classify exactly as the table above expects,
including the four TLS fixtures and the expired-cert variant. The old
"engine lacks TLS support" FIXME is obsolete: Wave 7 landed TLS probing
(engine `_Conn` ssl param, `TLS_FALLBACK` retry, `tls` dict capture, and the
`--no-tls` CLI flag), and the earlier `_Conn.get()` bytes-header-keys crash is
fixed too (header keys are decoded to `str` before `detect_sigs()`).

Known spec deviations (srecon intentionally NOT modified — see the FINDINGS
block printed at the end of `run_lab.py`):

- `authwall` yields `verify='skipped'` instead of the spec's `'auth-walled'`
  (an all-401 server produces no status-200 JSON, so no sig → no verify schema).
- `triton` has no verify schema yet, so `verify='skipped'` is the expected
  current behaviour.
