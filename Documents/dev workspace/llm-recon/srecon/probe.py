"""Auto-split from silicon_recon.py. Stdlib only."""
import hashlib
import http.client
import json
import re
import socket
import time

from .config import (
    PROBE_TIMEOUT, CONNECT_TIMEOUT, PROBE_PATHS,
    SCORE_WEIGHTS, LEGIT_COMBOS, FRONTENDS, SIG_PRIORITY,
    REAL_LLAMACPP_MARKERS, PROPRIETARY_VENDORS,
    CLOUD_SUFFIX, VERIFY_TIMEOUT, VERIFY_PROMPT, VERIFY_MAX_TOKENS,
)

# frameworks whose OpenAI-compatible surface verifies via POST /v1/completions
OPENAI_COMPAT_VERIFY = frozenset({
    "vllm", "openai-compat", "custom-gateway", "litellm", "localai",
    "xinference", "tabbyapi", "mlc", "aphrodite", "lmstudio", "tgwui",
    "sglang",
})
# vLLM /version looks like "v0.6.6.post1" (v-prefixed dotted semver)
_VLLM_VERSION_RE = re.compile(r"^v?\d+\.\d+\.\d+(\.post\d+)?$")


def classify(host, port, probe_cb=None, timeout=PROBE_TIMEOUT, paths=None):
    """Probe one host:port. Returns a dossier dict.
    probe_cb(host, port, path, status, err) fires after every request."""
    paths = paths or PROBE_PATHS
    dossier = {
        "target": f"{host}:{port}",
        "product": "unknown",
        "verdict": "DARK",
        "version": None,
        "model": None,
        "models_served": [],
        "flags": [],
        "endpoints": {},
        "latency_ms": None,
        "error": None,
        "asn": None,
        "as_name": None,
        "bgp_prefix": None,
        "net_type": None,
        "score": 0,
        "inventory_hash": None,
        "verify_result": None,     # live / auth-walled / honeypot / timeout / error
        "verify_detail": None,
    }
    t0 = time.time()
    # TCP preflight: one cheap connect before any HTTP work
    try:
        _s = socket.create_connection((host, port), timeout=min(timeout, CONNECT_TIMEOUT))
        _s.close()
    except OSError as e:
        dossier["error"] = type(e).__name__
        dossier["latency_ms"] = round((time.time() - t0) * 1000)
        if probe_cb:
            probe_cb(host, port, "/", None, type(e).__name__)
        return dossier
    any_http = False
    conn = None
    for path in paths:
        status, js, body, err = None, None, "", None
        headers = {}
        for _attempt in range(2):  # retry once on a dropped keep-alive
            try:
                if conn is None:
                    conn = http.client.HTTPConnection(host, port, timeout=timeout)
                conn.request("GET", path, headers={"User-Agent": "silicon-recon/1.0"})
                resp = conn.getresponse()
                body = resp.read(65536).decode("utf-8", errors="replace")
                status = resp.status
                headers = {k.lower(): str(v) for k, v in resp.getheaders()[:24]}
                try:
                    js = json.loads(body)
                except json.JSONDecodeError:
                    js = None
                break
            except (http.client.HTTPException, OSError) as e:
                conn = None
                err = type(e).__name__
        if status is None:
            # connection-level failure: host is dead on this port, fail fast
            dossier["endpoints"][path] = {"status": None, "json": None, "raw": "", "headers": {}}
            dossier["error"] = err
            if probe_cb:
                probe_cb(host, port, path, None, err)
            break
        any_http = True
        dossier["endpoints"][path] = {
            "status": status, "json": js, "raw": str(body)[:512], "headers": headers}
        if probe_cb:
            probe_cb(host, port, path, status, None)
    if conn:
        try:
            conn.close()
        except OSError:
            pass
    dossier["latency_ms"] = round((time.time() - t0) * 1000)

    if not any_http:
        dossier["error"] = dossier["error"] or "no response"
        return dossier
    return analyze(dossier)


def _hdrs(ep, path):
    e = ep.get(path) or {}
    return e.get("headers") or {}


def _header_evidence(ep):
    """Framework hints from Server + x-* response headers across endpoints.
    Returns {framework: ["k: v", ...]}. Lowercased header values are sniffed
    for well-known server banners (x-vllm, litellm, x-mlc-llm, ...)."""
    ev = {}
    for path, e in ep.items():
        if not isinstance(e, dict):
            continue
        for k, v in (e.get("headers") or {}).items():
            kl = k.lower()
            if kl != "server" and not kl.startswith("x-"):
                continue
            vl = str(v).lower()
            for key, needle in (
                ("vllm", "vllm"), ("litellm", "litellm"), ("mlc", "mlc"),
                ("aphrodite", "aphrodite"), ("sglang", "sglang"),
                ("koboldcpp", "kobold"), ("tabbyapi", "tabby"),
                ("tgwui", "oobabooga"), ("tgwui", "text-generation-webui"),
            ):
                # match header key (e.g. x-mlc-llm: 1) or value (Server: vllm/0.6)
                if needle in kl or needle in vl:
                    ev.setdefault(key, []).append(f"{k}: {v}")
    return ev


def detect_sigs(ep):
    """Collect product-family signatures from a probed endpoint map."""

    def j(path):
        e = ep.get(path) or {}
        return e.get("json") if e.get("status") == 200 else None

    def raw(path):
        e = ep.get(path) or {}
        return e.get("raw") or ""

    hdr = _header_evidence(ep)
    sigs = {}  # product -> evidence dict

    ver = j("/version")
    v1 = j("/v1/models")

    # OpenAI-compatible envelope (/v1/models with id-bearing data entries).
    # Many backends serve it; treat it as generic until a specific framework
    # is pinned, and only claim vLLM when a vLLM-specific marker is present.
    env = None
    if isinstance(v1, dict) and isinstance(v1.get("data"), list):
        ids = [str(m.get("id")) for m in v1["data"]
               if isinstance(m, dict) and m.get("id")]
        if ids:
            env = {
                "ids": ids,
                "owners": {str(m.get("owned_by", "")).lower()
                           for m in v1["data"] if isinstance(m, dict)} - {""},
            }

    def backend_present():
        return any(s not in FRONTENDS for s in sigs)

    # --- collect one signature per product family ---
    tags = j("/api/tags")
    if isinstance(tags, dict) and isinstance(tags.get("models"), list):
        root_ok = "ollama" in raw("/").lower()
        # split local GGUF models from :cloud models (proxied via ollama.com)
        all_names = [m.get("name", "?") for m in tags["models"][:30] if isinstance(m, dict)]
        cloud_names = [n for n in all_names if n.endswith(CLOUD_SUFFIX)]
        local_names = [n for n in all_names if not n.endswith(CLOUD_SUFFIX)]
        # remote_host on a model entry confirms official ollama.com cloud routing
        remote_hosts = {
            m.get("remote_host") for m in tags["models"][:30]
            if isinstance(m, dict) and m.get("remote_host")
        }
        sigs["ollama"] = {
            "models": all_names,
            "cloud_models": cloud_names,
            "local_models": local_names,
            "remote_hosts": sorted(str(h) for h in remote_hosts),
            "root_banner": root_ok,
        }
    ov = j("/api/version")
    if "ollama" in sigs and isinstance(ov, dict) and ov.get("version"):
        sigs["ollama"]["version"] = str(ov["version"])

    mi = j("/get_model_info")
    if isinstance(mi, dict) and ("model_path" in mi or "tokenizer_path" in mi):
        sigs["sglang"] = {"model": mi.get("model_path")}
    elif "sglang" in hdr:
        sigs["sglang"] = {"evidence": "; ".join(hdr["sglang"])}
    si = j("/get_server_info")
    if "sglang" in sigs and isinstance(si, dict) and si.get("version"):
        sigs["sglang"]["version"] = str(si["version"])

    props = j("/props")
    if isinstance(props, dict) and (
        "model" in props or "model_path" in props or "default_generation_settings" in props
    ):
        real = any(k in props for k in REAL_LLAMACPP_MARKERS)
        sigs["llamacpp"] = {
            "model": props.get("model_path") or props.get("model"),
            "real_markers": real,
        }
        bi = props.get("build_info")
        if bi:
            sigs["llamacpp"]["version"] = str(bi)[:40]

    lms = j("/api/v0/models")
    if isinstance(lms, dict) and isinstance(lms.get("data"), list):
        sigs["lmstudio"] = {
            "models": [m.get("id", "?") for m in lms["data"][:30] if isinstance(m, dict)]
        }

    kv = j("/api/extra/version")
    if isinstance(kv, dict) and "kobold" in str(kv.get("result", "")).lower():
        sigs["koboldcpp"] = {"version": str(kv.get("version", "")) or None}
    elif "koboldcpp" in hdr:
        sigs["koboldcpp"] = {"evidence": "; ".join(hdr["koboldcpp"])}

    tgi_sig = {}
    tg = j("/info")
    if isinstance(tg, dict) and tg.get("model_id"):
        tgi_sig = {"model": tg["model_id"]}
        if tg.get("version"):
            tgi_sig["version"] = str(tg["version"])
    if not tgi_sig:
        tgi_info = j("/v1/internal/model/info")
        if isinstance(tgi_info, dict) and tgi_info.get("model_name"):
            tgi_sig = {"model": tgi_info["model_name"]}
            if tgi_info.get("version"):
                tgi_sig["version"] = str(tgi_info["version"])
    if tgi_sig:
        sigs["tgi"] = tgi_sig

    owc = j("/api/config")
    if (isinstance(owc, dict) and owc.get("status") is True
            and isinstance(ov, dict) and ov.get("version")):
        sigs["openwebui"] = {"version": str(ov["version"])}

    # TensorRT-LLM / Triton: /v2/health/ready + /v2/models — disjoint from the
    # OpenAI /v1 envelope, so it never collides with openai-compat/vllm.
    v2ready = ep.get("/v2/health/ready") or {}
    v2m = j("/v2/models")
    triton_sig = {}
    if isinstance(v2m, dict) and isinstance(v2m.get("models"), list):
        triton_sig["models"] = [
            str(m.get("name", m)) for m in v2m["models"][:30] if isinstance(m, dict)]
    if (v2ready.get("status") == 200 and "ready" in raw("/v2/health/ready").lower()
            or isinstance(v2m, dict) and isinstance(v2m.get("models"), list)):
        sigs["triton"] = triton_sig

    # Aphrodite Engine: /version reports a vLLM-style app_name.
    if isinstance(ver, dict) and "aphrodite" in str(ver.get("app_name", "")).lower():
        sig = {"version": ver.get("version") or ver.get("app_name")}
        if env:
            sig["models"] = env["ids"]
        sigs["aphrodite"] = sig
    elif "aphrodite" in hdr:
        sig = {"evidence": "; ".join(hdr["aphrodite"])}
        if env:
            sig["models"] = env["ids"]
        sigs["aphrodite"] = sig

    # LocalAI: /readyz returns READY.
    rz = ep.get("/readyz") or {}
    if rz.get("status") == 200 and "ready" in raw("/readyz").lower():
        sig = {}
        if isinstance(ver, dict) and ver.get("version"):
            sig["version"] = str(ver["version"])
        if env:
            sig["models"] = env["ids"]
        sigs["localai"] = sig

    # Xinference: /api/models entries carry model_uid; envelope owned_by xinference.
    xm = j("/api/models")
    xin_models = []
    if isinstance(xm, list):
        xin_models = [str(m["model_uid"]) for m in xm
                      if isinstance(m, dict) and m.get("model_uid")]
    elif isinstance(xm, dict) and isinstance(xm.get("models"), list):
        xin_models = [str(m["model_uid"]) for m in xm["models"]
                      if isinstance(m, dict) and m.get("model_uid")]
    if xin_models:
        sigs["xinference"] = {"models": xin_models[:30]}
    elif env and "xinference" in env["owners"]:
        sigs["xinference"] = {"models": env["ids"]}

    # LiteLLM proxy: /health/liveliness LIVE + /models list + Server/litellm.
    hl = ep.get("/health/liveliness") or {}
    live_ok = hl.get("status") == 200 and \
        str(hl.get("raw", "")).strip().upper() == "LIVE"
    litellm_sig = {}
    lm = j("/models")
    if isinstance(lm, list):
        litellm_sig["models"] = [str(m) for m in lm[:30]]
    elif isinstance(lm, dict) and isinstance(lm.get("data"), list):
        litellm_sig["models"] = [
            str(m.get("id", m)) for m in lm["data"][:30] if isinstance(m, dict)]
    if live_ok or "litellm" in hdr:
        sigs["litellm"] = litellm_sig

    # TabbyAPI: /v1/model_template, /v1/profile, or envelope owned_by tabby.
    tpl = j("/v1/model_template")
    prof = j("/v1/profile")
    tabby_sig = {}
    if isinstance(tpl, dict) and ("data" in tpl or "id" in tpl):
        d = tpl.get("data") if isinstance(tpl.get("data"), dict) else tpl
        if isinstance(d, dict) and d.get("id"):
            tabby_sig["model"] = str(d["id"])
    if (isinstance(tpl, dict) and ("data" in tpl or "id" in tpl)
            or isinstance(prof, dict) and "data" in prof
            or "tabbyapi" in hdr
            or env is not None and "tabby" in env["owners"]):
        sigs["tabbyapi"] = tabby_sig

    # MLC-LLM: pinned by x-mlc-llm header or a Server: MLC banner.
    if "mlc" in hdr:
        sig = {}
        if env:
            sig["models"] = env["ids"]
        sigs["mlc"] = sig

    # text-generation-webui: /api/v1/model, Gradio /run/predict, or banner.
    am = j("/api/v1/model")
    rp = ep.get("/run/predict") or {}
    tgwui_sig = {}
    if isinstance(am, dict) and ("model" in am or "model_name" in am):
        tgwui_sig["model"] = am.get("model") or am.get("model_name")
    if (tgwui_sig or rp.get("status") in (200, 405) or "tgwui" in hdr):
        sigs["tgwui"] = tgwui_sig

    # vLLM: the OpenAI envelope + a vLLM-specific marker (/version vLLM-style
    # version, x-vllm/Server header), and no conflicting backend identified.
    vllm_marker = (
        "vllm" in raw("/").lower()
        or "vllm" in hdr
        or (isinstance(ver, dict)
            and isinstance(ver.get("version"), str)
            and (_VLLM_VERSION_RE.match(ver["version"])
                 or "vllm" in ver["version"].lower()))
    )
    if (env and vllm_marker and "ollama" not in sigs
            and not backend_present()
            and not (isinstance(ver, dict) and ver.get("model"))):
        sigs["vllm"] = {
            "version": ver.get("version") if isinstance(ver, dict) else None}
        if "vllm" in hdr:
            sigs["vllm"]["evidence"] = "; ".join(hdr["vllm"])

    # Generic gateway: serves the OpenAI envelope but no specific backend is
    # identifiable. /version carrying a hand-copied "model" field marks it a
    # custom gateway; otherwise it is a bare openai-compat surface.
    if env and not backend_present():
        v1_ids = env["ids"]
        if isinstance(ver, dict) and ver.get("model"):
            sig = {"model": ver["model"], "models": v1_ids}
            if isinstance(ver.get("version"), str):
                sig["version"] = ver["version"]
            sigs["custom-gateway"] = sig
        else:
            sigs["openai-compat"] = {"models": v1_ids}

    return sigs


def _fetch_json(host, port, path, timeout):
    c = http.client.HTTPConnection(host, port, timeout=min(timeout, 5))
    c.request("GET", path)
    r = c.getresponse()
    body = r.read(65536).decode("utf-8", "replace")
    c.close()
    return json.loads(body)


def _verify_schema(sigs):
    """Map detected product sigs to an inference-verification request schema."""
    if "ollama" in sigs:
        return "ollama"
    if "llamacpp" in sigs:
        return "llamacpp"
    if "tgi" in sigs:
        return "tgi"
    if any(s in sigs for s in OPENAI_COMPAT_VERIFY):
        return "openai"
    return None


def _verify_request(schema, model):
    """Build (json_payload, post_path) for a schema + chosen model."""
    if schema == "ollama":
        return json.dumps({
            "model": model, "prompt": VERIFY_PROMPT, "stream": False,
            "options": {"num_predict": VERIFY_MAX_TOKENS},
        }), "/api/generate"
    if schema == "llamacpp":
        return json.dumps({
            "prompt": VERIFY_PROMPT, "n_predict": VERIFY_MAX_TOKENS,
            "stream": False,
        }), "/completion"
    if schema == "tgi":
        return json.dumps({
            "inputs": VERIFY_PROMPT,
            "parameters": {"max_new_tokens": VERIFY_MAX_TOKENS},
        }), "/generate"
    return json.dumps({
        "model": model, "prompt": VERIFY_PROMPT,
        "max_tokens": VERIFY_MAX_TOKENS, "stream": False,
    }), "/v1/completions"


def _verify_response(schema, d):
    """Return (response_text, is_empty_honeypot) for a parsed response body."""
    if schema == "ollama":
        text = d.get("response", "") if isinstance(d, dict) else ""
        if isinstance(d, dict) and d.get("done") and not str(text).strip():
            return "", True
        return str(text), False
    if schema == "llamacpp":
        if isinstance(d, dict) and "content" in d:
            text = str(d.get("content", ""))
            return text, not text.strip()
        return "", False
    if schema == "tgi":
        items = d if isinstance(d, list) else ([d] if isinstance(d, dict) else [])
        texts = [str(i.get("generated_text", "")) for i in items if isinstance(i, dict)]
        if texts:
            return texts[0], not any(t.strip() for t in texts)
        return "", False
    # openai /v1/completions
    if isinstance(d, dict) and isinstance(d.get("choices"), list) and d["choices"]:
        texts = []
        for ch in d["choices"]:
            if isinstance(ch, dict):
                texts.append(str(
                    ch.get("text")
                    or (ch.get("message") or {}).get("content") or ""))
        if texts:
            return texts[0], not any(t.strip() for t in texts)
    return "", False


def verify_inference(host, port, sigs=None, timeout=VERIFY_TIMEOUT):
    """POST a tiny generate request to confirm real inference (not a stub).
    Returns (verdict, detail) where verdict is one of:
      live / auth-walled / honeypot / timeout / error / skipped
    Dispatch is framework-aware: the request schema matches the detected
    product (ollama /api/generate, llamacpp /completion, tgi /generate,
    OpenAI-compat family /v1/completions). Unknown products are skipped.
    The smallest advertised model is used to minimise cold-start cost."""
    sigs = sigs or {}
    schema = _verify_schema(sigs)
    if schema is None:
        return "skipped", "no verify schema for product " + \
            ("+".join(sorted(sigs)) or "unknown")

    # choose the smallest advertised model to minimise cold-start cost
    model = None
    try:
        if schema == "ollama":
            tags = _fetch_json(host, port, "/api/tags", timeout)
            names = [m.get("name", "?") for m in tags.get("models", [])
                     if isinstance(m, dict)]
            # prefer a local model over a :cloud one — cloud just returns auth error
            local = [n for n in names if not n.endswith(CLOUD_SUFFIX)]
            pool = local or names
            if pool:
                model = min(pool, key=len)
        elif schema in ("openai", "llamacpp"):
            v1 = _fetch_json(host, port, "/v1/models", timeout)
            ids = [m.get("id") for m in v1.get("data", [])
                   if isinstance(m, dict) and m.get("id")]
            if ids:
                model = min((str(i) for i in ids), key=len)
        elif schema == "tgi":
            info = _fetch_json(host, port, "/info", timeout)
            mid = info.get("model_id") if isinstance(info, dict) else None
            model = str(mid) if mid else None
    except Exception:
        pass
    if not model:
        return "error", "no models advertised"

    payload, post_path = _verify_request(schema, model)
    try:
        c = http.client.HTTPConnection(host, port, timeout=timeout)
        c.request("POST", post_path, body=payload,
                  headers={"Content-Type": "application/json"})
        r = c.getresponse()
        body = r.read(65536).decode("utf-8", "replace")
        c.close()
    except (socket.timeout, OSError) as e:
        return "timeout", f"{type(e).__name__} after {timeout:.0f}s"
    except Exception as e:
        return "error", type(e).__name__
    try:
        d = json.loads(body)
    except json.JSONDecodeError:
        return "error", f"non-json response: {body[:120]}"
    # auth wall
    err = d.get("error") if isinstance(d, dict) else None
    if "unauthorized" in str(err).lower() or "signin_url" in body.lower():
        return "auth-walled", str(err or "auth required")
    # honeypot: canned empty response for the schema
    text, is_empty = _verify_response(schema, d)
    if is_empty:
        return "honeypot", f"canned empty {schema} response {body[:80]!r}"
    if text:
        return "live", f"model={model}: {text[:80]}"
    return "error", f"unexpected: {body[:120]}"


def analyze(dossier):
    """Verdict, flags, suspicion score, inventory hash from a probed dossier."""
    ep = dossier["endpoints"]
    sigs = detect_sigs(ep)

    # --- verdict logic ---
    flags = dossier["flags"]
    if "llamacpp" in sigs and not sigs["llamacpp"]["real_markers"]:
        flags.append(
            "FAKE_LLAMACPP: /props present but lacks "
            "default_generation_settings/total_slots/build_info/chat_template"
        )
    if "ollama" in sigs and not sigs["ollama"]["root_banner"]:
        flags.append("WEAK_OLLAMA: /api/tags answered but no 'Ollama is running' banner at /")
    # cloud routing: ollama :cloud models proxied through ollama.com (require auth)
    if "ollama" in sigs and sigs["ollama"].get("cloud_models"):
        n_cloud = len(sigs["ollama"]["cloud_models"])
        n_local = len(sigs["ollama"].get("local_models", []))
        if n_local == 0:
            flags.append(f"CLOUD_ONLY: all {n_cloud} models are :cloud proxied via ollama.com (auth required)")
        else:
            flags.append(f"CLOUD_MIX: {n_cloud} cloud + {n_local} local models")
    combo = frozenset(sigs)
    # a frontend proxying exactly one backend is a legitimate stack, not an
    # impostor posing as several products
    backends = [s for s in sigs if s not in FRONTENDS]
    legit_stack = len(backends) == 1 and len(sigs) > 1
    if len(sigs) > 1 and combo not in LEGIT_COMBOS and not legit_stack:
        flags.append("MULTI_PERSONA: poses as " + "+".join(sorted(sigs)))

    if len(sigs) == 1 or (len(sigs) > 1 and (combo in LEGIT_COMBOS or legit_stack)):
        # primary selection by priority: specific backends beat the generic
        # openai-compat/custom-gateway labels; frontends come last
        order = [s for s in SIG_PRIORITY if s in sigs] + \
                [s for s in sigs if s not in SIG_PRIORITY]
        dossier["product"] = "+".join(order)
        primary = sigs[order[0]]
        dossier["version"] = primary.get("version")
        dossier["model"] = primary.get("model")
        for name in order:
            if sigs[name].get("models"):
                dossier["models_served"] = sigs[name]["models"][:20]
                break
        dossier["verdict"] = "GENUINE"
    elif len(sigs) > 1:
        dossier["product"] = "+".join(sorted(sigs))
        dossier["verdict"] = "IMPOSTOR"
    else:
        dossier["product"] = "unknown-http"
        dossier["verdict"] = "UNKNOWN"

    # --- cross-checks on /v1/models ---
    v1_ids = []
    _e = ep.get("/v1/models") or {}
    models = _e.get("json") if _e.get("status") == 200 else None
    if isinstance(models, dict) and isinstance(models.get("data"), list):
        owners = set()
        for m in models["data"]:
            if isinstance(m, dict):
                v1_ids.append(m.get("id", "?"))
                owners.add(str(m.get("owned_by", "")).lower())
        dossier["models_served"] = dossier["models_served"] or v1_ids[:20]
        if dossier["model"] is None and v1_ids:
            dossier["model"] = v1_ids[0]
        proprietary = owners & PROPRIETARY_VENDORS
        if len(proprietary) >= 2:
            dossier["verdict"] = "IMPOSTOR"
            flags.append(
                "IMPOSSIBLE_INVENTORY: claims proprietary vendors "
                f"{sorted(proprietary)} on one box"
            )
        elif proprietary and len(sigs) >= 1:
            flags.append(f"SUSPICIOUS_INVENTORY: claims {sorted(proprietary)} ownership")

    # --- suspicion score ---
    score = 0
    for f in flags:
        score += SCORE_WEIGHTS.get(f.split(":", 1)[0], 0)
    dossier["score"] = min(100, score)  # cap/normalize at 100
    if score >= 40:
        dossier["verdict"] = "IMPOSTOR"

    # --- inventory fingerprint (fleet clustering) ---
    inv_ids = sorted(str(i) for i in v1_ids)
    inv_names = sorted(str(n) for n in sigs.get("ollama", {}).get("models", []))
    if inv_ids or inv_names:
        dossier["inventory_hash"] = hashlib.sha256(
            ("|".join(inv_ids) + "#" + "|".join(inv_names)).encode()
        ).hexdigest()[:16]

    return dossier