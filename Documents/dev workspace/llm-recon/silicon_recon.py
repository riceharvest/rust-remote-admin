#!/usr/bin/env python3
"""
SILICON RECON - Vault7-style LLM server fingerprinter.
Stdlib only. Serves a classified-console web UI and probes targets
for vLLM / SGLang / llama.cpp / Ollama signatures, with honeypot detection.

Usage: python3 silicon_recon.py [--port 7777]
Then open http://127.0.0.1:7777
"""

import argparse
import asyncio
import hashlib
import http.client
import ipaddress
import json
import os
import queue
import random
import resource
import socket
import sqlite3
import struct
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROBE_PATHS = [
    "/",
    "/props", "/health",                    # llama.cpp
    "/version", "/v1/models",               # vLLM
    "/get_model_info", "/get_server_info",  # SGLang
    "/api/tags", "/api/version",            # Ollama
    "/api/v0/models",                       # LM Studio
    "/api/extra/version", "/api/v1/model",  # KoboldCpp
    "/v1/internal/model/info",              # text-generation-webui
    "/info",                                # TGI
    "/api/config",                          # Open WebUI
]
# per-framework probe paths and default ports (union is used when several are selected)
FRAMEWORKS = {
    "vllm": {"paths": ["/", "/version", "/v1/models"], "ports": [8000, 8001]},
    "llamacpp": {"paths": ["/", "/props", "/health", "/v1/models"], "ports": [8080]},
    "sglang": {"paths": ["/", "/get_model_info", "/get_server_info", "/v1/models"], "ports": [30000]},
    "ollama": {"paths": ["/", "/api/tags", "/api/version", "/v1/models"], "ports": [11434]},
    "lmstudio": {"paths": ["/", "/api/v0/models", "/v1/models"], "ports": [1234]},
    "koboldcpp": {"paths": ["/", "/api/extra/version", "/api/v1/model"], "ports": [5001]},
    "tgwui": {"paths": ["/", "/v1/internal/model/info", "/v1/models"], "ports": [5000]},
    "tgi": {"paths": ["/", "/info"], "ports": [80, 3000]},
    "openwebui": {"paths": ["/", "/api/version", "/api/config"], "ports": [3000]},
}
DEFAULT_PORTS = sorted({p for f in FRAMEWORKS.values() for p in f["ports"]})
CONNECT_TIMEOUT = 1.0  # TCP preflight before any HTTP work
# suspicion scoring: verdict IMPOSTOR at >= 40
SCORE_WEIGHTS = {
    "FAKE_LLAMACPP": 40,
    "MULTI_PERSONA": 35,
    "IMPOSSIBLE_INVENTORY": 40,
    "WEAK_OLLAMA": 15,
    "SUSPICIOUS_INVENTORY": 10,
}
# signature combinations that are common legitimate stacks, not impostors
LEGIT_COMBOS = {frozenset({"openwebui", "ollama"})}
# AS-name keyword lists for net-type classification (Team Cymru enrichment)
DC_KEYWORDS = [
    "choopa", "vultr", "digitalocean", "hetzner", "ovh", "amazon", "aws",
    "google", "microsoft", "azure", "linode", "akamai", "contabo", "oracle",
    "alibaba", "tencent", "leaseweb", "scaleway", "kamatera", "ionos",
    "datacamp", "m247", "hostinger", "rackspace", "equinix", "psychz",
    "sharktech", "buyvm", "frantech", "cloudflare", "fastly", "gcore",
    "g-core", "servers.com", "hostwinds", "interserver", "netcup", "aruba",
]
RES_KEYWORDS = [
    "comcast", "verizon", "at&t", "charter", "spectrum", "cox", "optimum",
    "frontier", "centurylink", "lumen", "deutsche telekom", "vodafone",
    "orange", "british telecom", "sky ", "virgin media", "telefonica",
    "kpn", "ziggo", "telia", "telstra", "optus", "bell canada", "rogers",
    "shaw", "telus", "videotron", "iliad", "bouygues", "sfr", "telecom italia",
    "movistar", "claro", "vivo", "sk broadband", "korea telecom", "ntt",
    "kddi", "softbank", "com hem", "t-mobile", "swisscom", "proximus",
]
MAX_CIDR_HOSTS = 4096
MAX_TOTAL_TARGETS = 100_000
PROBE_TIMEOUT = 3.0

# Real llama-server /props always carries these. A /props without any of them
# is an imitation (see 45.32.114.54:8000 incident).
REAL_LLAMACPP_MARKERS = [
    "default_generation_settings",
    "total_slots",
    "build_info",
    "chat_template",
]
# Proprietary vendors that cannot co-exist on one self-hosted box.
PROPRIETARY_VENDORS = {"openai", "anthropic", "google", "cohere", "xai", "moonshot"}

SCANS = {}  # scan_id -> threading.Event (cancel flag)
HISTORY = deque(maxlen=10)  # completed scan archives, newest first

# --- persistence + learned blocklist ---
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
STATE_DB = os.path.join(DATA_DIR, "state.db")
BLOCKLIST_FILE = os.path.join(DATA_DIR, "honeypot_blocklist.txt")
# DoD holds ~13 /8 blocks in US space — probing them is pure waste and attracts
# attention. One hardcoded default exclude list, removable in advanced options.
DEFAULT_DOD_EXCLUDES = [
    "6.0.0.0/8", "7.0.0.0/8", "11.0.0.0/8", "21.0.0.0/8", "22.0.0.0/8",
    "26.0.0.0/8", "28.0.0.0/8", "29.0.0.0/8", "30.0.0.0/8", "33.0.0.0/8",
    "55.0.0.0/8", "56.0.0.0/8", "214.0.0.0/8", "215.0.0.0/8",
]
# Lean port set: the 3 ports where real deployments dominate.
LEAN_PORTS = {8080, 11434, 8000}


def _init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(STATE_DB)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS targets ("
        "  ip TEXT NOT NULL, port INTEGER NOT NULL,"
        "  verdict TEXT NOT NULL, product TEXT, score INTEGER DEFAULT 0,"
        "  scanned_at REAL NOT NULL, fp TEXT, PRIMARY KEY (ip, port))")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS honeypot_fleets ("
        "  inv_hash TEXT PRIMARY KEY, member_count INTEGER,"
        "  verdicts TEXT, first_seen REAL, last_seen REAL)")
    # migrate: add fp column if table predates it
    cols = {r[1] for r in conn.execute("PRAGMA table_info(targets)")}
    if "fp" not in cols:
        conn.execute("ALTER TABLE targets ADD COLUMN fp TEXT")
    conn.commit()
    return conn


def store_results(results):
    try:
        conn = _init_db()
        now = time.time()
        for r in results:
            parts = r["target"].rsplit(":", 1)
            if len(parts) != 2:
                continue
            conn.execute(
                "INSERT OR REPLACE INTO targets (ip,port,verdict,product,score,scanned_at) "
                "VALUES (?,?,?,?,?,?)",
                (parts[0], int(parts[1]), r.get("verdict", "DARK"),
                 r.get("product"), r.get("score", 0), now))
        conn.commit()
        conn.close()
    except Exception:
        pass


def recent_targets(ttl_days):
    cutoff = time.time() - ttl_days * 86400
    try:
        conn = _init_db()
        rows = conn.execute(
            "SELECT ip, port FROM targets WHERE scanned_at > ?", (cutoff,)).fetchall()
        conn.close()
        return {(ip, port) for ip, port in rows}
    except Exception:
        return set()


def learn_honeypots(results):
    by_hash = {}
    for r in results:
        h = r.get("inventory_hash")
        if h and r.get("verdict") in ("IMPOSTOR", "GENUINE", "UNKNOWN"):
            by_hash.setdefault(h, []).append(r)
    learned = 0
    try:
        conn = _init_db()
        now = time.time()
        bl = set()
        if os.path.exists(BLOCKLIST_FILE):
            with open(BLOCKLIST_FILE) as f:
                bl = {l.strip() for l in f if l.strip() and not l.startswith("#")}
        for h, arr in by_hash.items():
            targets = list({a["target"] for a in arr})
            if len(targets) < 3:
                continue
            tally = {}
            for a in arr:
                tally[a["verdict"]] = tally.get(a["verdict"], 0) + 1
            conn.execute(
                "INSERT OR REPLACE INTO honeypot_fleets "
                "(inv_hash,member_count,verdicts,first_seen,last_seen) VALUES (?,?,?,?,?)",
                (h, len(targets), json.dumps(tally), now, now))
            # confirmed honeypot fleet: all members are impostor, or majority
            if tally.get("IMPOSTOR", 0) >= len(targets) * 0.6:
                for t in targets:
                    bl.add(t.rsplit(":", 1)[0])
                    learned += 1
        conn.commit()
        conn.close()
        if learned:
            with open(BLOCKLIST_FILE, "w") as f:
                f.write("\n".join(sorted(bl)) + "\n")
    except Exception:
        pass
    return learned


def load_blocklist():
    try:
        if os.path.exists(BLOCKLIST_FILE):
            with open(BLOCKLIST_FILE) as f:
                return {l.strip() for l in f if l.strip() and not l.startswith("#")}
    except OSError:
        pass
    return set()


def add_blocklist(target):
    """Append a confirmed honeypot target to the persistent blocklist."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(BLOCKLIST_FILE, "a") as f:
            f.write(target + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Scan-strategy helpers (progressive depth, banner prefilter, adaptive
# timeout, content dedup, diff mode, PTR enrichment, CT/Shodan seed import)
# ---------------------------------------------------------------------------

NON_HTTP_PREFIXES = (
    b"SSH-", b"220 ", b"530 ", b"+OK", b"-ERR", b"* OK",
    b"\x03\x00\x00", b"\x16\x03", b"RFB ",  # xdmcp, TLS hello, VNC
)


def banner_is_nonhttp(banner):
    """Heuristic: a service whose first bytes match a known non-HTTP
    protocol. Used by the banner prefilter to skip HTTP probes."""
    if not banner:
        return False
    for p in NON_HTTP_PREFIXES:
        if banner.startswith(p):
            return True
    # binary garbage (mostly NULs / high bytes) is almost never HTTP
    if len(banner) >= 8 and sum(1 for c in banner if c < 32 and c != 9) > 4:
        return True
    return False


async def banner_grab(host, port, timeout):
    """Connect, wait briefly for a server greeting. Returns first bytes
    (may be empty for HTTP servers that speak only after a request)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout)
        try:
            return await asyncio.wait_for(reader.read(64), 0.35)
        except asyncio.TimeoutError:
            return b""
        finally:
            try:
                writer.close()
            except Exception:
                pass
    except Exception:
        return None


async def tcp_alive(host, port, timeout):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout)
        try:
            writer.close()
        except Exception:
            pass
        return True
    except Exception:
        return False


def ptr_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def ct_search(query, limit=200):
    """crt.sh certificate-transparency search. Returns [(name, port), ...]."""
    url = f"https://crt.sh/?q=%25{query}%25&output=json"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "silicon-recon/2.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
        names = set()
        for row in data[:limit * 4]:
            for nm in (row.get("name_value") or "").split("\n"):
                nm = nm.strip().lstrip("*.").lower()
                if nm and not nm.endswith(".local") and "." in nm:
                    names.add(nm)
        ports = FRAMEWORKS.get(query, {}).get("ports", [443])
        port = ports[0] if ports else 443
        return [(n, port) for n in list(names)[:limit]]
    except Exception:
        return []


def shodan_search(query, api_key=None, limit=200):
    """Shodan host search. Requires SHODAN_API_KEY env var or arg."""
    key = api_key or os.environ.get("SHODAN_API_KEY", "")
    if not key:
        return []
    url = (f"https://api.shodan.io/shodan/host/search?key={key}"
           f"&query={urllib.parse.quote(query)}")
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "silicon-recon/2.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
        out = []
        for m in (data.get("matches") or [])[:limit]:
            ip = m.get("ip_str")
            port = m.get("port")
            if ip and port:
                out.append((ip, int(port)))
        return out
    except Exception:
        return []


def fingerprint_hash(d):
    """Stable hash of a result's identifying surface, for diff mode."""
    parts = [
        d.get("product") or "", d.get("version") or "",
        d.get("verdict") or "", d.get("inventory_hash") or "",
    ]
    models = sorted(d.get("models_served") or [])
    parts.append("|".join(models))
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def diff_check(target, fp_hash):
    """True if target's stored fingerprint differs from fp_hash (or unseen)."""
    try:
        conn = _init_db()
        parts = target.rsplit(":", 1)
        if len(parts) != 2:
            conn.close()
            return True
        ip, port = parts[0], int(parts[1])
        row = conn.execute(
            "SELECT fp FROM targets WHERE ip=? AND port=?",
            (ip, port)).fetchone()
        conn.close()
        return row is None or row[0] != fp_hash
    except Exception:
        return True


def scan_cache_hit(target):
    """True if target was scanned within the dedup TTL (default 7 days)."""
    try:
        conn = _init_db()
        parts = target.rsplit(":", 1)
        if len(parts) != 2:
            conn.close()
            return False
        ip, port = parts[0], int(parts[1])
        cutoff = time.time() - 7 * 86400
        row = conn.execute(
            "SELECT 1 FROM targets WHERE ip=? AND port=? AND scanned_at>?",
            (ip, port, cutoff)).fetchone()
        conn.close()
        return row is not None
    except Exception:
        return False


def store_scan_result(d):
    """Persist a single scan result to SQLite."""
    try:
        conn = _init_db()
        parts = d["target"].rsplit(":", 1)
        if len(parts) != 2:
            conn.close()
            return
        conn.execute(
            "INSERT OR REPLACE INTO targets (ip,port,verdict,product,score,scanned_at,fp) "
            "VALUES (?,?,?,?,?,?,?)",
            (parts[0], int(parts[1]), d.get("verdict", "DARK"),
             d.get("product"), d.get("score", 0), time.time(),
             fingerprint_hash(d)))
        conn.commit()
        conn.close()
    except Exception:
        pass


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
        for _attempt in range(2):  # retry once on a dropped keep-alive
            try:
                if conn is None:
                    conn = http.client.HTTPConnection(host, port, timeout=timeout)
                conn.request("GET", path, headers={"User-Agent": "silicon-recon/1.0"})
                resp = conn.getresponse()
                body = resp.read(65536).decode("utf-8", errors="replace")
                status = resp.status
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
            dossier["endpoints"][path] = {"status": None, "json": None, "raw": ""}
            dossier["error"] = err
            if probe_cb:
                probe_cb(host, port, path, None, err)
            break
        any_http = True
        dossier["endpoints"][path] = {"status": status, "json": js, "raw": str(body)[:512]}
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


def detect_sigs(ep):
    """Collect product-family signatures from a probed endpoint map."""

    def j(path):
        e = ep.get(path) or {}
        return e.get("json") if e.get("status") == 200 else None

    def raw(path):
        e = ep.get(path) or {}
        return e.get("raw") or ""

    # --- collect one signature per product family ---
    sigs = {}  # product -> evidence dict

    tags = j("/api/tags")
    if isinstance(tags, dict) and isinstance(tags.get("models"), list):
        root_ok = "ollama" in raw("/").lower()
        sigs["ollama"] = {
            "models": [m.get("name", "?") for m in tags["models"][:30] if isinstance(m, dict)],
            "root_banner": root_ok,
        }
    ov = j("/api/version")
    if "ollama" in sigs and isinstance(ov, dict) and ov.get("version"):
        sigs["ollama"]["version"] = str(ov["version"])

    ver = j("/version")
    if isinstance(ver, dict) and isinstance(ver.get("version"), str):
        sigs["vllm"] = {"version": ver["version"]}

    mi = j("/get_model_info")
    if isinstance(mi, dict) and ("model_path" in mi or "tokenizer_path" in mi):
        sigs["sglang"] = {"model": mi.get("model_path")}
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

    tgi_info = j("/v1/internal/model/info")
    if isinstance(tgi_info, dict) and tgi_info.get("model_name"):
        sigs["tgwui"] = {"model": tgi_info["model_name"]}

    tg = j("/info")
    if isinstance(tg, dict) and tg.get("model_id"):
        sigs["tgi"] = {"model": tg["model_id"]}
        if tg.get("version"):
            sigs["tgi"]["version"] = str(tg["version"])

    owc = j("/api/config")
    if (isinstance(owc, dict) and owc.get("status") is True
            and isinstance(ov, dict) and ov.get("version")):
        sigs["openwebui"] = {"version": str(ov["version"])}
    return sigs


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
    combo = frozenset(sigs)
    if len(sigs) > 1 and combo not in LEGIT_COMBOS:
        flags.append("MULTI_PERSONA: poses as " + "+".join(sorted(sigs)))

    if len(sigs) == 1 or (len(sigs) > 1 and combo in LEGIT_COMBOS):
        dossier["product"] = "+".join(sorted(sigs))
        primary = sigs[sorted(sigs)[0]]
        dossier["version"] = primary.get("version")
        dossier["model"] = primary.get("model")
        for ev in sigs.values():
            if ev.get("models"):
                dossier["models_served"] = ev["models"][:20]
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
    dossier["score"] = score
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


def expand_targets(lines, ports=None, excludes=None):
    """Parse target lines: host | host:port | CIDR. ports overrides defaults.
    excludes: list of ip_network objects; matching hosts are skipped."""
    ports = ports or DEFAULT_PORTS
    targets = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.replace("http://", "").replace("https://", "").strip("/")
        try:
            if "/" in line:  # CIDR
                net = ipaddress.ip_network(line, strict=False)
                if net.version != 4:  # engine is IPv4-only; skip v6 (hosts() would be astronomic)
                    continue
                count = 0
                for h in net.hosts():
                    if count >= MAX_CIDR_HOSTS:
                        break
                    count += 1
                    for p in ports:
                        targets.append((str(h), p))
                if count == 0:
                    for p in ports:
                        targets.append((str(net.network_address), p))
                if len(targets) >= MAX_TOTAL_TARGETS * 2:
                    break
            elif ":" in line:
                host, port = line.rsplit(":", 1)
                targets.append((host, int(port)))
            else:
                for p in ports:
                    targets.append((line, p))
        except ValueError:
            continue
    # dedupe, preserve order
    seen, out = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            out.append(t)
    if excludes:
        kept = []
        for h, p in out:
            try:
                addr = ipaddress.ip_address(h)
                if any(addr in net for net in excludes):
                    continue
            except ValueError:
                pass  # hostname, not an IP: keep
            kept.append((h, p))
        out = kept
    truncated = len(out) > MAX_TOTAL_TARGETS
    if truncated:
        out = out[:MAX_TOTAL_TARGETS]
    return out, truncated


# ---------- country CIDR builder (RIR delegated stats) ----------
RIR_URLS = [
    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "https://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest",
    "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
]
RIR_CACHE = "/tmp/silicon_recon_rir.txt"


def fetch_rir_stats():
    """Download all RIR delegated stats files, cached 24h, combined."""
    try:
        if os.path.exists(RIR_CACHE) and time.time() - os.path.getmtime(RIR_CACHE) < 86400:
            with open(RIR_CACHE) as f:
                return f.read()
    except OSError:
        pass
    chunks = []
    for url in RIR_URLS:
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                chunks.append(r.read().decode("utf-8", "replace"))
        except OSError:
            continue  # one dead RIR mirror must not kill the feature
    if not chunks:
        raise OSError("all RIR stats mirrors unreachable")
    data = "\n".join(chunks)
    try:
        with open(RIR_CACHE, "w") as f:
            f.write(data)
    except OSError:
        pass
    return data


def country_cidrs(cc, limit):
    """Extract allocated/assigned IPv4 CIDRs for a country code from RIR stats."""
    cidrs = []
    for line in fetch_rir_stats().splitlines():
        parts = line.split("|")
        if len(parts) < 7 or parts[2] != "ipv4":
            continue
        if parts[1].upper() != cc.upper():
            continue
        if parts[6] not in ("allocated", "assigned"):
            continue
        try:
            start = ipaddress.ip_address(parts[3])
            end = start + int(parts[4]) - 1
            for net in ipaddress.summarize_address_range(start, end):
                cidrs.append(str(net))
        except ValueError:
            continue
    random.shuffle(cidrs)
    total = len(cidrs)
    return cidrs[:limit], total


def bgpview_prefixes(asn, limit=5000):
    """Announced IPv4 prefixes for an AS number, via RIPEstat (no key). Cached 24h."""
    cache = f"/tmp/silicon_recon_asn_{asn}.json"
    data = None
    try:
        if os.path.exists(cache) and time.time() - os.path.getmtime(cache) < 86400:
            with open(cache) as f:
                data = json.load(f)
    except (OSError, json.JSONDecodeError):
        data = None
    if data is None:
        def _get(url):
            with urllib.request.urlopen(url, timeout=30) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        payload = _get(
            f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}")
        prefixes = [p["prefix"] for p in
                    (payload.get("data") or {}).get("prefixes", []) if p.get("prefix")]
        name = ""
        try:
            ov = _get(
                f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}")
            name = (ov.get("data") or {}).get("holder") or ""
        except Exception:
            pass
        data = {"name": name, "prefixes": prefixes}
        try:
            with open(cache, "w") as f:
                json.dump(data, f)
        except OSError:
            pass
    # IPv4 only: the probe engine is IPv4, and an IPv6 /32 would explode
    # expand_targets' hosts() enumeration (memory bomb). Filter at read time
    # so stale 24h caches containing IPv6 entries are also covered.
    prefixes = [p for p in data["prefixes"] if ":" not in p]
    random.shuffle(prefixes)
    return data["name"], prefixes[:limit], len(prefixes)


def parse_excludes(lines):
    """Parse exclude CIDR lines into ip_network objects."""
    nets = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    return nets


# ---------- ASN enrichment (Team Cymru DNS, stdlib raw DNS client) ----------
_DNS_NS = None
ASN_CACHE = {}      # ip -> info dict or None
PREFIX_CACHE = {}   # ip_network -> info dict


def _nameserver():
    global _DNS_NS
    if _DNS_NS is None:
        _DNS_NS = "1.1.1.1"
        try:
            with open("/etc/resolv.conf") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        _DNS_NS = line.split()[1]
                        break
        except OSError:
            pass
    return _DNS_NS


def dns_txt(name, timeout=2.0):
    """Minimal DNS TXT query. Returns joined TXT string or None."""
    tid = random.randint(0, 65535)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00" + struct.pack(">HH", 16, 1)  # QTYPE TXT, QCLASS IN
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(q, (_nameserver(), 53))
        data, _ = s.recvfrom(4096)
    except OSError:
        return None
    finally:
        s.close()
    if len(data) < 12:
        return None
    ancount = struct.unpack(">H", data[6:8])[0]
    off = 12
    try:
        while data[off] != 0:  # skip question qname
            off += data[off] + 1
        off += 5  # null + qtype + qclass
        for _ in range(ancount):
            if data[off] & 0xC0 == 0xC0:  # compression pointer
                off += 2
            else:
                while data[off] != 0:
                    off += data[off] + 1
                off += 1
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            off += rdlen
            if rtype == 16:  # TXT
                txts, i = [], 0
                while i < len(rdata):
                    ln = rdata[i]
                    i += 1
                    txts.append(rdata[i:i + ln].decode("utf-8", "replace"))
                    i += ln
                return "".join(txts)
    except (IndexError, struct.error):
        return None
    return None


def classify_net(as_name):
    n = (as_name or "").lower()
    if not n:
        return "UNKNOWN"
    if any(k in n for k in DC_KEYWORDS):
        return "DATACENTER"
    if any(k in n for k in RES_KEYWORDS):
        return "RESIDENTIAL"
    return "UNKNOWN"


def asn_lookup(ip_str):
    """Return {asn, prefix, as_name, net_type} or None. Cached per IP + BGP prefix."""
    if ip_str in ASN_CACHE:
        return ASN_CACHE[ip_str]
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for pfx, info in PREFIX_CACHE.items():
        if addr in pfx:
            ASN_CACHE[ip_str] = info
            return info
    info = None
    try:
        rev = ".".join(reversed(ip_str.split(".")))
        txt = dns_txt(f"{rev}.origin.asn.cymru.com")
        if txt:
            parts = [p.strip() for p in txt.split("|")]
            asn = parts[0] if parts else ""
            prefix = parts[1] if len(parts) > 1 else ""
            name = ""
            if asn.isdigit():
                t2 = dns_txt(f"AS{asn}.asn.cymru.com")
                if t2:
                    p2 = [x.strip() for x in t2.split("|")]
                    name = p2[-1] if p2 else ""
            info = {"asn": asn, "prefix": prefix, "as_name": name,
                    "net_type": classify_net(name)}
            try:
                PREFIX_CACHE[ipaddress.ip_network(prefix, strict=False)] = info
            except ValueError:
                pass
    except Exception:
        info = None
    ASN_CACHE[ip_str] = info
    return info


def bulk_asn_lookup(ips):
    """Team Cymru bulk whois (TCP 43): one session for many IPs.
    Returns {ip: info}; also populates ASN/PREFIX caches."""
    results = {}
    todo = []
    for ip in dict.fromkeys(ips):
        if ip in ASN_CACHE:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if any(addr in p for p in PREFIX_CACHE):
            continue
        todo.append(ip)
    for off in range(0, len(todo), 1000):
        chunk = todo[off:off + 1000]
        try:
            s = socket.create_connection(("whois.cymru.com", 43), timeout=15)
            f = s.makefile("rw")
            f.write("begin\nverbose\n")
            for ip in chunk:
                f.write(ip + "\n")
            f.write("end\n")
            f.flush()
            for line in f:
                parts = [p.strip() for p in line.split("|")]
                if len(parts) < 7 or not parts[0].isdigit():
                    continue  # banner / header lines
                asn, ip, prefix, name = parts[0], parts[1], parts[2], parts[6]
                info = {"asn": asn, "prefix": prefix, "as_name": name,
                        "net_type": classify_net(name)}
                results[ip] = info
                ASN_CACHE[ip] = info
                try:
                    PREFIX_CACHE[ipaddress.ip_network(prefix, strict=False)] = info
                except ValueError:
                    pass
            s.close()
        except OSError:
            break  # callers fall back to per-IP DNS for what's missing
    return results


# ---------- async probe engine ----------
# discriminator paths always run (multi-persona detection depends on them);
# auxiliary paths only run when relevant in fast profile.
DISC_PATHS = {
    "/props", "/api/tags", "/version", "/get_model_info", "/api/v0/models",
    "/api/extra/version", "/v1/internal/model/info", "/info", "/api/config",
    "/v1/models",
}


def fd_worker_cap():
    """Max concurrent hosts the fd soft limit can sustain (4 conns per host)."""
    try:
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        return max(50, (soft - 256) // 4)
    except (ValueError, OSError):
        return 256


class _Conn:
    __slots__ = ("reader", "writer")

    @classmethod
    async def open(cls, host, port, timeout):
        c = cls()
        c.reader, c.writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout)
        return c

    def close(self):
        try:
            self.writer.close()
        except Exception:
            pass

    async def get(self, host, port, path, timeout):
        """HTTP GET with one reconnect retry. Returns (status, body_str)."""
        last_err = OSError("probe failed")
        for _ in range(2):
            try:
                self.writer.write(
                    f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                    f"User-Agent: silicon-recon/2.0\r\n"
                    f"Connection: keep-alive\r\n\r\n".encode())
                await self.writer.drain()
                head = await asyncio.wait_for(
                    self.reader.readuntil(b"\r\n\r\n"), timeout)
                status = int(head.split(b"\r\n", 1)[0].split(b" ", 2)[1])
                headers = {}
                for line in head.split(b"\r\n")[1:]:
                    if b":" in line:
                        k, v = line.split(b":", 1)
                        headers[k.strip().lower()] = v.strip()
                if "chunked" in headers.get("transfer-encoding", "").lower():
                    body = await asyncio.wait_for(_read_chunked(self.reader), timeout)
                elif "content-length" in headers:
                    n = min(int(headers["content-length"]), 65536)
                    body = await asyncio.wait_for(
                        self.reader.readexactly(n), timeout) if n else b""
                else:
                    body = await asyncio.wait_for(self.reader.read(65536), timeout)
                return status, body.decode("utf-8", "replace")
            except Exception as e:
                last_err = e
                self.close()
                try:
                    self.reader, self.writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout)
                except Exception as e2:
                    last_err = e2
        raise last_err


async def _read_chunked(reader, cap=65536):
    out = bytearray()
    while True:
        line = await reader.readline()
        n = int(line.strip().split(b";", 1)[0] or b"0", 16)
        if n == 0:
            await reader.readline()
            break
        out += await reader.readexactly(n)
        await reader.readexactly(2)  # trailing CRLF
        if len(out) >= cap:
            break
    return bytes(out[:cap])


def _aux_needed(path, ep, sigs):
    if path == "/":
        return "ollama" in sigs
    if path == "/health":
        return "llamacpp" in sigs
    if path == "/get_server_info":
        return "sglang" in sigs
    if path == "/api/v1/model":
        return "koboldcpp" in sigs
    if path == "/api/version":
        if "ollama" in sigs or "openwebui" in sigs:
            return True
        e = ep.get("/api/config") or {}
        cfg = e.get("json") if e.get("status") == 200 else None
        return isinstance(cfg, dict) and cfg.get("status") is True
    return True


async def probe_host(host, port, paths, timeout, probe_cb, fast, fanout=False,
                     content_hashes=None, banner_prefilter=False,
                     ptr_seed=False, diff_mode=False):
    dossier = {
        "target": f"{host}:{port}", "product": "unknown", "verdict": "DARK",
        "version": None, "model": None, "models_served": [], "flags": [],
        "endpoints": {}, "latency_ms": None, "error": None,
        "asn": None, "as_name": None, "bgp_prefix": None, "net_type": None,
        "score": 0, "inventory_hash": None, "ptr": None,
    }
    t0 = time.time()
    endpoints = dossier["endpoints"]
    disc = [p for p in paths if p in DISC_PATHS]
    aux = [p for p in paths if p not in DISC_PATHS]

    # banner prefilter: skip HTTP entirely if the service is clearly not HTTP
    if banner_prefilter:
        banner = await banner_grab(host, port, min(timeout, 1.0))
        if banner and banner_is_nonhttp(banner):
            dossier["error"] = "non-http"
            dossier["latency_ms"] = round((time.time() - t0) * 1000)
            if probe_cb:
                probe_cb(host, port, "/", None, "non-http")
            return dossier

    nconns = max(1, min(4, len(disc)))
    conns = []
    first_err = "connect failed"
    for _ in range(nconns):
        try:
            conns.append(await _Conn.open(host, port, min(timeout, CONNECT_TIMEOUT)))
        except Exception as e:
            first_err = type(e).__name__
            break
    if not conns:
        dossier["error"] = first_err
        dossier["latency_ms"] = round((time.time() - t0) * 1000)
        if probe_cb:
            probe_cb(host, port, "/", None, first_err)
        return dossier

    async def probe_paths(conn, todo):
        for path in todo:
            try:
                status, body = await conn.get(host, port, path, timeout)
                try:
                    js = json.loads(body)
                except json.JSONDecodeError:
                    js = None
                endpoints[path] = {"status": status, "json": js, "raw": body[:512]}
                if probe_cb:
                    probe_cb(host, port, path, status, None)
            except Exception as e:
                endpoints[path] = {"status": None, "json": None, "raw": ""}
                if probe_cb:
                    probe_cb(host, port, path, None, type(e).__name__)

    async def wave(todo):
        if todo:
            chunks = [todo[i::len(conns)] for i in range(len(conns))]
            await asyncio.gather(
                *(probe_paths(c, ch) for c, ch in zip(conns, chunks)))

    await wave(disc)
    if fast:
        sigs = detect_sigs(endpoints)
        aux = [p for p in aux if _aux_needed(p, endpoints, sigs)]
    await wave(aux)
    for c in conns:
        c.close()
    dossier["latency_ms"] = round((time.time() - t0) * 1000)
    if not any(v["status"] is not None for v in endpoints.values()):
        dossier["error"] = "no response"
        return dossier
    d = analyze(dossier)
    # content dedup: hash the identifying surface; on >=3 byte-identical
    # responses tag as DUPLICATE_CDN so the UI can collapse the cluster.
    if content_hashes is not None and d["verdict"] not in ("DARK", "ERROR"):
        sig = hashlib.sha256("".join(
            (ep.get("raw") or "") for ep in endpoints.values()
            if ep.get("status") == 200).encode("utf-8", "replace")).hexdigest()[:24]
        content_hashes[sig] = content_hashes.get(sig, 0) + 1
        if content_hashes[sig] >= 3:
            d["flags"] = list(d.get("flags") or []) + ["DUPLICATE_CDN"]
    if fanout and d["verdict"] not in ("DARK", "ERROR"):
        # operator co-located instances commonly run on sequential ports;
        # probe ±2 of a live port for free extra coverage on the same host.
        neighbors = {port + k for k in (-2, -1, 1, 2) if 0 < port + k < 65536}
        return d, neighbors
    return d


def run_async_engine(targets, paths, timeout, workers, enrich, fast, cancel, q,
                     fanout=False, skip_set=None, blocklist=None,
                     banner_prefilter=False, adaptive_timeout=False,
                     content_dedup=False, ptr_seed=False, diff_mode=False):
    """Owns an asyncio loop in a dedicated thread; pushes events to q."""
    skip_set = skip_set or set()
    blocklist = blocklist or set()

    def probe_cb(host, port, path, status, err):
        q.put({"type": "probe", "target": f"{host}:{port}",
               "path": path, "status": status, "err": err})

    async def main():
        sem = asyncio.Semaphore(workers)
        pending = []  # (ip, target) awaiting bulk ASN enrichment
        seen_fanout = set()  # avoid duplicate fanout probes
        # adaptive timeout: track live latencies, shrink to 3x P95
        cur_timeout = [timeout]
        lat_samples = []
        # content dedup: signature -> count; >=3 identical = cluster
        sig_counts = {}
        ptr_seen = set()

        async def flush_asn():
            if not pending:
                return
            batch, pending[:] = pending[:], []
            ips = list({ip for ip, _t in batch})
            res = await asyncio.to_thread(bulk_asn_lookup, ips)
            for ip, target in batch:
                info = res.get(ip)
                if info is None:  # straggler: per-IP DNS fallback
                    try:
                        info = await asyncio.wait_for(
                            asyncio.to_thread(asn_lookup, ip), 6)
                    except Exception:
                        info = None
                if info:
                    q.put({"type": "enrich", "target": target,
                           "asn": info["asn"], "as_name": info["as_name"],
                           "bgp_prefix": info["prefix"],
                           "net_type": info["net_type"]})

        async def flusher():
            while True:
                await asyncio.sleep(4)
                await flush_asn()

        async def bound(h, p, is_fanout=False):
            async with sem:
                if cancel is not None and cancel.is_set():
                    return None
                tgt = f"{h}:{p}"
                if tgt in skip_set or tgt in blocklist:
                    return None
                try:
                    d = await probe_host(
                        h, p, paths, cur_timeout[0], probe_cb, fast,
                        fanout=is_fanout, content_hashes=(sig_counts if content_dedup else None),
                        banner_prefilter=banner_prefilter,
                        ptr_seed=ptr_seed, diff_mode=diff_mode)
                    # normalize tuple return (fanout yields (d, neighbors))
                    if isinstance(d, tuple):
                        d = d[0]
                except Exception as e:
                    d = {"target": tgt, "product": "unknown", "verdict": "ERROR",
                         "error": str(e), "flags": [], "endpoints": {},
                         "models_served": [], "version": None, "model": None,
                         "latency_ms": None, "asn": None, "as_name": None,
                         "bgp_prefix": None, "net_type": None,
                         "score": 0, "inventory_hash": None, "ptr": None}
                return d

        fl = asyncio.create_task(flusher())
        tasks = [asyncio.ensure_future(bound(h, p)) for h, p in targets]
        task_set = set(tasks)
        for fut in asyncio.as_completed(task_set):
            if cancel is not None and cancel.is_set():
                for t in task_set:
                    t.cancel()
                fl.cancel()
                return
            try:
                d = await fut
            except asyncio.CancelledError:
                continue
            if not d:
                continue
            ip, port_s = d["target"].rsplit(":", 1)
            port = int(port_s)
            live = d["verdict"] not in ("DARK", "ERROR")
            # adaptive timeout: shrink to 3x P95 once we have samples
            if adaptive_timeout and d.get("latency_ms") is not None and live:
                lat_samples.append(d["latency_ms"])
                if len(lat_samples) >= 200:
                    srt = sorted(lat_samples)
                    p95 = srt[int(len(srt) * 0.95)]
                    cur_timeout[0] = max(1.0, min(timeout, 3 * p95 / 1000.0))
            # PTR enrichment on first live hit per IP
            if ptr_seed and live and ip not in ptr_seen:
                ptr_seen.add(ip)
                name = await asyncio.to_thread(ptr_lookup, ip)
                if name:
                    d["ptr"] = name
            # diff mode: unchanged fingerprint since last scan
            if diff_mode and live and not diff_check(d["target"], fingerprint_hash(d)):
                d["flags"] = list(d.get("flags") or []) + ["UNCHANGED"]
            q.put({"type": "result", "data": d})
            # adjacent-port fan-out on live hits
            if fanout and d["verdict"] in ("GENUINE", "IMPOSTOR") and d["product"] != "unknown":
                for dp in (port - 2, port - 1, port + 1, port + 2):
                    if dp < 1 or dp > 65535:
                        continue
                    key = (ip, dp)
                    if key in seen_fanout:
                        continue
                    seen_fanout.add(key)
                    t = asyncio.ensure_future(bound(ip, dp, is_fanout=True))
                    task_set.add(t)
                    tasks.append(t)
            if enrich and live:
                pending.append((ip, d["target"]))
            # learn honeypots into blocklist (persistent across scans)
            if d["verdict"] == "IMPOSTOR" and d.get("score", 0) >= 40:
                add_blocklist(d["target"])
        fl.cancel()
        await flush_asn()
        q.put({"type": "enrich_done"})

    asyncio.run(main())


def _heartbeat(gen_state, interval=2.5):
    """Background thread that appends heartbeat log events to gen_state['q']
    so scan_events can yield progress during long synchronous phases."""
    while not gen_state["stop"].wait(interval):
        gen_state["q"].append({
            "type": "log",
            "message": f"PHASE: {gen_state['phase']}...",
            "cls": "warn",
        })


def scan_events(lines, workers=1000, timeout=PROBE_TIMEOUT, cancel=None,
                frameworks=None, excludes=None, enrich=True, fast=True,
                lean_ports=False, exclude_dod=True, dedup=False,
                asn_prefilter=False, fanout=False,
                progressive=False, banner_prefilter=False,
                adaptive_timeout=False, content_dedup=False,
                diff_mode=False, ptr_seed=False,
                ct_search_seed=False, shodan_seed=False):
    """Generator: yields start / probe / result / done / stopped events."""
    frameworks = [f for f in (frameworks or list(FRAMEWORKS)) if f in FRAMEWORKS]
    if not frameworks:
        frameworks = list(FRAMEWORKS)
    paths = [p for p in PROBE_PATHS
             if any(p in FRAMEWORKS[f]["paths"] for f in frameworks)]

    # CT / Shodan seed import: pull pre-curated hosts into the target list
    # before expansion. Near-zero false positives; tiny probe count.
    seed_count = 0
    seed_lines = list(lines or [])
    if ct_search_seed or shodan_seed:
        yield {"type": "log", "message": "querying CT / Shodan seed endpoints...", "cls": "warn"}
    if ct_search_seed:
        for fw in frameworks:
            for name, port in ct_search(fw, limit=100):
                seed_lines.append(f"{name}:{port}")
                seed_count += 1
    if shodan_seed:
        for fw in frameworks:
            for port in FRAMEWORKS[fw]["ports"][:1]:
                for ip, pt in shodan_search(f'port:{port}', limit=100):
                    seed_lines.append(f"{ip}:{pt}")
                    seed_count += 1

    # port selection: lean = top port per framework only
    if lean_ports:
        ports = sorted({FRAMEWORKS[f]["ports"][0] for f in frameworks})
    else:
        ports = sorted({pt for f in frameworks for pt in FRAMEWORKS[f]["ports"]})
    excl_nets = parse_excludes(excludes or [])
    if exclude_dod:
        dod_nets = parse_excludes(DEFAULT_DOD_EXCLUDES)
        excl_nets.extend(dod_nets)
    # heartbeat: keeps the NDJSON stream alive during long synchronous phases
    hb_state = {"stop": threading.Event(), "q": [], "phase": "expanding CIDRs"}
    hb_thread = threading.Thread(target=_heartbeat, args=(hb_state,), daemon=True)
    hb_thread.start()

    def _drain_hb():
        """Yield any heartbeat events that accumulated during a sync phase."""
        events = []
        while hb_state["q"]:
            events.append(hb_state["q"].pop(0))
        return events

    yield {"type": "log", "message": "expanding target CIDRs into target list...", "cls": "warn"}
    hb_state["phase"] = "expanding CIDRs"
    targets, truncated = expand_targets(seed_lines, ports=ports, excludes=excl_nets)
    for ev in _drain_hb():
        yield ev
    random.shuffle(targets)  # break worker lockstep on homogeneous ranges
    for ev in _drain_hb():
        yield ev
    fd_cap = fd_worker_cap()
    capped = workers > fd_cap
    workers = min(workers, fd_cap)

    # dedup: skip recently scanned targets
    skip_set = set()
    if dedup:
        hb_state["phase"] = f"dedup check ({len(targets)} targets)"
        for ip, port in targets:
            tgt = f"{ip}:{port}"
            if scan_cache_hit(tgt):
                skip_set.add(tgt)
        for ev in _drain_hb():
            yield ev

    # learned honeypot blocklist
    blocklist = load_blocklist()

    # ASN prefilter: classify candidate /24s and drop residential ones
    prefilt_total = len(targets)
    prefilt_dropped = 0
    if asn_prefilter and targets:
        yield {"type": "log", "message": f"ASN prefilter: inspecting {len(targets)} targets for residential ranges...", "cls": "warn"}
        hb_state["phase"] = "ASN prefilter"
        import collections as _coll
        subnet_groups = _coll.defaultdict(list)
        for ip, port in targets:
            parts = ip.split(".")
            key = ".".join(parts[:3])
            subnet_groups[key].append((ip, port))
        keep = []
        # process subnets in chunks of 128 (whois line limit)
        items = list(subnet_groups.items())
        for i in range(0, len(items), 128):
            chunk = items[i:i + 128]
            sample_ips = [grp[0][0] for _k, grp in chunk]  # first IP per /24
            res = bulk_asn_lookup(sample_ips)
            for key, group in chunk:
                sample = group[0][0]
                info = res.get(sample)
                if info and info["net_type"] == "RESIDENTIAL":
                    prefilt_dropped += len(group)
                else:
                    keep.extend(group)
            for ev in _drain_hb():
                yield ev
        targets = keep

    # progressive depth: TCP-sweep each host's candidate ports cheaply,
    # keeping only hosts where at least one port answers. Big ranges go
    # from N*ports full HTTP probes down to N*ports cheap connects +
    # live*ports deep probes.
    pre_swept = 0
    if progressive and targets:
        yield {"type": "log", "message": f"progressive depth: running TCP pre-sweep on {len(targets)} host:port targets @ {workers} workers...", "cls": "warn"}
        hb_state["phase"] = "TCP pre-sweep"
        by_ip = {}
        for ip, p in targets:
            by_ip.setdefault(ip, set()).add(p)

        async def sweep():
            sem = asyncio.Semaphore(workers)
            live_keys = set()

            async def chk(ip, p):
                async with sem:
                    if cancel is not None and cancel.is_set():
                        return
                    if await tcp_alive(ip, p, min(timeout, 1.5)):
                        live_keys.add((ip, p))
            await asyncio.gather(*(chk(ip, p) for ip, ports_ in by_ip.items()
                                   for p in ports_))
            return live_keys
        live_keys = asyncio.run(sweep())
        pre_swept = len(targets) - len(live_keys)
        targets = [(ip, p) for ip, p in targets if (ip, p) in live_keys]
        for ev in _drain_hb():
            yield ev

    # stop heartbeat before the scan engine takes over
    hb_state["stop"].set()
    hb_thread.join(timeout=1)

    yield {"type": "start", "total": len(targets),
           "frameworks": frameworks, "ports": ports,
           "excluded_nets": len(excl_nets), "truncated": truncated,
           "engine": "asyncio", "profile": "fast" if fast else "exhaustive",
           "workers": workers, "fd_capped": capped,
           "dedup_skipped": len(skip_set), "prefiltered": prefilt_dropped,
           "blocklisted": len(blocklist), "seeded": seed_count,
           "progressive_dropped": pre_swept}
    t0 = time.time()
    if not targets:
        yield {"type": "done", "requests": 0, "elapsed_s": 0}
        return
    q = queue.Queue()
    reqs = [0]
    eng = threading.Thread(
        target=run_async_engine,
        args=(targets, paths, timeout, workers, enrich, fast, cancel, q),
        kwargs={"fanout": fanout, "skip_set": skip_set, "blocklist": blocklist,
                "banner_prefilter": banner_prefilter,
                "adaptive_timeout": adaptive_timeout,
                "content_dedup": content_dedup,
                "ptr_seed": ptr_seed, "diff_mode": diff_mode},
        daemon=True)
    eng.start()
    got = 0
    engine_done = False
    try:
        while not (got >= len(targets) and engine_done):
            if cancel is not None and cancel.is_set():
                el = round(time.time() - t0, 1)
                yield {"type": "stopped", "done": got, "requests": reqs[0],
                       "elapsed_s": el, "hosts_per_s": round(got / el, 1) if el else 0}
                return
            try:
                ev = q.get(timeout=0.25)
            except queue.Empty:
                if not eng.is_alive() and q.empty():
                    break
                continue
            if ev["type"] == "probe":
                reqs[0] += 1
            elif ev["type"] == "result":
                got += 1
                d = ev["data"]
                store_scan_result(d)  # persist to SQLite
            elif ev["type"] == "enrich_done":
                engine_done = True
                continue  # internal marker, not streamed
            yield ev
    finally:
        eng.join(timeout=5)
    el = round(time.time() - t0, 1)
    yield {"type": "done", "requests": reqs[0], "elapsed_s": el,
           "hosts_per_s": round(got / el, 1) if el else 0}


PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SILICON RECON // LLM SERVER FINGERPRINT</title>
<style>
  :root {
    --phos: #33ff66; --phos-dim: #1a9933; --amber: #ffb000; --red: #ff3333;
    --bg: #050805; --panel: #0a120a; --line: #1c3a1c;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg); color: var(--phos);
    font-family: "Courier New", ui-monospace, monospace;
    font-size: 14px; line-height: 1.45; min-height: 100vh;
  }
  body::after {
    content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 50;
    background: repeating-linear-gradient(0deg, rgba(0,0,0,.22) 0 1px, transparent 1px 3px);
  }
  .wrap { max-width: 1200px; margin: 0 auto; padding: 18px 20px 60px; }
  .classif {
    text-align: center; letter-spacing: .35em; font-weight: bold;
    color: var(--amber); border: 1px solid var(--amber);
    padding: 5px 0; margin-bottom: 4px; font-size: 12px;
  }
  .classif.bottom { margin: 4px 0 18px; }
  h1 {
    text-align: center; font-size: 26px; letter-spacing: .2em;
    margin: 22px 0 4px; text-shadow: 0 0 12px rgba(51,255,102,.6);
  }
  .sub { text-align: center; color: var(--phos-dim); letter-spacing: .3em; font-size: 11px; margin-bottom: 14px; }
  .panel { border: 1px solid var(--line); background: var(--panel); padding: 14px 16px; margin-bottom: 18px; }
  .panel h2 { font-size: 12px; letter-spacing: .25em; color: var(--amber); margin-bottom: 10px; }
  textarea {
    width: 100%; height: 100px; background: #000; color: var(--phos);
    border: 1px solid var(--line); font: inherit; padding: 10px; resize: vertical;
  }
  textarea:focus, input:focus, select:focus { outline: 1px solid var(--phos); }
  .hint { color: var(--phos-dim); font-size: 11px; margin-top: 6px; }
  button {
    background: transparent; color: var(--phos); border: 1px solid var(--phos);
    font: inherit; letter-spacing: .25em; padding: 10px 22px; cursor: pointer;
    margin-top: 12px; margin-right: 8px; text-transform: uppercase;
  }
  button:hover { background: var(--phos); color: #000; box-shadow: 0 0 14px rgba(51,255,102,.7); }
  button:disabled { opacity: .35; cursor: not-allowed; box-shadow: none; }
  button.danger { color: var(--red); border-color: var(--red); }
  button.danger:hover { background: var(--red); color: #000; box-shadow: 0 0 14px rgba(255,51,51,.7); }
  button.small { padding: 4px 12px; font-size: 11px; margin-top: 0; }
  button.active { background: var(--phos); color: #000; }
  #export, #exportcsv, #abort, #retarget { display: none; }
  .modebar { text-align: center; margin-bottom: 18px; }
  .modebar button { margin: 0 4px; }
  .adv-only { display: none; }
  body.adv .adv-only { display: block; }
  body.adv span.adv-only, body.adv label.adv-only { display: inline-block; }
  body:not(.adv) .simp-hide { display: none !important; }
  .preset-hint { color: var(--amber); font-size: 11px; letter-spacing: .05em; margin: 6px 0 8px; }
  .chip.preset { font-size: 12px; padding: 5px 16px; }
  .chip.pack { border-color: #432; color: var(--amber); }
  .chip.pack:hover { border-color: var(--amber); box-shadow: 0 0 6px rgba(255,176,0,.25); }
  .pack-row { margin: 4px 0 10px; }
  input[type=text], input[type=number], select {
    background: #000; color: var(--phos); border: 1px solid var(--line);
    font: inherit; padding: 5px 8px;
  }
  .opts { margin-top: 10px; font-size: 12px; color: var(--phos-dim); }
  .opts label { margin-right: 18px; }
  .opts input { width: 70px; }
  #log { height: 150px; overflow-y: auto; white-space: pre-wrap; font-size: 12px; color: var(--phos-dim); }
  #log .warn { color: var(--amber); }
  #log .bad { color: var(--red); }
  table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  th, td { border: 1px solid var(--line); padding: 6px 8px; text-align: left; vertical-align: top; }
  th { color: var(--amber); letter-spacing: .15em; font-size: 11px; cursor: pointer; user-select: none; }
  th:hover { background: #102410; }
  tbody tr.d-row { cursor: pointer; }
  tbody tr.d-row:hover { background: #0d1f0d; }
  tr.detail td { background: #020502; font-size: 11.5px; color: var(--phos-dim); }
  .ep { display: inline-block; margin: 2px 10px 2px 0; }
  .stamp {
    display: inline-block; border: 2px solid; padding: 1px 8px; font-weight: bold;
    letter-spacing: .15em; transform: rotate(-2deg);
  }
  .GENUINE { color: var(--phos); border-color: var(--phos); }
  .IMPOSTOR { color: var(--red); border-color: var(--red); text-shadow: 0 0 8px rgba(255,51,51,.8); }
  .UNKNOWN { color: var(--amber); border-color: var(--amber); }
  .DARK, .ERROR { color: #555; border-color: #555; }
  .flag { color: var(--red); font-size: 11px; display: block; }
  .stat { display: inline-block; margin-right: 26px; }
  .stat b { color: var(--amber); }
  #bar-outer { border: 1px solid var(--line); height: 14px; background: #000; }
  #bar-inner {
    height: 100%; width: 0%; background: var(--phos);
    box-shadow: 0 0 10px rgba(51,255,102,.8); transition: width .2s;
  }
  #wire { height: 140px; overflow-y: auto; font-size: 11px; white-space: pre-wrap; color: var(--phos-dim); }
  #wire .w-ok { color: var(--phos); }
  #wire .w-err { color: #555; }
  .chips { margin-bottom: 10px; }
  .chip {
    display: inline-block; border: 1px solid var(--line); padding: 3px 12px;
    margin: 0 6px 6px 0; cursor: pointer; font-size: 11px; letter-spacing: .15em;
  }
  .chip:hover { border-color: var(--phos); }
  .chip.on { background: var(--phos); color: #000; border-color: var(--phos); font-weight: bold; }
  .charts { display: flex; flex-wrap: wrap; gap: 18px; }
  .chart-box { text-align: center; }
  .chart-box .lbl { font-size: 10px; letter-spacing: .2em; color: var(--phos-dim); margin-top: 4px; }
  canvas { background: #000; border: 1px solid var(--line); }
  .cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; }
  .card { border: 1px solid var(--line); padding: 10px 12px; font-size: 12px; background: #020502; }
  .card .tgt { font-size: 14px; font-weight: bold; }
  .card .muted { color: var(--phos-dim); }
  .cap-note { color: var(--amber); font-size: 11px; margin-top: 8px; }
</style>
</head>
<body class="adv">
<div class="wrap">
  <div class="classif">TOP SECRET // SILICON // NOFORN</div>
  <div class="classif bottom">PROJECT SILICON RECON &mdash; HANDLE VIA COMINT CHANNELS ONLY</div>

  <h1>&#9608; SILICON RECON &#9608;</h1>
  <div class="sub">LLM SERVER FINGERPRINTING CONSOLE &mdash; VLLM / SGLANG / LLAMA.CPP / OLLAMA</div>

  <div class="modebar">
    <button id="mode-simple" class="small">SIMPLE</button>
    <button id="mode-advanced" class="small active">ADVANCED</button>
  </div>

  <div class="panel">
    <h2>&#9656; TARGETING PACKAGE</h2>
    <div class="preset-hint">// SELECT SCAN PROFILE:</div>
    <div class="chips" id="presetchips">
      <span class="chip preset" data-preset="fast">FAST SWEEP</span>
      <span class="chip preset on" data-preset="standard">STANDARD</span>
      <span class="chip preset" data-preset="deep">DEEP SCAN</span>
    </div>
    <div class="preset-hint" style="margin-top:8px">// OR LOAD A TARGET PACK (fills range box):</div>
    <div class="chips pack-row" id="packchips">
      <span class="chip pack" data-pack="coreweave">COREWEAVE</span>
      <span class="chip pack" data-pack="lambda">LAMBDA</span>
      <span class="chip pack" data-pack="vultr">VULTR</span>
      <span class="chip pack" data-pack="hetzner">HETZNER</span>
      <span class="chip pack" data-pack="gcp">GOOGLE CLOUD</span>
      <span class="chip pack" data-pack="azure">AZURE</span>
      <span class="chip pack" data-pack="aws">AWS</span>
      <span class="chip pack" data-pack="allcloud">ALL CLOUDS</span>
    </div>
    <textarea id="targets" placeholder="one target per line:&#10;45.32.114.54:8000&#10;192.0.2.10        (default ports: all framework ports)&#10;203.0.113.0/28    (CIDR, capped at 4096 hosts)"></textarea>
    <div class="hint">// fingerprint only. no inference traffic. collection of open banners is authorized; use of foreign compute is not.</div>
    <div class="chips simp-hide" style="margin-top:10px" id="fwchips">
      <span style="color:var(--phos-dim);font-size:11px;margin-right:8px">FRAMEWORKS:</span>
      <span class="chip on" data-fw="vllm">VLLM</span>
      <span class="chip on" data-fw="llamacpp">LLAMA.CPP</span>
      <span class="chip on" data-fw="sglang">SGLANG</span>
      <span class="chip on" data-fw="ollama">OLLAMA</span>
      <span class="chip on" data-fw="lmstudio">LM STUDIO</span>
      <span class="chip on" data-fw="koboldcpp">KOBOLDCPP</span>
      <span class="chip on" data-fw="tgwui">TEXTGEN-WEBUI</span>
      <span class="chip on" data-fw="tgi">TGI</span>
      <span class="chip on" data-fw="openwebui">OPEN WEBUI</span>
    </div>
    <div class="opts adv-only">
      <label>WORKERS <input type="number" id="opt-workers" value="1000" min="1" max="5000"></label>
      <label>TIMEOUT(s) <input type="number" id="opt-timeout" value="3" min="0.5" max="10" step="0.5"></label>
      <label><input type="checkbox" id="opt-fast" checked> FAST PROFILE</label>
      <label><input type="checkbox" id="opt-enrich" checked> ASN ENRICHMENT</label>
      <label><input type="checkbox" id="opt-exclude-dod" checked> EXCLUDE DoD</label>
      <label><input type="checkbox" id="opt-lean-ports"> LEAN PORTS</label>
      <label><input type="checkbox" id="opt-fanout"> FAN-OUT ±2</label>
      <label><input type="checkbox" id="opt-dedup"> DEDUP (7d)</label>
      <label><input type="checkbox" id="opt-asn-prefilter"> ASN PREFILTER</label>
    </div>
    <div class="adv-only" style="margin-top:10px; border-top:1px dashed #143; padding-top:8px">
      <div class="hint">// SCAN STRATEGY (high-yield optimizations):</div>
      <label><input type="checkbox" id="opt-progressive" checked> PROGRESSIVE DEPTH</label>
      <label><input type="checkbox" id="opt-banner" checked> BANNER PREFILTER</label>
      <label><input type="checkbox" id="opt-adaptive" checked> ADAPTIVE TIMEOUT</label>
      <label><input type="checkbox" id="opt-contentdedup" checked> CONTENT DEDUP</label>
      <label><input type="checkbox" id="opt-diff"> DIFF MODE</label>
      <label><input type="checkbox" id="opt-ptr" checked> PTR ENRICH</label>
      <label><input type="checkbox" id="opt-ct"> CT SEED</label>
      <label><input type="checkbox" id="opt-shodan"> SHODAN SEED</label>
      <div class="hint">// progressive: TCP-sweep one port first, deep-probe only live hosts (up to 160x fewer probes on big ranges). banner: skip non-HTTP services (SSH/SMTP/RDP) on open ports. adaptive: shrink timeout to 3× P95 after first 200 probes. content-dedup: skip reclassifying ≥3 byte-identical responses (CDN/LB clusters). diff: only re-classify hosts whose fingerprint changed since last scan. ptr: reverse-DNS every live host, surfaces fleet hostnames. ct: pull pre-curated hosts from crt.sh (ollama/vllm/sglang certs). shodan: pull pre-curated open-port lists from Shodan API.</div>
    </div>
    <div class="adv-only" style="margin-top:10px">
      <div class="hint">EXCLUDE CIDRS (one per line, e.g. gov/mil ranges):</div>
      <textarea id="excludes" style="height:52px" placeholder="198.51.100.0/24"></textarea>
    </div>
    <button id="go">Initiate Scan</button>
    <button id="abort" class="danger">Abort Scan</button>
    <button id="export">Export JSONL</button>
    <button id="exportcsv">Export CSV</button>
    <button id="retarget" style="background:var(--amber);color:#000">⟳ Retarget Live</button>
  </div>

  <div class="panel simp-hide">
    <h2>&#9656; CIDR RANGE BUILDER</h2>
    <div>
      <input type="text" id="b-ip" value="45.32.114.0" style="width:150px">
      <span style="color:var(--phos-dim)">/</span>
      <input type="number" id="b-prefix" value="24" min="8" max="32" style="width:60px">
      <span id="b-info" class="hint" style="margin-left:10px"></span>
      <br>
      <button id="b-add" class="small">ADD RANGE TO TARGETS</button>
      <button id="b-next" class="small">NEXT SUBNET &raquo;</button>
    </div>
    <div style="margin-top:12px">
      <span style="font-size:11px;color:var(--phos-dim)">COUNTRY:</span>
      <input type="text" id="b-cc" value="US" maxlength="2" style="width:50px">
      <span style="font-size:11px;color:var(--phos-dim)">MAX RANGES:</span>
      <input type="number" id="b-limit" value="256" min="1" max="5000" style="width:80px">
      <button id="b-fetch" class="small">FETCH COUNTRY RANGES (RIR)</button>
      <div class="hint">// pulls real allocations from RIR delegated stats, appends to targeting package. hard cap: 100,000 targets per scan.</div>
    </div>
    <div style="margin-top:12px">
      <span style="font-size:11px;color:var(--phos-dim)">ASN:</span>
      <input type="text" id="b-asn" placeholder="20473" style="width:90px">
      <button id="b-asn-fetch" class="small">FETCH ASN RANGES</button>
      <button id="b-expand" class="small">EXPAND HITS TO /24</button>
      <div class="chips" id="asnchips" style="margin-top:8px">
        <span style="color:var(--phos-dim);font-size:11px;margin-right:8px">PRESETS:</span>
        <span class="chip" data-asn="20473">VULTR</span>
        <span class="chip" data-asn="14061">DIGITALOCEAN</span>
        <span class="chip" data-asn="24940">HETZNER</span>
        <span class="chip" data-asn="16276">OVH</span>
        <span class="chip" data-asn="51167">CONTABO</span>
        <span class="chip" data-asn="63949">LINODE</span>
        <span class="chip" data-asn="16509">AWS</span>
        <span class="chip" data-asn="396982">GCP</span>
        <span class="chip" data-asn="8075">AZURE</span>
        <span class="chip" data-asn="31898">ORACLE</span>
      </div>
      <div class="hint">// LLM servers live in VPS/GPU-cloud space, not residential. select presets or enter an ASN. EXPAND HITS re-targets the /24 of every live hit.</div>
    </div>
  </div>

  <div class="panel adv-only">
    <h2>&#9656; IMPORT SCAN RESULTS &mdash; MASSCAN / ZMAP</h2>
    <textarea id="import" style="height:64px" placeholder='masscan -oG: Host: 1.2.3.4 () Ports: 8000/open/tcp//http//&#10;masscan JSON: [{"ip":"1.2.3.4","ports":[{"port":8000,"status":"open"}]}]&#10;zmap CSV / plain: 1.2.3.4,8000 or 1.2.3.4:8000'></textarea>
    <input type="file" id="import-file" accept=".txt,.json,.csv,.log" style="margin-top:8px;font-size:11px;color:var(--phos-dim)">
    <br><button id="import-go" class="small">PARSE &amp; APPEND TO TARGETS</button>
    <span id="import-info" class="hint" style="margin-left:10px"></span>
  </div>

  <div class="panel">
    <h2>&#9656; SIGNAL PROGRESS</h2>
    <div id="bar-outer"><div id="bar-inner"></div></div>
    <div id="bar-text" class="hint">0 / 0 targets &mdash; 0 requests</div>
    <div class="chart-box" style="margin-top:10px">
      <canvas id="spark" width="1100" height="70"></canvas>
      <div class="lbl">REQUESTS / SECOND</div>
    </div>
  </div>

  <div class="panel adv-only">
    <h2>&#9656; ANALYSIS</h2>
    <div class="charts">
      <div class="chart-box"><canvas id="donut" width="180" height="180"></canvas><div class="lbl">VERDICT MIX</div></div>
      <div class="chart-box"><canvas id="ports" width="300" height="180"></canvas><div class="lbl">LIVE HITS BY PORT</div></div>
      <div class="chart-box"><canvas id="latency" width="300" height="180"></canvas><div class="lbl">LATENCY DISTRIBUTION (MS)</div></div>
      <div class="chart-box"><div id="asnagg" style="width:340px;height:180px;overflow-y:auto;text-align:left;font-size:11px;background:#000;border:1px solid var(--line);padding:6px 8px"></div><div class="lbl">TOP NETWORKS (I/G/U)</div></div>
    </div>
  </div>

  <div class="panel adv-only">
    <h2>&#9656; FLEET CLUSTERS &mdash; SHARED INVENTORY HASH</h2>
    <div id="fleets" class="hint">no fleets detected.</div>
  </div>

  <div class="panel simp-hide">
    <h2>&#9656; LIVE WIRE &mdash; EVERY REQUEST</h2>
    <div id="wire"></div>
  </div>

  <div class="panel">
    <h2>&#9656; FILTERS</h2>
    <div class="chips" id="chips">
      <span class="chip on" data-v="ALL">ALL</span>
      <span class="chip" data-v="GENUINE">GENUINE</span>
      <span class="chip" data-v="IMPOSTOR">IMPOSTOR</span>
      <span class="chip" data-v="UNKNOWN">UNKNOWN</span>
      <span class="chip" data-v="DARK">DARK</span>
    </div>
    <input type="text" id="ftext" placeholder="search target / model / flag..." style="width:320px">
    <select id="fproduct" class="simp-hide"><option value="ALL">ALL PRODUCTS</option></select>
    <select id="fnet" class="simp-hide">
      <option value="ALL">ALL NET TYPES</option>
      <option value="DATACENTER">DATACENTER</option>
      <option value="RESIDENTIAL">RESIDENTIAL</option>
      <option value="UNKNOWN">UNKNOWN ASN</option>
    </select>
    <span id="fcount" class="hint" style="margin-left:12px"></span>
  </div>

  <div class="panel">
    <h2>&#9656; OPERATIONS LOG</h2>
    <div id="log">[SYS] silicon recon console ready. awaiting targeting package.
</div>
  </div>

  <div class="panel">
    <h2>&#9656; COLLECTION SUMMARY</h2>
    <div id="stats"><span class="stat">PROBED: <b>0</b></span><span class="stat">GENUINE: <b>0</b></span><span class="stat">IMPOSTOR: <b>0</b></span><span class="stat">UNKNOWN: <b>0</b></span><span class="stat">DARK: <b>0</b></span></div>
  </div>

  <div class="panel adv-only">
    <h2>&#9656; ARCHIVE &mdash; LAST 10 SCANS</h2>
    <select id="hist" style="min-width:340px"></select>
    <button id="hist-load" class="small">Load</button>
    <button id="hist-refresh" class="small">Refresh List</button>
  </div>

  <div class="panel">
    <h2>&#9656; DOSSIERS</h2>
    <div id="dossiers">
      <table id="dtable">
        <thead><tr>
          <th data-k="target">TARGET</th><th data-k="product">PRODUCT</th><th data-k="verdict">VERDICT</th>
          <th data-k="version">VERSION</th><th>MODEL / INVENTORY</th><th>ASN</th><th data-k="score">SCORE</th><th>FLAGS</th><th data-k="latency_ms">MS</th>
        </tr></thead>
        <tbody id="rows"></tbody>
      </table>
      <div id="cards" class="cards" style="display:none"></div>
    </div>
    <div id="capnote" class="cap-note"></div>
  </div>

  <div class="classif">TOP SECRET // SILICON // NOFORN</div>
</div>
<script>
const PATHS = ["/","/props","/health","/version","/v1/models","/get_model_info","/get_server_info","/api/tags","/api/version","/api/v0/models","/api/extra/version","/api/v1/model","/v1/internal/model/info","/info","/api/config"];
const RENDER_CAP = 500;
const S = {
  mode: 'advanced', results: [], total: 0, done: 0, reqs: 0,
  t0: 0, timer: null, scanId: null, ctrl: null,
  filter: {verdict: 'ALL', text: '', product: 'ALL', net: 'ALL'},
  sortKey: null, sortAsc: true, rps: [], lastReqs: 0, chartsDirty: false,
  rowsDirty: false, byTarget: {},
};

const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const log = (msg, cls) => {
  const el = $('log');
  const line = document.createElement('div');
  if (cls) line.className = cls;
  line.textContent = `[${new Date().toISOString().substr(11,8)}Z] ${msg}`;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
};

// ---------- mode ----------
function setMode(m) {
  S.mode = m;
  document.body.classList.toggle('adv', m === 'advanced');
  $('mode-simple').classList.toggle('active', m === 'simple');
  $('mode-advanced').classList.toggle('active', m === 'advanced');
  $('dtable').style.display = m === 'advanced' ? '' : 'none';
  $('cards').style.display = m === 'simple' ? '' : 'none';
  renderDossiers();
}
$('mode-simple').onclick = () => setMode('simple');
$('mode-advanced').onclick = () => setMode('advanced');

// ---------- scan presets ----------
const PRESETS = {
  fast:     {workers:2000, timeout:2,  fast:true,  enrich:false, progressive:true, banner:true,  adaptive:true,  contentdedup:true, ptr:false, dedup:true,  diff:false, dod:true,  lean:true},
  standard: {workers:1000, timeout:3,  fast:true,  enrich:true,  progressive:true, banner:true,  adaptive:true,  contentdedup:true, ptr:true,  dedup:false, diff:false, dod:true,  lean:false},
  deep:     {workers:500,  timeout:4.5, fast:false, enrich:true,  progressive:false, banner:true, adaptive:false, contentdedup:true, ptr:true,  dedup:false, diff:true,  dod:false, lean:false},
};
const PRESET_HINTS = {
  fast:     'FAST SWEEP — broad reach. lean ports, DoD excluded, progressive pre-sweep, 7-day dedup. best for big ranges.',
  standard: 'STANDARD — balanced fingerprinting. all 9 frameworks, full enrichment, every high-yield optimization. recommended.',
  deep:     'DEEP SCAN — thorough single-target audit. slow profile, long timeout, diff mode, no prefilter. best for one suspect host.',
};
function applyPreset(name) {
  const p = PRESETS[name]; if (!p) return;
  document.querySelectorAll('#presetchips .chip').forEach(c =>
    c.classList.toggle('on', c.dataset.preset === name));
  $('opt-workers').value = p.workers;
  $('opt-timeout').value = p.timeout;
  $('opt-fast').checked = p.fast;
  $('opt-enrich').checked = p.enrich;
  $('opt-exclude-dod').checked = p.dod;
  $('opt-lean-ports').checked = p.lean;
  $('opt-progressive').checked = p.progressive;
  $('opt-banner').checked = p.banner;
  $('opt-adaptive').checked = p.adaptive;
  $('opt-contentdedup').checked = p.contentdedup;
  $('opt-ptr').checked = p.ptr;
  $('opt-dedup').checked = p.dedup;
  $('opt-diff').checked = p.diff;
  log(PRESET_HINTS[name], 'warn');
}
document.querySelectorAll('#presetchips .chip').forEach(ch => {
  ch.onclick = () => applyPreset(ch.dataset.preset);
});

// ---------- target packs (cloud providers → announced prefixes) ----------
const PACKS = {
  coreweave: {label:'COREWEAVE', asns:['33425'], hint:'GPU-focused cloud. prime vLLM/SGLang host territory.'},
  lambda:    {label:'LAMBDA',    asns:['398090'], hint:'Lambda Labs GPU cloud. inference clusters + on-demand boxes.'},
  vultr:     {label:'VULTR',     asns:['20473'], hint:'cheap VPS fleet. lots of self-hosted llama.cpp/ollama.'},
  hetzner:   {label:'HETZNER',   asns:['24940','47583'], hint:'EU dedicated servers. budget GPU rentals proliferating.'},
  gcp:       {label:'GCP',       asns:['15169','396982'], hint:'Google Cloud. Vertex + GKE inference endpoints. huge range.'},
  azure:     {label:'AZURE',     asns:['8075'], hint:'Microsoft Azure. Azure ML / OpenAI service endpoints.'},
  aws:       {label:'AWS',       asns:['16509','14618'], hint:'Amazon Web Services. SageMaker / Bedrock + EC2 inference.'},
  allcloud:  {label:'ALL CLOUDS', asns:['33425','398090','20473','24940','47583','15169','396982','8075','16509','14618'],
              hint:'every cloud provider at once. very large. pair with FAST SWEEP + dedup.'},
};
async function loadPack(name) {
  const pk = PACKS[name]; if (!pk) return;
  const chip = document.querySelector(`#packchips .chip[data-pack="${name}"]`);
  log(`loading ${pk.label} target pack (${pk.asns.length} ASN${pk.asns.length>1?'s':''})...`, 'warn');
  if (chip) chip.style.opacity = '0.4';
  let added = 0;
  const errors = [];
  for (const asn of pk.asns) {
    try {
      const r = await fetch(`/api/asn-prefixes?asn=${asn}`);
      const d = await r.json();
      if (d.error) { errors.push(`AS${asn}: ${d.error}`); continue; }
      if (d.prefixes && d.prefixes.length) { appendTargets(d.prefixes); added += d.prefixes.length; }
    } catch (e) { errors.push(`AS${asn}: ${e}`); }
  }
  if (chip) chip.style.opacity = '';
  if (added) log(`${pk.label}: ${added} prefix(es) loaded into targeting package. ${pk.hint}`);
  else log(`${pk.label}: no prefixes returned.`, 'bad');
  errors.forEach(e => log(`  ${e}`, 'bad'));
}
document.querySelectorAll('#packchips .chip').forEach(ch => {
  ch.onclick = () => loadPack(ch.dataset.pack);
});

// ---------- filters ----------
document.querySelectorAll('#chips .chip').forEach(ch => {
  ch.onclick = () => {
    document.querySelectorAll('#chips .chip').forEach(c => c.classList.remove('on'));
    ch.classList.add('on');
    S.filter.verdict = ch.dataset.v;
    renderDossiers();
  };
});
$('ftext').oninput = () => { S.filter.text = $('ftext').value.toLowerCase(); renderDossiers(); };
$('fproduct').onchange = () => { S.filter.product = $('fproduct').value; renderDossiers(); };
$('fnet').onchange = () => { S.filter.net = $('fnet').value; renderDossiers(); };

// framework chips (multi-select toggle)
document.querySelectorAll('#fwchips .chip').forEach(ch => {
  ch.onclick = () => { ch.classList.toggle('on'); updateBuilder(); };
});
function selectedFrameworks() {
  return [...document.querySelectorAll('#fwchips .chip.on')].map(c => c.dataset.fw);
}

// ---------- CIDR builder ----------
const FW_PORTS = {vllm:[8000,8001], llamacpp:[8080], sglang:[30000], ollama:[11434], lmstudio:[1234], koboldcpp:[5001], tgwui:[5000], tgi:[80,3000], openwebui:[3000]};
const ipToInt = ip => ip.split('.').reduce((a, o) => (a << 8) + (+o), 0) >>> 0;
const intToIp = n => [(n>>>24)&255, (n>>>16)&255, (n>>>8)&255, n&255].join('.');

function builderPorts() {
  const fw = selectedFrameworks();
  const set = new Set();
  (fw.length ? fw : Object.keys(FW_PORTS)).forEach(f => FW_PORTS[f].forEach(p => set.add(p)));
  return [...set];
}
function updateBuilder() {
  const ip = $('b-ip').value.trim() || '0.0.0.0';
  const p = Math.min(32, Math.max(8, +$('b-prefix').value || 24));
  const hosts = p === 32 ? 1 : p === 31 ? 2 : Math.pow(2, 32 - p) - 2;
  const np = builderPorts().length;
  $('b-info').textContent =
    `${ip}/${p} — ${hosts.toLocaleString()} hosts — ~${(hosts * np).toLocaleString()} probes (${np} port(s))`;
}
function appendTargets(lines) {
  const ta = $('targets');
  const cur = ta.value.trim();
  ta.value = (cur ? cur + '\n' : '') + lines.join('\n');
}
$('b-ip').oninput = updateBuilder;
$('b-prefix').oninput = updateBuilder;
$('b-add').onclick = () => {
  const p = Math.min(32, Math.max(8, +$('b-prefix').value || 24));
  appendTargets([`${$('b-ip').value.trim()}/${p}`]);
  log(`range added: ${$('b-ip').value.trim()}/${p}`);
};
$('b-next').onclick = () => {
  const p = Math.min(32, Math.max(8, +$('b-prefix').value || 24));
  const block = Math.pow(2, 32 - p);
  try {
    $('b-ip').value = intToIp((ipToInt($('b-ip').value.trim()) + block) >>> 0);
  } catch (e) { log('bad base IP', 'bad'); }
  updateBuilder();
};
$('b-fetch').onclick = async () => {
  const cc = ($('b-cc').value.trim() || 'US').toUpperCase();
  const limit = Math.min(5000, Math.max(1, +$('b-limit').value || 256));
  log(`fetching ${cc} allocations from RIR delegated stats...`);
  try {
    const r = await fetch(`/api/country-cidrs?cc=${cc}&limit=${limit}`);
    const d = await r.json();
    if (d.error) { log('RIR FETCH FAILED: ' + d.error, 'bad'); return; }
    appendTargets(d.cidrs);
    log(`${d.cidrs.length} ${cc} range(s) appended (${d.total_ranges} total allocated${d.truncated ? ', truncated by limit' : ''}).`);
  } catch (e) { log('RIR FETCH FAILED: ' + e, 'bad'); }
};
updateBuilder();

// ---------- ASN targeting ----------
document.querySelectorAll('#asnchips .chip').forEach(ch => {
  ch.onclick = () => ch.classList.toggle('on');
});
$('b-asn-fetch').onclick = async () => {
  const asns = [...document.querySelectorAll('#asnchips .chip.on')].map(c => c.dataset.asn);
  const free = $('b-asn').value.trim().replace(/^AS/i, '');
  if (free && /^\d+$/.test(free)) asns.push(free);
  if (!asns.length) { log('no ASN selected.', 'warn'); return; }
  for (const asn of asns) {
    log(`fetching announced prefixes for AS${asn} (RIPEstat)...`);
    try {
      const r = await fetch(`/api/asn-prefixes?asn=${asn}`);
      const d = await r.json();
      if (d.error) { log(`AS${asn}: ${d.error}`, 'bad'); continue; }
      appendTargets(d.prefixes);
      log(`AS${asn} ${d.name}: ${d.prefixes.length} prefix(es) appended (${d.total} announced${d.truncated ? ', truncated' : ''}).`);
    } catch (e) { log(`AS${asn} fetch failed: ${e}`, 'bad'); }
  }
};
$('b-expand').onclick = () => {
  const nets = new Set();
  for (const d of S.results) {
    if (d.verdict === 'DARK' || d.verdict === 'ERROR') continue;
    const m = d.target.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}:/);
    if (m) nets.add(`${m[1]}.0/24`);
  }
  if (!nets.size) { log('no live hits to expand.', 'warn'); return; }
  appendTargets([...nets]);
  log(`neighbor expansion: ${nets.size} /24 range(s) appended from live hits.`);
};

// ---------- masscan / zmap import ----------
function parseImport(text) {
  const out = new Set();
  try {
    const j = JSON.parse(text);
    if (Array.isArray(j)) {
      for (const e of j) {
        const ip = e && (e.ip || e.address);
        for (const p of (e && e.ports) || []) {
          if (ip && p && p.port) out.add(`${ip}:${p.port}`);
        }
      }
      if (out.size) return [...out];
    }
  } catch (_) {}
  for (const line of text.split('\n')) {
    const l = line.trim();
    if (!l || l.startsWith('#')) continue;
    let m = l.match(/^Host:\s+(\S+)\s+\(\)\s+Ports:\s+(.*)$/);  // masscan -oG
    if (m) {
      for (const seg of m[2].split(',')) {
        const pm = seg.trim().match(/^(\d+)\/open/);
        if (pm) out.add(`${m[1]}:${pm[1]}`);
      }
      continue;
    }
    m = l.match(/(\d{1,3}(?:\.\d{1,3}){3})\s*[: ,]\s*(\d{1,5})/);  // ip:port | ip,port | ip port
    if (m && +m[2] <= 65535) out.add(`${m[1]}:${m[2]}`);
  }
  return [...out];
}
$('import-go').onclick = () => {
  const found = parseImport($('import').value);
  if (!found.length) { $('import-info').textContent = 'no targets recognized'; return; }
  appendTargets(found);
  $('import-info').textContent = `${found.length} endpoint(s) appended`;
  log(`import: ${found.length} endpoint(s) appended to targeting package.`);
};
$('import-file').onchange = ev => {
  const f = ev.target.files[0];
  if (!f) return;
  const r = new FileReader();
  r.onload = () => { $('import').value = r.result; };
  r.readAsText(f);
};

// ---------- fleet clusters + ASN aggregate ----------
function updateIntel() {
  const byHash = {};
  for (const d of S.results) {
    if (!d.inventory_hash || d.verdict === 'DARK' || d.verdict === 'ERROR') continue;
    (byHash[d.inventory_hash] = byHash[d.inventory_hash] || []).push(d);
  }
  const fleets = Object.entries(byHash)
    .filter(([, arr]) => new Set(arr.map(d => d.target)).size >= 2)
    .sort((a, b) => b[1].length - a[1].length);
  $('fleets').innerHTML = fleets.length ? fleets.slice(0, 20).map(([h, arr]) => {
    const asns = [...new Set(arr.map(d => d.asn).filter(Boolean))];
    const t = {};
    arr.forEach(d => t[d.verdict] = (t[d.verdict] || 0) + 1);
    return `<div style="margin-bottom:8px;border:1px solid var(--line);padding:6px 8px">` +
      `<b style="color:var(--amber)">FLEET #${esc(h)}</b> — ${arr.length} host(s)` +
      ` — <span style="color:var(--red)">${t.IMPOSTOR || 0}I</span>/<span style="color:var(--phos)">${t.GENUINE || 0}G</span>/<span style="color:#777">${t.UNKNOWN || 0}U</span>` +
      (asns.length ? ` — AS ${asns.map(esc).join(', ')}` : '') +
      `<br><span style="color:var(--phos-dim)">${arr.slice(0, 8).map(d => esc(d.target)).join(', ')}${arr.length > 8 ? ' …' : ''}</span></div>`;
  }).join('') : 'no fleets detected.';
  const byAsn = {};
  for (const d of S.results) {
    if (!d.asn) continue;
    const k = `AS${d.asn} ${d.as_name || ''}`;
    const e = byAsn[k] = byAsn[k] || {I: 0, G: 0, U: 0, total: 0};
    e.total++;
    if (d.verdict === 'GENUINE') e.G++;
    else if (d.verdict === 'IMPOSTOR') e.I++;
    else e.U++;
  }
  const rows = Object.entries(byAsn).sort((a, b) => b[1].total - a[1].total).slice(0, 30);
  $('asnagg').innerHTML = rows.map(([k, e]) =>
    `<div>${esc(k.slice(0, 40))} — <span style="color:var(--red)">${e.I}I</span>/<span style="color:var(--phos)">${e.G}G</span>/<span style="color:#555">${e.U}U</span></div>`
  ).join('') || '<span class="hint">no ASN data yet.</span>';
}

function matches(d) {
  if (S.filter.verdict !== 'ALL') {
    const v = d.verdict === 'ERROR' ? 'DARK' : d.verdict;
    if (v !== S.filter.verdict) return false;
  }
  if (S.filter.product !== 'ALL' && d.product !== S.filter.product) return false;
  if (S.filter.net !== 'ALL' && (d.net_type || 'UNKNOWN') !== S.filter.net) return false;
  if (S.filter.text) {
    const hay = (d.target + ' ' + d.product + ' ' + (d.model||'') + ' ' +
                 (d.version||'') + ' ' + (d.as_name||'') + ' ' +
                 (d.flags||[]).join(' ')).toLowerCase();
    if (!hay.includes(S.filter.text)) return false;
  }
  return true;
}

function refreshProductSelect() {
  const sel = $('fproduct');
  const cur = sel.value;
  const prods = [...new Set(S.results.map(r => r.product))].sort();
  sel.innerHTML = '<option value="ALL">ALL PRODUCTS</option>' +
    prods.map(p => `<option value="${esc(p)}">${esc(p)}</option>`).join('');
  sel.value = prods.includes(cur) ? cur : 'ALL';
}

// ---------- rendering ----------
function flagHtml(d) {
  return (d.flags || []).map(f => `<span class="flag">&#9888; ${esc(f)}</span>`).join('');
}
function invHtml(d) {
  if (d.models_served && d.models_served.length)
    return (d.model ? `<b>${esc(d.model)}</b><br>` : '') +
      `<span style="color:var(--phos-dim)">${d.models_served.length} model(s) listed</span>`;
  return esc(d.model || d.error || '\u2014');
}
function asnHtml(d) {
  if (!d.asn) return '<span style="color:#555">&mdash;</span>';
  const col = d.net_type === 'DATACENTER' ? 'var(--amber)'
            : d.net_type === 'RESIDENTIAL' ? 'var(--phos)' : '#555';
  return `<span style="color:${col}">AS${esc(d.asn)}</span><br>` +
    `<span style="color:var(--phos-dim);font-size:10.5px">${esc(d.as_name || '')}</span>`;
}
function sortedResults() {
  const items = S.results.filter(matches);
  if (S.sortKey) {
    const k = S.sortKey, dir = S.sortAsc ? 1 : -1;
    items.sort((a, b) => {
      const va = a[k] ?? '', vb = b[k] ?? '';
      return (typeof va === 'number' && typeof vb === 'number')
        ? (va - vb) * dir
        : String(va).localeCompare(String(vb)) * dir;
    });
  }
  return items;
}
function renderDossiers() {
  const items = sortedResults();
  $('fcount').textContent = `${items.length} shown / ${S.results.length} total`;
  const capped = items.slice(0, RENDER_CAP);
  $('capnote').textContent = items.length > RENDER_CAP
    ? `render capped: showing ${RENDER_CAP} of ${items.length} matches (filter to narrow)` : '';
  if (S.mode === 'simple') {
    $('cards').innerHTML = capped.map(d =>
      `<div class="card"><div class="tgt">${esc(d.target)}</div>` +
      `<div class="muted">${esc(d.product)}${d.version ? ' ' + esc(d.version) : ''}</div>` +
      `<div style="margin:6px 0"><span class="stamp ${d.verdict}">${d.verdict}</span></div>` +
      `<div>${d.model ? esc(d.model) : '<span class="muted">&mdash;</span>'}</div>` +
      (d.asn ? `<div class="muted">AS${esc(d.asn)} ${esc(d.as_name || '')} [${esc(d.net_type || '?')}]</div>` : '') +
      (d.flags && d.flags.length ? `<div class="muted">${d.flags.length} flag(s)</div>` : '') +
      `</div>`).join('');
  } else {
    const tb = $('rows');
    tb.innerHTML = '';
    for (const d of capped) tb.appendChild(rowFor(d));
  }
}
function rowFor(d) {
  const tr = document.createElement('tr');
  tr.className = 'd-row';
  tr.innerHTML = `<td>${esc(d.target)}</td><td>${esc(d.product)}</td>` +
    `<td><span class="stamp ${d.verdict}">${d.verdict}</span></td>` +
    `<td>${esc(d.version || '\u2014')}</td><td>${invHtml(d)}</td>` +
    `<td>${asnHtml(d)}</td>` +
    `<td style="color:${d.score >= 40 ? 'var(--red)' : d.score > 0 ? 'var(--amber)' : '#555'}">${d.score || 0}</td>` +
    `<td>${flagHtml(d) || '\u2014'}</td><td>${d.latency_ms ?? '\u2014'}</td>`;
  tr.onclick = () => toggleDetail(tr, d);
  return tr;
}
function toggleDetail(tr, d) {
  const next = tr.nextSibling;
  if (next && next.classList && next.classList.contains('detail')) { next.remove(); return; }
  const det = document.createElement('tr');
  det.className = 'detail';
  const eps = PATHS.map(p => {
    const e = (d.endpoints || {})[p];
    const st = e ? (e.status || (d.error || 'FAIL')) : '?';
    const cls = e && e.status && e.status < 400 ? 'w-ok' : 'w-err';
    return `<span class="ep ${cls}">${p}: ${st}</span>`;
  }).join('');
  det.innerHTML = `<td colspan="9"><b>ENDPOINT MATRIX</b> &mdash; ${esc(d.target)}<br>${eps}` +
    (d.bgp_prefix ? `<br>BGP PREFIX: ${esc(d.bgp_prefix)} &mdash; AS${esc(d.asn)} ${esc(d.as_name || '')} [${esc(d.net_type || '?')}]` : '') +
    (d.error ? `<br><span class="w-err">error: ${esc(d.error)}</span>` : '') + `</td>`;
  tr.parentNode.insertBefore(det, tr.nextSibling);
}

// sorting
document.querySelectorAll('#dtable th[data-k]').forEach(th => {
  th.onclick = () => {
    const k = th.dataset.k;
    if (S.sortKey === k) S.sortAsc = !S.sortAsc;
    else { S.sortKey = k; S.sortAsc = true; }
    renderDossiers();
  };
});

// ---------- progress / stats ----------
function updateProgress() {
  const pct = S.total ? Math.round(S.done / S.total * 100) : 0;
  $('bar-inner').style.width = pct + '%';
  $('bar-text').textContent = `${S.done} / ${S.total} targets — ${S.reqs} requests`;
}
function updateStats() {
  const t = {};
  for (const d of S.results) t[d.verdict] = (t[d.verdict] || 0) + 1;
  const g = k => t[k] || 0;
  $('stats').innerHTML =
    `<span class="stat">PROBED: <b>${S.results.length}</b></span>` +
    `<span class="stat">GENUINE: <b>${g('GENUINE')}</b></span>` +
    `<span class="stat">IMPOSTOR: <b>${g('IMPOSTOR')}</b></span>` +
    `<span class="stat">UNKNOWN: <b>${g('UNKNOWN')}</b></span>` +
    `<span class="stat">DARK: <b>${g('DARK') + g('ERROR')}</b></span>`;
}
function wireLine(ev) {
  const el = $('wire');
  const line = document.createElement('div');
  line.className = ev.status ? (ev.status < 400 ? 'w-ok' : '') : 'w-err';
  line.textContent = `${ev.target}  GET ${ev.path}  ->  ${ev.status || ev.err || 'FAIL'}`;
  el.appendChild(line);
  while (el.children.length > 60) el.removeChild(el.firstChild);
  el.scrollTop = el.scrollHeight;
}
function maybeWire(ev) {
  // on large scans, sample the wire so the DOM survives 100k+ events
  if (S.total > 2000 && S.reqs % Math.ceil(S.total / 2000) !== 0) return;
  wireLine(ev);
}

// ---------- charts ----------
function drawSpark() {
  const c = $('spark'), ctx = c.getContext('2d');
  ctx.clearRect(0, 0, c.width, c.height);
  if (S.rps.length < 2) return;
  const max = Math.max(...S.rps, 1);
  ctx.strokeStyle = '#33ff66'; ctx.lineWidth = 1.5; ctx.beginPath();
  S.rps.forEach((v, i) => {
    const x = i / (S.rps.length - 1) * c.width;
    const y = c.height - 4 - (v / max) * (c.height - 8);
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.stroke();
  ctx.fillStyle = '#1a9933'; ctx.font = '10px monospace';
  ctx.fillText(`peak ${max}/s`, 6, 12);
}
function drawDonut() {
  const c = $('donut'), ctx = c.getContext('2d');
  ctx.clearRect(0, 0, c.width, c.height);
  const t = {};
  for (const d of S.results) {
    const v = d.verdict === 'ERROR' ? 'DARK' : d.verdict;
    t[v] = (t[v] || 0) + 1;
  }
  const total = S.results.length || 1;
  const cols = {GENUINE: '#33ff66', IMPOSTOR: '#ff3333', UNKNOWN: '#ffb000', DARK: '#2a4a2a'};
  let a = -Math.PI / 2;
  const cx = c.width / 2, cy = c.height / 2, r = 70, ir = 42;
  for (const [k, col] of Object.entries(cols)) {
    const frac = (t[k] || 0) / total;
    if (frac <= 0) continue;
    ctx.beginPath(); ctx.fillStyle = col;
    ctx.arc(cx, cy, r, a, a + frac * 2 * Math.PI);
    ctx.arc(cx, cy, ir, a + frac * 2 * Math.PI, a, true);
    ctx.closePath(); ctx.fill();
    a += frac * 2 * Math.PI;
  }
  ctx.fillStyle = '#33ff66'; ctx.font = '11px monospace'; ctx.textAlign = 'center';
  ctx.fillText(String(S.results.length), cx, cy + 4); ctx.textAlign = 'left';
}
function drawPorts() {
  const c = $('ports'), ctx = c.getContext('2d');
  ctx.clearRect(0, 0, c.width, c.height);
  const hits = {};
  for (const d of S.results) {
    if (d.verdict === 'DARK' || d.verdict === 'ERROR') continue;
    const p = d.target.split(':').pop();
    hits[p] = (hits[p] || 0) + 1;
  }
  const keys = Object.keys(hits).sort();
  if (!keys.length) return;
  const max = Math.max(...Object.values(hits));
  keys.forEach((k, i) => {
    const y = 18 + i * 30;
    ctx.fillStyle = '#1a9933'; ctx.font = '11px monospace';
    ctx.fillText(k, 4, y + 11);
    ctx.fillStyle = '#33ff66';
    ctx.fillRect(60, y, (hits[k] / max) * (c.width - 110), 14);
    ctx.fillText(String(hits[k]), 66 + (hits[k] / max) * (c.width - 110), y + 11);
  });
}
function drawLatency() {
  const c = $('latency'), ctx = c.getContext('2d');
  ctx.clearRect(0, 0, c.width, c.height);
  const buckets = [0, 0, 0, 0, 0];
  const labels = ['<200', '200-500', '500-1k', '1k-3k', '>3k'];
  for (const d of S.results) {
    const ms = d.latency_ms;
    if (ms == null) continue;
    buckets[ms < 200 ? 0 : ms < 500 ? 1 : ms < 1000 ? 2 : ms < 3000 ? 3 : 4]++;
  }
  const max = Math.max(...buckets, 1);
  buckets.forEach((v, i) => {
    const x = 10 + i * 58;
    const h = (v / max) * 130;
    ctx.fillStyle = '#33ff66'; ctx.fillRect(x, 150 - h, 44, h);
    ctx.fillStyle = '#1a9933'; ctx.font = '10px monospace';
    ctx.fillText(labels[i], x, 164);
    ctx.fillText(String(v), x, 146 - h);
  });
}
function drawCharts() { drawSpark(); drawDonut(); drawPorts(); drawLatency(); }

function tick() {
  const el = (Date.now() - S.t0) / 1000;
  const eta = S.done ? Math.round(el / S.done * (S.total - S.done)) : 0;
  const rate = (S.reqs - S.lastReqs) * 2;
  S.lastReqs = S.reqs;
  S.rps.push(rate); if (S.rps.length > 200) S.rps.shift();
  $('bar-text').textContent =
    `${S.done} / ${S.total} targets — ${S.reqs} requests — ${Math.round(el)}s elapsed` +
    (S.done && S.done < S.total ? ` — ETA ${eta}s` : '');
  drawSpark();
  if (S.chartsDirty) { drawDonut(); drawPorts(); drawLatency(); updateIntel(); S.chartsDirty = false; }
  if (S.rowsDirty) { renderDossiers(); S.rowsDirty = false; }

  // Periodic signal feed update so console never sits silent
  const now = Date.now();
  if (!S.lastLogTime) S.lastLogTime = now;
  if (now - S.lastLogTime >= 3000) {
    S.lastLogTime = now;
    if (S.total > 0) {
      let genuine = 0, impostor = 0;
      for (const d of S.results) {
        if (d.verdict === 'GENUINE') genuine++;
        else if (d.verdict === 'IMPOSTOR') impostor++;
      }
      const dark = S.results.length - genuine - impostor;
      const pct = Math.round(S.done / S.total * 100);
      log(`FEED UPDATE: ${S.done.toLocaleString()} / ${S.total.toLocaleString()} targets (${pct}%) — ${rate} req/s — hits: ${genuine} genuine, ${impostor} impostor | dark/unknown: ${dark.toLocaleString()}`);
    } else {
      log(`AWAITING TARGETING PACKAGE... (${Math.round(el)}s elapsed, ${S.reqs} requests queued)`);
    }
  }
}

// ---------- scan control ----------
function setScanUI(scanning) {
  $('go').disabled = scanning;
  $('abort').style.display = scanning ? 'inline-block' : 'none';
}

$('go').onclick = async () => {
  const lines = $('targets').value.split('\n');
  S.results = []; S.total = 0; S.done = 0; S.reqs = 0; S.rps = []; S.lastReqs = 0;
  S.byTarget = {}; S.rowsDirty = false; S.lastLogTime = Date.now();
  $('rows').innerHTML = ''; $('cards').innerHTML = ''; $('wire').innerHTML = '';
  updateProgress(); updateStats(); renderDossiers(); drawCharts();
  setScanUI(true);
  S.t0 = Date.now();
  S.timer = setInterval(tick, 500);
  S.scanId = crypto.randomUUID();
  S.ctrl = new AbortController();
  log('scan initiated. opening signal feed...');
  try {
    const r = await fetch('/api/scan', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      signal: S.ctrl.signal,
      body: JSON.stringify({
        targets: lines, scan_id: S.scanId,
        workers: Math.min(5000, Math.max(1, +$('opt-workers').value || 1000)),
        timeout: Math.min(10, Math.max(0.5, +$('opt-timeout').value || 3)),
        frameworks: selectedFrameworks(),
        excludes: $('excludes').value.split('\n'),
        enrich: $('opt-enrich').checked,
        fast: $('opt-fast').checked,
        exclude_dod: $('opt-exclude-dod').checked,
        lean_ports: $('opt-lean-ports').checked,
        fanout: $('opt-fanout').checked,
        dedup: $('opt-dedup').checked,
        asn_prefilter: $('opt-asn-prefilter').checked,
        progressive: $('opt-progressive').checked,
        banner_prefilter: $('opt-banner').checked,
        adaptive_timeout: $('opt-adaptive').checked,
        content_dedup: $('opt-contentdedup').checked,
        diff_mode: $('opt-diff').checked,
        ptr_seed: $('opt-ptr').checked,
        ct_search_seed: $('opt-ct').checked,
        shodan_seed: $('opt-shodan').checked
      })
    });
    const reader = r.body.getReader();
    const dec = new TextDecoder();
    let buf = '';
    while (true) {
      const {value, done} = await reader.read();
      if (done) break;
      buf += dec.decode(value, {stream: true});
      let idx;
      while ((idx = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, idx).trim();
        buf = buf.slice(idx + 1);
        if (!line) continue;
        const ev = JSON.parse(line);
        if (ev.type === 'log') {
          log(ev.message, ev.cls || 'warn');
        } else if (ev.type === 'start') {
          S.total = ev.total; updateProgress();
          log(`targeting package expanded: ${ev.total} target(s) — frameworks [${ev.frameworks}] ports [${ev.ports}] — engine ${ev.engine}/${ev.profile} @ ${ev.workers} workers${ev.fd_capped ? ' (FD-capped: raise ulimit -n for more)' : ''}.`);
          if (ev.dedup_skipped > 0) log(`DEDUP: skipped ${ev.dedup_skipped} recently scanned target(s).`);
          if (ev.prefiltered > 0) log(`ASN PREFILTER: dropped ${ev.prefiltered} residential target(s) before probing.`);
          if (ev.blocklisted > 0) log(`BLOCKLIST: ${ev.blocklisted} confirmed honeypot(s) excluded.`);
          if (ev.seeded > 0) log(`SEED: pulled ${ev.seeded} pre-curated host(s) from CT/Shodan.`);
          if (ev.progressive_dropped > 0) log(`PROGRESSIVE: TCP pre-sweep dropped ${ev.progressive_dropped} dead host(s) before deep-probe.`);
          if (ev.truncated) log('WARNING: target list hit the 100,000 cap and was TRUNCATED.', 'warn');
        } else if (ev.type === 'probes') {
          for (const p of ev.items) { S.reqs++; maybeWire(p); }
          updateProgress();
        } else if (ev.type === 'enrich') {
          const d = S.byTarget[ev.target];
          if (d) {
            d.asn = ev.asn; d.as_name = ev.as_name;
            d.bgp_prefix = ev.bgp_prefix; d.net_type = ev.net_type;
            S.rowsDirty = true; S.chartsDirty = true;
          }
        } else if (ev.type === 'result') {
          S.done++; S.results.push(ev.data);
          S.byTarget[ev.data.target] = ev.data;
          updateStats(); updateProgress(); S.chartsDirty = true;
          if (ev.data.verdict === 'IMPOSTOR')
            log(`${ev.data.target}: IMPOSTOR - ${ev.data.flags.join('; ')}`, 'bad');
          else if (ev.data.verdict === 'GENUINE')
            log(`${ev.data.target}: genuine ${ev.data.product}${ev.data.version ? ' ' + ev.data.version : ''}`);
        } else if (ev.type === 'done') {
          log(`collection complete. ${S.results.length} dossier(s) filed in ${ev.elapsed_s}s (${ev.requests} requests, ${ev.hosts_per_s} hosts/s).`);
        } else if (ev.type === 'stopped') {
          log(`SCAN ABORTED BY OPERATOR. ${ev.done} dossier(s) filed before abort.`, 'warn');
        }
      }
    }
    refreshProductSelect(); renderDossiers(); drawCharts(); updateIntel();
    $('export').style.display = 'inline-block';
    $('exportcsv').style.display = 'inline-block';
    $('retarget').style.display = 'inline-block';
    refreshHistory();
  } catch (e) {
    if (e.name === 'AbortError') log('signal feed closed by operator.', 'warn');
    else log('SCAN FAILURE: ' + e, 'bad');
  }
  clearInterval(S.timer);
  setScanUI(false);
};

$('abort').onclick = async () => {
  try {
    await fetch('/api/stop', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({scan_id: S.scanId})
    });
  } catch (e) {}
  if (S.ctrl) S.ctrl.abort();
  log('abort order transmitted.', 'warn');
};

// ---------- export ----------
$('export').onclick = () => {
  const blob = new Blob([S.results.map(r => JSON.stringify(r)).join('\n') + '\n'],
    {type: 'application/x-ndjson'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'silicon_recon_' + new Date().toISOString().replace(/[:.]/g, '-') + '.jsonl';
  a.click();
  log('dossiers exported to JSONL.', 'warn');
};
$('exportcsv').onclick = () => {
  const q = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
  const rows = [['target','product','verdict','version','model','asn','as_name','net_type','bgp_prefix','score','inventory_hash','flags','latency_ms'].join(',')];
  for (const d of S.results)
    rows.push([d.target, d.product, d.verdict, d.version, d.model,
               d.asn, d.as_name, d.net_type, d.bgp_prefix, d.score, d.inventory_hash,
               (d.flags||[]).join(' | '), d.latency_ms].map(q).join(','));
  const blob = new Blob([rows.join('\n') + '\n'], {type: 'text/csv'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'silicon_recon_' + new Date().toISOString().replace(/[:.]/g, '-') + '.csv';
  a.click();
  log('dossiers exported to CSV.', 'warn');
};

// ---------- retarget live responders ----------
// Take every non-DARK result from the last scan and load it back into the
// target list as an explicit host:port, so a fast sweep can feed a deeper
// follow-up scan on just the hosts that answered.
$('retarget').onclick = () => {
  const live = S.results.filter(d => d.verdict && d.verdict !== 'DARK');
  if (!live.length) { log('RETARGET: no live responders to reload (all DARK).', 'warn'); return; }
  const lines = [...new Set(live.map(d => d.target))].sort();
  const ta = $('targets');
  const existing = ta.value.trim();
  ta.value = existing ? existing + '\n' + lines.join('\n') : lines.join('\n');
  const tally = {};
  for (const d of live) tally[d.verdict] = (tally[d.verdict] || 0) + 1;
  const summary = Object.entries(tally).map(([v, n]) => `${n} ${v}`).join(', ');
  log(`RETARGET: ${lines.length} live host(s) loaded into target list (${summary}). switch profile and re-scan for deep probe.`, 'warn');
};

// ---------- history ----------
async function refreshHistory() {
  try {
    const r = await fetch('/api/history');
    const d = await r.json();
    $('hist').innerHTML = d.scans.map(s =>
      `<option value="${esc(s.id)}">${esc(s.when)} — ${s.total} dossiers (${s.impostor} impostor, ${s.genuine} genuine)</option>`
    ).join('') || '<option value="">(empty)</option>';
  } catch (e) {}
}
$('hist-refresh').onclick = refreshHistory;
$('hist-load').onclick = async () => {
  const id = $('hist').value;
  if (!id) return;
  const r = await fetch('/api/history?id=' + encodeURIComponent(id));
  const d = await r.json();
  S.results = d.results || [];
  S.total = S.done = S.results.length;
  S.byTarget = {};
  for (const r of S.results) S.byTarget[r.target] = r;
  updateProgress(); updateStats(); refreshProductSelect(); renderDossiers(); drawCharts(); updateIntel();
  $('export').style.display = 'inline-block';
  $('exportcsv').style.display = 'inline-block';
  $('retarget').style.display = 'inline-block';
  log(`archive loaded: ${S.results.length} dossier(s) from ${id}.`);
};
refreshHistory();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - silence request logging
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif self.path == "/api/history":
            scans = []
            for h in HISTORY:
                tally = {}
                for r in h["results"]:
                    tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
                scans.append({
                    "id": h["id"], "when": h["when"], "total": len(h["results"]),
                    "genuine": tally.get("GENUINE", 0),
                    "impostor": tally.get("IMPOSTOR", 0),
                })
            self._send(200, json.dumps({"scans": scans}))
        elif self.path.startswith("/api/asn-prefixes"):
            try:
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                asn = qs.get("asn", [""])[0].strip().upper().removeprefix("AS")
                if not asn.isdigit():
                    return self._send(400, '{"error":"invalid ASN"}')
                limit = min(5000, max(1, int(qs.get("limit", ["5000"])[0])))
                name, prefixes, total = bgpview_prefixes(asn, limit)
                self._send(200, json.dumps({
                    "asn": asn, "name": name, "prefixes": prefixes,
                    "total": total, "truncated": total > limit,
                }))
            except Exception as e:
                self._send(502, json.dumps({"error": f"RIPEstat fetch failed: {e}"}))
        elif self.path.startswith("/api/country-cidrs"):
            try:
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                cc = (qs.get("cc", ["US"])[0] or "US")[:2]
                limit = min(5000, max(1, int(qs.get("limit", ["256"])[0])))
                cidrs, total = country_cidrs(cc, limit)
                self._send(200, json.dumps({
                    "cc": cc.upper(), "cidrs": cidrs, "total_ranges": total,
                    "truncated": total > limit,
                }))
            except Exception as e:
                self._send(502, json.dumps({"error": f"RIR fetch failed: {e}"}))
        elif self.path.startswith("/api/history?id="):
            sid = self.path.split("id=", 1)[1]
            for h in HISTORY:
                if h["id"] == sid:
                    return self._send(200, json.dumps({"results": h["results"]}))
            self._send(404, '{"error":"scan not found"}')
        else:
            self._send(404, '{"error":"not found"}')

    def do_POST(self):
        if self.path == "/api/stop":
            try:
                n = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(n) or b"{}")
                ev = SCANS.get(str(payload.get("scan_id", "")))
                if ev:
                    ev.set()
                self._send(200, '{"ok":true}')
            except Exception as e:
                self._send(400, json.dumps({"error": str(e)}))
            return
        if self.path != "/api/scan":
            return self._send(404, '{"error":"not found"}')
        try:
            n = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(n) or b"{}")
            lines = payload.get("targets", [])
            if not isinstance(lines, list):
                raise ValueError("targets must be a list")
            lines = [str(x) for x in lines]
            scan_id = str(payload.get("scan_id", ""))[:64] or f"scan-{int(time.time())}"
            workers = min(5000, max(1, int(payload.get("workers", 1000))))
            timeout = min(10.0, max(0.5, float(payload.get("timeout", PROBE_TIMEOUT))))
            frameworks = payload.get("frameworks")
            if not isinstance(frameworks, list):
                frameworks = None
            excludes = payload.get("excludes")
            if not isinstance(excludes, list):
                excludes = None
            enrich = bool(payload.get("enrich", True))
            fast = bool(payload.get("fast", True))
            lean_ports = bool(payload.get("lean_ports", False))
            exclude_dod = bool(payload.get("exclude_dod", True))
            dedup = bool(payload.get("dedup", False))
            asn_prefilter = bool(payload.get("asn_prefilter", False))
            fanout = bool(payload.get("fanout", False))
            progressive = bool(payload.get("progressive", False))
            banner_prefilter = bool(payload.get("banner_prefilter", False))
            adaptive_timeout = bool(payload.get("adaptive_timeout", False))
            content_dedup = bool(payload.get("content_dedup", False))
            diff_mode = bool(payload.get("diff_mode", False))
            ptr_seed = bool(payload.get("ptr_seed", False))
            ct_search_seed = bool(payload.get("ct_search_seed", False))
            shodan_seed = bool(payload.get("shodan_seed", False))
        except Exception as e:
            return self._send(400, json.dumps({"error": str(e)}))

        cancel = threading.Event()
        SCANS[scan_id] = cancel
        results = []
        # stream NDJSON events; connection-close delimits the body
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        try:
            probe_buf = []
            last_flush = time.time()
            for ev in scan_events(lines, workers, timeout, cancel,
                                  frameworks, excludes, enrich, fast,
                                  lean_ports=lean_ports, exclude_dod=exclude_dod,
                                  dedup=dedup, asn_prefilter=asn_prefilter,
                                  fanout=fanout, progressive=progressive,
                                  banner_prefilter=banner_prefilter,
                                  adaptive_timeout=adaptive_timeout,
                                  content_dedup=content_dedup,
                                  diff_mode=diff_mode, ptr_seed=ptr_seed,
                                  ct_search_seed=ct_search_seed,
                                  shodan_seed=shodan_seed):
                if ev["type"] == "probe":
                    # batch probe events: one JSON line per ~50 or per 200ms
                    probe_buf.append(ev)
                    if len(probe_buf) < 50 and time.time() - last_flush < 0.2:
                        continue
                    ev = {"type": "probes", "items": probe_buf}
                    probe_buf = []
                    last_flush = time.time()
                elif probe_buf:
                    self.wfile.write((json.dumps(
                        {"type": "probes", "items": probe_buf}) + "\n").encode())
                    probe_buf = []
                    last_flush = time.time()
                if ev["type"] == "result":
                    results.append(ev["data"])
                elif ev["type"] == "enrich":
                    for r in results:
                        if r["target"] == ev["target"]:
                            r["asn"] = ev["asn"]
                            r["as_name"] = ev["as_name"]
                            r["bgp_prefix"] = ev["bgp_prefix"]
                            r["net_type"] = ev["net_type"]
                            break
                self.wfile.write((json.dumps(ev) + "\n").encode())
                self.wfile.flush()
            if probe_buf:
                self.wfile.write((json.dumps(
                    {"type": "probes", "items": probe_buf}) + "\n").encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            cancel.set()
        finally:
            SCANS.pop(scan_id, None)
            if results:
                HISTORY.appendleft({
                    "id": scan_id,
                    "when": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
                    "results": results,
                })


def main():
    # raise fd soft limit to hard limit (up to 65536) so the async engine
    # can hold thousands of concurrent sockets regardless of launch env
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = min(hard, 65536)
        if soft < want:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
    except (ValueError, OSError):
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=7777)
    ap.add_argument("--bind", default="127.0.0.1")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"[SILICON RECON] console up on http://{args.bind}:{args.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
