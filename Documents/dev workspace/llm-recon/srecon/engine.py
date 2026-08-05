"""Auto-split from silicon_recon.py. Stdlib only."""
import asyncio
import collections
import hashlib
import json
import queue
import random
import resource
import ssl
import sys
import threading
import time

from .config import (
    PROBE_TIMEOUT, CONNECT_TIMEOUT, FRAMEWORKS, PROBE_PATHS,
    DEFAULT_PORTS, DEFAULT_DOD_EXCLUDES,
    HTTPS_ENABLED, TLS_VERIFY, TLS_FALLBACK,
)
from .db import (
    load_blocklist, add_blocklist, store_scan_result,
    start_scan, finish_scan,
    scan_cache_hits_batch, fingerprint_hash, diff_check,
)
from .net import (
    ct_search, shodan_search, ptr_lookup, tcp_alive,
    banner_grab, banner_is_nonhttp,
)
from .targets import expand_targets, parse_excludes
from .asn import bulk_asn_lookup, asn_lookup
from .probe import analyze, detect_sigs, verify_inference

# ---------- engine robustness constants ----------
# These bound worst-case per-host behaviour so a single hostile host (slow-rolling
# server, hang in a thread-backed lookup, etc.) can never stall a worker slot or
# the whole scan indefinitely.
# Per-exchange overall deadline: the socket timeout applies per I/O op, so a
# server trickling bytes could otherwise hold a worker for N*timeout. We bound
# the whole probe_host exchange at timeout * max(4, len(paths)).
DEADLINE_PATHS_FLOOR = 4
# Verification (a 45s cold-start inference POST) gets its own bounded concurrency
# so a queue of verifies can never steal scan-worker slots from probing.
VERIFY_WORKERS = 32
# Bulk ASN flush runs whois/RDAP in an executor thread; guard it against hanging
# (and outliving a cancel) with an overall budget.
FLUSH_ASN_TIMEOUT = 60.0
# Bounded wait for the engine thread to exit cooperatively after a cancel. It
# can never outlive forever — probe_host cancellation unwinds at the next await.
ENGINE_JOIN_TIMEOUT = 20.0
# Network/parsing failures we expect from probe_host are surfaced as ordinary
# DARK/ERROR results. *Anything else* (TypeError, KeyError, AttributeError, ...)
# is an engine bug: it is counted + logged separately (engine_error) instead of
# being silently rewritten into an ERROR result that hides the defect.
_EXPECTED_NET_EXC = (OSError, asyncio.TimeoutError, ValueError)


def _overall_deadline(timeout, npaths):
    """Overall per-host exchange budget = timeout * max(DEADLINE_PATHS_FLOOR, npaths).

    A slow-rolling server outlasts the per-op socket timeout one I/O at a time;
    bounding the whole probe_host exchange in this deadline guarantees one host
    can never hold a worker slot for more than timeout * npaths seconds.
    """
    return timeout * max(DEADLINE_PATHS_FLOOR, npaths)


def _adaptive_timeout_step(original_timeout, cur_timeout, p50_ms=None,
                           p95_ms=None, timeout_share=None, floor=1.0,
                           regrow_at=0.5, regrow_err=0.25, regrow_step=2.0):
    """One step of the adaptive-timeout controller (pure, testable).

    Shrink: pull cur_timeout toward 3x P95 when latency samples exist,
    floored at `floor` and never exceeding the original.

    Regrow: when the timeout was shrunk and either recent P50 latency has
    climbed to >= `regrow_at` of the shrunk value (the safety slack is gone)
    or the share of recently-timed-out probes exceeds `regrow_err`, grow back
    toward the original in `regrow_step` increments, capped at the original.

    Order matters: regrowth is decided before shrink so a transient latency
    spike cannot be immediately re-collapsed.
    """
    if cur_timeout >= original_timeout:
        return original_timeout
    # regrowth signals take priority over shrinking
    if p50_ms is not None and p50_ms / 1000.0 >= regrow_at * cur_timeout:
        return min(original_timeout, cur_timeout + regrow_step)
    if timeout_share is not None and timeout_share >= regrow_err:
        return min(original_timeout, cur_timeout + regrow_step)
    # shrink toward 3x P95 once we have latency signal
    if p95_ms is not None:
        return max(floor, min(original_timeout, 3.0 * p95_ms / 1000.0))
    return cur_timeout


def _error_dossier(target, verdict, error):
    """A minimal dossier for a host that failed before any HTTP exchange."""
    return {
        "target": target, "product": "unknown", "verdict": verdict,
        "version": None, "model": None, "models_served": [], "flags": [],
        "endpoints": {}, "latency_ms": None, "error": error,
        "asn": None, "as_name": None, "bgp_prefix": None, "net_type": None,
        "score": 0, "inventory_hash": None, "ptr": None,
        "verify_result": None, "verify_detail": None,
    }


def _warn(msg):
    """Warn to stderr from a generator/thread context where no logger exists."""
    print(msg, file=sys.stderr)


# ---------- async probe engine ----------
# discriminator paths always run (multi-persona detection depends on them);
# auxiliary paths only run when relevant in fast profile.
DISC_PATHS = {
    "/props", "/api/tags", "/version", "/get_model_info", "/api/v0/models",
    "/api/extra/version", "/v1/internal/model/info", "/info", "/api/config",
    "/v1/models",
    "/v2/health/ready", "/v2/models", "/readyz", "/api/models",
    "/health/liveliness", "/models", "/v1/model_template", "/v1/profile",
    "/api/v1/model", "/run/predict",
}


def fd_worker_cap():
    """Max concurrent hosts the fd soft limit can sustain (4 conns per host)."""
    try:
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        return max(50, (soft - 256) // 4)
    except (ValueError, OSError):
        return 256


# ---------- TLS / certificate helpers ----------

def _make_tls_ctx():
    """Unverified client SSLContext for probing (or verified when TLS_VERIFY)."""
    ctx = ssl.create_default_context()
    if not TLS_VERIFY:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# minimal X.509 DER parsing (stdlib only) — enough to pull issuer/subject
# and validity out of a peer certificate's DER bytes
_OID_NAMES = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
}


def _der_len(data, i):
    b = data[i]
    i += 1
    if b < 0x80:
        return b, i
    n = b & 0x7F
    return int.from_bytes(data[i:i + n], "big"), i + n


def _read_tlv(data, i):
    tag = data[i]
    i += 1
    ln, i = _der_len(data, i)
    return tag, i, i + ln


def _oid_to_str(b):
    if not b:
        return ""
    n0 = b[0]
    first = min(n0 // 40, 2)
    second = n0 - first * 40
    out = [first, second]
    cur = 0
    for byte in b[1:]:
        cur = (cur << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            out.append(cur)
            cur = 0
    if cur:
        out.append(cur)
    return ".".join(str(x) for x in out)


def _parse_der_string(tag, val):
    # 0x17 = UTCTime, 0x18 = GeneralizedTime (validity fields)
    if tag in (0x17, 0x18):
        try:
            return val.decode("latin-1")
        except Exception:
            return None
    try:
        return val.decode("utf-8")
    except Exception:
        try:
            return val.decode("latin-1")
        except Exception:
            return None


def _parse_der_name(data):
    """X.509 Name (SEQUENCE OF SET OF AttributeTypeAndValue) -> {oid: value}."""
    attrs = {}
    i = 0
    while i < len(data):
        tag, vs, ve = _read_tlv(data, i)
        if tag != 0x31:  # SET
            break
        j = vs
        while j < ve:
            _, avs, ave = _read_tlv(data, j)
            _, os_, oe = _read_tlv(data, avs)  # AttributeType (OID)
            oid = _oid_to_str(data[os_:oe])
            vt, ps, pe = _read_tlv(data, oe)  # AttributeValue
            val = _parse_der_string(vt, data[ps:pe])
            if val is not None:
                attrs.setdefault(_OID_NAMES.get(oid, oid), val)
            j = ave
        i = ve
    return attrs


def _parse_der_cert(der):
    """Extract {issuer, subject, not_before, not_after} from DER certificate."""
    out = {"issuer": None, "subject": None, "not_before": None,
           "not_after": None}
    try:
        tag, vs, ve = _read_tlv(der, 0)  # Certificate SEQUENCE
        _, tbs_vs, tbs_ve = _read_tlv(der, vs)  # tbsCertificate SEQUENCE
        i = tbs_vs
        t, s, e = _read_tlv(der, i)
        if t == 0xA0:  # optional explicit version
            i = e
        seq_idx = 0  # 0=sigAlg, 1=issuer, 2=validity, 3=subject, ...
        while i < tbs_ve:
            t, s, e = _read_tlv(der, i)
            if t == 0x30:
                if seq_idx == 1:
                    out["issuer"] = _parse_der_name(der[s:e])
                elif seq_idx == 2:
                    # Validity SEQUENCE: notBefore, notAfter
                    vi = s
                    vt, vs_, ve_ = _read_tlv(der, vi)
                    out["not_before"] = _parse_der_string(vt, der[vs_:ve_])
                    vi = ve_
                    vt, vs_, ve_ = _read_tlv(der, vi)
                    out["not_after"] = _parse_der_string(vt, der[vs_:ve_])
                elif seq_idx == 3:
                    out["subject"] = _parse_der_name(der[s:e])
                seq_idx += 1
            i = e
    except Exception:
        pass
    return out


def _norm_time(t):
    """UTCTime/GeneralizedTime (YYMMDDHHMMSSZ) -> 'YYYY-MM-DD HH:MM UTC'."""
    if not t:
        return None
    s = t.rstrip("Zz")
    if len(s) == 12:  # UTCTime YYMMDDHHMMSS
        s = ("19" if int(s[:2]) >= 50 else "20") + s
    if len(s) == 14:  # GeneralizedTime YYYYMMDDHHMMSS
        try:
            return (f"{s[0:4]}-{s[4:6]}-{s[6:8]} {s[8:10]}:{s[10:12]} UTC")
        except Exception:
            return None
    return t


def _capture_tls_info(conn, ssl_ctx):
    """Snapshot the peer certificate of a freshly opened (TLS) connection.

    Returns a compact dict {enabled, fingerprint_sha256, issuer, subject,
    not_after, self_signed} or None for plaintext connections. Certificate
    failures never raise — the caller treats TLS like a probe error."""
    if ssl_ctx is None:
        return None
    info = {"enabled": True, "fingerprint_sha256": None,
            "issuer": None, "subject": None, "not_after": None,
            "self_signed": None}
    try:
        ssl_obj = conn.writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            return info
        der = ssl_obj.getpeercert(True)  # DER bytes, always available
        if der:
            info["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()
            parsed = _parse_der_cert(der)
            info["issuer"] = parsed["issuer"]
            info["subject"] = parsed["subject"]
            info["not_after"] = _norm_time(parsed["not_after"])
            iss, sub = parsed["issuer"], parsed["subject"]
            info["self_signed"] = bool(
                iss is not None and sub is not None and iss == sub)
        # ssl_object.getpeercert() dict (validated only; empty under CERT_NONE)
        try:
            certdict = ssl_obj.getpeercert()
        except Exception:
            certdict = {}
        if certdict:
            info["not_after"] = _norm_time(certdict.get("notAfter"))
    except Exception:
        pass
    return info


class _Conn:
    __slots__ = ("reader", "writer", "tls_info", "ssl_ctx")

    @classmethod
    async def open(cls, host, port, timeout, ssl_ctx=None):
        c = cls()
        c.ssl_ctx = ssl_ctx
        c.reader, c.writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx), timeout)
        c.tls_info = _capture_tls_info(c, ssl_ctx)
        return c

    def close(self):
        try:
            self.writer.close()
        except Exception:
            pass

    async def get(self, host, port, path, timeout, ssl_ctx=None):
        """HTTP GET with one reconnect retry. Returns (status, body, headers)
        where headers is a bounded dict of lowercased response headers.
        ssl_ctx defaults to this conn's TLS context (if it was opened with one),
        so reconnects on a TLS conn keep speaking TLS."""
        ssl_ctx = ssl_ctx if ssl_ctx is not None else getattr(self, "ssl_ctx", None)
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
                        headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
                if "chunked" in headers.get("transfer-encoding", "").lower():
                    body = await asyncio.wait_for(_read_chunked(self.reader), timeout)
                elif "content-length" in headers:
                    n = min(int(headers["content-length"]), 65536)
                    body = await asyncio.wait_for(
                        self.reader.readexactly(n), timeout) if n else b""
                else:
                    body = await asyncio.wait_for(self.reader.read(65536), timeout)
                # bound the stored header map (hostile servers send junk)
                if len(headers) > 24:
                    headers = dict(list(headers.items())[:24])
                return status, body.decode("utf-8", "replace"), headers
            except Exception as e:
                last_err = e
                self.close()
                try:
                    self.reader, self.writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port, ssl=ssl_ctx), timeout)
                    self.tls_info = _capture_tls_info(self, ssl_ctx)
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
                     ptr_seed=False, diff_mode=False, conn_registry=None,
                     tls=False, tls_fallback=False):
    dossier = {
        "target": f"{host}:{port}", "product": "unknown", "verdict": "DARK",
        "version": None, "model": None, "models_served": [], "flags": [],
        "endpoints": {}, "latency_ms": None, "error": None,
        "asn": None, "as_name": None, "bgp_prefix": None, "net_type": None,
        "score": 0, "inventory_hash": None, "ptr": None,
        "verify_result": None, "verify_detail": None,
        "tls": {"enabled": False, "fingerprint_sha256": None,
                "issuer": None, "subject": None, "not_after": None,
                "self_signed": None},
    }
    t0 = time.time()
    endpoints = dossier["endpoints"]
    disc = [p for p in paths if p in DISC_PATHS]
    aux = [p for p in paths if p not in DISC_PATHS]

    # banner prefilter is a plaintext grab; don't trust it on a (possibly TLS)
    # port, so skip it whenever TLS probing or a TLS fallback is in play.
    if banner_prefilter and not tls and not tls_fallback:
        banner = await banner_grab(host, port, min(timeout, 1.0))
        if banner and banner_is_nonhttp(banner):
            dossier["error"] = "non-http"
            dossier["latency_ms"] = round((time.time() - t0) * 1000)
            if probe_cb:
                probe_cb(host, port, "/", None, "non-http")
            return dossier

    nconns = max(1, min(4, len(disc)))

    async def _try_connect(ssl_ctx):
        try:
            conns = await asyncio.gather(*(
                _Conn.open(host, port, min(timeout, CONNECT_TIMEOUT),
                           ssl_ctx=ssl_ctx)
                for _ in range(nconns)))
            conns = list(conns)
            if conn_registry is not None:
                # register live sockets so a cancellation/timeout mid-exchange can
                # still close them via the caller's registry instead of leaking fd.
                conn_registry.update(conns)
            return conns, None
        except Exception as e:
            return [], type(e).__name__

    # TLS mode: if the caller asked for TLS (port 443), connect straight over
    # TLS. Otherwise try plaintext; if the plaintext connect fails and TLS
    # fallback is on (HTTPS-on-8000 nginx front), retry the connect once over TLS.
    hello_ctx = _make_tls_ctx() if (tls and HTTPS_ENABLED) else None
    conns, first_err = await _try_connect(hello_ctx)
    if not conns and hello_ctx is None and tls_fallback and HTTPS_ENABLED:
        conns, first_err = await _try_connect(_make_tls_ctx())
        if conns:
            dossier["flags"].append("TLS_FALLBACK")
            dossier["tls_fallback"] = True
    if not conns:
        dossier["error"] = first_err
        dossier["latency_ms"] = round((time.time() - t0) * 1000)
        if probe_cb:
            probe_cb(host, port, "/", None, first_err)
        return dossier

    # capture peer cert info from the first live socket if TLS is in use
    if conns[0].tls_info:
        dossier["tls"] = conns[0].tls_info

    async def probe_paths(conn, todo):
        for path in todo:
            try:
                status, body, headers = await conn.get(host, port, path, timeout)
                try:
                    js = json.loads(body)
                except json.JSONDecodeError:
                    js = None
                endpoints[path] = {
                    "status": status, "json": js, "raw": body[:512],
                    "headers": headers}
                if probe_cb:
                    probe_cb(host, port, path, status, None)
            except Exception as e:
                endpoints[path] = {"status": None, "json": None, "raw": "",
                                   "headers": {}}
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
    # TLS fallback round 2: a TLS server accepts the plaintext TCP connect, so
    # the first exchange can end with zero successful responses without the
    # connect itself failing. When fallback is enabled and every endpoint came
    # back empty, retry the whole exchange over TLS before giving up.
    got = any(v["status"] is not None for v in endpoints.values())
    if (not got and not tls and tls_fallback and HTTPS_ENABLED
            and not dossier.get("tls_fallback")):
        for c in conns:
            c.close()
        if conn_registry is not None:
            conn_registry.difference_update(conns)
        conns, first_err = await _try_connect(_make_tls_ctx())
        if conns:
            dossier["flags"].append("TLS_FALLBACK")
            dossier["tls_fallback"] = True
            if conns[0].tls_info:
                dossier["tls"] = conns[0].tls_info
            endpoints.clear()
            await wave(disc)
            if fast:
                sigs = detect_sigs(endpoints)
                aux = [p for p in aux if _aux_needed(p, endpoints, sigs)]
            await wave(aux)
    for c in conns:
        c.close()
    if conn_registry is not None:
        conn_registry.difference_update(conns)
    dossier["latency_ms"] = round((time.time() - t0) * 1000)
    if not any(v["status"] is not None for v in endpoints.values()):
        dossier["error"] = "no response"
        return dossier
    d = await asyncio.to_thread(analyze, dossier)
    # NOTE: inference verification is intentionally NOT done here. It runs a
    # 45s-cold-start POST that must not hold a scan worker slot, so the caller
    # (run_async_engine.bound) performs it under its own bounded semaphore.
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
                     content_dedup=False, ptr_seed=False, diff_mode=False,
                     verify=False, tls=True):
    """Owns an asyncio loop in a dedicated thread; pushes events to q."""
    skip_set = skip_set or set()
    blocklist = blocklist or set()

    def probe_cb(host, port, path, status, err):
        q.put({"type": "probe", "target": f"{host}:{port}",
               "path": path, "status": status, "err": err})

    async def main():
        sem = asyncio.Semaphore(workers)
        # verification has its own bounded concurrency so 45s cold-start POSTs
        # never steal scan-worker slots from live probing.
        verify_sem = asyncio.Semaphore(VERIFY_WORKERS)
        # live sockets opened by in-flight probe_host coroutines. Registered so
        # that a cancel/timeout can close them instead of leaking file descriptors.
        live_conns = set()
        # counter for unexpected (non-network) engine exceptions; distinct from
        # DARK/ERROR verdict accounting so engine bugs are never silently masked.
        engine_err_count = [0]
        pending = []  # (ip, target) awaiting bulk ASN enrichment
        seen_fanout = set()  # avoid duplicate fanout probes
        # adaptive timeout: track live latencies, shrink to 3x P95 on latency
        # pressure and regrow toward the original when slack runs out.
        cur_timeout = [timeout]
        lat_samples = []
        recent_lats = collections.deque(maxlen=100)  # recent live latencies (P50)
        recent_to = collections.deque(maxlen=100)    # recent did-it-timeout flags
        # content dedup: signature -> count; >=3 identical = cluster
        sig_counts = {}
        ptr_seen = set()

        async def flush_asn():
            if not pending:
                return
            if cancel is not None and cancel.is_set():
                pending[:] = []
                return
            batch, pending[:] = pending[:], []
            ips = list({ip for ip, _t in batch})
            try:
                # bulk whois/RDAP runs in an executor thread with no per-op
                # bound of its own; wrap it in an overall budget and treat a
                # cancel as a reason to abort rather than flush.
                res = await asyncio.wait_for(
                    asyncio.to_thread(bulk_asn_lookup, ips), FLUSH_ASN_TIMEOUT)
            except asyncio.TimeoutError:
                res = {}
            except _EXPECTED_NET_EXC:
                res = {}
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
                if cancel is not None and cancel.is_set():
                    return
                await flush_asn()

        async def bound(h, p, is_fanout=False):
            if cancel is not None and cancel.is_set():
                return None
            tgt = f"{h}:{p}"
            if tgt in skip_set or tgt in blocklist:
                return None
            # conns opened by *this* probe; anything residual after it returns
            # (its registry cleanup was skipped by a cancel/timeout/exception)
            # must be closed so fd usage stays bounded per host.
            prev_conns = set(live_conns)
            d = None
            err = None
            try:
                # TLS policy per target: port 443 (and --tls forced targets)
                # always speak TLS first. Other ports try plaintext and fall
                # back to TLS on connect failure when TLS_FALLBACK is enabled,
                # so HTTPS-on-8000 (nginx-fronted) services get discovered.
                tls_on = bool(tls and HTTPS_ENABLED and p == 443)
                fallback = bool(tls and HTTPS_ENABLED and TLS_FALLBACK and p != 443)
                async with sem:
                    d = await asyncio.wait_for(
                        probe_host(
                            h, p, paths, cur_timeout[0], probe_cb, fast,
                            fanout=is_fanout,
                            content_hashes=(sig_counts if content_dedup else None),
                            banner_prefilter=banner_prefilter,
                            ptr_seed=ptr_seed, diff_mode=diff_mode,
                            conn_registry=live_conns,
                            tls=tls_on, tls_fallback=fallback),
                        _overall_deadline(timeout, len(paths)))
                    # normalize tuple return (fanout yields (d, neighbors))
                    if isinstance(d, tuple):
                        d = d[0]
            except asyncio.TimeoutError:
                err = "exchange timeout"
            except _EXPECTED_NET_EXC as e:
                err = f"{type(e).__name__}: {e}"
            except asyncio.CancelledError:
                raise
            except Exception as e:
                # Unexpected exception type => engine bug, not a failed host.
                # Count + log it separately; do NOT rewrite into DARK/ERROR.
                engine_err_count[0] += 1
                q.put({"type": "engine_error", "target": tgt,
                       "exc_type": type(e).__name__, "message": str(e),
                       "count": engine_err_count[0]})
            finally:
                # close any sockets this probe leaked (overall-deadline timeout,
                # expected network error, or unexpected exception unwound it)
                leaked = live_conns - prev_conns
                for c in list(leaked):
                    try:
                        c.close()
                    except Exception:
                        pass
                    live_conns.discard(c)
            if d is None:
                if err is None:
                    return None  # engine error already logged above
                d = _error_dossier(tgt, "DARK" if err == "exchange timeout"
                                   else "ERROR", err)
            # deep verify runs OUTSIDE the scan semaphore, under its own bounded
            # concurrency: a 45s cold-start POST must not stall scan workers.
            if verify and d["verdict"] in ("GENUINE", "UNKNOWN"):
                async with verify_sem:
                    if cancel is not None and cancel.is_set():
                        return d
                    try:
                        vr, vd = await asyncio.to_thread(
                            verify_inference, h, p,
                            detect_sigs(d.get("endpoints") or {}),
                            tls=bool((d.get("tls") or {}).get("enabled")))
                        d["verify_result"] = vr
                        d["verify_detail"] = vd
                        if vr == "honeypot":
                            d["verdict"] = "IMPOSTOR"
                            d["flags"] = list(d.get("flags") or []) + ["HONEYPOT_STUB: canned empty response"]
                            d["score"] = d.get("score", 0) + 50
                        elif vr == "auth-walled":
                            d["flags"] = list(d.get("flags") or []) + ["AUTH_WALLED: inference requires ollama.com account"]
                        elif vr == "live":
                            d["flags"] = list(d.get("flags") or []) + ["INFERENCE_CONFIRMED"]
                    except asyncio.CancelledError:
                        raise
                    except _EXPECTED_NET_EXC as e:
                        # verify network failure: keep the base dossier untouched
                        d.setdefault("flags", [])
                        d["flags"] = list(d["flags"]) + [f"VERIFY_{type(e).__name__}"]
                    except Exception as e:
                        engine_err_count[0] += 1
                        q.put({"type": "engine_error", "target": tgt,
                               "exc_type": type(e).__name__, "message": str(e),
                               "count": engine_err_count[0]})
            return d

        fl = asyncio.create_task(flusher())
        tasks = [asyncio.ensure_future(bound(h, p)) for h, p in targets]
        task_set = set(tasks)
        for fut in asyncio.as_completed(task_set):
            if cancel is not None and cancel.is_set():
                # cooperative cancellation: cancel pending probe tasks and close
                # any sockets they may have opened before unwinding the loop.
                for t in task_set:
                    t.cancel()
                for c in list(live_conns):
                    try:
                        c.close()
                    except Exception:
                        pass
                live_conns.clear()
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
            # adaptive timeout: shrink to 3x P95 on latency pressure; regrow
            # toward the original when P50 climbs or the timeout rate spikes.
            if adaptive_timeout:
                if d.get("latency_ms") is not None and live:
                    lat_samples.append(d["latency_ms"])
                    recent_lats.append(d["latency_ms"])
                recent_to.append(1 if "timeout" in (d.get("error") or "").lower() else 0)
                p50, p95 = None, None
                if len(recent_lats) >= 25:
                    _srt = sorted(recent_lats)
                    p50 = _srt[len(_srt) // 2]
                if len(lat_samples) >= 200:
                    _srt = sorted(lat_samples)
                    p95 = _srt[int(len(_srt) * 0.95)]
                to_share = sum(recent_to) / len(recent_to) if recent_to else None
                cur_timeout[0] = _adaptive_timeout_step(
                    timeout, cur_timeout[0], p50_ms=p50, p95_ms=p95,
                    timeout_share=to_share)
            # PTR enrichment on first live hit per IP (fire-and-forget: DNS
            # lookups take 1-5s and must NOT block the as_completed loop)
            if ptr_seed and live and ip not in ptr_seen:
                ptr_seen.add(ip)
                async def _ptr(_ip, _tgt):
                    name = await asyncio.to_thread(ptr_lookup, _ip)
                    if name:
                        q.put({"type": "ptr", "target": _tgt, "ptr": name})
                asyncio.ensure_future(_ptr(ip, d["target"]))
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
                ct_search_seed=False, shodan_seed=False,
                sweep_all_ports=False, verify=False, tls=True):
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

    # port selection: sweep_all_ports = probe every known LLM port regardless of
    # framework chips (framework chips then only gate fingerprint classification).
    # lean = top port per framework only. Default = ports from selected frameworks.
    if sweep_all_ports:
        ports = DEFAULT_PORTS  # all 13 known LLM ports
    elif lean_ports:
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

    # dedup: skip recently scanned targets (batched SQLite query)
    skip_set = set()
    if dedup:
        hb_state["phase"] = f"dedup check ({len(targets)} targets)"
        skip_set = scan_cache_hits_batch(targets)
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
        # one bulk whois call for all /24 sample IPs (1000 IP batching per socket)
        items = list(subnet_groups.items())
        sample_ips = [grp[0][0] for _k, grp in items]
        res = bulk_asn_lookup(sample_ips)
        for key, group in items:
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
            # pre-sweep opens 1 socket per target (vs 4 for deep probe),
            # so it can use 4x the worker count for the same fd budget
            sem = asyncio.Semaphore(min(workers * 4, 65000))
            live_keys = set()

            async def chk(ip, p):
                async with sem:
                    if cancel is not None and cancel.is_set():
                        return
                    if await tcp_alive(ip, p, min(timeout, 2.5)):
                        live_keys.add((ip, p))
            await asyncio.gather(*(chk(ip, p) for ip, ports_ in by_ip.items()
                                   for p in ports_))
            return live_keys
        # run pre-sweep in a background thread so the generator can yield
        # heartbeat events during the sweep (asyncio.run blocks the caller)
        hb_state["phase"] = "TCP pre-sweep"
        sweep_result = [None]
        def _run_sweep():
            sweep_result[0] = asyncio.run(sweep())
        sweep_thread = threading.Thread(target=_run_sweep, daemon=True)
        sweep_thread.start()
        while sweep_thread.is_alive():
            sweep_thread.join(timeout=1.0)
            for ev in _drain_hb():
                yield ev
        for ev in _drain_hb():
            yield ev
        live_keys = sweep_result[0] or set()
        pre_swept = len(targets) - len(live_keys)
        targets = [(ip, p) for ip, p in targets if (ip, p) in live_keys]
        for ev in _drain_hb():
            yield ev

    # stop heartbeat before the scan engine takes over
    hb_state["stop"].set()
    hb_thread.join(timeout=1)

    # --- open the scan session row ---
    # Captures scan parameters (targets source, framework filter, options) as
    # params_json; the returned DB scan_id links every persisted result row and
    # is surfaced on the start/done/stopped events so CLI consumers can run
    # `report --scan-id N` afterwards. The event stream shape is unchanged.
    scan_params = {
        "frameworks": frameworks,
        "ports": ports,
        "input_targets": len(seed_lines),
        "excludes": excludes or [],
        "exclude_dod": exclude_dod,
        "options": {
            "workers": workers, "timeout": timeout, "enrich": enrich,
            "fast": fast, "lean_ports": lean_ports, "dedup": dedup,
            "asn_prefilter": asn_prefilter, "fanout": fanout,
            "progressive": progressive, "banner_prefilter": banner_prefilter,
            "adaptive_timeout": adaptive_timeout, "content_dedup": content_dedup,
            "diff_mode": diff_mode, "ptr_seed": ptr_seed,
            "ct_search_seed": ct_search_seed, "shodan_seed": shodan_seed,
            "sweep_all_ports": sweep_all_ports, "verify": verify,
            "tls": tls, "https_enabled": HTTPS_ENABLED,
            "tls_verify": TLS_VERIFY, "tls_fallback": TLS_FALLBACK,
        },
    }
    verdict_counts = {"GENUINE": 0, "IMPOSTOR": 0, "UNKNOWN": 0,
                      "DARK": 0, "ERROR": 0}
    scan_id = start_scan(target_count=(len(targets) if targets else 0),
                         params=scan_params)

    yield {"type": "start", "total": len(targets),
           "frameworks": frameworks, "ports": ports,
           "excluded_nets": len(excl_nets), "truncated": truncated,
           "engine": "asyncio", "profile": "fast" if fast else "exhaustive",
           "workers": workers, "fd_capped": capped,
           "dedup_skipped": len(skip_set), "prefiltered": prefilt_dropped,
           "blocklisted": len(blocklist), "seeded": seed_count,
           "progressive_dropped": pre_swept,
           "scan_id": scan_id}
    t0 = time.time()
    if not targets:
        finish_scan(scan_id, {"requests": 0, "elapsed_s": 0,
                              "verdicts": verdict_counts})
        yield {"type": "done", "requests": 0, "elapsed_s": 0,
               "scan_id": scan_id}
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
                "ptr_seed": ptr_seed, "diff_mode": diff_mode,
                "verify": verify},
        daemon=True)
    eng.start()
    got = 0
    engine_done = False
    try:
        while not (got >= len(targets) and engine_done):
            if cancel is not None and cancel.is_set():
                el = round(time.time() - t0, 1)
                stats = {"requests": reqs[0], "elapsed_s": el,
                         "hosts_per_s": round(got / el, 1) if el else 0,
                         "verdicts": verdict_counts, "status": "stopped"}
                finish_scan(scan_id, stats)
                yield {"type": "stopped", "done": got, "requests": reqs[0],
                       "elapsed_s": el, "hosts_per_s": round(got / el, 1) if el else 0,
                       "scan_id": scan_id}
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
                verdict_counts[d.get("verdict", "DARK")] = \
                    verdict_counts.get(d.get("verdict", "DARK"), 0) + 1
                store_scan_result(d, scan_id=scan_id)  # persist to SQLite, linked to scan
            elif ev["type"] == "enrich_done":
                engine_done = True
                continue  # internal marker, not streamed
            elif ev["type"] == "engine_error":
                # engine bug (unexpected exception type), surfaced loudly rather
                # than being hidden as a DARK/ERROR result. Counted separately.
                yield {"type": "log",
                       "message": f"ENGINE ERROR #{ev.get('count')} @ "
                                  f"{ev.get('target')}: {ev.get('exc_type')}: "
                                  f"{ev.get('message', '')}",
                       "cls": "error"}
                continue
            yield ev
    except Exception as e:
        # engine failure mid-scan: still close the scan row, flagged with error
        el = round(time.time() - t0, 1)
        finish_scan(scan_id, {"requests": reqs[0], "elapsed_s": el,
                              "verdicts": verdict_counts,
                              "status": "error", "error": str(e)})
        raise
    finally:
        # Cooperative cancellation: flip the cancel flag so run_async_engine's
        # loop can cancel its pending asyncio tasks and close open sockets, then
        # wait a bounded time. The engine thread is daemonic and self-terminates
        # at the next await, but a hung to_thread (e.g. 45s cold-start verify)
        # can outlive even this; warn loudly instead of blocking the caller.
        if cancel is not None:
            cancel.set()
        try:
            eng.join(timeout=ENGINE_JOIN_TIMEOUT)
        finally:
            if eng.is_alive():
                _warn(f"[engine] scan {scan_id} engine thread still alive after "
                      f"{ENGINE_JOIN_TIMEOUT:.0f}s cancel grace; leaving it to "
                      f"finish and close its own sockets in the background.")
    el = round(time.time() - t0, 1)
    hps = round(got / el, 1) if el else 0
    finish_scan(scan_id, {"requests": reqs[0], "elapsed_s": el,
                          "hosts_per_s": hps, "verdicts": verdict_counts})
    yield {"type": "done", "requests": reqs[0], "elapsed_s": el,
           "hosts_per_s": hps, "scan_id": scan_id}
