"""Auto-split from silicon_recon.py. Stdlib only."""
import asyncio
import collections
import hashlib
import json
import queue
import random
import resource
import threading
import time

from .config import (
    PROBE_TIMEOUT, CONNECT_TIMEOUT, FRAMEWORKS, PROBE_PATHS,
    DEFAULT_PORTS, DEFAULT_DOD_EXCLUDES,
)
from .db import (
    load_blocklist, add_blocklist, store_scan_result,
    scan_cache_hits_batch, fingerprint_hash, diff_check,
)
from .net import (
    ct_search, shodan_search, ptr_lookup, tcp_alive,
    banner_grab, banner_is_nonhttp,
)
from .targets import expand_targets, parse_excludes
from .asn import bulk_asn_lookup, asn_lookup
from .probe import analyze, detect_sigs, verify_inference

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
        """HTTP GET with one reconnect retry. Returns (status, body, headers)
        where headers is a bounded dict of lowercased response headers."""
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
                # bound the stored header map (hostile servers send junk)
                if len(headers) > 24:
                    headers = dict(list(headers.items())[:24])
                return status, body.decode("utf-8", "replace"), headers
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
                     ptr_seed=False, diff_mode=False, verify=False):
    dossier = {
        "target": f"{host}:{port}", "product": "unknown", "verdict": "DARK",
        "version": None, "model": None, "models_served": [], "flags": [],
        "endpoints": {}, "latency_ms": None, "error": None,
        "asn": None, "as_name": None, "bgp_prefix": None, "net_type": None,
        "score": 0, "inventory_hash": None, "ptr": None,
        "verify_result": None, "verify_detail": None,
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
    first_err = "connect failed"
    try:
        conns = await asyncio.gather(*(
            _Conn.open(host, port, min(timeout, CONNECT_TIMEOUT))
            for _ in range(nconns)))
        conns = list(conns)
    except Exception as e:
        first_err = type(e).__name__
        conns = []
    if not conns:
        dossier["error"] = first_err
        dossier["latency_ms"] = round((time.time() - t0) * 1000)
        if probe_cb:
            probe_cb(host, port, "/", None, first_err)
        return dossier

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
    for c in conns:
        c.close()
    dossier["latency_ms"] = round((time.time() - t0) * 1000)
    if not any(v["status"] is not None for v in endpoints.values()):
        dossier["error"] = "no response"
        return dossier
    d = await asyncio.to_thread(analyze, dossier)
    # deep verify: POST a tiny generate to confirm real inference (not stub/auth)
    if verify and d["verdict"] in ("GENUINE", "UNKNOWN"):
        vr, vd = await asyncio.to_thread(
            verify_inference, host, port, detect_sigs(endpoints))
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
                     verify=False):
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
                        ptr_seed=ptr_seed, diff_mode=diff_mode, verify=verify)
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
                sweep_all_ports=False, verify=False):
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
