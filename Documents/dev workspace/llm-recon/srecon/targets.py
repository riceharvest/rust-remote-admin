"""Auto-split from silicon_recon.py. Stdlib only."""
import ipaddress
import json
import os
import random
import time
import urllib.request

from .config import DEFAULT_PORTS, MAX_CIDR_HOSTS, MAX_TOTAL_TARGETS

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
