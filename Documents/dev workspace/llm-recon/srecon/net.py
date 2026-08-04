"""Auto-split from silicon_recon.py. Stdlib only."""
import asyncio
import json
import os
import socket
import time
import urllib.parse
import urllib.request

from .config import FRAMEWORKS

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
