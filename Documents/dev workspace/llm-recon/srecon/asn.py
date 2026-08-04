"""Auto-split from silicon_recon.py. Stdlib only."""
import ipaddress
import random
import socket
import struct

from .config import DC_KEYWORDS, RES_KEYWORDS

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
