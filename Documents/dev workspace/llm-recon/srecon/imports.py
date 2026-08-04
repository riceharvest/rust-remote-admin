"""Offline data importer for Silicon Recon.

Ingest exported Shodan / Censys datasets into the state DB with **no network
access**. Each imported row is mapped onto the srecon result schema but is
*never* auto-classified as GENUINE: no probe validation happened, so the
verdict is always ``UNKNOWN`` and the row is tagged with an ``IMPORTED_*``
flag so it can be told apart from real scan results.

Supports three real-world export shapes:

* **Shodan JSONL** — one JSON object per line with ``ip_str``, ``port``,
  ``http.title``, ``http.components``, ``data``, ``hostnames``, ``org``,
  ``asn``, ``timestamp``.
* **Censys JSON** — a single object (or JSON-lines) exposing a ``services``
  array with ``ip``, ``port``, ``service_name`` and ``http`` response body/
  title fields.
* **Censys CSV** — rows with ``ip`` and ``port`` columns (and usually
  ``service_name``).

The module is also directly CLI-runnable so exports can be ingested without
editing ``srecon/__main__.py``::

    python3 -m srecon.imports <file> [--format shodan|censys] [--scan-id N] [--dry-run]
"""
import argparse
import csv
import json
import os
import time

from . import db

# Banner keyword -> canonical framework product, checked in priority order.
PRODUCT_KEYWORDS = [
    ("vllm", "vllm"),
    ("ollama", "ollama"),
    ("llama.cpp", "llamacpp"),
    ("llama-cpp", "llamacpp"),
    ("sglang", "sglang"),
    ("text-generation-inference", "tgi"),
    ("tgi", "tgi"),
    ("lm studio", "lmstudio"),
    ("lmstudio", "lmstudio"),
    ("koboldcpp", "koboldcpp"),
    ("kobold cpp", "koboldcpp"),
    ("open webui", "openwebui"),
    ("openwebui", "openwebui"),
    ("aphrodite", "aphrodite"),
    ("litellm", "litellm"),
    ("xinference", "xinference"),
    ("localai", "localai"),
    ("local ai", "localai"),
    ("triton", "triton"),
]

VERDICT = "UNKNOWN"


def _guess_product(text):
    """Map banner evidence onto a known framework product, if any."""
    if not text:
        return None
    haystack = text.lower()
    for keyword, product in PRODUCT_KEYWORDS:
        if keyword in haystack:
            return product
    return None


def _base_result(target, asn=None, as_name=None):
    """Build an srecon result skeleton for an imported (never validated) row."""
    return {
        "target": target,
        "verdict": VERDICT,          # imports are never auto-GENUINE
        "product": None,             # filled by the per-format mapper
        "version": None,
        "model": None,
        "models_served": [],
        "score": 0,
        "latency_ms": None,          # no live probe latency
        "flags": [],                 # set by the per-format mapper
        "asn": asn,
        "as_name": as_name,
        "bgp_prefix": None,
        "net_type": None,
        "ptr": None,
        "inventory_hash": None,
    }


# ---------------------------------------------------------------------------
# Shodan (.jsonl) mapping
# ---------------------------------------------------------------------------

def _shodan_banner(obj):
    """Concatenate the banner-ish evidence from a Shodan record."""
    parts = []
    if isinstance(obj.get("data"), str):
        parts.append(obj["data"])
    http = obj.get("http") or {}
    if isinstance(http.get("title"), str):
        parts.append(http["title"])
    comps = http.get("components")
    if isinstance(comps, dict):
        parts.append(" ".join(str(k) for k in comps))
    return " ".join(p for p in parts if p)


def _map_shodan_record(obj):
    ip = obj.get("ip_str")
    port = obj.get("port")
    if not ip or port is None:
        raise ValueError("missing ip_str/port")
    res = _base_result(
        target="{}:{}".format(ip, int(port)),
        asn=str(obj["asn"]) if obj.get("asn") is not None else None,
        as_name=obj.get("org") or obj.get("as_name") or None,
    )
    res["flags"] = ["IMPORTED_SHODAN"]
    res["product"] = _guess_product(_shodan_banner(obj))
    hostnames = obj.get("hostnames")
    if isinstance(hostnames, list) and hostnames:
        res["ptr"] = hostnames[0]
    return res


def import_shodan(path):
    """Parse a Shodan JSON-lines export into mapped srecon result dicts.

    Returns ``(results, parse_errors)`` where ``parse_errors`` counts lines
    that could not be decoded/parsed. No DB writes happen here.
    """
    results = []
    errors = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                results.append(_map_shodan_record(obj))
            except (ValueError, TypeError) as e:
                errors += 1
                _ = e
    return results, errors


# ---------------------------------------------------------------------------
# Censys JSON / CSV mapping
# ---------------------------------------------------------------------------

def _censys_service_banner(service):
    """Concatenate banner-ish evidence from a Censys service entry."""
    parts = []
    name = service.get("service_name")
    if name:
        parts.append(str(name))
    http = service.get("http") or {}
    body = http.get("response", {}) if isinstance(http.get("response"), dict) else {}
    if isinstance(body.get("body"), str):
        parts.append(body["body"])
    if isinstance(body.get("title"), str):
        parts.append(body["title"])
    if isinstance(http.get("title"), str):
        parts.append(http["title"])
    return " ".join(p for p in parts if p)


def _map_censys_service(service, asn=None, as_name=None):
    ip = service.get("ip")
    port = service.get("port")
    if not ip or port is None:
        raise ValueError("missing ip/port")
    res = _base_result(
        target="{}:{}".format(ip, int(port)),
        asn=asn,
        as_name=as_name,
    )
    res["flags"] = ["IMPORTED_CENSYS"]
    res["product"] = _guess_product(_censys_service_banner(service))
    http = service.get("http") or {}
    body = http.get("response", {}) if isinstance(http.get("response"), dict) else {}
    title = body.get("title")
    if not title and http.get("title"):
        title = http["title"]
    if isinstance(title, str):
        res["version"] = None  # title is not a reliable product version
    return res


def _iter_censys_json(path):
    """Yield Censys ``services`` entries from a JSON object or JSON-lines."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (ValueError, TypeError):
                continue
            services = obj.get("services")
            if isinstance(services, list):
                for svc in services:
                    yield svc
            elif isinstance(obj, dict) and "ip" in obj and "port" in obj:
                # a single service object on one line (Censys modern JSON-lines)
                yield obj


def import_censys_json(path):
    """Parse a Censys JSON export (object-of-services or services JSON-lines)."""
    results = []
    errors = 0
    for service in _iter_censys_json(path):
        try:
            results.append(_map_censys_service(service))
        except (ValueError, TypeError):
            errors += 1
    return results, errors


def import_censys_csv(path):
    """Parse a Censys CSV export (headers with ip + port columns)."""
    results = []
    errors = 0
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            return results, errors
        for row in reader:
            service = {}
            for key, value in row.items():
                if value is None:
                    continue
                service[key] = value
            try:
                results.append(_map_censys_service(
                    service,
                    asn=service.get("asn"),
                    as_name=service.get("org") or service.get("as_name"),
                ))
            except (ValueError, TypeError):
                errors += 1
    return results, errors


def import_censys(path):
    """Auto-detect Censys JSON vs CSV and parse either into result dicts."""
    if _looks_csv(path):
        return import_censys_csv(path)
    return import_censys_json(path)


# ---------------------------------------------------------------------------
# Format detection + single-file dispatcher
# ---------------------------------------------------------------------------

def _looks_csv(path):
    name = path.lower()
    if name.endswith(".csv"):
        return True
    ext = os.path.splitext(path)[1].lower()
    if ext == ".csv":
        return True
    # header sniff fallback — only meaningful for a real CSV, never JSON
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.readline(4096).strip()
        if not head or head.startswith("{") or "," not in head:
            return False
        return "ip" in head and "port" in head
    except OSError:
        return False


def detect_format(path, fmt=None):
    """Return 'shodan', 'censys', or 'censys-csv' based on a sniff + optional hint."""
    if fmt:
        f = fmt.lower()
        if f in ("shodan", "jsonl"):
            return "shodan"
        if f in ("censys",):
            return "censys-csv" if _looks_csv(path) else "censys"
        raise ValueError("unknown format: %r" % fmt)
    # Sniff the first non-empty lines
    for s in _sniff_lines(path, 20):
        if s.startswith("{"):
            try:
                obj = json.loads(s)
            except (ValueError, TypeError):
                continue
            if not isinstance(obj, dict):
                continue
            if "ip_str" in obj:
                return "shodan"
            if isinstance(obj.get("services"), list) or (
                    "ip" in obj and "port" in obj):
                return "censys"
    if _looks_csv(path):
        return "censys-csv"
    raise ValueError(
        "could not auto-detect format for %r; pass --format shodan|censys"
        % path)


def _sniff_lines(path, n):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = [ln.strip() for ln in fh if ln.strip()]
        return lines[:n]
    except OSError:
        return []


def _resolve_dedup(results, ref_ts=None):
    """Return (stored, skipped) split honoring the fresher-row dedup rule.

    Rows whose ``(ip, port)`` already exists in the targets table with a
    ``scanned_at`` *newer* than ``ref_ts`` are skipped so imports never
    overwrite fresher real probe data.
    """
    ref_ts = time.time() if ref_ts is None else ref_ts
    pairs = []
    for r in results:
        parts = r["target"].rsplit(":", 1)
        if len(parts) != 2:
            continue
        pairs.append((parts[0], int(parts[1])))
    if not pairs:
        return list(results), []
    fresher = _existing_scanned_at(pairs)
    stored = []
    skipped = []
    for r in results:
        parts = r["target"].rsplit(":", 1)
        key = (parts[0], int(parts[1])) if len(parts) == 2 else None
        existing = fresher.get(key)
        if existing is not None and existing > ref_ts:
            skipped.append(r)
        else:
            stored.append(r)
    return stored, skipped


def _existing_scanned_at(pairs):
    """Map {(ip, port)} -> scanned_at currently stored, absent pairs omitted."""
    out = {}
    if not pairs:
        return out
    try:
        conn = db._init_db()
    except Exception:
        return out
    try:
        unique = list(set(pairs))
        for i in range(0, len(unique), 400):
            chunk = unique[i:i + 400]
            ph = ",".join("(?,?)" for _ in chunk)
            flat = [v for pair in chunk for v in pair]
            rows = conn.execute(
                "SELECT ip, port, scanned_at FROM targets WHERE (ip, port) IN (%s)" % ph,
                flat).fetchall()
            for ip, port, scanned_at in rows:
                out[(ip, port)] = scanned_at
    except Exception:
        pass
    finally:
        conn.close()
    return out


def import_file(path, fmt=None, scan_id=None, dry_run=False):
    """Parse an export file and persist it via ``db.store_results``.

    Returns ``{"imported": int, "skipped": int, "errors": int}``.

    * ``fmt`` — optional hint: ``shodan`` or ``censys``; otherwise the format
      is auto-detected by sniffing the first lines and filename.
    * ``scan_id`` — optional scan row to associate imported rows with.
    * ``dry_run`` — parse + map but write nothing to the DB.
    """
    if not os.path.exists(path):
        return {"imported": 0, "skipped": 0, "errors": 0, "error": "no such file"}

    fmt = detect_format(path, fmt)
    if fmt == "shodan":
        results, errors = import_shodan(path)
        flag = "IMPORTED_SHODAN"
    elif fmt == "censys-csv":
        results, errors = import_censys_csv(path)
        flag = "IMPORTED_CENSYS"
    else:  # censys (json)
        results, errors = import_censys_json(path)
        flag = "IMPORTED_CENSYS"

    if dry_run:
        return {
            "imported": len(results),
            "skipped": 0,
            "errors": errors,
            "format": fmt,
            "results": results,
        }

    stored, skipped = _resolve_dedup(results)
    # Ensure every row carries the right flag even if a mapper missed it.
    for r in stored:
        if flag not in r.get("flags", []):
            r["flags"] = [flag]
    db.store_results(stored, scan_id=scan_id)
    return {"imported": len(stored), "skipped": len(skipped), "errors": errors,
            "format": fmt}


# ---------------------------------------------------------------------------
# CLI: python3 -m srecon.imports <file> [--format shodan|censys]
#                                  [--scan-id N] [--dry-run]
# ---------------------------------------------------------------------------

def _print_results(results, limit=3):
    for r in results[:limit]:
        print(json.dumps(r, sort_keys=True))


def _main(argv=None):
    parser = argparse.ArgumentParser(
        prog="srecon.imports",
        description="Ingest exported Shodan/Censys datasets offline.")
    parser.add_argument("file", help="path to the export file")
    parser.add_argument("--format", choices=["shodan", "censys"],
                        default=None, help="format hint (auto-detected otherwise)")
    parser.add_argument("--scan-id", type=int, default=None,
                        help="scan row to associate imported rows with")
    parser.add_argument("--dry-run", action="store_true",
                        help="parse + map only; do not touch the database")
    args = parser.parse_args(argv)

    try:
        counts = import_file(args.file, fmt=args.format,
                             scan_id=args.scan_id, dry_run=args.dry_run)
    except Exception as e:  # noqa: BLE001 - CLI must always print a verdict
        print("ERROR: %s" % e)
        return 1

    if args.dry_run:
        print("dry-run %s: imported=%d errors=%d format=%r"
              % (os.path.basename(args.file), counts["imported"],
                 counts["errors"], counts.get("format")))
        print("first mapped results:")
        _print_results(counts.get("results", []))
    else:
        print("imported=%d skipped=%d errors=%d"
              % (counts["imported"], counts["skipped"], counts["errors"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())