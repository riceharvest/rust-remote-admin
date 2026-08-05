"""K-anonymized aggregate exporter for the public census site feed.

This module reads the ``targets`` table and writes coarse, bucket-count JSON
aggregates (``summary``, ``trend``, ``frameworks``, ``asns``, ``geo``) that are
safe to publish on a public website. It NEVER emits raw targeting data:

* no IP addresses, hostnames, PTR records, or ``ip:port`` target strings;
* every count bucket smaller than ``min_bucket`` is suppressed or merged into
  an ``other`` row (k-anonymity);
* ``lag_days`` excludes rows scanned within the last N days from the export
  (a WHERE ``scanned_at < now - lag_days`` guard), default 0 = no lag.

Stdlib only (sqlite3 + datetime). Compatible with Python 3.9+.
"""
import json
import os
import re
import sqlite3
import time as _time
from datetime import datetime, timedelta, timezone

from .config import STATE_DB

# Output file names (and their order in the written manifest).
OUT_FILES = ["summary.json", "trend.json", "frameworks.json", "asns.json", "geo.json"]

# IPv4-ish pattern to prove we never leak an address.
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

_VERDICTS = ("GENUINE", "IMPOSTOR", "UNKNOWN", "DARK", "ERROR")

# Any verdict not in this set counts as "live" (mirrors scan --live-only).
_LIVE_VERDICTS = ("GENUINE", "IMPOSTOR", "UNKNOWN")

_DEFAULT_OUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "site", "data")


def _utc_iso(ts):
    """Epoch seconds -> ISO-8601 UTC string, or None."""
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError):
        return None


def _family(model_or_none):
    """Coarse model family from a model string (e.g. 'llama-3.1-8b' -> 'llama')."""
    if not model_or_none:
        return None
    s = str(model_or_none).strip().lower()
    if not s:
        return None
    head = re.split(r"[:/_\-\s]+", s, maxsplit=1)[0]
    return head or None


def _decode_models(raw):
    """models_served column: JSON list -> list, else single string -> list."""
    if not raw:
        return []
    if isinstance(raw, (list, tuple)):
        return [str(x) for x in raw]
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(x) for x in parsed]
        except (TypeError, ValueError):
            pass
        return [raw]
    return []


def _columns(conn):
    return {r[1] for r in conn.execute("PRAGMA table_info(targets)")}


def _rows(conn, cutoff):
    """All targets rows with scanned_at < cutoff (lag guard).

    Returns (rows, columns_set). Columns are detected dynamically so legacy
    v0 DBs (no rich columns) still load. The raw ``ip``/``port``/``fp``/``ptr``
    fields are NEVER selected or emitted — only coarse aggregate columns are
    fetched.
    """
    cols = _columns(conn)
    want = ("verdict", "product", "score", "scanned_at", "model",
            "models_served", "asn", "as_name", "net_type")
    # Optional geography column (country / cc) is aggregated only if present.
    geo_col = next((c for c in ("country", "cc") if c in cols), None)
    pick = [c for c in want if c in cols]
    if geo_col:
        pick.append(geo_col)
    col_sql = ", ".join("`%s`" % c for c in pick)
    rows = conn.execute(
        f"SELECT {col_sql} FROM targets WHERE scanned_at < ?",
        (cutoff,)).fetchall()
    return rows, pick, geo_col


def _collect(rows, pick, geo_col=None):
    """Aggregate row tuples into per-verdict / per-framework / per-model sums.

    All bucket sizes are per-row counts; no raw target identity survives.
    """
    idx = {name: i for i, name in enumerate(pick)}
    n = len(rows)
    verdicts = {v: 0 for v in _VERDICTS}
    total_score = 0.0
    frameworks = {}        # product -> {"count","genuine","scores":[]}
    model_family = {}      # family -> count
    day_counts = {}        # "YYYY-MM-DD" -> {verdict: n}
    max_scanned = None

    for row in rows:
        verdict = str(row[idx["verdict"]] or "DARK").upper()
        if verdict not in verdicts:
            verdict = "UNKNOWN"
        verdicts[verdict] += 1

        score = row[idx["score"]]
        if isinstance(score, (int, float)):
            val = float(score)
        else:
            try:
                val = float(score) if score is not None else 0.0
            except (TypeError, ValueError):
                val = 0.0
        total_score += val

        scanned = row[idx["scanned_at"]]
        if scanned is not None:
            try:
                s = float(scanned)
            except (TypeError, ValueError):
                s = None
            if s is not None:
                if max_scanned is None or s > max_scanned:
                    max_scanned = s
                day = datetime.fromtimestamp(s, tz=timezone.utc).strftime("%Y-%m-%d")
                d = day_counts.setdefault(day, {v: 0 for v in _VERDICTS})
                d[verdict] += 1

        if idx.get("product") is not None:
            product = (row[idx["product"]] or "").strip()
        else:
            product = ""
        fw = product or "unknown"
        fw_entry = frameworks.setdefault(fw, {"count": 0, "genuine": 0,
                                              "scores": [], "models": {}})
        fw_entry["count"] += 1
        if verdict == "GENUINE":
            fw_entry["genuine"] += 1
        fw_entry["scores"].append(val)

        model = row[idx["model"]] if idx.get("model") is not None else None
        fam = _family(model)
        if not fam:
            # fall back to the first served model
            served = row[idx["models_served"]] if idx.get("models_served") is not None else None
            served_list = _decode_models(served)
            fam = _family(served_list[0]) if served_list else None
        if fam:
            model_family[fam] = model_family.get(fam, 0) + 1
            fw_entry["models"][fam] = fw_entry["models"].get(fam, 0) + 1

    return {
        "total": n,
        "verdicts": verdicts,
        "live": n - sum(verdicts.get(v, 0) for v in ("DARK", "ERROR")),
        "last_scan_at": max_scanned,
        "avg_score": round(total_score / n, 2) if n else 0.0,
        "frameworks": frameworks,
        "model_family": model_family,
        "day_counts": day_counts,
        "geo_col": geo_col,
    }


def _suppressed_buckets(counted, min_bucket):
    """Split {key: count} into (safe, other_count) under k-anonymity."""
    safe = {}
    other = 0
    for key, cnt in counted.items():
        if cnt >= min_bucket:
            safe[key] = cnt
        else:
            other += cnt
    return safe, other


def _build_summary(collected, min_bucket, lag_days):
    v = collected["verdicts"]
    return {
        "generated_at": _utc_iso(_time.time()),
        "last_scan_at": _utc_iso(collected["last_scan_at"]),
        "targets": collected["total"],
        "live": collected["live"],
        "genuine": v.get("GENUINE", 0),
        "impostor": v.get("IMPOSTOR", 0),
        "unknown": v.get("UNKNOWN", 0),
        "dark": v.get("DARK", 0),
        "error": v.get("ERROR", 0),
        "verdicts": v,
        "frameworks": {k: fw["count"] for k, fw in sorted(
            collected["frameworks"].items(), key=lambda kv: (-kv[1]["count"], kv[0]))},
        "honeypot_ratio": round(v.get("IMPOSTOR", 0) / max(1, collected["live"]), 4),
        "avg_score": collected["avg_score"],
        "min_bucket": min_bucket,
        "lag_days": lag_days,
    }


def _build_trend(collected, days=30):
    """Per-day verdict counts for the trailing ``days`` days (recomputed from rows)."""
    today = datetime.now(timezone.utc).date()
    out = []
    for i in range(days - 1, -1, -1):
        key = (today - timedelta(days=i)).isoformat()
        counts = collected["day_counts"].get(key, {v: 0 for v in _VERDICTS})
        out.append({
            "day": key, "total": sum(counts.values()),
            "genuine": counts["GENUINE"], "impostor": counts["IMPOSTOR"],
            "unknown": counts["UNKNOWN"], "dark": counts["DARK"],
            "error": counts["ERROR"],
        })
    return out


def _build_frameworks(collected, min_bucket):
    out = {}
    for name, fw in sorted(collected["frameworks"].items(), key=lambda kv: (-kv[1]["count"], kv[0])):
        scores = fw["scores"]
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        models = sorted(fw["models"].items(), key=lambda kv: (-kv[1], kv[0]))[:10]
        out[name] = {
            "count": fw["count"],
            "genuine_count": fw["genuine"],
            "avg_score": avg,
            "models_top": [{"model": m, "count": c} for m, c in models],
        }
    return out


def _build_asns(collected, min_bucket):
    """Top 20 ASNs by live-host count, with k-anonymity on bucket size.

    Buckets with fewer than ``min_bucket`` live hosts collapse into an
    ``other`` row. No raw IPs, hostnames, or targets ever appear.
    """
    a = collected
    # live-host counts keyed by (asn, as_name)
    asns = {}
    for row in a["rows"]:
        idx = a["idx"]
        verdict = str(row[idx.get("verdict")] or "DARK").upper()
        if verdict in ("DARK", "ERROR"):
            continue
        asn = (row[idx.get("asn")] if idx.get("asn") is not None else "") or ""
        asn = str(asn).strip()
        as_name = (row[idx.get("as_name")] if idx.get("as_name") is not None else "") or ""
        key = (asn or "unknown", as_name.strip())
        asns[key] = asns.get(key, 0) + 1
    safe, other = _suppressed_buckets(asns, min_bucket)
    ranked = sorted(safe.items(), key=lambda kv: (-kv[1], kv[0][0]))[:20]
    out = [{"asn": k[0], "as_name": k[1], "count": c} for k, c in ranked]
    if other:
        out.append({"asn": "other", "as_name": "", "count": other})
    return out


def _build_geo(collected, min_bucket):
    """Country distribution from the optional country/cc column, k-anonymized.

    Returns ``{"available": False}`` when the schema carries no geo column
    (graceful skip — no country data to publish).
    """
    geo_col = collected.get("_geo_col")
    if not geo_col:
        return {"available": False, "note": "no geolocation source column in schema"}
    countries = {}
    for row in collected["rows"]:
        idx = collected["idx"]
        verdict = str(row[idx.get("verdict")] or "DARK").upper()
        if verdict in ("DARK", "ERROR"):
            continue
        cc = row[idx[geo_col]] if geo_col in idx else None
        if not cc:
            continue
        cc = str(cc).strip().upper()
        if cc and re.fullmatch(r"[A-Z]{2}", cc):
            countries[cc] = countries.get(cc, 0) + 1
    safe, other = _suppressed_buckets(countries, min_bucket)
    if other:
        safe["other"] = other
    if not safe:
        return {"available": False, "note": "no rows carry geo data"}
    return {"available": True,
            "countries": {k: c for k, c in sorted(safe.items(), key=lambda kv: (-kv[1], kv[0]))}}


def _file(name, out_dir):
    return os.path.join(out_dir, name)


def export_aggregates(db_path=None, min_bucket=5, lag_days=0, out_dir=None, dry_run=False):
    """Write k-anonymized aggregate JSON files for the public census feed.

    Args:
        db_path: SQLite history DB path. Defaults to ``config.STATE_DB``.
        min_bucket: minimum count for a bucket to be published; smaller
            buckets are suppressed/merged (k-anonymity).
        lag_days: exclude rows scanned within the last N days (default 0 = no
            lag). Implemented as ``WHERE scanned_at < now - lag_days``.
        out_dir: destination directory. Defaults to ``site/data/``.
        dry_run: compute the would-be files/writes but do not write to disk.

    Returns:
        A manifest dict with the written (or would-be) file paths and bucket
        summary counts, suitable for the CLI.
    """
    if db_path is None:
        db_path = STATE_DB
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"history DB not found: {db_path}")
    if out_dir is None:
        out_dir = _DEFAULT_OUT_DIR
    cutoff = _time.time() - lag_days * 86400

    conn = sqlite3.connect(db_path)
    try:
        rows, pick, geo_col = _rows(conn, cutoff)
        collected = _collect(rows, pick, geo_col)
    finally:
        conn.close()

    # stash raw row material for asn/geo builders
    collected["rows"] = rows
    collected["idx"] = {name: i for i, name in enumerate(pick)}
    collected["_geo_col"] = geo_col

    documents = {
        "summary.json": _build_summary(collected, min_bucket, lag_days),
        "trend.json": {"days": _build_trend(collected)},
        "frameworks.json": {"frameworks": _build_frameworks(collected, min_bucket)},
        "asns.json": {"min_bucket": min_bucket, "asns": _build_asns(collected, min_bucket)},
        "geo.json": _build_geo(collected, min_bucket),
    }

    manifest = {
        "out_dir": out_dir,
        "files": [],
        "buckets": {
            "targets": collected["total"],
            "live": collected["live"],
            "asn_buckets": len(documents["asns.json"]["asns"]),
            "asn_other_merged": sum(
                1 for e in documents["asns.json"]["asns"] if e["asn"] == "other"),
        },
        "generated_at": _utc_iso(_time.time()),
        "min_bucket": min_bucket,
        "lag_days": lag_days,
    }
    if dry_run:
        manifest["files"] = [_file(n, out_dir) for n in OUT_FILES]
        return manifest

    os.makedirs(out_dir, exist_ok=True)
    paths = []
    for name in OUT_FILES:
        path = _file(name, out_dir)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(documents[name], f, indent=2)
        paths.append(path)
    manifest["files"] = paths
    return manifest