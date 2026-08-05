"""Offline filtered export of raw targets from the srecon history DB.

Pure-stdlib, no network and no scanning: reads the ``targets`` table and
projects it out to JSONL / CSV / plain ``host:port`` lines (the latter feeds
straight back into ``--targets-file`` / ``--targets`` for a re-scan).

Drives the ``python3 -m srecon export`` subcommand. Like ``srecon.publish`` and
``srecon.alert``, this module reads a *specific* SQLite path (``db_path``,
falling back to ``srecon.config.STATE_DB``) with raw ``sqlite3`` so alternate /
temporary DBs are fully supported without touching the real ``srecon/data``
directory.
"""

import csv
import json
import os
import sqlite3
from typing import Any, Dict, List, Optional

from .config import STATE_DB

# ---------------------------------------------------------------------------
# field model
# ---------------------------------------------------------------------------

# Fields exported by default. ``target`` is the derived ``ip:port`` key and
# ``tls_enabled`` the derived TLS flag (parsed from the persisted ``tls``
# JSON object, else a port-443 heuristic). ``flags`` / ``models_served`` are
# JSON-array string columns projected to native lists.
DEFAULT_FIELDS = [
    "target", "ip", "port", "verdict", "product", "score", "scanned_at",
    "flags", "model", "version", "verify_result", "asn", "as_name",
    "tls_enabled",
]

# Every resolvable field (``fields='*'``). Derived keys are ``target`` and
# ``tls_enabled``; everything else maps to a ``targets`` column when present.
ALL_FIELDS = [
    "target", "ip", "port", "verdict", "product", "score", "scanned_at",
    "flags", "model", "models_served", "version", "verify_result",
    "verify_detail", "latency_ms", "asn", "as_name", "bgp_prefix", "net_type",
    "tls_enabled", "tls", "scan_id", "error", "fp",
]

_LIVE_VERDICTS = {"GENUINE", "IMPOSTOR", "UNKNOWN"}  # DARK / ERROR are "dead"


# ---------------------------------------------------------------------------
# row helpers
# ---------------------------------------------------------------------------

def _parse_json_list(raw: Any) -> List[str]:
    """Project a JSON-array TEXT column to a Python list ([] when absent)."""
    if isinstance(raw, (list, tuple)):
        return [str(x) for x in raw]
    if isinstance(raw, str):
        try:
            val = json.loads(raw)
        except ValueError:
            return []
        if isinstance(val, list):
            return [str(x) for x in val]
    return []


def _tls_enabled(d: Dict[str, Any]) -> bool:
    """Whether a row was served over TLS (persisted tls object, else p443)."""
    raw = d.get("tls")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = None
    if isinstance(raw, dict) and "enabled" in raw:
        return bool(raw["enabled"])
    p = d.get("port")
    if p is None:
        return False
    try:
        return int(p) == 443
    except (TypeError, ValueError):
        return False


def _field_value(d: Dict[str, Any], name: str) -> Any:
    """Resolve one export field against a row dict."""
    if name == "target":
        return d["target"]
    if name == "tls_enabled":
        return _tls_enabled(d)
    if name == "flags":
        return _parse_json_list(d.get("flags"))
    if name == "models_served":
        return _parse_json_list(d.get("models_served"))
    return d.get(name)


def _select_fields(row: Dict[str, Any], names: List[str]) -> Dict[str, Any]:
    """Project a row to a dict containing exactly the requested fields."""
    return {name: _field_value(row, name) for name in names}


def export_targets(db_path: Optional[str] = None, verdict: Optional[str] = None,
                   product: Optional[str] = None, scan_id: Optional[int] = None,
                   min_score: Optional[int] = None, tls_only: bool = False,
                   live_only: bool = False, limit: Optional[int] = None,
                   fields: Optional[str] = None) -> List[Dict[str, Any]]:
    """Query the targets table offline and return a filtered list of dicts.

    Filters (all optional, combined with AND):
      * verdict  -- comma-separated verdicts (case-insensitive), e.g.
                    ``"GENUINE,IMPOSTOR"``
      * product  -- comma-separated products, e.g. ``"vllm,ollama"``
      * scan_id  -- keep rows from that scan only
      * min_score-- keep rows with score >= that integer
      * tls_only -- keep only rows served over TLS
      * live_only-- drop DARK / ERROR rows
      * limit    -- cap returned rows

    ``fields`` selects exported columns: ``None`` -> DEFAULT_FIELDS,
    ``'*'`` -> ALL_FIELDS, else a comma-separated field list. Returns [] for a
    missing DB, an unpopulated DB, or a filter that matches nothing.
    """
    if db_path is None:
        db_path = STATE_DB
    if not os.path.exists(db_path):
        return []

    conn = sqlite3.connect(db_path)
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(targets)")]
        if not cols:
            return []
        rows = conn.execute(f"SELECT {', '.join(cols)} FROM targets").fetchall()
    finally:
        conn.close()

    out = []
    for r in rows:
        d = dict(zip(cols, r))
        d["target"] = f"{d.get('ip')}:{d.get('port')}"
        out.append(d)

    # --- filters ---
    if verdict:
        wanted = {v.strip().upper() for v in verdict.split(",") if v.strip()}
        if wanted:
            out = [d for d in out if (d.get("verdict") or "").upper() in wanted]
    if product:
        wanted = {p.strip().lower() for p in product.split(",") if p.strip()}
        if wanted:
            out = [d for d in out if (d.get("product") or "").lower() in wanted]
    if scan_id is not None:
        out = [d for d in out if d.get("scan_id") == scan_id]
    if min_score is not None:
        out = [d for d in out if (d.get("score") or 0) >= min_score]
    if tls_only:
        out = [d for d in out if _tls_enabled(d)]
    if live_only:
        out = [d for d in out if (d.get("verdict") or "").upper() in _LIVE_VERDICTS]

    if limit is not None:
        out = out[:limit]

    # --- field projection ---
    if fields is None:
        names = DEFAULT_FIELDS
    elif fields == "*":
        names = ALL_FIELDS
    else:
        names = [f.strip() for f in fields.split(",") if f.strip()]
        # keep only resolvable names; unknown ones are skipped silently
        names = [n for n in names if n in ALL_FIELDS or n in cols]
    return [_select_fields(d, names) for d in out]


# ---------------------------------------------------------------------------
# writers (path string or writable text file-like object)
# ---------------------------------------------------------------------------

def _resolve_out(path: Any, newline: str = "") -> Any:
    """Return (file, owns) — owns=True means we must close the file."""
    if hasattr(path, "write"):
        return path, False
    return open(path, "w", newline=newline, encoding="utf-8"), True


def write_jsonl(rows: List[Dict[str, Any]], path: Any) -> None:
    """Write rows as NDJSON (one compact JSON object per line)."""
    f, owns = _resolve_out(path)
    try:
        for r in rows:
            f.write(json.dumps(r, default=str) + "\n")
    finally:
        if owns:
            f.close()


def write_csv(rows: List[Dict[str, Any]], path: Any) -> None:
    """Write rows as CSV with a header row."""
    headers = list(rows[0].keys()) if rows else []
    f, owns = _resolve_out(path, newline="")
    try:
        w = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        if headers:
            w.writeheader()
        for r in rows:
            w.writerow(r)
    finally:
        if owns:
            f.close()


def _txt_lines(rows: List[Dict[str, Any]]) -> List[str]:
    """host:port lines for retargeting (matches targets.py expand_targets)."""
    lines = []
    for r in rows:
        ip = r.get("ip")
        port = r.get("port")
        if ip is not None and port is not None:
            lines.append(f"{ip}:{port}")
        else:
            t = r.get("target")
            if t:
                lines.append(t)
    return lines


def write_txt(rows: List[Dict[str, Any]], path: Any) -> None:
    """Write one ``host:port`` per line (re-parseable by ``--targets-file``)."""
    lines = _txt_lines(rows)
    f, owns = _resolve_out(path)
    try:
        f.write("\n".join(lines))
        if lines:
            f.write("\n")
    finally:
        if owns:
            f.close()