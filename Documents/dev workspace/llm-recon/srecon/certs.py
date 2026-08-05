"""Offline TLS certificate-expiry tracker for Silicon Recon.

Reads the persisted ``tls`` JSON dicts on the targets table (written by the
engine in wave 12: ``{enabled, fingerprint_sha256, issuer, subject,
not_after, self_signed}``) and classifies every cert by how soon it
expires, with **no network access and no scanning**.

Status thresholds (both in days):

* ``expired``  — ``not_after`` is in the past (``not_after < now``).
* ``critical`` — ``days_left <= critical_days`` (default 7).
* ``warn``     — ``days_left <= warn_days`` (default 30).
* ``ok``       — everything else.

``not_after`` is parsed from either the engine's ``'YYYY-MM-DD HH:MM UTC'``
shape or an ISO-8601 string (``T`` or space separator, optional ``Z`` /
``+HH:MM`` offset). Rows whose ``tls`` column is NULL, is not valid JSON, or
whose ``not_after`` cannot be parsed are skipped — only certs with a usable
expiry make it into the result list.

The module is also directly CLI-runnable (same standalone pattern as
``srecon/imports.py``; ``srecon/__main__.py`` is untouched)::

    python3 -m srecon.certs [--db PATH] [--warn-days 30] [--critical-days 7]
                            [--json] [--csv PATH]
"""
import argparse
import csv
import datetime
import json
import sqlite3
import time

from . import db

STATUS_EXPIRED = "expired"
STATUS_CRITICAL = "critical"
STATUS_WARN = "warn"
STATUS_OK = "ok"

# not_after shapes the engine can produce ('YYYY-MM-DD HH:MM UTC') plus the
# optional-seconds variant, before the ISO-8601 fallback.
_ENGINE_FORMATS = (
    "%Y-%m-%d %H:%M UTC",
    "%Y-%m-%d %H:%M:%S UTC",
)

_RESULT_KEYS = ("target", "ip", "port", "issuer", "subject",
                "fingerprint_sha256", "not_after", "days_left", "status")


def _parse_not_after(value):
    """Parse a stored not_after into an aware UTC datetime, or None.

    Handles the engine's 'YYYY-MM-DD HH:MM UTC' format and ISO-8601 (with
    'T' or space separator, optional 'Z' or numeric offset).
    """
    if not value:
        return None
    s = str(value).strip()
    for fmt in _ENGINE_FORMATS:
        try:
            return datetime.datetime.strptime(
                s, fmt).replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
    try:
        # fromisoformat does not accept a bare 'Z' before 3.11; normalize it.
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _classify(days_left, now_ts, not_after_ts, warn_days, critical_days):
    """Status for one cert: expired > critical > warn > ok."""
    if not_after_ts < now_ts:
        return STATUS_EXPIRED
    if days_left <= critical_days:
        return STATUS_CRITICAL
    if days_left <= warn_days:
        return STATUS_WARN
    return STATUS_OK


def _connect(db_path):
    """Open the state DB: default project DB, or an explicit path.

    The default path goes through ``db._init_db()`` so migrations run and
    WAL is enabled exactly as everywhere else. An explicit path is opened
    read-only-ish (no migration writes) — callers own that database.
    """
    if db_path:
        return sqlite3.connect(db_path)
    return db._init_db()


def scan_certs(db_path=None, warn_days=30, critical_days=7):
    """Return per-cert expiry records for every target with TLS data.

    Reads targets rows with a non-NULL ``tls`` column, ``json.loads`` each
    dict, parses ``not_after`` (engine 'YYYY-MM-DD HH:MM UTC' or ISO-8601),
    and returns a list of dicts::

        {target, ip, port, issuer, subject, fingerprint_sha256,
         not_after, days_left, status}

    sorted by ``days_left`` ascending (most urgent first). ``days_left`` is
    ``(not_after - now) / 86400`` rounded to 2 decimals (negative when
    expired). Rows with NULL/invalid tls JSON or an unparseable
    ``not_after`` are skipped. An unreadable/missing DB yields ``[]``.
    """
    certs = []
    try:
        conn = _connect(db_path)
        try:
            rows = conn.execute(
                "SELECT ip, port, tls FROM targets WHERE tls IS NOT NULL"
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.OperationalError:
        return []  # missing DB, missing tls column (pre-v4), etc.

    now_ts = time.time()
    for ip, port, tls_raw in rows:
        try:
            tls = json.loads(tls_raw)
        except (ValueError, TypeError):
            continue
        if not isinstance(tls, dict):
            continue
        not_after = _parse_not_after(tls.get("not_after"))
        if not_after is None:
            continue
        not_after_ts = not_after.timestamp()
        days_left = round((not_after_ts - now_ts) / 86400.0, 2)
        certs.append({
            "target": "{}:{}".format(ip, port),
            "ip": ip,
            "port": port,
            "issuer": tls.get("issuer"),
            "subject": tls.get("subject"),
            "fingerprint_sha256": tls.get("fingerprint_sha256"),
            "not_after": tls.get("not_after"),
            "days_left": days_left,
            "status": _classify(days_left, now_ts, not_after_ts,
                                warn_days, critical_days),
        })
    certs.sort(key=lambda c: c["days_left"])
    return certs


def summarize(db_path=None, warn_days=30, critical_days=7, top=5):
    """Count certs by status and return the most-urgent records.

    Returns ``{"total": int, "counts": {ok, warn, critical, expired},
    "top_expiring": [...]}`` where ``top_expiring`` is the ``top`` certs
    closest to expiry (already sorted by ``days_left`` ascending).
    """
    certs = scan_certs(db_path, warn_days=warn_days,
                       critical_days=critical_days)
    counts = {STATUS_OK: 0, STATUS_WARN: 0,
              STATUS_CRITICAL: 0, STATUS_EXPIRED: 0}
    for c in certs:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    return {
        "total": len(certs),
        "counts": counts,
        "top_expiring": certs[:top],
    }


# ---------------------------------------------------------------------------
# CLI: python3 -m srecon.certs [--db PATH] [--warn-days 30] [--critical-days 7]
#                              [--json] [--csv PATH]
# ---------------------------------------------------------------------------

_CSV_HEADER = list(_RESULT_KEYS)


def _print_table(certs):
    if not certs:
        return
    print("{:<22}{:>10}  {:<10}{}".format(
        "TARGET", "DAYS_LEFT", "STATUS", "ISSUER"))
    print("-" * 80)
    for c in certs:
        print("{:<22}{:>10.1f}  {:<10}{}".format(
            c["target"], c["days_left"], c["status"],
            c["issuer"] or ""))


def _write_csv(certs, path):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_HEADER,
                                extrasaction="ignore")
        writer.writeheader()
        for c in certs:
            writer.writerow(c)


def _main(argv=None):
    parser = argparse.ArgumentParser(
        prog="srecon.certs",
        description="Offline TLS certificate-expiry tracker.")
    parser.add_argument("--db", default=None,
                        help="path to the state DB (default: project state.db)")
    parser.add_argument("--warn-days", type=int, default=30,
                        help="warn when days_left <= N (default 30)")
    parser.add_argument("--critical-days", type=int, default=7,
                        help="critical when days_left <= N (default 7)")
    parser.add_argument("--json", action="store_true",
                        help="emit NDJSON (one record per line) instead of a table")
    parser.add_argument("--csv", default=None, metavar="PATH",
                        help="also export all records to a CSV file")
    args = parser.parse_args(argv)

    certs = scan_certs(args.db, warn_days=args.warn_days,
                       critical_days=args.critical_days)

    if args.csv:
        _write_csv(certs, args.csv)

    if not certs:
        print("no TLS records")
        return 0

    if args.json:
        for c in certs:
            print(json.dumps(c, sort_keys=True))
    else:
        _print_table(certs)
        counts = summarize(args.db, warn_days=args.warn_days,
                           critical_days=args.critical_days)["counts"]
        print("summary: total={} expired={} critical={} warn={} ok={}".format(
            len(certs), counts[STATUS_EXPIRED], counts[STATUS_CRITICAL],
            counts[STATUS_WARN], counts[STATUS_OK]))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
