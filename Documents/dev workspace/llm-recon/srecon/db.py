"""Auto-split from silicon_recon.py. Stdlib only."""
import hashlib
import json
import os
import sqlite3
import time

from .config import DATA_DIR, STATE_DB, BLOCKLIST_FILE

# ---------------------------------------------------------------------------
# Schema migrations (PRAGMA user_version).
#
# `_SCHEMA_VERSION` is the highest applied migration. Migrations are applied
# transactionally on first connect by `_init_db` -> `_apply_migrations`.
# Each migration runs at most once (user_version is bumped as they succeed),
# and every step inside a migration is guarded (CREATE IF NOT EXISTS / column
# presence check) so re-running the runner against an already-current DB is a
# no-op. Existing DBs are migrated in place: new columns are added with
# ALTER TABLE ADD COLUMN, so pre-existing rows simply get NULL.
# ---------------------------------------------------------------------------
_SCHEMA_VERSION = 3

# Dropped/enriched result fields persisted onto the targets table. Order is
# the write order used by the store functions.
_NEW_TARGET_COLUMNS = [
    ("scan_id", "INTEGER"),
    ("model", "TEXT"),
    ("models_served", "TEXT"),
    ("version", "TEXT"),
    ("verify_result", "TEXT"),
    ("verify_detail", "TEXT"),
    ("latency_ms", "REAL"),
    ("asn", "TEXT"),
    ("as_name", "TEXT"),
    ("bgp_prefix", "TEXT"),
    ("net_type", "TEXT"),
    ("error", "TEXT"),
]


def _columns(conn, table):
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _migration_1_base_schema(conn):
    """Base tables (targets, honeypot_fleets) plus the legacy fp column."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS targets ("
        "  ip TEXT NOT NULL, port INTEGER NOT NULL,"
        "  verdict TEXT NOT NULL, product TEXT, score INTEGER DEFAULT 0,"
        "  scanned_at REAL NOT NULL, fp TEXT, PRIMARY KEY (ip, port))")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS honeypot_fleets ("
        "  inv_hash TEXT PRIMARY KEY, member_count INTEGER,"
        "  verdicts TEXT, first_seen REAL, last_seen REAL)")
    cols = _columns(conn, "targets")
    if "fp" not in cols:
        conn.execute("ALTER TABLE targets ADD COLUMN fp TEXT")


def _migration_2_scans_and_fields(conn):
    """Scan history table, scan linkage + dropped-field columns on targets,
    and the lookup indexes."""
    cols = _columns(conn, "targets")
    for name, ddl in _NEW_TARGET_COLUMNS:
        if name not in cols:
            conn.execute(f"ALTER TABLE targets ADD COLUMN {name} {ddl}")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scans ("
        "  scan_id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  started_at REAL, finished_at REAL,"
        "  target_count INTEGER, params_json TEXT, stats_json TEXT)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_targets_scanned_at "
        "  ON targets (scanned_at)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_targets_scan_id "
        "  ON targets (scan_id)")


def _migration_3_flags(conn):
    """Persist result flags onto the targets table (JSON-array TEXT column)."""
    cols = _columns(conn, "targets")
    if "flags" not in cols:
        conn.execute("ALTER TABLE targets ADD COLUMN flags TEXT")


_MIGRATIONS = [
    _migration_1_base_schema,
    _migration_2_scans_and_fields,
    _migration_3_flags,
]


def schema_version(conn=None):
    """Current PRAGMA user_version. Open a temp connection if none given."""
    if conn is not None:
        return conn.execute("PRAGMA user_version").fetchone()[0]
    conn = sqlite3.connect(STATE_DB)
    try:
        return conn.execute("PRAGMA user_version").fetchone()[0]
    finally:
        conn.close()


def _apply_migrations(conn):
    """Apply pending migrations in order, inside a single transaction."""
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    if current >= _SCHEMA_VERSION:
        return
    conn.execute("BEGIN")
    try:
        for version in range(current + 1, _SCHEMA_VERSION + 1):
            _MIGRATIONS[version - 1](conn)
        conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def _init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(STATE_DB)
    # WAL journaling + busy timeout on every connect (WAL persists; the timeout
    # is per-connection and must be re-set each time).
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")
    _apply_migrations(conn)
    return conn


def _models_json(d):
    """Serialize a models_served list to a JSON string (or passthrough)."""
    models = d.get("models_served")
    if isinstance(models, (list, tuple)):
        return json.dumps(models)
    return models


def _flags_json(d):
    """Serialize a flags list to a JSON string (missing/None -> NULL)."""
    flags = d.get("flags")
    if isinstance(flags, (list, tuple)):
        return json.dumps(list(flags))
    return None


def store_results(results, scan_id=None):
    try:
        conn = _init_db()
        now = time.time()
        for r in results:
            parts = r["target"].rsplit(":", 1)
            if len(parts) != 2:
                continue
            conn.execute(
                "INSERT OR REPLACE INTO targets "
                "(ip,port,verdict,product,score,scanned_at,scan_id,"
                "model,models_served,version,verify_result,verify_detail,"
                "latency_ms,asn,as_name,bgp_prefix,net_type,error,flags) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (parts[0], int(parts[1]), r.get("verdict", "DARK"),
                 r.get("product"), r.get("score", 0), now, scan_id,
                 r.get("model"), _models_json(r), r.get("version"),
                 r.get("verify_result"), r.get("verify_detail"),
                 r.get("latency_ms"), r.get("asn"), r.get("as_name"),
                 r.get("bgp_prefix"), r.get("net_type"), r.get("error"),
                 _flags_json(r)))
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
        # load_blocklist() normalizes any host:port lines to bare IPs in memory
        bl = load_blocklist()
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


def _bare_ip(s):
    """Return the bare IP from either an 'ip' or an 'ip:port' string."""
    s = s.strip()
    return s.rsplit(":", 1)[0] if ":" in s else s


def _read_blocklist_lines():
    if not os.path.exists(BLOCKLIST_FILE):
        return []
    with open(BLOCKLIST_FILE) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def load_blocklist():
    try:
        # Normalize-on-load only: host:port lines become bare IPs in memory.
        # The file itself is never rewritten unless normalize_blocklist() is
        # called explicitly.
        return {_bare_ip(l) for l in _read_blocklist_lines()}
    except OSError:
        return set()


def add_blocklist(target):
    """Append a confirmed honeypot IP to the persistent blocklist.

    Stores one bare IP per line (strips any host:port suffix), so the file
    stays consistent with what learn_honeypots() writes.
    """
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(BLOCKLIST_FILE, "a") as f:
            f.write(_bare_ip(target) + "\n")
    except OSError:
        pass


def normalize_blocklist():
    """Rewrite the blocklist file as deduped, sorted bare IPs.

    This is the *only* function that rewrites BLOCKLIST_FILE. Reads the current
    contents (normalizing any mixed host:port lines), then writes back one bare
    IP per line. Returns the normalized set.
    """
    try:
        ips = {_bare_ip(l) for l in _read_blocklist_lines()}
        with open(BLOCKLIST_FILE, "w") as f:
            f.write("\n".join(sorted(ips)) + "\n")
        return ips
    except OSError:
        return set()


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


def scan_cache_hits_batch(targets):
    """Batch dedup check: returns set of 'ip:port' strings found in cache.
    One connection, chunked queries — replaces N individual scan_cache_hit calls."""
    hit = set()
    try:
        conn = _init_db()
        cutoff = time.time() - 7 * 86400
        # SQLite variable limit ~999 on older builds; 500 pairs = 1000 vars
        for i in range(0, len(targets), 500):
            chunk = targets[i:i + 500]
            pairs = [(ip, int(port)) for ip, port in chunk]
            placeholders = ",".join(["(?,?)"] * len(pairs))
            flat = [v for pair in pairs for v in pair]
            rows = conn.execute(
                f"SELECT ip, port FROM targets "
                f"WHERE (ip, port) IN ({placeholders}) AND scanned_at>?",
                flat + [cutoff]).fetchall()
            for ip, port in rows:
                hit.add(f"{ip}:{port}")
        conn.close()
    except Exception:
        pass
    return hit


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


def store_scan_result(d, scan_id=None):
    """Persist a single scan result to SQLite (scan_id optional)."""
    try:
        conn = _init_db()
        parts = d["target"].rsplit(":", 1)
        if len(parts) != 2:
            conn.close()
            return
        conn.execute(
            "INSERT OR REPLACE INTO targets "
            "(ip,port,verdict,product,score,scanned_at,fp,scan_id,"
            "model,models_served,version,verify_result,verify_detail,"
            "latency_ms,asn,as_name,bgp_prefix,net_type,error,flags) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (parts[0], int(parts[1]), d.get("verdict", "DARK"),
             d.get("product"), d.get("score", 0), time.time(),
             fingerprint_hash(d), scan_id,
             d.get("model"), _models_json(d), d.get("version"),
             d.get("verify_result"), d.get("verify_detail"),
             d.get("latency_ms"), d.get("asn"), d.get("as_name"),
             d.get("bgp_prefix"), d.get("net_type"), d.get("error"),
             _flags_json(d)))
        conn.commit()
        conn.close()
    except Exception:
        pass


def list_honeypots():
    """Return learned honeypot fleets (previously write-only table)."""
    try:
        conn = _init_db()
        rows = conn.execute(
            "SELECT inv_hash, member_count, verdicts, first_seen, last_seen "
            "FROM honeypot_fleets ORDER BY last_seen DESC, inv_hash").fetchall()
        conn.close()
        return [
            {
                "inv_hash": inv_hash, "member_count": member_count,
                "verdicts": (json.loads(verdicts) if verdicts else {}),
                "first_seen": first_seen, "last_seen": last_seen,
            }
            for inv_hash, member_count, verdicts, first_seen, last_seen in rows
        ]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Scan history (scans table)
# ---------------------------------------------------------------------------

def start_scan(target_count=None, params=None):
    """Open a new scan row and return its scan_id."""
    conn = _init_db()
    cur = conn.execute(
        "INSERT INTO scans (started_at, target_count, params_json) "
        "VALUES (?,?,?)",
        (time.time(), target_count, json.dumps(params or {}) if params else None))
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def finish_scan(scan_id, stats=None):
    """Mark a scan finished with optional summary stats (dict)."""
    try:
        conn = _init_db()
        conn.execute(
            "UPDATE scans SET finished_at=?, stats_json=? WHERE scan_id=?",
            (time.time(), json.dumps(stats or {}) if stats else None, scan_id))
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_scan(scan_id):
    """Return a single scan as a dict, or None if not present."""
    try:
        conn = _init_db()
        row = conn.execute(
            "SELECT scan_id, started_at, finished_at, target_count, "
            "       params_json, stats_json FROM scans WHERE scan_id=?",
            (scan_id,)).fetchone()
        conn.close()
        if row is None:
            return None
        scan_id_, started_at, finished_at, target_count, params_json, stats_json = row
        return {
            "scan_id": scan_id_, "started_at": started_at,
            "finished_at": finished_at, "target_count": target_count,
            "params_json": params_json, "stats_json": stats_json,
        }
    except Exception:
        return None


def list_scans():
    """Return all scans, newest first."""
    try:
        conn = _init_db()
        rows = conn.execute(
            "SELECT scan_id, started_at, finished_at, target_count, "
            "       params_json, stats_json FROM scans "
            "ORDER BY started_at DESC, scan_id DESC").fetchall()
        conn.close()
        return [
            {
                "scan_id": s, "started_at": st, "finished_at": fi,
                "target_count": tc, "params_json": pj, "stats_json": sj,
            }
            for s, st, fi, tc, pj, sj in rows
        ]
    except Exception:
        return []