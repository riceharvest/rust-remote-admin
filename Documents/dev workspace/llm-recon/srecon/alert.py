"""Offline alert generator for Silicon Recon (srecon).

Pure-stdlib change detector over scan history. Given a *baseline* scan (A) and a
*current* scan (B), it watches every target present in B and emits an alert when
an endpoint CHANGES in a security-relevant way:

* ``new``      -> kind ``NEW``             target appeared in B but not A
* ``flip``     -> kind ``VERDICT_FLIP``    verdict changed (GENUINE/IMPOSTOR/
                                            UNKNOWN/DARK/ERROR)
* ``model``    -> kind ``MODEL_CHANGE``    models_served set changed
* ``tls``      -> kind ``TLS_DROP``        endpoint was TLS in A but plaintext
                                            in B (or tls.enabled flipped false)
* ``verify``   -> kind ``VERIFY_REGRESSION`` verify_result went live ->
                                            auth-walled / honeypot

Severity: ``high`` for VERDICT_FLIP->IMPOSTOR, TLS_DROP and VERIFY_REGRESSION;
``medium`` for NEW; ``low`` for MODEL_CHANGE (VERDICT_FLIP to a non-IMPOSTOR
state is ``medium``).

The CLI (``python3 -m srecon alerts``) drives this module. State: a small JSON
file records the last ``scan_id_b`` processed so repeated runs do not re-emit;
pass ``--no-state`` (``use_state=False``) to ignore it.

Schema note: the ``targets`` table keys on ``(ip, port)`` with INSERT OR REPLACE,
so a single live DB retains only the newest row per endpoint. This generator is
a *reader*: it reflectively loads whatever columns the table exposes (per the
column discovery patterns in ``srecon.db`` / ``srecon.report``) and compares the
rows matching two ``scan_id`` values. Snapshots of the same target can therefore
coexist and be compared whenever the underlying table is scan-versioned — which
is exactly the shape a caller needs to diff two historical snapshots.
"""

import json
import os
import sqlite3

from .config import STATE_DB

# ---------------------------------------------------------------------------
# Kinds / watch names
# ---------------------------------------------------------------------------

NEW = "NEW"
VERDICT_FLIP = "VERDICT_FLIP"
MODEL_CHANGE = "MODEL_CHANGE"
TLS_DROP = "TLS_DROP"
VERIFY_REGRESSION = "VERIFY_REGRESSION"

# All supported watch kinds (also the `--watch` flag values for the CLI).
WATCHES = {
    "new": NEW,
    "flip": VERDICT_FLIP,
    "model": MODEL_CHANGE,
    "tls": TLS_DROP,
    "verify": VERIFY_REGRESSION,
}

_VERDICTS = {"GENUINE", "IMPOSTOR", "UNKNOWN", "DARK", "ERROR"}

# ---------------------------------------------------------------------------
# tiny standalone db reads (no scans executed, no network involved)
# ---------------------------------------------------------------------------


def _list_scans(db_path):
    """Return scan rows (newest first) as a list of dicts, or [] if none."""
    conn = sqlite3.connect(db_path)
    try:
        has = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='scans'").fetchone()
        if not has:
            return []
        rows = conn.execute(
            "SELECT scan_id, started_at FROM scans "
            "ORDER BY started_at DESC, scan_id DESC").fetchall()
    finally:
        conn.close()
    return [{"scan_id": s, "started_at": st} for s, st in rows]


def _load_targets(db_path, scan_id):
    """Load one scan's target rows -> {target: row_dict}.

    Raises FileNotFoundError for a missing DB and ValueError for an unknown
    scan_id, mirroring ``srecon.report.load_db_results``.
    """
    if not os.path.exists(db_path):
        raise FileNotFoundError(
            f"history DB not found: {db_path} (run a scan first to populate it)")
    conn = sqlite3.connect(db_path)
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(targets)")]
        if not cols:
            raise ValueError(f"no history table in {db_path}")
        sel = ", ".join(cols)
        if "scan_id" in cols:
            rows = conn.execute(
                f"SELECT {sel} FROM targets WHERE scan_id = ?",
                (scan_id,)).fetchall()
            if not rows:
                raise ValueError(
                    f"no history rows for scan_id {scan_id} in {db_path}")
        else:
            # legacy v0 DB: scan_id is the rowid
            rows = conn.execute(
                f"SELECT {sel} FROM targets WHERE rowid = ?",
                (scan_id,)).fetchall()
            if not rows:
                raise ValueError(
                    f"no history row with id {scan_id} in {db_path}")
    finally:
        conn.close()
    out = {}
    for r in rows:
        d = dict(zip(cols, r))
        target = f"{d.get('ip')}:{d.get('port')}"
        d["models_served"] = _parse_models(d.get("models_served"))
        d["verdict"] = _norm_verdict(d.get("verdict"))
        out[target] = d
    return out


# ---------------------------------------------------------------------------
# row projection helpers
# ---------------------------------------------------------------------------

def _parse_models(raw):
    """Return a list of model names from the stored models_served field,
    or [] when absent/unparseable."""
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


def _models_set(row):
    return set(_parse_models(row.get("models_served")))


def _norm_verdict(v):
    v = (v or "DARK").upper()
    return v if v in _VERDICTS else "UNKNOWN"


def _tls_enabled(row):
    """Whether a row was served over TLS.

    Uses the persisted ``tls`` column (a JSON dict with an ``enabled`` key) when
    present, else assumes port 443 (the engine's TLS probe port) is TLS.
    """
    raw = row.get("tls")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            raw = None
    if isinstance(raw, dict) and "enabled" in raw:
        return bool(raw["enabled"])
    port = row.get("port")
    try:
        return int(port) == 443
    except (TypeError, ValueError):
        return False


def _verify_regressed(a, b):
    a_v = (a.get("verify_result") or "").lower()
    b_v = (b.get("verify_result") or "").lower()
    return a_v == "live" and b_v in ("auth-walled", "honeypot")


# ---------------------------------------------------------------------------
# alert generation
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


def _severity(kind, new):
    if kind == VERDICT_FLIP:
        return "high" if new == "IMPOSTOR" else "medium"
    if kind == TLS_DROP or kind == VERIFY_REGRESSION:
        return "high"
    if kind == NEW:
        return "medium"
    if kind == MODEL_CHANGE:
        return "low"
    return "low"


def _diff_alerts(rows_a, rows_b, scan_id_b=None, watch=None):
    """Pure comparison of two {target: row} maps -> list of alert dicts.

    ``watch`` is an optional collection of watch names (defaults to all); a
    target's NEW/flip/model/tls/verify signals are emitted independently when a
    target is present in B.
    """
    if watch is None:
        watch = set(WATCHES)
    else:
        watch = {w.lower() for w in watch}
        unknown = watch - set(WATCHES)
        if unknown:
            raise ValueError(
                f"unknown watch kind(s): {', '.join(sorted(unknown))} "
                f"(available: {', '.join(sorted(WATCHES))})")

    am = rows_a
    bm = rows_b
    alerts = []

    for target in sorted(bm):
        b = bm[target]
        b_target = target
        if target in am:
            if "new" in watch:  # sanity: never NEW for a target present in A
                pass
            a = am[target]
            # verdict flip
            if "flip" in watch:
                va, vb = _norm_verdict(a.get("verdict")), _norm_verdict(b.get("verdict"))
                if va != vb:
                    alerts.append({
                        "target": b_target, "kind": VERDICT_FLIP, "watch": "flip",
                        "old": va, "new": vb, "scan_id_b": scan_id_b,
                        "severity": _severity(VERDICT_FLIP, vb),
                    })
            # model change
            if "model" in watch:
                ma, mb = _models_set(a), _models_set(b)
                if ma != mb:
                    alerts.append({
                        "target": b_target, "kind": MODEL_CHANGE, "watch": "model",
                        "old": _join_models(ma),
                        "new": _join_models(mb), "scan_id_b": scan_id_b,
                        "severity": _severity(MODEL_CHANGE, None),
                    })
            # tls drop
            if "tls" in watch:
                ta, tb = _tls_enabled(a), _tls_enabled(b)
                if ta and not tb:
                    alerts.append({
                        "target": b_target, "kind": TLS_DROP, "watch": "tls",
                        "old": "TLS", "new": "plaintext", "scan_id_b": scan_id_b,
                        "severity": _severity(TLS_DROP, None),
                    })
            # verify regression
            if "verify" in watch and _verify_regressed(a, b):
                alerts.append({
                    "target": b_target, "kind": VERIFY_REGRESSION, "watch": "verify",
                    "old": (a.get("verify_result") or "").upper() or "live",
                    "new": (b.get("verify_result") or "").upper(),
                    "scan_id_b": scan_id_b,
                    "severity": _severity(VERIFY_REGRESSION, None),
                })
        elif "new" in watch:
            # target appeared in B only
            summary = f"{b.get('verdict') or ''} {(b.get('product') or '')}".strip()
            alerts.append({
                "target": b_target, "kind": NEW, "watch": "new",
                "old": None, "new": summary or "present", "scan_id_b": scan_id_b,
                "severity": _severity(NEW, None),
            })

    alerts.sort(key=lambda a: (_SEVERITY_RANK.get(a["severity"], 3), a["kind"], a["target"]))
    return alerts


def _join_models(names):
    return ", ".join(sorted(names)) if names else "-"


# ---------------------------------------------------------------------------
# state (dedup) helpers
# ---------------------------------------------------------------------------

def default_state_path(db_path=None):
    """Default dedup-state file: ``alerts_state.json`` next to the DB.

    This keeps temp / alternate DB runs fully isolated from the real
    ``srecon/data`` directory and matches the design default (the state DB lives
    in ``srecon/data``).
    """
    if db_path is None:
        db_path = STATE_DB
    return os.path.join(os.path.dirname(os.path.abspath(db_path)),
                        "alerts_state.json")


def _load_state(state_path):
    try:
        with open(state_path) as f:
            data = json.load(f)
        return int(data.get("last_scan_id_b") or 0)
    except (OSError, ValueError, TypeError):
        return 0


def _save_state(state_path, scan_id_b):
    try:
        os.makedirs(os.path.dirname(state_path) or ".", exist_ok=True)
        with open(state_path, "w") as f:
            json.dump({"last_scan_id_b": scan_id_b}, f)
    except OSError:
        pass  # state is best-effort


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def resolve_scan_pair(db_path=None, baseline_scan_id=None, current_scan_id=None):
    """Resolve the (baseline, current) scan ids to compare.

    With neither given, the two most recent scans are used (A=older, B=newer).
    If only one is given, the other defaults to the most recent other scan.
    Raises ValueError when both resolve to the same scan.
    """
    if db_path is None:
        db_path = STATE_DB
    if not os.path.exists(db_path):
        raise FileNotFoundError(
            f"history DB not found: {db_path} (run a scan first to populate it)")
    scans = _list_scans(db_path)

    if baseline_scan_id is None and current_scan_id is None:
        if len(scans) < 2:
            return None, None
        return scans[1]["scan_id"], scans[0]["scan_id"]

    if current_scan_id is None:
        if not scans:
            return None, None
        current_scan_id = scans[0]["scan_id"]
    if baseline_scan_id is None:
        older = [s["scan_id"] for s in scans if s["scan_id"] != current_scan_id]
        if not older:
            return None, None
        baseline_scan_id = older[0]

    if baseline_scan_id == current_scan_id:
        raise ValueError("baseline and current scan must differ")
    return baseline_scan_id, current_scan_id


def generate_alerts(db_path=None, baseline_scan_id=None, current_scan_id=None,
                    watch=None, state_path=None, use_state=True):
    """Generate security-relevant change alerts between two scans.

    Loads the baseline/current scan snapshots from SQLite, emits an alert per
    watched target that changed (see module docstring), and (unless
    ``use_state`` is False) records ``current scan_id`` in ``state_path`` so
    repeated runs do not re-emit the same batch.

    Returns a list of alert dicts:
        {target, kind, watch, old, new, scan_id_b, severity}
    Emits nothing ([]) when there are no alerts or the state already consumed
    the current scan.

    Raises ``FileNotFoundError`` for a missing DB and ``ValueError`` for an
    unknown scan_id or watch kind.
    """
    if db_path is None:
        db_path = STATE_DB
    baseline, current = resolve_scan_pair(
        db_path, baseline_scan_id, current_scan_id)
    if baseline is None or current is None:
        return []

    if state_path is None:
        state_path = default_state_path(db_path)
    if use_state and _load_state(state_path) >= current:
        return []

    rows_a = _load_targets(db_path, baseline)
    rows_b = _load_targets(db_path, current)
    alerts = _diff_alerts(rows_a, rows_b, scan_id_b=current, watch=watch)

    if use_state:
        _save_state(state_path, current)
    return alerts


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def _change_summary(alert):
    kind = alert["kind"]
    old = alert["old"]
    new = alert["new"]
    if kind == NEW:
        return f"appeared as {new}"
    if kind == TLS_DROP:
        return f"{old} -> {new}"
    if kind in (VERDICT_FLIP, MODEL_CHANGE, VERIFY_REGRESSION):
        return f"{old or '-'} -> {new or '-'}"
    return f"{old or '-'} -> {new or '-'}"


def render_alerts_human(alerts):
    """Render a human-readable table of alerts (no header when empty)."""
    if not alerts:
        return ""
    scan = alerts[0].get("scan_id_b")
    lines = [f"ALERTS for scan {scan} ({len(alerts)} found)", ""]
    hdr = (f"{'SEVERITY':<9} {'KIND':<18} {'TARGET':<26} CHANGE")
    lines.append(hdr)
    lines.append("-" * len(hdr))
    for a in alerts:
        lines.append(
            f"{a['severity']:<9} {a['kind']:<18} {a['target']:<26} "
            f"{_change_summary(a)}")
    return "\n".join(lines)