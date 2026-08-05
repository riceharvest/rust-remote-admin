"""Offline monthly-census writeup generator for Silicon Recon (srecon).

Long-form, engraved-terminal style monthly reports generated entirely offline
from the SQLite history DB (no network, no scanning). Pulls the scan rows and
target rows whose timestamps fall in a given month, aggregates them in the same
coarse style as ``srecon.publish`` (fine for a private report — counts only,
never raw IPs unless ``--include-targets``), folds in the month's change
alerts (``srecon.alert``) and TLS cert hygiene (``srecon.certs``), and renders
a self-contained HTML page or plain Markdown.

The HTML is fully self-contained (inline CSS, no external assets) in the
"engraved terminal" design language: cream plate, ultramarine accent, Didone
serif headlines, monospace data tables, 1px hairline rules and cross-hatch
accents.

Standalone CLI (same pattern as ``srecon/imports.py`` / ``srecon/certs.py``;
``srecon/__main__.py`` is untouched)::

    python3 -m srecon.writeup [--year N] [--month N] [--format html|md]
                              [--out PATH] [--include-targets] [--db PATH]

``--include-targets`` lists live targets (``ip:port``) — private use only,
OFF by default. Exit code 0 on success.
"""
import argparse
import html
import json
import os
import re
import sqlite3
import time
from datetime import datetime, timezone

from .config import STATE_DB
from . import alert
from . import certs

VERDICTS = ("GENUINE", "IMPOSTOR", "UNKNOWN", "DARK", "ERROR")
LIVE_VERDICTS = ("GENUINE", "IMPOSTOR", "UNKNOWN")

# Design tokens for the engraved-terminal HTML renderer (kept here so tests
# can assert the palette literally).
CREAM = "#f4f1e8"
CREAM_2 = "#f8f6ef"
INK = "#1a1a18"
BLUE = "#1a2ee6"
GRAY = "#6b6a63"

_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _utc_iso(ts=None):
    """Epoch seconds -> ISO-8601 UTC string, or None."""
    if ts is None:
        ts = time.time()
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError):
        return None


def _family(model_or_none):
    """Coarse model family from a model string ('llama-3.1-8b' -> 'llama')."""
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


def _prev_month(year, month):
    """(prev_year, prev_month) for a (year, month) pair."""
    if month <= 1:
        return year - 1, 12
    return year, month - 1


def _month_bounds(year, month):
    """(start_ts, end_ts) for a calendar month, exclusive end, in UTC."""
    first = datetime(year, month, 1, tzinfo=timezone.utc)
    if month == 12:
        nxt = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        nxt = datetime(year, month + 1, 1, tzinfo=timezone.utc)
    return first.timestamp(), nxt.timestamp()


def _scan_ids_in_month(conn, start, end):
    """scan_ids whose started_at falls in [start, end), newest first."""
    has = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='scans'"
    ).fetchone()
    if not has:
        return []
    rows = conn.execute(
        "SELECT scan_id FROM scans WHERE started_at >= ? AND started_at < ? "
        "ORDER BY started_at DESC, scan_id DESC",
        (start, end)).fetchall()
    return [r[0] for r in rows]


def _target_rows_in_month(conn, start, end):
    """Target rows scanned in [start, end) -> (rows, idx).

    Column selection is reflective (like publish/report) so legacy v0 tables
    still load; the raw identity columns (ip/port) are only selected so the
    optional private target manifest can be built — they never reach any
    renderer unless ``include_targets`` is set.
    """
    cols = _columns(conn)
    want = ("ip", "port", "verdict", "product", "score", "scanned_at",
            "model", "models_served", "asn", "as_name")
    pick = [c for c in want if c in cols]
    col_sql = ", ".join('"%s"' % c for c in pick)
    rows = conn.execute(
        "SELECT %s FROM targets WHERE scanned_at >= ? AND scanned_at < ?"
        % col_sql, (start, end)).fetchall()
    idx = {c: i for i, c in enumerate(pick)}
    return rows, idx


def _framework_counts(conn, start, end):
    """{product: count} for target rows in a time window (shift baseline)."""
    rows, idx = _target_rows_in_month(conn, start, end)
    counts = {}
    if "product" not in idx:
        return counts
    for r in rows:
        product = (r[idx["product"]] or "").strip()
        name = product or "unknown"
        counts[name] = counts.get(name, 0) + 1
    return counts


def _month_alerts(db_path, scans, include_targets):
    """Counts by kind/severity from alert.generate_alerts on the month's
    two most recent scans. Never leaks targets unless include_targets."""
    base = {
        "total": 0, "counts": {}, "top_alerts": [],
        "by_severity": {"high": 0, "medium": 0, "low": 0},
        "note": None,
    }
    if len(scans) < 2:
        base["note"] = "fewer than two scans this month — no diff available"
        return base
    baseline, current = scans[1], scans[0]  # scans already newest-first
    try:
        alerts_list = alert.generate_alerts(
            db_path, baseline_scan_id=baseline, current_scan_id=current,
            use_state=False)
    except Exception as exc:  # noqa: BLE001 - tolerate any diff failure
        base["note"] = "alert diff unavailable: %s" % exc
        return base
    counts = {}
    sev = {"high": 0, "medium": 0, "low": 0}
    for a in alerts_list:
        kind = a.get("kind") or "OTHER"
        counts[kind] = counts.get(kind, 0) + 1
        s = a.get("severity")
        if s in sev:
            sev[s] += 1
    out = {"total": len(alerts_list), "counts": counts,
           "by_severity": sev, "note": None}
    if include_targets and alerts_list:
        out["top_alerts"] = [
            {"kind": a.get("kind"), "severity": a.get("severity"),
             "target": a.get("target"), "old": a.get("old"),
             "new": a.get("new")}
            for a in alerts_list[:8]]
    else:
        out["top_alerts"] = []
    return out


def _cert_summary(db_path, include_targets):
    """certs.summarize() result, with raw cert records stripped unless
    include_targets (a cert record carries ip/target strings)."""
    try:
        summ = certs.summarize(db_path, top=6)
    except Exception:  # noqa: BLE001 - tolerate missing tls column / bad DB
        return None
    out = {"total": summ.get("total", 0),
           "counts": dict(summ.get("counts") or {})}
    if include_targets and summ.get("top_expiring"):
        out["top_expiring"] = [dict(c) for c in summ["top_expiring"][:6]]
    else:
        out["top_expiring"] = []
    return out


def collect_month(db_path=None, year=None, month=None, include_targets=False):
    """Collect one calendar month of census data into a writeup dict.

    Pulls the scans (``started_at``) and targets (``scanned_at``) that fall in
    ``year``/``month`` (default: the current month, UTC) and aggregates them
    publish-style — counts only, no raw IPs unless ``include_targets``.

    Returns a dict with ``month_key``, ``scan_count``, ``target_count``,
    ``verdicts``, ``frameworks`` (+ per-framework ``prev_count``/``delta`` vs
    the previous month), ``honeypot_ratio``, ``avg_score``, ``top_asns``,
    ``top_models``, ``alert_summary`` and ``cert_summary``. A missing or empty
    DB yields a zeroed dict so renderers always have something to draw.
    """
    now = datetime.now(timezone.utc)
    year = now.year if year is None else year
    month = now.month if month is None else month

    out = {
        "year": year, "month": month,
        "month_key": "%04d-%02d" % (year, month),
        "generated_at": _utc_iso(),
        "scan_count": 0, "target_count": 0,
        "verdicts": {v: 0 for v in VERDICTS},
        "live_count": 0,
        "genuine_count": 0, "impostor_count": 0, "unknown_count": 0,
        "dark_count": 0, "error_count": 0,
        "honeypot_ratio": 0.0, "avg_score": 0.0,
        "frameworks": [], "top_asns": [], "top_models": [],
        "alert_summary": _month_alerts(db_path, [], include_targets),
        "cert_summary": None,
        "targets": [],
    }
    if db_path is None:
        db_path = STATE_DB
    if not os.path.exists(db_path):
        return out

    try:
        conn = sqlite3.connect(db_path)
    except sqlite3.Error:
        return out

    try:
        start, end = _month_bounds(year, month)
        rows, idx = _target_rows_in_month(conn, start, end)
        scans = _scan_ids_in_month(conn, start, end)
        out["scan_count"] = len(scans)
        out["target_count"] = len(rows)

        verdicts = {v: 0 for v in VERDICTS}
        total_score = 0.0
        fw = {}       # product -> {"count","genuine","scores":[]}
        model_family = {}
        asns = {}     # (asn, as_name) -> count, live hosts only
        targets = []  # private manifest rows, only when include_targets

        def _g(r, name):
            return r[idx[name]] if name in idx else None

        for r in rows:
            verdict = str(_g(r, "verdict") or "DARK").upper()
            if verdict not in verdicts:
                verdict = "UNKNOWN"
            verdicts[verdict] += 1

            score = _g(r, "score")
            try:
                val = float(score) if score is not None else 0.0
            except (TypeError, ValueError):
                val = 0.0
            total_score += val

            product = (_g(r, "product") or "").strip()
            name = product or "unknown"
            entry = fw.setdefault(name, {"count": 0, "genuine": 0,
                                         "scores": []})
            entry["count"] += 1
            if verdict == "GENUINE":
                entry["genuine"] += 1
            entry["scores"].append(val)

            model = _g(r, "model")
            fam = _family(model)
            if not fam:
                served = _decode_models(_g(r, "models_served"))
                fam = _family(served[0]) if served else None
            if fam:
                model_family[fam] = model_family.get(fam, 0) + 1

            if verdict in LIVE_VERDICTS:
                asn = (_g(r, "asn") or "")
                as_name = (_g(r, "as_name") or "")
                key = ((str(asn).strip() or "unknown"),
                       (str(as_name).strip() if as_name else ""))
                asns[key] = asns.get(key, 0) + 1
                if include_targets:
                    targets.append({
                        "ip": str(_g(r, "ip")),
                        "port": _g(r, "port"),
                        "verdict": verdict,
                        "product": product,
                        "score": val,
                    })

        for v in VERDICTS:
            out["%s_count" % v.lower()] = verdicts[v]
        out["verdicts"] = verdicts
        out["live_count"] = sum(verdicts[v] for v in LIVE_VERDICTS)
        out["honeypot_ratio"] = round(
            verdicts["IMPOSTOR"] / max(1, out["live_count"]), 4)
        out["avg_score"] = round(total_score / len(rows), 2) if rows else 0.0

        frameworks = [
            {"name": n,
             "count": e["count"],
             "genuine": e["genuine"],
             "avg_score": round(sum(e["scores"]) / len(e["scores"]), 2)
             if e["scores"] else 0.0}
            for n, e in fw.items()]
        frameworks.sort(key=lambda f: (-f["count"], f["name"]))

        # shift vs the previous month (counts only, no identity data)
        py, pm = _prev_month(year, month)
        ps, pe = _month_bounds(py, pm)
        prev_counts = _framework_counts(conn, ps, pe)
        for f in frameworks:
            f["prev_count"] = prev_counts.get(f["name"], 0)
            f["delta"] = f["count"] - f["prev_count"]
        out["frameworks"] = frameworks

        asn_ranked = sorted(asns.items(), key=lambda kv: (-kv[1], kv[0][0]))
        out["top_asns"] = [
            {"asn": k[0], "as_name": k[1], "count": c}
            for k, c in asn_ranked[:20]]

        model_ranked = sorted(model_family.items(),
                              key=lambda kv: (-kv[1], kv[0]))
        out["top_models"] = [
            {"family": k, "count": c} for k, c in model_ranked[:10]]

        out["alert_summary"] = _month_alerts(db_path, scans, include_targets)
        out["cert_summary"] = _cert_summary(db_path, include_targets)

        if include_targets:
            targets.sort(key=lambda t: (-t["score"], t["ip"]))
            out["targets"] = targets[:50]
    finally:
        conn.close()
    return out


# ---------------------------------------------------------------------------
# HTML rendering — engraved terminal, fully self-contained
# ---------------------------------------------------------------------------

_CSS = """\
/* ============================================================================
   SILICON RECON — monthly census writeup
   Design system: "engraved terminal"
   cream #f4f1e8 plate · ultramarine #1a2ee6 accent · Didone serif headlines
   monospace data tables · 1px hairline rules · cross-hatch accents
   ========================================================================== */
:root {
  --cream:  #f4f1e8;
  --cream-2:#f8f6ef;
  --ink:    #1a1a18;
  --blue:   #1a2ee6;
  --gray:   #6b6a63;
  --hair:       rgba(26, 26, 24, 0.35);
  --hair-soft:  rgba(26, 26, 24, 0.18);
  --hair-strong:rgba(26, 26, 24, 0.6);
  --serif: 'Didot', 'Bodoni MT', 'Cormorant Garamond', Georgia,
           'Times New Roman', serif;   /* Didone serif headlines */
  --mono:  ui-monospace, 'Cascadia Mono', Consolas,
           'Liberation Mono', 'DejaVu Sans Mono', monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--cream); color: var(--ink);
  font-family: var(--mono); font-size: 14px; line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 900px; margin: 0 auto; padding: 40px 22px 80px; }
.hero {
  text-align: center; padding: 40px 20px 34px;
  border-bottom: 2px solid var(--ink); box-shadow: 0 1px 0 var(--hair);
}
.kicker {
  margin: 0 0 12px; font-size: 11px; font-weight: 700;
  text-transform: uppercase; letter-spacing: 0.3em; color: var(--blue);
}
.hero-title {
  margin: 0; font-family: var(--serif); font-weight: 400;
  font-size: clamp(2rem, 5.4vw, 3.4rem); line-height: 1.06;
  letter-spacing: 0.015em; text-transform: uppercase;
}
.hero-title::after {
  content: ""; display: block; width: 72px; height: 1px;
  margin: 20px auto 0; background: var(--ink); opacity: 0.55;
}
.tagline {
  margin: 16px auto 0; max-width: 620px; font-size: 11px;
  text-transform: uppercase; letter-spacing: 0.16em; opacity: 0.72;
}
section { margin: 38px 0; }
.rule { display: flex; align-items: center; gap: 14px; margin-bottom: 16px; }
.rule::before, .rule::after {
  content: ""; flex: 1; height: 1px; background: var(--hair);
}
.rule-label {
  font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.18em; white-space: nowrap;
}
.rule-label::before { content: "\\2014\\2002"; color: var(--hair-strong); }
.rule-label::after  { content: "\\2002\\2014"; color: var(--hair-strong); }
.lede { font-family: var(--serif); font-size: 16.5px; line-height: 1.6; }
.stat-strip {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px; margin: 18px 0;
}
.stat {
  background: var(--cream-2); border: 1px groove rgba(26, 26, 24, 0.45);
  border-radius: 2px; padding: 13px 15px 11px;
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.6),
              inset 0 -1px 0 rgba(26, 26, 24, 0.12);
}
.stat-label {
  font-size: 10px; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.16em; opacity: 0.6; margin-bottom: 7px;
}
.stat-num { font-size: 1.7rem; line-height: 1; font-variant-numeric: tabular-nums; }
.stat-num.blue { color: var(--blue); }
.stat-num.dim  { color: var(--gray); }
.hatch {
  height: 6px; margin: 14px 0; border: 1px solid var(--hair);
  background: repeating-linear-gradient(
    45deg, var(--blue) 0, var(--blue) 2px, transparent 2px, transparent 4px);
  opacity: 0.55;
}
table.census {
  width: 100%; border-collapse: collapse; font-size: 12.5px;
  font-variant-numeric: tabular-nums;
}
table.census th {
  font-size: 10px; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.18em; text-align: left; padding: 8px 12px 8px 0;
  border-bottom: 1px solid var(--ink); box-shadow: 0 1px 0 var(--hair);
  white-space: nowrap;
}
table.census th.num, table.census td.num { text-align: right; }
table.census td {
  padding: 8px 12px 8px 0; border-bottom: 1px solid var(--hair);
  vertical-align: top; white-space: nowrap;
}
table.census tbody tr:last-child td { border-bottom: none; }
table.census .up   { color: var(--blue); font-weight: 700; }
table.census .down { color: var(--gray); opacity: 0.7; }
.placeholder {
  color: var(--gray); opacity: 0.6; font-style: italic;
  letter-spacing: 0.05em; font-size: 12.5px; text-align: center;
  padding: 22px 10px; border: 1px dashed var(--hair);
}
.statusbar {
  position: sticky; bottom: 0; z-index: 20; display: flex; flex-wrap: wrap;
  align-items: center; gap: 6px 0; background: var(--ink); color: var(--cream);
  font-size: 11px; letter-spacing: 0.07em; padding: 9px 16px;
  box-shadow: 0 -2px 0 rgba(26, 26, 24, 0.9), 0 -6px 14px rgba(26, 26, 24, 0.25);
}
.statusbar span { padding: 0 12px; border-right: 1px solid rgba(244, 241, 232, 0.28); }
.statusbar .sb-blue { color: #7d8bff; }
@media (max-width: 720px) {
  .wrap { padding: 26px 14px 80px; }
  .stat-strip { grid-template-columns: repeat(2, 1fr); }
  .hero { padding: 30px 14px 26px; }
}
@media print { .statusbar { position: static; } body { background: #fff; } }
"""


def _esc(value):
    return html.escape("" if value is None else str(value))


def _fmt_pct(ratio):
    return "%.1f%%" % (ratio * 100)


def _verdict_rows(writeup):
    v = writeup["verdicts"]
    for verdict in VERDICTS:
        yield (verdict, v.get(verdict, 0))


def render_html(writeup, style="engraved"):
    """Self-contained engraved-terminal HTML page for a monthly writeup.

    ``style`` is accepted for API symmetry; ``'engraved'`` is the only design
    implemented (an unknown style falls back to it).
    """
    m = writeup["month_key"]
    total = writeup["target_count"]
    scans = writeup["scan_count"]
    live = writeup["live_count"]
    hp = _fmt_pct(writeup["honeypot_ratio"])
    sections = []

    # ---- EXECUTIVE SUMMARY ------------------------------------------------
    parts = ["<section>", '<div class="rule"><span class="rule-label">'
                          "EXECUTIVE SUMMARY</span></div>"]
    if total == 0:
        parts.append(
            '<p class="lede">No census rows were recorded in %s. '
            "The month is quiet — either no scans ran, or every monitored "
            "endpoint fell outside the collection window.</p>" % _esc(m))
        parts.append('<p class="placeholder">no data for this period</p>')
    else:
        parts.append(
            '<p class="lede">In %s, Silicon Recon completed %d scan run%s, '
            "touching %d monitored endpoint%s. Of those, %d tested genuine, "
            "%d were classified impostor (a honeypot ratio of %s), and %d "
            "remained unknown. Mean confidence score across the census was "
            "%.2f.</p>"
            % (_esc(m), scans, "" if scans == 1 else "s", total,
               "" if total == 1 else "s", writeup["genuine_count"],
               writeup["impostor_count"], hp, writeup["unknown_count"],
               writeup["avg_score"]))
    parts.append('<div class="stat-strip">')
    for label, num, cls in (
            ("scans", str(scans), ""),
            ("endpoints", str(total), "blue"),
            ("live", str(live), ""),
            ("genuine", str(writeup["genuine_count"]), ""),
            ("impostor", str(writeup["impostor_count"]), ""),
            ("honeypot ratio", hp, "dim"),
            ("avg score", "%.2f" % writeup["avg_score"], "dim")):
        parts.append(
            '<div class="stat"><div class="stat-label">%s</div>'
            '<div class="stat-num %s">%s</div></div>'
            % (label, cls, _esc(num)))
    parts.append("</div><div class='hatch'></div></section>")
    sections.append("".join(parts))

    # ---- FRAMEWORK SHIFT ---------------------------------------------------
    parts = ["<section>", '<div class="rule"><span class="rule-label">'
                          "FRAMEWORK SHIFT</span></div>"]
    if not writeup["frameworks"]:
        parts.append('<p class="placeholder">no framework data this month</p>')
    else:
        parts.append(
            "<p class='lede'>Detected serving frameworks, ordered by row "
            "count, with the delta versus %s.</p>" % _esc(_prev_key(m)))
        parts.append("<table class='census'><thead><tr>"
                     "<th>Framework</th><th class='num'>Rows</th>"
                     "<th class='num'>Genuine</th><th class='num'>Avg score</th>"
                     "<th class='num'>vs prev</th></tr></thead><tbody>")
        for f in writeup["frameworks"]:
            delta = f.get("delta", 0)
            cls = "up" if delta > 0 else ("down" if delta < 0 else "")
            sign = ("+%d" % delta) if delta > 0 else str(delta)
            parts.append(
                "<tr><td>%s</td><td class='num'>%d</td>"
                "<td class='num'>%d</td><td class='num'>%.2f</td>"
                "<td class='num %s'>%s</td></tr>"
                % (_esc(f["name"]), f["count"], f["genuine"],
                   f.get("avg_score", 0.0), cls, sign))
        parts.append("</tbody></table>")
    sections.append("".join(parts))

    # ---- EXPOSURE TREND ----------------------------------------------------
    parts = ["<section>", '<div class="rule"><span class="rule-label">'
                          "EXPOSURE TREND</span></div>"]
    if total == 0:
        parts.append('<p class="placeholder">no verdict data this month</p>')
    else:
        parts.append(
            "<p class='lede'>Verdict mix across every endpoint recorded in "
            "%s.</p>" % _esc(m))
        parts.append("<table class='census'><thead><tr>"
                     "<th>Verdict</th><th class='num'>Endpoints</th>"
                     "<th class='num'>Share</th></tr></thead><tbody>")
        for verdict, count in _verdict_rows(writeup):
            share = (count / total * 100.0) if total else 0.0
            parts.append(
                "<tr><td>%s</td><td class='num'>%d</td>"
                "<td class='num'>%.1f%%</td></tr>"
                % (_esc(verdict), count, share))
        parts.append("</tbody></table>")
        if writeup["top_models"]:
            parts.append("<p class='lede'>Most-served model families:</p>")
            parts.append("<table class='census'><thead><tr>"
                         "<th>Family</th><th class='num'>Rows</th>"
                         "</tr></thead><tbody>")
            for tm in writeup["top_models"]:
                parts.append("<tr><td>%s</td><td class='num'>%d</td></tr>"
                             % (_esc(tm["family"]), tm["count"]))
            parts.append("</tbody></table>")
    sections.append("".join(parts))

    # ---- NOTABLE EVENTS ----------------------------------------------------
    parts = ["<section>", '<div class="rule"><span class="rule-label">'
                          "NOTABLE EVENTS</span></div>"]
    alert_summary = writeup["alert_summary"] or {}
    if not alert_summary.get("counts"):
        parts.append(
            "<p class='lede'>No security-relevant changes were detected "
            "between the month's scans%s.</p>"
            % ((" (%s)" % alert_summary["note"])
               if alert_summary.get("note") else ""))
        parts.append('<p class="placeholder">no alerts</p>')
    else:
        sev = alert_summary.get("by_severity", {})
        parts.append(
            "<p class='lede'>%d change alert%s fired between the month's "
            "scan pairs: %d high, %d medium, %d low.</p>"
            % (alert_summary["total"],
               "" if alert_summary["total"] == 1 else "s",
               sev.get("high", 0), sev.get("medium", 0), sev.get("low", 0)))
        parts.append("<table class='census'><thead><tr>"
                     "<th>Kind</th><th class='num'>Count</th>"
                     "</tr></thead><tbody>")
        for kind, count in sorted(alert_summary["counts"].items(),
                                  key=lambda kv: (-kv[1], kv[0])):
            parts.append("<tr><td>%s</td><td class='num'>%d</td></tr>"
                         % (_esc(kind), count))
        parts.append("</tbody></table>")
    sections.append("".join(parts))

    # ---- CERT HYGIENE -------------------------------------------------------
    parts = ["<section>", '<div class="rule"><span class="rule-label">'
                          "CERT HYGIENE</span></div>"]
    cert_summary = writeup.get("cert_summary")
    if not cert_summary or not cert_summary.get("total"):
        parts.append(
            "<p class='lede'>No TLS certificates are on record, so there is "
            "nothing to expire.</p>")
        parts.append('<p class="placeholder">no TLS records</p>')
    else:
        counts = cert_summary.get("counts", {})
        parts.append(
            "<p class='lede'>%d certificate%s currently on record across the "
            "census: %d ok, %d warn, %d critical, %d expired.</p>"
            % (cert_summary["total"],
               "" if cert_summary["total"] == 1 else "s",
               counts.get("ok", 0), counts.get("warn", 0),
               counts.get("critical", 0), counts.get("expired", 0)))
        if cert_summary.get("top_expiring"):
            parts.append("<table class='census'><thead><tr>"
                         "<th>Issuer</th><th>Subject</th>"
                         "<th class='num'>Days left</th></tr></thead><tbody>")
            for c in cert_summary["top_expiring"]:
                parts.append(
                    "<tr><td>%s</td><td>%s</td><td class='num'>%.1f</td></tr>"
                    % (_esc(c.get("issuer") or "-"),
                       _esc(c.get("subject") or "-"),
                       c.get("days_left", 0.0)))
            parts.append("</tbody></table>")
    sections.append("".join(parts))

    # ---- TARGET MANIFEST (private, opt-in) ----------------------------------
    if writeup.get("targets"):
        parts = ["<section>", '<div class="rule"><span class="rule-label">'
                              "TARGET MANIFEST — PRIVATE</span></div>",
                 "<p class='lede'>Live endpoints recorded this month "
                 "(ip:port), most-confident first. This section is only "
                 "present because the report was generated with "
                 "--include-targets.</p>",
                 "<table class='census'><thead><tr><th>Target</th>"
                 "<th>Verdict</th><th>Product</th>"
                 "<th class='num'>Score</th></tr></thead><tbody>"]
        for t in writeup["targets"]:
            parts.append(
                "<tr><td>%s:%s</td><td>%s</td><td>%s</td><td class='num'>%.0f"
                "</td></tr>"
                % (_esc(t["ip"]), _esc(t["port"]), _esc(t["verdict"]),
                   _esc(t.get("product") or "-"), t.get("score", 0)))
        parts.append("</tbody></table></section>")
        sections.append("".join(parts))

    body = "\n".join(sections)
    status = ("DATA: offline private monthly report &middot; no raw addresses "
              "unless --include-targets")
    doc = (
        "<!DOCTYPE html>\n<html lang='en'>\n<head>\n"
        "<meta charset='utf-8'>\n"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
        "<title>Silicon Recon — monthly census writeup %s</title>\n"
        "<style>%s</style>\n</head>\n<body>\n"
        "<header class='hero'><p class='kicker'>Silicon Recon &middot; "
        "offline monthly census</p>"
        "<h1 class='hero-title'>Monthly Writeup &mdash; %s</h1>"
        "<p class='tagline'>engraved long-form census report &middot; "
        "generated %s &middot; no network &middot; no scanning</p>"
        "</header>\n<div class='wrap'>\n%s\n</div>\n"
        "<footer class='statusbar'><span class='sb-blue'>SRECON</span>"
        "<span>%s</span></footer>\n</body>\n</html>\n"
    ) % (_esc(m), _CSS, _esc(m), _esc(writeup.get("generated_at") or ""),
         body, status)
    return doc


def _prev_key(month_key):
    """'YYYY-MM' -> previous 'YYYY-MM' label (for prose only)."""
    try:
        y, m = month_key.split("-")
        py, pm = _prev_month(int(y), int(m))
        return "%04d-%02d" % (py, pm)
    except (ValueError, AttributeError):
        return "the prior month"


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def render_markdown(writeup):
    """Plain Markdown version of the writeup for email/newsletter."""
    m = writeup["month_key"]
    total = writeup["target_count"]
    lines = [
        "# Silicon Recon — monthly census writeup %s" % m,
        "",
        "*Generated %s — offline, no network, no scanning.*"
        % (writeup.get("generated_at") or "?"),
        "",
        "## EXECUTIVE SUMMARY",
        "",
    ]
    if total == 0:
        lines += [
            "No census rows were recorded in %s." % m,
            "",
            "> no data for this period",
            "",
        ]
    else:
        lines += [
            "In %s, Silicon Recon completed **%d scan run(s)** touching "
            "**%d endpoint(s)**. %d genuine, %d impostor (honeypot ratio "
            "**%s**), %d unknown. Mean confidence score **%.2f**."
            % (m, writeup["scan_count"], total, writeup["genuine_count"],
               writeup["impostor_count"], _fmt_pct(writeup["honeypot_ratio"]),
               writeup["unknown_count"], writeup["avg_score"]),
            "",
            "| scans | endpoints | live | genuine | impostor | honey ratio | avg score |",
            "|---|---|---|---|---|---|---|",
            "| %d | %d | %d | %d | %d | %s | %.2f |"
            % (writeup["scan_count"], total, writeup["live_count"],
               writeup["genuine_count"], writeup["impostor_count"],
               _fmt_pct(writeup["honeypot_ratio"]), writeup["avg_score"]),
            "",
        ]
    lines += ["## FRAMEWORK SHIFT", ""]
    if not writeup["frameworks"]:
        lines += ["> no framework data this month", ""]
    else:
        lines += ["| framework | rows | genuine | avg score | vs %s |"
                  % _prev_key(m), "|---|---|---|---|---|"]
        for f in writeup["frameworks"]:
            delta = f.get("delta", 0)
            sign = ("+%d" % delta) if delta > 0 else str(delta)
            lines.append(
                "| %s | %d | %d | %.2f | %s |"
                % (f["name"], f["count"], f["genuine"],
                   f.get("avg_score", 0.0), sign))
        lines.append("")
    lines += ["## EXPOSURE TREND", ""]
    if total == 0:
        lines += ["> no verdict data this month", ""]
    else:
        lines += ["| verdict | endpoints | share |", "|---|---|---|"]
        for verdict, count in _verdict_rows(writeup):
            share = (count / total * 100.0) if total else 0.0
            lines.append("| %s | %d | %.1f%% |" % (verdict, count, share))
        lines.append("")
        if writeup["top_models"]:
            lines += ["Most-served model families:", ""]
            for tm in writeup["top_models"]:
                lines.append("- %s: %d" % (tm["family"], tm["count"]))
            lines.append("")
    lines += ["## NOTABLE EVENTS", ""]
    alert_summary = writeup["alert_summary"] or {}
    if not alert_summary.get("counts"):
        lines += ["> no alerts"
                  + ((" (%s)" % alert_summary["note"])
                     if alert_summary.get("note") else ""), ""]
    else:
        sev = alert_summary.get("by_severity", {})
        lines += [
            "%d change alert(s) fired between the month's scan pairs: "
            "%d high, %d medium, %d low."
            % (alert_summary["total"], sev.get("high", 0),
               sev.get("medium", 0), sev.get("low", 0)),
            "",
        ]
        for kind, count in sorted(alert_summary["counts"].items(),
                                  key=lambda kv: (-kv[1], kv[0])):
            lines.append("- **%s**: %d" % (kind, count))
        lines.append("")
    lines += ["## CERT HYGIENE", ""]
    cert_summary = writeup.get("cert_summary")
    if not cert_summary or not cert_summary.get("total"):
        lines += ["> no TLS records", ""]
    else:
        counts = cert_summary.get("counts", {})
        lines += [
            "%d certificate(s) on record: %d ok, %d warn, %d critical, "
            "%d expired." % (cert_summary["total"], counts.get("ok", 0),
                             counts.get("warn", 0), counts.get("critical", 0),
                             counts.get("expired", 0)),
            "",
        ]
        if cert_summary.get("top_expiring"):
            for c in cert_summary["top_expiring"]:
                lines.append("- %s (%s): %.1f days left"
                             % (c.get("subject") or "-",
                                c.get("issuer") or "-",
                                c.get("days_left", 0.0)))
            lines.append("")
    if writeup.get("targets"):
        lines += ["## TARGET MANIFEST — private", "",
                  "Live endpoints recorded this month (ip:port). Present only "
                  "because --include-targets was set.", ""]
        for t in writeup["targets"]:
            lines.append("- `%s:%s` %s (%s, score %.0f)"
                         % (t["ip"], t["port"], t["verdict"],
                            t.get("product") or "-", t.get("score", 0)))
        lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI: python3 -m srecon.writeup [--year N] [--month N] [--format html|md]
#                                [--out PATH] [--include-targets] [--db PATH]
# ---------------------------------------------------------------------------

def _default_out_dir():
    return os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "site", "reports")


def _default_out_path(month_key, fmt):
    return os.path.join(_default_out_dir(),
                        "%s.%s" % (month_key, "html" if fmt == "html" else "md"))


def _main(argv=None):
    parser = argparse.ArgumentParser(
        prog="srecon.writeup",
        description="Offline monthly census writeup generator.")
    parser.add_argument("--year", type=int, default=None,
                        help="year (default: current year)")
    parser.add_argument("--month", type=int, default=None,
                        help="month 1-12 (default: current month)")
    parser.add_argument("--format", choices=["html", "md"], default="html",
                        help="output format (default: html)")
    parser.add_argument("--out", default=None, metavar="PATH",
                        help="output file path (default: site/reports/YYYY-MM.<ext>)")
    parser.add_argument("--include-targets", action="store_true",
                        help="list live targets ip:port in the report "
                             "(PRIVATE use only; off by default)")
    parser.add_argument("--db", default=None, metavar="PATH",
                        help="path to the state DB (default: project state.db)")
    args = parser.parse_args(argv)

    writeup = collect_month(db_path=args.db, year=args.year,
                            month=args.month,
                            include_targets=args.include_targets)
    fmt = args.format
    if args.out:
        out_path = args.out
    else:
        out_path = _default_out_path(writeup["month_key"], fmt)

    text = render_html(writeup) if fmt == "html" else render_markdown(writeup)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
