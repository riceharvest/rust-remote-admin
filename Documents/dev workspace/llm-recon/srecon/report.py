"""Offline report generation for scan results.

Stdlib only. Turns scan results into:

* a self-contained dark-themed HTML report (inline CSS + a tiny inline JS
  snippet, no external assets) with verdict distribution, framework
  breakdown, top ASNs and a sortable results table;
* a Markdown summary report;
* a CSV export of results.

Results are loaded either from a JSON file written by ``scan -o`` (the
``{"results": [...]}`` envelope) or from the SQLite history DB whose schema
lives in ``db.py`` (``srecon/data/state.db``, ``targets`` table).

The ``targets`` table stores the last recorded result per ``ip:port``
(ip, port, verdict, product, score, scanned_at, fp) and has *no* scan_id
column, so ``scan_id`` selects a history row by its SQLite rowid. DB rows
carry fewer fields than live scan results (no model/version/latency/ASN
enrichment) — every renderer tolerates missing keys.
"""

import csv
import html
import io
import json
import os
import sqlite3
from datetime import datetime, timezone

from .config import STATE_DB

VERDICTS = ("GENUINE", "IMPOSTOR", "UNKNOWN", "DARK", "ERROR")

VERDICT_COLORS = {
    "GENUINE": "#22c55e",
    "IMPOSTOR": "#ef4444",
    "UNKNOWN": "#eab308",
    "DARK": "#6b7280",
    "ERROR": "#a855f7",
}

CSV_COLUMNS = [
    "target", "verdict", "product", "version", "model", "score",
    "latency_ms", "asn", "as_name", "bgp_prefix", "net_type", "ptr", "flags",
]


# --------------------------------------------------------------------------
# loaders
# --------------------------------------------------------------------------

def load_json_results(path):
    """Load results from a JSON file as produced by ``scan -o``.

    Accepts either the writer envelope ``{"results": [...], "elapsed_s": ...,
    "total_probed": ...}`` or a bare list of result objects.

    Returns ``(results, meta)`` where ``meta`` carries any envelope keys
    other than ``results``.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        results = data.get("results")
        if not isinstance(results, list):
            raise ValueError(f"{path}: missing 'results' list")
        meta = {k: v for k, v in data.items() if k != "results"}
    elif isinstance(data, list):
        results = data
        meta = {}
    else:
        raise ValueError(f"{path}: expected a JSON object with 'results' or a list")
    return results, meta


def load_db_results(scan_id=None, db_path=None):
    """Load results from the SQLite history DB (schema in ``db.py``).

    ``scan_id=None`` returns the whole history, most recently scanned first.
    ``scan_id=N`` returns the single row whose SQLite ``rowid`` is N (the
    ``targets`` table has no scan_id column; rowid is the stable per-target
    identifier of the last recorded result).

    Raises ``FileNotFoundError`` if the DB file does not exist and
    ``ValueError`` if a requested rowid is not present.
    """
    if db_path is None:
        db_path = STATE_DB
    if not os.path.exists(db_path):
        raise FileNotFoundError(
            f"history DB not found: {db_path} (run a scan first to populate it)")
    conn = sqlite3.connect(db_path)
    try:
        if scan_id is None:
            rows = conn.execute(
                "SELECT rowid, ip, port, verdict, product, score, scanned_at, fp "
                "FROM targets ORDER BY scanned_at DESC, ip, port").fetchall()
        else:
            rows = conn.execute(
                "SELECT rowid, ip, port, verdict, product, score, scanned_at, fp "
                "FROM targets WHERE rowid = ?", (int(scan_id),)).fetchall()
            if not rows:
                raise ValueError(f"no history row with id {scan_id} in {db_path}")
    finally:
        conn.close()
    results = []
    for rowid, ip, port, verdict, product, score, scanned_at, fp in rows:
        results.append({
            "target": f"{ip}:{port}",
            "verdict": verdict or "DARK",
            "product": product or "",
            "score": score or 0,
            "scanned_at": scanned_at,
            "fp": fp or "",
            "_rowid": rowid,
        })
    meta = {"source": "sqlite history", "scan_id": scan_id}
    return results, meta


# --------------------------------------------------------------------------
# aggregation
# --------------------------------------------------------------------------

def summarize(results):
    """Aggregate verdict distribution, framework breakdown, top ASNs."""
    verdicts = {v: 0 for v in VERDICTS}
    frameworks = {}
    asns = {}  # (asn, as_name) -> count
    for r in results:
        v = (r.get("verdict") or "UNKNOWN").upper()
        if v not in verdicts:
            v = "UNKNOWN"
        verdicts[v] += 1
        p = (r.get("product") or "").strip() or "unknown"
        frameworks[p] = frameworks.get(p, 0) + 1
        a = (r.get("asn") or "").strip()
        if a:
            name = (r.get("as_name") or "").strip() or "-"
            asns[(a, name)] = asns.get((a, name), 0) + 1
    return {
        "total": len(results),
        "verdicts": verdicts,
        "frameworks": sorted(frameworks.items(), key=lambda kv: (-kv[1], kv[0])),
        "asns": sorted(asns.items(), key=lambda kv: (-kv[1], kv[0][0])),
    }


def _fmt_scanned(ts):
    """Epoch seconds -> 'YYYY-MM-DD HH:MM UTC' (or '' if missing)."""
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _join_list(value, sep=", "):
    if isinstance(value, (list, tuple)):
        return sep.join(str(x) for x in value)
    return str(value) if value not in (None, "") else ""


def _esc(value):
    return html.escape(str(value) if value is not None else "")


# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------

_CSS = """
:root{--bg:#0b0f17;--panel:#131a29;--panel2:#0f1522;--border:#232e45;--text:#e5e7eb;
--muted:#8b93a7;--accent:#38bdf8;--good:#22c55e;--bad:#ef4444;--warn:#eab308;
--dark:#6b7280;--err:#a855f7;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.wrap{max-width:1200px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:22px;margin:0 0 4px;letter-spacing:.3px}
h1 .dot{color:var(--accent)}
.sub{color:var(--muted);margin:0 0 22px}
h2{font-size:15px;margin:26px 0 10px;text-transform:uppercase;letter-spacing:1.2px;color:var(--accent)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:12px 14px}
.card .n{font-size:24px;font-weight:700}
.card .l{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px}
.card.g .n{color:var(--good)} .card.i .n{color:var(--bad)} .card.u .n{color:var(--warn)}
.card.d .n{color:var(--dark)} .card.e .n{color:var(--err)} .card.t .n{color:var(--accent)}
.bar-row{display:flex;align-items:center;gap:10px;margin:6px 0}
.bar-label{width:110px;color:var(--muted);font-size:12px;text-align:right}
.bar-track{flex:1;background:var(--panel2);border:1px solid var(--border);border-radius:6px;height:18px;overflow:hidden}
.bar-fill{height:100%;border-radius:6px;min-width:2px}
.bar-count{width:60px;font-size:12px;color:var(--text)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:10px;overflow:hidden}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--border);vertical-align:top}
th{background:var(--panel2);color:var(--muted);font-size:11px;text-transform:uppercase;
letter-spacing:.8px;cursor:pointer;user-select:none;white-space:nowrap}
th:hover{color:var(--accent)}
th[data-dir="asc"]::after{content:" \\25B2";color:var(--accent)}
th[data-dir="desc"]::after{content:" \\25BC";color:var(--accent)}
td.num{text-align:right;font-variant-numeric:tabular-nums}
tr:last-child td{border-bottom:none}
.v-GENUINE{color:var(--good);font-weight:700} .v-IMPOSTOR{color:var(--bad);font-weight:700}
.v-UNKNOWN{color:var(--warn)} .v-DARK{color:var(--dark)} .v-ERROR{color:var(--err)}
.tag{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11px;border:1px solid var(--border);background:var(--panel2);color:var(--muted)}
.empty{color:var(--muted);padding:18px;text-align:center}
.small{color:var(--muted);font-size:11px;margin-top:26px}
"""

_JS = """
(function(){
  var table = document.getElementById('results');
  if (!table || !table.tBodies.length) return;
  var headers = Array.prototype.slice.call(table.querySelectorAll('th'));
  headers.forEach(function(th, idx){
    th.addEventListener('click', function(){
      var tb = table.tBodies[0];
      var rows = Array.prototype.slice.call(tb.rows);
      var asc = this.dataset.dir !== 'asc';
      rows.sort(function(a, b){
        var av = a.cells[idx].dataset.v != null ? a.cells[idx].dataset.v : a.cells[idx].textContent.trim();
        var bv = b.cells[idx].dataset.v != null ? b.cells[idx].dataset.v : b.cells[idx].textContent.trim();
        var na = parseFloat(av), nb = parseFloat(bv);
        var cmp = (!isNaN(na) && !isNaN(nb) && av !== '' && bv !== '') ? (na - nb) : av.localeCompare(bv);
        return asc ? cmp : -cmp;
      });
      rows.forEach(function(r){ tb.appendChild(r); });
      headers.forEach(function(h){ h.dataset.dir = ''; });
      this.dataset.dir = asc ? 'asc' : 'desc';
    });
  });
})();
"""


def _html_meta_line(meta):
    bits = []
    if meta:
        src = meta.get("source")
        if src:
            bits.append(f"source: {src}")
        if meta.get("input"):
            bits.append(f"file: {meta['input']}")
        if meta.get("scan_id") is not None:
            bits.append(f"history row: {meta['scan_id']}")
        if meta.get("elapsed_s") is not None:
            bits.append(f"elapsed: {meta['elapsed_s']}s")
        if meta.get("total_probed") is not None:
            bits.append(f"probed: {meta['total_probed']}")
    bits.append("generated: " + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    return " &middot; ".join(bits)


def _html_cards(summary):
    cards = [
        ("t", "Total", summary["total"]),
        ("g", "Genuine", summary["verdicts"]["GENUINE"]),
        ("i", "Impostor", summary["verdicts"]["IMPOSTOR"]),
        ("u", "Unknown", summary["verdicts"]["UNKNOWN"]),
        ("d", "Dark", summary["verdicts"]["DARK"]),
        ("e", "Error", summary["verdicts"]["ERROR"]),
    ]
    return "\n".join(
        f'<div class="card {cls}"><div class="n">{n}</div><div class="l">{lbl}</div></div>'
        for cls, lbl, n in cards)


def _html_verdict_bars(summary):
    total = summary["total"] or 1
    rows = []
    for v in VERDICTS:
        n = summary["verdicts"].get(v, 0)
        pct = round(n / total * 100, 1) if n else 0.0
        color = VERDICT_COLORS.get(v, "#6b7280")
        rows.append(
            f'<div class="bar-row"><span class="bar-label">{_esc(v)}</span>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{color}"></div></div>'
            f'<span class="bar-count">{n} ({pct}%)</span></div>')
    return "\n".join(rows)


def _html_table_rows(results):
    out = []
    for r in results:
        score = r.get("score") or 0
        lat = r.get("latency_ms")
        lat_v = lat if isinstance(lat, (int, float)) else ""
        lat_s = str(lat) if lat is not None and str(lat) != "" else "&mdash;"
        flags = r.get("flags")
        if flags:
            flags = " ".join(f'<span class="tag">{_esc(x)}</span>' for x in flags)
        else:
            flags = "&mdash;"
        verdict = (r.get("verdict") or "UNKNOWN").upper()

        def _cell(value, cls=""):
            # escape first, then fall back to an em-dash placeholder so the
            # entity is not double-escaped into literal "&mdash;" text
            if value is None or str(value).strip() == "":
                body = "&mdash;"
            else:
                body = _esc(value)
            if cls:
                return f'<td class="{cls}">{body}</td>'
            return f"<td>{body}</td>"

        out.append(
            "<tr>"
            + _cell(r.get("target"), "tv")
            + f'<td class="v-{_esc(verdict)}">{_esc(verdict)}</td>'
            + _cell(r.get("product"))
            + _cell(r.get("version"))
            + _cell(r.get("model"))
            + f'<td class="num" data-v="{_esc(score)}">{score}</td>'
            + f'<td class="num" data-v="{_esc(lat_v)}">{lat_s}</td>'
            + _cell(r.get("asn"))
            + _cell(r.get("as_name"))
            + _cell(r.get("bgp_prefix"))
            + _cell(r.get("net_type"))
            + _cell(r.get("ptr"))
            + f"<td>{flags}</td>"
            + "</tr>")
    return "\n".join(out)


def _html_framework_table(frameworks):
    if not frameworks:
        return '<p class="empty">No product data recorded.</p>'
    rows = "".join(
        f'<tr><td>{_esc(name)}</td><td class="num">{n}</td></tr>'
        for name, n in frameworks)
    return f'<table><thead><tr><th>Product</th><th>Count</th></tr></thead><tbody>{rows}</tbody></table>'


def _html_asn_table(asns):
    if not asns:
        return '<p class="empty">No ASN enrichment recorded.</p>'
    rows = "".join(
        f'<tr><td>{_esc(asn)}</td><td>{_esc(name)}</td><td class="num">{n}</td></tr>'
        for (asn, name), n in asns[:10])
    return (f'<table><thead><tr><th>ASN</th><th>Name</th><th>Count</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>')


def render_html(results, meta=None):
    """Render a self-contained dark-themed HTML report (inline CSS + JS)."""
    summary = summarize(results)
    meta = dict(meta or {})
    if meta.get("source") == "sqlite history":
        meta["source"] = f"sqlite history ({STATE_DB})"
    rows_html = _html_table_rows(results)
    if not results:
        rows_html = '<tr><td colspan="13" class="empty">No results recorded.</td></tr>'
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Silicon Recon Report</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
  <h1>Silicon Recon <span class="dot">&#9679;</span> Report</h1>
  <p class="sub">{_html_meta_line(meta)}</p>
  <div class="cards">
{_html_cards(summary)}
  </div>
  <h2>Verdict distribution</h2>
{_html_verdict_bars(summary)}
  <h2>Framework breakdown</h2>
{_html_framework_table(summary["frameworks"])}
  <h2>Top ASNs</h2>
{_html_asn_table(summary["asns"])}
  <h2>Results <span class="small">(click a column header to sort)</span></h2>
  <table id="results">
    <thead><tr>
      <th>Target</th><th>Verdict</th><th>Product</th><th>Version</th><th>Model</th>
      <th>Score</th><th>Latency</th><th>ASN</th><th>AS Name</th><th>BGP Prefix</th>
      <th>Net Type</th><th>PTR</th><th>Flags</th>
    </tr></thead>
    <tbody>
{rows_html}
    </tbody>
  </table>
  <p class="small">Silicon Recon &mdash; stdlib-only offline report &middot; {summary["total"]} result(s)</p>
</div>
<script>{_JS}</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# Markdown report
# --------------------------------------------------------------------------

def _md_escape(value):
    s = str(value) if value is not None else ""
    return s.replace("|", "\\|").replace("\n", " ")


def _md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        out.append("| " + " | ".join(_md_escape(c) for c in row) + " |")
    return "\n".join(out)


def render_markdown(results, meta=None):
    """Render a Markdown summary report."""
    summary = summarize(results)
    meta = dict(meta or {})
    lines = ["# Silicon Recon Report", ""]
    meta_bits = []
    if meta.get("source"):
        meta_bits.append(f"**Source:** {meta['source']}")
    if meta.get("input"):
        meta_bits.append(f"**File:** {meta['input']}")
    if meta.get("scan_id") is not None:
        meta_bits.append(f"**History row:** {meta['scan_id']}")
    if meta.get("elapsed_s") is not None:
        meta_bits.append(f"**Elapsed:** {meta['elapsed_s']}s")
    if meta.get("total_probed") is not None:
        meta_bits.append(f"**Probed:** {meta['total_probed']}")
    meta_bits.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("  \n".join(meta_bits))
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(_md_table(
        ["Verdict", "Count"],
        [[v, summary["verdicts"].get(v, 0)] for v in VERDICTS]))
    lines.append("")

    lines.append("## Frameworks")
    lines.append("")
    lines.append(_md_table(
        ["Product", "Count"],
        [[name, n] for name, n in summary["frameworks"]]))
    lines.append("")

    lines.append("## Top ASNs")
    lines.append("")
    if summary["asns"]:
        lines.append(_md_table(
            ["ASN", "Name", "Count"],
            [[asn, name, n] for (asn, name), n in summary["asns"][:10]]))
    else:
        lines.append("_No ASN enrichment recorded._")
    lines.append("")

    lines.append("## Results")
    lines.append("")
    if results:
        lines.append(_md_table(
            ["Target", "Verdict", "Product", "Version", "Model", "Score", "Latency"],
            [[r.get("target"), r.get("verdict") or "?", r.get("product") or "",
              r.get("version") or "", r.get("model") or "", r.get("score") or 0,
              r.get("latency_ms") if r.get("latency_ms") is not None else ""]
             for r in results]))
    else:
        lines.append("_No results recorded._")
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CSV export
# --------------------------------------------------------------------------

def render_csv(results, meta=None):
    """Render results as CSV (header + one row per result)."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for r in results:
        w.writerow([
            r.get("target", ""),
            r.get("verdict", ""),
            r.get("product", ""),
            r.get("version", ""),
            r.get("model", ""),
            r.get("score", ""),
            r.get("latency_ms", ""),
            r.get("asn", ""),
            r.get("as_name", ""),
            r.get("bgp_prefix", ""),
            r.get("net_type", ""),
            r.get("ptr", ""),
            _join_list(r.get("flags"), "; "),
        ])
    return buf.getvalue()


# --------------------------------------------------------------------------
# dispatch
# --------------------------------------------------------------------------

def render_report(results, fmt="html", meta=None):
    """Render ``results`` in the requested format: html, md or csv."""
    fmt = (fmt or "html").lower()
    if fmt == "html":
        return render_html(results, meta)
    if fmt == "md":
        return render_markdown(results, meta)
    if fmt == "csv":
        return render_csv(results, meta)
    raise ValueError(f"unknown format: {fmt} (expected html, md or csv)")
