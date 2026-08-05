"""Offline tests for srecon.writeup (monthly census writeup generator).

Uses the tempdir module-global patching pattern from test_publish.py /
test_certs.py: db.DATA_DIR / db.STATE_DB are repointed at a TemporaryDirectory
so no real project state is touched, and no network is involved. collect_month
is always called with an explicit db_path pointing at that temp DB.

Covers:
* collect_month aggregation matches the seeded month (scans, targets,
  verdicts, honeypot ratio, frameworks + delta vs previous month, top ASNs,
  top models, alert summary, cert summary);
* render_html contains every narrative section and the engraved palette;
* render_markdown contains the summary numbers;
* the CLI honours --include-targets (ip:port listed) and omits raw IPs by
  default (no IPv4 pattern in the HTML);
* an empty month renders gracefully.
"""
import io
import json
import os
import re
import sqlite3
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from srecon import db, writeup  # noqa: E402

IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

YEAR, MONTH = 2026, 7
MONTH_START = datetime(YEAR, MONTH, 1, tzinfo=timezone.utc).timestamp()


def _engine_ts(days_from_now):
    """Engine-style 'YYYY-MM-DD HH:MM UTC' not_after offset from now."""
    when = (datetime.now(timezone.utc) + timedelta(days=days_from_now))
    return when.strftime("%Y-%m-%d %H:%M UTC")


class WriteupTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = (db.DATA_DIR, db.STATE_DB, db.BLOCKLIST_FILE)
        db.DATA_DIR = self._tmp.name
        db.STATE_DB = os.path.join(self._tmp.name, "state.db")
        db.BLOCKLIST_FILE = os.path.join(self._tmp.name, "honeypot_blocklist.txt")
        db._init_db().close()  # build the v4 schema in the temp DB
        self.db_path = db.STATE_DB

    def tearDown(self):
        db.DATA_DIR, db.STATE_DB, db.BLOCKLIST_FILE = self._orig
        self._tmp.cleanup()

    # ----- seeding ------------------------------------------------------
    def _add_scan(self, started_at):
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.execute(
                "INSERT INTO scans (started_at, target_count) VALUES (?,?)",
                (started_at, 0))
            sid = cur.lastrowid
            conn.commit()
        finally:
            conn.close()
        return sid

    def _insert(self, ip, port, verdict, product=None, score=0,
                scanned_at=None, scan_id=None, model=None,
                models_served=None, asn=None, as_name=None, tls=None):
        """Insert one targets row directly (full control over timestamps)."""
        now = scanned_at if scanned_at is not None else MONTH_START + 86400
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO targets "
                "(ip,port,verdict,product,score,scanned_at,scan_id,model,"
                "models_served,asn,as_name,tls) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (ip, port, verdict, product, score, now, scan_id, model,
                 json.dumps(models_served) if models_served is not None else None,
                 asn, as_name, json.dumps(tls) if tls is not None else None))
            conn.commit()
        finally:
            conn.close()

    def _seed_july(self):
        """Two July scans + targets spanning all verdicts/frameworks/ASNs,
        plus June rows for the framework-shift delta and TLS rows for the
        cert summary."""
        # --- June (previous month) rows ---------------------------------
        jun_start = datetime(2026, 6, 1, tzinfo=timezone.utc).timestamp()
        self._insert("10.6.0.1", 8000, "GENUINE", "vllm", score=60,
                     scanned_at=jun_start + 3600)
        self._insert("10.6.0.2", 11434, "GENUINE", "ollama", score=70,
                     scanned_at=jun_start + 7200)
        # --- July scans ---------------------------------------------------
        scan_old = self._add_scan(MONTH_START + 2 * 86400)
        scan_new = self._add_scan(MONTH_START + 20 * 86400)
        # scan_old rows (baseline for the alert diff)
        self._insert("10.99.0.99", 8000, "DARK", None, score=0,
                     scanned_at=MONTH_START + 2 * 86400, scan_id=scan_old)
        self._insert("10.99.0.98", 8000, "ERROR", None, score=0,
                     scanned_at=MONTH_START + 2 * 86400, scan_id=scan_old)
        self._insert("10.5.0.1", 443, "GENUINE", "vllm", score=60,
                     scanned_at=MONTH_START + 2 * 86400, scan_id=scan_old,
                     model="llama-3.1-8b", asn="AS1000", as_name="Alpha DC",
                     tls={"enabled": True, "issuer": "CN=crit-ca",
                          "subject": "CN=crit-host",
                          "fingerprint_sha256": "a" * 64,
                          "not_after": _engine_ts(3), "self_signed": True})
        # scan_new rows (current scan -> 8 NEW alerts vs scan_old)
        self._insert("10.0.0.1", 8000, "GENUINE", "vllm", score=90,
                     scanned_at=MONTH_START + 20 * 86400, scan_id=scan_new,
                     model="llama-3.1-8b", asn="AS1000", as_name="Alpha DC",
                     tls={"enabled": True, "issuer": "CN=ok-ca",
                          "subject": "CN=ok-host",
                          "fingerprint_sha256": "b" * 64,
                          "not_after": _engine_ts(200), "self_signed": False})
        self._insert("10.0.0.2", 8000, "GENUINE", "vllm", score=85,
                     scanned_at=MONTH_START + 20 * 86400, scan_id=scan_new,
                     model="llama-3.1-70b", asn="AS1000", as_name="Alpha DC")
        self._insert("10.0.0.3", 8000, "UNKNOWN", "vllm", score=40,
                     scanned_at=MONTH_START + 20 * 86400, scan_id=scan_new,
                     model="qwen2.5-7b", asn="AS1000", as_name="Alpha DC")
        self._insert("10.0.1.1", 8080, "GENUINE", "llamacpp", score=80,
                     scanned_at=MONTH_START + 20 * 86400, scan_id=scan_new,
                     model="mistral-7b", asn="AS1000", as_name="Alpha DC")
        self._insert("10.0.1.2", 8080, "IMPOSTOR", "llamacpp", score=40,
                     scanned_at=MONTH_START + 20 * 86400, scan_id=scan_new,
                     asn="AS1000", as_name="Alpha DC")
        self._insert("10.0.2.1", 11434, "GENUINE", "ollama", score=95,
                     scanned_at=MONTH_START + 20 * 86400, scan_id=scan_new,
                     model="qwen3:8b", asn="AS2000", as_name="Beta")
        self._insert("10.0.2.2", 11434, "GENUINE", "ollama", score=75,
                     scanned_at=MONTH_START + 20 * 86400, scan_id=scan_new,
                     model="phi3:mini", asn="AS2000", as_name="Beta")
        self._insert("10.0.3.1", 8000, "GENUINE", "vllm", score=70,
                     scanned_at=MONTH_START + 20 * 86400, scan_id=scan_new,
                     model="deepseek-r1:7b", asn="AS3000", as_name="Gamma")
        return scan_old, scan_new

    def _collect(self, include_targets=False):
        return writeup.collect_month(db_path=self.db_path, year=YEAR,
                                     month=MONTH,
                                     include_targets=include_targets)

    def _run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = writeup._main(list(argv))
        return rc, buf.getvalue()


class CollectMonthTest(WriteupTestCase):
    def test_aggregates_match_seeded_month(self):
        self._seed_july()
        w = self._collect()
        self.assertEqual(w["month_key"], "2026-07")
        self.assertEqual(w["scan_count"], 2)
        self.assertEqual(w["target_count"], 11)
        self.assertEqual(w["verdicts"],
                         {"GENUINE": 7, "IMPOSTOR": 1, "UNKNOWN": 1,
                          "DARK": 1, "ERROR": 1})
        self.assertEqual(w["live_count"], 9)
        self.assertAlmostEqual(w["honeypot_ratio"], 1 / 9, places=4)
        # scores: 90+85+40+80+40+95+75+70+60 = 635 over 11 rows
        self.assertAlmostEqual(w["avg_score"], round(635 / 11, 2), places=2)

    def test_frameworks_with_previous_month_delta(self):
        self._seed_july()
        w = self._collect()
        by_name = {f["name"]: f for f in w["frameworks"]}
        # vllm: 5 rows this month (4 genuine) vs 1 in June -> delta +4
        self.assertEqual(by_name["vllm"]["count"], 5)
        self.assertEqual(by_name["vllm"]["genuine"], 4)
        self.assertEqual(by_name["vllm"]["prev_count"], 1)
        self.assertEqual(by_name["vllm"]["delta"], 4)
        # ollama: 2 rows vs 1 in June -> delta +1
        self.assertEqual(by_name["ollama"]["count"], 2)
        self.assertEqual(by_name["ollama"]["delta"], 1)
        # llamacpp: 2 rows vs none in June -> delta +2
        self.assertEqual(by_name["llamacpp"]["count"], 2)
        self.assertEqual(by_name["llamacpp"]["delta"], 2)
        # DARK/ERROR rows have no product -> unknown bucket
        self.assertEqual(by_name["unknown"]["count"], 2)
        # sorted by count desc
        counts = [f["count"] for f in w["frameworks"]]
        self.assertEqual(counts, sorted(counts, reverse=True))

    def test_top_asns_and_models(self):
        self._seed_july()
        w = self._collect()
        # live-only ASN counts: AS1000 has 6, AS2000 has 2, AS3000 has 1
        self.assertEqual(w["top_asns"][0]["asn"], "AS1000")
        self.assertEqual(w["top_asns"][0]["count"], 6)
        self.assertEqual(w["top_asns"][1]["count"], 2)
        self.assertEqual(w["top_asns"][2]["count"], 1)
        # no raw IPs in the aggregate surface
        for entry in w["top_asns"]:
            self.assertNotIn("10.", str(entry))
        # model families: llama 3, then qwen2.5/qwen3/mistral/phi3/deepseek 1
        self.assertEqual(w["top_models"][0]["family"], "llama")
        self.assertEqual(w["top_models"][0]["count"], 3)

    def test_alert_summary_counts_new_kind(self):
        self._seed_july()
        w = self._collect()
        a = w["alert_summary"]
        self.assertEqual(a["total"], 8)  # every scan_new target is NEW
        self.assertEqual(a["counts"].get("NEW"), 8)
        self.assertEqual(a["by_severity"]["medium"], 8)
        self.assertEqual(a["by_severity"]["high"], 0)
        # targets are NOT leaked by default
        self.assertEqual(a["top_alerts"], [])

    def test_cert_summary_present_with_counts(self):
        self._seed_july()
        w = self._collect()
        cs = w["cert_summary"]
        self.assertIsNotNone(cs)
        self.assertEqual(cs["total"], 2)
        self.assertEqual(cs["counts"].get("ok"), 1)
        self.assertEqual(cs["counts"].get("critical"), 1)
        self.assertEqual(cs["top_expiring"], [])  # no raw cert records by default

    def test_no_targets_field_without_include_targets(self):
        self._seed_july()
        w = self._collect(include_targets=False)
        self.assertEqual(w["targets"], [])

    def test_include_targets_populates_manifest(self):
        self._seed_july()
        w = self._collect(include_targets=True)
        self.assertTrue(w["targets"])
        # highest score first
        self.assertEqual(w["targets"][0]["ip"], "10.0.2.1")
        self.assertEqual(w["targets"][0]["score"], 95)


class RenderTest(WriteupTestCase):
    def test_render_html_contains_all_sections_and_palette(self):
        self._seed_july()
        w = self._collect()
        doc = writeup.render_html(w)
        for section in ("EXECUTIVE SUMMARY", "FRAMEWORK SHIFT",
                        "EXPOSURE TREND", "NOTABLE EVENTS", "CERT HYGIENE"):
            self.assertIn(section, doc, "missing section %s" % section)
        # engraved-terminal palette + design tokens
        for token in ("#f4f1e8", "#1a2ee6", "Didone", "cross-hatch",
                      "engraved", "hairline", "monospace"):
            self.assertIn(token, doc, "missing palette token %s" % token)
        # summary numbers appear
        self.assertIn("11", doc)
        self.assertIn("11.1%", doc)  # 1/9 honeypot ratio

    def test_render_html_default_omits_raw_ips(self):
        self._seed_july()
        w = self._collect(include_targets=False)
        doc = writeup.render_html(w)
        self.assertFalse(IPV4_RE.search(doc),
                         "IPv4 pattern leaked: %s" % IPV4_RE.search(doc))

    def test_render_html_include_targets_lists_ip(self):
        self._seed_july()
        w = self._collect(include_targets=True)
        doc = writeup.render_html(w)
        self.assertIn("10.0.2.1:11434", doc)
        self.assertIn("TARGET MANIFEST", doc)

    def test_render_markdown_contains_summary_numbers(self):
        self._seed_july()
        w = self._collect()
        md = writeup.render_markdown(w)
        for section in ("EXECUTIVE SUMMARY", "FRAMEWORK SHIFT",
                        "EXPOSURE TREND", "NOTABLE EVENTS", "CERT HYGIENE"):
            self.assertIn(section, md)
        self.assertIn("**11 endpoint(s)**", md)
        self.assertIn("| 2 | 11 | 9 | 7 | 1 | 11.1% | 57.73 |", md)
        self.assertIn("11.1%", md)
        self.assertIn("| GENUINE | 7 |", md)
        self.assertIn("- **NEW**: 8", md)

    def test_render_markdown_default_omits_raw_ips(self):
        self._seed_july()
        w = self._collect(include_targets=False)
        md = writeup.render_markdown(w)
        self.assertFalse(IPV4_RE.search(md))

    def test_empty_month_renders_gracefully(self):
        w = self._collect()  # seeded DB, but no rows in July
        self.assertEqual(w["target_count"], 0)
        self.assertEqual(w["scan_count"], 0)
        self.assertEqual(w["frameworks"], [])
        self.assertEqual(w["alert_summary"]["counts"], {})
        doc = writeup.render_html(w)
        self.assertIn("no data for this period", doc)
        self.assertIn("EXECUTIVE SUMMARY", doc)
        md = writeup.render_markdown(w)
        self.assertIn("no data for this period", md)
        self.assertFalse(IPV4_RE.search(doc))
        self.assertFalse(IPV4_RE.search(md))

    def test_missing_db_renders_gracefully(self):
        w = writeup.collect_month(db_path="/nonexistent/x.db", year=YEAR,
                                  month=MONTH)
        self.assertEqual(w["target_count"], 0)
        doc = writeup.render_html(w)
        self.assertIn("no data for this period", doc)


class CliTest(WriteupTestCase):
    def _out(self, name):
        return os.path.join(self._tmp.name, name)

    def test_include_targets_lists_ip_and_exits_zero(self):
        self._seed_july()
        out = self._out("report.html")
        rc, printed = self._run_cli(
            "--db", self.db_path, "--year", "2026", "--month", "7",
            "--format", "html", "--out", out, "--include-targets")
        self.assertEqual(rc, 0)
        self.assertEqual(printed.strip(), out)
        self.assertTrue(os.path.isfile(out))
        with open(out, encoding="utf-8") as fh:
            doc = fh.read()
        self.assertIn("10.0.0.1:8000", doc)
        self.assertIn("TARGET MANIFEST", doc)

    def test_default_omits_ips(self):
        self._seed_july()
        out = self._out("report.html")
        rc, _ = self._run_cli(
            "--db", self.db_path, "--year", "2026", "--month", "7",
            "--format", "html", "--out", out)
        self.assertEqual(rc, 0)
        with open(out, encoding="utf-8") as fh:
            doc = fh.read()
        self.assertFalse(IPV4_RE.search(doc),
                         "IPv4 leaked without --include-targets")

    def test_markdown_format_writes_md(self):
        self._seed_july()
        out = self._out("report.md")
        rc, _ = self._run_cli(
            "--db", self.db_path, "--year", "2026", "--month", "7",
            "--format", "md", "--out", out)
        self.assertEqual(rc, 0)
        with open(out, encoding="utf-8") as fh:
            md = fh.read()
        self.assertIn("EXECUTIVE SUMMARY", md)
        self.assertIn("**11 endpoint(s)**", md)
        self.assertFalse(IPV4_RE.search(md))

    def test_empty_month_cli_exits_zero(self):
        out = self._out("empty.html")
        rc, _ = self._run_cli(
            "--db", self.db_path, "--year", "2026", "--month", "7",
            "--format", "html", "--out", out)
        self.assertEqual(rc, 0)
        with open(out, encoding="utf-8") as fh:
            doc = fh.read()
        self.assertIn("no data for this period", doc)


if __name__ == "__main__":
    unittest.main()
