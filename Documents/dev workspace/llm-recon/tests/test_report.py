"""Offline tests for srecon.report CLI/reporting additions (round 2).

Uses the same module-global patching pattern as test_db.py: db.DATA_DIR /
db.STATE_DB / db.BLOCKLIST_FILE AND report.STATE_DB are repointed at a
TemporaryDirectory so no real project state is touched and no network is
involved. report.py calls ``from .config import STATE_DB`` at import time and
keeps it as its own module global, so it too must be repointed.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from srecon import db, report  # noqa: E402


class ReportTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._db_orig = (db.DATA_DIR, db.STATE_DB, db.BLOCKLIST_FILE)
        db.DATA_DIR = self._tmp.name
        db.STATE_DB = os.path.join(self._tmp.name, "state.db")
        db.BLOCKLIST_FILE = os.path.join(self._tmp.name, "honeypot_blocklist.txt")
        self._rep_orig = report.STATE_DB
        report.STATE_DB = db.STATE_DB
        db._init_db().close()

    def tearDown(self):
        report.STATE_DB = self._rep_orig
        db.DATA_DIR, db.STATE_DB, db.BLOCKLIST_FILE = self._db_orig
        self._tmp.cleanup()

    # ----- helpers ----------------------------------------------------
    def _seed_scan(self, rows, verdict_stats=None, params=None):
        sid = db.start_scan(target_count=len(rows), params=params or {"fast": True})
        db.store_results(rows, scan_id=sid)
        db.finish_scan(sid, stats={"verdicts": verdict_stats or {}})
        return sid


class ScansListingTest(ReportTestCase):
    def test_scan_view_parses_verdict_counts_and_status(self):
        sid = db.start_scan(target_count=4)
        db.finish_scan(sid, stats={
            "verdicts": {"GENUINE": 3, "IMPOSTOR": 0, "UNKNOWN": 1,
                         "DARK": 0, "ERROR": 0}})
        scan = db.get_scan(sid)
        v = report.scan_view(scan)
        self.assertEqual(v["scan_id"], sid)
        self.assertEqual(v["target_count"], 4)
        self.assertEqual(v["status"], "finished")
        self.assertEqual(v["verdicts"]["GENUINE"], 3)
        self.assertEqual(v["verdicts"]["UNKNOWN"], 1)
        self.assertTrue(v["started"].endswith("UTC"))

    def test_scan_view_unfinished_is_running(self):
        sid = db.start_scan()
        v = report.scan_view(db.get_scan(sid))
        self.assertEqual(v["status"], "running")
        self.assertEqual(v["finished"], "")

    def test_scan_view_reflects_stopped_and_error_status(self):
        a = db.start_scan()
        db.finish_scan(a, stats={"status": "stopped", "verdicts": {}})
        b = db.start_scan()
        db.finish_scan(b, stats={"status": "error", "error": "boom", "verdicts": {}})
        self.assertEqual(report.scan_view(db.get_scan(a))["status"], "stopped")
        self.assertEqual(report.scan_view(db.get_scan(b))["status"], "error")

    def test_render_scans_human_contains_rows(self):
        sid = self._seed_scan(
            [{"target": "1.1.1.1:8000", "verdict": "GENUINE"}],
            verdict_stats={"GENUINE": 1, "IMPOSTOR": 0, "UNKNOWN": 0,
                           "DARK": 0, "ERROR": 0})
        text = report.render_scans_human([report.scan_view(s) for s in db.list_scans()])
        lines = text.splitlines()
        self.assertIn(str(sid), lines[2])  # header (0) + rule (1) + row (2)


class DiffTest(ReportTestCase):
    def _row(self, target, verdict="GENUINE", product="vllm", version=None,
             model=None, models=None):
        r = {"target": target, "verdict": verdict, "product": product,
             "version": version, "model": model, "score": 0}
        if models is not None:
            r["models_served"] = models
        return r

    def test_classify_diff_changed_variants(self):
        a = [
            self._row("1.1.1.1:8000", verdict="GENUINE", product="vllm",
                      version="0.6.4", models=["llama-8b"]),
            # verdict flip UNKNOWN -> IMPOSTOR
            self._row("2.2.2.2:8000", verdict="UNKNOWN", product="ollama",
                      version="0.5.7", models=["qwen2.5:7b"]),
            # version + model-set change
            self._row("3.3.3.3:8000", verdict="GENUINE", product="llamacpp",
                      version="b4000", models=["mistral:7b"]),
        ]
        b = [
            # unchanged (must not be flagged)
            self._row("1.1.1.1:8000", verdict="GENUINE", product="vllm",
                      version="0.6.4", models=["llama-8b"]),
            self._row("2.2.2.2:8000", verdict="IMPOSTOR", product="ollama",
                      version="0.5.7", models=["qwen2.5:7b"]),
            self._row("3.3.3.3:8000", verdict="GENUINE", product="llamacpp",
                      version="b4199", models=["qwen3:8b"]),
            # brand new
            self._row("4.4.4.4:8000", verdict="GENUINE", product="vllm",
                      version="0.7.0", models=["deepseek-r1:7b"]),
        ]
        d = report.classify_diff(a, b)
        self.assertEqual(d["summary"], {"new": 1, "gone": 0, "changed": 2})
        self.assertEqual([r["target"] for r in d["new"]], ["4.4.4.4:8000"])
        changed = {c["target"]: c["changes"] for c in d["changed"]}
        self.assertNotIn("1.1.1.1:8000", changed)  # unchanged target NOT flagged
        self.assertEqual(changed["2.2.2.2:8000"]["verdict"], ["UNKNOWN", "IMPOSTOR"])
        self.assertEqual(changed["3.3.3.3:8000"]["version"], ["b4000", "b4199"])
        self.assertEqual(changed["3.3.3.3:8000"]["models"],
                         [["mistral:7b"], ["qwen3:8b"]])

    def test_classify_diff_gone(self):
        # shared target carries model data on both sides -> identical, no change
        a = [self._row("1.1.1.1:8000", models=["x"]), self._row("2.2.2.2:8000", models=["y"])]
        b = [self._row("1.1.1.1:8000", models=["x"])]
        d = report.classify_diff(a, b)
        self.assertEqual(d["summary"], {"new": 0, "gone": 1, "changed": 0})
        self.assertEqual([r["target"] for r in d["gone"]], ["2.2.2.2:8000"])

    def test_classify_diff_legacy_row_model_change_is_unknown(self):
        # rich row in A vs legacy row (no model data) in B for the same target
        a = [self._row("9.9.9.9:8080", model="llama-8b", models=["llama-8b"])]
        b = [self._row("9.9.9.9:8080")]  # legacy: no model/models_served
        d = report.classify_diff(a, b)
        self.assertEqual(d["summary"]["changed"], 1)
        c = d["changed"][0]
        self.assertEqual(c["target"], "9.9.9.9:8080")
        self.assertEqual(c["changes"]["models"], "unknown")
        # both legacy but otherwise identical -> models 'unknown' too, no false 'no change'
        d2 = report.classify_diff(
            [self._row("9.9.9.9:8080")], [self._row("9.9.9.9:8080")])
        self.assertEqual(d2["summary"]["changed"], 1)
        self.assertEqual(d2["changed"][0]["changes"]["models"], "unknown")

    def test_diff_scans_db_new_gone(self):
        # disjoint-ish scans through the DB path: B re-records 1.1.1.1 (which
        # replaces A's row per the ip:port PRIMARY KEY), so A keeps only rows
        # B did not touch -> NEW/GONE; CHANGED needs in-memory snapshots
        a = self._seed_scan([
            {"target": "1.1.1.1:8000", "verdict": "GENUINE", "product": "vllm"},
            {"target": "2.2.2.2:8000", "verdict": "UNKNOWN", "product": "ollama"},
            {"target": "3.3.3.3:8000", "verdict": "GENUINE", "product": "llamacpp"},
        ], verdict_stats={"GENUINE": 2, "UNKNOWN": 1, "IMPOSTOR": 0, "DARK": 0, "ERROR": 0})
        b = self._seed_scan([
            {"target": "1.1.1.1:8000", "verdict": "GENUINE", "product": "vllm"},
            {"target": "4.4.4.4:8000", "verdict": "GENUINE", "product": "vllm"},
        ], verdict_stats={"GENUINE": 2, "UNKNOWN": 0, "IMPOSTOR": 0, "DARK": 0, "ERROR": 0})
        d = report.diff_scans(a, b)
        self.assertEqual(d["scan_a"], a)
        self.assertEqual(d["scan_b"], b)
        # A keeps only the rows B did not touch (2.2.2.2, 3.3.3.3); B holds
        # 1.1.1.1 (which replaced A's copy) + 4.4.4.4 -> both are 'new' to A
        self.assertEqual(d["summary"], {"new": 2, "gone": 2, "changed": 0})
        self.assertEqual([r["target"] for r in d["new"]],
                         ["1.1.1.1:8000", "4.4.4.4:8000"])
        self.assertEqual(sorted(r["target"] for r in d["gone"]),
                         ["2.2.2.2:8000", "3.3.3.3:8000"])

    def test_diff_render_human_has_summary_line(self):
        a = [self._row("1.1.1.1:8000"), self._row("2.2.2.2:8000")]
        b = [self._row("1.1.1.1:8000", version="0.9.0"), self._row("3.3.3.3:8000")]
        d = report.classify_diff(a, b)
        text = report.render_diff_human(d)
        self.assertIn("NEW (1)", text)
        self.assertIn("GONE (1)", text)
        self.assertIn("CHANGED (1)", text)
        self.assertIn("SUMMARY: 1 new, 1 gone, 1 changed", text)
        self.assertIn("version: - -> 0.9.0", text)


class ReportJsonTest(ReportTestCase):
    def test_render_json_is_valid_json_with_fields(self):
        sid = self._seed_scan([
            {"target": "1.1.1.1:8000", "verdict": "GENUINE", "product": "vllm",
             "version": "0.6.4", "model": "llama-8b",
             "models_served": ["llama-8b"], "score": 60, "latency_ms": 412,
             "verify_result": "PASS", "asn": "398090"},
        ])
        results, meta = report.load_db_results(sid)
        out = report.render_report(results, "json", {"scan_id": sid})
        doc = json.loads(out)
        self.assertIn("meta", doc)
        self.assertIn("summary", doc)
        self.assertEqual(len(doc["results"]), 1)
        r = doc["results"][0]
        self.assertEqual(r["target"], "1.1.1.1:8000")
        self.assertEqual(r["model"], "llama-8b")
        self.assertEqual(r["verify_result"], "PASS")
        self.assertEqual(doc["summary"]["verdicts"]["GENUINE"], 1)


class ScanIdReportRenderTest(ReportTestCase):
    def test_scan_id_report_includes_verify_column(self):
        sid = self._seed_scan([
            {"target": "1.1.1.1:8000", "verdict": "GENUINE", "product": "vllm",
             "model": "llama-8b", "verify_result": "PASS", "latency_ms": 99},
        ])
        results, meta = report.load_db_results(sid)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["model"], "llama-8b")
        self.assertEqual(results[0]["verify_result"], "PASS")
        html = report.render_html(results, meta)
        self.assertIn("<th>Verify</th>", html)
        self.assertIn('class="vbadge v-pass"', html)
        self.assertIn("PASS", html)

    def test_report_scans_embeds_scan_session_section(self):
        sid = self._seed_scan(
            [{"target": "1.1.1.1:8000", "verdict": "GENUINE", "product": "vllm"}],
            verdict_stats={"GENUINE": 1, "IMPOSTOR": 0, "UNKNOWN": 0, "DARK": 0, "ERROR": 0},
            params={"fast": True})
        scans = db.list_scans()
        results, meta = report.load_db_results(sid)
        md = report.render_markdown(results, meta, scans=scans)
        self.assertIn("## Scan history", md)
        self.assertIn(str(sid), md)
        self.assertIn("fast", md)  # params_json pretty-printed, visible
        # json embeds the decoded session list
        doc = json.loads(report.render_json(results, meta, scans=scans))
        self.assertEqual(len(doc["scans"]), 1)
        self.assertEqual(doc["scans"][0]["scan_id"], sid)
        self.assertEqual(doc["scans"][0]["params"]["fast"], True)


class LoadDbResultsRichTest(ReportTestCase):
    def test_rich_columns_present_and_models_decoded(self):
        sid = self._seed_scan([
            {"target": "1.1.1.1:8000", "verdict": "GENUINE", "product": "vllm",
             "version": "0.6.4", "model": "llama-8b",
             "models_served": ["a", "b"], "verify_result": "PASS",
             "latency_ms": 42.5, "asn": "AS1234", "as_name": "Acme",
             "bgp_prefix": "1.1.1.0/24", "net_type": "datacenter"},
        ])
        results, meta = report.load_db_results(sid)
        r = results[0]
        self.assertEqual(r["models_served"], ["a", "b"])  # decoded from JSON
        self.assertEqual(r["asn"], "AS1234")
        self.assertEqual(r["latency_ms"], 42.5)
        self.assertEqual(meta["scan_id"], sid)

    def test_db_flags_round_trip_and_legacy_null_loads_empty(self):
        sid = self._seed_scan([
            {"target": "1.1.1.1:8000", "verdict": "GENUINE", "product": "vllm",
             "flags": ["IMPORTED_SHODAN", "CLOUD_ONLY"]},
            {"target": "2.2.2.2:8000", "verdict": "UNKNOWN"},  # NULL flags
        ])
        results, _ = report.load_db_results(sid)
        by_target = {r["target"]: r for r in results}
        self.assertEqual(by_target["1.1.1.1:8000"]["flags"],
                         ["IMPORTED_SHODAN", "CLOUD_ONLY"])
        self.assertEqual(by_target["2.2.2.2:8000"]["flags"], [])

    def test_db_backed_report_renders_flags_in_html(self):
        sid = self._seed_scan([
            {"target": "1.1.1.1:8000", "verdict": "GENUINE", "product": "vllm",
             "flags": ["IMPORTED_SHODAN", "TLS_FALLBACK"]},
        ])
        results, meta = report.load_db_results(sid)
        html = report.render_html(results, meta)
        self.assertIn('class="tag"', html)
        self.assertIn("IMPORTED_SHODAN", html)
        self.assertIn("TLS_FALLBACK", html)

    def test_summarize_aggregates_top_flags(self):
        results = [
            {"verdict": "GENUINE", "flags": ["IMPORTED_SHODAN", "CLOUD_ONLY"]},
            {"verdict": "UNKNOWN", "flags": ["IMPORTED_SHODAN"]},
            {"verdict": "DARK"},  # no flags
            {"verdict": "GENUINE", "flags": ["TLS_FALLBACK"]},
        ]
        s = report.summarize(results)
        self.assertEqual(s["top_flags"], [
            ("IMPORTED_SHODAN", 2), ("CLOUD_ONLY", 1), ("TLS_FALLBACK", 1)])


if __name__ == "__main__":
    unittest.main()