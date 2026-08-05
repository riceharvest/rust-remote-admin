"""Offline tests for srecon.alert (the change-alert generator).

Uses a tempdir SQLite DB (never the real srecon/data/state.db). Because the
product store is INSERT OR REPLACE on (ip,port) and therefore keeps only the
newest row per endpoint, this test seeds a *scan-versioned* targets table
(PK ip,port,scan_id) so two historical snapshots of the same target can coexist
and be diffed — exactly the shape the generator is designed to read. All reads
are reflective (column discovery via PRAGMA), so the generator works unchanged
against this shape or the production store. No network, no scanning.
"""
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from srecon import alert  # noqa: E402


class AlertTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "state.db")
        self._make_db()
        self.scan_ids = []  # in creation order

    def tearDown(self):
        self._tmp.cleanup()

    # ---- db seeding helpers ------------------------------------------------
    def _make_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.executescript(
                """
                CREATE TABLE scans (
                  scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                  started_at REAL, finished_at REAL,
                  target_count INTEGER, params_json TEXT, stats_json TEXT);
                CREATE TABLE targets (
                  ip TEXT NOT NULL, port INTEGER NOT NULL,
                  verdict TEXT NOT NULL, product TEXT, score INTEGER DEFAULT 0,
                  scanned_at REAL NOT NULL, fp TEXT, scan_id INTEGER,
                  model TEXT, models_served TEXT, version TEXT,
                  verify_result TEXT, verify_detail TEXT, latency_ms REAL,
                  asn TEXT, as_name TEXT, bgp_prefix TEXT, net_type TEXT,
                  error TEXT, tls TEXT,
                  PRIMARY KEY (ip, port, scan_id));
                """)
            conn.commit()
        finally:
            conn.close()

    def add_scan(self, started_at=None):
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.execute(
                "INSERT INTO scans (started_at, target_count) VALUES (?,?)",
                (started_at if started_at is not None else time.time(), 0))
            sid = cur.lastrowid
            conn.commit()
        finally:
            conn.close()
        self.scan_ids.append(sid)
        return sid

    def add_target(self, ip, port, scan_id, verdict="GENUINE", product="",
                   models_served=None, verify_result=None, tls=None):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "INSERT INTO targets "
                "(ip,port,verdict,product,scanned_at,scan_id,models_served,"
                "verify_result,tls) VALUES (?,?,?,?,?,?,?,?,?)",
                (ip, port, verdict, product, time.time(), scan_id,
                 json.dumps(models_served) if models_served is not None else None,
                 verify_result, tls))
            conn.commit()
        finally:
            conn.close()

    def by_kind(self, alerts):
        return {a["kind"]: a for a in alerts}

    def state_path(self):
        return os.path.join(self._tmp.name, "alerts_state.json")

    # ---- fixtures ----------------------------------------------------------
    def seed_known_diff(self):
        """Two scans with a target exercising each diff kind (+ one GONE)."""
        a = self.add_scan(100.0)
        b = self.add_scan(200.0)
        # scan A (baseline)
        self.add_target("10.0.0.1", 8000, a, verdict="GENUINE", product="vllm",
                        models_served=[], verify_result="live")        # flip
        self.add_target("10.0.0.2", 8000, a, "GENUINE", "ollama",
                        ["a"])                                       # model
        self.add_target("10.0.0.3", 8000, a, "GENUINE", "vllm",
                        [], "live", '{"enabled": true}')             # tls
        self.add_target("10.0.0.4", 8000, a, "GENUINE", "vllm",
                        [], "live")                                  # verify
        self.add_target("10.0.0.6", 8000, a, "GENUINE", "vllm")     # gone
        # scan B (current)
        self.add_target("10.0.0.1", 8000, b, verdict="IMPOSTOR",
                        product="ollama")                            # flip -> IMPOSTOR
        self.add_target("10.0.0.2", 8000, b, "GENUINE", "ollama",
                        ["a", "b"])                                 # model changed
        self.add_target("10.0.0.3", 8000, b, "GENUINE", "vllm",
                        [], "live", '{"enabled": false}')            # tls dropped
        self.add_target("10.0.0.4", 8000, b, "GENUINE", "vllm",
                        [], "honeypot")                              # verify regression
        self.add_target("10.0.0.5", 8000, b, "GENUINE", "ollama",
                        ["qwen2:7b"])                                # new
        return a, b

    # ---- tests -------------------------------------------------------------
    def test_each_watch_kind_fires_with_correct_old_new(self):
        a, b = self.seed_known_diff()
        alerts = alert.generate_alerts(db_path=self.db_path,
                                       baseline_scan_id=a,
                                       current_scan_id=b,
                                       use_state=False)
        kinds = {al["kind"] for al in alerts}
        self.assertEqual(kinds, {"VERDICT_FLIP", "MODEL_CHANGE", "TLS_DROP",
                                 "VERIFY_REGRESSION", "NEW"})
        by = self.by_kind(alerts)

        fl = by["VERDICT_FLIP"]
        self.assertEqual(fl["target"], "10.0.0.1:8000")
        self.assertEqual(fl["old"], "GENUINE")
        self.assertEqual(fl["new"], "IMPOSTOR")
        self.assertEqual(fl["watch"], "flip")
        self.assertEqual(fl["scan_id_b"], b)
        self.assertEqual(fl["severity"], "high")

        mc = by["MODEL_CHANGE"]
        self.assertEqual(mc["target"], "10.0.0.2:8000")
        self.assertEqual(mc["old"], "a")
        self.assertEqual(mc["new"], "a, b")
        self.assertEqual(mc["watch"], "model")
        self.assertEqual(mc["severity"], "low")

        td = by["TLS_DROP"]
        self.assertEqual(td["target"], "10.0.0.3:8000")
        self.assertEqual(td["old"], "TLS")
        self.assertEqual(td["new"], "plaintext")
        self.assertEqual(td["watch"], "tls")
        self.assertEqual(td["severity"], "high")

        vr = by["VERIFY_REGRESSION"]
        self.assertEqual(vr["target"], "10.0.0.4:8000")
        self.assertEqual(vr["old"], "LIVE")
        self.assertEqual(vr["new"], "HONEYPOT")
        self.assertEqual(vr["watch"], "verify")
        self.assertEqual(vr["severity"], "high")

        nw = by["NEW"]
        self.assertEqual(nw["target"], "10.0.0.5:8000")
        self.assertEqual(nw["old"], None)
        self.assertEqual(nw["new"], "GENUINE ollama")
        self.assertEqual(nw["watch"], "new")
        self.assertEqual(nw["severity"], "medium")

        # a target present only in A (GONE) produces no alert
        self.assertNotIn("10.0.0.6:8000", [a_["target"] for a_ in alerts])
        self.assertEqual(len(alerts), 5)

    def test_flip_not_to_impostor_is_medium(self):
        a = self.add_scan()
        b = self.add_scan()
        self.add_target("10.0.0.1", 8000, a, "IMPOSTOR", "ollama")
        self.add_target("10.0.0.1", 8000, b, "GENUINE", "ollama")
        alerts = alert.generate_alerts(self.db_path, a, b)
        fl = self.by_kind(alerts)["VERDICT_FLIP"]
        self.assertEqual((fl["old"], fl["new"]), ("IMPOSTOR", "GENUINE"))
        self.assertEqual(fl["severity"], "medium")

    def test_model_change_from_empty_and_to_empty(self):
        a = self.add_scan()
        b = self.add_scan()
        self.add_target("10.0.0.1", 8000, a, models_served=None)
        self.add_target("10.0.0.1", 8000, b, models_served=["new"])
        hits = alert.generate_alerts(self.db_path, a, b)
        mc = self.by_kind(hits)["MODEL_CHANGE"]
        self.assertEqual((mc["old"], mc["new"]), ("-", "new"))

    def test_state_dedups_second_run(self):
        a, b = self.seed_known_diff()
        sp = self.state_path()
        first = alert.generate_alerts(self.db_path, a, b, state_path=sp)
        self.assertEqual(len(first), 5)
        self.assertTrue(os.path.exists(sp))
        with open(sp) as f:
            self.assertEqual(json.load(f)["last_scan_id_b"], b)
        second = alert.generate_alerts(self.db_path, a, b, state_path=sp)
        self.assertEqual(second, [])

    def test_no_state_reemits(self):
        a, b = self.seed_known_diff()
        sp = self.state_path()
        self.assertEqual(len(alert.generate_alerts(self.db_path, a, b,
                                                   state_path=sp)), 5)
        # --no-state ignores the state file and re-emits
        again = alert.generate_alerts(self.db_path, a, b, state_path=sp,
                                      use_state=False)
        self.assertEqual(len(again), 5)

    def test_no_alert_case_emits_nothing(self):
        a = self.add_scan()
        b = self.add_scan()
        self.add_target("10.0.0.1", 8000, a, "GENUINE", "vllm",
                        ["a"], "live")
        self.add_target("10.0.0.1", 8000, b, "GENUINE", "vllm",
                        ["a"], "live")
        alerts = alert.generate_alerts(self.db_path, a, b, use_state=False)
        self.assertEqual(alerts, [])

    def test_watch_filter_selects_only_requested_kinds(self):
        a, b = self.seed_known_diff()
        alerts = alert.generate_alerts(self.db_path, a, b, watch=["new"],
                                       use_state=False)
        kinds = {al["kind"] for al in alerts}
        self.assertEqual(kinds, {"NEW"})

    def test_default_pair_uses_two_most_recent_scans(self):
        self.seed_known_diff()  # creates scans[0]=a, [1]=b (a older, b newer)
        a_id, b_id = alert.resolve_scan_pair(self.db_path)
        self.assertEqual(b_id, self.scan_ids[-1])
        self.assertEqual(a_id, self.scan_ids[-2])
        alerts = alert.generate_alerts(self.db_path, use_state=False)
        self.assertEqual([al["scan_id_b"] for al in alerts], [b_id] * len(alerts))
        self.assertGreater(len(alerts), 0)

    def test_same_baseline_and_current_raises(self):
        a = self.add_scan()
        with self.assertRaises(ValueError):
            alert.resolve_scan_pair(self.db_path, a, a)

    def test_unknown_watch_kind_raises(self):
        a, b = self.seed_known_diff()
        with self.assertRaises(ValueError):
            alert.generate_alerts(self.db_path, a, b, watch=["nope"],
                                  use_state=False)

    def test_default_state_path_next_to_db(self):
        self.assertEqual(alert.default_state_path(self.db_path),
                         self.state_path())

    def test_tls_helpers(self):
        self.assertTrue(alert._tls_enabled({"port": 443}))
        self.assertFalse(alert._tls_enabled({"port": 8000}))
        self.assertTrue(alert._tls_enabled({"port": 8000, "tls": '{"enabled": true}'}))
        self.assertFalse(alert._tls_enabled({"port": 8000, "tls": '{"enabled": false}'}))


if __name__ == "__main__":
    unittest.main()