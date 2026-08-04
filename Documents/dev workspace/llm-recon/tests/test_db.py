"""Offline tests for srecon.db using a tempdir SQLite database.

The module-level DATA_DIR/STATE_DB/BLOCKLIST_FILE globals are repointed at
a TemporaryDirectory so no real project state is touched and no network is
involved.
"""
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from srecon import db


class DbTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = (db.DATA_DIR, db.STATE_DB, db.BLOCKLIST_FILE)
        db.DATA_DIR = self._tmp.name
        db.STATE_DB = os.path.join(self._tmp.name, "state.db")
        db.BLOCKLIST_FILE = os.path.join(self._tmp.name, "honeypot_blocklist.txt")

    def tearDown(self):
        db.DATA_DIR, db.STATE_DB, db.BLOCKLIST_FILE = self._orig
        self._tmp.cleanup()

    def _tables(self):
        conn = sqlite3.connect(db.STATE_DB)
        try:
            rows = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            return {r[0] for r in rows}
        finally:
            conn.close()


class SchemaTest(DbTestCase):
    def test_init_db_creates_schema(self):
        conn = db._init_db()
        conn.close()
        self.assertEqual(self._tables(), {"targets", "honeypot_fleets"})
        conn = sqlite3.connect(db.STATE_DB)
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(targets)")}
        finally:
            conn.close()
        self.assertTrue({"ip", "port", "verdict", "product", "score",
                         "scanned_at", "fp"} <= cols)

    def test_init_db_is_idempotent(self):
        db._init_db().close()
        db._init_db().close()  # must not raise
        self.assertEqual(self._tables(), {"targets", "honeypot_fleets"})


class DedupCacheTest(DbTestCase):
    def test_store_and_lookup_single(self):
        db.store_scan_result({
            "target": "1.2.3.4:8080", "verdict": "GENUINE",
            "product": "ollama", "score": 0})
        self.assertTrue(db.scan_cache_hit("1.2.3.4:8080"))
        self.assertFalse(db.scan_cache_hit("1.2.3.4:8081"))
        self.assertFalse(db.scan_cache_hit("no-colon-here"))

    def test_batch_lookup(self):
        db.store_scan_result({"target": "1.2.3.4:8080", "verdict": "GENUINE",
                              "product": "ollama", "score": 0})
        db.store_scan_result({"target": "5.6.7.8:11434", "verdict": "UNKNOWN",
                              "product": "unknown-http", "score": 0})
        hits = db.scan_cache_hits_batch(
            [("1.2.3.4", 8080), ("5.6.7.8", 11434), ("9.9.9.9", 80)])
        self.assertEqual(hits, {"1.2.3.4:8080", "5.6.7.8:11434"})

    def test_cache_expires_after_ttl(self):
        db.store_scan_result({"target": "1.2.3.4:8080", "verdict": "GENUINE",
                              "product": "ollama", "score": 0})
        conn = sqlite3.connect(db.STATE_DB)
        conn.execute("UPDATE targets SET scanned_at=? WHERE ip='1.2.3.4'",
                     (time.time() - 8 * 86400,))  # older than 7-day TTL
        conn.commit()
        conn.close()
        self.assertFalse(db.scan_cache_hit("1.2.3.4:8080"))

    def test_store_results_and_recent_targets(self):
        db.store_results([
            {"target": "1.2.3.4:80", "verdict": "GENUINE", "product": "vllm"},
            {"target": "2.3.4.5:11434", "verdict": "UNKNOWN"},
            {"target": "no-colon", "verdict": "GENUINE"},  # malformed -> skipped
        ])
        self.assertEqual(db.recent_targets(ttl_days=30),
                         {("1.2.3.4", 80), ("2.3.4.5", 11434)})
        # age one row beyond the TTL window
        conn = sqlite3.connect(db.STATE_DB)
        conn.execute("UPDATE targets SET scanned_at=? WHERE ip='1.2.3.4'",
                     (time.time() - 31 * 86400,))
        conn.commit()
        conn.close()
        self.assertEqual(db.recent_targets(ttl_days=30), {("2.3.4.5", 11434)})


class BlocklistTest(DbTestCase):
    def test_add_and_load_blocklist(self):
        self.assertEqual(db.load_blocklist(), set())
        db.add_blocklist("1.2.3.4")
        db.add_blocklist("5.6.7.8")
        db.add_blocklist("1.2.3.4")  # duplicate append tolerated, set dedupes
        self.assertEqual(db.load_blocklist(), {"1.2.3.4", "5.6.7.8"})


class HoneypotFleetTest(DbTestCase):
    def _results(self, n, verdict="IMPOSTOR", host="1.2.3.4"):
        return [
            {"target": f"{host}:{8000 + i}", "verdict": verdict,
             "product": "ollama", "score": 15, "inventory_hash": "abc123"}
            for i in range(n)
        ]

    def test_learn_honeypots_blocks_fleet(self):
        learned = db.learn_honeypots(self._results(3))
        self.assertEqual(learned, 3)
        self.assertEqual(db.load_blocklist(), {"1.2.3.4"})
        conn = sqlite3.connect(db.STATE_DB)
        try:
            row = conn.execute(
                "SELECT member_count, verdicts FROM honeypot_fleets "
                "WHERE inv_hash='abc123'").fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 3)
        self.assertEqual(json.loads(row[1]), {"IMPOSTOR": 3})

    def test_fleet_requires_three_members(self):
        learned = db.learn_honeypots(self._results(2))
        self.assertEqual(learned, 0)
        self.assertEqual(db.load_blocklist(), set())

    def test_majority_impostor_threshold(self):
        # 2 of 3 impostor (0.66 >= 0.6) still blocks the fleet
        results = self._results(3, verdict="GENUINE")
        results[0]["verdict"] = "IMPOSTOR"
        results[1]["verdict"] = "IMPOSTOR"
        learned = db.learn_honeypots(results)
        self.assertEqual(learned, 3)
        self.assertEqual(db.load_blocklist(), {"1.2.3.4"})

    def test_no_inventory_hash_means_no_learning(self):
        results = self._results(3)
        for r in results:
            r.pop("inventory_hash")
        self.assertEqual(db.learn_honeypots(results), 0)
        self.assertEqual(db.load_blocklist(), set())


class FingerprintTest(DbTestCase):
    def test_fingerprint_hash_deterministic(self):
        d = {"product": "ollama", "version": "0.5.7", "verdict": "GENUINE",
             "inventory_hash": "abc", "models_served": ["llama3.2:1b", "x:y"]}
        self.assertEqual(db.fingerprint_hash(d), db.fingerprint_hash(dict(d)))

    def test_fingerprint_hash_changes_with_surface(self):
        base = {"product": "ollama", "version": "0.5.7", "verdict": "GENUINE",
                "inventory_hash": "abc", "models_served": ["llama3.2:1b"]}
        changed = dict(base)
        changed["models_served"] = ["llama3.2:3b"]
        self.assertNotEqual(db.fingerprint_hash(base),
                            db.fingerprint_hash(changed))

    def test_diff_check(self):
        d = {"target": "1.2.3.4:8080", "verdict": "GENUINE",
             "product": "ollama", "score": 0, "inventory_hash": "h"}
        self.assertTrue(db.diff_check("1.2.3.4:8080", "whatever"))  # unseen
        db.store_scan_result(d)
        same = db.fingerprint_hash(d)
        self.assertFalse(db.diff_check("1.2.3.4:8080", same))
        self.assertTrue(db.diff_check("1.2.3.4:8080", "different-hash"))
        self.assertTrue(db.diff_check("no-colon", same))


if __name__ == "__main__":
    unittest.main()
