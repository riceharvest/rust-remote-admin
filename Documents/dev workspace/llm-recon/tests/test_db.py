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
            # sqlite_sequence is internal bookkeeping for AUTOINCREMENT
            return {r[0] for r in rows if r[0] != "sqlite_sequence"}
        finally:
            conn.close()


class SchemaTest(DbTestCase):
    def test_init_db_creates_schema(self):
        conn = db._init_db()
        conn.close()
        self.assertEqual(self._tables(),
                         {"targets", "honeypot_fleets", "scans"})
        conn = sqlite3.connect(db.STATE_DB)
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(targets)")}
        finally:
            conn.close()
        self.assertTrue({"ip", "port", "verdict", "product", "score",
                         "scanned_at", "fp", "scan_id"} <= cols)

    def test_init_db_is_idempotent(self):
        db._init_db().close()
        db._init_db().close()  # must not raise
        self.assertEqual(self._tables(),
                         {"targets", "honeypot_fleets", "scans"})

    def test_migration_bumps_user_version_to_latest(self):
        db._init_db().close()  # fresh temp DB migrates straight to latest
        self.assertEqual(db.schema_version(), db._SCHEMA_VERSION)
        db._init_db().close()
        self.assertEqual(db.schema_version(), db._SCHEMA_VERSION)

    def test_targets_table_has_persisted_drop_fields(self):
        db._init_db().close()
        conn = sqlite3.connect(db.STATE_DB)
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(targets)")}
        finally:
            conn.close()
        expected = {"model", "models_served", "version", "verify_result",
                    "verify_detail", "latency_ms", "asn", "as_name",
                    "bgp_prefix", "net_type", "error", "scan_id", "flags",
                    "tls"}
        self.assertTrue(expected <= cols)

    def test_wal_journal_mode_on_connect(self):
        db._init_db().close()
        conn = sqlite3.connect(db.STATE_DB)
        try:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(mode, "wal")


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


class DropFieldPersistenceTest(DbTestCase):
    def test_store_scan_result_round_trips_persisted_fields(self):
        db.store_scan_result({
            "target": "1.2.3.4:11434", "verdict": "GENUINE",
            "product": "ollama", "score": 12,
            "model": "llama3.1:8b", "models_served": ["a", "b"],
            "version": "0.3.10", "verify_result": "PASS",
            "verify_detail": "first token ok", "latency_ms": 42.5,
            "asn": "AS1234", "as_name": "Example", "bgp_prefix": "1.2.3.0/24",
            "net_type": "datacenter",
        })
        conn = sqlite3.connect(db.STATE_DB)
        try:
            row = conn.execute(
                "SELECT model, models_served, version, verify_result, "
                "verify_detail, latency_ms, asn, as_name, bgp_prefix, net_type "
                "FROM targets WHERE ip='1.2.3.4'").fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(row)
        model, models_served, version, verify_result, verify_detail, \
            latency_ms, asn, as_name, bgp_prefix, net_type = row
        self.assertEqual(model, "llama3.1:8b")
        self.assertEqual(json.loads(models_served), ["a", "b"])
        self.assertEqual(version, "0.3.10")
        self.assertEqual(verify_result, "PASS")
        self.assertEqual(verify_detail, "first token ok")
        self.assertEqual(latency_ms, 42.5)
        self.assertEqual(asn, "AS1234")
        self.assertEqual(as_name, "Example")
        self.assertEqual(bgp_prefix, "1.2.3.0/24")
        self.assertEqual(net_type, "datacenter")

    def test_store_scan_result_without_enrichment_keeps_nulls(self):
        db.store_scan_result({"target": "1.2.3.4:8080", "verdict": "DARK"})
        conn = sqlite3.connect(db.STATE_DB)
        try:
            row = conn.execute(
                "SELECT model, asn, error, scan_id FROM targets "
                "WHERE ip='1.2.3.4'").fetchone()
        finally:
            conn.close()
        self.assertEqual(row, (None, None, None, None))

    def test_store_results_persists_scan_id_and_fields(self):
        sid = db.start_scan(target_count=1, params={"fast": True})
        db.store_results([
            {"target": "1.2.3.4:8000", "verdict": "GENUINE",
             "product": "vllm", "model": "qwen2.5:7b"},
        ], scan_id=sid)
        conn = sqlite3.connect(db.STATE_DB)
        try:
            row = conn.execute(
                "SELECT scan_id, model FROM targets WHERE ip='1.2.3.4'"
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row, (sid, "qwen2.5:7b"))


class FlagsMigrationTest(DbTestCase):
    def test_migrations_add_flags_and_tls_columns_and_preserve_rows(self):
        # Build a v2 database by hand (migrations 1+2 only), insert a row,
        # then let _init_db upgrade it to the latest version (v4).
        conn = sqlite3.connect(db.STATE_DB)
        db._migration_1_base_schema(conn)
        db._migration_2_scans_and_fields(conn)
        conn.execute("PRAGMA user_version = 2")
        conn.execute(
            "INSERT INTO targets (ip,port,verdict,product,score,scanned_at) "
            "VALUES (?,?,?,?,?,?)",
            ("1.2.3.4", 8080, "GENUINE", "ollama", 12, time.time()))
        conn.commit()
        conn.close()
        self.assertEqual(db.schema_version(), 2)
        conn = sqlite3.connect(db.STATE_DB)
        try:
            pre = conn.execute("PRAGMA table_info(targets)").fetchall()
        finally:
            conn.close()
        self.assertNotIn("flags", {r[1] for r in pre})
        self.assertNotIn("tls", {r[1] for r in pre})
        # runtime upgrade v2 -> v4 (migrations 3 + 4)
        db._init_db().close()
        self.assertEqual(db.schema_version(), 4)
        conn = sqlite3.connect(db.STATE_DB)
        try:
            count = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
            cols = {r[1] for r in conn.execute("PRAGMA table_info(targets)")}
            row = conn.execute(
                "SELECT ip, port, verdict, product, score FROM targets "
                "WHERE ip='1.2.3.4'").fetchone()
        finally:
            conn.close()
        self.assertEqual(count, 1)  # preserved row count
        self.assertIn("flags", cols)  # column added
        self.assertIn("tls", cols)  # column added
        self.assertEqual(row, ("1.2.3.4", 8080, "GENUINE", "ollama", 12))

    def test_migrations_are_idempotent_and_noop_on_existing_rows(self):
        db._init_db().close()  # fresh DB migrates straight to the latest
        self.assertEqual(db.schema_version(), 4)
        db._init_db().close()
        self.assertEqual(db.schema_version(), 4)


class TlsMigrationTest(DbTestCase):
    def test_v4_migration_adds_tls_column_and_preserves_rows(self):
        # Build a v3 database by hand (migrations 1+2+3), insert a row,
        # then let _init_db upgrade it to v4.
        conn = sqlite3.connect(db.STATE_DB)
        db._migration_1_base_schema(conn)
        db._migration_2_scans_and_fields(conn)
        db._migration_3_flags(conn)
        conn.execute("PRAGMA user_version = 3")
        conn.execute(
            "INSERT INTO targets (ip,port,verdict,product,score,scanned_at) "
            "VALUES (?,?,?,?,?,?)",
            ("1.2.3.4", 8080, "GENUINE", "ollama", 12, time.time()))
        conn.commit()
        conn.close()
        self.assertEqual(db.schema_version(), 3)
        conn = sqlite3.connect(db.STATE_DB)
        try:
            pre = conn.execute("PRAGMA table_info(targets)").fetchall()
        finally:
            conn.close()
        self.assertNotIn("tls", {r[1] for r in pre})
        # runtime upgrade v3 -> v4
        db._init_db().close()
        self.assertEqual(db.schema_version(), 4)
        conn = sqlite3.connect(db.STATE_DB)
        try:
            count = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
            cols = {r[1] for r in conn.execute("PRAGMA table_info(targets)")}
            row = conn.execute(
                "SELECT ip, port, verdict, product, score FROM targets "
                "WHERE ip='1.2.3.4'").fetchone()
        finally:
            conn.close()
        self.assertEqual(count, 1)  # preserved row count
        self.assertIn("tls", cols)  # column added
        self.assertEqual(row, ("1.2.3.4", 8080, "GENUINE", "ollama", 12))


class FlagsPersistenceTest(DbTestCase):
    def test_store_scan_result_round_trips_flags_json(self):
        db.store_scan_result({
            "target": "1.2.3.4:11434", "verdict": "GENUINE",
            "flags": ["IMPORTED_SHODAN", "CLOUD_ONLY"]})
        conn = sqlite3.connect(db.STATE_DB)
        try:
            flags = conn.execute(
                "SELECT flags FROM targets WHERE ip='1.2.3.4'").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(json.loads(flags),
                         ["IMPORTED_SHODAN", "CLOUD_ONLY"])

    def test_store_scan_result_missing_flags_keeps_null(self):
        db.store_scan_result({"target": "1.2.3.4:8080", "verdict": "DARK"})
        conn = sqlite3.connect(db.STATE_DB)
        try:
            flags = conn.execute(
                "SELECT flags FROM targets WHERE ip='1.2.3.4'").fetchone()[0]
        finally:
            conn.close()
        self.assertIsNone(flags)

    def test_store_results_round_trips_flags(self):
        db.store_results([
            {"target": "1.2.3.4:8000", "verdict": "GENUINE",
             "flags": ["IMPORTED_SHODAN"]},
            {"target": "2.3.4.5:11434", "verdict": "UNKNOWN"},  # no flags
        ])
        conn = sqlite3.connect(db.STATE_DB)
        try:
            a = conn.execute(
                "SELECT flags FROM targets WHERE ip='1.2.3.4'").fetchone()[0]
            b = conn.execute(
                "SELECT flags FROM targets WHERE ip='2.3.4.5'").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(json.loads(a), ["IMPORTED_SHODAN"])
        self.assertIsNone(b)


class TlsPersistenceTest(DbTestCase):
    def test_store_scan_result_round_trips_tls_json(self):
        tls = {"enabled": True, "fingerprint_sha256": "a" * 64,
               "issuer": "CN=test", "subject": "CN=test",
               "not_after": "2027-01-01 00:00:00 UTC", "self_signed": True}
        db.store_scan_result({
            "target": "1.2.3.4:443", "verdict": "GENUINE",
            "product": "vllm", "tls": tls})
        conn = sqlite3.connect(db.STATE_DB)
        try:
            stored = conn.execute(
                "SELECT tls FROM targets WHERE ip='1.2.3.4'").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(json.loads(stored), tls)

    def test_store_scan_result_missing_tls_keeps_null(self):
        db.store_scan_result({"target": "1.2.3.4:8080", "verdict": "DARK"})
        conn = sqlite3.connect(db.STATE_DB)
        try:
            tls = conn.execute(
                "SELECT tls FROM targets WHERE ip='1.2.3.4'").fetchone()[0]
        finally:
            conn.close()
        self.assertIsNone(tls)

    def test_store_results_round_trips_tls(self):
        tls = {"enabled": True, "fingerprint_sha256": "b" * 64,
               "issuer": None, "subject": None, "not_after": None,
               "self_signed": None}
        db.store_results([
            {"target": "1.2.3.4:443", "verdict": "GENUINE", "tls": tls},
            {"target": "2.3.4.5:11434", "verdict": "UNKNOWN"},  # no tls
        ])
        conn = sqlite3.connect(db.STATE_DB)
        try:
            a = conn.execute(
                "SELECT tls FROM targets WHERE ip='1.2.3.4'").fetchone()[0]
            b = conn.execute(
                "SELECT tls FROM targets WHERE ip='2.3.4.5'").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(json.loads(a), tls)
        self.assertIsNone(b)


class ScanHistoryTest(DbTestCase):
    def test_start_and_query_scan(self):
        sid = db.start_scan(target_count=10, params={"fleet": "llamacpp"})
        self.assertIsInstance(sid, int)
        scan = db.get_scan(sid)
        self.assertEqual(scan["scan_id"], sid)
        self.assertEqual(scan["target_count"], 10)
        self.assertIsNotNone(scan["started_at"])
        self.assertIsNone(scan["finished_at"])
        self.assertIn("llamacpp", scan["params_json"])

    def test_finish_scan_records_stats(self):
        sid = db.start_scan()
        db.finish_scan(sid, stats={"total": 3, "genuine": 2})
        scan = db.get_scan(sid)
        self.assertIsNotNone(scan["finished_at"])
        self.assertEqual(json.loads(scan["stats_json"]),
                         {"total": 3, "genuine": 2})

    def test_list_scans_newest_first(self):
        a = db.start_scan()
        b = db.start_scan()
        scans = db.list_scans()
        ids = [s["scan_id"] for s in scans]
        self.assertIn(a, ids)
        self.assertIn(b, ids)
        self.assertEqual(ids, sorted(ids, reverse=True))

    def test_get_scan_missing_returns_none(self):
        self.assertIsNone(db.get_scan(999999))

    def test_store_scan_result_associates_scan_id(self):
        sid = db.start_scan()
        db.store_scan_result(
            {"target": "1.2.3.4:8080", "verdict": "UNKNOWN"}, scan_id=sid)
        db.store_scan_result({"target": "5.6.7.8:8080", "verdict": "DARK"})
        conn = sqlite3.connect(db.STATE_DB)
        try:
            linked = conn.execute(
                "SELECT COUNT(*) FROM targets WHERE scan_id=?", (sid,)
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(linked, 1)


class BlocklistTest(DbTestCase):
    def test_add_and_load_blocklist(self):
        self.assertEqual(db.load_blocklist(), set())
        db.add_blocklist("1.2.3.4")
        db.add_blocklist("5.6.7.8")
        db.add_blocklist("1.2.3.4")  # duplicate append tolerated, set dedupes
        self.assertEqual(db.load_blocklist(), {"1.2.3.4", "5.6.7.8"})

    def test_add_blocklist_strips_port(self):
        db.add_blocklist("9.9.9.9:11434")
        self.assertEqual(db.load_blocklist(), {"9.9.9.9"})
        # file itself stores bare IP
        with open(db.BLOCKLIST_FILE) as f:
            content = set(f.read().splitlines())
        self.assertEqual(content, {"9.9.9.9"})

    def test_load_blocklist_normalizes_host_port_in_memory(self):
        # pre-existing mixed-format file
        with open(db.BLOCKLIST_FILE, "w") as f:
            f.write("# comment\n1.2.3.4\n5.6.7.8:8080\n\n")
        self.assertEqual(db.load_blocklist(), {"1.2.3.4", "5.6.7.8"})
        # load does NOT rewrite the file
        with open(db.BLOCKLIST_FILE) as f:
            self.assertIn("5.6.7.8:8080", f.read())

    def test_normalize_blocklist_rewrites_bare_ips(self):
        with open(db.BLOCKLIST_FILE, "w") as f:
            f.write("# comment\n1.2.3.4\n5.6.7.8:8080\n9.9.9.9\n5.6.7.8\n")
        ips = db.normalize_blocklist()
        self.assertEqual(ips, {"1.2.3.4", "5.6.7.8", "9.9.9.9"})
        with open(db.BLOCKLIST_FILE) as f:
            self.assertEqual(f.read().strip(), "1.2.3.4\n5.6.7.8\n9.9.9.9")


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

    def test_list_honeypots_returns_learned_fleets(self):
        self.assertEqual(db.list_honeypots(), [])
        db.learn_honeypots(self._results(3))
        fleets = db.list_honeypots()
        self.assertEqual(len(fleets), 1)
        self.assertEqual(fleets[0]["inv_hash"], "abc123")
        self.assertEqual(fleets[0]["member_count"], 3)
        self.assertEqual(fleets[0]["verdicts"], {"IMPOSTOR": 3})
        self.assertIsNotNone(fleets[0]["first_seen"])
        self.assertIsNotNone(fleets[0]["last_seen"])

    def test_fleet_requires_three_members(self):
        learned = db.learn_honeypots(self._results(2))
        self.assertEqual(learned, 0)
        self.assertEqual(db.load_blocklist(), set())

    def test_learn_honeypots_tolerates_host_port_in_file(self):
        # seed a mixed-format line; learn_honeypots must still load bare IPs
        with open(db.BLOCKLIST_FILE, "w") as f:
            f.write("8.8.8.8:53\n")
        db.learn_honeypots(self._results(3))
        self.assertEqual(db.load_blocklist(), {"1.2.3.4", "8.8.8.8"})

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
