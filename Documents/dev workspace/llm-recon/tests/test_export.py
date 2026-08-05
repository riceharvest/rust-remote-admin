"""Offline tests for srecon.export — filtered raw-target export from a tempdir DB.

No network, no scanning: the targets table is seeded directly on a schema that
is migrated into a TemporaryDirectory, and every export reads that temp DB via
``db_path``. The real ``srecon/data`` directory is never touched.
"""
import csv
import json
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from srecon import db
from srecon import export
from srecon.targets import expand_targets  # to validate txt re-parseability


class ExportTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self._tmp.name, "state.db")
        # Repoint db so _init_db() migrates the temp schema (offline).
        self._orig = (db.DATA_DIR, db.STATE_DB, db.BLOCKLIST_FILE)
        db.DATA_DIR = self._tmp.name
        db.STATE_DB = self.db_path
        db.BLOCKLIST_FILE = os.path.join(self._tmp.name, "blocklist.txt")
        db._init_db().close()
        self._seed()

    def tearDown(self):
        db.DATA_DIR, db.STATE_DB, db.BLOCKLIST_FILE = self._orig
        self._tmp.cleanup()

    # ------------------------------------------------------------------
    def _insert(self, ip, port, verdict, product=None, score=0, scan_id=None,
                tls=None, flags=None, model=None, version=None,
                verify_result=None, asn=None, as_name=None):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "INSERT INTO targets "
                "(ip,port,verdict,product,score,scanned_at,scan_id,flags,"
                "model,version,verify_result,asn,as_name,tls) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ip, port, verdict, product, score, 1_700_000_000.0, scan_id,
                 json.dumps(flags) if flags is not None else None,
                 model, version, verify_result, asn, as_name,
                 json.dumps(tls) if tls is not None else None))
            conn.commit()
        finally:
            conn.close()

    def _seed(self):
        # scan 1
        self._insert("1.0.0.1", 8000, "GENUINE", "vllm", score=85, scan_id=1,
                     tls={"enabled": True}, flags=["GENUINE"], model="Qwen2-7B",
                     version="v0.6.0", verify_result="live",
                     asn="AS24940", as_name="Hetzner")
        self._insert("1.0.0.2", 11434, "IMPOSTOR", "ollama", score=60, scan_id=1,
                     tls={"enabled": False}, flags=[],
                     verify_result="honeypot")
        # scan 2
        self._insert("1.0.0.3", 8001, "GENUINE", "ollama", score=70, scan_id=2,
                     tls={"enabled": True}, flags=["GENUINE"], model="Llama-3-8B",
                     verify_result="live", asn="AS13335", as_name="Cloudflare")
        self._insert("1.0.0.4", 8000, "DARK", None, score=0, scan_id=2)
        # scan 3 (no tls stored; port 443 -> TLS via fallback)
        self._insert("1.0.0.5", 443, "UNKNOWN", "vllm", score=45, scan_id=3,
                     model="gpt-oss-20b")
        self._insert("1.0.0.6", 11434, "ERROR", None, score=0, scan_id=3)

    # ------------------------------------------------------------------
    def test_default_fields_present(self):
        rows = export.export_targets(db_path=self.db_path)
        self.assertEqual(len(rows), 6)
        first = rows[0]
        self.assertEqual(list(first.keys()), export.DEFAULT_FIELDS)
        # derived target + tls_enabled for a TLS row
        self.assertEqual(first["target"], "1.0.0.1:8000")
        self.assertIs(first["tls_enabled"], True)

    def test_verdict_filter(self):
        rows = export.export_targets(db_path=self.db_path, verdict="GENUINE")
        self.assertEqual({r["target"] for r in rows},
                         {"1.0.0.1:8000", "1.0.0.3:8001"})
        rows = export.export_targets(db_path=self.db_path,
                                     verdict="genuine,unknown")
        self.assertEqual({r["target"] for r in rows},
                         {"1.0.0.1:8000", "1.0.0.3:8001", "1.0.0.5:443"})

    def test_product_filter(self):
        rows = export.export_targets(db_path=self.db_path, product="vllm")
        self.assertEqual({r["target"] for r in rows},
                         {"1.0.0.1:8000", "1.0.0.5:443"})
        rows = export.export_targets(db_path=self.db_path,
                                     product="ollama,vllm")
        self.assertEqual(len(rows), 4)

    def test_scan_id_filter(self):
        rows = export.export_targets(db_path=self.db_path, scan_id=1)
        self.assertEqual({r["target"] for r in rows},
                         {"1.0.0.1:8000", "1.0.0.2:11434"})

    def test_min_score_filter(self):
        rows = export.export_targets(db_path=self.db_path, min_score=70)
        self.assertEqual({r["target"] for r in rows},
                         {"1.0.0.1:8000", "1.0.0.3:8001"})

    def test_tls_only_filter(self):
        rows = export.export_targets(db_path=self.db_path, tls_only=True)
        # row1 (enabled), row3 (enabled), row5 (port 443 fallback)
        self.assertEqual({r["target"] for r in rows},
                         {"1.0.0.1:8000", "1.0.0.3:8001", "1.0.0.5:443"})

    def test_live_only_filter(self):
        rows = export.export_targets(db_path=self.db_path, live_only=True)
        # drops DARK and ERROR
        self.assertEqual({r["target"] for r in rows},
                         {"1.0.0.1:8000", "1.0.0.2:11434",
                          "1.0.0.3:8001", "1.0.0.5:443"})

    def test_composed_filters(self):
        rows = export.export_targets(db_path=self.db_path, verdict="GENUINE",
                                     product="ollama", min_score=70)
        self.assertEqual({r["target"] for r in rows}, {"1.0.0.3:8001"})

    def test_limit(self):
        rows = export.export_targets(db_path=self.db_path, limit=2)
        self.assertEqual(len(rows), 2)

    def test_fields_selection(self):
        rows = export.export_targets(db_path=self.db_path,
                                     fields="target,ip,port,score")
        self.assertEqual(list(rows[0].keys()),
                         ["target", "ip", "port", "score"])
        self.assertEqual(rows[0]["score"], 85)
        # '*' returns all resolvable fields, incl. derived
        rows = export.export_targets(db_path=self.db_path, fields="*",
                                     limit=1)
        self.assertIn("tls_enabled", rows[0])
        self.assertIn("target", rows[0])
        self.assertIn("models_served", rows[0])

    def test_empty_filter_returns_empty(self):
        rows = export.export_targets(db_path=self.db_path, verdict="IMPOSTOR2")
        self.assertEqual(rows, [])
        rows = export.export_targets(db_path=self.db_path, product="nope")
        self.assertEqual(rows, [])
        rows = export.export_targets(db_path=self.db_path, min_score=10_000)
        self.assertEqual(rows, [])

    def test_missing_db_returns_empty(self):
        rows = export.export_targets(
            db_path=os.path.join(self._tmp.name, "absent.db"),
            verdict="GENUINE")
        self.assertEqual(rows, [])

    # ------------------------------------------------------------------
    # writers
    # ------------------------------------------------------------------
    def test_write_jsonl(self):
        rows = export.export_targets(db_path=self.db_path)
        path = os.path.join(self._tmp.name, "out.jsonl")
        export.write_jsonl(rows, path)
        with open(path) as f:
            lines = [l for l in f.read().strip().splitlines() if l]
        self.assertEqual(len(lines), len(rows))
        parsed = [json.loads(l) for l in lines]
        self.assertEqual({r["target"] for r in parsed},
                         {r["target"] for r in rows})
        self.assertEqual(list(parsed[0].keys()), export.DEFAULT_FIELDS)

    def test_write_csv(self):
        rows = export.export_targets(db_path=self.db_path)
        path = os.path.join(self._tmp.name, "out.csv")
        export.write_csv(rows, path)
        with open(path, newline="") as f:
            data = list(csv.reader(f))
        self.assertEqual(data[0], export.DEFAULT_FIELDS)
        self.assertEqual(len(data), len(rows) + 1)  # + header
        self.assertEqual(data[1][0], rows[0]["target"])

    def test_write_txt_is_host_port_and_reparseable(self):
        rows = export.export_targets(db_path=self.db_path)
        path = os.path.join(self._tmp.name, "out.txt")
        export.write_txt(rows, path)
        with open(path) as f:
            lines = [l for l in f.read().splitlines() if l]
        self.assertEqual(len(lines), len(rows))
        for line in lines:
            host, sep, port = line.rpartition(":")
            self.assertTrue(sep)          # host:port shape
            self.assertTrue(port.isdigit())
            self.assertNotIn("/", line)   # not a CIDR
        # re-parseable by targets.expand_targets -> (host, port) tuples
        targets, truncated = expand_targets(lines)
        self.assertFalse(truncated)
        self.assertEqual(set(targets), {(r["ip"], r["port"]) for r in rows})

    def test_write_empty_rows(self):
        rows = export.export_targets(db_path=self.db_path,
                                     product="does-not-exist")
        self.assertEqual(rows, [])
        path = os.path.join(self._tmp.name, "empty.txt")
        export.write_txt(rows, path)
        with open(path) as f:
            self.assertEqual(f.read(), "")

    def test_write_to_file_object(self):
        rows = export.export_targets(db_path=self.db_path, limit=1)
        import io
        buf = io.StringIO()
        export.write_csv(rows, buf)   # file-like target
        self.assertIn("target,ip,port", buf.getvalue())


if __name__ == "__main__":
    unittest.main()