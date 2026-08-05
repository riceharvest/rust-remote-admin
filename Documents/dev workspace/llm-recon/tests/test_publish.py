"""Offline tests for the srecon.publish aggregate exporter.

Uses the same tempdir module-global patching pattern as test_db.py / test_report.py:
db.DATA_DIR / db.STATE_DB are repointed at a TemporaryDirectory so no real
project state is touched and no network is involved. export_aggregates is
called with an explicit db_path pointing at that temp DB.

Covers the k-anonymity guarantees:
* outputs never contain an IPv4 pattern (no raw IP/host/PTR/target strings);
* count buckets smaller than min_bucket are suppressed/merged (ASNs, geo);
* lag_days excludes rows scanned within the last N days;
* summary/trend/frameworks/asns counts match the seeded rows.
"""
import json
import os
import re
import sqlite3
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from srecon import db, publish  # noqa: E402

IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


class PublishTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._db_orig = (db.DATA_DIR, db.STATE_DB, db.BLOCKLIST_FILE)
        db.DATA_DIR = self._tmp.name
        db.STATE_DB = os.path.join(self._tmp.name, "state.db")
        db.BLOCKLIST_FILE = os.path.join(self._tmp.name, "honeypot_blocklist.txt")
        db._init_db().close()  # build schema in the temp DB
        self.out_dir = os.path.join(self._tmp.name, "site", "data")

    def tearDown(self):
        db.DATA_DIR, db.STATE_DB, db.BLOCKLIST_FILE = self._db_orig
        self._tmp.cleanup()

    # ----- seeding ------------------------------------------------------
    def _insert(self, ip, port, verdict, product=None, score=0, scanned_at=None,
                model=None, models_served=None, asn=None, as_name=None,
                net_type=None, country=None):
        """Insert one targets row directly (full control over scanned_at/asn)."""
        now = scanned_at if scanned_at is not None else time.time()
        conn = sqlite3.connect(db.STATE_DB)
        try:
            conn.execute(
                "INSERT OR REPLACE INTO targets "
                "(ip,port,verdict,product,score,scanned_at,model,models_served,"
                "asn,as_name,net_type,error) VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL)",
                (ip, port, verdict, product, score, now, model,
                 json.dumps(models_served) if models_served is not None else None,
                 asn, as_name, net_type))
            conn.commit()
        finally:
            conn.close()

    def _seed_basic(self):
        """A representative dataset: live hosts across several ASNs + one
        DARK row. AS1000 has 8 live hosts (>= min_bucket 5), AS2000 has 2
        (< min_bucket -> must collapse into 'other'), AS3000 has 7."""
        self._insert("10.0.0.1", 8000, "GENUINE", "vllm", score=90,
                     model="llama-3.1-8b", asn="AS1000", as_name="Alpha DC",
                     net_type="datacenter")
        self._insert("10.0.0.2", 8000, "GENUINE", "vllm", score=85,
                     model="llama-3.1-70b", asn="AS1000", as_name="Alpha DC")
        self._insert("10.0.0.3", 8000, "UNKNOWN", "vllm", score=40,
                     model="qwen2.5-7b", asn="AS1000", as_name="Alpha DC")
        self._insert("10.0.1.1", 8080, "GENUINE", "llamacpp", score=80,
                     model="mistral-7b", asn="AS1000", as_name="Alpha DC")
        self._insert("10.0.1.2", 8080, "IMPOSTOR", "llamacpp", score=40,
                     asn="AS1000", as_name="Alpha DC")
        self._insert("10.0.2.1", 11434, "GENUINE", "ollama", score=95,
                     model="qwen3:8b", asn="AS1000", as_name="Alpha DC")
        self._insert("10.0.2.2", 11434, "GENUINE", "ollama", score=75,
                     model="phi3:mini", asn="AS1000", as_name="Alpha DC")
        self._insert("10.0.3.1", 8000, "GENUINE", "vllm", score=70,  # 8th live AS1000
                     model="deepseek-r1:7b", asn="AS1000", as_name="Alpha DC")
        # AS3000: 7 live hosts
        for i in range(7):
            self._insert(f"10.30.0.{i}", 8000, "GENUINE", "vllm", score=60,
                         model="qwen2.5-72b", asn="AS3000", as_name="Gamma")
        # AS2000: only 2 live hosts -> below min_bucket 5 -> 'other'
        self._insert("10.20.0.1", 8000, "GENUINE", "vllm", score=50,
                     asn="AS2000", as_name="Beta Small")
        self._insert("10.20.0.2", 8000, "IMPOSTOR", "vllm", score=30,
                     asn="AS2000", as_name="Beta Small")
        # DARK row (not live)
        self._insert("10.99.0.99", 8000, "DARK", None, score=0)
        # ERROR row (not live)
        self._insert("10.99.0.98", 8000, "ERROR", None, score=0)


class ExportAggregatesTest(PublishTestCase):
    def test_files_exist_and_are_valid_json(self):
        self._seed_basic()
        publish.export_aggregates(db_path=db.STATE_DB, out_dir=self.out_dir)
        for name in publish.OUT_FILES:
            path = os.path.join(self.out_dir, name)
            self.assertTrue(os.path.isfile(path), f"missing {name}")
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)  # raises if not valid JSON

    def test_no_ipv4_in_any_output(self):
        self._seed_basic()
        publish.export_aggregates(db_path=db.STATE_DB, out_dir=self.out_dir)
        for name in os.listdir(self.out_dir):
            with open(os.path.join(self.out_dir, name), encoding="utf-8") as f:
                text = f.read()
            self.assertFalse(IPV4_RE.search(text),
                             f"IPv4 pattern leaked in {name}: {text}")

    def test_small_asn_bucket_merged_into_other(self):
        self._seed_basic()
        publish.export_aggregates(db_path=db.STATE_DB, out_dir=self.out_dir,
                                  min_bucket=5)
        with open(os.path.join(self.out_dir, "asns.json"), encoding="utf-8") as f:
            doc = json.load(f)
        asns = {e["asn"]: e for e in doc["asns"]}
        # AS2000 (2 hosts) must NOT be published as its own bucket
        self.assertNotIn("AS2000", asns)
        # ...but its two live hosts land in an 'other' row
        self.assertEqual(asns["other"]["count"], 2)
        # big buckets survive
        self.assertEqual(asns["AS1000"]["count"], 8)
        self.assertEqual(asns["AS3000"]["count"], 7)

    def test_counts_match_seeded_rows(self):
        self._seed_basic()
        publish.export_aggregates(db_path=db.STATE_DB, out_dir=self.out_dir)
        with open(os.path.join(self.out_dir, "summary.json"), encoding="utf-8") as f:
            s = json.load(f)
        # seeded: 8 AS1000 + 7 AS3000 + 2 AS2000 = 17 live, + 1 DARK + 1 ERROR
        self.assertEqual(s["targets"], 19)
        self.assertEqual(s["live"], 17)
        self.assertEqual(s["genuine"], 14)
        self.assertEqual(s["impostor"], 2)
        self.assertEqual(s["unknown"], 1)
        self.assertEqual(s["dark"], 1)
        self.assertEqual(s["error"], 1)
        self.assertEqual(s["min_bucket"], 5)
        self.assertEqual(s["lag_days"], 0)

    def test_trend_has_30_days_and_recomputes_from_rows(self):
        self._seed_basic()
        publish.export_aggregates(db_path=db.STATE_DB, out_dir=self.out_dir)
        with open(os.path.join(self.out_dir, "trend.json"), encoding="utf-8") as f:
            doc = json.load(f)
        days = doc["days"]
        self.assertEqual(len(days), 30)
        # today's bucket reflects the seeded rows (all scanned now)
        today = days[-1]
        self.assertEqual(today["total"], 19)
        self.assertEqual(today["genuine"], 14)
        self.assertEqual(today["error"], 1)

    def test_frameworks_per_framework_breakdown(self):
        self._seed_basic()
        publish.export_aggregates(db_path=db.STATE_DB, out_dir=self.out_dir)
        with open(os.path.join(self.out_dir, "frameworks.json"), encoding="utf-8") as f:
            doc = json.load(f)
        fw = doc["frameworks"]
        # vllm rows: 4 on AS1000 (3 GENUINE + 1 UNKNOWN) + 7 on AS3000 (GENUINE)
        #            + 2 on AS2000 (1 GENUINE + 1 IMPOSTOR) = 13 rows, 11 GENUINE
        self.assertEqual(fw["vllm"]["count"], 13)
        self.assertEqual(fw["vllm"]["genuine_count"], 11)
        self.assertTrue(fw["vllm"]["avg_score"] > 0)
        top = [m["model"] for m in fw["vllm"]["models_top"]]
        self.assertEqual(top[0], "qwen2.5")  # most common vllm model family

    def test_geo_skips_gracefully_without_geo_column(self):
        # "AS1000", "AS3000", "AS2000" are not real geo columns; our schema has
        # no country/cc column, so geo MUST be available:false
        self._seed_basic()
        publish.export_aggregates(db_path=db.STATE_DB, out_dir=self.out_dir)
        with open(os.path.join(self.out_dir, "geo.json"), encoding="utf-8") as f:
            g = json.load(f)
        self.assertEqual(g["available"], False)

    def test_lag_days_excludes_fresh_rows(self):
        now = time.time()
        old = now - 10 * 86400  # 10 days ago
        # 3 live old rows + 2 fresh rows (scanned now)
        for i in range(3):
            self._insert(f"10.1.0.{i}", 8000, "GENUINE", "vllm", score=60,
                         scanned_at=old, asn="AS1000", as_name="Alpha DC")
        for i in range(2):
            self._insert(f"10.2.0.{i}", 8000, "GENUINE", "vllm", score=60,
                         scanned_at=now, asn="AS1000", as_name="Alpha DC")

        # lag_days=7 -> only old rows (3) survive
        publish.export_aggregates(db_path=db.STATE_DB, out_dir=self.out_dir,
                                  lag_days=7)
        with open(os.path.join(self.out_dir, "summary.json"), encoding="utf-8") as f:
            s = json.load(f)
        self.assertEqual(s["targets"], 3)
        self.assertEqual(s["live"], 3)
        self.assertEqual(s["lag_days"], 7)

        # no lag -> all 5 rows included
        publish.export_aggregates(db_path=db.STATE_DB, out_dir=self.out_dir,
                                  lag_days=0)
        with open(os.path.join(self.out_dir, "summary.json"), encoding="utf-8") as f:
            s = json.load(f)
        self.assertEqual(s["targets"], 5)

    def test_dry_run_writes_nothing(self):
        self._seed_basic()
        manifest = publish.export_aggregates(db_path=db.STATE_DB,
                                             out_dir=self.out_dir, dry_run=True)
        self.assertEqual(len(manifest["files"]), len(publish.OUT_FILES))
        self.assertFalse(os.path.exists(self.out_dir))  # nothing on disk

    def test_empty_db_still_writes_valid_aggregates(self):
        # no rows seeded -> aggregates are zeroed but still written and valid JSON
        publish.export_aggregates(db_path=db.STATE_DB, out_dir=self.out_dir)
        with open(os.path.join(self.out_dir, "summary.json"), encoding="utf-8") as f:
            s = json.load(f)
        self.assertEqual(s["targets"], 0)
        self.assertEqual(s["live"], 0)


class GeoColumnTest(PublishTestCase):
    def test_geo_available_when_country_column_exists(self):
        # synthesize a schema with a country column via manual DDL
        self._seed_basic()
        conn = sqlite3.connect(db.STATE_DB)
        conn.execute("ALTER TABLE targets ADD COLUMN country TEXT")
        for ip, cc in (("10.0.0.1", "DE"), ("10.0.0.2", "DE"),
                       ("10.0.0.3", "DE"), ("10.0.1.1", "DE"),
                       ("10.0.1.2", "DE"), ("10.0.2.1", "DE"),
                       ("10.0.2.2", "US"), ("10.0.3.1", "US")):
            conn.execute("UPDATE targets SET country=? WHERE ip=?", (cc, ip))
        conn.commit()
        conn.close()
        publish.export_aggregates(db_path=db.STATE_DB, out_dir=self.out_dir,
                                  min_bucket=5)
        with open(os.path.join(self.out_dir, "geo.json"), encoding="utf-8") as f:
            g = json.load(f)
        self.assertTrue(g["available"])
        self.assertEqual(g["countries"]["DE"], 6)
        # US has only 2 live hosts (< min_bucket 5) -> suppressed to 'other'
        self.assertNotIn("US", g["countries"])
        self.assertEqual(g["countries"]["other"], 2)


if __name__ == "__main__":
    unittest.main()