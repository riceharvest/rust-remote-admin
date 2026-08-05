"""Offline tests for srecon.certs (cert-expiry tracker) using a tempdir DB.

Follows the tests/test_db.py patching pattern: module-level
DATA_DIR/STATE_DB/BLOCKLIST_FILE are repointed at a TemporaryDirectory so no
real project state is touched, and no network is involved.
"""
import csv
import datetime
import io
import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from srecon import certs
from srecon import db


def _engine_ts(days_from_now):
    """Engine-style 'YYYY-MM-DD HH:MM UTC' not_after offset from now."""
    when = (datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=days_from_now))
    return when.strftime("%Y-%m-%d %H:%M UTC")


def _iso_ts(days_from_now):
    """ISO-8601 (Z) not_after offset from now."""
    when = (datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=days_from_now))
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


class CertsTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = (db.DATA_DIR, db.STATE_DB, db.BLOCKLIST_FILE)
        db.DATA_DIR = self._tmp.name
        db.STATE_DB = os.path.join(self._tmp.name, "state.db")
        db.BLOCKLIST_FILE = os.path.join(self._tmp.name, "honeypot_blocklist.txt")
        db._init_db().close()

    def tearDown(self):
        db.DATA_DIR, db.STATE_DB, db.BLOCKLIST_FILE = self._orig
        self._tmp.cleanup()

    def _seed(self, ip, port, tls):
        """Persist one target row with a tls dict (or None for NULL tls)."""
        db.store_scan_result({
            "target": "{}:{}".format(ip, port),
            "verdict": "GENUINE",
            "product": "vllm",
            "tls": tls,
        })

    def _seed_raw_tls(self, ip, port, tls_text):
        """Persist a row with a raw (possibly invalid) tls column string."""
        conn = sqlite3.connect(db.STATE_DB)
        try:
            conn.execute(
                "INSERT INTO targets (ip,port,verdict,product,score,scanned_at,tls) "
                "VALUES (?,?,?,?,?,?,?)",
                (ip, port, "GENUINE", "vllm", 0, time.time(), tls_text))
            conn.commit()
        finally:
            conn.close()


class ScanCertsTest(CertsTestCase):
    def test_status_classification_and_null_tls_skipped(self):
        self._seed("10.0.0.1", 443, {"enabled": True,
                                     "issuer": "CN=expired-ca",
                                     "subject": "CN=expired-host",
                                     "fingerprint_sha256": "a" * 64,
                                     "not_after": _engine_ts(-5),
                                     "self_signed": True})
        self._seed("10.0.0.2", 443, {"enabled": True,
                                     "issuer": "CN=crit-ca",
                                     "subject": "CN=crit-host",
                                     "fingerprint_sha256": "b" * 64,
                                     "not_after": _engine_ts(3),
                                     "self_signed": True})
        self._seed("10.0.0.3", 8443, {"enabled": True,
                                      "issuer": "CN=warn-ca",
                                      "subject": "CN=warn-host",
                                      "fingerprint_sha256": "c" * 64,
                                      "not_after": _engine_ts(15),
                                      "self_signed": False})
        self._seed("10.0.0.4", 11434, {"enabled": True,
                                       "issuer": "CN=ok-ca",
                                       "subject": "CN=ok-host",
                                       "fingerprint_sha256": "d" * 64,
                                       "not_after": _engine_ts(200),
                                       "self_signed": False})
        self._seed("10.0.0.5", 8080, None)  # NULL tls -> skipped
        certs_out = certs.scan_certs()
        self.assertEqual(len(certs_out), 4)
        by_ip = {c["ip"]: c for c in certs_out}
        self.assertEqual(by_ip["10.0.0.1"]["status"], "expired")
        self.assertEqual(by_ip["10.0.0.2"]["status"], "critical")
        self.assertEqual(by_ip["10.0.0.3"]["status"], "warn")
        self.assertEqual(by_ip["10.0.0.4"]["status"], "ok")
        self.assertNotIn("10.0.0.5", by_ip)
        # field surface per spec
        self.assertEqual(
            set(by_ip["10.0.0.1"]),
            {"target", "ip", "port", "issuer", "subject",
             "fingerprint_sha256", "not_after", "days_left", "status"})
        self.assertEqual(by_ip["10.0.0.1"]["target"], "10.0.0.1:443")
        self.assertEqual(by_ip["10.0.0.1"]["issuer"], "CN=expired-ca")
        self.assertEqual(by_ip["10.0.0.1"]["fingerprint_sha256"], "a" * 64)

    def test_sort_by_days_left_ascending(self):
        self._seed("10.0.0.1", 443, {"not_after": _engine_ts(90)})
        self._seed("10.0.0.2", 443, {"not_after": _engine_ts(-1)})
        self._seed("10.0.0.3", 443, {"not_after": _engine_ts(10)})
        certs_out = certs.scan_certs()
        days = [c["days_left"] for c in certs_out]
        self.assertEqual(days, sorted(days))
        self.assertEqual([c["ip"] for c in certs_out],
                         ["10.0.0.2", "10.0.0.3", "10.0.0.1"])

    def test_days_left_math(self):
        self._seed("10.0.0.1", 443, {"not_after": _engine_ts(10)})
        self._seed("10.0.0.2", 443, {"not_after": _engine_ts(-3)})
        certs_out = certs.scan_certs()
        by_ip = {c["ip"]: c for c in certs_out}
        self.assertAlmostEqual(by_ip["10.0.0.1"]["days_left"], 10.0, delta=0.02)
        self.assertAlmostEqual(by_ip["10.0.0.2"]["days_left"], -3.0, delta=0.02)

    def test_iso_format_parsed(self):
        self._seed("10.0.0.1", 443, {"not_after": _iso_ts(60)})
        certs_out = certs.scan_certs()
        self.assertEqual(len(certs_out), 1)
        self.assertEqual(certs_out[0]["status"], "ok")
        self.assertAlmostEqual(certs_out[0]["days_left"], 60.0, delta=0.02)

    def test_engine_format_with_seconds_parsed(self):
        when = (datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=12))
        self._seed("10.0.0.1", 443,
                   {"not_after": when.strftime("%Y-%m-%d %H:%M:%S UTC")})
        certs_out = certs.scan_certs()
        self.assertEqual(len(certs_out), 1)
        self.assertEqual(certs_out[0]["status"], "warn")

    def test_unparseable_not_after_skipped(self):
        self._seed("10.0.0.1", 443, {"not_after": "not-a-date"})
        self._seed("10.0.0.2", 443, {"not_after": None})
        self.assertEqual(certs.scan_certs(), [])

    def test_malformed_tls_json_skipped(self):
        self._seed_raw_tls("10.0.0.1", 443, "{broken json")
        self._seed_raw_tls("10.0.0.2", 443, '"just-a-string"')
        self._seed("10.0.0.3", 443, {"not_after": _engine_ts(30)})
        certs_out = certs.scan_certs()
        self.assertEqual(len(certs_out), 1)
        self.assertEqual(certs_out[0]["ip"], "10.0.0.3")
        self.assertEqual(certs_out[0]["status"], "warn")

    def test_custom_db_path(self):
        # scan_certs(db_path=...) reads an explicit database file.
        path = os.path.join(self._tmp.name, "other.db")
        conn = sqlite3.connect(path)
        db._apply_migrations(conn)
        conn.execute(
            "INSERT INTO targets (ip,port,verdict,product,score,scanned_at,tls) "
            "VALUES (?,?,?,?,?,?,?)",
            ("10.0.0.9", 443, "GENUINE", "vllm", 0, time.time(),
             json.dumps({"not_after": _engine_ts(5)})))
        conn.commit()
        conn.close()
        certs_out = certs.scan_certs(db_path=path)
        self.assertEqual(len(certs_out), 1)
        self.assertEqual(certs_out[0]["status"], "critical")

    def test_missing_db_returns_empty(self):
        self.assertEqual(certs.scan_certs(db_path="/nonexistent/x.db"), [])

    def test_custom_thresholds(self):
        self._seed("10.0.0.1", 443, {"not_after": _engine_ts(10)})
        # default: 10 <= 30 -> warn
        self.assertEqual(certs.scan_certs()[0]["status"], "warn")
        # warn_days=5: 10 > 5 -> ok
        self.assertEqual(certs.scan_certs(warn_days=5)[0]["status"], "ok")
        # critical_days=12: 10 <= 12 -> critical
        self.assertEqual(
            certs.scan_certs(critical_days=12)[0]["status"], "critical")


class SummarizeTest(CertsTestCase):
    def test_counts_and_top_expiring(self):
        self._seed("10.0.0.1", 443, {"not_after": _engine_ts(-5)})
        self._seed("10.0.0.2", 443, {"not_after": _engine_ts(3)})
        self._seed("10.0.0.3", 443, {"not_after": _engine_ts(15)})
        self._seed("10.0.0.4", 443, {"not_after": _engine_ts(200)})
        self._seed("10.0.0.5", 443, {"not_after": _engine_ts(400)})
        summ = certs.summarize(top=3)
        self.assertEqual(summ["total"], 5)
        self.assertEqual(summ["counts"],
                         {"ok": 2, "warn": 1, "critical": 1, "expired": 1})
        self.assertEqual([c["ip"] for c in summ["top_expiring"]],
                         ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        # empty DB -> zero-filled counts
        empty = certs.summarize(db_path=os.path.join(self._tmp.name, "empty.db"))
        self.assertEqual(empty["total"], 0)
        self.assertEqual(empty["counts"],
                         {"ok": 0, "warn": 0, "critical": 0, "expired": 0})
        self.assertEqual(empty["top_expiring"], [])


class CliTest(CertsTestCase):
    def _run(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = certs._main(list(argv))
        return rc, buf.getvalue()

    def test_table_output(self):
        self._seed("10.0.0.1", 443, {"issuer": "CN=expired-ca",
                                     "not_after": _engine_ts(-2)})
        self._seed("10.0.0.2", 443, {"issuer": "CN=ok-ca",
                                     "not_after": _engine_ts(120)})
        rc, out = self._run("--db", db.STATE_DB)
        self.assertEqual(rc, 0)
        self.assertIn("TARGET", out)
        self.assertIn("DAYS_LEFT", out)
        self.assertIn("10.0.0.1:443", out)
        self.assertIn("expired", out)
        self.assertIn("CN=expired-ca", out)
        self.assertIn("summary: total=2 expired=1", out)

    def test_json_ndjson_output(self):
        self._seed("10.0.0.1", 443, {"issuer": "CN=x",
                                     "not_after": _engine_ts(5)})
        rc, out = self._run("--db", db.STATE_DB, "--json")
        self.assertEqual(rc, 0)
        lines = [ln for ln in out.splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1)
        obj = json.loads(lines[0])
        self.assertEqual(obj["status"], "critical")
        self.assertEqual(obj["ip"], "10.0.0.1")
        self.assertEqual(obj["port"], 443)

    def test_csv_export(self):
        self._seed("10.0.0.1", 443, {"issuer": "CN=a", "subject": "CN=b",
                                     "fingerprint_sha256": "f" * 64,
                                     "not_after": _engine_ts(5)})
        self._seed("10.0.0.2", 443, {"not_after": _engine_ts(-1)})
        csv_path = os.path.join(self._tmp.name, "certs.csv")
        rc, out = self._run("--db", db.STATE_DB, "--csv", csv_path)
        self.assertEqual(rc, 0)
        self.assertIn("10.0.0.1:443", out)  # table still shown
        with open(csv_path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 2)
        first = rows[1] if rows[0]["target"] == "10.0.0.2:443" else rows[0]
        self.assertEqual(set(first),
                         {"target", "ip", "port", "issuer", "subject",
                          "fingerprint_sha256", "not_after", "days_left",
                          "status"})
        self.assertEqual(first["status"], "critical")

    def test_empty_db_prints_no_tls_records_and_exits_zero(self):
        rc, out = self._run("--db", db.STATE_DB)
        self.assertEqual(rc, 0)
        self.assertIn("no TLS records", out)

    def test_null_tls_only_db_prints_no_tls_records(self):
        self._seed("10.0.0.1", 443, None)
        rc, out = self._run("--db", db.STATE_DB, "--json")
        self.assertEqual(rc, 0)
        self.assertIn("no TLS records", out)

    def test_empty_db_csv_export_writes_header(self):
        csv_path = os.path.join(self._tmp.name, "empty.csv")
        rc, out = self._run("--db", db.STATE_DB, "--csv", csv_path)
        self.assertEqual(rc, 0)
        self.assertIn("no TLS records", out)
        with open(csv_path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
