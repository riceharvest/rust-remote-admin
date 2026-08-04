"""Offline tests for srecon.imports using a tempdir SQLite database.

Uses the same module-global patching pattern as test_db.py: db.DATA_DIR /
db.STATE_DB / db.BLOCKLIST_FILE are repointed at a TemporaryDirectory so no
real project state is touched, and import_file / import_* functions bind to
the db module at call time, so the patched paths take effect.
"""
import json
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from srecon import db, imports


class ImportsTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = (db.DATA_DIR, db.STATE_DB, db.BLOCKLIST_FILE)
        db.DATA_DIR = self._tmp.name
        db.STATE_DB = os.path.join(self._tmp.name, "state.db")
        db.BLOCKLIST_FILE = os.path.join(self._tmp.name, "honeypot_blocklist.txt")

    def tearDown(self):
        db.DATA_DIR, db.STATE_DB, db.BLOCKLIST_FILE = self._orig
        self._tmp.cleanup()

    def _write(self, name, content):
        path = os.path.join(self._tmp.name, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path


class DetectFormatTest(ImportsTestCase):
    def test_sniffs_shodan_jsonl(self):
        p = self._write("shodan.jsonl", '{"ip_str":"1.2.3.4","port":8000}\n')
        self.assertEqual(imports.detect_format(p), "shodan")

    def test_sniffs_censys_json(self):
        p = self._write("c.json",
                        '{"services":[{"ip":"1.2.3.4","port":80}]}')
        self.assertEqual(imports.detect_format(p), "censys")

    def test_sniffs_censys_csv_by_extension(self):
        p = self._write("c.csv", "ip,port,service_name\n1.2.3.4,80,http\n")
        self.assertEqual(imports.detect_format(p), "censys-csv")

    def test_explicit_hint_wins(self):
        p = self._write("weird", '{"ip_str":"1.2.3.4","port":8000}\n')
        self.assertEqual(imports.detect_format(p, "shodan"), "shodan")

    def test_unknown_format_raises(self):
        p = self._write("empty.csv", "ip,port\n")
        with self.assertRaises(ValueError):
            imports.detect_format(p, "nonsense")


class ShodanImportTest(ImportsTestCase):
    FIXTURE = (
        '{"ip_str":"1.2.3.4","port":8000,"org":"Acme","asn":"64512",'
        '"http":{"title":"vLLM API server"},"data":"","hostnames":["a.example"]}\n'
        '{"ip_str":"5.6.7.8","port":11434,"org":"Beta","asn":"64513",'
        '"http":{},"data":"Ollama is running"}\n'
        '{"ip_str":"9.9.9.9","port":8080,"org":"Gamma","asn":null,'
        '"http":{},"data":"nginx"}\n'
    )

    def test_maps_banner_to_product(self):
        p = self._write("shodan.jsonl", self.FIXTURE)
        results, errors = imports.import_shodan(p)
        self.assertEqual(errors, 0)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["product"], "vllm")       # http.title
        self.assertEqual(results[1]["product"], "ollama")      # data banner
        self.assertIsNone(results[2]["product"])               # no keyword
        # verdict + flag + schema basics
        for r in results:
            self.assertEqual(r["verdict"], "UNKNOWN")
            self.assertEqual(r["flags"], ["IMPORTED_SHODAN"])
            self.assertIsNone(r["latency_ms"])
            self.assertEqual(r["score"], 0)
            self.assertIn(":", r["target"])
        self.assertEqual(results[0]["asn"], "64512")
        self.assertEqual(results[0]["as_name"], "Acme")
        self.assertEqual(results[0]["ptr"], "a.example")
        self.assertIsNone(results[2]["asn"])

    def test_malformed_line_counts_error(self):
        p = self._write("bad.jsonl",
                        '{"ip_str":"1.2.3.4","port":80}\n'
                        'this is not json\n'
                        '{"ip_str":"5.6.7.8"}\n')  # missing port
        results, errors = imports.import_shodan(p)
        self.assertEqual(len(results), 1)
        self.assertEqual(errors, 2)


class CensysJsonImportTest(ImportsTestCase):
    def test_maps_services_banner(self):
        obj = {"services": [
            {"ip": "1.2.3.4", "port": 8000, "service_name": "http",
             "http": {"response": {"body": "SGLang server ready", "title": "sglang"}}},
            {"ip": "5.6.7.8", "port": 1234, "service_name": "http",
             "http": {"response": {"body": "Chat with LM Studio", "title": None}}},
            {"ip": "9.9.9.9", "port": 80, "service_name": "http", "http": {}},
        ]}
        p = self._write("c.json", json.dumps(obj))
        results, errors = imports.import_censys_json(p)
        self.assertEqual(errors, 0)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["product"], "sglang")      # response body
        self.assertEqual(results[1]["product"], "lmstudio")    # service/title
        self.assertIsNone(results[2]["product"])
        for r in results:
            self.assertEqual(r["verdict"], "UNKNOWN")
            self.assertEqual(r["flags"], ["IMPORTED_CENSYS"])
        self.assertEqual(results[0]["target"], "1.2.3.4:8000")

    def test_jsonl_of_services(self):
        p = self._write("c.jsonl",
                        '{"services":[{"ip":"1.2.3.4","port":80,"service_name":"http"}]}\n'
                        '{"services":[{"ip":"5.6.7.8","port":80,"service_name":"http"}]}\n')
        results, errors = imports.import_censys_json(p)
        self.assertEqual(errors, 0)
        self.assertEqual(len(results), 2)

    def test_import_censys_autodetects_json(self):
        p = self._write("c.json", json.dumps({"services": [
            {"ip": "1.2.3.4", "port": 4000, "service_name": "http",
             "http": {"response": {"body": "LiteLLM Proxy is Running"}}}]}))
        results, errors = imports.import_censys(p)
        self.assertEqual(errors, 0)
        self.assertEqual(results[0]["product"], "litellm")


class CensysCsvImportTest(ImportsTestCase):
    def test_parses_csv_rows(self):
        p = self._write("c.csv",
                        "ip,port,service_name,org\n"
                        "1.2.3.4,8000,http,Acme\n"
                        "5.6.7.8,11434,http,Beta\n")
        results, errors = imports.import_censys_csv(p)
        self.assertEqual(errors, 0)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["target"], "1.2.3.4:8000")
        self.assertEqual(results[0]["as_name"], "Acme")
        for r in results:
            self.assertEqual(r["verdict"], "UNKNOWN")
            self.assertEqual(r["flags"], ["IMPORTED_CENSYS"])

    def test_import_censys_autodetects_csv(self):
        p = self._write("c.csv", "ip,port\n1.2.3.4,8000\n")
        results, errors = imports.import_censys(p)
        self.assertEqual(errors, 0)
        self.assertEqual(len(results), 1)


class ImportFileTest(ImportsTestCase):
    def test_persists_and_counts(self):
        p = self._write("shodan.jsonl",
                        '{"ip_str":"1.2.3.4","port":8000,"http":{"title":"vLLM"}}\n'
                        '{"ip_str":"5.6.7.8","port":11434,"data":"ollama"}\n')
        counts = imports.import_file(p)
        self.assertEqual(counts["imported"], 2)
        self.assertEqual(counts["skipped"], 0)
        self.assertEqual(counts["errors"], 0)
        conn = sqlite3.connect(db.STATE_DB)
        try:
            rows = {}
            for ip, product, verdict in conn.execute(
                    "SELECT ip, product, verdict FROM targets"):
                rows[ip] = (product, verdict)
        finally:
            conn.close()
        self.assertEqual(rows["1.2.3.4"], ("vllm", "UNKNOWN"))
        self.assertEqual(rows["5.6.7.8"], ("ollama", "UNKNOWN"))

    def test_associates_scan_id(self):
        sid = db.start_scan(target_count=2, params={"import": True})
        p = self._write("c.csv", "ip,port\n1.2.3.4,8000\n2.2.2.2,80\n")
        imports.import_file(p, fmt="censys", scan_id=sid)
        conn = sqlite3.connect(db.STATE_DB)
        try:
            ids = set(r[0] for r in conn.execute("SELECT scan_id FROM targets"))
        finally:
            conn.close()
        self.assertEqual(ids, {sid})

    def test_dedup_skips_fresher_existing_row(self):
        # A real probe already stored a fresher row for this (ip,port).
        db.store_scan_result(
            {"target": "1.2.3.4:8000", "verdict": "GENUINE", "product": "vllm"},
            scan_id=db.start_scan())
        conn = sqlite3.connect(db.STATE_DB)
        # make the existing row strictly NEWER than *anything* the import can produce
        conn.execute("UPDATE targets SET scanned_at=? WHERE ip='1.2.3.4'",
                     (9999999999.0,))
        conn.commit()
        conn.close()
        p = self._write("shodan.jsonl",
                        '{"ip_str":"1.2.3.4","port":8000,"http":{"title":"vllm"}}\n')
        counts = imports.import_file(p)
        self.assertEqual(counts["skipped"], 1)
        self.assertEqual(counts["imported"], 0)
        # fresher real row untouched
        conn = sqlite3.connect(db.STATE_DB)
        try:
            row = conn.execute(
                "SELECT verdict, product, scanned_at FROM targets "
                "WHERE ip='1.2.3.4'").fetchone()
        finally:
            conn.close()
        self.assertEqual(row[0], "GENUINE")
        self.assertEqual(row[1], "vllm")
        self.assertEqual(row[2], 9999999999.0)

    def test_dry_run_writes_nothing(self):
        p = self._write("shodan.jsonl",
                        '{"ip_str":"1.2.3.4","port":8000,"http":{"title":"vLLM"}}\n')
        counts = imports.import_file(p, dry_run=True)
        self.assertEqual(counts["imported"], 1)
        self.assertEqual(counts["errors"], 0)
        self.assertIn("results", counts)
        self.assertEqual(counts["results"][0]["product"], "vllm")
        # DB completely untouched: dry-run must not even create the state file
        self.assertFalse(os.path.exists(db.STATE_DB))

    def test_dataclass_import_older_than_existing_overwrites(self):
        # Existing row is OLDER than import -> import allowed to overwrite.
        db.store_scan_result(
            {"target": "1.2.3.4:8080", "verdict": "GENUINE", "product": "ollama"})
        conn = sqlite3.connect(db.STATE_DB)
        conn.execute("UPDATE targets SET scanned_at=? WHERE ip='1.2.3.4'",
                     (1.0,))
        conn.commit()
        conn.close()
        p = self._write("c.csv", "ip,port,service_name\n1.2.3.4,8080,http\n")
        counts = imports.import_file(p, fmt="censys")
        self.assertEqual(counts["imported"], 1)
        self.assertEqual(counts["skipped"], 0)
        conn = sqlite3.connect(db.STATE_DB)
        try:
            row = conn.execute(
                "SELECT verdict, product FROM targets WHERE ip='1.2.3.4'").fetchone()
        finally:
            conn.close()
        self.assertEqual(row, ("UNKNOWN", None))  # import replaced the old row

    def test_missing_file_returns_error_count(self):
        counts = imports.import_file(os.path.join(self._tmp.name, "nope.jsonl"),
                                     fmt="shodan")
        self.assertEqual(counts["imported"], 0)
        self.assertIn("error", counts)


class CliRunTest(ImportsTestCase):
    def test_main_dry_run_exit_zero(self):
        p = self._write("shodan.jsonl",
                        '{"ip_str":"1.2.3.4","port":8000,"http":{"title":"vLLM"}}\n')
        code = imports._main([p, "--dry-run"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()