"""Offline tests for srecon.notify + the alerts --min-severity filter.

Covers:
* webhook delivery against a local ``ThreadingHTTPServer`` (localhost only,
  no external network) with generic / slack / discord payload shapes;
* webhook error paths (HTTP 500, connection refused) — ok=False, never raises;
* email delivery via a stubbed ``smtplib.SMTP`` (no real SMTP server);
* the ``deliver()`` dispatcher over a config dict;
* ``generate_alerts(min_severity=...)`` filtering (high > medium > low) and
  the CLI missing-notify-config exit path (exit code 2) via a subprocess.

The alert generator tests use a tempdir SQLite DB (never the real
``srecon/data/state.db``), seeded with the scan-versioned targets shape.
"""
import http.server
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from srecon import alert, notify  # noqa: E402


# ---------------------------------------------------------------------------
# local webhook capture server (localhost only)
# ---------------------------------------------------------------------------

class _CaptureHandler(http.server.BaseHTTPRequestHandler):
    """Records the POST body and replies with a configurable status."""

    bodies = []
    status = 200

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        _CaptureHandler.bodies.append(self.rfile.read(length))
        self.send_response(_CaptureHandler.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):  # silence stderr noise
        pass


class WebhookServer:
    """Context manager: ThreadingHTTPServer bound to 127.0.0.1 on a free port."""

    def __init__(self, status=200):
        self.status = status

    def __enter__(self):
        _CaptureHandler.bodies = []
        _CaptureHandler.status = self.status
        self.server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), _CaptureHandler)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.url = f"http://{host}:{port}/hook"
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @property
    def bodies(self):
        return _CaptureHandler.bodies


# ---------------------------------------------------------------------------
# alert generator fixture (scan-versioned tempdir DB)
# ---------------------------------------------------------------------------

def _seed_db(tmpdir):
    """Two scans with one high, one medium and one low severity alert."""
    db_path = os.path.join(tmpdir, "state.db")
    conn = sqlite3.connect(db_path)
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
        conn.execute("INSERT INTO scans (started_at) VALUES (100.0)")
        conn.execute("INSERT INTO scans (started_at) VALUES (200.0)")
        a, b = 1, 2
        # scan A
        conn.execute(
            "INSERT INTO targets (ip,port,verdict,product,scanned_at,scan_id,"
            "models_served) VALUES (?,?,?,?,?,?,?)",
            ("10.0.0.1", 8000, "GENUINE", "vllm", time.time(), a,
             json.dumps([])))          # -> IMPOSTOR flip (high)
        conn.execute(
            "INSERT INTO targets (ip,port,verdict,product,scanned_at,scan_id,"
            "models_served) VALUES (?,?,?,?,?,?,?)",
            ("10.0.0.2", 8000, "GENUINE", "ollama", time.time(), a,
             json.dumps(["a"])))       # -> model change (low)
        # scan B
        conn.execute(
            "INSERT INTO targets (ip,port,verdict,product,scanned_at,scan_id,"
            "models_served) VALUES (?,?,?,?,?,?,?)",
            ("10.0.0.1", 8000, "IMPOSTOR", "ollama", time.time(), b, "[]"))
        conn.execute(
            "INSERT INTO targets (ip,port,verdict,product,scanned_at,scan_id,"
            "models_served) VALUES (?,?,?,?,?,?,?)",
            ("10.0.0.2", 8000, "GENUINE", "ollama", time.time(), b,
             json.dumps(["a", "b"])))
        conn.execute(
            "INSERT INTO targets (ip,port,verdict,product,scanned_at,scan_id,"
            "models_served) VALUES (?,?,?,?,?,?,?)",
            ("10.0.0.3", 8000, "GENUINE", "vllm", time.time(), b,
             json.dumps(["qwen2:7b"])))  # NEW (medium)
        conn.commit()
    finally:
        conn.close()
    return db_path


SAMPLE_ALERTS = [
    {"target": "10.0.0.1:8000", "kind": "VERDICT_FLIP", "watch": "flip",
     "old": "GENUINE", "new": "IMPOSTOR", "scan_id_b": 2, "severity": "high"},
    {"target": "10.0.0.3:8000", "kind": "NEW", "watch": "new",
     "old": None, "new": "GENUINE vllm", "scan_id_b": 2, "severity": "medium"},
    {"target": "10.0.0.2:8000", "kind": "MODEL_CHANGE", "watch": "model",
     "old": "a", "new": "a, b", "scan_id_b": 2, "severity": "low"},
]


# ---------------------------------------------------------------------------
# webhook tests
# ---------------------------------------------------------------------------

class WebhookDeliveryTest(unittest.TestCase):
    def test_generic_payload_shape(self):
        with WebhookServer() as srv:
            res = notify.notify_webhook(srv.url, SAMPLE_ALERTS)
        self.assertTrue(res["ok"], res)
        self.assertIsNone(res["error"])
        self.assertEqual(len(srv.bodies), 1)
        payload = json.loads(srv.bodies[0])
        self.assertEqual(payload["count"], 3)
        self.assertEqual(payload["alerts"], SAMPLE_ALERTS)
        self.assertIn("generated_at", payload)
        self.assertEqual(set(payload), {"alerts", "generated_at", "count"})

    def test_slack_kind_mapping_from_url(self):
        with WebhookServer() as srv:
            res = notify.notify_webhook(srv.url + "?kind=slack", SAMPLE_ALERTS)
        self.assertTrue(res["ok"], res)
        payload = json.loads(srv.bodies[0])
        self.assertEqual(set(payload), {"text", "attachments"})
        self.assertIn("3 change alert(s)", payload["text"])
        self.assertEqual(len(payload["attachments"]), 3)
        first = payload["attachments"][0]
        self.assertEqual(first["color"], "#D93025")  # high
        self.assertIn("VERDICT_FLIP", first["title"])
        self.assertIn("GENUINE -> IMPOSTOR", first["text"])

    def test_discord_kind_mapping_from_url(self):
        with WebhookServer() as srv:
            res = notify.notify_webhook(srv.url + "?kind=discord", SAMPLE_ALERTS)
        self.assertTrue(res["ok"], res)
        payload = json.loads(srv.bodies[0])
        self.assertEqual(set(payload), {"embeds"})
        self.assertEqual(len(payload["embeds"]), 1)
        embed = payload["embeds"][0]
        self.assertEqual(embed["color"], 0xD93025)  # high
        self.assertIn("VERDICT_FLIP", embed["description"])
        self.assertIn("MODEL_CHANGE", embed["description"])

    def test_kind_argument_fallback_without_query(self):
        with WebhookServer() as srv:
            res = notify.notify_webhook(srv.url, SAMPLE_ALERTS, kind="slack")
        self.assertTrue(res["ok"], res)
        payload = json.loads(srv.bodies[0])
        self.assertIn("attachments", payload)

    def test_unknown_kind_in_url_falls_back_to_default(self):
        with WebhookServer() as srv:
            res = notify.notify_webhook(srv.url + "?kind=bogus", SAMPLE_ALERTS)
        self.assertTrue(res["ok"], res)
        payload = json.loads(srv.bodies[0])
        self.assertEqual(set(payload), {"alerts", "generated_at", "count"})

    def test_http_500_is_caught_not_raised(self):
        with WebhookServer(status=500) as srv:
            res = notify.notify_webhook(srv.url, SAMPLE_ALERTS)
        self.assertFalse(res["ok"])
        self.assertIn("HTTP Error 500", res["error"])

    def test_connection_refused_is_caught_not_raised(self):
        # bind a server, note its port, close it, then POST to the dead port
        srv = WebhookServer()
        inner = srv.__enter__()
        dead_url = inner.url
        srv.__exit__(None, None, None)
        res = notify.notify_webhook(dead_url, SAMPLE_ALERTS)
        self.assertFalse(res["ok"])
        self.assertIsInstance(res["error"], str)
        self.assertNotEqual(res["error"], "")

    def test_bad_url_is_caught_not_raised(self):
        res = notify.notify_webhook("not a url", SAMPLE_ALERTS)
        self.assertFalse(res["ok"])
        self.assertIsInstance(res["error"], str)


# ---------------------------------------------------------------------------
# email tests (stubbed smtplib.SMTP — no real SMTP)
# ---------------------------------------------------------------------------

class EmailDeliveryTest(unittest.TestCase):
    def _stub_smtp(self):
        patcher = mock.patch("srecon.notify.smtplib.SMTP")
        fake_cls = patcher.start()
        self.addCleanup(patcher.stop)
        return fake_cls, fake_cls.return_value

    def test_send_message_with_built_body(self):
        fake_cls, instance = self._stub_smtp()
        res = notify.notify_email(
            "smtp.example.com", "srecon@example.com",
            ["ops@example.com", "sec@example.com"],
            "srecon alerts", notify.build_email_body(SAMPLE_ALERTS))
        self.assertTrue(res["ok"], res)
        fake_cls.assert_called_once_with("smtp.example.com", 587, timeout=10)
        instance.starttls.assert_called_once()
        instance.send_message.assert_called_once()
        msg = instance.send_message.call_args.args[0]
        self.assertEqual(msg["From"], "srecon@example.com")
        self.assertEqual(msg["To"], "ops@example.com, sec@example.com")
        self.assertEqual(msg["Subject"], "srecon alerts")
        body = msg.get_content()
        self.assertIn("3 change alert(s) for scan 2", body)
        self.assertIn("[HIGH] VERDICT_FLIP 10.0.0.1:8000: GENUINE -> IMPOSTOR",
                      body)
        self.assertIn("[LOW] MODEL_CHANGE 10.0.0.2:8000: a -> a, b", body)

    def test_login_when_user_given(self):
        fake_cls, instance = self._stub_smtp()
        res = notify.notify_email(
            "smtp.example.com", "a@b.c", ["d@e.f"], "subj", "body",
            user="alice", password="hunter2")
        self.assertTrue(res["ok"], res)
        instance.login.assert_called_once_with("alice", "hunter2")

    def test_no_login_without_user(self):
        fake_cls, instance = self._stub_smtp()
        res = notify.notify_email(
            "smtp.example.com", "a@b.c", ["d@e.f"], "subj", "body")
        self.assertTrue(res["ok"], res)
        instance.login.assert_not_called()

    def test_port_465_uses_smtp_ssl(self):
        with mock.patch("srecon.notify.smtplib.SMTP_SSL") as ssl_cls:
            instance = ssl_cls.return_value
            res = notify.notify_email(
                "smtp.example.com", "a@b.c", ["d@e.f"], "subj", "body",
                port=465)
        self.assertTrue(res["ok"], res)
        ssl_cls.assert_called_once_with("smtp.example.com", 465, timeout=10)

    def test_smtp_failure_caught_not_raised(self):
        fake_cls, instance = self._stub_smtp()
        instance.send_message.side_effect = OSError("connection lost")
        res = notify.notify_email(
            "smtp.example.com", "a@b.c", ["d@e.f"], "subj", "body")
        self.assertFalse(res["ok"])
        self.assertIn("connection lost", res["error"])


# ---------------------------------------------------------------------------
# dispatcher
# ---------------------------------------------------------------------------

class DeliverTest(unittest.TestCase):
    def test_webhook_only_config(self):
        with WebhookServer() as srv:
            res = notify.deliver(SAMPLE_ALERTS, {"webhook": srv.url})
        self.assertEqual(set(res), {"webhook"})
        self.assertTrue(res["webhook"]["ok"])
        self.assertEqual(json.loads(srv.bodies[0])["count"], 3)

    def test_smtp_only_config(self):
        with mock.patch("srecon.notify.smtplib.SMTP") as fake_cls:
            res = notify.deliver(SAMPLE_ALERTS, {
                "smtp": {"host": "smtp.example.com", "from": "a@b.c",
                         "to": ["d@e.f"]}})
        self.assertEqual(set(res), {"email"})
        self.assertTrue(res["email"]["ok"], res)
        self.assertTrue(fake_cls.return_value.send_message.called)

    def test_both_channels(self):
        with WebhookServer() as srv, \
                mock.patch("srecon.notify.smtplib.SMTP") as fake_cls:
            res = notify.deliver(SAMPLE_ALERTS, {
                "webhook": srv.url,
                "smtp": {"host": "smtp.example.com", "from": "a@b.c",
                         "to": ["d@e.f"]}})
        self.assertEqual(set(res), {"webhook", "email"})
        self.assertTrue(res["webhook"]["ok"])
        self.assertTrue(res["email"]["ok"], res)

    def test_incomplete_smtp_config_reports_error(self):
        res = notify.deliver(SAMPLE_ALERTS, {
            "smtp": {"host": "smtp.example.com"}})
        self.assertIn("email", res)
        self.assertFalse(res["email"]["ok"])
        self.assertIn("requires host, from and to", res["email"]["error"])

    def test_no_channels_returns_empty(self):
        self.assertEqual(notify.deliver(SAMPLE_ALERTS, {}), {})


# ---------------------------------------------------------------------------
# min-severity filter (generate_alerts) + CLI missing-config exit path
# ---------------------------------------------------------------------------

class MinSeverityFilterTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = _seed_db(self._tmp.name)
        self.state_path = os.path.join(self._tmp.name, "alerts_state.json")

    def tearDown(self):
        self._tmp.cleanup()

    def _alerts(self, min_severity=None):
        return alert.generate_alerts(
            db_path=self.db_path, baseline_scan_id=1, current_scan_id=2,
            state_path=self.state_path, use_state=False,
            min_severity=min_severity)

    def test_all_severities_by_default(self):
        sevs = {a["severity"] for a in self._alerts()}
        self.assertEqual(sevs, {"high", "medium", "low"})

    def test_high_keeps_only_high(self):
        alerts = self._alerts("high")
        self.assertEqual({a["severity"] for a in alerts}, {"high"})
        self.assertEqual(alerts[0]["kind"], "VERDICT_FLIP")

    def test_medium_keeps_high_and_medium(self):
        sevs = {a["severity"] for a in self._alerts("medium")}
        self.assertEqual(sevs, {"high", "medium"})

    def test_low_keeps_everything(self):
        self.assertEqual(len(self._alerts("low")), 3)

    def test_unknown_severity_raises(self):
        with self.assertRaises(ValueError):
            self._alerts("critical")

    def test_existing_tests_stay_green_shape(self):
        # the seeded fixture still yields the same alert dict shape/filtering
        # behaviour as before the min_severity param was added
        alerts = self._alerts()
        self.assertEqual(
            {a["kind"] for a in alerts}, {"VERDICT_FLIP", "MODEL_CHANGE", "NEW"})


class CliMissingConfigTest(unittest.TestCase):
    def test_notify_without_config_exits_2(self):
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as tmp:
            missing = os.path.join(tmp, "nope.json")
            db = os.path.join(tmp, "state.db")  # never created/read
            proc = subprocess.run(
                [sys.executable, "-m", "srecon", "alerts", "--notify",
                 "--notify-config", missing, "--db", db],
                cwd=repo, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 2)
        self.assertIn(f"no notify config at {missing}", proc.stderr)

    def test_notify_without_config_exits_2_default_path(self):
        # --notify with no --notify-config points at srecon/data/notify.json,
        # which does not exist in the checkout
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "state.db")
            proc = subprocess.run(
                [sys.executable, "-m", "srecon", "alerts", "--notify",
                 "--db", db],
                cwd=repo, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("no notify config at", proc.stderr)
        self.assertIn("notify.json", proc.stderr)


if __name__ == "__main__":
    unittest.main()
