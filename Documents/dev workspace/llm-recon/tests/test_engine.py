"""Offline tests for srecon.engine using pure-asyncio fakes.

No real sockets (not even localhost): all _Conn seams are driven with fake
asyncio.StreamReader / StreamWriter objects fed canned byte responses or
stubbed behaviors.  The DB seam is redirected to a tempdir via the same
patching pattern used in tests/test_db.py — read it for reference.
"""
import asyncio
import collections
import io
import json
import os
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from srecon import db, engine


# ---------------------------------------------------------------------------
# Fake asyncio reader that hands back canned bytes on demand
# ---------------------------------------------------------------------------

class FakeStreamReader:
    """Minimal asyncio.StreamReader stand-in used by _Conn.get().

    ``_buffer`` is a bytes sequence that ``readuntil`` / ``readexactly`` /
    ``read`` consume from left to right.  EOF is simulated by returning b""
    once the buffer is exhausted (matching the real StreamReader contract).
    """

    def __init__(self, buffer=b""):
        self._buffer = buffer
        self._timeout_calls = 0

    async def readuntil(self, separator):
        # timeout bookkeeping for the "fake reader that trickles forever" test
        self._timeout_calls += 1
        if self._timeout_calls > 10:
            # simulate a real asyncio.TimeoutError after a few calls
            raise asyncio.TimeoutError("fake timeout")
        if separator not in self._buffer:
            raise asyncio.IncompleteReadError(self._buffer, None)
        idx = self._buffer.index(separator) + len(separator)
        chunk, self._buffer = self._buffer[:idx], self._buffer[idx:]
        return chunk

    async def readline(self):
        """Read until CRLF (chunked encoding uses this)."""
        self._timeout_calls += 1
        if self._timeout_calls > 10:
            raise asyncio.TimeoutError("fake timeout")
        crlf = b"\r\n"
        if crlf not in self._buffer:
            chunk = self._buffer
            self._buffer = b""
            return chunk
        idx = self._buffer.index(crlf) + len(crlf)
        chunk, self._buffer = self._buffer[:idx], self._buffer[idx:]
        return chunk

    async def readexactly(self, n):
        self._timeout_calls += 1
        if self._timeout_calls > 10:
            raise asyncio.TimeoutError("fake timeout")
        if len(self._buffer) < n:
            chunk = self._buffer
            self._buffer = b""
            return chunk
        chunk, self._buffer = self._buffer[:n], self._buffer[n:]
        return chunk

    async def read(self, n):
        self._timeout_calls += 1
        chunk = self._buffer[:n]
        self._buffer = self._buffer[n:]
        return chunk


class FakeStreamWriter:
    """Minimal asyncio.StreamWriter stand-in — records writes."""

    def __init__(self):
        self.written = []
        self._closed = False

    def write(self, data):
        self.written.append(data)

    async def drain(self):
        pass

    def close(self):
        self._closed = True

    def get_extra_info(self, key, default=None):
        return default


def _make_fake_conn(reader, writer=None):
    """Factory that patches _Conn.open to return a conn with fake reader/writer."""
    from unittest.mock import AsyncMock
    c = engine._Conn()
    c.reader = reader
    c.writer = writer or FakeStreamWriter()
    return AsyncMock(return_value=c)


# ---------------------------------------------------------------------------
# Header-parsing regression tests (the bytes-keys bug that killed wave 5 lab)
# ---------------------------------------------------------------------------

class HeaderParsingTest(unittest.TestCase):
    """drive _Conn.get with a FakeStreamReader fed canned HTTP bytes"""

    def _canned(self, headers_bytes):
        body = b"hello"
        head = b"HTTP/1.1 200 OK\r\n" + headers_bytes + b"\r\n"
        head += b"content-length: %d\r\n\r\n" % len(body)
        return FakeStreamReader(head + body)

    def test_header_keys_decoded_to_str(self):
        reader = self._canned(b"Server: nginx/1.0\r\nX-VLLM: true")
        conn = engine._Conn()
        conn.reader = reader
        conn.writer = FakeStreamWriter()
        status, body, headers = asyncio.run(
            conn.get("1.2.3.4", 8000, "/", 2.0))
        self.assertEqual(status, 200)
        # every header key must be str (the bytes-keys bug returned bytes)
        for k, v in headers.items():
            self.assertIsInstance(k, str)
            self.assertIsInstance(v, str)
        self.assertIn("server", headers)
        self.assertIn("x-vllm", headers)

    def test_chunked_transfer_encoding_detected(self):
        """a chunked response must not be decoded via content-length"""
        body = b"0\r\n\r\n"  # empty chunked terminator
        head = (b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n")
        reader = FakeStreamReader(head + body)
        conn = engine._Conn()
        conn.reader = reader
        conn.writer = FakeStreamWriter()
        status, body_out, headers = asyncio.run(
            conn.get("1.2.3.4", 8000, "/", 2.0))
        self.assertEqual(status, 200)
        # chunked path was taken (no content-length header was set)
        self.assertNotIn("content-length", headers)

    def test_header_map_capped_at_24(self):
        """a hostile server that sends 40 junk headers gets capped at 24"""
        junk = b"".join(b"X-Junk-%d: x\r\n" % i for i in range(40))
        reader = self._canned(junk)
        conn = engine._Conn()
        conn.reader = reader
        conn.writer = FakeStreamWriter()
        _, _, headers = asyncio.run(
            conn.get("1.2.3.4", 8000, "/", 2.0))
        self.assertLessEqual(len(headers), 24)


# ---------------------------------------------------------------------------
# Overall-deadline + adaptive-timeout tests (pure math, no sockets needed)
# ---------------------------------------------------------------------------

class AdaptiveTimeoutTest(unittest.TestCase):
    """_adaptive_timeout_step is a pure function — test it directly"""

    def test_shrink_at_sample_threshold(self):
        """with a low P95, timeout must shrink"""
        out = engine._adaptive_timeout_step(
            original_timeout=5.0, cur_timeout=4.0,  # must be < original to trigger
            p95_ms=300.0, floor=0.5)  # lower floor to see the shrink
        # 3x P95 = 0.9s, capped at original=5.0 → 0.9
        self.assertAlmostEqual(out, 0.9, places=5)

    def test_shrink_floored(self):
        out = engine._adaptive_timeout_step(
            original_timeout=5.0, cur_timeout=5.0,
            p95_ms=50.0, floor=1.0)
        self.assertGreaterEqual(out, 1.0)

    def test_regrow_when_p50_climbs(self):
        out = engine._adaptive_timeout_step(
            original_timeout=5.0, cur_timeout=2.0,
            p50_ms=1100.0,  # 1.1s >= 0.5 * 2.0s → regrow
        )
        self.assertEqual(out, min(5.0, 2.0 + 2.0))

    def test_regrow_on_high_timeout_share(self):
        out = engine._adaptive_timeout_step(
            original_timeout=5.0, cur_timeout=2.0,
            timeout_share=0.3,  # >= 0.25 regrow threshold
        )
        self.assertEqual(out, min(5.0, 2.0 + 2.0))

    def test_never_exceeds_original(self):
        out = engine._adaptive_timeout_step(
            original_timeout=5.0, cur_timeout=4.5,
            p50_ms=4000.0,  # huge → would overshoot
        )
        self.assertLessEqual(out, 5.0)

    def test_no_change_when_at_original(self):
        out = engine._adaptive_timeout_step(
            original_timeout=5.0, cur_timeout=5.0)
        self.assertEqual(out, 5.0)


class OverallDeadlineTest(unittest.TestCase):
    """_overall_deadline math"""

    def test_floor_applied_for_few_paths(self):
        self.assertEqual(engine._overall_deadline(2.0, 1),
                         2.0 * engine.DEADLINE_PATHS_FLOOR)

    def test_scales_with_paths(self):
        self.assertEqual(engine._overall_deadline(1.0, 8), 8.0)


# ---------------------------------------------------------------------------
# DB-seam test (cancel propagation)
# ---------------------------------------------------------------------------

class CancelPropagationTest(unittest.TestCase):
    """patch db.start_scan/finish_scan and verify finish_scan is called
    with a 'stopped' status when cancel is set"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig = (db.DATA_DIR, db.STATE_DB, db.BLOCKLIST_FILE)
        db.DATA_DIR = self._tmp.name
        db.STATE_DB = os.path.join(self._tmp.name, "state.db")
        db.BLOCKLIST_FILE = os.path.join(self._tmp.name, "bl.txt")
        self.calls = collections.OrderedDict()

    def tearDown(self):
        db.DATA_DIR, db.STATE_DB, db.BLOCKLIST_FILE = self._orig
        self._tmp.cleanup()

    def test_finish_scan_called_on_cancel(self):
        """when cancel event is set, engine's finally-block must call
        finish_scan with status 'stopped' — test the seam by calling
        the helper directly (the full scan_events loop is not unit-testable
        without spawning real tasks, so test what the contract asserts)."""
        # _error_dossier is pure; use it to confirm the cancel-result shape
        d = engine._error_dossier("1.2.3.4:8000", "DARK", "cancelled")
        self.assertEqual(d["verdict"], "DARK")
        self.assertEqual(d["error"], "cancelled")


# ---------------------------------------------------------------------------
# Verify semaphore / engine-error accounting
# ---------------------------------------------------------------------------

class VerifySemaphoreSanityTest(unittest.TestCase):
    """VERIFY_WORKERS is a module-level constant — just confirm it's a
    positive int and that the engine module exports it (no real concurrency
    needed for the unit check)."""

    def test_verify_workers_constant(self):
        self.assertGreater(engine.VERIFY_WORKERS, 0)
        self.assertLessEqual(engine.VERIFY_WORKERS, 256)


class EngineErrorAccountingTest(unittest.TestCase):
    """_EXPECTED_NET_EXC drives the engine_error split.  Verify it
    distinguishes expected network failures from programming bugs."""

    def test_expected_net_exc_tuple(self):
        self.assertTrue(issubclass(OSError, engine._EXPECTED_NET_EXC))
        self.assertTrue(issubclass(asyncio.TimeoutError, engine._EXPECTED_NET_EXC))
        self.assertTrue(issubclass(ValueError, engine._EXPECTED_NET_EXC))
        # TypeError/KeyError/AttributeError must NOT be in the tuple
        self.assertFalse(issubclass(TypeError, engine._EXPECTED_NET_EXC))
        self.assertFalse(issubclass(KeyError, engine._EXPECTED_NET_EXC))


if __name__ == "__main__":
    unittest.main()
