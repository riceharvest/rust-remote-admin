"""Offline tests for srecon.targets: CIDR expansion, host:port parsing,
IPv6 guard, DoD exclusion. No network: RIR fetches and RIPEstat lookups
are stubbed out entirely.
"""
import ipaddress
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from srecon import targets
from srecon.config import DEFAULT_PORTS, DEFAULT_DOD_EXCLUDES, MAX_CIDR_HOSTS


class ExpandTargetsTest(unittest.TestCase):
    def test_single_host_with_default_ports(self):
        out, truncated = targets.expand_targets(["1.2.3.4"])
        self.assertFalse(truncated)
        self.assertEqual(len(out), len(DEFAULT_PORTS))
        self.assertEqual(out[0], ("1.2.3.4", DEFAULT_PORTS[0]))
        for host, port in out:
            self.assertEqual(host, "1.2.3.4")
            self.assertIn(port, DEFAULT_PORTS)

    def test_host_with_explicit_ports(self):
        out, _ = targets.expand_targets(["1.2.3.4"], ports=[8080, 11434])
        self.assertEqual(out, [("1.2.3.4", 8080), ("1.2.3.4", 11434)])

    def test_host_port_parsing(self):
        out, _ = targets.expand_targets(["1.2.3.4:8080"])
        self.assertEqual(out, [("1.2.3.4", 8080)])

    def test_hostname_port_parsing(self):
        out, _ = targets.expand_targets(["example.com:5000"])
        self.assertEqual(out, [("example.com", 5000)])

    def test_scheme_prefixes_stripped(self):
        for line in ("http://1.2.3.4:8080", "https://1.2.3.4:8080", "https://1.2.3.4:8080/"):
            out, _ = targets.expand_targets([line])
            self.assertEqual(out, [("1.2.3.4", 8080)], line)

    def test_blank_and_comment_lines_skipped(self):
        out, _ = targets.expand_targets(["", "   ", "# comment", "1.2.3.4:80"])
        self.assertEqual(out, [("1.2.3.4", 80)])

    def test_invalid_port_drops_line(self):
        out, _ = targets.expand_targets(["1.2.3.4:notaport", "5.6.7.8:80"])
        self.assertEqual(out, [("5.6.7.8", 80)])

    def test_invalid_cidr_dropped(self):
        # a malformed CIDR raises ValueError and the line is skipped
        out, _ = targets.expand_targets(["garbage/24", "1.2.3.4:80"])
        self.assertEqual(out, [("1.2.3.4", 80)])

    def test_non_cidr_text_treated_as_hostname(self):
        # any line without '/' or ':' is treated as a bare hostname
        out, _ = targets.expand_targets(["not an ip at all!!", "unreachable"])
        self.assertEqual(len(out), 2 * len(DEFAULT_PORTS))
        self.assertEqual(out[0], ("not an ip at all!!", DEFAULT_PORTS[0]))

    def test_duplicates_deduped_preserving_order(self):
        out, _ = targets.expand_targets(
            ["1.2.3.4:80", "1.2.3.4:80", "5.6.7.8:80", "1.2.3.4:80"])
        self.assertEqual(out, [("1.2.3.4", 80), ("5.6.7.8", 80)])

    def test_cidr_expansion(self):
        out, truncated = targets.expand_targets(["10.0.0.0/30"], ports=[80])
        self.assertFalse(truncated)
        # /30 has 2 usable hosts: .1 and .2 (network + broadcast excluded)
        self.assertEqual(out, [("10.0.0.1", 80), ("10.0.0.2", 80)])

    def test_cidr_expansion_ports_cartesian(self):
        out, _ = targets.expand_targets(["10.0.0.0/30"], ports=[80, 443])
        self.assertEqual(
            out,
            [("10.0.0.1", 80), ("10.0.0.1", 443),
             ("10.0.0.2", 80), ("10.0.0.2", 443)])

    def test_cidr_host_cap(self):
        # MAX_CIDR_HOSTS caps enumeration per network (memory guard)
        out, _ = targets.expand_targets(["10.0.0.0/8"], ports=[80])
        self.assertEqual(len(out), MAX_CIDR_HOSTS)

    def test_ipv6_cidr_skipped(self):
        # engine is IPv4-only; v6 CIDRs must never be enumerated
        out, truncated = targets.expand_targets(["2001:db8::/32"], ports=[80])
        self.assertFalse(truncated)
        self.assertEqual(out, [])

    def test_bare_ipv6_literal_never_yields_v6_target(self):
        # bare IPv6 literals must never produce a target whose host is a
        # valid IPv6 address (guarantees the engine stays IPv4-only)
        out, _ = targets.expand_targets(["2001:db8::1", "fe80::1"], ports=[80])
        for host, _port in out:
            with self.assertRaises(ValueError):
                ipaddress.IPv6Address(host)

    def test_truncation_at_max_total(self):
        with mock.patch.object(targets, "MAX_TOTAL_TARGETS", 3):
            out, truncated = targets.expand_targets(
                ["a", "b", "c", "d", "e"], ports=[80])
        self.assertTrue(truncated)
        self.assertEqual(out, [("a", 80), ("b", 80), ("c", 80)])

    def test_cidr_early_break_respects_max_total(self):
        with mock.patch.object(targets, "MAX_TOTAL_TARGETS", 3):
            out, truncated = targets.expand_targets(["10.0.0.0/29"], ports=[80])
        self.assertTrue(truncated)
        self.assertEqual(len(out), 3)
        self.assertEqual(out[0], ("10.0.0.1", 80))

    def test_dod_exclusion(self):
        dod = targets.parse_excludes(DEFAULT_DOD_EXCLUDES)
        self.assertEqual(len(dod), len(DEFAULT_DOD_EXCLUDES))
        out, _ = targets.expand_targets(
            ["11.0.0.5", "1.2.3.4", "example.com"], ports=[80], excludes=dod)
        # 11.0.0.5 sits inside 11.0.0.0/8 -> dropped; hostname kept
        self.assertEqual(out, [("1.2.3.4", 80), ("example.com", 80)])

    def test_exclusion_does_not_apply_to_hostnames(self):
        dod = targets.parse_excludes(["10.0.0.0/8"])
        out, _ = targets.expand_targets(
            ["db.internal.example:5432"], ports=[5432], excludes=dod)
        self.assertEqual(out, [("db.internal.example", 5432)])


class ParseExcludesTest(unittest.TestCase):
    def test_parses_valid_and_skips_invalid(self):
        nets = targets.parse_excludes(
            ["10.0.0.0/8", "", "# comment", "not-a-cidr", "2001:db8::/32"])
        self.assertEqual(
            nets, [ipaddress.ip_network("10.0.0.0/8"),
                   ipaddress.ip_network("2001:db8::/32")])

    def test_dod_defaults_are_valid_networks(self):
        for net in targets.parse_excludes(DEFAULT_DOD_EXCLUDES):
            self.assertEqual(net.version, 4)
            self.assertEqual(net.prefixlen, 8)


class CountryCidrsTest(unittest.TestCase):
    """Offline: fetch_rir_stats() is stubbed with a fabricated delegated file."""

    FAKE_STATS = "\n".join([
        "2|ripencc|20240101|1|1234|19700101|+0100",
        "ripencc|NL|ipv4|83.81.0.0|65536|20100101|allocated",
        "ripencc|DE|ipv4|1.0.0.0|256|20100101|allocated",
        "ripencc|NL|ipv4|84.0.0.0|256|20100101|reserved",
        "ripencc|NL|ipv6|2001:db8::|32|20100101|allocated",
    ])

    def test_extracts_allocated_ipv4_for_country(self):
        with mock.patch.object(targets, "fetch_rir_stats", return_value=self.FAKE_STATS):
            cidrs, total = targets.country_cidrs("NL", limit=10)
        self.assertEqual(total, 1)
        self.assertEqual(cidrs, ["83.81.0.0/16"])

    def test_country_match_is_case_insensitive(self):
        with mock.patch.object(targets, "fetch_rir_stats", return_value=self.FAKE_STATS):
            cidrs, total = targets.country_cidrs("nl", limit=10)
        self.assertEqual(total, 1)
        self.assertEqual(cidrs, ["83.81.0.0/16"])


class FakeUrlOpenResult:
    """Stand-in for urllib response; supports the `with` protocol."""
    def __init__(self, payload):
        self._payload = payload if isinstance(payload, bytes) else json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n=-1):
        return self._payload


class BgpviewPrefixesTest(unittest.TestCase):
    """Offline: cache read, urllib fetch and cache write are all stubbed."""

    CACHE_FILE = "/tmp/silicon_recon_asn_64500.json"

    def tearDown(self):
        try:
            os.remove(self.CACHE_FILE)
        except OSError:
            pass

    def _call(self, announced, overview, limit):
        import contextlib
        responses = iter([FakeUrlOpenResult(announced), FakeUrlOpenResult(overview)])
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(targets.os.path,
                                                  "exists", return_value=False))
            stack.enter_context(mock.patch.object(
                targets.urllib.request, "urlopen",
                side_effect=lambda url, timeout: next(responses)))
            stack.enter_context(mock.patch.object(targets.json, "dump",
                                                  return_value=None))
            return targets.bgpview_prefixes("64500", limit=limit)

    def test_prefixes_filtered_and_meta_returned(self):
        announced = {"data": {"prefixes": [
            {"prefix": "1.2.3.0/24"},
            {"prefix": "2001:db8::/32"},   # IPv6 -> must be filtered out
            {"prefix": "5.6.7.0/24"},
        ]}}
        overview = {"data": {"holder": "EXAMPLE-AS"}}
        name, prefixes, total = self._call(announced, overview, limit=100)

        self.assertEqual(name, "EXAMPLE-AS")
        # bgpview_prefixes() shuffles; compare as sets
        self.assertEqual(set(prefixes), {"1.2.3.0/24", "5.6.7.0/24"})
        self.assertEqual(total, 2)

    def test_limit_applied(self):
        announced = {"data": {"prefixes": [
            {"prefix": f"10.0.{i}.0/24"} for i in range(20)
        ]}}
        overview = {"data": {"holder": ""}}
        _name, prefixes, total = self._call(announced, overview, limit=5)
        self.assertEqual(len(prefixes), 5)
        self.assertEqual(total, 20)


if __name__ == "__main__":
    unittest.main()
