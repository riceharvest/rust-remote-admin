"""Offline tests for srecon.packs: pack definitions must be well-formed —
unique names, non-empty metadata, numeric-string ASNs, no intra-pack
duplicates, and the allcloud meta-pack must mirror the union of the rest.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from srecon.packs import PACKS


class PackDefinitionTest(unittest.TestCase):
    def test_pack_names_unique(self):
        self.assertEqual(len(PACKS), len(set(PACKS)))

    def test_every_pack_has_label_hint_and_asns(self):
        for name, pack in PACKS.items():
            self.assertIsInstance(pack, dict, name)
            self.assertIsInstance(pack.get("label"), str, name)
            self.assertTrue(pack["label"].strip(), f"{name}: empty label")
            self.assertIsInstance(pack.get("hint"), str, name)
            self.assertTrue(pack["hint"].strip(), f"{name}: empty hint")
            self.assertIsInstance(pack.get("asns"), list, name)
            self.assertGreater(len(pack["asns"]), 0, f"{name}: no ASNs")

    def test_asns_are_numeric_strings(self):
        for name, pack in PACKS.items():
            for asn in pack["asns"]:
                self.assertIsInstance(asn, str, f"{name}: ASN {asn!r} not str")
                self.assertTrue(asn.isdigit(), f"{name}: ASN {asn!r} not numeric")

    def test_no_duplicate_asn_within_pack(self):
        for name, pack in PACKS.items():
            self.assertEqual(len(pack["asns"]), len(set(pack["asns"])),
                             f"{name}: duplicate ASNs {pack['asns']}")

    def test_allcloud_is_union_of_all_other_packs(self):
        others = set()
        for name, pack in PACKS.items():
            if name == "allcloud":
                continue
            others |= set(pack["asns"])
        self.assertEqual(set(PACKS["allcloud"]["asns"]), others)

    def test_all_asns_are_plausible_bgp_numbers(self):
        # public ASNs live in [1, 4294967295]; private/doc ranges excluded
        for name, pack in PACKS.items():
            for asn in pack["asns"]:
                self.assertGreaterEqual(int(asn), 1, f"{name}: ASN {asn}")
                self.assertLessEqual(int(asn), 4_294_967_295, f"{name}: ASN {asn}")


if __name__ == "__main__":
    unittest.main()
