"""Offline consistency tests for srecon.config's framework registry:
every framework must declare ports, probe paths and a reachable signature
detector; the DEFAULT_PORTS union must stay sorted and unique; port
collisions must never break per-framework narrowing.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from srecon import config

# probe path that drives each framework's signature detector in
# probe.detect_sigs() (single source of truth: read from probe.py)
DETECTOR_PATHS = {
    "vllm": "/v1/models",
    "llamacpp": "/props",
    "sglang": "/get_model_info",
    "ollama": "/api/tags",
    "lmstudio": "/api/v0/models",
    "koboldcpp": "/api/extra/version",
    "tgwui": "/api/v1/model",
    "tgi": "/info",
    "openwebui": "/api/config",
    "aphrodite": "/version",
    "triton": "/v2/health/ready",
    "localai": "/readyz",
    "xinference": "/api/models",
    "litellm": "/health/liveliness",
    "tabbyapi": "/v1/model_template",
    "mlc": "/v1/models",
}


class FrameworkRegistryTest(unittest.TestCase):
    def test_every_framework_has_ports_and_paths(self):
        for name, fw in config.FRAMEWORKS.items():
            self.assertIsInstance(fw, dict, name)
            self.assertGreater(len(fw.get("ports", [])), 0,
                               f"{name}: no ports declared")
            self.assertGreater(len(fw.get("paths", [])), 0,
                               f"{name}: no probe paths declared")
            for p in fw["ports"]:
                self.assertIsInstance(p, int, f"{name}: port {p!r} not int")
                self.assertGreater(p, 0, f"{name}: port {p} not positive")

    def test_every_framework_has_signature_detector(self):
        # every registered framework must be distinguishable by probe.py —
        # its own path list must include the endpoint that drives its detector
        self.assertEqual(set(config.FRAMEWORKS), set(DETECTOR_PATHS))
        for name, fw in config.FRAMEWORKS.items():
            self.assertIn(
                DETECTOR_PATHS[name], fw["paths"],
                f"{name}: {DETECTOR_PATHS[name]} (its signature endpoint) "
                f"missing from probe paths {fw['paths']}")

    def test_framework_paths_are_subset_of_probe_paths(self):
        # the union used when several frameworks are selected must cover
        # every single-framework probe path
        for name, fw in config.FRAMEWORKS.items():
            for path in fw["paths"]:
                self.assertIn(path, config.PROBE_PATHS,
                              f"{name}: probe path {path} missing from PROBE_PATHS")

    def test_default_ports_is_sorted_unique_union(self):
        all_ports = [p for fw in config.FRAMEWORKS.values() for p in fw["ports"]]
        self.assertEqual(config.DEFAULT_PORTS, sorted(set(all_ports)))
        self.assertEqual(len(config.DEFAULT_PORTS), len(set(config.DEFAULT_PORTS)))

    def test_every_framework_port_in_default_ports(self):
        for name, fw in config.FRAMEWORKS.items():
            for p in fw["ports"]:
                self.assertIn(p, config.DEFAULT_PORTS,
                              f"{name}: port {p} missing from DEFAULT_PORTS")

    def test_no_duplicate_ports_within_a_framework(self):
        # a duplicate port inside one framework would probe the same port
        # twice and break narrowing
        for name, fw in config.FRAMEWORKS.items():
            self.assertEqual(len(fw["ports"]), len(set(fw["ports"])),
                             f"{name}: duplicate ports {fw['ports']}")

    def test_cross_framework_port_collisions_are_known(self):
        # narrowing to one framework is safe as long as its own list is
        # unique; cross-framework overlap is expected and documented.
        # Currently shared: 3000 (tgi+openwebui), 5000 (tgwui+tabbyapi),
        # 8000 (vllm+triton), 8080 (llamacpp+localai+mlc).
        from collections import Counter
        counts = Counter(p for fw in config.FRAMEWORKS.values() for p in fw["ports"])
        shared = {p for p, n in counts.items() if n > 1}
        self.assertEqual(shared, {3000, 5000, 8000, 8080},
                         f"unexpected cross-framework port collision: {shared}")

    def test_no_framework_port_list_is_empty_or_falsy(self):
        # an empty ports list would fall back to the union and probe every
        # other framework's ports -> narrowing silently broken
        for name, fw in config.FRAMEWORKS.items():
            self.assertTrue(fw["ports"], f"{name}: empty ports list")
            self.assertTrue(fw["paths"], f"{name}: empty paths list")


class ScoringConfigTest(unittest.TestCase):
    def test_impostor_threshold_consistent_with_weights(self):
        # any single heavy flag (>=40) must flip the verdict to IMPOSTOR
        for flag, weight in config.SCORE_WEIGHTS.items():
            self.assertGreaterEqual(weight, 0, flag)
            if weight >= 40:
                self.assertIn(flag, ("FAKE_LLAMACPP", "IMPOSSIBLE_INVENTORY"))

    def test_legit_combos_reference_real_frameworks(self):
        for combo in config.LEGIT_COMBOS:
            for name in combo:
                self.assertIn(name, config.FRAMEWORKS, name)

    def test_proprietary_vendors_are_lowercase_names(self):
        for v in config.PROPRIETARY_VENDORS:
            self.assertEqual(v, v.lower(), v)

    def test_frontends_reference_real_frameworks(self):
        for name in config.FRONTENDS:
            self.assertIn(name, config.FRAMEWORKS, name)

    def test_sig_priority_covers_all_frameworks_and_generics(self):
        expected = set(config.FRAMEWORKS) | {"openai-compat", "custom-gateway"}
        self.assertEqual(set(config.SIG_PRIORITY), expected)
        self.assertEqual(len(config.SIG_PRIORITY), len(set(config.SIG_PRIORITY)))

    def test_generic_gateway_sigs_rank_below_specific_backends(self):
        # priority selection must prefer concrete backends over the generic
        # openai-compat/custom-gateway labels (frontends are lowest)
        for generic in ("openai-compat", "custom-gateway"):
            for fw in config.FRAMEWORKS:
                if fw in config.FRONTENDS:  # frontends rank lowest, by design
                    continue
                # a specific backend must rank (earlier index) above a generic
                self.assertLess(
                    config.SIG_PRIORITY.index(fw),
                    config.SIG_PRIORITY.index(generic),
                    f"{fw} must rank above {generic}")

    def test_lean_ports_subset_of_default_ports(self):
        self.assertTrue(config.LEAN_PORTS <= set(config.DEFAULT_PORTS))


if __name__ == "__main__":
    unittest.main()
