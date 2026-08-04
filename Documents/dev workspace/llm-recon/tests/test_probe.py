"""Offline tests for srecon.probe classification.

analyze()/detect_sigs() are pure functions over fabricated endpoint dicts —
no sockets. verify_inference() is exercised with a stubbed
http.client.HTTPConnection so no connection ever leaves the process.
"""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from srecon import probe


def ep(status, js=None, raw=""):
    return {"status": status, "json": js, "raw": raw}


def make_dossier(endpoints):
    return {
        "target": "1.2.3.4:8080",
        "product": "unknown",
        "verdict": "DARK",
        "version": None,
        "model": None,
        "models_served": [],
        "flags": [],
        "endpoints": endpoints,
        "latency_ms": 1,
        "error": None,
        "asn": None,
        "as_name": None,
        "bgp_prefix": None,
        "net_type": None,
        "score": 0,
        "inventory_hash": None,
        "verify_result": None,
        "verify_detail": None,
    }


def flag_names(dossier):
    return [f.split(":", 1)[0] for f in dossier["flags"]]


class AnalyzeVerdictsTest(unittest.TestCase):
    def test_vllm_genuine(self):
        d = make_dossier({
            "/version": ep(200, {"version": "v0.6.6.post1"}),
            "/v1/models": ep(200, {"object": "list", "data": [
                {"id": "Qwen/Qwen2.5-7B-Instruct", "owned_by": "x"}]}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["verdict"], "GENUINE")
        self.assertEqual(out["product"], "vllm")
        self.assertEqual(out["version"], "v0.6.6.post1")
        self.assertEqual(out["model"], "Qwen/Qwen2.5-7B-Instruct")
        self.assertEqual(out["models_served"], ["Qwen/Qwen2.5-7B-Instruct"])
        self.assertEqual(out["flags"], [])
        self.assertEqual(out["score"], 0)
        self.assertIsNotNone(out["inventory_hash"])
        self.assertRegex(out["inventory_hash"], r"^[0-9a-f]{16}$")

    def test_ollama_genuine_with_root_banner(self):
        d = make_dossier({
            "/": ep(200, None, "<html><body>Ollama is running</body></html>"),
            "/api/tags": ep(200, {"models": [
                {"name": "llama3.2:1b"}, {"name": "deepseek-r1:70b"}]}),
            "/api/version": ep(200, {"version": "0.5.7"}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["verdict"], "GENUINE")
        self.assertEqual(out["product"], "ollama")
        self.assertEqual(out["version"], "0.5.7")
        self.assertEqual(out["models_served"],
                         ["llama3.2:1b", "deepseek-r1:70b"])
        self.assertEqual(out["flags"], [])
        self.assertEqual(out["score"], 0)
        self.assertIsNotNone(out["inventory_hash"])

    def test_ollama_without_root_banner_flagged_weak(self):
        d = make_dossier({
            "/": ep(200, None, "<html>some other app</html>"),
            "/api/tags": ep(200, {"models": [{"name": "llama3.2:1b"}]}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["verdict"], "GENUINE")  # single sig, score 15 < 40
        self.assertIn("WEAK_OLLAMA", flag_names(out))
        self.assertEqual(out["score"], 15)

    def test_honeypot_canned_empty_models_list(self):
        # a honeypot answering /api/tags with an empty canned list: still
        # classifies as ollama but flagged weak (no real banner, no models)
        d = make_dossier({
            "/": ep(200, None, "<html><title>Login required</title></html>"),
            "/api/tags": ep(200, {"models": []}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["verdict"], "GENUINE")
        self.assertEqual(out["product"], "ollama")
        self.assertEqual(out["models_served"], [])
        self.assertIn("WEAK_OLLAMA", flag_names(out))

    def test_auth_walled_401_is_unknown(self):
        # every endpoint answers 401 -> no signatures -> UNKNOWN
        d = make_dossier({
            "/v1/models": ep(401, None, "Unauthorized"),
            "/api/tags": ep(401, None, "Unauthorized"),
        })
        out = probe.analyze(d)
        self.assertEqual(out["verdict"], "UNKNOWN")
        self.assertEqual(out["product"], "unknown-http")
        self.assertEqual(out["flags"], [])

    def test_plain_html_unknown(self):
        d = make_dossier({"/": ep(200, None, "<html>Welcome to nginx</html>")})
        out = probe.analyze(d)
        self.assertEqual(out["verdict"], "UNKNOWN")
        self.assertEqual(out["product"], "unknown-http")

    def test_multi_persona_impostor(self):
        # answers ollama AND llamacpp endpoints -> cannot be one process
        d = make_dossier({
            "/": ep(200, None, "<html><body>Ollama is running</body></html>"),
            "/api/tags": ep(200, {"models": [{"name": "llama3.2:1b"}]}),
            "/props": ep(200, {"model_path": "/m/models.gguf",
                               "default_generation_settings": {}}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["verdict"], "IMPOSTOR")
        self.assertEqual(out["product"], "llamacpp+ollama")
        self.assertIn("MULTI_PERSONA", flag_names(out))
        self.assertEqual(out["score"], 35)

    def test_legit_openwebui_ollama_stack_is_genuine(self):
        d = make_dossier({
            "/": ep(200, None, "<html><body>Ollama is running</body></html>"),
            "/api/tags": ep(200, {"models": [{"name": "llama3.2:1b"}]}),
            "/api/version": ep(200, {"version": "0.5.8"}),
            "/api/config": ep(200, {"status": True}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["verdict"], "GENUINE")
        self.assertEqual(out["product"], "ollama+openwebui")
        self.assertNotIn("MULTI_PERSONA", flag_names(out))

    def test_fake_llamacpp_impostor(self):
        # /props present but missing real llama-server markers
        d = make_dossier({
            "/props": ep(200, {"model_path": "/m/models.gguf"}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["product"], "llamacpp")
        self.assertIn("FAKE_LLAMACPP", flag_names(out))
        self.assertEqual(out["score"], 40)
        self.assertEqual(out["verdict"], "IMPOSTOR")  # score >= 40

    def test_impossible_proprietary_inventory(self):
        # claims two proprietary vendors on one box -> IMPOSTOR
        d = make_dossier({
            "/v1/models": ep(200, {"data": [
                {"id": "gpt-4", "owned_by": "openai"},
                {"id": "claude-3", "owned_by": "anthropic"},
            ]}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["verdict"], "IMPOSTOR")
        self.assertIn("IMPOSSIBLE_INVENTORY", flag_names(out))
        self.assertEqual(out["score"], 40)

    def test_single_proprietary_vendor_merely_suspicious(self):
        d = make_dossier({
            "/version": ep(200, {"version": "v0.6.6"}),
            "/v1/models": ep(200, {"data": [
                {"id": "gpt-4", "owned_by": "openai"}]}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["verdict"], "GENUINE")
        self.assertIn("SUSPICIOUS_INVENTORY", flag_names(out))
        self.assertEqual(out["score"], 10)


class DetectSigsMatrixTest(unittest.TestCase):
    """Every framework registered in config must be fingerprintable here."""

    CASES = {
        "vllm": ({"/version": ep(200, {"version": "v0.6.6"}),
                  "/v1/models": ep(200, {"object": "list", "data": [
                      {"id": "Qwen/Qwen2.5-7B"}]})}, "vllm"),
        "llamacpp": ({"/props": ep(200, {"model_path": "/m.gguf",
                                         "default_generation_settings": {},
                                         "total_slots": 1,
                                         "build_info": {},
                                         "chat_template": ""})}, "llamacpp"),
        "sglang": ({"/get_model_info": ep(200, {"model_path": "/models/llama"}),
                    "/get_server_info": ep(200, {"version": "0.4.1"})}, "sglang"),
        "ollama": ({"/": ep(200, None, "Ollama is running"),
                    "/api/tags": ep(200, {"models": [{"name": "llama3.2:1b"}]}),
                    "/api/version": ep(200, {"version": "0.5.7"})}, "ollama"),
        "lmstudio": ({"/api/v0/models": ep(200, {"data": [
            {"id": "llama-3.2-3b"}]})}, "lmstudio"),
        "koboldcpp": ({"/api/extra/version": ep(
            200, {"result": "KoboldCpp v1.79", "version": "1.79"})}, "koboldcpp"),
        "tgwui": ({"/v1/internal/model/info": ep(
            200, {"model_name": "llama3"})}, "tgwui"),
        "tgi": ({"/info": ep(200, {"model_id": "meta-llama/Llama-3.1-8B",
                                   "version": "2.4.0"})}, "tgi"),
        "openwebui": ({"/api/version": ep(200, {"version": "0.5.8"}),
                       "/api/config": ep(200, {"status": True})}, "openwebui"),
    }

    def test_every_framework_produces_its_signature(self):
        for name, (endpoints, sig_key) in self.CASES.items():
            with self.subTest(framework=name):
                sigs = probe.detect_sigs(endpoints)
                self.assertIn(sig_key, sigs, f"{name}: no signature detected")

    def test_ollama_suppresses_vllm_signature(self):
        # ollama serves /version + the OpenAI /v1/models envelope too, so a
        # single ollama process must NOT be reported as vLLM co-hosted
        endpoints = {
            "/version": ep(200, {"version": "0.5.7"}),
            "/v1/models": ep(200, {"object": "list", "data": [
                {"id": "llama3.2:1b"}]}),
            "/": ep(200, None, "Ollama is running"),
            "/api/tags": ep(200, {"models": [{"name": "llama3.2:1b"}]}),
        }
        sigs = probe.detect_sigs(endpoints)
        self.assertIn("ollama", sigs)
        self.assertNotIn("vllm", sigs)


class VerifyInferenceTest(unittest.TestCase):
    """verify_inference() with a fully stubbed HTTPConnection: offline."""

    class FakeResponse:
        def __init__(self, status, payload):
            self.status = status
            self._body = payload if isinstance(payload, bytes) \
                else json.dumps(payload).encode()

        def read(self, n=-1):
            return self._body

    class FakeHTTPConnection:
        responses = []
        instances = []

        def __init__(self, host, port, timeout=None):
            self.host, self.port, self.timeout = host, port, timeout
            self.last = None
            self.__class__.instances.append(self)

        def request(self, method, path, body=None, headers=None):
            self.last = (method, path, body)

        def getresponse(self):
            return self.__class__.responses.pop(0)

        def close(self):
            pass

    def _run(self, responses):
        self.FakeHTTPConnection.responses = responses
        self.FakeHTTPConnection.instances = []
        with mock.patch("srecon.probe.http.client.HTTPConnection",
                        self.FakeHTTPConnection):
            return probe.verify_inference("1.2.3.4", 11434)

    def test_live_generation(self):
        verdict, detail = self._run([
            self.FakeResponse(200, {"models": [{"name": "llama3.2:1b"}]}),
            self.FakeResponse(200, {"done": True, "response": "Hello!",
                                    "model": "llama3.2:1b"}),
        ])
        self.assertEqual(verdict, "live")
        self.assertIn("Hello!", detail)

    def test_honeypot_canned_empty_response(self):
        verdict, detail = self._run([
            self.FakeResponse(200, {"models": [{"name": "llama3.2:1b"}]}),
            self.FakeResponse(200, {"done": True, "response": "",
                                    "model": "llama3.2:1b"}),
        ])
        self.assertEqual(verdict, "honeypot")
        self.assertIn("done=true, empty response", detail)

    def test_auth_walled_401(self):
        verdict, detail = self._run([
            self.FakeResponse(200, {"models": [{"name": "m:cloud"}]}),
            self.FakeResponse(401, {"error": "unauthorized: sign in required"}),
        ])
        self.assertEqual(verdict, "auth-walled")
        self.assertIn("unauthorized", detail.lower())

    def test_no_models_advertised(self):
        verdict, detail = self._run([
            self.FakeResponse(200, {"models": []}),
        ])
        self.assertEqual(verdict, "error")
        self.assertEqual(detail, "no models advertised")

    def test_prefers_local_model_over_cloud(self):
        self._run([
            self.FakeResponse(200, {"models": [
                {"name": "very-long-name:cloud"}, {"name": "aa"}]}),
            self.FakeResponse(200, {"done": True, "response": "ok",
                                    "model": "aa"}),
        ])
        posts = [i.last for i in self.FakeHTTPConnection.instances
                 if i.last and i.last[0] == "POST"]
        self.assertEqual(len(posts), 1)
        self.assertIn('"model": "aa"', posts[0][2])


if __name__ == "__main__":
    unittest.main()
