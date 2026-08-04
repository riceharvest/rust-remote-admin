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


def ep(status, js=None, raw="", headers=None):
    return {"status": status, "json": js, "raw": raw,
            "headers": headers or {}}


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
        "latency_ms": 120,
        "error": None,
        "asn": None,
        "as_name": None,
        "bgp_prefix": None,
        "net_type": None,
        "score": 0,
        "score_reasons": [],
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

    def test_openai_compat_envelope_alone_is_not_vllm(self):
        # bare OpenAI envelope with no vLLM-specific marker: generic family,
        # NOT proof of vLLM (LiteLLM/LocalAI/MLC/proxies all serve this)
        d = make_dossier({
            "/v1/models": ep(200, {"object": "list", "data": [
                {"id": "gpt-4o-mini", "owned_by": "openai"}]}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["product"], "openai-compat")
        self.assertNotIn("vllm", out["product"])
        self.assertEqual(out["verdict"], "GENUINE")
        self.assertEqual(out["models_served"], ["gpt-4o-mini"])
        self.assertIsNotNone(out["inventory_hash"])

    def test_fake_litellm_not_vllm(self):
        # LiteLLM answers the envelope + /health/liveliness LIVE: the
        # specific backend wins and vllm must NOT be claimed
        d = make_dossier({
            "/health/liveliness": ep(200, None, "LIVE"),
            "/models": ep(200, ["gpt-4o-mini", "claude-3-haiku"]),
            "/version": ep(200, {"version": "v0.6.6"}),  # vllm-like version!
            "/v1/models": ep(200, {"object": "list", "data": [
                {"id": "gpt-4o-mini"}]}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["product"], "litellm")
        self.assertNotIn("vllm", out["product"])
        self.assertEqual(out["verdict"], "GENUINE")
        self.assertEqual(out["models_served"], ["gpt-4o-mini", "claude-3-haiku"])

    def test_custom_gateway_when_version_carries_model_field(self):
        # hand-copied endpoints: /version has a "model" field no stock
        # framework sets -> custom-gateway, not vllm, not openai-compat
        d = make_dossier({
            "/version": ep(200, {"model": "my-gateway-model",
                                 "version": "1.2.3"}),
            "/v1/models": ep(200, {"object": "list", "data": [
                {"id": "my-gateway-model"}]}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["product"], "custom-gateway")
        self.assertEqual(out["model"], "my-gateway-model")
        self.assertEqual(out["verdict"], "GENUINE")

    def test_vllm_via_x_vllm_header(self):
        d = make_dossier({
            "/v1/models": ep(200, {"data": [{"id": "Qwen2.5-7B"}]},
                             headers={"x-vllm": "0.6.6"}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["product"], "vllm")
        self.assertEqual(out["verdict"], "GENUINE")

    def test_vllm_via_server_banner(self):
        d = make_dossier({
            "/v1/models": ep(200, {"data": [{"id": "Qwen2.5-7B"}]},
                             headers={"server": "vllm/0.6.6"}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["product"], "vllm")

    def test_mlc_via_x_mlc_llm_header(self):
        d = make_dossier({
            "/v1/models": ep(200, {"data": [{"id": "Llama-3-8B"}]},
                             headers={"x-mlc-llm": "1"}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["product"], "mlc")
        self.assertEqual(out["verdict"], "GENUINE")

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

    def test_legit_openwebui_tgi_stack_is_genuine(self):
        # frontend + exactly one backend is a legit stack, not multi-persona
        d = make_dossier({
            "/info": ep(200, {"model_id": "meta-llama/Llama-3.1-8B"}),
            "/api/version": ep(200, {"version": "0.5.8"}),
            "/api/config": ep(200, {"status": True}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["verdict"], "GENUINE")
        self.assertEqual(out["product"], "tgi+openwebui")  # priority order
        self.assertNotIn("MULTI_PERSONA", flag_names(out))

    def test_legit_openwebui_plus_generic_backend_is_genuine(self):
        # openwebui in front of an unidentified OpenAI-compatible backend
        d = make_dossier({
            "/v1/models": ep(200, {"object": "list", "data": [
                {"id": "gpt-4o-mini"}]}),
            "/api/version": ep(200, {"version": "0.5.8"}),
            "/api/config": ep(200, {"status": True}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["verdict"], "GENUINE")
        self.assertEqual(out["product"], "openai-compat+openwebui")
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
        # (bare surface with no headers also trips MISSING_SERVER_HEADER)
        d = make_dossier({
            "/v1/models": ep(200, {"data": [
                {"id": "gpt-4", "owned_by": "openai"},
                {"id": "claude-3", "owned_by": "anthropic"},
            ]}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["verdict"], "IMPOSTOR")
        self.assertIn("IMPOSSIBLE_INVENTORY", flag_names(out))
        self.assertIn("MISSING_SERVER_HEADER", flag_names(out))
        self.assertEqual(out["score"], 55)

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

    def test_score_capped_at_100(self):
        # FAKE_LLAMACPP(40) + MULTI_PERSONA(35) + WEAK_OLLAMA(15) +
        # IMPOSSIBLE_INVENTORY(40) = 130 -> must cap at 100
        d = make_dossier({
            "/": ep(200, None, "<html>other app</html>"),
            "/api/tags": ep(200, {"models": [{"name": "llama3"}]}),
            "/props": ep(200, {"model_path": "/m/models.gguf"}),
            "/v1/models": ep(200, {"data": [
                {"id": "gpt-4", "owned_by": "openai"},
                {"id": "claude-3", "owned_by": "anthropic"},
            ]}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["score"], 100)
        self.assertEqual(out["verdict"], "IMPOSTOR")


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
        "tgwui": ({"/api/v1/model": ep(200, {"model": "llama3"})}, "tgwui"),
        "tgi": ({"/info": ep(200, {"model_id": "meta-llama/Llama-3.1-8B",
                                   "version": "2.4.0"})}, "tgi"),
        "openwebui": ({"/api/version": ep(200, {"version": "0.5.8"}),
                       "/api/config": ep(200, {"status": True})}, "openwebui"),
        "aphrodite": ({"/version": ep(200, {"app_name": "Aphrodite-Engine",
                                            "version": "0.6.6"}),
                       "/v1/models": ep(200, {"data": [
                           {"id": "mistral-7b"}]})}, "aphrodite"),
        "triton": ({"/v2/health/ready": ep(200, None, "ready"),
                    "/v2/models": ep(200, {"models": [
                        {"name": "llama-3-8b"}]})}, "triton"),
        "localai": ({"/readyz": ep(200, None, "READY"),
                     "/v1/models": ep(200, {"data": [
                         {"id": "gpt-4"}]})}, "localai"),
        "xinference": ({"/api/models": ep(200, [{"model_uid": "llama3"}]),
                        "/v1/models": ep(200, {"data": [
                            {"id": "llama3", "owned_by": "xinference"}]})},
                       "xinference"),
        "litellm": ({"/health/liveliness": ep(200, None, "LIVE"),
                     "/models": ep(200, ["gpt-4o-mini"])}, "litellm"),
        "tabbyapi": ({"/v1/model_template": ep(
            200, {"data": {"id": "tabby-8b"}}),
            "/v1/profile": ep(200, {"data": {"id": "tabby"}})}, "tabbyapi"),
        "mlc": ({"/v1/models": ep(200, {"data": [{"id": "Llama-3-8B"}]},
                                  headers={"x-mlc-llm": "1"})}, "mlc"),
        "openai-compat": ({"/v1/models": ep(200, {"object": "list", "data": [
            {"id": "gpt-4o-mini"}]})}, "openai-compat"),
    }

    def test_every_framework_produces_its_signature(self):
        for name, (endpoints, sig_key) in self.CASES.items():
            with self.subTest(framework=name):
                sigs = probe.detect_sigs(endpoints)
                self.assertIn(sig_key, sigs, f"{name}: no signature detected")

    def test_ollama_suppresses_vllm_signature(self):
        # ollama serves /version + the OpenAI /v1/models envelope too, so a
        # single ollama process must NOT be reported as vLLM co-hosted (nor
        # as a generic openai-compat backend)
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
        self.assertNotIn("openai-compat", sigs)

    def test_tgi_internal_model_info_credited_to_tgi(self):
        # /v1/internal/model/info is a TGI marker, not text-generation-webui
        sigs = probe.detect_sigs({
            "/v1/internal/model/info": ep(200, {"model_name": "llama3"}),
        })
        self.assertIn("tgi", sigs)
        self.assertNotIn("tgwui", sigs)

    def test_tgwui_via_gradio_run_predict(self):
        # Gradio apps answer GET /run/predict with 405 (POST-only endpoint)
        sigs = probe.detect_sigs({
            "/run/predict": ep(405, None, "Method Not Allowed"),
        })
        self.assertIn("tgwui", sigs)


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

    def _run(self, responses, sigs=None):
        self.FakeHTTPConnection.responses = responses
        self.FakeHTTPConnection.instances = []
        # default to the ollama schema when sigs not supplied
        sigs = sigs if sigs is not None else {"ollama"}
        with mock.patch("srecon.probe.http.client.HTTPConnection",
                        self.FakeHTTPConnection):
            return probe.verify_inference("1.2.3.4", 11434, sigs=sigs)

    def _posts(self):
        return [i.last for i in self.FakeHTTPConnection.instances
                if i.last and i.last[0] == "POST"]

    def test_live_generation_ollama(self):
        verdict, detail = self._run([
            self.FakeResponse(200, {"models": [{"name": "llama3.2:1b"}]}),
            self.FakeResponse(200, {"done": True, "response": "Hello!",
                                    "model": "llama3.2:1b"}),
        ], sigs={"ollama"})
        self.assertEqual(verdict, "live")
        self.assertIn("Hello!", detail)
        posts = self._posts()
        self.assertEqual(posts[0][1], "/api/generate")

    def test_honeypot_canned_empty_response_ollama(self):
        verdict, detail = self._run([
            self.FakeResponse(200, {"models": [{"name": "llama3.2:1b"}]}),
            self.FakeResponse(200, {"done": True, "response": "",
                                    "model": "llama3.2:1b"}),
        ], sigs={"ollama"})
        self.assertEqual(verdict, "honeypot")
        self.assertIn("canned empty ollama response", detail)

    def test_auth_walled_401(self):
        verdict, detail = self._run([
            self.FakeResponse(200, {"models": [{"name": "m:cloud"}]}),
            self.FakeResponse(401, {"error": "unauthorized: sign in required"}),
        ], sigs={"ollama"})
        self.assertEqual(verdict, "auth-walled")
        self.assertIn("unauthorized", detail.lower())

    def test_no_models_advertised(self):
        verdict, detail = self._run([
            self.FakeResponse(200, {"models": []}),
        ], sigs={"ollama"})
        self.assertEqual(verdict, "error")
        self.assertEqual(detail, "no models advertised")

    def test_prefers_local_model_over_cloud(self):
        self._run([
            self.FakeResponse(200, {"models": [
                {"name": "very-long-name:cloud"}, {"name": "aa"}]}),
            self.FakeResponse(200, {"done": True, "response": "ok",
                                    "model": "aa"}),
        ], sigs={"ollama"})
        posts = self._posts()
        self.assertEqual(len(posts), 1)
        self.assertIn('"model": "aa"', posts[0][2])

    def test_openai_compat_verify_dispatches_to_v1_completions(self):
        verdict, detail = self._run([
            self.FakeResponse(200, {"object": "list", "data": [
                {"id": "gpt-4o-mini"}, {"id": "x"}]}),
            self.FakeResponse(200, {"choices": [{"text": "Hi there"}]}),
        ], sigs={"openai-compat"})
        self.assertEqual(verdict, "live")
        posts = self._posts()
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0][1], "/v1/completions")
        self.assertIn('"model": "x"', posts[0][2])  # shortest id wins
        self.assertIn('"max_tokens"', posts[0][2])

    def test_vllm_verify_uses_openai_schema(self):
        self._run([
            self.FakeResponse(200, {"data": [{"id": "Qwen2.5-7B"}]}),
            self.FakeResponse(200, {"choices": [{"text": "ok"}]}),
        ], sigs={"vllm"})
        posts = self._posts()
        self.assertEqual(posts[0][1], "/v1/completions")

    def test_llamacpp_verify_dispatches_to_completion(self):
        verdict, detail = self._run([
            self.FakeResponse(200, {"data": [{"id": "llama-3.2-3b"}]}),
            self.FakeResponse(200, {"content": "Hi!"}),
        ], sigs={"llamacpp"})
        self.assertEqual(verdict, "live")
        posts = self._posts()
        self.assertEqual(posts[0][1], "/completion")
        self.assertIn('"n_predict"', posts[0][2])

    def test_tgi_verify_dispatches_to_generate(self):
        verdict, detail = self._run([
            self.FakeResponse(200, {"model_id": "meta-llama/Llama-3.1-8B"}),
            self.FakeResponse(200, {"generated_text": "Hi"}),
        ], sigs={"tgi"})
        self.assertEqual(verdict, "live")
        posts = self._posts()
        self.assertEqual(posts[0][1], "/generate")
        self.assertIn('"max_new_tokens"', posts[0][2])

    def test_openai_honeypot_canned_empty_choices(self):
        verdict, detail = self._run([
            self.FakeResponse(200, {"data": [{"id": "gpt-4o-mini"}]}),
            self.FakeResponse(200, {"choices": [{"text": ""}]}),
        ], sigs={"openai-compat"})
        self.assertEqual(verdict, "honeypot")
        self.assertIn("canned empty openai response", detail)

    def test_unknown_product_skipped(self):
        verdict, detail = self._run([], sigs={})
        self.assertEqual(verdict, "skipped")
        self.assertEqual(detail, "no verify schema for product unknown")
        self.assertEqual(self.FakeHTTPConnection.instances, [])


class VersionExtractionTest(unittest.TestCase):
    """Every framework's version must surface as result['version'] — from
    framework-specific endpoints, the generic /version fallback, or headers."""

    def test_vllm_version_from_json(self):
        d = make_dossier({
            "/version": ep(200, {"version": "v0.6.6.post1", "app_name": "vLLM"}),
            "/v1/models": ep(200, {"data": [{"id": "Qwen-7B", "owned_by": "vllm"}]},
                             headers={"server": "vllm/0.6.6"}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["product"], "vllm")
        self.assertEqual(out["version"], "v0.6.6.post1")

    def test_vllm_version_from_x_header_only(self):
        d = make_dossier({
            "/v1/models": ep(200, {"data": [{"id": "Qwen-7B"}]},
                             headers={"x-vllm": "0.6.6"}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["product"], "vllm")
        self.assertEqual(out["version"], "0.6.6")

    def test_ollama_version(self):
        d = make_dossier({
            "/": ep(200, None, "Ollama is running"),
            "/api/tags": ep(200, {"models": [{"name": "llama3.2:1b"}]}),
            "/api/version": ep(200, {"version": "0.5.7"}),
        })
        self.assertEqual(probe.analyze(d)["version"], "0.5.7")

    def test_llamacpp_version_from_banner_header(self):
        # build_info absent -> mine the "Server: llama-cpp-rXXXX" banner
        d = make_dossier({
            "/props": ep(200, {"model_path": "/m.gguf",
                               "default_generation_settings": {},
                               "total_slots": 1, "build_info": {},
                               "chat_template": ""},
                          headers={"server": "llama-cpp-r2285"}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["product"], "llamacpp")
        self.assertEqual(out["version"], "r2285")

    def test_sglang_version_from_get_server_info(self):
        d = make_dossier({
            "/get_model_info": ep(200, {"model_path": "/models/llama-3-8b"}),
            "/get_server_info": ep(200, {"version": "0.4.5"}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["product"], "sglang")
        self.assertEqual(out["version"], "0.4.5")
        self.assertEqual(out["models_served"], ["/models/llama-3-8b"])
        self.assertEqual(out["model"], "/models/llama-3-8b")

    def test_sglang_version_from_version_endpoint(self):
        # /get_server_info absent -> /version fallback
        d = make_dossier({
            "/get_model_info": ep(200, {"model_path": "/models/llama-3-8b"}),
            "/version": ep(200, {"version": "0.4.1", "app_name": "sglang"}),
        })
        self.assertEqual(probe.analyze(d)["version"], "0.4.1")

    def test_tgi_version(self):
        d = make_dossier({
            "/info": ep(200, {"model_id": "meta-llama/Llama-3.1-8B",
                              "version": "2.4.0"}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["product"], "tgi")
        self.assertEqual(out["version"], "2.4.0")

    def test_aphrodite_version(self):
        d = make_dossier({
            "/version": ep(200, {"app_name": "Aphrodite-Engine",
                                 "version": "0.6.6"}),
            "/v1/models": ep(200, {"data": [{"id": "mistral-7b"}]}),
        })
        out = probe.analyze(d)
        self.assertIn("aphrodite", out["product"])
        self.assertEqual(out["version"], "0.6.6")

    def test_litellm_version_from_version_endpoint(self):
        d = make_dossier({
            "/health/liveliness": ep(200, None, "LIVE"),
            "/models": ep(200, ["gpt-4o-mini"]),
            "/version": ep(200, {"version": "1.45.0"}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["product"], "litellm")
        self.assertEqual(out["version"], "1.45.0")

    def test_localai_version(self):
        d = make_dossier({
            "/readyz": ep(200, None, "READY"),
            "/v1/models": ep(200, {"data": [{"id": "gpt-4"}]}),
            "/version": ep(200, {"version": "2.23.3"}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["product"], "localai")
        self.assertEqual(out["version"], "2.23.3")

    def test_lmstudio_version_from_version_endpoint(self):
        d = make_dossier({
            "/api/v0/models": ep(200, {"data": [{"id": "llama-3.2-3b"}]}),
            "/version": ep(200, {"version": "0.3.9"}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["product"], "lmstudio")
        self.assertEqual(out["version"], "0.3.9")

    def test_koboldcpp_version(self):
        d = make_dossier({
            "/api/extra/version": ep(
                200, {"result": "KoboldCpp v1.79", "version": "1.79"}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["product"], "koboldcpp")
        self.assertEqual(out["version"], "1.79")

    def test_llamacpp_model_depth_uses_alias_and_dgs(self):
        # model_alias and default_generation_settings.model both deepen the
        # served-model name beyond model_path
        d = make_dossier({
            "/props": ep(200, {
                "model_path": "/models/llama-3.2-1b-instruct.Q4_K_M.gguf",
                "model_alias": "my-alias",
                "default_generation_settings": {"model": "llama-3.2-1b"},
                "total_slots": 1, "build_info": "b1234", "chat_template": ""}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["model"], "my-alias")
        self.assertEqual(out["models_served"], ["my-alias"])

    def test_ollama_model_meta_from_tags_details(self):
        # GET-visible depth: /api/tags "details" carries parameter size/quant
        d = make_dossier({
            "/": ep(200, None, "Ollama is running"),
            "/api/tags": ep(200, {"models": [
                {"name": "llama3.2:1b", "details": {
                    "parameter_size": "1.24B",
                    "quantization_level": "Q4_K_M"}}]}),
            "/api/version": ep(200, {"version": "0.5.7"}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["model"], "llama3.2:1b")
        self.assertEqual(out["models_served"], ["llama3.2:1b"])
        sigs = probe.detect_sigs(d["endpoints"])
        self.assertEqual(sigs["ollama"]["model_meta"]["llama3.2:1b"],
                         {"parameter_size": "1.24B", "quantization": "Q4_K_M"})


class InventoryHashTest(unittest.TestCase):
    def test_same_models_different_product_differ(self):
        # identical model list, different framework -> different fleet hash
        vllm = make_dossier({
            "/version": ep(200, {"version": "v0.6.6", "app_name": "vLLM"}),
            "/v1/models": ep(200, {"data": [{"id": "gpt-4o", "owned_by": "x"}]},
                             headers={"server": "vllm/0.6.6"}),
        })
        compat = make_dossier({
            "/v1/models": ep(200, {"data": [{"id": "gpt-4o", "owned_by": "x"}]},
                             headers={"server": "nginx"}),
        })
        a, b = probe.analyze(vllm), probe.analyze(compat)
        self.assertEqual(a["models_served"], b["models_served"])
        self.assertNotEqual(a["inventory_hash"], b["inventory_hash"])

    def test_version_contributes_to_hash(self):
        def mk(ver):
            return probe.analyze(make_dossier({
                "/version": ep(200, {"version": ver, "app_name": "vLLM"}),
                "/v1/models": ep(200, {"data": [{"id": "Qwen-7B"}]},
                                 headers={"server": "vllm/0.6.6"}),
            }))
        self.assertNotEqual(mk("v0.6.1")["inventory_hash"],
                            mk("v0.6.2")["inventory_hash"])

    def test_hash_stable_across_runs(self):
        d = make_dossier({
            "/version": ep(200, {"version": "v0.6.6", "app_name": "vLLM"}),
            "/v1/models": ep(200, {"data": [{"id": "Qwen-7B"}, {"id": "A-1B"}]},
                             headers={"server": "vllm/0.6.6"}),
        })
        self.assertEqual(probe.analyze(d)["inventory_hash"],
                         probe.analyze(d)["inventory_hash"])

    def test_same_surface_same_framework_same_hash(self):
        # identical framework + models -> identical hash (fleet clustering works)
        def mk():
            return probe.analyze(make_dossier({
                "/version": ep(200, {"version": "v0.6.6", "app_name": "vLLM"}),
                "/v1/models": ep(200, {"data": [{"id": "Qwen-7B"}]},
                                 headers={"server": "vllm/0.6.6"}),
            }))
        self.assertEqual(mk()["inventory_hash"], mk()["inventory_hash"])


class ProxyInventoryTest(unittest.TestCase):
    def test_litellm_suppresses_impossible_inventory(self):
        # a LiteLLM proxy legitimately fronts OpenAI + Anthropic: conflicting
        # vendors must NOT flip IMPOSTOR, only an informational flag
        d = make_dossier({
            "/health/liveliness": ep(200, None, "LIVE"),
            "/models": ep(200, ["gpt-4o-mini", "claude-3-haiku"]),
            "/v1/models": ep(200, {"data": [
                {"id": "gpt-4o", "owned_by": "openai"},
                {"id": "claude-3", "owned_by": "anthropic"},
            ]}),
        })
        out = probe.analyze(d)
        self.assertIn("litellm", out["product"])
        self.assertEqual(out["verdict"], "GENUINE")
        self.assertIn("PROXY_INVENTORY", flag_names(out))
        self.assertNotIn("IMPOSSIBLE_INVENTORY", flag_names(out))
        self.assertEqual(out["score"], 0)  # informational: weightless
        self.assertNotIn("PROXY_INVENTORY", out["score_reasons"])

    def test_frontend_suppresses_impossible_inventory(self):
        # Open WebUI multiplexing OpenAI + Anthropic is a legit stack too
        d = make_dossier({
            "/api/version": ep(200, {"version": "0.5.8"}),
            "/api/config": ep(200, {"status": True}),
            "/v1/models": ep(200, {"data": [
                {"id": "gpt-4o", "owned_by": "openai"},
                {"id": "claude-3", "owned_by": "anthropic"},
            ]}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["verdict"], "GENUINE")
        self.assertIn("PROXY_INVENTORY", flag_names(out))
        self.assertNotIn("IMPOSSIBLE_INVENTORY", flag_names(out))


class HoneypotHeuristicsTest(unittest.TestCase):
    # --- MISSING_SERVER_HEADER ---
    def test_missing_server_header_positive(self):
        d = make_dossier({"/v1/models": ep(200, {"data": [{"id": "gpt-4o-mini"}]})})
        out = probe.analyze(d)
        self.assertIn("MISSING_SERVER_HEADER", flag_names(out))
        self.assertEqual(out["score"], 15)

    def test_missing_server_header_negative_with_server_header(self):
        d = make_dossier({"/v1/models": ep(200, {"data": [{"id": "gpt-4o-mini"}]},
                                           headers={"server": "nginx"})})
        out = probe.analyze(d)
        self.assertNotIn("MISSING_SERVER_HEADER", flag_names(out))
        self.assertEqual(out["score"], 0)

    def test_missing_server_header_negative_with_version(self):
        d = make_dossier({
            "/version": ep(200, {"version": "0.6.6", "app_name": "vLLM"}),
            "/v1/models": ep(200, {"data": [{"id": "Qwen-7B"}]}),
        })
        out = probe.analyze(d)
        self.assertNotIn("MISSING_SERVER_HEADER", flag_names(out))

    # --- IMPOSSIBLE_LATENCY ---
    def test_impossible_latency_positive(self):
        d = make_dossier({"/v1/models": ep(200, {"data": [{"id": "x"}]},
                                           headers={"server": "nginx"})})
        d["latency_ms"] = 2
        out = probe.analyze(d)
        self.assertIn("IMPOSSIBLE_LATENCY", flag_names(out))
        self.assertEqual(out["score"], 30)

    def test_impossible_latency_negative_normal_latency(self):
        d = make_dossier({"/v1/models": ep(200, {"data": [{"id": "x"}]},
                                           headers={"server": "nginx"})})
        d["latency_ms"] = 120
        out = probe.analyze(d)
        self.assertNotIn("IMPOSSIBLE_LATENCY", flag_names(out))

    def test_impossible_latency_suppressed_on_localhost(self):
        d = make_dossier({"/v1/models": ep(200, {"data": [{"id": "x"}]})})
        d["latency_ms"] = 1
        d["target"] = "127.0.0.1:11434"
        out = probe.analyze(d)
        self.assertNotIn("IMPOSSIBLE_LATENCY", flag_names(out))

    def test_impossible_latency_absent_when_no_latency(self):
        d = make_dossier({"/v1/models": ep(200, {"data": [{"id": "x"}]})})
        d["latency_ms"] = None
        out = probe.analyze(d)
        self.assertNotIn("IMPOSSIBLE_LATENCY", flag_names(out))

    # --- CANNED_BANNER ---
    def test_canned_banner_positive(self):
        d = make_dossier({
            "/": ep(200, None,
                    "<html><head><title>vLLM — Serving</title></head></html>"),
            "/version": ep(404, None, "not found"),
            "/v1/models": ep(404, None, "not found"),
            "/api/tags": ep(404, None, "not found"),
            "/props": ep(404, None, "not found"),
        })
        out = probe.analyze(d)
        self.assertIn("CANNED_BANNER", flag_names(out))
        self.assertEqual(out["score"], 20)

    def test_canned_banner_negative_distinct_bodies(self):
        d = make_dossier({
            "/": ep(200, None,
                    "<html><head><title>vLLM — Serving</title></head></html>"),
            "/version": ep(404, None, "not found A"),
            "/v1/models": ep(404, None, "not found B"),
            "/api/tags": ep(404, None, "not found C"),
            "/props": ep(404, None, "not found D"),
        })
        out = probe.analyze(d)
        self.assertNotIn("CANNED_BANNER", flag_names(out))

    def test_canned_banner_negative_no_title(self):
        d = make_dossier({
            "/": ep(200, None, "vllm serving multiple models"),
            "/version": ep(404, None, "not found"),
            "/v1/models": ep(404, None, "not found"),
            "/api/tags": ep(404, None, "not found"),
        })
        out = probe.analyze(d)
        self.assertNotIn("CANNED_BANNER", flag_names(out))


class ScoreReasonsTest(unittest.TestCase):
    def test_score_reasons_list_scored_flags(self):
        d = make_dossier({
            "/": ep(200, None, "some app"),
            "/api/tags": ep(200, {"models": [{"name": "llama3"}]}),
            "/props": ep(200, {"model_path": "/m.gguf"}),
            "/v1/models": ep(200, {"data": [
                {"id": "gpt-4", "owned_by": "openai"},
                {"id": "claude-3", "owned_by": "anthropic"},
            ]}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["score"], 100)  # capped at 100
        for name in ("WEAK_OLLAMA", "FAKE_LLAMACPP", "MULTI_PERSONA",
                     "IMPOSSIBLE_INVENTORY"):
            self.assertIn(name, out["score_reasons"])
        self.assertEqual(len(out["score_reasons"]),
                         len(set(out["score_reasons"])))  # no duplicates

    def test_no_flags_gives_empty_reasons(self):
        d = make_dossier({
            "/version": ep(200, {"version": "v0.6.6", "app_name": "vLLM"}),
            "/v1/models": ep(200, {"data": [{"id": "Qwen-7B"}]},
                             headers={"server": "vllm/0.6.6"}),
        })
        out = probe.analyze(d)
        self.assertEqual(out["score_reasons"], [])
        self.assertEqual(out["score"], 0)


if __name__ == "__main__":
    unittest.main()
