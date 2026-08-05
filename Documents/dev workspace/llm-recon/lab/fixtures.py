"""lab/fixtures.py — fake LLM servers for the consent-free srecon test lab.

Each fixture is a stdlib ThreadingHTTPServer bound to **127.0.0.1 only**, on an
ephemeral (or configurable) port, speaking just enough of a framework's HTTP
surface for srecon's probe/verify pipeline to exercise it end-to-end.

Every request is logged to the shared REQUEST_LOG list (name, method, path,
status) so the lab harness can assert that the right endpoints were hit.

Zero packets leave the machine: nothing here binds a non-loopback address and
no fixture makes outbound connections.
"""

import json
import os
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --- shared request log (fixture_name, method, path, status) ---
REQUEST_LOG = []
_LOCK = threading.Lock()

# --- TLS cert handling (self-signed, generated at fixture start) ---
_CERT_CACHE = None
_CERT_CACHE_LOCK = threading.Lock()

def _get_or_create_self_signed_cert():
    """Return (certfile, keyfile) paths for a self-signed certificate.

    Generates a new cert via `openssl` on first call (cached thereafter).
    Requires `openssl` command in PATH — documented in lab/README.md.
    """
    global _CERT_CACHE
    with _CERT_CACHE_LOCK:
        if _CERT_CACHE is not None:
            return _CERT_CACHE

        # Create a temp dir for the cert pair; it persists for the process lifetime.
        cert_dir = tempfile.mkdtemp(prefix="srecon_lab_cert_")
        cert_path = os.path.join(cert_dir, "cert.pem")
        key_path = os.path.join(cert_dir, "key.pem")

        # Generate self-signed cert: CN=127.0.0.1, valid 365 days, no passphrase.
        # 2048-bit RSA is fine for a local test fixture.
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "365", "-nodes", "-subj", "/CN=127.0.0.1",
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            # Clean up on failure
            import shutil
            shutil.rmtree(cert_dir, ignore_errors=True)
            raise RuntimeError(
                "Failed to generate self-signed TLS cert. "
                "Ensure 'openssl' is installed and in PATH. "
                f"Original error: {e}"
            )

        _CERT_CACHE = (cert_path, key_path)
        return _CERT_CACHE


def log_request(name, method, path, status):
    with _LOCK:
        REQUEST_LOG.append((name, method, path, status))


def requests_for(name):
    """Requests logged for one fixture: [(name, method, path, status), ...]"""
    with _LOCK:
        return [r for r in REQUEST_LOG if r[0] == name]


def requests_for_path(name, path):
    return [r for r in requests_for(name) if r[2] == path]


def jresp(obj, status=200, extra_headers=None):
    """JSON response helper -> (status, headers, body_bytes)."""
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    return status, headers, json.dumps(obj).encode()


def _read_model(data):
    try:
        return json.loads(data or b"{}").get("model", "unknown")
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# route tables: (method, path) -> handler(post_body: bytes) -> (status, hdrs, body)
# ("*", path) and (method, "*") are wildcards; the plain (method, path) wins.
# ---------------------------------------------------------------------------

def _vllm_routes():
    return {
        ("GET", "/"): lambda _d: (200, {"Content-Type": "text/plain"},
                                  b"vllm serving multiple models"),
        ("GET", "/version"): lambda _d: jresp(
            {"version": "0.6.6.post1", "app_name": "vLLM"}),
        ("GET", "/v1/models"): lambda _d: jresp({
            "object": "list",
            "data": [{
                "id": "meta-llama/Llama-3.1-8B-Instruct",
                "object": "model", "created": 1700000000, "owned_by": "vllm",
                "root": "meta-llama/Llama-3.1-8B-Instruct", "parent": None,
                "permission": [{
                    "id": "modelperm-lab", "object": "model_permission",
                    "created": 1700000000, "allow_create_engine": False,
                    "allow_sampling": True, "allow_logprobs": True,
                    "allow_search": False, "allow_view": True,
                    "allow_fine_tuning": False, "organization": "*",
                    "group": None, "is_blocking": False}]}]}),
        ("POST", "/v1/completions"): lambda data: jresp({
            "id": "cmpl-lab-vllm", "object": "text_completion",
            "created": 1700000000, "model": _read_model(data),
            "choices": [{"index": 0, "text": "Hello from fake vLLM!",
                         "logprobs": None, "finish_reason": "length"}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 5,
                      "total_tokens": 8}}),
    }


def _ollama_routes():
    tags = {
        "models": [{
            "name": "llama3.2:1b", "model": "llama3.2:1b",
            "modified_at": "2024-11-01T00:00:00Z", "size": 1320000000,
            "digest": "aabbccddeeff00112233445566778899",
            "details": {"parent_model": "", "format": "gguf", "family": "llama",
                        "families": ["llama"], "parameter_size": "1.24B",
                        "quantization_level": "Q4_K_M"}}]}
    return {
        ("GET", "/"): lambda _d: (200, {"Content-Type": "text/plain"},
                                  b"Ollama is running"),
        ("GET", "/api/tags"): lambda _d: jresp(tags),
        ("GET", "/api/version"): lambda _d: jresp({"version": "0.5.0"}),
        ("GET", "/v1/models"): lambda _d: jresp({
            "object": "list",
            "data": [{"id": "llama3.2:1b", "object": "model",
                      "created": 1700000000, "owned_by": "library"}]}),
        ("POST", "/api/generate"): lambda data: jresp({
            "model": _read_model(data), "created_at": "2024-11-01T00:00:00Z",
            "response": "Hello from fake Ollama!", "done": True,
            "done_reason": "stop", "context": [1, 2, 3],
            "total_duration": 12000000, "load_duration": 0,
            "prompt_eval_count": 3, "eval_count": 5, "eval_duration": 1000000}),
    }


def _llamacpp_routes():
    return {
        ("GET", "/"): lambda _d: (200, {"Content-Type": "text/plain"},
                                  b"llama.cpp server"),
        ("GET", "/props"): lambda _d: jresp({
            "model_path": "/models/llama-3.2-1b-instruct.Q4_K_M.gguf",
            "model": "llama-3.2-1b-instruct",
            "default_generation_settings": {
                "n_ctx": 4096, "n_predict": -1, "seed": 42, "temperature": 0.8,
                "top_k": 40, "top_p": 0.95, "repeat_penalty": 1.1,
                "n_batch": 2048, "stream": False},
            "total_slots": 1, "chat_template": "llama3",
            "build_info": "b1234 (abc1234)", "n_ctx": 4096, "n_parallel": 1,
            "n_batch": 2048}),
        ("GET", "/health"): lambda _d: jresp({"status": "ok"}),
        ("GET", "/v1/models"): lambda _d: jresp({
            "object": "list",
            "data": [{"id": "llama-3.2-1b", "object": "model",
                      "created": 1700000000, "owned_by": "llamacpp"}]}),
        ("POST", "/completion"): lambda data: jresp({
            "content": "Hello from fake llama.cpp!", "stop": True,
            "model": "llama-3.2-1b-instruct", "tokens_predicted": 5,
            "tokens_evaluated": 3, "truncated": False}),
    }


def _honeypot_routes():
    """IMPOSTOR: looks like Ollama (tags + banner) but POST /api/generate
    returns done=true with an EMPTY canned response — the classic stub."""
    tags = {
        "models": [{
            "name": "gpt-4o-mini", "model": "gpt-4o-mini",
            "modified_at": "2024-11-01T00:00:00Z", "size": 1,
            "digest": "deadbeefdeadbeefdeadbeefdeadbeef", "details": {}}]}
    return {
        ("GET", "/"): lambda _d: (200, {"Content-Type": "text/plain"},
                                  b"Ollama is running"),
        ("GET", "/api/tags"): lambda _d: jresp(tags),
        ("GET", "/api/version"): lambda _d: jresp({"version": "0.4.7"}),
        # canned empty completion: done=true, response="" — honeypot signature
        ("POST", "/api/generate"): lambda data: jresp({
            "model": _read_model(data), "created_at": "2024-11-01T00:00:00Z",
            "response": "", "done": True, "done_reason": "stop"}),
    }


def _authwall_routes():
    """Auth-walled server: 401 + sign-in HTML on EVERY path (GET and POST)."""
    return {}  # only the default route is used


_AUTHWALL_HTML = (
    b"<html><head><title>Sign in required</title></head><body>"
    b"<h1>401 Unauthorized</h1><p>Authentication required. "
    b'<a href="https://example.com/signin?signin_url=https%3A%2F%2F127.0.0.1%2F">'
    b"Sign in</a></p></body></html>"
)


def _gateway_routes():
    """Bare OpenAI-compatible gateway: /v1/models envelope ONLY, generic
    Server header. Must NOT classify as vLLM."""
    return {
        ("GET", "/v1/models"): lambda _d: jresp({
            "object": "list",
            "data": [{"id": "gpt-3.5-turbo", "object": "model",
                      "created": 1700000000, "owned_by": "acme-corp"}]},
            extra_headers={"Server": "nginx"}),
        ("POST", "/v1/completions"): lambda data: jresp({
            "id": "cmpl-lab-gw", "object": "text_completion",
            "created": 1700000000, "model": _read_model(data),
            "choices": [{"index": 0, "text": "Hello from the gateway!",
                         "logprobs": None, "finish_reason": "length"}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 6,
                      "total_tokens": 9}},
            extra_headers={"Server": "nginx"}),
    }


# --- Wave 2 framework fixtures ------------------------------------------------

def _sglang_routes():
    """SGLang: /get_model_info with model_path, /get_server_info, /version,
    POST /generate (OpenAI-compatible)."""
    return {
        ("GET", "/"): lambda _d: (200, {"Content-Type": "text/plain"},
                                  b"SGLang"),
        ("GET", "/version"): lambda _d: jresp(
            {"version": "0.3.0", "app_name": "SGLang"}),
        ("GET", "/get_model_info"): lambda _d: jresp(
            {"model_path": "/models/meta-llama/Llama-3.1-8B-Instruct",
             "tokenizer_path": "/models/meta-llama/Llama-3.1-8B-Instruct"}),
        ("GET", "/get_server_info"): lambda _d: jresp(
            {"version": "0.3.0"}),
        ("GET", "/v1/models"): lambda _d: jresp({
            "object": "list",
            "data": [{
                "id": "meta-llama/Llama-3.1-8B-Instruct",
                "object": "model", "created": 1700000000,
                "owned_by": "sglang",
                "root": "meta-llama/Llama-3.1-8B-Instruct", "parent": None,
                "permission": [{"id": "modelperm-lab", "object": "model_permission",
                    "created": 1700000000, "allow_create_engine": False,
                    "allow_sampling": True, "allow_logprobs": True,
                    "allow_search": False, "allow_view": True,
                    "allow_fine_tuning": False, "organization": "*",
                    "group": None, "is_blocking": False}]}]}),
        ("POST", "/generate"): lambda data: jresp({
            "id": "cmpl-lab-sglang", "object": "text_completion",
            "created": 1700000000, "model": _read_model(data),
            "choices": [{"index": 0, "text": "Hello from fake SGLang!",
                         "logprobs": None, "finish_reason": "length"}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 5,
                      "total_tokens": 8}}),
        ("POST", "/v1/completions"): lambda data: jresp({
            "id": "cmpl-lab-sglang-v1", "object": "text_completion",
            "created": 1700000000, "model": _read_model(data),
            "choices": [{"index": 0, "text": "Hello from fake SGLang!",
                         "logprobs": None, "finish_reason": "length"}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 5,
                      "total_tokens": 8}}),
    }


def _tgi_routes():
    """TGI: /info with version+model_id, / (router banner), POST /generate."""
    return {
        ("GET", "/"): lambda _d: (200, {"Content-Type": "text/plain"},
                                  b"text-generation-inference router"),
        ("GET", "/info"): lambda _d: jresp({
            "model_id": "meta-llama/Llama-3.1-8B-Instruct",
            "version": "2.0.0",
            "sha": "lab-build",
            "docker_label": "ghcr.io/huggingface/text-generation-inference:2.0.0"}),
        ("GET", "/v1/internal/model/info"): lambda _d: jresp({
            "model_name": "meta-llama/Llama-3.1-8B-Instruct",
            "version": "2.0.0"}),
        ("POST", "/generate"): lambda data: jresp([
            {"generated_text": "Hello from fake TGI!",
             "details": {"finish_reason": "length", "generated_tokens": 5}}]),
    }


def _aphrodite_routes():
    """Aphrodite Engine: root JSON app_name Aphrodite-Engine, /version, /v1/models."""
    return {
        ("GET", "/"): lambda _d: jresp({
            "app_name": "Aphrodite-Engine", "version": "1.0.0"}),
        ("GET", "/version"): lambda _d: jresp({
            "version": "1.0.0", "app_name": "Aphrodite-Engine"}),
        ("GET", "/v1/models"): lambda _d: jresp({
            "object": "list",
            "data": [{
                "id": "meta-llama/Llama-3.1-8B-Instruct",
                "object": "model", "created": 1700000000,
                "owned_by": "aphrodite",
                "root": "meta-llama/Llama-3.1-8B-Instruct", "parent": None,
                "permission": [{"id": "modelperm-lab", "object": "model_permission",
                    "created": 1700000000, "allow_create_engine": False,
                    "allow_sampling": True, "allow_logprobs": True,
                    "allow_search": False, "allow_view": True,
                    "allow_fine_tuning": False, "organization": "*",
                    "group": None, "is_blocking": False}]}]}),
        ("POST", "/v1/completions"): lambda data: jresp({
            "id": "cmpl-lab-aph", "object": "text_completion",
            "created": 1700000000, "model": _read_model(data),
            "choices": [{"index": 0, "text": "Hello from fake Aphrodite!",
                         "logprobs": None, "finish_reason": "length"}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 5,
                      "total_tokens": 8}}),
    }


def _litellm_routes():
    """LiteLLM proxy: /health/liveliness -> LIVE, /models list, /v1/models
    with mixed owned_by (openai+anthropic), Server: litellm header.
    This is a LEGIT proxy inventory — must NOT flip IMPOSTOR."""
    server_hdr = {"Server": "litellm"}
    return {
        ("GET", "/"): lambda _d: jresp({"app": "litellm", "version": "1.40.0"}),
        ("GET", "/health/liveliness"): lambda _d: (
            200, {"Content-Type": "text/plain"}, b"LIVE"),
        ("GET", "/models"): lambda _d: jresp([
            "gpt-4o", "gpt-4o-mini", "claude-3-5-sonnet-20241022", "claude-3-haiku-20240307"]),
        ("GET", "/v1/models"): lambda _d: jresp({
            "object": "list",
            "data": [
                {"id": "gpt-4o", "object": "model", "created": 1700000000,
                 "owned_by": "openai"},
                {"id": "gpt-4o-mini", "object": "model", "created": 1700000000,
                 "owned_by": "openai"},
                {"id": "claude-3-5-sonnet-20241022", "object": "model",
                 "created": 1700000000, "owned_by": "anthropic"},
                {"id": "claude-3-haiku-20240307", "object": "model",
                 "created": 1700000000, "owned_by": "anthropic"},
            ]}, extra_headers=server_hdr),
        ("POST", "/v1/completions"): lambda data: jresp({
            "id": "cmpl-lab-litellm", "object": "text_completion",
            "created": 1700000000, "model": _read_model(data),
            "choices": [{"index": 0, "text": "Hello from fake LiteLLM!",
                         "logprobs": None, "finish_reason": "length"}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 6,
                      "total_tokens": 9}}, extra_headers=server_hdr),
    }


def _triton_routes():
    """TensorRT-LLM / Triton: /v2/health/ready 200, /v2/models list,
    NO /v1 paths at all."""
    return {
        ("GET", "/"): lambda _d: (200, {"Content-Type": "text/plain"},
                                  b"NVIDIA Triton Inference Server"),
        ("GET", "/v2/health/ready"): lambda _d: jresp({"ready": True}),
        ("GET", "/v2/models"): lambda _d: jresp({
            "models": [
                {"name": "llama-3.1-8b", "version": "1"},
                {"name": "llama-3.1-70b", "version": "1"},
            ]}),
        # Explicit 404 for /v1/* to confirm they don't exist
        ("*", "/v1/models"): lambda _d: (404, {"Content-Type": "application/json"},
                                          b'{"error":"not found"}'),
        ("*", "/v1/completions"): lambda _d: (404, {"Content-Type": "application/json"},
                                               b'{"error":"not found"}'),
    }


# name -> (routes_builder, default_route, server_header)
FIXTURE_SPECS = {
    "vllm":     (_vllm_routes, (404, {"Content-Type": "application/json"},
                                b'{"error":"not found"}'), "Server: vllm/0.6.6"),
    "ollama":   (_ollama_routes, (404, {"Content-Type": "application/json"},
                                  b'{"error":"not found"}'), None),
    "llamacpp": (_llamacpp_routes, (404, {"Content-Type": "application/json"},
                                    b'{"error":"not found"}'), None),
    "honeypot": (_honeypot_routes, (404, {"Content-Type": "application/json"},
                                    b'{"error":"not found"}'), None),
    "authwall": (_authwall_routes,
                 (401, {"Content-Type": "text/html; charset=utf-8"},
                  _AUTHWALL_HTML), None),
    "gateway":  (_gateway_routes, (404, {"Content-Type": "application/json"},
                                   b'{"error":"not found"}'),
                 "Server: nginx"),
    # Wave 2
    "sglang":   (_sglang_routes, (404, {"Content-Type": "application/json"},
                                  b'{"error":"not found"}'), "Server: sglang/0.3.0"),
    "tgi":      (_tgi_routes, (404, {"Content-Type": "application/json"},
                                 b'{"error":"not found"}'), "Server: tgi/2.0.0"),
    "aphrodite": (_aphrodite_routes, (404, {"Content-Type": "application/json"},
                                      b'{"error":"not found"}'), None),
    "litellm":  (_litellm_routes, (404, {"Content-Type": "application/json"},
                                     b'{"error":"not found"}'), None),  # Server header in routes
    "triton":   (_triton_routes, (404, {"Content-Type": "application/json"},
                                   b'{"error":"not found"}'), "Server: triton/24.08"),
    # TLS variant: same vLLM surface over HTTPS with self-signed cert
    "https-vllm": (_vllm_routes, (404, {"Content-Type": "application/json"},
                                    b'{"error":"not found"}'), "Server: vllm/0.6.6"),
}


# ---------------------------------------------------------------------------
# server plumbing
# ---------------------------------------------------------------------------

class _LabServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self, method):
        srv = self.server
        path = self.path.split("?", 1)[0]
        routes = srv.routes
        fn = (routes.get((method, path))
              or routes.get(("*", path))
              or routes.get((method, "*")))
        if fn is None:
            status, headers, body = srv.default_route
        else:
            try:
                clen = int(self.headers.get("Content-Length") or 0)
                data = self.rfile.read(clen) if clen else b""
                status, headers, body = fn(data)
            except Exception:
                status, headers, body = (
                    500, {"Content-Type": "application/json"},
                    b'{"error":"fixture internal error"}')
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        log_request(srv.fixture_name, method, path, status)

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_HEAD(self):
        self._handle("HEAD")

    def log_message(self, *args):  # silence access-log noise
        pass


class Fixture:
    """A running fake LLM server."""

    def __init__(self, name, port=0):
        routes_builder, default_route, banner = FIXTURE_SPECS[name]
        self.name = name
        self.routes = routes_builder()
        self.server = _LabServer(("127.0.0.1", port), _Handler)
        self.server.fixture_name = name
        self.server.routes = self.routes
        self.server.default_route = default_route
        self.port = self.server.server_address[1]
        self.target = f"127.0.0.1:{self.port}"
        self._thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        try:
            self.server.shutdown()
        except Exception:
            pass
        try:
            self.server.server_close()
        except Exception:
            pass

    def __repr__(self):
        return f"<Fixture {self.name} {self.target}>"


class HTTPSFixture:
    """A running fake LLM server over HTTPS (TLS with self-signed cert).

    Serves the same routes as the HTTP variant but on a TLS-wrapped socket.
    Binds 127.0.0.1 only. Uses a high port (default 0 = ephemeral) since
    port 443 requires root.
    """

    def __init__(self, name, routes_builder, default_route, banner, port=0):
        self.name = name
        self.routes = routes_builder()
        cert_path, key_path = _get_or_create_self_signed_cert()

        # Create SSL context for server-side TLS
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

        # Create the server socket, then wrap it with SSL
        self.server = _LabServer(("127.0.0.1", port), _Handler)
        self.server.fixture_name = name
        self.server.routes = self.routes
        self.server.default_route = default_route
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.target = f"127.0.0.1:{self.port}"
        self._thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        try:
            self.server.shutdown()
        except Exception:
            pass
        try:
            self.server.server_close()
        except Exception:
            pass

    def __repr__(self):
        return f"<HTTPSFixture {self.name} {self.target}>"


def start_all(port=0):
    """Start every fixture. Returns a list of Fixture, one per spec, in the
    canonical order (vllm, ollama, llamacpp, honeypot, authwall, gateway,
    sglang, tgi, aphrodite, litellm, triton, https-vllm)."""
    fixtures = []
    for name in FIXTURE_SPECS:
        if name == "https-vllm":
            routes_builder, default_route, banner = FIXTURE_SPECS[name]
            fixtures.append(HTTPSFixture(name, routes_builder, default_route, banner, port=port))
        else:
            fixtures.append(Fixture(name, port=port))
    return fixtures


def stop_all(fixtures):
    for f in fixtures:
        f.stop()


if __name__ == "__main__":
    fx = start_all()
    try:
        for f in fx:
            print(f)
    finally:
        stop_all(fx)
