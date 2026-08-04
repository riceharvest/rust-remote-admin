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
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --- shared request log (fixture_name, method, path, status) ---
REQUEST_LOG = []
_LOCK = threading.Lock()


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


def start_all(port=0):
    """Start every fixture. Returns a list of Fixture, one per spec, in the
    canonical order (vllm, ollama, llamacpp, honeypot, authwall, gateway)."""
    return [Fixture(name, port=port) for name in FIXTURE_SPECS]


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
