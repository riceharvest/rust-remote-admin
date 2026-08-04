"""Auto-split from silicon_recon.py. Stdlib only."""
import os
from collections import deque

PROBE_PATHS = [
    "/",
    "/props", "/health",                    # llama.cpp
    "/version", "/v1/models",               # vLLM
    "/get_model_info", "/get_server_info",  # SGLang
    "/api/tags", "/api/version",            # Ollama
    "/api/v0/models",                       # LM Studio
    "/api/extra/version", "/api/v1/model",  # KoboldCpp (also text-generation-webui)
    "/v1/internal/model/info", "/info",     # TGI
    "/api/config",                          # Open WebUI
    "/v2/health/ready", "/v2/models",       # TensorRT-LLM / Triton
    "/readyz",                              # LocalAI
    "/api/models",                          # Xinference
    "/health/liveliness", "/models",        # LiteLLM
    "/v1/model_template", "/v1/profile",    # TabbyAPI
    "/run/predict",                         # text-generation-webui (Gradio)
]
# per-framework probe paths and default ports (union is used when several are selected)
FRAMEWORKS = {
    "vllm": {"paths": ["/", "/version", "/v1/models"], "ports": [8000, 8001]},
    "llamacpp": {"paths": ["/", "/props", "/health", "/v1/models"], "ports": [8080]},
    "sglang": {"paths": ["/", "/get_model_info", "/get_server_info", "/v1/models"], "ports": [30000]},
    "ollama": {"paths": ["/", "/api/tags", "/api/version", "/v1/models"], "ports": [11434]},
    "lmstudio": {"paths": ["/", "/api/v0/models", "/v1/models"], "ports": [1234]},
    "koboldcpp": {"paths": ["/", "/api/extra/version", "/api/v1/model"], "ports": [5001]},
    "tgwui": {"paths": ["/", "/api/v1/model", "/run/predict", "/v1/models"], "ports": [5000, 7860]},
    "tgi": {"paths": ["/", "/info", "/v1/internal/model/info"], "ports": [80, 3000]},
    "openwebui": {"paths": ["/", "/api/version", "/api/config"], "ports": [3000]},
    "aphrodite": {"paths": ["/", "/version", "/v1/models"], "ports": [2242]},
    "triton": {"paths": ["/", "/v2/health/ready", "/v2/models"], "ports": [8000]},
    "localai": {"paths": ["/", "/readyz", "/version", "/v1/models"], "ports": [8080]},
    "xinference": {"paths": ["/", "/api/models", "/v1/models"], "ports": [9997]},
    "litellm": {"paths": ["/", "/health/liveliness", "/models", "/v1/models"], "ports": [4000]},
    "tabbyapi": {"paths": ["/", "/v1/model_template", "/v1/profile", "/v1/models"], "ports": [5000]},
    "mlc": {"paths": ["/", "/v1/models"], "ports": [8080]},
}
DEFAULT_PORTS = sorted({p for f in FRAMEWORKS.values() for p in f["ports"]})
CONNECT_TIMEOUT = 1.0  # TCP preflight before any HTTP work
# suspicion scoring: verdict IMPOSTOR at >= 40
SCORE_WEIGHTS = {
    "FAKE_LLAMACPP": 40,
    "MULTI_PERSONA": 35,
    "IMPOSSIBLE_INVENTORY": 40,
    "WEAK_OLLAMA": 15,
    "SUSPICIOUS_INVENTORY": 10,
}
# signature combinations that are common legitimate stacks, not impostors
LEGIT_COMBOS = {
    frozenset({"openwebui", "ollama"}),
    frozenset({"openwebui", "tgi"}),
    frozenset({"openwebui", "vllm"}),
    frozenset({"openwebui", "litellm"}),
    frozenset({"litellm", "ollama"}),   # LiteLLM proxy in front of Ollama
}
# UI frontends that legitimately proxy to exactly one backend on the same port.
# A frontend + a single backend is a normal stack, not MULTI_PERSONA imposture.
FRONTENDS = {"openwebui"}
# Signature priority for primary product selection + display order. Specific
# backends beat the generic openai-compat/custom-gateway; frontends come last.
SIG_PRIORITY = [
    "vllm", "llamacpp", "sglang", "ollama", "lmstudio", "koboldcpp",
    "tgi", "triton", "aphrodite", "localai", "xinference", "litellm",
    "tabbyapi", "mlc", "tgwui", "custom-gateway", "openai-compat",
    "openwebui",
]
# AS-name keyword lists for net-type classification (Team Cymru enrichment)
DC_KEYWORDS = [
    "choopa", "vultr", "digitalocean", "hetzner", "ovh", "amazon", "aws",
    "google", "microsoft", "azure", "linode", "akamai", "contabo", "oracle",
    "alibaba", "tencent", "leaseweb", "scaleway", "kamatera", "ionos",
    "datacamp", "m247", "hostinger", "rackspace", "equinix", "psychz",
    "sharktech", "buyvm", "frantech", "cloudflare", "fastly", "gcore",
    "g-core", "servers.com", "hostwinds", "interserver", "netcup", "aruba",
]
RES_KEYWORDS = [
    "comcast", "verizon", "at&t", "charter", "spectrum", "cox", "optimum",
    "frontier", "centurylink", "lumen", "deutsche telekom", "vodafone",
    "orange", "british telecom", "sky ", "virgin media", "telefonica",
    "kpn", "ziggo", "telia", "telstra", "optus", "bell canada", "rogers",
    "shaw", "telus", "videotron", "iliad", "bouygues", "sfr", "telecom italia",
    "movistar", "claro", "vivo", "sk broadband", "korea telecom", "ntt",
    "kddi", "softbank", "com hem", "t-mobile", "swisscom", "proximus",
]
MAX_CIDR_HOSTS = 4096
MAX_TOTAL_TARGETS = 500_000
PROBE_TIMEOUT = 3.0
# inference verification: POST a tiny generate request to confirm real inference
VERIFY_TIMEOUT = 45.0        # cold-start model load can take 20-30s on small VPS
VERIFY_PROMPT = "Say hi"
VERIFY_MAX_TOKENS = 3
# ollama :cloud suffix → models proxied through ollama.com (require account auth)
CLOUD_SUFFIX = ":cloud"

# Real llama-server /props always carries these. A /props without any of them
# is an imitation (see 45.32.114.54:8000 incident).
REAL_LLAMACPP_MARKERS = [
    "default_generation_settings",
    "total_slots",
    "build_info",
    "chat_template",
]
# Proprietary vendors that cannot co-exist on one self-hosted box.
PROPRIETARY_VENDORS = {"openai", "anthropic", "google", "cohere", "xai", "moonshot"}

SCANS = {}  # scan_id -> threading.Event (cancel flag)
HISTORY = deque(maxlen=10)  # completed scan archives, newest first

# --- persistence + learned blocklist ---
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
STATE_DB = os.path.join(DATA_DIR, "state.db")
BLOCKLIST_FILE = os.path.join(DATA_DIR, "honeypot_blocklist.txt")
# DoD holds ~13 /8 blocks in US space — probing them is pure waste and attracts
# attention. One hardcoded default exclude list, removable in advanced options.
DEFAULT_DOD_EXCLUDES = [
    "6.0.0.0/8", "7.0.0.0/8", "11.0.0.0/8", "21.0.0.0/8", "22.0.0.0/8",
    "26.0.0.0/8", "28.0.0.0/8", "29.0.0.0/8", "30.0.0.0/8", "33.0.0.0/8",
    "55.0.0.0/8", "56.0.0.0/8", "214.0.0.0/8", "215.0.0.0/8",
]
# Lean port set: the ports where real deployments dominate.
LEAN_PORTS = {8080, 11434, 8000, 4000}   # 4000 = LiteLLM, a very common gateway
