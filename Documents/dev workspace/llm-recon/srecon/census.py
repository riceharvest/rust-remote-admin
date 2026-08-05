"""Fetch public LLM-serving census counts from Shodan's free count API.

This is DATA FETCHING from a search engine's already-collected index — it
sends no probe packets to any target host. The free Shodan plan allows
`host/count` queries (totals only); `host/search` (individual IPs) requires
a paid membership, so this module intentionally never returns raw hosts.

Usage:
    python3 -m srecon.census [--out site/data/shodan_census.json]
"""
import json
import os
import sys
import time
import urllib.parse
import urllib.request

# framework -> Shodan search query (framework names = config.FRAMEWORKS keys)
QUERIES = {
    "vllm": "vllm",
    "ollama": "ollama",
    "llamacpp": '"llama.cpp"',
    "sglang": "sglang",
    "tgi": "text-generation-inference",
    "lmstudio": '"LM Studio"',
    "koboldcpp": "koboldcpp",
    "openwebui": '"Open WebUI"',
    "aphrodite": "aphrodite-engine",
    "litellm": "litellm",
    "xinference": "xinference",
    "localai": "localai",
    "tabbyapi": "tabbyapi",
    "triton": "triton",
}

API = "https://api.shodan.io/shodan/host/count?key={key}&query={query}"


def fetch_counts(api_key, queries=None, delay=1.1):
    """Return {framework: total} from Shodan host/count (free tier).

    ``delay`` spaces requests to stay polite to the free tier. A query that
    errors (network, plan limits) yields None so the caller can tell a
    missing datum from a zero.
    """
    out = {}
    for fw, q in (queries or QUERIES).items():
        url = API.format(key=api_key, query=urllib.parse.quote(q))
        try:
            with urllib.request.urlopen(url, timeout=15) as r:
                out[fw] = json.loads(r.read().decode("utf-8", "replace")).get("total", 0)
        except Exception:
            out[fw] = None
        if delay:
            time.sleep(delay)
    return out


def resolve_key(env_var="SHODAN_KEY", secrets_path=None):
    """Fail-closed key resolution: env var, then a mode-600 secrets file."""
    if os.environ.get(env_var):
        return os.environ[env_var]
    if secrets_path and os.path.exists(secrets_path):
        for line in open(secrets_path, encoding="utf-8"):
            if line.startswith(env_var + "="):
                return line.strip().split("=", 1)[1]
    return None


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(description="Fetch LLM-server census counts from Shodan (free count API)")
    p.add_argument("--out", default="site/data/shodan_census.json")
    p.add_argument("--key", default=None, help="Shodan API key (default: $SHODAN_KEY or .secrets/intel.env)")
    p.add_argument("--delay", type=float, default=1.1)
    args = p.parse_args(argv)

    here = os.path.dirname(os.path.abspath(__file__))
    secrets = os.path.join(os.path.dirname(here), ".secrets", "intel.env")
    key = args.key or resolve_key(secrets_path=secrets)
    if not key:
        print("no Shodan API key found (set SHODAN_KEY or create .secrets/intel.env)", file=sys.stderr)
        return 2

    print("fetching Shodan counts...", file=sys.stderr)
    counts = fetch_counts(key, delay=args.delay)
    payload = {
        "source": "shodan host/count (free)",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "counts": counts,
        "note": "index-wide totals from Shodan's public index; no raw hosts are ever fetched or stored",
    }
    out = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=1)
    print(f"wrote {out}", file=sys.stderr)
    for fw, n in sorted(counts.items(), key=lambda kv: -(kv[1] or 0)):
        print(f"  {fw:12s} {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
