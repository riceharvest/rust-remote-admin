"""Cloud provider target packs — curated ASN bundles.

Single source of truth shared by the web UI and the CLI. The web page
embeds this dict as a JS constant at render time (see web.PAGE), so the
two can never drift apart.
"""

# Each pack maps to a list of BGP autonomous system numbers whose IPv4
# prefixes are expanded into the target list via bgpview_prefixes().
PACKS = {
    "coreweave": {
        "label": "COREWEAVE",
        "asns": ["33425"],
        "hint": "GPU-focused cloud. prime vLLM/SGLang host territory.",
    },
    "lambda": {
        "label": "LAMBDA",
        "asns": ["398090"],
        "hint": "Lambda Labs GPU cloud. inference clusters + on-demand boxes.",
    },
    "vultr": {
        "label": "VULTR",
        "asns": ["20473"],
        "hint": "cheap VPS fleet. lots of self-hosted llama.cpp/ollama.",
    },
    "hetzner": {
        "label": "HETZNER",
        "asns": ["24940", "47583"],
        "hint": "EU dedicated servers. budget GPU rentals proliferating.",
    },
    "gcp": {
        "label": "GCP",
        "asns": ["15169", "396982"],
        "hint": "Google Cloud. Vertex + GKE inference endpoints. huge range.",
    },
    "azure": {
        "label": "AZURE",
        "asns": ["8075"],
        "hint": "Microsoft Azure. Azure ML / OpenAI service endpoints.",
    },
    "aws": {
        "label": "AWS",
        "asns": ["16509", "14618"],
        "hint": "Amazon Web Services. SageMaker / Bedrock + EC2 inference.",
    },
    "allcloud": {
        "label": "ALL CLOUDS",
        "asns": ["33425", "398090", "20473", "24940", "47583",
                 "15169", "396982", "8075", "16509", "14618"],
        "hint": "every cloud provider at once. very large. pair with FAST SWEEP + dedup.",
    },
}
