#!/usr/bin/env python3
"""Backward-compatibility launcher.

The codebase now lives in the `srecon` package. This script preserves the
original single-file entry point:

    python3 silicon_recon.py [--port 7777] [--bind 127.0.0.1]

For the full agent-friendly interface use:

    python3 -m srecon --help
"""
import argparse
import sys

from srecon.serve import serve


def main():
    ap = argparse.ArgumentParser(description="Silicon Recon web console (compat launcher)")
    ap.add_argument("--port", type=int, default=7777)
    ap.add_argument("--bind", default="127.0.0.1")
    args = ap.parse_args()
    serve(host=args.bind, port=args.port)


if __name__ == "__main__":
    main()
