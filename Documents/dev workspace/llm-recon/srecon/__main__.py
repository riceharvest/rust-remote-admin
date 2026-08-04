"""Silicon Recon CLI — agent-friendly interface for LLM endpoint discovery.

Usage:
    python3 -m srecon scan --pack hetzner --framework vllm --json
    python3 -m srecon scan --targets 1.2.3.4:8000,5.6.7.8:11434
    python3 -m srecon report --input results.json --format html -o report.html
    python3 -m srecon report --scan-id 5 --format csv
    python3 -m srecon prefixes --asn 24940
    python3 -m srecon cidrs --cc DE
    python3 -m srecon packs
    python3 -m srecon frameworks
    python3 -m srecon serve --port 7777

All output is machine-parseable JSON/NDJSON by default.
"""
import argparse
import json
import sys
import time

from .config import FRAMEWORKS, DEFAULT_PORTS, PROBE_TIMEOUT
from .engine import scan_events
from .packs import PACKS
from .serve import raise_fd_limit
from .targets import bgpview_prefixes, country_cidrs


def _eprint(msg):
    print(msg, file=sys.stderr)


def cmd_frameworks(args):
    """List known LLM serving frameworks and their ports."""
    out = {}
    for name, meta in sorted(FRAMEWORKS.items()):
        out[name] = {
            "ports": meta.get("ports", []),
            "paths": meta.get("paths", []),
        }
    print(json.dumps(out, indent=2))


def cmd_packs(args):
    """List available cloud provider target packs."""
    out = {}
    for name, meta in PACKS.items():
        out[name] = {
            "label": meta["label"],
            "asns": meta["asns"],
            "hint": meta.get("hint", ""),
        }
    print(json.dumps(out, indent=2))


def cmd_prefixes(args):
    """Resolve one or more ASNs to announced IPv4 prefixes via RIPEstat."""
    asns = args.asn
    limit = args.limit
    results = []
    for asn in asns:
        asn = asn.strip().upper().removeprefix("AS")
        if not asn.isdigit():
            _eprint(f"error: invalid ASN '{asn}'")
            continue
        try:
            name, prefixes, total = bgpview_prefixes(asn, limit)
            results.append({
                "asn": asn,
                "name": name,
                "prefixes": prefixes,
                "total": total,
                "truncated": total > limit,
            })
        except Exception as e:
            results.append({"asn": asn, "error": str(e)})
    print(json.dumps(results, indent=2))


def cmd_cidrs(args):
    """Resolve a country code to delegated IPv4 CIDR ranges via RIR stats."""
    cc = args.cc.strip()[:2].upper()
    limit = args.limit
    try:
        cidrs, total = country_cidrs(cc, limit)
        out = {
            "cc": cc,
            "cidrs": cidrs,
            "total_ranges": total,
            "truncated": total > limit,
        }
    except Exception as e:
        out = {"cc": cc, "error": str(e)}
    print(json.dumps(out, indent=2))


def cmd_serve(args):
    """Start the web console."""
    from .serve import serve
    serve(host=args.bind, port=args.port)


def cmd_report(args):
    """Render scan results as an offline report (HTML / Markdown / CSV)."""
    from .report import load_json_results, load_db_results, render_report

    if args.input and args.scan_id is not None:
        _eprint("error: --input and --scan-id are mutually exclusive")
        sys.exit(1)

    if args.input:
        try:
            results, meta = load_json_results(args.input)
        except (OSError, ValueError) as e:
            _eprint(f"error: cannot load results: {e}")
            sys.exit(1)
        meta["source"] = "scan output"
        meta["input"] = args.input
        src = args.input
    else:
        try:
            results, meta = load_db_results(args.scan_id)
        except (OSError, ValueError, FileNotFoundError) as e:
            _eprint(f"error: cannot load history: {e}")
            sys.exit(1)
        src = "sqlite history"
        if args.scan_id is not None:
            src += f" row {args.scan_id}"

    try:
        out = render_report(results, args.format, meta)
    except ValueError as e:
        _eprint(f"error: {e}")
        sys.exit(1)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
            _eprint(f"[report] {args.format} report ({len(results)} results from {src}) "
                    f"written to {args.output}")
        except OSError as e:
            _eprint(f"error: cannot write output: {e}")
            sys.exit(1)
    else:
        sys.stdout.write(out)


def cmd_scan(args):
    """Run a scan and stream results as NDJSON (or print a summary table)."""
    # --- resolve targets ---
    lines = []
    if args.targets:
        for chunk in args.targets.split(","):
            chunk = chunk.strip()
            if chunk:
                lines.append(chunk)
    if args.pack:
        for pname in args.pack.split(","):
            pname = pname.strip().lower()
            pk = PACKS.get(pname)
            if not pk:
                _eprint(f"error: unknown pack '{pname}' (available: {', '.join(PACKS)})")
                sys.exit(1)
            _eprint(f"[scan] resolving pack '{pk['label']}' ({len(pk['asns'])} ASNs)...")
            for asn in pk["asns"]:
                try:
                    _name, prefixes, _total = bgpview_prefixes(asn, args.prefix_limit)
                    lines.extend(prefixes)
                    _eprint(f"  AS{asn}: {len(prefixes)} prefixes")
                except Exception as e:
                    _eprint(f"  AS{asn}: fetch failed ({e})")
    if args.cidrs:
        for chunk in args.cidrs.split(","):
            chunk = chunk.strip()
            if chunk:
                lines.append(chunk)
    if args.targets_file:
        try:
            with open(args.targets_file) as f:
                for raw in f:
                    raw = raw.strip()
                    if raw and not raw.startswith("#"):
                        lines.append(raw)
        except OSError as e:
            _eprint(f"error: cannot read targets file: {e}")
            sys.exit(1)

    if not lines:
        _eprint("error: no targets specified. Use --targets, --pack, --cidrs, or --targets-file.")
        sys.exit(1)

    # --- resolve frameworks ---
    frameworks = None
    if args.framework:
        frameworks = [f.strip().lower() for f in args.framework.split(",") if f.strip()]
        unknown = [f for f in frameworks if f not in FRAMEWORKS]
        if unknown:
            _eprint(f"error: unknown framework(s): {', '.join(unknown)}")
            _eprint(f"available: {', '.join(sorted(FRAMEWORKS))}")
            sys.exit(1)

    # --- raise fd limit ---
    soft = raise_fd_limit()
    if soft:
        _eprint(f"[scan] fd limit: {soft} (worker cap: {(soft-256)//4})")

    # --- run scan ---
    cancel = None
    results = []
    t_start = time.time()
    total = 0

    for ev in scan_events(
        lines,
        workers=args.workers,
        timeout=args.timeout,
        cancel=cancel,
        frameworks=frameworks,
        excludes=None,
        enrich=args.enrich,
        fast=args.fast,
        lean_ports=args.lean_ports,
        exclude_dod=not args.include_dod,
        dedup=args.dedup,
        asn_prefilter=args.asn_prefilter,
        fanout=args.fanout,
        progressive=args.progressive,
        banner_prefilter=args.banner_prefilter,
        adaptive_timeout=args.adaptive_timeout,
        content_dedup=args.content_dedup,
        diff_mode=args.diff_mode,
        ptr_seed=args.ptr_seed,
        ct_search_seed=args.ct_seed,
        shodan_seed=args.shodan_seed,
        sweep_all_ports=args.sweep_all_ports,
        verify=args.verify,
    ):
        etype = ev["type"]
        if etype == "start":
            total = ev["total"]
            if not args.quiet:
                _eprint(f"[scan] probing {total} targets on ports {ev.get('ports', [])}")
            if args.ndjson:
                print(json.dumps(ev))
        elif etype == "result":
            d = ev["data"]
            results.append(d)
            if args.ndjson:
                print(json.dumps({"type": "result", "data": d}))
        elif etype == "enrich":
            # apply enrichment to matching result
            for r in results:
                if r["target"] == ev["target"]:
                    r["asn"] = ev.get("asn")
                    r["as_name"] = ev.get("as_name")
                    r["bgp_prefix"] = ev.get("bgp_prefix")
                    r["net_type"] = ev.get("net_type")
                    break
            if args.ndjson:
                print(json.dumps(ev))
        elif etype == "ptr":
            for r in results:
                if r["target"] == ev["target"]:
                    r["ptr"] = ev.get("ptr")
                    break
            if args.ndjson:
                print(json.dumps(ev))
        elif etype in ("log",):
            if not args.quiet and not args.ndjson:
                _eprint(f"  {ev.get('message', '')}")
            elif args.ndjson:
                print(json.dumps(ev))
        elif etype in ("done", "stopped"):
            if args.ndjson:
                print(json.dumps(ev))
        # probes: skip in CLI output (too noisy) unless ndjson

    elapsed = round(time.time() - t_start, 1)

    # --- output ---
    if args.ndjson:
        # final summary line
        print(json.dumps({
            "type": "summary",
            "total_results": len(results),
            "elapsed_s": elapsed,
        }))
        return

    # filter for display
    display = results
    if args.genuine_only:
        display = [r for r in results if r.get("verdict") == "GENUINE"]
    elif args.live_only:
        display = [r for r in results if r.get("verdict") not in ("DARK", "ERROR")]

    # --- write output file ---
    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump({"results": display, "elapsed_s": elapsed, "total_probed": total}, f, indent=2)
            _eprint(f"[scan] results written to {args.output}")
        except OSError as e:
            _eprint(f"error: cannot write output: {e}")
            sys.exit(1)

    # --- print summary table ---
    genuine = sum(1 for r in results if r.get("verdict") == "GENUINE")
    impostor = sum(1 for r in results if r.get("verdict") == "IMPOSTOR")
    unknown = sum(1 for r in results if r.get("verdict") == "UNKNOWN")
    dark = sum(1 for r in results if r.get("verdict") == "DARK")
    error = sum(1 for r in results if r.get("verdict") == "ERROR")

    _eprint(f"\n{'='*70}")
    _eprint(f"SCAN COMPLETE — {len(results)} results in {elapsed}s ({total} targets probed)")
    _eprint(f"  GENUINE:   {genuine}")
    _eprint(f"  IMPOSTOR:  {impostor}")
    _eprint(f"  UNKNOWN:   {unknown}")
    _eprint(f"  DARK:      {dark}")
    _eprint(f"  ERROR:     {error}")
    _eprint(f"{'='*70}")

    if display:
        # table header
        hdr = f"{'TARGET':<24} {'VERDICT':<10} {'PRODUCT':<18} {'MODEL':<30} {'VER':<10} {'SCORE':>5} {'MS':>5}"
        print(hdr)
        print("-" * len(hdr))
        for r in sorted(display, key=lambda x: (x.get("verdict") != "GENUINE", -(x.get("score") or 0))):
            model = (r.get("model") or "")[:30]
            ver = (r.get("version") or "")[:10]
            print(f"{r['target']:<24} {r.get('verdict','?'):<10} "
                  f"{(r.get('product') or '?'):<18} {model:<30} {ver:<10} "
                  f"{r.get('score',0):>5} {r.get('latency_ms','?'):>5}")


def main():
    ap = argparse.ArgumentParser(
        prog="srecon",
        description="Silicon Recon — LLM inference endpoint discovery and classification.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = ap.add_subparsers(dest="command", help="sub-command help")

    # --- scan ---
    p_scan = sub.add_parser("scan", help="Run a scan against targets")
    tgt = p_scan.add_argument_group("target selection (combine freely)")
    tgt.add_argument("--targets", help="Comma-separated host:port or CIDR list")
    tgt.add_argument("--targets-file", help="File with one target/CIDR per line")
    tgt.add_argument("--pack", help="Cloud provider pack(s): comma-separated names (see 'packs')")
    tgt.add_argument("--cidrs", help="Comma-separated CIDR ranges")
    tgt.add_argument("--prefix-limit", type=int, default=5000,
                     help="Max prefixes per ASN when resolving packs (default: 5000)")

    fw = p_scan.add_argument_group("scan options")
    fw.add_argument("--framework", "-f", help="Framework filter: comma-separated (see 'frameworks')")
    fw.add_argument("--workers", "-w", type=int, default=1000, help="Concurrent workers (default: 1000)")
    fw.add_argument("--timeout", type=float, default=PROBE_TIMEOUT, help=f"Per-probe timeout seconds (default: {PROBE_TIMEOUT})")
    fw.add_argument("--sweep-all-ports", action="store_true", help="Probe all 13 known LLM ports regardless of framework filter")
    fw.add_argument("--lean-ports", action="store_true", help="Top port per framework only")
    fw.add_argument("--no-enrich", dest="enrich", action="store_false", default=True, help="Skip ASN enrichment")
    fw.add_argument("--no-fast", dest="fast", action="store_false", default=True, help="Disable fast mode (probe all paths)")
    fw.add_argument("--include-dod", action="store_true", help="Include DoD ranges (excluded by default)")
    fw.add_argument("--dedup", action="store_true", help="Dedup against scan history")
    fw.add_argument("--asn-prefilter", action="store_true", help="Skip residential ASN ranges")
    fw.add_argument("--fanout", action="store_true", help="Fan-out adjacent ports on live hits")
    fw.add_argument("--progressive", action="store_true", help="TCP pre-sweep before deep probe")
    fw.add_argument("--banner-prefilter", action="store_true", help="Skip non-HTTP banners")
    fw.add_argument("--adaptive-timeout", action="store_true", help="Shrink timeout to 3x P95")
    fw.add_argument("--content-dedup", action="store_true", help="Cluster identical response hashes")
    fw.add_argument("--diff-mode", action="store_true", help="Only report changed targets")
    fw.add_argument("--ptr-seed", action="store_true", help="Seed targets via PTR lookups")
    fw.add_argument("--ct-seed", action="store_true", help="Seed via Certificate Transparency")
    fw.add_argument("--shodan-seed", action="store_true", help="Seed via Shodan")
    fw.add_argument("--verify", action="store_true", help="Deep verify: POST a tiny generate request to confirm real inference (not stub/auth)")

    out = p_scan.add_argument_group("output")
    out.add_argument("--json", dest="ndjson", action="store_true", help="Stream results as NDJSON (machine-readable)")
    out.add_argument("--output", "-o", help="Write JSON results to file")
    out.add_argument("--genuine-only", action="store_true", help="Only show GENUINE results in table")
    out.add_argument("--live-only", action="store_true", help="Only show live (non-DARK) results in table")
    out.add_argument("--quiet", "-q", action="store_true", help="Suppress progress messages")

    p_scan.set_defaults(func=cmd_scan)

    # --- serve ---
    p_serve = sub.add_parser("serve", help="Start the web console")
    p_serve.add_argument("--port", type=int, default=7777, help="Listen port (default: 7777)")
    p_serve.add_argument("--bind", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    p_serve.set_defaults(func=cmd_serve)

    # --- packs ---
    p_packs = sub.add_parser("packs", help="List available cloud provider target packs")
    p_packs.set_defaults(func=cmd_packs)

    # --- frameworks ---
    p_fw = sub.add_parser("frameworks", help="List known LLM serving frameworks")
    p_fw.set_defaults(func=cmd_frameworks)

    # --- prefixes ---
    p_pfx = sub.add_parser("prefixes", help="Resolve ASN(s) to announced IPv4 prefixes")
    p_pfx.add_argument("--asn", required=True, nargs="+", help="ASN number(s), e.g. 24940 47583")
    p_pfx.add_argument("--limit", type=int, default=5000, help="Max prefixes per ASN (default: 5000)")
    p_pfx.set_defaults(func=cmd_prefixes)

    # --- cidrs ---
    p_cc = sub.add_parser("cidrs", help="Resolve country code to IPv4 CIDR ranges")
    p_cc.add_argument("--cc", required=True, help="ISO country code, e.g. DE, US, NL")
    p_cc.add_argument("--limit", type=int, default=256, help="Max CIDR ranges (default: 256)")
    p_cc.set_defaults(func=cmd_cidrs)

    # --- report ---
    p_rep = sub.add_parser("report", help="Render an offline report from scan results (JSON file or history DB)")
    src = p_rep.add_argument_group("source (pick one)")
    src.add_argument("--input", "-i", metavar="FILE",
                     help="Results JSON file as produced by `scan -o`")
    src.add_argument("--scan-id", type=int, metavar="N",
                     help="History DB row by SQLite rowid (the targets table has no scan_id column); "
                          "renders the last recorded result for that row. Omit both --input and "
                          "--scan-id to render the full scan history.")
    p_rep.add_argument("--format", choices=["html", "md", "csv"], default="html",
                       help="Output format (default: html)")
    p_rep.add_argument("--output", "-o", metavar="FILE",
                       help="Write the report to FILE (default: stdout)")
    p_rep.set_defaults(func=cmd_report)

    args = ap.parse_args()
    if not args.command:
        ap.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
