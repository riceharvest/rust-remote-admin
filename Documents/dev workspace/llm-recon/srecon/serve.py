"""HTTP server bootstrap for the Silicon Recon web console.

Lifts the file-descriptor soft limit (the async engine holds thousands of
concurrent sockets) and serves the web UI on a ThreadingHTTPServer.
"""
import resource
from http.server import ThreadingHTTPServer

from .web import Handler


def raise_fd_limit(want=65536):
    """Raise the fd soft limit toward `want` (capped by the hard limit).

    Returns the effective soft limit, or None if it could not be raised.
    """
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = min(hard, want)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        return soft
    except (ValueError, OSError):
        return None


def serve(host="127.0.0.1", port=7777, quiet=False):
    """Start the web console and block until interrupted."""
    soft = raise_fd_limit()
    if not quiet:
        if soft:
            print(f"[SILICON RECON] fd limit: {soft} (cap: {(soft-256)//4} workers)")
        else:
            print("[SILICON RECON] WARNING: could not raise fd limit; "
                  "start with: ulimit -n 65536 && python3 -m srecon serve")
    srv = ThreadingHTTPServer((host, port), Handler)
    if not quiet:
        print(f"[SILICON RECON] console up on http://{host}:{port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
