"""Serve the provenance graph page from the audit file. Read-only. Loopback only.

    python scripts/serve_ledger_view.py --audit gateway-audit.jsonl --port 8001

It binds 127.0.0.1 and nothing else (there is no option to change that). Reach it through an SSM
port-forward, not the internet. Each page load re-reads the audit file, so the view is fresh.
It never writes to the audit file and never touches the gateway on port 8000.
"""

from __future__ import annotations

import argparse
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit_timeline as tl  # noqa: E402
from ledger import build_graph  # noqa: E402
from ledger.visualize import build_view, render_html  # noqa: E402

BIND = "127.0.0.1"


def page(audit_path: str) -> bytes:
    with open(audit_path, encoding="utf-8") as f:
        events, _bad = tl.load(f)
    return render_html(build_view(build_graph(events))).encode("utf-8")


def host_ok(host: str | None) -> bool:
    """Only the name 127.0.0.1 or localhost, on any port. The port differs behind a tunnel
    (the browser says 18001, the server listens on 8001), so the name is what we check."""
    if not host:
        return False
    name, sep, port = host.rpartition(":")
    if not sep:
        name, port = host, ""
    return name in ("127.0.0.1", "localhost") and (port == "" or port.isdigit())


def make_handler(audit_path: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "LedgerView"

        def _send(self, code: int, body: bytes, ctype: str = "text/plain; charset=utf-8") -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if not host_ok(self.headers.get("Host")):
                return self._send(403, b"forbidden host")  # blocks DNS-rebinding style requests
            if self.path.split("?", 1)[0] not in ("/", "/index.html"):
                return self._send(404, b"not found")
            try:
                body = page(audit_path)
            except Exception:  # unreadable file, bad data: say so, never print details
                return self._send(500, b"could not build the view from the audit file")
            self._send(200, body, "text/html; charset=utf-8")

        def log_message(self, fmt, *args):  # keep the console quiet and free of request data
            pass

    return Handler


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--audit", default="gateway-audit.jsonl")
    ap.add_argument("--port", type=int, default=8001)
    args = ap.parse_args(argv)
    if args.port == 8000:
        print("port 8000 is the gateway; pick another", file=sys.stderr)
        return 2
    srv = ThreadingHTTPServer((BIND, args.port), make_handler(args.audit))
    print(f"serving the ledger view on http://{BIND}:{args.port}/ (loopback only). Ctrl+C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
