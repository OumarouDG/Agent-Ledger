"""G0 check: sign in as a demo user with authorization code + PKCE, like the Go CLI will.

Opens Cognito managed login in the browser, catches the redirect on
localhost:8765, exchanges the code, verifies the ID token and prints the
username and groups. Demo passwords are in infra/out/demo-users.local.json.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import sys
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from controlplane.auth.config import load_config  # noqa: E402
from controlplane.auth.jwt_verify import Verifier  # noqa: E402

result: dict = {}
TIMEOUT_S = 120
POLL_S = 0.2


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        result.update({k: v[0] for k, v in qs.items()})
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"AgentLedger: signed in. You can close this tab.")

    def log_message(self, *args):
        pass


def main() -> int:
    try:
        return _login()
    except KeyboardInterrupt:
        print("\nLogin cancelled")
        return 1


def _login() -> int:
    result.clear()
    cfg = load_config()
    cli = cfg["cli"]
    callback = urllib.parse.urlparse(cli["callback"])

    verifier_str = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier_str.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)

    server = HTTPServer((callback.hostname, callback.port), Handler)
    server.timeout = TIMEOUT_S  # handle_request() returns after this even if nothing arrives
    try:
        return _run(cfg, cli, server, verifier_str, challenge, state)
    finally:
        server.server_close()


def _serve_once(server) -> None:
    try:
        server.handle_request()
    except (OSError, ValueError):
        pass  # main thread closed the socket (cancel or timeout); nothing to report


def _run(cfg: dict, cli: dict, server, verifier_str: str, challenge: str, state: str) -> int:
    threading.Thread(target=lambda: _serve_once(server), daemon=True).start()

    url = f"{cfg['domain']}/oauth2/authorize?" + urllib.parse.urlencode({
        "response_type": "code",
        "client_id": cli["client_id"],
        "redirect_uri": cli["callback"],
        "scope": " ".join(cli["scopes"]),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    })
    print("Opening the browser. Sign in as alice, bob or dana.")
    webbrowser.open(url)
    print(f"If it didn't open, visit:\n{url}\n")

    deadline = time.monotonic() + TIMEOUT_S
    while "code" not in result and "error" not in result:
        if time.monotonic() >= deadline:
            print(f"Login timed out after {TIMEOUT_S} s: no sign-in reached {cli['callback']}. "
                  f"Run python infra/human_login.py again and finish signing in within {TIMEOUT_S} s.")
            return 1
        threading.Event().wait(POLL_S)

    if "error" in result:
        print(f"Login failed: {result['error']}")
        return 1
    if result.get("state") != state:
        print("Login failed: state mismatch")
        return 1

    resp = requests.post(f"{cfg['domain']}/oauth2/token", data={
        "grant_type": "authorization_code",
        "client_id": cli["client_id"],
        "code": result["code"],
        "redirect_uri": cli["callback"],
        "code_verifier": verifier_str,
    }, timeout=10)
    resp.raise_for_status()
    tokens = resp.json()

    claims = Verifier.from_config().verify_human(tokens["id_token"], cli["client_id"])
    print(f"Signed in: {claims.get('cognito:username')}  groups={claims.get('cognito:groups', [])}")
    print("Tokens received: id, access" + (", refresh" if "refresh_token" in tokens else "") + " (not printed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
