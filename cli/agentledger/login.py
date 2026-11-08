"""Human sign-in: authorization code + PKCE against Cognito managed login.

Opens the browser, catches the redirect on the configured callback, exchanges
the code at /oauth2/token and verifies the ID token. Tokens are never printed.

`infra/human_login.py` is a thin wrapper over `run()`, so there is one
implementation. The keyword arguments of `run()` are test seams: callers pass
fakes for the config, socket server, threads, clock and verifier.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable

import requests

from controlplane.auth.config import load_config as _load_config
from controlplane.auth.jwt_verify import Verifier

TIMEOUT_S = 120
POLL_S = 0.2
DEFAULT_RETRY_HINT = "agentledger login"


def make_handler(result: dict) -> type[BaseHTTPRequestHandler]:
    """Callback handler that copies the redirect's query parameters into `result`."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            result.update({k: v[0] for k, v in qs.items()})
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"AgentLedger: signed in. You can close this tab.")

        def log_message(self, *args: Any) -> None:
            pass

    return Handler


def pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, S256 code_challenge) per RFC 7636."""
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def authorize_url(cfg: dict, challenge: str, state: str) -> str:
    cli = cfg["cli"]
    return f"{cfg['domain']}/oauth2/authorize?" + urllib.parse.urlencode({
        "response_type": "code",
        "client_id": cli["client_id"],
        "redirect_uri": cli["callback"],
        "scope": " ".join(cli["scopes"]),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    })


def run(
    retry_hint: str = DEFAULT_RETRY_HINT,
    *,
    result: dict | None = None,
    load_config: Callable[[], dict] | None = None,
    server_cls: Callable[..., Any] | None = None,
    threading_mod: Any = None,
    monotonic: Callable[[], float] | None = None,
    verifier_cls: Any = None,
) -> int:
    """Sign in and print the verified username and groups. Returns a process exit code."""
    try:
        return _login(
            retry_hint,
            result if result is not None else {},
            load_config or _load_config,
            server_cls or HTTPServer,
            threading_mod or threading,
            monotonic or time.monotonic,
            verifier_cls or Verifier,
        )
    except KeyboardInterrupt:
        print("\nLogin cancelled")
        return 1


def _login(retry_hint, result, load_config, server_cls, threading_mod, monotonic, verifier_cls) -> int:
    result.clear()
    cfg = load_config()
    callback = urllib.parse.urlparse(cfg["cli"]["callback"])
    code_verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(16)

    server = server_cls((callback.hostname, callback.port), make_handler(result))
    server.timeout = TIMEOUT_S  # handle_request() returns after this even if nothing arrives
    try:
        threading_mod.Thread(target=lambda: _serve_once(server), daemon=True).start()
        return _await_and_exchange(cfg, result, code_verifier, challenge, state,
                                   retry_hint, threading_mod, monotonic, verifier_cls)
    finally:
        server.server_close()


def _serve_once(server: Any) -> None:
    try:
        server.handle_request()
    except (OSError, ValueError):
        pass  # main thread closed the socket (cancel or timeout); nothing to report


def _await_and_exchange(cfg, result, code_verifier, challenge, state,
                        retry_hint, threading_mod, monotonic, verifier_cls) -> int:
    cli = cfg["cli"]
    url = authorize_url(cfg, challenge, state)
    print("Opening the browser. Sign in as alice, bob or dana.")
    webbrowser.open(url)
    print(f"If it didn't open, visit:\n{url}\n")

    deadline = monotonic() + TIMEOUT_S
    while "code" not in result and "error" not in result:
        if monotonic() >= deadline:
            print(f"Login timed out after {TIMEOUT_S} s: no sign-in reached {cli['callback']}. "
                  f"Run {retry_hint} again and finish signing in within {TIMEOUT_S} s.")
            return 1
        threading_mod.Event().wait(POLL_S)

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
        "code_verifier": code_verifier,
    }, timeout=10)
    resp.raise_for_status()
    tokens = resp.json()

    claims = verifier_cls.from_config().verify_human(tokens["id_token"], cli["client_id"])
    print(f"Signed in: {claims.get('cognito:username')}  groups={claims.get('cognito:groups', [])}")
    print("Tokens received: id, access" + (", refresh" if "refresh_token" in tokens else "") + " (not printed)")
    return 0
