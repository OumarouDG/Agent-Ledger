"""Human sign-in: authorization code + PKCE against Cognito managed login.

Opens the browser, catches the redirect on the configured callback, exchanges
the code at /oauth2/token and verifies the ID token. Tokens are never printed.

`authenticate()` returns the tokens and verified claims; the `agentledger login`
command stores them. `run()` is the print-only flow used by `infra/human_login.py`,
so there is one implementation. The keyword arguments are test seams: callers pass
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
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable

import requests

from controlplane.auth.config import load_config as _load_config
from controlplane.auth.jwt_verify import AuthError, Verifier

TIMEOUT_S = 120
POLL_S = 0.2
DEFAULT_RETRY_HINT = "agentledger login"


class LoginError(Exception):
    """Sign-in did not complete. The message is safe to print."""


@dataclass
class LoginResult:
    claims: dict
    tokens: dict = field(repr=False)  # never in repr, so a stray print can't leak them

    @property
    def username(self) -> str:
        return str(self.claims.get("cognito:username", ""))

    @property
    def groups(self) -> list[str]:
        return list(self.claims.get("cognito:groups", []))


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


def run(retry_hint: str = DEFAULT_RETRY_HINT, **seams: Any) -> int:
    """Sign in and print the verified username and groups. Returns a process exit code."""
    try:
        res = authenticate(retry_hint, **seams)
    except KeyboardInterrupt:
        print("\nLogin cancelled")
        return 1
    except LoginError as e:
        print(e)
        return 1
    print(f"Signed in: {res.username}  groups={res.groups}")
    print("Tokens received: id, access" + (", refresh" if "refresh_token" in res.tokens else "") + " (not printed)")
    return 0


def authenticate(
    retry_hint: str = DEFAULT_RETRY_HINT,
    *,
    result: dict | None = None,
    load_config: Callable[[], dict] | None = None,
    server_cls: Callable[..., Any] | None = None,
    threading_mod: Any = None,
    monotonic: Callable[[], float] | None = None,
    verifier_cls: Any = None,
) -> LoginResult:
    """Run the browser flow. Raises LoginError (or KeyboardInterrupt on Ctrl+C)."""
    result = result if result is not None else {}
    threading_mod = threading_mod or threading
    result.clear()
    cfg = (load_config or _load_config)()
    callback = urllib.parse.urlparse(cfg["cli"]["callback"])
    code_verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(16)

    server = (server_cls or HTTPServer)((callback.hostname, callback.port), make_handler(result))
    server.timeout = TIMEOUT_S  # handle_request() returns after this even if nothing arrives
    try:
        threading_mod.Thread(target=lambda: _serve_once(server), daemon=True).start()
        code = _await_code(cfg, result, challenge, state, retry_hint,
                           threading_mod, monotonic or time.monotonic)
    finally:
        server.server_close()
    tokens = _exchange(cfg, code, code_verifier)
    return LoginResult(claims=_verify(cfg, tokens, verifier_cls or Verifier), tokens=tokens)


def _serve_once(server: Any) -> None:
    try:
        server.handle_request()
    except (OSError, ValueError):
        pass  # main thread closed the socket (cancel or timeout); nothing to report


def _await_code(cfg, result, challenge, state, retry_hint, threading_mod, monotonic) -> str:
    cli = cfg["cli"]
    url = authorize_url(cfg, challenge, state)
    print("Opening the browser. Sign in as alice, bob or dana.")
    webbrowser.open(url)
    print(f"If it didn't open, visit:\n{url}\n")

    deadline = monotonic() + TIMEOUT_S
    while "code" not in result and "error" not in result:
        if monotonic() >= deadline:
            raise LoginError(f"Login timed out after {TIMEOUT_S} s: no sign-in reached {cli['callback']}. "
                             f"Run {retry_hint} again and finish signing in within {TIMEOUT_S} s.")
        threading_mod.Event().wait(POLL_S)

    if "error" in result:
        raise LoginError(f"Login failed: {result['error']}")
    if result.get("state") != state:
        raise LoginError("Login failed: state mismatch")
    return result["code"]


def _exchange(cfg: dict, code: str, code_verifier: str) -> dict:
    cli = cfg["cli"]
    token_url = f"{cfg['domain']}/oauth2/token"
    try:
        resp = requests.post(token_url, data={
            "grant_type": "authorization_code",
            "client_id": cli["client_id"],
            "code": code,
            "redirect_uri": cli["callback"],
            "code_verifier": code_verifier,
        }, timeout=10)
        resp.raise_for_status()
        tokens = resp.json()
    except requests.HTTPError as e:
        status = e.response.status_code if e.response is not None else "?"
        raise LoginError(f"Login failed: token exchange returned HTTP {status} at {token_url}. "
                         "Sign in again; a code works only once and expires in minutes.") from None
    except (requests.RequestException, ValueError) as e:
        raise LoginError(f"Login failed: can't complete token exchange at {token_url} "
                         f"({type(e).__name__}). Check the network and the domain in shared/cognito.json.") from None
    if not isinstance(tokens, dict) or not tokens.get("id_token") or not tokens.get("access_token"):
        raise LoginError("Login failed: token response had no id_token or access_token.")
    return tokens


def _verify(cfg: dict, tokens: dict, verifier_cls: Any) -> dict:
    try:
        return verifier_cls.from_config().verify_human(tokens["id_token"], cfg["cli"]["client_id"])
    except AuthError as e:
        raise LoginError(f"Login failed: ID token rejected ({e.reason}).") from None
