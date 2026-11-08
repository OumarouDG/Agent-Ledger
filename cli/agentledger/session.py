"""The signed-in human session: verify stored tokens, refresh once, revoke.

`current_session()` is the entry point for the agent runtime. It returns a verified
Session or raises a SessionError subclass whose message says what to do
("run agentledger login"). Token values never appear in messages or reprs.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import requests

from controlplane.auth.config import load_config
from controlplane.auth.jwt_verify import AuthError, Verifier

from .storage import StorageError, StoredSessionCorrupt, TokenStore

RELOGIN = "run agentledger login"
HTTP_TIMEOUT_S = 10
_ERROR_CODE = re.compile(r"^[a-z_]{1,40}$")


class SessionError(Exception):
    """No usable session. The message is safe to print and names the fix."""


class NotSignedIn(SessionError):
    pass


class SessionExpired(SessionError):
    pass


class InvalidSession(SessionError):
    """A stored or refreshed ID token failed verification for a reason other than expiry."""

    def __init__(self, reason: str):
        super().__init__(f"Stored sign-in failed verification ({reason}); {RELOGIN}.")
        self.reason = reason


class RevokeFailed(Exception):
    pass


@dataclass(frozen=True)
class Session:
    username: str
    groups: list[str]
    expires_at: int  # ID token `exp`, epoch seconds
    refreshed: bool
    id_token: str = field(repr=False)
    access_token: str = field(repr=False)


# --- HTTP calls to Cognito ------------------------------------------------------

def _error_code(resp: Any) -> str:
    """Cognito's `error` field if it looks like an OAuth error code, else 'HTTP <status>'. Never the raw body."""
    try:
        code = resp.json().get("error")
    except Exception:  # noqa: BLE001 - any unparseable body
        code = None
    return code if isinstance(code, str) and _ERROR_CODE.match(code) else f"HTTP {resp.status_code}"


def refresh(cfg: dict, refresh_token: str, *, client_id: str | None = None,
            post: Callable[..., Any] | None = None) -> dict:
    """One refresh_token grant at /oauth2/token. Returns the new token dict, or raises SessionExpired."""
    client_id = client_id or cfg["cli"]["client_id"]
    url = f"{cfg['domain']}/oauth2/token"
    try:
        resp = (post or requests.post)(url, data={
            "grant_type": "refresh_token", "client_id": client_id, "refresh_token": refresh_token,
        }, timeout=HTTP_TIMEOUT_S)
    except requests.RequestException as e:
        raise SessionExpired(f"Session expired and refresh could not reach {url} ({type(e).__name__}). "
                             f"Check the network, or {RELOGIN}.") from None
    if resp.status_code != 200:
        raise SessionExpired(f"Session expired and Cognito refused the refresh ({_error_code(resp)}); {RELOGIN}.")
    try:
        tokens = resp.json()
    except ValueError:
        tokens = None
    if not isinstance(tokens, dict) or not tokens.get("id_token") or not tokens.get("access_token"):
        raise SessionExpired(f"Session expired and the refresh reply had no tokens; {RELOGIN}.")
    return tokens


def revoke(cfg: dict, refresh_token: str, *, client_id: str | None = None,
           post: Callable[..., Any] | None = None) -> None:
    """POST /oauth2/revoke. Raises RevokeFailed on anything but HTTP 200.

    Cognito also answers 200 for a token that was already revoked or invalid, so a
    return here means "Cognito accepted the request", not "a live token was revoked".
    """
    client_id = client_id or cfg["cli"]["client_id"]
    url = f"{cfg['domain']}/oauth2/revoke"
    try:
        resp = (post or requests.post)(url, data={"token": refresh_token, "client_id": client_id},
                                       timeout=HTTP_TIMEOUT_S)
    except requests.RequestException as e:
        raise RevokeFailed(f"could not reach {url} ({type(e).__name__})") from None
    if resp.status_code != 200:
        raise RevokeFailed(f"Cognito refused the revoke ({_error_code(resp)})")


# --- current_session ------------------------------------------------------------

def current_session(
    *,
    cfg: dict | None = None,
    store: TokenStore | None = None,
    verifier: Verifier | None = None,
    post: Callable[..., Any] | None = None,
) -> Session:
    """Verified session for the signed-in human. Refreshes at most once if the ID token expired."""
    cfg = cfg or _config()
    store = store or TokenStore.for_config(cfg)
    verifier = verifier or Verifier.from_config()
    client_id = cfg["cli"]["client_id"]

    bundle = _load(store)
    try:
        claims = verifier.verify_human(bundle["id_token"], client_id)
        return _session(claims, bundle, refreshed=False)
    except AuthError as e:
        if e.reason != "token_expired":
            raise InvalidSession(e.reason) from None

    if not bundle.get("refresh_token"):
        raise SessionExpired(f"Session expired and no refresh token is stored; {RELOGIN}.")
    new = refresh(cfg, bundle["refresh_token"], post=post)
    try:
        claims = verifier.verify_human(new["id_token"], client_id)
    except AuthError as e:
        raise InvalidSession(f"refreshed token: {e.reason}") from None
    # With refresh token rotation Cognito returns a new refresh token; otherwise keep the old one.
    saved = {"id_token": new["id_token"], "access_token": new["access_token"],
             "refresh_token": new.get("refresh_token") or bundle["refresh_token"]}
    try:
        store.save(saved)
    except StorageError as e:
        raise SessionError(f"Session refreshed but could not be saved: {e}") from None
    return _session(claims, saved, refreshed=True)


def _config() -> dict:
    try:
        return load_config()
    except FileNotFoundError as e:
        raise SessionError(str(e)) from None


def _load(store: TokenStore) -> dict:
    try:
        bundle = store.load()
    except StoredSessionCorrupt as e:
        raise NotSignedIn(str(e)) from None
    except StorageError as e:
        raise SessionError(str(e)) from None
    if bundle is None:
        raise NotSignedIn(f"Not signed in; {RELOGIN}.")
    return bundle


def _session(claims: dict, bundle: dict, refreshed: bool) -> Session:
    return Session(
        username=str(claims.get("cognito:username", "")),
        groups=list(claims.get("cognito:groups", [])),
        expires_at=int(claims["exp"]),
        refreshed=refreshed,
        id_token=bundle["id_token"],
        access_token=bundle["access_token"],
    )


def minutes_left(expires_at: int, now: float | None = None) -> int:
    return int((expires_at - (time.time() if now is None else now)) // 60)
