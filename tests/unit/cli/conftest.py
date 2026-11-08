"""Fakes for CLI unit tests: in-memory keyring, and seams for the browser login flow.

No socket, no browser, no network, no OS credential store. Token values are fakes.
"""

from __future__ import annotations

import types
import urllib.parse

import pytest
from keyring.errors import KeyringError, PasswordDeleteError

from agentledger import login, storage

CFG = {
    "user_pool_id": "us-east-1_FAKEPOOL",
    "domain": "https://agentledger-test.auth.us-east-1.amazoncognito.com",
    "cli": {"client_id": "fakecliclient", "callback": "http://localhost:8765/callback", "scopes": ["openid"]},
}
FAKE_TOKENS = {
    "id_token": "fake-id-token-value",
    "access_token": "fake-access-token-value",
    "refresh_token": "fake-refresh-token-value",
    "expires_in": 3600,
    "token_type": "Bearer",
}


class MemoryKeyring:
    """Same get/set/delete interface as a keyring backend. Not a KeyringBackend subclass,
    so it is never registered with keyring's backend discovery."""

    def __init__(self):
        self.data: dict[tuple[str, str], str] = {}
        self.fail_set_on: str | None = None  # username whose write raises
        self.fail_reads = False

    def get_password(self, service, username):
        if self.fail_reads:
            raise KeyringError("backend unavailable")
        return self.data.get((service, username))

    def set_password(self, service, username, password):
        if self.fail_set_on is not None and username == self.fail_set_on:
            raise KeyringError("write refused")
        self.data[(service, username)] = password

    def delete_password(self, service, username):
        if (service, username) not in self.data:
            raise PasswordDeleteError("not found")
        del self.data[(service, username)]


@pytest.fixture
def mem(monkeypatch) -> MemoryKeyring:
    """In-memory keyring, installed as the default backend for TokenStore."""
    backend = MemoryKeyring()
    monkeypatch.setattr(storage.keyring, "get_keyring", lambda: backend)
    return backend


class FakeServer:
    def __init__(self, addr, handler):
        self.timeout = None
        self.closed = False

    def handle_request(self):
        pass

    def server_close(self):
        self.closed = True


class FakeThread:
    def __init__(self, target=None, daemon=None):
        self.target = target

    def start(self):
        self.target()


class FakeVerifier:
    claims = {"cognito:username": "alice", "cognito:groups": ["engineer"], "token_use": "id"}
    error: Exception | None = None

    @classmethod
    def from_config(cls):
        return cls()

    def verify_human(self, token, client_id):
        if self.error:
            raise self.error
        assert token == FAKE_TOKENS["id_token"] and client_id == CFG["cli"]["client_id"]
        return dict(self.claims)


class FakeResp:
    def __init__(self, body=None, status=200):
        self.body = FAKE_TOKENS if body is None else body
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"{self.status_code} error", response=self)

    def json(self):
        if isinstance(self.body, Exception):
            raise self.body
        return dict(self.body) if isinstance(self.body, dict) else self.body


@pytest.fixture
def seams(monkeypatch):
    """Seams for login.authenticate() where the browser signs in at once.

    Set seams["post"] to change the token endpoint's reply.
    """
    result: dict = {}
    clock = {"now": 0.0}

    class FakeEvent:
        def wait(self, t):
            clock["now"] += t

    def browser(url):
        state = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["state"][0]
        result.update({"code": "fake-code", "state": state})
        return True

    FakeVerifier.error = None
    monkeypatch.setattr(login.webbrowser, "open", browser)
    monkeypatch.setattr(login.requests, "post", lambda *a, **k: FakeResp())
    return {
        "result": result,
        "load_config": lambda: CFG,
        "server_cls": FakeServer,
        "threading_mod": types.SimpleNamespace(Thread=FakeThread, Event=FakeEvent),
        "monotonic": lambda: clock["now"],
        "verifier_cls": FakeVerifier,
    }
