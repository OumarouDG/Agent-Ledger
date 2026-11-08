"""CLI-3: guards for failures that looked like success (or like the wrong failure). Offline.

Each section names the bad case. These tests were written before the fixes and run
against the CLI-2 code first, to show the bad case. Token values are fakes or
generated here.
"""

from __future__ import annotations

import errno
import io
import json
import types
import urllib.error
import urllib.parse

import jwt
import pytest
from click.testing import CliRunner
from jwt.algorithms import RSAAlgorithm

from agentledger import commands, login, session
from agentledger.main import cli
from agentledger.storage import TokenStore
from controlplane.auth.jwt_verify import Verifier

from .conftest import CFG as LOGIN_CFG, FAKE_TOKENS, FakeResp, FakeServer
from .test_session import CFG, OTHER_KEY, Post, Resp, expired_id_token, id_token, save, verifier

# --- 1. JWKS unreachable was reported as a bad token ---------------------------------
# Bad case: with no network, whoami said "Stored sign-in failed verification
# (unknown_signing_key); run agentledger login". The token was fine; logging in again
# would not help. Fail closed stays: the session is still refused, with the real cause.


class _Opener:
    def __init__(self, behaviour):
        self.behaviour = behaviour

    def open(self, req, timeout=None):
        if isinstance(self.behaviour, Exception):
            raise self.behaviour
        return io.BytesIO(json.dumps(self.behaviour).encode())


@pytest.fixture
def jwks(monkeypatch):
    """Control what the real PyJWKClient gets from the JWKS URL. Default: network down."""
    state = {"behaviour": urllib.error.URLError("getaddrinfo failed")}
    monkeypatch.setattr(jwt.jwks_client.urllib.request, "build_opener",
                        lambda *handlers: _Opener(state["behaviour"]))
    return state


def real_verifier() -> Verifier:
    # Real JWKS client and decode path; only the HTTP layer underneath is faked.
    return Verifier(issuer=CFG["issuer"], jwks_url=CFG["jwks_url"])


def other_key_jwks() -> dict:
    jwk = json.loads(RSAAlgorithm.to_jwk(OTHER_KEY.public_key()))
    jwk.update({"kid": "some-other-kid", "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


@pytest.fixture
def cmd_store(mem, monkeypatch) -> TokenStore:
    s = TokenStore(CFG["user_pool_id"])
    monkeypatch.setattr(commands, "_context", lambda: (CFG, s, real_verifier()))
    return s


def test_jwks_unreachable_is_not_reported_as_bad_token(mem, jwks):
    store = TokenStore(CFG["user_pool_id"])
    save(store, id_token())
    with pytest.raises(session.VerifierUnavailable) as e:
        session.current_session(cfg=CFG, store=store, verifier=real_verifier())
    assert "can't reach the pool's signing keys" in str(e.value)
    assert "failed verification" not in str(e.value)
    assert isinstance(e.value, session.SessionError)  # still refused: fail closed


def test_unknown_signing_key_with_reachable_jwks_is_still_a_bad_token(mem, jwks):
    # Control: the JWKS answers but has no key for this token. That is a bad token.
    jwks["behaviour"] = other_key_jwks()
    store = TokenStore(CFG["user_pool_id"])
    save(store, id_token())
    with pytest.raises(session.InvalidSession) as e:
        session.current_session(cfg=CFG, store=store, verifier=real_verifier())
    assert e.value.reason == "unknown_signing_key"


def test_whoami_with_jwks_unreachable(cmd_store, jwks):
    save(cmd_store, id_token())
    res = CliRunner().invoke(cli, ["whoami"])
    assert res.exit_code == 1
    assert "can't reach the pool's signing keys" in res.output
    assert "failed verification" not in res.output
    assert "Signed in as" not in res.output


def test_status_with_jwks_unreachable(cmd_store, jwks):
    save(cmd_store, id_token())
    res = CliRunner().invoke(cli, ["status"])
    assert res.exit_code == 0
    assert res.output.startswith("Status unknown: can't reach the pool's signing keys")
    assert "failed verification" not in res.output


def test_refresh_then_jwks_unreachable_is_not_saved(mem, jwks):
    store = TokenStore(CFG["user_pool_id"])
    jwks["behaviour"] = urllib.error.URLError("timed out")
    before = save(store, expired_id_token())

    class ExpiredThenReal(Verifier):
        calls = 0

        def verify_human(self, token, client_id, key=None):
            ExpiredThenReal.calls += 1
            if ExpiredThenReal.calls == 1:
                from controlplane.auth.jwt_verify import AuthError
                raise AuthError("token_expired")
            return super().verify_human(token, client_id, key)

    post = Post(Resp(200, {"id_token": id_token(), "access_token": "fake-access-2"}))
    v = ExpiredThenReal(issuer=CFG["issuer"], jwks_url=CFG["jwks_url"])
    with pytest.raises(session.VerifierUnavailable):
        session.current_session(cfg=CFG, store=store, verifier=v, post=post)
    assert store.load() == before


def test_login_with_jwks_unreachable(seams, jwks, monkeypatch):
    # A real JWT in the token reply, so verification reaches the JWKS fetch.
    monkeypatch.setattr(login.requests, "post",
                        lambda *a, **k: FakeResp({"id_token": id_token(), "access_token": "fake-access-2"}))
    seams["verifier_cls"] = types.SimpleNamespace(
        from_config=lambda: Verifier(issuer=CFG["issuer"], jwks_url=CFG["jwks_url"]))
    with pytest.raises(login.LoginError) as e:
        login.authenticate(**seams)
    assert "can't reach the pool's signing keys" in str(e.value)
    assert "ID token rejected" not in str(e.value)


# --- 2. Port 8765 in use gave a raw OSError traceback ------------------------------------

class BusyServer:
    def __init__(self, addr, handler):
        e = OSError(errno.EADDRINUSE, "Only one usage of each socket address is normally permitted")
        e.winerror = 10048
        raise e


def test_port_in_use_is_a_clear_login_error(seams):
    seams["server_cls"] = BusyServer
    with pytest.raises(login.LoginError) as e:
        login.authenticate(**seams)
    msg = str(e.value)
    assert "localhost:8765 is already in use" in msg
    assert "another agentledger login" in msg


def test_port_in_use_via_cli_has_no_traceback(mem, seams, monkeypatch):
    import controlplane.auth.config as config

    seams["server_cls"] = BusyServer
    monkeypatch.setattr(config, "load_config", lambda: LOGIN_CFG)
    real = login.authenticate
    monkeypatch.setattr(login, "authenticate", lambda *a, **k: real(*a, **{**seams, **k}))
    res = CliRunner().invoke(cli, ["login"])
    assert res.exit_code == 1
    assert isinstance(res.exception, SystemExit)  # handled, not an escaped OSError
    assert "already in use" in res.output


# --- 3. The browser tab said "signed in" when sign-in had failed --------------------------

class FakeConn:
    """Enough of a socket for BaseHTTPRequestHandler to handle one request."""

    def __init__(self, path: str):
        self.rfile = io.BytesIO(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        self.sent = bytearray()

    def makefile(self, mode, *a, **k):
        return self.rfile if "r" in mode else io.BytesIO()

    def sendall(self, data):
        self.sent += data


def browser_gets(handler_cls, path: str) -> tuple[int, str]:
    conn = FakeConn(path)
    handler_cls(conn, ("127.0.0.1", 50000), None)
    head, _, body = bytes(conn.sent).partition(b"\r\n\r\n")
    return int(head.split()[1]), body.decode()


def test_browser_tab_does_not_say_signed_in_on_error():
    result: dict = {}
    status, body = browser_gets(login.make_handler(result), "/callback?error=access_denied")
    assert status == 400
    assert "signed in" not in body.lower()
    assert "failed" in body and "access_denied" in body
    assert result["error"] == "access_denied"  # terminal still reports it


def test_browser_tab_does_not_say_signed_in_on_state_mismatch():
    result: dict = {}
    status, body = browser_gets(login.make_handler(result, "expected-state"),
                                "/callback?code=fake-code&state=wrong")
    assert status == 400
    assert "signed in" not in body.lower()
    assert "state mismatch" in body


def test_browser_tab_on_good_redirect_says_received_not_signed_in():
    # The page is sent before the code exchange and token check, so it can't claim success.
    result: dict = {}
    status, body = browser_gets(login.make_handler(result, "st"), "/callback?code=fake-code&state=st")
    assert status == 200
    assert "Return to the terminal" in body
    assert "signed in" not in body.lower()
    assert result == {"code": "fake-code", "state": "st"}


def test_error_text_from_redirect_is_sanitised():
    # The redirect's query is attacker-controllable; terminal escapes must not reach the console.
    result: dict = {}
    _, body = browser_gets(login.make_handler(result), "/callback?error=" + urllib.parse.quote("bad\x1b[2Jx"))
    assert "\x1b" not in body
    assert result["error"] == "bad[2Jx"


# --- 4. A stray request (favicon, probe) used up the only callback slot -------------------

class QueueServer(FakeServer):
    """Delivers queued paths through the real handler, one per handle_request()."""
    paths: list[str] = []

    def __init__(self, addr, handler):
        super().__init__(addr, handler)
        self.handler = handler
        self.served: list[int] = []

    def handle_request(self):
        if QueueServer.paths:
            status, _ = browser_gets(self.handler, QueueServer.paths.pop(0))
            self.served.append(status)


def test_stray_request_before_redirect_does_not_hang_login(seams, monkeypatch):
    # Bad case: the server handled exactly one request. A /favicon.ico first meant the real
    # redirect was never read, and login waited the full 120 s, then timed out.
    def browser(url):
        state = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["state"][0]
        QueueServer.paths = ["/favicon.ico", f"/callback?code=fake-code&state={state}"]
        return True

    created = []

    def server(addr, handler):
        created.append(QueueServer(addr, handler))
        return created[-1]

    # Run the server thread's target on the first poll, i.e. after the browser has opened.
    deferred = []

    class DeferredThread:
        def __init__(self, target=None, daemon=None):
            self.target = target

        def start(self):
            deferred.append(self.target)

    clock = [0.0]

    class RunServerOnWait:
        def wait(self, t):
            clock[0] += t  # without this, old code would poll forever in this test
            while deferred:
                deferred.pop()()

    seams["server_cls"] = server
    seams["monotonic"] = lambda: clock[0]
    seams["threading_mod"] = types.SimpleNamespace(Thread=DeferredThread, Event=RunServerOnWait)
    monkeypatch.setattr(login.webbrowser, "open", browser)
    res = login.authenticate(**seams)
    assert res.username == "alice"
    assert created[0].served == [404, 200]


# --- 5. Token values in output: sweep every command and failure path ----------------------
# Checked: no leak found on the CLI-2 code. Kept as a regression sweep.

SWEEP_TOKENS = ["fake-access-1", "fake-refresh-1", FAKE_TOKENS["id_token"], FAKE_TOKENS["access_token"],
                FAKE_TOKENS["refresh_token"]]


@pytest.mark.parametrize("args, reply", [
    (["whoami"], Resp(400, {"error": "invalid_grant"})),
    (["whoami"], Resp(200, {"id_token": "fake-bad-id", "access_token": "fake-access-2"})),
    (["status"], None),
    (["logout"], Resp(400, {"error": "invalid_request"})),
    (["logout"], Resp(200, None)),
])
def test_no_token_values_in_any_output(mem, monkeypatch, args, reply):
    import requests

    store = TokenStore(CFG["user_pool_id"])
    monkeypatch.setattr(commands, "_context", lambda: (CFG, store, verifier()))
    monkeypatch.setattr(requests, "post", Post(*([reply] if reply else [])))
    tok = expired_id_token()
    save(store, tok)
    res = CliRunner().invoke(cli, args)
    text = res.output + (repr(res.exception) if res.exception else "")
    for t in SWEEP_TOKENS + [tok, "fake-bad-id"]:
        assert t not in text



# --- 6. Two logins could both listen on the callback port (Windows) -------------------
# Found by the real run check, not by the fakes above: on Windows, HTTPServer's
# SO_REUSEADDR let a second process bind a port that was already listening, and a
# bind over a non-reuse socket failed with WSAEACCES (13) instead of "in use".
# These use real loopback sockets on a free port: the bug is OS socket behaviour.

import sys  # noqa: E402
from http.server import BaseHTTPRequestHandler, HTTPServer  # noqa: E402

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="Windows SO_REUSEADDR semantics")


@windows_only
def test_plain_httpserver_lets_a_second_server_share_the_port():
    # Bad case, kept as evidence: this is what login used before CLI-3.
    a = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    try:
        b = HTTPServer(("127.0.0.1", a.server_address[1]), BaseHTTPRequestHandler)
        b.server_close()
    finally:
        a.server_close()


def test_callback_server_refuses_a_second_bind():
    a = login.CallbackServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    try:
        with pytest.raises(OSError) as e:
            login.CallbackServer(("127.0.0.1", a.server_address[1]), BaseHTTPRequestHandler)
        assert e.value.errno == errno.EADDRINUSE or getattr(e.value, "winerror", None) == 10048
    finally:
        a.server_close()


def test_second_login_on_a_busy_port_says_in_use(seams):
    a = login.CallbackServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    port = a.server_address[1]
    cfg = {**LOGIN_CFG, "cli": {**LOGIN_CFG["cli"], "callback": f"http://127.0.0.1:{port}/callback"}}
    seams.update(load_config=lambda: cfg, server_cls=login.CallbackServer)
    try:
        with pytest.raises(login.LoginError, match=f"127.0.0.1:{port} is already in use"):
            login.authenticate(**seams)
    finally:
        a.server_close()
