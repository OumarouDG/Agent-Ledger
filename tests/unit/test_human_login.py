"""Offline tests for infra/human_login.py: Ctrl+C, timeout, and the normal path. No browser, no socket, no network.

Token values here are fakes.
"""

from __future__ import annotations

import types
import urllib.parse

import pytest

import infra.human_login as human_login

FAKE_ID_TOKEN = "fake-id-token-value"
FAKE_ACCESS_TOKEN = "fake-access-token-value"
CFG = {
    "domain": "https://agentledger-test.auth.us-east-1.amazoncognito.com",
    "cli": {"client_id": "fakecliclient", "callback": "http://localhost:8765/callback", "scopes": ["openid"]},
}


class FakeServer:
    instances: list["FakeServer"] = []

    def __init__(self, addr, handler):
        self.addr = addr
        self.closed = False
        self.timeout = None
        FakeServer.instances.append(self)

    def handle_request(self):
        pass

    def server_close(self):
        self.closed = True


class FakeThread:
    def __init__(self, target=None, daemon=None):
        self.target = target

    def start(self):
        self.target()


class Clock:
    def __init__(self):
        self.now = 1000.0
        self.waits = 0

    def monotonic(self):
        return self.now


@pytest.fixture
def env(monkeypatch):
    """Patch everything human_login touches outside Python; return (clock, on_wait hook setter, posts)."""
    human_login.result.clear()
    FakeServer.instances.clear()
    clock = Clock()
    hook = {"on_wait": None}

    class FakeEvent:
        def wait(self, t):
            clock.waits += 1
            clock.now += t
            if hook["on_wait"]:
                hook["on_wait"]()
            if clock.waits > 5000:
                raise AssertionError("still waiting after 5000 polls: there is no timeout")

    posts = []

    def refuse_post(*a, **k):
        posts.append((a, k))
        raise AssertionError("token exchange must not run on this path")

    monkeypatch.setattr(human_login, "load_config", lambda: CFG)
    monkeypatch.setattr(human_login, "HTTPServer", FakeServer)
    monkeypatch.setattr(human_login, "threading", types.SimpleNamespace(Thread=FakeThread, Event=FakeEvent))
    monkeypatch.setattr(human_login, "time", types.SimpleNamespace(monotonic=clock.monotonic), raising=False)
    monkeypatch.setattr(human_login.webbrowser, "open", lambda url: True)
    monkeypatch.setattr(human_login.requests, "post", refuse_post)
    yield clock, hook, posts
    human_login.result.clear()


def run_main() -> int:
    try:
        return human_login.main()
    except KeyboardInterrupt:
        pytest.fail("KeyboardInterrupt escaped main(): user sees a raw traceback")


# --- (b) Ctrl+C -------------------------------------------------------------

def test_ctrl_c_while_waiting_prints_cancelled_and_exits_1(env, capsys):
    # Bad case: Ctrl+C while waiting for the browser raised a raw KeyboardInterrupt traceback.
    clock, hook, posts = env

    def interrupt():
        raise KeyboardInterrupt

    hook["on_wait"] = interrupt
    rc = run_main()
    out = capsys.readouterr()
    assert rc == 1
    assert "Login cancelled" in out.out
    assert "Traceback" not in out.out + out.err
    assert FakeServer.instances[0].closed
    assert posts == []


def test_ctrl_c_during_token_exchange_prints_cancelled(env, monkeypatch, capsys):
    clock, hook, _ = env

    def browser(url):
        state = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["state"][0]
        human_login.result.update({"code": "fake-code", "state": state})
        return True

    def interrupt_post(*a, **k):
        raise KeyboardInterrupt

    monkeypatch.setattr(human_login.webbrowser, "open", browser)
    monkeypatch.setattr(human_login.requests, "post", interrupt_post)
    rc = run_main()
    assert rc == 1
    assert "Login cancelled" in capsys.readouterr().out


# --- (c) timeout ------------------------------------------------------------

def test_no_sign_in_times_out_after_120_s(env, capsys):
    # Bad case: if nobody signed in, the script polled forever.
    clock, hook, posts = env
    start = clock.now
    rc = run_main()
    out = capsys.readouterr().out
    assert rc == 1
    assert "timed out after 120 s" in out
    assert "python infra/human_login.py" in out  # tells the user what to do next
    assert 120 <= clock.now - start < 121
    assert FakeServer.instances[0].closed
    assert FakeServer.instances[0].timeout == 120  # handle_request() gives up too
    assert posts == []


def test_sign_in_just_before_timeout_still_works(env, monkeypatch, capsys):
    # Control: a redirect that lands at 119 s is accepted.
    clock, hook, _ = env
    start = clock.now
    captured = {}

    def browser(url):
        captured["state"] = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["state"][0]
        return True

    def arrive():
        if clock.now - start >= 119:
            human_login.result.update({"code": "fake-code", "state": captured["state"]})

    hook["on_wait"] = arrive
    monkeypatch.setattr(human_login.webbrowser, "open", browser)
    _patch_exchange(monkeypatch)
    assert run_main() == 0
    assert "Signed in: alice" in capsys.readouterr().out


# --- control: normal login -------------------------------------------------

def _patch_exchange(monkeypatch):
    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"id_token": FAKE_ID_TOKEN, "access_token": FAKE_ACCESS_TOKEN}

    class FakeVerifier:
        @classmethod
        def from_config(cls):
            return cls()

        def verify_human(self, token, client_id):
            assert token == FAKE_ID_TOKEN and client_id == CFG["cli"]["client_id"]
            return {"cognito:username": "alice", "cognito:groups": ["engineer"]}

    monkeypatch.setattr(human_login.requests, "post", lambda *a, **k: Resp())
    monkeypatch.setattr(human_login, "Verifier", FakeVerifier)


def test_normal_login_prints_user_and_groups_not_tokens(env, monkeypatch, capsys):
    def browser(url):
        state = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["state"][0]
        human_login.result.update({"code": "fake-code", "state": state})
        return True

    monkeypatch.setattr(human_login.webbrowser, "open", browser)
    _patch_exchange(monkeypatch)
    rc = run_main()
    out = capsys.readouterr().out
    assert rc == 0
    assert "Signed in: alice" in out and "['engineer']" in out
    assert FAKE_ID_TOKEN not in out and FAKE_ACCESS_TOKEN not in out


def test_state_mismatch_rejected(env, monkeypatch, capsys):
    monkeypatch.setattr(human_login.webbrowser, "open",
                        lambda url: human_login.result.update({"code": "c", "state": "wrong"}) or True)
    assert run_main() == 1
    assert "state mismatch" in capsys.readouterr().out
