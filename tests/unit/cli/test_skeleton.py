"""CLI-0: the agentledger package, its four stub commands, and the shared PKCE login. Offline."""

from __future__ import annotations

import base64
import hashlib
import subprocess
import sys
import types
import urllib.parse

import pytest
from click.testing import CliRunner

import infra.human_login as human_login
from agentledger import login
from agentledger.main import cli

COMMANDS = ("login", "whoami", "status", "logout")
CFG = {
    "domain": "https://agentledger-test.auth.us-east-1.amazoncognito.com",
    "cli": {"client_id": "fakecliclient", "callback": "http://localhost:8765/callback", "scopes": ["openid"]},
}


# --- package and commands ---------------------------------------------------

def test_help_lists_the_four_commands():
    res = CliRunner().invoke(cli, ["--help"])
    assert res.exit_code == 0
    for name in COMMANDS:
        assert f"  {name} " in res.output


def test_python_dash_m_agentledger_runs():
    res = subprocess.run([sys.executable, "-m", "agentledger", "--help"],
                         capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr
    assert "Usage: agentledger" in res.stdout


@pytest.mark.parametrize("name", ("whoami", "status", "logout"))
def test_stub_fails_instead_of_looking_like_success(name):
    # A stub that exits 0 would read as "signed in" or "signed out" to a script.
    res = CliRunner().invoke(cli, [name])
    assert res.exit_code == 1
    assert "not implemented yet" in res.output


def test_unknown_command_rejected():
    res = CliRunner().invoke(cli, ["signin"])
    assert res.exit_code == 2
    assert "No such command" in res.output


# --- one login implementation ----------------------------------------------

def test_human_login_has_no_own_pkce_code():
    # The wrapper must delegate; a second copy of the flow would drift.
    for name in ("Handler", "_run", "_login", "_serve_once"):
        assert not hasattr(human_login, name), f"infra/human_login.py still defines {name}"
    assert human_login.login is login


def test_pkce_challenge_is_s256_of_verifier():
    verifier, challenge = login.pkce_pair()
    assert 43 <= len(verifier) <= 128  # RFC 7636 section 4.1
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert challenge == expected
    assert "=" not in challenge


def test_pkce_verifier_is_fresh_each_call():
    assert login.pkce_pair()[0] != login.pkce_pair()[0]


def test_authorize_url_sends_challenge_not_verifier():
    verifier, challenge = login.pkce_pair()
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(login.authorize_url(CFG, challenge, "st")).query)
    assert qs["code_challenge"] == [challenge]
    assert qs["code_challenge_method"] == ["S256"]
    assert qs["response_type"] == ["code"]
    assert qs["state"] == ["st"]
    assert verifier not in login.authorize_url(CFG, challenge, "st")


def test_cli_timeout_message_names_agentledger_login(monkeypatch, capsys):
    # Same flow as human_login, but the retry hint points at the CLI command.
    clock = {"now": 0.0}

    class FakeServer:
        def __init__(self, addr, handler):
            self.timeout = None

        def handle_request(self):
            pass

        def server_close(self):
            pass

    class FakeEvent:
        def wait(self, t):
            clock["now"] += t

    class Thread:
        def __init__(self, target=None, daemon=None):
            self.target = target

        def start(self):
            self.target()

    monkeypatch.setattr(login.webbrowser, "open", lambda url: True)
    rc = login.run(
        load_config=lambda: CFG,
        server_cls=FakeServer,
        threading_mod=types.SimpleNamespace(Thread=Thread, Event=FakeEvent),
        monotonic=lambda: clock["now"],
    )
    out = capsys.readouterr().out
    assert rc == 1
    assert "Run agentledger login again" in out
    assert "python infra/human_login.py" not in out
