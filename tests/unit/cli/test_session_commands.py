"""CLI-2: `agentledger whoami`, `status`, `logout`. Offline, locally signed JWTs, in-memory keyring."""

from __future__ import annotations

import re

import pytest
import requests
from click.testing import CliRunner

from agentledger import commands
from agentledger.main import cli
from agentledger.storage import TokenStore

from .test_session import CFG, Post, Resp, expired_id_token, id_token, save, verifier


@pytest.fixture
def store(mem, monkeypatch) -> TokenStore:
    s = TokenStore(CFG["user_pool_id"])
    monkeypatch.setattr(commands, "_context", lambda: (CFG, s, verifier()))
    return s


@pytest.fixture
def http(monkeypatch):
    """Install a Post fake for requests.post; refuse any call unless replies are queued."""
    holder = {"post": Post()}

    def post(*a, **k):
        if not holder["post"].replies:
            raise AssertionError("unexpected HTTP call")
        return holder["post"](*a, **k)

    monkeypatch.setattr(requests, "post", post)
    return holder


def run(*args):
    return CliRunner().invoke(cli, list(args))


def assert_no_tokens(output: str, *tokens: str):
    for t in tokens:
        assert t not in output
    assert "fake-access" not in output and "fake-refresh" not in output


# --- whoami ---------------------------------------------------------------------

def test_whoami_signed_in(store, http):
    tok = id_token()
    save(store, tok)
    res = run("whoami")
    assert res.exit_code == 0, res.output
    assert "Signed in as alice" in res.output
    assert "Groups:  engineer" in res.output
    assert re.search(r"^Expires: \d{4}-\d\d-\d\d \d\d:\d\d .*\(in (59|60) min\)$", res.output, re.M)
    assert "refreshed" not in res.output
    assert_no_tokens(res.output, tok)


def test_whoami_refreshes_expired_session(store, http):
    save(store, expired_id_token())
    http["post"] = Post(Resp(200, {"id_token": id_token(), "access_token": "fake-access-2"}))
    res = run("whoami")
    assert res.exit_code == 0, res.output
    assert res.output.startswith("Session refreshed.")
    assert "Signed in as alice" in res.output


def test_whoami_expired_refresh_fails(store, http):
    save(store, expired_id_token())
    http["post"] = Post(Resp(400, {"error": "invalid_grant"}))
    res = run("whoami")
    assert res.exit_code == 1
    assert "Session expired" in res.output and "run agentledger login" in res.output
    assert "Signed in as" not in res.output


def test_whoami_not_signed_in(store, http):
    res = run("whoami")
    assert res.exit_code == 1
    assert "Not signed in; run agentledger login." in res.output


def test_whoami_bad_token_names_reason(store, http):
    save(store, id_token(aud="someoneelse"))
    res = run("whoami")
    assert res.exit_code == 1
    assert "failed verification (wrong_audience)" in res.output
    assert "Signed in as" not in res.output


# --- status -----------------------------------------------------------------------

@pytest.mark.parametrize("setup, first_line", [
    (lambda s: None, "Not signed in."),
    (lambda s: save(s, id_token()), "Signed in as alice (engineer)"),
    (lambda s: save(s, expired_id_token()), "Session expired; agentledger whoami refreshes it"),
    (lambda s: save(s, expired_id_token(), refresh=None), "Session expired; run agentledger login."),
    (lambda s: save(s, id_token(iss="https://evil.example")), "Stored sign-in failed verification (wrong_issuer)"),
], ids=["signed_out", "signed_in", "expired_with_refresh", "expired_no_refresh", "wrong_issuer"])
def test_status_states(store, http, setup, first_line):
    setup(store)
    res = run("status")
    assert res.exit_code == 0, res.output
    lines = res.output.splitlines()
    assert lines[0].startswith(first_line)
    assert f"Pool:    {CFG['user_pool_id']}" in lines
    assert "Region:  us-east-1" in lines
    assert_no_tokens(res.output)


def test_expired_session_is_not_shown_as_signed_in(store, http):
    save(store, expired_id_token())
    assert "Signed in" not in run("status").output


def test_status_does_not_refresh(store, http):
    save(store, expired_id_token())
    run("status")  # http fake raises on any call; status must still exit 0
    assert http["post"].calls == []


def test_status_with_corrupt_store(store, http, mem):
    save(store, id_token())
    mem.data[("agentledger", CFG["user_pool_id"])] = "garbage"
    res = run("status")
    assert res.exit_code == 0
    assert "unreadable; run agentledger login" in res.output


def test_status_with_unreadable_credential_store(store, http, mem):
    mem.fail_reads = True
    res = run("status")
    assert res.exit_code == 0
    assert "OS credential store" in res.output


def test_status_without_config_never_errors(monkeypatch):
    def missing():
        raise FileNotFoundError("shared/cognito.json not found")

    monkeypatch.setattr(commands, "_context", missing)
    res = run("status")
    assert res.exit_code == 0
    assert res.output.startswith("Status unknown: can't load the IdP config (FileNotFoundError)")


def test_status_unexpected_error_prints_type_only(store, monkeypatch):
    class Boom(Exception):
        pass

    def explode(*a, **k):
        raise Boom("fake-secret-detail")

    monkeypatch.setattr(store, "load", explode)
    res = run("status")
    assert res.exit_code == 0
    assert "Status unknown (Boom)." in res.output
    assert "fake-secret-detail" not in res.output


# --- logout ----------------------------------------------------------------------

def test_logout_revokes_then_deletes(store, http, mem):
    save(store, id_token())
    http["post"] = Post(Resp(200, None))
    res = run("logout")
    assert res.exit_code == 0, res.output
    assert http["post"].calls == [(f"{CFG['domain']}/oauth2/revoke",
                                   {"token": "fake-refresh-1", "client_id": CFG["cli"]["client_id"]})]
    assert "Refresh token revoke accepted by Cognito." in res.output
    assert "Signed out: deleted 2 stored entries." in res.output
    assert mem.data == {}
    assert_no_tokens(res.output)


@pytest.mark.parametrize("reply, reason", [
    (Resp(400, {"error": "invalid_request"}), "invalid_request"),
    (requests.ConnectionError("down"), "ConnectionError"),
])
def test_logout_deletes_even_when_revoke_fails(store, http, mem, reply, reason):
    # Bad case this guards: revoke failed but logout printed plain success.
    save(store, id_token())
    http["post"] = Post(reply)
    res = run("logout")
    assert res.exit_code == 1
    assert "Revoke failed: " in res.output and reason in res.output
    assert "stays valid at Cognito" in res.output
    assert "Signed out: deleted 2 stored entries." in res.output
    assert mem.data == {}


def test_logout_then_whoami_is_not_signed_in(store, http):
    save(store, id_token())
    http["post"] = Post(Resp(200, None))
    assert run("logout").exit_code == 0
    res = run("whoami")
    assert res.exit_code == 1 and "Not signed in" in res.output


def test_logout_when_signed_out(store, http):
    res = run("logout")
    assert res.exit_code == 0
    assert "Not signed in; nothing to revoke." in res.output
    assert "No stored tokens to delete." in res.output


def test_logout_without_refresh_token_skips_revoke(store, http, mem):
    save(store, id_token(), refresh=None)
    res = run("logout")
    assert res.exit_code == 0
    assert "No refresh token stored; nothing to revoke." in res.output
    assert mem.data == {}


def test_logout_with_corrupt_store_still_deletes(store, http, mem):
    save(store, id_token())
    mem.data[("agentledger", CFG["user_pool_id"])] = "garbage"
    res = run("logout")
    assert res.exit_code == 0
    assert "unreadable, so nothing could be revoked" in res.output
    assert mem.data == {}
