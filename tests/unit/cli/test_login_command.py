"""CLI-1: `agentledger login` and login.authenticate(). Offline: fake browser, server, HTTP, verifier, keyring."""

from __future__ import annotations

import pytest
import requests
from click.testing import CliRunner

from agentledger import login
from agentledger.main import cli
from agentledger.storage import TokenStore
from controlplane.auth.jwt_verify import AuthError

from .conftest import CFG, FAKE_TOKENS, FakeResp, FakeVerifier

TOKEN_VALUES = [FAKE_TOKENS[k] for k in ("id_token", "access_token", "refresh_token")]


@pytest.fixture
def cli_env(monkeypatch, mem, seams):
    """Run `agentledger login` with the fake browser flow and in-memory keyring."""
    import controlplane.auth.config as config

    monkeypatch.setattr(config, "load_config", lambda: CFG)
    real = login.authenticate
    monkeypatch.setattr(login, "authenticate", lambda *a, **k: real(*a, **{**seams, **k}))
    return mem


def invoke_login():
    return CliRunner().invoke(cli, ["login"])


# --- authenticate() -----------------------------------------------------------

def test_authenticate_returns_verified_claims_and_tokens(seams):
    res = login.authenticate(**seams)
    assert res.username == "alice" and res.groups == ["engineer"]
    assert res.tokens["id_token"] == FAKE_TOKENS["id_token"]


def test_login_result_repr_hides_tokens(seams):
    text = repr(login.authenticate(**seams))
    assert "alice" in text
    for v in TOKEN_VALUES:
        assert v not in text


def test_token_endpoint_http_error_is_a_clean_login_error(seams, monkeypatch):
    monkeypatch.setattr(login.requests, "post", lambda *a, **k: FakeResp({"error": "invalid_grant"}, 400))
    with pytest.raises(login.LoginError, match="HTTP 400"):
        login.authenticate(**seams)


def test_network_failure_is_a_clean_login_error(seams, monkeypatch):
    def down(*a, **k):
        raise requests.ConnectionError("no route")

    monkeypatch.setattr(login.requests, "post", down)
    with pytest.raises(login.LoginError, match="ConnectionError.*Check the network"):
        login.authenticate(**seams)


@pytest.mark.parametrize("body", [
    {"access_token": "fake-access"}, {"id_token": "fake-id"}, [], ValueError("not json"),
])
def test_token_response_without_tokens_is_rejected(seams, monkeypatch, body):
    monkeypatch.setattr(login.requests, "post", lambda *a, **k: FakeResp(body))
    with pytest.raises(login.LoginError, match="Login failed"):
        login.authenticate(**seams)


@pytest.mark.parametrize("reason", ["wrong_audience", "wrong_issuer", "token_expired", "wrong_token_use"])
def test_rejected_id_token_names_the_reason(seams, reason):
    FakeVerifier.error = AuthError(reason)
    with pytest.raises(login.LoginError, match=f"ID token rejected \\({reason}\\)"):
        login.authenticate(**seams)


# --- agentledger login ----------------------------------------------------------

def test_login_stores_tokens_and_prints_user_and_groups(cli_env):
    res = invoke_login()
    assert res.exit_code == 0, res.output
    assert res.output.strip().endswith("Signed in as alice (engineer)")
    for v in TOKEN_VALUES:
        assert v not in res.output
    stored = TokenStore(CFG["user_pool_id"]).load()
    assert stored == {k: FAKE_TOKENS[k] for k in ("id_token", "access_token", "refresh_token")}


def test_login_with_no_groups_says_so(cli_env, monkeypatch):
    monkeypatch.setattr(FakeVerifier, "claims", {"cognito:username": "dana", "token_use": "id"})
    res = invoke_login()
    assert res.exit_code == 0
    assert "Signed in as dana (no groups)" in res.output


def test_failed_sign_in_stores_nothing(cli_env, monkeypatch):
    FakeVerifier.error = AuthError("wrong_audience")
    res = invoke_login()
    assert res.exit_code == 1
    assert "ID token rejected (wrong_audience)" in res.output
    assert "Signed in as" not in res.output
    assert cli_env.data == {}


def test_storage_failure_is_not_reported_as_signed_in(cli_env):
    # Bad case this guards: browser sign-in succeeded, keyring write failed, CLI said "Signed in".
    cli_env.fail_set_on = CFG["user_pool_id"]
    res = invoke_login()
    assert res.exit_code == 1
    assert "not signed in" in res.output
    assert "Signed in as" not in res.output
    for v in TOKEN_VALUES:
        assert v not in res.output


def test_ctrl_c_during_login_is_clean(cli_env, monkeypatch):
    def interrupt(*a, **k):
        raise KeyboardInterrupt

    monkeypatch.setattr(login.requests, "post", interrupt)
    res = invoke_login()
    assert res.exit_code == 1
    assert "Login cancelled" in res.output
    assert "Traceback" not in res.output
    assert cli_env.data == {}


def test_missing_config_names_the_fix(monkeypatch, mem):
    import controlplane.auth.config as config

    def missing():
        raise FileNotFoundError("shared/cognito.json not found. Run `python infra/cognito_setup.py` first.")

    monkeypatch.setattr(config, "load_config", missing)
    res = invoke_login()
    assert res.exit_code == 1
    assert "cognito_setup.py" in res.output
