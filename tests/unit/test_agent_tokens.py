"""Offline tests for agent token minting. AWS is stubbed with botocore Stubber; requests.post is patched.

All secret and token values here are fakes.
"""

import json

import boto3
import pytest
from botocore.stub import Stubber

from controlplane.auth import agent_tokens
from controlplane.auth.agent_tokens import AgentNotRegistered, AgentToken, mint_agent_token
from controlplane.auth.config import load_config

REGION = "us-east-1"
DOMAIN = "https://agentledger-test.auth.us-east-1.amazoncognito.com"
FAKE_CLIENT_ID = "fakeclientid0001"
FAKE_SECRET = "fake-client-secret-not-real"
FAKE_TOKEN = "fake.access.token-value-XYZ"
SCOPES = ["agentledger/tools", "agentledger/llm"]


def write_config(tmp_path, monkeypatch, agent: dict) -> None:
    cfg = {"region": REGION, "domain": DOMAIN, "agents": {"agent_coder": agent}}
    p = tmp_path / "cognito.json"
    p.write_text(json.dumps(cfg))
    monkeypatch.setenv("AGENTLEDGER_COGNITO_CONFIG", str(p))
    load_config.cache_clear()


def agent_entry(secret_ref: str, token_mode: str = "get_client_token") -> dict:
    return {"client_id": FAKE_CLIENT_ID, "scopes": SCOPES, "secret_ref": secret_ref, "token_mode": token_mode}


@pytest.fixture(autouse=True)
def fresh_cache():
    load_config.cache_clear()
    yield
    load_config.cache_clear()


@pytest.fixture
def aws(monkeypatch):
    """Real botocore clients with fake creds, wrapped in Stubbers. Any unstubbed call raises."""
    real_client = boto3.client
    clients = {
        svc: real_client(svc, region_name=REGION, aws_access_key_id="testing",
                         aws_secret_access_key="testing", aws_session_token="testing")
        for svc in ("secretsmanager", "cognito-idp")
    }
    stubbers = {svc: Stubber(c) for svc, c in clients.items()}
    created: list[str] = []

    def fake_client(svc, region_name=None, **_):
        assert region_name == REGION
        created.append(svc)
        return clients[svc]

    monkeypatch.setattr(agent_tokens.boto3, "client", fake_client)
    for s in stubbers.values():
        s.activate()
    yield stubbers, created
    for s in stubbers.values():
        s.deactivate()


@pytest.fixture
def no_http(monkeypatch):
    calls = []

    def refuse(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("requests.post must not be called on this path")

    monkeypatch.setattr(agent_tokens.requests, "post", refuse)
    return calls


def stub_secret(stubbers, name: str) -> None:
    stubbers["secretsmanager"].add_response(
        "get_secret_value",
        {"SecretString": json.dumps({"client_id": FAKE_CLIENT_ID, "client_secret": FAKE_SECRET})},
        {"SecretId": name},
    )


def stub_get_client_token(stubbers, scopes=SCOPES) -> None:
    stubbers["cognito-idp"].add_response(
        "get_client_token",
        {"ClientAuthenticationResult": {"AccessToken": FAKE_TOKEN, "ExpiresIn": 3600, "TokenType": "Bearer"}},
        {"ClientId": FAKE_CLIENT_ID, "Secret": FAKE_SECRET, "Scopes": scopes},
    )


class FakeResponse:
    def __init__(self, body: dict, status: int = 200):
        self._body = body
        self.status_code = status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise agent_tokens.requests.HTTPError(f"{self.status_code} from token endpoint")

    def json(self) -> dict:
        return self._body


# --- secret lookup ---------------------------------------------------------

def test_secret_read_from_secrets_manager(tmp_path, monkeypatch, aws, no_http):
    stubbers, _ = aws
    write_config(tmp_path, monkeypatch, agent_entry("secretsmanager:agentledger/agent_coder"))
    stub_secret(stubbers, "agentledger/agent_coder")
    stub_get_client_token(stubbers)

    tok = mint_agent_token("agent_coder")

    stubbers["secretsmanager"].assert_no_pending_responses()
    stubbers["cognito-idp"].assert_no_pending_responses()
    assert tok.access_token == FAKE_TOKEN
    assert tok.client_id == FAKE_CLIENT_ID


def test_secret_read_from_local_file(tmp_path, monkeypatch, aws, no_http):
    stubbers, created = aws
    secrets_file = tmp_path / "agent-secrets.local.json"
    secrets_file.write_text(json.dumps(
        {"agent_coder": {"client_id": FAKE_CLIENT_ID, "client_secret": FAKE_SECRET}}))
    monkeypatch.setattr(agent_tokens, "LOCAL_SECRETS_FILE", secrets_file)
    write_config(tmp_path, monkeypatch, agent_entry("local:agent_coder"))
    stub_get_client_token(stubbers)  # expected_params proves the local secret was sent

    tok = mint_agent_token("agent_coder")

    assert "secretsmanager" not in created
    stubbers["cognito-idp"].assert_no_pending_responses()
    assert tok.access_token == FAKE_TOKEN


@pytest.mark.parametrize("secret_ref", ["vault:agent_coder", "agent_coder", "", "SecretsManager:x"])
def test_unknown_secret_ref_kind_raises(tmp_path, monkeypatch, aws, no_http, secret_ref):
    _, created = aws
    write_config(tmp_path, monkeypatch, agent_entry(secret_ref))
    with pytest.raises(ValueError) as e:
        mint_agent_token("agent_coder")
    assert "agent_coder" in str(e.value)
    assert created == []  # failed before any AWS client was made


# --- agent lookup ----------------------------------------------------------

@pytest.mark.parametrize("agent_id", ["agent_unknown", "", "AGENT_CODER"])
def test_unknown_agent_raises_agent_not_registered(tmp_path, monkeypatch, aws, no_http, agent_id):
    _, created = aws
    write_config(tmp_path, monkeypatch, agent_entry("secretsmanager:agentledger/agent_coder"))
    with pytest.raises(AgentNotRegistered) as e:
        mint_agent_token(agent_id)
    assert e.value.args == (agent_id,)
    assert created == []  # no secret fetched for an unregistered agent


# --- token path selection --------------------------------------------------

def test_get_client_token_path_used_when_token_mode_says_so(tmp_path, monkeypatch, aws, no_http):
    stubbers, _ = aws
    write_config(tmp_path, monkeypatch, agent_entry("secretsmanager:agentledger/agent_coder"))
    stub_secret(stubbers, "agentledger/agent_coder")
    stub_get_client_token(stubbers)

    tok = mint_agent_token("agent_coder")

    stubbers["cognito-idp"].assert_no_pending_responses()
    assert no_http == []
    assert (tok.access_token, tok.expires_in, tok.agent_id) == (FAKE_TOKEN, 3600, "agent_coder")


def test_get_client_token_passes_requested_scopes(tmp_path, monkeypatch, aws, no_http):
    stubbers, _ = aws
    write_config(tmp_path, monkeypatch, agent_entry("secretsmanager:agentledger/agent_coder"))
    stub_secret(stubbers, "agentledger/agent_coder")
    stub_get_client_token(stubbers, scopes=["agentledger/tools"])

    mint_agent_token("agent_coder", scopes=["agentledger/tools"])

    stubbers["cognito-idp"].assert_no_pending_responses()


def test_get_client_token_error_propagates(tmp_path, monkeypatch, aws, no_http):
    stubbers, _ = aws
    write_config(tmp_path, monkeypatch, agent_entry("secretsmanager:agentledger/agent_coder"))
    stub_secret(stubbers, "agentledger/agent_coder")
    stubbers["cognito-idp"].add_client_error("get_client_token", "NotAuthorizedException", "bad secret")

    with pytest.raises(Exception) as e:
        mint_agent_token("agent_coder")
    assert "NotAuthorizedException" in str(e.value)
    assert no_http == []  # no silent fallback to /oauth2/token on a Cognito error


def test_oauth2_token_fallback_used_otherwise(tmp_path, monkeypatch, aws):
    stubbers, _ = aws
    write_config(tmp_path, monkeypatch,
                 agent_entry("secretsmanager:agentledger/agent_coder", token_mode="oauth2_token"))
    stub_secret(stubbers, "agentledger/agent_coder")
    # No cognito-idp responses queued: a get_client_token call would raise.
    calls = []

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse({"access_token": FAKE_TOKEN, "expires_in": 3600, "token_type": "Bearer"})

    monkeypatch.setattr(agent_tokens.requests, "post", fake_post)

    tok = mint_agent_token("agent_coder")

    assert len(calls) == 1
    url, kwargs = calls[0]
    assert url == f"{DOMAIN}/oauth2/token"
    assert kwargs["auth"] == (FAKE_CLIENT_ID, FAKE_SECRET)
    assert kwargs["data"] == {"grant_type": "client_credentials", "scope": " ".join(SCOPES)}
    assert kwargs["timeout"] > 0
    assert (tok.access_token, tok.expires_in) == (FAKE_TOKEN, 3600)


def test_oauth2_token_fallback_http_error_raises(tmp_path, monkeypatch, aws):
    stubbers, _ = aws
    write_config(tmp_path, monkeypatch,
                 agent_entry("secretsmanager:agentledger/agent_coder", token_mode="oauth2_token"))
    stub_secret(stubbers, "agentledger/agent_coder")
    monkeypatch.setattr(agent_tokens.requests, "post",
                        lambda url, **kw: FakeResponse({"error": "invalid_client"}, status=400))

    with pytest.raises(agent_tokens.requests.HTTPError):
        mint_agent_token("agent_coder")


# --- AgentToken never shows the token --------------------------------------

def test_agent_token_repr_never_contains_token():
    tok = AgentToken(access_token=FAKE_TOKEN, expires_in=3600, agent_id="agent_coder", client_id=FAKE_CLIENT_ID)
    for rendered in (repr(tok), str(tok), f"{tok}", repr([tok]), repr({"t": tok})):
        assert FAKE_TOKEN not in rendered
        assert "agent_coder" in rendered
