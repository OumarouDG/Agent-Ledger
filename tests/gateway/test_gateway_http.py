"""Offline HTTP tests for the gateway: real server on 127.0.0.1, local RSA keys, no cloud calls."""

import asyncio
import threading
import time

import httpx2
import jwt
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from fastmcp import Client

from controlplane.auth.jwt_verify import Verifier
from gateway import server as gw
from gateway.auth import AUTH_MODE, AgentTokenVerifier

ISS = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_TEST"
CODER = "coderclient123"
CLIENT_IDS = {CODER: "coder-agent", "reviewerclient456": "reviewer-agent"}
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SERVER_THREAD = "gateway-test-server"


class FakeJwksVerifier(Verifier):
    """Real Verifier checks; only the JWKS lookup is replaced by the local public key."""

    def __init__(self):
        super().__init__(issuer=ISS, jwks_url="https://example.invalid/jwks.json")
        self.lookup_threads: list[str] = []
        self.fail_with: Exception | None = None

    def _signing_key(self, token):
        self.lookup_threads.append(threading.current_thread().name)
        if self.fail_with:
            raise self.fail_with
        return KEY.public_key()


def make(signing_key=KEY, **overrides) -> str:
    now = int(time.time())
    claims = {"iss": ISS, "token_use": "access", "client_id": CODER, "sub": CODER,
              "scope": "agentledger/tools", "iat": now, "exp": now + 3600}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, signing_key, algorithm="RS256")


@pytest.fixture(scope="module")
def fake_verifier():
    return FakeJwksVerifier()


@pytest.fixture(scope="module")
def base_url(fake_verifier):
    app = gw.create_server(verifier=fake_verifier, client_ids=CLIENT_IDS).http_app()
    cfg = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(cfg)
    thread = threading.Thread(target=server.run, name=SERVER_THREAD, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, "test server did not start"
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}/mcp"
    server.should_exit = True
    thread.join(timeout=10)


INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "test", "version": "0"}}}
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def post(url, token=None, scheme="Bearer", body=INIT):
    headers = dict(HEADERS)
    if token is not None:
        headers["Authorization"] = f"{scheme} {token}"
    return httpx2.post(url, json=body, headers=headers, timeout=10)


# --- rejected at HTTP level ---------------------------------------------------

def test_no_token_is_401(base_url):
    r = post(base_url)
    assert r.status_code == 401
    assert r.headers["www-authenticate"].startswith("Bearer")


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_other_methods_without_token_are_401(base_url, method):
    assert httpx2.request(method, base_url, headers=HEADERS, timeout=10).status_code == 401


def test_notification_without_token_is_401(base_url):
    body = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    assert post(base_url, body=body).status_code == 401


@pytest.mark.parametrize("token, scheme", [
    ("not-a-jwt", "Bearer"),
    ("a.b.c", "Bearer"),
    ("eyJhbGciOiJub25lIn0.e30.", "Bearer"),
])
def test_malformed_token_is_401(base_url, token, scheme):
    assert post(base_url, token, scheme).status_code == 401


def test_empty_bearer_header_is_401(base_url):
    headers = {**HEADERS, "Authorization": "Bearer"}
    assert httpx2.post(base_url, json=INIT, headers=headers, timeout=10).status_code == 401


def test_non_bearer_scheme_is_401(base_url):
    assert post(base_url, make(), scheme="Basic").status_code == 401


@pytest.mark.parametrize("overrides", [
    pytest.param({"exp": int(time.time()) - 3600}, id="expired"),
    pytest.param({"iss": "https://evil.example"}, id="wrong-issuer"),
    pytest.param({"client_id": "someoneelse"}, id="wrong-client"),
    pytest.param({"token_use": "id", "aud": CODER}, id="human-id-token"),
    pytest.param({"username": "alice"}, id="human-access-token"),
    pytest.param({"scope": "agentledger/llm"}, id="missing-scope"),
    pytest.param({"scope": None}, id="no-scope-claim"),
    pytest.param({"exp": None}, id="no-exp"),
])
def test_bad_claims_are_401(base_url, overrides):
    assert post(base_url, make(**overrides)).status_code == 401


def test_token_signed_by_other_key_is_401(base_url):
    assert post(base_url, make(signing_key=OTHER_KEY)).status_code == 401


@pytest.mark.parametrize("failure", [
    jwt.PyJWKClientConnectionError("jwks down"),
    RuntimeError("boom"),
])
def test_jwks_failure_fails_closed(base_url, fake_verifier, failure):
    fake_verifier.fail_with = failure
    try:
        assert post(base_url, make()).status_code == 401
    finally:
        fake_verifier.fail_with = None


# --- accepted -----------------------------------------------------------------

def _call(base_url, token, tool=None):
    async def run():
        async with Client(base_url, auth=token) as c:
            tools = {t.name for t in await c.list_tools()}
            result = await c.call_tool(tool, {}) if tool else None
            return tools, result
    return asyncio.run(run())


def test_valid_token_initializes_and_lists_tools(base_url):
    tools, _ = _call(base_url, make())
    assert tools == {"agentledger_ping", "agentledger_whoami", "get_issue"}


def test_whoami_returns_verified_claims(base_url):
    _, result = _call(base_url, make(), "agentledger_whoami")
    assert result.data == {
        "agent_id": "coder-agent",
        "client_id": CODER,
        "scopes": ["agentledger/tools"],
        "auth_mode": AUTH_MODE,
    }


def test_whoami_lists_all_token_scopes(base_url):
    token = make(scope="agentledger/tools agentledger/llm")
    _, result = _call(base_url, token, "agentledger_whoami")
    assert result.data["scopes"] == ["agentledger/tools", "agentledger/llm"]


def test_whoami_distinguishes_agents(base_url):
    _, result = _call(base_url, make(client_id="reviewerclient456", sub="reviewerclient456"),
                      "agentledger_whoami")
    assert result.data["agent_id"] == "reviewer-agent"


def test_ping_reports_accurate_auth_mode(base_url):
    _, result = _call(base_url, make(), "agentledger_ping")
    assert result.data["connected"] is True
    assert result.data["auth_mode"] == AUTH_MODE
    assert result.data["auth_mode"] != "development_connectivity_only"


def test_client_without_token_cannot_connect(base_url):
    async def run():
        async with Client(base_url):
            pass
    with pytest.raises(Exception):
        asyncio.run(run())


def test_jwks_lookup_runs_off_the_event_loop(base_url, fake_verifier):
    fake_verifier.lookup_threads.clear()
    assert post(base_url, make()).status_code == 200
    assert fake_verifier.lookup_threads
    assert SERVER_THREAD not in fake_verifier.lookup_threads


# --- adapter / factory --------------------------------------------------------

def test_access_token_maps_claims_without_raw_token():
    raw = make()
    verifier = AgentTokenVerifier(FakeJwksVerifier(), CLIENT_IDS)
    at = asyncio.run(verifier.verify_token(raw))
    assert at.client_id == CODER
    assert at.scopes == ["agentledger/tools"]
    assert at.subject == CODER
    assert at.claims["iss"] == ISS
    assert at.expires_at > time.time()
    assert raw not in at.model_dump_json()
    assert raw not in repr(at)


def test_adapter_rejects_instead_of_raising():
    verifier = AgentTokenVerifier(FakeJwksVerifier(), CLIENT_IDS)
    assert asyncio.run(verifier.verify_token("garbage")) is None
    assert verifier.required_scopes == ["agentledger/tools"]


def test_create_server_fails_closed_without_config(monkeypatch):
    def boom(cls):
        raise FileNotFoundError("shared/cognito.json not found")
    monkeypatch.setattr(Verifier, "from_config", classmethod(boom))
    with pytest.raises(gw.GatewayConfigError):
        gw.create_server()


def test_create_server_rejects_empty_client_ids():
    with pytest.raises(gw.GatewayConfigError):
        gw.create_server(verifier=FakeJwksVerifier(), client_ids={})


def test_server_binds_to_loopback_only(monkeypatch):
    calls = {}

    class Stub:
        def run(self, **kwargs):
            calls.update(kwargs)

    monkeypatch.setattr(gw, "create_server", lambda: Stub())
    gw.main()
    assert calls["host"] == "127.0.0.1"
    assert calls["transport"] == "http"
