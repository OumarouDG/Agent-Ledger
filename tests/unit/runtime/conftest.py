"""In-process gateway for runtime tests: real server on 127.0.0.1, local RSA keys, fake store.

Nothing here calls AWS or GitHub. Without a fake GitHub App the gateway serves its mock
issue #42; the Sentinel is off and its lock file and the audit file live in tmp dirs.
"""

from __future__ import annotations

import contextlib
import dataclasses
import socket
import threading
import time

import jwt
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa

from controlplane.auth.agent_tokens import AgentToken
from controlplane.auth.jwt_verify import Verifier
from gateway import server as gw
from gateway import sentinel as sentinel_mod
from gateway.grants import Grant

ISS = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_FAKE"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
WF = "wf_test01"
CLIENT_IDS = {"fakeleadclient": "agent_lead", "fakecoderclient": "agent_coder",
              "faketesterclient": "agent_tester"}
AGENT_CLIENT = {agent: cid for cid, agent in CLIENT_IDS.items()}


class FakeJwksVerifier(Verifier):
    """Real Verifier checks; only the JWKS lookup is replaced by the local public key."""

    def __init__(self):
        super().__init__(issuer=ISS, jwks_url="https://example.invalid/jwks.json")

    def _signing_key(self, token):
        return KEY.public_key()


def make_token(client_id: str, **overrides) -> str:
    now = int(time.time())
    claims = {"iss": ISS, "token_use": "access", "client_id": client_id, "sub": client_id,
              "scope": "agentledger/tools", "iat": now, "exp": now + 3600}
    claims.update(overrides)
    return jwt.encode({k: v for k, v in claims.items() if v is not None}, KEY, algorithm="RS256")


def fake_mint(client_for: dict[str, str] | None = None, **overrides):
    """A mint function that signs a local token for the agent's (or a substituted) client."""
    mapping = AGENT_CLIENT if client_for is None else client_for

    def mint(agent_id: str) -> AgentToken:
        cid = mapping[agent_id]
        return AgentToken(make_token(cid, **overrides), 3600, agent_id, cid)
    return mint


class MutableStore:
    def __init__(self, *grants: Grant):
        self.items = {g.grant_id: g for g in grants}

    def get(self, grant_id):
        return self.items.get(grant_id)

    def revoke(self, grant_id):
        self.items[grant_id] = dataclasses.replace(self.items[grant_id], status="revoked")


def lead_grant(grant_id: str, **kw) -> Grant:
    base = dict(grant_id=grant_id, agent_id="agent_lead", workflow_id=WF, human_id="alice",
                expires_at=int(time.time()) + 3600, tools=frozenset({"get_issue", "llm_converse"}),
                resources={"repository": "acme/demo", "branch_prefix": f"agentledger/{WF}/"})
    base.update(kw)
    return Grant(**base)


@dataclasses.dataclass(frozen=True)
class Human:
    username: str
    groups: tuple[str, ...] = ("engineer",)


ALICE = Human("alice")
AGENTS = frozenset({"agent_lead", "agent_coder", "agent_tester", "agent_rogue"})


class MemStore:
    """GrantWriter in memory. Records who created each grant."""

    def __init__(self):
        self.items: dict = {}
        self.created_by: dict[str, str] = {}

    def get(self, grant_id):
        return self.items.get(grant_id)

    def put_new(self, grant, *, created_at, created_by):
        assert grant.grant_id not in self.items
        self.items[grant.grant_id] = grant
        self.created_by[grant.grant_id] = created_by

    def mark_revoked(self, grant_id, *, revoked_at, revoked_by):
        g = self.items.get(grant_id)
        if g is None or g.status == "revoked":
            return False
        self.items[grant_id] = dataclasses.replace(g, status="revoked")
        return True


def opener(url="http://127.0.0.1:9/mcp", mint=None):
    """open_agent for tests: a real AgentSession with a local key and a fake mint."""
    from controlplane.runtime.gateway_client import AgentSession

    def open_agent(agent_id, grant_id, workflow_id):
        return AgentSession(agent_id, grant_id, workflow_id, url, mint=mint or fake_mint(),
                            verifier=FakeJwksVerifier(), client_ids=CLIENT_IDS)
    return open_agent


@contextlib.contextmanager
def serve_gateway(store, d, github_app=None, llm_client=None):
    """Run a gateway over `store` on a free loopback port; yields its /mcp URL."""
    app = gw.create_server(
        verifier=FakeJwksVerifier(), client_ids=CLIENT_IDS, grants=store,
        audit_path=d / "audit.jsonl", github_app=github_app, llm_client=llm_client,
        sentinel=sentinel_mod.Sentinel(d / "quarantine.json", threshold=0)).http_app()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, "test gateway did not start"
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.should_exit = True
        t.join(timeout=10)


@pytest.fixture(scope="module")
def gateway(tmp_path_factory):
    store = MutableStore(lead_grant("g_lead"), lead_grant("g_revoke_me"))
    with serve_gateway(store, tmp_path_factory.mktemp("rt-gw")) as url:
        yield {"url": url, "store": store}


@pytest.fixture
def dead_url():
    """A loopback URL with nothing listening on it."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}/mcp"
