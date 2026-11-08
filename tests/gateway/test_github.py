"""GitHub App adapter and the real get_issue path. Offline: fake HTTP, local RSA key."""

import asyncio
import json
import threading
import time

import jwt
import pytest
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastmcp import Client
from fastmcp.client.auth import BearerAuth
from fastmcp.client.transports import StreamableHttpTransport

from gateway import github
from gateway import server as gw
from gateway.grants import JsonFileGrantStore
from tests.gateway.test_gateway_http import CLIENT_IDS, FakeJwksVerifier, make

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption()).decode()


class Resp:
    def __init__(self, status, body=None):
        self.status_code, self._body = status, body or {}

    def json(self):
        return self._body


class FakeHttp:
    def __init__(self, issue=None, issue_status=200, token_status=201):
        self.issue = issue or {"number": 1, "title": "T", "state": "open", "body": None,
                               "labels": [{"name": "bug"}], "html_url": "https://x/1"}
        self.issue_status, self.token_status = issue_status, token_status
        self.posts, self.gets = [], []

    def post(self, url, headers, timeout):
        self.posts.append((url, headers))
        return Resp(self.token_status, {"token": "ghs_secret_install_token"})

    def get(self, url, headers, timeout):
        self.gets.append((url, headers))
        return Resp(self.issue_status, self.issue)


def app(http):
    return github.GitHubApp("123", "456", lambda: PEM, http=http)


def test_get_issue_returns_only_expected_fields():
    out = app(FakeHttp()).get_issue("acme/demo", 1)
    assert out == {"repository": "acme/demo", "number": 1, "title": "T", "state": "open",
                   "body": "", "labels": ["bug"], "url": "https://x/1"}
    assert "ghs_secret_install_token" not in json.dumps(out)


def test_app_jwt_is_signed_for_the_app_and_install_token_is_cached():
    http = FakeHttp()
    a = app(http)
    a.get_issue("acme/demo", 1)
    a.get_issue("acme/demo", 2)
    assert len(http.posts) == 1 and len(http.gets) == 2
    url, headers = http.posts[0]
    assert url.endswith("/app/installations/456/access_tokens")
    claims = jwt.decode(headers["Authorization"].split()[1], KEY.public_key(),
                        algorithms=["RS256"])
    assert claims["iss"] == "123" and claims["exp"] - claims["iat"] <= 600 + 60


@pytest.mark.parametrize("repo", ["", "nope", "a/b/c", "a/b; rm", "../etc/passwd", None])
def test_bad_repo_rejected_before_any_http(repo):
    http = FakeHttp()
    with pytest.raises(github.GitHubError):
        app(http).get_issue(repo, 1)
    assert not http.posts and not http.gets


@pytest.mark.parametrize("number", [0, -1, "1", None])
def test_bad_issue_number_rejected(number):
    with pytest.raises(github.GitHubError):
        app(FakeHttp()).get_issue("acme/demo", number)


def test_pull_request_is_not_an_issue():
    http = FakeHttp(issue={"number": 3, "pull_request": {}})
    with pytest.raises(github.GitHubError, match="not found"):
        app(http).get_issue("acme/demo", 3)


@pytest.mark.parametrize("kw, msg", [({"issue_status": 404}, "not found"),
                                     ({"issue_status": 500}, "HTTP 500"),
                                     ({"token_status": 401}, "github auth failed")])
def test_github_failures_become_safe_errors(kw, msg):
    with pytest.raises(github.GitHubError, match=msg):
        app(FakeHttp(**kw)).get_issue("acme/demo", 1)


def test_not_configured_returns_none():
    assert github.from_env({}) is None
    assert github.from_env({"AGENTLEDGER_GITHUB_APP_ID": "1"}) is None


# --- through the gateway --------------------------------------------------------

def g(**kw):
    base = {"agent_id": "coder-agent", "workflow_id": "wf1", "human_id": "alice",
            "tools": ["get_issue"], "expires_at": int(time.time()) + 3600,
            "resources": {"repository": "acme/demo"}}
    base.update(kw)
    return base


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    d = tmp_path_factory.mktemp("ghgw")
    gfile, afile = d / "grants.json", d / "audit.jsonl"
    gfile.write_text(json.dumps({"grants": {"ok": g(), "norepo": g(resources={})}}))
    http = FakeHttp()
    server = gw.create_server(
        verifier=FakeJwksVerifier(), client_ids=CLIENT_IDS, grants=JsonFileGrantStore(gfile),
        audit_path=afile, github_app=app(http)).http_app()
    srv = uvicorn.Server(uvicorn.Config(server, host="127.0.0.1", port=0, log_level="warning"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    deadline = time.time() + 10
    while not srv.started and time.time() < deadline:
        time.sleep(0.05)
    assert srv.started
    port = srv.servers[0].sockets[0].getsockname()[1]
    yield {"url": f"http://127.0.0.1:{port}/mcp", "afile": afile, "http": http}
    srv.should_exit = True
    t.join(timeout=10)


def call(env, grant_id, number=1):
    async def go():
        tr = StreamableHttpTransport(
            env["url"], headers={"X-Grant-Id": grant_id, "X-Workflow-Id": "wf1"},
            auth=BearerAuth(make()))
        async with Client(tr) as c:
            return await c.call_tool("get_issue", {"issue_number": number}, raise_on_error=False)
    return asyncio.run(go())


def last_audit(env):
    return json.loads(env["afile"].read_text().splitlines()[-1])


def test_gateway_reads_repo_from_grant_not_from_agent(env):
    r = call(env, "ok", 1)
    assert not r.is_error and r.data["repository"] == "acme/demo"
    assert "/repos/acme/demo/issues/1" in env["http"].gets[-1][0]
    assert last_audit(env)["resource"] == {"issue": 1, "repository": "acme/demo"}


def test_grant_without_repository_is_denied_and_audited(env):
    before = len(env["http"].gets)
    r = call(env, "norepo")
    assert r.is_error and "resource_not_in_grant" in r.content[0].text
    assert len(env["http"].gets) == before
    assert last_audit(env)["decision"] == "deny"
