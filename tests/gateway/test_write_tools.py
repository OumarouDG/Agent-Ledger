"""create_branch / commit_file: adapter rules and grant-scoped access. Offline, fake HTTP."""

import asyncio
import base64
import json
import threading
import time

import pytest
import uvicorn
from fastmcp import Client
from fastmcp.client.auth import BearerAuth
from fastmcp.client.transports import StreamableHttpTransport

from gateway import github
from gateway import server as gw
from gateway.grants import JsonFileGrantStore
from tests.gateway.test_gateway_http import CLIENT_IDS, FakeJwksVerifier, make
from tests.gateway.test_github import PEM, Resp


class Fake:
    """Records every request. Files in `files` already exist on the branch."""

    def __init__(self, files=None, ref_status=200, create_status=201, put_status=201):
        self.files, self.ref_status = files or {}, ref_status
        self.create_status, self.put_status = create_status, put_status
        self.calls = []

    def post(self, url, headers, timeout, json=None):
        self.calls.append(("POST", url, json))
        if url.endswith("/access_tokens"):
            return Resp(201, {"token": "ghs_x"})
        return Resp(self.create_status, {})

    def get(self, url, headers, timeout, params=None):
        self.calls.append(("GET", url, params))
        if "/git/ref/heads/" in url:
            return Resp(self.ref_status, {"object": {"sha": "basesha"}})
        path = url.split("/contents/")[1]
        return Resp(200, {"sha": "oldsha"}) if path in self.files else Resp(404, {})

    def put(self, url, headers, timeout, json=None):
        self.calls.append(("PUT", url, json))
        return Resp(self.put_status, {"commit": {"sha": "newsha", "html_url": "https://x/c"}})

    def writes(self):
        return [c for c in self.calls if c[0] in ("PUT",) or
                (c[0] == "POST" and not c[1].endswith("/access_tokens"))]


def app(http):
    return github.GitHubApp("1", "2", lambda: PEM, http=http)


# --- validators -----------------------------------------------------------------

@pytest.mark.parametrize("name", ["agentledger/wf1/x", "a/b", "feature-1.2"])
def test_good_branches(name):
    assert github.valid_branch(name)


@pytest.mark.parametrize("name", ["", "../x", "a/../b", "a//b", "/a", "a/", "a b", "x.lock",
                                  "a..b", "a;b", "a" * 101, None, 5])
def test_bad_branches(name):
    assert not github.valid_branch(name)


@pytest.mark.parametrize("path", ["a.py", "src/a/b.txt", "docs/x-1.md"])
def test_good_paths(path):
    assert github.valid_path(path)


@pytest.mark.parametrize("path", ["", "/etc/passwd", "../x", "a/../b", ".git/config",
                                  "a/.GIT/x", "a//b", "a b", "a\\b", "x" * 201, None])
def test_bad_paths(path):
    assert not github.valid_path(path)


# --- adapter --------------------------------------------------------------------

def test_create_branch_uses_base_sha():
    http = Fake()
    out = app(http).create_branch("o/r", "agentledger/wf1", "main")
    assert out["sha"] == "basesha"
    post = [c for c in http.calls if c[0] == "POST" and "/git/refs" in c[1]][0]
    assert post[2] == {"ref": "refs/heads/agentledger/wf1", "sha": "basesha"}


def test_create_branch_existing_is_a_clean_error():
    with pytest.raises(github.GitHubError, match="already exists"):
        app(Fake(create_status=422)).create_branch("o/r", "agentledger/wf1", "main")


def test_commit_new_file_has_no_sha_and_content_is_base64():
    http = Fake()
    out = app(http).commit_file("o/r", "agentledger/wf1", "a.py", "print('hi')\n", "add a")
    put = [c for c in http.calls if c[0] == "PUT"][0]
    assert "sha" not in put[2] and put[2]["branch"] == "agentledger/wf1"
    assert base64.b64decode(put[2]["content"]).decode() == "print('hi')\n"
    assert out["commit_sha"] == "newsha"


def test_commit_existing_file_sends_its_sha():
    http = Fake(files={"a.py"})
    app(http).commit_file("o/r", "agentledger/wf1", "a.py", "x", "update a")
    assert [c for c in http.calls if c[0] == "PUT"][0][2]["sha"] == "oldsha"


@pytest.mark.parametrize("kw", [
    {"branch": "../x"}, {"path": ".git/config"}, {"path": "/abs"}, {"content": None},
    {"content": "x" * (github.MAX_CONTENT_BYTES + 1)}, {"message": ""}, {"message": "m" * 201},
])
def test_commit_rejects_bad_input_before_any_write(kw):
    http = Fake()
    args = dict(repo="o/r", branch="agentledger/wf1", path="a.py", content="x", message="m")
    args.update(kw)
    with pytest.raises(github.GitHubError):
        app(http).commit_file(**args)
    assert not http.writes()


# --- through the gateway ---------------------------------------------------------

def grant(**res):
    resources = {"repository": "o/r", "branch_prefix": "agentledger/wf1/"}
    resources.update(res)
    return {"agent_id": "coder-agent", "workflow_id": "wf1", "human_id": "alice",
            "tools": ["create_branch", "commit_file"], "resources": resources,
            "expires_at": int(time.time()) + 3600}


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    d = tmp_path_factory.mktemp("wgw")
    gfile, afile = d / "g.json", d / "a.jsonl"
    gfile.write_text(json.dumps({"grants": {
        "ok": grant(), "noprefix": grant(branch_prefix=None),
        "readonly": {**grant(), "tools": ["get_issue"]},
        "slashless": grant(branch_prefix="agentledger"),
    }}))
    http = Fake()
    srv_app = gw.create_server(verifier=FakeJwksVerifier(), client_ids=CLIENT_IDS,
                               grants=JsonFileGrantStore(gfile), audit_path=afile,
                               github_app=app(http)).http_app()
    srv = uvicorn.Server(uvicorn.Config(srv_app, host="127.0.0.1", port=0, log_level="warning"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    deadline = time.time() + 10
    while not srv.started and time.time() < deadline:
        time.sleep(0.05)
    assert srv.started
    yield {"url": f"http://127.0.0.1:{srv.servers[0].sockets[0].getsockname()[1]}/mcp",
           "afile": afile, "http": http}
    srv.should_exit = True
    t.join(timeout=10)


def call(env, grant_id, tool, args):
    async def go():
        tr = StreamableHttpTransport(
            env["url"], headers={"X-Grant-Id": grant_id, "X-Workflow-Id": "wf1"},
            auth=BearerAuth(make()))
        async with Client(tr) as c:
            return await c.call_tool(tool, args, raise_on_error=False)
    return asyncio.run(go())


def last_audit(env):
    """The latest authorization decision (outcome lines come after it)."""
    lines = [json.loads(x) for x in env["afile"].read_text().splitlines()]
    return [e for e in lines if e.get("event") == "decision"][-1]


def test_branch_under_prefix_is_created_and_audited(env):
    r = call(env, "ok", "create_branch", {"branch": "agentledger/wf1/feat"})
    assert not r.is_error and r.data["branch"] == "agentledger/wf1/feat"
    e = last_audit(env)
    assert e["decision"] == "allow" and e["resource"]["branch"] == "agentledger/wf1/feat"


@pytest.mark.parametrize("branch", ["main", "agentledger/wf1/", "agentledger/wf2/x",
                                    "agentledger/wf1/../main", "other/x"])
def test_branch_outside_prefix_is_denied_before_github(env, branch):
    before = len(env["http"].writes())
    r = call(env, "ok", "create_branch", {"branch": branch})
    assert r.is_error and "branch_not_permitted" in r.content[0].text
    assert len(env["http"].writes()) == before
    assert last_audit(env)["decision"] == "deny"


@pytest.mark.parametrize("gid", ["noprefix", "slashless"])
def test_grant_without_a_usable_prefix_cannot_write(env, gid):
    r = call(env, gid, "commit_file", {"branch": "main", "path": "a.py",
                                       "content": "x", "message": "m"})
    assert r.is_error and "branch_not_permitted" in r.content[0].text


def test_tool_not_in_grant_is_denied(env):
    r = call(env, "readonly", "create_branch", {"branch": "agentledger/wf1/x"})
    assert r.is_error and "tool_not_permitted" in r.content[0].text


def test_commit_to_allowed_branch_works_and_never_touches_main(env):
    r = call(env, "ok", "commit_file", {"branch": "agentledger/wf1/feat", "path": "src/g.py",
                                        "content": "def greet(n): return n", "message": "add"})
    assert not r.is_error and r.data["commit_sha"] == "newsha"
    puts = [c for c in env["http"].calls if c[0] == "PUT"]
    assert all(c[2]["branch"].startswith("agentledger/wf1/") for c in puts)
